"""Packet-level feature extraction and flow assembly from per-host pcaps (M2).

One extractor for every data source (CIC per-host members and our own lab
capture — decision 001): a streaming pass turns a pcap into a compact per-packet
table; vectorised passes assemble canonical flows and the packet-level features
the problem statement names (TTL, TCP window, fragments, payload sizes,
port-scan signature, retransmissions), keyed on ``(src_ip, window_id)``.

Performance: packets are parsed with raw struct offsets over scapy's
RawPcapReader/PcapNgReader byte stream (full scapy dissection is ~30x slower);
memory stays bounded because nothing keeps more than one packet plus fixed-size
per-flow sequence caches (M2.1: 1 GB pcap under 4 GB RSS).

The retransmission count here is the scapy-path heuristic (repeated TCP
sequence number with identical payload length within a flow). The tshark path
(`tcp.analysis.retransmission`) lands with M2.2's agreement test once Wireshark
is installed on this machine.
"""

from __future__ import annotations

import math
import struct
from collections import OrderedDict
from pathlib import Path

import numpy as np
import pandas as pd

_ETH_IPV4 = 0x0800
_ETH_VLAN = 0x8100
_PROTO_TCP = 6
_PROTO_UDP = 17

_PACKET_COLUMNS = [
    "ts", "src_ip", "dst_ip", "src_port", "dst_port", "protocol",
    "ttl", "tcp_win", "is_frag", "payload_len", "is_retrans",
    "syn", "ack", "fin", "rst", "psh", "urg",
]


def _ip_str(raw: bytes) -> str:
    return f"{raw[0]}.{raw[1]}.{raw[2]}.{raw[3]}"


class _RetransTracker:
    """Per-flow cache of (seq, payload_len); a repeat is a retransmission."""

    def __init__(self, per_flow_cap: int):
        self._cap = per_flow_cap
        self._flows: dict[tuple, OrderedDict] = {}

    def is_retrans(self, flow_key: tuple, seq: int, payload_len: int) -> bool:
        seen = self._flows.setdefault(flow_key, OrderedDict())
        key = (seq, payload_len)
        if key in seen:
            return True
        seen[key] = None
        if len(seen) > self._cap:
            seen.popitem(last=False)
        return False


def _open_raw_reader(pcap_path: Path):
    from scapy.utils import PcapNgReader, RawPcapReader

    with open(pcap_path, "rb") as fh:
        magic = fh.read(4)
    if magic == b"\x0a\x0d\x0d\x0a":
        return PcapNgReader(str(pcap_path))
    return RawPcapReader(str(pcap_path))


def _packet_time(reader, meta) -> float:
    # RawPcapReader metadata carries sec/usec; PcapNgReader gives tshigh/tslow.
    if hasattr(meta, "sec"):
        divisor = 1e9 if getattr(reader, "nano", False) else 1e6
        return meta.sec + meta.usec / divisor
    ts = (meta.tshigh << 32) | meta.tslow
    return ts / meta.tsresol


def extract_packet_table(pcap_path: str | Path, cfg: dict) -> pd.DataFrame:
    """Stream one pcap into the compact per-packet table (pass 1)."""
    pcap_path = Path(pcap_path)
    if not pcap_path.exists():
        raise FileNotFoundError(f"pcap not found: {pcap_path}")

    tracker = _RetransTracker(cfg["packet_features"]["retrans_track_per_flow"])
    rows: list[tuple] = []

    reader = _open_raw_reader(pcap_path)
    try:
        for raw, meta in reader:
            ts = _packet_time(reader, meta)
            if len(raw) < 34:
                continue
            ethertype = struct.unpack_from("!H", raw, 12)[0]
            offset = 14
            if ethertype == _ETH_VLAN:
                ethertype = struct.unpack_from("!H", raw, 16)[0]
                offset = 18
            if ethertype != _ETH_IPV4 or len(raw) < offset + 20:
                continue

            ver_ihl = raw[offset]
            ihl = (ver_ihl & 0x0F) * 4
            total_len = struct.unpack_from("!H", raw, offset + 2)[0]
            flags_frag = struct.unpack_from("!H", raw, offset + 6)[0]
            is_frag = int(bool(flags_frag & 0x2000) or bool(flags_frag & 0x1FFF))
            ttl = raw[offset + 8]
            proto = raw[offset + 9]
            src_ip = _ip_str(raw[offset + 12 : offset + 16])
            dst_ip = _ip_str(raw[offset + 16 : offset + 20])

            l4 = offset + ihl
            src_port = dst_port = 0
            tcp_win = 0
            payload_len = max(total_len - ihl, 0)
            syn = ack = fin = rst = psh = urg = 0
            retrans = 0

            if proto == _PROTO_TCP and len(raw) >= l4 + 20:
                src_port, dst_port = struct.unpack_from("!HH", raw, l4)
                seq = struct.unpack_from("!I", raw, l4 + 4)[0]
                data_off = (raw[l4 + 12] >> 4) * 4
                tcp_flags = raw[l4 + 13]
                tcp_win = struct.unpack_from("!H", raw, l4 + 14)[0]
                fin = tcp_flags & 0x01
                syn = (tcp_flags >> 1) & 0x01
                rst = (tcp_flags >> 2) & 0x01
                psh = (tcp_flags >> 3) & 0x01
                ack = (tcp_flags >> 4) & 0x01
                urg = (tcp_flags >> 5) & 0x01
                payload_len = max(total_len - ihl - data_off, 0)
                if not is_frag and (payload_len > 0 or syn or fin):
                    flow_key = (src_ip, dst_ip, src_port, dst_port)
                    retrans = int(tracker.is_retrans(flow_key, seq, payload_len))
            elif proto == _PROTO_UDP and len(raw) >= l4 + 8:
                src_port, dst_port = struct.unpack_from("!HH", raw, l4)
                payload_len = max(struct.unpack_from("!H", raw, l4 + 4)[0] - 8, 0)

            rows.append(
                (ts, src_ip, dst_ip, src_port, dst_port, proto, ttl, tcp_win,
                 is_frag, payload_len, retrans, syn, ack, fin, rst, psh, urg)
            )
    finally:
        reader.close()

    df = pd.DataFrame(rows, columns=_PACKET_COLUMNS)
    return df.sort_values("ts", kind="stable").reset_index(drop=True)


# ---------------------------------------------------------------------------
# Window grid — shared by the flow side and the packet side (M2.4 key parity).
# ---------------------------------------------------------------------------


def window_ids_for(ts: pd.Series, cfg: dict) -> list[np.ndarray]:
    """For each timestamp (epoch seconds), the window ids it falls into.

    Windows start on the stride grid: window w covers
    [w * stride, w * stride + window_seconds). With 15 s windows / 5 s stride a
    packet belongs to exactly window_seconds//stride consecutive windows.
    """
    window = cfg["windows"]["window_seconds"]
    stride = cfg["windows"]["stride_seconds"]
    n_overlap = window // stride
    last = np.floor(ts.to_numpy(dtype=float) / stride).astype(np.int64)
    return [last - k for k in range(n_overlap)][::-1]


def _explode_to_windows(df: pd.DataFrame, cfg: dict) -> pd.DataFrame:
    """Repeat rows once per covering window, adding a window_id column."""
    parts = []
    for ids in window_ids_for(df["ts"], cfg):
        part = df.copy()
        part["window_id"] = ids
        parts.append(part)
    return pd.concat(parts, ignore_index=True)


def _port_scan_stats(ports: np.ndarray) -> tuple[float, float]:
    """(sequential_port_ratio, port_entropy) over a host-window's dst ports."""
    if len(ports) < 2:
        return 0.0, 0.0
    diffs = np.diff(ports.astype(np.int64))
    sequential_ratio = float(np.mean(diffs == 1))
    _, counts = np.unique(ports, return_counts=True)
    p = counts / counts.sum()
    entropy = float(-(p * np.log2(p)).sum())
    return sequential_ratio, entropy


def packet_window_features(packets: pd.DataFrame, cfg: dict) -> pd.DataFrame:
    """The PS-mandated packet features per (src_ip, window_id)."""
    edges = list(cfg["packet_features"]["payload_hist_bin_edges"]) + [np.inf]
    n_hist = len(edges) - 1

    exploded = _explode_to_windows(packets, cfg)
    out_rows = []
    for (src_ip, window_id), g in exploded.groupby(["src_ip", "window_id"], sort=True):
        ttl = g["ttl"].to_numpy(dtype=float)
        tcp = g.loc[g["protocol"] == _PROTO_TCP, "tcp_win"].to_numpy(dtype=float)
        hist, _ = np.histogram(g["payload_len"].to_numpy(dtype=float), bins=edges)
        seq_ratio, entropy = _port_scan_stats(g["dst_port"].to_numpy())
        row = {
            "src_ip": src_ip,
            "window_id": int(window_id),
            "ttl_mean": float(ttl.mean()),
            "ttl_var": float(ttl.var()),
            "tcp_win_mean": float(tcp.mean()) if len(tcp) else 0.0,
            "tcp_win_var": float(tcp.var()) if len(tcp) else 0.0,
            "frag_flag_count": int(g["is_frag"].sum()),
            "distinct_dst_ports": int(g["dst_port"].nunique()),
            "sequential_port_ratio": seq_ratio,
            "port_entropy": entropy,
            "retransmission_count": int(g["is_retrans"].sum()),
        }
        for i in range(n_hist):
            row[f"payload_hist_{i}"] = int(hist[i])
        out_rows.append(row)

    result = pd.DataFrame(out_rows)
    expected = {"src_ip", "window_id", *cfg["packet_features"]["fields"]}
    if not result.empty and set(result.columns) != expected:
        raise ValueError(
            f"packet feature columns drifted from configs/data.yaml: "
            f"{sorted(set(result.columns) ^ expected)}"
        )
    return result


# ---------------------------------------------------------------------------
# Flow assembly (canonical schema — same columns the CSV loader emits).
# ---------------------------------------------------------------------------


def assemble_flows(packets: pd.DataFrame, cfg: dict) -> pd.DataFrame:
    """Group packets into bidirectional flows; emit the canonical 23 columns.

    Direction: the endpoint that sent the first packet of the flow is the
    source. A quiet gap longer than flows.timeout_seconds splits the 5-tuple
    into a new flow. The label column is 'unlabeled' — labels come from the
    attack timeline at window-build time (M3), never from the extractor.
    """
    timeout = cfg["flows"]["timeout_seconds"]
    missing_win = cfg["flows"]["missing_init_win"]

    pk = packets.copy()
    a = pk[["src_ip", "src_port"]].astype(str).agg(":".join, axis=1)
    b = pk[["dst_ip", "dst_port"]].astype(str).agg(":".join, axis=1)
    lo = np.minimum(a, b)
    hi = np.maximum(a, b)
    pk["pair_key"] = lo + "|" + hi + "|" + pk["protocol"].astype(str)

    pk = pk.sort_values("ts", kind="stable")
    gap = pk.groupby("pair_key")["ts"].diff().fillna(0.0)
    pk["flow_id"] = (gap > timeout).groupby(pk["pair_key"]).cumsum()
    pk["flow_key"] = pk["pair_key"] + "#" + pk["flow_id"].astype(str)

    flows = []
    for _, g in pk.groupby("flow_key", sort=False):
        first = g.iloc[0]
        src_ip, src_port = first["src_ip"], int(first["src_port"])
        dst_ip, dst_port = first["dst_ip"], int(first["dst_port"])
        fwd = (g["src_ip"] == src_ip) & (g["src_port"] == src_port)
        bwd = ~fwd

        ts = g["ts"].to_numpy(dtype=float)
        iat = np.diff(ts) if len(ts) > 1 else np.array([0.0])

        fwd_syn = g[fwd & (g["syn"] == 1)]
        bwd_syn = g[bwd & (g["syn"] == 1)]

        flows.append({
            "timestamp": pd.to_datetime(ts[0], unit="s"),
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": int(first["protocol"]),
            "duration": float((ts[-1] - ts[0]) * 1e6),  # microseconds, like CIC
            "fwd_bytes": float(g.loc[fwd, "payload_len"].sum()),
            "bwd_bytes": float(g.loc[bwd, "payload_len"].sum()),
            "fwd_pkts": int(fwd.sum()),
            "bwd_pkts": int(bwd.sum()),
            "syn": int(g["syn"].sum()),
            "ack": int(g["ack"].sum()),
            "fin": int(g["fin"].sum()),
            "rst": int(g["rst"].sum()),
            "psh": int(g["psh"].sum()),
            "urg": int(g["urg"].sum()),
            "iat_mean": float(iat.mean() * 1e6),
            "iat_std": float(iat.std() * 1e6),
            "iat_max": float(iat.max() * 1e6),
            "init_win_fwd": int(fwd_syn.iloc[0]["tcp_win"]) if len(fwd_syn) else missing_win,
            "init_win_bwd": int(bwd_syn.iloc[0]["tcp_win"]) if len(bwd_syn) else missing_win,
            "label": "unlabeled",
        })

    out = pd.DataFrame(flows)
    if not out.empty:
        canonical = list(cfg["schema"].keys())
        if list(out.columns) != canonical:
            raise ValueError("flow assembler drifted from the canonical schema")
        out = out.sort_values("timestamp", kind="stable").reset_index(drop=True)
    return out
