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

# Column -> array.array typecode. IPs travel as uint32 through the whole
# pipeline (object strings for 4.7M packets alone cost gigabytes); they become
# dotted strings only at the output edge via ips_to_str.
_PACKET_LAYOUT = {
    "ts": "d", "src_ip": "I", "dst_ip": "I", "src_port": "H", "dst_port": "H",
    "protocol": "B", "ttl": "B", "tcp_win": "H", "is_frag": "B",
    "payload_len": "I", "is_retrans": "B",
    "syn": "B", "ack": "B", "fin": "B", "rst": "B", "psh": "B", "urg": "B",
}


def ips_to_str(values: pd.Series) -> pd.Series:
    """uint32 addresses -> dotted strings, via a small unique-value table."""
    lut = {
        int(v): f"{(v >> 24) & 255}.{(v >> 16) & 255}.{(v >> 8) & 255}.{v & 255}"
        for v in pd.unique(values)
    }
    return values.map(lut)


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
    # Raw readers only: the dissecting PcapNgReader yields Packet objects, not
    # (bytes, metadata) tuples — that mistake crashed on the first pcapng member.
    from scapy.utils import RawPcapNgReader, RawPcapReader

    with open(pcap_path, "rb") as fh:
        magic = fh.read(4)
    if magic == b"\x0a\x0d\x0d\x0a":
        return RawPcapNgReader(str(pcap_path))
    return RawPcapReader(str(pcap_path))


def _packet_time(reader, meta) -> float:
    # RawPcapReader metadata carries sec/usec; PcapNgReader gives tshigh/tslow.
    if hasattr(meta, "sec"):
        divisor = 1e9 if getattr(reader, "nano", False) else 1e6
        return meta.sec + meta.usec / divisor
    ts = (meta.tshigh << 32) | meta.tslow
    return ts / meta.tsresol


def extract_packet_table(pcap_path: str | Path, cfg: dict) -> pd.DataFrame:
    """Stream one pcap into the compact per-packet table (pass 1).

    Accumulates into typed array buffers (~40 bytes/packet total) — a
    list-of-tuples design peaked at ~4 GB RSS on a 4.7M-packet member and
    would crash on DoS-day captures (M2.1 bound: 1 GB pcap under 4 GB RSS).
    """
    import array

    pcap_path = Path(pcap_path)
    if not pcap_path.exists():
        raise FileNotFoundError(f"pcap not found: {pcap_path}")

    tracker = _RetransTracker(cfg["packet_features"]["retrans_track_per_flow"])
    cols = {name: array.array(code) for name, code in _PACKET_LAYOUT.items()}

    reader = _open_raw_reader(pcap_path)
    try:
        for raw, meta in reader:
            if len(raw) < 34:
                continue
            ethertype = struct.unpack_from("!H", raw, 12)[0]
            offset = 14
            if ethertype == _ETH_VLAN:
                ethertype = struct.unpack_from("!H", raw, 16)[0]
                offset = 18
            if ethertype != _ETH_IPV4 or len(raw) < offset + 20:
                continue

            ihl = (raw[offset] & 0x0F) * 4
            total_len = struct.unpack_from("!H", raw, offset + 2)[0]
            flags_frag = struct.unpack_from("!H", raw, offset + 6)[0]
            is_frag = 1 if (flags_frag & 0x2000 or flags_frag & 0x1FFF) else 0
            ttl = raw[offset + 8]
            proto = raw[offset + 9]
            src_ip = int.from_bytes(raw[offset + 12 : offset + 16], "big")
            dst_ip = int.from_bytes(raw[offset + 16 : offset + 20], "big")

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
                    retrans = int(
                        tracker.is_retrans(
                            (src_ip, dst_ip, src_port, dst_port), seq, payload_len
                        )
                    )
            elif proto == _PROTO_UDP and len(raw) >= l4 + 8:
                src_port, dst_port = struct.unpack_from("!HH", raw, l4)
                payload_len = max(struct.unpack_from("!H", raw, l4 + 4)[0] - 8, 0)

            cols["ts"].append(_packet_time(reader, meta))
            cols["src_ip"].append(src_ip)
            cols["dst_ip"].append(dst_ip)
            cols["src_port"].append(src_port)
            cols["dst_port"].append(dst_port)
            cols["protocol"].append(proto)
            cols["ttl"].append(ttl)
            cols["tcp_win"].append(tcp_win)
            cols["is_frag"].append(is_frag)
            cols["payload_len"].append(min(payload_len, 0xFFFFFFFF))
            cols["is_retrans"].append(retrans)
            cols["syn"].append(syn)
            cols["ack"].append(ack)
            cols["fin"].append(fin)
            cols["rst"].append(rst)
            cols["psh"].append(psh)
            cols["urg"].append(urg)
    finally:
        reader.close()

    df = pd.DataFrame(
        {name: np.frombuffer(buf, dtype=buf.typecode).copy() for name, buf in cols.items()}
    )
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


def packet_window_features(packets: pd.DataFrame, cfg: dict) -> pd.DataFrame:
    """The PS-mandated packet features per (src_ip, window_id).

    Fully vectorised — the naive per-group loop ran at ~2.3k pkt/s on real
    members; group-wise pandas aggregations keep whole days tractable on CPU.
    Variances are population variances (ddof=0).
    """
    edges = list(cfg["packet_features"]["payload_hist_bin_edges"]) + [np.inf]
    n_hist = len(edges) - 1
    keys = ["src_ip", "window_id"]

    ex = _explode_to_windows(packets, cfg)
    ex = ex.sort_values(keys + ["ts"], kind="stable").reset_index(drop=True)
    ex["tcp_win_only"] = ex["tcp_win"].where(ex["protocol"] == _PROTO_TCP)
    ex["seq_step"] = ex.groupby(keys)["dst_port"].diff() == 1

    grp = ex.groupby(keys, sort=True)
    size = grp.size()

    out = pd.DataFrame(index=size.index)
    out["ttl_mean"] = grp["ttl"].mean()
    out["ttl_var"] = grp["ttl"].var(ddof=0)
    out["tcp_win_mean"] = grp["tcp_win_only"].mean()
    out["tcp_win_var"] = grp["tcp_win_only"].var(ddof=0)
    out[["tcp_win_mean", "tcp_win_var"]] = out[["tcp_win_mean", "tcp_win_var"]].fillna(0.0)
    out["frag_flag_count"] = grp["is_frag"].sum().astype(int)
    out["distinct_dst_ports"] = grp["dst_port"].nunique().astype(int)
    out["sequential_port_ratio"] = (
        (grp["seq_step"].sum() / (size - 1).clip(lower=1)).where(size >= 2, 0.0)
    )

    port_counts = ex.groupby(keys + ["dst_port"]).size()
    p = port_counts / port_counts.groupby(level=keys).transform("sum")
    out["port_entropy"] = (
        (-(p * np.log2(p))).groupby(level=keys).sum().reindex(out.index).fillna(0.0)
    )

    out["retransmission_count"] = grp["is_retrans"].sum().astype(int)

    ex["hist_bin"] = pd.cut(
        ex["payload_len"], bins=edges, right=False, include_lowest=True, labels=False
    ).astype(int)
    hist = (
        ex.groupby(keys + ["hist_bin"]).size().unstack("hist_bin", fill_value=0)
        .reindex(columns=range(n_hist), fill_value=0)
    )
    for i in range(n_hist):
        out[f"payload_hist_{i}"] = hist[i].reindex(out.index).fillna(0).astype(int)

    result = out.reset_index()
    result["src_ip"] = ips_to_str(result["src_ip"])
    result["window_id"] = result["window_id"].astype(int)

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


def find_tshark(cfg: dict) -> str | None:
    """Resolve the tshark binary: explicit config path, PATH, default install."""
    import shutil

    configured = cfg["packet_features"].get("tshark_path")
    if configured:
        return configured if Path(configured).exists() else None
    on_path = shutil.which("tshark")
    if on_path:
        return on_path
    default = Path("C:/Program Files/Wireshark/tshark.exe")
    return str(default) if default.exists() else None


def retransmission_counts_tshark(pcap_path: str | Path, cfg: dict) -> pd.DataFrame:
    """Ground-truth retransmissions per (src_ip, window_id) via tshark (M2.2).

    Uses `tcp.analysis.retransmission` on the same window grid as the scapy
    path, so the two backends are directly comparable. Raises loudly when
    tshark is not installed — the scapy heuristic is the documented fallback,
    never a silent substitute for this function.
    """
    import subprocess

    tshark = find_tshark(cfg)
    if tshark is None:
        raise RuntimeError(
            "tshark not found — install Wireshark (or set packet_features.tshark_path) "
            "to run the M2.2 backend-agreement check"
        )

    result = subprocess.run(
        [tshark, "-r", str(pcap_path), "-Y", "tcp.analysis.retransmission",
         "-T", "fields", "-e", "frame.time_epoch", "-e", "ip.src",
         "-E", "separator=,"],
        capture_output=True, text=True, timeout=600,
    )
    if result.returncode != 0:
        raise RuntimeError(f"tshark failed on {pcap_path}: {result.stderr.strip()[:500]}")

    rows = []
    for line in result.stdout.splitlines():
        parts = line.strip().split(",")
        if len(parts) == 2 and parts[0] and parts[1]:
            rows.append((float(parts[0]), parts[1]))
    events = pd.DataFrame(rows, columns=["ts", "src_ip"])
    if events.empty:
        return pd.DataFrame(columns=["src_ip", "window_id", "retransmission_count"])

    exploded = _explode_to_windows(events, cfg)
    counts = (
        exploded.groupby(["src_ip", "window_id"]).size()
        .rename("retransmission_count").reset_index()
    )
    counts["window_id"] = counts["window_id"].astype(int)
    return counts


def assemble_flows(packets: pd.DataFrame, cfg: dict) -> pd.DataFrame:
    """Group packets into bidirectional flows; emit the canonical 23 columns.

    Direction: the endpoint that sent the first packet of the flow is the
    source. A quiet gap longer than flows.timeout_seconds splits the 5-tuple
    into a new flow. The label column is 'unlabeled' — labels come from the
    attack timeline at window-build time (M3), never from the extractor.
    """
    timeout = cfg["flows"]["timeout_seconds"]
    missing_win = cfg["flows"]["missing_init_win"]

    pk = packets.sort_values("ts", kind="stable").reset_index(drop=True).copy()
    pk["payload_len"] = pk["payload_len"].astype("int64")

    # Endpoint pair as numbers (uint32 ip << 16 | port), order-normalised.
    a_key = (pk["src_ip"].to_numpy("uint64") << 16) | pk["src_port"].to_numpy("uint64")
    b_key = (pk["dst_ip"].to_numpy("uint64") << 16) | pk["dst_port"].to_numpy("uint64")
    pk["_pair_lo"] = np.minimum(a_key, b_key)
    pk["_pair_hi"] = np.maximum(a_key, b_key)

    conn = pk.groupby(["_pair_lo", "_pair_hi", "protocol"], sort=False).ngroup()
    gap = pk.groupby(conn)["ts"].diff().fillna(0.0)
    split = (gap > timeout).groupby(conn).cumsum()
    pk["flow_key"] = pk.groupby([conn, split], sort=False).ngroup()

    # Direction: the first packet of each flow defines the (src, dst) endpoints.
    grp = pk.groupby("flow_key", sort=False)
    first = grp[["src_ip", "src_port", "dst_ip", "dst_port", "protocol", "ts"]].first()
    first_src = pk["flow_key"].map(first["src_ip"])
    first_sport = pk["flow_key"].map(first["src_port"])
    fwd = (pk["src_ip"] == first_src) & (pk["src_port"] == first_sport)

    pk["fwd_pkt"] = fwd.astype(int)
    pk["bwd_pkt"] = (~fwd).astype(int)
    pk["fwd_payload"] = pk["payload_len"].where(fwd, 0)
    pk["bwd_payload"] = pk["payload_len"].where(~fwd, 0)
    pk["iat"] = grp["ts"].diff()

    agg = grp.agg(
        ts_first=("ts", "first"),
        ts_last=("ts", "last"),
        fwd_bytes=("fwd_payload", "sum"),
        bwd_bytes=("bwd_payload", "sum"),
        fwd_pkts=("fwd_pkt", "sum"),
        bwd_pkts=("bwd_pkt", "sum"),
        syn=("syn", "sum"),
        ack=("ack", "sum"),
        fin=("fin", "sum"),
        rst=("rst", "sum"),
        psh=("psh", "sum"),
        urg=("urg", "sum"),
        iat_mean=("iat", "mean"),
        iat_max=("iat", "max"),
    )
    iat_std = grp["iat"].std(ddof=0)

    syn_rows = pk[pk["syn"] == 1]
    init_fwd = syn_rows[fwd.loc[syn_rows.index]].groupby("flow_key")["tcp_win"].first()
    init_bwd = syn_rows[~fwd.loc[syn_rows.index]].groupby("flow_key")["tcp_win"].first()

    out = pd.DataFrame(
        {
            "timestamp": pd.to_datetime(agg["ts_first"], unit="s"),
            "src_ip": ips_to_str(first["src_ip"]),
            "dst_ip": ips_to_str(first["dst_ip"]),
            "src_port": first["src_port"].astype(int),
            "dst_port": first["dst_port"].astype(int),
            "protocol": first["protocol"].astype(int),
            "duration": (agg["ts_last"] - agg["ts_first"]) * 1e6,  # microseconds, like CIC
            "fwd_bytes": agg["fwd_bytes"].astype(float),
            "bwd_bytes": agg["bwd_bytes"].astype(float),
            "fwd_pkts": agg["fwd_pkts"].astype(int),
            "bwd_pkts": agg["bwd_pkts"].astype(int),
            "syn": agg["syn"].astype(int),
            "ack": agg["ack"].astype(int),
            "fin": agg["fin"].astype(int),
            "rst": agg["rst"].astype(int),
            "psh": agg["psh"].astype(int),
            "urg": agg["urg"].astype(int),
            "iat_mean": (agg["iat_mean"] * 1e6).fillna(0.0),
            "iat_std": (iat_std * 1e6).fillna(0.0),
            "iat_max": (agg["iat_max"] * 1e6).fillna(0.0),
            "init_win_fwd": init_fwd.reindex(agg.index).fillna(missing_win).astype(int),
            "init_win_bwd": init_bwd.reindex(agg.index).fillna(missing_win).astype(int),
            "label": "unlabeled",
        }
    )

    canonical = list(cfg["schema"].keys())
    if list(out.columns) != canonical:
        raise ValueError("flow assembler drifted from the canonical schema")
    return out.sort_values("timestamp", kind="stable").reset_index(drop=True)
