"""M2: the packet/flow extractor — scan signatures (2.3), retransmissions and
fragments, canonical flow assembly, and flow/packet window-key parity (2.4).
The pcaps are written with scapy exactly like our own lab captures (2.5's
one-code-path requirement).
"""

from __future__ import annotations

import random

import pandas as pd

import pytest
from scapy.all import IP, TCP, Ether, wrpcap

from data import packet_features as pf

BASE_TS = 1_500_000_000.0
SRC = "10.0.0.5"
DST = "10.0.0.9"


def _pkt(ts, sport, dport, flags="S", seq=0, payload=b"", src=SRC, dst=DST, **ip_kwargs):
    pkt = (
        Ether(src="aa:aa:aa:aa:aa:aa", dst="bb:bb:bb:bb:bb:bb")
        / IP(src=src, dst=dst, ttl=64, **ip_kwargs)
        / TCP(sport=sport, dport=dport, flags=flags, seq=seq, window=8192)
        / payload
    )
    pkt.time = ts
    return pkt


def _extract(tmp_path, packets, cfg):
    tmp_path.mkdir(parents=True, exist_ok=True)
    path = tmp_path / "capture.pcap"
    wrpcap(str(path), packets)
    return pf.extract_packet_table(path, cfg)


def test_sequential_scan_separates_from_randomised_scan(tmp_path, data_cfg):
    seq_ports = list(range(2000, 2064))
    rand_ports = seq_ports.copy()
    random.Random(7).shuffle(rand_ports)

    sequential = [_pkt(BASE_TS + i * 0.05, 40000, p) for i, p in enumerate(seq_ports)]
    randomised = [_pkt(BASE_TS + i * 0.05, 40000, p) for i, p in enumerate(rand_ports)]

    feats_seq = pf.packet_window_features(_extract(tmp_path / "a", sequential, data_cfg), data_cfg)
    feats_rand = pf.packet_window_features(_extract(tmp_path / "b", randomised, data_cfg), data_cfg)

    row_seq = feats_seq[feats_seq["src_ip"] == SRC].iloc[0]
    row_rand = feats_rand[feats_rand["src_ip"] == SRC].iloc[0]

    assert row_seq["sequential_port_ratio"] > 0.95, "sequential scan must score ~1"
    assert row_rand["sequential_port_ratio"] < 0.2, "randomised scan must score ~0"
    assert row_seq["distinct_dst_ports"] == 64
    assert row_rand["port_entropy"] == pytest.approx(6.0), "64 unique ports = 6 bits"


def test_retransmissions_and_fragments_are_counted(tmp_path, data_cfg):
    packets = [
        _pkt(BASE_TS + 0.0, 40000, 80, flags="PA", seq=1000, payload=b"HELLO"),
        _pkt(BASE_TS + 0.2, 40000, 80, flags="PA", seq=1000, payload=b"HELLO"),  # retrans
        _pkt(BASE_TS + 0.4, 40000, 80, flags="PA", seq=1005, payload=b"WORLD"),
    ]
    frag = _pkt(BASE_TS + 0.8, 40001, 81, flags="A", seq=1, payload=b"X" * 8)
    frag[IP].flags = "MF"
    packets.append(frag)

    feats = pf.packet_window_features(_extract(tmp_path, packets, data_cfg), data_cfg)
    row = feats[(feats["src_ip"] == SRC) & (feats["window_id"] == feats["window_id"].max())]
    assert int(row["retransmission_count"].iloc[0]) == 1
    assert int(row["frag_flag_count"].iloc[0]) == 1


def test_flow_assembly_emits_canonical_schema_with_direction(tmp_path, data_cfg):
    conversation = [
        _pkt(BASE_TS + 0.00, 44000, 80, flags="S", seq=1),
        _pkt(BASE_TS + 0.01, 80, 44000, flags="SA", seq=9, src=DST, dst=SRC),
        _pkt(BASE_TS + 0.02, 44000, 80, flags="A", seq=2),
        _pkt(BASE_TS + 0.03, 44000, 80, flags="PA", seq=2, payload=b"GET / HTTP/1.1"),
        _pkt(BASE_TS + 0.05, 80, 44000, flags="PA", seq=10, payload=b"200 OK", src=DST, dst=SRC),
        _pkt(BASE_TS + 0.07, 44000, 80, flags="FA", seq=16),
    ]
    flows = pf.assemble_flows(_extract(tmp_path, conversation, data_cfg), data_cfg)

    assert list(flows.columns) == list(data_cfg["schema"].keys()), (
        "flow assembler must emit exactly the canonical schema"
    )
    assert len(flows) == 1, "one conversation must become one flow"
    flow = flows.iloc[0]
    assert flow["src_ip"] == SRC and flow["dst_ip"] == DST, "initiator defines direction"
    assert flow["fwd_pkts"] == 4 and flow["bwd_pkts"] == 2
    assert flow["fwd_bytes"] == 14 and flow["bwd_bytes"] == 6
    assert flow["syn"] == 2 and flow["fin"] == 1
    assert flow["init_win_fwd"] == 8192 and flow["init_win_bwd"] == 8192
    assert flow["duration"] == pytest.approx(0.07 * 1e6, rel=1e-3)


def test_idle_timeout_splits_a_5tuple_into_two_flows(tmp_path, data_cfg):
    timeout = data_cfg["flows"]["timeout_seconds"]
    packets = [
        _pkt(BASE_TS, 44000, 80, flags="PA", seq=1, payload=b"one"),
        _pkt(BASE_TS + timeout + 5, 44000, 80, flags="PA", seq=50, payload=b"two"),
    ]
    flows = pf.assemble_flows(_extract(tmp_path, packets, data_cfg), data_cfg)
    assert len(flows) == 2, "an idle gap beyond the timeout must split the flow"


def test_flow_and_packet_window_keys_align_with_no_silent_loss(tmp_path, data_cfg):
    packets = [
        _pkt(BASE_TS + i, 44000 + i, 80 + i, flags="S", seq=i) for i in range(0, 40, 7)
    ]
    table = _extract(tmp_path, packets, data_cfg)
    flows = pf.assemble_flows(table, data_cfg)
    feats = pf.packet_window_features(table, data_cfg)

    packet_keys = set(zip(feats["src_ip"], feats["window_id"]))
    flow_start = flows["timestamp"].map(pd.Timestamp.timestamp)  # -> epoch seconds
    for ids in pf.window_ids_for(flow_start, data_cfg):
        for src_ip, window_id in zip(flows["src_ip"], ids):
            assert (src_ip, int(window_id)) in packet_keys, (
                f"flow window ({src_ip}, {window_id}) missing on the packet side"
            )


def test_scapy_and_tshark_retransmission_counts_agree(tmp_path, data_cfg):
    """M2.2: both backends must give the same count on the fixture. Skips (loudly)
    until Wireshark is installed on this machine — never silently substituted."""
    if pf.find_tshark(data_cfg) is None:
        pytest.skip("tshark not installed — install Wireshark to run the M2.2 agreement check")

    packets = [
        _pkt(BASE_TS + 0.0, 40000, 80, flags="PA", seq=1000, payload=b"HELLO"),
        _pkt(BASE_TS + 0.3, 40000, 80, flags="PA", seq=1000, payload=b"HELLO"),  # retrans
        _pkt(BASE_TS + 0.6, 40000, 80, flags="PA", seq=1005, payload=b"WORLD"),
        _pkt(BASE_TS + 0.9, 40001, 443, flags="S", seq=7),
    ]
    pcap_dir = tmp_path / "agree"
    table = _extract(pcap_dir, packets, data_cfg)

    scapy_counts = (
        pf.packet_window_features(table, data_cfg)
        .set_index(["src_ip", "window_id"])["retransmission_count"]
    )
    tshark_counts = (
        pf.retransmission_counts_tshark(pcap_dir / "capture.pcap", data_cfg)
        .set_index(["src_ip", "window_id"])["retransmission_count"]
    )

    scapy_nonzero = scapy_counts[scapy_counts > 0].sort_index()
    tshark_nonzero = tshark_counts[tshark_counts > 0].sort_index()
    assert scapy_nonzero.to_dict() == tshark_nonzero.to_dict(), (
        "scapy heuristic and tshark disagree on the fixture's retransmissions"
    )


def test_pcapng_members_parse_identically_to_pcap(tmp_path, data_cfg):
    """Two of the real 16-02 members are pcapng; the dissecting-reader bug that
    crashed on them stays fixed: both container formats parse to equal tables."""
    from scapy.utils import PcapNgWriter

    packets = [
        _pkt(BASE_TS + 0.0, 44000, 80, flags="S", seq=1),
        _pkt(BASE_TS + 0.2, 44000, 80, flags="PA", seq=2, payload=b"payload"),
        _pkt(BASE_TS + 0.4, 44000, 443, flags="S", seq=3),
    ]
    classic = _extract(tmp_path, packets, data_cfg)

    ng_path = tmp_path / "capture.pcapng"
    writer = PcapNgWriter(str(ng_path))
    for p in packets:
        writer.write(p)
    writer.close()
    assert ng_path.read_bytes()[:4] == b"\x0a\x0d\x0d\x0a", "fixture must be real pcapng"
    ng = pf.extract_packet_table(ng_path, data_cfg)

    pd.testing.assert_frame_equal(classic, ng)
