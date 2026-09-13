"""M2: the packet/flow extractor — scan signatures (2.3), retransmissions and
fragments, canonical flow assembly, and flow/packet window-key parity (2.4).
The pcaps are written with scapy exactly like our own lab captures (2.5's
one-code-path requirement).
"""

from __future__ import annotations

import random

import pandas as pd

import pytest
from scapy.all import ARP, IP, IPv6, TCP, Dot1Q, Ether, wrpcap

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


def _v6_pkt(ts, sport, dport, src="2001:db8::5", dst="2001:db8::9"):
    pkt = (
        Ether(src="aa:aa:aa:aa:aa:aa", dst="bb:bb:bb:bb:bb:bb")
        / IPv6(src=src, dst=dst, hlim=64)
        / TCP(sport=sport, dport=dport, flags="S", window=8192)
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


def _random_packet_table(n, n_hosts=6, seed=3):
    """A synthetic parsed-packet table shaped like extract_packet_table output."""
    import numpy as np

    rng = np.random.default_rng(seed)
    hosts = (0x0A000000 + rng.integers(1, 250, n_hosts)).astype("uint32")  # 10.0.0.x
    df = pd.DataFrame(
        {
            "ts": BASE_TS + np.sort(rng.uniform(0, 120, n)),
            "src_ip": rng.choice(hosts, n),
            "dst_ip": rng.choice(hosts, n),
            "src_port": rng.integers(1024, 65535, n).astype("uint16"),
            "dst_port": rng.choice(
                np.concatenate([np.arange(2000, 2032), [80, 443]]), n
            ).astype("uint16"),
            "protocol": rng.choice(np.array([6, 6, 6, 17], dtype="uint8"), n),
            "ttl": rng.choice(np.array([32, 64, 128], dtype="uint8"), n),
            "tcp_win": rng.integers(0, 65535, n).astype("uint16"),
            "is_frag": (rng.random(n) < 0.02).astype("uint8"),
            "payload_len": rng.choice(
                np.array([0, 40, 100, 512, 1460, 3000], dtype="uint32"), n
            ),
            "is_retrans": (rng.random(n) < 0.05).astype("uint8"),
        }
    )
    for flag in ("syn", "ack", "fin", "rst", "psh", "urg"):
        df[flag] = (rng.random(n) < 0.3).astype("uint8")
    return df


def test_bin_composed_features_equal_reference_implementation(data_cfg):
    table = _random_packet_table(50_000)
    composed = pf.packet_window_features(table, data_cfg)
    reference = pf._packet_window_features_reference(table, data_cfg)

    composed = composed[sorted(composed.columns)].reset_index(drop=True)
    reference = reference[sorted(reference.columns)].reset_index(drop=True)
    pd.testing.assert_frame_equal(
        composed, reference, check_dtype=False, rtol=1e-9, atol=1e-9
    )


def test_partitioned_flow_assembly_equals_direct(data_cfg):
    table = _random_packet_table(30_000, seed=11)
    direct = pf.assemble_flows(table, data_cfg)
    # force ~15 partitions via config (flows.partition_rows), not a module patch
    small_parts = {**data_cfg, "flows": {**data_cfg["flows"], "partition_rows": 2_000}}
    partitioned = pf.assemble_flows(table, small_parts)

    key = ["timestamp", "src_ip", "dst_ip", "src_port", "dst_port", "protocol"]
    direct = direct.sort_values(key, kind="stable").reset_index(drop=True)
    partitioned = partitioned.sort_values(key, kind="stable").reset_index(drop=True)
    pd.testing.assert_frame_equal(direct, partitioned, check_dtype=False)


def test_non_first_fragment_is_not_parsed_as_l4(tmp_path, data_cfg):
    """Fix: a fragment with offset > 0 carries datagram payload at the L4
    position; parsing it fabricates ports/flags/window from payload bytes."""
    payload = bytes([0x5A]) * 40  # 'Z' bytes would decode to port 23130, phantom flags
    frag = Ether() / IP(src=SRC, dst=DST, proto=6, flags=0, frag=100) / payload
    frag.time = BASE_TS
    table = _extract(tmp_path, [frag], data_cfg)

    assert len(table) == 1
    row = table.iloc[0]
    assert row["src_port"] == 0 and row["dst_port"] == 0, "later fragment must not yield ports"
    assert row["tcp_win"] == 0
    assert int(row["syn"]) == int(row["ack"]) == int(row["fin"]) == 0, "no phantom flags"
    assert int(row["is_frag"]) == 1
    assert int(row["payload_len"]) == 40, "all IP payload bytes count as payload"

    feats = pf.packet_window_features(table, data_cfg)
    frow = feats[feats["src_ip"] == SRC].iloc[0]
    assert int(frow["distinct_dst_ports"]) == 1, "phantom port must not inflate distinct ports"
    assert float(frow["tcp_win_mean"]) == 0.0


def test_retransmission_backend_dispatch(tmp_path, data_cfg):
    """Fix: retransmission_backend is now read. scapy passes counts through;
    tshark falls back to scapy when Wireshark is absent; junk raises."""
    packets = [
        _pkt(BASE_TS, 40000, 80, flags="PA", seq=1, payload=b"x"),
        _pkt(BASE_TS + 0.1, 40000, 80, flags="PA", seq=1, payload=b"x"),  # retrans
    ]
    table = _extract(tmp_path, packets, data_cfg)
    feats = pf.packet_window_features(table, data_cfg)
    pcap = tmp_path / "capture.pcap"

    out, backend = pf.apply_retransmission_backend(feats, pcap, data_cfg)
    assert backend == "scapy"
    pd.testing.assert_frame_equal(out, feats)

    def with_backend(name):
        return {**data_cfg, "packet_features": {**data_cfg["packet_features"],
                                                "retransmission_backend": name}}

    tshark_cfg = with_backend("tshark")
    _, backend2 = pf.apply_retransmission_backend(feats, pcap, tshark_cfg)
    assert backend2 in ("tshark", "scapy-fallback")
    if pf.find_tshark(tshark_cfg) is None:
        assert backend2 == "scapy-fallback", "no Wireshark -> documented scapy fallback"

    with pytest.raises(ValueError, match="unknown retransmission_backend"):
        pf.apply_retransmission_backend(feats, pcap, with_backend("bogus"))


def test_m24_join_has_no_silent_row_loss(tmp_path, data_cfg):
    """BUILD_PLAN M2.4 acceptance: an explicit row-count assertion on the
    flow/packet-window join — every flow's start window resolves to a real
    packet-side host-window, counted, not merely membership-checked."""
    packets = [
        _pkt(BASE_TS + i, 44000 + i, 80 + i, flags="S", seq=i) for i in range(0, 40, 7)
    ]
    table = _extract(tmp_path, packets, data_cfg)
    flows = pf.assemble_flows(table, data_cfg)
    feats = pf.packet_window_features(table, data_cfg)

    packet_keys = set(zip(feats["src_ip"], feats["window_id"]))
    flow_start = flows["timestamp"].map(pd.Timestamp.timestamp)
    start_windows = pf.window_ids_for(flow_start, data_cfg)[-1]  # the flow-start window
    joined = sum(
        (src_ip, int(w)) in packet_keys for src_ip, w in zip(flows["src_ip"], start_windows)
    )
    assert joined == len(flows), (
        f"{len(flows) - joined} of {len(flows)} flows lost their packet-side window in the join"
    )


def test_ipv6_scan_is_counted_not_silently_dropped(tmp_path, data_cfg):
    """The parser is IPv4-only, so an IPv6 scan produces ZERO feature rows. The
    frames must still be COUNTED: an uncounted drop means the tool reports "no
    threat" for traffic it never saw — the worst failure mode a security tool
    has. Full IPv6 feature support is not implemented — docs/limitations.md §5,
    whose text test_the_ipv6_limitation_citation_points_at_text_that_exists
    pins so this reference cannot rot into a claim the doc does not make."""
    scan = [_v6_pkt(BASE_TS + i * 0.05, 40000, 2000 + i) for i in range(200)]
    table = _extract(tmp_path, scan, data_cfg)

    assert len(table) == 0, "IPv4-only parser must not invent IPv6 rows"
    drops = pf.dropped_frames(table)
    assert drops["ipv6"] == 200, f"every IPv6 frame must be counted: {drops}"
    assert sum(drops.values()) == 200


def test_every_frame_is_either_a_row_or_a_counted_drop(tmp_path, data_cfg):
    """The accounting identity: rows + drops = frames read. No third outcome."""
    ipv4 = [_pkt(BASE_TS + i * 0.05, 40000, 80 + i) for i in range(5)]
    ipv6 = [_v6_pkt(BASE_TS + 1 + i * 0.05, 40000, 443) for i in range(3)]
    arp = Ether(src="aa:aa:aa:aa:aa:aa", dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=DST)
    arp.time = BASE_TS + 2
    runt = Ether(src="aa:aa:aa:aa:aa:aa", dst="bb:bb:bb:bb:bb:bb") / (b"\x00" * 4)
    runt.time = BASE_TS + 3

    table = _extract(tmp_path, ipv4 + ipv6 + [arp, runt], data_cfg)
    drops = pf.dropped_frames(table)

    assert len(table) == 5
    assert drops == {"short_frame": 1, "ipv6": 3, "non_ipv4_ethertype": 1,
                     "truncated_ip_header": 0}
    assert len(table) + sum(drops.values()) == 10, "a frame must never just vanish"


def test_the_ipv6_limitation_citation_points_at_text_that_exists():
    """A citation to a document that does not make the claim is the drift this
    suite exists to catch: the IPv6 gap was cited to docs/limitations.md while
    that file said nothing about IPv6. This pins the reference to real text."""
    from configs import resolve_path

    doc = resolve_path("docs/limitations.md").read_text(encoding="utf-8")
    heading = next((line for line in doc.splitlines()
                    if line.startswith("## ") and "IPv6" in line), None)
    assert heading and heading.startswith("## 5."), (
        "docs/limitations.md §5 must be the IPv6/ethertype section the extractor "
        f"and its tests cite; found {heading!r}"
    )
    for claim in ("IPv6", "DROP_REASONS", "unparsed_frames"):
        assert claim in doc, f"docs/limitations.md no longer states {claim!r}"


def test_a_lost_drop_history_reads_as_unknown_not_as_zero_drops(tmp_path, data_cfg):
    """The counter's own failure mode: the counts ride on `.attrs`, which pandas
    keeps only while every input carries the same ones. A table that lost them
    must answer None — "I do not know" — because an empty dict would be read
    downstream as "every frame was parsed", the silent success this feature
    exists to prevent."""
    table = _extract(tmp_path, [_pkt(BASE_TS, 40000, 80), _v6_pkt(BASE_TS + 0.1, 40000, 443)],
                     data_cfg)
    assert pf.dropped_frames(table) == {"short_frame": 0, "ipv6": 1,
                                        "non_ipv4_ethertype": 0, "truncated_ip_header": 0}

    plain = pd.DataFrame({"ts": table["ts"], "extra": 1})  # no drop history of its own
    for lost in (table.merge(plain, on="ts"),
                 pd.concat([table, plain], ignore_index=True),
                 table.groupby("src_ip", as_index=False).size(),
                 pd.DataFrame({c: table[c] for c in table.columns})):
        assert pf.dropped_frames(lost) is None, (
            "a table with no drop history must not claim zero drops"
        )


def test_vlan_tagged_ipv4_still_parses_while_tagged_ipv6_is_counted(tmp_path, data_cfg):
    """The VLAN unwrap must not turn a counted drop into a silent one."""

    def tagged(ts, l3):
        pkt = (Ether(src="aa:aa:aa:aa:aa:aa", dst="bb:bb:bb:bb:bb:bb")
               / Dot1Q(vlan=10) / l3 / TCP(sport=40000, dport=80, flags="S"))
        pkt.time = ts
        return pkt

    table = _extract(
        tmp_path,
        [tagged(BASE_TS, IP(src=SRC, dst=DST, ttl=64)),
         tagged(BASE_TS + 0.1, IPv6(src="2001:db8::5", dst="2001:db8::9"))],
        data_cfg,
    )
    assert len(table) == 1 and table.iloc[0]["dst_port"] == 80
    assert pf.dropped_frames(table)["ipv6"] == 1


@pytest.mark.skipif(
    not __import__("configs").resolve_path("app/assets/synthetic_demo.pcap").exists(),
    reason="synthetic demo pcap not built — run python -m capture.make_synthetic_demo",
)
def test_extraction_is_deterministic_on_the_bundled_capture(data_cfg):
    """Enforced determinism is a headline claim, so it needs a test. This is the
    artifact-free half: parsing and feature assembly on the committed demo
    capture must be bit-identical across runs (no set/dict ordering, no
    unseeded RNG). The model half needs trained weights and is covered by the
    artifact-gated engine tests."""
    from configs import resolve_path

    pcap = resolve_path("app/assets/synthetic_demo.pcap")
    first, second = (pf.extract_packet_table(pcap, data_cfg) for _ in range(2))
    pd.testing.assert_frame_equal(first, second, check_exact=True)
    assert pf.dropped_frames(first) == pf.dropped_frames(second)

    for fn in (pf.packet_window_features, pf.sent_window_features):
        pd.testing.assert_frame_equal(fn(first, data_cfg), fn(second, data_cfg),
                                      check_exact=True)
    pd.testing.assert_frame_equal(pf.assemble_flows(first, data_cfg),
                                  pf.assemble_flows(second, data_cfg), check_exact=True)


def test_sent_window_features_equal_reference(data_cfg):
    table = _random_packet_table(50_000)
    composed = pf.sent_window_features(table, data_cfg)
    reference = pf._sent_window_features_reference(table, data_cfg)
    composed = composed[sorted(composed.columns)].reset_index(drop=True)
    reference = reference[sorted(reference.columns)].reset_index(drop=True)
    pd.testing.assert_frame_equal(composed, reference, check_dtype=False, rtol=1e-9, atol=1e-9)


def test_sent_features_are_window_bounded_not_whole_flow(tmp_path, data_cfg):
    """The decision-003 fix: a long flow's bytes land in the windows its PACKETS
    fall in, never summed wholesale into the start window."""
    # 3 packets from one host, 20 s apart => different (non-overlapping) windows.
    packets = [
        _pkt(BASE_TS + 0.0, 40000, 80, flags="PA", seq=1, payload=b"A" * 100),
        _pkt(BASE_TS + 20.0, 40000, 80, flags="PA", seq=101, payload=b"B" * 100),
        _pkt(BASE_TS + 40.0, 40000, 80, flags="PA", seq=201, payload=b"C" * 100),
    ]
    table = _extract(tmp_path, packets, data_cfg)
    sent = pf.sent_window_features(table, data_cfg)
    by_window = sent.groupby("window_id")["sent_bytes"].sum()
    # no single window may hold all 300 bytes — each packet is bounded to its own windows
    assert by_window.max() < 300, "a window must not accumulate bytes from packets outside it"
    assert sent["sent_bytes"].sum() >= 300  # each packet counted in its overlapping windows
