"""Adversarial evasion bench: what a cheap evasion COSTS the attacker, measured
beside what it BUYS against this repo's own features.

    python -m eval.evasion --pcap app/assets/synthetic_demo.pcap

`docs/threat_model.md` §3 measures this family of evasions on hand-built
synthetic frames. This module runs them end to end on a real capture: parse the
pcap with the production extractor, apply one named transformation to the
packets the ATTACKER originates, re-extract every feature through the unmodified
`data/packet_features.py`, and report both halves of the trade — the operational
cost (campaign span, packets on the wire, bytes delivered, destinations reached)
next to the benefit (the feature values that moved, and the stage
`engine/predict.py`'s rules then infer).

Both halves, or it is a self-own. A table of features that collapse says nothing
until it also says what the attacker paid. Randomising your own TTL is free.
Pacing 15x means a 15x longer campaign against a defender who is still watching.
Those are not the same finding, and a defence that cannot tell them apart cannot
prioritise anything. §5 of the generated document is the other direction — the
features that did NOT move, because moving them means not doing the attack.

WHERE THE TRANSFORM IS APPLIED. A transformation rewrites the per-packet table
`extract_packet_table` emits: the timestamp, TTL, TCP window, destination port
and payload length of the attacker's own packets. Every one of those is a field
that attacker's stack writes, so rewriting them models a choice the attacker
really has. Everything downstream — `packet_window_features`,
`sent_window_features`, `engine.predict._infer_stage` — is production code,
called unmodified. `write_packet_table_pcap` closes the remaining gap by
re-emitting a transformed table as a real pcap; re-parsing that file has to
reproduce the same features, which is checked rather than asserted
(`tests/test_evasion.py::test_a_transformed_table_survives_a_pcap_round_trip`).

WHAT THIS DOES NOT MEASURE. The trained engine's score. That needs
`artifacts/engine_model.json` + `window_scaler.pkl`, which are gitignored and
absent from a fresh clone, so every model-score effect is TBD — reported as TBD
with the command that would produce it, never as a zero that reads like a
measurement. `model_scoring_status` is what prints that line, and it says
"runnable" only when the files are actually on disk.

Determinism: every randomised transform draws from `numpy.default_rng(seed)`
with `seed` defaulting to `configs/data.yaml`'s `seed`, one fresh generator per
variant, consumed in the documented primitive order. Same capture + same seed =
same table, which is what lets `docs/evasion.md` publish digits.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import ipaddress
import json
import sys
from dataclasses import dataclass
from pathlib import Path

import numpy as np
import pandas as pd

from configs import load_config

# The sidecar that names who attacked, written beside the capture by
# capture/capture.sh and capture/make_synthetic_demo.py. Reading it (rather than
# hardcoding an address) is what makes this bench run on any labelled capture —
# and the parser is capture.label_capture's, not a second one.
OPERATOR_LOG_SUFFIX = ".operator-log.txt"

# Protocol numbers the pcap writer can reconstruct. The extractor parses more
# than this (it counts every IPv4 frame); the writer refuses what it cannot
# re-emit faithfully instead of emitting an approximation.
_PROTO_TCP = 6
_PROTO_UDP = 17

# Artifacts the trained-model score would need. Named here so the TBD line can
# say WHICH file is missing rather than "artifacts absent".
MODEL_ARTIFACTS = ("engine_model.json", "window_scaler.pkl")

# Fixed link-layer addresses for the writer. A bare `Ether()` makes scapy try to
# resolve a MAC for the destination, which reaches for the network stack (and is
# slow); the parser reads only the ethertype at offset 12, so the values are
# irrelevant to every feature. tests/test_engine.py pins its own frames the same
# way, and this repo has to stay runnable with sockets blocked (test_offline.py).
_WRITER_SRC_MAC = "02:00:00:00:00:01"
_WRITER_DST_MAC = "02:00:00:00:00:02"

SCORING_COMMAND = (
    'python -c "from engine import predict; '
    "r = predict.predict_file(PCAP, out_dir=OUT); print(r['n_alerts'])\""
)


# ---------------------------------------------------------------------------
# Who is the attacker
# ---------------------------------------------------------------------------


def operator_log_for(pcap_path: str | Path) -> Path:
    """The sidecar operator log beside a capture (`x.pcap` -> `x.operator-log.txt`)."""
    return Path(pcap_path).with_suffix(OPERATOR_LOG_SUFFIX)


def attackers_from_operator_log(pcap_path: str | Path, capture_date: str) -> list[str]:
    """Attacker addresses declared in the capture's operator log.

    Parsed by `capture.label_capture.parse_operator_log` — the same parser the
    labelling path uses, so a log this bench accepts is a log the labeller
    accepts (and a bad stage name fails here too). `capture_date` is taken from
    the capture's own first timestamp by the caller, so the timeline the parser
    builds is the real one rather than a placeholder.
    """
    from capture.label_capture import parse_operator_log

    log = operator_log_for(pcap_path)
    if not log.exists():
        raise FileNotFoundError(
            f"no operator log at {log} — this bench transforms only the packets the "
            "ATTACKER sends, so it has to be told who that is. Either put the "
            "sidecar log beside the capture (see capture/attack_scenarios.md) or "
            "pass --attacker <ip> explicitly."
        )
    timeline = parse_operator_log(log, capture_date)
    ips: list[str] = []
    for day in timeline["days"]:
        for attack in day["attacks"]:
            for ip in attack["attacker_ips"]:
                if ip not in ips:
                    ips.append(ip)
    if not ips:
        raise ValueError(
            f"{log} declares no attacker_ip on any row — nothing to transform. "
            "Pass --attacker <ip> if the log cannot carry it."
        )
    return ips


def capture_date(packets: pd.DataFrame) -> str:
    """UTC date of the capture's first packet, as the operator-log parser wants it."""
    first = float(packets["ts"].min())
    return _dt.datetime.fromtimestamp(first, tz=_dt.timezone.utc).strftime("%Y-%m-%d")


def is_internal(ip: str, cfg: dict) -> bool:
    """`internal` exactly as `data.anonymize.Anonymizer.is_internal` computes it.

    Deliberately key-free. The Anonymizer refuses to construct without
    SIH26_HMAC_KEY (correctly — its pseudonyms and `net24_bucket` are keyed), but
    `internal` is pure set-membership in `anonymisation.internal_networks` and the
    stage rules read it. Computing it here keeps the stage column identical with
    and without a key in the environment, instead of silently flipping an
    internal scan from lateral_movement to recon on a machine that has no key.
    `net24_bucket` is NOT computed: no stage rule reads it, and inventing a zero
    for it would be exactly the fabricated feature value this project bans.
    `tests/test_evasion.py::test_internal_matches_the_production_anonymizer` pins
    this against the real implementation.
    """
    addr = ipaddress.ip_address(str(ip))
    return any(
        addr in ipaddress.ip_network(net) for net in cfg["anonymisation"]["internal_networks"]
    )


# ---------------------------------------------------------------------------
# Primitive transformations — each rewrites fields the attacker's own stack sets
# ---------------------------------------------------------------------------


def _attacker_mask(table: pd.DataFrame, attackers: set[int]) -> np.ndarray:
    """Rows the attacker ORIGINATED. Scoped by source address on purpose: a
    victim's replies are not the attacker's to shape, and a host that appears as
    both (a pivot the attacker owns) originates everything from that box once it
    is compromised."""
    return table["src_ip"].isin(attackers).to_numpy()


# Scope of the port permutation. The destination port is chosen by whatever
# process owns the source port, so (src_ip, dst_ip, src_port) is one of the
# attacker's own sockets: permuting inside it reorders one sweep's port list and
# nothing else. The coarser (src_ip, dst_ip) scope is wrong and measurably so —
# on the bundled capture it shuffles the recon sweep's 800 ports into the SSH
# brute force's packets, turning the brute force into a port scan and then
# reporting that relabelling as an evasion win.
#
# `reach` does NOT catch that (permuting inside one peer leaves the
# (dst_ip, dst_port) multiset intact, which was checked by widening the scope and
# watching the invariant hold). `sockets` does, which is why Measurement carries
# both: reach is the target surface, sockets is which connection reached it.
_PORT_PERMUTATION_SCOPE = ("src_ip", "dst_ip", "src_port")


def port_random(table: pd.DataFrame, attackers: set[int], cfg: dict, rng, **_) -> pd.DataFrame:
    """Randomise the ORDER of the attacker's destination ports (nmap default vs `-r`).

    Permuted within each of the attacker's own sockets (`_PORT_PERMUTATION_SCOPE`),
    so the multiset of (destination, port) the campaign touches is bit-for-bit
    identical, each sweep still contacts exactly the ports it contacted, and only
    the order changes.

    Known limitation, stated because it bounds the result: a scanner that draws a
    fresh ephemeral source port for every probe puts each packet in its own group
    and this transform becomes a no-op on it. Refusing to guess which packets
    belong to the same sweep is the cost of not inventing a grouping — a real
    attacker knows its own sweep and reorders it for free regardless.
    """
    out = table.copy()
    ports = out["dst_port"].to_numpy().copy()
    idx = np.flatnonzero(_attacker_mask(out, attackers))
    if len(idx):
        groups = out.iloc[idx].groupby(list(_PORT_PERMUTATION_SCOPE), sort=True).indices
        for key in sorted(groups):
            g = idx[groups[key]]
            ports[g] = ports[rng.permutation(g)]
    out["dst_port"] = ports.astype(table["dst_port"].dtype)
    return out


def pace(table: pd.DataFrame, attackers: set[int], cfg: dict, rng, factor: float = 1.0,
         **_) -> pd.DataFrame:
    """Stretch the attacker's inter-packet timing by `factor`, anchored at that
    host's first packet, leaving every other host's timing untouched.

    This is the one transformation with a real price: the same campaign now
    occupies `factor` times as much wall clock, and the `span_s` column prices
    it. Every per-window aggregate is a rate (decision 003 made every feature
    window-bounded), so dividing the rate by `factor` divides the per-window
    evidence while the threshold stays where it was fitted.
    """
    out = table.copy()
    ts = out["ts"].to_numpy(dtype=float).copy()
    idx = np.flatnonzero(_attacker_mask(out, attackers))
    if len(idx):
        groups = out.iloc[idx].groupby("src_ip", sort=True).indices
        for key in sorted(groups):
            g = idx[groups[key]]
            t0 = ts[g].min()
            ts[g] = t0 + (ts[g] - t0) * float(factor)
    out["ts"] = ts
    return out


def pad_payload(table: pd.DataFrame, attackers: set[int], cfg: dict, rng,
                target_bin: int = 3, **_) -> pd.DataFrame:
    """Re-chunk the attacker's payloads across the PUBLISHED histogram bin edges.

    `payload_hist_bin_edges` is a committed config value, so an attacker who read
    the repo knows exactly where the walls are. Each payload above `target_bin`
    is split into the FEWEST equal-ish chunks whose size lands inside that bin;
    the split is exact (`len // n` with the remainder spread one byte at a time),
    so bytes delivered is preserved to the byte rather than approximately.

    Chunks inherit the parent packet's timestamp, so the histogram shift is
    measured in isolation from any timing change — and they inherit its
    `is_retrans` flag, because the writer cannot know whether a real stack would
    have retransmitted a chunk (see the retransmission note in docs/evasion.md).

    The price is on the wire: n chunks means n packets and n headers, which
    `sent_pkts` sees. Only `target_bin` is this experiment's own choice; the
    edges themselves come from configs/data.yaml.
    """
    edges = list(cfg["packet_features"]["payload_hist_bin_edges"])
    if not 0 <= target_bin < len(edges) - 1:
        raise ValueError(
            f"pad target bin {target_bin} is outside the configured edges {edges} "
            f"(bins 0..{len(edges) - 2})"
        )
    lo, hi = int(edges[target_bin]), int(edges[target_bin + 1])

    lengths = table["payload_len"].to_numpy(dtype=np.int64)
    sel = _attacker_mask(table, attackers) & (lengths >= hi)
    n_chunks = np.ones(len(table), dtype=np.int64)
    # Smallest n with ceil(len / n) < hi.
    n_chunks[sel] = (lengths[sel] - 1) // (hi - 1) + 1

    rep = np.repeat(np.arange(len(table), dtype=np.int64), n_chunks)
    out = table.iloc[rep].copy()
    starts = np.repeat(np.cumsum(n_chunks) - n_chunks, n_chunks)
    k = np.arange(len(rep), dtype=np.int64) - starts
    parent_len, parent_n = lengths[rep], n_chunks[rep]
    sizes = parent_len // parent_n + (k < (parent_len % parent_n))

    split = parent_n > 1
    if split.any() and int(sizes[split].min()) < lo:
        raise ValueError(
            f"equal chunks cannot land in bin {target_bin} = [{lo}, {hi}): the "
            f"smallest chunk is {int(sizes[split].min())} B. Pick a target bin whose "
            "edges the payload sizes in this capture can actually divide into."
        )
    out["payload_len"] = sizes.astype(table["payload_len"].dtype)
    return out.reset_index(drop=True)


def ttl_random(table: pd.DataFrame, attackers: set[int], cfg: dict, rng,
               ttl_low: int = 32, ttl_high: int = 65, **_) -> pd.DataFrame:
    """Randomise the attacker's OWN IP TTL field. Costs nothing whatsoever.

    The range matches docs/threat_model.md §3.1 so the two documents measure the
    same adversary; `--ttl-range` overrides it. The receiver never sees the
    sender's choice as anomalous — a TTL is just a number the sending stack
    writes into a header field it owns.
    """
    out = table.copy()
    idx = np.flatnonzero(_attacker_mask(out, attackers))
    if len(idx):
        ttl = out["ttl"].to_numpy().copy()
        ttl[idx] = rng.integers(int(ttl_low), int(ttl_high), size=len(idx))
        out["ttl"] = ttl.astype(table["ttl"].dtype)
    return out


def win_random(table: pd.DataFrame, attackers: set[int], cfg: dict, rng,
               win_low: int = 8192, win_high: int = 65536, **_) -> pd.DataFrame:
    """Randomise the attacker's advertised TCP window. One socket option.

    Applied to the attacker's TCP packets only: `tcp_win` is meaningless on a
    UDP row and `packet_window_features` masks non-TCP out of `tcp_win_mean` /
    `tcp_win_var` anyway, so writing a window onto a UDP packet would be
    fabricating a field that does not exist on the wire.
    """
    out = table.copy()
    idx = np.flatnonzero(
        _attacker_mask(out, attackers) & (out["protocol"].to_numpy() == _PROTO_TCP)
    )
    if len(idx):
        win = out["tcp_win"].to_numpy().copy()
        win[idx] = rng.integers(int(win_low), int(win_high), size=len(idx))
        out["tcp_win"] = win.astype(table["tcp_win"].dtype)
    return out


_PRIMITIVES = {
    "port_random": port_random,
    "pace": pace,
    "pad_payload": pad_payload,
    "ttl_random": ttl_random,
    "win_random": win_random,
}


# ---------------------------------------------------------------------------
# Named variants — the experiment definitions
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Variant:
    """One named evasion: the primitives it applies, and its price in plain terms.

    `cost` is prose on purpose. The measured columns price the campaign
    (`span_s`, `pkts`, `bytes`, `reach`); this sentence says what that price
    means to someone running the attack, which is the half a feature table
    cannot express.
    """

    name: str
    steps: tuple[tuple[str, dict], ...]
    cost: str


# Order inside `combined` is deliberate: ports are permuted BEFORE payloads are
# re-chunked (so chunks inherit the port their parent packet was already going
# to), header fields are set per packet, and pacing runs last because it only
# moves timestamps and must not be re-scaled by a later step.
VARIANTS: tuple[Variant, ...] = (
    Variant("baseline", (), "nothing - the campaign as captured"),
    Variant("port_random", (("port_random", {}),),
            "free. One nmap flag; the same hosts and ports are touched, in a "
            "different order"),
    Variant("pace_5x", (("pace", {"factor": 5.0}),),
            "a 5x longer campaign - 5x more wall clock exposed to a defender"),
    Variant("pace_15x", (("pace", {"factor": 15.0}),),
            "a 15x longer campaign; the single most expensive evasion here"),
    Variant("pad_payload", (("pad_payload", {}),),
            "more packets and headers for identical bytes delivered; ~zero in "
            "time, a small constant in bandwidth"),
    Variant("ttl_random", (("ttl_random", {}),),
            "free. A field the attacker's own stack writes"),
    Variant("win_random", (("win_random", {}),),
            "free. One setsockopt on the attacker's own socket"),
    Variant("combined", (("port_random", {}), ("pad_payload", {}),
                         ("ttl_random", {}), ("win_random", {}),
                         ("pace", {"factor": 15.0})),
            "dominated by the pacing: a 15x longer campaign. Everything else "
            "stacked on top is free"),
)

VARIANTS_BY_NAME = {v.name: v for v in VARIANTS}


# ---------------------------------------------------------------------------
# Measurement
# ---------------------------------------------------------------------------


def stage_order(cfg: dict) -> tuple[str, ...]:
    """The stage vector's column order: configs/data.yaml `stages` (whose list
    order IS the label encoding) then `unclassified`, which is not one of the
    seven and never becomes one."""
    from engine.predict import UNCLASSIFIED_STAGE

    return (*cfg["stages"], UNCLASSIFIED_STAGE)


@dataclass(frozen=True)
class Measurement:
    """One variant's row: what it cost, then what it bought.

    Cost is measured on the wire over the attacker's own packets; benefit is
    measured over the attacker's (host, window) feature rows. `hist` and
    `stages` are vectors so a new bin or a new stage cannot appear without
    changing a published figure.
    """

    variant: str
    cost: str
    # cost, on the wire
    span_s: float
    pkts: int
    bytes: int
    reach: int      # distinct (dst_ip, dst_port) — the target surface
    sockets: int    # distinct (dst_ip, src_port, dst_port) — which connection reached it
    # benefit, in the features
    windows: int
    ttl_var: float
    win_var: float
    seq_ratio: float
    peak_pkts: int
    peak_bytes: int
    hist: tuple[int, ...]
    stages: tuple[int, ...]


def window_features(table: pd.DataFrame, cfg: dict) -> pd.DataFrame:
    """The production packet + sent feature families, merged on (src_ip, window_id).

    Identical assembly to `engine.predict._windows_from_input`'s PCAP branch,
    minus the retransmission-backend swap (which shells out to tshark and would
    make a measurement depend on whether Wireshark is installed).
    """
    from data import packet_features as PF

    merged = PF.packet_window_features(table, cfg).merge(
        PF.sent_window_features(table, cfg), on=["src_ip", "window_id"], how="outer"
    ).fillna(0.0)

    expected = {
        "src_ip", "window_id",
        *cfg["packet_features"]["fields"], *cfg["packet_features"]["sent_fields"],
    }
    if not merged.empty and set(merged.columns) != expected:
        raise ValueError(
            "merged window features drifted from configs/data.yaml: "
            f"{sorted(set(merged.columns) ^ expected)}"
        )
    return merged


def measure(table: pd.DataFrame, cfg: dict, attackers: list[str], variant: str = "baseline",
            cost: str = "") -> Measurement:
    """Price one packet table against the attacker hosts that produced it."""
    from engine.predict import _infer_stage

    attacker_ints = _ip_ints(attackers)
    mask = _attacker_mask(table, attacker_ints)
    sent = table[mask]
    if sent.empty:
        raise ValueError(
            f"none of the attacker addresses {attackers} sent a packet in this "
            "capture — a bench that silently measures an empty set reports every "
            "evasion as free. Check --attacker, or the operator log's attacker_ip "
            "column."
        )

    ts = sent["ts"].to_numpy(dtype=float)
    # Two campaign invariants, not one. `reach` is what was contacted; `sockets`
    # is which of the attacker's own connections contacted it. A transform can
    # hold the first and break the second (see _PORT_PERMUTATION_SCOPE), and a
    # bench that only checked reach would publish that as an evasion win.
    pairs = pd.MultiIndex.from_arrays([sent["dst_ip"], sent["dst_port"]])
    sockets = pd.MultiIndex.from_arrays(
        [sent["dst_ip"], sent["src_port"], sent["dst_port"]]
    )

    feats = window_features(table, cfg)
    attacker_strs = set(str(a) for a in attackers)
    rows = feats[feats["src_ip"].astype(str).isin(attacker_strs)]
    if rows.empty:
        raise ValueError(
            f"the attacker hosts {attackers} produced no feature windows from "
            f"{len(sent)} packets — the extractor and the packet table disagree"
        )

    # Counted off the DECLARED feature names, not off the bin-edge list: the
    # extractor appends an open-ended final bin, so the two differ by one and
    # deriving the count from the edges would drop a published bin the day an
    # edge is added.
    n_hist = sum(1 for f in cfg["packet_features"]["fields"]
                 if f.startswith("payload_hist_"))
    hist = tuple(int(rows[f"payload_hist_{i}"].sum()) for i in range(n_hist))

    stages = stage_order(cfg)
    counts = dict.fromkeys(stages, 0)
    # Keys are not features. `window_id` would be passed to the stage rules as
    # though it were one; nothing reads it today, and nothing should start.
    feature_names = [c for c in rows.columns if c not in ("src_ip", "window_id")]
    for _, row in rows.iterrows():
        feats_row = {name: float(row[name]) for name in feature_names}
        feats_row["internal"] = int(is_internal(row["src_ip"], cfg))
        counts[_infer_stage(feats_row, cfg["stage_rules"])] += 1

    return Measurement(
        variant=variant,
        cost=cost,
        span_s=float(ts.max() - ts.min()),
        pkts=int(len(sent)),
        bytes=int(sent["payload_len"].to_numpy(dtype=np.int64).sum()),
        reach=int(pairs.nunique()),
        sockets=int(sockets.nunique()),
        windows=int(len(rows)),
        ttl_var=float(rows["ttl_var"].max()),
        win_var=float(rows["tcp_win_var"].max()),
        seq_ratio=float(rows["sequential_port_ratio"].max()),
        peak_pkts=int(rows["sent_pkts"].max()),
        peak_bytes=int(rows["sent_bytes"].max()),
        hist=hist,
        stages=tuple(counts[s] for s in stages),
    )


def _ip_ints(addresses) -> set[int]:
    return {int(ipaddress.ip_address(str(a))) for a in addresses}


def apply_variant(table: pd.DataFrame, variant: Variant, cfg: dict, attackers: list[str],
                  seed: int, overrides: dict | None = None) -> pd.DataFrame:
    """Run one variant's primitives over the attacker's packets, in order.

    The attacker mask is recomputed inside each primitive rather than passed
    down, because `pad_payload` changes the row count. The result is re-sorted by
    timestamp exactly as `extract_packet_table` leaves its own output — the
    window and sequential-port features read row order, so a paced table that was
    not re-sorted would measure an artefact of the transform.
    """
    attacker_ints = _ip_ints(attackers)
    rng = np.random.default_rng(seed)
    out = table
    for name, params in variant.steps:
        merged = {**params, **(overrides or {})}
        out = _PRIMITIVES[name](out, attacker_ints, cfg, rng, **merged)
    if not out["ts"].is_monotonic_increasing:
        out = out.sort_values("ts", kind="stable")
    return out.reset_index(drop=True)


def run(pcap_path: str | Path, cfg: dict | None = None, variants=None,
        attackers: list[str] | None = None, seed: int | None = None,
        overrides: dict | None = None) -> dict:
    """Measure every named variant against one capture.

    Returns {"pcap", "attackers", "seed", "n_packets", "stage_order",
    "measurements": [Measurement, ...]}. The pcap is parsed ONCE; every variant
    transforms that one baseline table, so no variant can differ from another
    because of a re-parse.
    """
    from data import packet_features as PF

    cfg = cfg or load_config("data")
    seed = int(cfg["seed"] if seed is None else seed)
    names = [v.name for v in VARIANTS] if variants is None else list(variants)
    unknown = [n for n in names if n not in VARIANTS_BY_NAME]
    if unknown:
        raise ValueError(f"unknown variant(s) {unknown}; have {sorted(VARIANTS_BY_NAME)}")

    pcap_path = Path(pcap_path)
    table = PF.extract_packet_table(pcap_path, cfg)
    if attackers is None:
        attackers = attackers_from_operator_log(pcap_path, capture_date(table))

    measurements = []
    for name in names:
        variant = VARIANTS_BY_NAME[name]
        transformed = apply_variant(table, variant, cfg, attackers, seed, overrides)
        measurements.append(
            measure(transformed, cfg, attackers, variant=name, cost=variant.cost)
        )
    return {
        # as_posix: the report is a committed document, so the path it prints must
        # not change shape with the operating system that produced it.
        "pcap": pcap_path.as_posix(),
        "attackers": list(attackers),
        "seed": seed,
        "n_packets": int(len(table)),
        "stage_order": list(stage_order(cfg)),
        "measurements": measurements,
    }


# ---------------------------------------------------------------------------
# Re-emitting a transformed table as real packets
# ---------------------------------------------------------------------------


def write_packet_table_pcap(table: pd.DataFrame, path: str | Path) -> Path:
    """Re-emit a (possibly transformed) packet table as a real pcap.

    This is what turns "the attacker could set these fields" from an assertion
    into something checkable: the written file goes back through
    `extract_packet_table` and has to produce the same features
    (`verify_round_trip`).

    TCP sequence numbers are RECONSTRUCTED, because the packet table does not
    carry them: each packet gets a fresh strictly-increasing seq within its flow,
    except a row flagged `is_retrans`, which re-emits the seq already used for
    that (flow, payload_len) — precisely the pair
    `packet_features._RetransTracker` keys on. Where no such pair exists yet the
    flag cannot be reproduced, and `verify_round_trip` fails rather than the
    caller believing a file it cannot regenerate.

    Refuses fragments and non-TCP/UDP protocols outright: an approximation
    written silently is the failure mode this whole repo is built against.
    """
    from scapy.all import IP, TCP, UDP, Ether, wrpcap

    if int(table["is_frag"].sum()):
        raise ValueError(
            f"{int(table['is_frag'].sum())} fragmented rows — the writer cannot "
            "reconstruct IP fragmentation, so it refuses rather than emitting "
            "whole datagrams and calling them the same traffic"
        )
    bad = sorted(set(table["protocol"].unique()) - {_PROTO_TCP, _PROTO_UDP})
    if bad:
        raise ValueError(f"cannot re-emit IP protocol(s) {bad} — TCP and UDP only")

    flags_for = [("fin", "F"), ("syn", "S"), ("rst", "R"), ("psh", "P"),
                 ("ack", "A"), ("urg", "U")]
    next_seq: dict[tuple, int] = {}
    seen_seq: dict[tuple, int] = {}
    packets = []
    for row in table.itertuples(index=False):
        src, dst = _int_to_ip(row.src_ip), _int_to_ip(row.dst_ip)
        payload = b"\x00" * int(row.payload_len)
        eth = Ether(src=_WRITER_SRC_MAC, dst=_WRITER_DST_MAC)
        if int(row.protocol) == _PROTO_UDP:
            pkt = (eth / IP(src=src, dst=dst, ttl=int(row.ttl))
                   / UDP(sport=int(row.src_port), dport=int(row.dst_port)) / payload)
        else:
            flow = (int(row.src_ip), int(row.dst_ip), int(row.src_port), int(row.dst_port))
            key = (flow, int(row.payload_len))
            if int(row.is_retrans) and key in seen_seq:
                seq = seen_seq[key]
            else:
                seq = next_seq.get(flow, 1)
                next_seq[flow] = seq + max(int(row.payload_len), 1)
                seen_seq.setdefault(key, seq)
            flags = "".join(ch for col, ch in flags_for if int(getattr(row, col)))
            pkt = (eth / IP(src=src, dst=dst, ttl=int(row.ttl))
                   / TCP(sport=int(row.src_port), dport=int(row.dst_port), flags=flags,
                         seq=seq, window=int(row.tcp_win)) / payload)
        pkt.time = float(row.ts)
        packets.append(pkt)

    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(path), packets)
    return path


def _int_to_ip(value: int) -> str:
    v = int(value)
    return f"{(v >> 24) & 255}.{(v >> 16) & 255}.{(v >> 8) & 255}.{v & 255}"


def verify_round_trip(table: pd.DataFrame, cfg: dict, path: str | Path) -> pd.DataFrame:
    """Write `table` as a pcap, parse it back, and require identical features.

    Returns the re-parsed packet table on success; raises with the offending
    columns on any disagreement. The comparison is on the FEATURE frames, not on
    the packet tables, because the features are what the claim is about — "this
    transformed table describes traffic that could really be sent" is only true
    if sending it produces the same numbers.
    """
    from data import packet_features as PF

    written = write_packet_table_pcap(table, path)
    reread = PF.extract_packet_table(written, cfg)

    before = window_features(table, cfg).sort_values(["src_ip", "window_id"]).reset_index(
        drop=True)
    after = window_features(reread, cfg).sort_values(["src_ip", "window_id"]).reset_index(
        drop=True)
    if before.shape != after.shape:
        raise RuntimeError(
            f"round trip through {written} changed the feature frame shape: "
            f"{before.shape} -> {after.shape}"
        )
    mismatched = []
    for col in before.columns:
        if col in ("src_ip",):
            if not before[col].equals(after[col]):
                mismatched.append(col)
        elif not np.allclose(before[col].to_numpy(dtype=float),
                             after[col].to_numpy(dtype=float), rtol=1e-9, atol=1e-9):
            mismatched.append(col)
    if mismatched:
        raise RuntimeError(
            f"round trip through {written} did not reproduce {mismatched} — the "
            "transformed table does not describe traffic this writer can emit, so "
            "its measurements must not be published as realisable"
        )
    return reread


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------


def model_scoring_status(cfg: dict) -> str:
    """One line: whether the trained-model delta is runnable on THIS machine.

    Never a number. The point of this line is that a missing artifact produces
    the word TBD and a command, not a zero that a reader would take for
    "the model score did not move".
    """
    from configs import resolve_path

    art = resolve_path(cfg["paths"]["artifacts_dir"])
    missing = [name for name in MODEL_ARTIFACTS if not (art / name).exists()]
    if missing:
        return (f"model-score effect: **TBD** - {', '.join(missing)} absent under "
                f"{art} (gitignored). With the artifacts present, "
                f"`--write-pcap DIR` then: {SCORING_COMMAND}")
    return (f"model-score effect: runnable here - artifacts present under {art}. "
            f"`--write-pcap DIR` then: {SCORING_COMMAND}")


def _fmt_hist(values) -> str:
    return "[" + ",".join(str(int(v)) for v in values) + "]"


def probe_lines(result: dict) -> list[str]:
    """`3.N <variant>  field=value ...` — one line per published table row.

    This flat rendering is what `docs/evasion.md`'s fenced block prints and what
    `tests/test_evasion.py` parses back, so every figure in that document is
    compared against a live run rather than against a re-implementation.
    """
    lines = []
    for m in result["measurements"]:
        lines.append(f"3.1 {m.variant}  span={m.span_s:.3f}  pkts={m.pkts}  "
                     f"bytes={m.bytes}  reach={m.reach}  sockets={m.sockets}")
    for m in result["measurements"]:
        lines.append(f"3.2 {m.variant}  windows={m.windows}  ttl_var={m.ttl_var:.3f}  "
                     f"win_var={m.win_var:.4g}  seq_ratio={m.seq_ratio:.3f}  "
                     f"peak_pkts={m.peak_pkts}  peak_bytes={m.peak_bytes}")
    for m in result["measurements"]:
        lines.append(f"3.3 {m.variant}  bytes={m.bytes}  hist={_fmt_hist(m.hist)}")
    for m in result["measurements"]:
        lines.append(f"3.4 {m.variant}  stages={_fmt_hist(m.stages)}")
    return lines


def _table(header: list[str], rows: list[list[str]]) -> str:
    """A markdown table whose FIRST header cell is empty.

    That is docs/threat_model.md §3's convention and it is load-bearing, not
    cosmetic: the shared figure-pinning helper in
    `tests/test_threat_model_figures.py` tells a header row from a data row by
    its empty first cell. A header that named the first column would be parsed
    as an unguarded published row.
    """
    head = ["", *header]
    lines = ["| " + " | ".join(head) + " |", "|" + "---|" * len(head)]
    for row in rows:
        lines.append("| " + " | ".join(row) + " |")
    return "\n".join(lines)


def to_markdown(result: dict, cfg: dict) -> str:
    """The four §3 tables of docs/evasion.md, rendered from this run.

    Every cell inside a table is a number or a vector so the pinning test can
    compare it digit for digit; the prose cost of each variant rides in a list
    beneath §3.1 instead of in a column, because a sentence cannot be compared
    that way and a table with one uncomparable column is a table with an
    unguarded figure.
    """
    ms = result["measurements"]
    base = ms[0]
    out = [
        f"Capture `{result['pcap']}` - {result['n_packets']:,} packets parsed, "
        f"attacker host(s) {', '.join(result['attackers'])}, seed {result['seed']}.",
        "",
        model_scoring_status(cfg),
        "",
        "**3.1 What the evasion costs on the wire.** Attacker-sent packets only.",
        "",
        _table(["span (s)", "packets", "bytes delivered", "reach (dst,port)",
                "connections"],
               [[f"`{m.variant}`", f"{m.span_s:.3f}", f"{m.pkts:,}", f"{m.bytes:,}",
                 f"{m.reach:,}", f"{m.sockets:,}"] for m in ms]),
        "",
        "What each one costs the attacker:",
        "",
        *[f"- `{m.variant}` - {m.cost}" for m in ms],
        "",
        "**3.2 What it buys in the features.** Attacker host-windows only; "
        "`ttl_var`/`win_var`/`seq_ratio` are the maximum over those windows.",
        "",
        _table(["windows", "ttl_var", "tcp_win_var", "sequential_port_ratio",
                "peak sent_pkts", "peak sent_bytes"],
               [[f"`{m.variant}`", str(m.windows), f"{m.ttl_var:.3f}", f"{m.win_var:.4g}",
                 f"{m.seq_ratio:.3f}", f"{m.peak_pkts:,}", f"{m.peak_bytes:,}"]
                for m in ms]),
        "",
        "**3.3 The payload histogram.** Summed `payload_hist_0..7` over the attacker's "
        f"windows; every packet falls in exactly "
        f"{cfg['windows']['window_seconds'] // cfg['windows']['stride_seconds']} windows, "
        "so these are that multiple of the packet counts.",
        "",
        _table(["bytes delivered", "payload_hist_[0..7]"],
               [[f"`{m.variant}`", f"{m.bytes:,}", f"`{_fmt_hist(m.hist)}`"] for m in ms]),
        "",
        "**3.4 The stage the rules infer.** Windows per stage, in "
        f"`configs/data.yaml` order: `{', '.join(result['stage_order'])}`.",
        "",
        _table(["stage windows"],
               [[f"`{m.variant}`", f"`{_fmt_hist(m.stages)}`"] for m in ms]),
        "",
        f"Invariants held by every variant: bytes delivered {base.bytes:,}, reach "
        f"{base.reach:,} and connections {base.sockets:,} are unchanged - the "
        "campaign delivered the same bytes over the same connections to the same "
        "destinations on the same ports.",
    ]
    return "\n".join(out)


def to_json(result: dict, cfg: dict) -> str:
    from dataclasses import asdict

    payload = {k: v for k, v in result.items() if k != "measurements"}
    payload["model_score"] = None  # TBD, never 0 — see model_scoring_status
    payload["model_scoring_status"] = model_scoring_status(cfg)
    payload["measurements"] = [asdict(m) for m in result["measurements"]]
    return json.dumps(payload, indent=2)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--pcap", required=True, help="capture to transform")
    parser.add_argument("--variant", action="append", choices=sorted(VARIANTS_BY_NAME),
                        help="repeatable; default every variant")
    parser.add_argument("--attacker", action="append",
                        help="attacker source address; default from the operator log")
    parser.add_argument("--seed", type=int, default=None,
                        help="override configs/data.yaml seed for the randomised transforms")
    parser.add_argument("--target-bin", type=int, default=None,
                        help="pad_payload target histogram bin (default 3, the "
                             "configured [256, 512) bin)")
    parser.add_argument("--ttl-range", type=int, nargs=2, default=None,
                        metavar=("LOW", "HIGH"), help="ttl_random bounds (default 32 65)")
    parser.add_argument("--format", choices=("markdown", "json", "probe"),
                        default="markdown")
    parser.add_argument("--write-pcap", default=None, metavar="DIR",
                        help="also write each variant's transformed capture as a real "
                             "pcap into DIR, verifying it re-parses to the same features")
    args = parser.parse_args(argv)

    cfg = load_config("data")
    overrides: dict = {}
    if args.target_bin is not None:
        overrides["target_bin"] = args.target_bin
    if args.ttl_range is not None:
        overrides["ttl_low"], overrides["ttl_high"] = args.ttl_range

    result = run(args.pcap, cfg=cfg, variants=args.variant, attackers=args.attacker,
                 seed=args.seed, overrides=overrides)

    if args.format == "json":
        print(to_json(result, cfg))
    elif args.format == "probe":
        print("\n".join(probe_lines(result)))
    else:
        print(to_markdown(result, cfg))

    if args.write_pcap:
        from data import packet_features as PF

        table = PF.extract_packet_table(args.pcap, cfg)
        attackers = result["attackers"]
        for name in [m.variant for m in result["measurements"]]:
            transformed = apply_variant(table, VARIANTS_BY_NAME[name], cfg, attackers,
                                        result["seed"], overrides)
            path = Path(args.write_pcap) / f"{name}.pcap"
            verify_round_trip(transformed, cfg, path)
            print(f"wrote {path} ({len(transformed):,} packets, "
                  "re-parsed to identical features)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
