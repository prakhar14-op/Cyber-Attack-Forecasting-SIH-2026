"""`docs/evasion.md` §3 publishes 32 measured rows. This runs the document's own
probe and checks they still reproduce — and separately pins the claims the
document makes about them.

Two jobs, deliberately kept apart:

**Job 1 — the figures.** Same machinery `tests/test_threat_model_figures.py` puts
on `docs/threat_model.md`, importing its comparison helpers rather than
re-implementing them, so the two documents are checked by literally the same
parser at literally the same tolerance (each figure to the precision the document
prints it). The probe is taken FROM the document and executed, the published
values are parsed FROM the document's tables, and coverage is checked in both
directions: a table row with no guard fails
`test_every_published_row_is_claimed_by_a_guard`, and a guard whose row vanished
fails its own assertion. `EXTRACTORS_THE_PROBE_MUST_CALL` counts real calls into
`data/packet_features.py` and `engine/predict.py` while the block runs, so a probe
rewritten to print the published constants fails however faithfully it quotes
their names.

**Job 2 — the transformations.** A figure pin proves the document matches the
code; it proves nothing about whether the code models an evasion honestly. These
tests are the ones with teeth:

- `test_every_evasion_delivers_the_identical_campaign` is the control. Bytes
  delivered, (destination, port) reach and the set of connections opened must be
  bit-identical across all eight variants, because a transformation that changed
  them would be measuring a *different, smaller attack* and reporting the
  shrinkage as evasion. The connection count is in there because reach alone was
  not enough: widening the port permutation's scope from one socket to one peer
  leaves reach untouched while moving the recon sweep's ports onto the SSH brute
  force's packets, which the bench would then report as a stage evasion. That was
  found by making the change and watching the reach assertion hold.
- `test_a_transformed_table_survives_a_pcap_round_trip` is the realisability
  check. The transformed packet table is written back out as a real pcap and
  re-parsed; the features must come out identical. Without it, every figure here
  rests on "an attacker could set these fields", asserted.
- `test_port_randomisation_alone_does_not_hide_the_sweep` and
  `test_pacing_alone_does_not_hide_the_sweep` pin the *negative* results. Either
  one alone leaves a stage rule firing. A bench that only recorded its wins would
  be the self-own this document exists to avoid.
- `test_exfiltration_survives_until_the_pacing_crosses_the_byte_rule` pins §5's
  headline: the one stage the full evasion cannot silence, and the measured
  pacing factor at which it finally goes quiet.

Tolerance, stated: §3's figures reproduce exactly at the precision the document
publishes — `389.960` to three decimals, `4.24e+08` to three significant figures,
`4,257,060` and the two vectors exactly. The three randomised transforms are
pseudo-random draws, which is why `evasion.run` seeds from `configs/data.yaml`
and the document prints the seed it used.
"""

from __future__ import annotations

import io
import re
from contextlib import redirect_stdout
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

# Imported, not copied. These helpers define what "the document reproduces"
# MEANS — header-vs-data row detection, the per-cell precision rule, the probe
# line grammar — and docs/evasion.md deliberately follows docs/threat_model.md's
# table conventions so one implementation covers both. If that file moves a
# helper this import fails loudly at collection, which is the correct outcome:
# two documents silently checked by two drifting parsers is the failure mode.
from tests.test_threat_model_figures import (  # noqa: E402
    PublishedRow,
    extract_probe,
    normalise,
    parse_probe,
    reproduces,
    subsections,
    table_rows,
    _as_ints,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
DOC = REPO_ROOT / "docs" / "evasion.md"
PCAP = REPO_ROOT / "app" / "assets" / "synthetic_demo.pcap"

# Names that make the fenced block a measurement rather than a print statement.
# A cheap textual pre-check only; EXTRACTORS_THE_PROBE_MUST_CALL is what proves it.
PROBE_MUST_MENTION = ('load_config("data")', "evasion.run", "probe_lines")

# Counted during exec. `_infer_stage` is in the list because §3.4 is a claim
# about engine/predict.py's stage rules: a probe that computed stages any other
# way would publish a column that does not describe the shipped engine.
EXTRACTORS_THE_PROBE_MUST_CALL = {
    "data.packet_features": ("packet_window_features", "sent_window_features"),
    "engine.predict": ("_infer_stage",),
}

VARIANTS = ("baseline", "port_random", "pace_5x", "pace_15x", "pad_payload",
            "ttl_random", "win_random", "combined")

_COST_FIELDS = ("span", "pkts", "bytes", "reach", "sockets")
_FEATURE_FIELDS = ("windows", "ttl_var", "win_var", "seq_ratio", "peak_pkts", "peak_bytes")
_PAYLOAD_FIELDS = ("bytes", "hist")
_STAGE_FIELDS = ("stages",)

PUBLISHED: tuple[PublishedRow, ...] = tuple(
    PublishedRow(section, name, name, fields)
    for section, fields in (("3.1", _COST_FIELDS), ("3.2", _FEATURE_FIELDS),
                            ("3.3", _PAYLOAD_FIELDS), ("3.4", _STAGE_FIELDS))
    for name in VARIANTS
)

# Both counts asserted so a table quietly losing a column or a variant cannot
# shrink this guard without failing it.
EXPECTED_ROWS = 4 * len(VARIANTS)
EXPECTED_FIGURES = len(VARIANTS) * (
    len(_COST_FIELDS) + len(_FEATURE_FIELDS) + len(_PAYLOAD_FIELDS) + len(_STAGE_FIELDS)
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def doc_text() -> str:
    assert DOC.exists(), f"{DOC} is missing"
    return DOC.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def measured(doc_text) -> dict[tuple[str, str], dict[str, str]]:
    """Run the document's own probe and parse what it printed.

    Executing the document's block is the point: a re-implementation here could
    drift from the published snippet, and then the tables would be checked
    against something a reader cannot run.
    """
    import importlib

    source = extract_probe(doc_text)
    buffer = io.StringIO()
    namespace: dict = {"__name__": "evasion_section_3_probe"}

    calls: dict[tuple[str, str], int] = {}
    originals: dict[tuple[str, str], object] = {}
    for module_name, names in EXTRACTORS_THE_PROBE_MUST_CALL.items():
        module = importlib.import_module(module_name)
        for name in names:
            key = (module_name, name)
            calls[key] = 0
            originals[key] = getattr(module, name)

    def _counting(key, fn):
        def proxy(*args, **kwargs):
            calls[key] += 1
            return fn(*args, **kwargs)

        return proxy

    for (module_name, name), fn in originals.items():
        setattr(importlib.import_module(module_name), name,
                _counting((module_name, name), fn))
    try:
        with redirect_stdout(buffer):
            exec(compile(source, f"{DOC} [§3 probe]", "exec"), namespace)  # noqa: S102
    finally:
        for (module_name, name), fn in originals.items():
            setattr(importlib.import_module(module_name), name, fn)

    uncalled = [f"{m}.{n}" for (m, n), count in calls.items() if count == 0]
    assert not uncalled, (
        f"the §3 probe ran without calling {uncalled} — so §3's tables are not "
        "measurements of this repo's extractor and stage rules, whatever the probe "
        "prints. A block rewritten to print the published constants reaches this "
        "assertion."
    )

    parsed = parse_probe(buffer.getvalue())
    assert parsed, (
        "the §3 probe printed nothing this test could parse — its output format "
        f"changed. Raw output:\n{buffer.getvalue()!r}"
    )
    return parsed


@pytest.fixture(scope="module")
def cfg() -> dict:
    from configs import load_config

    return load_config("data")


@pytest.fixture(scope="module")
def bench(cfg) -> dict:
    """One full run of the bench, shared by the behavioural tests."""
    from eval import evasion

    assert PCAP.exists(), f"bundled demo capture missing: {PCAP}"
    return evasion.run(PCAP, cfg=cfg)


@pytest.fixture(scope="module")
def by_variant(bench) -> dict:
    return {m.variant: m for m in bench["measurements"]}


def _stage(measurement, name: str, cfg: dict) -> int:
    from eval import evasion

    return measurement.stages[list(evasion.stage_order(cfg)).index(name)]


# ---------------------------------------------------------------------------
# Job 1 — the published figures
# ---------------------------------------------------------------------------


def test_the_document_still_carries_the_probe_that_produced_the_figures(doc_text):
    """Cheap textual pre-check that the fenced block still reads as a measurement.

    Defeatable on its own — a block that prints the published constants while
    quoting these names passes it. The proof that a probe really reached the
    extractor is in the `measured` fixture, which counts calls into production
    code while the block executes. Keep both: this one names the missing piece,
    that one proves the measurement happened.
    """
    source = extract_probe(doc_text)
    missing = [name for name in PROBE_MUST_MENTION if name not in source]
    assert not missing, (
        f"the §3 probe no longer mentions {missing}. §3's figures are published as "
        "measurements produced by eval/evasion.py under configs/data.yaml; a probe "
        "that does not run the bench cannot produce them."
    )


def test_every_published_row_is_claimed_by_a_guard(doc_text):
    """Coverage, in the direction that rots: a row added to a §3 table without an
    entry in PUBLISHED would be an unguarded published figure."""
    unclaimed = []
    for section, text in subsections(doc_text).items():
        labels = {row.doc_label for row in PUBLISHED if row.section == section}
        for cells in table_rows(text):
            if not any(label in cells[0] for label in labels):
                unclaimed.append((section, cells[0]))
    assert not unclaimed, (
        f"§3 publishes table rows no guard claims: {unclaimed}. Add a PublishedRow "
        "for each, or the figure ships unchecked."
    )


def test_every_published_figure_in_section_3_reproduces(doc_text, measured):
    """The 32 rows, digit for digit, against a live run of the document's probe."""
    by_section = subsections(doc_text)
    failures: list[str] = []
    figures = 0
    rows_checked = 0

    for row in PUBLISHED:
        assert row.section in by_section, (
            f"§{row.section} is missing from {DOC.name}; "
            f"the '{row.doc_label}' row cannot be checked"
        )
        candidates = [
            cells for cells in table_rows(by_section[row.section])
            if row.doc_label == cells[0]
        ]
        assert len(candidates) == 1, (
            f"§{row.section}: expected exactly one table row labelled "
            f"{row.doc_label!r}, found {len(candidates)}: {candidates}"
        )
        published_cells = candidates[0][1:]
        assert len(published_cells) == len(row.fields), (
            f"§{row.section} '{row.doc_label}' publishes {len(published_cells)} "
            f"values but this guard knows {len(row.fields)} columns "
            f"{row.fields}: {published_cells}"
        )

        key = (row.section, row.probe_label)
        assert key in measured, (
            f"the §3 probe printed no '{row.section} {row.probe_label}' line; "
            f"it printed {sorted(measured)}"
        )
        probe_values = measured[key]

        rows_checked += 1
        for field, published in zip(row.fields, published_cells):
            figures += 1
            assert field in probe_values, (
                f"§{row.section} '{row.probe_label}': the probe printed no "
                f"{field!r} (it printed {sorted(probe_values)})"
            )
            if not reproduces(published, probe_values[field]):
                failures.append(
                    f"§{row.section} '{row.doc_label}' {field}: "
                    f"document publishes {published!r}, probe measured "
                    f"{probe_values[field]!r}"
                )

    assert rows_checked == EXPECTED_ROWS and figures == EXPECTED_FIGURES, (
        f"checked {rows_checked} rows / {figures} figures, expected "
        f"{EXPECTED_ROWS}/{EXPECTED_FIGURES} — the §3 tables changed shape, so this "
        "guard is no longer covering what it claims to cover"
    )
    assert not failures, (
        "docs/evasion.md §3 no longer reproduces:\n  "
        + "\n  ".join(failures)
        + "\n\nEither eval/evasion.py, data/packet_features.py or configs/data.yaml "
        "changed the measurement, or a published figure was edited by hand. Re-run "
        "`python -m eval.evasion --pcap app/assets/synthetic_demo.pcap` and publish "
        "what it prints."
    )


def test_section_3_3_prose_bin_shift_matches_the_measured_histograms(doc_text, measured):
    """§3.3's headline sentence names two bin indices and a count. All measured."""
    text = normalise(subsections(doc_text)["3.3"])
    match = re.search(r"from bin (\d+) to bin (\d+)", text)
    assert match, "§3.3 no longer states which bin the payload mass moves from and to"
    source_bin, target_bin = int(match.group(1)), int(match.group(2))

    before = _as_ints(measured[("3.3", "baseline")]["hist"])
    after = _as_ints(measured[("3.3", "pad_payload")]["hist"])
    moved = before[source_bin]
    assert moved > 0 and after[source_bin] == 0, (
        f"§3.3 claims 100 % of bin {source_bin}'s mass moves away; measured "
        f"{before} -> {after}"
    )
    assert after[target_bin] == before[target_bin] + 3 * moved, (
        f"§3.3 claims every bin-{source_bin} packet becomes three bin-{target_bin} "
        f"chunks; measured {before} -> {after}"
    )

    # The separator is prose (an arrow, a word); only the two counts are pinned.
    counts = re.search(rf"bin-{target_bin} count goes ([\d,]+)[^\d]+([\d,]+)", text)
    assert counts, f"§3.3 no longer states the bin-{target_bin} count before and after"
    assert (int(counts.group(1).replace(",", "")) == before[target_bin]
            and int(counts.group(2).replace(",", "")) == after[target_bin]), (
        f"§3.3 publishes a bin-3 count of {counts.groups()}; measured "
        f"{before[target_bin]} -> {after[target_bin]}"
    )

    assert measured[("3.3", "baseline")]["bytes"] == measured[("3.3", "pad_payload")]["bytes"], (
        "§3.3 claims bytes delivered is unchanged to the byte by re-chunking"
    )


def test_section_5_survival_claims_match_the_measured_stage_vectors(doc_text, measured, cfg):
    """§5's headline numbers are derived from §3.4's vectors, so they are checked
    against the same live run rather than against the table they were copied from."""
    from eval import evasion

    order = list(evasion.stage_order(cfg))
    combined = _as_ints(measured[("3.4", "combined")]["stages"])
    text = normalise(subsections(doc_text).get("3.4", "")) + " " + normalise(doc_text)

    match = re.search(r"still (\d+)\s*\n?\s*windows exfiltration", text) or re.search(
        r"still \*\*(\d+)\*\* windows `?exfiltration", doc_text)
    assert match, "§3.4/§5 no longer states how many windows survive as exfiltration"
    published = int(match.group(1))
    assert published == combined[order.index("exfiltration")], (
        f"the document says {published} exfiltration windows survive `combined`; "
        f"measured {combined[order.index('exfiltration')]}"
    )
    for silenced in ("recon", "lateral_movement"):
        assert combined[order.index(silenced)] == 0, (
            f"§3.4 reading 3 and §5 both say `combined` erases {silenced}; measured "
            f"{combined[order.index(silenced)]} windows"
        )


# ---------------------------------------------------------------------------
# Job 2 — the transformations themselves
# ---------------------------------------------------------------------------


def test_internal_matches_the_production_anonymizer(cfg):
    """`evasion.is_internal` is key-free so the stage column does not depend on
    whether SIH26_HMAC_KEY happens to be set. That is only acceptable while it
    agrees with the real implementation, so this pins it to `Anonymizer`."""
    from data.anonymize import Anonymizer
    from eval import evasion

    anonymizer = Anonymizer(b"pin-only-not-a-secret", cfg["anonymisation"])
    addresses = ["10.20.0.10", "10.20.0.20", "172.31.0.5", "192.168.1.1",
                 "203.0.113.7", "8.8.8.8", "1.1.1.1"]
    mine = {ip: evasion.is_internal(ip, cfg) for ip in addresses}
    theirs = {ip: anonymizer.is_internal(ip) for ip in addresses}
    assert mine == theirs, f"internal drifted from data/anonymize.py: {mine} vs {theirs}"
    # Both directions present, or the agreement above is vacuous.
    assert set(theirs.values()) == {True, False}, theirs


def test_every_evasion_delivers_the_identical_campaign(by_variant):
    """THE control. Bytes delivered, (destination, port) reach and the set of
    connections opened must be identical across every variant.

    A transformation that moved any of them would be measuring a smaller attack
    and reporting the shrinkage as evasion — which is not evasion, it is the
    attacker partly defending us.

    `sockets` is the assertion with teeth for the port permutation. Widening
    `_PORT_PERMUTATION_SCOPE` from one socket to one peer leaves `reach`
    untouched — the (dst_ip, dst_port) multiset per peer is preserved either way —
    while shuffling the recon sweep's 800 ports onto the SSH brute force's
    packets, which the stage rules then read as a scan. Only the connection count
    notices.
    """
    base = by_variant["baseline"]
    for name, m in by_variant.items():
        assert m.bytes == base.bytes, (
            f"{name} delivered {m.bytes} bytes, baseline delivered {base.bytes} — "
            "this variant changed the attack, not just its shape"
        )
        assert m.reach == base.reach, (
            f"{name} reached {m.reach} (dst, port) pairs, baseline reached "
            f"{base.reach} — this variant changed which services were contacted"
        )
        assert m.sockets == base.sockets, (
            f"{name} opened {m.sockets} distinct connections, baseline opened "
            f"{base.sockets} — this variant moved traffic between the attacker's "
            "own sockets, so it is rewriting which activity contacted what"
        )


def test_only_pacing_costs_wall_clock_and_only_padding_costs_packets(by_variant):
    """The cost column is a measurement, not a label: the free variants must be
    measurably free, and the expensive ones measurably expensive."""
    base = by_variant["baseline"]
    for name in ("port_random", "ttl_random", "win_random", "pad_payload"):
        assert by_variant[name].span_s == pytest.approx(base.span_s), (
            f"{name} is documented as costing no time but moved the campaign span"
        )
    for name, factor in (("pace_5x", 5.0), ("pace_15x", 15.0), ("combined", 15.0)):
        assert by_variant[name].span_s == pytest.approx(base.span_s * factor, rel=1e-6), (
            f"{name} should stretch the campaign {factor}x"
        )
    for name in ("port_random", "ttl_random", "win_random", "pace_5x", "pace_15x"):
        assert by_variant[name].pkts == base.pkts, f"{name} changed the packet count"
    assert by_variant["pad_payload"].pkts > base.pkts, (
        "re-chunking costs packets; a variant that paid nothing did not re-chunk"
    )


def test_free_header_randomisation_lifts_variance_off_zero_and_changes_no_stage(
        by_variant, cfg):
    """threat_model.md §3.1, on a real capture: two mandated packet-feature
    families go from exactly zero to large at zero cost — and move no stage,
    because no stage rule reads them."""
    base = by_variant["baseline"]
    assert base.ttl_var == 0.0 and base.win_var == 0.0, (
        "the bundled capture is a stock stack; if these are non-zero the baseline "
        "changed and the 'zero becomes large for free' claim needs re-measuring"
    )
    assert by_variant["ttl_random"].ttl_var > 1.0
    assert by_variant["win_random"].win_var > 1e6
    for name in ("ttl_random", "win_random", "pad_payload"):
        assert by_variant[name].stages == base.stages, (
            f"{name} changed the inferred stages; §3.4 reading 1 says it does not, "
            "because no stage rule reads TTL, TCP window or the payload histogram"
        )


def test_port_randomisation_alone_does_not_hide_the_sweep(by_variant, cfg):
    """A NEGATIVE result, pinned. `sequential_port_ratio` collapses, but
    `scan_distinct_dst_ports_gt` still fires, so recon survives. A bench that
    recorded only its wins would publish this as a defeated scan detector."""
    base, pr = by_variant["baseline"], by_variant["port_random"]
    assert base.seq_ratio == pytest.approx(1.0)
    assert pr.seq_ratio < cfg["stage_rules"]["scan_sequential_port_ratio_gt"], (
        "port randomisation is supposed to put sequential_port_ratio under the rule"
    )
    assert _stage(pr, "recon", cfg) > 0, (
        "recon disappeared under port randomisation alone — the distinct-port arm of "
        "the scan rule no longer fires, so §3.4 reading 2 and §5 item 2 are stale"
    )


def test_pacing_alone_does_not_hide_the_sweep(by_variant, cfg):
    """The other half of the same negative result: 15x pacing puts the sweep under
    the distinct-port threshold, and the still-ascending port order keeps the
    sequential arm firing."""
    paced = by_variant["pace_15x"]
    assert paced.seq_ratio == pytest.approx(1.0), (
        "pacing does not reorder ports, so the sequential signature must survive it"
    )
    assert _stage(paced, "recon", cfg) > 0, (
        "recon disappeared under pacing alone — §3.4 reading 2 says both arms have "
        "to be defeated before it does"
    )
    assert _stage(by_variant["combined"], "recon", cfg) == 0, (
        "the combination no longer erases recon; §3.4 reading 3 is stale"
    )


def test_exfiltration_survives_until_the_pacing_crosses_the_byte_rule(
        bench, cfg, by_variant, doc_text):
    """§5's headline, measured: volume is the one feature the full evasion cannot
    cheapen, and the pacing factor that finally silences it is set by the byte
    rule and the campaign's own volume — not by anything we chose.

    The two factors are READ OUT OF §5, not restated here, so editing the
    published number without re-measuring fails this instead of quietly changing
    a claim.
    """
    from data import packet_features as PF
    from eval import evasion

    combined = by_variant["combined"]
    rule = cfg["stage_rules"]["exfiltration_sent_bytes_gt"]
    assert combined.peak_bytes > rule and _stage(combined, "exfiltration", cfg) > 0, (
        f"exfiltration no longer survives `combined` (peak {combined.peak_bytes} B vs "
        f"rule {rule} B) — §5 item 1 is stale"
    )

    section_5 = normalise(doc_text.split("## 5.")[-1].split("## 6.")[0])
    claim = re.search(r"at (\d+)x exfiltration still fires, at (\d+)x", section_5)
    assert claim, "§5 no longer states the pacing factors either side of the crossing"
    survives_at, silent_at = float(claim.group(1)), float(claim.group(2))
    # Adjacent, or the pair does not BRACKET a crossing: "silent at 25x" is true of
    # any factor past it and would pass the assertions below while publishing the
    # wrong price. Checked by editing 22 to 25 and watching this catch it.
    assert silent_at == survives_at + 1, (
        f"§5 publishes {survives_at:g}x and {silent_at:g}x as the two sides of the "
        "crossing; non-adjacent factors do not locate it"
    )

    # §5 also publishes the arithmetic that predicts the crossing.
    quotient = re.search(r"([\d,]+) / ([\d,]+) = (\d+)", section_5)
    assert quotient, "§5 no longer shows the arithmetic behind the crossing factor"
    peak, floor, ratio = (int(g.replace(",", "")) for g in quotient.groups())
    assert (peak, floor) == (by_variant["baseline"].peak_bytes, rule), (
        f"§5's arithmetic uses {peak} / {floor}; the measured baseline peak is "
        f"{by_variant['baseline'].peak_bytes} and the rule is {rule}"
    )
    assert ratio == peak // floor == int(survives_at), (
        f"§5 computes {peak} / {floor} = {ratio} and says {survives_at:g}x still fires"
    )

    table = PF.extract_packet_table(PCAP, cfg)
    attackers = bench["attackers"]
    template = evasion.VARIANTS_BY_NAME["combined"]
    order = list(evasion.stage_order(cfg))
    measured = {}
    for factor in (survives_at, silent_at):
        steps = tuple((name, ({"factor": factor} if name == "pace" else params))
                      for name, params in template.steps)
        variant = evasion.Variant(f"combined_{factor:g}x", steps, "probe")
        transformed = evasion.apply_variant(table, variant, cfg, attackers, bench["seed"])
        measured[factor] = evasion.measure(transformed, cfg, attackers, variant=variant.name)

    assert _stage(measured[survives_at], "exfiltration", cfg) > 0, (
        f"exfiltration is already silent at {survives_at:g}x (peak "
        f"{measured[survives_at].peak_bytes} B vs rule {rule} B) — §5 publishes "
        f"{survives_at:g}x as still firing"
    )
    # "every stage rule goes silent" is the published claim, so every stage is
    # checked, not just the one §5 is about.
    still_firing = {
        stage: count for stage, count in zip(order, measured[silent_at].stages)
        if count and stage not in ("benign", "unclassified")
    }
    assert not still_firing, (
        f"§5 publishes {silent_at:g}x as the factor at which every stage rule in this "
        f"capture goes silent; at {silent_at:g}x these still fire: {still_firing}"
    )


def test_a_transformed_table_survives_a_pcap_round_trip(cfg, tmp_path, no_network, caplog):
    """Realisability. A transformed packet table is written back out as a real
    pcap and re-parsed; every feature must come out identical.

    Without this the whole document rests on "an attacker could set these
    fields", asserted. Two slices, chosen from the capture rather than named: the
    attacker's single biggest flow (which carries retransmissions, so the
    writer's sequence-number reconstruction is exercised) and its widest port
    sweep. `python -m eval.evasion --write-pcap DIR` runs the same check over the
    whole capture for all eight variants; the slices keep this test quick.

    The link-layer assertion at the end is not decoration. A bare `Ether()` makes
    scapy resolve the destination MAC — reaching for the network stack, which
    CLAUDE.md's first constraint forbids — and then writes **this machine's own
    NIC address** as the source. Measured: dropping the writer's pinned MACs
    produced `src=2c:3b:70:fa:e5:f1`, the host's real adapter, inside a file the
    tool hands to an analyst. Neither `no_network` nor a log assertion catches
    that (scapy swallows the failed lookup and falls back to broadcast, and its
    warning does not reach caplog — both were tried and both stayed green). The
    written bytes do.
    """
    from data import packet_features as PF
    from eval import evasion

    table = PF.extract_packet_table(PCAP, cfg)
    attackers = evasion.attackers_from_operator_log(PCAP, evasion.capture_date(table))
    attacker_rows = table[table["src_ip"].isin(
        {int(__import__("ipaddress").ip_address(a)) for a in attackers})]

    flow_keys = ["src_ip", "dst_ip", "src_port", "dst_port"]
    biggest = attacker_rows.groupby(flow_keys).size().idxmax()
    bulk = attacker_rows[
        (attacker_rows[flow_keys] == pd.Series(biggest, index=flow_keys)).all(axis=1)
    ].head(300).reset_index(drop=True)
    assert int(bulk["is_retrans"].sum()) > 0, (
        "the bulk slice carries no retransmissions, so this test would not exercise "
        "the writer's sequence-number reconstruction"
    )

    socket_keys = ["src_ip", "dst_ip", "src_port"]
    widest = attacker_rows.groupby(socket_keys)["dst_port"].nunique().idxmax()
    sweep = attacker_rows[
        (attacker_rows[socket_keys] == pd.Series(widest, index=socket_keys)).all(axis=1)
    ].head(400).reset_index(drop=True)
    assert sweep["dst_port"].nunique() > 100, "the sweep slice is not a port sweep"

    written = []
    for name, slice_ in (("pad_payload", bulk), ("combined", sweep)):
        transformed = evasion.apply_variant(
            slice_, evasion.VARIANTS_BY_NAME[name], cfg, attackers, cfg["seed"]
        )
        # Raises with the offending columns on any disagreement.
        evasion.verify_round_trip(transformed, cfg, tmp_path / f"{name}.pcap")
        written.append(tmp_path / f"{name}.pcap")

    expected = (bytes.fromhex(evasion._WRITER_DST_MAC.replace(":", "")),
                bytes.fromhex(evasion._WRITER_SRC_MAC.replace(":", "")))
    for path in written:
        from scapy.utils import RawPcapReader

        reader = RawPcapReader(str(path))
        try:
            raw, _meta = next(iter(reader))
        finally:
            reader.close()
        assert (raw[0:6], raw[6:12]) == expected, (
            f"{path.name} carries link-layer addresses the writer did not choose: "
            f"dst={raw[0:6].hex(':')} src={raw[6:12].hex(':')}. A bare Ether() "
            "resolves the destination MAC (touching the network stack) and stamps "
            "this machine's own adapter address into a file the tool publishes."
        )


def test_the_bench_fails_loudly_rather_than_measuring_an_empty_set(cfg, tmp_path):
    """An attacker address that sent nothing must raise, not report every evasion
    as free over zero packets."""
    from data import packet_features as PF
    from eval import evasion

    table = PF.extract_packet_table(PCAP, cfg)
    with pytest.raises(ValueError, match="sent a packet in this capture"):
        evasion.measure(table, cfg, ["198.51.100.99"])

    missing = tmp_path / "no-sidecar.pcap"
    missing.write_bytes(b"")
    with pytest.raises(FileNotFoundError, match="--attacker"):
        evasion.attackers_from_operator_log(missing, "2018-01-01")

    with pytest.raises(ValueError, match="unknown variant"):
        evasion.run(PCAP, cfg=cfg, variants=["not_a_variant"], attackers=["10.20.0.10"])


def test_pad_payload_refuses_a_target_bin_it_cannot_hit(cfg):
    """Equal chunks cannot always land in the requested bin. When they cannot the
    transform raises, instead of emitting chunks in a different bin and letting
    the report call that a bin shift."""
    from eval import evasion

    cols = dict(
        ts=np.arange(4, dtype=float), src_ip=np.full(4, 3232235777, "uint32"),
        dst_ip=np.full(4, 3232235778, "uint32"), src_port=np.full(4, 40000, "uint16"),
        dst_port=np.full(4, 80, "uint16"), protocol=np.full(4, 6, "uint8"),
        ttl=np.full(4, 64, "uint8"), tcp_win=np.full(4, 64240, "uint16"),
        is_frag=np.zeros(4, "uint8"), payload_len=np.full(4, 2000, "uint32"),
        is_retrans=np.zeros(4, "uint8"), syn=np.zeros(4, "uint8"),
        ack=np.ones(4, "uint8"), fin=np.zeros(4, "uint8"), rst=np.zeros(4, "uint8"),
        psh=np.zeros(4, "uint8"), urg=np.zeros(4, "uint8"),
    )
    from data.packet_features import _PACKET_LAYOUT

    frame = pd.DataFrame(cols)[list(_PACKET_LAYOUT)]
    attackers = {3232235777}

    # 2000 B into [1024, 1460) needs 2 chunks of 1000 - below the bin's floor.
    with pytest.raises(ValueError, match="smallest chunk"):
        evasion.pad_payload(frame, attackers, cfg, np.random.default_rng(0), target_bin=5)
    with pytest.raises(ValueError, match="outside the configured edges"):
        evasion.pad_payload(frame, attackers, cfg, np.random.default_rng(0), target_bin=99)


def test_the_report_never_prints_a_model_score(cfg, bench):
    """The model-score column is TBD on a machine without the weights, and the
    line has to say which file is missing. A zero here would read as 'the model
    was unaffected', which is the fabricated measurement this repo bans."""
    from configs import resolve_path
    from eval import evasion

    status = evasion.model_scoring_status(cfg)
    art = resolve_path(cfg["paths"]["artifacts_dir"])
    present = [n for n in evasion.MODEL_ARTIFACTS if (art / n).exists()]
    if present == list(evasion.MODEL_ARTIFACTS):
        assert "runnable here" in status
    else:
        assert "**TBD**" in status
        for name in evasion.MODEL_ARTIFACTS:
            if name not in present:
                assert name in status, f"the TBD line does not name the missing {name}"
    assert "predict_file" in status, "the TBD line must carry the command that closes it"

    import json

    payload = json.loads(evasion.to_json(bench, cfg))
    assert payload["model_score"] is None, "model_score must be null, never 0"
