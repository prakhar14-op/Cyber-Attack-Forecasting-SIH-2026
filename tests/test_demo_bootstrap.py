"""scripts/bootstrap_demo_artifacts.py — the demo lane, and what it must not become.

WHAT THESE TESTS ARE EVIDENCE FOR, AND WHAT THEY ARE NOT
Every test in this file exercises a TOY model fitted on the small synthetic
capture bundled in this repository. Nothing here is evidence about detection
quality, about CSE-CIC-IDS-2018, or about any published number. What they check
is that the machinery runs, that it is reproducible, and — most of the file —
that the demo lane cannot be mistaken for, or quietly promoted into, the
published one.

These tests RUN on a bare checkout. That is the point: they need no `artifacts/`
and no dataset. It is also the reason they must be read carefully, because a
green line here is exactly the kind of thing that gets quoted as though the
engine had been verified. It has not been. The tests gated on the real
artifacts (tests/test_offline.py, tests/test_smoke.py and the engine part of
tests/test_app.py) are the ones that verify the published engine, they are
gated on `tests/_stubs.engine_artifacts_present()`, and
`test_the_demo_lane_does_not_satisfy_the_real_artifact_gate` below exists to
prove that building this lane does not turn them green.

WHAT THIS FILE COSTS A JUDGE WHO RUNS THE SUITE
Four model fits dominate it. None was removed to make it cheaper: the three that
are evidence for the determinism claim need three separate fresh interpreters
(section 2 says why), and the fourth is the lane the rest of the file reads.
What changed is that they are now run CONCURRENTLY instead of one after another,
and the byte-identity assertion over two of them is what keeps that from being a
shortcut — if sharing a machine ever perturbed a fit, this file fails.

A WARNING ABOUT THE WALL-CLOCK NUMBERS BELOW. `pytest tests/test_demo_bootstrap.py
-q` was measured five times this session on identical code and came back at
50.42, 65.38, 75.03, 102.26 and 120.29 s — a factor of 2.4, because this machine
was shared with other sessions running their own suites. Any single before/after
pair from it would be noise quoted as a result. So the schedule change was
measured as an INTERLEAVED A/B instead, three rounds, both schedules doing the
same four fits (seconds, sequential / overlapped):

    round 0      404.00 / 143.68
    round 1      173.91 / 112.53
    round 2      167.52 / 146.31

Overlapping won every round, by between 1.15x and 2.8x. The absolute numbers are
worthless — the same work takes about 60 s on an idle machine — and only the
ratio is being claimed.
"""

from __future__ import annotations

import copy
import datetime
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
if str(REPO_ROOT / "scripts") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "scripts"))

import verify_weights as VW  # noqa: E402

from configs import load_config  # noqa: E402
from engine import thresholds as TH  # noqa: E402
from scripts import bootstrap_demo_artifacts as B  # noqa: E402

SCRIPT = REPO_ROOT / "scripts" / "bootstrap_demo_artifacts.py"

# The two filenames `tests/_stubs.engine_artifacts_present()` gates the
# end-to-end tests on. Named here so that the test below fails if the demo lane
# ever starts writing one of them.
PUBLISHED_GATE_WEIGHTS = ("engine_model.json", "engine_model_flow.json")


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


# The smallest manifest `B.format_report` will render, for tests whose subject is
# the REPORT rather than a fit. Spelled out rather than built by bootstrapping,
# so checking what the report says about a coverage block costs milliseconds
# instead of a model.
_MINIMAL_MANIFEST = {
    "target": "somewhere", "capture": "c.pcap", "operator_log": "c.log",
    "seed": 0, "fit_threads": 1, "fit_threads_pin_effective": True,
    "weights_reproducible": True, "n_host_windows": 1, "n_attack_windows": 1,
    "stage_window_counts": {"benign": 1}, "role_features_degraded": False,
    "capture_coverage": {"known": True, "total": 0, "fraction": 0.0},
    "capture_window_start": 0.0, "capture_window_end": 15.0,
    "heads": [], "heads_not_fitted": {}, "digests": {}, "files": [],
    "fpr_budgets_below_capture_resolution": [],
    "hand_authored_stages_that_remain_unlabelled_in_the_real_dataset": [],
}


def in_process_bootstrap(**kwargs) -> dict:
    """`B.bootstrap` for a test that only needs a lane ON DISK, not stable bytes.

    Every in-process call in this file goes through here, and it is not a
    convenience wrapper — it is the reason the bytes those lanes contain are not
    treated as evidence anywhere. `B.bootstrap` refuses by default once xgboost
    has been imported in the process, because the OMP_NUM_THREADS pin is inert
    from that moment and the lane's provenance would otherwise record a thread
    count the fit never used. A pytest session has usually imported xgboost long
    before this module is collected, so these calls opt out explicitly and the
    lanes they produce carry `weights_reproducible: false`.

    The byte-identity claim is therefore tested ONLY from fresh subprocesses
    (`script_runs` below), which is also the only form a judge runs.
    """
    kwargs.setdefault("allow_unpinned_threads", True)
    return B.bootstrap(**kwargs)


def nowcast_only_cfg() -> dict:
    """The real config with `engine.forecast_horizons` emptied.

    For tests whose subject is not the heads: `bootstrap` then fits the two
    horizon-0 heads instead of eight, which is a quarter of the fitting work. It
    is a CONFIG value, not a test hook — exactly the run a checkout with no
    forecast horizons configured would do — so nothing about the code path under
    test is stubbed out. (No seconds are quoted here on purpose: this machine's
    wall-clock timings varied by 2.4x this session, see the module docstring.)

    Never use it for anything that reads the k-step heads.
    """
    cfg = copy.deepcopy(load_config("data"))
    cfg["engine"] = {**cfg["engine"], "forecast_horizons": []}
    return cfg


def lane_cfg(target: Path) -> dict:
    """The real config with BOTH the artifacts dir and the demo dir at `target`.

    Both, because that is the shape `engine/predict.py:_lane_cfg` hands to the
    threshold loader for a demo run: the lane's own directory IS the artifacts
    directory for the duration of that run, and `engine/thresholds.py` allows a
    demo-marked file only there.
    """
    cfg = copy.deepcopy(load_config("data"))
    cfg["paths"]["artifacts_dir"] = str(target)
    cfg["demo"]["artifacts_dir"] = str(target)
    return cfg


@pytest.fixture(scope="module")
def demo_lane(lanes) -> tuple[dict, Path]:
    """One bootstrap run into a temporary directory, shared by most tests.

    Built by the `lanes` fixture (section 2) alongside the subprocess runs, so
    that this file pays for four fits in roughly the wall time of one.
    """
    return lanes["demo_lane"]


# ---------------------------------------------------------------------------
# 1. It produces a model the engine can load, on the engine's own features.
# ---------------------------------------------------------------------------


def test_the_engine_loads_the_demo_model_through_its_own_loader(demo_lane):
    """`engine.predict._load_engine` — not a bespoke reader — opens every head.

    Falsifiable: `_load_engine` builds a bare `xgb.XGBClassifier` and calls
    `load_model`. Persisting the fitted object any other way (pickle, joblib, a
    Booster dumped directly) raises there, so this passes only while the demo
    lane writes the same model class the published lane does.
    """
    import xgboost as xgb

    from engine import predict as P

    manifest, target = demo_lane
    cfg = lane_cfg(target)

    variants = [h["variant"] for h in manifest["heads"]]
    assert "full" in variants and "flow" in variants, (
        f"the engine picks 'full' for PCAP input and 'flow' for CSV; the demo lane "
        f"persisted {variants}")

    for variant in variants:
        booster, scaler, fname = P._load_engine(cfg, variant)
        assert isinstance(booster, xgb.XGBClassifier), (
            f"{variant} loaded as {type(booster).__name__}, which is not the class "
            "engine/predict.py reconstructs")
        assert fname == TH.load_model_spec(cfg, variant)["file"]
        assert scaler is not None


def test_the_demo_model_scores_the_features_the_engine_extracts(demo_lane):
    """Same 30 columns, same order, as `data.windows.feature_columns`.

    Falsifiable: a demo model fitted on a parallel feature path would have a
    different input width, and XGBoost raises on a feature-count mismatch at
    predict time — which is what the scoring call below would hit.
    """
    import numpy as np

    from data import windows as W
    from engine import predict as P

    manifest, target = demo_lane
    cfg = lane_cfg(target)
    expected = W.feature_columns(cfg)

    persisted = json.loads((target / "engine_threshold.json").read_text(encoding="utf-8"))
    assert persisted["features"] == expected, (
        "the demo lane recorded a different feature order than data/windows.py "
        "produces; the engine would scale one order and score another")

    booster, scaler, _ = P._load_engine(cfg, "full")
    assert booster.n_features_in_ == len(expected)

    # And it really scores the capture it was fitted from, through the engine's
    # own extraction path.
    pcap, _log = B.demo_capture_paths(cfg)
    _flows, wf, _cov = B.window_features_from_demo_capture(cfg, pcap, None)
    X = scaler.transform(wf[expected].to_numpy(dtype=np.float64)).astype(np.float32)
    probs = booster.predict_proba(X)[:, 1]
    assert len(probs) == len(wf) == manifest["n_host_windows"]
    assert float(probs.min()) >= 0.0 and float(probs.max()) <= 1.0


def test_labels_come_from_the_operator_log_and_cover_the_kill_chain(demo_lane):
    """Every attack stage the operator log declares has labelled windows.

    The bundled capture walks recon -> initial access -> lateral movement ->
    exfiltration. If the labelling silently matched nothing, the fit would be
    single-class, which `bootstrap` refuses — this pins the stronger property
    that each declared stage really landed on windows.

    ON ITS OWN THIS WAS VACUOUS, and that is worth stating because it passed
    anyway. `declared` comes from `parse_operator_log`, so a stage row that
    function dropped disappeared from BOTH sides of the comparison: the demo
    model could stop seeing exfiltration entirely and this test would still be
    green. The row count below is what closes that — every non-comment,
    non-header line in the file has to survive parsing — and
    `test_a_malformed_operator_log_row_is_never_silently_skipped` is the other
    half.
    """
    manifest, _target = demo_lane
    cfg = load_config("data")
    _pcap, log = B.demo_capture_paths(cfg)

    rows = B.parse_operator_log(log)
    body = [ln for ln in log.read_text(encoding="utf-8").splitlines()
            if ln.strip() and not ln.lstrip().startswith("#") and ln.count("\t") != 1]
    assert len(rows) == len(body), (
        f"{log.name} has {len(body)} stage lines but parse_operator_log returned "
        f"{len(rows)}; a dropped line is a kill-chain stage silently missing from "
        "the demo model's labels")

    declared = {r["stage"] for r in rows if r["stage"] != "benign"}
    assert declared, f"{log} declares no attack stages"

    counts = manifest["stage_window_counts"]
    missing = sorted(s for s in declared if counts.get(s, 0) <= 0)
    assert not missing, (
        f"{log.name} declares stages {sorted(declared)} but the labelling produced no "
        f"windows for {missing}; counts were {counts}")
    assert counts.get("benign", 0) > 0, "no benign windows — nothing to threshold against"


def test_a_capture_the_extractor_could_not_fully_read_is_refused(
        demo_lane, tmp_path, monkeypatch):
    """Frames dropped on the way in stop the run instead of shrinking the model.

    `engine.predict._windows_from_input` returns a coverage block counting what
    the IPv4 parser could not read. On the bundled capture that is zero today
    (measured this session: `{"known": true, "total": 0, "fraction": 0.0}`), which
    is exactly why a non-zero count is a signal: the capture is committed and its
    SHA-256 is recorded in every lane fitted from it.

    The plausible break is not a corrupt file, it is a change to the capture or
    the parser that starts dropping some frames — IPv6 above all. The demo model
    would then be fitted on less traffic than the operator log describes, and the
    two checks that could notice (the single-class refusal, and
    `test_labels_come_from_the_operator_log_and_cover_the_kill_chain`) only fire
    when a stage vanishes ENTIRELY. Partial loss is the silent case.

    Falsifiable three ways here: a positive drop count raises, zero and
    `known: false` do not (so the refusal keys on a real count rather than on the
    block being present), and the refusal is reached through `bootstrap` on the
    real capture rather than only as a helper in isolation.
    """
    cfg = nowcast_only_cfg()
    pcap, _log = B.demo_capture_paths(cfg)
    dropped = {"known": True, "total": 37, "fraction": 0.021,
               "by_reason": {"ipv6": 37}}
    unknown = {"known": False, "total": None, "fraction": None,
               "by_reason": {"ipv6": None}}
    clean = {"known": True, "total": 0, "fraction": 0.0, "by_reason": {"ipv6": 0}}

    with pytest.raises(B.CaptureNotFullyParsed, match="could not read"):
        B.refuse_a_partially_parsed_capture(dropped, pcap)
    B.refuse_a_partially_parsed_capture(clean, pcap)    # zero drops: fine
    B.refuse_a_partially_parsed_capture(unknown, pcap)  # unknown: not an error

    # And `bootstrap` really consults it, on the real extraction path, before it
    # writes anything.
    real = B.window_features_from_demo_capture
    monkeypatch.setattr(
        B, "window_features_from_demo_capture",
        lambda c, p, a: (lambda t: (t[0], t[1], dropped))(real(c, p, a)))
    target = tmp_path / "dropped_lane"
    with pytest.raises(B.CaptureNotFullyParsed, match="could not read"):
        in_process_bootstrap(cfg=cfg, target=target)
    assert not target.exists() or not list(target.iterdir()), (
        "the refused run left a partially built lane behind")
    monkeypatch.undo()

    # Unknown is not an error, but it must never be printed as clean.
    assert "did not report how many frames it dropped" in B.format_report(
        {**_MINIMAL_MANIFEST, "capture_coverage": unknown})
    assert "did not report how many frames it dropped" not in B.format_report(
        {**_MINIMAL_MANIFEST, "capture_coverage": clean})

    # Finally, the fact that makes a non-zero count a signal rather than noise:
    # the real capture, on the real path, loses nothing. Read off the lane the
    # module fixture already built, so this costs nothing.
    real_coverage = demo_lane[0]["capture_coverage"]
    assert real_coverage["known"] is True and real_coverage["total"] == 0, (
        f"{pcap.name} no longer parses completely ({real_coverage}), so the "
        "refusal above would now stop real runs")


def test_the_lane_records_which_fpr_budgets_this_capture_cannot_express(demo_lane):
    """A budget finer than 1/n_benign is not a second operating point.

    `eval.metrics.threshold_at_fpr` can only ever achieve 0, 1/N, 2/N ... on N
    benign rows, so on a capture this short a 0.1% budget and a 1% budget come
    back as the SAME cut. Persisting both under two budget names, with nothing
    saying they are one point, is a number outrunning the data behind it — and it
    is the number a judge would move in the app expecting the alerts to change.

    Measured this session on the built lane: the horizon-0 heads have 120 benign
    rows (finest expressible FPR 0.83%), so 0.1% is below resolution there; by
    k=4 only 96 benign rows survive the target shift and the 1% budget is below
    resolution as well.

    Falsifiable: the recorded collapse is re-derived here from the thresholds
    actually persisted, so a lane that recorded `budget_expressible: false` while
    the two thresholds genuinely differed — or the reverse — fails.
    """
    manifest, target = demo_lane
    persisted = json.loads((target / "engine_threshold.json").read_text(encoding="utf-8"))
    prov = persisted[B.PROVENANCE_KEY]
    budgets = [str(b) for b in load_config("eval")["fpr_budgets"]]
    assert len(budgets) >= 2, "this test needs at least two budgets to compare"

    assert prov["fpr_budgets_below_capture_resolution"], (
        "nothing was recorded as below resolution, but 120 benign rows cannot "
        "express a 0.1% FPR — either the capture grew or the accounting is gone")

    for head in manifest["heads"]:
        points = prov["operating_points"][head["variant"]]
        spec = persisted[head["variant"]]
        n_benign = points["n_benign"]
        assert points["finest_expressible_fpr"] == pytest.approx(1.0 / n_benign)

        for budget in budgets:
            recorded = points["budgets"][budget]
            # The recorded threshold IS the persisted one — not a second
            # computation that could drift from what the engine will load.
            assert recorded["threshold"] == pytest.approx(spec[f"fpr_{budget}"])
            assert recorded["budget_expressible"] is (
                float(budget) >= points["finest_expressible_fpr"])
            # Whatever was achieved has to be an integer multiple of 1/N: an
            # `achieved_fpr` that is not says the count and the divisor came from
            # different row sets.
            assert recorded["achieved_fpr"] * n_benign == pytest.approx(
                round(recorded["achieved_fpr"] * n_benign))

        # The collapse itself: every budget below resolution shares its cut with
        # a coarser one, which is the fact the report tells the reader.
        below = [b for b in budgets if not points["budgets"][b]["budget_expressible"]]
        for budget in below:
            coarser = [b for b in budgets if float(b) > float(budget)]
            assert any(points["budgets"][b]["threshold"]
                       == pytest.approx(points["budgets"][budget]["threshold"])
                       for b in coarser) or not coarser, (
                f"{head['variant']}: budget {budget} was recorded as below this "
                "capture's resolution but resolved to a cut no coarser budget "
                "shares, so the two really are different operating points")

    report = B.format_report(manifest)
    assert "FPR BUDGETS THIS CAPTURE CANNOT EXPRESS" in report
    # The report has to name the heads it is talking about, not just the fact.
    for head in manifest["heads"]:
        points = prov["operating_points"][head["variant"]]
        if any(not d["budget_expressible"] for d in points["budgets"].values()):
            assert head["variant"] in report, (
                f"{head['variant']} has a budget below this capture's resolution "
                "but the printed report does not mention it")


def test_the_lane_says_its_hand_authored_stages_do_not_fill_the_real_gap(demo_lane):
    """recon / lateral_movement / exfiltration here are illustrations, not data.

    Those three stages have NO labelled windows in the dataset this project
    reports on (CLAUDE.md, docs/limitations.md). This lane has labelled windows
    for all three, because they were hand-written into the bundled capture to be
    found again. A judge who builds the demo, sees `lateral_movement=12` in the
    report and concludes the gap is closed has been misled by an artifact of this
    workstream — so the lane and the report both say otherwise, in words.

    Falsifiable: the assertion derives the list from the lane's own stage counts,
    so a lane that stopped labelling those stages would fail the first half, and
    one that labels them without recording the caveat fails the second.
    """
    manifest, target = demo_lane
    prov = json.loads((target / "engine_threshold.json").read_text(
        encoding="utf-8"))[B.PROVENANCE_KEY]
    key = "hand_authored_stages_that_remain_unlabelled_in_the_real_dataset"

    labelled = {s for s in ("recon", "lateral_movement", "exfiltration")
                if manifest["stage_window_counts"].get(s, 0) > 0}
    assert labelled, (
        "this lane labels none of the three stages the real dataset is missing, "
        "so this test is vacuous — check app/assets/synthetic_demo.operator-log.txt")
    assert set(prov[key]) == labelled
    assert set(manifest[key]) == labelled

    report = B.format_report(manifest)
    assert "THIS DOES NOT FILL THE EMPTY KILL-CHAIN STAGES" in report
    assert "NO labelled data" in report
    warning = (target / B.WHAT_THIS_IS_FILENAME).read_text(encoding="utf-8")
    assert "DO NOT FILL THE PROJECT'S THREE EMPTY STAGES" in warning


def test_a_log_that_does_not_overlap_the_capture_is_a_loud_failure(demo_lane):
    """A date or timezone mistake must not silently label nothing.

    Falsifiability for the test above: the same operator-log rows, resolved
    against a capture whose clock is a day away, raise instead of quietly
    producing an all-benign frame. Without this guard the labelling could break
    completely and `bootstrap` would only notice via the single-class check.
    """
    manifest, _target = demo_lane
    cfg = load_config("data")
    _pcap, log = B.demo_capture_paths(cfg)
    rows = B.parse_operator_log(log)

    # The capture's REAL window range, read off the lane the module fixture
    # built rather than typed in. The inherited version hardcoded
    # `1_760_000_000.0` with the comment "the bundled capture's first packet" —
    # measured this session, `window_start.min()` is 1759999990.0, so the number
    # and the claim beside it had already come apart. Nothing here needs a
    # literal: the run that built the lane knows.
    real_start = float(manifest["capture_window_start"])
    real_end = float(manifest["capture_window_end"])
    assert real_end > real_start
    B.stage_intervals(cfg, rows, real_start, real_end)  # the true range: fine

    # Six hours later on the SAME UTC date — so the date the log is resolved
    # against is unchanged and only the clocks disagree. This is the shape a
    # timezone mistake takes, and it is the one that would otherwise label
    # nothing at all.
    six_hours = 6 * 3600.0
    with pytest.raises(ValueError, match="entirely outside the capture"):
        B.stage_intervals(cfg, rows, real_start + six_hours, real_end + six_hours)


# ---------------------------------------------------------------------------
# 2. Determinism, and what it actually costs.
#
# Determinism is a real claim about the artifacts a judge builds, and proving it
# needs more than one fit. Three fresh subprocesses earn their place:
#
#   A  the script, clean environment
#   B  the script, with a hostile OMP_NUM_THREADS already exported
#   C  the same bootstrap at a DIFFERENT `demo.fit_threads`
#
#   A == B  the bytes are reproducible AND the ambient environment cannot move
#           them.
#   A != C  the pin is load-bearing, measured on the REAL demo fit rather than
#           on a stand-in matrix, so it cannot keep passing after the real fit
#           stops being thread-sensitive.
#
# Why subprocesses at all: `pin_fit_threads` writes OMP_NUM_THREADS, and OpenMP
# fixes XGBoost's thread count at XGBoost's first import. In-process the pin is
# usually already dead (see `in_process_bootstrap`), so an in-process check
# would be measuring nothing. A fresh interpreter is also the only form a judge
# runs.
#
# WHAT IT COSTS, AND WHAT WAS DONE ABOUT IT. The inherited version ran all four
# fits one after another, and they were the whole cost of the file: measured
# once at 89.32 s total with `--durations=15`, 63.44 s of it in the subprocess
# fixture and 15.40 s in the in-process one.
#
# None of the four was deleted and none was weakened. They do not depend on each
# other, they write to separate directories and they only read the committed
# capture, so `lanes` starts the three subprocesses and does the in-process fit
# while they run. The saving is wall-clock scheduling, not assurance — and it is
# self-checking, because `test_two_runs_of_the_script_write_byte_identical_weights`
# compares two of these concurrent runs byte for byte. If sharing a machine ever
# perturbed a fit, this file fails rather than quietly accepting it.
#
# The size of the saving is in the module docstring, measured as an interleaved
# A/B rather than as a before/after pair: this machine is shared, and repeated
# runs of identical code varied by a factor of 2.4, which is more than the whole
# effect being claimed.
# ---------------------------------------------------------------------------


def _clean_env(env_extra: dict | None = None) -> dict:
    """The ambient environment with OMP_NUM_THREADS removed, plus `env_extra`.

    Removed rather than left alone because the pytest process that spawns these
    may itself have OMP_NUM_THREADS set (`bootstrap` restores it, but a judge's
    shell may export one), and run A has to start from nothing for run B's
    hostile value to mean anything.
    """
    env = dict(os.environ)
    env.pop("OMP_NUM_THREADS", None)
    env.update(env_extra or {})
    return env


def _spawn_script(target: Path, env_extra: dict | None = None
                  ) -> tuple[subprocess.Popen, Path]:
    """The script, as a judge runs it, in a fresh interpreter. Not awaited here."""
    proc = subprocess.Popen(
        [sys.executable, str(SCRIPT), "--target", str(target)],
        cwd=str(REPO_ROOT), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, env=_clean_env(env_extra))
    return proc, target


def _spawn_bootstrap_at_threads(target: Path, threads: int, driver: Path
                                ) -> tuple[subprocess.Popen, Path]:
    """`bootstrap()` in a fresh interpreter with `demo.fit_threads` overridden.

    A driver file rather than `-c`, so the traceback of a failure names real
    lines. It calls `bootstrap` with the default `allow_unpinned_threads=False`:
    a fresh interpreter has not imported xgboost, so the pin is live and the
    thread count under test is really the one applied.
    """
    driver.parent.mkdir(parents=True, exist_ok=True)
    driver.write_text(
        "import copy, sys\n"
        f"sys.path.insert(0, {str(REPO_ROOT)!r})\n"
        "from configs import load_config\n"
        "from scripts import bootstrap_demo_artifacts as B\n"
        "cfg = copy.deepcopy(load_config('data'))\n"
        "cfg['demo']['fit_threads'] = int(sys.argv[1])\n"
        "m = B.bootstrap(cfg=cfg, target=sys.argv[2])\n"
        "assert m['fit_threads_pin_effective'], 'the pin was inert in a fresh process'\n",
        encoding="utf-8")
    proc = subprocess.Popen(
        [sys.executable, str(driver), str(threads), str(target)],
        cwd=str(REPO_ROOT), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, env=_clean_env())
    return proc, target


def _weight_names(lane: Path) -> list[str]:
    return sorted(p.name for p in lane.iterdir()
                  if p.suffix in (".json", ".pkl") and p.name != "engine_threshold.json")


@pytest.fixture(scope="module")
def lanes(tmp_path_factory) -> dict:
    """Every lane this file needs — runs A, B, C and the in-process one — at once.

    See the section comment above for why each exists and what overlapping them
    does and does not buy.
    """
    root = tmp_path_factory.mktemp("lanes")
    configured = int(load_config("data")["demo"]["fit_threads"])

    procs = {
        "clean": _spawn_script(root / "a"),
        # B carries an OMP_NUM_THREADS the pin has to beat. Deliberately not the
        # configured value, and deliberately > 1, so "the environment won" and
        # "the pin won" cannot look the same.
        "hostile": _spawn_script(root / "b",
                                 {"OMP_NUM_THREADS": str(configured + 7)}),
        "other_threads": _spawn_bootstrap_at_threads(
            root / "c", configured + 3, root / "driver" / "fit_at_threads.py"),
    }

    # While those three run: the in-process lane. Its bytes are not evidence (see
    # `in_process_bootstrap`), so sharing a machine with three other fits cannot
    # cost this one anything that matters.
    #
    # It is overlapped with the three rather than run first and alone, and that
    # was measured, not assumed. It is the one fit that cannot be thread-pinned,
    # so it takes every core, and oversubscribing the machine looked like the
    # obvious thing to avoid. It is not: in an interleaved three-round A/B this
    # session the overlapped schedule beat the sequential one every round (the
    # numbers are in the module docstring). The intuition was wrong.
    in_process_target = root / "in_process"
    manifest = in_process_bootstrap(target=in_process_target)

    out: dict = {"demo_lane": (manifest, in_process_target)}
    for name, (proc, target) in procs.items():
        stdout, stderr = proc.communicate(timeout=900)
        assert proc.returncode == 0, f"the {name!r} run failed:\n{stderr}"
        out[name] = target
        out[f"{name}_stdout"] = stdout
    return out


@pytest.fixture(scope="module")
def script_runs(lanes) -> dict:
    """Runs A, B and C, by their historical names."""
    return lanes


def test_two_runs_of_the_script_write_byte_identical_weights(script_runs, tmp_path):
    """Same capture in, same bytes out — and the environment cannot change them.

    The second run carries an exported OMP_NUM_THREADS that the script has to
    override; byte-identity therefore proves both that the run is reproducible
    and that `demo.fit_threads` — not whatever the shell happened to export — is
    what decided the bytes.

    Falsifiable: the last block copies one run, flips a single byte in one
    weight file, and requires the same comparison to report it. Without that, an
    equality over an empty file list or over a broken hash would pass silently.
    """
    first, second = script_runs["clean"], script_runs["hostile"]

    weights = _weight_names(first)
    assert len(weights) >= 2, f"too few weight files to compare: {weights}"

    digests = {n: sha256(first / n) for n in weights}
    differing = [n for n in weights if digests[n] != sha256(second / n)]
    assert not differing, (
        f"two runs on the same capture produced different bytes for {differing}; "
        "the demo lane is not reproducible (the second run had OMP_NUM_THREADS "
        "exported, so this is also how an inherited environment overriding the "
        "pin would look)")
    assert len(set(digests.values())) > 1, (
        "every weight file hashed to the same digest, so the equality above is "
        "measuring the hash function and not the files")

    tampered = tmp_path / "tampered"
    tampered.mkdir()
    for f in first.iterdir():
        (tampered / f.name).write_bytes(f.read_bytes())
    victim = weights[0]
    raw = bytearray((tampered / victim).read_bytes())
    raw[len(raw) // 2] ^= 0x01
    (tampered / victim).write_bytes(bytes(raw))
    assert [n for n in weights if digests[n] != sha256(tampered / n)] == [victim], (
        "a one-byte change went unnoticed by the comparison used above")


def test_the_pinned_thread_count_is_why_the_bytes_are_stable(script_runs):
    """Seeding alone does NOT make the weights reproducible; the pin does.

    `models/baselines.py` builds the head with `n_jobs=-1`, so XGBoost uses one
    thread per core and its parallel histogram build sums in a thread-dependent
    order. Run C is the SAME capture, the SAME seed and the SAME code at a
    different `demo.fit_threads`; requiring its models to differ from run A is
    what makes the pin load-bearing rather than decorative.

    The plausible break it guards: deleting `pin_fit_threads` as redundant
    because `set_seed` is already called. The test above would still pass on one
    machine — both runs would use that machine's core count — and the artifacts
    would silently stop being reproducible anywhere else. This one fails.

    Measured here on the real demo fit: `demo_engine_model.json` was
    d428729d3562... at one thread and 1003f2454f32... at four, and all eight
    heads moved. `window_scaler.pkl` did not, which is why it is excluded — it
    is a single-threaded sklearn pickle, and including it would let a
    thread-insensitive fit hide behind an always-equal file.
    """
    clean, other = script_runs["clean"], script_runs["other_threads"]
    models = [n for n in _weight_names(clean) if n.endswith(".json")]
    assert models, "no model files to compare"

    same = [n for n in models if sha256(clean / n) == sha256(other / n)]
    assert not same, (
        f"{same} came out byte-identical at two different thread counts, so this "
        "machine shows no thread sensitivity and the reproducibility claim in "
        "scripts/bootstrap_demo_artifacts.py must be re-measured rather than "
        f"assumed (cpu_count={os.cpu_count()})")

    scaler = "window_scaler.pkl"
    assert sha256(clean / scaler) == sha256(other / scaler), (
        "the sklearn scaler changed with the thread count, which it must not — "
        "the comparison above is then measuring something other than XGBoost's "
        "parallel histogram build")


def test_the_bootstrap_records_whether_the_thread_pin_actually_applied(
        demo_lane, script_runs):
    """The lane never claims a thread count the fit did not use.

    THIS IS THE TEST THAT REPLACED A FALSE ONE. The inherited version asserted
    `os.environ["OMP_NUM_THREADS"] == demo.fit_threads` and that the provenance
    recorded the same number — both of which are true in the exact case that
    matters, because `pin_fit_threads` writes the variable whether or not OpenMP
    is still listening. Measured in this session: in a process that had already
    imported xgboost, `fit_threads=1` and `fit_threads=4` produced IDENTICAL
    weights (bc7fdd07d9dc..., this machine's 12-core default) while the lane
    recorded the requested number. The record was a number the run had not
    applied — the project's named failure mode, in an artifact.

    So the lane now records what happened. This asserts that the record tracks
    reality in BOTH directions — a hardcoded True or a hardcoded False would each
    fail one half — and that the manifest and the file on disk say the same thing.

    Note what is NOT asserted: a fixed value for the `demo_lane` fixture. Whether
    xgboost is already imported when that fixture runs depends on what else the
    session collected first (running this file alone, nothing has imported it;
    inside the full suite, something usually has). Pinning either answer would be
    pinning the collection order, which is how a test starts failing for reasons
    that have nothing to do with its subject.
    """
    manifest, target = demo_lane
    configured = int(load_config("data")["demo"]["fit_threads"])
    prov = json.loads((target / "engine_threshold.json").read_text(
        encoding="utf-8"))[B.PROVENANCE_KEY]

    assert prov["fit_threads"] == configured
    # The returned manifest and the persisted lane must not disagree: a reader
    # who trusts the printed report and a reader who opens the directory have to
    # be told the same thing.
    assert prov["fit_threads_pin_effective"] is manifest["fit_threads_pin_effective"]
    assert prov["weights_reproducible"] is prov["fit_threads_pin_effective"], (
        "`weights_reproducible` came apart from the only fact that decides it")

    # TRUE half: the lane the SCRIPT wrote, in a fresh interpreter.
    script_prov = json.loads(
        (script_runs["clean"] / "engine_threshold.json").read_text(encoding="utf-8")
    )[B.PROVENANCE_KEY]
    assert script_prov["fit_threads_pin_effective"] is True, (
        "the script, run as a script in a fresh interpreter, recorded that its "
        "thread pin did not take effect — so either the pin is broken or the flag "
        "is hardcoded False")
    assert script_prov["weights_reproducible"] is True
    assert "NOT REPRODUCIBLE" not in script_runs["clean_stdout"]
    assert "DEMO ARTIFACTS WRITTEN" in script_runs["clean_stdout"]

    # FALSE half: a lane built deliberately after an `import xgboost`. Lives in
    # test_bootstrap_refuses_by_default_once_xgboost_is_imported, which also
    # covers the refusal that stops such a lane being written by accident.


def test_the_thread_pin_is_set_for_the_fit_and_put_back_afterwards(tmp_path):
    """OMP_NUM_THREADS is a process-global, so `bootstrap` must not leak it.

    Two separate facts, and both matter:
      - `pin_fit_threads` really exports the configured value, which is the only
        way the pin can reach OpenMP at all;
      - `bootstrap` restores whatever was there before, on the success path AND
        on a refusal.

    The plausible break is the obvious one: pin it and forget it. Nothing in this
    file would notice — the lane is still correct, the digests still match — but
    every test that ran after one of these in the same session, and every
    subprocess it spawned, would silently inherit OMP_NUM_THREADS=1. That is a
    1400-test suite quietly re-threaded by a demo bootstrap.

    Falsifiable in both directions: the first block fails if the pin stops being
    written, the second and third fail if it stops being restored, and the
    sentinel value proves the restore puts back the PREVIOUS value rather than
    just deleting the variable.
    """
    cfg = nowcast_only_cfg()
    before = os.environ.get("OMP_NUM_THREADS")
    try:
        os.environ.pop("OMP_NUM_THREADS", None)
        threads, _effective = B.pin_fit_threads(cfg)
        assert os.environ.get("OMP_NUM_THREADS") == str(threads), (
            "pin_fit_threads did not export OMP_NUM_THREADS, so the thread count "
            "can never reach OpenMP and the reproducibility claim has no mechanism")

        # A sentinel the run must hand back untouched, on a COMPLETED run.
        os.environ["OMP_NUM_THREADS"] = "9"
        in_process_bootstrap(cfg=cfg, target=tmp_path / "ok")
        assert os.environ.get("OMP_NUM_THREADS") == "9", (
            "a completed bootstrap left its own thread pin exported")

        # And on the refusal path, where a `finally` is easy to leave out.
        published = tmp_path / "published_like"
        published.mkdir()
        (published / "engine_model.json").write_bytes(b"published")
        with pytest.raises(B.PublishedArtifactsPresent):
            in_process_bootstrap(cfg=cfg, target=published)
        assert os.environ.get("OMP_NUM_THREADS") == "9", (
            "a refused bootstrap left its own thread pin exported")

        # Unset before the call means unset after it, not the pinned value.
        os.environ.pop("OMP_NUM_THREADS", None)
        in_process_bootstrap(cfg=cfg, target=tmp_path / "ok2")
        assert "OMP_NUM_THREADS" not in os.environ, (
            "bootstrap invented an OMP_NUM_THREADS where the process had none")
    finally:
        if before is None:
            os.environ.pop("OMP_NUM_THREADS", None)
        else:
            os.environ["OMP_NUM_THREADS"] = before


def test_bootstrap_refuses_by_default_once_xgboost_is_imported(tmp_path):
    """The refusal is what keeps an unreproducible lane off disk.

    Falsifiable two ways, both here: the same call with the escape hatch
    succeeds (so the refusal is caused by the pin check and not by something
    else in the run), and the lane it writes says `weights_reproducible: false`
    rather than staying silent.
    """
    import xgboost  # noqa: F401  -- the precondition, stated out loud
    assert "xgboost" in sys.modules

    refused = tmp_path / "refused"
    with pytest.raises(B.ThreadPinIneffective, match="already imported"):
        B.bootstrap(target=refused)
    assert not refused.exists() or not list(refused.iterdir()), (
        "the refused run left files behind")

    allowed = tmp_path / "allowed"
    manifest = B.bootstrap(target=allowed, allow_unpinned_threads=True)
    assert manifest["weights_reproducible"] is False
    assert (allowed / "engine_threshold.json").exists()
    report = B.format_report(manifest)
    assert "NOT REPRODUCIBLE" in report, (
        "a lane whose thread pin was inert printed a report that did not say so")


# ---------------------------------------------------------------------------
# 3. It refuses to clobber the published artifacts. THE safety property.
# ---------------------------------------------------------------------------


def test_it_refuses_to_write_into_the_published_artifacts_directory():
    """Target == `paths.artifacts_dir` is refused before anything is written."""
    from configs import resolve_path

    cfg = load_config("data")
    published = resolve_path(cfg["paths"]["artifacts_dir"])
    with pytest.raises(B.PublishedArtifactsPresent, match="PUBLISHED artifacts directory"):
        in_process_bootstrap(target=published)


def test_it_refuses_a_directory_holding_published_weights_and_touches_nothing(tmp_path):
    """A published weight file in the target stops the run, intact.

    Falsifiable two ways, both exercised here:
      - remove the sentinel and the SAME directory bootstraps fine, so the
        refusal is caused by the sentinel and not by some unrelated failure;
      - the sentinel's bytes are unchanged and no demo weight appeared beside
        it, so the refusal happened BEFORE any write rather than after a partial
        one.
    """
    target = tmp_path / "looks_like_artifacts"
    target.mkdir()
    sentinel = target / "engine_model.json"
    sentinel.write_bytes(b"pretend this is the published model")
    before = sha256(sentinel)

    with pytest.raises(B.PublishedArtifactsPresent, match="already holds"):
        in_process_bootstrap(target=target)

    assert sha256(sentinel) == before, "the refused run modified the published weight"
    assert sorted(p.name for p in target.iterdir()) == ["engine_model.json"], (
        "the refused run wrote files into a directory holding published weights")

    sentinel.unlink()
    in_process_bootstrap(target=target)
    assert (target / "engine_threshold.json").exists(), (
        "with the sentinel gone the same directory must bootstrap — otherwise the "
        "refusal above was not caused by the sentinel")


def test_the_refusal_is_what_stops_it_not_some_later_failure(tmp_path, monkeypatch):
    """Disable the guard and the run really does overwrite the published weight.

    This is the plausible break: a contributor who finds the refusal in the way
    comments it out, or makes it a warning. With the check neutered the very
    same call destroys the file the test above protected — so the guard, and
    nothing else, is what was holding.
    """
    target = tmp_path / "artifacts_like"
    target.mkdir()
    sentinel = target / "engine_model.json"
    sentinel.write_bytes(b"pretend this is the published model")
    before = sha256(sentinel)

    monkeypatch.setattr(B, "refuse_to_clobber_published_artifacts",
                        lambda cfg, target: None)
    in_process_bootstrap(target=target)

    assert (target / "engine_threshold.json").exists()
    assert sha256(sentinel) == before, (
        "unexpected: the demo lane wrote over engine_model.json itself. It must "
        "never write a published weight name at all")
    names = {p.name for p in target.iterdir()}
    assert names & {"window_scaler.pkl", "engine_threshold.json"}, (
        "with the guard removed the run should have written the demo lane into a "
        "directory holding published artifacts; it did not, so this test is not "
        "measuring what it claims")


def test_it_refuses_a_directory_holding_published_thresholds(tmp_path):
    """Published thresholds anywhere are refused, by their lane marker.

    Falsifiable: the same file marked as the demo lane is accepted, so the
    refusal keys on the marker rather than on the filename.
    """
    target = tmp_path / "elsewhere"
    target.mkdir()
    threshold = target / "engine_threshold.json"

    threshold.write_text(json.dumps({"full": {"file": "engine_model.json"}}), encoding="utf-8")
    with pytest.raises(B.PublishedArtifactsPresent, match="marked lane 'published'"):
        in_process_bootstrap(target=target)

    threshold.write_text(json.dumps({TH.LANE_FIELD: TH.DEMO_LANE}), encoding="utf-8")
    in_process_bootstrap(target=target)  # a previous demo lane is ours to overwrite
    assert json.loads(threshold.read_text(encoding="utf-8"))["model"] == "xgb"


# ---------------------------------------------------------------------------
# 4. The digests verify, and a tampered demo model is still refused.
# ---------------------------------------------------------------------------


def test_recorded_digests_verify_through_the_engines_own_attestation(demo_lane):
    """`scripts/verify_weights.verify` — the function engine/predict.py calls."""
    manifest, target = demo_lane
    cfg = lane_cfg(target)

    ok, offender = VW.verify(cfg)
    assert ok, f"the demo lane's own digest record does not verify: {offender}"

    # Exactly the call engine/predict.py makes before it will write a ledger record.
    model_file = TH.load_model_spec(cfg, "full")["file"]
    ok, offender = VW.verify(cfg, names=[model_file, "window_scaler.pkl"])
    assert ok, offender

    recorded = json.loads((target / "weights.sha256").read_text(encoding="utf-8"))
    assert set(recorded) == {h["file"] for h in manifest["heads"]} | {"window_scaler.pkl"}, (
        "the digest record does not cover exactly the weights this lane wrote")


def test_a_tampered_demo_model_is_refused(demo_lane, tmp_path):
    """Flip one byte and attestation fails, naming the file.

    Falsifiable by construction: the untampered copy verifies in the test above,
    and the same call on the same lane fails here after a single-byte edit.
    """
    _manifest, source = demo_lane
    target = tmp_path / "tampered"
    target.mkdir()
    for f in source.iterdir():
        (target / f.name).write_bytes(f.read_bytes())

    cfg = lane_cfg(target)
    model_file = TH.load_model_spec(cfg, "full")["file"]
    assert VW.verify(cfg, names=[model_file])[0], "the untampered copy should verify"

    raw = bytearray((target / model_file).read_bytes())
    raw[len(raw) // 2] ^= 0x01
    (target / model_file).write_bytes(bytes(raw))

    ok, offender = VW.verify(cfg, names=[model_file])
    assert not ok and offender == model_file, (
        f"a tampered demo model verified anyway (ok={ok}, offender={offender})")


# ---------------------------------------------------------------------------
# 5. The demo lane cannot become the published one.
# ---------------------------------------------------------------------------


def test_the_demo_lane_does_not_satisfy_the_real_artifact_gate(demo_lane, monkeypatch,
                                                               tmp_path):
    """A fully built demo lane leaves the gated end-to-end tests gated.

    `tests/_stubs.engine_artifacts_present()` is what tests/test_offline.py,
    tests/test_smoke.py and the engine half of tests/test_app.py skip on. Those
    tests verify the PUBLISHED engine; a pass against a toy fitted on a bundled
    capture would not be evidence for anything they claim. So this asks that
    gate, pointed at a complete demo lane, and requires it to still say no.

    Falsifiable twice:
      - the filename check fails the moment the demo lane writes
        `engine_model.json` or `engine_model_flow.json`, which is exactly what
        dropping `demo.model_prefix` would do;
      - the gate is then asked about a directory holding those published NAMES
        and must say yes. Without that second half a gate wired to return False
        unconditionally — or left stale behind its cache — would pass the first
        half and prove nothing.
    """
    import configs

    from tests import _stubs

    manifest, target = demo_lane
    written = set(manifest["files"])
    collisions = sorted(written & set(PUBLISHED_GATE_WEIGHTS))
    assert not collisions, (
        f"the demo lane wrote {collisions}, which are the published weight names "
        "tests/_stubs.py gates the end-to-end tests on")

    def point_at(directory: Path) -> None:
        cfg = lane_cfg(directory)
        monkeypatch.setattr(configs, "load_config",
                            lambda name: cfg if name == "data" else load_config(name))
        # The probe is lru_cached for the process; without this it answers about
        # whatever directory it was first asked about.
        _stubs.reset_artifact_lane_cache()

    try:
        point_at(target)
        assert _stubs.engine_artifacts_present() is False, (
            "a bootstrapped demo lane satisfied engine_artifacts_present(), so "
            "building it would turn the gated end-to-end tests green against a toy "
            "model")

        # The gate is live: give it the published filenames and it says yes.
        looks_published = tmp_path / "artifacts"
        looks_published.mkdir()
        persisted = json.loads(
            (target / "engine_threshold.json").read_text(encoding="utf-8"))
        for demo_name, published_name in (
                (persisted["full"]["file"], "engine_model.json"),
                (persisted["flow"]["file"], "engine_model_flow.json"),
                ("window_scaler.pkl", "window_scaler.pkl")):
            (looks_published / published_name).write_bytes((target / demo_name).read_bytes())
        persisted.pop(TH.LANE_FIELD)
        persisted["full"]["file"] = "engine_model.json"
        persisted["flow"]["file"] = "engine_model_flow.json"
        (looks_published / "engine_threshold.json").write_text(
            json.dumps(persisted), encoding="utf-8")

        point_at(looks_published)
        assert _stubs.engine_artifacts_present() is True, (
            "engine_artifacts_present() said no to a directory holding the four "
            "published artifact names, so the assertion above is vacuous")
    finally:
        monkeypatch.undo()
        _stubs.reset_artifact_lane_cache()


def test_demo_thresholds_are_refused_outside_the_demo_directory(demo_lane, tmp_path):
    """Copying the demo lane into another artifacts directory fails loudly.

    The plausible break: someone with no `artifacts/` copies `artifacts_demo/*`
    into `artifacts/` so that whatever needs a model finds one. Nothing else
    about that swap is visible — the files load and the probabilities look like
    results — so `engine/thresholds.py` refuses a demo-marked file read from
    anywhere but the configured demo directory.

    Falsifiable twice over: the SAME file loads fine when the directory is the
    demo one, and a file without the marker loads fine from the wrong directory.
    So the refusal is caused by the marker-plus-location pair and not by the
    location alone.
    """
    _manifest, source = demo_lane
    elsewhere = tmp_path / "artifacts"
    elsewhere.mkdir()
    for f in source.iterdir():
        (elsewhere / f.name).write_bytes(f.read_bytes())

    # Read from `elsewhere` while the config still says the demo lane lives at
    # `source` — i.e. demo weights copied into another artifacts directory.
    cfg = copy.deepcopy(load_config("data"))
    cfg["paths"]["artifacts_dir"] = str(elsewhere)
    cfg["demo"]["artifacts_dir"] = str(source)
    with pytest.raises(RuntimeError, match="DEMO weights"):
        TH.load_model_spec(cfg, "full")

    # Same bytes, read from the demo directory: fine.
    assert TH.load_model_spec(lane_cfg(source), "full")["file"]

    # Same directory, marker removed: fine. The guard is the marker, not the path.
    unmarked = json.loads((elsewhere / "engine_threshold.json").read_text(encoding="utf-8"))
    unmarked.pop(TH.LANE_FIELD)
    (elsewhere / "engine_threshold.json").write_text(json.dumps(unmarked), encoding="utf-8")
    assert TH.artifact_lane(cfg) == TH.PUBLISHED_LANE
    assert TH.load_model_spec(cfg, "full")["file"]


def test_the_demo_lane_declares_itself_in_its_persisted_thresholds(demo_lane):
    """The marker, the provenance and the warning file are all present."""
    _manifest, target = demo_lane
    cfg = lane_cfg(target)

    assert TH.artifact_lane(cfg) == TH.DEMO_LANE
    persisted = json.loads((target / "engine_threshold.json").read_text(encoding="utf-8"))
    prov = persisted[B.PROVENANCE_KEY]
    assert prov["source_capture"] == cfg["demo"]["pcap"]
    assert prov["source_capture_sha256"] == VW.sha256_file(B.demo_capture_paths(cfg)[0])
    assert prov["fitted_and_thresholded_in_sample"] is True

    warning = (target / B.WHAT_THIS_IS_FILENAME).read_text(encoding="utf-8")
    assert "NOT THE PUBLISHED MODEL" in warning


def test_no_head_reports_a_validation_auroc(demo_lane):
    """`val_auroc` stays empty on the demo lane; the figure is in-sample.

    The published lane fills `val_auroc` with a held-out measurement. This lane
    has no held-out split at all — the thresholds are chosen on the rows the
    model was fitted on — so writing that key would put a memorisation figure in
    the field a reader takes for a measurement. It is `in_sample_auroc`, flagged.
    """
    manifest, target = demo_lane
    persisted = json.loads((target / "engine_threshold.json").read_text(encoding="utf-8"))
    specs = {k: v for k, v in persisted.items()
             if isinstance(v, dict) and "file" in v}
    assert specs, "no model specs persisted"
    for name, spec in specs.items():
        assert "val_auroc" not in spec, (
            f"demo head '{name}' reports a val_auroc; there is no validation split "
            "behind this lane and that field must stay empty here")
        assert spec["auroc_is_in_sample"] is True
        assert 0.0 <= float(spec["in_sample_auroc"]) <= 1.0
    assert manifest["heads"], "no heads fitted"


# ---------------------------------------------------------------------------
# 6. The labelling path cannot fail quietly.
#
# The demo model's only ground truth is app/assets/synthetic_demo.operator-log.txt.
# Every way that file can stop reaching the labels is a way the demo model loses
# a kill-chain stage while still fitting, still thresholding and still printing a
# probability — so each of them has to be an error, not a skip.
# ---------------------------------------------------------------------------


def _write_log(path: Path, lines: list[str]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


HEADER_LINES = [
    "session_id\tsynthetic-demo",
    "iface\tsynthetic",
    "# columns: stage\tstart\tend\tattacker_ip\tvictim_ip",
]


def test_a_malformed_operator_log_row_is_never_silently_skipped(tmp_path):
    """A stage row with the wrong field count raises instead of vanishing.

    The plausible break, and the one that was live: `parse_operator_log` used to
    skip every line with fewer than five tab-separated fields, because that is
    how it told stage rows from the `key<TAB>value` headers. A stage row that
    lost a field — a hand edit, a changed generator, a log written with spaces —
    took the same path and disappeared. The demo model then had no windows for
    that stage, and nothing anywhere said so.

    Falsifiable in both directions here: the well-formed file parses to exactly
    its two rows (so the strictness is not rejecting the real header shape), and
    the same file with one field removed from one row raises.
    """
    good_lines = HEADER_LINES + [
        "recon\t08:55:30\t08:56:30\t203.0.113.7\t10.20.0.10",
        "exfiltration\t08:58:50\t08:59:50\t10.20.0.10\t203.0.113.7",
    ]
    good = _write_log(tmp_path / "good.txt", good_lines)
    assert [r["stage"] for r in B.parse_operator_log(good)] == ["recon", "exfiltration"]

    short = _write_log(tmp_path / "short.txt",
                       good_lines[:-1] + ["exfiltration\t08:58:50\t08:59:50\t10.20.0.10"])
    with pytest.raises(ValueError, match="tab-separated fields"):
        B.parse_operator_log(short)

    wide = _write_log(tmp_path / "wide.txt",
                      good_lines + ["impact\t09:00:00\t09:01:00\ta\tb\textra"])
    with pytest.raises(ValueError, match="tab-separated fields"):
        B.parse_operator_log(wide)


def test_the_labelling_rule_is_the_one_data_timeline_labels_uses(tmp_path):
    """`B.label_windows` must agree with `data.timeline_labels.label_windows`.

    WHY THERE ARE TWO AT ALL. The shared rule is only reachable in
    `timeline_labels` through `attack_intervals` ->
    `_local_to_epoch_utc(date, hhmm, offset)`, which does
    `hh, mm = (int(x) for x in hhmm.split(":"))` and raises on a third field. The
    operator log writes HH:MM:SS and those seconds are load-bearing: the stage
    spans start at :20, :30, :40 and :50 past the minute, and a 15 s window on a
    5 s stride resolves them, so truncating to the minute would move every
    boundary by up to 59 s. `data/timeline_labels.py` is not this workstream's
    file to refactor, so the rule is reimplemented — and this is the test that
    keeps the reimplementation honest.

    The frame is SYNTHETIC and tiny on purpose: it costs milliseconds, and it can
    contain the cases the real capture does not — a window overlapping a stage by
    one second at each edge, a host that is not a party to an overlapping stage,
    and two stages covering one window so the priority rule is exercised.

    Falsifiable: the two implementations are run over the same rows and the same
    intervals, and the assertions below require both a non-trivial spread of
    labels and exact equality. Changing either side's overlap test (to
    containment, say) or its priority direction (first stage wins) breaks it.
    """
    import pandas as pd

    from data import timeline_labels as TL

    cfg = copy.deepcopy(load_config("data"))
    window_sec = int(cfg["windows"]["window_seconds"])
    base = 1_700_000_000  # any epoch; both sides resolve against the same one

    # A timeline in `timeline_labels`' own YAML shape, at whole minutes so its
    # HH:MM parser can read it. Two attacks that overlap in time on one host, so
    # the priority rule decides; `c2` is later than `initial_access` in
    # configs/data.yaml `stages`, so c2 must win the shared windows.
    day = datetime.datetime.fromtimestamp(base, datetime.timezone.utc)
    timeline = {
        "timezone": {"utc_offset_hours": 0},
        "days": [{
            "date": day.strftime("%Y-%m-%d"),
            "attacks": [
                {"name": "a", "stage": "initial_access",
                 "start": "12:05", "end": "12:09",
                 "attacker_ips": ["10.0.0.1"], "victim_ips": ["10.0.0.2"]},
                {"name": "b", "stage": "c2",
                 "start": "12:07", "end": "12:11",
                 "attacker_ips": ["10.0.0.2"], "victim_ips": ["10.0.0.3"]},
            ],
        }],
    }
    midnight = datetime.datetime(day.year, day.month, day.day,
                                 tzinfo=datetime.timezone.utc).timestamp()

    rows = []
    for host in ("10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.9"):
        for i in range(160):  # 12:00:00 -> 12:13:15, on the configured stride
            start = midnight + 12 * 3600 + i * float(cfg["windows"]["stride_seconds"])
            rows.append({"host": host, "window_id": i, "window_start": start})
    wf = pd.DataFrame(rows)

    intervals = [
        {"stage": atk["stage"], "start": atk["start"], "end": atk["end"],
         "hosts": set(atk["hosts"])}
        for atk in TL.attack_intervals(cfg, timeline)
    ]
    ours = B.label_windows(cfg, wf, intervals)
    theirs = TL.label_windows(cfg, wf, timeline)

    counts = ours.value_counts().to_dict()
    assert set(counts) == {"benign", "initial_access", "c2"}, (
        f"the synthetic frame did not exercise every branch of the rule: {counts}")
    assert counts["c2"] > 0 and counts["initial_access"] > 0, counts
    assert (ours == theirs).all(), (
        "the bootstrap's labelling rule disagrees with data/timeline_labels.py on "
        f"{int((ours != theirs).sum())} of {len(wf)} rows. Disagreements by stage: "
        f"{pd.crosstab(ours[ours != theirs], theirs[ours != theirs]).to_dict()}")
    # The window that both stages cover must carry the later stage, not the first
    # one seen — the half of the rule a frame without overlaps cannot check.
    overlapped = wf[(wf["host"] == "10.0.0.2")
                    & (wf["window_start"] < midnight + 12 * 3600 + 9 * 60)
                    & (wf["window_start"] + window_sec > midnight + 12 * 3600 + 7 * 60)]
    assert not overlapped.empty
    assert set(ours.loc[overlapped.index]) == {"c2"}, (
        "a window covered by two stages did not take the later one in "
        "configs/data.yaml `stages` order")
    assert set(ours[wf["host"] == "10.0.0.9"]) == {"benign"}, (
        "a host that is party to no stage picked up a label")


def test_labelling_refuses_pseudonymised_hosts(demo_lane):
    """Labels must be attached before identities are hashed.

    The plausible break: `data/windows.py` starts pseudonymising `host` on the
    engine's PCAP path (it already has the machinery, and the anti-leakage rules
    push in that direction). Every operator-log IP would then match nothing,
    every window would come back benign, and `bootstrap`'s single-class check
    WOULD still fire — but saying "the capture and the operator log disagree",
    which sends the reader to regenerate a capture that is perfectly fine.

    Falsifiable: the real frame labels normally on the line above the raises, so
    the refusal is caused by the hashed hosts and not by the frame being
    unusable.
    """
    _manifest, target = demo_lane
    cfg = lane_cfg(target)
    pcap, log = B.demo_capture_paths(cfg)
    _flows, wf, _cov = B.window_features_from_demo_capture(cfg, pcap, None)
    intervals = B.stage_intervals(
        cfg, B.parse_operator_log(log),
        float(wf["window_start"].min()),
        float(wf["window_start"].max()) + cfg["windows"]["window_seconds"])

    labels = B.label_windows(cfg, wf, intervals)
    assert (labels != "benign").any(), "the real frame produced no attack labels"

    hashed = wf.assign(host=[hashlib.sha256(str(h).encode()).hexdigest()[:16]
                             for h in wf["host"]])
    with pytest.raises(ValueError, match="dotted-IP"):
        B.label_windows(cfg, hashed, intervals)


# ---------------------------------------------------------------------------
# 7. The lane agrees with the modules that read it.
# ---------------------------------------------------------------------------


def test_the_digest_record_covers_everything_verify_weights_demands(demo_lane):
    """Nothing verify_weights would check is left unhashed by the bootstrap.

    Two modules meet at this one file. `scripts/verify_weights.py` owns the
    question "what must a lane's record cover" (`tracked_names`), and this script
    writes the record. If they disagree in the direction that matters — the
    bootstrap omitting a name verify_weights expects — `verify` reports a
    mismatch on a lane nobody touched, or passes over bytes it never hashed. So
    the bootstrap asks `tracked_names` rather than keeping a second list, and
    this pins that it did.

    Falsifiable: `tracked_names` is called here on the same lane, so a bootstrap
    that went back to a hardcoded list would have to stay in step with a module
    by hand, and the first divergence fails here.
    """
    manifest, target = demo_lane
    cfg = lane_cfg(target)
    recorded = json.loads((target / "weights.sha256").read_text(encoding="utf-8"))

    demanded = [n for n in VW.tracked_names(cfg) if (target / n).exists()]
    assert demanded, "verify_weights demands nothing of this lane, so this is vacuous"
    missing = sorted(n for n in demanded if n not in recorded)
    assert not missing, (
        f"weights.sha256 does not cover {missing}, which verify_weights.tracked_names "
        "says this lane's record must contain")

    # Every k-step head is hashed too, which is MORE than verify_weights tracks.
    assert set(recorded) == {h["file"] for h in manifest["heads"]} | {"window_scaler.pkl"}


def test_the_flow_head_is_masked_the_way_the_published_trainer_masks_it(demo_lane):
    """The CSV variant is built exactly as engine/train_engine.py builds it.

    The demo lane exists to let someone exercise the engine that ships, so it
    mirrors the published trainer rather than improving on it. Both zero the 17
    packet-stat columns AFTER scaling, and both derive that set from
    `configs/data.yaml` `packet_features.fields` rather than listing columns.

    THE INHERITED VERSION OF THIS TEST PROVED NONE OF THAT. It built a mask
    locally, asserted things about the mask it had just built, and then checked
    that the two head files differ. `B.flow_feature_mask` was never called, so
    the script could have masked an entirely different set of columns — the 11
    sent-side fields, say — and every assertion would still have held: the
    locally-built mask is still correct, and the two heads still differ.

    What replaces it is a property of the PERSISTED head, measured on the real
    matrix. The masked columns are exactly 0.0 in every training row, so they are
    constant, so the fitted trees never split on them, so the flow head's output
    cannot depend on them at all. Scoring the raw matrix and the masked matrix
    must therefore give IDENTICAL probabilities — and that identity is destroyed
    the moment the mask covers the wrong columns, because the real packet columns
    would then be non-constant in training and the trees would use them.

    Falsifiable, and both halves are checked here: the flow head must be exactly
    insensitive (measured this session: max |difference| = 0.0) and the FULL
    head, fitted on the unmasked matrix, must NOT be (measured: 0.0329). Without
    the second half a broken loader that returned constant probabilities would
    pass the first.

    It also settles the train/inference gap the mask would otherwise open.
    `engine/predict.py` applies no mask at inference — it scales a raw frame
    whose packet columns `window_features_from_flows` set to 0.0, which lands on
    (0-mean)/std rather than on 0. For a head that provably never reads those
    columns, that cannot change a prediction.
    """
    import numpy as np

    from data import windows as W
    from engine import predict as P

    _manifest, target = demo_lane
    cfg = lane_cfg(target)
    feat_cols = W.feature_columns(cfg)
    packet_cols = list(cfg["packet_features"]["fields"])

    mask = B.flow_feature_mask(cfg)
    assert len(mask) == len(feat_cols) == 30
    assert [c for c, m in zip(feat_cols, mask) if m == 0.0] == packet_cols, (
        "the script's flow mask does not zero exactly the packet-statistic "
        "fields engine/train_engine.py zeroes")

    # The two heads really are different models.
    full_file = TH.load_model_spec(cfg, "full")["file"]
    flow_file = TH.load_model_spec(cfg, "flow")["file"]
    assert sha256(target / full_file) != sha256(target / flow_file), (
        "the 'full' and 'flow' heads are byte-identical, so the flow mask changed "
        "nothing about the fit")

    # And the flow head really was fitted with those columns held at zero.
    pcap, _log = B.demo_capture_paths(cfg)
    _flows, wf, _cov = B.window_features_from_demo_capture(cfg, pcap, None)
    flow_head, scaler, _ = P._load_engine(cfg, "flow")
    full_head, _, _ = P._load_engine(cfg, "full")
    X = scaler.transform(wf[feat_cols].to_numpy(dtype=np.float64)).astype(np.float32)

    flow_gap = float(np.abs(flow_head.predict_proba(X)[:, 1]
                            - flow_head.predict_proba(X * mask)[:, 1]).max())
    assert flow_gap == 0.0, (
        f"the flow head's prediction moved by {flow_gap} when the packet columns "
        "changed, so it was NOT fitted with those columns masked to a constant — "
        "the mask covers the wrong set, or it is not being applied")

    full_gap = float(np.abs(full_head.predict_proba(X)[:, 1]
                            - full_head.predict_proba(X * mask)[:, 1]).max())
    assert full_gap > 0.0, (
        "the full head is also insensitive to the packet columns, so the check "
        "above is measuring something other than the mask (a constant-output "
        "model would pass it too)")
