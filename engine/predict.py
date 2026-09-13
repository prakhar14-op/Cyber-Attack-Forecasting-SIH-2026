"""Prediction engine (M8.6): file -> forecasts -> explanations -> ledger.

    from engine import predict
    predict.predict_file("capture.csv", out_dir="run/")

Fully offline: loads the persisted engine model + threshold + scaler (no
network, no runtime downloads), builds per-(source_host, window) features from
the input, scores each host-window, and for every ALERT emits an explained
forecast object (probability, stage, MITRE technique, named top features,
flagged flows, estimated lead) validated against a JSON schema, and appends it
to the tamper-evident ledger. Returns the summary the app and smoke runner use.

CSV input gives flow-derived features only (packet-statistic features need
PCAP — decision 001); the pipeline runs either way.

Weights come from one ARTIFACT LANE, resolved once per run: the published engine
if it is on disk, otherwise a declared demo lane fitted from the bundled
synthetic capture so a fresh clone can run at all. See the lane section below —
the demo lane can never shadow the published one, and every result of a demo run
says so in its own data.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import NamedTuple

import numpy as np
import pandas as pd

from configs import load_config, resolve_path, set_seed

# An alert whose window matches no stage rule. NOT one of the seven stage
# classes (configs/data.yaml `stages` is the label encoding for the trained
# heads and must not grow an eighth entry) — it is the honest outcome of a rule
# set that did not fire, and carries no MITRE technique.
UNCLASSIFIED_STAGE = "unclassified"

# Hosts in the forecasts, the graph and forecasts.json are the addresses an
# analyst has to act on; nothing on this path pseudonymises them. Only the
# LEDGER does (M9.2, under its own key). The value reported in the run summary is
# MEASURED off the hosts actually emitted (_hosts_pseudonymised) rather than
# declared here, so a UI caption cannot claim a privacy property the data does
# not have; this constant is the design expectation a test pins that measurement
# against.
HOSTS_PSEUDONYMISED = False

# forecasts.json stays a bare schema-validated ARRAY of forecast objects — one
# entry per alert and nothing else. The run-level facts that are in no single
# forecast — coverage of the input, the alert threshold, whether the hosts are
# pseudonyms — go in a sibling file rather than in a wrapper object around that
# array, so a SAVED run carries them too: an in-process caller is not the only
# reader that must be able to tell "0 alerts" from "saw nothing".
#
# Nothing in this repo reads either file back (app/panels.py renders the dict
# predict_file RETURNS); they are the artifact of a run, for an analyst, a judge
# or an external tool to inspect afterwards. That is why the shape is pinned by
# tests rather than by a caller that would break if it changed.
FORECASTS_FILE = "forecasts.json"
RUN_SUMMARY_FILE = "run_summary.json"

# What predict_file puts in a caller-supplied `scoring_context` (see the
# docstring). engine/forecast.py scores the k-step heads off `wf`, `X`,
# `feature_columns` and `variant`; `probabilities`, `flows` and `threshold` are
# the rest of what this run decided, so a second consumer does not have to
# re-derive them. The names are pinned by tests/test_forecast_engine.py, so
# renaming one here without renaming it there cannot silently leave the k-step
# forecaster scoring nothing.
SCORING_CONTEXT_KEYS = ("variant", "feature_columns", "wf", "X", "probabilities",
                        "flows", "threshold", "lane")

# ---------------------------------------------------------------------------
# Artifact lanes: the PUBLISHED engine, and the DEMO model a fresh clone can fit
# ---------------------------------------------------------------------------
# The published weights are gitignored (CLAUDE.md: never commit weights) and the
# GitHub Release is unpublished, so a judge who clones this repository has no
# artifacts/ and cannot run anything. scripts/bootstrap_demo_artifacts.py fits a
# small model from the BUNDLED synthetic capture into a second artifact
# directory (`configs/data.yaml` `demo.artifacts_dir`) so the pipeline can be
# exercised end to end. That model has MEMORISED that capture. It reproduces none
# of this project's published numbers, which were measured on CSE-CIC-IDS-2018.
#
# A lane declares itself in its persisted thresholds: engine/thresholds.py owns
# the `artifact_lane` field and refuses to serve a demo-marked threshold file from
# any directory but the configured demo one. This module is the other half — it
# decides WHICH lane a run uses, and makes every result say so.
#
# Four rules keep the two impossible to confuse; each is pinned by a test in
# tests/test_engine.py:
#   1. The published lane is consulted FIRST and wins whenever it is usable. The
#      demo lane can never shadow it.
#   2. A PARTIALLY present published lane is a hard error, never a fallback. A
#      real artifact going missing must not quietly become a demo run that looks
#      normal — that is the exact failure this whole design exists to prevent.
#   3. The demo directory is used only when its own thresholds DECLARE it the demo
#      lane. Flipping that declaration (or deleting it) to dress the demo weights
#      up as published ones fails the run instead of renaming them.
#   4. The lane is resolved ONCE per run and travels as a config, so a run cannot
#      mix a published nowcast with a demo k-step head.
SCALER_FILE = "window_scaler.pkl"

# What every result produced on the demo lane carries, verbatim, in its return
# dict, in run_summary.json and in the k-step block. The text is OURS, in this
# module: the provenance block inside a demo lane is written by another script,
# and nothing written there may be able to soften what a demo run says about
# itself. Every sentence is a fact about the lane, not a hedge.
DEMO_MODEL_NOTICE = (
    "DEMO MODEL - NOT THE PUBLISHED ENGINE. This run scored against a small model "
    "fitted locally by scripts/bootstrap_demo_artifacts.py from the synthetic "
    "capture bundled in this repository, so that a fresh clone can execute the "
    "pipeline at all. It was fitted and thresholded on that one capture and has "
    "memorised it: a high probability here means the model has seen the row "
    "before, not that an attack was detected. It is NOT the model behind any "
    "number this project publishes - those were measured on CSE-CIC-IDS-2018, "
    "which is not on this machine, and the fused 0.933 AUROC is eval-side and "
    "does not run in this engine at all. Every probability, threshold, alert, "
    "stage and forecast in this run is an illustration of the machinery and "
    "reproduces nothing. Do not quote a number from a demo run."
)


class ArtifactLane(NamedTuple):
    """Which set of weights a run is using, and how to read it.

    `cfg` is the config with `paths.artifacts_dir` pointed at this lane. The lane
    travels as a CONFIG rather than as an extra argument because every reader of
    the artifacts directory — engine/thresholds.py, scripts/verify_weights.py and
    _load_engine — resolves it out of the config. Handing them one lane cfg puts
    the whole run on one lane by construction; an extra parameter would have to be
    threaded through three modules and could be forgotten on one, which is how a
    run ends up with a published nowcast and a demo k=8 head.
    """

    name: str          # engine.thresholds.PUBLISHED_LANE | .DEMO_LANE
    dir: Path
    cfg: dict
    demo: bool
    notice: str | None  # DEMO_MODEL_NOTICE on the demo lane, None on the published one
    source: str | None  # what the demo lane says it was fitted from, if it says


def _verify_weights():
    """scripts/verify_weights.py, imported by path.

    `scripts/` is not a package, so it goes on sys.path first. One helper rather
    than the same three lines in two places: the digest check and the
    half-installed-bundle check must be talking about the same module.
    """
    import sys as _sys
    from pathlib import Path as _Path

    scripts = str(_Path(__file__).resolve().parent.parent / "scripts")
    if scripts not in _sys.path:
        _sys.path.insert(0, scripts)
    import verify_weights as VW

    return VW


def _lane_core_files(cfg: dict) -> tuple[str, ...]:
    """The files a lane must hold before ANY variant can be loaded from it.

    The threshold filename is read from engine/thresholds.py rather than repeated
    here, so renaming it there cannot leave this check testing for a file the
    engine no longer writes.
    """
    from engine import thresholds as TH

    return (TH.threshold_path(cfg).name, SCALER_FILE)


def _published_lane_files(cfg: dict) -> tuple[str, ...]:
    """The files THIS ENGINE would load out of a published lane: its threshold
    file, its scaler, and its two nowcast weight files. Finding any of them in the
    published artifacts directory is evidence that a published bundle was being
    installed there.

    Deliberately not all of scripts/verify_weights.TRACKED: `tgn_encoder.pt` and
    `graft.pt` belong to the research models, the deployed engine never loads
    them, and a machine that has done research training but has no engine bundle
    is entitled to run the demo lane.

    Wider than `_lane_core_files` on purpose. Lane resolution needs to know
    whether the published directory is EMPTY (nothing was ever installed — fall
    back to the demo lane) or HALF-INSTALLED (a published bundle is partly there
    — refuse). The threshold file and the scaler alone do not answer that: a
    directory holding `engine_model.json` and `engine_model_flow.json` and
    nothing else is a half-finished release download, and before this list
    existed it resolved to the demo lane and ran, which is the precise failure
    this design exists to prevent (measured: the probe in this session resolved
    lane='demo' with both published weight files sitting in the directory).

    The weight names come from scripts/verify_weights.PUBLISHED_NOWCAST_WEIGHTS
    rather than being spelled here, so the module that attests published weights
    and the module that detects them cannot disagree about their names.
    """
    return (*_lane_core_files(cfg), *_verify_weights().PUBLISHED_NOWCAST_WEIGHTS)


def _lane_cfg(cfg: dict, art_dir: Path) -> dict:
    """`cfg` with paths.artifacts_dir repointed at one lane (never mutated)."""
    return {**cfg, "paths": {**cfg["paths"], "artifacts_dir": str(art_dir)}}


def demo_lane_dir(cfg: dict):
    """configs/data.yaml `demo.artifacts_dir`, or None when the config has no demo
    block at all (a stub cfg in a test, or a checkout predating the demo lane).

    Deliberately the same lookup engine/thresholds.py makes, and pinned against it
    by tests/test_engine.py::test_the_demo_lane_directory_is_one_place_in_config —
    two modules disagreeing about where the demo lane lives is how a lane gets
    loaded by one and disowned by the other.
    """
    demo = cfg.get("demo")
    configured = demo.get("artifacts_dir") if isinstance(demo, dict) else None
    return resolve_path(configured) if configured else None


def _demo_source(data: dict):
    """What the demo lane says it was fitted from, if it says.

    Best-effort DETAIL, read out of the lane's own provenance block. The
    load-bearing statement is DEMO_MODEL_NOTICE, which is ours; nothing this
    returns can soften it, and its absence changes nothing.
    """
    prov = data.get("demo_provenance")
    source = prov.get("source_capture") if isinstance(prov, dict) else None
    return source if isinstance(source, str) else None


def _demo_lane(cfg: dict) -> ArtifactLane | None:
    """The demo lane, or None if none was ever bootstrapped — but never a silent
    None for a lane that IS there and is wrong.

    A half-written lane, and a lane whose thresholds do not declare themselves
    demo, both raise here. Returning None for either would surface as the ordinary
    "no artifacts" error, which reads as "nothing was ever bootstrapped" and sends
    whoever is looking at it to the wrong fix.
    """
    from engine import thresholds as TH

    demo_dir = demo_lane_dir(cfg)
    if demo_dir is None:
        return None
    core = _lane_core_files(cfg)
    present = [n for n in core if (demo_dir / n).exists()]
    if not present:
        return None
    if len(present) < len(core):
        raise RuntimeError(
            f"the demo artifact lane {demo_dir} is INCOMPLETE: {present} present, "
            f"{[n for n in core if n not in present]} missing. A half-written demo lane "
            "is refused rather than skipped — skipping it would surface as the ordinary "
            "missing-artifacts error and hide that a bootstrap ran and did not finish. "
            "Re-run `python scripts/bootstrap_demo_artifacts.py`."
        )
    lane_cfg = _lane_cfg(cfg, demo_dir)
    declared = TH.artifact_lane(lane_cfg)
    if declared != TH.DEMO_LANE:
        raise RuntimeError(
            f"{TH.threshold_path(lane_cfg)} is in the demo artifact lane but declares "
            f"lane '{declared}', not '{TH.DEMO_LANE}'. The engine will not load weights "
            "from the demo directory as though they were published ones: either these "
            "are published artifacts in the wrong place, or a demo lane's marker was "
            "edited. Re-run `python scripts/bootstrap_demo_artifacts.py`, or point "
            "`paths.artifacts_dir` at the real bundle."
        )
    persisted = json.loads(TH.threshold_path(lane_cfg).read_text(encoding="utf-8"))
    return ArtifactLane(
        name=TH.DEMO_LANE, dir=demo_dir, cfg=lane_cfg, demo=True,
        notice=DEMO_MODEL_NOTICE, source=_demo_source(persisted),
    )


def resolve_artifact_lane(cfg: dict, variant: str) -> ArtifactLane:
    """Which lane this run uses, for this input variant. Published first, always;
    demo only as a complete, self-declared, announced fallback.

    The published lane's claim is tested the honest way — by ASKING IT for this
    variant's model spec, which is what the run is about to do anyway — rather than
    by guessing from filenames. If it answers, it wins and the demo lane is never
    looked at. Only a published lane with no persisted thresholds AT ALL
    (FileNotFoundError) opens the question; a threshold file that exists but does
    not carry this variant raises its own KeyError straight through here, because a
    bundle that is missing one of its two models is broken, not a demo.

    With nothing on disk anywhere this returns the PUBLISHED lane unchanged, so the
    caller fails with the existing "run engine.train_engine / fetch the release"
    error rather than a new one — "no weights at all" is not a demo-lane problem.
    """
    from engine import thresholds as TH

    published_dir = resolve_path(cfg["paths"]["artifacts_dir"])
    published = ArtifactLane(name=TH.PUBLISHED_LANE, dir=published_dir, cfg=cfg,
                             demo=False, notice=None, source=None)

    demo_dir = demo_lane_dir(cfg)
    if demo_dir is not None and demo_dir == published_dir:
        raise RuntimeError(
            f"configs/data.yaml points `paths.artifacts_dir` and `demo.artifacts_dir` at "
            f"the same directory ({published_dir}). One directory cannot be both lanes: "
            "every run out of it would be reported as published while possibly holding "
            "demo weights. Give the demo lane its own directory."
        )

    try:
        TH.load_model_spec(cfg, variant)
    except FileNotFoundError:
        pass  # no persisted thresholds in the published lane at all
    else:
        return published

    # The published lane has no threshold file. If it holds any OTHER part of a
    # published bundle — the scaler, or either nowcast weight file — it is a
    # half-installed published bundle, and quietly running the demo model instead
    # would hide exactly that: the failure this whole design exists to prevent.
    # The weight files are in this set because they alone are a plausible partial
    # install (an interrupted release download leaves them and nothing else), and
    # with only the scaler and the threshold in the set that state resolved to the
    # demo lane and ran.
    strays = [n for n in _published_lane_files(cfg) if (published_dir / n).exists()]
    if strays:
        raise RuntimeError(
            f"the published artifact lane {published_dir} is INCOMPLETE: it holds "
            f"{strays} but no {TH.threshold_path(cfg).name}. Refusing to fall back to a "
            "demo model — a published artifact that went missing must not silently "
            "become a demo run that looks normal. Restore it (`python "
            "scripts/fetch_artifacts.py`, or `python -m engine.train_engine`), or move "
            f"{published_dir} aside entirely if you meant to run the demo lane."
        )
    demo = _demo_lane(cfg)
    return demo if demo is not None else published


def announce_lane(lane: ArtifactLane, stream=None) -> None:
    """Put a demo run in front of whoever started it, on stderr, every time.

    The data fields are what a program reads; this is what a human sees when they
    run the CLI, the smoke runner or a script and would otherwise watch a normal
    -looking run scroll past. The published lane prints nothing.
    """
    if not lane.demo:
        return
    out = sys.stderr if stream is None else stream
    lines = [f"*** {lane.notice}", f"*** demo artifact lane: {lane.dir}"]
    if lane.source:
        lines.append(f"*** demo model fitted from (as declared by the lane): {lane.source}")
    print("\n".join(lines), file=out, flush=True)


OUTPUT_SCHEMA = {
    "type": "object",
    # `demo_model` is REQUIRED: a forecast object that does not say which lane
    # produced it must not validate. forecasts.json is a bare array that can be
    # read — or quoted from — on its own, long after the run summary beside it has
    # been lost, so the lane has to travel on every object rather than only once.
    "required": ["host", "window_start", "probability", "stage", "technique",
                 "top_features", "top_windows", "flagged_flows", "demo_model"],
    "properties": {
        "host": {"type": "string"},
        "window_start": {"type": "number"},
        "probability": {"type": "number", "minimum": 0, "maximum": 1},
        "stage": {"type": "string",
                  "enum": [*load_config("data")["stages"], UNCLASSIFIED_STAGE]},
        "technique": {"type": ["string", "null"]},
        "technique_name": {"type": "string"},
        "top_features": {"type": "array", "items": {
            "type": "object",
            "required": ["feature", "value", "contribution"],
            "properties": {"feature": {"type": "string"}},
        }},
        "top_windows": {"type": "array", "items": {
            "type": "object",
            "required": ["window_start", "probability", "seconds_before_alert"],
        }},
        "flagged_flows": {"type": "array", "items": {
            "type": "object",
            "required": ["dst_port", "protocol", "bytes", "syn", "duration_us"],
            "properties": {
                "dst_port": {"type": "integer"},
                "protocol": {"type": "integer"},
                "bytes": {"type": "integer"},
                "syn": {"type": "integer"},
                "duration_us": {"type": "number"},
            },
        }},
        "estimated_lead_seconds": {"type": ["number", "null"]},
        "demo_model": {"type": "boolean"},
    },
}


def _is_pcap(path) -> bool:
    return str(path).lower().endswith((".pcap", ".pcapng"))


def _load_engine(cfg, variant: str):
    """Load one variant's (booster, scaler, model filename) from the artifacts
    directory `cfg` points at.

    The LANE is the caller's decision, expressed by which cfg is handed in:
    predict_file resolves it once with resolve_artifact_lane and passes
    `lane.cfg`, and engine/forecast.py passes that same cfg on for every k-step
    head. Called with a bare config this reads the published lane — the safe
    default for any caller that has not thought about lanes at all.
    """
    import pickle

    import xgboost as xgb

    from engine import thresholds as TH

    art = resolve_path(cfg["paths"]["artifacts_dir"])
    fname = TH.load_model_spec(cfg, variant)["file"]
    model_path = art / fname
    if not model_path.exists():
        raise FileNotFoundError(
            f"{model_path} missing — run `python -m engine.train_engine` first (M8.1), "
            "fetch the release with `python scripts/fetch_artifacts.py`, or fit the "
            "bundled-capture demo model with `python scripts/bootstrap_demo_artifacts.py`"
        )
    scaler_path = art / SCALER_FILE
    if not scaler_path.exists():
        raise FileNotFoundError(
            f"{scaler_path} missing while {model_path.name} is present — an artifact "
            "lane with a model and no scaler would score a feature matrix on the wrong "
            "scale. Re-fetch or re-fit the whole lane; do not mix lanes."
        )
    booster = xgb.XGBClassifier()
    booster.load_model(str(model_path))
    # Unpickling executes code, so the scaler is a trust boundary: predict_file
    # checks both files against this lane's recorded SHA-256 BEFORE calling here
    # (see the M9.3 block there). Load order matters — attest, then unpickle.
    with open(scaler_path, "rb") as fh:
        scaler = pickle.load(fh)
    return booster, scaler, fname


def _coverage(n_parsed: int, drops: dict | None) -> dict:
    """What the extractor could NOT read, so silence is never read as safety.

    A capture whose frames the IPv4 parser skips (IPv6 above all) yields no
    host-windows and therefore no alerts; the run summary must report that as
    unseen traffic rather than as a clean result.

    `drops` is None when the table carries no drop history at all (the counts
    ride on `.attrs`, which pandas strips as soon as a frame is combined with one
    that has none). Unknown is not clean: the counts come
    back None under `known: False` rather than zero, and the per-reason keys stay
    present so a consumer reading by_reason["ipv6"] gets None instead of a
    KeyError or a fabricated 0.
    """
    from data import packet_features as pf

    if drops is None:
        return {"known": False, "total": None, "fraction": None,
                "by_reason": dict.fromkeys(pf.DROP_REASONS, None)}
    by_reason = dict.fromkeys(pf.DROP_REASONS, 0)
    by_reason.update({k: int(v) for k, v in drops.items()})
    total = int(sum(by_reason.values()))
    seen = n_parsed + total
    return {
        "known": True,
        "total": total,
        "fraction": (total / seen) if seen else 0.0,
        "by_reason": by_reason,
    }


def _windows_from_input(cfg, input_path, anonymizer):
    """(flows, window_features, unparsed_frames). PCAP -> full extractor (all 30
    features); CSV -> flow-derived features (packet-stats absent, decision 001).
    A CSV carries no frames, so its coverage counters are all zero."""
    from data import flow_features as FF
    from data import packet_features as pf
    from data import windows as W

    if _is_pcap(input_path):
        packets = pf.extract_packet_table(input_path, cfg)
        unparsed = _coverage(len(packets), pf.dropped_frames(packets))
        pkt_win = pf.packet_window_features(packets, cfg)
        pkt_win, _ = pf.apply_retransmission_backend(pkt_win, input_path, cfg)
        pkt_win = pkt_win.merge(pf.sent_window_features(packets, cfg),
                                on=["src_ip", "window_id"], how="outer")
        flows = pf.assemble_flows(packets, cfg)
        # windows.py's per-parquet loader expects files on disk; build the
        # feature frame directly from the in-memory packet-window table.
        wf = W.window_features_from_packet_windows(cfg, pkt_win, anonymizer=anonymizer)
        return flows, wf, unparsed

    flows = FF.load_canonical(cfg, input_path)
    wf = W.window_features_from_flows(cfg, flows, anonymizer=anonymizer)
    return flows, wf, _coverage(0, dict.fromkeys(pf.DROP_REASONS, 0))


def predict_file(csv_path, out_dir, fpr_budget: float = 0.01, exclude_host=None,
                 scoring_context: dict | None = None) -> dict:
    """Run the offline engine on one file. Writes out_dir/audit_chain.jsonl,
    forecasts.json (the forecast array) and run_summary.json (the run-level
    facts, including what could not be parsed); returns the same summary with
    the forecasts and the host graph attached.

    The returned summary — and therefore run_summary.json — carries
    `artifact_lane`, `demo_model`, `demo_model_notice` and `demo_model_source`,
    and every forecast object carries `demo_model`. On a demo run
    `demo_model` is True everywhere, each ledger record says `artifact_lane:
    "demo"`, and DEMO_MODEL_NOTICE has already been printed to stderr. None of
    those numbers reproduce a published result; see DEMO_MODEL_NOTICE.

    exclude_host: what-if ablation (M10.4). When set, that host's own
    (source, window) rows and every flow it participated in are dropped from the
    already-extracted features before scoring — so the counterfactual runs
    through the IDENTICAL path (CSV or PCAP; the input is never re-parsed) and is
    exact for the per-(host, window) model.

    scoring_context: an out-parameter, never part of the RETURN value. Pass a
    dict and this fills it with the rows this run scored (SCORING_CONTEXT_KEYS:
    the raw feature frame, the scaled matrix, the nowcast probabilities, the
    flows and the variant). engine/forecast.py scores those same rows through the
    per-horizon heads, so the k-step forecast and the nowcast are guaranteed to
    be about identical features — re-extracting would re-parse the input and
    could drift. It stays out of the return value because the returned dict is
    persisted verbatim as run_summary.json."""
    cfg = load_config("data")
    set_seed(cfg["seed"])
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    from data.anonymize import Anonymizer
    from data import windows as W
    from engine import explain as EX
    from engine import thresholds as TH
    from ledger.ledger import Ledger

    variant = "full" if _is_pcap(csv_path) else "flow"
    anonymizer = _maybe_anonymizer(cfg)

    # WHICH WEIGHTS. Resolved ONCE, here, and every later read of an artifact in
    # this run goes through `lane.cfg` — the nowcast model, the threshold, the
    # digest record, and (via the scoring context) engine/forecast.py's k-step
    # heads. One resolution is what makes a mixed-provenance run impossible.
    lane = resolve_artifact_lane(cfg, variant)
    announce_lane(lane)

    # M9.3: bind this batch to exact weights — refuse to log on mismatch, so a
    # ledger entry can never claim provenance it does not have. Two things about
    # this call:
    #   * it runs BEFORE the weights are loaded, because loading the scaler
    #     unpickles it; a tampered pickle must be refused, not executed and then
    #     refused;
    #   * it is the SAME call on both lanes, against `lane.cfg`, so it reads the
    #     demo lane's own weights.sha256. A tampered demo model is refused exactly
    #     as a tampered published one is, by this code and not by a special case.
    VW = _verify_weights()

    model_file = TH.load_model_spec(lane.cfg, variant)["file"]
    ok, offender = VW.verify(lane.cfg, names=[model_file, SCALER_FILE])
    if not ok:
        raise RuntimeError(
            f"model-weight SHA-256 mismatch ({offender}) in the {lane.name} artifact "
            f"lane {lane.dir} — refusing to write ledger records (M9.3). Re-record with "
            f"`python scripts/verify_weights.py --artifacts-dir {lane.dir} --record` "
            "after an intentional retrain or re-bootstrap."
        )

    booster, scaler, loaded_file = _load_engine(lane.cfg, variant)
    if loaded_file != model_file:
        raise RuntimeError(
            f"the {lane.name} lane attested {model_file} but loaded {loaded_file}; "
            "refusing to run on weights this run did not verify"
        )
    threshold = TH.load_threshold(lane.cfg, fpr_budget, variant=variant)

    flows, wf, unparsed = _windows_from_input(cfg, csv_path, anonymizer)
    if exclude_host is not None:
        exclude_host = str(exclude_host)
        wf = wf[wf["host"].astype(str) != exclude_host].reset_index(drop=True)
        if len(flows):
            flows = flows[(flows["src_ip"].astype(str) != exclude_host)
                          & (flows["dst_ip"].astype(str) != exclude_host)].reset_index(drop=True)

    feat_cols = W.feature_columns(cfg)
    raw_X = wf[feat_cols].to_numpy(dtype=np.float64)
    if len(raw_X):
        X = scaler.transform(raw_X).astype(np.float32)
        probs = booster.predict_proba(X)[:, 1]
    else:  # zero host-windows (empty/degenerate input): 0 alerts, no crash
        X = np.empty((0, len(feat_cols)), dtype=np.float32)
        probs = np.empty(0, dtype=float)

    if scoring_context is not None:
        # Filled unconditionally, including on a zero-row run: a caller that got
        # an empty `wf` knows it saw nothing, whereas an unfilled context is
        # indistinguishable from a caller bug.
        scoring_context.update({
            "variant": variant, "feature_columns": feat_cols, "wf": wf, "X": X,
            "probabilities": probs, "flows": flows, "threshold": threshold,
            # The lane this run resolved, so engine/forecast.py loads its k-step
            # heads from the SAME weights — never a published nowcast with a demo
            # head bolted onto it, or the reverse.
            "lane": lane,
        })

    explainer = EX.ShapExplainer(booster, feat_cols)
    window_sec = cfg["windows"]["window_seconds"]
    stage_rules = cfg["stage_rules"]

    # A run analyses ONE file -> a fresh chain. (A long-lived deployment would
    # append across batches; the file-analysis engine starts clean so re-running
    # the same file does not grow a stale chain.)
    chain_path = out_dir / "audit_chain.jsonl"
    cp_path = out_dir / "checkpoints.jsonl"
    chain_path.unlink(missing_ok=True)
    cp_path.unlink(missing_ok=True)
    ledger = Ledger(chain_path, checkpoint_path=cp_path)

    # M8.3: per-host (window_start, probability) history for the top-contributing
    # -windows view — for an alert at window t, the recent windows of that host
    # whose own forecast was strongest (the deployed model is per-window; the
    # transformer's true attention is in the research GRAFT model).
    host_hist: dict[str, list[tuple[float, float]]] = {}
    hosts_arr = wf["host"].astype(str).to_numpy()
    ws_arr = wf["window_start"].to_numpy(dtype=float)
    for h, s, p in zip(hosts_arr, ws_arr, probs):
        host_hist.setdefault(h, []).append((float(s), float(p)))

    forecasts = []
    alert_rows = np.flatnonzero(probs >= threshold)
    tops = explainer.top_features(X[alert_rows], k=5) if len(alert_rows) else []
    max_ctx = cfg["windows"]["max_sequence_windows"] * cfg["windows"]["stride_seconds"]
    for local_i, row in enumerate(alert_rows):
        # Read the row out of the arrays already built above, not out of the
        # frame. `wf.iloc[row][c]` is one mixed-dtype row materialisation PER
        # FEATURE (~30 per alert), and it was the second-largest cost in a run
        # with many alerts. `raw_X` is `wf[feat_cols].to_numpy(float)` and
        # hosts_arr/ws_arr are the same two columns, so the values are identical
        # — verified in this session by byte-comparing forecasts.json and
        # audit_chain.jsonl across the change on three input sizes.
        host = str(hosts_arr[row])
        ws = float(ws_arr[row])
        feats = {c: float(v) for c, v in zip(feat_cols, raw_X[row])}
        # stage: the engine model is binary attack/benign; stage is inferred
        # from the observed pattern via the technique rules' parent stage guess.
        stage = _infer_stage(feats, stage_rules)
        tech = EX.map_technique(stage, feats)
        top_windows = _top_contributing_windows(host_hist[host], ws, max_ctx)
        obj = {
            "host": host,
            "window_start": ws,
            "probability": float(probs[row]),
            "stage": stage,
            "technique": tech["technique"],
            "technique_name": tech["name"],
            "top_features": tops[local_i],
            "top_windows": top_windows,
            "flagged_flows": EX.flagged_flows(flows, host, ws, window_sec),
            "estimated_lead_seconds": None,
            # On every forecast, not just once per run: forecasts.json is an array
            # that gets read, copied and quoted from on its own.
            "demo_model": lane.demo,
        }
        _validate(obj)
        forecasts.append(obj)
        # `artifact_lane` rides inside the hashed content, so a demo record cannot
        # be edited into a published-looking one without breaking the chain. It is
        # written on BOTH lanes: a published record states its provenance rather
        # than implying it by the absence of a demo flag.
        ledger.append({"host": host, "window_start": ws, "probability": obj["probability"],
                       "stage": stage, "technique": tech["technique"],
                       "artifact_lane": lane.name})
    ledger.checkpoint()

    graph = _build_graph(flows, wf, forecasts)
    summary = {
        "n_flows": int(len(flows)),
        "n_host_windows": int(len(wf)),
        "n_alerts": int(len(alert_rows)),
        "threshold": threshold,
        "unparsed_frames": unparsed,
        "hosts_pseudonymised": _hosts_pseudonymised(
            [f["host"] for f in forecasts] + [n["ip"] for n in graph["nodes"]]
        ),
        "role_features_degraded": role_features_degraded(anonymizer),
        # WHICH WEIGHTS PRODUCED THESE NUMBERS, as data. Flat keys in the same
        # spirit as `unparsed_frames` and `role_features_degraded`: a downstream
        # consumer branches on the boolean without parsing any prose, and the
        # notice is there for whatever puts text in front of a human.
        "artifact_lane": lane.name,
        "demo_model": lane.demo,
        "demo_model_notice": lane.notice,
        "demo_model_source": lane.source,
        "forecasts_file": FORECASTS_FILE,
    }
    (out_dir / FORECASTS_FILE).write_text(json.dumps(forecasts, indent=2), encoding="utf-8")
    _write_run_summary(out_dir, summary)
    return {**summary, "forecasts": forecasts, "graph": graph}


def _write_run_summary(out_dir, summary: dict) -> Path:
    """Persist the run-level facts beside forecasts.json (RUN_SUMMARY_FILE).

    Written for every run, including one with zero alerts — that is the case it
    exists for: an IPv6-only capture and a genuinely quiet network both produce
    an empty forecasts.json, and only `unparsed_frames` tells them apart.
    """
    path = Path(out_dir) / RUN_SUMMARY_FILE
    path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return path


def _hosts_pseudonymised(hosts) -> bool:
    """Measured off every address this run emits — forecast hosts and graph nodes
    alike — never declared: True only when not one of them is a literal address,
    because one readable address is enough to make the claim false. Nothing
    emitted means nothing was pseudonymised (False); an empty run is not a
    privacy guarantee."""
    import ipaddress

    emitted = False
    for host in hosts:
        emitted = True
        try:
            ipaddress.ip_address(str(host))
        except ValueError:
            continue
        return False
    return emitted


def _build_graph(flows, wf, forecasts) -> dict:
    """Host communication graph for the 3D network view (M10.8).

    Nodes are hosts (real IPs / configured pseudonyms), edges are src->dst flow
    relationships aggregated by count. Each node carries its peak forecast
    probability and alert count (from the forecasts, keyed on the SOURCE host,
    which is what the model scores); each edge carries the risk of its source
    node so a risky edge can be highlighted. This is a summary of the same TGN
    host graph the encoder operates on — data, not a re-extraction."""
    peak: dict[str, float] = {}
    alerts: dict[str, int] = {}
    for f in forecasts:
        h = str(f["host"])
        peak[h] = max(peak.get(h, 0.0), float(f["probability"]))
        alerts[h] = alerts.get(h, 0) + 1

    internal = {}
    if wf is not None and len(wf) and "internal" in wf.columns:
        for h, v in zip(wf["host"].astype(str), wf["internal"]):
            internal.setdefault(h, int(v))

    edges = []
    ips = set(peak)
    if flows is not None and len(flows) and {"src_ip", "dst_ip"} <= set(flows.columns):
        agg = flows.groupby(["src_ip", "dst_ip"]).size().reset_index(name="weight")
        for r in agg.itertuples(index=False):
            s, d = str(r.src_ip), str(r.dst_ip)
            edges.append({"src": s, "dst": d, "weight": int(r.weight),
                          "risk": float(peak.get(s, 0.0))})
            ips.add(s)
            ips.add(d)

    nodes = [{"ip": ip, "peak_prob": float(peak.get(ip, 0.0)),
              "n_alerts": int(alerts.get(ip, 0)), "internal": internal.get(ip)}
             for ip in sorted(ips)]
    return {"nodes": nodes, "edges": edges}


def _top_contributing_windows(history, alert_ws: float, context_seconds: float, k: int = 3):
    """The k windows of this host, within `context_seconds` up to and including
    the alert window, whose own forecast probability was highest (M8.3).

    history: [(window_start, probability), ...] for one host. Returns
    [{window_start, probability, seconds_before_alert}] newest-first ties broken
    by recency — the windows an analyst should look at to see the attack forming.
    """
    ctx = [(s, p) for (s, p) in history if alert_ws - context_seconds <= s <= alert_ws]
    ctx.sort(key=lambda sp: (-sp[1], -sp[0]))
    return [
        {"window_start": s, "probability": p, "seconds_before_alert": round(alert_ws - s)}
        for s, p in ctx[:k]
    ]


def _infer_stage(feats: dict, rules: dict) -> str:
    """Coarse stage from the named-feature pattern within a 15 s WINDOW (the
    engine model is binary; stage granularity comes from interpretable rules).

    `rules` is configs/data.yaml `stage_rules`; the thresholds are windowed, not
    per-flow, and are unmeasured — stage accuracy is TBD. A window that matches
    nothing returns UNCLASSIFIED_STAGE: pacing an attack lowers every per-window
    count, and the honest answer there is "no rule fired", not a stage guess.
    That evasion is measured, not hypothetical — it is pinned by
    tests/test_engine.py::test_paced_randomised_scan_evades_the_stage_rules and
    noted above `stage_rules` in configs/data.yaml.
    """
    syn = feats.get("syn", 0)
    distinct_ports = feats.get("distinct_dst_ports", 0)
    distinct_ips = feats.get("distinct_dst_ips", 0)
    # bulk outbound to a single peer, few SYNs (an established transfer, not a scan)
    if (feats.get("sent_bytes", 0) > rules["exfiltration_sent_bytes_gt"]
            and distinct_ips <= rules["exfiltration_distinct_dst_ips_lte"]
            and syn < rules["exfiltration_syn_lt"]):
        return "exfiltration"
    # a sweep: many ports OR a strongly sequential scan signature
    if (distinct_ports > rules["scan_distinct_dst_ports_gt"]
            or feats.get("sequential_port_ratio", 0) > rules["scan_sequential_port_ratio_gt"]):
        # a scan sourced from an internal host toward another internal host reads
        # as lateral movement; from outside as reconnaissance
        return "lateral_movement" if feats.get("internal", 0) == 1 else "recon"
    if syn > rules["initial_access_syn_gt"] and feats.get("ack", 0) < syn:
        return "initial_access"
    if feats.get("sent_pkts", 0) > rules["impact_sent_pkts_gt"]:
        return "impact"
    return UNCLASSIFIED_STAGE


_VALIDATOR = None


def _validator():
    """One validator for OUTPUT_SCHEMA, built once per process.

    `jsonschema.validate(obj, schema)` re-validates the SCHEMA against its
    metaschema on every call, and every alert in a run is validated: measured
    here on a 977-alert demo run, that was 977 `check_schema` calls and the
    single largest cost in predict_file (~20s of a 41s profiled run). The schema
    is a module constant, so checking it once is the same guarantee — a malformed
    OUTPUT_SCHEMA still raises SchemaError on the first validated object, not
    silently.
    """
    global _VALIDATOR
    if _VALIDATOR is None:
        import jsonschema

        cls = jsonschema.validators.validator_for(OUTPUT_SCHEMA)
        cls.check_schema(OUTPUT_SCHEMA)
        _VALIDATOR = cls(OUTPUT_SCHEMA)
    return _VALIDATOR


def _validate(obj: dict) -> None:
    """Raise jsonschema.ValidationError unless `obj` satisfies OUTPUT_SCHEMA."""
    _validator().validate(obj)


def role_features_degraded(anonymizer) -> bool:
    """True when this run had no anonymisation key, so the role features are zeros.

    Not a style note. `data/windows.py:_ROLE_FEATURES` is ("internal", "net24_bucket"),
    both of which land in the deployed model's top-10 TreeSHAP attributions, and
    `_infer_stage`'s lateral_movement branch is reachable only when `internal == 1`.
    With no key both are 0 for every host, so the model scores a feature vector it
    was never trained on and lateral_movement becomes unreachable. The run still
    completes — that is deliberate, a judge without our key can still see the
    pipeline work — but it must never do so silently.
    """
    return anonymizer is None


def _maybe_anonymizer(cfg):
    from data.anonymize import Anonymizer

    try:
        return Anonymizer.from_config(cfg)
    except RuntimeError:
        # No HMAC key in the environment: role features fall back to 0 (the
        # engine still runs; identity is simply not derived). The LEDGER's
        # pseudonymisation uses its own key and is unaffected.
        return None
