"""K-step forward forecasting on the deployed engine (PS deliverable 3).

    from engine import forecast
    forecast.forecast_file("capture.csv", out_dir="run/")

WHAT THIS DOES. It runs engine.predict.predict_file unchanged — same feature
extraction, same nowcast alerts, same explanations, same ledger — and then
pushes the rows that run already scored through one persisted XGBoost head PER
HORIZON k. Each head was fitted by engine.train_engine on the target shifted
+k windows per host (the same shift eval/dataset.py applies, so the deployed
forecaster and the harness predict the same thing), and each is alerted against
ITS OWN FPR-budget threshold, loaded per horizon through engine/thresholds.py.
`seconds_ahead` is exactly `k * windows.stride_seconds`. Stage and MITRE
technique come from engine/explain.py + engine/technique_map.yaml — the same
call the nowcast makes, not a fork.

WHAT THIS DOES NOT ESTABLISH. Read this before quoting anything off this
module; the project has spent three rounds removing claims that outran the code.

  * THERE IS NO SUPPORTED FORWARD-FORECAST OPERATING POINT. At the shipped 1 %
    FPR budget the measured k-step head fires 0 of 2 attack episodes at k = 1,
    4 AND 8 alike, and the oracle-threshold analysis shows that no threshold
    recovers it — a ranking limit, not a calibration bug (docs/limitations.md;
    tier1_hardening_report.md Part 2). A per-horizon `alert` that stays False on
    real traffic is therefore the MEASURED behaviour of this capability, not a
    defect, and must never be "fixed" by loosening the budget.
  * The k-step ranking signal is real but modest — test AUROC 0.844 at k=4 and
    0.842 at k=8 — and it is flattered by its own target: the k-step label is
    93-96 % identical to the nowcast label, so ranking the future well is close
    to ranking the present well.
  * Those AUROC figures were measured on the EVAL-side k-step head (a linear
    head over frozen TGN embeddings, eval/forecast.py). They are NOT this
    module's numbers. What these XGBoost heads have earned is the per-horizon
    validation AUROC engine.train_engine persists beside each one; their
    test-set forecast quality is UNMEASURED until the harness is re-run on a
    machine that has the dataset.
  * The lead time this project actually claims comes from the HORIZON-0
    classifier — detecting an attack already in progress, early in its episode
    — not from forecasting ahead.
  * `stage` and `technique` describe the SOURCE window's observed pattern: the
    evidence behind the forecast. They are not a predicted future stage. The
    engine has no future features to infer one from, and inventing a future
    stage from a binary probability would be exactly the kind of confident
    fiction the stage rules already refuse (see predict.UNCLASSIFIED_STAGE).

FORWARD_FORECAST_CAVEAT carries the first, third and fifth of those points in
one string so a UI can put them in front of the viewer rather than in a
footnote; it travels in the returned dict and in the persisted file.

A horizon with no usable head is REPORTED, never skipped: `unavailable_horizons`
maps k to a plain-English reason. Silence must not be readable as safety.

No k-step record is written to the tamper-evident ledger. The M9.3 binding
engine/predict.py performs covers exactly two files — the horizon-0 weights it is
about to load and the scaler — in BOTH lanes, and no per-horizon head is among
them, so a k-step ledger entry could not carry the provenance a ledger entry is
supposed to prove. The nowcast alerts predict_file writes are ledgered exactly as
before.

Being precise about what that does and does not say, because the two are easy to
run together: `scripts/verify_weights.tracked_names` names the horizon-0 weights
only, in both lanes, and that is the list `--record` writes from. A demo lane
built by scripts/bootstrap_demo_artifacts.py nevertheless has its per-horizon
heads IN its `weights.sha256` — that script writes its own digest record, hashing
every weight it fitted (measured this session on a real bootstrap: nine files
recorded, six of them k-step heads). So on a demo lane `verify_weights.py` does
check the k-step heads, while the engine's own per-run binding still does not.
That is strictly more attestation than the published lane has, never less, and
neither lane's k-step head is verified at the moment this module loads it.

DEMO LANE. This module never resolves a lane of its own: it takes the one the
nowcast resolved out of the scoring context and loads every k-step head through
that lane's config, so a published nowcast can never be paired with a demo
forward curve. When that lane is the demo one, the returned block and
kstep_forecast.json carry `demo_model: true`, `artifact_lane: "demo"` and
`demo_model_notice`; each forecast entry carries `demo_model: true`; and
`forecast_caveat` leads with the demo notice rather than with the measured
forward-forecast caveat. A curve drawn from a model that memorised one 455-second
capture is the single most misleading artifact this feature can produce — it is
shaped like a forecast and plotted like one — so it is labelled at the block, at
the entry and in the caption a UI shows.
"""

from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import pandas as pd

from configs import load_config

# The k-step block of a run, persisted beside predict.py's forecasts.json /
# run_summary.json so a SAVED run carries the forward curve and — just as
# important — the horizons it could not produce. Named for the k-step head to
# keep it distinct from eval/forecast.py's results/forecast.json, which is the
# research harness's output and a different thing entirely.
FORECAST_FILE = "kstep_forecast.json"

# Shown wherever the forward curve is shown. Every sentence is a measured
# finding of this project's own audit, not a hedge.
FORWARD_FORECAST_CAVEAT = (
    "Forward forecast: RANKING SIGNAL ONLY - not a validated early-warning "
    "operating point. At the shipped 1% FPR budget the measured k-step head "
    "fires 0 of 2 attack episodes at k=1, 4 and 8 alike, and no threshold "
    "recovers it (a ranking limit, not a calibration bug). The lead time this "
    "system claims comes from the horizon-0 classifier, not from forecasting "
    "ahead. Stage and technique describe the evidence in the source window, "
    "not a predicted future stage."
)

_INPUT_KIND = {"full": "PCAP", "flow": "CSV/flow"}


def forecast_caveat(lane) -> str:
    """The caveat that travels with THIS run's curve.

    On the published lane it is FORWARD_FORECAST_CAVEAT, unchanged. On the demo
    lane the demo notice goes FIRST, because a k-step curve drawn from a model
    that memorised one small capture is the most misleading artifact this feature
    can produce: it looks exactly like a forecast, it is plotted exactly like a
    forecast, and its shape is a property of the capture the model was fitted on.
    The UI reads this string (app/panels.py), so prefixing it here is what puts
    the demo warning under the plot rather than in a docstring.
    """
    if lane is not None and getattr(lane, "demo", False):
        return f"{lane.notice}\n\n{FORWARD_FORECAST_CAVEAT}"
    return FORWARD_FORECAST_CAVEAT


def forecast_file(input_path, out_dir, fpr_budget: float = 0.01) -> dict:
    """Nowcast + K-step forward forecast for one file.

    Returns everything engine.predict.predict_file returns, plus `horizons`,
    `stride_seconds`, `unavailable_horizons`, `forecast`, `per_host_curve`,
    `forecast_caveat`, `artifact_lane`, `demo_model`, `demo_model_notice` and
    `forecast_file`. Also writes that k-step block to out_dir/kstep_forecast.json.

    `forecast` holds one entry per (host, source window, k). Source windows are
    the newest `engine.forecast_source_windows_per_host` windows of each host —
    a forecast made from a window in the middle of a long capture is a forecast
    about traffic the capture already contains, which is useful for inspection
    but is not what an operator acts on; `per_host_curve` therefore carries only
    the newest source window per host.

    Raises whatever predict_file raises (missing artifacts, weight-digest
    mismatch): a forecast on top of a nowcast that could not run is not a
    degraded forecast, it is no forecast.
    """
    from engine import explain as EX
    from engine import predict as P

    cfg = load_config("data")
    out_dir = Path(out_dir)
    stride = float(cfg["windows"]["stride_seconds"])
    horizons_wanted = [int(k) for k in cfg["engine"]["forecast_horizons"]]
    n_source = int(cfg["engine"]["forecast_source_windows_per_host"])
    if n_source < 1:
        raise ValueError(
            "configs/data.yaml engine.forecast_source_windows_per_host must be >= 1, "
            f"got {n_source} — a cap below 1 leaves every host with no source "
            "window, which is a forecast about nothing"
        )

    context: dict = {}
    base = P.predict_file(input_path, out_dir, fpr_budget=fpr_budget,
                          scoring_context=context)
    missing = [k for k in P.SCORING_CONTEXT_KEYS if k not in context]
    if missing:
        raise RuntimeError(
            f"engine.predict.predict_file did not fill the scoring context keys {missing}; "
            "engine/forecast.py cannot score the same rows the nowcast scored"
        )

    wf, X = context["wf"], context["X"]
    feat_cols = context["feature_columns"]
    variant = context["variant"]
    # The lane the NOWCAST resolved, reused verbatim. The k-step heads are loaded
    # through `lane.cfg`, so they come from the same artifact directory that
    # produced the nowcast — a run cannot pair a published nowcast with a demo
    # k=8 head, in either direction.
    lane = context["lane"]

    heads, unavailable = _load_horizon_heads(lane.cfg, variant, horizons_wanted,
                                             fpr_budget, lane=lane)
    # With no head at any horizon there is nothing to forecast FROM either; the
    # run still returns (and persists) `unavailable_horizons`, which is the
    # answer in that case.
    rows = _source_rows(wf, n_source) if heads else np.empty(0, dtype=int)
    X_src = X[rows] if len(rows) else np.empty((0, len(feat_cols)), dtype=np.float32)

    # One forward pass per horizon over the source rows, so a head is only ever
    # applied to the matrix the nowcast built from this same input.
    scored = {k: _score(head, X_src) for k, (head, _thr) in heads.items()}

    stage_rules = cfg["stage_rules"]
    forecast: list[dict] = []
    for j, row in enumerate(rows):
        source = wf.iloc[row]
        host = str(source["host"])
        window_start = float(source["window_start"])
        feats = {c: float(source[c]) for c in feat_cols}
        # The SOURCE window's stage/technique, through the nowcast's own path.
        stage = P._infer_stage(feats, stage_rules)
        technique = EX.map_technique(stage, feats)["technique"]
        for k in sorted(heads):
            probability = float(scored[k][j])
            threshold = heads[k][1]
            entry = {
                "host": host,
                "window_start": window_start,
                "k": int(k),
                "seconds_ahead": float(k) * stride,
                "probability": probability,
                "stage": stage,
                "technique": technique,
                "alert": bool(probability >= threshold),
                "threshold": threshold,
            }
            if lane.demo:
                # Only on the demo lane. The published entry key set is the
                # contract tests/test_forecast_engine.py pins exactly, and a
                # published run keeps it; a demo entry carries one key more so a
                # single entry lifted out of kstep_forecast.json still says what
                # produced it. `entry.get("demo_model")` is falsey either way.
                entry["demo_model"] = True
            forecast.append(entry)

    block = {
        "horizons": sorted(heads),
        "stride_seconds": stride,
        "unavailable_horizons": unavailable,
        "forecast": forecast,
        "per_host_curve": _per_host_curve(forecast),
        "forecast_caveat": forecast_caveat(lane),
        # The same three flat keys engine/predict.py puts in run_summary.json, so
        # the k-step block persisted on its own still says which weights drew the
        # curve without anyone parsing the caveat prose.
        "artifact_lane": lane.name,
        "demo_model": lane.demo,
        "demo_model_notice": lane.notice,
        "forecast_file": FORECAST_FILE,
    }
    _write_forecast(out_dir, block)
    return {**base, **block}


def _score(head, X_src: np.ndarray) -> np.ndarray:
    """P(attack at t+k) for each source row. An empty matrix scores empty rather
    than being handed to a booster that would raise on zero rows."""
    if not len(X_src):
        return np.empty(0, dtype=float)
    return np.asarray(head.predict_proba(X_src))[:, 1].astype(float)


def _load_horizon_heads(cfg: dict, variant: str, horizons: list[int],
                        fpr_budget: float, lane=None) -> tuple[dict, dict]:
    """({k: (head, threshold)}, {k: plain-English reason it is unavailable}).

    Each of the three ways a horizon can be unusable — never fitted, fitted but
    its weight file is gone, fitted but never thresholded at this FPR budget —
    gets its OWN message, because the fix differs and "k=8 unavailable" alone
    sends an operator to the wrong one. A horizon is never dropped silently:
    every k the config asks for ends up in exactly one of the two dicts.

    `cfg` must already be the LANE's config: every head, threshold and weight file
    is read from whatever artifacts directory it points at. `lane` is passed only
    so the unavailability messages can name the right remedy — on the demo lane
    "run engine.train_engine" is the wrong advice, and a horizon the small bundled
    capture cannot fit is expected rather than broken. The published wording is
    byte-identical to what it has always been.
    """
    from engine import predict as P
    from engine import thresholds as TH

    heads: dict[int, tuple[object, float]] = {}
    unavailable: dict[int, str] = {}
    kind = _INPUT_KIND.get(variant, variant)
    demo_tail = ""
    if lane is not None and getattr(lane, "demo", False):
        demo_tail = (
            f" [DEMO LANE {lane.dir}: these are not the published heads. A horizon "
            "the bundled synthetic capture leaves single-class is not fitted at all "
            "— re-run `python scripts/bootstrap_demo_artifacts.py`, which records "
            "why under `demo_provenance.heads_not_fitted`.]"
        )
    for k in horizons:
        key = TH.horizon_variant(variant, k)
        try:
            TH.load_model_spec(cfg, key)
        except KeyError:
            unavailable[k] = (
                f"no k={k} forecast head has been fitted for {kind} input: the persisted "
                f"thresholds carry no '{key}' entry. Run `python -m engine.train_engine` "
                "to fit and persist the per-horizon heads (artifacts built before the "
                "k-step heads existed have only the horizon-0 models)." + demo_tail
            )
            continue
        try:
            threshold = float(TH.load_threshold(cfg, fpr_budget, variant=key))
        except KeyError:
            unavailable[k] = (
                f"the k={k} forecast head for {kind} input is persisted but carries no "
                f"threshold for a {fpr_budget:g} FPR budget, and this run must not borrow "
                "another horizon's cut. Add that budget to configs/eval.yaml "
                "`fpr_budgets` and re-run `python -m engine.train_engine`." + demo_tail
            )
            continue
        try:
            head, _scaler, _fname = P._load_engine(cfg, key)
        except FileNotFoundError as exc:
            unavailable[k] = (
                f"the k={k} forecast head for {kind} input is recorded in the persisted "
                f"thresholds but its weight file is not in artifacts/ ({exc}). Re-run "
                "`python -m engine.train_engine`, or re-fetch the artifacts bundle."
                + demo_tail
            )
            continue
        heads[k] = (head, threshold)
    return heads, unavailable


def _source_rows(wf: pd.DataFrame, n_per_host: int) -> np.ndarray:
    """Positions in `wf` of the newest `n_per_host` windows of each host.

    Returned host-major then time-ascending, so the caller's output is stable
    across runs of the same input (determinism is a shipped claim, M0).
    """
    if wf is None or not len(wf):
        return np.empty(0, dtype=int)
    ordered = pd.DataFrame({
        "_row": np.arange(len(wf), dtype=int),
        "host": wf["host"].astype(str).to_numpy(),
        "window_start": wf["window_start"].to_numpy(dtype=float),
    }).sort_values(["host", "window_start"], kind="stable")
    newest = ordered.groupby("host", sort=True).tail(n_per_host)
    return newest.sort_values(["host", "window_start"], kind="stable")["_row"].to_numpy()


def _per_host_curve(forecast: list[dict]) -> dict[str, list[dict]]:
    """The UI risk curve: per host, the NEWEST source window's k-step points,
    ascending in k. Built from the same `forecast` entries the caller gets, so
    the curve can never disagree with the table it is drawn from."""
    newest: dict[str, float] = {}
    for entry in forecast:
        host, ws = entry["host"], entry["window_start"]
        if ws > newest.get(host, float("-inf")):
            newest[host] = ws
    curve: dict[str, list[dict]] = {}
    for entry in forecast:
        if entry["window_start"] != newest[entry["host"]]:
            continue
        curve.setdefault(entry["host"], []).append({
            "k": entry["k"], "seconds_ahead": entry["seconds_ahead"],
            "probability": entry["probability"], "alert": entry["alert"],
        })
    for points in curve.values():
        points.sort(key=lambda p: p["k"])
    return curve


def _write_forecast(out_dir, block: dict) -> Path:
    """Persist the k-step block (FORECAST_FILE), including on a run that
    produced no forecast at all — an empty `forecast` with a populated
    `unavailable_horizons` is the whole point: a saved run must say whether it
    had nothing to forecast or nothing to forecast WITH.

    JSON has no integer keys, so `unavailable_horizons` is written with string
    keys; the returned dict keeps them as ints.
    """
    path = Path(out_dir) / FORECAST_FILE
    path.parent.mkdir(parents=True, exist_ok=True)
    on_disk = {**block,
               "unavailable_horizons": {str(k): v
                                        for k, v in block["unavailable_horizons"].items()}}
    path.write_text(json.dumps(on_disk, indent=2), encoding="utf-8")
    return path
