"""Fit the DEMO-LANE engine artifacts from the bundled synthetic capture.

    python scripts/bootstrap_demo_artifacts.py

WHY THIS EXISTS
A fresh clone has no `artifacts/`: CLAUDE.md forbids committing weights and the
release bundle is not published, so `engine/predict.py` raises on the missing
threshold file and the app cannot run. The dataset that trained the published
model is ~12.7 GiB and is not in the repository either. What IS in the
repository is `app/assets/synthetic_demo.pcap` — a small, deterministic,
hand-authored capture. This script fits a model from THAT, into a lane of its
own, so the pipeline can be executed end to end by someone who has only the
clone.

WHAT THE MODEL IT PRODUCES IS
A toy. Measured this session: 5,620 packets spanning 454 seconds, which the
15 s / 5 s window grid turns into 174 host-windows across five hosts, 54 of them
labelled attack. The operating thresholds are chosen on the same rows the model
was fitted on. It has memorised that capture — every head's in-sample AUROC is
1.000. When the demo scores that same capture back, a high probability means "I
have seen this row before", not "I have detected an attack".

WHAT IT IS NOT
It is not the published model, it did not see CSE-CIC-IDS-2018, and no number
it produces is comparable to any number in the README, the report or the deck.
Running it reproduces nothing. It is also not a way to turn the repository's
skipped end-to-end tests green: the demo weight files are deliberately named so
that `tests/_stubs.engine_artifacts_present()` — the gate those tests use — is
still False when this lane is fully built, and
`tests/test_demo_bootstrap.py::test_the_demo_lane_does_not_satisfy_the_real_artifact_gate`
pins that.

AND IT DOES NOT FILL THE THREE EMPTY KILL-CHAIN STAGES. The bundled operator log
declares recon, initial_access, lateral_movement and exfiltration, and this lane
really does fit labelled windows for all four. Three of those — recon,
lateral_movement, exfiltration — are precisely the stages that have ZERO
labelled windows in the real dataset this project reports on. Hand-authoring
them into a 454-second synthetic capture does not supply the missing data; it
supplies four illustrations that were written to be found. Any per-stage
statement about those three has to keep saying "no training data", exactly as
CLAUDE.md and docs/limitations.md already do.

WHAT THE OPERATING POINTS ARE WORTH
A head with N benign rows can only achieve an FPR of 0, 1/N, 2/N ..., so a
budget finer than 1/N is not a second operating point — it collapses onto the
next expressible cut. Measured this session, per head:

    full / flow        120 benign rows, finest 0.83%  -> 0.1% collapses
    full_k1 / flow_k1  114 benign rows, finest 0.88%  -> 0.1% collapses
    full_k4 / flow_k4   96 benign rows, finest 1.04%  -> 0.1% AND 1% collapse
    full_k8 / flow_k8   72 benign rows, finest 1.39%  -> 0.1% AND 1% collapse

So on the k=4 and k=8 heads even the SHIPPED 1% budget is below what this
capture can express. Moving the FPR budget in the app does not move these
models. `operating_points` records, per head and per budget, the threshold, the
FPR it actually achieves, and whether the budget was expressible at all — rather
than persisting two numbers that look like two operating points.

HOW IT STAYS HONEST IN CODE, not just in prose
- A separate directory (`configs/data.yaml` `demo.artifacts_dir`), never the
  published one. `refuse_to_clobber_published_artifacts` stops the run if the
  target is the published directory or already holds published weights.
- Its own `weights.sha256`, recorded with `scripts/verify_weights.py`'s own
  hasher, so `engine/predict.py`'s weight attestation still runs and still
  refuses a tampered demo model.
- An `artifact_lane: "demo"` marker in the persisted thresholds.
  `engine/thresholds.py` refuses to serve a demo-lane spec from any directory
  other than the configured demo directory, so copying this lane into
  `artifacts/` fails loudly instead of quietly becoming "the model".
- A `WHAT_THIS_IS.txt` beside the weights, for whoever opens the folder.

The features are the REAL ones: the capture goes through
`data/packet_features.py` and `data/windows.py`, the same path
`engine/predict.py` scores. A demo model fitted on a parallel feature path
would prove nothing about the pipeline.

DETERMINISM, AND WHAT IT ACTUALLY DEPENDS ON
Re-running this script on the same capture writes byte-identical weight files.
Seeding is necessary but is NOT what makes that true: `models/baselines.py`
builds the XGBoost head with `n_jobs=-1`, and XGBoost's parallel histogram
build is thread-count dependent. Measured in this session, on the real demo
matrix (174 host-windows x 30 features), same seed, only OMP_NUM_THREADS
differing:

    fit_threads=1  demo_engine_model.json  d428729d3562...
    fit_threads=4  demo_engine_model.json  1003f2454f32...

— all eight heads differed; `window_scaler.pkl` (sklearn, single-threaded) did
not. So the thread count is pinned from `configs/data.yaml` `demo.fit_threads`.
`tests/test_demo_bootstrap.py::test_the_pinned_thread_count_is_why_the_bytes_are_stable`
re-measures both halves of that on every run rather than trusting these two
digests, which is the only reason they are safe to quote here.

The pin is a process-global environment variable, so `bootstrap` PUTS IT BACK
when it returns. A script run does not care, but an in-process caller — the
test suite — would otherwise leave OMP_NUM_THREADS=1 exported for every later
test and every subprocess they spawn.

THE PIN ONLY WORKS IN A PROCESS THAT HAS NOT YET IMPORTED XGBOOST, and that is
not a theoretical caveat — it is a defect this script used to have. OpenMP reads
OMP_NUM_THREADS when its runtime initialises, which happens on XGBoost's FIRST
IMPORT. Measured in this session: a process that does `import xgboost` before
calling `bootstrap()` produces the SAME weights at `fit_threads=1` and at
`fit_threads=4` (both `bc7fdd07d9dc...`, i.e. this machine's 12-core default),
and neither matches the pinned run. A bare import with no fit is enough. The
earlier version wrote `fit_threads: 1` into the lane's provenance in exactly
that case, so the record claimed a thread count the fit had not used. That is
why `pin_fit_threads` now REPORTS whether it took effect, `bootstrap` refuses by
default when it did not, and the provenance carries
`fit_threads_pin_effective` / `weights_reproducible` rather than a bare number.

Two other inputs change the bytes and are recorded for the same reason: the
capture's own digest, and whether an HMAC key was present (without one the
engine zeroes the two role features, so the model is fitted on different
columns).
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import sys
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))  # for `verify_weights`

from configs import load_config, resolve_path, set_seed  # noqa: E402
from engine import thresholds as TH  # noqa: E402

import verify_weights as VW  # noqa: E402  (same directory as this file)

# The plain-text warning dropped beside the weights, for a reader who opens the
# directory without having read this module. Kept here rather than in config:
# it is prose, not a tunable.
WHAT_THIS_IS_FILENAME = "WHAT_THIS_IS.txt"

WHAT_THIS_IS = """\
THESE ARE DEMO WEIGHTS. THEY ARE NOT THE PUBLISHED MODEL.

Every file in this directory was fitted by
scripts/bootstrap_demo_artifacts.py from ONE small synthetic capture that ships
in this repository: app/assets/synthetic_demo.pcap. That capture is
hand-authored illustrative traffic. It is not a network, not a dataset and not
evaluation data.

The model was fitted on that capture and its alert thresholds were chosen on
the same rows. It has memorised the capture. If you run the demo on that
capture and see a high probability, the model is recognising something it was
trained on. That is not a detection result and it is not a measurement.

THE STAGE LABELS HERE DO NOT FILL THE PROJECT'S THREE EMPTY STAGES. This lane
has labelled windows for recon, lateral_movement and exfiltration because they
were hand-written into the capture to be found. Those three stages have NO
labelled data in the dataset this project reports on, and that is still true
after you build this lane.

THE ALERT THRESHOLDS ARE COARSER THAN THE FPR BUDGETS THEY ARE NAMED AFTER.
There are only ~120 benign host-windows here, and fewer on the forward-forecast
heads, so no false-positive rate finer than about 0.8% can be expressed at all -
and on the k=4 and k=8 heads not even 1%. Budgets below that resolve to the same
cut as the next one up. Changing the FPR budget in the app will not move this
model. The `operating_points` block in engine_threshold.json has the per-head
numbers.

The published numbers in this project were measured on CSE-CIC-IDS-2018 with a
different model, on data that is not in this repository. Nothing produced here
reproduces, confirms or approximates any of them.

Do not copy these files into artifacts/. The engine refuses to load this lane
from anywhere but its own directory, and will say so.
"""

# Names that belong to the PUBLISHED lane. Taken from scripts/verify_weights.py
# rather than retyped, so a new published weight added there is automatically a
# sentinel here. `window_scaler.pkl` is excluded because engine/predict.py loads
# the scaler by that exact name from whichever artifacts directory it is
# pointed at, so the demo lane must also write one — it cannot double as proof
# that published artifacts are present.
PUBLISHED_ONLY_WEIGHTS = tuple(n for n in VW.TRACKED if n != "window_scaler.pkl")

# Threshold-file keys that carry the demo lane's provenance. `load_model_spec`
# only reads mappings that carry a "file" key, so this block is inert to the
# engine and visible to a human.
PROVENANCE_KEY = "demo_provenance"


# ---------------------------------------------------------------------------
# Safety: never write over the published artifacts.
# ---------------------------------------------------------------------------


class PublishedArtifactsPresent(RuntimeError):
    """The demo bootstrap was aimed at a directory it must not write into."""


class CaptureNotFullyParsed(RuntimeError):
    """The bundled capture lost frames on the way into the feature matrix.

    `engine.predict._coverage` counts what the IPv4 packet parser could not read.
    On a dataset capture that is a fact of life; on THIS capture it is a
    regression, because the capture is hand-authored, committed, and its SHA-256
    is recorded in every lane this script writes. A dropped frame means the demo
    model was fitted on less traffic than the operator log describes, and the
    checks that would otherwise notice — the single-class refusal, and
    `test_labels_come_from_the_operator_log_and_cover_the_kill_chain` — only fire
    when a stage disappears COMPLETELY. Partial loss is exactly the silent case,
    so it is an error.
    """


class ThreadPinIneffective(RuntimeError):
    """`demo.fit_threads` could not be applied, so the weights are not reproducible.

    Raised when XGBoost was already imported in this process (see
    `pin_fit_threads`). Its own class because the caller's options are specific:
    run the script in a fresh interpreter, or — only for a lane whose bytes do
    not matter, i.e. a test — pass `allow_unpinned_threads=True` and accept a
    lane whose provenance says `weights_reproducible: false`.
    """


def demo_artifacts_dir(cfg: dict) -> Path:
    """The demo lane's directory, from configs/data.yaml `demo.artifacts_dir`."""
    demo = cfg.get("demo")
    if not isinstance(demo, dict) or not demo.get("artifacts_dir"):
        raise KeyError(
            "configs/data.yaml has no `demo.artifacts_dir` — the demo lane has no "
            "directory to write into, and this script must never fall back to "
            "`paths.artifacts_dir` (that is the published lane)"
        )
    return resolve_path(demo["artifacts_dir"])


def refuse_to_clobber_published_artifacts(cfg: dict, target: Path) -> None:
    """Raise unless `target` is a safe place to write demo weights.

    Three ways it is not safe, each with its own message because the fix
    differs:

    1. it IS the published artifacts directory;
    2. it holds a published weight file (`PUBLISHED_ONLY_WEIGHTS`);
    3. it holds a persisted threshold file that is not marked as the demo lane —
       i.e. published thresholds, wherever they happen to live.

    This is the safety property of the whole script. Nothing here is best
    effort: the run stops before a single byte is written.
    """
    target = Path(target).resolve()
    published_dir = resolve_path(cfg["paths"]["artifacts_dir"])
    if target == published_dir:
        raise PublishedArtifactsPresent(
            f"refusing to write demo weights into {target} — that is the PUBLISHED "
            "artifacts directory (configs/data.yaml `paths.artifacts_dir`). The demo "
            "lane writes to `demo.artifacts_dir` and nowhere else."
        )

    present = [n for n in PUBLISHED_ONLY_WEIGHTS if (target / n).exists()]
    if present:
        raise PublishedArtifactsPresent(
            f"refusing to write demo weights into {target} — it already holds "
            f"published model weights: {', '.join(sorted(present))}. Demo weights "
            "must never sit next to, or on top of, the real ones. Move or remove "
            "them first if this directory really is meant to be the demo lane."
        )

    threshold_file = TH.threshold_path({"paths": {"artifacts_dir": str(target)}})
    if threshold_file.exists():
        try:
            lane = str(json.loads(threshold_file.read_text(encoding="utf-8"))
                       .get(TH.LANE_FIELD, TH.PUBLISHED_LANE))
        except (ValueError, OSError) as exc:
            raise PublishedArtifactsPresent(
                f"refusing to write demo weights into {target} — {threshold_file.name} "
                f"is there but could not be read ({exc}), so this script cannot tell "
                "whether it is about to overwrite published thresholds."
            ) from exc
        if lane != TH.DEMO_LANE:
            raise PublishedArtifactsPresent(
                f"refusing to write demo weights into {target} — {threshold_file.name} "
                f"is there and is marked lane '{lane}', not '{TH.DEMO_LANE}'. Those are "
                "published thresholds; overwriting them would destroy the record of "
                "the published operating points."
            )


# ---------------------------------------------------------------------------
# The bundled capture -> the real 30-feature window matrix.
# ---------------------------------------------------------------------------


def demo_capture_paths(cfg: dict) -> tuple[Path, Path]:
    """(pcap, operator log) from configs/data.yaml `demo`."""
    demo = cfg["demo"]
    pcap = resolve_path(demo["pcap"])
    log = resolve_path(demo["operator_log"])
    for path, what in ((pcap, "capture"), (log, "operator log")):
        if not path.exists():
            raise FileNotFoundError(
                f"bundled demo {what} missing: {path} — regenerate both with "
                "`python -m capture.make_synthetic_demo`"
            )
    return pcap, log


def window_features_from_demo_capture(cfg: dict, pcap: Path, anonymizer):
    """The SAME extraction engine/predict.py runs on a PCAP, reused verbatim.

    `engine.predict._windows_from_input` is the one function that knows how a
    capture becomes the 30-feature matrix the engine scores; calling anything
    else here would fit the demo model on features the engine never sees.
    Returns its (flows, window_features, coverage) triple.
    """
    from engine import predict as P

    return P._windows_from_input(cfg, str(pcap), anonymizer)


def refuse_a_partially_parsed_capture(coverage: dict, pcap: Path) -> None:
    """Raise if the extractor dropped frames from the bundled capture.

    See `CaptureNotFullyParsed`. `coverage` is `engine.predict._coverage`'s dict:
    `fraction` is None when the drop counts are unknown (pandas strips the
    `.attrs` they ride on as soon as a frame is combined with one that has none),
    and unknown is NOT treated as an error — it is a property of the extractor's
    plumbing rather than of the capture, and refusing on it would stop the
    bootstrap for a reason the reader could do nothing about. It is recorded in
    the lane's provenance and printed in the report instead, so "unknown" is
    never silently read as "clean".

    MEASURED this session on the bundled capture: `{"known": true, "total": 0,
    "fraction": 0.0}` — nothing is dropped today, which is what makes a non-zero
    count a signal rather than noise.
    """
    if not isinstance(coverage, dict) or not coverage.get("fraction"):
        return
    raise CaptureNotFullyParsed(
        f"{pcap.name}: the packet extractor could not read "
        f"{coverage.get('total')} frames ({coverage['fraction']:.3%} of the capture; "
        f"by reason: {coverage.get('by_reason')}). This capture is hand-authored and "
        "committed, and its SHA-256 is recorded in every lane built from it, so it "
        "parses completely or something has changed. Fitting the demo model on the "
        "remainder would train it on less traffic than "
        "app/assets/synthetic_demo.operator-log.txt describes, and nothing downstream "
        "would say so. Regenerate both with `python -m capture.make_synthetic_demo`, "
        "or fix the extractor."
    )


# ---------------------------------------------------------------------------
# Operator log -> per-window stage labels.
# ---------------------------------------------------------------------------


def parse_operator_log(path: Path) -> list[dict]:
    """The ground-truth stage spans in app/assets/synthetic_demo.operator-log.txt.

    Format (written by capture/make_synthetic_demo.py): tab-separated
    `stage <TAB> start <TAB> end <TAB> attacker_ip <TAB> victim_ip`, times as
    HH:MM:SS wall-clock UTC, after two `key <TAB> value` header lines and a
    `# columns:` comment. Rows are returned verbatim as
    {stage, start_hms, end_hms, hosts}; no time resolution happens here because
    the log carries no date.

    STRICT ON PURPOSE. Exactly two line shapes are accepted: a two-field
    `key <TAB> value` header, and a five-field stage row. Anything else raises.
    The earlier version skipped every line with fewer than five fields, which
    made a malformed stage row indistinguishable from a header — the stage
    vanished from the labels, and the only check that would have caught it
    (`test_labels_come_from_the_operator_log_and_cover_the_kill_chain`) derives
    the list of expected stages from THIS function, so the row disappeared from
    both sides of that comparison and the test stayed green on a demo model that
    had never seen, say, exfiltration. A silently dropped line here is a missing
    kill-chain stage, so it is an error.
    """
    rows: list[dict] = []
    for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        parts = line.split("\t")
        if len(parts) == 2:
            continue  # `key <TAB> value` header (session_id, iface)
        if len(parts) != 5:
            raise ValueError(
                f"{path}:{lineno}: {line!r} has {len(parts)} tab-separated fields. An "
                "operator-log line must be either a 2-field `key<TAB>value` header or "
                "a 5-field stage row (stage, start, end, attacker_ip, victim_ip). "
                "Skipping it would delete a kill-chain stage from the demo model's "
                "labels without anything failing. Regenerate with "
                "`python -m capture.make_synthetic_demo`.")
        stage, start, end, attacker, victim = (p.strip() for p in parts)
        if not stage:
            raise ValueError(f"{path}:{lineno}: stage row has an empty stage name")
        if not start or not end:
            raise ValueError(
                f"{path}:{lineno}: stage row '{stage}' has no start/end time")
        rows.append({
            "stage": stage,
            "start_hms": start,
            "end_hms": end,
            "hosts": {h for h in (attacker, victim) if h},
        })
    if not rows:
        raise ValueError(f"{path}: no stage rows — regenerate with "
                         "`python -m capture.make_synthetic_demo`")
    return rows


def stage_intervals(cfg: dict, rows: list[dict], capture_start: float,
                    capture_end: float) -> list[dict]:
    """Operator-log rows -> UTC-epoch intervals, in `timeline_labels`' shape.

    Same keys `data/timeline_labels.attack_intervals` produces
    ({stage, start, end, hosts}) so the labelling rule below is the same rule,
    reading the same shape.

    The log has no date, so each HH:MM:SS is resolved against the UTC date of
    the capture's FIRST packet — the capture is the authority on when it
    happened, and nothing is hardcoded from
    `capture/make_synthetic_demo.py`'s epoch base. `benign` rows are dropped:
    benign is the default label, not an interval.

    An interval that lands wholly outside the capture is a loud failure. It is
    the shape a date/timezone mistake takes, and silently labelling nothing
    would produce a single-class fit that still looks like a model.
    """
    day = datetime.datetime.fromtimestamp(
        capture_start, datetime.timezone.utc).date()
    known = set(cfg["stages"])
    out = []
    for row in rows:
        if row["stage"] == "benign":
            continue
        if row["stage"] not in known:
            raise ValueError(
                f"operator log names stage '{row['stage']}', which is not one of "
                f"configs/data.yaml `stages` {sorted(known)}")
        start, end = (_epoch_utc(day, row[k]) for k in ("start_hms", "end_hms"))
        if end <= start:
            raise ValueError(
                f"operator-log stage '{row['stage']}' ends at or before it starts "
                f"({row['start_hms']} -> {row['end_hms']})")
        if end <= capture_start or start >= capture_end:
            raise ValueError(
                f"operator-log stage '{row['stage']}' spans {row['start_hms']}-"
                f"{row['end_hms']} UTC on {day}, which lies entirely outside the "
                f"capture's own time range. The log and the capture disagree about "
                "when this happened; labelling would produce no attack windows. "
                "Regenerate both with `python -m capture.make_synthetic_demo`.")
        if not row["hosts"]:
            raise ValueError(
                f"operator-log stage '{row['stage']}' names no attacker or victim "
                "host, so no window can be attributed to it")
        out.append({"stage": row["stage"], "start": start, "end": end,
                    "hosts": set(row["hosts"])})
    if not out:
        raise ValueError("the operator log carries no attack stages — a demo model "
                         "cannot be fitted from benign-only labels")
    return out


def _epoch_utc(day: datetime.date, hms: str) -> float:
    hh, mm, ss = (int(x) for x in hms.split(":"))
    return datetime.datetime(day.year, day.month, day.day, hh, mm, ss,
                             tzinfo=datetime.timezone.utc).timestamp()


def label_windows(cfg: dict, wf: pd.DataFrame, intervals: list[dict]) -> pd.Series:
    """Per-window stage labels, by `data/timeline_labels.label_windows`' rule.

    That rule, unchanged: a (host, window) row is labelled with a stage when the
    window OVERLAPS the stage interval AND the row's host is a party to it; the
    row existing at all is the proof the host transmitted. Where two stages
    cover one window the later one in `configs/data.yaml` `stages` order wins.
    Everything else is benign.

    WHY THIS IS NOT A CALL TO `timeline_labels.label_windows`. That function
    reaches the rule only through `attack_intervals` ->
    `_local_to_epoch_utc(date, "HH:MM", offset)`, which parses two fields and
    raises on a third. The operator log writes HH:MM:SS, and those seconds are
    load-bearing: the stage spans start at :20, :30, :40 and :50 past the
    minute, and a 15 s window on a 5 s stride resolves them. Truncating to the
    minute would move every boundary by up to 59 s and mislabel windows at both
    ends of every stage. The interval SHAPE above is that module's, so the rule
    below reads the same fields in the same order; only the time parser differs.
    """
    window_sec = cfg["windows"]["window_seconds"]
    priority = {stage: i for i, stage in enumerate(cfg["stages"])}

    host = wf["host"].astype(str).to_numpy()
    # The same label-before-pseudonymise guard `timeline_labels.label_windows`
    # carries, for the same reason: HMAC pseudonyms are hex with no dots, so
    # nothing would match an operator-log IP and every window would come back
    # benign. `bootstrap` would then refuse the single-class fit — but with the
    # message "the capture and the operator log disagree", which sends the reader
    # to regenerate a capture that is fine. Name the real cause here instead.
    if len(host) and not any("." in h for h in host[: min(len(host), 1000)]):
        raise ValueError(
            "the window frame's `host` column holds no dotted-IP address, so no "
            "operator-log host can ever match and every window would be labelled "
            "benign. Labelling must run on REAL host IPs, before pseudonymisation "
            "(data/windows.py builds them that way for the engine's PCAP path). "
            f"First hosts seen: {sorted(set(host[:5]))}")
    w_start = wf["window_start"].to_numpy(dtype=float)
    w_end = w_start + window_sec

    labels = np.array(["benign"] * len(wf), dtype=object)
    rank = np.zeros(len(wf), dtype=int)
    for interval in intervals:
        hit = ((w_start < interval["end"]) & (w_end > interval["start"])
               & np.isin(host, list(interval["hosts"])))
        this_rank = priority[interval["stage"]]
        take = hit & (this_rank >= rank)
        labels[take] = interval["stage"]
        rank[take] = this_rank
    return pd.Series(labels, index=wf.index, name="stage")


# ---------------------------------------------------------------------------
# Fit.
# ---------------------------------------------------------------------------


def demo_head_filename(cfg: dict, tag: str, horizon: int) -> str:
    """Weight filename for one (input variant, horizon) DEMO head.

    `engine.train_engine.head_filename` spelled with the configured
    `demo.model_prefix` in front. The prefix is the reason
    `tests/_stubs.engine_artifacts_present()` stays False for a fully built demo
    lane: that gate looks for `engine_model.json` and `engine_model_flow.json`
    by name, and no file here is called either.
    """
    from engine.train_engine import head_filename

    return f"{cfg['demo']['model_prefix']}{head_filename(tag, horizon)}"


def flow_feature_mask(cfg: dict) -> np.ndarray:
    """The CSV ('flow') variant's column mask, as engine/train_engine.py builds it.

    Zero for each of the 17 packet-statistic fields, one everywhere else, in
    `data.windows.feature_columns` order. Applied AFTER scaling, which is what
    `engine/train_engine.py` does; both derive the masked set from
    `configs/data.yaml` `packet_features.fields` rather than listing columns, so
    a change to that list moves both together.

    Named rather than inlined so a test can assert on the mask this script really
    uses. The consequence that makes it checkable: the masked columns are
    constant (exactly 0.0) across every training row, so the fitted trees never
    split on them, so the flow head's predictions do not depend on those columns
    AT ALL. Measured this session on the real demo matrix — the flow head scores
    the raw and the masked matrix identically (max |difference| = 0.0) while the
    full head does not (0.0329).

    That also settles the train/inference gap this mask would otherwise open.
    `engine/predict.py` applies no mask at inference: it scales a raw frame whose
    packet columns `window_features_from_flows` set to 0.0, which lands on
    (0-mean)/std rather than on 0. For a head that never reads those columns,
    that difference cannot change a prediction — and the test measures it rather
    than arguing it.
    """
    feat_cols = list(_feature_columns(cfg))
    packet_cols = set(cfg["packet_features"]["fields"])
    return np.array([0.0 if c in packet_cols else 1.0 for c in feat_cols],
                    dtype=np.float32)


def _feature_columns(cfg: dict) -> list[str]:
    from data import windows as W

    return W.feature_columns(cfg)


def operating_points(y: np.ndarray, scores: np.ndarray, budgets) -> dict:
    """Per-budget threshold, the FPR it ACHIEVES, and whether the budget was
    expressible at all on this many benign rows.

    A budget finer than 1/n_benign cannot be distinguished from the next
    expressible one: `eval.metrics.threshold_at_fpr` picks the lowest threshold
    whose benign-hit fraction is within budget, and with 120 benign rows the only
    achievable fractions are 0, 1/120, 2/120 ... So 0.1% and 1% come back as the
    SAME cut (measured this session: both 0.98968..., both alerting on zero benign
    windows), and a reader who moves the FPR budget in the app sees nothing move.

    Persisting two numbers under two budget names without recording that is the
    project's named failure mode in miniature — a number that outruns the data
    behind it. So the lane records what each budget actually bought.
    """
    from eval import metrics as M

    y = np.asarray(y).astype(bool)
    benign = np.asarray(scores, dtype=float)[~y]
    if benign.size == 0:
        raise ValueError("no benign rows — no operating point can be chosen")
    finest = 1.0 / benign.size
    out = {"n_benign": int(benign.size), "finest_expressible_fpr": float(finest),
           "budgets": {}}
    for budget in budgets:
        thr = float(M.threshold_at_fpr(y, scores, budget))
        out["budgets"][str(budget)] = {
            "threshold": thr,
            "achieved_fpr": float(np.count_nonzero(benign >= thr) / benign.size),
            "budget_expressible": bool(float(budget) >= finest),
        }
    return out


def pin_fit_threads(cfg: dict) -> tuple[int, bool]:
    """(threads requested, whether the pin can still take effect).

    `models/baselines.py` builds the head with `n_jobs=-1`, which XGBoost reads
    as "one thread per core"; its parallel histogram build then sums in a
    thread-count-dependent order and the saved model differs byte for byte
    between machines with different core counts.

    OpenMP reads OMP_NUM_THREADS when its runtime INITIALISES, and for XGBoost
    that is its first import — not its first fit. So writing the variable after
    `import xgboost` has already happened does nothing at all, and the second
    element of the return value is that fact: True only when this process has not
    yet imported xgboost.

    MEASURED, this session, on the real demo matrix: in a process that imported
    xgboost first, `fit_threads=1` and `fit_threads=4` both produced
    `demo_engine_model.json` = bc7fdd07d9dc... (this machine's 12-core default),
    while clean processes produced d428729d3562... and 1003f2454f32...
    respectively. Reporting `fit_threads: 1` in that first case — which is what
    this function used to let `bootstrap` do — is a recorded number the run never
    applied.

    The probe is `"xgboost" in sys.modules`, and it is exact rather than
    conservative: the measurement above used a BARE import with no fit, and the
    pin was already dead.
    """
    threads = int(cfg["demo"]["fit_threads"])
    if threads < 1:
        raise ValueError(
            f"configs/data.yaml `demo.fit_threads` must be >= 1, got {threads}")
    effective = "xgboost" not in sys.modules
    os.environ["OMP_NUM_THREADS"] = str(threads)
    return threads, effective


def _fit_head(cfg_b: dict, X: np.ndarray, y: np.ndarray):
    """The same model class the engine loads: `models.baselines` 'xgb', whose
    `.model` is the `xgb.XGBClassifier` that `engine.predict._load_engine`
    reconstructs with `load_model`."""
    from models import baselines

    return baselines.build_model("xgb", cfg_b).fit(X, y)


def bootstrap(cfg: dict | None = None, cfg_baselines: dict | None = None,
              cfg_eval: dict | None = None, target: Path | None = None,
              allow_unpinned_threads: bool = False) -> dict:
    """Fit and persist the demo lane. Returns the manifest that `main` prints.

    `target` defaults to `demo.artifacts_dir` and exists so tests can aim the
    whole run at a temporary directory; wherever it points,
    `refuse_to_clobber_published_artifacts` runs first.

    `allow_unpinned_threads` is for CALLERS WHOSE BYTES DO NOT MATTER — a test
    that wants a lane on disk inside a pytest session that has already imported
    xgboost. It does not make the pin work; it makes the run continue and forces
    the lane to say so, in `weights_reproducible: false`. The default is to
    refuse, because a lane written under an ineffective pin has a provenance
    block that names a thread count the fit did not use.

    OMP_NUM_THREADS IS PUT BACK before this returns, whichever way it returns.
    The pin has to be process-global to reach XGBoost at all, but it must not
    outlive the fit: an in-process caller is the test suite, and leaving
    OMP_NUM_THREADS=1 exported would silently re-thread every later test and
    every subprocess they spawn. `pin_fit_threads` is still the one place that
    sets it, so a test can check the pin itself without depending on this
    cleanup.
    """
    previous_omp = os.environ.get("OMP_NUM_THREADS")
    try:
        return _bootstrap(cfg, cfg_baselines, cfg_eval, target, allow_unpinned_threads)
    finally:
        if previous_omp is None:
            os.environ.pop("OMP_NUM_THREADS", None)
        else:
            os.environ["OMP_NUM_THREADS"] = previous_omp


def _bootstrap(cfg, cfg_baselines, cfg_eval, target, allow_unpinned_threads) -> dict:
    """`bootstrap`'s body; see there. Split out only so the OMP_NUM_THREADS pin
    can be restored on every exit path without wrapping 120 lines in a `try`."""
    cfg = cfg or load_config("data")
    cfg_baselines = cfg_baselines or load_config("baselines")
    cfg_eval = cfg_eval or load_config("eval")

    target = Path(target).resolve() if target is not None else demo_artifacts_dir(cfg)
    refuse_to_clobber_published_artifacts(cfg, target)

    seed = int(cfg["demo"]["seed"])
    set_seed(seed)
    threads, pin_effective = pin_fit_threads(cfg)  # before anything imports XGBoost
    if not pin_effective and not allow_unpinned_threads:
        raise ThreadPinIneffective(
            f"xgboost is already imported in this process, so setting OMP_NUM_THREADS="
            f"{threads} has no effect — OpenMP fixed its thread count at that import. "
            "The weights this run would write are a property of this machine's core "
            f"count, not of {cfg['demo']['pcap']}, and the provenance block would "
            f"record `fit_threads: {threads}` for a fit that did not use it. Run "
            "`python scripts/bootstrap_demo_artifacts.py` in a fresh interpreter. If "
            "the bytes genuinely do not matter (a test building a lane on disk), pass "
            "allow_unpinned_threads=True and the lane will record "
            "`weights_reproducible: false`.")

    pcap, log = demo_capture_paths(cfg)

    # The engine's own anonymiser policy, so the demo lane is fitted on exactly
    # the role features the engine will compute at inference on this machine.
    # With no SIH26_HMAC_KEY the engine zeroes `internal`/`net24_bucket`; a demo
    # model fitted with them derived would then be scored on zeros.
    from engine import predict as P

    anonymizer = P._maybe_anonymizer(cfg)
    role_degraded = bool(P.role_features_degraded(anonymizer))

    _flows, wf, coverage = window_features_from_demo_capture(cfg, pcap, anonymizer)
    if wf.empty:
        raise ValueError(f"{pcap} produced no host-windows — nothing to fit")
    refuse_a_partially_parsed_capture(coverage, pcap)

    capture_start = float(wf["window_start"].min())
    capture_end = float(wf["window_start"].max()) + cfg["windows"]["window_seconds"]
    intervals = stage_intervals(cfg, parse_operator_log(log), capture_start, capture_end)
    wf = wf.assign(stage=label_windows(cfg, wf, intervals))
    wf = wf.sort_values(["host", "window_id"], kind="stable").reset_index(drop=True)

    stage_counts = {s: int(n) for s, n in wf["stage"].value_counts().items()}
    n_attack = int((wf["stage"] != "benign").sum())
    if n_attack == 0 or n_attack == len(wf):
        raise ValueError(
            f"labelling {pcap.name} against {log.name} produced {n_attack} attack "
            f"windows out of {len(wf)} — a single-class fit is not a model. The "
            "capture and the operator log disagree; regenerate both with "
            "`python -m capture.make_synthetic_demo`.")

    # -- scale, then fit one head per (variant, horizon), as engine/train_engine
    #    does. The scaler is persisted under the name engine/predict.py loads.
    from sklearn.preprocessing import StandardScaler

    from eval import dataset as D
    from eval import metrics as M

    feat_cols = _feature_columns(cfg)
    X_raw = wf[feat_cols].to_numpy(dtype=np.float64)
    scaler = StandardScaler().fit(X_raw)
    X_all = scaler.transform(X_raw).astype(np.float32)

    # The CSV ('flow') variant, masked EXACTLY as engine/train_engine.py masks
    # it: the 17 packet-stat columns zeroed AFTER scaling. See
    # `flow_feature_mask` for why mirroring the published trainer is the point
    # here, and for the measured consequence that makes the mirroring checkable.
    flow_mask = flow_feature_mask(cfg)

    target.mkdir(parents=True, exist_ok=True)
    D.persist_window_scaler({"paths": {"artifacts_dir": str(target)}}, scaler)

    horizons = [int(k) for k in cfg["engine"]["forecast_horizons"]]
    stride = float(cfg["windows"]["stride_seconds"])
    persisted: dict = {
        TH.LANE_FIELD: TH.DEMO_LANE,
        "model": "xgb",
        "features": feat_cols,
        "stride_seconds": stride,
        "horizons": horizons,
    }
    heads: list[dict] = []
    skipped: dict[str, str] = {}
    head_operating_points: dict[str, dict] = {}

    for horizon in [0, *horizons]:
        # The SAME target shift eval/dataset.py applies, called directly rather
        # than reimplemented, so the demo heads predict what the harness does.
        stage_k, y_k = D._shift_target_by_horizon(wf, horizon)
        keep = (np.array([s is not None for s in stage_k]) if horizon > 0
                else np.ones(len(wf), dtype=bool))
        X_k, y_k = X_all[keep], y_k[keep].astype(np.int8)
        pos = int(y_k.sum())
        if pos == 0 or pos == len(y_k):
            # Not an error here, unlike engine/train_engine: this capture is 454
            # seconds long, so a large k can legitimately leave one class. Record
            # WHY and carry on; engine/forecast.py reports a missing head.
            skipped[str(horizon)] = (
                f"k={horizon}: after shifting the target +{horizon} windows the demo "
                f"capture leaves {pos} attack rows out of {len(y_k)} — a single-class "
                "split cannot be fitted or thresholded, so no head is persisted")
            continue
        for tag, mask in (("full", None), ("flow", flow_mask)):
            X_fit = X_k if mask is None else X_k * mask
            model = _fit_head(cfg_baselines, X_fit, y_k)
            scores = model.predict_proba(X_fit)
            fname = demo_head_filename(cfg, tag, horizon)
            model.model.save_model(str(target / fname))
            block = {
                "file": fname,
                "horizon": horizon,
                "seconds_ahead": horizon * stride,
                # Deliberately NOT `val_auroc`. There is no validation split
                # here: this is the fitted model re-scoring its own training
                # rows. Naming it `val_auroc` would put a memorisation figure
                # in the field the published lane uses for a held-out one.
                "in_sample_auroc": float(M.auroc(y_k, scores)),
                "auroc_is_in_sample": True,
            }
            # The spec's SHAPE stays exactly the published lane's — one
            # `fpr_<budget>` float per budget, which is all engine/thresholds.py
            # reads. What each budget actually bought goes in the provenance
            # block, which is inert to the engine; see `operating_points`.
            points = operating_points(y_k, scores, cfg_eval["fpr_budgets"])
            for budget in cfg_eval["fpr_budgets"]:
                block[f"fpr_{budget}"] = points["budgets"][str(budget)]["threshold"]
            variant = TH.horizon_variant(tag, horizon)
            persisted[variant] = block
            head_operating_points[variant] = points
            heads.append({"variant": variant, "operating_points": points, **block})

    persisted[PROVENANCE_KEY] = {
        "what_this_is": (
            "a toy model fitted on the bundled synthetic capture "
            f"{cfg['demo']['pcap']}, so that a fresh clone can run the pipeline"),
        "what_this_is_not": (
            "the published model. It never saw CSE-CIC-IDS-2018. No number it "
            "produces is comparable to any published number, and running it "
            "reproduces nothing"),
        "source_capture": cfg["demo"]["pcap"],
        "source_capture_sha256": VW.sha256_file(pcap),
        "operator_log": cfg["demo"]["operator_log"],
        "operator_log_sha256": VW.sha256_file(log),
        "seed": seed,
        # Recorded because the saved bytes depend on it: see `pin_fit_threads`.
        # `fit_threads` alone was a lie waiting to happen — it is what was ASKED
        # for, and the pin is silently inert once xgboost has been imported. The
        # two fields below say whether it was actually applied, so a reader never
        # has to take the number on trust.
        "fit_threads": threads,
        "fit_threads_pin_effective": pin_effective,
        "weights_reproducible": pin_effective,
        "n_host_windows": int(len(wf)),
        "stage_window_counts": stage_counts,
        "fitted_and_thresholded_in_sample": True,
        "role_features_degraded": role_degraded,
        "heads_not_fitted": skipped,
        # What the extractor could not read. Zero on the bundled capture today;
        # a non-zero count stops the run (`refuse_a_partially_parsed_capture`),
        # and `known: false` is recorded rather than read as clean.
        "capture_coverage": coverage,
        # Per head: the FPR each persisted threshold ACHIEVES, and whether the
        # budget it is named after was expressible on this many benign rows at
        # all. See `operating_points` — with 120 benign windows the 0.1% and 1%
        # budgets are the same cut, and the lane has to say so rather than
        # present two numbers as two operating points.
        "operating_points": head_operating_points,
        "fpr_budgets_below_capture_resolution": sorted(
            {b for p in head_operating_points.values()
             for b, d in p["budgets"].items() if not d["budget_expressible"]}),
        # The three stages that have NO labelled data in the dataset this project
        # reports on. This lane labels them because they were hand-written into
        # the capture; that is an illustration, not the missing data, and the
        # distinction has to travel with the artifacts.
        "hand_authored_stages_that_remain_unlabelled_in_the_real_dataset": [
            s for s in ("recon", "lateral_movement", "exfiltration")
            if stage_counts.get(s, 0) > 0],
    }

    cfg_target = {"paths": {"artifacts_dir": str(target)}, "demo": cfg["demo"]}
    TH.persist_threshold(cfg_target, persisted)
    (target / WHAT_THIS_IS_FILENAME).write_text(WHAT_THIS_IS, encoding="utf-8")

    # Own digest record, with verify_weights' own hasher and path, so
    # engine/predict.py's M9.3 attestation runs against this lane unchanged and
    # a tampered demo weight is still refused.
    #
    # The base set is asked of `verify_weights.tracked_names` rather than listed
    # here, because that module decides what a lane's record must cover and two
    # lists would drift: this script would attest a file verify_weights did not
    # demand, or — the failure that matters — stop attesting one it does, and
    # `verify` would pass over bytes nobody had hashed. The k-step heads are then
    # ADDED on top; verify_weights leaves them untracked in both lanes, but this
    # lane writes them in the same run as everything else, so hashing them costs
    # nothing and a tampered k=8 head is caught too.
    tracked = [n for n in VW.tracked_names(cfg_target) if (target / n).exists()]
    weights = sorted(set(tracked) | {h["file"] for h in heads} | {"window_scaler.pkl"})
    digests = {n: VW.sha256_file(target / n) for n in weights}
    VW.digest_path(cfg_target).write_text(json.dumps(digests, indent=2), encoding="utf-8")

    return {
        "target": str(target),
        "capture": str(pcap),
        "operator_log": str(log),
        "seed": seed,
        "fit_threads": threads,
        "fit_threads_pin_effective": pin_effective,
        "weights_reproducible": pin_effective,
        "n_host_windows": int(len(wf)),
        "n_attack_windows": n_attack,
        "stage_window_counts": stage_counts,
        "role_features_degraded": role_degraded,
        "capture_coverage": coverage,
        # The window grid the operator log was resolved against, so a caller
        # never has to retype an epoch to reason about the capture's clock.
        "capture_window_start": capture_start,
        "capture_window_end": capture_end,
        "heads": heads,
        "heads_not_fitted": skipped,
        "fpr_budgets_below_capture_resolution":
            persisted[PROVENANCE_KEY]["fpr_budgets_below_capture_resolution"],
        "hand_authored_stages_that_remain_unlabelled_in_the_real_dataset":
            persisted[PROVENANCE_KEY][
                "hand_authored_stages_that_remain_unlabelled_in_the_real_dataset"],
        "digests": digests,
        "files": sorted(p.name for p in target.iterdir() if p.is_file()),
    }


# ---------------------------------------------------------------------------
# CLI.
# ---------------------------------------------------------------------------


def format_report(manifest: dict) -> str:
    lines = ["", "=" * 72,
             "DEMO ARTIFACTS WRITTEN. THESE ARE NOT THE PUBLISHED MODEL.",
             "=" * 72, "",
             f"directory : {manifest['target']}",
             f"fitted on : {manifest['capture']}",
             f"labels    : {manifest['operator_log']}",
             f"seed      : {manifest['seed']}  (fit threads pinned to "
             f"{manifest['fit_threads']} - the saved bytes depend on it)"
             + ("" if manifest["fit_threads_pin_effective"]
                else "  *** PIN DID NOT TAKE EFFECT ***"),
             f"windows   : {manifest['n_host_windows']} host-windows, "
             f"{manifest['n_attack_windows']} of them labelled attack",
             "stages    : " + ", ".join(
                 f"{s}={n}" for s, n in sorted(manifest["stage_window_counts"].items())),
             ""]
    lines.append("files written:")
    for name in manifest["files"]:
        digest = manifest["digests"].get(name)
        lines.append(f"  {name}" + (f"   sha256 {digest}" if digest else ""))
    lines.append("")
    lines.append("heads fitted (in-sample AUROC - the model re-scoring its own")
    lines.append("training rows, which is a property of the fit and not a measurement):")
    for head in manifest["heads"]:
        lines.append(f"  {head['variant']:<12} k={head['horizon']} "
                     f"(+{head['seconds_ahead']:g}s)  in-sample AUROC "
                     f"{head['in_sample_auroc']:.3f}")
    for horizon, why in sorted(manifest["heads_not_fitted"].items()):
        lines.append(f"  NOT FITTED  {why}")

    if manifest["fpr_budgets_below_capture_resolution"]:
        lines += [
            "",
            "FPR BUDGETS THIS CAPTURE CANNOT EXPRESS:",
            "  A head with N benign rows can only ever achieve a false-positive rate",
            "  of 0, 1/N, 2/N ... so a budget finer than 1/N is not a separate",
            "  operating point - it collapses onto the next expressible cut. Moving",
            "  the FPR budget in the app will not move these heads. Per head, benign",
            "  rows -> finest expressible FPR, then the budgets below it:",
        ]
        for head in manifest["heads"]:
            points = head["operating_points"]
            below = [b for b, d in points["budgets"].items()
                     if not d["budget_expressible"]]
            if not below:
                continue
            lines.append(
                f"  {head['variant']:<12} {points['n_benign']:>4} benign -> finest "
                f"{points['finest_expressible_fpr']:.2%}; below it: "
                f"{', '.join(below)}")
        lines += [
            "  That is a property of a capture this short, not of the engine. What",
            "  each budget actually achieved is recorded per head under",
            f"  `{PROVENANCE_KEY}.operating_points`.",
        ]

    hand_authored = manifest[
        "hand_authored_stages_that_remain_unlabelled_in_the_real_dataset"]
    if hand_authored:
        lines += [
            "",
            "THIS DOES NOT FILL THE EMPTY KILL-CHAIN STAGES:",
            f"  This lane has labelled windows for {', '.join(hand_authored)}.",
            "  Those stages have NO labelled data in the dataset this project reports",
            "  on. They are here because they were hand-written into a 454-second",
            "  capture to be found again. Building this lane does not change what can",
            "  be said about them - 'no training data' is still the honest answer.",
        ]

    coverage = manifest.get("capture_coverage") or {}
    if not coverage.get("known", False):
        lines += [
            "",
            "note: the extractor did not report how many frames it dropped, so this",
            "      run cannot confirm the whole capture reached the model. Unknown is",
            "      recorded as unknown, not as zero.",
        ]
    if not manifest["fit_threads_pin_effective"]:
        lines += [
            "",
            "*** THESE WEIGHTS ARE NOT REPRODUCIBLE ***",
            "  xgboost was already imported when this run pinned the thread count,",
            "  so OMP_NUM_THREADS had no effect and the fit used this machine's",
            f"  core count instead of {manifest['fit_threads']}. Another machine will",
            "  produce different bytes from the same capture. The lane records",
            "  `weights_reproducible: false`. Re-run this script as a script, in a",
            "  fresh interpreter, to get a lane whose bytes are a property of the",
            "  capture.",
        ]
    if manifest["role_features_degraded"]:
        lines.append("")
        lines.append("note: no SIH26_HMAC_KEY in the environment, so the two role")
        lines.append("      features (internal, net24_bucket) were zero when this was")
        lines.append("      fitted. The engine zeroes them too when the key is absent,")
        lines.append("      so fit and inference agree - but setting the key later")
        lines.append("      changes the inputs this model was fitted on. Re-run this")
        lines.append("      script if you set one.")
    lines += [
        "",
        "WHAT THIS MODEL IS:",
        "  A toy. It was fitted on one small hand-written capture that ships in",
        "  this repository, and its alert thresholds were chosen on the same rows",
        "  it was fitted on. It has memorised that capture.",
        "",
        "WHAT IT IS NOT:",
        "  It is not the published model. It never saw CSE-CIC-IDS-2018. If you",
        "  run the demo and see a probability, that number is this toy recognising",
        "  traffic it was trained on. It is not a detection result, it is not",
        "  comparable to any number in the README or the report, and it reproduces",
        "  nothing. It also does not make this repository's skipped end-to-end",
        "  tests run: those are gated on the real artifacts, by name.",
        "",
    ]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Fit demo-lane engine artifacts from the bundled synthetic capture.")
    parser.add_argument(
        "--target", default=None,
        help="directory to write into (default, and the only one the engine will "
             "load from: configs/data.yaml demo.artifacts_dir). A lane written "
             "anywhere else is refused by engine/thresholds.py — the flag exists for "
             "tests and for inspecting a build, not for relocating the lane")
    args = parser.parse_args(argv)

    try:
        manifest = bootstrap(target=Path(args.target) if args.target else None)
    except PublishedArtifactsPresent as exc:
        print(f"REFUSED: {exc}", file=sys.stderr)
        return 2
    except CaptureNotFullyParsed as exc:
        print(f"REFUSED: {exc}", file=sys.stderr)
        return 4
    except ThreadPinIneffective as exc:
        # Unreachable from a normal `python scripts/bootstrap_demo_artifacts.py`
        # — nothing this module imports at start-up pulls in xgboost, which is
        # what makes the script path the reproducible one. Handled anyway,
        # because the thing that would make it reachable is a new import at the
        # top of some module on this path, and that must surface as this message
        # rather than as a traceback.
        print(f"REFUSED: {exc}", file=sys.stderr)
        return 3
    print(format_report(manifest))
    return 0


if __name__ == "__main__":
    sys.exit(main())
