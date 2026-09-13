"""Photograph the offline demo app. Output: docs/img/screenshots/.

    python scripts/capture_screenshots.py

WHY THIS EXISTS
The repository contained no picture of the product. A judge opening README.md,
the deck or docs/architecture.pdf had read several thousand words about a
Streamlit app and had never seen it. Everything needed to fix that is already
here: `scripts/bootstrap_demo_artifacts.py` fits a demo lane from the bundled
synthetic capture, and `app/streamlit_app.py` runs against it on a bare clone.
This script joins those two and writes the frames.

WHAT IT PHOTOGRAPHS, AND WHAT THAT IS WORTH
The DEMO model. A toy fitted on one 454-second hand-authored capture
(`app/assets/synthetic_demo.pcap`), whose alert thresholds were chosen on the
rows it was fitted on — it has memorised that capture. Every probability, alert
count, threshold and ranking in every image this script writes is the demo
model's, and is **not comparable** to any number this project publishes. That is
not a caveat bolted onto the output; it is the single largest risk in shipping
screenshots at all, because a picture is believed faster than prose. So it is
enforced three ways, in descending order of strength:

1. THE BANNER IN FRAME. `app/panels.py` already marks the surfaces where a demo
   number misleads — the provenance box, the threshold metric's own label, the
   explanation caption, the graph caption, the k-step caption — and draws
   `DEMO_FIGURE_MARK` INTO the matplotlib PNGs. Each shot below declares which of
   those marks its crop must contain, the crop's own DOM text is read back after
   the rect is computed, and a shot whose frame does not contain its declared
   mark ABORTS THE RUN (`--allow-unmarked` downgrades that to a recorded
   failure). A screenshot that carries its own disclosure needs no reader to have
   read anything else.
2. THE MANIFEST. Every image gets a row in `docs/img/screenshots/manifest.json`
   carrying its SHA-256, the region it was cropped from, which marks were in
   frame, and a caption. `tests/test_screenshots.py` fails when a PNG in that
   directory has no row, and when a row's digest does not match the bytes on
   disk — so replacing an image without re-stating its provenance fails the
   suite rather than passing quietly.
3. THE README. `docs/img/screenshots/README.md` states in prose what these
   images are and are not, and carries the caption for the two frames (the
   ledger pair) where the app itself renders no demo mark and an honest answer
   is therefore a caption rather than a banner.

The script REFUSES TO RUN against the published model. If the page comes up
without the demo provenance box, these files would be pictures of a different
system under a README that says "demo", so it exits instead (see
`assert_demo_lane_page`).

HOW IT DRIVES THE APP
Streamlit needs a server, so one is started on a free port and polled at
`/_stcore/health` until it answers. The browser is the SAME headless Edge
`scripts/build_architecture_pdf.py` uses, located by importing that module's
`find_edge()` rather than by keeping a second list of paths that could drift
from it. Edge is driven over its own DevTools protocol: the transport is
`websockets`, which is already a pinned requirement (Streamlit's own
dependency), so nothing new is installed and the run stays fully offline —
127.0.0.1 only, no CDN, no driver download.

`--print-to-pdf`-style one-shot rendering could not do this job: the interesting
states are behind clicks (choose the demo capture, open the provenance fold,
tamper with the ledger), and Streamlit reruns the script over a websocket rather
than navigating, so there is no URL for "the page after the button". Hence CDP.

WHAT A RUN MEASURES RATHER THAN ASSUMES
- the demo lane's four weight files exist, else `bootstrap_demo_artifacts.py` is
  run as a SUBPROCESS (its OpenMP thread pin only binds in a process that has
  not yet imported xgboost — see that script's docstring);
- the app reached idle (Streamlit's own status widget gone) before every shot;
- each crop contains the elements it claims: a chart `<img>`, the plotly canvas,
  the strings the state is defined by ("TAMPER DETECTED at record 0" for the
  tamper frame — a tamper button that silently did nothing fails the run);
- each written PNG is not a flat rectangle (`min_colors`), which is how a
  headless WebGL failure would otherwise ship as a clean-looking empty box;
- each written PNG is not TORN — no band of content painted twice. This one is
  checked on the pixels because it is invisible to every check above it: the
  3D-graph frame shipped from this script with its heading painted three times
  and no graph in it, and passed all of them (`longest_repeated_band`).

Nothing in this file hard-codes a result. The four metric values that appear in
the manifest are read off the rendered page at capture time and are labelled
`demo_run_facts`.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import importlib.util
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from app import panels  # noqa: E402  (needs REPO on sys.path)
from configs import load_config, resolve_path  # noqa: E402

OUT_DIR_DEFAULT = REPO / "docs" / "img" / "screenshots"
MANIFEST_NAME = "manifest.json"
APP_RELATIVE = Path("app") / "streamlit_app.py"
BOOTSTRAP_RELATIVE = Path("scripts") / "bootstrap_demo_artifacts.py"

# Directories NOT copied into an isolated run root (see `isolated_run_root`).
# `artifacts` is the point of the exercise; the rest are large, regenerable or
# machine-local, and copying them would turn a 13 MB copy into a multi-gigabyte
# one.
ISOLATION_EXCLUDES = (
    "artifacts", "vendor", "run", "results", ".git", ".venv", ".pytest_cache",
    "__pycache__", "node_modules",
)

# The page is rendered into a viewport this wide and as tall as the content, so
# that every crop is a rect in one laid-out page and no shot has to scroll. 1500
# is wide enough for the app's `layout="wide"` columns to sit side by side, which
# is how a judge sees it on a projector.
VIEWPORT_WIDTH = 1500
# Height of the capture viewport. Every crop must fit inside it, and each shot
# scrolls its own region into view before the shutter.
#
# THE FIRST VERSION OF THIS SCRIPT DID THE OPPOSITE — it grew the viewport until
# the whole ~5,750 px page fitted, so no shot had to scroll. That is simpler and
# it does not work here. Headless Edge has no GPU, the app's plotly 3D scene is
# therefore rasterised in software, and a viewport that tall keeps that canvas
# inside the composited surface for EVERY frame. Measured on this machine, same
# page, same shots: shutters of 1.5 s, 48.2 s, 0.1 s and 72.9 s for the first
# four frames, and then the k-step frame — a static chart and two tables, no
# WebGL of its own — did not return in 900 s. Scrolling instead keeps the
# surface at one screenful, and keeps the WebGL canvas out of it entirely for
# the six shots that are not of the graph.
#
# 1800 is chosen from the crops themselves: the tallest (the k-step panel) is
# about 1,630 CSS px. A region that does not fit fails loudly rather than being
# silently trimmed.
CAPTURE_VIEWPORT_HEIGHT = 1800
# Device pixels per CSS pixel. 2 is retina and is what a projector wants, and it
# was the first choice here — but the whole page is laid out in ONE viewport so
# that every crop is a rect in one document, and at 2x on this app that surface
# is 3000 x 11494 px. Headless Edge has no GPU, so the plotly 3D scene in it is
# rasterised in software, and `Page.captureScreenshot` waits for that. Measured
# on this machine, at 2x, with the project's training run loading it: shutter
# times of 0.8 s, 47.3 s and 77.7 s for three successive frames, then a frame
# containing the WebGL canvas that had not returned after fifteen minutes.
# At 1x the surface is a quarter of the pixels. 1500 CSS px wide is still about
# 1.9x the width GitHub renders an image at, so the text stays legible.
# `--device-scale` raises it on a machine that can afford it.
DEVICE_SCALE = 1

HEALTH_TIMEOUT_S = 240.0
CDP_TIMEOUT_S = 180.0
# Its own budget, well above CDP_TIMEOUT_S. `Page.captureScreenshot` of a region
# containing the plotly WebGL canvas goes through the software rasteriser
# (swiftshader) on this headless browser, and that is minutes rather than
# seconds on a loaded machine — measured: the 3D-graph frame timed out at 180 s
# while every text-only frame returned in a few.
SCREENSHOT_TIMEOUT_S = 900.0
# One attempt inside that budget. A stalled capture is retried after the page is
# forced to paint, rather than waited on for the whole budget — see
# Browser.capture_clip.
SCREENSHOT_ATTEMPT_S = 90.0


class CDPTimeout(RuntimeError):
    """A DevTools command did not answer. Retryable; not necessarily fatal."""
IDLE_TIMEOUT_S = 900.0
# Streamlit's status widget disappears between the two reruns a click can cause,
# so "idle" is only believed after it has been absent for this long.
IDLE_SETTLE_S = 2.0
# After idle, matplotlib PNGs and the plotly canvas still have to paint.
PAINT_SETTLE_S = 4.0


# --------------------------------------------------------------------- markers
#
# The strings a crop must contain to carry its own provenance. Imported from
# app/panels.py, never retyped: these are the marks the page renders, and a copy
# here would let the page's wording change while this file kept checking the old
# words and reporting success.
#
# Markdown emphasis is stripped from both sides before comparison (`plain()`) —
# `**bold**` reaches the DOM as bold text, not as asterisks.
MARKERS: dict[str, str] = {
    "provenance-banner": panels.DEMO_MODEL_HEADLINE,
    "threshold-metric-label": panels.DEMO_THRESHOLD_METRIC_LABEL,
    "metrics-mark": panels.DEMO_METRICS_MARK,
    "explanation-mark": panels.DEMO_EXPLANATION_MARK,
    "graph-mark": panels.DEMO_GRAPH_MARK,
    "kstep-mark": panels.DEMO_FORECAST_MARK,
}


def plain(text: str) -> str:
    """Markdown source -> what the DOM shows, for substring comparison.

    Emphasis markers are removed, not just the bold pair: DEMO_METRICS_MARK
    italicises `*synthetic capture's*`, and leaving those asterisks in made the
    mark unfindable in the rendered text — measured on the first run of this
    script, which correctly refused to write the frame.
    """
    out = text.replace("`", "").replace("*", "")
    return " ".join(out.split())


def longest_common_prefix(needle: str, haystack: str) -> int:
    """How much of `needle` appears in `haystack` before the match breaks.

    Only used to explain a failure. "the mark is not in the crop" is true but
    useless when the real cause is one character of punctuation; this says where
    the two texts stopped agreeing.
    """
    for cut in range(len(needle), 0, -1):
        if needle[:cut] in haystack:
            return cut
    return 0


# ----------------------------------------------------------------- shot specs


@dataclass(frozen=True)
class Shot:
    """One frame: how to reach it, where to crop, and what must be inside it."""

    name: str                     # file stem, and the manifest key
    title: str                    # human title, into the manifest and README
    caption: str                  # the provenance that travels with the file
    top: tuple[str, str]          # ("header", "5 ·") | ("alert", <marker key>)
    bottom: tuple[str, str] | None  # same, or None for "to the end of content"
    requires: tuple[str, ...] = ()  # MARKERS keys that must be inside the crop
    expect_text: tuple[str, ...] = ()   # literal strings the crop must contain
    forbid_text: tuple[str, ...] = ()   # strings whose presence means a bad state
    expect_img: int = 0           # matplotlib chart <img> elements inside the crop
    expect_canvas: int = 0        # plotly WebGL canvases inside the crop
    # A sub-rect (CSS selector) that must itself be non-flat. This is what turns
    # "a canvas element is present" into "the canvas drew something": a headless
    # WebGL failure leaves a correctly-sized, perfectly blank box.
    nonblank_selector: str = ""
    # Floor on the distinct colours in the written PNG, and in `nonblank_selector`'s
    # sub-rect. NOT a round number pulled from the air: the frames this script
    # writes measured 9,384 / 2,495 / 1,625 / 2,294 colours, and the one broken
    # capture produced here (see Browser.capture_clip) measured 61 overall and 59
    # inside the canvas. 400 sits an order of magnitude below the real frames and
    # an order of magnitude above the broken one.
    min_colors: int = 400
    # Floor for `nonblank_selector`'s sub-rect, which needs its own number: the
    # 3D scene is a dark background with five nodes on it, so a CORRECT render is
    # far flatter than a page of text. Measured on this app — a correct graph
    # canvas: 238 and 329 distinct colours; the broken capture: 59. 120 sits
    # twice above the broken one and half below the correct ones.
    min_canvas_colors: int = 120
    # Actions run before the crop, as (kind, argument) pairs. See `do_action`.
    actions: tuple[tuple[str, str], ...] = ()
    # Extra seconds to let the page settle before the shutter. Needed where an
    # action changes the page's HEIGHT: measured here, opening the provenance
    # fold and shooting straight afterwards produced a TORN frame — the same two
    # paragraphs rendered twice, one above the other, because the compositor
    # reused tiles from before the expansion. The DOM text was identical before
    # and after the shutter, so nothing else in this script could have caught it;
    # it was found by looking at the picture.
    settle_s: float = 0.0
    # Actions run after the crop, to put the page back for the next shot.
    after: tuple[tuple[str, str], ...] = ()
    # Why this frame carries no in-frame demo mark. REQUIRED when `requires` is
    # empty: a shot with neither is a shot whose provenance nobody argued about.
    no_marker_reason: str = ""
    notes: str = ""


def _shots() -> tuple[Shot, ...]:
    return (
        Shot(
            name="01-forecast-timeline",
            title="Forecast timeline and triage ranking, under the demo-model banner",
            caption=(
                "The demo app after scoring the bundled synthetic capture: the provenance "
                "banner, the run's four metrics, the per-window forecast timeline against "
                "the alert threshold, and the host triage table. Every number is the DEMO "
                "model's and is not comparable to any published figure."
            ),
            top=("alert", "provenance-banner"),
            bottom=("header", "3 ·"),
            requires=("provenance-banner", "threshold-metric-label", "metrics-mark"),
            expect_img=1,
            forbid_text=("No alerts at this operating point.",),
            notes=(
                "Cropped from the banner rather than from the section-2 header on "
                "purpose: this is the frame most likely to be lifted into a slide, so "
                "the disclosure is inside it."
            ),
        ),
        Shot(
            name="02-host-explanation",
            title="Per-host explanation in named features",
            caption=(
                "Section 3 of the demo app: the top contributing NAMED features behind one "
                "host's alert (never embedding dimensions), the windows the evidence came "
                "from, and the flagged flows. The attributions explain the DEMO model's "
                "decision about invented traffic."
            ),
            top=("header", "3 ·"),
            bottom=("header", "4 ·"),
            requires=("explanation-mark",),
            expect_text=("Top contributing features",),
        ),
        Shot(
            name="03-ledger-verified",
            title="Audit ledger — chain verifies",
            caption=(
                "Section 5 of the demo app: the hash-chained forecast ledger for this run, "
                "verifying, with its anchor checkpoint. The record count is the number of "
                "alerts the DEMO model raised on the bundled synthetic capture, so it is a "
                "demo figure like every other number in these images; what the frame shows "
                "about the LEDGER (that a chain of that length verifies, and the command "
                "that re-verifies it) is a property of ledger/, not of the model."
            ),
            top=("header", "5 ·"),
            bottom=("header", "6 ·"),
            expect_text=("Chain verifies yes", panels.LEDGER_VERIFY_CMD),
            no_marker_reason=(
                "The app renders no demo mark in this section, and this script will not "
                "draw one into the pixels: an overlay the app did not render is a "
                "fabricated screenshot. Provenance for this frame therefore travels in "
                "the caption, the manifest row and docs/img/screenshots/README.md — "
                "weaker than a banner in frame, and stated as such."
            ),
        ),
        Shot(
            name="04-network-graph-3d",
            title="3D network attack graph",
            caption=(
                "Section 7 of the demo app: the host graph the TGN encoder operates on — "
                "nodes are devices, edges are flows, edges leaving an alerting host glow "
                "red. Node colour is the DEMO model's score on synthetic traffic, not a "
                "calibrated probability."
            ),
            top=("header", "7 ·"),
            bottom=("header", "8 ·"),
            requires=("graph-mark",),
            expect_canvas=1,
            nonblank_selector=".js-plotly-plot canvas",
            notes=(
                "The non-blank check is on the canvas rect, not on the whole crop: the "
                "caption and controls around it would keep a crop colourful while the "
                "WebGL surface under them was empty."
            ),
        ),
        Shot(
            name="05-kstep-forecast-curve",
            title="k-step forecast risk curve, behind its caveat",
            caption=(
                "Section 8 of the demo app: the k-step risk curve for one host, the "
                "per-horizon evidence table, and the caveat that is rendered BEFORE the "
                "chart — there is no supported forward-forecast operating point, and the "
                "AUROC figures in that caveat belong to the evaluated k-step heads, not to "
                "the demo model that drew this curve."
            ),
            top=("header", "8 ·"),
            bottom=None,
            requires=("kstep-mark",),
            expect_img=1,
            expect_text=("Read this before the curve",),
        ),
        Shot(
            name="06-demo-provenance-banner",
            title="Demo-provenance disclosure, with the engine's own record unfolded",
            caption=(
                "The disclosure the app puts above every number on the page, with the fold "
                "opened: what the demo model is, why it exists, and the engine's own record "
                "of the lane it loaded. This is the frame that says what the other frames "
                "are pictures of."
            ),
            top=("alert", "provenance-banner"),
            bottom=("header", "2 ·"),
            requires=("provenance-banner", "threshold-metric-label", "metrics-mark"),
            actions=(("expander", panels.DEMO_DETAILS_LABEL),),
            after=(("expander", panels.DEMO_DETAILS_LABEL),),
            settle_s=10.0,
            expect_text=(plain(panels.DEMO_MODEL_WHAT)[:60],),
        ),
        Shot(
            name="07-ledger-tampered",
            title="Audit ledger — tamper detected",
            caption=(
                "The same ledger panel after the demo's 'Tamper with record 0' button edits "
                "one record in place: the chain stops verifying and the panel names the "
                "record it broke at. Tamper-evidence is a property of ledger/, exercised "
                "here on a DEMO run's chain."
            ),
            top=("header", "5 ·"),
            bottom=("header", "6 ·"),
            actions=(("button", "Tamper with record 0"),),
            expect_text=("TAMPER DETECTED at record 0", "Chain verifies NO"),
            # The verified frame's own metric line. Its ABSENCE is what makes the
            # tamper frame a different state rather than the same panel with a red
            # box added, so it is checked from both directions.
            forbid_text=("Chain verifies yes",),
            no_marker_reason=(
                "Same as 03-ledger-verified: no demo mark is rendered in this section and "
                "none is painted in. The caption carries it."
            ),
            notes=(
                "Captured last. It mutates the run's ledger file, and every earlier frame "
                "would have to be re-taken after it."
            ),
        ),
    )


SHOTS: tuple[Shot, ...] = _shots()


# ------------------------------------------------------------------- plumbing


def find_edge() -> Path:
    """The same headless Edge scripts/build_architecture_pdf.py prints with.

    Imported from that module rather than re-listing the install paths: one
    definition of "where Edge is" means a machine where the PDF builds is a
    machine where the screenshots capture, and neither can quietly stop agreeing
    with the other. Loaded by file path so `scripts/` does not join sys.path for
    everything that imports this module (the same technique tests/_stubs.py uses
    for scripts/fetch_artifacts.py).
    """
    builder = REPO / "scripts" / "build_architecture_pdf.py"
    if not builder.exists():
        raise SystemExit(
            f"{builder} is missing — it owns the Edge lookup this script reuses. "
            "Restore it, or this script has no browser."
        )
    spec = importlib.util.spec_from_file_location("_sih26_pdf_builder", builder)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    return module.find_edge()


def free_port() -> int:
    """A port the OS says is free right now.

    Not a fixed port: two agents (or a leftover browser from an aborted run)
    holding 8501 is how this script would otherwise attach to SOMEONE ELSE'S
    page and photograph it. Measured while developing this script — a stale
    debug port produced exactly that, a connection that answered and then died.
    """
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def kill_tree(proc: subprocess.Popen | None, label: str) -> None:
    """Kill a process AND its children.

    Edge forks a browser process plus one renderer per site; terminating the
    launcher leaves the renderers alive holding the debug port and the profile
    directory. `taskkill /T` is the only thing on Windows that takes the tree.
    """
    if proc is None or proc.poll() is not None:
        return
    subprocess.run(["taskkill", "/PID", str(proc.pid), "/T", "/F"],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
    try:
        proc.wait(timeout=20)
    except subprocess.TimeoutExpired:
        print(f"   ! {label} (pid {proc.pid}) did not exit after taskkill /T /F")


def published_lane_present(cfg: dict) -> tuple[bool, list[str]]:
    """(is there anything in the published artifacts dir, what is in it).

    "Anything", not "a complete bundle", because a HALF-written published lane is
    the case that actually bites: `engine/predict.py` refuses to fall back to the
    demo model when the published directory exists but is incomplete — correctly,
    since a published artifact that went missing must not silently become a demo
    run. Measured on this machine while writing this script, with a training run
    concurrently filling `artifacts/`:

        The engine has not been trained on this machine yet ... the published
        artifact lane artifacts is INCOMPLETE: it holds ['window_scaler.pkl'] but
        no engine_threshold.json. Refusing to fall back to a demo model.

    So a screenshot run can be blocked by a directory it must not touch.
    """
    art = resolve_path(cfg["paths"]["artifacts_dir"])
    if not art.is_dir():
        return False, []
    contents = sorted(p.name for p in art.iterdir())
    return bool(contents), contents


def isolated_run_root(cfg: dict) -> Path:
    """A copy of this checkout with no published artifacts directory in it.

    WHY A COPY. The demo lane is reachable only when the published lane is
    absent — that is `engine/predict.py`'s rule and it is the right one. On a
    machine that has published weights, or is in the middle of writing them, the
    app will not produce the page these screenshots are of. The two ways to fix
    that are to move `artifacts/` aside or to run from somewhere it does not
    exist, and the first one is destructive: on this machine `artifacts/` was
    being written by another process at the time, and moving it would have broken
    that run. So the code is copied and the copy is what serves the page.

    A COPY, NOT A JUNCTION: `configs/loader.py` computes `REPO_ROOT` with
    `Path(__file__).resolve()`, and `resolve()` follows a Windows junction back
    to its target — a junction farm would have resolved straight back to the real
    checkout, published artifacts and all.

    The copy is code only (ISOLATION_EXCLUDES), it is thrown away when the run
    succeeds, and the manifest records that it was used, so no reader has to
    guess where these images came from.
    """
    root = Path(tempfile.mkdtemp(prefix="sih26-shot-root-")) / REPO.name
    # The DEMO lane is excluded too, and rebuilt inside the copy by
    # `ensure_demo_artifacts`. A demo lane on disk can be STALE against the code
    # it is about to be photographed with, and a stale one does not fail politely:
    # measured here, a run that had captured all seven frames an hour earlier came
    # back with the app showing
    #
    #     The pipeline failed (ValueError) X has 29 features, but StandardScaler
    #     is expecting 30 features as input.
    #
    # because `configs/data.yaml`'s role-feature set had changed underneath it
    # (net24_bucket is under review — data/windows.py). Fitting the lane from the
    # bundled capture at capture time costs seconds and makes the page a picture
    # of THIS checkout rather than of whatever was last fitted on this machine.
    ignore = shutil.ignore_patterns(*ISOLATION_EXCLUDES, cfg["demo"]["artifacts_dir"])
    started = time.monotonic()
    shutil.copytree(REPO, root, ignore=ignore, symlinks=False)
    art = root / Path(cfg["paths"]["artifacts_dir"])
    if art.exists():                      # a nested or oddly-named artifacts dir
        shutil.rmtree(art, ignore_errors=True)
    if art.exists():
        raise SystemExit(
            f"could not remove {art} from the isolated run root, so the copy would "
            "resolve the published lane exactly as the real checkout does. Nothing "
            "was captured.")
    size = sum(p.stat().st_size for p in root.rglob("*") if p.is_file())
    print(f"-> isolated run root: {root} ({size / 1e6:.1f} MB, "
          f"{time.monotonic() - started:.1f}s, no {cfg['paths']['artifacts_dir']}/)")
    return root


def demo_lane_files(cfg: dict, root: Path) -> tuple[Path, list[str]]:
    """(demo artifacts dir under `root`, the file names a screenshot run needs).

    The k-step heads are in the list because shot 05 photographs the k-step
    panel: a lane missing them renders an empty-state box, which would be
    captured as though it were the product. The horizons come from
    configs/data.yaml rather than being written out here, so adding a horizon
    does not leave this list quietly checking the old set.
    """
    demo = cfg["demo"]
    prefix = demo["model_prefix"]
    horizons = cfg["engine"]["forecast_horizons"]
    names = [f"{prefix}engine_model.json", f"{prefix}engine_model_flow.json"]
    for k in horizons:
        names += [f"{prefix}engine_model_k{k}.json", f"{prefix}engine_model_flow_k{k}.json"]
    names += ["window_scaler.pkl", "engine_threshold.json", "weights.sha256"]
    return (root / Path(demo["artifacts_dir"])).resolve(), names


def ensure_demo_artifacts(cfg: dict, python: str, root: Path) -> dict:
    """Build the demo lane if it is not already on disk. Returns a manifest dict.

    Run as a SUBPROCESS, never in-process: scripts/bootstrap_demo_artifacts.py
    pins OMP_NUM_THREADS so its weights are byte-stable, and that pin only binds
    in an interpreter that has not yet imported xgboost. This process imports
    app.panels (numpy, pandas) but a future edit could easily pull xgboost in,
    and the failure would be silent — a lane recording a thread count it did not
    use. A fresh interpreter cannot have that bug.
    """
    lane_dir, names = demo_lane_files(cfg, root)
    bootstrap = root / BOOTSTRAP_RELATIVE
    missing = [n for n in names if not (lane_dir / n).exists()]
    if not missing:
        print(f"-> demo lane already present at {lane_dir} ({len(names)} files)")
        return {"bootstrapped": False, "dir": str(lane_dir), "files": names}
    print(f"-> demo lane incomplete at {lane_dir} (missing {', '.join(missing)})")
    print(f"   running {BOOTSTRAP_RELATIVE.as_posix()} …")
    started = time.monotonic()
    completed = subprocess.run([python, str(bootstrap)], cwd=str(root), check=False)
    if completed.returncode != 0:
        raise SystemExit(
            f"{bootstrap} exited {completed.returncode}. Without the demo lane the app "
            "cannot score anything, so there is nothing to photograph. Its output is "
            "above; fix that first."
        )
    still_missing = [n for n in names if not (lane_dir / n).exists()]
    if still_missing:
        raise SystemExit(
            f"{bootstrap} reported success but {lane_dir} still lacks "
            f"{', '.join(still_missing)}. Refusing to photograph a half-built lane."
        )
    print(f"   demo lane built in {time.monotonic() - started:.1f}s")
    return {"bootstrapped": True, "dir": str(lane_dir), "files": names}


class Streamlit:
    """`streamlit run app/streamlit_app.py`, on a free port, polled until it answers."""

    def __init__(self, python: str, port: int, root: Path) -> None:
        self.python, self.port, self.root = python, port, root
        self.proc: subprocess.Popen | None = None
        self.log = Path(tempfile.mkdtemp(prefix="sih26-shot-app-")) / "streamlit.log"

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def __enter__(self) -> "Streamlit":
        env = dict(os.environ)
        # The app reaches ledger/ledger.py, which refuses to construct without a
        # key (F36). A capture run is not a security context and the key is not
        # persisted anywhere a reader could mistake for a secret; setdefault so
        # an operator running with the real key keeps it.
        env.setdefault("SIH26_LEDGER_KEY", "screenshot-capture-key-not-a-secret")
        # `self.root`, never REPO: on an isolated run the app must import the
        # copy's `configs` (whose REPO_ROOT has no published artifacts dir), and
        # a PYTHONPATH still pointing at the real checkout is exactly how it
        # would import the real one instead and refuse to serve the demo lane.
        env["PYTHONPATH"] = str(self.root) + os.pathsep + env.get("PYTHONPATH", "")
        handle = open(self.log, "w", encoding="utf-8", errors="replace")
        self.proc = subprocess.Popen(
            [self.python, "-m", "streamlit", "run", str(self.root / APP_RELATIVE),
             "--server.port", str(self.port), "--server.address", "127.0.0.1",
             "--server.headless", "true", "--browser.gatherUsageStats", "false",
             "--server.fileWatcherType", "none", "--logger.level", "error"],
            cwd=str(self.root), env=env, stdout=handle, stderr=subprocess.STDOUT)
        deadline = time.monotonic() + HEALTH_TIMEOUT_S
        while time.monotonic() < deadline:
            if self.proc.poll() is not None:
                raise SystemExit(
                    f"streamlit exited {self.proc.returncode} before answering. Log:\n"
                    + self.log.read_text(encoding="utf-8", errors="replace")[-4000:])
            try:
                with urllib.request.urlopen(f"{self.url}/_stcore/health", timeout=3) as r:
                    if r.read().strip() == b"ok":
                        print(f"-> streamlit healthy on {self.url}")
                        return self
            except (urllib.error.URLError, OSError):
                time.sleep(0.5)
        raise SystemExit(
            f"streamlit did not answer {self.url}/_stcore/health within "
            f"{HEALTH_TIMEOUT_S:.0f}s. Log:\n"
            + self.log.read_text(encoding="utf-8", errors="replace")[-4000:])

    def __exit__(self, *exc) -> None:
        kill_tree(self.proc, "streamlit")


class Browser:
    """Headless Edge with its DevTools port open, and a CDP session on its page."""

    def __init__(self, edge: Path, port: int) -> None:
        self.edge, self.port = edge, port
        self.proc: subprocess.Popen | None = None
        self.profile = Path(tempfile.mkdtemp(prefix="sih26-shot-edge-"))
        self.log = self.profile / "edge.log"
        self.ws = None
        self._next_id = 0
        self.viewport_height = 0

    def __enter__(self) -> "Browser":
        handle = open(self.log, "w", encoding="utf-8", errors="replace")
        self.proc = subprocess.Popen([
            str(self.edge), "--headless=new", "--hide-scrollbars",
            "--no-first-run", "--no-default-browser-check",
            # The 3D graph is WebGL. Headless Edge has no GPU here, so ANGLE is
            # pointed at the software rasteriser; without this the plotly canvas
            # comes out blank and shot 04's non-blank check fails.
            "--use-angle=swiftshader", "--enable-unsafe-swiftshader",
            # A headless window has no visible surface, so Chromium treats the
            # renderer as occluded and throttles its compositor — and
            # `Page.captureScreenshot` then waits for a frame that is being
            # produced a few times a minute. That is what the wild shutter
            # variance measured here looked like: the same 1500x294 crop took
            # 0.1 s on one run and 77.7 s on another, and one frame never
            # returned inside 900 s. These four flags turn the throttling off.
            "--disable-background-timer-throttling",
            "--disable-backgrounding-occluded-windows",
            "--disable-renderer-backgrounding",
            "--disable-features=CalculateNativeWinOcclusion",
            f"--remote-debugging-port={self.port}",
            f"--user-data-dir={self.profile}",
            f"--window-size={VIEWPORT_WIDTH},1000",
            "about:blank",
        ], stdout=handle, stderr=subprocess.STDOUT)
        ws_url = None
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline and ws_url is None:
            if self.proc.poll() is not None:
                raise SystemExit(
                    f"Edge exited {self.proc.returncode} at startup. Log:\n"
                    + self.log.read_text(encoding="utf-8", errors="replace")[-3000:])
            try:
                with urllib.request.urlopen(
                        f"http://127.0.0.1:{self.port}/json/list", timeout=3) as r:
                    pages = [t for t in json.load(r) if t.get("type") == "page"]
                if pages:
                    ws_url = pages[0]["webSocketDebuggerUrl"]
            except (urllib.error.URLError, OSError, ValueError):
                time.sleep(0.4)
        if ws_url is None:
            raise SystemExit(
                f"Edge never published a DevTools page target on port {self.port}. Log:\n"
                + self.log.read_text(encoding="utf-8", errors="replace")[-3000:])
        from websockets.sync.client import connect  # pinned via streamlit

        self.ws = connect(ws_url, max_size=512 * 1024 * 1024, open_timeout=30)
        self.call("Page.enable")
        self.call("Runtime.enable")
        print(f"-> headless Edge attached ({ws_url.rsplit('/', 1)[-1][:12]}…)")
        return self

    def __exit__(self, *exc) -> None:
        try:
            if self.ws is not None:
                self.ws.close()
        except Exception:
            pass
        kill_tree(self.proc, "edge")

    # ---------------------------------------------------------------- CDP
    def call(self, method: str, params: dict | None = None,
             timeout: float = CDP_TIMEOUT_S) -> dict:
        self._next_id += 1
        message_id = self._next_id
        self.ws.send(json.dumps({"id": message_id, "method": method,
                                 "params": params or {}}))
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                raw = self.ws.recv(timeout=max(1.0, deadline - time.monotonic()))
            except TimeoutError:
                # websockets raises the BUILTIN TimeoutError from recv. Caught and
                # re-raised as CDPTimeout below, so a stalled screenshot is
                # retryable instead of killing the run with a websockets
                # traceback — which is exactly what it did before this line.
                break
            message = json.loads(raw)
            if message.get("id") == message_id:
                if "error" in message:
                    raise SystemExit(f"CDP {method} failed: {message['error']}")
                return message.get("result", {})
        raise CDPTimeout(f"CDP {method} did not answer within {timeout:.0f}s")

    def capture_clip(self, rect: dict, shot_name: str) -> dict:
        """Screenshot `rect`, forcing a new frame and retrying if it stalls.

        `Page.captureScreenshot` waits for a compositor frame that covers the
        region. On a headless, GPU-less machine under load, a region that has not
        been rastered recently can wait indefinitely: measured here, the same
        1500x294 crop returned in 0.1 s on one run and 199.6 s on another, and
        two different frames — the k-step panel when the whole page was one tall
        viewport, the WebGL graph when it had just been scrolled into a short one
        — never returned inside 900 s at all.

        `fromSurface: false` is NOT the fix, though it looks like one: measured,
        it returns quickly and it both IGNORES `clip` (a 1500x852 request came
        back as the full 1500x1800 viewport) and produces a near-empty image (61
        distinct colours against 2,294 for the same frame captured properly).
        That is a blank screenshot that answers fast, which is worse than a slow
        one. `assert_written_size` and the colour floors exist because of it.

        So: short attempts, and between them make the page produce a frame — a
        one-pixel scroll of the region's own scroll container, and an opacity
        nudge that guarantees a paint even when nothing scrolls.
        """
        params = {"format": "png", "captureBeyondViewport": False,
                  "clip": {**rect, "scale": 1}}
        deadline = time.monotonic() + SCREENSHOT_TIMEOUT_S
        attempt = 0
        while True:
            attempt += 1
            budget = min(SCREENSHOT_ATTEMPT_S, deadline - time.monotonic())
            if budget <= 1:
                raise SystemExit(
                    f"[{shot_name}] Page.captureScreenshot never returned a frame "
                    f"for {rect} within {SCREENSHOT_TIMEOUT_S:.0f}s across {attempt - 1} "
                    "attempts, each followed by a forced repaint. Nothing was written. "
                    "The browser is not producing compositor frames for this region — "
                    "on a loaded machine, retry when it is quieter.")
            try:
                return self.call("Page.captureScreenshot", params, timeout=budget)
            except CDPTimeout:
                print(f"   … no frame after {budget:.0f}s (attempt {attempt}); "
                      "forcing a repaint and retrying")
                try:
                    self.js(PRELUDE, timeout=30)
                    self.js(f"window.__sih26.forceFrame({int(rect['y'])})", timeout=30)
                except (CDPTimeout, SystemExit):
                    pass
                time.sleep(1.5)

    def js(self, expression: str, timeout: float = CDP_TIMEOUT_S):
        result = self.call("Runtime.evaluate", {
            "expression": expression, "returnByValue": True, "awaitPromise": True,
        }, timeout)
        if result.get("exceptionDetails"):
            raise SystemExit(
                "JavaScript raised in the page: "
                + str(result["exceptionDetails"].get("text"))
                + " || " + expression[:300])
        return result["result"].get("value")

    def navigate(self, url: str) -> None:
        self.call("Page.navigate", {"url": url})

    def set_viewport(self, height: int) -> bool:
        """Resize, unless the viewport is already that tall. Returns True if it moved.

        The no-op guard is not a micro-optimisation: every resize makes plotly
        re-lay-out and re-render its WebGL scene through the software rasteriser,
        and the next `Page.captureScreenshot` then waits for that frame.
        """
        wanted = max(600, int(height))
        if wanted == self.viewport_height:
            return False
        self.viewport_height = wanted
        self.call("Emulation.setDeviceMetricsOverride", {
            "width": VIEWPORT_WIDTH, "height": self.viewport_height,
            "deviceScaleFactor": DEVICE_SCALE, "mobile": False,
        })
        return True

    def scroll_region_into_view(self, anchor_js: str, pad: int, what: str) -> None:
        """Put `anchor_js`'s element `pad` px below the top of the scrollport.

        Streamlit's main column is its own scroll container — the window does not
        scroll at all, which is why `document.documentElement.scrollHeight` reads
        as the window height on a page thousands of pixels long. So this walks up
        to the nearest ancestor that actually scrolls and moves THAT, rather than
        calling window.scrollTo and silently doing nothing.
        """
        self.js(PRELUDE)
        moved = self.js(
            f"window.__sih26.scrollToTop({anchor_js}, {int(pad)})")
        if not moved:
            raise SystemExit(
                f"could not scroll {what} into view — its anchor was not on the page. "
                "Nothing was captured.")
        time.sleep(0.6)

    def force_reraster(self) -> None:
        """Scroll the page away from the current region and back.

        Called only after a TORN frame. `forceFrame` nudges the compositor into
        producing A frame, which is enough when the paint is merely late; it does
        not help when the tiles the compositor is reusing are themselves stale,
        because the nudge redraws from those same tiles. Moving the region out of
        the viewport discards them, so the way back is a full re-raster.
        """
        self.js(PRELUDE)
        self.js("""(() => {
            const el = document.querySelector('[data-testid="stAppViewContainer"]')
                    || document.body;
            const sc = window.__sih26.scrollParent(el.firstElementChild || el)
                    || document.scrollingElement;
            if (!sc) return false;
            const was = sc.scrollTop;
            sc.scrollTop = Math.max(0, was - window.innerHeight * 1.5);
            void document.body.offsetHeight;
            sc.scrollTop = was;
            void document.body.offsetHeight;
            return true;
        })()""")
        time.sleep(1.5)

    def wait_for(self, expression: str, what: str, timeout: float) -> float:
        started = time.monotonic()
        while time.monotonic() - started < timeout:
            if self.js(expression):
                return time.monotonic() - started
            time.sleep(0.5)
        raise SystemExit(f"timed out after {timeout:.0f}s waiting for {what}")

    def wait_idle(self, timeout: float = IDLE_TIMEOUT_S) -> float:
        """Wait until Streamlit's status widget has been absent for IDLE_SETTLE_S.

        A single absence is not idle: a click can produce two reruns back to
        back (the widget's own rerun, then `st.rerun()`), and the gap between
        them looks exactly like the end of the run.
        """
        probe = "!!document.querySelector('[data-testid=\"stStatusWidget\"]')"
        started = time.monotonic()
        while time.monotonic() - started < timeout:
            if not self.js(probe):
                time.sleep(IDLE_SETTLE_S)
                if not self.js(probe):
                    return time.monotonic() - started
            time.sleep(0.8)
        raise SystemExit(
            f"the app never went idle within {timeout:.0f}s — its status widget was "
            "still showing. Nothing was captured.")


# ------------------------------------------------------------------ page work

# Injected before every query. Kept in one place so a shot spec stays a
# declaration; `window.__sih26` is re-defined each time because a Streamlit rerun
# can replace the whole DOM but never reloads the page.
PRELUDE = r"""
window.__sih26 = {
  headerStartingWith(prefix) {
    return Array.from(document.querySelectorAll('h1,h2,h3'))
      .find(h => h.innerText.trim().startsWith(prefix)) || null;
  },
  alertContaining(text) {
    const nodes = Array.from(document.querySelectorAll(
      '[data-testid="stAlert"],[data-testid="stAlertContainer"]'));
    // Outermost first: querySelectorAll is document order, and stAlert wraps
    // stAlertContainer, so the wrapper is found before the thing it wraps.
    return nodes.find(n => n.innerText.replace(/\s+/g, ' ').includes(text)) || null;
  },
  buttonContaining(text) {
    return Array.from(document.querySelectorAll('button'))
      .find(b => b.innerText.includes(text)) || null;
  },
  expanderContaining(text) {
    return Array.from(document.querySelectorAll('summary,[data-testid="stExpander"] summary'))
      .find(s => s.innerText.includes(text)) || null;
  },
  contentBottom() {
    let bottom = 0;
    for (const el of document.querySelectorAll('[data-testid]')) {
      const r = el.getBoundingClientRect();
      if (r.height > 0 && r.bottom > bottom) bottom = r.bottom;
    }
    return Math.ceil(bottom);
  },
  scrollParent(el) {
    let n = el.parentElement;
    while (n) {
      const s = getComputedStyle(n);
      if (/(auto|scroll)/.test(s.overflowY) && n.scrollHeight > n.clientHeight + 2) return n;
      n = n.parentElement;
    }
    return null;
  },
  forceFrame(y) {
    // Make the compositor produce a frame covering this region: nudge whatever
    // scrolls (one pixel down and back, so nothing actually moves), and change a
    // paint-only property so a repaint is unavoidable even when nothing scrolls.
    const at = document.elementFromPoint(40, Math.max(2, Math.min(y + 4, window.innerHeight - 2)));
    const sc = at ? window.__sih26.scrollParent(at) : null;
    if (sc) { sc.scrollTop += 1; sc.scrollTop -= 1; }
    document.body.style.opacity = '0.999';
    void document.body.offsetHeight;
    document.body.style.opacity = '';
    void document.body.offsetHeight;
    return true;
  },
  scrollToTop(el, pad) {
    if (!el) return false;
    el.scrollIntoView({block: 'start', inline: 'nearest', behavior: 'instant'});
    const sc = window.__sih26.scrollParent(el);
    // scrollIntoView is not enough on its own, and the difference is visible in
    // the output. Streamlit gives its HEADINGS a scroll-margin, so an h2 lands
    // below the app's fixed toolbar — but an alert box has no such margin and
    // lands at y=0, UNDER the toolbar, where the crop either includes a strip of
    // toolbar or starts below the box's first line. (Measured: the provenance
    // frame lost the first line of its headline that way.) So the element is
    // placed explicitly: `pad` below whatever the toolbar's bottom edge is.
    const header = document.querySelector('[data-testid="stHeader"]');
    const floorY = header ? header.getBoundingClientRect().bottom : 0;
    const delta = (floorY + pad) - el.getBoundingClientRect().top;
    if (delta) {
      if (sc) sc.scrollTop = Math.max(0, sc.scrollTop - delta);
      else window.scrollBy(0, -delta);
    }
    return true;
  },
  // "In the crop" means VISIBLE in the crop, not "touching" it. The looser
  // version shipped a frame here: the tamper panel's red box overlapped the
  // bottom edge by a few pixels, the expect_text check passed on it, and the
  // published picture cut it off. 80 % of the element's own height has to be
  // inside.
  mostlyInside(r, rect) {
    if (r.height < 1 || r.width < 1) return false;
    if (r.right <= rect.x || r.left >= rect.x + rect.width) return false;
    const overlap = Math.min(r.bottom, rect.y + rect.height) - Math.max(r.top, rect.y);
    return overlap >= Math.min(r.height * 0.8, rect.height);
  },
  // The crop for a section: from the top anchor down to the BOTTOM of the last
  // element that belongs to it, not down to the next header's top. Streamlit's
  // headings carry 75 px of their own box and the gap between sections is not
  // constant, so "next header minus a pad" cut real content off the bottom of
  // two frames before this existed.
  regionRect(top, bottom, pad, width) {
    if (!top) return {error: 'top anchor not found'};
    const t = top.getBoundingClientRect();
    const header = document.querySelector('[data-testid="stHeader"]');
    // The app's toolbar is painted over the top of the viewport, so a crop that
    // starts above it captures the toolbar instead of the page.
    const floorY = header ? Math.ceil(header.getBoundingClientRect().bottom) : 0;
    const limit = bottom ? bottom.getBoundingClientRect().top : window.innerHeight;
    let end = t.bottom;
    for (const el of document.querySelectorAll(
        '[data-testid="stElementContainer"],[data-testid="stHorizontalBlock"]')) {
      const r = el.getBoundingClientRect();
      if (r.height < 2) continue;
      if (r.top < t.top - 1 || r.top >= limit - 1) continue;
      if (r.bottom > end) end = r.bottom;
    }
    const y = Math.max(floorY, Math.floor(t.top - pad));
    const bottomY = Math.min(Math.ceil(end + pad), Math.floor(limit), window.innerHeight);
    return {x: 0, y: y, width: width, height: bottomY - y};
  },
  textIn(rect) {
    const parts = [];
    for (const el of document.querySelectorAll(
        // stCaptionContainer is separate from stMarkdownContainer and is where
        // every `st.caption` lives — DEMO_METRICS_MARK, DEMO_EXPLANATION_MARK and
        // DEMO_GRAPH_MARK are all captions, so leaving it out made three of the
        // page's demo marks invisible to this check.
        '[data-testid="stMarkdownContainer"],[data-testid="stCaptionContainer"],' +
        '[data-testid="stMetric"],[data-testid="stAlertContainer"],' +
        '[data-testid="stHeading"],[data-testid="stCode"],pre,summary,label,button')) {
      if (!window.__sih26.mostlyInside(el.getBoundingClientRect(), rect)) continue;
      parts.push(el.innerText);
    }
    return parts.join('\n');
  },
  countIn(rect, selector) {
    let n = 0;
    for (const el of document.querySelectorAll(selector)) {
      if (window.__sih26.mostlyInside(el.getBoundingClientRect(), rect)) n += 1;
    }
    return n;
  },
  rectOf(selector, rect) {
    for (const el of document.querySelectorAll(selector)) {
      const r = el.getBoundingClientRect();
      if (r.width < 2 || r.height < 2) continue;
      if (!window.__sih26.mostlyInside(r, rect)) continue;
      return {x: r.x, y: r.y, width: r.width, height: r.height};
    }
    return null;
  }
};
'ready'
"""


def anchor_expression(anchor: tuple[str, str]) -> str:
    kind, value = anchor
    if kind == "header":
        return f"window.__sih26.headerStartingWith({json.dumps(value)})"
    if kind == "alert":
        return f"window.__sih26.alertContaining({json.dumps(plain(MARKERS[value])[:80])})"
    raise SystemExit(f"unknown anchor kind {kind!r} in a Shot spec")


REGION_PAD = 14


def region_rect(browser: Browser, shot: Shot) -> dict:
    """Scroll the shot's region to the top of the viewport and return its rect.

    A missing anchor is fatal. The alternative — falling back to the whole page,
    or to a zero rect — is how a renamed section header would produce a
    plausible-looking picture of the wrong thing.

    Coordinates: the page's scrolling happens INSIDE Streamlit's main column, so
    the document itself never scrolls and `getBoundingClientRect()` values are
    also the page coordinates `Page.captureScreenshot`'s `clip` wants. That is an
    accident of this app's layout, so the result is bounds-checked against the
    viewport below rather than trusted.
    """
    browser.scroll_region_into_view(
        anchor_expression(shot.top), REGION_PAD, f"[{shot.name}] {shot.top!r}")
    browser.js(PRELUDE)
    top = anchor_expression(shot.top)
    bottom = "null" if shot.bottom is None else anchor_expression(shot.bottom)
    rect = browser.js(f"""(() => {{
        const top = {top};
        const bottom = {bottom};
        if ({json.dumps(shot.bottom is not None)} && !bottom)
            return {{error: 'bottom anchor not found'}};
        return window.__sih26.regionRect(top, bottom, {REGION_PAD}, {VIEWPORT_WIDTH});
    }})()""")
    if rect is None or "error" in rect:
        raise SystemExit(
            f"[{shot.name}] could not place the crop: "
            f"{(rect or {}).get('error', 'no rect returned')}. Anchors were "
            f"top={shot.top!r} bottom={shot.bottom!r} — a section of the app was "
            "renamed, removed or never rendered. Nothing was written.")
    if rect["height"] < 80:
        raise SystemExit(
            f"[{shot.name}] the crop came out {rect['height']} px tall between "
            f"{shot.top!r} and {shot.bottom!r}. That is an empty or collapsed section, "
            "not a screenshot.")
    # `captureBeyondViewport` is off (it re-lays-out the page and moves the
    # plotly canvas), so a clip that runs past the bottom of the viewport comes
    # back as blank pixels. Say so here rather than letting the colour check
    # report a mysterious flat rectangle later.
    if rect["y"] + rect["height"] > browser.viewport_height:
        raise SystemExit(
            f"[{shot.name}] the region is {rect['height']} px tall and ends at "
            f"y={rect['y'] + rect['height']}, past the {browser.viewport_height} px "
            f"capture viewport. This section of the app has grown taller than one "
            f"screenful: raise CAPTURE_VIEWPORT_HEIGHT (now "
            f"{CAPTURE_VIEWPORT_HEIGHT}) or split the shot. It is NOT trimmed to fit "
            "— a crop that silently loses its bottom half is the picture nobody "
            "notices is wrong.")
    return rect


def do_action(browser: Browser, kind: str, value: str, shot_name: str) -> None:
    """Click something, then wait for the app to settle."""
    browser.js(PRELUDE)
    if kind == "button":
        target = f"window.__sih26.buttonContaining({json.dumps(value)})"
    elif kind == "expander":
        target = f"window.__sih26.expanderContaining({json.dumps(value)})"
    else:
        raise SystemExit(f"unknown action kind {kind!r}")
    clicked = browser.js(f"(() => {{ const el = {target}; "
                         f"if (!el) return false; el.click(); return true; }})()")
    if not clicked:
        raise SystemExit(
            f"[{shot_name}] no {kind} matching {value!r} on the page. The app's "
            "controls changed; this script would otherwise capture the state before "
            "the click and label it as the state after.")
    time.sleep(1.0)
    if kind == "button":          # a button reruns the script; an expander does not
        browser.wait_idle()
    time.sleep(PAINT_SETTLE_S if kind == "button" else 1.0)


def assert_demo_lane_page(browser: Browser) -> None:
    """Refuse to photograph anything but the demo lane.

    `docs/img/screenshots/README.md` and every caption this script writes say
    these are demo-model images. On a machine that HAS the published artifacts
    the same run would produce real-model pictures filed under that claim, which
    is the project's named failure mode with the sign flipped. So the run stops
    rather than mislabelling its output.
    """
    browser.js(PRELUDE)
    found = browser.js(
        f"!!window.__sih26.alertContaining("
        f"{json.dumps(plain(panels.DEMO_MODEL_HEADLINE)[:80])})")
    if not found:
        # What the page DOES say is printed, because "no demo box" has two very
        # different causes and the message must not guess between them: the
        # published artifacts being present (the case this guard exists for), and
        # the run having failed before the engine returned, which stops the page
        # at an error card. Both leave the box absent.
        page = " ".join((browser.js("document.body.innerText") or "").split())
        raise SystemExit(
            "the app did not render the demo-provenance box, so this run is NOT a "
            "confirmed demo-lane run. Every caption and the README in "
            "docs/img/screenshots/ state that these images come from the demo model, "
            "so nothing was written.\nEither the published artifacts are present under "
            "configs/data.yaml paths.artifacts_dir (capture from a checkout whose "
            "artifacts/ is absent), or the run failed before the engine returned — "
            "a demo lane fitted before a change to the feature set fails with a "
            "StandardScaler feature-count mismatch, and is fixed by deleting the "
            "demo artifacts directory so this script refits it.\n"
            f"WHAT THE PAGE SHOWS:\n{page[:1200]}")


def page_facts(browser: Browser) -> dict:
    """The metric row and ledger row, read off the rendered page.

    Recorded in the manifest as `demo_run_facts`. These are the DEMO model's
    numbers; they are here so that a reader can tell which run an image came
    from, never as a result.
    """
    browser.js(PRELUDE)
    metrics = browser.js(
        """Array.from(document.querySelectorAll('[data-testid="stMetric"]'))
             .map(m => m.innerText.replace(/\\n+/g, ' = ').trim())""")
    return {"metric_row": metrics}


# ------------------------------------------------------------------- checking


def image_colour_count(path: Path, box: tuple[int, int, int, int] | None = None) -> int:
    """How many distinct colours a PNG (or a sub-rect of it) contains.

    A blank capture — the headless-WebGL failure mode, or a crop that landed on
    empty page — is a flat rectangle. Counting colours is the cheapest check that
    a picture has a picture in it.
    """
    from PIL import Image

    with Image.open(path) as im:
        im = im.convert("RGB")
        if box is not None:
            im = im.crop(box)
        colours = im.getcolors(maxcolors=1 << 22)
    return len(colours) if colours is not None else (1 << 22)


# A frame is TORN when the compositor painted the same band of content more than
# once — the region scrolled or changed height, and stale tiles were reused for
# part of the surface. Both thresholds must be exceeded together.
#
# THESE NUMBERS ARE MEASURED, NOT CHOSEN. `longest_repeated_band` over every
# frame this script has written, healthy and torn (rows, distinct rows, offset):
#
#     HEALTHY (the seven frames now in docs/img/screenshots/)
#       01-forecast-timeline          42 rows,   1 distinct, offset 558
#       02-host-explanation           23 rows,   1 distinct, offset  58
#       03-ledger-verified            24 rows,   1 distinct, offset  58
#       04-network-graph-3d          113 rows,   1 distinct, offset  24
#       05-kstep-forecast-curve       35 rows,   1 distinct, offset 892
#       06-demo-provenance-banner     25 rows,   1 distinct, offset 118
#       07-ledger-tampered            31 rows,   1 distinct, offset 144
#
#     TORN (both refused; neither is in the tree)
#       04-network-graph-3d          559 rows, 121 distinct, offset 306
#       05-kstep-forecast-curve      429 rows, 236 distinct, offset 865
#
# WHICH FLOOR IS ACTUALLY LOAD-BEARING: the distinct one. Every healthy frame's
# longest repeat is a run of IDENTICAL rows — flat page background, which repeats
# everywhere and means nothing — so all seven measure 1 distinct against a floor
# of 8, while the two torn frames measure 121 and 236. The row floor is the
# weaker of the two and is NOT where the margin lives: the healthy 3D-graph frame
# runs 113 px of flat dark background behind its scene, which is a hair under
# 120. That is fine because the two floors are required TOGETHER (`is_torn`) and
# that band has 1 distinct row, but it is the reason the row count alone must
# never be used as the test. 120 px is kept as "taller than about four lines of
# text", not as a margin.
TEAR_MIN_BAND_ROWS = 120
TEAR_MIN_BAND_DISTINCT = 8


def longest_repeated_band(path: Path) -> tuple[int, int, int]:
    """(band height, distinct row patterns in it, offset) of the worst repeat.

    WHY A PIXEL CHECK EXISTS AT ALL. Every other assertion in this file is made
    against the DOM, and a torn frame is invisible to all of them: the document
    is correct and only the PAINT is wrong. `04-network-graph-3d.png` shipped
    from this script with its heading and captions rendered three times and no 3D
    graph at all, and it passed the demo-mark check (the caption was in the
    text), the chart/canvas counts (the DOM had a canvas in the rect), the
    written-size check, the page-stayed-still check, the whole-image colour floor
    (1,276 colours — it is a picture of text) AND the canvas colour floor (1,275
    — because that floor crops the PNG at the canvas's DOM rect, which in a torn
    frame lands on a duplicate of the heading band instead of on the canvas). It
    was found by looking at the picture, which is exactly the audit this
    repository cannot rely on.

    So: hash each row of pixels, and find the longest run of consecutive rows
    that appears again, verbatim, at some other offset. Content painted twice
    produces a long run with many different row patterns in it; flat background
    produces a long run with one.

    WHAT THIS DOES NOT CATCH, stated rather than left to be discovered:
    - a tear shorter than TEAR_MIN_BAND_ROWS, or one whose two copies are not
      byte-identical (a partial overlap, or a repaint with different
      antialiasing). It detects whole-tile duplication, which is the failure
      observed here — not tearing in general;
    - a frame that is simply of the WRONG STATE, or of last week's UI. Nothing
      in a PNG can say that; the DOM checks and the README's procedural rule
      cover it.

    AND HOW IT CAN OVER-FIRE: a table holding eight or more consecutive
    byte-identical rows repeats at its own row pitch and can clear both floors.
    No frame captured so far comes near it (the worst healthy band is 113 px of
    flat background, at 1 distinct row against a floor of 8), and the failure
    direction is the safe one — the capture
    refuses to write and says at what offset the band repeated, which for this
    case is a table row pitch rather than a section height. Loosening a floor to
    accommodate a real table is a decision to be made against a measurement, not
    pre-emptively.
    """
    from PIL import Image

    with Image.open(path) as im:
        im = im.convert("RGB")
        width, height = im.size
        raw = im.tobytes()
    stride = width * 3
    rows = [hashlib.blake2b(raw[i * stride:(i + 1) * stride], digest_size=8).digest()
            for i in range(height)]
    best = (0, 0, 0)
    # Offsets below 24 px are glyph-height coincidences between adjacent lines of
    # text, not a duplicated region.
    for offset in range(24, height):
        run = 0
        seen: set[bytes] = set()
        for i in range(height - offset):
            if rows[i] == rows[i + offset]:
                run += 1
                seen.add(rows[i])
                if run > best[0]:
                    best = (run, len(seen), offset)
            else:
                run = 0
                seen = set()
    return best


def is_torn(band: tuple[int, int, int]) -> bool:
    """Both floors, together. Either alone has a benign explanation."""
    return band[0] >= TEAR_MIN_BAND_ROWS and band[1] >= TEAR_MIN_BAND_DISTINCT


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


@dataclass
class Failure:
    shot: str
    reason: str


class PageMoved(RuntimeError):
    """The page scrolled or re-rendered between measuring a crop and taking it."""


class TornFrame(RuntimeError):
    """The written PNG contains a band of content the compositor painted twice."""


MAX_RETAKES = 3


def capture_shot(browser: Browser, shot: Shot, out_dir: Path,
                 problems: list[Failure], allow_unmarked: bool) -> dict | None:
    """Drive the app to one state and photograph it, retaking if the page moves.

    THE RETAKE IS NOT DEFENSIVE PROGRAMMING; it is a defect this script shipped
    once. Every check on a frame — which demo marks are inside it, which strings
    prove the state, how many charts it contains — is computed from the DOM at
    the measured rect, and the shutter can come tens of seconds later on this
    machine. Measured: the tamper frame was validated at the ledger section, the
    capture stalled and was retried 90 s later, and in between Streamlit
    restored its scroll position, so the file that landed was a correct-sized
    crop of the WRONG PART OF THE PAGE — the benchmark section under a caption
    saying "audit ledger", every check green. `_attempt_shot` re-reads the
    region's text after the shutter and raises PageMoved if it is not the text it
    checked, which is the only way to bind the pixels to the assertions.

    The actions are performed ONCE, outside the loop: clicking "Tamper with
    record 0" twice would tamper with a second record.
    """
    print(f"-> [{shot.name}] {shot.title}")
    for kind, value in shot.actions:
        do_action(browser, kind, value, shot.name)
    last = ""
    for attempt in range(1, MAX_RETAKES + 1):
        try:
            return _attempt_shot(browser, shot, out_dir, problems, allow_unmarked,
                                 attempt)
        except PageMoved as moved:
            last = str(moved)
            print(f"   … {moved} (attempt {attempt}/{MAX_RETAKES}); retaking")
            time.sleep(2.0)
        except TornFrame as torn:
            last = str(torn)
            print(f"   … {torn} (attempt {attempt}/{MAX_RETAKES}); "
                  "re-rastering the region and retaking")
            # A retake at the same scroll position reuses the same stale tiles, so
            # the region is scrolled out of the viewport and back before the next
            # attempt: that discards its tiles and forces a full re-raster.
            # `_attempt_shot` also waits longer on each successive attempt.
            try:
                browser.force_reraster()
            except (CDPTimeout, SystemExit):
                pass
            time.sleep(3.0 * attempt)
    raise SystemExit(
        f"[{shot.name}] {MAX_RETAKES} attempts, and the frame was still not a "
        f"faithful picture of the page it was checked against — last failure: {last}. "
        "Nothing was written. A frame whose pixels do not correspond to the DOM that "
        "was checked is exactly the picture this script exists not to publish; on a "
        "loaded machine (software WebGL rasterisation) the fix is usually to retry "
        "when it is quieter.\nThis is fatal even under --allow-unmarked: that flag "
        "records a frame whose PROVENANCE could not be confirmed, and a torn frame is "
        "not a documented shortcoming but a picture of a rendering failure. To capture "
        f"the other frames meanwhile, use --only with the shots you can get (this one "
        f"is {shot.name}).")


def _attempt_shot(browser: Browser, shot: Shot, out_dir: Path,
                  problems: list[Failure], allow_unmarked: bool,
                  attempt: int = 1) -> dict | None:
    """One measure-check-shoot-verify cycle.

    Raises PageMoved or TornFrame to ask for another. `attempt` only lengthens the
    settle: a region that composited a stale band once needs longer to finish
    painting, and a retake that waits exactly as long as the attempt that just
    failed is a retake with no reason to succeed.
    """
    rect = region_rect(browser, shot)
    settle = shot.settle_s or (PAINT_SETTLE_S * 2 if shot.expect_canvas else 0.0)
    if attempt > 1:
        settle = max(settle, PAINT_SETTLE_S) * attempt
    if settle:
        # A WebGL scene that has just been scrolled into view has to be rastered
        # in software here, and a section whose height just changed has to be
        # re-rastered entirely. `Page.captureScreenshot` blocks on that frame, or
        # worse, composites half of it. Forcing a paint and waiting is cheaper
        # than a retake and is the only thing that fixes a torn frame.
        browser.js(PRELUDE)
        browser.js(f"window.__sih26.forceFrame({int(rect['y'])})")
        time.sleep(settle)
    text = " ".join((browser.js(
        f"window.__sih26.textIn({json.dumps(rect)})") or "").split())
    n_img = browser.js(
        f"window.__sih26.countIn({json.dumps(rect)}, "
        f"'[data-testid=\"stImage\"] img')")
    n_canvas = browser.js(
        f"window.__sih26.countIn({json.dumps(rect)}, '.js-plotly-plot canvas')")

    found_markers = [key for key in shot.requires if plain(MARKERS[key]) in text]
    missing_markers = [key for key in shot.requires if key not in found_markers]

    complaints: list[str] = []
    for key in missing_markers:
        wanted = plain(MARKERS[key])
        matched = longest_common_prefix(wanted, text)
        complaints.append(
            f"the crop does not contain the demo mark {key!r}, which this shot "
            f"declares must travel inside it (matched the first {matched} of "
            f"{len(wanted)} characters; it breaks at ...{wanted[max(0, matched - 30):matched + 40]!r})")
    for needle in shot.expect_text:
        if " ".join(needle.split()) not in text:
            complaints.append(f"expected text {needle!r} is not in the crop")
    for needle in shot.forbid_text:
        if " ".join(needle.split()) in text:
            complaints.append(f"forbidden text {needle!r} IS in the crop "
                              "— the app is in the wrong state")
    if n_img < shot.expect_img:
        complaints.append(f"expected >= {shot.expect_img} chart image(s), found {n_img}")
    if n_canvas < shot.expect_canvas:
        complaints.append(f"expected >= {shot.expect_canvas} plotly canvas(es), "
                          f"found {n_canvas}")

    inner_box = None
    if shot.nonblank_selector:
        inner = browser.js(
            f"window.__sih26.rectOf({json.dumps(shot.nonblank_selector)}, "
            f"{json.dumps(rect)})")
        if inner is None:
            complaints.append(f"no element matching {shot.nonblank_selector!r} "
                              "inside the crop to check for blankness")
        else:
            inner_box = tuple(int(round(v * DEVICE_SCALE)) for v in (
                inner["x"] - rect["x"], inner["y"] - rect["y"],
                inner["x"] - rect["x"] + inner["width"],
                inner["y"] - rect["y"] + inner["height"]))

    if complaints and not allow_unmarked:
        raise SystemExit(
            f"[{shot.name}] " + "; ".join(complaints)
            + ".\nNothing was written for this shot. Re-run with --allow-unmarked to "
            "record the failure and continue, but do NOT publish a frame whose "
            "provenance this check could not confirm.")

    path = out_dir / f"{shot.name}.png"
    shutter = time.monotonic()
    shot_result = browser.capture_clip(rect, shot.name)
    path.write_bytes(base64.b64decode(shot_result["data"]))
    shutter = time.monotonic() - shutter

    # The requested clip, in device pixels, is what the file must be. Checked
    # because a capture mode that silently ignores `clip` exists and was tried
    # here: `fromSurface: false` answered fast, returned the whole viewport
    # instead of the 1500x852 region asked for, and nothing else in this script
    # would have noticed a picture of the wrong rectangle.
    from PIL import Image  # a build-time check, imported where it is used

    expected = (round(rect["width"] * DEVICE_SCALE), round(rect["height"] * DEVICE_SCALE))
    with Image.open(path) as probe:
        written = probe.size
    if written != expected:
        path.unlink(missing_ok=True)
        raise SystemExit(
            f"[{shot.name}] asked for a {expected[0]}x{expected[1]} px crop and the "
            f"browser returned {written[0]}x{written[1]}. The clip was not honoured, "
            "so the file is a picture of some other rectangle. It was deleted.")

    # Did the page stay still? Every assertion above was made against the text at
    # this rect BEFORE the shutter; if the same rect now reads differently, the
    # pixels on disk are of something else and the checks certify nothing.
    text_after = " ".join((browser.js(
        f"window.__sih26.textIn({json.dumps(rect)})") or "").split())
    if text_after != text:
        path.unlink(missing_ok=True)
        raise PageMoved(
            f"the region at {rect['y']}..{rect['y'] + rect['height']} read "
            f"{len(text)} characters when it was checked and {len(text_after)} after "
            "the shutter")

    # Did the compositor paint the page, or paint part of it twice? Checked on
    # the BYTES, after every DOM assertion has passed, because a torn frame
    # passes all of them — see longest_repeated_band.
    band = longest_repeated_band(path)
    if is_torn(band):
        path.unlink(missing_ok=True)
        raise TornFrame(
            f"the frame is TORN: a {band[0]} px band carrying {band[1]} distinct "
            f"pixel rows is painted twice, {band[2]} px apart. The DOM was correct "
            "and the paint was not, so this file would have been a picture of the "
            "same section repeated with its real content missing")

    colours = image_colour_count(path)
    if colours < shot.min_colors:
        complaints.append(f"the written PNG has {colours} distinct colours "
                          f"(< {shot.min_colors}) — it is a blank rectangle")
    inner_colours = None
    if inner_box is not None:
        inner_colours = image_colour_count(path, inner_box)
        if inner_colours < shot.min_canvas_colors:
            complaints.append(
                f"the {shot.nonblank_selector} region of the written PNG has "
                f"{inner_colours} distinct colours (< {shot.min_canvas_colors}) — it "
                "rendered blank. On headless Edge this is a WebGL/swiftshader failure.")

    if complaints:
        if not allow_unmarked:
            path.unlink(missing_ok=True)
            raise SystemExit(f"[{shot.name}] " + "; ".join(complaints)
                             + ".\nThe file was deleted rather than published.")
        problems.append(Failure(shot.name, "; ".join(complaints)))
        print(f"   ! recorded as FAILED: {'; '.join(complaints)}")

    for kind, value in shot.after:
        do_action(browser, kind, value, shot.name)

    width, height = written
    print(f"   wrote {path.name} ({width}x{height}, {path.stat().st_size:,} B, "
          f"{colours} colours, {shutter:.1f}s shutter, marks in frame: "
          f"{', '.join(found_markers) or 'none'})")
    return {
        "file": path.name,
        "title": shot.title,
        "caption": shot.caption,
        "sha256": sha256_of(path),
        "bytes": path.stat().st_size,
        "pixels": [width, height],
        "region": {"top_anchor": list(shot.top),
                   "bottom_anchor": (list(shot.bottom) if shot.bottom else None),
                   "css_rect": rect},
        "provenance_in_frame": bool(found_markers) and not missing_markers,
        "provenance_markers_in_frame": found_markers,
        "no_marker_reason": shot.no_marker_reason,
        "checks": {"chart_images": n_img, "plotly_canvases": n_canvas,
                   "distinct_colours": colours,
                   "canvas_distinct_colours": inner_colours,
                   # The tear measurement, recorded so the margin is visible
                   # rather than merely asserted: the floors are
                   # TEAR_MIN_BAND_ROWS / TEAR_MIN_BAND_DISTINCT.
                   "longest_repeated_band_rows": band[0],
                   "longest_repeated_band_distinct_rows": band[1],
                   "longest_repeated_band_offset_px": band[2]},
        "notes": shot.notes,
        "failed_checks": [f.reason for f in problems if f.shot == shot.name],
    }


# ----------------------------------------------------------------------- main


def provenance_statement() -> str:
    """The one paragraph every consumer of this directory should copy."""
    return (
        "Every image in this directory was captured against the DEMO model, fitted by "
        f"scripts/bootstrap_demo_artifacts.py from {panels.DEMO_CAPTURE_PATH} — a small "
        "hand-authored synthetic capture bundled with this repository. The model was "
        "fitted on that capture and its alert thresholds were chosen on the same rows, "
        "so it has memorised it. No probability, alert count, threshold, host ranking or "
        "feature attribution visible in these images reproduces, corroborates or "
        f"approximates any figure this project publishes, and none of them saw "
        f"{panels.PUBLISHED_DATASET}: they are not comparable with those figures — not "
        "a weaker version of them. They show what the software does, not how well it "
        "does it."
    )


def main(argv: list[str] | None = None) -> int:
    # Declared first: Python requires the `global` before any read of the name in
    # this scope, and `--device-scale`'s default reads it.
    global DEVICE_SCALE

    parser = argparse.ArgumentParser(
        description="Capture PNGs of the offline demo app into docs/img/screenshots/.")
    parser.add_argument("--out", default=str(OUT_DIR_DEFAULT),
                        help="output directory (default: docs/img/screenshots)")
    parser.add_argument("--python", default=sys.executable,
                        help="interpreter used for the Streamlit server and the "
                             "demo-lane bootstrap (default: this one)")
    parser.add_argument("--only", default="", help="comma-separated shot names to capture")
    parser.add_argument("--allow-unmarked", action="store_true",
                        help="record a failed provenance/content check and carry on "
                             "instead of aborting. The frame is still written and is "
                             "marked failed in the manifest — do not publish it.")
    parser.add_argument(
        "--isolate", choices=("auto", "always", "never"), default="auto",
        help="serve the app from a throwaway COPY of this checkout that has no "
             "published artifacts directory. 'auto' (default) does that only when "
             "one exists here, because the app will not serve the demo lane while "
             "it does — and moving it aside is destructive when another process is "
             "writing it. See isolated_run_root().")
    parser.add_argument(
        "--device-scale", type=float, default=DEVICE_SCALE,
        help=f"device pixels per CSS pixel (default {DEVICE_SCALE}). 2 is sharper "
             "and is several times slower to capture on a machine with no GPU — "
             "see the DEVICE_SCALE comment.")
    parser.add_argument("--list", action="store_true", help="list the shots and exit")
    args = parser.parse_args(argv)
    DEVICE_SCALE = args.device_scale

    if args.list:
        for shot in SHOTS:
            print(f"{shot.name:28s} {shot.title}")
        return 0

    wanted = [s.strip() for s in args.only.split(",") if s.strip()]
    unknown = [w for w in wanted if w not in {s.name for s in SHOTS}]
    if unknown:
        raise SystemExit(f"unknown shot name(s): {', '.join(unknown)}")
    shots = tuple(s for s in SHOTS if not wanted or s.name in wanted)

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    cfg = load_config("data")
    edge = find_edge()

    has_published, published_contents = published_lane_present(cfg)
    isolate = args.isolate == "always" or (args.isolate == "auto" and has_published)
    if has_published:
        print(f"-> {cfg['paths']['artifacts_dir']}/ exists here and holds "
              f"{published_contents}. The app will not serve the DEMO lane while it "
              "does, and these images are defined as demo-lane images.")
    run_root = isolated_run_root(cfg) if isolate else REPO
    if not isolate:
        print(f"-> serving the app from the checkout itself ({REPO})")

    lane = ensure_demo_artifacts(cfg, args.python, run_root)
    lane_dir = Path(lane["dir"])

    problems: list[Failure] = []
    rows: list[dict] = []
    started = time.monotonic()

    with Streamlit(args.python, free_port(), run_root) as app, \
            Browser(edge, free_port()) as browser:
        browser.set_viewport(CAPTURE_VIEWPORT_HEIGHT)
        browser.navigate(app.url)
        browser.wait_for(
            "Array.from(document.querySelectorAll('button')).some(b => b.innerText"
            f".includes({json.dumps(panels.DEMO_PCAP_LABEL)}))",
            "the app's input panel", 120)
        do_action(browser, "button", panels.DEMO_PCAP_LABEL, "startup")
        assert_demo_lane_page(browser)

        browser.set_viewport(CAPTURE_VIEWPORT_HEIGHT)
        time.sleep(PAINT_SETTLE_S)
        print(f"-> capture viewport {VIEWPORT_WIDTH}x{CAPTURE_VIEWPORT_HEIGHT} "
              f"at {DEVICE_SCALE}x (each shot scrolls its own region into it)")

        facts = page_facts(browser)
        for shot in shots:
            row = capture_shot(browser, shot, out_dir, problems, args.allow_unmarked)
            if row is not None:
                rows.append(row)

    # `--only` must not silently drop the rows for the frames it did not take:
    # the manifest is what tests/test_screenshots.py reads to decide whether a
    # committed PNG has documented provenance, so a one-shot re-capture that
    # rewrote the whole file would orphan every other image in the directory.
    kept: list[dict] = []
    if wanted:
        previous = out_dir / MANIFEST_NAME
        if previous.exists():
            old = json.loads(previous.read_text(encoding="utf-8"))
            taken = {r["file"] for r in rows}
            kept = [r for r in old.get("images", [])
                    if r["file"] not in taken and (out_dir / r["file"]).exists()]
            if kept:
                print(f"-> carried {len(kept)} existing manifest row(s) forward "
                      f"({', '.join(r['file'] for r in kept)})")
    rows = sorted(rows + kept, key=lambda r: r["file"])

    manifest = {
        "schema": 1,
        "generated_by": "scripts/capture_screenshots.py",
        "captured_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "app": APP_RELATIVE.as_posix(),
        "input": panels.DEMO_CAPTURE_PATH,
        "artifact_lane": "demo",
        "demo_lane_dir": cfg["demo"]["artifacts_dir"],
        "demo_lane_bootstrapped_by_this_run": lane["bootstrapped"],
        # Stated, not hidden: on a machine that has (or is writing) published
        # weights the app is served from a throwaway copy of this checkout with
        # no artifacts/ in it, because the app correctly refuses to serve the
        # demo lane otherwise. Same code, same demo weights, different root.
        "served_from": ("an isolated copy of this checkout with no "
                        f"{cfg['paths']['artifacts_dir']}/" if isolate
                        else "this checkout"),
        "published_artifacts_dir_on_capture_machine": published_contents,
        "demo_weights_sha256_file_digest": (
            sha256_of(lane_dir / "weights.sha256")
            if (lane_dir / "weights.sha256").exists() else None),
        "viewport": {"width": VIEWPORT_WIDTH, "height": CAPTURE_VIEWPORT_HEIGHT,
                     "device_scale_factor": DEVICE_SCALE},
        "provenance_statement": provenance_statement(),
        "demo_run_facts": facts,
        "images": rows,
        "failed_checks": [{"shot": f.shot, "reason": f.reason} for f in problems],
        "shots_declared": [s.name for s in SHOTS],
        "shots_captured": [r["file"].removesuffix(".png") for r in rows],
    }
    (out_dir / MANIFEST_NAME).write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    if isolate:
        if problems:
            print(f"-> isolated run root KEPT for inspection: {run_root}")
        else:
            shutil.rmtree(run_root.parent, ignore_errors=True)
            print("-> isolated run root removed")

    total = sum(r["bytes"] for r in rows)
    print(f"\n-> {len(rows)} image(s), {total:,} bytes, into {out_dir}")
    print(f"-> manifest: {(out_dir / MANIFEST_NAME)}")
    print(f"-> wall clock {time.monotonic() - started:.1f}s")
    if problems:
        print("\n!! FRAMES THAT FAILED THEIR OWN CHECKS — do not publish these:")
        for failure in problems:
            print(f"   {failure.shot}: {failure.reason}")
        return 1
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except CDPTimeout as exc:   # a browser that stopped answering, stated plainly
        raise SystemExit(f"the headless browser stopped answering: {exc}")
