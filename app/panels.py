"""Pure logic behind the Streamlit panels (M10) — importable and testable.

The UI module (app/streamlit_app.py) is a thin shell over these functions so the
demo's behaviour can be tested without a browser, and so `test_offline`
conditions (sockets blocked) exercise real code paths.

The operator-facing strings (button labels, the empty-state hint, the benchmark
caveat) and the figure palette live here rather than in the UI module, so a test
can pin them against the things they claim — a hint that names a button, a
caveat that quotes docs/limitations.md, a chart colour that matches the theme.
"""

from __future__ import annotations

import importlib.util
import json
import math
import re
import tomllib
from pathlib import Path

import numpy as np
import pandas as pd

from configs import load_config, resolve_path

# ------------------------------------------------------------------ UI strings

DEMO_PCAP_LABEL = "Demo: synthetic PCAP (full features)"
DEMO_CSV_LABEL = "Demo: sample CSV (flow only)"
BUTTON_LABELS = (DEMO_PCAP_LABEL, DEMO_CSV_LABEL)

# Every **bolded** span here must be a real button label. The enforcement is
# test_empty_state_names_a_button_the_app_really_renders, which compares them
# against the buttons AppTest actually rendered — comparing them against these
# same constants would only restate the f-string.
EMPTY_STATE_HINT = (
    f"Upload a flow CSV or a PCAP, or click **{DEMO_PCAP_LABEL}** "
    f"(or **{DEMO_CSV_LABEL}**) to begin."
)

# The benchmark card's population caveat. One constant, quoted verbatim from
# docs/limitations.md — test_app.py asserts every fragment in
# LIMITATIONS_QUOTES still appears in that document, so the two cannot drift.
LIMITATIONS_QUOTES = ("n = 2 sessions of one host", "~30 of ~450 hosts/day")
BENCHMARK_CAVEAT = (
    "**Population caveat** — the figures in this section are not population "
    "statistics. Episode capture and lead time rest on **n = 2 sessions of one "
    "host**, not a distribution, and benign traffic is subsampled (**~30 of ~450 "
    "hosts/day**, decision 001), so any alerts/day figure is a within-sample "
    "extrapolation. Full statement: `docs/limitations.md`."
)

# The engine hands TreeSHAP the SCALED matrix, so the per-feature `value` it
# returns is a z-score, not a byte count — a negative sent_bytes is the scale,
# not a bug. Name the column for what it is instead of implying raw units.
EXPLANATION_VALUE_COLUMN = "value (z-score)"
EXPLANATION_VALUE_CAVEAT = (
    f"`{EXPLANATION_VALUE_COLUMN}` is the feature standardised against the "
    "training mean and standard deviation — the scale the model and TreeSHAP "
    "operate on, which is why a byte count can read negative. The feature "
    "**names** are real named features, never embedding dimensions; only the "
    "units are standardised."
)

# What the benchmark table means for the thing actually running on this page.
# It used to describe the live scorer with the two-stage phrasing the audit
# retired after establishing that engine/predict.py holds exactly one load_model
# and one predict_proba: there is no second stage for anything to escalate to.
# The retired sentence is quoted in tier1_hardening_report.md and nowhere else --
# tests/test_docs_claims.py bans it by pattern, so writing it down here in order
# to retract it would break that guard on this file, which is the one surface it
# was not watching when the sentence survived here.
# The wording below mirrors README.md and docs/architecture.md deliberately, so a
# judge reading the page and a judge reading the docs get the same sentence.
#
# No feature COUNT is quoted. Both documents say "30", and that number could not
# be re-measured here (this checkout has no `artifacts/`), and CLAUDE.md is
# explicit that an unverified figure does not go in front of a judge. The claim
# that decides how to read the table is which model runs, not how wide it is.
DEPLOYED_MODEL_NOTE = (
    "Live scoring in this app is a **single XGBoost model** — one of two variants selected by "
    "input format (PCAP → the full feature model, CSV → the flow-only model). The **fused** row "
    "above is an **eval-side** model that does not run in the engine; engine-side fusion is "
    "roadmap. The RSSM world model failed its lead-time gate and is not shipped — see "
    "`docs/decisions/004`."
)

BENCHMARK_EMPTY_HINT = (
    "No benchmark results on this machine yet — `results/*.json` is gitignored "
    "(`.gitignore`), and CLAUDE.md requires the numbers in the README to be "
    "reproducible by `eval/ablation.py`, so a fresh clone starts empty and "
    "regenerates them. This panel reads those files and never hardcodes a figure, "
    "which is why it is blank rather than showing a placeholder. Each "
    "`eval.harness` run writes one `results/<model>.json`; the `fused` and "
    "`tgn*` rows consume the score dumps of their own members, so run those "
    "members first."
)
# engine.predict reports the frames its IPv4 parser skipped. Any non-zero count
# is stated; past this fraction it is a warning rather than a caption, because a
# largely unparsed capture makes "0 alerts" meaningless rather than reassuring.
UNPARSED_WARN_FRACTION = 0.01

# `engine.predict._coverage` returns `known: False` when the drop counters were
# lost (they ride on the packet table's `.attrs`, which pandas strips the moment
# that table is combined with one that has none). Unknown is not clean, and the
# page must not render it the way it renders a known zero: silence.
COVERAGE_UNKNOWN_TEXT = (
    "**It is not known what this capture dropped** — the run reports no frame-drop history "
    "(`unparsed_frames.known` is false; the counters ride on the packet table's `.attrs`, which "
    "pandas strips when tables are combined). So this page cannot tell a capture that parsed "
    "cleanly from one the IPv4 parser could not read at all, and **0 alerts here is not evidence "
    "of a quiet network.** The raw block is in `run_summary.json` beside the forecasts."
)
# The same silence from the other direction: a block this page cannot parse. It
# is stated rather than swallowed, because "we could not read the counters" and
# "nothing was dropped" must never render identically.
COVERAGE_UNREADABLE_TEXT = (
    "**The frame-coverage counters for this run could not be read** — `unparsed_frames` came back "
    "in a shape this page cannot interpret, so the number of skipped frames is unknown and "
    "**0 alerts here is not evidence of a quiet network.** The raw block is in `run_summary.json` "
    "beside the forecasts; read it there before drawing a conclusion from this page."
)

# Sections 3 and 4 both consume the host list section 2 builds, so ONE failure
# in section 2 empties BOTH — and an empty section under a live header reads on
# camera as a panel that broke. Each states which of the two reasons it is.
NO_HOSTS_EXPLAIN = (
    "No host crossed the alert threshold, so there is no alert to explain. This panel explains "
    "one alerting host at a time — it is empty because section 2 ranked nothing, not because it "
    "failed."
)
NO_HOSTS_WHATIF = (
    "No host crossed the alert threshold, so there is nothing to ablate. The what-if removes an "
    "alerting host and re-runs the forecast; with no alerts there is no before/after to show."
)
RANKING_FAILED_EXPLAIN = (
    "Section 2 failed above, so the host ranking this panel reads was never built. The error card "
    "in section 2 is the thing to fix — this panel is blocked by it, not independently broken."
)
RANKING_FAILED_WHATIF = (
    "Section 2 failed above, so there is no ranked host list to ablate. Fix the error card in "
    "section 2 and reload: the what-if re-runs the forecast without one host and needs that list "
    "to name it."
)

# engine.predict.HOSTS_PSEUDONYMISED is False on the deployed path: the hosts in
# the forecasts are the addresses an analyst has to act on, and only the LEDGER
# holds keyed pseudonyms (M9.2). The picker's label must say which it is showing.
HOST_SELECT_REAL = "Host (real address — only the ledger stores keyed pseudonyms)"
HOST_SELECT_PSEUDONYMISED = "Host (pseudonymised)"

BENCHMARK_EMPTY_COMMANDS = (
    "python -m eval.harness --model lr        # graded LR baseline -> the comparison card\n"
    "python -m eval.harness --model forecast  # per-horizon table (results/forecast.json)\n"
    "python scripts/make_ablation_table.py --budget 0.01"
)

# ------------------------------------------------- k-step forecast (PS deliverable 3)
# The panel this block feeds answers "what does this host look like over the next
# k windows". The project's own audit established what that answer is worth, and
# the caveat below is the load-bearing half of the panel, not decoration: at the
# shipped 1 % FPR budget the k-step head fires no episode at any reported horizon,
# and the oracle analysis showed that is a ranking limit rather than a threshold
# to retune. Every figure quoted here is pinned against docs/limitations.md by
# test_app.py::test_forecast_caveat_quotes_the_limitations_doc, so the panel
# cannot drift into claiming more than the document supports.

# Fragments quoted verbatim from docs/limitations.md, whitespace-normalised and
# with markdown emphasis stripped. Same mechanism as LIMITATIONS_QUOTES above.
FORECAST_LIMITATION_QUOTES = (
    "There is no supported forward-forecast horizon.",
    "test AUROC 0.844 at k=4, 0.842 at k=8",
    "0/2 episodes at k=1, 4 and 8 alike",
    "a ranking limit, not a calibration bug",
    "93–96 % identical to the nowcast target",
    "warning this system does claim comes from the horizon-0 classifier, not from forecasting"
    " ahead",
)

FORECAST_HEADER_CAVEAT = (
    "**Read this before the curve. There is no supported forward-forecast horizon.** The k-step "
    "head has a real but modest ranking signal — **test AUROC 0.844 at k=4, 0.842 at k=8** — but "
    "at the shipped 1 % FPR budget it fires **0/2 episodes at k=1, 4 and 8 alike**, and the "
    "oracle-threshold analysis shows that is **a ranking limit, not a calibration bug**: no "
    "threshold recovers it. So the curve below **orders** hosts by k-step risk. It does not "
    "predict that an attack will happen, and a rising line here is not evidence that one will. "
    "Two further reasons not to read it as prediction — the k-step target is **93–96 % identical "
    "to the nowcast target**, so ranking it well is close to ranking the present well; and the "
    "early **warning this system does claim comes from the horizon-0 classifier, not from "
    "forecasting ahead** — that is section 2 above, not this panel. Full statement: "
    "`docs/limitations.md`."
)

# Drawn INTO the axes, not beside them: a screenshot of the curve is what travels
# off this page, and it has to carry the caveat with it.
FORECAST_FIGURE_CAVEAT = (
    "ranking signal — no validated operating point: 0/2 episodes at k=1, 4 and 8 "
    "at the 1 % FPR budget"
)

FORECAST_CURVE_CAPTION = (
    "One row per horizon k for this host's **newest** source window; `seconds_ahead` is k × the "
    "window stride the engine reports. The threshold is that horizon's **own** 1 %-FPR operating "
    "point, so a crossing means the host ranks in the top 1 % of benign host-windows at that "
    "horizon — the same crossing that caught 0 of 2 real episodes in evaluation. **`stage` and "
    "`technique` describe the SOURCE window's observed pattern — the evidence behind the "
    "forecast — not a predicted future stage**: `engine.forecast` has no future features to "
    "infer one from, so they are the same for every k and this panel will not relabel them as a "
    "progression."
)
# The table's own heading. It used to read "predicted stage progression", which
# is what the panel was asked for and NOT what engine/forecast.py computes — the
# stage comes from the source window through the nowcast's own rules. Naming a
# column for the feature you wanted rather than the one you have is the exact
# failure this project keeps removing.
FORECAST_STAGE_TABLE_HEADING = (
    "**Evidence behind each horizon** — the source window's stage and technique, not a "
    "predicted future stage"
)

# The three ways this panel can legitimately have nothing to draw. They are kept
# apart because they have three different fixes, and because a panel that renders
# one empty box for all of them teaches a judge nothing.
FORECAST_MISSING_TEXT = (
    "**The k-step forecaster is not present in this checkout** — there is no `engine/forecast.py` "
    "to import, so this panel has nothing to read. It is a separate module from the horizon-0 "
    "engine that sections 2–4 run, which is why those still render. Nothing here is stubbed or "
    "simulated: an absent forecaster is shown as absent."
)
FORECAST_NO_ENTRYPOINT_TEXT = (
    "**`engine/forecast.py` is present but exposes no `forecast_file(input_path, out_dir, "
    "fpr_budget)`** — the entry point this panel is built against. Until it does there is nothing "
    "for the panel to call, and it will not invent a curve to fill the space."
)
FORECAST_NO_HORIZONS_TEXT = (
    "**The forecaster ran and reported no horizon with a persisted k-step model**, so there is no "
    "risk curve to draw. Each missing horizon's own reason is in the table below, verbatim from "
    "the engine — this panel does not substitute a horizon-0 score for a missing k."
)
FORECAST_NO_CURVE_TEXT = (
    "**The forecaster has a persisted horizon but returned no usable per-host risk curve for this "
    "input**, so there is nothing to plot. That is what the engine returned for this capture; it "
    "is not a panel that failed."
)

# The engine calls its output a probability. The project claims only a ranking,
# so the column says both rather than letting the header make the stronger claim
# (same device as EXPLANATION_VALUE_COLUMN).
KSTEP_SCORE_COLUMN = "probability (ranking score)"
# Not "alert": at this budget a crossing is not a validated alert, and a column
# headed `alert` would undo the caveat three lines above it.
KSTEP_ALERT_COLUMN = "crosses k-step threshold"

# A horizon's 1 %-FPR threshold sits on the model's raw score scale and can be
# ~1e-5 while the scores are ~1e-1. On one linear axis the threshold then lies on
# the x-axis and every point reads as a dramatic crossing. Past this ratio between
# the largest and smallest positive value on the chart the axis goes logarithmic,
# so the distance between score and threshold is legible rather than flattering.
# A presentation rule over values the engine supplies — not a model parameter.
CURVE_LOG_SCALE_RATIO = 100.0


# --------------------------------------------------------------- app config

APP_CONFIG = ".streamlit/config.toml"


def app_config() -> dict:
    """Parsed `.streamlit/config.toml`.

    Single source for the upload cap and the figure palette: Streamlit enforces
    the same file, so the server-side guard and the charts cannot disagree with
    what the page actually does.
    """
    path = resolve_path(APP_CONFIG)
    if not path.exists():
        return {}
    return tomllib.loads(path.read_text(encoding="utf-8"))


def theme_colors() -> dict:
    """Figure colours taken from the `[theme]` block of `.streamlit/config.toml`.

    The 3D graph and the timeline draw on the page background, so their text and
    accent colours must follow the configured theme rather than assume one. The
    fallbacks are Streamlit's own light-theme defaults, which is what the page
    renders as when the block is absent.
    """
    theme = app_config().get("theme", {})
    text = theme.get("textColor", "#31333f")
    return {
        "text": text,
        "background": theme.get("backgroundColor", "#ffffff"),
        "panel": theme.get("secondaryBackgroundColor", "#f0f2f6"),
        "accent": theme.get("linkColor", "#1a6faf"),
        "alert": theme.get("redColor", "#d62728"),
        "muted": theme.get("grayColor", "#808495"),
    }


def rgba(color: str, alpha: float) -> str:
    """`#rrggbb` + opacity -> a CSS rgba() string for Plotly line/marker colours."""
    h = color.lstrip("#")
    if len(h) == 3:
        h = "".join(c * 2 for c in h)
    r, g, b = (int(h[i:i + 2], 16) for i in (0, 2, 4))
    return f"rgba({r},{g},{b},{alpha})"


# -------------------------------------------------------------- input guards

class InputTooLarge(ValueError):
    """The input is past the app's cap.

    Raised before a byte is written to disk or parsed: the CSV path expands each
    flow into every window it overlaps, so an oversize upload can hang the live
    demo rather than fail fast.
    """


def max_upload_mb() -> int:
    """`server.maxUploadSize` from `.streamlit/config.toml` (Streamlit's own
    default of 200 MB when the option is absent — that is the cap in force)."""
    return int(app_config().get("server", {}).get("maxUploadSize", 200))


def check_upload_size(n_bytes: int, name: str = "input") -> None:
    cap = max_upload_mb()
    if n_bytes > cap * 1024 * 1024:
        raise InputTooLarge(
            f"`{name}` is {n_bytes / 1_048_576:.1f} MB; this demo accepts at most "
            f"{cap} MB (server.maxUploadSize in .streamlit/config.toml). Slice the "
            "capture first — `editcap -r big.pcap small.pcap 1 200000`, or keep the "
            "first N rows of a CSV — and upload the slice."
        )


_SAFE_NAME = re.compile(r"[^A-Za-z0-9._-]+")


def safe_upload_name(name: str, default: str = "upload.csv") -> str:
    """A file name safe to join onto the session directory.

    Streamlit does not sanitise `UploadedFile.name`; it can carry directory
    components. The SUFFIX is preserved because the engine selects the PCAP or
    CSV feature path from it.
    """
    stem = Path(str(name).replace("\\", "/")).name
    cleaned = _SAFE_NAME.sub("_", stem).lstrip(".")
    return cleaned or default


# ------------------------------------------------------------- failure cards

_REPO_ROOT = Path(__file__).resolve().parent.parent
_PATH_CHAR = r"[^\s'\"<>|,;)]"
# The repo root is matched literally, so its own spaces need no special handling.
_REPO_PREFIX = re.compile(
    r"[\\/]".join(re.escape(p) for p in str(_REPO_ROOT).replace("\\", "/").split("/"))
    + rf"(?:[\\/]({_PATH_CHAR}*))?",
    re.IGNORECASE,
)

# What replaces a path that names no file. Markdown-inert on purpose: angle
# brackets would be eaten as a tag by Streamlit's markdown renderer, and a bare
# ellipsis would not read as deliberate.
REDACTED_PATH = "[redacted path]"

# The three absolute roots that put a machine's layout — and, on a managed
# Windows laptop, the operator's real name — on a projector: a drive letter, a
# UNC share, a POSIX root.
#   - the lookbehind keeps the POSIX branch off a separator inside an
#     already-relative path ("artifacts/engine_model.json"),
#   - `/(?![/\s])` keeps it off `https://host/page` and off a bare "/" in prose,
#   - `\\{2,}` catches a UNC share, doubled separators included: OSError renders
#     the file name with repr(), so a Windows path arrives with every separator
#     doubled ("... : 'C:\\Users\\HP\\x.csv'").
_ABS_ROOT = re.compile(r"(?<![\w.\-/\\])(?:[A-Za-z]:[\\/]|\\{2,}(?=[^\s\\/])|/(?![/\s]))")

_SEPARATORS = "\\/"
# Characters that cannot be inside a path this function consumes. Quotes and
# angle brackets are how Python's own messages delimit a path; `,;` separate
# list items; `*?|` are illegal in Windows file names anyway. Parentheses are
# deliberately NOT here — `C:\Program Files (x86)\...` is a real directory.
_PATH_STOP = frozenset("'\"<>|,;*?\t\r\n\v\f")
# Sentence punctuation that ends up glued to a trailing file name ("… a.pcap.",
# "(see /x/a.pcap)"). Stripped only to TEST whether a component names a file;
# the punctuation itself is put back on the page.
_TRAILING_PUNCT = ".,;:!?)]}"
# A component names a FILE when it ends in a dot plus a short LETTER-led
# extension. Letter-led on purpose: a directory called `v1.2` must not be read
# as a file, because reading a directory as a file STOPS the scan early and
# leaves whatever followed it on screen.
_FILE_SUFFIX = re.compile(r"\.[A-Za-z][A-Za-z0-9_+-]{0,9}\Z")


def _names_a_file(component: str) -> bool:
    return bool(_FILE_SUFFIX.search(component.rstrip(_TRAILING_PUNCT)))


# How far ahead `_separator_ahead` may look. The scan runs once per SPACE inside
# a path component, so an unbounded one is quadratic in the line length: measured
# on this repo, a hostile 4 KB line took 0.14 s, 32 KB 8.8 s and 200 KB 342 s —
# and every one of those seconds is the Streamlit page frozen. No message this
# repo raises reaches that shape (quotes and commas are stop characters, and a
# real 39 KB pandas error redacts in 0.001 s), but an exception message carries
# attacker-influenced text in general, so the scan is bounded rather than trusted.
#
# The cap is past Windows' own MAX_PATH of 260, so no real path is truncated by
# it. Past the cap the answer is "no separator ahead", which ends the component at
# the space and hands the rest to _consume_absolute_path's directory branch: the
# whole remainder of the line is replaced by REDACTED_PATH. That is the coarse
# fallback, and it errs toward over-redaction — the safe direction (guarantee 4).
SEPARATOR_LOOKAHEAD_CHARS = 512

# Same membership test as `_PATH_STOP`, compiled: the bounded scan below runs in
# C rather than a Python character loop, which is what keeps the bounded cost of
# the pathological line in milliseconds instead of seconds.
_PATH_STOP_RE = re.compile("[" + re.escape("".join(sorted(_PATH_STOP))) + "]")


def _separator_ahead(text: str, start: int, sep: str) -> bool:
    """Is another separator of the SAME style still ahead on this line?

    This is what lets a space be part of a directory name: `John Smith Jr\\x` has
    a backslash ahead of it and continues, `b.json read/write failed` does not —
    a Windows path's separators are backslashes, and `read/write` is prose.

    The search is bounded to SEPARATOR_LOOKAHEAD_CHARS (see the constant for why
    and for what the bound costs). Within the window the answer is exact: True
    iff a separator appears before any `_PATH_STOP` character.
    """
    window = text[start:start + SEPARATOR_LOOKAHEAD_CHARS]
    at_sep = window.find(sep)
    if at_sep < 0:
        return False
    return _PATH_STOP_RE.search(window, 0, at_sep) is None


def _consume_absolute_path(text: str, start: int, sep: str) -> tuple[int, str]:
    """Scan one absolute path whose root ends at `start`; return (end, replacement).

    Components are read one at a time. A space inside a component is consumed
    only while the component does not yet name a file AND another same-style
    separator is still ahead — the two conditions that separate `John Smith Jr\\`
    from `a.pcap read/write`.

    What ends the scan is the SEPARATORS, not a file name: a component is
    followed by another only while a separator immediately follows it, so the
    scan ends at the first component that no separator follows. `_names_a_file`
    never halts it mid-path — in `C:\\Users\\john.smith\\secret\\capture.pcap`
    the component `john.smith` satisfies `_names_a_file`, and the scan correctly
    runs past it to `capture.pcap` because a separator follows. `_names_a_file`
    decides two other things: whether a SPACE ends the component it sits inside,
    and whether the FINAL component is returned as a file name or handed to the
    directory branch below.
    """
    i, n = start, len(text)
    last = ""
    while i < n:
        while i < n and text[i] in _SEPARATORS:  # a run of separators is one
            i += 1
        comp_start = i
        while i < n:
            c = text[i]
            if c in _SEPARATORS or c in _PATH_STOP:
                break
            if c == " " and (_names_a_file(text[comp_start:i])
                             or not _separator_ahead(text, i + 1, sep)):
                break
            i += 1
        comp = text[comp_start:i]
        if not comp:
            break
        last = comp
        if i < n and text[i] in _SEPARATORS:
            continue                             # a separator follows: a directory
        break                                    # nothing follows: end of the path
    if not last:
        # A bare root with nothing after it ("the drive C:\ is full"). It names
        # nothing, so replace the root alone and leave the sentence intact.
        return start, REDACTED_PATH
    if _names_a_file(last):
        return i, last          # the file name, with any punctuation glued to it
    # No file name in the path, so its last component is a DIRECTORY name — a
    # user name as often as not — and nothing marks where it ends. Take the rest
    # of the line (or the quote that closes it) and say a path was removed.
    while i < n and text[i] not in _PATH_STOP:
        i += 1
    return i, REDACTED_PATH


_TRAIN_CMD = "python -m engine.train_engine"
_NOT_TRAINED = "The engine has not been trained on this machine yet"

# Ordered: the first marker found in the message wins. The weight-digest rule
# must precede the artifact rules — its message names an artifact file too.
_FAILURE_RULES = (
    ("sha-256 mismatch", "Model weights do not match their recorded digests",
     "python scripts/verify_weights.py"),
    ("engine_threshold", _NOT_TRAINED, _TRAIN_CMD),
    ("engine_model", _NOT_TRAINED, _TRAIN_CMD),
    ("window_scaler", _NOT_TRAINED, _TRAIN_CMD),
    ("engine model persisted", _NOT_TRAINED, _TRAIN_CMD),
    ("no persisted threshold", _NOT_TRAINED, _TRAIN_CMD),
    ("lacks mapped column", "That CSV is not in the CIC-IDS-2018 flow schema",
     "python -c \"import yaml;print(yaml.safe_load(open('configs/data.yaml'))['schema'])\""),
    ("no 'label' column", "That CSV is not in the CIC-IDS-2018 flow schema",
     "python -c \"import yaml;print(yaml.safe_load(open('configs/data.yaml'))['schema'])\""),
    ("flow csv not found", "That input file is not on disk", ""),
    ("synthetic_demo.pcap", "The bundled demo capture has not been generated",
     "python -m capture.make_synthetic_demo"),
    ("codec can't decode", "That file is binary but was read as a CSV — rename it "
     "to .pcap (or .pcapng) so the packet path handles it", ""),
)


def redact_paths(text: str) -> str:
    """Rewrite absolute filesystem paths out of a message.

    A failure on a projector shows the presenter's home directory, the machine's
    layout and — on a managed Windows laptop — the operator's real name
    (`C:\\Users\\John Smith`, `OneDrive - Contoso Ltd`). Exactly what this
    guarantees, in the order the guarantees matter:

    1. **No absolute root survives.** A drive letter (`C:\\`, `C:/`), a UNC share
       (`\\\\server\\...`) and a POSIX `/` root are all removed, whatever their
       components contain. tests/test_app.py asserts this as an invariant over
       the whole corpus with its own pattern, not example by example.
    2. A path **under this repo** becomes repo-relative (`artifacts/engine_model.json`)
       — that is the part a judge can act on, and it names no one.
    3. Any other path that **names a file** collapses to that file name, however
       many spaces its directories carry, and any sentence punctuation glued to
       it stays: `C:\\Users\\John Smith Jr\\caps\\a.pcap.` -> `a.pcap.`
    4. Any other path that **does not name a file** — it ends at a directory — is
       replaced together with the rest of that line (or up to the quote that
       closes it) by REDACTED_PATH. Nothing marks where `C:\\Users\\John Smith`
       ends, and the safe direction of failure is to take too much: an
       over-redacted clause costs a sentence, an under-redacted one puts a name
       on the projector.
    5. Consumption **follows the separators**, and a space ends a component that
       already names a file. The scan reads one component at a time and continues
       only while a separator immediately follows; it ends at the first component
       that no separator follows. A file-naming component in the MIDDLE of a path
       does **not** stop it — in `C:\\Users\\john.smith\\secret\\capture.pcap`,
       `john.smith` names a file by this module's test and the scan still reaches
       `capture.pcap`, because a separator follows it. What the file test decides
       is (a) whether a SPACE ends the component it sits inside, which is why
       `C:\\a\\b.json read/write failed` keeps both `b.json` and `read/write`,
       and (b) whether the FINAL component is kept under guarantee 3 or
       over-redacted under guarantee 4.
    6. The scan is **bounded**: deciding (a) looks ahead at most
       SEPARATOR_LOOKAHEAD_CHARS characters, so a hostile message cannot make
       this function quadratic and freeze the page. Past the bound the component
       ends at the space and guarantee 4 takes the rest of the line.

    What it is not: a secrets filter, and not a rule-matching input. It shapes
    only what an operator SEES — `failure_card` matches its rules against the
    raw message, so redaction can be this aggressive without changing which card
    is shown.
    """
    inside = _REPO_PREFIX.sub(lambda m: (m.group(1) or ".").replace("\\", "/"), text)
    out: list[str] = []
    pos = 0
    while True:
        match = _ABS_ROOT.search(inside, pos)
        if match is None:
            break
        sep = "\\" if "\\" in match.group(0) else "/"
        end, replacement = _consume_absolute_path(inside, match.end(), sep)
        out.append(inside[pos:match.start()])
        out.append(replacement)
        pos = end
    out.append(inside[pos:])
    return "".join(out)


def failure_card(exc: BaseException) -> dict:
    """Map a failure onto `{title, detail, command}` for the app's error panel.

    Streamlit's default handler renders a raw traceback carrying absolute paths;
    every failure-prone call in the UI routes here instead. An unknown failure
    still gets a card — never a traceback — naming its exception type so the
    terminal log can be matched to what the judge saw.

    The rules match the RAW message and only `detail` is redacted. Redaction is
    deliberately aggressive (see redact_paths) and can remove the very marker a
    rule keys on — `...\\artifacts\\engine_threshold` has no file extension, so it
    is removed whole — and a card that lost its "run the trainer" command because
    the path was redacted would be a fix creating a new failure.
    """
    raw = str(exc)
    detail = redact_paths(raw) or type(exc).__name__

    if isinstance(exc, InputTooLarge):
        return {"title": "That file is too large for the live demo",
                "detail": detail, "command": ""}
    if isinstance(exc, ModuleNotFoundError):
        return {"title": f"A dependency is missing ({exc.name})", "detail": detail,
                "command": "pip install --no-index --find-links vendor -r requirements.txt"}
    if isinstance(exc, MemoryError):
        return {"title": "Ran out of memory on this input",
                "detail": "The input expanded past what this machine can hold. Slice "
                          "the capture and re-run.", "command": ""}

    low = raw.lower()
    for marker, title, command in _FAILURE_RULES:
        if marker in low:
            return {"title": title, "detail": detail, "command": command}

    return {"title": f"The pipeline failed ({type(exc).__name__})",
            "detail": detail, "command": ""}


def run_pipeline(input_path, out_dir, fpr_budget: float = 0.01) -> dict:
    """Full offline pipeline on one uploaded file (M10.1)."""
    from engine import predict

    return predict.predict_file(input_path, out_dir=out_dir, fpr_budget=fpr_budget)


def _as_int(value) -> int | None:
    """`int(value)`, or None when the engine handed us something that is not one."""
    try:
        return int(value)
    except (TypeError, ValueError, OverflowError):
        return None


def _as_fraction(value) -> float | None:
    """`float(value)` if it is a finite number, else None (NaN is not a fraction)."""
    try:
        out = float(value)
    except (TypeError, ValueError, OverflowError):
        return None
    return out if math.isfinite(out) else None


def _reason_breakdown(by_reason) -> str:
    """`` `ipv6`=812, `short_frame`=3 `` from the per-reason counts, defensively.

    Every count is coerced through _as_int: a reason whose value is not a number
    is reported as `?` rather than raising inside a format string.
    """
    if not isinstance(by_reason, dict) or not by_reason:
        return "reason not reported"
    parts = []
    for key, value in sorted(by_reason.items(), key=lambda kv: str(kv[0])):
        count = _as_int(value)
        if count is None:
            parts.append(f"`{key}`=?")
        elif count:
            parts.append(f"`{key}`={count:,}")
    return ", ".join(parts) or "reason not reported"


def coverage_note(result: dict) -> dict | None:
    """`{severity, text}` for frames the parser could not read, or None.

    `engine.predict._coverage` returns `unparsed_frames` =
    `{known, total, fraction, by_reason}`, and there are THREE states, not two.
    Frames the IPv4 parser skips (an IPv6 capture above all) produce no
    host-windows and therefore no alerts, and an unannotated "0 alerts" reads as
    safety — so a known non-zero count is stated, a known zero is genuinely
    silent, and an UNKNOWN drop history (`known: False`, counts None, because
    pandas strips the `.attrs` the counters ride on) is stated too. Unknown is
    not clean.

    Every coercion here is defensive. This function is deliberately exempt from
    the app's try/except wrapping (tests/test_app.py::UNGUARDED_PANEL_CALLS
    calls it a "pure reader of the result dict"), so an int() raising on a
    malformed block would surface as the Streamlit traceback the app's module
    docstring says is impossible. A block it cannot read becomes a warning that
    says so — never a swallowed None, which would be the same silence again.
    """
    cov = result.get("unparsed_frames")
    if not isinstance(cov, dict) or not cov:
        return None
    if cov.get("known") is False:
        return {"severity": "warning", "text": COVERAGE_UNKNOWN_TEXT}
    total = _as_int(cov.get("total"))
    frac = _as_fraction(cov.get("fraction"))
    if total is None or frac is None or not isinstance(cov.get("by_reason"), dict):
        return {"severity": "warning", "text": COVERAGE_UNREADABLE_TEXT}
    if not total:
        return None
    reasons = _reason_breakdown(cov.get("by_reason"))
    if frac >= 1.0:
        text = (
            f"**Nothing in this capture was parsed** — all {total:,} frames were skipped "
            f"({reasons}). The model saw no traffic at all, so **0 alerts here means "
            "nothing was seen, not that nothing happened.** The packet path reads IPv4 "
            "only; convert or re-capture in IPv4 before reading anything into this run."
        )
    else:
        text = (
            f"**{total:,} frames ({frac:.1%}) were not parsed** ({reasons}) and are absent "
            "from every figure on this page — the packet path reads IPv4 only."
        )
    return {"severity": "warning" if frac >= UNPARSED_WARN_FRACTION else "caption",
            "text": text}


def host_selector_label(result: dict) -> str:
    """Label for the host picker, honest about what the addresses on screen are.

    The picker used to claim "pseudonymised where a key is configured"; the
    engine reports `hosts_pseudonymised`, and on this path it is False.
    """
    return HOST_SELECT_PSEUDONYMISED if result.get("hosts_pseudonymised") else HOST_SELECT_REAL


def timeline_frame(result: dict, cfg: dict | None = None) -> pd.DataFrame:
    """Per-window max probability across hosts + the network-level score.

    CLAUDE.md fixes the network score as the MAX over host scores in a window.
    """
    cfg = cfg or load_config("data")
    rows = [
        {"window_start": f["window_start"], "host": f["host"],
         "probability": f["probability"], "stage": f["stage"]}
        for f in result["forecasts"]
    ]
    if not rows:
        return pd.DataFrame(columns=["window_start", "probability", "stage", "host"])
    df = pd.DataFrame(rows)
    idx = df.groupby("window_start")["probability"].idxmax()
    return df.loc[idx].sort_values("window_start").reset_index(drop=True)


def host_ranking(result: dict, top: int = 10) -> pd.DataFrame:
    """Hosts ranked by peak forecast probability (what the analyst triages)."""
    if not result["forecasts"]:
        return pd.DataFrame(columns=["host", "peak_probability", "alerts", "stage"])
    df = pd.DataFrame([
        {"host": f["host"], "probability": f["probability"], "stage": f["stage"]}
        for f in result["forecasts"]
    ])
    g = df.groupby("host").agg(
        peak_probability=("probability", "max"),
        alerts=("probability", "size"),
        stage=("stage", lambda s: s.mode().iloc[0]),
    ).reset_index()
    return g.sort_values("peak_probability", ascending=False).head(top).reset_index(drop=True)


def explanation_for(result: dict, host: str) -> dict | None:
    """The highest-probability alert for a host, with its named-feature
    explanation, technique and flagged flows (M10.3)."""
    hits = [f for f in result["forecasts"] if f["host"] == host]
    if not hits:
        return None
    return max(hits, key=lambda f: f["probability"])


def explanation_rows(exp: dict) -> list[dict]:
    """Top-feature rows for the explanation table.

    The `value` the engine returns is read off the SCALED matrix TreeSHAP was
    given, so the column is named as a z-score rather than presented as a raw
    feature value (see EXPLANATION_VALUE_CAVEAT).
    """
    return [
        {"feature": t["feature"],
         EXPLANATION_VALUE_COLUMN: round(float(t["value"]), 3),
         "contribution": round(float(t["contribution"]), 4)}
        for t in (exp.get("top_features") or [])
    ]


def what_if_remove_host(input_path, out_dir, host_to_remove: str, fpr_budget=0.01) -> dict:
    """M10.4 / M8.7: re-run the pipeline with one host ablated so the analyst can
    see that host's contribution.

    The ablation happens INSIDE the engine on the already-extracted features
    (predict_file(exclude_host=...)), so the input file is never re-parsed — a
    PCAP stays on the full-feature path instead of being (wrongly) read as a CSV,
    and the before/after curves share feature semantics."""
    from engine import predict

    after = predict.predict_file(
        input_path, out_dir=Path(out_dir) / "whatif",
        fpr_budget=fpr_budget, exclude_host=host_to_remove,
    )
    return {"removed_host": host_to_remove, "after": after}


def network_graph_layout(result: dict, max_nodes: int = 60, seed: int = 1337) -> dict:
    """3D force-directed layout of the host graph in result['graph'] (M10.8).

    Pure and offline: networkx computes the spring layout; the app renders it with
    Plotly. Nodes are ranked by risk (peak probability, then alerts, then flow
    degree) and trimmed to `max_nodes` for readability — never silently: the
    returned dict reports `shown`/`total`/`truncated` so the UI can say so.
    """
    import networkx as nx

    g = result.get("graph") or {"nodes": [], "edges": []}
    nodes = {n["ip"]: n for n in g["nodes"]}
    edges = g["edges"]

    degree: dict[str, int] = {}
    for e in edges:
        degree[e["src"]] = degree.get(e["src"], 0) + e["weight"]
        degree[e["dst"]] = degree.get(e["dst"], 0) + e["weight"]

    ranked = sorted(
        nodes.values(),
        key=lambda n: (n["peak_prob"], n["n_alerts"], degree.get(n["ip"], 0)),
        reverse=True,
    )
    keep = {n["ip"] for n in ranked[:max_nodes]}
    kept_edges = [e for e in edges if e["src"] in keep and e["dst"] in keep]

    G = nx.Graph()
    G.add_nodes_from(keep)
    for e in kept_edges:
        G.add_edge(e["src"], e["dst"])

    n = G.number_of_nodes()
    if n == 0:
        return {"nodes": [], "edges": [], "shown": 0, "total": len(nodes), "truncated": False}

    # Lay out by TOPOLOGY, not flow volume: weight=None so a heavy edge (e.g. a
    # 1300-flow scan) does not collapse its endpoints onto each other, and a
    # larger optimal distance k spreads a small graph so nodes stay legible.
    pos = nx.spring_layout(G, dim=3, seed=seed, weight=None,
                           k=(2.5 / (n ** 0.5)) if n > 1 else None, iterations=200)
    out_nodes = []
    for ip in keep:
        x, y, z = (float(c) for c in pos[ip])
        n = nodes[ip]
        out_nodes.append({
            "ip": ip, "x": x, "y": y, "z": z,
            "peak_prob": float(n["peak_prob"]), "n_alerts": int(n["n_alerts"]),
            "internal": n.get("internal"), "degree": int(degree.get(ip, 0)),
        })
    out_edges = []
    for e in kept_edges:
        a, b = pos[e["src"]], pos[e["dst"]]
        out_edges.append({
            "src": e["src"], "dst": e["dst"], "weight": int(e["weight"]),
            "risk": float(e["risk"]),
            "x0": float(a[0]), "y0": float(a[1]), "z0": float(a[2]),
            "x1": float(b[0]), "y1": float(b[1]), "z1": float(b[2]),
        })
    return {"nodes": out_nodes, "edges": out_edges,
            "shown": len(keep), "total": len(nodes), "truncated": len(nodes) > len(keep)}


LEDGER_VERIFY_CMD = "python -m ledger.verify_cli"


def ledger_status(out_dir) -> dict:
    """Chain length, head, checkpoint match and verification result (M10.5).

    `reason` is the verifier's machine-readable reason when the installed
    `verify_cli` exposes `verify_detailed`, else None. It is needed because the
    anchor-only failures — a missing, unsigned or forged checkpoint over an
    otherwise intact chain — report no bad record index.
    """
    from ledger import verify_cli
    from ledger.ledger import Ledger

    chain = Path(out_dir) / "audit_chain.jsonl"
    cps = Path(out_dir) / "checkpoints.jsonl"
    if not chain.exists():
        return {"exists": False}
    led = Ledger(chain, checkpoint_path=cps)
    detailed = getattr(verify_cli, "verify_detailed", None)
    if detailed is not None:
        ok, first_bad, reason = detailed(chain, cps)
    else:
        ok, first_bad = verify_cli.verify(chain, cps)
        reason = None
    n = sum(1 for line in chain.read_text(encoding="utf-8").splitlines() if line.strip())
    return {
        "exists": True, "records": n, "verified": ok, "first_bad_index": first_bad,
        "reason": reason, "anchored": led.verify_against_checkpoints(),
    }


def ledger_failure_text(status: dict) -> str:
    """What the red ledger panel says when verification fails.

    An edited record has an index; an anchor failure does not, so a panel that
    formats the index unconditionally announces "record None" — a fact the
    verifier never reported. Each branch states only what came back.
    """
    idx = status.get("first_bad_index")
    if idx is not None:
        return (f"TAMPER DETECTED at record {idx} — the hash chain no longer validates. "
                "Re-run the pipeline to rebuild a clean chain.")
    reason = status.get("reason")
    if reason:
        return (f"LEDGER VERIFICATION FAILED — reason `{reason}`. No bad record index was "
                f"reported, so run `{LEDGER_VERIFY_CMD}` on this chain for the verifier's "
                "full statement, then re-run the pipeline to rebuild chain and checkpoint.")
    return ("LEDGER VERIFICATION FAILED — the verifier reported neither a bad record index "
            f"nor a reason. Run `{LEDGER_VERIFY_CMD}` on this chain, which prints both.")


def tamper_ledger(out_dir, index: int = 0, field: str = "probability") -> bool:
    """Demo beat 5: edit one record in place so the verifier can catch it."""
    chain = Path(out_dir) / "audit_chain.jsonl"
    lines = chain.read_text(encoding="utf-8").splitlines()
    if index >= len(lines):
        return False
    rec = json.loads(lines[index])
    rec[field] = 0.999999
    lines[index] = json.dumps(rec, sort_keys=True, separators=(",", ":"))
    chain.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return True


def results_card() -> pd.DataFrame:
    """M10.6: the headline comparison, read from results/ — never hardcoded."""
    from eval import ablation

    return ablation.build_table(budget=0.01)


def forecast_horizons() -> pd.DataFrame:
    """Per-horizon forecasting rows from results/forecast.json (M7)."""
    cfg_eval = load_config("eval")
    p = resolve_path(cfg_eval["paths"]["results_dir"]) / "forecast.json"
    if not p.exists():
        return pd.DataFrame()
    d = json.loads(p.read_text(encoding="utf-8"))
    rows = []
    for k in sorted(d["horizons"], key=int):
        b = d["horizons"][k]
        pt = b["fpr_0.01"]
        rows.append({
            "horizon_k": int(k), "seconds_ahead": int(k) * 5,
            "test_AUROC": round(b["auroc_test"], 3),
            "median_lead_s": round(pt["lead_time_median"]),
            "episodes": f"{pt['episodes_detected']}/{pt['episodes_total']}",
        })
    return pd.DataFrame(rows)


# ------------------------------------------------- k-step forecast (PS deliverable 3)
# Everything below reads a dict from `engine.forecast.forecast_file`, whose shape
# is fixed by the shared k-step API contract (`horizons`, `stride_seconds`,
# `unavailable_horizons`, `forecast`, `per_host_curve`, plus everything
# `engine.predict.predict_file` already returns). The module is built in a
# separate workstream, so every reader here treats a missing or malformed key as
# something to SAY rather than something to fill in: this panel must never put a
# number on screen that the engine did not hand it.

FORECAST_MODULE = "engine.forecast"
# The forecaster re-runs the pipeline, and the pipeline appends to a ledger. It
# is therefore given its own directory under the session dir, exactly as the
# what-if is: section 5 verifies the chain the nowcast wrote, and a second
# pipeline appending to that chain would change the record count under the
# judge's feet mid-demo.
FORECAST_SUBDIR = "forecast"


class ForecastUnavailable(RuntimeError):
    """The k-step forecaster cannot run here, and no input would change that.

    Distinct from a pipeline failure: the capability is absent (no module, no
    entry point), not the input bad. The UI renders it as an empty state naming
    what is missing, never as a red error card telling a judge to fix something
    that is not broken.
    """


def run_forecast(input_path, out_dir, fpr_budget: float = 0.01) -> dict:
    """k-step forecast for one input, via `engine.forecast.forecast_file`.

    The module is imported defensively because it ships from another workstream
    and may not exist in a given checkout. Absence is detected with `find_spec`
    rather than by catching ImportError, so that a forecaster which is present
    but itself fails to import — a missing third-party dependency, a syntax
    error — surfaces as the failure it is instead of being reported as "not
    shipped". The two have different fixes and must not render identically.
    """
    if importlib.util.find_spec(FORECAST_MODULE) is None:
        raise ForecastUnavailable(FORECAST_MISSING_TEXT)
    from engine import forecast

    forecast_file = getattr(forecast, "forecast_file", None)
    if forecast_file is None:
        raise ForecastUnavailable(FORECAST_NO_ENTRYPOINT_TEXT)
    return forecast_file(
        input_path, out_dir=Path(out_dir) / FORECAST_SUBDIR, fpr_budget=fpr_budget
    )


def _curve_points(fc: dict, host: str) -> list[dict]:
    """`per_host_curve[host]`, or [] when the engine reported nothing for it."""
    curves = fc.get("per_host_curve")
    if not isinstance(curves, dict):
        return []
    points = curves.get(host)
    if not isinstance(points, (list, tuple)):
        return []
    return [p for p in points if isinstance(p, dict)]


def _newest_window_entries(fc: dict, host: str) -> dict[int, dict]:
    """`forecast` rows for this host's newest source window, keyed by k.

    The curve carries k / seconds_ahead / probability / alert; the per-(host,
    window, k) rows carry the threshold, stage and technique the table needs.
    They are joined on the NEWEST source window because that is the window the
    contract says `per_host_curve` is built from — joining on any other would
    caption one window's curve with another window's stage.
    """
    rows = [f for f in (fc.get("forecast") or []) if isinstance(f, dict)
            and f.get("host") == host]
    starts = [s for s in (_as_fraction(f.get("window_start")) for f in rows) if s is not None]
    if not starts:
        return {}
    newest = max(starts)
    out: dict[int, dict] = {}
    for f in rows:
        if _as_fraction(f.get("window_start")) != newest:
            continue
        k = _as_int(f.get("k"))
        if k is not None:
            out[k] = f
    return out


KSTEP_CURVE_COLUMNS = ("k", "seconds_ahead", "probability", "threshold",
                       "alert", "stage", "technique")


def kstep_curve(fc: dict, host: str) -> pd.DataFrame:
    """One host's risk curve: a row per horizon k, newest source window.

    `seconds_ahead` falls back to k × `stride_seconds` only because the contract
    DEFINES it that way; when neither is readable the cell stays empty rather
    than being filled with a plausible number.
    """
    detail = _newest_window_entries(fc, host)
    stride = _as_fraction(fc.get("stride_seconds"))
    rows = []
    for point in _curve_points(fc, host):
        k = _as_int(point.get("k"))
        if k is None:                 # a point with no horizon indexes nothing
            continue
        entry = detail.get(k, {})
        seconds = _as_fraction(point.get("seconds_ahead"))
        if seconds is None and stride is not None:
            seconds = k * stride
        rows.append({
            "k": k,
            "seconds_ahead": seconds,
            "probability": _as_fraction(point.get("probability")),
            "threshold": _as_fraction(entry.get("threshold")),
            "alert": bool(point.get("alert")),
            "stage": entry.get("stage"),
            "technique": entry.get("technique"),
        })
    if not rows:
        return pd.DataFrame(columns=list(KSTEP_CURVE_COLUMNS))
    df = pd.DataFrame(rows)[list(KSTEP_CURVE_COLUMNS)]
    return df.sort_values("k").reset_index(drop=True)


def kstep_plottable(curve: pd.DataFrame) -> pd.DataFrame:
    """The subset of a curve that can honestly be drawn.

    A point whose score or seconds-ahead the engine did not supply is not
    plotted — but it is not dropped from the TABLE either, so the gap is visible
    on the page instead of being closed by a line drawn through it.
    """
    if curve.empty:
        return curve
    ok = [i for i, row in curve.iterrows()
          if _as_fraction(row["probability"]) is not None
          and _as_fraction(row["seconds_ahead"]) is not None]
    return curve.loc[ok].reset_index(drop=True)


def kstep_use_log_scale(curve: pd.DataFrame) -> bool:
    """Should the risk curve's y-axis be logarithmic? (see CURVE_LOG_SCALE_RATIO)"""
    if curve.empty:
        return False
    values = [v for v in (_as_fraction(x) for x in
                          list(curve["probability"]) + list(curve["threshold"]))
              if v is not None and v > 0]
    if len(values) < 2:
        return False
    return max(values) / min(values) >= CURVE_LOG_SCALE_RATIO


def kstep_curve_rows(curve: pd.DataFrame) -> list[dict]:
    """Display rows for the stage-progression table.

    The score and crossing columns are named for what the project claims — a
    ranking, and a threshold crossing — rather than for a probability of attack
    and an alert (see KSTEP_SCORE_COLUMN / KSTEP_ALERT_COLUMN).
    """
    rows = []
    for _, row in curve.iterrows():
        probability = _as_fraction(row["probability"])
        threshold = _as_fraction(row["threshold"])
        rows.append({
            "horizon_k": int(row["k"]),
            "seconds_ahead": _as_fraction(row["seconds_ahead"]),
            KSTEP_SCORE_COLUMN: probability,
            "threshold": threshold,
            KSTEP_ALERT_COLUMN: bool(row["alert"]),
            "stage": row["stage"],
            "technique": row["technique"],
        })
    return rows


def kstep_hosts(fc: dict, top: int = 10) -> list[str]:
    """Hosts with a curve, ranked by peak k-step score (what an analyst reads first).

    A host whose every point came back unreadable keeps its place in the list
    rather than disappearing from the picker: its curve then renders as blanks,
    which says "the engine gave us nothing for this host" — vanishing says
    nothing at all.
    """
    curves = fc.get("per_host_curve")
    if not isinstance(curves, dict):
        return []
    ranked: list[tuple[float, str]] = []
    for host, points in curves.items():
        if not isinstance(points, (list, tuple)) or not points:
            continue
        scores = [s for s in (_as_fraction(p.get("probability"))
                              for p in points if isinstance(p, dict)) if s is not None]
        ranked.append((max(scores) if scores else -math.inf, str(host)))
    ranked.sort(key=lambda item: (-item[0], item[1]))
    return [host for _, host in ranked[:top]]


def kstep_unavailable_rows(fc: dict) -> list[dict]:
    """`unavailable_horizons` as table rows — the k, and the engine's own reason.

    A horizon with no model is STATED. A curve that quietly skips k=8 reads as a
    forecast that covered every horizon it was asked for, which is the silence
    this whole page exists to break.
    """
    raw = fc.get("unavailable_horizons")
    if not isinstance(raw, dict) or not raw:
        return []
    rows = []
    for k, reason in raw.items():
        parsed = _as_int(k)
        rows.append({"horizon_k": parsed if parsed is not None else str(k),
                     "why there is no forecast at this horizon": str(reason)})
    return sorted(rows, key=lambda r: (isinstance(r["horizon_k"], str), r["horizon_k"]))


def kstep_engine_caveat(fc: dict) -> str | None:
    """The forecaster's OWN caveat (`forecast_caveat`), or None if it sent none.

    `engine.forecast` ships FORWARD_FORECAST_CAVEAT in its return value
    specifically so a UI can put it in front of a viewer, and the page renders
    that string rather than only the one this module holds. The difference
    matters: if the engine's measured finding changes, the page changes with it
    instead of continuing to recite a constant that has quietly gone stale.
    """
    caveat = fc.get("forecast_caveat")
    if isinstance(caveat, str) and caveat.strip():
        return caveat.strip()
    return None


def kstep_empty_reason(fc: dict) -> str | None:
    """Why the curve panel has nothing to draw, or None when it does.

    Two emptinesses that look identical on screen and are not: a forecaster with
    no persisted horizon at all, and one that has horizons but returned no curve
    for THIS input. They are separated because their fixes are.
    """
    curves = fc.get("per_host_curve")
    if isinstance(curves, dict) and any(curves.values()):
        return None
    horizons = fc.get("horizons")
    if not isinstance(horizons, (list, tuple)) or not horizons:
        return FORECAST_NO_HORIZONS_TEXT
    return FORECAST_NO_CURVE_TEXT
