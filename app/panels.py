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


def _separator_ahead(text: str, start: int, sep: str) -> bool:
    """Is another separator of the SAME style still ahead on this line?

    This is what lets a space be part of a directory name: `John Smith Jr\\x` has
    a backslash ahead of it and continues, `b.json read/write failed` does not —
    a Windows path's separators are backslashes, and `read/write` is prose.
    """
    for c in text[start:]:
        if c == sep:
            return True
        if c in _PATH_STOP:
            return False
    return False


def _consume_absolute_path(text: str, start: int, sep: str) -> tuple[int, str]:
    """Scan one absolute path whose root ends at `start`; return (end, replacement).

    Components are read one at a time. A space inside a component is consumed
    only while the component does not yet name a file AND another same-style
    separator is still ahead — the two conditions that separate `John Smith Jr\\`
    from `a.pcap read/write`. The scan stops at the first component that names a
    file, because nothing follows a file in a path.
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
    5. Consumption **stops at the first component that names a file**, so prose
       that merely contains a slash survives: `C:\\a\\b.json read/write failed`
       keeps both `b.json` and `read/write`.

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
