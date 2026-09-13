"""M10.7: the app's logic runs under test_offline conditions (sockets blocked).

Streamlit's UI shell is not unit-testable, so all behaviour lives in
app/panels.py and is exercised here — including the ledger tamper/re-verify
demo beat, the what-if ablation, and the failure/empty-state paths a judge hits
first on a machine with no trained artifacts.

The engine-dependent tests carry `requires_engine` individually; the rest must
run on a bare checkout, because that is exactly the state they describe.
"""

from __future__ import annotations

import ast
import importlib.util
import inspect
import re
import time
from pathlib import Path

import pandas as pd
import pytest

from app import panels
from configs import resolve_path
# The retired-claim list is IMPORTED, never restated: see the section at the foot
# of this module for the scope contract between that ratchet and this one.
from tests.test_docs_claims import BANNED as RETIRED_CLAIMS
from tests.test_docs_claims import hits as claim_hits
from tests.test_docs_claims import normalise as claim_normalise


def _engine_ready() -> bool:
    """True when the PUBLISHED engine bundle is on disk.

    Narrow on purpose. `requires_engine` gates tests that assert on scored
    output, and a demo model fitted on one synthetic capture is not evidence for
    any of it — see tests/_stubs.engine_model_loadable, which is the broad
    predicate and is deliberately not a synonym for this one.
    """
    return (importlib.util.find_spec("xgboost") is not None
            and resolve_path("artifacts/engine_model.json").exists())


def _benchmark_rows_exist() -> bool:
    """True when results/*.json would give the benchmark section rows to draw.

    Two tests below pin what the section shows when it has NOTHING — the bootstrap
    card rather than a bare header. Running the evaluation harness on this machine
    fills results/, which is a legitimate state and makes those tests describe a
    page that is no longer on screen. Gate rather than assert, so a developer who
    has regenerated results does not see a red suite for having done real work.
    """
    from eval import ablation

    try:
        return not ablation.build_table(budget=0.01).empty
    except Exception:
        return False


def _app_can_score_anything() -> bool:
    """True when the app would find SOME bundle, published OR demo.

    The gate for the tests that pin what the app does when it can score NOTHING:
    a demo bundle closes those exactly as a published one does. Gating them on
    the published lane alone made them depend on whether someone had happened to
    run the demo bootstrap on this machine, which is how they broke.
    """
    from tests._stubs import engine_model_loadable

    return importlib.util.find_spec("xgboost") is not None and engine_model_loadable()


requires_engine = pytest.mark.skipif(
    not _engine_ready(), reason="engine model not trained — run python -m engine.train_engine"
)


# --------------------------------------------------------------- doc pinning
# Several panel strings QUOTE a document (docs/limitations.md, CLAUDE.md). The
# quote is the point: a caveat that cites a rule the project no longer holds, or
# a doc that no longer says what the page claims it says, is worse than neither.
# So the wording is pinned in both directions and the pin fails loudly — but a
# bare `assert "..." in doc` tells whoever hits it nothing about WHY a sentence
# in a file this workstream does not own is load-bearing, or where its twin
# lives. This carries that explanation into the failure message itself.


def _require_pinned_wording(document: str, fragment: str, *, doc: str,
                            mirror: str, why: str) -> None:
    assert fragment in document, (
        f"\nPINNED WORDING MISSING: {doc} no longer contains {fragment!r}."
        f"\nWHY IT IS PINNED: {why}"
        f"\nTHE COPY THAT QUOTES IT: {mirror}"
        f"\nHOW TO FIX: change the wording in {doc} and in {mirror} in the SAME"
        f" commit, then update the fragment in tests/test_app.py. Deleting this"
        f" assertion is not the fix — it exists so the demo cannot cite a"
        f" document that has stopped saying it."
    )


def test_a_pinned_wording_failure_explains_why_and_where():
    """The pin above is only useful if its failure is self-explanatory: a future
    contributor editing docs/limitations.md must learn from the failure alone
    what broke and which file mirrors it."""
    with pytest.raises(AssertionError) as excinfo:
        _require_pinned_wording("a document that drifted", "the pinned sentence",
                                doc="docs/limitations.md", mirror="app/panels.py::X",
                                why="the page quotes it verbatim")
    msg = str(excinfo.value)
    assert "WHY IT IS PINNED" in msg and "the page quotes it verbatim" in msg
    assert "docs/limitations.md" in msg and "app/panels.py::X" in msg
    assert "HOW TO FIX" in msg
    # and it must still pass the thing it is asked about
    _require_pinned_wording("a document that says the pinned sentence", "the pinned sentence",
                            doc="d", mirror="m", why="w")


@pytest.fixture(scope="module")
def run(fixture_csv, tmp_path_factory):
    out = tmp_path_factory.mktemp("apprun")
    return panels.run_pipeline(fixture_csv, out), out


@requires_engine
def test_pipeline_and_panels_work_offline(no_network, fixture_csv, tmp_path):
    """M10.7 + M10.1: the whole app path runs with every socket blocked."""
    result = panels.run_pipeline(fixture_csv, tmp_path)
    assert result["n_flows"] == 1000
    assert result["forecasts"], "app pipeline produced no forecasts"

    tl = panels.timeline_frame(result)
    assert not tl.empty
    # the network score is the MAX over hosts in a window (CLAUDE.md)
    assert tl["window_start"].is_unique
    assert (tl["probability"] <= 1.0).all()

    ranking = panels.host_ranking(result)
    assert not ranking.empty
    assert ranking["peak_probability"].is_monotonic_decreasing

    exp = panels.explanation_for(result, ranking.iloc[0]["host"])
    assert exp and exp["top_features"]
    assert all(isinstance(t["feature"], str) for t in exp["top_features"])

    rows = panels.explanation_rows(exp)
    assert rows and all(panels.EXPLANATION_VALUE_COLUMN in r for r in rows)


@requires_engine
def test_ledger_panel_tamper_then_detect(run):
    """Demo beat 5 (M10.5): verify -> tamper -> re-verify catches it."""
    result, out = run
    before = panels.ledger_status(out)
    assert before["exists"] and before["verified"] and before["records"] > 0

    assert panels.tamper_ledger(out, index=0)
    after = panels.ledger_status(out)
    assert not after["verified"], "tampered ledger must fail verification"
    assert after["first_bad_index"] == 0


@requires_engine
def test_what_if_remove_host_ablates_that_host(run, fixture_csv, tmp_path):
    """M10.4: removing a host drops its own alerts and never adds any."""
    result, _ = run
    ranking = panels.host_ranking(result)
    top = str(ranking.iloc[0]["host"])

    wi = panels.what_if_remove_host(fixture_csv, tmp_path, top)
    after = wi["after"]
    assert all(f["host"] != top for f in after["forecasts"]), "removed host still alerts"
    assert after["n_alerts"] <= result["n_alerts"], "ablation must not add alerts"


@requires_engine
@pytest.mark.skipif(
    not resolve_path("app/assets/synthetic_demo.pcap").exists(),
    reason="synthetic demo pcap not built",
)
def test_what_if_on_pcap_input_stays_on_full_path(tmp_path):
    """Regression: the what-if on a PCAP must ablate on the extracted features,
    not re-read the .pcap as a CSV (which raised UnicodeDecodeError)."""
    pcap = resolve_path("app/assets/synthetic_demo.pcap")
    result = panels.run_pipeline(pcap, tmp_path / "main")
    top = str(panels.host_ranking(result).iloc[0]["host"])

    wi = panels.what_if_remove_host(pcap, tmp_path / "wi", top)  # must not raise
    after = wi["after"]
    assert all(f["host"] != top for f in after["forecasts"])
    assert after["n_alerts"] < result["n_alerts"], "the top host drove alerts"


@requires_engine
def test_pipeline_result_carries_a_host_graph(run):
    """M10.8: predict_file attaches a nodes+edges host graph for the 3D view."""
    result, _ = run
    g = result.get("graph")
    assert g and g["nodes"], "result must carry a host graph"
    assert all({"ip", "peak_prob", "n_alerts"} <= set(n) for n in g["nodes"])
    assert all({"src", "dst", "weight", "risk"} <= set(e) for e in g["edges"])


def test_network_graph_layout_positions_edges_and_ranks():
    """M10.8: the 3D layout assigns coordinates, keeps edge risk, is deterministic,
    and trims to the highest-risk hosts without silently hiding the count."""
    result = {"graph": {
        "nodes": [
            {"ip": "10.0.0.1", "peak_prob": 0.90, "n_alerts": 3, "internal": 1},
            {"ip": "10.0.0.2", "peak_prob": 0.00, "n_alerts": 0, "internal": 1},
            {"ip": "8.8.8.8", "peak_prob": 0.00, "n_alerts": 0, "internal": 0},
        ],
        "edges": [
            {"src": "10.0.0.1", "dst": "10.0.0.2", "weight": 5, "risk": 0.90},
            {"src": "10.0.0.1", "dst": "8.8.8.8", "weight": 2, "risk": 0.90},
        ],
    }}
    layout = panels.network_graph_layout(result)
    assert layout["shown"] == 3 and not layout["truncated"]
    for n in layout["nodes"]:
        assert all(isinstance(n[c], float) for c in ("x", "y", "z"))
    for e in layout["edges"]:
        assert {"x0", "y0", "z0", "x1", "y1", "z1"} <= set(e)
    assert any(e["risk"] == 0.90 for e in layout["edges"])
    # deterministic under the fixed seed
    again = panels.network_graph_layout(result)
    assert [n["x"] for n in layout["nodes"]] == [n["x"] for n in again["nodes"]]

    # trimming reports what it dropped
    many = {"graph": {
        "nodes": [{"ip": f"10.0.0.{i}", "peak_prob": i / 100, "n_alerts": 0,
                   "internal": 1} for i in range(1, 91)],
        "edges": [],
    }}
    trimmed = panels.network_graph_layout(many, max_nodes=60)
    assert trimmed["shown"] == 60 and trimmed["total"] == 90 and trimmed["truncated"]


def test_results_card_reads_from_results_dir():
    """M10.6: the card is generated from results/*.json, not hardcoded."""
    fh = panels.forecast_horizons()
    if not fh.empty:
        assert {"horizon_k", "test_AUROC", "median_lead_s", "episodes"} <= set(fh.columns)
        assert (fh["seconds_ahead"] == fh["horizon_k"] * 5).all()


# --------------------------------------------------------------- demo shell
# None of the tests below need a trained engine: they pin what a judge sees on
# a bare checkout, which is the state in which the demo used to break.

APP_SOURCE = resolve_path("app/streamlit_app.py").read_text(encoding="utf-8")
DEMO_SCRIPT = resolve_path("docs/demo_script.md").read_text(encoding="utf-8")


def test_app_renders_the_buttons_from_the_shared_labels():
    """The UI module must take its labels from panels, or the hint can drift
    away from the buttons again."""
    assert "panels.DEMO_PCAP_LABEL" in APP_SOURCE
    assert "panels.DEMO_CSV_LABEL" in APP_SOURCE
    assert "panels.EMPTY_STATE_HINT" in APP_SOURCE
    assert "Use the bundled sample" not in APP_SOURCE


def test_demo_script_names_buttons_that_exist():
    """F30: the shot list drove the presenter to a non-existent button."""
    assert "Use the bundled sample" not in DEMO_SCRIPT
    for label in panels.BUTTON_LABELS:
        assert label in DEMO_SCRIPT, f"demo script never names the {label!r} button"


def test_demo_script_does_not_promise_a_fixed_test_count():
    """F30: the script told the presenter to show '93 passed, 1 skipped', a
    count this repo cannot produce. The count must be read off the screen."""
    assert not re.search(r"\d+\s+passed,\s+\d+\s+skipped", DEMO_SCRIPT)


# The guarded set is DERIVED from app/panels.py rather than listed here. The
# hand-maintained allowlist this replaces omitted timeline_frame, host_ranking,
# explanation_for and explanation_rows — precisely the calls that were in fact
# unwrapped — so it could not have caught them. Only the calls that need no
# guard are named, each with the reason it is safe.
UNGUARDED_PANEL_CALLS = {
    "failure_card": "the error renderer itself; guarding it would be circular",
    "redact_paths": "pure string rewriting, on that same path",
    "app_config": "reads .streamlit/config.toml at import — a broken config file is a "
                  "broken checkout, not a bad input, and must not be swallowed",
    "theme_colors": "same file, same reason",
    "max_upload_mb": "same file, same reason",
    "rgba": "pure colour arithmetic over theme_colors() output",
    "coverage_note": "pure reader of the result dict the pipeline already returned",
    "provenance_block": "same — assembles the provenance box out of the result dict",
    "is_demo_model_run": "same — one boolean out of the result dict",
    "threshold_metric_label": "same — formats a label from the result dict",
    "benchmark_caveats": "same — selects which caveats apply from the result dict",
    "role_features_degraded_note": "same — one boolean out of the result dict",
    "host_selector_label": "same",
    "ledger_failure_text": "same, over ledger_status() output",
}


def _panel_functions() -> set[str]:
    return {name for name, obj in vars(panels).items()
            if not name.startswith("_") and inspect.isfunction(obj)
            and obj.__module__ == panels.__name__}


RISKY_PANEL_CALLS = _panel_functions() - set(UNGUARDED_PANEL_CALLS)


def test_the_wrapped_set_is_derived_from_the_panels_module():
    """F23 follow-up: a hand-written allowlist under-covers silently. Deriving it
    inverts the failure mode — a new panel function is required to be wrapped
    until someone argues it out in UNGUARDED_PANEL_CALLS."""
    names = _panel_functions()
    assert not set(UNGUARDED_PANEL_CALLS) - names, "exemption names a non-function"
    assert {"timeline_frame", "host_ranking", "explanation_for", "explanation_rows",
            "network_graph_layout", "run_pipeline", "ledger_status"} <= RISKY_PANEL_CALLS


def test_every_failure_prone_call_in_the_app_is_wrapped():
    """F23: an unwrapped call renders a raw traceback, which leaks absolute
    filesystem paths onto the projector. Walk the AST instead of trusting a
    reviewer to notice the next unguarded call."""
    tree = ast.parse(APP_SOURCE)
    unguarded: list[str] = []

    def walk(node, guarded: bool):
        if isinstance(node, ast.Call):
            fn = node.func
            if (isinstance(fn, ast.Attribute) and isinstance(fn.value, ast.Name)
                    and fn.value.id == "panels" and fn.attr in RISKY_PANEL_CALLS
                    and not guarded):
                unguarded.append(f"{fn.attr} at line {node.lineno}")
        if isinstance(node, ast.Try):
            for child in node.body:
                walk(child, True)
            for child in node.handlers + node.orelse + node.finalbody:
                walk(child, guarded)
            return
        for child in ast.iter_child_nodes(node):
            walk(child, guarded)

    walk(tree, False)
    assert not unguarded, f"unwrapped failure-prone calls: {unguarded}"


def test_failure_card_sends_a_missing_engine_to_the_train_command():
    """F23: the first click on a clean machine. The card must name the fix."""
    exc = FileNotFoundError(
        f"{resolve_path('artifacts/engine_threshold.json')} missing — run "
        "`python -m engine.train_engine` to fit and persist the engine models"
    )
    card = panels.failure_card(exc)
    assert card["command"] == "python -m engine.train_engine"
    assert "trained" in card["title"].lower()


def test_failure_card_prefers_the_digest_rule_over_the_artifact_rule():
    """The weight-mismatch message names an artifact file too; order matters."""
    card = panels.failure_card(
        RuntimeError("model-weight SHA-256 mismatch (engine_model.json) — refusing to write")
    )
    assert card["command"] == "python scripts/verify_weights.py"


def test_failure_card_explains_a_non_cic_csv():
    """F23: any CSV whose header is not the CIC schema raises from the loader."""
    card = panels.failure_card(
        ValueError("/tmp/mine.csv lacks mapped column(s) ['Src IP'] — this day needs "
                   "features recomputed from PCAP")
    )
    assert "schema" in card["title"].lower()


@pytest.mark.parametrize("content", [
    "a,b,c\n1,2,3\n",                                    # no Label column at all
    "Timestamp,Label\n2018-02-14 08:00:00,Benign\n",     # Label, but not the CIC schema
])
def test_a_real_non_cic_csv_produces_a_schema_card(tmp_path, data_cfg, content):
    """F23 against the REAL loader, not a hand-written message: whatever the
    loader raises for a wrong header must land on the schema card."""
    from data import flow_features as FF

    path = tmp_path / "wrong.csv"
    path.write_text(content, encoding="utf-8")
    with pytest.raises(ValueError) as excinfo:
        FF.load_canonical(data_cfg, path)

    card = panels.failure_card(excinfo.value)
    assert card["title"] == "That CSV is not in the CIC-IDS-2018 flow schema"
    assert card["detail"].startswith("wrong.csv")


def test_failure_card_handles_an_unknown_failure_without_a_traceback():
    card = panels.failure_card(ZeroDivisionError("division by zero"))
    assert "ZeroDivisionError" in card["title"]
    assert card["detail"] and "Traceback" not in card["detail"]


def test_failure_card_never_shows_an_absolute_path():
    """A path outside the repo collapses to a file name; one inside becomes
    repo-relative, which is the part a judge can act on."""
    inside = panels.failure_card(FileNotFoundError(
        f"{resolve_path('artifacts/engine_model.json')} missing"))
    assert inside["detail"].startswith("artifacts/engine_model.json")

    outside = panels.redact_paths("failed to read C:/Users/someone/secret/capture.pcap now")
    assert "Users" not in outside and "capture.pcap" in outside


# Every row is a message shape that actually reaches this function — Python's own
# OSError text, our own FileNotFoundError text, a tshark lookup — as
# (message, exact expected output, substrings that must NOT survive).
#
# The first three rows are the round-1 cases (a spaced path is the common case:
# this repo itself lives under `sih 2026`). The rows after them are what the
# round-2 verifier measured STILL leaking, plus the over-consumption it found in
# the other direction. Two spaces in one component, "OneDrive - Org" and a
# trailing spaced component are not exotic: they are how a managed Windows
# laptop is laid out, which is the machine this demo runs on.
REDACTION_CASES = (
    (r"C:\Users\John Smith\secret\capture.pcap not found",
     "capture.pcap not found", ("John", "Users", "secret")),
    (r"/home/john doe/data/x.pcap missing",
     "x.pcap missing", ("john", "home", "data")),
    (r"C:\Program Files\Wireshark\tshark.exe is not on PATH",
     "tshark.exe is not on PATH", ("Program", "Files", "Wireshark")),
    # (a) TWO spaces in one directory component
    (r"C:\Users\John Smith Jr\secret\capture.pcap not found",
     "capture.pcap not found", ("John", "Smith", "Jr", "Users", "secret")),
    # (b) the "OneDrive - Org" shape of a managed Windows machine
    (r"C:\Users\HP\OneDrive - Contoso Ltd\caps\a.pcap",
     "a.pcap", ("OneDrive", "Contoso", "Ltd", "caps")),
    # (c) a TRAILING component with a space: no file name to keep, so the path
    # and the rest of the line go. Over-redaction is the safe direction.
    (r"PermissionError: C:\Users\John Smith",
     f"PermissionError: {panels.REDACTED_PATH}", ("John", "Smith", "Users")),
    (r"C:\Users\John Smith\out does not exist",
     panels.REDACTED_PATH, ("John", "Smith", "Users", "out")),
    (r"PermissionError: [Errno 13] 'C:\Users\John Smith\out' denied",
     f"PermissionError: [Errno 13] '{panels.REDACTED_PATH}' denied",
     ("John", "Smith", "Users")),
    # over-consumption: `read/write` is ordinary phrasing in an I/O error, and
    # swallowing it also swallowed the one actionable token, the file name.
    (r"engine_model.json: C:\a\b.json read/write failed",
     "engine_model.json: b.json read/write failed", ("C:",)),
    ("/home/hp/caps/a.pcap read/write failed",
     "a.pcap read/write failed", ("home", "caps")),
    # Program Files (x86): parentheses are legal in a Windows directory name
    (r"C:\Program Files (x86)\Wireshark\tshark.exe not found",
     "tshark.exe not found", ("Program", "x86", "Wireshark")),
    # OSError renders the file name with repr(), so the separators arrive DOUBLED
    (r"[Errno 2] No such file or directory: 'C:\\Users\\HP\\nope dir\\x.csv'",
     "[Errno 2] No such file or directory: 'x.csv'", ("Users", "HP", "nope")),
    # a UNC share names the file server as well as the operator
    (r"\\corpfs01\Users\jsmith\caps\a.pcap could not be opened",
     "a.pcap could not be opened", ("corpfs01", "jsmith", "Users")),
    # sentence punctuation glued to the file name stays on the page
    (r"could not open C:\caps\a.pcap.", "could not open a.pcap.", ("caps",)),
    # a URL is not a filesystem leak, and `//` must not be read as a path root
    ("see https://example.com/docs for the schema",
     "see https://example.com/docs for the schema", ()),
)


@pytest.mark.parametrize("message, expected, forbidden", REDACTION_CASES)
def test_redaction_keeps_the_file_name_and_drops_everything_above_it(
        message, expected, forbidden):
    """What redact_paths guarantees, case by case: a path that names a file
    collapses to that file name; a path that ends at a DIRECTORY takes the rest
    of its line with it, because nothing marks where `C:\\Users\\John Smith`
    ends; and consumption stops at the file name, so prose that merely contains
    a slash (`read/write`) is left alone."""
    out = panels.redact_paths(message)
    assert out == expected
    for token in forbidden:
        assert token not in out, f"{token!r} survived redaction: {out!r}"


@pytest.mark.parametrize("message", [c[0] for c in REDACTION_CASES])
def test_no_absolute_root_survives_redaction(message):
    """The invariant behind the per-case expectations, written independently of
    the module's own pattern so the two cannot drift into agreeing: no drive
    root, no UNC root and no POSIX root may appear in anything rendered."""
    # A drive root is exactly ONE letter before the colon — the lookbehind is
    # what keeps `https:` out of it, not a special case for URLs.
    leaked = re.compile(r"(?<![A-Za-z])[A-Za-z]:[\\/]|\\\\[A-Za-z0-9]"
                        r"|(?:^|[\s'\"(\[])/[A-Za-z0-9]")
    out = panels.redact_paths(message)
    assert not leaked.search(out), f"absolute root survived: {out!r}"


def test_failure_card_matches_its_rules_on_the_unredacted_message():
    """Redaction is deliberately aggressive, so it can swallow the very marker a
    rule keys on (`engine_threshold` here — an extension-less path that has to be
    removed whole). The rules therefore read the RAW message and only the
    rendered detail is redacted, so the card still names the fix."""
    card = panels.failure_card(
        FileNotFoundError(r"C:\Users\John Smith\artifacts\engine_threshold missing"))
    assert card["command"] == "python -m engine.train_engine"
    assert "John" not in card["detail"] and "Smith" not in card["detail"]
    assert panels.REDACTED_PATH in card["detail"]


def test_a_mid_path_file_name_does_not_stop_the_scan():
    """The docstring's guarantee 5 used to read "consumption stops at the first
    component that names a file". The code never did that, and the difference is
    not cosmetic: `john.smith` satisfies the module's own file test at position
    2, so a scan that really stopped there would leave `\\secret\\capture.pcap`
    — the directory AND the file — on screen. What ends the scan is the
    separators. This pins the behaviour the corrected docstring describes."""
    assert panels._names_a_file("john.smith"), (
        "the counterexample only bites while `john.smith` LOOKS like a file to "
        "this module; if the file test changed, this test is testing nothing"
    )
    assert panels.redact_paths(r"C:\Users\john.smith\secret\capture.pcap") == "capture.pcap"

    # and the docstring must no longer claim the mechanism it does not have
    doc = " ".join(panels.redact_paths.__doc__.split())
    assert "stops at the first component that names a file" not in doc
    assert "follows the separators" in doc
    assert " ".join(panels._consume_absolute_path.__doc__.split()).count(
        "stops at the first component that names a file") == 0


# A message reaching redact_paths is attacker-influenceable in general (a file
# name, a header, a host name can all land inside an exception string), and the
# function runs on the Streamlit thread with the page blocked behind it. These
# lines are the measured worst case: one drive root, then only spaces and
# word characters, then a single separator far away — which is what makes every
# space's lookahead scan to the end of the line. Sizes are in KB; 2.0 s is
# generous against the ~0.06 s a 1 MB line takes with the bound in place, and is
# ~4x under the 11 s the 32 KB row alone took without it on this machine.
HOSTILE_LINE_SIZES_KB = (32, 256)
REDACTION_TIME_BUDGET_S = 2.0


def _hostile_line(kilobytes: int) -> str:
    return "C:\\" + "a " * (kilobytes * 1024 // 2) + "\\end"


@pytest.mark.parametrize("kilobytes", HOSTILE_LINE_SIZES_KB)
def test_redacting_a_hostile_message_is_bounded_in_time(kilobytes):
    """F-minor: `_separator_ahead` ran once per space and scanned to the end of
    the line, making redaction quadratic — a verifier measured 8.8 s on a 32 KB
    line and 342 s on 200 KB, every second of it a frozen page mid-demo. The
    scan is now bounded to SEPARATOR_LOOKAHEAD_CHARS; this pins that bound with
    a wall-clock measurement, and pins that the bound did not cost the guarantee:
    the drive root still does not survive."""
    line = _hostile_line(kilobytes)
    started = time.perf_counter()
    out = panels.redact_paths(line)
    elapsed = time.perf_counter() - started

    assert elapsed < REDACTION_TIME_BUDGET_S, (
        f"redacting a {kilobytes} KB hostile line took {elapsed:.2f} s "
        f"(budget {REDACTION_TIME_BUDGET_S} s) — the page is frozen for that long"
    )
    # over-redaction is the documented fallback past the bound (guarantee 4/6)
    assert out == panels.REDACTED_PATH
    assert not re.search(r"[A-Za-z]:[\\/]", out), f"absolute root survived: {out!r}"


def test_the_lookahead_bound_is_past_every_real_path():
    """The bound must not truncate a path a real machine can produce, or it
    would trade a hang for a redaction that stops mid-path. MAX_PATH on Windows
    is 260; the deepest spaced directory chain this repo's own tests carry is far
    shorter. A component whose spaces sit inside the window still redacts fully."""
    assert panels.SEPARATOR_LOOKAHEAD_CHARS > 260
    deep = "C:\\" + "\\".join(f"Program Files {i}" for i in range(12)) + "\\tshark.exe"
    assert len(deep) < panels.SEPARATOR_LOOKAHEAD_CHARS
    assert panels.redact_paths(f"{deep} is not on PATH") == "tshark.exe is not on PATH"


def test_a_real_pandas_sized_error_message_is_untouched_and_fast():
    """The reachable case, as opposed to the hostile one: a large real error
    message carries quotes and commas, which are stop characters, so it never
    enters the pathological scan at all. It must stay fast AND keep its text."""
    message = ("Error tokenizing data. C error: Expected 1 fields in line 3, saw 12; "
               "columns: " + ", ".join(f"'col_{i}'" for i in range(2000)))
    started = time.perf_counter()
    out = panels.redact_paths(message)
    assert time.perf_counter() - started < REDACTION_TIME_BUDGET_S
    assert out == message


def test_upload_cap_is_read_from_the_streamlit_config():
    """F39: the server-side guard and Streamlit's own limit must be one number."""
    cap = panels.max_upload_mb()
    assert cap == panels.app_config()["server"]["maxUploadSize"]
    assert 0 < cap <= 200

    panels.check_upload_size(1024, "small.csv")  # must not raise
    with pytest.raises(panels.InputTooLarge) as excinfo:
        panels.check_upload_size((cap + 1) * 1024 * 1024, "huge.pcap")
    assert str(cap) in str(excinfo.value)
    assert panels.failure_card(excinfo.value)["title"].startswith("That file is too large")


def test_safe_upload_name_drops_directories_and_keeps_the_suffix():
    """Streamlit does not sanitise UploadedFile.name, and the suffix selects the
    PCAP or CSV feature path."""
    assert panels.safe_upload_name("../../etc/passwd.csv") == "passwd.csv"
    assert panels.safe_upload_name("photos/2024/a b.pcap") == "a_b.pcap"
    assert panels.safe_upload_name("").endswith(".csv")
    assert "/" not in panels.safe_upload_name("x/y/z.pcapng")


def test_figure_colours_come_from_the_configured_theme():
    """F29: the 3D labels were a hardcoded near-white over a transparent
    background, so they vanished on the light theme a projector defaults to."""
    theme = panels.app_config()["theme"]
    colors = panels.theme_colors()
    assert colors["text"] == theme["textColor"]
    assert colors["background"] == theme["backgroundColor"]
    assert colors["alert"] == theme["redColor"]
    assert "#e0e0e0" not in APP_SOURCE, "node labels must not hardcode a colour"
    assert "COLORS[" in APP_SOURCE

    assert panels.rgba("#ff5a5a", 0.85) == "rgba(255,90,90,0.85)"
    assert panels.rgba("#fff", 1) == "rgba(255,255,255,1)"


def test_benchmark_caveat_quotes_the_limitations_doc():
    """F72: the caveat text is one constant, and every figure it quotes must
    still be in docs/limitations.md — otherwise the two have drifted."""
    doc = resolve_path("docs/limitations.md").read_text(encoding="utf-8")
    for quote in panels.LIMITATIONS_QUOTES:
        _require_pinned_wording(
            doc, quote, doc="docs/limitations.md",
            mirror="app/panels.py::BENCHMARK_CAVEAT (rendered on the benchmark card)",
            why="the benchmark card puts this figure on screen as a population caveat "
                "and tells the judge the full statement is in docs/limitations.md; if "
                "the doc no longer carries the figure, the card is citing a source that "
                "does not support it",
        )
        assert quote in panels.BENCHMARK_CAVEAT.replace("**", "")
    assert "panels.BENCHMARK_CAVEAT" in APP_SOURCE


def test_empty_benchmark_panel_says_what_to_run():
    """F104: results/*.json is gitignored, so on a fresh clone this section
    rendered a bare header with nothing under it."""
    # The app branches on `.empty`, so both must really be frames — the previous
    # form of this line (`... or results_card() is not None`) could never fail.
    assert isinstance(panels.forecast_horizons(), pd.DataFrame)
    assert isinstance(panels.results_card(), pd.DataFrame)
    assert "gitignored" in panels.BENCHMARK_EMPTY_HINT
    # The hint attributes a rule to CLAUDE.md, so that rule must be in CLAUDE.md.
    # It used to cite one ("forbids committing generated numbers") that is not.
    rules = resolve_path("CLAUDE.md").read_text(encoding="utf-8")
    _require_pinned_wording(
        rules, "reproducible by `eval/ablation.py`", doc="CLAUDE.md",
        mirror="app/panels.py::BENCHMARK_EMPTY_HINT (the empty-benchmark card)",
        why="the card explains an EMPTY results panel by attributing a rule to "
            "CLAUDE.md. It previously cited one ('forbids committing generated "
            "numbers') that CLAUDE.md never contained — a fabricated citation on "
            "screen. The wording is pinned so the citation stays true",
    )
    assert "reproducible by `eval/ablation.py`" in panels.BENCHMARK_EMPTY_HINT
    assert "committing generated numbers" not in panels.BENCHMARK_EMPTY_HINT
    assert "python -m eval.harness" in panels.BENCHMARK_EMPTY_COMMANDS
    assert "python scripts/make_ablation_table.py" in panels.BENCHMARK_EMPTY_COMMANDS
    assert "panels.BENCHMARK_EMPTY_HINT" in APP_SOURCE
    assert "panels.BENCHMARK_EMPTY_COMMANDS" in APP_SOURCE


def test_explanation_rows_label_the_value_column_as_standardised():
    """F54: the explainer is handed the SCALED matrix, so `value` is a z-score.
    The column must not present it as a raw feature value."""
    exp = {"top_features": [
        {"feature": "sent_bytes", "value": -0.4231, "contribution": 0.0812},
        {"feature": "syn", "value": 4.6009, "contribution": 0.1913},
    ]}
    rows = panels.explanation_rows(exp)
    assert [r["feature"] for r in rows] == ["sent_bytes", "syn"]
    assert "z-score" in panels.EXPLANATION_VALUE_COLUMN
    assert all("value" not in r or r.get("value") is None for r in rows)
    assert rows[0][panels.EXPLANATION_VALUE_COLUMN] == -0.423
    assert "panels.EXPLANATION_VALUE_CAVEAT" in APP_SOURCE


def test_coverage_note_is_silent_when_nothing_was_skipped():
    """A CSV run carries no frame counters at all; a clean PCAP carries zeroes."""
    assert panels.coverage_note({}) is None
    assert panels.coverage_note({"unparsed_frames": {
        "total": 0, "fraction": 0.0, "by_reason": {"ipv6": 0, "short_frame": 0}}}) is None


def test_coverage_note_says_so_when_the_whole_capture_went_unseen():
    """engine.predict returns `unparsed_frames`. A capture the IPv4 parser
    skipped entirely produces no host-windows and therefore no alerts, and an
    unannotated '0 alerts' is silence read as safety."""
    note = panels.coverage_note({"unparsed_frames": {
        "total": 812, "fraction": 1.0, "by_reason": {"ipv6": 812, "short_frame": 0}}})
    assert note["severity"] == "warning"
    assert "812" in note["text"] and "ipv6" in note["text"]
    # docs/limitations.md §5 quotes this sentence as what the page says; the two
    # are pinned to each other the way BENCHMARK_CAVEAT is.
    quote = "0 alerts here means nothing was seen, not that nothing happened"
    doc = " ".join(resolve_path("docs/limitations.md").read_text(encoding="utf-8").split())
    _require_pinned_wording(
        doc, quote, doc="docs/limitations.md (§5, whitespace-normalised)",
        mirror="app/panels.py::coverage_note (the warning shown above the metrics)",
        why="§5 tells the reader the app 'says outright' this sentence when a capture "
            "is skipped entirely. That is a claim about the UI made in a document, so "
            "the sentence has to exist in both places or the doc is describing a page "
            "that does not exist",
    )
    assert quote in note["text"].replace("**", "")


@pytest.mark.parametrize("block", [
    {"total": "many", "fraction": 0.5, "by_reason": {"ipv6": 1}},       # not a number
    {"total": 812, "fraction": "most", "by_reason": {"ipv6": 812}},     # nor is this
    {"total": 812, "fraction": float("nan"), "by_reason": {"ipv6": 812}},
    {"total": 812, "fraction": 1.0, "by_reason": ["ipv6"]},             # not a mapping
    {"fraction": 1.0, "by_reason": {"ipv6": 812}},                      # no total at all
])
def test_coverage_note_survives_a_malformed_unparsed_block(block):
    """coverage_note is exempt from the app's try/except wrapping (it is listed
    in UNGUARDED_PANEL_CALLS as a pure reader), so an int()/float() raising here
    reaches the page as the Streamlit traceback app/streamlit_app.py's docstring
    says is impossible. It must not raise — and it must not silently return None
    either, because 'we could not read the drop counters' is exactly the silence
    this note exists to break."""
    note = panels.coverage_note({"unparsed_frames": block})
    assert note is not None, "an unreadable coverage block must still say something"
    assert note["severity"] == "warning"
    assert panels.COVERAGE_UNREADABLE_TEXT == note["text"]
    assert "0 alerts" in note["text"]


def test_one_unreadable_reason_count_does_not_discard_the_whole_note():
    """Partial malformation is not total malformation: `total` and `fraction`
    are readable here, so the substantive sentence is still true and still worth
    saying. Only the one count that cannot be read is marked unreadable."""
    note = panels.coverage_note({"unparsed_frames": {
        "total": 812, "fraction": 1.0, "by_reason": {"ipv6": "lots", "short_frame": 3}}})
    assert note["severity"] == "warning"
    assert "812" in note["text"]
    assert "`ipv6`=?" in note["text"] and "`short_frame`=3" in note["text"]


def test_coverage_note_reports_an_unknown_drop_history():
    """engine.predict._coverage distinguishes a known zero from an UNKNOWN drop
    history (`known: False`, counts None — pandas strips the `.attrs` the
    counters ride on). The UI has to distinguish them too: 'we do not know what
    was dropped' must not render as a clean page."""
    from engine import predict

    unknown = predict._coverage(100, None)
    assert unknown["known"] is False and unknown["total"] is None

    note = panels.coverage_note({"unparsed_frames": unknown})
    assert note is not None, "an unknown drop history rendered as a clean page"
    assert note["severity"] == "warning"
    assert note["text"] == panels.COVERAGE_UNKNOWN_TEXT
    assert "0 alerts" in note["text"]

    # a KNOWN zero is still silence-worthy: there is genuinely nothing to say
    assert panels.coverage_note({"unparsed_frames": predict._coverage(100, {})}) is None


def test_coverage_note_severity_follows_the_unparsed_fraction():
    small = panels.coverage_note({"unparsed_frames": {
        "total": 3, "fraction": 0.0005, "by_reason": {"short_frame": 3}}})
    big = panels.coverage_note({"unparsed_frames": {
        "total": 300, "fraction": 0.30, "by_reason": {"ipv6": 300}}})
    assert 0.0005 < panels.UNPARSED_WARN_FRACTION <= 0.30
    assert small["severity"] == "caption" and big["severity"] == "warning"
    assert "3 frames" in small["text"] and "300 frames" in big["text"]


def test_host_picker_does_not_claim_pseudonyms_the_engine_never_applied():
    """The picker read 'pseudonymised where a key is configured'. The engine
    reports `hosts_pseudonymised`, and on the deployed path it is False — only
    the ledger pseudonymises (M9.2)."""
    from engine import predict

    assert predict.HOSTS_PSEUDONYMISED is False
    real = panels.host_selector_label({"hosts_pseudonymised": predict.HOSTS_PSEUDONYMISED})
    assert real == panels.HOST_SELECT_REAL and "real address" in real
    assert (panels.host_selector_label({"hosts_pseudonymised": True})
            == panels.HOST_SELECT_PSEUDONYMISED)
    assert "pseudonymised where a key is configured" not in APP_SOURCE
    assert "panels.host_selector_label" in APP_SOURCE


def test_ledger_failure_text_never_announces_record_none():
    """The anchor-only failures — missing, unsigned or forged checkpoint over an
    intact chain — come back ok=False with first_bad_index=None, and the panel
    used to render 'TAMPER DETECTED at record None'."""
    edited = panels.ledger_failure_text(
        {"verified": False, "first_bad_index": 0, "reason": "chain-tampered"})
    assert "record 0" in edited

    anchor = panels.ledger_failure_text(
        {"verified": False, "first_bad_index": None,
         "reason": "checkpoint-log-missing-or-empty"})
    assert "record None" not in anchor
    assert "checkpoint-log-missing-or-empty" in anchor
    assert panels.LEDGER_VERIFY_CMD in anchor

    bare = panels.ledger_failure_text({"verified": False})
    assert "None" not in bare and panels.LEDGER_VERIFY_CMD in bare

    assert "panels.ledger_failure_text" in APP_SOURCE
    assert "first_bad_index" not in APP_SOURCE, "the app must not format the index itself"


def test_ledger_status_carries_the_verifier_reason(tmp_path, monkeypatch):
    """ledger_status used to return only (verified, first_bad_index), so an
    anchor failure reached the panel as `None` and nothing else. The reason is
    carried through when the installed verify_cli reports one, and its absence
    on the older two-value API is handled rather than rendered."""
    import sys
    import types

    from ledger.ledger import Ledger

    led = Ledger(tmp_path / "audit_chain.jsonl",
                 checkpoint_path=tmp_path / "checkpoints.jsonl")
    led.append({"host": "10.0.0.1", "window_start": 1.0, "probability": 0.9,
                "stage": "recon", "technique": "T1046"})
    led.checkpoint()

    def stub_verifier(*, detailed: bool) -> None:
        mod = types.ModuleType("ledger.verify_cli")
        mod.verify = lambda *a, **k: (False, None)
        if detailed:
            mod.verify_detailed = lambda *a, **k: (False, None, "checkpoint-unsigned")
        monkeypatch.setitem(sys.modules, "ledger.verify_cli", mod)

    stub_verifier(detailed=True)
    rich = panels.ledger_status(tmp_path)
    assert rich["verified"] is False and rich["first_bad_index"] is None
    assert rich["reason"] == "checkpoint-unsigned"
    assert "checkpoint-unsigned" in panels.ledger_failure_text(rich)
    assert "record None" not in panels.ledger_failure_text(rich)

    stub_verifier(detailed=False)
    legacy = panels.ledger_status(tmp_path)
    assert legacy["reason"] is None
    assert "record None" not in panels.ledger_failure_text(legacy)


def test_what_if_result_persists_outside_the_button_branch():
    """F31: the what-if output was drawn inside `if st.button(...)`, so it
    disappeared on the next interaction. It must live in session_state, the way
    section 7's containment already does."""
    assert "st.session_state.whatif_result" in APP_SOURCE
    assert 'st.session_state.get("whatif_result")' in APP_SOURCE


# ------------------------------------------------------- the rendered shell
# AppTest executes the real script headlessly, so these assert what a judge
# actually sees rather than what the source says.


@pytest.fixture
def app():
    from streamlit.testing.v1 import AppTest

    return AppTest.from_file(str(resolve_path("app/streamlit_app.py")), default_timeout=120)


def test_empty_state_names_a_button_the_app_really_renders(app):
    """F105: assert against the LIVE button list, not against a constant."""
    at = app.run()
    assert not at.exception
    labels = [b.label for b in at.button]
    assert labels == list(panels.BUTTON_LABELS)
    assert [i.value for i in at.info] == [panels.EMPTY_STATE_HINT]
    for quoted in re.findall(r"\*\*(.+?)\*\*", at.info[0].value):
        assert quoted in " | ".join(labels)


@pytest.mark.skipif(
    _app_can_score_anything(),
    reason="this pins the click when NO bundle exists; any bundle makes the pipeline run",
)
def test_first_click_without_artifacts_shows_a_card_not_a_traceback(app):
    """F23: the finding itself — the first click on a clean machine rendered a
    red Python traceback carrying absolute filesystem paths."""
    at = app.run()
    at.button[0].click().run()

    assert not at.exception, "the app must not surface a traceback"
    assert at.error, "a failed run must leave an error card"
    body = at.error[0].value
    assert "The engine has not been trained on this machine yet" in body
    # The FILE, not the path: panels.redact_paths deliberately strips directory
    # prefixes so a projector never shows a filesystem layout, and asserting the
    # path here would be asserting the redaction had failed.
    assert "engine_threshold.json" in body
    assert "Traceback" not in body
    assert not re.search(r"[A-Za-z]:[\\/]", body), f"absolute path leaked: {body}"
    assert "python -m engine.train_engine" in [c.value for c in at.code]


def _fake_result(n_alerts: int = 2) -> dict:
    """A minimal predict_file() return so the render paths can be driven without
    the trained artifacts this machine does not have."""
    hosts = [("203.0.113.7", "recon", 0.91), ("10.20.0.10", "exfiltration", 0.77)]
    forecasts = [
        {"host": h, "window_start": 1760000130.0 + i * 5, "probability": p, "stage": s,
         "technique": "T1046", "technique_name": "Network Service Discovery",
         "top_features": [{"feature": "sent_bytes", "value": -0.4231, "contribution": 0.081}],
         "top_windows": [], "flagged_flows": [], "estimated_lead_seconds": None}
        for i, (h, s, p) in enumerate(hosts[:n_alerts])
    ]
    return {
        "n_flows": 5620, "n_host_windows": 88, "n_alerts": n_alerts, "threshold": 1.8e-05,
        "forecasts": forecasts,
        "graph": {"nodes": [{"ip": h, "peak_prob": p, "n_alerts": 1, "internal": 0}
                            for h, _, p in hosts],
                  "edges": [{"src": hosts[0][0], "dst": hosts[1][0], "weight": 800,
                             "risk": 0.91}]},
    }


@pytest.fixture
def rendered(app):
    """The app with a result already in session_state, so every panel below the
    pipeline renders without the engine."""
    app.session_state["input_path"] = "app/assets/synthetic_demo.pcap"
    app.session_state["ran_for"] = "app/assets/synthetic_demo.pcap"
    app.session_state["result"] = _fake_result()
    return app


def test_all_panels_render_without_an_exception(rendered, no_forecast_engine):
    """The matplotlib timeline and the Plotly 3D graph are built from theme
    colours; a bad colour keyword would surface here, not on the projector."""
    at = rendered.run()
    assert not at.exception
    # 1 input, 2 timeline, 3 explain, 4 what-if, 5 ledger, 6 benchmark,
    # 7 network graph, 8 k-step forecast.
    assert len(at.header) == 8
    assert [m.value for m in at.metric][:3] == ["5,620", "88", "2"]


def test_graph_labels_are_drawn_in_the_theme_colour(rendered, no_forecast_engine):
    """F29: the node labels were a hardcoded near-white on a transparent
    background — invisible on the light theme a projector defaults to. Assert
    the colours in the RENDERED figure, not in the source."""
    import json

    at = rendered.run()
    colors = panels.theme_colors()
    spec = json.loads(at.get("plotly_chart")[0].proto.spec)

    nodes = next(t for t in spec["data"] if t.get("mode") == "markers+text")
    assert nodes["textfont"]["color"] == colors["text"]
    assert nodes["marker"]["colorbar"]["tickfont"]["color"] == colors["text"]
    assert spec["layout"]["font"]["color"] == colors["text"]
    for trace in (t for t in spec["data"] if t.get("mode") == "lines"):
        assert trace["line"]["color"] in (panels.rgba(colors["alert"], 0.85),
                                          panels.rgba(colors["muted"], 0.30))


def test_the_rendered_host_picker_states_what_the_addresses_are(rendered, no_forecast_engine):
    """Assert the LIVE label, not the constant: the page must not claim a
    privacy property `engine.predict` says the data does not have."""
    at = rendered.run()
    assert not at.exception
    labels = [s.label for s in at.selectbox]
    assert panels.HOST_SELECT_REAL in labels
    assert panels.HOST_SELECT_PSEUDONYMISED not in labels


def test_a_capture_the_parser_could_not_read_is_not_rendered_as_clean(app, no_forecast_engine):
    """The engine's `unparsed_frames` reaching nowhere on screen moves the
    'silence read as safety' failure from the engine into the UI: a capture whose
    frames were all skipped would show '0 alerts' and nothing else."""
    blind = dict(_fake_result(n_alerts=0), unparsed_frames={
        "total": 812, "fraction": 1.0, "by_reason": {"ipv6": 812, "short_frame": 0}})
    app.session_state["input_path"] = "app/assets/synthetic_demo.pcap"
    app.session_state["ran_for"] = "app/assets/synthetic_demo.pcap"
    app.session_state["result"] = blind

    at = app.run()
    assert not at.exception
    assert [m.value for m in at.metric][2] == "0"
    warnings = [w.value for w in at.warning]
    assert panels.coverage_note(blind)["text"] in warnings
    assert any("nothing was seen" in w.lower() for w in warnings)


def test_an_unknown_drop_history_is_not_rendered_as_clean(app, no_forecast_engine):
    """The engine can report `known: False` — it does not know what the parser
    dropped. That is not the same as nothing having been dropped, and the page
    must not let it render as a clean result the way a known zero does."""
    from engine import predict

    blind = dict(_fake_result(n_alerts=0), unparsed_frames=predict._coverage(100, None))
    app.session_state["input_path"] = "app/assets/synthetic_demo.pcap"
    app.session_state["ran_for"] = "app/assets/synthetic_demo.pcap"
    app.session_state["result"] = blind

    at = app.run()
    assert not at.exception
    assert [m.value for m in at.metric][2] == "0"
    assert panels.COVERAGE_UNKNOWN_TEXT in [w.value for w in at.warning]


def test_sections_3_and_4_explain_themselves_when_no_host_alerted(app, no_forecast_engine):
    """A bare '4 · What-if' header with nothing under it reads as a broken panel
    on camera. With no alerts there is legitimately nothing to explain or
    ablate; the page has to SAY that rather than render an empty section."""
    quiet = _fake_result(n_alerts=0)
    app.session_state["input_path"] = "app/assets/synthetic_demo.pcap"
    app.session_state["ran_for"] = "app/assets/synthetic_demo.pcap"
    app.session_state["result"] = quiet

    at = app.run()
    assert not at.exception
    assert not at.error
    shown = [i.value for i in at.info]
    assert panels.NO_HOSTS_EXPLAIN in shown
    assert panels.NO_HOSTS_WHATIF in shown


def test_sections_3_and_4_say_so_when_the_ranking_above_failed(rendered, monkeypatch, no_forecast_engine):
    """The disclosed-but-unexplained consequence of computing `ranking` inside
    section 2's try: if that try fires, sections 3 AND 4 lose their host list and
    BOTH used to render as bare headers — two empty panels from one failure, with
    nothing on screen tying them to the error card above."""
    def boom(*a, **k):
        raise RuntimeError("ranking exploded")

    monkeypatch.setattr(panels, "host_ranking", boom)
    at = rendered.run()

    assert not at.exception, "the failure must stay a card, not a traceback"
    assert any("ranking exploded" in e.value for e in at.error)
    shown = [i.value for i in at.info]
    assert panels.RANKING_FAILED_EXPLAIN in shown
    assert panels.RANKING_FAILED_WHATIF in shown
    # and it must not be confused with the honest "no alerts" case
    assert panels.NO_HOSTS_EXPLAIN not in shown


@pytest.mark.skipif(
    _benchmark_rows_exist(),
    reason="this pins the EMPTY benchmark section; results/*.json is populated here",
)
def test_empty_benchmark_section_renders_the_bootstrap_card(rendered, no_forecast_engine):
    """F104: with results/ absent the section used to be a bare header.

    It shows the bootstrap card instead — and NOT the population caveat, which is
    about how to read rows that are not there. A caveat printed over an empty
    section is noise, and noise is how a reader learns to skip the caveats that
    matter (panels.benchmark_caveats owns that rule)."""
    at = rendered.run()
    assert panels.BENCHMARK_EMPTY_HINT in [i.value for i in at.info]
    assert panels.BENCHMARK_EMPTY_COMMANDS in [c.value for c in at.code]
    assert panels.BENCHMARK_CAVEAT not in [w.value for w in at.warning], (
        "the population caveat qualifies rows; with no rows it must stay silent"
    )
    assert panels.benchmark_caveats({}, has_rows=False) == [], (
        "and the rule lives in the panel, not in this assertion"
    )


def test_what_if_result_survives_the_next_interaction(rendered, monkeypatch, no_forecast_engine):
    """F31: the output was drawn inside the button branch, so it vanished on the
    very next rerun. Drive a real interaction and assert it is still there."""
    after = dict(_fake_result(), n_flows=1200, n_alerts=1)
    monkeypatch.setattr(panels, "what_if_remove_host",
                        lambda *a, **k: {"removed_host": a[2], "after": after})

    at = rendered.run()

    def metrics():
        return {m.label: m.value for m in at.metric
                if m.label in ("Alerts before", "Alerts after")}

    assert metrics() == {}
    [b for b in at.button if b.label == "Run what-if"][0].click().run()
    assert metrics() == {"Alerts before": "2", "Alerts after": "1"}

    at.selectbox[0].select("10.20.0.10").run()  # any unrelated widget
    assert metrics() == {"Alerts before": "2", "Alerts after": "1"}, "what-if vanished"

    [b for b in at.button if b.label == "Clear what-if"][0].click().run()
    assert metrics() == {}


# ------------------------------------------------- k-step forecast (PS deliverable 3)
# The panel answers "what does this host look like over the next k windows". The
# project's audit established that the k-step head has a ranking signal and NO
# validated operating point at any horizon, so half of what these tests pin is
# that the panel says so — in the page copy, in the chart itself, and in the
# column headers, which are the three places a judge reads before a footnote.


def _fake_forecast(newest_first: bool = False, **overrides) -> dict:
    """A `forecast_file` return in the shape of the shared k-step API contract.

    Not a stand-in for the engine's judgement — it never reaches a page — but the
    exact shape both workstreams agreed on, so a contract change breaks a test
    here rather than a panel on a projector.

    `newest_first` flips the order of the two source windows in `forecast`. The
    contract fixes no order, and the ordering decides whether a join bug is
    visible at all: with the newest row LAST, a panel that simply kept the last
    entry per k would pass a newest-window test while doing no join. Both orders
    are exercised, so the assertion cannot be satisfied by accident.
    """
    host, stride, newest = "203.0.113.7", 5.0, 1760000130.0
    ks = (1, 2, 4)
    stage = {1: "recon", 2: "recon", 4: "lateral_movement"}
    prob = {1: 0.31, 2: 0.44, 4: 0.62}
    windows = (newest, newest - stride) if newest_first else (newest - stride, newest)
    rows = []
    for start in windows:                     # an older window the join must ignore
        current = start == newest
        for k in ks:
            rows.append({
                "host": host, "window_start": start, "k": k, "seconds_ahead": k * stride,
                "probability": prob[k] if current else 0.02,
                "stage": stage[k] if current else "benign",
                "technique": "T1046" if current else None,
                "alert": bool(current and k == 4), "threshold": 1.8e-05,
            })
    fc = dict(_fake_result(), **{
        "horizons": list(ks),
        "stride_seconds": stride,
        "unavailable_horizons": {8: "no persisted k=8 model in artifacts/"},
        "forecast": rows,
        "per_host_curve": {host: [
            {"k": k, "seconds_ahead": k * stride, "probability": prob[k],
             "alert": bool(k == 4)} for k in ks]},
        # engine.forecast ships its own caveat in the return value for the UI to
        # render; the double carries one so the render path is really exercised.
        "forecast_caveat": FAKE_ENGINE_CAVEAT,
    })
    fc.update(overrides)
    return fc


FAKE_FORECAST_HOST = "203.0.113.7"
FAKE_ENGINE_CAVEAT = (
    "Forward forecast: RANKING SIGNAL ONLY - not a validated early-warning operating point."
)


@pytest.fixture
def stub_forecast_engine(monkeypatch):
    """Install a stand-in `engine.forecast` so the UI can be driven here.

    The real module ships from another workstream and needs artifacts this
    machine does not have. The double exists only inside a test process:
    panels.run_forecast imports the module BY NAME, so on a machine without it
    the page renders the absent state instead — no stub output ever reaches a
    judge, which is the whole point of not stubbing the engine in app code.
    """
    import sys
    import types

    def install(forecast_file):
        module = types.ModuleType(panels.FORECAST_MODULE)
        # find_spec() consults sys.modules first and raises on a None __spec__.
        module.__spec__ = importlib.util.spec_from_loader(panels.FORECAST_MODULE, loader=None)
        if forecast_file is not None:
            module.forecast_file = forecast_file
        monkeypatch.setitem(sys.modules, panels.FORECAST_MODULE, module)
        import engine

        monkeypatch.setattr(engine, "forecast", module, raising=False)
        return module

    return install


@pytest.fixture
def no_forecast_engine(monkeypatch):
    """Force the "no k-step engine in this checkout" state whether or not
    engine/forecast.py exists, so the honest empty state is pinned on every
    machine rather than only on the ones that happen to lack the module.

    Every AppTest about sections 1-7 also takes it. Section 8 re-runs the whole
    pipeline, so without this those tests would quietly depend on whether the
    forecaster is installed and would run a second pipeline on any machine that
    HAS the artifacts — neither of which is what they are about. run_forecast
    checks find_spec before it calls anything, so this is also instant."""
    real = importlib.util.find_spec
    monkeypatch.setattr(
        panels.importlib.util, "find_spec",
        lambda name, *a, **k: None if name == panels.FORECAST_MODULE else real(name, *a, **k),
    )


def test_forecast_caveat_quotes_the_limitations_doc():
    """The caveat is the load-bearing half of this panel: it is what stops a
    rising curve being read as validated prediction. Every figure in it is
    pinned to docs/limitations.md in both directions, so the panel cannot drift
    into claiming more than the document supports, and the document cannot
    quietly stop supporting what the panel says."""
    doc = " ".join(resolve_path("docs/limitations.md")
                   .read_text(encoding="utf-8").replace("**", "").split())
    caveat = panels.FORECAST_HEADER_CAVEAT.replace("**", "")
    for quote in panels.FORECAST_LIMITATION_QUOTES:
        _require_pinned_wording(
            doc, quote, doc="docs/limitations.md (whitespace-normalised, emphasis stripped)",
            mirror="app/panels.py::FORECAST_HEADER_CAVEAT (rendered above the k-step curve)",
            why="the k-step panel draws a rising risk curve, which a judge will read as "
                "forward prediction unless told otherwise. The caveat above it quotes these "
                "figures as the reason not to; if the document no longer carries one, the "
                "page is citing a source that does not support it",
        )
        assert quote in caveat, f"the caveat stopped saying {quote!r}"

    # and the chart carries the operating-point failure itself, because a
    # screenshot of the curve travels without the warning rendered above it
    assert "0/2 episodes at k=1, 4 and 8" in panels.FORECAST_FIGURE_CAVEAT
    assert "panels.FORECAST_HEADER_CAVEAT" in APP_SOURCE
    assert "panels.FORECAST_FIGURE_CAVEAT" in APP_SOURCE


def test_the_caveat_is_drawn_inside_the_axes_not_beside_them():
    """Walk the AST rather than grep the source: the caveat must be an argument
    to the figure's own set_title, so it is baked into the PNG. Moved to a
    caption beside the chart it would be true on the page and absent from every
    screenshot of it."""
    tree = ast.parse(APP_SOURCE)
    figure = next(n for n in ast.walk(tree)
                  if isinstance(n, ast.FunctionDef) and n.name == "_kstep_figure")
    titled = [
        call for call in ast.walk(figure)
        if isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute)
        and call.func.attr == "set_title"
        and any(isinstance(a, ast.Attribute) and a.attr == "FORECAST_FIGURE_CAVEAT"
                for a in call.args)
    ]
    assert titled, "_kstep_figure must render FORECAST_FIGURE_CAVEAT into the axes"


def test_the_curve_columns_do_not_promote_a_ranking_into_an_alert():
    """Column headers are read before any caveat. At this operating point a
    crossing is not a validated alert and the score is claimed only as a
    ranking, so neither header may say otherwise."""
    assert "ranking score" in panels.KSTEP_SCORE_COLUMN
    assert panels.KSTEP_ALERT_COLUMN == "crosses k-step threshold"

    rows = panels.kstep_curve_rows(panels.kstep_curve(_fake_forecast(), FAKE_FORECAST_HOST))
    assert rows and all(set(r) == {"horizon_k", "seconds_ahead", panels.KSTEP_SCORE_COLUMN,
                                   "threshold", panels.KSTEP_ALERT_COLUMN, "stage",
                                   "technique"} for r in rows)
    assert all("alert" not in r and "probability" not in r for r in rows)
    assert [r[panels.KSTEP_ALERT_COLUMN] for r in rows] == [False, False, True]


@pytest.mark.parametrize("newest_first", [False, True])
def test_kstep_curve_joins_the_newest_window_not_an_older_one(newest_first):
    """`per_host_curve` is the newest source window per host; the threshold,
    stage and technique come from the per-(host, window, k) rows. Joining on any
    other window would caption one window's curve with another window's stage.

    Both row orders are run because only one of them can catch the likely bug:
    with the newest entry last, "keep whatever came last" passes without ever
    comparing a window_start."""
    curve = panels.kstep_curve(_fake_forecast(newest_first), FAKE_FORECAST_HOST)
    assert list(curve["k"]) == [1, 2, 4]
    assert list(curve["seconds_ahead"]) == [5.0, 10.0, 20.0]
    assert list(curve["probability"]) == [0.31, 0.44, 0.62]
    assert list(curve["stage"]) == ["recon", "recon", "lateral_movement"]
    assert "benign" not in list(curve["stage"]), "the older window's stage leaked in"
    assert list(curve["technique"]) == ["T1046"] * 3
    assert list(curve["alert"]) == [False, False, True]


def test_kstep_curve_never_invents_a_seconds_ahead_it_was_not_given():
    """The fallback to k x stride is allowed only because the contract DEFINES
    seconds_ahead that way. With no stride either, the cell stays empty: a panel
    that filled it with a plausible number would be writing a figure instead of
    reading one, which is the failure mode this repo keeps removing."""
    fc = _fake_forecast()
    for point in fc["per_host_curve"][FAKE_FORECAST_HOST]:
        point.pop("seconds_ahead")
    assert list(panels.kstep_curve(fc, FAKE_FORECAST_HOST)["seconds_ahead"]) == [5.0, 10.0, 20.0]

    fc.pop("stride_seconds")
    blind = panels.kstep_curve(fc, FAKE_FORECAST_HOST)
    assert blind["seconds_ahead"].isna().all()
    assert panels.kstep_plottable(blind).empty, "an unplottable point must not be plotted"
    assert len(panels.kstep_curve_rows(blind)) == 3, "but it must still be in the table"


def test_an_unavailable_horizon_is_stated_never_dropped():
    """A curve that silently skips k=8 reads as a forecast that covered every
    horizon it was asked for."""
    assert panels.kstep_unavailable_rows(_fake_forecast()) == [
        {"horizon_k": 8,
         "why there is no forecast at this horizon": "no persisted k=8 model in artifacts/"}
    ]
    assert panels.kstep_unavailable_rows({}) == []
    assert panels.kstep_unavailable_rows({"unavailable_horizons": {"oops": "not an int"}}) == [
        {"horizon_k": "oops", "why there is no forecast at this horizon": "not an int"}
    ]


@pytest.mark.parametrize("fc, expected", [
    ({}, "FORECAST_NO_HORIZONS_TEXT"),
    ({"horizons": [], "per_host_curve": {}}, "FORECAST_NO_HORIZONS_TEXT"),
    ({"horizons": [1, 4], "per_host_curve": {}}, "FORECAST_NO_CURVE_TEXT"),
    ({"horizons": [1, 4], "per_host_curve": {"10.0.0.1": []}}, "FORECAST_NO_CURVE_TEXT"),
])
def test_kstep_empty_reason_separates_no_model_from_no_curve(fc, expected):
    """Two emptinesses that render identically and are not the same thing: a
    forecaster with no persisted horizon at all, and one with horizons that
    returned nothing for THIS input. They have different fixes."""
    assert panels.kstep_empty_reason(fc) == getattr(panels, expected)


def test_the_panel_shows_the_engines_own_caveat_and_does_not_relabel_the_stage():
    """Two claims the engine makes about itself that the panel must not soften.

    engine.forecast ships FORWARD_FORECAST_CAVEAT in its return value so a UI can
    show it; if the page only ever recited a constant of its own, a change in the
    engine's measured finding would never reach the screen. And the engine
    derives `stage` from the SOURCE window — it has no future features — so the
    table heading must not sell it as a predicted progression."""
    assert panels.kstep_engine_caveat(_fake_forecast()) == FAKE_ENGINE_CAVEAT
    assert panels.kstep_engine_caveat({}) is None
    assert panels.kstep_engine_caveat({"forecast_caveat": "   "}) is None

    from engine import forecast as real

    assert panels.kstep_engine_caveat({"forecast_caveat": real.FORWARD_FORECAST_CAVEAT})

    heading = panels.FORECAST_STAGE_TABLE_HEADING.lower()
    assert "not a predicted future stage" in heading
    assert "predicted stage progression" not in heading
    caption = panels.FORECAST_CURVE_CAPTION.replace("**", "")
    assert "describe the SOURCE window's observed pattern" in caption
    assert "panels.FORECAST_STAGE_TABLE_HEADING" in APP_SOURCE
    assert "panels.kstep_engine_caveat" in APP_SOURCE


def test_kstep_empty_reason_is_none_when_there_is_something_to_draw():
    assert panels.kstep_empty_reason(_fake_forecast()) is None


def test_kstep_hosts_rank_by_peak_and_keep_a_scoreless_host_visible():
    fc = _fake_forecast()
    fc["per_host_curve"]["10.20.0.10"] = [
        {"k": 1, "seconds_ahead": 5.0, "probability": 0.95, "alert": False}]
    fc["per_host_curve"]["10.20.0.99"] = [
        {"k": 1, "seconds_ahead": 5.0, "probability": None, "alert": False}]

    hosts = panels.kstep_hosts(fc)
    assert hosts[:2] == ["10.20.0.10", FAKE_FORECAST_HOST]
    assert "10.20.0.99" in hosts, (
        "a host whose scores came back unreadable must stay in the picker — its curve "
        "then renders as blanks, which says something; vanishing says nothing"
    )
    assert panels.kstep_hosts({}) == []


def test_log_scale_kicks_in_when_the_threshold_is_orders_below_the_score():
    """A 1%-FPR threshold on the raw score scale can be ~1e-5 against scores of
    ~1e-1. On one linear axis the threshold lies on the x-axis and every point
    reads as a dramatic crossing — flattering, and wrong."""
    assert panels.kstep_use_log_scale(panels.kstep_curve(_fake_forecast(), FAKE_FORECAST_HOST))

    flat = _fake_forecast()
    for row in flat["forecast"]:
        row["threshold"] = 0.25
    assert not panels.kstep_use_log_scale(panels.kstep_curve(flat, FAKE_FORECAST_HOST))


def test_run_forecast_reports_an_absent_forecaster_as_absent(tmp_path, no_forecast_engine):
    """engine/forecast.py ships from another workstream and is not in every
    checkout. Absence has to be an empty state naming what is missing — not a
    ModuleNotFoundError card telling a judge to `pip install` something that
    was never a dependency."""
    with pytest.raises(panels.ForecastUnavailable) as excinfo:
        panels.run_forecast("capture.pcap", tmp_path)
    assert str(excinfo.value) == panels.FORECAST_MISSING_TEXT
    assert "stubbed or simulated" in panels.FORECAST_MISSING_TEXT


def test_a_forecaster_that_fails_to_import_is_not_reported_as_missing(
        tmp_path, stub_forecast_engine):
    """The other direction, and the reason absence is detected with find_spec
    rather than by catching ImportError: a forecaster that IS shipped but whose
    own import blows up (a missing third-party dependency, a syntax error) must
    surface as the failure it is. "Not shipped" and "shipped and broken" have
    different fixes and must not render identically."""
    module = stub_forecast_engine(None)

    def explode(name):
        raise ModuleNotFoundError("No module named 'lightgbm'", name="lightgbm")

    module.__getattr__ = explode        # PEP 562: any attribute lookup now raises
    with pytest.raises(ModuleNotFoundError) as excinfo:
        panels.run_forecast("capture.pcap", tmp_path)

    assert excinfo.value.name == "lightgbm"
    assert panels.failure_card(excinfo.value)["title"] == "A dependency is missing (lightgbm)"


def test_run_forecast_reports_a_forecaster_with_no_entry_point(tmp_path, stub_forecast_engine):
    stub_forecast_engine(None)
    with pytest.raises(panels.ForecastUnavailable) as excinfo:
        panels.run_forecast("capture.pcap", tmp_path)
    assert str(excinfo.value) == panels.FORECAST_NO_ENTRYPOINT_TEXT


def test_run_forecast_writes_beside_the_nowcast_ledger_not_into_it(tmp_path, stub_forecast_engine):
    """The forecaster re-runs the pipeline, and the pipeline appends to a ledger.
    Section 5 shows the record count of the chain the NOWCAST wrote and then
    tampers with record 0; a second pipeline appending to that same chain would
    move those numbers under the judge's feet between the two beats."""
    seen = {}

    def fake(input_path, out_dir, fpr_budget=0.01):
        seen.update(input_path=input_path, out_dir=Path(out_dir), fpr_budget=fpr_budget)
        return _fake_forecast()

    stub_forecast_engine(fake)
    out = panels.run_forecast("capture.pcap", tmp_path, fpr_budget=0.02)

    assert seen["out_dir"] == tmp_path / panels.FORECAST_SUBDIR
    assert seen["out_dir"] != tmp_path, "the forecaster shares the nowcast's ledger directory"
    assert seen["fpr_budget"] == 0.02
    assert out["per_host_curve"], "run_forecast must pass the engine's result straight through"


def test_the_real_forecaster_matches_the_shared_api_contract():
    """When engine/forecast.py lands, its entry point must be the one this panel
    calls. Signature only — running it needs artifacts that are not on this
    machine, and this test must not pretend otherwise."""
    if importlib.util.find_spec(panels.FORECAST_MODULE) is None:
        pytest.skip("engine/forecast.py is not in this checkout yet (built in another workstream)")
    from engine import forecast

    assert hasattr(forecast, "forecast_file"), panels.FORECAST_NO_ENTRYPOINT_TEXT
    assert list(inspect.signature(forecast.forecast_file).parameters)[:3] == [
        "input_path", "out_dir", "fpr_budget"]


# ---------------------------------------------------- the rendered forecast panel


def test_the_forecast_panel_leads_with_its_limitation_when_nothing_can_be_drawn(
        rendered, no_forecast_engine):
    """The caveat has to render on EVERY path through this section, including the
    ones where no curve is ever drawn — it is true regardless of what the engine
    returned, and a judge who scrolls to a header with only an empty state under
    it still has to see it."""
    at = rendered.run()
    assert not at.exception
    assert panels.FORECAST_HEADER_CAVEAT in [w.value for w in at.warning]
    assert panels.FORECAST_MISSING_TEXT in [i.value for i in at.info]
    assert not at.error, "an absent forecaster is an empty state, not a failure card"
    # st.pyplot renders as an image element: only section 2's timeline is drawn,
    # so no curve was invented to fill the section. The paired assertion is in
    # test_the_rendered_forecast_panel_draws_a_curve_..., which sees two.
    assert len(at.get("image")) == 1


def test_the_rendered_forecast_panel_draws_a_curve_and_states_the_missing_horizon(
        rendered, stub_forecast_engine):
    """Drive the whole section through AppTest against the contract shape: the
    curve is drawn, the caveat is still above it, and the horizon the engine
    could not forecast is on the page rather than quietly absent."""
    stub_forecast_engine(lambda input_path, out_dir, fpr_budget=0.01: _fake_forecast())

    at = rendered.run()
    assert not at.exception
    assert not at.error

    # two server-side charts now: the section-2 timeline and the k-step curve
    # (st.pyplot lands in the element tree as an image)
    assert len(at.get("image")) == 2
    captions = [c.value for c in at.caption]
    assert panels.FORECAST_HEADER_CAVEAT in [w.value for w in at.warning]
    assert panels.FORECAST_CURVE_CAPTION in captions
    assert panels.FORECAST_MISSING_TEXT not in [i.value for i in at.info]
    assert "Risk curve for host" in [s.label for s in at.selectbox]

    # the ENGINE's own caveat, rendered verbatim rather than paraphrased
    assert any(FAKE_ENGINE_CAVEAT in c for c in captions), (
        "engine.forecast ships forecast_caveat for the UI to show; it never reached the page"
    )

    markdown = [m.value for m in at.markdown]
    assert panels.FORECAST_STAGE_TABLE_HEADING in markdown
    assert not any("predicted stage progression" in m.lower() for m in markdown), (
        "engine.forecast derives stage from the SOURCE window; calling it a predicted "
        "progression claims a future stage the engine has no features to infer"
    )
    assert any("Horizons with no forecast" in m for m in markdown), (
        "the k=8 the engine reported as unavailable never reached the page"
    )


def test_a_forecaster_that_raises_becomes_a_card_not_a_traceback(rendered, stub_forecast_engine):
    """A forecaster that IS here and fails is a real failure with a real fix, so
    it gets the same operator card as every other panel — and no traceback, which
    would put absolute paths on the projector."""
    def explode(input_path, out_dir, fpr_budget=0.01):
        raise FileNotFoundError(
            "C:\\Users\\John Smith\\artifacts\\engine_threshold missing — run "
            "`python -m engine.train_engine`")

    stub_forecast_engine(explode)
    at = rendered.run()

    assert not at.exception
    body = " ".join(e.value for e in at.error)
    assert "The engine has not been trained on this machine yet" in body
    assert "John" not in body and "Smith" not in body
    assert not re.search(r"[A-Za-z]:[\\/]", body), f"absolute path leaked: {body}"
    # the caveat still renders above the failure
    assert panels.FORECAST_HEADER_CAVEAT in [w.value for w in at.warning]


# ------------------------- retired claims on the surface a judge actually reads
# tests/test_docs_claims.py is this repo's ratchet for retired claims, and its
# BANNED list is imported at the top of this module rather than restated here: a
# claim retired there is banned on this page in the same commit, and there is no
# second list to keep in step.
#
# The two guards divide by SCOPE, not by claim, and that is the whole contract:
#   * test_docs_claims.py scans the SOURCE TEXT of the files in its scope --
#     every byte of them, comments and docstrings included.
#   * this one scans the strings that reach a VIEWER: the arguments of the calls
#     that put text on the page, resolved through app.panels, on every branch of
#     the script, whether or not this machine can render that branch.
#
# The second scope is the one that was empty when a retired claim about the
# deployed scorer sat in the benchmark caption of app/streamlit_app.py. It was
# rendered on the running demo page, under the benchmark card, and it was in no
# document the ratchet scanned -- the one surface neither guard was watching.
#
# Why the set is extracted STATICALLY and not simply read off AppTest: the
# caption that carried that claim renders only when results/*.json exists, and a
# fresh clone has none (BENCHMARK_EMPTY_HINT is what shows instead). A guard
# built on what AppTest happens to render on this machine would have passed on
# the exact sentence it exists to catch. The live half is
# test_the_repaired_benchmark_caption_is_on_the_page_a_judge_sees, which drives
# that branch on purpose and ties the static set back to the real page.

# Methods that put text in front of a viewer, matched by METHOD NAME on any
# receiver rather than as `st.<name>`. This page renders through column handles
# (`cc1.selectbox`, `m1.metric`) and through matplotlib axes -- `ax.set_title`
# is what carries FORECAST_FIGURE_CAVEAT INTO the figure, which is the copy that
# travels when someone screenshots the curve. A guard keyed on the `st.` prefix
# would see none of those. Over-matching costs nothing: a same-named method on
# some other object contributes strings that simply are not banned.
VISIBLE_TEXT_METHODS = frozenset({
    "caption", "code", "markdown", "header", "subheader", "title", "text", "write",
    "info", "warning", "error", "success", "exception", "toast", "metric",
    "button", "download_button", "link_button", "selectbox", "multiselect", "radio",
    "checkbox", "toggle", "slider", "select_slider", "text_input", "text_area",
    "number_input", "date_input", "time_input", "file_uploader", "expander",
    "tabs", "spinner", "status", "dataframe", "table", "json", "help",
    "set_title", "suptitle", "set_xlabel", "set_ylabel", "annotate", "legend",
})


def _panels_constant_value(node) -> list[str]:
    """`panels.SOME_CONSTANT` in the UI module -> the string(s) it really holds.

    Resolved against the imported module, not re-typed here, so a constant whose
    wording changes is re-checked at its new wording and a constant that is
    deleted stops contributing instead of being asserted from memory.
    """
    if not (isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name)
            and node.value.id == "panels" and node.attr.isupper()):
        return []
    value = getattr(panels, node.attr, None)
    if isinstance(value, str):
        return [value]
    if isinstance(value, (list, tuple)):
        return [v for v in value if isinstance(v, str)]
    return []


def user_visible_strings() -> list[tuple[str, str]]:
    """(where it comes from, the text) for everything this app can put on screen.

    Two sources, because the page has two:

    1. Every text-rendering call in app/streamlit_app.py, walked whole -- its
       literals (adjacent string literals are already one Constant by the time
       ast sees them, so a caption split across source lines is scanned as the
       sentence a viewer reads), the constant parts of its f-strings, and the
       app.panels constants it passes through.

    2. Every public string constant in app/panels.py, which is where that
       module's docstring says the operator-facing strings live. This source is
       not redundant: `host_selector_label()` RETURNS HOST_SELECT_REAL, so no
       AST walk of the UI module can see that string reach the picker.

    Deliberately not de-duplicated: `where` is what a failure needs in order to
    name the line to edit, and the same sentence can reach the page twice.
    """
    found: list[tuple[str, str]] = []
    for node in ast.walk(ast.parse(APP_SOURCE)):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and node.func.attr in VISIBLE_TEXT_METHODS):
            continue
        where = f"app/streamlit_app.py:{node.lineno} {node.func.attr}()"
        for child in ast.walk(node):
            if isinstance(child, ast.Constant) and isinstance(child.value, str):
                found.append((where, child.value))
            found.extend((where, text) for text in _panels_constant_value(child))
    for name in sorted(dir(panels)):
        if not name.isupper():
            continue
        value = getattr(panels, name)
        where = f"app/panels.py::{name}"
        if isinstance(value, str):
            found.append((where, value))
        elif isinstance(value, (list, tuple)):
            found.extend((where, item) for item in value if isinstance(item, str))
    return found


def _sources_of(text: str) -> list[str]:
    return [where for where, found in user_visible_strings() if found == text]


@pytest.mark.parametrize("claim", RETIRED_CLAIMS, ids=lambda c: c.slug)
def test_no_retired_claim_reaches_the_apps_user_visible_strings(claim):
    """The guard the benchmark caption needed and did not have.

    Each string is scanned on its own, so an exemption in the ratchet's
    `allow_exact` only covers the string that actually contains the retracting
    sentence -- FORECAST_HEADER_CAVEAT may state that there is no supported
    forward-forecast horizon; the caption beside it may not acquire that phrase
    by being nearby.
    """
    offenders = []
    for where, text in user_visible_strings():
        for excerpt in claim_hits(claim_normalise(text), claim):
            offenders.append(f"{where}\n      {excerpt}")
    assert not offenders, (
        f"\nThe app shows a viewer a claim this project retired [{claim.slug}], at "
        f"{len(offenders)} place(s).\n\nWHY IT IS BANNED: {claim.why}\n\n"
        + "\n\n".join(offenders)
        + "\n\nThis is a string on the page, not a comment: fix the wording so it "
        "says what was measured. README.md and docs/architecture.md carry the "
        "corrected phrasing -- mirror one of them rather than inventing a third. "
        "Do NOT quote the retired sentence here in order to retract it; that quote "
        "belongs in tier1_hardening_report.md, which neither guard scans."
    )


def test_the_user_visible_sweep_reaches_every_way_this_page_shows_text():
    """The guard for the guard, and the reason it has four cases rather than one.

    A sweep that quietly stopped finding strings would pass the test above for
    ever. Each case below reaches the page by a DIFFERENT mechanism and is
    asserted against the source that must supply it, so no case can be carried
    by another one:

    * the benchmark note is a panels constant CONCATENATED into st.caption -- it
      proves the walk resolves `panels.NAME` inside a call rather than only
      literals (this is the repaired surface itself);
    * the model-comparison heading exists only as an inline literal;
    * FORECAST_FIGURE_CAVEAT reaches the page through `ax.set_title`, so it
      proves non-`st.` receivers are walked -- and it is required FROM THE UI
      MODULE specifically, because the panels sweep would otherwise supply it
      and hide a walk that had stopped matching axes methods;
    * HOST_SELECT_REAL is returned by a function, so the UI module's AST cannot
      see it at all and only the panels sweep can -- which is what makes that
      second source load-bearing rather than decorative.
    """
    cases = (
        ("panels constant passed into a render call", panels.DEPLOYED_MODEL_NOTE,
         "app/streamlit_app.py:", None),
        ("literal written inline in the UI module",
         "**Model comparison (test split, 1% FPR budget)**",
         "app/streamlit_app.py:", None),
        ("text drawn into the matplotlib axes, not through st.*",
         panels.FORECAST_FIGURE_CAVEAT, "app/streamlit_app.py:", "set_title()"),
        ("constant a function returns, invisible to the UI module's AST",
         panels.HOST_SELECT_REAL, "app/panels.py::HOST_SELECT_REAL", None),
    )
    for description, text, required_source, must_mention in cases:
        sources = _sources_of(text)
        assert any(s.startswith(required_source) for s in sources), (
            f"user_visible_strings() no longer finds the {description}. It must "
            f"come from {required_source!r}; found in {sources or 'nothing at all'}. "
            "The sweep has stopped covering one of the ways this page shows text, "
            "so test_no_retired_claim_reaches_the_apps_user_visible_strings is now "
            "blind to it. Fix the sweep, not this assertion."
        )
        if must_mention:
            assert any(must_mention in s for s in sources), (
                f"the {description} is no longer picked up via {must_mention}: "
                f"{sources}. VISIBLE_TEXT_METHODS has stopped matching the "
                "receiver that actually renders it."
            )


@pytest.fixture
def benchmark_results(monkeypatch):
    """Make section 6's tables non-empty so the branch that carries the caption
    really renders.

    On a fresh clone `results/*.json` does not exist, both frames come back empty
    and the page takes the bootstrap-card branch instead -- which is exactly how
    a retired claim lived in that caption without any rendered-output test
    tripping over it. The stand-in frames carry no figures: this fixture exists
    to open a branch, and a benchmark number invented in a fixture is the same
    defect in a smaller font.
    """
    def stand_in(*args, **kwargs):
        return pd.DataFrame([{"row": "stand-in, so the caption's branch renders"}])

    monkeypatch.setattr(panels, "forecast_horizons", stand_in)
    monkeypatch.setattr(panels, "results_card", stand_in)


def _rendered_text(at) -> list[str]:
    """Everything with words on it that AppTest actually produced."""
    out: list[str] = []
    for group in (at.caption, at.markdown, at.warning, at.info, at.error, at.code,
                  at.header, at.subheader, at.title, at.success):
        out.extend(getattr(element, "value", "") for element in group)
    for group in (at.selectbox, at.button, at.file_uploader):
        out.extend(getattr(element, "label", "") for element in group)
    return [text for text in out if isinstance(text, str) and text]


def test_the_repaired_benchmark_caption_is_on_the_page_a_judge_sees(
        rendered, benchmark_results, no_forecast_engine):
    """The live half: drive the benchmark branch and read the caption off the
    rendered page, then scan everything else that page rendered with it.

    This is what stops the static sweep above from guarding a string nobody can
    see. It is deliberately the second test and not the only one -- without the
    fixture above, this branch never opens on a bare checkout, and that blind
    spot is how the claim survived.
    """
    at = rendered.run()
    assert not at.exception

    captions = [c.value for c in at.caption]
    assert any(panels.DEPLOYED_MODEL_NOTE in c for c in captions), (
        "the benchmark caption is not on the rendered page, so the static sweep "
        f"is guarding a string a judge never sees. Captions rendered: {captions}"
    )

    shown = _rendered_text(at)
    assert len(shown) > 20, f"the page rendered almost nothing: {shown}"
    for claim in RETIRED_CLAIMS:
        for text in shown:
            assert not claim_hits(claim_normalise(text), claim), (
                f"a rendered element re-states a retired claim [{claim.slug}]: "
                f"{text!r}\n\nWHY IT IS BANNED: {claim.why}"
            )


def test_a_run_without_an_anonymisation_key_says_so():
    """No key means `internal` and `net24_bucket` are 0 for every host, which moves
    every score away from the published ones. A run that degraded must say it did;
    a run that did not must stay quiet, or the warning becomes noise people learn
    to ignore."""
    degraded = panels.role_features_degraded_note({"role_features_degraded": True})
    assert degraded is not None, "a keyless run must be disclosed on the page"
    assert degraded["severity"] == "warning"
    for token in ("internal", "net24_bucket", "SIH26_HMAC_KEY", "not comparable"):
        assert token in degraded["text"], (
            f"the disclosure must name {token!r} — a vague warning does not let a "
            "reader work out what is wrong with the numbers in front of them"
        )

    for quiet in ({"role_features_degraded": False}, {}, {"role_features_degraded": None}):
        assert panels.role_features_degraded_note(quiet) is None, (
            f"{quiet!r} is not a degraded run and must not raise the warning"
        )


def test_the_engine_reports_whether_role_features_were_degraded():
    """The page can only disclose what the engine measures. Pin the producer too,
    so the note cannot become permanently silent by the key simply never being set
    in the result dict."""
    from engine import predict as P

    assert P.role_features_degraded(None) is True, "no anonymiser means degraded"
    assert P.role_features_degraded(object()) is False, "an anonymiser means not degraded"
