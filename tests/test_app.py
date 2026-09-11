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

import pandas as pd
import pytest

from app import panels
from configs import resolve_path


def _engine_ready() -> bool:
    return (importlib.util.find_spec("xgboost") is not None
            and resolve_path("artifacts/engine_model.json").exists())


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
    _engine_ready(),
    reason="this pins the NO-artifacts first click; with artifacts the pipeline runs",
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
    assert "artifacts/engine_threshold.json" in body
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


def test_all_panels_render_without_an_exception(rendered):
    """The matplotlib timeline and the Plotly 3D graph are built from theme
    colours; a bad colour keyword would surface here, not on the projector."""
    at = rendered.run()
    assert not at.exception
    assert len(at.header) == 7
    assert [m.value for m in at.metric][:3] == ["5,620", "88", "2"]


def test_graph_labels_are_drawn_in_the_theme_colour(rendered):
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


def test_the_rendered_host_picker_states_what_the_addresses_are(rendered):
    """Assert the LIVE label, not the constant: the page must not claim a
    privacy property `engine.predict` says the data does not have."""
    at = rendered.run()
    assert not at.exception
    labels = [s.label for s in at.selectbox]
    assert panels.HOST_SELECT_REAL in labels
    assert panels.HOST_SELECT_PSEUDONYMISED not in labels


def test_a_capture_the_parser_could_not_read_is_not_rendered_as_clean(app):
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


def test_an_unknown_drop_history_is_not_rendered_as_clean(app):
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


def test_sections_3_and_4_explain_themselves_when_no_host_alerted(app):
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


def test_sections_3_and_4_say_so_when_the_ranking_above_failed(rendered, monkeypatch):
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


def test_empty_benchmark_section_renders_the_bootstrap_card(rendered):
    """F104: with results/ absent the section used to be a bare header."""
    at = rendered.run()
    assert panels.BENCHMARK_EMPTY_HINT in [i.value for i in at.info]
    assert panels.BENCHMARK_EMPTY_COMMANDS in [c.value for c in at.code]
    assert panels.BENCHMARK_CAVEAT in [w.value for w in at.warning]


def test_what_if_result_survives_the_next_interaction(rendered, monkeypatch):
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
