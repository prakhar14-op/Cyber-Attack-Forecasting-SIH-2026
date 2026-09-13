"""Shared fixtures. Paths come from configs/data.yaml, never from literals.

Also the LANE POLICY: which tests may run against the demo model fitted from the
bundled synthetic capture, and which must keep skipping until the published
artifacts are on disk. See the block comment above DEMO_LANE_ALLOWED.
"""

from __future__ import annotations

import ast
import os
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tests._stubs import LANE_DEMO, engine_artifact_lane  # noqa: E402
from tests.net_guard import network_disabled  # noqa: E402


TEST_LEDGER_KEY = "test-ledger-key-not-a-secret"


@pytest.fixture(scope="session", autouse=True)
def ledger_key_env() -> str:
    """ledger/ledger.py refuses to construct without SIH26_LEDGER_KEY (F36), so any
    test that reaches the ledger — directly, or through engine.predict / app.panels /
    scripts — needs one in the environment. Without this those tests raise
    RuntimeError on a machine that has the trained artifacts; they only skip here
    because artifacts/ is absent.

    `setdefault`, never overwrite: an operator running the suite with the real key
    exported must keep it, so a run on the demo machine verifies ledgers under the
    key they were written with. Tests that prove the refusal itself
    (test_ledger_tamper.test_ledger_refuses_to_construct_without_a_key) monkeypatch
    the variable away for their own duration, which still works on top of this.
    """
    from ledger.ledger import KEY_ENV_VAR

    os.environ.setdefault(KEY_ENV_VAR, TEST_LEDGER_KEY)
    return os.environ[KEY_ENV_VAR]


@pytest.fixture(scope="session")
def data_cfg() -> dict:
    from configs import load_config

    return load_config("data")


@pytest.fixture(scope="session")
def fixture_csv(data_cfg) -> Path:
    from configs import resolve_path

    path = resolve_path(data_cfg["paths"]["fixture_csv"])
    assert path.exists(), f"committed fixture missing: {path}"
    return path


@pytest.fixture
def no_network():
    """Run the test body with every socket primitive raising NetworkAttempt."""
    with network_disabled():
        yield


# ==========================================================================
# LANE POLICY
# ==========================================================================
# A demo model can now be fitted from app/assets/synthetic_demo.pcap, so a judge
# with no dataset and no released weights can watch the pipeline run. That is
# useful and it is also a trap: every test currently gated on "are the artifacts
# on disk" would start passing against a model fitted on a few minutes of
# hand-authored traffic, the skip count would fall, and nothing would have been
# verified. A green run against a toy model is not evidence for a number
# measured on CSE-CIC-IDS-2018.
#
# So each artifact-gated test declares which lane it needs
# (tests/_stubs.py::engine_artifact_lane):
#
#   DEMO_LANE_ALLOWED  its subject is PLUMBING — does the pipeline run end to
#                      end, with sockets blocked, without crashing, writing a
#                      ledger that verifies and a run that reproduces. Any
#                      loadable model exercises that, so the demo model is a
#                      legitimate way to run it. It is still not evidence for a
#                      measured number, and tests/test_bootstrap_state.py reports
#                      these as DEMO rather than RUNS for exactly that reason.
#
#   PUBLISHED_ONLY     its subject is a MEASURED NUMBER or a property of the
#                      training data. Passing against the demo model would mean
#                      nothing, or worse, would mean something false. These skip
#                      on the demo lane even when their own gate — usually "does
#                      artifacts/engine_model.json exist" — cannot tell the two
#                      apart.
#
#   NO_MODEL_ONLY      an INVERTED gate: it describes the bare-clone experience
#                      and runs only when no model is loadable. The hook below
#                      must never touch these; its own skipif already handles
#                      both lanes correctly.
#
# The values are the reasoning, not a label. They are printed verbatim in the
# skip reason a judge reads, so "why is this still skipped on my machine" is
# answered by the run itself.
#
# pytest_collection_modifyitems below only ever ADDS skips, and only on the demo
# lane. It cannot un-skip anything: a test gated by its own skipif stays gated.
# That direction is deliberate — this file can tighten what the suite claims and
# is structurally unable to loosen it.
#
# --------------------------------------------------------------------------
# DEMO_LANE_ALLOWED IS A PERMISSION, NOT A PREDICTION. READ THIS BEFORE
# REWIRING ANY GATE TO THE DEMO LANE.
# --------------------------------------------------------------------------
# An entry here says only this: "the subject of this test is plumbing, so IF it
# ran against the demo model the result would still mean something, and this
# file will not add a skip for it." It does NOT say the test runs on the demo
# lane today, and on this checkout none of them do — every one is held back by
# its OWN gate, which reads the published artifacts directory
# (`engine_artifacts_present`, `requires_engine`, or a literal
# `artifacts/engine_model.json`). Those gates live in test files that are not
# this workstream's to edit. The bootstrap report derives and prints which
# DEMO_LANE_ALLOWED nodes actually execute, so the gap is stated by a run rather
# than inferred from this comment
# (tests/test_bootstrap_state.py::demo_lane_permissions).
#
# Now the part that matters, because it is the trap one layer down. Rewiring
# those gates to `engine_model_loadable()` does NOT turn these tests green
# today. RE-MEASURED 2026-09-12 on the demo lane, with artifacts/ absent and
# artifacts_demo/ bootstrapped, driving the real engine and the real panels over
# the committed flow fixture (configs/data.yaml `paths.fixture_csv`):
#
#     engine.predict.predict_file(fixture_csv)
#       -> n_flows 1000, n_alerts 0, forecasts 0
#     app.panels.timeline_frame(result)    -> 0 rows
#     app.panels.host_ranking(result)      -> 0 rows
#     app.panels.ledger_status(out_dir)    -> exists=False, records=None
#     result["graph"]                      -> 164 nodes, 166 edges
#     audit_chain.jsonl                    -> NOT WRITTEN (there were no alerts)
#
# The demo model is fitted on one synthetic PCAP and its alert threshold is
# chosen on those same rows (artifacts_demo/engine_threshold.json carries
# `fpr_0.01` just under 0.99 for all eight heads, beside `in_sample_auroc: 1.0`
# and `auroc_is_in_sample: true`). Nothing in the committed CSE-CIC-format flow
# fixture clears that bar, so the run completes and produces an EMPTY forecast
# list. `tests/test_offline.py` asserts `result["forecasts"]` and
# `tests/test_smoke.py` asserts `result["forecasts"]`; both would FAIL, not
# pass, if their gates were pointed at the demo lane as things stand.
#
# And for three of the entries below it is worse than "fail", which is exactly
# the thing an entry must not quietly round off. With no alerts the engine
# writes NO audit_chain.jsonl and the host ranking is EMPTY, so those three
# would never reach an assertion at all: they raise FileNotFoundError,
# IndexError or TypeError first. Each of the three says so in its own entry,
# because the next person weighing up a gate move reads the entry and not this
# paragraph, and an entry that promises a clean red assertion where an error is
# waiting is how the assertion ends up deleted instead of the lane fixed. The
# one entry whose assertions the demo lane really does satisfy on this fixture
# is the host-graph one - 164 nodes with zero alerts - and it says that too.
#
# This does NOT contradict the demo-lane tests in tests/test_engine.py that do
# assert a non-empty forecast list and pass. Those use that module's `demo_lane`
# fixture, which builds a lane of its own at an alert threshold of 0.0 so that
# every window alerts and the ledger is deterministic. The bootstrapped lane on
# disk is the one thresholded at ~0.99, and it is the one a judge gets.
#
# The same asymmetry is why the PCAP path is not a counterexample either: over
# app/assets/synthetic_demo.pcap the bootstrapped demo lane produced 54 alerts
# with a top probability of 0.9913 in this session. It alerts confidently on the
# capture it memorised and not at all on data it has never seen, which is the
# signature of memorisation rather than detection - and the reason the PCAP
# assertion sits in PUBLISHED_ONLY below.
#
# So the failure mode to refuse is not "the gate is still published-only". It is
# someone rewiring the gate, watching the assertion fail, and deleting the
# assertion to get a green line. That converts "unverified" into "verified" with
# strictly less being checked than before. If the offline and smoke paths are to
# run on the demo lane, what has to change is the demo lane — a threshold or a
# fixture the demo model can actually alert on — never the assertions. Until
# then these stay skipped, and the report says so in those words.

DEMO_LANE_ALLOWED: dict[str, str] = {
    "tests/test_offline.py::test_inference_and_ledger_verify_run_end_to_end_with_sockets_blocked":
        "PS hard constraint #1 is a property of the CODE PATH, not of the weights: "
        "with every socket primitive raising, inference and ledger verification "
        "must still complete. A demo model drives the same loaders, the same "
        "feature extractor and the same ledger writer, so an offline violation "
        "anywhere in that path is caught here. What it does not check is any "
        "number the run produces, and it asserts none — only that forecasts "
        "exist and the chain verifies. That last one is why it is still gated on "
        "the published artifacts and not yet rewired: measured this session, the "
        "demo model alerts on 0 of the flow fixture's 1,000 rows, so "
        "`assert result['forecasts']` would fail on the demo lane rather than "
        "pass. See the PERMISSION, NOT A PREDICTION block above.",
    "tests/test_smoke.py::test_full_pipeline_on_1000_flow_fixture_offline_under_60s":
        "The subject is the pipeline completing on the committed 1,000-flow "
        "fixture inside a time budget with sockets blocked. Row count, "
        "completion and ledger validity are all model-independent. The 60 s "
        "budget is the one caveat and it cuts the safe way: the demo model is "
        "smaller, so a pass here is weaker evidence for the published model's "
        "runtime, never stronger — it can hide a slow real model, it cannot "
        "invent a fast one. Like the offline test it also asserts "
        "`result['forecasts']`, which the demo model does not satisfy on the "
        "flow fixture today, so its gate stays published-only.",
    "tests/test_engine.py::test_predict_file_produces_explained_forecasts_and_verifiable_ledger":
        "Asserts SHAPE, not accuracy: the fixture's 1,000 rows arrive as 1,000 "
        "flows, probabilities lie in [0, 1], every stage is one of the configured "
        "stages, forecasts carry named features rather than embedding indices, "
        "run_summary.json on disk agrees with the returned summary, no raw "
        "172.31./192.168. address reaches the ledger, and the chain verifies. "
        "Every one of those is a property of the output schema, the run-summary "
        "writer and the pseudonymiser, and a demo model exercises them exactly as "
        "the published one does. It also asserts `result['forecasts']` is "
        "non-empty, which the demo model does not satisfy on this fixture "
        "(measured: 0 alerts), so this is a third gate that must not be moved "
        "until the demo lane can alert on it.",
    "tests/test_engine.py::test_engine_refuses_to_log_on_weight_mismatch":
        "The subject is the REFUSAL MECHANISM (M9.3): it monkeypatches "
        "verify_weights.verify to report a mismatch and requires the engine to "
        "raise and write no ledger at all. No weight is hashed and no row is "
        "scored, so the identity of the model on disk cannot affect the outcome — "
        "this is as model-independent as an artifact-gated test gets. Running it "
        "on the demo lane is in fact the more valuable placement: the mismatch "
        "refusal is what stops a demo-lane run from logging records under "
        "published provenance, and engine/predict.py runs that same check against "
        "whichever lane resolved.",
    "tests/test_engine.py::test_predict_file_on_empty_input_yields_zero_alerts":
        "An edge case about the empty path: a header-only CSV must yield zero "
        "alerts and a valid empty ledger rather than a crash. There is no model "
        "output to be wrong about — zero rows in, zero forecasts out. MEASURED "
        "on the demo lane 2026-09-12: n_flows 0, n_host_windows 0, n_alerts 0, "
        "forecasts [] — every assertion in the test satisfied. One caveat "
        "belongs with that, because it is the only reason the last line passes: "
        "the engine writes NO audit_chain.jsonl when nothing alerted, and "
        "ledger.verify_cli.verify() answers (True, None) for a chain that is not "
        "there, so `assert ok, 'empty-input ledger must still verify'` is "
        "verifying an absent file. That is a weakness in the assertion on BOTH "
        "lanes, not something the demo lane introduces, and it is filed as a "
        "risk rather than fixed here — tests/test_engine.py is not this "
        "workstream's file.",
    "tests/test_engine.py::test_predict_file_is_deterministic":
        "Determinism is a property of the pipeline plus fixed weights, whichever "
        "weights those are: two runs over one input must agree byte for byte. A "
        "nondeterminism introduced anywhere in the engine shows up here on the "
        "demo lane just as it would on the published one, and it asserts "
        "equality between two runs, never a value. So the SUBJECT is plumbing "
        "and the permission stands — but what would actually happen if its gate "
        "moved today is not a pass, and the earlier version of this entry "
        "implied it was. MEASURED on the demo lane 2026-09-12: the flow fixture "
        "raises 0 alerts, no audit_chain.jsonl is written, and this test ends "
        "with `(first / 'audit_chain.jsonl').read_text()` — so it would ERROR "
        "with FileNotFoundError before comparing anything, and the "
        "`r1['forecasts'] == r2['forecasts']` line above it would have been two "
        "empty lists compared to each other. A vacuous comparison followed by an "
        "error is the worst possible thing to meet while rewiring a gate, "
        "because deleting the chain comparison makes it green and leaves nothing "
        "behind it.",
    "tests/test_app.py::test_pipeline_and_panels_work_offline":
        "The demo surface under the socket kill-switch. It checks that the "
        "panels render a result at all without reaching the network — the "
        "failure it guards against is an import-time or render-time socket, "
        "which no model can mask. Its assertions on the panels (a non-empty "
        "timeline, a non-empty host ranking, an explanation for the top host) "
        "all need at least one alert, and MEASURED on the demo lane 2026-09-12 "
        "over the flow fixture the panels return 0 timeline rows and 0 ranking "
        "rows, so `assert not tl.empty` fails and `ranking.iloc[0]` would raise "
        "IndexError right after. Gated on the published lane until the demo lane "
        "can alert on that input.",
    "tests/test_app.py::test_ledger_panel_tamper_then_detect":
        "The tamper/re-verify beat: edit a record through the panel and the "
        "verifier must fail at that index. The ledger's integrity properties are "
        "independent of what wrote the records, so a demo model is in PRINCIPLE "
        "a valid way to produce a chain to attack — but not from this input, and "
        "the earlier version of this entry stopped at the principle. MEASURED on "
        "the demo lane 2026-09-12 over the flow fixture: zero alerts means the "
        "engine writes no audit_chain.jsonl at all, panels.ledger_status() "
        "answers exists=False with records=None, so `assert before['exists'] and "
        "before['verified'] and before['records'] > 0` raises TypeError on "
        "None > 0 rather than failing cleanly, and panels.tamper_ledger() raises "
        "FileNotFoundError on the missing chain. The permission is about the "
        "subject; the lane still has to produce a chain before this can move.",
    "tests/test_app.py::test_what_if_remove_host_ablates_that_host":
        "Ablation BOOKKEEPING: the removed host must not appear in the re-scored "
        "forecasts and the alert count must not go up. Both are relations "
        "between two runs of the same model, not statements about either run's "
        "numbers — which is why the subject is plumbing. What the previous "
        "version of this entry left out is that the test has to NAME a host "
        "first: it takes `panels.host_ranking(result).iloc[0]`, and MEASURED on "
        "the demo lane 2026-09-12 that ranking has 0 rows over the flow fixture, "
        "so the test raises IndexError on its third line and never reaches "
        "either relation. Same conclusion as its neighbours: fix the lane, not "
        "the test.",
    "tests/test_app.py::test_what_if_on_pcap_input_stays_on_full_path":
        "A regression test for a crash — the what-if on a PCAP used to re-read "
        "the .pcap as a CSV and raise UnicodeDecodeError. The subject is which "
        "code path the ablation takes, which the demo lane exercises identically. "
        "One caveat, named rather than glossed: its last assertion is the STRICT "
        "`after['n_alerts'] < before`, so it needs the top host to have driven "
        "alerts. On the demo lane that holds for the reason that makes it no "
        "evidence of detection — the model was fitted on this very capture and "
        "has memorised it. The crash this pins is still a real crash on either "
        "lane.",
    "tests/test_app.py::test_pipeline_result_carries_a_host_graph":
        "A structural assertion about the result payload: the pipeline result "
        "carries a host graph. Presence and shape of a field, not its values. "
        "This is the ONE entry in this registry whose assertions the demo lane "
        "demonstrably satisfies on the committed flow fixture, and it is worth "
        "naming as such rather than leaving it indistinguishable from its "
        "neighbours: MEASURED 2026-09-12, result['graph'] came back with 164 "
        "nodes and 166 edges on a run that raised ZERO alerts, because the graph "
        "is built over the hosts seen in the capture and not over the alerts. So "
        "if a gate here is ever pointed at the demo lane it should pass on its "
        "merits — and even then it proves the payload's shape, never a number in "
        "it.",
}

PUBLISHED_ONLY: dict[str, str] = {
    "tests/test_engine.py::test_pcap_input_uses_full_features_and_verifies":
        "It asserts max(probability) > 0.5 on the bundled capture — a statement "
        "about how confidently THE MODEL separates that kill chain, which is a "
        "measured number. On the demo lane it is worse than uninformative, and "
        "this is measured rather than argued: running the demo lane over "
        "app/assets/synthetic_demo.pcap in this session produced 54 alerts with a "
        "top probability of 0.9913 — an in-sample score from a model fitted on "
        "that exact capture, comfortably clearing a bar the assertion sets at "
        "0.5. The test would pass every time and would read as the published "
        "engine confidently detecting a kill chain. Keeping it gated is the "
        "difference between a test and a rubber stamp.",
    "tests/test_scaler_train_only.py::test_persisted_scaler_statistics_match_train_split_refit":
        "The anti-leakage claim (CLAUDE.md: fit scalers on the training split "
        "only) is about the CSE-CIC-IDS-2018 split map. It refits from "
        "data.flow_features over the train split and compares statistics — there "
        "is no train split on a demo bootstrap, and a demo scaler fitted on one "
        "synthetic capture cannot evidence anything about normalisation leakage "
        "across days. Its own gate is the presence of `paths.scaler` — "
        "artifacts/scaler.pkl — which today's bootstrap does NOT write: it "
        "persists artifacts_demo/window_scaler.pkl, a different name in a "
        "different directory. So this entry is not what is holding the test back "
        "right now; it is the guard for the day a bootstrap, or an operator "
        "copying files about, does put a scaler where that gate looks. Without "
        "it, that day arrives as a silently green anti-leakage test fitted on one "
        "synthetic capture, which is the single most damaging false pass "
        "available in this suite.",
}

NO_MODEL_ONLY: dict[str, str] = {
    "tests/test_app.py::test_first_click_without_artifacts_shows_a_card_not_a_traceback":
        "F23: the first click on a machine with no model must render an error "
        "card, not a red traceback carrying absolute paths. Its skipif is "
        "INVERTED — it runs only when no model is loadable — so it is already "
        "correct on all three lanes and this hook must leave it alone.",
}

# Substrings that make a gate a PUBLISHED-ARTIFACT gate. A decorator or
# module-level pytestmark mentioning one of these gates on whether the trained
# model is on disk, which means its author owes a lane decision. Deliberately
# over-broad: a false positive costs one dictionary entry, a false negative costs
# a test that quietly starts passing against the demo model.
_HELPER_MARKER = "[via artifact helper(s):"

_ARTIFACT_GATE_TOKENS = (
    "engine_artifacts_present",
    "engine_model_loadable",
    "published_artifacts_are_the_released_ones",
    # Matches engine_artifact_lane, _artifact_lane_name and anything else a gate
    # spells with those two words - the lane helpers are the thing test modules
    # reach for when they gate on which model is on disk.
    "artifact_lane",
    "requires_engine",
    "_engine_ready",
    "_scaler_refit_inputs_present",
    "artifacts/",
    "artifacts_dir",
    "engine_model",
    "window_scaler",
    "engine_threshold",
    # ...and the annotation _gate_sources appends when a gate reaches artifacts
    # through a local helper instead of naming one of the above itself. This is
    # the entry that keeps `@requires_engine` and `skipif(_lane_available())` in
    # scope no matter what those helpers are renamed to.
    _HELPER_MARKER,
)

# Tokens that make a module-level HELPER an artifact helper (see
# _artifact_helper_names). Matched case-insensitively against the helper's whole
# source, docstring included, because a helper that talks about weights in its
# docstring and nowhere else is still a gate on whether weights are present.
_ARTIFACT_HELPER_TOKENS = (
    "artifact",
    "engine_model",
    "window_scaler",
    "engine_threshold",
    "scaler",
    "weights",
)

# ...and the tokens that take a gate back OUT of scope. A test whose gate says
# `requires_demo_lane` has already declared its lane in the clearest possible
# way: it runs ONLY on the demo lane and is about the demo lane. It owes this
# registry nothing, and deny-defaulting it would have this file skipping the very
# tests that exist to exercise the demo bootstrap.
# Narrow on purpose: the marker NAME, not the word "demo lane" anywhere in a
# gate. A wider match caught the inverted no-artifacts gate in tests/test_app.py,
# whose skip REASON mentions its demo-lane counterpart by name - which would have
# quietly dropped a real artifact gate out of this registry's scope. A gate this
# does not recognise is deny-defaulted and has to be classified by hand, which is
# the loud direction.
_DEMO_ONLY_GATE_TOKENS = ("requires_demo_lane",)

_DEMO_SKIP_PREFIX = (
    "demo lane: the model on this machine is NOT the published one, and this "
    "test's subject is not plumbing. "
)
_UNCLASSIFIED_SKIP = (
    "demo lane: this test is gated on trained artifacts but declares no lane in "
    "tests/conftest.py (DEMO_LANE_ALLOWED / PUBLISHED_ONLY / NO_MODEL_ONLY). "
    "Skipped rather than run, because an unclassified artifact gate on the demo "
    "lane is exactly how a toy model starts passing for the published one. "
    "tests/test_bootstrap_state.py::test_every_artifact_gated_test_declares_a_lane "
    "names it and fails."
)


def node_key(node_id: str) -> str:
    """A collected node id reduced to `tests/<file>.py::<function>`.

    Strips the parametrisation suffix and normalises separators so the registry
    above can be written once and match on any platform.
    """
    base = node_id.replace("\\", "/").split("[", 1)[0]
    parts = [p for p in base.split("::") if p]
    if len(parts) < 2:
        return base
    return f"{parts[0]}::{parts[-1]}"


def _is_gate_decorator(source: str, node: ast.expr) -> bool:
    """Is this decorator capable of SKIPPING the test?

    `@pytest.mark.parametrize(..., REDACTION_CASES)` is not, and letting it count
    put two redaction tests into this registry's scope because the data constant
    they parametrise over happens to contain artifact paths. Only a skip/skipif
    call, or a bare marker name that could be an alias for one
    (`@requires_engine`), can gate anything.
    """
    if isinstance(node, ast.Call):
        return "skip" in (ast.get_source_segment(source, node.func) or "")
    return isinstance(node, (ast.Name, ast.Attribute))


def _artifact_helper_names(source: str, tree: ast.Module) -> set[str]:
    """Module-level names whose own source is about artifacts, weights or lanes.

    A gate is usually a bare call to a local helper - `@requires_engine`,
    `skipif(not _lane_available())` - so matching only the gate text means the
    registry's scope depends on what those helpers are CALLED. It does not
    survive a rename, and it did not: `_engine_ready` became
    `_artifact_lane_name` became `_lane_available` inside one afternoon, and each
    rename silently dropped a real artifact gate out of scope. Resolving one
    level of indirection - what does the helper's own body talk about - is stable
    across every one of those renames.
    """
    names: set[str] = set()
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            targets = [node.name]
        elif isinstance(node, ast.Assign):
            targets = [t.id for t in node.targets if isinstance(t, ast.Name)]
        else:
            continue
        segment = (ast.get_source_segment(source, node) or "").lower()
        if any(token in segment for token in _ARTIFACT_HELPER_TOKENS):
            names.update(n for n in targets if not n.startswith("test_"))
    return names


def _gate_sources(path: Path) -> dict[str, str]:
    """{function name -> the source of every gate that applies to it}.

    Module-level `pytestmark` applies to every function in the file, so it is
    concatenated onto each. Unparsable files yield nothing: the caller treats
    that as "no artifact gate found here", and a test module that will not parse
    fails the suite on its own long before this matters.
    """
    try:
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source)
    except (OSError, SyntaxError, UnicodeDecodeError):
        return {}
    module_gate = " ".join(
        ast.get_source_segment(source, node) or ""
        for node in tree.body
        if isinstance(node, ast.Assign)
        and any(getattr(t, "id", "") == "pytestmark" for t in node.targets)
    )
    helpers = _artifact_helper_names(source, tree)
    gates: dict[str, str] = {}
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith(
            "test_"
        ):
            decorators = " ".join(
                ast.get_source_segment(source, d) or ""
                for d in node.decorator_list
                if _is_gate_decorator(source, d)
            )
            gate = f"{module_gate} {decorators}"
            named = sorted(h for h in helpers if h in gate)
            # The annotation is what puts an indirect gate IN SCOPE: it carries
            # the word "artifact", so the token check below sees a gate that only
            # ever says `@requires_engine`. It is also what a reader of the
            # failure message needs - the gate text alone does not say why a bare
            # decorator name counts.
            gates[node.name] = gate + (
                f"   {_HELPER_MARKER} {', '.join(named)}]" if named else "")
    return gates


def _tests_dir_signature() -> tuple:
    """A cheap fingerprint of every `tests/test_*.py` — name, size, mtime.

    The cache key for artifact_gated_nodes(). Reading and ast-parsing the whole
    tests/ directory costs about a second, and the answer is a pure function of
    those files' CONTENT, so recomputing it per call is waste — but caching it on
    nothing at all would be wrong for a session that edits a test file between
    calls (`pytest-watch`, and the lane-switching tests below, both do reimport
    work mid-process). Stat-ing the directory is the middle: an edit changes the
    signature and the cache misses, an unchanged directory answers from memory.

    This was not a micro-optimisation. `_lane_override` in
    tests/test_bootstrap_state.py calls unclassified_artifact_gates() once per
    probed node, so the uncached version cost ~1.1 s x 154 nodes; MEASURED in
    this session, `pytest tests/test_bootstrap_state.py -q` took 271.96 s before
    this cache and 5.37 s after, on the same machine with no other change.
    """
    return tuple(
        (p.name, s.st_size, s.st_mtime_ns)
        for p in sorted((REPO_ROOT / "tests").glob("test_*.py"))
        for s in (p.stat(),)
    )


_GATE_CACHE: dict[tuple, dict[str, str]] = {}


def artifact_gated_nodes() -> dict[str, str]:
    """{`tests/x.py::test_y` -> the gate source that makes it artifact-gated}.

    Read from the test files themselves rather than maintained by hand, so a
    newly added artifact gate cannot avoid the lane decision by not being listed
    anywhere.

    Memoised on _tests_dir_signature(). A COPY is returned, because callers
    (unclassified_artifact_gates, the report in tests/test_bootstrap_state.py)
    filter what they get back and a shared dict would let one caller's filtering
    reach another's.
    """
    signature = _tests_dir_signature()
    cached = _GATE_CACHE.get(signature)
    if cached is None:
        found: dict[str, str] = {}
        for path in sorted((REPO_ROOT / "tests").glob("test_*.py")):
            for name, gate in _gate_sources(path).items():
                if any(token in gate for token in _DEMO_ONLY_GATE_TOKENS):
                    continue
                if any(token in gate for token in _ARTIFACT_GATE_TOKENS):
                    found[f"tests/{path.name}::{name}"] = " ".join(gate.split())
        # One signature at a time: the files only ever move forward, so an old
        # entry is dead weight that would also hide a stale-cache bug.
        _GATE_CACHE.clear()
        _GATE_CACHE[signature] = found
        cached = found
    return dict(cached)


def unclassified_artifact_gates() -> dict[str, str]:
    """Artifact-gated nodes that declare no lane. Empty is the correct state."""
    classified = set(DEMO_LANE_ALLOWED) | set(PUBLISHED_ONLY) | set(NO_MODEL_ONLY)
    return {k: v for k, v in artifact_gated_nodes().items() if k not in classified}


def pytest_collection_modifyitems(config, items):
    """On the demo lane only, skip what the demo model must not be allowed to pass.

    Adds markers; never removes one. On LANE_REAL and LANE_NONE this returns
    immediately and the suite behaves exactly as it did before the demo
    bootstrap existed.
    """
    if engine_artifact_lane().lane != LANE_DEMO:
        return
    unclassified = unclassified_artifact_gates()
    for item in items:
        key = node_key(item.nodeid)
        why = PUBLISHED_ONLY.get(key)
        if why:
            item.add_marker(pytest.mark.skip(reason=_DEMO_SKIP_PREFIX + why))
        elif key in unclassified:
            item.add_marker(pytest.mark.skip(reason=_UNCLASSIFIED_SKIP))
