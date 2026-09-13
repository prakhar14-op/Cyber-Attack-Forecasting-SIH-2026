"""Disclosure: which guarantees this checkout actually exercises, and which it does not.

On a bare checkout `pytest tests/ -q` is green with a number of tests SKIPPED,
and those skips are not incidental — they include the end-to-end offline test
(the problem statement's hard constraint #1), the 1,000-flow smoke run, the
engine-dependent part of the Streamlit demo surface, and the train-only-scaler
anti-leakage check. A green summary line therefore overstates what has been
checked, and nothing else in the suite says so.

Nowhere here, in docs/INSTALL.md or in the CI comment is a pass/skip count
stated as an expectation. The one count still written down is the retracted
figure in the next sentence, quoted so that this paragraph can name what it is
retracting: an earlier version of this file published "78 passed, 16 skipped" in
its own docstring; the suite outgrew it within the same session and the figure
became a published falsehood in three places at once. The criterion for a
correct bare checkout is `0 failed, 0 errors, some skipped` — read the counts
off your own run. `tests/test_docs_claims.py` bans the reintroduction of a
hardcoded count, and since its scope is now every UTF-8-decodable file in the
repository rather than a list of documents, that ban covers this docstring: the
retracted figure above survives only because it is quoted verbatim in that
guard's `allow_exact`, and a second count written anywhere in this file would
fail the suite.

This test always runs. It prints a two-part report — which bootstrap
prerequisites are present, and which capability each one gates — so the gap
between "green" and "verified" is stated rather than inferred.

    python -m pytest tests/test_bootstrap_state.py -q -s

Every state below is DERIVED, never declared. Each capability names test node
ids; the state comes from the skip markers those nodes really carry in this
interpreter — the same markers pytest evaluates. That matters: a previous
version hand-asserted that tests/test_app.py was skipped in its entirety, and
went on telling judges the whole demo layer was unverified for as long as it
took someone to notice that most of that file had since become ungated. A
capability whose tests are only partly gated now reports PARTIAL with the
counts, and it counts them itself.

RUNS means every named test executes here; its verdict is then the suite's own
result. PARTIAL means some execute and some are gated. SKIPPED means every named
test is gated, so the guarantee is not checked here. Gating is the right shape:
the artifacts are gitignored (CLAUDE.md forbids committing weights) and the
dataset is ~12.7 GiB, so a bare checkout skipping them is correct behaviour, not
breakage.

DEMO is the state the demo bootstrap made necessary. A model can
now be fitted from the bundled synthetic capture (app/assets/synthetic_demo.pcap)
on a machine with no dataset and no released weights, which lets a judge watch
the pipeline run. The tests that then execute are real tests of the PLUMBING and
are not evidence for any published number, so reporting them as RUNS would be a
claim outrunning the code and reporting them as SKIPPED would be a second,
opposite falsehood. They report as DEMO. Which tests may reach this state is
declared per test in tests/conftest.py (DEMO_LANE_ALLOWED / PUBLISHED_ONLY),
with the reasoning beside each one; this report reads that registry rather than
restating it, and the collection hook in that same file enforces it, so the
report and the suite cannot disagree about which lane a test is in.

Which lane this checkout is in is DERIVED too — tests/_stubs.py::engine_artifact_lane
probes the artifacts directory engine/predict.py actually loads from. LANE_REAL
requires a SHA-256 match against the digests published in README.md; LANE_DEMO
requires nothing. Every way of getting that detection wrong therefore
under-claims, and the report says which lane it found and why at the top.

UNTESTED is the state that has to exist: a capability that names no test at
all. This report used to call those RUNS the moment their
prerequisites were present, which put "[RUNS] The published ablation table is
regenerable" directly above the line "no automated test" on any machine holding
results/*.json — a state whose legend promises that every named test executes,
awarded to a claim with none. Present inputs are not a check of what is done
with them, so a capability with no test reports UNTESTED whatever this machine
has bootstrapped, and names the manual procedure instead.

NO TEST FILE, UNIMPORTABLE and UNREADABLE are not verdicts. They mean this probe
could not work out what happens to a node, and `test_every_named_test_node_resolves`
fails on any of them rather than let the report print a plausible state it did not
derive. UNREADABLE in particular replaces an earlier fallback that reported a test
whose source could not be read as one that RUNS: of the two ways to be wrong, this
file is wrong in the direction that understates what has been checked.
"""

from __future__ import annotations

import contextlib
import copy
import hashlib
import importlib
import json
import importlib.util
import inspect
import re
import shutil
import sys
import textwrap
from dataclasses import dataclass
from pathlib import Path

if __name__ == "__main__":  # run as a plain script, the repo root is not on sys.path
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from configs import load_config, resolve_path
from tests._stubs import (
    ENGINE_ARTIFACTS,
    LANE_DEMO,
    LANE_NONE,
    LANE_REAL,
    REPO_ROOT,
    engine_artifact_lane,
)

# The lane registry and the collection hook that enforces it live together in
# tests/conftest.py. Imported, never restated: a second copy of "which tests may
# run on the demo model" is a second copy that can drift, and the whole point of
# this report is that its states are derived from what pytest really does.
from tests.conftest import (  # noqa: E402
    DEMO_LANE_ALLOWED,
    NO_MODEL_ONLY,
    PUBLISHED_ONLY,
    artifact_gated_nodes,
    node_key,
    unclassified_artifact_gates,
)

RUNS = "RUNS"
PARTIAL = "PARTIAL"
SKIPPED = "SKIPPED"
# Executed, but against the demo model fitted from the bundled synthetic
# capture. Neither RUNS nor SKIPPED would be true of it: the test really ran,
# and what it establishes is that the pipeline works, not that any published
# number is reproducible.
DEMO = "DEMO"
# A capability that names no test. Distinct from SKIPPED, which means named
# tests exist and every one of them is gated: UNTESTED means there is nothing to
# gate. It is deliberately not reachable from a prerequisite being present,
# because that is the over-claim it replaces.
UNTESTED = "UNTESTED"
UNKNOWN = "NO TEST FILE"
BROKEN = "UNIMPORTABLE"

# A node whose source could not be read, so whether it calls pytest.skip() in its
# body is not known. Reported, never guessed: see _node_state.
UNREADABLE = "UNREADABLE"
STATES = (RUNS, DEMO, PARTIAL, SKIPPED, UNTESTED, UNKNOWN, BROKEN, UNREADABLE)
# States that mean "this report could not work out what happens here". They are
# failures, not verdicts: test_every_named_test_node_resolves fails on any of
# them. Ordered worst-first; classify() reports the worst one present.
UNRESOLVED = (BROKEN, UNKNOWN, UNREADABLE)
_WIDTH = max(len(s) for s in STATES)

# state -> the one line the report prints defining it. The legend is RENDERED
# from this table rather than written out beside it, so a state cannot reach the
# report without a reader-facing definition, and the definition cannot drift
# from the state it defines. test_bootstrap_state_is_disclosed asserts every
# state the report actually uses is defined here and printed. The UNRESOLVED
# states share a line of their own below: they are failures, not verdicts.
LEGEND: dict[str, str] = {
    RUNS: "every named test executes here; its verdict is this suite's own.",
    DEMO: ("executes, but against the DEMO model fitted from the bundled "
           "synthetic capture: evidence the pipeline works, NOT evidence for "
           "any published number."),
    PARTIAL: "some execute, some are gated; the gated node ids are listed.",
    SKIPPED: "named tests exist and every one is gated. NOT checked in this checkout.",
    UNTESTED: "no test names this claim. Its prerequisites are not a check of it.",
}

# The heading of the report section that separates what the demo lane is
# PERMITTED to run from what it really runs. A constant because two tests assert
# the section is present and a heading typed twice is a heading that drifts.
DEMO_PERMISSION_HEADING = "DEMO LANE: PERMITTED vs ACTUALLY EXECUTING"

# Per-node verdicts, one level below the capability states above.
NODE_RUNS = "runs"
NODE_GATED = "gated"       # a skip / truthy-skipif marker: pytest will not run it
NODE_RUNTIME = "runtime"   # the body may call pytest.skip(); decided by `needs`


@dataclass(frozen=True)
class Prerequisite:
    """One bootstrap input, its presence, and the command that produces it."""

    key: str
    present: bool
    detail: str
    bootstrap: str


@dataclass(frozen=True)
class Capability:
    """A guarantee the project claims, and the test(s) that would check it here."""

    claim: str
    tests: tuple[str, ...]
    needs: tuple[str, ...]
    # What a reader must do BY HAND when `tests` is empty. Required for exactly
    # those capabilities: an unautomated claim with no stated manual procedure
    # is a claim with nothing behind it and no way to get behind it, and
    # test_untested_capabilities_name_the_manual_check fails on one. The
    # procedure lives with the capability rather than in the renderer so the
    # report cannot print one capability's instructions under another's claim.
    manual: str = ""
    # Which lane this capability's evidence comes from ON ANY MACHINE, when that
    # is a property of the tests rather than of the checkout. LANE_DEMO here
    # means the named tests build and score a demo model themselves, so they
    # exercise the machinery and can never be evidence for a published number -
    # true on a bare clone and on a fully bootstrapped machine alike. Left empty
    # for the normal case, where the lane is whichever one this checkout has.
    evidence_lane: str = ""


@dataclass(frozen=True)
class Node:
    """One collected test function and whether this checkout will execute it."""

    node_id: str
    state: str
    detail: str = ""


def _tshark_present() -> bool:
    """Mirrors the gate in tests/test_packet_features.py.

    Only an import failure is swallowed, and only because the extractor pulls
    scapy: a machine without libpcap must still get a report rather than an
    error. A renamed `find_tshark`, a bad config or anything else raising here
    is a real defect and propagates — printing "[ABSENT] tshark" for it would
    hide a broken probe behind a plausible answer.
    """
    try:
        from data import packet_features as pf
    except ImportError:
        return False
    return pf.find_tshark(load_config("data")) is not None


def probe_prerequisites() -> list[Prerequisite]:
    cfg = load_config("data")
    art = resolve_path(cfg["paths"]["artifacts_dir"])
    interim = resolve_path(cfg["paths"]["interim_dir"])
    results = resolve_path(load_config("eval")["paths"]["results_dir"])

    train_engine = "python -m engine.train_engine  (or: python scripts/fetch_artifacts.py)"
    data_pipeline = "python -m data.zip_fetch && python -m data.extract && python -m data.windows"
    lane = engine_artifact_lane()

    return [
        # Two prerequisites where there used to be one, because "is a model on
        # disk" and "is the PUBLISHED model on disk" are different questions and
        # only the second one can carry a published number. A capability that
        # needs the first can be satisfied by the demo bootstrap; a capability
        # that needs the second cannot be satisfied by anything except the
        # released bytes.
        Prerequisite(
            "a loadable engine model",
            lane.has_model,
            f"any model engine/predict.py can load - lane={lane.lane}: {lane.detail}",
            f"{train_engine}, or the demo bootstrap in docs/INSTALL.md",
        ),
        Prerequisite(
            "published engine artifacts",
            lane.is_published,
            f"the published bundle ({', '.join(ENGINE_ARTIFACTS)}) under {art}. A "
            "bootstrapped demo lane does NOT satisfy this - its weights carry the "
            "`demo.model_prefix` and live in their own directory",
            train_engine,
        ),
        Prerequisite(
            "published artifacts are the RELEASED bytes",
            lane.digests_match,
            "...and their SHA-256 matches the table published in README.md, so a "
            "result can be tied to a published number rather than to a local rebuild"
            + (f" [{lane.digest_detail}]" if lane.digest_detail else ""),
            "python scripts/fetch_artifacts.py  (the Release is not published yet)",
        ),
        Prerequisite(
            "xgboost",
            importlib.util.find_spec("xgboost") is not None,
            "the deployed scorer's library",
            "pip install -r requirements.txt  (docs/INSTALL.md)",
        ),
        Prerequisite(
            "full 30-feature model",
            (art / "engine_model.json").exists(),
            str(art / "engine_model.json"),
            train_engine,
        ),
        Prerequisite(
            "flow-only model",
            (art / "engine_model_flow.json").exists(),
            str(art / "engine_model_flow.json"),
            train_engine,
        ),
        Prerequisite(
            "synthetic demo pcap",
            resolve_path("app/assets/synthetic_demo.pcap").exists(),
            "the bundled illustrative capture (NOT real capture data)",
            "python -m capture.make_synthetic_demo",
        ),
        Prerequisite(
            "persisted train-only scaler",
            resolve_path(cfg["paths"]["scaler"]).exists(),
            str(resolve_path(cfg["paths"]["scaler"])),
            "python -m data.flow_features --fit-scaler",
        ),
        Prerequisite(
            "split map",
            resolve_path(cfg["paths"]["splits"]).exists(),
            str(resolve_path(cfg["paths"]["splits"])),
            "committed; nothing to do",
        ),
        Prerequisite(
            "extracted window features",
            interim.exists() and any(interim.glob("*/packets/*.parquet")),
            f"per-day flow/packet parquet under {interim}",
            data_pipeline,
        ),
        Prerequisite(
            "tshark",
            _tshark_present(),
            "Wireshark's CLI, the reference retransmission backend",
            "install Wireshark, or set packet_features.tshark_path in configs/data.yaml",
        ),
        Prerequisite(
            "published results",
            results.exists() and any(results.glob("*.json")),
            f"the per-model result JSON the ablation table is built from, under {results}",
            "scripts/reproduce_results.ps1  (needs the dataset and SIH26_HMAC_KEY)",
        ),
    ]


# Ordered worst-consequence-first: the PS's hard constraints before the
# convenience surfaces. `tests=()` marks a claim with no automated check at all.
CAPABILITIES: tuple[Capability, ...] = (
    Capability(
        "Fully offline end to end: inference + ledger verify with every socket blocked "
        "(PS hard constraint #1)",
        ("tests/test_offline.py",),
        # "published engine artifacts", not "a loadable engine model", because
        # that is what the gate in tests/test_offline.py really reads
        # (tests/_stubs.engine_artifacts_present, the published bundle). The demo
        # lane does not unlock it today - see JUDGES.md Part 3 and the
        # needs_orchestrator note about wiring this gate to the demo lane.
        ("published engine artifacts",),
    ),
    Capability(
        "The 1,000-flow smoke pipeline completes offline in under 60 s "
        "(CLAUDE.md definition of done)",
        ("tests/test_smoke.py",),
        ("published engine artifacts",),
    ),
    Capability(
        "No normalisation leakage: the persisted scaler matches a train-split-only refit",
        ("tests/test_scaler_train_only.py",),
        # "published engine artifacts" because the claim is about the
        # CSE-CIC-IDS-2018 train split. A demo bootstrap can put a scaler.pkl on
        # disk and satisfy the first two prerequisites; it cannot make a refit
        # over a split map that is not here mean anything.
        ("persisted train-only scaler", "split map", "published engine artifacts"),
    ),
    Capability(
        "No host-window appears in two splits",
        ("tests/test_splits_disjoint.py::test_no_host_window_crosses_splits",),
        ("extracted window features",),
    ),
    Capability(
        "CSV input produces explained forecasts and a ledger that verifies",
        ("tests/test_engine.py::test_predict_file_produces_explained_forecasts_"
         "and_verifiable_ledger",),
        ("xgboost", "full 30-feature model"),
    ),
    Capability(
        "PCAP input takes the full 30-feature path and the capture's kill chain "
        "scores above 0.5",
        ("tests/test_engine.py::test_pcap_input_uses_full_features_and_verifies",),
        # The claim now names the threshold the test asserts, and the threshold
        # is why "published engine artifacts" is in `needs`: max(probability) >
        # 0.5 is a measured statement about the model. The demo model is fitted
        # FROM this capture, so on the demo lane the assertion is near-tautological
        # - tests/conftest.py::PUBLISHED_ONLY gates it there.
        ("xgboost", "full 30-feature model", "synthetic demo pcap",
         "published engine artifacts"),
    ),
    Capability(
        "The engine refuses to write ledger records on a weight-digest mismatch",
        ("tests/test_engine.py::test_engine_refuses_to_log_on_weight_mismatch",),
        ("xgboost", "full 30-feature model"),
    ),
    Capability(
        "An empty input yields zero alerts and still-valid output",
        ("tests/test_engine.py::test_predict_file_on_empty_input_yields_zero_alerts",),
        ("xgboost", "flow-only model"),
    ),
    Capability(
        "The offline demo app: pipeline, timeline, what-if, ledger tamper/re-verify, and "
        "every failure card a judge hits before bootstrapping",
        ("tests/test_app.py",),
        ("xgboost", "full 30-feature model"),
    ),
    Capability(
        "The scapy and tshark retransmission backends agree on the fixture",
        ("tests/test_packet_features.py::test_scapy_and_tshark_retransmission_counts_agree",),
        ("tshark",),
    ),
    Capability(
        "A judge with no dataset and no released weights can fit the demo model "
        "from the bundled synthetic capture and run the whole pipeline on it",
        ("tests/test_demo_bootstrap.py",),
        (),
        # No prerequisite: the capture is committed, so these run on a bare
        # clone. evidence_lane pins what they are evidence FOR - the machinery,
        # never a number. They would otherwise report RUNS, which under this
        # report's own legend ("its verdict is this suite's own") invites a
        # reader to treat a toy model's green line as the engine's.
        evidence_lane=LANE_DEMO,
    ),
    Capability(
        "The published ablation table is regenerable from results/*.json",
        (),
        ("published results",),
        manual=(
            "run scripts/reproduce_results.ps1 (needs the dataset and "
            "SIH26_HMAC_KEY), then diff scripts/make_ablation_table.py's output "
            "against the table in README.md yourself"
        ),
    ),
)

# Guarantees that hold with nothing bootstrapped. Listed so the report is a
# complete picture rather than only a list of gaps.
ALWAYS_EXERCISED: tuple[tuple[str, str], ...] = (
    ("The encoder is causal: perturbing t+1..T leaves the prediction at t bit-identical",
     "tests/test_no_future_leakage.py"),
    ("A tampered ledger record is caught at its exact index; a full rewrite fails the "
     "anchored checkpoint", "tests/test_ledger_tamper.py"),
    ("No day appears in two splits",
     "tests/test_splits_disjoint.py::test_no_day_appears_in_two_splits"),
    ("Explanations name real features; an embedding index is rejected by the schema",
     "tests/test_engine.py::test_output_schema_rejects_embedding_dimensions"),
    ("The anonymiser refuses to run without SIH26_HMAC_KEY rather than use a default",
     "tests/test_anonymize.py"),
    # Was "in the judge-facing docs or in the test modules' own docstrings",
    # which stopped being what that guard does: it scans every UTF-8-decodable
    # file in the repository now, which is how the app source came into scope
    # after a retired claim was found live in a Streamlit caption. A disclosure
    # that describes a narrower guard than the one that runs is the same defect
    # as one that describes a wider one, pointed the other way.
    ("Retired claims have not reappeared in any prose surface of this repository "
     "- documents, app and engine source, CI, the SVG figures and the test "
     "modules' own docstrings alike",
     "tests/test_docs_claims.py"),
)


def _as_marks(value) -> list:
    if value is None:
        return []
    return list(value) if isinstance(value, (list, tuple)) else [value]


def _marker_verdict(mark) -> str | None:
    """What one pytest marker does to a test here, or None if it is irrelevant."""
    if mark.name == "skip":
        return NODE_GATED
    if mark.name != "skipif":
        return None
    conditions = list(mark.args)
    if "condition" in mark.kwargs:
        conditions.append(mark.kwargs["condition"])
    if not conditions:
        return None
    if any(isinstance(c, str) for c in conditions):
        # A string condition is eval'd by pytest against the module namespace,
        # not resolvable here. Treat it as undecided rather than guess.
        return NODE_RUNTIME
    return NODE_GATED if any(bool(c) for c in conditions) else None


def _node_state(module, function) -> tuple[str, str]:
    """(state, detail) for one test function in this interpreter.

    The source is read to find a `pytest.skip()` in the body. If it cannot be
    read, the honest answer is UNREADABLE, not NODE_RUNS. An earlier version
    returned NODE_RUNS here, which fails in the OVER-CLAIMING direction: a test
    whose source this probe could not open would have been reported to a judge as
    a guarantee that executes on their machine. Every other failure path in this
    file is loud (UNKNOWN for a missing node, UNIMPORTABLE for a broken module);
    this one is now loud too, and test_every_named_test_node_resolves fails on it.
    """
    verdicts = [
        _marker_verdict(m)
        for m in _as_marks(getattr(module, "pytestmark", None))
        + _as_marks(getattr(function, "pytestmark", None))
    ]
    if NODE_GATED in verdicts:
        return NODE_GATED, ""
    if NODE_RUNTIME in verdicts:
        return NODE_RUNTIME, ""
    try:
        source = inspect.getsource(function)
    except (OSError, TypeError) as exc:
        return UNREADABLE, (
            f"cannot read the source of {getattr(function, '__qualname__', function)!r} "
            f"({type(exc).__name__}: {exc}), so whether its body calls pytest.skip() "
            "is undecided - this report will not guess that it runs"
        )
    return (NODE_RUNTIME if "pytest.skip(" in source else NODE_RUNS), ""


def _test_functions(module) -> dict:
    """The module's own test functions — not ones it imported from elsewhere."""
    return {
        name: obj
        for name, obj in vars(module).items()
        if name.startswith("test_")
        and callable(obj)
        and getattr(obj, "__module__", None) == module.__name__
    }


_NODE_CACHE: dict[str, list[Node]] = {}


def _lane_override(node: Node) -> Node:
    """Apply tests/conftest.py's lane policy to a node this report resolved.

    The skip markers in the test files cannot tell the lanes apart - most of
    them ask "does artifacts/engine_model.json exist", which a demo bootstrap
    can make true. tests/conftest.py::pytest_collection_modifyitems adds the
    missing skips at collection time, and those markers are attached to the
    collected ITEM, not to the function object this report inspects. So the
    report applies the same registry, through the same functions, rather than
    inspecting markers that are not there yet and reporting RUNS for a node
    pytest is about to skip. One registry, two readers.
    """
    if engine_artifact_lane().lane != LANE_DEMO or node.state in UNRESOLVED:
        return node
    key = node_key(node.node_id)
    if key in PUBLISHED_ONLY:
        return Node(node.node_id, NODE_GATED,
                    "demo lane: tests/conftest.py::PUBLISHED_ONLY")
    if key in unclassified_artifact_gates():
        return Node(node.node_id, NODE_GATED,
                    "demo lane: artifact-gated but declares no lane in tests/conftest.py")
    return node


def probe_nodes(spec: str) -> list[Node]:
    """Resolve `tests/x.py` or `tests/x.py::test_y` to the nodes it names.

    The module is imported, exactly as pytest imports it, so the markers read
    here are the markers pytest acts on. Under a full-suite run the module is
    already in sys.modules and this is a cache hit.
    """
    if spec in _NODE_CACHE:
        return _NODE_CACHE[spec]
    relative, _, wanted = spec.partition("::")
    if not (REPO_ROOT / relative).exists():
        nodes = [Node(spec, UNKNOWN, f"{relative} does not exist")]
    else:
        try:
            module = importlib.import_module(relative[:-3].replace("/", "."))
        except Exception as exc:  # a broken test module must not pass for a gap
            nodes = [Node(spec, BROKEN, f"{type(exc).__name__}: {exc}")]
        else:
            functions = _test_functions(module)
            if wanted and wanted not in functions:
                nodes = [Node(spec, UNKNOWN, f"{relative} defines no test named {wanted!r}")]
            elif wanted:
                nodes = [_lane_override(
                    Node(f"{relative}::{wanted}", *_node_state(module, functions[wanted]))
                )]
            else:
                nodes = [
                    _lane_override(
                        Node(f"{relative}::{name}", *_node_state(module, functions[name]))
                    )
                    for name in sorted(functions)
                ]
                if not nodes:
                    nodes = [Node(spec, UNKNOWN, f"{relative} defines no test functions")]
    _NODE_CACHE[spec] = nodes
    return nodes


def _executes(node: Node, needs_met: bool) -> bool:
    if node.state in UNRESOLVED:
        # Not known to execute. Callers surface these as a loud state of their
        # own; counting one as running is the over-claim this must not make.
        return False
    if node.state == NODE_GATED:
        return False
    if node.state == NODE_RUNTIME:
        return needs_met
    return True


def classify(capability: Capability, present: dict[str, bool]) -> str:
    needs_met = all(present[n] for n in capability.needs)
    nodes = [n for spec in capability.tests for n in probe_nodes(spec)]
    if not nodes:
        # No test names this claim, so `present` cannot decide anything about it
        # and is not consulted. This branch used to return RUNS when the
        # prerequisites were met — a state defined as "every named test executes
        # here" awarded to a capability with no named tests at all.
        return UNTESTED
    for state in UNRESOLVED:  # worst first
        if any(n.state == state for n in nodes):
            return state
    running = [n for n in nodes if _executes(n, needs_met)]
    if not running:
        return SKIPPED
    # DEMO outranks RUNS and PARTIAL, and only DEMO can be reached by looking at
    # the lane. A capability some of whose evidence on this machine came from the
    # demo model is reported as DEMO even when every node executes, because
    # "RUNS - its verdict is this suite's own" would hand a judge a toy model's
    # verdict under a legend promising the published model's.
    if capability.evidence_lane == LANE_DEMO or (
        engine_artifact_lane().lane == LANE_DEMO
        and any(node_key(n.node_id) in DEMO_LANE_ALLOWED for n in running)
    ):
        return DEMO
    return RUNS if len(running) == len(nodes) else PARTIAL


def demo_lane_permissions() -> tuple[list[str], list[str]]:
    """(DEMO_LANE_ALLOWED nodes that execute here, nodes that do not).

    tests/conftest.py::DEMO_LANE_ALLOWED is a PERMISSION - "if this ran against
    the demo model the result would still mean something, and the collection hook
    will not add a skip for it". It is not a statement that the test runs. Every
    one of those tests carries its OWN gate, written in a test module this
    workstream does not own, and today all of those gates read the PUBLISHED
    artifacts directory. So a reader who sees eleven carefully argued entries and
    concludes that eleven tests now exercise the demo model would be wrong, and
    nothing in the registry itself would tell them.

    This derives the answer instead of asserting it: the same probe_nodes() the
    rest of the report uses, applied to the registry's own keys. On a machine in
    the published lane it reports all of them executing; on a bare clone, none;
    on the demo lane it reports what is really happening, which is the case this
    exists for.

    The gap it exposes is the honest kind - the suite checks LESS than the
    registry permits, never more - but it has to be visible, because the way it
    gets closed wrongly is someone rewiring a gate, watching an assertion fail on
    an empty forecast list, and deleting the assertion.
    """
    executing, held_back = [], []
    for key in sorted(DEMO_LANE_ALLOWED):
        nodes = probe_nodes(key)
        # A spec that resolves to nothing, or to an unresolved state, is not
        # "executing": test_the_lane_registry_names_tests_that_exist fails on a
        # stale key, and this must not quietly count one as a running test.
        if nodes and all(_executes(n, True) for n in nodes):
            executing.append(key)
        else:
            held_back.append(key)
    return executing, held_back


def _node_lines(spec: str, needs_met: bool) -> list[str]:
    """One line per named spec, plus the non-executing node ids, labelled by WHY.

    The two reasons a node is not counted as executing are different facts and
    were being printed under one word. `gated` is a skip marker pytest evaluates:
    the test does not run, full stop. `may self-skip` is a node whose body
    contains a `pytest.skip(` call - pytest DOES run it, and whether it skips
    itself is decided inside the body by something this probe cannot evaluate, so
    `needs` is used as the conservative stand-in.

    Printing both as "gated:" was wrong in the report's own terms. MEASURED
    2026-09-12 on this checkout, two of the eight test_app.py nodes listed under
    that word - test_the_real_forecaster_matches_the_shared_api_contract and
    test_the_app_sees_every_demo_flag_the_engine_ships - run and PASS
    (`pytest tests/test_app.py -k ... -q` -> 2 passed). Calling them gated
    understates what the suite checks, which is the safe direction to be wrong
    in and still a false statement in a document whose only job is to be
    accurate about this. Both labels are kept in the not-executing list, because
    the count above them must stay conservative; only the word changes.
    """
    nodes = probe_nodes(spec)
    if len(nodes) == 1 and nodes[0].node_id == spec:
        only = nodes[0]
        if only.state in UNRESOLVED:
            return [f"      {spec}  <- {only.state}: {only.detail}"]
        return [f"      {spec}"]
    idle = [n for n in nodes if not _executes(n, needs_met)]
    lines = [f"      {spec} - {len(nodes) - len(idle)} of {len(nodes)} test functions "
             "execute here"]
    lines += [
        f"        {'gated' if n.state == NODE_GATED else 'may self-skip'}: "
        f"{n.node_id.split('::', 1)[1]}"
        for n in idle
    ]
    if any(n.state == NODE_RUNTIME for n in idle):
        lines.append("        (`may self-skip` = pytest runs it; its body decides. Not "
                     "counted above, to keep that count conservative.)")
    return lines


def build_report() -> tuple[str, dict[str, str]]:
    prereqs = probe_prerequisites()
    present = {p.key: p.present for p in prereqs}
    verdicts = {c.claim: classify(c, present) for c in CAPABILITIES}

    lane = engine_artifact_lane()
    lines = ["", "=" * 78, "BOOTSTRAP STATE - what this checkout does and does not exercise",
             "=" * 78, "", f"MODEL LANE: {lane.lane.upper()}", ""]
    lines += [f"  {line}" for line in textwrap.wrap(lane.detail, 74)]
    if lane.lane == LANE_DEMO:
        lines += [
            "",
            "  Every capability below marked DEMO ran against that model. It is a",
            "  real check that the pipeline works and it is NOT a reproduction of",
            "  any number this project publishes: those were measured on",
            "  CSE-CIC-IDS-2018 under a standardised HMAC key, on a dataset this",
            "  bootstrap does not include. See docs/INSTALL.md and JUDGES.md Part 3.",
        ]
    lines += ["", "PREREQUISITES", ""]
    for p in prereqs:
        mark = "present" if p.present else "ABSENT "
        lines.append(f"  [{mark}] {p.key}: {p.detail}")
        if not p.present:
            lines.append(f"            -> {p.bootstrap}")

    lines += ["", "CAPABILITIES", ""]
    lines += [f"  {state:<{_WIDTH}} = {meaning}" for state, meaning in LEGEND.items()]
    lines += [f"  {'/'.join(UNRESOLVED)} = this probe could not decide; the suite fails.",
              "  States are read from the tests' real skip markers, not declared here.", ""]
    for capability in CAPABILITIES:
        state = verdicts[capability.claim]
        needs_met = all(present[n] for n in capability.needs)
        missing = [n for n in capability.needs if not present[n]]
        lines.append(f"  [{state:<{_WIDTH}}] {capability.claim}")
        for spec in capability.tests:
            lines += _node_lines(spec, needs_met)
        if not capability.tests:
            lines.append(f"      no automated test in this suite - {capability.manual}")
        if state in (SKIPPED, PARTIAL, DEMO):
            lines.append(f"      blocked on: {', '.join(missing) or 'a gate this report cannot name'}"
                         if missing else
                         "      nothing is blocked; what ran, ran on the demo model")
        elif missing:
            # UNTESTED (and any UNRESOLVED state) still names its absent inputs:
            # the state says nothing here checks the claim, this says the reader
            # could not check it by hand on this machine either.
            lines.append(f"      prerequisites absent: {', '.join(missing)}")

    lines += ["", "EXERCISED ON A BARE CHECKOUT", ""]
    for claim, spec in ALWAYS_EXERCISED:
        nodes = probe_nodes(spec)
        gated = [n for n in nodes if n.state == NODE_GATED]
        bad = [n for n in nodes if n.state in UNRESOLVED]
        state = bad[0].state if bad else (SKIPPED if len(gated) == len(nodes) else
                                          PARTIAL if gated else RUNS)
        lines.append(f"  [{state:<{_WIDTH}}] {claim}")
        lines += _node_lines(spec, True)

    # What the demo lane is PERMITTED to run, against what it really runs. This
    # section exists because the two numbers are different and the difference is
    # invisible from the registry alone. See demo_lane_permissions().
    executing, held_back = demo_lane_permissions()
    lines += ["", DEMO_PERMISSION_HEADING, "",
              f"  {len(executing)} of {len(executing) + len(held_back)} tests that "
              "tests/conftest.py judges safe to run against the demo",
              f"  model actually execute on this checkout (lane: {lane.lane.upper()})."]
    if lane.lane != LANE_DEMO:
        # Without this the section reads as a demo lane underperforming, on a
        # machine that has no demo lane at all. Both are "0 of 11" and they are
        # not the same fact.
        lines += [
            "  This checkout is not in the demo lane, so that count is the",
            "  ordinary one: nothing model-dependent runs here either way. Run",
            "  `python scripts/bootstrap_demo_artifacts.py` to see the demo-lane",
            "  answer.",
        ]
    if held_back:
        lines += [
            "",
            "  These are PERMITTED on the demo lane and are held back anyway, by",
            "  their own skip marker - which reads the PUBLISHED artifacts:",
            "",
        ]
        lines += [f"      {key}" for key in held_back]
        lines += [
            "",
            "  That gap understates what is checked; it can never overstate it. Do",
            "  not close it by rewiring those gates to the demo lane and then",
            "  softening whatever assertion fails - several of them require a",
            "  non-empty forecast list, and the demo model raises no alert at all",
            "  on the committed flow fixture. The thing that has to change is the",
            "  demo lane, never the assertion. tests/conftest.py records the",
            "  measurement above DEMO_LANE_ALLOWED.",
        ]
    lines.append("")

    fully = sum(1 for v in verdicts.values() if v == RUNS)
    partly = sum(1 for v in verdicts.values() if v == PARTIAL)
    on_demo = sum(1 for v in verdicts.values() if v == DEMO)
    untested = sum(1 for v in verdicts.values() if v == UNTESTED)
    lines += ["", f"{fully}/{len(CAPABILITIES)} capabilities are fully exercised against "
                  f"the published artifacts in this checkout; {on_demo} against the demo "
                  f"model only; {partly} partly; {untested} with no automated test on any "
                  "machine.", ""]
    # Bootstrapping is what closes a gap caused by a MISSING INPUT, so the hint
    # is conditioned on one being missing. Conditioning it on the verdicts
    # instead — as this did — tells a fully bootstrapped reader to bootstrap,
    # because UNTESTED is a gap no download can close.
    if not all(present.values()):
        lines += ["Bootstrap with `python scripts/fetch_artifacts.py` (GitHub Release) or",
                  "`python -m engine.train_engine` (needs the dataset). See docs/INSTALL.md.", ""]
    lines.append("=" * 78)
    return "\n".join(lines), verdicts


def test_bootstrap_state_is_disclosed():
    """Prints the report, and fails if the report is not a complete one.

    The assertions are deliberately about things a rendering bug can get wrong:
    a claim or a prerequisite silently dropped from the output, or a pass/skip
    count creeping back in. The substantive checks — that the states the report
    prints match the tests' real behaviour — are the three tests below.
    """
    report, verdicts = build_report()
    print(report)

    for capability in CAPABILITIES:
        assert capability.claim in report, (
            f"capability missing from the printed report: {capability.claim!r}. "
            "A disclosure that omits a gap is worse than none."
        )
        assert f"[{verdicts[capability.claim]:<{_WIDTH}}]" in report
    for prerequisite in probe_prerequisites():
        assert prerequisite.key in report, (
            f"prerequisite missing from the printed report: {prerequisite.key!r}"
        )
    for state in sorted(set(verdicts.values())):
        assert state in LEGEND or state in UNRESOLVED, (
            f"the report prints the state {state!r} and the legend does not define "
            "it. A state a reader cannot look up is worse than no state: add it to "
            "LEGEND with what it actually means."
        )
        if state in LEGEND:
            assert f"  {state:<{_WIDTH}} = {LEGEND[state]}" in report, (
                f"{state!r} is defined in LEGEND but its line is not in the report"
            )
    count = re.search(r"\d+\s+passed,\s+\d+\s+skipped", report)
    assert not count, (
        f"the report publishes a fixed suite count ({count.group(0)!r}). The suite "
        "grows; a hardcoded count becomes a lie. Report the criterion, not the number."
    )


def test_every_named_test_node_resolves():
    """Falsifiable: a renamed, deleted, unimportable or unreadable test must break
    this report loudly instead of being reported as a gap - or a guarantee - that
    happens to look plausible."""
    unresolved = []
    specs = [s for c in CAPABILITIES for s in c.tests]
    specs += [spec for _, spec in ALWAYS_EXERCISED]
    for spec in specs:
        for node in probe_nodes(spec):
            if node.state in UNRESOLVED:
                unresolved.append(f"{node.node_id}  <- {node.state}: {node.detail}")
    assert not unresolved, (
        "this report names test nodes that do not resolve:\n  "
        + "\n  ".join(unresolved)
        + "\nFix the node id, or move the claim - a disclosure that points at a "
        "test which no longer exists is not a disclosure."
    )


def test_the_report_separates_a_skip_marker_from_a_self_skipping_body():
    """"pytest will not run this" and "pytest runs it and it may skip itself" are
    different facts about a judge's machine, and the report printed both as
    `gated`.

    It mattered here and not in theory: on this checkout
    tests/test_app.py::test_the_real_forecaster_matches_the_shared_api_contract
    and ::test_the_app_sees_every_demo_flag_the_engine_ships were both listed as
    gated, and both run and pass (measured 2026-09-12, `pytest tests/test_app.py
    -k ... -q` -> 2 passed). The error is in the understating direction, which is
    the one this file always chooses when it must choose - but a disclosure
    document has no licence to be inaccurate in either direction.

    Constructed, never read off this machine, so it cannot go vacuous the day
    those two test functions change. Falsifiable against the obvious
    simplification: collapse the two labels back into one `gated:` and the second
    and third assertions fail. The last two pin the accounting the labels sit on
    top of - a cosmetic relabelling that also quietly promoted a self-skipping
    node into the executing count would be a real over-claim, and it fires here.
    """
    spec = "tests/test_a_synthetic_probe_module.py"
    _NODE_CACHE[spec] = [
        Node(f"{spec}::test_carries_a_skip_marker", NODE_GATED),
        Node(f"{spec}::test_body_calls_pytest_skip", NODE_RUNTIME),
        Node(f"{spec}::test_just_runs", NODE_RUNS),
    ]
    try:
        unmet = "\n".join(_node_lines(spec, needs_met=False))
        met = "\n".join(_node_lines(spec, needs_met=True))
    finally:
        _NODE_CACHE.pop(spec, None)

    assert "gated: test_carries_a_skip_marker" in unmet
    assert "may self-skip: test_body_calls_pytest_skip" in unmet, (
        "a node that pytest really executes is being reported to a judge as one "
        "pytest will not run"
    )
    assert "gated: test_body_calls_pytest_skip" not in unmet
    assert "1 of 3 test functions execute here" in unmet, (
        "with the prerequisite absent, only the ungated node may be counted"
    )
    assert "2 of 3 test functions execute here" in met, (
        "with the prerequisite present the self-skipping node is counted; a "
        "marker-gated one never is"
    )
    assert "gated: test_carries_a_skip_marker" in met


def test_claims_listed_as_exercised_are_not_gated():
    """Falsifiable and non-vacuous on a bare checkout: every ALWAYS_EXERCISED
    entry asserts the test runs here. Adding a skip gate to one of those files
    without moving the claim turns this report into a lie, and fails here."""
    gated = []
    for claim, spec in ALWAYS_EXERCISED:
        for node in probe_nodes(spec):
            if node.state == NODE_GATED:
                gated.append(f"{node.node_id} (listed as always exercised: {claim!r})")
    assert not gated, (
        "these are reported as exercised on a bare checkout but carry a skip "
        "marker:\n  " + "\n  ".join(gated)
        + "\nEither remove the gate or move the claim into CAPABILITIES with the "
        "prerequisite it now needs."
    )


def test_capability_states_match_the_declared_prerequisites():
    """`needs` must explain the state, in whichever direction this machine is in.

    An earlier version opened with `if not all(present[n] for n in needs):
    continue`, so on a bare checkout — where 0 of the 11 capabilities have every
    prerequisite — the body never ran at all. It shipped as coverage to judges
    cloning the repo and to CI, and could not have failed for either of them.

    So there are two assertions, and every capability goes through exactly one:

      prerequisites all present -> no named node may be gated. A node gated on
        something `needs` does not mention makes the `blocked on:` line
        incomplete, which is how a judge is told a gap is closed when it is not.
        This is the branch that runs on a bootstrapped machine.

      a prerequisite absent -> the capability must not be reported as RUNS. This
        is the branch that runs on a bare checkout, and it is the over-claiming
        direction: a guarantee announced as exercised while an input it declares
        it needs is missing. Remove the skip gate from tests/test_offline.py, say,
        and this fires here with nothing bootstrapped.

    `checked` then counts what was actually examined and asserts it covered every
    capability, so no future `continue` can quietly empty this test again. A
    capability with no tests passes through a branch here without an assertion of
    its own — `checked` counts it, the node loop has nothing to iterate — so the
    state it is given is checked by
    test_a_capability_with_no_test_is_never_reported_as_exercised instead, which
    constructs both prerequisite conditions rather than reading this machine's.
    """
    present = {p.key: p.present for p in probe_prerequisites()}
    wrong = []
    checked_bootstrapped = 0   # branch 1: everything this capability needs is here
    checked_bare = 0           # branch 2: something it needs is missing
    for capability in CAPABILITIES:
        missing = [n for n in capability.needs if not present[n]]
        if missing:
            if classify(capability, present) == RUNS:
                wrong.append(
                    f"{capability.claim!r} is reported RUNS although it declares "
                    f"prerequisites this checkout does not have: {missing}. Either "
                    f"a gate is missing from {list(capability.tests) or '(no tests)'}"
                    " or `needs` lists something the tests do not actually need."
                )
            checked_bare += 1
            continue
        for spec in capability.tests:
            for node in probe_nodes(spec):
                if node.state == NODE_GATED:
                    wrong.append(
                        f"{node.node_id} is gated although every declared "
                        f"prerequisite {list(capability.needs)} is present"
                    )
        checked_bootstrapped += 1
    checked = checked_bare + checked_bootstrapped
    assert checked == len(CAPABILITIES), (
        f"only {checked} of {len(CAPABILITIES)} capabilities were examined "
        f"({checked_bare} on the missing-prerequisite branch, "
        f"{checked_bootstrapped} on the all-present branch). This test was once "
        "made vacuous by an early `continue`; every capability must reach one of "
        "the two assertions above, on every machine."
    )
    assert not wrong, (
        "\n  ".join([""] + wrong)
        + "\nAdd the missing prerequisite to this capability's `needs` so the "
        "report can name what it is blocked on, or stop claiming the guarantee is "
        "exercised here."
    )


def test_a_capability_with_no_test_is_never_reported_as_exercised():
    """The over-claim UNTESTED exists to stop, checked in BOTH directions on every
    machine instead of only the one the runner happens to be sitting at.

    `classify` used to return RUNS for a capability whose `tests` is empty as soon
    as its prerequisites were present. On any checkout holding results/*.json the
    report therefore printed "[RUNS] The published ablation table is regenerable"
    on one line and "no automated test" on the next, under a legend saying RUNS
    means every named test executes here — of which there were none. A present
    input is not a check of what is done with it.

    Both prerequisite conditions are CONSTRUCTED here rather than read off this
    machine, so neither branch can go vacuous on a bare checkout or on a
    bootstrapped one. Restore the old `return RUNS if needs_met else SKIPPED` and
    the all-present case fails here with nothing bootstrapped.
    """
    testless = [c for c in CAPABILITIES if not c.tests]
    assert testless, (
        "no capability declares tests=() any more. If every claim is automated "
        "now, delete UNTESTED and this test together — do not leave behind a "
        "state that nothing can produce and that nothing therefore checks."
    )
    keys = [p.key for p in probe_prerequisites()]
    conditions = (
        ("every prerequisite present", dict.fromkeys(keys, True)),
        ("no prerequisite present", dict.fromkeys(keys, False)),
    )
    for capability in testless:
        for label, present in conditions:
            state = classify(capability, present)
            assert state == UNTESTED, (
                f"{capability.claim!r} names no test at all, yet with {label} this "
                f"report calls it {state!r}. Whatever is on disk, nothing here "
                f"verifies it: the honest state is {UNTESTED!r}."
            )


def test_untested_capabilities_name_the_manual_check():
    """An UNTESTED claim must at least tell a judge how to check it by hand.

    Without this, `manual=""` renders as a dangling "no automated test in this
    suite - " and the disclosure states a gap while withholding the one thing
    that would close it."""
    for capability in CAPABILITIES:
        if capability.tests:
            assert not capability.manual, (
                f"{capability.claim!r} names tests AND a manual procedure. The "
                "report prints `manual` only for a capability with no tests, so "
                "this one would never be seen — put it in the test's docstring."
            )
            continue
        assert capability.manual.strip(), (
            f"{capability.claim!r} has no automated test and no `manual` "
            "procedure, so this report would disclose the gap and then leave the "
            "reader with no way to close it. State the commands, or delete the "
            "claim."
        )
        assert f"no automated test in this suite - {capability.manual}" in build_report()[0], (
            f"the manual procedure declared for {capability.claim!r} is not in the "
            "printed report, so it is documentation only this test can see"
        )


def test_declared_prerequisites_are_probeable():
    """Every capability names prerequisites the probe actually reports on. A typo
    here would silently mark a gap as exercised."""
    known = {p.key for p in probe_prerequisites()}
    for capability in CAPABILITIES:
        unknown = set(capability.needs) - known
        assert not unknown, (
            f"{capability.claim!r} needs {sorted(unknown)}, which probe_prerequisites() "
            "does not report - add it there or fix the name"
        )


# ==========================================================================
# The three lanes, and the guard that keeps every artifact gate honest
# ==========================================================================
# Everything below CONSTRUCTS the lanes on disk rather than reading the one this
# machine happens to be in. A test that only inspected `engine_artifact_lane()`
# here would assert whatever this checkout is and prove nothing about the other
# two, and which one that is changes the day someone runs the demo bootstrap.
# Each case is built in a tmp_path and probed through the real
# engine/predict.py resolver, with nothing stubbed out.

_DEMO_THRESHOLDS = {
    "artifact_lane": "demo",
    "demo_provenance": {"fitted_from": "app/assets/synthetic_demo.pcap"},
    "flow": {"file": "demo_engine_model_flow.json", "fpr_0.01": 0.5},
    "full": {"file": "demo_engine_model.json", "fpr_0.01": 0.5},
}


@contextlib.contextmanager
def _lane_on_disk(tmp_path, kind: str, *, released_digests: bool = True):
    """Build one lane in tmp_path and make this process see it.

    `real`  writes the published bundle into the published directory and a README
            whose weights table carries its true SHA-256s, so LANE_REAL is reached
            the only way it can be - by the engine finding the bundle - and
            `digests_match` is reached the only way IT can, by hashing the files.
    `demo`  leaves the published directory EMPTY and writes a demo lane that
            declares itself one, exactly as scripts/bootstrap_demo_artifacts.py
            does: its own directory, its own model filenames, and
            `artifact_lane: "demo"` in the persisted thresholds.
    `none`  neither.

    released_digests=False publishes a table for OTHER bytes, which is the local
    retrain: a real published bundle that is not the released one.
    """
    import configs
    from tests import _stubs

    base = tmp_path / f"{kind}-{released_digests}"
    art = base / "artifacts"
    demo_dir = base / "artifacts_demo"
    fake_root = base / "repo"
    (fake_root / "scripts").mkdir(parents=True, exist_ok=True)
    shutil.copy(REPO_ROOT / "scripts" / "fetch_artifacts.py",
                fake_root / "scripts" / "fetch_artifacts.py")

    if kind == LANE_REAL:
        art.mkdir(parents=True, exist_ok=True)
        for name in ENGINE_ARTIFACTS:
            (art / name).write_bytes(f"published-bytes-{name}".encode())
    elif kind == LANE_DEMO:
        demo_dir.mkdir(parents=True, exist_ok=True)
        (demo_dir / "engine_threshold.json").write_text(
            json.dumps(_DEMO_THRESHOLDS), encoding="utf-8")
        (demo_dir / "window_scaler.pkl").write_bytes(b"demo-scaler")
        for name in ("demo_engine_model.json", "demo_engine_model_flow.json"):
            (demo_dir / name).write_bytes(b"demo-model")

    def sha(path):
        return hashlib.sha256(path.read_bytes()).hexdigest()

    if kind == LANE_REAL and released_digests:
        digests = {n: sha(art / n) for n in ENGINE_ARTIFACTS if n != "engine_threshold.json"}
    else:
        digests = {n: hashlib.sha256(f"released-{n}".encode()).hexdigest()
                   for n in ENGINE_ARTIFACTS if n != "engine_threshold.json"}
    rows = "\n".join(f"| `{k}` | `{v}` |" for k, v in digests.items())
    (fake_root / "README.md").write_text(
        "## Model weights\n\n| artefact | SHA-256 |\n|---|---|\n" + rows + "\n",
        encoding="utf-8",
    )

    # The gates under test are module-level `pytestmark = skipif(...)` and
    # decorator conditions, EVALUATED AT IMPORT. A module already imported under
    # another lane carries that lane's frozen answer, so switching the lane
    # without re-importing would test nothing. Purge the artifact-gated test
    # modules so probe_nodes re-imports them here, exactly as pytest imports them
    # on a machine really in this lane - then put the originals back, so a
    # full-suite run is left with the module objects it collected.
    gated_modules = sorted({
        "tests." + key.split("::")[0].split("/")[-1][:-3] for key in artifact_gated_nodes()
    })
    saved = {name: sys.modules[name] for name in gated_modules if name in sys.modules}

    real_load_config = configs.load_config
    real_stub_root = _stubs.REPO_ROOT

    def patched(name):
        cfg = copy.deepcopy(real_load_config(name))
        if name == "data":
            cfg["paths"]["artifacts_dir"] = str(art)
            # The demo lane is repointed too. Without this the repository's own
            # artifacts_demo/ leaks into every constructed lane, and `none`
            # silently becomes `demo` on any machine that has run the bootstrap -
            # which is every machine this is meant to protect.
            if isinstance(cfg.get("demo"), dict):
                cfg["demo"]["artifacts_dir"] = str(demo_dir)
        return cfg

    configs.load_config = patched
    _stubs.REPO_ROOT = fake_root
    for name in saved:
        del sys.modules[name]
    _stubs.reset_artifact_lane_cache()
    _NODE_CACHE.clear()
    try:
        yield art
    finally:
        configs.load_config = real_load_config
        _stubs.REPO_ROOT = real_stub_root
        for name in gated_modules:
            sys.modules.pop(name, None)
        sys.modules.update(saved)
        _stubs.reset_artifact_lane_cache()
        _NODE_CACHE.clear()


def test_the_three_artifact_lanes_are_distinguished(tmp_path):
    """One boolean cannot say which model is on disk; three lanes must.

    Falsifiable against the break this exists to stop: make
    engine_artifacts_present() answer "is there any loadable model" - the obvious
    way to turn the end-to-end skips green once a demo lane exists - and the demo
    case below fails, because a toy model would have satisfied the gate that
    tests/test_offline.py and tests/test_smoke.py read.
    """
    from tests._stubs import (
        engine_artifacts_present,
        engine_model_loadable,
        published_artifacts_are_the_released_ones,
    )

    with _lane_on_disk(tmp_path, LANE_NONE):
        lane = engine_artifact_lane()
        assert lane.lane == LANE_NONE, lane.detail
        assert not lane.has_model and not lane.is_published
        assert (engine_artifacts_present(), engine_model_loadable()) == (False, False)

    with _lane_on_disk(tmp_path, LANE_REAL):
        lane = engine_artifact_lane()
        assert lane.lane == LANE_REAL, lane.detail
        assert lane.has_model and lane.is_published and lane.digests_match
        assert (engine_artifacts_present(), engine_model_loadable()) == (True, True)
        assert published_artifacts_are_the_released_ones() is True

    with _lane_on_disk(tmp_path, LANE_DEMO):
        lane = engine_artifact_lane()
        assert lane.lane == LANE_DEMO, lane.detail
        assert lane.has_model, "the demo lane is loadable; the pipeline can run on it"
        assert engine_model_loadable() is True
        assert lane.is_published is False and engine_artifacts_present() is False, (
            "a demo lane that satisfies the published-artifact gate would turn "
            "tests/test_offline.py and tests/test_smoke.py green against a toy "
            "model fitted on one bundled capture. That is the trap."
        )
        assert published_artifacts_are_the_released_ones() is False
        assert "synthetic" in lane.detail and "cannot be evidence" in lane.detail


def test_a_local_retrain_is_published_but_not_the_released_bytes(tmp_path):
    """The fourth fact the lanes carry, and the one a report can get wrong
    quietly: the published bundle being PRESENT is not the same as it being the
    artefact the published numbers were measured on.

    Falsifiable: return True from digests_match whenever is_published is True -
    the "who checks hashes" simplification - and this fails, because a bundle
    whose bytes are not in README.md's table would be reported as the released
    one. Note the direction: the local retrain keeps every gate it had
    (engine_artifacts_present stays True), so this tightens a claim without
    removing a capability.
    """
    from tests._stubs import engine_artifacts_present

    with _lane_on_disk(tmp_path, LANE_REAL, released_digests=False):
        lane = engine_artifact_lane()
        assert lane.lane == LANE_REAL and engine_artifacts_present() is True
        assert lane.digests_match is False, lane.digest_detail
        assert lane.digest_unverified, "the mismatching artefacts must be named"
        assert "MISMATCH" in lane.digest_detail


def test_a_demo_lane_never_reports_a_model_capability_as_RUNS(tmp_path):
    """The report's half of the contract, checked in the lane it is about.

    Falsifiable: delete the DEMO branch from classify() and the demo-bootstrap
    capability reports RUNS - "its verdict is this suite's own" - for a toy model
    that has memorised the capture it is scored on.
    """
    with _lane_on_disk(tmp_path, LANE_DEMO):
        report, verdicts = build_report()
        assert "MODEL LANE: DEMO" in report
        assert f"  {DEMO:<{_WIDTH}} = {LEGEND[DEMO]}" in report, (
            "the DEMO state must carry its own legend line; a state a reader "
            "cannot look up is worse than no state"
        )
        assert RUNS not in {
            verdicts[c.claim] for c in CAPABILITIES
            if c.evidence_lane == LANE_DEMO
            or "published engine artifacts" in c.needs
            or "a loadable engine model" in c.needs
        }, "no model-dependent capability may report RUNS while the model is a demo model"

        demo_caps = [c for c in CAPABILITIES if c.evidence_lane == LANE_DEMO]
        assert demo_caps, (
            "no capability declares evidence_lane=LANE_DEMO any more, so the DEMO "
            "state and its legend line are unreachable. Delete them together or "
            "restore the capability - a state nothing can produce is a state "
            "nothing checks."
        )
        for capability in demo_caps:
            assert verdicts[capability.claim] == DEMO, (
                f"{capability.claim!r} is evidence from the demo model and reports "
                f"{verdicts[capability.claim]!r}"
            )


def test_a_demo_capability_reports_DEMO_on_every_machine(tmp_path):
    """evidence_lane is about the TESTS, not about this checkout.

    tests/test_demo_bootstrap.py builds and scores a demo model wherever it runs,
    so on a machine holding the full published bundle it is still demo evidence.
    Constructed in the published lane precisely because that is the machine where
    a lane-derived-only rule would silently upgrade it to RUNS.
    """
    with _lane_on_disk(tmp_path, LANE_REAL):
        _, verdicts = build_report()
        for capability in (c for c in CAPABILITIES if c.evidence_lane == LANE_DEMO):
            assert verdicts[capability.claim] == DEMO, (
                f"{capability.claim!r} reports {verdicts[capability.claim]!r} on a "
                "machine with the published artifacts. Its tests fit their own toy "
                "model; what is on disk cannot change what they are evidence for."
            )


def test_the_demo_lane_gates_exactly_the_published_only_tests(tmp_path):
    """The suite's half of the contract: on the demo lane, PUBLISHED_ONLY nodes
    are gated BY THE LANE and DEMO_LANE_ALLOWED nodes are not.

    This reads the same registry tests/conftest.py's collection hook reads, so a
    node moved between the two dictionaries changes the report and the suite at
    once - which is why the registry is imported here rather than restated.
    """
    with _lane_on_disk(tmp_path, LANE_DEMO):
        for spec in PUBLISHED_ONLY:
            nodes = probe_nodes(spec)
            assert nodes and all(
                n.state == NODE_GATED and "demo lane" in n.detail for n in nodes
            ), (
                f"{spec} is PUBLISHED_ONLY and must be gated BY THE LANE on the demo "
                f"lane, not incidentally by its own marker; got "
                f"{[(n.node_id, n.state, n.detail) for n in nodes]}"
            )
        for spec in DEMO_LANE_ALLOWED:
            nodes = probe_nodes(spec)
            assert nodes, f"{spec} resolved to no node at all"
            assert not any(
                n.state == NODE_GATED and "demo lane" in n.detail for n in nodes
            ), f"{spec} is DEMO_LANE_ALLOWED but this report gates it on the demo lane"


def test_the_collection_hook_itself_adds_the_demo_lane_skips(tmp_path):
    """The ENFORCEMENT half, which had no test at all until now.

    test_the_demo_lane_gates_exactly_the_published_only_tests above checks that
    THIS REPORT applies the registry (via _lane_override). It does not touch
    tests/conftest.py::pytest_collection_modifyitems, which is the code that
    really skips a test during a run - and on this checkout that hook has never
    been observed doing anything, because every PUBLISHED_ONLY node is already
    held back by its own marker, so the hook's effect is invisible in a normal
    run. An unobserved enforcement mechanism guarding a registry that reads as
    enforcement is this project's failure mode with the labels swapped.

    So the hook is called directly, on a constructed demo lane, with fake
    collected items - `nodeid` and `add_marker` are the whole interface it uses.
    Three properties, all of which a plausible edit breaks:

      * a PUBLISHED_ONLY node gets a skip whose reason carries the registry's own
        words, so a judge reading the skip line reads the decision record;
      * a DEMO_LANE_ALLOWED node gets NOTHING - the hook must not be a blanket
        "skip everything on the demo lane", which would make the per-test
        reasoning decorative;
      * an unclassified artifact gate gets a skip too. This is the deny-default,
        and it is what makes forgetting to classify a new test safe.

    Falsifiable: delete the `PUBLISHED_ONLY.get(key)` branch (the "their own
    markers already handle it" simplification, which is true today and false the
    moment a gate is rewired) and the first assertion fails; widen the hook to
    skip every artifact-gated node and the second fails; drop the `elif key in
    unclassified` branch and the third fails.
    """
    import tests.conftest as C

    class _Item:
        def __init__(self, nodeid):
            self.nodeid = nodeid
            self.markers = []

        def add_marker(self, marker):
            self.markers.append(marker)

    published_only = sorted(PUBLISHED_ONLY)[0]
    demo_allowed = sorted(DEMO_LANE_ALLOWED)[0]
    unclassified_id = "tests/test_not_in_any_registry.py::test_gated_on_artifacts"

    with _lane_on_disk(tmp_path, LANE_DEMO):
        assert engine_artifact_lane().lane == LANE_DEMO, "the lane fixture did not take"
        items = [_Item(published_only), _Item(demo_allowed), _Item(unclassified_id)]
        # The hook asks unclassified_artifact_gates() which nodes owe a decision.
        # The fabricated id is not in any test file, so it is injected here rather
        # than by writing a module into tests/ mid-session.
        real = C.unclassified_artifact_gates
        C.unclassified_artifact_gates = lambda: {unclassified_id: "skipif(artifacts/...)"}
        try:
            C.pytest_collection_modifyitems(config=None, items=items)
        finally:
            C.unclassified_artifact_gates = real

    gated, allowed, unknown = items
    assert len(gated.markers) == 1, (
        f"{published_only} is PUBLISHED_ONLY and the collection hook added no skip "
        "on the demo lane. The registry would then be commentary: the only thing "
        "keeping that test off the demo model is its own marker, which is exactly "
        "what a gate rewire removes."
    )
    reason = gated.markers[0].kwargs["reason"]
    assert reason.startswith(C._DEMO_SKIP_PREFIX)
    assert PUBLISHED_ONLY[published_only] in reason, (
        "the skip reason must carry this test's own entry verbatim - it is what a "
        "judge sees on the skip line and the decision record a reviewer reads"
    )
    assert allowed.markers == [], (
        f"{demo_allowed} is DEMO_LANE_ALLOWED and the hook skipped it anyway. A "
        "hook that skips everything on the demo lane makes every paragraph of "
        "per-test reasoning in tests/conftest.py decorative."
    )
    assert len(unknown.markers) == 1 and unknown.markers[0].kwargs["reason"] == (
        C._UNCLASSIFIED_SKIP), (
        "an artifact-gated test that declares no lane must be SKIPPED on the demo "
        "lane, not run. Deny-defaulting is what makes forgetting to classify a new "
        "test safe rather than silently green against a toy model."
    )


def test_the_collection_hook_does_nothing_off_the_demo_lane(tmp_path):
    """...and the other direction, which is the one that would break other people.

    The hook must be inert on LANE_REAL and LANE_NONE: on a machine with the
    published artifacts the suite has to behave exactly as it did before the demo
    bootstrap existed, or this workstream has quietly changed what every other
    machine verifies.

    Falsifiable: remove the `if engine_artifact_lane().lane != LANE_DEMO: return`
    early exit and both cases below fail - on LANE_REAL a PUBLISHED_ONLY test
    that SHOULD run against the published model would be skipped, which is the
    over-tightening mirror image of the trap this whole design is about.
    """
    import tests.conftest as C

    class _Item:
        def __init__(self, nodeid):
            self.nodeid = nodeid
            self.markers = []

        def add_marker(self, marker):
            self.markers.append(marker)

    published_only = sorted(PUBLISHED_ONLY)[0]
    for kind in (LANE_REAL, LANE_NONE):
        with _lane_on_disk(tmp_path, kind):
            assert engine_artifact_lane().lane == kind, "the lane fixture did not take"
            items = [_Item(published_only)]
            C.pytest_collection_modifyitems(config=None, items=items)
        assert items[0].markers == [], (
            f"the collection hook added a skip on lane {kind!r}. It may only ever "
            "tighten the DEMO lane; on any other lane the suite must be byte-for-"
            "byte the suite that existed before the demo bootstrap."
        )


def test_the_demo_lane_reports_what_it_permits_but_does_not_run(tmp_path):
    """A permission that reads as a capability is this project's failure mode.

    tests/conftest.py::DEMO_LANE_ALLOWED carries eleven paragraphs of reasoning
    for why each of those tests could legitimately run against the demo model.
    None of them runs against it today: every one is held back by its own skip
    marker, which reads the PUBLISHED artifacts directory and lives in a test
    module this workstream does not own. Argued permission, zero execution - and
    from the registry alone the two are indistinguishable.

    So the report must NAME the held-back ones on the demo lane, and this
    constructs the demo lane to check that it does rather than trusting whichever
    lane the runner happens to be sitting in.

    Falsifiable two ways, both of them plausible:
      * delete the section from build_report() - the obvious tidy-up, since the
        section says nothing on a machine where everything runs - and the
        assertions below fail;
      * make demo_lane_permissions() count a gated node as executing (drop the
        `all(_executes(...))` for a truthier-looking `any`, say) and `held_back`
        empties, the report prints nothing, and this fails on the first two
        assertions.
    """
    with _lane_on_disk(tmp_path, LANE_DEMO):
        report, _ = build_report()
        executing, held_back = demo_lane_permissions()

        assert DEMO_PERMISSION_HEADING in report, (
            "the report does not separate what the demo lane is permitted to run "
            "from what it runs. A reader who takes DEMO_LANE_ALLOWED at face "
            "value would believe those tests are exercising the demo model."
        )
        assert set(executing) | set(held_back) == set(DEMO_LANE_ALLOWED), (
            "demo_lane_permissions() dropped or invented a registry key; it must "
            "account for every DEMO_LANE_ALLOWED entry exactly once"
        )
        for key in held_back:
            assert key in report, (
                f"{key} is permitted on the demo lane and does not execute there, "
                "and the report does not name it. An unnamed gap is the one that "
                "gets closed by weakening an assertion."
            )
        assert f"{len(executing)} of {len(executing) + len(held_back)} tests" in report, (
            "the report must state the two counts side by side; a list without "
            "the ratio is easy to read as 'these few' rather than 'these of all'"
        )


def test_the_gate_scan_cache_notices_an_edited_test_file(tmp_path):
    """The cache added to tests/conftest.py must not outlive the files it read.

    artifact_gated_nodes() ast-parses every tests/test_*.py, which cost ~1.1 s
    per call and was being called once per probed node; memoising it took
    tests/test_bootstrap_state.py from 271.96 s to 5.37 s, both measured in this
    session. A cache is also how a registry silently stops seeing a newly added
    artifact gate, and `test_every_artifact_gated_test_declares_a_lane` would
    then pass on a stale answer - the exact shape of failure that guard exists to
    prevent.

    Falsifiable, and exercised: keying the cache on a constant instead of
    _tests_dir_signature() - the "the tests directory does not change during a
    run" simplification - makes this fail. It failed on the FIRST assertion when
    tried, not the second: with a constant key the entry cached from the real
    tests/ directory earlier in the session was served for this temporary one, so
    a directory holding a single ungated module reported the whole repository's
    artifact gates. Either assertion firing is the point; a stale gate scan is
    not a subtle wrongness.
    """
    import tests.conftest as C

    fake_tests = tmp_path / "tests"
    fake_tests.mkdir()
    added = fake_tests / "test_cache_probe.py"
    added.write_text(
        "def test_nothing_is_gated_here():\n    pass\n", encoding="utf-8")

    real_root = C.REPO_ROOT
    C.REPO_ROOT = tmp_path
    try:
        assert C.artifact_gated_nodes() == {}, (
            "a module with no gate at all must contribute no artifact-gated node"
        )
        # Now give it a gate, exactly as a new test would.
        added.write_text(
            "import pytest\n"
            "from tests._stubs import engine_artifacts_present\n\n\n"
            "@pytest.mark.skipif(not engine_artifacts_present(), reason='no artifacts')\n"
            "def test_nothing_is_gated_here():\n    pass\n",
            encoding="utf-8",
        )
        found = C.artifact_gated_nodes()
        assert "tests/test_cache_probe.py::test_nothing_is_gated_here" in found, (
            "an artifact gate added after the first scan was not seen on the "
            f"second: the cache is stale. Found {sorted(found)}"
        )
    finally:
        C.REPO_ROOT = real_root
        C._GATE_CACHE.clear()


def test_every_artifact_gated_test_declares_a_lane():
    """A new gate on "are the trained artifacts there" owes a lane decision.

    tests/conftest.py::artifact_gated_nodes() reads the gates out of the test
    files themselves, so this cannot be satisfied by forgetting to list
    something. Add a test gated on artifacts/engine_model.json and leave it out
    of all three dictionaries and this fails here naming it - and on the demo
    lane the collection hook skips it rather than letting a toy model pass it.
    """
    unclassified = unclassified_artifact_gates()
    assert not unclassified, (
        "these tests gate on the presence of trained artifacts but declare no "
        "lane in tests/conftest.py:\n  "
        + "\n  ".join(f"{k}\n    gate: {v}" for k, v in sorted(unclassified.items()))
        + "\nPut each in DEMO_LANE_ALLOWED (its subject is plumbing, so the demo "
          "model exercises it), PUBLISHED_ONLY (its subject is a measured number) "
          "or NO_MODEL_ONLY (its gate is inverted), with the reasoning as the value."
    )


def test_the_lane_registry_names_tests_that_exist():
    """A renamed or deleted test must break the registry loudly.

    Without this, an entry in PUBLISHED_ONLY that matches no node is a gate that
    has silently stopped applying: the test it was protecting would run on the
    demo lane and nothing would say so.
    """
    known = set(artifact_gated_nodes())
    stale = [
        f"{key} ({bucket})"
        for bucket, registry in (
            ("DEMO_LANE_ALLOWED", DEMO_LANE_ALLOWED),
            ("PUBLISHED_ONLY", PUBLISHED_ONLY),
            ("NO_MODEL_ONLY", NO_MODEL_ONLY),
        )
        for key in registry
        if key not in known
    ]
    assert not stale, (
        "the lane registry in tests/conftest.py names nodes that are not "
        "artifact-gated tests in this checkout:\n  " + "\n  ".join(stale)
        + "\nA registry entry that matches nothing protects nothing. Either the "
          "test was renamed (update the key), or its gate stopped being an "
          "artifact gate (drop the entry)."
    )
    overlap = (set(DEMO_LANE_ALLOWED) & set(PUBLISHED_ONLY)) | (
        set(DEMO_LANE_ALLOWED) & set(NO_MODEL_ONLY)
    ) | (set(PUBLISHED_ONLY) & set(NO_MODEL_ONLY))
    assert not overlap, f"a test declares two conflicting lanes: {sorted(overlap)}"
    for bucket, registry in (("DEMO_LANE_ALLOWED", DEMO_LANE_ALLOWED),
                             ("PUBLISHED_ONLY", PUBLISHED_ONLY),
                             ("NO_MODEL_ONLY", NO_MODEL_ONLY)):
        for key, why in registry.items():
            assert len(why.split()) >= 12, (
                f"{bucket}[{key}] gives no reasoning ({why!r}). The value is "
                "printed to a judge as the skip reason and is the decision record "
                "a reviewer reads; a label is not a reason."
            )

if __name__ == "__main__":  # `python tests/test_bootstrap_state.py` prints the report
    print(build_report()[0])                # sys.path was fixed up at import time
