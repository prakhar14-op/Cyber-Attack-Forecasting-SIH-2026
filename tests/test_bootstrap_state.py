"""Disclosure: which guarantees this checkout actually exercises, and which it does not.

On a bare checkout `pytest tests/ -q` is green with a number of tests SKIPPED,
and those skips are not incidental — they include the end-to-end offline test
(the problem statement's hard constraint #1), the 1,000-flow smoke run, the
engine-dependent part of the Streamlit demo surface, and the train-only-scaler
anti-leakage check. A green summary line therefore overstates what has been
checked, and nothing else in the suite says so.

No expected pass/skip count appears here, in docs/INSTALL.md or in the CI
comment. An earlier version of this file published "78 passed, 16 skipped" in
its own docstring; the suite outgrew it within the same session and the figure
became a published falsehood in three places at once. The criterion for a
correct bare checkout is `0 failed, 0 errors, some skipped` — read the counts
off your own run. `tests/test_docs_claims.py` bans the reintroduction of a
hardcoded count.

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
result. PARTIAL means some execute and some are gated. SKIPPED means the
guarantee is not checked here at all. Gating is the right shape: the artifacts
are gitignored (CLAUDE.md forbids committing weights) and the dataset is
~12.7 GiB, so a bare checkout skipping them is correct behaviour, not breakage.

NO TEST FILE, UNIMPORTABLE and UNREADABLE are not verdicts. They mean this probe
could not work out what happens to a node, and `test_every_named_test_node_resolves`
fails on any of them rather than let the report print a plausible state it did not
derive. UNREADABLE in particular replaces an earlier fallback that reported a test
whose source could not be read as one that RUNS: of the two ways to be wrong, this
file is wrong in the direction that understates what has been checked.
"""

from __future__ import annotations

import importlib
import importlib.util
import inspect
import re
import sys
from dataclasses import dataclass
from pathlib import Path

if __name__ == "__main__":  # run as a plain script, the repo root is not on sys.path
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from configs import load_config, resolve_path
from tests._stubs import REPO_ROOT, engine_artifacts_present

RUNS = "RUNS"
PARTIAL = "PARTIAL"
SKIPPED = "SKIPPED"
UNKNOWN = "NO TEST FILE"
BROKEN = "UNIMPORTABLE"
# A node whose source could not be read, so whether it calls pytest.skip() in its
# body is not known. Reported, never guessed: see _node_state.
UNREADABLE = "UNREADABLE"
STATES = (RUNS, PARTIAL, SKIPPED, UNKNOWN, BROKEN, UNREADABLE)
# States that mean "this report could not work out what happens here". They are
# failures, not verdicts: test_every_named_test_node_resolves fails on any of
# them. Ordered worst-first; classify() reports the worst one present.
UNRESOLVED = (BROKEN, UNKNOWN, UNREADABLE)
_WIDTH = max(len(s) for s in STATES)

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

    return [
        Prerequisite(
            "engine artifacts",
            engine_artifacts_present(),
            f"model + flow model + window scaler + threshold under {art}",
            train_engine,
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
        ("engine artifacts",),
    ),
    Capability(
        "The 1,000-flow smoke pipeline completes offline in under 60 s "
        "(CLAUDE.md definition of done)",
        ("tests/test_smoke.py",),
        ("engine artifacts",),
    ),
    Capability(
        "No normalisation leakage: the persisted scaler matches a train-split-only refit",
        ("tests/test_scaler_train_only.py",),
        ("persisted train-only scaler", "split map"),
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
        "PCAP input takes the full 30-feature path",
        ("tests/test_engine.py::test_pcap_input_uses_full_features_and_verifies",),
        ("xgboost", "full 30-feature model", "synthetic demo pcap"),
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
        "The published ablation table is regenerable from results/*.json",
        (),
        ("published results",),
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
    ("Retired claims have not reappeared in the judge-facing docs",
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
                nodes = [Node(spec, *_node_state(module, functions[wanted]))]
            else:
                nodes = [
                    Node(f"{relative}::{name}", *_node_state(module, functions[name]))
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
    if not nodes:  # a claim with no automated test: prerequisites are all we have
        return RUNS if needs_met else SKIPPED
    for state in UNRESOLVED:  # worst first
        if any(n.state == state for n in nodes):
            return state
    running = sum(1 for n in nodes if _executes(n, needs_met))
    if running == len(nodes):
        return RUNS
    return SKIPPED if running == 0 else PARTIAL


def _node_lines(spec: str, needs_met: bool) -> list[str]:
    """One line per named spec, plus the gated node ids when only some are gated."""
    nodes = probe_nodes(spec)
    if len(nodes) == 1 and nodes[0].node_id == spec:
        only = nodes[0]
        if only.state in UNRESOLVED:
            return [f"      {spec}  <- {only.state}: {only.detail}"]
        return [f"      {spec}"]
    gated = [n for n in nodes if not _executes(n, needs_met)]
    lines = [f"      {spec} - {len(nodes) - len(gated)} of {len(nodes)} test functions "
             "execute here"]
    lines += [f"        gated: {n.node_id.split('::', 1)[1]}" for n in gated]
    return lines


def build_report() -> tuple[str, dict[str, str]]:
    prereqs = probe_prerequisites()
    present = {p.key: p.present for p in prereqs}
    verdicts = {c.claim: classify(c, present) for c in CAPABILITIES}

    lines = ["", "=" * 78, "BOOTSTRAP STATE - what this checkout does and does not exercise",
             "=" * 78, "", "PREREQUISITES", ""]
    for p in prereqs:
        mark = "present" if p.present else "ABSENT "
        lines.append(f"  [{mark}] {p.key}: {p.detail}")
        if not p.present:
            lines.append(f"            -> {p.bootstrap}")

    lines += ["", "CAPABILITIES", "",
              "  RUNS    = every named test executes here; its verdict is this suite's own.",
              "  PARTIAL = some execute, some are gated; the gated node ids are listed.",
              "  SKIPPED = NOT checked in this checkout.",
              f"  {'/'.join(UNRESOLVED)} = this probe could not decide; the suite fails.",
              "  States are read from the tests' real skip markers, not declared here.", ""]
    for capability in CAPABILITIES:
        state = verdicts[capability.claim]
        needs_met = all(present[n] for n in capability.needs)
        lines.append(f"  [{state:<{_WIDTH}}] {capability.claim}")
        for spec in capability.tests:
            lines += _node_lines(spec, needs_met)
        if not capability.tests:
            lines.append("      no automated test - regenerate with scripts/reproduce_results.ps1")
        if state in (SKIPPED, PARTIAL):
            missing = [n for n in capability.needs if not present[n]]
            lines.append(f"      blocked on: {', '.join(missing) or 'a gate this report cannot name'}")

    lines += ["", "EXERCISED ON A BARE CHECKOUT", ""]
    for claim, spec in ALWAYS_EXERCISED:
        nodes = probe_nodes(spec)
        gated = [n for n in nodes if n.state == NODE_GATED]
        bad = [n for n in nodes if n.state in UNRESOLVED]
        state = bad[0].state if bad else (SKIPPED if len(gated) == len(nodes) else
                                          PARTIAL if gated else RUNS)
        lines.append(f"  [{state:<{_WIDTH}}] {claim}")
        lines += _node_lines(spec, True)

    fully = sum(1 for v in verdicts.values() if v == RUNS)
    partly = sum(1 for v in verdicts.values() if v == PARTIAL)
    lines += ["", f"{fully}/{len(CAPABILITIES)} gated capabilities are fully exercised in "
                  f"this checkout; {partly} partly.", ""]
    if fully + partly < len(CAPABILITIES):
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
    capability, so no future `continue` can quietly empty this test again.
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


if __name__ == "__main__":  # `python tests/test_bootstrap_state.py` prints the report
    print(build_report()[0])                # sys.path was fixed up at import time
