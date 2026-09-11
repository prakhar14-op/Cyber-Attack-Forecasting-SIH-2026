r"""Retired claims must stay retired.

An adversarial audit found published claims that were false, and the reason they
survived so long is that nothing in the build objected when a corrected sentence
drifted back. Several were retracted from the judge-facing docs; this test is the
ratchet that stops them returning.

It is deliberately NOT a spell-check of the docs. Each entry below is a specific
claim-shaped phrasing with the measurement that refutes it, so a failure tells a
contributor what is wrong with the sentence rather than that a word is forbidden.

WHAT IS IN SCOPE, AND WHY IT IS NOT A LIST OF FILE TYPES
--------------------------------------------------------
Scope is DISCOVERED. Every revision of this guard that decided scope by listing
something -- paths, then directories, then extensions -- has been escaped by a
claim written just outside whatever was listed, and each time it was someone
else who found the escape:

  * an early version enumerated documents by name, and three corrected claims
    landed in documents it did not name, `docs/INSTALL.md` among them;
  * the next version discovered markdown and swept `tests/`, and a verifier ran
    these same patterns over everything outside that scope and found a live hit
    -- a caption on the running Streamlit demo page, in `app/streamlit_app.py`,
    rendering the retired cascade claim to anyone who opened the app. The most
    judge-visible code in the repository was out of scope because the scope was
    a list of the places its author had thought of.

So nothing here enumerates what may carry a claim. A file is in scope if its
bytes decode as UTF-8 and its path is not one of the few named exclusions below.
Prose is what a human reads, and no extension makes text stop being read: this
sweeps markdown, Python (docstrings, comments, and the UI strings the app
renders), YAML, shell and PowerShell, the CI workflow, and the SVG architecture
diagrams, whose `<text>` labels a judge reads off a slide. Binary files are not
excluded by name either -- they fail to decode and drop out on their own, so a
new image format needs no maintenance here.

There is deliberately NO size cap. A cap is a silent hole exactly the width of
the file that crosses it.

DISCOVERY HAS TO DEFEND ITSELF, NOT MERELY BE RIGHT TODAY
----------------------------------------------------------
`is_text` deciding by decoding is the whole of that rule, which means one
function is all that stands between this guard and the list that caused the
defect above. A verifier rewrote it as an extension allowlist -- `.md`, `.py`,
`.yml`, `.svg`, under the comment "only prose formats actually carry claims;
skip the rest for speed" -- and nothing failed. Every path pinned at the time was
a `.md`, a `.py` or a `.yml`, so all of the pins passed while the discovered
scope quietly lost about a fifth of its files, and the number of tests generated
from SCOPE fell with it, with nothing asserting on either.

Two mechanisms now make that edit loud, and they fail for different reasons on
purpose:

  * `test_scope_is_every_decodable_file_not_a_chosen_kind` re-derives the whole
    of SCOPE from the filesystem using its own inline decode and compares the
    sets. It shares only the exclusion constants with `discover_scope`; in
    particular it never calls `is_text`, so an `is_text` that starts judging by
    filename disagrees with it on the first run. This is the same
    guard-the-shortcut trick `paragraph_slots_literal` applies to the other
    optimisation in this file, and it is worth exactly as much as its
    independence: do not make either side call the other to remove the
    duplication.
  * `KIND_SCOPE` pins one file of each kind that no `.md`, `.py` or `.yml` pin
    shares, so the pinned set stops being a single-family sample that any
    plausible prose-formats allowlist keeps by accident. Those entries are
    pinned for their KIND. They are not more precious than their neighbours.

WHAT THIS GUARD STRUCTURALLY CANNOT SEE
----------------------------------------
Deciding scope by decoding also decides what is unreachable: a judge-facing
deliverable that is not UTF-8 is outside this guard altogether, and two shipped
ones are -- `docs/architecture.pdf` and `docs/deck/sih26153_technical_deck.pptx`.
A retired claim printed on a deck slide is exactly as visible to a judge as one
in `README.md`, and nothing in this file would notice it. So the boundary is
asserted rather than assumed, by
`test_the_binary_deliverables_are_outside_this_guard`: it is a stated handover
rather than a silent hole. The PDF's contents are guarded by
`tests/test_figures.py`. The deck is built by `scripts/build_deck.py`, so
guarding what its slides SAY belongs with that builder -- `tests/test_build_deck.py`
-- and not here. Nothing in this module can read either file, whatever it is
named on any given day, so a claim that has to be checked on a slide has to be
checked there. This paragraph states where the boundary runs, not what currently
sits on the other side of it: the assertion is in the test.

`tier1_hardening_report.md`, `diagnosis_report.md` and `docs/decisions/` are
excluded on purpose: they are the record of these defects and have to quote them
verbatim. If you need to write one of these sentences down in order to retract
it, write it there.

This file is excluded for the same reason and no other: it is the specification
of the ban. It quotes every retired sentence in full, in `retired_sentences`, in
order to prove the patterns still catch them -- so scanning it would fail the
guard on its own evidence, and the tempting fix would be to delete the evidence.
The exclusion is one named path, not a pattern, so it cannot widen.

Dot-directories and `__pycache__` are pruned by the walk rather than excluded by
name. `.venv` is a junction to a 1.5 GB interpreter tree on this machine and
`.git` holds every historical revision of the very sentences this bans; neither
is prose anyone reads. The one prose surface that pruning puts out of reach is
`.github/workflows/ci.yml`, which is therefore pinned in UNREACHABLE_SCOPE and
appended unconditionally -- it is one of the three places the suite-count claim
has lived.

HOW AN EXEMPTION WORKS, AND WHY IT IS NOT A WINDOW
--------------------------------------------------
A retraction has to be able to quote what it retracts, so some occurrences must
be allowed. An earlier version of this file allowed a match when a *retraction
marker* appeared anywhere within 150-400 characters of it. That is how the
ratchet acquired a blind spot centred on the very paragraphs it existed to
protect: `docs/INSTALL.md` says "Do **not** check the suite against a memorised
pass/skip count", and `must not` / `do not check` / `three tests` / `opt-in` are
ordinary English that occurs all over a corrected document. Measured by running
the previous implementation over the scope as it stood at the time -- markdown
only, before the test modules were added -- inserting each retired sentence at
each paragraph boundary of each scanned file gave 8,722 insertion points, and
the old exemptions stayed silent at 98 of them, spread over ten documents
including `docs/INSTALL.md`, `README.md`, `docs/demo_script.md`,
`capture/CONSENT.md`, `CLAUDE.md` and `scripts/fetch_artifacts.py`. Those two
figures are a record of one run against one set of files and are not re-derived
here; the live number is the one below.

The same measurement against the code below gives ZERO escapes, at every
insertion point of the current, wider scope. Deliberately no total is written
down for it: an insertion-point count would go stale the moment a file is added,
which is the defect `hardcoded-suite-count` exists to ban, and this file is the
last place that should ship one. The escape count is not a claim made here
either -- it is what
`test_retired_sentences_are_caught_inside_the_real_documents` computes on every
run, and it prints the totals when it fails.

So the neighbourhood window is gone. An occurrence is exempt only when it lies
inside one of the verbatim excerpts in `allow_exact` -- the actual retracting
sentence, quoted from the document, tight around the phrase it exempts. A new
sentence next door is not covered by its neighbour's exemption, which is the
whole point. `test_every_allowance_is_anchored_in_a_real_document` then keeps the
allowlist honest from the other side: an excerpt that no scanned file actually
contains, or that does not itself contain a banned phrase, is dead weight
pretending to be a considered exception, and fails.

`test_retired_sentences_are_caught_inside_the_real_documents` re-runs the
measurement above on every commit, so the ratchet is proved against the real
files rather than against sentences held in isolation.

EVERY PATTERN MUST BE LOAD-BEARING, OR IT CAN BE SWITCHED OFF IN SILENCE
------------------------------------------------------------------------
An exemption covers any occurrence lying inside it, so an `allow_exact` entry
that IS the banned phrase exempts every occurrence of that phrase everywhere --
the pattern stops doing anything at all. A verifier added the bare word
`cascade` to the cascade claim's `allow_exact`. It satisfied
`test_every_allowance_is_anchored_in_a_real_document` on both counts, because the
word does contain a banned phrase and does occur in scanned documents, and the
ratchet stayed green too. He then appended "The deployed engine is a cascade." to
`README.md` and the whole file reported no new failure.

Nothing failed because no retired sentence depended on `/cascade/` ALONE: all
three cascade sentences also said "fast tier", so `/fast\s+tier/` went on
catching them while `/cascade/` did nothing. Five patterns here were unproven in
that sense.

`test_every_pattern_is_load_bearing_for_a_retired_sentence` closes it from the
pattern side. Each pattern must have at least one retired sentence that IT
catches and that the claim's OTHER patterns do not, so switching a pattern off --
by exempting it, by loosening it into a no-op, or by deleting it -- always drops
a sentence somewhere a test is watching. A new pattern now costs a sentence that
proves it, which is what makes a pattern mean anything.

The same test caught a pattern that had never worked at all:
`/net_guard(?:\.py)?\s+enforces/` could not match, because `normalise` strips `_`
before any pattern is applied and the text it hunts has by then become
`netguard`. It is repaired to `net_?guard` here. Every pattern is only ever
applied to normalised text, and the proving sentence is normalised like anything
else, so requiring one makes an inert pattern impossible to add unnoticed.

`allow_exact` is closed from its own side to match: an entry may not be a banned
phrase standing alone, and may not be a fragment of any retired sentence. A
retraction quotes what it retracts and then says something about it, so it is
WIDER than the claim it quotes. An excerpt that fits INSIDE the reintroduction is
not a retraction; it is a licence for one.
"""

from __future__ import annotations

import os
import re
from collections import Counter
from dataclasses import dataclass, field, replace
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent

# The record of the defects, plus this file. All three exist in order to quote
# the retired sentences: the first two are the audit record, and this module
# declares them in `retired_sentences` so the patterns can be proved against
# them. Named paths, never patterns -- an exclusion that can match a file nobody
# has written yet is a hole held open.
EXCLUDED_FILES = frozenset({
    "tier1_hardening_report.md",
    "diagnosis_report.md",
    "tests/test_docs_claims.py",
})
EXCLUDED_DIRS = frozenset({"docs/decisions"})

# Pruned by the walk rather than judged as prose: compiled bytecode is
# generated, and the dot-directories are `.git` (every historical revision of
# these sentences) and `.venv` (a junction to a 1.5 GB interpreter tree).
# Pruning `.github` along with them is what UNREACHABLE_SCOPE repairs.
PRUNED_DIR_NAMES = frozenset({"__pycache__"})

# Prose surfaces the walk structurally cannot reach, appended unconditionally.
# NOT filtered by `.exists()` -- an earlier version did that, and a renamed
# surface then left SCOPE without anything failing.
UNREACHABLE_SCOPE = (
    ".github/workflows/ci.yml",
)

# Discovery must not be able to silently collapse, so the surfaces whose
# DISAPPEARANCE should be loud are named. Discovery already survives a rename --
# the file is in scope under its new name the moment it exists -- so what these
# groups assert is the other direction: that a judge-facing surface still exists
# and that the walk still returns it.
CORE_SCOPE = (
    "README.md",
    "JUDGES.md",
    "docs/INSTALL.md",
    "docs/architecture.md",
    "docs/limitations.md",
    "docs/slides.md",
    "docs/benchmark_protocol.md",
    "docs/demo_script.md",
)

# The running demo, and the group whose absence was the defect: a verifier ran
# these patterns over everything this guard did not scan, and the only live hit
# in the repository was a caption here rendering the retired cascade claim on
# the page a judge looks at while the pitch is being made. The app is the one
# surface where a retired claim is not merely written down but displayed.
APP_SCOPE = (
    "app/streamlit_app.py",
    "app/panels.py",
)

# Non-markdown surfaces carrying claim-shaped prose in docstrings or comments.
# The walk reaches both now; they stay pinned because each has already carried
# one of these claims.
CODE_SCOPE = (
    "eval/fused.py",
    "scripts/fetch_artifacts.py",
)

# Test modules are documentation too: their docstrings are claim-shaped prose,
# and the "78 passed, 16 skipped" count lived in one of them. Both also carry a
# retraction quote anchored in `allow_exact`, and narrowing the walk away from
# `tests/` does trip `test_every_allowance_is_anchored_in_a_real_document` as
# well -- but from there an unscanned anchor is indistinguishable from a deleted
# one, and that test's advice is to delete the exemption, which would be exactly
# the wrong repair. These two entries are what names the actual cause.
PINNED_TEST_SCOPE = (
    "tests/test_bootstrap_state.py",
    "tests/test_app.py",
)

# Pinned for their KIND. Every other pinned path above is a `.md`, a `.py` or a
# `.yml`, and that is what let an extension allowlist replace `is_text` with all
# of the pins still passing: the pinned set was one prose family and the
# allowlist kept exactly that family. Each entry below is the only representative
# this guard needs of a kind such an allowlist drops -- no extension, `.ini`,
# `.txt`, `.yaml`, `.sh`, `.ps1` -- plus the architecture SVG, whose `<text>`
# labels carry the "not a cascade" retraction onto a slide a judge reads.
# They are ordinary files; what is load-bearing about them is their suffix.
KIND_SCOPE = (
    "LICENSE",
    "pytest.ini",
    "requirements.txt",
    "engine/technique_map.yaml",
    "capture/capture.sh",
    "scripts/reproduce_results.ps1",
    "docs/img/01-architecture-dataflow.svg",
)

# Judge-facing deliverables that do NOT decode as UTF-8 and are therefore outside
# this guard by construction, named so the boundary is owned rather than merely
# true. See the module docstring: the PDF's contents are guarded by
# tests/test_figures.py, the deck's belong with scripts/build_deck.py.
BINARY_DELIVERABLES = (
    "docs/architecture.pdf",
    "docs/deck/sih26153_technical_deck.pptx",
)

# Everything that must be scanned whatever the filesystem looks like.
PINNED_SCOPE = (
    CORE_SCOPE + APP_SCOPE + CODE_SCOPE + PINNED_TEST_SCOPE + KIND_SCOPE
    + UNREACHABLE_SCOPE
)


def is_text(path: Path) -> bool:
    """Whether this file is prose at all, decided by decoding it rather than by
    its extension.

    An extension allowlist is a list, and every list this guard has used has been
    escaped by a claim written just outside it. Decoding cannot be escaped by
    choosing a filename: a `.rst`, a `.toml` or an `.adoc` written tomorrow is
    scanned tomorrow, and a `.png` drops out without anyone maintaining a rule
    about images.
    """
    try:
        path.read_bytes().decode("utf-8")
    except (UnicodeDecodeError, OSError):
        return False
    return True


def discover_scope() -> tuple[str, ...]:
    """Every UTF-8-decodable file in the repository, minus the named exclusions,
    plus the surfaces the walk cannot reach.

    UNREACHABLE_SCOPE is appended unconditionally and de-duplicated against the
    walk, so an entry that later becomes reachable is scanned once rather than
    twice, and an entry that never becomes reachable is still scanned.
    """
    found: list[str] = []
    for root, dirs, files in os.walk(REPO_ROOT):
        here = Path(root)
        dirs[:] = [
            d for d in dirs
            if not d.startswith(".")
            and d not in PRUNED_DIR_NAMES
            and (here / d).relative_to(REPO_ROOT).as_posix() not in EXCLUDED_DIRS
        ]
        for name in files:
            relative = (here / name).relative_to(REPO_ROOT).as_posix()
            if relative in EXCLUDED_FILES:
                continue
            if is_text(here / name):
                found.append(relative)
    ordered = sorted(found)
    ordered += [s for s in UNREACHABLE_SCOPE if s not in found]
    return tuple(ordered)


SCOPE = discover_scope()


def scope_by_decoding() -> frozenset[str]:
    """A second opinion on SCOPE, written not to share the decision under attack.

    `discover_scope` asks `is_text`, and `is_text` is one function away from being
    the extension list that has been escaped every time this guard has used one.
    So this walks the tree again and decodes each file inline, right here, where
    the rule is visible next to the assertion that depends on it. It shares the
    exclusion constants -- those are named paths and are governed by their own
    tests -- and nothing else. It must NOT be refactored to call `is_text`,
    `discover_scope`, or anything they call: two implementations that agree are
    evidence only while they are two.
    """
    found: set[str] = set()
    for root, dirs, files in os.walk(REPO_ROOT):
        here = Path(root)
        dirs[:] = [
            d for d in dirs
            if not d.startswith(".")
            and d not in PRUNED_DIR_NAMES
            and (here / d).relative_to(REPO_ROOT).as_posix() not in EXCLUDED_DIRS
        ]
        for name in files:
            path = here / name
            relative = path.relative_to(REPO_ROOT).as_posix()
            if relative in EXCLUDED_FILES:
                continue
            try:
                path.read_bytes().decode("utf-8")
            except (UnicodeDecodeError, OSError):
                continue
            found.add(relative)
    return frozenset(found | set(UNREACHABLE_SCOPE))


@dataclass(frozen=True)
class BannedClaim:
    slug: str
    why: str
    patterns: tuple[re.Pattern[str], ...]
    # Verbatim excerpts -- quoted from the document that legitimately contains a
    # banned phrase in order to retract it. An occurrence is exempt ONLY if it
    # lies wholly inside one of these, so the exemption travels with the exact
    # sentence and not with its neighbourhood. Keep them tight: an excerpt is an
    # opening in the ratchet exactly as wide as the text you paste into it.
    allow_exact: tuple[str, ...] = ()
    # Sentences the patterns MUST catch. Without these a future contributor can
    # silence a failure by loosening a regex and the ratchet quietly releases.
    retired_sentences: tuple[str, ...] = field(default_factory=tuple)


def _rx(*patterns: str) -> tuple[re.Pattern[str], ...]:
    return tuple(re.compile(p, re.IGNORECASE) for p in patterns)


def normalise(text: str) -> str:
    """Markdown emphasis, hard line wrapping and dash characters must not hide a
    claim: `best **validation** AUROC` and the same phrase wrapped across two
    lines are the same sentence."""
    text = re.sub(r"[*_`]", "", text)
    text = text.replace("’", "'").replace("—", "-").replace("–", "-")
    return re.sub(r"\s+", " ", text)


BANNED: tuple[BannedClaim, ...] = (
    BannedClaim(
        slug="fused-best-val-auroc",
        why=(
            "FALSE, and it was our stated defence against test-set model selection. "
            "Validation AUROC is xgb 0.806 > lstm 0.774 > fused 0.765 - fused is third, "
            "and it has the largest val->test gap of any row. The honest statement is "
            "that fused is selected for test-set ranking quality and error "
            "decorrelation, and that xgb is the val-optimal single model."
        ),
        patterns=_rx(
            r"best\s+val(?:idation)?\s+AUROC\s+of\s+any\s+row",
            r"select\w*[^.]{0,60}never\s+on\s+test",
            r"fused[^.]{0,80}best\s+val(?:idation)?\s+AUROC",
        ),
        # No document currently needs to quote this one; nothing is exempt.
        retired_sentences=(
            "the fused model has the best validation AUROC of any row - selected on "
            "val, never on test",
            "It has the **best validation AUROC** of any row.",
            "the fused row was selected on val, never on test",
            # Proves the third pattern alone: names the fused row and the figure
            # without "of any row" and without the selection clause, so neither of
            # the other two patterns reaches it. Without this the third pattern
            # could be exempted or loosened away in silence.
            "the fused ensemble carries the best validation AUROC we measured",
        ),
    ),
    BannedClaim(
        slug="supported-forecast-horizon",
        why=(
            "There is no supported forward-forecast horizon. The k-step head ranks "
            "better than chance (test AUROC 0.844 at k=4, 0.842 at k=8) but its "
            "fixed-budget operating point is F1 <= 0.009 and 0/2 episodes at k=1, 4 "
            "and 8 alike, and the oracle-threshold analysis shows no threshold "
            "recovers it. The early warning this system claims comes from the "
            "horizon-0 classifier. 0.890 is a stale pre-determinism k=8 number; the "
            "measured value is 0.842."
        ),
        patterns=_rx(
            r"supported\s+(?:forward[- ]?)?(?:forecast(?:ing)?[- ])?horizon",
            r"0\.890",
        ),
        allow_exact=(
            # docs/limitations.md states the retraction; these are the only three
            # occurrences of these phrases anywhere in scope.
            "no supported forward-forecast horizon",
            'claimed "20 s ahead is our supported horizon"',
            "a stale AUROC of 0.890",
        ),
        retired_sentences=(
            "20 s ahead is our supported horizon",
            "our supported forecast horizon is 20 seconds",
            "the k-step head reaches AUROC 0.890 at k=8",
        ),
    ),
    BannedClaim(
        slug="deployed-scorer-is-a-cascade",
        why=(
            "No cascade exists. engine/predict.py scores with a SINGLE XGBoost model - "
            "one of two variants chosen by input format (PCAP -> full 30 features, "
            "CSV -> flow-only), not a fast tier in front of a slow one. The fused "
            "TGN+XGB row is an eval-side model that does not run in the engine at all; "
            "engine-side fusion is roadmap."
        ),
        patterns=_rx(
            r"cascade",
            r"fast\s+tier",
            r"tier[- ]?(?:one|1)\s+scorer",
        ),
        allow_exact=(
            # README.md, docs/architecture.md and the architecture SVG's own
            # <text> label all say "..., not a cascade". The exemption is those
            # three words, not the paragraph around them.
            "not a cascade",
            # tests/test_figures.py states the retraction in the `why` of the
            # figure claim that enforces it. Anchored to the retracting clause
            # and stopped before its object, so it exempts this sentence and
            # nothing that could be written after it.
            "The audit retired the cascade claim after proving",
        ),
        retired_sentences=(
            "the deployed scorer is the cascade's fast tier",
            "the engine runs the fast tier of the cascade, escalating to the fused model",
            # Verbatim from app/streamlit_app.py, where it was a live st.caption on
            # the ablation panel of the running demo -- the only occurrence of any
            # banned phrase anywhere outside the scope this guard had before, and
            # the reason that scope is now the whole repository. Kept here so the
            # ratchet re-proves at every insertion point of every scanned file
            # that this exact wording is caught, rather than the fix being a
            # one-off edit to one caption.
            "Live scoring in this app uses the deployed fast tier (XGBoost); the "
            "**fused** row is the eval-side headline model.",
            # The two sentences that make /cascade/ and /tier[- ]?(?:one|1)\s+
            # scorer/ load-bearing. Every sentence above also says "fast tier", so
            # /fast\s+tier/ was catching all of them and those two patterns were
            # provably doing nothing -- which is how the bare word "cascade" could
            # be added to allow_exact, switching /cascade/ off entirely, with this
            # file reporting no failure. Each of these says exactly one of the two
            # things, so neither pattern can be switched off in silence again.
            "the deployed engine is a cascade, escalating only when the first "
            "stage is unsure",
            "the tier-1 scorer handles most windows and defers the rest",
        ),
    ),
    BannedClaim(
        slug="suite-runs-socket-blocked",
        why=(
            "Nothing blocks sockets suite-wide. `no_network` in tests/conftest.py is "
            "an ordinary opt-in fixture with NO autouse, and exactly three tests "
            "request it: tests/test_offline.py, tests/test_smoke.py and "
            "tests/test_app.py::test_pipeline_and_panels_work_offline. All three are "
            "gated on trained artifacts, so on a bare checkout ZERO tests run with "
            "sockets blocked. This claim has now been written twice, by two different "
            "hands, about the problem statement's hard constraint #1 - name the tests "
            "that are socket-blocked, never the suite."
        ),
        patterns=_rx(
            r"(?:test\s+suite|every\s+test|all\s+(?:the\s+)?tests|whole\s+suite)"
            r"[^.]{0,120}(?:sockets?\s+(?:are\s+)?blocked|network\s+(?:is\s+)?"
            r"(?:disabled|blocked)|stays?\s+offline|all\s+run\s+offline)",
            r"(?:sockets?\s+blocked|network\s+disabled)[^.]{0,120}"
            r"(?:test\s+suite|every\s+test|all\s+(?:the\s+)?tests|whole\s+suite)",
            # `net_?guard`, not `net_guard`: every pattern is applied to NORMALISED
            # text, and `normalise` strips `_`, so the original spelling could not
            # match anything this guard ever looks at -- not a retired sentence and
            # not a document. It was inert from the day it was written, and the
            # measurement that found it is the load-bearing test below, which
            # demands a sentence that this pattern and no other catches.
            r"net_?guard(?:\.py)?\s+enforces",
        ),
        # The corrected wording in docs/INSTALL.md names the three tests instead
        # of the suite, so it trips none of these patterns and needs no exemption.
        retired_sentences=(
            "The demo, inference, ledger verification and the test suite all run "
            "with sockets blocked - tests/net_guard.py enforces it.",
            "Inference, the demo, ledger verification and the test suite all stay "
            "offline (CLAUDE.md hard constraint 1).",
            "every test in the suite runs with sockets blocked",
            # Proves the second pattern alone: the blocking clause comes FIRST, so
            # the suite-then-blocked pattern does not reach it.
            "With sockets blocked from conftest, the whole suite still passes",
            # Proves the repaired third pattern alone: names the enforcing module
            # without saying "suite", "every test" or "sockets blocked" anywhere.
            "tests/net_guard.py enforces the offline constraint for the demo",
        ),
    ),
    BannedClaim(
        slug="hardcoded-suite-count",
        why=(
            "An expected pass/skip count is a lie with a delay fuse: it goes stale "
            "the moment anyone adds a test. '78 passed, 16 skipped' was published in "
            "docs/INSTALL.md, in the CI comment and in tests/test_bootstrap_state.py's "
            "docstring while the suite had already grown well past it. State the "
            "criterion instead - 0 failed, 0 errors, some skipped - and let the reader "
            "read the counts off their own run."
        ),
        patterns=_rx(r"\d+\s+passed,\s+\d+\s+(?:skipped|failed)"),
        # No DOCUMENT quotes a count. Two test docstrings do, both in order to
        # retract the figure they quote, and both are anchored here verbatim
        # rather than by exempting the files they live in. The previous
        # /do not (expect|check)/ and /must not/ escapes matched ordinary prose in
        # four different documents and were what let a reintroduced count through;
        # these two anchors are the retracting clause and stop at its full stop.
        allow_exact=(
            # tests/test_bootstrap_state.py, naming the figure it retracts.
            'published "78 passed, 16 skipped" in its own docstring',
            # tests/test_app.py::test_demo_script_does_not_promise_a_fixed_test_count
            "show '93 passed, 1 skipped', a count this repo cannot produce",
        ),
        retired_sentences=(
            "The suite on a bare checkout is expected to report 78 passed, 16 skipped",
            'a green run here is "78 passed, 16 skipped"',
            "show 93 passed, 1 skipped",
        ),
    ),
)


_NORMALISED: dict[str, str] = {}


def normalised_document(relative: str) -> str:
    """Read-and-normalise, cached: several tests scan every file in SCOPE."""
    if relative not in _NORMALISED:
        _NORMALISED[relative] = normalise(
            (REPO_ROOT / relative).read_text(encoding="utf-8")
        )
    return _NORMALISED[relative]


def allowed_spans(text: str, claim: BannedClaim) -> list[tuple[int, int]]:
    """Character ranges of this claim's verbatim exemptions, as they really occur.

    An excerpt that does not occur contributes no span, so a reworded retraction
    stops exempting anything instead of continuing to exempt a neighbourhood.
    """
    spans: list[tuple[int, int]] = []
    for excerpt in claim.allow_exact:
        needle = normalise(excerpt)
        start = text.find(needle)
        while start != -1:
            spans.append((start, start + len(needle)))
            start = text.find(needle, start + 1)
    return spans


def hits(text: str, claim: BannedClaim) -> list[str]:
    """Excerpts around every occurrence not lying inside a verbatim exemption."""
    spans = allowed_spans(text, claim)
    found = []
    for pattern in claim.patterns:
        for m in pattern.finditer(text):
            if any(lo <= m.start() and m.end() <= hi for lo, hi in spans):
                continue
            found.append(
                f"...{text[max(0, m.start() - 90):m.end() + 90]}..."
                f"   [matched /{pattern.pattern}/]"
            )
    return found


def paragraph_slots(raw: str, sentence: str):
    """Every paragraph boundary of `raw`, with `sentence` inserted as its own
    paragraph there, each yielded already normalised.

    The paragraphs are normalised once and then joined with a single space,
    rather than the doctored document being normalised ~30 times per file. That
    is the same string: `normalise` only rewrites single characters and collapses
    runs of whitespace, and the join puts whitespace at every seam, so no rewrite
    can reach across one. Empty parts are dropped because a blank paragraph
    contributes no space of its own once the run around it has collapsed.

    This is an optimisation inside a guard, which is where blind spots come from,
    so `test_the_fast_insertion_path_matches_the_literal_one` checks it against
    `paragraph_slots_literal` instead of trusting the paragraph above."""
    paragraphs = [normalise(p).strip() for p in raw.split("\n\n")]
    inserted = normalise(sentence).strip()
    for index in range(len(paragraphs) + 1):
        parts = paragraphs[:index] + [inserted] + paragraphs[index:]
        yield index, " ".join(part for part in parts if part)


def paragraph_slots_literal(raw: str, sentence: str):
    """The obvious, slow version of `paragraph_slots`: splice the raw text, then
    normalise the whole doctored document. Kept as the reference the fast path is
    checked against."""
    paragraphs = raw.split("\n\n")
    for index in range(len(paragraphs) + 1):
        yield index, normalise(
            "\n\n".join(paragraphs[:index] + [sentence] + paragraphs[index:])
        ).strip()


@pytest.mark.parametrize("relative", PINNED_SCOPE)
def test_pinned_surfaces_are_scanned(relative):
    # Docstring assigned below, because it states how many paths are pinned and
    # a written count of a list that grows is the defect `hardcoded-suite-count`
    # bans. The last revision of this file said "ten" in this docstring while
    # PINNED_SCOPE held twelve entries -- a stale count inside the guard whose
    # purpose is to ban stale counts. `test_the_pinned_count_is_derived_not_written`
    # fails if anyone puts a literal back.
    assert (REPO_ROOT / relative).exists(), (
        f"{relative} is pinned into this guard's SCOPE but does not exist. Either "
        "restore it or follow the rename into the PINNED_SCOPE group it belongs to "
        "- a missing file here means a judge-facing surface has stopped being "
        "checked for retired claims."
    )
    assert relative in SCOPE, (
        f"{relative} exists but discover_scope() no longer returns it. Do not "
        "narrow the walk to make this pass; fix the walk."
    )


test_pinned_surfaces_are_scanned.__doc__ = (
    "Falsifiable: SCOPE is otherwise built by walking the filesystem, so every "
    "discovered entry exists by construction and asserting it proves nothing. "
    f"The {len(PINNED_SCOPE)} paths in PINNED_SCOPE are asserted instead of "
    "discovered -- rename or delete one and this fails, which is the only way a "
    "surface leaving SCOPE can be noticed at all. `.github/workflows/ci.yml` is "
    "the case that matters: it is unreachable by the walk (dot-directories are "
    "pruned) and it is one of the three places the suite-count claim has lived."
)


def test_the_pinned_count_is_derived_not_written():
    """The count of pinned paths must be computed from PINNED_SCOPE, never typed.

    This is not pedantry about a docstring: the previous revision of this file
    said one number in prose while PINNED_SCOPE held another, inside the guard
    whose whole subject is figures that outlive the thing they counted. Prose in
    a test is read by contributors exactly as documentation, and this file is
    excluded from its own document scan, so nothing else would catch it.

    Falsifiable in the way it actually broke, which takes both halves: replace
    the assignment below with a literal docstring -- correct on the day it is
    typed -- and then, in a later and unrelated edit, pin one more surface. Only
    then does the number stop matching, and it does. Pinning a surface while the
    assignment is left alone passes, because the figure follows the list; a test
    that failed on that too would be failing on the repair rather than on the
    defect.
    """
    doc = test_pinned_surfaces_are_scanned.__doc__ or ""
    assert f"{len(PINNED_SCOPE)} paths in PINNED_SCOPE" in doc, (
        "test_pinned_surfaces_are_scanned's docstring no longer states the real "
        f"size of PINNED_SCOPE ({len(PINNED_SCOPE)}). Its docstring is assigned "
        "from an f-string precisely so this figure cannot go stale; do not write "
        "the number by hand.\nThe docstring currently reads:\n" + doc
    )
    groups = (CORE_SCOPE, APP_SCOPE, CODE_SCOPE, PINNED_TEST_SCOPE, KIND_SCOPE,
              UNREACHABLE_SCOPE)
    assert len(PINNED_SCOPE) == sum(len(g) for g in groups), (
        "PINNED_SCOPE is no longer the concatenation of its groups, so a whole "
        "group can be dropped from the pinning without any test noticing."
    )
    assert len(set(PINNED_SCOPE)) == len(PINNED_SCOPE), (
        f"PINNED_SCOPE contains a duplicate: {sorted(PINNED_SCOPE)}. A path "
        "listed twice inflates the derived count and doubles its insertion "
        "points in the ratchet measurement."
    )


def test_the_defect_record_stays_out_of_scope():
    """The record files -- and this one -- quote the retired sentences in order
    to retract them. If they were ever pulled into SCOPE the guard would fail on
    its own evidence, and the tempting fix would be to delete the evidence."""
    for relative in EXCLUDED_FILES:
        assert relative not in SCOPE, (
            f"{relative} quotes the retired sentences in order to retract or to "
            "specify them; it must stay excluded"
        )
    assert not any(s.startswith("docs/decisions/") for s in SCOPE), (
        "docs/decisions/ supersede each other by quoting what they supersede"
    )


def _kinds(paths) -> str:
    counted = Counter(Path(p).suffix or "<no extension>" for p in paths)
    return ", ".join(f"{kind} x{n}" for kind, n in sorted(counted.items()))


def test_scope_is_every_decodable_file_not_a_chosen_kind():
    """Scope must stay a decode, and must not quietly become a list of kinds.

    The defect this exists for: `is_text` was replaced with an extension
    allowlist -- `.md`, `.py`, `.yml`, `.svg`, "only prose formats actually carry
    claims; skip the rest for speed" -- and every pinned path survived it, because
    the pinned paths were all in that family. SCOPE lost about a fifth of its
    files, the generated test count fell with it, and no assertion in this module
    was pointed at either number.

    So neither number is written down here. The comparison is against
    `scope_by_decoding`, which re-derives the whole set from the filesystem with
    its own decode, so the expectation is re-measured on every run and a file
    added tomorrow needs no edit here. Falsifiable exactly as it broke: make
    `is_text` decide by suffix and this fails, naming the kinds that vanished.

    What it does NOT cover, stated rather than left to be discovered: the two
    walks share their pruning and their exclusion constants, so an edit to THOSE
    -- pruning a real directory, or naming a live document in EXCLUDED_FILES --
    moves both sides together and this comparison stays silent. That direction is
    covered from two other sides instead: the pinned surfaces are asserted
    against the filesystem rather than against a second walk, and
    `test_no_exclusion_has_widened_without_being_written_down` pins the exclusion
    constants themselves. Neither mechanism alone is the guard; do not delete one
    because the other passes.
    """
    second = scope_by_decoding()
    first = frozenset(SCOPE)
    missing = sorted(second - first)
    surplus = sorted(first - second)
    assert not missing, (
        f"discover_scope() dropped {len(missing)} file(s) that decode as UTF-8, of "
        f"kinds: {_kinds(missing)}.\nA file whose bytes are text is in scope; that "
        "is the whole rule, and every revision of this guard that replaced it with "
        "a list of kinds was escaped by a claim written just outside the list. If "
        "`is_text` now judges by filename, revert it. If a path genuinely must be "
        "exempt, name it in EXCLUDED_FILES or EXCLUDED_DIRS, where both this test "
        "and the walk can see it.\nDropped:\n  " + "\n  ".join(missing[:20])
    )
    assert not surplus, (
        f"SCOPE contains {len(surplus)} path(s) a plain decode of the tree does not "
        f"find: {surplus[:20]}. Either the walk is reaching something it prunes, or "
        "UNREACHABLE_SCOPE names a path that no longer exists -- which is reported "
        "properly by test_pinned_surfaces_are_scanned."
    )


def test_no_exclusion_has_widened_without_being_written_down():
    """Every exclusion is a hole, so widening one must be a deliberate act.

    `test_the_defect_record_stays_out_of_scope` checks these constants from the
    inside -- that what is excluded really is out of SCOPE. Nothing checked the
    other direction, and that is the cheapest possible version of the defect this
    whole module exists for: a claim stops failing the guard the moment its
    document is named here, and the edit is one line in a frozenset. Only the
    pinned surfaces would notice, and only for the paths they pin -- exclude
    `docs/dataset_quality.md`, or prune `configs/`, and nothing in this file says
    a word.

    The duplication below is the point. These are deliberately restated rather
    than derived, so widening an exclusion takes two edits in two places and the
    second one is this test telling you what you are doing. If you are adding a
    document here, the question to answer in the commit message is why the
    retraction cannot live in `tier1_hardening_report.md` like the others.
    """
    assert EXCLUDED_FILES == frozenset({
        "tier1_hardening_report.md",
        "diagnosis_report.md",
        "tests/test_docs_claims.py",
    }), (
        "EXCLUDED_FILES has changed. It holds the two audit-record documents, "
        "which have to quote the retired sentences verbatim, and this module, "
        "which declares them. Anything else named here is a judge-facing document "
        f"that has been taken out of the scan.\nIt now reads: "
        f"{sorted(EXCLUDED_FILES)}"
    )
    assert EXCLUDED_DIRS == frozenset({"docs/decisions"}), (
        "EXCLUDED_DIRS has changed. Decision records supersede each other by "
        "quoting what they supersede, which is why that one directory is out. A "
        "second entry here is a directory of documents nothing is checking.\n"
        f"It now reads: {sorted(EXCLUDED_DIRS)}"
    )
    assert PRUNED_DIR_NAMES == frozenset({"__pycache__"}), (
        "PRUNED_DIR_NAMES has changed. It prunes generated bytecode, and the walk "
        "separately prunes dot-directories. Adding a real source directory here "
        "removes every file under it from the scan without excluding a single "
        f"named path.\nIt now reads: {sorted(PRUNED_DIR_NAMES)}"
    )


@pytest.mark.parametrize("relative", BINARY_DELIVERABLES)
def test_the_binary_deliverables_are_outside_this_guard(relative):
    """The edge of this guard, asserted instead of assumed.

    Scope is decided by decoding, so a judge-facing deliverable that is not UTF-8
    cannot be scanned for retired claims at all -- and a retired claim on a deck
    slide is exactly as visible to a judge as one in README.md. Naming the two
    shipped binaries here turns that from a thing someone happens to know into a
    handover: the PDF's contents are guarded by tests/test_figures.py, and the
    deck is built by scripts/build_deck.py, so guarding its text belongs with that
    builder rather than here.

    The decode is inline rather than through `is_text` on purpose: this test
    asserts what the bytes are, not what `is_text` currently thinks.
    """
    path = REPO_ROOT / relative
    assert path.exists(), (
        f"{relative} is declared here as a judge-facing binary outside this "
        "guard's reach, but it does not exist. If it was renamed, follow the "
        "rename; if it was dropped as a deliverable, drop it from "
        "BINARY_DELIVERABLES and from the module docstring in the same edit."
    )
    try:
        path.read_bytes().decode("utf-8")
    except (UnicodeDecodeError, OSError):
        decodes = False
    else:
        decodes = True
    assert not decodes, (
        f"{relative} now decodes as UTF-8, so it is no longer outside this guard: "
        "it is scannable prose. Remove it from BINARY_DELIVERABLES and let "
        "discovery pick it up -- and check the module docstring, which describes "
        "it as unreachable."
    )
    assert relative not in SCOPE, (
        f"{relative} does not decode as UTF-8 yet appears in SCOPE, so every "
        "pattern is being run over binary noise. discover_scope() is admitting "
        "files it cannot read."
    )


@pytest.mark.parametrize("claim", BANNED, ids=lambda c: c.slug)
def test_patterns_catch_the_sentences_they_retired(claim):
    """Guard for the guard: every retired sentence must still trip its own patterns,
    so a regex cannot be loosened into a no-op to make a failure go away.

    This checks the sentence in ISOLATION and is therefore the weaker of the two
    ratchet proofs -- proving a pattern matches a bare string says nothing about
    whether an exemption swallows it once it is in a file. That is
    test_retired_sentences_are_caught_inside_the_real_documents, below."""
    for sentence in claim.retired_sentences:
        assert hits(normalise(sentence), claim), (
            f"[{claim.slug}] no pattern matches the retired sentence it exists to "
            f"ban: {sentence!r}. Loosening these regexes releases the ratchet."
        )


@pytest.mark.parametrize("claim", BANNED, ids=lambda c: c.slug)
def test_every_pattern_is_load_bearing_for_a_retired_sentence(claim):
    """No pattern may be switched off without a sentence falling on the floor.

    The test above proves each SENTENCE is caught by SOME pattern, which is the
    wrong way round for the failure that actually happened: a pattern with no
    sentence of its own can be neutralised and every other test stays green. A
    verifier put the bare word `cascade` in this claim's allow_exact -- which
    exempts every occurrence of it anywhere, so /cascade/ stopped matching -- and
    then appended "The deployed engine is a cascade." to README.md. Nothing
    failed, because all three cascade sentences also said "fast tier" and
    /fast\\s+tier/ kept catching them.

    So each pattern must have a retired sentence that IT catches and its siblings
    do NOT. Exempt a pattern, loosen it into a no-op, or delete it, and that
    sentence stops being caught here. Note this is measured through `hits`, which
    applies allow_exact: an exemption wide enough to disable a pattern fails on
    this line, not on the README edit that follows it three commits later.

    It is also what caught /net_guard(?:\\.py)?\\s+enforces/, which had never
    matched anything: `normalise` strips `_` before any pattern runs, so the text
    it looked for did not survive to be looked at. Patterns are checked here
    against normalised sentences, exactly as documents are scanned, so an inert
    pattern cannot be added without a sentence it fails to prove.
    """
    for pattern in claim.patterns:
        alone = replace(claim, patterns=(pattern,))
        siblings = replace(
            claim, patterns=tuple(p for p in claim.patterns if p is not pattern)
        )
        caught = [s for s in claim.retired_sentences if hits(normalise(s), alone)]
        proving = [
            s for s in caught if not hits(normalise(s), siblings)
        ]
        assert proving, (
            f"[{claim.slug}] /{pattern.pattern}/ is not load-bearing: no retired "
            "sentence depends on it alone, so it can be switched off and every "
            "other test in this file still passes.\n"
            + (
                f"It catches {len(caught)} retired sentence(s), but each of them is "
                "also caught by another pattern of this claim, so removing it "
                "changes nothing that is checked."
                if caught else
                "It catches NO retired sentence at all -- it has been loosened, or "
                "it is inert. Check it against NORMALISED text: `normalise` strips "
                "* _ ` and folds dashes and whitespace before any pattern runs, "
                "which is how a pattern spelled `net_guard` came to match nothing "
                "in this repository, ever."
            )
            + "\nAdd a retired sentence that only this pattern catches -- the "
            "sentence a contributor would actually write -- or delete the pattern. "
            "A pattern nothing depends on is a pattern nobody will notice losing."
        )


@pytest.mark.parametrize("claim", BANNED, ids=lambda c: c.slug)
def test_retired_sentences_are_caught_inside_the_real_documents(claim):
    """The ratchet, proved where it has to work: inside the corrected files.

    Every retired sentence is inserted at every paragraph boundary of every
    scanned file and must be caught at every one of them. Run against the previous
    neighbourhood-window exemptions this reported 98 escapes out of 8,722
    insertion points, because retraction wording elsewhere in the paragraph was
    waving the reintroduction through."""
    escaped: list[str] = []
    slots = 0
    for sentence in claim.retired_sentences:
        for relative in SCOPE:
            path = REPO_ROOT / relative
            if not path.exists():  # reported by test_pinned_surfaces_are_scanned
                continue
            raw = path.read_text(encoding="utf-8")
            for index, doctored in paragraph_slots(raw, sentence):
                slots += 1
                if not hits(doctored, claim):
                    escaped.append(
                        f"{relative}, paragraph slot {index}: {sentence!r}"
                    )
    assert slots, (
        f"[{claim.slug}] examined no insertion points at all - this claim declares "
        "no retired_sentences, or SCOPE is empty. Either way it proves nothing."
    )
    assert not escaped, (
        f"\n[{claim.slug}] a retired sentence can be reintroduced without this "
        f"guard noticing, at {len(escaped)} of {slots} insertion points. First few:"
        "\n  " + "\n  ".join(escaped[:12])
        + "\n\nAn exemption in allow_exact is too wide, or a pattern is too narrow. "
        "allow_exact entries must be tight verbatim quotes of the retracting "
        "sentence, never a phrase that ordinary prose also contains."
    )


@pytest.mark.parametrize("relative", PINNED_SCOPE)
def test_the_fast_insertion_path_matches_the_literal_one(relative):
    """The ratchet proof above splices normalised paragraphs instead of
    normalising each doctored document, which is a ~2x saving and exactly the
    kind of shortcut that quietly changes what is being tested. Check it on the
    pinned surfaces with a sentence chosen to exercise every rewrite `normalise`
    performs: emphasis markers, a curly apostrophe, an em dash, and a hard line
    break inside the inserted text itself."""
    probe = "best **validation**\nAUROC — the fused row’s `claim`"
    path = REPO_ROOT / relative
    if not path.exists():  # reported by test_pinned_surfaces_are_scanned
        pytest.skip(f"{relative} missing")
    raw = path.read_text(encoding="utf-8")
    fast = [text for _, text in paragraph_slots(raw, probe)]
    literal = [text for _, text in paragraph_slots_literal(raw, probe)]
    assert len(fast) == len(literal)
    for index, (a, b) in enumerate(zip(fast, literal)):
        assert a == b, (
            f"{relative} slot {index}: the fast insertion path and the literal one "
            "disagree, so the ratchet proof is scanning text that a reintroduced "
            "claim would never produce. Use paragraph_slots_literal and take the "
            "cost.\n"
            f"  fast:    {a[:300]!r}\n  literal: {b[:300]!r}"
        )


@pytest.mark.parametrize("claim", BANNED, ids=lambda c: c.slug)
def test_every_allowance_is_anchored_in_a_real_document(claim):
    """The allowlist, kept honest from the other side.

    An exemption is a hole in the ratchet, so each one must earn its place: it has
    to contain a banned phrase (otherwise it exempts nothing and is there to look
    considered), and it has to be text a scanned document really contains
    (otherwise it is a pre-authorised hole waiting for someone to write into).
    Reword a retraction in the docs and this fails here rather than silently
    widening later.

    Containing a banned phrase and occurring somewhere are necessary and nowhere
    near sufficient: the bare word `cascade` satisfied both, and as an exemption
    it switched the /cascade/ pattern off everywhere at once. Two more conditions
    say what a retraction actually looks like. It is WIDER than the phrase it
    quotes -- a retraction says something about the claim, so an excerpt that is
    nothing but the matched phrase is not one. And it is not a fragment of the
    claim itself: if the excerpt fits inside a sentence this guard exists to ban,
    then writing that sentence anywhere carries its own exemption along with it.
    Both are checked against `retired_sentences`, so they get stronger as the
    ratchet does rather than depending on a list of suspicious words."""
    for excerpt in claim.allow_exact:
        needle = normalise(excerpt)
        assert any(p.search(needle) for p in claim.patterns), (
            f"[{claim.slug}] allow_exact entry {excerpt!r} contains none of this "
            "claim's banned phrases, so it exempts nothing. Delete it."
        )
        for pattern in claim.patterns:
            for m in pattern.finditer(needle):
                assert (m.start(), m.end()) != (0, len(needle)), (
                    f"[{claim.slug}] allow_exact entry {excerpt!r} is nothing but "
                    f"the banned phrase itself (it is exactly what "
                    f"/{pattern.pattern}/ matches). An exemption covers every "
                    "occurrence that lies inside it, so this one exempts the "
                    "phrase everywhere and switches the pattern off. Quote the "
                    "sentence that retracts the claim, not the claim."
                )
        for sentence in claim.retired_sentences:
            assert needle not in normalise(sentence), (
                f"[{claim.slug}] allow_exact entry {excerpt!r} is a fragment of a "
                f"retired sentence:\n  {sentence!r}\nAn exemption travels with the "
                "text it quotes, so this one would exempt that sentence wherever "
                "someone writes it -- the reintroduction arrives pre-authorised. A "
                "retraction quotes the claim and then says something about it, so "
                "it is wider than the claim; if yours is narrower, it is not a "
                "retraction."
            )
        where = [
            relative for relative in SCOPE
            if (REPO_ROOT / relative).exists() and needle in normalised_document(relative)
        ]
        assert where, (
            f"[{claim.slug}] allow_exact entry {excerpt!r} appears in no scanned "
            "document. An exemption for text that does not exist is a hole held "
            "open for a future reintroduction - delete it, or quote the retracting "
            "sentence as it is actually written."
        )


@pytest.mark.parametrize("relative", SCOPE)
@pytest.mark.parametrize("claim", BANNED, ids=lambda c: c.slug)
def test_retired_claim_has_not_reappeared(claim, relative):
    path = REPO_ROOT / relative
    if not path.exists():  # reported by test_pinned_surfaces_are_scanned
        pytest.skip(f"{relative} missing")
    found = hits(normalised_document(relative), claim)
    assert not found, (
        f"\n{relative} re-states a retired claim [{claim.slug}].\n\n"
        f"WHY IT IS BANNED: {claim.why}\n\n"
        + "\n\n".join(found)
        + "\n\nIf you are quoting the claim in order to retract it, put the quote in "
        "tier1_hardening_report.md, which this guard does not scan - or, if it has "
        "to appear in the document, add the retracting sentence VERBATIM to that "
        "claim's allow_exact. A nearby retraction does not exempt anything: the "
        "exemption covers the quoted sentence and nothing else."
    )
