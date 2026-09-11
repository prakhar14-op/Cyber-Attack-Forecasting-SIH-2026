"""Retired claims must stay retired.

An adversarial audit found published claims that were false, and the reason they
survived so long is that nothing in the build objected when a corrected sentence
drifted back. Several were retracted from the judge-facing docs; this test is the
ratchet that stops them returning.

It is deliberately NOT a spell-check of the docs. Each entry below is a specific
claim-shaped phrasing with the measurement that refutes it, so a failure tells a
contributor what is wrong with the sentence rather than that a word is forbidden.

Scope is DISCOVERED, not listed. An earlier version enumerated seven files, and
three claims corrected in an earlier round all landed in documents that
enumeration did not name -- including `docs/INSTALL.md`, written by the same hand
that wrote this guard. A guard that has to be extended by the author of the next
document is a guard that will be out of date by the next document. Every
markdown file in the repo is in scope the moment it is created; the only
exclusions are the defect record itself.

`tier1_hardening_report.md`, `diagnosis_report.md` and `docs/decisions/` are
excluded on purpose: they are the record of these defects and have to quote them
verbatim. If you need to write one of these sentences down in order to retract
it, write it there.

HOW AN EXEMPTION WORKS, AND WHY IT IS NOT A WINDOW
--------------------------------------------------
A retraction has to be able to quote what it retracts, so some occurrences must
be allowed. An earlier version of this file allowed a match when a *retraction
marker* appeared anywhere within 150-400 characters of it. That is how the
ratchet acquired a blind spot centred on the very paragraphs it existed to
protect: `docs/INSTALL.md` says "Do **not** check the suite against a memorised
pass/skip count", and `must not` / `do not check` / `three tests` / `opt-in` are
ordinary English that occurs all over a corrected document. Measured by running
the previous implementation over the present files: inserting each retired
sentence at each paragraph boundary of each scanned file gives 8,722 insertion
points, and the old exemptions stayed silent at **98 of them**, spread over ten
files including `docs/INSTALL.md`, `README.md`, `docs/demo_script.md`,
`capture/CONSENT.md`, `CLAUDE.md` and `scripts/fetch_artifacts.py`. The same
measurement against the code below gives 0. That measurement is not a claim made
here: it is what `test_retired_sentences_are_caught_inside_the_real_documents`
computes on every run.

So the neighbourhood window is gone. An occurrence is exempt only when it lies
inside one of the verbatim excerpts in `allow_exact` -- the actual retracting
sentence, quoted from the document, tight around the phrase it exempts. A new
sentence next door is not covered by its neighbour's exemption, which is the
whole point. `test_every_allowance_is_anchored_in_a_real_document` then keeps the
allowlist honest from the other side: an excerpt that no scanned document
actually contains, or that does not itself contain a banned phrase, is dead
weight pretending to be a considered exception, and fails.

`test_retired_sentences_are_caught_inside_the_real_documents` re-runs the
measurement above on every commit, so the ratchet is proved against the real
files rather than against sentences held in isolation.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent

# The record of the defects. These files exist to quote the retired sentences.
EXCLUDED_FILES = frozenset({"tier1_hardening_report.md", "diagnosis_report.md"})
EXCLUDED_DIRS = frozenset({"docs/decisions"})

# Non-markdown surfaces that carry claim-shaped prose in their docstrings or
# comments, and that a judge or a contributor reads as documentation. These are
# PINNED, not conditional: `.github/workflows/ci.yml` is one of the places the
# suite-count claim has lived, and an earlier version dropped a renamed entry out
# of scope silently because it filtered this tuple by `.exists()`.
EXTRA_SCOPE = (
    "eval/fused.py",
    "scripts/fetch_artifacts.py",
    ".github/workflows/ci.yml",
)

# Discovery must not be able to silently collapse: these are the documents a
# judge certainly reads.
CORE_SCOPE = (
    "README.md",
    "docs/INSTALL.md",
    "docs/architecture.md",
    "docs/limitations.md",
    "docs/slides.md",
    "docs/benchmark_protocol.md",
    "docs/demo_script.md",
)

# Everything that must be scanned whatever the filesystem looks like.
# `test_pinned_surfaces_are_scanned` fails if one of these stops existing or
# stops being discovered -- that is the only part of SCOPE a rename can break
# loudly, and it is why the list is written out rather than walked.
PINNED_SCOPE = CORE_SCOPE + EXTRA_SCOPE


def discover_scope() -> tuple[str, ...]:
    """Every markdown file in the repo, minus the defect record, plus EXTRA_SCOPE.

    Dot-directories are pruned rather than filtered: `.venv` is a junction to a
    1.5 GB interpreter tree on this machine and walking into it would make this
    guard cost seconds. `.github` is therefore unreachable by the walk, which is
    exactly why `ci.yml` is pinned in EXTRA_SCOPE instead.

    EXTRA_SCOPE is appended unconditionally. Filtering it by `.exists()` -- as an
    earlier version did -- means a renamed surface leaves SCOPE without anything
    failing, and `ci.yml` quietly stops being checked.
    """
    found: list[str] = []
    for root, dirs, files in os.walk(REPO_ROOT):
        here = Path(root)
        dirs[:] = [
            d for d in dirs
            if not d.startswith(".")
            and (here / d).relative_to(REPO_ROOT).as_posix() not in EXCLUDED_DIRS
        ]
        for name in files:
            if not name.endswith(".md"):
                continue
            relative = (here / name).relative_to(REPO_ROOT).as_posix()
            if relative not in EXCLUDED_FILES:
                found.append(relative)
    return tuple(sorted(found) + list(EXTRA_SCOPE))


SCOPE = discover_scope()


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
            # README.md and docs/architecture.md both say "..., not a cascade".
            # The exemption is those three words, not the paragraph around them.
            "not a cascade",
        ),
        retired_sentences=(
            "the deployed scorer is the cascade's fast tier",
            "the engine runs the fast tier of the cascade, escalating to the fused model",
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
            r"net_guard(?:\.py)?\s+enforces",
        ),
        # The corrected wording in docs/INSTALL.md names the three tests instead
        # of the suite, so it trips none of these patterns and needs no exemption.
        retired_sentences=(
            "The demo, inference, ledger verification and the test suite all run "
            "with sockets blocked - tests/net_guard.py enforces it.",
            "Inference, the demo, ledger verification and the test suite all stay "
            "offline (CLAUDE.md hard constraint 1).",
            "every test in the suite runs with sockets blocked",
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
        # Nothing in scope quotes a count, so nothing is exempt. The previous
        # /do not (expect|check)/ and /must not/ escapes matched ordinary prose in
        # four different documents and were what let a reintroduced count through.
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
    """Falsifiable: SCOPE is otherwise built by walking the filesystem, so every
    discovered entry exists by construction and asserting it proves nothing. These
    ten paths are asserted instead of discovered -- rename or delete one and this
    fails, which is the only way a surface leaving SCOPE can be noticed at all.
    `.github/workflows/ci.yml` is the case that matters: it is unreachable by the
    walk (dot-directories are pruned) and it is one of the three places the
    suite-count claim has lived."""
    assert (REPO_ROOT / relative).exists(), (
        f"{relative} is pinned into this guard's SCOPE but does not exist. Either "
        "restore it or follow the rename here and in CORE_SCOPE/EXTRA_SCOPE - a "
        "missing file here means a judge-facing surface has stopped being checked "
        "for retired claims."
    )
    assert relative in SCOPE, (
        f"{relative} exists but discover_scope() no longer returns it. Do not "
        "narrow the walk to make this pass; fix the walk."
    )


def test_the_defect_record_stays_out_of_scope():
    """The record files quote the retired sentences in order to retract them. If
    they were ever pulled into SCOPE the guard would fail on its own evidence,
    and the tempting fix would be to delete the evidence."""
    for relative in EXCLUDED_FILES:
        assert relative not in SCOPE, f"{relative} is the defect record; it must stay excluded"
    assert not any(s.startswith("docs/decisions/") for s in SCOPE), (
        "docs/decisions/ supersede each other by quoting what they supersede"
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
    widening later."""
    for excerpt in claim.allow_exact:
        needle = normalise(excerpt)
        assert any(p.search(needle) for p in claim.patterns), (
            f"[{claim.slug}] allow_exact entry {excerpt!r} contains none of this "
            "claim's banned phrases, so it exempts nothing. Delete it."
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
