"""The judge-facing deck, guarded in CI instead of only when a human rebuilds it.

`scripts/build_deck.py` grew a family of checks over five audit rounds and every
one of them fired **only inside the builder**. Nothing in `tests/` or `.github/`
named the script, so a contributor could change `docs/slides.md`, never run the
builder, and ship a deck whose guards had never executed. That is how each of
the defects below reached a verifier:

  * slide 2 drew ONE solid chain straight through TGN and GRAFT into the engine,
    with XGBoost -- the only model in the scoring path -- named nowhere;
  * slide 3's largest text was `Fused ... 0.933` with no on-slide marker saying
    it is an evaluation-side number, the correction living in 547 words of
    speaker notes that are never projected;
  * the XGBoost row's AUROC could be changed to the fused headline's 0.933 and
    the build passed, shipping two rows both reading 0.933;
  * `forward forecasts validated at k = 4 and 8` could be added to slide 3 while
    slide 1 still said `fires on 0 of 2 episodes at k = 1, 4 and 8`, because
    every check proved a disclosure PRESENT and none proved a contradiction
    ABSENT;
  * `(horizon-0)` could be deleted from the lead column header, though the
    report claimed that parenthesis was pinned.

Each of those is a test below, doctored the way a careless contributor would
really do it -- an edited cell, a moved phrase, a reworded caption -- never with
nonsense input. A guard that survives the plausible break is the wrong guard.

TWO HALVES, AND WHY
-------------------
python-pptx is a BUILD-time tool. `scripts/build_deck.py`'s docstring explains
why it is deliberately absent from `requirements.txt`: it would put a
document-authoring dependency into the air-gapped inference environment for no
reason. So on a bare checkout -- CI included -- it is not installed, exactly like
the trained artifacts `tests/_stubs.engine_artifacts_present` gates on.

The consequence is stated rather than hidden. Every check that can be made
WITHOUT rendering a .pptx is made without one, against the real `docs/slides.md`
and the real documents it is bound to, so it runs everywhere: the source-side
bindings, the limitation binding, the results-row binding and every banned-claim
pattern are all in that half. Only the round trip -- render, save, reopen, and
attack the saved bytes -- needs the library, and `requires_pptx` gates those with
the install line in its reason. If python-pptx is missing, the half that skips is
the half that proves the guards survive into the file a judge opens; the half
that still runs proves the guards themselves are not vacuous.
"""

from __future__ import annotations

import hashlib
import re
import zipfile
from pathlib import Path

import pytest

from scripts.build_deck import (
    BANNED_ON_SLIDE,
    DEPLOYED_MARKER,
    EVAL_MARKER,
    EVAL_ONLY_LANE_TOKENS,
    LEAD_HEADER_MARK,
    LIMITATION_TOPICS,
    REQUIRED_ON_SLIDE,
    SOURCE_DIGEST_KEY,
    banned_problems,
    check_source,
    deck_source_digest,
    limitation_problems,
    list_items,
    main,
    model_key,
    normalise,
    parse_slides,
    read_lane_split,
    read_measured_rows,
    read_source_facts,
    results_problems,
    stamped_source_digest,
    table_rows,
    verify,
)
from tests._stubs import REPO_ROOT

SLIDES = REPO_ROOT / "docs" / "slides.md"
LIMITATIONS = REPO_ROOT / "docs" / "limitations.md"
ARCHITECTURE = REPO_ROOT / "docs" / "architecture.md"
DECK = REPO_ROOT / "docs" / "deck" / "sih26153_technical_deck.pptx"


def _pptx_present() -> bool:
    """Whether the build-time renderer is installed on this machine.

    Deliberately absent from requirements.txt -- see this module's docstring and
    `scripts/build_deck.py`'s. The same shape as
    `tests/_stubs.engine_artifacts_present`: a documented, intentional absence
    gates the tests that need it instead of erroring the suite.
    """
    import importlib.util

    return importlib.util.find_spec("pptx") is not None


requires_pptx = pytest.mark.skipif(
    not _pptx_present(),
    reason=(
        "python-pptx is a BUILD-time tool and is deliberately not in "
        "requirements.txt (scripts/build_deck.py docstring). Install it to run the "
        "deck round-trip guards:  python -m pip install python-pptx"
    ),
)


# --------------------------------------------------------------------- helpers


def source_text() -> str:
    assert SLIDES.exists(), f"{SLIDES} is the deck's only source and is missing"
    return SLIDES.read_text(encoding="utf-8")


def facts():
    return read_source_facts(ARCHITECTURE, LIMITATIONS)


def slide_named(slides, number: int):
    return next(s for s in slides if s.number == number)


def block_of(slides, number: int, kind: str):
    return next(b for b in slide_named(slides, number).on_slide if b.kind == kind)


def limitation_items(markdown: str) -> list[str]:
    slides = parse_slides(markdown)
    limits = [s for s in slides if "cannot do" in s.title.lower()][0]
    return list_items(
        next(b for b in limits.on_slide if b.kind == "points").lines
    )


def source_table(markdown: str) -> list[list[str]]:
    return table_rows(block_of(parse_slides(markdown), 3, "table").lines)


def on_slide_units(markdown: str, number: int) -> list[tuple[str, str]]:
    """Every marked block of one slide, as (name, text) units for banned_problems.

    The source-side stand-in for `_slide_units`, and it has to split the same way
    the renderer does: one table CELL and one list ITEM per unit, not the whole
    block. The first draft passed the table through as one string and reported a
    hit that is not on the slide at all -- the fused row's model cell read as
    adjacent to the XGBoost row's, four cells away. Scope is part of the check.
    """
    units = []
    for index, block in enumerate(slide_named(parse_slides(markdown), number).on_slide):
        name = f"{block.kind}[{index}]"
        if block.label:
            units.append((name, block.label))
        if block.kind == "table":
            units.extend((name, cell) for row in table_rows(block.lines) for cell in row)
        elif block.kind in ("points", "chips"):
            units.extend((name, item) for item in list_items(block.lines))
        else:
            units.append((name, " ".join(block.lines)))
    return units


def build_to(tmp_path: Path, markdown: str, *extra: str) -> Path:
    """Build a doctored deck into tmp_path. Raises SystemExit if the build refuses."""
    tmp_path.mkdir(parents=True, exist_ok=True)
    source = tmp_path / "slides.md"
    source.write_text(markdown, encoding="utf-8")
    out = tmp_path / "deck.pptx"
    main(["--slides", str(source), "--out", str(out),
          "--limitations", str(LIMITATIONS), "--architecture", str(ARCHITECTURE),
          *extra])
    return out


def repack(src: Path, dst: Path, member: str, old: str, new: str) -> None:
    """Rewrite one member of a .pptx zip, the way a hand-edit would.

    Asserts `old` was really there first: a patch that silently matched nothing
    would make the test that uses it pass for the wrong reason.
    """
    with zipfile.ZipFile(src) as source:
        members = [(info, source.read(info.filename)) for info in source.infolist()]
    patched = False
    with zipfile.ZipFile(dst, "w", zipfile.ZIP_DEFLATED) as out:
        for info, data in members:
            if info.filename == member:
                text = data.decode("utf-8")
                assert old in text, (
                    f"{member} does not contain {old!r}, so this patch would test "
                    "nothing. The deck's XML changed shape."
                )
                data = text.replace(old, new).encode("utf-8")
                patched = True
            out.writestr(info, data)
    assert patched, f"{member} is not in {src}"


# ======================================================================= HALF A
# Everything below runs without python-pptx, against the real documents.


def test_the_shipped_source_is_consistent_with_every_document_it_binds_to():
    """The deck source, the limitations document, and architecture.md §2/§3/§4.

    Falsifiable in every direction the rest of this file exercises: each of the
    doctoring tests below starts from this same text and this same `facts()`, and
    each of them fails. If this one ever fails on its own, `docs/slides.md` and
    the documents disagree and the deck must not be built.
    """
    known = facts()
    check_source(parse_slides(source_text()), known.headings)
    assert results_problems(
        source_table(source_text()), known.measured, known.deployed_key,
        "docs/slides.md's results table",
    ) == []


def test_the_deployed_row_key_is_read_from_the_document_not_declared():
    """Which row a judge's demo is, is architecture.md §3's statement, not ours."""
    known = facts()
    assert known.deployed_key in known.measured, (
        f"docs/architecture.md §3 names {known.deployed_key!r} as the deployed "
        "scorer but §4 publishes no row for it, so the deck has nothing to label."
    )
    assert known.deployed_key != "fused", (
        "architecture.md §3 now says the engine runs the fused model. It does not: "
        "engine/predict.py loads one booster and calls predict_proba once."
    )


def test_model_key_resolves_the_fused_row_to_fused_and_not_to_a_member():
    """`Fused (rank-mean TGN+XGB)` names three models; only one of them is the row.

    Falsifiable: reorder MODEL_KEYS so `xgboost` precedes `fused` and the fused
    row starts resolving to the deployed key -- which would make the fused
    headline pass every check written for the XGBoost row.
    """
    assert model_key("**Fused (rank-mean TGN+XGB) — shipped**") == "fused"
    assert model_key("Fused TGN+XGBoost — EVAL-SIDE") == "fused"
    assert model_key("XGBoost — DEPLOYED ENGINE") == "xgboost"
    assert model_key("TGN encoder — eval-side") == "tgn"
    assert model_key("LR *(graded baseline)* — eval-side") == "logistic"
    assert model_key("LSTM") is None


def test_the_measured_rows_come_from_architecture_md():
    """Every figure the deck prints is looked up, never typed here.

    So this asserts the LOOKUP works, not the values: the values are whatever
    §4 measured, and `test_giving_one_model_another_models_auroc_fails` is what
    proves the comparison bites.
    """
    measured = read_measured_rows(ARCHITECTURE)
    for key in ("fused", "xgboost", "tgn", "graft", "logistic"):
        assert key in measured, (
            f"docs/architecture.md §4 no longer publishes a {key!r} row, and slide 3 "
            "prints one. Every printed figure is bound to that table."
        )
        assert any("auroc" in normalise(name) for name in measured[key]), (
            f"the {key!r} row of §4 has no AUROC column this builder can read"
        )


def test_giving_one_model_another_models_auroc_fails():
    """THE verifier's break: the XGBoost row relabelled with the fused headline.

    0.933 is a published number, so no check on the SET of numbers can see this.
    The row's figures are compared against the §4 row for the SAME model, which
    is what makes the right number on the wrong row a failure.

    Falsifiability: restore 0.872 below and the assertion at the end of
    `test_the_shipped_source_is_consistent_with_every_document_it_binds_to`
    passes on the same table.
    """
    known = facts()
    rows = source_table(source_text())
    doctored = [list(row) for row in rows]
    target = next(r for r in doctored if model_key(r[0]) == "xgboost")
    auroc_col = next(i for i, name in enumerate(rows[0]) if "auroc" in normalise(name))
    assert target[auroc_col] != "**0.933**", "this test doctors nothing"
    target[auroc_col] = "**0.933**"

    problems = results_problems(doctored, known.measured, known.deployed_key, "doctored")
    assert problems, "the deck shipped two rows both reading 0.933 and passed clean"
    assert any("0.933" in p and "xgboost" in p for p in problems), problems


def test_relabelling_the_eval_side_headline_as_the_engine_fails_twice():
    """The other half of the same break: the fused row called the shipped engine.

    Every number on the slide is still correct, so the figure binding alone would
    not catch it; the lane-label binding does, and `BANNED_ON_SLIDE` catches the
    wording independently. Two guards on the deck's single largest claim is
    deliberate -- this is the claim the previous round was opened to fix and
    shipped anyway.
    """
    known = facts()
    rows = [list(row) for row in source_table(source_text())]
    fused = next(r for r in rows if model_key(r[0]) == "fused")
    fused[0] = "**Fused TGN+XGBoost — shipped engine**"

    problems = results_problems(rows, known.measured, known.deployed_key, "doctored")
    assert any(EVAL_MARKER in p for p in problems), problems
    assert banned_problems([("cell", fused[0])], "doctored"), (
        "'shipped engine' beside the fused headline tripped no banned claim"
    )


def test_dropping_the_deployed_marker_from_the_engine_row_fails():
    """A judge must be able to see which of five rows their demo produces."""
    known = facts()
    rows = [list(row) for row in source_table(source_text())]
    row = next(r for r in rows if model_key(r[0]) == known.deployed_key)
    row[0] = re.sub(f"(?i)[—-]?\\s*{DEPLOYED_MARKER}", "", row[0]).strip()
    assert DEPLOYED_MARKER not in normalise(row[0]), row[0]

    problems = results_problems(rows, known.measured, known.deployed_key, "doctored")
    assert any(DEPLOYED_MARKER in p for p in problems), problems


def test_dropping_the_eval_side_marker_from_a_row_fails():
    """BLOCKER 2, at the level of one cell: the largest claim, unmarked."""
    known = facts()
    rows = [list(row) for row in source_table(source_text())]
    fused = next(r for r in rows if model_key(r[0]) == "fused")
    fused[0] = "**Fused (TGN + XGBoost, rank-mean)**"

    problems = results_problems(rows, known.measured, known.deployed_key, "doctored")
    assert any(EVAL_MARKER in p and "fused" in p for p in problems), problems


def test_deleting_horizon_0_from_the_lead_column_header_fails():
    """MINOR 5: the pin that was claimed and did not exist.

    The report said the attribution had two pins -- the column header and the
    band. A verifier deleted `(horizon-0)` from the header and the build passed,
    so there was one. This is the second.
    """
    known = facts()
    rows = [list(row) for row in source_table(source_text())]
    lead_col = next(i for i, name in enumerate(rows[0]) if "lead" in normalise(name))
    assert LEAD_HEADER_MARK in normalise(rows[0][lead_col])
    rows[0][lead_col] = "median lead"

    problems = results_problems(rows, known.measured, known.deployed_key, "doctored")
    assert any(LEAD_HEADER_MARK in p for p in problems), problems


def test_every_banned_claim_catches_the_sentences_it_retired():
    """Without this, a future contributor silences a failure by loosening a regex.

    Proving a pattern matches a bare string is worth little, so each retired
    sentence is passed through `banned_problems` itself -- the same entry point
    `verify` uses on the saved deck.
    """
    for claim in BANNED_ON_SLIDE:
        assert claim.retired, f"{claim.slug} pins no sentence; the regexes are free"
        for sentence in claim.retired:
            hits = banned_problems([("unit", sentence)], "proof")
            assert any(claim.slug in hit for hit in hits), (
                f"[{claim.slug}] no longer catches {sentence!r}. Loosening these "
                "regexes releases the ban.\nWHY IT IS BANNED: " + claim.why
            )


def test_the_shipped_slides_trip_no_banned_claim():
    """The other direction, and the one that keeps the ban honest.

    A pattern broad enough to ban the CORRECTION is worse than no pattern: it
    forces the next contributor to delete a disclosure to get a green build. Every
    marked block of all five slides is passed through the same check.
    """
    markdown = source_text()
    for number in range(1, 6):
        problems = banned_problems(on_slide_units(markdown, number), f"slide {number}")
        assert problems == [], (
            "a banned pattern fires on the deck as written, which means it would "
            "also fire on the correction:\n  - " + "\n  - ".join(problems)
        )


def test_an_additive_overclaim_in_a_kicker_is_caught():
    """MAJOR 4, reproduced: slide 1 says 0 of 2 episodes, slide 3 says validated.

    Both required disclosures are still present -- that is the point. The repo
    ratchet misses it too, because its pattern is `supported ... horizon` and this
    sentence says neither word.
    """
    kicker = block_of(parse_slides(source_text()), 3, "kicker")
    doctored = " ".join(kicker.lines) + " · forward forecasts validated at k = 4 and 8"
    problems = banned_problems([("deck-kicker[0]", doctored)], "slide 3")
    assert problems, f"{doctored!r} tripped nothing"
    assert "forward-forecasting-is-validated" in problems[0], problems


ITEM_5 = ("5. **The packet parser is IPv4-only** — IPv6 and other ethertypes are "
          "counted and reported,\n   never featurised: an IPv6-only capture yields "
          "**zero alerts**.")
ADAPTIVE_ATTACKER = ("5. **An adaptive attacker defeats several mandated packet "
                     "features at zero cost** —\n   measured, not guessed.")


def doctor_limitations(markdown: str, replacement: str) -> str:
    assert ITEM_5 in markdown, "slide 5's item 5 has been reworded; update ITEM_5"
    return markdown.replace(ITEM_5, replacement, 1)


def test_reverting_limitation_5_to_the_adaptive_attacker_fails():
    """The divergence the limitations binding was built for, replayed.

    `docs/limitations.md` §5 is the IPv4-only parser. The adaptive-attacker
    limitation is real, is on slide 5's band, and is NOT numbered -- because that
    document does not number it. Numbering it here is how the two lists diverged.

    Run through `check_source`, the function the builder itself calls, on a
    doctored `docs/slides.md`: the defect was never that the binding did not work.
    """
    known = facts()
    markdown = doctor_limitations(source_text(), ADAPTIVE_ATTACKER)
    with pytest.raises(SystemExit) as exc:
        check_source(parse_slides(markdown), known.headings)
    message = str(exc.value)
    assert "item 5" in message, message
    assert any(key in message for key in LIMITATION_TOPICS[4]), message


@pytest.mark.parametrize("replacement, expected", [
    (ITEM_5 + "\n6. **A sixth limitation the document does not number.**",
     "6 limitations"),
    ("", "4 limitations"),
], ids=["six-items", "four-items"])
def test_gaining_or_losing_a_limitation_fails(replacement, expected):
    """Count and content are separate failures, and both have to bite.

    Six items pass the content check for 1..5 and must still fail; four fails the
    count and leaves item 5 unbound. `check_source` runs BEFORE the render for
    exactly this reason -- a sixth item also overflows slide 5, and a height is
    not the useful thing to report about a list that stopped matching its
    document.
    """
    known = facts()
    markdown = doctor_limitations(source_text(), replacement)
    with pytest.raises(SystemExit) as exc:
        check_source(parse_slides(markdown), known.headings)
    assert expected in str(exc.value), str(exc.value)


def test_the_limitations_list_as_written_binds_cleanly():
    """The control for the three above: unchanged, it passes."""
    known = facts()
    items = limitation_items(source_text())
    assert limitation_problems(items, known.headings, "source") == []


def test_the_lane_split_is_read_from_architecture_md(tmp_path):
    """Slide 2's two lanes are that document's split, not this builder's opinion.

    Falsifiable two ways, both of them plausible edits to architecture.md: drop
    the sentence that names the evaluation-only lane, or move one of its
    components into the deployed sentence. Both stop the build and say what to
    decide.
    """
    lanes = read_lane_split(ARCHITECTURE)
    assert all(token in lanes["evaluation"] for token in EVAL_ONLY_LANE_TOKENS)

    text = ARCHITECTURE.read_text(encoding="utf-8")
    doctored = tmp_path / "architecture.md"

    doctored.write_text(text.replace("evaluation-only lane", "second lane"), "utf-8")
    with pytest.raises(SystemExit) as exc:
        read_lane_split(doctored)
    assert "evaluation-only lane" in str(exc.value)

    doctored.write_text(text.replace("the TGN encoder", "the encoder"), "utf-8")
    with pytest.raises(SystemExit) as exc:
        read_lane_split(doctored)
    assert "tgn" in str(exc.value), str(exc.value)


def test_every_required_phrase_is_really_on_the_slide_the_source_says():
    """The per-slide pins, checked against the markdown as well as the binary.

    `verify` checks them in the saved .pptx, which is the surface that matters --
    and which skips without python-pptx. This is the same assertion one step
    earlier, so the pins are not unguarded on a bare checkout.
    """
    slides = parse_slides(source_text())
    on_slide = {
        s.number: normalise(" ".join(
            " ".join(b.lines) + " " + b.label for b in s.on_slide
        ))
        for s in slides
    }
    for number, phrase, why in REQUIRED_ON_SLIDE:
        assert number in on_slide, f"docs/slides.md has no slide {number}"
        assert normalise(phrase) in on_slide[number], (
            f"slide {number} of docs/slides.md no longer states {phrase!r}.\n"
            f"WHY IT IS REQUIRED: {why}"
        )


def test_a_required_phrase_moved_to_another_slide_still_fails():
    """A disclosure two slides from its claim is not a disclosure.

    Deck-wide substring matching let the chance-baseline band move off slide 3 --
    away from the 0.933 / 2-2 table it qualifies -- and the build passed. Here it
    is moved to slide 4 and slide 3 must still fail.
    """
    markdown = source_text().replace(
        "matched-budget random baseline**", "chance baseline**", 1
    ).replace(
        "stated in `docs/limitations.md`.",
        "stated in `docs/limitations.md` — cf. the matched-budget random baseline.",
        1,
    )
    slides = parse_slides(markdown)
    on_slide = {
        s.number: normalise(" ".join(" ".join(b.lines) for b in s.on_slide))
        for s in slides
    }
    needle = normalise("matched-budget random baseline")
    assert needle not in on_slide[3], "the move did not take"
    assert needle in on_slide[4], "the phrase has to still be SOMEWHERE, or this "\
        "proves only that deletion is caught"


# ======================================================================= HALF B
# The round trip: render, save, reopen, and attack the saved bytes.


@requires_pptx
def test_the_committed_deck_passes_its_own_checks():
    """The file in `docs/deck/`, not the builder's intention.

    A committed binary is a second copy of every number on it, and nothing else
    in the suite opens it. If this fails the deck is stale: rebuild with
    `python scripts/build_deck.py`.
    """
    assert DECK.exists(), f"{DECK} is missing — run `python scripts/build_deck.py`"
    count, size = verify(DECK, facts())
    assert count == 5 and size > 0


@requires_pptx
def test_the_committed_deck_was_built_from_the_current_slides_md():
    """"Passes its own checks" and "is the current deck" are different claims.

    A .pptx built from last week's `docs/slides.md` satisfies every constraint in
    `verify` -- the constraints are about the deck, not about its date -- and
    still shows a judge the slide a fix replaced. That is this project's exact
    failure mode applied to a binary nothing else in the suite opens, so the
    builder stamps a digest of its source into the package and this recomputes it.

    Falsifiable: edit one character of `docs/slides.md` without rebuilding.
    """
    stamped = stamped_source_digest(DECK)
    assert stamped is not None, (
        f"{DECK} carries no {SOURCE_DIGEST_KEY} — it predates the stamp, so nothing "
        "can tell it from a stale deck. Rebuild: python scripts/build_deck.py"
    )
    assert stamped == deck_source_digest(SLIDES), (
        f"{DECK} is STALE: built from a docs/slides.md that hashed {stamped}, which "
        f"now hashes {deck_source_digest(SLIDES)}. Rebuild it — the build is "
        "deterministic, so this is one command and no judgement."
    )


@requires_pptx
def test_the_deck_builds_and_is_byte_deterministic(tmp_path):
    """Determinism is claimed in the builder's docstring; this is the check.

    Two builds of the same markdown into different paths must hash the same, or
    `--expect-sha256` pins nothing and a reviewer cannot tell a current deck from
    a stale one.
    """
    first = build_to(tmp_path / "a", source_text())
    second = build_to(tmp_path / "b", source_text())
    assert (hashlib.sha256(first.read_bytes()).hexdigest()
            == hashlib.sha256(second.read_bytes()).hexdigest())


@requires_pptx
def test_the_sha_pin_catches_a_deck_that_is_not_the_one_pinned(tmp_path):
    """`--expect-sha256` is what turns 'this file is current' into a check."""
    out = build_to(tmp_path / "a", source_text())
    digest = hashlib.sha256(out.read_bytes()).hexdigest()

    main(["--verify-only", "--out", str(out), "--limitations", str(LIMITATIONS),
          "--architecture", str(ARCHITECTURE), "--expect-sha256", digest])

    with pytest.raises(SystemExit) as exc:
        main(["--verify-only", "--out", str(out), "--limitations", str(LIMITATIONS),
              "--architecture", str(ARCHITECTURE), "--expect-sha256", "0" * 64])
    assert digest in str(exc.value)


@requires_pptx
def test_verify_only_refuses_a_deck_built_from_older_markdown(tmp_path):
    """The staleness stamp, proved on a deck this test builds and then outdates.

    `--verify-only` passes first, so the failure below is the stamp and not one
    of the constraints: the .pptx is byte-identical and every check still holds.
    The source moved under it, which is the one thing the constraints cannot see.
    """
    work = tmp_path / "a"
    out = build_to(work, source_text())
    argv = ["--verify-only", "--out", str(out), "--slides", str(work / "slides.md"),
            "--limitations", str(LIMITATIONS), "--architecture", str(ARCHITECTURE)]
    assert main(argv) == 0

    (work / "slides.md").write_text(
        source_text() + "\n<!-- a later edit nobody rebuilt for -->\n", encoding="utf-8"
    )
    with pytest.raises(SystemExit) as exc:
        main(argv)
    assert "STALE" in str(exc.value), str(exc.value)


@requires_pptx
def test_a_hand_edited_slide_xml_fails_verify_only(tmp_path):
    """`--verify-only` exists for a binary this run did not write. This is why.

    The .pptx is a zip of XML: editing a number in it takes a text editor. The
    edit made here is the audit's own named overclaim -- the deployed row given
    the fused headline -- applied to the bytes rather than to the markdown.
    """
    out = build_to(tmp_path / "a", source_text())
    patched = tmp_path / "patched.pptx"
    repack(out, patched, "ppt/slides/slide3.xml", ">0.872<", ">0.933<")

    with pytest.raises(SystemExit) as exc:
        main(["--verify-only", "--out", str(patched),
              "--limitations", str(LIMITATIONS), "--architecture", str(ARCHITECTURE)])
    assert "0.933" in str(exc.value) and "xgboost" in str(exc.value)


@requires_pptx
def test_redrawing_the_evaluation_lane_solid_fails_on_the_saved_file(tmp_path):
    """The lanes are separated by one visual difference; erasing it is caught.

    The dash is checked in the SAVED package, so this deletes it there. A judge
    reading an architecture slide from the back of a room separates two chains by
    how they are drawn, long before reading either caption.
    """
    out = build_to(tmp_path / "a", source_text())
    patched = tmp_path / "patched.pptx"
    repack(out, patched, "ppt/slides/slide2.xml", '<a:prstDash val="dash"/>', "")

    with pytest.raises(SystemExit) as exc:
        main(["--verify-only", "--out", str(patched),
              "--limitations", str(LIMITATIONS), "--architecture", str(ARCHITECTURE)])
    assert "dashed" in str(exc.value)


@requires_pptx
def test_merging_the_two_lanes_back_into_one_chain_fails(tmp_path):
    """BLOCKER 1, reproduced as the edit that actually made it.

    Slide 2 drew one solid chain: PCAP -> extractor -> features -> TGN -> GRAFT ->
    forecast head -> engine -> ledger. Here the evaluation lane is re-marked
    `deployed`, which is precisely what "draw it as one pipeline again" looks
    like in this source, and the build refuses.
    """
    markdown = source_text().replace(
        "<!-- deck:lane evaluation |", "<!-- deck:lane deployed |", 1
    )
    with pytest.raises(SystemExit) as exc:
        build_to(tmp_path / "a", markdown)
    message = str(exc.value)
    assert "draws no 'evaluation' lane" in message, message
    # The sibling test below is the other half: a merge that keeps both captions
    # and moves only one chevron up. That one is caught by the token binding, not
    # by the lane being absent, and the two failures must stay distinct.


@requires_pptx
def test_rewording_the_evaluation_caption_fails_even_though_the_phrase_stays(tmp_path):
    """The hole the per-slide phrase check leaves, and why the caption is pinned.

    Slide 2's headline also says "evaluation-only", so rewording the dashed lane's
    caption to "RESEARCH TRACK" left the phrase on the slide: the per-slide check
    passed and the build shipped a dashed lane that no longer said what it was.
    The caption is checked on its own shape.

    Falsifiable: this doctoring built clean before `LANE_CAPTION_MARK` existed.
    """
    markdown = source_text().replace(
        "EVALUATION-ONLY — measured in `eval/`, never loaded by the engine",
        "RESEARCH TRACK — measured in `eval/`",
        1,
    )
    assert "evaluation-only" in normalise(markdown), (
        "the phrase has to survive elsewhere on slide 2, or this proves only that "
        "deleting it everywhere is caught"
    )
    with pytest.raises(SystemExit) as exc:
        build_to(tmp_path / "a", markdown)
    assert "caption does not say 'evaluation-only'" in str(exc.value), str(exc.value)


@requires_pptx
def test_dropping_the_deployed_model_from_the_lane_fails(tmp_path):
    """The defect in one sentence: XGBoost appears nowhere on the architecture slide."""
    markdown = source_text().replace("**XGBoost scorer** (one booster)", "scorer", 1)
    with pytest.raises(SystemExit) as exc:
        build_to(tmp_path / "a", markdown)
    assert "xgboost" in str(exc.value).lower()


@requires_pptx
def test_an_evaluation_component_drawn_in_the_deployed_lane_fails(tmp_path):
    """Half a merge is the same untruth: the fused story written into the top lane.

    The chevron count is deliberately unchanged, so the failure has to come from
    the lane binding and not from the chevron-fit check that a sixth stage would
    trip first.
    """
    markdown = source_text().replace(
        "**XGBoost scorer** (one booster)", "**TGN + XGBoost scorer**", 1,
    )
    with pytest.raises(SystemExit) as exc:
        build_to(tmp_path / "a", markdown)
    message = str(exc.value)
    assert "DEPLOYED lane names 'tgn'" in message, message


@requires_pptx
def test_a_chevron_that_outgrows_its_own_outline_fails(tmp_path):
    """A chevron is not a rectangle, and nothing measured that until now.

    PowerPoint insets the arrow by half the shape's height at each end, so five
    chevrons on one row hold far less text than their bounding boxes suggest, and
    text that runs past the outline is unreadable on a projected slide. Failing
    is the right answer -- the fix is fewer words or fewer stages, never smaller
    type, which is the thing this deck may not do.
    """
    markdown = source_text().replace(
        "→ **XGBoost scorer** (one booster)",
        "→ **XGBoost scorer** (one gradient-boosted decision-tree booster, TreeSHAP)",
        1,
    )
    with pytest.raises(SystemExit) as exc:
        build_to(tmp_path / "a", markdown)
    message = str(exc.value)
    assert "chevron" in message and "lines" in message, message


@requires_pptx
def test_a_per_slide_phrase_removed_while_present_elsewhere_fails(tmp_path):
    """The move, end to end, through the saved file.

    The pure-markdown half of this is
    `test_a_required_phrase_moved_to_another_slide_still_fails`; this is the
    builder refusing to save it.
    """
    markdown = source_text().replace(
        "matched-budget random baseline**", "chance baseline**", 1
    ).replace(
        "stated in `docs/limitations.md`.",
        "stated in `docs/limitations.md` — cf. the matched-budget random baseline.",
        1,
    )
    with pytest.raises(SystemExit) as exc:
        build_to(tmp_path / "a", markdown)
    message = str(exc.value)
    assert "matched-budget random baseline" in message
    assert "slide [4]" in message, message


@requires_pptx
def test_an_additive_overclaim_stops_the_build(tmp_path):
    """MAJOR 4 through the whole builder, not just the pattern.

    Slide 1 still says `fires on 0 of 2 episodes at k = 1, 4 and 8`; slide 3 now
    also says forward forecasts are validated. Every required disclosure is
    present and the deck still contradicts itself.
    """
    markdown = source_text().replace(
        "tested on an unseen **bot** day · 1 % FPR budget",
        "tested on an unseen **bot** day · forward forecasts validated at k = 4 and 8",
        1,
    )
    with pytest.raises(SystemExit) as exc:
        build_to(tmp_path / "a", markdown)
    assert "forward-forecasting-is-validated" in str(exc.value)


@requires_pptx
@pytest.mark.parametrize(
    "old, new, expected",
    [
        # MAJOR 3, exactly as the verifier made it: the deployed row given the
        # fused headline. Two rows both reading 0.933, and the build passed.
        ("| **XGBoost — DEPLOYED ENGINE** | 0.872 |",
         "| **XGBoost — DEPLOYED ENGINE** | 0.933 |",
         "0.933"),
        # MAJOR 3's second half: the eval-side headline relabelled as the engine.
        ("| **Fused TGN+XGBoost — EVAL-SIDE** |",
         "| **Fused TGN+XGBoost — shipped engine** |",
         "fused"),
        # MINOR 5: the pin that was claimed and did not exist.
        ("| model — where it runs | AUROC | lead (horizon-0) | episodes |",
         "| model — where it runs | AUROC | median lead | episodes |",
         LEAD_HEADER_MARK),
    ],
    ids=["auroc-onto-the-wrong-row", "eval-side-row-called-the-engine",
         "horizon-0-deleted-from-the-header"],
)
def test_the_table_edits_that_used_to_build_clean_now_fail(tmp_path, old, new, expected):
    """Every one of these is a one-line edit to `docs/slides.md` that shipped.

    They are run through the WHOLE builder -- parse, render, save, reopen -- and
    not through `results_problems` alone, because the defect was never the
    function: it was that nothing called one.
    """
    markdown = source_text()
    assert old in markdown, f"the deck no longer contains {old!r} to doctor"
    with pytest.raises(SystemExit) as exc:
        build_to(tmp_path / "a", markdown.replace(old, new, 1))
    assert expected in str(exc.value), str(exc.value)


@requires_pptx
def test_the_largest_text_in_the_results_table_is_the_deployed_row(tmp_path):
    """BLOCKER 2's complaint was about SIZE, so size is what is checked.

    The largest text on slide 3 used to be `Fused ... 0.933`, an eval-side number
    in 18 pt. Emphasis is a claim: the biggest row is the one a judge's demo
    produces. Falsifiable by putting the emphasis back on the first row -- the
    fused row's runs then exceed the deployed row's and this fails.
    """
    from pptx import Presentation

    out = build_to(tmp_path / "a", source_text())
    deck = Presentation(str(out))
    table = next(s for s in list(deck.slides)[2].shapes if getattr(s, "has_table", False))

    sizes: dict[str, float] = {}
    for row in list(table.table.rows)[1:]:
        cells = list(row.cells)
        key = model_key(cells[0].text_frame.text)
        points = [run.font.size.pt
                  for cell in cells
                  for para in cell.text_frame.paragraphs
                  for run in para.runs
                  if run.font.size is not None]
        if key and points:
            sizes[key] = max(points)

    deployed = facts().deployed_key
    assert deployed in sizes, sizes
    assert sizes[deployed] == max(sizes.values()), (
        f"the largest type in the results table is not the {deployed!r} row: {sizes}. "
        "The row a judge's demo produces has to be the one that reads largest."
    )
    assert sizes[deployed] > sizes["fused"], (
        "the fused eval-side headline is set as large as the deployed row, which is "
        f"how 0.933 became the biggest number on the deck: {sizes}"
    )
