"""Render `docs/slides.md` into the 5-slide .pptx the PS asks for (deliverable 10).

    C:/sih26/.venv/Scripts/python.exe scripts/build_deck.py

python-pptx is a **build-time** tool, exactly like python-markdown and pypdf in
`scripts/build_architecture_pdf.py`. Nothing under `engine/`, `models/`, `eval/`,
`app/`, `data/` or `ledger/` imports it, the demo does not need it, and it must
NOT be added to `requirements.txt` / `environment.lock.yml` — adding it there
would put a document-authoring dependency into the air-gapped inference
environment for no reason. Install it on the build machine:

    C:/sih26/.venv/Scripts/python.exe -m pip install python-pptx

WHY A BUILDER AND NOT A HAND-MADE .pptx
---------------------------------------
Every number on these slides is load-bearing and was corrected over three audit
rounds. A hand-edited binary is a second copy of those numbers that nothing can
diff, and the project's recurring failure mode is exactly that: a figure written
rather than measured, a claim that outruns the code. So `docs/slides.md` stays
the single source and this script is the only way the .pptx is produced. Edit the
markdown; rebuild.

MARKER GRAMMAR
--------------
Markers are HTML comments, so they are invisible wherever the markdown renders.
A marker sits on its own line and claims the next block. An unmarked block
becomes that slide's **speaker notes** — that is how the full prose survives
onto a slide that has to be legible from the back of a room.

    <!-- deck:kicker -->          next paragraph -> small accent line above the title
    <!-- deck:headline -->        next paragraph -> the one large statement
    <!-- deck:pipeline -->        next fenced block -> chevron chain, split on the arrows
    <!-- deck:lane STYLE|CAP -->  next fenced block -> a CAPTIONED chevron chain in one of
                                  two visually distinct styles: `deployed` (solid, inked)
                                  or `evaluation` (dashed, muted). See ARCHITECTURE LANES.
    <!-- deck:table -->           next markdown table -> large table; a 0-1 column gets bars
    <!-- deck:points -->          next list -> the slide's bullets
    <!-- deck:chips LABEL -->     next list -> compact labelled cards
    <!-- deck:band LABEL -->      next paragraph -> the stated-limitation band
    <!-- deck:figure NAME -->     embed <img-dir>/NAME.png|jpg|svg, else a marked slot

`deck:figure` takes its target from the label and claims no block. `docs/img/`
holds SVGs, which python-pptx cannot embed, so an SVG is rasterised through the
same headless Edge `scripts/build_architecture_pdf.py` uses — offline, and on
Windows 11 already present. No figure marker appears in `docs/slides.md` today:
the three figures in `docs/img/` are page-scale diagrams (1180x470 to 1180x620),
and at the ~3in of slide height any of the five slides could spare they render
about 7.5in wide with body text far too small to read from the back of a room.
Giving one a slide of its own would breach the PS's five-slide cap. That is a
judgement about those figures at that size, not a missing capability.

WHAT THIS REFUSES TO BUILD
--------------------------
Three passes, in this order, because the later ones cannot see what the earlier
ones catch:

1. `check_source` — `docs/slides.md` against `docs/limitations.md`, before
   anything is painted. It runs first because a limitations list that has gained
   or lost an item also overflows slide 5, and a height is not the useful
   failure to report about it.
2. `render` — layout, on the slides as painted. Overflow past
   `CONTENT_BOTTOM_IN` and more than `MAX_ON_SLIDE_WORDS` on-slide words are
   **collected and reported together**; raising on the first one made the word
   cap unreachable in practice, since pasted prose runs off the bottom before it
   passes 160 words.
3. `verify` — the **saved file, reopened**, so the checks fail on what a judge
   would actually open rather than on the builder's own model. Reachable on its
   own with `--verify-only`, for a .pptx this run did not write.

What `verify` refuses:

  * more than `MAX_SLIDES` slides (the PS caps the deck at five);
  * a slide with no content;
  * any run below `MIN_ANY_PT`, or any content run below `MIN_CONTENT_PT`;
  * a slide missing one of the phrases `REQUIRED_ON_SLIDE` pins to **that
    slide by number**. Deck-wide substring matching is not enough: it let the
    whole chance-baseline band move off slide 3 onto slide 1, two slides from
    the table it qualifies, with the build still passing. Speaker notes never
    count — nobody projects them;
  * a limitations slide whose items do not match `docs/limitations.md` section
    for section, by content (`LIMITATION_TOPICS`), in the document's order. The
    old check counted to five, and the deck had already drifted straight through
    it: five items, one of them a limitation the document does not carry.
  * an architecture slide that does not draw TWO lanes, or that puts an
    evaluation-only component in the deployed one (`lane_problems`);
  * a results row whose AUROC / lead / episodes are not the figures
    `docs/architecture.md` §4 measured FOR THAT MODEL, or whose model cell does
    not say which lane it belongs to (`results_problems`);
  * any on-slide run matching a `BANNED_ON_SLIDE` claim -- a contradiction the
    presence checks above structurally cannot see.

ARCHITECTURE LANES, AND WHY THE SLIDE IS DRAWN TWICE
---------------------------------------------------
`docs/architecture.md` §2: the one 30-feature matrix feeds TWO lanes. The
DEPLOYED lane is the XGBoost scorer, its threshold, TreeSHAP and the ledger. The
EVALUATION-ONLY lane is TGN, GRAFT, the k-step head and the rank-mean fusion --
"none of it runs in the engine", in that document's own words. Slide 2 used to
draw one solid chain straight through TGN and GRAFT into the engine, with
XGBoost -- the only model in the scoring path -- named nowhere on the slide. A
judge reading it learned a pipeline the product does not have.

So the slide draws both lanes, in styles a reader separates at a glance, and
`lane_problems` binds them to the document rather than to this file's opinion:
each token in `DEPLOYED_LANE_TOKENS` / `EVAL_ONLY_LANE_TOKENS` must appear in
`docs/architecture.md`'s own sentence about that lane (`read_lane_split`) AND on
the matching lane of the saved deck; every evaluation-only token must ALSO be
absent from the deployed lane, because the way this slide broke was by merging
the two chains, not by losing a word. The dash style is checked too: the
evaluation lane's chevrons must really be dashed in the file a judge opens.

WHY EVERY FIGURE IN THE RESULTS TABLE IS BOUND TO ITS MODEL
-----------------------------------------------------------
`REQUIRED_ON_SLIDE` proves a string is present. It cannot see that the string is
attached to the wrong row. A verifier changed the XGBoost row's AUROC to the
fused headline's 0.933 -- the audit's own named example of this project's
recurring overclaim -- and the build passed, shipping two rows both reading
0.933. `results_problems` closes that: every row of slide 3's table is resolved
to a model key (`MODEL_KEYS`), looked up in the table of `docs/architecture.md`
§4, and its AUROC, median lead and episode count must be the figures measured
FOR THAT MODEL. The numbers are read from the document on every build, so this
file never asserts a measurement of its own.

The same function pins the lane label: exactly one row -- the one whose key is
`DEPLOYED_ROW_KEY`, itself read out of `docs/architecture.md` §3's "deployed
scorer" sentence -- may carry `DEPLOYED_MARKER`, and every other row must carry
`EVAL_MARKER`. Relabelling the fused row "shipped engine" therefore fails twice:
once here, and once in `BANNED_ON_SLIDE`.

Determinism: the same markdown produces a byte-identical .pptx — verify with
`sha256sum` across two builds. Core properties are pinned and the zip is rewritten
with a fixed member timestamp, because `zipfile` otherwise stamps the current time
into every entry. The one exception is a rasterised SVG, whose bytes come from the
installed Edge and therefore track its renderer version; the deck as shipped
embeds no raster, so it is byte-identical.

Offline: no network call, no font download. Font names are written into the file;
`FONT` and `FONT_MONO` ship with Windows 11, and PowerPoint substitutes if a
machine lacks them, which changes appearance only.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import math
import re
import subprocess
import sys
import tempfile
import time
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

# ---------------------------------------------------------------- constraints

MAX_SLIDES = 5                 # PS deliverable 10: "technical presentation (max 5 slides)"

# Derived, not chosen to fit what happens to be written today. The content box is
# BODY_W_IN wide and about 5.5in tall; at PT_POINTS a line holds ~98 characters
# (~16 words) and ~18 lines fit, so a slide packed solid with body text carries
# ~290 words. The cap is ~55% of that: dense is allowed, prose is not. The
# overflow check below is the tighter constraint in practice — this one is the
# blunt rule that still bites when someone shrinks nothing and pastes a paragraph.
MAX_ON_SLIDE_WORDS = 160
MIN_ANY_PT = 11.0              # the footer, and nothing smaller
MIN_CONTENT_PT = 14.0          # anything a judge has to read from the back of the room

# Phrases that must appear in the text of ONE NAMED SLIDE. Each is a disclosure a
# previous audit round put there on purpose, and each sits on the slide that
# carries the claim it qualifies. Per-slide, not deck-wide: an earlier version
# joined all five slides into one string and substring-matched, so the whole
# chance-baseline band could be moved off slide 3 — away from the 0.933 / 2-2
# table it qualifies — onto slide 1 and the build still passed. A disclosure two
# slides from its claim is not a disclosure. Matched case-insensitively after
# markdown stripping and whitespace normalisation, so a phrase must survive
# inside ONE run: do not let a `**bold**` boundary fall in the middle of one.
REQUIRED_ON_SLIDE: tuple[tuple[int, str, str], ...] = (
    (
        1,
        "0 of 2 episodes at k = 1, 4 and 8",
        "the k-step disclosure, on the slide that claims forecasting at t+k. At the "
        "shipped 1 % FPR budget the forecast head fires on no episode at any horizon "
        "we report, so there is no supported forward operating point. Slide 1 makes "
        "the t+k claim; the correction belongs beside it, not in the speaker notes, "
        "which nobody projects.",
    ),
    (
        1,
        "horizon-0",
        "what actually produces the lead time this deck claims. Without it slide 1 "
        "says 'forecast at t+k' and slide 3 shows a lead-time column, and a judge "
        "joins the two into a forward-forecasting claim the measurements do not "
        "support.",
    ),
    (
        2,
        "ranking only",
        "the qualification on the architecture chain's k-step forecast head. "
        "Unqualified, that chevron presents the forecast head as a shipped "
        "pipeline stage with a working operating point; measured, it ranks "
        "(AUROC 0.844 at k=4) and fires on nothing at the 1 % budget.",
    ),
    (
        2,
        "xgboost scorer",
        "the deployed model, named on the architecture slide. The slide drew one "
        "solid chain through TGN and GRAFT into the engine and named XGBoost "
        "nowhere, so a judge learned a pipeline the product does not have. "
        "`lane_problems` checks the chevron it sits in; this checks that the words "
        "reach the projected slide at all.",
    ),
    (
        2,
        "evaluation-only",
        "the caption on the lower lane. Two chains drawn in two styles still need "
        "the words: dashed means nothing to a judge who has not been told what the "
        "dashes are for, and TGN / GRAFT / the fusion are the components that do "
        "not run in the engine.",
    ),
    (
        3,
        "matched-budget random baseline",
        "slide 3's chance-baseline disclosure: at this alert budget the lead-time "
        "column does not separate from matched-budget uniform noise. Without it the "
        "lead-time column reads as a result rather than as evidence that the budget "
        "is generous.",
    ),
    (
        3,
        "n = 2 episodes",
        "the sample size the headline rests on. A judge who sees 0.933 and 2/2 must "
        "see n = 2 on the same slide.",
    ),
    (
        3,
        "AUROC is where the model earns its place",
        "the honest reading of the results table, given the line above it.",
    ),
    (
        3,
        "the lead column is horizon-0, not a t+k forecast",
        "the attribution, on the slide that prints the number. The 4195 s median lead "
        "and 2/2 episodes come from the horizon-0 classifier; the k-step head "
        "produces neither. The band says it in a sentence, because a parenthesis "
        "alone is deniable -- and `results_problems` pins the parenthesis in the "
        "column header as well, because a sentence on its own is one edit from "
        "being the only copy.",
    ),
    (
        3,
        "eval-side",
        "the marker on the fused row, in the table rather than in 547 words of "
        "speaker notes nobody projects. 0.933 is an EVALUATION-side result: "
        "engine/predict.py loads one booster, so the demo a judge runs is the "
        "XGBoost row. `results_problems` binds this marker to that row; this keeps "
        "the words on the projected slide.",
    ),
    (
        3,
        "deployed engine",
        "the other half of the same correction: the row a judge's demo actually is. "
        "Marking the fused row eval-side while leaving the deployed row unnamed "
        "still leaves a reader to guess which of five rows they are about to run.",
    ),
    (
        3,
        "What is actually new here",
        "the contribution box. The caveats are about the numbers; without this header "
        "the slide argues against itself and names no contribution.",
    ),
    (
        3,
        "0.573",
        "the graded logistic-regression baseline. A results slide without the "
        "baseline row is not a comparison.",
    ),
    (
        4,
        "publishing the anchor line",
        "the ledger limitation we disclose rather than hide: chain + checkpoint log "
        "truncated together cannot be caught from inside those two files.",
    ),
)

# ------------------------------------------------------- the limitations slide
#
# Slide 5 is `docs/limitations.md` compressed, and its title tells the judge to
# go read that document. So the slide's numbered five must BE that document's
# numbered five — otherwise the pointer is itself a small untruth, which is the
# failure mode this project keeps being caught by.
#
# It had already drifted: the document's §5 is the IPv4-only parser, the deck's
# item 5 was "an adaptive attacker defeats several mandated packet features at
# zero cost", and the old guard passed because it COUNTED items instead of
# binding them. Both are real limitations. The judgement, and why:
#
#   * the deck follows the document, so item 5 is now the IPv4-only parser. An
#     IPv6-only capture yields zero features, zero forecasts and zero alerts —
#     "0 alerts" that means "blind" is the worst failure mode a security tool
#     has, and it changes what the system can be RUN on;
#   * the adaptive-attacker limitation is not dropped. It keeps a clause in
#     slide 5's band and the full measured analysis in the speaker notes and
#     `docs/threat_model.md`. It is not numbered here because it is not numbered
#     THERE — docs/limitations.md does not carry it at all, and inventing a sixth
#     number on the slide is how the two lists diverged in the first place.
#
# The binding is two-sided. Each topic key below must appear BOTH in
# docs/limitations.md's own heading for that section AND in the deck's item at
# the same position. A key is therefore not a free-floating string this file
# asserts about itself: if the document renumbers, replaces or reorders a
# section, the key stops matching the heading and the build fails there too.
LIMITATIONS_DOC = REPO / "docs" / "limitations.md"
LIMITATION_HEADING = re.compile(r"^##\s+(?P<n>\d+)\.\s+(?P<title>.+?)\s*$")
LIMITATION_TOPICS: tuple[tuple[str, ...], ...] = (
    ("kill-chain", "stages"),
    ("four attack days", "splits"),
    ("csv", "packet"),
    ("world model", "rssm"),
    ("ipv4", "ipv6"),
)
LIMITATION_COUNT = len(LIMITATION_TOPICS)

# ------------------------------------------------------- the architecture slide
#
# Slide 2 is `docs/architecture.md` §2 compressed, and §2 is explicit that the
# feature matrix feeds TWO lanes. Everything below is a NAME, never a number:
# the names are checked against that document's own sentences on every build
# (`read_lane_split`), so a rename there fails here instead of leaving the deck
# quietly describing a pipeline the repository no longer has.
ARCHITECTURE_DOC = REPO / "docs" / "architecture.md"

LANE_STYLES = ("deployed", "evaluation")
# The sentence in docs/architecture.md that describes each lane is found by these
# phrases. They are the document's own wording for the split.
LANE_SENTENCE_MARK = {"deployed": "deployed lane", "evaluation": "evaluation-only lane"}
# What each lane's own CAPTION has to say, checked on the caption shape and not
# deck-wide. REQUIRED_ON_SLIDE alone was not enough: slide 2's headline also says
# "evaluation-only", so rewording the dashed lane's caption to "RESEARCH TRACK"
# left the phrase on the slide and the build passed — with the one lane a judge
# must not mistake for the product no longer saying what it is.
LANE_CAPTION_MARK = {"deployed": "deployed", "evaluation": "evaluation-only"}
# Components that must be IN the lane named, lower-cased. The deployed tokens are
# presence-only; the evaluation tokens are presence AND absence, because slide 2
# broke by merging the two chains into one, not by losing a word from either.
DEPLOYED_LANE_TOKENS = ("xgboost",)
EVAL_ONLY_LANE_TOKENS = ("tgn", "graft", "rank-mean")

# ------------------------------------------------------------ the results table
#
# Every figure on slide 3 is looked up in the table of `docs/architecture.md` §4
# BY MODEL, because the defect this replaces was not a wrong number — it was the
# right number on the wrong row. A verifier gave the deployed XGBoost row the
# fused headline's 0.933 and the build passed, shipping two rows both reading
# 0.933: exactly the overclaim the audit named. Nothing here is a measurement
# this file states; the values are read from the document every build.
#
# Keys are tried IN ORDER and the first that matches wins, so "Fused (rank-mean
# TGN+XGB)" resolves to `fused` rather than to `tgn` or `xgboost`.
RESULTS_DOC = ARCHITECTURE_DOC
MODEL_KEYS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("fused", re.compile(r"\bfus(?:ed|ion)\b")),
    ("xgboost", re.compile(r"\bxgb(?:oost)?\b")),
    ("tgn", re.compile(r"\btgn\b")),
    ("graft", re.compile(r"\bgraft\b")),
    ("logistic", re.compile(r"\b(?:logistic|lr)\b")),
)
# Column headers are matched by keyword so the deck and the document may word
# them differently; each maps to how the two sides are compared.
RESULTS_COLUMNS: tuple[tuple[str, str], ...] = (
    ("auroc", "exact"),        # "0.933" == "0.933"
    ("lead", "leading-number"),  # "4195 s (~70 min)" == "4195 s"
    ("episodes", "exact"),     # "2/2" == "2/2"
)
# The lead column must carry the attribution in its own header. The band on the
# same slide says it in a sentence; a verifier deleted the header parenthesis and
# the build passed, so the report that claimed "two pins" had one.
LEAD_HEADER_MARK = "horizon-0"
# Which row is the shipped one is NOT decided here: DEPLOYED_ROW_KEY is the model
# key whose token appears in docs/architecture.md §3's "deployed scorer" sentence
# (`read_deployed_row_key`). These two markers are the labels the slide prints.
DEPLOYED_SCORER_MARK = "deployed scorer"
DEPLOYED_MARKER = "deployed engine"
EVAL_MARKER = "eval-side"

# --------------------------------------------------- contradictions, not absences
#
# The whole REQUIRED_ON_SLIDE family proves a disclosure is PRESENT. Nothing in
# it can see a claim that contradicts one, so an ADDITIVE overclaim shipped: a
# verifier put "forward forecasts validated at k = 4 and 8" into slide 3's
# kicker and the build passed, producing a deck that says "fires on 0 of 2
# episodes at k = 1, 4 and 8" on slide 1 and "forward forecasts validated" on
# slide 3. Both disclosures were still present. The deck still lied.
#
# SCOPE, stated: each claim is matched against ONE RUN OF TEXT AT A TIME — a
# paragraph of a textbox, a chevron, a single table cell — never against the
# slide's runs joined together. Joining them manufactures adjacencies that are
# not on the slide (the fused row's model cell and the XGBoost row's, four cells
# apart, would read as one sentence) and the patterns would have to be loosened
# until they caught nothing. The consequence is honest and worth stating: a
# phrase split across two shapes is not caught here. The break this exists to
# catch is a contributor rewriting one line.
#
# `retired` is the other half. Without sentences the patterns MUST catch, a
# future contributor silences a failure by loosening a regex and the check
# quietly releases; tests/test_build_deck.py asserts every one of them matches.


@dataclass(frozen=True)
class BannedOnSlide:
    slug: str
    why: str
    patterns: tuple[re.Pattern[str], ...]
    retired: tuple[str, ...]


def _rx(*patterns: str) -> tuple[re.Pattern[str], ...]:
    return tuple(re.compile(p, re.IGNORECASE) for p in patterns)


# "this has been shown to work", in every form a contributor actually writes.
_VERBS = (r"\b(?:validat(?:e|es|ed)|demonstrat(?:e|es|ed)|prov(?:e|es|ed|en)"
          r"|confirm(?:s|ed)?|establish(?:es|ed)?)\b")
# "this is what we run in production", likewise.
_SHIPS = (r"\b(?:ship|ships|shipped|shipping|deploy|deploys|deployed"
          r"|in production|engine row|live demo)\b")


BANNED_ON_SLIDE: tuple[BannedOnSlide, ...] = (
    BannedOnSlide(
        slug="forward-forecasting-is-validated",
        why=(
            "Forward forecasting has NO supported operating point: at the shipped 1 % "
            "FPR budget the k-step head fires on 0 of 2 episodes at k = 1, 4 AND 8, "
            "and the oracle-threshold analysis says that is a ranking limit, not a "
            "threshold anyone forgot to retune. What is measured is a ranking signal "
            "(test AUROC 0.844 at k=4, 0.842 at k=8) whose target is 93-96 % identical "
            "to the nowcast target. Slide 1 states this; a slide that also calls "
            "forward forecasting validated does not retract it, it contradicts it."
        ),
        # The verb list covers the base form too: the first draft banned
        # "demonstrated" and not "demonstrate", which a contributor reaches by
        # writing "we demonstrate forecasting 40 s ahead" without trying.
        patterns=_rx(
            r"\bforecast(?:s|ing|ed)?\b[^.]{0,60}" + _VERBS,
            _VERBS + r"[^.]{0,60}\bforecast(?:s|ing|ed)?\b",
            r"\bforward\b[^.]{0,30}\bsupported\b",
            r"\bsupported\b[^.]{0,30}\bforward\b",
        ),
        retired=(
            "forward forecasts validated at k = 4 and 8",
            "we demonstrate forecasting 40 s ahead",
            "k-step forecasting is proven at k = 8",
            "forward operation is supported at the 1 % budget",
        ),
    ),
    BannedOnSlide(
        slug="fused-headline-is-the-engine",
        why=(
            "The 0.933 fused headline is an EVAL-SIDE result. engine/predict.py loads "
            "ONE booster and calls predict_proba once, so the demo a judge runs is the "
            "XGBoost row (test AUROC 0.872). docs/architecture.md §3 says the same in "
            "as many words. Attaching the fused row to the engine -- 'shipped', "
            "'deployed', 'in production' -- is the single largest overclaim this deck "
            "can make, and it is the one the previous round was opened to fix."
        ),
        # "ships" as well as "shipped": the deck's own slide-2 title says "only
        # one of them ships", which is how a contributor reaches for the word.
        patterns=_rx(
            r"\bfus(?:ed|ion)\b[^.]{0,60}" + _SHIPS,
            _SHIPS + r"[^.]{0,60}\bfus(?:ed|ion)\b",
            r"0\.933[^.]{0,60}(?:" + _SHIPS + r"|\bengine\b)",
            r"\b(?:engine|demo)\b[^.]{0,40}0\.933",
        ),
        retired=(
            "Fused (TGN + XGBoost, rank-mean) — shipped engine",
            "the shipped engine scores 0.933",
            "the deployed scorer is the fused rank-mean model",
            "the engine a judge runs reaches 0.933 AUROC",
            "the rank-mean fusion ships with the engine",
        ),
    ),
)

# ------------------------------------------------------------------- appearance

FONT = "Segoe UI"
FONT_MONO = "Consolas"

INK = (0x10, 0x1A, 0x28)
ACCENT = (0x1A, 0x6F, 0xAF)        # matches scripts/build_architecture_pdf.py
ACCENT_DEEP = (0x0E, 0x3A, 0x5C)
MUTED = (0x55, 0x62, 0x72)
PAPER = (0xFF, 0xFF, 0xFF)
PANEL = (0xEE, 0xF3, 0xF8)
RULE = (0xCE, 0xDA, 0xE6)
BAND_FILL = (0xFD, 0xF3, 0xE0)     # warm: "this is a stated limitation", not a result
BAND_EDGE = (0xC1, 0x7A, 0x1E)
BAND_INK = (0x6B, 0x40, 0x0A)
BAR = (0x9C, 0xC4, 0xE4)
BAR_TRACK = (0xE6, 0xEC, 0xF2)

SLIDE_W_IN = 13.333
SLIDE_H_IN = 7.5
MARGIN_IN = 0.62
BODY_W_IN = SLIDE_W_IN - 2 * MARGIN_IN
FOOTER_TOP_IN = 6.94
CONTENT_BOTTOM_IN = 6.84       # anything below this is an overflow, not a layout

PT_TITLE = 31.0
PT_KICKER = 14.5
PT_HEADLINE = 23.0
PT_POINTS = 17.0
PT_CHIP = 15.0
PT_CHIP_LABEL = 14.0
PT_TABLE_HEAD = 14.0
PT_TABLE_BODY = 17.0
PT_TABLE_LEAD = 18.0           # the fused row
PT_PIPE = 14.0
PT_LANE_LABEL = 14.0
PT_BAND = 15.0
PT_BAND_LABEL = 14.0
PT_FOOTER = 11.0

# Width of a character as a fraction of the font size, used only to size table
# columns so nothing wraps. Segoe UI mixed-case measures ~0.50; these are rounded
# up, and bold further up, because over-estimating costs whitespace while
# under-estimating costs a wrapped cell (see _column_widths).
TABLE_CHAR_REGULAR = 0.53
TABLE_CHAR_BOLD = 0.60
TABLE_CELL_PAD_IN = 0.20       # cell.margin_left + cell.margin_right
BAR_COL_W_IN = 2.00

# A chevron is not a rectangle. PowerPoint's default adjustment insets the arrow
# by half the shape's HEIGHT at each end, so a 2.34in chevron 0.92in tall holds
# text across about 1.88in, not 2.34in. Nothing measured that until a lane put
# five chevrons on one row, and a chevron whose text runs past its own outline is
# unreadable in exactly the place this deck is read from — the back of a room.
CHEVRON_ARROW_ADJ = 0.5
CHEVRON_MARGIN_IN = 0.13       # frame.margin_left, and again on the right

# Pinned so the output is byte-identical across builds (see module docstring).
FIXED_TIME = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc).replace(tzinfo=None)
ZIP_EPOCH = (1980, 1, 1, 0, 0, 0)

# Stamped into the saved package so a committed deck can be told from a stale
# one without rebuilding it. `--verify-only` checks a binary against the
# constraints, and a deck built from LAST week's slides.md still satisfies every
# one of them — it is simply not the deck the markdown now describes, which on
# this project is the whole failure mode: the fix lands in the source and the
# thing a judge opens still shows what was fixed. The bindings to
# docs/limitations.md and docs/architecture.md need no digest, because `verify`
# re-reads those documents live on every run.
SOURCE_DIGEST_KEY = "sih26-deck-source-sha256"

DECK_TITLE = "AI-based Network Attack Forecasting from Network Traffic Data"
FOOTER_LEFT = "SIH26153 · NTRO · built from docs/slides.md by scripts/build_deck.py"

# --------------------------------------------------------------------- parsing

MARKER = re.compile(r"^<!--\s*deck:(?P<kind>[a-z]+)\s*(?P<label>.*?)\s*-->\s*$")
SLIDE_HEAD = re.compile(r"^##\s+Slide\s+(?P<n>\d+)\s*[—-]\s*(?P<title>.+?)\s*$")
# Markers that carry their whole content in the label and claim no following
# block. Everything else claims the next block of markdown.
STANDALONE = frozenset({"figure"})

LIST_ITEM = re.compile(r"^\s*(?:[-*]\s+|\d+[.)]\s+)")
ORDERED_ITEM = re.compile(r"^\s*(\d+)[.)]\s+")
INLINE = re.compile(r"(\*\*.+?\*\*|`[^`]+`|\*[^*\n]+?\*)")


@dataclass(frozen=True)
class Block:
    """One marked block of slide content, or an unmarked block bound for the notes."""

    kind: str          # kicker | headline | pipeline | table | points | chips | band | notes
    label: str         # the marker's trailing text, where it carries one
    lines: tuple[str, ...]


@dataclass
class Slide:
    number: int
    title: str
    blocks: list[Block] = field(default_factory=list)

    @property
    def on_slide(self) -> list[Block]:
        return [b for b in self.blocks if b.kind != "notes"]

    @property
    def notes(self) -> str:
        chunks = ["\n".join(b.lines).strip() for b in self.blocks if b.kind == "notes"]
        return "\n\n".join(c for c in chunks if c)


def parse_slides(markdown: str) -> list[Slide]:
    """Split the document on `## Slide N — title` and bind each block to its marker.

    Deliberately small: markers claim the next block, everything else falls to the
    notes. A marker that claims nothing is an authoring mistake and raises rather
    than silently producing an empty slot.

    A pending marker survives blank lines. An earlier version cleared it on every
    flush, so `<!-- deck:figure lead_time -->` followed by a blank line was
    discarded without a word — the docstring promised a loud failure and the code
    delivered a missing slot. Markers that take no block (STANDALONE) are emitted
    where they are written instead of waiting for content that never comes.
    """
    slides: list[Slide] = []
    current: Slide | None = None
    pending: tuple[str, str] | None = None
    buffer: list[str] = []
    in_fence = False

    def flush() -> None:
        nonlocal buffer, pending
        body = [ln for ln in buffer]
        while body and not body[-1].strip():
            body.pop()
        buffer = []
        if not body:
            return                     # blank lines must not consume a pending marker
        if current is None:
            if pending:
                raise SystemExit(f"deck marker {pending[0]!r} appears outside any slide")
            return
        kind, label = pending if pending else ("notes", "")
        current.blocks.append(Block(kind, label, tuple(body)))
        pending = None

    for raw in markdown.splitlines():
        if raw.strip().startswith("```"):
            in_fence = not in_fence
            buffer.append(raw)
            if not in_fence:          # a fenced block is one block, always
                flush()
            continue
        if in_fence:
            buffer.append(raw)
            continue

        head = SLIDE_HEAD.match(raw)
        if head:
            flush()
            current = Slide(number=int(head.group("n")), title=head.group("title"))
            slides.append(current)
            continue

        marked = MARKER.match(raw)
        if marked:
            flush()
            kind, label = marked.group("kind"), marked.group("label")
            if kind in STANDALONE:
                if current is None:
                    raise SystemExit(f"deck marker {kind!r} appears outside any slide")
                if not label:
                    raise SystemExit(
                        f"<!-- deck:{kind} --> needs a name: <!-- deck:{kind} NAME -->"
                    )
                current.blocks.append(Block(kind, label, ()))
                continue
            if pending:
                raise SystemExit(
                    f"deck marker {pending[0]!r} is replaced by {kind!r} before it "
                    "claims anything. Put content under the first marker, or delete it."
                )
            pending = (kind, label)
            continue

        if not raw.strip():
            flush()
            continue

        # A list must not be glued to the paragraph above it by a missing blank line.
        if buffer and LIST_ITEM.match(raw) and not LIST_ITEM.match(buffer[0]):
            flush()
        buffer.append(raw)

    flush()
    if pending:
        raise SystemExit(
            f"deck marker {pending[0]!r} claims no block — put the content directly under it"
        )
    return slides


def list_is_ordered(lines: tuple[str, ...]) -> bool:
    """True for `1.`-style lists. docs/limitations.md numbers its five items and a
    judge cross-references them by number, so the deck must not turn them into
    anonymous bullets."""
    return any(ORDERED_ITEM.match(line) for line in lines)


def list_items(lines: tuple[str, ...]) -> list[str]:
    """Markdown list -> one string per item, continuation lines folded in."""
    items: list[str] = []
    for line in lines:
        if LIST_ITEM.match(line):
            items.append(LIST_ITEM.sub("", line).strip())
        elif items and line.strip():
            items[-1] += " " + line.strip()
    return items


def table_rows(lines: tuple[str, ...]) -> list[list[str]]:
    """Markdown pipe table -> rows of cells, separator row dropped."""
    rows = []
    for line in lines:
        stripped = line.strip()
        if not stripped.startswith("|"):
            continue
        cells = [c.strip() for c in stripped.strip("|").split("|")]
        if all(set(c) <= set("-: ") and c for c in cells):
            continue
        rows.append(cells)
    return rows


def pipeline_stages(lines: tuple[str, ...]) -> list[str]:
    """Fenced arrow diagram -> the stage labels, in order."""
    body = [ln for ln in lines if not ln.strip().startswith("```")]
    joined = " ".join(ln.strip() for ln in body)
    return [s.strip() for s in joined.split("→") if s.strip()]


def plain(text: str) -> str:
    """Markdown inline markup stripped, for word counts and width estimates."""
    return re.sub(r"[*`]", "", text)


def normalise(text: str) -> str:
    """The one form the source markdown and the .pptx runs both reduce to.

    Content checks compare a phrase against text that has been through two very
    different paths — straight off `docs/slides.md`, or read back out of the saved
    package where `**bold**` has become a separate run and the runs are re-joined
    with spaces. Lowercasing, stripping markdown and collapsing whitespace is what
    makes those two comparable; nothing else about the text is touched.
    """
    return re.sub(r"\s+", " ", plain(text)).strip().lower()


# ------------------------------------------------------------------- rendering


def _import_pptx():
    try:
        import pptx  # noqa: F401
    except ModuleNotFoundError:
        raise SystemExit(
            "python-pptx is not installed. It is a BUILD-time tool (see this "
            "script's docstring) and is deliberately absent from requirements.txt:\n"
            "    python -m pip install python-pptx"
        )
    return pptx


def _wrapped_line_count(text: str, size_pt: float, width_in: float) -> int:
    """Conservative line count for a run of text in a box of this width.

    Over-estimating is the safe direction: it pushes content down and trips the
    overflow check early, which is a build failure a human fixes, rather than
    text running off the bottom of a slide nobody rebuilt.
    """
    per_line = max(8, int((width_in * 72.0) / (0.52 * size_pt)))
    total = 0
    for para in plain(text).split("\n"):
        words = para.split()
        if not words:
            total += 1
            continue
        used, lines = 0, 1
        for word in words:
            need = len(word) + (1 if used else 0)
            if used and used + need > per_line:
                lines += 1
                used = len(word)
            else:
                used += need
        total += lines
    return total


def _height_in(text: str, size_pt: float, width_in: float, leading: float = 1.26) -> float:
    return _wrapped_line_count(text, size_pt, width_in) * size_pt * leading / 72.0


def _chevron_overflow(stages: list[str], width: float, height: float,
                      size_pt: float = PT_PIPE) -> list[str]:
    """Which chevrons hold more text than their own outline. See CHEVRON_ARROW_ADJ.

    Reported, never squeezed: shrinking the type is how a deck stops being
    readable from the back of a room, and silently letting the text run past the
    arrow is how it stops being readable at all.
    """
    usable = width - CHEVRON_ARROW_ADJ * height - 2 * CHEVRON_MARGIN_IN
    capacity = int(height / (size_pt * 1.26 / 72.0))
    problems = []
    for stage in stages:
        if usable <= 0 or capacity < 1:
            problems.append(
                f"a chevron {width:.2f}in wide and {height:.2f}in tall holds no text "
                "at all once the arrow is taken out. Use fewer stages."
            )
            break
        lines = _wrapped_line_count(stage, size_pt, usable)
        if lines > capacity:
            problems.append(
                f"the chevron {plain(stage)!r} needs {lines} lines of {usable:.2f}in "
                f"and only {capacity} fit in {height:.2f}in. Shorten it, or split the "
                "chain into fewer stages — the text would otherwise run past the "
                "chevron's own outline."
            )
    return problems


class Painter:
    """A vertical cursor over one slide. Every renderer returns the new cursor."""

    def __init__(self, slide, number: int, total: int):
        from pptx.util import Inches, Pt

        self._Inches = Inches
        self._Pt = Pt
        self.slide = slide
        self.number = number
        self.total = total
        self.y = 0.0
        self.words = 0

    # -- primitives ---------------------------------------------------------

    def _rgb(self, triple):
        from pptx.dml.color import RGBColor

        return RGBColor(*triple)

    def _runs(self, paragraph, text: str, size_pt: float, colour, bold_base=False):
        """Render inline `**bold**`, `*italic*` and `` `code` `` as real runs."""
        for token in INLINE.split(text):
            if not token:
                continue
            bold, italic, mono = bold_base, False, False
            if token.startswith("**") and token.endswith("**") and len(token) > 4:
                token, bold = token[2:-2], True
            elif token.startswith("`") and token.endswith("`") and len(token) > 2:
                token, mono = token[1:-1], True
            elif token.startswith("*") and token.endswith("*") and len(token) > 2:
                token, italic = token[1:-1], True
            run = paragraph.add_run()
            run.text = token
            run.font.size = self._Pt(size_pt)
            run.font.bold = bold
            run.font.italic = italic
            run.font.name = FONT_MONO if mono else FONT
            run.font.color.rgb = self._rgb(colour)

    def textbox(self, name: str, top: float, height: float, texts, size_pt: float,
                colour, left: float = MARGIN_IN, width: float = BODY_W_IN,
                space_after_pt: float = 0.0, hanging: float = 0.0, bold=False):
        from pptx.util import Inches, Pt

        box = self.slide.shapes.add_textbox(
            Inches(left), Inches(top), Inches(width), Inches(height)
        )
        box.name = name
        frame = box.text_frame
        frame.word_wrap = True
        frame.margin_left = frame.margin_right = 0
        frame.margin_top = frame.margin_bottom = 0
        for index, text in enumerate(texts):
            para = frame.paragraphs[0] if index == 0 else frame.add_paragraph()
            para.space_after = Pt(space_after_pt)
            if hanging:
                pPr = para._p.get_or_add_pPr()
                pPr.set("marL", str(Inches(hanging)))
                pPr.set("indent", str(-Inches(hanging)))
            self._runs(para, text, size_pt, colour, bold_base=bold)
            self.words += len(plain(text).split())
        return box

    def rect(self, name: str, left, top, width, height, fill, line=None,
             dashed=False, shape=None):
        from pptx.enum.shapes import MSO_SHAPE
        from pptx.util import Inches, Pt

        box = self.slide.shapes.add_shape(
            shape or MSO_SHAPE.RECTANGLE,
            Inches(left), Inches(top), Inches(width), Inches(height),
        )
        box.name = name
        box.shadow.inherit = False
        if fill is None:
            box.fill.background()
        else:
            box.fill.solid()
            box.fill.fore_color.rgb = self._rgb(fill)
        if line is None:
            box.line.fill.background()
        else:
            box.line.color.rgb = self._rgb(line)
            box.line.width = Pt(1.25)
            if dashed:
                from pptx.enum.dml import MSO_LINE_DASH_STYLE

                box.line.dash_style = MSO_LINE_DASH_STYLE.DASH
        box.text_frame.text = ""
        return box

    # -- slide furniture ----------------------------------------------------

    def chrome(self) -> None:
        """Paper, the accent rule, and the cursor at the top of the content box."""
        self.slide.background.fill.solid()
        self.slide.background.fill.fore_color.rgb = self._rgb(PAPER)
        self.rect("deck-accent", 0.0, 0.0, SLIDE_W_IN, 0.13, ACCENT)
        self.y = 0.40

    def title(self, text: str) -> None:
        height = _height_in(text, PT_TITLE, BODY_W_IN, leading=1.16)
        self.textbox("deck-title", self.y, height, [text], PT_TITLE, INK, bold=True)
        self.y += height + 0.10
        self.rect("deck-title-rule", MARGIN_IN, self.y, 2.1, 0.045, ACCENT)
        self.y += 0.26

    def footer(self) -> None:
        from pptx.util import Inches, Pt

        self.textbox("deck-footer", FOOTER_TOP_IN, 0.3, [FOOTER_LEFT], PT_FOOTER, MUTED,
                     width=BODY_W_IN - 1.2)
        box = self.slide.shapes.add_textbox(
            Inches(SLIDE_W_IN - MARGIN_IN - 1.2), Inches(FOOTER_TOP_IN),
            Inches(1.2), Inches(0.3),
        )
        box.name = "deck-footer-number"
        from pptx.enum.text import PP_ALIGN

        para = box.text_frame.paragraphs[0]
        para.alignment = PP_ALIGN.RIGHT
        self._runs(para, f"{self.number} / {self.total}", PT_FOOTER, MUTED)

    # -- content blocks -----------------------------------------------------

    def kicker(self, text: str) -> None:
        height = _height_in(text, PT_KICKER, BODY_W_IN)
        self.textbox("deck-kicker", self.y, height, [text], PT_KICKER, ACCENT, bold=True)
        self.y += height + 0.20

    def headline(self, text: str) -> None:
        height = _height_in(text, PT_HEADLINE, BODY_W_IN, leading=1.22)
        self.textbox("deck-headline", self.y, height, [text], PT_HEADLINE, ACCENT_DEEP)
        self.y += height + 0.26

    def points(self, items: list[str], ordered: bool = False) -> None:
        marks = ([f"{index}." for index in range(1, len(items) + 1)]
                 if ordered else ["▪"] * len(items))
        hanging = 0.40 if ordered else 0.32
        glyphed = [f"{mark}   {item}" for mark, item in zip(marks, items)]
        height = sum(
            _height_in(item, PT_POINTS, BODY_W_IN - hanging) for item in glyphed
        ) + 0.16 * len(glyphed)
        self.textbox("deck-points", self.y, height, glyphed, PT_POINTS, INK,
                     space_after_pt=11.0, hanging=hanging)
        self.y += height + 0.22

    def chips(self, label: str, items: list[str]) -> None:
        if label:
            height = _height_in(label, PT_CHIP_LABEL, BODY_W_IN)
            self.textbox("deck-chips-label", self.y, height, [label.upper()],
                         PT_CHIP_LABEL, ACCENT, bold=True)
            self.y += height + 0.06
        count = len(items)
        gap = 0.16
        width = (BODY_W_IN - gap * (count - 1)) / count
        text_h = max(_height_in(item, PT_CHIP, width - 0.30) for item in items)
        card_h = text_h + 0.24
        for index, item in enumerate(items):
            left = MARGIN_IN + index * (width + gap)
            self.rect(f"deck-chip-{index}", left, self.y, width, card_h, PANEL, RULE)
            self.textbox(f"deck-chip-text-{index}", self.y + 0.13, text_h, [item],
                         PT_CHIP, INK, left=left + 0.15, width=width - 0.30)
        self.y += card_h + 0.20

    def band(self, label: str, text: str) -> None:
        inner = BODY_W_IN - 0.56
        text_h = _height_in(text, PT_BAND, inner, leading=1.30)
        label_h = _height_in(label, PT_BAND_LABEL, inner) if label else 0.0
        card_h = text_h + label_h + (0.06 if label else 0.0) + 0.24
        self.rect("deck-band", MARGIN_IN, self.y, BODY_W_IN, card_h, BAND_FILL, BAND_EDGE)
        self.rect("deck-band-edge", MARGIN_IN, self.y, 0.075, card_h, BAND_EDGE)
        top = self.y + 0.12
        if label:
            self.textbox("deck-band-label", top, label_h, [label.upper()],
                         PT_BAND_LABEL, BAND_INK, left=MARGIN_IN + 0.28, width=inner,
                         bold=True)
            top += label_h + 0.06
        self.textbox("deck-band-text", top, text_h, [text], PT_BAND, INK,
                     left=MARGIN_IN + 0.28, width=inner)
        self.y += card_h + 0.16

    def pipeline(self, stages: list[str]) -> None:
        from pptx.enum.shapes import MSO_SHAPE
        from pptx.enum.text import MSO_ANCHOR, PP_ALIGN

        per_row = math.ceil(len(stages) / 2) if len(stages) > 4 else len(stages)
        rows = [stages[i:i + per_row] for i in range(0, len(stages), per_row)]
        gap = 0.10
        width = (BODY_W_IN - gap * (per_row - 1)) / per_row
        height = 0.92
        overflow = _chevron_overflow(stages, width, height)
        if overflow:
            raise SystemExit(
                "the pipeline does not fit its chevrons:\n  - " + "\n  - ".join(overflow)
            )
        for r, row in enumerate(rows):
            top = self.y + r * (height + 0.14)
            for c, stage in enumerate(row):
                left = MARGIN_IN + c * (width + gap)
                last = (r == len(rows) - 1) and (c == len(row) - 1)
                fill = ACCENT_DEEP if last or (r == 0 and c == 0) else PANEL
                ink = PAPER if fill is ACCENT_DEEP else INK
                shape = self.rect(
                    f"deck-pipe-{r}-{c}", left, top, width, height, fill,
                    None if fill is ACCENT_DEEP else RULE, shape=MSO_SHAPE.CHEVRON,
                )
                frame = shape.text_frame
                frame.word_wrap = True
                frame.vertical_anchor = MSO_ANCHOR.MIDDLE
                frame.margin_left = frame.margin_right = self._Inches(0.13)
                para = frame.paragraphs[0]
                para.alignment = PP_ALIGN.CENTER
                self._runs(para, stage, PT_PIPE, ink)
                self.words += len(plain(stage).split())
        self.y += len(rows) * (height + 0.14) + 0.14

    def lane(self, style: str, caption: str, stages: list[str]) -> None:
        """One captioned chevron chain, in the style that says which lane it is.

        `deployed` is drawn the way the rest of this deck draws a result: solid
        fill, inked text, a solid rule. `evaluation` is drawn the way
        `docs/img/01-architecture-dataflow.svg` draws the same lane — unfilled and
        DASHED — so the two are separable before a word of the caption is read.
        The caption is still mandatory: dashes mean nothing to a judge who has not
        been told what they are for, and `verify` checks both the words and the
        dash style in the saved file.
        """
        from pptx.enum.shapes import MSO_SHAPE
        from pptx.enum.text import MSO_ANCHOR, PP_ALIGN

        if style not in LANE_STYLES:
            raise SystemExit(
                f"unknown deck:lane style {style!r}; use one of {list(LANE_STYLES)} "
                "— the style is what makes the two lanes separable at a glance."
            )
        if not caption:
            raise SystemExit(
                f"the {style} lane has no caption. Write "
                f"<!-- deck:lane {style} | CAPTION --> : a dashed box a judge has to "
                "interpret is not a disclosure."
            )
        if not stages:
            raise SystemExit(f"the {style} lane has no stages")

        deployed = style == "deployed"
        label_h = _height_in(caption, PT_LANE_LABEL, BODY_W_IN)
        self.textbox(f"deck-lane-caption-{style}", self.y, label_h, [caption],
                     PT_LANE_LABEL, ACCENT_DEEP if deployed else MUTED, bold=True)
        self.y += label_h + 0.06

        gap = 0.10
        width = (BODY_W_IN - gap * (len(stages) - 1)) / len(stages)
        height = 0.92
        overflow = _chevron_overflow(stages, width, height)
        if overflow:
            raise SystemExit(
                f"the {style} lane does not fit its chevrons:\n  - "
                + "\n  - ".join(overflow)
            )
        for index, stage in enumerate(stages):
            left = MARGIN_IN + index * (width + gap)
            if deployed:
                first_or_last = index in (0, len(stages) - 1)
                fill = ACCENT_DEEP if first_or_last else PANEL
                ink = PAPER if first_or_last else INK
                line, dashed = (None if first_or_last else RULE), False
            else:
                fill, ink, line, dashed = None, MUTED, MUTED, True
            shape = self.rect(
                f"deck-lane-{style}-{index}", left, self.y, width, height, fill,
                line, dashed=dashed, shape=MSO_SHAPE.CHEVRON,
            )
            frame = shape.text_frame
            frame.word_wrap = True
            frame.vertical_anchor = MSO_ANCHOR.MIDDLE
            frame.margin_left = frame.margin_right = self._Inches(0.13)
            para = frame.paragraphs[0]
            para.alignment = PP_ALIGN.CENTER
            self._runs(para, stage, PT_PIPE, ink)
            self.words += len(plain(stage).split())
        self.y += height + 0.20

    def table(self, rows: list[list[str]], deployed_key: str | None = None) -> None:
        """The numbers are the slide. A 0-1 column gets a bar column beside it.

        The bar is drawn on a full 0-1 track: no truncated axis, so 0.573 looks
        like 0.573 and not like a near-miss of 0.933.

        The emphasised row — largest type, panel fill, inked bar — is the row
        whose model key is `deployed_key`, NOT the first one. It used to be the
        first, and the first row is the fused headline: the deck's largest text
        was an eval-side number, with the correction 547 words deep in speaker
        notes that are never projected. Emphasis is a claim like any other, so it
        goes to the row a judge's demo actually produces.
        """
        from pptx.enum.text import MSO_ANCHOR
        from pptx.util import Inches, Pt

        header, body = rows[0], rows[1:]
        if deployed_key is None:
            lead_body = 0            # an unbound table: the old first-row emphasis
        else:
            lead_body = next(
                (i for i, row in enumerate(body)
                 if model_key(row[0]) == deployed_key), None
            )
            if lead_body is None:
                raise SystemExit(
                    f"no row of this table names the deployed model {deployed_key!r}, "
                    "so there is no row to emphasise. docs/architecture.md §3 says "
                    "that is what the engine runs; the results slide has to print it."
                )
        bar_col = next(
            (i for i, name in enumerate(header)
             if all(_unit_value(r[i]) is not None for r in body)), None
        )
        widths = _column_widths(header, body, bar_col, lead_body)
        head_h, row_h = 0.38, 0.44
        cols = len(header) + (1 if bar_col is not None else 0)
        frame = self.slide.shapes.add_table(
            len(rows), cols, Inches(MARGIN_IN), Inches(self.y),
            Inches(BODY_W_IN), Inches(head_h + row_h * len(body)),
        )
        frame.name = "deck-table"
        table = frame.table
        table.first_row = True
        table.horz_banding = False
        for index, w in enumerate(widths):
            table.columns[index].width = Inches(w)
        table.rows[0].height = Inches(head_h)
        for index in range(1, len(rows)):   # _RowCollection is not sliceable
            table.rows[index].height = Inches(row_h)

        for r, source in enumerate(rows):
            cells = list(source)
            if bar_col is not None:
                # Header names the scale: the bars run a full 0-1 track, so a
                # reader can see that 0.573 is 0.573 and not a truncated axis.
                cells.insert(bar_col + 1, "0 → 1" if r == 0 else "")
            lead = r == lead_body + 1          # the deployed row, in body terms
            for c, text in enumerate(cells):
                cell = table.cell(r, c)
                cell.fill.solid()
                cell.fill.fore_color.rgb = self._rgb(
                    ACCENT_DEEP if r == 0 else (PANEL if lead else PAPER)
                )
                cell.vertical_anchor = MSO_ANCHOR.MIDDLE
                cell.margin_left = cell.margin_right = Inches(0.10)
                cell.margin_top = cell.margin_bottom = 0
                para = cell.text_frame.paragraphs[0]
                size = PT_TABLE_HEAD if r == 0 else (PT_TABLE_LEAD if lead else PT_TABLE_BODY)
                colour = PAPER if r == 0 else INK
                self._runs(para, text, size, colour, bold_base=(r == 0))
                self.words += len(plain(text).split())

        if bar_col is not None:
            track_left = MARGIN_IN + sum(widths[:bar_col + 1])
            track_w = widths[bar_col + 1] - 0.20
            for r, source in enumerate(body, start=1):
                value = _unit_value(source[bar_col])
                top = self.y + head_h + (r - 1) * row_h + row_h / 2 - 0.085
                self.rect(f"deck-bar-track-{r}", track_left + 0.10, top, track_w, 0.17,
                          BAR_TRACK)
                self.rect(f"deck-bar-{r}", track_left + 0.10, top,
                          max(0.02, track_w * value), 0.17,
                          ACCENT_DEEP if r == lead_body + 1 else BAR)
        self.y += head_h + row_h * len(body) + 0.20

    def figure(self, name: str, img_dir: Path) -> None:
        """Embed `<img-dir>/<name>.png|jpg`, or say plainly that there is none.

        No figure is ever invented: a missing one leaves a dashed slot naming the
        exact path to drop a file at. `docs/img/` holds SVGs, which python-pptx
        cannot embed, so an SVG is rasterised through the same headless Edge that
        `scripts/build_architecture_pdf.py` already uses — offline, and present on
        Windows 11. Silently ignoring a present .svg would look like the figure was
        forgotten, which is how an unnoticed gap gets into a judge-facing document.
        """
        from pptx.util import Inches

        slot_h = min(3.0, CONTENT_BOTTOM_IN - self.y)
        if slot_h < 0.9:
            raise SystemExit(f"figure {name!r} has no room left on the slide")
        blob, source = _figure_raster(name, img_dir)
        if blob is not None:
            pic = self.slide.shapes.add_picture(blob, Inches(0), Inches(0))
            pic.name = f"deck-figure-{name}"
            scale = min(Inches(BODY_W_IN) / pic.width, Inches(slot_h) / pic.height)
            pic.width, pic.height = int(pic.width * scale), int(pic.height * scale)
            pic.left = Inches(MARGIN_IN + (BODY_W_IN - pic.width / Inches(1)) / 2)
            pic.top = Inches(self.y)
            self.y += pic.height / Inches(1) + 0.20
            print(f"   figure {name}: embedded {source}")
            return
        detail = source
        text = f"FIGURE SLOT — {name}: no figure exists yet. {detail}"
        self.rect(f"deck-figure-slot-{name}", MARGIN_IN, self.y, BODY_W_IN, slot_h,
                  None, MUTED, dashed=True)
        self.textbox(f"deck-figure-note-{name}", self.y + slot_h / 2 - 0.18, 0.4,
                     [text], MIN_CONTENT_PT, MUTED, left=MARGIN_IN + 0.3,
                     width=BODY_W_IN - 0.6)
        self.y += slot_h + 0.20
        print(f"   figure {name}: PLACEHOLDER — {detail}")


EDGE_CANDIDATES = (
    Path("C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe"),
    Path("C:/Program Files/Microsoft/Edge/Application/msedge.exe"),
)
SVG_SIZE = re.compile(r'viewBox\s*=\s*"\s*[\d.-]+\s+[\d.-]+\s+([\d.]+)\s+([\d.]+)')
SVG_RASTER_SCALE = 2           # render at 2x so projected text stays crisp


def _figure_raster(name: str, img_dir: Path) -> tuple[object | None, str]:
    """(image bytes, what happened). `None` bytes means: render a placeholder.

    Returns a BytesIO rather than a path so a rasterised SVG never has to survive
    as a temp file past the moment python-pptx copies it into the package.
    """
    for ext in (".png", ".jpg", ".jpeg"):
        candidate = img_dir / f"{name}{ext}"
        if candidate.exists():
            return io.BytesIO(candidate.read_bytes()), str(candidate)

    svg = img_dir / f"{name}.svg"
    if not svg.exists():
        return None, f"drop {img_dir / (name + '.png')} or {name}.svg here and rebuild"

    edge = next((p for p in EDGE_CANDIDATES if p.exists()), None)
    if edge is None:
        return None, (f"{svg} exists but msedge.exe was not found to rasterise it — "
                      f"install Edge, or export {name}.png beside the .svg")
    match = SVG_SIZE.search(svg.read_text(encoding="utf-8")[:2000])
    if match is None:
        return None, (f"{svg} has no viewBox, so its size is unknown — add one, or "
                      f"export {name}.png beside it")
    # --window-size is CSS pixels and must be the SVG's OWN size; the scale factor
    # is what makes the raster 2x. Passing the scaled size here as well renders the
    # figure into the corner of a viewport twice too big, padded with white.
    width, height = int(float(match.group(1))), int(float(match.group(2)))
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / f"{name}.png"
        try:
            subprocess.run(
                [str(edge), "--headless=new", "--disable-gpu", "--no-sandbox",
                 f"--screenshot={out}", f"--window-size={width},{height}",
                 f"--force-device-scale-factor={SVG_RASTER_SCALE}",
                 "--hide-scrollbars", "--virtual-time-budget=5000",
                 "--run-all-compositor-stages-before-draw", svg.resolve().as_uri()],
                check=True, timeout=120, capture_output=True,
            )
        except (subprocess.SubprocessError, OSError) as exc:
            return None, f"{svg} could not be rasterised by Edge ({exc}); export {name}.png"
        # Edge's launcher process returns before the browser has flushed the file,
        # so the PNG appears a beat after subprocess.run comes back. Waiting for it
        # is the difference between this working and reporting "Edge produced no PNG"
        # about a render that in fact succeeded.
        deadline = time.monotonic() + 30.0
        while not out.exists() and time.monotonic() < deadline:
            time.sleep(0.25)
        if not out.exists():
            return None, f"Edge produced no PNG for {svg} within 30 s; export {name}.png"
        size = out.stat().st_size
        while time.monotonic() < deadline:       # and it must be fully written
            time.sleep(0.25)
            if out.stat().st_size == size and size > 0:
                break
            size = out.stat().st_size
        return (io.BytesIO(out.read_bytes()),
                f"{svg} (rasterised {width * SVG_RASTER_SCALE}x"
                f"{height * SVG_RASTER_SCALE} via headless Edge)")


def _unit_value(text: str) -> float | None:
    """The cell's value if it is a bare number in [0, 1], else None."""
    try:
        value = float(plain(text).strip())
    except ValueError:
        return None
    return value if 0.0 <= value <= 1.0 else None


def _cell_width_in(text: str, size_pt: float, bold: bool) -> float:
    # `bold` is the row's baseline weight; a cell that is ALSO `**bold**` in the
    # markdown is measured bold whatever its row is. Missing that under-estimated
    # every emphasised cell by ~13 %, and an under-estimate is the one direction
    # that costs a wrapped cell rather than whitespace (see _column_widths).
    bold = bold or "**" in text
    factor = TABLE_CHAR_BOLD if bold else TABLE_CHAR_REGULAR
    return len(plain(text)) * factor * size_pt / 72.0 + TABLE_CELL_PAD_IN


def _column_widths(header, body, bar_col, lead_body: int = 0) -> list[float]:
    """Wide enough that no cell has to wrap. Not proportional, and not squeezed.

    A row height in a .pptx is a MINIMUM, not a height: one cell that wraps grows
    its whole row, the table then runs taller than the space reserved for it, the
    AUROC bars drawn beside it stop lining up with their rows, and the block below
    is overwritten. That is what an earlier version of this function did — it
    shared the width out in proportion to character count, which gave `AUROC` and
    `0.933` a column too narrow for either, and the rendered deck had `0.93` above
    `3` sitting on top of the contribution row. So a table that cannot fit one
    line per cell is a build failure that names the column, never a squeeze.
    """
    natural = []
    for column in range(len(header)):
        candidates = [_cell_width_in(header[column], PT_TABLE_HEAD, True)]
        for index, row in enumerate(body):
            lead = index == lead_body               # the deployed row is bold and larger
            candidates.append(_cell_width_in(
                row[column], PT_TABLE_LEAD if lead else PT_TABLE_BODY, lead
            ))
        natural.append(max(candidates))

    bar_w = BAR_COL_W_IN if bar_col is not None else 0.0
    total = sum(natural) + bar_w
    if total > BODY_W_IN:
        widest = max(range(len(natural)), key=natural.__getitem__)
        raise SystemExit(
            f"the table needs {total:.2f}in but only {BODY_W_IN:.2f}in is available; "
            f"column {header[widest]!r} alone wants {natural[widest]:.2f}in. Shorten "
            "the longest cell in that column in docs/slides.md. Narrowing the column "
            "instead would wrap a cell, and a wrapped cell silently grows the table "
            "over whatever is below it."
        )
    natural[max(range(len(natural)), key=natural.__getitem__)] += BODY_W_IN - total
    if bar_col is not None:
        natural.insert(bar_col + 1, bar_w)
    return natural


@dataclass(frozen=True)
class SourceFacts:
    """Everything the deck is bound to, read out of the documents that own it.

    Read once, up front, and passed to both the render and the verify: nothing
    below states a measurement or a pipeline of its own.
    """

    headings: list[str]
    lanes: dict[str, str]
    measured: dict[str, dict[str, str]]
    deployed_key: str


def read_source_facts(architecture: Path, limitations: Path) -> SourceFacts:
    return SourceFacts(
        headings=read_limitation_headings(limitations),
        lanes=read_lane_split(architecture),
        measured=read_measured_rows(architecture),
        deployed_key=read_deployed_row_key(architecture),
    )


def deck_source_digest(slides_md: Path) -> str:
    """SHA-256 of the markdown the deck is rendered from. See SOURCE_DIGEST_KEY."""
    return hashlib.sha256(slides_md.read_bytes()).hexdigest()


def stamped_source_digest(path: Path) -> str | None:
    """The digest a saved deck was stamped with, or None if it predates the stamp."""
    from pptx import Presentation

    keywords = Presentation(str(path)).core_properties.keywords or ""
    match = re.search(rf"{SOURCE_DIGEST_KEY}=([0-9a-f]{{64}})", keywords)
    return match.group(1) if match else None


def render(slides: list[Slide], img_dir: Path, out: Path, facts: SourceFacts,
           source_digest: str = "") -> None:
    """Paint every slide, then save — but only if no slide broke a layout rule.

    The overflow check and the word cap are COLLECTED, not raised one at a time.
    An earlier version raised on overflow the moment it saw it, which made the
    word cap effectively unreachable: a paragraph pasted onto a slide runs past
    the bottom before it runs past 160 words, so the build reported the height
    and never the wall of text. Reporting both at once means a proof that the
    word cap bites does not have to be a case that happens to fit vertically.
    """
    pptx = _import_pptx()
    from pptx import Presentation
    from pptx.util import Inches

    deck = Presentation()
    deck.slide_width = Inches(SLIDE_W_IN)
    deck.slide_height = Inches(SLIDE_H_IN)
    blank = deck.slide_layouts[6]
    layout_problems: list[str] = []

    for slide_spec in slides:
        slide = deck.slides.add_slide(blank)
        painter = Painter(slide, slide_spec.number, len(slides))
        painter.chrome()
        painter.title(slide_spec.title)
        for block in slide_spec.on_slide:
            text = " ".join(ln.strip() for ln in block.lines).strip()
            if block.kind == "kicker":
                painter.kicker(text)
            elif block.kind == "headline":
                painter.headline(text)
            elif block.kind == "points":
                painter.points(list_items(block.lines),
                               ordered=list_is_ordered(block.lines))
            elif block.kind == "chips":
                painter.chips(block.label, list_items(block.lines))
            elif block.kind == "band":
                painter.band(block.label, text)
            elif block.kind == "pipeline":
                painter.pipeline(pipeline_stages(block.lines))
            elif block.kind == "lane":
                style, _, caption = block.label.partition("|")
                painter.lane(style.strip().lower(), caption.strip(),
                             pipeline_stages(block.lines))
            elif block.kind == "table":
                painter.table(table_rows(block.lines), facts.deployed_key)
            elif block.kind == "figure":
                painter.figure(block.label, img_dir)
            else:
                raise SystemExit(f"unknown deck marker {block.kind!r} on slide "
                                 f"{slide_spec.number}")
        painter.footer()

        if painter.y > CONTENT_BOTTOM_IN:
            layout_problems.append(
                f"slide {slide_spec.number} overflows: content reaches "
                f"{painter.y:.2f}in of {CONTENT_BOTTOM_IN:.2f}in usable. Move prose "
                "out of the marked blocks and into the unmarked paragraphs (they "
                "become the speaker notes) — do not shrink the type."
            )
        if painter.words > MAX_ON_SLIDE_WORDS:
            layout_problems.append(
                f"slide {slide_spec.number} carries {painter.words} on-slide words "
                f"(cap {MAX_ON_SLIDE_WORDS}). A wall of text that happens to be in "
                ".pptx format is not a deck; the prose belongs in the notes."
            )
        notes = slide_spec.notes
        if notes:
            slide.notes_slide.notes_text_frame.text = notes
        print(f"   slide {slide_spec.number}: {painter.words} on-slide words, "
              f"content to {painter.y:.2f}in, {len(notes.split())} words of notes")

    if layout_problems:
        raise SystemExit(
            "the deck does not fit its own slides:\n  - " + "\n  - ".join(layout_problems)
        )

    core = deck.core_properties
    core.title = DECK_TITLE
    core.subject = "SIH 2026 · problem statement SIH26153 (NTRO)"
    core.author = "SIH26153 team"
    core.last_modified_by = "scripts/build_deck.py"
    core.comments = "Generated from docs/slides.md — edit the markdown, not this file."
    core.keywords = f"{SOURCE_DIGEST_KEY}={source_digest}"
    core.created = FIXED_TIME
    core.modified = FIXED_TIME
    core.revision = 1

    out.parent.mkdir(parents=True, exist_ok=True)
    deck.save(str(out))
    _pin_zip_timestamps(out)


def _pin_zip_timestamps(path: Path) -> None:
    """Rewrite the package with a fixed member timestamp.

    A .pptx is a zip, and `zipfile` stamps the current clock into every entry, so
    two builds of identical content would otherwise differ. Pinning it makes
    "deterministic" a property a reviewer can check with sha256sum rather than a
    claim in a docstring.
    """
    with zipfile.ZipFile(path) as src:
        members = [(info, src.read(info.filename)) for info in src.infolist()]
    staging = path.with_suffix(".pptx.tmp")
    with zipfile.ZipFile(staging, "w", zipfile.ZIP_DEFLATED) as out:
        for info, data in members:
            pinned = zipfile.ZipInfo(info.filename, date_time=ZIP_EPOCH)
            pinned.compress_type = zipfile.ZIP_DEFLATED
            pinned.external_attr = info.external_attr
            pinned.create_system = 0
            out.writestr(pinned, data)
    staging.replace(path)


# ---------------------------------------------------------------- verification


def _slide_runs(slide):
    """(shape name, run) for every run the slide actually carries, tables included."""
    for shape in slide.shapes:
        yield from _shape_runs(shape)


def _shape_runs(shape):
    if shape.has_text_frame:
        for para in shape.text_frame.paragraphs:
            for run in para.runs:
                yield shape.name, run
    if getattr(shape, "has_table", False):
        for row in shape.table.rows:
            for cell in row.cells:
                for para in cell.text_frame.paragraphs:
                    for run in para.runs:
                        yield shape.name, run


def read_limitation_headings(doc: Path) -> list[str]:
    """The `## N. …` headings of docs/limitations.md, in order, or a loud failure.

    This is the source side of the limitations binding. It is read from the
    document itself on every build, so the deck cannot quietly stop matching it.
    """
    if not doc.exists():
        raise SystemExit(
            f"{doc} does not exist, and slide 5 of the deck is bound to it by "
            "content. Point --limitations at the document or restore it."
        )
    numbered = [
        (int(m.group("n")), m.group("title"))
        for m in (LIMITATION_HEADING.match(line)
                  for line in doc.read_text(encoding="utf-8").splitlines())
        if m
    ]
    if [n for n, _ in numbered] != list(range(1, len(numbered) + 1)):
        raise SystemExit(
            f"{doc} numbers its limitations {[n for n, _ in numbered]}, which is not "
            "1..N in order. The deck binds item i to section i, so the numbering has "
            "to be the document's own."
        )
    if len(numbered) != LIMITATION_COUNT:
        raise SystemExit(
            f"{doc} now numbers {len(numbered)} limitations but this builder binds "
            f"{LIMITATION_COUNT} of them to slide 5 (LIMITATION_TOPICS). That is a "
            "judgement call a human has to make, not a count to paper over: decide "
            "which belong on the slide, update LIMITATION_TOPICS and docs/slides.md "
            "together, and say why in the comment above LIMITATIONS_DOC."
        )
    return [title for _, title in numbered]


def _sentences(text: str) -> list[str]:
    """Normalised sentences of a document. Crude on purpose: the only thing split
    on is a full stop followed by whitespace, which is enough to keep one lane's
    description out of the other's."""
    return [normalise(s) for s in re.split(r"(?<=\.)\s+", text) if s.strip()]


def read_lane_split(doc: Path) -> dict[str, str]:
    """`docs/architecture.md`'s own sentence about each lane, or a loud failure.

    This is the source side of slide 2's binding, and the reason the slide's two
    lanes are not just this file's opinion about the pipeline. The document says
    the matrix feeds two lanes and names what is in each; if that sentence is
    reworded, moved or deleted, the build stops here and names what to restore
    rather than continuing to draw a split the repository no longer documents.
    """
    if not doc.exists():
        raise SystemExit(
            f"{doc} does not exist, and slide 2's two lanes are bound to its §2 by "
            "content. Point --architecture at the document or restore it."
        )
    sentences = _sentences(doc.read_text(encoding="utf-8"))
    found: dict[str, str] = {}
    for style in LANE_STYLES:
        mark = LANE_SENTENCE_MARK[style]
        hits = [s for s in sentences if mark in s]
        if len(hits) != 1:
            raise SystemExit(
                f"{doc} contains {len(hits)} sentences saying {mark!r}, expected "
                f"exactly one. Slide 2 draws the {style} lane and this builder "
                "checks its components against that sentence, so the deck cannot "
                "be built from a document that no longer states the split. Restore "
                "the §2 wording, or decide what slide 2 should now draw and update "
                "LANE_SENTENCE_MARK with it."
            )
        found[style] = hits[0]

    for style, tokens in (("deployed", DEPLOYED_LANE_TOKENS),
                          ("evaluation", EVAL_ONLY_LANE_TOKENS)):
        missing = [t for t in tokens if t not in found[style]]
        if missing:
            raise SystemExit(
                f"{doc}'s {style}-lane sentence no longer names {missing}:\n"
                f"      IT SAYS: {found[style][:160]!r}\n"
                "      The binding is two-sided on purpose. The document moved, so "
                "decide what slide 2 should draw and update DEPLOYED_LANE_TOKENS / "
                "EVAL_ONLY_LANE_TOKENS together with docs/slides.md."
            )
    return found


def model_key(cell: str) -> str | None:
    """Which model a table cell names, or None. First key in MODEL_KEYS wins, so
    'Fused (rank-mean TGN+XGB)' is `fused` and not `tgn`."""
    text = normalise(cell)
    return next((key for key, pattern in MODEL_KEYS if pattern.search(text)), None)


def read_deployed_row_key(doc: Path) -> str:
    """The model key `docs/architecture.md` §3 says the engine actually runs.

    Read rather than declared: which row a judge's demo corresponds to is the
    single fact this deck most needs to be right about, and a constant in this
    file would be one more copy of it to go stale.
    """
    hits = [s for s in _sentences(doc.read_text(encoding="utf-8"))
            if DEPLOYED_SCORER_MARK in s]
    if len(hits) != 1:
        raise SystemExit(
            f"{doc} contains {len(hits)} sentences saying {DEPLOYED_SCORER_MARK!r}, "
            "expected exactly one. Slide 3 labels one row as the deployed engine and "
            "this builder takes which row that is from that sentence."
        )
    key = model_key(hits[0])
    if key is None:
        raise SystemExit(
            f"{doc}'s {DEPLOYED_SCORER_MARK!r} sentence names no model this builder "
            f"knows ({[k for k, _ in MODEL_KEYS]}):\n      IT SAYS: {hits[0][:160]!r}"
        )
    return key


def read_measured_rows(doc: Path) -> dict[str, dict[str, str]]:
    """`docs/architecture.md` §4's results table, keyed by model. The measurement.

    Rows the builder has no key for (the LSTM row today) are skipped rather than
    failed: the deck prints a subset of that table and is free to. What is not
    free is printing a DIFFERENT value for a model the document measured.
    """
    rows: dict[str, dict[str, str]] = {}
    block: list[list[str]] = []
    blocks: list[list[list[str]]] = []
    for line in doc.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped.startswith("|"):
            if block:
                blocks.append(block)
                block = []
            continue
        cells = [plain(c).strip() for c in stripped.strip("|").split("|")]
        if all(set(c) <= set("-: ") and c for c in cells):
            continue                       # the |---|---| separator
        block.append(cells)
    if block:
        blocks.append(block)

    for table in blocks:
        header = table[0]
        if _column_index(header, "auroc") is None:
            continue                       # not the results table
        for cells in table[1:]:
            key = model_key(cells[0])
            if key is not None:            # e.g. the LSTM row has no key: skipped
                rows[key] = dict(zip(header, cells))
    if not rows:
        raise SystemExit(
            f"{doc} has no results table this builder can read, and every figure on "
            "slide 3 is bound to it by model. Restore §4's table."
        )
    return rows


def _column_index(header: list[str], keyword: str) -> int | None:
    return next((i for i, name in enumerate(header) if keyword in normalise(name)), None)


def _leading_number(text: str) -> str | None:
    match = re.search(r"-?\d+(?:\.\d+)?", plain(text))
    return match.group(0) if match else None


def results_problems(rows: list[list[str]], measured: dict[str, dict[str, str]],
                     deployed_key: str, where: str) -> list[str]:
    """Bind every figure in the deck's results table to the model it describes.

    Two bindings, and they fail on different edits. The FIGURES are compared
    against `docs/architecture.md` §4 row by row, so giving one model another
    model's AUROC fails even though both numbers are published. The LANE LABEL is
    checked for exactly one deployed row, so relabelling the eval-side headline
    'shipped engine' fails even though every number on the slide is still right.
    """
    problems: list[str] = []
    if not rows:
        return [f"{where} has no table at all, and the results are the slide."]
    header, body = rows[0], rows[1:]

    lead_index = _column_index(header, "lead")
    if lead_index is None:
        problems.append(
            f"{where} has no lead-time column. The PS's success metric is lead time."
        )
    elif LEAD_HEADER_MARK not in normalise(header[lead_index]):
        problems.append(
            f"{where}'s lead column header is {header[lead_index]!r} and no longer "
            f"says {LEAD_HEADER_MARK!r}. That column is produced by the horizon-0 "
            "classifier, not by forecasting ahead, and the band saying so in a "
            "sentence is one edit from being the only copy — which is how this was "
            "reported as two pins while only one existed."
        )

    deployed_rows: list[str] = []
    for row in body:
        key = model_key(row[0])
        if key is None:
            problems.append(
                f"{where} has a row {normalise(row[0])[:60]!r} naming no model this "
                f"builder can bind ({[k for k, _ in MODEL_KEYS]}). Every printed "
                "figure has to be attributable to a measured model."
            )
            continue
        label = normalise(row[0])
        is_deployed = DEPLOYED_MARKER in label
        if is_deployed:
            deployed_rows.append(key)
        if key == deployed_key and not is_deployed:
            problems.append(
                f"{where}'s {key!r} row does not say {DEPLOYED_MARKER!r}. "
                "docs/architecture.md §3 says that is the model the engine loads, so "
                "it is the row a judge's demo actually produces; leaving it unnamed "
                "makes the reader guess which of five rows they are about to run."
            )
        if key != deployed_key:
            if is_deployed:
                problems.append(
                    f"{where}'s {key!r} row claims to be the {DEPLOYED_MARKER!r}. "
                    f"docs/architecture.md §3 says the engine runs {deployed_key!r}. "
                    "This is the deck's single largest possible overclaim."
                )
            elif EVAL_MARKER not in label:
                problems.append(
                    f"{where}'s {key!r} row does not say {EVAL_MARKER!r}: "
                    f"{normalise(row[0])[:60]!r}. It is not what the engine runs, and "
                    "the largest number on this slide belonged to a row that said so "
                    "nowhere but the speaker notes."
                )
        if key not in measured:
            problems.append(
                f"{where} prints a {key!r} row that docs/architecture.md §4 does not "
                "measure. A figure with no measurement behind it is the one thing "
                "this project never ships."
            )
            continue
        source = measured[key]
        for keyword, how in RESULTS_COLUMNS:
            deck_index = _column_index(header, keyword)
            source_name = next(
                (n for n in source if keyword in normalise(n)), None
            )
            if deck_index is None or source_name is None:
                continue
            deck_value = plain(row[deck_index]).strip()
            source_value = source[source_name]
            if how == "leading-number":
                left, right = _leading_number(deck_value), _leading_number(source_value)
            else:
                left, right = normalise(deck_value), normalise(source_value)
            if left != right:
                problems.append(
                    f"{where}'s {key!r} row prints {keyword} {deck_value!r}, but "
                    f"docs/architecture.md §4 measured {source_value!r} for that "
                    "model. Every figure on this slide is bound to the model it "
                    "describes: the defect this catches is the RIGHT number on the "
                    "WRONG row, which no presence check can see."
                )
    if len(deployed_rows) != 1:
        problems.append(
            f"{where} marks {len(deployed_rows)} rows {DEPLOYED_MARKER!r} "
            f"({deployed_rows}); exactly one row is what the engine runs."
        )
    return problems


def banned_problems(runs: list[tuple[str, str]], where: str) -> list[str]:
    """Contradictions, checked one run of text at a time. See BANNED_ON_SLIDE."""
    problems: list[str] = []
    for claim in BANNED_ON_SLIDE:
        for name, text in runs:
            flat = normalise(text)
            for pattern in claim.patterns:
                match = pattern.search(flat)
                if match is None:
                    continue
                problems.append(
                    f"{where}: {name} says {match.group(0)!r} [{claim.slug}]\n"
                    f"      IN: {flat[:140]!r}\n"
                    f"      WHY IT IS BANNED: {claim.why}\n"
                    "      Every required disclosure can still be present while this "
                    "is on the deck; that is the point of this check."
                )
    return problems


def limitation_problems(items: list[str], headings: list[str], where: str) -> list[str]:
    """Bind the deck's limitations list to docs/limitations.md, by content.

    `items` is the deck's ordered list — from the parsed markdown before the
    render, and from the reopened .pptx after it. Both sides are checked against
    the same topic keys, and each key is checked against the document's own
    heading first, so this never degenerates into the file asserting something
    about itself.
    """
    if len(headings) != LIMITATION_COUNT:
        raise SystemExit(                 # loud, rather than an IndexError below
            f"{len(headings)} headings were passed for {LIMITATION_COUNT} topic keys; "
            "read_limitation_headings is the only supported way to produce them."
        )
    problems: list[str] = []
    if len(items) != LIMITATION_COUNT:
        problems.append(
            f"{where} lists {len(items)} limitations; docs/limitations.md numbers "
            f"{LIMITATION_COUNT}. Adding one that the document does not carry, or "
            "dropping one to make the slide fit, is exactly the divergence this "
            "check exists to stop."
        )
    for index, topic in enumerate(LIMITATION_TOPICS):
        heading = normalise(headings[index])
        absent_from_doc = [key for key in topic if key not in heading]
        if absent_from_doc:
            problems.append(
                f"limitation {index + 1}: topic key {absent_from_doc} is no longer in "
                f"docs/limitations.md's own heading ({headings[index]!r}). The binding "
                "is two-sided on purpose — the document moved, so decide what slide 5 "
                "should now say and update LIMITATION_TOPICS with it."
            )
            continue
        if index >= len(items):
            continue                      # already reported by the count above
        item = normalise(items[index])
        absent_from_deck = [key for key in topic if key not in item]
        if absent_from_deck:
            problems.append(
                f"{where} item {index + 1} does not state {absent_from_deck}.\n"
                f"      IT SAYS:      {normalise(items[index])[:96]!r}\n"
                f"      §{index + 1} SAYS:      {normalise(headings[index])[:96]!r}\n"
                "      Slide 5's title sends the judge to docs/limitations.md, so the "
                "slide's five have to be that document's five, in its order. Compress "
                "the wording as much as you like; do not substitute a different "
                "limitation."
            )
    return problems


def check_source(slides: list[Slide], headings: list[str]) -> None:
    """Structural checks on the markdown, before anything is painted.

    Not a duplicate of `verify`, and not the builder agreeing with itself: this
    pairs `docs/slides.md` against `docs/limitations.md`, which `verify` cannot
    do until a file exists. It runs FIRST because the render is where layout
    failures live — a sixth limitation overflows slide 5 and raises there, which
    would report a height and never the fact that the list stopped matching the
    document. Source first, then the saved binary.
    """
    limitations = [s for s in slides if "cannot do" in s.title.lower()]
    if len(limitations) != 1:
        raise SystemExit(
            "expected exactly one '## Slide N — …cannot do…' heading in the source; "
            f"found {len(limitations)}. docs/limitations.md is a graded part of the deck."
        )
    blocks = [b for b in limitations[0].on_slide if b.kind == "points"]
    if len(blocks) != 1:
        raise SystemExit(
            f"the limitations slide carries {len(blocks)} <!-- deck:points --> blocks; "
            "the numbered list bound to docs/limitations.md has to be exactly one."
        )
    if not list_is_ordered(blocks[0].lines):
        raise SystemExit(
            "the limitations slide's list is not numbered. docs/limitations.md numbers "
            "its sections and a judge cross-references them by number."
        )
    problems = limitation_problems(list_items(blocks[0].lines), headings,
                                   "docs/slides.md's limitations list")
    if problems:
        raise SystemExit(
            "docs/slides.md does not match docs/limitations.md:\n  - "
            + "\n  - ".join(problems)
        )


def _lane_text(slide) -> dict[str, list[tuple[str, str]]]:
    """style -> [(shape name, text)] for every lane chevron on this slide."""
    lanes: dict[str, list[tuple[str, str]]] = {style: [] for style in LANE_STYLES}
    for shape in slide.shapes:
        for style in LANE_STYLES:
            if shape.name.startswith(f"deck-lane-{style}-"):
                lanes[style].append((shape.name, shape.text_frame.text))
    return lanes


def _is_dashed(shape) -> bool:
    try:
        return shape.line.dash_style is not None
    except (AttributeError, TypeError, ValueError):
        return False


def lane_problems(slides, lanes: dict[str, str]) -> list[str]:
    """Slide 2's two lanes, in the file a judge opens. See ARCHITECTURE LANES.

    Four things have to hold, and they fail on four different careless edits:
    both lanes exist on ONE slide (deleting a marker); the deployed lane names
    the deployed model (dropping the XGBoost chevron); every evaluation-only
    component is in the evaluation lane and NOT in the deployed one (merging the
    two chains back into one, which is how this slide was drawn for five audit
    rounds); and the evaluation lane is really dashed in the saved package
    (redrawing it solid, so the caption is the only thing left saying it does not
    ship).
    """
    problems: list[str] = []
    carriers = [s for s in slides if any(_lane_text(s).values())]
    if len(carriers) != 1:
        return [
            f"{len(carriers)} slides draw architecture lanes; expected exactly one. "
            "docs/architecture.md §2 says the feature matrix feeds two lanes — a "
            "deployed one and an evaluation-only one — and a deck that draws them "
            "as a single chain teaches a judge a pipeline this product does not "
            "have. Restore both <!-- deck:lane --> blocks on the architecture slide."
        ]
    slide = carriers[0]
    drawn = _lane_text(slide)
    for style in LANE_STYLES:
        if not drawn[style]:
            problems.append(
                f"the architecture slide draws no {style!r} lane. Both lanes are "
                "required: one lane is a pipeline claim, and the claim would be "
                f"{'that nothing ships' if style == 'deployed' else 'that all of it ships'}."
            )
        caption = _named_shape(slide, f"deck-lane-caption-{style}")
        if caption is None or not caption.text_frame.text.strip():
            problems.append(f"the {style!r} lane has no caption on the slide.")
        elif LANE_CAPTION_MARK[style] not in normalise(caption.text_frame.text):
            problems.append(
                f"the {style!r} lane's caption does not say "
                f"{LANE_CAPTION_MARK[style]!r}: {caption.text_frame.text!r}. It has to "
                "say so IN THE CAPTION, not somewhere else on the slide — the phrase "
                "was already in the headline when this caption was reworded, so the "
                "per-slide check passed while the lane a judge must not mistake for "
                "the product stopped naming itself."
            )
    if problems:
        return problems

    deployed_text = normalise(" ".join(t for _, t in drawn["deployed"]))
    evaluation_text = normalise(" ".join(t for _, t in drawn["evaluation"]))

    for token in DEPLOYED_LANE_TOKENS:
        if token not in deployed_text:
            problems.append(
                f"the deployed lane does not name {token!r}: {deployed_text[:120]!r}. "
                "docs/architecture.md §2 says the deployed lane IS that scorer, and a "
                "judge reading an architecture slide that names every model except "
                "the one in the scoring path learns the wrong product."
            )
    for token in EVAL_ONLY_LANE_TOKENS:
        if token not in evaluation_text:
            problems.append(
                f"the evaluation-only lane does not name {token!r}: "
                f"{evaluation_text[:120]!r}. docs/architecture.md §2 puts it there; "
                "a component that is drawn nowhere cannot be marked evaluation-only."
            )
        if token in deployed_text:
            problems.append(
                f"the DEPLOYED lane names {token!r}. docs/architecture.md §2: "
                f"{lanes['evaluation'][:140]!r} — none of it runs in the engine. "
                "Drawing it inside the shipped chain is the exact defect the two "
                "lanes exist to prevent."
            )

    dashed = [name for name, _ in drawn["evaluation"]
              if _is_dashed(_named_shape(slide, name))]
    if len(dashed) != len(drawn["evaluation"]):
        problems.append(
            f"{len(drawn['evaluation']) - len(dashed)} of the evaluation lane's "
            "chevrons are not dashed in the saved file. The caption alone does not "
            "separate the lanes at a glance, and 'at a glance' is how a judge reads "
            "an architecture slide from the back of a room."
        )
    solid = [name for name, _ in drawn["deployed"]
             if _is_dashed(_named_shape(slide, name))]
    if solid:
        problems.append(
            f"{solid} in the DEPLOYED lane are dashed. The two lanes are told apart "
            "by that one visual difference; drawing both the same way erases it."
        )
    return problems


def verify(path: Path, facts: SourceFacts) -> tuple[int, int]:
    """Reopen the saved deck and check it against the constraints. Returns (slides, bytes).

    Everything here is read back off disk. Checking the in-memory model would
    prove the builder agrees with itself; checking the file proves the thing a
    judge opens is the thing we claim — which is also why this is reachable on
    its own, through `--verify-only`, for a .pptx this run did not write.
    """
    from pptx import Presentation

    deck = Presentation(str(path))
    slides = list(deck.slides)
    problems: list[str] = []

    if not slides:
        raise SystemExit(f"{path} has no slides")
    if len(slides) > MAX_SLIDES:
        problems.append(
            f"{len(slides)} slides — the PS caps the technical presentation at "
            f"{MAX_SLIDES}. Merge content or move it to the notes."
        )

    per_slide: list[str] = []
    for index, slide in enumerate(slides, start=1):
        problems.extend(banned_problems(_slide_units(slide), f"slide {index}"))
        texts, runs = [], 0
        for name, run in _slide_runs(slide):
            runs += 1
            size = run.font.size
            if size is None:
                problems.append(f"slide {index}: {name} has a run with no explicit "
                                "font size — it would inherit from the template")
                continue
            points = size.pt
            floor = MIN_ANY_PT if name.startswith("deck-footer") else MIN_CONTENT_PT
            if points < floor:
                problems.append(
                    f"slide {index}: {name} sets {points:g}pt, below the {floor:g}pt "
                    "floor — this deck has to be readable from the back of a room"
                )
            if not name.startswith("deck-footer"):
                texts.append(run.text)
        if runs == 0:
            problems.append(f"slide {index} has no text at all")
        body = " ".join(texts).strip()
        if not body:
            problems.append(f"slide {index} has no content outside its footer")
        per_slide.append(normalise(body))

    for number, phrase, why in REQUIRED_ON_SLIDE:
        needle = normalise(phrase)
        if number > len(slides):
            problems.append(
                f"slide {number} has to carry {phrase!r}, but the deck only has "
                f"{len(slides)} slides."
            )
            continue
        if needle in per_slide[number - 1]:
            continue
        found_on = [i + 1 for i, text in enumerate(per_slide) if needle in text]
        where = (f" It is on slide {found_on} instead — a disclosure two slides from "
                 "the claim it qualifies is not a disclosure; move it back."
                 if found_on else
                 " It is on no slide at all; the speaker notes do not count.")
        problems.append(
            f"slide {number} no longer states {phrase!r}.\n      WHY IT IS REQUIRED: "
            f"{why}\n     {where}"
        )

    problems.extend(lane_problems(slides, facts.lanes))

    tables = [(i, _named_shape(s, "deck-table"))
              for i, s in enumerate(slides, start=1)]
    tables = [(i, shape) for i, shape in tables if shape is not None]
    if len(tables) != 1:
        problems.append(
            f"{len(tables)} slides carry a results table; expected exactly one. "
            "Every figure on it is bound to the model docs/architecture.md §4 "
            "measured, and a second table is a second, unbound set of numbers."
        )
    else:
        index, shape = tables[0]
        problems.extend(results_problems(
            _table_rows_from_shape(shape), facts.measured, facts.deployed_key,
            f"{path.name}'s slide {index} table",
        ))

    limitations = [s for s in slides if "cannot do" in _slide_title(s).lower()]
    if len(limitations) != 1:
        problems.append(
            "expected exactly one slide whose title says what this cannot do; found "
            f"{len(limitations)}. docs/limitations.md is a graded part of the deck."
        )
    else:
        points = _named_shape(limitations[0], "deck-points")
        items = [] if points is None else [
            p.text.strip() for p in points.text_frame.paragraphs if p.text.strip()
        ]
        problems.extend(
            limitation_problems(items, facts.headings, f"{path.name}'s slide 5")
        )

    if problems:
        raise SystemExit(
            f"{path} fails the deck's own checks:\n  - " + "\n  - ".join(problems)
        )
    return len(slides), path.stat().st_size


def _slide_units(slide) -> list[tuple[str, str]]:
    """(shape name, text) for every unit BANNED_ON_SLIDE is matched against.

    A paragraph of a textbox, a chevron, one table cell. Never the slide's runs
    joined: see the scope note above BANNED_ON_SLIDE. The footer is skipped — it
    is the same line on all five slides and carries no claim.
    """
    units: list[tuple[str, str]] = []
    for shape in slide.shapes:
        if shape.name.startswith("deck-footer"):
            continue
        if shape.has_text_frame:
            for number, para in enumerate(shape.text_frame.paragraphs):
                if para.text.strip():
                    units.append((f"{shape.name}[{number}]", para.text))
        if getattr(shape, "has_table", False):
            for r, row in enumerate(shape.table.rows):
                for c, cell in enumerate(row.cells):
                    if cell.text_frame.text.strip():
                        units.append((f"{shape.name}[{r},{c}]", cell.text_frame.text))
    return units


def _table_rows_from_shape(shape) -> list[list[str]]:
    """The saved table, read back as rows of plain cell text.

    The bar column the builder inserts comes back with it and is simply not
    matched by any of RESULTS_COLUMNS' keywords, so it needs no special case.
    """
    return [[cell.text_frame.text.strip() for cell in row.cells]
            for row in shape.table.rows]


def _slide_title(slide) -> str:
    shape = _named_shape(slide, "deck-title")
    return shape.text_frame.text if shape is not None else ""


def _named_shape(slide, name: str):
    return next((s for s in slide.shapes if s.name == name), None)


# ----------------------------------------------------------------------- main


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--slides", type=Path, default=REPO / "docs" / "slides.md",
                        help="source markdown (default: docs/slides.md)")
    parser.add_argument("--out", type=Path,
                        default=REPO / "docs" / "deck" / "sih26153_technical_deck.pptx",
                        help="output .pptx (default: docs/deck/sih26153_technical_deck.pptx)")
    parser.add_argument("--img-dir", type=Path, default=REPO / "docs" / "img",
                        help="where deck:figure looks for rasters (default: docs/img)")
    parser.add_argument("--limitations", type=Path, default=LIMITATIONS_DOC,
                        help="document slide 5 is bound to (default: docs/limitations.md)")
    parser.add_argument("--architecture", type=Path, default=ARCHITECTURE_DOC,
                        help="document slides 2 and 3 are bound to — the lane split "
                             "(§2), which model the engine runs (§3) and every "
                             "measured figure (§4). Default: docs/architecture.md")
    parser.add_argument("--verify-only", action="store_true",
                        help="check an EXISTING .pptx and build nothing. The checks are "
                             "the same ones a build runs, against the bytes on disk, so "
                             "a committed or hand-edited binary can be audited without "
                             "re-rendering it. See --expect-sha256 for staleness.")
    parser.add_argument("--expect-sha256", default=None, metavar="HEX",
                        help="fail unless the .pptx has this SHA-256. The build is "
                             "byte-deterministic, so pinning the digest is what turns "
                             "'this file is current' from a claim into a check.")
    args = parser.parse_args(argv)

    facts = read_source_facts(args.architecture, args.limitations)

    if args.verify_only:
        if not args.out.exists():
            raise SystemExit(
                f"{args.out} does not exist, so there is nothing to verify. Drop "
                "--verify-only to build it."
            )
        count, size = verify(args.out, facts)
        print(f"verified (no rebuild) {args.out}")
        print(f"   {count} slides (cap {MAX_SLIDES}), {size:,} bytes")
        _report_digest(args.out, args.expect_sha256)
        stamped = stamped_source_digest(args.out)
        current = deck_source_digest(args.slides) if args.slides.exists() else None
        if stamped is None:
            print("   NOTE: this .pptx carries no source stamp — it predates "
                  f"{SOURCE_DIGEST_KEY}, so nothing here can tell it from a stale "
                  "deck. Rebuild it.")
        elif current is not None and stamped != current:
            raise SystemExit(
                f"{args.out} is STALE: it was built from a {args.slides.name} that "
                f"hashed {stamped}, and that file now hashes {current}. Every check "
                "above passed — a deck built from last week's markdown satisfies all "
                "of them and still shows a judge the slide the fix replaced. Rebuild "
                "it: python scripts/build_deck.py"
            )
        else:
            print(f"   source stamp matches {args.slides}")
        return 0

    if not args.slides.exists():
        raise SystemExit(f"{args.slides} does not exist")
    slides = parse_slides(args.slides.read_text(encoding="utf-8"))
    if not slides:
        raise SystemExit(
            f"{args.slides} contains no '## Slide N — title' headings, so there is "
            "nothing to build. This script never invents slide content."
        )
    print(f"{args.slides} -> {len(slides)} slides")
    check_source(slides, facts.headings)
    if not args.img_dir.exists():
        print(f"   note: {args.img_dir} does not exist — deck:figure slots will render "
              "as marked placeholders, and no figure is invented")

    render(slides, args.img_dir, args.out, facts, deck_source_digest(args.slides))
    count, size = verify(args.out, facts)
    print(f"-> {args.out}")
    print(f"   {count} slides (cap {MAX_SLIDES}), {size:,} bytes")
    _report_digest(args.out, args.expect_sha256)
    return 0


def _report_digest(path: Path, expected: str | None) -> None:
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    print(f"   sha256 {digest}")
    if expected and digest != expected.strip().lower():
        raise SystemExit(
            f"{path} hashes {digest}, not the expected {expected.strip().lower()}. "
            "Either the file is not the one that was pinned (stale, or edited by "
            "hand), or docs/slides.md changed and the pin was not updated."
        )


if __name__ == "__main__":
    sys.exit(main())
