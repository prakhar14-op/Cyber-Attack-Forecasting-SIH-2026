"""The three `docs/img/` figures are claims, and these are the guards on them.

A diagram is the one part of a submission a judge reads before the prose, and it
is also the part nothing in a test suite normally touches. That asymmetry is how
this repo shipped a 2-page architecture PDF whose only "diagram" was a 7.6 pt
ASCII fence — and that fence drew `TGN encoder -> forecast head -> engine` as a
single line, which is precisely the defect the audit named: the deployed engine
scores with ONE XGBoost model, and the fused / temporal-graph stack is
evaluation-side only. A wrong picture is worse than no picture, because a reader
believes it faster.

So every fact a figure states is bound to the file that owns it, and the binding
fails in the direction that actually rots — the source file changes and the
figure does not:

- **Stages** come from `configs/data.yaml` (`stages`, whose list order IS the
  label encoding). Adding an eighth stage without redrawing Figure 3 fails.
- **Technique ids** come from `engine/technique_map.yaml` — per stage, the
  default plus every rule. Remapping `exfiltration` to a different technique
  without redrawing fails.
- **Labelled-window counts** come from the class table in
  `docs/stage_mapping.md`, which `python -m data.windows` regenerates. Both the
  machine-readable `data-*` attributes and the visible text are checked, so a
  figure cannot look right and measure wrong.
- **Greying out is derived, not decorative.** A stage is greyed *if and only if*
  its total is 0, so the day the M11 lab capture gives `lateral_movement` a
  single labelled window, the figure that still calls it empty fails.
- **AUROC** figures are bound to the MODEL THEY DESCRIBE, not to the set of
  numbers that happen to exist. Every printed AUROC sits in a `<text>` tagged
  `data-auroc-model="<the §4 row label>"` and must equal that row's value.
  Checking membership of the value set was not enough: giving the deployed
  XGBoost card the fused headline's 0.933 passed, because 0.933 is a published
  number — of a different model. That substitution is the precise overclaim
  Figure 2 exists to prevent, so it is the one this now fails on.
- **The honesty claims themselves** are guarded, not just the names and counts.
  Each disclosure sentence carries `data-claim="<key>"` and must print the
  tokens `measured_facts()` parses out of `docs/limitations.md` and
  `docs/architecture.md` — so "Fires 0/2 episodes at the 1 % FPR budget — no
  forward operating point." cannot be replaced by "Validated forward
  forecasting at 20 s and 40 s ahead." without the suite noticing. The facts are
  read from those documents rather than restated here: there is one source, and
  when it moves this module fails loudly instead of silently guarding a number
  the project has retired.
- **Module paths** named in any figure must exist. A renamed module leaves the
  figure pointing at nothing, and that is caught here rather than by a judge.

Two structural guards protect how the figures are *consumed*:
`test_every_figure_declares_a_viewbox` (the PDF builder sizes its raster window
from the viewBox and fails without one) and
`test_figures_do_not_hide_their_meaning_in_a_css_block` (GitHub's SVG sanitiser
may drop `<style>`; a figure whose fills and dashes live in stripped CSS renders
as meaningless outlines on the page a judge actually opens).

Two guards check the committed deliverable itself rather than the builder's
intent. `test_the_shipped_architecture_pdf_contains_an_embedded_image` counts
image XObjects — the old PDF had `/XObject: 0` on both pages and nothing
noticed. `test_the_shipped_architecture_pdf_was_built_from_the_current_sources`
compares the digest stamped into the PDF at build time against a digest
recomputed from the files on disk now, because "has an image" and "is two pages"
are both still true of a PDF built from a figure that has since been rewritten.
`docs/architecture.pdf` is a committed binary, so that staleness is the default
outcome of editing a figure and forgetting the rebuild.
"""

from __future__ import annotations

import re
# stdlib ElementTree, not defusedxml: the only documents parsed here are the three
# repo-owned SVGs listed below, never untrusted input, and a new dependency would
# have to be added to the offline wheel-house (`pip install --no-index
# --find-links vendor`) that the PS's offline constraint requires.
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent

IMG_DIR = REPO_ROOT / "docs" / "img"
DATAFLOW_SVG = IMG_DIR / "01-architecture-dataflow.svg"
MODEL_STACK_SVG = IMG_DIR / "02-model-stack.svg"
KILLCHAIN_SVG = IMG_DIR / "03-mitre-killchain.svg"
FIGURES = (DATAFLOW_SVG, MODEL_STACK_SVG, KILLCHAIN_SVG)

# Sources of truth. These are module attributes rather than inline literals so a
# falsifiability probe can point them at a mutated copy without touching a file
# another contributor may be editing.
CONFIG_DATA = REPO_ROOT / "configs" / "data.yaml"
TECHNIQUE_MAP = REPO_ROOT / "engine" / "technique_map.yaml"
STAGE_MAPPING = REPO_ROOT / "docs" / "stage_mapping.md"
ARCHITECTURE_MD = REPO_ROOT / "docs" / "architecture.md"
ARCHITECTURE_PDF = REPO_ROOT / "docs" / "architecture.pdf"
LIMITATIONS_MD = REPO_ROOT / "docs" / "limitations.md"

SVG_NS = "http://www.w3.org/2000/svg"

# `configs/data.yaml stage_rules`, `docs/decisions/004-m7-hard-gate.md`,
# `models/tgn.py` — any repo-relative file a figure names.
_REPO_PATH = re.compile(r"\b(?:[a-z_]+/)+[a-z0-9_.-]+\.(?:py|yaml|md)\b")
_AUROC = re.compile(r"AUROC\s+(\d\.\d+)")
_TECHNIQUE_ID = re.compile(r"\bT\d{4}\b")

# The kill-chain figure's headline counts the empty stages in words, so the
# count is legible at a glance and cannot be skimmed past. Spelled out here
# because the figure spells it out; the count itself comes from the class table.
NUMBER_WORDS = {0: "no", 1: "one", 2: "two", 3: "three",
                4: "four", 5: "five", 6: "six", 7: "seven"}
_STAGE_HOLE = re.compile(r"\b([a-z]+)-stage hole\b")

# One pattern for every place the zero-coverage stage list is written out — the
# figure's <desc>, the figure's alt text in stage_mapping.md, and that
# document's own prose. They are phrased identically ON PURPOSE so that all of
# them are checked by one rule and none of them can be the one that drifts.
_ZERO_COVERAGE_LIST = re.compile(r"Zero-coverage stages\b[^:]*:\s*([^.]*)\.")

# Phrasings that assert forward forecasting WORKS. The project's own measured
# position is that it does not: 0/2 episodes at k = 1, 4 and 8 at the shipped
# budget, and the oracle analysis shows that is a ranking limit rather than a
# threshold anyone can recalibrate. The `(?<!no )` on the last one is load-
# bearing: "no supported forward-forecast horizon" is the honest sentence and
# must stay sayable.
_FORWARD_OVERCLAIMS = (
    r"\b(?:validated|verified|proven|demonstrated)\s+forward[-\s]forecast",
    r"\bforward\s+forecasting\s+at\b",
    r"\bforecasts?\s+\d+\s*s(?:econds)?\s+ahead\b",
    r"(?<!no )\bsupported\s+forward[-\s]forecast(?:ing)?\s+(?:operating\s+point|horizon)\b",
)

# --------------------------------------------------------------------------- #
# the measured facts the figures are allowed to state
#
# Parsed out of the documents that own them rather than restated here. Two
# things follow, and both are the point:
#   * a figure that stops printing the measured value fails, and
#   * if one of these sentences MOVES, this module fails at collection with a
#     message naming the fact and its file — instead of quietly going on to
#     guard a number the project has since retired, which is the failure mode
#     this whole file exists to stop.
# Values are matched case-insensitively in figures because the figures shout
# some of them for emphasis ("a verified RANKING result").
# --------------------------------------------------------------------------- #
_FACT_SOURCES: dict[str, tuple[Path, str]] = {
    "deployed_scorer": (
        ARCHITECTURE_MD, r"The deployed scorer is a \*\*(single XGBoost model)\*\*"),
    "fusion_status": (
        ARCHITECTURE_MD,
        r"headline in §4 is the \*\*eval-side\*\* model and (does not run in the engine)"),
    "kstep_capability": (
        LIMITATIONS_MD, r"The k-step head has a (ranking) signal"),
    "kstep_episodes": (
        LIMITATIONS_MD, r"\*\*(0/\d+) episodes at k=1, 4 and 8 alike\*\*"),
    "fpr_budget": (
        LIMITATIONS_MD, r"but at the (\d+ %) FPR budget its operating point collapses"),
    "nowcast_overlap": (
        LIMITATIONS_MD,
        r"the k-step target is \*\*(\d+[–-]\d+ %) identical to the nowcast target\*\*"),
}


@dataclass(frozen=True)
class Claim:
    """A disclosure a figure must make, and the measured facts it must state.

    `key` is the `data-claim` attribute carrying it. Exactly one element per
    figure may carry each key: a claim split across two elements is wrapped in a
    <g> so the sentence and its caveat cannot be separated by an edit that only
    touches one line.
    """

    key: str
    figures: tuple[Path, ...]
    facts: tuple[str, ...]
    why: str


CLAIMS: tuple[Claim, ...] = (
    Claim(
        "deployed-single-model", (DATAFLOW_SVG, MODEL_STACK_SVG), ("deployed_scorer",),
        "The audit retired the cascade claim after proving engine/predict.py has exactly "
        "one load_model and one predict_proba. A figure that re-inflates the deployed "
        "scorer is the same overclaim returning through the picture."),
    Claim(
        "fusion-not-deployed", (DATAFLOW_SVG, MODEL_STACK_SVG), ("fusion_status",),
        "0.933 is the fused, evaluation-side headline. A figure that prints it without "
        "saying it does not run in the engine credits the shipped product with a number "
        "the shipped product does not produce."),
    Claim(
        "kstep-ranking-only", (DATAFLOW_SVG, MODEL_STACK_SVG),
        ("kstep_capability", "nowcast_overlap"),
        "The k-step ranking result is real but its target is 93-96 % identical to the "
        "nowcast target, so ranking it well is close to ranking the PRESENT well. Without "
        "that caveat a reader takes a ranking number as forward evidence, which is exactly "
        "what it is not — so the caveat travels in the same element as the claim."),
    Claim(
        "kstep-no-operating-point", (MODEL_STACK_SVG,),
        ("kstep_episodes", "fpr_budget"),
        "At the shipped budget the k-step head fires 0 of 2 episodes at k = 1, 4 and 8 "
        "alike. There is no supported forward-forecast operating point, and the figure "
        "has to keep saying so in numbers."),
)


# --------------------------------------------------------------------------- #
# readers — no caching: the files are tiny, and an lru_cache would make the
# module attributes above un-monkeypatchable, which is how the probe proves
# these guards can fail.
# --------------------------------------------------------------------------- #
def configured_stages() -> list[str]:
    """`configs/data.yaml` `stages`, in order (the order IS the label encoding)."""
    stages = yaml.safe_load(CONFIG_DATA.read_text(encoding="utf-8"))["stages"]
    assert stages, f"{CONFIG_DATA} declares no stages"
    return [str(s) for s in stages]


def mapped_techniques() -> dict[str, set[str]]:
    """stage -> every ATT&CK id `engine/technique_map.yaml` can emit for it.

    Both the stage default and every rule, because the engine reaches either
    one. Keys that are not configured stages (`unclassified` — the outcome when
    no rule fired) are not kill-chain stages and are excluded deliberately.
    """
    raw = yaml.safe_load(TECHNIQUE_MAP.read_text(encoding="utf-8"))
    out: dict[str, set[str]] = {}
    for stage in configured_stages():
        assert stage in raw, (
            f"{TECHNIQUE_MAP.name} has no entry for the configured stage {stage!r}"
        )
        entry = raw[stage] or {}
        ids = {entry.get("default")}
        ids |= {rule.get("technique") for rule in entry.get("rules", []) or []}
        out[stage] = {i for i in ids if i}
    return out


def class_counts() -> dict[str, tuple[int, int, int, int]]:
    """stage -> (train, val, test, total) from the class table in stage_mapping.md.

    The zero-coverage rows carry a trailing `**(!) no data**` cell, so extra
    cells are tolerated; the four counts are positional and required.
    """
    stages = set(configured_stages())
    out: dict[str, tuple[int, int, int, int]] = {}
    for line in STAGE_MAPPING.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line.startswith("|"):
            continue
        cells = [c.strip().strip("`").strip("*").strip() for c in line.strip("|").split("|")]
        if cells[0] not in stages or len(cells) < 5:
            continue
        try:
            counts = tuple(int(c.replace(",", "")) for c in cells[1:5])
        except ValueError:
            continue
        out[cells[0]] = counts  # type: ignore[assignment]
    assert out, f"no class-count rows found in {STAGE_MAPPING}"
    return out


def published_auroc_by_model() -> dict[str, str]:
    """model row label -> its AUROC, from the §4 model-comparison table.

    Keyed by the MODEL, not collected into a set. A set answers "is 0.933 a
    number this project published?", to which the answer is yes — it is the
    fused model's. The question a figure has to survive is "is 0.933 the number
    for the model this card describes?", and only a mapping can answer that.
    """
    text = ARCHITECTURE_MD.read_text(encoding="utf-8")
    section = re.search(r"^## 4\..*?(?=^## 5\.)", text, re.DOTALL | re.MULTILINE)
    assert section, "docs/architecture.md has no '## 4.' section ending at '## 5.'"
    rows: dict[str, str] = {}
    model_col = auroc_col = None
    for line in section.group(0).splitlines():
        line = line.strip()
        if not line.startswith("|"):
            continue
        cells = [c.strip().replace("*", "").strip() for c in line.strip("|").split("|")]
        if auroc_col is None:
            if "AUROC" in cells and "model" in cells:
                model_col, auroc_col = cells.index("model"), cells.index("AUROC")
            continue
        if max(model_col, auroc_col) >= len(cells):
            continue
        try:
            value = f"{float(cells[auroc_col]):.3f}"
        except ValueError:
            continue  # the |---|---| separator row
        label = cells[model_col]
        assert label not in rows, (
            f"the §4 model-comparison table lists {label!r} twice; a figure bound to "
            "that row cannot tell which of the two it is quoting"
        )
        rows[label] = value
    assert rows, "no model/AUROC rows parsed from the §4 model-comparison table"
    return rows


def measured_facts() -> dict[str, str]:
    """The load-bearing figures of this project, read from the docs that own them.

    A missing match is a hard failure, not a skip. These sentences are what the
    diagrams are allowed to assert; if one has been reworded the guard below is
    no longer guarding the current claim, and finding that out at test time is
    the entire point.
    """
    facts: dict[str, str] = {}
    for name, (path, pattern) in _FACT_SOURCES.items():
        assert path.exists(), f"{path} is missing; {name!r} has no source to be read from"
        match = re.search(pattern, " ".join(path.read_text(encoding="utf-8").split()))
        assert match, (
            f"cannot find the measured fact {name!r} in {path.name} using {pattern!r}. "
            "Either that sentence was reworded or the fact itself changed. Do NOT relax "
            "this pattern to make the suite green: re-read the document, decide what the "
            "measured claim now is, and update the figures and _FACT_SOURCES together."
        )
        facts[name] = match.group(1)
    return facts


def claim_element(path: Path, key: str) -> ET.Element:
    """The single element in `path` carrying `data-claim="key"`.

    Exactly one, so that a claim cannot be quietly duplicated into a second
    element that says something else, and so that deleting the disclosure fails
    here rather than passing because some other element happened to mention it.
    """
    found = [el for el in svg_root(path).iter() if el.attrib.get("data-claim") == key]
    assert len(found) == 1, (
        f"{path.name} carries {len(found)} elements with data-claim={key!r}; expected "
        "exactly 1. A disclosure this figure is required to make is missing, or has "
        "been split in two so that half of it can be edited away."
    )
    return found[0]


def stage_names_in(text: str) -> set[str]:
    """Configured stage names appearing as whole words in `text`."""
    return {s for s in configured_stages() if re.search(rf"\b{re.escape(s)}\b", text)}


def svg_root(path: Path) -> ET.Element:
    return ET.parse(path).getroot()


def element_text(element: ET.Element) -> str:
    """All text under `element`, whitespace-normalised."""
    return " ".join("".join(element.itertext()).split())


def figure_text(path: Path) -> str:
    return element_text(svg_root(path)) + " " + " ".join(
        v for el in svg_root(path).iter() for v in el.attrib.values()
    )


def stage_groups() -> dict[str, ET.Element]:
    """`data-stage` -> its <g> in the kill-chain figure."""
    groups = {
        el.attrib["data-stage"]: el
        for el in svg_root(KILLCHAIN_SVG).iter(f"{{{SVG_NS}}}g")
        if "data-stage" in el.attrib
    }
    assert groups, f"{KILLCHAIN_SVG.name} has no data-stage groups"
    return groups


# --------------------------------------------------------------------------- #
# structure
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("path", FIGURES, ids=lambda p: p.name)
def test_every_figure_exists_and_is_well_formed_xml(path: Path):
    assert path.exists(), (
        f"{path} is missing. The architecture deliverable shipped with zero figures "
        "once already; a reference to a figure that is not there is the same defect "
        "with extra steps."
    )
    root = svg_root(path)
    assert root.tag == f"{{{SVG_NS}}}svg", f"{path.name} root element is {root.tag}, not <svg>"


@pytest.mark.parametrize("path", FIGURES, ids=lambda p: p.name)
def test_every_figure_declares_a_viewbox(path: Path):
    """scripts/build_architecture_pdf.py sizes its raster window from the viewBox;
    without one the figure cannot be embedded in the PDF at all."""
    assert "viewBox" in svg_root(path).attrib, (
        f"{path.name} has no viewBox. The PDF builder raises on this rather than "
        "guessing a size, so the figure would never reach the deliverable."
    )


@pytest.mark.parametrize("path", FIGURES, ids=lambda p: p.name)
def test_every_figure_carries_a_title_for_screen_readers(path: Path):
    title = svg_root(path).find(f"{{{SVG_NS}}}title")
    assert title is not None and (title.text or "").strip(), (
        f"{path.name} has no non-empty <title>; the figure is then unreadable to "
        "anyone using a screen reader and unlabelled in any SVG index."
    )


@pytest.mark.parametrize("path", FIGURES, ids=lambda p: p.name)
def test_figures_do_not_hide_their_meaning_in_a_css_block(path: Path):
    """Fills, strokes and dash patterns must be presentation attributes.

    GitHub's SVG sanitiser may strip `<style>`, and in these figures the outline
    style is what separates "runs in the deployed engine" from "evaluation-side
    only" and "zero labelled windows". A figure that loses that distinction on
    the repository page is a figure that misleads exactly where it matters.
    """
    assert svg_root(path).find(f".//{{{SVG_NS}}}style") is None, (
        f"{path.name} contains a <style> block. Move fills/strokes/dashes onto the "
        "elements as presentation attributes: a sanitiser that drops the CSS must "
        "not be able to drop the meaning with it."
    )


# --------------------------------------------------------------------------- #
# the kill-chain figure is bound to its sources
# --------------------------------------------------------------------------- #
def test_the_killchain_figure_names_exactly_the_configured_stages():
    """Exactly, and in the label-encoding order of configs/data.yaml."""
    expected = configured_stages()
    drawn = [
        el.attrib["data-stage"]
        for el in svg_root(KILLCHAIN_SVG).iter(f"{{{SVG_NS}}}g")
        if "data-stage" in el.attrib
    ]
    assert drawn == expected, (
        f"{KILLCHAIN_SVG.name} draws {drawn} but configs/data.yaml declares "
        f"{expected}. The list order in that config IS the label encoding, so the "
        "figure has to follow it — and a stage added to the config without being "
        "drawn is a kill-chain stage the submission claims to cover and does not "
        "show."
    )
    # The stage name must be visible, not only in an attribute a reader cannot see.
    for stage, group in stage_groups().items():
        assert stage in element_text(group), (
            f"{stage!r} is tagged in {KILLCHAIN_SVG.name} but never printed in its box"
        )


def test_the_killchain_figure_names_exactly_the_mapped_techniques():
    expected = mapped_techniques()
    for stage, group in stage_groups().items():
        drawn = set(_TECHNIQUE_ID.findall(element_text(group)))
        assert drawn == expected[stage], (
            f"{KILLCHAIN_SVG.name}: stage {stage!r} shows {sorted(drawn) or 'no technique'} "
            f"but engine/technique_map.yaml can emit {sorted(expected[stage]) or 'none'}. "
            "A figure that names a technique the engine never emits — or omits one it "
            "does — is an ATT&CK mapping claim with nothing behind it."
        )


def test_the_killchain_counts_match_the_class_table_in_stage_mapping():
    counts = class_counts()
    for stage, group in stage_groups().items():
        assert stage in counts, (
            f"{stage!r} is drawn in {KILLCHAIN_SVG.name} but has no row in the class "
            f"table of {STAGE_MAPPING.name}"
        )
        train, val, test, total = counts[stage]
        attrs = group.attrib
        assert (attrs.get("data-train"), attrs.get("data-val"), attrs.get("data-test"),
                attrs.get("data-labelled-windows")) == (str(train), str(val), str(test),
                                                        str(total)), (
            f"{KILLCHAIN_SVG.name}: {stage!r} is tagged "
            f"{attrs.get('data-train')}/{attrs.get('data-val')}/{attrs.get('data-test')}"
            f" (total {attrs.get('data-labelled-windows')}) but the class table says "
            f"{train}/{val}/{test} (total {total}). That table is regenerated by "
            "`python -m data.windows`; the figure has to be regenerated with it."
        )
        text = element_text(group)
        for label, value in (("train", train), ("val", val), ("test", test)):
            assert re.search(rf"\b{label}\s+{value}\b", text), (
                f"{KILLCHAIN_SVG.name}: {stage!r} does not PRINT '{label} {value}'. The "
                "data attribute agreeing with the class table while the visible number "
                "disagrees is the worst of both worlds."
            )


def test_zero_coverage_stages_are_greyed_out_and_say_so():
    """Greying is derived from the counts, not chosen by hand.

    The day the M11 lab capture gives one of these stages a labelled window, a
    figure that still calls it empty fails here — and a stage that silently loses
    its labels fails too.
    """
    counts = class_counts()
    for stage, group in stage_groups().items():
        total = counts[stage][3]
        coverage = group.attrib.get("data-coverage")
        assert coverage in {"none", "labelled"}, (
            f"{stage!r} has data-coverage={coverage!r}; expected 'none' or 'labelled'"
        )
        assert (coverage == "none") == (total == 0), (
            f"{KILLCHAIN_SVG.name}: {stage!r} is marked data-coverage={coverage!r} but "
            f"the class table gives it {total} labelled windows. Coverage in this figure "
            "is derived from that table, never asserted by hand."
        )
        rect = group.find(f"{{{SVG_NS}}}rect")
        assert rect is not None, f"{stage!r} has no box"
        dashed = "stroke-dasharray" in rect.attrib
        assert dashed == (total == 0), (
            f"{KILLCHAIN_SVG.name}: {stage!r} box dashed={dashed} but total={total}. "
            "The dash is the greyscale-safe carrier of 'no labelled windows'; it must "
            "track the data, or the figure lies on a black-and-white printout."
        )
        if total == 0:
            assert "NO LABELLED WINDOWS" in element_text(group), (
                f"{stage!r} has zero labelled windows but the box does not say so in "
                "words. Colour alone fails a projector and a greyscale print."
            )

    assert any(c[3] == 0 for c in counts.values()), (
        "no stage has zero labelled windows any more — the limitation this figure "
        "exists to make visible is gone, so redraw it (and update the footnote) "
        "rather than leaving stale greying in place"
    )


def test_the_killchain_figure_agrees_with_itself_about_which_stages_are_empty():
    """Headline, greying, footnote, <desc> and stage_mapping.md, against ONE set.

    This figure shipped saying "the two-stage hole we do not hide" in 19 pt bold
    over THREE grey boxes, a footnote naming three and a <desc> naming three. The
    one figure whose purpose is to prove the project discloses its gaps got its
    own gap count wrong in the largest text on the page.

    The guard that was supposed to stop that could not fail. It did
    `footnote = figure_text(KILLCHAIN_SVG)` and asserted each empty stage
    appeared in it — but `figure_text` returns every element's text PLUS every
    attribute value in the document, and each empty stage is its own
    `data-stage="recon"`. The assertion was satisfied by the markup that draws
    the box, so deleting the footnote entirely would have passed. Every surface
    below is therefore scoped to the element that actually carries it.
    """
    empty = sorted(s for s, c in class_counts().items() if c[3] == 0)
    assert empty, "no stage has zero labelled windows; this figure needs redrawing"

    greyed = sorted(s for s, g in stage_groups().items()
                    if g.attrib.get("data-coverage") == "none")
    assert greyed == empty, (
        f"{KILLCHAIN_SVG.name} greys out {greyed} but the class table says the empty "
        f"stages are {empty}"
    )

    # 1. the headline — the largest text on the page, and the one that was wrong.
    headline = element_text(claim_element(KILLCHAIN_SVG, "zero-coverage-headline"))
    counted = _STAGE_HOLE.search(headline)
    assert counted, (
        f"the headline of {KILLCHAIN_SVG.name} no longer says how many stages are "
        f"empty (it reads {headline!r}). It has to: a judge counts the grey boxes "
        "against it."
    )
    assert counted.group(1) == NUMBER_WORDS[len(empty)], (
        f"{KILLCHAIN_SVG.name} headlines a {counted.group(1)!r}-stage hole but "
        f"{len(empty)} stages have zero labelled windows ({', '.join(empty)}). The "
        "headline is the first thing read on the one figure that exists to prove this "
        "project discloses its gaps; it counting them wrong is worse than not counting."
    )

    # 2. the footnote — scoped to the disclosure group, not the whole document.
    footnote = element_text(claim_element(KILLCHAIN_SVG, "zero-coverage-footnote"))
    assert stage_names_in(footnote) == set(empty), (
        f"the footnote of {KILLCHAIN_SVG.name} names {sorted(stage_names_in(footnote))} "
        f"but the empty stages are {empty}. The footnote is what turns a grey box into "
        "a disclosed limitation; naming fewer stages than are greyed leaves a gap shown "
        "but unexplained, and naming more invents one."
    )

    # 3. the <desc> and 4. the document that embeds the figure — same phrasing,
    #    so one pattern checks every place the list is written out.
    written_out = _ZERO_COVERAGE_LIST.findall(
        element_text(svg_root(KILLCHAIN_SVG).find(f"{{{SVG_NS}}}desc"))
    ) + _ZERO_COVERAGE_LIST.findall(
        " ".join(STAGE_MAPPING.read_text(encoding="utf-8").split())
    )
    assert len(written_out) == 3, (
        f"expected the zero-coverage stage list in 3 places (the figure's <desc>, its "
        f"alt text in {STAGE_MAPPING.name}, and that document's prose) but found "
        f"{len(written_out)}. Each is a surface a reader may meet on its own."
    )
    for listed in written_out:
        assert stage_names_in(listed) == set(empty), (
            f"a zero-coverage list reads {listed!r} — that is "
            f"{sorted(stage_names_in(listed))}, not {empty}. Screen-reader text and alt "
            "text are the version some readers get instead of the picture, so they "
            "cannot be the copy that goes stale."
        )


# --------------------------------------------------------------------------- #
# figures must not out-run the repo
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("path", FIGURES, ids=lambda p: p.name)
def test_every_repo_path_named_in_a_figure_exists(path: Path):
    named = sorted(set(_REPO_PATH.findall(figure_text(path))))
    assert named, f"{path.name} names no repo file — it cannot be traced to any code"
    missing = [p for p in named if not (REPO_ROOT / p).exists()]
    assert not missing, (
        f"{path.name} points at files that do not exist: {missing}. A figure is the "
        "first thing a judge reads and the last thing a rename updates."
    )


@pytest.mark.parametrize("path", FIGURES, ids=lambda p: p.name)
def test_every_auroc_printed_in_a_figure_belongs_to_the_model_it_is_printed_next_to(
    path: Path,
):
    """Attribution, not membership of the set of published numbers.

    The earlier guard asked only whether a printed AUROC appeared anywhere in
    the §4 table's AUROC column. Changing the DEPLOYED XGBoost card from 0.872
    to 0.933 passed it — 0.933 is published, for the fused evaluation-side model
    — while handing the shipped engine a headline the shipped engine does not
    produce. That is the single overclaim this figure exists to prevent, so each
    number is now bound to the row it describes.
    """
    published = published_auroc_by_model()
    root = svg_root(path)
    attributed = 0

    for element in root.iter(f"{{{SVG_NS}}}text"):
        model = element.attrib.get("data-auroc-model")
        printed = _AUROC.findall(element_text(element))
        if model is None:
            assert not printed, (
                f"{path.name} prints AUROC {printed} in a <text> with no "
                "data-auroc-model. An unattributed number is one nobody can check "
                "against the model it is claimed for — tag it with its §4 row label."
            )
            continue
        assert model in published, (
            f"{path.name} attributes an AUROC to {model!r}, which is not a row of the "
            f"model-comparison table in docs/architecture.md §4 (rows: "
            f"{sorted(published)}). Either the row was renamed or retired, or the "
            "figure is quoting a model the project no longer measures."
        )
        assert printed, (
            f"{path.name} has a <text> tagged data-auroc-model={model!r} that prints no "
            "AUROC. The tag is what makes the number checkable; an empty one is a guard "
            "pointing at nothing."
        )
        for value in printed:
            assert f"{float(value):.3f}" == published[model], (
                f"{path.name} prints 'AUROC {value}' for {model!r}, but §4 measures "
                f"{published[model]} for that model. The nearest published number that "
                "IS {value} belongs to a different row — giving one model another "
                "model's score is the overclaim this figure exists to prevent, and it "
                "is invisible to anyone who only checks that the number exists somewhere."
            )
        attributed += len(printed)

    everywhere = _AUROC.findall(element_text(root))
    assert len(everywhere) == attributed, (
        f"{path.name} prints {len(everywhere)} AUROC value(s) but only {attributed} sit "
        "in an attributed <text>. A number in a <title>, <desc> or a bare tspan escapes "
        "the binding above, so it must not be there."
    )


# --------------------------------------------------------------------------- #
# the claims — what these figures exist to say
# --------------------------------------------------------------------------- #
def test_the_measured_facts_behind_the_figure_claims_are_still_where_the_guards_read_them():
    """Fails loudly if a source sentence moved, rather than guarding a dead fact.

    Every claim below is checked against a value parsed live out of
    docs/limitations.md or docs/architecture.md. If one of those sentences is
    reworded, the parse fails here — with the fact's name and its file — instead
    of the claim guards quietly continuing to enforce whatever this module last
    remembered.
    """
    facts = measured_facts()
    assert set(facts) == set(_FACT_SOURCES), sorted(set(_FACT_SOURCES) - set(facts))
    for claim in CLAIMS:
        missing = sorted(set(claim.facts) - set(facts))
        assert not missing, f"claim {claim.key!r} names unknown facts {missing}"


@pytest.mark.parametrize(
    "claim,path",
    [(c, p) for c in CLAIMS for p in c.figures],
    ids=lambda v: v.key if isinstance(v, Claim) else v.name,
)
def test_every_figure_states_its_required_disclosures_in_measured_numbers(
    claim: Claim, path: Path
):
    """The honesty statements, bound to the facts — MAJOR 3.

    Names, ids, counts, paths and AUROCs were all guarded; the deployed-versus-
    evaluation sentences the figures exist to make were not. Replacing Figure 2's
    k-step disclosure with "Validated forward forecasting at 20 s and 40 s
    ahead." left the suite fully green while converting the figure into precisely
    the overclaim four rounds of work removed. The disclosure element now has to
    print the measured tokens, so a sentence that stops stating them fails
    whatever it says instead.
    """
    facts = measured_facts()
    stated = element_text(claim_element(path, claim.key))
    for fact in claim.facts:
        value = facts[fact]
        assert value.lower() in stated.lower(), (
            f"{path.name}: the element carrying data-claim={claim.key!r} reads\n"
            f"  {stated!r}\n"
            f"but it must state the measured {fact} = {value!r} "
            f"({_FACT_SOURCES[fact][0].name}).\n\nWhy this claim is required: {claim.why}"
        )


@pytest.mark.parametrize("path", FIGURES, ids=lambda p: p.name)
def test_no_figure_claims_that_forward_forecasting_works(path: Path):
    """A backstop for a claim added somewhere no data-claim tag guards.

    The positive guard above binds the disclosure elements. This one scans
    everything a reader can see, because the cheapest way to reintroduce the
    overclaim is not to edit a guarded sentence but to add an unguarded one.
    """
    visible = element_text(svg_root(path))
    for pattern in _FORWARD_OVERCLAIMS:
        match = re.search(pattern, visible, re.IGNORECASE)
        assert match is None, (
            f"{path.name} claims forward forecasting works: {match.group(0)!r}.\n"
            "At the shipped 1 % FPR budget the k-step head fires 0 of 2 episodes at "
            "k = 1, 4 AND 8, and the oracle analysis shows that is a ranking limit, not "
            "a threshold that can be recalibrated (docs/limitations.md). There is no "
            "supported forward-forecast operating point. The lead time this project "
            "does claim comes from the horizon-0 classifier, not from forecasting ahead."
        )


# --------------------------------------------------------------------------- #
# the figures have to be reachable from the documents that need them
# --------------------------------------------------------------------------- #
def test_the_architecture_document_embeds_the_dataflow_figure():
    text = ARCHITECTURE_MD.read_text(encoding="utf-8")
    assert f"img/{DATAFLOW_SVG.name}" in text, (
        "docs/architecture.md no longer embeds the dataflow figure. It is the graded "
        "2-page deliverable and it shipped once as unbroken prose; the builder now "
        "refuses to produce a figure-less PDF, so this would fail the build anyway."
    )
    assert f"img/{MODEL_STACK_SVG.name}" in text, (
        "docs/architecture.md no longer points at the model-stack figure, which is "
        "where the deployed-vs-evaluation split is stated per component."
    )


def test_the_stage_mapping_document_embeds_the_killchain_figure():
    text = STAGE_MAPPING.read_text(encoding="utf-8")
    assert f"img/{KILLCHAIN_SVG.name}" in text, (
        "docs/stage_mapping.md no longer embeds the kill-chain figure — the one place "
        "the two empty stages are visible rather than buried in a table row."
    )


def test_the_shipped_architecture_pdf_contains_an_embedded_image():
    """The committed deliverable, not the builder's intention.

    `docs/architecture.pdf` had `/XObject: 0` on both pages for as long as it
    existed, because the builder printed its HTML from a temp directory where the
    relative image paths resolved to nothing. Nothing in the suite noticed.
    """
    from pypdf import PdfReader

    assert ARCHITECTURE_PDF.exists(), (
        f"{ARCHITECTURE_PDF} is missing — run "
        "`python scripts/build_architecture_pdf.py`"
    )
    reader = PdfReader(str(ARCHITECTURE_PDF))
    images = 0
    for page in reader.pages:
        resources = page.get("/Resources")
        if resources is None:
            continue
        xobjects = resources.get_object().get("/XObject")
        if xobjects is None:
            continue
        images += sum(
            1 for ref in xobjects.get_object().values()
            if ref.get_object().get("/Subtype") == "/Image"
        )
    assert images >= 1, (
        "docs/architecture.pdf contains ZERO embedded images. The figure did not "
        "survive the print step (or the PDF predates the fix): rebuild with "
        "`python scripts/build_architecture_pdf.py`, which asserts the same thing."
    )
    assert len(reader.pages) <= 2, (
        f"docs/architecture.pdf is {len(reader.pages)} pages; the problem statement "
        "caps the architecture document at 2."
    )


def test_the_shipped_architecture_pdf_was_built_from_the_current_sources():
    """The graded PDF is a committed binary, so staleness is the DEFAULT.

    "Contains an image" and "is at most two pages" are both still true of a PDF
    built from a figure that has since been rewritten: a contributor can edit
    docs/img/01-architecture-dataflow.svg, skip the rebuild, and ship a
    deliverable showing a figure that no longer exists in the repo. Nothing
    noticed.

    `scripts/build_architecture_pdf.py` now stamps a SHA-256 of everything that
    reaches the printed page — the markdown plus every image it embeds — into
    the PDF's Info dictionary. Here that digest is recomputed from the files on
    disk and compared. The digest function is IMPORTED from the builder rather
    than reimplemented, so the guard and the build can never disagree about
    what counts as an input.
    """
    from pypdf import PdfReader

    from scripts.build_architecture_pdf import (
        SOURCE_DIGEST_KEY,
        architecture_source_digest,
        referenced_image_paths,
    )

    assert ARCHITECTURE_PDF.exists(), (
        f"{ARCHITECTURE_PDF} is missing — run "
        "`python scripts/build_architecture_pdf.py`"
    )
    stamped = (PdfReader(str(ARCHITECTURE_PDF)).metadata or {}).get(SOURCE_DIGEST_KEY)
    assert stamped, (
        f"docs/architecture.pdf carries no {SOURCE_DIGEST_KEY} — it predates the "
        "freshness stamp, so there is no way to tell which version of the figures it "
        "was printed from. Rebuild with `python scripts/build_architecture_pdf.py`."
    )
    current = architecture_source_digest()
    assert stamped == current, (
        "docs/architecture.pdf is STALE. It was built from a different version of "
        f"{[p.name for p in [ARCHITECTURE_MD, *referenced_image_paths()]]} "
        f"(stamped {stamped[:16]}…, current {current[:16]}…). The PDF is the graded "
        "deliverable and it is a committed binary, so it is now showing a figure that "
        "is not the one in this repo. Rebuild it: "
        "`python scripts/build_architecture_pdf.py`."
    )
