"""Guards on the product screenshots in `docs/img/screenshots/`.

WHAT THIS MODULE IS DEFENDING
A screenshot is the most persuasive thing this repository can publish and the
least self-explanatory. Every image under `docs/img/screenshots/` was taken
against the DEMO model — a toy fitted by `scripts/bootstrap_demo_artifacts.py`
from one hand-authored synthetic capture, which it has memorised. Its
probabilities, alert counts, thresholds and stage labels look exactly like
results and are not results. An image published without that context is a false
claim made in pictures, which is this project's named failure mode in the medium
it is hardest to audit.

So the provenance is required to exist in three places and each is checked here:

- IN THE FRAME. `scripts/capture_screenshots.py` declares, per shot, which of
  `app/panels.py`'s demo marks must be inside the crop, reads the cropped
  region's own text back out of the DOM after the rect is computed, and refuses
  to write a frame that does not contain them. Whether that held is recorded per
  image as `provenance_in_frame`, and a shot that cannot carry a mark must say
  why in `no_marker_reason` — `test_every_shot_carries_a_demo_mark_or_argues_why_not`
  is what stops "why" from being left blank.
- IN THE MANIFEST. `manifest.json` carries a caption and a SHA-256 per image.
  The digest is the load-bearing part: a caption bound to a file is only worth
  something if the file cannot be swapped underneath it, and
  `test_every_committed_screenshot_has_documented_provenance` re-hashes the bytes
  on disk.
- IN THE README. `docs/img/screenshots/README.md` states in prose what these are
  and are not, and it must NAME every committed image — a picture that nothing
  in that file mentions is a picture nobody argued about.

WHAT IS GATED, AND HOW
Everything above reads files. Only `test_a_capture_run_produces_the_files_it_says`
needs a browser and a Streamlit server, and it is gated the way this repo gates
optional tooling (`tests/test_build_deck.py::requires_pptx`): a `skipif` whose
reason names the command that turns it on. It is opt-in via the environment
rather than merely browser-detected, because it starts a server, runs the
pipeline and drives headless Edge — two minutes on an idle machine, and this one
is not idle.

The file-reading tests skip — naming the capture command — while the directory
holds no manifest, which is the state of a checkout that has not run the capture
yet. They do NOT skip once one image exists: the moment a PNG is committed, its
provenance is mandatory.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

SCRIPT = REPO_ROOT / "scripts" / "capture_screenshots.py"
SHOT_DIR = REPO_ROOT / "docs" / "img" / "screenshots"
MANIFEST = SHOT_DIR / "manifest.json"
README = SHOT_DIR / "README.md"

CAPTURE_CMD = "python scripts/capture_screenshots.py"
RUN_E2E_ENV = "SIH26_CAPTURE_SCREENSHOTS"


# --------------------------------------------------------------------- loading


def capture_module():
    """Import `scripts/capture_screenshots.py` by path.

    By path, not as `scripts.capture_screenshots`: `scripts/` is not a package
    and putting it on sys.path for the whole suite to satisfy one import is how
    module-name collisions start. This is the same technique `tests/_stubs.py`
    uses for `scripts/fetch_artifacts.py`.

    The module is registered in `sys.modules` BEFORE it is executed. That is not
    tidiness — `@dataclass` resolves its annotations through
    `sys.modules[cls.__module__].__dict__`, so a module executed without being
    registered raises `AttributeError: 'NoneType' object has no attribute
    '__dict__'` on the first dataclass. Measured while writing this.
    """
    if not SCRIPT.exists():
        pytest.fail(f"{SCRIPT.relative_to(REPO_ROOT)} is missing", pytrace=False)
    name = "_sih26_capture_screenshots"
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, SCRIPT)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)  # type: ignore[union-attr]
    except Exception:
        del sys.modules[name]
        raise
    return module


def manifest_or_skip() -> dict:
    """The capture manifest, or a skip naming the command that writes it."""
    if not MANIFEST.exists():
        pngs = sorted(p.name for p in SHOT_DIR.glob("*.png")) if SHOT_DIR.is_dir() else []
        if pngs:
            pytest.fail(
                f"{SHOT_DIR.relative_to(REPO_ROOT).as_posix()} holds {pngs} but no "
                f"{MANIFEST.name}. These images were taken against the DEMO model and "
                "nothing in this directory records that. Re-run "
                f"`{CAPTURE_CMD}`, or delete them.", pytrace=False)
        pytest.skip(
            f"no screenshots captured on this machine yet — run `{CAPTURE_CMD}` "
            f"(it writes {MANIFEST.relative_to(REPO_ROOT).as_posix()})")
    return json.loads(MANIFEST.read_text(encoding="utf-8"))


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def committed_pngs() -> list[Path]:
    return sorted(SHOT_DIR.glob("*.png")) if SHOT_DIR.is_dir() else []


# ------------------------------------------------------- the script's own shape


def test_the_capture_script_is_importable_and_declares_its_shots():
    """It imports with no browser, no server and no side effects, and has shots.

    Importable matters beyond hygiene: every other test in this module reads the
    shot declarations out of it, and `docs/img/screenshots/README.md` describes
    the frames it produces. A script that only parses when a browser is present
    could not be checked by any of them.
    """
    module = capture_module()
    assert module.SHOTS, "capture_screenshots.SHOTS is empty — it photographs nothing"
    assert callable(module.main)
    assert callable(module.find_edge)
    names = [shot.name for shot in module.SHOTS]
    assert len(names) == len(set(names)), f"duplicate shot names: {names}"
    for shot in module.SHOTS:
        assert shot.name and shot.title and shot.caption, f"{shot.name}: incomplete spec"


def test_every_shot_carries_a_demo_mark_or_argues_why_not():
    """No frame may exist without an argued provenance.

    A shot either declares demo marks that must be INSIDE its crop (the strong
    answer — the disclosure travels with the pixels), or it states, in
    `no_marker_reason`, why the app renders none there and what carries it
    instead. The one thing it may not do is neither, which is how a picture ends
    up published with its context left to the reader's goodwill.
    """
    module = capture_module()
    unargued = [s.name for s in module.SHOTS if not s.requires and not s.no_marker_reason]
    assert not unargued, (
        f"these shots declare no in-frame demo mark and give no reason: {unargued}. "
        "Either require a mark from capture_screenshots.MARKERS, or write the "
        "no_marker_reason that says what carries the provenance instead.")


def test_every_caption_the_script_writes_says_which_model_took_the_picture():
    """The caption is the fallback disclosure, so it must actually disclose."""
    module = capture_module()
    silent = [s.name for s in module.SHOTS if "demo" not in s.caption.lower()]
    assert not silent, (
        f"these shots' captions never say the images are of the demo model: {silent}. "
        "The caption is what travels into the manifest and the README for a crop the "
        "banner does not reach.")


def test_every_mark_the_script_requires_is_a_string_the_app_still_uses():
    """The required marks are live `app/panels.py` constants, not stale copies.

    `MARKERS` is built from panels attributes, so the TEXT cannot drift. What can
    drift is the app dropping a mark it used to render: the constant would still
    exist, this script would still demand it in frame, and every capture would
    abort with a message about a mark nobody removed on purpose. So each required
    mark is traced back to its panels attribute name and that name must still be
    referenced by the app — in `app/streamlit_app.py`, or in `app/panels.py`
    somewhere other than its own definition.
    """
    module = capture_module()
    from app import panels

    attribute_of = {}
    for attribute, value in vars(panels).items():
        if isinstance(value, str) and value and attribute.isupper():
            attribute_of.setdefault(value, attribute)

    ui = (REPO_ROOT / "app" / "streamlit_app.py").read_text(encoding="utf-8")
    logic = (REPO_ROOT / "app" / "panels.py").read_text(encoding="utf-8")
    for key, text in module.MARKERS.items():
        attribute = attribute_of.get(text)
        assert attribute, (
            f"MARKERS[{key!r}] is not the value of any app.panels constant any more; "
            "it must be imported from panels, never retyped.")
        used = (attribute in ui) or (logic.count(attribute) > 1)
        assert used, (
            f"app.panels.{attribute} (MARKERS[{key!r}]) is no longer referenced by "
            "app/streamlit_app.py or anywhere else in app/panels.py, so the app very "
            "likely no longer renders it. Every capture would abort demanding it. "
            "Drop it from MARKERS and from the shots that require it, or restore the "
            "disclosure on the page.")


# ---------------------------------------------------- the committed screenshots


def test_every_committed_screenshot_has_documented_provenance():
    """Each PNG on disk: a manifest row, a caption, matching bytes, a provenance.

    The digest check is the one that does the work. A caption is only bound to an
    image if the image cannot be replaced underneath it — re-cropping a frame by
    hand, or dropping in a picture of the REAL model, leaves the caption saying
    "demo" over different pixels, and that is precisely the failure this
    directory could otherwise introduce.
    """
    manifest = manifest_or_skip()
    rows = {row["file"]: row for row in manifest["images"]}
    files = committed_pngs()
    assert files, (
        f"{MANIFEST.name} exists but {SHOT_DIR.relative_to(REPO_ROOT).as_posix()} "
        "holds no PNG. Either the capture wrote nothing or the images were deleted "
        "without the manifest.")
    for png in files:
        row = rows.get(png.name)
        assert row is not None, (
            f"{png.name} has no row in {MANIFEST.name}, so nothing on disk records "
            "that it was taken against the demo model. Re-run "
            f"`{CAPTURE_CMD}` rather than adding the file by hand.")
        assert row.get("caption", "").strip(), f"{png.name}: empty caption"
        assert row["sha256"] == sha256_of(png), (
            f"{png.name} does not match the SHA-256 recorded for it in "
            f"{MANIFEST.name}. The image changed and its provenance record did not — "
            f"re-run `{CAPTURE_CMD}`.")
        assert row.get("provenance_in_frame") or row.get("no_marker_reason", "").strip(), (
            f"{png.name} carries no demo mark inside the frame and gives no reason. "
            "One or the other is required.")
        assert not row.get("failed_checks"), (
            f"{png.name} is committed but its own capture-time checks failed: "
            f"{row['failed_checks']}. Do not publish a frame the capture script "
            "could not confirm.")


def test_the_manifest_names_no_image_that_is_missing():
    """A row with no file is a provenance record pointing at nothing."""
    manifest = manifest_or_skip()
    missing = [row["file"] for row in manifest["images"]
               if not (SHOT_DIR / row["file"]).exists()]
    assert not missing, (
        f"{MANIFEST.name} documents {missing}, which are not in "
        f"{SHOT_DIR.relative_to(REPO_ROOT).as_posix()}. Either the images were "
        f"deleted without the manifest, or the manifest is stale — re-run "
        f"`{CAPTURE_CMD}`.")


def test_the_manifest_matches_the_shots_the_script_declares_today():
    """A capture that predates a change to SHOTS must not read as current.

    Both directions. A shot added to the script and never captured leaves the
    directory advertising a state of the product that has no picture; a shot
    removed from the script leaves an image nothing regenerates. Either is
    allowed only if `README.md` says so in words — which is the brief's "report
    what you could not get", enforced instead of trusted.
    """
    manifest = manifest_or_skip()
    module = capture_module()
    declared_now = [shot.name for shot in module.SHOTS]
    declared_then = manifest.get("shots_declared", [])
    captured = set(manifest.get("shots_captured", []))
    readme = README.read_text(encoding="utf-8") if README.exists() else ""

    assert declared_then == declared_now, (
        f"{MANIFEST.name} was written when the script declared {declared_then}; it "
        f"now declares {declared_now}. Re-run `{CAPTURE_CMD}`.")
    undocumented = [name for name in declared_now
                    if name not in captured and name not in readme]
    assert not undocumented, (
        f"the script declares {undocumented} but the last capture did not produce "
        f"them and {README.name} does not mention them. A state of the product that "
        "could not be photographed has to be stated, not omitted.")


def test_the_readme_says_what_these_images_are_not():
    """The prose disclosure exists, names the source, and names every image.

    `PUBLISHED_DATASET` and the capture path are read from `app/panels.py`, not
    typed here: the README has to name the things the app itself names, and a
    test that hard-codes them would keep passing after either one changed.
    """
    manifest_or_skip()
    from app import panels

    assert README.exists(), (
        f"{README.relative_to(REPO_ROOT).as_posix()} is missing. Images of a toy "
        "model are published in this directory; the file that says so is not "
        "optional.")
    text = README.read_text(encoding="utf-8")
    for required in (panels.DEMO_CAPTURE_PATH, panels.PUBLISHED_DATASET,
                     "not comparable", CAPTURE_CMD, "bootstrap_demo_artifacts.py"):
        assert required in text, (
            f"{README.name} never mentions {required!r}. It is the only prose "
            "statement of what these images are; it must name the capture they came "
            "from, the dataset they did NOT come from, and how to regenerate them.")
    unnamed = [png.name for png in committed_pngs() if png.name not in text]
    assert not unnamed, (
        f"{README.name} does not mention {unnamed}. Every committed image needs a "
        "line saying what it shows and what it does not prove.")


def test_no_committed_screenshot_is_a_torn_frame():
    """No committed PNG has a band of content the compositor painted twice.

    THIS TEST EXISTS BECAUSE A TORN FRAME WAS COMMITTED. `04-network-graph-3d.png`
    was captured, checked and published with the section-7 heading and its two
    captions painted three times down the image and the 3D graph absent
    entirely — under a caption promising "nodes are devices, edges are flows".
    Every capture-time check passed it: the demo mark was in the DOM text, the
    DOM had a canvas inside the crop, the file was the requested size, the region
    read identically before and after the shutter, and both colour floors passed
    (the canvas floor crops the PNG at the canvas's DOM rect, which in a torn
    frame lands on a duplicated heading band — it measured 1,275 colours against
    a floor of 120). It was caught by a human looking at the picture.

    So this is checked where the defect actually lives: the bytes on disk, not
    the manifest. A manifest row can be rewritten to say anything; a duplicated
    band cannot be edited out of a PNG by editing JSON. The measurement comes
    from the capture script itself so there is one definition of "torn".
    """
    manifest_or_skip()
    module = capture_module()
    torn = []
    for png in committed_pngs():
        band = module.longest_repeated_band(png)
        if module.is_torn(band):
            torn.append(f"{png.name}: a {band[0]} px band of {band[1]} distinct "
                        f"pixel rows repeats at an offset of {band[2]} px")
    assert not torn, (
        "these committed screenshots are torn — part of the page is painted more "
        f"than once in them, and what should be there is missing: {torn}. They are "
        f"pictures of a rendering failure published under a caption describing the "
        f"product. Re-run `{CAPTURE_CMD}` (it now refuses to write a torn frame and "
        "re-rasters the region before retaking).")


def test_the_images_are_not_committed_as_the_only_record_of_a_number():
    """The manifest's run facts are labelled as the demo model's, not as results.

    CLAUDE.md forbids writing a number that was not measured, and the manifest
    does carry four numbers — the metric row read off the page. They are there so
    a reader can tell which run an image came from. This pins that they stay
    labelled `demo_run_facts` under `artifact_lane: demo`, so nothing downstream
    can lift them as though they were evaluation output.
    """
    manifest = manifest_or_skip()
    assert manifest.get("artifact_lane") == "demo"
    assert "demo_run_facts" in manifest
    assert manifest.get("provenance_statement", "").strip()
    assert "not comparable" in manifest["provenance_statement"]


# ------------------------------------------------- browser + server gated test


def _edge_present() -> bool:
    """Is the headless browser the capture script uses installed here?

    Asked through the script's own `find_edge()` — which asks
    `scripts/build_architecture_pdf.py` — so this gate cannot come to a different
    conclusion than the run it is gating.
    """
    try:
        capture_module().find_edge()
    except BaseException:
        return False
    return True


requires_capture_run = pytest.mark.skipif(
    os.environ.get(RUN_E2E_ENV, "") != "1" or not _edge_present(),
    reason=(
        f"end-to-end capture is opt-in: it starts a Streamlit server, runs the "
        f"pipeline and drives headless Edge (~2 min). Turn it on with "
        f"{RUN_E2E_ENV}=1 on a machine that has Microsoft Edge."
    ),
)


@requires_capture_run
def test_a_capture_run_produces_the_files_it_says(tmp_path):
    """One real shot, into a temp directory: the run writes what it claims.

    `--only` keeps it to the cheapest frame (the ledger panel — no WebGL, no
    matplotlib), because the subject here is the pipeline from "no output
    directory" to "a PNG and a manifest row whose digest matches", not the
    rendering of any one panel. It writes into `tmp_path`, so it can never
    disturb the committed screenshots.
    """
    module = capture_module()
    out = tmp_path / "shots"
    completed = subprocess.run(
        [sys.executable, str(SCRIPT), "--out", str(out),
         "--only", "03-ledger-verified"],
        cwd=str(REPO_ROOT), capture_output=True, text=True, timeout=1800)
    assert completed.returncode == 0, (
        f"capture exited {completed.returncode}\nSTDOUT:\n{completed.stdout[-4000:]}"
        f"\nSTDERR:\n{completed.stderr[-2000:]}")
    png = out / "03-ledger-verified.png"
    assert png.exists() and png.stat().st_size > 0
    written = json.loads((out / module.MANIFEST_NAME).read_text(encoding="utf-8"))
    rows = {row["file"]: row for row in written["images"]}
    assert png.name in rows
    assert rows[png.name]["sha256"] == sha256_of(png)
    assert written["artifact_lane"] == "demo"
