"""Render docs/architecture.md to the 2-page PDF deliverable (M12).

    python scripts/build_architecture_pdf.py

Markdown -> styled HTML (python-markdown, a build-time tool, not a runtime
dependency) -> PDF via Edge headless (present on Windows 11, fully offline).

TWO defects made this script ship a figure-less PDF for as long as it existed,
and both are fixed here:

1. The HTML was written into a TemporaryDirectory and printed from there, so a
   relative `src="img/..."` resolved against %TEMP%/<random>/ and loaded
   NOTHING. Every image in the document was silently dropped. The fix is to
   INLINE each referenced image as a base64 data URI rather than to move the
   HTML next to docs/: the printed page then has no filesystem-relative
   dependency at all, so it renders identically from a temp dir, from docs/, or
   from a CI checkout, and no build artefact is left in docs/ for someone to
   commit by accident. A referenced image that is missing now raises.

2. There was no `img` CSS rule, so a 1180 px-wide figure would have been laid
   out at its intrinsic size, overflowed the A4 text column and blown the
   2-page assert with no hint as to why. `img` is now width-constrained to the
   text column (FIGURE_WIDTH_PCT).

Why the SVG figures are RASTERISED before they are embedded: Chromium's PDF
backend draws an `<img>`-referenced SVG as vector operators straight into the
page content stream, which leaves the PDF with **zero image XObjects**
(measured: an SVG embedded either way gives `/XObject: 0`). The figure would be
there, but `assert_pdf_has_an_embedded_image` would have nothing to bind to and
a silently figure-less PDF would look identical to a correct one. A raster PNG
produces a real `/Subtype /Image` XObject that pypdf can count, so the assert
binds to a thing that prose cannot satisfy. RASTER_SCALE keeps it at print
resolution (2x of a 1180 px figure across a 184 mm column is ~326 dpi).

A THIRD defect is fixed here: the shipped PDF was never bound to the files it
was built from. `docs/architecture.pdf` is a committed binary, so rewriting a
figure and forgetting to rebuild left the graded deliverable showing a figure
that no longer exists in the repo — and the suite could not tell, because
"contains an image" and "is <= 2 pages" are both still true of a stale PDF.
`architecture_source_digest()` hashes every input that reaches the page (the
markdown plus each image it embeds); `main` stamps that digest into the PDF's
Info dictionary under SOURCE_DIGEST_KEY, and
`tests/test_figures.py::test_the_shipped_architecture_pdf_was_built_from_the_current_sources`
recomputes it and fails when the two disagree. The digest is computed by the
function the test imports from this module, so builder and guard can never
drift to different definitions of "the inputs".

Asserts, in order, and all of them fail the build loudly:
  - every image the markdown references exists,
  - the set of images inlined into the HTML is exactly the set the digest
    covers (otherwise the freshness guard would watch the wrong files),
  - the PDF carries at least one embedded image,
  - the PDF is <= 2 pages (the PS caps the architecture doc at two) — if this
    fails, tighten the CSS or the prose, never cut content silently.
Output: docs/architecture.pdf
"""

from __future__ import annotations

import base64
import hashlib
import html as html_mod
import io
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
DOC = REPO / "docs" / "architecture.md"
OUT_PDF = REPO / "docs" / "architecture.pdf"

# Figure width as a percentage of the A4 text column. Full width is the point —
# the figure is the part of this deliverable a judge reads first — but it is a
# knob, because it trades directly against the 2-page cap.
FIGURE_WIDTH_PCT = 100

# Device scale factor for the SVG -> PNG raster step. 2x of a 1180 px-wide
# figure laid out across a 184 mm column is ~326 dpi.
RASTER_SCALE = 2

# Edge writes --screenshot / --print-to-pdf after the process has already
# returned on this machine, so every output is waited for rather than assumed.
EDGE_OUTPUT_TIMEOUT_S = 60.0

CSS = """
@page { size: A4; margin: 11mm 13mm; }
body { font-family: 'Segoe UI', Arial, sans-serif; font-size: 8.6pt; line-height: 1.32;
       color: #1a1a1a; margin: 0; }
h1 { font-size: 13pt; margin: 0 0 4pt; border-bottom: 1.5px solid #1a6faf; padding-bottom: 2pt; }
h2 { font-size: 10pt; margin: 7pt 0 3pt; color: #1a4f7a; }
p, li { margin: 2.5pt 0; }
ul { margin: 2pt 0; padding-left: 14pt; }
code { font-family: Consolas, monospace; font-size: 8pt; background: #f2f4f7; padding: 0 2px; }
pre { background: #f2f4f7; padding: 4pt 6pt; font-size: 7.6pt; line-height: 1.25;
      margin: 3pt 0; white-space: pre-wrap; }
pre code { background: none; padding: 0; }
table { border-collapse: collapse; margin: 3pt 0; font-size: 8.2pt; }
th, td { border: 0.5px solid #999; padding: 1.5pt 5pt; text-align: left; }
th { background: #eef3f8; }
strong { color: #000; }
/* Without this a figure is laid out at its intrinsic pixel width, overflows the
   text column and blows the 2-page assert with no hint as to the cause. */
img { display: block; width: FIGURE_WIDTH%; height: auto; margin: 4pt auto 2pt; }
p.figure-caption { font-size: 7.6pt; color: #444; text-align: center; margin: 0 0 4pt; }
"""

EDGE_CANDIDATES = [
    Path("C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe"),
    Path("C:/Program Files/Microsoft/Edge/Application/msedge.exe"),
]

_IMG_SRC = re.compile(r'<img\b[^>]*?\bsrc="([^"]+)"[^>]*>')
_SVG_SIZE = re.compile(r'\bviewBox\s*=\s*"\s*[\d.+-]+\s+[\d.+-]+\s+([\d.]+)\s+([\d.]+)')
# Markdown image syntax. The alt text is deliberately multi-line in
# docs/architecture.md, and `[^\]]` matches newlines, so this spans it.
_MD_IMG = re.compile(r"!\[[^\]]*\]\(([^)\s]+)\)")

# Info-dictionary key carrying the digest of the files this PDF was built from.
# A custom key rather than /Subject: /Subject is prose a human may legitimately
# want to set, and silently overwriting it would trade one stale field for
# another.
SOURCE_DIGEST_KEY = "/SIH26SourceDigest"


def referenced_image_paths() -> list[Path]:
    """Every image `docs/architecture.md` embeds, resolved and sorted.

    Relative sources resolve against docs/ (where the markdown lives), exactly
    as `inline_images` resolves them — `main` asserts the two agree, so the
    freshness digest can never end up watching a different file set than the
    build actually inlines.
    """
    srcs = _MD_IMG.findall(DOC.read_text(encoding="utf-8"))
    return sorted({(DOC.parent / html_mod.unescape(s)).resolve() for s in srcs})


def architecture_source_digest() -> str:
    """SHA-256 over every input that reaches the printed page.

    The markdown plus each figure it embeds, each domain-separated by its
    repo-relative path and byte length so that moving content between files
    cannot produce a colliding digest. This is the function
    `tests/test_figures.py` imports: builder and guard share one definition of
    "the inputs" instead of each carrying their own list.

    Deliberately NOT covered: figures `docs/architecture.md` only mentions in
    prose (e.g. `docs/img/02-model-stack.svg`). They are not in the PDF, so
    they cannot make the PDF stale, and hashing them would raise a rebuild
    demand that the deliverable's own content does not justify.
    """
    h = hashlib.sha256()
    for path in [DOC, *referenced_image_paths()]:
        payload = path.read_bytes()
        rel = path.resolve().relative_to(REPO).as_posix()
        h.update(f"{rel}:{len(payload)}\n".encode("utf-8"))
        h.update(payload)
    return h.hexdigest()


def stamp_source_digest(pdf_path: Path, digest: str) -> None:
    """Record `digest` in the PDF's Info dictionary, preserving what is there.

    Edge writes the PDF, so the stamp is a second pass: read it back, copy the
    pages (and therefore the image XObjects the asserts below count), re-add the
    existing metadata plus our key, and replace the file. The re-written PDF is
    re-opened by `main` afterwards, so the page count and image count that get
    asserted are the ones in the file that actually ships, not the ones in the
    intermediate Edge wrote.
    """
    from pypdf import PdfReader, PdfWriter

    reader = PdfReader(str(pdf_path))
    writer = PdfWriter()
    writer.append(reader)
    metadata = {str(k): str(v) for k, v in (reader.metadata or {}).items()}
    metadata[SOURCE_DIGEST_KEY] = digest
    writer.add_metadata(metadata)
    buffer = io.BytesIO()
    writer.write(buffer)
    pdf_path.write_bytes(buffer.getvalue())


def find_edge() -> Path:
    edge = next((p for p in EDGE_CANDIDATES if p.exists()), None)
    if edge is None:
        raise SystemExit(
            "msedge.exe not found at " + " or ".join(str(p) for p in EDGE_CANDIDATES)
            + " — install Edge, or print docs/architecture.md manually"
        )
    return edge


def run_edge(edge: Path, args: list[str], expect: Path) -> bytes:
    """Run headless Edge and return the bytes it was asked to write.

    `expect` is deleted first and then waited for: Edge returns before the file
    lands on disk, and reading it straight after the call picks up either
    nothing or the PREVIOUS run's output — which is exactly how a stale,
    figure-less PDF survives a rebuild that looks like it worked.
    """
    expect.unlink(missing_ok=True)
    subprocess.run([str(edge), "--headless", "--disable-gpu", *args],
                   check=True, timeout=180)
    deadline = time.monotonic() + EDGE_OUTPUT_TIMEOUT_S
    while time.monotonic() < deadline:
        if expect.exists() and expect.stat().st_size > 0:
            return expect.read_bytes()
        time.sleep(0.1)
    raise SystemExit(
        f"Edge did not write {expect} within {EDGE_OUTPUT_TIMEOUT_S:.0f}s "
        f"(args: {args}) — nothing was produced, so nothing is asserted"
    )


def svg_pixel_size(svg_text: str) -> tuple[int, int]:
    """Logical pixel size of an SVG, from its viewBox.

    The raster window must match the figure exactly or the PNG is padded with
    white or cropped. viewBox is authoritative here because every figure in
    docs/img/ declares one.
    """
    match = _SVG_SIZE.search(svg_text)
    if not match:
        raise SystemExit("figure SVG has no viewBox — cannot size the raster window")
    return round(float(match.group(1))), round(float(match.group(2)))


def rasterise(edge: Path, svg_path: Path, work: Path) -> bytes:
    """SVG -> PNG bytes at RASTER_SCALE, via the same headless Edge.

    Rasterising is what gives the PDF a countable image XObject; see the module
    docstring. The SVG is inlined into a zero-margin page so the screenshot is
    the figure and nothing else.
    """
    svg_text = svg_path.read_text(encoding="utf-8")
    width, height = svg_pixel_size(svg_text)
    shell = work / f"{svg_path.stem}.html"
    shell.write_text(
        "<!doctype html><html><head><meta charset='utf-8'><style>"
        "html,body{margin:0;padding:0;background:#fff}svg{display:block}"
        f"</style></head><body>{svg_text}</body></html>",
        encoding="utf-8",
    )
    png = work / f"{svg_path.stem}.png"
    run_edge(edge, [
        "--hide-scrollbars",
        f"--force-device-scale-factor={RASTER_SCALE}",
        f"--window-size={width},{height}",
        f"--screenshot={png}",
        shell.as_uri(),
    ], expect=png)
    return png.read_bytes()


def inline_images(edge: Path, body_html: str, work: Path) -> tuple[str, list[Path]]:
    """Replace every `<img src="...">` with a base64 PNG data URI.

    Relative sources resolve against docs/ (where the markdown lives), NOT
    against the directory the HTML is printed from — that mismatch is the
    original bug. A source that does not exist raises: silently dropping a
    figure is the failure this whole change exists to make impossible.

    Returns the rewritten HTML and the resolved source paths actually inlined,
    so `main` can check them against `referenced_image_paths()` — the list the
    freshness digest is computed over.
    """
    embedded: list[Path] = []

    def replace(match: re.Match[str]) -> str:
        src = html_mod.unescape(match.group(1))
        if src.startswith(("http://", "https://", "data:")):
            raise SystemExit(
                f"docs/architecture.md references a non-local image ({src!r}). "
                "The PDF must build fully offline from files in this repo."
            )
        path = (DOC.parent / src).resolve()
        if not path.exists():
            raise SystemExit(
                f"docs/architecture.md references {src!r}, which does not exist "
                f"(looked for {path}). Add the figure or drop the reference — the "
                "PDF must never ship with a silently missing image."
            )
        if path.suffix.lower() == ".svg":
            payload, mime = rasterise(edge, path, work), "image/png"
        else:
            payload, mime = path.read_bytes(), f"image/{path.suffix.lower().lstrip('.')}"
        embedded.append(path)
        b64 = base64.b64encode(payload).decode("ascii")
        return match.group(0).replace(match.group(1), f"data:{mime};base64,{b64}")

    return _IMG_SRC.sub(replace, body_html), embedded


def count_embedded_images(pdf_path: Path) -> int:
    """Image XObjects across all pages of the PDF."""
    from pypdf import PdfReader

    total = 0
    for page in PdfReader(str(pdf_path)).pages:
        resources = page.get("/Resources")
        if resources is None:
            continue
        xobjects = resources.get_object().get("/XObject")
        if xobjects is None:
            continue
        for ref in xobjects.get_object().values():
            if ref.get_object().get("/Subtype") == "/Image":
                total += 1
    return total


def main() -> int:
    import markdown

    edge = find_edge()
    md_text = DOC.read_text(encoding="utf-8")
    body = markdown.markdown(md_text, extensions=["tables", "fenced_code"])

    with tempfile.TemporaryDirectory() as td:
        work = Path(td)
        body, embedded = inline_images(edge, body, work)
        if not embedded:
            raise SystemExit(
                "docs/architecture.md references no images. The architecture "
                "deliverable is the one document a judge reads first; shipping it "
                "as unbroken prose was a graded defect. Add the dataflow figure "
                "(docs/img/01-architecture-dataflow.svg) back."
            )
        watched = referenced_image_paths()
        if sorted(set(embedded)) != watched:
            raise SystemExit(
                "the images inlined into the PDF "
                f"({[p.name for p in sorted(set(embedded))]}) are not the images the "
                f"freshness digest covers ({[p.name for p in watched]}). The digest "
                "stamped into the PDF would then watch the wrong files and a stale "
                "deliverable would pass its guard — fix _MD_IMG or _IMG_SRC so the "
                "two agree before shipping anything."
            )
        css = CSS.replace("FIGURE_WIDTH%", f"{FIGURE_WIDTH_PCT}%")
        html = (f"<!doctype html><html><head><meta charset='utf-8'>"
                f"<style>{css}</style></head><body>{body}</body></html>")
        html_path = work / "architecture.html"
        html_path.write_text(html, encoding="utf-8")
        run_edge(edge, [
            f"--print-to-pdf={OUT_PDF}",
            "--no-pdf-header-footer",
            html_path.as_uri(),
        ], expect=OUT_PDF)

    # Stamp BEFORE the asserts: the stamp rewrites the file, so everything
    # asserted below has to be measured on the stamped bytes that actually ship.
    digest = architecture_source_digest()
    stamp_source_digest(OUT_PDF, digest)

    from pypdf import PdfReader
    reader = PdfReader(str(OUT_PDF))
    pages = len(reader.pages)
    images = count_embedded_images(OUT_PDF)
    stamped = (reader.metadata or {}).get(SOURCE_DIGEST_KEY)
    print(f"-> {OUT_PDF} ({pages} pages, {images} embedded image(s) from "
          f"{len(embedded)} figure reference(s), source digest {digest[:16]}…)")

    if stamped != digest:
        raise SystemExit(
            f"the source digest did not survive the write ({stamped!r} != "
            f"{digest!r}). Without it the freshness guard has nothing to compare "
            "against, and a stale PDF ships unnoticed."
        )

    # The assert the old build was missing. A PDF whose figures silently failed
    # to load still had two pages of clean prose and still passed the build.
    if images == 0:
        raise SystemExit(
            f"architecture.pdf embedded {len(embedded)} figure(s) into the HTML but "
            "the PDF contains ZERO image XObjects — the figures did not survive "
            "printing. Do not ship it: this is exactly the silently figure-less "
            "PDF this assert exists to catch."
        )
    if pages > 2:
        raise SystemExit(
            f"architecture.pdf is {pages} pages — the PS caps it at 2. Tighten the "
            f"CSS (font-size/margins) or FIGURE_WIDTH_PCT (now {FIGURE_WIDTH_PCT}), "
            "or tighten the prose and SAY what you tightened; do not cut content "
            "silently."
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
