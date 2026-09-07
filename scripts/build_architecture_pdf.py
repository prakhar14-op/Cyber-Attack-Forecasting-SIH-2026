"""Render docs/architecture.md to the 2-page PDF deliverable (M12).

    python scripts/build_architecture_pdf.py

Markdown -> styled HTML (python-markdown, a build-time tool, not a runtime
dependency) -> PDF via Edge headless (present on Windows 11, fully offline).
Asserts the result is <= 2 pages (pypdf) — the PS caps the architecture doc at
two pages; if this fails, tighten the CSS, never cut content silently.
Output: docs/architecture.pdf
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

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
"""

EDGE_CANDIDATES = [
    Path("C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe"),
    Path("C:/Program Files/Microsoft/Edge/Application/msedge.exe"),
]


def main() -> int:
    import markdown

    md_text = (REPO / "docs" / "architecture.md").read_text(encoding="utf-8")
    body = markdown.markdown(md_text, extensions=["tables", "fenced_code"])
    html = (f"<!doctype html><html><head><meta charset='utf-8'>"
            f"<style>{CSS}</style></head><body>{body}</body></html>")

    edge = next((p for p in EDGE_CANDIDATES if p.exists()), None)
    if edge is None:
        raise SystemExit("msedge.exe not found — install Edge or print the HTML manually")

    out_pdf = REPO / "docs" / "architecture.pdf"
    with tempfile.TemporaryDirectory() as td:
        html_path = Path(td) / "architecture.html"
        html_path.write_text(html, encoding="utf-8")
        subprocess.run(
            [str(edge), "--headless", "--disable-gpu",
             f"--print-to-pdf={out_pdf}", "--no-pdf-header-footer",
             html_path.as_uri()],
            check=True, timeout=120,
        )

    from pypdf import PdfReader
    n = len(PdfReader(str(out_pdf)).pages)
    print(f"-> {out_pdf} ({n} pages)")
    if n > 2:
        raise SystemExit(f"architecture.pdf is {n} pages — the PS caps it at 2; "
                         "tighten the CSS (font-size/margins), do not cut content")
    return 0


if __name__ == "__main__":
    sys.exit(main())
