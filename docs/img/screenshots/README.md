# Screenshots of the offline demo app — what they are, and what they are not

## Read this before you look at any number in them

Every image in this directory was photographed against the **demo model**: a toy
fitted by `scripts/bootstrap_demo_artifacts.py` from
`app/assets/synthetic_demo.pcap`, a small hand-authored synthetic capture
bundled with this repository. That model was fitted on that capture and its
alert thresholds were chosen on the same rows, so it has **memorised** it. When
the app then scores that same capture back, a high probability means "I have
seen this row before" — not "an attack was detected".

So:

- **No probability, alert count, threshold, host ranking or feature attribution
  visible in these images is a result.** None of them reproduces, corroborates or
  approximates any figure in `README.md`, in `docs/`, or in the deck. They are
  **not comparable** with those figures — not a weaker version of them, not an
  approximation of them, not evidence about them.
- **The demo model has never seen CSE-CIC-IDS-2018**, which is the dataset every
  number this project publishes was measured on.
- **The stage labels in these frames do not mean those stages are supported.**
  The synthetic capture was hand-authored to contain recon, lateral movement and
  exfiltration, and the demo lane really does fit labelled windows for them.
  Those are exactly the three kill-chain stages that have **zero labelled
  windows** in the dataset this project reports on (`docs/limitations.md`,
  `docs/stage_mapping.md`). Seeing `recon` or `exfiltration` printed beside a
  host in `01-forecast-timeline.png` is an illustration that was written to be
  found; it is not a per-stage capability.
- **What these images DO show is real**: that the pipeline runs end to end
  offline, what each panel looks like, what the app discloses about itself, and
  that the ledger detects tampering. Those are properties of the code, and the
  code in the frames is the code in this repository.

The same statement, machine-readable and per-image, is in
[`manifest.json`](manifest.json) (`provenance_statement`, and a `caption` on
every row).

## Where the disclosure lives in each frame

`app/streamlit_app.py` marks the surfaces where a demo number would mislead, and
the capture script **refuses to write a frame that does not contain the marks it
declared** — see `scripts/capture_screenshots.py` and
`tests/test_screenshots.py`. Five of the seven frames therefore carry the
disclosure inside the picture: the provenance banner, the `Threshold (1% FPR —
DEMO model)` metric label, the `DEMO MODEL — fitted on
app/assets/synthetic_demo.pcap` line drawn **into** the matplotlib charts, and
the per-panel captions on the explanation, the graph and the k-step curve.

Two frames — the ledger pair — carry no such mark, because the app renders none
in that section and this script does **not** paint one in: an overlay the
application never rendered would be a fabricated screenshot. For those two the
provenance is this file and the manifest caption. That is weaker than a banner
in frame, and it is stated here rather than glossed over.

| File | What it shows | Demo disclosure inside the frame? |
| --- | --- | --- |
| `01-forecast-timeline.png` | The provenance banner, the run's four metrics, the per-window forecast timeline against the alert threshold, and the host triage table. The single best "what does it look like" frame. | Yes — banner, threshold label, metrics caption, and the mark drawn into the chart |
| `02-host-explanation.png` | Why one host alerted, in **named** features (never embedding dimensions), with the contributing windows and the flagged flows. | Yes — the explanation caption |
| `03-ledger-verified.png` | The hash-chained forecast ledger for the run: record count, chain verifies, anchored to a checkpoint, and the command that re-verifies it offline. | No — caption only (see above) |
| `04-network-graph-3d.png` | The 3D host graph the TGN encoder operates on: nodes are devices, edges are flows, edges leaving an alerting host glow red. | Yes — the graph caption |
| `05-kstep-forecast-curve.png` | The k-step risk curve and the per-horizon evidence table, **underneath** the caveat the app renders before them: there is no supported forward-forecast operating point. | Yes — the k-step caption |
| `06-demo-provenance-banner.png` | The disclosure the app puts above every number on the page, with its fold opened. This is the frame that says what the other six are pictures of. | Yes — it *is* the disclosure |
| `07-ledger-tampered.png` | The same ledger panel after the demo's "Tamper with record 0" button edits one record in place: the chain stops verifying and the panel names the broken record. | No — caption only (see above) |

## How they were made, and how to remake them

```
python scripts/capture_screenshots.py
```

That script bootstraps the demo lane if it is absent, starts the Streamlit app
headless on a free port, drives it with headless Edge over the DevTools
protocol, crops each state, checks each crop, and writes the PNGs plus
`manifest.json`. It runs fully offline (127.0.0.1 only) and adds no dependency:
the browser is the same headless Edge `scripts/build_architecture_pdf.py` uses,
and the protocol transport is `websockets`, which is already pinned in
`requirements.txt` as a Streamlit dependency.

It refuses to write anything if the page comes up **without** the demo
provenance box — that is, if the published artifacts are present on the capture
machine, so the images would be of a different model than this file describes.
On a machine that has (or is mid-way through writing) `artifacts/`, the script
serves the app from a throwaway copy of the checkout with no `artifacts/` in it,
and records that it did so in the manifest; it never moves or deletes anything
in the working tree.

## Why these PNGs are in the repository

`CLAUDE.md` forbids committing weights and captures. It does not forbid images,
and the repository already commits diagnostic PNGs under `diagnostics/`. These
are the only pictures of the product a judge will see before they run anything,
they are small (under a megabyte for the set), they are regenerable from a
committed capture by one command, and they contain no data that is not already
in the tree — the synthetic capture they show is committed, and the demo model
they were scored with is refitted from it at capture time rather than stored.

A note on what varies between runs: the ledger frames show the absolute path of
that run's temporary output directory, which is different every time, so the
PNG bytes are not reproducible even though the page is. The manifest records
each file's digest at capture time; it is not a reproducibility claim.

## Regenerate them when the UI changes

These are committed binaries, so they go stale silently — the app gets a new
panel or a reworded caveat and the pictures keep showing the old one. There is
no digest binding a PNG to the app source (unlike `docs/architecture.pdf`, which
carries one), so the rule is procedural: **if you change `app/streamlit_app.py`
or `app/panels.py` in a way that changes what the page looks like, re-run the
capture.** `tests/test_screenshots.py` will catch an image whose provenance
record no longer matches its bytes, and a shot the script declares but has never
captured — it cannot catch a correctly-recorded picture of last week's UI.

## One failure these checks did not catch on their own

An earlier capture published `04-network-graph-3d.png` as a **torn frame**: the
section heading and its captions painted three times down the image, and no 3D
graph in it at all, under a caption describing the graph. Every check passed it,
because every check but one was made against the DOM — and the document was
correct; only the paint was wrong. Even the "the canvas is not blank" check
passed, because it crops the PNG at the canvas's DOM rectangle, which in a torn
frame lands on a duplicate of the heading. A human looking at the picture found
it.

The capture script now measures the written pixels for a band of content painted
twice (`longest_repeated_band`), refuses to write such a frame, and re-rasters
the region before retaking; `test_no_committed_screenshot_is_a_torn_frame` in
`tests/test_screenshots.py` re-measures every committed PNG on disk, so a torn
frame cannot be committed by hand either. The thresholds are measured rather
than guessed — the torn frame repeated a 559 px band carrying 121 distinct pixel
rows, while the worst healthy frame repeats 42 px of flat background. It detects
whole-band duplication, which is the failure that actually occurred. It is not a
general check that the renderer drew the right thing, and it still cannot tell
you whether the picture is of the current UI.
