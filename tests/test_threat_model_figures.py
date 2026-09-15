"""`docs/threat_model.md` §3 publishes eight measured rows. This runs the
document's own probe and checks they still reproduce.

§3 is the strongest content in the threat model precisely because it is measured
rather than argued: every figure comes out of the fenced `python` block at the
top of that document, run against this repo's own extractor. Until this file
existed nothing in the suite ran that block. A change to `data/packet_features.py`
— the packet layout, the window geometry, a feature's semantics — would have left
all eight rows silently non-reproducing, turning the one part of the document a
judge can check into exactly the un-reproducible measurement this project exists
to eliminate.

What is guarded, and how it fails:

- **The probe is taken FROM the document**, not re-implemented here. Editing the
  fenced block changes what this test runs, so the two cannot drift apart.
- **The published figures are parsed FROM the document's tables**, not restated
  here. Perturbing any digit in a §3.1–§3.4 table fails
  `test_every_published_figure_in_section_3_reproduces`.
- **Coverage is checked both ways.** `test_every_published_row_is_claimed_by_a_guard`
  fails if a §3 table gains a row this file does not know about (a new published
  figure with no guard), and the per-row assertions fail if the document loses one.
- **The probe cannot be hollowed out.**
  `test_the_document_still_carries_the_probe_that_produced_the_figures` pins the
  names that make it a measurement — `_PACKET_LAYOUT`, the pinned generator, and
  both feature-family entry points. A probe that printed constants would pass the
  comparison and fail this.

Tolerance, stated: each figure must reproduce **exactly at the precision the
document publishes it** — `88.970` is compared to three decimals, `2.886e8` to
four significant figures, `100,000` and the histogram vectors exactly. Nothing is
compared loosely; the document's own rendering sets the tolerance. Two rows (§3.1
jittered, §3.4 randomised) are pseudo-random draws, which is why the probe pins
`default_rng(1337)` and why the document says so — at that seed they are as
deterministic as the rest.
"""

from __future__ import annotations

import io
import re
from contextlib import redirect_stdout
from dataclasses import dataclass
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
DOC = REPO_ROOT / "docs" / "threat_model.md"

# The fenced probe, the §3 body, and the `**3.N ...**` subsection markers inside it.
_FENCE = re.compile(r"^```python\r?\n(.*?)^```", re.DOTALL | re.MULTILINE)
_SECTION_3 = re.compile(r"^## 3\..*?(?=^## 4\.)", re.DOTALL | re.MULTILINE)
_SUBSECTION = re.compile(r"\*\*(3\.\d)\s")

# Probe output: "3.1 jittered  ttl_mean=47.400  ttl_var=88.970  ..." — the label
# runs from the section id to the first `name=value` token, which may itself hold
# a bracketed vector with spaces in it.
_KV = re.compile(r"([A-Za-z_]\w*)=(\[[^\]]*\]|\S+)")
_LABEL_SPLIT = re.compile(r"\s{2,}(?=[A-Za-z_]\w*=)")
_VECTOR = re.compile(r"^\[[\d,\s]*\]$")

# Names that make the fenced block a measurement rather than a print statement.
# This is a cheap textual pre-check only: a block that merely MENTIONS these while
# printing constants would satisfy it. What actually proves the probe measured
# something is EXTRACTORS_THE_PROBE_MUST_CALL below, which counts real calls.
PROBE_MUST_MENTION = (
    '_PACKET_LAYOUT',
    'default_rng(1337)',
    'packet_window_features',
    'sent_window_features',
    'load_config("data")',
)

# The probe is a measurement only if it actually reaches the production extractor.
# These are counted during exec; a probe rewritten to print the published constants
# calls none of them and fails, however faithfully it quotes their names.
EXTRACTORS_THE_PROBE_MUST_CALL = ("packet_window_features", "sent_window_features")


@dataclass(frozen=True)
class PublishedRow:
    """One data row of a §3 table, and the probe line that produces it.

    `doc_label` is matched against the row's first cell; `fields` are the probe's
    value names in the document's column order.
    """

    section: str
    doc_label: str
    probe_label: str
    fields: tuple[str, ...]


_HEADER_FIELDS = ("ttl_mean", "ttl_var", "tcp_win_var", "sent_bytes")
_PAYLOAD_FIELDS = ("bytes", "hist")
_PACING_FIELDS = ("windows", "peak_pkts", "peak_bytes")
_SCAN_FIELDS = ("sequential_port_ratio", "port_entropy", "distinct_dst_ports")

PUBLISHED: tuple[PublishedRow, ...] = (
    PublishedRow("3.1", "stock stack", "stock", _HEADER_FIELDS),
    PublishedRow("3.1", "attacker randomises its own stack", "jittered", _HEADER_FIELDS),
    PublishedRow("3.2", "30 x 1400 B", "30 x 1400B", _PAYLOAD_FIELDS),
    PublishedRow("3.2", "90 x 466 B", "90 x 466B", _PAYLOAD_FIELDS),
    PublishedRow("3.3", "burst, 3 s", "burst 3s", _PACING_FIELDS),
    PublishedRow("3.3", "paced, 45 s", "paced 45s", _PACING_FIELDS),
    PublishedRow("3.4", "ascending", "ascending", _SCAN_FIELDS),
    PublishedRow("3.4", "randomised", "randomised", _SCAN_FIELDS),
)

# Eight rows; 4+2+3+3 value columns per pair of rows. Both counts are asserted so
# that a table quietly losing a column cannot shrink the guard without failing it.
EXPECTED_ROWS = 8
EXPECTED_FIGURES = 2 * (4 + 2 + 3 + 3)


def normalise(text: str) -> str:
    """Markdown emphasis, backticks, the multiplication sign and run-together
    whitespace must not change what a cell says."""
    return " ".join(text.replace("*", "").replace("`", "").replace("×", "x").split())


def extract_probe(doc_text: str) -> str:
    """The first fenced `python` block — the probe the document says reproduces §3."""
    match = _FENCE.search(doc_text)
    assert match, (
        f"{DOC.name} no longer contains a fenced ```python block. §3's figures are "
        "published as reproducible output of that block; without it they are "
        "unverifiable assertions."
    )
    return match.group(1)


def section_3(doc_text: str) -> str:
    match = _SECTION_3.search(doc_text)
    assert match, f"{DOC.name} has no '## 3.' section ending at '## 4.'"
    return match.group(0)


def subsections(doc_text: str) -> dict[str, str]:
    """`3.N` -> the text of that subsection of §3."""
    body = section_3(doc_text)
    marks = list(_SUBSECTION.finditer(body))
    assert marks, "§3 has no **3.N ...** subsection markers"
    out = {}
    for i, mark in enumerate(marks):
        end = marks[i + 1].start() if i + 1 < len(marks) else len(body)
        out[mark.group(1)] = body[mark.start():end]
    return out


def table_rows(section_text: str) -> list[list[str]]:
    """Data rows of every markdown table in `section_text` (header and separator
    rows dropped), each as normalised cells."""
    rows = []
    for line in section_text.splitlines():
        line = line.strip()
        if not line.startswith("|"):
            continue
        cells = [normalise(cell) for cell in line.strip("|").split("|")]
        if all(set(cell) <= set("-: ") for cell in cells):
            continue  # |---|---| separator
        if not cells[0]:
            continue  # header row: these tables label their columns, not their first cell
        rows.append(cells)
    return rows


def parse_probe(stdout: str) -> dict[tuple[str, str], dict[str, str]]:
    """`(section, label) -> {field: printed value}` for every probe line."""
    measured: dict[tuple[str, str], dict[str, str]] = {}
    for line in stdout.splitlines():
        line = line.strip()
        if not re.match(r"^3\.\d\s", line):
            continue
        head = _LABEL_SPLIT.split(line, maxsplit=1)[0]
        section, _, label = head.partition(" ")
        values = dict(_KV.findall(line[len(head):]))
        assert values, f"probe line carries no name=value pairs: {line!r}"
        measured[(section, normalise(label))] = values
    return measured


def reproduces(published: str, measured: str) -> bool:
    """Does `measured` render to exactly what the document published, at the
    precision the document chose?

    `2.886e8` is four significant figures, `88.970` is three decimals, `100,000`
    and `[0,0,0,90,0,0,0,0]` are exact. The document's own rendering sets the
    tolerance — nothing here is compared loosely.
    """
    pub_is_vector, meas_is_vector = bool(_VECTOR.match(published)), bool(_VECTOR.match(measured))
    if pub_is_vector or meas_is_vector:
        if not (pub_is_vector and meas_is_vector):
            return False
        return _as_ints(published) == _as_ints(measured)

    pub_raw, meas_raw = published.replace(",", ""), measured.replace(",", "")
    try:
        pub, meas = float(pub_raw), float(meas_raw)
    except ValueError:
        return False
    if "e" in pub_raw.lower():
        decimals = len(pub_raw.lower().split("e")[0].partition(".")[2])
        return f"{meas:.{decimals}e}" == f"{pub:.{decimals}e}"
    if "." in pub_raw:
        decimals = len(pub_raw.partition(".")[2])
        return f"{meas:.{decimals}f}" == f"{pub:.{decimals}f}"
    return meas == pub


def _as_ints(vector: str) -> list[int]:
    return [int(part) for part in vector.strip()[1:-1].split(",") if part.strip()]


@pytest.fixture(scope="module")
def doc_text() -> str:
    assert DOC.exists(), f"{DOC} is missing"
    return DOC.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def measured(doc_text) -> dict[tuple[str, str], dict[str, str]]:
    """Run the document's own probe and parse what it printed.

    Executing a document's code block is the point: a re-implementation here
    could drift from the published snippet, and then the tables would be
    checked against something a reader cannot run.
    """
    from data import packet_features as pf

    source = extract_probe(doc_text)
    buffer = io.StringIO()
    namespace: dict = {"__name__": "threat_model_section_3_probe"}

    calls: dict[str, int] = dict.fromkeys(EXTRACTORS_THE_PROBE_MUST_CALL, 0)
    originals = {name: getattr(pf, name) for name in calls}

    def _counting(name, fn):
        def proxy(*args, **kwargs):
            calls[name] += 1
            return fn(*args, **kwargs)

        return proxy

    for name, fn in originals.items():
        setattr(pf, name, _counting(name, fn))
    try:
        with redirect_stdout(buffer):
            exec(compile(source, f"{DOC} [§3 probe]", "exec"), namespace)  # noqa: S102
    finally:
        for name, fn in originals.items():
            setattr(pf, name, fn)

    uncalled = [name for name, n in calls.items() if n == 0]
    assert not uncalled, (
        f"the §3 probe ran without calling {uncalled} — so §3's tables are not "
        "measurements of data/packet_features.py, whatever the probe prints. A block "
        "rewritten to print the published constants reaches this assertion."
    )

    parsed = parse_probe(buffer.getvalue())
    assert parsed, (
        "the §3 probe printed nothing this test could parse — its output format "
        f"changed. Raw output:\n{buffer.getvalue()!r}"
    )
    return parsed


def test_the_document_still_carries_the_probe_that_produced_the_figures(doc_text):
    """Cheap textual pre-check that the fenced block still reads as a measurement.

    This alone is defeatable — a block that prints the published constants while
    quoting these names in a comment passes it. The assertion that a probe really
    reached `data/packet_features.py` is in the `measured` fixture, which counts
    calls into the production extractor while the block executes. Keep both: this
    one names the missing piece, that one proves the measurement happened.
    """
    source = extract_probe(doc_text)
    missing = [name for name in PROBE_MUST_MENTION if name not in source]
    assert not missing, (
        f"the §3 probe no longer mentions {missing}. §3's figures are published as "
        "measurements against data/packet_features.py under configs/data.yaml; a "
        "probe that does not call the extractor through the committed packet layout "
        "and the pinned generator cannot produce them."
    )


def test_every_published_row_is_claimed_by_a_guard(doc_text):
    """Coverage, in the direction that rots: a row added to a §3 table without an
    entry in PUBLISHED would be an unguarded published figure."""
    by_section = subsections(doc_text)
    unclaimed = []
    for section, text in by_section.items():
        labels = {row.doc_label for row in PUBLISHED if row.section == section}
        for cells in table_rows(text):
            if not any(label in cells[0] for label in labels):
                unclaimed.append((section, cells[0]))
    assert not unclaimed, (
        f"§3 publishes table rows no guard claims: {unclaimed}. Add a PublishedRow "
        "for each, or the figure ships unchecked."
    )


def test_every_published_figure_in_section_3_reproduces(doc_text, measured):
    """The eight rows, digit for digit, against a live run of the document's probe."""
    by_section = subsections(doc_text)
    failures: list[str] = []
    figures = 0
    rows_checked = 0

    for row in PUBLISHED:
        assert row.section in by_section, (
            f"§{row.section} is missing from {DOC.name}; "
            f"the '{row.doc_label}' row cannot be checked"
        )
        candidates = [
            cells for cells in table_rows(by_section[row.section])
            if row.doc_label in cells[0]
        ]
        assert len(candidates) == 1, (
            f"§{row.section}: expected exactly one table row whose label contains "
            f"{row.doc_label!r}, found {len(candidates)}: {candidates}"
        )
        published_cells = candidates[0][1:]
        assert len(published_cells) == len(row.fields), (
            f"§{row.section} '{row.doc_label}' publishes {len(published_cells)} "
            f"values but this guard knows {len(row.fields)} columns "
            f"{row.fields}: {published_cells}"
        )

        key = (row.section, row.probe_label)
        assert key in measured, (
            f"the §3 probe printed no '{row.section} {row.probe_label}' line; "
            f"it printed {sorted(measured)}"
        )
        probe_values = measured[key]

        rows_checked += 1
        for field, published in zip(row.fields, published_cells):
            figures += 1
            assert field in probe_values, (
                f"§{row.section} '{row.probe_label}': the probe printed no "
                f"{field!r} (it printed {sorted(probe_values)})"
            )
            if not reproduces(published, probe_values[field]):
                failures.append(
                    f"§{row.section} '{row.doc_label}' {field}: "
                    f"document publishes {published!r}, probe measured "
                    f"{probe_values[field]!r}"
                )

    assert rows_checked == EXPECTED_ROWS and figures == EXPECTED_FIGURES, (
        f"checked {rows_checked} rows / {figures} figures, expected "
        f"{EXPECTED_ROWS}/{EXPECTED_FIGURES} — the §3 tables changed shape, so this "
        "guard is no longer covering what it claims to cover"
    )
    assert not failures, (
        "docs/threat_model.md §3 no longer reproduces:\n  "
        + "\n  ".join(failures)
        + "\n\nEither data/packet_features.py / configs/data.yaml changed the "
        "measurement, or a published figure was edited by hand. Re-run the fenced "
        "probe from the repo root and publish what it prints."
    )


def test_section_3_2_prose_bin_shift_matches_the_measured_histograms(doc_text, measured):
    """§3.2's headline sentence names two bin indices. They are a measurement too."""
    text = subsections(doc_text)["3.2"]
    match = re.search(r"from bin (\d+) to bin (\d+)", normalise(text))
    assert match, "§3.2 no longer states which bin the payload mass moves from and to"
    source_bin, target_bin = int(match.group(1)), int(match.group(2))

    before = _as_ints(measured[("3.2", "30 x 1400B")]["hist"])
    after = _as_ints(measured[("3.2", "90 x 466B")]["hist"])
    assert sum(before) > 0 and sum(after) > 0, (before, after)
    assert before[source_bin] == sum(before) and after[target_bin] == sum(after), (
        f"§3.2 claims 100 % of the histogram mass moves from bin {source_bin} to "
        f"bin {target_bin}; measured {before} -> {after}"
    )


def test_section_3_4_prose_residual_step_count_matches_the_measurement(doc_text, measured):
    """§3.4 qualifies its 0.040 with '(here 4 of 99)'. Both halves are derived from
    the same measured row, so both are checked against it."""
    text = normalise(subsections(doc_text)["3.4"])
    match = re.search(r"\(here (\d+) of (\d+)\)", text)
    assert match, "§3.4 no longer states the residual sequential-step count"
    steps, denominator = int(match.group(1)), int(match.group(2))

    randomised = measured[("3.4", "randomised")]
    ports = int(float(randomised["distinct_dst_ports"]))
    assert denominator == ports - 1, (
        f"§3.4 says the residual is out of {denominator} steps; the measured row "
        f"touches {ports} ports, so the denominator is {ports - 1}"
    )
    ratio = float(randomised["sequential_port_ratio"])
    assert round(ratio * denominator) == steps, (
        f"§3.4 says {steps} of {denominator} accidental +1 steps; the measured "
        f"sequential_port_ratio {ratio} implies {round(ratio * denominator)}"
    )
