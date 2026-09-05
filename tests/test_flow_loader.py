"""M1.2/M1.3: the flow loader survives the dataset's real defects and emits the
canonical schema — on the committed fixture and on a deliberately corrupted copy.
"""

from __future__ import annotations

import numpy as np
import pytest
import pandas as pd

from data import flow_features


def test_fixture_loads_to_canonical_schema_sorted_and_finite(data_cfg, fixture_csv):
    df = flow_features.load_canonical(data_cfg, fixture_csv)

    assert list(df.columns) == list(data_cfg["schema"].keys())
    assert len(df) == 1000
    assert df["timestamp"].dtype.kind == "M", "timestamps must parse to datetimes"
    assert df["timestamp"].notna().all()
    assert df["timestamp"].is_monotonic_increasing, "loader must sort by time"

    labels = set(df["label"].unique())
    assert "Benign" in labels and len(labels) == 2, "fixture spans benign + one attack"

    for col in flow_features.canonical_numeric_columns(data_cfg):
        assert df[col].dtype.kind in "iuf", f"canonical column '{col}' is not numeric"
        values = df[col].to_numpy(dtype=float)
        assert not np.isinf(values).any(), f"Infinity leaked through '{col}'"

    assert df["src_port"].between(0, 65535).all()
    assert df["dst_port"].between(0, 65535).all()


def _corrupt(fixture_csv, target) -> None:
    """Write a copy with the dataset's defect catalogue injected on purpose:
    whitespace-padded header names, the header repeated mid-file (twice), an
    AM/PM timestamp variant, and Infinity/NaN in the rate columns.
    """
    lines = fixture_csv.read_text(encoding="utf-8").splitlines()
    header, body = lines[0], lines[1:]
    columns = header.split(",")

    padded_header = ",".join(f" {name} " for name in columns)

    ts_i = columns.index("Timestamp")
    byts_i = columns.index("Flow Byts/s")
    pkts_i = columns.index("Flow Pkts/s")

    row = body[10].split(",")
    row[ts_i] = row[ts_i] + " AM" if not row[ts_i].endswith("M") else row[ts_i]
    body[10] = ",".join(row)

    row = body[20].split(",")
    row[byts_i], row[pkts_i] = "Infinity", "NaN"
    body[20] = ",".join(row)

    corrupted = body[:100] + [header] + body[100:500] + [header] + body[500:]
    target.write_text(padded_header + "\n" + "\n".join(corrupted) + "\n", encoding="utf-8")


def test_deliberately_corrupted_copy_loads_identically(data_cfg, fixture_csv, tmp_path):
    corrupted_csv = tmp_path / "corrupted.csv"
    _corrupt(fixture_csv, corrupted_csv)

    clean = flow_features.load_canonical(data_cfg, fixture_csv)
    corrupted = flow_features.load_canonical(data_cfg, corrupted_csv)

    assert len(corrupted) == 1000, "repeated header rows must be dropped, not counted"
    assert corrupted["timestamp"].notna().all(), "AM/PM timestamp variant must parse"

    # The injected defects live outside the canonical columns (rates) or are
    # semantically neutral (AM suffix on a morning time, header padding), so the
    # canonical frames must come out identical.
    pd.testing.assert_frame_equal(clean, corrupted)

    raw = flow_features.load_raw(data_cfg, corrupted_csv)
    for col in ("Flow Byts/s", "Flow Pkts/s"):
        values = pd.to_numeric(raw[col], errors="coerce").to_numpy(dtype=float)
        assert not np.isinf(values).any(), f"Infinity survived load_raw in '{col}'"


def test_load_canonical_fails_loudly_when_ip_columns_absent(data_cfg, fixture_csv, tmp_path):
    """The dataset's dominant real defect (decision 001): every day but 20-02
    ships a CSV starting at 'Dst Port' with no Src/Dst IP. load_canonical must
    fail loudly naming the missing column, never silently drop identity."""
    header = fixture_csv.read_text(encoding="utf-8").splitlines()[0].split(",")
    keep = [c for c in header if c.strip() not in ("Src IP", "Dst IP")]
    df = pd.read_csv(fixture_csv, dtype=str)
    df.columns = [c.strip() for c in df.columns]
    no_ip = tmp_path / "no_ip_columns.csv"
    df[keep].to_csv(no_ip, index=False)

    with pytest.raises(ValueError, match="Src IP|Dst IP|PCAP"):
        flow_features.load_canonical(data_cfg, no_ip)
