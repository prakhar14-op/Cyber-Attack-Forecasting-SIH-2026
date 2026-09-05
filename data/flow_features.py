"""Flow-level feature pipeline (M1.2/M1.3): defect-tolerant loading + canonical schema.

The CIC-IDS-2018 processed CSVs ship real defects: repeated header rows mid-file,
``Infinity``/``NaN`` in the rate columns, mixed timestamp formats, whitespace
around column names, and rows out of time order. ``load_raw`` absorbs those;
``load_canonical`` maps the result onto the canonical schema defined in
``configs/data.yaml`` (the mapping lives there, never in code). Neither function
invents data — a missing mapped column raises.
"""

from __future__ import annotations

import os
from pathlib import Path

import numpy as np
import pandas as pd

# Fallback for the numeric-adoption ratio when a caller passes a config without
# a loader section (configs/data.yaml carries the real value). A column is
# adopted as numeric only if at least this share of its non-null values parse.
_NUMERIC_ADOPTION_RATIO = 0.9


def load_raw(cfg: dict, csv_path: str | os.PathLike) -> pd.DataFrame:
    """Read one processed-traffic CSV, absorbing the dataset's known defects.

    Returns a DataFrame with stripped raw column names, repeated header rows
    dropped, and every predominantly numeric column coerced to numbers with
    ``Infinity``/unparseable values as NaN. String columns (IPs, timestamps,
    labels, flow ids) are stripped but otherwise untouched.
    """
    csv_path = Path(csv_path)
    if not csv_path.exists():
        raise FileNotFoundError(f"flow CSV not found: {csv_path}")

    df = pd.read_csv(csv_path, dtype=str, skip_blank_lines=True)
    df.columns = [str(c).strip() for c in df.columns]

    label_col = cfg["schema"]["label"]
    if label_col not in df.columns:
        raise ValueError(
            f"{csv_path} has no '{label_col}' column after header cleanup; "
            f"columns start: {list(df.columns)[:6]}"
        )

    # Repeated header rows mid-file echo the column name into every cell.
    header_echo = df[label_col].astype(str).str.strip() == label_col
    if header_echo.any():
        df = df.loc[~header_echo]

    adoption_ratio = cfg.get("loader", {}).get(
        "numeric_adoption_ratio", _NUMERIC_ADOPTION_RATIO
    )
    for col in df.columns:
        # .str.strip() keeps genuine NaN cells as NaN (astype(str) would turn
        # them into the literal string "nan")
        series = df[col].str.strip()
        numeric = pd.to_numeric(series, errors="coerce")
        non_null = series.notna() & (series != "")
        if non_null.sum() == 0:
            df[col] = series
            continue
        parsed_ratio = numeric.notna()[non_null].mean()
        if parsed_ratio >= adoption_ratio:
            df[col] = numeric.replace([np.inf, -np.inf], np.nan)
        else:
            df[col] = series

    return df.reset_index(drop=True)


def load_canonical(cfg: dict, csv_path: str | os.PathLike) -> pd.DataFrame:
    """Load a CSV and map it onto the canonical schema from configs/data.yaml.

    Output columns follow the mapping's order; timestamps are parsed
    (mixed formats, day-first) and rows are stably sorted by time.
    """
    mapping = cfg["schema"]  # canonical name -> raw column
    df = load_raw(cfg, csv_path)

    missing = [raw for raw in mapping.values() if raw not in df.columns]
    if missing:
        raise ValueError(
            f"{csv_path} lacks mapped column(s) {missing} — "
            "this day needs features recomputed from PCAP (see decision 001)"
        )

    out = df[list(mapping.values())].copy()
    out.columns = list(mapping.keys())

    out["timestamp"] = pd.to_datetime(
        out["timestamp"].astype(str).str.strip(), format="mixed", dayfirst=True
    )

    out = out.sort_values("timestamp", kind="stable").reset_index(drop=True)
    return out


def canonical_numeric_columns(cfg: dict) -> list[str]:
    """Canonical columns that must be numeric (everything but time, IPs, label)."""
    non_numeric = {"timestamp", "src_ip", "dst_ip", "label"}
    return [name for name in cfg["schema"] if name not in non_numeric]


# ---------------------------------------------------------------------------
# Train-only scaler (M1.6 — resequenced after the extractor by decision 001).
# ---------------------------------------------------------------------------


def load_split_flows(cfg: dict, split: str) -> pd.DataFrame:
    """Concatenate the extracted canonical flows for every day in a split.

    Reads interim parquet written by `python -m data.extract`; a missing day
    fails loudly — this never falls back to CSVs or synthetic rows.
    """
    import yaml

    from configs import resolve_path

    with open(resolve_path(cfg["paths"]["splits"]), encoding="utf-8") as fh:
        splits = yaml.safe_load(fh)
    if split not in splits:
        raise KeyError(f"unknown split '{split}' (have {sorted(splits)})")

    frames = []
    for day in splits[split]:
        day_dir = resolve_path(cfg["paths"]["interim_dir"]) / str(day) / "flows"
        files = sorted(day_dir.glob("*.parquet"))
        if not files:
            raise FileNotFoundError(
                f"no extracted flows for {day} under {day_dir} — "
                "run `python -m data.zip_fetch` then `python -m data.extract`"
            )
        frames.extend(pd.read_parquet(f) for f in files)
    return pd.concat(frames, ignore_index=True)


def fit_scaler(cfg: dict, split: str = "train"):
    """Fit a StandardScaler on the canonical numeric columns of ONE split.

    Deterministic for a given extraction state (files sorted, no sampling),
    which is what tests/test_scaler_train_only.py exploits: refitting on the
    train split must reproduce the persisted statistics exactly.
    """
    from sklearn.preprocessing import StandardScaler

    flows = load_split_flows(cfg, split)
    columns = canonical_numeric_columns(cfg)
    matrix = flows[columns].astype(float)
    return StandardScaler().fit(matrix)


def fit_and_persist_scaler(cfg: dict) -> Path:
    """Fit on train only and persist scaler + feature order next to the weights."""
    import json
    import pickle

    from configs import resolve_path

    scaler = fit_scaler(cfg, split="train")
    scaler_path = resolve_path(cfg["paths"]["scaler"])
    scaler_path.parent.mkdir(parents=True, exist_ok=True)
    with open(scaler_path, "wb") as fh:
        pickle.dump(scaler, fh)
    names_path = resolve_path(cfg["paths"]["feature_names"])
    with open(names_path, "w", encoding="utf-8") as fh:
        json.dump({"flow_numeric": canonical_numeric_columns(cfg)}, fh, indent=2)
    return scaler_path


def main(argv: list[str] | None = None) -> int:
    import argparse

    from configs import load_config

    parser = argparse.ArgumentParser(description="Fit and persist the train-only scaler")
    parser.add_argument("--fit-scaler", action="store_true", required=True)
    parser.parse_args(argv)

    path = fit_and_persist_scaler(load_config("data"))
    print(f"scaler fitted on the train split only -> {path}")
    return 0


if __name__ == "__main__":
    import sys

    sys.exit(main())
