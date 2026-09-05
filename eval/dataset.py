"""Assemble the model-ready matrices from the M3 window features (M4).

Every model in the harness trains and is scored on the IDENTICAL feature matrix
(the PS's requirement for the graded LR baseline). This module is the one place
that turns per-(host, window) features + stage labels into (X, y, meta) and the
attack episodes the lead-time metric needs.

Anti-leakage: the scaler is fit on the TRAIN split only and reused for val/test.
The binary target is `attack = stage != benign`, shifted forward by `horizon`
windows per host for forecasting (`horizon=0` is nowcast, used by the M4
baselines).
"""

from __future__ import annotations

import pickle
from dataclasses import dataclass

import numpy as np
import pandas as pd
import yaml

from configs import resolve_path
from data import timeline_labels as TL
from data import windows as W


@dataclass
class Split:
    X: np.ndarray            # [n, F] scaled features, float32
    y: np.ndarray            # [n] binary attack target at window t+horizon
    stage: np.ndarray        # [n] stage label string at window t+horizon
    host: np.ndarray         # [n] real host IP (metadata, NOT a feature)
    window_start: np.ndarray # [n] epoch seconds of window t
    feature_names: list[str]
    n_host_windows: int


def _split_days(cfg: dict, split: str) -> list[str]:
    with open(resolve_path(cfg["paths"]["splits"]), encoding="utf-8") as fh:
        splits = yaml.safe_load(fh)
    return [str(d) for d in splits[split]]


def _shift_target_by_horizon(
    labelled: pd.DataFrame, horizon: int
) -> tuple[np.ndarray, np.ndarray]:
    """Per host, the stage/attack target at window t+horizon (aligned to t).

    Rows whose t+horizon window is not present for that host (no future window)
    are dropped by returning NaN markers the caller filters. horizon=0 is the
    identity.
    """
    if horizon == 0:
        stage = labelled["stage"].to_numpy()
        return stage, (stage != "benign")

    # Build a (host, window_id)->stage lookup, then read t+horizon.
    lut = {
        (h, int(w)): s
        for h, w, s in zip(labelled["host"], labelled["window_id"], labelled["stage"])
    }
    future_stage = np.array(
        [lut.get((h, int(w) + horizon), None)
         for h, w in zip(labelled["host"], labelled["window_id"])],
        dtype=object,
    )
    return future_stage, np.array([s is not None and s != "benign" for s in future_stage])


def assemble_split(
    cfg: dict, split: str, horizon: int = 0, scaler=None, fit_scaler: bool = False
) -> tuple[Split, object]:
    """Build (Split, scaler) for one split at a forecast horizon.

    Pass fit_scaler=True on the train split to fit and return a new scaler;
    pass the returned scaler for val/test. Feature order follows
    windows.feature_columns exactly.
    """
    from data.anonymize import Anonymizer

    anonymizer = Anonymizer.from_config(cfg)  # env HMAC key; role features only
    labelled = W.build_labelled_split(cfg, split, anonymizer=anonymizer)
    labelled = labelled.sort_values(["host", "window_id"], kind="stable").reset_index(
        drop=True
    )
    feat_cols = W.feature_columns(cfg)
    X_raw = labelled[feat_cols].to_numpy(dtype=np.float64)

    stage, y = _shift_target_by_horizon(labelled, horizon)
    # For horizon>0, drop rows with no t+horizon window (stage is None).
    keep = np.array([s is not None for s in stage]) if horizon > 0 else np.ones(len(labelled), bool)
    X_raw, stage, y = X_raw[keep], stage[keep], y[keep]
    meta = labelled.loc[keep]

    if fit_scaler:
        from sklearn.preprocessing import StandardScaler

        scaler = StandardScaler().fit(X_raw)
    if scaler is None:
        raise ValueError("scaler required for a non-fit split; pass fit_scaler=True on train")
    X = scaler.transform(X_raw).astype(np.float32)

    return (
        Split(
            X=X,
            y=y.astype(np.int8),
            stage=stage.astype(str) if horizon > 0 else stage,
            host=meta["host"].to_numpy(),
            window_start=meta["window_start"].to_numpy(dtype=float),
            feature_names=feat_cols,
            n_host_windows=len(meta),
        ),
        scaler,
    )


def attacker_episodes(cfg: dict, split: str) -> list[dict]:
    """Attack episodes for lead-time: one per (attack, attacker host) on the
    split's days, with the annotated completion time (UTC epoch).

    Lead time is measured on the ATTACKING host (PS wording). External/NAT'd
    attackers appear as sources inside the victims' captures, so they have
    host-windows to alert on.
    """
    days = set(_split_days(cfg, split))
    timeline = TL.load_timeline(cfg)
    offset = timeline["timezone"]["utc_offset_hours"]
    episodes = []
    for day in timeline["days"]:
        if day["date"] not in days:
            continue
        for atk in day["attacks"]:
            start = TL._local_to_epoch_utc(day["date"], atk["start"], offset)
            end = TL._local_to_epoch_utc(day["date"], atk["end"], offset)
            for host in atk["attacker_ips"]:
                episodes.append(
                    {"host": host, "start": start, "end": end,
                     "name": atk["name"], "stage": atk["stage"]}
                )
    return episodes


def persist_window_scaler(cfg: dict, scaler) -> str:
    """Save the window-level scaler next to the weights (M8 loads it)."""
    path = resolve_path(cfg["paths"]["artifacts_dir"]) / "window_scaler.pkl"
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "wb") as fh:
        pickle.dump(scaler, fh)
    return str(path)
