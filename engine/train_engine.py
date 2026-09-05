"""Fit and persist the deployed engine model + threshold (M8.1).

The engine ships an EXPLAINABLE gradient-boosted model on the 30 named window
features — TreeSHAP gives exact named-feature attributions (M8.2/8.4), it runs
offline and deterministically, and it is the strong cross-family baseline
(0.895 AUROC). The temporal-graph forecaster stays the research result in the
ablation table; the engine's requirement is explainability, which a black-box
graph rollout cannot provide directly.

Persists: artifacts/engine_model.json (xgboost), engine_threshold.json (M8.1),
and the feature order — all loaded by engine/predict.py with no network.
"""

from __future__ import annotations

import sys

import numpy as np

from configs import load_config, resolve_path, set_seed
from engine import thresholds as TH


def main() -> int:
    from eval import dataset as D
    from eval import metrics as M
    from models import baselines

    cfg = load_config("data")
    cfg_eval = load_config("eval")
    cfg_b = load_config("baselines")
    set_seed(cfg_b["seed"])

    train, scaler = D.assemble_split(cfg, "train", horizon=0, fit_scaler=True)
    val, _ = D.assemble_split(cfg, "val", horizon=0, scaler=scaler)

    # The deployed engine must run on CSV input, which has NO packet features
    # (decision 001). Zero the 17 packet-statistic columns in TRAINING too, so
    # the engine model is a flow-level model that behaves identically whether a
    # CSV (packet features naturally absent) or a PCAP feeds it. The strong
    # packet-feature model stays the research/ablation result; the engine's
    # non-negotiable requirement is running on the file the PS accepts.
    from data import windows as W

    packet_cols = list(cfg["packet_features"]["fields"])
    feat_names = W.feature_columns(cfg)
    zero = np.array([1.0 if c not in packet_cols else 0.0 for c in feat_names], dtype=np.float32)
    Xtr = train.X * zero
    Xva = val.X * zero

    model = baselines.build_model("xgb", cfg_b).fit(Xtr, train.y)
    val_scores = model.predict_proba(Xva)
    print(f"engine model trained on {int(zero.sum())} flow-derivable features "
          f"({len(feat_names) - int(zero.sum())} packet-stat features zeroed for CSV parity); "
          f"val AUROC {M.auroc(val.y, val_scores):.3f}")

    persisted = {"model": "xgb", "features": train.feature_names}
    for budget in cfg_eval["fpr_budgets"]:
        persisted[f"fpr_{budget}"] = M.threshold_at_fpr(val.y, val_scores, budget)

    art = resolve_path(cfg["paths"]["artifacts_dir"])
    art.mkdir(parents=True, exist_ok=True)
    model.model.save_model(str(art / "engine_model.json"))
    D.persist_window_scaler(cfg, scaler)  # the engine scales inputs with this
    TH.persist_threshold(cfg, persisted)

    print(f"engine model + thresholds persisted to {art}")
    print(f"  thresholds: " + ", ".join(
        f"{b}={persisted[f'fpr_{b}']:.4f}" for b in cfg_eval["fpr_budgets"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
