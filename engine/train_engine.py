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

    from data import windows as W

    train, scaler = D.assemble_split(cfg, "train", horizon=0, fit_scaler=True)
    val, _ = D.assemble_split(cfg, "val", horizon=0, scaler=scaler)
    art = resolve_path(cfg["paths"]["artifacts_dir"])
    art.mkdir(parents=True, exist_ok=True)
    D.persist_window_scaler(cfg, scaler)  # the engine scales inputs with this

    packet_cols = list(cfg["packet_features"]["fields"])
    feat_names = W.feature_columns(cfg)
    flow_mask = np.array(
        [0.0 if c in packet_cols else 1.0 for c in feat_names], dtype=np.float32)

    # Two models, picked at inference by the input's feature availability:
    #  - FULL (all 30 features) for PCAP input, which has packet features.
    #  - FLOW-ONLY (17 packet-stat cols zeroed) for CSV input, which cannot carry
    #    them (decision 001) — trained with them zeroed so train == inference.
    # The full model is the strong one; the engine's non-negotiable requirement
    # is that BOTH input formats the PS accepts produce self-consistent output.
    persisted = {"model": "xgb", "features": feat_names}
    for tag, X_tr, X_va, fname in (
        ("full", train.X, val.X, "engine_model.json"),
        ("flow", train.X * flow_mask, val.X * flow_mask, "engine_model_flow.json"),
    ):
        model = baselines.build_model("xgb", cfg_b).fit(X_tr, train.y)
        scores = model.predict_proba(X_va)
        model.model.save_model(str(art / fname))
        auc = M.auroc(val.y, scores)
        persisted[tag] = {"file": fname, "val_auroc": float(auc)}
        for budget in cfg_eval["fpr_budgets"]:
            persisted[tag][f"fpr_{budget}"] = M.threshold_at_fpr(val.y, scores, budget)
        print(f"engine {tag} model: val AUROC {auc:.3f} -> {fname}")

    TH.persist_threshold(cfg, persisted)
    print(f"engine models + thresholds persisted to {art}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
