"""Fit and persist the deployed engine models + thresholds (M8.1).

The engine ships an EXPLAINABLE gradient-boosted model on the 30 named window
features — TreeSHAP gives exact named-feature attributions (M8.2/8.4), it runs
offline and deterministically, and it is the strong cross-family baseline
(0.895 AUROC). The temporal-graph forecaster stays the research result in the
ablation table; the engine's requirement is explainability, which a black-box
graph rollout cannot provide directly.

Fits ONE HEAD PER (input variant, horizon): horizon 0 is the nowcast the engine
alerts on, and each k in configs/data.yaml `engine.forecast_horizons` gets its
own head trained on labels shifted +k windows per host — the SAME shift
eval/dataset.py applies, so the deployed forecaster and the harness predict the
same target. Each head also gets its OWN FPR-budget thresholds: a head at k=8
has its own score distribution, and reusing k=0's cut would move the operating
point without saying so.

Fitting a head is not evidence that it forecasts. What is persisted per head is
its own validation AUROC, and nothing else about it is measured here; the
published k-step verdict — no supported forward operating point at any horizon
— is in docs/limitations.md and is what engine/forecast.py reports to the user.

Persists: artifacts/engine_model[_flow][_k<K>].json (xgboost),
engine_threshold.json (M8.1), and the feature order — all loaded by
engine/predict.py and engine/forecast.py with no network.
"""

from __future__ import annotations

import sys

import numpy as np

from configs import load_config, resolve_path, set_seed
from engine import thresholds as TH


def head_filename(tag: str, horizon: int) -> str:
    """Weight file for one (input variant, horizon) head.

    Horizon 0 keeps the historical name, so artifacts persisted before the
    k-step heads existed stay loadable; k>0 gets its own file. Spelled here and
    nowhere else — two heads sharing a filename is a forecast served by the
    wrong horizon's model, and it is silent, because the file still loads.
    """
    TH.horizon_variant(tag, horizon)  # rejects a negative / non-int horizon
    stem = "engine_model" if tag == "full" else f"engine_model_{tag}"
    return f"{stem}.json" if horizon == 0 else f"{stem}_k{horizon}.json"


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

    # One head per (variant, horizon). The VARIANT is picked at inference by the
    # input's feature availability — FULL (all 30 features) for PCAP, FLOW-ONLY
    # for CSV, which cannot carry the 17 packet-stat features (decision 001).
    # The full model is the strong one; the engine's non-negotiable requirement
    # is that BOTH input formats the PS accepts produce self-consistent output.
    # The HORIZON is picked by the caller: 0 for engine/predict.py's nowcast
    # alerts, k>0 for engine/forecast.py's forward curve.
    horizons = [int(k) for k in cfg["engine"]["forecast_horizons"]]
    stride = float(cfg["windows"]["stride_seconds"])
    persisted = {"model": "xgb", "features": feat_names,
                 "stride_seconds": stride, "horizons": horizons}

    # Horizon 0 (the nowcast the engine alerts on) reuses the already-assembled
    # splits; each k>0 re-assembles with the target shifted +k windows per host.
    for horizon in [0, *horizons]:
        if horizon == 0:
            tr, va = train, val
        else:
            tr, _ = D.assemble_split(cfg, "train", horizon=horizon, scaler=scaler)
            va, _ = D.assemble_split(cfg, "val", horizon=horizon, scaler=scaler)
            # Shifting the target drops every row with no t+k window for that
            # host. A split left with one class cannot fit or threshold a head,
            # and a head fitted on it would score every window identically while
            # still looking like a model — refuse, loudly, rather than persist it.
            for name, split in (("train", tr), ("val", va)):
                n_attack = int(split.y.sum())
                if n_attack == 0 or n_attack == len(split.y):
                    raise ValueError(
                        f"horizon k={horizon}: the {name} split has {n_attack} attack "
                        f"rows out of {len(split.y)} after shifting the target +{horizon} "
                        "windows — a single-class split cannot fit or threshold a "
                        "forecast head. Lower engine.forecast_horizons in "
                        "configs/data.yaml or widen the split."
                    )
        for tag, mask in (
            ("full", None),
            # FLOW-ONLY: the 17 packet-stat cols zeroed, because CSV input cannot
            # carry them (decision 001) — trained zeroed so train == inference.
            ("flow", flow_mask),
        ):
            X_tr = tr.X if mask is None else tr.X * mask
            X_va = va.X if mask is None else va.X * mask
            fname = head_filename(tag, horizon)
            variant = TH.horizon_variant(tag, horizon)
            model = baselines.build_model("xgb", cfg_b).fit(X_tr, tr.y)
            scores = model.predict_proba(X_va)
            model.model.save_model(str(art / fname))
            auc = M.auroc(va.y, scores)
            block = {"file": fname, "val_auroc": float(auc),
                     "horizon": horizon, "seconds_ahead": horizon * stride}
            # Per-horizon thresholds: k=8's cut is NOT k=0's cut.
            for budget in cfg_eval["fpr_budgets"]:
                block[f"fpr_{budget}"] = M.threshold_at_fpr(va.y, scores, budget)
            persisted[variant] = block
            print(f"engine {variant} model (k={horizon}, +{horizon * stride:g}s): "
                  f"val AUROC {auc:.3f} -> {fname}")

    TH.persist_threshold(cfg, persisted)
    print(f"engine models + thresholds persisted to {art}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
