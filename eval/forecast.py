"""Encoder forecasting at horizon k (M7, shipped after decision 004).

The RSSM rollout failed the M7.7 hard gate (posterior collapse; worse than its
own inputs — decision 004). The forecasting SIGNAL, though, lives in the TGN
temporal-graph encoder: this module ships that capability honestly as a
FORECASTER — labels are shifted by k, so it predicts "attack on this host in
k windows", not a nowcast.

    python -m eval.harness --model forecast

Per horizon k in configs/eval.yaml: fit a benign-subsampled linear head on the
frozen TGN embeddings with labels shifted +k (the subsampled head is what gave
the strong M5 operating point; a full imbalanced fit ranks the same but
calibrates worse), choose the threshold on val, report test F1/AUROC/lead time
with grace = k*stride. Writes results/forecast.json for the ablation table and
the lead-time plot.
"""

from __future__ import annotations

import json
import sys

import numpy as np
import pandas as pd
import torch

from configs import load_config, resolve_path, set_seed
from eval import dataset as D
from eval import metrics as M


def _tgn_row_embeddings(cfg, cfg_t, encoder, anonymizer, msg_scaler, split, split_name):
    from data.flow_features import load_split_flows
    from models import tgn as T

    flows = load_split_flows(cfg, split_name)
    events = T.build_events(cfg_t, flows, anonymizer, 0, msg_scaler)
    ro = pd.DataFrame({"host": split.host, "window_start": split.window_start})
    return T.snapshot_embeddings(encoder, events, ro, cfg_t)


def evaluate_forecast() -> dict:
    from data.anonymize import Anonymizer
    from data.flow_features import fit_scaler
    from eval.world import _load_frozen_stack
    from sklearn.linear_model import LogisticRegression

    cfg = load_config("data")
    cfg_eval = load_config("eval")
    cfg_t = load_config("train_tgn")
    set_seed(cfg_t["seed"])
    stride = cfg["windows"]["stride_seconds"]

    anonymizer = Anonymizer.from_config(cfg)
    msg_scaler = fit_scaler(cfg, split="train")
    encoder, _graft, cfg_t, _cfg_g = _load_frozen_stack(cfg, msg_dim=len(msg_scaler.mean_))

    # base (horizon-0) rows + embeddings per split, keyed by (host, window_id)
    tr, scaler = D.assemble_split(cfg, "train", horizon=0, fit_scaler=True)
    va, _ = D.assemble_split(cfg, "val", horizon=0, scaler=scaler)
    te, _ = D.assemble_split(cfg, "test", horizon=0, scaler=scaler)
    base = {"train": tr, "val": va, "test": te}
    emb = {nm: _tgn_row_embeddings(cfg, cfg_t, encoder, anonymizer, msg_scaler, s, nm)
           for nm, s in base.items()}
    key = {nm: {(h, int(w)): i for i, (h, w) in enumerate(
                zip(s.host, (s.window_start / stride).astype(int)))}
           for nm, s in base.items()}

    def rows_for(nm, split_k):
        return np.array([key[nm][(h, int(w))]
                         for h, w in zip(split_k.host,
                                         (split_k.window_start / stride).astype(int))])

    rng = np.random.RandomState(cfg_t["seed"])
    sub_n = int(cfg_t["head"]["benign_subsample"])
    result = {"model": "forecast", "horizons": {}}

    for k in cfg_eval["horizons"] + ([0] if 0 not in cfg_eval["horizons"] else []):
        sk, _ = D.assemble_split(cfg, "train", horizon=k, scaler=scaler)
        vk, _ = D.assemble_split(cfg, "val", horizon=k, scaler=scaler)
        tk, _ = D.assemble_split(cfg, "test", horizon=k, scaler=scaler)

        Xtr = emb["train"][rows_for("train", sk)]
        ytr = sk.y
        atk = np.flatnonzero(ytr == 1)
        ben = np.flatnonzero(ytr == 0)
        take = min(sub_n, len(ben))
        idx = np.concatenate([atk, rng.choice(ben, take, replace=False)])
        head = LogisticRegression(
            C=cfg_t["head"]["C"], max_iter=cfg_t["head"]["max_iter"],
            class_weight="balanced").fit(Xtr[idx], ytr[idx])

        pv = head.predict_proba(emb["val"][rows_for("val", vk)])[:, 1]
        pt = head.predict_proba(emb["test"][rows_for("test", tk)])[:, 1]

        block = {"auroc_val": M.auroc(vk.y, pv), "auroc_test": M.auroc(tk.y, pt),
                 "n_attack_test": int(tk.y.sum())}

        # Per-horizon score dump for the calibration/oracle diagnosis (Part 2):
        # thresholds are ALREADY fitted per-horizon below, so k=8's miss is a
        # val->test transfer question, not a reused-threshold bug — these dumps
        # let scripts/threshold_diagnosis.py confirm which it is.
        scores_dir = resolve_path(cfg_eval["paths"]["results_dir"]) / "scores"
        scores_dir.mkdir(parents=True, exist_ok=True)
        np.savez(scores_dir / f"forecast_k{k}.npz",
                 val_y=np.asarray(vk.y), val_score=np.asarray(pv, dtype=float),
                 val_host=np.asarray(vk.host).astype(str),
                 val_ws=np.asarray(vk.window_start, dtype=float),
                 test_y=np.asarray(tk.y), test_score=np.asarray(pt, dtype=float),
                 test_host=np.asarray(tk.host).astype(str),
                 test_ws=np.asarray(tk.window_start, dtype=float))
        for budget in cfg_eval["fpr_budgets"]:
            thr = M.threshold_at_fpr(vk.y, pv, budget)
            pred = pt >= thr
            tp = int(np.count_nonzero(pred & (tk.y == 1)))
            fp = int(np.count_nonzero(pred & (tk.y == 0)))
            fn = int(np.count_nonzero(~pred & (tk.y == 1)))
            tn = int(np.count_nonzero(~pred & (tk.y == 0)))
            precision = tp / (tp + fp) if (tp + fp) else 0.0
            recall = tp / (tp + fn) if (tp + fn) else 0.0
            f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
            alerts = [{"host": h, "time": t}
                      for h, t, fired in zip(tk.host, tk.window_start, pred) if fired]
            lt = M.lead_time(D.attacker_episodes(cfg, "test"), alerts, grace_seconds=k * stride)
            block[f"fpr_{budget}"] = {
                "threshold": thr, "precision": precision, "recall": recall, "f1": f1,
                "fpr": fp / (fp + tn) if (fp + tn) else 0.0,
                "lead_time_median": lt.median, "lead_time_iqr": [lt.iqr_low, lt.iqr_high],
                "per_episode_seconds": list(lt.per_episode_seconds),
                "episodes_detected": lt.n_detected, "episodes_total": lt.n_episodes,
                "alerts_per_host_day": M.alerts_per_host_day(tp + fp, tk.n_host_windows, cfg),
            }
        result["horizons"][k] = block
        print(f"forecast k={k}: test AUROC {block['auroc_test']:.3f} "
              f"F1@1% {block['fpr_0.01']['f1']:.3f} "
              f"lead {block['fpr_0.01']['lead_time_median']:.0f}s "
              f"({block['fpr_0.01']['episodes_detected']}/{block['fpr_0.01']['episodes_total']})",
              flush=True)
    return result


def main() -> int:
    result = evaluate_forecast()
    cfg_eval = load_config("eval")
    out_dir = resolve_path(cfg_eval["paths"]["results_dir"])
    out_dir.mkdir(parents=True, exist_ok=True)
    out = out_dir / "forecast.json"
    out.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(f"-> {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
