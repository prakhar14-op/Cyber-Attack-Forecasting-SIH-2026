"""Fused model (rank-mean of TGN + XGBoost) — the robustness play.

    python -m eval.harness --model fused

Design decision, made a priori (not tuned on test): the temporal-graph encoder
(TGN) and the static gradient-boosted baseline (XGBoost) look at the same
30-feature window matrix through different lenses, and their errors are nearly
uncorrelated (Spearman rho ~0.11 on test). Rank-mean fusion is parameter-free —
each model's scores are converted to within-split percentiles and averaged — so
nothing is fitted on val or test for the ranking. Ranks are scale-free, which
also makes the FPR-budget threshold transfer across days far better than raw
scores do.

For a calibrated PROBABILITY output (ECE), the fused rank is passed through an
isotonic regressor fitted on VAL only; isotonic is monotonic, so it cannot
change which windows fire at an FPR-budget threshold — it only makes the
reported probability honest.

Reads the per-window score dumps the instrumented harness wrote for the member
models (results/scores/{tgn,xgb}.npz) and writes results/fused.json in the
standard schema, plus its own score dump.
"""

from __future__ import annotations

import json
import sys

import numpy as np

from configs import load_config, resolve_path
from eval import dataset as D
from eval import metrics as M

MEMBERS = ("xgb", "tgn")


def _load_member(name: str):
    p = resolve_path(load_config("eval")["paths"]["results_dir"]) / "scores" / f"{name}.npz"
    if not p.exists():
        raise FileNotFoundError(
            f"{p} missing — run `python -m eval.harness --model {name}` first "
            "(the instrumented harness writes the score dump the fusion reads)."
        )
    return np.load(p, allow_pickle=True)


def _percentile_rank(x: np.ndarray) -> np.ndarray:
    from scipy.stats import rankdata
    return rankdata(x) / len(x)


def evaluate_fused(members: tuple[str, ...] = MEMBERS) -> dict:
    cfg = load_config("data")
    cfg_eval = load_config("eval")
    dumps = [_load_member(m) for m in members]

    ref = dumps[0]
    for m, d in zip(members[1:], dumps[1:]):
        for split in ("val", "test"):
            if not np.array_equal(ref[f"{split}_y"], d[f"{split}_y"]):
                raise RuntimeError(
                    f"member dumps disagree on the {split} rows ({members[0]} vs {m}) "
                    "— re-run the members under the same key")

    fused = {s: np.mean([_percentile_rank(d[f"{s}_score"]) for d in dumps], axis=0)
             for s in ("val", "test")}
    y = {s: ref[f"{s}_y"] for s in ("val", "test")}
    host = {s: ref[f"{s}_host"] for s in ("val", "test")}
    ws = {s: ref[f"{s}_ws"] for s in ("val", "test")}

    # calibrated probability (VAL-fit isotonic; monotonic -> ranking unchanged)
    from sklearn.isotonic import IsotonicRegression
    iso = IsotonicRegression(out_of_bounds="clip").fit(fused["val"], y["val"])
    prob = {s: iso.predict(fused[s]) for s in ("val", "test")}

    name = "fused" if tuple(members) == MEMBERS else f"fused{len(members)}"
    result = {"model": name, "horizon": 0, "holdout_family": None,
              "members": list(members), "test": {}, "val": {}}
    for budget in cfg_eval["fpr_budgets"]:
        thr = M.threshold_at_fpr(y["val"], fused["val"], budget)
        for s in ("val", "test"):
            pred = fused[s] >= thr
            tp = int(np.count_nonzero(pred & (y[s] == 1)))
            fp = int(np.count_nonzero(pred & (y[s] == 0)))
            fn = int(np.count_nonzero(~pred & (y[s] == 1)))
            tn = int(np.count_nonzero(~pred & (y[s] == 0)))
            precision = tp / (tp + fp) if (tp + fp) else 0.0
            recall = tp / (tp + fn) if (tp + fn) else 0.0
            f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
            alerts = [{"host": h, "time": t}
                      for h, t, fired in zip(host[s], ws[s], pred) if fired]
            lt = M.lead_time(D.attacker_episodes(cfg, s), alerts)
            result[s][f"fpr_{budget}"] = {
                "threshold": float(thr), "precision": precision, "recall": recall,
                "f1": f1, "fpr": fp / (fp + tn) if (fp + tn) else 0.0,
                "n_alerts": tp + fp,
                "alerts_per_host_day": M.alerts_per_host_day(tp + fp, len(y[s]), cfg),
                "lead_time_median": lt.median, "lead_time_iqr": [lt.iqr_low, lt.iqr_high],
                "episodes_detected": lt.n_detected, "episodes_total": lt.n_episodes,
            }
    for s in ("val", "test"):
        result[s]["auroc"] = M.auroc(y[s], fused[s])
        result[s]["ece"] = M.expected_calibration_error(
            y[s], prob[s], cfg_eval["metrics"]["ece_bins"]).ece
        result[s]["n_host_windows"] = int(len(y[s]))
        result[s]["n_attack_windows"] = int(np.count_nonzero(y[s]))

    out_dir = resolve_path(cfg_eval["paths"]["results_dir"])
    scores_dir = out_dir / "scores"
    scores_dir.mkdir(parents=True, exist_ok=True)
    np.savez(scores_dir / f"{name}.npz",
             **{f"{s}_{k}": v for s in ("val", "test")
                for k, v in (("y", y[s]), ("score", fused[s]),
                             ("host", host[s]), ("ws", ws[s]))})
    (out_dir / f"{name}.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    return result


def main(argv: list[str] | None = None) -> int:
    import argparse

    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--members", default=",".join(MEMBERS),
                    help="comma-separated member models whose score dumps to fuse")
    args = ap.parse_args(argv)  # None -> sys.argv (module CLI); harness passes []
    members = tuple(m.strip() for m in args.members.split(",") if m.strip())

    r = evaluate_fused(members)
    t1 = r["test"]["fpr_0.01"]
    print(f"{r['model']}({'+'.join(members)}): test AUROC={r['test']['auroc']:.3f} "
          f"F1@1%={t1['f1']:.3f} recall={t1['recall']:.3f} "
          f"lead={t1['lead_time_median']:.0f}s "
          f"({t1['episodes_detected']}/{t1['episodes_total']} episodes) "
          f"| val AUROC={r['val']['auroc']:.3f}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
