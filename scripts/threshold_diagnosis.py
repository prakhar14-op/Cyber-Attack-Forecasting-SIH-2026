"""Phase-0 diagnosis: is the gap ranking, or threshold transfer?

    python scripts/threshold_diagnosis.py            # all dumped models
    python scripts/threshold_diagnosis.py --model tgn

Reads the per-window score dumps written by the instrumented harness
(results/scores/<model>.npz) and, per FPR budget, compares:
  - the threshold chosen on VAL (what we ship) vs the ORACLE threshold that would
    hit the same FPR on TEST (a leakage-using ceiling, for diagnosis only);
  - test recall + episodes at each;
so we can see how much detection is lost purely to the operating point not
transferring across the family-disjoint days — i.e. how much Phase-1 calibration
could recover. Also prints AUROC (ranking quality) and where the test attacker's
own windows rank.

Nothing here is a reportable metric — the oracle threshold uses test labels and
exists only to bound what is recoverable.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from configs import load_config, resolve_path  # noqa: E402
from eval import dataset as D  # noqa: E402
from eval import metrics as M  # noqa: E402


def _episodes(cfg, host, ws, fired) -> tuple[int, int, float]:
    alerts = [{"host": h, "time": t} for h, t, f in zip(host, ws, fired) if f]
    lt = M.lead_time(D.attacker_episodes(cfg, "test"), alerts)
    return lt.n_detected, lt.n_episodes, lt.median


def diagnose(model: str, cfg, budgets) -> None:
    dump = resolve_path(load_config("eval")["paths"]["results_dir"]) / "scores" / f"{model}.npz"
    if not dump.exists():
        print(f"  (no score dump for {model} — run `python -m eval.harness --model {model}`)")
        return
    d = np.load(dump, allow_pickle=True)
    vy, vs = d["val_y"], d["val_score"]
    ty, ts, th, tw = d["test_y"], d["test_score"], d["test_host"], d["test_ws"]

    print(f"\n### {model}")
    print(f"  test AUROC {M.auroc(ty, ts):.3f}  (ranking quality — operating-point-independent)")
    print(f"  score range: val benign [{vs[vy == 0].min():.3g}, {vs[vy == 0].max():.3g}] "
          f"p99.9={np.percentile(vs[vy == 0], 99.9):.3g} | "
          f"test attack [{ts[ty == 1].min():.3g}, {ts[ty == 1].max():.3g}] "
          f"median={np.median(ts[ty == 1]):.3g}")

    for b in budgets:
        val_thr = M.threshold_at_fpr(vy, vs, b)          # what we ship
        oracle_thr = M.threshold_at_fpr(ty, ts, b)       # ceiling (uses test — diagnostic only)

        def stats(thr):
            fired = ts >= thr
            tp = int(np.count_nonzero(fired & (ty == 1)))
            fp = int(np.count_nonzero(fired & (ty == 0)))
            rec = tp / max(int((ty == 1).sum()), 1)
            fpr = fp / max(int((ty == 0).sum()), 1)
            det, tot, lead = _episodes(cfg, th, tw, fired)
            return rec, fpr, det, tot, lead

        r_v, fpr_v, det_v, tot, lead_v = stats(val_thr)
        r_o, fpr_o, det_o, _, lead_o = stats(oracle_thr)
        print(f"  @ {b:g} FPR budget:")
        print(f"     val-thr  = {val_thr:.4g}  -> test recall {r_v:.3f}, FPR {fpr_v:.4f}, "
              f"episodes {det_v}/{tot}, lead {lead_v:.0f}s   [SHIPPED]")
        print(f"     oracle   = {oracle_thr:.4g}  -> test recall {r_o:.3f}, FPR {fpr_o:.4f}, "
              f"episodes {det_o}/{tot}, lead {lead_o:.0f}s   [ceiling if the threshold transferred]")
        gap = "TRANSFER GAP" if (det_o > det_v or r_o > r_v + 0.05) else "transfers OK"
        print(f"     -> {gap}: val threshold is {val_thr / max(oracle_thr, 1e-12):.1f}x the "
              f"oracle; recoverable recall +{max(r_o - r_v, 0):.3f}, "
              f"episodes +{det_o - det_v}")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--model", default=None)
    args = ap.parse_args(argv)
    cfg = load_config("data")
    budgets = load_config("eval")["fpr_budgets"]

    scores_dir = resolve_path(load_config("eval")["paths"]["results_dir"]) / "scores"
    models = ([args.model] if args.model
              else sorted(p.stem for p in scores_dir.glob("*.npz")) if scores_dir.exists() else [])
    if not models:
        print("No score dumps yet. Run e.g. `python -m eval.harness --model tgn` "
              "(the instrumented harness writes results/scores/<model>.npz).")
        return 0

    print("=" * 78)
    print("PHASE-0 DIAGNOSIS: ranking vs threshold-transfer (test split, oracle = ceiling)")
    print("=" * 78)
    for m in models:
        diagnose(m, cfg, budgets)
    print("\nIf AUROC is high but the val-thr episodes/recall trail the oracle, the gap is\n"
          "threshold transfer (Phase-1 calibration territory), not model capacity.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
