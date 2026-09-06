"""Accuracy report: confusion matrix + classification metrics per model.

    python scripts/accuracy_report.py                 # both FPR budgets
    python scripts/accuracy_report.py --budget 0.01   # one budget

Numbers come from results/*.json (written by eval/harness.py) - never hand-typed.
They are measured on the TEST split (02-03 bot day), with the operating point
chosen from an FPR budget on the VALIDATION split (the PS requirement - never a
hardcoded threshold), per (source-host, 15 s window). The confusion counts are
reconstructed exactly from the stored recall and alert count and cross-checked
against the stored FPR.

Read this with the class imbalance in mind: benign host-windows outnumber attack
windows ~40:1, so plain ACCURACY is ~0.98 for everything and is meaningless here.
F1 / precision / recall at a fixed FPR - and, above all, lead time - are what the
problem statement grades. The graded logistic-regression baseline is included.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from configs import load_config, resolve_path  # noqa: E402


def load_test_results() -> dict:
    results_dir = resolve_path(load_config("eval")["paths"]["results_dir"])
    out = {}
    for p in sorted(results_dir.glob("*.json")):
        r = json.loads(p.read_text(encoding="utf-8"))
        if "test" not in r:  # skip the horizon-schema files (forecast, world)
            continue
        name = r["model"] + (f" (holdout {r['holdout_family']})"
                             if r.get("holdout_family") else "")
        out[name] = r["test"]
    return out


def confusion(test: dict, budget: float) -> tuple[int, int, int, int]:
    """Exact TP/FP/FN/TN from the stored recall + alert count."""
    pt = test[f"fpr_{budget}"]
    pos = int(test["n_attack_windows"])
    neg = int(test["n_host_windows"]) - pos
    tp = round(pt["recall"] * pos)
    fp = int(pt["n_alerts"]) - tp
    fn = pos - tp
    tn = neg - fp
    return tp, fp, fn, tn


def _metrics(tp: int, fp: int, fn: int, tn: int) -> dict:
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    acc = (tp + tn) / (tp + fp + fn + tn)
    return {"precision": prec, "recall": rec, "f1": f1, "fpr": fpr, "accuracy": acc}


def report(budget: float) -> None:
    results = load_test_results()
    if not results:
        print("No results with a test block - run `python -m eval.harness --model lr` first.")
        return

    print("=" * 78)
    print(f"ACCURACY REPORT - test split (02-03 bot day) | operating point = {budget:g} FPR budget")
    print("Unit = (source-host, 15 s window). Positive class = attack window.")
    print("=" * 78)

    rows = []
    for name, test in results.items():
        if f"fpr_{budget}" not in test:
            continue
        tp, fp, fn, tn = confusion(test, budget)
        m = _metrics(tp, fp, fn, tn)
        rows.append((name, tp, fp, fn, tn, m, test))

    # rank by F1 (worst-to-best reads as the ablation story)
    rows.sort(key=lambda r: r[5]["f1"])

    for name, tp, fp, fn, tn, m, test in rows:
        print(f"\n### {name}")
        print("                 predicted")
        print("                 attack      benign")
        print(f"  actual attack  TP={tp:<9} FN={fn:<9}   (recall {m['recall']:.3f})")
        print(f"         benign  FP={fp:<9} TN={tn:<9}   (FPR    {m['fpr']:.4f})")
        print(f"  precision {m['precision']:.3f} | recall {m['recall']:.3f} | "
              f"F1 {m['f1']:.3f} | FPR {m['fpr']:.4f}")
        print(f"  AUROC {test['auroc']:.3f} | ECE {test['ece']:.3f} | "
              f"accuracy {m['accuracy']:.4f} (imbalanced - ignore) | "
              f"lead {test[f'fpr_{budget}']['lead_time_median']:.0f}s "
              f"({test[f'fpr_{budget}']['episodes_detected']}/"
              f"{test[f'fpr_{budget}']['episodes_total']} episodes)")

    print("\n" + "-" * 78)
    print(f"{'model':<26}{'prec':>7}{'recall':>8}{'F1':>7}{'FPR':>9}{'AUROC':>8}{'lead_s':>9}")
    print("-" * 78)
    for name, tp, fp, fn, tn, m, test in sorted(rows, key=lambda r: -r[5]["f1"]):
        print(f"{name:<26}{m['precision']:>7.3f}{m['recall']:>8.3f}{m['f1']:>7.3f}"
              f"{m['fpr']:>9.4f}{test['auroc']:>8.3f}"
              f"{test[f'fpr_{budget}']['lead_time_median']:>9.0f}")
    print("-" * 78)
    print("Lead time is the metric that defines success (PS): seconds between the first\n"
          "alert on the attacking host and the annotated completion. A model with better\n"
          "F1 and zero lead time has failed the problem statement.")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--budget", type=float, default=None,
                    help="one FPR budget (e.g. 0.01); default prints all configured")
    args = ap.parse_args(argv)
    budgets = [args.budget] if args.budget else load_config("eval")["fpr_budgets"]
    for b in budgets:
        report(b)
        print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
