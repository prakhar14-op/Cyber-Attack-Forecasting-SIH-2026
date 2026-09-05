"""Evaluation plots (M7.7): lead-time and AUROC vs forecast horizon.

    python -m eval.plots

Reads results/forecast.json (the shipped encoder forecaster, decision 004) and
the horizon-0 baseline JSONs, renders results/plots/lead_time.png with
matplotlib (Agg backend, no CDN — offline-safe). Numbers come only from the
results files, never typed here.
"""

from __future__ import annotations

import json
import sys

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

from configs import load_config, resolve_path


def main() -> int:
    cfg_eval = load_config("eval")
    results_dir = resolve_path(cfg_eval["paths"]["results_dir"])
    plots_dir = resolve_path(cfg_eval["paths"]["plots_dir"])
    plots_dir.mkdir(parents=True, exist_ok=True)

    fc_path = results_dir / "forecast.json"
    if not fc_path.exists():
        print("results/forecast.json missing — run `python -m eval.harness --model forecast`",
              file=sys.stderr)
        return 1
    fc = json.loads(fc_path.read_text(encoding="utf-8"))

    budget = "fpr_0.01"
    ks, lead, lo, hi, auroc = [], [], [], [], []
    for k, block in sorted(fc["horizons"].items(), key=lambda kv: int(kv[0])):
        pt = block[budget]
        ks.append(int(k))
        lead.append(pt["lead_time_median"])
        lo.append(pt["lead_time_iqr"][0])
        hi.append(pt["lead_time_iqr"][1])
        auroc.append(block["auroc_test"])

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(11, 4.4))

    ax1.plot(ks, lead, "o-", color="#1a6faf", label="encoder forecaster (median lead)")
    ax1.fill_between(ks, lo, hi, alpha=0.18, color="#1a6faf", label="IQR")
    for name, style, col in (("xgb", "--", "grey"), ("tgn", ":", "#b5651d")):
        p = results_dir / f"{name}.json"
        if p.exists():
            r = json.loads(p.read_text(encoding="utf-8"))
            v = r["test"][budget]["lead_time_median"]
            ax1.axhline(v, linestyle=style, color=col, label=f"{name} @ horizon 0 ({v:.0f}s)")
    ax1.set_xlabel("forecast horizon k (windows, 5 s stride)")
    ax1.set_ylabel("median lead time (s), test, 1% FPR")
    ax1.set_title("Lead time vs horizon (undetected = 0)")
    ax1.legend(fontsize=8, loc="lower left"); ax1.grid(alpha=0.3)

    ax2.plot(ks, auroc, "s-", color="#2a8f5a")
    ax2.set_xlabel("forecast horizon k (windows, 5 s stride)")
    ax2.set_ylabel("test AUROC")
    ax2.set_title("Ranking holds when forecasting ahead")
    ax2.set_ylim(0.5, 1.0); ax2.grid(alpha=0.3)

    out = plots_dir / "lead_time.png"
    fig.tight_layout(); fig.savefig(out, dpi=150)
    print(f"-> {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
