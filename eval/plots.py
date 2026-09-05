"""Evaluation plots (M7.7): the lead-time-vs-horizon plot.

    python -m eval.plots

Reads results/world.json (per-horizon world-model rows) and the horizon-0
baseline JSONs, renders results/plots/lead_time.png with matplotlib (no CDN,
offline-safe). Numbers come only from the results files — never typed here.
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

    world_path = results_dir / "world.json"
    if not world_path.exists():
        print("results/world.json missing — run `python -m eval.harness --model world`",
              file=sys.stderr)
        return 1
    world = json.loads(world_path.read_text(encoding="utf-8"))

    budget = "fpr_0.01"
    ks, medians, lo, hi = [], [], [], []
    for k, block in sorted(world["horizons"].items(), key=lambda kv: int(kv[0])):
        pt = block["test"][budget]
        ks.append(int(k))
        medians.append(pt["lead_time_median"])
        lo.append(pt["lead_time_iqr"][0])
        hi.append(pt["lead_time_iqr"][1])

    fig, ax = plt.subplots(figsize=(7, 4.5))
    ax.plot(ks, medians, "o-", label="world model (median lead)", color="#1a6faf")
    ax.fill_between(ks, lo, hi, alpha=0.2, color="#1a6faf", label="IQR")

    for name, style in (("xgb", "--"), ("tgn", ":")):
        p = results_dir / f"{name}.json"
        if p.exists():
            r = json.loads(p.read_text(encoding="utf-8"))
            lead = r["test"][budget]["lead_time_median"]
            ax.axhline(lead, linestyle=style, color="grey",
                       label=f"{name} @ horizon 0 ({lead:.0f}s)")

    ax.set_xlabel("forecast horizon k (windows of 5 s stride)")
    ax.set_ylabel("median lead time (s), test split, 1% FPR budget")
    ax.set_title("Lead time vs forecast horizon (undetected episodes = 0)")
    ax.legend(loc="lower left", fontsize=8)
    ax.grid(alpha=0.3)
    out = plots_dir / "lead_time.png"
    fig.tight_layout()
    fig.savefig(out, dpi=150)
    print(f"-> {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
