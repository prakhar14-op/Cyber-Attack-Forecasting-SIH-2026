"""Evaluation plots (M7.7): lead-time and AUROC vs forecast horizon.

    python -m eval.plots

Reads results/forecast.json (the shipped encoder forecaster, decision 004) and
the horizon-0 baseline JSONs, renders results/plots/lead_time.png with
matplotlib (Agg backend, no CDN — offline-safe). Numbers come only from the
results files, never typed here.

The IQR band obeys the same cutoff the table does
(`metrics.min_episodes_for_quantile_band`, configs/eval.yaml): below it the
literal per-episode lead times are drawn instead of a band interpolated between
two order statistics.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

from configs import load_config, resolve_path


def build_figure(fc: dict, cfg_eval: dict, results_dir: Path):
    """The lead-time figure for one forecast result, as a Figure the caller owns.

    Separate from `main` so the figure has an owner: pyplot keeps every figure it
    creates alive until someone closes it, and a renderer that only ever saves
    leaks one per call (and forces a test to find its own output through pyplot's
    global registry). `main` closes what this returns.

    `results_dir` is read for the horizon-0 baseline JSONs drawn as reference
    lines; `fc` is the already-parsed forecast result.
    """
    budget = "fpr_0.01"
    min_episodes = int(cfg_eval["metrics"]["min_episodes_for_quantile_band"])
    ks, lead, lo, hi, auroc = [], [], [], [], []
    n_episodes, per_episode = [], []
    for k, block in sorted(fc["horizons"].items(), key=lambda kv: int(kv[0])):
        pt = block[budget]
        ks.append(int(k))
        lead.append(pt["lead_time_median"])
        band = pt.get("lead_time_iqr") or [None, None]
        lo.append(band[0])
        hi.append(band[1])
        n_episodes.append(pt.get("episodes_total"))
        per_episode.append(pt.get("per_episode_seconds"))
        auroc.append(block["auroc_test"])

    # Same rule as the table (eval/ablation.py): below the configured episode
    # count a quartile band is interpolation between two adjacent order
    # statistics — and a missed episode enters it as a 0 s edge — so it is not a
    # dispersion anyone measured. The literal per-episode values are drawn
    # instead when the results JSON carries them.
    counts = [int(n) for n in n_episodes if n is not None]
    band_is_measured = (
        len(counts) == len(ks)
        and min(counts, default=0) >= min_episodes
        and all(v is not None for v in lo + hi)
    )

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(11, 4.4))

    ax1.plot(ks, lead, "o-", color="#1a6faf", label="encoder forecaster (median lead)")
    if band_is_measured:
        ax1.fill_between(ks, lo, hi, alpha=0.18, color="#1a6faf", label="IQR")
    else:
        drawn = False
        for k, values in zip(ks, per_episode):
            if not values:
                continue
            ax1.plot([k] * len(values), [float(v) for v in values], "x",
                     color="#1a6faf", alpha=0.75,
                     label="per-episode lead" if not drawn else None)
            drawn = True
        if len(counts) < len(ks):
            note = "IQR omitted: the results JSON does not record the episode count"
        elif min(counts) < min_episodes:
            note = (f"IQR omitted: n={min(counts)} episodes, below the "
                    f"{min_episodes}-episode cutoff (configs/eval.yaml)")
        else:
            note = "IQR omitted: the results JSON does not carry lead_time_iqr"
        if not drawn:
            note += "\nper-episode values absent from results/forecast.json"
        # top right: the legend sits lower-left and the lead curve descends.
        ax1.annotate(note, xy=(0.98, 0.97), xycoords="axes fraction",
                     ha="right", va="top", fontsize=7, color="#555555")
    for name, style, col in (("xgb", "--", "grey"), ("tgn", ":", "#b5651d")):
        p = results_dir / f"{name}.json"
        if p.exists():
            r = json.loads(p.read_text(encoding="utf-8"))
            v = r["test"][budget]["lead_time_median"]
            ax1.axhline(v, linestyle=style, color=col, label=f"{name} @ horizon 0 ({v:.0f}s)")
    ax1.set_xlabel("forecast horizon k (windows, 5 s stride)")
    ax1.set_ylabel("median lead time (s), test, 1% FPR")
    # The undetected-episode convention is a config value, not a constant: it is
    # what a missed episode contributes to every median on this axis, so the
    # title states the number the run actually used (configs/eval.yaml), the same
    # way eval/ablation.to_markdown does.
    undetected = float(cfg_eval["metrics"]["lead_time_undetected_seconds"])
    ax1.set_title(f"Lead time vs horizon (undetected = {undetected:g} s)")
    # translucent: a per-episode 0 s marker (a missed episode) sits at the very
    # bottom of this axis and must stay visible through the legend box.
    ax1.legend(fontsize=8, loc="lower left", framealpha=0.6); ax1.grid(alpha=0.3)

    ax2.plot(ks, auroc, "s-", color="#2a8f5a")
    ax2.set_xlabel("forecast horizon k (windows, 5 s stride)")
    ax2.set_ylabel("test AUROC")
    ax2.set_title("Ranking holds when forecasting ahead")
    ax2.set_ylim(0.5, 1.0); ax2.grid(alpha=0.3)

    fig.tight_layout()
    return fig


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

    fig = build_figure(fc, cfg_eval, results_dir)
    out = plots_dir / "lead_time.png"
    try:
        fig.savefig(out, dpi=150)
    finally:
        # pyplot holds a reference until the figure is closed; a harness that
        # renders in a loop would accumulate them.
        plt.close(fig)
    print(f"-> {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
