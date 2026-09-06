"""Build the model-comparison table from results/*.json (M4.5).

Each model's harness run writes results/<name>.json; this reads them all and
produces one row per model, columns per metric — the table that goes into the
README (rendered by scripts/make_ablation_table.py, never hand-typed).
"""

from __future__ import annotations

import json
from pathlib import Path

import pandas as pd

from configs import load_config, resolve_path


def load_results(results_dir: Path | None = None) -> list[dict]:
    cfg_eval = load_config("eval")
    results_dir = results_dir or resolve_path(cfg_eval["paths"]["results_dir"])
    return [json.loads(p.read_text(encoding="utf-8")) for p in sorted(results_dir.glob("*.json"))]


def _row(result: dict, budget: float) -> dict:
    key = f"fpr_{budget}"
    test = result.get("test", {})
    pt = test.get(key, {})
    name = result["model"] + (f" (holdout {result['holdout_family']})"
                              if result.get("holdout_family") else "")
    lo, hi = pt.get("lead_time_iqr", [0, 0])
    return {
        "model": name,
        f"F1@{budget:g}": round(pt.get("f1", 0.0), 3),
        f"precision@{budget:g}": round(pt.get("precision", 0.0), 3),
        f"recall@{budget:g}": round(pt.get("recall", 0.0), 3),
        "AUROC": round(test.get("auroc", 0.0), 3),
        "ECE": round(test.get("ece", 0.0), 3),
        "lead_median_s": round(pt.get("lead_time_median", 0.0), 0),
        "lead_IQR_s": f"{lo:.0f}-{hi:.0f}",
        "episodes": f"{pt.get('episodes_detected', 0)}/{pt.get('episodes_total', 0)}",
        "alerts/host/day": round(pt.get("alerts_per_host_day", pt.get("alerts_per_day", 0.0)), 1),
    }


def build_table(budget: float = 0.01, results_dir: Path | None = None) -> pd.DataFrame:
    results = load_results(results_dir)
    # This is the operating-point comparison table (baselines + encoder at
    # horizon 0). Results that use the horizon schema (forecast, world) carry no
    # `test` block and have their own presentation — the per-horizon table and
    # the negative-result note — so including them here renders spurious
    # all-zero rows. Drop them, and de-duplicate by (model, holdout) so a
    # re-run variant (e.g. world_v2.json) cannot appear twice. Runs tagged with
    # '__' (harness --tag / gpu_experiments) are experiments, never shipped rows.
    results = [r for r in results if "test" in r and "__" not in r.get("model", "")]
    seen: set = set()
    unique = []
    for r in results:
        marker = (r.get("model"), r.get("holdout_family"))
        if marker in seen:
            continue
        seen.add(marker)
        unique.append(r)
    results = unique
    if not results:
        return pd.DataFrame()
    rows = [_row(r, budget) for r in results]
    return pd.DataFrame(rows).sort_values("lead_median_s", ascending=False).reset_index(
        drop=True
    )


def to_markdown(table: pd.DataFrame, budget: float) -> str:
    if table.empty:
        return "_No results yet — run `python -m eval.harness --model lr` first._"
    header = f"Test split, operating point = {budget:g} FPR budget. " \
             "Lead time in seconds (higher is better); undetected episodes count as 0.\n\n"
    cols = list(table.columns)
    lines = ["| " + " | ".join(cols) + " |", "|" + "---|" * len(cols)]
    for _, r in table.iterrows():
        lines.append("| " + " | ".join(str(r[c]) for c in cols) + " |")
    return header + "\n".join(lines)
