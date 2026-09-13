"""Build the model-comparison table from results/*.json (M4.5).

Each model's harness run writes results/<name>.json; this reads them all and
produces one row per model, columns per metric — the table that goes into the
README (rendered by scripts/make_ablation_table.py, never hand-typed).

Three rules keep the rendered table readable as evidence rather than as a claim:

* The **achieved** FPR is printed beside the budget it was drawn from. The budget
  names the operating point; it is not what the model did on the split, and
  across models the achieved rate spans several-fold, so rows compared under one
  "1% FPR" heading can sit at very different alert volumes.
* A quantile band is printed only once the episode count reaches
  `metrics.min_episodes_for_quantile_band` (configs/eval.yaml). Below it a
  percentile over n episodes is interpolation between two adjacent order
  statistics and reads as a dispersion measurement that was never made; the
  literal per-episode lead times are the honest rendering.
* The split is explicit and selectable. val and test hold different attack
  families here (docs/benchmark_protocol.md), so the val->test gap IS the
  cross-family generalisation result — `build_split_comparison` shows it instead
  of a test-only table asserting it.

A field the results JSON does not carry renders as `TBD`, never as a zero that
reads like a measurement.
"""

from __future__ import annotations

import json
from pathlib import Path

import pandas as pd

from configs import load_config, resolve_path

SPLITS = ("val", "test")
MISSING = "TBD"


def _gap_columns(budget: float) -> tuple[tuple[str, str], ...]:
    """(label, _row column) pairs that build_split_comparison carries per split.

    Only numeric columns belong here — a gap is a subtraction.
    """
    return (("F1", f"F1@{budget:g}"), ("recall", f"recall@{budget:g}"),
            ("AUROC", "AUROC"), ("lead_median_s", "lead_median_s"))


def load_results(results_dir: Path | None = None) -> list[dict]:
    cfg_eval = load_config("eval")
    results_dir = results_dir or resolve_path(cfg_eval["paths"]["results_dir"])
    return [json.loads(p.read_text(encoding="utf-8")) for p in sorted(results_dir.glob("*.json"))]


def _min_episodes_for_band() -> int:
    return int(load_config("eval")["metrics"]["min_episodes_for_quantile_band"])


def _shipped_results(results: list[dict], require: tuple[str, ...]) -> list[dict]:
    """Rows that belong in a published table.

    Results that use the horizon schema (forecast, world) carry no split block
    and have their own presentation — the per-horizon table and the
    negative-result note — so including them here renders spurious all-zero
    rows. De-duplicate by (model, holdout) so a re-run variant (e.g.
    world_v2.json) cannot appear twice. Runs tagged with '__' (harness --tag /
    gpu_experiments) are experiments, never shipped rows.
    """
    kept, seen = [], set()
    for r in results:
        if "__" in r.get("model", "") or not all(s in r for s in require):
            continue
        marker = (r.get("model"), r.get("holdout_family"))
        if marker in seen:
            continue
        seen.add(marker)
        kept.append(r)
    return kept


def _fmt_fpr(value) -> str:
    return MISSING if value is None else f"{float(value) * 100:.3f}%"


def _fmt_band(pt: dict, min_episodes: int) -> str:
    """The quantile band, or why it is not printed.

    Refusing below `min_episodes` is the point: with 2 episodes np.percentile
    interpolates between the only two values it has, and an undetected episode
    (0 s) becomes the lower edge of what then reads as a spread.
    """
    band = pt.get("lead_time_iqr")
    n_episodes = pt.get("episodes_total")
    if band is None or n_episodes is None:
        return MISSING
    if int(n_episodes) < min_episodes:
        return f"n/a (n={int(n_episodes)})"
    return f"{band[0]:.0f}-{band[1]:.0f}"


def _fmt_per_episode(pt: dict) -> str:
    """The literal lead time of every episode, in episode order.

    An empty list is a run with no annotated episode on the split, which is a
    different statement from a results JSON that never carried the field — a
    blank cell would read as neither.
    """
    per_episode = pt.get("per_episode_seconds")
    if per_episode is None:
        return MISSING
    if not per_episode:
        return "n/a (no episodes)"
    return ", ".join(f"{float(v):.0f}" for v in per_episode)


def _num(source: dict, key: str, digits: int, alt: str | None = None):
    """A measured number, or MISSING — never a zero standing in for one.

    A budget the run never wrote (harness --model x at other budgets, an older
    schema) reaches here as an absent key. Rendering that as 0.0 says the model
    scored zero; it did not, it was not measured at this operating point.
    """
    value = source.get(key)
    if value is None and alt is not None:
        value = source.get(alt)
    return MISSING if value is None else round(float(value), digits)


def _fmt_episodes(pt: dict) -> str:
    detected, total = pt.get("episodes_detected"), pt.get("episodes_total")
    if detected is None or total is None:
        return MISSING
    return f"{int(detected)}/{int(total)}"


def _row(result: dict, budget: float, split: str, min_episodes: int) -> dict:
    key = f"fpr_{budget}"
    block = result.get(split, {})
    pt = block.get(key, {})
    name = result["model"] + (f" (holdout {result['holdout_family']})"
                              if result.get("holdout_family") else "")
    n_episodes = pt.get("episodes_total")
    return {
        "model": name,
        "split": split,
        f"F1@{budget:g}": _num(pt, "f1", 3),
        f"precision@{budget:g}": _num(pt, "precision", 3),
        f"recall@{budget:g}": _num(pt, "recall", 3),
        "FPR_achieved": _fmt_fpr(pt.get("fpr")),
        "AUROC": _num(block, "auroc", 3),
        "ECE": _num(block, "ece", 3),
        "lead_median_s": _num(pt, "lead_time_median", 0),
        "lead_each_s": _fmt_per_episode(pt),
        "lead_IQR_s": _fmt_band(pt, min_episodes),
        "n_episodes": MISSING if n_episodes is None else int(n_episodes),
        "episodes": _fmt_episodes(pt),
        "alerts/host/day": _num(pt, "alerts_per_host_day", 1, alt="alerts_per_day"),
    }


def _sorted_by(table: pd.DataFrame, column: str) -> pd.DataFrame:
    """Descending by `column`, with MISSING cells last.

    The column is mixed float/str once a measurement can be absent, which a bare
    sort_values cannot order.
    """
    rank = table[column].map(lambda v: float("-inf") if v == MISSING else float(v))
    order = rank.sort_values(ascending=False, kind="stable").index
    return table.reindex(order).reset_index(drop=True)


def build_table(budget: float = 0.01, results_dir: Path | None = None,
                split: str = "test") -> pd.DataFrame:
    """One row per model at `budget`, scored on `split`."""
    if split not in SPLITS:
        raise ValueError(f"split must be one of {SPLITS}, got {split!r}")
    results = _shipped_results(load_results(results_dir), (split,))
    if not results:
        return pd.DataFrame()
    min_episodes = _min_episodes_for_band()
    rows = [_row(r, budget, split, min_episodes) for r in results]
    return _sorted_by(pd.DataFrame(rows), "lead_median_s")


def build_split_comparison(budget: float = 0.01,
                           results_dir: Path | None = None) -> pd.DataFrame:
    """val and test side by side, with the gap between them.

    Only results carrying BOTH split blocks appear: a gap computed against a
    missing val block would be the test number wearing a minus sign.
    """
    results = _shipped_results(load_results(results_dir), SPLITS)
    if not results:
        return pd.DataFrame()
    min_episodes = _min_episodes_for_band()
    rows = []
    for r in results:
        cells = {s: _row(r, budget, s, min_episodes) for s in SPLITS}
        row = {"model": cells["test"]["model"]}
        for label, col in _gap_columns(budget):
            val, test = cells["val"][col], cells["test"][col]
            row[f"val_{label}"] = val
            row[f"test_{label}"] = test
            # A gap needs both ends measured; subtracting an unmeasured side
            # would print "no val->test gap" where nothing was compared.
            row[f"gap_{label}"] = (MISSING if MISSING in (val, test)
                                   else round(test - val, 3))
        row["val_FPR_achieved"] = cells["val"]["FPR_achieved"]
        row["test_FPR_achieved"] = cells["test"]["FPR_achieved"]
        rows.append(row)
    return _sorted_by(pd.DataFrame(rows), "test_lead_median_s")


def to_markdown(table: pd.DataFrame, budget: float, split: str | None = "test") -> str:
    if table.empty:
        return "_No results yet — run `python -m eval.harness --model lr` first._"
    # The header is emitted into the README by scripts/make_ablation_table.py
    # through stdout, so it stays ASCII.
    where = f"{split.capitalize()} split" if split else "val vs test"
    undetected = float(load_config("eval")["metrics"]["lead_time_undetected_seconds"])
    header = (
        f"{where}, operating point = {budget:g} FPR budget. `FPR_achieved` is the "
        "false-positive rate the model actually reached there; rows differing in it "
        "are not at the same alert volume. Lead time in seconds (higher is better); "
        f"an undetected episode counts as {undetected:g} s (configs/eval.yaml) and is "
        "never dropped. A quantile band is printed only from "
        f"{_min_episodes_for_band()} episodes up - below that `lead_each_s` carries the "
        f"literal per-episode values. `{MISSING}` = the results JSON does not carry "
        "that field.\n\n"
    )
    cols = list(table.columns)
    lines = ["| " + " | ".join(cols) + " |", "|" + "---|" * len(cols)]
    for _, r in table.iterrows():
        lines.append("| " + " | ".join(str(r[c]) for c in cols) + " |")
    return header + "\n".join(lines)
