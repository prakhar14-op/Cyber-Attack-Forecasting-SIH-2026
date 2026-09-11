"""Confidence intervals for the headline metrics.

A point estimate over 2 attack episodes reads as far more certain than it is, and
the rows behind it are not independent: an external attacker appears as a source
inside several victims' captures, so one logical (attacker-host, episode) window
contributes ~8.7 correlated rows against a 1.42 average. Resampling rows would
divide the real variance by roughly the cluster size and report an interval too
narrow to be honest.

Everything here resamples whole CLUSTERS — the groups the caller passes as
`group_ids` — with replacement, recomputes the statistic on the concatenated
rows, and takes the percentile interval. The grouping is the caller's claim about
what is independent; for the harness that is (attacker-host, episode), and
`group_ids = arange(n)` degenerates this to the row-level bootstrap it exists to
replace.

Resample count and interval level come from configs/eval.yaml
(metrics.bootstrap_resamples, metrics.bootstrap_ci_level), the RNG seed from its
top-level `seed`; no default lives in this module.

A resample can be degenerate — one class only, or no benign rows to hang an FPR
threshold on. Those are dropped and counted in `Interval.n_usable`, never
replaced by a substituted value, and an interval with no usable resample raises.

`annotate_split` is the one call a results writer needs. Every writer in eval/
(harness, fused, forecast, world) ends up holding the same five arrays — y,
score, host, window_start and the split's attacker episodes — and a result block
of `fpr_<budget>` sub-dicts that already record the threshold they fired at. The
helper turns those into `auroc_ci` on the block and `f1_ci` inside each
operating point, so wiring a writer is one line rather than a reimplementation
of the grouping and the refusal handling.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

import numpy as np

from configs import load_config
from eval import metrics as M

Statistic = Callable[[np.ndarray, np.ndarray], float]

#: Prefix every results writer uses for an operating-point sub-block,
#: `f"fpr_{budget}"` — `annotate_split` finds the points to annotate by it.
FPR_BLOCK_PREFIX = "fpr_"


@dataclass
class Interval:
    """A percentile confidence interval and the evidence it rests on.

    `n_usable` below `n_resamples` means degenerate resamples were dropped; a
    large gap says the interval is carried by few effective clusters.
    """

    point: float
    low: float
    high: float
    level: float
    n_groups: int
    n_resamples: int
    n_usable: int

    def as_dict(self) -> dict:
        return {
            "point": self.point, "low": self.low, "high": self.high,
            "level": self.level, "n_groups": self.n_groups,
            "n_resamples": self.n_resamples, "n_usable": self.n_usable,
        }

    def __str__(self) -> str:
        return (f"{self.point:.3f} [{self.low:.3f}, {self.high:.3f}] "
                f"({self.level:.0%} cluster bootstrap, {self.n_groups} groups)")


def _settings(n_resamples: int | None, level: float | None, seed: int | None):
    cfg = load_config("eval")
    n_resamples = int(cfg["metrics"]["bootstrap_resamples"]) if n_resamples is None \
        else int(n_resamples)
    level = float(cfg["metrics"]["bootstrap_ci_level"]) if level is None else float(level)
    seed = int(cfg["seed"]) if seed is None else int(seed)
    if n_resamples < 1:
        raise ValueError(f"n_resamples must be >= 1, got {n_resamples}")
    if not 0.0 < level < 1.0:
        raise ValueError(f"bootstrap_ci_level must lie in (0, 1), got {level}")
    return n_resamples, level, seed


def _validate(y_true, y_score, group_ids):
    y_true = np.asarray(y_true).astype(bool)
    y_score = np.asarray(y_score, dtype=float)
    groups = np.asarray(group_ids)
    if not (y_true.size == y_score.size == groups.size):
        raise ValueError(
            f"y_true/y_score/group_ids length mismatch: "
            f"{y_true.size}/{y_score.size}/{groups.size}"
        )
    if y_true.size == 0:
        raise ValueError("cannot bootstrap an empty sample")
    if not np.all(np.isfinite(y_score)):
        raise ValueError("y_score contains non-finite values")
    return y_true, y_score, groups


def cluster_bootstrap(
    statistic: Statistic,
    y_true: np.ndarray,
    y_score: np.ndarray,
    group_ids: np.ndarray,
    *,
    n_resamples: int | None = None,
    level: float | None = None,
    seed: int | None = None,
) -> Interval:
    """Percentile interval for `statistic`, resampling whole groups.

    `statistic(y_true, y_score) -> float` is recomputed on each resample; it
    returns a non-finite value to declare that resample degenerate. Every group
    is drawn with replacement and enters with all of its rows, so a group that is
    drawn twice contributes its correlation twice — that is the point.
    """
    y_true, y_score, groups = _validate(y_true, y_score, group_ids)
    n_resamples, level, seed = _settings(n_resamples, level, seed)

    _, inverse = np.unique(groups, return_inverse=True)
    n_groups = int(inverse.max()) + 1
    if n_groups < 2:
        raise ValueError(
            f"a cluster bootstrap needs >= 2 groups, got {n_groups} — every "
            "resample would be the original sample"
        )
    order = np.argsort(inverse, kind="stable")
    bounds = np.searchsorted(inverse[order], np.arange(n_groups + 1))
    rows_of = [order[bounds[g] : bounds[g + 1]] for g in range(n_groups)]

    point = float(statistic(y_true, y_score))
    if not np.isfinite(point):
        raise ValueError("the statistic is degenerate on the full sample")

    rng = np.random.RandomState(seed)
    draws: list[float] = []
    for _ in range(n_resamples):
        rows = np.concatenate([rows_of[g] for g in rng.randint(0, n_groups, n_groups)])
        value = float(statistic(y_true[rows], y_score[rows]))
        if np.isfinite(value):
            draws.append(value)
    if not draws:
        raise ValueError(
            f"all {n_resamples} resamples were degenerate — {n_groups} groups is "
            "too few, or one class lives entirely in one group"
        )

    tail = (1.0 - level) / 2.0 * 100.0
    return Interval(
        point=point,
        low=float(np.percentile(draws, tail)),
        high=float(np.percentile(draws, 100.0 - tail)),
        level=level,
        n_groups=n_groups,
        n_resamples=n_resamples,
        n_usable=len(draws),
    )


def _auroc_statistic(y_true: np.ndarray, y_score: np.ndarray) -> float:
    # metrics.auroc answers 0.5 for a single-class input; that is a stated
    # convention, not a measurement, so it must not enter the interval.
    n_pos = int(np.count_nonzero(y_true))
    if n_pos == 0 or n_pos == y_true.size:
        return float("nan")
    return M.auroc(y_true, y_score)


def auroc_interval(
    y_true: np.ndarray,
    y_score: np.ndarray,
    group_ids: np.ndarray,
    *,
    n_resamples: int | None = None,
    level: float | None = None,
    seed: int | None = None,
) -> Interval:
    """Cluster-bootstrap interval for AUROC."""
    return cluster_bootstrap(
        _auroc_statistic, y_true, y_score, group_ids,
        n_resamples=n_resamples, level=level, seed=seed,
    )


def f1_at_fpr_interval(
    y_true: np.ndarray,
    y_score: np.ndarray,
    group_ids: np.ndarray,
    fpr_budget: float,
    *,
    threshold: float | None = None,
    n_resamples: int | None = None,
    level: float | None = None,
    seed: int | None = None,
) -> Interval:
    """Cluster-bootstrap interval for F1 at an FPR budget.

    `threshold` fixes the operating point, which is what the harness needs: the
    shipped threshold is fitted on val and applied unchanged to test, so a
    test-split interval that refits it per resample measures a different
    estimand. Left None, the budget is re-applied inside each resample and the
    interval then covers threshold-selection variance as well.
    """
    if not 0.0 <= fpr_budget <= 1.0:
        raise ValueError(f"fpr_budget must lie in [0, 1], got {fpr_budget}")

    def statistic(yt: np.ndarray, ys: np.ndarray) -> float:
        n_pos = int(np.count_nonzero(yt))
        if n_pos == 0 or n_pos == yt.size:
            return float("nan")
        if threshold is None:
            return M.classification_at_fpr(yt, ys, fpr_budget).f1
        pred = ys >= threshold
        tp = int(np.count_nonzero(pred & yt))
        fp = int(np.count_nonzero(pred & ~yt))
        fn = int(np.count_nonzero(~pred & yt))
        precision = tp / (tp + fp) if (tp + fp) else 0.0
        recall = tp / (tp + fn) if (tp + fn) else 0.0
        return 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0

    return cluster_bootstrap(
        statistic, y_true, y_score, group_ids,
        n_resamples=n_resamples, level=level, seed=seed,
    )


def episode_group_ids(host: np.ndarray, window_start: np.ndarray,
                      episodes: list[dict]) -> np.ndarray:
    """Cluster label per row: the (host, episode) a row belongs to.

    A row inside an episode's [start, end] on that episode's attacking host joins
    that episode's cluster; every other row clusters by host alone, so benign
    host-time is still resampled at the host level rather than as independent
    rows. Episode order fixes the labels, so the grouping is reproducible.
    """
    host = np.asarray(host).astype(str)
    window_start = np.asarray(window_start, dtype=float)
    if host.size != window_start.size:
        raise ValueError(f"host/window_start length mismatch: {host.size}/{window_start.size}")

    labels = np.array([f"host:{h}" for h in host], dtype=object)
    for i, ep in enumerate(episodes):
        inside = (
            (host == str(ep["host"]))
            & (window_start >= float(ep["start"]))
            & (window_start <= float(ep["end"]))
        )
        labels[inside] = f"episode:{i}:{ep['host']}"
    return labels


# --------------------------------------------------------------- writer-facing


def interval_or_reason(interval_fn, *args, **kwargs) -> dict:
    """An interval as a dict, or a clearly-marked absent one.

    The bootstrap above refuses an interval it cannot honestly produce — fewer
    than two clusters, a degenerate statistic on the full sample, every resample
    degenerate. Those cases record `{"unavailable": <reason>}`, never a
    substituted bound: an absent interval must read as absent, not as a measured
    one that happens to be wide.
    """
    try:
        return interval_fn(*args, **kwargs).as_dict()
    except ValueError as exc:
        return {"unavailable": str(exc)}


def _budget_from_key(key: str) -> float:
    """The FPR budget a writer encoded in an operating-point key."""
    try:
        return float(key[len(FPR_BLOCK_PREFIX):])
    except ValueError as exc:
        raise ValueError(
            f"operating-point key {key!r} is not '{FPR_BLOCK_PREFIX}<budget>'; "
            "annotate_split reads the budget back out of the key the writer wrote"
        ) from exc


def annotate_split(
    block: dict,
    y_true,
    y_score,
    host,
    window_start,
    episodes: list[dict],
    *,
    auroc_key: str = "auroc_ci",
    n_resamples: int | None = None,
    level: float | None = None,
    seed: int | None = None,
) -> dict:
    """Attach cluster-bootstrap intervals to one split's result block, in place.

    This is the whole writer-facing API: a results writer that already holds
    `y_true`, `y_score`, `host`, `window_start` and the split's attacker
    episodes calls this once, immediately after its `fpr_<budget>` sub-blocks
    are complete, and gets

    * `block[auroc_key]` — the AUROC interval, and
    * `block["fpr_<budget>"]["f1_ci"]` — the F1 interval at that operating point

    without restating the (attacker-host, episode) grouping or the refusal
    convention. Each value is `Interval.as_dict()` or `{"unavailable": reason}`.

    The F1 interval is computed at the threshold the block already records, not
    at a threshold refitted inside each resample: the shipped threshold is
    chosen on val and applied unchanged, so refitting would measure a different
    estimand than the row it decorates (see `f1_at_fpr_interval`). A block whose
    operating point carries no `threshold` is a writer bug and raises — silently
    refitting would hand back an interval for a number nobody reported.

    Returns the same `block` object, so a writer can chain if it prefers.
    """
    groups = episode_group_ids(host, window_start, episodes)
    points = [(k, v) for k, v in list(block.items())
              if k.startswith(FPR_BLOCK_PREFIX) and isinstance(v, dict)]
    if not points:
        raise ValueError(
            f"no '{FPR_BLOCK_PREFIX}<budget>' operating point in this block "
            f"(keys: {sorted(block)}) — annotate_split is called after the "
            "operating points are built, not before"
        )

    block[auroc_key] = interval_or_reason(
        auroc_interval, y_true, y_score, groups,
        n_resamples=n_resamples, level=level, seed=seed,
    )
    for key, point in points:
        if "threshold" not in point:
            raise KeyError(
                f"operating point {key!r} records no 'threshold'; annotate_split "
                "will not refit one — the interval must cover the threshold the "
                "reported F1 was measured at"
            )
        point["f1_ci"] = interval_or_reason(
            f1_at_fpr_interval, y_true, y_score, groups, _budget_from_key(key),
            threshold=float(point["threshold"]),
            n_resamples=n_resamples, level=level, seed=seed,
        )
    return block
