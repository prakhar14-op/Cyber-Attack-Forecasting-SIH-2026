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

`annotate_split` is the one call a NOWCAST results writer needs. Every writer in
eval/ (harness, fused, forecast, world) ends up holding the same five arrays — y,
score, host, window_start and the split's attacker episodes — and a result block
of `fpr_<budget>` sub-dicts that already record the threshold they fired at. The
helper turns those into `auroc_ci` on the block and `f1_ci` inside each
operating point, so wiring a writer is one line rather than a reimplementation
of the grouping and the refusal handling.

A FORECASTING writer must call `annotate_horizon_split` instead. At horizon k the
row indexed at `window_start = t` carries the label for `t + k*stride`, so the
rows whose label IS the attack being forecast sit in the k*stride window BEFORE
the episode starts. Clustering them by `t` alone hands exactly those rows
host-level clusters, splitting one episode's correlated rows across groups the
bootstrap then treats as independent — an interval too narrow, produced silently.
`annotate_horizon_split` takes the horizon and the stride and shifts the episode
windows itself; there is no way to call it without stating both.

Refusal vs bug: the bootstrap raises `IntervalUnavailable` (a ValueError
subclass) when it cannot honestly produce an interval, and a plain ValueError
when the CALLER got the inputs wrong. `interval_or_reason` files only the former
as `{"unavailable": ...}`; a caller bug propagates.
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

#: Key a forecasting writer records its horizon under, in WINDOWS.
#: `annotate_horizon_split` writes it; `annotate_split` refuses a block that
#: carries a non-zero one, because a nowcast grouping would misplace its rows.
HORIZON_KEY = "horizon"


class IntervalUnavailable(ValueError):
    """The evidence does not support an interval — a refusal, not a defect.

    Raised only where the bootstrap has looked at the data and found it cannot
    honestly answer: fewer than two clusters, a statistic already degenerate on
    the full sample, every resample degenerate. `interval_or_reason` records
    exactly these as `{"unavailable": <reason>}`.

    A ValueError subclass so callers written against the old contract still
    catch it, but a DISTINCT type on purpose: an input-validation ValueError
    (length mismatch, an FPR budget outside [0, 1], a malformed operating-point
    key) is a bug in the calling writer. Filing a bug as "no interval available"
    is the silent-failure mode this project forbids, so those stay plain
    ValueError and reach the operator.
    """


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
        raise IntervalUnavailable(
            f"a cluster bootstrap needs >= 2 groups, got {n_groups} — every "
            "resample would be the original sample"
        )
    order = np.argsort(inverse, kind="stable")
    bounds = np.searchsorted(inverse[order], np.arange(n_groups + 1))
    rows_of = [order[bounds[g] : bounds[g + 1]] for g in range(n_groups)]

    point = float(statistic(y_true, y_score))
    if not np.isfinite(point):
        raise IntervalUnavailable("the statistic is degenerate on the full sample")

    rng = np.random.RandomState(seed)
    draws: list[float] = []
    for _ in range(n_resamples):
        rows = np.concatenate([rows_of[g] for g in rng.randint(0, n_groups, n_groups)])
        value = float(statistic(y_true[rows], y_score[rows]))
        if np.isfinite(value):
            draws.append(value)
    if not draws:
        raise IntervalUnavailable(
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
                      episodes: list[dict], *,
                      label_offset_seconds: float = 0.0) -> np.ndarray:
    """Cluster label per row: the (host, episode) the row's LABEL belongs to.

    A row whose labelled time falls inside an episode's [start, end] on that
    episode's attacking host joins that episode's cluster; every other row
    clusters by host alone, so benign host-time is still resampled at the host
    level rather than as independent rows. Episode order fixes the labels, so the
    grouping is reproducible.

    `label_offset_seconds` is the gap between the time a row is INDEXED at
    (`window_start`) and the time its label DESCRIBES. It is 0 for a nowcast and
    `horizon_windows * stride_seconds` for a forecaster, whose row at t carries
    the label for t + k*stride (eval/dataset.py `_shift_target_by_horizon`). The
    grouping must follow the label, not the index: at a positive offset the rows
    that carry an episode's attack are the ones just BEFORE it starts, and
    clustering them at offset 0 scatters one episode's correlated rows into
    host-level groups the bootstrap then treats as independent — a narrower
    interval than the evidence supports, with nothing on screen to say so.
    """
    host = np.asarray(host).astype(str)
    window_start = np.asarray(window_start, dtype=float)
    if host.size != window_start.size:
        raise ValueError(f"host/window_start length mismatch: {host.size}/{window_start.size}")
    label_offset_seconds = float(label_offset_seconds)
    if not np.isfinite(label_offset_seconds):
        raise ValueError(
            f"label_offset_seconds must be finite, got {label_offset_seconds}")

    labelled_time = window_start + label_offset_seconds
    labels = np.array([f"host:{h}" for h in host], dtype=object)
    for i, ep in enumerate(episodes):
        inside = (
            (host == str(ep["host"]))
            & (labelled_time >= float(ep["start"]))
            & (labelled_time <= float(ep["end"]))
        )
        labels[inside] = f"episode:{i}:{ep['host']}"
    return labels


# --------------------------------------------------------------- writer-facing


def interval_or_reason(interval_fn, *args, **kwargs) -> dict:
    """An interval as a dict, or a clearly-marked absent one.

    The bootstrap above refuses an interval it cannot honestly produce — fewer
    than two clusters, a degenerate statistic on the full sample, every resample
    degenerate — by raising `IntervalUnavailable`. Those cases record
    `{"unavailable": <reason>}`, never a substituted bound: an absent interval
    must read as absent, not as a measured one that happens to be wide.

    Only that type is caught. A plain ValueError from input validation (a length
    mismatch, an FPR budget outside [0, 1] because a writer keyed a block
    "fpr_5") is a bug in the caller, and a bug filed as "no interval available"
    would ship a results JSON whose missing intervals all look like honest
    refusals. It propagates.
    """
    try:
        return interval_fn(*args, **kwargs).as_dict()
    except IntervalUnavailable as exc:
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
    label_offset_seconds: float = 0.0,
    n_resamples: int | None = None,
    level: float | None = None,
    seed: int | None = None,
) -> dict:
    """Attach cluster-bootstrap intervals to one NOWCAST result block, in place.

    This is the whole writer-facing API for a horizon-0 writer: one that already
    holds `y_true`, `y_score`, `host`, `window_start` and the split's attacker
    episodes calls this once, immediately after its `fpr_<budget>` sub-blocks
    are complete, and gets

    * `block[auroc_key]` — the AUROC interval, and
    * `block["fpr_<budget>"]["f1_ci"]` — the F1 interval at that operating point

    without restating the (attacker-host, episode) grouping or the refusal
    convention. Each value is `Interval.as_dict()` or `{"unavailable": reason}`.

    A FORECASTING writer calls `annotate_horizon_split` instead; it is the only
    entry point that can state a horizon, and it states it in windows and stride
    rather than as a raw offset. `label_offset_seconds` here exists for that
    delegation and for a writer whose label offset is not a whole number of
    windows; a block declaring a non-zero `horizon` with a zero offset is
    refused, because that combination is exactly the grouping bug.

    The F1 interval is computed at the threshold the block already records, not
    at a threshold refitted inside each resample: the shipped threshold is
    chosen on val and applied unchanged, so refitting would measure a different
    estimand than the row it decorates (see `f1_at_fpr_interval`). A block whose
    operating point carries no `threshold` is a writer bug and raises — silently
    refitting would hand back an interval for a number nobody reported.

    Returns the same `block` object, so a writer can chain if it prefers.
    """
    if block.get(HORIZON_KEY) and not label_offset_seconds:
        raise ValueError(
            f"this block declares {HORIZON_KEY}={block[HORIZON_KEY]!r} but was "
            "annotated with a zero label offset — its labels are shifted, so the "
            "rows carrying an episode would cluster by host instead of by "
            "episode. Call annotate_horizon_split(..., horizon_windows=k, "
            "stride_seconds=stride)"
        )
    groups = episode_group_ids(host, window_start, episodes,
                               label_offset_seconds=label_offset_seconds)
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


def annotate_horizon_split(
    block: dict,
    y_true,
    y_score,
    host,
    window_start,
    episodes: list[dict],
    *,
    horizon_windows: int,
    stride_seconds: float,
    auroc_key: str = "auroc_ci",
    n_resamples: int | None = None,
    level: float | None = None,
    seed: int | None = None,
) -> dict:
    """`annotate_split` for a block whose labels are shifted k windows ahead.

    eval/forecast.py and eval/world.py score rows indexed at `window_start = t`
    against the label at `t + k*stride` — the same shift their lead time already
    accounts for with `grace_seconds=k*stride`. The cluster bootstrap has to
    account for it too: the rows carrying episode i's attack are the ones in
    [start - k*stride, end - k*stride] on the attacking host, so the episode
    windows are shifted back by the same amount before the grouping is built.

    `horizon_windows` and `stride_seconds` are both required and neither has a
    default, so the offset cannot be forgotten or guessed; the function derives
    `k * stride` itself rather than accepting a pre-multiplied number, so it
    cannot be given in the wrong unit either. It records
    `block[HORIZON_KEY] = horizon_windows`, which makes the results JSON say
    which grouping produced its intervals and makes a later `annotate_split` on
    the same block refuse.

    Returns the same `block` object.
    """
    if isinstance(horizon_windows, bool) or int(horizon_windows) != horizon_windows:
        raise ValueError(
            f"horizon_windows must be a whole number of windows, got "
            f"{horizon_windows!r}")
    horizon_windows = int(horizon_windows)
    if horizon_windows < 0:
        raise ValueError(
            f"horizon_windows must be >= 0, got {horizon_windows} — a negative "
            "horizon would cluster rows against episodes that have not started")
    stride_seconds = float(stride_seconds)
    if not np.isfinite(stride_seconds) or stride_seconds <= 0.0:
        raise ValueError(
            f"stride_seconds must be finite and > 0, got {stride_seconds} — pass "
            "configs/data.yaml windows.stride_seconds, never a literal")

    declared = block.get(HORIZON_KEY)
    if declared is not None and int(declared) != horizon_windows:
        raise ValueError(
            f"block declares {HORIZON_KEY}={declared!r} but was annotated at "
            f"horizon {horizon_windows} — one of the two is wrong, and the "
            "intervals would describe a different estimand than the row")
    block[HORIZON_KEY] = horizon_windows

    # horizon 0 IS the nowcast: offset 0 and a falsy recorded horizon, so the
    # delegation below stays inside annotate_split's contract unchanged.
    offset = horizon_windows * stride_seconds
    return annotate_split(
        block, y_true, y_score, host, window_start, episodes,
        auroc_key=auroc_key, label_offset_seconds=offset,
        n_resamples=n_resamples, level=level, seed=seed,
    )
