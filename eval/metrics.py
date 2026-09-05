"""Evaluation metrics (M4.1/M4.2). The harness is judged by these.

The metric that defines success for SIH26153 is **lead time** — seconds between
the first alert on the attacking host and the annotated completion of the attack,
at a fixed false-positive budget. F1 is reported but a model with better F1 and
zero lead time has failed the problem statement.

Operating points are chosen from an FPR budget on benign host-windows, never a
hardcoded threshold. Undetected attack episodes contribute lead time 0 — they are
never dropped from the median.

Everything here is a pure function of arrays/records so each metric has a unit
test with a hand-computed value.
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np


def threshold_at_fpr(y_true: np.ndarray, y_score: np.ndarray, fpr_budget: float) -> float:
    """Smallest score threshold whose FPR on benign samples is <= fpr_budget.

    FPR = (benign samples with score >= threshold) / (benign samples). Choosing
    the smallest such threshold maximises recall within the budget. If even the
    highest score exceeds the budget (too many benign at the top), returns
    nextafter(max_score) so nothing alerts.
    """
    y_true = np.asarray(y_true).astype(bool)
    y_score = np.asarray(y_score, dtype=float)
    benign = y_score[~y_true]
    if benign.size == 0:
        raise ValueError("cannot set an FPR threshold with no benign samples")

    # Candidate thresholds = unique benign scores, descending. For each, FPR is
    # the fraction of benign at or above it. Pick the lowest threshold with
    # FPR <= budget.
    order = np.sort(np.unique(y_score))[::-1]
    n_benign = benign.size
    chosen = np.nextafter(order[0], np.inf)  # default: alert nothing
    for thr in order:
        fpr = np.count_nonzero(benign >= thr) / n_benign
        if fpr <= fpr_budget:
            chosen = thr
        else:
            break
    return float(chosen)


@dataclass
class ClassificationPoint:
    threshold: float
    fpr_budget: float
    precision: float
    recall: float
    f1: float
    fpr: float
    n_alerts: int


def classification_at_fpr(
    y_true: np.ndarray, y_score: np.ndarray, fpr_budget: float
) -> ClassificationPoint:
    """Precision/recall/F1/FPR at the threshold implied by an FPR budget."""
    y_true = np.asarray(y_true).astype(bool)
    y_score = np.asarray(y_score, dtype=float)
    thr = threshold_at_fpr(y_true, y_score, fpr_budget)
    pred = y_score >= thr

    tp = int(np.count_nonzero(pred & y_true))
    fp = int(np.count_nonzero(pred & ~y_true))
    fn = int(np.count_nonzero(~pred & y_true))
    tn = int(np.count_nonzero(~pred & ~y_true))

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    return ClassificationPoint(
        threshold=thr, fpr_budget=fpr_budget, precision=precision, recall=recall,
        f1=f1, fpr=fpr, n_alerts=tp + fp,
    )


def auroc(y_true: np.ndarray, y_score: np.ndarray) -> float:
    """Area under the ROC curve via the rank-sum (Mann-Whitney U) identity.

    Handles ties by averaging ranks. Returns 0.5 for a degenerate single-class
    input (no discriminative signal is measurable).
    """
    y_true = np.asarray(y_true).astype(bool)
    y_score = np.asarray(y_score, dtype=float)
    n_pos = int(np.count_nonzero(y_true))
    n_neg = y_true.size - n_pos
    if n_pos == 0 or n_neg == 0:
        return 0.5

    order = np.argsort(y_score, kind="stable")
    ranks = np.empty(y_score.size, dtype=float)
    sorted_scores = y_score[order]
    i = 0
    while i < sorted_scores.size:
        j = i
        while j + 1 < sorted_scores.size and sorted_scores[j + 1] == sorted_scores[i]:
            j += 1
        avg_rank = (i + j) / 2.0 + 1.0  # 1-based, averaged over the tie block
        ranks[order[i : j + 1]] = avg_rank
        i = j + 1

    rank_sum_pos = ranks[y_true].sum()
    return float((rank_sum_pos - n_pos * (n_pos + 1) / 2.0) / (n_pos * n_neg))


@dataclass
class Calibration:
    ece: float
    bin_confidence: np.ndarray
    bin_accuracy: np.ndarray
    bin_count: np.ndarray


def expected_calibration_error(
    y_true: np.ndarray, y_score: np.ndarray, n_bins: int = 15
) -> Calibration:
    """ECE with equal-width bins, plus the reliability-curve data."""
    y_true = np.asarray(y_true).astype(float)
    y_score = np.asarray(y_score, dtype=float)
    edges = np.linspace(0.0, 1.0, n_bins + 1)
    idx = np.clip(np.digitize(y_score, edges[1:-1], right=False), 0, n_bins - 1)

    conf = np.zeros(n_bins)
    acc = np.zeros(n_bins)
    count = np.zeros(n_bins, dtype=int)
    ece = 0.0
    n = y_score.size
    for b in range(n_bins):
        mask = idx == b
        count[b] = int(np.count_nonzero(mask))
        if count[b]:
            conf[b] = float(y_score[mask].mean())
            acc[b] = float(y_true[mask].mean())
            ece += count[b] / n * abs(acc[b] - conf[b])
    return Calibration(ece=float(ece), bin_confidence=conf, bin_accuracy=acc, bin_count=count)


@dataclass
class LeadTimeResult:
    per_episode_seconds: list[float]
    median: float
    iqr_low: float
    iqr_high: float
    n_detected: int
    n_episodes: int


def lead_time(
    episodes: list[dict], alerts: list[dict], grace_seconds: float = 0.0
) -> LeadTimeResult:
    """Median lead time (with IQR) over attack episodes.

    Each episode: {host, start, end} in epoch seconds — `host` is the attacking
    host, `end` the annotated completion. Each alert: {host, time} (window_start
    of a fired host-window). Lead time for an episode = end - (time of the first
    alert on that host with start-grace <= time <= end). An episode with no such
    alert contributes 0 (undetected, never dropped). Positive lead time = the
    attack was flagged before completion.
    """
    by_host: dict[str, list[float]] = {}
    for a in alerts:
        by_host.setdefault(str(a["host"]), []).append(float(a["time"]))
    for host in by_host:
        by_host[host].sort()

    leads: list[float] = []
    detected = 0
    for ep in episodes:
        host = str(ep["host"])
        lo = float(ep["start"]) - grace_seconds
        hi = float(ep["end"])
        first = next((t for t in by_host.get(host, []) if lo <= t <= hi), None)
        if first is None:
            leads.append(0.0)
        else:
            leads.append(max(hi - first, 0.0))
            detected += 1

    if not leads:
        return LeadTimeResult([], 0.0, 0.0, 0.0, 0, 0)
    arr = np.asarray(leads, dtype=float)
    return LeadTimeResult(
        per_episode_seconds=leads,
        median=float(np.median(arr)),
        iqr_low=float(np.percentile(arr, 25)),
        iqr_high=float(np.percentile(arr, 75)),
        n_detected=detected,
        n_episodes=len(leads),
    )


def alerts_per_day(n_alerts: int, n_host_windows: int, cfg: dict) -> float:
    """Extrapolate alerts/day from the alert count over a set of host-windows.

    Uses the stride (each host-window advances `stride` seconds of one host's
    timeline) to convert a host-window count into host-days observed.
    """
    stride = cfg["windows"]["stride_seconds"]
    host_seconds = n_host_windows * stride
    host_days = host_seconds / 86400.0
    return float(n_alerts / host_days) if host_days > 0 else 0.0
