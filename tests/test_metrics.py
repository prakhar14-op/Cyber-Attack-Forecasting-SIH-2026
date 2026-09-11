"""M4.1: metrics with hand-computed expected values."""

from __future__ import annotations

import numpy as np
import pytest

from configs import CONFIG_DIR, REPO_ROOT, load_config
from eval import metrics as M
from eval import uncertainty as U


def test_threshold_and_classification_at_fpr():
    # 6 benign (scores .1,.2,.3,.4,.5,.6), 4 attack (.55,.65,.75,.85).
    y = np.array([0, 0, 0, 0, 0, 0, 1, 1, 1, 1])
    s = np.array([0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.55, 0.65, 0.75, 0.85])

    # budget 1/6 ~= 0.167: exactly 1 benign may fire. The rule picks the LOWEST
    # threshold within budget (max recall) -> 0.55, at which the single benign .6
    # fires (fpr = 1/6, exactly the budget) and all 4 attacks fire.
    pt = M.classification_at_fpr(y, s, fpr_budget=1 / 6)
    assert pt.threshold == pytest.approx(0.55)
    assert pt.fpr == pytest.approx(1 / 6)
    assert pt.recall == pytest.approx(1.0)      # all 4 attacks caught
    assert pt.precision == pytest.approx(0.8)   # 4 TP, 1 FP (benign .6)
    assert pt.f1 == pytest.approx(2 * 0.8 * 1.0 / 1.8)
    assert pt.n_alerts == 5

    # a stricter budget of 0 benign allowed -> threshold above .6, catches .65/.75/.85.
    strict = M.classification_at_fpr(y, s, fpr_budget=0.0)
    assert strict.fpr == 0.0
    assert strict.recall == pytest.approx(0.75) and strict.precision == pytest.approx(1.0)


def test_auroc_matches_rank_identity_and_ties():
    y = np.array([0, 0, 1, 1])
    s = np.array([0.1, 0.4, 0.35, 0.8])
    # pairs (neg,pos): (.1,.35)+, (.1,.8)+, (.4,.35)-, (.4,.8)+ -> 3/4
    assert M.auroc(y, s) == pytest.approx(0.75)
    # a perfect separation
    assert M.auroc([0, 0, 1, 1], [0.1, 0.2, 0.9, 0.95]) == pytest.approx(1.0)
    # all ties -> 0.5
    assert M.auroc([0, 1, 0, 1], [0.5, 0.5, 0.5, 0.5]) == pytest.approx(0.5)
    # single-class degenerate
    assert M.auroc([1, 1, 1], [0.2, 0.5, 0.9]) == pytest.approx(0.5)


def test_ece_hand_computed():
    # 2 bins via n_bins=2: scores .1,.2 (bin0), .8,.9 (bin1).
    y = np.array([0, 0, 1, 1])
    s = np.array([0.1, 0.2, 0.8, 0.9])
    cal = M.expected_calibration_error(y, s, n_bins=2)
    # bin0: conf .15, acc 0 -> gap .15; bin1: conf .85, acc 1 -> gap .15.
    # ECE = .5*.15 + .5*.15 = .15
    assert cal.ece == pytest.approx(0.15)
    assert cal.bin_count.tolist() == [2, 2]


def test_lead_time_median_iqr_and_undetected_zero():
    # episode ends at t=100; alerts on the attacker at various times.
    episodes = [
        {"host": "A", "start": 0, "end": 100},   # alerted at 40 -> lead 60
        {"host": "B", "start": 0, "end": 100},   # alerted at 90 -> lead 10
        {"host": "C", "start": 0, "end": 100},   # never alerted -> lead 0
    ]
    alerts = [
        {"host": "A", "time": 40},
        {"host": "A", "time": 55},   # earlier one (40) wins
        {"host": "B", "time": 90},
        {"host": "D", "time": 5},    # not an attacker episode
    ]
    res = M.lead_time(episodes, alerts)
    assert res.per_episode_seconds == [60.0, 10.0, 0.0]
    assert res.n_detected == 2 and res.n_episodes == 3
    assert res.median == pytest.approx(10.0)  # median of [0,10,60]


def test_lead_time_ignores_alerts_after_completion():
    episodes = [{"host": "A", "start": 0, "end": 100}]
    alerts = [{"host": "A", "time": 150}]  # after completion -> not counted
    res = M.lead_time(episodes, alerts)
    assert res.per_episode_seconds == [0.0] and res.n_detected == 0


def test_alerts_per_host_day(data_cfg):
    # 5s stride: 17280 host-windows = 1 host-day; 10 alerts -> 10 alerts/host-day.
    per_day = M.alerts_per_host_day(n_alerts=10, n_host_windows=17280, cfg=data_cfg)
    assert per_day == pytest.approx(10.0)
    # back-compat alias resolves to the same function.
    assert M.alerts_per_day is M.alerts_per_host_day


def test_undetected_lead_value_comes_from_config():
    # the shipped value is 0 and the docstring's "never dropped" rule depends on
    # it staying a number; the point is that the module does not hardcode it.
    assert load_config("eval")["metrics"]["lead_time_undetected_seconds"] == 0
    episodes = [{"host": "A", "start": 0, "end": 100}]
    assert M.lead_time(episodes, []).per_episode_seconds == [0.0]
    assert M.lead_time(episodes, [], undetected_seconds=-1.0).per_episode_seconds == [-1.0]


# --------------------------------------------------------- cluster bootstrap CI

def test_cluster_bootstrap_percentile_is_exact_on_a_two_group_mean():
    # 2 groups whose scores are constant at 0 and 1. A resample draws 2 groups
    # with replacement, so the mean is 0 / 0.5 / 1 with probability 1/4, 1/2, 1/4
    # -> over 1000 draws the 2.5th percentile is exactly 0 and the 97.5th is
    # exactly 1 (P(no all-zero draw) = 0.75**1000).
    y = np.array([0, 1, 0, 1])
    s = np.array([0.0, 0.0, 1.0, 1.0])
    g = np.array([0, 0, 1, 1])
    ci = U.cluster_bootstrap(lambda yt, ys: ys.mean(), y, s, g, n_resamples=1000, seed=1)
    assert (ci.point, ci.low, ci.high) == (0.5, 0.0, 1.0)
    assert ci.n_groups == 2 and ci.n_resamples == 1000


def test_cluster_bootstrap_auroc_on_perfect_separation_is_a_degenerate_interval():
    y = np.array([0, 0, 0, 0, 1, 1, 1, 1])
    s = np.array([0.1, 0.2, 0.3, 0.4, 0.6, 0.7, 0.8, 0.9])
    g = np.array([0, 0, 1, 1, 2, 2, 3, 3])
    ci = U.auroc_interval(y, s, g, n_resamples=500, seed=3)
    assert ci.point == 1.0 and ci.low == 1.0 and ci.high == 1.0
    # single-class resamples are dropped, not scored 0.5 by metrics.auroc's
    # stated convention, so fewer than 500 draws carry the interval.
    assert 0 < ci.n_usable < 500


def test_cluster_bootstrap_is_wider_than_a_row_bootstrap_on_replicated_rows():
    # 20 clusters, each emitting 10 identical rows — the correlated-rows regime
    # the attacker host is in. Row resampling sees 200 "independent" rows and
    # shrinks the interval by ~sqrt(10); resampling clusters must not.
    rng = np.random.RandomState(0)
    n_groups, rep = 20, 10
    y = np.repeat(np.array([0, 1] * (n_groups // 2)), rep)
    s = np.repeat(rng.rand(n_groups), rep)
    g = np.repeat(np.arange(n_groups), rep)

    by_cluster = U.auroc_interval(y, s, g, n_resamples=2000, seed=7)
    by_row = U.auroc_interval(y, s, np.arange(y.size), n_resamples=2000, seed=7)
    assert by_cluster.point == by_row.point  # same estimate, different variance
    assert (by_cluster.high - by_cluster.low) > 2.0 * (by_row.high - by_row.low)


def test_cluster_bootstrap_f1_at_a_fixed_threshold_matches_the_point_metric():
    # same hand-computed sample as test_threshold_and_classification_at_fpr.
    y = np.array([0, 0, 0, 0, 0, 0, 1, 1, 1, 1])
    s = np.array([0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.55, 0.65, 0.75, 0.85])
    g = np.array([0, 0, 1, 1, 2, 2, 3, 3, 4, 4])
    expected = M.classification_at_fpr(y, s, 1 / 6).f1

    refit = U.f1_at_fpr_interval(y, s, g, fpr_budget=1 / 6, n_resamples=300, seed=5)
    fixed = U.f1_at_fpr_interval(y, s, g, fpr_budget=1 / 6, threshold=0.55,
                                 n_resamples=300, seed=5)
    assert refit.point == pytest.approx(expected)
    assert fixed.point == pytest.approx(expected)
    assert fixed.low <= fixed.point <= fixed.high


def test_cluster_bootstrap_is_reproducible_and_reads_its_defaults_from_config():
    y = np.array([0, 0, 1, 1, 0, 1])
    s = np.array([0.1, 0.2, 0.7, 0.9, 0.3, 0.6])
    g = np.array([0, 0, 1, 1, 2, 2])
    a = U.auroc_interval(y, s, g)
    b = U.auroc_interval(y, s, g)
    assert (a.low, a.high, a.n_usable) == (b.low, b.high, b.n_usable)

    cfg = load_config("eval")["metrics"]
    assert a.n_resamples == cfg["bootstrap_resamples"]
    assert a.level == cfg["bootstrap_ci_level"]


def test_cluster_bootstrap_rejects_bad_input():
    y = np.array([0, 1, 0, 1])
    s = np.array([0.1, 0.9, 0.2, 0.8])
    g = np.array([0, 0, 1, 1])
    with pytest.raises(ValueError, match="length mismatch"):
        U.auroc_interval(y, s[:3], g)
    with pytest.raises(ValueError, match="empty sample"):
        U.auroc_interval([], [], [])
    with pytest.raises(ValueError, match=">= 2 groups"):
        U.auroc_interval(y, s, np.zeros(4))
    with pytest.raises(ValueError, match="degenerate on the full sample"):
        U.auroc_interval(np.ones(4), s, g)  # single class -> nothing to rank
    with pytest.raises(ValueError, match="fpr_budget"):
        U.f1_at_fpr_interval(y, s, g, fpr_budget=1.5)


def test_episode_group_ids_clusters_attack_rows_by_episode():
    host = np.array(["A", "A", "A", "B", "B"])
    ws = np.array([0.0, 50.0, 500.0, 10.0, 20.0])
    episodes = [{"host": "A", "start": 0, "end": 100}]
    groups = U.episode_group_ids(host, ws, episodes)
    # the two A-rows inside [0, 100] share one cluster; A's later window and both
    # B-rows fall back to host-level clusters.
    assert groups[0] == groups[1] != groups[2]
    assert groups[3] == groups[4] and groups[3] != groups[2]
    assert len(set(groups)) == 3


def test_episode_group_ids_feed_the_bootstrap_directly():
    # the labels are strings in an object array; the grouping must survive
    # np.unique without the caller re-encoding it.
    rng = np.random.RandomState(0)
    n = 400
    host = np.array(["attacker"] * 40 + [f"h{i % 8}" for i in range(n - 40)])
    ws = np.arange(float(n))
    y = np.zeros(n, dtype=int)
    y[:40] = 1
    s = rng.rand(n)
    s[:40] += 0.6
    episodes = [{"host": "attacker", "start": 0, "end": 19},
                {"host": "attacker", "start": 20, "end": 39}]

    groups = U.episode_group_ids(host, ws, episodes)
    ci = U.auroc_interval(y, s, groups, n_resamples=500, seed=2)
    assert ci.n_groups == 10  # 2 episodes + 8 victim hosts
    assert ci.low <= ci.point <= ci.high


# ------------------------------------------------ configs/eval.yaml has no dead keys

def test_every_eval_metrics_config_key_is_consumed():
    """A declared metric knob that nothing reads is a claim the code does not make.

    Matching on the quoted key is deliberate: `cfg["metrics"]["ece_bins"]` counts,
    a mention in a comment does not.
    """
    sources = "\n".join(
        p.read_text(encoding="utf-8") for p in sorted((REPO_ROOT / "eval").glob("*.py"))
    )
    dead = [k for k in load_config("eval")["metrics"] if f'"{k}"' not in sources]
    assert not dead, (
        f"configs/eval.yaml declares metrics keys nothing in eval/ reads: {dead} — "
        "implement them or delete them"
    )
    assert (CONFIG_DIR / "eval.yaml").exists()
