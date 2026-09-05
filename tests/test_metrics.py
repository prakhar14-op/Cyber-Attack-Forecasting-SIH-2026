"""M4.1: metrics with hand-computed expected values."""

from __future__ import annotations

import numpy as np
import pytest

from eval import metrics as M


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


def test_alerts_per_day(data_cfg):
    # 5s stride: 17280 host-windows = 1 host-day; 10 alerts -> 10 alerts/day.
    per_day = M.alerts_per_day(n_alerts=10, n_host_windows=17280, cfg=data_cfg)
    assert per_day == pytest.approx(10.0)
