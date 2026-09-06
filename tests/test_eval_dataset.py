"""M4: horizon target shifting, ablation table rendering, attacker episodes."""

from __future__ import annotations

import json

import numpy as np
import pandas as pd

from eval import ablation
from eval import dataset as D


def test_horizon_shift_reads_future_window_label():
    # one host, windows 0..4; attack at windows 2,3.
    labelled = pd.DataFrame(
        {
            "host": ["A"] * 5,
            "window_id": [0, 1, 2, 3, 4],
            "window_start": [0, 5, 10, 15, 20],
            "stage": ["benign", "benign", "c2", "c2", "benign"],
        }
    )
    # horizon 0: target is the window's own label
    stage0, y0 = D._shift_target_by_horizon(labelled, 0)
    assert y0.tolist() == [False, False, True, True, False]

    # horizon 2: window t's target is window t+2's label
    stage2, y2 = D._shift_target_by_horizon(labelled, 2)
    # w0->w2=c2(attack), w1->w3=c2(attack), w2->w4=benign, w3->w5=missing, w4->w6=missing
    assert y2[0] and y2[1]
    assert not y2[2]
    assert stage2[3] is None and stage2[4] is None  # no future window


def test_attacker_episodes_from_timeline(data_cfg):
    # test split = 02-03 (bot); attacker 18.219.211.138, two sessions.
    episodes = D.attacker_episodes(data_cfg, "test")
    assert episodes, "bot day must yield attacker episodes"
    assert all(e["host"] == "18.219.211.138" for e in episodes)
    assert all(e["end"] > e["start"] for e in episodes)
    assert all(e["stage"] == "c2" for e in episodes)


def _fake_result(model, f1, lead, detected, total):
    return {
        "model": model, "holdout_family": None,
        "test": {
            "auroc": 0.9, "ece": 0.05,
            "fpr_0.01": {
                "f1": f1, "precision": f1, "recall": f1, "lead_time_median": lead,
                "lead_time_iqr": [lead - 5, lead + 5], "episodes_detected": detected,
                "episodes_total": total, "alerts_per_host_day": 12.0,
            },
        },
    }


def test_ablation_table_sorts_by_lead_and_renders(tmp_path):
    (tmp_path / "lr.json").write_text(json.dumps(_fake_result("lr", 0.6, 30, 1, 2)))
    (tmp_path / "xgb.json").write_text(json.dumps(_fake_result("xgb", 0.8, 10, 1, 2)))

    table = ablation.build_table(budget=0.01, results_dir=tmp_path)
    # sorted by lead_median descending -> lr (30s) before xgb (10s)
    assert list(table["model"]) == ["lr", "xgb"]
    assert table.iloc[0]["lead_median_s"] == 30

    md = ablation.to_markdown(table, 0.01)
    assert "| model |" in md and "lr" in md and "xgb" in md


def test_lstm_segment_chunking_covers_every_row_once():
    from types import SimpleNamespace

    from eval.harness import _segment_split

    n = 130  # host A: 100 windows, host B: 30
    X = np.random.RandomState(0).rand(n, 4).astype(np.float32)
    y = np.zeros(n, np.int8)
    host = np.array(["A"] * 100 + ["B"] * 30)
    ws = np.concatenate([np.arange(100.0), np.arange(30.0)])
    split = SimpleNamespace(X=X, y=y, host=host, window_start=ws)

    Xs, Ys, Ms, Is = _segment_split(split, 48)
    assert Xs.shape == (4, 48, 4)  # ceil(100/48)=3 + ceil(30/48)=1
    rows = Is.reshape(-1)
    real = rows[rows >= 0]
    assert sorted(np.unique(real)) == list(range(n)), "every row mapped exactly once"
    assert len(real) == n
    assert int(Ms.sum()) == n, "mask marks exactly the real positions"
    # scatter round-trip
    probs = np.random.RandomState(1).rand(*Ys.shape)
    flat = np.zeros(n)
    flat[rows[rows >= 0]] = probs.reshape(-1)[rows >= 0]
    assert np.count_nonzero(flat) >= n - 1


def test_family_days_and_family_derivation(data_cfg):
    fam = D.family_days(data_cfg)
    assert "2018-02-14" in fam["bruteforce"]
    assert "2018-02-16" in fam["dos"]
    assert "2018-03-02" in fam["bot"]
    assert D.attack_family("DoS-Hulk") == "dos"
    assert D.attack_family("SSH-Bruteforce") == "bruteforce"
    assert D.attack_family("Bot (session 1)") == "bot"


def test_holdout_family_drops_attack_windows_and_guards(data_cfg):
    import pytest

    # synthetic labelled frame: 16-02 (dos) attack + benign, 14-02 benign.
    labelled = pd.DataFrame(
        {
            "host": ["a", "a", "b", "b"],
            "window_id": [1, 2, 3, 4],
            "window_start": [5, 10, 15, 20],
            "day": ["2018-02-16", "2018-02-16", "2018-02-16", "2018-02-14"],
            "stage": ["impact", "benign", "impact", "benign"],
        }
    )
    kept = D.drop_holdout_family(data_cfg, labelled, "dos", "train")
    assert (kept["stage"] == "impact").sum() == 0, "dos attack windows dropped"
    assert (kept["stage"] == "benign").sum() == 2, "benign preserved"

    # a family absent from the frame must fail loudly, never silently no-op.
    with pytest.raises(ValueError, match="removed nothing"):
        D.drop_holdout_family(data_cfg, labelled, "bot", "train")
