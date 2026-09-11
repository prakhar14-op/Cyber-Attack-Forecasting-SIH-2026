"""The writer-facing layer of eval/uncertainty.py: `annotate_split`.

The cluster bootstrap ITSELF (percentile exactness, cluster-vs-row width, the
input rejections, `episode_group_ids`) is pinned in tests/test_metrics.py and is
deliberately not restated here. What this file covers is the one call a results
writer makes — that it attaches the intervals where the results schema expects
them, at the threshold the block already records rather than a refitted one, and
that a refused interval lands as `{"unavailable": ...}` rather than a number.

That distinction is the whole reason the helper exists: `eval/fused.py`,
`eval/forecast.py` and `eval/world.py` each assemble their own result block, and
the headline fused row is a bare AUROC point estimate over 2 attack episodes.
The helper is what makes wiring one of them a single line instead of a
re-implementation that can drift from the harness's.
"""

from __future__ import annotations

import ast
from pathlib import Path

import numpy as np
import pytest

from eval import uncertainty as U

RESAMPLES = 200  # enough for a stable interval; the default 1000 is config-tested


def _synthetic_split(seed: int = 0):
    """Four hosts of 5 s windows, two of them carrying an attack episode.

    Shaped like what a writer holds at the point it would call annotate_split:
    y / score / host / window_start arrays plus the split's episode list.
    """
    rng = np.random.RandomState(seed)
    per_host = 150
    hosts, ws = [], []
    for h in range(4):
        hosts += [f"h{h}"] * per_host
        ws += list(np.arange(per_host, dtype=float) * 5.0)
    host = np.array(hosts)
    window_start = np.array(ws)

    episodes = [{"host": "h0", "start": 100.0, "end": 300.0},
                {"host": "h1", "start": 400.0, "end": 600.0}]
    y = np.zeros(host.size, dtype=np.int8)
    for ep in episodes:
        y[(host == ep["host"]) & (window_start >= ep["start"])
          & (window_start <= ep["end"])] = 1
    score = rng.rand(host.size) * 0.5 + y * 0.35
    return y, score, host, window_start, episodes


def _block(threshold: float, budgets=(0.001, 0.01)) -> dict:
    """A result block in the shape every eval writer builds."""
    return {f"fpr_{b}": {"threshold": threshold, "f1": 0.3, "precision": 0.4,
                         "recall": 0.25, "fpr": b}
            for b in budgets}


# ------------------------------------------------------------ the one-line call

def test_annotate_split_attaches_intervals_where_the_schema_expects_them():
    y, score, host, ws, episodes = _synthetic_split()
    block = _block(threshold=0.6)

    U.annotate_split(block, y, score, host, ws, episodes, n_resamples=RESAMPLES)

    auroc_ci = block["auroc_ci"]
    assert auroc_ci["low"] <= auroc_ci["point"] <= auroc_ci["high"]
    assert auroc_ci["low"] < auroc_ci["high"], "a collapsed band is not a measurement"
    # 2 episodes + 4 host-level clusters; the harness's real number is this small.
    assert auroc_ci["n_groups"] == 6
    assert auroc_ci["n_resamples"] == RESAMPLES and auroc_ci["n_usable"] > 0

    for key in ("fpr_0.001", "fpr_0.01"):
        f1_ci = block[key]["f1_ci"]
        assert f1_ci["low"] <= f1_ci["point"] <= f1_ci["high"]
        assert f1_ci["n_groups"] == 6
    # the point estimates it decorates are untouched
    assert block["fpr_0.01"]["f1"] == 0.3


def test_annotate_split_uses_the_recorded_threshold_and_does_not_refit_one():
    """The block's own threshold fixes the operating point.

    Two blocks differing ONLY in the threshold they record must get different F1
    intervals: a threshold above every score fires on nothing, so F1 is 0 at
    every resample. If the helper refitted the budget inside each resample
    instead, both blocks would come back identical — which is what makes this
    assertion able to fail.
    """
    y, score, host, ws, episodes = _synthetic_split()

    as_reported = _block(threshold=0.6)
    above_every_score = _block(threshold=float(score.max()) + 1.0)
    for block in (as_reported, above_every_score):
        U.annotate_split(block, y, score, host, ws, episodes, n_resamples=RESAMPLES)

    fires = as_reported["fpr_0.01"]["f1_ci"]
    silent = above_every_score["fpr_0.01"]["f1_ci"]
    assert silent["point"] == 0.0 and silent["low"] == 0.0 and silent["high"] == 0.0
    assert fires["point"] > 0.0
    assert fires != silent


def test_annotate_split_records_a_reason_never_a_substituted_bound():
    """One cluster -> the bootstrap refuses; the block must say so in words."""
    n = 40
    host = np.array(["only-host"] * n)
    ws = np.arange(float(n))
    y = (np.arange(n) % 2).astype(np.int8)
    score = np.linspace(0.0, 1.0, n)
    block = _block(threshold=0.5)

    U.annotate_split(block, y, score, host, ws, episodes=[], n_resamples=RESAMPLES)

    for entry in (block["auroc_ci"], block["fpr_0.01"]["f1_ci"]):
        assert set(entry) == {"unavailable"}, entry
        assert ">= 2 groups" in entry["unavailable"]
        assert "low" not in entry and "high" not in entry


def test_annotate_split_honours_a_writers_own_auroc_key():
    # eval/forecast.py names its per-horizon AUROC `auroc_test`, so its interval
    # has to be able to sit beside it rather than under a fixed key.
    y, score, host, ws, episodes = _synthetic_split()
    block = _block(threshold=0.6)
    U.annotate_split(block, y, score, host, ws, episodes,
                     auroc_key="auroc_test_ci", n_resamples=RESAMPLES)
    assert "auroc_test_ci" in block and "auroc_ci" not in block


def test_annotate_split_fails_loudly_on_a_block_it_cannot_honestly_annotate():
    y, score, host, ws, episodes = _synthetic_split()

    with pytest.raises(ValueError, match="no 'fpr_<budget>' operating point"):
        U.annotate_split({"auroc": 0.9}, y, score, host, ws, episodes,
                         n_resamples=RESAMPLES)

    no_threshold = {"fpr_0.01": {"f1": 0.3}}
    with pytest.raises(KeyError, match="records no 'threshold'"):
        U.annotate_split(no_threshold, y, score, host, ws, episodes,
                         n_resamples=RESAMPLES)

    with pytest.raises(ValueError, match="not 'fpr_<budget>'"):
        U._budget_from_key("fpr_one-percent")


def test_interval_or_reason_lets_a_real_exception_through():
    """Only the bootstrap's own refusals become `{"unavailable": ...}`.

    A ValueError is the documented refusal channel; anything else (a bug in the
    statistic, a missing key) must still crash the run rather than be filed as
    "no interval available".
    """
    def boom(*_a, **_k):
        raise KeyError("this is a bug, not a refusal")

    with pytest.raises(KeyError):
        U.interval_or_reason(boom)

    def refuses(*_a, **_k):
        raise ValueError("fewer than 2 groups")

    assert U.interval_or_reason(refuses) == {"unavailable": "fewer than 2 groups"}


# --------------------------------------------------------------- harness wiring

def test_the_harness_attaches_intervals_through_this_helper():
    """STRUCTURAL check (AST), not an execution of the harness.

    eval/harness.py's evaluate() needs the CIC-IDS-2018 split on disk and a
    trained model, so the suite cannot run it. What can be pinned without the
    dataset is that the call is still there: round 2 wired the intervals into
    the harness and nothing in the suite would have noticed them being removed.
    """
    src = Path(U.__file__).resolve().parent / "harness.py"
    tree = ast.parse(src.read_text(encoding="utf-8"))
    called = {
        node.func.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
    }
    assert "annotate_split" in called, (
        f"{src} no longer calls uncertainty.annotate_split — the shipped results "
        "JSON would carry bare point estimates over 2 episodes"
    )
