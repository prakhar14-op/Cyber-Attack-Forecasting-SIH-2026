"""Fused model (rank-mean TGN+XGB): the fusion math is sound and leak-free."""

from __future__ import annotations

import numpy as np
import pytest

from eval.fused import _percentile_rank


def test_percentile_rank_is_uniform_and_order_preserving():
    rng = np.random.RandomState(0)
    x = rng.lognormal(size=10_000)  # heavy-tailed, like real scores
    r = _percentile_rank(x)
    # order preserved exactly
    assert np.array_equal(np.argsort(x, kind="stable"), np.argsort(r, kind="stable"))
    # ranks live on (0, 1] and are ~uniform (scale-free by construction)
    assert 0.0 < r.min() and r.max() <= 1.0
    assert abs(r.mean() - 0.5) < 0.01


def test_rank_mean_fusion_rewards_complementary_rankers():
    """Two weak, DECORRELATED rankers fuse into a stronger one — the property
    the fused model's 0.94 rests on. Built synthetically so the test needs no
    dataset: each member sees a different half of the signal."""
    from eval import metrics as M

    rng = np.random.RandomState(1)
    n = 20_000
    y = (rng.rand(n) < 0.05).astype(np.int8)
    sig_a, sig_b = rng.randn(n), rng.randn(n)      # independent evidence channels
    a = 1.2 * y * (sig_a > 0) + rng.randn(n) * 0.8  # member A sees channel a
    b = 1.2 * y * (sig_b > 0) + rng.randn(n) * 0.8  # member B sees channel b
    fused = (_percentile_rank(a) + _percentile_rank(b)) / 2

    au_a, au_b = M.auroc(y, a), M.auroc(y, b)
    au_f = M.auroc(y, fused)
    assert au_f > max(au_a, au_b) + 0.02, (
        f"fusion must beat both members on complementary signal "
        f"(a={au_a:.3f}, b={au_b:.3f}, fused={au_f:.3f})"
    )


def test_isotonic_probability_is_monotone_so_ranking_never_reorders():
    """fused.py cuts the ALERT SET on the raw rank score and uses the val-fit
    isotonic only for the reported probability (ECE). The property that makes
    that safe is monotonicity: the calibrated probability may coarsen scores
    into ties (flat segments — which is exactly why thresholding is NOT done on
    it), but it can never invert the order of two windows."""
    from sklearn.isotonic import IsotonicRegression

    rng = np.random.RandomState(2)
    y_val = (rng.rand(5000) < 0.1).astype(np.int8)
    s_val = np.clip(y_val * 0.3 + rng.rand(5000) * 0.7, 0, 1)
    s_test = np.sort(rng.rand(3000))  # ascending inputs

    iso = IsotonicRegression(out_of_bounds="clip").fit(s_val, y_val)
    p = iso.predict(s_test)
    assert np.all(np.diff(p) >= 0), "isotonic output must be non-decreasing in the score"
    # and it maps into [0, 1] — an honest probability
    assert p.min() >= 0.0 and p.max() <= 1.0


def test_fused_refuses_misaligned_member_dumps(monkeypatch, tmp_path):
    """Members must describe the SAME host-windows; anything else is an error,
    never a silent mis-join."""
    import eval.fused as F

    def fake_load(name):
        n = 100
        rng = np.random.RandomState(3 if name == "xgb" else 4)
        y = (rng.rand(n) < 0.2).astype(np.int8)  # different y per member -> misaligned
        return {f"{s}_{k}": v for s in ("val", "test")
                for k, v in (("y", y), ("score", rng.rand(n)),
                             ("host", np.array(["h"] * n)), ("ws", np.arange(n, dtype=float)))}

    monkeypatch.setattr(F, "_load_member", fake_load)
    with pytest.raises(RuntimeError, match="disagree"):
        F.evaluate_fused()
