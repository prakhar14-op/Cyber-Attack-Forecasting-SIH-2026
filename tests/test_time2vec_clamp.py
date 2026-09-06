"""Time2Vec gap clamp (diagnosis follow-up): the clamp bounds the time term."""

from __future__ import annotations

import torch

from configs import load_config
from models import graft as G


def _variant(**model_over):
    cfg = load_config("train_graft")
    return {**cfg, "model": {**cfg["model"], **model_over}}


def test_clamp_makes_outlier_gaps_equivalent_to_the_clamp_value():
    """With delta_t_clamp=10, a 5000-stride idle gap must produce the SAME
    embedding as a 10-stride gap (the outlier can no longer swamp the features);
    without the clamp they must differ."""
    x = torch.zeros(1, 4, 16)  # zero features isolate the time term

    clamped = G.build_model(_variant(use_time2vec=True, delta_t_clamp=10), feature_dim=16)
    clamped.eval()
    with torch.no_grad():
        at_clamp = clamped(x, delta_t=torch.full((1, 4), 10.0))["embedding"]
        outlier = clamped(x, delta_t=torch.full((1, 4), 5000.0))["embedding"]
    assert torch.allclose(at_clamp, outlier), "clamped gap must saturate at the clamp"

    unclamped = G.build_model(_variant(use_time2vec=True), feature_dim=16)
    unclamped.eval()
    with torch.no_grad():
        a = unclamped(x, delta_t=torch.full((1, 4), 10.0))["embedding"]
        b = unclamped(x, delta_t=torch.full((1, 4), 5000.0))["embedding"]
    assert not torch.allclose(a, b), "without a clamp the gap magnitude leaks through"


def test_clamp_is_inert_for_normal_gaps():
    """Below the clamp, clamped and unclamped models (identical init) agree —
    the clamp only touches the outlier tail."""
    x = torch.randn(2, 6, 16)
    dt = torch.tensor([[1.0, 1, 2, 3, 5, 9]] * 2)
    m1 = G.build_model(_variant(use_time2vec=True, delta_t_clamp=10), feature_dim=16)
    m2 = G.build_model(_variant(use_time2vec=True), feature_dim=16)
    m1.eval(), m2.eval()
    with torch.no_grad():
        assert torch.allclose(m1(x, delta_t=dt)["embedding"],
                              m2(x, delta_t=dt)["embedding"])
