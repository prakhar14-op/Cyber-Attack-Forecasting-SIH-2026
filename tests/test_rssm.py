"""M7: filter-then-imagine dependence (7.2), missing-window guard (7.5),
ensemble band widening (7.6), KL free bits (7.3), dynamics loss (7.4)."""

from __future__ import annotations

import pytest
import torch

from configs import load_config
from models import rssm as R

EMBED = 32


@pytest.fixture(scope="module")
def rssm_cfg():
    return load_config("train_rssm")


@pytest.fixture
def model(rssm_cfg):
    return R.build_model(rssm_cfg, embed_dim=EMBED)


def test_filtered_initial_state_depends_on_the_inputs(model):
    """M7.2: the rollout starts from the FILTERED state — never zeros."""
    torch.manual_seed(0)
    e1 = torch.randn(2, 10, EMBED)
    e2 = torch.randn(2, 10, EMBED)

    s1 = model.filter(e1, sample=False)
    s2 = model.filter(e2, sample=False)
    assert not torch.allclose(s1["h"][:, -1], s2["h"][:, -1]), (
        "terminal filtered state must depend on the observed sequence"
    )
    assert float(s1["h"][:, -1].abs().sum()) > 0, "state must not be zeros"

    r1 = model.filter_then_imagine(e1, horizon=4, sample=False)
    r2 = model.filter_then_imagine(e2, horizon=4, sample=False)
    assert not torch.allclose(r1["attack_prob"], r2["attack_prob"]), (
        "forecasts must depend on what was observed"
    )


def test_missing_window_guard_uses_prior_and_stays_finite(model):
    """M7.5: gaps (huge delta_t) and padding positions must not crash or NaN,
    and a padding position must NOT inject observation information."""
    torch.manual_seed(0)
    e = torch.randn(2, 8, EMBED)
    delta = torch.ones(2, 8)
    delta[:, 4] = 720.0  # a one-hour gap in stride units
    valid = torch.ones(2, 8, dtype=torch.bool)
    valid[:, 4] = False  # the gap window is absent

    out = model.filter_then_imagine(e, horizon=4, delta_t=delta, valid=valid, sample=False)
    assert torch.isfinite(out["attack_prob"]).all()

    # changing the OBSERVATION at an invalid position must not change anything
    e2 = e.clone()
    e2[:, 4] = 999.0
    out2 = model.filter_then_imagine(e2, horizon=4, delta_t=delta, valid=valid, sample=False)
    assert torch.allclose(out["attack_prob"], out2["attack_prob"]), (
        "a padding/gap position must be driven by the prior, not the observation"
    )


def test_ensemble_rollout_machinery(model, rssm_cfg):
    """M7.6 (mechanism): N stochastic rollouts disagree, the band is positive,
    and shapes are right.

    Band WIDENING with horizon is a property of the TRAINED transition (an
    untrained GRU contracts state divergence, so per-step prior noise gives a
    flat band — measured). The widening check therefore lives in the harness
    world-model run: band(k=1)/band(k=8)/band_widens are recorded in
    results/world.json and a non-widening band prints a loud WARNING there."""
    torch.manual_seed(1337)
    e = torch.randn(8, 12, EMBED)
    roll = model.ensemble_rollout(e, horizon=8, n_samples=rssm_cfg["rollout"]["ensemble_samples"])
    band = roll["band"]  # [B, K]
    assert band.shape == (8, 8)
    assert float(band.mean()) > 0, "tier-2 ensemble members must disagree"
    assert not torch.allclose(roll["samples"][0], roll["samples"][1]), (
        "distinct stochastic rollouts must differ"
    )


def test_kl_balanced_loss_floor_and_raw_kl_can_expose_collapse(model, rssm_cfg):
    torch.manual_seed(0)
    states = model.filter(torch.randn(4, 6, EMBED), sample=True)
    loss_kl, raw_kl = R.kl_balanced(states, rssm_cfg)
    assert torch.isfinite(loss_kl)
    assert float(loss_kl) >= rssm_cfg["loss"]["kl_free_bits"], "loss term is floored"

    # The collapse alert watches the RAW KL, which must be able to drop below
    # the floor (the audit found alerting on the clamped value was dead code):
    # posterior == prior -> raw KL == 0 while the loss term still reads the floor.
    collapsed = {
        "post_mean": states["prior_mean"], "post_std": states["prior_std"],
        "prior_mean": states["prior_mean"], "prior_std": states["prior_std"],
        "h": states["h"],
    }
    loss_c, raw_c = R.kl_balanced(collapsed, rssm_cfg)
    assert raw_c == pytest.approx(0.0, abs=1e-6), "raw KL must expose collapse"
    assert float(loss_c) >= rssm_cfg["loss"]["kl_free_bits"]


def test_dynamics_loss_finite_and_positive(model, rssm_cfg, data_cfg):
    torch.manual_seed(0)
    b, t = 3, 12
    e = torch.randn(b, t, EMBED)
    states = model.filter(e, sample=False)
    attack = (torch.rand(b, t) < 0.2).float()
    stage = torch.randint(0, len(data_cfg["stages"]), (b, t))
    valid = torch.ones(b, t, dtype=torch.bool)
    loss = R.dynamics_loss(model, states, attack, stage, valid, horizon=4, cfg=rssm_cfg)
    assert torch.isfinite(loss) and float(loss) > 0


def test_dynamics_loss_supervises_only_stride_exact_pairs(model, rssm_cfg, data_cfg):
    """Audit fix: with a gap in the host's timeline, the k-th next ROW is not k
    strides away and must be excluded from step-k supervision."""
    torch.manual_seed(0)
    b, t = 2, 8
    e = torch.randn(b, t, EMBED)
    states = model.filter(e, sample=False)
    attack = torch.zeros(b, t)
    stage = torch.zeros(b, t, dtype=torch.long)
    valid = torch.ones(b, t, dtype=torch.bool)

    # A 5-stride gap before position 4: pairs crossing it are not stride-exact.
    delta = torch.ones(b, t)
    delta[:, 4] = 5.0
    gapped = R.dynamics_loss(
        model, states, attack, stage, valid, horizon=2, cfg=rssm_cfg, delta_t=delta
    )
    regular = R.dynamics_loss(
        model, states, attack, stage, valid, horizon=2, cfg=rssm_cfg,
        delta_t=torch.ones(b, t),
    )
    assert torch.isfinite(gapped) and torch.isfinite(regular)
    # the gap removes supervised pairs, so the two losses must differ
    assert float(gapped) != float(regular)
