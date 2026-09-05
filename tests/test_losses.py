"""M6.5: the loss library — Dirichlet evidential behaviour, benign-only
reconstruction that never NaNs (M6.4), composite weighting."""

from __future__ import annotations

import pytest
import torch

from models import losses as L


def test_dirichlet_alpha_floor_and_uncertainty():
    logits = torch.tensor([[-100.0, 0.0, 100.0]])
    alpha = L.dirichlet_alpha(logits)
    # softplus underflows to exactly 0 at very negative logits -> alpha == 1.0
    # (zero evidence, the uniform-Dirichlet limit). The floor is >= 1, never below.
    assert torch.all(alpha >= 1.0), "alpha = softplus + 1 never drops below 1"
    assert float(alpha[0, 0]) == pytest.approx(1.0)
    assert float(alpha[0, 2]) > 100.0
    # zero evidence everywhere -> alpha ~= 1 -> uncertainty ~= K/S = 3/3 = 1
    u_ignorant = L.dirichlet_uncertainty(torch.ones(1, 3))
    assert float(u_ignorant) == pytest.approx(1.0)
    # much evidence -> uncertainty small
    u_confident = L.dirichlet_uncertainty(torch.tensor([[1.0, 1.0, 100.0]]))
    assert float(u_confident) < 0.05


def test_evidential_loss_prefers_correct_confidence():
    target = torch.tensor([2])
    confident_right = torch.full((1, 3), -10.0)
    confident_right[0, 2] = 10.0
    confident_wrong = torch.full((1, 3), -10.0)
    confident_wrong[0, 0] = 10.0
    ignorant = torch.full((1, 3), -10.0)  # alpha ~= 1 everywhere

    l_right = float(L.evidential_loss(confident_right, target, anneal=1.0))
    l_wrong = float(L.evidential_loss(confident_wrong, target, anneal=1.0))
    l_ignorant = float(L.evidential_loss(ignorant, target, anneal=1.0))

    assert l_right < l_ignorant < l_wrong, (
        "loss order must be confident-right < ignorant < confident-wrong"
    )
    # with the true class at alpha=1 and no wrong evidence, the KL term is ~0:
    # ignorant loss with anneal=0 equals ignorant loss with anneal=1
    assert float(L.evidential_loss(ignorant, target, anneal=0.0)) == pytest.approx(
        l_ignorant, rel=1e-4
    )


def test_evidential_kl_anneal_penalises_wrong_evidence():
    target = torch.tensor([1])
    wrong = torch.full((1, 3), -10.0)
    wrong[0, 0] = 5.0  # evidence for a wrong class
    no_kl = float(L.evidential_loss(wrong, target, anneal=0.0))
    with_kl = float(L.evidential_loss(wrong, target, anneal=1.0))
    assert with_kl > no_kl, "annealed KL must add a penalty for misleading evidence"


def test_benign_reconstruction_all_attack_batch_is_finite():
    recon = torch.randn(2, 4, 8)
    feats = torch.randn(2, 4, 8)
    all_attack = torch.zeros(2, 4, dtype=torch.bool)  # empty benign mask
    loss = L.benign_reconstruction_loss(recon, feats, all_attack)
    assert torch.isfinite(loss), "M6.4: an all-attack batch must not NaN"
    assert float(loss) == 0.0

    some_benign = all_attack.clone()
    some_benign[0, 0] = True
    loss2 = L.benign_reconstruction_loss(recon, feats, some_benign)
    expected = float(((recon[0, 0] - feats[0, 0]) ** 2).mean())
    assert float(loss2) == pytest.approx(expected)


def test_composite_loss_runs_and_respects_weights(data_cfg):
    from configs import load_config

    cfg = load_config("train_graft")
    b, t, f, k = 2, 6, 8, len(data_cfg["stages"])
    outputs = {
        "attack_logit": torch.randn(b, t),
        "stage_logits": torch.randn(b, t, k),
        "evidential_logits": torch.randn(b, t, k),
        "reconstruction": torch.randn(b, t, f),
    }
    targets = {
        "attack": torch.randint(0, 2, (b, t)).float(),
        "stage": torch.randint(0, k, (b, t)),
        "features": torch.randn(b, t, f),
        "valid": torch.ones(b, t, dtype=torch.bool),
    }
    total, parts = L.composite_loss(outputs, targets, cfg, anneal=0.5)
    assert torch.isfinite(total)
    assert set(parts) == {"attack", "stage", "evidential", "reconstruction"}

    # doubling a weight moves the total by exactly that part
    cfg2 = {**cfg, "loss": {**cfg["loss"], "w_attack": cfg["loss"]["w_attack"] * 2}}
    total2, _ = L.composite_loss(outputs, targets, cfg2, anneal=0.5)
    assert float(total2 - total) == pytest.approx(
        cfg["loss"]["w_attack"] * parts["attack"], rel=1e-5
    )
