"""Loss functions for the GRAFT encoder and the RSSM world model (M6.3–M6.5).

- Dirichlet evidential loss (Sensoy et al. 2018) — the PS's uncertainty
  requirement. alpha = softplus(logits) + 1; total evidence S = sum(alpha);
  predictive uncertainty = K / S. Loss = expected cross-entropy under the
  Dirichlet + an ANNEALED KL(Dir(alpha_misleading) || Dir(1)) that burns away
  evidence for wrong classes. Never Normal-Inverse-Gamma (CLAUDE.md).
- Benign-only masked reconstruction (M6.4): the OOD signal. Must stay finite
  on an all-attack batch (denominator clamped) — tested.
- Composite loss with config-driven weights and class weighting (M6.5).
"""

from __future__ import annotations

import torch
import torch.nn.functional as F


def dirichlet_alpha(logits: torch.Tensor) -> torch.Tensor:
    """Evidence parameterisation: alpha = softplus(logits) + 1 (alpha > 1 floor)."""
    return F.softplus(logits) + 1.0


def dirichlet_uncertainty(alpha: torch.Tensor) -> torch.Tensor:
    """Predictive uncertainty u = K / S in (0, 1]; 1 = total ignorance."""
    k = alpha.size(-1)
    return k / alpha.sum(dim=-1)


def _kl_dirichlet_to_uniform(alpha: torch.Tensor) -> torch.Tensor:
    """KL( Dir(alpha) || Dir(1,...,1) ), elementwise over the batch dims."""
    k = alpha.size(-1)
    s = alpha.sum(dim=-1)
    ones = torch.ones_like(alpha)
    return (
        torch.lgamma(s)
        - torch.lgamma(alpha).sum(dim=-1)
        - torch.lgamma(ones.sum(dim=-1))  # log B(1) denominator = lgamma(K)
        + ((alpha - 1.0) * (torch.digamma(alpha) - torch.digamma(s.unsqueeze(-1)))).sum(dim=-1)
    )


def evidential_loss(
    logits: torch.Tensor,
    target: torch.Tensor,
    anneal: float,
    valid_mask: torch.Tensor | None = None,
) -> torch.Tensor:
    """Sensoy et al. expected-CE + annealed KL, masked mean.

    logits [.., K]; target [..] long class ids; anneal in [0, 1];
    valid_mask [..] bool (True = count this position).
    """
    alpha = dirichlet_alpha(logits)
    s = alpha.sum(dim=-1, keepdim=True)
    y = F.one_hot(target, num_classes=alpha.size(-1)).to(alpha.dtype)

    expected_ce = (y * (torch.digamma(s) - torch.digamma(alpha))).sum(dim=-1)

    # Misleading evidence: keep the true class at alpha=1, shrink the rest.
    alpha_tilde = y + (1.0 - y) * alpha
    kl = _kl_dirichlet_to_uniform(alpha_tilde)

    per_pos = expected_ce + anneal * kl
    if valid_mask is None:
        return per_pos.mean()
    denom = valid_mask.sum().clamp(min=1)
    return (per_pos * valid_mask).sum() / denom


def benign_reconstruction_loss(
    reconstruction: torch.Tensor,
    features: torch.Tensor,
    benign_mask: torch.Tensor,
) -> torch.Tensor:
    """MSE over BENIGN, non-padding positions only (the OOD signal, M6.4).

    benign_mask [..] bool (True = benign AND real). An all-attack batch has an
    empty mask; the clamped denominator keeps the loss finite (0), never NaN.
    """
    per_pos = ((reconstruction - features) ** 2).mean(dim=-1)
    denom = benign_mask.sum().clamp(min=1)
    return (per_pos * benign_mask).sum() / denom


def composite_loss(
    outputs: dict,
    targets: dict,
    cfg: dict,
    anneal: float,
    class_weights: torch.Tensor | None = None,
) -> tuple[torch.Tensor, dict]:
    """Weighted sum of the four heads' losses (weights from configs, M6.5).

    outputs: attack_logit [B,T], stage_logits [B,T,K], evidential_logits
    [B,T,K], reconstruction [B,T,F].
    targets: attack [B,T] float {0,1}, stage [B,T] long, features [B,T,F],
    valid [B,T] bool (True = real window, not padding).
    """
    w = cfg["loss"]
    valid = targets["valid"]
    denom = valid.sum().clamp(min=1)

    pos_weight = None
    if class_weights is not None:
        pos_weight = class_weights  # scalar tensor: benign/attack ratio
    attack_bce = F.binary_cross_entropy_with_logits(
        outputs["attack_logit"], targets["attack"], reduction="none",
        pos_weight=pos_weight,
    )
    l_attack = (attack_bce * valid).sum() / denom

    stage_ce = F.cross_entropy(
        outputs["stage_logits"].movedim(-1, 1), targets["stage"], reduction="none"
    )
    l_stage = (stage_ce * valid).sum() / denom

    l_evid = evidential_loss(
        outputs["evidential_logits"], targets["stage"], anneal, valid_mask=valid
    )

    benign_mask = valid & (targets["attack"] < 0.5)
    l_recon = benign_reconstruction_loss(
        outputs["reconstruction"], targets["features"], benign_mask
    )

    total = (
        w["w_attack"] * l_attack
        + w["w_stage"] * l_stage
        + w["w_evidential"] * l_evid
        + w["w_reconstruction"] * l_recon
    )
    parts = {
        "attack": float(l_attack.detach()),
        "stage": float(l_stage.detach()),
        "evidential": float(l_evid.detach()),
        "reconstruction": float(l_recon.detach()),
    }
    return total, parts
