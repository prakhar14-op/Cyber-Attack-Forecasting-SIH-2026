"""RSSM world model (M7) — the actual "world model" deliverable.

Filters a posterior over the OBSERVED window-embedding sequence (GRAFT output),
then rolls the PRIOR forward K steps ("filter-then-imagine", M7.2 — the rollout
never starts from zeros: it starts from the filtered state, and a test pins that
the state depends on the inputs). Heads are applied to the DECODED state
decode(h, z), never to raw h (M7.1).

Tier 1 (`model.tier: 1`): deterministic latent (tanh MLP), no KL.
Tier 2 (`model.tier: 2`): Gaussian latent with reparameterised sampling,
KL-balanced posterior/prior loss with free bits (M7.3); the ensemble rollout
(M7.6) samples the prior N times — the band is the forecast uncertainty and
its widening with horizon is asserted by a test.

Missing-window guard (M7.5): the transition consumes the inter-window gap
delta_t, and padding positions update the state with the PRIOR (no fabricated
observation) — a gap never crashes and never invents data.
"""

from __future__ import annotations

import torch
import torch.nn.functional as F
from torch import nn

from configs import load_config, set_seed


def _mlp(inp: int, hidden: int, out: int) -> nn.Sequential:
    return nn.Sequential(nn.Linear(inp, hidden), nn.ELU(), nn.Linear(hidden, out))


class RSSM(nn.Module):
    def __init__(self, cfg: dict, embed_dim: int, n_stages: int):
        super().__init__()
        p = cfg["model"]
        self.tier = int(p["tier"])
        self.deter_dim = p["deter_dim"]
        self.stoch_dim = p["stoch_dim"]
        hidden = p["hidden_dim"]
        dec_dim = p["decoder_dim"]

        # transition h_t = GRU([z_{t-1}, log1p(delta_t)], h_{t-1})
        self.gru = nn.GRUCell(self.stoch_dim + 1, self.deter_dim)
        out_mult = 2 if self.tier == 2 else 1
        self.prior_net = _mlp(self.deter_dim, hidden, out_mult * self.stoch_dim)
        self.post_net = _mlp(self.deter_dim + embed_dim, hidden, out_mult * self.stoch_dim)

        # heads act on the DECODED state, never raw h (M7.1)
        self.decoder = _mlp(self.deter_dim + self.stoch_dim, hidden, dec_dim)
        self.obs_recon = nn.Linear(dec_dim, embed_dim)
        self.attack_head = nn.Linear(dec_dim, 1)
        self.stage_head = nn.Linear(dec_dim, n_stages)

        self.min_std = 0.1

    # -- latent helpers -----------------------------------------------------

    def _dist_params(self, raw: torch.Tensor):
        if self.tier == 1:
            return torch.tanh(raw), None
        mean, std_raw = raw.chunk(2, dim=-1)
        return mean, F.softplus(std_raw) + self.min_std

    def _sample(self, mean, std, sample: bool):
        if self.tier == 1 or std is None:
            return mean
        if not sample:
            return mean
        return mean + std * torch.randn_like(std)

    def decode(self, h: torch.Tensor, z: torch.Tensor) -> torch.Tensor:
        return self.decoder(torch.cat([h, z], dim=-1))

    def _heads(self, d: torch.Tensor) -> dict:
        return {
            "attack_logit": self.attack_head(d).squeeze(-1),
            "attack_prob": torch.sigmoid(self.attack_head(d).squeeze(-1)),
            "stage_logits": self.stage_head(d),
            "obs_recon": self.obs_recon(d),
        }

    # -- filtering over observed windows ------------------------------------

    def filter(
        self,
        e: torch.Tensor,
        delta_t: torch.Tensor | None = None,
        valid: torch.Tensor | None = None,
        sample: bool = True,
    ) -> dict:
        """Posterior filtering over e [B, T, D].

        valid [B, T] bool (False = padding: state advances with the PRIOR —
        M7.5's no-fabricated-observation rule). Returns per-step tensors
        h, z [B, T, ·] plus the prior/posterior params for the KL loss.
        """
        b, t, _ = e.shape
        device = e.device
        if delta_t is None:
            delta_t = torch.ones(b, t, device=device)
        if valid is None:
            valid = torch.ones(b, t, dtype=torch.bool, device=device)

        h = torch.zeros(b, self.deter_dim, device=device)
        z = torch.zeros(b, self.stoch_dim, device=device)
        hs, zs = [], []
        post_means, post_stds, prior_means, prior_stds = [], [], [], []

        for step in range(t):
            gru_in = torch.cat([z, torch.log1p(delta_t[:, step : step + 1])], dim=-1)
            h = self.gru(gru_in, h)

            prior_mean, prior_std = self._dist_params(self.prior_net(h))
            post_mean, post_std = self._dist_params(
                self.post_net(torch.cat([h, e[:, step]], dim=-1))
            )
            # padding: no observation — the prior drives the state (M7.5)
            v = valid[:, step].unsqueeze(-1).to(e.dtype)
            mean = v * post_mean + (1 - v) * prior_mean
            std = None
            if self.tier == 2:
                std = v * post_std + (1 - v) * prior_std
            z = self._sample(mean, std, sample)

            hs.append(h)
            zs.append(z)
            post_means.append(mean)
            prior_means.append(prior_mean)
            if self.tier == 2:
                post_stds.append(std)
                prior_stds.append(prior_std)

        out = {
            "h": torch.stack(hs, dim=1),
            "z": torch.stack(zs, dim=1),
            "post_mean": torch.stack(post_means, dim=1),
            "prior_mean": torch.stack(prior_means, dim=1),
        }
        if self.tier == 2:
            out["post_std"] = torch.stack(post_stds, dim=1)
            out["prior_std"] = torch.stack(prior_stds, dim=1)
        return out

    # -- imagination (prior rollout) ----------------------------------------

    def imagine(
        self, h: torch.Tensor, z: torch.Tensor, horizon: int, sample: bool = True
    ) -> dict:
        """Roll the PRIOR forward `horizon` steps from (h, z) [N, ·].

        Returns stacked per-step head outputs [N, horizon, ·]. Heads decode
        (h_k, z_k) — the imagined future states, never raw h.
        """
        outs = {"attack_logit": [], "attack_prob": [], "stage_logits": []}
        dt = torch.ones(h.size(0), 1, device=h.device)
        for _ in range(horizon):
            h = self.gru(torch.cat([z, torch.log1p(dt)], dim=-1), h)
            mean, std = self._dist_params(self.prior_net(h))
            z = self._sample(mean, std, sample)
            head = self._heads(self.decode(h, z))
            for k in outs:
                outs[k].append(head[k])
        return {k: torch.stack(v, dim=1) for k, v in outs.items()}

    def filter_then_imagine(
        self,
        e: torch.Tensor,
        horizon: int,
        delta_t: torch.Tensor | None = None,
        valid: torch.Tensor | None = None,
        sample: bool = False,
    ) -> dict:
        """The M7.2 contract: filter all observed windows, then imagine from the
        FILTERED terminal state (never zeros). With right-padded sequences the
        terminal state is the LAST VALID position's state, not the last slot.
        Returns [B, horizon, ·] heads."""
        states = self.filter(e, delta_t=delta_t, valid=valid, sample=sample)
        if valid is None:
            h_t, z_t = states["h"][:, -1], states["z"][:, -1]
        else:
            last = (valid.long().cumsum(dim=1).argmax(dim=1)).clamp(min=0)
            idx = last.view(-1, 1, 1)
            h_t = states["h"].gather(1, idx.expand(-1, 1, states["h"].size(-1))).squeeze(1)
            z_t = states["z"].gather(1, idx.expand(-1, 1, states["z"].size(-1))).squeeze(1)
        return self.imagine(h_t, z_t, horizon, sample=sample)

    @torch.no_grad()
    def ensemble_rollout(
        self, e: torch.Tensor, horizon: int, n_samples: int, **kw
    ) -> dict:
        """M7.6: N stochastic rollouts -> mean, band (std) and per-step
        disagreement (the second OOD signal). Diagnostic only — no autograd."""
        probs = torch.stack(
            [
                self.filter_then_imagine(e, horizon, sample=True, **kw)["attack_prob"]
                for _ in range(n_samples)
            ],
            dim=0,
        )  # [N, B, K]
        return {
            "mean": probs.mean(dim=0),
            "band": probs.std(dim=0),
            "samples": probs,
        }


def build_model(cfg: dict, embed_dim: int) -> RSSM:
    """The M7 model-construction API (tests/test_shapes, the harness)."""
    set_seed(cfg["seed"])
    n_stages = len(load_config("data")["stages"])
    return RSSM(cfg, embed_dim=embed_dim, n_stages=n_stages)


# ---------------------------------------------------------------------------
# Losses (M7.3 / M7.4)
# ---------------------------------------------------------------------------


def kl_balanced(
    states: dict, cfg: dict, valid: torch.Tensor | None = None
) -> tuple[torch.Tensor, float]:
    """KL(q || p) with Dreamer-style balancing and free bits (tier 2 only).

    Returns (loss_term, raw_kl): the loss term is clamped to the free-bits
    floor; raw_kl is the UNCLAMPED valid-masked mean KL(q||p) — the quantity
    the posterior-collapse alert must watch (comparing the clamped value to
    its own floor is dead code, audit finding). Padding positions are excluded
    from both (their blended posterior equals the prior, diluting the mean).
    """
    if "post_std" not in states:
        return torch.zeros((), device=states["h"].device), 0.0
    balance = cfg["loss"]["kl_balance"]
    free = cfg["loss"]["kl_free_bits"]

    q = torch.distributions.Normal(states["post_mean"], states["post_std"])
    p = torch.distributions.Normal(states["prior_mean"], states["prior_std"])
    q_sg = torch.distributions.Normal(states["post_mean"].detach(), states["post_std"].detach())
    p_sg = torch.distributions.Normal(states["prior_mean"].detach(), states["prior_std"].detach())

    def _masked_mean(kl_bt: torch.Tensor) -> torch.Tensor:
        if valid is None:
            return kl_bt.mean()
        v = valid.to(kl_bt.dtype)
        return (kl_bt * v).sum() / v.sum().clamp(min=1)

    kl_lhs = _masked_mean(torch.distributions.kl_divergence(q_sg, p).sum(-1))
    kl_rhs = _masked_mean(torch.distributions.kl_divergence(q, p_sg).sum(-1))
    kl = balance * kl_lhs + (1.0 - balance) * kl_rhs
    raw_kl = float(_masked_mean(torch.distributions.kl_divergence(q, p).sum(-1)).detach())
    return torch.clamp(kl, min=free), raw_kl


def dynamics_loss(
    model: RSSM,
    states: dict,
    attack: torch.Tensor,
    stage: torch.Tensor,
    valid: torch.Tensor,
    horizon: int,
    cfg: dict,
    class_weight: torch.Tensor | None = None,
    delta_t: torch.Tensor | None = None,
) -> torch.Tensor:
    """Supervised K-step dynamics (M7.4): imagine k=1..K from EVERY position t
    with the prior, decode, and match the label EXACTLY k strides ahead,
    discounted 0.9^k.

    Segments hold only a host's PRESENT windows, so row t+k is not always the
    window k strides after row t (audit finding: training on next-row targets
    while eval grades wall-clock t+k diverges on gapped hosts). delta_t [B, T]
    carries the true inter-window gaps; a (t, t+k-row) pair is supervised only
    when its cumulative gap is exactly k — matching both imagine()'s dt=1
    steps and the eval convention. Without delta_t, gaps of 1 are assumed.
    """
    b, t = attack.shape
    discount = cfg["loss"]["dynamics_discount"]

    if delta_t is None:
        pos = torch.arange(t, device=attack.device, dtype=torch.float32).expand(b, t)
    else:
        # position of row j = sum of gaps AFTER the segment's first row
        # (delta_t[:, 0] is the pre-segment gap — irrelevant to intra-segment
        # differences, so zero it in the cumulative sum).
        gaps = delta_t.clone().to(torch.float32)
        gaps[:, 0] = 0.0
        pos = gaps.cumsum(dim=1)

    h = states["h"].reshape(b * t, -1)
    z = states["z"].reshape(b * t, -1)
    rolled = model.imagine(h, z, horizon, sample=self_sample(model))
    attack_logit = rolled["attack_logit"].reshape(b, t, horizon)
    stage_logits = rolled["stage_logits"].reshape(b, t, horizon, -1)

    total = torch.zeros((), device=attack.device)
    norm = torch.zeros((), device=attack.device)
    for k in range(1, horizon + 1):
        if t - k <= 0:
            break
        tgt_a = attack[:, k:]
        tgt_s = stage[:, k:]
        stride_exact = (pos[:, k:] - pos[:, : t - k]) == float(k)
        v = (valid[:, k:] & valid[:, : t - k] & stride_exact).to(attack.dtype)
        la = F.binary_cross_entropy_with_logits(
            attack_logit[:, : t - k, k - 1], tgt_a, reduction="none",
            pos_weight=class_weight,
        )
        ls = F.cross_entropy(
            stage_logits[:, : t - k, k - 1].movedim(-1, 1), tgt_s, reduction="none"
        )
        w = discount ** k
        denom = v.sum()
        if float(denom) == 0.0:
            continue  # no stride-exact pairs at this k — skip, don't dilute
        total = total + w * ((la + ls) * v).sum() / denom
        norm = norm + w
    return total / norm.clamp(min=1e-8)


def self_sample(model: RSSM) -> bool:
    return model.tier == 2
