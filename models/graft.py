"""GRAFT encoder (M6): a CAUSAL transformer over per-host window sequences.

The encoder is causal — position t must not attend to t+1 (CLAUDE.md:
"Bidirectional is a bug, not a choice"). Enforced with
generate_square_subsequent_mask + src_key_padding_mask on every
TransformerEncoder call, and pinned bit-identically by
tests/test_no_future_leakage.py, the most important test in the repo.

Time2Vec on the inter-window gap replaces sinusoidal position encoding (M6.2):
host sequences have irregular gaps (inactive windows are absent), and the gap
itself is signal (a scan burst vs an idle host).

Heads (M6.3/6.4): attack logit, 7-class stage logits, Dirichlet evidential
logits (alpha = softplus+1 downstream in models.losses), and a reconstruction
head trained on benign windows only (the OOD signal).
"""

from __future__ import annotations

import torch
from torch import nn

from configs import set_seed


class Time2Vec(nn.Module):
    """Time2Vec (Kazemi et al.): one linear + (dim-1) periodic components."""

    def __init__(self, dim: int):
        super().__init__()
        self.w0 = nn.Linear(1, 1)
        self.wp = nn.Linear(1, dim - 1)

    def forward(self, delta_t: torch.Tensor) -> torch.Tensor:
        """delta_t [B, T] (gap to the previous window, in stride units) -> [B, T, dim]."""
        dt = delta_t.unsqueeze(-1).to(self.w0.weight.dtype)
        return torch.cat([self.w0(dt), torch.sin(self.wp(dt))], dim=-1)


class GRAFT(nn.Module):
    def __init__(self, cfg: dict, feature_dim: int):
        super().__init__()
        p = cfg["model"]
        if not p.get("causal", True):
            raise ValueError("GRAFT must be causal — bidirectional is a bug (CLAUDE.md)")
        d = p["d_model"]
        self.d_model = d
        n_stages = cfg["heads"]["stage_classes"]

        self.input_proj = nn.Linear(feature_dim, d)
        self.use_time2vec = bool(p.get("use_time2vec", True))  # M6.2 ablation switch
        # Optional gap clamp (stride units). Time2Vec's linear component grows
        # unbounded with delta_t: measured at init, its additive term is ~0.7x
        # the feature projection at gap<=10 but 3.4x at gap 100 and 33x at gap
        # 1000 — and ~2% of real gaps exceed 100 (diagnostics/delta_t_gap_stats
        # .json). Clamping at ~p95 of real gaps keeps the time term informative
        # without letting idle-gap outliers swamp the feature signal.
        self.delta_t_clamp = p.get("delta_t_clamp")
        self.time2vec = Time2Vec(p["time2vec_dim"])
        self.time_proj = nn.Linear(p["time2vec_dim"], d)

        layer = nn.TransformerEncoderLayer(
            d_model=d,
            nhead=p["heads"],
            dim_feedforward=p["ffn_dim"],
            dropout=p["dropout"],
            batch_first=True,
        )
        self.encoder = nn.TransformerEncoder(
            layer, num_layers=p["layers"], enable_nested_tensor=False
        )

        self.attack_head = nn.Linear(d, 1)
        self.stage_head = nn.Linear(d, n_stages)
        self.evidential_head = nn.Linear(d, n_stages)
        self.reconstruction_head = nn.Linear(d, feature_dim)

    def forward(
        self,
        x: torch.Tensor,
        delta_t: torch.Tensor | None = None,
        padding_mask: torch.Tensor | None = None,
    ) -> dict:
        """x [B, T, F]; delta_t [B, T] (defaults to 1 = regular stride);
        padding_mask [B, T] bool, True = PAD (torch convention)."""
        b, t, _ = x.shape
        if delta_t is None:
            delta_t = torch.ones(b, t, device=x.device)

        h = self.input_proj(x)
        if self.use_time2vec:
            if self.delta_t_clamp is not None:
                delta_t = delta_t.clamp(max=float(self.delta_t_clamp))
            h = h + self.time_proj(self.time2vec(delta_t))

        # Bool causal mask (True = masked = future), same dtype as the padding
        # mask; equivalent to generate_square_subsequent_mask's -inf float form.
        causal = torch.triu(
            torch.ones(t, t, dtype=torch.bool, device=x.device), diagonal=1
        )
        z = self.encoder(h, mask=causal, src_key_padding_mask=padding_mask)
        if padding_mask is not None:
            # Zero pad positions so any degenerate value there (an all-masked
            # attention row yields NaN) can never poison later consumers.
            z = torch.where(padding_mask.unsqueeze(-1), torch.zeros_like(z), z)

        return {
            "embedding": z,
            "attack_logit": self.attack_head(z).squeeze(-1),
            "attack_prob": torch.sigmoid(self.attack_head(z).squeeze(-1)),
            "stage_logits": self.stage_head(z),
            "evidential_logits": self.evidential_head(z),
            "reconstruction": self.reconstruction_head(z),
        }


def build_model(cfg: dict, feature_dim: int) -> GRAFT:
    """The M6 model-construction API (tests/test_no_future_leakage, test_shapes)."""
    set_seed(cfg["seed"])
    return GRAFT(cfg, feature_dim)
