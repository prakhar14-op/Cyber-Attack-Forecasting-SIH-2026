"""The most important test in the repo (BUILD_PLAN M6.1).

Perturbing windows t+1..T must leave the prediction at t BIT-IDENTICAL. If this
fails after M6, the encoder is not causal and every reported lead time is invalid.
"""

from __future__ import annotations

from tests._stubs import require_attr, require_module

FEATURE_DIM = 32  # arbitrary for the property test; real dim comes from feature_names.json


def test_perturbing_future_windows_leaves_past_predictions_bit_identical(data_cfg):
    graft = require_module("models.graft", "M6")
    build_model = require_attr(graft, "build_model", "M6")

    import torch

    from configs import load_config, set_seed

    cfg = load_config("train_graft")
    set_seed(cfg["seed"])

    model = build_model(cfg, feature_dim=FEATURE_DIM)
    model.eval()

    batch, seq_len = 2, data_cfg["windows"]["max_sequence_windows"]
    x = torch.randn(batch, seq_len, FEATURE_DIM)
    t = seq_len // 2

    x_future_perturbed = x.clone()
    x_future_perturbed[:, t + 1 :, :] += 100.0 * torch.randn(
        batch, seq_len - t - 1, FEATURE_DIM
    )

    with torch.no_grad():
        base = model(x)
        perturbed = model(x_future_perturbed)

    for head in ("attack_prob", "stage_logits"):
        assert head in base, f"model output missing '{head}' head"
        # bit-identical up to and including t — torch.equal, not allclose
        assert torch.equal(base[head][:, : t + 1], perturbed[head][:, : t + 1]), (
            f"'{head}' at positions <= t changed when windows t+1..T were perturbed: "
            "the encoder attends to the future"
        )
