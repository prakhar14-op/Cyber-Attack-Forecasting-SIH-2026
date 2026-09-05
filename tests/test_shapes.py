"""BUILD_PLAN M7.1: TGN -> GRAFT -> RSSM -> heads dimensions agree for K=1 and K=8.

The stage head must decode to exactly the 7 classes fixed in configs/data.yaml,
for every rollout horizon.
"""

from __future__ import annotations

from tests._stubs import require_attr, require_module

FEATURE_DIM = 32  # arbitrary for the shape test


def test_tgn_graft_rssm_head_dimensions_agree_for_k1_and_k8(data_cfg):
    tgn = require_module("models.tgn", "M5")
    graft = require_module("models.graft", "M6")
    rssm = require_module("models.rssm", "M7")

    require_attr(tgn, "build_model", "M5")
    build_graft = require_attr(graft, "build_model", "M6")
    build_rssm = require_attr(rssm, "build_model", "M7")

    import torch

    from configs import load_config, set_seed

    graft_cfg = load_config("train_graft")
    rssm_cfg = load_config("train_rssm")
    set_seed(graft_cfg["seed"])

    n_stages = len(data_cfg["stages"])
    batch, seq_len = 2, data_cfg["windows"]["max_sequence_windows"]

    encoder = build_graft(graft_cfg, feature_dim=FEATURE_DIM)
    world_model = build_rssm(rssm_cfg, embed_dim=graft_cfg["model"]["d_model"])
    encoder.eval()
    world_model.eval()

    x = torch.randn(batch, seq_len, FEATURE_DIM)

    with torch.no_grad():
        encoded = encoder(x)["embedding"]
        assert encoded.shape == (batch, seq_len, graft_cfg["model"]["d_model"])

        for horizon_k in (1, 8):
            rollout = world_model.filter_then_imagine(encoded, horizon=horizon_k)
            assert rollout["attack_prob"].shape == (batch, horizon_k), (
                f"attack_prob shape wrong for K={horizon_k}"
            )
            assert rollout["stage_logits"].shape == (batch, horizon_k, n_stages), (
                f"stage_logits must decode to the {n_stages} configured stages "
                f"for K={horizon_k}"
            )
