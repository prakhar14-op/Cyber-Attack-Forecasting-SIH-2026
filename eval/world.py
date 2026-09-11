"""World-model evaluation (M7.7): TGN -> GRAFT -> RSSM at horizons k = 1, 4, 8.

    python -m eval.harness --model world     (delegates here)

Pipeline: load the frozen TGN encoder + GRAFT weights persisted by the M6.6
run (artifacts/), compute GRAFT embeddings over per-host 48-window segments,
train the RSSM (reconstruction + KL-balanced + supervised K-step dynamics),
then for every eval row imagine K steps from its filtered state.

Per horizon k: the target row set comes from eval.dataset.assemble_split(
horizon=k) (labels shifted per host, rows without a t+k window dropped) and
the score is the imagined attack probability at step k. Lead time uses
grace = k * stride so a genuine pre-attack forecast alert counts.

M7.6/M7.3 checks on the TRAINED model, recorded in the results json and
enforced loudly: the ensemble band must widen from k=1 to k=8, and the KL
must stay above the free-bits floor (collapse alert).
"""

from __future__ import annotations

import json
import sys

import numpy as np
import pandas as pd
import torch

from configs import load_config, resolve_path, set_seed
from eval import dataset as D
from eval import metrics as M
from eval.harness import _delta_t_for_segments, _segment_split


def _load_frozen_stack(cfg, msg_dim):
    from models import graft as G
    from models import tgn as T

    cfg_t = load_config("train_tgn")
    cfg_g = load_config("train_graft")
    art = resolve_path(cfg["paths"]["artifacts_dir"])

    tgn_path = art / "tgn_encoder.pt"
    graft_path = art / "graft.pt"
    if not tgn_path.exists() or not graft_path.exists():
        raise FileNotFoundError(
            "artifacts/tgn_encoder.pt or graft.pt missing — run "
            "`python -m eval.harness --model tgn_graft` (M6.6) first"
        )
    if cfg_t.get("model", "tgn") != "tgn":
        raise ValueError(
            "artifacts were trained with the TGN encoder; configs/train_tgn.yaml "
            f"now selects '{cfg_t.get('model')}' — refusing a mismatched load"
        )
    tgn_state = torch.load(tgn_path, weights_only=True)
    num_nodes = tgn_state["memory.memory"].shape[0]
    encoder = T.build_model(cfg_t, num_nodes=num_nodes, msg_dim=msg_dim)
    encoder.load_state_dict(tgn_state)
    graft = G.build_model(cfg_g, feature_dim=cfg_t["tgn"]["memory_dim"])
    graft.load_state_dict(torch.load(graft_path, weights_only=True))
    graft.eval()
    return encoder, graft, cfg_t, cfg_g


def _graft_segments(cfg, cfg_t, cfg_g, encoder, graft, split, split_name, msg_scaler, anonymizer):
    """Split -> (E [N,T,d_model] GRAFT embeddings, Ys, Ms, Is, Ss, Dt)."""
    from types import SimpleNamespace

    from data.flow_features import load_split_flows
    from models import tgn as T

    stride = cfg["windows"]["stride_seconds"]
    seg_len = cfg["windows"]["max_sequence_windows"]
    stage_of = {s: i for i, s in enumerate(cfg["stages"])}

    flows = load_split_flows(cfg, split_name)
    events = T.build_events(cfg_t, flows, anonymizer, 0, msg_scaler)
    ro = pd.DataFrame({"host": split.host, "window_start": split.window_start})
    emb = T.snapshot_embeddings(encoder, events, ro, cfg_t)

    proxy = SimpleNamespace(X=emb, y=split.y, host=split.host, window_start=split.window_start)
    Xs, Ys, Ms, Is = _segment_split(proxy, seg_len)
    stage_ids = np.array([stage_of[s] for s in split.stage], dtype=np.int64)
    Ss = np.where(Is >= 0, stage_ids[np.clip(Is, 0, None)], 0)
    Dt = _delta_t_for_segments(split, Is, stride)

    # frozen GRAFT forward -> embeddings E
    E = np.zeros((Xs.shape[0], Xs.shape[1], graft.d_model), dtype=np.float32)
    bs = 128
    with torch.no_grad():
        for i in range(0, Xs.shape[0], bs):
            sl = slice(i, i + bs)
            out = graft(
                torch.tensor(Xs[sl]),
                delta_t=torch.tensor(Dt[sl]),
                padding_mask=~torch.tensor(Ms[sl].astype(bool)),
            )
            E[sl] = out["embedding"].numpy()
    return E, Ys, Ms, Is, Ss, Dt


def _train_rssm(cfg, cfg_r, E, Ys, Ms, Ss, Dt, horizon):
    from models import rssm as R

    set_seed(cfg_r["seed"])
    model = R.build_model(cfg_r, embed_dim=E.shape[2])
    opt = torch.optim.Adam(
        model.parameters(), lr=cfg_r["optim"]["lr"],
        weight_decay=cfg_r["optim"]["weight_decay"],
    )
    w = cfg_r["loss"]
    pos = max(float(Ys[Ms > 0].sum()), 1.0)
    neg = float(Ms.sum() - pos)
    class_w = torch.tensor(neg / pos)

    Et = torch.tensor(E); Yt = torch.tensor(Ys, dtype=torch.float32)
    Mt = torch.tensor(Ms.astype(bool)); St = torch.tensor(Ss); Dtt = torch.tensor(Dt)
    bs = cfg_r["optim"]["batch_size"]
    n = Et.shape[0]
    g = torch.Generator().manual_seed(cfg_r["seed"])
    kl_log = []

    warmup = int(w.get("kl_warmup_epochs", 0))
    model.train()
    for epoch in range(cfg_r["optim"]["epochs"]):
        # KL warm-up: anneal the KL weight 0 -> w_kl over the first `warmup`
        # epochs so the decoder learns to use the latent before KL pressure can
        # collapse it (the v1 failure mode).
        kl_scale = 1.0 if warmup == 0 else min(1.0, (epoch + 1) / warmup)
        perm = torch.randperm(n, generator=g)
        tot, kl_sum, batches = 0.0, 0.0, 0
        for i in range(0, n, bs):
            idx = perm[i : i + bs]
            opt.zero_grad()
            states = model.filter(Et[idx], delta_t=Dtt[idx], valid=Mt[idx], sample=True)
            d = model.decode(states["h"], states["z"])
            recon = model.obs_recon(d)
            v = Mt[idx].to(Et.dtype)
            l_recon = (((recon - Et[idx]) ** 2).mean(-1) * v).sum() / v.sum().clamp(min=1)
            l_kl, raw_kl = R.kl_balanced(states, cfg_r, valid=Mt[idx])
            l_dyn = R.dynamics_loss(
                model, states, Yt[idx], St[idx], Mt[idx], horizon, cfg_r,
                class_weight=class_w, delta_t=Dtt[idx],
            )
            loss = (w["w_reconstruction"] * l_recon
                    + kl_scale * w["w_kl"] * l_kl
                    + w["w_dynamics"] * l_dyn)
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), cfg_r["optim"]["grad_clip"])
            opt.step()
            tot += float(loss.detach()); kl_sum += raw_kl; batches += 1
        # kl_log records the RAW (unclamped, valid-masked) KL — the clamped loss
        # term can never sit below the floor, so alerting on it was dead code.
        kl_epoch = kl_sum / max(batches, 1)
        kl_log.append(kl_epoch)
        print(f"rssm epoch {epoch}: loss {tot / max(batches, 1):.4f} raw_kl {kl_epoch:.3f}",
              flush=True)
        if kl_epoch < cfg_r["loss"]["kl_free_bits"] - 1e-6:
            print(f"WARNING: raw KL {kl_epoch:.4f} below the free-bits floor "
                  f"({cfg_r['loss']['kl_free_bits']}) — posterior collapse", flush=True)
    return model, kl_log


@torch.no_grad()
def _score_all_horizons(model, E, Ms, Is, Dt, horizon, n_rows):
    """Imagined attack prob at every (row, k): filter each segment, imagine K
    from every position, scatter back to flat [n_rows, K]."""
    model.eval()
    flat = np.zeros((n_rows, horizon), dtype=float)
    bs = 64
    for i in range(0, E.shape[0], bs):
        sl = slice(i, i + bs)
        Et = torch.tensor(E[sl]); Mt = torch.tensor(Ms[sl].astype(bool))
        states = model.filter(Et, delta_t=torch.tensor(Dt[sl]), valid=Mt, sample=False)
        b, t = Et.shape[0], Et.shape[1]
        h = states["h"].reshape(b * t, -1)
        z = states["z"].reshape(b * t, -1)
        probs = model.imagine(h, z, horizon, sample=False)["attack_prob"]
        probs = probs.reshape(b, t, horizon).numpy()
        rows = Is[sl].reshape(-1)
        keep = rows >= 0
        flat[rows[keep]] = probs.reshape(-1, horizon)[keep]
    return flat


def evaluate_world(rssm_config: str = "train_rssm") -> dict:
    from data.anonymize import Anonymizer
    from data.flow_features import fit_scaler
    from models import rssm as R

    cfg = load_config("data")
    cfg_eval = load_config("eval")
    cfg_r = load_config(rssm_config)
    horizon = cfg["windows"]["forecast_horizon_windows"]
    stride = cfg["windows"]["stride_seconds"]

    anonymizer = Anonymizer.from_config(cfg)
    msg_scaler = fit_scaler(cfg, split="train")
    encoder, graft, cfg_t, cfg_g = _load_frozen_stack(cfg, msg_dim=len(msg_scaler.mean_))

    train, scaler = D.assemble_split(cfg, "train", horizon=0, fit_scaler=True)
    val, _ = D.assemble_split(cfg, "val", horizon=0, scaler=scaler)
    test, _ = D.assemble_split(cfg, "test", horizon=0, scaler=scaler)

    print("building GRAFT embedding segments (train)...", flush=True)
    E, Ys, Ms, Is, Ss, Dt = _graft_segments(
        cfg, cfg_t, cfg_g, encoder, graft, train, "train", msg_scaler, anonymizer
    )
    model, kl_log = _train_rssm(cfg, cfg_r, E, Ys, Ms, Ss, Dt, horizon)

    result = {"model": "world", "horizons": {}, "kl_per_epoch": kl_log}
    flat_scores = {}
    seg_cache = {}
    for name, split in (("val", val), ("test", test)):
        print(f"scoring {name}...", flush=True)
        Ee, _, Me, Ie, _, De = _graft_segments(
            cfg, cfg_t, cfg_g, encoder, graft, split, name, msg_scaler, anonymizer
        )
        flat_scores[name] = _score_all_horizons(model, Ee, Me, Ie, De, horizon, len(split.y))
        seg_cache[name] = (Ee, Me, De)

    # M7.6 on the TRAINED model: band must widen k=1 -> k=8 (subsampled segments).
    Ee, Me, De = seg_cache["test"]
    sub = slice(0, min(200, Ee.shape[0]))
    roll = model.ensemble_rollout(
        torch.tensor(Ee[sub]), horizon,
        n_samples=cfg_r["rollout"]["ensemble_samples"],
        delta_t=torch.tensor(De[sub]), valid=torch.tensor(Me[sub].astype(bool)),
    )
    band_k1 = float(roll["band"][:, 0].mean())
    band_k8 = float(roll["band"][:, -1].mean())
    result["band_k1"], result["band_k8"] = band_k1, band_k8
    result["band_widens"] = band_k8 > band_k1  # M7.6, recorded — never silent
    print(f"ensemble band: k=1 {band_k1:.4f} -> k={horizon} {band_k8:.4f} "
          f"(widens: {result['band_widens']})", flush=True)
    if not result["band_widens"]:
        print("WARNING: band does NOT widen with horizon on the trained model (M7.6)",
              flush=True)

    # per-horizon metrics: targets from horizon-shifted assembly, scores aligned
    # via (host, window_id). Horizons come from configs/eval.yaml, never a literal.
    for k in cfg_eval["horizons"]:
        result["horizons"][k] = {}
        for name, split0 in (("val", val), ("test", test)):
            split_k, _ = D.assemble_split(cfg, name, horizon=k, scaler=scaler)
            key0 = {(h, int(w)): i for i, (h, w) in enumerate(
                zip(split0.host, (split0.window_start / stride).astype(int)))}
            rows = np.array([
                key0[(h, int(w))] for h, w in zip(
                    split_k.host, (split_k.window_start / stride).astype(int))
            ])
            scores_k = flat_scores[name][rows, k - 1]

            block = {"auroc": M.auroc(split_k.y, scores_k)}
            for budget in cfg_eval["fpr_budgets"]:
                if name == "val":
                    thr = M.threshold_at_fpr(split_k.y, scores_k, budget)
                    result["horizons"][k].setdefault("_thr", {})[budget] = thr
                thr = result["horizons"][k]["_thr"][budget]
                pred = scores_k >= thr
                tp = int(np.count_nonzero(pred & (split_k.y == 1)))
                fp = int(np.count_nonzero(pred & (split_k.y == 0)))
                fn = int(np.count_nonzero(~pred & (split_k.y == 1)))
                tn = int(np.count_nonzero(~pred & (split_k.y == 0)))
                precision = tp / (tp + fp) if (tp + fp) else 0.0
                recall = tp / (tp + fn) if (tp + fn) else 0.0
                f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
                alerts = [
                    {"host": h, "time": t}
                    for h, t, fired in zip(split_k.host, split_k.window_start, pred) if fired
                ]
                lt = M.lead_time(
                    D.attacker_episodes(cfg, name), alerts,
                    grace_seconds=k * stride,
                )
                block[f"fpr_{budget}"] = {
                    "threshold": thr, "precision": precision, "recall": recall,
                    "f1": f1, "fpr": fp / (fp + tn) if (fp + tn) else 0.0,
                    "lead_time_median": lt.median,
                    "lead_time_iqr": [lt.iqr_low, lt.iqr_high],
                    "per_episode_seconds": list(lt.per_episode_seconds),
                    "episodes_detected": lt.n_detected,
                    "episodes_total": lt.n_episodes,
                }
            result["horizons"][k][name] = block
        result["horizons"][k].pop("_thr", None)

    return result


def main(rssm_config: str = "train_rssm", out_name: str = "world") -> int:
    result = evaluate_world(rssm_config=rssm_config)
    result["rssm_config"] = rssm_config
    cfg_eval = load_config("eval")
    out_dir = resolve_path(cfg_eval["paths"]["results_dir"])
    out_dir.mkdir(parents=True, exist_ok=True)
    out = out_dir / f"{out_name}.json"
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2)

    for k, block in result["horizons"].items():
        t = block["test"]
        pt = t.get("fpr_0.01", {})
        print(f"world k={k}: test AUROC {t['auroc']:.3f} F1@1%FPR {pt.get('f1', 0):.3f} "
              f"lead {pt.get('lead_time_median', 0):.0f}s "
              f"({pt.get('episodes_detected')}/{pt.get('episodes_total')})")
    print(f"-> {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
