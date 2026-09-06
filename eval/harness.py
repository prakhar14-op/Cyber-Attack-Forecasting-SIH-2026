"""Evaluation harness (M4.4): one command runs any model over the split.

    python -m eval.harness --model lr
    python -m eval.harness --model xgb --holdout-family dos

Trains on the train split, chooses the operating threshold from the VALIDATION
benign host-windows at each FPR budget, and reports on the TEST split:
F1/precision/recall at each budget, AUROC, ECE, median lead time (with IQR),
and alerts/host-day. Writes results/<name>.json — the ablation table (M4.5) is built
from those, never hand-typed.

Anti-leakage is structural: the scaler is fit on train only (eval.dataset), the
threshold is fit on val (not test), and lead time counts undetected episodes as 0.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import numpy as np

from configs import load_config, resolve_path, set_seed
from eval import dataset as D
from eval import metrics as M
from models import baselines


def _dump_scores(cfg_eval, model_name, holdout, evals, scores) -> None:
    """Phase-0 instrumentation: persist per-(host, window) val/test scores so the
    threshold-transfer diagnosis and Phase-1 calibration can work on the real
    score arrays without re-running the model. Written under results/scores/
    (gitignored, offline)."""
    out = resolve_path(cfg_eval["paths"]["results_dir"]) / "scores"
    out.mkdir(parents=True, exist_ok=True)
    suffix = f"_holdout-{holdout}" if holdout else ""
    payload = {}
    for name, split in evals.items():
        payload[f"{name}_y"] = np.asarray(split.y)
        payload[f"{name}_score"] = np.asarray(scores[name], dtype=float)
        payload[f"{name}_host"] = np.asarray(split.host).astype(str)
        payload[f"{name}_ws"] = np.asarray(split.window_start, dtype=float)
    np.savez(out / f"{model_name}{suffix}.npz", **payload)


def _dump_curve(name: str, curves: dict) -> None:
    """Phase-0 instrumentation: persist per-epoch training loss curves so under-
    vs over-fitting is diagnosable from artefacts, not just stdout."""
    out = resolve_path(load_config("eval")["paths"]["results_dir"]) / "curves"
    out.mkdir(parents=True, exist_ok=True)
    (out / f"{name}.json").write_text(json.dumps(curves, indent=2), encoding="utf-8")


def _flat_scores(model_name, cfg_b, train, evals):
    """Train a per-window model (lr/xgb) and score each eval Split."""
    model = baselines.build_model(model_name, cfg_b).fit(train.X, train.y)
    return {name: model.predict_proba(s.X) for name, s in evals.items()}


def _segment_split(split, seg_len):
    """Chunk each host's time-ordered windows into consecutive seg_len segments.

    Returns X [N, seg_len, F], Y [N, seg_len], mask [N, seg_len] (1 = REAL —
    note callers must invert with ~ for torch's True=PAD src_key_padding_mask),
    and flat_index [N, seg_len] mapping each position back to its row in
    `split` (-1 for padding). Segments are RIGHT-padded (pads at the tail,
    matching windows.pad_sequence): position 0 must always be a real window,
    because a left-pad makes the first causal query's key set fully masked and
    its NaN softmax poisons real positions in deeper layers (commit 90db486).
    """
    feat_dim = split.X.shape[1]
    order = np.lexsort((split.window_start, split.host))
    host_sorted = split.host[order]

    Xs, Ys, Ms, Is = [], [], [], []
    start = 0
    n = len(order)
    while start < n:
        end = start
        while end < n and host_sorted[end] == host_sorted[start]:
            end += 1
        rows = order[start:end]  # this host's rows, time-ordered
        for c in range(0, len(rows), seg_len):
            seg_rows = rows[c : c + seg_len]
            pad = seg_len - len(seg_rows)
            xrow = split.X[seg_rows]
            yrow = split.y[seg_rows]
            if pad:
                # RIGHT-pad: position 0 is always a real window. Left-padding
                # makes the first query's key set fully masked (causal ∩
                # padding), whose softmax NaN then poisons real positions in
                # deeper attention layers — observed on real data (nan ECE).
                xrow = np.vstack([xrow, np.zeros((pad, feat_dim), np.float32)])
                yrow = np.concatenate([yrow, np.zeros(pad, np.int8)])
                idx = np.concatenate([seg_rows, np.full(pad, -1, np.int64)])
                m = np.concatenate([np.ones(len(seg_rows), np.float32), np.zeros(pad, np.float32)])
            else:
                idx = seg_rows.astype(np.int64)
                m = np.ones(seg_len, np.float32)
            Xs.append(xrow); Ys.append(yrow); Ms.append(m); Is.append(idx)
        start = end
    return (np.stack(Xs), np.stack(Ys), np.stack(Ms), np.stack(Is))


def _lstm_scores(cfg, cfg_b, train_split, eval_splits):
    """Train the LSTM on 48-window segments (many-to-many); score per window."""
    seg_len = cfg["windows"]["max_sequence_windows"]
    Xtr, Ytr, Mtr, _ = _segment_split(train_split, seg_len)
    model = baselines.build_model("lstm", cfg_b).fit(Xtr, Ytr, Mtr)

    scores = {}
    for name, split in eval_splits.items():
        Xe, _, Me, Ie = _segment_split(split, seg_len)
        probs = model.predict_proba_segments(Xe)  # [N, seg_len]
        flat = np.zeros(len(split.y), dtype=float)
        rows = Ie.reshape(-1)
        vals = probs.reshape(-1)
        real = rows >= 0
        flat[rows[real]] = vals[real]
        scores[name] = flat
    return scores


def _tgn_scores(cfg, train_split, eval_splits):
    """M5.5: TGN memory embeddings + linear head, scored per (host, window).

    Link-prediction training on TRAIN events only; per-split snapshot passes
    start from a fresh memory (M5.3); the linear head is fit on train snapshot
    embeddings (all attack + a benign subsample) and applied everywhere.
    """
    import pandas as pd
    from sklearn.linear_model import LogisticRegression

    from data.anonymize import Anonymizer
    from data.flow_features import fit_scaler, load_split_flows
    from models import tgn as T

    cfg_t = load_config("train_tgn")
    set_seed(cfg_t["seed"])
    anonymizer = Anonymizer.from_config(cfg)
    msg_scaler = fit_scaler(cfg, split="train")  # train-only, deterministic

    train_flows = load_split_flows(cfg, "train")
    encoder = T.build_model(
        cfg_t,
        num_nodes=pd.concat([train_flows["src_ip"], train_flows["dst_ip"]]).nunique(),
        msg_dim=len(msg_scaler.mean_),
    )

    # per-epoch node permutation: rebuild events (ids) each epoch; memory resets
    # inside train_link_pred at every epoch start.
    tgn_curve = []
    for epoch in range(cfg_t["link_pred"]["epochs"]):
        events = T.build_events(cfg_t, train_flows, anonymizer, epoch, msg_scaler)
        one_epoch = {**cfg_t, "link_pred": {**cfg_t["link_pred"], "epochs": 1}}
        losses = T.train_link_pred(encoder, events, one_epoch)
        tgn_curve.append(float(losses[0]))
        print(f"tgn link-pred epoch {epoch}: loss {losses[0]:.4f}", flush=True)
    _dump_curve("tgn", {"tgn_link_pred": tgn_curve})

    # ---- head fit on train snapshot embeddings (subsampled benign) ----
    rng = np.random.RandomState(cfg_t["seed"])
    attack_idx = np.flatnonzero(train_split.y == 1)
    benign_idx = np.flatnonzero(train_split.y == 0)
    take = min(int(cfg_t["head"]["benign_subsample"]), len(benign_idx))
    sub = np.concatenate([attack_idx, rng.choice(benign_idx, take, replace=False)])
    readouts = pd.DataFrame(
        {"host": train_split.host[sub], "window_start": train_split.window_start[sub]}
    )
    train_events = T.build_events(cfg_t, train_flows, anonymizer, 0, msg_scaler)
    emb_train = T.snapshot_embeddings(encoder, train_events, readouts, cfg_t)
    head = LogisticRegression(
        C=cfg_t["head"]["C"], max_iter=cfg_t["head"]["max_iter"], class_weight="balanced"
    ).fit(emb_train, train_split.y[sub])

    # ---- fresh-memory snapshot + score per eval split ----
    scores = {}
    for name, split in eval_splits.items():
        flows = load_split_flows(cfg, name)
        events = T.build_events(cfg_t, flows, anonymizer, 0, msg_scaler)
        ro = pd.DataFrame({"host": split.host, "window_start": split.window_start})
        emb = T.snapshot_embeddings(encoder, events, ro, cfg_t)
        scores[name] = head.predict_proba(emb)[:, 1]
    return scores


def _delta_t_for_segments(split, index_map, stride):
    """Per-position gap (in strides) to the host's TRUE previous window.

    index_map [N, T] maps segment positions to split rows (-1 = pad). Gaps are
    computed on the full per-host row series BEFORE chunking, so a
    segment-initial position carries its real gap to the previous chunk's last
    window (the audit caught the old fabricated gap=1 there — those positions
    are real windows, not masked). A host's very first window and pad
    positions get gap 1.
    """
    order = np.lexsort((split.window_start, split.host))
    row_delta = np.ones(len(split.window_start), dtype=np.float32)
    ws_sorted = split.window_start[order]
    same_host = split.host[order][1:] == split.host[order][:-1]
    gaps = (ws_sorted[1:] - ws_sorted[:-1]) / stride
    good = same_host & (gaps > 0)
    row_delta[order[1:][good]] = gaps[good].astype(np.float32)

    delta = np.ones_like(index_map, dtype=np.float32)
    real = index_map >= 0
    delta[real] = row_delta[index_map[real]]
    return delta


def _tgn_graft_scores(cfg, train_split, eval_splits, ablate_time2vec: bool = False):
    """M6.6: GRAFT (causal transformer) over TGN embedding sequences, horizon 0.

    TGN is trained exactly as in the M5 row (link-pred, train events only,
    per-epoch id permutation); its per-(host, window) memory embeddings become
    GRAFT's input sequences. GRAFT trains with the composite loss (attack +
    stage + annealed Dirichlet evidential + benign-only reconstruction).
    Trained weights are persisted to artifacts/ for M7.
    """
    import pandas as pd
    import torch

    from data.anonymize import Anonymizer
    from data.flow_features import fit_scaler, load_split_flows
    from models import graft as G
    from models import losses as L
    from models import tgn as T

    cfg_t = load_config("train_tgn")
    cfg_g = load_config("train_graft")
    if ablate_time2vec:  # M6.2 ablation row: identical run, Time2Vec off
        cfg_g = {**cfg_g, "model": {**cfg_g["model"], "use_time2vec": False}}
    set_seed(cfg_g["seed"])
    anonymizer = Anonymizer.from_config(cfg)
    msg_scaler = fit_scaler(cfg, split="train")
    stage_of = {s: i for i, s in enumerate(cfg["stages"])}
    stride = cfg["windows"]["stride_seconds"]
    seg_len = cfg["windows"]["max_sequence_windows"]

    # ---- TGN exactly as the M5 row ----
    train_flows = load_split_flows(cfg, "train")
    encoder = T.build_model(
        cfg_t,
        num_nodes=pd.concat([train_flows["src_ip"], train_flows["dst_ip"]]).nunique(),
        msg_dim=len(msg_scaler.mean_),
    )
    tgn_curve = []
    for epoch in range(cfg_t["link_pred"]["epochs"]):
        events = T.build_events(cfg_t, train_flows, anonymizer, epoch, msg_scaler)
        one = {**cfg_t, "link_pred": {**cfg_t["link_pred"], "epochs": 1}}
        loss = T.train_link_pred(encoder, events, one)[0]
        tgn_curve.append(float(loss))
        print(f"tgn link-pred epoch {epoch}: loss {loss:.4f}", flush=True)

    def tgn_embeddings(split, split_name):
        flows = train_flows if split_name == "train" else load_split_flows(cfg, split_name)
        events = T.build_events(cfg_t, flows, anonymizer, 0, msg_scaler)
        ro = pd.DataFrame({"host": split.host, "window_start": split.window_start})
        return T.snapshot_embeddings(encoder, events, ro, cfg_t)

    # ---- segment the train split over TGN embeddings ----
    emb_train = tgn_embeddings(train_split, "train")
    from types import SimpleNamespace

    def seg(split, emb):
        proxy = SimpleNamespace(
            X=emb, y=split.y, host=split.host, window_start=split.window_start
        )
        Xs, Ys, Ms, Is = _segment_split(proxy, seg_len)
        stage_ids = np.array([stage_of[s] for s in split.stage], dtype=np.int64)
        Ss = np.where(Is >= 0, stage_ids[np.clip(Is, 0, None)], 0)
        Dt = _delta_t_for_segments(split, Is, stride)
        return Xs, Ys, Ms, Is, Ss, Dt

    Xs, Ys, Ms, Is, Ss, Dt = seg(train_split, emb_train)
    print(f"graft train segments: {Xs.shape}", flush=True)

    model = G.build_model(cfg_g, feature_dim=Xs.shape[2])
    opt = torch.optim.Adam(
        model.parameters(), lr=cfg_g["optim"]["lr"],
        weight_decay=cfg_g["optim"]["weight_decay"],
    )
    pos = max(float(Ys[Ms > 0].sum()), 1.0)
    neg = float(Ms.sum() - pos)
    class_w = torch.tensor(neg / pos)

    Xt = torch.tensor(Xs); Yt = torch.tensor(Ys, dtype=torch.float32)
    Mt = torch.tensor(Ms.astype(bool)); St = torch.tensor(Ss); Dtt = torch.tensor(Dt)
    bs = cfg_g["optim"]["batch_size"]
    n = Xt.shape[0]
    anneal_ep = cfg_g["loss"]["evidential_kl_anneal_epochs"]
    g = torch.Generator().manual_seed(cfg_g["seed"])

    model.train()
    graft_curve = []
    for epoch in range(cfg_g["optim"]["epochs"]):
        perm = torch.randperm(n, generator=g)
        tot = 0.0
        for i in range(0, n, bs):
            idx = perm[i : i + bs]
            opt.zero_grad()
            out = model(Xt[idx], delta_t=Dtt[idx], padding_mask=~Mt[idx])
            targets = {
                "attack": Yt[idx], "stage": St[idx], "features": Xt[idx],
                "valid": Mt[idx],
            }
            loss, _ = L.composite_loss(
                out, targets, cfg_g, anneal=min(1.0, epoch / anneal_ep),
                class_weights=class_w,
            )
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), cfg_g["optim"]["grad_clip"])
            opt.step()
            tot += float(loss.detach())
        graft_curve.append(tot / max(1, n // bs))
        print(f"graft epoch {epoch}: loss {graft_curve[-1]:.4f}", flush=True)
    _dump_curve("tgn_graft_no_time2vec" if ablate_time2vec else "tgn_graft",
                {"tgn_link_pred": tgn_curve, "graft": graft_curve})

    from configs import resolve_path

    art = resolve_path(cfg["paths"]["artifacts_dir"]); art.mkdir(parents=True, exist_ok=True)
    if not ablate_time2vec:  # only the full model becomes the M7 artifact
        torch.save(encoder.state_dict(), art / "tgn_encoder.pt")
        torch.save(model.state_dict(), art / "graft.pt")

    # ---- score eval splits ----
    scores = {}
    model.eval()
    for name, split in eval_splits.items():
        emb = tgn_embeddings(split, name)
        Xs, Ys, Ms, Is, Ss, Dt = seg(split, emb)
        flat = np.zeros(len(split.y), dtype=float)
        with torch.no_grad():
            for i in range(0, Xs.shape[0], bs):
                sl = slice(i, i + bs)
                out = model(
                    torch.tensor(Xs[sl]), delta_t=torch.tensor(Dt[sl]),
                    padding_mask=~torch.tensor(Ms[sl].astype(bool)),
                )
                probs = out["attack_prob"].numpy()
                rows = Is[sl].reshape(-1)
                vals = probs.reshape(-1)
                keep = rows >= 0
                flat[rows[keep]] = vals[keep]
        scores[name] = flat
    return scores


def evaluate(model_name: str, holdout_family: str | None = None) -> dict:
    cfg = load_config("data")
    cfg_eval = load_config("eval")
    cfg_b = load_config("baselines")
    set_seed(cfg_b["seed"])

    # Leave-one-attack-family-out (M4.6): the family is removed from TRAIN only,
    # so the scaler and model never see it; val/test are untouched.
    train, scaler = D.assemble_split(
        cfg, "train", horizon=0, fit_scaler=True, holdout_family=holdout_family
    )
    val, _ = D.assemble_split(cfg, "val", horizon=0, scaler=scaler)
    test, _ = D.assemble_split(cfg, "test", horizon=0, scaler=scaler)
    D.persist_window_scaler(cfg, scaler)

    evals = {"val": val, "test": test}
    if model_name == "lstm":
        scores = _lstm_scores(cfg, cfg_b, train, evals)
    elif model_name == "tgn":
        scores = _tgn_scores(cfg, train, evals)
    elif model_name == "tgn_graft":
        scores = _tgn_graft_scores(cfg, train, evals)
    elif model_name == "tgn_graft_no_time2vec":
        scores = _tgn_graft_scores(cfg, train, evals, ablate_time2vec=True)
    else:
        scores = _flat_scores(model_name, cfg_b, train, evals)

    _dump_scores(cfg_eval, model_name, holdout_family, evals, scores)

    # Threshold(s) from validation benign; applied to test.
    result = {"model": model_name, "horizon": 0, "holdout_family": holdout_family,
              "operating_points": {}, "test": {}, "val": {}}
    for budget in cfg_eval["fpr_budgets"]:
        thr = M.threshold_at_fpr(val.y, scores["val"], budget)
        for split_name, split in evals.items():
            pred = scores[split_name] >= thr
            tp = int(np.count_nonzero(pred & (split.y == 1)))
            fp = int(np.count_nonzero(pred & (split.y == 0)))
            fn = int(np.count_nonzero(~pred & (split.y == 1)))
            tn = int(np.count_nonzero(~pred & (split.y == 0)))
            precision = tp / (tp + fp) if (tp + fp) else 0.0
            recall = tp / (tp + fn) if (tp + fn) else 0.0
            f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
            fpr = fp / (fp + tn) if (fp + tn) else 0.0

            # Lead time from alerts on the attacker hosts of THIS split.
            alerts = [
                {"host": h, "time": t}
                for h, t, fired in zip(split.host, split.window_start, pred) if fired
            ]
            lt = M.lead_time(D.attacker_episodes(cfg, split_name), alerts)
            result[split_name][f"fpr_{budget}"] = {
                "threshold": thr, "precision": precision, "recall": recall, "f1": f1,
                "fpr": fpr, "n_alerts": tp + fp,
                "alerts_per_host_day": M.alerts_per_host_day(tp + fp, split.n_host_windows, cfg),
                "lead_time_median": lt.median, "lead_time_iqr": [lt.iqr_low, lt.iqr_high],
                "episodes_detected": lt.n_detected, "episodes_total": lt.n_episodes,
            }

    for split_name, split in evals.items():
        result[split_name]["auroc"] = M.auroc(split.y, scores[split_name])
        result[split_name]["ece"] = M.expected_calibration_error(
            split.y, scores[split_name], cfg_eval["metrics"]["ece_bins"]
        ).ece
        result[split_name]["n_host_windows"] = int(split.n_host_windows)
        result[split_name]["n_attack_windows"] = int(np.count_nonzero(split.y))

    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--model", required=True,
        choices=sorted(baselines.REGISTRY) + ["tgn", "tgn_graft", "tgn_graft_no_time2vec",
                                              "world", "forecast", "fused"],
    )
    parser.add_argument("--holdout-family", default=None)
    args = parser.parse_args(argv)

    if args.model == "world":  # M7.7: multi-horizon RSSM (failed the gate — decision 004)
        from eval import world

        return world.main()
    if args.model == "forecast":  # M7 shipped: encoder forecasting at horizon k
        from eval import forecast

        return forecast.main()
    if args.model == "fused":  # rank-mean fusion of tgn+xgb (reads their score dumps)
        from eval import fused

        return fused.main([])

    result = evaluate(args.model, args.holdout_family)

    cfg_eval = load_config("eval")
    out_dir = resolve_path(cfg_eval["paths"]["results_dir"])
    out_dir.mkdir(parents=True, exist_ok=True)
    suffix = f"_holdout-{args.holdout_family}" if args.holdout_family else ""
    out_path = out_dir / f"{args.model}{suffix}.json"
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2)

    test1 = result["test"].get("fpr_0.01", {})
    print(f"{args.model}: test F1@1%FPR={test1.get('f1', 0):.3f} "
          f"recall={test1.get('recall', 0):.3f} AUROC={result['test']['auroc']:.3f} "
          f"lead_median={test1.get('lead_time_median', 0):.0f}s "
          f"({test1.get('episodes_detected')}/{test1.get('episodes_total')} episodes) "
          f"-> {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
