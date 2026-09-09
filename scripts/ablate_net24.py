"""Part 3: size net24_bucket's contribution by retraining without it.

    python scripts/ablate_net24.py

net24_bucket is a key-derived role feature. It is a column of the 30-dim window
matrix, which feeds the FLAT models (xgb / lr / lstm) — but NOT tgn or graft,
whose head inputs are the TGN embeddings (memory_dim), not the raw matrix. So
this ablation retrains the flat models with the column zeroed (equivalent to
dropping it for a tree/linear model) and reports the drop; tgn/graft are
net24-independent by construction (verified: the head is fit on embeddings).

Reports AUROC/F1/recall/lead/episodes with vs without net24, side by side, at
the 1% FPR budget (val-fit threshold, same policy as the benchmark table).
"""

from __future__ import annotations

import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from configs import load_config, set_seed  # noqa: E402
from data import windows as W  # noqa: E402
from eval import dataset as D  # noqa: E402
from eval import metrics as M  # noqa: E402
from models import baselines  # noqa: E402


def _point(cfg, val, test, sv, st, budget=0.01):
    thr = M.threshold_at_fpr(val.y, sv, budget)
    pred = st >= thr
    tp = int(np.count_nonzero(pred & (test.y == 1))); fp = int(np.count_nonzero(pred & (test.y == 0)))
    fn = int(np.count_nonzero(~pred & (test.y == 1))); tn = int(np.count_nonzero(~pred & (test.y == 0)))
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
    alerts = [{"host": h, "time": t} for h, t, f in zip(test.host, test.window_start, pred) if f]
    lt = M.lead_time(D.attacker_episodes(cfg, "test"), alerts)
    return {"auroc": M.auroc(test.y, st), "f1": f1, "recall": rec,
            "lead": lt.median, "eps": f"{lt.n_detected}/{lt.n_episodes}"}


def main() -> int:
    cfg = load_config("data")
    cfg_b = load_config("baselines")
    feat = W.feature_columns(cfg)
    j = feat.index("net24_bucket")
    print(f"net24_bucket is feature column {j} of {len(feat)}")

    train, scaler = D.assemble_split(cfg, "train", horizon=0, fit_scaler=True)
    val, _ = D.assemble_split(cfg, "val", horizon=0, scaler=scaler)
    test, _ = D.assemble_split(cfg, "test", horizon=0, scaler=scaler)

    def zero_net24(split):
        from types import SimpleNamespace
        X = split.X.copy(); X[:, j] = 0.0
        return SimpleNamespace(X=X, y=split.y, host=split.host,
                               window_start=split.window_start,
                               n_host_windows=split.n_host_windows)

    tr0, va0, te0 = zero_net24(train), zero_net24(val), zero_net24(test)

    print(f"\n{'model':6} {'variant':16} {'AUROC':>7} {'F1':>6} {'recall':>7} {'lead':>7} {'eps':>5}")
    print("-" * 56)
    rows = {}
    for name in ["xgb", "lr"]:
        set_seed(cfg_b["seed"])
        m_with = baselines.build_model(name, cfg_b).fit(train.X, train.y)
        with_ = _point(cfg, val, test, m_with.predict_proba(val.X), m_with.predict_proba(test.X))
        set_seed(cfg_b["seed"])
        m_wo = baselines.build_model(name, cfg_b).fit(tr0.X, tr0.y)
        wo = _point(cfg, va0, te0, m_wo.predict_proba(va0.X), m_wo.predict_proba(te0.X))
        rows[name] = (with_, wo)
        for tag, r in [("with net24", with_), ("WITHOUT net24", wo)]:
            print(f"{name:6} {tag:16} {r['auroc']:7.3f} {r['f1']:6.3f} {r['recall']:7.3f} "
                  f"{r['lead']:7.0f} {r['eps']:>5}")
        print(f"{'':6} {'-> drop':16} {with_['auroc']-wo['auroc']:+7.3f} "
              f"{with_['f1']-wo['f1']:+6.3f}")
    print("\ntgn / graft: net24 does not enter (head fit on TGN embeddings, not the "
          "30-dim matrix) -> ablation is a no-op for them by construction.")
    print("fused = rank-mean(tgn, xgb): its only net24 dependence is via the xgb member above.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
