"""Baseline models (M4.3). All train from one config and share the identical
feature matrix (eval.dataset), the PS's requirement for the graded LR baseline.

- `lr`  : class-weighted logistic regression — the PS-mandated, graded baseline.
- `xgb` : gradient-boosted trees (expected strong at horizon 0 — the world
          model must beat it on LEAD TIME, not horizon-0 F1).
- `lstm`: an LSTM over each host's window sequence (a learned temporal baseline
          the world model is measured against).

Each exposes fit(X, y) / predict_proba(X) -> P(attack). The registry maps a
config name to a constructor so `python -m eval.harness --model lr` works.
"""

from __future__ import annotations

import numpy as np


class LogisticRegressionBaseline:
    """Class-weighted logistic regression (scikit-learn)."""

    def __init__(self, cfg: dict):
        p = cfg["models"]["lr"]
        from sklearn.linear_model import LogisticRegression

        self.model = LogisticRegression(
            C=p["C"], max_iter=p["max_iter"], class_weight="balanced",
            solver=p["solver"], n_jobs=-1,
        )

    def fit(self, X, y):
        self.model.fit(X, y)
        return self

    def predict_proba(self, X):
        return self.model.predict_proba(X)[:, 1]


class XGBoostBaseline:
    """Gradient-boosted trees with imbalance-aware scale_pos_weight."""

    def __init__(self, cfg: dict):
        self.p = cfg["models"]["xgb"]
        self.model = None

    def fit(self, X, y):
        import xgboost as xgb

        pos = max(int(np.count_nonzero(y)), 1)
        neg = int(len(y) - pos)
        self.model = xgb.XGBClassifier(
            n_estimators=self.p["n_estimators"],
            max_depth=self.p["max_depth"],
            learning_rate=self.p["learning_rate"],
            subsample=self.p["subsample"],
            colsample_bytree=self.p["colsample_bytree"],
            scale_pos_weight=neg / pos,
            eval_metric="logloss",
            n_jobs=-1,
            tree_method="hist",
        )
        self.model.fit(X, y)
        return self

    def predict_proba(self, X):
        return self.model.predict_proba(X)[:, 1]


class LSTMBaseline:
    """LSTM over each host's window sequence, scored per window (horizon 0).

    Trains on padded per-host sequences; the loss is masked over padding and
    class-weighted for imbalance. A learned temporal baseline — deliberately
    NOT the world model (no rollout, no evidential head).
    """

    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.p = cfg["models"]["lstm"]
        self.net = None
        self._feat_dim = None

    def _build(self, feat_dim: int):
        import torch.nn as nn

        from configs import set_seed

        set_seed(self.cfg["seed"])

        class _Net(nn.Module):
            def __init__(self, f, hidden, layers, dropout):
                super().__init__()
                self.lstm = nn.LSTM(
                    f, hidden, num_layers=layers, batch_first=True,
                    dropout=dropout if layers > 1 else 0.0,
                )
                self.head = nn.Linear(hidden, 1)

            def forward(self, x):
                out, _ = self.lstm(x)
                return self.head(out).squeeze(-1)  # [B, T] logits per window

        return _Net(feat_dim, self.p["hidden_dim"], self.p["layers"], self.p["dropout"])

    def fit(self, X_seq: np.ndarray, Y_seq: np.ndarray, mask: np.ndarray):
        """X_seq [N, T, F] segments, Y_seq [N, T] binary, mask [N, T] (1=real).

        Many-to-many: a per-window logit for every position, masked+class-weighted
        BCE over real positions, mini-batched over segments.
        """
        import torch

        from configs import set_seed

        set_seed(self.cfg["seed"])
        self._feat_dim = X_seq.shape[2]
        self.net = self._build(self._feat_dim)

        X = torch.tensor(X_seq, dtype=torch.float32)
        Y = torch.tensor(Y_seq, dtype=torch.float32)
        Mt = torch.tensor(mask, dtype=torch.float32)
        pos = float(Y[Mt.bool()].sum())
        neg = float(Mt.sum() - pos)
        pos_weight = torch.tensor([neg / max(pos, 1.0)])

        opt = torch.optim.Adam(self.net.parameters(), lr=self.p["lr"])
        loss_fn = torch.nn.BCEWithLogitsLoss(reduction="none", pos_weight=pos_weight)
        bs = self.p["batch_size"]
        n = X.shape[0]
        self.net.train()
        for _ in range(self.p["epochs"]):
            perm = torch.randperm(n)
            for i in range(0, n, bs):
                idx = perm[i : i + bs]
                opt.zero_grad()
                logits = self.net(X[idx])
                m = Mt[idx]
                loss = (loss_fn(logits, Y[idx]) * m).sum() / m.sum().clamp(min=1)
                loss.backward()
                torch.nn.utils.clip_grad_norm_(self.net.parameters(), self.p["grad_clip"])
                opt.step()
        return self

    def predict_proba_segments(self, X_seq: np.ndarray) -> np.ndarray:
        """[N, T, F] -> [N, T] P(attack) per window position."""
        import torch

        self.net.eval()
        X = torch.tensor(X_seq, dtype=torch.float32)
        with torch.no_grad():
            probs = torch.sigmoid(self.net(X)).numpy()
        return probs


REGISTRY = {
    "lr": LogisticRegressionBaseline,
    "xgb": XGBoostBaseline,
    "lstm": LSTMBaseline,
}


def build_model(name: str, cfg: dict):
    if name not in REGISTRY:
        raise KeyError(f"unknown model '{name}' (have {sorted(REGISTRY)})")
    return REGISTRY[name](cfg)
