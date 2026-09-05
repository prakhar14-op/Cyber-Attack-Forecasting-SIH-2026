"""Explainability (M8.2/8.4/8.5): named-feature attributions + technique mapping.

"Black-box outputs are not acceptable" (PS). Every alert is explained in terms
of REAL named features (never embedding dimensions): TreeSHAP on the deployed
gradient-boosted model gives per-alert, signed, named-feature contributions,
and a stage+pattern rule set names the MITRE technique.
"""

from __future__ import annotations

import numpy as np
import yaml

from configs import resolve_path

_TECHNIQUE_MAP = None


def _load_technique_map():
    global _TECHNIQUE_MAP
    if _TECHNIQUE_MAP is None:
        path = resolve_path("engine/technique_map.yaml")
        _TECHNIQUE_MAP = yaml.safe_load(path.read_text(encoding="utf-8"))
    return _TECHNIQUE_MAP


class ShapExplainer:
    """TreeSHAP over the deployed XGBoost, in named-feature space."""

    def __init__(self, xgb_model, feature_names: list[str]):
        import shap

        self.feature_names = feature_names
        self.explainer = shap.TreeExplainer(xgb_model)

    def top_features(self, X: np.ndarray, k: int = 5) -> list[list[dict]]:
        """Per row, the top-k features by |SHAP|, as [{feature, value, shap}]."""
        sv = self.explainer.shap_values(X)
        if isinstance(sv, list):  # binary classifier -> positive class
            sv = sv[1]
        out = []
        for i in range(X.shape[0]):
            order = np.argsort(np.abs(sv[i]))[::-1][:k]
            out.append([
                {"feature": self.feature_names[j],
                 "value": float(X[i, j]),
                 "contribution": float(sv[i, j])}
                for j in order
            ])
        return out


def _rule_matches(when: dict, feats: dict) -> bool:
    for key, thr in when.items():
        if key.endswith("_gt"):
            name = key[:-3]
            if not (feats.get(name, 0.0) > thr):
                return False
    return True


def map_technique(stage: str, feats: dict) -> dict:
    """Stage + observed named-feature pattern -> {technique, name} (M8.5)."""
    tmap = _load_technique_map()
    entry = tmap.get(stage, {})
    for rule in entry.get("rules", []) or []:
        if _rule_matches(rule.get("when", {}), feats):
            return {"technique": rule["technique"], "name": rule.get("name", "")}
    tech = entry.get("default")
    return {"technique": tech, "name": entry.get("name", "")}


def flagged_flows(flows, host: str, window_start: float, window_seconds: float, top: int = 5):
    """The PS's 'flagged flows' list for an alerted host-window: the host's
    flows active in the window, ranked by byte volume (a lightweight, offline
    stand-in for a TreeSHAP flow pre-filter — the same named-feature story)."""
    import pandas as pd

    ts = flows["timestamp"].map(pd.Timestamp.timestamp)
    mask = (flows["src_ip"] == host) & (ts >= window_start) & (ts < window_start + window_seconds)
    hits = flows[mask].copy()
    if hits.empty:
        return []
    hits["_bytes"] = hits["fwd_bytes"] + hits["bwd_bytes"]
    hits = hits.sort_values("_bytes", ascending=False).head(top)
    return [
        {"dst_port": int(r["dst_port"]), "protocol": int(r["protocol"]),
         "bytes": int(r["_bytes"]), "syn": int(r["syn"]), "duration_us": float(r["duration"])}
        for _, r in hits.iterrows()
    ]
