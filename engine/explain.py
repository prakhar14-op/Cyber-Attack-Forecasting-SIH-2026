"""Explainability (M8.2/8.4/8.5): named-feature attributions + technique mapping.

"Black-box outputs are not acceptable" (PS). Every alert is explained in terms
of REAL named features (never embedding dimensions): TreeSHAP on the deployed
gradient-boosted model gives per-alert, signed, named-feature contributions,
and a stage+pattern rule set names the MITRE technique.
"""

from __future__ import annotations

import numpy as np
import yaml

from configs import load_config, resolve_path

# A technique rule whose threshold is `stage_rule:<key>` reads that key from
# configs/data.yaml `stage_rules` instead of repeating its value. The stage
# decision and the technique that explains it are then driven by ONE number:
# recalibrating a stage threshold can no longer leave the two contradicting each
# other in front of an operator.
STAGE_RULE_REF = "stage_rule:"

# A technique-rule `when` key is `<feature>_<comparison>`, and the comparison has
# to be one this module actually applies. Only `_gt` is implemented, because that
# is the only comparison engine/technique_map.yaml uses; an unrecognised suffix
# raises rather than being skipped. It used to be skipped, and a skipped
# condition is not a weaker rule — it is NO rule: `sequential_port_ratio_gte`
# (one typo) made every window match that technique unconditionally, which is
# exactly the silent failure the MITRE mapping must not have.
#
# To add a comparison, put it here AND decide what it means for a feature the
# caller did not supply: `_gt` fails closed on the 0.0 default below (an absent
# feature cannot exceed a positive threshold), while a `_lt` would fail OPEN on
# it, so it needs a missing-feature policy of its own before it ships.
COMPARISONS = {"gt": lambda value, threshold: value > threshold}

_TECHNIQUE_MAP = None
_STAGE_RULES = None


def _load_technique_map():
    global _TECHNIQUE_MAP
    if _TECHNIQUE_MAP is None:
        path = resolve_path("engine/technique_map.yaml")
        _TECHNIQUE_MAP = yaml.safe_load(path.read_text(encoding="utf-8"))
    return _TECHNIQUE_MAP


def _stage_rules() -> dict:
    global _STAGE_RULES
    if _STAGE_RULES is None:
        _STAGE_RULES = load_config("data")["stage_rules"]
    return _STAGE_RULES


def _threshold(key: str, thr):
    """Resolve a technique-rule threshold, following a STAGE_RULE_REF to the
    configs/data.yaml value that owns it. A reference to a key that is not there
    raises — a silently unmatched rule would hide the drift it exists to catch."""
    if not (isinstance(thr, str) and thr.startswith(STAGE_RULE_REF)):
        return thr
    name = thr[len(STAGE_RULE_REF):]
    rules = _stage_rules()
    if name not in rules:
        raise KeyError(
            f"engine/technique_map.yaml rule {key!r} references stage_rule {name!r}, "
            f"which is not in configs/data.yaml stage_rules (known: {sorted(rules)})"
        )
    return rules[name]


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


def parse_when_key(key: str) -> tuple[str, object]:
    """`when` key -> (feature name, comparison). Raises on anything else.

    A key whose suffix names no comparison in COMPARISONS is a typo, and a typo
    must not quietly become "no condition" — see COMPARISONS.
    """
    name, _, suffix = key.rpartition("_")
    op = COMPARISONS.get(suffix)
    if not name or op is None:
        raise ValueError(
            f"engine/technique_map.yaml rule key {key!r} names no supported "
            f"comparison: expected <feature>_<{'|'.join(sorted(COMPARISONS))}>. "
            "An unrecognised suffix is a typo, and skipping it would make the "
            "rule match every window."
        )
    return name, op


def _rule_matches(when: dict, feats: dict) -> bool:
    """True when EVERY condition in `when` holds for these window features.

    A feature the caller did not supply reads as 0.0 (callers outside
    predict_file pass partial dicts); with `_gt` that fails closed.
    An empty `when` raises: a rule with no conditions matches everything, which
    is the stage `default`, not a rule.
    """
    if not when:
        raise ValueError(
            "engine/technique_map.yaml has a technique rule with no `when` "
            "conditions — that matches every window; use the stage `default`."
        )
    for key, thr in when.items():
        name, op = parse_when_key(key)
        if not op(feats.get(name, 0.0), _threshold(key, thr)):
            return False
    return True


def map_technique(stage: str, feats: dict) -> dict:
    """Stage + observed named-feature pattern -> {technique, name} (M8.5).

    An unmapped stage raises: a stage the map has never heard of is a drift bug,
    and returning a blank technique for it would hide that behind a plausible
    output. `unclassified` IS mapped — to no technique, deliberately.
    """
    tmap = _load_technique_map()
    if stage not in tmap:
        raise KeyError(
            f"stage {stage!r} has no entry in engine/technique_map.yaml "
            f"(known: {sorted(tmap)})"
        )
    entry = tmap[stage]
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
