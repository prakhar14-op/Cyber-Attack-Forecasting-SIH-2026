"""Operating threshold selection + persistence (M8.1).

The alert threshold is chosen from an FPR budget on the validation split and
persisted next to the model — never a literal in code. The engine loads it at
inference; there is no hardcoded 0.42.
"""

from __future__ import annotations

import json

from configs import resolve_path


def threshold_path(cfg: dict):
    return resolve_path(cfg["paths"]["artifacts_dir"]) / "engine_threshold.json"


def persist_threshold(cfg: dict, thresholds: dict) -> str:
    """thresholds: {fpr_budget(str): threshold(float)} plus metadata."""
    path = threshold_path(cfg)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(thresholds, indent=2), encoding="utf-8")
    return str(path)


def _load(cfg: dict) -> dict:
    path = threshold_path(cfg)
    if not path.exists():
        raise FileNotFoundError(
            f"{path} missing — run `python -m engine.train_engine` to fit and "
            "persist the engine models + thresholds (M8.1)"
        )
    return json.loads(path.read_text(encoding="utf-8"))


def load_model_spec(cfg: dict, variant: str) -> dict:
    """{'file', 'val_auroc', 'fpr_<b>': thr} for 'full' (PCAP) or 'flow' (CSV)."""
    data = _load(cfg)
    if variant not in data:
        raise KeyError(f"no '{variant}' engine model persisted; have {sorted(data)}")
    return data[variant]


def load_threshold(cfg: dict, fpr_budget: float, variant: str = "full") -> float:
    spec = load_model_spec(cfg, variant)
    key = f"fpr_{fpr_budget}"
    if key not in spec:
        raise KeyError(f"no persisted threshold for {variant}/{key}; have {sorted(spec)}")
    return float(spec[key])
