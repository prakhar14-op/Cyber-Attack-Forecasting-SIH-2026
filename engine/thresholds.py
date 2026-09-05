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


def load_threshold(cfg: dict, fpr_budget: float) -> float:
    path = threshold_path(cfg)
    if not path.exists():
        raise FileNotFoundError(
            f"{path} missing — run `python -m engine.train_engine` to fit and "
            "persist the operating threshold (M8.1)"
        )
    data = json.loads(path.read_text(encoding="utf-8"))
    key = f"fpr_{fpr_budget}"
    if key not in data:
        raise KeyError(f"no persisted threshold for {key}; have {sorted(data)}")
    return float(data[key])
