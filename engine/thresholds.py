"""Operating threshold selection + persistence (M8.1).

The alert threshold is chosen from an FPR budget on the validation split and
persisted next to the model — never a literal in code. The engine loads it at
inference; there is no hardcoded 0.42.

One persisted entry per (input variant, forecast horizon): the k-step heads
(engine/forecast.py) have their own score distributions, so k=8's threshold is
not k=0's and reading one for the other would silently change the operating
point. `horizon_variant` is the single place that spells those keys.
"""

from __future__ import annotations

import json

from configs import resolve_path


def horizon_variant(variant: str, horizon: int) -> str:
    """Persisted key for one input variant ('full'/'flow') at one horizon.

    horizon 0 keeps the BARE variant name, so nowcast artifacts persisted before
    the k-step heads existed stay readable; k>0 gets its own suffixed key
    ('full_k4'). Every caller — the trainer that writes the entry and the
    forecaster that reads it — goes through here, because a key spelled two ways
    is a threshold silently shared between horizons.
    """
    if not isinstance(horizon, (int,)) or isinstance(horizon, bool) or horizon < 0:
        raise ValueError(f"horizon must be a non-negative int, got {horizon!r}")
    return variant if horizon == 0 else f"{variant}_k{horizon}"


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
    """{'file', 'val_auroc', 'fpr_<b>': thr} for one `horizon_variant` key —
    'full' (PCAP) or 'flow' (CSV) at horizon 0, 'full_k4'/'flow_k4' at k=4."""
    data = _load(cfg)
    spec = data.get(variant)
    # Non-variant bookkeeping keys ('model', 'features', ...) live in the same
    # file; a name that resolves to one of those is still "no such model".
    if not isinstance(spec, dict) or "file" not in spec:
        raise KeyError(
            f"no '{variant}' engine model persisted; have "
            f"{sorted(k for k, v in data.items() if isinstance(v, dict) and 'file' in v)}"
        )
    return spec


def load_threshold(cfg: dict, fpr_budget: float, variant: str = "full") -> float:
    spec = load_model_spec(cfg, variant)
    key = f"fpr_{fpr_budget}"
    if key not in spec:
        raise KeyError(f"no persisted threshold for {variant}/{key}; have {sorted(spec)}")
    return float(spec[key])
