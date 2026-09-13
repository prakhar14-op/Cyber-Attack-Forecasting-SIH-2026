"""Operating threshold selection + persistence (M8.1).

The alert threshold is chosen from an FPR budget on the validation split and
persisted next to the model — never a literal in code. The engine loads it at
inference; there is no hardcoded 0.42.

One persisted entry per (input variant, forecast horizon): the k-step heads
(engine/forecast.py) have their own score distributions, so k=8's threshold is
not k=0's and reading one for the other would silently change the operating
point. `horizon_variant` is the single place that spells those keys.

LANES. A persisted threshold file belongs to a lane, named by the top-level
`artifact_lane` field. Absent, it is the PUBLISHED lane — that is every file
`engine/train_engine.py` has ever written, so nothing existing changes meaning.
The DEMO lane is what `scripts/bootstrap_demo_artifacts.py` fits from the small
synthetic capture bundled in this repository so a fresh clone can run the
pipeline; it has memorised that capture and none of its output is comparable to
a published number. The two must never be confused, so `load_model_spec`
refuses a demo-lane file found anywhere but `configs/data.yaml`
`demo.artifacts_dir`: copying demo weights into `artifacts/` to make something
run is the obvious shortcut, and it has to fail out loud rather than quietly
become "the model".
"""

from __future__ import annotations

import json

from configs import resolve_path

# Lane marker (see the module docstring). The field is additive: a file without
# it is published, which is every artifact bundle written before demo lanes
# existed.
LANE_FIELD = "artifact_lane"
PUBLISHED_LANE = "published"
DEMO_LANE = "demo"


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


def artifact_lane(cfg: dict) -> str:
    """Which lane the persisted thresholds belong to (see the module docstring).

    PUBLISHED_LANE when the file carries no marker — every bundle
    engine/train_engine.py writes.
    """
    return str(_load(cfg).get(LANE_FIELD, PUBLISHED_LANE))


def _demo_artifacts_dir(cfg: dict):
    """configs/data.yaml `demo.artifacts_dir`, or None if this cfg has no demo
    block (a stub cfg in a test, or a checkout predating the demo lane)."""
    demo = cfg.get("demo")
    configured = demo.get("artifacts_dir") if isinstance(demo, dict) else None
    return resolve_path(configured) if configured else None


def _refuse_demo_lane_outside_its_own_directory(cfg: dict, data: dict) -> None:
    """Raise if demo-lane thresholds are being loaded from anywhere else.

    The guard costs nothing on the published lane: a file with no `artifact_lane`
    marker returns immediately. It bites the one shortcut that would otherwise
    work silently — copying `artifacts_demo/*` into `artifacts/` so that
    something which needs a model finds one. That swap has no other symptom: the
    files load, the engine scores, and the probabilities look like results.
    """
    if str(data.get(LANE_FIELD, PUBLISHED_LANE)) != DEMO_LANE:
        return
    here = resolve_path(cfg["paths"]["artifacts_dir"])
    demo_dir = _demo_artifacts_dir(cfg)
    if demo_dir is not None and here == demo_dir:
        return
    raise RuntimeError(
        f"{threshold_path(cfg)} is marked lane '{DEMO_LANE}' but is being loaded from "
        f"{here}, which is not configs/data.yaml `demo.artifacts_dir` "
        f"({demo_dir if demo_dir is not None else 'unset in this config'}). These are "
        "DEMO weights fitted by scripts/bootstrap_demo_artifacts.py on the small "
        "synthetic capture bundled in this repository; they have memorised it and "
        "nothing they output is comparable to a published number. Refusing to serve "
        "them as the published model. Either point the engine at the demo directory "
        "on purpose, or fetch the real artifacts."
    )


def load_model_spec(cfg: dict, variant: str) -> dict:
    """{'file', 'val_auroc', 'fpr_<b>': thr} for one `horizon_variant` key —
    'full' (PCAP) or 'flow' (CSV) at horizon 0, 'full_k4'/'flow_k4' at k=4.

    Demo-lane files carry `in_sample_auroc` in place of `val_auroc`: there is no
    validation split behind them, and the field the published lane fills with a
    held-out figure must not be filled with a memorisation one.
    """
    data = _load(cfg)
    _refuse_demo_lane_outside_its_own_directory(cfg, data)
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
