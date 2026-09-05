"""Prediction engine (M8.6): file -> forecasts -> explanations -> ledger.

    from engine import predict
    predict.predict_file("capture.csv", out_dir="run/")

Fully offline: loads the persisted engine model + threshold + scaler (no
network, no runtime downloads), builds per-(source_host, window) features from
the input, scores each host-window, and for every ALERT emits an explained
forecast object (probability, stage, MITRE technique, named top features,
flagged flows, estimated lead) validated against a JSON schema, and appends it
to the tamper-evident ledger. Returns the summary the app and smoke runner use.

CSV input gives flow-derived features only (packet-statistic features need
PCAP — decision 001); the pipeline runs either way.
"""

from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import pandas as pd

from configs import load_config, resolve_path, set_seed

OUTPUT_SCHEMA = {
    "type": "object",
    "required": ["host", "window_start", "probability", "stage", "technique",
                 "top_features", "flagged_flows"],
    "properties": {
        "host": {"type": "string"},
        "window_start": {"type": "number"},
        "probability": {"type": "number", "minimum": 0, "maximum": 1},
        "stage": {"type": "string"},
        "technique": {"type": ["string", "null"]},
        "technique_name": {"type": "string"},
        "top_features": {"type": "array", "items": {
            "type": "object",
            "required": ["feature", "value", "contribution"],
            "properties": {"feature": {"type": "string"}},
        }},
        "flagged_flows": {"type": "array"},
        "estimated_lead_seconds": {"type": ["number", "null"]},
    },
}


def _load_engine(cfg):
    import pickle

    import xgboost as xgb

    from engine import thresholds as TH

    art = resolve_path(cfg["paths"]["artifacts_dir"])
    model_path = art / "engine_model.json"
    if not model_path.exists():
        raise FileNotFoundError(
            f"{model_path} missing — run `python -m engine.train_engine` first (M8.1)"
        )
    booster = xgb.XGBClassifier()
    booster.load_model(str(model_path))
    with open(art / "window_scaler.pkl", "rb") as fh:
        scaler = pickle.load(fh)
    return booster, scaler


def _windows_from_input(cfg, csv_path, anonymizer):
    from data import flow_features as FF
    from data import windows as W

    flows = FF.load_canonical(cfg, csv_path)
    wf = W.window_features_from_flows(cfg, flows, anonymizer=anonymizer)
    return flows, wf


def predict_file(csv_path, out_dir, fpr_budget: float = 0.01) -> dict:
    """Run the offline engine on one file. Writes out_dir/audit_chain.jsonl and
    a forecasts.json; returns {n_flows, forecasts, n_alerts, ...}."""
    cfg = load_config("data")
    set_seed(cfg["seed"])
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    from data.anonymize import Anonymizer
    from data import windows as W
    from engine import explain as EX
    from engine import thresholds as TH
    from ledger.ledger import Ledger

    anonymizer = _maybe_anonymizer(cfg)
    booster, scaler = _load_engine(cfg)
    threshold = TH.load_threshold(cfg, fpr_budget)

    # M9.3: bind this batch to exact weights — refuse to log on mismatch, so a
    # ledger entry can never claim provenance it does not have.
    import sys as _sys
    from pathlib import Path as _Path

    _sys.path.insert(0, str(_Path(__file__).resolve().parent.parent / "scripts"))
    import verify_weights as VW

    ok, offender = VW.verify(cfg, names=["engine_model.json", "window_scaler.pkl"])
    if not ok:
        raise RuntimeError(
            f"model-weight SHA-256 mismatch ({offender}) — refusing to write ledger "
            "records (M9.3). Re-record with scripts/verify_weights.py --record after "
            "an intentional retrain."
        )

    flows, wf = _windows_from_input(cfg, csv_path, anonymizer)
    feat_cols = W.feature_columns(cfg)
    X = scaler.transform(wf[feat_cols].to_numpy(dtype=np.float64)).astype(np.float32)
    probs = booster.predict_proba(X)[:, 1]

    explainer = EX.ShapExplainer(booster, feat_cols)
    window_sec = cfg["windows"]["window_seconds"]
    stages = cfg["stages"]

    ledger = Ledger(out_dir / "audit_chain.jsonl", checkpoint_path=out_dir / "checkpoints.jsonl")

    forecasts = []
    alert_rows = np.flatnonzero(probs >= threshold)
    tops = explainer.top_features(X[alert_rows], k=5) if len(alert_rows) else []
    for local_i, row in enumerate(alert_rows):
        host = str(wf.iloc[row]["host"])
        ws = float(wf.iloc[row]["window_start"])
        feats = {c: float(wf.iloc[row][c]) for c in feat_cols}
        # stage: the engine model is binary attack/benign; stage is inferred
        # from the observed pattern via the technique rules' parent stage guess.
        stage = _infer_stage(feats, stages)
        tech = EX.map_technique(stage, feats)
        obj = {
            "host": host,
            "window_start": ws,
            "probability": float(probs[row]),
            "stage": stage,
            "technique": tech["technique"],
            "technique_name": tech["name"],
            "top_features": tops[local_i],
            "flagged_flows": EX.flagged_flows(flows, host, ws, window_sec),
            "estimated_lead_seconds": None,
        }
        _validate(obj)
        forecasts.append(obj)
        ledger.append({"host": host, "window_start": ws, "probability": obj["probability"],
                       "stage": stage, "technique": tech["technique"]})
    ledger.checkpoint()

    (out_dir / "forecasts.json").write_text(json.dumps(forecasts, indent=2), encoding="utf-8")
    return {
        "n_flows": int(len(flows)),
        "n_host_windows": int(len(wf)),
        "n_alerts": int(len(alert_rows)),
        "forecasts": forecasts,
        "threshold": threshold,
    }


def _infer_stage(feats: dict, stages: list[str]) -> str:
    """Coarse stage from named-feature pattern (the engine model is binary;
    stage granularity comes from the interpretable rules)."""
    if feats.get("sent_bytes", 0) > 1_000_000 and feats.get("distinct_dst_ips", 0) <= 2:
        return "exfiltration"
    if feats.get("distinct_dst_ips", 0) > 20 or feats.get("sequential_port_ratio", 0) > 0.5:
        return "recon"
    if feats.get("syn", 0) > 50 and feats.get("ack", 0) < feats.get("syn", 0):
        return "initial_access"
    if feats.get("sent_pkts", 0) > 500:
        return "impact"
    return "c2"


def _validate(obj: dict) -> None:
    import jsonschema

    jsonschema.validate(obj, OUTPUT_SCHEMA)


def _maybe_anonymizer(cfg):
    from data.anonymize import Anonymizer

    try:
        return Anonymizer.from_config(cfg)
    except RuntimeError:
        # No HMAC key in the environment: role features fall back to 0 (the
        # engine still runs; identity is simply not derived). The LEDGER's
        # pseudonymisation uses its own key and is unaffected.
        return None
