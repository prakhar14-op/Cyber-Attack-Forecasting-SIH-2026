"""Pure logic behind the Streamlit panels (M10) — importable and testable.

The UI module (app/streamlit_app.py) is a thin shell over these functions so the
demo's behaviour can be tested without a browser, and so `test_offline`
conditions (sockets blocked) exercise real code paths.
"""

from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import pandas as pd

from configs import load_config, resolve_path


def run_pipeline(input_path, out_dir, fpr_budget: float = 0.01) -> dict:
    """Full offline pipeline on one uploaded file (M10.1)."""
    from engine import predict

    return predict.predict_file(input_path, out_dir=out_dir, fpr_budget=fpr_budget)


def timeline_frame(result: dict, cfg: dict | None = None) -> pd.DataFrame:
    """Per-window max probability across hosts + the network-level score.

    CLAUDE.md fixes the network score as the MAX over host scores in a window.
    """
    cfg = cfg or load_config("data")
    rows = [
        {"window_start": f["window_start"], "host": f["host"],
         "probability": f["probability"], "stage": f["stage"]}
        for f in result["forecasts"]
    ]
    if not rows:
        return pd.DataFrame(columns=["window_start", "probability", "stage", "host"])
    df = pd.DataFrame(rows)
    idx = df.groupby("window_start")["probability"].idxmax()
    return df.loc[idx].sort_values("window_start").reset_index(drop=True)


def host_ranking(result: dict, top: int = 10) -> pd.DataFrame:
    """Hosts ranked by peak forecast probability (what the analyst triages)."""
    if not result["forecasts"]:
        return pd.DataFrame(columns=["host", "peak_probability", "alerts", "stage"])
    df = pd.DataFrame([
        {"host": f["host"], "probability": f["probability"], "stage": f["stage"]}
        for f in result["forecasts"]
    ])
    g = df.groupby("host").agg(
        peak_probability=("probability", "max"),
        alerts=("probability", "size"),
        stage=("stage", lambda s: s.mode().iloc[0]),
    ).reset_index()
    return g.sort_values("peak_probability", ascending=False).head(top).reset_index(drop=True)


def explanation_for(result: dict, host: str) -> dict | None:
    """The highest-probability alert for a host, with its named-feature
    explanation, technique and flagged flows (M10.3)."""
    hits = [f for f in result["forecasts"] if f["host"] == host]
    if not hits:
        return None
    return max(hits, key=lambda f: f["probability"])


def what_if_remove_host(input_path, out_dir, host_to_remove: str, fpr_budget=0.01) -> dict:
    """M10.4 / M8.7: re-run the pipeline with one host ablated so the analyst can
    see that host's contribution.

    The ablation happens INSIDE the engine on the already-extracted features
    (predict_file(exclude_host=...)), so the input file is never re-parsed — a
    PCAP stays on the full-feature path instead of being (wrongly) read as a CSV,
    and the before/after curves share feature semantics."""
    from engine import predict

    after = predict.predict_file(
        input_path, out_dir=Path(out_dir) / "whatif",
        fpr_budget=fpr_budget, exclude_host=host_to_remove,
    )
    return {"removed_host": host_to_remove, "after": after}


def network_graph_layout(result: dict, max_nodes: int = 60, seed: int = 1337) -> dict:
    """3D force-directed layout of the host graph in result['graph'] (M10.8).

    Pure and offline: networkx computes the spring layout; the app renders it with
    Plotly. Nodes are ranked by risk (peak probability, then alerts, then flow
    degree) and trimmed to `max_nodes` for readability — never silently: the
    returned dict reports `shown`/`total`/`truncated` so the UI can say so.
    """
    import networkx as nx

    g = result.get("graph") or {"nodes": [], "edges": []}
    nodes = {n["ip"]: n for n in g["nodes"]}
    edges = g["edges"]

    degree: dict[str, int] = {}
    for e in edges:
        degree[e["src"]] = degree.get(e["src"], 0) + e["weight"]
        degree[e["dst"]] = degree.get(e["dst"], 0) + e["weight"]

    ranked = sorted(
        nodes.values(),
        key=lambda n: (n["peak_prob"], n["n_alerts"], degree.get(n["ip"], 0)),
        reverse=True,
    )
    keep = {n["ip"] for n in ranked[:max_nodes]}
    kept_edges = [e for e in edges if e["src"] in keep and e["dst"] in keep]

    G = nx.Graph()
    G.add_nodes_from(keep)
    for e in kept_edges:
        G.add_edge(e["src"], e["dst"])

    n = G.number_of_nodes()
    if n == 0:
        return {"nodes": [], "edges": [], "shown": 0, "total": len(nodes), "truncated": False}

    # Lay out by TOPOLOGY, not flow volume: weight=None so a heavy edge (e.g. a
    # 1300-flow scan) does not collapse its endpoints onto each other, and a
    # larger optimal distance k spreads a small graph so nodes stay legible.
    pos = nx.spring_layout(G, dim=3, seed=seed, weight=None,
                           k=(2.5 / (n ** 0.5)) if n > 1 else None, iterations=200)
    out_nodes = []
    for ip in keep:
        x, y, z = (float(c) for c in pos[ip])
        n = nodes[ip]
        out_nodes.append({
            "ip": ip, "x": x, "y": y, "z": z,
            "peak_prob": float(n["peak_prob"]), "n_alerts": int(n["n_alerts"]),
            "internal": n.get("internal"), "degree": int(degree.get(ip, 0)),
        })
    out_edges = []
    for e in kept_edges:
        a, b = pos[e["src"]], pos[e["dst"]]
        out_edges.append({
            "src": e["src"], "dst": e["dst"], "weight": int(e["weight"]),
            "risk": float(e["risk"]),
            "x0": float(a[0]), "y0": float(a[1]), "z0": float(a[2]),
            "x1": float(b[0]), "y1": float(b[1]), "z1": float(b[2]),
        })
    return {"nodes": out_nodes, "edges": out_edges,
            "shown": len(keep), "total": len(nodes), "truncated": len(nodes) > len(keep)}


def ledger_status(out_dir) -> dict:
    """Chain length, head, checkpoint match and verification result (M10.5)."""
    from ledger import verify_cli
    from ledger.ledger import Ledger

    chain = Path(out_dir) / "audit_chain.jsonl"
    cps = Path(out_dir) / "checkpoints.jsonl"
    if not chain.exists():
        return {"exists": False}
    led = Ledger(chain, checkpoint_path=cps)
    ok, first_bad = verify_cli.verify(chain, cps)
    n = sum(1 for line in chain.read_text(encoding="utf-8").splitlines() if line.strip())
    return {
        "exists": True, "records": n, "verified": ok, "first_bad_index": first_bad,
        "anchored": led.verify_against_checkpoints(),
    }


def tamper_ledger(out_dir, index: int = 0, field: str = "probability") -> bool:
    """Demo beat 5: edit one record in place so the verifier can catch it."""
    chain = Path(out_dir) / "audit_chain.jsonl"
    lines = chain.read_text(encoding="utf-8").splitlines()
    if index >= len(lines):
        return False
    rec = json.loads(lines[index])
    rec[field] = 0.999999
    lines[index] = json.dumps(rec, sort_keys=True, separators=(",", ":"))
    chain.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return True


def results_card() -> pd.DataFrame:
    """M10.6: the headline comparison, read from results/ — never hardcoded."""
    from eval import ablation

    return ablation.build_table(budget=0.01)


def forecast_horizons() -> pd.DataFrame:
    """Per-horizon forecasting rows from results/forecast.json (M7)."""
    cfg_eval = load_config("eval")
    p = resolve_path(cfg_eval["paths"]["results_dir"]) / "forecast.json"
    if not p.exists():
        return pd.DataFrame()
    d = json.loads(p.read_text(encoding="utf-8"))
    rows = []
    for k in sorted(d["horizons"], key=int):
        b = d["horizons"][k]
        pt = b["fpr_0.01"]
        rows.append({
            "horizon_k": int(k), "seconds_ahead": int(k) * 5,
            "test_AUROC": round(b["auroc_test"], 3),
            "median_lead_s": round(pt["lead_time_median"]),
            "episodes": f"{pt['episodes_detected']}/{pt['episodes_total']}",
        })
    return pd.DataFrame(rows)
