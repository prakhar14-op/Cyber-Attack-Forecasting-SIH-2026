"""M10.7: the app's logic runs under test_offline conditions (sockets blocked).

Streamlit's UI shell is not unit-testable, so all behaviour lives in
app/panels.py and is exercised here — including the ledger tamper/re-verify
demo beat and the what-if ablation.
"""

from __future__ import annotations

import importlib.util

import pytest

from app import panels


def _engine_ready() -> bool:
    from configs import resolve_path

    return (importlib.util.find_spec("xgboost") is not None
            and resolve_path("artifacts/engine_model.json").exists())


pytestmark = pytest.mark.skipif(
    not _engine_ready(), reason="engine model not trained — run python -m engine.train_engine"
)


@pytest.fixture(scope="module")
def run(fixture_csv, tmp_path_factory):
    out = tmp_path_factory.mktemp("apprun")
    return panels.run_pipeline(fixture_csv, out), out


def test_pipeline_and_panels_work_offline(no_network, fixture_csv, tmp_path):
    """M10.7 + M10.1: the whole app path runs with every socket blocked."""
    result = panels.run_pipeline(fixture_csv, tmp_path)
    assert result["n_flows"] == 1000
    assert result["forecasts"], "app pipeline produced no forecasts"

    tl = panels.timeline_frame(result)
    assert not tl.empty
    # the network score is the MAX over hosts in a window (CLAUDE.md)
    assert tl["window_start"].is_unique
    assert (tl["probability"] <= 1.0).all()

    ranking = panels.host_ranking(result)
    assert not ranking.empty
    assert ranking["peak_probability"].is_monotonic_decreasing

    exp = panels.explanation_for(result, ranking.iloc[0]["host"])
    assert exp and exp["top_features"]
    assert all(isinstance(t["feature"], str) for t in exp["top_features"])


def test_ledger_panel_tamper_then_detect(run):
    """Demo beat 5 (M10.5): verify -> tamper -> re-verify catches it."""
    result, out = run
    before = panels.ledger_status(out)
    assert before["exists"] and before["verified"] and before["records"] > 0

    assert panels.tamper_ledger(out, index=0)
    after = panels.ledger_status(out)
    assert not after["verified"], "tampered ledger must fail verification"
    assert after["first_bad_index"] == 0


def test_what_if_remove_host_ablates_that_host(run, fixture_csv, tmp_path):
    """M10.4: removing a host drops its own alerts and never adds any."""
    result, _ = run
    ranking = panels.host_ranking(result)
    top = str(ranking.iloc[0]["host"])

    wi = panels.what_if_remove_host(fixture_csv, tmp_path, top)
    after = wi["after"]
    assert all(f["host"] != top for f in after["forecasts"]), "removed host still alerts"
    assert after["n_alerts"] <= result["n_alerts"], "ablation must not add alerts"


@pytest.mark.skipif(
    not __import__("configs").resolve_path("app/assets/synthetic_demo.pcap").exists(),
    reason="synthetic demo pcap not built",
)
def test_what_if_on_pcap_input_stays_on_full_path(tmp_path):
    """Regression: the what-if on a PCAP must ablate on the extracted features,
    not re-read the .pcap as a CSV (which raised UnicodeDecodeError)."""
    from configs import resolve_path

    pcap = resolve_path("app/assets/synthetic_demo.pcap")
    result = panels.run_pipeline(pcap, tmp_path / "main")
    top = str(panels.host_ranking(result).iloc[0]["host"])

    wi = panels.what_if_remove_host(pcap, tmp_path / "wi", top)  # must not raise
    after = wi["after"]
    assert all(f["host"] != top for f in after["forecasts"])
    assert after["n_alerts"] < result["n_alerts"], "the top host drove alerts"


def test_pipeline_result_carries_a_host_graph(run):
    """M10.8: predict_file attaches a nodes+edges host graph for the 3D view."""
    result, _ = run
    g = result.get("graph")
    assert g and g["nodes"], "result must carry a host graph"
    assert all({"ip", "peak_prob", "n_alerts"} <= set(n) for n in g["nodes"])
    assert all({"src", "dst", "weight", "risk"} <= set(e) for e in g["edges"])


def test_network_graph_layout_positions_edges_and_ranks():
    """M10.8: the 3D layout assigns coordinates, keeps edge risk, is deterministic,
    and trims to the highest-risk hosts without silently hiding the count."""
    result = {"graph": {
        "nodes": [
            {"ip": "10.0.0.1", "peak_prob": 0.90, "n_alerts": 3, "internal": 1},
            {"ip": "10.0.0.2", "peak_prob": 0.00, "n_alerts": 0, "internal": 1},
            {"ip": "8.8.8.8", "peak_prob": 0.00, "n_alerts": 0, "internal": 0},
        ],
        "edges": [
            {"src": "10.0.0.1", "dst": "10.0.0.2", "weight": 5, "risk": 0.90},
            {"src": "10.0.0.1", "dst": "8.8.8.8", "weight": 2, "risk": 0.90},
        ],
    }}
    layout = panels.network_graph_layout(result)
    assert layout["shown"] == 3 and not layout["truncated"]
    for n in layout["nodes"]:
        assert all(isinstance(n[c], float) for c in ("x", "y", "z"))
    for e in layout["edges"]:
        assert {"x0", "y0", "z0", "x1", "y1", "z1"} <= set(e)
    assert any(e["risk"] == 0.90 for e in layout["edges"])
    # deterministic under the fixed seed
    again = panels.network_graph_layout(result)
    assert [n["x"] for n in layout["nodes"]] == [n["x"] for n in again["nodes"]]

    # trimming reports what it dropped
    many = {"graph": {
        "nodes": [{"ip": f"10.0.0.{i}", "peak_prob": i / 100, "n_alerts": 0,
                   "internal": 1} for i in range(1, 91)],
        "edges": [],
    }}
    trimmed = panels.network_graph_layout(many, max_nodes=60)
    assert trimmed["shown"] == 60 and trimmed["total"] == 90 and trimmed["truncated"]


def test_results_card_reads_from_results_dir():
    """M10.6: the card is generated from results/*.json, not hardcoded."""
    fh = panels.forecast_horizons()
    if not fh.empty:
        assert {"horizon_k", "test_AUROC", "median_lead_s", "episodes"} <= set(fh.columns)
        assert (fh["seconds_ahead"] == fh["horizon_k"] * 5).all()
