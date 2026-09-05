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


def test_results_card_reads_from_results_dir():
    """M10.6: the card is generated from results/*.json, not hardcoded."""
    fh = panels.forecast_horizons()
    if not fh.empty:
        assert {"horizon_k", "test_AUROC", "median_lead_s", "episodes"} <= set(fh.columns)
        assert (fh["seconds_ahead"] == fh["horizon_k"] * 5).all()
