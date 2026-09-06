"""M8: the offline prediction engine — output schema, technique mapping,
named-feature explanations, ledger integration.

The end-to-end offline run is covered by test_offline/test_smoke; these pin the
engine's internals without needing the socket guard.
"""

from __future__ import annotations

import importlib.util

import pytest

from engine import explain as EX


def test_technique_map_is_named_and_data_grounded():
    # recon with a broad scan -> T1046; large exfil transfer -> T1048.
    assert EX.map_technique("recon", {"distinct_dst_ips": 40})["technique"] == "T1046"
    assert EX.map_technique("initial_access", {"syn": 100})["technique"] == "T1110"
    assert EX.map_technique("impact", {})["technique"] == "T1498"
    big = EX.map_technique("exfiltration", {"sent_bytes": 5_000_000})
    assert big["technique"] == "T1048"
    # benign has no technique
    assert EX.map_technique("benign", {})["technique"] is None


def test_output_schema_rejects_embedding_dimensions():
    """Explanations must name real features, never embedding indices (PS)."""
    from engine.predict import OUTPUT_SCHEMA, _validate

    good = {
        "host": "abc", "window_start": 10.0, "probability": 0.9, "stage": "recon",
        "technique": "T1046", "technique_name": "Network Service Discovery",
        "top_features": [{"feature": "distinct_dst_ips", "value": 40.0, "contribution": 1.2}],
        "flagged_flows": [],
    }
    _validate(good)  # must not raise

    bad = dict(good, probability=1.5)  # out of [0,1]
    with pytest.raises(Exception):
        _validate(bad)

    bad2 = dict(good, top_features=[{"value": 1.0, "contribution": 0.2}])  # no 'feature' name
    with pytest.raises(Exception):
        _validate(bad2)


@pytest.mark.skipif(
    not (importlib.util.find_spec("xgboost")
         and __import__("configs").resolve_path("artifacts/engine_model.json").exists()),
    reason="engine model not trained — run python -m engine.train_engine",
)
def test_predict_file_produces_explained_forecasts_and_verifiable_ledger(fixture_csv, tmp_path):
    from engine import predict
    from ledger import verify_cli

    result = predict.predict_file(fixture_csv, out_dir=tmp_path)

    assert result["n_flows"] == 1000
    assert result["forecasts"], "engine produced no forecasts"
    for f in result["forecasts"][:20]:
        assert 0.0 <= f["probability"] <= 1.0
        assert f["stage"] in __import__("configs").load_config("data")["stages"]
        # every top feature is a NAMED feature, not an index
        assert all(isinstance(t["feature"], str) and not t["feature"].isdigit()
                   for t in f["top_features"])

    chain = tmp_path / "audit_chain.jsonl"
    assert chain.exists()
    # no raw IP may appear in the ledger (keyed-HMAC pseudonyms only)
    text = chain.read_text(encoding="utf-8")
    assert "172.31." not in text and "192.168." not in text
    ok, first_bad = verify_cli.verify(chain)
    assert ok, f"ledger failed verification at {first_bad}"


@pytest.mark.skipif(
    not (importlib.util.find_spec("xgboost")
         and __import__("configs").resolve_path("artifacts/engine_model.json").exists()
         and __import__("configs").resolve_path("app/assets/synthetic_demo.pcap").exists()),
    reason="engine model or synthetic demo pcap not built",
)
def test_pcap_input_uses_full_features_and_verifies(tmp_path):
    """The engine's PCAP path runs the full extractor (real packet features) and
    produces meaningful, non-degenerate forecasts + a verifiable ledger."""
    from configs import resolve_path
    from engine import predict
    from ledger import verify_cli

    pcap = resolve_path("app/assets/synthetic_demo.pcap")
    result = predict.predict_file(pcap, out_dir=tmp_path)
    assert result["forecasts"], "PCAP path produced no forecasts"
    # a PCAP has real packet features, so at least one alert is confidently high
    assert max(f["probability"] for f in result["forecasts"]) > 0.5
    ok, first_bad = verify_cli.verify(tmp_path / "audit_chain.jsonl")
    assert ok, f"ledger failed at {first_bad}"
