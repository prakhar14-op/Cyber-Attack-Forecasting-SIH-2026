"""Hard constraint #1 (CLAUDE.md): fully offline.

With every socket primitive blocked, inference over the committed fixture and
ledger verification must run end to end. Passing this test is what "offline"
means for the rest of the project (BUILD_PLAN M0.6).
"""

from __future__ import annotations

import socket

import pytest

from tests._stubs import engine_artifacts_present, require_attr, require_module
from tests.net_guard import NetworkAttempt

pytestmark = pytest.mark.skipif(
    not engine_artifacts_present(),
    reason="engine artifacts not built — run `python -m engine.train_engine` "
           "(they are gitignored; see README bootstrap)",
)


def test_inference_and_ledger_verify_run_end_to_end_with_sockets_blocked(
    no_network, fixture_csv, tmp_path
):
    # The guard itself must bite: any socket construction or DNS lookup raises.
    with pytest.raises(NetworkAttempt):
        socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    with pytest.raises(NetworkAttempt):
        socket.getaddrinfo("example.com", 443)

    predict = require_module("engine.predict", "M8")
    predict_file = require_attr(predict, "predict_file", "M8")
    verify_cli = require_module("ledger.verify_cli", "M9")
    verify = require_attr(verify_cli, "verify", "M9")

    result = predict_file(fixture_csv, out_dir=tmp_path)

    assert result["forecasts"], "inference produced no forecasts"

    chain_path = tmp_path / "audit_chain.jsonl"
    assert chain_path.exists(), "inference did not write the audit chain"

    ok, first_bad_index = verify(chain_path)
    assert ok, f"offline ledger verification failed at record {first_bad_index}"
