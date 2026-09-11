"""Shared fixtures. Paths come from configs/data.yaml, never from literals."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tests.net_guard import network_disabled  # noqa: E402


TEST_LEDGER_KEY = "test-ledger-key-not-a-secret"


@pytest.fixture(scope="session", autouse=True)
def ledger_key_env() -> str:
    """ledger/ledger.py refuses to construct without SIH26_LEDGER_KEY (F36), so any
    test that reaches the ledger — directly, or through engine.predict / app.panels /
    scripts — needs one in the environment. Without this those tests raise
    RuntimeError on a machine that has the trained artifacts; they only skip here
    because artifacts/ is absent.

    `setdefault`, never overwrite: an operator running the suite with the real key
    exported must keep it, so a run on the demo machine verifies ledgers under the
    key they were written with. Tests that prove the refusal itself
    (test_ledger_tamper.test_ledger_refuses_to_construct_without_a_key) monkeypatch
    the variable away for their own duration, which still works on top of this.
    """
    from ledger.ledger import KEY_ENV_VAR

    os.environ.setdefault(KEY_ENV_VAR, TEST_LEDGER_KEY)
    return os.environ[KEY_ENV_VAR]


@pytest.fixture(scope="session")
def data_cfg() -> dict:
    from configs import load_config

    return load_config("data")


@pytest.fixture(scope="session")
def fixture_csv(data_cfg) -> Path:
    from configs import resolve_path

    path = resolve_path(data_cfg["paths"]["fixture_csv"])
    assert path.exists(), f"committed fixture missing: {path}"
    return path


@pytest.fixture
def no_network():
    """Run the test body with every socket primitive raising NetworkAttempt."""
    with network_disabled():
        yield
