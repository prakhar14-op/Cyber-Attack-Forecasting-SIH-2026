"""Shared fixtures. Paths come from configs/data.yaml, never from literals."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tests.net_guard import network_disabled  # noqa: E402


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
