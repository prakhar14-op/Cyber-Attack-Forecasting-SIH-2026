"""Helpers for milestone-gated tests.

The seven required tests are written against the final APIs before those APIs
exist. Until the owning milestone lands, each test must FAIL (never error, never
skip) with a message naming that milestone — `pytest -q` at M0 shows 7 failures,
0 errors (BUILD_PLAN M0.5).
"""

from __future__ import annotations

import importlib
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent


def require_module(dotted: str, milestone: str):
    """Import a project module, or fail the test naming the milestone that ships it."""
    try:
        return importlib.import_module(dotted)
    except ModuleNotFoundError as exc:
        missing = exc.name or ""
        if (
            missing == dotted
            or dotted.startswith(missing + ".")
            or missing.startswith(dotted + ".")
        ):
            pytest.fail(f"{dotted} is not implemented yet — lands in {milestone}", pytrace=False)
        raise  # a genuinely missing third-party dependency is an environment bug


def require_attr(module, name: str, milestone: str):
    """Fetch an attribute from a module, or fail naming the owning milestone."""
    if not hasattr(module, name):
        pytest.fail(
            f"{module.__name__}.{name} is not implemented yet — lands in {milestone}",
            pytrace=False,
        )
    return getattr(module, name)


def require_file(repo_relative: str, milestone: str) -> Path:
    """Return a repo file's Path, or fail naming the milestone that creates it."""
    path = REPO_ROOT / repo_relative
    if not path.exists():
        pytest.fail(
            f"{repo_relative} does not exist yet — created in {milestone}", pytrace=False
        )
    return path
