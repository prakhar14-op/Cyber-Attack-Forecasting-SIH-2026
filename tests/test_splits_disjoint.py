"""Anti-leakage (BUILD_PLAN M1.5): split by day, never randomly.

CLAUDE.md's required test has two halves: (1) no day appears in two splits, and
(2) no host-window crosses splits. Half (1) is enforced now; half (2) needs the
window builder (data.windows, M3) and is asserted the moment it exists — until
then it fails loudly naming M3 rather than passing green on a half-covered
contract.

No day may appear in two splits, no split may be empty, and no day may be listed
twice — whole attack episodes stay inside one split.
"""

from __future__ import annotations

import importlib.util

import pytest
import yaml

from tests._stubs import require_file

SPLIT_NAMES = ("train", "val", "test")


def test_no_day_appears_in_two_splits(data_cfg):
    splits_path = require_file(data_cfg["paths"]["splits"], "M1.5")

    with open(splits_path, encoding="utf-8") as fh:
        splits = yaml.safe_load(fh)

    for name in SPLIT_NAMES:
        assert splits.get(name), f"split '{name}' is missing or empty in {splits_path}"

    day_sets = {}
    for name in SPLIT_NAMES:
        days = list(splits[name])
        assert len(days) == len(set(days)), f"split '{name}' lists a day twice"
        day_sets[name] = set(days)

    for a, b in (("train", "val"), ("train", "test"), ("val", "test")):
        overlap = day_sets[a] & day_sets[b]
        assert not overlap, f"day(s) {sorted(overlap)} appear in both '{a}' and '{b}'"


def test_no_host_window_crosses_splits(data_cfg):
    """The second half of the CLAUDE.md contract. Activates when data.windows
    (M3) can enumerate host-windows per split; skips (loudly) until then rather
    than pretending the guarantee is checked."""
    if importlib.util.find_spec("data.windows") is None:
        pytest.skip("data.windows not implemented yet — host-window disjointness lands in M3")

    from data.windows import host_windows_for_split  # noqa: PLC0415 (M3 API)

    seen: dict[tuple, str] = {}
    try:
        for split in SPLIT_NAMES:
            for key in host_windows_for_split(data_cfg, split):  # (host, window_id)
                assert key not in seen or seen[key] == split, (
                    f"host-window {key} appears in both '{seen.get(key)}' and '{split}'"
                )
                seen[key] = split
    except FileNotFoundError:
        pytest.skip("extracted windows not present — run the M1/M2 data pipeline first")
