"""Anti-leakage (BUILD_PLAN M1.5): split by day, never randomly.

No day may appear in two splits, no split may be empty, and no day may be listed
twice — whole attack episodes stay inside one split.
"""

from __future__ import annotations

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
