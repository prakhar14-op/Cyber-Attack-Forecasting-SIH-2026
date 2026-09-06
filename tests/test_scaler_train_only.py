"""Anti-leakage (BUILD_PLAN M1.6): the persisted scaler was fitted on train only.

Refitting a scaler on the train split alone must reproduce the persisted
statistics exactly — any difference means validation/test rows leaked into
normalisation.
"""

from __future__ import annotations

import pickle

import numpy as np
import pytest

from configs import load_config, resolve_path
from tests._stubs import require_attr, require_file, require_module


def _scaler_refit_inputs_present() -> bool:
    """The persisted scaler and the split map must exist to refit-and-compare.
    Both are gitignored / dataset-derived (CLAUDE.md), so a bare checkout skips
    rather than failing — run the M1 data pipeline + `--fit-scaler` to enable it."""
    cfg = load_config("data")
    return (resolve_path(cfg["paths"]["scaler"]).exists()
            and resolve_path(cfg["paths"]["splits"]).exists())


@pytest.mark.skipif(
    not _scaler_refit_inputs_present(),
    reason="persisted scaler / split map not built — needs the extracted dataset "
           "+ `python -m data.flow_features --fit-scaler` (see README bootstrap)",
)
def test_persisted_scaler_statistics_match_train_split_refit(data_cfg):
    require_file(data_cfg["paths"]["splits"], "M1.5")
    scaler_path = require_file(data_cfg["paths"]["scaler"], "M1.6")
    flow_features = require_module("data.flow_features", "M1.6")
    fit_scaler = require_attr(flow_features, "fit_scaler", "M1.6")

    with open(scaler_path, "rb") as fh:
        persisted = pickle.load(fh)

    refit = fit_scaler(data_cfg, split="train")

    np.testing.assert_array_equal(
        persisted.mean_, refit.mean_, err_msg="scaler means differ from a train-only fit"
    )
    np.testing.assert_array_equal(
        persisted.scale_, refit.scale_, err_msg="scaler scales differ from a train-only fit"
    )
