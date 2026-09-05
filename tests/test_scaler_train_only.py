"""Anti-leakage (BUILD_PLAN M1.6): the persisted scaler was fitted on train only.

Refitting a scaler on the train split alone must reproduce the persisted
statistics exactly — any difference means validation/test rows leaked into
normalisation.
"""

from __future__ import annotations

import pickle

import numpy as np

from tests._stubs import require_attr, require_file, require_module


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
