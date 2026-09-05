"""M3.1/M3.5: window feature matrix, stable feature order, padding masks.

Uses a tiny synthetic day written to a tmp interim dir — never the out-of-repo
extracted data — so the tests run anywhere.
"""

from __future__ import annotations

import numpy as np
import pandas as pd
import pytest

from data import windows as W
from data.anonymize import Anonymizer

FLOW_SCHEMA_ORDER = None  # filled from cfg in the fixture


@pytest.fixture
def synthetic_day(data_cfg, tmp_path):
    """Write one day's flow + packet parquet into a tmp interim dir; return a
    cfg pointing at it plus the day string."""
    day = "2018-02-14"
    interim = tmp_path / "interim" / day
    (interim / "flows").mkdir(parents=True)
    (interim / "packets").mkdir(parents=True)

    base = 1_518_600_000  # arbitrary epoch inside the day
    schema = list(data_cfg["schema"].keys())
    # Two hosts, a few flows each, spread across ~30 s (=> several windows).
    rows = []
    for i, (src, dst, sport, dport) in enumerate(
        [("172.31.0.5", "8.8.8.8", 50000, 443),
         ("172.31.0.5", "8.8.8.8", 50001, 443),
         ("9.9.9.9", "172.31.0.9", 40000, 22),
         ("9.9.9.9", "172.31.0.9", 40001, 22)]
    ):
        r = {c: 0 for c in schema}
        r["timestamp"] = pd.to_datetime(base + i * 7, unit="s")
        r["src_ip"], r["dst_ip"] = src, dst
        r["src_port"], r["dst_port"], r["protocol"] = sport, dport, 6
        r["fwd_bytes"], r["bwd_bytes"], r["fwd_pkts"], r["bwd_pkts"] = 100, 50, 2, 1
        r["syn"], r["init_win_fwd"], r["init_win_bwd"] = 1, 8192, 8192
        r["label"] = "unlabeled"
        rows.append(r)
    flows = pd.DataFrame(rows)[schema]
    flows.to_parquet(interim / "flows" / "m.parquet", index=False)

    stride = data_cfg["windows"]["stride_seconds"]
    # The packet parquet now carries BOTH the 17 packet-stat fields and the 11
    # window-bounded sent fields (decision 003) — build_window_features reads
    # them directly and no longer aggregates flows.
    pkt_fields = list(data_cfg["packet_features"]["fields"]) + list(
        data_cfg["packet_features"]["sent_fields"]
    )
    pkt_rows = []
    for src in ("172.31.0.5", "9.9.9.9"):
        for k in range(3):
            wid = base // stride + k
            row = {"src_ip": src, "window_id": wid}
            for f in pkt_fields:
                row[f] = 1.0
            pkt_rows.append(row)
    pd.DataFrame(pkt_rows).to_parquet(interim / "packets" / "m.parquet", index=False)

    cfg = {**data_cfg, "paths": {**data_cfg["paths"], "interim_dir": str(tmp_path / "interim")}}
    return cfg, day


def test_feature_columns_stable_and_unique(data_cfg):
    cols = W.feature_columns(data_cfg)
    assert len(cols) == len(set(cols)), "feature names must be unique"
    # packet-stat fields and window-bounded sent fields are all present
    for f in data_cfg["packet_features"]["fields"]:
        assert f in cols
    for f in data_cfg["packet_features"]["sent_fields"]:
        assert f in cols
    assert "server_port_ratio" in cols, "server_port_ratio is now a window-bounded feature"
    assert cols[-2:] == ["internal", "net24_bucket"], (
        "the two static role features must be last, in fixed order"
    )
    # order is a pure function of config — calling twice gives the same list
    assert cols == W.feature_columns(data_cfg)


def test_build_window_features_joins_flow_and_packet(synthetic_day):
    cfg, day = synthetic_day
    anon = Anonymizer(b"k", cfg["anonymisation"])
    wf = W.build_window_features(cfg, day, anonymizer=anon)

    assert list(wf.columns) == W._META_COLS + W.feature_columns(cfg)
    assert set(wf["host"]) == {"172.31.0.5", "9.9.9.9"}
    feats = wf[W.feature_columns(cfg)].to_numpy(dtype=float)
    assert np.isfinite(feats).all(), "no NaN/inf may reach the feature matrix"
    # internal/external role feature resolved correctly
    assert wf.loc[wf["host"] == "172.31.0.5", "internal"].iloc[0] == 1
    assert wf.loc[wf["host"] == "9.9.9.9", "internal"].iloc[0] == 0
    # window_start is window_id * stride
    stride = cfg["windows"]["stride_seconds"]
    assert (wf["window_start"] == wf["window_id"] * stride).all()


def test_pseudonymise_replaces_host_with_hmac(synthetic_day):
    cfg, day = synthetic_day
    anon = Anonymizer(b"k", cfg["anonymisation"])
    wf = W.build_window_features(cfg, day, anonymizer=anon, with_pseudonyms=True)
    assert "172.31.0.5" not in set(wf["host"]), "real IP must not survive pseudonymisation"
    assert all(len(h) == 16 for h in wf["host"].unique())


def test_pad_sequence_masks_short_and_truncates_long():
    feats = np.arange(5 * 3, dtype=np.float32).reshape(5, 3)

    padded, mask = W.pad_sequence(feats, max_len=8)
    assert padded.shape == (8, 3) and mask.shape == (8,)
    assert mask[:3].all() and not mask[3:].any(), "pad positions (front) are masked True"
    assert np.array_equal(padded[3:], feats), "real windows sit at the end (causal)"
    assert (padded[:3] == 0).all()

    padded2, mask2 = W.pad_sequence(feats, max_len=3)
    assert padded2.shape == (3, 3) and not mask2.any()
    assert np.array_equal(padded2, feats[-3:]), "keep the most recent windows"


def test_build_host_sequences_orders_and_pads(synthetic_day):
    cfg, day = synthetic_day
    anon = Anonymizer(b"k", cfg["anonymisation"])
    wf = W.build_window_features(cfg, day, anonymizer=anon)
    seqs = W.build_host_sequences(wf, cfg)

    max_len = cfg["windows"]["max_sequence_windows"]
    n_feat = len(W.feature_columns(cfg))
    for host, s in seqs.items():
        assert s["features"].shape == (max_len, n_feat)
        assert s["mask"].shape == (max_len,)
        # a valid (non-pad) position exists for every host that had windows
        assert (~s["mask"]).any()
