"""M5: temporal graph round-trip (5.1), memory reset between splits (5.3),
causal snapshots (edges land at flow END — decision-003 discipline), and the
sage fallback interface (5.4)."""

from __future__ import annotations

import numpy as np
import pandas as pd
import pytest

from configs import load_config
from data.anonymize import Anonymizer
from data.flow_features import canonical_numeric_columns


@pytest.fixture(scope="module")
def tgn_cfg():
    return load_config("train_tgn")


@pytest.fixture
def small_flows(data_cfg):
    """Three flows: two quick ones, one long-running (starts early, ends late)."""
    rows = []
    base = 1_500_000_000.0
    specs = [
        ("10.0.0.1", "10.0.0.2", base + 0.0, 2.0),     # ends base+2
        ("10.0.0.2", "10.0.0.3", base + 5.0, 1.0),     # ends base+6
        ("10.0.0.1", "10.0.0.3", base + 1.0, 60.0),    # LONG: ends base+61
    ]
    for src, dst, start, dur_s in specs:
        r = {c: 1.0 for c in data_cfg["schema"]}
        r["timestamp"] = pd.to_datetime(start, unit="s")
        r["src_ip"], r["dst_ip"] = src, dst
        r["src_port"], r["dst_port"], r["protocol"] = 40000, 80, 6
        r["duration"] = dur_s * 1e6  # canonical duration is microseconds
        r["label"] = "unlabeled"
        rows.append(r)
    return pd.DataFrame(rows)[list(data_cfg["schema"].keys())]


@pytest.fixture
def msg_scaler(data_cfg, small_flows):
    from sklearn.preprocessing import StandardScaler

    return StandardScaler().fit(
        small_flows[canonical_numeric_columns(data_cfg)].to_numpy(dtype=float)
    )


def test_build_events_roundtrip_and_end_time_stamping(
    data_cfg, tgn_cfg, small_flows, msg_scaler
):
    from models import tgn

    anon = Anonymizer(b"k", data_cfg["anonymisation"])
    events = tgn.build_events(
        {**tgn_cfg, "seed": tgn_cfg["seed"]}, small_flows, anon, epoch=0,
        msg_scaler=msg_scaler,
    )

    assert events.num_nodes == 3
    assert sorted(events.node_of_host.values()) == [0, 1, 2], "ids are a permutation"
    # time-ordered by END: quick flow (end+2) first, then end+6, then the long one (end+61)
    assert events.t.tolist() == [0, 4, 59]
    # round-trip: reverse the id map and recover the src hosts in end order
    id_to_host = {v: k for k, v in events.node_of_host.items()}
    assert [id_to_host[i] for i in events.src.tolist()] == ["10.0.0.1", "10.0.0.2", "10.0.0.1"]
    assert events.msg.shape == (3, len(canonical_numeric_columns(data_cfg)))


def test_memory_reset_between_splits(data_cfg, tgn_cfg, small_flows, msg_scaler):
    import torch

    from models import tgn

    anon = Anonymizer(b"k", data_cfg["anonymisation"])
    events = tgn.build_events(tgn_cfg, small_flows, anon, 0, msg_scaler)
    enc = tgn.build_model(tgn_cfg, num_nodes=events.num_nodes, msg_dim=events.msg.shape[1])

    # A fresh encoder with identical weights is the reference state.
    fresh = tgn.build_model(tgn_cfg, num_nodes=events.num_nodes, msg_dim=events.msg.shape[1])
    fresh.load_state_dict(enc.state_dict())
    with torch.no_grad():
        mem_fresh, _ = fresh.memory(torch.arange(events.num_nodes))

    enc.memory.update_state(events.src, events.dst, events.t, events.msg)
    with torch.no_grad():
        mem_after, _ = enc.memory(torch.arange(events.num_nodes))
    assert not torch.equal(mem_after, mem_fresh), "memory must move after events"

    enc.reset()
    with torch.no_grad():
        mem_reset, _ = enc.memory(torch.arange(events.num_nodes))
    # M5.3: after reset the read must be BIT-IDENTICAL to a never-used encoder —
    # nothing of the processed events (train state) may survive into test.
    assert torch.equal(mem_reset, mem_fresh), (
        "M5.3: post-reset memory differs from a fresh encoder — train state leaked"
    )


def test_snapshot_is_causal_wrt_flow_end(data_cfg, tgn_cfg, small_flows, msg_scaler):
    """The long flow (ends at +61) must NOT affect a readout at +20, and must
    affect one at +70 — edges land only once the flow has completed."""
    from models import tgn

    anon = Anonymizer(b"k", data_cfg["anonymisation"])
    events = tgn.build_events(tgn_cfg, small_flows, anon, 0, msg_scaler)
    enc = tgn.build_model(tgn_cfg, num_nodes=events.num_nodes, msg_dim=events.msg.shape[1])

    window_sec = data_cfg["windows"]["window_seconds"]
    base = events.t0
    readouts = pd.DataFrame(
        {
            "host": ["10.0.0.1", "10.0.0.1"],
            # window_start such that window END = start + window_sec hits +20 and +70
            "window_start": [base + 20 - window_sec, base + 70 - window_sec],
        }
    )
    embs = tgn.snapshot_embeddings(enc, events, readouts, tgn_cfg)

    # At +20 only the short flow from 10.0.0.1 (end +2) has landed; at +70 the
    # long one (end +61) has too — the embeddings must differ.
    assert not np.allclose(embs[0], embs[1]), "long flow must change the later snapshot"
    assert np.abs(embs[0]).sum() > 0, "the early snapshot still sees the short flow"


def test_sage_fallback_selected_by_config(tgn_cfg):
    from models import tgn

    sage = tgn.build_model({**tgn_cfg, "model": "sage"}, msg_dim=19)
    assert type(sage).__name__ == "SAGEHostEncoder"
    sage.reset()  # interface parity: must exist and be a no-op
