"""M3.2/M3.3: stage labelling with the measured UTC offset and no day-smearing."""

from __future__ import annotations

import datetime

import numpy as np
import pandas as pd

from data import timeline_labels as TL

# Synthetic timeline: one attack, local 10:00-11:00 on 2018-02-14, +4h -> UTC 14:00-15:00.
TIMELINE = {
    "timezone": {"utc_offset_hours": 4},
    "days": [
        {
            "date": "2018-02-14",
            "attacks": [
                {
                    "name": "TestScan",
                    "stage": "initial_access",
                    "start": "10:00",
                    "end": "11:00",
                    "attacker_ips": ["9.9.9.9"],
                    "victim_ips": ["172.31.0.5"],
                }
            ],
        }
    ],
}


def _utc_epoch(y, mo, d, h, mi):
    return datetime.datetime(y, mo, d, h, mi, tzinfo=datetime.timezone.utc).timestamp()


def _window_row(host, window_start):
    return {"host": host, "window_id": int(window_start // 5), "window_start": window_start}


def test_offset_applied_and_only_parties_in_interval_are_labelled(data_cfg):
    inside = _utc_epoch(2018, 2, 14, 14, 30)   # 14:30 UTC == 10:30 ADT, inside
    before = _utc_epoch(2018, 2, 14, 13, 30)   # 09:30 ADT, before the attack
    after = _utc_epoch(2018, 2, 14, 15, 30)    # 11:30 ADT, after

    wf = pd.DataFrame(
        [
            _window_row("9.9.9.9", inside),        # attacker, in interval -> stage
            _window_row("172.31.0.5", inside),     # victim, in interval   -> stage
            _window_row("9.9.9.9", before),        # attacker, before      -> benign
            _window_row("9.9.9.9", after),         # attacker, after       -> benign
            _window_row("1.2.3.4", inside),        # unrelated host        -> benign
        ]
    )

    labels = TL.label_windows(data_cfg, wf, timeline=TIMELINE)
    assert list(labels) == [
        "initial_access", "initial_access", "benign", "benign", "benign"
    ]


def test_window_overlap_is_inclusive_at_the_boundary(data_cfg):
    # A window starting 10 s before the attack still overlaps (15 s window).
    window_sec = data_cfg["windows"]["window_seconds"]
    attack_start = _utc_epoch(2018, 2, 14, 14, 0)
    overlapping = attack_start - (window_sec - 1)   # window covers [start, start+15) -> overlaps by 1 s
    disjoint = attack_start - window_sec            # window ends exactly at attack start -> no overlap

    wf = pd.DataFrame(
        [_window_row("9.9.9.9", overlapping), _window_row("9.9.9.9", disjoint)]
    )
    labels = TL.label_windows(data_cfg, wf, timeline=TIMELINE)
    assert labels.iloc[0] == "initial_access"
    assert labels.iloc[1] == "benign"


def test_higher_priority_stage_wins_on_overlapping_attacks(data_cfg):
    two_attacks = {
        "timezone": {"utc_offset_hours": 4},
        "days": [{"date": "2018-02-14", "attacks": [
            {"name": "A", "stage": "recon", "start": "10:00", "end": "11:00",
             "attacker_ips": ["9.9.9.9"], "victim_ips": []},
            {"name": "B", "stage": "impact", "start": "10:30", "end": "11:30",
             "attacker_ips": ["9.9.9.9"], "victim_ips": []},
        ]}],
    }
    overlap = _utc_epoch(2018, 2, 14, 14, 45)  # inside both (10:45 ADT)
    wf = pd.DataFrame([_window_row("9.9.9.9", overlap)])
    labels = TL.label_windows(data_cfg, wf, timeline=two_attacks)
    # impact is later in the configured stage order than recon
    assert labels.iloc[0] == "impact"


def test_class_counts_table_shape(data_cfg):
    labelled = {
        "train": pd.Series(["benign", "benign", "initial_access"]),
        "val": pd.Series(["benign", "c2"]),
    }
    table = TL.class_counts(data_cfg, labelled)
    assert list(table.index) == data_cfg["stages"]
    assert table.loc["benign", "total"] == 3  # 2 in train + 1 in val
    assert table.loc["initial_access", "train"] == 1
    assert table.loc["c2", "val"] == 1
    md = TL.render_class_counts_markdown(data_cfg, table)
    assert "lateral_movement" in md and "no data" in md  # absent class flagged
