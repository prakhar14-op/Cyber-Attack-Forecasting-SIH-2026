"""Stage labelling (M3.2/M3.3): attack timeline -> per-window kill-chain stage.

CIC-IDS-2018 ships attack-*type* labels, not kill-chain *stage* labels; this
module derives stage labels from the UNB attack timeline
(data/attack_timeline.yaml), the deliverable mapping described in
docs/stage_mapping.md. The same code path labels our own lab capture in M11.

Rules (CLAUDE.md, BUILD_PLAN 3.3):
- A (host, window) is labelled with an attack stage only when the host is that
  attack's attacker or victim AND the window overlaps the attack interval AND
  the host actually transmits in the window (the window row exists only if the
  host was an active source — so an existing row IS transmission). No smearing
  a stage across a whole day.
- Timeline times are local (ADT); captures are UTC. The measured
  utc_offset_hours is added before intersecting (see attack_timeline.yaml).
- Everything else is `benign`.

Labels are targets only — never fed back as an input feature (CLAUDE.md).
`label_windows` requires the REAL host IP column, so call it before any
pseudonymisation.
"""

from __future__ import annotations

import datetime

import numpy as np
import pandas as pd
import yaml

from configs import resolve_path


def _local_to_epoch_utc(date_str: str, hhmm: str, offset_hours: int) -> float:
    """A local wall-clock (date + HH:MM, ADT) -> UTC epoch seconds."""
    y, m, d = (int(x) for x in date_str.split("-"))
    hh, mm = (int(x) for x in hhmm.split(":"))
    wall = datetime.datetime(y, m, d, hh, mm, tzinfo=datetime.timezone.utc)
    return (wall + datetime.timedelta(hours=offset_hours)).timestamp()


def load_timeline(cfg: dict) -> dict:
    with open(resolve_path(cfg["dataset"]["timeline"]), encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def attack_intervals(cfg: dict, timeline: dict | None = None) -> list[dict]:
    """Flatten the timeline to UTC-epoch intervals with the hosts and stage.

    Each entry: {name, stage, start, end (epoch UTC), hosts (set of real IPs)}.
    """
    timeline = timeline or load_timeline(cfg)
    offset = timeline["timezone"]["utc_offset_hours"]
    out = []
    for day in timeline["days"]:
        for atk in day["attacks"]:
            out.append(
                {
                    "name": atk["name"],
                    "stage": atk["stage"],
                    "start": _local_to_epoch_utc(day["date"], atk["start"], offset),
                    "end": _local_to_epoch_utc(day["date"], atk["end"], offset),
                    "hosts": set(atk["attacker_ips"]) | set(atk["victim_ips"]),
                }
            )
    return out


def label_windows(
    cfg: dict, window_features: pd.DataFrame, timeline: dict | None = None
) -> pd.Series:
    """Return a stage-label Series aligned to window_features.index.

    Requires the real 'host' IP column and the 'window_start' epoch column
    (both produced by data.windows.build_window_features with with_pseudonyms
    =False). A window [start, start+window_seconds) is labelled by any attack
    interval it overlaps whose host set contains this row's host; benign
    otherwise. Where two attacks overlap one window, the higher-priority stage
    (later in the configured stage order) wins.
    """
    window_sec = cfg["windows"]["window_seconds"]
    stage_priority = {s: i for i, s in enumerate(cfg["stages"])}

    host = window_features["host"].astype(str).to_numpy()
    # Guard the label-before-pseudonymise ordering: HMAC pseudonyms are 16 hex
    # chars with no dots, so nothing would match a timeline IP and every window
    # would be silently benign. Fail loudly instead.
    if len(host) and not any("." in h for h in host[: min(len(host), 1000)]):
        raise ValueError(
            "label_windows received hosts with no dotted-IP form — it must run on "
            "REAL host IPs, before pseudonymisation (build_window_features "
            "with_pseudonyms=False)"
        )
    w_start = window_features["window_start"].to_numpy(dtype=float)
    w_end = w_start + window_sec

    labels = np.array(["benign"] * len(window_features), dtype=object)
    label_rank = np.zeros(len(window_features), dtype=int)

    for atk in attack_intervals(cfg, timeline):
        overlaps = (w_start < atk["end"]) & (w_end > atk["start"])
        is_party = np.isin(host, list(atk["hosts"]))
        hit = overlaps & is_party
        rank = stage_priority[atk["stage"]]
        take = hit & (rank >= label_rank)
        labels[take] = atk["stage"]
        label_rank[take] = rank

    return pd.Series(labels, index=window_features.index, name="stage")


def class_counts(cfg: dict, labelled: dict[str, pd.Series]) -> pd.DataFrame:
    """Per-split stage counts (rows = stages in config order, cols = splits)."""
    table = pd.DataFrame(index=cfg["stages"])
    for split, labels in labelled.items():
        counts = labels.value_counts()
        table[split] = [int(counts.get(stage, 0)) for stage in cfg["stages"]]
    table["total"] = table.sum(axis=1)
    return table


def render_class_counts_markdown(cfg: dict, table: pd.DataFrame) -> str:
    """Markdown for docs/stage_mapping.md (M3.4), flagging absent/small classes."""
    lines = ["| stage | " + " | ".join(table.columns) + " |",
             "|---|" + "---|" * len(table.columns)]
    for stage, row in table.iterrows():
        cells = " | ".join(str(int(row[c])) for c in table.columns)
        flag = ""
        if int(row["total"]) == 0:
            flag = "  **(!) no data** (lab capture only — M11)"
        elif int(row["total"]) < 500:
            flag = "  **(!) small class**"
        lines.append(f"| `{stage}` | {cells} |{flag}")
    return "\n".join(lines)
