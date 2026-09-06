"""Label a lab capture from the operator log (M11.3).

    python -m capture.label_capture takes/take-<id>.operator-log.txt [--date YYYY-MM-DD]

Turns the operator's recorded scenario times into an attack_timeline.yaml-shaped
structure and labels the capture's window features through the SAME code path as
data/timeline_labels.py — one labeller for CIC and for our own capture (M2.5's
one-code-path rule extended to labelling).

The operator log is tab-separated:
    stage <TAB> HH:MM:SS start <TAB> HH:MM:SS end <TAB> attacker_ip <TAB> victim_ip
with `session_id`, `iface` and `#`-comment lines ignored.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import pandas as pd
import yaml

from configs import load_config
from data import timeline_labels as TL


def parse_operator_log(path: Path, date: str) -> dict:
    """Operator log -> the timeline dict attack_intervals/label_windows consume.

    Local capture times; the capture machine's own clock is the reference, so
    utc_offset_hours is 0 (unlike the CIC data, which is UTC vs an ADT timeline).
    """
    attacks = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "\t" not in line:
            continue
        parts = line.split("\t")
        if parts[0] in ("session_id", "iface"):
            continue
        if len(parts) < 3:
            continue
        stage, start, end = parts[0], parts[1], parts[2]
        attacker = parts[3] if len(parts) > 3 else ""
        victim = parts[4] if len(parts) > 4 else ""
        if stage not in load_config("data")["stages"]:
            raise ValueError(f"unknown stage '{stage}' in {path} — must be one of the 7")
        attacks.append({
            "name": f"lab-{stage}",
            "stage": stage,
            "start": start[:5] if len(start) > 5 else start,   # HH:MM
            "end": end[:5] if len(end) > 5 else end,
            "attacker_ips": [a for a in [attacker] if a],
            "victim_ips": [v for v in [victim] if v],
        })
    return {
        "timezone": {"timeline": "capture-local", "capture": "capture-local",
                     "utc_offset_hours": 0},
        "days": [{"date": date, "attacks": attacks}],
    }


def label_capture(cfg: dict, window_features: pd.DataFrame, timeline: dict) -> pd.Series:
    """Per-(host, window) stage label for a capture, via the shared labeller.

    label_windows requires real host IPs and a window_start epoch column —
    exactly what data.windows produces (with_pseudonyms=False)."""
    return TL.label_windows(cfg, window_features, timeline=timeline)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operator_log")
    parser.add_argument("--date", default="2026-01-01", help="capture date (YYYY-MM-DD)")
    parser.add_argument("--out", default=None, help="write the derived timeline YAML here")
    args = parser.parse_args(argv)

    timeline = parse_operator_log(Path(args.operator_log), args.date)
    n = sum(len(d["attacks"]) for d in timeline["days"])
    print(f"parsed {n} labelled interval(s) from {args.operator_log}")
    for atk in timeline["days"][0]["attacks"]:
        print(f"  {atk['stage']:16s} {atk['start']}–{atk['end']}  "
              f"{atk['attacker_ips']} -> {atk['victim_ips']}")

    out = Path(args.out) if args.out else Path(args.operator_log).with_suffix(".timeline.yaml")
    out.write_text(yaml.safe_dump(timeline, sort_keys=False), encoding="utf-8")
    print(f"-> {out}  (feed to data.windows / the labeller alongside the capture's features)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
