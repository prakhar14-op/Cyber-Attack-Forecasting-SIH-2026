"""Window builder (M3.1/M3.5): per-(source_host, window) feature rows + sequences.

The unit of prediction is (source_host, window) — never per-flow, never
whole-network (CLAUDE.md). This module turns the extracted per-day flow and
packet parquet into a single feature matrix keyed on (host, window_id), writes
the authoritative feature-name order to artifacts/feature_names.json, and builds
the padded per-host sequences GRAFT consumes in M6.

Every window covers 15 s on a 5 s stride grid (config), so a timestamp belongs
to `window_seconds // stride_seconds` overlapping windows — the exact same grid
the packet features already use (data.packet_features.window_ids_for), so flow
and packet sides join with no key drift.

Node identity never enters the feature matrix raw: host columns carry role-only
features (internal / hashed-/24 bucket / server-like port profile) via
data.anonymize, and the host key itself is replaced by its keyed-HMAC pseudonym
when `with_pseudonyms=True`.
"""

from __future__ import annotations

import json

import numpy as np
import pandas as pd

from configs import resolve_path
from data import packet_features as pf

# Flow columns aggregated into each (host, window). (canonical col, agg, output name).
# Everything the host did AS SOURCE in the window; a flow contributes to every
# window its start timestamp falls in (same overlap rule as the packet side).
_FLOW_AGGS = [
    ("fwd_bytes", "sum", "flow_fwd_bytes"),
    ("bwd_bytes", "sum", "flow_bwd_bytes"),
    ("fwd_pkts", "sum", "flow_fwd_pkts"),
    ("bwd_pkts", "sum", "flow_bwd_pkts"),
    ("syn", "sum", "flow_syn"),
    ("ack", "sum", "flow_ack"),
    ("fin", "sum", "flow_fin"),
    ("rst", "sum", "flow_rst"),
    ("psh", "sum", "flow_psh"),
    ("urg", "sum", "flow_urg"),
    ("duration", "mean", "flow_duration_mean"),
    ("duration", "max", "flow_duration_max"),
    ("iat_mean", "mean", "flow_iat_mean"),
    ("iat_std", "mean", "flow_iat_std"),
    ("iat_max", "max", "flow_iat_max"),
    ("init_win_fwd", "mean", "flow_init_win_fwd"),
    ("init_win_bwd", "mean", "flow_init_win_bwd"),
]
_ROLE_FEATURES = ["internal", "net24_bucket", "server_port_ratio"]

# Columns present on every window row that are NOT model features.
_META_COLS = ["host", "window_id", "window_start", "day"]


def feature_columns(cfg: dict) -> list[str]:
    """The authoritative, ordered feature-name list used everywhere downstream.

    Order: flow aggregates, then flow-count + distinct counts, then the 17
    packet fields (config order), then role features. Stable and asserted by
    tests — this list, not column insertion order, is the single source of truth.
    """
    flow = [out for (_, _, out) in _FLOW_AGGS] + [
        "flow_count",
        "flow_distinct_dst_ports",
        "flow_distinct_dst_ips",
    ]
    packet = list(cfg["packet_features"]["fields"])
    return flow + packet + _ROLE_FEATURES


def write_feature_names(cfg: dict):
    """Persist the authoritative window-feature order to feature_names.json.

    Merges with any existing keys (e.g. `flow_numeric` written by the M1.6
    flow-level scaler for the M8 flow pre-filter) rather than clobbering them,
    so the file records every feature vocabulary the pipeline uses.
    """
    path = resolve_path(cfg["paths"]["feature_names"])
    existing = {}
    if path.exists():
        with open(path, encoding="utf-8") as fh:
            existing = json.load(fh)
    existing["window_features"] = feature_columns(cfg)
    existing["role_features"] = list(_ROLE_FEATURES)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(existing, fh, indent=2)
    return path


def _load_day(cfg: dict, day: str) -> tuple[pd.DataFrame, pd.DataFrame]:
    interim = resolve_path(cfg["paths"]["interim_dir"]) / str(day)
    flow_files = sorted((interim / "flows").glob("*.parquet"))
    pkt_files = sorted((interim / "packets").glob("*.parquet"))
    if not flow_files or not pkt_files:
        raise FileNotFoundError(
            f"no extracted parquet for {day} under {interim} — run "
            "`python -m data.zip_fetch` then `python -m data.extract`"
        )
    flows = pd.concat([pd.read_parquet(f) for f in flow_files], ignore_index=True)
    packets = pd.concat([pd.read_parquet(f) for f in pkt_files], ignore_index=True)
    return flows, packets


def _aggregate_flows(flows: pd.DataFrame, cfg: dict) -> pd.DataFrame:
    """Flow features per (host=src_ip, window_id). Flows explode over the windows
    their start timestamp covers (overlap rule identical to the packet side)."""
    fl = flows.copy()
    fl["ts"] = fl["timestamp"].map(pd.Timestamp.timestamp)
    parts = []
    for ids in pf.window_ids_for(fl["ts"], cfg):
        part = fl.copy()
        part["window_id"] = ids
        parts.append(part)
    ex = pd.concat(parts, ignore_index=True)
    ex = ex.rename(columns={"src_ip": "host"})

    grouped = ex.groupby(["host", "window_id"], sort=True)
    out = pd.DataFrame(index=grouped.size().index)
    for col, how, name in _FLOW_AGGS:
        out[name] = grouped[col].agg(how)
    out["flow_count"] = grouped.size()
    out["flow_distinct_dst_ports"] = grouped["dst_port"].nunique()
    out["flow_distinct_dst_ips"] = grouped["dst_ip"].nunique()

    # window_start (epoch seconds) = window_id * stride, for label/time joins later.
    stride = cfg["windows"]["stride_seconds"]
    result = out.reset_index()
    result["window_start"] = result["window_id"].astype("int64") * stride
    return result


def build_window_features(
    cfg: dict, day: str, with_pseudonyms: bool = False, anonymizer=None
) -> pd.DataFrame:
    """Per-(host, window) feature matrix for one day.

    Columns: _META_COLS + feature_columns(cfg). host holds the real IP unless
    with_pseudonyms (then the keyed-HMAC pseudonym; requires an Anonymizer).
    """
    flows, packet_windows = _load_day(cfg, day)
    flow_feats = _aggregate_flows(flows, cfg)
    # The packet parquet is ALREADY the per-(src_ip, window_id) feature output of
    # data.extract (packet_window_features), not a raw packet table — use directly.
    pkt_feats = packet_windows.rename(columns={"src_ip": "host"})

    merged = flow_feats.merge(pkt_feats, on=["host", "window_id"], how="outer")

    # Packet side can surface a host-window with no host-as-source flows (a host
    # that only sent bare ACKs/responses); flow side can surface one whose packets
    # were all fragments. Fill the numeric gaps with 0 and recompute window_start.
    stride = cfg["windows"]["stride_seconds"]
    merged["window_start"] = merged["window_id"].astype("int64") * stride
    merged["day"] = str(day)

    feat_cols = feature_columns(cfg)
    role_set = set(_ROLE_FEATURES)
    numeric_feats = [c for c in feat_cols if c not in role_set]
    for c in numeric_feats:
        if c not in merged:
            merged[c] = 0.0
    merged[numeric_feats] = merged[numeric_feats].fillna(0.0)

    # Role features per host (constant across that host's windows).
    if anonymizer is not None:
        roles = _role_table(anonymizer, flows)
        merged = merged.merge(roles, on="host", how="left")
        for c in _ROLE_FEATURES:
            merged[c] = merged[c].fillna(0.0)
        if with_pseudonyms:
            merged["host"] = merged["host"].map(lambda ip: anonymizer.pseudonym(ip))
    else:
        for c in _ROLE_FEATURES:
            merged[c] = 0.0

    ordered = _META_COLS + feat_cols
    return merged[ordered].sort_values(["host", "window_id"], kind="stable").reset_index(
        drop=True
    )


def _role_table(anonymizer, flows: pd.DataFrame) -> pd.DataFrame:
    """Role-only features for every host in the day, vectorised.

    Equivalent to calling anonymizer.role_features per host (a test pins the
    equivalence) but computed in one groupby instead of O(hosts x flows) —
    server_port_ratio is the share of a host's OWN ports (src_port where it is
    the source, dst_port where it is the destination) that are server ports.
    """
    src = flows[["src_ip", "src_port"]].rename(
        columns={"src_ip": "host", "src_port": "own_port"}
    )
    dst = flows[["dst_ip", "dst_port"]].rename(
        columns={"dst_ip": "host", "dst_port": "own_port"}
    )
    long = pd.concat([src, dst], ignore_index=True)
    long["is_server"] = long["own_port"].isin(anonymizer._server_ports)
    server_ratio = long.groupby("host")["is_server"].mean()

    hosts = server_ratio.index.to_numpy()
    return pd.DataFrame(
        {
            "host": hosts,
            "internal": [int(anonymizer.is_internal(h)) for h in hosts],
            "net24_bucket": [anonymizer.net24_bucket(h) for h in hosts],
            "server_port_ratio": server_ratio.to_numpy(),
        }
    )


def build_split_windows(cfg: dict, split: str, **kwargs) -> pd.DataFrame:
    """Concatenate per-day window features for every day in a split."""
    import yaml

    with open(resolve_path(cfg["paths"]["splits"]), encoding="utf-8") as fh:
        splits = yaml.safe_load(fh)
    if split not in splits:
        raise KeyError(f"unknown split '{split}' (have {sorted(splits)})")
    frames = [build_window_features(cfg, day, **kwargs) for day in splits[split]]
    return pd.concat(frames, ignore_index=True)


def host_windows_for_split(cfg: dict, split: str) -> set[tuple[str, int]]:
    """(host, window_id) pairs in a split — used by test_splits_disjoint (M1.5's
    second half). window_id encodes absolute time, so day-disjoint splits are
    host-window-disjoint by construction; the test guards against a regression to
    relative ids."""
    wf = build_split_windows(cfg, split)
    return set(zip(wf["host"].astype(str), wf["window_id"].astype(int)))


# ---------------------------------------------------------------------------
# Sequence assembly + padding masks (M3.5) — consumed by GRAFT (M6).
# ---------------------------------------------------------------------------


def pad_sequence(
    features: np.ndarray, max_len: int
) -> tuple[np.ndarray, np.ndarray]:
    """Right-pad (or left-truncate) a [t, F] window sequence to [max_len, F].

    Keeps the most recent max_len windows (causal: the newest window is last).
    Returns (padded, pad_mask) where pad_mask[i] is True for a PADDING position
    (True = ignore), matching torch TransformerEncoder's src_key_padding_mask.
    """
    t, feat_dim = features.shape
    if t >= max_len:
        return features[-max_len:].copy(), np.zeros(max_len, dtype=bool)
    padded = np.zeros((max_len, feat_dim), dtype=features.dtype)
    padded[max_len - t :] = features  # newest windows sit at the end
    mask = np.ones(max_len, dtype=bool)
    mask[max_len - t :] = False
    return padded, mask


def build_host_sequences(
    window_features: pd.DataFrame, cfg: dict
) -> dict[str, dict]:
    """Per-host time-ordered feature sequence + padding mask (to max_sequence_windows).

    Returns {host: {"features": [max_len, F], "mask": [max_len], "window_ids":
    [<=max_len]}}. Feature columns follow feature_columns(cfg) exactly.
    """
    max_len = cfg["windows"]["max_sequence_windows"]
    cols = feature_columns(cfg)
    result: dict[str, dict] = {}
    for host, g in window_features.sort_values("window_id").groupby("host", sort=True):
        feats = g[cols].to_numpy(dtype=np.float32)
        padded, mask = pad_sequence(feats, max_len)
        kept_ids = g["window_id"].to_numpy()[-max_len:]
        result[str(host)] = {"features": padded, "mask": mask, "window_ids": kept_ids}
    return result


def build_labelled_split(cfg: dict, split: str) -> pd.DataFrame:
    """Window features (real hosts) + a 'stage' label column for one split."""
    from data.timeline_labels import label_windows

    wf = build_split_windows(cfg, split)
    wf["stage"] = label_windows(cfg, wf)
    return wf


def main(argv: list[str] | None = None) -> int:
    """Build all splits, persist feature_names.json, print the class-count report
    (M3.4) — the numbers that go into docs/stage_mapping.md."""
    import sys

    from data.timeline_labels import class_counts, render_class_counts_markdown
    from configs import load_config, set_seed

    cfg = load_config("data")
    set_seed(cfg["seed"])

    path = write_feature_names(cfg)
    print(f"wrote {path} ({len(feature_columns(cfg))} window features)")

    import yaml

    with open(resolve_path(cfg["paths"]["splits"]), encoding="utf-8") as fh:
        split_names = list(yaml.safe_load(fh))

    labelled = {}
    for split in split_names:
        wf = build_labelled_split(cfg, split)
        labelled[split] = wf["stage"]
        print(f"[{split}] {len(wf):,} host-windows")

    table = class_counts(cfg, labelled)
    print("\n" + render_class_counts_markdown(cfg, table))
    return 0


if __name__ == "__main__":
    import sys

    sys.exit(main())
