"""Window builder (M3.1/M3.5): per-(source_host, window) feature rows + sequences.

The unit of prediction is (source_host, window) — never per-flow, never
whole-network (CLAUDE.md). Every feature is WINDOW-BOUNDED: it summarises only
packets whose own timestamp falls in [w*stride, w*stride+window_seconds). This
is the whole point of decision 003 — the earlier design attributed whole-flow
totals to a flow's start window, which (because flows can run far longer than a
window) injected forecast-horizon traffic into window t and would have
fabricated the lead-time metric.

So this module does NO flow aggregation. It reads the packet-window parquet
written by data.extract — which already carries the 17 packet-statistic
features plus the 11 window-bounded sent-side features (bytes/pkts/flags/
server-port ratio/distinct dst IPs) — and adds two static, IP-derived role
features (internal, hashed /24 bucket) via data.anonymize. The host key itself
is replaced by its keyed-HMAC pseudonym when `with_pseudonyms=True`.
"""

from __future__ import annotations

import json

import numpy as np
import pandas as pd

from configs import resolve_path

# Static, IP-derived node features (no behaviour, so no temporal leak).
# server-like behaviour now lives in the window-bounded sent feature
# `server_port_ratio`, not here.
_ROLE_FEATURES = ["internal", "net24_bucket"]

# Columns present on every window row that are NOT model features.
_META_COLS = ["host", "window_id", "window_start", "day"]


def feature_columns(cfg: dict) -> list[str]:
    """The authoritative, ordered feature-name list used everywhere downstream.

    Order: the 17 packet-statistic fields, the 11 window-bounded sent-side
    fields (both in config order), then the 2 static role features. Stable and
    asserted by tests — this list, not column insertion order, is the source of
    truth.
    """
    packet = list(cfg["packet_features"]["fields"])
    sent = list(cfg["packet_features"]["sent_fields"])
    return packet + sent + _ROLE_FEATURES


def write_feature_names(cfg: dict):
    """Persist the authoritative window-feature order to feature_names.json.

    Merges with any existing keys (e.g. `flow_numeric` from the M1.6 flow-level
    scaler) rather than clobbering them.
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


def _load_packet_windows(cfg: dict, day: str) -> pd.DataFrame:
    interim = resolve_path(cfg["paths"]["interim_dir"]) / str(day)
    pkt_files = sorted((interim / "packets").glob("*.parquet"))
    if not pkt_files:
        raise FileNotFoundError(
            f"no extracted packet-window parquet for {day} under {interim} — run "
            "`python -m data.zip_fetch` then `python -m data.extract`"
        )
    return pd.concat([pd.read_parquet(f) for f in pkt_files], ignore_index=True)


def build_window_features(
    cfg: dict,
    day: str,
    with_pseudonyms: bool = False,
    anonymizer=None,
    split: str = "train",
) -> pd.DataFrame:
    """Per-(host, window) feature matrix for one day.

    Columns: _META_COLS + feature_columns(cfg). host holds the real IP unless
    with_pseudonyms (then the keyed-HMAC pseudonym for `split`; requires an
    Anonymizer). Role features are always computed from the REAL IP first, so
    pseudonymisation never affects them.
    """
    pw = _load_packet_windows(cfg, day).rename(columns={"src_ip": "host"})

    packet_fields = cfg["packet_features"]["fields"]
    sent_fields = cfg["packet_features"]["sent_fields"]
    feat_numeric = list(packet_fields) + list(sent_fields)
    for c in feat_numeric:
        if c not in pw:
            pw[c] = 0.0
    pw[feat_numeric] = pw[feat_numeric].fillna(0.0)

    stride = cfg["windows"]["stride_seconds"]
    pw["window_start"] = pw["window_id"].astype("int64") * stride
    pw["day"] = str(day)

    if anonymizer is not None:
        real_host = pw["host"]
        pw["internal"] = real_host.map(lambda ip: int(anonymizer.is_internal(ip)))
        pw["net24_bucket"] = real_host.map(anonymizer.net24_bucket)
        if with_pseudonyms:
            pw["host"] = real_host.map(lambda ip: anonymizer.pseudonym(ip, split=split))
    else:
        pw["internal"] = 0
        pw["net24_bucket"] = 0

    ordered = _META_COLS + feature_columns(cfg)
    return pw[ordered].sort_values(["host", "window_id"], kind="stable").reset_index(
        drop=True
    )


def build_split_windows(cfg: dict, split: str, **kwargs) -> pd.DataFrame:
    """Concatenate per-day window features for every day in a split."""
    import yaml

    with open(resolve_path(cfg["paths"]["splits"]), encoding="utf-8") as fh:
        splits = yaml.safe_load(fh)
    if split not in splits:
        raise KeyError(f"unknown split '{split}' (have {sorted(splits)})")
    frames = [build_window_features(cfg, day, split=split, **kwargs) for day in splits[split]]
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


def pad_sequence(features: np.ndarray, max_len: int) -> tuple[np.ndarray, np.ndarray]:
    """RIGHT-pad (or front-truncate) a [t, F] window sequence to [max_len, F].

    Truncation keeps the most recent max_len windows; padding goes at the END so
    position 0 is always a real window — left-padding gives the first causal
    query a fully-masked key set, whose NaN softmax poisons deeper attention
    layers (observed on real data). Returns (padded, pad_mask), pad_mask True =
    PADDING (torch src_key_padding_mask convention).
    """
    t, feat_dim = features.shape
    if t >= max_len:
        return features[-max_len:].copy(), np.zeros(max_len, dtype=bool)
    padded = np.zeros((max_len, feat_dim), dtype=features.dtype)
    padded[:t] = features  # real windows first, pads at the end
    mask = np.ones(max_len, dtype=bool)
    mask[:t] = False
    return padded, mask


def build_host_sequences(window_features: pd.DataFrame, cfg: dict) -> dict[str, dict]:
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


def window_features_from_packet_windows(
    cfg: dict, packet_windows: pd.DataFrame, anonymizer=None
) -> pd.DataFrame:
    """Full 30-feature matrix from an in-memory packet-window table (engine PCAP
    path). Same as build_window_features but for a table already in memory
    rather than parquet on disk."""
    pw = packet_windows.rename(columns={"src_ip": "host"}).copy()
    feat_numeric = list(cfg["packet_features"]["fields"]) + list(
        cfg["packet_features"]["sent_fields"])
    for c in feat_numeric:
        if c not in pw:
            pw[c] = 0.0
    pw[feat_numeric] = pw[feat_numeric].fillna(0.0)
    stride = cfg["windows"]["stride_seconds"]
    pw["window_start"] = pw["window_id"].astype("int64") * stride
    pw["day"] = "input"
    if anonymizer is not None:
        pw["internal"] = pw["host"].map(lambda ip: int(anonymizer.is_internal(ip)))
        pw["net24_bucket"] = pw["host"].map(anonymizer.net24_bucket)
    else:
        pw["internal"] = 0
        pw["net24_bucket"] = 0
    ordered = _META_COLS + feature_columns(cfg)
    return pw[ordered].sort_values(["host", "window_id"], kind="stable").reset_index(drop=True)


def window_features_from_flows(cfg: dict, flows: pd.DataFrame, anonymizer=None) -> pd.DataFrame:
    """Per-(source_host, window) features from a FLOW table (engine CSV path).

    A CSV input (CICFlowMeter) has no packets, so the 17 packet-statistic
    features are unavailable and set to 0; the 11 window-bounded sent features
    are derived from the flows (bytes/pkts/flags summed per host-window, distinct
    dst ports/IPs), and role features from the IP. Honest degradation — full
    features need PCAP (decision 001). Flows contribute to the windows their
    start timestamp covers (the same overlap grid as the packet path).
    """
    from data import packet_features as pf

    fl = flows.copy()
    fl["ts"] = fl["timestamp"].map(pd.Timestamp.timestamp)
    parts = []
    for ids in pf.window_ids_for(fl["ts"], cfg):
        part = fl.copy()
        part["window_id"] = ids
        parts.append(part)
    ex = pd.concat(parts, ignore_index=True).rename(columns={"src_ip": "host"})

    g = ex.groupby(["host", "window_id"], sort=True)
    out = pd.DataFrame(index=g.size().index)
    out["sent_bytes"] = g["fwd_bytes"].sum()
    out["sent_pkts"] = g["fwd_pkts"].sum()
    for flag in ("syn", "ack", "fin", "rst", "psh", "urg"):
        out[flag] = g[flag].sum()
    out["syn_win_mean"] = g["init_win_fwd"].mean().clip(lower=0)
    out["distinct_dst_ips"] = g["dst_ip"].nunique()
    server_ports = set(int(p) for p in cfg["anonymisation"]["server_ports"])
    ex["_srv"] = ex["src_port"].isin(server_ports)
    out["server_port_ratio"] = ex.groupby(["host", "window_id"])["_srv"].mean()

    for c in cfg["packet_features"]["fields"]:
        out[c] = 0.0  # packet-statistic features are unavailable from a CSV

    result = out.reset_index()
    stride = cfg["windows"]["stride_seconds"]
    result["window_start"] = result["window_id"].astype("int64") * stride
    result["day"] = "input"
    if anonymizer is not None:
        result["internal"] = result["host"].map(lambda ip: int(anonymizer.is_internal(ip)))
        result["net24_bucket"] = result["host"].map(anonymizer.net24_bucket)
    else:
        result["internal"] = 0
        result["net24_bucket"] = 0

    ordered = _META_COLS + feature_columns(cfg)
    return result[ordered].sort_values(["host", "window_id"], kind="stable").reset_index(
        drop=True
    )


def build_labelled_split(cfg: dict, split: str, anonymizer=None) -> pd.DataFrame:
    """Window features (real hosts) + a 'stage' label column for one split.

    Pass an Anonymizer to populate the role features (internal/net24_bucket);
    hosts stay real (with_pseudonyms=False) so labelling and lead-time work.
    """
    from data.timeline_labels import label_windows

    wf = build_split_windows(cfg, split, anonymizer=anonymizer)
    wf["stage"] = label_windows(cfg, wf)
    return wf


def main(argv: list[str] | None = None) -> int:
    """Build all splits, persist feature_names.json, print the class-count report
    (M3.4) — the numbers that go into docs/stage_mapping.md."""
    import yaml

    from configs import load_config, set_seed
    from data.timeline_labels import class_counts, render_class_counts_markdown

    cfg = load_config("data")
    set_seed(cfg["seed"])

    path = write_feature_names(cfg)
    print(f"wrote {path} ({len(feature_columns(cfg))} window features)")

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
