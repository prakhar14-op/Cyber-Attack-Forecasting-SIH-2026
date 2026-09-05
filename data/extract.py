"""Run the one extractor over every fetched per-host pcap (M2 driver).

    python -m data.extract                # all configured days, resumable
    python -m data.extract --day 2018-02-14
    python -m data.extract --limit 2      # first N members per day (bench)

Per member: packet table -> canonical flows parquet + packet-window features
parquet under interim_dir/<date>/{flows,packets}/. Existing outputs are
skipped, so the driver can resume after interruption. Each member logs packet
count, wall time and peak RSS — the M2.1 acceptance evidence (1 GB pcap under
4 GB RSS).
"""

from __future__ import annotations

import argparse
import ctypes
import sys
import time
from pathlib import Path


def peak_rss_mb() -> float:
    """Peak working-set of this process in MB (Windows; -1 elsewhere)."""
    try:
        class _PMC(ctypes.Structure):
            _fields_ = [
                ("cb", ctypes.c_uint32),
                ("PageFaultCount", ctypes.c_uint32),
                ("PeakWorkingSetSize", ctypes.c_size_t),
                ("WorkingSetSize", ctypes.c_size_t),
                ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                ("PagefileUsage", ctypes.c_size_t),
                ("PeakPagefileUsage", ctypes.c_size_t),
            ]

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        get_info = kernel32.K32GetProcessMemoryInfo
        get_info.argtypes = [ctypes.c_void_p, ctypes.POINTER(_PMC), ctypes.c_uint32]
        get_info.restype = ctypes.c_int

        pmc = _PMC()
        pmc.cb = ctypes.sizeof(_PMC)
        handle = ctypes.c_void_p(kernel32.GetCurrentProcess())
        if not get_info(handle, ctypes.byref(pmc), pmc.cb):
            return -1.0
        return pmc.PeakWorkingSetSize / 2**20
    except Exception:
        return -1.0


def extract_member(pcap_path: Path, out_flows: Path, out_packets: Path, cfg: dict) -> dict:
    from data import packet_features as pf

    started = time.perf_counter()
    packets = pf.extract_packet_table(pcap_path, cfg)
    t_parse = time.perf_counter() - started
    flows = pf.assemble_flows(packets, cfg)
    t_flows = time.perf_counter() - started - t_parse
    features = pf.packet_window_features(packets, cfg)
    features, retrans_backend = pf.apply_retransmission_backend(features, pcap_path, cfg)
    # Window-bounded sent-side features (decision 003): merge onto the same
    # (src_ip, window_id) key so windows.py never re-aggregates whole flows.
    sent = pf.sent_window_features(packets, cfg)
    features = features.merge(sent, on=["src_ip", "window_id"], how="outer")
    t_feats = time.perf_counter() - started - t_parse - t_flows

    out_flows.parent.mkdir(parents=True, exist_ok=True)
    out_packets.parent.mkdir(parents=True, exist_ok=True)
    flows.to_parquet(out_flows, index=False)
    features.to_parquet(out_packets, index=False)

    return {
        "packets": len(packets),
        "flows": len(flows),
        "host_windows": len(features),
        "retrans_backend": retrans_backend,
        "seconds": time.perf_counter() - started,
        "stage_seconds": (t_parse, t_flows, t_feats),
        "pcap_mb": pcap_path.stat().st_size / 2**20,
        "peak_rss_mb": peak_rss_mb(),
    }


def main(argv: list[str] | None = None) -> int:
    from configs import load_config, resolve_path

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--day", help="only this date (YYYY-MM-DD)")
    parser.add_argument("--limit", type=int, help="first N members per day")
    args = parser.parse_args(argv)

    cfg = load_config("data")
    raw_dir = resolve_path(cfg["paths"]["raw_dir"])
    interim_dir = resolve_path(cfg["paths"]["interim_dir"])

    days = [d["date"] for d in cfg["dataset"]["days"]]
    if args.day:
        if args.day not in days:
            print(f"day {args.day} is not configured", file=sys.stderr)
            return 2
        days = [args.day]

    grand = {"members": 0, "packets": 0, "flows": 0}
    for date in days:
        host_dir = raw_dir / date / "hosts"
        members = sorted(host_dir.glob("*.pcap"))
        if not members:
            print(f"[{date}] no fetched members under {host_dir} — "
                  "run python -m data.zip_fetch first", file=sys.stderr)
            return 1
        if args.limit:
            members = members[: args.limit]

        for i, pcap_path in enumerate(members, 1):
            stem = pcap_path.stem
            out_flows = interim_dir / date / "flows" / f"{stem}.parquet"
            out_packets = interim_dir / date / "packets" / f"{stem}.parquet"
            if out_flows.exists() and out_packets.exists():
                continue
            stats = extract_member(pcap_path, out_flows, out_packets, cfg)
            grand["members"] += 1
            grand["packets"] += stats["packets"]
            grand["flows"] += stats["flows"]
            rate = stats["packets"] / max(stats["seconds"], 1e-9)
            t_parse, t_flows, t_feats = stats["stage_seconds"]
            print(
                f"[{date}] ({i}/{len(members)}) {stem}: "
                f"{stats['pcap_mb']:.0f} MB pcap, {stats['packets']:,} pkts -> "
                f"{stats['flows']:,} flows, {stats['host_windows']:,} host-windows "
                f"in {stats['seconds']:.1f}s "
                f"(parse {t_parse:.1f}s / flows {t_flows:.1f}s / feats {t_feats:.1f}s, "
                f"{rate:,.0f} pkt/s, peak RSS {stats['peak_rss_mb']:.0f} MB)",
                flush=True,
            )
        print(f"[{date}] done", flush=True)

    print(f"TOTAL new: {grand['members']} members, {grand['packets']:,} packets, "
          f"{grand['flows']:,} flows")
    return 0


if __name__ == "__main__":
    sys.exit(main())
