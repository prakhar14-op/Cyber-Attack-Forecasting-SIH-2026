"""Edge-case / robustness report for the offline engine.

    python scripts/edge_case_report.py

Exercises the input and integrity edge cases and prints EXPECTED vs OBSERVED for
each, with [OK]/[FAIL]. Fully offline. Cases that need the trained engine are
skipped (with a note) when artifacts/ is not built.

The invariant here (CLAUDE.md): fail LOUDLY on bad input, never silently
zero-fill or fabricate; degenerate-but-valid input yields 0 alerts, never a
crash; tampering with weights or the ledger is caught.
"""

from __future__ import annotations

import csv
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from configs import load_config, resolve_path  # noqa: E402

CFG = load_config("data")
SCHEMA = CFG["schema"]
_n_ok = 0
_n_fail = 0


def _row(**over) -> dict:
    r = {c: "0" for c in SCHEMA.values()}
    r["Label"] = "Benign"
    for k, v in over.items():
        r[SCHEMA.get(k, k)] = v
    return r


def _write_csv(path: Path, rows: list[dict]) -> None:
    cols = list(SCHEMA.values())
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=cols)
        w.writeheader()
        for r in rows:
            w.writerow({c: r.get(c, "0") for c in cols})


def case(name: str, expected: str, fn) -> None:
    global _n_ok, _n_fail
    try:
        ok, observed = fn()
    except Exception as e:  # a case's own harness failing is a FAIL
        ok, observed = False, f"harness error: {type(e).__name__}: {e}"
    mark = "OK  " if ok else "FAIL"
    if ok:
        _n_ok += 1
    else:
        _n_fail += 1
    print(f"[{mark}] {name}")
    print(f"       expected: {expected}")
    print(f"       observed: {observed}")


def _engine_ready() -> bool:
    art = resolve_path(CFG["paths"]["artifacts_dir"])
    return (art / "engine_model_flow.json").exists() and (art / "window_scaler.pkl").exists()


# ---- cases -----------------------------------------------------------------

def c_missing_columns():
    from data import flow_features as FF
    sd = Path(tempfile.mkdtemp())
    p = sd / "bad.csv"
    import pandas as pd
    pd.DataFrame({"foo": [1], "bar": [2]}).to_csv(p, index=False)
    try:
        FF.load_canonical(CFG, p)
        return False, "load_canonical returned a frame (SILENT — should raise)"
    except Exception as e:
        return True, f"raised {type(e).__name__}: {str(e)[:80]}"


def c_non_pcap_bytes():
    from data import packet_features as pf
    sd = Path(tempfile.mkdtemp())
    p = sd / "junk.pcap"
    p.write_bytes(b"definitely not a capture file" * 8)
    try:
        pf.extract_packet_table(p, CFG)
        return False, "extractor returned a table (SILENT — should raise)"
    except Exception as e:
        return True, f"raised {type(e).__name__}: {str(e)[:70]}"


def c_long_flow_window_bounded():
    from data import windows as W
    import pandas as pd
    t0 = pd.Timestamp("2018-02-20 00:00:00")
    flow = _row(timestamp=t0, src_ip="10.0.0.1", dst_ip="10.0.0.2", src_port="4",
                dst_port="80", protocol="6", duration="40000000",
                fwd_bytes="40000", fwd_pkts="400", init_win_fwd="64240")
    flow = {k: (v if k != "Label" else v) for k, v in flow.items()}
    df = pd.DataFrame([{**{c: 0 for c in ["src_ip", "dst_ip", "src_port", "dst_port",
                                          "protocol", "duration", "fwd_bytes", "fwd_pkts",
                                          "syn", "ack", "fin", "rst", "psh", "urg",
                                          "init_win_fwd"]},
                        "timestamp": t0, "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2",
                        "src_port": 4, "dst_port": 80, "protocol": 6,
                        "duration": 40_000_000, "fwd_bytes": 40000.0, "fwd_pkts": 400,
                        "init_win_fwd": 64240}])
    wf = W.window_features_from_flows(CFG, df)
    mx = float(wf["sent_bytes"].max())
    ok = mx < 40000 * 0.5 and 2 * 40000 < float(wf["sent_bytes"].sum()) < 4 * 40000
    return ok, (f"40 s / 40000-byte flow spread over {len(wf)} windows; "
                f"max window has {mx:.0f} bytes (<20000 = not dumped in start window)")


def c_empty_input():
    from engine import predict
    from ledger import verify_cli
    if not _engine_ready():
        return True, "SKIPPED (engine not trained)"
    sd = Path(tempfile.mkdtemp())
    p = sd / "empty.csv"
    _write_csv(p, [])
    r = predict.predict_file(p, out_dir=sd)
    ok, _ = verify_cli.verify(sd / "audit_chain.jsonl")
    good = r["n_flows"] == 0 and r["n_alerts"] == 0 and ok
    return good, (f"flows={r['n_flows']} windows={r['n_host_windows']} "
                  f"alerts={r['n_alerts']} ledger_ok={ok}")


def c_single_benign_flow():
    from engine import predict
    if not _engine_ready():
        return True, "SKIPPED (engine not trained)"
    sd = Path(tempfile.mkdtemp())
    p = sd / "one.csv"
    _write_csv(p, [_row(timestamp="2018-02-20 01:00:00", src_ip="10.0.0.5",
                        dst_ip="10.0.0.6", src_port="50000", dst_port="443",
                        protocol="6", duration="1000000", fwd_bytes="500", fwd_pkts="5")])
    r = predict.predict_file(p, out_dir=sd)
    return r["n_alerts"] == 0, (f"flows={r['n_flows']} windows={r['n_host_windows']} "
                                f"alerts={r['n_alerts']} (benign -> no alert)")


def c_all_benign_fixture():
    from engine import predict
    if not _engine_ready():
        return True, "SKIPPED (engine not trained)"
    sd = Path(tempfile.mkdtemp())
    r = predict.predict_file(resolve_path(CFG["paths"]["fixture_csv"]), out_dir=sd)
    rate = r["n_alerts"] / max(r["n_host_windows"], 1)
    return rate < 0.05, (f"fixture (mostly benign): {r['n_alerts']} alerts of "
                         f"{r['n_host_windows']} host-windows = {rate:.1%} at the 1% budget")


def c_weight_mismatch_refusal():
    if not _engine_ready():
        return True, "SKIPPED (engine not trained)"
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import verify_weights as VW
    from engine import predict
    orig = VW.verify
    VW.verify = lambda *a, **k: (False, "engine_model_flow.json")
    sd = Path(tempfile.mkdtemp())
    try:
        predict.predict_file(resolve_path(CFG["paths"]["fixture_csv"]), out_dir=sd)
        return False, "engine wrote a ledger despite a weight mismatch (SHOULD REFUSE)"
    except RuntimeError as e:
        wrote = (sd / "audit_chain.jsonl").exists()
        return (not wrote), f"raised RuntimeError ({str(e)[:50]}...); ledger written = {wrote}"
    finally:
        VW.verify = orig


def c_ledger_tamper():
    import json as _json
    from ledger.ledger import Ledger
    sd = Path(tempfile.mkdtemp())
    chain, cp = sd / "c.jsonl", sd / "cp.jsonl"
    led = Ledger(chain, checkpoint_path=cp)
    for i in range(10):
        led.append({"host": f"h{i}", "window": i, "prob": i / 10, "stage": "recon"})
    led.checkpoint()
    clean_ok, _ = led.verify()
    lines = chain.read_text(encoding="utf-8").splitlines()
    rec = _json.loads(lines[3])
    rec["prob"] = 0.999
    lines[3] = _json.dumps(rec)
    chain.write_text("\n".join(lines) + "\n", encoding="utf-8")
    ok, bad = Ledger(chain, checkpoint_path=cp).verify()
    # full rewrite
    chain.unlink()
    forged = Ledger(chain, checkpoint_path=cp)
    for i in range(10):
        forged.append({"host": f"h{i}", "window": i, "prob": 0.99, "stage": "recon"})
    rewrite_caught = forged.verify_against_checkpoints() is False
    good = clean_ok and (not ok) and bad == 3 and rewrite_caught
    return good, (f"clean=verifies; edit@3 -> fails at index {bad}; "
                  f"full rewrite -> checkpoint mismatch caught = {rewrite_caught}")


def c_huge_csv_timing():
    from data import windows as W
    import numpy as np
    import pandas as pd
    n = 50_000
    rng = np.random.RandomState(0)
    base = pd.Timestamp("2018-02-20 00:00:00").timestamp()
    df = pd.DataFrame({
        "timestamp": pd.to_datetime(base + rng.randint(0, 3600, n), unit="s"),
        "src_ip": [f"10.0.{i % 8}.{i % 250}" for i in range(n)],
        "dst_ip": ["10.0.9.9"] * n, "src_port": rng.randint(1024, 65535, n),
        "dst_port": 443, "protocol": 6, "duration": rng.randint(0, 5_000_000, n),
        "fwd_bytes": rng.randint(0, 5000, n).astype(float), "fwd_pkts": rng.randint(1, 50, n),
        "syn": 1, "ack": 1, "fin": 0, "rst": 0, "psh": 0, "urg": 0, "init_win_fwd": 64240,
    })
    t = time.perf_counter()
    wf = W.window_features_from_flows(CFG, df)
    dt = time.perf_counter() - t
    return dt < 30, (f"{n:,} flows -> {len(wf):,} host-windows in {dt:.1f}s "
                     f"({n / dt:,.0f} flows/s); loop is O(flows x windows/flow)")


def main() -> int:
    print("=" * 78)
    print("EDGE-CASE / ROBUSTNESS REPORT")
    print("=" * 78)
    print("\n-- Bad input must FAIL LOUDLY --------------------------------------------")
    case("CSV missing PS columns / wrong schema",
         "load_canonical raises a clear error (no silent zero-fill)", c_missing_columns)
    case("Non-pcap / truncated bytes with a .pcap name",
         "extractor raises (no silent empty table)", c_non_pcap_bytes)
    print("\n-- Degenerate-but-valid input: 0 alerts, NO crash ------------------------")
    case("Empty input (header only, 0 flows)",
         "0 flows / 0 alerts, ledger still verifies", c_empty_input)
    case("Single benign flow", "few windows, 0 alerts", c_single_benign_flow)
    case("All-benign fixture", "alert rate stays near the FPR budget", c_all_benign_fixture)
    print("\n-- Leakage guard ---------------------------------------------------------")
    case("Very long flow (CSV path)",
         "bytes distributed across spanned windows, not dumped in the start window",
         c_long_flow_window_bounded)
    print("\n-- Integrity guards ------------------------------------------------------")
    case("Model weight SHA-256 mismatch",
         "engine raises and writes NO ledger record", c_weight_mismatch_refusal)
    case("Tampered ledger",
         "edit caught at the exact index; full rewrite caught by the checkpoint",
         c_ledger_tamper)
    print("\n-- Scale -----------------------------------------------------------------")
    case("Huge CSV (50k flows)", "completes quickly, no blow-up", c_huge_csv_timing)

    print("\n" + "=" * 78)
    print(f"SUMMARY: {_n_ok} ok, {_n_fail} fail")
    print("=" * 78)
    return 1 if _n_fail else 0


if __name__ == "__main__":
    sys.exit(main())
