"""Offline demo app (M10).

    streamlit run app/streamlit_app.py

Fully offline: no CDN assets, no network calls, no runtime downloads. Charts are
matplotlib (rendered server-side to PNG by Streamlit), so nothing is fetched
from a CDN at view time. All logic lives in app/panels.py so it is testable
without a browser.

Panels: upload -> forecast timeline (M10.2) -> explanation (M10.3) -> what-if
(M10.4) -> ledger verify/tamper/re-verify (M10.5) -> results card (M10.6).
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import streamlit as st

from app import panels
from configs import load_config, resolve_path

st.set_page_config(page_title="Network Attack Forecasting", layout="wide")
CFG = load_config("data")


def _fmt_threshold(x: float) -> str:
    """The FPR-budget threshold lives on the model's raw score scale, which can
    be tiny (e.g. 1.8e-05) — plain fixed-point would round it to 0.0000 and read
    as 'no threshold'. Show small values in scientific notation."""
    return f"{x:.4f}" if abs(x) >= 1e-3 else f"{x:.2e}"


def _session_dir() -> Path:
    if "run_dir" not in st.session_state:
        st.session_state.run_dir = Path(tempfile.mkdtemp(prefix="sih26-run-"))
    return st.session_state.run_dir


st.title("Network Attack Forecasting — offline demo")
st.caption(
    "SIH26153 · forecasts the infiltration probability and ATT&CK stage per "
    "(source host, 15 s window), explains every alert in named features, and "
    "writes each forecast to a tamper-evident ledger. Runs with no network."
)

# ---------------------------------------------------------------- input
st.header("1 · Input")
col_a, col_b = st.columns([2, 1])
with col_a:
    uploaded = st.file_uploader("Upload a flow CSV or a PCAP", type=["csv", "pcap", "pcapng"])
with col_b:
    use_pcap = st.button("Demo: synthetic PCAP (full features)")
    use_csv = st.button("Demo: sample CSV (flow only)")

_synth = resolve_path("app/assets/synthetic_demo.pcap")
input_path = None
if uploaded is not None:
    input_path = _session_dir() / uploaded.name
    input_path.write_bytes(uploaded.getbuffer())
elif use_pcap and _synth.exists():
    input_path = _synth
elif use_csv:
    input_path = resolve_path(CFG["paths"]["fixture_csv"])

if input_path is not None:
    st.session_state.input_path = str(input_path)
input_path = st.session_state.get("input_path")

if not input_path:
    st.info("Upload a file or click **Use the bundled sample** to begin.")
    st.stop()

st.success(f"Input: `{Path(input_path).name}`")
if "synthetic_demo" in str(input_path):
    st.info(
        "This is a **synthetic, illustrative** capture (not real data, never used for any "
        "reported metric) — it walks the full kill chain so the demo can show lateral movement "
        "and exfiltration, which no public dataset contains. See app/assets/README.md.",
        icon="🧪",
    )
if str(input_path).endswith(".csv"):
    st.warning(
        "CSV input carries flow features only — the packet-level features "
        "(TTL, TCP window, payload histogram, scan signature, retransmissions) "
        "need a PCAP. Forecast quality is correspondingly reduced; see "
        "docs/decisions/001-feature-source.md.",
        icon="⚠️",
    )

# ---------------------------------------------------------------- run
# Cache the result per input so interacting with widgets (tamper, what-if,
# re-verify) does NOT re-run the pipeline and re-append to the ledger.
if st.session_state.get("ran_for") != str(input_path):
    with st.spinner("Running the offline pipeline (features → forecast → explanations → ledger)…"):
        st.session_state.result = panels.run_pipeline(input_path, _session_dir())
        st.session_state.ran_for = str(input_path)
result = st.session_state.result

m1, m2, m3, m4 = st.columns(4)
m1.metric("Flows", f"{result['n_flows']:,}")
m2.metric("Host-windows", f"{result['n_host_windows']:,}")
m3.metric("Alerts", f"{result['n_alerts']:,}")
m4.metric("Threshold (1% FPR)", _fmt_threshold(result["threshold"]))

# ---------------------------------------------------------------- timeline
st.header("2 · Forecast timeline")
tl = panels.timeline_frame(result, CFG)
if tl.empty:
    st.info("No alerts at this operating point.")
else:
    fig, ax = plt.subplots(figsize=(11, 3.4))
    t0 = tl["window_start"].min()
    ax.plot((tl["window_start"] - t0), tl["probability"], "-o", ms=3,
            color="#1a6faf", label="network score (max over hosts)")
    ax.axhline(result["threshold"], ls="--", color="crimson",
               label=f"alert threshold ({_fmt_threshold(result['threshold'])})")
    for stage in tl["stage"].unique():
        sub = tl[tl["stage"] == stage]
        ax.scatter(sub["window_start"] - t0, sub["probability"], s=14, label=stage)
    ax.set_xlabel("seconds since first alert window")
    ax.set_ylabel("forecast probability")
    ax.legend(fontsize=7, ncol=3)
    ax.grid(alpha=0.3)
    st.pyplot(fig)

st.subheader("Hosts to triage")
st.dataframe(panels.host_ranking(result), width="stretch")

# ---------------------------------------------------------------- explain
st.header("3 · Why this host? (named features — never embedding dimensions)")
hosts = list(panels.host_ranking(result)["host"]) if result["forecasts"] else []
if hosts:
    chosen = st.selectbox("Host (pseudonymised where a key is configured)", hosts)
    exp = panels.explanation_for(result, chosen)
    if exp:
        c1, c2 = st.columns([1, 1])
        with c1:
            st.markdown(
                f"**Probability** {exp['probability']:.3f} · **Stage** `{exp['stage']}` · "
                f"**Technique** `{exp['technique']}` {exp['technique_name']}"
            )
            st.markdown("**Top contributing features**")
            st.dataframe(
                [{"feature": t["feature"], "value": round(t["value"], 3),
                  "contribution": round(t["contribution"], 4)} for t in exp["top_features"]],
                width="stretch",
            )
        with c2:
            st.markdown("**Top contributing windows** (where the attack was forming)")
            tw = exp.get("top_windows") or []
            st.dataframe(
                [{"seconds_before_alert": w["seconds_before_alert"],
                  "probability": round(w["probability"], 3)} for w in tw]
                or [{"note": "single-window alert"}],
                width="stretch",
            )
            st.markdown("**Flagged flows in this window**")
            st.dataframe(exp["flagged_flows"] or [{"note": "no flows in window"}],
                         width="stretch")

# ---------------------------------------------------------------- what-if
st.header("4 · What-if: remove a host")
if hosts:
    target = st.selectbox("Ablate this host's traffic and re-run", hosts, key="whatif")
    if st.button("Run what-if"):
        with st.spinner("Re-running with that host removed…"):
            wi = panels.what_if_remove_host(input_path, _session_dir(), target)
        a, b = st.columns(2)
        a.metric("Alerts before", result["n_alerts"])
        b.metric("Alerts after", wi["after"]["n_alerts"],
                 delta=wi["after"]["n_alerts"] - result["n_alerts"])
        st.caption(
            f"Flows {wi['n_flows_before']:,} → {wi['n_flows_after']:,} after removing "
            f"`{target}`. A large drop means that host drove the forecast."
        )

# ---------------------------------------------------------------- ledger
st.header("5 · Audit ledger")
status = panels.ledger_status(_session_dir())
if status.get("exists"):
    l1, l2, l3 = st.columns(3)
    l1.metric("Records", status["records"])
    l2.metric("Chain verifies", "yes" if status["verified"] else "NO")
    l3.metric("Anchored to checkpoint", "yes" if status["anchored"] else "no")
    st.code(f"python -m ledger.verify_cli {_session_dir() / 'audit_chain.jsonl'}", language="bash")

    t1, t2 = st.columns(2)
    if t1.button("Tamper with record 0 (demo)"):
        panels.tamper_ledger(_session_dir(), 0)
        st.rerun()
    if t2.button("Re-verify"):
        st.rerun()
    if not status["verified"]:
        st.error(
            f"TAMPER DETECTED at record {status['first_bad_index']} — the hash chain "
            "no longer validates. Re-run the pipeline to rebuild a clean chain."
        )

# ---------------------------------------------------------------- results
st.header("6 · Benchmark results (read from results/, never hardcoded)")
fh = panels.forecast_horizons()
if not fh.empty:
    st.markdown("**Forecasting at horizon k** — the shipped M7 deliverable")
    st.dataframe(fh, width="stretch")
card = panels.results_card()
if not card.empty:
    st.markdown("**Model comparison (test split, 1% FPR budget)**")
    st.dataframe(card, width="stretch")
st.caption(
    "Regenerate: `python scripts/make_ablation_table.py`. The RSSM world model "
    "failed its lead-time gate and is not shipped — see docs/decisions/004."
)
