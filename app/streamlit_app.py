"""Offline demo app (M10).

    streamlit run app/streamlit_app.py

Fully offline: no CDN assets, no network calls, no runtime downloads. Charts are
matplotlib (rendered server-side to PNG by Streamlit), so nothing is fetched
from a CDN at view time. All logic lives in app/panels.py so it is testable
without a browser.

Panels: upload -> forecast timeline (M10.2) -> explanation (M10.3) -> what-if
(M10.4) -> ledger verify/tamper/re-verify (M10.5) -> results card (M10.6) ->
network graph (M10.8) -> k-step risk curve (PS deliverable 3).

The k-step panel is deliberately the one panel that leads with its own
limitation: the head behind it has a ranking signal and no validated operating
point at any horizon, and a rising curve read as a prediction would be exactly
the overclaim this repo has spent three rounds removing. The caveat is rendered
before the chart and drawn INTO the chart, and its figures are pinned against
docs/limitations.md from tests/test_app.py.

Every failure-prone call into panels is wrapped and routed through
panels.failure_card: a raw Streamlit traceback on a projector leaks the
presenter's filesystem layout and tells a judge nothing about what to run. That
claim is enforced, not asserted: tests/test_app.py derives the list of calls it
checks from the panels module itself, so a panel function added tomorrow is
covered unless it is explicitly listed as needing no guard.
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import pandas as pd
import streamlit as st

from app import panels
from configs import load_config, resolve_path

st.set_page_config(page_title="Network Attack Forecasting", layout="wide")
CFG = load_config("data")
COLORS = panels.theme_colors()


def _error_card(exc: BaseException) -> None:
    """Render a failure as an operator card instead of a traceback."""
    card = panels.failure_card(exc)
    st.error(f"**{card['title']}**\n\n{card['detail']}", icon="🚫")
    if card["command"]:
        st.caption("Run this, then reload the page:")
        st.code(card["command"], language="bash")
    st.caption(
        "The traceback stays in the terminal running Streamlit — it is deliberately "
        "not rendered here, because it carries absolute filesystem paths."
    )


def _fmt_threshold(x: float) -> str:
    """The FPR-budget threshold lives on the model's raw score scale, which can
    be tiny (e.g. 1.8e-05) — plain fixed-point would round it to 0.0000 and read
    as 'no threshold'. Show small values in scientific notation."""
    return f"{x:.4f}" if abs(x) >= 1e-3 else f"{x:.2e}"


def _network_figure(layout: dict):
    """Plotly 3D figure of the host graph (M10.8). Rendered by st.plotly_chart,
    which serves plotly.js from Streamlit's own assets — no CDN, stays offline.

    The scene background is transparent, so every colour here comes from
    panels.theme_colors() — the page's own theme — and never assumes one."""
    import plotly.graph_objects as go

    nodes, edges = layout["nodes"], layout["edges"]
    alerting = {n["ip"] for n in nodes if n["n_alerts"] > 0}

    def _segments(es):
        xs, ys, zs = [], [], []
        for e in es:
            xs += [e["x0"], e["x1"], None]
            ys += [e["y0"], e["y1"], None]
            zs += [e["z0"], e["z1"], None]
        return xs, ys, zs

    risky = [e for e in edges if e["src"] in alerting]
    normal = [e for e in edges if e["src"] not in alerting]

    traces = []
    if normal:
        xs, ys, zs = _segments(normal)
        traces.append(go.Scatter3d(
            x=xs, y=ys, z=zs, mode="lines", hoverinfo="none",
            line=dict(color=panels.rgba(COLORS["muted"], 0.30), width=2), name="flows"))
    if risky:
        xs, ys, zs = _segments(risky)
        traces.append(go.Scatter3d(
            x=xs, y=ys, z=zs, mode="lines", hoverinfo="none",
            line=dict(color=panels.rgba(COLORS["alert"], 0.85), width=5),
            name="edge from an alerting host"))

    max_deg = max((n["degree"] for n in nodes), default=1) or 1
    sizes = [13 + (17 if n["n_alerts"] > 0 else 0) + 12 * (n["degree"] / max_deg) for n in nodes]
    traces.append(go.Scatter3d(
        x=[n["x"] for n in nodes], y=[n["y"] for n in nodes], z=[n["z"] for n in nodes],
        mode="markers+text",
        marker=dict(
            size=sizes, color=[n["peak_prob"] for n in nodes], colorscale="YlOrRd",
            cmin=0.0, cmax=1.0, showscale=True,
            colorbar=dict(
                title=dict(text="attack<br>prob", font=dict(color=COLORS["text"])),
                tickfont=dict(color=COLORS["text"]), thickness=12, len=0.6),
            line=dict(width=0.5, color=panels.rgba(COLORS["text"], 0.35))),
        text=[n["ip"] if n["n_alerts"] > 0 else "" for n in nodes],
        textposition="top center", textfont=dict(size=9, color=COLORS["text"]),
        hovertext=[f"{n['ip']}<br>peak prob {n['peak_prob']:.3g}<br>"
                   f"alerts {n['n_alerts']} · flows {n['degree']}" for n in nodes],
        hoverinfo="text", name="hosts"))

    # Tight, symmetric axis ranges from the data (Plotly auto-range pads a small
    # point cloud into a dot in an empty box), plus a close camera, so a handful
    # of hosts fills the view.
    r = max((abs(c) for n in nodes for c in (n["x"], n["y"], n["z"])), default=1.0) * 1.15
    axis = dict(visible=False, range=[-r, r])
    fig = go.Figure(traces)
    fig.update_layout(
        showlegend=False, height=600, margin=dict(l=0, r=0, t=0, b=0),
        paper_bgcolor="rgba(0,0,0,0)", font=dict(color=COLORS["text"]),
        hoverlabel=dict(bgcolor=COLORS["panel"], font=dict(color=COLORS["text"])),
        scene=dict(
            xaxis=axis, yaxis=axis, zaxis=axis,
            bgcolor="rgba(0,0,0,0)", aspectmode="cube",
            camera=dict(eye=dict(x=1.0, y=1.0, z=0.85))))
    return fig


def _kstep_figure(curve, host: str, log_scale: bool):
    """The per-host k-step risk curve (PS deliverable 3), rendered server-side.

    Matplotlib like the section-2 timeline, so the page stays offline, and the
    same theme palette, so it is legible on the light theme a projector defaults
    to.

    Two constraints shape it. Each horizon's threshold is drawn as its OWN
    marker rather than one line across the chart, because they are separate
    operating points and a single line would imply one shared decision rule. And
    FORECAST_FIGURE_CAVEAT is drawn inside the axes: a screenshot of this chart
    travels without the warning rendered above it, and a risk curve that arrives
    somewhere else with no caveat attached is the overclaim in its most portable
    form.

    `log_scale` is decided by panels.kstep_use_log_scale and passed in rather
    than queried here: every panels call this module makes has to sit inside the
    section's try (tests/test_app.py walks the AST for that), and a figure
    builder is not inside one.
    """
    fig, ax = plt.subplots(figsize=(11, 3.6), facecolor=COLORS["background"])
    ax.set_facecolor(COLORS["background"])

    seconds = [float(s) for s in curve["seconds_ahead"]]
    scores = [float(p) for p in curve["probability"]]
    ax.plot(seconds, scores, "-o", ms=5, color=COLORS["accent"],
            label=f"`{host}` k-step ranking score")

    # Thresholds are per-horizon and may be absent for some k; only the ones the
    # engine actually supplied are drawn.
    th = [(s, float(t)) for s, t in zip(seconds, curve["threshold"]) if pd.notna(t)]
    if th:
        ax.plot([s for s, _ in th], [t for _, t in th], "--s", ms=5,
                color=COLORS["alert"], label="that horizon's own 1% FPR threshold")

    crossings = [(s, p) for s, p, a in zip(seconds, scores, curve["alert"]) if bool(a)]
    if crossings:
        ax.scatter([s for s, _ in crossings], [p for _, p in crossings], s=110,
                   facecolors="none", edgecolors=COLORS["alert"], linewidths=1.6,
                   label="crosses that horizon's threshold (not a validated alert)")

    # The stage behind the curve, annotated only where it CHANGES. engine.forecast
    # derives it from the SOURCE window, so on today's engine it is one label for
    # the whole curve and exactly one annotation appears — which is the honest
    # picture. The loop still handles a change so the chart would show one if a
    # future engine ever produced a per-k stage; it does not imply one exists.
    previous = None
    for s, p, stage in zip(seconds, scores, curve["stage"]):
        if stage and stage != previous:
            # Offset right, not centred: the first annotated point is usually the
            # leftmost one, and a centred label there is clipped by the y-axis.
            ax.annotate(f"source-window stage: {stage}", (s, p),
                        textcoords="offset points", xytext=(8, 10),
                        ha="left", fontsize=8, color=COLORS["text"])
        previous = stage

    if log_scale:
        ax.set_yscale("log")
        ax.set_ylabel("k-step ranking score (log)", color=COLORS["text"])
    else:
        ax.set_ylabel("k-step ranking score", color=COLORS["text"])
    ax.set_xlabel("seconds ahead of this host's newest window (k × stride)",
                  color=COLORS["text"])
    ax.set_title(panels.FORECAST_FIGURE_CAVEAT, loc="left", fontsize=8,
                 color=COLORS["alert"])
    ax.tick_params(colors=COLORS["text"])
    for spine in ax.spines.values():
        spine.set_color(COLORS["muted"])
    legend = ax.legend(fontsize=7, ncol=3, facecolor=COLORS["panel"],
                       edgecolor=COLORS["muted"], labelcolor=COLORS["text"])
    legend.get_frame().set_alpha(0.9)
    ax.grid(alpha=0.3, color=COLORS["muted"])
    return fig


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
    use_pcap = st.button(panels.DEMO_PCAP_LABEL)
    use_csv = st.button(panels.DEMO_CSV_LABEL)

_synth = resolve_path("app/assets/synthetic_demo.pcap")
input_path = None
input_error = None
try:
    if uploaded is not None:
        # Size is checked BEFORE the bytes touch disk (M10 / F39), and the name is
        # sanitised because Streamlit does not sanitise UploadedFile.name.
        panels.check_upload_size(uploaded.size, uploaded.name)
        input_path = _session_dir() / panels.safe_upload_name(uploaded.name)
        input_path.write_bytes(uploaded.getbuffer())
    elif use_pcap:
        if not _synth.exists():
            raise FileNotFoundError(
                f"{_synth} missing — regenerate it with `python -m capture.make_synthetic_demo`"
            )
        input_path = _synth
    elif use_csv:
        input_path = resolve_path(CFG["paths"]["fixture_csv"])
        if not input_path.exists():
            raise FileNotFoundError(f"flow CSV not found: {input_path}")
except Exception as exc:  # a bad input must never reach the traceback renderer
    input_error = exc
    input_path = None

if input_error is not None:
    _error_card(input_error)
    st.stop()

if input_path is not None:
    st.session_state.input_path = str(input_path)
input_path = st.session_state.get("input_path")

if not input_path:
    st.info(panels.EMPTY_STATE_HINT)
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
_COUNTERFACTUAL_KEYS = ("whatif_result", "whatif_host", "contained_result", "contained_host")

if st.session_state.get("ran_for") != str(input_path):
    for _k in _COUNTERFACTUAL_KEYS:  # a counterfactual belongs to one input only
        st.session_state.pop(_k, None)
    try:
        with st.spinner(
            "Running the offline pipeline (features → forecast → explanations → ledger)…"
        ):
            st.session_state.result = panels.run_pipeline(input_path, _session_dir())
        st.session_state.ran_for = str(input_path)
    except Exception as exc:
        st.session_state.pop("result", None)
        st.session_state.pop("ran_for", None)
        _error_card(exc)
        st.stop()
result = st.session_state.result

m1, m2, m3, m4 = st.columns(4)
m1.metric("Flows", f"{result['n_flows']:,}")
m2.metric("Host-windows", f"{result['n_host_windows']:,}")
m3.metric("Alerts", f"{result['n_alerts']:,}")
m4.metric("Threshold (1% FPR)", _fmt_threshold(result["threshold"]))

# Frames the IPv4 parser skipped are stated here, before any panel below can be
# read as a clean result: an unseen capture scores zero alerts, and zero alerts
# with nothing said next to it is the silence this whole page exists to break.
_coverage = panels.coverage_note(result)
if _coverage:
    if _coverage["severity"] == "warning":
        st.warning(_coverage["text"], icon="🕳️")
    else:
        st.caption(_coverage["text"])

# Same rule, the other way a run can quietly see less than it appears to: with no
# anonymisation key the two role features are zeros, which moves every score away
# from the published ones.
_role = panels.role_features_degraded_note(result)
if _role:
    st.warning(_role["text"], icon="🔑")

# ---------------------------------------------------------------- timeline
st.header("2 · Forecast timeline")
# `ranking` is built here and consumed by sections 3 AND 4, so one failure in
# this try empties BOTH of them. Which of the two reasons emptied them —
# this failure, or an honest zero-alert run — is recorded and said on the page:
# an empty section under a live header reads on camera as a broken panel.
ranking = None
ranking_failed = False
try:
    tl = panels.timeline_frame(result, CFG)
    if tl.empty:
        st.info("No alerts at this operating point.")
    else:
        # Colours come from the page theme (panels.theme_colors), so the chart never
        # renders as a white box on a dark page or invisible text on a light one.
        fig, ax = plt.subplots(figsize=(11, 3.4), facecolor=COLORS["background"])
        ax.set_facecolor(COLORS["background"])
        t0 = tl["window_start"].min()
        ax.plot((tl["window_start"] - t0), tl["probability"], "-o", ms=3,
                color=COLORS["accent"], label="network score (max over hosts)")
        ax.axhline(result["threshold"], ls="--", color=COLORS["alert"],
                   label=f"alert threshold ({_fmt_threshold(result['threshold'])})")
        for stage in tl["stage"].unique():
            sub = tl[tl["stage"] == stage]
            ax.scatter(sub["window_start"] - t0, sub["probability"], s=14, label=stage)
        ax.set_xlabel("seconds since first alert window", color=COLORS["text"])
        ax.set_ylabel("forecast probability", color=COLORS["text"])
        ax.tick_params(colors=COLORS["text"])
        for spine in ax.spines.values():
            spine.set_color(COLORS["muted"])
        legend = ax.legend(fontsize=7, ncol=3, facecolor=COLORS["panel"],
                           edgecolor=COLORS["muted"], labelcolor=COLORS["text"])
        legend.get_frame().set_alpha(0.9)
        ax.grid(alpha=0.3, color=COLORS["muted"])
        st.pyplot(fig)

    st.subheader("Hosts to triage")
    ranking = panels.host_ranking(result)
    st.dataframe(ranking, width="stretch")
except Exception as exc:
    ranking_failed = True
    _error_card(exc)

# ---------------------------------------------------------------- explain
st.header("3 · Why this host? (named features — never embedding dimensions)")
hosts = [] if ranking is None or ranking.empty else list(ranking["host"])
if hosts:
    chosen = st.selectbox(panels.host_selector_label(result), hosts)
    try:
        exp = panels.explanation_for(result, chosen)
        if exp:
            c1, c2 = st.columns([1, 1])
            with c1:
                st.markdown(
                    f"**Probability** {exp['probability']:.3f} · **Stage** `{exp['stage']}` · "
                    f"**Technique** `{exp['technique']}` {exp['technique_name']}"
                )
                st.markdown("**Top contributing features**")
                st.dataframe(panels.explanation_rows(exp), width="stretch")
                st.caption(panels.EXPLANATION_VALUE_CAVEAT)
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
    except Exception as exc:
        _error_card(exc)
else:
    st.info(panels.RANKING_FAILED_EXPLAIN if ranking_failed else panels.NO_HOSTS_EXPLAIN)

# ---------------------------------------------------------------- what-if
st.header("4 · What-if: remove a host")
if hosts:
    target = st.selectbox("Ablate this host's traffic and re-run", hosts, key="whatif_pick")
    w1, w2 = st.columns([1, 3])
    if w1.button("Run what-if"):
        try:
            with st.spinner("Re-running with that host removed…"):
                st.session_state.whatif_result = panels.what_if_remove_host(
                    input_path, _session_dir(), target)["after"]
            st.session_state.whatif_host = target
        except Exception as exc:
            st.session_state.pop("whatif_result", None)
            st.session_state.pop("whatif_host", None)
            _error_card(exc)

    # The result is held in session_state, not drawn inside the button branch, so
    # it survives the next widget interaction (same contract as section 7).
    wi = st.session_state.get("whatif_result")
    if wi is not None:
        removed = st.session_state.get("whatif_host", target)
        if w2.button("Clear what-if"):
            st.session_state.pop("whatif_result", None)
            st.session_state.pop("whatif_host", None)
            st.rerun()
        a, b = st.columns(2)
        a.metric("Alerts before", result["n_alerts"])
        b.metric("Alerts after", wi["n_alerts"], delta=wi["n_alerts"] - result["n_alerts"])
        st.caption(
            f"Flows {result['n_flows']:,} → {wi['n_flows']:,} after removing "
            f"`{removed}`. A large drop in alerts means that host drove the forecast."
        )
else:
    st.info(panels.RANKING_FAILED_WHATIF if ranking_failed else panels.NO_HOSTS_WHATIF)

# ---------------------------------------------------------------- ledger
st.header("5 · Audit ledger")
try:
    status = panels.ledger_status(_session_dir())
except Exception as exc:
    status = {"exists": False}
    _error_card(exc)
if status.get("exists"):
    l1, l2, l3 = st.columns(3)
    l1.metric("Records", status["records"])
    l2.metric("Chain verifies", "yes" if status["verified"] else "NO")
    l3.metric("Anchored to checkpoint", "yes" if status["anchored"] else "no")
    st.code(f"{panels.LEDGER_VERIFY_CMD} {_session_dir() / 'audit_chain.jsonl'}",
            language="bash")

    t1, t2 = st.columns(2)
    if t1.button("Tamper with record 0 (demo)"):
        try:
            panels.tamper_ledger(_session_dir(), 0)
            st.rerun()
        except Exception as exc:
            _error_card(exc)
    if t2.button("Re-verify"):
        st.rerun()
    if not status["verified"]:
        st.error(panels.ledger_failure_text(status))

# ---------------------------------------------------------------- results
st.header("6 · Benchmark results (read from results/, never hardcoded)")
st.warning(panels.BENCHMARK_CAVEAT, icon="📉")

fh = card = None
try:
    fh = panels.forecast_horizons()
    card = panels.results_card()
except Exception as exc:
    _error_card(exc)

if fh is not None and card is not None and fh.empty and card.empty:
    # A bare header with nothing under it reads as a broken panel on camera.
    st.info(panels.BENCHMARK_EMPTY_HINT, icon="📂")
    st.code(panels.BENCHMARK_EMPTY_COMMANDS, language="bash")
else:
    if fh is not None and not fh.empty:
        st.markdown("**Forecasting at horizon k** — the shipped M7 deliverable")
        st.dataframe(fh, width="stretch")
    if card is not None and not card.empty:
        st.markdown("**Model comparison (test split, 1% FPR budget)**")
        st.dataframe(card, width="stretch")
    st.caption(
        "Regenerate: `python scripts/make_ablation_table.py`. " + panels.DEPLOYED_MODEL_NOTE
    )

# ---------------------------------------------------------------- network graph
st.header("7 · Network attack graph (3D)")
st.caption(
    "The same host graph the TGN encoder operates on: **nodes are devices** (hover "
    "for the IP), **edges are flows**. Node colour and size grow with forecast "
    "probability; **edges leaving an alerting host glow red**. Drag to rotate, scroll "
    "to zoom."
)
_gnodes = (result.get("graph") or {}).get("nodes", [])
if not _gnodes:
    st.info("No host graph for this input (no flows).")
else:
    ranked_ips = [n["ip"] for n in sorted(
        _gnodes, key=lambda n: (n["peak_prob"], n["n_alerts"]), reverse=True)]

    cc1, cc2 = st.columns([3, 1])
    pick = cc1.selectbox(
        "Contain a host (what-if: ablate its traffic and re-score the network)",
        ["— none —"] + ranked_ips, key="contain_pick")
    if cc2.button("Apply containment"):
        try:
            if pick != "— none —":
                with st.spinner(f"Re-scoring the network without {pick}…"):
                    st.session_state.contained_result = panels.what_if_remove_host(
                        input_path, _session_dir(), pick)["after"]
                    st.session_state.contained_host = pick
            else:
                st.session_state.pop("contained_result", None)
                st.session_state.pop("contained_host", None)
            st.rerun()
        except Exception as exc:
            st.session_state.pop("contained_result", None)
            st.session_state.pop("contained_host", None)
            _error_card(exc)

    gresult = st.session_state.get("contained_result", result)
    contained = st.session_state.get("contained_host")
    if contained:
        delta = gresult["n_alerts"] - result["n_alerts"]
        st.warning(
            f"**Containment (what-if):** removed `{contained}` → network alerts "
            f"{result['n_alerts']} → {gresult['n_alerts']} ({delta:+d}). This is a "
            "counterfactual re-score, **not** a live block — a defence orchestrator is "
            "roadmap, not a shipped action.",
            icon="🛡️",
        )
        if st.button("Clear containment"):
            st.session_state.pop("contained_result", None)
            st.session_state.pop("contained_host", None)
            st.rerun()

    try:
        layout = panels.network_graph_layout(gresult)
        if layout["nodes"]:
            st.plotly_chart(_network_figure(layout), width="stretch")
            if layout["truncated"]:
                st.caption(
                    f"Showing the {layout['shown']} highest-risk hosts of {layout['total']}."
                )
        else:
            st.info("The contained network has no remaining host graph.")
    except Exception as exc:
        _error_card(exc)

# ------------------------------------------------------------ k-step forecast
# PS deliverable 3, the "what next" half. Sections 2-4 answer "is this host under
# attack now"; this one answers "what does this host look like over the next k
# windows". The caveat is rendered FIRST and unconditionally — before the
# spinner, before any failure branch — because it is true on every path through
# this section, including the ones where no curve is ever drawn.
st.header("8 · k-step forecast — the next k windows (PS deliverable 3)")
st.warning(panels.FORECAST_HEADER_CAVEAT, icon="🚧")

# The forecaster re-runs the pipeline, so its result is cached per input exactly
# as the nowcast is: a widget interaction must not re-run it, and must not
# re-append to a ledger.
_FORECAST_KEYS = ("forecast", "forecast_unavailable", "forecast_error")
if st.session_state.get("forecast_ran_for") != str(input_path):
    for _k in _FORECAST_KEYS:
        st.session_state.pop(_k, None)
    try:
        with st.spinner("Running the k-step forecaster over the available horizons…"):
            st.session_state.forecast = panels.run_forecast(input_path, _session_dir())
    except panels.ForecastUnavailable as exc:
        # Not a failure a judge can fix on this machine: the capability is absent.
        # It gets an empty state naming what is missing, not a red error card.
        st.session_state.forecast_unavailable = str(exc)
    except Exception as exc:
        # A forecaster that IS here and broke. The exception is held rather than
        # re-raised on every rerun, so the card survives the next interaction
        # without the expensive failing call being repeated behind it.
        st.session_state.forecast_error = exc
    st.session_state.forecast_ran_for = str(input_path)

if st.session_state.get("forecast_unavailable"):
    st.info(st.session_state["forecast_unavailable"], icon="🚫")
elif st.session_state.get("forecast_error") is not None:
    _error_card(st.session_state["forecast_error"])
else:
    fc = st.session_state.get("forecast") or {}
    try:
        empty_reason = panels.kstep_empty_reason(fc)
        if empty_reason:
            st.info(empty_reason, icon="📭")
        else:
            k_hosts = panels.kstep_hosts(fc)
            k_pick = st.selectbox("Risk curve for host", k_hosts, key="kstep_host")
            curve = panels.kstep_curve(fc, k_pick)
            plottable = panels.kstep_plottable(curve)
            if plottable.empty:
                st.info(panels.FORECAST_NO_CURVE_TEXT, icon="📭")
            else:
                st.pyplot(_kstep_figure(plottable, k_pick,
                                        panels.kstep_use_log_scale(plottable)))
                if len(plottable) < len(curve):
                    # Said, not smoothed over: a line drawn through a horizon the
                    # engine returned nothing for would invent the missing point.
                    st.caption(
                        f"{len(curve) - len(plottable)} of {len(curve)} horizons had no "
                        "readable score or seconds-ahead and are not on the chart; they "
                        "are in the table below with those cells empty."
                    )
            st.markdown(panels.FORECAST_STAGE_TABLE_HEADING)
            st.dataframe(panels.kstep_curve_rows(curve), width="stretch")
            st.caption(panels.FORECAST_CURVE_CAPTION)
            # The forecaster's own statement of what it does not establish,
            # rendered verbatim. It travels in the engine's return value for
            # exactly this purpose, and showing it means the page tracks the
            # engine's finding instead of reciting a constant of its own.
            engine_caveat = panels.kstep_engine_caveat(fc)
            if engine_caveat:
                st.caption(f"**engine.forecast states:** {engine_caveat}")

        unavailable = panels.kstep_unavailable_rows(fc)
        if unavailable:
            st.markdown("**Horizons with no forecast** — stated, never dropped")
            st.dataframe(unavailable, width="stretch")
    except Exception as exc:
        _error_card(exc)
