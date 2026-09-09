# Architecture

## Source of truth: the Python backend

The **Python backend is the single source of truth** for all functionality, data,
models, business logic, predictions, explanations and the audit ledger. It already
implements the complete pipeline:

```
PCAP / CSV -> extract -> window features -> TGN encoder -> forecast head -> engine -> ledger
```

Key entry points the rest of the system depends on (do not change their contracts):

- `engine/predict.py :: predict_file(path, out_dir, fpr_budget, exclude_host)` — the
  full offline pipeline. Returns the canonical result dict:
  `{ n_flows, n_host_windows, n_alerts, threshold, forecasts[], graph{nodes,edges} }`.
- `app/panels.py` — pure, testable logic: `run_pipeline`, `timeline_frame`,
  `host_ranking`, `explanation_for`, `what_if_remove_host`, `network_graph_layout`,
  `ledger_status`, `tamper_ledger`, `results_card`, `forecast_horizons`.
- `engine/explain.py`, `engine/technique_map.yaml` — named-feature SHAP + MITRE mapping.
- `ledger/` — hash chain, Merkle, `verify_cli`.
- `eval/ablation.py` — the reproducible results table.

## The React frontend is additive

The React frontend is a **new, additive presentation layer**. It does not replace the
existing Streamlit app (`app/streamlit_app.py`), which remains the reference/fallback
demo. The frontend communicates through a **thin localhost-only bridge** that is a 1:1
passthrough to the functions above and introduces **no new ML logic**.

- The bridge binds to `127.0.0.1` only, no auth, no telemetry, CORS restricted to
  localhost — this preserves the offline guarantee. It must never be exposed publicly.
- The frontend lives in its own directory and is built to static assets that can be
  served locally with no internet access.

## Hard rules

1. **Never rewrite ML logic.** Do not modify `models/`, `engine/` internals, `eval/`,
   `data/` feature extraction, or `ledger/` mechanics to suit the UI. The frontend and
   the thin bridge are the only additive surface.
2. **Never fabricate data.** The frontend renders only real engine output. Every number
   must trace back to `predict_file`, `panels.*`, or `results/`. No placeholder metrics,
   no synthesized forecasts, no invented hosts, no mock alerts in production paths.
3. **Preserve current tests.** `pytest tests/ -q` and `python -m tests.smoke` must stay
   green, with sockets blocked. The seven required tests
   (`test_no_future_leakage`, `test_scaler_train_only`, `test_splits_disjoint`,
   `test_offline`, `test_shapes`, `test_ledger_tamper`, `test_smoke`) are load-bearing —
   do not weaken or delete them.
4. **Offline is graded.** No CDN fonts/scripts/styles, no analytics, no runtime network
   calls except to the loopback bridge. Verify in the browser Network panel.
5. **Respect the fixed design decisions** in `CLAUDE.md` (unit of prediction, window /
   stride, horizon, stage classes, network score = max over hosts, FPR-budget threshold).
   The UI presents these; it does not redefine them.

## Data contract (consumed verbatim by the frontend)

```
{ n_flows, n_host_windows, n_alerts, threshold,
  forecasts: [ { host, window_start, probability, stage, technique, technique_name,
                 top_features:[{feature,value,contribution}],
                 top_windows:[{window_start,probability,seconds_before_alert}],
                 flagged_flows:[{dst_port,protocol,bytes,syn,duration_us}],
                 estimated_lead_seconds } ],
  graph: { nodes:[{ip,peak_prob,n_alerts,internal}],
           edges:[{src,dst,weight,risk}] } }
```
