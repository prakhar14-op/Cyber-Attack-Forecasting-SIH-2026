# Expected output — `synthetic_demo.pcap`

What a **correct** run of `app/streamlit_app.py` on the bundled demo capture looks like, so
anyone can tell a working render from a broken one without having seen it before.

The capture is **synthetic and illustrative** (`python -m capture.make_synthetic_demo`), never
evaluation data and never the source of a reported metric — see `app/assets/README.md`. Ground
truth is `app/assets/synthetic_demo.operator-log.txt`; the traffic that produced it is written
out line by line in `capture/make_synthetic_demo.py`.

> **Every quantitative field below is `TBD`.** The engine artifacts
> (`artifacts/engine_model.json`, `artifacts/window_scaler.pkl`,
> `artifacts/engine_threshold.json`) are gitignored and are not present on a fresh clone, so the
> probabilities, alert counts and the threshold have not been measured on this capture. Fill each
> `TBD` from a real run — `python -m engine.train_engine`, then click
> **Demo: synthetic PCAP (full features)** — and never from an estimate. A plausible placeholder
> here would be exactly the failure this file exists to prevent.

## The hosts

The capture contains **six** IPs (verified against the extracted packet table); three of them
carry the story and three are benign noise:

| IP | Role | What it does | Should it alert? |
|---|---|---|---|
| `203.0.113.7` | external attacker (TEST-NET-3) | port scan, then SSH brute force, then receives the exfiltration | yes — as a **source** during recon and initial access |
| `10.20.0.10` | victim, then pivot | serves benign HTTP, is scanned and brute-forced, then scans `10.20.0.20` and ships bulk data out | yes — as a **source** during lateral movement and exfiltration |
| `10.20.0.20` | internal pivot target | receives the internal sweep only | no — it is a **destination**, and the unit of prediction is `(source_host, window)` |
| `10.20.0.100` `.101` `.102` | benign clients | HTTP request/response to the victim throughout | no |

If `10.20.0.20` or a benign client tops the triage table, something is wrong — the model scores
the host that **sends** the traffic, and `10.20.0.20` sources no packets at all in this capture
(verified: it appears only as a destination in the extracted packet table).

## Timeline (ground truth, from the operator log)

Offsets are seconds from the capture's fixed epoch (`BASE = 1_760_000_000.0`, so the windows are
deterministic). Wall-clock times are the operator log's own column.

| Offset | Log time | Stage | Source → destination | Traffic generated |
|---|---|---|---|---|
| 0–120 s | 08:53:20–08:55:20 | `benign` | benign clients → `10.20.0.10` | HTTP GET / 200 OK, ~1 exchange per 1.5 s |
| 130–190 s | 08:55:30–08:56:30 | `recon` | `203.0.113.7` → `10.20.0.10` | sequential SYN scan, ports 1–800 |
| 200–260 s | 08:56:40–08:57:40 | `initial_access` | `203.0.113.7` → `10.20.0.10` | 700 SSH attempts to :22, SYN + `SSH-2.0-attempt` payload |
| 270–320 s | 08:57:50–08:58:40 | `lateral_movement` | `10.20.0.10` → `10.20.0.20` | internal sequential SYN sweep, ports 20–219 |
| 330–390 s | 08:58:50–08:59:50 | `exfiltration` | `10.20.0.10` → `203.0.113.7` | 3,000 × 1,400-byte packets to :4444 |
| 395–455 s | — | benign tail | benign clients → `10.20.0.10` | closes the last attack window cleanly |

## Panel by panel

**1 · Input.** Green `Input: synthetic_demo.pcap`, plus the 🧪 synthetic-capture notice. The CSV
warning must **not** appear — this is the PCAP path, which runs the full 30-feature model.

- Flows: `TBD`
- Host-windows: `TBD`
- Alerts: `TBD`
- Threshold (1 % FPR): `TBD` — read from `artifacts/engine_threshold.json`, never hardcoded

**2 · Forecast timeline.** A curve that is flat through the benign warm-up and rises across the
attack window; the dashed threshold line sits below the alerting points. Stage-coloured points
should follow the table above in order: `recon` → `initial_access` → `lateral_movement` →
`exfiltration`. The stage labels come from `engine.predict._infer_stage`'s named-feature rules,
not from a trained 7-class head, so treat a disagreement with the operator log as a **finding to
record**, not as a render fault.

**Hosts to triage.** `203.0.113.7` and `10.20.0.10` at the top, in some order. Peak
probabilities: `TBD`.

**3 · Why this host.** Real feature names only — `sent_bytes`, `syn`, `distinct_dst_ports`,
`sequential_port_ratio`, `payload_hist_*`, `ttl_mean` and friends. **Never** `f12`, `dim_3` or
any index. The `value (z-score)` column is standardised against the training mean and σ, so a
negative byte count there is the scale, not a bug. Expected shape of the explanation:

- for `203.0.113.7` during the scan: port-count / scan-signature features dominate
- for `10.20.0.10` during the transfer: `sent_bytes` dominates

Contribution values: `TBD`.

**4 · What-if.** Removing `10.20.0.10` must drop the exfiltration and lateral-movement alerts and
must never *add* alerts. Before/after counts: `TBD`.

**5 · Audit ledger.** Records `TBD` — `engine.predict.predict_file` appends exactly one record
per alert — with **chain verifies: yes** and **anchored: yes**. After clicking
*Tamper with record 0*, the panel turns red and names index `0`.

**6 · Benchmark results.** On a fresh clone this is the "no results yet" card with the commands
to populate it — `results/*.json` is gitignored. These figures come from the dataset evaluation,
**not** from this capture, and carry the population caveat shown beside them.

**7 · Network attack graph.** Six nodes. `203.0.113.7` and `10.20.0.10` are the large, hot ones
with red edges leaving them; `10.20.0.20` and the three benign clients stay small and cool.
`10.20.0.20` never sources a flow, so no edge leaves it. Labels are legible against the
configured theme.

## Fast negative checks

A render is **broken**, not merely different, if any of these hold:

- a red Python traceback appears anywhere
- `10.20.0.20` or a `10.20.0.10x` benign client is the top-ranked host
- the explanation panel shows an index instead of a feature name
- the ledger says *chain verifies: NO* before anyone clicks *Tamper*
- zero alerts, or a peak probability below 0.5 — with the artifacts present,
  `tests/test_engine.py::test_pcap_input_uses_full_features_and_verifies` asserts non-empty
  forecasts, a peak above 0.5 and a verifying ledger **on this exact file**, so a render that
  disagrees means the app and the engine have diverged
- section 6 renders a bare header with nothing under it
