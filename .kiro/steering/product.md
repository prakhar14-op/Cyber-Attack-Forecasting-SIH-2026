# Product

## What this product does

**Network Attack Forecasting** — SIH 2026, problem statement **SIH26153** (NTRO,
theme: Blockchain & Cybersecurity).

Given network traffic (a PCAP or flow CSV) up to time *t*, the system:

- Scores each **(source host, 15-second window)** for infiltration probability.
- Predicts a **MITRE ATT&CK stage** for the window
  (`benign, recon, initial_access, lateral_movement, c2, exfiltration, impact`).
- Explains every alert in **named features** (e.g. `distinct_dst_ips`,
  `payload_hist_3`, `sequential_port_ratio`) — never embedding indices.
- Ranks forward risk with a **k-step head** at *t+1 … t+8* windows (up to 40 s ahead).
- Appends every forecast to a **tamper-evident, offline-verifiable ledger**
  (hash chain + Merkle roots + weight-SHA-256 provenance).

It is judged as an **early-warning system, not a flow classifier**. The metric that
defines success is **lead time**: seconds between the first alert on the attacking
host and the annotated completion of the attack, at a fixed false-positive budget
(0.1% / 1% of host-windows). Shipped result: both test attack episodes flagged with a
median ~70-minute lead at a 1% FPR budget.

## Users

### Primary — SOC analyst / network defender

The main user is a **SOC analyst** (NTRO / network-defence context) performing
**forensic triage on a capture**. Their decisions the product must support:

- Which host do I investigate first? (triage by peak forecast probability)
- Is this alert real, and *why* did the model fire? (named-feature evidence, flagged
  flows, MITRE technique)
- Where in time did the attack form, and how much lead time did we get?
- If I contain host X, does the network threat drop? (what-if ablation)
- Can I trust that this record has not been altered? (ledger verify / tamper)

Design every primary view for this user first.

### Secondary — judge / reviewer

The secondary users are the **hackathon judge** and the **ML reviewer**. They need to:

- Verify offline claims (ledger integrity, tamper detection, weight provenance).
- Confirm metrics are **reproducible** (read from `results/`, never hand-entered).
- Inspect explainability (named SHAP features, technique mapping).
- See the **stated limitations** as first-class content, not footnotes
  (n = 2 episodes, same attacker host, XGBoost-carried detection, k-step head not
  firing at the fixed budget, missing training coverage for
  recon / lateral_movement / exfiltration).

## Operating model

This is a **batch, offline early-warning system**, not a live streaming monitor.

- **Batch:** the user uploads a file (PCAP/CSV); the pipeline runs once and produces
  a complete result. There is no continuous websocket stream.
- **Offline:** the demo, inference and ledger verification run with **no network** —
  no cloud APIs, no runtime model downloads, no telemetry. This is a graded,
  non-negotiable requirement of the problem statement and constrains every decision,
  including the frontend (no CDN assets, no analytics, no external fetches).
- **Early-warning:** the product exists to raise an alert *before* an attack
  completes; lead time is the headline, not F1.
