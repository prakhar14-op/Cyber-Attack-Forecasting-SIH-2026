# CLAUDE.md — project rules

Read this fully before any task. `docs/BUILD_PLAN.md` has the milestone sequence.

## What we are building

SIH 2026, problem statement **SIH26153** (NTRO, theme: Blockchain & Cybersecurity):
*AI-based Network Attack Forecasting from Network Traffic Data.*

A **world model** for network telemetry. Not a flow classifier. Given windows up to time `t`,
it forecasts the infiltration probability and MITRE ATT&CK stage at `t+1 … t+K`, explains each
forecast in terms of named flags/ports/flow statistics, and writes every forecast to a
tamper-evident ledger.

The metric that defines success is **lead time**: seconds between the first alert on the
attacking host and the annotated completion of the attack, at a fixed false-positive budget.
A model with better F1 and zero lead time has failed this problem statement.

## Hard constraints (from the PS — do not negotiate these away)

1. **Fully offline.** The demo, inference and ledger verification must run with no network.
   No cloud APIs, no runtime model downloads, no telemetry.
2. **Flow-level AND packet-level features are both required.** Packet-level means:
   TTL values + variance, TCP window size, IP fragment flags, payload-size distribution,
   port-scan signature (sequential vs randomised), retransmission counts.
3. **Logistic-regression baseline on the identical feature matrix** is a graded deliverable.
   Report F1, precision, recall, FPR.
4. **Explainability is mandatory.** "Black-box outputs are not acceptable" — PS wording.
   Explanations must name real features, never embedding dimensions.
5. **Input is a file** (PCAP or CSV) through a Streamlit/Flask/CLI interface.
6. Deliverables: source link, README, architecture doc (max 2 pages), demo video (max 2 min),
   technical presentation (max 5 slides).
7. Everything open source. Apache-2.0. `THIRD_PARTY_NOTICES.md` maintained.

## Fixed design decisions (do not change without asking)

| Decision | Value |
|---|---|
| Unit of prediction | `(source_host, window)` — never per-flow, never whole-network |
| Window / stride / max sequence | 15 s / 5 s / 48 windows (4 min context) |
| Forecast horizon K | 8 windows (40 s) |
| Stage classes (7) | `benign, recon, initial_access, lateral_movement, c2, exfiltration, impact` |
| Network-level score | `max` over host scores in the window |
| Evidential head | Dirichlet (Sensoy et al. 2018), **not** Normal-Inverse-Gamma |
| Encoder | Causal Transformer encoder (masked). Bidirectional is a bug, not a choice |
| Dynamics model | RSSM — filter over observed windows, then roll out the prior |
| Alert threshold | Chosen from an FPR budget (0.1% / 1% of host-windows), not a hardcoded 0.42 |

## Anti-leakage rules (violating one invalidates every number we report)

- **Split by day, never randomly.** Whole attack episodes stay inside one split.
- **Fit scalers/encoders on the training split only.** Persist them next to the weights.
- **Anonymise node identity.** CIC-IDS-2018 attackers are ~15 fixed public IPs; a model keyed
  on IP memorises them. Hash node IDs with a per-epoch permutation; node features are role-only
  (internal/external, /24 bucket, server-like port profile).
- **The encoder is causal.** Position `t` must not attend to `t+1`. There is a test for this.
- Labels for window `t+k` are only ever used as a loss target, never as an input feature.

If a result looks too good (F1 > 0.99, or lead time larger than the attack duration), assume
leakage first and go looking for it. Say so in the commit message.

## Repository layout

```
configs/     YAML: every hyper-parameter, seed and path. No magic numbers in code.
data/        download_cic.sh, flow_features.py, packet_features.py,
             timeline_labels.py, windows.py, splits.yaml
models/      tgn.py, graft.py, rssm.py, baselines.py, losses.py
engine/      predict.py, explain.py, flag_flows.py, thresholds.py, technique_map.yaml
eval/        harness.py, metrics.py, ablation.py, plots.py
ledger/      ledger.py, merkle.py, anchor.py, verify_cli.py
app/         streamlit_app.py, assets/backup_capture.{csv,pcap}
capture/     capture.sh, attack_scenarios.md, label_capture.py
tests/       see below
docs/        BUILD_PLAN.md, architecture.md, stage_mapping.md, benchmark_protocol.md,
             limitations.md, demo_script.md
scripts/     verify_weights.py, make_ablation_table.py
```

## Definition of done (every task)

- `pytest tests/ -q` passes.
- `python -m tests.smoke` runs the full pipeline on 1,000 flows in under 60 s **with the network
  disabled**.
- No new dependency without pinning it in `requirements.txt` / `environment.lock.yml`.
- Config-driven: no path, seed or hyper-parameter hardcoded in a module.
- If the task changed a number that appears in `docs/` or `README.md`, that number is updated
  in the same commit.

## Required tests (keep these green)

| Test | Asserts |
|---|---|
| `test_no_future_leakage.py` | Perturbing windows `t+1…T` leaves the prediction at `t` bit-identical |
| `test_scaler_train_only.py` | Scaler statistics match a scaler fitted on the train split alone |
| `test_splits_disjoint.py` | No day appears in two splits; no host-window crosses splits |
| `test_offline.py` | Blocks `socket.socket`, then runs inference + ledger verify end to end |
| `test_shapes.py` | TGN → GRAFT → RSSM → heads dimensions agree for K=1 and K=8 |
| `test_ledger_tamper.py` | Edited record → verify fails at the right index; full rewrite → checkpoint mismatch |
| `test_smoke.py` | End-to-end on the bundled 1,000-flow fixture |

## Things not to do

- Do not fabricate results. If a number is not yet measured, write `TBD` — never a plausible
  placeholder. Numbers in the README must be reproducible by `eval/ablation.py`.
- Do not silently substitute synthetic data when a real file is missing. Fail loudly.
- Do not add a component because it appears in a paper. Every block must earn a row in the
  ablation table or it does not ship. This applies to: latent overshooting, CfC, Mamba,
  categorical latents, backward-forecast head, variable-selection gate, FlashAttention.
- Do not refactor across milestone boundaries. Finish and tag a milestone first.
- Do not write `torch.nn.TransformerEncoder` without `mask=` and `src_key_padding_mask=`.
- Do not store raw IPs or payloads in the ledger. Keyed-HMAC pseudonyms only.
- Do not implement online learning / auto-retraining at inference. Scheduled batch only.
- Do not build the roadmap features (defence orchestrator, deception, host/identity telemetry,
  federated retraining). They are slide content.
- Do not commit weights or `.pcap` files to git. Use GitHub Releases and record the SHA-256.

## Stop and ask the human

- A design decision from the table above needs to change.
- A metric contradicts the plan (e.g. XGBoost beats the world model on lead time).
- A dataset day turns out to lack columns the pipeline needs.
- A dependency cannot be installed offline.
- Scope would grow past the milestone's acceptance criteria.

## Context you cannot infer

- CIC-IDS-2018 ships attack-**type** labels, not kill-chain **stage** labels. Stage labels are
  derived from the UNB attack timeline in `data/timeline_labels.py`. That mapping is a
  deliverable in itself — see `docs/stage_mapping.md`.
- Only the `02-20-2018` processed CSV carries `Src IP` / `Dst IP` columns. Other days need
  features recomputed from PCAP. This forces an early decision — M1, Task 1.4.
- `lateral_movement` and `exfiltration` have **no training data** in the public dataset. They
  come only from our own lab capture. Never report per-class metrics for them without saying so.
- The dataset has known label errors (Liu et al. 2022). Do not chase the last 0.5% of F1.
