# BUILD_PLAN.md — SIH26153 execution plan

Companion to `CLAUDE.md`. Milestones are ordered so the repo is **demoable from M4 onward**.
Never start milestone *n+1* before *n*'s acceptance criteria pass and the tag is cut.

Timeline assumption: submission ~28 Sept (portal shows 30 Sept — verify), grand finale December.
M0–M7 must land before submission. M8–M11 are the finale window.

```
M0 skeleton ──> M1 flow features ──> M2 packet features ──> M3 windows + stage labels
                                                                    │
                                    M4 eval harness + baselines <───┘   ← first demoable point
                                                │
                     M5 TGN ──> M6 GRAFT ──> M7 RSSM ──> M8 engine + explain
                                                                    │
                             M9 ledger ──> M10 app ──> M11 capture ──> M12 deliverables
```

---

## M0 — Skeleton, environment, test harness

**Why first:** every later milestone is verified by the harness built here. Building it last means
nothing is verified.

| # | Task | Done when |
|---|---|---|
| 0.1 | Repo layout per `CLAUDE.md`; Apache-2.0 LICENSE; `.gitignore` excluding `weights/`, `*.pcap`, `data/raw/` | `tree -L 2` matches the layout |
| 0.2 | `environment.lock.yml` + `requirements.txt`, fully pinned. Verify a clean install works with pip's index unreachable (pre-downloaded wheels in `vendor/`) | `pip install --no-index --find-links vendor -r requirements.txt` succeeds |
| 0.3 | `configs/` with `data.yaml`, `train_*.yaml`, `eval.yaml`; a single `load_config()` helper; global seed setter | No module reads a literal path or seed |
| 0.4 | `tests/fixtures/mini.csv` — 1,000 real flow rows spanning benign + one attack, committed | Under 500 KB |
| 0.5 | Write all seven tests from `CLAUDE.md` as **failing stubs** with real assertions | `pytest -q` shows 7 failures, 0 errors |
| 0.6 | `tests/test_offline.py` blocks `socket.socket` via monkeypatch and fails the run on any network attempt | Passing this test is what "offline" means for the rest of the project |

**Prompt to open with:**
> Read CLAUDE.md and docs/BUILD_PLAN.md. Execute M0 only. Do not create model files yet.
> The seven tests must exist as failing stubs with real assertions, not `pass`.

**Tag:** `m0-skeleton`

---

## M1 — Flow-level feature pipeline and splits

| # | Task | Done when |
|---|---|---|
| 1.1 | `data/download_cic.sh`: `aws s3 sync --no-sign-request` for the chosen days only. Print sizes before downloading | Dry-run mode prints the plan without downloading |
| 1.2 | CSV loader handling the dataset's real defects: repeated header rows mid-file, `Inf`/`NaN` in `Flow Byts/s` and `Flow Pkts/s`, mixed timestamp formats, whitespace in column names | Loader test on `mini.csv` plus a deliberately corrupted copy |
| 1.3 | Canonical schema: `timestamp, src_ip, dst_ip, src_port, dst_port, protocol, duration, fwd_bytes, bwd_bytes, fwd_pkts, bwd_pkts, syn, ack, fin, rst, psh, urg, iat_mean, iat_std, iat_max, init_win_fwd, init_win_bwd, label` | Column mapping lives in `configs/data.yaml`, not in code |
| **1.4** | **DECISION TASK — stop and report.** Only `02-20-2018` has IP columns. Compare: (a) recompute all features from PCAP with one tool for all chosen days, (b) restrict to days with IPs. Report time, disk and feature-parity cost for each, then wait | A short written recommendation in `docs/decisions/001-feature-source.md`. Do not proceed alone |
| 1.5 | `data/splits.yaml`: day-wise train/val/test; loader raises if any day appears twice | `test_splits_disjoint.py` green |
| 1.6 | Scaler fitted on train split only, persisted to `artifacts/scaler.pkl` | `test_scaler_train_only.py` green |
| 1.7 | IP anonymisation: keyed HMAC + per-epoch permutation; role-only node features | A held-out-attacker-IP evaluation mode exists in the config |

**Tag:** `m1-flow-features`

---

## M2 — Packet-level feature extractor (the PS's Missing item)

`data/packet_features.py`, PyShark or Scapy (both named in the PS). Output keyed on
`(src_ip, window_id)` so it joins cleanly onto flow features.

Required fields: `ttl_mean, ttl_var, tcp_win_mean, tcp_win_var, frag_flag_count,
payload_hist_0..7, distinct_dst_ports, sequential_port_ratio, port_entropy,
retransmission_count`.

| # | Task | Done when |
|---|---|---|
| 2.1 | Streaming PCAP reader — never load a whole capture into memory | 1 GB PCAP processed under 4 GB RSS |
| 2.2 | Retransmissions via `tcp.analysis.retransmission` (tshark) with a pure-Scapy fallback | Both paths give the same count on the fixture |
| 2.3 | `sequential_port_ratio`: fraction of consecutive dst-port accesses from one host that differ by exactly 1 — separates sequential from randomised scans | Unit test with a synthetic sequential scan and a randomised one |
| 2.4 | Join test: flow-window and packet-window keys align, no silent row loss | Row-count assertion in the test |
| 2.5 | Same extractor runs on our own capture — one code path, not two | `capture/` fixture passes |

**Tag:** `m2-packet-features`

---

## M3 — Window builder and stage labels

| # | Task | Done when |
|---|---|---|
| 3.1 | `data/windows.py`: 15 s / 5 s sliding, per source host; ~45 named features; explicit `feature_names.json` used everywhere downstream | Feature order is stable and asserted |
| 3.2 | `data/timeline_labels.py`: UNB attack timeline (attack, date, attacker IP, victim IP, start, end) → per-window stage label using the 7 classes | `docs/stage_mapping.md` generated from the same table the code uses |
| 3.3 | Label the window as attack-stage only if the attacking host actually transmits inside it — no smearing across the whole day | Test on a known attack interval |
| 3.4 | Class-count report printed at build time; write it into `docs/stage_mapping.md` | Small classes (web attacks) flagged explicitly |
| 3.5 | Padding mask for sequences shorter than 48 | Consumed by GRAFT in M6 |

**Tag:** `m3-windows-labels`

---

## M4 — Evaluation harness and baselines ← **first demoable point**

Build this before any deep model. Every later milestone is judged by it.

| # | Task | Done when |
|---|---|---|
| 4.1 | `eval/metrics.py`: F1/precision/recall at **fixed FPR** (0.1%, 1%), AUROC, ECE + reliability data, **median lead time with IQR**, alerts/day at the operating point | Unit tests with hand-computed values |
| 4.2 | Lead time defined precisely: first alert on the attacking host → annotated attack completion (or first successful login / first large transfer in our capture). Undetected episodes counted as 0, not dropped | Definition also written into `docs/benchmark_protocol.md` |
| 4.3 | `models/baselines.py`: class-weighted logistic regression (PS-mandated), XGBoost, LSTM-over-windows | All three train from one config |
| 4.4 | `eval/harness.py` — one command runs any model over the split and emits `results/<name>.json` | `python -m eval.harness --model lr` works |
| 4.5 | `eval/ablation.py` builds the comparison table from the JSONs; `scripts/make_ablation_table.py` renders Markdown for the README | Table has a row per model, columns per metric |
| 4.6 | Leave-one-attack-family-out mode for the generalisation table | `--holdout-family bot` runs |

**Acceptance:** a real ablation table with LR / XGBoost / LSTM rows and honest numbers. Expect
XGBoost to be strong at horizon 0. That is fine and expected — record it.

**Tag:** `m4-baselines`

---

## M5 — Temporal graph + TGN

| # | Task | Done when |
|---|---|---|
| 5.1 | Graph builder: anonymised host nodes, flow edges with timestamp + attributes; PyG `TemporalData` format | Round-trip test |
| 5.2 | TGN via `torch_geometric.nn.models.TGNMemory` + last-neighbour loader; per-window readout for each source host | Output shape `[hosts, windows, embed_dim]` |
| 5.3 | Memory reset between splits — never carry train memory into test | Explicit test |
| 5.4 | `GraphSAGE-per-window` fallback behind `configs/train_tgn.yaml: model: sage` | Both paths produce the same interface |
| 5.5 | Run through the M4 harness at horizon 0 and add the `TGN + linear head` row | Row present in the ablation table |

**Stop condition:** if TGN does not train stably in two working days, switch to the fallback and
record it in `docs/decisions/`. Do not spend a week here.

**Tag:** `m5-tgn`

---

## M6 — GRAFT encoder

`models/graft.py`. Ship the four load-bearing pieces only.

| # | Task | Done when |
|---|---|---|
| 6.1 | **Causal** `TransformerEncoder` (2 layers, 4 heads) with `generate_square_subsequent_mask` and padding mask | `test_no_future_leakage.py` green — this is the most important test in the repo |
| 6.2 | Time2Vec on inter-arrival time, added to the window embedding in place of sinusoidal PE | Ablation row with and without |
| 6.3 | Heads: attack probability, 7-class stage, **Dirichlet** evidential (alpha = softplus+1, uncertainty = K/S, expected-CE loss with annealed KL) | ECE and reliability plot produced by the harness |
| 6.4 | Reconstruction head trained on **benign windows only** (masked loss) as the OOD signal | Loss test with an all-attack batch (must not NaN) |
| 6.5 | Composite loss with class weighting for imbalance; loss weights in config | `models/losses.py` covered by tests |
| 6.6 | Harness row: `TGN + GRAFT` at horizon 0 | Row present |

**Do not build yet:** variable-selection gate, backward-forecast head. They are optional
ablation candidates for the finale window, not submission scope.

**Tag:** `m6-graft`

---

## M7 — RSSM world model (the actual "world model" deliverable)

| # | Task | Done when |
|---|---|---|
| 7.1 | Tier 1: deterministic GRU transition, K-step rollout, heads applied to the **decoded** state (not raw `h`) | `test_shapes.py` green for K=1 and K=8 |
| 7.2 | **Filter-then-imagine**: posterior steps over all observed windows → `(h_T, z_T)` → prior rollout. Never start from zeros | Explicit test that the initial state depends on the input sequence |
| 7.3 | Tier 2: stochastic latent, prior/posterior nets, explicit decoder, KL-balanced loss with free bits | KL monitored and logged; alert if it collapses below the floor |
| 7.4 | **Supervised K-step dynamics loss** — the PS's "supervised dynamics learning": `CE(stage_head(decode(h_k, z_k)), stage_label[t+k])` weighted `0.9^k` | Ablation row with and without |
| 7.5 | Missing/empty window guard (`is_valid_window`, carry-forward with `delta_t` preserved) | Test with a gap injected |
| 7.6 | Ensemble rollout (20 samples) → mean + band; disagreement as the second OOD signal | Band widens with horizon — assert it in a test |
| 7.7 | Harness rows at horizon k = 1, 4, 8, with lead time | The lead-time plot exists |

**This is where the project either works or does not.** If the world model shows no lead-time
advantage over XGBoost at k ≥ 4, stop and report before building anything else — the pitch
changes.

**Tag:** `m7-rssm`

---

## M8 — Prediction engine and explainability

| # | Task | Done when |
|---|---|---|
| 8.1 | Threshold selection from an FPR budget on the validation split; persisted with the model | No literal threshold in code |
| 8.2 | `engine/explain.py`: Integrated Gradients (Captum) from the prediction to the **named** feature vector, top-5 per alert | Output contains feature names, never indices |
| 8.3 | Attention over windows → top-3 contributing windows with timestamps | Shown in the same panel |
| 8.4 | TreeSHAP on the flow-level pre-filter for the "flagged flows" list the PS asks for | Ranked flow list per alerted host-window |
| 8.5 | `engine/technique_map.yaml`: stage + observed pattern → technique. Internal scan → **T1046**, external → T1595. Only techniques present in our data | Reviewed against `docs/stage_mapping.md` |
| 8.6 | Output object per step: probability, stage, technique, confidence verdict, uncertainties, top features, top windows, flagged flows, estimated lead time | JSON-schema validated |
| 8.7 | What-if: ablate a host's edges, re-encode, re-roll, return both curves | Test that removing the attacker's edges lowers the forecast on a real trace |

**Tag:** `m8-engine`

---

## M9 — Audit ledger

| # | Task | Done when |
|---|---|---|
| 9.1 | Hash-chained records for **alerts only**; per-minute **Merkle root** over all predictions | Write-rate test at 500 hosts scale |
| 9.2 | Keyed-HMAC pseudonyms for IPs; salted feature hash; salt in a separate owner-only file | No raw IP anywhere in `audit_chain.json` |
| 9.3 | Model-weight SHA-256 verified before every batch; refuse to log on mismatch | Test with a corrupted weight file |
| 9.4 | Append-only storage (SQLite or JSONL), not full-file rewrite per record | Benchmark in the test |
| 9.5 | Checkpoint anchoring: chain head + count appended to a separate log; `verify_against_checkpoints()` catches a full rewrite | `test_ledger_tamper.py` covers both single-edit and full-rewrite |
| 9.6 | `ledger/verify_cli.py` — standalone offline verifier a judge can run | `python -m ledger.verify_cli audit_chain.json` |

**Deliberately not built:** live blockchain push. One pre-anchored public checkpoint before the
demo is enough, and is honest.

**Tag:** `m9-ledger`

---

## M10 — Offline Streamlit app

| # | Task | Done when |
|---|---|---|
| 10.1 | Upload CSV **or** PCAP → full pipeline → results, with a progress indicator | Works on the bundled backup files |
| 10.2 | Probability timeline with confidence band, threshold line, stage annotations | Matplotlib/Altair, no CDN assets |
| 10.3 | Explanation panel: top features (named), top windows, flagged flows table | A stranger can read it without narration |
| 10.4 | What-if control: pick an edge, show both curves | One click |
| 10.5 | Ledger panel: verify / tamper / re-verify, checkpoint status | Demo beat 5 works |
| 10.6 | Results card: F1@1%FPR vs LR, median lead time, held-out-family row — read from `results/`, never hardcoded | Regenerates when the harness reruns |
| 10.7 | Runs under `test_offline.py` conditions | Green |

**Tag:** `m10-app`

---

## M11 — Own capture (lab evidence for the three stages with no labelled windows)

| # | Task | Done when |
|---|---|---|
| 11.1 | `capture/capture.sh`: one laptop as hotspot host/gateway, `tcpdump` on its interface, static IPs, written participant consent noted in `capture/CONSENT.md` | Documented, reproducible |
| 11.2 | Scenarios: 2 min benign warm-up → nmap `-sS` → hydra SSH → **SSH pivot (lateral movement)** → **large outbound transfer (exfiltration)**; plus a slow variant (`nmap -T1`) | `capture/attack_scenarios.md` with exact commands and timings |
| 11.3 | `capture/label_capture.py`: operator-recorded start/end times → per-window stage labels, same code path as `timeline_labels.py` | Labels validate against the schema |
| 11.4 | At least 3 clean takes; best one bundled as `app/assets/backup_capture.{csv,pcap}` | Under the git file-size limit or in a Release |
| 11.5 | Slow-scan degradation curve measured and plotted | Slide-ready |

**Tag:** `m11-capture`

---

## M12 — Deliverables

| # | Task | Done when |
|---|---|---|
| 12.1 | `README.md`: pitch, architecture image, offline setup, "run the demo in 3 commands", ablation table generated by script, weight SHA-256, dataset citation, licence | A stranger reproduces the demo from it alone |
| 12.2 | `docs/architecture.md` → 2-page PDF, structure per the review document | Exactly 2 pages |
| 12.3 | `docs/limitations.md` — the four honest limitations | Copied verbatim onto slide 5 |
| 12.4 | `docs/demo_script.md` — 2-minute video shot list with timings | Matches the app's actual behaviour |
| 12.5 | Weights + scaler + threshold released together; `scripts/verify_weights.py` | Hash matches the README and the ledger |
| 12.6 | Final offline test on a freshly imaged laptop | Zero pip installs at demo time |

**Tag:** `v1.0-submission`

---

## How to drive Claude Code

**Opening a session:**
> Read CLAUDE.md and docs/BUILD_PLAN.md. We are at M<n>. Show me the task list for this
> milestone and the acceptance criteria, then start with task <n>.1. Do not touch files
> outside the ones that milestone names.

**One task at a time.** Long autonomous runs on this project drift toward adding papers and
abstractions. Task-sized turns keep the ablation table honest.

**After every milestone:**
> Run pytest and the smoke test. Show me the ablation table as it stands. Then write a
> two-paragraph summary in docs/decisions/ of what changed and what surprised you.

**When it proposes a new component:**
> Which row of the ablation table does this add, and what does it cost in build time?
> If it cannot earn a row before <date>, put it in docs/roadmap.md instead.

**When a number looks great:**
> That F1 is suspicious. Check the causal mask, the split, the scaler and the node-identity
> anonymisation before we believe it. Write what you checked.

**Weekly:**
> Regenerate the ablation table and the lead-time plot from scratch on a clean checkout.
> Report anything that no longer reproduces.

---

## Risk register

| Risk | Trigger | Response |
|---|---|---|
| TGN unstable | No convergence in 2 days | GraphSAGE fallback (M5.4), documented |
| RSSM shows no lead-time gain | M7.7 rows flat vs XGBoost | Stop; report; consider shipping TGN+GRAFT at horizon k with the same rollout framing |
| PCAP processing too slow | M2 over 6 h per day of data | Reduce to 3 days; state the subset |
| Only one day has IPs | M1.4 | The decision task exists precisely for this |
| Offline install breaks | M0.2 or M12.6 | `vendor/` wheels; test on a clean machine early, not on demo day |
| Deadline pressure | Mid-September | M4 is already demoable. Ship the best tagged milestone, never a broken merge |
