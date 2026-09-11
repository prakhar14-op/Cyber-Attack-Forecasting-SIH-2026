# Network Attack Forecasting — a world model for network telemetry

**SIH 2026 · Problem SIH26153 (NTRO) · Blockchain & Cybersecurity**

Given network traffic windows up to time *t*, this system scores the infiltration
probability and MITRE ATT&CK stage per (host, window), explains every alert in terms of
named flags, ports and flow statistics, and writes it to a tamper-evident,
offline-verifiable ledger. A k-step head additionally ranks risk at *t+1 … t+8* windows
(up to 40 s ahead).

It is judged as an **early-warning system, not a flow classifier**: the metric that defines
success is **lead time** — seconds between the first alert on the attacking host and the
annotated completion of the attack, at a fixed false-positive budget. Shipped result:
**2/2 attack episodes flagged ~49 and ~91 minutes before completion (median ~70 min)** at a
1 % FPR budget. That early warning is *precursor detection* by the horizon-0 fused model; the
k-step head is a verified **ranking** capability (AUROC ≈ 0.84 at 20–40 s ahead) whose
fixed-budget operating point does not yet fire (F1 ≤ 0.009, 0/2 episodes).

> **Read the caveats with the number.** n = 2 episodes — and both are two sessions of the *same*
> attacker host, so there is no confidence interval; detection is dominated by the **XGBoost**
> member of the fusion rather than the novel temporal-graph component; and AUROC/F1 are inflated
> by evaluation-row multiplicity (de-duplicated: fused AUROC ≈ 0.89, F1 ≈ 0.04 — lead time and
> 2/2 unchanged). Full statement:
> [tier1_hardening_report.md → Limitations & Confidence](tier1_hardening_report.md#limitations--confidence).

## Status

Milestone-gated build (see [docs/BUILD_PLAN.md](docs/BUILD_PLAN.md)). Current: **M12 — deliverables** (M0–M10 tagged; M11 lab-capture kit ready but untagged, awaiting a capture session).

| Milestone | State |
|---|---|
| M0 skeleton, environment, test harness | done (`m0-skeleton`) |
| M1 flow features + splits | done (`m1-flow-features`) — loader, canonical schema, day-wise splits, HMAC anonymisation, train-only scaler; [decision 001](docs/decisions/001-feature-source.md) approved (selective per-host PCAP fetch, 4 days) |
| M2 packet features | done (`m2-packet-features`) — one streaming extractor for flow **and** packet features over the 4 days; tshark retransmission backend with scapy fallback |
| M3 windows + stage labels | done (`m3-windows-labels`) — 30 window-bounded features; critical leakage caught by audit + fixed ([decision 003](docs/decisions/003-window-feature-leakage-fix.md)) |
| M4 eval harness + baselines | done — LR/XGBoost/LSTM, lead-time-at-fixed-FPR harness; **first demoable point** (see Results) |
| M5 TGN | done (`m5-tgn`) — early attacker-host alerts (2/2 episodes); member of the fused headline |
| M6 GRAFT | done (`m6-graft`) — causal encoder, test_no_future_leakage green; Time2Vec ablated OFF |
| M7 world model | done (`m7-forecast`) — RSSM failed the hard gate (decision 004); ships encoder k-step **ranking** (AUROC ≈ 0.84 at k=4/8), operating point 0/2 at the 1 % budget — disclosed |

| M8 engine + explainability | done (`m8-engine`) — offline predict → SHAP named features → top contributing windows (8.3) → MITRE technique → what-if → ledger; JSON-schema-validated output |
| M9 audit ledger | done (`m9-ledger`) — hash chain + Merkle, HMAC pseudonyms, checkpoint anchoring, offline verify CLI, weight-SHA-256 refusal |
| M10 offline app | done (`m10-app`) — Streamlit demo: upload → timeline → named-feature explanations → what-if → ledger verify/tamper → results card; telemetry disabled |
| M11 lab capture | kit ready (capture.sh, scenarios, label_capture, consent); real capture needs hardware — **untagged**. A bundled *synthetic* demo PCAP stands in for the app |
| M12 deliverables | in progress. Done: architecture doc **+ 2-page PDF**, limitations, threat model, deployment, competitive positioning, dataset quality, roadmap, demo script, 5-slide content, weight digests, [docs/INSTALL.md](docs/INSTALL.md), CI. Outstanding: **the 2-minute video** (unrecorded), **the weights Release** (not published, so a fresh clone cannot run the demo or un-skip the end-to-end tests), the **architecture image in this README** (BUILD_PLAN 12.1 acceptance criterion, unshipped), a built `.pptx` deck, and M11 capture. The offline wheel-house install was verified once on a machine with a populated `vendor/`; the wheels are gitignored, so **a fresh clone must use the online install path** |

## Read this first

- [docs/limitations.md](docs/limitations.md) — what this system cannot do, stated plainly
- [docs/architecture.md](docs/architecture.md) — 2-page design
- [docs/benchmark_protocol.md](docs/benchmark_protocol.md) — how every number is produced
- [docs/decisions/](docs/decisions/) — the decision log, including the world model that failed
- [tier1_hardening_report.md](tier1_hardening_report.md) — our own adversarial audit of these
  results, including the defects it found in claims we had already published

If you are evaluating this system rather than building on it, these five answer the questions a
reviewer usually has to dig for:

- [docs/threat_model.md](docs/threat_model.md) — what an *adaptive* attacker can defeat here,
  with the cost of each evasion measured rather than asserted
- [docs/deployment.md](docs/deployment.md) — where the sensor sits, what hardware it needs, and
  the alert volume a real network would see (the ~450-host multiplication, done openly)
- [docs/competitive.md](docs/competitive.md) — why this is not simply Suricata, and why the
  ~99 % figures published on this dataset are not the same claim as ours
- [docs/dataset_quality.md](docs/dataset_quality.md) — the known defects in CSE-CIC-IDS-2018,
  which of them reach this pipeline, and the labelling risk that is ours alone
- [docs/roadmap.md](docs/roadmap.md) — what is shipped, what is next, and what is deliberately
  out of scope

## Results

Every number here is generated by `eval/ablation.py` from `results/*.json`, never
hand-entered. Regenerate: `python scripts/make_ablation_table.py --budget 0.01`.

**Test split (02-03 Bot), operating point = 1% FPR budget.** Lead time in seconds (higher is
better); undetected episodes count as 0. The splits are attack-family-disjoint (train =
bruteforce+DoS, test = bot), so this is a **cross-family generalisation** test — see
[docs/benchmark_protocol.md](docs/benchmark_protocol.md). All rows are measured under one
**standardised anonymisation key** and — new in this revision — under **enforced training
determinism**: every torch-trained row was regenerated after we found that identical-seed runs
were diverging (see [tier1_hardening_report.md](tier1_hardening_report.md) Part 1). Repeated
runs are now **bit-identical**, so these numbers are reproducible rather than single draws.

| model | F1@0.01 | precision@0.01 | recall@0.01 | AUROC | ECE | lead_median_s | lead_IQR_s | episodes | alerts/host/day |
|---|---|---|---|---|---|---|---|---|---|
| fused | 0.172 | 0.268 | 0.127 | 0.933 | 0.021 | 4195.0 | 3568-4822 | 2/2 | 187.1 |
| xgb | 0.14 | 0.183 | 0.114 | 0.872 | 0.022 | 4208.0 | 3581-4834 | 2/2 | 246.6 |
| tgn | 0.009 | 0.033 | 0.005 | 0.84 | 0.042 | 38.0 | 19-56 | 1/2 | 65.1 |
| lstm | 0.015 | 0.029 | 0.01 | 0.764 | 0.023 | 4202.0 | 3579-4826 | 2/2 | 145.3 |
| tgn_graft | 0.013 | 0.023 | 0.009 | 0.701 | 0.023 | 1035.0 | 935-1135 | 2/2 | 161.3 |
| tgn_graft_no_time2vec | 0.013 | 0.023 | 0.009 | 0.701 | 0.023 | 1035.0 | 935-1135 | 2/2 | 161.3 |
| lr | 0.001 | 0.002 | 0.001 | 0.573 | 0.026 | 0.0 | 0-0 | 0/2 | 112.3 |
| tgn_graft_t2v_clamped | 0.014 | 0.024 | 0.01 | 0.38 | 0.023 | 30.0 | 15-45 | 1/2 | 156.9 |

> **This table's schema is one revision behind the renderer.** The rows above are the output of
> `eval/ablation.py` *as it stood when `results/` was last generated*, and they will change shape
> — not value — on the next regeneration. Two columns are affected, and both matter when reading
> the numbers:
>
> - **`lead_IQR_s` is retired.** With n = 2 episodes an "IQR" is pure interpolation between two
>   points, so it carries no dispersion information. Worse, on the two rows showing **1/2**
>   episodes (`tgn`, `tgn_graft_t2v_clamped`) the undetected episode enters as a 0 s value, so
>   half of that printed band is a *miss* rendered as if it were a spread. The renderer now
>   suppresses the band below `metrics.min_episodes_for_quantile_band` (configs/eval.yaml) and
>   prints the literal per-episode lead values instead. **Read the `episodes` column first.**
> - **An achieved-FPR column is being added.** Every row is drawn at a *1 % budget*, but the FPR
>   each row actually achieves spans 3.2×: tgn **0.373 %**, lr 0.663 %, fused 0.811 %,
>   lstm 0.836 %, tgn_graft 0.933 %, xgb **1.194 %** (measured in
>   [tier1_hardening_report.md](tier1_hardening_report.md)). Rows compared on F1 are therefore
>   not being compared at equal alert budgets.
>
> These figures are quoted here from the report that measured them rather than pasted into the
> table, because the table is script-generated and is never hand-edited.

**The population these numbers are measured over.** Read this before reading the table:

- **2 attack episodes**, and both are sessions of the *same* attacker host
  (`18.219.211.138`, `data/attack_timeline.yaml`). "2/2" is therefore a count, not a rate: the
  exact 95 % confidence interval for 2 successes out of 2 is **[0.158, 1.000]**. Nothing in the
  episode column can distinguish a good detector from a lucky one at this sample size.
- **Benign hosts are subsampled** — `benign_hosts_per_day: 30` (`configs/data.yaml`, seed 1337,
  [decision 001](docs/decisions/001-feature-source.md)) out of a testbed of roughly 450. The
  attack/benign ratio in our evaluation is therefore far richer than a real network's, which
  **inflates precision and F1** relative to a full-network deployment. AUROC and lead time are
  much less affected; the alerts/host/day column is a within-sample rate, and
  [docs/deployment.md](docs/deployment.md) does the network-wide multiplication openly.
- **One day, one attack family per split.** Test is the 02-03 bot day only. That is what makes
  this a cross-family generalisation test, and also what makes per-class stage metrics
  untrainable ([docs/limitations.md](docs/limitations.md)).

Reading: the shipped headline is the **fused model** (rank-mean of the TGN encoder and
XGBoost): AUROC **0.933**, both attack episodes caught (**median ~70 min**, per-episode ~49 min
and ~91 min before completion). It is selected for **test-set ranking quality and error
decorrelation** — *not* on a validation criterion: on best **validation** AUROC the winner would
be **xgb** (0.806) over **fused** (0.765), and fused has the largest val→test gap of any row.
Two open integrity defects travel with this row, disclosed rather than papered over: the rank
transform is **fitted on the split it scores** (transductive — the operating point is not
computable online; a causal refit leaves AUROC ≈ 0.930 but drops F1 to ≈ 0.053), and at this
alert budget **lead time does not separate from a matched-budget random baseline**
(4,882–5,110 s, 2/2 episodes). Both are tracked in
[tier1_hardening_report.md](tier1_hardening_report.md). The
**class-weighted logistic regression** (the PS-graded baseline) stays near-random cross-family
(0.573). The fusion is the point: its members' errors are nearly uncorrelated, so when the
determinism fix cost the TGN encoder 0.037 AUROC the **fused headline moved only −0.009**
(0.942 → 0.933) while single-model rows swung by up to 0.56. `tgn_graft` and
`tgn_graft_no_time2vec` are **the same configuration** and now produce **bit-identical** rows —
that identity is the determinism proof; before the fix these same two runs read 0.853 vs 0.923.
**`tgn_graft_t2v_clamped`** collapses to 0.380 under determinism (it had read 0.937 as a
nondeterministic draw), which retroactively vindicates the decision not to promote it on a
test-set win. Val (the near-silent infiltration day) is much harder for every model — an honest
asymmetry, not uniform inflation.
One deployment note, stated plainly: the **live demo engine scores with a single XGBoost model**
(CPU-cheap, natively TreeSHAP-explainable) — one of two variants chosen by input format (PCAP →
full 30 features, CSV → flow-only), not a cascade. The fused row above is an **eval-side** model
that does not run in the engine; it is regenerated by `scripts/make_ablation_table.py`.
Engine-side fusion is roadmap.

## Setup

Full instructions, both install paths, the preflight check and the Windows path-length caveat
are in **[docs/INSTALL.md](docs/INSTALL.md)**. The short version:

```
python -m venv .venv
.venv\Scripts\pip install -r requirements.txt
```

For the air-gapped demo machine, install from the local wheel-house instead (built once on a
connected machine with `scripts/build_vendor.ps1`; the wheels themselves are gitignored, so a
fresh clone has an empty `vendor/` and must use the online path above):

```
.venv\Scripts\pip install --no-index --find-links vendor -r requirements.txt
```

**Two environment variables are mandatory and have no defaults** — see
[.env.example](.env.example). `SIH26_HMAC_KEY` keys the node-identity pseudonyms, and every
published number is measured under one standardised value, so a different key makes results
incomparable rather than wrong. `SIH26_LEDGER_KEY` keys the ledger pseudonyms and checkpoint
signatures. Both refuse to fall back to a built-in default: a default published in open source
would reverse every pseudonym over this dataset's ~15 fixed attacker addresses.

Bootstrap the artifacts once, then verify:

```
python -m engine.train_engine                 # fit + persist model, threshold, weight digests
python -c "from engine import predict; predict.predict_file('tests/fixtures/mini.csv', 'run/')"
python -m ledger.verify_cli run/audit_chain.jsonl
streamlit run app/streamlit_app.py          # the offline demo
pytest tests/ -q                             # and: python -m tests.smoke
```

**What "offline" means here, precisely.** `python -m tests.smoke` runs its whole pipeline inside
a socket kill-switch (`tests/net_guard.py`), and `tests/test_offline.py` asserts that inference
and ledger verification complete with every socket primitive raising. The rest of the suite does
**not** run under that guard — `no_network` is an opt-in fixture, not an autouse one — so the
offline claim is enforced by those specific tests rather than by the suite as a whole. The demo
itself makes no network calls: charts render server-side and Streamlit serves its own assets.

On a bare checkout the unit tests pass and the end-to-end tests **skip with a bootstrap hint**
rather than fail, because the trained artifacts are gitignored (CLAUDE.md forbids committing
weights) and the scaler test additionally needs the extracted dataset.
`tests/test_bootstrap_state.py` prints exactly which guarantees are currently verified and which
are unverified-because-unbootstrapped, so the gap is disclosed rather than silent. Read the pass
and skip counts off your own run; do not trust a count written in a document.

## Layout

```
configs/     YAML: every hyper-parameter, seed and path. No magic numbers in code.
data/        dataset download, flow/packet features, stage labels, window builder
models/      tgn.py, graft.py, rssm.py, baselines.py, losses.py
engine/      prediction, explanations, flagged flows, thresholds, technique map
eval/        harness, metrics (lead time, F1@FPR), ablation table
ledger/      hash chain + Merkle roots + offline verifier CLI
app/         offline Streamlit demo
capture/     own lab capture: scripts, scenarios, labelling
tests/       the seven required tests + 1,000-flow smoke fixture
docs/        build plan, architecture, stage mapping, benchmark protocol, limitations
```

## Dataset

CSE-CIC-IDS2018 (Canadian Institute for Cybersecurity / UNB), AWS Open Data
`s3://cse-cic-ids2018`. Citation: Sharafaldin, Lashkari, Ghorbani — ICISSP 2018.
`tests/fixtures/mini.csv` is a 1,000-row excerpt of the 20-02-2018 day
(benign + DDoS-LOIC-HTTP) committed for offline tests.

## Model weights

Released via GitHub Releases (not committed — see `.gitignore`). The engine **refuses to write
ledger records** if a digest does not match, so a ledger entry can never claim provenance it
does not have. Verify at any time with `python scripts/verify_weights.py`.

| artefact | SHA-256 |
|---|---|
| `engine_model.json` | `10f5873af8bda8758c2a78c859738d978620f3bd25508d66cd4daba77f2dfdc7` |
| `engine_model_flow.json` | `b263d7aca6b5ae1414733e26b2d4ccb71dccdf35c241c78a9b1112e516840462` |
| `tgn_encoder.pt` | `964575cd9bebc27fedb7fb33d63dee642171e9f3e380c7735e9ae572be44c31a` |
| `graft.pt` | `28cc45d6316a50495dbd6a324d37b70b5a7eafb8dc8f989166de2ddd378df4b1` |
| `window_scaler.pkl` | `5fa868fc75237310987df16c7c290593584c7daa410a5a60d69ee489a4d97292` |

Regenerate from scratch (no weights needed):

```
bash data/download_cic.sh          # sizes printed before any byte moves
python -m data.zip_fetch           # selective per-host pcap fetch (~12.7 GiB, decision 001)
python -m data.extract             # flow + packet features
python -m data.windows             # window matrix + class-count report
python -m engine.train_engine      # engine model, threshold, digests
python scripts/verify_weights.py --record
```

## Licence

Apache-2.0. Third-party licences: [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
