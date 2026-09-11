# Roadmap

`docs/limitations.md` says what this cannot do. This says what would fix it, in the order we
would actually do it. **Nothing below is claimed as working.** The dividing line is enforced by
CLAUDE.md, which forbids building the §3 items at all — they are pitch content, and they are
labelled as such here.

## 0. What is already shipped (the baseline this builds on)

Windowed packet+flow extraction, TGN encoder, causal GRAFT transformer, k-step head
(ranking only), offline engine with named-feature TreeSHAP, hash-chained Merkle ledger with an
offline verifier, and a Streamlit demo — M0–M10 tagged, see `README.md`. Everything below is
*not* that.

## 1. Engineering roadmap — the repo's own open items

These are not ideas; each one is an open defect or decision already written down in this
repository, with the evidence that sizes it.

| # | Work | Why | Evidence |
|---|---|---|---|
| 1.1 | **GPU seed-averaging** (`scripts/gpu_experiments.py`, pack E1): N TGN seeds, rank-mean | The only documented path to a **forward-horizon operating point**. The k-step head currently fires 0/2 episodes at the 1 % budget, and the oracle analysis proves no threshold recovers it — it is a ranking limit. Seed-averaging also replaces a single deterministic point with a distribution | `tier1_hardening_report.md` Part 2 + "Open decisions" #3 |
| 1.2 | **Record the M11 lab capture** | `lateral_movement` and `exfiltration` have **zero** labelled windows in CIC-IDS-2018, so two of seven stages are untrained and unmeasured. The capture kit (`capture/capture.sh`, `capture/attack_scenarios.md`, `capture/label_capture.py`, `capture/CONSENT.md`) is written and untagged; it needs hardware and a session | `docs/stage_mapping.md` class table; `README.md` M11 row |
| 1.3 | **Slow-scan degradation curve** | `capture/attack_scenarios.md` scenario 5 (`nmap -T1`) exists precisely to measure how lead time decays under pacing — the cheapest evasion in `docs/threat_model.md` §3.3. Currently **TBD** | `capture/attack_scenarios.md` §5; BUILD_PLAN 11.5 |
| 1.4 | **Engine-side fusion** | The published headline is the rank-mean fused model, but the deployed engine scores with a **single XGBoost model**. The pitch number and the demo are different models, disclosed but not reconciled | `README.md` "One deployment note"; `docs/architecture.md` §3 |
| 1.5 | **Causal refit of the fusion** | The fused rank transform is fitted on the split it scores, so its operating point is not computable online. A causal refit is already sized: AUROC ≈ 0.930 holds, F1 drops 0.172 → 0.053 | `tier1_hardening_report.md` defect #3 |
| 1.6 | **Alert coalescing into incidents** | Not implemented anywhere — a repo-wide grep finds no coalescing or incident-grouping code. It is the single largest lever on operator load; see `docs/deployment.md` §5 for the arithmetic it has to fix | — |
| 1.7 | **Settle `net24_bucket`** | Dropping it *raises* every graded metric (xgb F1 0.140 → 0.392, recall 0.114 → 0.452, lead → ~86 min) at the cost of 0.080 AUROC, and removes a dependence on an anonymisation-key artifact an attacker can re-roll by renting a different /24 | `tier1_hardening_report.md` Part 3 |
| 1.8 | **Settle the evaluation unit** | Row multiplicity (8.7 rows per attacker host-window) inflates AUROC/F1. De-duplicated: fused 0.933 → 0.888, F1 0.172 → 0.040; lead time and 2/2 episodes unchanged. Both bases are defensible; publishing one is a decision, not a fix | `tier1_hardening_report.md` "Open decisions" #0 |
| 1.9 | **Hash the training inputs** | `scripts/verify_weights.py` digests training *outputs* only. Adding the timeline, `data/splits.yaml` and an interim-parquet manifest to the same record closes the poisoning gap in `docs/threat_model.md` §4 | `docs/threat_model.md` §4 |
| 1.10 | **IPv6 and QUIC feature blocks** | The extractor parses **IPv4 only** — `data/packet_features.py` skips any frame whose ethertype is not `0x0800`, so IPv6 traffic reaches **no feature at all**, and QUIC is seen as opaque UDP with no flag or window structure. Both are ordinary in a modern network. The drop is no longer *silent*: skipped frames are counted by reason (`DROP_REASONS`, `ipv6` its own bucket) and `engine/predict.py:_coverage` surfaces them as `unparsed_frames` on the `predict_file` result, in `run_summary.json`, and on the Streamlit page via `panels.coverage_note`. Counted is not parsed, though — an IPv6-only capture still yields zero host-windows and zero alerts, so this item is a parse path, not a better counter | `data/packet_features.py` (`DROP_REASONS`, `_ETH_IPV4` branch); `engine/predict.py:_coverage`; `docs/limitations.md` §5 |
| 1.11 | **Suricata / Zeek head-to-head** | We argue the positioning in `docs/competitive.md` but have **not run** either tool over the test day. Until we do, the comparison is analytical | `docs/competitive.md` §4 |

## 2. Ledger roadmap

`ledger/` ships a hash chain + per-batch Merkle roots + anchored checkpoints, verifiable offline
by `python -m ledger.verify_cli`. A live blockchain push was **deliberately not built** (BUILD_PLAN
M9): the demo must run air-gapped, and a chain that needs a network call to verify defeats that.

The honest extension is **optional** public-chain anchoring of *checkpoints only*: the chain head
hash is already a 32-byte value written to a separate checkpoint log, so publishing that one hash
to a public chain (or any third-party timestamping service) at a chosen cadence buys
third-party time attestation without moving any record off the air-gapped host, and without the
verifier ever needing a network. It stays optional because the offline property is the deployment
advantage (`docs/deployment.md` §4), not a compromise.

## 3. Mission roadmap — slide content, deliberately not built

CLAUDE.md: *"Do not build the roadmap features (defence orchestrator, deception, host/identity
telemetry, federated retraining). They are slide content."* They are here as the sustainability
story, marked as what they are.

- **Defence orchestrator.** Today the system emits a ranked, explained forecast and stops — it
  has no actuator by design. The extension turns a forecast into a staged response (rate-limit,
  quarantine a VLAN, force re-auth), gated on the same FPR budget. Prerequisite is 1.6: at
  ~84,000 alerts/day (`docs/deployment.md` §5) an orchestrator would be an outage generator.
- **Deception.** A forecast with lead time is only worth the time it buys. Honeytokens and
  decoy services placed on the hosts a forecast is rising on convert lead time into attacker
  cost and into a much cleaner label — a touch on a decoy is a near-zero-false-positive signal,
  which is exactly what §1.6 and `docs/dataset_quality.md` say the label supply lacks.
- **Host and identity telemetry.** Two of the seven stages (`lateral_movement`, `exfiltration`)
  are the ones network telemetry sees worst and endpoint/identity telemetry sees best. Fusing
  process and authentication events would address the same gap 1.2 attacks from the network side.
- **Federated retraining.** Multiple air-gapped sites cannot pool traffic — that is the point of
  air-gapping. Sharing model updates rather than data is the standard answer, and it composes
  with the ledger: every update is already a hashable artefact with a digest the engine enforces.
  CLAUDE.md separately forbids online learning at inference; this is **scheduled batch** only.

## 4. What we would not do

- **Chase F1 on CIC-IDS-2018.** The dataset's label defects are documented
  (`docs/dataset_quality.md`) and CLAUDE.md forbids it.
- **Add architecture without an ablation row.** Latent overshooting, CfC, Mamba, categorical
  latents, a backward-forecast head, a variable-selection gate and FlashAttention are all named
  in CLAUDE.md as things that must earn a row or not ship. The RSSM is the precedent: it failed
  its gate and was published as a negative result (`docs/decisions/004`) rather than kept.
- **Move the demo online.** Every roadmap item above has to survive the offline constraint or it
  does not ship.
