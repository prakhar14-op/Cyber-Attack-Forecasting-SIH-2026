# Limitations

Stated plainly, because a reviewer will find them anyway and because CLAUDE.md forbids
fabricating results. Every number below traces to a file: the model-comparison figures via
`python scripts/make_ablation_table.py` (over `results/*.json`), the per-horizon and RSSM
figures from `results/forecast.json` / `results/world*.json`, and the flow-only vs full
operating points from `artifacts/engine_threshold.json`. Nothing here is hand-entered.

## 1. Two of the seven kill-chain stages have no training data at all

`lateral_movement` and `exfiltration` have **zero labelled windows** in CSE-CIC-IDS2018
(see the class table in `docs/stage_mapping.md`: both are 0 across train, val and test).
They exist in the taxonomy because the problem statement requires the full kill chain, and
they are the specific reason the lab capture (M11) exists. Until that capture is recorded,
**we report no per-class metric for those two stages** — any number we printed for them
would be invented.

Consequence: the shipped system forecasts a binary *infiltration probability* reliably, and
assigns a stage from interpretable named-feature rules. It is not a validated 7-class
classifier.

## 2. With four attack days, the splits are attack-family-disjoint

Day-wise splitting (mandatory — whole attack episodes must stay in one split, or the metrics
leak) with four attack days means **no attack family appears in both train and eval**: train
carries bruteforce + DoS, validation infiltration, test bot. Two consequences:

- The headline result is a genuine **cross-family generalisation** test, which is the honest
  hard version of the problem — and the reason the linear baseline collapses to 0.573 AUROC
  while the fused temporal model reaches 0.933 (all under the standardised anonymisation key and
  enforced training determinism; earlier unreproducible numbers were retired).
- **Multi-class stage metrics are not meaningfully trainable**: `c2` never appears in the
  training split, so the stage head cannot be expected to emit it on val/test.

## 3. CSV input cannot carry packet-level features

The problem statement accepts a CSV *or* a PCAP. A CICFlowMeter CSV has no packets, so the
packet-level features the PS itself mandates — TTL mean/variance, TCP window, fragment flags,
payload-size histogram, sequential-vs-random port-scan signature, retransmission counts —
**cannot be computed from CSV input at all**.

The deployed engine therefore runs a flow-only model so a CSV still produces self-consistent
forecasts, while the full model uses all 30 features from a PCAP. On the matched **validation**
split the two are close — flow-only **0.847** vs full **0.806** AUROC (`artifacts/engine_threshold.json`),
so the flow model is not worse there. We still recommend a PCAP not for a raw AUROC win but
because only the PCAP path carries the packet-level features the PS itself mandates (TTL, TCP
window, fragment flags, payload histogram, scan signature, retransmissions), and the headline
**test-split** numbers (full features: XGBoost 0.872, fused model 0.933 AUROC, 2-of-2 episodes)
are built on them. **Feed the demo a PCAP for the full, PS-compliant feature set**; the app warns
explicitly when given a CSV. This is not a bug we can engineer away — it is a property of the
input format.

## 4. The RSSM world model did not work; we ship the encoder instead

The planned deliverable was a Recurrent State-Space Model rolled forward K steps. It **failed
its own acceptance gate** (`docs/decisions/004`): the posterior collapsed, the uncertainty band
did not widen with horizon, and it detected **0 of 2** attack episodes with **0 s** lead time —
worse than the embeddings it consumes. A second attempt with the standard anti-collapse recipe
recovered most of the ranking (k=8 AUROC 0.683 → 0.851) but still detected 0/2 episodes.
(Those RSSM figures are the historical gate record from decision 004, measured before the
anonymisation key was standardised; the gate verdict — 0/2 episodes — is the decision-bearing
fact and did not depend on the key.)

We ship what actually works — and, after the determinism fix, we are precise about which
mechanism earns the headline. **Episode capture and lead time come from the horizon-0 fused
classifier** (2/2 episodes, ~49 min and ~91 min before completion, median ~70 min): precursor
detection on live windows, scored by the PS's own lead-time definition. The **k-step forecast
head** is retained as a verified *ranking* capability (test AUROC ≈ 0.84 at k=4 and k=8) whose
fixed 1 % operating point does not fire (0/2) — and the oracle check confirms that is a ranking
limit, not a recalibratable threshold, so we did not force a threshold fix. Seed-averaging on
GPU is the documented path to recover a forward operating point. The RSSM is recorded as a
negative result with its recipe, not quietly dropped. (The k-step head and the RSSM are two
*different* negative results: the RSSM failed its M7 gate and never shipped; the encoder forecast
head ships as a ranking capability whose operating point does not fire.)

The full statistical qualification of the lead-time headline — n = 2 sessions of one host,
XGBoost-dominated detection, what AUROC ≈ 0.84 does and does not mean, and the evaluation-row
multiplicity that inflates AUROC/F1 — is in
[tier1_hardening_report.md → Limitations & Confidence](../tier1_hardening_report.md#limitations--confidence).

## Also worth knowing

- **Benign traffic is subsampled** (~30 of ~450 hosts/day, seed 1337 — decision 001), so
  `alerts/day` is a within-sample extrapolation, not a full-network projection.
- **Our features are CICFlowMeter-*like*, not byte-identical** to the published CSVs: every
  model, including the graded LR baseline, is trained and scored on our own matrix, which is
  what makes the comparison fair.
- **Overlapping windows shorten the effective horizon**: 15 s windows on a 5 s stride mean
  window *t* and *t+3* are the first fully-disjoint pair, so k=1 and k=2 are near-nowcasts and
  only k=4 and k=8 are structurally ahead of the present. Even there the *label* being predicted
  is 93.5 % (k=4) and 93.1 % (k=8) identical to the nowcast label, so a model that simply scores
  the present well already scores most of the k-step target correctly.
- **There is no supported forward-forecast horizon.** The k-step head has a ranking signal at
  every horizon we report (test AUROC 0.844 at k=4, 0.842 at k=8 — better than chance), but at
  the 1 % FPR budget its operating point collapses to F1 ≤ 0.009 and **0/2 episodes at k=1, 4
  and 8 alike**, and the oracle-threshold analysis shows no threshold recovers it — a ranking
  limit, not a calibration bug. Earlier drafts claimed "20 s ahead is our supported horizon"
  against a stale AUROC of 0.890; both are retracted (`tier1_hardening_report.md`). The early
  warning this system does claim comes from the **horizon-0** classifier, not from forecasting
  ahead. One further caveat on the ranking figure itself: the k-step target is **93–96 %
  identical to the nowcast target**, so ranking it well is close to ranking the present well.
- **The dataset has known label errors** (Liu et al. 2022); we deliberately do not chase the
  last fraction of F1.
- **The ledger is tamper-evident, not a distributed blockchain.** Hash chain + Merkle roots +
  anchored checkpoints, verifiable offline by a judge. A live chain push was scoped out
  deliberately (BUILD_PLAN M9) because the demo must run air-gapped.
