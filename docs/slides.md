# Technical presentation — 5 slides (M12 deliverable)

Content for the submission deck. Every number is reproducible via
`python scripts/make_ablation_table.py`; slide 5 is `docs/limitations.md` verbatim-in-spirit.

---

## Slide 1 — The problem, and why it is not classification

**AI-based network attack forecasting (SIH26153, NTRO)**

Most IDS work answers *"is this flow malicious?"* — after the fact. The problem statement asks
something harder: given traffic up to time *t*, **forecast** the infiltration probability and
ATT&CK stage at *t+k*, explain it, and make the record tamper-evident.

- Unit of prediction: **(source host, 15 s window)**, 5 s stride — not per-flow, not whole-network
- Success metric: **lead time** at a fixed false-positive budget
- *A model with better F1 and zero lead time has failed this problem.*
- Hard constraints: fully offline, flow **and** packet features, graded LR baseline on the
  identical matrix, file input, Apache-2.0

---

## Slide 2 — Architecture

```
PCAP/CSV → streaming extractor → 30 window-bounded features → TGN temporal-graph memory
        → causal Transformer (GRAFT) → forecast head (horizon k) → engine → tamper-evident ledger
```

- **Packet + flow features**: TTL variance, TCP window, fragment flags, payload histogram,
  **sequential-vs-random scan signature**, retransmissions — 110k packets/s, bounded memory
- **Causality is enforced, not assumed**: features are strictly window-bounded, graph edges are
  stamped at flow *end*, and the encoder is causal — `test_no_future_leakage` proves perturbing
  the future leaves the past **bit-identical**
- **Identity is anonymised**: keyed-HMAC pseudonyms, per-epoch permutation, role-only node
  features. No raw IP reaches the model or the ledger.

---

## Slide 3 — Results: temporal dynamics generalise, flow signatures do not

Test = a **bot** day; trained on **brute-force + DoS** days. Nothing about the test family was
seen in training. 1 % FPR budget.

| model | AUROC | median lead | episodes |
|---|---|---|---|
| **Fused (TGN + XGBoost, rank-mean)** | **0.933** | 4195 s (~70 min) | **2/2** |
| XGBoost | 0.872 | 4208 s | 2/2 |
| TGN temporal encoder | 0.840 | 38 s | 1/2 |
| GRAFT (shipped config) | 0.701 | 1035 s | 2/2 |
| Logistic regression *(graded baseline)* | 0.573 | 0 s | **0/2** |

**Early warning:** both attack episodes are flagged **~49 and ~91 minutes before completion**
(median ~70 min) at a 1 % false-positive budget — *precursor detection* on live windows, the
PS's own lead-time definition. Forecasting **ahead** is verified as a **ranking** capability
(AUROC ≈ 0.84 at 20 s and 40 s ahead); its fixed-budget operating point does not yet fire, which
we state rather than hide. Every number is under one standardised key **and enforced training
determinism** — repeated runs are bit-identical.

*Caveats carried with this claim, from our own adversarial audit:* n = 2 episodes, both sessions
of one attacker host — the exact 95 % CI for 2/2 is [0.158, 1.000]; **at this alert budget lead
time does not separate from a matched-budget random baseline** (uniform noise scores
4,882–5,110 s, 2/2), so the *lead-time* row is evidence the budget is generous, not that the
model is clairvoyant — **AUROC is where the model earns its place**; detection is carried by the
XGBoost member, not the temporal-graph component; AUROC/F1 are inflated by row multiplicity
(de-duplicated ≈ 0.89 / 0.04) and by benign subsampling. See `tier1_hardening_report.md` →
Limitations & Confidence.

**What is actually new here** (the caveats above are about the *numbers*, not the contribution):

1. **A lead-time-at-fixed-FPR protocol that is honest by construction** — undetected episodes
   count as 0 s and are never dropped, the threshold is fitted on validation and never on test,
   splits are attack-family-disjoint, and the result is published **beside a chance baseline**.
   Most published work on this dataset reports random-split accuracy, which leaks whole attack
   episodes across train and test.
2. **Decorrelated rank fusion as a robustness mechanism** — the members' errors are nearly
   uncorrelated (ρ = 0.05), and the payoff is measurable: when the determinism fix cost the TGN
   encoder 0.037 AUROC, single-model rows swung by up to 0.56 while the **fused headline moved
   0.009**.
3. **A ledger that refuses to lie about its own provenance** — the engine will not write a
   record if the model weights' SHA-256 does not match, so a ledger entry can never claim a
   model it did not run.

> Temporal host *dynamics* transfer across attack families. Static flow signatures do not —
> the linear baseline is at chance on an unseen family.

---

## Slide 4 — Explainability and the audit ledger

**Explainability is mandatory, so we made black-box output impossible.**
Every alert carries top-5 **named** features (`payload_hist_0`, `distinct_dst_ips`, `syn`…),
a MITRE technique (T1046 / T1110 / T1071 / T1498 / T1048), and the flagged flows in that window.
A test fails the build if an explanation returns an index instead of a feature name.

**Tamper-evident ledger** (the Blockchain & Cybersecurity theme, done honestly):
- Append-only **hash chain** + per-batch **Merkle roots**; HMAC pseudonyms, never raw IPs
- Edit one record → the verifier names its **exact index**
- Rewrite the chain self-consistently → caught: the head no longer matches the **signed,
  chained checkpoint** (each checkpoint signs the previous one's signature, and only the last
  may anchor)
- Delete a record, or splice the checkpoint log → caught
- The engine **refuses to write** if the model weights' SHA-256 does not match
- `python -m ledger.verify_cli` — a judge verifies **offline**

**And the attack we could *not* close, because we went looking for it:** truncating the chain
**and** its checkpoint log together, discarding the tail of both, leaves two files that agree
with each other. No scheme confined to those two files can detect it — nothing inside them
records that the run continued. It is closed by publishing the anchor line
(`scripts/anchor_checkpoint.py`) **before** the demo, which is why that step exists. The
limitation is stated in the module docstring, in the verifier's own output, and in
`docs/limitations.md` — not discovered by the judge.

---

## Slide 5 — What this cannot do (read `docs/limitations.md`)

1. **Two kill-chain stages have zero public data.** `lateral_movement` and `exfiltration` have
   no labelled windows in CIC-IDS-2018, so **we report no metric for them** rather than invent
   one. That is precisely what the lab capture is for.
2. **Four attack days ⇒ family-disjoint splits.** This makes our headline an honest
   cross-family test, but multi-class stage metrics are not meaningfully trainable.
3. **CSV cannot carry packet features.** The PS accepts CSV *or* PCAP; a CSV physically lacks
   TTL/window/payload/scan/retransmission data. The engine runs a flow-only model on CSV and
   warns; **feed it a PCAP** for full quality.
4. **The world model we planned failed.** The RSSM rollout collapsed its posterior and detected
   **0/2** episodes — worse than the embeddings it consumed. A tuned retry recovered ranking
   (0.683 → 0.851 AUROC) but still 0/2. We ship the encoder that works and publish the RSSM as a
   **negative result with its recipe**.
5. **An adaptive attacker defeats several of the mandated packet features at zero cost** — and
   we measured the cost rather than guessing it. Jittering the attacker's own TTL and TCP window
   turns a deterministic `ttl_var` of **0.000** into a large one for free; re-chunking a 1400 B
   payload into 3×466 B moves **100 %** of the payload-histogram mass into a different bin while
   delivering the same bytes (the bin edges are a committed config value); pacing an attack 15×
   thins every per-window aggregate, which is enough to re-label a port scan from `recon` to
   `c2`. These features are attacker-*written*, not observed. Full analysis — including which
   features are expensive to fake, which is where the defence actually lives — is in
   [docs/threat_model.md](threat_model.md).

**Where this goes next** (SIH sustainability criterion): GPU seed-averaging to recover a forward
operating point, the M11 lab capture to obtain the two missing kill-chain stages, engine-side
fusion, an IPv6/QUIC feature path, and optional public anchoring of ledger checkpoints —
[docs/roadmap.md](roadmap.md) separates what is shipped from what is planned.

*Also: benign traffic is subsampled, so alerts/day is a within-sample rate; the k-step head has
**no usable operating point at any horizon** (0/2 episodes at k=1/4/8 — ranking signal only),
and its target is 93–96 % identical to the nowcast target; the ledger is tamper-evident, not a
distributed blockchain — deliberately, so the demo runs air-gapped.*
