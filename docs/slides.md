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
- Rewrite the entire chain self-consistently → still caught, because the head no longer matches
  the **anchored checkpoint**
- The engine **refuses to write** if the model weights' SHA-256 does not match
- `python -m ledger.verify_cli` — a judge verifies **offline**

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

*Also: benign traffic is subsampled, so alerts/day is a within-sample rate; k=8 degrades at the
operating point (20 s is our supported horizon); the ledger is tamper-evident, not a distributed
blockchain — deliberately, so the demo runs air-gapped.*
