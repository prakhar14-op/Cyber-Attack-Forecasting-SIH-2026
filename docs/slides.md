# Technical presentation — 5 slides (M12 deliverable)

Content for the submission deck. Every number is reproducible via
`python scripts/make_ablation_table.py`; slide 5's numbered list is bound by content to
`docs/limitations.md`'s numbered sections, and the build fails if the two lists diverge.

`scripts/build_deck.py` renders this file to `docs/deck/` as the .pptx the PS asks for.
The `<!-- deck:… -->` comments are build markers, invisible in rendered markdown. A marked
block goes **on the slide**; everything unmarked becomes that slide's **speaker notes**. That
split is the only reason the deck can be readable from the back of a room without losing a
sentence of what follows — the prose is still here, and it still reaches the presenter. Marker
grammar is documented in `scripts/build_deck.py`; the builder refuses to produce a deck that
exceeds five slides, overflows a slide, or drops one of the disclosures below.

Two things the builder enforces that are easy to undo by accident:

- **Each required disclosure is pinned to the slide that carries the claim it qualifies**, not
  to the deck. The k-step correction is on slide 1 because slide 1 is where the *t+k* claim is
  made; the lead-time attribution is on slide 3 because slide 3 is where the number is printed.
  Moving one two slides away is the same as deleting it, and the build now says so.
- **Slide 5's numbered five are `docs/limitations.md`'s numbered five, section for section, in
  its order**, bound by content and not by count. The slide's own title sends a judge to that
  document, so the two lists have to be the same list. The adaptive-attacker limitation is a
  real one and stays on the slide — in the band and in the notes — but it is not numbered here,
  because `docs/limitations.md` does not number it. Numbering it on the slide alone is how the
  two lists diverged in the first place.

---

## Slide 1 — The problem, and why it is not classification

<!-- deck:kicker -->
SIH26153 · NTRO · theme: Blockchain & Cybersecurity

<!-- deck:headline -->
The problem statement asks: given traffic up to *t*, **forecast** infiltration at *t+k* — not
"was this flow malicious?"

<!-- deck:points -->
- Unit of prediction: **(source host, 15 s window)**, 5 s stride — not per-flow, not whole-network
- Success metric: **lead time** at a fixed false-positive budget
- Hard constraints: fully offline, flow **and** packet features, graded LR baseline on the
  identical matrix, file input, Apache-2.0

<!-- deck:band the standard, and where we stand -->
A model with better F1 and zero lead time has failed this problem. Ours: at the 1 % budget the
k-step head **fires on 0 of 2 episodes at k = 1, 4 and 8** — forward is **ranking only** (test
AUROC 0.844 at k=4, 0.842 at k=8). The lead time on slide 3 is the **horizon-0** classifier.

**AI-based network attack forecasting (SIH26153, NTRO)**

Most IDS work answers *"is this flow malicious?"* — after the fact. The problem statement asks
something harder: given traffic up to time *t*, **forecast** the infiltration probability and
ATT&CK stage at *t+k*, explain it, and make the record tamper-evident.

**Say the band out loud; it is the frame for everything after it.** That is the PS's ask in the
headline, not a capability claim, and the band is what we actually measured against it. The
k-step head has **no supported forward operating point**: at the shipped 1 % FPR budget it fires
on 0 of 2 episodes at k = 1, 4 *and* 8, and the oracle-threshold analysis says that is a ranking
limit, not a threshold we forgot to retune. What it does have is a real but modest ranking
signal — test AUROC 0.844 at k=4 and 0.842 at k=8 — carrying one further caveat a judge should
hear: the k-step *target* is 93–96 % identical to the nowcast target, so ranking it well is close
to ranking the present well. Every lead-time number in this deck comes from the **horizon-0**
classifier. Sources: `docs/limitations.md` §4 and "Also worth knowing",
`tier1_hardening_report.md`.

The graded LR baseline is trained and scored on the **identical feature matrix**, which is what
makes the comparison on slide 3 fair rather than flattering; everything is Apache-2.0.

---

## Slide 2 — Architecture

<!-- deck:headline -->
Causality is enforced, not assumed — and no raw identity reaches the model.

<!-- deck:pipeline -->
```
PCAP/CSV → streaming extractor → 30 window-bounded features → TGN temporal-graph memory
        → causal Transformer (GRAFT) → forecast head (horizon k): **ranking only**
        → engine → tamper-evident ledger
```

<!-- deck:points -->
- **Packet + flow features** — TTL variance, TCP window, fragment flags, payload histogram, scan
  signature, retransmissions — 110k packets/s in bounded memory
- **Causal by construction** — `test_no_future_leakage` proves perturbing the future leaves the
  past **bit-identical**
- **Anonymised identity** — keyed-HMAC pseudonyms, per-epoch permutation, role-only node features

- **Packet + flow features**: TTL variance, TCP window, fragment flags, payload histogram,
  **sequential-vs-random scan signature**, retransmissions — 110k packets/s, bounded memory
- **Causality is enforced, not assumed**: features are strictly window-bounded, graph edges are
  stamped at flow *end*, and the encoder is causal — `test_no_future_leakage` proves perturbing
  the future leaves the past **bit-identical**
- **Identity is anonymised**: keyed-HMAC pseudonyms, per-epoch permutation, role-only node
  features. No raw IP reaches the model or the ledger.

---

## Slide 3 — Results: dynamics generalise, flow signatures do not

<!-- deck:kicker -->
Trained on brute-force + DoS days · tested on an unseen **bot** day · 1 % FPR budget

<!-- deck:table -->
| model | AUROC | median lead (horizon-0) | episodes |
|---|---|---|---|
| **Fused (TGN + XGBoost, rank-mean)** | **0.933** | 4195 s (~70 min) | **2/2** |
| XGBoost | 0.872 | 4208 s | 2/2 |
| TGN temporal encoder | 0.840 | 38 s | 1/2 |
| GRAFT (shipped config) | 0.701 | 1035 s | 2/2 |
| Logistic regression *(graded baseline)* | 0.573 | 0 s | **0/2** |

<!-- deck:chips What is actually new here -->
- **Honest-by-construction** protocol
- **Decorrelated** rank fusion
- Ledger that **refuses to lie**

<!-- deck:band carried with the claim — the lead column is horizon-0, not a t+k forecast -->
n = 2 episodes, one attacker host (exact 95 % CI for 2/2: [0.158, 1.000]). **At this alert
budget lead time does not separate from a matched-budget random baseline** — **AUROC is where
the model earns its place**.

Test = a **bot** day; trained on **brute-force + DoS** days. Nothing about the test family was
seen in training. 1 % FPR budget.

**Early warning:** both attack episodes are flagged **~49 and ~91 minutes before completion**
(median ~70 min) at a 1 % false-positive budget — *precursor detection* on live windows, the
PS's own lead-time definition. That whole column is the **horizon-0** classifier; the band above
the table and the column header both say so, because it is the one number in this deck a judge
is most likely to read as evidence of forecasting ahead. Forecasting **ahead** is a **ranking**
result only (test AUROC 0.844 at k=4, 0.842 at k=8) with **no operating point that fires** at
the 1 % budget — 0 of 2 episodes at k = 1, 4 and 8, and the oracle check says that is a ranking
limit rather than a threshold waiting to be retuned. Every number is under one standardised key
**and enforced training determinism** — repeated runs are bit-identical.

*Caveats carried with this claim, from our own adversarial audit:* n = 2 episodes, both sessions
of one attacker host — the exact 95 % CI for 2/2 is [0.158, 1.000]; **at this alert budget lead
time does not separate from a matched-budget random baseline** (uniform noise scores
4,882–5,110 s, 2/2), so the *lead-time* row is evidence the budget is generous, not that the
model is clairvoyant — **AUROC is where the model earns its place**; detection is carried by the
XGBoost member, not the temporal-graph component; AUROC/F1 are inflated by row multiplicity
(de-duplicated ≈ 0.89 / 0.04) and by benign subsampling. See `tier1_hardening_report.md` →
Limitations & Confidence.

*And which row the live demo actually is:* the fused row is an **evaluation-side** result.
`engine/predict.py` loads one booster and calls `predict_proba` once — the deployed engine is a
**single XGBoost model**, so the demo a judge runs corresponds to the **XGBoost row**, not the
fused one. Engine-side fusion is on the roadmap (slide 5's band), not in the shipped binary. If
a judge asks whether the demo is the 0.933 system, the answer is no, and this is where you say so.

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

<!-- deck:headline -->
Explainability is mandatory, so we made black-box output impossible.

<!-- deck:points -->
- Top-5 **named** features per alert (`payload_hist_0`, `distinct_dst_ips`…), a MITRE technique,
  the flagged flows — the build fails if an explanation returns an index
- **Tamper-evident ledger**: append-only hash chain + per-batch Merkle roots; HMAC pseudonyms,
  never raw IPs
- Edit a record → the verifier names its **exact index**. Rewrite the chain → the **signed,
  chained checkpoint** catches it. Wrong weight hash → the engine **refuses to write**.
- `python -m ledger.verify_cli` — a judge verifies **offline**

<!-- deck:band the attack we could not close -->
Truncating the chain **and** its checkpoint log together leaves two files that agree with each
other. No scheme confined to those two files can detect it — closed by publishing the anchor
line **before** the demo, and stated in `docs/limitations.md`.

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

<!-- deck:points -->
1. **Three kill-chain stages have zero public data** — `recon`, `lateral_movement`,
   `exfiltration`: no labelled windows, **no metric reported**.
2. **Four attack days ⇒ family-disjoint splits** — an honest cross-family test; stage metrics
   are not meaningfully trainable.
3. **CSV cannot carry packet features** — the engine runs a flow-only model and warns.
   **Feed it a PCAP.**
4. **The world model we planned failed** — the RSSM detected **0/2** episodes; we publish it as
   a negative result with its recipe.
5. **The packet parser is IPv4-only** — IPv6 and other ethertypes are counted and reported,
   never featurised: an IPv6-only capture yields **zero alerts**.

<!-- deck:band where this goes next -->
GPU seed-averaging for a forward operating point, the M11 lab capture for the three missing
stages, engine-side fusion, IPv6/QUIC — `docs/roadmap.md`. Not on it: an adaptive attacker
defeats several **mandated packet features at zero cost** (`docs/threat_model.md`).

1. **Three kill-chain stages have zero public data.** `recon`, `lateral_movement` and
   `exfiltration` have no labelled windows in CIC-IDS-2018, so **we report no metric for them**
   rather than invent one. That is precisely what the lab capture is for.
2. **Four attack days ⇒ family-disjoint splits.** This makes our headline an honest
   cross-family test, but multi-class stage metrics are not meaningfully trainable.
3. **CSV cannot carry packet features.** The PS accepts CSV *or* PCAP; a CSV physically lacks
   TTL/window/payload/scan/retransmission data. The engine runs a flow-only model on CSV and
   warns; **feed it a PCAP** for full quality.
4. **The world model we planned failed.** The RSSM rollout collapsed its posterior and detected
   **0/2** episodes — worse than the embeddings it consumed. A tuned retry recovered ranking
   (0.683 → 0.851 AUROC) but still 0/2. We ship the encoder that works and publish the RSSM as a
   **negative result with its recipe**.
5. **The packet parser is IPv4-only.** `data/packet_features.py` reads a frame only when its
   ethertype is `0x0800`; a VLAN tag is unwrapped and the inner ethertype used, and everything
   else — IPv6 (`0x86DD`), frames too short to hold an IPv4 header, truncated IP headers — is
   skipped before it can become a row, so **IPv6 is absent from all 30 features**. QUIC is not
   skipped but is seen as opaque UDP. What the system refuses to do is be silent about it, because
   "0 alerts" must never be indistinguishable from "nothing happened": every skipped frame is
   counted against a named reason (`DROP_REASONS` in `data/packet_features.py`),
   `engine/predict.py` turns those counters into an `unparsed_frames` block that reaches the
   `predict_file` return value, `run_summary.json` and the Streamlit page, and
   `tests/test_packet_features.py::test_ipv6_scan_is_counted_not_silently_dropped` pins it —
   a 200-frame IPv6 scan must yield 0 rows **and** `drops["ipv6"] == 200`. Counted is not parsed:
   an IPv6-only capture still produces no features, no forecasts and no ledger records. Closing
   the gap means a parse path, not a better counter — `docs/limitations.md` §5,
   `docs/roadmap.md` §1.10.

**These five are `docs/limitations.md`'s five, in its order** — the slide's title sends a judge
to that document, so the slide must not be a different list. The next paragraph is a limitation
that document does not number; it is on the slide, in the band, but not inside the numbered five.

**And one the numbered list does not carry: an adaptive attacker defeats several of the mandated
packet features at zero cost** — and we measured the cost rather than guessing it. Jittering the
attacker's own TTL and TCP window turns a deterministic `ttl_var` of **0.000** into a large one
for free; re-chunking a 1400 B payload into 3×466 B moves **100 %** of the payload-histogram mass
into a different bin while delivering the same bytes (the bin edges are a committed config value);
pacing an attack 15× thins every per-window aggregate, which is enough to re-label a port scan
from `recon` to `c2`. These features are attacker-*written*, not observed. Full analysis —
including which features are expensive to fake, which is where the defence actually lives — is in
[docs/threat_model.md](threat_model.md).

**Where this goes next** (SIH sustainability criterion): GPU seed-averaging to recover a forward
operating point, the M11 lab capture to obtain the two missing kill-chain stages, engine-side
fusion, an IPv6/QUIC feature path, and optional public anchoring of ledger checkpoints —
[docs/roadmap.md](roadmap.md) separates what is shipped from what is planned.

*Also: benign traffic is subsampled, so alerts/day is a within-sample rate; the k-step head has
**no usable operating point at any horizon** (0/2 episodes at k=1/4/8 — ranking signal only),
and its target is 93–96 % identical to the nowcast target; the ledger is tamper-evident, not a
distributed blockchain — deliberately, so the demo runs air-gapped.*
