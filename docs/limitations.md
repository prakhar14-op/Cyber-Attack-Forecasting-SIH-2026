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

## 5. The packet parser is IPv4-only: IPv6 and other ethertypes are counted, never featurised

`data/packet_features.py` reads a frame only when its ethertype is `0x0800` (IPv4). A VLAN tag is
handled — `0x8100` is unwrapped and the inner ethertype is used — but everything else is skipped
before it can become a row. **IPv6 (`0x86DD`) is therefore absent from all 30 features.** So are
frames shorter than Ethernet + the smallest IPv4 header, and frames whose IP header is truncated.
QUIC is not skipped but is seen as opaque UDP, with none of the flag or window structure the TCP
features rely on. Full IPv6 feature support **is not implemented** and is not planned inside this
milestone; it is `docs/roadmap.md` §1.10.

What the system does instead is **refuse to be silent about it**, because the alternative failure
mode is the worst one a security tool has: a capture the parser cannot read produces zero
host-windows, therefore zero alerts, and "0 alerts" must never be indistinguishable from "nothing
happened". Every skipped frame is counted against a named reason —
`DROP_REASONS = ("short_frame", "ipv6", "non_ipv4_ethertype", "truncated_ip_header")` — and
`engine/predict.py` turns those counters into an `unparsed_frames` block (total, fraction of
frames seen, per-reason breakdown), and it reaches all three surfaces an operator might look at:
the `predict_file` return value, a `run_summary.json` written beside `forecasts.json` on every run
including a zero-alert one, and the Streamlit page, where `panels.coverage_note` escalates to a
warning once the unparsed fraction crosses `UNPARSED_WARN_FRACTION` and says outright that "0
alerts here means nothing was seen, not that nothing happened" when a capture is skipped entirely.
`tests/test_packet_features.py::test_ipv6_scan_is_counted_not_silently_dropped` pins the counting:
a 200-frame IPv6 scan must yield 0 rows **and** `drops["ipv6"] == 200`.

The qualification that still stands: **counted is not parsed.** An IPv6-only capture produces no
features, no forecasts and no ledger records. The counter tells an operator the run was blind; it
does not make it see. Closing the gap means an IPv6 parse path, not a better counter.

## Also worth knowing

- **Benign traffic is subsampled** (~30 of ~450 hosts/day, seed 1337 — decision 001), so
  `alerts/day` is a within-sample extrapolation, not a full-network projection. The published rate
  is **per host-day**; `docs/deployment.md` §5 now does the network-wide multiplication openly
  (×~450 ≈ 84,000 alerts/day at the 1 % budget) and states the assumption it rests on — that the
  unsampled hosts behave like the sampled ones, which is reasonable and unverified.
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
  last fraction of F1. That half-sentence used to travel uncited — `docs/dataset_quality.md` now
  carries the bibliography behind it, with a per-entry confidence statement, plus which of the
  documented defect families actually reach this pipeline and which are removed by recomputing
  features from pcap. Read that before quoting the citation anywhere.
- **The ledger is tamper-evident, not a distributed blockchain.** Hash chain + Merkle roots +
  anchored checkpoints, verifiable offline by a judge. A live chain push was scoped out
  deliberately (BUILD_PLAN M9) because the demo must run air-gapped.
- **The ledger has one tampering mode it cannot catch, and it is deletion, not forgery.** Editing
  a record fails verification at that record's index. Rewriting the whole chain fails because
  each checkpoint is HMAC-signed under a key derived from `SIH26_LEDGER_KEY`, which lives in the
  operator's environment and never in the run directory. Deleting records while their checkpoints
  survive fails because only the *last* checkpoint may anchor and it names a longer chain; and
  deleting, reordering or splicing in a checkpoint fails because each one carries the previous
  one's signature in `prev_sig`. What is **not** caught is truncating **both files together** —
  dropping trailing records *and* the checkpoint lines that cover them. What is left is a
  shorter ledger that is internally perfect and correctly signed, and `python -m
  ledger.verify_cli` **exits 0 on it**. Nothing inside those two files records that the run
  continued, so no scheme reading only them can tell this from an honest run that stopped
  earlier. This is asserted, not assumed:
  `tests/test_ledger_tamper.py::test_tail_truncation_of_both_files_is_not_caught_without_the_published_anchor`
  performs the truncation and pins the exit code, so if the limit is ever closed the test fails
  and this paragraph gets rewritten.
- **What the external anchor does and does not prove.** The one thing that closes the gap is
  publishing the checkpoint *outside* the run directory before the demo:
  `python scripts/anchor_checkpoint.py <chain>` prints a single
  `SIH26-ANCHOR count=… head=… root=… sig=…` line plus a six-group spoken digest, for a presenter
  to read out and an audience to keep. A ledger later truncated to a shorter length contradicts a
  count the room already holds. It **proves**: that the chain was at least that long at the moment
  the line was published, and — because the operator holds the signing key and could otherwise
  re-sign any rewrite — it is the only thing here that constrains the operator rather than just a
  filesystem attacker. It does **not** prove: anything about records appended *after* the line was
  published (they are outside it), anything at all if nobody published a line or nobody kept it,
  and it is not checked by any code — `verify_cli` prints the anchored count and tells the reader
  to compare it, but nothing in this repository takes an anchor line as input. The comparison is a
  human step: `docs/slides.md` names it and `docs/demo_script.md`'s run sheet now carries it as
  an explicit pre-filming action, but nothing enforces it, so on the day it still depends on the
  presenter actually doing it.
