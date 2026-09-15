# Network Attack Forecasting from Network Traffic Data

**SIH 2026 · Problem SIH26153 (NTRO) · Blockchain & Cybersecurity**
One page, written to be read on its own. Everything on it is checkable from this repository.

## What it does

Takes a **PCAP or a CICFlowMeter CSV**, offline. Cuts traffic into **(source host, 15 s window)** on a
5 s stride and builds a **30-feature, strictly window-bounded** matrix — every value summarises only
packets timestamped inside its own window. Per host-window it emits an **infiltration probability**,
an **ATT&CK stage and technique**, the **five named features** that drove the score (`payload_hist_0`,
`distinct_dst_ips`, … — never an embedding index), the **three earlier windows** that contributed
most, and the flows involved. Every forecast is appended to a **hash-chained, Merkle-committed
ledger** an evaluator can verify with no network. No cloud call, no runtime download, no telemetry.

## The one claim we will defend

**A temporal host-window model transfers to an attack family it has never seen; a flow-signature
model does not.** Splits are day-wise, and with four attack days that makes them
**attack-family-disjoint**: trained on brute-force and DoS days, evaluated on a *bot* day the model
never saw. The claim rests on the deployed engine's row against the graded **logistic-regression**
baseline fitted on the **identical feature matrix**, in [`architecture.md` §4](architecture.md).
**Ranking quality (AUROC) is where this system earns its place — not lead time.**

This page does **not** copy that table: it is the authority, it is being regenerated under a new
anonymisation key as this is written, and a copied number goes stale in silence. If regeneration
closes that gap, this claim is the first thing that goes.

## Architecture, in three lines

1. **One extractor.** A streaming parser turns pcap bytes (or flow rows) into the 30-feature window
   matrix, with an HMAC pseudonym per host. No raw IP reaches the model or the ledger.
2. **Deployed lane.** That matrix → a **single XGBoost model** (**not a cascade**: two variants
   chosen by input format — 30 features for PCAP, flow-only for CSV) → a threshold **fitted from a
   1 % false-positive budget on validation**, never a literal → TreeSHAP named-feature explanation →
   ledger.
3. **Evaluation-only lane.** TGN memory over the host graph, a causal Transformer, horizon-shifted
   k-step heads, a rank-mean fusion. **None of it runs in the engine.** The fused row that headlines
   §4 is eval-side; engine-side fusion is roadmap.

## The headline result, and the population behind it

The problem statement's graded metric is **lead time** — seconds from the first alert on the
attacking host to annotated attack completion, at a fixed false-positive budget. Every figure
(AUROC, F1, median lead, episodes, per model) is in [`architecture.md` §4](architecture.md), the only
place they are published. Read them against this population, which regeneration does not change:

- **n = 2 attack episodes**, both sessions of the **same attacker host**. Exact 95 % CI for 2 of 2:
  **[0.158, 1.000]** (Clopper–Pearson, recomputed 2026-09-12). A median over two points is not a
  distribution.
- **Benign traffic is subsampled** to ~30 of ~450 hosts/day ([`limitations.md`](limitations.md) →
  "Also worth knowing"), inflating precision and F1 against a real network.
- **A judge's own demo run corresponds to the XGBoost row** — that is the model `engine/predict.py`
  loads.
- **The lead time is *precursor detection* by the horizon-0 classifier**: alerts fire on
  early-episode windows as they occur. It is not forward forecasting.

## What it cannot do

- **There is no supported forward-forecast horizon.** The k-step heads rank better than chance, but
  at the shipped 1 % budget they fire **0 of 2 episodes at every k reported**, and the
  oracle-threshold analysis shows no threshold recovers it.
- **At this alert budget, lead time does not separate from chance.** Our own audit measured a
  matched-budget random baseline scoring as well or better. The figure is still reported — it is the
  graded metric — but never without this sentence.
- **Three of the seven kill-chain stages have no data at all.** `recon`, `lateral_movement` and
  `exfiltration` have **zero labelled windows**, so no metric is reported for them. This is **not a
  validated 7-class classifier**.
- **A CSV cannot carry packet-level features** (TTL, TCP window, fragment flags, payload histogram,
  scan signature, retransmissions). Feed it a PCAP. The parser is also IPv4-only; other ethertypes
  are counted and reported, never featurised.
- **It is not a blockchain.** It is a tamper-evident hash chain with signed, anchored checkpoints,
  chosen so the demo runs air-gapped. Truncating the chain *and* its checkpoint log together is the
  one attack those two files cannot detect — which is why the anchor is published outside them.
- **On a fresh clone you are watching a demo model**, fitted on the bundled synthetic capture and
  scoring its own training data — the app says so on screen, on every forecast object and in every
  ledger record. Trained weights are not committed and the Release is unpublished, so **no number a
  fresh clone prints reproduces anything here.**

## Verify it; do not believe it

**[JUDGES.md](../JUDGES.md)** — ten minutes, no trust required: what runs on a bare clone, the ledger
attacked four ways with the expected output of each, what reproducing a published number would take,
and **Part 3, what we cannot currently let you verify. Read Part 3 first.** Supporting detail:
[`limitations.md`](limitations.md) · [`threat_model.md`](threat_model.md) (measured evasion costs) ·
[`dataset_quality.md`](dataset_quality.md) · [`../tier1_hardening_report.md`](../tier1_hardening_report.md)
— our own adversarial audit, including the defects it found in claims we had already published.
