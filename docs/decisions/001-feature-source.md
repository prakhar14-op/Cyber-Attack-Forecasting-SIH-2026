# 001 — Feature source for CIC-IDS-2018 days (M1.4) — **APPROVED**

**Status: proposed 2026-09-05; approved 2026-09-05 (option (c), 4-day set) via the reviewed
execution plan.** Consequence recorded at approval: task 1.6 (train-only scaler) resequences to
the end of M2, because under (c) the flow features it normalises come from our own PCAP
extractor rather than from the published CSVs. `m1-flow-features` therefore tags after the
scaler lands, immediately before `m2-packet-features`.

## Problem

The model keys everything on `(source_host, window)`, so every training day needs `Src IP`.
Verified by header probes today: only `Thuesday-20-02-2018` (3.8 GiB) carries
`Flow ID, Src IP, Src Port, Dst IP` — every other processed CSV starts at `Dst Port`.
Packet-level features (a hard PS requirement) additionally need PCAP for whichever days we use.

## Measured constraints (this laptop, today)

| Fact | Value |
|---|---|
| Free disk on C: | **53 GB** |
| S3 throughput (measured, 30 MB range pull) | **~4.2 MB/s** |
| Processed CSVs, other days | 100–365 MiB each |
| Raw `pcap.zip` per day | **36–55 GiB** (×10 days); `20-02` is `pcap.rar` 41.3 GiB |
| Structure of `pcap.zip` (probed 14-02 via remote central directory) | **449 members, one per capture host** (`pcap/capDESKTOP-…-172.31.64.x`), avg ~89 MB, individually deflated → members are range-fetchable without downloading the archive |

## Options

**(a) Recompute all features from PCAP for all chosen days, one tool.**
Honest cost for 5 days: ~200 GiB download (~13 h at 4.2 MB/s) and ~85 GiB peak disk per day
(zip + extracted). **Dead on arrival: exceeds the 53 GB free disk on any single day.**
Feature parity: perfect (one extractor).

**(b) Restrict to days that ship IPs.**
That is exactly one day (20-02). Day-wise disjoint train/val/test is impossible with one day,
so this violates the anti-leakage split rule on its own; stage coverage would be benign+DDoS
only. **Invalid alone.**

**(c) Selective per-host PCAP fetch, one extractor, 4 days — recommended.**
The zip members are per-host, so for each chosen day we range-fetch only the attacker/victim
hosts named in the UNB timeline plus ~30 sampled benign hosts (~3–4 GiB per day, ~15 min each),
and run our own single extractor (M2) to produce **both** flow and packet features for every
day — identical code path, full parity, real IPs.

Proposed days (stage coverage; `lateral_movement`/`exfiltration` come from the M11 lab capture
regardless): `14-02` FTP/SSH bruteforce (recon, initial_access) · `16-02` DoS-Hulk/SlowHTTPTest
(impact) · `28-02` Infiltration (c2/initial_access per stage-mapping doc) · `02-03` Bot (c2).
4 days → 2/1/1 day-wise splits. Estimated totals: **~14 GiB download (~1 h), <20 GB peak disk,
extraction a few hours CPU (measured properly in M2)**.
`20-02` stays what it already is — the committed loader fixture — and is excluded from model
days (its `.rar` blocks the selective path, and mixing its CICFlowMeter CSV features with our
recomputed features would let the model key on extractor artefacts that correlate with splits).

## Costs of (c) to state honestly

- Benign background is **subsampled** (~30 of ~450 hosts/day); alerts/day extrapolations must
  say so, and the benchmark protocol must record the sampling seed and host list.
- Our flow features are CICFlowMeter-*like*, not byte-identical to the published CSVs; the LR
  baseline runs on our matrix (which is what the PS grades — same matrix for all models).
- Slight engineering cost: a ranged-zip reader (~100 lines, central-directory parse already
  prototyped today).

## Recommendation

**(c).** (a) cannot run on this hardware; (b) is methodologically invalid alone.

**Sign-off required before implementing 1.5–1.7 (splits.yaml day list, scaler, anonymisation).**
