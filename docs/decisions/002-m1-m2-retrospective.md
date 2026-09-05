# 002 — M1 + M2 retrospective (2026-09-05)

**What we built.** M1 (flow features, splits, anonymisation, scaler) and M2 (one streaming
extractor producing flow **and** packet features) under the decision-001 strategy: selectively
range-fetch only the attack-relevant per-host pcap members from the CIC-IDS-2018 day archives,
then recompute every feature with our own extractor for feature parity across splits.

**Measured numbers (this laptop).**
- **Fetch:** 4 days, 136 members, **12.71 GiB** compressed — vs ~160+ GiB to pull the four full
  `pcap.zip` archives. ~4.2 MB/s sustained S3; 8 MB ranges paid a TLS handshake each (~1.5 MB/s),
  48 MB ranges recovered the full line rate.
- **Extract:** 71–110k packets/s after the columnar rewrite. Peak RSS **4.4 GB on the 4.3 GB
  pcapng DoS-victim member** (18.9M packets) — the single largest capture; every other member
  stayed near 2 GB. Post-fix re-extraction totals: 14-02 638,498 · 16-02 455,964 · 28-02 629,319 ·
  02-03 637,550 = **2,361,331 flows** and **5,259,975 host-windows** across 136 members / ~52.8M
  packets. The three fragment-free days reproduced byte-for-byte after the fragment fix; only
  16-02 (the DoS day, where the fragments live) changed — exactly as expected.
- **Splits:** day-wise 2/1/1 (14-02+16-02 train / 28-02 val / 02-03 test), applying attack-family
  generalisation pressure (bruteforce+DoS → infiltration → bot).

**What surprised us.**
1. **pcap timestamps are UTC; the UNB timeline is local ADT (UTC−4).** Measured end-to-end on
   every day: FTP bruteforce at 14:33–16:10 UTC ≡ published 10:33–12:09 ADT, etc. `timeline_labels`
   (M3) must add +4h before intersecting — otherwise every stage label lands on empty windows.
   Recorded in `data/attack_timeline.yaml`.
2. **Attack signal is wildly uneven.** DoS victim: 105k flows in one attack window. Infiltration
   victim: **11 attacker flows** total (a reverse shell is near-silent — the model's signal that
   day is the victim's own internal scanning, an M3 labelling nuance). Bot: C2 on all 10 victims.
3. **Real container/format sloppiness in the dataset**: 2 of 32 members on 16-02 are pcapng (not
   pcap); the victim capture is split into `-part1`/`-part2`; one 28-02 member name contains a
   stray space; the processed CSV filename is misspelled `Thuesday`. All handled without special
   cases beyond a raw-reader branch.
4. **SlowHTTPTest's modal destination port is 21**, and Hulk's flows arrive in a tight burst —
   noted as data quirks, irrelevant to window labelling (which keys on transmit time).

**Flood hardening (M2.1).** The honest 853 MB benchmark, then the 4.3 GB member, forced a rewrite:
typed-array streaming parse with uint32 IPs, bin-composed window features (no ×3 row explosion),
and endpoint-pair-partitioned flow assembly — each pinned equal to a direct reference
implementation by a test. Without it the DoS day would have OOM'd.

**Adversarial pre-tag audit.** A 112-agent workflow (4 dimension auditors × 3 refuters/finding)
raised 36 candidates; **7 survived majority refutation and were all fixed before tagging**
(commit `781900a`): a critical `base`-shadowing fetch bug (a fresh multi-day fetch crashed after
day 1 — the live fetch had survived only on pre-edit code), a major fragment-parsing bug
(non-first IP fragments decoded as L4 → phantom ports/flows; 3,648 fragments in the data, so we
**re-extracted all four days** on the fix before fitting the scaler), a dead `retransmission_backend`
config key (now wired), and four minor doc/test/shell fixes. The 29 rejected findings are recorded
below as known limitations / deferred work, not silently dropped.

**Known limitations carried forward (audit-rejected but real; revisit at M3+ / M11).**
- `sequential_port_ratio` counts only ascending +1 steps — a descending sequential scan scores 0
  (nmap default randomises; `-r` ascends, so low practical risk).
- Benign background is subsampled (~30 hosts/day) — alerts/day extrapolations must disclose this
  (already flagged for `docs/benchmark_protocol.md`, M4).
- `_RetransTracker` keeps one bounded cache per distinct flow; total memory grows with flow count
  on scan/flood captures (contributed to the 4.4 GB peak). Acceptable at current scale; revisit if
  a bigger capture is added.
- A handful of module-level tuning knobs (`_NUMERIC_ADOPTION_RATIO`, `_FLOW_PARTITION_ROWS`, zip
  chunk/timeout) remain in code rather than config — low-churn, move to config if they need tuning.
- M2.5 ("capture/ fixture passes") is genuinely unmet until the M11 lab capture exists; the
  extractor is unit-tested via scapy-written pcaps in the meantime.

**Deferred honestly:** 1.6 scaler ran at the end of M2 (its flow features come from our extractor,
not the CSVs — decision 001), so `m1-flow-features` tags after the scaler lands.
