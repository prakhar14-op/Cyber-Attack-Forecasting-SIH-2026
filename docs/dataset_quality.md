# Dataset quality and label risk

Three files in this repository carry the same uncited half-sentence — *"the dataset has known
label errors (Liu et al. 2022)"* (`CLAUDE.md`, `docs/benchmark_protocol.md`,
`docs/limitations.md`) — with no bibliography and no statement of whether those errors reach our
pipeline. This document replaces it. §4 is the part that matters most, because it is the label
risk this project carries that the literature does not cover.

## 1. What the literature documents

CSE-CIC-IDS-2018 and its sibling CIC-IDS-2017 have been audited repeatedly. The recurring
findings fall into three families:

- **CICFlowMeter implementation defects.** The tool that produced the published feature CSVs has
  documented bugs — incorrect TCP flow termination (flows not closed on FIN, so a "flow" spans
  what should be several), mis-computed or duplicated statistics, and direction/ordering errors.
- **Labelling errors.** Attacks labelled benign and benign traffic labelled attack, arising from
  the label being applied by IP-and-time rules over flows whose boundaries were themselves wrong.
- **Traffic-generation artifacts.** The benign background is synthetic and profile-generated, so
  a classifier can key on generator artefacts rather than on behaviour and still score well.

### Bibliography — with an explicit confidence statement

**Verify these against the papers before any of them is printed on a slide.** I am confident
about the existence and the substance of each entry; I am **not** certain of every venue, year
and author-list detail, and inventing a precise citation would be worse than saying so.

| Source | What it documents | My confidence |
|---|---|---|
| Liu, Engelen, Lynar, Essam, Joosen — *Error Prevalence in NIDS Datasets: A Case Study on CIC-IDS-2017 and CSE-CIC-IDS-2018*, IEEE CNS, 2022 | The citation already used throughout this repo: prevalence of labelling and generation errors across **both** datasets | High on substance and authors; **verify venue/year** |
| Engelen, Rimmer, Joosen — *Troubleshooting an Intrusion Detection Dataset: the CICIDS2017 Case Study*, IEEE Security & Privacy Workshops, 2021 | The original systematic teardown of CICFlowMeter behaviour and CICIDS2017 labels | High on substance; **verify venue/year** |
| Rosay et al. — analyses of CICFlowMeter correctness / a corrected reimplementation | Feature-computation errors in the published CSVs | Medium — **verify authors, title and venue** |
| Lanvin et al. — errors in CICIDS2017 and a corrected release | Re-labelled/corrected dataset and the effect on reported performance | Medium — **verify authors, title and venue** |

Most of this work targets CIC-IDS-**2017** directly; it is cited here because the same laboratory,
the same generator and the same CICFlowMeter produced CIC-IDS-**2018**, which is the basis for
treating the defect classes as shared. Liu et al. is the entry that addresses 2018 specifically.

## 2. Which of these reach *this* repository

The answer turns on `docs/decisions/001-feature-source.md`: we do **not** use the published
CICFlowMeter CSVs for any model day. Option (c) was approved — selectively range-fetch the
per-host pcap members and recompute **both** flow and packet features with our own extractor
(`data/packet_features.py`), for feature parity across splits.

| Documented defect | Exposed? | Why |
|---|---|---|
| CICFlowMeter feature-computation bugs (flow termination, direction, duplicated stats) | **No** | Our flows are assembled from packets by `assemble_flows` in `data/packet_features.py` with our own idle-timeout rule (`flows.timeout_seconds: 120`, `configs/data.yaml`). None of the published feature columns are consumed for model days |
| Published CSV **label** errors | **No** | Stage labels come from `data/timeline_labels.py` over `data/attack_timeline.yaml`. Flows assembled from pcap are written with `label: "unlabeled"`; the dataset's `Label` column is never a training target. It is read only by the CSV loader (`data/flow_features.py`), which serves the committed fixture and the CSV input path |
| Synthetic / profile-generated benign background | **Yes, fully** | Nothing about recomputing features changes what the packets are. Our benign class is the same generated traffic, additionally **subsampled** to ~30 of ~450 hosts/day (seed 1337, decision 001) |
| Attack traffic realism (unmodified public tooling, no adaptive adversary) | **Yes, fully** | See `docs/threat_model.md` |

So the honest summary is: **we inherit the dataset's traffic, not its feature engineering or its
labels.** That removes two of the three defect families and leaves the one nobody can remove by
re-extracting.

Our extractor has its own defects instead, and the repo has already found some of them —
`docs/decisions/002` records a fragment-parsing bug (non-first IP fragments decoded as L4,
fabricating ports and flows; 3,648 affected fragments, all four days re-extracted on the fix) and
an ongoing limitation that `sequential_port_ratio` counts only ascending steps. "Our own
extractor" is a different risk profile, not a smaller one. The production bin-composed path *is*
pinned by test to a direct reference implementation for both feature sets
(`tests/test_packet_features.py::test_bin_composed_features_equal_reference_implementation`,
`::test_sent_window_features_equal_reference`) — but that pins the **optimisation**, not the
**definition**: both implementations can share the same wrong semantics, which is exactly what
the fragment bug was.

## 3. What we do about it

Per CLAUDE.md we **do not chase the last 0.5 % of F1** — below that margin we would be fitting
label noise. The protocol is also structurally hostile to artefact-fitting: splits are day-wise
and attack-family-disjoint, so a generator artefact learned from one family does not carry to an
unseen one — one reading of why the logistic-regression baseline collapses to 0.573 AUROC
cross-family.

## 4. The label risk this project actually carries

The literature is about *their* labels. Ours are different, and the risk is larger and less
discussed. **Every label in every reported number derives from three things:**

**4.1 A hand-authored timeline.** `data/attack_timeline.yaml` is a ~90-line file transcribed by
hand from UNB's published Table 2 (header comment: "verified 2026-09-05"). It is the single
source of truth for every attack's start time, end time, attacker addresses and victim addresses.
It is not generated, not cross-checked against the traffic, and — see `docs/threat_model.md` §4 —
**not covered by any digest**: `scripts/verify_weights.py` hashes model outputs only. A
transcription error in one `HH:MM` field silently relabels a corpus.

**4.2 A victim-inclusive host rule.** `attack_intervals()` builds each attack's host set as
`attacker_ips ∪ victim_ips`, and `label_windows()` labels any window where **either party
transmits** inside the interval. On the 02-03 Bot test day that means **1 attacker host and 10
victim hosts** are all labelled `c2` while transmitting during the session — so most labelled
attack windows are victim-side, and a victim's window is labelled attack whether it carries C2
traffic or the machine's ordinary background chatter. This is defensible (a bot-infected host *is*
compromised) but it is a modelling choice, not ground truth, and it has a measured consequence:
`diagnosis_report.md` §2 row 5b found GRAFT recalling 37 % of attack windows while firing on
essentially none of the **attacker's** windows — its alerts sat on the victims. Window-F1 and
episode lead time were measuring different populations.

**4.3 One `+4h` offset constant.** `utc_offset_hours: 4` converts the timeline's local Atlantic
wall-clock times to the captures' UTC. It is a single scalar applied to **every** interval on
**every** day. It was measured rather than assumed — `docs/decisions/002` records the FTP
brute-force appearing at 14:33–16:10 UTC against a published 10:32–12:09 local, a <2 min agreement
— and it is documented, but only in a YAML comment. If it were wrong, every stage label would land
on empty or benign windows and the failure would not be loud. `tests/test_timeline_labels.py`
asserts the offset is **applied**, against a synthetic timeline; nothing asserts the configured
value is **correct**, or that the real intervals intersect traffic from their declared hosts.

**4.4 Consequences to state with any number.**

- Attack windows are **0.88 %** of host-windows (46,338 / 5,259,975, `docs/stage_mapping.md`), so
  label noise is concentrated where precision is measured.
- `recon`, `lateral_movement` and `exfiltration` have **zero** labelled windows — not sparse,
  zero. No per-class metric is reported for them, and none should be.
- The test split contains exactly **two** episodes, both sessions of one attacker host. Whatever
  the timeline says about those two intervals is, effectively, the entire test ground truth.
- Boundary windows are labelled by interval **overlap**, so a 15 s window straddling an attack's
  annotated start or end is labelled attack in full. The ep1 "+10 s" alert was specifically
  audited for this and is clean — the firing window spans [+10 s, +25 s], entirely post-onset,
  with zero alerts in the 60 s before onset (`tier1_hardening_report.md`) — but that audit
  covered one alert, not the corpus.

**What would reduce this risk**, in order of cost: digest the timeline, `data/splits.yaml` and an
interim-parquet manifest into the same integrity record as the weights (`docs/roadmap.md` §1.9);
add a test asserting that each declared attack interval intersects non-trivial traffic from its
declared hosts, which would catch both a transcription error and a wrong offset loudly; and
record the M11 lab capture, where the operator log *is* the ground truth and the labels are
generated by the same code path (`capture/label_capture.py`) from times someone actually observed.
