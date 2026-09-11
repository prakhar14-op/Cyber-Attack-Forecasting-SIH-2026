# Positioning — "why not just run Suricata?"

A fair question, and until now this repository never answered it: a repo-wide grep for Suricata,
Zeek, Snort or any commercial NDR returns **zero hits**. This document answers it without
caricaturing the alternatives, and **without claiming a head-to-head we have not run** (§4).

## 1. What the incumbents actually do — stated fairly

**Suricata / Snort — signature and rule engines.** Mature, fast, multi-threaded, deployable
inline as an IPS, and driven by large maintained rulesets. Against a *known* threat with a
published signature they are more precise than anything in this repository, need no training
data, and give an analyst an immediate, unambiguous reason for the alert. They are the right tool
for known-bad, and a deployment without one is not better for having this system.

**Zeek — a protocol analysis framework.** It is a mistake to file Zeek under "signatures". It
produces rich typed logs (connections, DNS, TLS, files, notices) and a scripting language for
stateful, behavioural detection, and its protocol coverage is far deeper than our 30 features.
In a real deployment **Zeek is a better feed than our extractor**, not a competitor to it.

**Commercial NDR.** Behavioural baselining and ML-driven anomaly scoring, generally with far more
telemetry (endpoint, identity, cloud) and far more engineering than this. Their structural
mismatch with SIH26153 is not capability — it is that they are typically closed-source,
licence-bound and cloud-assisted, and the PS requires fully offline, open-source, Apache-2.0.

## 2. Where the problem statement is not covered by any of them

SIH26153 asks for four things at once, and the gap is the conjunction, not any single item:

| PS requirement | Suricata / Snort | Zeek | This system |
|---|---|---|---|
| **Forecast** ahead of the event, graded on **lead time at a fixed FPR** | detects on match, at the event | detects on scripted condition | the graded metric — `docs/benchmark_protocol.md` |
| Flow **and** packet features from one extractor | rule-dependent | rich, protocol-level | 30 window-bounded features, one code path |
| Explanation naming **real features**, never embeddings | the rule is the explanation (excellent) | the script is the explanation | TreeSHAP in named-feature space, enforced by a test |
| **Tamper-evident, offline-verifiable** record of every forecast | logs (protect them yourself) | logs | hash chain + Merkle + anchored checkpoints, `ledger/verify_cli.py` |
| Fully air-gapped, including verification | yes | yes | yes, enforced by `tests/test_offline.py` |

Two of those rows are where this system is genuinely different rather than merely different:

1. **Lead time is the success metric, not F1.** CLAUDE.md: *"A model with better F1 and zero lead
   time has failed this problem statement."* A rule engine's lead time on an unknown campaign is
   structurally zero until someone writes the rule.
2. **The forecast record is itself an evidence artefact.** Editing one record breaks its hash and
   the verifier names the exact index; rewriting the whole chain self-consistently still fails
   against the anchored checkpoint; and the engine refuses to write at all if the weights' SHA-256
   does not match. That is the Blockchain & Cybersecurity theme done as provenance rather than as
   a token, and it is not something an IDS log gives you.

## 3. The evaluation-protocol argument

This is the part of the positioning we can defend with our own numbers.

**One thing first, because the rest of this section is measured and this part is not.** It is the
team's impression, from reading around CSE-CIC-IDS-2018, that near-perfect accuracy and F1 —
0.99 and up — are commonly reported on it. We attach **no citation**: we have not assembled those
papers under the offline constraint, and inventing a precise reference would be worse than saying
so (CLAUDE.md). Treat it as recollection, not evidence, and note that **nothing below depends on
it** — the argument is about our own protocol and our own numbers.

The mechanism that inflates a benchmark number is not in doubt, and it is checkable here rather
than in the literature: the **split**. A random train/test split over flows or windows puts parts
of the *same attack episode* on both sides, so a model can memorise an episode rather than
generalise to an unseen one. CLAUDE.md forbids exactly this ("Split by day, never randomly. Whole
attack episodes stay inside one split"), and `docs/decisions/003` records a leakage bug of the
same family caught and fixed in this repository before any number was published.

Under this protocol the numbers are modest, and publishing them anyway is the argument:

- Splits are **day-wise and attack-family-disjoint** — train on brute-force + DoS, test on bot.
  Nothing about the test family is seen in training (`docs/benchmark_protocol.md`).
- The operating point comes from an **FPR budget fitted on validation**, never a tuned threshold.
- Undetected episodes count as **0 s lead** and are never dropped from the median.
- On that protocol the graded logistic-regression baseline reaches **AUROC 0.573** — near chance.
  Our published fused result — an evaluation-side model, not the deployed engine — reaches
  0.933 (≈ 0.89 de-duplicated) with 2/2 episodes at ~49–91 min
  lead. Both are our own measurements, regenerated by `python scripts/make_ablation_table.py` over
  `results/*.json` — which is gitignored, so a judge reproduces them by running the evaluation,
  not by reading a committed table.

So the claim is **not** "we beat the literature" — we have not measured the literature, so we
cannot make that claim and do not. The defensible version is narrower and entirely internal:
**on a cross-family day-wise split the linear baseline is at chance (0.573) and the fused model is
not (0.933)**, so what separates them is the ability to transfer to an attack family never seen in
training. Any benchmark number, ours included, is only comparable to another number produced under
the same split rule — which is why `docs/benchmark_protocol.md` states ours before it states any
result. We would rather publish our smaller number with its caveats
(`tier1_hardening_report.md` → Limitations & Confidence) than a larger one we cannot defend.

## 4. What we have not measured — and are not claiming

**No head-to-head has been run.** Suricata has not been executed over the 02-03 test day; neither
has Zeek; no commercial NDR has been evaluated. Any table comparing our AUROC to theirs would be
fabricated, and CLAUDE.md forbids that. The comparison above is **analytical** — about what each
tool is designed to do — and it stops there.

Running Suricata with a standard ruleset over the test-day pcap and reporting its alerts against
the same episode/lead-time definition is a concrete, cheap experiment. It is **roadmap**
(`docs/roadmap.md` §1.11), not a result.

Three further points of fairness that cut against us:

- **Alert volume.** At the 1 % budget the deployed XGBoost engine implies roughly 111,000
  alerts/day on
  a ~450-host network (`docs/deployment.md` §5). A tuned signature deployment against known
  threats is far quieter. We have a configured-but-unpublished 0.1 % budget and no alert
  coalescing at all.
- **Our operating-point detection is carried by XGBoost**, a conventional gradient-boosted model
  on tabular features — not by the temporal-graph component that is the research contribution
  (`tier1_hardening_report.md` → Limitations & Confidence §2).
- **n = 2 episodes, one attacker host.** No mature tool would be evaluated on that, and neither
  should this be without saying so every time.

## 5. The one-line answer

Run Suricata *and* Zeek. This is not a replacement for either — it is the layer they do not
provide: a host-level forecast graded on **lead time at a fixed false-positive budget**,
explained in named features, and committed to a tamper-evident record that a third party can
verify offline.
