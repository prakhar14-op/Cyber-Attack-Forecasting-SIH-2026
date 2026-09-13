# Idea-round deck — 6 slides (SIH September screening)

**This is not `docs/slides.md`.** That file is the five-slide *technical* deck for the December
Grand Finale, rendered by `scripts/build_deck.py`, and it is written for expert judges who will
open the repository and probe the limitations. This file is the **idea-round** deck: the September
screening submission, read fast, by judges who will almost certainly never clone anything.

`scripts/build_idea_deck.py` renders this file to `docs/deck/sih26153_idea_deck.pptx`. The
`<!-- deck:… -->` markers are the grammar `scripts/build_deck.py` established and this builder
imports; a marked block goes **on the slide**, an unmarked block becomes that slide's **speaker
notes**.

## The format this deck is built to

The official SIH *IDEA* presentation format is **six slides, submitted as PDF**, with a fixed
section list. Confirmed against the official `SIH2024_IDEA_Presentation_Format.pdf` (slide titles
and pointers read directly) and against the SIH2026 revision of the same template:

| # | Official section | Official pointers |
|---|---|---|
| 1 | Title Page | PS ID · PS Title · Theme · PS Category · Team ID · Team Name |
| 2 | Proposed Solution | detailed explanation · how it addresses the problem · innovation and uniqueness |
| 3 | Technical Approach | technologies to be used · methodology and process for implementation |
| 4 | Feasibility and Viability | feasibility analysis · potential challenges and risks · strategies for overcoming them |
| 5 | Impact and Benefits | potential impact on the target audience · social / economic / environmental benefits |
| 6 | Research and References | details / links of the reference and research work |

`SECTIONS` in `scripts/build_idea_deck.py` is that list, and the build fails if this document
renames, reorders, drops or adds one.

## Why this deck is shaped differently from the technical deck

`docs/slides.md` **leads with its limitations**, which is right in front of finale judges who will
go looking for them anyway. A screening judge reads six slides in about ninety seconds, against
rivals who claim near-perfect accuracy with no caveats. A deck that opens by apologising loses
that comparison without ever being read.

The resolution is **not** to hide the caveats. It is to open on the strongest claim that is
actually true — a cross-family generalisation gap over a graded linear baseline on the identical
feature matrix — and let the caveats land on slide 4, which is the slide the official template
*asks* for risks on. Rigour placed where the template wants it reads as rigour. The same rigour
placed on slide 2 reads as weakness.

## No results number is typed into this file

Every published figure is a placeholder resolved **at build time** from `docs/architecture.md` §4
(and §3, for which row the engine actually runs):

| placeholder | resolves to |
|---|---|
| `{{measured:MODEL:COLUMN}}` | that model's cell in the §4 results table |
| `{{lead_min:MODEL}}` | that model's median-lead cell, converted to whole minutes |
| `{{clopper_lower:MODEL}}` | the exact binomial (Clopper–Pearson) 95 % lower bound for that model's episode count, computed at build time |

The results table is being regenerated under a new anonymisation key and a `net24_bucket`
ablation may move the F1/recall columns, so pasting a value here would ship a stale number.

Three checks hold that line, and they fail on different edits:

1. **No figure may be typed into the slide body** (everything from the first `## Slide` heading
   down, speaker notes included). The builder refuses any literal value under 1 with two or more
   decimals and names the placeholder that replaces it. This front-matter section is above that
   line and is not scanned.
2. **A figure for a model the engine does not run must be marked evaluation-side in the same
   block as the figure** — not merely somewhere on the slide. Slide 2's band says "measured
   evaluation-side" about the fused row; a slide-scoped check would therefore have waved through
   a swap of the headline's own figure to that row, four blocks away, which is the exact overclaim
   this project keeps making. The one exception is a row `docs/architecture.md` §4 itself labels a
   baseline — the graded logistic row — where the word "baseline" beside it is disclosure enough.
3. **Every figure in the saved `.pptx` is re-checked against the document**, so the deck fails
   verification the moment the regenerated table lands, instead of quietly showing a stale number.

---

## Slide 1 — Title Page

<!-- deck:kicker -->
SIH 2026 · idea submission · Problem Statement **SIH26153** · NTRO · theme: Blockchain & Cybersecurity

<!-- deck:headline -->
**Forecast the host. Explain the alert. Prove the record.**

<!-- deck:chips the idea in three parts -->
- **Forecast** — per (source host, 15 s window), so *"how early did we know?"* is a question the system can answer
- **Explain** — every alert names real features and a MITRE ATT&CK technique, never an embedding index
- **Prove** — each alert is sealed into a hash-chained ledger a judge re-verifies with the network unplugged

<!-- deck:points -->
- **Problem Statement ID** SIH26153 — *AI based Network Attack Forecasting from Network Traffic Data*
- **Theme** Blockchain & Cybersecurity · **PS Category** Software · **Licence** Apache-2.0, fully open source
- **Team ID** TBD · **Team Name** TBD — the portal-registered values go here before upload

**Team ID and Team Name are deliberately TBD.** They are not facts this repository holds, and
CLAUDE.md forbids inventing a value where one has not been established. Fill both in from the SIH
portal registration before the deck is exported to PDF.

The three chips are the whole submission in one line each, and they are ordered by how hard they
are to fake: forecasting is a modelling claim, explanation is an interface claim, and the ledger
is the only one of the three a judge can falsify on the spot with no network and no trust in us.

---

## Slide 2 — Proposed Solution

<!-- deck:headline -->
On a **day-wise, attack-family-disjoint test split**, the deployed scorer reaches
**AUROC {{measured:xgboost:AUROC}}** — the graded logistic baseline on the *identical* feature
matrix reaches {{measured:logistic:AUROC}}.

<!-- deck:points -->
- **What it is** — one extractor, 30 window-bounded features per (host, window), one gradient-boosted scorer, a validation-fitted FPR threshold
- **How it addresses the PS** — black-box output is ruled out, so every alert carries top-5 **named** features and an ATT&CK technique
- **What is uniquely ours is the protocol** — whole episodes never straddle a split, and an undetected episode counts as **0 s lead**, never dropped from the median

<!-- deck:band figures resolved from docs/architecture.md at build time -->
That table's best row is a **rank-mean fusion measured evaluation-side**; the engine loads one
booster, so the row above is what a judge's own demo produces. That table's AUROC and F1 are
inflated by **evaluation-row multiplicity**; de-duplication is an open decision.

**Why this claim and not a bigger one.** Day-wise splitting over four attack days makes train and
test **attack-family-disjoint** — train carries brute-force and DoS, test carries bot — so the gap
between the two figures above is a genuine cross-family transfer result, not a memorised episode.
That is the honest hard version of this problem statement, and it is the one place where our
numbers separate cleanly from a baseline rather than from the literature. We have **not** measured
the literature and make no claim against it (`docs/competitive.md` §4).

The unit of prediction is the load-bearing design decision. A per-flow classifier answers "was
this flow malicious?" after the fact; scoring a *host over a window* is what makes lead time —
the PS's own success metric — a measurable quantity at all.

Window-bounded features are the second. Every feature value summarises only packets whose own
timestamp lies inside the window. Attributing whole-flow totals to a flow's start window leaked
forecast-horizon traffic into the present and would have fabricated our headline; the leak was
found and removed before anything was published (`docs/decisions/003`).

---

## Slide 3 — Technical Approach

<!-- deck:points -->
- **Stack** — Python · XGBoost · SHAP (TreeSHAP) · scikit-learn · PyTorch + torch-geometric · scapy / tshark · Streamlit · JSON-Schema · SHA-256 hash chain
- **Flow and packet features, both mandated by the PS** — TTL mean and variance, TCP window, fragment flags, payload histogram, port entropy, scan signature, retransmissions
- **Causal by construction** — perturbing windows *t+1…T* leaves the prediction at *t* bit-identical; identity is keyed-HMAC pseudonyms, so no raw IP reaches the model or the ledger

<!-- deck:lane deployed | DEPLOYED — what `engine/predict.py` loads and runs -->
```
PCAP / CSV → 30 window-bounded features → XGBoost scorer (one booster) → FPR-budget threshold → TreeSHAP + ledger
```

<!-- deck:lane evaluation | EVALUATION-ONLY — measured in `eval/`, never loaded by the engine -->
```
same 30 features → TGN graph memory → GRAFT causal Transformer → k-step head (ranking only) → rank-mean fusion
```

**Two lanes, one feature matrix, and the judge's demo is the top lane.** This is
`docs/architecture.md` §2's own split. Drawing them as a single chain would teach a reader a
pipeline the product does not have, so the builder refuses to put an evaluation-only component
into the deployed lane.

**Methodology, in the order it runs.** Parse pcap bytes with raw struct offsets (≈110k packets/s,
bounded memory) → join flow records and per-(src, window) packet statistics into the 30-feature
matrix → fit the scaler on the training split only → score each host-window → convert the score
to an alert using a threshold fitted from an FPR budget on **validation** → attribute it with
TreeSHAP in named-feature space → map stage and observed pattern to an ATT&CK technique
(`engine/technique_map.yaml`) → append to the hash chain and close the batch with a Merkle root.

**Why XGBoost is the deployed scorer and the temporal-graph stack is not.** It is CPU-cheap, it is
natively TreeSHAP-explainable in the same named-feature space the PS demands, and it is what
measured best on the deployable path. The TGN/GRAFT lane is the research contribution and it is
measured honestly in `eval/` — but honesty about which of the two a judge is actually running is
the single thing this project has been audited hardest on.

---

## Slide 4 — Feasibility and Viability

<!-- deck:points -->
- **Built, not proposed** — M0–M10 tagged; *offline* is a test, not a promise: `tests/test_offline.py` blocks every socket, then runs inference and ledger verification end to end
- **Runs where the customer runs** — CPU-only inference, offline wheel-house install, no cloud API, no telemetry
- **Reproducible by the judge** — splits, seeds and the FPR budget are YAML config; the results table regenerates from the evaluation, not from a committed number

<!-- deck:table -->
| risk we carry | what we do about it |
|---|---|
| n = 2 attack episodes, one host | publish the exact binomial CI |
| 3 of 7 kill-chain stages have no labels | no per-class metric is published |
| the k-step head fires at no FPR budget | ship horizon-0 precursor detection |
| a 1 % FPR budget means many alerts | coalesce alerts; a 0.1 % budget exists |
| the packet parser is IPv4-only | every skipped frame is counted and shown |

**Feasibility is the easy half and we treat it as already answered.** Nothing above is a plan: the
extractor, the scorer, the explainer, the ledger, the offline verifier and the Streamlit file-input
demo exist and run air-gapped today. The install is a local wheel-house, the inference is CPU-only,
and the whole thing is Apache-2.0 with `THIRD_PARTY_NOTICES.md` maintained.

**The risks are the half worth a judge's attention, so they are stated at full strength.**
`recon`, `lateral_movement` and `exfiltration` have **zero labelled windows**: the latter two do
not exist in CSE-CIC-IDS2018 at all, and `recon` has none in the four days we fetched. So the
system forecasts a binary infiltration probability reliably and assigns a stage by interpretable
named-feature rules — it is **not** a validated seven-class classifier, and we publish no
per-class number for those three. The k-step forecast head is a real ranking capability whose
fixed-budget operating point does not fire, and the oracle-threshold check says that is a ranking
limit rather than a threshold anyone forgot to retune; the early warning this system claims comes
from the **horizon-0** classifier instead. Benign hosts are subsampled (~30 of ~450 per day), which
inflates precision and F1 and makes any alerts-per-day figure a within-sample extrapolation.

**Viability.** Apache-2.0, no licence cost, no per-seat model, and no vendor in the loop — a CERT
or a lab can run it on hardware it already owns. `docs/roadmap.md` §1 is a sized list of the open
engineering items, each tied to the evidence that sizes it, rather than a wish list.

---

## Slide 5 — Impact and Benefits

<!-- deck:headline -->
Triage starts from evidence; the record still verifies at the review.

<!-- deck:points -->
- **Social** — a defender gets evidence, not a score: top-5 named features, the windows where the attack formed, an ATT&CK technique
- **Economic and environmental** — Apache-2.0 and fully offline: an air-gapped lab or CERT runs it with no licence and no cloud egress
- **Evidentiary — the theme done as provenance** — append-only hash chain, per-batch Merkle roots, anchored checkpoints, verified offline
- **Methodological** — the evaluation protocol is published *before* the result

<!-- deck:band measured lead time — and what it does not prove -->
Horizon-0, test day: alerts on **{{measured:xgboost:episodes}}** attack episodes, median
**{{lead_min:xgboost}} min** before completion. But **n = 2, both sessions of one attacker host**
(exact binomial 95 % lower bound {{clopper_lower:xgboost}} %), and at this budget lead time
**does not separate from a matched-budget random baseline**.

**Impact, stated at the size it actually is.** The lead-time number is the most attractive thing on
this page and the least supported, which is exactly why it sits in the band and not in the
headline. Two episodes of one host is not a population; the interval above is what two-for-two
honestly buys, and the matched-budget random comparison is the test this number has not yet
passed.

What is *not* hedged: the explanation and the ledger. Every alert names real features because the
problem statement rules out black-box output, and every forecast is committed to a chain where
editing one record breaks that record's hash and the verifier names its exact index — a fully
rewritten, self-consistent chain still fails against an anchored checkpoint. `ledger/verify_cli.py`
does that with no network. The one tampering mode it cannot catch — truncating the chain and its
checkpoints together — is documented and pinned by a test rather than left to be discovered.

**Environmental:** CPU-only inference and no cloud round-trip, so the compute footprint is a
laptop's. We have measured no energy figure and therefore claim none.

---

## Slide 6 — Research and References

<!-- deck:points -->
- **Dataset** — CSE-CIC-IDS2018, CSE & Canadian Institute for Cybersecurity, UNB — `unb.ca/cic/datasets/ids-2018.html`
- **Dataset defects** — Liu, Engelen, Lynar, Essam, Joosen, *Error Prevalence in NIDS datasets*, IEEE CNS 2022, doi:10.1109/CNS56114.2022.9947235
- **Deployed scorer** — Chen & Guestrin, *XGBoost: A Scalable Tree Boosting System*, KDD 2016 — arXiv:1603.02754
- **Explanations** — Lundberg et al., *Explainable AI for Trees: From Local Explanations to Global Understanding* — arXiv:1905.04610
- **Temporal graph encoder** — Rossi, Chamberlain, Frasca, Eynard, Monti, Bronstein, *Temporal Graph Networks for Deep Learning on Dynamic Graphs* — arXiv:2006.10637
- **Uncertainty head** — Sensoy, Kaplan, Kandemir, *Evidential Deep Learning to Quantify Classification Uncertainty*, NeurIPS 2018 — arXiv:1806.01768
- **Append-only log design** — Merkle-tree logs as specified in RFC 6962 (Laurie, Langley, Kasper, 2013); attack taxonomy from MITRE ATT&CK, `attack.mitre.org`

**Every entry above was checked against the publisher this round**, not quoted from memory: titles
and author lists from the arXiv abstract pages, the CNS 2022 venue and DOI for Liu et al. (which
`docs/dataset_quality.md` had flagged "verify venue/year" and which is now verified), the dataset
page at UNB, and RFC 6962 at the RFC Editor. `docs/dataset_quality.md` carries the rest of the
bibliography with a per-entry confidence statement, including the entries we are **not** yet
confident enough to print on a slide.

**Our own written work, which is the reference a judge can actually audit:**
`docs/architecture.md` (two pages, every measured figure), `docs/benchmark_protocol.md` (the split
and threshold rules, stated before any result), `docs/limitations.md` (five numbered limitations),
`docs/dataset_quality.md` (which published dataset defects reach this pipeline and which do not),
`docs/competitive.md` (why not just run Suricata or Zeek — and the head-to-head we have **not**
run), `docs/threat_model.md`, `docs/evasion.md` and `docs/roadmap.md`.
