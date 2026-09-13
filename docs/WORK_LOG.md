# Work log — the audit and what it changed

**Branch:** `audit/tier1-false-claims` · **14 commits** · 97 files, +32,845 / −544 · 53 new files
**Test suite:** 78 passed / 16 skipped → **1,499 passed / 19 skipped** (1,518 collected)
**Period:** 10–13 September 2026

This is the honest record of what was done to this repository after it was cloned, why each
thing was done, and what came out of it. It is written for the team, and it does not flatter the
work: several of the findings below are about defects this project had already shipped, and two
are about defects the fixing itself introduced.

---

## 1. Why any of this happened

The repository was already substantial when this work started: a working pipeline, a Streamlit
demo, a hash-chained ledger, 78 passing tests, and a set of published benchmark numbers. It also
already contained two adversarial self-audits (`tier1_hardening_report.md`,
`diagnosis_report.md`) that the team had run on themselves.

The question asked was not "does this work" but **"would this win SIH?"** — which is a different
question, and it is answered by a judge, not by a test suite.

So the work began by putting the repository in front of a simulated hostile judge: a
multi-agent audit that read the problem statement, the code, and every judge-facing document, and
was told to find every reason a judge would not award this project the win.

That audit produced **108 findings**, of which 14 were rated critical. Everything in the rest of
this log follows from it.

---

## 2. What the audit found — the uncomfortable parts

Three findings mattered more than the rest, because each one would have ended a judging
conversation on its own.

### 2.1 The repository published claims its own audit had already disproved

`tier1_hardening_report.md` — written by the team, in this repository — listed six verified
defects and stated, at the top, that the team should not film a video or submit a deck against
the current README numbers until they were resolved.

**None of the five recommended resolutions had been applied.** The README, the architecture
document, and the graded 2-page PDF still carried:

- a sentence asserting that the fused row led every other on the **validation** split, and was
  therefore chosen there rather than on test — while the report's own measurement showed it
  ranked *third* on validation (xgb 0.806 > lstm 0.774 > fused 0.765);
- a description of the deployed engine as the quick first stage of a two-model chain, when
  `engine/predict.py` contains exactly one `load_model` and one `predict_proba` — it is a
  single model, not a cascade, and the old phrasing is now banned by a test;
- a k-step AUROC higher than the deterministic measurement of 0.842 (the stale figure itself is
  in `tier1_hardening_report.md`, which this guard deliberately does not scan), and a claim that
  20 seconds ahead was an operating point the system stood behind — when it fires **0 of 2
  episodes at every horizon**;
- a Spearman correlation of 0.11 between the fusion's members, when the measured value is 0.05.

**Why this mattered.** The team's honesty was the project's strongest differentiator. A judge who
opened `tier1_hardening_report.md` — which sits at the repository root — would have found the
team's own analysis contradicting the team's own README. That is worse than never having audited
at all.

### 2.2 The problem statement's flagship deliverable did not exist

SIH26153 lists ten deliverables. Number 3 is a *"K-step forward simulation engine with
probability scores and MITRE ATT&CK stage mapping"*.

There was no `k > 0` code path anywhere in `engine/` or `app/`. The k-step head existed only in
offline evaluation scripts. The product a judge would run was a **nowcaster** — it answered "is
this host under attack now", not "what does this host look like in 40 seconds".

The project is named *forecasting*.

### 2.3 The ledger could be forged, and the demo could not be run

Two independent problems, both fatal in front of an NTRO judge:

- The ledger's HMAC key defaulted to a literal string in public source. The dataset has about
  fifteen fixed attacker addresses, so that default makes every pseudonym in a demo run
  reversible with a fifteen-entry lookup table. Separately, an audit agent **forged a complete
  self-consistent chain and the verifier printed OK** — because the chain and its checkpoint log
  were written by the same process into the same directory, so rewriting both was enough.
- `artifacts/` is gitignored and the weights Release was never published, so a judge who cloned
  the repository got a red Python traceback on the first click and fifteen skipped tests —
  including the end-to-end offline test that is the problem statement's own hard constraint.

---

## 3. How the work was done, and why that method mattered

The fixes were not written by one agent in one pass. The structure was:

1. **Fix agents with strictly disjoint file ownership.** Each agent owned a named set of files and
   could touch nothing else, so several could work at once without overwriting each other. None
   of them could commit — the orchestrator did that, after verification.
2. **Independent adversarial verifiers.** After each round, a separate agent was told to *not
   trust the report* and to reproduce every claim itself: run the commands, replay the attacks,
   and break every new guard with a **plausible** edit — the kind a careless contributor would
   actually make, not a nonsense one.

**This is the part worth keeping.** The verifiers caught something real in every single round:

| Round | What the fixing itself got wrong |
|---|---|
| 1 | An agent wrote "~4 GB for the venv" into the install guide. Measured: **1.49 GB**. Never measured, presented as fact. |
| 1 | `.env.example` instructed the reader to use "the value recorded in the README bootstrap section". No such section existed. |
| 2 | The documentation guard had a blind spot **centred on the paragraphs it existed to protect** — its exemption windows were wide enough that a corrected file's own retraction wording silenced the check. |
| 3 | A regression test for a persistence call could not detect that call being deleted. The verifier deleted it; the suite stayed green. |
| 4 | The kill-chain figure's 19-point title said "the two-stage hole we do not hide" over **three** greyed-out stages. |
| 5 | The slide deck's architecture diagram drew the evaluation-only pipeline as the shipped one. XGBoost — the only model in the scoring path — appeared nowhere on the slide. |

Every one of those would have shipped without an adversarial second pass. The lesson is not that
agents are unreliable; it is that **a claim and its verification must not come from the same
place**, which is the same principle the project already applied to its own metrics.

---

## 4. What was built

### 4.1 The k-step forecast engine (PS deliverable 3)

`engine/forecast.py` scores every host at each configured horizon. `engine/train_engine.py` fits
and persists **one model per horizon**, each with its own FPR-budget thresholds — the threshold
for k=8 is not the threshold for k=0, and silently reusing one for the other is exactly the class
of error this audit existed to catch. Labels shift through the same machinery `eval/dataset.py`
already used, so the engine and the evaluation harness predict the same target. A horizon with no
persisted head is **reported**, never silently skipped. The app draws a per-host risk curve.

It is labelled for exactly what it is. The measured facts — no supported operating point at any
horizon, ranking AUROCs that belong to the eval-side head rather than these engine heads, and a
k-step target that is 93–96% identical to the nowcast target — appear in the module docstring, in
the engine's own caveat constant, and **on the app panel before the curve is drawn**.

### 4.2 The ledger, hardened

Three attacks closed: the default key is gone (an unset key now raises, matching the pattern
`data/anonymize.py` already used); checkpoints are HMAC-signed and chained, each signing its
predecessor's signature, with only the last able to anchor; and a missing or absent chain is now
an **error** rather than a cheerful "OK".

One attack was **not** closed, and that is stated rather than hidden: truncating the chain *and*
its checkpoint log together leaves two files that agree with each other, and nothing inside them
records that the run continued. No scheme confined to those two files can detect it. That is what
`scripts/anchor_checkpoint.py` exists for — publishing a count and digest outside the run
directory before a demo. The limitation lives in the module docstring, in the verifier's output,
in `docs/limitations.md`, and in a test that performs the truncation and asserts it is *not*
caught — so if it ever becomes caught, the test fails and the documentation gets corrected.

### 4.3 A demo a judge can actually run

`scripts/bootstrap_demo_artifacts.py` fits a small model from the bundled synthetic capture into
a separate lane at `artifacts_demo/`, so a fresh clone runs the whole pipeline in under a minute
with no dataset, no released weights and no network.

The model it produces is a toy, and the code says so in those words: fitted on one 455-second
hand-authored capture, with thresholds chosen on the same rows it was fitted on, so a high
probability when it scores that capture back means *"I have seen this row before"*, not *"I have
detected an attack"*. That statement travels with the run as **data, not prose** — the engine
reports the demo lane in its result dict and in `run_summary.json`, and the app says it before
showing any number.

The trap this had to avoid was making the skipped tests pass. A test that goes green against a
toy model is not evidence for a claim measured on CSE-CIC-IDS-2018, so `tests/_stubs.py` now
distinguishes three states — published bundle, demo bundle, neither — and each test declares which
it needs. **The skip count did not fall.**

### 4.4 Documents, figures and decks

Five judge-facing documents that did not exist: a threat model with **measured** evasion costs, a
deployment document that does the alert-volume multiplication openly, a competitive positioning
document, a dataset-quality treatment, and a roadmap. Plus `JUDGES.md`, a ten-minute verification
guide whose every command was run before it was written — and one of whose documented outputs was
**wrong on the first attempt** and corrected to what the tool actually prints.

Three SVG figures; an architecture PDF that finally embeds one (it previously had `/XObject: 0`
on both pages because the builder wrote its HTML into a temp directory where relative image paths
could not resolve); a real 5-slide technical deck; a **separate September idea-round deck**, which
matters because that round's judges typically never open the repository; seven product
screenshots, each carrying the demo-model provenance **inside the frame** rather than in a caption
a crop would drop; a one-page summary; a recording checklist; and CI, which the repository did not
have.

### 4.5 A ratchet, so this cannot recur

`tests/test_docs_claims.py` scans ~153 files for the retired claims. It is measured rather than
asserted: the test inserts each retired sentence at every paragraph boundary of every scanned file
and requires a catch at all of them. Its first version had exemption windows that let 98 of 8,722
insertion points through; the replacement lets through **zero**, and that measurement is itself a
test.

---

## 5. The accuracy question

The team asked whether accuracy could be improved. The first thing worth saying is that the
framing needed correcting.

**AUROC 0.933 is not low.** What looks low is **F1 (0.172)**, and that is a consequence of the
operating point, not of model weakness: benign windows outnumber attack windows about 40:1, and
the threshold is set at a **1% false-positive budget**. Plain accuracy would read ~0.98 for
everything, which is why this project does not report it.

So the dataset was fetched (12.71 GiB compressed, selective per-host, four days) and extracted.
**The class counts reproduced the published table exactly** — benign 2,217,799 / 1,360,972 /
1,634,866, initial_access 4,463, c2 1,953 / 38,241, impact 1,681 — under a *different*
anonymisation key. That is a meaningful validation of the extraction pipeline on its own.

Then both role-feature arms ran through the shipped harness. For XGBoost, the model the engine
actually deploys:

| arm | val AUROC | val F1 | test AUROC | test F1 | recall | lead | episodes |
|---|---|---|---|---|---|---|---|
| with `net24_bucket` | **0.758** | 0.046 | 0.782 | 0.234 | 0.185 | 4,210 s | 2/2 |
| without | 0.740 | **0.047** | 0.774 | **0.388** | **0.460** | **5,148 s** | 2/2 |

The lead time reproduces the earlier column-zeroing ablation **to the second** (5,148 s), which is
good evidence the measurement is sound.

**It was not promoted, and the reason matters more than the number.** Validation cannot separate
the arms — 0.018 AUROC and 0.001 F1, both inside the noise of a one-family validation day — so the
rule this project selects on does not decide it. Promoting on the test-set F1 gain would be
*precisely* the error the audit found published here once already. And `lstm` flips the other way
entirely (val 0.869 without vs 0.793 with; test 0.652 vs 0.865), which is a fair warning about how
noisy n = 2 episodes on one attacker host makes all of this.

The reasoning, both arms' numbers, and the command that reproduces them are recorded in
`configs/data.yaml` beside the key, and the run is in `results/accuracy_experiment.json`.

**One more finding, and it is uncomfortable.** Under a new key the published figures move
materially: xgb AUROC 0.872 → 0.782 while F1 0.140 → 0.234. Key-sensitivity was already
documented for the TGN encoder; this is the same effect on the deployed model. It means **the
published table is one key's draw**, not a universal result — and that belongs in how the numbers
are presented.

---

## 6. What came out of it

**Closed:** 9 of the 14 critical findings, plus the great majority of the high and medium ones.
The suite went from 78 to 1,499 passing tests. Every claim the project's own audit had disproved
is retracted, and a guard stops them returning. The problem statement's flagship deliverable
exists. A judge can run the demo on a bare clone. The ledger survives the attacks that previously
defeated it, and the one it does not survive is disclosed.

**A limitation was found *understated*, which is worth recording separately.** Six documents —
including the judges' guide — said two kill-chain stages have no data. The class table has always
shown **three** (`recon` is 0/0/0/0 alongside `lateral_movement` and `exfiltration`). Understating
a limitation is the same defect as overstating a result. The count is corrected everywhere, the
figure guard now derives it from the class table rather than from prose, and the two *reasons* are
distinguished: `lateral_movement` and `exfiltration` are absent from CSE-CIC-IDS-2018 entirely,
while `recon` simply has no labelled windows in the four days fetched.

**Still open, and each one needs a person, not an agent:**

| # | What | Why it is blocking |
|---|---|---|
| 1 | **Make the repository public** | Every judge-facing link 404s. Until this is done, none of the work in this log is visible to anyone evaluating it. Thirty seconds. |
| 2 | Publish the weights Release | Without it a clone cannot reproduce anything, and fifteen tests stay skipped. |
| 3 | Record the 2-minute video | A graded deliverable. Script and pre-flight checklist are written. |
| 4 | Run the M11 lab capture | The only route to data for the three empty kill-chain stages. |
| 5 | Team commits | Four of six members have none, and SIH judges read git history. |

**Still open and needing a machine, not a decision:** promoting the `net24` arm (every row must be
regenerated together, including the TGN rows, which cost hours), the causal fusion refit, the
permanent chance-baseline row, CTU-13 cross-dataset evaluation, and confidence intervals in the
remaining results writers.

---

## 7. The one thing to take from this

The most valuable output is not the code. It is that the project now **cannot quietly drift from
its own evidence**: the documentation ratchet fails the build if a retired claim returns, the
threat model's figures are executed against the production extractor rather than typed, the figure
guards derive their counts from the class table, and the bootstrap-state report tells a reader
which guarantees are currently unverified on their machine.

That property is what survives contact with a judge who does not believe you.
