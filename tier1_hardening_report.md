# Tier-1 hardening report

Three findings, each backed by produced numbers. Machine context: **torch 2.14.0+CPU**
(CUDA unavailable), 8 threads — so the CUDA/cuDNN parts of the determinism fix are inert
here but correct for the RTX 4060; the nondeterminism seen on this box is CPU parallel-reduction
order.

---

## 🛑 STOP-THE-PRESS — six verified defects that invalidate published claims

Found by a 6-dimension adversarial audit of the eval pipeline (34 raw findings, 15 surviving
independent refutation), then **re-verified by hand** here. These are not subagent assertions;
every number below was reproduced directly from the cached score dumps.

> **RESOLUTION STATUS — 12 September 2026.** The blanket "do not film" order this section
> originally carried has been narrowed to what is actually still open. Four of the six defects
> are closed in the repository; two need a regeneration run on a machine that has the dataset.
>
> | # | Defect | Status | Where |
> |---|---|---|---|
> | 1 | "best validation AUROC — selected on val, never on test" is FALSE | **closed** | `909d722` — deleted from README, `docs/architecture.md` and the PDF; `tests/test_docs_claims.py` fails the build if it returns |
> | 2 | Lead time does not beat chance | **disclosed, row still to generate** | `909d722` — the matched-budget random baseline is stated beside every lead-time claim in README, the slides, the deck and `JUDGES.md`. The permanent ablation ROW needs `results/*.json`, so it waits on the dataset |
> | 3 | The fusion is transductive | **disclosed, code fix open** | `909d722` — `eval/fused.py`'s docstring now carries a KNOWN DEFECT block with the causal-refit consequence (F1 0.172 → 0.053). The refit itself changes published numbers, so it must land together with a regeneration run |
> | 4 | The 1 % FPR table is not like-for-like | **closed** | `bdb89f2` — `eval/ablation.py` prints achieved FPR per row; the 3.2× spread is quoted under the README table until the table is regenerated |
> | 5 | The k-step target is nearly the nowcast target | **closed** | `579ab05` — the 93–96 % overlap is stated wherever the k-step result appears, including the engine's own caveat constant and the app panel |
> | 6 | Published Spearman ρ does not reproduce | **closed** | `909d722` — corrected to 0.05 in `docs/architecture.md` and `eval/fused.py` |
>
> **What this means for filming.** Defects 1, 4, 5 and 6 were textual and are fixed, so the
> documents are safe to film against. Defects 2 and 3 are *disclosed rather than repaired*: the
> lead-time and fused-F1 numbers on screen are the ones this report criticises, and every surface
> that shows them now says so. Film against them only while that disclosure is on screen too.

| # | Defect | Verified evidence | Severity |
|---|---|---|---|
| 1 | **"Best validation AUROC of any row — selected on val, never on test" is FALSE** | Val AUROC: **xgb 0.806 > lstm 0.774 > fused 0.765**. Fused is **third**. | **critical** |
| 2 | **Lead time does not beat chance** | Uniform random noise at the *same* alert budget (18,117 alerts) scores **lead 4,882–5,110 s, 2/2 episodes** over 3 trials, vs fused **4,195 s, 2/2** | **critical** |
| 3 | **The fusion is transductive** — percentile ranks are fitted on the split they score | Causal refit (ECDF fitted on val only): F1 **0.172 → 0.053**, precision 0.268 → 0.093. AUROC is rank-invariant so **0.933 → 0.930 stands** | **critical** |
| 4 | **The "1 % FPR budget" table is not like-for-like** | Achieved test FPR: tgn **0.373 %**, lr 0.663 %, fused 0.811 %, lstm 0.836 %, tgn_graft 0.933 %, xgb **1.194 %** — a 3.2× spread in alert budget across rows being compared on F1 | **major** |
| 5 | **The k-step "forecast" target is nearly the nowcast target** | labels at k=1/4/8 are **95.7 % / 93.5 % / 93.1 % identical** to k=0 | **major** |
| 6 | **Published Spearman ρ does not reproduce** | docs and `eval/fused.py:8` claim member ρ ≈ 0.11; actual test ρ = **0.050** | minor |

### What each one costs us

**#1 is the most damaging to credibility.** That sentence is our *stated defence against
test-set model selection*, it appears in `README.md`, `docs/architecture.md` **and the 2-page
PDF deliverable**, and it is false. Worse, fused has the largest val→test gap of any row
(0.765 → 0.933), which is exactly the signature of test-set selection that the claim was meant
to rebut. On the stated criterion (best val AUROC) the selected model would be **xgb**.

**#2 means the headline lead-time result is not evidence of model skill.** The metric saturates
at this alert budget: episodes are thousands of windows long, lead time is measured from the
*first* alert, so any detector firing ~1 % uniformly will hit an early window of both episodes
by chance. "2/2 episodes, ~70 min lead" is a property of the budget and episode length, not of
the model. It is still the PS's graded metric and we still meet it — but it must be reported
**alongside a chance baseline**, or it reads as a claim we have not earned.

**#3 means the fused row's operating point is not deployable and not comparable.** Ranking each
split against its own empirical CDF makes the val-chosen threshold land at the same *quantile*
in test — which is why fused appeared to transfer thresholds so well. It cannot be computed
online at time *t* (the score at 10:11 depends on windows from 15:55), and under a causal
refit the fused F1 (0.053) drops **below the untouched XGBoost baseline (0.140)**. The F1-column
ordering that puts fused first is an artifact of the transform. Note the AUROC headline is
unaffected — AUROC is invariant to any monotonic per-split transform.

**#5 undercuts the forecasting framing further** than the operating-point failure already did:
predicting the label 40 s ahead is predicting a label that is the same as *now* 93 % of the
time. Combined with the 0/2 operating point, "k-step forecasting" is not currently a
substantiated capability at all — not even the ranking claim carries the weight we gave it,
because the ranking target is nearly the nowcast target.

### Recommended resolution

*(Status of each is in the table above. 1, 4, 5 and 6 are applied; 2 and 3 need a regeneration run on a dataset machine.)*

1. Delete the "best validation AUROC" sentence everywhere; replace with the honest statement:
   fused is selected for **test-set ranking quality and error decorrelation**, and xgb is the
   val-optimal single model. Rebuild the PDF.
2. Add a **chance baseline row** to the results table (random scores at matched alert budget)
   and state that lead time at this budget does not separate from it.
3. Fix `eval/fused.py:48-50,66-67` to fit each member's ECDF on **val only** and apply it
   pointwise, then regenerate the fused row (expect AUROC ≈ 0.930, F1 ≈ 0.05, lead ≈ 4,158 s,
   2/2). Correct the "parameter-free, nothing fitted on val/test" prose, which is false as
   written.
4. Print achieved FPR per row in the table so the budget spread is visible.
5. Correct ρ to 0.05 and the stale k=8 AUROC (0.890 → 0.842) in `docs/limitations.md`.

---

## ⚠ FLAG — what the deterministic lead-time claim actually is (affects the core pitch)

**Question answered here:** does episode capture now come from the current-window (nowcast)
fused classifier rather than the K-step forecaster — and what lead time can we honestly claim?

**Yes.** Under determinism, the K-step forecaster **no longer provides operating-point
early-warning on its own**: at the 1 % FPR budget it fires 0/2 episodes at k = 1/4/8, and this
is a **ranking limit, not a threshold bug** (even the test-ideal oracle threshold reaches only
F1 ≤ 0.009 — Part 2). Episode detection in the deterministic table comes from the
**horizon-0 fused classifier**, and within the fusion, overwhelmingly from its **XGBoost
member's behavioural signal** (deterministic TGN alone: ep0 missed, ep1 lead 75 s).

**The honest, current, deterministic lead-time number** (fused nowcast, 1 % FPR budget,
val-fit threshold 0.9397, per-episode from the score dump):

| episode | duration | first alert | lead time |
|---|---|---|---|
| ep0 (18.219.211.138, session 1) | 4,980 s | **+2,040 s** into the episode | **2,940 s (~49 min)** |
| ep1 (same host, session 2) | 5,460 s | **+10 s** — at onset | **5,450 s (~91 min)** |
| **median** | | | **4,195 s (~70 min), 2/2 episodes** |

**Mechanism, stated precisely:** this is *precursor detection, not forward extrapolation* —
the alert fires on early-episode windows as they happen, and "lead time" is the PS's own
definition (first alert on the attacking host → annotated attack completion). The PS's graded
success metric is therefore **still genuinely met** (2/2 at ~49–91 min lead at 1 % FPR); what
is no longer supportable is the *mechanistic* claim "predicts attacks 20–40 s ahead and
catches both episodes" — the pre-fix forecast numbers (0.913 @ k=4, 2/2, ~80 min) were a
nondeterministic draw.

### Limitations & Confidence

This section qualifies the lead-time table directly above it. Every number in that table
carries all four caveats below; none of them is a footnote.

**1. n = 2 is not a distribution — and it is really n = 2 sessions of one host.**
There are exactly two attack episodes in the test split, and both are the *same attacker host*
(18.219.211.138) in two sessions of the same bot campaign. "2/2 episodes" and "median ~70 min"
therefore have **no confidence interval and no variance estimate** — a median over two points is
not a statistic. The per-episode leads differ by a factor of ~1.9 (2,940 s vs 5,450 s), which is
the only spread information available. These numbers must **not** be read as validated across
attack diversity, across attacker hosts, or as an expected operating characteristic on unseen
traffic. They are two observations, reported as two observations.

**2. Detection is dominated by the XGBoost member — the least novel part of the architecture.**
Within the fusion, the behavioural gradient-boosted model does essentially all the work at the
operating point. Measured on the attacker host: **XGBoost alone fires on 19.3 % of ep1's windows;
the deterministic TGN encoder fires on 0.1 %, misses ep0 entirely, and reaches ep1 only at 75 s
lead.** The fused row's 2/2 capture is therefore carried by XGBoost, not by the temporal-graph /
world-model component that constitutes the project's research contribution. Stated plainly:
**our PS-compliance claim currently rests on the conventional baseline, not on the novel
architecture.** The TGN's contribution is real but narrow — it decorrelates errors, which is what
made the fused headline robust to the determinism fix (−0.009 where single models moved up to
0.56) — but it is not what produces the graded result.

**3. AUROC ≈ 0.84 at +20 s / +40 s does not mean k-step forecasting works.**
It means only this: *ranking signal exists* at those horizons — the forecaster orders attack
windows above benign ones better than chance. At **any FPR budget we can actually afford (1 %),
that signal collapses to F1 ≤ 0.009 and 0/2 episodes**, and the oracle-threshold analysis (Part 2)
confirms no threshold recovers it — it is a ranking limit, not a calibration bug. **The
forecaster cannot currently produce a usable alert at a real operating threshold.** The AUROC
figure must not be quoted anywhere in a way that implies working forward forecasting; wherever it
appears it is to be labelled a ranking-signal-exists result and nothing more.

**4. Reported AUROC and F1 are inflated by row multiplicity (found during this audit).**
The effective evaluation unit is `(source_host, window, observing_capture)`, not the documented
`(source_host, window)`: an external attacker appears as a source inside multiple victims'
captures, so the same logical host-window contributes several rows with differing features
(29.5 % of keys are duplicated; **8.7 rows per window for the attacker host** vs 1.42 average).
De-duplicating by aggregating per host-window:

| metric | as published (raw rows) | de-duplicated (max / mean) |
|---|---|---|
| fused AUROC | 0.933 | **0.888 / 0.895** |
| fused F1@1 % | 0.172 | **0.040 / 0.038** |
| xgb AUROC | 0.872 | **0.777 / 0.788** |
| fused lead median | 4,195 s | 4,190 s |
| fused episodes | 2/2 | **2/2 (unchanged)** |
| ep1 first alert | +10 s | **+10 s (unchanged)** |

So the **lead-time and episode results — the PS's graded metric — are robust to this**, but the
**ranking/threshold metrics are not**: read fused AUROC as ≈ 0.89 and F1 as ≈ 0.04 on a
de-duplicated basis. Whether to make de-duplication the shipped evaluation unit is an open
decision (below), not silently applied.

**What the sanity-check did rule out.** The ep1 "+10 s" alert was audited specifically for
artifact status and is clean: the onset annotation is exogenous (hand-curated UNB timeline,
never derived from any feature); the firing window spans [+10 s, +25 s], entirely post-onset,
with **zero alerts in the 60 s before onset**; the model fires on only **0.9 %** of the attacker's
windows during its 2.8 h idle gap between sessions (vs 0.8 % for all other hosts) and **18.3 %**
once the attack starts — a ~20× behavioural response, not host-keying; and SHAP attributes the
alert to a **~20× SYN burst** over the same host's idle baseline (`syn` +4.60, the top driver),
with `net24_bucket` identical in both and contributing *negatively*. Mechanism: bot C2 session
establishment. The number survives de-duplication exactly.

**Recommended reframe for the pitch:** lead the deck with "detects infiltration **~49–91 min
before attack completion (median ~70 min) at a 1 % false-positive budget, 2/2 episodes**,"
present k-step forecasting as ranking-verified capability with the operating point as
documented future work, and carry caveats 1–2 (n = 2 sessions of one host; XGBoost-dominated)
wherever the lead-time number is claimed.

---

## Part 1 — GRAFT training non-determinism

### Step 1 — Audit (actual state of every RNG source)

| Source | State (verified by grep + read, not assumed) |
|---|---|
| `random.seed` | seeded — `configs/loader.py:45` |
| `PYTHONHASHSEED` | set at runtime — `loader.py:46` (too late for the current process's own hashing; affects children only) |
| `numpy.random.seed` | seeded — `loader.py:53` |
| `torch.manual_seed` | seeded — `loader.py:61` |
| `torch.cuda.manual_seed_all` | called — `loader.py:62` (no-op on this CPU build) |
| DataLoader workers | **N/A** — no torch `DataLoader`; batching is manual via a **seeded** `torch.Generator` (`harness.py:320`, `tgn.py:146`) |
| Dropout / weight init | seeded — `set_seed()` runs before every `build_model` (12 call sites confirmed) |
| `torch.use_deterministic_algorithms` | **NOT set** — the gap |
| cuDNN flags / `CUBLAS_WORKSPACE_CONFIG` | **NOT set** — the gap (matters on the 4060) |

`set_seed` was applied everywhere; the defect was exactly the user's hypothesis — **seeding without algorithm-determinism**, which does not defeat nondeterministic parallel float-sum order.

### Step 2 — Fix (code)

`configs/loader.py:set_seed` now also sets, inside the torch branch:
`torch.use_deterministic_algorithms(True, warn_only=True)`, `cudnn.deterministic=True`,
`cudnn.benchmark=False`, and `os.environ["CUBLAS_WORKSPACE_CONFIG"]=":4096:8"`.

### Step 3/4 — Verification (mandatory twin, produced numbers)

| run | test AUROC | F1@1% | note |
|---|---|---|---|
| pre-fix, "same config" (`tgn_graft` vs `tgn_graft_no_time2vec`) | **0.853 / 0.923** | 0.008 / 0.371 | nondeterministic draws — a ~0.07 spread |
| **det1** (fix, seed 1337) | **0.7008** | 0.013 | — |
| **det2** (fix, seed 1337, identical) | **0.7008** | 0.013 | **bit-identical to det1** |

**det1 vs det2: test-score arrays `array-equal = True`, max abs diff = `0.0`, AUROC gap `0.0000`.**
Zero ops were flagged by `use_deterministic_algorithms(warn_only=True)` in the real path.

**Verdict:** the fix achieves **full bit-identical determinism** (0.0 residual), verified by an
actual repeated run — not code inspection.

**Correction I owe (rule: report what you find):** an initial *synthetic* probe (400 events)
showed identical output with determinism on/off, which I first read as "op-nondeterminism absent."
That was **wrong — the probe was too small** to trigger real-scale (1M-event, 8-thread)
reduction nondeterminism. The full-scale twin above is the authoritative test and supersedes it.

**Flag (rule: determinism changing numbers):** the fix **changes the numbers**. Deterministic
`tgn_graft` = **0.701**, vs the unreproducible 0.853/0.923 draws. The old values were single
samples of a ~0.70–0.92 distribution and should not have been trusted as point estimates.
The same TGN training path underlies the shipped **`tgn`** row and the **fused** headline.
**Measured impact of determinism on every headline-relevant number** (same key, same seed):

| row | pre-fix (nondeterministic draw) | deterministic | Δ |
|---|---|---|---|
| xgb | 0.872 | **0.872** | 0.000 (xgb was already deterministic) |
| tgn | 0.877 (2/2 @ 3595 s) | **0.840** (1/2 @ 38 s) | −0.037, and the episode story weakens |
| tgn_graft | 0.853 / 0.923 (two draws) | **0.701** | the twin collapses to one reproducible value |
| **fused (headline)** | 0.942 (2/2 @ 5008 s) | **0.933** (2/2 @ 4195 s) | **−0.009 — the headline survives** |
| forecast k=4 | 0.913, 2/2, ~80 min | **0.844, 0/2 at the 1 % budget** | the forecast operating point collapses (see Part 2 — it is a ranking limit, not thresholds) |

The rank-mean fusion is exactly the robustness mechanism it was claimed to be: its members'
errors decorrelate, so the encoder's determinism regression barely moves it (−0.009) while
single-model rows swing far more.

### Unresolved / uncertain
- Whether the deterministic value (0.701) is representative or a low corner of the old
  distribution cannot be known from one deterministic point; the honest statement is "0.701 is
  the reproducible value," not "0.701 is the true skill." Seed-averaging (GPU pack E1) is the
  way to get a distribution.
- **Consequence for the benchmark table:** every torch-trained row (`tgn`, `tgn_graft`,
  `forecast`, and the `fused`/clamped variants) was produced pre-fix and is a nondeterministic
  draw. A trustworthy table needs a **full regeneration under the determinism fix** — flagged,
  scoped below, not silently left mixed.

---

## Part 2 — 40 s-ahead forecast threshold

### Step 1 — Diagnosis (before any fix)

**Code fact first:** `eval/forecast.py:100` fits `threshold_at_fpr(vk.y, pv, budget)` **inside the
per-horizon `k` loop** — so thresholds are **already calibrated per-horizon**, not carried over
from 20 s. The premise "20 s threshold reused at 40 s" does not hold in this codebase.

**Oracle result (produced from the per-horizon score dumps, deterministic run):**

| k | val-thr percentile in test scores | val-thr / oracle-thr | alerts fired | ORACLE F1 @ 1% test-FPR | oracle recall |
|---|---|---|---|---|---|
| 1 | p99.61 | **1.0×** | 5,917 | 0.009 | 0.005 |
| 4 | p99.58 | **1.0×** | 4,925 | 0.008 | 0.004 |
| 8 | p99.61 | **1.0×** | 4,259 | 0.007 | 0.004 |

**Verdict: NOT a calibration bug — a ranking limitation.** The val-chosen threshold lands
essentially exactly where the test-ideal (oracle) threshold does (ratio 1.0×) and fires ~1% of
windows as budgeted. But even the **oracle** threshold recovers only F1 ≤ 0.009 — the attack
windows are simply not in the deterministic encoder's top-1% tail at any horizon. Per the
task's own escalation rule ("if no threshold produces reasonable F1/recall, escalate as a
modeling issue, don't force a threshold fix"), **no threshold recalibration is performed** —
there is nothing for it to recover. Episode capture at the fixed budget comes from the **fused
nowcast** (2/2), and the pre-fix "0.913 @ k=4, 2/2" forecast was a nondeterministic draw of a
stronger encoder (see Part 1). The path to a stronger *deterministic* forecaster is seed
averaging (GPU pack E1), not thresholding.

### Step 3 — Generalisation
Per-horizon thresholding is already the pattern in `forecast.py` (verified: the fit is inside
the k-loop); the RSSM path (`eval/world.py`) is a documented negative result (0/2 at every
horizon, decision 004). There is no live "single-threshold-reused" bug anywhere to generalise
a fix to — **confirmed against the dumps**.

### Unresolved / uncertain
None mechanical. The open item is model-quality, not calibration: the deterministic encoder's
top-tail ranking is weak at all horizons (oracle F1 ≤ 0.009), quantified above and disclosed
in the regenerated docs.

---

## Part 3 — net24_bucket ablation

### Architectural finding (before the numbers)
Tracing the data path: `net24_bucket` is a column of the **30-dim window matrix**, consumed by
the **flat models (`xgb`/`lr`/`lstm`)** — but **not** by `tgn` or `graft`, whose heads are fit on
the TGN **embeddings** (memory_dim=100), not the raw matrix. So:
- the **fused** headline's only net24 dependence is via its **xgb** member;
- **TGN's key-sensitivity (0.877↔0.954) is a *different* mechanism** — the key-derived node-ID
  permutation (`anonymize.epoch_node_ids`), not net24-the-feature. (The user's framing conflated
  the two; the code separates them.)

### Step 2 — Effect size (produced: retrained with the column zeroed, same key/seed/split)

`net24_bucket` is feature column 28 of 30. Retrained, evaluated at the 1 % FPR budget:

| model | variant | AUROC | F1 | recall | lead (s) | episodes |
|---|---|---|---|---|---|---|
| xgb | **with** net24 | **0.872** | 0.140 | 0.114 | 4208 | 2/2 |
| xgb | **without** net24 | 0.792 | **0.392** | **0.452** | **5148** | 2/2 |
| | **Δ (with − without)** | **+0.080** | **−0.251** | −0.338 | −940 | — |
| lr | with net24 | 0.573 | 0.001 | 0.001 | 0 | 0/2 |
| lr | without net24 | 0.533 | 0.000 | 0.000 | 0 | 0/2 |
| | Δ | +0.040 | +0.001 | — | — | — |

`tgn` / `graft`: **not affected** — their heads are fit on TGN embeddings, not the 30-dim
matrix, so the ablation is a no-op for them by construction. `fused`'s only net24 dependence is
through its xgb member.

### Step 3 — Findings and decision

**Two findings, and the second is uncomfortable:**

1. **net24 IS load-bearing for AUROC** — removing it costs xgb **0.080** AUROC, four times the
   0.02 "non-load-bearing" threshold. So the key-derived bucket is *not* a free feature: part of
   xgb's (and therefore the fused headline's) global ranking rests on a value that is an artifact
   of the anonymisation scheme. This needs to be stated in the docs, and now is.
2. **But net24 actively HURTS the graded operating point.** Without it, xgb's F1 goes
   **0.140 → 0.392**, recall **0.114 → 0.452**, and median lead **4208 s → 5148 s (~86 min)**,
   still 2/2 episodes. Every metric the problem statement actually grades improves substantially
   when the key-derived feature is removed; only AUROC (which the PS does not grade) falls.

I am **not** unilaterally changing the shipped feature set this close to submission: dropping a
column means retraining the engine model, re-recording weight digests, re-verifying the app path,
and regenerating the table again — a real change with real blast radius. It is flagged for the
human as a scope decision (see the report's top-level flag list), with the recommendation that
**dropping net24 is the technically better end-state** on the graded metrics *and* removes a
key-artifact dependency — the two goals point the same way here, which is rare.

**Documented caveat (applied now, in lieu of the change):** the xgb and fused AUROC figures
partially depend on `net24_bucket`, a /24 bucket derived from the anonymisation key; a different
key produces different bucket values, and ~0.08 of xgb's AUROC moves with it. The
*episode/lead-time* results — the PS's graded metric — do **not** depend on it favourably and in
fact improve without it.

### Unresolved / uncertain
- Whether a **key-stable, order-preserving** bucket assignment recovers the AUROC without the
  operating-point damage is untested (it would need a new bucketing implementation + a retrain).
- The ablation zeroes the (already standard-scaled) column, which is equivalent to dropping it
  for a tree/linear model but is not literally a 29-column retrain; a true column-drop retrain
  would be the confirmatory version.

---

## Code changes
- `configs/loader.py:56-78` — determinism locks in `set_seed`
  (`use_deterministic_algorithms(True, warn_only=True)`, `cudnn.deterministic`,
  `cudnn.benchmark=False`, `CUBLAS_WORKSPACE_CONFIG`).
- `scripts/determinism_probe.py` — op-flagging + reproducibility probe (new).
- `eval/forecast.py:97-112` — per-horizon score dumps enabling the oracle diagnosis (new).
- `scripts/ablate_net24.py` — the Part-3 ablation (new).
- `README.md`, `docs/architecture.md`, `docs/slides.md`, `docs/demo_script.md`,
  `docs/limitations.md`, `docs/architecture.pdf` — regenerated table + the lead-time reframe +
  the determinism disclosure.

## Two premises worth correcting

- The k-step forecaster is **not** the RSSM. The RSSM (autoregressive world model) failed its
  hard gate and was never shipped (decision 004). The shipped forecaster is the **TGN encoder
  plus a linear head trained on labels shifted by k** (`eval/forecast.py`) — so "the
  autoregressive RSSM is confirmed dead" conflates two separate negative results. The RSSM died
  at M7; what this audit shows is that the *encoder forecast head*'s operating point is dead.
- There is **no Mamba** in this build. CLAUDE.md explicitly lists Mamba among components not to
  add without an ablation row. The novel components are the TGN temporal-graph encoder and the
  GRAFT causal transformer.

## Open decisions for the human
0. **Make de-duplication the shipped evaluation unit?** Full evidence, all models, aggregating
   each host-window by max score (val and test treated identically, threshold refitted on the
   de-duplicated val):

   | model | AUROC raw | AUROC dedup | Δ | F1 raw | F1 dedup | lead raw | lead dedup | eps |
   |---|---|---|---|---|---|---|---|---|
   | **fused** | 0.933 | **0.888** | −0.045 | 0.172 | 0.040 | 4195 s | 4190 s | 2/2 → 2/2 |
   | xgb | 0.872 | 0.777 | **−0.095** | 0.140 | 0.055 | 4208 s | 4198 s | 2/2 → 2/2 |
   | tgn | 0.840 | 0.803 | −0.037 | 0.009 | 0.014 | 38 s | 38 s | 1/2 → 1/2 |
   | lstm | 0.764 | 0.773 | **+0.009** | 0.015 | 0.021 | 4202 s | 4190 s | 2/2 → 2/2 |
   | lr | 0.573 | 0.506 | −0.067 | 0.001 | 0.001 | 0 s | 0 s | 0/2 → 0/2 |
   | tgn_graft (both) | 0.701 | 0.605 | −0.096 | 0.013 | 0.007 | 1035 s | 878 s | 2/2 → 2/2 |
   | clamped-T2V | 0.380 | 0.358 | −0.022 | 0.014 | 0.017 | 30 s | 30 s | 1/2 → 1/2 |

   Three things this settles:
   - **The shipped choice is safe either way.** `fused` ranks #1 under both bases, so the
     headline model selection does not depend on this decision.
   - **Episode capture is completely unaffected** — every model keeps its exact episode count
     (2/2, 1/2, 0/2) and its lead time to within ~10 s. The PS's graded metric is basis-independent.
   - **XGBoost is the biggest beneficiary of the multiplicity** (−0.095, the largest drop), and
     de-duplication *reverses* the #2/#3 order: raw reads `xgb > tgn`, de-duplicated reads
     `tgn > xgb`. So the row multiplicity was flattering the conventional baseline specifically —
     which slightly *softens* caveat 2 in ranking terms, though xgb still dominates at the
     operating point (dedup F1 0.055 vs tgn's 0.014).

   Both bases are defensible — per-sensor alerting is what a real IDS deployed at each victim
   would do, and that is what the raw rows measure — but they are different claims. The docs
   currently publish the raw-row numbers with the caveat attached. Switching means regenerating
   the table a third time; the evidence above is complete enough to decide without re-running.
1. **Drop `net24_bucket` from the shipped feature set?** Evidence says it would *raise* the
   graded metrics (xgb F1 0.140 → 0.392, recall 0.114 → 0.452, lead → ~86 min) and remove a
   key-artifact dependency, at the cost of 0.080 AUROC. Not done unilaterally — it retrains the
   engine and moves every number again. (Part 3.)
2. **Reframe the forecasting headline** as recommended in the top flag — already applied to the
   docs in this commit; confirm it matches how you want to pitch it.
3. **GPU seed-averaging (pack E1)** is now the concrete path to recover a forward-horizon
   operating point and to report a *distribution* rather than one deterministic point.
