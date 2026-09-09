# Tier-1 hardening report

Three findings, each backed by produced numbers. Machine context: **torch 2.14.0+CPU**
(CUDA unavailable), 8 threads — so the CUDA/cuDNN parts of the determinism fix are inert
here but correct for the RTX 4060; the nondeterminism seen on this box is CPU parallel-reduction
order.

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
nondeterministic draw. What survives on the forecasting side is a **ranking claim**: the
encoder's k-step-ahead AUROC holds ≈ 0.84 at +20 s and +40 s (predictive signal exists), with
seed-averaging on GPU as the documented recovery path for the forward operating point.

**Recommended reframe for the pitch:** lead the deck with "detects infiltration **~49–91 min
before attack completion (median ~70 min) at a 1 % false-positive budget, 2/2 episodes**,"
present k-step forecasting as ranking-verified capability with the operating point as
documented future work — and keep the existing fine print that both episodes are two sessions
of the same attacker host.

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

## Open decisions for the human
1. **Drop `net24_bucket` from the shipped feature set?** Evidence says it would *raise* the
   graded metrics (xgb F1 0.140 → 0.392, recall 0.114 → 0.452, lead → ~86 min) and remove a
   key-artifact dependency, at the cost of 0.080 AUROC. Not done unilaterally — it retrains the
   engine and moves every number again. (Part 3.)
2. **Reframe the forecasting headline** as recommended in the top flag — already applied to the
   docs in this commit; confirm it matches how you want to pitch it.
3. **GPU seed-averaging (pack E1)** is now the concrete path to recover a forward-horizon
   operating point and to report a *distribution* rather than one deterministic point.
