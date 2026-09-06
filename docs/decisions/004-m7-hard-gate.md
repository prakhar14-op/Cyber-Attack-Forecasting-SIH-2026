# 004 — M7.7 hard gate: RSSM world model failed; forecasting works via the encoder — **RESOLVED**

**Status: reported 2026-09-06; option 3 ("both") approved and executed. The encoder forecaster
ships as `m7-forecast`; the RSSM fix-up was attempted and ALSO failed the gate (below), so the
RSSM is not shipped and `m7-rssm` was never tagged.**

## Fix-up attempt outcome (v2, configs/train_rssm_v2.yaml)

The anti-collapse recipe — KL warm-up (0→1 over 6 epochs), free-bits 1.0→0.3, reconstruction
weight 1.0→0.1, dynamics 1.0→3.0, epochs 6→15 — **markedly improved the ranking but did not
clear the gate**:

| | v1 | v2 | shipped forecaster |
|---|---|---|---|
| test AUROC k=1 | 0.604 | 0.788 | 0.893 |
| test AUROC k=4 | 0.662 | 0.843 | **0.895** |
| test AUROC k=8 | 0.683 | 0.851 | 0.890 |
| episodes @1% FPR | 0/2 | 0/2 | **2/2** (to k=4) |
| median lead | 0 s | 0 s | **3885 s** |

Loss rebalancing recovered most of the ranking gap (k=8 AUROC 0.683 → 0.851), which confirms the
v1 diagnosis: the 128-d reconstruction MSE really was starving the supervised dynamics term. But
the posterior still collapses (raw KL 0.245–0.293 against a 0.3 floor), the ensemble band still
does not widen (0.0003 → 0.0002), and **the operating point never recovers — 0/2 episodes and
0 s lead at every horizon**. The RSSM remains worse than the encoder it consumes.

**Verdict: the fallback stands.** The RSSM is a documented negative result, not a shipped
component. The recipe above is recorded because it is the honest starting point for anyone
resuming this line with a GPU and a longer schedule; on this CPU budget it does not earn its row.

BUILD_PLAN M7.7 is the make-or-break gate: *"if the world model shows no lead-time advantage over
XGBoost at k ≥ 4, stop and report before building anything else — the pitch changes."* It failed.

## What the world run produced (results/world.json, on the shipped no-Time2Vec encoder)

| horizon | test AUROC | test F1@1%FPR | median lead | episodes |
|---|---|---|---|---|
| k=1 | 0.604 | 0.003 | 0 s | 0/2 |
| k=4 | 0.662 | 0.004 | 0 s | 0/2 |
| k=8 | 0.683 | 0.003 | 0 s | 0/2 |

vs the M4/M5 references (horizon 0): **XGBoost** 0.895 AUROC / 5148 s / 2-2 episodes; **TGN**
0.954 / 5038 s / 2-2. The RSSM is worse than every baseline **and worse than its own input
embeddings** — it destroys signal rather than adding forecasting power.

Diagnostics (the audit-fixed monitors, all firing correctly):
- **Posterior collapse every epoch**: raw KL 0.93 → 0.77–0.83, below the 1.0 free-bits floor. The
  stochastic latent carries almost no information.
- **Ensemble band flat**: 0.0058 → 0.0057 across k=1..8 (does not widen — the samples barely
  differ because the posterior collapsed toward the prior mean).

## Why (diagnosed, not guessed)

The eval harness is sound — the fallback probe below reuses the same alignment / lead-time /
threshold code and produces sensible numbers, so the failure is in the RSSM model, not the
scoring. Most likely causes: (a) the 128-dim embedding **reconstruction MSE dominates** the
composite loss and starves the supervised dynamics term; (b) **no KL warm-up**, so the latent
collapses before the decoder learns to use it; (c) **6 CPU epochs** is very little for an RSSM.
All three are consistent with the collapse + flat-band signature.

## The forecasting signal is real — it lives in the ENCODER (fallback probe)

The BUILD_PLAN risk register's fallback ("ship TGN+GRAFT at horizon k with the rollout framing")
was tested: the frozen **TGN encoder + a plain linear head**, trained on labels shifted by k and
scored at the val-fit 1% FPR threshold on the bot test day:

| horizon | test AUROC | median lead | episodes |
|---|---|---|---|
| k=0 | 0.891 | 2000 s | 1/2 |
| k=1 | 0.893 | 2000 s | 1/2 |
| k=4 | **0.895** | 2000 s | 1/2 |
| k=8 | 0.889 | 0 s | 0/2 |

**The ranking barely degrades out to k=4 (20 s ahead)** — genuine forecasting, not nowcasting.
(The weak F1/episodes here are the operating-point/head-fitting issue seen across the supervised
rows, not a ranking failure; the M5 subsampled-head TGN row already reached F1 0.565.)

## Options (for human decision)

1. **Pivot to the fallback (recommended):** make the deliverable "TGN(+GRAFT) forecasting at
   horizon k" — labels shifted, so it is honestly a forecaster, not a classifier — and report the
   RSSM as a tried-and-failed ablation row (honest, and the collapse is a real finding). Guarantees
   a working lead-time demo. The RSSM code stays, flag-gated.
2. **One RSSM fix-up run first:** KL warm-up + lower free-bits, down-weight reconstruction /
   up-weight dynamics, more epochs. ~1 h/run on CPU. If it clears the gate, ship it; if not,
   fall back to (1). A bounded time gamble.
3. **Both, in parallel:** ship (1) as the submission baseline now, attempt (2) as a bonus that
   only gets added if it wins. De-risks the deadline.

Recommendation: **3** — lock in the working forecaster, attempt the RSSM improvement without
betting the submission on it. Either way, **the RSSM as-is is not tagged and not shipped.**
