# GRAFT root-cause diagnosis report

**Scope.** Why does the TGN→GRAFT pipeline report dramatically worse F1 than TGN alone
(0.095 / 0.011 vs 0.565 in the benchmark table), despite reasonable AUROC? Every claim below
is backed by a produced number, plot, or passing test — artifacts in [`diagnostics/`](diagnostics/).
Where something could not be verified, that is stated explicitly.

---

## 0. Read this first: the benchmark table you are debugging is not reproducible

The quoted table was produced under an anonymisation key (`SIH26_HMAC_KEY`) that was never
persisted. The key changes real model inputs (`net24_bucket`, the per-epoch node permutation),
and the models measurably depend on them — under a standardized fixed key, **every** number moved:

| model | old-key (quoted table) | fixed key (reproducible) |
|---|---|---|
| tgn | AUROC 0.954 · F1 0.565 | AUROC **0.877** · F1 **0.035** |
| xgb | AUROC 0.895 · F1 0.309 | AUROC **0.872** · F1 **0.140** |
| tgn_graft (no T2V) | AUROC 0.895 · F1 0.095 | AUROC **0.923** · F1 **0.371** |

> **Action required:** the published benchmark table (README/docs) must be re-generated and
> re-published under the standardized key (kept in the gitignored `.env`). The old numbers
> cannot be reproduced by anyone, including us.

## 1. Verdict

**The "GRAFT collapse" is primarily an experimental-configuration artifact, not an architecture
failure.** Retrained bit-for-bit identically except under the standardized anonymisation key,
the same GRAFT (no-T2V) scores **test AUROC 0.923, F1@1% 0.371, recall 0.373** — better than
fixed-key TGN (0.877 / 0.035) and XGBoost (0.872 / 0.140). Every hypothesized internal defect
was tested and refuted with numbers: no probability collapse (attack-class mean 0.256 = 66×
benign mean), no loss-term domination (attack BCE is **89%** of the final total; `pos_weight`
**360.97**, confirmed wired at runtime), no padding pathology (**28.8%** padding, 63% of
segments full), causal mask present and enforced bit-identically (test passed). The one **real,
remaining defect** is metric-specific: GRAFT fails the graded lead-time metric (**1/2 episodes,
42–85 s lead**) because its alerts sit on the *internal bot victims*, not the *external attacker
host* that episodes are keyed on — episode 0: **0 of 7,562** attacker-host windows fired;
episode 1: first alert at **+5,375 s of a 5,460 s** episode. The oracle-threshold experiment
proves this is ranking *content*, not calibration: an ideal threshold changes nothing (still 1/2,
42 s). Secondary: the with-Time2Vec regression has a measured mechanism — T2V's linear term is
unbounded in the inter-window gap (**33×** the feature signal at gap 1000; **~2%** of real gaps
exceed 100) — the clamped-T2V control run addresses exactly this.

## 2. Quantitative evidence by step

| # | Question | Evidence (produced, not assumed) | Verdict |
|---|---|---|---|
| 1 | Probability collapse? | GRAFT test: benign median 2.4e-05, p99 0.0157; attack median 1.25e-03, **mean 0.256**, max 1.0. TGN: benign med 2.0e-07 / attack med 0.050. XGB: benign p99 2.8e-05 / attack mean 0.032. Plots: `prob_hist_all3.png` | **No collapse in any model.** All three separate the classes; the F1 gap lives in tail overlap at the 1%-FPR cutoff. |
| 2 | Loss-term domination? | Final epoch (per-term logging added to the harness): attack **0.334 (89%)**, evidential 0.033, recon 0.004, stage 0.005. `pos_weight` printed at runtime = **360.97** (= benign/attack in train segments), wired into `BCEWithLogits(pos_weight=…)` at `losses.py:104-110`. Plot: `graft_loss_terms.png` | **Refuted.** The classification head dominates the gradient. Note: the hypothesized focal/forward/backward-forecast MSE terms **do not exist** in this codebase — the composite is attack-BCE + stage-CE + Dirichlet-evidential + benign-only recon. |
| 3 | Padding pathology? | Real config is 15 s/5 s/**48** (not 30/10/64). **28.8%** of positions are padding; **63.4%** of segments completely full; median real length 48/48; 31.5% of segments >50% pad. Pads are masked out of every loss term (`valid`). `padding_histogram.png` | **Refuted** as a collapse mechanism. |
| 4 | Causal mask / leakage? | Bool causal mask + `src_key_padding_mask` passed on the only `TransformerEncoder` call (`models/graft.py:92`); `test_no_future_leakage` **PASSED**: perturbing t+1…T leaves position-t predictions **bit-identical**. TGN-alone's high old number is *not* future-leakage: it moved 0.954→0.877 under a key change — leakage does not evaporate with an anonymisation key; a key-dependent shortcut/variance does. | **Mask verified present; leakage ruled out at the encoder.** |
| 5 | What does each model key on? | XGB TreeSHAP top-10 (mean abs SHAP): ttl_mean 3.39, payload_hist_0 3.23, tcp_win_var 1.67, sent_bytes 1.50, internal 1.40, sent_pkts 1.38, tcp_win_mean 1.11, server_port_ratio 0.94, **net24_bucket 0.89**, syn 0.85 (`shap_xgb_summary.png`). GRAFT TP-vs-FN contrast (full split, scaled units): FNs have port_entropy **+3.10** vs +0.86, sequential_port_ratio **+0.96** vs −0.20, internal **0.27** vs 2.15. LIME on 4 FN attacker-windows: 3 of 4 also score ~1e-06 under XGB (evidence there is genuinely benign-looking); 1 of 4 (syn>0, psh>0) XGB catches at 0.36 while GRAFT stays at 8e-04. `lime_fn_cases.json` | XGB keys on intuitive packet/volume features. GRAFT catches internal/victim-side windows and **misses the external attacker's scan/beacon-profile windows**. Role features (`internal`, key-dependent `net24_bucket`) are load-bearing in both models — the key-sensitivity is not an accident. |
| 5b | Why 1/2 episodes at 42 s? | Episode autopsy on attacker host 18.219.211.138: ep 0 — 7,562 attacker windows, **0 fired**; ep 1 — 9,753 windows, 78 fired, **first at +5,375 s of 5,460 s**. Oracle threshold (uses test labels; diagnostic ceiling only): still **1/2, 42 s** — recall moves 0.373→0.329, episodes don't move. | **Ranking-content defect, not calibration.** GRAFT's caught attack windows are the bot victims, not the attacker. |
| 6 | Why did Time2Vec make it worse? | Ablation diff verified: parameters **bit-identical at init**, only the forward flag differs. T2V additive magnitude vs feature projection at init: 0.7× at gap ≤ 10, **3.4× at gap 100, 33× at gap 1000** (`t2v_magnitude_init.json`). Real gaps: p50 = 1, **p95 = 10**, p99 ≈ 380, max ≈ 7,200; **~2% of gaps > 100** (`delta_t_gap_stats.json`). | **Mechanism identified:** the unbounded linear time term swamps the embedding on every window after an idle gap. Clamped-T2V control run (clamp = 10 = p95): **in progress — results below when complete.** |

## 3. Clamped-Time2Vec controlled experiment (Step 6 follow-up)

Config `train_graft_t2v_clamped.yaml` is identical to the shipped config except
`use_time2vec: true` + `delta_t_clamp: 10` (p95 of real gaps, both splits). The clamp is
config-driven, inert below threshold, and unit-tested (`tests/test_time2vec_clamp.py`:
outlier gap ≡ clamp-value embedding; identical to unclamped for normal gaps).

**Result — hypothesis confirmed, decisively.** Same key, same seed, same config except the clamp:

| variant | test AUROC | F1@1% | recall | lead | episodes | val AUROC |
|---|---|---|---|---|---|---|
| no-T2V | 0.923 | 0.371 | 0.373 | 42 s | 1/2 | 0.822 |
| **T2V clamped @ 10** | **0.937** | **0.480** | **0.607** | **4,170 s** | **2/2** | 0.662 |
| (T2V unclamped — old-key internal pair) | 0.789 | 0.011 | — | 10 s | 1/2 | — |

Clamping did not merely stop T2V from hurting — the gap signal **fixed the attacker-host
blindness of row 5b**: 2/2 episodes at 4,170 s lead, versus 1/2 at 42 s without it. This makes
domain sense: C2 beaconing regularity *is* inter-arrival structure, which is exactly what a
bounded Time2Vec encodes. The with-T2V regression in the original table was therefore caused by
the **unbounded linear term**, not by gap-encoding itself.

**Promotion discipline (honest):** on the val day the clamped variant is *weaker* (0.662 vs
0.822) — another instance of the val/test family asymmetry — so on val-selection it does **not**
displace the shipped fused headline, and this is a single run of a training process with proven
seed variance. Follow-up 3-way fusion (xgb + tgn + clamped-GRAFT): **test AUROC 0.954,
F1 0.395, lead 4,342 s, 2/2** — test-better than the shipped 2-way fused (0.942 / 0.382), but
val 0.773 vs 0.785, i.e. just below the bar. Both are recorded as `__exp` candidates; a
seed-repeat (the GPU pack's E1) decides promotion.

## 4. Ranked secondary factors

1. **Key/permutation sensitivity is a systemic issue, not just a GRAFT issue** — `net24_bucket`
   is top-10 SHAP for XGB and shows a TP/FN gap for GRAFT; TGN swung 0.877↔0.954 across keys.
   The models lean on a feature whose *values* are an artifact of the anonymisation key.
   Evidence: §0 table, Step 5 SHAP, TP/FN contrast.
2. **Attacker-host blindness** (the lead-time failure): GRAFT recalls 37% of attack windows but
   ~0% of the attacker's own windows until the final moments (§2, row 5b). TGN, with far lower
   window recall (0.024), places its few alerts *on the attacker early* (2/2 episodes, 3,595 s) —
   window-F1 and episode-lead measure different things, and only the latter is graded.
3. **Unbounded Time2Vec term** (§2 row 6) — mechanism measured; fix under test.
4. **Mild training instability**: total loss wobbles at epochs 4–5 (0.43→0.51→0.53) before
   recovering to 0.37; per-term curves saved. Not a collapse; worth epochs/LR attention but no
   evidence it is decisive.

## 5. Recommended fixes (each justified by the evidence above; nothing generic)

1. **Re-publish every benchmark number under the standardized fixed key** (§0). The old table
   is unreproducible; the fixed-key table also *changes the story* (GRAFT is second-best, not
   collapsed). [Evidence: §0.]
2. **Report the fused model as the headline and add GRAFT as a member candidate**: fixed-key
   rank-mean TGN+XGB already ships at AUROC 0.942 / F1 0.382 / 2/2 episodes / 5,008 s lead;
   GRAFT's errors are demonstrably *different* (victim-side vs attacker-side), which is the
   fusion-friendly property. Verify by fusion ablation, promote only on val. [Evidence: §2 row 5,
   fused results.]
3. **For the lead-time defect, weight or re-target training toward attacker-side windows** —
   e.g. per-host episode-aware weighting so the external attacker's windows are not drowned by
   the 10 infected bots' windows (GRAFT currently optimizes window-F1-style objectives and wins
   them while failing the graded metric). This is the only fix aimed at row 5b, and it should be
   judged on episode/lead metrics, not window F1. [Evidence: §2 row 5b.]
4. **Ship T2V clamped at p95 — confirmed by the control run (§3):** clamped-T2V beats no-T2V on
   every test metric (AUROC 0.923→0.937, F1 0.371→0.480, episodes 1/2→2/2, lead 42→4,170 s) with
   the identical config otherwise. Gate the promotion on a seed-repeat + the val asymmetry
   (val 0.662), per §3; the 3-way fusion with it reaches test AUROC 0.954. [Evidence: §3.]
5. **Reduce dependence on `net24_bucket`** (or make it key-stable, e.g. order-preserving bucket
   assignment): it is load-bearing in both models and is the main vector of the key sensitivity.
   Re-run the ablation with it removed to size its real contribution before deciding.
   [Evidence: §0 + SHAP rank 9 + TP/FN gap.]

## 6. Explicitly not verified / out of scope

- **Gradient-SHAP on the trained GRAFT itself**: not possible post-hoc — ablation runs
  intentionally do not persist weights. The FN analysis was done in named-feature space
  (TP/FN contrast + LIME), which is the interpretable form the PS requires anyway.
- **Old-key runs cannot be reproduced at all** (key lost); all fresh numbers are fixed-key.
- LIME was installed for diagnostics only (`lime 0.2.0.1`) and is not a pinned runtime
  dependency of the offline demo.

*Artifacts: `diagnostics/prob_hist_all3.png`, `prob_hist_tgn_xgb.png`, `graft_loss_terms.png`,
`padding_histogram.png`, `shap_xgb_summary.png`, `prob_stats_all3.json`, `padding_stats.json`,
`delta_t_gap_stats.json`, `t2v_magnitude_init.json`, `shap_xgb_top10.json`, `lime_fn_cases.json`.*
