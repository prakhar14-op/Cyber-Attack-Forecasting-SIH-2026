# Benchmark protocol (M4.2)

How every number in the ablation table is produced. All metrics are computed by
`eval/metrics.py` and emitted by `eval/harness.py`; nothing is hand-entered.

## Unit and target

- **Unit of prediction:** `(source_host, window)` — a 15 s window on a 5 s stride,
  per source host. Never per-flow, never whole-network.
- **Binary target:** `attack = stage != benign`. At forecast horizon `k`, the target
  for window `t` is the attack label of the same host's window `t+k` (`k=0` = nowcast,
  used by the M4 baselines; the world model reports `k=1,4,8`).
- **Features:** the 30 window-bounded features in `artifacts/feature_names.json`
  (decision 003). Every model trains and is scored on this identical matrix — the PS's
  requirement for the graded LR baseline.

## Splits and anti-leakage

- Day-wise (`data/splits.yaml`): train = 14-02+16-02, val = 28-02, test = 02-03. Whole
  attack episodes stay inside one split.
- The feature scaler is fit on **train only**; the operating threshold is fit on
  **validation** benign host-windows; both are reused unchanged on test.
- With 4 attack days the splits are attack-**family-disjoint** (train: bruteforce+DoS →
  `initial_access`,`impact`; val/test: infiltration,bot → `c2`). So the headline result
  is the **binary infiltration forecast generalising across families**; multi-class stage
  metrics are reported only where a stage is present in both train and the eval split.

## Operating point

Chosen from a **false-positive budget** on validation benign host-windows, never a fixed
threshold. Budgets: **0.1 %** and **1 %** of benign host-windows. `threshold_at_fpr` picks
the lowest threshold whose benign FPR ≤ budget (maximising recall within the budget).

The budget **names** the operating point; it is not what a model did on the split it is
scored on. The table therefore carries an `FPR_achieved` column beside it — the false-
positive rate actually reached there (`fpr` in the results JSON). Two rows sharing the
"1 % FPR" heading can sit at several-fold different alert volumes, and only that column
shows it, so rows differing in `FPR_achieved` are not being compared at equal cost.

## Lead time — the metric that defines success

> **Lead time = (annotated attack completion) − (time of the first alert on the
> attacking host), in seconds.**

- The attacking host is the attacker IP(s) from `data/attack_timeline.yaml` (external/
  NAT'd attackers appear as sources inside the victims' captures, so they have
  host-windows to alert on). Completion is the attack's end time, converted to UTC with
  the measured +4 h offset.
- The "first alert" is the earliest fired host-window on that attacker with
  `start − grace ≤ time ≤ completion`. Positive lead time = flagged before completion.
- **Undetected episodes are never dropped from the median.** They contribute
  `metrics.lead_time_undetected_seconds` (configs/eval.yaml), which is **0** in the shipped
  configuration. A model with high F1 but zero lead time has failed the problem statement.
- Reported as the **median** across episodes, plus episodes-detected / total. The IQR is
  reported **only from `metrics.min_episodes_for_quantile_band` episodes up** (8 in the
  shipped configuration); below it `eval/ablation.py` prints the literal per-episode
  seconds (`lead_each_s`) instead and `eval/plots.py` omits the band. Both reported splits
  carry exactly **2** attacker episodes — val 28-02 and test 02-03 each list one attacker
  IP over two sessions in `data/attack_timeline.yaml` — so in every shipped run the band is
  suppressed and the per-episode values are what you read. A quartile over 2 points is
  interpolation between the only two order statistics there are, and a missed episode
  enters it as a 0 s edge, so it would read as a dispersion nobody measured.

**Horizon caveat.** 15 s windows on a 5 s stride overlap; window `t` and `t+3` are the
first fully-disjoint pair, so only `k ≥ 3` strides ahead are genuinely future. The
meaningful lead-time horizons (`k=4`,`k=8`) are overlap-clean; `k=1` is reported as
known-optimistic (a near-nowcast).

## Uncertainty on the headline numbers

Two episodes is a small population, and the rows behind them are not independent: one
external attacker is a source inside several victims' captures, so a single logical
host-window contributes several correlated rows. `eval/harness.py` therefore reports AUROC
and F1-at-budget with a **cluster bootstrap** (`eval/uncertainty.py`) that resamples whole
`(attacker-host, episode)` groups, never rows — row resampling would divide the real
variance by roughly the cluster size and print an interval too narrow to be honest.
Resample count and level are `metrics.bootstrap_resamples` / `metrics.bootstrap_ci_level`
(configs/eval.yaml), the seed is the file's top-level `seed`.

The intervals land in the results JSON as `auroc_ci` and `f1_ci` next to their point
estimates, each recording `n_groups`, `n_resamples` and `n_usable`. A resample that is
degenerate (one class only) is dropped, not scored by convention, so `n_usable` below
`n_resamples` says how few effective clusters carry the interval. An interval the bootstrap
refuses outright — fewer than two clusters, a degenerate full sample — is written as
`{"unavailable": <reason>}`; there is no substituted bound to mistake for a measurement.

**Coverage, stated exactly.** The intervals are written by `eval/harness.py`'s `evaluate()`,
so they are present for the models it runs itself (`--model lr | xgb | lstm | tgn |
tgn_graft`). `eval/fused.py`, `eval/forecast.py` and `eval/world.py` assemble their own
result blocks and **do not carry intervals yet** — their AUROC/F1 are point estimates only.
Read an absent `auroc_ci` as "not computed for this run", never as "no uncertainty".

## Honest disclosures

- **Alerts/day is per HOST-day, not per network-day.** The `alerts_per_host_day` metric
  normalises the alert count by the observed *host*-time (alert count ÷ host-days, where a
  host-day = 17280 windows at the 5 s stride), so it is invariant to how many hosts were
  sampled. A whole network's daily alert volume is this rate **times the number of hosts** —
  a 450-host network sees ~450× the tabled figure. Read the column as "alerts a single host
  raises per day", never as an operator's total daily load.
- **Benign subsampling.** Per decision 001, ~30 benign hosts/day were fetched
  (`dataset.benign_hosts_per_day`, seed `dataset.host_sample_seed = 1337`), not the full
  ~450. Because the metric is per-host-day (above), the reported rate is a within-sample
  host rate, not a full-network projection.
- **Our features are CICFlowMeter-like, not byte-identical** to the published CSVs — the
  LR baseline runs on our matrix, which is the same matrix every model uses (what the PS
  grades).
- Known dataset label errors (Liu et al. 2022) — we do not chase the last 0.5 % of F1. See
  [dataset_quality.md](dataset_quality.md) for the bibliography, which defects actually reach
  this pipeline, and the labelling risk specific to our own timeline-derived labels.

## Metrics reported per model

F1 / precision / recall at each budget, beside the `FPR_achieved` that budget actually
reached · AUROC · ECE (+reliability data) · median lead time, with the literal per-episode
seconds and an IQR only above the episode cutoff · alerts/host-day · episodes detected ·
cluster-bootstrap intervals for AUROC and F1-at-budget. Generalisation: `--holdout-family`
retrains with one attack family removed from train (M4.6).
