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

## Lead time — the metric that defines success

> **Lead time = (annotated attack completion) − (time of the first alert on the
> attacking host), in seconds.**

- The attacking host is the attacker IP(s) from `data/attack_timeline.yaml` (external/
  NAT'd attackers appear as sources inside the victims' captures, so they have
  host-windows to alert on). Completion is the attack's end time, converted to UTC with
  the measured +4 h offset.
- The "first alert" is the earliest fired host-window on that attacker with
  `start − grace ≤ time ≤ completion`. Positive lead time = flagged before completion.
- **Undetected episodes count as 0 seconds — never dropped from the median.** A model
  with high F1 but zero lead time has failed the problem statement.
- Reported as **median with IQR** across episodes, plus episodes-detected / total.

**Horizon caveat.** 15 s windows on a 5 s stride overlap; window `t` and `t+3` are the
first fully-disjoint pair, so only `k ≥ 3` strides ahead are genuinely future. The
meaningful lead-time horizons (`k=4`,`k=8`) are overlap-clean; `k=1` is reported as
known-optimistic (a near-nowcast).

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
- Known dataset label errors (Liu et al. 2022) — we do not chase the last 0.5 % of F1.

## Metrics reported per model

F1 / precision / recall / FPR at each budget · AUROC · ECE (+reliability data) · median
lead time with IQR · alerts/host-day · episodes detected. Generalisation: `--holdout-family`
retrains with one attack family removed from train (M4.6).
