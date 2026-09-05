# 003 — Window features must be window-bounded (M3 leakage fix) — 2026-09-05

**Status: implemented.** Found by the M3 adversarial audit workflow BEFORE any model
trained on the features. This is exactly the "if lead time looks too good, assume leakage
first" scenario CLAUDE.md warns about — caught at the data layer, not after fabricating a
result.

## The bug (critical)

The first `data/windows.py` built each window's flow-level features (bytes, packets, TCP
flags, duration) by aggregating **whole-flow totals** and attributing them to the window
containing the flow's **start** timestamp. But flows split only on a 120 s idle gap
(`flows.timeout_seconds`), so a single flow routinely spans far more than one 15 s window —
its entire lifetime's totals were dumped into the start window.

Because the unit is `(source_host, window)` and the model forecasts windows t+1…t+8, this
injected **forecast-horizon traffic into window t's own feature vector**: the model could
"forecast" an attack whose bytes it had already summed. Measured on the real extracted data:

- 7–13 % of flows have duration > 15 s; 7–12 % exceed the full 40 s (K=8) horizon; some
  persistent connections run > 30,000 s.
- **64–94 % of all byte volume** is carried by flows longer than one window.

So the majority of the traffic-volume signal summarised future traffic. This would have
inflated F1 and — critically — the **lead-time metric that defines success**. The existing
`test_no_future_leakage` could not catch it: it perturbs the model-input tensor and checks the
encoder's causal mask; the leak was baked into the features *upstream* of the encoder, which a
perfectly causal encoder then faithfully propagates.

## The fix

Every window feature is now **window-bounded**: it summarises only packets whose own
timestamp falls in `[w*stride, w*stride+window_seconds)`, exactly like the packet-statistic
features already did.

- New `data.packet_features.sent_window_features` computes, per `(src_ip, window_id)`, the
  window-bounded sent-side aggregates: `sent_bytes, sent_pkts, syn, ack, fin, rst, psh, urg,
  syn_win_mean, server_port_ratio, distinct_dst_ips`. Bin-composed for bounded memory on the
  flood day; pinned equal to a direct reference implementation by a test, plus a test that a
  long flow's bytes never accumulate into a single window.
- `data.windows.build_window_features` no longer aggregates flows at all — it reads the
  enriched packet-window parquet and adds two **static, IP-derived** role features
  (`internal`, `net24_bucket`). `server_port_ratio` moved from a leaky whole-day role
  aggregate (audit finding #2) to the window-bounded sent feature above.
- Dropped the whole-flow features entirely (`flow_fwd_bytes`, `flow_duration_*`, `flow_iat_*`,
  and `flow_init_win_*` — the last also corrupted by averaging over the −1 missing sentinel,
  audit finding #3). The SYN window-size fingerprint survives as the window-bounded
  `syn_win_mean`.

Feature count: 40 (leaky) → **30 (all window-bounded)**. All four days re-extracted; the
window-level scaler (M4) fits on the corrected matrix.

## Minor audit fixes folded in

- Timezone label corrected: February Atlantic time is **AST (UTC−4)**, not ADT (UTC−3). The
  measured +4 h offset was always right; only the name was wrong.
- `label_windows` now fails loudly if handed pseudonymised hosts (enforces label-before-
  pseudonymise), and `build_window_features` plumbs `split` into `pseudonym()` so held-out-
  attacker eval actually re-domains identities.

## Known items recorded, not fixed (audit-rejected or deferred)

- **k=1/k=2 forecasts are near-nowcasts.** 15 s windows on a 5 s stride overlap; window t and
  t+3 are the first fully-disjoint pair, so only k≥3 strides ahead are genuinely future. The
  meaningful lead-time horizons (k=4, k=8) are overlap-clean; k=1 is reported as known-
  optimistic. Formalised in `benchmark_protocol.md` (M4).
- **`net24_bucket` is a near-lossless /24 identifier.** CLAUDE.md lists "/24 bucket" as a
  wanted node feature, so it stays, but it is the anti-memorisation weak point (the attacked
  victim subnet is stable across splits). The primary mitigation is the per-epoch node-id
  permutation (M5); revisit if M5/M7 numbers look identity-driven.
  **Verified empirically at M4:** XGBoost's cross-family generalisation (0.895 test AUROC) is
  driven by behavioural, window-bounded features — `payload_hist_0` (0.54), `sent_pkts`
  (0.25), `ttl_mean` (0.05); `net24_bucket` ranks 5th at importance 0.028, not load-bearing.
  So the strong baseline is not an identity artefact. Kept as a minor feature; if any later
  model's importance shifts onto it, drop it.
