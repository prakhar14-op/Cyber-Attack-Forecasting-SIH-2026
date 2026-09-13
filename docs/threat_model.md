# Threat model — an adaptive adversary

The rest of the docs assume the attacker behaves like the one in the dataset. This document
assumes the attacker has **read this repository**, which for an NTRO deployment is the realistic
assumption: the feature list, the payload bin edges, the window geometry and the FPR-budget
thresholding policy are all in committed config files (`configs/data.yaml`, `configs/eval.yaml`).
The fitted threshold values themselves live in gitignored artefacts — but a budget of 1 % of
benign host-windows tells an attacker what it needs to know.

Every "cheap" claim below was **measured against this repo's own extractor**
(`data/packet_features.py` under `configs/data.yaml`), not asserted — and every figure in §3 comes
out of the probe below. Two of the rows (§3.1's jittered stack, §3.4's randomised sweep) are
draws from a pseudo-random generator, so they are only meaningful if the seed and the frame that
produced them are pinned. Both are, here: paste this into `python` from the repo root and you get
the tables in §3.1–§3.4 digit for digit. Change the seed and the magnitudes hold while the third
decimal moves — that is the point of the measurement, not the digits.

You do not have to take that on trust, and neither does the build:
`tests/test_threat_model_figures.py` extracts the block below from this file, runs it, and
compares its output against every row of the §3.1–§3.4 tables at the precision printed here. If
`data/packet_features.py` or `configs/data.yaml` changes what these features mean, the figures
stop reproducing and the suite fails instead of the document quietly going stale.

```python
# Reproduces every figure in threat_model.md §3. Repo root, project venv.
import numpy as np, pandas as pd
from configs import load_config
from data import packet_features as PF

cfg = load_config("data")           # 15 s windows / 5 s stride, committed payload bin edges
LAYOUT = list(PF._PACKET_LAYOUT)    # the per-packet column order the extractor emits
rng = np.random.default_rng(1337)   # the ONE generator every randomised row below draws from,
                                    # in the order the script runs: TTL, TCP window, port sweep

def frame(n, **override):
    """n packets from one host: 500 B payloads on a stock stack (TTL 64, win 64240)."""
    cols = dict(
        ts=np.arange(n) * 0.01,
        src_ip=np.full(n, 3232235777, "uint32"), dst_ip=np.full(n, 3232235778, "uint32"),
        src_port=np.full(n, 40000, "uint16"), dst_port=np.full(n, 80, "uint16"),
        protocol=np.full(n, 6, "uint8"), ttl=np.full(n, 64, "uint8"),
        tcp_win=np.full(n, 64240, "uint16"), is_frag=np.zeros(n, "uint8"),
        payload_len=np.full(n, 500, "uint32"), is_retrans=np.zeros(n, "uint8"),
        syn=np.zeros(n, "uint8"), ack=np.ones(n, "uint8"), fin=np.zeros(n, "uint8"),
        rst=np.zeros(n, "uint8"), psh=np.zeros(n, "uint8"), urg=np.zeros(n, "uint8"),
    )
    cols.update(override)
    return pd.DataFrame(cols)[LAYOUT]

def w0(f):
    """The window_id == 0 row of each feature family, for one synthetic frame."""
    p, s = PF.packet_window_features(f, cfg), PF.sent_window_features(f, cfg)
    return p[p.window_id == 0].iloc[0], s[s.window_id == 0].iloc[0]

# 3.1 — a stock stack, then an attacker that jitters only its own TTL and TCP window
for name, f in [
    ("stock   ", frame(200)),
    ("jittered", frame(200, ttl=rng.integers(32, 65, 200).astype("uint8"),
                            tcp_win=rng.integers(8192, 65536, 200).astype("uint16"))),
]:
    p, s = w0(f)
    print(f"3.1 {name}  ttl_mean={p.ttl_mean:.3f}  ttl_var={p.ttl_var:.3f}  "
          f"tcp_win_var={p.tcp_win_var:.4g}  sent_bytes={s.sent_bytes}")

# 3.2 — the same payload bytes re-chunked across the published bin edges
for name, n, size in [("30 x 1400B", 30, 1400), ("90 x  466B", 90, 466)]:
    p, s = w0(frame(n, payload_len=np.full(n, size, "uint32")))
    print(f"3.2 {name}  bytes={s.sent_bytes}  "
          f"hist={[int(p[f'payload_hist_{i}']) for i in range(8)]}")

# 3.3 — the same 300 packets, burst over 3 s vs paced over 45 s
for name, span in [("burst 3s ", 3.0), ("paced 45s", 45.0)]:
    s = PF.sent_window_features(frame(300, ts=np.linspace(0.0, span, 300, endpoint=False)), cfg)
    print(f"3.3 {name}  windows={len(s)}  peak_pkts={int(s.sent_pkts.max())}  "
          f"peak_bytes={int(s.sent_bytes.max())}")

# 3.4 — 100 ports over 100 hosts, ascending then randomised by the same generator
hosts = np.arange(3232235778, 3232235878, dtype="uint32")
ports = np.arange(1, 101, dtype="uint16")
for name, p_order in [("ascending ", ports), ("randomised", rng.permutation(ports))]:
    p, _ = w0(frame(100, dst_port=p_order, dst_ip=hosts))
    print(f"3.4 {name}  sequential_port_ratio={p.sequential_port_ratio:.3f}  "
          f"port_entropy={p.port_entropy:.3f}  distinct_dst_ports={p.distinct_dst_ports}")
```

## 1. Assumed attacker capability

| Tier | Capability | Assumed? |
|---|---|---|
| A | Controls the traffic it originates — timing, packet sizes, header fields, port order | **Yes** |
| B | Knows the feature set and the published config (public repo, Apache-2.0) | **Yes** |
| C | Can rent infrastructure in an arbitrary /24 | **Yes** |
| D | Can inject traffic into the *training* capture, or edit the label source | **Yes — see §4** |
| E | White-box gradient attacks on the weights | No — out of scope, stated rather than defended |
| F | Compromise of the sensor host or the ledger HMAC key | No — a host-security problem, not a model problem |

We do **not** claim robustness against a tier-A/B adversary. We claim we know which features they
own.

## 2. Which features the attacker controls

The authoritative list is `data/windows.py:feature_columns` — 17 packet-statistic fields, 11
window-bounded sent-side fields, then 2 static role features, 30 in total. The split by *who
controls the value* is a different cut of the same 30, and it is not subtle. (Two unrelated 17s,
so read the labels: the code's 17 is the packet-statistic *family*; the 17 below is how many
features an attacker can set for free, and it draws from both families.)

**Attacker-controlled — free to set, no cost to the attack (17).**
`ttl_mean`, `ttl_var`, `tcp_win_mean`, `tcp_win_var`, `syn_win_mean`, `frag_flag_count`,
`payload_hist_0…7`, `sequential_port_ratio`, `port_entropy`, `server_port_ratio`.

`server_port_ratio` belongs here, and the reason is worth stating because the name invites the
opposite reading. It is **not** a role feature: it is a window-bounded sent-side field
(`configs/data.yaml` → `packet_features.sent_fields`) computed by
`packet_features.sent_window_features` as `px["is_server_src"] = px["src_port"].isin(server_ports)`
— the share of the host's **own source ports** that sit in the configured server-port list. A host
chooses its own source port for free, so this is as writable as the TTL field. (A same-named
quantity exists in `anonymize.role_features`, but that is not the code path that feeds the 30
features; see §3.5 for what moving it buys the attacker.)

**Attacker-controlled at a cost in time or reach (11).**
`sent_bytes`, `sent_pkts`, `distinct_dst_ips`, `distinct_dst_ports`, the flag counts
(`syn`/`ack`/`fin`/`rst`/`psh`/`urg`), `retransmission_count`.

**Costly to fake — the attacker must actually not do the thing.**
The objective itself: to brute-force credentials you must send attempts; to scan a subnet you
must touch distinct hosts; to exfiltrate 50 MB you must move 50 MB. Lowering these is not
evasion, it is a slower attack — the only defensible property this system has.

**Not attacker-controlled, but not defensive either (2).**
Exactly two: `internal` and `net24_bucket`. `_ROLE_FEATURES` in `data/windows.py` is that pair and
nothing else — the only static, IP-derived features in the matrix, computed from the real address
by `data/anonymize.py` before the host key is replaced by its pseudonym.
`net24_bucket` is `HMAC-SHA256(key, "net24:" + the /24 prefix) mod 256` (`n_net24_buckets: 256`)
— the bucket follows the prefix, so it is **re-rolled by renting a VPS in a different /24**, at
the cost of one hosting invoice. It is also load-bearing: removing it costs
XGBoost 0.080 AUROC (`tier1_hardening_report.md` Part 3), so part of the published ranking rests
on a value an attacker can change for a few dollars.

## 3. Cheap evasions (measured)

**3.1 Header fields are free.** 200 packets, identical payloads, only the IP TTL and TCP window
field jittered by the sender:

| | `ttl_mean` | `ttl_var` | `tcp_win_var` | bytes sent |
|---|---|---|---|---|
| stock stack (TTL 64, win 64240) | 64.000 | **0.000** | 0 | 100,000 |
| attacker randomises its own stack | 47.400 | **88.970** | 2.886e8 | 100,000 |

The first row is deterministic. The second is one draw at the pinned seed — a different seed moves
the third decimal and leaves the conclusion untouched, which is why the seed is in the snippet:
the claim is "zero becomes large for free", not "88.970".

Zero cost, zero change to what was accomplished. The PS mandates six packet-feature families
(TTL + variance, TCP window, fragment flags, payload-size distribution, port-scan signature,
retransmission counts); this alone makes two of them attacker-writable, and §3.2 and §3.4 take
two more.

**3.2 The payload histogram is defeated by re-chunking — and the bin edges are published.**
`payload_hist_bin_edges: [0, 64, 128, 256, 512, 1024, 1460, 8192]` is a committed config value.
Bin 5 is `[1024, 1460)` and bin 3 is `[256, 512)`, so splitting each 1400 B write into three
466 B writes moves **100 % of the histogram mass from bin 5 to bin 3** with the same bytes
delivered:

| | bytes | `payload_hist_[0..7]` |
|---|---|---|
| 30 × 1400 B | 42,000 | `[0,0,0,0,0,30,0,0]` |
| 90 × 466 B | 41,940 | `[0,0,0,90,0,0,0,0]` |

**3.3 Pacing thins every per-window aggregate.** Features are window-bounded by design
(decision 003) — which also means every one of them is a *rate*. The same 300 packets, paced 15×:

| | windows touched | peak `sent_pkts`/window | peak `sent_bytes`/window |
|---|---|---|---|
| burst, 3 s | 3 | 300 | 150,000 |
| paced, 45 s | 11 | **100** | **50,000** |

The operating threshold is a fixed quantile of *per-window* benign scores
(`eval/metrics.py:threshold_at_fpr`, fitted on validation). An attacker who divides its rate by
*N* divides its per-window evidence by roughly *N* while the threshold stays put. `capture/`
already contemplates this — scenario 5 is `nmap -T1` explicitly to measure lead-time degradation
— but **that capture has not been recorded, so the degradation curve is TBD.**

**3.4 The scan-signature feature is a single nmap flag.** 100 ports, same 100 destinations:

| | `sequential_port_ratio` | `port_entropy` | `distinct_dst_ports` |
|---|---|---|---|
| ascending (`nmap -r`) | **1.000** | 6.644 | 100 |
| randomised (nmap default) | **0.040** | 6.644 | 100 |

Both rows reach the same 100 hosts on the same 100 ports, and `port_entropy` cannot tell them
apart. As in §3.1 the randomised row is one draw at the pinned seed: the residual is whatever
handful of accidental +1 steps the permutation leaves (here 4 of 99), so read it as "collapses to
near zero", not as 0.040 exactly.

`sequential_port_ratio` additionally counts only **ascending +1** steps (known limitation,
decision 002), so a descending sweep scores 0 without any randomisation at all.

**3.5 Mimicry in the other direction — and it is free.** `server_port_ratio` is the share of a
host's own source ports that fall in `anonymisation.server_ports` (`configs/data.yaml`), a list
that includes 443. An attacker raises it by sourcing its C2 from 443 — one socket option, no
change to the campaign — which is the §2 classification in concrete form. C2 over 443 is standard
practice anyway. Unlike §3.1–§3.4 this row is **reasoning, not a measurement**: we have not run
the system against TLS-wrapped or domain-fronted C2, and the dataset's bot traffic is not that.

## 4. Training-data and label poisoning — the open gap

The integrity machinery is real but it points the wrong way. `scripts/verify_weights.py` hashes
the *outputs* of training — its `TRACKED` list is exactly `engine_model.json`,
`engine_model_flow.json`, `tgn_encoder.pt`, `graft.pt`, `window_scaler.pkl` — and the engine
refuses to write a ledger record on a digest mismatch. **Nothing in this repo hashes a training
input.** There is no digest over the raw pcaps, over the interim parquet in
`interim_dir/<date>/{flows,packets}/`, over `data/splits.yaml`, or over
`data/attack_timeline.yaml`; every other hashing site in the tree serves pseudonymisation
(`data/anonymize.py`), the ledger itself, or the released-weight check.

That matters more here than in a typical pipeline because of where the labels come from:

- **100 % of stage labels derive from one hand-authored YAML.** `data/timeline_labels.py`
  builds every label from `data/attack_timeline.yaml`; flows assembled from pcap are written with
  `label: "unlabeled"` by `assemble_flows` in `data/packet_features.py`, and the dataset's own
  `Label` column is never a training target. So the label set is a ~90-line file, editable
  without breaking any test, hash or digest.
- **A one-character edit to `utc_offset_hours: 4`** moves every attack interval an hour off the
  traffic it is meant to mark, silently relabelling attack windows benign. The offset is a
  measured quantity (`docs/decisions/002`) documented only in a YAML comment, and no test asserts
  that a labelled interval intersects traffic from its declared hosts.
- **Poisoning does not need file access.** A tier-D attacker who was *present on the network
  during the capture window* gets their traffic labelled by whichever interval and host set the
  timeline names — and the host rule is attacker ∪ victim, so traffic to a listed victim is
  labelled attack regardless of who sent it.

Consequence to state plainly: **a ledger entry proves which weights scored a window; it proves
nothing about what those weights were trained on.** Closing this is a small change (digest the
timeline, the split file and the interim parquet manifest into the same `weights.sha256` record)
and it is on `docs/roadmap.md`; it is not done.

## 5. What is actually expensive for the attacker

Honest short list:

1. **Being slower.** Pacing defeats the per-window threshold, but a 15× slower campaign is a 15×
   longer exposure window, and lead time is measured against attack *completion*.
2. **Contacting fewer hosts.** `distinct_dst_ips` and `distinct_dst_ports` are the two features
   an attacker cannot lower without narrowing the attack itself.
3. **Bulk egress.** `sent_bytes` over a window has a floor set by the data volume. Re-chunking
   moves the histogram but not the sum.
4. **Error decorrelation.** The fused model's members key on different things (Spearman ρ = 0.050
   on test, `tier1_hardening_report.md` #6), so a single-feature evasion is unlikely to move both
   — but this has not been measured under evasion and is an argument, not a result.

## 6. Residual risk

- No adaptive-adversary evaluation has been run. There is **no evasion benchmark, no adversarial
  retraining, and no robustness number** in this repository. Everything in §3 is a feature-level
  demonstration on synthetic packets, not an end-to-end attack against the deployed scorer.
- The published lead-time result is n = 2 episodes of **one** attacker host running unmodified
  bot tooling (`tier1_hardening_report.md` → Limitations & Confidence). It is not evidence about
  an attacker who is trying to avoid us.
- Detection at the operating point is carried by the XGBoost member — a gradient-boosted model on
  attacker-influenced tabular features — not by the temporal-graph component.
- The system is a **forecasting and audit layer, not a control**. It cannot block, and an
  operator who acts on it acts on a ranked alert, not a verdict.
