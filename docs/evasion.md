# Evasion bench — what each evasion costs, measured beside what it buys

`docs/threat_model.md` §3 argues that several of our features are cheap to defeat, and measures
that on hand-built synthetic frames. This document runs the same adversary end to end on a real
capture: parse `app/assets/synthetic_demo.pcap` with the production extractor, rewrite the
packets the **attacker** originates, re-extract every feature through the unmodified
`data/packet_features.py`, and infer the stage with `engine/predict.py`'s own rules.

Both halves are reported on purpose. A table of features collapsing to zero is a self-own unless
it also says what the attacker paid for that. Randomising your own TTL is free. Pacing a campaign
15× means running it for 15× as long against a defender who is still watching. §3 prices each
one; §5 is the other direction — what did **not** move, and why moving it means not doing the
attack.

Every figure in §3 is the output of the block below. Paste it into `python` from the repo root
and you get the tables digit for digit; `tests/test_evasion.py` extracts this block from this
file, runs it, and compares its output against every row, so if `data/packet_features.py`,
`configs/data.yaml` or `eval/evasion.py` changes what these numbers mean the suite fails instead
of the document quietly going stale. That is the same guard
`tests/test_threat_model_figures.py` puts on the threat model, sharing its comparison helpers.

```python
# Reproduces every figure in evasion.md §3. Repo root, project venv.
# Equivalent CLI: python -m eval.evasion --pcap app/assets/synthetic_demo.pcap --format probe
from configs import load_config
from eval import evasion

cfg = load_config("data")          # 15 s windows / 5 s stride, committed payload bin edges
result = evasion.run(              # seed defaults to configs/data.yaml `seed` (1337)
    "app/assets/synthetic_demo.pcap", cfg=cfg,
)
print("\n".join(evasion.probe_lines(result)))
```

## 1. What is measured, and what is not

**The transform is applied to the per-packet table, not to a hand-written pcap.**
`extract_packet_table` parses the capture; a transformation then rewrites the timestamp, TTL,
TCP window, destination port or payload length of the attacker's own packets — every one of them
a field that attacker's stack writes. Everything after that is production code called unmodified:
`packet_window_features`, `sent_window_features`, `engine.predict._infer_stage`.

**That the rewritten packets are sendable is checked, not assumed.**
`eval/evasion.py:write_packet_table_pcap` re-emits a transformed table as a real pcap and
`verify_round_trip` parses it back and requires identical features;
`tests/test_evasion.py::test_a_transformed_table_survives_a_pcap_round_trip` runs that check, and
`python -m eval.evasion --pcap … --write-pcap DIR` runs it for all eight variants. So "the
attacker could have sent this" is a property the tool fails on rather than a claim the document
makes.

**The attacker is whoever the capture's operator log says it is.** No address is hardcoded:
`eval/evasion.py` reads `app/assets/synthetic_demo.operator-log.txt` through
`capture.label_capture.parse_operator_log` — the same parser the labelling path uses — or takes
`--attacker`. Only packets whose **source** is an attacker are rewritten; a victim's replies are
not the attacker's to shape.

**The capture is synthetic and illustrative.** `app/assets/README.md` says so and it stays true
here: `synthetic_demo.pcap` is hand-authored, deterministic traffic, not evaluation data. What
§3 measures is how this repo's *features and stage rules* respond to an adaptive sender. It is
**not** a robustness number, and no AUROC or F1 delta appears anywhere in this document.

**Three things this bench does not do.** It does not score through the trained model (§4). It
does not re-train under attack, so there is no adversarial-training result. And it does not
search for the best evasion — the seven variants are the ones `docs/threat_model.md` predicted,
run to see whether the prediction held.

## 2. The capture and the attacker

`app/assets/synthetic_demo.pcap`, 5,620 packets, two attacker hosts declared by the operator log:

| host | role | `internal` | phases it originates |
|---|---|---|---|
| `203.0.113.7` | external attacker | 0 | recon sweep (800 ports), SSH brute force |
| `10.20.0.10` | victim, then pivot | 1 | lateral sweep (200 ports), bulk outbound transfer |

`10.20.0.10` appears on both sides of the kill chain: it is the victim of the first two phases and
the origin of the last two. Everything it sends is rewritten, including the HTTP it served before
it was compromised — once an attacker owns a box it owns that box's stack.

The seven variants and the primitives they apply:

| variant | primitives, in order |
|---|---|
| `port_random` | permute destination-port order within each of the attacker's own sockets |
| `pace_5x`, `pace_15x` | stretch the attacker's inter-packet timing, anchored at its first packet |
| `pad_payload` | re-chunk payloads above bin 3 into the fewest equal chunks landing in `[256, 512)` |
| `ttl_random` | draw the attacker's own IP TTL from `[32, 65)` |
| `win_random` | draw the attacker's advertised TCP window from `[8192, 65536)` |
| `combined` | all of the above, with `pace_15x` |

## 3. Results (measured)

Capture `app/assets/synthetic_demo.pcap` — 5,620 packets parsed, attacker hosts `203.0.113.7`
and `10.20.0.10`, seed 1337.

**3.1 What the evasion costs on the wire.** Attacker-sent packets only.

|  | span (s) | packets | bytes delivered | reach (dst,port) | connections |
|---|---|---|---|---|---|
| `baseline` | 389.960 | 5,480 | 4,257,060 | 1,081 | 1,581 |
| `port_random` | 389.960 | 5,480 | 4,257,060 | 1,081 | 1,581 |
| `pace_5x` | 1949.800 | 5,480 | 4,257,060 | 1,081 | 1,581 |
| `pace_15x` | 5849.400 | 5,480 | 4,257,060 | 1,081 | 1,581 |
| `pad_payload` | 389.960 | 11,480 | 4,257,060 | 1,081 | 1,581 |
| `ttl_random` | 389.960 | 5,480 | 4,257,060 | 1,081 | 1,581 |
| `win_random` | 389.960 | 5,480 | 4,257,060 | 1,081 | 1,581 |
| `combined` | 5849.400 | 11,480 | 4,257,060 | 1,081 | 1,581 |

Read the last three columns first. **Bytes delivered, reach and connections are identical in
every row** — the campaign moved the same 4,257,060 bytes over the same 1,581 connections to the
same 1,081 (destination, port) pairs no matter what was done to it. That is the control: any row
where they moved would be a *different* attack, and the cost of the evasion would have been paid
in the objective rather than in seconds. `connections` is there because `reach` alone is too
weak to be that control — a port permutation scoped to a whole peer rather than to one socket
holds `reach` exactly while shuffling one phase's ports into another's, which the stage rules
then misread. That was found by widening the scope and watching the reach assertion hold; the
guard is `tests/test_evasion.py::test_every_evasion_delivers_the_identical_campaign`. What
changed is the first column. Five of the seven variants are free — same span, same
packets. `pad_payload` costs 6,000 extra packets (three chunks for each 1,400 B write) and no
time. Pacing costs exactly what it says: `pace_15x` turns a 6.5-minute campaign into a
97-minute one.

**3.2 What it buys in the features.** Attacker host-windows only; `ttl_var` / `tcp_win_var` /
`sequential_port_ratio` are the maximum over those windows.

|  | windows | ttl_var | tcp_win_var | sequential_port_ratio | peak sent_pkts | peak sent_bytes |
|---|---|---|---|---|---|---|
| `baseline` | 80 | 0.000 | 0 | 1.000 | 750 | 1,050,000 |
| `port_random` | 80 | 0.000 | 0 | 0.111 | 750 | 1,050,000 |
| `pace_5x` | 353 | 0.000 | 0 | 1.000 | 150 | 210,000 |
| `pace_15x` | 916 | 0.000 | 0 | 1.000 | 50 | 70,000 |
| `pad_payload` | 80 | 0.000 | 0 | 1.000 | 2,250 | 1,050,000 |
| `ttl_random` | 80 | 140.290 | 0 | 1.000 | 750 | 1,050,000 |
| `win_random` | 80 | 0.000 | 4.24e+08 | 1.000 | 750 | 1,050,000 |
| `combined` | 916 | 218.688 | 5.145e+08 | 0.077 | 150 | 70,000 |

`ttl_var` and `tcp_win_var` go from exactly zero to large for free, which is `threat_model.md`
§3.1 confirmed on a real capture rather than on 200 constructed frames.
`sequential_port_ratio` collapses from 1.000 to 0.111 for the price of one nmap flag, which is
§3.4 confirmed. Pacing divides every rate: `peak sent_bytes` falls 1,050,000 → 70,000 at 15×
while the number of windows the attacker occupies rises 80 → 916, because the same campaign now
spans fifteen times as much of the window grid.

That last pair is worth dwelling on. Pacing does not make the attacker disappear; it makes each
window quieter and the campaign longer. Against a **fixed per-window threshold** that is a win.
Against anything that accumulates across windows it is the opposite of a win, and this repo does
not have that detector — `configs/data.yaml`'s `stage_rules` note and
`tests/test_engine.py::test_paced_randomised_scan_evades_the_stage_rules` already say so.

**3.3 The payload histogram.** Summed `payload_hist_0..7` over the attacker's windows; every
packet falls in exactly 3 windows (15 s / 5 s), so these are three times the packet counts.

|  | bytes delivered | payload_hist_[0..7] |
|---|---|---|
| `baseline` | 4,257,060 | `[7200,0,0,240,0,9000,0,0]` |
| `port_random` | 4,257,060 | `[7200,0,0,240,0,9000,0,0]` |
| `pace_5x` | 4,257,060 | `[7200,0,0,240,0,9000,0,0]` |
| `pace_15x` | 4,257,060 | `[7200,0,0,240,0,9000,0,0]` |
| `pad_payload` | 4,257,060 | `[7200,0,0,27240,0,0,0,0]` |
| `ttl_random` | 4,257,060 | `[7200,0,0,240,0,9000,0,0]` |
| `win_random` | 4,257,060 | `[7200,0,0,240,0,9000,0,0]` |
| `combined` | 4,257,060 | `[7200,0,0,27240,0,0,0,0]` |

`payload_hist_bin_edges: [0, 64, 128, 256, 512, 1024, 1460, 8192]` is a committed config value,
so an attacker who read this repository knows where the walls are. The exfiltration phase's
3,000 × 1,400 B writes sit in bin 5; splitting each into three lands them in bin 3. **100 % of
the bin-5 mass moves from bin 5 to bin 3**, the bin-3 count goes 240 → 27,240, and bytes
delivered is unchanged to the byte (the split is exact: 1,400 = 467 + 467 + 466). The histogram
feature family sees a completely different distribution for traffic that carried identical
content to an identical destination.

The price is in §3.1 and §3.2: 6,000 more packets, and `peak sent_pkts` triples 750 → 2,250. Any
detector keyed on packet *count* rather than payload size sees the re-chunking clearly. Ours is
not, at this operating point — `impact_sent_pkts_gt: 500` was already exceeded at baseline.

**3.4 The stage the rules infer.** Windows per stage, in `configs/data.yaml` order:
`benign, recon, initial_access, lateral_movement, c2, exfiltration, impact, unclassified`.

|  | stage windows |
|---|---|
| `baseline` | `[0,14,0,29,0,14,0,23]` |
| `port_random` | `[0,13,0,10,0,14,0,43]` |
| `pace_5x` | `[0,58,0,132,0,62,0,101]` |
| `pace_15x` | `[0,170,0,151,0,178,0,417]` |
| `pad_payload` | `[0,14,0,29,0,14,0,23]` |
| `ttl_random` | `[0,14,0,29,0,14,0,23]` |
| `win_random` | `[0,14,0,29,0,14,0,23]` |
| `combined` | `[0,0,0,0,0,178,0,738]` |

Four readings, and the third is the one that matters most:

1. **Neither free header trick moves the stage at all.** `ttl_random`, `win_random` and
   `pad_payload` leave `[0,14,0,29,0,14,0,23]` untouched. They defeat *features* — three of the
   six packet-feature families the problem statement mandates — without defeating the *rules*,
   because no stage rule reads TTL, TCP window or the payload histogram. Those features are
   attacker-writable and currently load-bearing only for the trained model, whose response is
   §4's TBD.
2. **`port_random` alone is not enough, and neither is `pace_15x` alone.** Randomising the port
   order kills `sequential_port_ratio` but `scan_distinct_dst_ports_gt: 20` still fires on an
   800-port sweep, so recon survives at 13 windows. Pacing 15× drops the sweep to ≤ 15 distinct
   ports per window — under that threshold — but the ports are still *ascending*, so
   `scan_sequential_port_ratio_gt: 0.5` fires instead, and recon is reported in 170 windows. Each
   rule covers the other's blind spot. Only doing both silences them.
3. **`combined` erases recon and lateral movement entirely, and exfiltration survives.** Under
   the full evasion the rules call 0 windows `recon`, 0 `lateral_movement`, and still **178**
   windows `exfiltration`. The evaded windows report `unclassified` — "no rule matched" — not a
   confident wrong stage, which is the behaviour `engine/predict.py` was fixed to have.
4. **Everything the attacker bought was in stage granularity, not in silence.** 738 of the
   `combined` windows are `unclassified` rather than absent. Whether the trained model still
   alerts on them is exactly the question §4 cannot answer here.

Invariants held by every variant above: bytes delivered 4,257,060, reach 1,081 and connections
1,581 are unchanged.

## 4. Model-score effects — TBD

**Not measured, and not zero.** Scoring these captures through the deployed engine needs
`artifacts/engine_model.json` and `artifacts/window_scaler.pkl`, which are gitignored (README's
release-download step) and absent from a fresh clone. `eval/evasion.py:model_scoring_status`
prints which file is missing rather than filling the column, so a run on a machine without the
weights cannot be mistaken for a run that found no effect.

With the artifacts present, this is the command:

```bash
python -m eval.evasion --pcap app/assets/synthetic_demo.pcap --write-pcap run/evasion
python -c "from engine import predict; \
  print({n: predict.predict_file(f'run/evasion/{n}.pcap', out_dir=f'run/evasion/{n}')['n_alerts'] \
         for n in ('baseline', 'combined')})"
```

`--write-pcap` verifies each written capture re-parses to the same features before it is scored,
so an alert-count delta cannot come from the writer. Until someone runs it, every model-score
figure in this repository under evasion is **TBD**.

Two further gaps, stated rather than glossed: there is no adversarial *retraining* result, and
`tier1_hardening_report.md`'s error-decorrelation argument (Spearman ρ = 0.050 between the fused
members) has never been measured **under** evasion, so it remains an argument.

## 5. What survives — the expensive half

The point of the exercise is which features an attacker cannot cheapen, and §3 measured three.

**1. Volume. `sent_bytes` is the only feature that carried a stage through the full evasion.**
Under `combined` — 15× pacing, randomised ports, re-chunked payloads, randomised TTL and window —
`peak sent_bytes` is still 70,000 per window against `exfiltration_sent_bytes_gt: 50000`, and
the rule fires in 178 windows. The arithmetic is in §3.2: the baseline peak is 1,050,000, so
pacing divides it by the factor and the rule only goes quiet once the factor passes
1,050,000 / 50,000 = 21. Measured: at 21× exfiltration still fires, at **22×** every stage rule
in this capture goes silent. That is the price list. Hiding this transfer costs a 22× longer
transfer, and the reason is not clever feature engineering — it is that the attacker has to move
the bytes. Re-chunking moved the histogram (§3.3) and did not move the sum by one byte.

**2. Reach. `distinct_dst_ips` and `distinct_dst_ports` are invariant under all seven variants
by construction.** §3.1's `reach` column is 1,081 in every row, and that is not a property of
our features being clever — it is the definition of the attack. To scan fewer ports you must
scan fewer ports; to reach fewer hosts you must reach fewer hosts. `scan_distinct_dst_ports_gt`
survived `port_random` (13 recon windows) for exactly this reason and only fell to *pacing*,
which lowers the per-window count without lowering the campaign's reach. A detector that
accumulated distinct ports across windows instead of within one would not have been evaded here
at all. We do not have one; that is the finding, and it is on `docs/roadmap.md` as a sequential
cross-window detector rather than presented as a defence we already have.

**3. Completing the intrusion.** You cannot brute-force credentials without sending attempts,
pivot without touching the pivot, or exfiltrate 4 MB without moving 4 MB. Every "evasion" in §3
that is free is free precisely because it touches something the attack does not need: a TTL
field, a window field, a chunk boundary, a port ordering. The moment a transformation reaches the
objective — fewer bytes, fewer hosts, fewer attempts — the attacker has partly defended us.

**What survives is therefore a short list, and an honest one:** volume, reach, and the fact of
the attack happening. Three of the six packet-feature families the problem statement mandates
(TTL and variance, TCP window, payload-size distribution) are attacker-writable at zero cost,
measured in §3.2 and §3.3, and the port-scan signature is one nmap flag. Those four are evidence
about an attacker who is not trying, not about one who is. A defence that has looked at its own
evasion surface and says which half is load-bearing is worth more than one that has never
looked — but the half that is load-bearing here is smaller than the feature list suggests, and
the useful consequence is where detection effort should go: cross-window accumulation, not more
header statistics.

## 6. Reproducing this document

```bash
python -m eval.evasion --pcap app/assets/synthetic_demo.pcap            # §3's tables
python -m eval.evasion --pcap app/assets/synthetic_demo.pcap --format probe
python -m eval.evasion --pcap app/assets/synthetic_demo.pcap --format json
python -m eval.evasion --pcap app/assets/synthetic_demo.pcap --write-pcap run/evasion
pytest tests/test_evasion.py -q                                         # pins every figure above
```

`--pcap` takes any capture with an operator-log sidecar, or pass `--attacker <ip>` directly.
`--seed` overrides the generator behind `port_random` / `ttl_random` / `win_random`; the
magnitudes in §3.2 hold across seeds and the third decimal moves, which is why the seed is
printed with the report.
