# Deployment

Who runs this, where it sits, what it costs to run, and — §5 — how many alerts it actually
produces. Every number is cited to the file that measures it; where no measurement exists the
value is **TBD** with the experiment that would produce it.

## 1. Operator and placement

The intended operator is a **SOC or network-monitoring team inside a closed environment** — the
NTRO framing of SIH26153 — not a cloud-managed service. The shape follows from CLAUDE.md's hard
constraints (fully offline, file input, offline ledger verification), not from preference.

```
 core / distribution switch
        │  SPAN / mirror port  (or a passive optical TAP)
        ▼
 sensor host ── capture ──► pcap on local disk ──► extractor ──► engine ──► ledger
 (CPU only, no network)                                                      │
                                                                    verify_cli (offline)
```

- **Passive, out-of-band.** The sensor receives a copy of traffic from a SPAN/mirror port or a
  TAP. It is not inline, has no failure mode that drops production traffic, and cannot block —
  it is a forecasting and audit layer, stated plainly in `docs/threat_model.md` §6.
- **File-driven by design.** The PS requires file input (PCAP or CSV); the engine's entry point
  is `predict.predict_file(...)`, so the sensor's job is to roll captures and hand files to the
  engine. This also means the analysis host and the capture host can be **different machines**,
  with the capture moved across an air gap, if a site prefers that.
- **Feed it a PCAP.** A CICFlowMeter CSV physically cannot carry the packet-level features the PS
  mandates; the engine runs a reduced flow-only model on CSV and warns (`docs/limitations.md` §3).

## 2. Hardware

**CPU-only and offline by design**, not by shortfall: no GPU at inference, no runtime model
download, no telemetry. The development machine ran `torch 2.14.0+CPU`
(`tier1_hardening_report.md` header) and the deployed scorer is a **single XGBoost model**, chosen
partly because it is CPU-cheap and natively TreeSHAP-explainable (`docs/architecture.md` §3).

Measured on the development laptop, not a server:

| Quantity | Measured | Source |
|---|---|---|
| Extractor throughput | **71–110k packets/s** | `docs/decisions/002` |
| Peak RSS, worst member | **4.4 GB** on a 4.3 GB pcapng (18.9M packets); every other member ~2 GB | `docs/decisions/002` |
| End-to-end demo path | 1,000 flows → features → forecast → explanation → ledger → offline verify in **~9 s** | `docs/architecture.md` §5 |
| Offline install | wheel-house `pip install --no-index --find-links vendor -r requirements.txt`, built by `scripts/build_vendor.ps1` on a connected machine | `README.md` "Offline setup" |

Sizing guidance, offered as guidance: an 8-core x86 host with **16 GB RAM**, plus disk for the
retention window, clears every figure above with headroom — the 4.4 GB peak is the worst single
member in the corpus. Windows hosts need the short-path caveat in `README.md`.

## 3. How many hosts one sensor covers

Honest arithmetic from the repo's own measurements, and then the caveat that matters.

The four-day corpus is **~52.8M packets across 136 per-host capture members**
(`docs/decisions/002`), i.e. ~388k packets per host-day, or **~4.5 packets/s per host** averaged
over a day. Against the measured 110k packets/s extractor rate that is a headline ratio of
~24,000 hosts per sensor.

**Do not put that number on a slide.** It is an upper bound from a single offline batch-parse
benchmark and it ignores: scoring cost, capture-side packet loss at the NIC, burstiness (the DoS
member carried 105k flows in one attack window — `docs/decisions/002`), and the fact that a
mirror port delivers an aggregate stream rather than neat per-host files. The dataset network is
~450 hosts (`docs/decisions/001`: 449 archive members, one per capture host), so **a single
sensor covering a ~450-host segment is well inside the measured envelope** and is the size we
would actually claim.

**The real sustained figure is TBD.** The experiment that produces it: run the extractor on a
live mirror at increasing offered load and record the rate at which capture drops appear —
possible on the M11 lab kit (`capture/capture.sh`), not yet run.

## 4. Offline is the feature, not the compromise

For a classified or air-gapped environment the offline property inverts from limitation to
requirement:

- **No egress path for telemetry.** No cloud APIs, no runtime model downloads, Streamlit usage
  reporting explicitly disabled (`docs/architecture.md` §5). Exactly what the suite enforces,
  because the distinction matters:
  - **Enforced.** `python -m tests.smoke` wraps its whole pipeline run in `network_disabled()`
    (`tests/smoke.py` → `tests/net_guard.py`), which makes every socket primitive raise. Exactly
    three *tests* opt into the same guard through the `no_network` fixture. Naming the third by
    its file would overstate it — `tests/test_app.py` holds dozens of tests and only one of them
    asks for the fixture — so they are named individually:
    - `tests/test_offline.py::test_inference_and_ledger_verify_run_end_to_end_with_sockets_blocked`
      — which additionally asserts the guard *bites* before running inference and offline ledger
      verification end to end
    - `tests/test_smoke.py::test_full_pipeline_on_1000_flow_fixture_offline_under_60s`
    - `tests/test_app.py::test_pipeline_and_panels_work_offline` — this one test, not the app
      suite around it

    Check it rather than trusting it: `grep -rn no_network tests/` lists every opt-in (plus the
    fixture's own definition in `tests/conftest.py`), and `pytest tests/test_app.py
    --collect-only -q` shows how much of that file is *not* among them.
  - **Not enforced.** `no_network` (`tests/conftest.py`) is an ordinary opt-in fixture with no
    `autouse`, so the rest of `pytest tests/ -q` runs with sockets available. The suite does not
    prove the whole codebase is offline; those four runs prove the *demo path* is.
  - **Gated on artefacts.** All three of those tests and the smoke runner need the trained engine
    (`artifacts/`, gitignored), so on a bare checkout they skip or fail loudly rather than
    silently passing — on a checkout with no `artifacts/`, `python -m tests.smoke` exits on a
    `FileNotFoundError` naming the missing `artifacts/engine_threshold.json`, and the three tests
    skip. Build the artefacts first if you want the offline claim checked rather than skipped.
- **No raw identifiers at rest.** Hosts enter the ledger as keyed-HMAC pseudonyms; the key lives
  only in the operator's environment, so an exported ledger is unlinkable without it
  (`ledger/ledger.py`). No raw IP or payload reaches the model or the chain.
- **A third party can verify without joining the network.** `python -m ledger.verify_cli` checks
  the chain, the Merkle roots and the anchored checkpoints with no connectivity — which is why a
  live blockchain push was deliberately scoped out (BUILD_PLAN M9): a chain that needs a network
  call to verify defeats the deployment it is meant to serve.
- **Provenance is enforced, not documented.** The engine refuses to write ledger records when a
  weight file's SHA-256 does not match `artifacts/weights.sha256`, so a record cannot claim
  provenance it does not have. The converse gap — nothing hashes the *training inputs* — is
  stated in `docs/threat_model.md` §4 and tracked in `docs/roadmap.md` §1.9.

## 5. Alert volume — the number nobody has published

**The published rate is per host-day, and the multiplication has never appeared in a pitch
document. Here it is.**

Take the rate for the model that would actually be deployed. The engine runs **XGBoost**, and
`README.md` reports **246.6 alerts/host/day** for it at the 1 % FPR budget.
`docs/benchmark_protocol.md` is explicit that this is normalised per *host*-day and that "a
whole network's daily alert volume is this rate times the number of hosts". The dataset's network
is ~450 hosts. So:

> **246.6 × 450 ≈ 111,000 alerts/day** — about **4,600/hour**, or **~77/minute**, continuously.

That is not a reviewable queue, and no model choice rescues it: the eval-side fused row is
187.1/host/day (**≈ 84,000/day**) and even the logistic-regression baseline is 112.3
(**≈ 50,500/day**). It is the arithmetic consequence of a 1 % false-positive budget applied to a
5-second stride: a host produces 17,280 windows/day (`docs/benchmark_protocol.md`), and 1 % of
that is ~173 before any model skill is involved.

**Mitigations the system actually has:**

1. **The 0.1 % budget is already implemented and configured — and never published.**
   `configs/eval.yaml` sets `fpr_budgets: [0.001, 0.01]`; the harness fits a threshold at both
   (`eval/harness.py`), `engine/train_engine.py` persists both, and `engine/predict.py` accepts
   `fpr_budget` as a parameter. Every table in `README.md`, `docs/architecture.md` and
   `docs/slides.md` publishes **only** the 1 % column. The 0.1 % operating point is a
   configuration change, not a code change. Its alert volume should fall roughly 10× — to the
   order of 8,000/day at ~450 hosts — but **the actual 0.1 % rate, and the recall and lead time
   it costs, are TBD**: they are produced by `python scripts/make_ablation_table.py --budget
   0.001`, which requires `results/*.json` and has not been published.
2. **Rank, don't gate.** The engine emits a probability, a stage, top-5 named features and the
   contributing windows per alert, so the queue is orderable by score rather than consumed
   first-in-first-out. Alerts are also written to the ledger for after-the-fact audit regardless
   of whether an analyst opened them.
3. **The graded metric is not queue-shaped.** Lead time is measured from the *first* alert on an
   attacking host, so the operating question is "did the host rise" — a per-host trend — not
   "did an analyst read 111,000 tickets".

**Mitigation the system does not have: alert coalescing.** There is no incident-grouping,
deduplication or suppression logic anywhere in this repository. Consecutive windows on one host
during one episode each raise their own alert. The measured firing rate on the test day, quoted
with the attribution the source gives it: **XGBoost alone fires on 19.3 % of ep1's windows**
(`tier1_hardening_report.md` → Limitations & Confidence #2) — which is the relevant number here
because the deployed engine *is* the single XGBoost model (§2). The same report's episode-level
audit puts the attacker host at **18.3 % once the attack starts**, against 0.9 % during its 2.8 h
idle gap between sessions ("What the sanity-check did rule out"). Neither figure is a property of
the fused headline model. Coalescing per
(host, episode) is the obvious first reduction and would likely cut the volume by orders of
magnitude, but **it is not implemented, so we quote no number for it.** It is `docs/roadmap.md`
§1.6.

One further honesty note carried from `docs/benchmark_protocol.md`: benign traffic was subsampled
to ~30 of ~450 hosts/day (decision 001), so the per-host rate is a within-sample rate. The ×450
extrapolation above assumes the unsampled hosts behave like the sampled ones — reasonable, but
unverified.

## 6. Updating an air-gapped deployment

Retraining is **scheduled batch, never online** (CLAUDE.md forbids auto-retraining at inference),
so updates are a discrete, auditable event rather than a drift:

1. Train on the connected side. `python -m engine.train_engine` fits the model, the FPR-budget
   thresholds and the scaler, then `python scripts/verify_weights.py --record` writes
   `artifacts/weights.sha256`.
2. Publish the artefacts with their SHA-256s (GitHub Release on the open side; any signed medium
   on a closed one). The digests are also in `README.md`.
3. Carry the artefacts across the air gap on removable media, along with the wheel-house
   (`vendor/`) if dependencies moved.
4. On the sensor, `python scripts/verify_weights.py` before anything runs. **The engine refuses
   to write ledger records on a digest mismatch**, so a mis-transferred or tampered model fails
   closed rather than silently scoring.
5. The ledger chain continues across the update; the weight digest recorded with each batch is
   what ties a historical alert to the model version that produced it.

What this does **not** cover: a site with no connected side at all cannot retrain, and the
model's training corpus stays whatever was last carried in. Federated retraining is the intended
answer and is explicitly not built (`docs/roadmap.md` §3).
