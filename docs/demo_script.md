# Demo script — 2 minutes (M12.4)

Shot list for the submission video. Timings match the app's **actual** behaviour
(`app/streamlit_app.py`); nothing here is aspirational. Rehearse once with the network
physically off — that is the point.

**This file is the performance. The pre-flight and post-flight are
[`docs/recording_checklist.md`](recording_checklist.md)** — exact machine state, which artifact
lane you are on and what that forbids you from saying, the anchor you must publish *before*
filming, and the frame-by-frame check afterwards. Read it first; nothing below is safe to record
until it passes.

**Setup before recording** — two lanes, and **which one you are on changes what you may say**.

```
$env:SIH26_HMAC_KEY   = "..."            # both are mandatory and have no defaults (.env.example)
$env:SIH26_LEDGER_KEY = "..."

# PUBLISHED lane — needs the extracted dataset (~12.7 GiB) and a training run:
python -m engine.train_engine            # fits + persists model, threshold, weight digests
python scripts/verify_weights.py         # -> OK (published lane)

# DEMO lane — a bare clone, no dataset, no released weights:
python scripts/bootstrap_demo_artifacts.py
python scripts/verify_weights.py --artifacts-dir artifacts_demo    # -> OK (demo lane)

streamlit run app/streamlit_app.py
```

`python scripts/verify_weights.py` with no argument checks the **published** lane and exits 1 with
`MISMATCH: weights.sha256 ...` when `artifacts/` is absent — which is the normal state of a clone
that has never trained. That is not a failure to work around; it is the command telling you which
lane you are about to record. On the demo lane the app prints a standing disclosure over every
number on the page, and the narration below has to change with it: see the checklist.

Disconnect Wi-Fi / unplug Ethernet **before** starting the recording, and say so on camera.

---

### 0:00–0:15 — The claim (title card + terminal)

> "This forecasts network attacks *before* they finish. Not a flow classifier: it scores a **host
> over a window**, and the problem statement's graded metric is **lead time**. Where the model
> actually earns its place is **ranking quality** — it transfers to an attack family it never
> trained on, and we will show you both numbers. And it runs with the network physically
> disconnected."

Do **not** open with "the metric that matters is lead time" and stop there. At our alert budget
lead time does not separate from a matched-budget random baseline (our own audit measured it;
`JUDGES.md` Part 3), so a first sentence that rests the whole system on lead time is the one claim
in this video a judge can knock down with our own document.

Show `pytest tests/ -q` finishing and **read the pass/skip line off the screen** — do not
rehearse a number, the count moves with the suite and with what is bootstrapped on the
recording machine (skips are gated on the trained artifacts, the dataset and tshark). Then
`python -m tests.smoke`, which prints one line in exactly this form — read the numbers off
the screen, do not rehearse them:

```
smoke: <n> flows -> <k> forecasts, ledger_verified=True, <elapsed>s
```

**`python -m tests.smoke` runs inside a socket kill-switch. The pytest run does not** — `no_network`
in `tests/conftest.py` is an opt-in fixture with no autouse, and only a named handful of tests
request it. An earlier revision of this line said "both run with sockets blocked", which is the
suite-wide offline claim the audit retracted (`docs/INSTALL.md`, `JUDGES.md` Part 2b). On camera,
say it about the smoke run and about the network cable — never about the suite.

### 0:15–0:35 — Input and forecast timeline

Click **Demo: synthetic PCAP (full features)** — the bundled capture, which exercises the full
30-feature packet path. (**Demo: sample CSV (flow only)** is the flow-only path; the app warns
honestly when a CSV lacks packet-level data.) Point at the four metrics: flows, host-windows,
alerts, and the **threshold fitted from a 1 % false-positive budget**, not hardcoded.

**On the demo lane that last sentence is false and the app will contradict you in frame.** The
fourth metric is then labelled `Threshold (1% FPR — DEMO model)`, a caption under the row says the
budget was fitted over the *synthetic capture's own* benign windows, and a standing warning above
the metrics says every number on the page came from the demo model. If that is the lane you are
recording, say instead: *"this threshold is fitted from a false-positive budget rather than
hardcoded — on this machine it is fitted over the bundled synthetic capture, and the page says so;
the published operating point is in the architecture document."* Checklist step P2 is where you
establish which lane you are on, before a camera is running.

What a correct run looks like — hosts, stages and the operator log they should match — is in
`app/assets/expected_output.md`. Check the render against it before recording.

If the capture contains frames the IPv4 packet path cannot read, a banner under the metrics
says how many and why. A capture the parser never saw must not render as "0 alerts, all clear".

Then the timeline: probability per window, the red threshold line, stage-coloured points.

> "The score is the maximum over hosts in each window. The threshold comes from a false-positive
> budget on validation data — we never hand-tuned it."

### 0:35–1:00 — Why this host (the explainability beat)

Pick the top host in the triage table. Show the explanation panel. The picker is labelled
**Host (real address — only the ledger stores keyed pseudonyms)**: the forecasts carry the
address an analyst has to act on, and the pseudonymisation happens in the ledger, not here.

> "Every alert is explained in **named features** — payload-size distribution, packet counts,
> distinct destinations — never embedding dimensions. Black-box output is not acceptable for
> this problem, so we made it impossible: a test fails the build if an explanation returns an
> index instead of a feature name."

Point at the **top contributing windows** (when the attack was forming, seconds before the
alert), the MITRE technique, and the flagged-flows table underneath.

If a judge asks why a byte count reads negative: the `value (z-score)` column is the feature
standardised against the training mean and σ — the scale TreeSHAP attributes over. Say so; the
column is labelled for it and the panel carries the caveat. The *names* are real features.

### 1:00–1:20 — The result, and which row of it you are looking at

Scroll to section 6, "Benchmark results (read from `results/`, never hardcoded)".

**There may be no table there.** `panels.forecast_horizons()` and `panels.results_card()` read
`results/*.json`, which is gitignored; on any machine that has not run `eval/`, section 6 renders
`BENCHMARK_EMPTY_HINT` and nothing else. That is correct behaviour — the panel refuses to print a
placeholder figure — but it is not a beat you can narrate over. Checklist step P6 makes you look at
this section during the dry run and decide *then* whether this beat is a live table or a cut to
`docs/architecture.md` §4 on screen. Do not discover it with the camera running.

**Read the four figures below off `docs/architecture.md` §4 on the morning of the shoot and write
them onto the card you are reading from.** They are NOT printed here on purpose: that table is
being regenerated under a new anonymisation key and an ablation may move the F1 and recall columns,
so a number memorised from this file is a number that can be stale on camera. The checklist's
pre-flight step P7 is the check that they match.

> "This is the result. What you just watched is the **deployed engine — a single gradient-boosted
> model**, and it is the **XGBoost row** of this table: `<AUROC_xgb>` on a *bot* day it has never
> seen, trained on brute-force and DoS days. The logistic regression on the **identical feature
> matrix** is at `<AUROC_lr>`. That gap is the claim: temporal host-window dynamics transfer
> across attack families, static flow signatures do not. The higher fused row — `<AUROC_fused>` —
> is an **evaluation-side** model. It is not what ran just now, and engine-side fusion is roadmap;
> the table says so in its own words. On the graded metric, lead time, the horizon-0 classifier
> flags **both** episodes, median `<median_lead>` — and we will not sell you that number, because
> at this alert budget it does not separate from a matched-budget random baseline; our own audit
> measured that. Forecasting *forward*, k windows ahead, ranks better than chance but fires **0 of
> 2 episodes at every horizon we report** — a ranking capability with no working operating point,
> and we say so rather than show you a curve. Two caveats out loud: two sessions of one attacker
> host is not a distribution, and the detection is carried by the gradient-boosted member, not by
> the graph encoder."

Three things that must not be said here, each because a document in this repo contradicts it:
the fused row is **not** what the demo just ran; the k-step head has **no supported
forward-forecast horizon**; and lead time must never leave your mouth without the random-baseline
sentence attached to it.

### 1:20–1:45 — The ledger (the integrity beat)

Ledger panel: records, **chain verifies: yes**, **anchored: yes**.

Click **Tamper with record 0**, then **Re-verify** → the app turns red and names the exact
record index.

> "Every forecast is hash-chained and Merkle-committed. Edit one record and the verifier names
> it. Rewrite the whole chain to be self-consistent and it still fails, because the head no
> longer matches the anchored checkpoint. No raw IP ever enters the ledger — `append`
> replaces the host with a keyed-HMAC pseudonym — and the engine refuses to write at all if
> the model weights' SHA-256 doesn't match."

Cut to a terminal and verify that chain independently, offline. **Use the path the app is
showing you, not `run/audit_chain.jsonl`.** The Streamlit app writes each session's ledger into a
fresh temporary directory — `app/streamlit_app.py::_session_dir` is
`tempfile.mkdtemp(prefix="sih26-run-")`, created once per browser session — and section 5 prints
the exact command for *that* directory in a copyable code block right under the three ledger
metrics. Copy it from the screen:

```
python -m ledger.verify_cli <the path in section 5's code block>/audit_chain.jsonl
```

An earlier revision of this line said `run/audit_chain.jsonl`. On a machine with no `run/` that
verifies nothing and exits 2 with `NO CHAIN`; on a machine that happens to have one, it verifies a
**different chain from the one on screen**, which is worse, because it looks like it worked.

**Before filming, and before any judged run: publish the anchor — from that same session
directory.**

```
python scripts/anchor_checkpoint.py <the path in section 5's code block>/audit_chain.jsonl
```

It prints a `SIH26-ANCHOR` line and a six-group spoken digest. Read the digest aloud on camera,
or write the anchor line somewhere outside the run directory.

The chain has to exist before it can be anchored, so the order is: start the app → run the
analysis once → read the path off section 5 → anchor → *then* roll camera. Do not restart the app
between anchoring and filming: a new browser session is a new temp directory and an empty chain,
and the anchor you published commits to a chain that is no longer the one on screen. Checklist
steps P5 and P8 walk this in order.

This is not ceremony: truncating
the chain **and** its checkpoint log together leaves two files that agree with each other, and
nothing inside them records that the run continued — so that one attack is closed only by an
anchor published outside them. Saying so on camera is stronger than claiming a completeness the
ledger does not have.

### 1:45–2:00 — Honesty close

> "One thing we won't hide: the recurrent world model we planned **failed its own acceptance
> gate** — zero episodes detected. We recorded it as a negative result and shipped the encoder
> that actually works. Three kill-chain stages have no public data at all, so we report no numbers
> for them. Everything you saw the app do regenerates from a script — the published *table* does
> not, because the dataset is 12.7 gigabytes and we say so in JUDGES.md rather than pretend
> otherwise."

The qualifier in that last sentence is load-bearing. "Everything you saw regenerates from a script"
is false the moment a figure from `docs/architecture.md` §4 has been on screen: `results/*.json` is
gitignored and `JUDGES.md` Part 2b states plainly that reproducing a published number is not
available to a judge **or to us** without the extracted dataset.

End on `docs/limitations.md` open on screen.

---

**Do not** claim a live blockchain (it is a tamper-evident ledger with anchored checkpoints —
deliberately, so the demo runs air-gapped), a validated 7-class classifier, or any metric on
`recon`, `lateral_movement` or `exfiltration` — **three** stages, not two. This line named only two
of them until now, which is the same error `docs/limitations.md` §1 records having already
corrected in the slides and in itself: understating a limitation is the same defect as overstating
a result. All three have zero labelled windows.

The honesty *is* the differentiator; every claim above is backed by a test, a results file, or a
document named beside it.
