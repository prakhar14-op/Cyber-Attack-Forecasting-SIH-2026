# Demo script — 2 minutes (M12.4)

Shot list for the submission video. Timings match the app's **actual** behaviour
(`app/streamlit_app.py`); nothing here is aspirational. Rehearse once with the network
physically off — that is the point.

**Setup before recording**
```
python -m engine.train_engine            # once: fits + persists model, threshold, weight digests
python scripts/verify_weights.py         # should print OK
streamlit run app/streamlit_app.py
```
Disconnect Wi-Fi / unplug Ethernet **before** starting the recording, and say so on camera.

---

### 0:00–0:15 — The claim (title card + terminal)

> "This forecasts network attacks *before* they finish. Not a flow classifier — the metric that
> matters is lead time. And it runs with the network physically disconnected."

Show `pytest tests/ -q` finishing and **read the pass/skip line off the screen** — do not
rehearse a number, the count moves with the suite and with what is bootstrapped on the
recording machine (skips are gated on the trained artifacts, the dataset and tshark). Then
`python -m tests.smoke`, which prints one line in exactly this form — read the numbers off
the screen, do not rehearse them:

```
smoke: <n> flows -> <k> forecasts, ledger_verified=True, <elapsed>s
```

Both run with sockets blocked.

### 0:15–0:35 — Input and forecast timeline

Click **Demo: synthetic PCAP (full features)** — the bundled capture, which exercises the full
30-feature packet path. (**Demo: sample CSV (flow only)** is the flow-only path; the app warns
honestly when a CSV lacks packet-level data.) Point at the four metrics: flows, host-windows,
alerts, and the **threshold fitted from a 1 % false-positive budget**, not hardcoded.

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

### 1:00–1:20 — Forecasting ahead (the headline)

Scroll to the per-horizon table.

> "This is the result. The fused model ranks attacks at 0.933 AUROC and flags **both** attack
> episodes about **49 and 91 minutes before they complete** — at a 1% false-positive budget.
> Forecasting 20 and 40 seconds ahead is verified as a ranking capability at 0.84 AUROC; its
> fixed operating point doesn't fire yet, and we say so. Trained on
> brute-force and DoS days — tested on a *bot* day it has never seen. A logistic regression on
> the identical feature matrix is at 0.573: essentially random. Two caveats we state out loud:
> that's two sessions of one attacker host, not a distribution, and the detection is carried by
> the gradient-boosted member, not the graph encoder. Temporal host dynamics transfer
> across attack families; static flow signatures do not."

### 1:20–1:45 — The ledger (the integrity beat)

Ledger panel: records, **chain verifies: yes**, **anchored: yes**.

Click **Tamper with record 0**, then **Re-verify** → the app turns red and names the exact
record index.

> "Every forecast is hash-chained and Merkle-committed. Edit one record and the verifier names
> it. Rewrite the whole chain to be self-consistent and it still fails, because the head no
> longer matches the anchored checkpoint. No raw IP ever enters the ledger — `append`
> replaces the host with a keyed-HMAC pseudonym — and the engine refuses to write at all if
> the model weights' SHA-256 doesn't match."

Cut to a terminal: `python -m ledger.verify_cli run/audit_chain.jsonl` — a judge can verify
independently, offline.

**Before filming, and before any judged run: publish the anchor.**

```
python scripts/anchor_checkpoint.py run/audit_chain.jsonl
```

It prints a `SIH26-ANCHOR` line and a six-group spoken digest. Read the digest aloud on camera,
or write the anchor line somewhere outside the run directory. This is not ceremony: truncating
the chain **and** its checkpoint log together leaves two files that agree with each other, and
nothing inside them records that the run continued — so that one attack is closed only by an
anchor published outside them. Saying so on camera is stronger than claiming a completeness the
ledger does not have.

### 1:45–2:00 — Honesty close

> "One thing we won't hide: the recurrent world model we planned **failed its own acceptance
> gate** — zero episodes detected. We recorded it as a negative result and shipped the encoder
> that actually works. Two kill-chain stages have no public data at all, so we report no numbers
> for them. Everything you saw regenerates from a script."

End on `docs/limitations.md` open on screen.

---

**Do not** claim a live blockchain (it is a tamper-evident ledger with anchored checkpoints —
deliberately, so the demo runs air-gapped), a validated 7-class classifier, or lead time on
`lateral_movement`/`exfiltration`. The honesty *is* the differentiator; every claim above is
backed by a test or a results file.
