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

Show `pytest tests/ -q` finishing: **76 passed**, then `python -m tests.smoke` →
`1000 flows -> forecasts, ledger_verified=True, 9.2s`. Both run with sockets blocked.

### 0:15–0:35 — Input and forecast timeline

Click **Use the bundled sample** (or upload a PCAP for full features — the app warns honestly
when a CSV lacks packet-level data). Point at the four metrics: flows, host-windows, alerts, and
the **threshold fitted from a 1 % false-positive budget**, not hardcoded.

Then the timeline: probability per window, the red threshold line, stage-coloured points.

> "The score is the maximum over hosts in each window. The threshold comes from a false-positive
> budget on validation data — we never hand-tuned it."

### 0:35–1:00 — Why this host (the explainability beat)

Pick the top host in the triage table. Show the explanation panel.

> "Every alert is explained in **named features** — payload-size distribution, packet counts,
> distinct destinations — never embedding dimensions. Black-box output is not acceptable for
> this problem, so we made it impossible: a test fails the build if an explanation returns an
> index instead of a feature name."

Point at the **top contributing windows** (when the attack was forming, seconds before the
alert), the MITRE technique, and the flagged-flows table underneath.

### 1:00–1:20 — Forecasting ahead (the headline)

Scroll to the per-horizon table.

> "This is the result. Forecasting **20 seconds ahead**, the model still ranks attacks at 0.895
> AUROC and catches **both** attack episodes about 65 minutes before they complete. Trained on
> brute-force and DoS days — tested on a *bot* day it has never seen. A logistic regression on
> the identical feature matrix is at 0.537: essentially random. Temporal host dynamics transfer
> across attack families; static flow signatures do not."

### 1:20–1:45 — The ledger (the integrity beat)

Ledger panel: records, **chain verifies: yes**, **anchored: yes**.

Click **Tamper with record 0**, then **Re-verify** → the app turns red and names the exact
record index.

> "Every forecast is hash-chained and Merkle-committed. Edit one record and the verifier names
> it. Rewrite the whole chain to be self-consistent and it still fails, because the head no
> longer matches the anchored checkpoint. No raw IP is ever stored — only keyed pseudonyms —
> and the engine refuses to write at all if the model weights' SHA-256 doesn't match."

Cut to a terminal: `python -m ledger.verify_cli run/audit_chain.jsonl` — a judge can verify
independently, offline.

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
