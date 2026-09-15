# Recording checklist — the 2-minute video

[`docs/demo_script.md`](demo_script.md) is the **performance**: what is said, in what order, at what
timing. This file is the **pre-flight and post-flight**: the machine state a take needs in order to
succeed, what has to be in frame at each moment, what to do when a take goes wrong, and how to prove
afterwards that nothing false is on screen. Nothing here repeats the script's narration.

The video is a graded deliverable and it is currently **unrecorded** (`README.md` → Status, M12).
Treat a take as unusable until §X passes, not until it feels good.

Verified on this machine 2026-09-12; every command below was run, and the outputs quoted are the
outputs it produced. Re-run them — the point of the list is that you watch it happen, not that you
trust this file.

---

## §0 · The decision that governs every other line: which artifact lane

The app runs the **same** extractor, scorer, thresholding, explanation panel and ledger on either
lane. That is deliberate (`JUDGES.md` Part 3: a demo on a parallel code path would prove nothing),
and it has a consequence you must internalise before you speak:

> **You cannot tell a demo-lane run from a published run by looking at the numbers.** Only the
> stamped provenance tells you, and it is the presenter's job to read it, not the viewer's.

Establish the lane with one command and write the answer at the top of your shot card.

```
python scripts/verify_weights.py                                  # published lane
python scripts/verify_weights.py --artifacts-dir artifacts_demo   # demo lane
```

Measured here, with `artifacts/` absent and `artifacts_demo/` present:

| command | output | exit |
|---|---|---|
| no argument | `MISMATCH: weights.sha256 (run scripts/verify_weights.py --record) (published lane)` | 1 |
| `--artifacts-dir artifacts_demo` | `OK: all tracked model weights match their recorded SHA-256 (demo lane, …)` followed by a `NOTE:` line saying matching digests say nothing about detection quality | 0 |

| | **PUBLISHED lane** | **DEMO lane** |
|---|---|---|
| Needs | the extracted dataset (~12.7 GiB) + `python -m engine.train_engine` | a bare clone + `python scripts/bootstrap_demo_artifacts.py` |
| Directory | `artifacts/` | `artifacts_demo/` |
| On screen | no provenance warning above the metrics; metric reads `Threshold (1% FPR)` | a standing warning above the first number; metric reads `Threshold (1% FPR — DEMO model)`; a caption under the metric row; marks drawn **inside** the charts |
| You may say | "this is the deployed engine" and name the §4 XGBoost row | **only** "this is the pipeline running"; no probability, alert count, threshold, ranking or lead time on screen is comparable to any published figure |
| You must say | which row of `docs/architecture.md` §4 the run corresponds to | that this model was fitted on the bundled synthetic capture and is scoring its own training data |

**If you record the demo lane and narrate the published numbers, the video is a false claim with a
warning banner visible behind it.** That is the single worst outcome available here.

---

## §P · Pre-flight, in order

Each step has an observable pass condition. Do not proceed past a step that did not produce it.

### P1 — Machine and desktop state
- Close everything that can draw over the window: mail, chat, notifications, update prompts,
  screen-recorder overlays. Turn on Focus Assist / Do Not Disturb.
- Terminal font large enough to read at 1080p when the window is half the screen. Check by
  standing back from the monitor; a judge will watch this on a laptop.
- Browser at 100 % zoom, **no** bookmarks bar, **no** other tabs. The URL bar will be in frame and
  it must read `localhost`.
- Nothing in frame carries a real hostname, a real IP of yours, or a path with your name in it that
  you would not publish. The app's host picker deliberately shows real addresses from the capture
  (that is the analyst-facing design) — those are the bundled synthetic capture's invented
  addresses, which is fine; your own machine's are not.
- **Pass:** a blank desktop, one terminal, one browser window.

### P2 — Lane
- Run both commands in §0 and write the answer on the shot card.
- **Pass:** you can say out loud, without looking anything up, which lane you are recording and
  which sentences from `demo_script.md` that forbids.

### P3 — Environment variables
Both are mandatory and **neither has a default** — the modules raise a `RuntimeError` naming the
variable rather than falling back ([`.env.example`](../.env.example)).

```
$env:SIH26_HMAC_KEY   = "..."     # anonymisation; a REPRODUCIBILITY parameter, not a secret
$env:SIH26_LEDGER_KEY = "..."     # ledger pseudonyms + checkpoint signature; this one IS a secret
```

- `SIH26_LEDGER_KEY` is needed by anything that constructs a ledger: the app's analysis run, the
  ledger card, `scripts/anchor_checkpoint.py`, and `python -m ledger.verify_cli`. **Use the same
  value in the terminal you verify from as in the shell that launched Streamlit**, or the on-camera
  verification fails against a chain it cannot check.
- To reproduce the *published* table you would need the team's `SIH26_HMAC_KEY`, which is not in
  this repository. For a recording, any value works — record which one you used.
- **Pass:** `python -c "import os;print(bool(os.environ.get('SIH26_HMAC_KEY')), bool(os.environ.get('SIH26_LEDGER_KEY')))"` prints `True True` **in the same shell** you will launch the app from.

### P4 — Artifacts
- Demo lane: `python scripts/bootstrap_demo_artifacts.py`, then re-run the demo-lane verify.
- Published lane: `python -m engine.train_engine`, then the no-argument verify.
- **Pass:** the verify for *your* lane exits 0. A `MISMATCH` here is the command telling you the
  lane is not there — it is not noise to record over.

### P5 — Start the app and produce a chain
The app writes each session's ledger into a **fresh temporary directory**:
`app/streamlit_app.py::_session_dir` is `tempfile.mkdtemp(prefix="sih26-run-")`, created once per
browser session. It is **not** `run/`.

1. `streamlit run app/streamlit_app.py`
2. Click **`Demo: synthetic PCAP (full features)`** once. Let it finish.
3. Scroll to **`5 · Audit ledger`** and copy the path out of the code block under the three ledger
   metrics — the app prints the exact `python -m ledger.verify_cli <path>/audit_chain.jsonl`
   command for *this* session.
- **Pass:** section 5 shows `Records` > 0, `Chain verifies` = `yes`, `Anchored to checkpoint` = `yes`.
- **If `Records` is absent or zero:** the run raised no alerts, so no ledger was written. That is a
  real state on the demo lane (`JUDGES.md` Part 3 records the demo model raising **0 alerts on the
  committed 1,000-flow fixture**, measured 2026-09-12). Fix it before filming by choosing an input
  that does alert; do not film a ledger beat with no ledger.

### P6 — Full dry run, watching for the two panels that can be empty
Walk the entire script end to end with the camera **off**, and specifically look at:

- **Section 6, `Benchmark results (read from results/, never hardcoded)`.** It reads
  `results/*.json`, which is gitignored. With no `results/` directory the section renders
  `BENCHMARK_EMPTY_HINT` and a commands block — correct behaviour, and **not a beat you can narrate
  over.** Decide *now* whether the 1:00 beat is a live table or a cut to `docs/architecture.md` §4
  on screen.
- **Section 8, `k-step forecast`.** Its warning is long and it is the most honest thing on the page;
  it also contains figures. If it will be in frame, it goes on the post-flight number list (§X3).
- **Section 5's tamper control** is labelled exactly `Tamper with record 0 (demo)`, beside
  `Re-verify`.
- **Pass:** you have walked every beat, nothing rendered an error card, and you know what each beat
  looks like before the camera sees it.

### P7 — The number card
The results table is **being regenerated under a new anonymisation key**, and an ablation may move
the F1 and recall columns. `demo_script.md` therefore prints no figures in the 1:00 narration and
leaves named slots instead.

- Open `docs/architecture.md` §4 **on the day of the shoot**. Copy the four values into the slots on
  your card: the XGBoost row's AUROC, the logistic-regression row's AUROC, the fused row's AUROC,
  and the median lead.
- Re-read the sentences around that table. If the "which of these ships" paragraph has changed,
  your narration changes with it.
- **Pass:** every number you intend to say aloud exists, today, in `docs/architecture.md` §4, and
  you can point at the line it came from. A number you remember is a number that can be stale.

### P8 — Publish the anchor, before the camera rolls
This has to happen **before** filming and **after** P5, because the chain must exist to be anchored,
and because the whole value of the anchor is that it commits to a state before anyone could have
truncated it.

```
python scripts/anchor_checkpoint.py <the path from P5>/audit_chain.jsonl
```

It prints a `SIH26-ANCHOR count=… head=… root=… sig=…` line and a `spoken digest:` of six
four-character groups. Put the anchor line somewhere **outside the run directory** and **in frame** —
a sticky note, a second terminal, a whiteboard.

- Do **not** restart the app between anchoring and filming. A new browser session is a new temp
  directory and an empty chain, and the anchor you just published commits to a chain that is no
  longer on screen.
- If you re-click the analysis during the take, the chain grows past the anchored count. That is
  fine and it is the intended semantics — say so rather than hiding it: the anchor commits to the
  count the room already heard, and a later truncation contradicts it.
- **Pass:** the anchor line is readable in frame, and you can read the spoken digest aloud without
  stumbling.

### P9 — Network off, visibly
- Unplug Ethernet and turn Wi-Fi off at the adapter, not just at the app. Do it **on camera** if you
  can; it is the problem statement's first hard constraint and it costs three seconds.
- **Pass:** the system tray shows no connectivity, and the app still responds.

### P10 — What you may claim about the tests
- `python -m tests.smoke` runs inside a socket kill-switch. **The pytest run does not** — `no_network`
  in `tests/conftest.py` is an opt-in fixture with no autouse and only a named handful of tests
  request it. Say it about the smoke run and about the unplugged cable; never about the whole run.
- Read the pass/skip line **off the screen**. Do not rehearse a count: it moves with the suite and
  with what is bootstrapped on this machine, and a memorised count is the defect the repo already
  has a guard against.
- **Pass:** your card says "read the counts off the screen" and carries no count.

---

## §F · What must be in frame, beat by beat

Columns: what the viewer must be able to *see*, and what must not be on screen while you say it.

| Beat | Must be visible | Must not be on screen |
|---|---|---|
| 0:00 title | the claim card; the disconnected adapter if you can show it | a cloud login, an "updating" toast |
| 0:00 terminal | the pytest summary line **and** the `smoke: … ledger_verified=True …` line, both readable | any rehearsed count typed into a slide |
| 0:15 input | the button `Demo: synthetic PCAP (full features)` actually being clicked | a file dialog showing your home directory |
| 0:15 metrics | all four metrics, **with the threshold metric's full label** — `Threshold (1% FPR)` or `Threshold (1% FPR — DEMO model)`. The label is the provenance; a crop that cuts it turns a demo figure into a measured one | a crop that shows the number without its label |
| 0:15 provenance | on the demo lane, the warning block above the metric row, **legible, for at least two seconds** | the metrics scrolled into view with the warning scrolled off the top |
| 0:35 explanation | the `Why this host?` panel with **named** features, and the `value (z-score)` column header | the column cropped to hide that it is a z-score |
| 1:00 result | either section 6's live table, or `docs/architecture.md` §4 on screen — whichever P6 decided | a figure you are saying that is not visible anywhere |
| 1:20 ledger | `Records`, `Chain verifies: yes`, `Anchored to checkpoint: yes`; then the same three after the tamper, with the failure naming the record index | the verify command typed with `run/audit_chain.jsonl` instead of the session path |
| 1:20 anchor | the `SIH26-ANCHOR` line, outside the run directory, in frame | the anchor produced *after* the tamper demo |
| 1:45 close | `docs/limitations.md` open | a results table with a number you did not check in P7 |

Two standing rules for the whole take:

1. **Every number you say must be visible somewhere in the same shot.** If you can say it but the
   viewer cannot see it, cut the sentence or cut to the document.
2. **Never crop a provenance label out of a metric.** The label travels with a screenshot; a
   caption underneath does not.

---

## §T · When a take goes wrong

| What happened | Do this |
|---|---|
| You said "the fused model" about what the app just ran | Stop. Re-take. The engine is a single XGBoost model, **not a cascade**, and the fused row is evaluation-side. This is the project's named failure mode; it is not fixable in the edit. |
| You said a lead-time figure without the random-baseline sentence | Stop. Re-take the whole beat. The caveat is not a footnote that can be added later in voice-over; it has to be in the same breath. |
| You said "the suite runs offline" | Stop. Re-take. See P10. |
| A panel rendered an error card | Do not cut around it. Fix it, then re-run P6. A card you scrolled past is a card a judge will pause on. |
| Section 6 was empty and you narrated a table | Re-take with the §4 document on screen instead. |
| The app restarted mid-session | The ledger is a new temp directory and the published anchor is stale. Go back to **P5** and redo P5→P8 in order. |
| A notification appeared | Re-take the beat. Do not blur it in post; a blurred rectangle in a submission video reads as something hidden. |
| The ledger shows `Chain verifies: NO` before you tampered | Stop and diagnose. Most likely `SIH26_LEDGER_KEY` differs between the shell that ran the app and the shell you verified from (P3). |
| You are out of time and tempted to trim a caveat | Trim a *capability* claim instead. The honesty is the differentiator; a 2-minute video that drops a limitation to fit a feature has traded the strongest thing it had. |

Re-take by beat, not by whole video: every beat above is a separate shot, and the script's timings
are per beat.

---

## §X · Post-flight — watch the take with this list, before anyone else sees it

Watch it **once at normal speed for feel**, then again with a finger on the pause key.

### X1 — Read every frame that contains text
Pause on each panel, caption, warning and terminal line that is legible. For each one ask: *is this
sentence true on the lane I recorded?* On the demo lane, a metric label reading `Threshold (1% FPR)`
without `— DEMO model` means the frame came from somewhere else and does not belong in this cut.

### X2 — Transcribe your own narration and check it line by line
Write out what you actually said, not what the script says. Check each sentence against:
- `docs/architecture.md` §4 — which row ships, and the four figures from P7;
- `JUDGES.md` Part 3 — the list of what the project says it cannot let anyone verify;
- `docs/limitations.md` §1 — **three** stages with zero labelled windows (`recon`,
  `lateral_movement`, `exfiltration`), not two.

A sentence that cannot be pointed at a line in one of those files does not ship.

### X3 — The number audit
List every number that appears **in vision or in audio**. For each: which file is it from, and did
you check that file today? Figures rendered by the app itself count — section 8's warning and
section 6's population caveat both carry figures, and they are constants in `app/panels.py`, so they
are exactly as capable of going stale as a slide is. A number you cannot source gets cut.

### X4 — The four sentences that must be present
A take that is otherwise perfect and missing any of these is not usable:
1. Which model actually ran (a single gradient-boosted model), and that the fused row is
   evaluation-side.
2. The population: n = 2 episodes, both sessions of one attacker host.
3. That lead time does not separate from a matched-budget random baseline at this budget.
4. On the demo lane: that the model was fitted on the bundled synthetic capture and is scoring its
   own training data.

### X5 — Independent verification still works after the shoot
```
python -m ledger.verify_cli <the path from P5>/audit_chain.jsonl
```
Expect `OK: … chain intact and anchored to a signed checkpoint` and the anchored count. Compare that
count against the `SIH26-ANCHOR` line you published in P8 — if the take included a re-run, it is
larger, and that is the anchor doing its job. If it is **smaller**, something truncated the chain
and that is the exact attack the anchor exists to expose.

### X6 — Ship the evidence with the video
Keep, in one folder beside the cut: the lane verify output, the `SIH26-ANCHOR` line and spoken
digest, the post-shoot verify output, and the copy of `docs/architecture.md` §4 you read the numbers
off. If a judge questions a figure in the video, that folder is the answer.

---

## Known gaps in this checklist

Stated rather than left to be discovered:

- **The timings in `demo_script.md` have not been measured against a stopwatch on a real take.**
  They are a plan, not an observation, until someone records one.
- **No take exists yet**, so nothing here has been exercised end to end on camera. The commands and
  on-screen strings have been verified on this machine; the *flow* has not.
- **This file cannot tell you whether the published lane behaves as described**, because `artifacts/`
  is absent here. Every published-lane line above is derived from the code and from `JUDGES.md`, not
  from a run.
