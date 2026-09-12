# Verifying this project

Written for an evaluator who has ten minutes, no trust in our claims, and no intention of taking
a README's word for anything. Everything in Part 1 runs on a **bare clone** — no dataset, no
trained weights, no network. Part 2a also runs on a bare clone and lets you watch the pipeline
execute end to end, on a deliberately worthless model whose worthlessness we make impossible to
forget; Part 2b is what reproducing a published number would take, and it is not available to
you or to us here. Part 3 lists what we cannot currently let you verify, and why; read that one
first if you are short of time, because a project is easier to judge from what it admits than
from what it demonstrates.

## Setup (about two minutes)

```
python -m venv .venv
.venv\Scripts\pip install -r requirements.txt
```

Python 3.12. The offline wheel-house path and the Windows path-length caveat are in
[docs/INSTALL.md](docs/INSTALL.md).

Two environment variables are mandatory and deliberately have no defaults — see
[.env.example](.env.example). For the checks below, any value works:

```
set SIH26_LEDGER_KEY=judge-demo-key
```

---

## Part 1 — what you can check on a bare clone

### 1. The test suite runs

```
.venv\Scripts\python -m pytest tests/ -q
```

Read the pass and skip counts off your own run. We deliberately do not print an expected count
anywhere in the documentation, because a number written in a document goes stale and then it is
a lie — and a test now fails the build if one reappears. The skips are gated on the artifacts and
the dataset, neither of which ships. Which brings us to:

### 2. The project tells you which of its own guarantees are currently unverified

```
.venv\Scripts\python -m pytest tests/test_bootstrap_state.py -q -s
```

A capability-by-capability report: which claims have tests that actually execute on your machine,
and which are unverified because the prerequisites are absent. It never fails — its job is
disclosure. We would rather hand you the list of what you cannot check than have you find it.

### 3. Retracted claims cannot come back

```
.venv\Scripts\python -m pytest tests/test_docs_claims.py -q
```

An internal adversarial audit found three false claims published across the README, the
architecture document and the graded PDF — including a statement about model selection that our
own analysis had already disproved. This guard scans every judge-facing surface for those
sentences and fails if one returns. It is measured rather than asserted: the test inserts each
retired sentence at every paragraph boundary of every scanned file and requires a catch at all of
them.

### 4. The threat model's numbers are executable, not typed

```
.venv\Scripts\python -m pytest tests/test_threat_model_figures.py -q
```

[docs/threat_model.md](docs/threat_model.md) publishes measured evasion costs — what an adaptive
attacker gets for free by randomising their own TTL, or by re-chunking a payload across our
published histogram bin edges. This test lifts the probe out of the document, runs it against the
production feature extractor, and compares every published figure. Change
`data/packet_features.py` and the document fails until it is re-measured.

### 5. The audit ledger, attacked four ways

Build a chain:

```
.venv\Scripts\python -c "from ledger.ledger import Ledger; from pathlib import Path; d=Path('run'); d.mkdir(exist_ok=True); l=Ledger(d/'audit_chain.jsonl', checkpoint_path=d/'checkpoints.jsonl'); [l.append({'host': 'h%d' % i, 'window_start': float(i), 'probability': 0.1*i, 'stage': 'recon', 'technique': 'T1046'}) for i in range(5)]; l.checkpoint()"
.venv\Scripts\python -m ledger.verify_cli run\audit_chain.jsonl
```

> `OK: ... chain intact and anchored to a signed checkpoint`
> `5 records anchored. This proves the two files agree, not that none were deleted ...`

**Edit one record** — change any `probability` value in `run\audit_chain.jsonl` — and re-verify:

> `TAMPERED: ... fails at record 2` · exit 1. It names the index.

**Rewrite the whole chain self-consistently** under a different key: delete both files and
regenerate them with `SIH26_LEDGER_KEY` set to something else, then verify with the original key:

> `FORGED ANCHOR: a checkpoint ... has an invalid signature.` · exit 1.

**Delete the checkpoint log** and verify the chain alone:

> `UNANCHORED: ... A chain on its own is not evidence` · exit 1 — because a verifier that prints
> OK for an unanchored chain attests nothing.

**Point it at a path with no chain and no checkpoint log at all:**

> `NO CHAIN: ... Nothing was verified. An absent file is not an intact ledger` · exit 2.

(Point it at a missing chain whose checkpoint log still attests five records and you get
`TAMPERED ... a chain of a different length` instead, which is the more useful answer: the
records did not merely go unread, they went missing.)

There is a fifth attack this does **not** catch, and we would rather tell you than have you find
it: truncating the chain **and** its checkpoint log together leaves two files that agree with each
other, and nothing inside them records that the run continued. No scheme confined to those two
files can detect it. That is what `scripts/anchor_checkpoint.py` is for — it publishes a count and
digest outside the run directory, before the demo:

```
.venv\Scripts\python scripts\anchor_checkpoint.py run\audit_chain.jsonl
```

> `SIH26-ANCHOR count=5 head=2fe2664a... root=bfb41b1d... sig=b9d1454a...`
> `spoken digest: D9F7-BCDA-16B4-D355-8D76-4B29`

A ledger later truncated to four records contradicts a count the room already heard. Exactly what
the anchor does and does not prove is in [docs/limitations.md](docs/limitations.md).

### 6. The documents that answer the hard questions

- [docs/threat_model.md](docs/threat_model.md) — what an adaptive attacker defeats here, costed
- [docs/limitations.md](docs/limitations.md) — what this system cannot do
- [docs/deployment.md](docs/deployment.md) — sensor placement, and the alert volume a real
  network would actually see
- [docs/competitive.md](docs/competitive.md) — why this is not Suricata, and why the ~99 %
  figures published on this dataset are not the same claim as ours
- [docs/dataset_quality.md](docs/dataset_quality.md) — the known defects in the public dataset,
  which reach this pipeline, and the labelling risk that is ours alone
- [tier1_hardening_report.md](tier1_hardening_report.md) — our own adversarial audit, including
  the defects it found in claims we had already published

---

## Part 2 — running the pipeline

There are two different things you might want here, and they are not the same thing. Part 2a
lets you **watch the pipeline work** on a bare clone. Part 2b is what it would take to
**reproduce a published number**, and you cannot do it on this machine or on ours.

### 2a. Watch it run, with nothing but the clone (under a minute)

```
.venv\Scripts\python scripts\bootstrap_demo_artifacts.py
.venv\Scripts\streamlit run app\streamlit_app.py
```

No dataset, no released weights, no network. The script fits a small model from
`app/assets/synthetic_demo.pcap` — the deterministic hand-authored capture bundled in the
repository — into a **separate artifact lane** at `artifacts_demo/`. Timed on the machine this
was written on, 2026-09-12: two consecutive runs took 16.7 s and 18.4 s with the venv already
built. Your first run on a cold clone will be slower; time it rather than trusting this line.

**Now the part you should hold us to.** That model is a toy. It was fitted on one capture of
a few minutes and its alert thresholds were chosen **on the same rows it was fitted on**, so it
has memorised that capture. When you run the demo on that capture and see a high probability,
the model is recognising traffic it was trained on. That is not a detection and it is not a
measurement. The artifact's own threshold file records `"auroc_is_in_sample": true` and an
in-sample AUROC of 1.0 for every head — we print the number that proves it is meaningless
rather than the one that would look good.

It never saw CSE-CIC-IDS-2018. **Nothing it produces is comparable to any number in the README,
this document, the report or the deck, and running it reproduces none of them.** You should not
have to take that on trust, so it is enforced rather than asserted: every demo run prints the
warning in full on stderr before it does anything, stamps `demo_model: true` on every forecast
object, writes `artifact_lane: "demo"` into every ledger record, and drops a
`WHAT_THIS_IS.txt` beside the weights. The published lane always wins when present, a
*partially* present published lane is a hard error rather than a quiet fallback, and copying
`artifacts_demo/` into `artifacts/` **fails loudly** — `engine/thresholds.py` refuses to serve a
demo-marked threshold file from any directory but the demo one.

It also does not make the skipped tests pass, deliberately — see Part 3.

### 2b. Reproduce a published number

You cannot, and neither can we on a machine without the data. The trained weights are not in git
(the project forbids committing them), the GitHub Release is not published, and the extracted
dataset is ~12.7 GiB. With both present:

```
.venv\Scripts\python -m engine.train_engine
.venv\Scripts\python -m tests.smoke
```

`python -m tests.smoke` runs the whole pipeline inside a socket kill-switch, so a network call
anywhere in it raises rather than succeeding quietly. That test and `tests/test_offline.py` are
what "offline" means for the **inference path** — those specific tests, not the suite as a
whole: the `no_network` fixture is opt-in, and [docs/INSTALL.md](docs/INSTALL.md) says so, along
with the one socket-blocked test that *does* run on a bare clone and what it covers.

The reproduction order for the published benchmark table is `scripts/reproduce_results.ps1`,
which fails with a diagnosis rather than a stack trace when a prerequisite is missing.

---

## Part 3 — what we cannot let you verify, and why

- **The published benchmark numbers are not regenerable on a bare clone.** `results/*.json` is
  gitignored, so the README table is the output of a run you cannot repeat without the dataset.
  The evaluation population is small and it is stated beside the table: two attack episodes, both
  sessions of one attacker host, and benign traffic subsampled to roughly 30 of ~450 hosts a day.
- **The headline lead time does not separate from chance at our alert budget.** Our own audit
  measured a matched-budget random baseline scoring as well or better. The figure is still
  reported — it is the problem statement's graded metric — but never without that fact. AUROC,
  not lead time, is where the model earns its place.
- **Forward forecasting is a ranking capability, not a working operating point.** At the shipped
  budget the k-step head fires 0 of 2 episodes at every horizon we report, and its target is
  93–96 % identical to the nowcast target. The lead time we claim comes from the horizon-0
  classifier.
- **The deployed engine is a single gradient-boosted model**, not the fused temporal-graph
  architecture the results table headlines. Engine-side fusion is roadmap, and the table says so.
- **Three of the seven kill-chain stages have no data at all.** `recon`,
  `lateral_movement` and `exfiltration` have zero labelled windows in the public dataset, so we
  report no metric for them rather than invent one.
- **A demo run looks exactly like a real one, and you cannot tell them apart by watching.**
  This is new, and it is a cost of Part 2a rather than a benefit of it. The demo lane drives the
  same feature extractor, the same scorer, the same thresholding, the same explanation panel and
  the same ledger as the published engine — that is the point, because a demo on a parallel code
  path would prove nothing about the pipeline. The consequence is that a screenshot, a recorded
  walkthrough or a number read off the screen during a demo session is indistinguishable, to the
  eye, from the published engine doing the same thing. **Every probability, alert, stage, lead
  time and forecast you see in a bare-clone demo comes from a model that memorised one bundled
  capture.** We cannot make a running demo self-evidently a demo; what we can do is make it
  impossible for the *data* to lose its provenance, which is why the lane is stamped on every
  forecast object, every ledger record and every run summary, and printed on stderr at the start
  of every run. If you are handed a number from this project and it did not come with the
  dataset, check `artifact_lane` before you believe it.
- **The demo bootstrap does not convert a single skipped test into a passing one, and if it ever
  appears to, that is the defect.** A test that passes against a model trained on five minutes
  of synthetic traffic is not evidence for a claim measured on CSE-CIC-IDS-2018, so letting the
  skip count fall would turn "unverified" into "verified" with nothing verified.
  `tests/conftest.py` records, per test, whether its subject is plumbing (which the demo model
  could legitimately exercise) or a measured number (which it never can), and
  `tests/test_bootstrap_state.py` prints the gap between the two under **DEMO LANE: PERMITTED vs
  ACTUALLY EXECUTING**. On a demo-lane checkout that currently reads `0 of 11`: eleven tests are
  judged safe to run against the demo model and none of them does, because each still carries
  its own published-artifact gate. The gap understates what is checked and cannot overstate it.
  There is a concrete reason it is still open — measured 2026-09-12, the demo model raises **0
  alerts on the committed 1,000-flow fixture**, so the offline and smoke tests, which both
  assert a non-empty forecast list, would *fail* on the demo lane rather than pass. For three
  of the eleven it is worse than failing: with no alerts the engine writes no ledger file and
  the host ranking comes back empty, so those tests raise `FileNotFoundError`, `IndexError` or
  `TypeError` before reaching an assertion at all. That distinction is written into each of
  their entries in `tests/conftest.py`, because an error met while rewiring a gate is the
  situation most likely to end with the assertion deleted instead of the lane fixed. Exactly
  one of the eleven — the host-graph payload check — has assertions the demo lane really does
  satisfy (measured: 164 graph nodes on a run with zero alerts), and its entry says so. If you
  ever see that count rise, check that it rose because the demo lane got better and not because
  an assertion got weaker.
- **The problem statement's first hard constraint — fully offline inference — is not asserted
  on a machine like yours, and the demo lane does not change that.** `tests/test_offline.py`
  and `tests/test_smoke.py` are the tests that run the engine end to end inside a socket
  kill-switch, and both are gated on the published artifacts, so on a bare clone *and* on a
  demo-lane clone they skip. What does run with sockets blocked on a bare clone is one pcap
  round-trip test that touches the writer and parser, not the engine
  (`tests/test_evasion.py::test_a_transformed_table_survives_a_pcap_round_trip`, verified
  passing here on 2026-09-12). The offline *design* — no cloud calls, no runtime downloads — is
  readable in the source; the offline *guarantee over the inference path* is something you
  currently have to take on our word, and we would rather say that than let a green suite imply
  otherwise.

If a command on this page does not do what it says, that is a defect and we want to know — it is
the same class of defect our own audit was built to find.
