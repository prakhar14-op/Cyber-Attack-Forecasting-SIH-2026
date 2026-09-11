# Verifying this project

Written for an evaluator who has ten minutes, no trust in our claims, and no intention of taking
a README's word for anything. Everything in Part 1 runs on a **bare clone** — no dataset, no
trained weights, no network. Part 2 needs the bootstrap. Part 3 lists what we cannot currently
let you verify, and why; read that one first if you are short of time, because a project is
easier to judge from what it admits than from what it demonstrates.

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

## Part 2 — what needs the bootstrap

The trained weights are not in git (the project forbids committing them) and the extracted
dataset is tens of gigabytes. With both present:

```
.venv\Scripts\python -m engine.train_engine
.venv\Scripts\python -m tests.smoke
streamlit run app\streamlit_app.py
```

`python -m tests.smoke` runs the whole pipeline inside a socket kill-switch, so a network call
anywhere in it raises rather than succeeding quietly. That test and `tests/test_offline.py` are
what "offline" means here — those specific tests, not the suite as a whole: the `no_network`
fixture is opt-in, and [docs/INSTALL.md](docs/INSTALL.md) says so.

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
- **Two of the seven kill-chain stages have no data at all.** `lateral_movement` and
  `exfiltration` have zero labelled windows in the public dataset, so we report no metric for them
  rather than invent one.

If a command on this page does not do what it says, that is a defect and we want to know — it is
the same class of defect our own audit was built to find.
