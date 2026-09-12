# Install

Two supported paths. **Online** is what a judge cloning the repo should use; **offline
wheel-house** is what the air-gapped demo laptop uses. They install the identical pinned
set — `requirements.txt` is the single source of truth for both.

## Assumptions

| | |
|---|---|
| Interpreter | **CPython 3.12** (`cp312`). `environment.lock.yml` records the build interpreter as 3.12.4; the verified dev venv on this machine is 3.12.1. Any 3.12.x works; 3.11 and 3.13 do **not** — every wheel in the house is tagged `cp312`. |
| OS | **Windows 10/11, x86-64** (`win_amd64`). This is the only platform the pins are verified on: the wheel-house is built `win_amd64/cp312` (`vendor/README.md`), and `configs/data.yaml` carries a Windows default for `tshark_default_path`. Linux/macOS are **untested** — the offline path will not work there at all (wrong wheel tags), and the online path is unverified. |
| Network | Needed **only to install** (online path), to fetch the dataset (`data/download_cic.sh`, `data.zip_fetch`) and to pull released weights (`scripts/fetch_artifacts.py`). Inference, the demo's analysis path and ledger verification are built to make no network calls (PS hard constraint #1). What actually *asserts* that, and when, is below — it is narrower than you would guess. |
| Disk | **1.49 GB** for the venv, measured on this machine 2026-09-11 (`torch` is 502 MB of it). Measure your own: `(Get-ChildItem C:\sih26\.venv -Recurse -File -Force \| Measure-Object Length -Sum).Sum / 1GB`. The dataset is separate and lives **outside** the repo at the `paths.*_dir` values in `configs/data.yaml` (default `C:/sih26_data`, ~12.7 GiB of selectively fetched pcap). |

> **What "offline" is actually enforced by, precisely.** `tests/net_guard.py`
> supplies `network_disabled()`, exposed by `tests/conftest.py` as the
> `no_network` fixture. That fixture is **opt-in — it is not `autouse`**, so it
> does not apply to the suite. Count the tests that request it yourself —
> `grep -rn "no_network" tests/*.py` — rather than trusting a number typed here;
> an earlier revision of this paragraph said "exactly three" and was already
> wrong by the time anyone read it, because the suite grew one.
>
> What matters is which of them run *on your machine*, and that is not "all" or
> "none". The three that exercise the **engine** end to end —
> `tests/test_offline.py`, `tests/test_smoke.py` and
> `tests/test_app.py::test_pipeline_and_panels_work_offline` — are gated on the
> **published** trained artifacts, and a bootstrapped demo lane does not satisfy
> that gate (see *Run the pipeline with nothing but the clone* below). So on a
> bare checkout the offline guarantee over the **inference path** (PS hard
> constraint #1) is **not** asserted. It is asserted only after you bootstrap
> the published artifacts.
>
> One test under the socket kill-switch is **not** artifact-gated and does run on
> a bare clone: `tests/test_evasion.py::test_a_transformed_table_survives_a_pcap_round_trip`,
> which writes a transformed packet table back out as a real pcap and re-parses
> it with sockets blocked. Verified on this machine on 2026-09-12 with no
> `artifacts/` and no `artifacts_demo/` present — it passes rather than skipping.
> That covers the pcap writer/parser, not the engine, so it does not close the
> gap above; it is recorded because "zero tests run with sockets blocked" was the
> previous wording and it was false.
>
> `python -m pytest tests/test_bootstrap_state.py -q -s` prints which of these
> hold on your machine, derived from the real skip markers rather than from this
> paragraph.

## Preflight

Run this from the repo root before creating the venv. It checks the two things
that actually break installs here. `$Venv` is the path you intend to create the
venv at — the length that matters for MAX_PATH is that one, **not** the repo's.

```powershell
$Venv = 'C:\sih26\.venv'
python -c "import sys; print(sys.version)"
if ((Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem' -Name LongPathsEnabled -ErrorAction SilentlyContinue).LongPathsEnabled -eq 1) { 'long paths: enabled' } else { 'long paths: DISABLED - use a short venv path' }
"venv path: $Venv ($($Venv.Length) chars)"
"repo path: $($PWD.Path) ($($PWD.Path.Length) chars)"
```

Real output, produced from the repo root on this machine (2026-09-11):

```
3.12.1 (tags/v3.12.1:2305ca5, Dec  7 2023, 22:03:25) [MSC v.1937 64 bit (AMD64)]
long paths: enabled
venv path: C:\sih26\.venv (14 chars)
repo path: C:\Users\HP\OneDrive\Desktop\sih 2026\Cyber-Attack-Forecasting-SIH-2026 (71 chars)
```

The repo path is printed only to show why the venv is kept out of it: a venv
inside this clone would start from a 71-character prefix, and that is the
configuration that broke on 2026-09-05 (next paragraph). `C:\sih26\.venv` starts
from 14.

**Windows path-length caveat** (hit for real on 2026-09-05, recorded in `README.md` and
`vendor/README.md`): torch's include tree nests deep enough to breach the 260-char MAX_PATH
when the venv sits under a long prefix, and pip then dies mid-extract with
`[Errno 2] ... mem_eff_attention\epilogue\epilogue_rescale_output.h`. If the preflight reports
`long paths: DISABLED`, either enable NTFS long paths or create the venv at a short path such
as `C:\sih26\.venv` — a long prefix plus disabled long paths is the failing combination.
Cloning under OneDrive (as here) makes the repo prefix long, so **the venv does not have to
live inside the repo**.

## Path A — online install (a fresh clone, connected machine)

```powershell
git clone https://github.com/prakhar14-op/Cyber-Attack-Forecasting-SIH-2026.git
cd Cyber-Attack-Forecasting-SIH-2026
python -m venv C:\sih26\.venv           # short prefix; see the caveat above
C:\sih26\.venv\Scripts\python -m pip install --upgrade pip
C:\sih26\.venv\Scripts\python -m pip install -r requirements.txt
```

`requirements.txt` pins 84 distributions exactly. The resolve pulls exactly one unpinned
transitive dependency — `tenacity` (via `plotly`) — so a fully air-gapped machine needs it in
the wheel-house too; `scripts\build_vendor.ps1` picks it up automatically because it downloads
the resolved graph, not just the pin list.

## Path B — offline wheel-house (the air-gapped demo laptop)

Build the house **once on a connected machine with the same interpreter** (3.12, win_amd64),
carry `vendor/` to the demo laptop on disk, then install with no index access:

```powershell
# connected machine, repo root
scripts\build_vendor.ps1                # pip download -r requirements.txt -d vendor

# demo laptop, repo root, no network
python -m venv C:\sih26\.venv
C:\sih26\.venv\Scripts\pip install --no-index --find-links vendor -r requirements.txt
```

The wheels themselves are **not** committed (`.gitignore`: `vendor/*.whl`) — a fresh clone
gets `vendor/README.md` and nothing else, so Path B requires the build step first. Rebuild the
house whenever `requirements.txt` changes.

## Verify the install

```powershell
C:\sih26\.venv\Scripts\python -m pip check
C:\sih26\.venv\Scripts\python -m pytest tests\ -q
```

`pip check` must print `No broken requirements found.`

Do **not** check the suite against a memorised pass/skip count — the suite grows,
and a hardcoded expected count in a document is a lie waiting to happen. The
criterion for a correct bare checkout is **`0 failed`, `0 errors`, and a non-zero
number of skips**. Read the counts off your own run. The skips are the tests
gated on trained artifacts and the extracted dataset, neither of which is in git;
that is a correct result, not a broken install.

For a line-by-line statement of which guarantees those skips leave unverified —
derived from the real skip markers in the test files, not from a hand-maintained
list — run:

```powershell
C:\sih26\.venv\Scripts\python -m pytest tests\test_bootstrap_state.py -q -s
```

## Run the pipeline with nothing but the clone (the demo lane)

This is the route for a judge who wants to *watch the thing work* in the next five
minutes. It does not need the dataset, the released weights, or a network.

```powershell
C:\sih26\.venv\Scripts\python scripts\bootstrap_demo_artifacts.py
```

It fits a small XGBoost model from `app/assets/synthetic_demo.pcap` — the
deterministic hand-authored capture that ships in the repo — and writes it to
`artifacts_demo/`, which is a **separate artifact lane** from the published
`artifacts/`. Timed on this machine on 2026-09-12, two consecutive runs into a
scratch directory: **16.7 s** and **18.4 s**, with the venv already built and the
bytecode already compiled. Time your own — a first run on a cold clone is slower,
and that is the number you will actually experience. It needs no network and no environment
variables, though it will tell you if `SIH26_HMAC_KEY` is unset, because the two
role features are then zero at fit time — the engine zeroes them at inference
too, so the two agree, but setting the key later changes the inputs the model was
fitted on and you should re-run the script.

After it finishes, the app and the CLI run:

```powershell
C:\sih26\.venv\Scripts\streamlit run app\streamlit_app.py
```

### What this is not

Read this before you read a probability off the screen.

The demo model is fitted on one capture of a few minutes, and its alert
thresholds are chosen **on the same rows it was fitted on**. It has memorised
that capture. Score the capture back and a high probability means *the model has
seen this row before* — it is not a detection, and it is not a measurement. The
persisted thresholds say so themselves: `artifacts_demo/engine_threshold.json`
records `"auroc_is_in_sample": true` and an in-sample AUROC of 1.0 for every
head, which is what perfect memorisation looks like, not what good detection
looks like.

It never saw CSE-CIC-IDS-2018. **No number it produces is comparable to any
number in `README.md`, the report or the deck, and running it reproduces
none of them.** Every run of the demo lane prints that in full on stderr before
it does anything, tags every forecast object with `demo_model: true`, and writes
`artifact_lane: "demo"` into every ledger record. `artifacts_demo/WHAT_THIS_IS.txt`
repeats it beside the weights.

Three structural guards keep the two lanes apart, so this is not a promise in a
document:

- the demo weights carry a `demo_` filename prefix and live in their own
  directory; `engine/thresholds.py` refuses to serve a demo-marked threshold file
  from any directory but the configured demo one, so **copying `artifacts_demo/`
  into `artifacts/` fails loudly** rather than quietly becoming "the model";
- the published lane always wins when it is present, and a *partially* present
  published lane is a hard error rather than a silent fallback to the demo model;
- the demo lane gets its own `weights.sha256`, so the engine's existing
  weight attestation still runs against it and still refuses a tampered demo
  model.

### It does not turn any skipped test green, and that is deliberate

Bootstrapping the demo lane does **not** reduce the suite's skip count. The
end-to-end tests (`tests/test_offline.py`, `tests/test_smoke.py`, the
engine-dependent part of `tests/test_app.py`) stay gated on the *published*
artifacts. A test that passes against a model trained on five minutes of
synthetic traffic is not evidence for a claim measured on CSE-CIC-IDS-2018, and
letting the count fall would convert "unverified" into "verified" with nothing
actually verified.

`tests/conftest.py` records, per test, whether its subject is plumbing (which the
demo model could legitimately exercise) or a measured number (which it never
can). The report prints the resulting gap under **DEMO LANE: PERMITTED vs
ACTUALLY EXECUTING**:

```powershell
C:\sih26\.venv\Scripts\python -m pytest tests\test_bootstrap_state.py -q -s
```

On a demo-lane checkout that section currently reads `0 of 11` — eleven tests are
judged safe to run against the demo model and none of them does, because each
still carries its own published-artifact gate. That gap understates what is
checked and can never overstate it. Measured on this machine on 2026-09-12, the
reason it has not been closed is concrete: the demo model raises **0 alerts on
the committed 1,000-flow fixture** (`tests/fixtures/mini.csv`), because nothing
in CSE-CIC-format flow data clears a threshold chosen on synthetic packet
captures. `tests/test_offline.py` and `tests/test_smoke.py` both assert a
non-empty forecast list, so pointing their gates at the demo lane today would
make them **fail**, not pass. The fix, when it comes, is to the demo lane — never
to the assertions.

Three of the eleven would not even get as far as a failing assertion, and that
matters more than it sounds. The same run produced 0 timeline rows, 0 host-ranking
rows and **no `audit_chain.jsonl` at all**, so the ledger-tamper, what-if-ablation
and determinism tests raise `TypeError`, `IndexError` and `FileNotFoundError`
respectively before asserting anything. An error hit while moving a gate is the
single most likely way this ends with a deleted assertion instead of a better
demo lane, so each of those three carries the measurement in its own entry in
`tests/conftest.py`. In the other direction, exactly one of the eleven —
`test_pipeline_result_carries_a_host_graph` — has assertions the demo lane really
does satisfy on this fixture (measured: 164 graph nodes and 166 edges on a run
with zero alerts, because the graph is built over hosts rather than alerts). Its
entry says so too. The registry is a record of what was measured, not a list of
hopes.

What the demo lane *does* exercise honestly is `tests/test_demo_bootstrap.py`,
which fits and scores a demo model of its own and runs on a bare clone. The
report shows it as `DEMO` rather than `RUNS`, because "the pipeline works" and
"the published number holds" are different claims.

## Bootstrap: turning skips into passes

The gated tests need `artifacts/` populated. The demo lane above does **not** do
this, by design — these are the two routes that do:

```powershell
# 1. Download the released artifacts and check them against the README digests.
python scripts\fetch_artifacts.py
```

> The GitHub Release does **not exist yet** — re-verified 2026-09-11 by running the command
> above: `api.github.com/repos/prakhar14-op/Cyber-Attack-Forecasting-SIH-2026/releases/latest`
> answers 404 to an anonymous client, and the script exits 1 with that diagnosis rather than
> pretending. The download-and-verify path has therefore **never been exercised against a real
> release**; only the 404 diagnosis and `--verify-only` have been run. See `README.md` →
> Model weights.

```powershell
# 2. Or retrain from the dataset. Needs the dataset AND the anonymisation key.
$env:SIH26_HMAC_KEY = "<the team key — never committed>"
bash data/download_cic.sh
python -m data.zip_fetch
python -m data.extract
python -m data.windows
python -m engine.train_engine
python scripts\verify_weights.py --record
```

`SIH26_HMAC_KEY` is deliberately unset by default: `data/anonymize.py` raises rather than fall
back to a default key. No test on a bare checkout needs it.

To regenerate the published results table on top of that, see `scripts\reproduce_results.ps1`,
which states its own prerequisites and refuses to run without them.
