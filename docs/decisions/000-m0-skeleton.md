# 000 — M0 skeleton retrospective (2026-09-05)

**What changed.** Fresh repo in `Desktop/SIH26` (nested on purpose — the user's home directory is
itself an unrelated git repo on branch `FastAPI`, so a bare `git` outside a project targets it).
Full CLAUDE.md layout, Apache-2.0, third-party notices, and configs carrying every fixed design
decision; a single `configs.loader.load_config()`/`set_seed()` is the only YAML entry point. All
seven required tests exist as failing stubs with real assertions against the final APIs
(`models.graft.build_model`, `rssm.filter_then_imagine`, `ledger.Ledger`…): `pytest -q` shows
exactly 7 failed / 0 errors in 0.44 s, each failure naming the milestone that turns it green.
`tests/fixtures/mini.csv` holds 1,000 **real** rows range-fetched over HTTPS from the 4 GB
`Thuesday-20-02-2018` processed CSV (no full download): 513 benign + 487 `DDoS attacks-LOIC-HTTP`
starting 10:13:54 — consistent with the UNB timeline — at 476 KB. Environment: Python 3.12.4,
83 pins frozen into `requirements.txt`/`environment.lock.yml` (pip-managed; no conda on this
machine), `torch 2.14.0+cpu`, wheel-house in `vendor/` proven with a `--no-index` install
into a fresh venv (at a short path — see the long-path caveat in `vendor/README.md`).

**What surprised us.** (1) The 20-02 CSV is not time-ordered: the attack block sits at the file
head (row 64 onward), with benign traffic and out-of-order timestamps (01:35 next to 09:49)
further down — the M1 loader must sort by parsed timestamp, and mixed 12/24-hour formats are
real, not theoretical. (2) The fixture picked up two genuine `Infinity` values in
`Flow Byts/s`/`Flow Pkts/s` without us hunting for them — the defect rate is that high.
(3) The dataset filename itself is misspelled upstream (`Thuesday-...`), worth hardcoding nowhere.
(4) This laptop had no git identity configured anywhere (set repo-locally) and has no tshark —
Wireshark must be installed before M2's retransmission path. (5) `aws` CLI is present, so M1.1
can use `aws s3 sync --no-sign-request` as planned. No GPU: M5–M7 train on CPU; day subsetting
(decision 001) is also the compute lever.
