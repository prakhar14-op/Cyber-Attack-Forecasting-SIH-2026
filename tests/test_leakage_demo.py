"""The leakage demonstration: does it measure the mechanism, or just print a gap?

`eval/leakage_demo.py` exists to support one sentence — "a random train/test
split inflates the score, and here is by how much on data where we control the
answer". A demo that always prints a positive inflation supports nothing, because
a procedural bias (unequal test sizes, an arm trained on more rows, an arm scored
on an easier subset) would print the same thing.

So the load-bearing test here is the NEGATIVE one:
`test_removing_the_planted_structure_removes_the_gap` sets `fingerprint_effect=0`
— the same code, the same split rules, the same sample sizes, with nothing
planted to memorise — and requires the two arms to agree. If the comparison had
a thumb on the scale, that test fails. Everything else checks that the claim is
not knob-dependent, and that the real-data arm refuses loudly rather than
answering with synthetic numbers.

The worlds here are smaller than the module's shipped defaults so the suite stays
fast; the replicate count is not, because a single world's held-out day carries
two episodes and its AUROC swings by tenths.
"""

from __future__ import annotations

import builtins
import json
import os
from pathlib import Path

import numpy as np
import pytest

from configs import load_config, resolve_path
from eval import leakage_demo as L

# A small world: same structure, fewer rows. The replicate count matters more
# than the row count for a stable median, so it is kept at the shipped default.
SMALL = dict(hosts_per_day=8, windows_per_host=60, episode_windows=20)
REPLICATES = L.DEFAULT_REPLICATES
MODEL = L.ModelSpec()


def _world(**overrides) -> L.WorldSpec:
    return L.WorldSpec(**{**SMALL, **overrides})


def _cic_windows_present() -> bool:
    """True if the extracted per-day packet windows are on this machine."""
    cfg = load_config("data")
    interim = resolve_path(cfg["paths"]["interim_dir"])
    if not interim.exists():
        return False
    return any(list((interim / str(d["date"]) / "packets").glob("*.parquet"))
               for d in cfg["dataset"]["days"])


# ------------------------------------------------------- the mechanism it claims

def test_the_planted_fingerprint_is_what_the_random_split_cashes_in():
    """With a memorisable per-episode signature, the random split scores higher.

    Both arms get the same model, the same features and the same number of test
    rows. The only difference is that the random split leaves parts of every
    episode in training, so the fingerprint it learns is present at test time.
    """
    c = L.measure_synthetic(_world(), MODEL, seed=1337, n_worlds=REPLICATES)

    assert c.random_auroc > c.disjoint_auroc
    assert c.inflation > 0.10, (
        f"the planted fingerprint bought only {c.inflation:+.3f} AUROC "
        f"(random {c.random_auroc:.3f} vs disjoint {c.disjoint_auroc:.3f}) — "
        "either the world is not planting it or the random split is not "
        "reaching it")
    assert len(c.random_aurocs) == len(c.disjoint_aurocs) == REPLICATES


def test_removing_the_planted_structure_removes_the_gap():
    """THE control. Nothing to memorise, so the two splits must agree.

    `fingerprint_effect=0` leaves only the shared signal, which generalises
    across episodes by construction — a day-disjoint model can use all of it.
    Everything else is unchanged: same code path, same sample sizes, same model.
    So this pins the gap to the planted structure specifically: make
    `fingerprint_effect` stop reaching the generator and the control reports the
    planted gap and fails.

    What it does NOT prove, checked rather than assumed: it is not a general
    detector of a biased comparison. Training the random arm on every row
    (including its own test rows), halving the disjoint arm's training set, and
    scoring the random arm in-sample were each tried against this assertion and
    none moved it — with a signal this simple a linear model is neither
    sample-limited nor overfitting, so those biases buy nothing. The claim this
    test supports is exactly "the gap tracks the memorisable structure", which
    is the claim the module makes.
    """
    planted = L.measure_synthetic(_world(), MODEL, seed=1337, n_worlds=REPLICATES)
    control = L.measure_synthetic(_world(fingerprint_effect=0.0), MODEL,
                                  seed=1337, n_worlds=REPLICATES)

    assert abs(control.inflation) < 0.06, (
        f"with nothing planted the two splits still differ by "
        f"{control.inflation:+.3f} (random {control.random_auroc:.3f} vs "
        f"disjoint {control.disjoint_auroc:.3f}) — that gap is the comparison's "
        "own bias, not leakage")
    assert planted.inflation > abs(control.inflation) * 2


@pytest.mark.parametrize("seed", [3, 77, 404])
def test_the_conclusion_survives_a_different_world(seed):
    """Not a knob setting that happens to work: other worlds say the same thing."""
    c = L.measure_synthetic(_world(), MODEL, seed=seed, n_worlds=REPLICATES)
    assert c.inflation > 0.05, f"seed {seed}: inflation {c.inflation:+.3f}"


@pytest.mark.parametrize("overrides", [
    dict(episodes_per_day=3),
    dict(shared_effect=1.0),
    dict(fingerprint_effect=2.0),
    dict(n_fingerprint_features=8),
])
def test_the_conclusion_survives_changing_the_knobs(overrides):
    c = L.measure_synthetic(_world(**overrides), MODEL, seed=1337,
                            n_worlds=REPLICATES)
    assert c.inflation > 0.0, f"{overrides}: inflation {c.inflation:+.3f}"


def test_both_arms_are_scored_on_the_same_number_of_rows(monkeypatch):
    """An AUROC gap that came from unequal test sizes would prove nothing.

    OBSERVED at the model, not read back off the return value. `split_aurocs`
    returns `n_test = int(held_out.sum())`, which is what the DISJOINT arm was
    given; the random arm's size is a separate slice of a permutation and is
    never reported. Asserting on the return value therefore cannot fail for this
    property: halve the random arm and the returned number does not move. So
    this wraps `_score_test` — the one door both arms go through to reach the
    model — and asserts on the matrices that arrived there.
    """
    spec = _world()
    X, y, day, _ = L.synthesise(spec, seed=1337)
    held_out = day == f"day{spec.n_days - 1}"

    scored: list[tuple[int, int, int]] = []
    real_score_test = L._score_test

    def recording(X_train, y_train, X_test, model, seed):
        scored.append((len(X_train), len(y_train), len(X_test)))
        return real_score_test(X_train, y_train, X_test, model, seed)

    monkeypatch.setattr(L, "_score_test", recording)

    disjoint, randoms, n_train, n_test, n_attack = L.split_aurocs(
        X, y, day, {f"day{spec.n_days - 1}"}, model=MODEL, seed=1337, n_shuffles=3)

    assert len(scored) == 4, (
        f"expected one day-disjoint fit and three random ones; the model was "
        f"reached {len(scored)} times")
    assert len(set(scored)) == 1, (
        f"the arms were not fitted and scored on the same row counts. "
        f"(train rows, train labels, test rows) per call, disjoint first: "
        f"{scored}")

    train_rows, train_labels, test_rows = scored[0]
    assert train_labels == train_rows, "a fit got more rows than labels"
    assert test_rows == int(held_out.sum()), (
        f"each arm scored {test_rows} rows; the held-out day has "
        f"{int(held_out.sum())}")
    assert train_rows == y.size - test_rows
    assert (n_train, n_test) == (train_rows, test_rows), (
        f"the returned counts ({n_train}, {n_test}) are not the row counts the "
        f"arms were actually handed ({train_rows}, {test_rows})")
    assert n_attack == int(np.count_nonzero(y[held_out]))
    assert len(randoms) == 3 and len(set(randoms)) > 1, (
        "three shuffles produced identical AUROCs — the shuffle is not varying")
    assert 0.0 <= disjoint <= 1.0


# ------------------------------------------------------ the world it synthesises

def test_every_planted_episode_lives_on_one_host_of_one_day():
    """The disjointness the demo rests on, checked rather than asserted in prose.

    If an episode's rows straddled two days, the day-disjoint arm would see part
    of the held-out day's episode in training and the demo would be comparing
    two leaky splits.
    """
    spec = _world()
    X, y, day, episode = L.synthesise(spec, seed=1337)

    assert X.shape == (spec.n_days * spec.hosts_per_day * spec.windows_per_host,
                       spec.n_shared_features + spec.n_fingerprint_features)
    assert set(np.unique(episode[y == 1])).isdisjoint({-1})
    assert (episode[y == 0] == -1).all(), "a benign row was given an episode"

    for e in np.unique(episode[episode >= 0]):
        rows = np.flatnonzero(episode == e)
        assert len(set(day[rows])) == 1, f"episode {e} straddles days"
        assert len(rows) == spec.episode_windows
        assert (y[rows] == 1).all()

    n_expected = spec.n_days * spec.episodes_per_day
    assert len(np.unique(episode[episode >= 0])) == n_expected


def test_the_fingerprint_block_is_flat_for_benign_rows_and_per_episode_for_attacks():
    """Each episode's signature is its own: a direction no other episode shares."""
    spec = _world()
    X, y, _day, episode = L.synthesise(spec, seed=1337)
    fp = X[:, spec.n_shared_features:]

    directions = []
    for e in np.unique(episode[episode >= 0]):
        centre = fp[episode == e].mean(axis=0)
        assert np.linalg.norm(centre) > spec.fingerprint_effect * 0.8, (
            f"episode {e}'s fingerprint block has norm "
            f"{np.linalg.norm(centre):.2f}, far short of the planted "
            f"{spec.fingerprint_effect} — nothing was planted to memorise")
        directions.append(centre / np.linalg.norm(centre))
    gram = np.abs(np.array(directions) @ np.array(directions).T)
    np.fill_diagonal(gram, 0.0)
    assert gram.max() < 0.9, (
        "two episodes share nearly the same fingerprint direction — one would "
        "transfer to the other and the control test would stop being a control")

    benign_norm = np.linalg.norm(fp[y == 0].mean(axis=0))
    attack_norm = np.linalg.norm(fp[y == 1].mean(axis=0))
    assert benign_norm < spec.fingerprint_effect / 4
    assert attack_norm < spec.fingerprint_effect, (
        "the episode directions did not average down — a linear model could "
        "read the fingerprint block as a single generalising feature")


# ------------------------------------------------------------------- refusals

def test_a_single_class_test_split_is_refused_not_answered_with_half():
    y = np.zeros(20, dtype=int)
    with pytest.raises(ValueError, match="AUROC is undefined, not 0.5"):
        L._auroc_or_refuse(y, np.linspace(0, 1, 20), "day-disjoint")


def test_a_world_that_cannot_support_the_comparison_is_refused():
    with pytest.raises(ValueError, match="n_days must be >= 2"):
        L.WorldSpec(n_days=1).validate()
    with pytest.raises(ValueError, match="episode_windows"):
        L.WorldSpec(windows_per_host=10, episode_windows=20).validate()
    with pytest.raises(ValueError, match="episodes_per_day"):
        L.WorldSpec(hosts_per_day=2, episodes_per_day=3).validate()
    with pytest.raises(ValueError, match="noise must be > 0"):
        L.WorldSpec(noise=0.0).validate()
    with pytest.raises(ValueError, match="n_worlds must be >= 1"):
        L.measure_synthetic(_world(), MODEL, seed=1, n_worlds=0)
    with pytest.raises(ValueError, match="n_shuffles must be >= 1"):
        X, y, day, _ = L.synthesise(_world(), seed=1)
        L.split_aurocs(X, y, day, {"day3"}, model=MODEL, seed=1, n_shuffles=0)


def test_a_day_that_is_not_in_the_data_is_refused():
    X, y, day, _ = L.synthesise(_world(), seed=1337)
    with pytest.raises(ValueError, match="no row carries a held-out day"):
        L.split_aurocs(X, y, day, {"day99"}, model=MODEL, seed=1, n_shuffles=1)
    with pytest.raises(ValueError, match="every row is held out"):
        L.split_aurocs(X, y, day, set(np.unique(day)), model=MODEL, seed=1,
                       n_shuffles=1)


# ------------------------------------------------------------- the real-data arm

@pytest.mark.skipif(_cic_windows_present(),
                    reason="CIC-IDS-2018 windows are present; the refusal path "
                           "cannot be exercised on this machine")
def test_the_real_arm_refuses_loudly_and_names_the_command():
    """Missing real data must raise, not quietly become the synthetic figures."""
    with pytest.raises(L.DatasetMissing) as exc:
        L.measure_cic(MODEL, seed=1337, n_shuffles=1)

    message = str(exc.value)
    assert "will not be approximated" in message
    assert "python -m eval.leakage_demo --data cic" in message
    assert "TBD" in message
    assert "underlying error:" in message, "the real cause must survive the wrap"


def test_the_refusal_quotes_the_cause_it_saw_instead_of_naming_one(monkeypatch):
    """Two preconditions fail here, and the message must not pick the wrong one.

    Assembling the CIC split needs the extracted windows AND the anonymisation
    key (`SIH26_HMAC_KEY`), and on this machine the key is what fails first. A
    refusal hardcoded to "the window features are not on this machine" would
    have sent a reader with the dataset already downloaded off to re-download
    it. So the wrapper states both preconditions and quotes the exception it
    actually caught; this test drives each cause through it in turn and requires
    the quoted type AND text to be the ones raised.

    The third case is the message this demo really triggers. The key check in
    the data layer writes an em dash, and this report is printed to a Windows
    console (cp1252, often cp437) and pasted into docs, where that character
    arrives as a replacement glyph. Injecting only ASCII causes, as this test
    used to, made the `.encode("ascii")` below a check on the literals in
    eval/leakage_demo.py and on nothing else - the foreign text those literals
    wrap was never exercised. The expected quote spells the transliteration out,
    so a wrapper that reached ASCII by DELETING the character fails here too.
    """
    em_dash = chr(0x2014)
    cases = (
        (FileNotFoundError("no such file: windows.parquet"),
         "no such file: windows.parquet"),
        (RuntimeError("anonymisation key env var 'SIH26_HMAC_KEY' is unset"),
         "anonymisation key env var 'SIH26_HMAC_KEY' is unset"),
        (RuntimeError(f"key env var is unset {em_dash} refusing to run with a "
                      "default key"),
         "key env var is unset -- refusing to run with a default key"),
    )
    seen = []
    for error, quoted in cases:
        def boom(*_a, _error=error, **_k):
            raise _error

        monkeypatch.setattr("eval.dataset.assemble_split", boom)
        with pytest.raises(L.DatasetMissing) as exc:
            L.measure_cic(MODEL, seed=1337, n_shuffles=1)

        message = str(exc.value)
        assert f"underlying error: {type(error).__name__}: {quoted}" in message, message
        # both preconditions named, so neither cause reads as the only one
        assert "extracted windows" in message and "anonymisation key" in message
        # the rendered refusal, foreign text included, on a cp1252 console
        message.encode("ascii")
        seen.append(type(error).__name__)

    assert seen == ["FileNotFoundError", "RuntimeError", "RuntimeError"], (
        "one of the three causes did not reach the wrapper at all")


@pytest.mark.skipif(_cic_windows_present(),
                    reason="CIC-IDS-2018 windows are present on this machine")
def test_the_cic_only_run_exits_non_zero_and_prints_no_table(capsys):
    assert L.main(["--data", "cic"]) == 2
    captured = capsys.readouterr()
    assert captured.out == "", "a refused run printed something that reads as a result"
    assert "--data cic" in captured.err


@pytest.mark.skipif(_cic_windows_present(),
                    reason="CIC-IDS-2018 windows are present on this machine")
def test_the_cic_row_reads_tbd_beside_the_synthetic_one(capsys):
    """Both arms asked for, one unmeasurable: it must be TBD, never a number."""
    assert L.main(_cli(["--data", "both"])) == 0
    out = capsys.readouterr().out

    cic_row = next(line for line in out.splitlines()
                   if line.startswith("CIC-IDS-2018"))
    assert cic_row.count("TBD") == 3, cic_row
    assert "NOT MEASURED on this machine" in out
    assert "python -m eval.leakage_demo --data cic" in out


# --------------------------------------------------------------------- the CLI

def _cli(extra: list[str]) -> list[str]:
    """A fast small-world invocation of main()."""
    return [
        "--hosts-per-day", str(SMALL["hosts_per_day"]),
        "--windows-per-host", str(SMALL["windows_per_host"]),
        "--episode-windows", str(SMALL["episode_windows"]),
        "--replicates", "3",
    ] + extra


def test_the_report_is_ascii_and_states_what_it_does_not_claim(capsys):
    assert L.main(_cli([])) == 0
    out = capsys.readouterr().out

    out.encode("ascii")  # pasted into docs and read on a cp1252 console
    assert "never about CIC-IDS-2018" in out, (
        "the report no longer says the synthetic row is not a CIC measurement")
    assert "not by itself proof of a leaky split" in out, (
        "the report no longer disclaims the inference to anyone else's number")
    assert "median AUROC over replicates" in out


def test_the_shipped_report_stays_ascii_when_it_quotes_a_foreign_error(
        monkeypatch, capsys):
    """The ASCII guarantee has to cover the text this module did not write.

    The test above runs the synthetic-only path, where every character printed
    is a literal in eval/leakage_demo.py: it can only ever pin our own typing.
    The shipped `--data both` report is the one that embeds an exception raised
    in eval/dataset.py, and that is where the em dash a cp1252 console mangles
    actually came from - a real run of this command printed one. So this drives
    a foreign em dash through the whole report, stdout included.
    """
    em_dash = chr(0x2014)

    def boom(*_a, **_k):
        raise RuntimeError(f"anonymisation key env var 'SIH26_HMAC_KEY' is "
                           f"unset {em_dash} refusing to run with a default key")

    monkeypatch.setattr("eval.dataset.assemble_split", boom)
    assert L.main(_cli(["--data", "both"])) == 0
    out = capsys.readouterr().out

    out.encode("ascii")  # printed to a cp1252 console and pasted into docs
    assert "is unset -- refusing to run with a default key" in out, (
        "the em dash the other module wrote was dropped rather than "
        "transliterated; the quoted cause must keep every word it had")
    assert "NOT MEASURED on this machine" in out


def test_the_json_report_is_written_only_when_asked(tmp_path, capsys):
    out_path = tmp_path / "leakage.json"
    assert L.main(_cli([])) == 0
    capsys.readouterr()
    assert not out_path.exists()

    assert L.main(_cli(["--json", str(out_path)])) == 0
    capsys.readouterr()
    payload = json.loads(out_path.read_text(encoding="utf-8"))

    assert payload["cic"] == "not requested", (
        "a synthetic-only run recorded the CIC arm as something other than "
        "'not requested' — a reader could take its absence for a measurement")
    assert payload["world"]["hosts_per_day"] == SMALL["hosts_per_day"]
    one = payload["comparisons"][0]
    assert len(one["random_aurocs"]) == 3
    assert one["inflation"] == pytest.approx(
        one["random_auroc_median"] - one["disjoint_auroc_median"])


def _inside(path: Path, directory: Path) -> bool:
    """True if `path` lies in `directory`. Neither has to exist yet."""
    try:
        path.resolve().relative_to(directory)
    except ValueError:
        return False
    return True


def _record_writes(monkeypatch) -> list[Path]:
    """Start recording every path opened for writing; return the growing list.

    Covers the three doors a module has onto a file - `builtins.open`,
    `Path.open`, and `Path.write_text`/`write_bytes`, which on this Python go
    through `io.open` rather than through the builtin and so need their own
    patch. It RECORDS and lets the write through rather than blocking it, so a
    demo that does write into results/ fails on an assertion naming the path
    instead of on an OSError thrown out of json.dump.
    """
    written: list[Path] = []
    real_open, real_path_open = builtins.open, Path.open
    real_write_text, real_write_bytes = Path.write_text, Path.write_bytes

    def note(target, mode) -> None:
        if not any(ch in str(mode) for ch in "wax+"):
            return
        try:
            written.append(Path(os.fspath(target)))
        except TypeError:
            pass  # an already-open file descriptor names no path

    def fake_open(file, mode="r", *a, **k):
        note(file, mode)
        return real_open(file, mode, *a, **k)

    def fake_path_open(self, mode="r", *a, **k):
        note(self, mode)
        return real_path_open(self, mode, *a, **k)

    def fake_write_text(self, *a, **k):
        note(self, "w")
        return real_write_text(self, *a, **k)

    def fake_write_bytes(self, *a, **k):
        note(self, "wb")
        return real_write_bytes(self, *a, **k)

    monkeypatch.setattr(builtins, "open", fake_open)
    monkeypatch.setattr(Path, "open", fake_path_open)
    monkeypatch.setattr(Path, "write_text", fake_write_text)
    monkeypatch.setattr(Path, "write_bytes", fake_write_bytes)
    return written


def test_the_demo_never_writes_into_the_results_directory(tmp_path, monkeypatch,
                                                          capsys):
    """eval/ablation.py globs results/*.json and would read a demo as a model row.

    ORDER-INDEPENDENT, which the listing-based version of this test was not: two
    earlier tests in this file call `main()`, so a stray results/leakage_demo.json
    would already be on disk before this test starts and a before/after listing
    of results/ finds it in BOTH listings. That version passed in a normal run
    and failed only when the test was run alone - exactly backwards.

    So this observes the writes themselves. Every path opened for writing during
    the two runs below is recorded, and none of them may lie inside results/ -
    true whatever ran first, and true on the first invocation as much as on the
    tenth. The probe is proved able to see a write at all by the `--json` run,
    whose output file must appear in the record; without that check a probe that
    silently intercepted nothing would report the same clean result.
    """
    results_dir = resolve_path(load_config("eval")["paths"]["results_dir"]).resolve()
    written = _record_writes(monkeypatch)

    assert L.main(_cli([])) == 0
    capsys.readouterr()
    asked_for = tmp_path / "asked-for.json"
    assert L.main(_cli(["--json", str(asked_for)])) == 0
    capsys.readouterr()

    assert asked_for.resolve() in [q.resolve() for q in written], (
        "the probe recorded no write even though the demo was asked for a JSON "
        "report, so its silence about results/ would mean nothing")
    landed_in_results = sorted({str(q) for q in written if _inside(q, results_dir)})
    assert landed_in_results == [], (
        f"the demo wrote into the results directory: {landed_in_results}. "
        "eval/ablation.py globs results/*.json and would render the demo as a "
        "model row.")


def test_the_seed_comes_from_config_when_the_flag_is_absent(tmp_path, capsys):
    """No seed literal in the module: an unflagged run uses configs/eval.yaml."""
    configured = int(load_config("eval")["seed"])
    out_path = tmp_path / "a.json"
    assert L.main(_cli(["--json", str(out_path)])) == 0
    capsys.readouterr()
    assert json.loads(out_path.read_text(encoding="utf-8"))["seed"] == configured
