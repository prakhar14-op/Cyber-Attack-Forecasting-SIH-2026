"""What a random train/test split is worth on network-attack data.

    python -m eval.leakage_demo                  # synthetic, runs anywhere
    python -m eval.leakage_demo --data cic       # CIC-IDS-2018 (needs the dataset)

CLAUDE.md forbids a random split ("Split by day, never randomly. Whole attack
episodes stay inside one split"). This module is the measurement behind that
rule: it fits the SAME model on the SAME features twice, changing only how the
rows are divided, and reports both scores.

Why the split is the whole ballgame. An attack episode is one host doing one
thing for minutes or hours, sliced into hundreds of overlapping windows that
share a source IP, a destination, a port profile, a packet-size distribution.
Shuffle those rows and put 70% in train and 30% in test, and the test rows are
near-duplicates of rows the model already fitted: it can recognise *this
episode* without learning anything about attacks. Split by day instead, with
whole attack families on one side only, and the model has to transfer to
behaviour it has never seen. The second number is smaller. It is also the only
one that answers the problem statement, which asks for a forecast of the NEXT
attack, not a recall of the last one.

What this module is entitled to claim, and what it is not:

* ENTITLED: "this evaluation design inflates the score, and here is by how much
  on data where we planted the structure and therefore know the answer." The
  synthetic world has a per-episode fingerprint that is memorisable and carries
  zero information about any other episode, plus a weak signal that does
  generalise. The random split can use both; the day-disjoint split can only use
  the second. The gap between them is what the design is worth.
* NOT ENTITLED: any statement about a specific number published by anyone else.
  We have not run anyone else's code, and a high score is not by itself evidence
  of a leaky split — it can also come from an easier dataset or a better model.
  What can be said is what the protocol permits: a number produced under a
  random split and a number produced under a family-disjoint split are not
  comparable quantities, and ours is the second kind.
* NOT ENTITLED: presenting the synthetic figures as a measurement of
  CIC-IDS-2018. `--data cic` is the run that measures that, and it needs the
  dataset; without it this module refuses rather than substituting anything.

The synthetic world's parameters are the DEFINITION of the planted structure,
not knobs tuned against an outcome — every one is on the command line, and
`tests/test_leakage_demo.py` shows the conclusion survives changing them and
disappears when the planted fingerprint is removed. The RNG seed comes from
configs/eval.yaml, never from a literal here.

Nothing is written to results/ unless `--json PATH` asks for it: eval/ablation.py
globs results/*.json and would read a demo file as a model row.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict, dataclass, fields

import numpy as np

from configs import load_config
from eval import metrics as M


#: Independent replicates behind each reported median. Odd on purpose: the
#: median is then an observed replicate rather than the interpolation between
#: two order statistics the project refuses elsewhere (eval/ablation.py's
#: quantile-band rule). One replicate is not a result — a held-out day carries
#: two episodes, and AUROC over two episodes moves by tenths between seeds.
DEFAULT_REPLICATES = 9


#: Typographic punctuation another module may have written, and the ASCII
#: spelling this report prints in its place. Held as code points rather than as
#: the characters themselves so the table survives a re-encoding of this file.
_ASCII_PUNCTUATION = {
    chr(0x2014): "--",   # em dash
    chr(0x2013): "-",    # en dash
    chr(0x2018): "'",    # left single quotation mark
    chr(0x2019): "'",    # right single quotation mark
    chr(0x201C): '"',    # left double quotation mark
    chr(0x201D): '"',    # right double quotation mark
    chr(0x2026): "...",  # horizontal ellipsis
    chr(0x00A0): " ",    # non-breaking space
}


def _console_safe(text: str) -> str:
    """Text written by somebody else, made readable on the console this prints to.

    Every literal in this module is ASCII by hand, but the refusal below QUOTES
    an exception raised elsewhere, and that text is not ours to keep ASCII: the
    key-check message this demo actually triggers carries an em dash. Python on
    Windows prints to a cp1252/cp437 console, where that arrives as a replacement
    glyph, and the report is also pasted into docs. So known punctuation is
    transliterated and anything else is backslash-escaped rather than dropped -
    the reader still gets every word of the cause, which is the whole reason the
    cause is quoted instead of paraphrased.
    """
    for fancy, plain in _ASCII_PUNCTUATION.items():
        text = text.replace(fancy, plain)
    return text.encode("ascii", "backslashreplace").decode("ascii")


class DatasetMissing(RuntimeError):
    """The real-data arm was asked for and the real data is not on this machine.

    Its own type so a caller cannot mistake it for a modelling failure, and so
    the synthetic arm can never be returned in its place — substituting
    synthetic data for missing real data is what CLAUDE.md forbids.
    """


@dataclass(frozen=True)
class WorldSpec:
    """The planted structure the synthetic arm demonstrates on.

    These are not fitted or tuned: they describe a world we are choosing to
    build, and the demonstration is a statement about that world. Read them as
    the experiment's design, the way `episode_windows = 30` is a design choice
    and not a result.

    * `n_days` days, the last of which is the day-disjoint test day — mirroring
      the project's rule that whole attack families live on one side.
    * `episodes_per_day` attack episodes per day, each a contiguous
      `episode_windows` run on one host: the unit a random split tears apart.
    * `n_shared_features` features carry `shared_effect` on every attack row,
      whatever the episode. This is the part a model can legitimately transfer.
    * `n_fingerprint_features` features carry, for each episode, a random
      direction of magnitude `fingerprint_effect` shared by that episode's rows
      and by nothing else. Memorisable within an episode; worth nothing on an
      episode never seen. A linear model cannot extract its magnitude without
      knowing its direction, which is exactly the property being demonstrated.
    * every feature also carries N(0, `noise`).
    """

    n_days: int = 4
    hosts_per_day: int = 12
    windows_per_host: int = 120
    episodes_per_day: int = 2
    episode_windows: int = 30
    n_shared_features: int = 4
    shared_effect: float = 0.5
    n_fingerprint_features: int = 16
    fingerprint_effect: float = 4.0
    noise: float = 1.0

    def validate(self) -> "WorldSpec":
        if self.n_days < 2:
            raise ValueError(
                f"n_days must be >= 2, got {self.n_days}: a day-disjoint split "
                "needs at least one day to hold out")
        if self.episode_windows > self.windows_per_host:
            raise ValueError(
                f"episode_windows ({self.episode_windows}) exceeds "
                f"windows_per_host ({self.windows_per_host})")
        if self.episodes_per_day < 1 or self.episodes_per_day > self.hosts_per_day:
            raise ValueError(
                f"episodes_per_day must lie in [1, hosts_per_day], got "
                f"{self.episodes_per_day}")
        if self.noise <= 0:
            raise ValueError(f"noise must be > 0, got {self.noise}")
        return self


@dataclass(frozen=True)
class ModelSpec:
    """The one model both arms get. Identical on both sides — that is the point.

    Logistic regression on purpose: it is the problem statement's graded
    baseline, and it is linear, so it cannot read a fingerprint's MAGNITUDE
    without having learnt its direction from that same episode. A tree ensemble
    would blur the demonstration by finding the magnitude too.
    """

    C: float = 1.0
    max_iter: int = 2000


@dataclass(frozen=True)
class Comparison:
    """One model, one feature matrix, two ways of cutting the rows.

    Both arms are REPLICATED, and every replicate is kept. A single draw of this
    comparison is close to worthless: a day-disjoint test day carries only a
    couple of episodes, so its AUROC swings by tenths between seeds — the same
    small-n problem the project's own 2-episode results have. The headline is the
    median over replicates and the reported spread is the observed min and max,
    never an interpolated band.
    """

    source: str
    random_aurocs: tuple[float, ...]
    disjoint_aurocs: tuple[float, ...]
    n_train: int
    n_test: int
    n_test_attack: int
    disjoint_rule: str
    replicates: str

    @staticmethod
    def _median(values: tuple[float, ...]) -> float:
        return float(np.median(np.asarray(values, dtype=float)))

    @property
    def random_auroc(self) -> float:
        return self._median(self.random_aurocs)

    @property
    def disjoint_auroc(self) -> float:
        return self._median(self.disjoint_aurocs)

    @property
    def inflation(self) -> float:
        """AUROC the random split adds over the honest one. Not an error bar."""
        return self.random_auroc - self.disjoint_auroc

    def as_dict(self) -> dict:
        d = asdict(self)
        d["random_auroc_median"] = self.random_auroc
        d["disjoint_auroc_median"] = self.disjoint_auroc
        d["inflation"] = self.inflation
        return d


# ------------------------------------------------------------------- the model

def _score_test(X_train, y_train, X_test, model: ModelSpec, seed: int) -> np.ndarray:
    """Fit on (X_train, y_train), return P(attack) on X_test.

    The scaler is fitted on THIS arm's training rows, so each arm is standardised
    against its own training data — the project's train-only rule applied
    identically on both sides, leaving the row split as the only difference
    between them.
    """
    from sklearn.linear_model import LogisticRegression
    from sklearn.preprocessing import StandardScaler

    scaler = StandardScaler().fit(X_train)
    clf = LogisticRegression(
        C=model.C, max_iter=model.max_iter, class_weight="balanced",
        random_state=seed,
    ).fit(scaler.transform(X_train), y_train)
    return clf.predict_proba(scaler.transform(X_test))[:, 1]


def _auroc_or_refuse(y_true: np.ndarray, y_score: np.ndarray, what: str) -> float:
    """AUROC, or a loud refusal — metrics.auroc answers 0.5 for one class.

    That 0.5 is a stated convention, not a measurement, and a demo whose whole
    output is two numbers side by side must not print one of them.
    """
    n_pos = int(np.count_nonzero(y_true))
    if n_pos == 0 or n_pos == y_true.size:
        raise ValueError(
            f"the {what} test rows are single-class ({n_pos} attack of "
            f"{y_true.size}): AUROC is undefined, not 0.5")
    return float(M.auroc(y_true, y_score))


def split_aurocs(
    X: np.ndarray,
    y: np.ndarray,
    day: np.ndarray,
    test_days: set,
    *,
    model: ModelSpec,
    seed: int,
    n_shuffles: int,
) -> tuple[float, tuple[float, ...], int, int, int]:
    """One day-disjoint AUROC, and `n_shuffles` random-split AUROCs beside it.

    `test_days` names the held-out days. Each random split draws a test set of
    the SAME SIZE from the pooled rows, so both arms estimate AUROC on equally
    many rows and the difference cannot be a sample-size artifact. The random
    arm's attack count is whatever the shuffle gives, which is part of the point:
    a random split does not preserve the episode structure it cuts through.

    The disjoint arm has no shuffle to repeat — the split is fixed by the day
    assignment — so it is measured once per world and the caller replicates
    worlds instead.
    """
    X = np.asarray(X, dtype=float)
    y = np.asarray(y).astype(int)
    day = np.asarray(day).astype(str)
    test_days = {str(d) for d in test_days}
    if n_shuffles < 1:
        raise ValueError(f"n_shuffles must be >= 1, got {n_shuffles}")

    held_out = np.isin(day, list(test_days))
    if not held_out.any():
        raise ValueError(f"no row carries a held-out day (asked for {sorted(test_days)})")
    if held_out.all():
        raise ValueError("every row is held out; nothing would be left to train on")

    disjoint = _auroc_or_refuse(
        y[held_out],
        _score_test(X[~held_out], y[~held_out], X[held_out], model, seed),
        "day-disjoint",
    )

    n_test = int(held_out.sum())
    rng = np.random.RandomState(seed)
    randoms = []
    for _ in range(n_shuffles):
        test_rows = rng.permutation(y.size)[:n_test]
        is_random_test = np.zeros(y.size, dtype=bool)
        is_random_test[test_rows] = True
        randoms.append(_auroc_or_refuse(
            y[is_random_test],
            _score_test(X[~is_random_test], y[~is_random_test],
                        X[is_random_test], model, seed),
            "random-split",
        ))

    return (disjoint, tuple(randoms), int((~held_out).sum()), n_test,
            int(np.count_nonzero(y[held_out])))


# --------------------------------------------------------------- synthetic arm

def synthesise(spec: WorldSpec, seed: int):
    """(X, y, day, episode) for the planted world. Episode -1 means benign.

    Every attack row of episode e carries the same fingerprint direction, drawn
    once per episode from an isotropic Gaussian and independently of every other
    episode's — so two directions agree only by coincidence, and in 16 dimensions
    that is rare (tests/test_leakage_demo.py pins the observed worst-case
    overlap). Episodes never cross a day boundary.

    So a model that has seen episode e's rows can identify e's other rows, and
    that ability transfers to no other episode — which is the property a random
    split turns into a score and a day-disjoint split does not.
    """
    spec.validate()
    rng = np.random.RandomState(seed)

    rows_per_day = spec.hosts_per_day * spec.windows_per_host
    n = spec.n_days * rows_per_day
    n_features = spec.n_shared_features + spec.n_fingerprint_features

    day = np.repeat([f"day{d}" for d in range(spec.n_days)], rows_per_day)
    host_of_row = np.tile(
        np.repeat(np.arange(spec.hosts_per_day), spec.windows_per_host), spec.n_days)
    window_of_row = np.tile(
        np.tile(np.arange(spec.windows_per_host), spec.hosts_per_day), spec.n_days)

    y = np.zeros(n, dtype=np.int8)
    episode = np.full(n, -1, dtype=int)
    next_episode = 0
    for d in range(spec.n_days):
        base = d * rows_per_day
        attacker_hosts = rng.choice(spec.hosts_per_day, spec.episodes_per_day,
                                    replace=False)
        for h in attacker_hosts:
            start = int(rng.randint(0, spec.windows_per_host - spec.episode_windows + 1))
            rows = np.flatnonzero(
                (host_of_row == h) & (window_of_row >= start)
                & (window_of_row < start + spec.episode_windows)
            )
            rows = rows[(rows >= base) & (rows < base + rows_per_day)]
            y[rows] = 1
            episode[rows] = next_episode
            next_episode += 1

    X = rng.normal(0.0, spec.noise, size=(n, n_features))
    X[y == 1, : spec.n_shared_features] += spec.shared_effect

    for e in range(next_episode):
        rows = np.flatnonzero(episode == e)
        direction = rng.normal(size=spec.n_fingerprint_features)
        direction /= np.linalg.norm(direction)
        X[np.ix_(rows, np.arange(spec.n_shared_features, n_features))] += (
            spec.fingerprint_effect * direction)

    return X, y, day, episode


def measure_synthetic(spec: WorldSpec, model: ModelSpec, seed: int,
                      n_worlds: int) -> Comparison:
    """The demonstration on data whose answer we planted, so we know it.

    `n_worlds` INDEPENDENT worlds are built (seeds `seed .. seed+n-1`), each
    contributing one day-disjoint AUROC and one random-split AUROC. A single
    world is not a result: its held-out day carries `episodes_per_day` episodes,
    and the AUROC over two episodes swings by tenths. Replicating the world is
    the only honest way to say what the split rule is worth here, and every
    replicate is kept so the reported spread is observed rather than modelled.
    """
    if n_worlds < 1:
        raise ValueError(f"n_worlds must be >= 1, got {n_worlds}")
    spec.validate()

    disjoint, randoms = [], []
    n_train = n_test = n_test_attack = 0
    for world_seed in range(seed, seed + n_worlds):
        X, y, day, _episode = synthesise(spec, world_seed)
        d, r, n_train, n_test, n_test_attack = split_aurocs(
            X, y, day, {f"day{spec.n_days - 1}"},
            model=model, seed=world_seed, n_shuffles=1,
        )
        disjoint.append(d)
        randoms.extend(r)

    return Comparison(
        source="synthetic (planted per-episode fingerprint)",
        random_aurocs=tuple(randoms),
        disjoint_aurocs=tuple(disjoint),
        n_train=n_train, n_test=n_test, n_test_attack=n_test_attack,
        disjoint_rule="last day held out; its episodes appear in no training row",
        replicates=f"{n_worlds} independent worlds, seeds "
                   f"{seed}..{seed + n_worlds - 1}",
    )


# --------------------------------------------------------------- real-data arm

def measure_cic(model: ModelSpec, seed: int, n_shuffles: int) -> Comparison:
    """The same comparison on CIC-IDS-2018. Requires the dataset on this machine.

    Pools the TRAIN and TEST day rows — not val, so the honest arm is exactly the
    shipped train->test evaluation — and cuts that pool twice: by day (the
    project's rule, brute-force + DoS days training, the bot day testing) and at
    random. Features are the 30-column window matrix every model in the harness
    shares (eval/dataset.assemble_split), so the two numbers differ only in which
    rows the model was allowed to see.

    Raises DatasetMissing if the split cannot be assembled, quoting the reason
    rather than naming one: on a machine without the dataset that is a missing
    file, on a machine with it, it is usually the unset anonymisation key. It
    does not fall back to the synthetic arm: those figures describe a world we
    built, and printing them under a CIC heading would be the fabrication this
    project is built to avoid.
    """
    from eval import dataset as D

    cfg = load_config("data")
    try:
        train, scaler = D.assemble_split(cfg, "train", horizon=0, fit_scaler=True)
        test, _ = D.assemble_split(cfg, "test", horizon=0, scaler=scaler)
    except (FileNotFoundError, RuntimeError, OSError) as exc:
        raise DatasetMissing(
            # ASCII only: this text is printed to a console and pasted into
            # docs, and it is the one message a reader sees on a machine that
            # cannot run the real arm.
            "the CIC-IDS-2018 arm could not be prepared on this machine, so it "
            "will not run and will not be approximated. Which of the two "
            "preconditions failed is quoted below rather than guessed at: the "
            "extracted windows and the anonymisation key are both needed, and "
            "reporting the wrong one would send a reader after the wrong fix.\n"
            f"  underlying error: {type(exc).__name__}: {_console_safe(str(exc))}\n"
            "  to produce these numbers:\n"
            "    python -m data.zip_fetch && python -m data.extract\n"
            "    $env:SIH26_HMAC_KEY='<the run key>'\n"
            "    python -m eval.leakage_demo --data cic\n"
            "  until then the CIC row of this comparison is TBD."
        ) from exc

    X = np.vstack([train.X, test.X]).astype(float)
    y = np.concatenate([train.y, test.y]).astype(int)
    # One label per row naming the side it belongs to; the honest arm holds out
    # the test-day rows, which is the shipped split (data/splits.yaml).
    day = np.array(["train-days"] * train.y.size + ["test-days"] * test.y.size)

    disjoint, randoms, n_train, n_test, n_test_attack = split_aurocs(
        X, y, day, {"test-days"}, model=model, seed=seed, n_shuffles=n_shuffles)
    return Comparison(
        source="CIC-IDS-2018 (30-feature window matrix)",
        random_aurocs=randoms,
        disjoint_aurocs=(disjoint,),
        n_train=n_train, n_test=n_test, n_test_attack=n_test_attack,
        disjoint_rule="data/splits.yaml: train days 02-14/02-16, test day 03-02 "
                      "(bot); a family absent from training",
        replicates=f"1 day-disjoint split (fixed by data/splits.yaml) vs "
                   f"{n_shuffles} random shuffles of the same pooled rows",
    )


# ------------------------------------------------------------------- reporting

def _range(values: tuple[float, ...]) -> str:
    """Observed min-max, or a single value when there is only one replicate."""
    if len(values) == 1:
        return f"{values[0]:.3f}"
    return f"{min(values):.3f}-{max(values):.3f}"


def render(comparisons: list[Comparison], cic_note: str | None) -> str:
    """The side-by-side table, plus what is and is not being claimed."""
    lines = [
        "Same model, same features, two ways of splitting the rows",
        "=========================================================",
        "median AUROC over replicates; the spread below is observed, not modelled",
        "",
        f"{'data':<46} {'random':>8} {'disjoint':>9} {'inflation':>10}",
        f"{'-' * 46} {'-' * 8} {'-' * 9} {'-' * 10}",
    ]
    for c in comparisons:
        lines.append(
            f"{c.source:<46} {c.random_auroc:>8.3f} {c.disjoint_auroc:>9.3f} "
            f"{c.inflation:>+10.3f}")
    if cic_note is not None:
        lines.append(f"{'CIC-IDS-2018 (30-feature window matrix)':<46} "
                     f"{'TBD':>8} {'TBD':>9} {'TBD':>10}")
    lines.append("")
    for c in comparisons:
        lines.append(
            f"{c.source}: AUROC on {c.n_test} held-out rows "
            f"({c.n_test_attack} attack) after training on {c.n_train}.")
        lines.append(f"  replicates:    {c.replicates}")
        lines.append(f"  random split:  {_range(c.random_aurocs)} "
                     f"({len(c.random_aurocs)} values)")
        lines.append(f"  disjoint:      {_range(c.disjoint_aurocs)} "
                     f"({len(c.disjoint_aurocs)} values)")
        lines.append(f"  disjoint rule: {c.disjoint_rule}")
    if cic_note is not None:
        lines += ["", "CIC-IDS-2018 row: NOT MEASURED on this machine.", cic_note]
    lines += [
        "",
        "Reading this honestly:",
        "  * 'inflation' is what the RANDOM SPLIT is worth on this data, not an",
        "    error bar and not anyone else's error. Both columns come from the",
        "    same model on the same features.",
        "  * A high published score is not by itself proof of a leaky split: an",
        "    easier dataset or a better model also raise it. What the two columns",
        "    do show is that scores produced under the two rules are different",
        "    quantities and cannot be compared to each other.",
        "  * The synthetic row measures a world whose structure we planted. It is",
        "    a statement about the evaluation design, never about CIC-IDS-2018.",
    ]
    return "\n".join(lines)


def _spec_from_args(cls, args):
    """Build a frozen spec from the parser's namespace (every field is a flag)."""
    return cls(**{f.name: getattr(args, f.name) for f in fields(cls)})


def _add_spec_arguments(parser: argparse.ArgumentParser, cls) -> None:
    # `from __future__ import annotations` makes dataclass field types strings,
    # so the declared default's type is what the flag parses with.
    for f in fields(cls):
        parser.add_argument(f"--{f.name.replace('_', '-')}", dest=f.name,
                            type=type(f.default), default=f.default)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Random split vs day/family-disjoint split, same model.")
    ap.add_argument("--data", choices=("synthetic", "cic", "both"), default="synthetic",
                    help="which arm(s) to run; 'cic' and 'both' need the dataset")
    ap.add_argument("--seed", type=int, default=None,
                    help="RNG seed; defaults to configs/eval.yaml seed")
    ap.add_argument("--replicates", type=int, default=DEFAULT_REPLICATES,
                    help="independent synthetic worlds (and CIC random shuffles) "
                         "to measure; odd, so the median is an observed value")
    ap.add_argument("--json", dest="json_path", default=None,
                    help="also write the report here (NOT into results/, which "
                         "eval/ablation.py globs)")
    _add_spec_arguments(ap, WorldSpec)
    _add_spec_arguments(ap, ModelSpec)
    args = ap.parse_args(argv)

    seed = int(load_config("eval")["seed"]) if args.seed is None else int(args.seed)
    world = _spec_from_args(WorldSpec, args).validate()
    model = _spec_from_args(ModelSpec, args)

    comparisons: list[Comparison] = []
    cic_note: str | None = None
    if args.data in ("synthetic", "both"):
        comparisons.append(measure_synthetic(world, model, seed, args.replicates))
    if args.data in ("cic", "both"):
        try:
            comparisons.append(measure_cic(model, seed, args.replicates))
        except DatasetMissing as exc:
            if args.data == "cic":
                # Asked for the real arm and only the real arm: refuse.
                print(f"eval.leakage_demo: {exc}", file=sys.stderr)
                return 2
            cic_note = str(exc)

    report = render(comparisons, cic_note)
    print(report)
    if args.json_path:
        # Three distinct states, because "measured" must never stand in for "not
        # asked for": a reader of this file has to be able to tell whether the
        # CIC numbers are absent because the arm failed or because it never ran.
        if cic_note:
            cic_status = "TBD"
        elif args.data in ("cic", "both"):
            cic_status = "measured"
        else:
            cic_status = "not requested"
        payload = {
            "seed": seed,
            "world": asdict(world),
            "model": asdict(model),
            "comparisons": [c.as_dict() for c in comparisons],
            "cic": cic_status,
        }
        with open(args.json_path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2)
        print(f"\n-> {args.json_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

