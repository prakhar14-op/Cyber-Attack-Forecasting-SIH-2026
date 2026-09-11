"""The writer-facing layer of eval/uncertainty.py: `annotate_split`.

The cluster bootstrap ITSELF (percentile exactness, cluster-vs-row width, the
input rejections, `episode_group_ids` at horizon 0) is pinned in
tests/test_metrics.py and is deliberately not restated here. What this file
covers is the one call a results writer makes — that it attaches the intervals
where the results schema expects them, at the threshold the block already
records rather than a refitted one, that a refused interval lands as
`{"unavailable": ...}` rather than a number, and that a writer BUG lands as a
crash rather than as an absent interval.

That distinction is the whole reason the helper exists: `eval/fused.py`,
`eval/forecast.py` and `eval/world.py` each assemble their own result block, and
the headline fused row is a bare AUROC point estimate over 2 attack episodes.
The helper is what makes wiring one of them a single line instead of a
re-implementation that can drift from the harness's.

The horizon section is the other half. A forecasting writer's rows are indexed
at t and labelled for t+k*stride, so the grouping has to follow the label; the
tests there show the two groupings differ, that `annotate_horizon_split` is the
only way to state the shift, and that a block declaring a horizon is refused by
the nowcast entry point.
"""

from __future__ import annotations

import ast
from pathlib import Path

import numpy as np
import pytest

from eval import uncertainty as U

RESAMPLES = 200  # enough for a stable interval; the default 1000 is config-tested


def _synthetic_split(seed: int = 0):
    """Four hosts of 5 s windows, two of them carrying an attack episode.

    Shaped like what a writer holds at the point it would call annotate_split:
    y / score / host / window_start arrays plus the split's episode list.
    """
    rng = np.random.RandomState(seed)
    per_host = 150
    hosts, ws = [], []
    for h in range(4):
        hosts += [f"h{h}"] * per_host
        ws += list(np.arange(per_host, dtype=float) * 5.0)
    host = np.array(hosts)
    window_start = np.array(ws)

    episodes = [{"host": "h0", "start": 100.0, "end": 300.0},
                {"host": "h1", "start": 400.0, "end": 600.0}]
    y = np.zeros(host.size, dtype=np.int8)
    for ep in episodes:
        y[(host == ep["host"]) & (window_start >= ep["start"])
          & (window_start <= ep["end"])] = 1
    score = rng.rand(host.size) * 0.5 + y * 0.35
    return y, score, host, window_start, episodes


def _block(threshold: float, budgets=(0.001, 0.01)) -> dict:
    """A result block in the shape every eval writer builds."""
    return {f"fpr_{b}": {"threshold": threshold, "f1": 0.3, "precision": 0.4,
                         "recall": 0.25, "fpr": b}
            for b in budgets}


# ------------------------------------------------------------ the one-line call

def test_annotate_split_attaches_intervals_where_the_schema_expects_them():
    y, score, host, ws, episodes = _synthetic_split()
    block = _block(threshold=0.6)

    U.annotate_split(block, y, score, host, ws, episodes, n_resamples=RESAMPLES)

    auroc_ci = block["auroc_ci"]
    assert auroc_ci["low"] <= auroc_ci["point"] <= auroc_ci["high"]
    assert auroc_ci["low"] < auroc_ci["high"], "a collapsed band is not a measurement"
    # 2 episodes + 4 host-level clusters; the harness's real number is this small.
    assert auroc_ci["n_groups"] == 6
    assert auroc_ci["n_resamples"] == RESAMPLES and auroc_ci["n_usable"] > 0

    for key in ("fpr_0.001", "fpr_0.01"):
        f1_ci = block[key]["f1_ci"]
        assert f1_ci["low"] <= f1_ci["point"] <= f1_ci["high"]
        assert f1_ci["n_groups"] == 6
    # the point estimates it decorates are untouched
    assert block["fpr_0.01"]["f1"] == 0.3


def test_annotate_split_uses_the_recorded_threshold_and_does_not_refit_one():
    """The block's own threshold fixes the operating point.

    Two blocks differing ONLY in the threshold they record must get different F1
    intervals: a threshold above every score fires on nothing, so F1 is 0 at
    every resample. If the helper refitted the budget inside each resample
    instead, both blocks would come back identical — which is what makes this
    assertion able to fail.
    """
    y, score, host, ws, episodes = _synthetic_split()

    as_reported = _block(threshold=0.6)
    above_every_score = _block(threshold=float(score.max()) + 1.0)
    for block in (as_reported, above_every_score):
        U.annotate_split(block, y, score, host, ws, episodes, n_resamples=RESAMPLES)

    fires = as_reported["fpr_0.01"]["f1_ci"]
    silent = above_every_score["fpr_0.01"]["f1_ci"]
    assert silent["point"] == 0.0 and silent["low"] == 0.0 and silent["high"] == 0.0
    assert fires["point"] > 0.0
    assert fires != silent


def test_annotate_split_records_a_reason_never_a_substituted_bound():
    """One cluster -> the bootstrap refuses; the block must say so in words."""
    n = 40
    host = np.array(["only-host"] * n)
    ws = np.arange(float(n))
    y = (np.arange(n) % 2).astype(np.int8)
    score = np.linspace(0.0, 1.0, n)
    block = _block(threshold=0.5)

    U.annotate_split(block, y, score, host, ws, episodes=[], n_resamples=RESAMPLES)

    for entry in (block["auroc_ci"], block["fpr_0.01"]["f1_ci"]):
        assert set(entry) == {"unavailable"}, entry
        assert ">= 2 groups" in entry["unavailable"]
        assert "low" not in entry and "high" not in entry


def test_annotate_split_honours_a_writers_own_auroc_key():
    # eval/forecast.py names its per-horizon AUROC `auroc_test`, so its interval
    # has to be able to sit beside it rather than under a fixed key.
    y, score, host, ws, episodes = _synthetic_split()
    block = _block(threshold=0.6)
    U.annotate_split(block, y, score, host, ws, episodes,
                     auroc_key="auroc_test_ci", n_resamples=RESAMPLES)
    assert "auroc_test_ci" in block and "auroc_ci" not in block


def test_annotate_split_fails_loudly_on_a_block_it_cannot_honestly_annotate():
    y, score, host, ws, episodes = _synthetic_split()

    with pytest.raises(ValueError, match="no 'fpr_<budget>' operating point"):
        U.annotate_split({"auroc": 0.9}, y, score, host, ws, episodes,
                         n_resamples=RESAMPLES)

    no_threshold = {"fpr_0.01": {"f1": 0.3}}
    with pytest.raises(KeyError, match="records no 'threshold'"):
        U.annotate_split(no_threshold, y, score, host, ws, episodes,
                         n_resamples=RESAMPLES)

    with pytest.raises(ValueError, match="not 'fpr_<budget>'"):
        U._budget_from_key("fpr_one-percent")


def test_interval_or_reason_lets_a_real_exception_through():
    """Only the bootstrap's own refusals become `{"unavailable": ...}`.

    `IntervalUnavailable` is the refusal channel; anything else (a bug in the
    statistic, a missing key, a plain ValueError from input validation) must
    still crash the run rather than be filed as "no interval available".
    """
    def boom(*_a, **_k):
        raise KeyError("this is a bug, not a refusal")

    with pytest.raises(KeyError):
        U.interval_or_reason(boom)

    def refuses(*_a, **_k):
        raise U.IntervalUnavailable("fewer than 2 groups")

    assert U.interval_or_reason(refuses) == {"unavailable": "fewer than 2 groups"}


def test_an_input_validation_bug_is_not_filed_as_an_absent_interval():
    """A writer bug must reach the operator, not the results JSON.

    `f1_at_fpr_interval` rejects an FPR budget outside [0, 1], and the budget
    comes from the key the writer wrote — so a block keyed "fpr_5" (a 500% FPR
    budget: a typo, or a percentage written where a fraction belongs) is a bug
    in the writer, not evidence the data cannot support an interval. Catching
    every ValueError filed it as `{"unavailable": "fpr_budget must lie in
    [0, 1]..."}` beside the genuine refusals, where it reads as an honest
    absence. It must propagate instead.
    """
    y, score, host, ws, episodes = _synthetic_split()
    groups = U.episode_group_ids(host, ws, episodes)

    with pytest.raises(ValueError, match="fpr_budget must lie in"):
        U.interval_or_reason(U.f1_at_fpr_interval, y, score, groups, 5.0,
                             threshold=0.6, n_resamples=RESAMPLES)

    block = {"fpr_5": {"threshold": 0.6, "f1": 0.3}}
    with pytest.raises(ValueError, match="fpr_budget must lie in"):
        U.annotate_split(block, y, score, host, ws, episodes, n_resamples=RESAMPLES)
    assert "f1_ci" not in block["fpr_5"], (
        "the bug was recorded on the block instead of raising")

    # the same channel still reports a GENUINE refusal as an absence
    one_cluster = U.episode_group_ids(np.array(["h"] * y.size), ws, [])
    assert U.interval_or_reason(U.auroc_interval, y, score, one_cluster,
                                n_resamples=RESAMPLES) == {
        "unavailable": "a cluster bootstrap needs >= 2 groups, got 1 — every "
                       "resample would be the original sample"}


def test_every_refusal_the_bootstrap_documents_is_an_intervalunavailable():
    """The three refusal sites, and nothing else, raise the catchable type.

    `interval_or_reason` now catches exactly `IntervalUnavailable`; if a refusal
    site went back to a plain ValueError the writer would crash on a split the
    bootstrap is entitled to decline, and if an input-validation site started
    raising `IntervalUnavailable` the silent-failure hole would reopen.
    """
    y = np.array([0, 1, 0, 1])
    s = np.array([0.1, 0.9, 0.2, 0.8])
    g = np.array([0, 0, 1, 1])

    # refusals
    with pytest.raises(U.IntervalUnavailable, match=">= 2 groups"):
        U.auroc_interval(y, s, np.zeros(4))
    with pytest.raises(U.IntervalUnavailable, match="degenerate on the full sample"):
        U.auroc_interval(np.ones(4), s, g)
    with pytest.raises(U.IntervalUnavailable, match="resamples were degenerate"):
        # both positives live in group 0, so any resample drawing group 1 twice
        # is single-class; seeded so every draw is.
        U.auroc_interval(np.array([1, 1, 0, 0]), s, g, n_resamples=1,
                         seed=_seed_drawing_only(1, n_groups=2))

    # input-validation bugs, which must NOT be catchable as a refusal
    for bad in (
        lambda: U.auroc_interval(y, s[:3], g),
        lambda: U.auroc_interval([], [], []),
        lambda: U.f1_at_fpr_interval(y, s, g, fpr_budget=1.5),
        lambda: U.auroc_interval(y, np.array([0.1, np.nan, 0.2, 0.3]), g),
    ):
        with pytest.raises(ValueError) as exc:
            bad()
        assert not isinstance(exc.value, U.IntervalUnavailable), (
            f"input validation raised the refusal type: {exc.value}")


def _seed_drawing_only(group: int, *, n_groups: int) -> int:
    """A seed whose first `n_groups` draws are all `group`.

    Searched rather than asserted: the RandomState stream is an implementation
    detail, so the test finds a seed that produces the degenerate resample it
    needs instead of hardcoding one that a numpy version could invalidate.
    """
    for seed in range(10_000):
        draws = np.random.RandomState(seed).randint(0, n_groups, n_groups)
        if np.all(draws == group):
            return seed
    raise AssertionError("no seed produced an all-one-group resample")


# ------------------------------------------------------- the horizon-shifted API

# eval/forecast.py and eval/world.py score a row indexed at window_start = t
# against the label at t + k*stride (eval/dataset._shift_target_by_horizon), and
# already account for the shift in lead time via grace_seconds = k*stride. The
# cluster bootstrap has to account for it too, or the rows that carry an
# episode's attack — the ones just BEFORE it starts — land in host-level
# clusters and the interval is computed as if they were independent.

STRIDE = 5.0   # configs/data.yaml windows.stride_seconds
HORIZON = 8    # configs/data.yaml windows.forecast_horizon_windows (K)


def _forecast_split(horizon_windows: int = HORIZON, seed: int = 0):
    """A split shaped like a forecaster's: row at t, label for t + k*stride.

    The episodes are deliberately SHORTER than k*stride, so the rows an episode
    labels (t in [start - k*stride, end - k*stride]) and the rows whose own
    window falls inside [start, end] are disjoint sets. Real episodes run for
    hours and the two sets overlap almost entirely, which is exactly why the
    wrong grouping is invisible in a real run; here there is no overlap for a
    wrong offset to hide in.
    """
    rng = np.random.RandomState(seed)
    per_host, n_hosts = 200, 4
    host = np.array([f"h{h}" for h in range(n_hosts) for _ in range(per_host)])
    ws = np.array([i * STRIDE for _ in range(n_hosts) for i in range(per_host)])

    episodes = [{"host": "h0", "start": 500.0, "end": 530.0},
                {"host": "h1", "start": 700.0, "end": 730.0}]
    labelled_time = ws + horizon_windows * STRIDE
    y = np.zeros(host.size, dtype=np.int8)
    for ep in episodes:
        y[(host == ep["host"]) & (labelled_time >= ep["start"])
          & (labelled_time <= ep["end"])] = 1
    score = rng.rand(host.size) * 0.5 + y * 0.35
    return y, score, host, ws, episodes


def test_episode_grouping_follows_the_label_not_the_window_index():
    y, score, host, ws, episodes = _forecast_split()
    del score

    shifted = U.episode_group_ids(host, ws, episodes,
                                  label_offset_seconds=HORIZON * STRIDE)
    unshifted = U.episode_group_ids(host, ws, episodes)
    in_episode = np.vectorize(lambda g: str(g).startswith("episode:"))

    carries_attack = y == 1
    assert carries_attack.sum() == 14, "2 episodes x 7 labelled windows"
    assert in_episode(shifted[carries_attack]).all(), (
        "a row whose label IS the attack was clustered by host")
    assert not in_episode(unshifted[carries_attack]).any(), (
        "the unshifted grouping put every attack-carrying row in a host cluster "
        "— the bootstrap would treat one episode's correlated rows as "
        "independent draws")
    # and it pulls the wrong rows in: windows inside [start, end] whose own
    # labels, k windows further on, are benign.
    assert in_episode(unshifted).any()
    assert not (in_episode(unshifted) & carries_attack).any()


def test_annotate_horizon_split_reports_a_different_interval_than_the_nowcast_call():
    """The offset reaches the bootstrap, not just the docstring.

    Both calls see identical y/score/host/window_start and the same seed, so the
    ONLY difference is which rows share a cluster. If `annotate_horizon_split`
    ever stopped passing the offset through, these two would be equal — which is
    what makes the assertion able to fail.
    """
    y, score, host, ws, episodes = _forecast_split()

    at_horizon = _block(threshold=0.6)
    U.annotate_horizon_split(at_horizon, y, score, host, ws, episodes,
                             horizon_windows=HORIZON, stride_seconds=STRIDE,
                             n_resamples=RESAMPLES)
    as_nowcast = _block(threshold=0.6)
    U.annotate_split(as_nowcast, y, score, host, ws, episodes,
                     n_resamples=RESAMPLES)

    assert at_horizon["auroc_ci"] != as_nowcast["auroc_ci"]
    assert at_horizon["fpr_0.01"]["f1_ci"] != as_nowcast["fpr_0.01"]["f1_ci"]
    assert at_horizon["auroc_ci"]["low"] <= at_horizon["auroc_ci"]["point"]
    # the block says which grouping produced its intervals
    assert at_horizon[U.HORIZON_KEY] == HORIZON


def test_a_block_declaring_a_horizon_is_refused_by_the_nowcast_entry_point():
    """The second half of the guard: a horizon block cannot be re-annotated flat.

    `annotate_horizon_split` stamps the horizon onto the block, so a later
    `annotate_split` on the same block — a writer that adds a second budget and
    re-runs the helper, say — fails loudly instead of overwriting honest
    intervals with ones built on the nowcast grouping.
    """
    y, score, host, ws, episodes = _forecast_split()
    block = _block(threshold=0.6)
    block[U.HORIZON_KEY] = HORIZON

    with pytest.raises(ValueError, match="zero label offset"):
        U.annotate_split(block, y, score, host, ws, episodes, n_resamples=RESAMPLES)
    assert "auroc_ci" not in block

    # horizon 0 is the nowcast and is not refused
    zero = _block(threshold=0.6)
    zero[U.HORIZON_KEY] = 0
    U.annotate_split(zero, y, score, host, ws, episodes, n_resamples=RESAMPLES)
    assert "auroc_ci" in zero


def test_annotate_horizon_split_at_zero_is_the_nowcast_call():
    y, score, host, ws, episodes = _forecast_split(horizon_windows=0)

    at_zero = _block(threshold=0.6)
    U.annotate_horizon_split(at_zero, y, score, host, ws, episodes,
                             horizon_windows=0, stride_seconds=STRIDE,
                             n_resamples=RESAMPLES)
    flat = _block(threshold=0.6)
    U.annotate_split(flat, y, score, host, ws, episodes, n_resamples=RESAMPLES)

    assert at_zero["auroc_ci"] == flat["auroc_ci"]
    assert at_zero["fpr_0.01"]["f1_ci"] == flat["fpr_0.01"]["f1_ci"]


def test_annotate_horizon_split_will_not_accept_a_horizon_it_cannot_trust():
    y, score, host, ws, episodes = _forecast_split()
    args = (y, score, host, ws, episodes)

    with pytest.raises(ValueError, match="whole number of windows"):
        U.annotate_horizon_split(_block(0.6), *args, horizon_windows=1.5,
                                 stride_seconds=STRIDE, n_resamples=RESAMPLES)
    with pytest.raises(ValueError, match="horizon_windows must be >= 0"):
        U.annotate_horizon_split(_block(0.6), *args, horizon_windows=-1,
                                 stride_seconds=STRIDE, n_resamples=RESAMPLES)
    for bad_stride in (0.0, -5.0, float("nan")):
        with pytest.raises(ValueError, match="stride_seconds must be finite"):
            U.annotate_horizon_split(_block(0.6), *args, horizon_windows=HORIZON,
                                     stride_seconds=bad_stride, n_resamples=RESAMPLES)

    # a block that already declares a DIFFERENT horizon is a wiring bug
    mismatched = _block(0.6)
    mismatched[U.HORIZON_KEY] = 1
    with pytest.raises(ValueError, match="but was annotated at horizon"):
        U.annotate_horizon_split(mismatched, *args, horizon_windows=HORIZON,
                                 stride_seconds=STRIDE, n_resamples=RESAMPLES)

    # the offset itself must be a number, not a stray None/inf
    with pytest.raises(ValueError, match="label_offset_seconds must be finite"):
        U.episode_group_ids(host, ws, episodes, label_offset_seconds=float("inf"))


# --------------------------------------------------------------- harness wiring

def test_the_harness_attaches_intervals_through_this_helper():
    """STRUCTURAL check (AST), not an execution of the harness.

    eval/harness.py's evaluate() needs the CIC-IDS-2018 split on disk and a
    trained model, so the suite cannot run it. What can be pinned without the
    dataset is that the call is still there: round 2 wired the intervals into
    the harness and nothing in the suite would have noticed them being removed.
    """
    src = Path(U.__file__).resolve().parent / "harness.py"
    tree = ast.parse(src.read_text(encoding="utf-8"))
    called = {
        node.func.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
    }
    assert "annotate_split" in called, (
        f"{src} no longer calls uncertainty.annotate_split — the shipped results "
        "JSON would carry bare point estimates over 2 episodes"
    )


def _called_attrs(source: str) -> set[str]:
    return {
        node.func.attr
        for node in ast.walk(ast.parse(source))
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
    }


def _evaluates_a_horizon(source: str) -> bool:
    """True if this source measures lead time with a NON-ZERO grace.

    `grace_seconds = k * stride` is the tell that a writer's labels are shifted:
    it is the same offset, already accounted for in the lead-time metric and
    therefore owed to the cluster grouping as well.
    """
    for node in ast.walk(ast.parse(source)):
        if not isinstance(node, ast.Call):
            continue
        for kw in node.keywords:
            if kw.arg != "grace_seconds":
                continue
            if not (isinstance(kw.value, ast.Constant) and not kw.value.value):
                return True
    return False


def test_a_writer_that_evaluates_a_horizon_never_uses_the_nowcast_annotator():
    """STRUCTURAL check (AST): the grouping must follow the labels, everywhere.

    The detector is exercised on fixtures FIRST. A scan that silently matched
    nothing would pass over the real modules for the wrong reason, and the whole
    point of this file is not to ship a check that cannot fail.
    """
    wrong = ("lt = M.lead_time(eps, alerts, grace_seconds=k * stride)\n"
             "U.annotate_split(block, y, s, h, w, eps)\n")
    right = ("lt = M.lead_time(eps, alerts, grace_seconds=k * stride)\n"
             "U.annotate_horizon_split(block, y, s, h, w, eps,\n"
             "                         horizon_windows=k, stride_seconds=stride)\n")
    nowcast = ("lt = M.lead_time(eps, alerts)\n"
               "U.annotate_split(block, y, s, h, w, eps)\n")

    assert _evaluates_a_horizon(wrong) and _evaluates_a_horizon(right)
    assert not _evaluates_a_horizon(nowcast)
    assert _misgrouped(wrong), "the detector does not flag the bug it exists for"
    assert not _misgrouped(right) and not _misgrouped(nowcast)

    eval_dir = Path(U.__file__).resolve().parent
    for path in sorted(eval_dir.glob("*.py")):
        source = path.read_text(encoding="utf-8")
        assert not _misgrouped(source), (
            f"{path.name} evaluates horizon-shifted targets (grace_seconds is "
            "k*stride) but annotates its intervals with the nowcast helper — the "
            "rows carrying each episode would cluster by host, and the reported "
            "interval would be narrower than the evidence supports. Call "
            "uncertainty.annotate_horizon_split(..., horizon_windows=k, "
            "stride_seconds=stride) instead")


def _misgrouped(source: str) -> bool:
    called = _called_attrs(source)
    return (_evaluates_a_horizon(source)
            and "annotate_split" in called
            and "annotate_horizon_split" not in called)
