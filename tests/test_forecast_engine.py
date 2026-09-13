"""M13: the K-step forward forecast engine (engine/forecast.py).

The trained artifacts are gitignored and the dataset is not on every machine, so
these drive the REAL engine.forecast.forecast_file — and through it the real
engine.predict.predict_file — with only the four seams that read a trained
artifact stubbed: the per-variant model/scaler loader, the persisted per-horizon
thresholds and model specs, the weight-digest check and TreeSHAP. Feature
extraction, the horizon plumbing, the stage rules, the technique map, the
per-host curve and every write into out_dir are the production path. That is the
same pattern tests/test_engine.py::artifact_free_engine established, for the
same reason: a test that only calls helpers lets the call site rot.

What these pin is the SHARED API CONTRACT (engine/forecast.py <-> app UI), the
per-horizon threshold isolation, and the rule that a horizon with no head is
reported rather than dropped. What they cannot pin is whether the forecast is
any good — that needs the dataset and the harness, and the measured verdict
(no supported forward operating point at any horizon) is in docs/limitations.md
and in engine/forecast.FORWARD_FORECAST_CAVEAT.
"""

from __future__ import annotations

import json

import numpy as np
import pytest

from configs import load_config
from engine import thresholds as TH

# The contract both the engine and the UI workstream build against. Spelled out
# here rather than derived from the implementation: a test that reads the keys
# off the object it is checking cannot catch the object losing one.
CONTRACT_TOP_KEYS = {"horizons", "stride_seconds", "unavailable_horizons",
                     "forecast", "per_host_curve"}
CONTRACT_ENTRY_KEYS = {"host", "window_start", "k", "seconds_ahead", "probability",
                       "stage", "technique", "alert", "threshold"}
CONTRACT_CURVE_KEYS = {"k", "seconds_ahead", "probability", "alert"}
# Everything engine.predict.predict_file returns must survive into the result.
PREDICT_KEYS = {"n_flows", "n_host_windows", "n_alerts", "threshold", "unparsed_frames",
                "hosts_pseudonymised", "forecasts_file", "forecasts", "graph"}

NOWCAST_THRESHOLD = 0.50


def by_k_value(result: dict, k: int) -> tuple[float, bool, float]:
    """(threshold, alert, probability) of the first forecast entry at horizon k."""
    for entry in result["forecast"]:
        if entry["k"] == k:
            return entry["threshold"], entry["alert"], entry["probability"]
    raise AssertionError(f"no forecast entry at k={k}")


def _stub_tables(horizons: list[int]) -> tuple[dict, dict]:
    """Per-horizon (probability, threshold) for the stub heads.

    Every horizon gets a DISTINCT probability, and the first horizon's own
    threshold sits above both its probability and the nowcast threshold, so a
    forecaster that reused the nowcast cut (or another horizon's) would alert
    where this horizon must not. That is the whole point of the table.
    """
    probability, threshold = {}, {}
    for i, k in enumerate(sorted(horizons)):
        probability[k] = max(round(0.80 - 0.20 * i, 2), 0.0)
        threshold[k] = 0.90 if i == 0 else 0.50
    return probability, threshold


class _Head:
    """Constant-probability stand-in for one persisted XGBoost head. Doubles as
    the persisted scaler (`transform`), which the real loader returns alongside
    it and which is identical across horizons."""

    def __init__(self, probability: float):
        self.probability = float(probability)

    def transform(self, X):
        return X

    def _probs(self, X) -> np.ndarray:
        return np.full(len(X), self.probability)

    def predict_proba(self, X):
        p = self._probs(X)
        return np.column_stack([1.0 - p, p])


class _NowcastHead(_Head):
    """The horizon-0 head: exactly one host-window above NOWCAST_THRESHOLD, so
    the nowcast alert path is exercised without alerting on every row."""

    def __init__(self):
        super().__init__(0.10)

    def _probs(self, X) -> np.ndarray:
        p = np.full(len(X), 0.10)
        if len(p):
            p[0] = 0.99
        return p


# Width of the per-row probability spread used by _RowVaryingHead. Wide enough
# that two source windows of one host are unmistakably different numbers, narrow
# enough that a horizon's band still cannot reach its neighbour's (the stub
# bases are 0.20 apart, see _stub_tables) or leave [0, 1].
_ROW_PROBABILITY_SPAN = 0.20


class _RowVaryingHead(_Head):
    """A head whose probability varies with the POSITION of the source row in
    the matrix it is handed, so two source windows of the SAME host score
    differently at the same horizon.

    Every other test here uses the constant-probability `_Head`, which is what
    the per-horizon isolation tests need — but under a constant, a host's newest
    and oldest source windows produce byte-identical forecast entries, and which
    one `per_host_curve` picks is unobservable. This head is the only condition
    under which that property can be tested at all.

    The spread is a strictly increasing function of the row index and nothing
    else; the test never assumes which index is the newest window, it reads
    (window_start, probability) off the forecast entries themselves.
    """

    def _probs(self, X) -> np.ndarray:
        n = len(X)
        if not n:
            return np.empty(0, dtype=float)
        steps = (np.arange(n, dtype=float) + 1.0) / (n + 1.0)
        return self.probability + _ROW_PROBABILITY_SPAN * steps


class _StubShap:
    """Stands in for TreeSHAP, which needs a real booster. Still returns NAMED
    features, so predict_file's output schema is applied for real."""

    def __init__(self, model, feature_names):
        self.feature_names = feature_names

    def top_features(self, X, k: int = 5):
        return [[{"feature": n, "value": 0.0, "contribution": 0.0}
                 for n in self.feature_names[:k]] for _ in range(len(X))]


class _StubArtifacts:
    """The artifacts/ directory this machine does not have.

    Resolves a persisted-variant key ('flow', 'flow_k4', ...) back to its
    horizon through engine.thresholds.horizon_variant — the same function the
    trainer and the forecaster spell keys with, so a test cannot pass by
    agreeing with itself on a spelling the production code does not use.

    `drop_spec`/`drop_threshold`/`drop_weights` remove one horizon the way the
    three real failure modes do.
    """

    def __init__(self):
        cfg = load_config("data")
        self.horizons = [int(k) for k in cfg["engine"]["forecast_horizons"]]
        probability, threshold = _stub_tables(self.horizons)
        self.probability = probability
        self.threshold = {0: NOWCAST_THRESHOLD, **threshold}
        self.key_to_k = {TH.horizon_variant(base, k): k
                         for base in ("full", "flow") for k in [0, *self.horizons]}
        self.no_spec: set[int] = set()
        self.no_threshold: set[int] = set()
        self.no_weights: set[int] = set()
        # When set, the horizon-0 head alerts on EVERY window instead of one, so
        # the nowcast's emitted forecasts.json covers every k-step source window
        # and the two can be compared entry-for-entry.
        self.nowcast_alerts_everywhere = False
        # When set, the k>0 heads return a DIFFERENT probability per source row
        # instead of one constant per horizon, so a host's newest and oldest
        # source windows are distinguishable in the output. Only the
        # per_host_curve freshness test needs this; the per-horizon isolation
        # tests need the constant.
        self.per_window_probability = False

    def drop_spec(self, k: int) -> None:
        self.no_spec.add(int(k))

    def drop_threshold(self, k: int) -> None:
        self.no_threshold.add(int(k))

    def drop_weights(self, k: int) -> None:
        self.no_weights.add(int(k))

    def _horizon_of(self, variant: str) -> int:
        if variant not in self.key_to_k:
            raise KeyError(f"no '{variant}' engine model persisted (stub)")
        return self.key_to_k[variant]

    def load_model_spec(self, cfg, variant: str) -> dict:
        k = self._horizon_of(variant)
        if k in self.no_spec:
            raise KeyError(f"no '{variant}' engine model persisted (stub)")
        return {"file": f"stub_{variant}.json", "val_auroc": 0.5, "horizon": k}

    def load_threshold(self, cfg, fpr_budget, variant: str = "full") -> float:
        k = self._horizon_of(variant)
        if k in self.no_spec:
            raise KeyError(f"no '{variant}' engine model persisted (stub)")
        if k in self.no_threshold:
            raise KeyError(f"no persisted threshold for {variant}/fpr_{fpr_budget} (stub)")
        return self.threshold[k]

    def load_engine(self, cfg, variant: str):
        k = self._horizon_of(variant)
        if k in self.no_weights:
            raise FileNotFoundError(f"artifacts/stub_{variant}.json missing (stub)")
        if k != 0:
            factory = _RowVaryingHead if self.per_window_probability else _Head
            head = factory(self.probability[k])
        elif self.nowcast_alerts_everywhere:
            head = _Head(0.99)
        else:
            head = _NowcastHead()
        return head, head, f"stub_{variant}.json"


@pytest.fixture
def stub_artifacts(monkeypatch):
    """Run the REAL forecast_file on a machine with no artifacts/."""
    import pathlib
    import sys

    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "scripts"))
    import verify_weights as VW

    from engine import explain as EX
    from engine import predict as P

    state = _StubArtifacts()
    monkeypatch.setattr(P, "_load_engine", state.load_engine)
    monkeypatch.setattr(TH, "load_model_spec", state.load_model_spec)
    monkeypatch.setattr(TH, "load_threshold", state.load_threshold)
    monkeypatch.setattr(VW, "verify", lambda *a, **k: (True, None))
    monkeypatch.setattr(EX, "ShapExplainer", _StubShap)
    return state


# --------------------------------------------------------------------------
# config + key-spelling guards (no run needed)
# --------------------------------------------------------------------------

def test_engine_horizons_are_a_subset_of_the_evaluated_ones():
    """A horizon the engine SHIPS a head for must be a horizon the harness
    reports. Shipping k=2 because it is cheap to fit, while the published
    forecast table only covers k=1/4/8, would be a capability with no evidence
    behind it — the exact overclaim shape this project keeps removing."""
    shipped = [int(k) for k in load_config("data")["engine"]["forecast_horizons"]]
    evaluated = [int(k) for k in load_config("eval")["horizons"]]

    assert shipped, "engine.forecast_horizons is empty — the engine would ship no forecast"
    assert all(k > 0 for k in shipped), "horizon 0 is the nowcast, not a forward horizon"
    extra = sorted(set(shipped) - set(evaluated))
    assert not extra, (
        f"configs/data.yaml engine.forecast_horizons ships {extra}, which configs/eval.yaml "
        f"`horizons` ({evaluated}) does not evaluate: the engine would serve a forward "
        "horizon whose forecast quality has never been measured"
    )


def test_horizon_variant_keys_are_distinct_per_horizon():
    """k=8's threshold must not be reachable under k=0's key. horizon_variant is
    the single place those keys are spelled, so this is where that is pinned."""
    assert TH.horizon_variant("full", 0) == "full"
    assert TH.horizon_variant("flow", 0) == "flow"
    assert TH.horizon_variant("full", 4) == "full_k4"
    assert TH.horizon_variant("flow", 8) == "flow_k8"

    keys = [TH.horizon_variant("flow", k) for k in (0, 1, 4, 8)]
    assert len(set(keys)) == len(keys), f"horizon keys collide: {keys}"
    # a variant's keys never collide with another variant's
    assert TH.horizon_variant("full", 4) != TH.horizon_variant("flow", 4)

    with pytest.raises(ValueError, match="non-negative int"):
        TH.horizon_variant("full", -1)
    with pytest.raises(ValueError, match="non-negative int"):
        TH.horizon_variant("full", 1.5)


def test_forecast_caveat_states_the_measured_limit():
    """The honesty constraint, as a test. The caveat travels with the data so a
    UI can put it in front of the viewer; deleting or softening the measured
    finding inside it must break the build, not just a code review."""
    from engine.forecast import FORWARD_FORECAST_CAVEAT as caveat

    lowered = caveat.lower()
    assert "0 of 2" in lowered, "the caveat must state the measured episode count"
    assert "ranking" in lowered, "the caveat must say the signal is ranking-only"
    assert "horizon-0" in lowered, (
        "the caveat must attribute the claimed lead time to the horizon-0 classifier"
    )
    assert "not a validated" in lowered or "not validated" in lowered


def test_predict_file_fills_the_documented_scoring_context(stub_artifacts, fixture_csv,
                                                           tmp_path):
    """engine/forecast.py reuses predict_file's extracted features through the
    `scoring_context` out-parameter instead of re-extracting them. Renaming a key
    on one side and not the other would leave the forecaster scoring nothing, so
    the documented key list is pinned against what predict_file actually fills."""
    from engine import predict as P

    context: dict = {}
    result = P.predict_file(fixture_csv, out_dir=tmp_path, scoring_context=context)

    assert set(context) == set(P.SCORING_CONTEXT_KEYS), (
        f"predict_file filled {sorted(context)} but SCORING_CONTEXT_KEYS documents "
        f"{sorted(P.SCORING_CONTEXT_KEYS)}"
    )
    assert len(context["wf"]) == result["n_host_windows"]
    assert context["X"].shape == (result["n_host_windows"], len(context["feature_columns"]))
    assert context["variant"] == "flow", "a CSV input scores through the flow-only head"
    # the out-parameter must not leak into the dict that is persisted as run_summary.json
    assert "scoring_context" not in result and "wf" not in result


# --------------------------------------------------------------------------
# the shared API contract
# --------------------------------------------------------------------------

def test_forecast_file_returns_the_shared_contract_shape(stub_artifacts, fixture_csv,
                                                         tmp_path):
    """The shape engine/forecast.py and the UI workstream both build against."""
    from engine import forecast

    result = forecast.forecast_file(fixture_csv, out_dir=tmp_path)

    missing = CONTRACT_TOP_KEYS - set(result)
    assert not missing, f"the contract keys {sorted(missing)} are absent from the result"
    assert PREDICT_KEYS <= set(result), (
        f"forecast_file dropped predict_file keys {sorted(PREDICT_KEYS - set(result))}"
    )
    assert result["horizons"] == sorted(stub_artifacts.horizons)
    assert result["stride_seconds"] == float(
        load_config("data")["windows"]["stride_seconds"])
    assert result["unavailable_horizons"] == {}, "every stubbed horizon is available"
    assert result["forecast"], "the forecast is empty on an input the nowcast scored"

    hosts = set()
    for entry in result["forecast"]:
        assert set(entry) == CONTRACT_ENTRY_KEYS, (
            f"forecast entry keys {sorted(entry)} != contract {sorted(CONTRACT_ENTRY_KEYS)}"
        )
        assert entry["k"] in result["horizons"]
        assert 0.0 <= entry["probability"] <= 1.0
        assert isinstance(entry["alert"], bool)
        assert entry["technique"] is None or isinstance(entry["technique"], str)
        hosts.add(entry["host"])

    # one entry per (host, source window, k)
    triples = {(e["host"], e["window_start"], e["k"]) for e in result["forecast"]}
    assert len(triples) == len(result["forecast"]), "duplicate (host, window, k) entries"

    assert set(result["per_host_curve"]) == hosts
    for points in result["per_host_curve"].values():
        assert [p["k"] for p in points] == result["horizons"], "curve is k-ascending"
        for point in points:
            assert set(point) == CONTRACT_CURVE_KEYS


def test_seconds_ahead_is_k_times_the_configured_stride(stub_artifacts, fixture_csv,
                                                        tmp_path):
    """The one arithmetic claim the forward curve makes. A window is 15 s on a
    5 s stride, so multiplying by the WINDOW would overstate every horizon by 3x
    — and the number is what an operator reads off the axis."""
    from engine import forecast

    cfg = load_config("data")
    stride = float(cfg["windows"]["stride_seconds"])
    assert stride != float(cfg["windows"]["window_seconds"]), (
        "this test cannot distinguish stride from window while they are equal"
    )

    result = forecast.forecast_file(fixture_csv, out_dir=tmp_path)
    assert result["stride_seconds"] == stride
    for entry in result["forecast"]:
        assert entry["seconds_ahead"] == entry["k"] * stride, (
            f"k={entry['k']} claims {entry['seconds_ahead']}s ahead, not {entry['k'] * stride}s"
        )
    for points in result["per_host_curve"].values():
        for point in points:
            assert point["seconds_ahead"] == point["k"] * stride


def test_each_horizon_alerts_against_its_own_threshold(stub_artifacts, fixture_csv,
                                                       tmp_path):
    """A horizon's alert decision uses ITS OWN persisted threshold.

    The stub gives the first horizon a cut ABOVE the nowcast cut and above its
    own probability: a forecaster that reused the nowcast threshold — or any
    other horizon's — would alert there. Reusing one threshold across horizons is
    silent by construction (the numbers still look like probabilities), which is
    why it is pinned here rather than left to review.
    """
    from engine import forecast

    result = forecast.forecast_file(fixture_csv, out_dir=tmp_path)
    by_k = {}
    for entry in result["forecast"]:
        by_k.setdefault(entry["k"], set()).add((entry["threshold"], entry["alert"],
                                                entry["probability"]))

    assert set(by_k) == set(stub_artifacts.horizons)
    for k, seen in by_k.items():
        assert len(seen) == 1, f"k={k} used more than one threshold: {seen}"
        threshold, alert, probability = seen.pop()
        own = stub_artifacts.threshold[k]
        assert threshold == own, f"k={k} alerted against {threshold}, not its own {own}"
        assert alert is (probability >= threshold)

    first = min(stub_artifacts.horizons)
    first_threshold, first_alert, first_probability = by_k_value(result, first)
    assert first_threshold != NOWCAST_THRESHOLD, "stub table is degenerate"
    assert first_alert is False
    assert first_probability >= NOWCAST_THRESHOLD, (
        "the stub must place the first horizon's probability above the NOWCAST cut, "
        "so borrowing that cut would visibly flip this alert"
    )
    # and the horizons genuinely disagree, so a shared threshold would show up
    assert len({stub_artifacts.threshold[k] for k in stub_artifacts.horizons}) > 1


def test_each_horizon_is_scored_by_its_own_head(stub_artifacts, fixture_csv, tmp_path):
    """...and by its own MODEL, not the nowcast's. Every stub head returns a
    distinct constant, so a forecaster that scored every horizon through one
    booster would return one probability for all of them."""
    from engine import forecast

    result = forecast.forecast_file(fixture_csv, out_dir=tmp_path)
    seen = {e["k"]: e["probability"] for e in result["forecast"]}
    assert seen == {k: stub_artifacts.probability[k] for k in stub_artifacts.horizons}
    assert len(set(seen.values())) == len(seen), "all horizons returned the same score"


def test_source_windows_are_the_newest_and_are_capped_by_config(stub_artifacts,
                                                                fixture_csv, tmp_path):
    """The forecast is made from each host's NEWEST windows, capped by config.

    This says nothing about which of those windows `per_host_curve` is drawn
    from. It cannot: under the constant-probability stub head every source
    window of a host produces an identical entry. That property has its own
    test, test_per_host_curve_is_drawn_from_each_hosts_newest_source_window,
    which switches to a head that varies per source row. This docstring used to
    claim the curve property as well, and the claim was the reason inverting
    `_per_host_curve` left the whole suite green.
    """
    from engine import forecast
    from engine import predict as P

    cfg = load_config("data")
    cap = int(cfg["engine"]["forecast_source_windows_per_host"])
    context: dict = {}
    P.predict_file(fixture_csv, out_dir=tmp_path / "base", scoring_context=context)
    wf = context["wf"]

    result = forecast.forecast_file(fixture_csv, out_dir=tmp_path / "fc")
    per_host: dict[str, set[float]] = {}
    for entry in result["forecast"]:
        per_host.setdefault(entry["host"], set()).add(entry["window_start"])

    for host, windows in per_host.items():
        every = wf.loc[wf["host"].astype(str) == host, "window_start"].astype(float)
        assert len(windows) <= cap, f"{host} forecast from {len(windows)} windows > cap {cap}"
        assert windows == set(sorted(every)[-cap:]), f"{host} did not use its NEWEST windows"
        # the newest window is scored at EVERY served horizon, so the curve has
        # a complete set of points available to be built from
        newest = max(windows)
        at_newest = {e["k"] for e in result["forecast"]
                     if e["host"] == host and e["window_start"] == newest}
        assert at_newest == set(result["horizons"]), (
            f"{host}'s newest source window ({newest}) was scored at {sorted(at_newest)}, "
            f"not at every served horizon {result['horizons']}"
        )

    # at least one host must actually hit the cap, or the cap is untested here
    assert any(len(w) == cap for w in per_host.values()), (
        f"no host in the fixture has more than {cap} windows — the cap is not exercised"
    )


def test_per_host_curve_is_drawn_from_each_hosts_newest_source_window(
        stub_artifacts, fixture_csv, tmp_path):
    """`per_host_curve` must carry the host's NEWEST source window, and no other.

    The engine forecasts from up to `forecast_source_windows_per_host` windows
    per host (12 at the shipped config). The app draws its risk curve from
    `per_host_curve` alone, and a curve point carries no `window_start` — so a
    curve built from a host's OLDEST source window is a curve about traffic up
    to (cap - 1) * stride seconds old, drawn as if it were current, with nothing
    on screen to say otherwise. Nothing crashes, no reason string appears, and
    the degradation is silent.

    Under the constant-probability `_Head` every other test uses, a host's
    newest and oldest source windows produce identical entries, so inverting the
    comparison in `_per_host_curve` changes no output at all. This test switches
    to `_RowVaryingHead` for exactly that reason, and asserts BOTH halves: the
    curve equals the newest window's points, AND it differs from the oldest
    window's — the second half is what stops the test from passing on a curve
    built from either.
    """
    from engine import forecast

    stub_artifacts.per_window_probability = True
    result = forecast.forecast_file(fixture_csv, out_dir=tmp_path)

    def curve_point(entry: dict) -> dict:
        """The projection of a forecast entry that per_host_curve carries."""
        return {key: entry[key] for key in CONTRACT_CURVE_KEYS}

    # host -> window_start -> k -> entry
    entries: dict[str, dict[float, dict[int, dict]]] = {}
    for entry in result["forecast"]:
        entries.setdefault(entry["host"], {}).setdefault(
            entry["window_start"], {})[entry["k"]] = entry

    assert result["horizons"], "no horizon is served — there is no curve to check"
    assert set(result["per_host_curve"]) == set(entries)
    multi = sorted(host for host, w in entries.items() if len(w) > 1)
    assert multi, (
        "no host in this fixture was forecast from two source windows, so its "
        "newest and oldest window are the same one and this test cannot tell a "
        "fresh curve from a stale one"
    )

    for host, windows in entries.items():
        newest, oldest = max(windows), min(windows)
        curve = result["per_host_curve"][host]
        assert [point["k"] for point in curve] == result["horizons"]
        for point in curve:
            k = point["k"]
            assert point == curve_point(windows[newest][k]), (
                f"{host}: the k={k} curve point does not come from the newest "
                f"source window ({newest}); it matches source window(s) "
                f"{[w for w in sorted(windows) if curve_point(windows[w][k]) == point]}"
                " — the app would draw a stale window as the current risk"
            )
            if host in multi:
                assert point != curve_point(windows[oldest][k]), (
                    f"{host}: the newest ({newest}) and oldest ({oldest}) source "
                    f"windows scored identically at k={k}, so this test would pass "
                    "on a curve built from either — the stub head is no longer "
                    "varying per source row"
                )


def test_per_host_curve_picks_the_later_window_of_two():
    """The same property stated directly on the helper, with no dataset.

    The end-to-end test above can only run where the fixture happens to give
    some host two source windows; this one states the rule unconditionally, so
    the newest-window selection stays pinned even on a thinner fixture.
    """
    from engine.forecast import _per_host_curve

    def entry(host: str, window_start: float, k: int, probability: float) -> dict:
        return {"host": host, "window_start": window_start, "k": k,
                "seconds_ahead": 5.0 * k, "probability": probability,
                "alert": probability >= 0.5, "stage": "benign", "technique": None,
                "threshold": 0.5}

    # deliberately not in window or k order, so the helper's own ordering is used
    curve = _per_host_curve([
        entry("a", 10.0, 4, 0.20), entry("a", 35.0, 1, 0.90),
        entry("a", 10.0, 1, 0.10), entry("a", 35.0, 4, 0.80),
        entry("b", 0.0, 1, 0.30),
    ])

    assert set(curve) == {"a", "b"}
    assert [point["k"] for point in curve["a"]] == [1, 4], "the curve is k-ascending"
    assert [point["probability"] for point in curve["a"]] == [0.90, 0.80], (
        "host 'a' curve was built from window_start=10.0, the OLDER of its two "
        "source windows, instead of 35.0"
    )
    assert [point["alert"] for point in curve["a"]] == [True, True]
    assert [point["probability"] for point in curve["b"]] == [0.30]
    assert set(curve["a"][0]) == CONTRACT_CURVE_KEYS


@pytest.mark.parametrize("n_source", [0, -1])
def test_a_source_window_cap_below_one_is_refused_before_the_run(
        fixture_csv, tmp_path, monkeypatch, n_source):
    """`engine.forecast_source_windows_per_host` < 1 must fail LOUDLY.

    A cap of 0 is not a smaller forecast, it is no forecast. Measured with the
    guard removed, on the bundled fixture (2080 host-windows): `forecast` comes
    back [], `per_host_curve` {}, `unavailable_horizons` {} — and `horizons`
    still [1, 4, 8]. Nothing raises, and the app then draws its empty-curve
    copy, which says the forecaster "returned no usable per-host risk curve for
    this input" and that this "is not a panel that failed" — a statement about
    the capture, when the cause is one config line. The engine refuses instead,
    and refuses BEFORE predict_file runs, so a misconfigured cap costs a message
    rather than a full nowcast.

    The enforcement existed with no test behind it, which meant deleting the
    three lines would have left the suite green.
    """
    from engine import forecast
    from engine import predict as P

    real_load_config = forecast.load_config

    def patched_load_config(name: str) -> dict:
        cfg = real_load_config(name)
        if name == "data":
            cfg["engine"] = {**cfg["engine"],
                             "forecast_source_windows_per_host": n_source}
        return cfg

    def predict_file_must_not_run(*args, **kwargs):
        raise AssertionError(
            "predict_file ran under a source-window cap of "
            f"{n_source}: the cap is validated too late, or not at all"
        )

    monkeypatch.setattr(forecast, "load_config", patched_load_config)
    monkeypatch.setattr(P, "predict_file", predict_file_must_not_run)

    with pytest.raises(ValueError) as raised:
        forecast.forecast_file(fixture_csv, out_dir=tmp_path)

    message = str(raised.value)
    assert "forecast_source_windows_per_host" in message, (
        f"the error does not name the setting to fix: {message!r}"
    )
    assert "configs/data.yaml" in message, (
        f"the error does not name the file to fix it in: {message!r}"
    )
    assert str(n_source) in message, (
        f"the error does not quote the offending value {n_source}: {message!r}"
    )
    assert not (tmp_path / forecast.FORECAST_FILE).exists(), (
        "a run that refused to forecast still wrote a k-step block"
    )


def test_stage_and_technique_come_from_the_shared_mapping(stub_artifacts, fixture_csv,
                                                          tmp_path, monkeypatch):
    """The forecast must not fork the stage rules or the MITRE map.

    Two halves: the values agree with a direct call on the same source window,
    AND redirecting the shared functions redirects the forecast — a forked copy
    would keep returning the real mapping and pass the first half alone. BOTH
    the stage rules and the MITRE map are redirected, because a fork of either
    one drifts from the nowcast independently of the other.
    """
    from engine import explain as EX
    from engine import forecast
    from engine import predict as P

    cfg = load_config("data")
    context: dict = {}
    P.predict_file(fixture_csv, out_dir=tmp_path / "base", scoring_context=context)
    wf, feat_cols = context["wf"], context["feature_columns"]
    rows = {(str(h), float(w)): i
            for i, (h, w) in enumerate(zip(wf["host"], wf["window_start"]))}

    result = forecast.forecast_file(fixture_csv, out_dir=tmp_path / "fc")
    stages = set()
    for entry in result["forecast"]:
        source = wf.iloc[rows[(entry["host"], entry["window_start"])]]
        feats = {c: float(source[c]) for c in feat_cols}
        expected_stage = P._infer_stage(feats, cfg["stage_rules"])
        assert entry["stage"] == expected_stage
        assert entry["technique"] == EX.map_technique(expected_stage, feats)["technique"]
        stages.add(entry["stage"])
    assert stages <= {*cfg["stages"], P.UNCLASSIFIED_STAGE}

    # A stage the rules did NOT produce on this fixture, so the redirect is
    # detectable — but still a real one, because predict.OUTPUT_SCHEMA enforces
    # the stage enum and a synthetic value would fail validation instead of
    # proving anything. (That enum is also why this redirect is proof the
    # forecast shares _infer_stage with predict_file rather than copying it.)
    unobserved = next(s for s in cfg["stages"] if s not in stages)
    monkeypatch.setattr(EX, "map_technique",
                        lambda stage, feats: {"technique": "T9999", "name": "redirected"})
    monkeypatch.setattr(P, "_infer_stage", lambda feats, rules: unobserved)
    redirected = forecast.forecast_file(fixture_csv, out_dir=tmp_path / "redirected")
    assert {e["technique"] for e in redirected["forecast"]} == {"T9999"}, (
        "the forecast does not go through engine.explain.map_technique — it has a "
        "forked copy of the MITRE mapping, which will drift from the nowcast's"
    )
    assert {e["stage"] for e in redirected["forecast"]} == {unobserved}, (
        "the forecast does not go through engine.predict._infer_stage — it has a "
        "forked copy of the stage rules, which will drift from the nowcast's"
    )


def test_forecast_stage_matches_the_nowcast_emitted_for_the_same_window(
        stub_artifacts, fixture_csv, tmp_path):
    """The stronger form of the previous test: agreement ON THE WIRE.

    The previous test compares the forecast against a direct call to the shared
    helpers. This one compares it against what the NOWCAST ACTUALLY EMITTED for
    the same (host, window) in forecasts.json — the artifact a judge opens. If
    the two ever disagreed, the UI would show one stage in the alert table and a
    different one on the forward curve for the same window, and each half would
    still pass its own unit test.
    """
    from engine import forecast

    stub_artifacts.nowcast_alerts_everywhere = True
    result = forecast.forecast_file(fixture_csv, out_dir=tmp_path)

    on_the_wire = json.loads(
        (tmp_path / "forecasts.json").read_text(encoding="utf-8"))
    nowcast = {(e["host"], e["window_start"]): (e["stage"], e["technique"])
               for e in on_the_wire}
    assert nowcast, "the nowcast emitted no forecasts.json entries to compare against"

    compared = 0
    for entry in result["forecast"]:
        key = (entry["host"], entry["window_start"])
        if key not in nowcast:
            continue
        assert (entry["stage"], entry["technique"]) == nowcast[key], (
            f"{key}: the forward curve says {entry['stage']}/{entry['technique']} "
            f"while the nowcast alert says {nowcast[key][0]}/{nowcast[key][1]}"
        )
        compared += 1
    # every source window must be covered, or this test compared nothing
    assert compared == len(result["forecast"]), (
        f"only {compared} of {len(result['forecast'])} forecast entries had a "
        "nowcast entry to compare against"
    )


def test_the_kstep_heads_are_outside_the_weight_provenance_binding(stub_artifacts):
    """engine/forecast.py's docstring states that the M9.3 weight-digest binding
    does NOT cover the per-horizon heads, and that this is why no k-step record
    is ledgered. That is a claim about another module, so it is pinned here.

    If someone adds the k-step weights to verify_weights.TRACKED, this fails —
    and the right response is to make forecast.py verify them and revisit the
    ledger decision, not to edit the docstring. Filenames come from
    train_engine.head_filename, so the test cannot pass by agreeing with itself
    on a spelling the trainer does not use.
    """
    import pathlib
    import sys

    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "scripts"))
    import verify_weights as VW

    from engine import forecast
    from engine.train_engine import head_filename

    nowcast = [head_filename(tag, 0) for tag in ("full", "flow")]
    kstep = [head_filename(tag, k) for tag in ("full", "flow")
             for k in stub_artifacts.horizons]

    assert set(nowcast) <= set(VW.TRACKED), (
        f"the horizon-0 heads {nowcast} are no longer digest-tracked — "
        "engine/predict.py's ledger provenance claim (M9.3) is broken"
    )
    assert not (set(kstep) & set(VW.TRACKED)), (
        f"{sorted(set(kstep) & set(VW.TRACKED))} is now digest-tracked, so "
        "engine/forecast.py's stated reason for not ledgering k-step records "
        "('the per-horizon heads are not among them') is now false"
    )
    assert "no k-step record is written to the tamper-evident ledger" in (
        forecast.__doc__.lower()), (
        "the module docstring no longer states the k-step ledger exclusion"
    )


# --------------------------------------------------------------------------
# missing horizons are reported, never dropped
# --------------------------------------------------------------------------

@pytest.mark.parametrize("failure,fragment", [
    ("drop_spec", "has been fitted"),
    ("drop_weights", "weight file"),
    ("drop_threshold", "threshold"),
])
def test_an_unavailable_horizon_is_reported_not_silently_dropped(
        stub_artifacts, fixture_csv, tmp_path, failure, fragment):
    """Silence is never safety. A horizon whose head was never fitted, whose
    weight file is gone, or which has no threshold at this budget must appear in
    `unavailable_horizons` with a reason an operator can act on — not simply be
    absent from `horizons`, which reads as "nothing to worry about at k=8"."""
    from engine import forecast

    gone = max(stub_artifacts.horizons)
    getattr(stub_artifacts, failure)(gone)

    result = forecast.forecast_file(fixture_csv, out_dir=tmp_path)

    assert gone not in result["horizons"]
    assert gone in result["unavailable_horizons"], (
        f"k={gone} has no head and no reason — it vanished from the output entirely"
    )
    reason = result["unavailable_horizons"][gone]
    assert f"k={gone}" in reason and fragment in reason
    assert "train_engine" in reason, "the reason must name the command that fixes it"
    assert len(reason.split()) >= 10, f"not a plain-English reason: {reason!r}"

    # the surviving horizons still forecast, and nothing claims the missing one
    survivors = sorted(set(stub_artifacts.horizons) - {gone})
    assert result["horizons"] == survivors
    assert {e["k"] for e in result["forecast"]} == set(survivors)
    for points in result["per_host_curve"].values():
        assert [p["k"] for p in points] == survivors


def test_every_configured_horizon_is_either_served_or_explained(stub_artifacts,
                                                                fixture_csv, tmp_path):
    """The partition property behind the previous test: served + unavailable
    covers the configured list exactly, with no overlap and nothing invented."""
    from engine import forecast

    wanted = set(stub_artifacts.horizons)
    stub_artifacts.drop_spec(min(wanted))
    stub_artifacts.drop_weights(max(wanted))

    result = forecast.forecast_file(fixture_csv, out_dir=tmp_path)
    served = set(result["horizons"])
    explained = set(result["unavailable_horizons"])

    assert served | explained == wanted
    assert not (served & explained)
    assert served == wanted - {min(wanted), max(wanted)}


def test_a_run_with_no_head_at_any_horizon_explains_every_one(stub_artifacts,
                                                              fixture_csv, tmp_path):
    """Artifacts that predate the k-step heads: the nowcast still runs, and the
    forward block says — for every configured horizon — why there is no curve.
    An empty `horizons` with an empty `unavailable_horizons` would read as "this
    build has no forward horizons", which is a different and false statement."""
    from engine import forecast

    for k in stub_artifacts.horizons:
        stub_artifacts.drop_spec(k)

    result = forecast.forecast_file(fixture_csv, out_dir=tmp_path)
    assert result["n_alerts"] >= 1, "the nowcast must still run and alert"
    assert result["horizons"] == [] and result["forecast"] == []
    assert result["per_host_curve"] == {}
    assert set(result["unavailable_horizons"]) == set(stub_artifacts.horizons)


def test_a_run_with_nothing_to_forecast_still_says_so(stub_artifacts, tmp_path):
    """An input that yields zero host-windows produces an empty forecast and an
    empty curve — not a crash, and not a missing file. The persisted block is
    what tells a saved run apart from a run that never happened."""
    import csv

    from engine import forecast

    cfg = load_config("data")
    empty = tmp_path / "empty.csv"
    with open(empty, "w", newline="", encoding="utf-8") as fh:
        csv.writer(fh).writerow(list(cfg["schema"].values()))

    result = forecast.forecast_file(empty, out_dir=tmp_path / "out")
    assert result["n_host_windows"] == 0
    assert result["forecast"] == [] and result["per_host_curve"] == {}
    assert result["horizons"] == sorted(stub_artifacts.horizons)
    assert result["forecast_caveat"]
    assert (tmp_path / "out" / forecast.FORECAST_FILE).exists()


def test_the_kstep_block_is_persisted_beside_the_run(stub_artifacts, fixture_csv,
                                                     tmp_path):
    """The forward curve and the horizons that could not be produced must
    survive the process, exactly as predict.py's run_summary.json does: a saved
    run is what a judge or an external tool reads afterwards."""
    from engine import forecast

    result = forecast.forecast_file(fixture_csv, out_dir=tmp_path)
    stub_artifacts.drop_spec(max(stub_artifacts.horizons))
    degraded = forecast.forecast_file(fixture_csv, out_dir=tmp_path / "degraded")

    on_disk = json.loads((tmp_path / forecast.FORECAST_FILE).read_text(encoding="utf-8"))
    assert on_disk["forecast"] == result["forecast"]
    assert on_disk["horizons"] == result["horizons"]
    assert on_disk["per_host_curve"] == result["per_host_curve"]
    assert on_disk["forecast_caveat"] == forecast.FORWARD_FORECAST_CAVEAT
    assert on_disk["unavailable_horizons"] == {}

    # JSON has no integer keys: the reason must still be readable after a save
    saved = json.loads(
        (tmp_path / "degraded" / forecast.FORECAST_FILE).read_text(encoding="utf-8"))
    gone = max(stub_artifacts.horizons)
    assert saved["unavailable_horizons"][str(gone)] == degraded["unavailable_horizons"][gone]
    assert saved["forecast"] != on_disk["forecast"], "the degraded run saved stale content"


# --------------------------------------------------------------------------
# the trainer's horizon plumbing
#
# engine.train_engine.main() needs CIC-IDS-2018, which is not on this machine
# (and is gitignored). These stub the split assembler, the model factory and the
# metrics so the LOOP itself — one head and one threshold set per horizon, each
# under its own key and its own file — is executed for real. They prove the
# plumbing; they say nothing about how well any head forecasts, which needs the
# dataset and the harness.
# --------------------------------------------------------------------------

class _FakeXgb:
    """Stands in for models.baselines' xgb wrapper: .fit -> self,
    .predict_proba -> 1-D scores, .model.save_model(path) -> writes the file."""

    def __init__(self):
        self.model = self
        self.n_fitted = 0
        self.saved: list[str] = []

    def fit(self, X, y):
        self.n_fitted = len(y)
        return self

    def predict_proba(self, X):
        return np.linspace(0.0, 1.0, num=len(X))

    def save_model(self, path):
        self.saved.append(path)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("{}")


def _stub_threshold_at_fpr(y, scores, budget) -> float:
    """The stubbed FPR-budget cut: a function of the budget AND of the split it
    is handed — its length and its positive count.

    Both of those vary with the horizon in `stub_trainer` (shifting the target
    +k drops rows, and some of the dropped rows are attack rows), so every
    (horizon, budget) pair gets its own number. That is what lets the test below
    pin each head's cut to ITS OWN validation split: a trainer that thresholded
    every head against horizon 0's scores, or against horizon 0's labels, is
    visible in `persisted`. A cut that ignored y and s — as this stub once
    did, while its comment claimed to be horizon-dependent — would make
    those trainers indistinguishable from a correct one.

    The scale factors keep every value a plausible probability in (0, 1) and
    keep the row term (1e-4 per row) an order of magnitude above the label term
    (1e-6 per positive), so neither can mask the other.
    """
    return float(budget) + len(scores) / 10_000.0 + float(np.sum(y)) / 1_000_000.0


# Rows in a stub split at horizon 0. A real split SHRINKS as the target is
# shifted forward: the newest k windows of every host have no t+k label and drop
# out. The stub reproduces that (one row per horizon of shift), which is what
# makes the stubbed threshold_at_fpr in `stub_trainer` genuinely horizon-
# dependent rather than budget-dependent alone.
_SPLIT_ROWS_AT_HORIZON_0 = 200

# Attack rows in a stub split at horizon 0. Shrinks with the horizon for the
# same reason the row count does, so the LABELS a head is thresholded against
# differ per horizon too, not only the number of scores.
_ATTACK_ROWS_AT_HORIZON_0 = 20


class _FakeSplit:
    def __init__(self, n: int, n_attack: int):
        self.X = np.zeros((n, 30), dtype=np.float32)
        self.y = np.array([1] * n_attack + [0] * (n - n_attack), dtype=np.int8)


@pytest.fixture
def stub_trainer(monkeypatch, tmp_path):
    """engine.train_engine.main() with the dataset, the model and the metrics
    stubbed. Returns the recorder: which horizons were assembled, which files
    were written, and the dict that would have been persisted."""
    from eval import dataset as D
    from eval import metrics as M
    from models import baselines

    from engine import train_engine as TE

    record = {"horizons": [], "persisted": None, "dir": tmp_path,
              "attack_rows": {}, "models": [], "splits": {}}

    def fake_assemble(cfg, split, horizon=0, scaler=None, fit_scaler=False,
                      holdout_family=None):
        record["horizons"].append((split, horizon))
        n_attack = record["attack_rows"].get(
            (split, horizon), _ATTACK_ROWS_AT_HORIZON_0 - int(horizon))
        n_rows = _SPLIT_ROWS_AT_HORIZON_0 - int(horizon)
        assembled = _FakeSplit(n_rows, n_attack)
        record["splits"][(split, horizon)] = assembled
        return assembled, (scaler or object())

    def fake_build(name, cfg):
        model = _FakeXgb()
        record["models"].append(model)
        return model

    monkeypatch.setattr(D, "assemble_split", fake_assemble)
    monkeypatch.setattr(D, "persist_window_scaler", lambda cfg, scaler: "stub")
    monkeypatch.setattr(baselines, "build_model", fake_build)
    monkeypatch.setattr(M, "auroc", lambda y, s: 0.5)
    # Genuinely horizon-dependent, because it reads the split it is given; see
    # _stub_threshold_at_fpr for why a budget-only cut proved nothing.
    monkeypatch.setattr(M, "threshold_at_fpr", _stub_threshold_at_fpr)
    monkeypatch.setattr(TE, "resolve_path", lambda p: tmp_path)
    monkeypatch.setattr(TH, "persist_threshold",
                        lambda cfg, thresholds: record.__setitem__("persisted", thresholds))
    return record


def test_train_engine_fits_one_head_per_horizon_under_its_own_key(stub_trainer):
    """Every configured horizon gets its OWN model file and its OWN persisted
    threshold entry, keyed through thresholds.horizon_variant. A trainer that
    fitted the nowcast and reused it for k>0 would leave the forecaster serving
    the present under a future label."""
    from engine import train_engine as TE

    cfg = load_config("data")
    horizons = [int(k) for k in cfg["engine"]["forecast_horizons"]]
    stride = float(cfg["windows"]["stride_seconds"])

    assert TE.main() == 0
    persisted = stub_trainer["persisted"]
    assert persisted is not None, "train_engine persisted nothing"

    # the target really was shifted: train AND val assembled at every horizon
    assembled = set(stub_trainer["horizons"])
    for k in [0, *horizons]:
        assert ("train", k) in assembled and ("val", k) in assembled, (
            f"horizon k={k} was never assembled — its head cannot have been fitted "
            "on a shifted target"
        )

    for variant in ("full", "flow"):
        for k in [0, *horizons]:
            key = TH.horizon_variant(variant, k)
            assert key in persisted, f"no persisted entry for {key}"
            block = persisted[key]
            assert block["horizon"] == k
            assert block["seconds_ahead"] == k * stride
            assert (stub_trainer["dir"] / block["file"]).exists(), (
                f"{key} persisted a weight file that was never written"
            )
            for budget in load_config("eval")["fpr_budgets"]:
                assert f"fpr_{budget}" in block

    # The persisted cuts are genuinely DIFFERENT numbers per horizon and per
    # budget. This is the assertion the horizon-dependent stub above buys: it
    # fails both if the trainer reuses one horizon's cut for the others and if
    # the stub stops varying with the horizon, which would quietly retire the
    # guard rather than break it.
    budgets = list(load_config("eval")["fpr_budgets"])
    assert len(budgets) > 1, "one FPR budget cannot exercise per-budget isolation"
    for variant in ("full", "flow"):
        for budget in budgets:
            cuts = {k: persisted[TH.horizon_variant(variant, k)][f"fpr_{budget}"]
                    for k in [0, *horizons]}
            assert len(set(cuts.values())) == len(cuts), (
                f"{variant} @ fpr_{budget}: horizons share a threshold ({cuts}) — "
                "either the trainer reused one horizon's cut for the others, or the "
                "stubbed cut stopped depending on the horizon and this test no longer "
                "distinguishes the two"
            )
        for k in [0, *horizons]:
            cuts = {b: persisted[TH.horizon_variant(variant, k)][f"fpr_{b}"]
                    for b in budgets}
            assert len(set(cuts.values())) == len(cuts), (
                f"{variant} k={k}: every FPR budget got the same cut ({cuts})"
            )
    # ...and every head's cut was computed from ITS OWN validation split. The
    # stubbed cut reads that split's length and its positive count
    # (_stub_threshold_at_fpr), both of which differ per horizon, so a trainer
    # that thresholded a k>0 head against horizon 0's SCORES or against horizon
    # 0's LABELS lands on a different number here. The expectation is rebuilt
    # from the split the stub actually handed the trainer.
    for variant in ("full", "flow"):
        for k in [0, *horizons]:
            va = stub_trainer["splits"][("val", k)]
            block = persisted[TH.horizon_variant(variant, k)]
            for budget in budgets:
                expected = _stub_threshold_at_fpr(va.y, np.empty(len(va.y)), budget)
                # exact: the test rebuilds the cut from the same inputs the
                # trainer had, so a one-label difference must not be tolerated
                assert block[f"fpr_{budget}"] == pytest.approx(expected, rel=0, abs=1e-12), (
                    f"{variant} k={k} @ fpr_{budget}: the cut {block[f'fpr_{budget}']} "
                    f"was not computed from the k={k} validation split "
                    f"({len(va.y)} rows, {int(va.y.sum())} attack) — this head is "
                    "thresholded against another horizon's scores or labels"
                )

    # the stub really did hand every horizon a DIFFERENT val split, or the
    # assertion above would also hold for a trainer that reused one of them
    shapes = {(len(stub_trainer["splits"][("val", k)].y),
               int(stub_trainer["splits"][("val", k)].y.sum()))
              for k in [0, *horizons]}
    assert len(shapes) == len(horizons) + 1, (
        f"the stub val splits are not distinct per horizon ({sorted(shapes)}) — the "
        "per-horizon threshold assertions above cannot fail on a reused split"
    )

    # one head per (variant, horizon), each written to a distinct file
    files = [persisted[TH.horizon_variant(v, k)]["file"]
             for v in ("full", "flow") for k in [0, *horizons]]
    assert len(set(files)) == len(files), f"horizon heads overwrite each other: {files}"
    assert len(stub_trainer["models"]) == len(files)
    assert persisted["horizons"] == horizons and persisted["stride_seconds"] == stride


def test_train_engine_refuses_a_single_class_shifted_split(stub_trainer):
    """Shifting the target +k drops every row with no t+k window. If that leaves
    one class, the head would score every window the same while still looking
    like a model — and its threshold would be meaningless. Fail loudly instead."""
    from engine import train_engine as TE

    gone = max(int(k) for k in load_config("data")["engine"]["forecast_horizons"])
    stub_trainer["attack_rows"][("val", gone)] = 0

    with pytest.raises(ValueError, match=f"horizon k={gone}"):
        TE.main()
    assert stub_trainer["persisted"] is None, (
        "a run that could not fit every configured horizon must persist nothing"
    )


def test_forecast_file_is_deterministic(stub_artifacts, fixture_csv, tmp_path):
    """Same input, same heads, same forward curve — the M0 determinism claim
    extended to the k-step path, including the order entries come out in."""
    from engine import forecast

    first = forecast.forecast_file(fixture_csv, out_dir=tmp_path / "a")
    second = forecast.forecast_file(fixture_csv, out_dir=tmp_path / "b")

    assert first["forecast"] == second["forecast"]
    assert first["per_host_curve"] == second["per_host_curve"]
    assert (tmp_path / "a" / forecast.FORECAST_FILE).read_text(encoding="utf-8") == (
        tmp_path / "b" / forecast.FORECAST_FILE).read_text(encoding="utf-8")
