"""The published results table and plot: what they show and what they refuse.

Every test here renders from a synthetic results directory, because both the
table (eval/ablation.py) and the lead-time figure (eval/plots.py) are pure
functions of results/*.json — the renderers must be provable without the dataset
or a trained model.

The refusals are the load-bearing part and are tested as hard as the numbers:

* an absent measurement renders `TBD`, never a 0.0 that reads as "the model
  scored zero here" (`_num`, `_fmt_episodes`, and the val->test gap);
* the quantile band is suppressed below `metrics.min_episodes_for_quantile_band`
  in BOTH renderers, and the literal per-episode lead times are drawn instead;
* the achieved FPR is printed beside the budget that names the operating point.

The renderer can only print per-episode values if the writers serialise them, so
`test_every_results_writer_serialises_the_per_episode_lead_times` pins the
writer side of that contract structurally — see its docstring.
"""

from __future__ import annotations

import ast
import copy
import json
from pathlib import Path

import pytest

from configs import load_config
from eval import ablation


def _point(f1, lead, detected, total, fpr=None, band=None, per_episode=None):
    pt = {
        "f1": f1, "precision": f1, "recall": f1, "threshold": 0.5,
        "lead_time_median": lead, "lead_time_iqr": band if band else [lead - 5, lead + 5],
        "episodes_detected": detected, "episodes_total": total,
        "alerts_per_host_day": 12.0, "n_alerts": 100,
    }
    if fpr is not None:
        pt["fpr"] = fpr
    if per_episode is not None:
        pt["per_episode_seconds"] = per_episode
    return pt


def _result(model, *, test, val=None, auroc=0.9, val_auroc=0.95):
    r = {"model": model, "horizon": 0, "holdout_family": None,
         "test": {"auroc": auroc, "ece": 0.05, "fpr_0.01": test}}
    if val is not None:
        r["val"] = {"auroc": val_auroc, "ece": 0.04, "fpr_0.01": val}
    return r


def _write(tmp_path, name, result):
    (tmp_path / f"{name}.json").write_text(json.dumps(result), encoding="utf-8")


def _sparse(model, *, test, val=None):
    """A results JSON with exactly the blocks given — nothing filled in."""
    r = {"model": model, "horizon": 0, "holdout_family": None, "test": test}
    if val is not None:
        r["val"] = val
    return r


# ---------------------------------------------------------------- achieved FPR

def test_achieved_fpr_column_separates_rows_sharing_a_budget(tmp_path):
    # the audit's real spread: every row is labelled "1% FPR", tgn fires at
    # 0.373% of benign host-windows and xgb at 1.194% — a 3.2x alert-volume gap
    # the budget column alone cannot show.
    _write(tmp_path, "tgn", _result("tgn", test=_point(0.30, 50, 1, 2, fpr=0.00373)))
    _write(tmp_path, "xgb", _result("xgb", test=_point(0.20, 10, 1, 2, fpr=0.01194)))

    table = ablation.build_table(budget=0.01, results_dir=tmp_path)
    achieved = dict(zip(table["model"], table["FPR_achieved"]))
    assert achieved == {"tgn": "0.373%", "xgb": "1.194%"}

    md = ablation.to_markdown(table, 0.01)
    assert "FPR_achieved" in md and "0.373%" in md and "1.194%" in md


def test_achieved_fpr_is_tbd_when_the_json_lacks_it(tmp_path):
    _write(tmp_path, "lr", _result("lr", test=_point(0.6, 30, 1, 2)))
    table = ablation.build_table(budget=0.01, results_dir=tmp_path)
    assert table.iloc[0]["FPR_achieved"] == "TBD"


def test_achieved_fpr_does_not_disturb_the_existing_numbers(tmp_path):
    _write(tmp_path, "lr", _result("lr", test=_point(0.6, 30, 1, 2, fpr=0.0066)))
    row = ablation.build_table(budget=0.01, results_dir=tmp_path).iloc[0]
    assert row["F1@0.01"] == 0.6 and row["recall@0.01"] == 0.6
    assert row["AUROC"] == 0.9 and row["lead_median_s"] == 30
    assert row["alerts/host/day"] == 12.0


# -------------------------------------------------- an absent number reads TBD

# `_num` is the single place a missing measurement could turn into a 0.0. A zero
# in the F1 column says "this model scored zero at this operating point"; the
# truth is that nobody measured it there (a run at other budgets, an older
# schema). These tests fail if `_num`/`_fmt_episodes` ever go back to zero-fill.

NUMERIC_COLUMNS = ("F1@0.01", "precision@0.01", "recall@0.01", "AUROC", "ECE",
                   "lead_median_s", "alerts/host/day")


def test_an_operating_point_the_run_never_wrote_renders_tbd_not_zero(tmp_path):
    # a run scored at other budgets: the split block exists, fpr_0.01 does not.
    _write(tmp_path, "lr", _sparse("lr", test={"fpr_0.005": {"f1": 0.9}}))
    row = ablation.build_table(budget=0.01, results_dir=tmp_path).iloc[0]

    for column in NUMERIC_COLUMNS:
        assert row[column] == ablation.MISSING, (
            f"{column} rendered {row[column]!r}; an unmeasured cell must read "
            f"{ablation.MISSING}, never a number a judge can read as a score")
    assert row["n_episodes"] == ablation.MISSING
    assert row["episodes"] == ablation.MISSING
    assert row["FPR_achieved"] == ablation.MISSING
    assert row["lead_IQR_s"] == ablation.MISSING
    assert row["lead_each_s"] == ablation.MISSING
    assert 0.0 not in list(row.values) and 0 not in list(row.values)


def test_a_partially_measured_point_keeps_what_was_measured(tmp_path):
    # f1 and AUROC were measured; precision/recall/ECE/lead were not. The row
    # must not average the two into zeros, and must not drop the real numbers.
    _write(tmp_path, "lr", _sparse("lr", test={
        "auroc": 0.83, "fpr_0.01": {"f1": 0.42, "fpr": 0.0066}}))
    row = ablation.build_table(budget=0.01, results_dir=tmp_path).iloc[0]

    assert row["F1@0.01"] == 0.42 and row["AUROC"] == 0.83
    assert row["FPR_achieved"] == "0.660%"
    for column in ("precision@0.01", "recall@0.01", "ECE", "lead_median_s",
                   "alerts/host/day"):
        assert row[column] == ablation.MISSING, column


def test_episode_counts_absent_render_tbd_not_zero_over_zero(tmp_path):
    _write(tmp_path, "lr", _sparse("lr", test={"fpr_0.01": {"f1": 0.42}}))
    row = ablation.build_table(budget=0.01, results_dir=tmp_path).iloc[0]
    assert row["episodes"] == ablation.MISSING
    assert row["episodes"] != "0/0", "0/0 reads as 'detected none of none'"


def test_alerts_per_host_day_falls_back_to_the_legacy_key_then_to_tbd(tmp_path):
    _write(tmp_path, "old", _sparse("old", test={"fpr_0.01": {"alerts_per_day": 7.25}}))
    _write(tmp_path, "new", _sparse("new", test={"fpr_0.01": {"alerts_per_host_day": 3.5}}))
    _write(tmp_path, "none", _sparse("none", test={"fpr_0.01": {"f1": 0.1}}))
    rows = ablation.build_table(budget=0.01, results_dir=tmp_path)
    by_model = dict(zip(rows["model"], rows["alerts/host/day"]))
    assert by_model == {"old": 7.2, "new": 3.5, "none": ablation.MISSING}


def test_the_val_to_test_gap_is_tbd_when_either_side_is_unmeasured(tmp_path):
    # test carries AUROC, val does not. Subtracting would print the test number
    # wearing a minus sign and call it a generalisation gap.
    _write(tmp_path, "tgn", _sparse(
        "tgn",
        test={"auroc": 0.90, "fpr_0.01": {"f1": 0.30, "lead_time_median": 50.0,
                                          "recall": 0.2}},
        val={"fpr_0.01": {"f1": 0.71, "lead_time_median": 400.0, "recall": 0.6}}))
    row = ablation.build_split_comparison(budget=0.01, results_dir=tmp_path).iloc[0]

    assert row["test_AUROC"] == 0.9 and row["val_AUROC"] == ablation.MISSING
    assert row["gap_AUROC"] == ablation.MISSING
    assert row["gap_AUROC"] != -0.9 and row["gap_AUROC"] != 0.9
    # the fully measured columns still subtract
    assert row["gap_F1"] == pytest.approx(-0.41)
    assert row["gap_lead_median_s"] == pytest.approx(-350.0)


# ------------------------------------------- the writers emit what this reads

def _lead_time_blocks(path: Path) -> list[set[str]]:
    """Key sets of every dict literal in `path` that reports a lead time.

    A results writer builds its operating point as one dict literal; any literal
    carrying `lead_time_median` is such a block, so this finds them without
    running the module.
    """
    tree = ast.parse(Path(path).read_text(encoding="utf-8"))
    blocks = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Dict):
            continue
        keys = {k.value for k in node.keys
                if isinstance(k, ast.Constant) and isinstance(k.value, str)}
        if "lead_time_median" in keys:
            blocks.append(keys)
    return blocks


def _writer_paths() -> list[Path]:
    eval_dir = Path(ablation.__file__).resolve().parent
    return [eval_dir / name for name in
            ("harness.py", "fused.py", "forecast.py", "world.py")]


def test_every_results_writer_serialises_the_per_episode_lead_times():
    """STRUCTURAL check (AST), not an execution of the writers.

    `_fmt_per_episode` can only print the literal per-episode lead times if the
    writer put them in the JSON, and below the quantile-band cutoff those values
    ARE the dispersion the table reports. Three of the four writers need the
    CIC-IDS-2018 split and trained weights on disk, so the suite cannot run them;
    what it can pin without the dataset is that every dict literal reporting a
    lead-time median also reports `per_episode_seconds`. A writer that drops the
    field fails here instead of silently rendering TBD in the shipped table.
    """
    for path in _writer_paths():
        blocks = _lead_time_blocks(path)
        assert blocks, f"{path} reports no lead time at all — has it been renamed?"
        for keys in blocks:
            assert "per_episode_seconds" in keys, (
                f"{path.name} writes a lead-time block without "
                f"per_episode_seconds (keys: {sorted(keys)}); the table would "
                "render TBD where the per-episode values are the only honest "
                "dispersion at n=2 episodes")
            assert "episodes_total" in keys, (
                f"{path.name} writes a lead-time block without episodes_total; "
                "the band-suppression rule needs the episode count")


# -------------------------------------------------------- lead-time dispersion

def test_quantile_band_is_refused_below_the_episode_cutoff(tmp_path):
    cutoff = load_config("eval")["metrics"]["min_episodes_for_quantile_band"]
    assert cutoff > 2, "the shipped runs have 2 episodes; a cutoff of 2 pins nothing"

    # 2 episodes, one of them a MISS: percentile(25) of [0, 56] is interpolation,
    # and half of the band is the missed episode.
    _write(tmp_path, "tgn", _result(
        "tgn", test=_point(0.3, 28, 1, 2, band=[19.0, 56.0], per_episode=[0.0, 56.0])))
    row = ablation.build_table(budget=0.01, results_dir=tmp_path).iloc[0]
    assert row["lead_IQR_s"] == "n/a (n=2)"
    assert "19-56" not in row["lead_IQR_s"]
    assert row["lead_each_s"] == "0, 56"
    assert row["n_episodes"] == 2


def test_quantile_band_prints_once_enough_episodes_exist(tmp_path):
    cutoff = int(load_config("eval")["metrics"]["min_episodes_for_quantile_band"])
    leads = [float(10 * i) for i in range(cutoff)]
    _write(tmp_path, "lr", _result("lr", test=_point(
        0.6, 30, cutoff, cutoff, band=[2940.0, 5450.0], per_episode=leads)))
    row = ablation.build_table(budget=0.01, results_dir=tmp_path).iloc[0]
    assert row["lead_IQR_s"] == "2940-5450"
    assert row["n_episodes"] == cutoff


def test_per_episode_column_is_tbd_when_the_results_json_lacks_it(tmp_path):
    # Every shipped writer now serialises the per-episode list (pinned by
    # test_every_results_writer_serialises_the_per_episode_lead_times), so this
    # exercises the OLDER schema: a results JSON carrying median/iqr/counts only,
    # e.g. one left in results/ by a run that predates the field. The renderer
    # must say TBD rather than reconstruct the values from the median and band.
    _write(tmp_path, "lr", _result("lr", test=_point(0.6, 30, 1, 2)))
    assert ablation.build_table(budget=0.01, results_dir=tmp_path).iloc[0]["lead_each_s"] == "TBD"


def test_markdown_states_the_band_rule(tmp_path):
    cutoff = int(load_config("eval")["metrics"]["min_episodes_for_quantile_band"])
    _write(tmp_path, "lr", _result("lr", test=_point(0.6, 30, 1, 2, fpr=0.0066)))
    md = ablation.to_markdown(ablation.build_table(budget=0.01, results_dir=tmp_path), 0.01)
    assert f"from {cutoff} episodes up" in md
    assert "TBD" in md
    md.encode("ascii")  # rendered into the README through stdout


# ------------------------------------------------------------ split visibility

def test_build_table_renders_the_requested_split(tmp_path):
    _write(tmp_path, "tgn", _result(
        "tgn",
        test=_point(0.30, 50, 1, 2, fpr=0.00373),
        val=_point(0.71, 400, 2, 2, fpr=0.00250),
        auroc=0.90, val_auroc=0.97,
    ))
    test_row = ablation.build_table(budget=0.01, results_dir=tmp_path, split="test").iloc[0]
    val_row = ablation.build_table(budget=0.01, results_dir=tmp_path, split="val").iloc[0]

    assert test_row["split"] == "test" and val_row["split"] == "val"
    assert test_row["F1@0.01"] == 0.3 and val_row["F1@0.01"] == 0.71
    assert test_row["AUROC"] == 0.9 and val_row["AUROC"] == 0.97
    assert val_row["FPR_achieved"] == "0.250%"


def test_split_comparison_exposes_the_val_to_test_gap(tmp_path):
    _write(tmp_path, "tgn", _result(
        "tgn",
        test=_point(0.30, 50, 1, 2, fpr=0.00373),
        val=_point(0.71, 400, 2, 2, fpr=0.00250),
        auroc=0.90, val_auroc=0.97,
    ))
    row = ablation.build_split_comparison(budget=0.01, results_dir=tmp_path).iloc[0]
    assert row["val_F1"] == 0.71 and row["test_F1"] == 0.3
    assert row["gap_F1"] == pytest.approx(-0.41)
    assert row["gap_AUROC"] == pytest.approx(-0.07)
    assert row["gap_lead_median_s"] == pytest.approx(-350.0)
    assert row["val_FPR_achieved"] == "0.250%" and row["test_FPR_achieved"] == "0.373%"

    md = ablation.to_markdown(
        ablation.build_split_comparison(budget=0.01, results_dir=tmp_path), 0.01, split=None)
    assert "val vs test" in md and "gap_F1" in md


def test_split_comparison_skips_results_without_both_blocks(tmp_path):
    _write(tmp_path, "lr", _result("lr", test=_point(0.6, 30, 1, 2)))  # test only
    assert ablation.build_split_comparison(budget=0.01, results_dir=tmp_path).empty


def test_unknown_split_fails_loudly(tmp_path):
    with pytest.raises(ValueError, match="split must be one of"):
        ablation.build_table(budget=0.01, results_dir=tmp_path, split="train")


def test_val_table_excludes_results_carrying_no_val_block(tmp_path):
    _write(tmp_path, "lr", _result("lr", test=_point(0.6, 30, 1, 2)))
    _write(tmp_path, "tgn", _result("tgn", test=_point(0.3, 50, 1, 2),
                                    val=_point(0.7, 400, 2, 2)))
    models = list(ablation.build_table(budget=0.01, results_dir=tmp_path, split="val")["model"])
    assert models == ["tgn"], "a missing val block must drop the row, not render zeros"


# ------------------------------------------------- the figure obeys the same rules

# eval/plots.py renders the SHIPPED PNG, so its refusals matter as much as the
# table's: a quartile band drawn over 2 episodes is a picture of a dispersion
# nobody measured. These tests build the figure from a synthetic results dir and
# inspect the axes matplotlib actually built.

def _forecast_json(tmp_path, *, n_episodes, per_episode, band=(50.0, 150.0)):
    horizons = {
        str(k): {
            "auroc_test": 0.9,
            "fpr_0.01": {
                "lead_time_median": 100.0 - 10.0 * k,
                "lead_time_iqr": list(band) if band else None,
                "episodes_total": n_episodes,
                "per_episode_seconds": per_episode,
            },
        }
        for k in (1, 4, 8)
    }
    (tmp_path / "forecast.json").write_text(
        json.dumps({"horizons": horizons}), encoding="utf-8")


def _render(tmp_path, cfg_eval=None):
    """Render the lead-time figure from tmp_path/forecast.json; return its axis.

    Calls `plots.build_figure` rather than `main`, so the figure under test is
    the object this function was handed — no lookup through pyplot's global
    figure registry, which would be reading whatever the last renderer left open.

    The figure is closed before the axis is returned, for the same reason
    `main` closes its own: `build_figure` goes through pyplot, so an unclosed
    one would sit in the registry for the rest of the session and a test file
    that complains about leaked figures must not leak its own. Closing detaches
    the figure from pyplot's manager; the Axes object stays intact and every
    assertion below still reads the marks matplotlib drew on it.
    """
    import matplotlib.pyplot as plt

    from eval import plots

    fc = json.loads((tmp_path / "forecast.json").read_text(encoding="utf-8"))
    fig = plots.build_figure(fc, cfg_eval or load_config("eval"), tmp_path)
    ax = fig.axes[0]
    plt.close(fig)
    return ax


def test_plot_main_writes_the_png_and_leaves_no_figure_open(monkeypatch, tmp_path):
    """pyplot owns every figure until someone closes it.

    `main` is the CLI entry point but also a function anything may call in a
    loop (the ablation script renders after a re-run). A figure it never closes
    stays alive in pyplot's registry for the life of the process, and the only
    reason the tests above could find their output was that leak. Asserting the
    registry is empty AFTER a successful render is what makes this falsifiable:
    drop the `plt.close(fig)` in eval/plots.main and this fails.
    """
    import matplotlib.pyplot as plt

    from eval import plots

    _forecast_json(tmp_path, n_episodes=2, per_episode=[0.0, 56.0])
    monkeypatch.setattr(plots, "resolve_path", lambda *a, **k: tmp_path)
    plt.close("all")

    # Twice, because the claim being pinned is "one leaked figure PER CALL":
    # a single call leaking one is the same assertion, but a renderer used in a
    # loop is the case that actually accumulates them.
    for _ in range(2):
        assert plots.main() == 0
    assert (tmp_path / "lead_time.png").exists()
    assert plt.get_fignums() == [], (
        f"eval.plots.main left {len(plt.get_fignums())} figure(s) open in "
        "pyplot's global registry after 2 calls — one leaked figure per call")


def test_plot_omits_the_band_below_the_episode_cutoff_and_draws_each_episode(tmp_path):
    cutoff = int(load_config("eval")["metrics"]["min_episodes_for_quantile_band"])
    assert cutoff > 2, "the shipped runs have 2 episodes; a cutoff of 2 pins nothing"

    _forecast_json(tmp_path, n_episodes=2, per_episode=[0.0, 56.0])
    ax = _render(tmp_path)

    assert not ax.collections, (
        "fill_between drew an IQR band over 2 episodes — half of that band is a "
        "missed episode entering as a 0 s edge")
    markers = [line for line in ax.lines if line.get_marker() == "x"]
    assert len(markers) == 3, "one per-episode marker set per horizon"
    assert [list(m.get_ydata()) for m in markers] == [[0.0, 56.0]] * 3
    note = " ".join(t.get_text() for t in ax.texts)
    assert "IQR omitted" in note and f"{cutoff}-episode cutoff" in note


def test_plot_draws_the_band_once_the_episode_count_clears_the_cutoff(tmp_path):
    cutoff = int(load_config("eval")["metrics"]["min_episodes_for_quantile_band"])
    _forecast_json(tmp_path, n_episodes=cutoff, per_episode=[10.0] * cutoff)
    ax = _render(tmp_path)

    assert len(ax.collections) == 1, "the band must be drawn once n >= the cutoff"
    assert not [line for line in ax.lines if line.get_marker() == "x"]
    assert not ax.texts


def test_plot_omits_the_band_when_the_results_json_never_recorded_the_count(tmp_path):
    _forecast_json(tmp_path, n_episodes=None, per_episode=None)
    ax = _render(tmp_path)

    assert not ax.collections
    note = " ".join(t.get_text() for t in ax.texts)
    assert "does not record the episode count" in note
    assert "per-episode values absent" in note


def test_plot_title_states_the_configured_undetected_convention(tmp_path):
    """The '(undetected = 0)' in the title is `lead_time_undetected_seconds`.

    It is what every median on that axis charges a missed episode, and it is a
    config value — a shipped PNG must not assert a number the run did not use.
    """
    shipped = load_config("eval")
    _forecast_json(tmp_path, n_episodes=2, per_episode=[0.0, 56.0])
    ax = _render(tmp_path)
    undetected = float(shipped["metrics"]["lead_time_undetected_seconds"])
    assert ax.get_title() == f"Lead time vs horizon (undetected = {undetected:g} s)"

    changed = copy.deepcopy(shipped)
    changed["metrics"]["lead_time_undetected_seconds"] = -1
    ax = _render(tmp_path, cfg_eval=changed)
    assert ax.get_title() == "Lead time vs horizon (undetected = -1 s)", (
        "the title is hardcoded again — it would print '0' for a run that "
        "charged something else")
