"""Measure whether dropping `net24_bucket` should ship, and decide it on validation.

    python scripts/accuracy_experiment.py                # both arms, all models
    python scripts/accuracy_experiment.py --models xgb   # one model, both arms

WHY THIS EXISTS
`net24_bucket` is a hashed /24 bucket of the source address. It is attacker-
influenceable — renting a different VPS re-rolls it — and the project's own
ablation (`scripts/ablate_net24.py`, `tier1_hardening_report.md` Part 3) measured
dropping it as a large gain on the flat models: F1 0.140 -> 0.392 and recall
0.114 -> 0.452 for XGBoost. That ablation ZEROED the column. This runs the real
thing: a genuine 29-column feature matrix, through the shipped harness, so the
numbers it produces are the numbers that would ship.

HOW THE DECISION IS MADE
On the VALIDATION split, never on test. That is this project's standing rule and
the reason it survived an audit that found the opposite claim published about the
fused model. Test numbers are printed for the record and are not the criterion.
A test-set win with a validation loss is not a promotion; it is a warning.

WHAT IT DOES NOT DO
It does not touch `tgn`, `tgn_graft` or anything downstream of the TGN memory:
those models read embeddings of dimension `memory_dim`, not the 30-column window
matrix, so `net24_bucket` cannot reach them. Running them under both arms would
burn hours to reproduce the same number twice. `scripts/ablate_net24.py` states
the same fact and the harness confirms it.

MECHANISM
Each arm writes `anonymisation.role_features` into `configs/data.yaml` and invokes
`python -m eval.harness` as a subprocess, so every arm goes through the SHIPPED
code path rather than an in-process reconstruction that could drift from it. The
config is restored on every exit path, including a keyboard interrupt; if the
process is killed hard, the backup sits beside the file and the script says so on
its next run.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from configs import load_config, resolve_path  # noqa: E402

CONFIG = REPO / "configs" / "data.yaml"
BACKUP = REPO / "configs" / "data.yaml.accuracy-experiment-backup"

# Models whose feature matrix actually contains the column under test.
FLAT_MODELS = ("lr", "xgb", "lstm")

ARMS = {
    "with_net24": ["internal", "net24_bucket"],
    "without_net24": ["internal"],
}


def _set_role_features(names: list[str]) -> None:
    """Rewrite anonymisation.role_features in configs/data.yaml.

    Line-oriented rather than a YAML round-trip on purpose: the file carries
    comments that explain every key, and dumping it back through a YAML writer
    would delete all of them.
    """
    text = CONFIG.read_text(encoding="utf-8")
    rendered = "[" + ", ".join(names) + "]"
    marker = "  role_features:"
    lines = text.splitlines(keepends=True)
    for i, line in enumerate(lines):
        if line.startswith(marker):
            lines[i] = f"{marker} {rendered}\n"
            break
    else:
        for i, line in enumerate(lines):
            if line.startswith("anonymisation:"):
                lines.insert(
                    i + 1,
                    "  # Written by scripts/accuracy_experiment.py; the shipped value is\n"
                    "  # whatever the promoted arm measured best on validation.\n"
                    f"{marker} {rendered}\n",
                )
                break
        else:
            raise RuntimeError("configs/data.yaml has no `anonymisation:` block")
    CONFIG.write_text("".join(lines), encoding="utf-8")


def _run_harness(model: str) -> dict | None:
    """Invoke the shipped harness for one model; return its results JSON."""
    print(f"    ...running eval.harness --model {model}", flush=True)
    proc = subprocess.run(
        [sys.executable, "-m", "eval.harness", "--model", model],
        cwd=REPO, capture_output=True, text=True,
    )
    if proc.returncode != 0:
        tail = (proc.stderr or proc.stdout).strip().splitlines()[-6:]
        print(f"    FAILED (exit {proc.returncode}):", flush=True)
        for line in tail:
            print(f"      {line}", flush=True)
        return None
    out = resolve_path(load_config("eval")["paths"]["results_dir"]) / f"{model}.json"
    if not out.exists():
        print(f"    harness exited 0 but wrote no {out.name}", flush=True)
        return None
    return json.loads(out.read_text(encoding="utf-8"))


def _point(result: dict, split: str, budget: float) -> dict:
    block = result.get(split, {})
    pt = block.get(f"fpr_{budget}", {})
    return {
        "auroc": block.get("auroc"),
        "f1": pt.get("f1"),
        "recall": pt.get("recall"),
        "precision": pt.get("precision"),
        "fpr_achieved": pt.get("fpr"),
        "lead_median": pt.get("lead_time_median"),
        "episodes": f"{pt.get('episodes_detected')}/{pt.get('episodes_total')}",
    }


def _fmt(v) -> str:
    if v is None:
        return "TBD"
    return f"{v:.3f}" if isinstance(v, float) and abs(v) < 100 else f"{v:.0f}"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--models", default=",".join(FLAT_MODELS),
                    help="comma-separated models whose matrix contains the column")
    ap.add_argument("--budget", type=float, default=0.01)
    args = ap.parse_args(argv)
    models = [m.strip() for m in args.models.split(",") if m.strip()]

    if BACKUP.exists():
        print(f"REFUSING TO START: {BACKUP.name} already exists, which means a previous run\n"
              f"was killed before it could restore {CONFIG.name}. Compare the two files and\n"
              "restore by hand before running again — otherwise this run would back up an\n"
              "already-modified config and the original would be lost.", file=sys.stderr)
        return 2

    shutil.copy2(CONFIG, BACKUP)
    table: dict[str, dict[str, dict]] = {}
    try:
        for arm, names in ARMS.items():
            print(f"\n=== arm: {arm}  (role_features = {names}) ===", flush=True)
            _set_role_features(names)
            n_features = len(__import__("data.windows", fromlist=["x"]).feature_columns(
                load_config("data")))
            print(f"    feature matrix: {n_features} columns", flush=True)
            table[arm] = {}
            for model in models:
                res = _run_harness(model)
                if res is None:
                    continue
                table[arm][model] = {
                    "val": _point(res, "val", args.budget),
                    "test": _point(res, "test", args.budget),
                    "n_features": n_features,
                }
    finally:
        shutil.copy2(BACKUP, CONFIG)
        BACKUP.unlink()
        print(f"\nrestored {CONFIG.name}", flush=True)

    out = resolve_path(load_config("eval")["paths"]["results_dir"]) / "accuracy_experiment.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(table, indent=2), encoding="utf-8")

    print("\n" + "=" * 78)
    print("VALIDATION is the criterion. Test is printed for the record only.")
    print("=" * 78)
    header = f"{'model':6s} {'arm':14s} | {'val AUROC':>9s} {'val F1':>7s} | {'test AUROC':>10s} {'test F1':>8s} {'recall':>7s} {'lead':>7s} {'eps':>5s}"
    print(header)
    print("-" * len(header))
    for model in models:
        for arm in ARMS:
            cell = table.get(arm, {}).get(model)
            if not cell:
                print(f"{model:6s} {arm:14s} | {'(no result)':>9s}")
                continue
            v, t = cell["val"], cell["test"]
            print(f"{model:6s} {arm:14s} | {_fmt(v['auroc']):>9s} {_fmt(v['f1']):>7s} | "
                  f"{_fmt(t['auroc']):>10s} {_fmt(t['f1']):>8s} {_fmt(t['recall']):>7s} "
                  f"{_fmt(t['lead_median']):>7s} {t['episodes']:>5s}")

    print("\nVERDICT (val AUROC, then val F1 as the tie-break):")
    for model in models:
        arms = {a: table.get(a, {}).get(model) for a in ARMS}
        if not all(arms.values()):
            print(f"  {model}: incomplete — cannot decide")
            continue
        def key(a):
            v = arms[a]["val"]
            return (v["auroc"] or 0.0, v["f1"] or 0.0)
        winner = max(ARMS, key=key)
        loser = next(a for a in ARMS if a != winner)
        dv = (key(winner)[0] - key(loser)[0])
        print(f"  {model}: promote **{winner}** (val AUROC +{dv:.3f} over {loser})")

    print(f"\n-> {out}")
    print("Nothing was promoted automatically. Read the table, then set\n"
          "`anonymisation.role_features` in configs/data.yaml to the winning arm and\n"
          "regenerate every row under it — a table with rows from two different\n"
          "feature matrices is not a comparison.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
