"""GPU experiment pack: the ranked, val-selected attempts to lift the headline.

    python scripts/gpu_experiments.py                 # run everything (resumable)
    python scripts/gpu_experiments.py --seeds 5
    python scripts/gpu_experiments.py --skip focused

Designed for the RTX 4060 box, but runs anywhere (CUDA just makes it fast).
Prerequisites on that machine:
  1. this repo cloned, venv installed (CUDA torch optional:
     pip install torch --index-url https://download.pytorch.org/whl/cu121)
  2. the extracted dataset copied to the SAME path configs/data.yaml uses
     (C:/sih26_data/interim — ~177 MB; raw/ is NOT needed)
  3. the SAME fixed anonymisation key exported (copy the gitignored .env and
     `export $(grep -v '^#' .env | xargs)` — a different key makes every number
     incomparable, which we learned the hard way)

Experiments, ranked by expected value (from the Phase-0 diagnosis):
  E1 seed-averaging: N TGN seeds -> rank-mean into tgn_avg__exp. Training
     variance is proven huge (0.877 vs 0.954 across keys); averaging harvests it.
  E2 longer TGN link-pred (3 -> N epochs), one tagged run.
  E3 GRAFT focused retrain (configs/train_graft_focused.yaml) as a candidate
     THIRD fusion member, then the 3-way fusion.

Discipline (CLAUDE.md): every candidate is judged on the VALIDATION day only;
test numbers are printed for the record but promotion = val AUROC beats the
shipped fused model's val AUROC. All runs are tagged '__exp'-style so nothing
here touches the shipped ablation table or artifacts. Copy results/scores/*.npz
and results/*__*.json back to the main machine to merge.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from configs import load_config, resolve_path  # noqa: E402


def _run(args: list[str]) -> None:
    cmd = [sys.executable, "-m"] + args
    print(f"\n$ {' '.join(cmd)}", flush=True)
    r = subprocess.run(cmd, cwd=REPO)
    if r.returncode != 0:
        raise SystemExit(f"command failed ({r.returncode}): {' '.join(cmd)}")


def _scores_dir() -> Path:
    return resolve_path(load_config("eval")["paths"]["results_dir"]) / "scores"


def _results_dir() -> Path:
    return resolve_path(load_config("eval")["paths"]["results_dir"])


def _val_test(name: str):
    p = _results_dir() / f"{name}.json"
    if not p.exists():
        return None
    r = json.loads(p.read_text(encoding="utf-8"))
    return {"val_auroc": r["val"]["auroc"], "test_auroc": r["test"]["auroc"],
            "val_f1": r["val"]["fpr_0.01"]["f1"], "test_f1": r["test"]["fpr_0.01"]["f1"]}


def _ensure_member(name: str) -> None:
    """A fusion member's score dump must exist; run the harness if it doesn't."""
    if not (_scores_dir() / f"{name}.npz").exists():
        _run(["eval.harness", "--model", name])


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--seeds", type=int, default=3, help="TGN seeds for E1 (default 3)")
    ap.add_argument("--long-epochs", type=int, default=15, help="TGN epochs for E2")
    ap.add_argument("--skip", nargs="*", default=[],
                    choices=["seeds", "long", "focused"], help="experiments to skip")
    args = ap.parse_args(argv)

    import os
    if not os.environ.get("SIH26_HMAC_KEY"):
        raise SystemExit("SIH26_HMAC_KEY is unset — copy .env from the main machine and "
                         "export it; a different key makes results incomparable.")
    interim = resolve_path(load_config("data")["paths"]["interim_dir"])
    if not interim.exists():
        raise SystemExit(f"dataset not found at {interim} — copy C:/sih26_data/interim "
                         "from the main machine (177 MB; raw/ is not needed).")
    try:
        import torch
        print(f"torch {torch.__version__} | CUDA available: {torch.cuda.is_available()}"
              + (f" ({torch.cuda.get_device_name(0)})" if torch.cuda.is_available() else
                 "  — runs on CPU too, just slower"))
    except Exception as e:  # noqa: BLE001
        print(f"torch check: {e}")

    candidates: dict[str, dict] = {}

    # Baseline members every fusion needs.
    _ensure_member("xgb")
    _ensure_member("tgn")

    # ---- E1: seed-averaging --------------------------------------------------
    if "seeds" not in args.skip:
        members = []
        for i in range(1, args.seeds + 1):
            tag = f"s{i}"
            name = f"tgn__{tag}"
            members.append(name)
            if (_scores_dir() / f"{name}.npz").exists():
                print(f"[skip] {name} dump exists (resumable)")
                continue
            _run(["eval.harness", "--model", "tgn", "--seed", str(1000 + i),
                  "--tag", tag])
        _run(["eval.fused", "--members", ",".join(members), "--name", "tgn_avg__exp"])
        _run(["eval.fused", "--members", "tgn_avg__exp,xgb", "--name", "fused_avg__exp"])
        candidates["fused_avg__exp (E1 seed-avg TGN + xgb)"] = _val_test("fused_avg__exp")

    # ---- E2: longer TGN training --------------------------------------------
    if "long" not in args.skip:
        name = f"tgn__e{args.long_epochs}"
        if not (_scores_dir() / f"{name}.npz").exists():
            _run(["eval.harness", "--model", "tgn", "--tgn-epochs",
                  str(args.long_epochs), "--tag", f"e{args.long_epochs}"])
        _run(["eval.fused", "--members", f"{name},xgb", "--name", "fused_long__exp"])
        candidates[f"fused_long__exp (E2 {args.long_epochs}-epoch TGN + xgb)"] = (
            _val_test("fused_long__exp"))

    # ---- E3: focused GRAFT as a third member --------------------------------
    if "focused" not in args.skip:
        name = "tgn_graft_focused__gpu"
        if not (_scores_dir() / f"{name}.npz").exists():
            _run(["eval.harness", "--model", "tgn_graft_focused", "--tag", "gpu"])
        base_tgn = ("tgn_avg__exp" if (_scores_dir() / "tgn_avg__exp.npz").exists()
                    else "tgn")
        _run(["eval.fused", "--members", f"{base_tgn},xgb,{name}",
              "--name", "fused3__exp"])
        candidates[f"fused3__exp (E3 {base_tgn} + xgb + focused GRAFT)"] = (
            _val_test("fused3__exp"))

    # ---- verdicts (VAL-selected; test shown for the record only) ------------
    shipped = _val_test("fused")
    print("\n" + "=" * 78)
    print("VERDICTS — promote a candidate ONLY if its VAL AUROC beats the shipped fused")
    print("=" * 78)
    if shipped:
        print(f"shipped fused         : val AUROC {shipped['val_auroc']:.3f} | "
              f"test AUROC {shipped['test_auroc']:.3f} (the bar)")
    for label, m in candidates.items():
        if not m:
            print(f"{label}: (no result written)")
            continue
        beat = shipped and m["val_auroc"] > shipped["val_auroc"]
        print(f"{label}:\n    val AUROC {m['val_auroc']:.3f} "
              f"{'BEATS the bar — candidate for promotion' if beat else 'does not beat the bar'}"
              f" | test AUROC {m['test_auroc']:.3f} (record only)")
    print("\nCopy back to the main machine: results/scores/*.npz and results/*__*.json.")
    print("Promotion (renaming a winner to a shipped row + docs update) happens there,")
    print("with the full regenerated ablation — never here.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
