"""Per-episode lead-time breakdown from a score dump (seed-repeat validation).

    python scripts/per_episode.py <model_name> [<model_name> ...]

Episode counts are out of only 2 total, so a 1/2->2/2 swing is exactly one more
episode caught. This prints EACH attacker episode individually — did it fire, at
what lead, and how confidently — at the shipped val-chosen 1% threshold, so a
seed's aggregate isn't mistaken for stability.
"""

from __future__ import annotations

import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from configs import load_config, resolve_path  # noqa: E402
from eval import dataset as D  # noqa: E402
from eval import metrics as M  # noqa: E402


def analyse(name: str) -> None:
    p = resolve_path(load_config("eval")["paths"]["results_dir"]) / "scores" / f"{name}.npz"
    if not p.exists():
        print(f"[{name}] no score dump")
        return
    cfg = load_config("data")
    d = np.load(p, allow_pickle=True)
    vy, vs = d["val_y"], d["val_score"]
    ty, ts, th, tw = d["test_y"], d["test_score"], d["test_host"], d["test_ws"]
    thr = M.threshold_at_fpr(vy, vs, 0.01)  # shipped val-chosen 1% threshold

    print(f"\n### {name}  (val-1% threshold = {thr:.4g})")
    eps = D.attacker_episodes(cfg, "test")
    for k, ep in enumerate(eps):
        on = (th == ep["host"]) & (tw >= ep["start"]) & (tw <= ep["end"])
        fired = on & (ts >= thr)
        n_in, n_f = int(on.sum()), int(fired.sum())
        if n_f:
            first_t = float(tw[fired].min())
            print(f"  ep{k} host={ep['host']} dur={ep['end']-ep['start']:.0f}s "
                  f"windows={n_in}: FIRED {n_f}x, first +{first_t-ep['start']:.0f}s, "
                  f"lead {ep['end']-first_t:.0f}s, "
                  f"max score on host {float(ts[on].max()):.3g}")
        else:
            print(f"  ep{k} host={ep['host']} dur={ep['end']-ep['start']:.0f}s "
                  f"windows={n_in}: MISSED (max score on host {float(ts[on].max()):.3g} "
                  f"< thr {thr:.3g})")


def main() -> int:
    for name in sys.argv[1:] or ["tgn_graft_t2v_clamped"]:
        analyse(name)
    return 0


if __name__ == "__main__":
    sys.exit(main())
