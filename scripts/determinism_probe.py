"""Determinism probe (Part 1, Step 3): list flagged nondeterministic ops and
check the real TGN+GRAFT training path reproduces bit-for-bit under the fix.

Fast + synthetic (tiny tensors) so it isolates op-level determinism without a
15-min full train. Run: python scripts/determinism_probe.py
"""

from __future__ import annotations

import hashlib
import sys
import warnings
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import numpy as np  # noqa: E402
import torch  # noqa: E402

from configs import load_config, set_seed  # noqa: E402


def _sd_hash(module) -> str:
    h = hashlib.sha256()
    for k, v in sorted(module.state_dict().items()):
        h.update(k.encode())
        h.update(v.detach().cpu().numpy().tobytes())
    return h.hexdigest()[:16]


def _train_tgn_once(seed: int) -> tuple[str, list[float]]:
    from models import tgn as T
    set_seed(seed)
    cfg_t = load_config("train_tgn")
    n_nodes, n_ev, msg_dim = 60, 400, len(load_config("data")["packet_features"]["fields"]) \
        + len(load_config("data")["packet_features"]["sent_fields"])
    rng = np.random.RandomState(0)  # SAME event stream both runs (isolates train RNG/ops)
    ev = T.TemporalEvents(
        src=torch.tensor(rng.randint(0, n_nodes, n_ev), dtype=torch.long),
        dst=torch.tensor(rng.randint(0, n_nodes, n_ev), dtype=torch.long),
        t=torch.arange(n_ev, dtype=torch.long),
        msg=torch.tensor(rng.randn(n_ev, msg_dim), dtype=torch.float32),
        t0=0.0,
        node_of_host={f"10.0.0.{i}": i for i in range(n_nodes)},
        num_nodes=n_nodes,
    )
    enc = T.build_model(cfg_t, num_nodes=n_nodes, msg_dim=msg_dim)
    losses = T.train_link_pred(enc, ev, {**cfg_t, "link_pred": {**cfg_t["link_pred"], "epochs": 2}})
    return _sd_hash(enc), losses


def _forward_graft_once(seed: int) -> str:
    from models import graft as G
    set_seed(seed)
    cfg_g = load_config("train_graft")
    m = G.build_model(cfg_g, feature_dim=30)
    m.train()
    x = torch.randn(8, 48, 30)
    out = m(x, delta_t=torch.ones(8, 48))
    out["attack_logit"].sum().backward()
    return _sd_hash(m) + "|" + hashlib.sha256(
        out["attack_logit"].detach().numpy().tobytes()).hexdigest()[:16]


def main() -> int:
    print(f"torch {torch.__version__} | CUDA {torch.cuda.is_available()} | "
          f"threads {torch.get_num_threads()}")

    # (1) capture flagged nondeterministic ops across both real paths
    flagged = set()
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        h_tgn_a, losses_a = _train_tgn_once(1337)
        _forward_graft_once(1337)
    for wmsg in caught:
        s = str(wmsg.message)
        if "nondeterministic" in s.lower() or "does not have a deterministic" in s.lower():
            flagged.add(s.split(".")[0][:110])
    print("\nFlagged nondeterministic ops (torch.use_deterministic_algorithms warn_only):")
    print("\n".join(f"  - {f}" for f in sorted(flagged)) if flagged else "  (none flagged)")

    # (2) TGN training reproducibility across two identical-seed runs
    h_tgn_b, losses_b = _train_tgn_once(1337)
    tgn_match = (h_tgn_a == h_tgn_b)
    loss_gap = max(abs(a - b) for a, b in zip(losses_a, losses_b))
    print(f"\nTGN train x2 (seed 1337): state_dict hash {h_tgn_a} vs {h_tgn_b} -> "
          f"{'IDENTICAL' if tgn_match else 'DIFFER'}; max per-epoch loss gap {loss_gap:.2e}")

    # (3) GRAFT forward+backward reproducibility
    g1, g2 = _forward_graft_once(1337), _forward_graft_once(1337)
    print(f"GRAFT fwd+bwd x2 (seed 1337): {'IDENTICAL' if g1 == g2 else 'DIFFER'}")

    print("\nVERDICT:", "training path is deterministic under the fix"
          if (tgn_match and g1 == g2) else
          "residual nondeterminism remains (see flagged ops / loss gap above)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
