"""Config loading and global seeding.

The only module that touches YAML under configs/. Everything downstream calls
load_config(name) and reads paths, seeds and hyper-parameters from the returned
dict — never from literals in code (CLAUDE.md, M0.3).
"""

from __future__ import annotations

import os
import random
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
CONFIG_DIR = Path(__file__).resolve().parent


def load_config(name: str) -> dict:
    """Load configs/<name>.yaml into a dict. `name` may include the extension."""
    filename = name if name.endswith((".yaml", ".yml")) else f"{name}.yaml"
    path = CONFIG_DIR / filename
    if not path.exists():
        raise FileNotFoundError(f"config not found: {path}")
    with open(path, encoding="utf-8") as fh:
        cfg = yaml.safe_load(fh)
    if not isinstance(cfg, dict):
        raise ValueError(f"config {path} did not parse to a mapping")
    return cfg


def resolve_path(repo_relative: str | os.PathLike) -> Path:
    """Resolve a repo-relative path from a config value to an absolute Path."""
    return (REPO_ROOT / Path(repo_relative)).resolve()


def set_seed(seed: int) -> list[str]:
    """Seed every RNG framework installed; return the names of those seeded.

    torch is optional at M0 (no model files yet) but mandatory from M5 on —
    model modules import it directly and fail loudly if it is absent.
    """
    seeded = ["random", "hashseed"]
    random.seed(seed)
    os.environ["PYTHONHASHSEED"] = str(seed)

    try:
        import numpy as np
    except ImportError:
        pass
    else:
        np.random.seed(seed)
        seeded.append("numpy")

    # CUBLAS workspace must be pinned for deterministic CUDA matmul; harmless on
    # CPU. setdefault + set here (set_seed runs before any CUDA context) — for a
    # hard guarantee on GPU, also export it in the shell before the process.
    os.environ.setdefault("CUBLAS_WORKSPACE_CONFIG", ":4096:8")

    try:
        import torch
    except ImportError:
        pass
    else:
        torch.manual_seed(seed)
        torch.cuda.manual_seed_all(seed)  # no-op on a CPU build
        # Seeding alone does not defeat nondeterministic parallel reductions
        # (CPU multi-thread scatter/index sums) or cuDNN algorithm search — that
        # is what let identical-seed twin runs diverge 0.853 vs 0.923. Lock the
        # algorithms too. warn_only=True: an op with no deterministic kernel
        # still runs (and is flagged) rather than hard-failing mid-training.
        torch.backends.cudnn.deterministic = True
        torch.backends.cudnn.benchmark = False
        try:
            torch.use_deterministic_algorithms(True, warn_only=True)
        except Exception:  # older torch without the flag
            pass
        seeded.append("torch")

    return seeded
