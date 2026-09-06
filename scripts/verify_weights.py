"""Model-weight integrity (M9.3 / M12.5).

    python scripts/verify_weights.py            # verify against the recorded digest
    python scripts/verify_weights.py --record   # record the current digests

Every ledger batch is bound to exact weights: the engine refuses to log if the
model file's SHA-256 does not match `artifacts/weights.sha256`. The same digest
is published in the README and travels with the GitHub Release, so a judge can
confirm the demo ran the released model.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from configs import load_config, resolve_path  # noqa: E402

TRACKED = ["engine_model.json", "engine_model_flow.json", "tgn_encoder.pt",
           "graft.pt", "window_scaler.pkl"]


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def digest_path(cfg) -> Path:
    return resolve_path(cfg["paths"]["artifacts_dir"]) / "weights.sha256"


def record(cfg) -> dict:
    art = resolve_path(cfg["paths"]["artifacts_dir"])
    digests = {n: sha256_file(art / n) for n in TRACKED if (art / n).exists()}
    digest_path(cfg).write_text(json.dumps(digests, indent=2), encoding="utf-8")
    return digests


def verify(cfg, names: list[str] | None = None) -> tuple[bool, str | None]:
    """(ok, offending_name). Missing digest file -> not verified."""
    path = digest_path(cfg)
    if not path.exists():
        return False, "weights.sha256 (run scripts/verify_weights.py --record)"
    recorded = json.loads(path.read_text(encoding="utf-8"))
    art = resolve_path(cfg["paths"]["artifacts_dir"])
    for name in names or list(recorded):
        if name not in recorded:
            return False, name
        f = art / name
        if not f.exists() or sha256_file(f) != recorded[name]:
            return False, name
    return True, None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--record", action="store_true")
    args = parser.parse_args(argv)
    cfg = load_config("data")

    if args.record:
        for n, d in record(cfg).items():
            print(f"{d}  {n}")
        print(f"-> {digest_path(cfg)}")
        return 0

    ok, bad = verify(cfg)
    if ok:
        print("OK: all tracked model weights match their recorded SHA-256")
        return 0
    print(f"MISMATCH: {bad}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
