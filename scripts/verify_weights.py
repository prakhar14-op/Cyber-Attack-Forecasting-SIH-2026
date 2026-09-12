"""Model-weight integrity (M9.3 / M12.5).

    python scripts/verify_weights.py            # verify against the recorded digest
    python scripts/verify_weights.py --record   # record the current digests

    # the same two commands against a non-default artifact lane, e.g. the demo
    # model a fresh clone fits from the bundled capture:
    python scripts/verify_weights.py --artifacts-dir artifacts/demo
    python scripts/verify_weights.py --artifacts-dir artifacts/demo --record

Every ledger batch is bound to exact weights: the engine refuses to log if the
model file's SHA-256 does not match the `weights.sha256` OF THE LANE IT LOADED.
For the published lane that digest is published in the README and travels with
the GitHub Release, so a judge can confirm the demo ran the released model.

BOTH LANES ARE ATTESTED, NEITHER IS EXEMPT. The demo lane
(scripts/bootstrap_demo_artifacts.py, resolved by engine/predict.py) keeps its own
directory and its own `weights.sha256`, so a tampered demo model is refused
exactly as a tampered published one is — the same `verify` call, reached with a
different artifacts directory.

`TRACKED` names the PUBLISHED weight files, and a demo lane does not use those
names (its files carry `configs/data.yaml` `demo.model_prefix`). Exempting it and
recording nothing would have been the silent failure here: `record` would write an
empty digest file and `verify` would then pass over a lane it had checked no bytes
of. So `tracked_names` EXTENDS the list for a demo lane, reading that lane's own
nowcast weight filenames out of its persisted thresholds instead of guessing at a
prefix. The k-step heads stay untracked in BOTH lanes, which is what
engine/forecast.py says about them.

AN EMPTY RECORD IS NOT AN ATTESTATION. On either lane, `record` refuses to write
a digest file covering no weight at all, and `verify` reads such a file as NOT
verified. Before that, `--record` in a directory with none of the tracked files
wrote `{}` and the next `verify` printed OK, having checked no bytes of anything.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from configs import load_config, resolve_path  # noqa: E402

# The PUBLISHED lane's two nowcast weight files — the only weights
# engine/predict.py ever loads for scoring. Named as their own list because a
# second module needs exactly this set and must not keep a private copy of it:
# engine/predict.py reads it to decide whether the published artifacts directory
# is HALF-INSTALLED (some of these present, no threshold file), which is the one
# state that must never be allowed to fall through to the demo lane. Two lists
# that drift would mean one module treating a file as published evidence and the
# other not seeing it at all.
PUBLISHED_NOWCAST_WEIGHTS = ["engine_model.json", "engine_model_flow.json"]

TRACKED = [*PUBLISHED_NOWCAST_WEIGHTS, "tgn_encoder.pt",
           "graft.pt", "window_scaler.pkl"]

# The two nowcast variants TRACKED names for the published lane
# ("engine_model.json", "engine_model_flow.json"). A demo lane has its own
# filenames for exactly these two, and they are read from the lane, not guessed.
_NOWCAST_TAGS = ("full", "flow")


def _persisted_thresholds(cfg) -> dict:
    """The lane's threshold file as a plain dict, or {} if there is none.

    Read directly instead of through `engine.thresholds.load_model_spec`, because
    that applies the "a demo lane may only be SERVED from its own directory"
    guard. Enumerating filenames to hash is not serving a model, and a lane must
    stay hashable even when it is sitting somewhere the engine would refuse to run
    it from — that is precisely when someone wants to check its digests.
    """
    from engine import thresholds as TH

    path = TH.threshold_path(cfg)
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (ValueError, OSError):
        # An unreadable threshold file is a lane problem, not a digest problem;
        # engine/predict.py is where it gets its loud error. Here it simply does
        # not name any demo weights, so TRACKED is what gets recorded.
        return {}
    return data if isinstance(data, dict) else {}


def is_demo_lane(cfg) -> bool:
    """True when the artifacts directory `cfg` points at declares itself a demo
    lane, by the same `artifact_lane` field engine/thresholds.py owns."""
    from engine import thresholds as TH

    return str(_persisted_thresholds(cfg).get(TH.LANE_FIELD,
                                              TH.PUBLISHED_LANE)) == TH.DEMO_LANE


def demo_nowcast_weights(cfg) -> list[str]:
    """This demo lane's own filenames for the two horizon-0 heads, out of its own
    persisted thresholds.

    Read rather than rebuilt from `demo.model_prefix`: the digest record has to
    cover the file the engine will actually load, and the persisted spec is the
    only thing that says which file that is.
    """
    from engine import thresholds as TH

    data = _persisted_thresholds(cfg)
    names: list[str] = []
    for tag in _NOWCAST_TAGS:
        spec = data.get(TH.horizon_variant(tag, 0))
        name = spec.get("file") if isinstance(spec, dict) else None
        if isinstance(name, str) and name not in names:
            names.append(name)
    return names


def tracked_names(cfg) -> list[str]:
    """What this LANE's digest record must cover.

    Detected from the directory rather than passed in, so `record(cfg)` called by
    a bootstrap script — not just by this CLI — covers that lane's weights too.
    """
    names = list(TRACKED)
    if is_demo_lane(cfg):
        names += [n for n in demo_nowcast_weights(cfg) if n not in names]
    return names


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
    digests = {n: sha256_file(art / n) for n in tracked_names(cfg) if (art / n).exists()}
    if is_demo_lane(cfg):
        # A demo lane whose own nowcast weights are not in the record is the
        # silent-exemption failure this function exists to avoid: `verify` would
        # then pass over a lane it had hashed none of.
        unhashed = [n for n in demo_nowcast_weights(cfg)
                    if (art / n).exists() and n not in digests]
        if unhashed:
            raise RuntimeError(
                f"refusing to write a digest record for the demo lane {art} that does "
                f"not cover {unhashed}. A record that hashes nothing verifies nothing."
            )
    if not digests:
        # BOTH lanes. `--record` against a directory holding none of the tracked
        # files used to write `{}`, and `verify` then reported OK because it had
        # nothing to disagree with: an empty record is not an attestation, it is
        # the absence of one wearing its name. Refuse to write it.
        raise RuntimeError(
            f"refusing to write a digest record for {art}: none of the tracked weight "
            f"files {tracked_names(cfg)} are there, so the record would hash nothing "
            "and `verify` would then pass over a directory it had checked no bytes of. "
            "Fetch or fit the artifacts first."
        )
    digest_path(cfg).write_text(json.dumps(digests, indent=2), encoding="utf-8")
    return digests


def verify(cfg, names: list[str] | None = None) -> tuple[bool, str | None]:
    """(ok, offending_name). Missing digest file -> not verified.

    An EMPTY record is also not verified. Called with `names=None` it used to
    iterate an empty list and return (True, None) — "OK: all tracked model
    weights match" for a directory whose record covered no file at all. `record`
    now refuses to write such a file, but a record can also be emptied by hand,
    and the answer to "is this bundle attested" must never be yes on no evidence.
    """
    path = digest_path(cfg)
    if not path.exists():
        return False, "weights.sha256 (run scripts/verify_weights.py --record)"
    recorded = json.loads(path.read_text(encoding="utf-8"))
    if not recorded:
        return False, f"weights.sha256 records no file at all ({path})"
    art = resolve_path(cfg["paths"]["artifacts_dir"])
    for name in names or list(recorded):
        if name not in recorded:
            return False, name
        f = art / name
        if not f.exists() or sha256_file(f) != recorded[name]:
            return False, name
    return True, None


def lane_cfg(cfg: dict, artifacts_dir: str | None) -> dict:
    """`cfg` aimed at one artifact lane. Unchanged when no directory is given, so
    the default remains the published lane exactly as before."""
    if not artifacts_dir:
        return cfg
    return {**cfg, "paths": {**cfg["paths"], "artifacts_dir": artifacts_dir}}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--record", action="store_true")
    parser.add_argument(
        "--artifacts-dir", default=None,
        help="verify/record a lane other than paths.artifacts_dir — e.g. the demo "
             "lane at configs/data.yaml `demo.artifacts_dir`. Each lane keeps its "
             "own weights.sha256; neither is exempt from attestation.")
    args = parser.parse_args(argv)
    cfg = lane_cfg(load_config("data"), args.artifacts_dir)
    from engine import thresholds as TH

    lane = TH.DEMO_LANE if is_demo_lane(cfg) else TH.PUBLISHED_LANE

    if args.record:
        try:
            digests = record(cfg)
        except RuntimeError as exc:
            # A record that hashes nothing is refused (see `record`). Say so as a
            # message and an exit code, not as a traceback.
            print(f"REFUSED: {exc}", file=sys.stderr)
            return 1
        for n, d in digests.items():
            print(f"{d}  {n}")
        print(f"-> {digest_path(cfg)} ({lane} lane)")
        return 0

    ok, bad = verify(cfg)
    if ok:
        print(f"OK: all tracked model weights match their recorded SHA-256 "
              f"({lane} lane, {resolve_path(cfg['paths']['artifacts_dir'])})")
        if lane == TH.DEMO_LANE:
            print("NOTE: these are DEMO weights fitted from the bundled synthetic "
                  "capture. Matching digests prove the files are unmodified — they "
                  "say nothing about detection quality, and this lane reproduces no "
                  "published number.")
        return 0
    print(f"MISMATCH: {bad} ({lane} lane)", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
