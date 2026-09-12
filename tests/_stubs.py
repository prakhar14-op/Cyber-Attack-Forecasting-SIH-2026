"""Helpers for milestone-gated tests.

The seven required tests are written against the final APIs before those APIs
exist. Until the owning milestone lands, each test must FAIL (never error, never
skip) with a message naming that milestone — `pytest -q` at M0 shows 7 failures,
0 errors (BUILD_PLAN M0.5).
"""

from __future__ import annotations

import hashlib
import importlib
import inspect
import importlib.util
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent


def require_module(dotted: str, milestone: str):
    """Import a project module, or fail the test naming the milestone that ships it."""
    try:
        return importlib.import_module(dotted)
    except ModuleNotFoundError as exc:
        missing = exc.name or ""
        if (
            missing == dotted
            or dotted.startswith(missing + ".")
            or missing.startswith(dotted + ".")
        ):
            pytest.fail(f"{dotted} is not implemented yet — lands in {milestone}", pytrace=False)
        raise  # a genuinely missing third-party dependency is an environment bug


def require_attr(module, name: str, milestone: str):
    """Fetch an attribute from a module, or fail naming the owning milestone."""
    if not hasattr(module, name):
        pytest.fail(
            f"{module.__name__}.{name} is not implemented yet — lands in {milestone}",
            pytrace=False,
        )
    return getattr(module, name)


def require_file(repo_relative: str, milestone: str) -> Path:
    """Return a repo file's Path, or fail naming the milestone that creates it."""
    path = REPO_ROOT / repo_relative
    if not path.exists():
        pytest.fail(
            f"{repo_relative} does not exist yet — created in {milestone}", pytrace=False
        )
    return path




# --------------------------------------------------------------------------
# Which model, if any, is on this machine - and whose numbers it can be evidence
# for.
#
# This was one boolean, `engine_artifacts_present()`. One boolean has exactly two
# answers and the repository now has three situations, because
# scripts/bootstrap_demo_artifacts.py can fit a demo model from the bundled
# synthetic capture (app/assets/synthetic_demo.pcap) on a machine that has
# neither the released weights nor the ~12.7 GiB dataset. A boolean cannot tell
# those apart, so a suite gated on one would eventually report a toy model fitted
# on one 455-second hand-authored capture as though it were the CSE-CIC-IDS-2018
# model whose numbers this project publishes. That is the project's named failure
# mode - claims outrunning the code - in test form.
#
# The three lanes:
#
#   LANE_REAL  the published bundle is complete under
#              configs/data.yaml `paths.artifacts_dir`. This is the only lane in
#              which a passing test can be evidence for a published number, and
#              even here the lane carries its own digest evidence (see
#              `digest_verified` / `digest_unverified`), because "the files are
#              present" and "the files are the RELEASED files" are different
#              facts and only the second one ties a result to a published table.
#   LANE_DEMO  the published bundle is absent and engine/predict.py would fall
#              back to the demo lane. Tests that exercise PLUMBING (does the
#              pipeline run with sockets blocked, does the ledger verify, is a run
#              reproducible) are real checks here. Tests whose subject is a
#              measured number are not, and must not run - see
#              tests/conftest.py::PUBLISHED_ONLY.
#   LANE_NONE  no lane the engine would load. A bare clone, and also a
#              half-written or self-contradictory lane, because neither of those
#              can run anything either.
#
# WHICH lane is not decided here. engine/predict.py::resolve_artifact_lane is
# what actually chooses the bundle a run loads, so this asks THAT function rather
# than reimplementing its precedence rules. A second copy of "published first,
# demo only as a complete self-declared fallback" is a second copy that can
# drift, and the drift would be invisible: the suite would report one lane while
# the engine loaded another.
#
# The asymmetry is deliberate. Every failure of this probe - engine.predict not
# importable, a contradictory config, a half-written bundle - resolves to
# LANE_NONE or LANE_DEMO and therefore UNDER-claims. There is no path to
# LANE_REAL except the published bundle being complete where the engine looks
# for it.

LANE_REAL = "real"
LANE_DEMO = "demo"
LANE_NONE = "none"
LANES = (LANE_REAL, LANE_DEMO, LANE_NONE)

# The published bundle, by name. UNCHANGED from the single-boolean version on
# purpose: `engine_artifacts_present()` still answers exactly the question it
# answered before (is the published bundle on disk), three test modules outside
# this workstream gate on it at import time, and
# tests/test_demo_bootstrap.py::test_the_demo_lane_does_not_satisfy_the_real_artifact_gate
# pins that building a demo lane does not make it true. Widening it here would
# have turned those skips green against a toy model, which is the one outcome
# every part of this design exists to prevent.
ENGINE_ARTIFACTS = (
    "engine_model.json",
    "engine_model_flow.json",
    "window_scaler.pkl",
    "engine_threshold.json",
)


@dataclass(frozen=True)
class ArtifactLane:
    """Which lane this checkout is in, and the evidence that put it there."""

    lane: str
    detail: str
    artifacts_dir: Path
    present: tuple[str, ...] = ()
    missing: tuple[str, ...] = ()
    digest_verified: tuple[str, ...] = ()
    digest_unverified: tuple[str, ...] = ()
    digest_detail: str = ""

    @property
    def has_model(self) -> bool:
        """A bundle engine/predict.py would load, of either provenance."""
        return self.lane in (LANE_REAL, LANE_DEMO)

    @property
    def is_published(self) -> bool:
        """The published bundle is on disk. Necessary for a published claim."""
        return self.lane == LANE_REAL

    @property
    def digests_match(self) -> bool:
        """...and it is the RELEASED bundle, not a local rebuild of it.

        Separate from `is_published` so that a team member who retrains locally
        keeps every gate they had, while a report that says "verified against the
        published artifacts" can require the stronger fact.
        """
        return (self.is_published
                and bool(self.digest_verified)
                and not self.digest_unverified)


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _published_digests() -> tuple[dict[str, str], str]:
    """(name -> SHA-256, why it is empty).

    The README weights table is the published record; scripts/fetch_artifacts.py
    parses it to decide whether a downloaded artifact is the released one, and
    this reuses that parser rather than writing a second regex that could
    disagree with it. Loaded by file path, not imported, so `scripts/` does not
    end up on sys.path for the rest of the suite.
    """
    script = REPO_ROOT / "scripts" / "fetch_artifacts.py"
    if not script.exists():
        return {}, f"{script} is missing, so no digest can be checked"
    try:
        spec = importlib.util.spec_from_file_location("_fetch_artifacts_probe", script)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)  # type: ignore[union-attr]
        return module.published_digests(REPO_ROOT / "README.md"), ""
    except Exception as exc:  # a moved table must not silently become a pass
        return {}, f"{type(exc).__name__}: {exc}"


def _digest_evidence(art: Path, present: tuple[str, ...]):
    """(verified, unverified, detail) for the published bundle on disk."""
    published, why_empty = _published_digests()
    if not published:
        return (), (), f"no digest could be checked ({why_empty})"
    checkable = [n for n in present if n in published]
    if not checkable:
        return (), tuple(present), (
            "the published table in README.md names none of these artefacts")
    verified = tuple(n for n in checkable if _sha256(art / n) == published[n])
    unverified = tuple(n for n in checkable if n not in verified)
    if unverified:
        return verified, unverified, (
            f"SHA-256 MISMATCH against README.md on {', '.join(unverified)} - these "
            "are not the released bytes (a local retrain, or a tampered file)")
    return verified, (), (
        f"{', '.join(verified)} match the SHA-256 digests published in README.md")


def _engine_demo_lane(cfg: dict) -> tuple[Path | None, str, str]:
    """(demo dir, what it says it was fitted from, why not) via engine/predict.py.

    Asks the engine's own resolver, so this cannot disagree with the bundle a run
    would actually load. Every failure answers "no demo lane" WITH the reason, and
    the reason reaches the report: a contradictory config or a half-written
    bootstrap must not read as a bare clone.
    """
    try:
        from engine import predict as P
    except Exception as exc:
        return None, "", f"engine.predict is not importable ({type(exc).__name__}: {exc})"
    resolve = getattr(P, "resolve_artifact_lane", None)
    if resolve is None:
        return None, "", ("engine.predict has no resolve_artifact_lane(); this checkout "
                          "predates the demo lane")
    # The resolver takes the input variant ('flow' for CSV, 'full' for PCAP)
    # because a lane's claim is tested by asking it for that variant's model
    # spec. Both are tried, and the signature is inspected rather than assumed,
    # so this probe keeps working whichever shape that function has - a lane the
    # engine can serve for EITHER variant is a lane a test could run on.
    try:
        takes_variant = len(inspect.signature(resolve).parameters) > 1
    except (TypeError, ValueError):
        takes_variant = True
    attempts = [("flow",), ("full",)] if takes_variant else [()]
    reasons = []
    for args in attempts:
        try:
            lane = resolve(cfg, *args)
        except Exception as exc:
            reasons.append(f"{'/'.join(args) or 'default'}: {exc}")
            continue
        if getattr(lane, "demo", False):
            return Path(lane.dir), (getattr(lane, "source", None) or ""), ""
    if reasons:
        return None, "", ("engine.predict resolves no lane here - "
                          + "; ".join(reasons))
    return None, "", "engine.predict resolves no demo lane here"


@lru_cache(maxsize=1)
def engine_artifact_lane() -> ArtifactLane:
    """Which bundle this checkout has, and what it is evidence for.

    Cached for the process (test modules call it at import time). Call
    reset_artifact_lane_cache() after changing the config or the directories.
    """
    from configs import load_config, resolve_path

    cfg = load_config("data")
    art = resolve_path(cfg["paths"]["artifacts_dir"])
    present = tuple(n for n in ENGINE_ARTIFACTS if (art / n).exists())
    missing = tuple(n for n in ENGINE_ARTIFACTS if n not in present)

    if not missing:
        verified, unverified, digest_detail = _digest_evidence(art, present)
        return ArtifactLane(
            LANE_REAL,
            f"the published bundle is complete under {art}. {digest_detail}.",
            art, present, missing, verified, unverified, digest_detail,
        )

    demo_dir, source, why_not = _engine_demo_lane(cfg)
    if demo_dir is not None:
        fitted = f" It declares it was fitted from {source}." if source else ""
        return ArtifactLane(
            LANE_DEMO,
            f"the published bundle under {art} is incomplete ({', '.join(missing)} "
            f"missing), and engine/predict.py would fall back to the DEMO lane at "
            f"{demo_dir}.{fitted} That model was fitted from bundled synthetic "
            "traffic, not from CSE-CIC-IDS-2018: it can show the pipeline running "
            "and it cannot be evidence for any published number.",
            demo_dir, present, missing,
        )

    return ArtifactLane(
        LANE_NONE,
        f"no bundle engine/predict.py would load: {', '.join(missing)} missing under "
        f"{art}, and {why_not}.",
        art, present, missing,
    )


def reset_artifact_lane_cache() -> None:
    """Drop the cached probe. Tests that construct a lane on disk call this."""
    engine_artifact_lane.cache_clear()


def engine_artifacts_present() -> bool:
    """True when the PUBLISHED engine artifacts are on disk.

    Same question, same answer as before the lanes existed: all four files of the
    published bundle under configs/data.yaml `paths.artifacts_dir`. A
    bootstrapped demo lane does NOT make this true - the demo weights are written
    to their own directory under their own names, and
    tests/test_demo_bootstrap.py pins that. Widening this to "any loadable model"
    would turn the gated end-to-end tests green against a toy model, which is
    exactly the trap.

    Use engine_model_loadable() for "can this machine run the pipeline at all",
    and see tests/conftest.py for which tests may be answered by which.
    """
    return engine_artifact_lane().is_published


def engine_model_loadable() -> bool:
    """True when engine/predict.py would find SOME bundle - published or demo.

    The gate for a test whose subject is plumbing rather than accuracy. It is
    deliberately NOT a synonym for engine_artifacts_present(): a test gated on
    this one may run against the demo model, so it must not assert a number.
    """
    return engine_artifact_lane().has_model


def published_artifacts_are_the_released_ones() -> bool:
    """True only when the published bundle on disk matches the README digests.

    Stronger than engine_artifacts_present(): it distinguishes "someone trained a
    model here" from "this is the artefact the published numbers were measured
    on". Nothing gates on it today; the bootstrap report states it, so that a
    reader is never told "verified against the published artifacts" on the
    strength of a local rebuild.
    """
    return engine_artifact_lane().digests_match
