"""Fetch the released model artifacts and check them against the README digests.

    python scripts/fetch_artifacts.py                 # download + verify
    python scripts/fetch_artifacts.py --verify-only   # check what is on disk, no network
    python scripts/fetch_artifacts.py --tag weights-v1

The weights are gitignored (CLAUDE.md forbids committing them), so a fresh clone
skips every artifact-gated test. This is the one documented command between
`git clone` and a fully exercised suite: it pulls the artifacts from the GitHub
Release and refuses to keep any file whose SHA-256 does not match the digest
published in README.md. The README table is the only source of truth for both
the artefact names and their digests - nothing is hardcoded here.

Alongside the dataset fetch, this is one of the few steps that needs network at
all: inference, the demo and ledger verification open no sockets (CLAUDE.md hard
constraint 1), and `--verify-only` re-checks the downloaded artifacts with no
network. Note that the test suite is not itself run under a socket block - that
is opt-in per test, see docs/INSTALL.md.

The release does not exist yet: the repository's /releases endpoint answers 404
to an anonymous client (re-checked 2026-09-11), so a plain run fails with that
diagnosis rather than a stack trace. A 404 is ambiguous between "no release
published" and "private repository, no credentials" - set GITHUB_TOKEN to
distinguish them. Consequently the download-and-verify path below has NEVER been
exercised against a real release; only the 404 diagnosis and `--verify-only`
have been run here.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from configs import load_config, resolve_path  # noqa: E402

# The README digest table: | `engine_model.json` | `<64 hex>` |
DIGEST_ROW = re.compile(
    r"^\|\s*`?([A-Za-z0-9_.\-]+)`?\s*\|\s*`?([0-9a-f]{64})`?\s*\|\s*$", re.MULTILINE
)
CHUNK = 1 << 20


class FetchError(RuntimeError):
    """A failure a judge can act on: message is the whole diagnosis."""


def published_digests(readme: Path) -> dict[str, str]:
    """Artefact name -> SHA-256, parsed from the README's weights table."""
    if not readme.exists():
        raise FetchError(f"{readme} is missing - it carries the published digests.")
    rows = DIGEST_ROW.findall(readme.read_text(encoding="utf-8"))
    if not rows:
        raise FetchError(
            f"no `| <artefact> | <64-hex SHA-256> |` rows found in {readme}. "
            "The 'Model weights' table is what this script verifies against; "
            "without it there is nothing to check a download against."
        )
    return dict(rows)


def repo_slug(explicit: str | None) -> str:
    """owner/name for the API, from --repo or the `origin` remote."""
    if explicit:
        return explicit.strip().strip("/")
    try:
        url = subprocess.run(
            ["git", "remote", "get-url", "origin"],
            cwd=REPO_ROOT, capture_output=True, text=True, check=True,
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError) as exc:
        raise FetchError(
            "could not read the `origin` remote to find the GitHub repository "
            f"({exc}). Pass it explicitly: --repo owner/name"
        ) from exc
    m = re.search(r"[:/]([^/:]+)/([^/]+?)(?:\.git)?/?$", url)
    if not m:
        raise FetchError(f"cannot parse an owner/name out of the origin remote: {url!r}")
    return f"{m.group(1)}/{m.group(2)}"


def _request(url: str, token: str | None, accept: str) -> urllib.request.Request:
    req = urllib.request.Request(url, headers={"Accept": accept,
                                               "User-Agent": "sih26153-fetch-artifacts"})
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    return req


def fetch_release(slug: str, tag: str | None, token: str | None,
                  api_base: str, timeout: float) -> dict:
    """The release JSON, or a FetchError whose message names the actual cause."""
    path = f"releases/tags/{tag}" if tag else "releases/latest"
    url = f"{api_base}/repos/{slug}/{path}"
    try:
        with urllib.request.urlopen(
            _request(url, token, "application/vnd.github+json"), timeout=timeout
        ) as resp:
            return json.load(resp)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            which = f"release tagged {tag!r}" if tag else "latest release"
            hint = ("GITHUB_TOKEN is set, so a private repository would still have "
                    "resolved - this really is a missing release."
                    if token else
                    "No GITHUB_TOKEN is set, so this is ambiguous: either no release "
                    "has been published yet, or the repository is private. Export a "
                    "token with `repo` scope to tell the two apart.")
            raise FetchError(
                f"GitHub returned 404 for the {which} of {slug} ({url}).\n"
                f"{hint}\n"
                "Until the Release exists there is no download to verify. Either "
                "publish it, or bootstrap the artifacts locally with "
                "`python -m engine.train_engine` (needs the dataset and "
                "SIH26_HMAC_KEY - see docs/INSTALL.md)."
            ) from exc
        if exc.code in (401, 403):
            raise FetchError(
                f"GitHub returned {exc.code} for {url}. Either the API rate limit "
                "for anonymous requests is exhausted, or the token lacks access. "
                "Set GITHUB_TOKEN and retry."
            ) from exc
        raise FetchError(f"GitHub returned HTTP {exc.code} for {url}: {exc.reason}") from exc
    except urllib.error.URLError as exc:
        raise FetchError(
            f"cannot reach {url}: {exc.reason}. This is the only step in the "
            "project that needs network; everything else runs offline."
        ) from exc


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(CHUNK), b""):
            h.update(chunk)
    return h.hexdigest()


def download_verified(url: str, dest: Path, expected: str, token: str | None,
                      timeout: float) -> None:
    """Stream to a .part file, hash as it lands, and only publish it on a match.

    A mismatching download is deleted, never left on disk: the engine binds
    ledger records to weight digests, so an unverified artefact must not be able
    to masquerade as the released one.
    """
    part = dest.with_suffix(dest.suffix + ".part")
    h = hashlib.sha256()
    dest.parent.mkdir(parents=True, exist_ok=True)
    try:
        with urllib.request.urlopen(
            _request(url, token, "application/octet-stream"), timeout=timeout
        ) as resp, open(part, "wb") as fh:
            for chunk in iter(lambda: resp.read(CHUNK), b""):
                h.update(chunk)
                fh.write(chunk)
    except urllib.error.URLError as exc:
        part.unlink(missing_ok=True)
        raise FetchError(f"download of {dest.name} failed: {exc}") from exc

    got = h.hexdigest()
    if got != expected:
        part.unlink(missing_ok=True)
        raise FetchError(
            f"SHA-256 mismatch for {dest.name}: README publishes {expected}, the "
            f"download hashed to {got}. The file was deleted."
        )
    part.replace(dest)


def verify_local(digests: dict[str, str], art_dir: Path) -> int:
    """Check what is already on disk against the README. Offline; returns an exit code."""
    bad = 0
    for name, expected in sorted(digests.items()):
        path = art_dir / name
        if not path.exists():
            print(f"MISSING   {name}  (expected under {art_dir})")
            bad += 1
            continue
        got = sha256_file(path)
        if got == expected:
            print(f"OK        {name}  {got}")
        else:
            print(f"MISMATCH  {name}  published {expected}  on disk {got}")
            bad += 1
    print(f"\n{len(digests) - bad}/{len(digests)} artifacts match the README digests.")
    return 1 if bad else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--repo", default=None,
                        help="owner/name (default: parsed from the `origin` remote)")
    parser.add_argument("--tag", default=None,
                        help="release tag to fetch (default: the latest release)")
    parser.add_argument("--verify-only", action="store_true",
                        help="hash the artifacts already on disk; no network")
    parser.add_argument("--api-base", default="https://api.github.com",
                        help="GitHub API root (change for GitHub Enterprise)")
    parser.add_argument("--timeout", type=float, default=30.0,
                        help="per-request timeout in seconds")
    args = parser.parse_args(argv)

    cfg = load_config("data")
    art_dir = resolve_path(cfg["paths"]["artifacts_dir"])

    try:
        digests = published_digests(REPO_ROOT / "README.md")
        print(f"README publishes {len(digests)} artefact digest(s); "
              f"destination {art_dir}")

        if args.verify_only:
            return verify_local(digests, art_dir)

        token = os.environ.get("GITHUB_TOKEN") or None
        slug = repo_slug(args.repo)
        release = fetch_release(slug, args.tag, token, args.api_base, args.timeout)
        print(f"release {release.get('tag_name')!r} on {slug}")

        assets = {a["name"]: a for a in release.get("assets", [])}
        absent = sorted(set(digests) - set(assets))
        if absent:
            raise FetchError(
                f"release {release.get('tag_name')!r} does not carry: "
                f"{', '.join(absent)}. It has: "
                f"{', '.join(sorted(assets)) or '(no assets)'}. The README "
                "digest table and the release must list the same artefacts."
            )

        for name, expected in sorted(digests.items()):
            asset = assets[name]
            # The API asset URL works for private releases with a token; the
            # browser URL is the anonymous path.
            url = asset["url"] if token else asset["browser_download_url"]
            print(f"downloading {name} ({asset.get('size', '?')} bytes)")
            download_verified(url, art_dir / name, expected, token, args.timeout)
            print(f"  verified {expected}")

        print(f"\n{len(digests)} artifacts downloaded and verified into {art_dir}.")
        print("Next: python -m pytest tests/ -q   (the artifact-gated tests now run)")
        return 0
    except FetchError as exc:
        print(f"\nfetch_artifacts: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
