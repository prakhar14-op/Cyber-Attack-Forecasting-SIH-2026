"""Tamper-evident audit ledger (M9).

An append-only, hash-chained JSONL of forecast records plus a separate anchored
checkpoint log. Two tamper modes are caught (BUILD_PLAN M9.5, test_ledger_tamper):

- **Single-record edit** — each record carries `prev` (the previous record's
  hash) and `hash` (the hash of its canonical content including `prev`).
  Editing record i breaks i's own hash, so `verify()` fails at exactly i.
- **Full self-consistent rewrite** — a forger who recomputes the whole chain
  passes `verify()`, but the chain HEAD hash no longer matches the value
  anchored in the separate checkpoint log, so `verify_against_checkpoints()`
  fails. (In the demo, one checkpoint is anchored to a public location before
  the run — BUILD_PLAN scopes out a live blockchain push as dishonest overkill.)

Privacy (M9.2): raw IPs never enter the ledger. `append` replaces any `host`
field with a keyed-HMAC pseudonym; the HMAC key lives only in the owner's
environment, so pseudonyms are unlinkable without it.

Storage is append-only (one JSON line per record); verification streams the
file and never rewrites it.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from pathlib import Path

from ledger.merkle import leaf_hash, merkle_root

_GENESIS = "0" * 64


def _canonical(obj: dict) -> str:
    """Deterministic JSON for hashing (sorted keys, no whitespace)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _record_hash(prev: str, content: dict) -> str:
    m = hashlib.sha256()
    m.update(prev.encode("ascii"))
    m.update(_canonical(content).encode("utf-8"))
    return m.hexdigest()


class Ledger:
    def __init__(
        self,
        chain_path: str | os.PathLike,
        checkpoint_path: str | os.PathLike | None = None,
        hmac_key: bytes | None = None,
    ):
        self.chain_path = Path(chain_path)
        self.checkpoint_path = (
            Path(checkpoint_path)
            if checkpoint_path is not None
            else self.chain_path.with_name("checkpoints.jsonl")
        )
        self._key = hmac_key if hmac_key is not None else self._env_key()
        self._head, self._count = self._resume_head()

    @staticmethod
    def _env_key() -> bytes:
        # A ledger-specific key; falls back to a fixed test key only when unset
        # (real deployments set SIH26_LEDGER_KEY; pseudonyms are meaningless
        # across keys, which is the point).
        return os.environ.get("SIH26_LEDGER_KEY", "sih26-ledger-dev").encode("utf-8")

    # -- pseudonymisation ---------------------------------------------------

    def _pseudonym(self, value: str) -> str:
        return hmac.new(self._key, value.encode("utf-8"), hashlib.sha256).hexdigest()[:16]

    # -- append -------------------------------------------------------------

    def _resume_head(self) -> tuple[str, int]:
        """Recover (head hash, count) from an existing chain, so a process
        restart continues the same chain."""
        if not self.chain_path.exists():
            return _GENESIS, 0
        head, count = _GENESIS, 0
        with open(self.chain_path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                head = json.loads(line)["hash"]
                count += 1
        return head, count

    def append(self, record: dict) -> dict:
        """Append one forecast record. Any `host` is pseudonymised; the record
        is chained to the current head and flushed to disk immediately."""
        content = dict(record)
        if "host" in content:
            content["host"] = self._pseudonym(str(content["host"]))
        content["seq"] = self._count
        content["prev"] = self._head
        h = _record_hash(self._head, content)
        entry = dict(content, hash=h)

        self.chain_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.chain_path, "a", encoding="utf-8") as fh:
            fh.write(_canonical(entry) + "\n")
        self._head, self._count = h, self._count + 1
        return entry

    # -- checkpoints (anchoring) -------------------------------------------

    def checkpoint(self) -> dict:
        """Anchor the current chain head + count + Merkle root of all records
        into the separate checkpoint log. In the demo this log's latest line is
        also copied to a public location before the run."""
        leaves = []
        if self.chain_path.exists():
            with open(self.chain_path, encoding="utf-8") as fh:
                for line in fh:
                    if line.strip():
                        leaves.append(leaf_hash(line.strip()))
        cp = {"head": self._head, "count": self._count, "merkle_root": merkle_root(leaves)}
        self.checkpoint_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.checkpoint_path, "a", encoding="utf-8") as fh:
            fh.write(_canonical(cp) + "\n")
        return cp

    # -- verification -------------------------------------------------------

    def verify(self) -> tuple[bool, int | None]:
        """Recompute the hash chain. Returns (ok, first_bad_index): the first
        record whose stored hash or prev-link is inconsistent, or (True, None)."""
        if not self.chain_path.exists():
            return True, None
        prev = _GENESIS
        with open(self.chain_path, encoding="utf-8") as fh:
            for i, line in enumerate(fh):
                line = line.strip()
                if not line:
                    continue
                entry = json.loads(line)
                stored = entry.pop("hash", None)
                if entry.get("prev") != prev:
                    return False, i
                if stored != _record_hash(prev, entry):
                    return False, i
                prev = stored
        return True, None

    def verify_against_checkpoints(self) -> bool:
        """True iff the current chain head matches an anchored checkpoint at the
        same count. Catches a full self-consistent rewrite (which re-passes
        verify() but produces a different head hash)."""
        if not self.checkpoint_path.exists():
            return False
        head, count = self._resume_head()
        with open(self.checkpoint_path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                cp = json.loads(line)
                if cp["count"] == count:
                    return cp["head"] == head
        return False
