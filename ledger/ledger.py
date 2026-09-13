"""Tamper-evident audit ledger (M9).

An append-only, hash-chained JSONL of forecast records plus a separate,
independently authenticated checkpoint log. What `check_anchor()` catches
(BUILD_PLAN M9.5, test_ledger_tamper) — and, at the end, what it does not:

- **Single-record edit** — each record carries `prev` (the previous record's
  hash) and `hash` (the hash of its canonical content including `prev`).
  Editing record i breaks i's own hash, so `verify()` fails at exactly i.
- **Full self-consistent rewrite** — a forger who recomputes the whole chain
  passes `verify()`, so the chain alone proves nothing. Both files live in the
  same directory and are writable by the same process, so a forger who can
  rewrite the chain can rewrite the checkpoint log with it. What they cannot do
  is re-sign it: every checkpoint carries an HMAC over its own content under a
  key derived from SIH26_LEDGER_KEY, which lives in the operator's environment
  and never in the run directory. `check_anchor()` rejects a checkpoint log with
  any unsigned or wrongly-signed line, so a forged checkpoint is not an anchor.
- **Rollback / truncation** — deleting trailing records rolls the ledger back to
  an earlier honest state with every remaining hash still correct, so neither
  `verify()` nor a per-line signature check notices. Two rules close the part of
  this that is closable: each checkpoint carries `prev_sig` (the previous
  checkpoint's signature, `_GENESIS` for the first), making the checkpoint log a
  signed chain of its own; and only the LAST checkpoint line may anchor the
  chain. Deleting or reordering an interior checkpoint breaks `prev_sig`;
  deleting records while the checkpoint log survives leaves the last checkpoint
  describing a longer chain.

**Not caught, by construction:** truncating BOTH files together — dropping
trailing records *and* the checkpoint lines that cover them. The result is a
shorter, internally perfect, correctly signed ledger, indistinguishable from an
honest run that stopped earlier. No scheme reading only these two files can tell
the difference, because nothing inside them records that the run continued. Only
an external anchor closes it: `scripts/anchor_checkpoint.py` emits the signed
head and count for a human to publish before a demo, and a truncated ledger
contradicts the count the room already has. The same anchor is what constrains
the operator, who holds the signing key and can therefore re-sign any rewrite.

Privacy (M9.2): raw IPs never enter the ledger. `append` replaces any `host`
field with a keyed-HMAC pseudonym. There is no default key: the attackers in
CIC-IDS-2018 are ~15 fixed public addresses, so a key an attacker can read out
of the source tree reverses every pseudonym in one rainbow table.

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

KEY_ENV_VAR = "SIH26_LEDGER_KEY"

# Checkpoint signatures use a key derived from the ledger key rather than the
# ledger key itself, so a signature can never act as a pseudonym oracle.
_ANCHOR_DOMAIN = b"sih26-checkpoint-anchor-v1"
_SIG_FIELD = "sig"
_PREV_SIG_FIELD = "prev_sig"

# check_anchor() reasons — the CLI maps these to distinct operator messages.
ANCHOR_OK = "ok"
ANCHOR_MISSING = "checkpoint-log-missing-or-empty"
ANCHOR_UNSIGNED = "checkpoint-unsigned"
ANCHOR_BAD_SIGNATURE = "checkpoint-signature-invalid"
ANCHOR_CHECKPOINT_CHAIN_BROKEN = "checkpoint-log-chain-broken"
ANCHOR_LENGTH_MISMATCH = "last-checkpoint-length-mismatch"
ANCHOR_MISMATCH = "chain-does-not-match-checkpoint"


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
        if hmac_key is not None and not hmac_key:
            raise ValueError("ledger key must be non-empty")
        self._key = hmac_key if hmac_key is not None else self._env_key()
        self._anchor_key = hmac.new(self._key, _ANCHOR_DOMAIN, hashlib.sha256).digest()
        self._head, self._count = self._resume_head()

    @staticmethod
    def _env_key(env: dict | None = None) -> bytes:
        env = os.environ if env is None else env
        key = env.get(KEY_ENV_VAR, "")
        if not key:
            raise RuntimeError(
                f"ledger key env var '{KEY_ENV_VAR}' is unset. Refusing to run with a "
                "default key (a default published in the source reverses every host "
                "pseudonym over the dataset's ~15 fixed attacker IPs; see .env.example)"
            )
        return key.encode("utf-8")

    @property
    def head(self) -> str:
        return self._head

    @property
    def count(self) -> int:
        return self._count

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

    def _checkpoint_sig(self, cp: dict) -> str:
        body = {k: v for k, v in cp.items() if k != _SIG_FIELD}
        return hmac.new(
            self._anchor_key, _canonical(body).encode("utf-8"), hashlib.sha256
        ).hexdigest()

    def _prev_checkpoint_sig(self) -> str:
        """The signature of the last checkpoint already in the log, which the new
        checkpoint commits to. `_GENESIS` when the log is absent or empty."""
        last = self.latest_checkpoint()
        if last is None:
            return _GENESIS
        sig = last.get(_SIG_FIELD)
        if not isinstance(sig, str):
            raise RuntimeError(
                f"refusing to extend {self.checkpoint_path}: its last checkpoint "
                "carries no signature, so a new checkpoint cannot chain to it"
            )
        return sig

    def checkpoint(self) -> dict:
        """Anchor the current chain head + count + Merkle root of all records
        into the separate checkpoint log, signed under the derived anchor key.
        The signature is what makes the log an anchor rather than a second copy
        of the same directory's contents. The Merkle root is recomputed the same
        way check_anchor() checks it, so the two can never drift. `prev_sig`
        chains this checkpoint to the previous one, so a checkpoint cannot be
        removed from the middle of the log or lifted out of another run."""
        cp = {"head": self._head, "count": self._count,
              "merkle_root": self._current_merkle_root(),
              _PREV_SIG_FIELD: self._prev_checkpoint_sig()}
        cp[_SIG_FIELD] = self._checkpoint_sig(cp)
        self.checkpoint_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.checkpoint_path, "a", encoding="utf-8") as fh:
            fh.write(_canonical(cp) + "\n")
        return cp

    def latest_checkpoint(self) -> dict | None:
        """The last signed checkpoint line, or None when the log is absent or
        empty. Signatures are NOT checked here — callers that need authenticity
        go through check_anchor()."""
        if not self.checkpoint_path.exists():
            return None
        last = None
        with open(self.checkpoint_path, encoding="utf-8") as fh:
            for line in fh:
                if line.strip():
                    last = json.loads(line)
        return last

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

    def _current_merkle_root(self) -> str:
        """Merkle root recomputed over the current chain records (one leaf per
        line), matching what checkpoint() anchored."""
        leaves = []
        if self.chain_path.exists():
            with open(self.chain_path, encoding="utf-8") as fh:
                for line in fh:
                    if line.strip():
                        leaves.append(leaf_hash(line.strip()))
        return merkle_root(leaves)

    def check_anchor(self) -> tuple[bool, str]:
        """(ok, reason) for the chain against its checkpoint log.

        Every line must carry a valid signature, not just the one at the current
        length: a forger who rewrites the chain and appends a matching checkpoint
        is caught by the signature, and one who rewrites the whole log is caught
        on its first line. Every line must also carry the previous line's
        signature in `prev_sig`, so a checkpoint cannot be dropped from the
        middle of the log or spliced in from another run. Only the LAST
        checkpoint anchors, and it must agree on record count, head hash AND
        recomputed Merkle root — the count catches deleted trailing records, the
        root catches a content edit that leaves the head alone.

        See the module docstring for the one mode this cannot catch: truncating
        the chain and the checkpoint log together.
        """
        if not self.checkpoint_path.exists():
            return False, ANCHOR_MISSING
        head, count = self._resume_head()
        root = self._current_merkle_root()
        last = None
        prev_sig = _GENESIS
        with open(self.checkpoint_path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                cp = json.loads(line)
                sig = cp.get(_SIG_FIELD)
                if not isinstance(sig, str):
                    return False, ANCHOR_UNSIGNED
                if not hmac.compare_digest(sig, self._checkpoint_sig(cp)):
                    return False, ANCHOR_BAD_SIGNATURE
                if cp.get(_PREV_SIG_FIELD) != prev_sig:
                    return False, ANCHOR_CHECKPOINT_CHAIN_BROKEN
                prev_sig, last = sig, cp
        if last is None:
            return False, ANCHOR_MISSING
        if last.get("count") != count:
            return False, ANCHOR_LENGTH_MISMATCH
        if last.get("head") == head and last.get("merkle_root") == root:
            return True, ANCHOR_OK
        return False, ANCHOR_MISMATCH

    def verify_against_checkpoints(self) -> bool:
        """Boolean form of check_anchor() — kept for the app panel and the M9.5
        test, which only ask whether the chain is anchored."""
        return self.check_anchor()[0]
