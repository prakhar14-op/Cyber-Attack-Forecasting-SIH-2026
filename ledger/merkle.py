"""Merkle root over a batch of prediction records (M9.1).

A Merkle root commits to every record written to the ledger (one leaf per
alert forecast), so a judge can verify the whole batch with one root while the
hash chain gives per-record tamper-evidence. The root is anchored in each
checkpoint and re-checked at verification (Ledger.verify_against_checkpoints),
so it is an independently verified commitment. Duplicated last leaf on odd
counts (Bitcoin-style), domain-separated leaf/node hashing to prevent
second-preimage tricks.
"""

from __future__ import annotations

import hashlib

_LEAF = b"\x00"
_NODE = b"\x01"


def _h(prefix: bytes, *parts: bytes) -> str:
    m = hashlib.sha256()
    m.update(prefix)
    for p in parts:
        m.update(p)
    return m.hexdigest()


def leaf_hash(payload: str) -> str:
    return _h(_LEAF, payload.encode("utf-8"))


def merkle_root(leaves: list[str]) -> str:
    """Root over pre-hashed leaf hex digests. Empty -> the empty-leaf hash."""
    if not leaves:
        return _h(_LEAF, b"")
    level = list(leaves)
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])  # duplicate the last leaf
        level = [
            _h(_NODE, bytes.fromhex(level[i]), bytes.fromhex(level[i + 1]))
            for i in range(0, len(level), 2)
        ]
    return level[0]
