"""Standalone offline ledger verifier (M9.6).

    python -m ledger.verify_cli audit_chain.jsonl [checkpoints.jsonl]

A judge runs this with no network. Exit 0 = the hash chain is intact AND (if a
checkpoint log is present) the head matches an anchored checkpoint; non-zero
otherwise, naming the first bad record.
"""

from __future__ import annotations

import sys
from pathlib import Path

from ledger.ledger import Ledger


def verify(chain_path, checkpoint_path=None) -> tuple[bool, int | None]:
    """Chain integrity (and checkpoint anchoring when a checkpoint log exists).
    Returns (ok, first_bad_index) — the API tests/test_offline.py expects."""
    chain_path = Path(chain_path)
    cp = Path(checkpoint_path) if checkpoint_path else chain_path.with_name("checkpoints.jsonl")
    ledger = Ledger(chain_path, checkpoint_path=cp)

    ok, first_bad = ledger.verify()
    if not ok:
        return False, first_bad
    if cp.exists() and not ledger.verify_against_checkpoints():
        return False, None  # chain self-consistent but not anchored -> rewrite
    return True, None


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if not args:
        print("usage: python -m ledger.verify_cli <audit_chain.jsonl> [checkpoints.jsonl]",
              file=sys.stderr)
        return 2
    chain = args[0]
    cp = args[1] if len(args) > 1 else None
    ok, first_bad = verify(chain, cp)
    if ok:
        print(f"OK: {chain} verifies (chain intact"
              + (", anchored to checkpoints)" if (cp or Path(chain).with_name('checkpoints.jsonl').exists()) else ")"))
        return 0
    if first_bad is not None:
        print(f"TAMPERED: {chain} fails at record {first_bad}", file=sys.stderr)
    else:
        print(f"TAMPERED: {chain} is self-consistent but does not match the anchored "
              "checkpoint (full rewrite)", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
