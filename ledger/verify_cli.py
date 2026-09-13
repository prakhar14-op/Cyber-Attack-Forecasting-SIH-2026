"""Standalone offline ledger verifier (M9.6).

    python -m ledger.verify_cli audit_chain.jsonl [checkpoints.jsonl]
    python -m ledger.verify_cli audit_chain.jsonl --no-anchor

A judge runs this with no network. Exit 0 = the hash chain is intact AND it
matches a validly signed anchored checkpoint; 1 = it does not, naming the first
bad record or the reason the anchor did not hold; 2 = nothing could be verified
at all (no key in the environment, or no chain at the path given).

A missing checkpoint log is a FAILURE, not a downgrade. The chain check alone
cannot distinguish a genuine chain from a full self-consistent rewrite, so
deleting the checkpoint log would otherwise be the cheapest possible attack.
`--no-anchor` is for the one honest case — a chain shipped without its
checkpoint log — and says so loudly in the output.

A missing or empty chain file is likewise a FAILURE, and for the same reason in
sharper form: a verifier whose whole job is attestation must never print OK for
a file that is not there. An absent chain is vacuously "internally consistent",
so a typo'd path or a deleted ledger used to exit 0 under `--no-anchor`. It now
exits 2 with NO CHAIN. The one case that still passes is the case that is
actually attested: a run that produced zero records but wrote a signed
checkpoint saying so — then the checkpoint, not the absence of a file, is the
evidence, and the output says EMPTY rather than OK.

Exit 0 means these two files agree with each other under the key. It does not
mean the ledger is complete: an attacker who deletes trailing records *and* the
checkpoint lines covering them leaves a shorter ledger that is internally
perfect. Only the published anchor line (`scripts/anchor_checkpoint.py`) settles
the length, which is why exit 0 prints the anchored count for comparison.

Both modes read SIH26_LEDGER_KEY from the environment (see .env.example): the
checkpoint signature cannot be checked without it.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from ledger.ledger import (
    ANCHOR_BAD_SIGNATURE,
    ANCHOR_CHECKPOINT_CHAIN_BROKEN,
    ANCHOR_LENGTH_MISMATCH,
    ANCHOR_MISMATCH,
    ANCHOR_MISSING,
    ANCHOR_UNSIGNED,
    Ledger,
)

OK = "ok"
OK_EMPTY = "ok-empty-run-anchored"
OK_CHAIN_ONLY = "ok-chain-only"
CHAIN_TAMPERED = "chain-tampered"
NO_CHAIN = "no-chain"

_ANCHOR_MESSAGE = {
    ANCHOR_MISSING: (
        "UNANCHORED: checkpoint log {cp} is missing or empty. A chain on its own is "
        "not evidence: a full self-consistent rewrite passes the chain check. Pass "
        "--no-anchor only if you knowingly received a chain without its checkpoint log."
    ),
    ANCHOR_UNSIGNED: (
        "FORGED ANCHOR: {cp} contains an unsigned checkpoint. Genuine checkpoints "
        "carry an HMAC under SIH26_LEDGER_KEY; an unsigned line was written by "
        "something that did not hold the key."
    ),
    ANCHOR_BAD_SIGNATURE: (
        "FORGED ANCHOR: a checkpoint in {cp} has an invalid signature. Either the "
        "checkpoint log was rewritten, or SIH26_LEDGER_KEY is not the key this run "
        "was written with."
    ),
    ANCHOR_CHECKPOINT_CHAIN_BROKEN: (
        "FORGED ANCHOR: {cp} is not a chain - a checkpoint's prev_sig does not match "
        "the signature of the line before it. A checkpoint was deleted from the "
        "middle of the log, reordered, or lifted out of another run. (A checkpoint "
        "log written before checkpoint chaining also lands here: re-run the engine.)"
    ),
    ANCHOR_LENGTH_MISMATCH: (
        "TAMPERED: {chain} is self-consistent but the LAST signed checkpoint in {cp} "
        "describes a chain of a different length: records were added or removed "
        "after that checkpoint, or checkpoint lines were deleted from the end of the "
        "log. (Deleting records AND their checkpoints together is not detectable "
        "here - compare the anchored count against the published anchor line.)"
    ),
    ANCHOR_MISMATCH: (
        "TAMPERED: {chain} is self-consistent but its head/Merkle root do not match "
        "the signed checkpoint (full rewrite)."
    ),
}


def verify_detailed(
    chain_path, checkpoint_path=None, require_anchor: bool = True
) -> tuple[bool, int | None, str]:
    """(ok, first_bad_index, reason). `reason` is one of this module's OK*/
    NO_CHAIN/CHAIN_TAMPERED constants or a ledger.ANCHOR_* constant.

    A chain with no records is the special case. `Ledger.verify()` answers
    (True, None) for a file that does not exist — correctly, since there is no
    inconsistent record in it — and that emptiness must not be laundered into a
    pass. Only a signed checkpoint can attest a zero-record run; without one,
    an absent or empty chain is NO_CHAIN.
    """
    chain_path = Path(chain_path)
    cp = Path(checkpoint_path) if checkpoint_path else chain_path.with_name("checkpoints.jsonl")
    ledger = Ledger(chain_path, checkpoint_path=cp)
    n_records = ledger.count  # 0 for a missing file and for an empty one alike

    if n_records == 0 and not require_anchor:
        # --no-anchor skips the only evidence that could speak for an empty
        # ledger, so there is nothing left to be internally consistent about.
        return False, None, NO_CHAIN

    ok, first_bad = ledger.verify()
    if not ok:
        return False, first_bad, CHAIN_TAMPERED
    if not require_anchor:
        return True, None, OK_CHAIN_ONLY
    anchored, reason = ledger.check_anchor()
    if not anchored:
        if n_records == 0 and reason == ANCHOR_MISSING:
            # No chain and no checkpoint: report the absent chain, which is the
            # first thing the operator has to fix, not the absent anchor.
            return False, None, NO_CHAIN
        return False, None, reason
    return True, None, OK_EMPTY if n_records == 0 else OK


def verify(
    chain_path, checkpoint_path=None, require_anchor: bool = True
) -> tuple[bool, int | None]:
    """Chain integrity plus checkpoint anchoring. Returns (ok, first_bad_index)
    — the API tests/test_offline.py expects."""
    ok, first_bad, _ = verify_detailed(chain_path, checkpoint_path, require_anchor)
    return ok, first_bad


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m ledger.verify_cli",
        description="Verify a tamper-evident audit chain against its signed checkpoint log.",
    )
    parser.add_argument("chain", help="audit_chain.jsonl")
    parser.add_argument("checkpoints", nargs="?",
                        help="checkpoints.jsonl (default: next to the chain)")
    parser.add_argument("--no-anchor", action="store_true",
                        help="verify the hash chain only, for a chain shipped without "
                             "its checkpoint log; proves internal consistency, NOT "
                             "that this is the chain the engine wrote")
    args = parser.parse_args(argv)

    cp = Path(args.checkpoints) if args.checkpoints else Path(args.chain).with_name(
        "checkpoints.jsonl")
    try:
        ok, first_bad, reason = verify_detailed(
            args.chain, cp, require_anchor=not args.no_anchor
        )
    except RuntimeError as exc:
        print(f"CANNOT VERIFY: {exc}", file=sys.stderr)
        return 2

    if reason == NO_CHAIN:
        # Say only what was actually checked: under --no-anchor the checkpoint
        # log was never read, so this must not claim anything about it.
        detail = (
            "--no-anchor was given, so the checkpoint log was not read - and it is "
            "the only thing that could have spoken for an empty ledger. Drop "
            "--no-anchor to check it."
            if args.no_anchor else
            f"and {cp} carries no signed checkpoint attesting a zero-record run."
        )
        print(f"NO CHAIN: {args.chain} does not exist or contains no records, {detail} "
              "Nothing was verified. An absent file is not an intact ledger, and a "
              "verifier that prints OK for one attests nothing - check the path, or "
              "re-run the engine to write a chain.", file=sys.stderr)
        return 2
    if reason == OK:
        anchored_count = Ledger(args.chain, checkpoint_path=cp).count
        print(f"OK: {args.chain} verifies - chain intact and anchored to a signed "
              f"checkpoint in {cp}")
        print(f"    {anchored_count} records anchored. This proves the two files agree, "
              "not that none were deleted: check this count against the published "
              "anchor line (scripts/anchor_checkpoint.py).")
        return 0
    if reason == OK_EMPTY:
        print(f"OK (EMPTY): {args.chain} holds NO records, and the last signed "
              f"checkpoint in {cp} attests a zero-record run.")
        print("    0 records anchored. This verifies that the engine wrote nothing - "
              "not that a ledger with content is intact. Check the 0 against the "
              "published anchor line (scripts/anchor_checkpoint.py) before reading it "
              "as 'no alerts'.")
        return 0
    if reason == OK_CHAIN_ONLY:
        print(f"OK (CHAIN ONLY): {args.chain} is internally consistent, but --no-anchor "
              "was given so NO anchor was checked. This does not rule out a full "
              "self-consistent rewrite.")
        return 0
    if reason == CHAIN_TAMPERED:
        print(f"TAMPERED: {args.chain} fails at record {first_bad}", file=sys.stderr)
        return 1
    print(_ANCHOR_MESSAGE[reason].format(chain=args.chain, cp=cp), file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
