"""Emit the current signed checkpoint for external anchoring (M9.5).

    python scripts/anchor_checkpoint.py run/<session>/audit_chain.jsonl
    python scripts/anchor_checkpoint.py run/<session>/audit_chain.jsonl --out anchor.txt

The checkpoint log is signed under SIH26_LEDGER_KEY, which stops a filesystem
attacker forging an anchor but not the operator, who holds the key. Publishing
the head before the demo closes that gap: a later rewrite, however well signed,
contradicts a value the room already has.

Run this after the engine has written a chain and before the demo, then put the
ANCHOR line somewhere the audience can see it (chat, whiteboard, a signed commit
elsewhere) and read the spoken digest aloud. Entirely offline — it reads two
local files and writes one.
"""

from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ledger import verify_cli  # noqa: E402
from ledger.ledger import Ledger, _canonical  # noqa: E402

_SPOKEN_GROUPS = 6
_SPOKEN_GROUP_LEN = 4


def spoken_digest(anchor_line: str) -> str:
    """Short human-readable digest of the anchor line — six 4-character groups,
    enough for a presenter to read aloud and an audience to check later."""
    digest = hashlib.sha256(anchor_line.encode("utf-8")).hexdigest().upper()
    return "-".join(
        digest[i * _SPOKEN_GROUP_LEN:(i + 1) * _SPOKEN_GROUP_LEN]
        for i in range(_SPOKEN_GROUPS)
    )


def anchor_line(cp: dict) -> str:
    """One copy-pasteable line committing to the chain: length, head, Merkle
    root and the checkpoint's own signature."""
    return (f"SIH26-ANCHOR count={cp['count']} head={cp['head']} "
            f"root={cp['merkle_root']} sig={cp['sig']}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python scripts/anchor_checkpoint.py", description=__doc__.split("\n\n")[0]
    )
    parser.add_argument("chain", help="audit_chain.jsonl written by the engine")
    parser.add_argument("checkpoints", nargs="?",
                        help="checkpoints.jsonl (default: next to the chain)")
    parser.add_argument("--out", help="anchor file to write "
                                      "(default: anchor.txt next to the chain)")
    args = parser.parse_args(argv)

    chain = Path(args.chain)
    cp_path = Path(args.checkpoints) if args.checkpoints else chain.with_name(
        "checkpoints.jsonl")
    out = Path(args.out) if args.out else chain.with_name("anchor.txt")

    if not chain.exists():
        print(f"no chain at {chain} - run the engine first", file=sys.stderr)
        return 2
    try:
        ledger = Ledger(chain, checkpoint_path=cp_path)
    except RuntimeError as exc:
        print(f"CANNOT ANCHOR: {exc}", file=sys.stderr)
        return 2

    ok, first_bad, reason = verify_cli.verify_detailed(chain, cp_path)
    if not ok:
        print(f"REFUSING TO ANCHOR: {chain} does not verify ({reason}"
              + (f", first bad record {first_bad}" if first_bad is not None else "")
              + "). Anchoring a chain that already fails verification would publish "
                "a forgery under our own name.", file=sys.stderr)
        return 1

    cp = ledger.latest_checkpoint()
    if cp is None or cp["count"] != ledger.count:
        print(f"REFUSING TO ANCHOR: the last checkpoint in {cp_path} does not describe "
              f"the current {ledger.count}-record chain", file=sys.stderr)
        return 1

    line = anchor_line(cp)
    body = (f"{line}\n"
            f"chain: {chain}\n"
            f"checkpoint-log: {cp_path}\n"
            f"checkpoint-record: {_canonical(cp)}\n"
            f"spoken-digest: {spoken_digest(line)}\n"
            f"verify-with: python -m ledger.verify_cli {chain} {cp_path}\n")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(body, encoding="utf-8")

    print(line)
    print(f"spoken digest: {spoken_digest(line)}")
    print(f"records anchored: {cp['count']}")
    print(f"written to: {out}")
    print(f"a judge re-checks it with: python -m ledger.verify_cli {chain} {cp_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
