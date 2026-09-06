"""BUILD_PLAN M9.5: the ledger catches both tampering modes.

Editing one record must fail verification at exactly that index; rebuilding the
whole chain (self-consistent rewrite) must be caught by checkpoint anchoring.
"""

from __future__ import annotations

import json

from tests._stubs import require_attr, require_module

N_RECORDS = 10
TAMPER_INDEX = 3


def _write_records(ledger, n, tamper_from=None):
    for i in range(n):
        prob = 0.99 if (tamper_from is not None and i >= tamper_from) else i / n
        ledger.append({"host": f"host-{i % 3}", "window": i, "prob": prob, "stage": "recon"})


def test_single_edit_fails_at_index_and_full_rewrite_trips_checkpoints(tmp_path):
    ledger_mod = require_module("ledger.ledger", "M9")
    ledger_cls = require_attr(ledger_mod, "Ledger", "M9")

    chain_path = tmp_path / "audit_chain.jsonl"
    checkpoint_path = tmp_path / "checkpoints.jsonl"

    ledger = ledger_cls(chain_path, checkpoint_path=checkpoint_path)
    _write_records(ledger, N_RECORDS)
    ledger.checkpoint()

    ok, first_bad = ledger.verify()
    assert ok and first_bad is None, "freshly written chain must verify clean"
    assert ledger.verify_against_checkpoints() is True, (
        "a genuine chain must match its own anchored checkpoint (head + Merkle root)"
    )

    # --- single-record edit: verification fails at exactly TAMPER_INDEX ---
    lines = chain_path.read_text(encoding="utf-8").splitlines()
    record = json.loads(lines[TAMPER_INDEX])
    record["prob"] = 0.999
    lines[TAMPER_INDEX] = json.dumps(record)
    chain_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    edited = ledger_cls(chain_path, checkpoint_path=checkpoint_path)
    ok, first_bad = edited.verify()
    assert not ok, "edited record must fail verification"
    assert first_bad == TAMPER_INDEX, (
        f"verification must fail at index {TAMPER_INDEX}, reported {first_bad}"
    )
    # The anchored Merkle root also catches the content edit independently of the
    # hash chain (the edited leaf changes the root even though the head is intact).
    assert edited.verify_against_checkpoints() is False, (
        "the anchored Merkle root must not match a chain with an edited record"
    )

    # --- full rewrite: a self-consistent forged chain passes verify() ---
    # but cannot match the anchored checkpoints ---
    chain_path.unlink()
    forged = ledger_cls(chain_path, checkpoint_path=checkpoint_path)
    _write_records(forged, N_RECORDS, tamper_from=0)

    ok, _ = forged.verify()
    assert ok, "a full self-consistent rewrite passes plain hash-chain verification"
    assert forged.verify_against_checkpoints() is False, (
        "checkpoint anchoring must catch a full chain rewrite"
    )
