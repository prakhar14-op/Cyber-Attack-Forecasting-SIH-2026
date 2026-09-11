"""BUILD_PLAN M9.5: the ledger catches its tampering modes — and admits the one
it cannot.

Editing one record must fail verification at exactly that index; rebuilding the
whole chain (self-consistent rewrite) must be caught by checkpoint anchoring —
including when the forger rewrites the checkpoint log in the same pass, which is
the attack an audit verifier actually landed. The forger's advantage is the run
directory; the defence is the signing key, which is not in it.

Deletion is the third mode and needs no key at all: every surviving hash stays
correct, so `verify()` is blind to it. Checkpoint chaining plus the last-line
rule catch the fixable half (records deleted while their checkpoints survive; a
checkpoint deleted, reordered or spliced in). The half that no self-contained
scheme can catch — trailing records deleted together with the checkpoints that
cover them — is pinned as a documented limit by
`test_tail_truncation_of_both_files_is_not_caught_without_the_published_anchor`,
which asserts the limit exists rather than letting anyone believe it is covered.

A fourth mode is not tampering at all and was the loudest defect of the three:
pointing the verifier at a chain that is not there. `Ledger.verify()` reports
(True, None) for a missing file, so `--no-anchor` used to exit 0 with "OK (CHAIN
ONLY)" on a typo'd path, a zero-byte file, or a ledger someone deleted.
`test_a_missing_or_empty_chain_is_an_error_not_OK` pins the fix, and
`test_a_zero_record_run_passes_only_because_a_signed_checkpoint_says_so` pins
the one empty ledger that is still evidence — the zero-alert run whose signed
count=0 checkpoint attests it — so the fix cannot be over-applied to the
engine's own empty-input path.
"""

from __future__ import annotations

import json

import pytest

from tests._stubs import require_attr, require_module

N_RECORDS = 10
HALF_RECORDS = 3
TAMPER_INDEX = 3
TEST_KEY = "test-ledger-key-not-a-secret"
ATTACKER_KEY = "key-the-forger-picked"
# The default that used to ship in ledger/ledger.py. A published default is a
# published key, so an attacker holding it must still get nowhere.
FORMER_DEV_DEFAULT = "sih26-ledger-dev"


@pytest.fixture(autouse=True)
def ledger_key(monkeypatch):
    """The ledger refuses to run without a key, so every test states one."""
    monkeypatch.setenv("SIH26_LEDGER_KEY", TEST_KEY)


def _write_records(ledger, n, tamper_from=None):
    for i in range(n):
        prob = 0.99 if (tamper_from is not None and i >= tamper_from) else i / n
        ledger.append({"host": f"host-{i % 3}", "window": i, "prob": prob, "stage": "recon"})


def _genuine_run(ledger_cls, tmp_path):
    """A chain of N_RECORDS with its signed checkpoint, as the engine writes it."""
    chain_path = tmp_path / "audit_chain.jsonl"
    checkpoint_path = tmp_path / "checkpoints.jsonl"
    ledger = ledger_cls(chain_path, checkpoint_path=checkpoint_path)
    _write_records(ledger, N_RECORDS)
    ledger.checkpoint()
    return chain_path, checkpoint_path


def _run_anchored_twice(ledger_cls, tmp_path):
    """Six records anchored at count=3 and again at count=6 — what a long-lived
    deployment writes (engine/predict.py starts a fresh chain per file, but
    scripts/edge_case_report.py and any batch loop append across checkpoints).
    The last three records are the incriminating ones a rollback would delete."""
    chain_path = tmp_path / "audit_chain.jsonl"
    checkpoint_path = tmp_path / "checkpoints.jsonl"
    ledger = ledger_cls(chain_path, checkpoint_path=checkpoint_path)
    _write_records(ledger, HALF_RECORDS)
    ledger.checkpoint()
    for i in range(HALF_RECORDS, 2 * HALF_RECORDS):
        ledger.append({"host": f"host-{i}", "window": i, "prob": 0.99,
                       "stage": "exfiltration"})
    ledger.checkpoint()
    return chain_path, checkpoint_path


def test_single_edit_fails_at_index_and_full_rewrite_trips_checkpoints(tmp_path):
    ledger_mod = require_module("ledger.ledger", "M9")
    ledger_cls = require_attr(ledger_mod, "Ledger", "M9")

    chain_path, checkpoint_path = _genuine_run(ledger_cls, tmp_path)
    ledger = ledger_cls(chain_path, checkpoint_path=checkpoint_path)

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


@pytest.mark.parametrize("forger_key", [ATTACKER_KEY, FORMER_DEV_DEFAULT])
def test_rewriting_both_files_consistently_is_still_caught(tmp_path, monkeypatch, forger_key):
    """F35: the chain and its checkpoint log sit in one directory, so a forger who
    can edit one can edit both. Rewriting both consistently must still fail, because
    the checkpoint signature is keyed on something the directory does not contain."""
    ledger_mod = require_module("ledger.ledger", "M9")
    ledger_cls = require_attr(ledger_mod, "Ledger", "M9")
    verify_cli = require_module("ledger.verify_cli", "M9")

    chain_path, checkpoint_path = _genuine_run(ledger_cls, tmp_path)
    assert verify_cli.verify(chain_path, checkpoint_path)[0], "genuine run must verify"

    # The forger owns the run directory but not SIH26_LEDGER_KEY: they rewrite the
    # chain at probability 0.999 and re-anchor it with the best key they have.
    chain_path.unlink()
    checkpoint_path.unlink()
    monkeypatch.setenv("SIH26_LEDGER_KEY", forger_key)
    forged = ledger_cls(chain_path, checkpoint_path=checkpoint_path)
    _write_records(forged, N_RECORDS, tamper_from=0)
    forged.checkpoint()
    assert forged.verify()[0], "the forgery is internally consistent by construction"
    assert forged.verify_against_checkpoints() is True, (
        "and self-consistent under the forger's own key — which is why the chain "
        "and its checkpoint log alone cannot settle this"
    )

    monkeypatch.setenv("SIH26_LEDGER_KEY", TEST_KEY)
    audited = ledger_cls(chain_path, checkpoint_path=checkpoint_path)
    anchored, reason = audited.check_anchor()
    assert anchored is False, "a re-signed rewrite must not verify under the real key"
    assert reason == ledger_mod.ANCHOR_BAD_SIGNATURE, reason

    ok, first_bad = verify_cli.verify(chain_path, checkpoint_path)
    assert ok is False and first_bad is None, (
        "the CLI must report a forged anchor, not a clean chain"
    )


def test_unsigned_checkpoint_is_not_an_anchor(tmp_path):
    """A checkpoint log in the pre-signature format is unauthenticated: anyone who
    can read the chain can write one, so it must not count as an anchor."""
    ledger_mod = require_module("ledger.ledger", "M9")
    ledger_cls = require_attr(ledger_mod, "Ledger", "M9")

    chain_path, checkpoint_path = _genuine_run(ledger_cls, tmp_path)
    genuine = json.loads(checkpoint_path.read_text(encoding="utf-8").splitlines()[-1])
    stripped = {k: v for k, v in genuine.items() if k != "sig"}
    checkpoint_path.write_text(json.dumps(stripped) + "\n", encoding="utf-8")

    anchored, reason = ledger_cls(chain_path, checkpoint_path=checkpoint_path).check_anchor()
    assert anchored is False and reason == ledger_mod.ANCHOR_UNSIGNED, reason


def test_deleting_records_is_caught_while_their_checkpoints_survive(tmp_path, capsys):
    """Rollback needs no key and forges nothing: delete the trailing records and
    every surviving hash is still correct, so verify() passes. Only the anchored
    record count notices, and only if the LAST checkpoint is the one consulted —
    an earlier checkpoint at the truncated length is exactly what the attacker is
    rolling back to, so finding *a* checkpoint at this length proves nothing."""
    ledger_mod = require_module("ledger.ledger", "M9")
    ledger_cls = require_attr(ledger_mod, "Ledger", "M9")
    verify_cli = require_module("ledger.verify_cli", "M9")

    chain_path, checkpoint_path = _run_anchored_twice(ledger_cls, tmp_path)
    assert verify_cli.verify_detailed(chain_path, checkpoint_path) == (
        True, None, verify_cli.OK
    ), "the untruncated run must verify"

    lines = chain_path.read_text(encoding="utf-8").splitlines()
    chain_path.write_text("\n".join(lines[:HALF_RECORDS]) + "\n", encoding="utf-8")

    rolled_back = ledger_cls(chain_path, checkpoint_path=checkpoint_path)
    assert rolled_back.verify()[0], (
        "truncation leaves every surviving record's hash correct — the chain "
        "check cannot see it, which is why the anchor has to"
    )
    anchored, reason = rolled_back.check_anchor()
    assert anchored is False, "a truncated chain must not verify as anchored"
    assert reason == ledger_mod.ANCHOR_LENGTH_MISMATCH, reason

    assert verify_cli.main([str(chain_path), str(checkpoint_path)]) == 1
    err = capsys.readouterr().err
    assert "TAMPERED" in err and "removed" in err, err


def test_a_checkpoint_cannot_be_removed_from_or_spliced_into_the_log(tmp_path):
    """Each checkpoint carries the previous one's signature, so the checkpoint log
    is a chain too. Without that, deleting the earlier checkpoint would leave a
    log whose single surviving line still describes the whole chain."""
    ledger_mod = require_module("ledger.ledger", "M9")
    ledger_cls = require_attr(ledger_mod, "Ledger", "M9")

    chain_path, checkpoint_path = _run_anchored_twice(ledger_cls, tmp_path)
    lines = checkpoint_path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2, lines

    checkpoint_path.write_text(lines[1] + "\n", encoding="utf-8")
    anchored, reason = ledger_cls(chain_path, checkpoint_path=checkpoint_path).check_anchor()
    assert anchored is False, (
        "the surviving checkpoint still matches the chain's head, count and "
        "Merkle root — only prev_sig shows a line is missing before it"
    )
    assert reason == ledger_mod.ANCHOR_CHECKPOINT_CHAIN_BROKEN, reason

    # A checkpoint signed under the same key but belonging to another run cannot
    # be pasted onto the end of this log either.
    _, other_checkpoints = _genuine_run(ledger_cls, tmp_path / "other-run")
    foreign = other_checkpoints.read_text(encoding="utf-8").splitlines()[-1]
    checkpoint_path.write_text("\n".join(lines + [foreign]) + "\n", encoding="utf-8")
    anchored, reason = ledger_cls(chain_path, checkpoint_path=checkpoint_path).check_anchor()
    assert anchored is False and reason == ledger_mod.ANCHOR_CHECKPOINT_CHAIN_BROKEN, reason


def test_tail_truncation_of_both_files_is_not_caught_without_the_published_anchor(
    tmp_path, capsys
):
    """The documented limit, asserted rather than assumed.

    Delete the trailing records AND the checkpoint covering them and what is left
    is a shorter ledger that is internally perfect and correctly signed — nothing
    inside these two files records that the run continued, so no self-contained
    scheme can tell it from an honest run that stopped earlier. This test pins
    both halves of the honest story: the verifier still exits 0, and the anchor
    line published before the truncation is what contradicts it.

    If the first assertion ever fails, the limit was closed — update the
    ledger/ledger.py docstring and delete this test rather than loosening it.
    """
    ledger_mod = require_module("ledger.ledger", "M9")
    ledger_cls = require_attr(ledger_mod, "Ledger", "M9")
    verify_cli = require_module("ledger.verify_cli", "M9")
    anchor = require_module("scripts.anchor_checkpoint", "M9")

    chain_path, checkpoint_path = _run_anchored_twice(ledger_cls, tmp_path)
    honest = ledger_cls(chain_path, checkpoint_path=checkpoint_path)
    published = anchor.anchor_line(honest.latest_checkpoint())
    assert f"count={2 * HALF_RECORDS}" in published, published

    chain_lines = chain_path.read_text(encoding="utf-8").splitlines()
    cp_lines = checkpoint_path.read_text(encoding="utf-8").splitlines()
    chain_path.write_text("\n".join(chain_lines[:HALF_RECORDS]) + "\n", encoding="utf-8")
    checkpoint_path.write_text(cp_lines[0] + "\n", encoding="utf-8")

    assert verify_cli.verify_detailed(chain_path, checkpoint_path) == (
        True, None, verify_cli.OK
    ), "LIMIT: truncating both files together is not detectable from the files alone"
    assert verify_cli.main([str(chain_path), str(checkpoint_path)]) == 0
    out = capsys.readouterr().out
    assert f"{HALF_RECORDS} records anchored" in out and "published anchor line" in out, (
        "exit 0 must state how many records it anchored and send the operator to "
        "the published anchor, or it reads as 'nothing was deleted'"
    )

    truncated = ledger_cls(chain_path, checkpoint_path=checkpoint_path)
    rolled_back = anchor.anchor_line(truncated.latest_checkpoint())
    assert rolled_back != published, "the published anchor is what catches this"
    assert f"count={HALF_RECORDS}" in rolled_back, rolled_back


def test_ledger_refuses_to_construct_without_a_key(tmp_path, monkeypatch):
    """F36: no default key. A default in public source reverses every pseudonym —
    the dataset's attackers are ~15 fixed public IPs, so a rainbow table over them
    is trivial. Fail the way data/anonymize.py does: loudly, naming the env var."""
    ledger_mod = require_module("ledger.ledger", "M9")
    ledger_cls = require_attr(ledger_mod, "Ledger", "M9")

    monkeypatch.delenv("SIH26_LEDGER_KEY", raising=False)
    with pytest.raises(RuntimeError) as exc:
        ledger_cls(tmp_path / "audit_chain.jsonl")
    assert "SIH26_LEDGER_KEY" in str(exc.value), (
        "the error must name the env var the operator has to set"
    )

    monkeypatch.setenv("SIH26_LEDGER_KEY", "")
    with pytest.raises(RuntimeError):
        ledger_cls(tmp_path / "audit_chain.jsonl")


def test_pseudonyms_differ_across_keys(tmp_path, monkeypatch):
    """The privacy claim only holds if the key is what makes a pseudonym: two keys
    over the same host must not produce the same value."""
    ledger_mod = require_module("ledger.ledger", "M9")
    ledger_cls = require_attr(ledger_mod, "Ledger", "M9")

    under_test_key = ledger_cls(tmp_path / "a.jsonl").append({"host": "172.31.0.1"})
    monkeypatch.setenv("SIH26_LEDGER_KEY", ATTACKER_KEY)
    under_other_key = ledger_cls(tmp_path / "b.jsonl").append({"host": "172.31.0.1"})

    assert under_test_key["host"] != "172.31.0.1", "raw IPs never enter the ledger"
    assert under_test_key["host"] != under_other_key["host"]


def test_missing_checkpoint_log_fails_unless_explicitly_waived(tmp_path, capsys):
    """F37: deleting the checkpoint log is the cheapest attack there is. Losing the
    anchor must fail the verifier, with an opt-out that says what it gave up."""
    ledger_mod = require_module("ledger.ledger", "M9")
    ledger_cls = require_attr(ledger_mod, "Ledger", "M9")
    verify_cli = require_module("ledger.verify_cli", "M9")

    chain_path, checkpoint_path = _genuine_run(ledger_cls, tmp_path)

    # A forged chain plus a deleted anchor: chain-only checks cannot tell it apart
    # from a genuine one, so the verifier must not call it OK.
    chain_path.unlink()
    checkpoint_path.unlink()
    forged = ledger_cls(chain_path, checkpoint_path=checkpoint_path)
    _write_records(forged, N_RECORDS, tamper_from=0)
    assert forged.verify()[0], "the forged chain is internally consistent"

    ok, first_bad, reason = verify_cli.verify_detailed(chain_path, checkpoint_path)
    assert ok is False and first_bad is None
    assert reason == ledger_mod.ANCHOR_MISSING, reason
    assert verify_cli.main([str(chain_path), str(checkpoint_path)]) == 1
    err = capsys.readouterr().err
    assert "UNANCHORED" in err and "--no-anchor" in err, err

    # The opt-out still works, and says out loud that it proved less.
    assert verify_cli.main([str(chain_path), str(checkpoint_path), "--no-anchor"]) == 0
    out = capsys.readouterr().out
    assert "CHAIN ONLY" in out and "rewrite" in out, out


@pytest.mark.parametrize("how", ["absent", "zero-byte", "blank-lines"])
@pytest.mark.parametrize("no_anchor", [False, True])
def test_a_missing_or_empty_chain_is_an_error_not_OK(tmp_path, capsys, how, no_anchor):
    """The worst possible default for an attestation tool is saying OK about a
    file that is not there.

    `Ledger.verify()` answers (True, None) for a chain that does not exist —
    correctly, since it finds no inconsistent record — and the CLI used to hand
    that straight to the operator as "OK (CHAIN ONLY): ... is internally
    consistent". A typo'd path, a ledger that was never written and a ledger
    deleted outright all exited 0. Nothing distinguishes those three from each
    other or from a real chain, so none of them may pass.
    """
    verify_cli = require_module("ledger.verify_cli", "M9")

    chain_path = tmp_path / "audit_chain.jsonl"
    checkpoint_path = tmp_path / "checkpoints.jsonl"
    if how == "zero-byte":
        chain_path.write_text("", encoding="utf-8")
    elif how == "blank-lines":
        chain_path.write_text("\n\n  \n", encoding="utf-8")

    ok, first_bad, reason = verify_cli.verify_detailed(
        chain_path, checkpoint_path, require_anchor=not no_anchor
    )
    assert ok is False, f"a {how} chain must not verify"
    assert first_bad is None, "there is no bad record to point at — the chain is absent"
    assert reason == verify_cli.NO_CHAIN, reason

    argv = [str(chain_path), str(checkpoint_path)] + (["--no-anchor"] if no_anchor else [])
    assert verify_cli.main(argv) == 2, "exit 2 = nothing could be verified"
    captured = capsys.readouterr()
    assert "NO CHAIN" in captured.err, captured.err
    assert "OK" not in captured.out, captured.out

    # The 2-tuple contract tests/test_offline.py depends on is unchanged.
    assert verify_cli.verify(chain_path, checkpoint_path) == (False, None)


def test_a_zero_record_run_passes_only_because_a_signed_checkpoint_says_so(tmp_path, capsys):
    """The one empty ledger that is evidence, and the reason it is.

    `engine.predict.predict_file` deletes any stale chain, appends one record per
    alert and always checkpoints — so a run with zero alerts leaves NO chain file
    and a signed checkpoint at count=0. That run is attested: the checkpoint, not
    the absence of a file, is what speaks for it, and it is signed under a key the
    run directory does not contain. This is why the rule above is "no chain AND no
    checkpoint attesting one", not "no chain".

    The distinction has to survive in the output too, or an operator reads "OK" on
    a blind run as "no alerts, all clear".
    """
    ledger_mod = require_module("ledger.ledger", "M9")
    ledger_cls = require_attr(ledger_mod, "Ledger", "M9")
    verify_cli = require_module("ledger.verify_cli", "M9")

    chain_path = tmp_path / "audit_chain.jsonl"
    checkpoint_path = tmp_path / "checkpoints.jsonl"
    ledger_cls(chain_path, checkpoint_path=checkpoint_path).checkpoint()
    assert not chain_path.exists(), (
        "a zero-alert run writes no chain file at all — that is the case under test"
    )

    ok, first_bad, reason = verify_cli.verify_detailed(chain_path, checkpoint_path)
    assert (ok, first_bad, reason) == (True, None, verify_cli.OK_EMPTY)
    assert verify_cli.verify(chain_path, checkpoint_path) == (True, None), (
        "engine/predict.py's zero-alert path and scripts/edge_case_report.py both "
        "assert this stays True"
    )

    assert verify_cli.main([str(chain_path), str(checkpoint_path)]) == 0
    out = capsys.readouterr().out
    assert "EMPTY" in out and "0 records anchored" in out, out
    assert "wrote nothing" in out, (
        "exit 0 on an empty ledger must say the engine wrote nothing, or it reads "
        "as a verified ledger that happens to be clean"
    )

    # Take the checkpoint away and the same empty chain stops being evidence.
    checkpoint_path.unlink()
    assert verify_cli.verify_detailed(chain_path, checkpoint_path) == (
        False, None, verify_cli.NO_CHAIN
    )


def test_cli_reports_a_genuine_run_as_anchored(tmp_path, capsys):
    """The happy path must stay distinguishable from the chain-only path, or the
    loud failure modes above are just noise."""
    ledger_mod = require_module("ledger.ledger", "M9")
    ledger_cls = require_attr(ledger_mod, "Ledger", "M9")
    verify_cli = require_module("ledger.verify_cli", "M9")

    chain_path, checkpoint_path = _genuine_run(ledger_cls, tmp_path)
    assert verify_cli.main([str(chain_path), str(checkpoint_path)]) == 0
    out = capsys.readouterr().out
    assert out.startswith("OK:") and "anchored" in out, out
