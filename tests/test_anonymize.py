"""M1.7: node identity never reaches the model raw, and cannot be memorised."""

from __future__ import annotations

import pandas as pd
import pytest

from data.anonymize import Anonymizer

ATTACKER = "18.221.219.4"
VICTIM = "172.31.69.25"
HOSTS = [VICTIM, ATTACKER, "172.31.69.24", "172.31.64.17", "13.58.98.64", "8.8.8.8"]


@pytest.fixture
def anon(data_cfg):
    return Anonymizer(b"unit-test-key", data_cfg["anonymisation"])


def test_missing_env_key_fails_loudly(data_cfg):
    with pytest.raises(RuntimeError, match="SIH26_HMAC_KEY"):
        Anonymizer.from_config(data_cfg, env={})


def test_pseudonyms_are_keyed_stable_and_not_the_address(anon, data_cfg):
    p1 = anon.pseudonym(ATTACKER)
    assert p1 == anon.pseudonym(ATTACKER), "pseudonym must be deterministic under one key"
    assert p1 != anon.pseudonym(VICTIM)
    assert len(p1) == 16 and all(c in "0123456789abcdef" for c in p1)
    assert ATTACKER not in p1

    other_key = Anonymizer(b"another-key", data_cfg["anonymisation"])
    assert other_key.pseudonym(ATTACKER) != p1, "pseudonym must depend on the key"

    same_net = anon.pseudonym("18.221.219.5")
    assert same_net != p1, "adjacent addresses must not collide"


def test_epoch_permutation_changes_ids_but_stays_a_permutation(anon):
    ids_e0 = anon.epoch_node_ids(HOSTS, epoch=0, seed=1337)
    ids_e0_again = anon.epoch_node_ids(HOSTS, epoch=0, seed=1337)
    ids_e1 = anon.epoch_node_ids(HOSTS, epoch=1, seed=1337)

    assert ids_e0 == ids_e0_again, "same epoch + seed must reproduce ids"
    assert sorted(ids_e0.values()) == list(range(len(HOSTS)))
    assert sorted(ids_e1.values()) == list(range(len(HOSTS)))
    assert ids_e0 != ids_e1, "ids must be re-permuted across epochs"


def test_heldout_attacker_mode_breaks_identity_across_splits(data_cfg):
    cfg_anon = dict(data_cfg["anonymisation"], heldout_attacker_ip_eval=True)
    anon = Anonymizer(b"unit-test-key", cfg_anon)
    assert anon.pseudonym(ATTACKER, split="train") != anon.pseudonym(ATTACKER, split="test"), (
        "held-out mode must re-domain eval pseudonyms"
    )

    off = Anonymizer(b"unit-test-key", data_cfg["anonymisation"])
    assert off.pseudonym(ATTACKER, split="train") == off.pseudonym(ATTACKER, split="test")


def test_role_features_are_role_only(anon):
    flows = pd.DataFrame(
        {
            "src_ip": [VICTIM, VICTIM, ATTACKER, "172.31.64.17"],
            "dst_ip": [ATTACKER, "8.8.8.8", VICTIM, VICTIM],
            "src_port": [22, 51000, 40000, 40001],
            "dst_port": [40000, 53, 22, 22],
        }
    )
    feats = anon.role_features(flows, VICTIM)

    assert set(feats) == {"internal", "net24_bucket", "server_port_ratio"}, (
        "role features must not carry anything else (no identity)"
    )
    assert feats["internal"] == 1
    assert 0 <= feats["net24_bucket"] < anon._n_buckets
    # VICTIM's own ports across its 4 flows: 22, 51000, 22, 22 -> 3/4 server-like
    assert feats["server_port_ratio"] == pytest.approx(0.75)

    assert anon.role_features(flows, ATTACKER)["internal"] == 0
