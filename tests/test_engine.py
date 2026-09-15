"""M8: the offline prediction engine — output schema, technique mapping,
named-feature explanations, ledger integration.

The end-to-end offline run is covered by test_offline/test_smoke; these pin the
engine's internals without needing the socket guard.
"""

from __future__ import annotations

import importlib.util
import random
from collections import Counter

import numpy as np
import pandas as pd
import pytest
from scapy.all import IP, IPv6, TCP, Ether, wrpcap

from engine import explain as EX
from engine.predict import HOSTS_PSEUDONYMISED, UNCLASSIFIED_STAGE, _infer_stage
from tests._stubs import engine_artifacts_present

BASE_TS = 1_500_000_000.0
SCAN_SRC = "10.0.0.5"
SCAN_DST = "10.0.0.9"


def test_technique_map_is_named_and_data_grounded():
    # recon with a broad scan -> T1046; large exfil transfer -> T1048.
    assert EX.map_technique("recon", {"distinct_dst_ips": 40})["technique"] == "T1046"
    assert EX.map_technique("initial_access", {"syn": 100})["technique"] == "T1110"
    assert EX.map_technique("impact", {})["technique"] == "T1498"
    big = EX.map_technique("exfiltration", {"sent_bytes": 5_000_000})
    assert big["technique"] == "T1048"
    # benign has no technique
    assert EX.map_technique("benign", {})["technique"] is None
    # an internal port sweep is discovery (T1046), not a login — T1021 is
    # reserved for the pivot-login signature (no scan features).
    assert EX.map_technique("lateral_movement", {"distinct_dst_ports": 40})["technique"] == "T1046"
    assert EX.map_technique("lateral_movement", {})["technique"] == "T1021"
    # no rule matched -> no technique is claimed, and the reason is named
    unknown = EX.map_technique(UNCLASSIFIED_STAGE, {"syn": 1})
    assert unknown["technique"] is None and unknown["name"]
    # a stage the map has never heard of is a drift bug, not a blank technique
    with pytest.raises(KeyError, match="technique_map.yaml"):
        EX.map_technique("privilege_escalation", {})


def test_output_schema_rejects_embedding_dimensions():
    """Explanations must name real features, never embedding indices (PS)."""
    from engine.predict import OUTPUT_SCHEMA, _validate

    good = {
        "host": "abc", "window_start": 10.0, "probability": 0.9, "stage": "recon",
        "technique": "T1046", "technique_name": "Network Service Discovery",
        "top_features": [{"feature": "distinct_dst_ips", "value": 40.0, "contribution": 1.2}],
        "top_windows": [{"window_start": 5.0, "probability": 0.8, "seconds_before_alert": 5.0}],
        "flagged_flows": [{"dst_port": 80, "protocol": 6, "bytes": 500, "syn": 1,
                           "duration_us": 1200.0}],
        "demo_model": False,
    }
    _validate(good)  # must not raise

    bad = dict(good, probability=1.5)  # out of [0,1]
    with pytest.raises(Exception):
        _validate(bad)

    bad2 = dict(good, top_features=[{"value": 1.0, "contribution": 0.2}])  # no 'feature' name
    with pytest.raises(Exception):
        _validate(bad2)

    # A forecast that does not say which lane of weights produced it is not a
    # valid forecast. forecasts.json is an array that gets read on its own, so
    # "which model said this" cannot live only in the run summary beside it.
    anonymous = {k: v for k, v in good.items() if k != "demo_model"}
    with pytest.raises(Exception):
        _validate(anonymous)
    _validate(dict(good, demo_model=True))  # the demo lane's objects validate too
    with pytest.raises(Exception):  # ... but the flag is a boolean, not prose
        _validate(dict(good, demo_model="no"))


@pytest.mark.skipif(
    not (importlib.util.find_spec("xgboost")
         and __import__("configs").resolve_path("artifacts/engine_model.json").exists()),
    reason="engine model not trained — run python -m engine.train_engine",
)
def test_predict_file_produces_explained_forecasts_and_verifiable_ledger(fixture_csv, tmp_path):
    from engine import predict
    from ledger import verify_cli

    result = predict.predict_file(fixture_csv, out_dir=tmp_path)

    assert result["n_flows"] == 1000
    assert result["forecasts"], "engine produced no forecasts"
    for f in result["forecasts"][:20]:
        assert 0.0 <= f["probability"] <= 1.0
        assert f["stage"] in [
            *__import__("configs").load_config("data")["stages"], UNCLASSIFIED_STAGE
        ]
        # every top feature is a NAMED feature, not an index
        assert all(isinstance(t["feature"], str) and not t["feature"].isdigit()
                   for t in f["top_features"])

    # the run-level facts reach the DISK, not just this return value
    import json

    from engine.predict import RUN_SUMMARY_FILE

    summary = json.loads((tmp_path / RUN_SUMMARY_FILE).read_text(encoding="utf-8"))
    assert summary["n_alerts"] == result["n_alerts"]
    assert summary["unparsed_frames"] == result["unparsed_frames"]
    assert summary["hosts_pseudonymised"] == result["hosts_pseudonymised"] is False

    chain = tmp_path / "audit_chain.jsonl"
    assert chain.exists()
    # no raw IP may appear in the ledger (keyed-HMAC pseudonyms only)
    text = chain.read_text(encoding="utf-8")
    assert "172.31." not in text and "192.168." not in text
    ok, first_bad = verify_cli.verify(chain)
    assert ok, f"ledger failed verification at {first_bad}"


@pytest.mark.skipif(
    not (importlib.util.find_spec("xgboost")
         and __import__("configs").resolve_path("artifacts/engine_model.json").exists()
         and __import__("configs").resolve_path("app/assets/synthetic_demo.pcap").exists()),
    reason="engine model or synthetic demo pcap not built",
)
def test_pcap_input_uses_full_features_and_verifies(tmp_path):
    """The engine's PCAP path runs the full extractor (real packet features) and
    produces meaningful, non-degenerate forecasts + a verifiable ledger."""
    from configs import resolve_path
    from engine import predict
    from ledger import verify_cli

    pcap = resolve_path("app/assets/synthetic_demo.pcap")
    result = predict.predict_file(pcap, out_dir=tmp_path)
    assert result["forecasts"], "PCAP path produced no forecasts"
    # a PCAP has real packet features, so at least one alert is confidently high
    assert max(f["probability"] for f in result["forecasts"]) > 0.5
    ok, first_bad = verify_cli.verify(tmp_path / "audit_chain.jsonl")
    assert ok, f"ledger failed at {first_bad}"


@pytest.mark.skipif(
    not (importlib.util.find_spec("xgboost")
         and __import__("configs").resolve_path("artifacts/engine_model.json").exists()),
    reason="engine model not trained — run python -m engine.train_engine",
)
def test_engine_refuses_to_log_on_weight_mismatch(fixture_csv, tmp_path, monkeypatch):
    """M9.3: on a model-weight SHA-256 mismatch the engine raises and writes NO
    ledger, so a record can never claim provenance it does not have."""
    import pathlib
    import sys

    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "scripts"))
    import verify_weights as VW

    from engine import predict

    monkeypatch.setattr(VW, "verify", lambda *a, **k: (False, "engine_model.json"))
    with pytest.raises(RuntimeError, match="SHA-256 mismatch"):
        predict.predict_file(fixture_csv, out_dir=tmp_path)
    assert not (tmp_path / "audit_chain.jsonl").exists(), (
        "no ledger records may be written when the weight digest does not match"
    )


@pytest.mark.skipif(
    not (importlib.util.find_spec("xgboost")
         and __import__("configs").resolve_path("artifacts/engine_model_flow.json").exists()),
    reason="engine model not trained — run python -m engine.train_engine",
)
def test_predict_file_on_empty_input_yields_zero_alerts(tmp_path):
    """Edge case: an empty (header-only) CSV must produce 0 alerts and a valid
    (empty) ledger, never a crash."""
    import csv

    from configs import load_config
    from engine import predict
    from ledger import verify_cli

    cfg = load_config("data")
    empty = tmp_path / "empty.csv"
    with open(empty, "w", newline="", encoding="utf-8") as fh:
        csv.writer(fh).writerow(list(cfg["schema"].values()))

    result = predict.predict_file(empty, out_dir=tmp_path)
    assert result["n_flows"] == 0 and result["n_host_windows"] == 0
    assert result["n_alerts"] == 0 and result["forecasts"] == []
    ok, _ = verify_cli.verify(tmp_path / "audit_chain.jsonl")
    assert ok, "empty-input ledger must still verify"


_STAGE_CASES = [
    # (name, window features, expected stage)
    ("bulk transfer to one peer", {"sent_bytes": 60_000, "distinct_dst_ips": 1, "syn": 2},
     "exfiltration"),
    ("wide port sweep from outside", {"distinct_dst_ports": 40, "internal": 0}, "recon"),
    ("sequential sweep, few ports", {"distinct_dst_ports": 5, "sequential_port_ratio": 0.9,
                                     "internal": 0}, "recon"),
    ("the same sweep from inside", {"distinct_dst_ports": 40, "internal": 1},
     "lateral_movement"),
    ("SYNs without matching ACKs", {"syn": 50, "ack": 1, "distinct_dst_ports": 3},
     "initial_access"),
    ("packet flood", {"sent_pkts": 600, "syn": 0, "distinct_dst_ports": 1}, "impact"),
    ("bulk bytes but fanned out (not exfil)", {"sent_bytes": 60_000, "distinct_dst_ips": 30,
                                               "syn": 2, "distinct_dst_ports": 3},
     UNCLASSIFIED_STAGE),
    ("SYNs answered by ACKs (not brute force)", {"syn": 50, "ack": 50,
                                                 "distinct_dst_ports": 3}, UNCLASSIFIED_STAGE),
    ("exactly at the port threshold", {"distinct_dst_ports": 20, "internal": 0},
     UNCLASSIFIED_STAGE),
    ("a quiet window", {}, UNCLASSIFIED_STAGE),
]


@pytest.mark.parametrize("name,feats,expected", _STAGE_CASES, ids=[c[0] for c in _STAGE_CASES])
def test_infer_stage_covers_every_branch(name, feats, expected, data_cfg):
    """Every branch of the rule set, including the fallback. The fallback used to
    return `c2` with full confidence, so a window matching nothing was reported
    to an operator as command-and-control."""
    assert _infer_stage(feats, data_cfg["stage_rules"]) == expected


def test_stage_thresholds_come_from_config_not_the_module():
    """CLAUDE.md: no hyper-parameter hardcoded in a module. Moving the threshold
    in the config must move the decision — a literal in predict.py would not."""
    feats = {"distinct_dst_ports": 25, "internal": 0}
    base = {"exfiltration_sent_bytes_gt": 50_000, "exfiltration_distinct_dst_ips_lte": 2,
            "exfiltration_syn_lt": 10, "scan_distinct_dst_ports_gt": 20,
            "scan_sequential_port_ratio_gt": 0.5, "initial_access_syn_gt": 30,
            "impact_sent_pkts_gt": 500}

    assert _infer_stage(feats, base) == "recon"
    assert _infer_stage(feats, {**base, "scan_distinct_dst_ports_gt": 100}) == UNCLASSIFIED_STAGE

    with pytest.raises(KeyError):  # an incomplete config fails loudly
        _infer_stage(feats, {k: v for k, v in base.items() if k != "scan_distinct_dst_ports_gt"})


def test_stage_rule_names_state_their_own_comparison(data_cfg):
    """A bare `_max` hid an off-by-one: `..._distinct_dst_ips_max: 2` was applied
    as `<= 2` while `..._syn_max: 10` was applied as `< 10`, so that maximum was
    really 9. Every key now names its comparison, and these cases pin the
    boundary each name promises."""
    rules = data_cfg["stage_rules"]
    assert all(k.rsplit("_", 1)[-1] in {"gt", "lt", "lte"} for k in rules), (
        f"a stage_rule key must end in the comparison it gets: {sorted(rules)}"
    )

    bulk = {"sent_bytes": rules["exfiltration_sent_bytes_gt"] + 1,
            "distinct_dst_ips": 1, "syn": 0, "distinct_dst_ports": 1}
    lte = rules["exfiltration_distinct_dst_ips_lte"]
    assert _infer_stage({**bulk, "distinct_dst_ips": lte}, rules) == "exfiltration"
    assert _infer_stage({**bulk, "distinct_dst_ips": lte + 1}, rules) == UNCLASSIFIED_STAGE

    lt = rules["exfiltration_syn_lt"]
    assert _infer_stage({**bulk, "syn": lt - 1}, rules) == "exfiltration"
    assert _infer_stage({**bulk, "syn": lt}, rules) == UNCLASSIFIED_STAGE

    gt = rules["exfiltration_sent_bytes_gt"]
    assert _infer_stage({**bulk, "sent_bytes": gt + 1}, rules) == "exfiltration"
    assert _infer_stage({**bulk, "sent_bytes": gt}, rules) == UNCLASSIFIED_STAGE


def _technique_map() -> dict:
    import yaml

    from configs import resolve_path

    return yaml.safe_load(resolve_path("engine/technique_map.yaml").read_text(encoding="utf-8"))


def _technique_rule_conditions(tmap: dict):
    """(stage, when_key, threshold) for every condition in the shipped map."""
    for stage, entry in tmap.items():
        for rule in entry.get("rules") or []:
            for key, thr in (rule.get("when") or {}).items():
                yield stage, key, thr


def _owning_stage_rule(when_key: str, stage_rules: dict) -> str | None:
    """The configs/data.yaml stage_rules key that owns the same (feature,
    comparison) as this technique_map `when` key, or None.

    DERIVED by matching the WHOLE key — feature and comparison together — against
    the shipped stage_rules (`sent_bytes_gt` <- `exfiltration_sent_bytes_gt`), so
    every technique rule that reuses a stage (feature, comparison) is found, not
    only the ones a literal in this file remembered to name.

    The comparison is part of the match on purpose, and it is narrower than the
    feature name: `recon.distinct_dst_ips_gt` has NO owner even though
    `distinct_dst_ips` appears in stage_rules, because it appears there as
    `exfiltration_distinct_dst_ips_lte`. "more than 20 destinations" and "at most
    2 destinations" are two thresholds doing two different jobs, so they are not
    one number with two homes and a `stage_rule:` reference between them would be
    wrong. test_owning_stage_rule_pairs_feature_with_comparison pins that gap.

    Two owners for one key is ambiguity, not a silent pick.
    """
    owners = [r for r in stage_rules if r == when_key or r.endswith("_" + when_key)]
    assert len(owners) <= 1, f"{when_key!r} is owned by more than one stage_rule: {owners}"
    return owners[0] if owners else None


# (stage, `when` key) -> why this literal is deliberately NOT the stage threshold
# it shadows. The escape hatch is narrow on purpose: the test below fails the
# moment a registered literal EQUALS its stage threshold, because then it is a
# copy with two homes, which is the thing the reference mechanism exists to stop.
_INDEPENDENT_OF_THE_STAGE_RULE = {
    ("initial_access", "syn_gt"): (
        "the stage fires on SYNs unmatched by ACKs; naming credential guessing "
        "needs a strictly larger volume than the stage threshold"
    ),
}

# The stage_rules keys the shipped map currently reads by reference. Pinned so a
# derivation that silently matched nothing, or a reference quietly replaced by a
# literal, fails here — the loop above is what checks NEW keys; this is what
# stops the known ones from being dropped.
_REFERENCED_STAGE_RULES = {
    "scan_sequential_port_ratio_gt": 2,   # recon + lateral_movement sweeps
    "scan_distinct_dst_ports_gt": 1,
    "exfiltration_sent_bytes_gt": 1,
}


def test_technique_rules_never_copy_a_shared_stage_threshold(data_cfg):
    """One number, one home. A threshold that decides the stage AND appears in
    the technique rule for that stage must be read from configs/data.yaml, not
    copied into engine/technique_map.yaml — a copy lets a recalibrated
    stage_rule hand an operator a stage and a technique that contradict.

    The shared keys are DERIVED from configs/data.yaml stage_rules, so every rule
    keyed on the same (feature, comparison) as a stage_rule is checked — not a
    list of keys someone remembered; a literal that is deliberately a different
    number must be registered above, and stops being allowed the moment it equals
    the stage threshold it shadows.

    A rule that shares only the FEATURE with a stage_rule, under a different
    comparison, is a different threshold and is not required to reference it.
    That is the whole of what this test does not cover, and
    test_owning_stage_rule_pairs_feature_with_comparison pins which rules are in
    that position today so the set cannot grow unnoticed.
    """
    stage_rules = data_cfg["stage_rules"]
    referenced: Counter = Counter()
    independent = set()

    for stage, key, thr in _technique_rule_conditions(_technique_map()):
        owner = _owning_stage_rule(key, stage_rules)
        if owner is None:
            continue
        if thr == f"{EX.STAGE_RULE_REF}{owner}":
            referenced[owner] += 1
            continue
        reason = _INDEPENDENT_OF_THE_STAGE_RULE.get((stage, key))
        assert reason, (
            f"{stage}.{key} = {thr!r} shadows configs/data.yaml "
            f"stage_rules.{owner}; write '{EX.STAGE_RULE_REF}{owner}' instead, or "
            "register it in _INDEPENDENT_OF_THE_STAGE_RULE with the reason it is "
            "a different number"
        )
        assert thr != stage_rules[owner], (
            f"{stage}.{key} is registered as independent of stage_rules.{owner} "
            f"but now equals it ({thr!r}) — that is one number with two homes; "
            f"write '{EX.STAGE_RULE_REF}{owner}'"
        )
        independent.add((stage, key))

    assert dict(referenced) == _REFERENCED_STAGE_RULES, (
        f"the shared thresholds read by reference changed: {dict(referenced)}"
    )
    assert independent == set(_INDEPENDENT_OF_THE_STAGE_RULE), (
        "a registered independent threshold is no longer in engine/technique_map.yaml"
    )
    for owner in referenced:
        assert owner in stage_rules


# (stage, `when` key) -> the stage_rule that shares its FEATURE under a
# DIFFERENT comparison. These are precisely the rules the derivation above does
# not pair up, and the gap between what three comments used to say it checked
# ("a rule keyed on any stage feature") and what it checks ("the same feature
# AND comparison"). Pinned rather than tolerated: a new entry is a new place an
# operator could be shown a stage and a technique resting on two unrelated
# thresholds for one feature, and it should be read by a person before it ships.
_FEATURE_SHARED_COMPARISON_DIFFERS = {
    # `> 20 destinations` names a sweep; `<= 2 destinations` is part of what makes
    # a window an exfiltration transfer. Different jobs, different numbers.
    ("recon", "distinct_dst_ips_gt"): "exfiltration_distinct_dst_ips_lte",
}


def test_owning_stage_rule_pairs_feature_with_comparison(data_cfg):
    """The derivation matches the WHOLE `when` key, and the comments now say so.

    They used to say "a rule keyed on any stage feature is checked", which is
    wider than the code: the match is on the (feature, comparison) pair, so
    `recon.distinct_dst_ips_gt` is not paired with
    `stage_rules.exfiltration_distinct_dst_ips_lte`. That is the right behaviour
    — the two numbers answer different questions — but a description that
    overstates a check is how the check stops being looked at, so both halves are
    pinned here: the pairing rule itself, and the exact set of rules it leaves
    unpaired in the shipped map.
    """
    rules = {"exfiltration_distinct_dst_ips_lte": 2, "scan_distinct_dst_ports_gt": 20}
    assert _owning_stage_rule("distinct_dst_ips_gt", rules) is None, (
        "the comparison stopped being part of the match: a `_gt` rule is now "
        "paired with a `_lte` stage threshold and will be told to reference it"
    )
    assert _owning_stage_rule("distinct_dst_ips_lte", rules) == "exfiltration_distinct_dst_ips_lte"
    assert _owning_stage_rule("distinct_dst_ports_gt", rules) == "scan_distinct_dst_ports_gt"

    stage_rules = data_cfg["stage_rules"]
    unpaired = {}
    for stage, key, _thr in _technique_rule_conditions(_technique_map()):
        if _owning_stage_rule(key, stage_rules) is not None:
            continue
        feature, _op = EX.parse_when_key(key)
        shared = [
            rule for rule in stage_rules
            if rule.startswith(f"{feature}_") or f"_{feature}_" in rule
        ]
        if shared:
            assert len(shared) == 1, f"{stage}.{key} shares its feature with {shared}"
            unpaired[(stage, key)] = shared[0]

    assert unpaired == _FEATURE_SHARED_COMPARISON_DIFFERS, (
        f"the set of technique rules that share a stage_rule's FEATURE under a "
        f"different comparison changed to {unpaired}.\n"
        "test_technique_rules_never_copy_a_shared_stage_threshold does not "
        "require these to be written as 'stage_rule:' references, because a "
        "different comparison is a different threshold. Confirm that is still "
        "true of each one, then update _FEATURE_SHARED_COMPARISON_DIFFERS — or, "
        "if the two numbers really are the same number, give them one home."
    )


def test_every_technique_rule_key_names_a_comparison_the_engine_applies():
    """F-round-2: `_rule_matches` used to SKIP a `when` key whose suffix it did
    not recognise, so one typo (`..._gte` for `..._gt`) turned a condition into
    no condition and promoted every window to that technique. Unrecognised now
    raises — and the shipped map must contain no key that would."""
    for stage, key, _thr in _technique_rule_conditions(_technique_map()):
        name, op = EX.parse_when_key(key)  # raises on a typo'd suffix
        assert name and callable(op), f"{stage}.{key}"

    # the exact key the round-2 verifier measured as silently matching
    with pytest.raises(ValueError, match="names no supported comparison"):
        EX.parse_when_key("sequential_port_ratio_gte")

    # ... and a rule built on it no longer matches unconditionally
    typo = {"sequential_port_ratio_gte": 0.5}
    with pytest.raises(ValueError, match="sequential_port_ratio_gte"):
        EX._rule_matches(typo, {"sequential_port_ratio": 0.0})
    with pytest.raises(ValueError, match="sequential_port_ratio_gte"):
        EX._rule_matches(typo, {"sequential_port_ratio": "nonsense"})

    # a bare comparison with no feature, and a rule with no conditions at all,
    # are the same silent-match failure and raise too
    with pytest.raises(ValueError, match="names no supported comparison"):
        EX.parse_when_key("gt")
    with pytest.raises(ValueError, match="no `when` conditions"):
        EX._rule_matches({}, {"syn": 1})

    # the implemented comparison still compares
    assert EX._rule_matches({"syn_gt": 10}, {"syn": 11}) is True
    assert EX._rule_matches({"syn_gt": 10}, {"syn": 10}) is False
    assert EX._rule_matches({"syn_gt": 10}, {}) is False, "a missing feature fails closed"


def test_a_typo_in_the_technique_map_fails_the_run_instead_of_promoting_it(monkeypatch):
    """The same defect through the public API: a mistyped `when` key used to make
    map_technique return that technique for EVERY window of the stage."""
    broken = {"recon": {"default": None,
                        "rules": [{"when": {"sequential_port_ratio_gte": 0.5},
                                   "technique": "T1046", "name": "sweep"}]}}
    monkeypatch.setattr(EX, "_TECHNIQUE_MAP", broken)
    with pytest.raises(ValueError, match="sequential_port_ratio_gte"):
        EX.map_technique("recon", {"sequential_port_ratio": 0.0})


def test_retuning_a_stage_threshold_moves_the_technique_with_it(monkeypatch, data_cfg):
    """The other half: the reference must actually be followed at match time."""
    feats = {"sequential_port_ratio": 0.4, "distinct_dst_ports": 1, "internal": 0}
    shipped = data_cfg["stage_rules"]
    tuned = {**shipped, "scan_sequential_port_ratio_gt": 0.3}

    assert _infer_stage(feats, shipped) == UNCLASSIFIED_STAGE
    assert _infer_stage(feats, tuned) == "recon"

    monkeypatch.setattr(EX, "_stage_rules", lambda: shipped)
    assert EX.map_technique("recon", feats)["name"] == "", "0.4 is not a sweep at 0.5"
    monkeypatch.setattr(EX, "_stage_rules", lambda: tuned)
    assert EX.map_technique("recon", feats)["name"] == (
        "Network Service Discovery (sequential port sweep)"
    )

    monkeypatch.setattr(EX, "_stage_rules", lambda: {})
    with pytest.raises(KeyError, match="scan_sequential_port_ratio_gt"):
        EX.map_technique("recon", feats)


def test_unclassified_is_honest_in_the_schema_and_the_technique_map(data_cfg):
    """The fallback must be representable end to end: schema, technique map and
    config stage list agree, and `unclassified` is NOT smuggled into the seven
    trained stage classes (that list is the label encoding)."""
    import yaml

    from configs import resolve_path
    from engine.predict import OUTPUT_SCHEMA, _validate

    assert UNCLASSIFIED_STAGE not in data_cfg["stages"]
    assert OUTPUT_SCHEMA["properties"]["stage"]["enum"] == [
        *data_cfg["stages"], UNCLASSIFIED_STAGE
    ]

    tmap = yaml.safe_load(resolve_path("engine/technique_map.yaml").read_text(encoding="utf-8"))
    missing = [s for s in OUTPUT_SCHEMA["properties"]["stage"]["enum"] if s not in tmap]
    assert not missing, f"stages with no technique_map entry: {missing}"

    obj = {"host": "10.0.0.5", "window_start": 10.0, "probability": 0.9,
           "stage": UNCLASSIFIED_STAGE, "technique": None, "technique_name": "",
           "top_features": [{"feature": "syn", "value": 1.0, "contribution": 0.1}],
           "top_windows": [], "flagged_flows": [], "demo_model": False}
    _validate(obj)  # an unclassified alert must still validate

    with pytest.raises(Exception):  # ... and an invented stage must not
        _validate(dict(obj, stage="ransomware"))


def _syn(ts, sport, dport):
    pkt = (Ether(src="aa:aa:aa:aa:aa:aa", dst="bb:bb:bb:bb:bb:bb")
           / IP(src=SCAN_SRC, dst=SCAN_DST, ttl=64)
           / TCP(sport=sport, dport=dport, flags="S", seq=1, window=8192))
    pkt.time = ts
    return pkt


def _stage_counts(tmp_path, cfg, packets) -> Counter:
    """Stage decision for every host-window of a synthetic capture (no model)."""
    from data import packet_features as pf

    tmp_path.mkdir(parents=True, exist_ok=True)
    path = tmp_path / "scan.pcap"
    wrpcap(str(path), packets)
    table = pf.extract_packet_table(path, cfg)
    feats = pf.packet_window_features(table, cfg).merge(
        pf.sent_window_features(table, cfg), on=["src_ip", "window_id"], how="outer"
    ).fillna(0.0)
    return Counter(
        _infer_stage({c: float(r[c]) for c in feats.columns if c != "src_ip"},
                     cfg["stage_rules"])
        for _, r in feats.iterrows()
    )


def test_paced_randomised_scan_evades_the_stage_rules(tmp_path, data_cfg):
    """MEASURED WEAKNESS, NOT A FIX (F77). The rules count events inside a 15 s
    window, so slowing the SAME 200-port sweep 15x and randomising the port
    order puts every window under every threshold: recon disappears.

    This test pins the current behaviour so the gap is visible in the suite
    rather than only in an audit report. A sequential detector that spans
    windows is the real fix; when it lands this assertion must be inverted.
    """
    ports = list(range(2000, 2200))
    fast = _stage_counts(tmp_path / "fast", data_cfg,
                         [_syn(BASE_TS + i * 0.05, 40000 + i, p) for i, p in enumerate(ports)])

    paced_ports = ports.copy()
    random.Random(7).shuffle(paced_ports)
    paced = _stage_counts(tmp_path / "paced", data_cfg,
                          [_syn(BASE_TS + i * 0.75, 40000 + i, p)
                           for i, p in enumerate(paced_ports)])

    assert fast["recon"] == sum(fast.values()) > 0, "the fast sweep is recognised as recon"
    assert paced["recon"] == 0, (
        "the paced sweep is now detected — the evasion is fixed, so update this test "
        "and configs/data.yaml's stage_rules note"
    )
    # The evasion still works, but the fallback no longer invents a stage: every
    # evaded window says "no rule matched" instead of claiming C2 / T1071.
    assert set(paced) == {UNCLASSIFIED_STAGE}, paced
    assert EX.map_technique(UNCLASSIFIED_STAGE, {})["technique"] is None


def test_engine_reports_frames_it_could_not_parse(tmp_path, data_cfg):
    """F79: an IPv6 capture yields zero host-windows, so the engine reports zero
    alerts. 'Nothing happened' and 'I could not read the traffic' must not look
    the same in the summary."""
    from engine.predict import _windows_from_input

    tmp_path.mkdir(parents=True, exist_ok=True)
    v6 = []
    for i in range(200):
        pkt = (Ether(src="aa:aa:aa:aa:aa:aa", dst="bb:bb:bb:bb:bb:bb")
               / IPv6(src="2001:db8::5", dst="2001:db8::9", hlim=64)
               / TCP(sport=40000, dport=2000 + i, flags="S", window=8192))
        pkt.time = BASE_TS + i * 0.05
        v6.append(pkt)
    ipv4 = [_syn(BASE_TS + i * 0.05, 40000 + i, 2000 + i) for i in range(50)]

    path = tmp_path / "v6.pcap"
    wrpcap(str(path), v6)
    _flows, wf, unparsed = _windows_from_input(data_cfg, path, None)
    assert len(wf) == 0, "IPv6 produces no features (documented gap)"
    assert unparsed["known"] is True
    assert unparsed["total"] == 200 and unparsed["fraction"] == 1.0
    assert unparsed["by_reason"]["ipv6"] == 200

    mixed = tmp_path / "mixed.pcap"
    wrpcap(str(mixed), ipv4 + v6)
    _flows, wf, unparsed = _windows_from_input(data_cfg, mixed, None)
    assert len(wf) > 0 and unparsed["total"] == 200
    assert unparsed["fraction"] == pytest.approx(200 / 250)


def test_csv_input_reports_zero_unparsed_frames(fixture_csv, data_cfg):
    """A CSV carries no frames; the coverage counters must be present and zero
    rather than absent, so every consumer can read the same field."""
    from data import packet_features as pf
    from engine.predict import _windows_from_input

    _flows, wf, unparsed = _windows_from_input(data_cfg, fixture_csv, None)
    assert len(wf) > 0
    assert unparsed == {"known": True, "total": 0, "fraction": 0.0,
                        "by_reason": dict.fromkeys(pf.DROP_REASONS, 0)}


def test_an_unknown_drop_history_is_reported_unknown_not_clean(tmp_path, data_cfg):
    """The counter's own silent-failure mode. The counts ride on `.attrs`, which
    pandas strips as soon as the table is combined with a frame that has none, so
    a packet table can arrive with no drop history — which must never be
    summarised as 'every frame was parsed'."""
    from data import packet_features as pf
    from engine.predict import _coverage

    tmp_path.mkdir(parents=True, exist_ok=True)
    path = tmp_path / "one.pcap"
    wrpcap(str(path), [_syn(BASE_TS, 40000, 80)])
    table = pf.extract_packet_table(path, data_cfg)
    assert pf.dropped_frames(table) == dict.fromkeys(pf.DROP_REASONS, 0)

    plain = pd.DataFrame({"ts": table["ts"], "extra": 1})
    reshaped = table.merge(plain, on="ts")  # the history does not survive this
    assert pf.dropped_frames(reshaped) is None, "a lost history must not read as {}"

    unknown = _coverage(len(reshaped), pf.dropped_frames(reshaped))
    clean = _coverage(len(table), pf.dropped_frames(table))
    assert unknown["known"] is False and clean["known"] is True
    assert unknown["total"] is None and unknown["fraction"] is None
    assert clean["total"] == 0
    # the per-reason keys survive, so a consumer reads None rather than a
    # fabricated 0 (and never a KeyError)
    assert unknown["by_reason"]["ipv6"] is None
    assert unknown != clean


def test_forecast_hosts_are_raw_addresses_and_the_summary_says_so(fixture_csv, data_cfg):
    """F40: the engine's hosts are real addresses (an analyst cannot act on a
    hash); only the ledger pseudonymises. The reported flag is MEASURED off the
    emitted hosts, so it cannot drift from what the run actually wrote."""
    from engine.predict import _hosts_pseudonymised, _windows_from_input

    flows, wf, _unparsed = _windows_from_input(data_cfg, fixture_csv, None)
    hosts = set(wf["host"].astype(str))
    assert hosts and hosts <= set(flows["src_ip"].astype(str)), "hosts are raw source IPs"
    assert _hosts_pseudonymised(hosts) is False, "raw addresses are not pseudonyms"
    assert _hosts_pseudonymised(hosts) is HOSTS_PSEUDONYMISED, (
        "the measurement and the documented design expectation have diverged"
    )
    # the measurement is of the data, not of this module: real pseudonyms read as
    # pseudonymised, an empty run as nothing-to-pseudonymise (never as a
    # privacy guarantee), and one leaked address is enough to say False.
    assert _hosts_pseudonymised(["9f3ac1", "0b21ee"]) is True
    assert _hosts_pseudonymised([]) is False
    assert _hosts_pseudonymised(["9f3ac1", "172.31.0.5"]) is False
    assert _hosts_pseudonymised(["2001:db8::5"]) is False


class _StubEngine:
    """Stands in for the two trained artifacts predict_file loads: the persisted
    scaler (`transform`) and the persisted booster (`predict_proba`).

    `alerting` decides whether the first host-window scores above
    `threshold`, so a run can be driven onto the alert path or kept quiet.
    """

    threshold = 0.5

    def __init__(self, alerting: bool = True):
        self.alerting = alerting

    def transform(self, X):
        return X

    def predict_proba(self, X):
        p = np.full(len(X), 0.10)
        if self.alerting and len(p):
            p[0] = 0.99
        return np.column_stack([1.0 - p, p])


class _StubShap:
    """Stands in for TreeSHAP, which needs the real booster. Still returns NAMED
    features (never indices), so the output schema is applied for real."""

    def __init__(self, model, feature_names):
        self.feature_names = feature_names

    def top_features(self, X, k: int = 5):
        return [[{"feature": n, "value": 0.0, "contribution": 0.0}
                 for n in self.feature_names[:k]] for _ in range(len(X))]


@pytest.fixture
def artifact_free_engine(monkeypatch):
    """Run the REAL predict.predict_file on a machine with no artifacts/.

    Only the seams that read a trained artifact are stubbed — the model+scaler
    loader (`_load_engine`), the persisted model spec and threshold, the
    weight-digest check and the TreeSHAP explainer. Feature extraction,
    thresholding, the stage rules, the technique map, schema validation, the
    ledger and EVERY write into out_dir are the production path.

    Stubbing `load_model_spec` is also what pins these runs to the PUBLISHED lane:
    `resolve_artifact_lane` asks the published thresholds for the variant, so a
    stub that answers is a published bundle as far as the engine is concerned.
    Without it these tests would silently change lane on a machine where the demo
    lane happens to be bootstrapped, and would assert against demo output while
    claiming to be artifact-free. The demo lane has its own tests below.

    This exists because the alternative — a test that calls predict.py's helpers
    directly — let the `_write_run_summary` call site be deleted from
    predict_file with the whole engine test file still green: the only
    assertions tying persistence to the production call site were in tests that
    skip wherever artifacts/ is absent (CI, a judge's clone).

    Returns the stub, whose `.alerting` flag the test can flip before the run.
    """
    import pathlib
    import sys

    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "scripts"))
    import verify_weights as VW

    from engine import predict
    from engine import thresholds as TH

    stub = _StubEngine()
    monkeypatch.setattr(predict, "_load_engine",
                        lambda cfg, variant: (stub, stub, "engine_model.json"))
    monkeypatch.setattr(TH, "load_model_spec",
                        lambda cfg, variant: {"file": "engine_model.json",
                                              "val_auroc": 0.5})
    monkeypatch.setattr(TH, "load_threshold",
                        lambda cfg, fpr_budget, variant="full": _StubEngine.threshold)
    monkeypatch.setattr(VW, "verify", lambda *a, **k: (True, None))
    monkeypatch.setattr(EX, "ShapExplainer", _StubShap)
    return stub


def test_predict_file_persists_the_run_summary_it_returns(
        artifact_free_engine, fixture_csv, tmp_path):
    """The PRODUCTION call site, not the helper (F79 / round-2 verifier).

    Deleting `_write_run_summary(out_dir, summary)` from predict_file must break
    a test that runs on a bare checkout. This is that test: it drives the real
    predict_file with the trained artifacts stubbed out and reads the result off
    the DISK. It also pins the persisted summary to the returned one, so a
    partial or stale write fails too.
    """
    import json

    from engine import predict
    from engine.predict import FORECASTS_FILE, RUN_SUMMARY_FILE

    result = predict.predict_file(fixture_csv, out_dir=tmp_path)
    assert result["n_alerts"] >= 1, "the stub booster must exercise the alert path"

    summary_path = tmp_path / RUN_SUMMARY_FILE
    assert summary_path.exists(), (
        f"predict_file wrote {sorted(p.name for p in tmp_path.iterdir())} but no "
        f"{RUN_SUMMARY_FILE}: the run-level facts would live only in the return "
        "value, so a SAVED run could not tell '0 alerts' from 'saw nothing' (F79)"
    )
    on_disk = json.loads(summary_path.read_text(encoding="utf-8"))
    assert on_disk == {k: v for k, v in result.items() if k not in ("forecasts", "graph")}, (
        "the persisted run summary and the returned one have drifted"
    )
    assert json.loads((tmp_path / FORECASTS_FILE).read_text(encoding="utf-8")) == (
        result["forecasts"]), "forecasts.json is not what the run returned"


def test_a_saved_blind_run_is_distinguishable_from_a_saved_quiet_one(
        artifact_free_engine, tmp_path):
    """F79's claim, end to end through predict_file rather than through its
    helper: an IPv6-only capture (nothing could be read) and a quiet IPv4
    capture (nothing happened) both save an empty forecasts.json, and only the
    files predict_file itself writes tell them apart."""
    import json

    from engine import predict
    from engine.predict import FORECASTS_FILE, RUN_SUMMARY_FILE

    artifact_free_engine.alerting = False

    v6 = []
    for i in range(200):
        pkt = (Ether(src="aa:aa:aa:aa:aa:aa", dst="bb:bb:bb:bb:bb:bb")
               / IPv6(src="2001:db8::5", dst="2001:db8::9", hlim=64)
               / TCP(sport=40000, dport=2000 + i, flags="S", window=8192))
        pkt.time = BASE_TS + i * 0.05
        v6.append(pkt)
    wrpcap(str(tmp_path / "v6.pcap"), v6)
    wrpcap(str(tmp_path / "v4.pcap"),
           [_syn(BASE_TS + i * 0.05, 40000 + i, 80) for i in range(30)])

    blind_dir, quiet_dir = tmp_path / "blind", tmp_path / "quiet"
    blind = predict.predict_file(tmp_path / "v6.pcap", out_dir=blind_dir)
    quiet = predict.predict_file(tmp_path / "v4.pcap", out_dir=quiet_dir)
    assert blind["n_alerts"] == quiet["n_alerts"] == 0
    assert blind["n_host_windows"] == 0 and quiet["n_flows"] == 30

    # both saved runs alerted on nothing ...
    for d in (blind_dir, quiet_dir):
        assert (d / FORECASTS_FILE).read_text(encoding="utf-8") == "[]"
    # ... and the summaries predict_file wrote still tell them apart
    for d in (blind_dir, quiet_dir):
        assert (d / RUN_SUMMARY_FILE).exists(), (
            f"predict_file wrote {sorted(p.name for p in d.iterdir())} but no "
            f"{RUN_SUMMARY_FILE}, so these two saved runs are indistinguishable"
        )
    seen = json.loads((blind_dir / RUN_SUMMARY_FILE).read_text(encoding="utf-8"))
    unseen = json.loads((quiet_dir / RUN_SUMMARY_FILE).read_text(encoding="utf-8"))
    assert seen["unparsed_frames"]["by_reason"]["ipv6"] == 200
    assert seen["unparsed_frames"]["fraction"] == 1.0
    assert unseen["unparsed_frames"]["total"] == 0
    assert seen != unseen


def test_run_summary_is_persisted_beside_the_forecasts(tmp_path):
    """F79's artifact half: the coverage counters must survive the process. A
    saved run of an IPv6-only capture has to be distinguishable from a clean one
    by its FILES, not only by an in-process return value.

    A unit test of the writer alone — it proves the two summaries differ on
    disk, NOT that predict_file calls it. The call site is guarded by
    test_predict_file_persists_the_run_summary_it_returns and
    test_a_saved_blind_run_is_distinguishable_from_a_saved_quiet_one, which run
    the real predict_file.
    """
    import json

    from engine.predict import (FORECASTS_FILE, RUN_SUMMARY_FILE, _coverage,
                                _write_run_summary)

    blind = {"n_flows": 0, "n_host_windows": 0, "n_alerts": 0, "threshold": 0.5,
             "unparsed_frames": _coverage(0, {"ipv6": 200}),
             "hosts_pseudonymised": False, "forecasts_file": FORECASTS_FILE}
    quiet = {**blind, "n_flows": 1000, "n_host_windows": 40,
             "unparsed_frames": _coverage(1000, {})}

    a, b = tmp_path / "ipv6_only", tmp_path / "quiet"
    a.mkdir()
    b.mkdir()
    (a / FORECASTS_FILE).write_text("[]", encoding="utf-8")
    (b / FORECASTS_FILE).write_text("[]", encoding="utf-8")
    _write_run_summary(a, blind)
    _write_run_summary(b, quiet)

    # both runs alerted on nothing ...
    assert (a / FORECASTS_FILE).read_text(encoding="utf-8") == (
        b / FORECASTS_FILE).read_text(encoding="utf-8") == "[]"
    # ... and the saved summaries still tell them apart
    seen = json.loads((a / RUN_SUMMARY_FILE).read_text(encoding="utf-8"))
    unseen = json.loads((b / RUN_SUMMARY_FILE).read_text(encoding="utf-8"))
    assert seen["unparsed_frames"]["by_reason"]["ipv6"] == 200
    assert seen["unparsed_frames"]["fraction"] == 1.0
    assert unseen["unparsed_frames"]["total"] == 0
    assert seen != unseen
    assert seen["hosts_pseudonymised"] is False


@pytest.mark.skipif(
    not __import__("configs").resolve_path("app/assets/synthetic_demo.pcap").exists(),
    reason="synthetic demo pcap not built — run python -m capture.make_synthetic_demo",
)
def test_engine_feature_path_and_stage_rules_are_deterministic(data_cfg):
    """M0 determinism claim, artifact-free half: two runs of the engine's own
    feature path over the bundled capture agree bit for bit, and the stage rules
    over those rows are a pure function of them. The model half needs weights —
    test_predict_file_is_deterministic covers it when they are present."""
    from configs import resolve_path
    from engine.predict import _windows_from_input

    pcap = resolve_path("app/assets/synthetic_demo.pcap")
    flows_a, wf_a, unparsed_a = _windows_from_input(data_cfg, pcap, None)
    flows_b, wf_b, unparsed_b = _windows_from_input(data_cfg, pcap, None)

    pd.testing.assert_frame_equal(wf_a, wf_b, check_exact=True)
    pd.testing.assert_frame_equal(flows_a, flows_b, check_exact=True)
    assert unparsed_a == unparsed_b

    def stages_of(wf):
        cols = [c for c in wf.columns if c not in ("host", "day")]
        return [_infer_stage({c: float(r[c]) for c in cols}, data_cfg["stage_rules"])
                for _, r in wf.iterrows()]

    assert stages_of(wf_a) == stages_of(wf_b)


@pytest.mark.skipif(not engine_artifacts_present(),
                    reason="engine artifacts absent — run python -m engine.train_engine")
def test_predict_file_is_deterministic(fixture_csv, tmp_path):
    """The other half of the determinism claim: same input, same weights, same
    forecasts — byte for byte, including the ledger records."""
    from engine import predict

    first = (tmp_path / "a")
    second = (tmp_path / "b")
    r1 = predict.predict_file(fixture_csv, out_dir=first)
    r2 = predict.predict_file(fixture_csv, out_dir=second)

    assert r1["forecasts"] == r2["forecasts"]
    from engine.predict import FORECASTS_FILE, RUN_SUMMARY_FILE

    for name in (FORECASTS_FILE, RUN_SUMMARY_FILE, "audit_chain.jsonl"):
        assert (first / name).read_text(encoding="utf-8") == (
            second / name).read_text(encoding="utf-8"), f"{name} is not reproducible"


def test_top_contributing_windows_ranks_and_bounds_context():
    """M8.3: top windows are the host's highest-probability windows within the
    context leading up to the alert, with seconds-before-alert."""
    from engine.predict import _top_contributing_windows

    # (window_start, prob); alert at 100, context 60s -> windows 40..100 only
    hist = [(20, 0.9), (45, 0.3), (60, 0.95), (80, 0.6), (100, 0.7), (120, 0.99)]
    top = _top_contributing_windows(hist, alert_ws=100, context_seconds=60, k=3)
    assert [w["window_start"] for w in top] == [60, 100, 80], "ranked by prob, in-context"
    assert top[0]["seconds_before_alert"] == 40 and top[1]["seconds_before_alert"] == 0
    # the future window (120) and the out-of-context one (20) are excluded
    assert all(40 <= w["window_start"] <= 100 for w in top)


# ==========================================================================
# ARTIFACT LANES: the published engine vs the demo model a fresh clone can fit
# ==========================================================================
# engine/predict.py resolves which weights a run loads. The published lane must
# keep absolute priority, the demo lane must never shadow it, a half-installed
# lane of either kind must fail loudly instead of becoming the other one, and
# every result of a demo run must say so IN ITS DATA.
#
# These tests build their own lanes under tmp_path - a real (tiny) XGBoost model,
# a real scaler, a real threshold file, a real SHA-256 record - so they run on a
# bare clone, on the demo machine and on a machine with the published bundle
# alike, and assert the same thing in all three. Nothing here asserts a
# probability, an AUROC or a detection: passing these is evidence about LABELLING
# and REFUSAL, never about model quality. That is the point - a test that passes
# against a toy model must not be readable as evidence for a number measured on
# CSE-CIC-IDS-2018.

DEMO_NOWCAST_FULL = "demo_engine_model.json"
DEMO_NOWCAST_FLOW = "demo_engine_model_flow.json"


def _verify_weights_module():
    import pathlib
    import sys

    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "scripts"))
    import verify_weights as VW

    return VW


def _tiny_booster(n_features: int, seed: int = 0):
    """A real XGBClassifier, small and seeded. Real because the point is to drive
    the production loader (`xgb.XGBClassifier().load_model`) and the production
    TreeSHAP explainer, not a stub of either."""
    import xgboost as xgb

    rng = np.random.default_rng(seed)
    X = rng.normal(size=(64, n_features)).astype(np.float32)
    y = (X[:, 0] > 0).astype(int)
    model = xgb.XGBClassifier(n_estimators=4, max_depth=2, tree_method="hist",
                              eval_metric="logloss")
    model.fit(X, y)
    return model


def _write_scaler(path, n_features: int) -> None:
    import pickle

    from sklearn.preprocessing import StandardScaler

    rng = np.random.default_rng(1)
    scaler = StandardScaler().fit(rng.normal(size=(64, n_features)))
    with open(path, "wb") as fh:
        pickle.dump(scaler, fh)


def _two_lane_cfg(data_cfg, published_dir, demo_dir) -> dict:
    """The real config with both lanes pointed into tmp_path."""
    return {
        **data_cfg,
        "paths": {**data_cfg["paths"], "artifacts_dir": str(published_dir)},
        "demo": {**data_cfg.get("demo", {}), "artifacts_dir": str(demo_dir)},
    }


def _stub_lane_files(directory, lane, *, threshold=True, scaler=True) -> None:
    """The two files lane resolution looks at, without fitting anything.

    `lane` is written into the persisted thresholds exactly as
    engine/thresholds.py spells it, because that field is what declares a lane.
    Pass None to write a threshold file with no declaration at all.
    """
    import json as _json

    from engine import thresholds as TH

    directory.mkdir(parents=True, exist_ok=True)
    if threshold:
        body = {"full": {"file": "x.json", "fpr_0.01": 0.5},
                "flow": {"file": "x.json", "fpr_0.01": 0.5}}
        if lane is not None:
            body[TH.LANE_FIELD] = lane
        (directory / "engine_threshold.json").write_text(
            _json.dumps(body), encoding="utf-8")
    if scaler:
        (directory / "window_scaler.pkl").write_bytes(b"")


def _build_demo_lane(cfg, demo_dir, *, threshold_value: float = 0.0,
                     horizons=(), source="app/assets/synthetic_demo.pcap") -> dict:
    """A COMPLETE demo lane under tmp_path: real weights, real scaler, real
    threshold file. The digest record is written separately, by
    scripts/verify_weights.py, because that is the production path.

    `threshold_value` defaults to 0.0 so every scored window alerts. That makes
    the alert path, the forecast objects and the ledger deterministic for a
    plumbing test; it is an operating point chosen FOR the test, and nothing here
    reads it as a measurement.
    """
    import json as _json

    from data import windows as W
    from engine import thresholds as TH

    demo_dir.mkdir(parents=True, exist_ok=True)
    columns = W.feature_columns(cfg)
    _write_scaler(demo_dir / "window_scaler.pkl", len(columns))

    persisted = {
        TH.LANE_FIELD: TH.DEMO_LANE,
        "model": "xgb",
        "features": columns,
        "demo_provenance": {"source_capture": source},
    }
    for tag, base in (("full", DEMO_NOWCAST_FULL), ("flow", DEMO_NOWCAST_FLOW)):
        for horizon in (0, *horizons):
            name = base if horizon == 0 else base.replace(".json", "_k%d.json" % horizon)
            _tiny_booster(len(columns), seed=horizon).save_model(str(demo_dir / name))
            persisted[TH.horizon_variant(tag, horizon)] = {
                "file": name, "horizon": horizon,
                "in_sample_auroc": 1.0, "auroc_is_in_sample": True,
                "fpr_0.01": threshold_value, "fpr_0.001": threshold_value,
            }
    (demo_dir / "engine_threshold.json").write_text(
        _json.dumps(persisted, indent=2), encoding="utf-8")
    return persisted


def _small_input(fixture_csv, tmp_path, rows: int = 40):
    """The head of the committed fixture, as its own CSV.

    The same loader, the same schema, the same code path - fewer rows, because
    these tests drive the REAL TreeSHAP explainer at an alert threshold of 0.0
    (every window alerts, which is what makes the ledger deterministic) and
    explaining a thousand flows' worth of windows costs a minute per test for no
    extra coverage. Nothing here asserts a count.

    40 rows is still 591 host-windows and 591 alerts on the committed fixture
    (measured this session), so every labelling assertion below has hundreds of
    objects to be true of; 120 rows bought 977 and cost roughly half as much
    again per test.
    """
    lines = fixture_csv.read_text(encoding="utf-8").splitlines()[:rows + 1]
    small = tmp_path / "small.csv"
    small.write_text("".join(line + "\n" for line in lines), encoding="utf-8")
    return small


@pytest.fixture
def demo_lane(data_cfg, tmp_path, monkeypatch):
    """A built demo lane, with `engine.predict` and `engine.forecast` pointed at
    it and no published bundle in sight. Yields (cfg, published_dir, demo_dir).

    Nowcast heads only; `_add_horizon_heads` adds the k-step ones for the two
    tests that need them. Everything downstream of the config is the production
    path: the real resolver, the real loader, the real digest check, the real
    TreeSHAP explainer, the real ledger.
    """
    from configs import load_config as _load_config
    from engine import forecast as FC
    from engine import predict as P

    published_dir = tmp_path / "artifacts"
    demo_dir = tmp_path / "demo"
    cfg = _two_lane_cfg(data_cfg, published_dir, demo_dir)
    _build_demo_lane(cfg, demo_dir)
    _verify_weights_module().record(P._lane_cfg(cfg, demo_dir))

    monkeypatch.setattr(P, "load_config",
                        lambda name: cfg if name == "data" else _load_config(name))
    monkeypatch.setattr(FC, "load_config",
                        lambda name: cfg if name == "data" else _load_config(name))
    return cfg, published_dir, demo_dir


def _add_horizon_heads(cfg, demo_dir, threshold_value: float = 0.0) -> list:
    """Fit and persist this demo lane's k-step heads, for the forecast tests.

    Separate from the fixture because the k-step heads cost a model fit each and
    only two tests read them; the digest record is untouched because the k-step
    weights are not digest-tracked in either lane (engine/forecast.py says so).
    """
    import json as _json

    from data import windows as W
    from engine import thresholds as TH

    horizons = [int(k) for k in cfg["engine"]["forecast_horizons"]]
    path = demo_dir / "engine_threshold.json"
    persisted = _json.loads(path.read_text(encoding="utf-8"))
    n_features = len(W.feature_columns(cfg))
    for tag, base in (("full", DEMO_NOWCAST_FULL), ("flow", DEMO_NOWCAST_FLOW)):
        for horizon in horizons:
            name = base.replace(".json", "_k%d.json" % horizon)
            _tiny_booster(n_features, seed=horizon).save_model(str(demo_dir / name))
            persisted[TH.horizon_variant(tag, horizon)] = {
                "file": name, "horizon": horizon,
                "in_sample_auroc": 1.0, "auroc_is_in_sample": True,
                "fpr_0.01": threshold_value, "fpr_0.001": threshold_value,
            }
    path.write_text(_json.dumps(persisted, indent=2), encoding="utf-8")
    return horizons


# -- lane resolution -------------------------------------------------------

def test_the_published_lane_wins_even_with_a_demo_lane_sitting_beside_it(
        data_cfg, tmp_path):
    """Priority, as a test. A complete demo lane next to a usable published one
    changes nothing: the run loads the published weights and never looks at the
    demo directory.

    FALSIFIABLE: swap the order in resolve_artifact_lane so the demo lane is
    consulted first - the plausible edit, since "prefer the lane we just built"
    is what makes a fresh clone work - and this fails on both variants.
    """
    from engine import predict as P
    from engine import thresholds as TH

    published, demo = tmp_path / "artifacts", tmp_path / "demo"
    cfg = _two_lane_cfg(data_cfg, published, demo)
    _stub_lane_files(published, TH.PUBLISHED_LANE)
    _stub_lane_files(demo, TH.DEMO_LANE)

    for variant in ("full", "flow"):
        lane = P.resolve_artifact_lane(cfg, variant)
        assert lane.name == TH.PUBLISHED_LANE and lane.demo is False
        assert lane.dir == published.resolve(), (
            "a demo lane at %s shadowed the published artifacts at %s" % (demo, published))
        assert lane.notice is None


def test_the_demo_lane_is_used_only_when_the_published_thresholds_are_absent(
        data_cfg, tmp_path):
    """The fallback itself: with no published bundle, a complete self-declared
    demo lane is resolved, carries the notice, and hands downstream a config
    pointed at its own directory.

    FALSIFIABLE: delete the `_demo_lane(cfg)` call at the end of
    resolve_artifact_lane (returning `published` unconditionally) and every
    assertion here fails.
    """
    from configs import resolve_path
    from engine import predict as P
    from engine import thresholds as TH

    published, demo = tmp_path / "artifacts", tmp_path / "demo"
    cfg = _two_lane_cfg(data_cfg, published, demo)
    _stub_lane_files(demo, TH.DEMO_LANE)

    lane = P.resolve_artifact_lane(cfg, "flow")
    assert lane.name == TH.DEMO_LANE and lane.demo is True
    assert lane.dir == demo.resolve()
    assert lane.notice == P.DEMO_MODEL_NOTICE
    # the lane travels as a config, so thresholds / verify_weights / _load_engine
    # all read the same directory without being told about lanes at all
    assert resolve_path(lane.cfg["paths"]["artifacts_dir"]) == demo.resolve()


@pytest.mark.parametrize("leftover", [
    ("window_scaler.pkl",),
    ("engine_model.json", "engine_model_flow.json"),
    ("engine_model_flow.json",),
    ("engine_model.json", "window_scaler.pkl"),
])
def test_a_half_installed_published_bundle_refuses_instead_of_running_the_demo_model(
        data_cfg, tmp_path, leftover):
    """The failure this whole design exists to prevent: part of a published
    bundle is on disk and the run quietly becomes a demo run that looks normal.

    Every partial state is the same refusal, because the ways a bundle ends up
    partial are not all the same: a deleted threshold file leaves the scaler, and
    an interrupted release download leaves the weight files and nothing else.

    MEASURED IN THIS SESSION: before scripts/verify_weights.PUBLISHED_NOWCAST_WEIGHTS
    was added to `_published_lane_files`, the second case here - both published
    weight files present, no threshold, no scaler - resolved to lane='demo' and
    ran. The guard looked only at the threshold file and the scaler, so the two
    files a judge is most likely to have half-downloaded were invisible to it.

    FALSIFIABLE, two ways:
      * delete the `strays` check in resolve_artifact_lane -> every case returns
        a demo lane instead of raising;
      * narrow `_published_lane_files` back to `_lane_core_files` -> the
        weight-file-only cases fall through to the demo lane again, which is
        exactly the bug this parametrisation was added for.
    """
    from engine import predict as P
    from engine import thresholds as TH

    published, demo = tmp_path / "artifacts", tmp_path / "demo"
    cfg = _two_lane_cfg(data_cfg, published, demo)
    _stub_lane_files(demo, TH.DEMO_LANE)

    published.mkdir(parents=True, exist_ok=True)
    for name in leftover:
        (published / name).write_bytes(b"not a real weight file")

    with pytest.raises(RuntimeError, match="INCOMPLETE") as exc:
        P.resolve_artifact_lane(cfg, "flow")
    for name in leftover:
        assert name in str(exc.value), (
            "the refusal must name the published file it found, so whoever reads it "
            "knows which bundle went missing")


def test_the_published_file_names_come_from_the_module_that_attests_them(data_cfg):
    """`_published_lane_files` must not keep its own spelling of the published
    weight filenames. engine/predict.py uses them to DETECT a half-installed
    bundle and scripts/verify_weights.py uses them to ATTEST one; two copies that
    drift means one module treating a file as published evidence while the other
    cannot see it.

    FALSIFIABLE: inline the names as literals in engine/predict.py and rename one
    in scripts/verify_weights.py - this fails, where the drift would otherwise be
    invisible until a partial bundle silently ran as a demo.
    """
    from engine import predict as P

    VW = _verify_weights_module()
    names = P._published_lane_files(data_cfg)

    assert set(VW.PUBLISHED_NOWCAST_WEIGHTS) <= set(names)
    assert set(VW.PUBLISHED_NOWCAST_WEIGHTS) <= set(VW.TRACKED), (
        "the published nowcast weights must stay inside the digest-tracked list")
    assert "engine_threshold.json" in names and "window_scaler.pkl" in names


def test_a_demo_directory_that_does_not_declare_itself_demo_is_refused(
        data_cfg, tmp_path):
    """A directory is not a demo lane because of where it sits; it is one because
    its persisted thresholds say so. Editing that declaration away - the obvious
    way to dress demo weights up as published ones - must fail the run.

    FALSIFIABLE: drop the `declared != TH.DEMO_LANE` check in `_demo_lane` and
    both cases below resolve happily, reporting demo weights as published.
    """
    from engine import predict as P
    from engine import thresholds as TH

    published, demo = tmp_path / "artifacts", tmp_path / "demo"
    cfg = _two_lane_cfg(data_cfg, published, demo)

    _stub_lane_files(demo, TH.PUBLISHED_LANE)  # declaration flipped
    with pytest.raises(RuntimeError, match="declares lane"):
        P.resolve_artifact_lane(cfg, "flow")

    _stub_lane_files(demo, None)  # declaration deleted entirely
    with pytest.raises(RuntimeError, match="declares lane"):
        P.resolve_artifact_lane(cfg, "flow")


def test_a_half_written_demo_lane_is_refused_rather_than_skipped(data_cfg, tmp_path):
    """A bootstrap that died halfway must not read downstream as "no artifacts
    were ever built" - that sends whoever is looking at it to the wrong fix.

    FALSIFIABLE: turn the incompleteness branch in `_demo_lane` into `return None`
    and this raises the ordinary missing-artifacts FileNotFoundError instead of
    naming the half-written lane.
    """
    from engine import predict as P
    from engine import thresholds as TH

    published, demo = tmp_path / "artifacts", tmp_path / "demo"
    cfg = _two_lane_cfg(data_cfg, published, demo)
    _stub_lane_files(demo, TH.DEMO_LANE, scaler=False)

    with pytest.raises(RuntimeError, match="demo artifact lane.*INCOMPLETE"):
        P.resolve_artifact_lane(cfg, "flow")


def test_one_directory_cannot_be_both_lanes(data_cfg, tmp_path):
    """If the two configured directories are the same, every run out of it would
    be reported as published whatever it holds. That is a config error, and it is
    refused before anything is loaded.

    FALSIFIABLE: remove the equality check and the run reports lane 'published'
    while loading whatever is in the shared directory.
    """
    from engine import predict as P
    from engine import thresholds as TH

    both = tmp_path / "artifacts"
    cfg = _two_lane_cfg(data_cfg, both, both)
    _stub_lane_files(both, TH.DEMO_LANE)

    with pytest.raises(RuntimeError, match="same directory"):
        P.resolve_artifact_lane(cfg, "flow")


def test_with_no_lane_at_all_the_missing_artifact_error_is_unchanged(
        data_cfg, tmp_path):
    """A bare clone has no published bundle and no demo lane. That is not a
    demo-lane problem, so resolution returns the published lane untouched and the
    existing "run engine.train_engine / fetch the release" error is what the
    operator sees.

    FALSIFIABLE: make resolve_artifact_lane raise its own error for the empty
    case and the message a bare clone gets stops naming the fix.
    """
    from engine import predict as P
    from engine import thresholds as TH

    published, demo = tmp_path / "artifacts", tmp_path / "demo"
    cfg = _two_lane_cfg(data_cfg, published, demo)

    lane = P.resolve_artifact_lane(cfg, "flow")
    assert lane.name == TH.PUBLISHED_LANE and lane.demo is False

    with pytest.raises(FileNotFoundError, match="engine_threshold"):
        TH.load_model_spec(lane.cfg, "flow")


def test_the_demo_lane_directory_is_one_place_in_the_config(data_cfg):
    """engine/predict.py and engine/thresholds.py must look for the demo lane in
    the SAME directory. Two answers here is a lane one module loads and the other
    disowns, and the symptom would be a demo run reported as published.

    FALSIFIABLE: point `demo_lane_dir` at anything else - a different config key,
    a sibling of the published directory - and this fails.
    """
    from engine import predict as P
    from engine import thresholds as TH

    assert P.demo_lane_dir(data_cfg) == TH._demo_artifacts_dir(data_cfg)
    assert P.demo_lane_dir({"paths": data_cfg["paths"]}) is None, (
        "a config with no demo block must yield no demo lane, not a guess")


def test_the_demo_notice_states_what_the_run_is_not():
    """The honesty constraint as a test, in the same spirit as
    test_forecast_engine.py's caveat test. The notice travels in the result dict,
    in run_summary.json and in the k-step block, so softening it must break the
    build rather than only a review.

    FALSIFIABLE: delete any one of these statements from DEMO_MODEL_NOTICE.
    """
    from engine.predict import DEMO_MODEL_NOTICE as notice

    lowered = notice.lower()
    assert "not the published" in lowered, "it must deny being the published engine"
    assert "cse-cic-ids2018" in lowered.replace("cse-cic-ids-2018", "cse-cic-ids2018"), (
        "it must name the dataset the published numbers were measured on")
    assert "memorised" in lowered or "memorized" in lowered, (
        "it must say the demo model has memorised its one capture")
    assert "reproduces nothing" in lowered
    assert "do not quote" in lowered


# -- the demo flag as DATA, through the production call path ---------------

def test_a_demo_run_is_flagged_in_the_return_dict_and_the_persisted_summary(
        demo_lane, fixture_csv, tmp_path):
    """A downstream consumer must be able to tell demo output from real output
    without parsing prose - the same way `unparsed_frames` and
    `role_features_degraded` are read - and a SAVED run must carry it too.

    FALSIFIABLE: drop `demo_model` (or `artifact_lane`) from the summary dict in
    predict_file and this fails in the return value and on disk at once, because
    the persisted file is asserted to equal the returned one.
    """
    import json

    from engine import predict as P
    from engine.predict import RUN_SUMMARY_FILE

    out = tmp_path / "run"
    result = P.predict_file(_small_input(fixture_csv, tmp_path), out_dir=out)

    assert result["demo_model"] is True
    assert result["artifact_lane"] == "demo"
    assert result["demo_model_notice"] == P.DEMO_MODEL_NOTICE
    assert result["demo_model_source"] == "app/assets/synthetic_demo.pcap"

    on_disk = json.loads((out / RUN_SUMMARY_FILE).read_text(encoding="utf-8"))
    assert on_disk["demo_model"] is True and on_disk["artifact_lane"] == "demo"
    assert on_disk == {k: v for k, v in result.items()
                       if k not in ("forecasts", "graph")}, (
        "the persisted run summary and the returned one have drifted")


def test_every_forecast_object_says_which_lane_produced_it(
        demo_lane, fixture_csv, tmp_path):
    """forecasts.json is a bare array. It gets read, copied and quoted from on its
    own, long after the summary beside it is gone, so the lane has to travel on
    every object rather than once per run.

    FALSIFIABLE: remove `"demo_model": lane.demo` from the forecast object in
    predict_file. The schema requires it, so this fails as a validation error
    inside predict_file - the run stops rather than emitting unlabelled
    forecasts.
    """
    import json

    from engine import predict as P
    from engine.predict import FORECASTS_FILE

    out = tmp_path / "run"
    result = P.predict_file(_small_input(fixture_csv, tmp_path), out_dir=out)
    assert result["forecasts"], "the demo lane produced no forecasts to label"
    assert all(f["demo_model"] is True for f in result["forecasts"])

    saved = json.loads((out / FORECASTS_FILE).read_text(encoding="utf-8"))
    assert saved == result["forecasts"]
    assert all(f["demo_model"] is True for f in saved)


def test_every_ledger_record_names_the_lane_that_wrote_it(
        demo_lane, fixture_csv, tmp_path):
    """The ledger is the tamper-evident record of what the engine forecast. A demo
    record that looks exactly like a published one is the worst version of this
    feature's failure, and the lane rides INSIDE the hashed content, so a record
    cannot be edited into a published-looking one without breaking the chain.

    FALSIFIABLE: drop `artifact_lane` from the ledger.append call and the first
    assertion fails; keep it but edit a written record's lane field by hand (done
    below) and verification fails at that record.
    """
    import json

    from engine import predict as P
    from ledger import verify_cli

    out = tmp_path / "run"
    result = P.predict_file(_small_input(fixture_csv, tmp_path), out_dir=out)
    assert result["n_alerts"] >= 1, "no ledger records were written to inspect"

    chain = out / "audit_chain.jsonl"
    lines = [ln for ln in chain.read_text(encoding="utf-8").splitlines() if ln.strip()]
    records = [json.loads(ln) for ln in lines]
    assert {r["artifact_lane"] for r in records} == {"demo"}
    ok, first_bad = verify_cli.verify(chain)
    assert ok, "an untampered demo-lane ledger must verify (failed at %s)" % (first_bad,)

    # relabelling a demo record as published is a tamper, not an edit
    records[0]["artifact_lane"] = "published"
    lines[0] = json.dumps(records[0], sort_keys=True, separators=(",", ":"))
    chain.write_text("\n".join(lines) + "\n", encoding="utf-8")
    ok, first_bad = verify_cli.verify(chain)
    assert not ok and first_bad == 0, (
        "editing a record's lane must break the hash chain at that record")


def test_a_demo_run_announces_itself_on_stderr(demo_lane, fixture_csv, tmp_path,
                                               capsys):
    """The data fields are what a program reads. This is what a human sees when
    they run the CLI or the smoke runner and would otherwise watch a normal
    -looking run scroll past.

    FALSIFIABLE: delete the `announce_lane(lane)` call from predict_file and
    nothing is printed. A published run must stay silent, which the second half
    checks by asserting the notice is the only thing that could have printed it.
    """
    from engine import predict as P

    P.predict_file(_small_input(fixture_csv, tmp_path), out_dir=tmp_path / "run")
    err = capsys.readouterr().err
    assert "DEMO MODEL" in err and "NOT THE PUBLISHED ENGINE" in err
    assert str(demo_lane[2]) in err, "the announcement must name the lane directory"
    assert "app/assets/synthetic_demo.pcap" in err

    # the published lane says nothing at all
    published = P.ArtifactLane(name="published", dir=tmp_path, cfg={}, demo=False,
                               notice=None, source=None)
    P.announce_lane(published)
    assert capsys.readouterr().err == ""


def test_a_tampered_demo_model_is_refused_exactly_as_a_tampered_published_one(
        demo_lane, fixture_csv, tmp_path):
    """M9.3 on the demo lane. The attestation is the same call against the demo
    lane's own weights.sha256 - not a special case, not an exemption - so a
    demo model edited after its digests were recorded is refused and NO ledger is
    written.

    FALSIFIABLE (two ways):
      * skip the digest check when `lane.demo` - the obvious shortcut, since a
        locally fitted model "obviously" matches - and the tampered run below
        completes and writes a chain;
      * pass the base `cfg` instead of `lane.cfg` to VW.verify, so the check
        reads the PUBLISHED digest record: with no such record, `verify` returns
        (False, 'weights.sha256 ...') and the control run at the top of this test
        fails instead.
    """
    from engine import predict as P

    _cfg, _published, demo_dir = demo_lane

    # control: the untampered lane runs and writes a ledger
    small = _small_input(fixture_csv, tmp_path)
    clean = tmp_path / "clean"
    P.predict_file(small, out_dir=clean)
    assert (clean / "audit_chain.jsonl").exists()

    # a CSV scores through the flow head; edit that model's bytes
    model = demo_dir / DEMO_NOWCAST_FLOW
    model.write_bytes(model.read_bytes().replace(b'"base_score"', b'"base_scorE"', 1))

    out = tmp_path / "tampered"
    with pytest.raises(RuntimeError, match="SHA-256 mismatch"):
        P.predict_file(small, out_dir=out)
    assert not (out / "audit_chain.jsonl").exists(), (
        "no ledger record may be written when a demo weight fails its digest")


def test_the_kstep_forecast_inherits_the_lane_and_leads_with_the_demo_notice(
        demo_lane, fixture_csv, tmp_path):
    """A k-step curve drawn from a demo model is the most misleading artifact this
    feature can produce: it is shaped like a forecast and plotted like one. So the
    block, the persisted file and every entry carry the lane, and the caveat a UI
    renders leads with the demo notice rather than with the forward-forecast one.

    FALSIFIABLE: return FORWARD_FORECAST_CAVEAT unconditionally from
    `forecast_caveat`, or drop `demo_model` from the block - each breaks a
    separate assertion here.
    """
    import json

    from engine import forecast as FC

    _add_horizon_heads(demo_lane[0], demo_lane[2])
    out = tmp_path / "run"
    result = FC.forecast_file(_small_input(fixture_csv, tmp_path), out_dir=out)

    assert result["demo_model"] is True and result["artifact_lane"] == "demo"
    assert result["horizons"], "no k-step head was served, so there is no curve to label"
    assert all(e["demo_model"] is True for e in result["forecast"])
    assert result["forecast_caveat"].startswith("DEMO MODEL")
    assert FC.FORWARD_FORECAST_CAVEAT in result["forecast_caveat"], (
        "the measured forward-forecast caveat must survive the demo prefix, not be "
        "replaced by it")

    block = json.loads((out / FC.FORECAST_FILE).read_text(encoding="utf-8"))
    assert block["demo_model"] is True and block["artifact_lane"] == "demo"
    assert block["forecast_caveat"] == result["forecast_caveat"]
    assert block["demo_model_notice"]


def test_the_kstep_heads_are_loaded_from_the_same_lane_as_the_nowcast(
        demo_lane, fixture_csv, tmp_path, monkeypatch):
    """A run must not pair a published nowcast with a demo forward curve, or the
    reverse. engine/forecast.py never resolves a lane of its own: it reuses the
    one the nowcast put in the scoring context.

    FALSIFIABLE: pass `cfg` instead of `lane.cfg` to `_load_horizon_heads` in
    forecast_file. Every head then resolves against the PUBLISHED directory,
    which here is empty, so `horizons` comes back empty and
    `unavailable_horizons` fills up - both asserted below.
    """
    from engine import forecast as FC
    from engine import predict as P

    _cfg, _published, demo_dir = demo_lane
    seen = []
    real_load = P._load_engine

    def spy(cfg, variant):
        seen.append(str(cfg["paths"]["artifacts_dir"]))
        return real_load(cfg, variant)

    _add_horizon_heads(_cfg, demo_dir)
    monkeypatch.setattr(P, "_load_engine", spy)
    result = FC.forecast_file(_small_input(fixture_csv, tmp_path), out_dir=tmp_path / "run")

    assert result["horizons"] == sorted(int(k) for k in _cfg["engine"]["forecast_horizons"])
    assert result["unavailable_horizons"] == {}
    assert seen, "no weights were loaded at all"
    assert set(seen) == {str(demo_dir)}, (
        "the nowcast and the k-step heads came from different directories: %s" % (
            sorted(set(seen)),))


def test_verify_weights_covers_the_demo_lanes_own_weights(demo_lane, tmp_path):
    """The demo lane's weight filenames are not the published ones, so TRACKED
    alone would hash none of them: `record` would write a digest file covering
    nothing and `verify` would then pass over a lane it had checked no bytes of.
    That is the silent exemption this extension exists to prevent.

    FALSIFIABLE: make `tracked_names` return TRACKED unconditionally. `record`
    then raises (it refuses a demo record that covers none of the lane's own
    weights), and every assertion below fails.
    """
    import json

    from engine import predict as P

    cfg, _published, demo_dir = demo_lane
    VW = _verify_weights_module()
    lane_cfg = P._lane_cfg(cfg, demo_dir)

    assert VW.is_demo_lane(lane_cfg) is True
    assert VW.is_demo_lane(cfg) is False, "the published lane must not read as demo"

    names = VW.tracked_names(lane_cfg)
    assert DEMO_NOWCAST_FULL in names and DEMO_NOWCAST_FLOW in names
    assert set(VW.TRACKED) <= set(names), "the published names must not be dropped"
    assert DEMO_NOWCAST_FULL not in VW.TRACKED, (
        "the demo names belong to the lane, not to the published TRACKED list")

    recorded = json.loads(VW.digest_path(lane_cfg).read_text(encoding="utf-8"))
    assert DEMO_NOWCAST_FULL in recorded and DEMO_NOWCAST_FLOW in recorded
    assert "window_scaler.pkl" in recorded
    ok, offender = VW.verify(lane_cfg)
    assert ok, "the recorded demo lane must verify (%s)" % (offender,)

    # and the record is about THIS lane only: the published lane has none
    ok, offender = VW.verify(cfg)
    assert not ok and "weights.sha256" in str(offender)


def test_a_digest_record_that_hashes_nothing_is_refused_and_never_reads_as_verified(
        data_cfg, tmp_path):
    """An empty attestation is the absence of one wearing its name.

    MEASURED IN THIS SESSION: `--record` against a directory holding none of the
    tracked files wrote `{}`, and the next `verify` returned (True, None) - the
    CLI printed "OK: all tracked model weights match their recorded SHA-256"
    having hashed no bytes of anything. The engine's own call passes explicit
    `names`, so it was never fooled; the human running the attestation script
    was.

    FALSIFIABLE, two ways: drop the `if not digests` refusal in `record` and the
    first half passes (an empty record is written); drop the `if not recorded`
    check in `verify` and the second half returns verified for a record of
    nothing.
    """
    import json

    from engine import predict as P

    VW = _verify_weights_module()
    empty = tmp_path / "artifacts"
    empty.mkdir(parents=True)
    cfg = P._lane_cfg(data_cfg, empty)

    with pytest.raises(RuntimeError, match="hash nothing"):
        VW.record(cfg)
    assert not VW.digest_path(cfg).exists(), (
        "a refused record must not leave a digest file behind")

    # ... and a record emptied by hand is not verified either
    VW.digest_path(cfg).write_text(json.dumps({}), encoding="utf-8")
    ok, offender = VW.verify(cfg)
    assert not ok and "no file at all" in str(offender)

    # the CLI reports the refusal as a message and an exit code, not a traceback
    assert VW.main(["--record", "--artifacts-dir", str(empty)]) == 1
