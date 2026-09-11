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
    }
    _validate(good)  # must not raise

    bad = dict(good, probability=1.5)  # out of [0,1]
    with pytest.raises(Exception):
        _validate(bad)

    bad2 = dict(good, top_features=[{"value": 1.0, "contribution": 0.2}])  # no 'feature' name
    with pytest.raises(Exception):
        _validate(bad2)


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
           "top_windows": [], "flagged_flows": []}
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

    Only the four seams that read a trained artifact are stubbed — the
    model+scaler loader (`_load_engine`), the persisted threshold, the
    weight-digest check and the TreeSHAP explainer. Feature extraction,
    thresholding, the stage rules, the technique map, schema validation, the
    ledger and EVERY write into out_dir are the production path.

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
