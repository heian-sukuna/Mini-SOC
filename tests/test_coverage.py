"""Tests for the MITRE ATT&CK coverage rollup."""

from __future__ import annotations

from minisoc.detections.coverage import mitre_coverage, technique_ids, technique_url
from minisoc.detections.loader import load_rules
from minisoc.detections.rule import Rule


def _rule(rule_id: str, tags: list[str], level: str = "high") -> Rule:
    return Rule(id=rule_id, title=rule_id.title(), condition="selection", level=level, tags=tags)


def test_technique_ids_extracts_techniques_and_subtechniques():
    tags = ["attack.credential_access", "attack.t1110", "attack.t1110.001"]
    assert technique_ids(tags) == ["T1110", "T1110.001"]


def test_technique_ids_ignores_tactics_and_junk():
    assert technique_ids(["attack.persistence", "tool.nmap", "T1110"]) == []


def test_technique_url_technique_and_subtechnique():
    assert technique_url("T1110") == "https://attack.mitre.org/techniques/T1110/"
    assert technique_url("T1110.001") == "https://attack.mitre.org/techniques/T1110/001/"


def test_mitre_coverage_groups_rules_by_technique():
    rules = [
        _rule("r1", ["attack.t1110"]),
        _rule("r2", ["attack.t1110", "attack.t1046"]),
    ]
    rollup = mitre_coverage(rules)

    techniques = {t["technique"]: t for t in rollup["techniques"]}
    assert set(techniques) == {"T1046", "T1110"}
    assert {r["id"] for r in techniques["T1110"]["rules"]} == {"r1", "r2"}
    assert techniques["T1046"]["url"].endswith("/T1046/")


def test_mitre_coverage_reports_untagged_rules():
    rules = [_rule("tagged", ["attack.t1110"]), _rule("bare", [])]
    rollup = mitre_coverage(rules)
    assert rollup["untagged"] == ["bare"]


def test_mitre_coverage_techniques_sorted():
    rules = [_rule("r", ["attack.t1110", "attack.t1003", "attack.t1046"])]
    order = [t["technique"] for t in mitre_coverage(rules)["techniques"]]
    assert order == sorted(order)


def test_loaded_rules_carry_tags():
    # The loader must populate `tags` (it used to silently drop them) so coverage works.
    from minisoc.core.config import REPO_ROOT

    rules = load_rules(REPO_ROOT / "minisoc" / "detections" / "rules")
    brute = next(r for r in rules if r.id == "ssh-bruteforce-001")
    assert "attack.t1110" in brute.tags

    rollup = mitre_coverage(rules)
    assert any(t["technique"] == "T1110" for t in rollup["techniques"])
