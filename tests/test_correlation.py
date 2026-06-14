"""Tests for Phase 4: temporal correlation (Sigma Correlations subset).

Covers the new base rule (match + non-match), the correlation rule loader, the
Correlator's chain-finding logic (ordered + unordered, and every way a chain can fail),
and the pipeline-level suppression of correlation-only rules.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from pathlib import Path

import pytest

from minisoc.alerting.alert import Alert
from minisoc.core.event import Event
from minisoc.core.pipeline import Pipeline
from minisoc.core.runner import run_scenario
from minisoc.detections.correlation import CorrelationRule, Correlator
from minisoc.detections.engine import DetectionEngine
from minisoc.detections.loader import load_rule, load_rules
from tests.util import make_config as _config

RULES_DIR = Path(__file__).resolve().parents[1] / "minisoc" / "detections" / "rules"

T0 = datetime(2026, 6, 12, 10, 0, 0)


# --------------------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------------------


def _login_event(action: str, ip: str, when: datetime) -> Event:
    outcome = "success" if action == "ssh_login_success" else "failure"
    return Event(
        timestamp=when,
        event_category="authentication",
        event_action=action,
        event_outcome=outcome,
        source_ip=ip,
        user_name="root",
        host_name="web01",
        process_name="sshd",
        log_source="auth.log",
    )


def _alert(rule_id: str, ip: str, when: datetime) -> Alert:
    """A minimal base-rule alert backed by one event carrying the group field."""
    return Alert(
        rule_id=rule_id,
        rule_title=rule_id,
        severity="high",
        timestamp=when,
        events=[_login_event("ssh_login_failed", ip, when)],
        source="auth.log",
    )


def _correlation(corr_type: str = "temporal_ordered") -> CorrelationRule:
    return CorrelationRule(
        id="corr-001",
        title="A then B",
        type=corr_type,
        rules=["rule-a", "rule-b"],
        group_by=["source.ip"],
        timespan="5m",
        level="critical",
    )


# --------------------------------------------------------------------------------------
# The new base rule: SSH Successful Login (match + non-match)
# --------------------------------------------------------------------------------------

SUCCESS_RULE = load_rule(RULES_DIR / "ssh_login_success.yml")


def test_login_success_rule_matches_successful_login():
    events = [_login_event("ssh_login_success", "192.0.2.66", T0)]
    alerts = DetectionEngine().evaluate_rule(SUCCESS_RULE, events)
    assert len(alerts) == 1
    assert alerts[0].rule_id == "ssh-login-success-001"


def test_login_success_rule_ignores_failed_login():
    events = [_login_event("ssh_login_failed", "192.0.2.66", T0)]
    alerts = DetectionEngine().evaluate_rule(SUCCESS_RULE, events)
    assert alerts == []


# --------------------------------------------------------------------------------------
# Loader: correlation documents
# --------------------------------------------------------------------------------------


def test_correlation_rule_loads_correctly():
    corr = load_rule(RULES_DIR / "ssh_bruteforce_success.yml")
    assert isinstance(corr, CorrelationRule)
    assert corr.id == "ssh-bruteforce-success-001"
    assert corr.type == "temporal_ordered"
    assert corr.rules == ["ssh-bruteforce-001", "ssh-login-success-001"]
    assert corr.group_by == ["source.ip"]
    assert corr.timespan == "5m"
    assert corr.level == "critical"
    # `generate` list: brute force keeps alerting, the success matcher does not.
    assert corr.generates("ssh-bruteforce-001") is True
    assert corr.generates("ssh-login-success-001") is False


def test_load_rules_rejects_unknown_reference(tmp_path):
    (tmp_path / "bad_corr.yml").write_text(
        "title: Bad\n"
        "id: bad-corr-001\n"
        "correlation:\n"
        "  type: temporal\n"
        "  rules: [no-such-rule-001, also-missing-002]\n"
        "  timespan: 5m\n"
    )
    with pytest.raises(ValueError, match="unknown rule id"):
        load_rules(tmp_path)


def test_load_rule_requires_timespan(tmp_path):
    (tmp_path / "no_span.yml").write_text(
        "title: Bad\n"
        "id: bad-corr-002\n"
        "correlation:\n"
        "  type: temporal\n"
        "  rules: [a, b]\n"
    )
    with pytest.raises(ValueError, match="timespan"):
        load_rule(tmp_path / "no_span.yml")


# --------------------------------------------------------------------------------------
# Correlator: ordered chains
# --------------------------------------------------------------------------------------


def test_ordered_chain_fires_a_then_b_same_group():
    by_rule = {
        "rule-a": [_alert("rule-a", "192.0.2.66", T0)],
        "rule-b": [_alert("rule-b", "192.0.2.66", T0 + timedelta(minutes=2))],
    }
    alerts = Correlator().evaluate(_correlation(), by_rule)
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.rule_id == "corr-001"
    assert alert.severity == "critical"
    assert alert.group_value == "192.0.2.66"
    assert alert.timestamp == T0 + timedelta(minutes=2)
    assert alert.match_count == 2  # evidence from both links of the chain


def test_ordered_chain_rejects_wrong_order():
    # B happens BEFORE A -> temporal_ordered must not fire.
    by_rule = {
        "rule-a": [_alert("rule-a", "192.0.2.66", T0 + timedelta(minutes=2))],
        "rule-b": [_alert("rule-b", "192.0.2.66", T0)],
    }
    assert Correlator().evaluate(_correlation(), by_rule) == []


def test_unordered_accepts_either_order():
    # The same out-of-order firings DO satisfy plain `temporal`.
    by_rule = {
        "rule-a": [_alert("rule-a", "192.0.2.66", T0 + timedelta(minutes=2))],
        "rule-b": [_alert("rule-b", "192.0.2.66", T0)],
    }
    alerts = Correlator().evaluate(_correlation("temporal"), by_rule)
    assert len(alerts) == 1


def test_chain_rejects_different_groups():
    # A and B fire, but from different IPs -> no shared group, no correlation.
    by_rule = {
        "rule-a": [_alert("rule-a", "192.0.2.66", T0)],
        "rule-b": [_alert("rule-b", "10.0.0.8", T0 + timedelta(minutes=1))],
    }
    assert Correlator().evaluate(_correlation(), by_rule) == []


def test_chain_rejects_outside_timespan():
    # B follows A in order, but 20 minutes later (> 5m timespan).
    by_rule = {
        "rule-a": [_alert("rule-a", "192.0.2.66", T0)],
        "rule-b": [_alert("rule-b", "192.0.2.66", T0 + timedelta(minutes=20))],
    }
    assert Correlator().evaluate(_correlation(), by_rule) == []


def test_chain_requires_every_rule():
    # Only A fired -> incomplete chain.
    by_rule = {
        "rule-a": [_alert("rule-a", "192.0.2.66", T0)],
        "rule-b": [],
    }
    assert Correlator().evaluate(_correlation(), by_rule) == []


def test_unordered_survives_tied_timestamps():
    # Regression: two same-second firings of the same rule with different content used
    # to crash the merged sort (tuple comparison fell through to Alert < Alert).
    tied_a1 = _alert("rule-a", "192.0.2.66", T0)
    tied_a2 = _alert("rule-a", "192.0.2.66", T0)
    tied_a2.events[0].user_name = "admin"  # same time, different content
    by_rule = {
        "rule-a": [tied_a1, tied_a2],
        "rule-b": [_alert("rule-b", "192.0.2.66", T0 + timedelta(minutes=1))],
    }
    alerts = Correlator().evaluate(_correlation("temporal"), by_rule)
    assert len(alerts) == 1


def test_ordered_chain_uses_best_start_not_just_first():
    # A fires early (chain from there would exceed the window) and again later
    # (chain fits). The correlator must find the later, valid start.
    by_rule = {
        "rule-a": [
            _alert("rule-a", "192.0.2.66", T0),
            _alert("rule-a", "192.0.2.66", T0 + timedelta(minutes=18)),
        ],
        "rule-b": [_alert("rule-b", "192.0.2.66", T0 + timedelta(minutes=20))],
    }
    alerts = Correlator().evaluate(_correlation(), by_rule)
    assert len(alerts) == 1
    assert alerts[0].timestamp == T0 + timedelta(minutes=20)


# --------------------------------------------------------------------------------------
# Pipeline integration: suppression + the real rule chain
# --------------------------------------------------------------------------------------


def test_success_logins_alone_produce_no_alerts(tmp_path):
    # The match-only success rule is referenced by the correlation and must therefore
    # never alert on its own — otherwise every legitimate login would page someone.
    pipeline = Pipeline(_config(tmp_path))
    events = [
        _login_event("ssh_login_success", "10.0.0.8", T0 + timedelta(minutes=i))
        for i in range(3)
    ]
    assert pipeline.run_events(events) == []


def test_bruteforce_then_success_fires_correlation(tmp_path):
    pipeline = Pipeline(_config(tmp_path))
    events = [
        _login_event("ssh_login_failed", "192.0.2.66", T0 + timedelta(seconds=20 * i))
        for i in range(5)
    ]
    events.append(_login_event("ssh_login_success", "192.0.2.66", T0 + timedelta(minutes=3)))

    fired = {a.rule_id for a in pipeline.run_events(events)}
    # The standalone brute-force alert (generate list) AND the critical correlation —
    # but NOT a bare success alert.
    assert fired == {"ssh-bruteforce-001", "ssh-bruteforce-success-001"}


def test_bruteforce_without_success_does_not_fire_correlation(tmp_path):
    pipeline = Pipeline(_config(tmp_path))
    events = [
        _login_event("ssh_login_failed", "192.0.2.66", T0 + timedelta(seconds=20 * i))
        for i in range(5)
    ]
    fired = {a.rule_id for a in pipeline.run_events(events)}
    assert fired == {"ssh-bruteforce-001"}


def test_success_from_other_ip_does_not_fire_correlation(tmp_path):
    # A brute force from one IP and a legitimate login from another must not chain.
    pipeline = Pipeline(_config(tmp_path))
    events = [
        _login_event("ssh_login_failed", "192.0.2.66", T0 + timedelta(seconds=20 * i))
        for i in range(5)
    ]
    events.append(_login_event("ssh_login_success", "10.0.0.8", T0 + timedelta(minutes=3)))

    fired = {a.rule_id for a in pipeline.run_events(events)}
    assert fired == {"ssh-bruteforce-001"}


def test_scenario_fires_bruteforce_and_correlation(tmp_path):
    result = run_scenario("ssh-bruteforce-success", _config(tmp_path))
    by_severity = {a.rule_id: a.severity for a in result.alerts}
    assert by_severity == {
        "ssh-bruteforce-001": "high",
        "ssh-bruteforce-success-001": "critical",
    }
