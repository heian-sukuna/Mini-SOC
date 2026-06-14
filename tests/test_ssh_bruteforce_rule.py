"""Tests for the SSH brute-force detection rule and the engine internals it exercises.

Each rule gets a matching-event test (proves it fires) AND a non-matching test (proves
it does not false-positive).
"""

from __future__ import annotations

from datetime import datetime, timedelta
from pathlib import Path

from minisoc.core.event import Event
from minisoc.detections.engine import DetectionEngine
from minisoc.detections.loader import load_rule

RULES_DIR = Path(__file__).resolve().parents[1] / "minisoc" / "detections" / "rules"
RULE = load_rule(RULES_DIR / "ssh_bruteforce.yml")


def _failed_login(ip: str, when: datetime, user: str = "root") -> Event:
    return Event(
        timestamp=when,
        event_category="authentication",
        event_action="ssh_login_failed",
        event_outcome="failure",
        source_ip=ip,
        user_name=user,
        host_name="web01",
        process_name="sshd",
        log_source="auth.log",
    )


def _engine() -> DetectionEngine:
    return DetectionEngine(default_window="5m")


def test_rule_loads_correctly():
    assert RULE.id == "ssh-bruteforce-001"
    assert RULE.timeframe == "5m"
    assert RULE.logsource["service"] == "sshd"
    assert "selection" in RULE.selections


def test_fires_on_five_failures_from_one_ip_in_window():
    start = datetime(2026, 6, 11, 19, 30, 0)
    events = [_failed_login("192.0.2.66", start + timedelta(seconds=20 * i)) for i in range(5)]
    alerts = _engine().evaluate_rule(RULE, events)
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.rule_id == "ssh-bruteforce-001"
    assert alert.severity == "high"
    assert alert.group_value == "192.0.2.66"
    assert alert.match_count >= 5


def test_does_not_fire_on_four_failures():
    start = datetime(2026, 6, 11, 19, 30, 0)
    events = [_failed_login("192.0.2.66", start + timedelta(seconds=20 * i)) for i in range(4)]
    alerts = _engine().evaluate_rule(RULE, events)
    assert alerts == []


def test_does_not_fire_when_failures_spread_across_ips():
    # Five failures, but from five different IPs -> no single IP crosses the threshold.
    start = datetime(2026, 6, 11, 19, 30, 0)
    events = [
        _failed_login(f"192.0.2.{10 + i}", start + timedelta(seconds=20 * i)) for i in range(5)
    ]
    alerts = _engine().evaluate_rule(RULE, events)
    assert alerts == []


def test_does_not_fire_when_failures_outside_window():
    # Five failures from one IP, but spread over ~33 minutes -> never 5 within 5 minutes.
    start = datetime(2026, 6, 11, 19, 0, 0)
    events = [_failed_login("192.0.2.66", start + timedelta(minutes=8 * i)) for i in range(5)]
    alerts = _engine().evaluate_rule(RULE, events)
    assert alerts == []


def test_successful_logins_do_not_count():
    # Successful logins from the same IP must not satisfy the failed-login selection.
    start = datetime(2026, 6, 11, 19, 30, 0)
    events = []
    for i in range(6):
        e = _failed_login("192.0.2.66", start + timedelta(seconds=20 * i))
        e.event_action = "ssh_login_success"  # flip the action so the selection misses
        e.event_outcome = "success"
        events.append(e)
    alerts = _engine().evaluate_rule(RULE, events)
    assert alerts == []
