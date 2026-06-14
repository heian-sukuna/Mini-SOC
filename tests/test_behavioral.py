"""Tests for behavioral detections (impossible travel)."""

from __future__ import annotations

from datetime import datetime

from minisoc.core.event import Event
from minisoc.detections.behavioral import default_detectors, impossible_travel


def _login(user, country, minute):
    return Event(
        timestamp=datetime(2026, 6, 12, 10, minute, 0),
        event_category="authentication",
        event_action="ssh_login_success",
        event_outcome="success",
        user_name=user,
        source_ip="203.0.113.7",
        log_source="auth.log",
        extra={"source.geo.country_iso_code": country},
    )


def test_impossible_travel_fires_on_country_change():
    events = [_login("alice", "US", 0), _login("alice", "RU", 5)]
    alerts = impossible_travel(
        events, timespan_seconds=3600, level="critical",
        rule_id="impossible-travel-001", title="Impossible Travel", description="",
    )
    assert len(alerts) == 1
    assert alerts[0].group_value == "alice"
    assert alerts[0].severity == "critical"
    assert len(alerts[0].events) == 2


def test_no_alert_when_same_country():
    events = [_login("alice", "US", 0), _login("alice", "US", 5)]
    assert impossible_travel(
        events, timespan_seconds=3600, level="critical",
        rule_id="impossible-travel-001", title="t", description="",
    ) == []


def test_no_alert_when_outside_window():
    # Two countries but 2 hours apart -> travel is plausible, no alert.
    events = [_login("alice", "US", 0), _login("alice", "RU", 0)]
    events[1].timestamp = datetime(2026, 6, 12, 12, 30, 0)
    assert impossible_travel(
        events, timespan_seconds=3600, level="critical",
        rule_id="impossible-travel-001", title="t", description="",
    ) == []


def test_ignores_logins_without_country():
    # LAN logins carry no country and must not trigger.
    events = [_login("bob", "US", 0)]
    events.append(_login("bob", "RU", 5))
    events[1].extra = {}  # second login has no geo
    assert impossible_travel(
        events, timespan_seconds=3600, level="critical",
        rule_id="impossible-travel-001", title="t", description="",
    ) == []


def test_default_detector_dispatch():
    detector = default_detectors()[0]
    assert detector.id == "impossible-travel-001"
    assert "attack.t1078" in detector.tags
    events = [_login("carol", "NG", 0), _login("carol", "DE", 10)]
    alerts = detector.evaluate(events)
    assert len(alerts) == 1 and alerts[0].rule_id == "impossible-travel-001"
