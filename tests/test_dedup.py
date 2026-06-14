"""Tests for alert deduplication within a sliding window."""

from __future__ import annotations

from datetime import datetime, timedelta

from minisoc.alerting.alert import Alert
from minisoc.alerting.dedup import Deduplicator
from minisoc.core.event import Event


def _alert(rule_id: str, when: datetime, *, ip: str | None = None, group=None) -> Alert:
    events = [Event(source_ip=ip)] if ip else []
    return Alert(
        rule_id=rule_id,
        rule_title=rule_id,
        severity="high",
        timestamp=when,
        events=events,
        group_value=group,
    )


def test_collapses_repeats_within_window():
    base = datetime(2026, 6, 11, 19, 0, 0)
    alerts = [
        _alert("r1", base, ip="1.2.3.4"),
        _alert("r1", base + timedelta(seconds=30), ip="1.2.3.4"),
        _alert("r1", base + timedelta(seconds=60), ip="1.2.3.4"),
    ]
    kept = Deduplicator(window_seconds=300).filter(alerts)
    assert len(kept) == 1
    assert kept[0].occurrences == 3
    assert kept[0].last_seen == base + timedelta(seconds=60)


def test_distinct_sources_are_not_merged():
    base = datetime(2026, 6, 11, 19, 0, 0)
    alerts = [
        _alert("r1", base, ip="1.2.3.4"),
        _alert("r1", base + timedelta(seconds=10), ip="9.9.9.9"),
    ]
    kept = Deduplicator(window_seconds=300).filter(alerts)
    assert len(kept) == 2


def test_distinct_rules_are_not_merged():
    base = datetime(2026, 6, 11, 19, 0, 0)
    alerts = [_alert("r1", base, ip="1.2.3.4"), _alert("r2", base, ip="1.2.3.4")]
    kept = Deduplicator(window_seconds=300).filter(alerts)
    assert len(kept) == 2


def test_repeat_outside_window_starts_new_alert():
    base = datetime(2026, 6, 11, 19, 0, 0)
    alerts = [
        _alert("r1", base, ip="1.2.3.4"),
        _alert("r1", base + timedelta(seconds=400), ip="1.2.3.4"),  # > 300s gap
    ]
    kept = Deduplicator(window_seconds=300).filter(alerts)
    assert len(kept) == 2
    assert all(a.occurrences == 1 for a in kept)


def test_sliding_window_keeps_burst_collapsed():
    # Each event is < window apart, but first and last span more than the window.
    base = datetime(2026, 6, 11, 19, 0, 0)
    alerts = [_alert("r1", base + timedelta(seconds=200 * i), ip="1.2.3.4") for i in range(4)]
    kept = Deduplicator(window_seconds=300).filter(alerts)
    assert len(kept) == 1
    assert kept[0].occurrences == 4


def test_group_value_takes_precedence_over_ip():
    base = datetime(2026, 6, 11, 19, 0, 0)
    alerts = [
        _alert("r1", base, group="192.0.2.66"),
        _alert("r1", base + timedelta(seconds=10), group="192.0.2.66"),
    ]
    kept = Deduplicator(window_seconds=300).filter(alerts)
    assert len(kept) == 1
    assert kept[0].occurrences == 2
