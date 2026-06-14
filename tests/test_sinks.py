"""Tests for the alert sinks (JSONL store + reader)."""

from __future__ import annotations

from datetime import datetime

from minisoc.alerting.alert import Alert
from minisoc.alerting.sinks import JsonlSink, read_jsonl
from minisoc.core.event import Event


def _alert(rule_id: str = "r1") -> Alert:
    event = Event(
        timestamp=datetime(2026, 6, 11, 19, 0, 0),
        event_action="ssh_login_failed",
        source_ip="192.0.2.66",
        log_source="auth.log",
    )
    return Alert(
        rule_id=rule_id,
        rule_title="Test Rule",
        severity="high",
        timestamp=datetime(2026, 6, 11, 19, 0, 0),
        events=[event],
        group_value="192.0.2.66",
        description="a test",
    )


def test_jsonl_sink_writes_roundtrippable_records(tmp_path):
    store = JsonlSink(tmp_path / "alerts.jsonl")
    store.emit([_alert("r1"), _alert("r2")])

    records = read_jsonl(store.path)
    assert len(records) == 2
    assert records[0]["rule_id"] == "r1"
    assert records[0]["severity"] == "high"
    assert records[0]["group_value"] == "192.0.2.66"
    # ECS-nested event evidence is preserved.
    assert records[0]["events"][0]["source"]["ip"] == "192.0.2.66"


def test_jsonl_sink_appends_across_calls(tmp_path):
    store = JsonlSink(tmp_path / "alerts.jsonl")
    store.emit([_alert("r1")])
    store.emit([_alert("r2")])
    assert len(read_jsonl(store.path)) == 2


def test_jsonl_sink_reset_truncates(tmp_path):
    store = JsonlSink(tmp_path / "alerts.jsonl")
    store.emit([_alert("r1")])
    store.reset()
    store.emit([_alert("r2")])
    records = read_jsonl(store.path)
    assert len(records) == 1
    assert records[0]["rule_id"] == "r2"


def test_emit_empty_does_not_create_file(tmp_path):
    store = JsonlSink(tmp_path / "alerts.jsonl")
    store.emit([])
    assert not store.path.exists()


def test_read_missing_store_returns_empty(tmp_path):
    assert read_jsonl(tmp_path / "nope.jsonl") == []


def test_read_skips_malformed_lines(tmp_path):
    path = tmp_path / "alerts.jsonl"
    path.write_text('{"rule_id": "ok"}\nnot json\n\n{"rule_id": "ok2"}\n')
    records = read_jsonl(path)
    assert [r["rule_id"] for r in records] == ["ok", "ok2"]
