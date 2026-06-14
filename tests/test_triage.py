"""Tests for the SQLite triage store: lifecycle, notes, incidents, and JSONL sync."""

from __future__ import annotations

from minisoc.alerting.sinks import JsonlSink
from minisoc.core.runner import run_scenario
from minisoc.scenarios.registry import store_path
from minisoc.triage import TriageStore, alert_uid
from minisoc.triage.store import triage_db_path
from tests.util import make_config as _config


def _record(rule_id="ssh-bruteforce-001", group="10.0.0.9", ts="2026-06-12T10:00:00", mode="live"):
    return {
        "rule_id": rule_id, "rule_title": "SSH Brute Force", "severity": "high",
        "timestamp": ts, "source": "auth.log", "group_value": group, "mode": mode,
        "occurrences": 1, "description": "d", "enrichment": {"country": "RU"}, "events": [],
    }


def test_ingest_is_idempotent():
    store = TriageStore(":memory:")
    uid1 = store.ingest_record(_record())
    uid2 = store.ingest_record(_record())   # same logical alert
    assert uid1 == uid2 == alert_uid(_record())
    assert store.count() == 1


def test_new_alerts_start_as_new_and_carry_enrichment():
    store = TriageStore(":memory:")
    store.ingest_record(_record())
    alerts = store.list_alerts()
    assert len(alerts) == 1
    assert alerts[0]["status"] == "new"
    assert alerts[0]["enrichment"] == {"country": "RU"}


def test_status_lifecycle_and_open_filter():
    store = TriageStore(":memory:")
    uid = store.ingest_record(_record())
    assert store.set_status(uid, "acknowledged") is True
    assert store.set_status("nope", "acknowledged") is False
    assert store.list_alerts(open_only=True)[0]["status"] == "acknowledged"
    store.set_status(uid, "closed_false_positive")
    assert store.list_alerts(open_only=True) == []        # closed -> not open
    assert len(store.list_alerts()) == 1                   # still there unfiltered
    assert store.stats()["by_status"]["closed_false_positive"] == 1


def test_notes_round_trip():
    store = TriageStore(":memory:")
    uid = store.ingest_record(_record())
    store.add_note(uid, "looks like a real brute force", author="ryan")
    alert = store.get_alert(uid)
    assert alert["notes"][0]["body"] == "looks like a real brute force"
    assert alert["notes"][0]["author"] == "ryan"


def test_incident_grouping():
    store = TriageStore(":memory:")
    a = store.ingest_record(_record(group="10.0.0.1"))
    b = store.ingest_record(_record(group="10.0.0.2"))
    inc = store.group_into_incident([a, b], "Coordinated SSH campaign")
    incidents = store.list_incidents()
    assert incidents[0]["id"] == inc
    assert incidents[0]["alert_count"] == 2
    assert store.list_alerts(incident_id=inc)[0]["incident_id"] == inc


def test_set_status_rejects_unknown():
    store = TriageStore(":memory:")
    uid = store.ingest_record(_record())
    try:
        store.set_status(uid, "bogus")
    except ValueError as exc:
        assert "unknown status" in str(exc)
    else:
        raise AssertionError("expected ValueError")


def test_sync_from_jsonl_pulls_real_alerts(tmp_path):
    # End-to-end: a scenario writes the JSONL store; the triage store syncs from it.
    config = _config(tmp_path)
    run_scenario("ssh-bruteforce", config, fresh=True)
    store = TriageStore(triage_db_path(config))
    new = store.sync_from_jsonl(store_path(config))
    assert new == 1
    # Re-sync adds nothing (idempotent).
    assert store.sync_from_jsonl(store_path(config)) == 0
    assert store.list_alerts()[0]["rule_id"] == "ssh-bruteforce-001"
