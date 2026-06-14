"""Tests for the dashboard's pure logic functions and app wiring.

The HTTP layer is a thin shell over plain functions (``load_alerts``, ``compute_stats``,
``list_scenarios``, ``trigger_scenario``), so we test those directly — no HTTP client is
needed (and ``httpx``/``TestClient`` are intentionally not dependencies). We also assert the
FastAPI app exposes the expected routes and that the static page exists.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from minisoc.core.pipeline import Pipeline
from minisoc.dashboard import app as dash
from minisoc.scenarios.registry import scenario_names, store_path
from tests.util import make_config as _config


def test_list_scenarios_matches_registry():
    scenarios = dash.list_scenarios()
    names = [s["name"] for s in scenarios]
    assert names == scenario_names()
    # Each entry carries its log source.
    assert all(s["source"] for s in scenarios)


def test_compute_stats_orders_severity_and_counts_sources():
    alerts = [
        {"severity": "medium", "source": "access.log", "mode": "live"},
        {"severity": "critical", "source": "auth.log"},
        {"severity": "high", "source": "auth.log", "mode": "replay"},
        {"severity": "high", "source": "sysmon", "mode": "simulation"},
    ]
    stats = dash.compute_stats(alerts)
    assert stats["total"] == 4
    # by_severity is ordered most-to-least severe.
    assert list(stats["by_severity"].keys()) == ["critical", "high", "medium"]
    assert stats["by_severity"]["high"] == 2
    # by_source counts every source.
    assert stats["by_source"]["auth.log"] == 2
    # by_mode separates the sides; a record without a mode counts as simulation.
    assert stats["by_mode"] == {"simulation": 2, "live": 1, "replay": 1}


def test_compute_stats_empty():
    stats = dash.compute_stats([])
    assert stats == {"total": 0, "by_severity": {}, "by_source": {}, "by_mode": {}}


def test_load_alerts_newest_first(tmp_path):
    config = _config(tmp_path)
    pipeline = Pipeline(config)
    # Two scenarios -> two alerts appended in order.
    dash.trigger_scenario("ssh-bruteforce", config, fresh=True, pipeline=pipeline)
    dash.trigger_scenario("port-scan", config, fresh=False, pipeline=pipeline)

    alerts = dash.load_alerts(config)
    assert len(alerts) == 2
    # Newest (port-scan) is first.
    assert alerts[0]["rule_id"] == "port-scan-001"
    assert alerts[1]["rule_id"] == "ssh-bruteforce-001"
    # Scenario-run alerts belong to the training side.
    assert all(a["mode"] == "simulation" for a in alerts)


def test_trigger_scenario_returns_summary_and_stores(tmp_path):
    config = _config(tmp_path)
    pipeline = Pipeline(config)
    summary = dash.trigger_scenario("ssh-bruteforce", config, fresh=True, pipeline=pipeline)
    assert summary["scenario"] == "ssh-bruteforce"
    assert summary["source"] == "auth.log"
    assert summary["deduped_count"] == 1
    assert summary["alerts"][0]["rule_id"] == "ssh-bruteforce-001"
    # It persisted to the store.
    from minisoc.alerting.sinks import read_jsonl

    assert len(read_jsonl(store_path(config))) == 1


def test_coverage_summary_rolls_up_techniques(tmp_path):
    config = _config(tmp_path)
    pipeline = Pipeline(config)
    rollup = dash.coverage_summary(pipeline)
    techniques = {t["technique"] for t in rollup["techniques"]}
    # The SSH brute-force rule is tagged T1110.
    assert "T1110" in techniques


def test_create_app_exposes_expected_routes(tmp_path):
    config = _config(tmp_path)
    app = dash.create_app(config)
    paths = {route.path for route in app.routes}
    for expected in (
        "/", "/api/scenarios", "/api/alerts", "/api/stats", "/api/coverage", "/api/run",
        "/api/metrics", "/api/coverage/navigator", "/api/pivot", "/api/triage/alerts/{uid}",
        "/api/risk",
    ):
        assert expected in paths


def test_risk_board_ranks_entities_and_flags_threshold_crossings(tmp_path):
    config = _config(tmp_path, risk={"enabled": True, "threshold": 100, "window": "24h"})
    pipeline = Pipeline(config)
    records = [
        {"rule_id": "scan", "severity": "medium", "group_value": "9.9.9.9",
         "timestamp": "2026-06-12T10:00:00", "events": [{"source": {"ip": "9.9.9.9"}}]},
        {"rule_id": "brute", "severity": "high", "group_value": "9.9.9.9",
         "timestamp": "2026-06-12T10:01:00", "events": [{"source": {"ip": "9.9.9.9"}}]},
        {"rule_id": "ok", "severity": "low", "group_value": "1.1.1.1",
         "timestamp": "2026-06-12T10:00:00", "events": [{"source": {"ip": "1.1.1.1"}}]},
    ]
    board = dash.risk_board(records, pipeline)
    assert board["enabled"] and board["threshold"] == 100
    top = board["entities"][0]
    assert top["value"] == "9.9.9.9" and top["score"] == 90 and top["over_threshold"] is False
    # Risk notables themselves are excluded from the board.
    records.append({"rule_id": "risk-notable", "severity": "critical", "group_value": "9.9.9.9",
                    "timestamp": "2026-06-12T10:02:00", "events": []})
    assert all(r["value"] != "risk-notable" for r in dash.risk_board(records, pipeline)["entities"])


def test_risk_board_empty_when_risk_disabled(tmp_path):
    pipeline = Pipeline(_config(tmp_path))  # risk off
    board = dash.risk_board([], pipeline)
    assert board == {"enabled": False, "threshold": None, "entities": []}


def test_dashboard_auth_guard_enforced_when_configured(tmp_path):
    from fastapi import HTTPException
    from fastapi.security import HTTPBasicCredentials

    config = _config(tmp_path, dashboard={"auth": {"user": "analyst", "password": "s3cret"}})
    guard = dash._build_auth_guard(config)
    for bad in (None, HTTPBasicCredentials(username="analyst", password="wrong"),
                HTTPBasicCredentials(username="x", password="s3cret")):
        with pytest.raises(HTTPException) as exc:
            guard(bad)
        assert exc.value.status_code == 401
    # Correct credentials pass (no exception).
    assert guard(HTTPBasicCredentials(username="analyst", password="s3cret")) is None


def test_dashboard_auth_guard_is_noop_when_unconfigured(tmp_path):
    guard = dash._build_auth_guard(_config(tmp_path))
    assert guard(None) is None   # open dashboard, any/no credentials accepted


def test_compute_metrics_buckets_volume_and_ranks_source_ips():
    alerts = [
        {"timestamp": "2026-06-12T10:00:00", "severity": "medium", "group_value": "45.155.205.7",
         "events": [{"source": {"ip": "45.155.205.7"}}]},
        {"timestamp": "2026-06-12T11:00:00", "severity": "high", "group_value": "alice",
         "events": [{"source": {"ip": "203.0.113.9"}}]},
        {"timestamp": "2026-06-11T09:00:00", "severity": "medium", "group_value": "45.155.205.7",
         "events": [{"source": {"ip": "45.155.205.7"}}]},
    ]
    m = dash.compute_metrics(alerts, {"mttr_seconds": 312.0, "false_positive_rate": 0.25, "resolved": 4})
    # Two day buckets, chronological.
    assert m["volume"] == [
        {"bucket": "2026-06-11", "count": 1},
        {"bucket": "2026-06-12", "count": 2},
    ]
    # The scanner IP leads; a non-IP group value falls back to the event's source.ip.
    assert m["top_sources"][0] == {"ip": "45.155.205.7", "count": 2}
    assert {"ip": "203.0.113.9", "count": 1} in m["top_sources"]
    # Triage KPIs are passed through.
    assert m["mttr_seconds"] == 312.0
    assert m["false_positive_rate"] == 0.25


def test_compute_metrics_empty_is_safe():
    m = dash.compute_metrics([], None)
    assert m["volume"] == [] and m["top_sources"] == []
    assert m["mttr_seconds"] is None and m["resolved"] == 0


def test_triage_metrics_compute_mttr_and_fp_rate(tmp_path):
    from minisoc.triage import TriageStore

    store = TriageStore(":memory:")
    store.ingest_record({"rule_id": "r1", "group_value": "1.2.3.4",
                         "timestamp": "2026-06-12T10:00:00", "mode": "live"})
    store.ingest_record({"rule_id": "r2", "group_value": "5.6.7.8",
                         "timestamp": "2026-06-12T10:05:00", "mode": "live"})
    uids = [a["uid"] for a in store.list_alerts()]
    store.set_status(uids[0], "closed_true_positive")
    store.set_status(uids[1], "closed_false_positive")
    metrics = store.metrics()
    assert metrics["resolved"] == 2
    assert metrics["closed_true_positive"] == 1
    assert metrics["false_positive_rate"] == 0.5
    assert metrics["mttr_seconds"] is not None and metrics["mttr_seconds"] >= 0


def test_alert_pivots_extracts_distinct_entities():
    alert = {
        "group_value": "45.155.205.7",
        "data": {"events": [
            {"source": {"ip": "45.155.205.7"}, "user": {"name": "root"},
             "destination": {"ip": "10.0.0.5"}},
            {"source": {"ip": "45.155.205.7"}, "user": {"name": "alice"}},
        ]},
    }
    pivots = dash.alert_pivots(alert)
    pairs = {(p["field"], p["value"]) for p in pivots}
    assert ("source.ip", "45.155.205.7") in pairs
    assert ("user.name", "root") in pairs
    assert ("user.name", "alice") in pairs
    assert ("destination.ip", "10.0.0.5") in pairs
    # Distinct: the repeated source IP appears once.
    assert sum(1 for p in pivots if p == {"field": "source.ip", "value": "45.155.205.7"}) == 1


def test_store_pivot_finds_alerts_sharing_an_entity(tmp_path):
    from minisoc.triage import TriageStore

    store = TriageStore(":memory:")
    store.ingest_record({
        "rule_id": "port-scan-001", "group_value": "45.155.205.7",
        "timestamp": "2026-06-12T10:00:00", "mode": "live",
        "events": [{"source": {"ip": "45.155.205.7"}}],
    })
    store.ingest_record({
        "rule_id": "ssh-bruteforce-001", "group_value": "45.155.205.7",
        "timestamp": "2026-06-12T10:02:00", "mode": "live",
        "events": [{"source": {"ip": "45.155.205.7"}, "user": {"name": "root"}}],
    })
    store.ingest_record({
        "rule_id": "web-shell-001", "group_value": "10.0.0.9",
        "timestamp": "2026-06-12T10:03:00", "mode": "live",
        "events": [{"source": {"ip": "10.0.0.9"}}],
    })
    matched = store.pivot("source.ip", "45.155.205.7")
    rule_ids = {m["rule_id"] for m in matched}
    assert rule_ids == {"port-scan-001", "ssh-bruteforce-001"}
    # Pivoting on a username only hits the alert whose evidence carries it.
    assert {m["rule_id"] for m in store.pivot("user.name", "root")} == {"ssh-bruteforce-001"}


def test_navigator_layer_scores_covered_techniques(tmp_path):
    pipeline = Pipeline(_config(tmp_path))
    layer = dash.navigator_layer(pipeline)
    assert layer["domain"] == "enterprise-attack"
    ids = {t["techniqueID"] for t in layer["techniques"]}
    assert "T1110" in ids  # the SSH brute-force technique
    for t in layer["techniques"]:
        assert t["score"] >= 1 and t["comment"]


def test_static_index_page_exists():
    # The `/` route serves this file; if it is missing, `minisoc serve` would 404 at runtime.
    index = Path(dash.__file__).parent / "static" / "index.html"
    assert index.is_file()
    assert "minisoc" in index.read_text(encoding="utf-8")
