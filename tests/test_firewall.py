"""Tests for the firewall (UFW/netfilter) network log source — Phase 9.

Every parser carries a matching-event test and a non-matching-event test (proving no
false positives), plus an end-to-end check that the real network source fires
``port-scan-001`` and that the alert inherits Phase 5 enrichment.
"""

from __future__ import annotations

from datetime import datetime

from minisoc.core.config import load_config
from minisoc.core.pipeline import Pipeline
from minisoc.core.replay import detect_source
from minisoc.parsers.firewall import parse_firewall, parse_line
from minisoc.scenarios import network_attacks
from tests.util import make_config as _config

_BLOCK = (
    "Jun 12 10:00:01 gw01 kernel: [123.456] [UFW BLOCK] IN=eth0 OUT= "
    "SRC=45.155.205.7 DST=10.0.0.5 LEN=60 TTL=54 PROTO=TCP SPT=44321 DPT=22 SYN"
)
_ALLOW = (
    "Jun 12 10:00:02 gw01 kernel: [123.460] [UFW ALLOW] IN=eth0 OUT= "
    "SRC=10.0.0.20 DST=10.0.0.5 PROTO=TCP SPT=51000 DPT=443 SYN"
)


def test_parses_a_blocked_connection():
    event = parse_line(_BLOCK, year=2026)
    assert event is not None
    assert event.event_category == "network"
    assert event.event_action == "network_connection"
    assert event.event_outcome == "failure"
    assert event.source_ip == "45.155.205.7"
    assert event.source_port == 44321
    assert event.get("destination.ip") == "10.0.0.5"
    assert event.get("destination.port") == 22
    assert event.get("firewall.action") == "blocked"
    assert event.get("network.protocol") == "TCP"
    assert event.timestamp == datetime(2026, 6, 12, 10, 0, 1)


def test_allow_verdict_is_a_success_outcome():
    event = parse_line(_ALLOW, year=2026)
    assert event is not None
    assert event.event_outcome == "success"
    assert event.get("firewall.action") == "allowed"


def test_non_netfilter_line_is_skipped_not_raised():
    # A plain kernel message with no SRC= connection record must not yield an event.
    noise = "Jun 12 10:00:03 gw01 kernel: [123.999] usb 1-1: new high-speed USB device"
    assert parse_line(noise) is None
    assert list(parse_firewall([noise, "", "garbage"])) == []


def test_detect_source_recognizes_firewall_logs(tmp_path):
    path = tmp_path / "ufw.log"
    path.write_text(_BLOCK + "\n")
    assert detect_source(path) == "firewall"


def test_scenario_fires_port_scan_with_enrichment():
    lines = list(network_attacks.generate_port_scan(start=datetime(2026, 6, 12, 10, 0, 0)))
    events = list(parse_firewall(lines))
    # 1 benign ALLOW + 20 blocked scan probes.
    assert len(events) == 21
    alerts = Pipeline(load_config()).run_events(events)
    scan = [a for a in alerts if a.rule_id == "port-scan-001"]
    assert len(scan) == 1
    assert scan[0].group_value == "45.155.205.7"
    # The network alert inherits threat-intel + GeoIP context from Phase 5.
    assert scan[0].enrichment.get("ioc") == "local-blocklist"
    assert scan[0].enrichment.get("country") == "RU"


def test_benign_traffic_alone_does_not_alert(tmp_path):
    # A handful of allowed connections from a trusted host must not trip the scan rule.
    benign = [_ALLOW] * 5
    events = list(parse_firewall(benign))
    assert Pipeline(_config(tmp_path)).run_events(events) == []
