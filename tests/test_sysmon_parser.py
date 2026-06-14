"""Tests for the Sysmon JSON parser."""

from __future__ import annotations

import json

from minisoc.parsers.sysmon import LOG_SOURCE, parse_record, parse_sysmon


def test_parses_process_create():
    record = {
        "EventID": 1,
        "UtcTime": "2026-06-11 19:30:01.123",
        "Computer": "WIN-DC01",
        "User": "WIN-DC01\\Administrator",
        "ProcessId": 6120,
        "Image": "C:\\Windows\\System32\\wevtutil.exe",
        "CommandLine": "wevtutil cl Security",
        "ParentImage": "C:\\Windows\\System32\\cmd.exe",
    }
    event = parse_record(record)
    assert event is not None
    assert event.event_category == "process"
    assert event.event_action == "process_create"
    assert event.process_name == "wevtutil.exe"
    assert event.process_pid == 6120
    assert event.log_source == LOG_SOURCE
    assert event.get("process.command_line") == "wevtutil cl Security"
    assert event.get("process.parent.name") == "cmd.exe"
    assert event.get("winlog.event_id") == 1
    assert event.timestamp is not None and event.timestamp.hour == 19


def test_parses_network_connection():
    record = {
        "EventID": 3,
        "UtcTime": "2026-06-11 19:30:02",
        "Computer": "WIN-DC01",
        "Image": "System",
        "Protocol": "tcp",
        "SourceIp": "198.51.100.77",
        "SourcePort": 40000,
        "DestinationIp": "10.0.0.5",
        "DestinationPort": 445,
    }
    event = parse_record(record)
    assert event is not None
    assert event.event_category == "network"
    assert event.event_action == "network_connection"
    assert event.source_ip == "198.51.100.77"
    assert event.source_port == 40000
    assert event.get("destination.port") == 445


def test_unsupported_eventid_is_skipped():
    assert parse_record({"EventID": 11, "UtcTime": "2026-06-11 19:30:02"}) is None


def test_malformed_json_lines_skipped():
    good = json.dumps({"EventID": 1, "UtcTime": "2026-06-11 19:30:01", "Image": "a.exe",
                       "CommandLine": "a.exe"})
    lines = ["{ not valid json", "", good]
    events = list(parse_sysmon(lines))
    assert len(events) == 1
    assert events[0].event_action == "process_create"
