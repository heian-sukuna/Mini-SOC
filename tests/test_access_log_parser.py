"""Tests for the nginx/apache combined access log parser."""

from __future__ import annotations

from minisoc.parsers.access_log import LOG_SOURCE, parse_access_log, parse_line


def test_parses_combined_line():
    line = (
        '192.0.2.10 - alice [11/Jun/2026:19:30:01 +0000] '
        '"GET /index.html HTTP/1.1" 200 1234 "http://ex.com/" "Mozilla/5.0"'
    )
    event = parse_line(line)
    assert event is not None
    assert event.event_category == "web"
    assert event.event_action == "http_request"
    assert event.event_outcome == "success"
    assert event.source_ip == "192.0.2.10"
    assert event.user_name == "alice"
    assert event.log_source == LOG_SOURCE
    assert event.get("http.request.method") == "GET"
    assert event.get("url.original") == "/index.html"
    assert event.get("http.response.status_code") == 200
    assert event.get("user_agent.original") == "Mozilla/5.0"


def test_timestamp_parsed():
    line = '192.0.2.10 - - [11/Jun/2026:19:30:01 +0000] "GET / HTTP/1.1" 200 1 "-" "-"'
    event = parse_line(line)
    assert event is not None
    assert event.timestamp is not None
    assert (event.timestamp.year, event.timestamp.month, event.timestamp.day) == (2026, 6, 11)
    assert event.timestamp.hour == 19


def test_dash_user_becomes_none_and_4xx_is_failure():
    line = '192.0.2.10 - - [11/Jun/2026:19:30:01 +0000] "GET /missing HTTP/1.1" 404 153 "-" "curl/8"'
    event = parse_line(line)
    assert event is not None
    assert event.user_name is None
    assert event.event_outcome == "failure"
    assert event.get("http.response.status_code") == 404


def test_malformed_lines_skipped():
    lines = [
        "not an access log line",
        "",
        '192.0.2.10 - - [11/Jun/2026:19:30:01 +0000] "GET /ok HTTP/1.1" 200 10 "-" "-"',
    ]
    events = list(parse_access_log(lines))
    assert len(events) == 1
    assert events[0].get("url.original") == "/ok"
