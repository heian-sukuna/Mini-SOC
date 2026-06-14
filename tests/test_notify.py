"""Tests for notification sinks (ntfy + webhook), using an injected fake transport."""

from __future__ import annotations

import json

import pytest

from minisoc.alerting.alert import Alert
from minisoc.alerting.notify import NtfySink, WebhookSink, build_notification_sinks
from minisoc.core.config import Config


def _alert(severity, rule_id="ssh-bruteforce-001", group="45.155.205.7", enrichment=None):
    return Alert(
        rule_id=rule_id, rule_title="SSH Brute Force", severity=severity,
        group_value=group, enrichment=enrichment or {},
    )


class _Capture:
    """A fake POST transport that records every call."""

    def __init__(self):
        self.calls = []

    def __call__(self, url, body, headers):
        self.calls.append({"url": url, "body": body.decode("utf-8"), "headers": headers})


def test_ntfy_sends_above_threshold_only():
    cap = _Capture()
    sink = NtfySink("http://127.0.0.1:8091", "minisoc-alerts", min_severity="high", post=cap)
    sink.emit([_alert("low"), _alert("medium"), _alert("high"), _alert("critical")])
    assert len(cap.calls) == 2                                  # high + critical only
    assert cap.calls[0]["url"] == "http://127.0.0.1:8091/minisoc-alerts"
    assert cap.calls[0]["headers"]["Title"].startswith("[HIGH]")
    assert cap.calls[1]["headers"]["Priority"] == "5"           # critical -> urgent


def test_ntfy_body_includes_enrichment():
    cap = _Capture()
    sink = NtfySink("http://h", "t", min_severity="high", post=cap)
    sink.emit([_alert("critical", enrichment={"ioc": "local-blocklist", "country": "RU", "trusted": False})])
    body = cap.calls[0]["body"]
    assert "SSH Brute Force" in body and "IOC" in body and "RU" in body and "untrusted" in body


def test_webhook_sends_slack_style_json():
    cap = _Capture()
    sink = WebhookSink("https://hooks.example/abc", min_severity="critical", post=cap)
    sink.emit([_alert("high"), _alert("critical")])
    assert len(cap.calls) == 1                                  # critical only
    payload = json.loads(cap.calls[0]["body"])
    assert "text" in payload and "CRITICAL" in payload["text"]


def test_notifier_never_raises_on_transport_error(capsys):
    def boom(url, body, headers):
        raise ConnectionError("down")

    NtfySink("http://h", "t", min_severity="low", post=boom).emit([_alert("critical")])
    # The failure is logged to stderr, not raised.
    assert "notification failed" in capsys.readouterr().err


def test_build_from_config_activates_only_configured_channels():
    cap = _Capture()
    config = Config(notifications={
        "ntfy": {"server": "http://127.0.0.1:8091", "topic": "minisoc-alerts", "min_severity": "high"},
        "webhook": {"url": "", "min_severity": "critical"},   # empty url -> not built
    })
    sinks = build_notification_sinks(config, post=cap)
    assert len(sinks) == 1                                      # only ntfy (webhook url empty)


def test_build_from_config_empty_when_unconfigured():
    assert build_notification_sinks(Config(), post=lambda *a: None) == []


# -- security hardening ------------------------------------------------------------------


@pytest.mark.parametrize("url", ["file:///etc/passwd", "gopher://x/1", "ftp://h/p", "/no/scheme"])
def test_non_http_webhook_url_is_rejected(url):
    with pytest.raises(ValueError):
        WebhookSink(url)


def test_non_http_ntfy_server_is_rejected():
    with pytest.raises(ValueError):
        NtfySink("file:///etc", "topic")


def test_build_skips_bad_url_but_keeps_valid_sink(capsys):
    config = Config(notifications={
        "ntfy": {"server": "http://127.0.0.1:8091", "topic": "alerts"},
        "webhook": {"url": "file:///etc/passwd"},   # bad scheme -> skipped, not raised
    })
    sinks = build_notification_sinks(config, post=lambda *a: None)
    assert [type(s).__name__ for s in sinks] == ["NtfySink"]
    assert "skipping notification sink" in capsys.readouterr().err


def test_ntfy_title_header_cannot_carry_crlf():
    cap = _Capture()
    # A rule id with CR/LF (e.g. from an imported rule) must not survive into the header.
    NtfySink("http://h", "t", min_severity="low", post=cap).emit(
        [_alert("critical", rule_id="evil\r\nX-Inject: pwned")]
    )
    title = cap.calls[0]["headers"]["Title"]
    assert "\r" not in title and "\n" not in title
