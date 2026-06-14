"""Notification sinks — push alerts off the box to ntfy / a webhook.

The console and JSONL sinks (``sinks.py``) record alerts where you can go *look* at them.
These sinks come to *you*: when a high-severity detection fires, your phone buzzes. Two
ship:

* :class:`NtfySink` — POSTs to an `ntfy <https://ntfy.sh>`_ topic (self-hosted or the
  public server). Title/priority/tags map from the alert's severity.
* :class:`WebhookSink` — POSTs a Slack/Discord/Mattermost-compatible ``{"text": …}`` JSON
  body to any incoming-webhook URL.

Both filter by a ``min_severity`` so routine noise doesn't page anyone, and both are
**fail-safe**: a notifier that can't reach its server logs to stderr and never breaks the
pipeline. The HTTP call is injected (``post=``) so tests assert payloads without a network.
No new dependencies — delivery uses the standard library ``urllib``.
"""

from __future__ import annotations

import json
import sys
import urllib.parse
import urllib.request
from collections.abc import Callable
from typing import Any

from minisoc.alerting.alert import Alert
from minisoc.alerting.sinks import AlertSink

__all__ = ["NtfySink", "WebhookSink", "build_notification_sinks", "SEVERITY_RANK"]

# Only ever speak HTTP(S). A notifier URL comes from config, but refusing other schemes
# (file://, gopher://, …) keeps a typo'd or hostile URL from reaching the local filesystem
# or an unintended protocol handler via urllib.
_ALLOWED_SCHEMES = ("http", "https")


def _require_http_url(url: str) -> str:
    """Return ``url`` if it is a well-formed http(s) URL, else raise ``ValueError``."""
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in _ALLOWED_SCHEMES or not parsed.netloc:
        raise ValueError(f"notification URL must be http(s) with a host: {url!r}")
    return url


def _header_safe(value: str) -> str:
    """Strip control characters (CR/LF, etc.) so a value can't inject HTTP headers.

    Rule ids/titles can originate from imported rules; without this a crafted id could
    smuggle extra headers into an ntfy request line.
    """
    return "".join(ch for ch in value if ch.isprintable()).strip()

# Severity ordering used by the min_severity gate.
SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}
# ntfy priority (1–5) and an icon tag per severity.
_NTFY_PRIORITY = {"low": "2", "medium": "3", "high": "4", "critical": "5"}
_NTFY_TAGS = {"low": "information_source", "medium": "warning", "high": "rotating_light", "critical": "skull"}

# A transport: (url, body, headers) -> None. Default uses urllib; tests inject a fake.
PostFn = Callable[[str, bytes, dict[str, str]], None]


def _urllib_post(url: str, body: bytes, headers: dict[str, str]) -> None:
    request = urllib.request.Request(url, data=body, headers=headers, method="POST")
    urllib.request.urlopen(request, timeout=5).close()


def _summary(alert: Alert) -> str:
    """A compact human line for an alert (reused by both sinks)."""
    group = f" [{alert.group_value}]" if alert.group_value else ""
    line = f"{alert.rule_title}{group}"
    if alert.enrichment:
        bits = []
        if alert.enrichment.get("ioc"):
            bits.append("IOC")
        if alert.enrichment.get("country"):
            bits.append(str(alert.enrichment["country"]))
        if alert.enrichment.get("trusted") is False:
            bits.append("untrusted")
        if bits:
            line += " — " + " · ".join(bits)
    return line


class _ThresholdSink(AlertSink):
    """Shared min-severity gating for notification sinks."""

    def __init__(self, *, min_severity: str = "high", post: PostFn = _urllib_post) -> None:
        self._min_rank = SEVERITY_RANK.get(min_severity, 2)
        self._post = post

    def _above_threshold(self, alerts: list[Alert]) -> list[Alert]:
        return [a for a in alerts if SEVERITY_RANK.get(a.severity, 0) >= self._min_rank]

    def _send(self, url: str, body: bytes, headers: dict[str, str]) -> None:
        try:
            self._post(url, body, headers)
        except Exception as exc:  # never let a notifier break detection
            print(f"minisoc: notification failed ({type(exc).__name__}: {exc})", file=sys.stderr)


class NtfySink(_ThresholdSink):
    """Pushes qualifying alerts to an ntfy topic.

    Args:
        server: Base URL of the ntfy server (e.g. ``http://127.0.0.1:8091``).
        topic: The topic to publish to.
        min_severity: Only alerts at or above this severity are sent.
        post: HTTP transport (injectable for tests).
    """

    def __init__(self, server: str, topic: str, *, min_severity: str = "high", post: PostFn = _urllib_post) -> None:
        super().__init__(min_severity=min_severity, post=post)
        self._url = _require_http_url(f"{server.rstrip('/')}/{topic}")

    def emit(self, alerts: list[Alert]) -> None:
        for alert in self._above_threshold(alerts):
            headers = {
                "Title": _header_safe(f"[{alert.severity.upper()}] {alert.rule_id}"),
                "Priority": _NTFY_PRIORITY.get(alert.severity, "3"),
                "Tags": _NTFY_TAGS.get(alert.severity, "warning"),
            }
            self._send(self._url, _summary(alert).encode("utf-8"), headers)


class WebhookSink(_ThresholdSink):
    """Pushes qualifying alerts to a Slack/Discord-style incoming webhook.

    Args:
        url: The incoming-webhook URL.
        min_severity: Only alerts at or above this severity are sent.
        post: HTTP transport (injectable for tests).
    """

    def __init__(self, url: str, *, min_severity: str = "critical", post: PostFn = _urllib_post) -> None:
        super().__init__(min_severity=min_severity, post=post)
        self._url = _require_http_url(url)

    def emit(self, alerts: list[Alert]) -> None:
        for alert in self._above_threshold(alerts):
            text = f":rotating_light: *{alert.severity.upper()}* {_summary(alert)}"
            body = json.dumps({"text": text}).encode("utf-8")
            self._send(self._url, body, {"Content-Type": "application/json"})


def build_notification_sinks(config, *, post: PostFn = _urllib_post) -> list[AlertSink]:
    """Build the notification sinks enabled in the ``notifications:`` config section.

    A sink is created only when its destination is configured (ntfy needs a ``topic``, the
    webhook needs a ``url``). Returns an empty list when nothing is configured.
    """
    section: dict[str, Any] = getattr(config, "notifications", {}) or {}
    sinks: list[AlertSink] = []

    def _add(make: Callable[[], AlertSink]) -> None:
        # A misconfigured destination (e.g. a non-http URL) must not break startup —
        # warn and skip the sink, consistent with the sinks' fail-safe delivery.
        try:
            sinks.append(make())
        except ValueError as exc:
            print(f"minisoc: skipping notification sink ({exc})", file=sys.stderr)

    ntfy = section.get("ntfy") or {}
    if ntfy.get("topic"):
        _add(lambda: NtfySink(
            ntfy.get("server", "https://ntfy.sh"),
            ntfy["topic"],
            min_severity=ntfy.get("min_severity", "high"),
            post=post,
        ))

    webhook = section.get("webhook") or {}
    if webhook.get("url"):
        _add(lambda: WebhookSink(
            webhook["url"], min_severity=webhook.get("min_severity", "critical"), post=post
        ))

    return sinks
