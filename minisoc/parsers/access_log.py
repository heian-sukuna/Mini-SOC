"""Parser for nginx/apache **combined** access logs.

The combined log format is::

    %h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-Agent}i"

e.g.::

    192.0.2.10 - alice [11/Jun/2026:19:30:01 +0000] "GET /index.html HTTP/1.1" 200 1234 "http://ex.com/" "Mozilla/5.0"

Emits normalized :class:`~minisoc.core.event.Event` objects with
``event.category = "web"`` and ``event.action = "http_request"``. HTTP-specific fields
that have no first-class :class:`Event` attribute are placed in :attr:`Event.extra` under
their ECS dotted names (``url.original``, ``http.request.method``,
``http.response.status_code``, ``user_agent.original``, …) so detection rules can address
them.

Like every parser, this is a tolerant generator: malformed lines are skipped, never
raised.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Iterator
from datetime import datetime

from minisoc.core.event import Event

__all__ = ["parse_access_log", "parse_line", "LOG_SOURCE"]

LOG_SOURCE = "access.log"
_CATEGORY = "web"

_COMBINED_RE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+(?P<user>\S+)\s+'
    r'\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<request>[^"]*)"\s+'
    r'(?P<status>\d{3}|-)\s+'
    r'(?P<size>\d+|-)'
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<ua>[^"]*)")?'
)

# Apache/nginx timestamp, e.g. "11/Jun/2026:19:30:01 +0000".
_TIME_FORMAT = "%d/%b/%Y:%H:%M:%S %z"


def _parse_time(text: str) -> datetime | None:
    try:
        return datetime.strptime(text, _TIME_FORMAT)
    except ValueError:
        return None


def parse_line(line: str) -> Event | None:
    """Parse a single combined-format access log line into an :class:`Event`.

    Args:
        line: One raw access log line.

    Returns:
        A normalized :class:`Event`, or ``None`` if the line is not a valid combined
        log entry.
    """
    line = line.rstrip("\n")
    if not line.strip():
        return None

    match = _COMBINED_RE.match(line)
    if not match:
        return None

    # The request line is "METHOD URL PROTOCOL". A raw URL may itself contain spaces
    # (e.g. unencoded injection payloads), so split off the method (first token) and the
    # protocol (trailing "HTTP/x" token) and treat everything in between as the URL.
    method = path = protocol = None
    request = match["request"]
    parts = request.split(" ")
    if len(parts) >= 2:
        method = parts[0]
        if len(parts) >= 3 and parts[-1].startswith("HTTP/"):
            protocol = parts[-1]
            path = " ".join(parts[1:-1])
        else:
            path = " ".join(parts[1:])

    status = int(match["status"]) if match["status"].isdigit() else None
    size = int(match["size"]) if match["size"].isdigit() else None
    user = match["user"] if match["user"] != "-" else None

    extra: dict[str, object] = {}
    if method is not None:
        extra["http.request.method"] = method
    if path is not None:
        extra["url.original"] = path
    if protocol is not None:
        extra["http.version"] = protocol
    if status is not None:
        extra["http.response.status_code"] = status
    if size is not None:
        extra["http.response.bytes"] = size
    if match["referer"]:
        extra["http.request.referrer"] = match["referer"]
    if match["ua"]:
        extra["user_agent.original"] = match["ua"]

    outcome = None
    if status is not None:
        outcome = "failure" if status >= 400 else "success"

    return Event(
        timestamp=_parse_time(match["time"]),
        event_category=_CATEGORY,
        event_action="http_request",
        event_outcome=outcome,
        source_ip=match["ip"],
        user_name=user,
        log_source=LOG_SOURCE,
        message=request,
        raw=line,
        extra=extra,
    )


def parse_access_log(lines: Iterable[str]) -> Iterator[Event]:
    """Parse an iterable of combined access log lines into normalized events.

    Args:
        lines: Any iterable of raw log lines (e.g. an open file).

    Yields:
        Normalized :class:`Event` objects, one per valid line. Malformed lines are
        skipped without raising.
    """
    for line in lines:
        try:
            event = parse_line(line)
        except Exception:
            continue
        if event is not None:
            yield event
