"""Parser for Sysmon-style JSON events (one JSON object per line).

Sysmon (System Monitor) emits rich Windows endpoint telemetry. Exported to JSON-lines,
each event is one object with an ``EventID`` and event-specific fields. This parser
supports the two event types minisoc's scenarios use:

* **EventID 1 — Process Create**: ``Image``, ``CommandLine``, ``User``, ``ParentImage``…
* **EventID 3 — Network Connection**: ``SourceIp``/``SourcePort``,
  ``DestinationIp``/``DestinationPort``, ``Image``…

Both are normalized to the common :class:`~minisoc.core.event.Event`. Endpoint-specific
fields go in :attr:`Event.extra` under ECS dotted names (``process.command_line``,
``process.parent.name``, ``destination.ip``, ``destination.port``, ``winlog.event_id``).

Tolerant generator: lines that aren't valid JSON, or carry an unsupported ``EventID``,
are skipped rather than raised.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Iterator
from datetime import datetime

from minisoc.core.event import Event

__all__ = ["parse_sysmon", "parse_record", "LOG_SOURCE"]

LOG_SOURCE = "sysmon"

# Sysmon UtcTime, e.g. "2026-06-11 19:30:01.123" (sometimes without fractional secs).
_TIME_FORMATS = ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S")


def _parse_time(text: str | None) -> datetime | None:
    if not text:
        return None
    for fmt in _TIME_FORMATS:
        try:
            return datetime.strptime(text, fmt)
        except ValueError:
            continue
    return None


def _basename(path: str | None) -> str | None:
    """Return the final component of a Windows/Unix path (e.g. ``cmd.exe``)."""
    if not path:
        return None
    return re.split(r"[\\/]", path)[-1]


def parse_record(record: dict) -> Event | None:
    """Normalize a single decoded Sysmon JSON object into an :class:`Event`.

    Args:
        record: A decoded JSON object with at least an ``EventID``.

    Returns:
        A normalized :class:`Event`, or ``None`` for unsupported event types.
    """
    try:
        event_id = int(record.get("EventID"))
    except (TypeError, ValueError):
        return None

    base = dict(
        timestamp=_parse_time(record.get("UtcTime")),
        host_name=record.get("Computer"),
        user_name=record.get("User"),
        log_source=LOG_SOURCE,
        process_pid=_as_int(record.get("ProcessId")),
        raw=json.dumps(record, sort_keys=True),
    )

    if event_id == 1:  # Process Create
        image = record.get("Image")
        return Event(
            **base,
            event_category="process",
            event_action="process_create",
            event_outcome="success",
            process_name=_basename(image),
            message=record.get("CommandLine"),
            extra={
                "winlog.event_id": 1,
                "process.executable": image,
                "process.command_line": record.get("CommandLine"),
                "process.parent.name": _basename(record.get("ParentImage")),
                "process.parent.executable": record.get("ParentImage"),
                "process.parent.command_line": record.get("ParentCommandLine"),
            },
        )

    if event_id == 3:  # Network Connection
        image = record.get("Image")
        return Event(
            **base,
            event_category="network",
            event_action="network_connection",
            process_name=_basename(image),
            source_ip=record.get("SourceIp"),
            source_port=_as_int(record.get("SourcePort")),
            message=(
                f"{record.get('SourceIp')}:{record.get('SourcePort')} -> "
                f"{record.get('DestinationIp')}:{record.get('DestinationPort')}"
            ),
            extra={
                "winlog.event_id": 3,
                "process.executable": image,
                "destination.ip": record.get("DestinationIp"),
                "destination.port": _as_int(record.get("DestinationPort")),
                "network.protocol": record.get("Protocol"),
            },
        )

    return None


def _as_int(value: object) -> int | None:
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None


def parse_sysmon(lines: Iterable[str]) -> Iterator[Event]:
    """Parse an iterable of Sysmon JSON-lines into normalized events.

    Args:
        lines: Any iterable of raw JSON-line strings (e.g. an open file).

    Yields:
        Normalized :class:`Event` objects. Invalid JSON or unsupported event types are
        skipped without raising.
    """
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
            event = parse_record(record)
        except Exception:
            continue
        if event is not None:
            yield event
