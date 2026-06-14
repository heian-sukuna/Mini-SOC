"""The normalized event schema shared by every parser and consumed by every detection.

Design goal
-----------
Every log source in minisoc is parsed into a single, common :class:`Event` shape so
that detection rules are *source-agnostic* — a rule matches on field names, not on the
quirks of a particular log format.

ECS alignment
-------------
The schema is loosely aligned to the **Elastic Common Schema (ECS)**. ECS names fields
with dotted, nested paths (``source.ip``, ``event.action``, ``user.name``). Python
attributes cannot contain dots, so each ECS field is stored as a flat snake_case
attribute and mapped back to its canonical dotted name via :data:`ECS_FIELD_MAP`.

Detection rules reference the **dotted ECS names** (just like real Sigma rules), and the
engine resolves them through :meth:`Event.get`. This keeps our YAML rules readable and
close to upstream Sigma/ECS conventions while the in-memory representation stays a plain
dataclass.

Only a practical subset of ECS is implemented — enough for the log sources minisoc
supports. Source-specific fields that do not have a first-class attribute live in
:attr:`Event.extra` and are still addressable by dotted key (e.g. ``"sudo.command"``).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

__all__ = ["Event", "ECS_FIELD_MAP"]


# Canonical ECS dotted field name -> Event attribute name.
# This is the single source of truth for how rules address event fields.
ECS_FIELD_MAP: dict[str, str] = {
    "@timestamp": "timestamp",
    "event.category": "event_category",
    "event.action": "event_action",
    "event.outcome": "event_outcome",
    "source.ip": "source_ip",
    "source.port": "source_port",
    "user.name": "user_name",
    "host.name": "host_name",
    "process.name": "process_name",
    "process.pid": "process_pid",
    "log.source": "log_source",
    "message": "message",
    "raw": "raw",
}


@dataclass
class Event:
    """A single normalized log event, loosely aligned to ECS.

    Attributes map to ECS fields per :data:`ECS_FIELD_MAP`. All fields are optional
    because no single log line populates every field; parsers fill what they can.

    Attributes:
        timestamp: Event time (ECS ``@timestamp``).
        event_category: High-level category, e.g. ``"authentication"`` (ECS
            ``event.category``).
        event_action: Normalized action, e.g. ``"ssh_login_failed"`` (ECS
            ``event.action``). This is the primary field most rules match on.
        event_outcome: ``"success"`` / ``"failure"`` (ECS ``event.outcome``).
        source_ip: Originating IP address (ECS ``source.ip``).
        source_port: Originating port (ECS ``source.port``).
        user_name: Account name referenced by the event (ECS ``user.name``).
        host_name: Host that produced the log (ECS ``host.name``).
        process_name: Producing process, e.g. ``"sshd"`` (ECS ``process.name``).
        process_pid: Producing process id (ECS ``process.pid``).
        log_source: Tag identifying the originating log, e.g. ``"auth.log"`` (ECS
            ``log.source``). Used by rule ``logsource`` matching.
        message: Human-readable summary of the event.
        raw: The original, unparsed log line — always preserved for triage.
        extra: Source-specific fields with no first-class attribute. Keys are dotted
            ECS-style paths (e.g. ``"sudo.command"``) and are resolvable via
            :meth:`get`.
    """

    timestamp: datetime | None = None
    event_category: str | None = None
    event_action: str | None = None
    event_outcome: str | None = None
    source_ip: str | None = None
    source_port: int | None = None
    user_name: str | None = None
    host_name: str | None = None
    process_name: str | None = None
    process_pid: int | None = None
    log_source: str | None = None
    message: str | None = None
    raw: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    def get(self, ecs_field: str) -> Any:
        """Resolve a value by its canonical ECS dotted field name.

        This is the lookup detections use. Resolution order:

        1. A first-class attribute mapped in :data:`ECS_FIELD_MAP`.
        2. A dotted key inside :attr:`extra` (exact match).

        Args:
            ecs_field: Dotted ECS field name, e.g. ``"source.ip"`` or
                ``"sudo.command"``.

        Returns:
            The field value, or ``None`` if the field is absent.
        """
        attr = ECS_FIELD_MAP.get(ecs_field)
        if attr is not None:
            return getattr(self, attr)
        return self.extra.get(ecs_field)

    def to_ecs_dict(self) -> dict[str, Any]:
        """Render the event as a nested ECS dict (dotted paths expanded).

        Useful for JSONL output and the dashboard. ``None`` values are omitted.
        :attr:`extra` keys are merged in using their dotted paths.

        Returns:
            A nested dict, e.g. ``{"source": {"ip": "10.0.0.5"}, "event": {...}}``.
        """
        flat: dict[str, Any] = {}
        for ecs_field, attr in ECS_FIELD_MAP.items():
            value = getattr(self, attr)
            if value is None:
                continue
            flat[ecs_field] = value.isoformat() if isinstance(value, datetime) else value
        for key, value in self.extra.items():
            if value is not None:
                flat[key] = value

        nested: dict[str, Any] = {}
        for dotted, value in flat.items():
            parts = dotted.lstrip("@").split(".") if dotted != "@timestamp" else ["@timestamp"]
            cursor = nested
            for part in parts[:-1]:
                cursor = cursor.setdefault(part, {})
            cursor[parts[-1]] = value
        return nested
