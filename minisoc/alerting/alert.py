"""The Alert model produced by the detection engine.

Phase 0 keeps this a plain data holder plus a stable dedup key. Dedup windows and
output sinks (JSONL, dashboard) are layered on in a later phase.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from minisoc.core.event import Event

__all__ = ["Alert"]


@dataclass
class Alert:
    """A fired detection.

    Attributes:
        rule_id: Id of the rule that fired.
        rule_title: Human-readable rule title.
        severity: ``low``/``medium``/``high``/``critical``.
        timestamp: Detection time — the timestamp of the latest matched event.
        events: The event(s) that triggered the alert (evidence for triage).
        source: The ``log.source`` the events came from.
        group_value: For aggregation rules, the grouping value (e.g. the source IP
            that exceeded the brute-force threshold); ``None`` for per-event rules.
        description: Copied from the rule, for context in output.
        occurrences: How many times this alert fired within the dedup window. Set by the
            :class:`~minisoc.alerting.dedup.Deduplicator`; a kept alert that absorbed
            duplicates reports >1.
        last_seen: Timestamp of the most recent occurrence (== ``timestamp`` until dedup
            merges later duplicates into this one).
        mode: Where the triggering logs came from — ``"simulation"`` (scenario
            generators, the training side), ``"replay"`` (recorded datasets fed through
            ``minisoc replay``), or ``"live"`` (real logs tailed by ``minisoc watch``).
            The dashboard uses this to separate the training side from the live side.
        enrichment: Compact context folded on by the enrichment layer — e.g.
            ``{"ioc": "local-blocklist", "country": "RU", "trusted": False,
            "role": "admin"}``. Populated by
            :meth:`~minisoc.enrichment.enricher.Enricher.enrich_alert`; empty when no
            enrichment applied.
    """

    rule_id: str
    rule_title: str
    severity: str
    timestamp: datetime | None = None
    events: list[Event] = field(default_factory=list)
    source: str | None = None
    group_value: Any = None
    description: str = ""
    occurrences: int = 1
    last_seen: datetime | None = None
    mode: str = "simulation"
    enrichment: dict[str, Any] = field(default_factory=dict)
    risk: dict[str, Any] = field(default_factory=dict)

    @property
    def dedup_key(self) -> tuple[str, Any]:
        """A stable key for deduplicating repeated alerts.

        Keyed by ``(rule_id, discriminator)`` where the discriminator is the rule's
        grouping value when present, otherwise the source IP of the triggering event.
        This means repeated per-event alerts from the *same* attacker collapse together,
        while distinct attackers stay separate.
        """
        discriminator = self.group_value
        if discriminator is None and self.events:
            discriminator = self.events[0].source_ip
        return (self.rule_id, discriminator)

    @property
    def match_count(self) -> int:
        """Number of events backing this alert."""
        return len(self.events)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-friendly dict (used by JSONL/dashboard sinks)."""
        return {
            "rule_id": self.rule_id,
            "rule_title": self.rule_title,
            "severity": self.severity,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "source": self.source,
            "group_value": self.group_value,
            "mode": self.mode,
            "occurrences": self.occurrences,
            "match_count": self.match_count,
            "description": self.description,
            "enrichment": self.enrichment,
            "risk": self.risk,
            "events": [e.to_ecs_dict() for e in self.events],
        }
