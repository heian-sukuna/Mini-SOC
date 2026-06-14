"""Behavioral detections that need enriched context, not just a single log line.

The Sigma engine matches fields on events; correlations chain *rule firings*. Some
detections need neither — they reason over a *sequence* of enriched events. Impossible
travel is the canonical one: the same user authenticating successfully from two different
countries within a span too short to have physically travelled between them. It only works
because the GeoIP enricher has stamped ``source.geo.country_iso_code`` onto each event.

A :class:`BehavioralDetector` carries the same ``id``/``title``/``level``/``tags`` surface
as a :class:`~minisoc.detections.rule.Rule`, so it shows up in MITRE ATT&CK coverage, and
exposes a ``timespan`` so live mode can size its buffer. The pipeline runs registered
detectors over the enriched event list alongside the rule engine.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field

from minisoc.alerting.alert import Alert
from minisoc.core.config import parse_window_seconds
from minisoc.core.event import Event

__all__ = ["BehavioralDetector", "impossible_travel", "default_detectors"]

_COUNTRY = "source.geo.country_iso_code"


def impossible_travel(
    events: list[Event], *, timespan_seconds: int, level: str, rule_id: str, title: str, description: str
) -> list[Alert]:
    """Detect a user authenticating from two countries within ``timespan_seconds``.

    Considers only successful authentications carrying a resolved country (private/LAN
    logins have none and are ignored). Groups by user, sweeps time-ordered events, and
    fires the first time two consecutive in-window logins disagree on country — evidence
    being both logins. One alert per user.
    """
    by_user: dict[str, list[Event]] = defaultdict(list)
    for event in events:
        if event.event_outcome != "success" or not event.user_name:
            continue
        if event.timestamp is None or not event.extra.get(_COUNTRY):
            continue
        by_user[event.user_name].append(event)

    alerts: list[Alert] = []
    for user, user_events in by_user.items():
        user_events.sort(key=lambda e: e.timestamp)
        for prev, cur in zip(user_events, user_events[1:]):
            same_window = (cur.timestamp - prev.timestamp).total_seconds() <= timespan_seconds
            different_country = prev.extra[_COUNTRY] != cur.extra[_COUNTRY]
            if same_window and different_country:
                alerts.append(
                    Alert(
                        rule_id=rule_id,
                        rule_title=title,
                        severity=level,
                        timestamp=cur.timestamp,
                        events=[prev, cur],
                        source=cur.log_source,
                        group_value=user,
                        description=description,
                    )
                )
                break  # first crossing per user is enough
    return alerts


@dataclass
class BehavioralDetector:
    """A sequence-based detector with a rule-like metadata surface.

    Attributes:
        id/title/level/description/tags: Mirror :class:`~minisoc.detections.rule.Rule`
            so the detector appears in ATT&CK coverage and listings.
        timespan: Window string (e.g. ``"1h"``) used by the detector and by live mode to
            size its rolling buffer.
    """

    id: str
    title: str
    level: str
    description: str
    timespan: str
    tags: list[str] = field(default_factory=list)

    def evaluate(self, events: list[Event]) -> list[Alert]:
        """Run this detector over the enriched event list."""
        if self.id == "impossible-travel-001":
            return impossible_travel(
                events,
                timespan_seconds=parse_window_seconds(self.timespan),
                level=self.level,
                rule_id=self.id,
                title=self.title,
                description=self.description,
            )
        return []


def default_detectors() -> list[BehavioralDetector]:
    """The behavioral detectors minisoc ships with."""
    return [
        BehavioralDetector(
            id="impossible-travel-001",
            title="Impossible Travel",
            level="critical",
            description=(
                "Same user authenticated successfully from two different countries within "
                "a span too short to have travelled — likely credential compromise."
            ),
            timespan="1h",
            tags=["attack.t1078", "attack.initial_access"],
        )
    ]
