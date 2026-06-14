"""Risk-based alerting (RBA) — accumulate risk per entity, alert on the threshold.

The problem RBA solves
----------------------
One rule = one alert does not scale: a real environment generates a flood of low-fidelity
signals, and an analyst can't chase each one. The modern SOC answer (Splunk RBA, Elastic's
risk engine) is to stop treating every detection as a page. Instead each detection becomes a
small **risk contribution** attributed to the *entities* it involves — a source IP, a user, a
host. Risk accumulates per entity inside a sliding window, and a single high-fidelity **risk
notable** fires only when an entity's combined risk crosses a threshold.

The payoff: an attacker who trips a port scan, then a brute force, then a sudo escalation —
each individually "medium" — rolls up into *one* critical alert on that source IP, with all
the contributing signals attached as evidence. Ten noisy alerts collapse into one story.

How it plugs in
---------------
:class:`RiskEngine` runs after the normal detection pass. It reads the alerts the engine
already produced (it never re-implements detection), maps each to a score and its entities,
and emits ``risk-notable`` :class:`~minisoc.alerting.alert.Alert` objects — so risk notables
flow through dedup, the JSONL store, triage, notifications, and the dashboard like any other
alert. Scores derive from severity, with an optional per-rule ``risk_score`` override.
"""

from __future__ import annotations

import ipaddress
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Callable

from minisoc.alerting.alert import Alert
from minisoc.core.config import parse_window_seconds
from minisoc.core.event import Event

__all__ = ["RiskEngine", "RiskContribution", "RISK_BY_SEVERITY", "score_for_severity"]

# The id every aggregated risk alert carries, so it is recognizable end-to-end.
RISK_RULE_ID = "risk-notable"

# Base risk a single detection contributes, by its severity. Tunable, but the ordering is
# the point: a critical signal alone nearly trips a default threshold; lows must stack.
RISK_BY_SEVERITY = {
    "informational": 5,
    "low": 15,
    "medium": 30,
    "high": 60,
    "critical": 90,
}

# Default entities risk is tracked against. Each is a dotted ECS field on the evidence.
_DEFAULT_OBJECTS = ("source.ip", "user.name", "host.name")


def score_for_severity(severity: str | None) -> int:
    """Base risk score for a severity label (unknown severities score as ``medium``)."""
    return RISK_BY_SEVERITY.get((severity or "").lower(), RISK_BY_SEVERITY["medium"])


@dataclass
class RiskContribution:
    """One detection's contribution to an entity's risk."""

    rule_id: str
    rule_title: str
    severity: str
    score: int
    timestamp: datetime | None = None


class RiskEngine:
    """Accumulates per-entity risk and emits risk notables over a threshold.

    Args:
        threshold: Cumulative risk (within ``window``) at which an entity becomes notable.
        window: Sliding-window string (e.g. ``"24h"``) over which risk accumulates.
        objects: Dotted entity fields risk is tracked against (e.g. ``source.ip``).
        rule_scores: Optional ``rule_id -> score`` overrides (from rule ``risk_score:``).
    """

    def __init__(
        self,
        *,
        threshold: int = 100,
        window: str = "24h",
        objects: tuple[str, ...] | list[str] = _DEFAULT_OBJECTS,
        rule_scores: dict[str, int] | None = None,
    ) -> None:
        self.threshold = int(threshold)
        self.window = window
        self._window_seconds = parse_window_seconds(window)
        self.objects = tuple(objects)
        self._rule_scores = dict(rule_scores or {})

    @classmethod
    def from_config(cls, config, rules: list | None = None) -> "RiskEngine | None":
        """Build from the ``risk:`` config section, or ``None`` when disabled.

        Per-rule ``risk_score`` overrides are read off the loaded ``rules`` (those that
        carry the attribute), so a rule can declare its own weight.
        """
        section: dict[str, Any] = getattr(config, "risk", {}) or {}
        if not section.get("enabled", False):
            return None
        rule_scores = {
            r.id: int(r.risk_score)
            for r in (rules or [])
            if getattr(r, "risk_score", None) is not None
        }
        return cls(
            threshold=section.get("threshold", 100),
            window=section.get("window", "24h"),
            objects=section.get("objects") or _DEFAULT_OBJECTS,
            rule_scores=rule_scores,
        )

    # -- scoring inputs ----------------------------------------------------------------

    def _score(self, rule_id: str, severity: str | None) -> int:
        return self._rule_scores.get(rule_id, score_for_severity(severity))

    def _entity_scores(
        self, get: Callable[[str], Any], group_value: Any, base_score: int
    ) -> dict[tuple[str, str], int]:
        """Score one alert against each entity it touches, with per-field dilution.

        ``get(field)`` resolves a dotted field over the evidence; ``group_value`` is folded
        into ``source.ip`` when it is an IP, so aggregation alerts attribute correctly.

        A signal that touches *many* values of one field (a brute force spraying 30
        usernames) is a weak signal against any single one of them — so the score is
        **divided across the distinct values within that field**. This keeps a spray from
        minting a notable per target (it instead rolls up to the single attacker IP), while
        a *focused* signal on one value keeps its full weight. The attacker dimension
        (one IP, undivided) is what accumulates.
        """
        by_field: dict[str, set[str]] = {}
        for field in self.objects:
            values = {str(v) for v in get(field) if v not in (None, "")}
            if field == "source.ip" and _is_ip(group_value):
                values.add(str(group_value))
            if values:
                by_field[field] = values

        scores: dict[tuple[str, str], int] = {}
        for field, values in by_field.items():
            share = max(1, base_score // len(values))
            for value in values:
                scores[(field, value)] = share
        return scores

    # -- public entry points -----------------------------------------------------------

    def assess(self, alerts: list[Alert], *, now: datetime | None = None) -> list[Alert]:
        """Score ``alerts`` and return one risk notable per entity over the threshold."""
        now = now or datetime.now()
        buckets: dict[tuple[str, str], list[tuple[float, RiskContribution, Alert]]] = defaultdict(list)

        for alert in alerts:
            if alert.rule_id == RISK_RULE_ID:
                continue  # never let a risk notable feed back into risk
            base = self._score(alert.rule_id, alert.severity)
            if base <= 0:
                continue
            ts = (alert.timestamp or now).timestamp()
            scores = self._entity_scores(
                lambda f: _event_values(alert.events, f), alert.group_value, base
            )
            for entity, share in scores.items():
                contrib = RiskContribution(
                    alert.rule_id, alert.rule_title, alert.severity, share, alert.timestamp
                )
                buckets[entity].append((ts, contrib, alert))

        notables: list[Alert] = []
        for (field, value), items in buckets.items():
            items.sort(key=lambda x: x[0])
            crossing = self._crossing(items)
            if crossing is not None:
                total, window_items = crossing
                notables.append(self._build_notable(field, value, total, window_items, now))
        return notables

    def leaderboard(self, records: list[dict], *, limit: int = 10) -> list[dict]:
        """Top entities by accumulated risk across stored alert records (for the dashboard).

        Operates on serialized alert dicts (as the JSONL store holds), recomputing the
        max-window risk per entity. Returns ``{entity, value, score, signals, over_threshold}``
        rows, highest risk first. Risk notables themselves are excluded.
        """
        buckets: dict[tuple[str, str], list[tuple[float, RiskContribution, None]]] = defaultdict(list)
        for rec in records:
            if rec.get("rule_id") == RISK_RULE_ID:
                continue
            base = self._score(rec.get("rule_id", ""), rec.get("severity"))
            if base <= 0:
                continue
            ts = _parse_ts(rec.get("timestamp"))
            events = rec.get("events") or []
            scores = self._entity_scores(
                lambda f: _record_values(events, f), rec.get("group_value"), base
            )
            for entity, share in scores.items():
                contrib = RiskContribution(
                    rec.get("rule_id", ""), rec.get("rule_title", ""), rec.get("severity", ""), share
                )
                buckets[entity].append((ts, contrib, None))

        rows = []
        for (field, value), items in buckets.items():
            items.sort(key=lambda x: x[0])
            best = self._max_window(items)
            rows.append({
                "entity": field,
                "value": value,
                "score": best,
                "signals": len(items),
                "over_threshold": best >= self.threshold,
            })
        rows.sort(key=lambda r: r["score"], reverse=True)
        return rows[:limit]

    # -- windowing ---------------------------------------------------------------------

    def _crossing(self, items):
        """Return ``(total, window_items)`` for the max-sum window that crosses threshold."""
        best = self._max_window(items, return_items=True)
        if best is None or best[0] < self.threshold:
            return None
        return best

    def _max_window(self, items, *, return_items: bool = False):
        """Max scored sum over any ``window``-wide span (two-pointer over sorted items)."""
        start = running = 0
        best_sum = 0
        best_items: list = []
        for end in range(len(items)):
            running += items[end][1].score
            while items[end][0] - items[start][0] > self._window_seconds:
                running -= items[start][1].score
                start += 1
            if running > best_sum:
                best_sum = running
                if return_items:
                    best_items = items[start:end + 1]
        if return_items:
            return (best_sum, best_items) if best_items else None
        return best_sum

    def _build_notable(self, field, value, total, window_items, now) -> Alert:
        contribs = [c for _, c, _ in window_items]
        # Union the evidence of the contributing alerts (deduped by raw line / identity).
        events: list[Event] = []
        seen: set = set()
        for _, _, alert in window_items:
            for event in alert.events:
                key = event.raw if event.raw is not None else id(event)
                if key not in seen:
                    seen.add(key)
                    events.append(event)
        latest = max((c.timestamp for c in contribs if c.timestamp), default=now)
        severity = "critical" if total >= 2 * self.threshold else "high"
        rule_ids = sorted({c.rule_id for c in contribs})
        description = (
            f"{len(contribs)} signal(s) accumulated risk {total} "
            f"(threshold {self.threshold}) on {field}={value}: {', '.join(rule_ids)}"
        )
        return Alert(
            rule_id=RISK_RULE_ID,
            rule_title=f"Elevated risk: {value}",
            severity=severity,
            timestamp=latest,
            events=events,
            source="risk",
            group_value=value,
            description=description,
            risk={
                "score": total,
                "threshold": self.threshold,
                "object": field,
                "signals": len(contribs),
                "contributors": [
                    {"rule_id": c.rule_id, "severity": c.severity, "score": c.score}
                    for c in contribs
                ],
            },
        )


def _is_ip(value: Any) -> bool:
    try:
        ipaddress.ip_address(str(value))
        return True
    except ValueError:
        return False


def _event_values(events: list[Event], field: str) -> set[Any]:
    """Distinct values of a dotted field across a list of :class:`Event` objects."""
    return {e.get(field) for e in events if e.get(field) is not None}


def _record_values(events: list[dict], field: str) -> set[Any]:
    """Distinct values of a dotted field across nested ECS event dicts."""
    out: set[Any] = set()
    for event in events:
        cursor: Any = event
        for part in field.split("."):
            cursor = cursor.get(part) if isinstance(cursor, dict) else None
        if cursor is not None:
            out.add(cursor)
    return out


def _parse_ts(value: Any) -> float:
    try:
        return datetime.fromisoformat(value).timestamp()
    except (TypeError, ValueError):
        return 0.0
