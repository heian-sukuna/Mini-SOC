"""A hand-written subset of Sigma *Correlations* — temporal rule chaining.

Sigma v2 introduces correlation rules: meta-rules that don't match events themselves but
fire when *other* rules fire in a particular relationship. minisoc implements the temporal
slice of that spec::

    correlation:
      type: temporal_ordered          # or `temporal` (unordered)
      rules:                          # the base rules being chained, by id
        - ssh-bruteforce-001
        - ssh-login-success-001
      group-by:                       # the chain must share these field values
        - source.ip
      timespan: 5m                    # the whole chain must fit in this window
      generate:                       # subset extension, see below
        - ssh-bruteforce-001

* ``temporal`` — every referenced rule fired for the same group within ``timespan``,
  in any order.
* ``temporal_ordered`` — same, but in the listed order.

Per the Sigma spec, rules referenced by a correlation do **not** generate their own
alerts (they exist to feed the correlation). The spec's ``generate`` field is a boolean
(all or nothing); minisoc extends it to also accept a *list of rule ids* that should keep
alerting independently — e.g. the brute-force rule stays a standalone alert while the
match-only "successful login" rule stays silent.

The :class:`Correlator` operates on **alerts produced by base rules**, not raw events:
per-event rules contribute one occurrence per matching event, and windowed aggregation
rules contribute one occurrence per threshold crossing. That makes correlation a layer on
top of the existing engine rather than a change to it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from minisoc.alerting.alert import Alert
from minisoc.core.config import parse_window_seconds
from minisoc.detections.rule import DEFAULT_LEVEL

__all__ = ["CorrelationRule", "Correlator", "CORRELATION_TYPES"]

CORRELATION_TYPES = {"temporal", "temporal_ordered"}


@dataclass
class CorrelationRule:
    """A parsed Sigma-subset correlation rule.

    Attributes:
        id: Stable rule identifier.
        title: Human-readable title.
        type: ``"temporal"`` (any order) or ``"temporal_ordered"`` (listed order).
        rules: Ids of the base rules being correlated (at least two).
        group_by: ECS fields whose values must be shared across the chain (the spec's
            ``group-by``). Empty means one global group.
        timespan: Window the whole chain must fit in (e.g. ``"5m"``).
        level: Severity of the correlation alert.
        description: What the correlation detects.
        generate: Which referenced rules still generate their own alerts. ``False``
            (spec default) suppresses all of them, ``True`` suppresses none, and a list
            of rule ids suppresses all but those (minisoc extension).
        source_path: Path the rule was loaded from (for diagnostics).
    """

    id: str
    title: str
    type: str
    rules: list[str]
    group_by: list[str] = field(default_factory=list)
    timespan: str = "5m"
    level: str = DEFAULT_LEVEL
    description: str = ""
    generate: bool | list[str] = False
    tags: list[str] = field(default_factory=list)
    source_path: str | None = None

    def generates(self, rule_id: str) -> bool:
        """Whether a referenced base rule may still emit its own alerts."""
        if isinstance(self.generate, bool):
            return self.generate
        return rule_id in self.generate


# One base-rule firing usable by the correlator: when it fired, and the alert as evidence.
_Occurrence = tuple[datetime, Alert]


class Correlator:
    """Evaluates :class:`CorrelationRule` objects over base-rule alerts."""

    def evaluate(
        self, correlation: CorrelationRule, alerts_by_rule: dict[str, list[Alert]]
    ) -> list[Alert]:
        """Evaluate one correlation against the alerts each base rule produced.

        Args:
            correlation: The correlation rule.
            alerts_by_rule: Mapping of base rule id -> alerts that rule fired.

        Returns:
            At most one alert per group whose chain satisfies the correlation
            (mirroring the engine's first-window-crossing behavior).
        """
        window = parse_window_seconds(correlation.timespan)

        # Bucket each base rule's occurrences by group key.
        # groups: group_key -> rule_id -> [(timestamp, alert), ...] sorted by time.
        groups: dict[object, dict[str, list[_Occurrence]]] = {}
        for rule_id in correlation.rules:
            for alert in alerts_by_rule.get(rule_id, []):
                if alert.timestamp is None:
                    continue  # an undated firing can't be placed in a time window
                key = self._group_key(alert, correlation.group_by)
                if key is None:
                    continue  # missing group field -> can't be correlated
                groups.setdefault(key, {}).setdefault(rule_id, []).append(
                    (alert.timestamp, alert)
                )

        alerts: list[Alert] = []
        for key, by_rule in groups.items():
            # Every referenced rule must have fired for this group at least once.
            if any(rule_id not in by_rule for rule_id in correlation.rules):
                continue
            for occurrences in by_rule.values():
                occurrences.sort(key=lambda occ: occ[0])

            if correlation.type == "temporal_ordered":
                chain = self._find_ordered_chain(correlation.rules, by_rule, window)
            else:
                chain = self._find_unordered_chain(correlation.rules, by_rule, window)
            if chain is not None:
                alerts.append(self._make_alert(correlation, key, chain))
        return alerts

    # -- internals ---------------------------------------------------------------------

    @staticmethod
    def _group_key(alert: Alert, group_by: list[str]) -> object | None:
        """Resolve an alert's group key from its evidence events.

        Returns ``None`` when any ``group-by`` field is absent — such an alert cannot
        participate in the correlation.
        """
        if not group_by:
            return "__all__"
        values = []
        for field_name in group_by:
            value = next(
                (e.get(field_name) for e in alert.events if e.get(field_name) is not None),
                None,
            )
            if value is None:
                return None
            values.append(value)
        return tuple(values)

    @staticmethod
    def _find_ordered_chain(
        rule_ids: list[str],
        by_rule: dict[str, list[_Occurrence]],
        window_seconds: int,
    ) -> list[_Occurrence] | None:
        """Find the first chain hitting every rule in listed order within the window.

        For each candidate start (an occurrence of the first rule, in time order), greedily
        take the earliest occurrence of each subsequent rule at-or-after the previous link.
        Greedy-earliest minimizes the chain's end time for a fixed start, so if that chain
        exceeds the window no other chain from the same start can fit.
        """
        for start in by_rule[rule_ids[0]]:
            chain = [start]
            for rule_id in rule_ids[1:]:
                prev_ts = chain[-1][0]
                nxt = next((occ for occ in by_rule[rule_id] if occ[0] >= prev_ts), None)
                if nxt is None:
                    break
                chain.append(nxt)
            else:
                if (chain[-1][0] - chain[0][0]).total_seconds() <= window_seconds:
                    return chain
        return None

    @staticmethod
    def _find_unordered_chain(
        rule_ids: list[str],
        by_rule: dict[str, list[_Occurrence]],
        window_seconds: int,
    ) -> list[_Occurrence] | None:
        """Find the first time window containing at least one firing of every rule.

        Two-pointer sweep over the merged, time-sorted occurrences of all rules,
        tracking how many distinct rules are represented inside the window.
        """
        # Sort key must exclude the Alert itself: with tied (timestamp, rule_id) the
        # default tuple comparison would fall through to Alert < Alert and raise.
        merged: list[tuple[datetime, str, Alert]] = sorted(
            (
                (ts, rule_id, alert)
                for rule_id, occurrences in by_rule.items()
                for ts, alert in occurrences
            ),
            key=lambda item: (item[0], item[1]),
        )
        counts: dict[str, int] = {}
        start = 0
        for end, (end_ts, end_rule, _) in enumerate(merged):
            counts[end_rule] = counts.get(end_rule, 0) + 1
            while (end_ts - merged[start][0]).total_seconds() > window_seconds:
                counts[merged[start][1]] -= 1
                if counts[merged[start][1]] == 0:
                    del counts[merged[start][1]]
                start += 1
            if len(counts) == len(rule_ids):
                # Evidence: the latest in-window occurrence of each rule.
                latest: dict[str, _Occurrence] = {}
                for ts, rule_id, alert in merged[start : end + 1]:
                    latest[rule_id] = (ts, alert)
                return [latest[rule_id] for rule_id in rule_ids]
        return None

    @staticmethod
    def _make_alert(
        correlation: CorrelationRule, key: object, chain: list[_Occurrence]
    ) -> Alert:
        """Build the correlation alert from the qualifying chain."""
        events = [event for _, alert in chain for event in alert.events]
        group_value: object | None
        if key == "__all__":
            group_value = None
        elif isinstance(key, tuple) and len(key) == 1:
            group_value = key[0]
        else:
            group_value = key
        return Alert(
            rule_id=correlation.id,
            rule_title=correlation.title,
            severity=correlation.level,
            timestamp=chain[-1][0],
            events=events,
            source=events[0].log_source if events else None,
            group_value=group_value,
            description=correlation.description,
        )
