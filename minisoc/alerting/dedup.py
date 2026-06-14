"""Alert deduplication within a sliding time window.

Real SOCs drown in repeated alerts — the same detection firing over and over for the same
attacker. The :class:`Deduplicator` collapses repeats that share a
:attr:`~minisoc.alerting.alert.Alert.dedup_key` and fall within ``window`` seconds of the
previous occurrence, keeping the first as the representative and recording how many times
it fired (:attr:`Alert.occurrences`).

The window is *sliding*: each new occurrence within the window resets the clock, so a
continuous burst stays collapsed into one alert. A gap longer than the window starts a
fresh alert.
"""

from __future__ import annotations

from datetime import datetime

from minisoc.alerting.alert import Alert

__all__ = ["Deduplicator"]

_EPOCH = datetime.min


class Deduplicator:
    """Collapses duplicate alerts within a sliding window.

    Args:
        window_seconds: Suppress a repeat if it occurs within this many seconds of the
            previous occurrence of the same :attr:`Alert.dedup_key`.
    """

    def __init__(self, window_seconds: int) -> None:
        self._window = window_seconds

    def filter(self, alerts: list[Alert]) -> list[Alert]:
        """Deduplicate a batch of alerts.

        Alerts are processed in timestamp order. The first occurrence of each key is
        kept and returned; later occurrences within the window are suppressed but bump
        the kept alert's :attr:`Alert.occurrences` and :attr:`Alert.last_seen`.

        Args:
            alerts: The alerts to deduplicate.

        Returns:
            The kept (representative) alerts, in first-seen order.
        """
        ordered = sorted(alerts, key=lambda a: a.timestamp or _EPOCH)
        representative: dict[tuple, Alert] = {}
        last_seen: dict[tuple, datetime] = {}
        kept: list[Alert] = []

        for alert in ordered:
            key = alert.dedup_key
            ts = alert.timestamp
            prev = last_seen.get(key)

            within_window = (
                prev is not None
                and ts is not None
                and (ts - prev).total_seconds() <= self._window
            )

            if within_window:
                rep = representative[key]
                rep.occurrences += 1
                rep.last_seen = ts
            else:
                alert.occurrences = 1
                alert.last_seen = ts
                representative[key] = alert
                kept.append(alert)

            if ts is not None:
                last_seen[key] = ts

        return kept
