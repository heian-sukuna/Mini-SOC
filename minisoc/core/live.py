"""Live monitoring: tail real log files and run detections continuously.

This is minisoc's deployable side. Where :mod:`minisoc.core.runner` exists to *train* —
synthetic scenarios, safe to fire from the dashboard — this module points the same
parsers, rules, and alert store at logs a real machine is writing right now
(``/var/log/nginx/access.log``, an sshd auth log, a Sysmon JSON export). Personnel can
practice on the simulation side and then watch identical detections fire on real
traffic, because every layer except the log *source* is shared.

Design: each watched file gets a :class:`FileTail` that remembers its read offset and
survives rotation/truncation. The :class:`LiveMonitor` polls the tails, parses new lines
into events, keeps a rolling buffer wide enough for the longest rule window, re-runs the
full rule set over the buffer, and emits only alerts it has not already emitted within
the dedup window. Emitted alerts carry ``mode="live"`` so the dashboard can separate
them from training runs.
"""

from __future__ import annotations

import time
from datetime import datetime, timedelta
from pathlib import Path

from minisoc.alerting.alert import Alert
from minisoc.alerting.dedup import Deduplicator
from minisoc.alerting.sinks import AlertSink
from minisoc.core.config import Config, parse_window_seconds
from minisoc.core.event import Event
from minisoc.core.pipeline import Pipeline

__all__ = ["FileTail", "LiveMonitor"]

# Safety cap on the rolling event buffer: events without timestamps can never age out,
# so bound the buffer to keep a runaway log from growing memory without limit.
_MAX_BUFFER_EVENTS = 50_000


class FileTail:
    """Incrementally reads newly appended lines from one log file.

    Tolerates the realities of tailing real logs: the file may not exist yet (watch
    starts before the service does), may be truncated in place (``copytruncate``
    rotation), or replaced by a smaller file (rename rotation). Whenever the file
    shrinks below the remembered offset, reading restarts from the top of the new file.

    Args:
        path: The log file to tail.
        source: Log source tag (``"auth.log"``, ``"access.log"``, ``"sysmon"``)
            selecting the parser for this file's lines.
        from_start: If true, the first poll reads the file from the beginning
            (historical lines included). Default is to start at the current end and
            only report lines written after the watch began.
    """

    def __init__(self, path: str | Path, source: str, *, from_start: bool = False) -> None:
        self.path = Path(path)
        self.source = source
        self._offset = 0
        self._partial = ""
        self._inode: int | None = None
        if not from_start and self.path.exists():
            stat = self.path.stat()
            self._offset = stat.st_size
            self._inode = stat.st_ino

    def read_new(self) -> list[str]:
        """Return complete lines appended since the last call.

        A trailing line without a newline is buffered until its newline arrives, so a
        half-written log line is never handed to a parser.
        """
        if not self.path.exists():
            return []
        stat = self.path.stat()
        if (self._inode is not None and stat.st_ino != self._inode) or stat.st_size < self._offset:
            # Rotated (new inode after rename) or truncated in place: whatever is
            # there now is a new file — read it from the top.
            self._offset = 0
            self._partial = ""
        self._inode = stat.st_ino
        if stat.st_size == self._offset:
            return []
        with open(self.path, "rb") as handle:
            handle.seek(self._offset)
            chunk = handle.read()
        self._offset += len(chunk)
        text = self._partial + chunk.decode("utf-8", errors="replace")
        lines = text.split("\n")
        self._partial = lines.pop()  # "" when the chunk ended on a newline
        return [line for line in lines if line.strip()]


class LiveMonitor:
    """Continuously evaluates detection rules over tailed log files.

    Args:
        config: Loaded configuration (dedup window).
        tails: The :class:`FileTail` instances to poll.
        pipeline: An optional pre-built :class:`Pipeline` to reuse.
        sinks: Sinks that receive each batch of newly fired alerts (e.g. a console
            sink plus the JSONL store the dashboard reads).
    """

    def __init__(
        self,
        config: Config,
        tails: list[FileTail],
        *,
        pipeline: Pipeline | None = None,
        sinks: list[AlertSink] | None = None,
    ) -> None:
        self._config = config
        self._pipeline = pipeline or Pipeline(config)
        self._tails = list(tails)
        self._sinks = list(sinks or [])
        self._dedup_window = config.alert_window_seconds
        self._horizon = self._compute_horizon()
        self._buffer: list[Event] = []
        self._emitted: dict[tuple, datetime] = {}
        self.lines_read = 0
        self.events_parsed = 0
        self.alerts_emitted = 0

    @property
    def tails(self) -> list[FileTail]:
        """The tails being polled."""
        return list(self._tails)

    @property
    def pipeline(self) -> Pipeline:
        """The pipeline evaluating the rules."""
        return self._pipeline

    def _compute_horizon(self) -> int:
        """How long (seconds) events must stay in the buffer to be re-evaluable.

        The widest rule/correlation window plus the dedup window: any pattern still in
        flight (e.g. a brute force building toward its threshold) fits in the buffer,
        and an alert older than the horizon is free to fire again as a new alert.
        """
        windows = [self._dedup_window]
        for rule in self._pipeline.rules:
            if rule.timeframe:
                windows.append(parse_window_seconds(rule.timeframe))
        for correlation in self._pipeline.correlations:
            windows.append(parse_window_seconds(correlation.timespan))
        for detector in self._pipeline.behavioral:
            windows.append(parse_window_seconds(detector.timespan))
        return max(windows) + self._dedup_window

    def poll_once(self, *, now: datetime | None = None) -> list[Alert]:
        """Read new lines from every tail and return newly fired alerts.

        The whole rolling buffer is re-evaluated each poll (windowed and correlation
        rules need history, not just the new lines); alerts whose dedup key already
        fired within the dedup window are suppressed, so a detection that keeps
        matching does not re-alert every poll.
        """
        new_events: list[Event] = []
        for tail in self._tails:
            lines = tail.read_new()
            self.lines_read += len(lines)
            if lines:
                new_events.extend(self._pipeline.parse_lines(lines, tail.source))
        if not new_events:
            return []
        self.events_parsed += len(new_events)
        self._buffer.extend(new_events)
        self._trim_buffer()

        raw = self._pipeline.run_events(self._buffer)
        batch = Deduplicator(self._dedup_window).filter(raw)
        now = now or datetime.now()

        fresh: list[Alert] = []
        for alert in batch:
            previous = self._emitted.get(alert.dedup_key)
            timestamp = alert.timestamp or now
            if previous is not None and (timestamp - previous).total_seconds() <= self._dedup_window:
                continue
            alert.mode = "live"
            self._emitted[alert.dedup_key] = timestamp
            fresh.append(alert)

        if fresh:
            self.alerts_emitted += len(fresh)
            for sink in self._sinks:
                sink.emit(fresh)
        return fresh

    def _trim_buffer(self) -> None:
        """Drop events older than the horizon (and cap the buffer size)."""
        timestamps = [e.timestamp for e in self._buffer if e.timestamp is not None]
        if timestamps:
            cutoff = max(timestamps) - timedelta(seconds=self._horizon)
            self._buffer = [
                e for e in self._buffer if e.timestamp is None or e.timestamp >= cutoff
            ]
        if len(self._buffer) > _MAX_BUFFER_EVENTS:
            self._buffer = self._buffer[-_MAX_BUFFER_EVENTS:]

    def run(self, interval: float = 2.0) -> None:
        """Poll forever at ``interval`` seconds. Stop with Ctrl-C (KeyboardInterrupt)."""
        while True:
            self.poll_once()
            time.sleep(interval)
