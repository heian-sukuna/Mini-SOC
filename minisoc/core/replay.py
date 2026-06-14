"""Replay arbitrary log files through the detection pipeline.

Where :mod:`minisoc.core.runner` runs *synthetic* attack scenarios, this module runs the
same engine over logs minisoc did **not** generate — public datasets (loghub, Mordor,
…), a machine's real ``auth.log``/nginx logs, or logs captured from a real attack in a
lab. That is how you answer the two questions that turn a detection toy into evidence of
judgment:

* **Recall:** do the rules fire on attacks in data whose log lines you never touched?
* **False positives:** how often do they cry wolf on a large benign corpus?

Pass ``expect="benign"`` to treat every fired alert as a false positive (and report a
rate), or ``expect="attack"`` to report whether anything was detected at all.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from minisoc.alerting.alert import Alert
from minisoc.alerting.dedup import Deduplicator
from minisoc.alerting.sinks import JsonlSink
from minisoc.core.config import Config
from minisoc.core.pipeline import Pipeline
from minisoc.parsers import access_log, auth_log, firewall, sysmon
from minisoc.scenarios.registry import store_path

__all__ = ["ReplayResult", "detect_source", "replay_files"]

# Sources we can auto-detect, in the order we test for them.
_KNOWN_SOURCES = (
    auth_log.LOG_SOURCE,
    access_log.LOG_SOURCE,
    sysmon.LOG_SOURCE,
    firewall.LOG_SOURCE,
)


def detect_source(path: str | Path) -> str:
    """Guess which parser a log file needs from its first non-empty line.

    A JSON object per line is Sysmon; an HTTP request line in quotes is an access log;
    a netfilter ``SRC=...`` connection record is a firewall log; anything else is treated
    as syslog-style ``auth.log``. This is a convenience for ``minisoc replay`` — an
    explicit ``--source`` always overrides it.
    """
    path = Path(path)
    with open(path, encoding="utf-8", errors="replace") as handle:
        for line in handle:
            stripped = line.strip()
            if not stripped:
                continue
            if stripped.startswith("{"):
                return sysmon.LOG_SOURCE
            if '"' in stripped and "HTTP/" in stripped:
                return access_log.LOG_SOURCE
            if "SRC=" in stripped and ("PROTO=" in stripped or "DPT=" in stripped):
                return firewall.LOG_SOURCE
            return auth_log.LOG_SOURCE
    return auth_log.LOG_SOURCE


@dataclass
class ReplayResult:
    """The outcome of replaying one or more log files through the pipeline.

    Attributes:
        files: The files that were replayed, with the source each was parsed as.
        lines_read: Total raw lines read across all files.
        events_parsed: Total events the parsers recognized (lines they understood).
        alerts: The deduplicated alerts that fired.
        expect: ``"benign"``, ``"attack"``, or ``None`` (no expectation set).
        stored: Whether the alerts were appended to the JSONL store.
    """

    files: list[tuple[Path, str]]
    lines_read: int
    events_parsed: int
    alerts: list[Alert] = field(default_factory=list)
    expect: str | None = None
    stored: bool = False

    @property
    def alert_count(self) -> int:
        """Number of (deduplicated) alerts that fired."""
        return len(self.alerts)

    @property
    def false_positives(self) -> int:
        """Alerts counted as false positives — every alert when ``expect='benign'``."""
        return self.alert_count if self.expect == "benign" else 0

    @property
    def false_positive_rate(self) -> float:
        """False positives per 1,000 benign lines (0.0 when no lines or not benign)."""
        if self.expect != "benign" or self.lines_read == 0:
            return 0.0
        return self.false_positives / self.lines_read * 1000

    @property
    def verdict(self) -> str:
        """A one-line human verdict appropriate to the expectation."""
        if self.expect == "benign":
            return (
                f"{self.false_positives} false positive(s) across "
                f"{self.lines_read} benign line(s) "
                f"({self.false_positive_rate:.2f} per 1k lines)"
            )
        if self.expect == "attack":
            caught = "DETECTED" if self.alert_count else "MISSED"
            return f"{caught}: {self.alert_count} alert(s) on attack data"
        return f"{self.alert_count} alert(s) from {self.events_parsed} parsed event(s)"


def replay_files(
    paths: list[str | Path],
    config: Config,
    *,
    source: str | None = None,
    expect: str | None = None,
    year: int | None = None,
    store: bool = False,
    fresh: bool = False,
    pipeline: Pipeline | None = None,
) -> ReplayResult:
    """Run real/recorded log files through the detection pipeline.

    Each file is parsed (with its ``source`` auto-detected unless one is given), the
    combined events are evaluated by every rule, and the resulting alerts are
    deduplicated with the configured window.

    Args:
        paths: One or more log files to replay.
        config: Loaded configuration (alert window, store path).
        source: Force a parser for *all* files; ``None`` auto-detects per file.
        expect: ``"benign"`` (alerts are false positives) or ``"attack"`` (alerts are
            hits) to drive the verdict; ``None`` for a plain run.
        year: Year for year-less ``auth.log`` timestamps (recorded datasets).
        store: Append the alerts to the JSONL store (off by default — validation runs
            should not pollute the dashboard's store unless asked).
        fresh: If storing, truncate the store first.
        pipeline: An optional pre-built :class:`Pipeline` to reuse.

    Returns:
        A :class:`ReplayResult`.

    Raises:
        FileNotFoundError: If a given path does not exist.
        KeyError: If an explicit ``source`` has no registered parser.
    """
    pipeline = pipeline or Pipeline(config)

    files: list[tuple[Path, str]] = []
    lines_read = 0
    all_events = []
    for raw_path in paths:
        path = Path(raw_path)
        if not path.exists():
            raise FileNotFoundError(f"log file not found: {path}")
        file_source = source or detect_source(path)
        with open(path, encoding="utf-8", errors="replace") as handle:
            lines_read += sum(1 for _ in handle)
        all_events.extend(pipeline.parse_file(path, file_source, year=year))
        files.append((path, file_source))

    raw_alerts = pipeline.run_events(all_events)
    deduped = Deduplicator(config.alert_window_seconds).filter(raw_alerts)
    for alert in deduped:
        alert.mode = "replay"

    stored = False
    if store:
        sink = JsonlSink(store_path(config))
        if fresh:
            sink.reset()
        sink.emit(deduped)
        stored = bool(deduped)

    return ReplayResult(
        files=files,
        lines_read=lines_read,
        events_parsed=len(all_events),
        alerts=deduped,
        expect=expect,
        stored=stored,
    )
