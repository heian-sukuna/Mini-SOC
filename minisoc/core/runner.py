"""The shared scenario runner used by both the CLI and the dashboard.

One function, :func:`run_scenario`, performs the full vertical flow for a named scenario:
generate malicious log lines → write them → parse + detect → deduplicate → (optionally)
append to the JSONL store. It returns a :class:`RunResult` describing what happened, so
callers (CLI printing a table, dashboard returning JSON) share identical behavior.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from minisoc.alerting.alert import Alert
from minisoc.alerting.dedup import Deduplicator
from minisoc.alerting.sinks import JsonlSink
from minisoc.core.config import Config
from minisoc.core.pipeline import Pipeline
from minisoc.scenarios.registry import SCENARIOS, scenario_log_path, store_path

__all__ = ["RunResult", "run_scenario"]


@dataclass
class RunResult:
    """The outcome of running one scenario through the pipeline.

    Attributes:
        scenario: The scenario name that was run.
        source: The log source it fed.
        log_path: Where the generated log was written.
        lines_generated: Number of log lines the scenario emitted.
        raw_alert_count: Alerts before deduplication.
        alerts: The deduplicated alerts.
        stored: Whether the alerts were appended to the JSONL store.
        rule_count: Number of rules evaluated (detection + correlation rules).
    """

    scenario: str
    source: str
    log_path: Path
    lines_generated: int
    raw_alert_count: int
    alerts: list[Alert]
    stored: bool
    rule_count: int

    @property
    def deduped_count(self) -> int:
        """Number of alerts after deduplication."""
        return len(self.alerts)


def run_scenario(
    name: str,
    config: Config,
    *,
    fresh: bool = False,
    store: bool = True,
    pipeline: Pipeline | None = None,
) -> RunResult:
    """Run one attack scenario end-to-end.

    Args:
        name: A scenario name registered in
            :data:`~minisoc.scenarios.registry.SCENARIOS`.
        config: Loaded configuration (paths, alert window).
        fresh: If true and ``store`` is enabled, truncate the JSONL store first.
        store: If true, append the deduplicated alerts to the JSONL store.
        pipeline: An optional pre-built :class:`Pipeline` to reuse (the dashboard keeps
            one alive across requests instead of reloading rules each time).

    Returns:
        A :class:`RunResult`.

    Raises:
        KeyError: If ``name`` is not a registered scenario.
    """
    generate, source = SCENARIOS[name]

    log_path = scenario_log_path(config, source)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    lines = list(generate())
    log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    pipeline = pipeline or Pipeline(config)
    raw_alerts = pipeline.run_file(log_path, source)
    deduped = Deduplicator(config.alert_window_seconds).filter(raw_alerts)
    for alert in deduped:
        alert.mode = "simulation"

    stored = False
    if store:
        sink = JsonlSink(store_path(config))
        if fresh:
            sink.reset()
        sink.emit(deduped)
        stored = bool(deduped)

    return RunResult(
        scenario=name,
        source=source,
        log_path=log_path,
        lines_generated=len(lines),
        raw_alert_count=len(raw_alerts),
        alerts=deduped,
        stored=stored,
        rule_count=pipeline.rule_count,
    )
