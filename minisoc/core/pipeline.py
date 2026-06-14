"""Pipeline orchestration: raw log file -> normalized events -> detections -> alerts.

Phase 0 wires a single log source (``auth.log``) to the detection engine. The
``log.source`` tag on each event selects which parser produced it, which keeps the
orchestration source-agnostic as more parsers are added.
"""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path

from minisoc.alerting.alert import Alert
from minisoc.core.config import Config
from minisoc.core.event import Event
from minisoc.detections.behavioral import BehavioralDetector, default_detectors
from minisoc.detections.correlation import CorrelationRule, Correlator
from minisoc.detections.engine import DetectionEngine
from minisoc.detections.loader import load_rules
from minisoc.detections.rule import Rule
from minisoc.enrichment import Enricher
from minisoc.parsers import access_log, auth_log, firewall, sysmon
from minisoc.risk import RiskEngine

__all__ = ["Pipeline"]

# Maps a log source tag -> a callable(lines) -> Iterator[Event].
_PARSERS = {
    auth_log.LOG_SOURCE: auth_log.parse_auth_log,
    access_log.LOG_SOURCE: access_log.parse_access_log,
    sysmon.LOG_SOURCE: sysmon.parse_sysmon,
    firewall.LOG_SOURCE: firewall.parse_firewall,
}


class Pipeline:
    """Runs the parse → detect stage of minisoc.

    Args:
        config: Loaded :class:`Config`. Provides the default alert window and the
            rules directory.
    """

    def __init__(self, config: Config) -> None:
        self._config = config
        self._engine = DetectionEngine(default_window=config.alert_window)
        loaded = load_rules(config.rules_dir)
        self._rules = [r for r in loaded if isinstance(r, Rule)]
        self._correlations = [r for r in loaded if isinstance(r, CorrelationRule)]
        self._correlator = Correlator()
        self._enricher = Enricher.from_config(config)
        self._behavioral = default_detectors()

        # Optionally fold in importable upstream SigmaHQ rules. Native rule ids win on a
        # collision, so the imported set never shadows a hand-written detection.
        self.sigma_report = None
        if config.sigma_rules_dir and config.sigma_rules_dir.exists():
            from minisoc.detections.sigma_import import import_sigma_dir

            self.sigma_report = import_sigma_dir(config.sigma_rules_dir)
            known = {r.id for r in self._rules}
            self._rules.extend(r for r in self.sigma_report.loaded if r.id not in known)
        # Per the Sigma correlations spec, rules referenced by a correlation do not
        # generate their own alerts unless the correlation's `generate` allows it.
        self._suppressed = {
            ref
            for corr in self._correlations
            for ref in corr.rules
            if not corr.generates(ref)
        }
        # Risk-based alerting runs after detection: it turns the alerts the engine
        # produced into per-entity risk and emits a notable when an entity crosses the
        # configured threshold. Built once the full rule set (incl. imports) is known so
        # per-rule `risk_score` overrides are picked up.
        self._risk = RiskEngine.from_config(config, self._rules)

        # An empty `enabled_sources` means "all sources enabled"; otherwise only the
        # listed sources may be parsed. This makes the config field actually drive
        # behavior instead of being decorative.
        self._enabled = set(config.enabled_sources)

    @property
    def rule_count(self) -> int:
        """Number of loaded rules (detection rules + correlation rules)."""
        return len(self._rules) + len(self._correlations)

    @property
    def rules(self) -> list[Rule]:
        """The loaded detection rules."""
        return list(self._rules)

    @property
    def correlations(self) -> list[CorrelationRule]:
        """The loaded correlation rules."""
        return list(self._correlations)

    @property
    def behavioral(self) -> list[BehavioralDetector]:
        """The behavioral detectors (e.g. impossible travel)."""
        return list(self._behavioral)

    @property
    def risk(self) -> RiskEngine | None:
        """The risk-based alerting engine, or ``None`` when risk is disabled in config."""
        return self._risk

    @property
    def suppressed_rule_ids(self) -> set[str]:
        """Base rule ids a correlation silences (feeders that never emit their own alert)."""
        return set(self._suppressed)

    def tagged_rules(self) -> list:
        """Everything that carries ATT&CK tags — rules, correlations, and detectors.

        Used by the coverage rollup so behavioral detections count toward coverage.
        """
        return [*self._rules, *self._correlations, *self._behavioral]

    def is_source_enabled(self, source: str) -> bool:
        """Whether ``source`` is enabled per config ``enabled_sources``."""
        return not self._enabled or source in self._enabled

    def parse_lines(
        self, lines: Iterable[str], source: str, *, year: int | None = None
    ) -> list[Event]:
        """Parse raw log lines using the parser registered for ``source``.

        Args:
            lines: Raw log lines (an open file handle works too).
            source: Log source tag (e.g. ``"auth.log"``), selecting the parser.
            year: Year to assume for year-less syslog timestamps (``auth.log`` only).
                Useful when replaying recorded datasets whose logs predate this year.

        Returns:
            The list of normalized events.

        Raises:
            KeyError: If no parser is registered for ``source``.
            ValueError: If ``source`` is disabled in config ``enabled_sources``.
        """
        if not self.is_source_enabled(source):
            raise ValueError(
                f"log source {source!r} is disabled in config 'enabled_sources'"
            )
        parser = _PARSERS[source]
        # Syslog-style parsers (auth.log, firewall) carry no year in the timestamp and
        # accept an assumed one; the others embed their own timestamps.
        if source in (auth_log.LOG_SOURCE, firewall.LOG_SOURCE) and year is not None:
            return list(parser(lines, year=year))
        return list(parser(lines))

    def parse_file(
        self, path: str | Path, source: str, *, year: int | None = None
    ) -> list[Event]:
        """Parse a log file using the parser registered for ``source``.

        See :meth:`parse_lines` for the ``source``/``year`` semantics and errors.
        """
        with open(path, encoding="utf-8", errors="replace") as handle:
            return self.parse_lines(handle, source, year=year)

    def run_file(self, path: str | Path, source: str) -> list[Alert]:
        """Parse a log file and evaluate all rules against it.

        Args:
            path: Path to the log file.
            source: Log source tag selecting the parser.

        Returns:
            Fired alerts.
        """
        events = self.parse_file(path, source)
        return self.run_events(events)

    def run_events(self, events: list[Event]) -> list[Alert]:
        """Evaluate all rules against an already-parsed list of events.

        Events are enriched first (threat-intel/geo/asset context), so rules and
        behavioral detectors see the added fields. Base detection rules run next; their
        per-rule results feed the correlation rules. Base rules referenced by a
        correlation are suppressed unless the correlation's ``generate`` field allows
        them. Finally every alert is annotated with an enrichment summary.
        """
        events = self._enricher.enrich(events)
        by_rule = {rule.id: self._engine.evaluate_rule(rule, events) for rule in self._rules}

        alerts: list[Alert] = []
        for rule_id, rule_alerts in by_rule.items():
            if rule_id not in self._suppressed:
                alerts.extend(rule_alerts)
        for correlation in self._correlations:
            alerts.extend(self._correlator.evaluate(correlation, by_rule))
        for detector in self._behavioral:
            alerts.extend(detector.evaluate(events))

        # Risk-based alerting: fold the detections into per-entity risk and append any
        # notables that cross the threshold (so they ride the same dedup/sink/triage path).
        if self._risk is not None:
            alerts.extend(self._risk.assess(alerts))

        for alert in alerts:
            self._enricher.enrich_alert(alert)
        return alerts
