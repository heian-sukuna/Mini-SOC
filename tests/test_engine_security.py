"""Security/robustness tests for the detection engine's regex (`|re`) modifier.

The `re` modifier runs Python's backtracking engine on a pattern that can come from an
*imported* (untrusted) Sigma rule. A malformed or oversized pattern must be skipped (match
nothing) rather than crash the whole detection run, and a valid pattern must still work.
"""

from __future__ import annotations

from minisoc.core.event import Event
from minisoc.detections.engine import _MAX_RE_PATTERN, DetectionEngine
from minisoc.detections.rule import Rule


def _rule(pattern: str) -> Rule:
    return Rule(
        id="re-test", title="re test", condition="selection",
        selections={"selection": {"message|re": pattern}},
    )


def test_invalid_regex_does_not_crash_and_matches_nothing(capsys):
    event = Event(log_source="auth.log", message="hello world")
    alerts = DetectionEngine().evaluate_rule(_rule("("), [event])  # unbalanced -> invalid
    assert alerts == []
    assert "invalid regex" in capsys.readouterr().err


def test_valid_regex_still_matches():
    event = Event(log_source="auth.log", message="Failed password for root")
    alerts = DetectionEngine().evaluate_rule(_rule(r"Failed password for \w+"), [event])
    assert len(alerts) == 1


def test_oversized_regex_is_rejected():
    pattern = "a" * (_MAX_RE_PATTERN + 1)
    event = Event(log_source="auth.log", message="a" * (_MAX_RE_PATTERN + 1))
    assert DetectionEngine().evaluate_rule(_rule(pattern), [event]) == []


def test_repeated_invalid_pattern_warns_once(capsys):
    events = [Event(log_source="auth.log", message=f"line {i}") for i in range(5)]
    DetectionEngine().evaluate_rule(_rule("(unterminated"), events)
    # Warned once for the pattern, not once per event.
    assert capsys.readouterr().err.count("invalid regex") == 1
