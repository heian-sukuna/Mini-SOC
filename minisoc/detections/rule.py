"""The in-memory representation of a Sigma-subset detection rule."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

__all__ = ["Rule", "DEFAULT_LEVEL"]

DEFAULT_LEVEL = "medium"


@dataclass
class Rule:
    """A parsed Sigma-subset detection rule.

    Mirrors the relevant parts of the Sigma rule structure. Only the subset minisoc
    implements is represented here.

    Attributes:
        id: Stable rule identifier (Sigma ``id``).
        title: Human-readable title.
        description: What the rule detects.
        level: Severity, one of ``low``/``medium``/``high``/``critical`` (Sigma
            ``level``). Defaults to :data:`DEFAULT_LEVEL`.
        logsource: ``logsource`` block (``category``/``product``/``service``). An
            event must match all present keys for the rule to apply.
        selections: Named selection blocks from ``detection:`` (every key except
            ``condition`` and ``timeframe``). Each maps a name to its match spec.
        condition: The ``condition:`` expression string.
        timeframe: Optional aggregation window string (e.g. ``"5m"``). When set, the
            rule is evaluated as a windowed threshold rule.
        tags: Sigma ``tags`` (e.g. ``attack.t1110``, ``attack.credential_access``),
            used for the MITRE ATT&CK coverage rollup.
        risk_score: Optional explicit risk weight for risk-based alerting. When unset, the
            risk engine derives the weight from ``level``; setting it lets a rule punch
            above or below its severity (e.g. a noisy-but-weak signal scoring low).
        source_path: Path the rule was loaded from (for diagnostics).
    """

    id: str
    title: str
    condition: str
    description: str = ""
    level: str = DEFAULT_LEVEL
    logsource: dict[str, str] = field(default_factory=dict)
    selections: dict[str, Any] = field(default_factory=dict)
    timeframe: str | None = None
    tags: list[str] = field(default_factory=list)
    risk_score: int | None = None
    source_path: str | None = None
