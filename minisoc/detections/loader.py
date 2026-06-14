"""Load Sigma-subset detection and correlation rules from YAML files."""

from __future__ import annotations

from pathlib import Path

import yaml

from minisoc.detections.correlation import CORRELATION_TYPES, CorrelationRule
from minisoc.detections.rule import DEFAULT_LEVEL, Rule

__all__ = ["load_rule", "load_rules"]

# Keys inside `detection:` that are not selections.
_RESERVED_DETECTION_KEYS = {"condition", "timeframe"}


def load_rule(path: str | Path) -> Rule | CorrelationRule:
    """Load and validate a single rule YAML file.

    A file containing a ``correlation:`` block is parsed as a
    :class:`CorrelationRule`; otherwise it must contain a ``detection:`` block and is
    parsed as a regular :class:`Rule`.

    Args:
        path: Path to the rule ``.yml``/``.yaml`` file.

    Returns:
        The parsed :class:`Rule` or :class:`CorrelationRule`.

    Raises:
        ValueError: If the file is missing required keys or is malformed.
    """
    path = Path(path)
    data = yaml.safe_load(path.read_text()) or {}

    for required in ("id", "title"):
        if not data.get(required):
            raise ValueError(f"{path}: '{required}' is required")

    if "correlation" in data:
        return _load_correlation(path, data)
    return _load_detection(path, data)


def _load_detection(path: Path, data: dict) -> Rule:
    """Parse a regular detection rule document."""
    detection = data.get("detection")
    if not isinstance(detection, dict):
        raise ValueError(f"{path}: missing or invalid 'detection:' block")

    condition = detection.get("condition")
    if not condition:
        raise ValueError(f"{path}: 'detection.condition' is required")

    selections = {
        name: spec
        for name, spec in detection.items()
        if name not in _RESERVED_DETECTION_KEYS
    }
    if not selections:
        raise ValueError(f"{path}: 'detection' must define at least one selection")

    return Rule(
        id=str(data["id"]),
        title=str(data["title"]),
        condition=str(condition),
        description=str(data.get("description", "")),
        level=str(data.get("level", DEFAULT_LEVEL)),
        logsource=dict(data.get("logsource") or {}),
        selections=selections,
        timeframe=detection.get("timeframe"),
        tags=[str(t) for t in (data.get("tags") or [])],
        risk_score=int(data["risk_score"]) if data.get("risk_score") is not None else None,
        source_path=str(path),
    )


def _load_correlation(path: Path, data: dict) -> CorrelationRule:
    """Parse a Sigma-subset correlation rule document."""
    corr = data["correlation"]
    if not isinstance(corr, dict):
        raise ValueError(f"{path}: 'correlation:' must be a mapping")

    corr_type = corr.get("type")
    if corr_type not in CORRELATION_TYPES:
        raise ValueError(
            f"{path}: 'correlation.type' must be one of {sorted(CORRELATION_TYPES)}, "
            f"got {corr_type!r}"
        )

    refs = corr.get("rules")
    if not isinstance(refs, list) or len(refs) < 2:
        raise ValueError(f"{path}: 'correlation.rules' must list at least two rule ids")

    timespan = corr.get("timespan")
    if not timespan:
        raise ValueError(f"{path}: 'correlation.timespan' is required")

    group_by = corr.get("group-by") or []
    if isinstance(group_by, str):
        group_by = [group_by]

    generate = corr.get("generate", False)
    if isinstance(generate, list):
        generate = [str(g) for g in generate]
    elif not isinstance(generate, bool):
        raise ValueError(
            f"{path}: 'correlation.generate' must be a boolean or a list of rule ids"
        )

    return CorrelationRule(
        id=str(data["id"]),
        title=str(data["title"]),
        type=str(corr_type),
        rules=[str(r) for r in refs],
        group_by=[str(f) for f in group_by],
        timespan=str(timespan),
        level=str(data.get("level", DEFAULT_LEVEL)),
        description=str(data.get("description", "")),
        generate=generate,
        tags=[str(t) for t in (data.get("tags") or [])],
        source_path=str(path),
    )


def load_rules(rules_dir: str | Path) -> list[Rule | CorrelationRule]:
    """Load every ``.yml``/``.yaml`` rule in a directory.

    Correlation rules are validated against the detection rules loaded alongside them:
    a correlation referencing an unknown rule id is a configuration error.

    Args:
        rules_dir: Directory containing rule files.

    Returns:
        A list of :class:`Rule` and :class:`CorrelationRule`, sorted by rule id for
        determinism.

    Raises:
        ValueError: If a correlation references a rule id that does not exist (or
            references another correlation, which this subset does not support).
    """
    rules_dir = Path(rules_dir)
    rules: list[Rule | CorrelationRule] = []
    for file in sorted(rules_dir.glob("*.y*ml")):
        rules.append(load_rule(file))

    detection_ids = {r.id for r in rules if isinstance(r, Rule)}
    for rule in rules:
        if isinstance(rule, CorrelationRule):
            unknown = [ref for ref in rule.rules if ref not in detection_ids]
            if unknown:
                raise ValueError(
                    f"{rule.source_path}: correlation references unknown rule id(s): "
                    f"{', '.join(unknown)}"
                )

    return sorted(rules, key=lambda r: r.id)
