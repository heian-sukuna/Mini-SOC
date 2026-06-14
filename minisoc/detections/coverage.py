"""MITRE ATT&CK coverage rollup over the loaded rules.

Sigma rules carry ``tags`` such as ``attack.t1110`` (a technique) or
``attack.credential_access`` (a tactic). This module reads those tags off the loaded
:class:`~minisoc.detections.rule.Rule` and
:class:`~minisoc.detections.correlation.CorrelationRule` objects and rolls them up into a
"which techniques do we cover, and which rules are untagged" report — the common way to
express detection coverage in blue-team work.
"""

from __future__ import annotations

import re
from typing import Protocol

__all__ = ["technique_ids", "technique_url", "mitre_coverage"]

# Sigma technique tags: `attack.t1110` or the sub-technique form `attack.t1110.001`.
_TECHNIQUE_RE = re.compile(r"^attack\.t(?P<num>\d{4})(?:\.(?P<sub>\d{3}))?$", re.IGNORECASE)


class _Tagged(Protocol):
    """Anything with the attributes the rollup reads (a Rule or CorrelationRule)."""

    id: str
    title: str
    level: str
    tags: list[str]


def technique_ids(tags: list[str]) -> list[str]:
    """Extract MITRE technique ids (e.g. ``T1110``, ``T1110.001``) from Sigma tags.

    Tactic tags like ``attack.credential_access`` are intentionally ignored here — this
    returns only concrete techniques/sub-techniques, uppercased to the canonical form.
    """
    ids: list[str] = []
    for tag in tags:
        match = _TECHNIQUE_RE.match(tag)
        if match:
            tid = f"T{match['num']}"
            if match["sub"]:
                tid += f".{match['sub']}"
            ids.append(tid)
    return ids


def technique_url(technique: str) -> str:
    """Return the canonical attack.mitre.org URL for a technique id."""
    base, _, sub = technique.partition(".")
    if sub:
        return f"https://attack.mitre.org/techniques/{base}/{sub}/"
    return f"https://attack.mitre.org/techniques/{base}/"


def mitre_coverage(rules: list[_Tagged]) -> dict[str, list]:
    """Roll up technique coverage across the given rules.

    Args:
        rules: The loaded detection and correlation rules (anything exposing
            ``id``/``title``/``level``/``tags``).

    Returns:
        ``{"techniques": [...], "untagged": [...]}`` where each technique record is
        ``{"technique", "url", "rules": [{"id", "title", "severity"}, ...]}`` sorted by
        technique id, and ``untagged`` lists rule ids that carry no technique tag (the
        coverage gaps worth knowing about).
    """
    by_technique: dict[str, list[dict[str, str]]] = {}
    untagged: list[str] = []

    for rule in rules:
        ids = technique_ids(rule.tags)
        if not ids:
            untagged.append(rule.id)
            continue
        entry = {"id": rule.id, "title": rule.title, "severity": rule.level}
        for tid in ids:
            by_technique.setdefault(tid, []).append(entry)

    techniques = [
        {"technique": tid, "url": technique_url(tid), "rules": by_technique[tid]}
        for tid in sorted(by_technique)
    ]
    return {"techniques": techniques, "untagged": sorted(untagged)}
