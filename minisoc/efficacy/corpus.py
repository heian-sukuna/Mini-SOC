"""Loading the labeled detection corpus.

A *case* is one labeled sample: some log lines, the source that parses them, a label
(``attack`` or ``benign``), and — for attack cases — the rule id(s) that *should* fire.
Cases live as small YAML files under ``datasets/efficacy/`` so the ground truth is
inspectable and version-controlled.

A case supplies its log content one of two ways:

* ``scenario: <name>`` — reuse a registered attack scenario's generator (keeps the attack
  corpus in lockstep with the scenarios, so the lines are always valid), or
* ``source: <tag>`` + ``lines: |`` — inline log lines (used for the authored benign corpus).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

from minisoc.scenarios.registry import SCENARIOS

__all__ = ["Case", "load_cases"]

_LABELS = ("attack", "benign")


@dataclass
class Case:
    """One labeled corpus sample.

    Attributes:
        name: Human label for the case.
        label: ``"attack"`` or ``"benign"``.
        expects: Rule ids that should fire (always empty for a benign case).
        source: Log source tag selecting the parser.
        lines: The raw log lines for this case.
        year: Year for year-less syslog timestamps (auth.log / firewall), if needed.
        path: The file the case was loaded from (diagnostics).
    """

    name: str
    label: str
    source: str
    lines: list[str]
    expects: list[str] = field(default_factory=list)
    year: int | None = None
    path: str | None = None

    @property
    def is_attack(self) -> bool:
        return self.label == "attack"

    @property
    def line_count(self) -> int:
        return len(self.lines)


def _case_from_data(data: dict, path: Path) -> Case:
    name = str(data.get("name") or path.stem)
    label = str(data.get("label") or "")
    if label not in _LABELS:
        raise ValueError(f"{path}: 'label' must be one of {_LABELS}, got {label!r}")

    expects = [str(r) for r in (data.get("expects") or [])]
    if label == "benign" and expects:
        raise ValueError(f"{path}: a benign case cannot 'expects' any rule to fire")

    scenario = data.get("scenario")
    if scenario:
        if scenario not in SCENARIOS:
            raise ValueError(f"{path}: unknown scenario {scenario!r}")
        generator, source = SCENARIOS[scenario]
        lines = [line.rstrip("\n") for line in generator()]
    else:
        source = data.get("source")
        if not source:
            raise ValueError(f"{path}: a case needs 'scenario', or 'source' with 'lines'/'file'")
        if data.get("file"):
            # Point at an external log file (e.g. a downloaded public dataset). A relative
            # path resolves against the case file's own directory.
            ref = Path(str(data["file"]))
            ref = ref if ref.is_absolute() else path.parent / ref
            if not ref.exists():
                raise ValueError(f"{path}: referenced log file not found: {ref}")
            raw = ref.read_text(encoding="utf-8", errors="replace")
        else:
            raw = str(data.get("lines") or "")
        lines = [line for line in raw.splitlines() if line.strip()]

    if not lines:
        raise ValueError(f"{path}: case produced no log lines")

    return Case(
        name=name,
        label=label,
        source=str(source),
        lines=lines,
        expects=expects,
        year=data.get("year"),
        path=str(path),
    )


def load_cases(corpus_dir: str | Path) -> list[Case]:
    """Load every ``*.case.yaml`` / ``*.case.yml`` under ``corpus_dir`` (recursively).

    Args:
        corpus_dir: Root of the labeled corpus tree.

    Returns:
        The parsed cases, sorted by (label, name) for a stable report ordering.

    Raises:
        ValueError: If a case file is malformed.
    """
    corpus_dir = Path(corpus_dir)
    cases: list[Case] = []
    for file in sorted(corpus_dir.rglob("*.case.y*ml")):
        data = yaml.safe_load(file.read_text(encoding="utf-8")) or {}
        cases.append(_case_from_data(data, file))
    return sorted(cases, key=lambda c: (c.label, c.name))
