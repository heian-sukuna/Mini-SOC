"""Ingest upstream SigmaHQ rules — prove the engine is the real thing.

minisoc's YAML is a deliberate *subset* of Sigma. This module loads rules written for the
full Sigma spec (e.g. a clone of `SigmaHQ/sigma <https://github.com/SigmaHQ/sigma>`_),
*translates* their field names onto minisoc's normalized event schema, and **imports the
ones the engine can actually run** — honestly reporting (and skipping) the ones that use
features minisoc doesn't implement. A handful of native rules is a demo; running community
rules unmodified is the proof.

Two jobs:

1. **Compatibility analysis** (:func:`analyze_rule`) — does this rule use only the
   subset minisoc supports? Unsupported value modifiers (``|all``, ``|base64``, ``|cidr``,
   …), keyword/full-text selections, ``null`` matches, and aggregations beyond
   ``count() by`` are detected and become skip reasons.
2. **Field translation** — upstream rules say ``Image`` / ``CommandLine`` / ``EventID``;
   minisoc events expose ``process.executable`` / ``process.command_line`` /
   ``winlog.event_id``. :data:`SIGMA_FIELD_MAP` bridges them so an imported rule resolves.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

from minisoc.detections.engine import _MODIFIERS, Aggregation, parse_condition
from minisoc.detections.rule import DEFAULT_LEVEL, Rule

__all__ = ["SIGMA_FIELD_MAP", "analyze_rule", "import_sigma_dir", "ImportReport"]

# Upstream Sigma / Windows field name -> a key minisoc's Event.get resolves.
SIGMA_FIELD_MAP = {
    "Image": "process.executable",
    "OriginalFileName": "process.executable",
    "CommandLine": "process.command_line",
    "ParentImage": "process.parent.executable",
    "ParentCommandLine": "process.parent.command_line",
    "User": "user.name",
    "EventID": "winlog.event_id",
    "Computer": "host.name",
    "SourceIp": "source.ip",
    "SourcePort": "source.port",
    "DestinationIp": "destination.ip",
    "DestinationPort": "destination.port",
    "Protocol": "network.protocol",
}

# Upstream Sigma logsource category -> minisoc's normalized ``event.category``. Sigma
# splits Windows telemetry finely (``process_creation``, ``network_connection``); minisoc's
# parsers emit coarser categories. Categories with no mapping are dropped from the imported
# rule's logsource so the field selections alone gate it (rather than never matching).
SIGMA_CATEGORY_MAP = {
    "process_creation": "process",
    "network_connection": "network",
    "process_access": "process",
    "image_load": "process",
}

_RESERVED_DETECTION_KEYS = {"condition", "timeframe"}


def _translate_logsource(logsource: dict) -> dict:
    """Map a Sigma ``logsource`` block onto minisoc's event schema.

    A known ``category`` is rewritten to its minisoc equivalent; an unknown one is
    dropped so it doesn't permanently veto the rule (the parser-level selections, e.g.
    ``winlog.event_id``, still scope it). ``product`` is informational and kept as-is.
    """
    out = dict(logsource)
    category = out.get("category")
    if category is not None:
        mapped = SIGMA_CATEGORY_MAP.get(category)
        if mapped is not None:
            out["category"] = mapped
        else:
            out.pop("category")
    return out


def _translate_field(field_spec: str) -> str:
    """Map a ``Field|modifier`` spec's field name through :data:`SIGMA_FIELD_MAP`."""
    name, sep, modifier = field_spec.partition("|")
    return SIGMA_FIELD_MAP.get(name, name) + sep + modifier


def _check_selection(spec, reasons: list[str], unmapped: set[str]) -> object:
    """Validate one selection and return it with field names translated.

    Records unsupported constructs in ``reasons`` and unmapped field names in
    ``unmapped`` (informational — they import but won't match minisoc events).
    """
    if isinstance(spec, list):
        # A list of dicts is an OR of selections; a list of scalars is a keyword/full-text
        # search, which minisoc does not implement.
        if all(isinstance(item, dict) for item in spec):
            return [_check_selection(item, reasons, unmapped) for item in spec]
        reasons.append("keyword/full-text selection (list of values) is unsupported")
        return spec
    if not isinstance(spec, dict):
        reasons.append(f"unsupported selection shape: {type(spec).__name__}")
        return spec

    translated: dict[str, object] = {}
    for field_spec, value in spec.items():
        name, _, modifier = field_spec.partition("|")
        if modifier and modifier not in _MODIFIERS:
            reasons.append(f"unsupported field modifier '|{modifier}'")
        if value is None:
            reasons.append(f"null match on '{name}' is unsupported")
        if name not in SIGMA_FIELD_MAP and "." not in name and name not in {
            "source_ip", "user_name", "process_name", "event_action", "message",
        }:
            unmapped.add(name)
        translated[_translate_field(field_spec)] = value
    return translated


@dataclass
class SigmaImportResult:
    """The outcome of analyzing one upstream Sigma file."""

    path: str
    rule: Rule | None = None
    reasons: list[str] = field(default_factory=list)
    unmapped_fields: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.rule is not None


def analyze_rule(path: str | Path, data: dict | None = None) -> SigmaImportResult:
    """Analyze (and if compatible, build) one upstream Sigma rule.

    Args:
        path: The rule file path (for diagnostics).
        data: Pre-parsed YAML; if ``None`` the file is read and parsed.

    Returns:
        A :class:`SigmaImportResult`. ``result.rule`` is set when the rule is importable;
        otherwise ``result.reasons`` explains why it was skipped.
    """
    path = Path(path)
    if data is None:
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        except yaml.YAMLError as exc:
            return SigmaImportResult(str(path), reasons=[f"invalid YAML: {exc}"])

    reasons: list[str] = []
    if not data.get("title"):
        reasons.append("missing 'title'")
    detection = data.get("detection")
    if not isinstance(detection, dict) or "condition" not in detection:
        return SigmaImportResult(str(path), reasons=reasons + ["no usable 'detection.condition'"])
    condition = detection["condition"]
    if isinstance(condition, list):
        reasons.append("multi-condition (list) rules are unsupported")

    unmapped: set[str] = set()
    selections = {}
    for name, spec in detection.items():
        if name in _RESERVED_DETECTION_KEYS:
            continue
        selections[name] = _check_selection(spec, reasons, unmapped)
    if not selections:
        reasons.append("no selections")

    # Validate the condition parses under our grammar (and any aggregation is supported).
    if isinstance(condition, str):
        try:
            parse_condition(condition)
        except ValueError as exc:
            reasons.append(f"unsupported condition: {exc}")

    if reasons:
        return SigmaImportResult(str(path), reasons=reasons, unmapped_fields=sorted(unmapped))

    rule = Rule(
        id=str(data.get("id") or path.stem),
        title=str(data["title"]),
        condition=str(condition),
        description=str(data.get("description", "")),
        level=str(data.get("level", DEFAULT_LEVEL)),
        logsource=_translate_logsource(data.get("logsource") or {}),
        selections=selections,
        timeframe=detection.get("timeframe"),
        tags=[str(t) for t in (data.get("tags") or [])],
        source_path=str(path),
    )
    return SigmaImportResult(str(path), rule=rule, unmapped_fields=sorted(unmapped))


@dataclass
class ImportReport:
    """Summary of importing a directory of upstream Sigma rules."""

    loaded: list[Rule] = field(default_factory=list)
    skipped: list[SigmaImportResult] = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.loaded) + len(self.skipped)

    @property
    def loaded_count(self) -> int:
        return len(self.loaded)


def import_sigma_dir(rules_dir: str | Path) -> ImportReport:
    """Analyze every ``.yml``/``.yaml`` Sigma rule in a directory tree.

    Args:
        rules_dir: A directory (searched recursively) of upstream Sigma rules.

    Returns:
        An :class:`ImportReport` with the importable rules and the skipped ones (each
        carrying its reasons).
    """
    rules_dir = Path(rules_dir)
    report = ImportReport()
    for file in sorted(rules_dir.rglob("*.y*ml")):
        result = analyze_rule(file)
        if result.ok:
            report.loaded.append(result.rule)
        else:
            report.skipped.append(result)
    return report
