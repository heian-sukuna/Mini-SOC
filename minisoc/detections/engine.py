"""A from-scratch detection engine implementing a practical subset of Sigma.

This is intentionally *not* a wrapper around pySigma — the point is to implement the
internals. It supports the slice of the Sigma spec minisoc needs:

* **logsource matching** — a rule applies only to events whose ``log.source`` and
  ``event.category`` (etc.) match the rule's ``logsource`` block.
* **selections** — named groups of field matchers. Within a selection, all fields must
  match (AND); a field whose value is a list matches if any value matches (OR).
* **field modifiers** — ``contains``, ``startswith``, ``endswith``, ``re`` via the
  ``field|modifier: value`` syntax. No modifier means exact (case-insensitive) equality.
* **condition** — a boolean expression over selection names supporting ``and``/``or``/
  ``not``, parentheses, and the ``1 of ...`` / ``all of ...`` quantifiers (with ``them``
  or a ``prefix*`` pattern).
* **aggregation** — a trailing ``| count() by <field> <op> <n>`` pipe, evaluated as a
  sliding window of width ``timeframe``. This is what threshold rules (e.g. SSH brute
  force) use.

The engine is event-list based: :meth:`DetectionEngine.evaluate_rule` takes all events
and returns the alerts that fired. Per-event boolean rules emit one alert per matching
event; aggregation rules emit one alert per group that crosses the threshold.
"""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass
from functools import lru_cache

from minisoc.alerting.alert import Alert
from minisoc.core.config import parse_window_seconds
from minisoc.core.event import Event
from minisoc.detections.rule import Rule

__all__ = ["DetectionEngine", "Aggregation", "parse_condition"]


# --------------------------------------------------------------------------------------
# Field matching (selections + modifiers)
# --------------------------------------------------------------------------------------

_MODIFIERS = {"contains", "startswith", "endswith", "re"}

# Upper bound on a ``|re`` pattern's length. The ``re`` modifier runs Python's backtracking
# engine, so a pattern from an *imported* (untrusted) rule could hang on a crafted log line
# (catastrophic backtracking / ReDoS). We can't bound backtracking without a different regex
# engine, but we cap pattern size and compile defensively so a hostile or malformed pattern
# is skipped (matching nothing) instead of crashing the run. Review imported ``|re`` rules.
_MAX_RE_PATTERN = 1024
_warned_patterns: set[str] = set()


@lru_cache(maxsize=512)
def _compile_re(pattern: str) -> re.Pattern[str] | None:
    """Compile a rule-supplied regex once, or return ``None`` if it is unusable.

    A pattern that is over-long or does not compile is rejected (and warned about once)
    rather than raised — one bad rule must never take down the whole detection run.
    """
    if len(pattern) > _MAX_RE_PATTERN:
        _warn_pattern(pattern, "pattern too long")
        return None
    try:
        return re.compile(pattern)
    except re.error as exc:
        _warn_pattern(pattern, str(exc))
        return None


def _warn_pattern(pattern: str, reason: str) -> None:
    if pattern not in _warned_patterns:
        _warned_patterns.add(pattern)
        print(
            f"minisoc: skipping invalid regex in rule ({reason}): {pattern[:80]!r}",
            file=sys.stderr,
        )


def _match_scalar(event_value: object, expected: object, modifier: str | None) -> bool:
    """Match a single event value against one expected value under a modifier."""
    if event_value is None:
        return False
    actual = str(event_value)
    if modifier == "re":
        compiled = _compile_re(str(expected))
        return compiled is not None and compiled.search(actual) is not None

    a, e = actual.lower(), str(expected).lower()
    if modifier == "contains":
        return e in a
    if modifier == "startswith":
        return a.startswith(e)
    if modifier == "endswith":
        return a.endswith(e)
    # Exact, case-insensitive equality (numbers compared as strings too).
    return a == e


def _match_field(event: Event, field_spec: str, expected: object) -> bool:
    """Match one ``field|modifier`` spec. List ``expected`` is OR'd."""
    if "|" in field_spec:
        field_name, modifier = field_spec.split("|", 1)
        if modifier not in _MODIFIERS:
            raise ValueError(f"unsupported field modifier: {modifier!r}")
    else:
        field_name, modifier = field_spec, None

    event_value = event.get(field_name)
    expected_values = expected if isinstance(expected, list) else [expected]
    return any(_match_scalar(event_value, exp, modifier) for exp in expected_values)


def _match_selection(event: Event, spec: object) -> bool:
    """Match an event against a single selection spec.

    A selection is a mapping of ``field|modifier -> value`` where all entries must
    match (AND). A list-of-maps selection matches if any map matches (OR).
    """
    if isinstance(spec, list):
        return any(_match_selection(event, item) for item in spec)
    if isinstance(spec, dict):
        return all(_match_field(event, field_spec, expected) for field_spec, expected in spec.items())
    raise ValueError(f"unsupported selection spec: {spec!r}")


# --------------------------------------------------------------------------------------
# Condition expression parsing & evaluation
# --------------------------------------------------------------------------------------
#
# Grammar (recursive descent):
#   expr     := or_expr
#   or_expr  := and_expr ('or' and_expr)*
#   and_expr := not_expr ('and' not_expr)*
#   not_expr := 'not' not_expr | atom
#   atom     := '(' expr ')' | quantifier | IDENT
#   quantifier := ('1' | 'all') 'of' ('them' | PATTERN)
#
# Each node evaluates to a bool given a dict {selection_name: bool}.


class _Node:
    def eval(self, results: dict[str, bool]) -> bool:  # pragma: no cover - interface
        raise NotImplementedError


@dataclass
class _Ident(_Node):
    name: str

    def eval(self, results: dict[str, bool]) -> bool:
        return results.get(self.name, False)


@dataclass
class _Not(_Node):
    child: _Node

    def eval(self, results: dict[str, bool]) -> bool:
        return not self.child.eval(results)


@dataclass
class _And(_Node):
    children: list[_Node]

    def eval(self, results: dict[str, bool]) -> bool:
        return all(c.eval(results) for c in self.children)


@dataclass
class _Or(_Node):
    children: list[_Node]

    def eval(self, results: dict[str, bool]) -> bool:
        return any(c.eval(results) for c in self.children)


@dataclass
class _Quantifier(_Node):
    """``1 of ...`` / ``all of ...`` over selection names matching a pattern."""

    quant: str  # "1" or "all"
    pattern: str  # "them" or "prefix*" or an exact name

    def _matching(self, results: dict[str, bool]) -> list[bool]:
        if self.pattern == "them":
            names = list(results)
        elif self.pattern.endswith("*"):
            prefix = self.pattern[:-1]
            names = [n for n in results if n.startswith(prefix)]
        else:
            names = [n for n in results if n == self.pattern]
        return [results[n] for n in names]

    def eval(self, results: dict[str, bool]) -> bool:
        vals = self._matching(results)
        if not vals:
            return False
        return all(vals) if self.quant == "all" else any(vals)


def _tokenize(expr: str) -> list[str]:
    """Split a condition string into tokens (parentheses are their own tokens)."""
    return re.findall(r"\(|\)|[^\s()]+", expr)


class _ConditionParser:
    """Recursive-descent parser for the search part of a condition string."""

    def __init__(self, tokens: list[str]) -> None:
        self._tokens = tokens
        self._pos = 0

    def _peek(self) -> str | None:
        return self._tokens[self._pos] if self._pos < len(self._tokens) else None

    def _next(self) -> str:
        tok = self._tokens[self._pos]
        self._pos += 1
        return tok

    def parse(self) -> _Node:
        node = self._parse_or()
        if self._peek() is not None:
            raise ValueError(f"unexpected token in condition: {self._peek()!r}")
        return node

    def _parse_or(self) -> _Node:
        children = [self._parse_and()]
        while self._peek() == "or":
            self._next()
            children.append(self._parse_and())
        return children[0] if len(children) == 1 else _Or(children)

    def _parse_and(self) -> _Node:
        children = [self._parse_not()]
        while self._peek() == "and":
            self._next()
            children.append(self._parse_not())
        return children[0] if len(children) == 1 else _And(children)

    def _parse_not(self) -> _Node:
        if self._peek() == "not":
            self._next()
            return _Not(self._parse_not())
        return self._parse_atom()

    def _parse_atom(self) -> _Node:
        tok = self._peek()
        if tok is None:
            raise ValueError("unexpected end of condition")
        if tok == "(":
            self._next()
            node = self._parse_or()
            if self._peek() != ")":
                raise ValueError("missing closing ')' in condition")
            self._next()
            return node
        if tok in ("1", "all"):
            return self._parse_quantifier()
        return _Ident(self._next())

    def _parse_quantifier(self) -> _Node:
        quant = self._next()  # "1" or "all"
        if self._peek() != "of":
            raise ValueError(f"expected 'of' after {quant!r} in condition")
        self._next()
        pattern = self._next()
        return _Quantifier(quant=quant, pattern=pattern)


def parse_condition(condition: str) -> tuple[_Node, "Aggregation | None"]:
    """Parse a full condition string into a search AST and optional aggregation.

    Args:
        condition: e.g. ``"selection"`` or ``"selection | count() by source.ip >= 5"``.

    Returns:
        A ``(search_ast, aggregation)`` tuple; ``aggregation`` is ``None`` for plain
        boolean rules.
    """
    if "|" in condition:
        search_part, agg_part = condition.split("|", 1)
        aggregation = Aggregation.parse(agg_part)
    else:
        search_part, aggregation = condition, None

    ast = _ConditionParser(_tokenize(search_part)).parse()
    return ast, aggregation


# --------------------------------------------------------------------------------------
# Aggregation (windowed threshold)
# --------------------------------------------------------------------------------------

_OPS = {
    ">": lambda a, b: a > b,
    ">=": lambda a, b: a >= b,
    "<": lambda a, b: a < b,
    "<=": lambda a, b: a <= b,
    "==": lambda a, b: a == b,
}

_AGG_RE = re.compile(
    r"^\s*count\(\s*\)\s*(?:by\s+(?P<field>[\w.@]+)\s+)?(?P<op>>=|<=|==|>|<)\s*(?P<n>\d+)\s*$"
)


@dataclass
class Aggregation:
    """A ``count() by <field> <op> <n>`` aggregation clause.

    Attributes:
        by_field: ECS field to group by (``None`` = a single global group).
        op: Comparison operator string.
        threshold: Integer threshold to compare the per-group count against.
    """

    by_field: str | None
    op: str
    threshold: int

    @classmethod
    def parse(cls, text: str) -> "Aggregation":
        """Parse the aggregation tail (the part after ``|``)."""
        match = _AGG_RE.match(text)
        if not match:
            raise ValueError(f"unsupported aggregation: {text.strip()!r}")
        return cls(by_field=match["field"], op=match["op"], threshold=int(match["n"]))

    def compare(self, count: int) -> bool:
        """Return whether ``count`` satisfies the threshold."""
        return _OPS[self.op](count, self.threshold)


# --------------------------------------------------------------------------------------
# Engine
# --------------------------------------------------------------------------------------


class DetectionEngine:
    """Evaluates :class:`Rule` objects against streams of events.

    Args:
        default_window: Fallback window string used by aggregation rules that do not
            declare their own ``timeframe``.
    """

    def __init__(self, default_window: str = "5m") -> None:
        self._default_window = default_window

    # -- public API --------------------------------------------------------------------

    def evaluate(self, rules: list[Rule], events: list[Event]) -> list[Alert]:
        """Evaluate every rule against all events and return the fired alerts."""
        alerts: list[Alert] = []
        for rule in rules:
            alerts.extend(self.evaluate_rule(rule, events))
        return alerts

    def evaluate_rule(self, rule: Rule, events: list[Event]) -> list[Alert]:
        """Evaluate a single rule against all events.

        Args:
            rule: The rule to evaluate.
            events: All candidate events.

        Returns:
            Alerts produced by this rule (possibly empty).
        """
        ast, aggregation = parse_condition(rule.condition)

        # Filter to events that match the rule's logsource and the boolean search.
        matching = [
            event
            for event in events
            if self._logsource_matches(rule, event) and self._search_matches(rule, ast, event)
        ]
        if not matching:
            return []

        if aggregation is None:
            return [self._make_alert(rule, [event], group=None) for event in matching]
        return self._evaluate_aggregation(rule, aggregation, matching)

    # -- internals ---------------------------------------------------------------------

    @staticmethod
    def _logsource_matches(rule: Rule, event: Event) -> bool:
        """Match a rule's ``logsource`` block against an event.

        ``category`` is matched against ``event.category``; ``service`` against
        ``process.name`` (with prefix tolerance, so ``sshd[123]`` matches ``sshd``);
        ``product`` is treated as an informational tag and not strictly enforced
        (our normalized events don't carry an OS field yet).
        """
        ls = rule.logsource
        if not ls:
            return True
        if "category" in ls and event.event_category != ls["category"]:
            return False
        if "service" in ls:
            proc = event.process_name or ""
            if not proc.startswith(ls["service"]):
                return False
        return True

    def _search_matches(self, rule: Rule, ast: _Node, event: Event) -> bool:
        """Evaluate the boolean search AST for a single event."""
        results = {name: _match_selection(event, spec) for name, spec in rule.selections.items()}
        return ast.eval(results)

    def _evaluate_aggregation(
        self, rule: Rule, aggregation: Aggregation, matching: list[Event]
    ) -> list[Alert]:
        """Evaluate a windowed threshold rule and return one alert per crossing group."""
        window = parse_window_seconds(rule.timeframe or self._default_window)

        groups: dict[object, list[Event]] = {}
        for event in matching:
            key = event.get(aggregation.by_field) if aggregation.by_field else "__all__"
            groups.setdefault(key, []).append(event)

        alerts: list[Alert] = []
        for key, group_events in groups.items():
            window_events = self._first_window_crossing(group_events, aggregation, window)
            if window_events is not None:
                alerts.append(self._make_alert(rule, window_events, group=key))
        return alerts

    @staticmethod
    def _first_window_crossing(
        events: list[Event], aggregation: Aggregation, window_seconds: int
    ) -> list[Event] | None:
        """Find the first sliding window in which the count crosses the threshold.

        Uses a two-pointer sweep over timestamp-sorted events. Returns the events in
        the qualifying window, or ``None`` if the threshold is never met.
        """
        timed = sorted((e for e in events if e.timestamp is not None), key=lambda e: e.timestamp)
        # Events without a usable timestamp can't be windowed; treat them as a single
        # unbounded bucket so the rule still fires if the count alone qualifies.
        if not timed:
            return events if aggregation.compare(len(events)) else None

        start = 0
        for end in range(len(timed)):
            while (timed[end].timestamp - timed[start].timestamp).total_seconds() > window_seconds:
                start += 1
            count = end - start + 1
            if aggregation.compare(count):
                return timed[start : end + 1]
        return None

    @staticmethod
    def _make_alert(rule: Rule, events: list[Event], group: object) -> Alert:
        """Construct an :class:`Alert` from a rule and its matched events."""
        latest = max(
            (e.timestamp for e in events if e.timestamp is not None),
            default=None,
        )
        source = events[0].log_source if events else None
        return Alert(
            rule_id=rule.id,
            rule_title=rule.title,
            severity=rule.level,
            timestamp=latest,
            events=list(events),
            source=source,
            group_value=None if group in (None, "__all__") else group,
            description=rule.description,
        )
