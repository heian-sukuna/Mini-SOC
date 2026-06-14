"""Scoring the detection rules against a labeled corpus.

For every case we run the real pipeline, collect which rules fired, and compare to ground
truth to build a per-rule confusion matrix:

* **TP** — an attack case fired the rule it was labeled to fire.
* **FN** — an attack case did *not* fire the rule it should have (a miss).
* **FP** — any case fired a rule it was *not* labeled for (noise — the benign corpus is
  what exercises this).
* **TN** — a case correctly did not fire a rule it was not labeled for.

From those: precision = TP/(TP+FP), recall = TP/(TP+FN), F1, and a corpus-level benign
false-positive rate (the headline SOC number). Risk-based alerting is disabled during
scoring so we measure the *detection content*, not the risk aggregation layer.
"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field
from typing import Any

from minisoc.core.config import Config
from minisoc.core.pipeline import Pipeline
from minisoc.efficacy.corpus import Case
from minisoc.risk.engine import RISK_RULE_ID

__all__ = [
    "RuleScore",
    "EfficacyReport",
    "evaluate",
    "precision",
    "recall",
    "f1_score",
]


def precision(tp: int, fp: int) -> float:
    """TP / (TP + FP); 0.0 when the rule never fired."""
    return tp / (tp + fp) if (tp + fp) else 0.0


def recall(tp: int, fn: int) -> float:
    """TP / (TP + FN); 0.0 when nothing expected the rule."""
    return tp / (tp + fn) if (tp + fn) else 0.0


def f1_score(p: float, r: float) -> float:
    """Harmonic mean of precision and recall; 0.0 when both are 0."""
    return 2 * p * r / (p + r) if (p + r) else 0.0


@dataclass
class RuleScore:
    """Per-rule confusion matrix and derived metrics."""

    rule_id: str
    tp: int = 0
    fp: int = 0
    fn: int = 0
    tn: int = 0

    @property
    def expected(self) -> int:
        """How many attack cases were labeled for this rule (TP + FN)."""
        return self.tp + self.fn

    @property
    def tested(self) -> bool:
        """Whether any case expected this rule (an untested rule has no recall signal)."""
        return self.expected > 0

    @property
    def precision(self) -> float:
        return precision(self.tp, self.fp)

    @property
    def recall(self) -> float:
        return recall(self.tp, self.fn)

    @property
    def f1(self) -> float:
        return f1_score(self.precision, self.recall)

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "tp": self.tp, "fp": self.fp, "fn": self.fn, "tn": self.tn,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1, 4),
            "tested": self.tested,
        }


@dataclass
class EfficacyReport:
    """The full efficacy result: per-rule scores plus corpus-level rollups."""

    rules: list[RuleScore] = field(default_factory=list)
    case_count: int = 0
    attack_cases: int = 0
    benign_cases: int = 0
    benign_lines: int = 0
    benign_false_positives: int = 0  # benign cases that fired any alert
    misses: list[tuple[str, str]] = field(default_factory=list)  # (case, missed rule)
    untested_rules: list[str] = field(default_factory=list)

    @property
    def totals(self) -> dict[str, int]:
        return {
            "tp": sum(r.tp for r in self.rules),
            "fp": sum(r.fp for r in self.rules),
            "fn": sum(r.fn for r in self.rules),
        }

    @property
    def micro_precision(self) -> float:
        t = self.totals
        return precision(t["tp"], t["fp"])

    @property
    def micro_recall(self) -> float:
        t = self.totals
        return recall(t["tp"], t["fn"])

    @property
    def micro_f1(self) -> float:
        return f1_score(self.micro_precision, self.micro_recall)

    @property
    def benign_fp_rate(self) -> float:
        """Fraction of benign cases that fired at least one alert (lower is better)."""
        return self.benign_false_positives / self.benign_cases if self.benign_cases else 0.0

    @property
    def fp_per_1k_lines(self) -> float:
        """False-positive alerts per 1,000 benign log lines."""
        fp = sum(r.fp for r in self.rules)
        return fp / self.benign_lines * 1000 if self.benign_lines else 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_count": self.case_count,
            "attack_cases": self.attack_cases,
            "benign_cases": self.benign_cases,
            "benign_lines": self.benign_lines,
            "micro_precision": round(self.micro_precision, 4),
            "micro_recall": round(self.micro_recall, 4),
            "micro_f1": round(self.micro_f1, 4),
            "benign_fp_rate": round(self.benign_fp_rate, 4),
            "fp_per_1k_lines": round(self.fp_per_1k_lines, 2),
            "untested_rules": self.untested_rules,
            "misses": [{"case": c, "rule": r} for c, r in self.misses],
            "rules": [r.to_dict() for r in self.rules],
        }


def _fired_rules(pipeline: Pipeline, case: Case) -> set[str]:
    """Run one case through the pipeline and return the set of rule ids that alerted."""
    events = pipeline.parse_lines(case.lines, case.source, year=case.year)
    alerts = pipeline.run_events(events)
    return {a.rule_id for a in alerts if a.rule_id != RISK_RULE_ID}


def evaluate(cases: list[Case], config: Config) -> EfficacyReport:
    """Score ``cases`` against the rules loaded by ``config``.

    A fresh pipeline is built with risk-based alerting disabled (so we measure the
    detection rules themselves). Returns a fully-populated :class:`EfficacyReport`.
    """
    # Measure detection content, not the risk aggregation layer.
    scoring_config = dataclasses.replace(config, risk={})
    pipeline = Pipeline(scoring_config)

    # The rule universe: every loaded rule/correlation/detector that can fire, plus any
    # id named in a case's `expects` (so a typo'd expectation surfaces as an all-miss row).
    universe: set[str] = {r.id for r in pipeline.tagged_rules()}
    for case in cases:
        universe.update(case.expects)

    scores = {rid: RuleScore(rid) for rid in universe}
    report = EfficacyReport()

    for case in cases:
        report.case_count += 1
        if case.is_attack:
            report.attack_cases += 1
        else:
            report.benign_cases += 1
            report.benign_lines += case.line_count

        fired = _fired_rules(pipeline, case)
        expected = set(case.expects)
        if not case.is_attack and fired:
            report.benign_false_positives += 1

        for rule_id, score in scores.items():
            want = rule_id in expected
            got = rule_id in fired
            if want and got:
                score.tp += 1
            elif want and not got:
                score.fn += 1
                report.misses.append((case.name, rule_id))
            elif not want and got:
                score.fp += 1
            else:
                score.tn += 1

    report.rules = sorted(scores.values(), key=lambda s: s.rule_id)
    # Suppressed feeders (silenced by a correlation) never emit their own alert, so a
    # missing case for them is not a coverage gap — exclude them from the untested list.
    feeders = pipeline.suppressed_rule_ids
    report.untested_rules = sorted(
        s.rule_id for s in report.rules
        if not s.tested and s.fp == 0 and s.rule_id not in feeders
    )
    return report
