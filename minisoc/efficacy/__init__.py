"""Detection efficacy harness: measure precision/recall/FP-rate against labeled corpora.

A detection you can't measure is a detection you can't trust. This package runs the shipped
rules against a labeled corpus of attack and benign cases and reports, per rule and overall,
how often they fire when they should (recall), how often they fire when they shouldn't
(false positives / precision), and the benign false-positive rate — the headline number any
SOC lives and dies by.
"""

from __future__ import annotations

from minisoc.efficacy.corpus import Case, load_cases
from minisoc.efficacy.evaluate import (
    EfficacyReport,
    RuleScore,
    evaluate,
    f1_score,
    precision,
    recall,
)

__all__ = [
    "Case",
    "load_cases",
    "evaluate",
    "EfficacyReport",
    "RuleScore",
    "precision",
    "recall",
    "f1_score",
]
