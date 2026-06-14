"""Tests for the detection efficacy harness — metrics, confusion matrix, and the corpus.

The headline test runs the *shipped* corpus through the *shipped* rules and asserts no
missed detections and no benign false positives — the regression guard that lets the project
claim measured precision/recall. The rest prove the scorer actually catches misses and FPs
(an always-green harness would be worthless).
"""

from __future__ import annotations

import pytest

from minisoc.core.config import REPO_ROOT, load_config
from minisoc.efficacy import evaluate, f1_score, load_cases, precision, recall
from minisoc.efficacy.corpus import Case, _case_from_data
from pathlib import Path

_CORPUS = REPO_ROOT / "datasets" / "efficacy"


# -- metric helpers ----------------------------------------------------------------------


def test_metric_helpers_and_zero_division_safety():
    assert precision(8, 2) == 0.8
    assert recall(6, 4) == 0.6
    assert f1_score(0.5, 0.5) == 0.5
    # No firing / no expectation must not raise.
    assert precision(0, 0) == 0.0
    assert recall(0, 0) == 0.0
    assert f1_score(0.0, 0.0) == 0.0


# -- confusion matrix on hand-built cases ------------------------------------------------


def _benign(name, source, lines):
    return Case(name=name, label="benign", source=source, lines=lines)


def _attack(name, source, lines, expects, year=None):
    return Case(name=name, label="attack", source=source, lines=lines, expects=expects, year=year)


def test_benign_case_that_fires_is_counted_as_a_false_positive():
    # A "benign" sample containing a traversal payload should fire the rule -> FP.
    poisoned = _benign("poisoned", "access.log", [
        '1.2.3.4 - - [12/Jun/2026:08:00:00 +0000] "GET /../../etc/passwd HTTP/1.1" 200 10 "-" "x"'
    ])
    report = evaluate([poisoned], load_config())
    trav = next(r for r in report.rules if r.rule_id == "directory-traversal-001")
    assert trav.fp == 1
    assert report.benign_false_positives == 1
    assert report.benign_fp_rate == 1.0


def test_attack_case_that_does_not_fire_is_a_miss():
    # Normal request but labeled to fire sqli -> the rule misses -> FN + recorded miss.
    mislabeled = _attack("quiet", "access.log", [
        '1.2.3.4 - - [12/Jun/2026:08:00:00 +0000] "GET /home HTTP/1.1" 200 10 "-" "x"'
    ], expects=["sqli-attempt-001"])
    report = evaluate([mislabeled], load_config())
    sqli = next(r for r in report.rules if r.rule_id == "sqli-attempt-001")
    assert sqli.fn == 1 and sqli.tp == 0
    assert ("quiet", "sqli-attempt-001") in report.misses
    assert sqli.recall == 0.0


def test_true_positive_scores_perfectly():
    attack = _attack("trav", "access.log", [
        '9.9.9.9 - - [12/Jun/2026:08:00:00 +0000] "GET /a/..%2f..%2fetc/passwd HTTP/1.1" 404 5 "-" "x"'
    ], expects=["directory-traversal-001"])
    report = evaluate([attack], load_config())
    trav = next(r for r in report.rules if r.rule_id == "directory-traversal-001")
    assert trav.tp == 1 and trav.fp == 0 and trav.fn == 0
    assert trav.precision == 1.0 and trav.recall == 1.0 and trav.f1 == 1.0


def test_suppressed_feeder_is_not_reported_as_an_untested_gap():
    # ssh-login-success-001 never emits (correlation feeder) -> excluded from untested.
    attack = _attack("trav", "access.log", [
        '9.9.9.9 - - [12/Jun/2026:08:00:00 +0000] "GET /a/..%2fetc/passwd HTTP/1.1" 404 5 "-" "x"'
    ], expects=["directory-traversal-001"])
    report = evaluate([attack], load_config())
    assert "ssh-login-success-001" not in report.untested_rules


# -- corpus loading ----------------------------------------------------------------------


def test_corpus_loader_rejects_benign_case_with_expectations(tmp_path):
    bad = tmp_path / "x.case.yaml"
    with pytest.raises(ValueError):
        _case_from_data({"label": "benign", "source": "auth.log", "lines": "x",
                         "expects": ["ssh-bruteforce-001"]}, bad)


def test_corpus_loader_rejects_unknown_scenario(tmp_path):
    with pytest.raises(ValueError):
        _case_from_data({"label": "attack", "scenario": "nope"}, tmp_path / "x.case.yaml")


def test_corpus_loader_reads_an_external_file(tmp_path):
    log = tmp_path / "benign.log"
    log.write_text("line one\nline two\n", encoding="utf-8")
    case = _case_from_data(
        {"label": "benign", "source": "auth.log", "file": "benign.log"},
        tmp_path / "x.case.yaml",
    )
    assert case.line_count == 2


def test_corpus_loader_errors_on_missing_referenced_file(tmp_path):
    with pytest.raises(ValueError):
        _case_from_data(
            {"label": "benign", "source": "auth.log", "file": "nope.log"},
            tmp_path / "x.case.yaml",
        )


def test_corpus_loader_expands_a_scenario(tmp_path):
    case = _case_from_data(
        {"label": "attack", "scenario": "ssh-bruteforce", "expects": ["ssh-bruteforce-001"]},
        tmp_path / "x.case.yaml",
    )
    assert case.source == "auth.log" and case.line_count > 5


# -- the regression guard: shipped corpus vs shipped rules -------------------------------


def test_shipped_corpus_loads():
    cases = load_cases(_CORPUS)
    assert len(cases) >= 12
    assert any(c.is_attack for c in cases) and any(not c.is_attack for c in cases)


def test_shipped_rules_have_no_misses_and_no_false_positives():
    report = evaluate(load_cases(_CORPUS), load_config())
    assert report.misses == [], f"unexpected missed detections: {report.misses}"
    assert report.benign_false_positives == 0, "a benign case fired an alert"
    assert report.micro_precision == 1.0
    assert report.micro_recall == 1.0
