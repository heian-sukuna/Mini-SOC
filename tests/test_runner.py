"""Tests for the shared scenario runner and config-driven source enabling.

The runner is the single code path used by both the CLI and the dashboard, so it is worth
testing directly. Each test runs against an isolated config whose paths point into a
``tmp_path`` so nothing touches the repo's ``data/`` directory.
"""

from __future__ import annotations

import pytest

from minisoc.alerting.sinks import read_jsonl
from minisoc.core.runner import run_scenario
from minisoc.scenarios.registry import store_path
from tests.util import make_config as _config


def test_run_scenario_produces_and_stores_alert(tmp_path):
    config = _config(tmp_path)
    result = run_scenario("ssh-bruteforce", config)
    assert result.scenario == "ssh-bruteforce"
    assert result.source == "auth.log"
    assert result.lines_generated > 0
    assert result.deduped_count == 1
    assert result.stored is True
    # The alert was appended to the store.
    assert len(read_jsonl(store_path(config))) == 1


def test_run_scenario_dedups_repeats(tmp_path):
    config = _config(tmp_path)
    result = run_scenario("sqli", config)
    # The sqli scenario emits two malicious requests from one IP -> dedups to one.
    assert result.raw_alert_count == 2
    assert result.deduped_count == 1
    assert result.alerts[0].occurrences == 2


def test_no_store_does_not_write(tmp_path):
    config = _config(tmp_path)
    result = run_scenario("port-scan", config, store=False)
    assert result.stored is False
    assert read_jsonl(store_path(config)) == []


def test_fresh_truncates_store(tmp_path):
    config = _config(tmp_path)
    run_scenario("ssh-bruteforce", config)
    run_scenario("port-scan", config)
    assert len(read_jsonl(store_path(config))) == 2
    # A fresh run wipes the store first.
    run_scenario("log-tampering", config, fresh=True)
    records = read_jsonl(store_path(config))
    assert len(records) == 1
    assert records[0]["rule_id"] == "log-tampering-001"


def test_disabled_source_is_rejected(tmp_path):
    # Only auth.log enabled -> a sysmon scenario must be refused.
    config = _config(tmp_path, enabled=["auth.log"])
    with pytest.raises(ValueError, match="disabled"):
        run_scenario("port-scan", config)


def test_enabled_source_runs(tmp_path):
    config = _config(tmp_path, enabled=["auth.log"])
    result = run_scenario("ssh-bruteforce", config)
    assert result.deduped_count == 1
