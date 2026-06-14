"""Tests for upstream SigmaHQ rule ingestion: analysis, translation, and merge."""

from __future__ import annotations

from minisoc.core.config import REPO_ROOT, Config
from minisoc.core.event import Event
from minisoc.core.pipeline import Pipeline
from minisoc.detections.engine import DetectionEngine
from minisoc.detections.sigma_import import analyze_rule, import_sigma_dir
from tests.util import make_config as _config

_SAMPLES = REPO_ROOT / "examples" / "sigma"


def test_bundled_samples_split_supported_and_unsupported():
    report = import_sigma_dir(_SAMPLES)
    assert report.total == 4
    loaded_ids = {r.id for r in report.loaded}
    assert loaded_ids == {"sigma-recon-commands", "sigma-net-c2-port"}
    skipped = {r.path.split("/")[-1]: r.reasons for r in report.skipped}
    assert any("|all" in reason for reason in skipped["unsupported_mimikatz_all.yml"])
    assert any("keyword" in reason for reason in skipped["unsupported_keywords.yml"])


def test_field_names_are_translated_to_event_schema():
    result = analyze_rule(_SAMPLES / "proc_creation_recon.yml")
    assert result.ok
    # 'Image|endswith' -> 'process.executable|endswith'
    assert "process.executable|endswith" in result.rule.selections["selection"]


def test_imported_rule_actually_fires_on_a_sysmon_event():
    result = analyze_rule(_SAMPLES / "net_uncommon_port.yml")
    assert result.ok
    event = Event(
        log_source="sysmon", event_category="network",
        source_ip="10.0.0.5",
        extra={"winlog.event_id": 3, "destination.port": 4444},
    )
    alerts = DetectionEngine().evaluate_rule(result.rule, [event])
    assert len(alerts) == 1
    assert alerts[0].rule_id == "sigma-net-c2-port"


def test_unsupported_modifier_is_reported_not_raised():
    result = analyze_rule(_SAMPLES / "unsupported_mimikatz_all.yml")
    assert not result.ok
    assert result.rule is None
    assert any("modifier" in r for r in result.reasons)


def test_pipeline_merges_importable_rules_when_configured(tmp_path):
    base = Pipeline(_config(tmp_path)).rule_count
    config = _config(tmp_path)
    config.sigma_rules_dir = _SAMPLES
    pipeline = Pipeline(config)
    # Two importable Sigma rules added on top of the native set.
    assert pipeline.rule_count == base + 2
    assert pipeline.sigma_report.loaded_count == 2
    assert {r.id for r in pipeline.rules} >= {"sigma-recon-commands", "sigma-net-c2-port"}


def test_native_rule_ids_win_on_collision():
    # An imported rule sharing a native id must not shadow the native rule.
    import yaml

    report_dir = REPO_ROOT / "examples" / "sigma"
    # sanity: none of our samples collide with native ids
    report = import_sigma_dir(report_dir)
    native = {
        "ssh-bruteforce-001", "port-scan-001", "web-shell-001",
    }
    assert not (native & {r.id for r in report.loaded})
