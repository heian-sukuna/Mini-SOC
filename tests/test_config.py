"""Tests for configuration loading and window parsing."""

from __future__ import annotations

import pytest

from minisoc.core.config import load_config, parse_window_seconds


def test_explicit_missing_config_path_raises(tmp_path):
    # A typo'd --config must error, not silently run with defaults.
    with pytest.raises(FileNotFoundError, match="config file not found"):
        load_config(tmp_path / "nope.yaml")


def test_explicit_config_path_loads_values(tmp_path):
    cfg_file = tmp_path / "config.yaml"
    cfg_file.write_text(
        "alert_window: 2m\n"
        "enabled_sources: [auth.log]\n"
        "paths:\n"
        "  generated_dir: data/generated\n"
    )
    config = load_config(cfg_file)
    assert config.alert_window == "2m"
    assert config.alert_window_seconds == 120
    assert config.enabled_sources == ["auth.log"]
    assert config.paths["generated_dir"].is_absolute()


def test_parse_window_seconds_units():
    assert parse_window_seconds("30s") == 30
    assert parse_window_seconds("5m") == 300
    assert parse_window_seconds("1h") == 3600
    assert parse_window_seconds("1d") == 86400


def test_parse_window_seconds_rejects_garbage():
    with pytest.raises(ValueError, match="invalid window"):
        parse_window_seconds("five minutes")
