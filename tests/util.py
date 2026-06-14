"""Shared test helpers."""

from __future__ import annotations

from pathlib import Path

from minisoc.core.config import Config


def make_config(
    tmp_path: Path,
    *,
    enabled: list[str] | None = None,
    risk: dict | None = None,
    dashboard: dict | None = None,
) -> Config:
    """An isolated :class:`Config` whose paths all point inside ``tmp_path``.

    Used by the runner, dashboard, and correlation tests so scenario runs never touch
    the repo's ``data/`` directory.

    Args:
        tmp_path: The test's temporary directory (pytest ``tmp_path`` fixture).
        enabled: Value for ``enabled_sources`` (``None`` -> all sources enabled).
        risk: Optional ``risk:`` section (e.g. ``{"enabled": True, "threshold": 100}``).
        dashboard: Optional ``dashboard:`` section (e.g. Basic-auth credentials).
    """
    gen = tmp_path / "generated"
    return Config(
        paths={
            "generated_dir": gen,
            "auth_log": gen / "auth.log",
            "access_log": gen / "access.log",
            "sysmon_log": gen / "sysmon.json",
            "alerts_jsonl": gen / "alerts.jsonl",
        },
        alert_window="5m",
        enabled_sources=enabled or [],
        risk=risk or {},
        dashboard=dashboard or {},
    )
