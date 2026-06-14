"""Configuration loading for minisoc.

The whole tool is config-driven via ``config/config.yaml``. This module loads that
file into a lightweight :class:`Config` object, resolves paths relative to the repo
root, and exposes a couple of helpers (window parsing) used across the pipeline.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

__all__ = ["Config", "load_config", "parse_window_seconds", "REPO_ROOT"]

# Repo root = three levels up from this file: minisoc/core/config.py -> repo root.
REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CONFIG_PATH = REPO_ROOT / "config" / "config.yaml"

_WINDOW_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400}


def parse_window_seconds(window: str) -> int:
    """Parse a window string like ``"5m"`` / ``"30s"`` / ``"1h"`` into seconds.

    Args:
        window: ``<int><unit>`` where unit is one of ``s``, ``m``, ``h``, ``d``.

    Returns:
        The window length in seconds.

    Raises:
        ValueError: If the string is not a recognized window format.
    """
    match = re.fullmatch(r"\s*(\d+)\s*([smhd])\s*", window)
    if not match:
        raise ValueError(f"invalid window {window!r}; expected e.g. '5m', '30s', '1h'")
    value, unit = match.groups()
    return int(value) * _WINDOW_UNITS[unit]


@dataclass
class Config:
    """Resolved minisoc configuration.

    Attributes:
        paths: Mapping of named paths (resolved to absolute :class:`Path`).
        rules_dir: Directory to load detection rules from.
        alert_window: Default aggregation window string (e.g. ``"5m"``).
        enabled_sources: Log sources/parsers that are enabled.
        live_poll_interval: Seconds between polls in ``minisoc watch``.
        live_sources: Default files for ``minisoc watch``: ``{"path": Path,
            "source": str | None}`` records (``source=None`` means auto-detect).
        enrichment: The ``enrichment:`` section — ``{"enabled": bool, "blocklist": Path,
            "geoip": Path, "assets": Path}`` (paths resolved). Consumed by
            :meth:`~minisoc.enrichment.enricher.Enricher.from_config`.
        raw: The original parsed YAML, for forward-compatibility.
    """

    paths: dict[str, Path] = field(default_factory=dict)
    rules_dir: Path = field(default_factory=lambda: REPO_ROOT / "minisoc" / "detections" / "rules")
    sigma_rules_dir: Path | None = None
    alert_window: str = "5m"
    enabled_sources: list[str] = field(default_factory=list)
    live_poll_interval: float = 2.0
    live_sources: list[dict[str, Any]] = field(default_factory=list)
    enrichment: dict[str, Any] = field(default_factory=dict)
    triage: dict[str, Any] = field(default_factory=dict)
    notifications: dict[str, Any] = field(default_factory=dict)
    risk: dict[str, Any] = field(default_factory=dict)
    dashboard: dict[str, Any] = field(default_factory=dict)
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def alert_window_seconds(self) -> int:
        """The default alert window expressed in seconds."""
        return parse_window_seconds(self.alert_window)


def _resolve(path_str: str) -> Path:
    """Resolve ``path_str`` to an absolute path under the repo root if relative."""
    path = Path(path_str)
    return path if path.is_absolute() else REPO_ROOT / path


def load_config(path: str | Path | None = None) -> Config:
    """Load configuration from ``config/config.yaml`` (or an explicit path).

    Args:
        path: Optional explicit config path. Defaults to ``config/config.yaml`` at
            the repo root. The *default* file being missing yields a :class:`Config`
            with defaults (the tool works out of the box), but an explicitly given
            path that does not exist is an error — a typo'd ``--config`` must not
            silently run with defaults.

    Returns:
        A resolved :class:`Config`.

    Raises:
        FileNotFoundError: If ``path`` was given explicitly but does not exist.
    """
    config_path = Path(path) if path else DEFAULT_CONFIG_PATH
    if path is not None and not config_path.exists():
        raise FileNotFoundError(f"config file not found: {config_path}")
    data: dict[str, Any] = {}
    if config_path.exists():
        data = yaml.safe_load(config_path.read_text()) or {}

    paths = {name: _resolve(value) for name, value in (data.get("paths") or {}).items()}

    rules_dir_str = data.get("rules_dir")
    rules_dir = _resolve(rules_dir_str) if rules_dir_str else Config().rules_dir
    if not rules_dir.exists():
        # Fall back to the packaged rules directory.
        rules_dir = REPO_ROOT / "minisoc" / "detections" / "rules"

    sigma_dir_str = data.get("sigma_rules_dir")
    sigma_rules_dir = _resolve(sigma_dir_str) if sigma_dir_str else None

    live = data.get("live") or {}
    live_sources: list[dict[str, Any]] = []
    for entry in live.get("sources") or []:
        # Each entry is either a bare path string or {path: ..., source: ...}.
        if isinstance(entry, str):
            live_sources.append({"path": _resolve(entry), "source": None})
        else:
            live_sources.append(
                {"path": _resolve(str(entry["path"])), "source": entry.get("source")}
            )

    enrichment_raw = data.get("enrichment") or {}
    enrichment: dict[str, Any] = {"enabled": bool(enrichment_raw.get("enabled", True))}
    for key in ("blocklist", "geoip", "assets"):
        if enrichment_raw.get(key):
            enrichment[key] = _resolve(str(enrichment_raw[key]))

    triage_raw = data.get("triage") or {}
    triage: dict[str, Any] = {}
    if triage_raw.get("db"):
        triage["db"] = _resolve(str(triage_raw["db"]))

    return Config(
        paths=paths,
        rules_dir=rules_dir,
        sigma_rules_dir=sigma_rules_dir,
        alert_window=data.get("alert_window", "5m"),
        enabled_sources=list(data.get("enabled_sources") or []),
        live_poll_interval=float(live.get("poll_interval", 2.0)),
        live_sources=live_sources,
        enrichment=enrichment,
        triage=triage,
        notifications=data.get("notifications") or {},
        risk=data.get("risk") or {},
        dashboard=data.get("dashboard") or {},
        raw=data,
    )
