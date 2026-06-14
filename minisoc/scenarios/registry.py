"""The central registry of attack scenarios and their output routing.

Both the CLI (``minisoc run``) and the dashboard (``minisoc serve``) drive scenarios
through this registry, so there is one source of truth for *what scenarios exist*, *which
parser/log source each feeds*, and *where its generated log and the alert store live*.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from pathlib import Path

from minisoc.core.config import REPO_ROOT, Config
from minisoc.scenarios import (
    network_attacks,
    ssh_bruteforce,
    sudo_privesc,
    sysmon_attacks,
    web_attacks,
)

__all__ = [
    "SCENARIOS",
    "scenario_names",
    "scenario_log_path",
    "store_path",
]

# Scenario name -> (generator callable yielding log lines, log source tag).
# The log source selects the parser and the output file.
SCENARIOS: dict[str, tuple[Callable[[], Iterator[str]], str]] = {
    ssh_bruteforce.SCENARIO_NAME: (ssh_bruteforce.generate, "auth.log"),
    ssh_bruteforce.SUCCESS_SCENARIO_NAME: (ssh_bruteforce.generate_with_success, "auth.log"),
    sudo_privesc.SCENARIO_NAME: (sudo_privesc.generate, "auth.log"),
    web_attacks.WEB_SHELL_NAME: (web_attacks.generate_web_shell, "access.log"),
    web_attacks.DIR_TRAVERSAL_NAME: (web_attacks.generate_dir_traversal, "access.log"),
    web_attacks.SQLI_NAME: (web_attacks.generate_sqli, "access.log"),
    sysmon_attacks.PORT_SCAN_NAME: (sysmon_attacks.generate_port_scan, "sysmon"),
    sysmon_attacks.LOG_TAMPERING_NAME: (sysmon_attacks.generate_log_tampering, "sysmon"),
    network_attacks.FIREWALL_PORT_SCAN_NAME: (network_attacks.generate_port_scan, "firewall"),
}

# Default output filename per log source, used when config has no explicit path.
_SOURCE_FILES = {
    "auth.log": "auth.log",
    "access.log": "access.log",
    "sysmon": "sysmon.json",
    "firewall": "firewall.log",
}
# Maps a log source to the config `paths:` key that may override its output location.
_SOURCE_PATH_KEYS = {
    "auth.log": "auth_log",
    "access.log": "access_log",
    "sysmon": "sysmon_log",
    "firewall": "firewall_log",
}


def scenario_names() -> list[str]:
    """Return the available scenario names, sorted."""
    return sorted(SCENARIOS)


def scenario_log_path(config: Config, source: str) -> Path:
    """Resolve where a scenario's generated log should be written.

    Prefers an explicit per-source path from config ``paths:`` (e.g. ``auth_log``),
    otherwise falls back to ``<generated_dir>/<default filename>``.
    """
    path_key = _SOURCE_PATH_KEYS.get(source)
    if path_key and path_key in config.paths:
        return config.paths[path_key]
    # Anchor the fallback to the repo root so `minisoc` works from any directory.
    generated = config.paths.get("generated_dir", REPO_ROOT / "data" / "generated")
    return generated / _SOURCE_FILES.get(source, source)


def store_path(config: Config) -> Path:
    """Resolve the JSONL alert store path from config (with a sensible default)."""
    if "alerts_jsonl" in config.paths:
        return config.paths["alerts_jsonl"]
    generated = config.paths.get("generated_dir", REPO_ROOT / "data" / "generated")
    return generated / "alerts.jsonl"
