"""Match + non-match tests for the Phase 1 detection rules.

Each rule is exercised through the real parser → engine path: raw log lines are parsed
into events, then the single relevant rule is evaluated. Every rule has a test proving it
fires on an attack and a test proving it does NOT fire on benign traffic.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from minisoc.detections.engine import DetectionEngine
from minisoc.detections.loader import load_rule
from minisoc.parsers import access_log, auth_log, sysmon

RULES_DIR = Path(__file__).resolve().parents[1] / "minisoc" / "detections" / "rules"
YEAR = 2026


def _fires(rule_file: str, events) -> bool:
    rule = load_rule(RULES_DIR / rule_file)
    alerts = DetectionEngine(default_window="5m").evaluate_rule(rule, list(events))
    return len(alerts) > 0


def _auth(lines: list[str]):
    return list(auth_log.parse_auth_log(lines, year=YEAR))


def _access(lines: list[str]):
    return list(access_log.parse_access_log(lines))


def _sysmon(records: list[dict]):
    return list(sysmon.parse_sysmon(json.dumps(r) for r in records))


# --- sudo privilege escalation --------------------------------------------------------

def test_sudo_privesc_fires_on_root_shell():
    line = ("Jun 11 19:31:00 web01 sudo:   bob : TTY=pts/0 ; PWD=/home/bob ; "
            "USER=root ; COMMAND=/bin/bash")
    assert _fires("sudo_privesc.yml", _auth([line]))


def test_sudo_privesc_ignores_benign_admin_command():
    line = ("Jun 11 19:31:00 web01 sudo:   alice : TTY=pts/0 ; PWD=/home/alice ; "
            "USER=root ; COMMAND=/usr/bin/apt update")
    assert not _fires("sudo_privesc.yml", _auth([line]))


# --- web shell ------------------------------------------------------------------------

def _acc(req: str, status: int = 200) -> str:
    return f'198.51.100.23 - - [11/Jun/2026:19:30:01 +0000] "{req}" {status} 64 "-" "curl/8"'


def test_web_shell_fires_on_shell_under_uploads():
    assert _fires("web_shell.yml", _access([_acc("GET /uploads/shell.php?cmd=id")]))


def test_web_shell_ignores_legit_upload_handler_and_static():
    benign = [_acc("POST /upload.php"), _acc("GET /index.html")]
    assert not _fires("web_shell.yml", _access(benign))


# --- directory traversal --------------------------------------------------------------

def test_dir_traversal_fires():
    assert _fires("directory_traversal.yml", _access([_acc("GET /../../../../etc/passwd", 404)]))


def test_dir_traversal_ignores_normal_path():
    assert not _fires("directory_traversal.yml", _access([_acc("GET /docs/guide.html")]))


# --- SQL injection --------------------------------------------------------------------

def test_sqli_fires():
    assert _fires("sqli_attempt.yml", _access([_acc("GET /products?id=1' OR '1'='1")]))


def test_sqli_ignores_normal_query():
    assert not _fires("sqli_attempt.yml", _access([_acc("GET /products?id=42")]))


# --- port scan ------------------------------------------------------------------------

def _net(i: int, src_ip: str = "198.51.100.77") -> dict:
    ms = (200 * i) % 1000
    sec = 30 + (200 * i) // 1000
    return {
        "EventID": 3,
        "UtcTime": f"2026-06-11 19:30:{sec:02d}.{ms:03d}",
        "Computer": "WIN-DC01",
        "Image": "System",
        "Protocol": "tcp",
        "SourceIp": src_ip,
        "SourcePort": 40000 + i,
        "DestinationIp": "10.0.0.5",
        "DestinationPort": 20 + i,
    }


def test_port_scan_fires_on_many_connections():
    records = [_net(i) for i in range(16)]
    assert _fires("port_scan.yml", _sysmon(records))


def test_port_scan_ignores_few_connections():
    records = [_net(i) for i in range(10)]
    assert not _fires("port_scan.yml", _sysmon(records))


# --- log tampering --------------------------------------------------------------------

def _proc(cmd: str, image: str = "C:\\Windows\\System32\\wevtutil.exe") -> dict:
    return {
        "EventID": 1,
        "UtcTime": "2026-06-11 19:30:01.000",
        "Computer": "WIN-DC01",
        "User": "WIN-DC01\\Administrator",
        "ProcessId": 6120,
        "Image": image,
        "CommandLine": cmd,
        "ParentImage": "C:\\Windows\\System32\\cmd.exe",
    }


def test_log_tampering_fires_on_wevtutil_clear():
    assert _fires("log_tampering.yml", _sysmon([_proc("wevtutil cl Security")]))


def test_log_tampering_ignores_benign_process():
    benign = _proc("powershell.exe Get-Service",
                   image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe")
    assert not _fires("log_tampering.yml", _sysmon([benign]))
