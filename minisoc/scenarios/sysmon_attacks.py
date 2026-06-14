"""Sysmon-based attack scenarios, emitted as Sysmon-style JSON lines.

Two scenarios:

* ``port-scan``     — one source host opening many connections (EventID 3) in seconds.
* ``log-tampering`` — a process (EventID 1) that clears the Windows event log.

Log text only — nothing is executed.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from datetime import datetime, timedelta

__all__ = ["generate_port_scan", "generate_log_tampering", "PORT_SCAN_NAME", "LOG_TAMPERING_NAME"]

PORT_SCAN_NAME = "port-scan"
LOG_TAMPERING_NAME = "log-tampering"

_HOST = "WIN-DC01"
_SCANNER_IP = "198.51.100.77"
_TARGET_IP = "10.0.0.5"
_BENIGN_IP = "10.0.0.20"

# A realistic spread of probed service ports.
_SCAN_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143,
               443, 445, 993, 995, 1433, 3306, 3389, 5432, 5900, 8080]


def _utc(ts: datetime) -> str:
    return ts.strftime("%Y-%m-%d %H:%M:%S.") + f"{ts.microsecond // 1000:03d}"


def _network_event(ts: datetime, src_ip: str, src_port: int, dst_port: int) -> str:
    return json.dumps({
        "EventID": 3,
        "UtcTime": _utc(ts),
        "Computer": _HOST,
        "User": "NT AUTHORITY\\SYSTEM",
        "ProcessId": 4,
        "Image": "System",
        "Protocol": "tcp",
        "SourceIp": src_ip,
        "SourcePort": src_port,
        "DestinationIp": _TARGET_IP,
        "DestinationPort": dst_port,
    })


def _process_event(ts: datetime, image: str, command_line: str, parent: str) -> str:
    return json.dumps({
        "EventID": 1,
        "UtcTime": _utc(ts),
        "Computer": _HOST,
        "User": "WIN-DC01\\Administrator",
        "ProcessId": 6120,
        "Image": image,
        "CommandLine": command_line,
        "ParentImage": parent,
    })


def generate_port_scan(*, start: datetime | None = None) -> Iterator[str]:
    """Yield Sysmon JSON lines for a port scan from a single source IP."""
    now = start or datetime.now()
    # A little benign network noise from another host.
    yield _network_event(now, _BENIGN_IP, 51000, 443)
    for i, dst_port in enumerate(_SCAN_PORTS):
        ts = now + timedelta(milliseconds=200 * i)
        yield _network_event(ts, _SCANNER_IP, 40000 + i, dst_port)


def generate_log_tampering(*, start: datetime | None = None) -> Iterator[str]:
    """Yield Sysmon JSON lines for an event-log clearing action."""
    now = start or datetime.now()
    # Benign process create (should NOT alert).
    yield _process_event(
        now,
        "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "powershell.exe Get-Service",
        "C:\\Windows\\explorer.exe",
    )
    # Clearing the Security event log (SHOULD alert).
    yield _process_event(
        now + timedelta(seconds=3),
        "C:\\Windows\\System32\\wevtutil.exe",
        "wevtutil cl Security",
        "C:\\Windows\\System32\\cmd.exe",
    )
