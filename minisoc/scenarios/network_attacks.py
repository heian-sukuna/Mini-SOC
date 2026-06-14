"""Network attack scenarios, emitted as Linux firewall (UFW/netfilter) log lines.

One scenario for now:

* ``firewall-port-scan`` — a single external host sweeping many service ports on an
  internal target, as the perimeter firewall sees it: a burst of ``[UFW BLOCK]`` records
  from one ``SRC`` in seconds. This is what fires ``port-scan-001`` on a *real* network
  log source (the Sysmon ``port-scan`` scenario is the endpoint-telemetry equivalent).

The scanner IP is deliberately one that is both on the bundled threat-intel blocklist and
in the GeoIP table (Russia), so the resulting alert also shows enrichment in action:
"...and this IP is known-bad, geolocated to RU."

Log text only — nothing is executed.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import datetime, timedelta

__all__ = ["generate_port_scan", "FIREWALL_PORT_SCAN_NAME"]

FIREWALL_PORT_SCAN_NAME = "firewall-port-scan"

_GATEWAY = "gw01"
_SCANNER_IP = "45.155.205.7"   # on the bundled blocklist + GeoIP -> RU
_TARGET_IP = "10.0.0.5"
_BENIGN_IP = "10.0.0.20"

# A realistic spread of probed service ports.
_SCAN_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143,
               443, 445, 993, 995, 1433, 3306, 3389, 5432, 5900, 8080]


def _ufw_line(ts: datetime, verdict: str, src: str, spt: int, dst: str, dpt: int) -> str:
    stamp = ts.strftime("%b %d %H:%M:%S")
    return (
        f"{stamp} {_GATEWAY} kernel: [{ts.timestamp():.3f}] [UFW {verdict}] "
        f"IN=eth0 OUT= SRC={src} DST={dst} LEN=60 TTL=54 PROTO=TCP "
        f"SPT={spt} DPT={dpt} SYN"
    )


def generate_port_scan(*, start: datetime | None = None) -> Iterator[str]:
    """Yield UFW firewall log lines for a port scan from a single external IP."""
    now = start or datetime.now()
    # A little benign allowed traffic from an internal host (should NOT alert).
    yield _ufw_line(now, "ALLOW", _BENIGN_IP, 51000, _TARGET_IP, 443)
    for i, dpt in enumerate(_SCAN_PORTS):
        ts = now + timedelta(milliseconds=200 * i)
        yield _ufw_line(ts, "BLOCK", _SCANNER_IP, 40000 + i, _TARGET_IP, dpt)
