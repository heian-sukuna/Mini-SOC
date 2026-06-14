"""Parser for Linux netfilter firewall logs (UFW / iptables kernel messages).

A firewall is the network's front door, and its log is where a port scan is most visible:
one source host hammering many destination ports leaves a burst of connection records. This
is the *network log source* that lets ``port-scan-001`` fire on real traffic, not just on
synthetic Sysmon telemetry.

Supported line shape — the standard syslog-wrapped netfilter format that UFW and most
iptables ``LOG`` targets emit::

    Jun 12 10:00:01 gw kernel: [12345.678] [UFW BLOCK] IN=eth0 OUT= SRC=45.155.205.7 \
        DST=10.0.0.5 PROTO=TCP SPT=44321 DPT=22 SYN

Each line is one connection the firewall saw, normalized to ``event.category = "network"``
and ``event.action = "network_connection"`` (so the source-agnostic ``port-scan-001`` rule
matches it). The firewall's verdict (block/allow) is preserved in ``event.outcome`` and in
``extra["firewall.action"]``; ``SRC``/``DST``/``DPT``/``PROTO`` map to the ECS
``source.ip`` / ``destination.ip`` / ``destination.port`` / ``network.protocol`` fields.

Tolerant generator: lines without the netfilter key/value block (no ``SRC=``) are skipped
rather than raised, so a mixed kernel log never halts the stream.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Iterator
from datetime import datetime

from minisoc.core.event import Event

__all__ = ["parse_firewall", "parse_line", "LOG_SOURCE"]

LOG_SOURCE = "firewall"
_CATEGORY = "network"

# Syslog prefix: "Mon DD HH:MM:SS host proc: <rest>" — the kernel/ufw message tail is `rest`.
_SYSLOG_RE = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+\S+?:\s+(?P<msg>.*)$"
)
# A bracketed verdict tag like "[UFW BLOCK]" / "[UFW ALLOW]", if present.
_VERDICT_RE = re.compile(r"\[(?:UFW|IPTABLES)?\s*(BLOCK|DROP|DENY|ALLOW|ACCEPT)\]", re.I)
# netfilter KEY=VALUE pairs (VALUE may be empty, e.g. "OUT=").
_KV_RE = re.compile(r"(\w+)=(\S*)")

_MONTHS = {
    m: i
    for i, m in enumerate(
        ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
         "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"],
        start=1,
    )
}

# netfilter verdict word -> (event.outcome, normalized firewall.action).
_BLOCKED = {"BLOCK", "DROP", "DENY", "REJECT"}
_ALLOWED = {"ALLOW", "ACCEPT", "PASS"}


def _parse_syslog_timestamp(ts: str, year: int) -> datetime | None:
    try:
        mon_str, day_str, clock = ts.split(maxsplit=2)
        hour, minute, second = (int(p) for p in clock.split(":"))
        return datetime(year, _MONTHS[mon_str], int(day_str), hour, minute, second)
    except (ValueError, KeyError):
        return None


def _as_int(value: object) -> int | None:
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None


def parse_line(line: str, *, year: int | None = None) -> Event | None:
    """Parse a single firewall log line into an :class:`Event`.

    Args:
        line: One raw firewall/kernel log line.
        year: Year to assume for the (year-less) syslog timestamp. Defaults to now.

    Returns:
        A normalized :class:`Event`, or ``None`` if the line carries no netfilter
        connection record (no ``SRC=``) — such lines are skipped, not raised.
    """
    line = line.rstrip("\n")
    if not line.strip():
        return None

    syslog = _SYSLOG_RE.match(line)
    msg = syslog["msg"] if syslog else line
    fields = {k.upper(): v for k, v in _KV_RE.findall(msg)}
    if "SRC" not in fields:
        return None  # not a netfilter connection record

    year = year or datetime.now().year
    timestamp = _parse_syslog_timestamp(syslog["ts"], year) if syslog else None
    host = syslog["host"] if syslog else None

    verdict_match = _VERDICT_RE.search(msg)
    verdict = verdict_match.group(1).upper() if verdict_match else None
    if verdict in _BLOCKED:
        outcome, fw_action = "failure", "blocked"
    elif verdict in _ALLOWED:
        outcome, fw_action = "success", "allowed"
    else:
        outcome, fw_action = None, "logged"

    dst, dpt = fields.get("DST"), _as_int(fields.get("DPT"))
    return Event(
        timestamp=timestamp,
        event_category=_CATEGORY,
        event_action="network_connection",
        event_outcome=outcome,
        host_name=host,
        source_ip=fields.get("SRC") or None,
        source_port=_as_int(fields.get("SPT")),
        log_source=LOG_SOURCE,
        message=f"{fw_action} {fields.get('PROTO', '?')} {fields.get('SRC')} -> {dst}:{dpt}",
        raw=line,
        extra={
            "firewall.action": fw_action,
            "destination.ip": dst or None,
            "destination.port": dpt,
            "network.protocol": (fields.get("PROTO") or "").upper() or None,
            "network.direction": "inbound" if fields.get("IN") else "outbound",
        },
    )


def parse_firewall(lines: Iterable[str], *, year: int | None = None) -> Iterator[Event]:
    """Parse an iterable of firewall log lines into normalized events.

    This is a generator: lines that aren't netfilter connection records are skipped
    silently so a single unrelated kernel message never halts the stream.

    Args:
        lines: Any iterable of raw log lines (e.g. an open file).
        year: Year to assume for year-less syslog timestamps. Defaults to now.

    Yields:
        Normalized :class:`Event` objects, one per connection record.
    """
    for line in lines:
        try:
            event = parse_line(line, year=year)
        except Exception:
            continue
        if event is not None:
            yield event
