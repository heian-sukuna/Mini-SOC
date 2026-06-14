"""Parser for Linux ``auth.log`` (syslog-style sshd + sudo events).

Emits normalized :class:`~minisoc.core.event.Event` objects with
``event.category = "authentication"`` and a normalized ``event.action`` such as
``ssh_login_failed``, ``ssh_login_success``, or ``sudo_command``.

The parser is a generator that yields one event per recognized line and **tolerates
malformed input without crashing** — unrecognized or broken lines are simply skipped.

Supported line shapes (traditional syslog, no year in the timestamp)::

    Jun 11 19:30:01 web01 sshd[12345]: Failed password for invalid user admin from 192.0.2.50 port 54321 ssh2
    Jun 11 19:30:02 web01 sshd[12345]: Failed password for root from 192.0.2.50 port 54321 ssh2
    Jun 11 19:30:09 web01 sshd[12345]: Accepted password for alice from 10.0.0.8 port 51022 ssh2
    Jun 11 19:31:00 web01 sudo:   alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/apt update
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Iterator
from datetime import datetime

from minisoc.core.event import Event

__all__ = ["parse_auth_log", "parse_line", "LOG_SOURCE"]

LOG_SOURCE = "auth.log"
_CATEGORY = "authentication"

# "Mon DD HH:MM:SS host process[pid]: message"  (pid optional; sudo has no pid here)
_SYSLOG_RE = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<proc>[\w./-]+?)(?:\[(?P<pid>\d+)\])?:\s+"
    r"(?P<msg>.*)$"
)

# sshd: "Failed password for [invalid user ]<user> from <ip> port <port> ssh2"
_SSH_FAIL_RE = re.compile(
    r"^Failed password for (?:invalid user )?(?P<user>\S+) "
    r"from (?P<ip>\S+) port (?P<port>\d+)"
)
# sshd: "Accepted password for <user> from <ip> port <port> ssh2"
_SSH_OK_RE = re.compile(
    r"^Accepted \S+ for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)"
)
# sudo: "<user> : TTY=... ; PWD=... ; USER=<target> ; COMMAND=<cmd>"
_SUDO_RE = re.compile(
    r"^\s*(?P<user>\S+)\s*:.*?USER=(?P<target>\S+)\s*;\s*COMMAND=(?P<cmd>.*)$"
)

_MONTHS = {
    m: i
    for i, m in enumerate(
        ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
         "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"],
        start=1,
    )
}


def _parse_syslog_timestamp(ts: str, year: int) -> datetime | None:
    """Parse a traditional syslog timestamp (no year) given an assumed ``year``."""
    try:
        mon_str, day_str, clock = ts.split(maxsplit=2)
        hour, minute, second = (int(p) for p in clock.split(":"))
        return datetime(year, _MONTHS[mon_str], int(day_str), hour, minute, second)
    except (ValueError, KeyError):
        return None


def parse_line(line: str, *, year: int | None = None) -> Event | None:
    """Parse a single ``auth.log`` line into an :class:`Event`.

    Args:
        line: One raw log line.
        year: Year to assume for the (year-less) syslog timestamp. Defaults to the
            current year.

    Returns:
        A normalized :class:`Event`, or ``None`` if the line is not a recognized
        sshd/sudo event (malformed or irrelevant lines are skipped, not raised).
    """
    line = line.rstrip("\n")
    if not line.strip():
        return None

    syslog = _SYSLOG_RE.match(line)
    if not syslog:
        return None

    year = year or datetime.now().year
    timestamp = _parse_syslog_timestamp(syslog["ts"], year)
    host = syslog["host"]
    proc = syslog["proc"]
    pid = int(syslog["pid"]) if syslog["pid"] else None
    msg = syslog["msg"]

    base = dict(
        timestamp=timestamp,
        event_category=_CATEGORY,
        host_name=host,
        process_name=proc,
        process_pid=pid,
        log_source=LOG_SOURCE,
        raw=line,
    )

    if proc.startswith("sshd"):
        fail = _SSH_FAIL_RE.match(msg)
        if fail:
            return Event(
                **base,
                event_action="ssh_login_failed",
                event_outcome="failure",
                user_name=fail["user"],
                source_ip=fail["ip"],
                source_port=int(fail["port"]),
                message=msg,
            )
        ok = _SSH_OK_RE.match(msg)
        if ok:
            return Event(
                **base,
                event_action="ssh_login_success",
                event_outcome="success",
                user_name=ok["user"],
                source_ip=ok["ip"],
                source_port=int(ok["port"]),
                message=msg,
            )
        return None

    if proc.startswith("sudo"):
        sudo = _SUDO_RE.match(msg)
        if sudo:
            return Event(
                **base,
                event_action="sudo_command",
                event_outcome="success",
                user_name=sudo["user"],
                message=msg,
                extra={
                    "sudo.target_user": sudo["target"],
                    "sudo.command": sudo["cmd"].strip(),
                },
            )
        return None

    return None


def parse_auth_log(lines: Iterable[str], *, year: int | None = None) -> Iterator[Event]:
    """Parse an iterable of ``auth.log`` lines into normalized events.

    This is a generator: malformed or irrelevant lines are skipped silently so a
    single bad line never halts the stream.

    Args:
        lines: Any iterable of raw log lines (e.g. an open file).
        year: Year to assume for year-less syslog timestamps. Defaults to now.

    Yields:
        Normalized :class:`Event` objects, one per recognized line.
    """
    for line in lines:
        try:
            event = parse_line(line, year=year)
        except Exception:
            # Defensive: a parser must never crash the pipeline on bad data.
            continue
        if event is not None:
            yield event
