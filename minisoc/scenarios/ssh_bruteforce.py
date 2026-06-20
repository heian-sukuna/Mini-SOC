"""Attack scenarios: SSH brute force, with and without a successful break-in.

Emits a stream of realistic ``auth.log`` lines representing an attacker repeatedly
guessing SSH passwords from a single source IP. **Nothing real is executed** — the
scenario only produces log text in the exact format the auth.log parser consumes.

Two registered scenarios share this generator:

* ``ssh-bruteforce`` — failed attempts only (the attack didn't get in).
* ``ssh-bruteforce-success`` — the same attack ending with one successful login from
  the attacker IP, which additionally fires the temporal correlation rule
  (*SSH Brute Force Followed by Successful Login*, severity critical).

The stream is intentionally noisy: it interleaves a legitimate login from another host
so the detection has to discriminate.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import datetime, timedelta

__all__ = ["generate", "generate_with_success", "SCENARIO_NAME", "SUCCESS_SCENARIO_NAME"]

SCENARIO_NAME = "ssh-bruteforce"
SUCCESS_SCENARIO_NAME = "ssh-bruteforce-success"

_HOST = "web01"
_ATTACKER_IP = "192.0.2.66"
_ATTACKER_PORT_BASE = 40000
_USERNAMES = ["root", "admin", "ubuntu", "postgres", "git", "test", "oracle", "deploy"]

# A little legitimate background traffic from a benign host.
_BENIGN_IP = "10.0.0.8"


def _fmt(ts: datetime, pid: int, message: str) -> str:
    """Format one sshd auth.log line in traditional syslog form."""
    # Traditional syslog pads the day to width 2 with a space (e.g. "Jun  1").
    stamp = f"{ts.strftime('%b')} {ts.day:2d} {ts.strftime('%H:%M:%S')}"
    return f"{stamp} {_HOST} sshd[{pid}]: {message}"


def generate(
    *,
    attempts: int = 8,
    start: datetime | None = None,
    interval_seconds: int = 20,
    succeed_after: bool = False,
) -> Iterator[str]:
    """Yield ``auth.log`` lines for an SSH brute-force attack.

    Args:
        attempts: Number of failed-login attempts from the attacker IP.
        start: Timestamp of the first attempt. Defaults to now.
        interval_seconds: Seconds between consecutive attempts.
        succeed_after: If true, append one successful login from the attacker IP at
            the end (the cracked-credential beat the correlation rule detects).

    Yields:
        Raw ``auth.log`` lines, in chronological order.
    """
    now = start or datetime.now()
    pid = 22001

    # One benign successful login before the attack, from a different IP.
    yield _fmt(
        now - timedelta(seconds=interval_seconds),
        pid,
        f"Accepted password for alice from {_BENIGN_IP} port 51022 ssh2",
    )

    for i in range(attempts):
        ts = now + timedelta(seconds=i * interval_seconds)
        user = _USERNAMES[i % len(_USERNAMES)]
        port = _ATTACKER_PORT_BASE + i
        invalid = "invalid user " if user not in ("root", "ubuntu") else ""
        yield _fmt(
            ts,
            pid + 1 + i,
            f"Failed password for {invalid}{user} from {_ATTACKER_IP} port {port} ssh2",
        )

    if succeed_after:
        ts = now + timedelta(seconds=attempts * interval_seconds)
        yield _fmt(
            ts,
            pid + 1 + attempts,
            f"Accepted password for root from {_ATTACKER_IP} port "
            f"{_ATTACKER_PORT_BASE + attempts} ssh2",
        )


def generate_with_success(
    *,
    attempts: int = 8,
    start: datetime | None = None,
    interval_seconds: int = 20,
) -> Iterator[str]:
    """The ``ssh-bruteforce-success`` scenario: the brute force that got in.

    Identical to :func:`generate` but ends with one successful login from the attacker
    IP, which fires the *SSH Brute Force Followed by Successful Login* correlation. The
    timing arguments are forwarded so callers can align this scenario with others on a
    shared timeline (e.g. correlating it with a port scan inside one risk window).
    """
    return generate(
        attempts=attempts,
        start=start,
        interval_seconds=interval_seconds,
        succeed_after=True,
    )
