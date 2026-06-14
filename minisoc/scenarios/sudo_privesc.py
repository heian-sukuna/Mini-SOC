"""Attack scenario: sudo privilege escalation.

Emits ``auth.log`` sudo lines: some benign administrative sudo usage as noise, then a
suspicious escalation to a root shell. Produces log text only.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import datetime, timedelta

__all__ = ["generate", "SCENARIO_NAME"]

SCENARIO_NAME = "sudo-privesc"
_HOST = "web01"


def _sudo(ts: datetime, user: str, target: str, command: str) -> str:
    stamp = f"{ts.strftime('%b')} {ts.day:2d} {ts.strftime('%H:%M:%S')}"
    return (
        f"{stamp} {_HOST} sudo:   {user} : TTY=pts/0 ; PWD=/home/{user} ; "
        f"USER={target} ; COMMAND={command}"
    )


def generate(*, start: datetime | None = None) -> Iterator[str]:
    """Yield ``auth.log`` lines for a sudo privilege-escalation scenario.

    Args:
        start: Timestamp of the first line. Defaults to now.

    Yields:
        Raw ``auth.log`` lines in chronological order.
    """
    now = start or datetime.now()
    # Benign administrative sudo (should NOT alert).
    yield _sudo(now, "alice", "root", "/usr/bin/apt update")
    yield _sudo(now + timedelta(seconds=5), "alice", "root", "/usr/bin/systemctl status nginx")
    # Suspicious: dropping into an interactive root shell (SHOULD alert).
    yield _sudo(now + timedelta(seconds=12), "bob", "root", "/bin/bash")
