"""Web attack scenarios against an nginx/apache combined access log.

Three separate scenarios share one line formatter:

* ``web-shell``     — upload to an app handler, then access a planted shell under /uploads/.
* ``dir-traversal`` — path-traversal attempts to read /etc/passwd.
* ``sqli``          — SQL-injection payloads in query strings.

Each interleaves benign traffic so detections must discriminate. Log text only — nothing
is executed.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import datetime, timedelta

__all__ = [
    "generate_web_shell",
    "generate_dir_traversal",
    "generate_sqli",
    "WEB_SHELL_NAME",
    "DIR_TRAVERSAL_NAME",
    "SQLI_NAME",
]

WEB_SHELL_NAME = "web-shell"
DIR_TRAVERSAL_NAME = "dir-traversal"
SQLI_NAME = "sqli"

_ATTACKER_IP = "198.51.100.23"
_BENIGN_IP = "203.0.113.7"
_UA = "Mozilla/5.0 (X11; Linux x86_64)"
_ATTACK_UA = "curl/8.5.0"


def _line(ts: datetime, ip: str, request: str, status: int, size: int, ua: str) -> str:
    stamp = ts.strftime("%d/%b/%Y:%H:%M:%S +0000")
    return f'{ip} - - [{stamp}] "{request}" {status} {size} "-" "{ua}"'


def _benign(ts: datetime) -> list[str]:
    return [
        _line(ts, _BENIGN_IP, "GET /index.html HTTP/1.1", 200, 1734, _UA),
        _line(ts + timedelta(seconds=1), _BENIGN_IP, "GET /css/site.css HTTP/1.1", 200, 812, _UA),
    ]


def generate_web_shell(*, start: datetime | None = None) -> Iterator[str]:
    """Yield access-log lines for a web-shell upload + access."""
    now = start or datetime.now()
    yield from _benign(now)
    # Upload goes to the app's legitimate handler (not under /uploads/) -> no alert.
    yield _line(now + timedelta(seconds=3), _ATTACKER_IP,
                "POST /upload.php HTTP/1.1", 200, 51, _ATTACK_UA)
    # Accessing the planted shell under a writable dir -> SHOULD alert.
    yield _line(now + timedelta(seconds=8), _ATTACKER_IP,
                "GET /uploads/shell.php?cmd=id HTTP/1.1", 200, 64, _ATTACK_UA)


def generate_dir_traversal(*, start: datetime | None = None) -> Iterator[str]:
    """Yield access-log lines for directory-traversal attempts."""
    now = start or datetime.now()
    yield from _benign(now)
    yield _line(now + timedelta(seconds=4), _ATTACKER_IP,
                "GET /../../../../etc/passwd HTTP/1.1", 404, 153, _ATTACK_UA)
    yield _line(now + timedelta(seconds=6), _ATTACKER_IP,
                "GET /download?file=..%2f..%2f..%2fetc%2fpasswd HTTP/1.1", 200, 1022, _ATTACK_UA)


def generate_sqli(*, start: datetime | None = None) -> Iterator[str]:
    """Yield access-log lines for SQL-injection attempts."""
    now = start or datetime.now()
    yield from _benign(now)
    yield _line(now + timedelta(seconds=4), _ATTACKER_IP,
                "GET /products?id=1' OR '1'='1 HTTP/1.1", 200, 4096, _ATTACK_UA)
    yield _line(now + timedelta(seconds=7), _ATTACKER_IP,
                "GET /search?q=x' UNION SELECT username,password FROM users-- HTTP/1.1",
                500, 219, _ATTACK_UA)
