"""Tests for live mode: tailing real log files and alerting continuously.

Covers the :class:`~minisoc.core.live.FileTail` mechanics (append-only reads, rotation,
partial lines) and the :class:`~minisoc.core.live.LiveMonitor` semantics — detections
fire on newly appended lines, carry ``mode="live"``, persist to the store, and do not
re-alert every poll while the same pattern keeps matching.
"""

from __future__ import annotations

from pathlib import Path

from minisoc.alerting.sinks import JsonlSink, read_jsonl
from minisoc.core.live import FileTail, LiveMonitor
from minisoc.scenarios.registry import store_path
from tests.util import make_config as _config


def _fail_line(second: int, ip: str = "192.0.2.50") -> str:
    return (
        f"Jun 11 19:30:{second:02d} web01 sshd[12345]: "
        f"Failed password for root from {ip} port 54321 ssh2\n"
    )


def _burst(ip: str = "192.0.2.50", *, start: int = 1, n: int = 6) -> str:
    """n failed SSH logins from one IP inside a minute — crosses the brute-force rule."""
    return "".join(_fail_line(start + i, ip) for i in range(n))


# --------------------------------------------------------------------------------------
# FileTail
# --------------------------------------------------------------------------------------


def test_tail_skips_existing_lines_by_default(tmp_path):
    log = tmp_path / "x.log"
    log.write_text("old line\n", encoding="utf-8")
    tail = FileTail(log, "auth.log")
    assert tail.read_new() == []

    with open(log, "a", encoding="utf-8") as f:
        f.write("new line\n")
    assert tail.read_new() == ["new line"]


def test_tail_from_start_reads_existing_lines(tmp_path):
    log = tmp_path / "x.log"
    log.write_text("old line\n", encoding="utf-8")
    tail = FileTail(log, "auth.log", from_start=True)
    assert tail.read_new() == ["old line"]


def test_tail_tolerates_missing_file_until_it_appears(tmp_path):
    log = tmp_path / "later.log"
    tail = FileTail(log, "auth.log")
    assert tail.read_new() == []

    log.write_text("first\n", encoding="utf-8")
    assert tail.read_new() == ["first"]


def test_tail_restarts_after_truncation(tmp_path):
    log = tmp_path / "x.log"
    log.write_text("a\nb\nc\n", encoding="utf-8")
    tail = FileTail(log, "auth.log", from_start=True)
    tail.read_new()

    # Rotation/copytruncate: the file shrinks; the new content must be read from 0.
    log.write_text("ok\n", encoding="utf-8")
    assert tail.read_new() == ["ok"]


def test_tail_restarts_after_rename_rotation(tmp_path):
    log = tmp_path / "x.log"
    log.write_text("a\nb\nc\n", encoding="utf-8")
    tail = FileTail(log, "auth.log", from_start=True)
    tail.read_new()

    # logrotate-style: the file is moved aside and a new one (new inode) appears,
    # even one at least as large as the old read offset.
    log.rename(tmp_path / "x.log.1")
    log.write_text("brand new file\n", encoding="utf-8")
    assert tail.read_new() == ["brand new file"]


def test_tail_buffers_partial_lines(tmp_path):
    log = tmp_path / "x.log"
    log.write_text("", encoding="utf-8")
    tail = FileTail(log, "auth.log")

    with open(log, "a", encoding="utf-8") as f:
        f.write("half a li")  # no newline yet — must not be handed to a parser
    assert tail.read_new() == []

    with open(log, "a", encoding="utf-8") as f:
        f.write("ne\n")
    assert tail.read_new() == ["half a line"]


# --------------------------------------------------------------------------------------
# LiveMonitor
# --------------------------------------------------------------------------------------


def _monitor(tmp_path: Path, log: Path, *, store: bool = False) -> LiveMonitor:
    config = _config(tmp_path)
    sinks = [JsonlSink(store_path(config))] if store else []
    return LiveMonitor(config, [FileTail(log, "auth.log")], sinks=sinks)


def test_live_alert_fires_on_appended_attack(tmp_path):
    log = tmp_path / "auth.log"
    log.write_text("", encoding="utf-8")
    monitor = _monitor(tmp_path, log)

    assert monitor.poll_once() == []  # nothing happened yet

    with open(log, "a", encoding="utf-8") as f:
        f.write(_burst())
    alerts = monitor.poll_once()

    assert [a.rule_id for a in alerts] == ["ssh-bruteforce-001"]
    assert alerts[0].mode == "live"
    assert monitor.lines_read == 6
    assert monitor.alerts_emitted == 1


def test_live_does_not_realert_within_dedup_window(tmp_path):
    log = tmp_path / "auth.log"
    log.write_text("", encoding="utf-8")
    monitor = _monitor(tmp_path, log)

    with open(log, "a", encoding="utf-8") as f:
        f.write(_burst())
    assert len(monitor.poll_once()) == 1

    # The attack continues: more failures from the same IP inside the dedup window.
    with open(log, "a", encoding="utf-8") as f:
        f.write(_burst(start=10))
    assert monitor.poll_once() == []
    assert monitor.alerts_emitted == 1


def test_live_distinct_attackers_alert_separately(tmp_path):
    log = tmp_path / "auth.log"
    log.write_text("", encoding="utf-8")
    monitor = _monitor(tmp_path, log)

    with open(log, "a", encoding="utf-8") as f:
        f.write(_burst("192.0.2.50"))
    assert len(monitor.poll_once()) == 1

    # A second source IP is a different dedup key — it must alert on its own.
    with open(log, "a", encoding="utf-8") as f:
        f.write(_burst("198.51.100.9", start=20))
    second = monitor.poll_once()
    assert len(second) == 1
    assert second[0].group_value == "198.51.100.9"


def test_live_alerts_persist_to_store_with_mode(tmp_path):
    log = tmp_path / "auth.log"
    log.write_text("", encoding="utf-8")
    config = _config(tmp_path)
    monitor = _monitor(tmp_path, log, store=True)

    with open(log, "a", encoding="utf-8") as f:
        f.write(_burst())
    monitor.poll_once()

    records = read_jsonl(store_path(config))
    assert len(records) == 1
    assert records[0]["rule_id"] == "ssh-bruteforce-001"
    assert records[0]["mode"] == "live"


def test_live_poll_with_no_new_lines_is_quiet(tmp_path):
    log = tmp_path / "auth.log"
    log.write_text(_burst(), encoding="utf-8")  # pre-existing attack is *not* read
    monitor = _monitor(tmp_path, log)

    assert monitor.poll_once() == []
    assert monitor.events_parsed == 0
