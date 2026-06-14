"""Tests for replaying real/recorded log files through the pipeline.

Covers the two validation questions ``minisoc replay`` exists to answer: does it fire on
attack data it never generated, and does it stay quiet on a benign corpus?
"""

from __future__ import annotations

from pathlib import Path

import pytest

from minisoc.core.replay import ReplayResult, detect_source, replay_files
from tests.util import make_config as _config

# Six failed SSH logins from one IP inside a minute — a brute-force burst the
# ssh-bruteforce-001 rule (>= 5 failures in 5m by source.ip) must catch.
_ATTACK_AUTH = "\n".join(
    f"Jun 11 19:30:0{i} web01 sshd[12345]: "
    f"Failed password for root from 192.0.2.50 port 54321 ssh2"
    for i in range(1, 7)
) + "\n"

# Benign auth.log: a couple of successful logins and a sudo. Successful-login is a
# suppressed correlation feeder, so a clean corpus should produce zero alerts.
_BENIGN_AUTH = (
    "Jun 11 08:00:01 web01 sshd[2001]: Accepted password for alice from 10.0.0.8 port 51022 ssh2\n"
    "Jun 11 08:05:14 web01 sshd[2002]: Accepted password for bob from 10.0.0.9 port 51140 ssh2\n"
    "Jun 11 08:06:00 web01 sudo:   alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/apt update\n"
)

_ACCESS_LINE = (
    '192.0.2.7 - - [11/Jun/2026:08:00:00 +0000] "GET /index.html HTTP/1.1" 200 12 "-" "curl/8"\n'
)
_SYSMON_LINE = '{"EventID": 1, "Image": "C:\\\\Windows\\\\System32\\\\cmd.exe"}\n'


def _write(tmp_path: Path, name: str, content: str) -> Path:
    path = tmp_path / name
    path.write_text(content, encoding="utf-8")
    return path


def test_replay_attack_file_fires(tmp_path):
    config = _config(tmp_path)
    path = _write(tmp_path, "attack.log", _ATTACK_AUTH)

    result = replay_files([path], config, source="auth.log", expect="attack")

    assert isinstance(result, ReplayResult)
    assert result.events_parsed == 6
    assert any(a.rule_id == "ssh-bruteforce-001" for a in result.alerts)
    assert "DETECTED" in result.verdict


def test_replay_benign_file_is_quiet(tmp_path):
    config = _config(tmp_path)
    path = _write(tmp_path, "benign.log", _BENIGN_AUTH)

    result = replay_files([path], config, source="auth.log", expect="benign")

    assert result.alert_count == 0
    assert result.false_positives == 0
    assert result.false_positive_rate == 0.0
    assert "0 false positive" in result.verdict


def test_replay_counts_lines_and_false_positive_rate(tmp_path):
    config = _config(tmp_path)
    # One real brute force buried in benign noise -> 1 alert; the rate is per-1k lines.
    path = _write(tmp_path, "mixed.log", _BENIGN_AUTH + _ATTACK_AUTH)

    result = replay_files([path], config, source="auth.log", expect="benign")

    assert result.lines_read == 9  # 3 benign + 6 attack
    assert result.alert_count == 1
    assert result.false_positives == 1
    assert result.false_positive_rate == pytest.approx(1 / 9 * 1000)


def test_replay_aggregates_multiple_files(tmp_path):
    config = _config(tmp_path)
    a = _write(tmp_path, "a.log", _BENIGN_AUTH)
    b = _write(tmp_path, "b.log", _ATTACK_AUTH)

    result = replay_files([a, b], config, source="auth.log")

    assert len(result.files) == 2
    assert result.lines_read == 9
    assert result.alert_count == 1


def test_replay_missing_file_raises(tmp_path):
    config = _config(tmp_path)
    with pytest.raises(FileNotFoundError):
        replay_files([tmp_path / "nope.log"], config)


def test_replay_does_not_store_by_default(tmp_path):
    config = _config(tmp_path)
    path = _write(tmp_path, "attack.log", _ATTACK_AUTH)

    result = replay_files([path], config, source="auth.log")

    assert result.stored is False
    assert not (tmp_path / "generated" / "alerts.jsonl").exists()


def test_replay_stores_when_asked(tmp_path):
    config = _config(tmp_path)
    path = _write(tmp_path, "attack.log", _ATTACK_AUTH)

    result = replay_files([path], config, source="auth.log", store=True, fresh=True)

    assert result.stored is True
    assert (tmp_path / "generated" / "alerts.jsonl").exists()


def test_detect_source_auth(tmp_path):
    path = _write(tmp_path, "x.log", _BENIGN_AUTH)
    assert detect_source(path) == "auth.log"


def test_detect_source_access(tmp_path):
    path = _write(tmp_path, "x.log", _ACCESS_LINE)
    assert detect_source(path) == "access.log"


def test_detect_source_sysmon(tmp_path):
    path = _write(tmp_path, "x.json", _SYSMON_LINE)
    assert detect_source(path) == "sysmon"


def test_replay_auto_detects_source(tmp_path):
    config = _config(tmp_path)
    path = _write(tmp_path, "attack.log", _ATTACK_AUTH)

    # No explicit source -> detect_source picks auth.log -> rule still fires.
    result = replay_files([path], config)

    assert result.files[0][1] == "auth.log"
    assert result.alert_count == 1
