"""Tests for the Linux auth.log parser."""

from __future__ import annotations

from minisoc.parsers.auth_log import LOG_SOURCE, parse_auth_log, parse_line

YEAR = 2026


def test_parses_failed_ssh_password():
    line = (
        "Jun 11 19:30:01 web01 sshd[12345]: Failed password for invalid user "
        "admin from 192.0.2.50 port 54321 ssh2"
    )
    event = parse_line(line, year=YEAR)
    assert event is not None
    assert event.event_category == "authentication"
    assert event.event_action == "ssh_login_failed"
    assert event.event_outcome == "failure"
    assert event.user_name == "admin"
    assert event.source_ip == "192.0.2.50"
    assert event.source_port == 54321
    assert event.process_name == "sshd"
    assert event.process_pid == 12345
    assert event.host_name == "web01"
    assert event.log_source == LOG_SOURCE
    assert event.raw == line
    # ECS dotted lookup used by detections.
    assert event.get("source.ip") == "192.0.2.50"
    assert event.get("event.action") == "ssh_login_failed"


def test_parses_accepted_ssh_password():
    line = "Jun 11 19:30:09 web01 sshd[20]: Accepted password for alice from 10.0.0.8 port 51022 ssh2"
    event = parse_line(line, year=YEAR)
    assert event is not None
    assert event.event_action == "ssh_login_success"
    assert event.event_outcome == "success"
    assert event.user_name == "alice"
    assert event.source_ip == "10.0.0.8"


def test_parses_sudo_command():
    line = (
        "Jun 11 19:31:00 web01 sudo:   alice : TTY=pts/0 ; PWD=/home/alice ; "
        "USER=root ; COMMAND=/usr/bin/apt update"
    )
    event = parse_line(line, year=YEAR)
    assert event is not None
    assert event.event_action == "sudo_command"
    assert event.user_name == "alice"
    assert event.get("sudo.target_user") == "root"
    assert event.get("sudo.command") == "/usr/bin/apt update"


def test_timestamp_parsed_with_year():
    line = "Jun 11 19:30:01 web01 sshd[1]: Failed password for root from 192.0.2.50 port 22 ssh2"
    event = parse_line(line, year=YEAR)
    assert event is not None
    assert event.timestamp is not None
    assert (event.timestamp.year, event.timestamp.month, event.timestamp.day) == (2026, 6, 11)
    assert (event.timestamp.hour, event.timestamp.minute) == (19, 30)


def test_malformed_and_irrelevant_lines_are_skipped():
    lines = [
        "this is not a syslog line at all",
        "",
        "Jun 11 19:30:01 web01 sshd[1]: Server listening on 0.0.0.0 port 22.",  # not an auth event
        "Jun 11 19:30:01 web01 CRON[99]: pam_unix(cron:session): session opened",  # other proc
        "Jun 11 19:30:02 web01 sshd[2]: Failed password for root from 192.0.2.50 port 22 ssh2",
    ]
    events = list(parse_auth_log(lines, year=YEAR))
    # Only the single real Failed-password line should yield an event.
    assert len(events) == 1
    assert events[0].event_action == "ssh_login_failed"


def test_generator_does_not_crash_on_bad_input():
    # A line that matches syslog shape but has a nonsense timestamp still must not raise.
    weird = "Zzz 99 99:99:99 web01 sshd[1]: Failed password for root from 1.2.3.4 port 22 ssh2"
    events = list(parse_auth_log([weird], year=YEAR))
    # It either parses with timestamp=None or is skipped; the point is no exception.
    assert isinstance(events, list)
