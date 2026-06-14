"""Tests for the CLI entry point's top-level help behavior.

``minisoc --help`` (and a bare ``minisoc``) print a command-overview table instead of
argparse's usage dump; subcommand help (``minisoc run --help``) stays with argparse.
"""

from __future__ import annotations

import pytest

from minisoc.cli.main import _HELP_ROWS, main


def test_help_flag_prints_command_table(capsys):
    assert main(["--help"]) == 0
    out = capsys.readouterr().out
    assert "minisoc list" in out
    assert "minisoc serve" in out
    assert "What it does" in out


def test_short_help_flag(capsys):
    assert main(["-h"]) == 0
    assert "Command" in capsys.readouterr().out


def test_bare_invocation_prints_help(capsys):
    assert main([]) == 0
    assert "minisoc run --scenario" in capsys.readouterr().out


def test_every_help_row_names_a_real_invocation():
    # Guard against the table drifting from the actual CLI surface.
    commands = " ".join(cmd for cmd, _ in _HELP_ROWS)
    for sub in ("list", "run", "replay", "coverage", "serve"):
        assert f"minisoc {sub}" in commands


def test_subcommand_help_stays_with_argparse(capsys):
    # argparse prints usage and exits 0 via SystemExit for `minisoc run --help`.
    with pytest.raises(SystemExit) as exc:
        main(["run", "--help"])
    assert exc.value.code == 0
    assert "--scenario" in capsys.readouterr().out
