# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Tests for the per-check mode options and their deprecated aliases.

Two properties matter here and are easy to lose. A mode given on the
command line must settle the *whole* behaviour of its check, and a check
that did not run must never be reported as clean.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest
from typer.testing import CliRunner

from gha_workflow_linter.check_modes import CheckMode
from gha_workflow_linter.cli import (
    _apply_check_modes,
    _mode_from_action_call_flags,
    _mode_from_allow_list_flags,
    app,
)
from gha_workflow_linter.exceptions import ConfigurationError
from gha_workflow_linter.models import CLIOptions, Config
from tests.conftest import strip_ansi

if TYPE_CHECKING:
    from pathlib import Path

WORKFLOW = """name: Test
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
"""


def _workspace(root: Path) -> Path:
    """Write one workflow carrying an unpinned reference.

    Args:
        root: Directory to build the repository layout under.

    Returns:
        The directory to point the linter at.
    """
    workflow = root / ".github" / "workflows" / "test.yaml"
    workflow.parent.mkdir(parents=True, exist_ok=True)
    workflow.write_text(WORKFLOW)
    return root


def _off(workspace: Path) -> list[str]:
    """Build an invocation with every check switched off.

    Args:
        workspace: Directory to point the linter at.

    Returns:
        The command-line arguments.
    """
    return [
        "lint",
        str(workspace),
        "--action-calls",
        "off",
        "--allow-list",
        "off",
    ]


class TestLegacyFlagsDescribeThemselvesAsModes:
    """The booleans are read back as a mode, not reimplemented as one.

    Deriving in this direction is what preserves every existing
    precedence rule between the command line and the configuration file
    without restating any of it.
    """

    def test_defaults_are_fix_and_report(self) -> None:
        config = Config()
        assert _mode_from_action_call_flags(config) is CheckMode.FIX
        assert _mode_from_allow_list_flags(config) is CheckMode.REPORT

    def test_disabled_fixer_is_report(self) -> None:
        config = Config(auto_fix=False)
        assert _mode_from_action_call_flags(config) is CheckMode.REPORT

    def test_updating_fixer_is_update(self) -> None:
        config = Config(auto_fix=True, update_actions=True)
        assert _mode_from_action_call_flags(config) is CheckMode.UPDATE

    def test_updating_without_a_fixer_is_report(self) -> None:
        """``update_actions`` only ever acted through the fixer.

        Reporting this as ``update`` would name work that never
        happened, which is the confusion modes exist to remove.
        """
        config = Config(auto_fix=False, update_actions=True)
        assert _mode_from_action_call_flags(config) is CheckMode.REPORT

    def test_disabled_allow_list_is_off(self) -> None:
        config = Config()
        config.allow_list.enabled = False
        assert _mode_from_allow_list_flags(config) is CheckMode.OFF

    def test_updating_allow_list_is_update(self) -> None:
        config = Config()
        config.allow_list.update = True
        assert _mode_from_allow_list_flags(config) is CheckMode.UPDATE


class TestAModeSettlesTheWholeBehaviour:
    """A mode is authoritative: the booleans are derived from it."""

    @pytest.mark.parametrize(
        ("mode", "auto_fix", "update_actions"),
        [
            (CheckMode.OFF, False, False),
            (CheckMode.REPORT, False, False),
            (CheckMode.FIX, True, False),
            (CheckMode.UPDATE, True, True),
        ],
    )
    def test_action_call_modes_derive_the_flags(
        self, mode: CheckMode, auto_fix: bool, update_actions: bool
    ) -> None:
        """Args:
        mode: The mode requested.
        auto_fix: The fixer setting it should imply.
        update_actions: The update setting it should imply.
        """
        config = Config()
        _apply_check_modes(config, CLIOptions(action_calls_mode=mode))

        assert config.action_calls_mode is mode
        assert config.auto_fix is auto_fix
        assert config.update_actions is update_actions

    def test_a_mode_overrides_a_contradictory_legacy_setting(self) -> None:
        """The command line said 'report'; the file said 'update'."""
        config = Config(auto_fix=True, update_actions=True)
        _apply_check_modes(
            config, CLIOptions(action_calls_mode=CheckMode.REPORT)
        )

        assert config.auto_fix is False
        assert config.update_actions is False

    def test_allow_list_off_disables_the_check(self) -> None:
        config = Config()
        _apply_check_modes(config, CLIOptions(allow_list_mode=CheckMode.OFF))

        assert config.allow_list.enabled is False
        assert config.allow_list.update is False

    def test_allow_list_update_enables_remediation(self) -> None:
        config = Config()
        _apply_check_modes(config, CLIOptions(allow_list_mode=CheckMode.UPDATE))

        assert config.allow_list.enabled is True
        assert config.allow_list.update is True

    def test_an_unsupported_rung_is_refused(self) -> None:
        """Refused outright rather than quietly downgraded to update."""
        config = Config()
        with pytest.raises(ConfigurationError, match="does not support"):
            _apply_check_modes(
                config, CLIOptions(allow_list_mode=CheckMode.FIX)
            )

    def test_no_mode_leaves_the_legacy_settings_alone(self) -> None:
        config = Config(auto_fix=False)
        _apply_check_modes(config, CLIOptions())

        assert config.auto_fix is False
        assert config.action_calls_mode is CheckMode.REPORT


class TestOffMeansTheCheckDoesNotRun:
    """And, crucially, is not reported as having passed."""

    def test_it_does_not_claim_the_calls_are_valid(
        self, temp_dir: Path
    ) -> None:
        """The failure this whole design exists to prevent.

        With validation skipped there are no errors to report, which is
        byte-identical to a clean repository unless the run says which
        it was.

        Args:
            temp_dir: Scratch directory for the workspace.
        """
        result = CliRunner().invoke(app, _off(_workspace(temp_dir)))
        output = strip_ansi(result.output)

        assert result.exit_code == 0
        assert "All action calls are valid" not in output
        assert "Action-call checking is off" in output

    def test_the_document_records_every_mode(self, temp_dir: Path) -> None:
        """Args:
        temp_dir: Scratch directory for the workspace.
        """
        result = CliRunner().invoke(
            app, [*_off(_workspace(temp_dir)), "--format", "json"]
        )
        document = json.loads(result.output)

        assert document["checks"] == {
            "action-calls": {"mode": "off", "ran": False},
            "allow-list": {"mode": "off", "ran": False},
        }

    def test_it_makes_no_network_request(
        self, temp_dir: Path, request: pytest.FixtureRequest
    ) -> None:
        """Both checks off must reach nothing at all.

        The suite's network guard records every attempt on the test
        node, so the recording is the evidence. Asserted rather than
        left to the teardown check, so the reason this test exists
        survives a reader.

        Args:
            temp_dir: Scratch directory for the workspace.
            request: Used to read what the guard recorded.
        """
        result = CliRunner().invoke(app, _off(_workspace(temp_dir)))

        assert result.exit_code == 0
        assert getattr(request.node, "network_attempts", []) == []

    def test_off_leaves_the_file_alone(self, temp_dir: Path) -> None:
        """The fixer is part of the check, not a stage beside it.

        Args:
            temp_dir: Scratch directory for the workspace.
        """
        workspace = _workspace(temp_dir)
        workflow = workspace / ".github" / "workflows" / "test.yaml"

        CliRunner().invoke(app, _off(workspace))

        assert workflow.read_text() == WORKFLOW


class TestDeprecatedSpellingsStillWork:
    """Superseded flags keep working, and say what replaced them."""

    def test_a_superseded_flag_names_its_replacement(
        self, temp_dir: Path
    ) -> None:
        """Args:
        temp_dir: Scratch directory for the workspace.
        """
        result = CliRunner().invoke(
            app,
            ["lint", str(temp_dir), "--no-auto-fix", "--allow-list", "off"],
        )
        output = strip_ansi(result.output)

        assert "--no-auto-fix is deprecated" in output
        assert "--action-calls report" in output

    def test_a_mode_beside_a_superseded_flag_says_which_won(
        self, temp_dir: Path
    ) -> None:
        """Silently discarding a flag the caller passed is the trap.

        Args:
            temp_dir: Scratch directory for the workspace.
        """
        result = CliRunner().invoke(app, [*_off(temp_dir), "--no-auto-fix"])
        output = strip_ansi(result.output)

        assert "ignored here" in output
        assert "--action-calls was given" in output

    def test_quiet_suppresses_the_notices(self, temp_dir: Path) -> None:
        """Args:
        temp_dir: Scratch directory for the workspace.
        """
        result = CliRunner().invoke(
            app,
            [
                "lint",
                str(temp_dir),
                "--no-auto-fix",
                "--allow-list",
                "off",
                "--quiet",
            ],
        )

        assert "deprecated" not in strip_ansi(result.output)
