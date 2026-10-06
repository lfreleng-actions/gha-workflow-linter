# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""``report`` detects outdated action calls (issue #388).

Currency detection lived inside the fixer, and ``report`` switched the
fixer off because it must not write. So
``--action-calls report --verify-action-calls`` never reported an
outdated call and always exited ``0``: a false all-clear from the
natural way to audit pins without touching files.

The end-to-end tests drive the real ``lint`` command and the real fixer,
with only its network lookups answered here: the newest release of every
repository, the SHA each reference resolves to, and validation's
``ls-remote``. Every assertion about a finding is paired with a control
that has none, so a run that reported everything, or nothing, fails.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from gha_workflow_linter import cli, exit_codes
from gha_workflow_linter.action_call_fix import AutoFixer
from gha_workflow_linter.check_modes import CheckMode
from gha_workflow_linter.cli import app
from gha_workflow_linter.models import (
    ActionCall,
    ActionCallType,
    CLIOptions,
    Config,
    ReferenceType,
    ValidationError,
    ValidationResult,
)
from tests.conftest import SHA_ANSWERING_EVERY_LOOKUP

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

#: The SHA every pinned call names, and every lookup of an existing
#: reference returns, so validation finds the pin genuine.
PINNED = SHA_ANSWERING_EVERY_LOOKUP

#: The commit a newer release resolves to.
NEWER = "b" * 40

#: A workflow pinned to a release that is genuine but not the newest.
WORKFLOW = f"""\
name: CI
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@{PINNED}  # v4.0.0
"""


def _repository(root: Path) -> Path:
    """Write a repository holding the pinned workflow.

    Args:
        root: Directory to populate.

    Returns:
        The workflow file.
    """
    workflow = root / ".github" / "workflows" / "ci.yml"
    workflow.parent.mkdir(parents=True)
    workflow.write_text(WORKFLOW)
    return workflow


@pytest.fixture
def newest(monkeypatch: pytest.MonkeyPatch) -> Iterator[dict[str, str]]:
    """Answer the fixer's lookups with a settable newest release.

    Yields:
        A mapping holding ``version`` and ``sha``; a test sets it to the
        pinned release for an up-to-date tree, or leaves the newer one.
    """
    release = {"version": "v9.9.9", "sha": NEWER}

    async def latest(_self: AutoFixer, keys: list[str]) -> dict[str, Any]:
        """Report the configured release as every repository's newest.

        Args:
            _self: The fixer, unused.
            keys: Repositories asked about.

        Returns:
            A version and SHA for each.
        """
        return dict.fromkeys(keys, (release["version"], release["sha"]))

    async def shas(
        _self: AutoFixer, refs: list[tuple[str, str]]
    ) -> dict[tuple[str, str], str]:
        """Resolve the pinned version to the pin, anything else to newer.

        Args:
            _self: The fixer, unused.
            refs: ``(repository, reference)`` pairs to resolve.

        Returns:
            A SHA for each pair.
        """
        return {
            ref: PINNED if ref[1] == "v4.0.0" else release["sha"]
            for ref in refs
        }

    monkeypatch.setattr(AutoFixer, "_get_latest_versions_batch", latest)
    monkeypatch.setattr(AutoFixer, "_get_shas_batch", shas)
    yield release


def _lint(root: Path, *args: str) -> Any:
    """Run ``lint`` on ``root`` with nothing but the action-call check.

    Args:
        root: Path to scan.
        args: Further options.

    Returns:
        The CliRunner result.
    """
    return CliRunner().invoke(
        app,
        [
            "lint",
            str(root),
            "--no-cache",
            "--cooldown",
            "0",
            "--allow-list",
            "off",
            *args,
        ],
    )


@pytest.mark.usefixtures("mock_git_commands", "no_repository_redirect")
class TestReportFindsOutdatedCalls:
    """The issue's acceptance criteria, through the real command."""

    def test_verify_fails_on_an_outdated_call_without_writing(
        self, tmp_path: Path, newest: dict[str, str]
    ) -> None:
        """Listed, exit 5, and the file is byte-identical afterwards."""
        workflow = _repository(tmp_path)

        result = _lint(
            tmp_path, "--action-calls", "report", "--verify-action-calls"
        )

        assert result.exit_code == exit_codes.ACTIONS_OUTDATED, result.output
        assert "outdated" in result.output
        assert workflow.read_text() == WORKFLOW

    def test_report_lists_it_and_stays_advisory(
        self, tmp_path: Path, newest: dict[str, str]
    ) -> None:
        """Without ``--verify-action-calls`` the finding is shown, not failed."""
        workflow = _repository(tmp_path)

        result = _lint(tmp_path, "--action-calls", "report")

        assert result.exit_code == exit_codes.SUCCESS, result.output
        assert "Found 1 outdated action call" in result.output
        assert workflow.read_text() == WORKFLOW

    def test_json_output_fails_the_same_way(
        self, tmp_path: Path, newest: dict[str, str]
    ) -> None:
        """JSON forces quiet output; detection must not depend on it."""
        _repository(tmp_path)

        result = _lint(
            tmp_path,
            "--action-calls",
            "report",
            "--verify-action-calls",
            "--format",
            "json",
        )

        document = json.loads(result.stdout)
        assert result.exit_code == exit_codes.ACTIONS_OUTDATED
        assert document["checks"]["action-calls"] == {
            "mode": "report",
            "ran": True,
        }

    def test_an_up_to_date_tree_passes(
        self, tmp_path: Path, newest: dict[str, str]
    ) -> None:
        """The control: nothing newer, nothing reported, exit 0."""
        newest.update(version="v4.0.0", sha=PINNED)
        _repository(tmp_path)

        result = _lint(
            tmp_path, "--action-calls", "report", "--verify-action-calls"
        )

        assert result.exit_code == exit_codes.SUCCESS, result.output
        assert "outdated action call" not in result.output

    def test_fix_mode_still_reports_and_does_not_advance(
        self, tmp_path: Path, newest: dict[str, str]
    ) -> None:
        """What ``fix`` always did, and what ``report`` now matches."""
        workflow = _repository(tmp_path)

        result = _lint(
            tmp_path, "--action-calls", "fix", "--verify-action-calls"
        )

        assert result.exit_code == exit_codes.ACTIONS_OUTDATED, result.output
        assert workflow.read_text() == WORKFLOW

    def test_off_still_examines_nothing(
        self, tmp_path: Path, newest: dict[str, str]
    ) -> None:
        """``off`` does not run the check, so it cannot fail on it."""
        _repository(tmp_path)

        with patch.object(AutoFixer, "find_outdated", create=True) as found:
            result = _lint(
                tmp_path, "--action-calls", "off", "--verify-action-calls"
            )

        assert result.exit_code == exit_codes.SUCCESS, result.output
        found.assert_not_called()


def _call(line: int, reference: str, comment: str | None) -> ActionCall:
    """Build a ``uses:`` call to ``actions/checkout``.

    Args:
        line: Line number.
        reference: The reference after ``@``.
        comment: Trailing version comment, if any.

    Returns:
        The call.
    """
    suffix = f"  # {comment}" if comment else ""
    return ActionCall(
        raw_line=f"      - uses: actions/checkout@{reference}{suffix}",
        line_number=line,
        organization="actions",
        repository="checkout",
        reference=reference,
        comment=f"# {comment}" if comment else None,
        call_type=ActionCallType.ACTION,
        reference_type=(
            ReferenceType.COMMIT_SHA
            if len(reference) == 40
            else ReferenceType.TAG
        ),
    )


@pytest.mark.usefixtures("no_repository_redirect")
class TestDetectionMatchesFixMode:
    """``report`` finds exactly what ``fix`` would report, no more."""

    @pytest.mark.asyncio
    async def test_the_same_calls_are_outdated(
        self, tmp_path: Path, newest: dict[str, str]
    ) -> None:
        """Outdated, invalid, unpinned and test calls, judged both ways.

        An invalid reference and an unpinned tag are defects ``fix``
        repairs rather than reports, and a call marked as a test is left
        alone; none of them may surface as outdated in ``report``.
        """
        path = tmp_path / "ci.yml"
        calls = {
            path: {
                1: _call(1, PINNED, "v4.0.0"),
                2: _call(2, "v4", None),
                3: _call(3, "not-a-ref", None),
                4: _call(4, PINNED, "v4.0.0").model_copy(
                    update={
                        "raw_line": (
                            f"      - uses: actions/checkout@{PINNED}"
                            "  # v4.0.0 testing"
                        ),
                        "comment": "# v4.0.0 testing",
                    }
                ),
            }
        }
        errors = [
            ValidationError(
                file_path=path,
                action_call=calls[path][2],
                result=ValidationResult.NOT_PINNED_TO_SHA,
            ),
            ValidationError(
                file_path=path,
                action_call=calls[path][3],
                result=ValidationResult.INVALID_REFERENCE,
            ),
        ]
        config = Config()

        async with AutoFixer(config, base_path=tmp_path) as fixer:
            with patch.object(
                AutoFixer, "_apply_fixes_to_file", return_value=[]
            ):
                (
                    _fixed,
                    _redirects,
                    from_fix,
                ) = await fixer.fix_validation_errors(errors, calls)
        async with AutoFixer(config, base_path=tmp_path) as fixer:
            from_report = await fixer.find_outdated(errors, calls)

        assert from_report == from_fix
        assert [entry["line"] for entry in from_report["ci.yml"]] == [1]


class TestAnUnansweredQuestionIsNotAPass:
    """``--verify-action-calls`` asks a question in ``report`` too."""

    def test_a_throttled_report_run_says_it_could_not_look(
        self, tmp_path: Path
    ) -> None:
        """Rate-limited, the run must not claim the pins are current."""
        config = Config()
        cli._apply_check_modes(
            config, CLIOptions(action_calls_mode=CheckMode.REPORT)
        )

        assert cli._demanded_an_answer(
            CLIOptions(path=tmp_path, verify_actions=True), config
        )

    def test_off_still_asks_nothing(self, tmp_path: Path) -> None:
        """The control: a check that does not run asks no question."""
        config = Config()
        cli._apply_check_modes(
            config, CLIOptions(action_calls_mode=CheckMode.OFF)
        )

        assert not cli._demanded_an_answer(
            CLIOptions(path=tmp_path, verify_actions=True), config
        )

    def test_a_detection_stage_that_failed_fails_a_verifying_run(
        self, tmp_path: Path
    ) -> None:
        """Looking and crashing is not looking and finding nothing."""
        config = Config()
        cli._apply_check_modes(
            config, CLIOptions(action_calls_mode=CheckMode.REPORT)
        )
        outcome = cli._AutoFixOutcome(
            {},
            {"actions_moved": 0, "calls_updated": 0},
            {},
            stage_error="boom",
        )

        code = cli._determine_exit_code(
            CLIOptions(path=tmp_path, verify_actions=True),
            cli._ValidationOutcome({}, [], None, 0),  # type: ignore[arg-type]
            outcome,
            config,
        )

        assert code != exit_codes.SUCCESS

    def test_a_failed_stage_stays_advisory_without_verification(
        self, tmp_path: Path
    ) -> None:
        """The control: a default run must not fail on a network blip."""
        config = Config()
        cli._apply_check_modes(
            config, CLIOptions(action_calls_mode=CheckMode.REPORT)
        )
        outcome = cli._AutoFixOutcome(
            {},
            {"actions_moved": 0, "calls_updated": 0},
            {},
            stage_error="boom",
        )

        code = cli._determine_exit_code(
            CLIOptions(path=tmp_path),
            cli._ValidationOutcome({}, [], None, 0),  # type: ignore[arg-type]
            outcome,
            config,
        )

        assert code == exit_codes.SUCCESS
