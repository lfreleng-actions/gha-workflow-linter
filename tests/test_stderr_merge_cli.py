# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""The stderr-merge check through the command line."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING
from unittest import mock

from typer.testing import CliRunner

from gha_workflow_linter import exit_codes
from gha_workflow_linter.cli import RunOutcome, _sweep_status, app
from gha_workflow_linter.stderr_merge import (
    StderrMergeFinding,
    StderrMergeResult,
)
from tests.conftest import strip_ansi

if TYPE_CHECKING:
    from pathlib import Path

SCRIPT = """\
#!/bin/bash
out=$(curl -s x 2>&1)
if [ "$(jq -r .ok <<< "$out")" = true ]; then echo ok; fi
v=$(java -version 2>&1 | head -1)
x 2>&1 | jq .  # stderr-merge-ok -- [prints JSON on stderr]
"""


def _repository(root: Path) -> Path:
    (root / ".git").mkdir()
    (root / "scripts").mkdir()
    (root / "scripts" / "fetch.sh").write_text(SCRIPT)
    return root


def _lint(root: Path, *args: str) -> tuple[int, str]:
    result = CliRunner().invoke(
        app,
        [
            "lint",
            str(root),
            "--action-calls",
            "off",
            "--allow-list",
            "off",
            *args,
        ],
    )
    return result.exit_code, strip_ansi(result.output)


def test_text_report_names_rule_confidence_line_and_fix(
    tmp_path: Path,
) -> None:
    code, output = _lint(_repository(tmp_path))

    assert code == exit_codes.SUCCESS
    assert "scripts/fetch.sh" in output
    assert "line 2  SEM002 high  $out is parsed by jq (line 3)" in output
    assert "out=$(curl -s x 2>&1)" in output
    assert "fix: capture stdout only" in output
    assert "line 4  SEM004 low" in output
    assert "1 stderr merge(s) suppressed" in output
    assert "prints JSON on stderr" not in output


def test_show_suppressed_prints_the_reason(tmp_path: Path) -> None:
    """Square brackets in a reason are text, not Rich markup."""
    _, output = _lint(_repository(tmp_path), "--show-suppressed")

    assert "suppressed: [prints JSON on stderr]" in output


def test_quiet_prints_no_report(tmp_path: Path) -> None:
    _, output = _lint(_repository(tmp_path), "--quiet")

    assert "SEM002" not in output


def test_verify_fails_with_its_own_code(tmp_path: Path) -> None:
    code, _ = _lint(_repository(tmp_path), "--verify-stderr-merge")

    assert code == exit_codes.STDERR_MERGE_FOUND


def test_the_floor_can_be_raised_past_every_finding(tmp_path: Path) -> None:
    (tmp_path / ".git").mkdir()
    (tmp_path / "a.sh").write_text("a 2>&1 | cut -d' ' -f1\n")

    default, _ = _lint(tmp_path, "--verify-stderr-merge")
    raised, _ = _lint(
        tmp_path,
        "--verify-stderr-merge",
        "--stderr-merge-min-confidence",
        "high",
    )

    assert default == exit_codes.STDERR_MERGE_FOUND
    assert raised == exit_codes.SUCCESS


def test_off_runs_nothing(tmp_path: Path) -> None:
    code, output = _lint(
        _repository(tmp_path),
        "--stderr-merge",
        "off",
        "--verify-stderr-merge",
    )

    assert code == exit_codes.SUCCESS
    assert "SEM002" not in output


def test_named_files_are_scanned_whatever_their_name(tmp_path: Path) -> None:
    (tmp_path / ".git").mkdir()
    (tmp_path / "notes.txt").write_text("a 2>&1 | jq .\n")
    (tmp_path / "other.sh").write_text("b 2>&1 | jq .\n")

    result = CliRunner().invoke(
        app,
        [
            "lint",
            str(tmp_path),
            "--action-calls",
            "off",
            "--allow-list",
            "off",
            "--files",
            "notes.txt",
            "--format",
            "json",
        ],
    )

    findings = json.loads(result.stdout)["stderr_merge"]["findings"]
    assert [f["path"] for f in findings] == ["notes.txt"]


def test_json_output_refuses_a_named_script(tmp_path: Path) -> None:
    """A script outside the tree, read for the check, is not overwritten."""
    repository = tmp_path / "repo"
    repository.mkdir()
    (repository / ".git").mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    script = outside / "tool.sh"
    script.write_text("a 2>&1 | jq .\n")

    code, _ = _lint(
        repository, "--files", str(script), "--json-output", str(script)
    )

    assert code != exit_codes.SUCCESS
    assert script.read_text() == "a 2>&1 | jq .\n"


def test_excluded_paths_are_left_out(tmp_path: Path) -> None:
    _, output = _lint(_repository(tmp_path), "--exclude", "scripts/")

    assert "SEM002" not in output


def test_a_failed_check_does_not_stop_the_run(tmp_path: Path) -> None:
    """Advisory, it degrades; asked to enforce, it must not pass."""
    with mock.patch(
        "gha_workflow_linter.stderr_merge_report.scan_repository",
        side_effect=RuntimeError("boom"),
    ):
        advisory, _ = _lint(_repository(tmp_path))
        enforced, _ = _lint(tmp_path, "--verify-stderr-merge")

    assert advisory == exit_codes.SUCCESS
    assert enforced == exit_codes.RUNTIME_ERROR


def test_a_sweep_row_with_findings_is_not_clean() -> None:
    finding = StderrMergeFinding("a.sh", 1, "SEM001", "detail", "snippet")
    outcome = RunOutcome(
        exit_code=exit_codes.SUCCESS,
        stderr_merge=StderrMergeResult([finding], files_scanned=1),
    )

    assert "findings" in _sweep_status(outcome)
    assert "clean" in _sweep_status(RunOutcome(exit_code=0))


def test_a_sweep_row_honours_the_confidence_floor() -> None:
    """A low finding is outstanding only when the floor admits it."""
    finding = StderrMergeFinding("a.sh", 1, "SEM004", "detail", "snippet")
    result = StderrMergeResult([finding], files_scanned=1)
    enforced = RunOutcome(
        exit_code=exit_codes.STDERR_MERGE_FOUND,
        stderr_merge=result,
        stderr_merge_floor="low",
        files_changed=1,
    )
    advisory = RunOutcome(exit_code=exit_codes.SUCCESS, stderr_merge=result)

    assert "findings" in _sweep_status(enforced)
    assert "clean" in _sweep_status(advisory)


def test_a_sweep_records_the_configured_floor(tmp_path: Path) -> None:
    """The run's own floor reaches the sweep row, not the default."""
    root = tmp_path / "repos"
    (root / "one").mkdir(parents=True)
    repository = _repository(root / "one")
    (repository / "scripts" / "fetch.sh").write_text(
        "#!/bin/bash\nv=$(java -version 2>&1 | head -1)\n"
    )
    seen: list[RunOutcome] = []
    status = _sweep_status

    def record(outcome: RunOutcome) -> str:
        seen.append(outcome)
        return status(outcome)

    with mock.patch("gha_workflow_linter.cli._sweep_status", record):
        _lint(
            root,
            "--multi-repo",
            "--verify-stderr-merge",
            "--stderr-merge-min-confidence",
            "low",
        )

    assert [o.stderr_merge_floor for o in seen] == ["low"]
    assert "findings" in status(seen[0])


def test_a_sweep_row_with_scan_problems_is_incomplete() -> None:
    """A scan that could not read a file is not clean, whatever it found."""
    finding = StderrMergeFinding("a.sh", 1, "SEM001", "detail", "snippet")
    for findings in ([], [finding]):
        outcome = RunOutcome(
            exit_code=exit_codes.SUCCESS,
            stderr_merge=StderrMergeResult(
                findings, files_scanned=1, problems=("b.sh: unreadable",)
            ),
        )
        assert "incomplete" in _sweep_status(outcome)


def test_a_missing_named_file_fails_verification(tmp_path: Path) -> None:
    """A --files path that does not exist must not pass verification."""
    code, _ = _lint(
        _repository(tmp_path),
        "--files",
        "scripts/typo.sh",
        "--verify-stderr-merge",
    )

    assert code == exit_codes.RUNTIME_ERROR


def test_skip_actions_leaves_action_metadata_out(tmp_path: Path) -> None:
    """--skip-actions keeps the check off action.yml, as the scan is."""
    (tmp_path / ".git").mkdir()
    (tmp_path / "action.yml").write_text(
        "runs:\n  using: composite\n  steps:\n"
        "    - shell: bash\n      run: gh api x 2>&1 | jq .\n"
    )

    found, _ = _lint(tmp_path, "--verify-stderr-merge")
    skipped, _ = _lint(tmp_path, "--skip-actions", "--verify-stderr-merge")

    assert found == exit_codes.STDERR_MERGE_FOUND
    assert skipped == exit_codes.SUCCESS
