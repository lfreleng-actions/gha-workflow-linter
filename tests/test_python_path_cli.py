# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""The python-path check through the command line."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING
from unittest import mock

import pytest
from typer.testing import CliRunner

from gha_workflow_linter import exit_codes, python_path_report
from gha_workflow_linter.cli import RunOutcome, _sweep_status, app
from gha_workflow_linter.directives import find_suppression
from gha_workflow_linter.python_path import _engine
from gha_workflow_linter.python_path_report import (
    PythonPathFinding,
    PythonPathResult,
    _yaml_comment,
    comments,
    scan_repository,
)
from tests.conftest import strip_ansi

if TYPE_CHECKING:
    from pathlib import Path

SCRIPT = """\
#!/bin/bash
python3 -m json.tool f
python3 -I -m json.tool f
python3 -c 'import x'  # python-path-ok -- [the tool is vendored]
"""

UNRESOLVED = """\
---
runs:
  using: composite
  steps:
    - shell: bash
      run: '"$PYTHON" -I script.py'
"""


def _repository(root: Path) -> Path:
    (root / ".git").mkdir(parents=True)
    (root / "scripts").mkdir()
    (root / "scripts" / "fmt.sh").write_text(SCRIPT)
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


def _json(root: Path, *args: str) -> dict[str, object]:
    result = CliRunner().invoke(
        app,
        [
            "lint",
            str(root),
            "--action-calls",
            "off",
            "--allow-list",
            "off",
            "--format",
            "json",
            *args,
        ],
    )
    document: dict[str, object] = json.loads(result.stdout)
    return document


def test_text_report_names_rule_line_and_snippet(tmp_path: Path) -> None:
    code, output = _lint(_repository(tmp_path))

    assert code == exit_codes.SUCCESS
    assert "Python runs that take in workspace files" in output
    assert "scripts/fmt.sh" in output
    assert "line 2  PPA001  python -m without -I" in output
    assert "python3 -m json.tool f" in output
    assert "line 3" not in output
    assert "1 python-path finding(s) suppressed" in output
    assert "the tool is vendored" not in output


def test_show_suppressed_prints_the_reason(tmp_path: Path) -> None:
    """Square brackets in a reason are text, not Rich markup."""
    _, output = _lint(_repository(tmp_path), "--show-suppressed")

    assert "suppressed: [the tool is vendored]" in output


def test_quiet_prints_no_report(tmp_path: Path) -> None:
    _, output = _lint(_repository(tmp_path), "--quiet")

    assert "PPA001" not in output


def test_verify_fails_with_its_own_code(tmp_path: Path) -> None:
    code, _ = _lint(_repository(tmp_path), "--verify-python-path")

    assert code == exit_codes.PYTHON_PATH_FOUND


def test_an_unresolved_interpreter_is_a_notice(tmp_path: Path) -> None:
    """PPA009 says the scan could not prove safety; it never fails."""
    (tmp_path / ".git").mkdir()
    (tmp_path / "action.yaml").write_text(UNRESOLVED)

    code, output = _lint(tmp_path, "--verify-python-path")

    assert code == exit_codes.SUCCESS
    assert "PPA009 notice" in output


def test_off_runs_nothing(tmp_path: Path) -> None:
    code, output = _lint(
        _repository(tmp_path),
        "--python-path",
        "off",
        "--verify-python-path",
    )

    assert code == exit_codes.SUCCESS
    assert "PPA001" not in output


def test_named_files_are_scanned_whatever_their_name(tmp_path: Path) -> None:
    (tmp_path / ".git").mkdir()
    (tmp_path / "notes.txt").write_text("python3 -m json.tool f\n")
    (tmp_path / "other.sh").write_text("python3 -m json.tool g\n")

    document = _json(tmp_path, "--files", "notes.txt")

    section = document["python_path"]
    assert isinstance(section, dict)
    assert [f["path"] for f in section["findings"]] == ["notes.txt"]


def test_excluded_paths_are_left_out(tmp_path: Path) -> None:
    _, output = _lint(_repository(tmp_path), "--exclude", "scripts/")

    assert "PPA001" not in output


def test_a_failed_check_does_not_stop_the_run(tmp_path: Path) -> None:
    """Advisory, it degrades; asked to enforce, it must not pass."""
    with mock.patch(
        "gha_workflow_linter.python_path_report.scan_repository",
        side_effect=RuntimeError("boom"),
    ):
        advisory, _ = _lint(_repository(tmp_path))
        enforced, _ = _lint(tmp_path, "--verify-python-path")

    assert advisory == exit_codes.SUCCESS
    assert enforced == exit_codes.RUNTIME_ERROR


def test_a_sweep_row_with_findings_is_not_clean() -> None:
    finding = PythonPathFinding(
        "repo", "a.sh", 1, "script", "PPA001", "detail", "snippet"
    )
    outcome = RunOutcome(
        exit_code=exit_codes.SUCCESS,
        python_path=PythonPathResult([finding], files_scanned=1),
    )

    assert "findings" in _sweep_status(outcome)
    assert "clean" in _sweep_status(RunOutcome(exit_code=0))


def test_a_sweep_row_with_scan_problems_is_a_failed_scan() -> None:
    """An incomplete scan is not clean, enforced or not."""
    outcome = RunOutcome(
        exit_code=exit_codes.SUCCESS,
        python_path=PythonPathResult([], problems=("a.sh: Permission denied",)),
    )

    assert _sweep_status(outcome) == "[red]scan failed[/red]"


def test_discovery_stops_at_nested_repositories(tmp_path: Path) -> None:
    """A worktree or clone below the root is another checkout."""
    (tmp_path / ".git").mkdir()
    (tmp_path / "a.sh").write_text("python3 -m json.tool f\n")
    worktree = tmp_path / ".worktrees" / "topic"
    worktree.mkdir(parents=True)
    (worktree / ".git").write_text("gitdir: ../../.git/wt\n")
    (worktree / "a.sh").write_text("python3 -m json.tool f\n")
    clone = tmp_path / "vendor" / "lib"
    (clone / ".git").mkdir(parents=True)
    (clone / "b.sh").write_text("python3 -m json.tool f\n")

    result = scan_repository(tmp_path)

    assert [f.path for f in result.findings] == ["a.sh"]


def test_a_directive_on_the_line_above_suppresses(tmp_path: Path) -> None:
    (tmp_path / ".git").mkdir()
    (tmp_path / "a.sh").write_text(
        "# gha-workflow-linter: python-path-ok -- trusted\n"
        "python3 -m json.tool f\n"
    )

    result = scan_repository(tmp_path)

    assert [(f.rule, f.suppressed, f.reason) for f in result.findings] == [
        ("PPA001", True, "trusted")
    ]


def _action(run: str) -> str:
    return f"---\nruns:\n  using: composite\n  steps:\n    - shell: bash\n{run}"


@pytest.mark.parametrize(
    ("name", "text", "suppressed"),
    [
        ("a.sh", "python3 -m json.tool f  # python-path-ok\n", True),
        ("a.sh", "echo '# python-path-ok' && python3 -m json.tool f\n", False),
        (
            "a.sh",
            'echo "a # b" && python3 -m json.tool f # python-path-ok\n',
            True,
        ),
        ("a.sh", "echo a#python-path-ok && python3 -m json.tool f\n", False),
        (
            "a.sh",
            r"echo \# python-path-ok && python3 -m json.tool f" "\n",
            False,
        ),
        (
            "a.sh",
            'x="a\nb # python-path-ok -- x"; python3 -m json.tool f\n',
            False,
        ),
        (
            "a.sh",
            "echo $'it\\'s # python-path-ok -- x'; python3 -m json.tool f\n",
            False,
        ),
        (
            "a.sh",
            'x="a\n# gha-workflow-linter: python-path-ok\n"; '
            "python3 -m json.tool f\n",
            False,
        ),
        (
            "action.yaml",
            _action("      run: 'python3 -m json.tool f # python-path-ok'\n"),
            True,
        ),
        (
            "action.yaml",
            _action("      run: python3 -m json.tool f  # python-path-ok\n"),
            True,
        ),
        (
            "action.yaml",
            _action(
                "      run: 'python3 -m json.tool f # why'  # python-path-ok\n"
            ),
            True,
        ),
        (
            "action.yaml",
            _action(
                "      run: 'python3 -m json.tool f # python-path-ok'  # why\n"
            ),
            True,
        ),
        (
            "action.yaml",
            _action(
                "      run: |\n"
                '        x="a\n'
                '        b # python-path-ok -- x"; python3 -m json.tool f\n'
            ),
            False,
        ),
        (
            "action.yaml",
            _action(
                "      run: |\n"
                "        # gha-workflow-linter: python-path-ok -- vendored\n"
                "        python3 -m json.tool f\n"
            ),
            True,
        ),
    ],
)
def test_directives_are_read_as_shell_reads_them(
    tmp_path: Path, name: str, text: str, suppressed: bool
) -> None:
    """Only a real shell or YAML comment suppresses a finding.

    A ``#`` inside a shell string, quoted, multi-line or ANSI-C, opens
    no comment; one inside a quoted YAML ``run:`` value does.

    Args:
        tmp_path: The repository root.
        name: The file the text goes in.
        text: The file's text.
        suppressed: Whether the one PPA001 finding is suppressed.
    """
    (tmp_path / ".git").mkdir()
    (tmp_path / name).write_text(text)

    result = scan_repository(tmp_path)

    assert [(f.rule, f.suppressed) for f in result.findings] == [
        ("PPA001", suppressed)
    ]


def test_directives_on_yaml_lines_suppress(tmp_path: Path) -> None:
    """A YAML comment suppresses a setup-uv or env: PYTHONPATH finding."""
    (tmp_path / ".git").mkdir()
    (tmp_path / "action.yaml").write_text(
        "---\nruns:\n  using: composite\n  steps:\n"
        "    - uses: astral-sh/setup-uv@v6  # python-path-ok -- a\n"
        "    - shell: bash\n"
        "      env:\n"
        "        PYTHONPATH: ${{ github.workspace }}  # python-path-ok -- b\n"
        "      run: echo hi\n"
    )

    result = scan_repository(tmp_path)

    assert [(f.rule, f.suppressed, f.reason) for f in result.findings] == [
        ("PPA008", True, "a"),
        ("PPA011", True, "a"),
        ("PPA012", True, "a"),
        ("PPA005", True, "b"),
    ]


def _steps(steps: str) -> str:
    return f"---\nruns:\n  using: composite\n  steps:\n{steps}"


AFTER_RUN = "    - shell: bash\n      run: |\n        echo hi\n"


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        (
            _steps(
                AFTER_RUN
                + "    - uses: astral-sh/setup-uv@v6  # python-path-ok\n"
            ),
            [("PPA008", True), ("PPA011", True), ("PPA012", True)],
        ),
        (
            _steps(
                AFTER_RUN
                + "    # gha-workflow-linter: python-path-ok\n"
                + "    - uses: astral-sh/setup-uv@v6\n"
            ),
            [("PPA008", True), ("PPA011", True), ("PPA012", True)],
        ),
        (
            _steps(
                "    - shell: bash\n"
                "      env:\n"
                "        NOTE: |\n"
                "          text\n"
                "          # gha-workflow-linter: python-path-ok\n"
                "        PYTHONPATH: ${{ github.workspace }}\n"
                "      run: echo hi\n"
            ),
            [("PPA005", False)],
        ),
        (
            _steps(
                "    - name: |\n"
                "        x\n"
                "        # gha-workflow-linter: python-path-ok\n"
                "      uses: astral-sh/setup-uv@v6\n"
            ),
            [("PPA008", False), ("PPA011", False), ("PPA012", False)],
        ),
        (
            _steps(
                "    - name: 'x\n"
                "        # gha-workflow-linter: python-path-ok'\n"
                "      uses: astral-sh/setup-uv@v6\n"
            ),
            [("PPA008", False), ("PPA011", False), ("PPA012", False)],
        ),
        (
            _steps(
                "    - name: x  # python-path-ok\n"
                "      uses: astral-sh/setup-uv@v6\n"
            ),
            [("PPA008", False), ("PPA011", False), ("PPA012", False)],
        ),
    ],
)
def test_only_genuine_yaml_comments_suppress(
    tmp_path: Path, text: str, expected: list[tuple[str, bool]]
) -> None:
    """A directive counts only where YAML reads a comment.

    The line after a ``run: |`` block is YAML again, so a comment there
    suppresses; directive-shaped text inside a block or quoted scalar
    is part of the value and does not.

    Args:
        tmp_path: The repository root.
        text: The action's text.
        expected: Each finding's rule and whether it is suppressed.
    """
    (tmp_path / ".git").mkdir()
    (tmp_path / "action.yaml").write_text(text)

    result = scan_repository(tmp_path)

    assert [(f.rule, f.suppressed) for f in result.findings] == expected


@pytest.mark.parametrize(
    ("line", "comment"),
    [
        ("key: value  # python-path-ok", ("# python-path-ok",)),
        ("# python-path-ok", ("# python-path-ok",)),
        ("key: 'a # b'", None),
        ("key: 'it''s # b'", None),
        ('key: "a \\" # b"', None),
        ("key: it's # c", ("# c",)),
        ("key: a#b", None),
        ("key: | # c", ("# c",)),
        ("key: [a, '#b'] # c", ("# c",)),
        ("key: ['#a', b, ' #c', ' # d'] # e", ("# e",)),
        ("key: [' # a', {b: ' # c'}, ' # d'] # e", ("# e",)),
    ],
)
def test_yaml_comments(line: str, comment: tuple[str, ...] | None) -> None:
    """A quoted or mid-word ``#`` opens no YAML comment.

    Args:
        line: The first line of a document.
        comment: The comments expected on it, if any.
    """
    assert comments(f"{line}\n", "action").by_line.get(1) == comment


def test_shell_and_yaml_comments_share_a_line() -> None:
    """A quoted one-line run keeps both its shell and its YAML comment."""
    text = _action("      run: 'python3 -m json.tool f # why'  # ok\n")

    found = comments(text, "action")

    assert found.by_line[6] == ("# why", "# ok")
    assert found.yaml[6] == ("# ok",)


@pytest.mark.parametrize(
    ("line", "spans", "column"),
    [
        ("a # b", [], 2),
        ("a # b # c", [(6, 9), (0, 4)], None),
        ("a # b # c", [(0, 4), (6, 7)], None),
        ("a # b # c", [(0, 3)], 6),
        ("a # b # c", [(0, 9), (1, 2)], None),
        ("a # b # c", [(1, 2), (0, None)], None),
        ("a # b # c", [(0, 1), (2, 3)], 6),
    ],
)
def test_yaml_comment_sweeps_spans_in_any_order(
    line: str, spans: list[tuple[int, int | None]], column: int | None
) -> None:
    """Overlapping, open or unsorted spans cover each ``#`` they hold.

    Args:
        line: One line of YAML.
        spans: The columns scalars cover on it.
        column: The column the comment opens at, if any.
    """
    assert _yaml_comment(line, spans) == column


ALIASED = _steps(
    "    - &step\n"
    "      shell: bash\n"
    "      run: |\n"
    "        # gha-workflow-linter: python-path-ok -- vendored\n"
    "        python3 -m json.tool f  # why\n" + "    - *step\n" * 16
)


def test_an_aliased_step_holds_its_comments_once() -> None:
    """An alias repeats a step; its comments are still one per line."""
    found = comments(ALIASED, "action")

    assert len(found.shell) == 1
    assert found.by_line[8] == (
        "# gha-workflow-linter: python-path-ok -- vendored",
    )
    assert found.by_line[9] == ("# why",)
    assert 8 in found.leading
    assert found.shell_leading == {0: frozenset({8})}


def _counting_lookups(
    monkeypatch: pytest.MonkeyPatch,
) -> list[None]:
    """Count the directive lookups the report makes.

    Args:
        monkeypatch: Replaces the lookup for one test.

    Returns:
        A list that gains one entry per lookup.
    """
    calls: list[None] = []

    def counted(**kwargs: str | None) -> object:
        calls.append(None)
        return find_suppression(**kwargs)

    monkeypatch.setattr(python_path_report, "find_suppression", counted)
    return calls


def test_aliased_findings_share_one_directive_lookup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Repeated comments must not multiply the lookups per finding.

    Args:
        tmp_path: The repository root.
        monkeypatch: Counts the lookups.
    """
    (tmp_path / ".git").mkdir()
    (tmp_path / "action.yaml").write_text(ALIASED)
    calls = _counting_lookups(monkeypatch)

    result = scan_repository(tmp_path)

    assert len(result.findings) == 17
    assert {(f.rule, f.suppressed, f.reason) for f in result.findings} == {
        ("PPA001", True, "vendored")
    }
    assert len(calls) == 1


def test_a_flow_sequence_looks_up_its_line_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """N one-line steps on one line cost N lookups, not N squared.

    Args:
        tmp_path: The repository root.
        monkeypatch: Counts the lookups.
    """
    count = 32
    steps = ", ".join(
        f"{{shell: bash, run: 'python3 -m json.tool f # c{n}'}}"
        for n in range(count)
    )
    (tmp_path / ".git").mkdir()
    (tmp_path / "action.yaml").write_text(
        f"---\nruns:\n  using: composite\n  steps: [{steps}]\n"
    )
    calls = _counting_lookups(monkeypatch)

    result = scan_repository(tmp_path)

    assert len(result.findings) == count
    assert not any(f.suppressed for f in result.findings)
    assert len(calls) == count


def test_json_names_the_enforced_setting(tmp_path: Path) -> None:
    """The flag and the configuration file both set ``verify``."""
    repository = _repository(tmp_path / "repo")
    config = tmp_path / "config.yaml"
    config.write_text("python_path:\n  verify: true\n")

    def verify(*args: str) -> object:
        section = _json(repository, *args)["python_path"]
        assert isinstance(section, dict)
        return section["verify"]

    assert verify() is False
    assert verify("--verify-python-path") is True
    assert verify("--config", str(config)) is True


def test_findings_match_the_standalone_engine(tmp_path: Path) -> None:
    """The lint run reports what the engine's own entry point reports."""
    repository = _repository(tmp_path / "repo")
    workflows = repository / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "ci.yaml").write_text(
        "---\non: push\njobs:\n  a:\n    runs-on: x\n    steps:\n"
        "      - run: python3 -c 'import x'\n"
    )
    (repository / "action.yaml").write_text(UNRESOLVED)

    ours = {
        (f.path, f.line, f.rule) for f in scan_repository(repository).findings
    }
    theirs = {(f.path, f.line, f.rule) for f in _engine.scan([str(repository)])}

    assert ours == theirs
    assert len(ours) >= 3


@pytest.mark.parametrize(
    ("steps", "expected"),
    [
        (
            "[{run: 'python3 -m first # python-path-ok'}, "
            "{run: 'python3 -m second'}]",
            [("PPA001", True), ("PPA001", False)],
        ),
        (
            "[{run: 'python3 -m same'}, "
            "{run: 'python3 -m same # python-path-ok'}]",
            [("PPA001", False), ("PPA001", True)],
        ),
        (
            "[{run: 'python3 -m first'}, "
            "{run: 'python3 -m second'}]  # python-path-ok",
            [("PPA001", True), ("PPA001", True)],
        ),
        (
            "[{uses: astral-sh/setup-uv@v6}, "
            "{run: 'python3 -m first # python-path-ok'}]",
            [
                ("PPA001", True),
                ("PPA008", False),
                ("PPA011", False),
                ("PPA012", False),
            ],
        ),
    ],
)
def test_a_shell_directive_suppresses_its_own_step_alone(
    tmp_path: Path, steps: str, expected: list[tuple[str, bool]]
) -> None:
    """Steps sharing a line do not share each other's shell comments.

    A YAML comment after the line still covers every step on it.

    Args:
        tmp_path: The repository root.
        steps: The action's steps, on one line.
        expected: Each finding's rule, in order, and whether it is
            suppressed.
    """
    (tmp_path / ".git").mkdir()
    (tmp_path / "action.yaml").write_text(
        f"---\nruns:\n  using: composite\n  steps: {steps}\n"
    )

    result = scan_repository(tmp_path)

    assert [(f.rule, f.suppressed) for f in result.findings] == expected
    assert len({f.line for f in result.findings}) == 1


def test_a_shell_directive_above_covers_its_own_step_alone(
    tmp_path: Path,
) -> None:
    """A directive ending one ``run: |`` block is not the next step's."""
    (tmp_path / ".git").mkdir()
    (tmp_path / "action.yaml").write_text(
        _steps(
            "    - shell: bash\n"
            "      run: |\n"
            "        echo hi\n"
            "        # gha-workflow-linter: python-path-ok\n"
            "    - run: python3 -m json.tool f\n"
            "      shell: bash\n"
        )
    )

    result = scan_repository(tmp_path)

    assert [(f.rule, f.line, f.suppressed) for f in result.findings] == [
        ("PPA001", 9, False)
    ]


def test_a_shell_directive_above_covers_its_own_block(tmp_path: Path) -> None:
    """Inside one block, a comment line still covers the line below."""
    (tmp_path / ".git").mkdir()
    (tmp_path / "action.yaml").write_text(
        _steps(
            "    - shell: bash\n"
            "      run: |\n"
            "        # gha-workflow-linter: python-path-ok\n"
            "        python3 -m json.tool f\n"
        )
    )

    result = scan_repository(tmp_path)

    assert [(f.rule, f.suppressed) for f in result.findings] == [
        ("PPA001", True)
    ]


def test_equal_steps_with_different_env_are_told_apart(
    tmp_path: Path,
) -> None:
    """A step's env decides its findings, so it keys the rescan too."""
    find = "uv python find --system # python-path-ok"
    (tmp_path / ".git").mkdir()
    (tmp_path / "action.yaml").write_text(
        "---\nruns:\n  using: composite\n  steps: ["
        f"{{shell: bash, run: '{find}', env: {{UV_NO_CONFIG: '1'}}}}, "
        f"{{shell: bash, run: '{find}'}}, "
        "{shell: bash, run: 'echo hi'}]\n"
    )

    result = scan_repository(tmp_path)

    # PPA013 holds for both steps; PPA006 only for the second.
    assert [(f.rule, f.suppressed) for f in result.findings] == [
        ("PPA013", True),
        ("PPA006", True),
        ("PPA013", True),
    ]
    assert result.enforced() == []


def test_block_keys_are_built_once_per_block(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A long block's key is not rebuilt and rehashed for each line.

    Args:
        tmp_path: The repository root.
        monkeypatch: Counts the keys built.
    """
    built: list[None] = []
    real = python_path_report._key

    def counted(block: object) -> object:
        built.append(None)
        return real(block)  # type: ignore[arg-type]

    monkeypatch.setattr(python_path_report, "_key", counted)
    (tmp_path / ".git").mkdir()
    (tmp_path / "action.yaml").write_text(
        _steps(
            "    - shell: bash\n      run: |\n"
            + "        echo hi\n" * 500
            + "        python3 -m json.tool f\n"
        )
    )

    result = scan_repository(tmp_path)

    assert [f.rule for f in result.findings] == ["PPA001"]
    assert len(built) <= 2


#: A setup-uv step with every input left at its default but the
#: working directory, so PPA011 and PPA012 alone apply.
DEFAULT_SETUP_UV = (
    "- uses: astral-sh/setup-uv@v6\n"
    "  with:\n"
    "    working-directory: ${{ runner.temp }}\n"
)


def _indented(text: str, depth: int) -> str:
    return "".join(" " * depth + line for line in text.splitlines(True))


def _action_with_default_setup_uv(root: Path) -> Path:
    (root / ".git").mkdir()
    (root / "action.yaml").write_text(
        "---\nruns:\n  using: composite\n  steps:\n"
        + _indented(DEFAULT_SETUP_UV, 4)
    )
    return root


def _workflow_with_default_setup_uv(root: Path) -> Path:
    workflows = root / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (root / ".git").mkdir()
    (workflows / "ci.yaml").write_text(
        "---\non: push\njobs:\n  a:\n    runs-on: x\n    steps:\n"
        + _indented(DEFAULT_SETUP_UV, 6)
    )
    return root


def test_default_setup_uv_fails_verify_in_an_action(tmp_path: Path) -> None:
    """A composite action inherits the caller's environment."""
    code, output = _lint(
        _action_with_default_setup_uv(tmp_path), "--verify-python-path"
    )

    assert code == exit_codes.PYTHON_PATH_FOUND
    assert "PPA011  " in output
    assert "PPA012  " in output


def test_default_setup_uv_never_fails_verify_in_a_workflow(
    tmp_path: Path,
) -> None:
    """A job sees its own environment: the findings never gate."""
    code, _ = _lint(
        _workflow_with_default_setup_uv(tmp_path), "--verify-python-path"
    )

    assert code == exit_codes.SUCCESS


def test_default_setup_uv_is_reported_in_a_workflow(tmp_path: Path) -> None:
    root = _workflow_with_default_setup_uv(tmp_path)

    _, output = _lint(root, "--verify-python-path")
    rules = [f.rule for f in scan_repository(root).findings]

    assert rules == ["PPA011", "PPA012"]
    assert "PPA011 notice" in output
