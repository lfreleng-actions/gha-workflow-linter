# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""PPA014: a Python a composite action finds on the caller's PATH.

A composite action inherits its caller's ``PATH``, so a Python started
by bare name runs whichever interpreter the caller's earlier steps put
first. The rule reports one unless an earlier step of the same file
runs ``actions/setup-python``. Workflow files and scripts get none: a
job's ``PATH`` is its own, and a script's caller is unknown.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from gha_workflow_linter import exit_codes
from gha_workflow_linter.cli import app
from gha_workflow_linter.python_path import _engine as audit
from gha_workflow_linter.python_path_report import ACTION_ENFORCEABLE_RULES
from tests.conftest import strip_ansi

PENDING = pytest.mark.xfail(strict=True, reason="PPA014 not implemented")
CORPUS = Path(__file__).parent / "fixtures" / "trusted_interpreter_corpus"
SETUP_PYTHON = "    - id: py\n      uses: actions/setup-python@v5\n"
PYTHON_PATH = "${{ steps.py.outputs.python-path }}"
MESSAGE = "Python resolved on the caller's PATH"
PARTIAL = (
    MESSAGE + "; partial: -P leaves PYTHONPATH and other PYTHON* settings "
    "active"
)


def step(script: str, env: dict[str, str] | None = None) -> str:
    """A composite action step running ``script`` with ``env``."""
    head = "    - shell: bash\n"
    if env:
        head += "      env:\n" + "".join(
            f"        {name}: {value}\n" for name, value in env.items()
        )
    body = "".join(f"        {line}\n" for line in script.split("\n"))
    return f"{head}      run: |\n{body}"


def action(*steps: str) -> str:
    """A composite action with ``steps``."""
    return "runs:\n  using: composite\n  steps:\n" + "".join(steps)


def workflow(script: str) -> str:
    """A workflow with one job whose one step runs ``script``."""
    body = "".join(f"          {line}\n" for line in script.split("\n"))
    return (
        "on: push\njobs:\n  a:\n    runs-on: x\n    steps:\n"
        f"      - shell: bash\n        run: |\n{body}"
    )


def found(text: str, kind: str = "action") -> list[str]:
    """Each PPA014 finding in ``text`` as ``line: detail``."""
    return [
        f"{f.line}: {f.detail}"
        for f in audit.scan_text(text, kind, "repo", "file")
        if f.rule == "PPA014"
    ]


@PENDING
@pytest.mark.parametrize(
    "script",
    [
        "python3 -m json.tool f",
        "python3 -I s.py",
        "python -I -c 'import sys'",
        "python3.12 -I s.py",
        "python3 --version",
        "sudo python3 -I s.py",
        '"$(command -v python3)" -I s.py',
    ],
)
def test_bare_python_is_reported(script: str) -> None:
    """``-I`` keeps the workspace out, not the caller's interpreter."""
    assert found(action(step(script))) == [f"6: {MESSAGE}"]


def test_earlier_setup_python_clears_it() -> None:
    assert found(action(SETUP_PYTHON, step("python3 -I -m json.tool f"))) == []


@PENDING
def test_later_setup_python_does_not() -> None:
    """Only a setup-python step ahead of the command counts."""
    text = action(step("python3 -I s.py"), SETUP_PYTHON)
    assert found(text) == [f"6: {MESSAGE}"]


@PENDING
@pytest.mark.parametrize(
    ("script", "env"),
    [
        ("python3 -P -m mod", None),
        ("python3 -sP s.py", None),
        ("PYTHONSAFEPATH=1 python3 s.py", None),
        ("python3 s.py", {"PYTHONSAFEPATH": "'1'"}),
    ],
)
def test_safe_path_alone_is_partial(
    script: str, env: dict[str, str] | None
) -> None:
    """-P leaves PYTHONPATH and the other PYTHON* settings active."""
    line = 8 if env else 6
    assert found(action(step(script, env))) == [f"{line}: {PARTIAL}"]


@PENDING
def test_isolated_mode_is_not_partial() -> None:
    """-I implies -P, so -P is not the only isolation."""
    assert found(action(step("python3 -I -P s.py"))) == [f"6: {MESSAGE}"]


@pytest.mark.parametrize(
    ("script", "env"),
    [
        ('"$PYTHON" -I s.py', {"PYTHON": PYTHON_PATH}),
        ("/usr/bin/python3 -I s.py", None),
        ("./venv/bin/python -I s.py", None),
    ],
)
def test_resolved_interpreters_are_not_reported(
    script: str, env: dict[str, str] | None
) -> None:
    """A trusted value or any path is not looked up on PATH."""
    assert found(action(SETUP_PYTHON, step(script, env))) == []
    assert found(action(step(script, env))) == []


def test_workflows_and_scripts_are_not_reported() -> None:
    """A job's PATH is its own; a script's caller is unknown."""
    assert found(workflow("python3 -I s.py"), "workflow") == []
    assert found("python3 -I s.py\n", "script") == []


def test_ignore_mark_drops_it() -> None:
    script = "# python-path-audit: ignore\npython3 -I s.py"
    assert found(action(step(script))) == []


@PENDING
def test_rule_text_and_gating() -> None:
    assert audit.RULES["PPA014"] == MESSAGE
    assert "PPA014" in ACTION_ENFORCEABLE_RULES


@pytest.mark.parametrize("path", sorted(CORPUS.glob("*.yaml")), ids=str)
def test_hardened_corpus_stays_clean(path: Path) -> None:
    """The #469 actions start Python through a trusted interpreter."""
    assert found(path.read_text()) == []


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


def _repository(root: Path, name: str, text: str) -> Path:
    (root / ".git").mkdir()
    target = root / name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text)
    return root


@PENDING
@pytest.mark.parametrize("script", ["python3 -m json.tool f", "python3 -I f"])
def test_verify_fails_in_an_action(tmp_path: Path, script: str) -> None:
    root = _repository(tmp_path, "action.yaml", action(step(script)))

    code, output = _lint(root, "--verify-python-path")

    assert code == exit_codes.PYTHON_PATH_FOUND
    assert "PPA014" in output


def test_python_path_ok_suppresses_it(tmp_path: Path) -> None:
    script = "python3 -I f  # python-path-ok -- the runner image's Python"
    root = _repository(tmp_path, "action.yaml", action(step(script)))

    code, _ = _lint(root, "--verify-python-path")

    assert code == exit_codes.SUCCESS


def test_workflow_never_fails_verify(tmp_path: Path) -> None:
    root = _repository(
        tmp_path, ".github/workflows/ci.yaml", workflow("python3 -I f")
    )

    code, _ = _lint(root, "--verify-python-path")

    assert code == exit_codes.SUCCESS
