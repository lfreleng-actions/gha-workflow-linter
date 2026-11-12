# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""PPA013: uv commands whose interpreter the caller's environment chooses.

Rule 1 reports a uv command that discovers an interpreter without a
trusted ``--python`` or ``UV_PYTHON``. Rule 2 reports ``uv python
find`` or ``install`` run without ``env -i``. Rule 3 reports a uv
interpreter setting in ``env:`` or written to ``$GITHUB_ENV``. A
trusted interpreter is an absolute path outside the workspace, a
setup-python ``python-path`` output from an earlier step of the job,
or a run step's output written once from ``env -i … uv python find``.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from typer.testing import CliRunner

from gha_workflow_linter import exit_codes
from gha_workflow_linter.cli import app
from gha_workflow_linter.python_path import _engine as audit
from gha_workflow_linter.python_path._invocation import RULES

PENDING = pytest.mark.xfail(strict=True, reason="PPA013 lands with #467")

if TYPE_CHECKING:
    from pathlib import Path

SETUP_PYTHON = "    - id: py\n      uses: actions/setup-python@v5\n"
SETUP_UV = (
    "    - id: setup-uv\n      uses: astral-sh/setup-uv@v6\n"
    "      with: {python-version: '3.12'}\n"
)
PYTHON_PATH = "${{ steps.py.outputs.python-path }}"


def run_step(line: str, extra: str = "") -> str:
    """A composite action step that runs ``line``, with ``extra`` keys."""
    body = "".join(f"        {part}\n" for part in line.split("\n"))
    return f"    - shell: bash\n{extra}      run: |\n{body}"


def action(*steps: str) -> str:
    """A composite action with ``steps``."""
    return "runs:\n  using: composite\n  steps:\n" + "".join(steps)


def found(text: str, rules: tuple[str, ...] = ("PPA013",)) -> list[str]:
    """Each finding of ``rules`` in ``text`` as ``RULE line: detail``."""
    return [
        f"{f.rule} {f.line}: {f.detail}"
        for f in audit.scan_text(text, _kind(text), "repo", "file")
        if f.rule in rules
    ]


def _kind(text: str) -> str:
    if text.startswith("runs:"):
        return "action"
    if text.startswith("on:"):
        return "workflow"
    return "script"


def mismatches(
    cases: list[tuple[str, list[str]]],
) -> list[tuple[str, list[str], list[str]]]:
    """The cases whose PPA013 findings differ from what they expect."""
    out = []
    for text, expected in cases:
        actual = found(text)
        if actual != expected:
            out.append((text, actual, expected))
    return out


NO_PYTHON = "no --python: UV_PYTHON, VIRTUAL_ENV or CONDA_PREFIX choose"


@PENDING
def test_the_rule_is_named() -> None:
    assert RULES["PPA013"] == (
        "uv chooses its interpreter from the caller's environment"
    )


@PENDING
def test_rule_one_each_subcommand() -> None:
    """Each discovering subcommand without a trusted --python (rule 1)."""
    cases = [
        (
            action(run_step(f"{cmd} --no-config")),
            [f"PPA013 6: {NO_PYTHON}"],
        )
        for cmd in (
            "uv run --no-project python -I s.py",
            "uvx ruff check",
            "uv tool run ruff check",
            "uv venv /opt/v",
            "uv sync --locked",
            "uv export --locked",
            "uv pip install .",
        )
    ]
    assert mismatches(cases) == []


@PENDING
def test_rule_one_requests() -> None:
    """A version, --system or --managed-python leaves the caller choosing."""
    cases = [
        (
            action(run_step("uv pip install --no-config --python 3.12 .")),
            [
                "PPA013 6: --python 3.12 is a request, not a path: "
                "VIRTUAL_ENV, CONDA_PREFIX or the caller's PATH choose"
            ],
        ),
        (
            action(run_step("uv pip install --no-config --system .")),
            ["PPA013 6: --system searches the caller's PATH"],
        ),
        (
            action(run_step("uv venv --no-config --managed-python /opt/v")),
            [
                "PPA013 6: --managed-python: UV_PYTHON, VIRTUAL_ENV or "
                "CONDA_PREFIX still choose"
            ],
        ),
        (
            action(
                run_step(
                    "uv pip install --no-config .",
                    "      env: {UV_SYSTEM_PYTHON: '1'}\n",
                )
            ),
            [
                "PPA013 5: UV_SYSTEM_PYTHON is set; the step's uv commands "
                "inherit it",
                "PPA013 7: UV_SYSTEM_PYTHON searches the caller's PATH",
            ],
        ),
    ]
    assert mismatches(cases) == []


def test_rule_one_trusted_interpreters() -> None:
    """A trusted --python or UV_PYTHON settles the interpreter."""
    install = 'uv pip install --no-config --python "$PY" .'
    cases: list[tuple[str, list[str]]] = [
        (
            action(
                run_step(
                    "uv pip install --no-config --python /usr/bin/python3 ."
                )
            ),
            [],
        ),
        (
            action(
                SETUP_PYTHON,
                run_step(
                    f'uv pip install --no-config --python "{PYTHON_PATH}" .'
                ),
            ),
            [],
        ),
        (
            action(
                SETUP_PYTHON,
                run_step(install, f"      env: {{PY: '{PYTHON_PATH}'}}\n"),
            ),
            [],
        ),
        (action(SETUP_PYTHON, run_step(f'PY="{PYTHON_PATH}"\n{install}')), []),
        (
            action(
                SETUP_PYTHON,
                run_step(
                    "uv pip install --no-config .",
                    f"      env: {{UV_PYTHON: '{PYTHON_PATH}'}}\n",
                ),
            ),
            [],
        ),
    ]
    assert mismatches(cases) == []


@PENDING
def test_trusted_uv_and_python_programs() -> None:
    """setup-uv's uv-path is uv; setup-python's python-path is Python."""
    env = (
        "      env:\n"
        "        UV: ${{ steps.setup-uv.outputs.uv-path }}\n"
        f"        PY: {PYTHON_PATH}\n"
    )
    uv_text = action(
        SETUP_PYTHON,
        SETUP_UV,
        run_step('"$UV" pip install --no-config --python "$PY" .', env),
    )
    assert found(uv_text, ("PPA009", "PPA013")) == []
    uv_unpinned = action(
        SETUP_UV, run_step('"$UV" pip install --no-config .', env)
    )
    assert found(uv_unpinned) == [f"PPA013 12: {NO_PYTHON}"]
    py_env = f"      env: {{PYTHON: '{PYTHON_PATH}'}}\n"
    rules = ("PPA001", "PPA009")
    assert (
        found(
            action(SETUP_PYTHON, run_step('"$PYTHON" -I s.py', py_env)), rules
        )
        == []
    )
    assert found(
        action(SETUP_PYTHON, run_step('"$PYTHON" -m x', py_env)), rules
    ) == [
        "PPA001 9: python -m without -I: the working directory leads sys.path"
    ]


@PENDING
def test_rule_two_find_and_install() -> None:
    """uv python find and install need env -i (rule 2)."""
    steered = "runs without env -i: PATH and UV_* from the caller choose"
    cases = [
        (
            action(run_step("uv python find --no-config 3.12")),
            [f"PPA013 6: {steered}"],
        ),
        (
            action(run_step("uv python install --no-config 3.12")),
            [f"PPA013 6: {steered}"],
        ),
        (
            action(
                run_step("env -i PATH=/usr/bin uv python find --no-config 3.12")
            ),
            [],
        ),
        (
            action(
                run_step(
                    "env - PATH=/usr/bin uv python install --no-config 3.12"
                )
            ),
            [],
        ),
        (
            "on: push\njobs:\n  a:\n    steps:\n      - run: uv python find 3.12\n",
            [f"PPA013 5: {steered}"],
        ),
    ]
    assert mismatches(cases) == []


@PENDING
def test_rule_three_settings() -> None:
    """A uv interpreter setting in env: or GITHUB_ENV (rule 3)."""
    head = "on: push\njobs:\n  a:\n"
    cases = [
        (
            head
            + "    env:\n      UV_PYTHON: '3.12'\n    steps:\n      - run: echo\n",
            [
                "PPA013 5: UV_PYTHON is not a trusted interpreter; "
                "the job's uv commands inherit it"
            ],
        ),
        (
            "on: push\nenv:\n  UV_MANAGED_PYTHON: '1'\njobs:\n  a:\n"
            "    steps:\n      - run: echo\n",
            [
                "PPA013 3: UV_MANAGED_PYTHON is set; every job's uv "
                "commands inherit it"
            ],
        ),
        (
            head + "    env:\n      UV_PYTHON: /usr/bin/python3\n"
            "    steps:\n      - run: echo\n",
            [],
        ),
        (
            head + "    env:\n      # python-path-audit: ignore\n"
            "      UV_SYSTEM_PYTHON: '1'\n    steps:\n      - run: echo\n",
            [],
        ),
        (
            head
            + '    steps:\n      - run: echo "UV_PYTHON=$GITHUB_WORKSPACE/py"'
            ' >> "$GITHUB_ENV"\n',
            [
                "PPA013 5: UV_PYTHON written to GITHUB_ENV is not a trusted "
                "interpreter; later uv commands in the job inherit it"
            ],
        ),
        (
            head + "    steps:\n      - run: echo UV_SYSTEM_PYTHON=1"
            ' >> "$GITHUB_ENV"\n',
            [
                "PPA013 5: UV_SYSTEM_PYTHON written to GITHUB_ENV; later uv "
                "commands in the job inherit it"
            ],
        ),
        (
            head + "    steps:\n      - run: echo UV_PYTHON=/usr/bin/python3"
            ' >> "$GITHUB_ENV"\n',
            [],
        ),
    ]
    assert mismatches(cases) == []


def find_step(script: str) -> str:
    """A step with id ``find`` running ``script``, then a uv consumer."""
    return action(
        run_step(script, "      id: find\n"),
        run_step(
            "uv pip install --no-config --python "
            '"${{ steps.find.outputs.python }}" .'
        ),
    )


@PENDING
def test_run_step_output_from_a_cleared_find() -> None:
    """An output written once from env -i … uv python find is trusted."""
    write = 'echo "python=$py" >> "$GITHUB_OUTPUT"'
    find = "py=$(env -i PATH=/usr/bin uv python find --no-config 3.12)"
    untraced = (
        "PPA009 {}: --python is ${{{{ ... }}}}, which the scan cannot trace "
        "to a trusted interpreter"
    )
    rules = ("PPA009", "PPA013")
    assert found(find_step(f"{find}\n{write}"), rules) == []
    # Near misses: written twice, or found without env -i.
    assert found(
        find_step(f'{find}\n{write}\necho python=x >> "$GITHUB_OUTPUT"'), rules
    ) == [untraced.format(12)]
    assert found(
        find_step(f"py=$(uv python find --no-config 3.12)\n{write}"), rules
    ) == [
        "PPA013 7: runs without env -i: PATH and UV_* from the caller choose",
        untraced.format(11),
    ]


@PENDING
def test_near_misses_are_not_trusted() -> None:
    """Values the trust model cannot pin stay findings."""
    install = 'uv pip install --no-config --python "$PY" .'
    twice = action(
        SETUP_PYTHON, run_step(f'PY="{PYTHON_PATH}"\nPY=python3\n{install}')
    )
    assert found(twice, ("PPA009", "PPA013")) == [
        'PPA009 10: uv --python is "$PY", which the scan cannot read'
    ]
    no_setup = action(
        run_step(f'uv pip install --no-config --python "{PYTHON_PATH}" .')
    )
    assert found(no_setup, ("PPA009", "PPA013")) == [
        "PPA009 6: --python is ${{ ... }}, which the scan cannot trace to "
        "a trusted interpreter"
    ]
    other_job = (
        "on: push\njobs:\n  a:\n    steps:\n      - id: py\n"
        "        uses: actions/setup-python@v5\n  b:\n    steps:\n"
        "      - run: $PY -c 'import x'\n"
        f"        env: {{PY: '{PYTHON_PATH}'}}\n"
    )
    assert found(other_job, ("PPA009",)) == [
        "PPA009 9: program is '$PY', which the scan cannot resolve"
    ]
    same_job = other_job.replace("  b:\n    steps:\n", "")
    assert found(same_job, ("PPA002", "PPA009")) == [
        "PPA002 7: python -c without -I: the working directory leads sys.path"
    ]


def test_scripts_are_not_reported() -> None:
    """A script's caller is unknown; PPA013 judges YAML alone."""
    assert found("uv pip install --no-config --system .\n") == []


def _lint(root: Path, *args: str) -> int:
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
    return result.exit_code


@PENDING
def test_verify_fails_in_an_action_alone(tmp_path: Path) -> None:
    """PPA013 gates a composite action, never a workflow."""
    step = "uv pip install --no-config --system ."
    action_root = tmp_path / "action"
    action_root.mkdir()
    (action_root / ".git").mkdir()
    (action_root / "action.yaml").write_text(
        "---\nruns:\n  using: composite\n  steps:\n"
        f"    - shell: bash\n      run: {step}\n"
    )
    assert _lint(action_root, "--verify-python-path") == (
        exit_codes.PYTHON_PATH_FOUND
    )
    workflow_root = tmp_path / "workflow"
    workflows = workflow_root / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflow_root / ".git").mkdir()
    (workflows / "ci.yaml").write_text(
        "---\non: push\njobs:\n  a:\n    runs-on: x\n    steps:\n"
        f"      - run: {step}\n"
    )
    assert _lint(workflow_root, "--verify-python-path") == exit_codes.SUCCESS
