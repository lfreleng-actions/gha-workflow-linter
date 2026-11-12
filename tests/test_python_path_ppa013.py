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

from typer.testing import CliRunner

from gha_workflow_linter import exit_codes
from gha_workflow_linter.cli import app
from gha_workflow_linter.python_path import _engine as audit
from gha_workflow_linter.python_path._invocation import RULES
from gha_workflow_linter.python_path._words import Block

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


def test_the_rule_is_named() -> None:
    assert RULES["PPA013"] == (
        "uv chooses its interpreter from the caller's environment"
    )


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


def test_run_step_output_from_a_cleared_find() -> None:
    """An output written once from env -i … uv python find is trusted."""
    write = 'echo "python=$py" >> "$GITHUB_OUTPUT"'
    find = "py=$(env -i PATH=/usr/bin uv python find --system --no-config 3.12)"
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
        "      - run: >-\n          \"$PY\" -c 'import x'\n"
        f"        env: {{PY: '{PYTHON_PATH}'}}\n"
    )
    assert found(other_job, ("PPA009",)) == [
        "PPA009 10: program is '\"$PY\"', which the scan cannot resolve"
    ]
    same_job = other_job.replace("  b:\n    steps:\n", "")
    assert found(same_job, ("PPA002", "PPA009")) == [
        "PPA002 8: python -c without -I: the working directory leads sys.path"
    ]


def test_only_stdout_writes_to_github_output_count() -> None:
    """A write counts when its standard output goes to GITHUB_OUTPUT."""
    rules = ("PPA009", "PPA013")
    untraced = [
        "PPA009 11: --python is ${{ ... }}, which the scan cannot trace "
        "to a trusted interpreter"
    ]
    for redirect, expected in (
        ('>> "$GITHUB_OUTPUT"', []),
        ('1>> "$GITHUB_OUTPUT"', []),
        ('&>> "$GITHUB_OUTPUT"', []),
        ('2>> "$GITHUB_OUTPUT"', untraced),
        ('>> "$GITHUB_OUTPUT" > /dev/null', untraced),
        ('>> "$GITHUB_OUTPUT" >&2', untraced),
        ('>> "$GITHUB_OUTPUT" 2>&1', []),
    ):
        script = f'py=/usr/bin/python3\necho "python=$py" {redirect}'
        assert found(find_step(script), rules) == expected, redirect


def test_quoted_eval_invalidates_trust() -> None:
    """A quoted or builtin-wrapped eval, source or . runs unread text."""
    install = 'uv pip install --no-config --python "$PY" .'
    rules = ("PPA009", "PPA013")
    plain = action(run_step(f"PY=/usr/bin/python3\n{install}"))
    assert found(plain, rules) == []
    for runs in (
        "\"eval\" 'PY=./x'",
        "'source' f.sh",
        '"." f.sh',
        "e\\val x",
        "builtin eval 'PY=./x'",
        "command eval 'PY=./x'",
        "command -p source f.sh",
    ):
        text = action(run_step(f"PY=/usr/bin/python3\n{runs}\n{install}"))
        assert found(text, rules) == [
            'PPA009 8: uv --python is "$PY", which the scan cannot read'
        ], runs


def test_conditional_output_writes_are_not_trusted() -> None:
    """A GITHUB_OUTPUT write that may not run trusts no output."""
    rules = ("PPA009", "PPA013")
    untraced = [
        "PPA009 11: --python is ${{ ... }}, which the scan cannot trace "
        "to a trusted interpreter"
    ]
    write = 'echo "python=$py" >> "$GITHUB_OUTPUT"'
    for script in (
        f"if false; then {write}; fi",
        f"f() {{ {write}; }}",
        f"false && {write}",
        f"( {write} )",
    ):
        text = find_step(f"py=/usr/bin/python3\n{script}")
        assert found(text, rules) == untraced, script


def test_quoted_assignment_targets() -> None:
    """Assigning builtins match names after quote removal."""
    install = 'uv pip install --no-config --python "$PY" .'
    rules = ("PPA009", "PPA013")
    for assigns in (
        "printf -v \"PY\" '%s' 3.12",
        "printf -vPY '%s' 3.12",
        "read -r 'PY' < f",
        'unset "PY"',
        'export "PY=./x"',
        "builtin export PY=./x",
        'builtin printf -v "PY" 3.12',
    ):
        text = action(run_step(f"PY=/usr/bin/python3\n{assigns}\n{install}"))
        assert found(text, rules) == [
            'PPA009 8: uv --python is "$PY", which the scan cannot read'
        ], assigns


def test_printf_format_assigns_nothing() -> None:
    """printf assigns through -v alone; its format names no variable."""
    write = 'printf \'python=%s\\n\' "$python" >> "$GITHUB_OUTPUT"'
    text = find_step(f"python=/usr/bin/python3\n{write}")
    assert found(text, ("PPA009", "PPA013")) == []


def test_unquoted_values_that_may_split() -> None:
    """An unquoted value resolves only when it cannot split or glob."""
    rules = ("PPA001", "PPA009")
    split = "PPA009 7: program is '$PY', which the scan cannot resolve"
    unsafe = (
        "PPA001 7: python -m without -I: the working directory leads sys.path"
    )
    for script, expected in (
        ("PY=/usr/bin/python3\n$PY -m tool", [unsafe]),
        ("PY='/usr/bin/python3 -S'\n$PY -m tool", [split]),
        ('PY=/usr/bin/python3\n"$PY" -m tool', [unsafe]),
        ("PY='/usr/bin/python*'\n$PY -m tool", [split]),
        (
            "PY=/usr/bin/python3\nIFS=/\n$PY -m tool",
            [split.replace(" 7:", " 8:")],
        ),
    ):
        assert found(action(run_step(script)), rules) == expected, script
    marker = action(
        SETUP_PYTHON,
        run_step("$PY -I s.py", f"      env: {{PY: '{PYTHON_PATH}'}}\n"),
    )
    assert found(marker, rules) == [
        "PPA009 9: program is '$PY', which the scan cannot resolve"
    ]


def test_unknown_interpreter_paths_stay_unresolved() -> None:
    """A trusted path the scan does not know as Python stays PPA009."""
    rules = ("PPA001", "PPA009")
    assert found(
        action(run_step('PYTHON=/opt/pypy3\n"$PYTHON" -m pkg')), rules
    ) == ["PPA009 7: program is '\"$PYTHON\"', which the scan cannot resolve"]
    assert (
        found(
            action(run_step('PYTHON=/usr/bin/python3\n"$PYTHON" -I -m x')),
            rules,
        )
        == []
    )


def test_rule_two_under_unread_wrapper_settings() -> None:
    """env -u leaves the caller's environment reaching uv python find."""
    steered = "runs without env -i: PATH and UV_* from the caller choose"
    rules = ("PPA009", "PPA013")
    unsettled = (
        "PPA009 6: env -u or a NAME= word the scan cannot read changes "
        "the uv settings"
    )
    assert found(
        action(
            run_step("env -u PYTHONPATH uv python find --no-config --system")
        ),
        rules,
    ) == [unsettled, f"PPA013 6: {steered}"]
    assert found(
        action(run_step("env -i -u X uv python find --no-config --system")),
        rules,
    ) == [unsettled]


def test_lookup_must_pass_the_workspace_rules() -> None:
    """Only a lookup that cannot return a workspace .venv is trusted."""
    write = 'echo "python=$py" >> "$GITHUB_OUTPUT"'
    rules = ("PPA009",)
    for lookup, trusted in (
        ("env -i PATH=/usr/bin uv python find --system --no-config", True),
        ("env -i PATH=/usr/bin uv python find --managed-python 3.12", True),
        ("env -i UV_NO_CONFIG=1 uv python find --system", True),
        ("env -i uv python install --managed-python 3.12", True),
        ("env -i PATH=/usr/bin uv python find --no-config 3.12", False),
        ("env -i PATH=/usr/bin uv python find --system", False),
        ("env -i VIRTUAL_ENV=/v uv python find --system --no-config", False),
        (
            "env -i UV_PYTHON_SEARCH_PATH=/w uv python find --system "
            "--no-config",
            False,
        ),
    ):
        text = find_step(f"py=$({lookup})\n{write}")
        assert (found(text, rules) == []) is trusted, lookup


def test_preserved_selectors_keep_the_caller_choosing() -> None:
    """sudo keeping any interpreter selector is not a cleared env."""
    install = "uv pip install --no-config --system ."
    assert found(action(run_step(f"sudo {install}"))) == []
    for name in (
        "PYTHONEXECUTABLE",
        "__PYVENV_LAUNCHER__",
        "CONDA_DEFAULT_ENV",
        "CONDA_ROOT",
        "UV_INTERNAL__TEST_PYTHON_MANAGED",
    ):
        text = action(run_step(f"sudo --preserve-env={name} {install}"))
        assert found(text) == [
            "PPA013 6: --system searches the caller's PATH"
        ], name


def test_cleared_wrappers_passing_a_selector() -> None:
    """A selector passed into a cleared env, at any nesting, steers uv."""
    allowed = (
        "env -i PATH=/usr/bin HOME=/tmp UV_NO_CONFIG=1 UV_CACHE_DIR=/tmp/c "
        "UV_PYTHON_INSTALL_DIR=/tmp/p UV_NO_PROGRESS=1"
    )
    detail = (
        "PPA013 6: {} passed into the cleared environment chooses uv's "
        "interpreter"
    )
    parent = "UV_INTERNAL__PARENT_INTERPRETER"
    cases = [
        (action(run_step(f"{allowed} uv python find --system")), []),
        (action(run_step(f"{allowed} uv pip install --system .")), []),
        (
            action(
                run_step(
                    f"env -i {parent}=/github/workspace/evil "
                    "uv pip install --no-config --system ."
                )
            ),
            [detail.format(parent)],
        ),
        (
            action(
                run_step(
                    "env -i UV_PYTHON_SEARCH_PATH=/github/workspace/evil "
                    "uv pip install --no-config --system ."
                )
            ),
            [detail.format("UV_PYTHON_SEARCH_PATH")],
        ),
        (
            action(
                run_step("env -i sudo VIRTUAL_ENV=/v uv python find --system")
            ),
            [detail.format("VIRTUAL_ENV")],
        ),
        (
            action(
                run_step(
                    "env -i env CONDA_PREFIX=/c PYTHONEXECUTABLE=/p "
                    "uv pip install --system ."
                )
            ),
            [detail.format("CONDA_PREFIX, PYTHONEXECUTABLE")],
        ),
        (
            action(
                run_step(
                    "env -i UV_PYTHON=/usr/bin/python3 "
                    "uv pip install --no-config ."
                )
            ),
            [],
        ),
    ]
    assert mismatches(cases) == []


def test_github_env_records() -> None:
    """GITHUB_ENV is read by record, as the runner reads it."""

    def write(body: str) -> str:
        return action(run_step(f"cat >> \"$GITHUB_ENV\" <<'END'\n{body}\nEND"))

    system = (
        "PPA013 6: UV_SYSTEM_PYTHON written to GITHUB_ENV; later uv "
        "commands in the job inherit it"
    )
    untrusted = (
        "PPA013 6: UV_PYTHON written to GITHUB_ENV is not a trusted "
        "interpreter; later uv commands in the job inherit it"
    )
    cases = [
        (write("OTHER<<EOF\nUV_SYSTEM_PYTHON=1\nEOF"), []),
        (
            write("OTHER<<EOF\nUV_SYSTEM_PYTHON=1\nEOF\nUV_SYSTEM_PYTHON=1"),
            [system],
        ),
        (write("UV_PYTHON<<EOF\n/usr/bin/python3\nEOF"), []),
        (write("UV_PYTHON<<EOF\n/usr/bin/python3\nx\nEOF"), [untrusted]),
        (write("UV_PYTHON<<EOF\n3.12\nEOF"), [untrusted]),
        (write("UV_SYSTEM_PYTHON<<EOF\n0\nEOF"), []),
        (write("UV_SYSTEM_PYTHON<<EOF\n1\nEOF"), [system]),
        (write("UV_SYSTEM_PYTHON<<EOF\n1"), [system]),
    ]
    assert mismatches(cases) == []


def test_conditional_producers_give_no_output() -> None:
    """A step with if: or continue-on-error: may leave its output empty."""
    rules = ("PPA009", "PPA013")
    consumer = run_step(
        "uv pip install --no-config .",
        f"      env: {{UV_PYTHON: '{PYTHON_PATH}'}}\n",
    )
    for extra, expected in (
        ("", []),
        ("      continue-on-error: false\n", []),
        (
            "      if: false\n",
            [
                "PPA013 8: UV_PYTHON is not a trusted interpreter; the "
                "step's uv commands inherit it",
                "PPA009 10: UV_PYTHON is a value the scan cannot trace to "
                "a trusted interpreter",
            ],
        ),
        (
            "      continue-on-error: true\n",
            [
                "PPA013 8: UV_PYTHON is not a trusted interpreter; the "
                "step's uv commands inherit it",
                "PPA009 10: UV_PYTHON is a value the scan cannot trace to "
                "a trusted interpreter",
            ],
        ),
    ):
        text = action(SETUP_PYTHON + extra, consumer)
        assert found(text, rules) == expected, extra
    write = 'py=/usr/bin/python3\necho "python=$py" >> "$GITHUB_OUTPUT"'
    text = find_step(write).replace(
        "      id: find\n", "      id: find\n      if: always()\n"
    )
    assert found(text, rules) == [
        "PPA009 12: --python is ${{ ... }}, which the scan cannot trace "
        "to a trusted interpreter"
    ]


def test_subscript_writes_bind_no_scalar() -> None:
    """PY[1]=x changes PY, but "$PY" reads element zero."""
    rules = ("PPA009", "PPA013")
    install = 'UV_PYTHON="$PY" uv pip install --no-config .'
    assert (
        found(action(run_step(f"PY=/usr/bin/python3\n{install}")), rules) == []
    )
    assert found(
        action(run_step(f"PY[1]=/usr/bin/python3\n{install}")), rules
    ) == [
        "PPA009 7: UV_PYTHON is a value the scan cannot trace to a "
        "trusted interpreter"
    ]


def test_values_with_line_breaks_are_not_trusted() -> None:
    """A line break would write a second GITHUB_OUTPUT record."""
    rules = ("PPA009", "PPA013")
    write = 'echo "python=$py" >> "$GITHUB_OUTPUT"'
    for value in (
        '"/usr/bin/python3\npython=/github/workspace/evil"',
        "'/usr/bin/python3\npython=/github/workspace/evil'",
    ):
        assert found(find_step(f"py={value}\n{write}"), rules) == [
            "PPA009 12: --python is ${{ ... }}, which the scan cannot "
            "trace to a trusted interpreter"
        ], value
    install = 'uv pip install --no-config --python "$PY" .'
    text = action(run_step(f'PY="/usr/bin/python3\nx"\n{install}'))
    assert found(text, rules) == [
        'PPA009 8: uv --python is "$PY", which the scan cannot read'
    ]


def test_implicit_builtin_destinations() -> None:
    """read and select set REPLY, mapfile and readarray MAPFILE."""
    rules = ("PPA009", "PPA013")
    for name, assigns in (
        ("REPLY", "read <<< 3.12"),
        ("REPLY", "read -r -p x <<< 3.12"),
        ("REPLY", "select x in a; do break; done"),
        ("MAPFILE", "mapfile < f"),
        ("MAPFILE", "readarray -t < f"),
    ):
        install = f'uv pip install --no-config --python "${name}" .'
        text = action(
            run_step(f"{name}=/usr/bin/python3\n{assigns}\n{install}")
        )
        assert found(text, rules) == [
            f'PPA009 8: uv --python is "${name}", which the scan cannot read'
        ], assigns


def test_printf_n_assigns_its_arguments() -> None:
    """printf %n, or a format the scan cannot read, assigns its arguments."""
    rules = ("PPA009", "PPA013")
    install = 'uv pip install --no-config --python "$PY" .'
    for assigns, expected in (
        ("printf '%n' PY", True),
        ("printf -- '%5n' PY", True),
        ("printf 'a%s%n' x PY", True),
        ('printf "$FMT" PY', True),
        ("printf '%%n' PY", False),
        ("printf '%s\\n' PY", False),
    ):
        text = action(run_step(f"PY=/usr/bin/python3\n{assigns}\n{install}"))
        unread = ['PPA009 8: uv --python is "$PY", which the scan cannot read']
        assert found(text, rules) == (unread if expected else []), assigns


def test_literal_output_paths_keep_their_program() -> None:
    """A literal path written to GITHUB_OUTPUT keeps its name: uv or Python."""
    producer = "      id: producer\n"
    use = '"${{ steps.producer.outputs.tool }}"'
    uv = action(
        run_step(
            'tool=/usr/bin/uv\necho "tool=$tool" >> "$GITHUB_OUTPUT"', producer
        ),
        run_step(f"{use} pip install --no-config --system ."),
    )
    assert found(uv, ("PPA009", "PPA013")) == [
        "PPA013 11: --system searches the caller's PATH"
    ]
    python = action(
        run_step(
            'tool=/usr/bin/python3\necho "tool=$tool" >> "$GITHUB_OUTPUT"',
            producer,
        ),
        run_step(f"{use} -I -m pip install ."),
    )
    assert found(python, ("PPA001", "PPA009", "PPA013")) == []


def test_unread_allowed_values_count_as_selectors() -> None:
    """An allowed name passed into env -i with an unread value steers uv."""
    rules = ("PPA009", "PPA013")
    unsettled = (
        "PPA009 6: env -u or a NAME= word the scan cannot read changes "
        "the uv settings"
    )
    detail = (
        "PPA013 6: {} passed into the cleared environment chooses uv's "
        "interpreter"
    )
    find = "uv python find --system --no-config"
    assert found(action(run_step(f'env -i PATH="$PATH" {find}')), rules) == [
        unsettled,
        detail.format("PATH"),
    ]
    assert found(
        action(run_step(f'env -i PATH="${{{{ inputs.path }}}}" {find}'))
    ) == [detail.format("PATH")]
    assert found(
        action(run_step('env -i HOME="$X" uv pip install --system .')),
        ("PPA013",),
    ) == [detail.format("HOME")]
    assert found(action(run_step(f"env -i PATH=/usr/bin {find}")), rules) == []
    # Nor does an unread PATH give a lookup the trusted model accepts.
    write = 'echo "python=$py" >> "$GITHUB_OUTPUT"'
    lookup = find_step(f'py=$(env -i PATH="$PATH" {find})\n{write}')
    assert found(lookup, rules)[-1] == (
        "PPA009 11: --python is ${{ ... }}, which the scan cannot trace "
        "to a trusted interpreter"
    )


def test_substituted_outputs_naming_no_interpreter() -> None:
    """A traced output holding /opt/pypy3 as the program stays PPA009."""
    use = '"${{ steps.producer.outputs.tool }}"'
    rules = ("PPA001", "PPA009", "PPA013")

    def text(value: str, command: str) -> str:
        return action(
            run_step(
                f'tool={value}\necho "tool=$tool" >> "$GITHUB_OUTPUT"',
                "      id: producer\n",
            ),
            run_step(f'echo "${{{{ github.ref }}}} é"\n{command}'),
        )

    assert found(text("/opt/pypy3", f"{use} -m pkg"), rules) == [
        f"PPA009 12: program is '{use}', which the scan cannot resolve"
    ]
    assert found(text("/usr/bin/python3", f"{use} -I -m pkg"), rules) == []
    assert found(text("/opt/pypy3", f"echo {use}"), rules) == []


def test_unread_env_file_writes_naming_uv_settings() -> None:
    """A GITHUB_ENV write the scan cannot read that names a uv setting."""
    rules = ("PPA009", "PPA013")
    unread = (
        "PPA009 6: a uv interpreter setting written to GITHUB_ENV in a "
        "form the scan cannot read; later uv commands in the job may "
        "inherit it"
    )
    for write, expected in (
        ("printf \"$fmt\" 'UV_SYSTEM_PYTHON=1'", [unread]),
        ("printf \"$fmt\" 'UV_PYTHON=/usr/bin/python3'", [unread]),
        ("printf '%b' 'UV_MANAGED_PYTHON=1\\n'", [unread]),
        ('echo "${N}UV_SYSTEM_PYTHON=1"', [unread]),
        ("printf \"$fmt\" 'UV_PYTHON_INSTALL_DIR=/x'", []),
        ("printf \"$fmt\" 'FOO=1'", []),
        ('echo "$LINE"', []),
    ):
        text = action(run_step(f'{write} >> "$GITHUB_ENV"'))
        assert found(text, rules) == expected, write
    script = 'printf "$fmt" \'UV_SYSTEM_PYTHON=1\' >> "$GITHUB_ENV"\n'
    assert found(script, rules) == []


def test_unread_assignment_targets_drop_all_trust() -> None:
    """An assigning builtin whose target is unread may set any variable."""
    rules = ("PPA009", "PPA013")
    install = 'uv pip install --no-config --python "$PY" .'
    unread = ['PPA009 8: uv --python is "$PY", which the scan cannot read']
    for assigns, expected in (
        ('DEST=PY; read -r "$DEST" <<< 3.12', unread),
        ('DEST=PY; printf -v "$DEST" %s 3.12', unread),
        ('printf -v"$DEST" %s 3.12', unread),
        ('printf "$FMT" "$DEST"', unread),
        ('mapfile -t "$DEST" < f', unread),
        ('export "$DEST"', unread),
        ("export $DEST", unread),
        ('declare "$DEST=3.12"', unread),
        ('unset "$DEST"', unread),
        ('builtin read "$DEST" <<< 3.12', unread),
        ("printf '%s\\n' \"$x\"", []),
        ("read -r line < f", []),
        ("printf -v OTHER %s x", []),
    ):
        text = action(run_step(f"PY=/usr/bin/python3\n{assigns}\n{install}"))
        assert found(text, rules) == expected, assigns


def test_untraced_python_expressions_are_unresolved() -> None:
    """A Python-named expression no trusted step produces is PPA009."""
    rules = ("PPA001", "PPA009")
    unresolved = [
        "PPA009 6: program is ${{ ... }}, which no trusted step produces; "
        "the scan cannot resolve it"
    ]
    for program in ('"${{ inputs.python }}"', "${{ inputs.python }}"):
        text = action(run_step(f"{program} -I script.py"))
        assert found(text, rules) == unresolved, program
    # The invocation is still judged: -m without -I is PPA001.
    assert found(action(run_step('"${{ inputs.python }}" -m x')), rules) == [
        "PPA001 6: python -m without -I: the working directory leads sys.path"
    ]
    traced = action(SETUP_PYTHON, run_step(f'"{PYTHON_PATH}" -I script.py'))
    assert found(traced, rules) == []


def test_trap_actions_drop_all_trust() -> None:
    """A trap action is text the scan does not read, run at any time."""
    rules = ("PPA009", "PPA013")
    install = 'uv pip install --no-config --python "$PY" .'
    unread = ['PPA009 8: uv --python is "$PY", which the scan cannot read']
    for trap, expected in (
        ("trap 'PY=3.12' DEBUG", unread),
        ('trap "$handler" EXIT', unread),
        ("trap -- 'PY=3.12' DEBUG", unread),
        ("builtin trap 'PY=3.12' DEBUG", unread),
        ("trap - DEBUG", []),
        ("trap '' DEBUG", []),
        ("trap -p", []),
        ("trap", []),
    ):
        text = action(run_step(f"PY=/usr/bin/python3\n{trap}\n{install}"))
        assert found(text, rules) == expected, trap


def test_unquoted_output_values_that_may_split() -> None:
    """An unquoted output value with a blank or glob is not trusted."""
    rules = ("PPA009", "PPA013")
    untraced = [
        "PPA009 {}: --python is ${{{{ ... }}}}, which the scan cannot trace "
        "to a trusted interpreter"
    ]
    printf = "printf 'python=%s\\n' {} >> \"$GITHUB_OUTPUT\""
    echo = 'echo python={} >> "$GITHUB_OUTPUT"'
    find = "py=$(env -i PATH=/usr/bin uv python find --system --no-config 3.12)"
    for script, expected in (
        (f"py='/usr/bin/python3 3.12'\n{printf.format('$py')}", untraced),
        (f"py='/usr/bin/python3 3.12'\n{echo.format('$py')}", untraced),
        (f"py='/usr/bin/python*'\n{printf.format('$py')}", untraced),
        (f"py=/usr/bin/python3\nIFS=/\n{printf.format('$py')}", untraced),
        (f"{find}\n{printf.format('$py')}", untraced),
        (f"py=/usr/bin/python3\n{printf.format('$py')}", []),
        (f"py=/usr/bin/python3\n{echo.format('${py}')}", []),
        (f"{find}\n{printf.format(chr(34) + '$py' + chr(34))}", []),
        (f"{find}\n{echo.format(chr(34) + '$py' + chr(34))}", []),
    ):
        line = 10 + script.count("\n")
        want = [e.format(line) for e in expected]
        assert found(find_step(script), rules) == want, script


def test_traced_spans_are_found_by_offset() -> None:
    """A word's traced spans come from a range lookup, not a full walk."""

    class Counted(dict[int, tuple[int, str]]):
        reads = 0

        def __getitem__(self, key: int) -> tuple[int, str]:
            Counted.reads += 1
            return super().__getitem__(key)

    count = 4000
    traced = Counted({10 * i: (10 * i + 5, f"e{i}") for i in range(count)})
    block = Block("", 1, [(0, 1)], "action", traced=traced)
    assert block.traced_within(10, 25) == [(10, 15, "e1"), (20, 25, "e2")]
    assert block.traced_within(11, 24) == []
    assert block.traced_within(0, 4) == []
    assert block.traced_within(10 * count, 10 * count + 9) == []
    Counted.reads = 0
    for i in range(count):
        assert block.traced_within(10 * i, 10 * i + 9) == [
            (10 * i, 10 * i + 5, f"e{i}")
        ]
    # One span read for each word, and at most one past it.
    assert Counted.reads <= 2 * count


def test_output_templates_with_line_breaks() -> None:
    """A line break in a GITHUB_OUTPUT template writes an extra record."""
    rules = ("PPA009", "PPA013")
    untraced = [
        "PPA009 {}: --python is ${{{{ ... }}}}, which the scan cannot trace "
        "to a trusted interpreter"
    ]
    for write, expected in (
        ('echo "python=\n$py" >> "$GITHUB_OUTPUT"', untraced),
        ('echo "python=$py\n" >> "$GITHUB_OUTPUT"', untraced),
        ('printf \'%s\\n\' "python=\n$py" >> "$GITHUB_OUTPUT"', untraced),
        ('echo "python=$py" >> "$GITHUB_OUTPUT"', []),
    ):
        script = f"py=/usr/bin/python3\n{write}"
        line = 10 + script.count("\n")
        want = [e.format(line) for e in expected]
        assert found(find_step(script), rules) == want, write


def test_inherited_uv_python_after_shell_changes() -> None:
    """A step env UV_PYTHON the block may change gives no exemption."""
    rules = ("PPA009", "PPA013")
    env = "      env: {UV_PYTHON: /usr/bin/python3}\n"
    install = "uv pip install --no-config --system ."
    unread = [
        "PPA009 {}: UV_PYTHON is a value the scan cannot trace to a "
        "trusted interpreter"
    ]
    for script, expected in (
        (install, []),
        (f"unset UV_PYTHON\n{install}", unread),
        (f"UV_PYTHON=3.12\n{install}", unread),
        (f"export UV_PYTHON=.venv/bin/python\n{install}", unread),
        (f'eval "$x"\n{install}', unread),
        (f'read -r "$DEST" < f\n{install}', unread),
        (f"trap 'UV_PYTHON=3.12' DEBUG\n{install}", unread),
        # An explicit command or wrapper value still decides.
        (f"unset UV_PYTHON\nUV_PYTHON=/usr/bin/python3 {install}", []),
        (f"unset UV_PYTHON\nenv UV_PYTHON=/usr/bin/python3 {install}", []),
    ):
        line = 7 + script.count("\n")
        want = [e.format(line) for e in expected]
        assert found(action(run_step(script, env)), rules) == want, script


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
