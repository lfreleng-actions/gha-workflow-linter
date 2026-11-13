# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""The hardened interpreter shapes of #469, and three stated-rule gaps.

``tests/fixtures/trusted_interpreter_corpus`` pins the producer and
consumer steps of four lfreleng-actions actions; no consumer may read
as PPA009 or PPA013. The other tests pin each model reading those
steps rely on, and where it stops.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from gha_workflow_linter.python_path import _engine as audit
from gha_workflow_linter.python_path._invocation import (
    env_of,
    expression_marker,
    is_outside_path,
)

CORPUS = Path(__file__).parent / "fixtures" / "trusted_interpreter_corpus"
RULES = ("PPA009", "PPA013")
TEMP_ROOT = expression_marker("TEMP")
SETUP_PYTHON = "    - id: py\n      uses: actions/setup-python@v5\n"
PYTHON_PATH = "${{ steps.py.outputs.python-path }}"
CORPUS_NAMES = [
    "info-yaml-validate-action",
    "pypi-version-check-action",
    "repository-metadata-action",
    "tag-validate-action",
]


def found(
    text: str,
    rules: tuple[str, ...] | None = RULES,
    kind: str = "action",
) -> list[str]:
    """Each finding of ``rules`` (None: any) as ``RULE line: detail``.

    Every input here is a composite action unless ``kind`` says not.
    """
    return [
        f"{f.rule} {f.line}: {f.detail}"
        for f in audit.scan_text(text, kind, "repo", "file")
        if rules is None or f.rule in rules
    ]


def step(script: str, env: dict[str, str] | None = None, sid: str = "") -> str:
    """A composite action step running ``script`` with ``env``."""
    head = "    - shell: bash\n"
    if sid:
        head += f"      id: {sid}\n"
    if env:
        head += "      env:\n" + "".join(
            f"        {name}: {value}\n" for name, value in env.items()
        )
    body = "".join(f"        {line}\n" for line in script.split("\n"))
    return f"{head}      run: |\n{body}"


def action(*steps: str) -> str:
    return "runs:\n  using: composite\n  steps:\n" + "".join(steps)


def consumer(script: str) -> str:
    """``script``, then ``"$PYTHON" -I s.py`` on a setup-python path."""
    return action(
        SETUP_PYTHON,
        step(f'{script}\n"$PYTHON" -I s.py', {"PYTHON": PYTHON_PATH}),
    )


# -- the corpus


@pytest.mark.parametrize("name", CORPUS_NAMES)
def test_hardened_consumers_resolve(name: str) -> None:
    """No pinned step reads as PPA009 or PPA013."""
    text = (CORPUS / f"{name}.yaml").read_text()
    assert found(text) == []


@pytest.mark.parametrize("name", CORPUS_NAMES)
def test_hardened_corpus_reports_what_main_did(name: str) -> None:
    """Only the setup-uv step's PPA011, which main reports too, remains."""
    text = (CORPUS / f"{name}.yaml").read_text()
    assert {f.split()[0] for f in found(text, None)} == {"PPA011"}


def test_pypi_output_is_trusted() -> None:
    """pypi-version-check-action's own consumer runs the step's path output.

    The pinned consumer, with its unset, is the fixture's last step;
    without the lookup's ``--managed-python`` it is PPA009 again.
    """
    text = (CORPUS / "pypi-version-check-action.yaml").read_text()
    consumer_line = '"$PYTHON" -I "$GITHUB_ACTION_PATH/scripts/check_index.py"'
    line = 1 + text.splitlines().index(f"        {consumer_line}")
    assert found(text) == []
    untrusted = text.replace("python find --managed-python", "python find")
    assert [f.split(":")[0] for f in found(untrusted, ("PPA009",))] == [
        f"PPA009 {line}"
    ]


# -- unset


def test_literal_unset_keeps_other_names() -> None:
    """``unset NAME`` changes NAME alone."""
    assert found(consumer("unset PYTHONEXECUTABLE __PYVENV_LAUNCHER__")) == []
    assert found(consumer("unset PYTHON")) != []


CASE = 'for name in $(compgen -e); do\n  case "$name" in\n{arms}  esac\ndone'


@pytest.mark.parametrize(
    ("arms", "trusted"),
    [
        (
            "    PYTHON) ;;\n"
            '    PYTHON*|__PYVENV_LAUNCHER__) unset "$name" ;;\n',
            True,
        ),
        ('    PYTHON?*|__PYVENV_LAUNCHER__) unset "$name" ;;\n', True),
        # The arm matches the interpreter's own name.
        ('    PYTHON*|__PYVENV_LAUNCHER__) unset "$name" ;;\n', False),
        # ;& falls through from PYTHON into the unset.
        (
            "    PYTHON) ;&\n"
            '    PYTHON*|__PYVENV_LAUNCHER__) unset "$name" ;;\n',
            False,
        ),
        ('    PY[T]HON*) unset "$name" ;;\n', False),
        ('    PYTHON?*) echo; unset "$name" ;;\n', False),
        ('    PYTHON?*) unset "$other" ;;\n', False),
        ('    PYTHON?*) unset "${name}" ;;\n', True),
        # Unquoted, the name splits on IFS: PYTHONX unsets PYTHON.
        ("    PYTHON?*) unset $name ;;\n", False),
        ("    PYTHON?*) unset ${name} ;;\n", False),
    ],
)
def test_case_filtered_unset(arms: str, trusted: bool) -> None:
    """A case arm bounds what ``unset "$name"`` may remove."""
    assert (found(consumer(CASE.format(arms=arms))) == []) is trusted


def test_case_filter_under_nocasematch() -> None:
    """nocasematch changes what a pattern matches: no filter."""
    script = "shopt -s nocasematch\n" + CASE.format(
        arms='    PYTHON?*) unset "$name" ;;\n'
    )
    assert found(consumer(script)) != []


GREP = (
    'while IFS= read -r name; do\n  unset "${{name}}"\n'
    "done < <(compgen -e | {feed})"
)


@pytest.mark.parametrize(
    ("feed", "trusted"),
    [
        ("grep -E '^(PYTHON.+|__PYVENV_LAUNCHER__)$' || true", True),
        ("grep -E '^PYTHON.+$'", True),
        ("grep -E '^(PYTHON.*|__PYVENV_LAUNCHER__)$' || true", False),
        ("grep -E '^PYTHON.+$' || echo PYTHON", False),
        ("grep -vE '^X$'", False),
        ('grep -E "$re"', False),
        ("grep -E '^PYTHON[A-Z]+$'", False),
    ],
)
def test_grep_filtered_unset(feed: str, trusted: bool) -> None:
    """A grep -E feed bounds what the loop's unset may remove."""
    assert (found(consumer(GREP.format(feed=feed))) == []) is trusted


IFS_GREP = GREP.format(feed="grep -E '^PYTHONX$'")


@pytest.mark.parametrize(
    ("script", "trusted"),
    [
        (IFS_GREP, True),
        ("IFS=X\n" + IFS_GREP, True),
        ("IFS=X\n" + IFS_GREP.replace("IFS= ", ""), False),
        # Unquoted, the name read splits on IFS: PYTHONX unsets PYTHON.
        ("IFS=X\n" + IFS_GREP.replace('"${name}"', "$name"), False),
        (IFS_GREP.replace('"${name}"', "${name}"), False),
    ],
)
def test_grep_filter_under_a_set_ifs(script: str, trusted: bool) -> None:
    """With IFS=X, a bare ``read`` turns the line PYTHONX into PYTHON."""
    assert (found(consumer(script)) == []) is trusted


BACKSLASH_GREP = GREP.format(feed="grep -E '^PY.THON$'")


@pytest.mark.parametrize(
    ("script", "trusted"),
    [
        (BACKSLASH_GREP, True),
        (
            BACKSLASH_GREP.replace("read -r", "read"),
            False,
        ),
    ],
)
def test_grep_filter_needs_read_r(script: str, trusted: bool) -> None:
    """Without -r, ``read`` turns the line PY\\THON into PYTHON."""
    assert (found(consumer(script)) == []) is trusted


@pytest.mark.parametrize(
    "pattern",
    [
        "^PYTH.++N$",
        "^PYTHONX+?$",
        "^PYTHON.*+$",
    ],
)
def test_grep_filter_rejects_stacked_quantifiers(pattern: str) -> None:
    """Python reads ``++`` as possessive and ``+?`` as lazy; grep does not.

    grep -E matches PYTHON with each pattern, so the loop unsets it,
    while Python's search finds no match and would leave it trusted.
    """
    feed = f"grep -E '{pattern}'"
    assert found(consumer(GREP.format(feed=feed))) != []


# -- the cleared lookup


def lookup(
    appended: str,
    version: str = '"$PYTHON_VERSION"',
    flags: str = "--managed-python --system",
) -> str:
    """A producer whose env -i array a literal-name loop extends."""
    script = (
        "clean=(UV_NO_CONFIG=1 UV_NO_PROJECT=1\n"
        '  "UV_PYTHON_INSTALL_DIR=$INSTALL_DIR" "UV_CACHE_DIR=$CACHE_DIR")\n'
        f"for name in {appended}; do\n"
        '  if [ -n "${!name+set}" ]; then clean+=("$name=${!name}"); fi\n'
        "done\n"
        'PY=$(env -i "${clean[@]}" "$UV" python find \\\n'
        f"  {flags} {version})\n"
        'echo "path=$PY" >> "$GITHUB_OUTPUT"'
    )
    return action(
        "    - id: setup-uv\n      uses: astral-sh/setup-uv@v6\n",
        step(
            script,
            {
                "UV": "${{ steps.setup-uv.outputs.uv-path }}",
                "INSTALL_DIR": "${{ runner.temp }}/a/python",
                "CACHE_DIR": "${{ runner.temp }}/a/cache",
                "PYTHON_VERSION": "'3.13'",
            },
            "python",
        ),
        step(
            '"$PYTHON" -I s.py',
            {"PYTHON": "${{ steps.python.outputs.path }}"},
        ),
    )


@pytest.mark.parametrize(
    ("appended", "trusted"),
    [
        ("HTTP_PROXY HTTPS_PROXY NO_PROXY SSL_CERT_FILE", True),
        # Selectors, or allowed names, with the caller's value.
        ("HTTP_PROXY PATH", False),
        ("UV_PYTHON", False),
        ("UV_CACHE_DIR", False),
        ('"$names"', False),
    ],
)
def test_loop_appends_to_the_cleared_array(
    appended: str, trusted: bool
) -> None:
    """Each name a loop appends passes with a value the scan cannot read."""
    assert (found(lookup(appended)) == []) is trusted


CONDITIONAL_UV = "    - id: setup-uv\n      if: inputs.uv\n      uses: astral-sh/setup-uv@v6\n"


@pytest.mark.parametrize(
    ("command", "rules"),
    [
        ('"$UV" python find --managed-python 3.13', []),
        ('"$UV" python install --quiet 3.13', []),
        # As main reads it: the program is the unread array.
        ('"$UV" run s.py', ["PPA009 15: program is '\"${clean[@]}\"'"]),
    ],
)
def test_forwarded_array_before_an_unread_program(
    command: str, rules: list[str]
) -> None:
    """A program the scan cannot read past a forwarding array reads as main.

    Behind a conditional setup-uv, ``"$UV"`` is unresolved; the
    array's indirect reads must not expose it as a new PPA009.
    """
    script = (
        "clean=(UV_NO_CONFIG=1)\nfor name in HTTP_PROXY; do\n"
        '  clean+=("$name=${!name}")\ndone\n'
        f'env -i "${{clean[@]}}" {command}'
    )
    text = action(
        CONDITIONAL_UV,
        step(script, {"UV": "${{ steps.setup-uv.outputs.uv-path }}"}),
    )
    out = [f.split(",")[0] for f in found(text, ("PPA009",))]
    assert out == rules


def test_indirect_read_keeps_step_env_bindings() -> None:
    """``${!name}`` reads: it neither assigns nor makes the step opaque."""
    text = lookup("HTTP_PROXY").replace(
        "        done\n", '        done\n        echo "${!name}" "${!UV}"\n', 1
    )
    assert '"${!UV}"' in text
    assert found(text) == []


@pytest.mark.parametrize(
    ("flags", "rules"),
    [
        ("--managed-python --system", []),
        ("--managed-python", []),
        ("--system", []),
        ("", ["PPA007"]),
    ],
)
def test_lookup_workspace_verdict(flags: str, rules: list[str]) -> None:
    """``--managed-python`` keeps the lookup off a workspace ``.venv``."""
    text = lookup("HTTP_PROXY", flags=flags)
    assert [f.split()[0] for f in found(text, ("PPA006", "PPA007"))] == rules


EXPORT = '"$UV" export --no-config --locked --python "$PYTHON"'


@pytest.mark.parametrize(
    ("script", "rules"),
    [(f"{EXPORT} --script s.py", []), (EXPORT, ["PPA007"])],
)
def test_script_export_uses_no_project(script: str, rules: list[str]) -> None:
    """``uv export --script`` exports the script's lock, not a project's."""
    text = action(
        SETUP_PYTHON,
        "    - id: setup-uv\n      uses: astral-sh/setup-uv@v6\n",
        step(
            script,
            {
                "UV": "${{ steps.setup-uv.outputs.uv-path }}",
                "PYTHON": PYTHON_PATH,
            },
        ),
    )
    assert [f.split()[0] for f in found(text, ("PPA007",))] == rules


def test_runner_temp_values_may_pass() -> None:
    """``${{ runner.temp }}/…`` is outside the workspace; ``..`` is not."""
    assert is_outside_path(f"{TEMP_ROOT}/a/python")
    assert is_outside_path(f"{TEMP_ROOT}/a\\b/python")
    assert not is_outside_path(TEMP_ROOT)
    assert not is_outside_path(f"{TEMP_ROOT}/")
    assert not is_outside_path(f"{TEMP_ROOT}/../w/python")
    assert not is_outside_path(f"{TEMP_ROOT}/a/..\\w/python")
    assert not is_outside_path(f"{TEMP_ROOT}/a//python")
    assert not is_outside_path(f"{TEMP_ROOT}/{TEMP_ROOT}/python")


# -- composed interpreter paths


def venv(bin_value: str, env_dir: str = "${{ runner.temp }}/v") -> str:
    """``"${ENV_DIR}/${BIN}"`` as a later command's interpreter."""
    return action(
        step(
            'VPY="${ENV_DIR}/${BIN}"\n"$VPY" -I s.py',
            {"ENV_DIR": env_dir, "BIN": bin_value},
        )
    )


@pytest.mark.parametrize(
    ("bin_value", "trusted"),
    [
        (
            ">-\n          ${{ runner.os == 'Windows' && 'Scripts/python.exe'"
            " || 'bin/python' }}",
            True,
        ),
        ("${{ runner.os == 'Windows' && 'python.exe' || 'python3' }}", True),
        (
            "${{ runner.os == 'Windows' && 'Scripts/sh' || 'bin/python' }}",
            False,
        ),
        ("${{ runner.os == 'Windows' && '../python' || 'bin/python' }}", False),
        ("${{ inputs.a || 'Scripts/python.exe' && 'bin/python' }}", False),
        ("${{ inputs.bin }}", False),
    ],
)
def test_choice_expressions_compose_a_path(
    bin_value: str, trusted: bool
) -> None:
    """Every value of a composed word must be a trusted interpreter."""
    assert (found(venv(bin_value)) == []) is trusted


def test_composed_paths_need_a_trusted_root() -> None:
    """A root the scan cannot read, or the workspace, is no path outside."""
    choice = "${{ runner.os == 'Windows' && 'python.exe' || 'python3' }}"
    assert found(venv(choice, "${{ github.workspace }}/v")) != []
    assert found(venv(choice, "${{ inputs.dir }}")) != []


def test_composed_paths_keep_line_breaks() -> None:
    """A line break inside the quotes is part of the path, so no path."""
    text = action(
        step(
            'VPY="${ENV_DIR}/bin\n/python"\n"$VPY" -I s.py',
            {"ENV_DIR": "${{ runner.temp }}/v"},
        )
    )
    assert found(text) != []


def test_composed_words_as_command_arguments() -> None:
    """A composed word reads the same used directly or assigned first."""
    choice = "${{ runner.os == 'Windows' && 'python.exe' || 'python3' }}"
    script = 'uv pip install --no-config --python "${ENV_DIR}/${BIN}" .'
    env = {"ENV_DIR": "${{ runner.temp }}/v", "BIN": choice}
    assert found(action(step(script, env))) == []
    env["ENV_DIR"] = "${{ inputs.dir }}"
    assert found(action(step(script, env))) != []


@pytest.mark.parametrize(
    "script",
    ['"${ROOT}/pypy3" -m pkg', 'P="${ROOT}/pypy3"\n"$P" -m pkg'],
)
def test_composed_programs_stay_unresolved(script: str) -> None:
    """A composed program neither Python nor uv is PPA009, direct or assigned."""
    text = action(step(script, {"ROOT": "/opt/private"}))
    assert [f.split()[0] for f in found(text)] == ["PPA009"]


@pytest.mark.parametrize(
    "script",
    [
        '"${ROOT}/Scripts/python.exe" -I s.py',
        'P="${ROOT}/Scripts/python.exe"\n"$P" -I s.py',
    ],
)
def test_composed_windows_python_reads_as_python(script: str) -> None:
    """One composed ``python.exe`` path is trusted, as two choices are."""
    assert found(action(step(script, {"ROOT": "${{ runner.temp }}/v"}))) == []


def test_composed_workspace_windows_python_stays_unresolved() -> None:
    """A ``python.exe`` path under the workspace is no path outside."""
    script = '"${ROOT}/Scripts/python.exe" -I s.py'
    text = action(step(script, {"ROOT": "${{ github.workspace }}/v"}))
    assert [f.split()[0] for f in found(text)] == ["PPA009"]


def test_composed_python_programs_read_as_python() -> None:
    """A composed path to python3 is judged as Python, not as unresolved."""
    text = action(step('"${ROOT}/python3" -m pkg', {"ROOT": "/opt/private"}))
    assert [f.split()[0] for f in found(text, None)] == ["PPA001"]


def test_quoted_path_expressions_read_as_inline() -> None:
    """``"$ACTION_PATH"`` reads as ``${{ github.action_path }}`` would."""
    text = action(
        SETUP_PYTHON,
        step(
            'uv sync --no-config --project "${ACTION_PATH}" --python "$PYTHON"',
            {
                "ACTION_PATH": "${{ github.action_path }}",
                "PYTHON": PYTHON_PATH,
                "UV_PROJECT_ENVIRONMENT": "${{ runner.temp }}/lint",
            },
        ),
    )
    assert found(text) == []
    assert found(text.replace("github.action_path", "inputs.path")) != []


def test_leaf_subcommand_operands_are_not_subcommands() -> None:
    """``uv venv DIR``: DIR is an operand, whatever it holds."""
    text = action(
        SETUP_PYTHON,
        step(
            'uv venv --no-config --python "$PYTHON" "$DIR"',
            {"PYTHON": PYTHON_PATH, "DIR": "${{ runner.temp }}/v"},
        ),
    )
    assert found(text) == []


@pytest.mark.parametrize(
    "operand",
    [
        '"$DIR"',
        "$DIR",
        '"${DIR}/v"',
        '"${{ inputs.dir }}"',
    ],
)
def test_leaf_operands_may_hold_options(operand: str) -> None:
    """An operand the scan cannot read may expand to ``--python=...``."""
    text = action(
        step(
            f"uv venv --no-config {operand}",
            {"UV_PYTHON": "/usr/bin/python3", "DIR": "${{ inputs.dir }}"},
        )
    )
    assert [f.split()[0] for f in found(text)] == ["PPA009"]


def test_leaf_operands_quoted_in_part() -> None:
    """``"${DIR}/v"$EXTRA`` may split off ``--python=...``."""
    text = action(
        step(
            'uv venv --no-config "${DIR}/v"$EXTRA',
            {
                "UV_PYTHON": "/usr/bin/python3",
                "DIR": "${{ runner.temp }}",
                "EXTRA": "${{ inputs.extra }}",
            },
        )
    )
    assert [f.split()[0] for f in found(text)] == ["PPA009"]


def test_workflow_action_path_is_no_path() -> None:
    """A workflow's ``${{ github.action_path }}`` is empty: no exemption."""
    script = 'uv venv --no-config "${ACTION_PATH}${OPT}"'
    env = {
        "UV_PYTHON": "/usr/bin/python3",
        "ACTION_PATH": "${{ github.action_path }}",
        "OPT": "${{ inputs.option }}",
    }
    workflow = (
        "on: push\njobs:\n  j:\n    runs-on: ubuntu-latest\n"
        "    steps:\n" + step(script, env)
    )
    assert [f.split()[0] for f in found(workflow, kind="workflow")] == [
        "PPA009"
    ]
    assert found(action(step(script, env))) == []


def test_leaf_operands_under_a_path_expression() -> None:
    """``"${DIR}/v"`` under ``${{ runner.temp }}`` starts with a path."""
    text = action(
        step(
            'uv venv --no-config "${DIR}/v"',
            {"UV_PYTHON": "/usr/bin/python3", "DIR": "${{ runner.temp }}"},
        )
    )
    assert found(text) == []


# -- the stated-rule gaps


@pytest.mark.parametrize(
    "wrapper",
    [
        "env -u UV_PYTHON",
        "env --unset=UV_PYTHON",
        "env --unset UV_PYTHON",
        "env --uns=UV_PYTHON",
        "env -uUV_PYTHON",
    ],
)
def test_env_unset_removes_an_inherited_uv_python(wrapper: str) -> None:
    """A wrapper's -u drops UV_PYTHON from the trust decision."""
    text = action(
        step(
            f"{wrapper} uv pip install --no-config .",
            {"UV_PYTHON": "/usr/bin/python3"},
        )
    )
    assert [f.split(":")[0].split()[0] for f in found(text, ("PPA013",))] == [
        "PPA013"
    ]


def test_env_unset_then_set_keeps_the_value() -> None:
    """A later NAME=value sets what -u removed."""
    text = action(
        step(
            "env -u UV_PYTHON UV_PYTHON=/usr/bin/python3 "
            "uv pip install --no-config .",
            {"UV_PYTHON": "/usr/bin/python3"},
        )
    )
    assert found(text, ("PPA013",)) == []


def test_env_unset_unread_drops_wrapper_values() -> None:
    """An unread -u operand may remove an earlier wrapper's UV_PYTHON."""
    texts = ["env", "UV_PYTHON=/usr/bin/python3", "env", "-u", '\x00"$N"']
    assert env_of(texts, texts).names == {"UV_PYTHON": None}
    texts = [*texts, "UV_PYTHON=/usr/bin/python3"]
    assert env_of(texts, texts).names == {"UV_PYTHON": "/usr/bin/python3"}


@pytest.mark.parametrize("operand", ['"$NAME"', "${{ inputs.name }}"])
def test_env_unset_unread_drops_a_wrapper_safe_path(operand: str) -> None:
    """PYTHONSAFEPATH set before an unread -u operand may not reach Python."""
    text = action(step(f"env PYTHONSAFEPATH=1 env -u {operand} python3 -m pkg"))
    findings = found(text, ("PPA001",))
    assert len(findings) == 1
    assert "PYTHONSAFEPATH" not in findings[0]


def env_write(script: str) -> str:
    return action(SETUP_PYTHON, step(script, {"PY": PYTHON_PATH}))


@pytest.mark.parametrize(
    ("script", "trusted"),
    [
        ('echo "UV_PYTHON=$PY" >> "$GITHUB_ENV"', True),
        ('echo UV_PYTHON="$PY" >> "$GITHUB_ENV"', True),
        ('printf \'UV_PYTHON=%s\\n\' "$PY" >> "$GITHUB_ENV"', True),
        ('X=/usr/bin/python3\necho UV_PYTHON=$X >> "$GITHUB_ENV"', True),
        ('echo UV_PYTHON=$PY >> "$GITHUB_ENV"', False),
        ("printf 'UV_PYTHON=%s\\n' $PY >> \"$GITHUB_ENV\"", False),
        ("X='/opt/a b/python'\necho UV_PYTHON=$X >> \"$GITHUB_ENV\"", False),
        ("X='/opt/py*'\necho UV_PYTHON=${X} >> \"$GITHUB_ENV\"", False),
        # ${{ runner.temp }} may hold a blank on a self-hosted runner.
        (
            'X="${{ runner.temp }}/v/bin/python"\n'
            'printf \'UV_PYTHON=%s\\n\' "$X" >> "$GITHUB_ENV"',
            True,
        ),
        (
            'X="${{ runner.temp }}/v/bin/python"\n'
            "printf 'UV_PYTHON=%s\\n' $X >> \"$GITHUB_ENV\"",
            False,
        ),
    ],
)
def test_unquoted_env_file_values_that_may_split(
    script: str, trusted: bool
) -> None:
    """``$GITHUB_ENV`` writes split as ``$GITHUB_OUTPUT`` writes do."""
    assert (found(env_write(script), ("PPA013",)) == []) is trusted


@pytest.mark.parametrize(
    ("value", "script", "trusted"),
    [
        (
            "'/opt/a b/python'",
            'printf \'UV_PYTHON=%s\\n\' "$PYTHONPATH" >> "$GITHUB_ENV"',
            True,
        ),
        (
            "/opt/python",
            "printf 'UV_PYTHON=%s\\n' $PYTHONPATH >> \"$GITHUB_ENV\"",
            True,
        ),
        (
            "'/opt/a b/python'",
            "printf 'UV_PYTHON=%s\\n' $PYTHONPATH >> \"$GITHUB_ENV\"",
            False,
        ),
        (
            "'/opt/a b/python'",
            'echo UV_PYTHON=${PYTHONPATH} >> "$GITHUB_ENV"',
            False,
        ),
    ],
)
def test_unquoted_pythonpath_in_env_file_writes(
    value: str, script: str, trusted: bool
) -> None:
    """An unquoted ``$PYTHONPATH`` splits as any other reference does."""
    text = action(step(script, {"PYTHONPATH": value}))
    assert (found(text, ("PPA013",)) == []) is trusted


def test_install_output_is_not_an_interpreter() -> None:
    """``uv python install`` prints a path on some uv versions only."""
    text = action(
        step(
            "py=$(env -i PATH=/usr/bin uv python install --managed-python "
            '3.12)\necho "python=$py" >> "$GITHUB_OUTPUT"',
            sid="find",
        ),
        step(
            "uv pip install --no-config --python "
            '"${{ steps.find.outputs.python }}" .'
        ),
    )
    assert found(text, ("PPA009",)) != []
