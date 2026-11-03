# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""The caller's environment must not choose the Action's interpreter.

A composite action inherits the caller job's environment. A ``PATH``,
``UV_PYTHON``, ``VIRTUAL_ENV`` or ``PYTHONPATH`` written to
``$GITHUB_ENV`` by an earlier step would otherwise pick, or redirect,
the Python that ``setup-uv``, ``uv`` and the linter run, with the job's
tokens in reach.

These tests read ``action.yaml`` and pin the guarded form: the
``setup-uv`` step's inputs and environment, one trusted interpreter
taken from ``actions/setup-python``, every ``uv`` call naming it with
``--python``, and every Python start using it by path with ``-I``. The
CI job ``Workspace Isolation`` in ``testing.yaml`` proves the same
against a live runner.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
ACTION = yaml.safe_load((ROOT / "action.yaml").read_text(encoding="utf-8"))
STEPS: list[dict[str, Any]] = ACTION["runs"]["steps"]

#: The trusted interpreter: setup-python's absolute path output.
TRUSTED_PYTHON = "${{ steps.setup-python.outputs.python-path }}"

#: uv by the absolute path setup-uv reports, never from ``PATH``.
TRUSTED_UV = "${{ steps.setup-uv.outputs.uv-path }}"

#: The ``setup-uv`` inputs that keep it from executing a caller-chosen
#: interpreter or putting a caller-chosen directory on ``PATH``.
SETUP_UV_WITH = {
    "working-directory": "${{ github.action_path }}",
    "tool-bin-dir": "${{ runner.temp }}/gha-workflow-linter/bin",
    "enable-cache": False,
}

#: ``setup-uv``'s step environment. The invalid preference makes uv
#: refuse its arguments before any interpreter lookup.
SETUP_UV_ENV = {
    "UV_NO_CONFIG": "1",
    "UV_NO_PROJECT": "1",
    "UV_PYTHON_PREFERENCE": "lookup-disabled",
    "UV_PYTHON_ARCH": "",
    "UV_PYTHON_INSTALL_DIR": "${{ runner.temp }}/gha-workflow-linter/python",
}

_UV_COMMAND = re.compile(r'(?:^|[\s;&|(])("\$UV"|uvx|uv)(?=\s)')
_PYTHON_REFERENCE = re.compile(r'"\$TRUSTED_PYTHON"')
_BARE_PYTHON = re.compile(r"(?:^|[\s;&|(])python3?(?:\.\d+)?(?=\s|$)")

#: How the runner starts a ``shell: bash`` step.
GITHUB_BASH = ["bash", "--noprofile", "--norc", "-eo", "pipefail"]

#: Settings an earlier step of the caller's job could export. The
#: install step must clear them before uv starts a build backend.
CALLER_PYTHON_ENV = {
    "PYTHON": "/caller/bin/python3",
    "PYTHONPATH": "pkg:.",
    "PYTHONHOME": "/caller",
    "PYTHONSTARTUP": "/caller/startup.py",
    "PYTHONEXECUTABLE": "/caller/bin/python3",
    "__PYVENV_LAUNCHER__": "/caller/bin/python3",
}

#: Stands in for uv and for the trusted interpreter: records which it
#: was started as, its arguments and the ``PYTHON*`` settings it
#: inherited, one JSON line per start.
_STUB = """#!{python} -I
import json, os, sys
seen = {{k: v for k, v in os.environ.items()
         if k.startswith("PYTHON") or k == "__PYVENV_LAUNCHER__"}}
record = {{"tool": os.path.basename(sys.argv[0]), "argv": sys.argv[1:],
           "env": seen}}
with open(os.environ["UV_STUB_LOG"], "a", encoding="utf-8") as log:
    log.write(json.dumps(record) + "\\n")
"""


def _step(step_id: str) -> dict[str, Any]:
    """Return the composite step with the given ``id``.

    Args:
        step_id: The step's ``id``.

    Returns:
        The step mapping.
    """
    matches = [step for step in STEPS if step.get("id") == step_id]
    assert len(matches) == 1, f"expected one step with id {step_id!r}"
    return matches[0]


def _commands() -> list[tuple[str, dict[str, Any], str]]:
    """Return every command line of every ``run:`` step.

    Continued lines are joined and comments dropped, so each entry is
    one command as bash reads it.

    Returns:
        ``(step name, step, command)`` triples.
    """
    commands = []
    for step in STEPS:
        if "run" not in step:
            continue
        script = str(step["run"]).replace("\\\n", " ")
        for line in script.splitlines():
            text = line.strip()
            if text and not text.startswith("#"):
                commands.append((str(step.get("name")), step, text))
    return commands


def test_setup_uv_step_is_guarded() -> None:
    step = _step("setup-uv")

    assert str(step["uses"]).startswith("astral-sh/setup-uv@")
    assert step["with"] == SETUP_UV_WITH
    assert step["env"] == SETUP_UV_ENV


def test_setup_python_is_the_trusted_interpreter() -> None:
    step = _step("setup-python")

    assert str(step["uses"]).startswith("actions/setup-python@")


def test_steps_bind_the_trusted_tools() -> None:
    for step in STEPS:
        env = step.get("env") or {}
        if "TRUSTED_PYTHON" in env:
            assert env["TRUSTED_PYTHON"] == TRUSTED_PYTHON, step.get("name")
        if "UV" in env:
            assert env["UV"] == TRUSTED_UV, step.get("name")

    used = [cmd for _, _, cmd in _commands()]
    assert any(_UV_COMMAND.search(cmd) for cmd in used)
    assert any(_PYTHON_REFERENCE.search(cmd) for cmd in used)


def test_every_uv_call_names_the_trusted_interpreter() -> None:
    for name, step, command in _commands():
        for match in _UV_COMMAND.finditer(command):
            assert match.group(1) == '"$UV"', f"{name}: {command}"
            assert "UV" in (step.get("env") or {}), name
            rest = command[match.end() :]
            assert '--python "$TRUSTED_PYTHON"' in rest or command.startswith(
                "env -i "
            ), f"{name}: {command}"
            assert "--system" not in rest, f"{name}: {command}"
            assert "--managed-python" not in rest or command.startswith(
                "env -i "
            ), f"{name}: {command}"


def test_uv_builds_without_caller_python_settings() -> None:
    for step in STEPS:
        script = str(step.get("run", ""))
        uses_uv = any(
            _UV_COMMAND.search(cmd) for _, s, cmd in _commands() if s is step
        )
        if uses_uv:
            assert "PYTHON* | __PYVENV_LAUNCHER__) unset" in script, step.get(
                "name"
            )


def test_every_python_start_is_isolated() -> None:
    starts = 0
    for name, _, command in _commands():
        assert not _BARE_PYTHON.search(command), f"{name}: {command}"
        for match in _PYTHON_REFERENCE.finditer(command):
            before = command[: match.start()].rstrip()
            if before.endswith(("--python", "case")):
                continue
            starts += 1
            after = command[match.end() :].split()
            assert after[:1] == ["-I"], f"{name}: {command}"
    assert starts, "no step starts the trusted interpreter"


def test_linter_runs_through_the_trusted_interpreter() -> None:
    script = str(_step("gha-workflow-linter")["run"])

    assert 'linter=("$TRUSTED_PYTHON" -I -m gha_workflow_linter.cli)' in script
    assert '"${linter[@]}" lint ' in script
    assert "uvx" not in script
    assert "cmd_prefix" not in script


def test_cleanup_spares_the_trusted_bindings() -> None:
    checked = 0
    for step in STEPS:
        if "PYTHON* | __PYVENV_LAUNCHER__) unset" not in str(
            step.get("run", "")
        ):
            continue
        env = step.get("env") or {}
        cleared = [
            key
            for key in env
            if key.startswith("PYTHON") or key == "__PYVENV_LAUNCHER__"
        ]
        assert not cleared, f"{step.get('name')}: {cleared}"
        assert env.get("TRUSTED_PYTHON") == TRUSTED_PYTHON, step.get("name")
        checked += 1
    assert checked, "no step clears the caller's PYTHON* settings"


#: The system part of the ``PATH`` that ``_run_step`` gives a step,
#: after the stubs.
_STEP_PATH = os.pathsep.join(["/usr/bin", "/bin"])


def _run_step(
    tmp_path: Path, name: str, env: dict[str, str]
) -> subprocess.CompletedProcess[str]:
    """Execute a step's ``run:`` block the way the runner would.

    ``uv`` is a stub, both as ``$UV`` and on ``PATH``, so no real
    install happens whichever form the script takes. A ``python3`` stub
    beside it can stand in for the trusted interpreter.

    Args:
        tmp_path: Scratch directory for the stub and its log.
        name: The step's ``name``.
        env: Step environment on top of the stub's own.

    Returns:
        The finished process.
    """
    (step,) = [s for s in STEPS if s.get("name") == name]
    script = tmp_path / "step.sh"
    script.write_text(str(step["run"]), encoding="utf-8")
    stub_dir = tmp_path / "stub-bin"
    stub_dir.mkdir()
    stub = stub_dir / "uv"
    for tool in ("uv", "python3"):
        path = stub_dir / tool
        path.write_text(_STUB.format(python=sys.executable), encoding="utf-8")
        path.chmod(0o755)
    github_env = tmp_path / "github_env"
    github_env.write_text("", encoding="utf-8")
    full_env = {
        "PATH": f"{stub_dir}{os.pathsep}{_STEP_PATH}",
        "UV": str(stub),
        "UV_STUB_LOG": str(tmp_path / "uv.jsonl"),
        "GITHUB_ENV": str(github_env),
        **env,
    }
    return subprocess.run(
        [*GITHUB_BASH, str(script)],
        env=full_env,
        capture_output=True,
        text=True,
        check=False,
        cwd=tmp_path,
    )


def _starts(tmp_path: Path) -> list[dict[str, Any]]:
    """Return what the stubs recorded, one entry per start.

    Args:
        tmp_path: The directory ``_run_step`` ran in.

    Returns:
        ``{"tool": ..., "argv": [...], "env": {...}}`` per start.
    """
    log = tmp_path / "uv.jsonl"
    if not log.exists():
        return []
    return [
        json.loads(line)
        for line in log.read_text(encoding="utf-8").splitlines()
        if line
    ]


_NEEDS_BASH = pytest.mark.skipif(
    shutil.which("bash") is None, reason="the step script needs bash"
)

#: The run step reads the linter's document with jq, from the ``PATH``
#: ``_run_step`` gives it, so a run expected to succeed needs jq there.
_NEEDS_JQ = pytest.mark.skipif(
    shutil.which("jq", path=_STEP_PATH) is None,
    reason="the run step needs jq on /usr/bin or /bin",
)


@_NEEDS_BASH
@pytest.mark.parametrize("source_tree", [True, False], ids=["source", "pypi"])
def test_install_keeps_the_trusted_interpreter(
    tmp_path: Path, source_tree: bool
) -> None:
    action_path = tmp_path / "action"
    action_path.mkdir()
    if source_tree:
        (action_path / "pyproject.toml").write_text("", encoding="utf-8")
    trusted = str(tmp_path / "trusted" / "bin" / "python3")

    result = _run_step(
        tmp_path,
        "Install gha-workflow-linter",
        {
            **CALLER_PYTHON_ENV,
            "ACTION_PATH": str(action_path),
            "TRUSTED_PYTHON": trusted,
        },
    )

    assert result.returncode == 0, result.stderr
    (start,) = _starts(tmp_path)
    assert start["tool"] == "uv", start
    argv = start["argv"]
    assert argv[:2] == ["pip", "install"], argv
    assert argv[argv.index("--python") + 1] == trusted, argv
    assert "--system" not in argv, argv
    assert start["env"] == {}, start["env"]


@_NEEDS_BASH
def test_pypi_install_upgrades_an_installed_linter(tmp_path: Path) -> None:
    # setup-python's interpreter is shared by the whole job, so an
    # earlier step may already have installed an older release there;
    # a bare install would keep it, and the run step would start it.
    action_path = tmp_path / "action"
    action_path.mkdir()
    trusted = str(tmp_path / "trusted" / "bin" / "python3")

    result = _run_step(
        tmp_path,
        "Install gha-workflow-linter",
        {"ACTION_PATH": str(action_path), "TRUSTED_PYTHON": trusted},
    )

    assert result.returncode == 0, result.stderr
    (start,) = _starts(tmp_path)
    argv = start["argv"]
    assert argv[:2] == ["pip", "install"], argv
    assert argv[argv.index("--upgrade-package") + 1] == "gha-workflow-linter"
    assert argv[-1] == "gha-workflow-linter", argv


@_NEEDS_BASH
@pytest.mark.parametrize(
    ("name", "trusted"),
    [
        ("Install gha-workflow-linter", ""),
        ("Install gha-workflow-linter", "python3"),
        ("Run gha-workflow-linter", ""),
        ("Run gha-workflow-linter", "python3"),
    ],
)
def test_step_refuses_an_untrusted_interpreter(
    tmp_path: Path, name: str, trusted: str
) -> None:
    action_path = tmp_path / "action"
    action_path.mkdir()

    result = _run_step(
        tmp_path,
        name,
        {
            **CALLER_PYTHON_ENV,
            "ACTION_PATH": str(action_path),
            "TRUSTED_PYTHON": trusted,
            "INPUT_PATH": str(tmp_path),
            "RUNNER_TEMP": str(tmp_path),
        },
    )

    assert result.returncode != 0, result.stdout
    assert "no absolute trusted interpreter" in result.stderr, result.stderr
    assert _starts(tmp_path) == []


@_NEEDS_BASH
@pytest.mark.parametrize("value", [None, "", "1"], ids=["unset", "empty", "1"])
def test_inherited_no_modify_path_is_refused(
    tmp_path: Path, value: str | None
) -> None:
    # With UV_NO_MODIFY_PATH set, setup-uv runs a bare "uv python find",
    # so the caller's PATH would pick that uv before any guard applies.
    names = [step.get("id") for step in STEPS]
    assert names.index("no-modify-path") < names.index("setup-uv")
    env = {} if value is None else {"UV_NO_MODIFY_PATH": value}

    result = _run_step(tmp_path, str(_step("no-modify-path")["name"]), env)

    if value is None:
        assert result.returncode == 0, result.stdout
    else:
        assert result.returncode != 0, result.stdout
        assert "UV_NO_MODIFY_PATH" in result.stdout, result.stdout
    assert _starts(tmp_path) == []


def _run_linter_step(
    tmp_path: Path, env: dict[str, str]
) -> subprocess.CompletedProcess[str]:
    """Execute the run step against an empty tree.

    Args:
        tmp_path: Scratch directory for the step.
        env: Step environment, ``TRUSTED_PYTHON`` included.

    Returns:
        The finished process.
    """
    tree = tmp_path / "tree"
    tree.mkdir()
    return _run_step(
        tmp_path,
        "Run gha-workflow-linter",
        {
            "INPUT_PATH": str(tree),
            "RUNNER_TEMP": str(tmp_path),
            "GITHUB_OUTPUT": str(tmp_path / "github_output"),
            "GITHUB_STEP_SUMMARY": str(tmp_path / "github_summary"),
            **env,
        },
    )


@_NEEDS_BASH
def test_linter_starts_without_caller_python_settings(tmp_path: Path) -> None:
    # -I ignores PYTHON* settings but not __PYVENV_LAUNCHER__, so the
    # run step clears the caller's before it starts the interpreter.
    trusted = str(tmp_path / "stub-bin" / "python3")

    _run_linter_step(tmp_path, {**CALLER_PYTHON_ENV, "TRUSTED_PYTHON": trusted})

    starts = _starts(tmp_path)
    assert starts, "the run step never started the trusted interpreter"
    for start in starts:
        assert start["tool"] == "python3", start
        assert start["argv"][:1] == ["-I"], start
        assert start["env"] == {}, start["env"]


def _caller_venv(tmp_path: Path, marker: Path) -> Path:
    """Plant a virtual environment whose site-packages runs bait.

    Its ``pyvenv.cfg`` points at the running interpreter's base, as a
    real one would, and a ``.pth`` file appends to ``marker`` whenever
    an interpreter loads that site-packages.

    Args:
        tmp_path: Scratch directory to plant it in.
        marker: The file the bait appends to.

    Returns:
        The path of the environment's ``bin/python3``, as a caller would
        name it in ``__PYVENV_LAUNCHER__``.
    """
    venv = tmp_path / "caller-venv"
    base = Path(getattr(sys, "_base_executable", sys.executable))
    version = f"{sys.version_info.major}.{sys.version_info.minor}"
    (venv / "bin").mkdir(parents=True)
    (venv / "pyvenv.cfg").write_text(
        f"home = {base.parent}\ninclude-system-site-packages = false\n"
        f"version = {sys.version_info.major}.{sys.version_info.minor}."
        f"{sys.version_info.micro}\n",
        encoding="utf-8",
    )
    site = venv / "lib" / f"python{version}" / "site-packages"
    site.mkdir(parents=True)
    (site / "bait.pth").write_text(
        f"import os; open({str(marker)!r}, 'a').write('venv site\\n')\n",
        encoding="utf-8",
    )
    launcher = venv / "bin" / "python3"
    launcher.symlink_to(base)
    return launcher


@_NEEDS_BASH
@_NEEDS_JQ
def test_caller_venv_launcher_cannot_redirect_python(tmp_path: Path) -> None:
    marker = tmp_path / "bait-ran"
    launcher = _caller_venv(tmp_path, marker)
    subprocess.run(
        [sys.executable, "-I", "-c", "pass"],
        env={
            "PATH": os.environ.get("PATH", ""),
            "__PYVENV_LAUNCHER__": str(launcher),
        },
        capture_output=True,
        check=False,
    )
    if not marker.exists():
        pytest.skip("this interpreter ignores __PYVENV_LAUNCHER__")
    marker.unlink()

    result = _run_linter_step(
        tmp_path,
        {
            "TRUSTED_PYTHON": sys.executable,
            "__PYVENV_LAUNCHER__": str(launcher),
            "PYTHONEXECUTABLE": str(launcher),
        },
    )

    assert not marker.exists(), marker.read_text(encoding="utf-8")
    assert result.returncode == 0, result.stdout + result.stderr
