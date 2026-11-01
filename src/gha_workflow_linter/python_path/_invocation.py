# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""What one command line starts: a Python interpreter, uv, or neither.

The walk in ``_walk`` resolves variables and wrappers, then passes the
command's words here as text, with what it knows about each word's
place on disk.
"""

from __future__ import annotations

from dataclasses import dataclass
import os
import re

INTERPRETER_NAME = re.compile(r"^python(?:3(?:\.\d+)?)?$")
# setup-python's python-path output and similar, after expression rewriting.
INTERPRETER_EXPR = re.compile(r"^__GH_\w*python(?:_path|_bin|_executable)?__$")
ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
# Words that may precede the command itself without being it. Shell
# keywords are among them, so a fragment such as "then python3 -m x"
# is still read.
PREFIXES = frozenset(
    {
        "!",
        "coproc",
        "if",
        "then",
        "else",
        "elif",
        "do",
        "while",
        "until",
        "{",
        "}",
    }
)
# Programs that run the program named after their options, and their
# options that take a value as the next word. A wrapper in POSITIONAL
# also takes that many plain arguments before the program.
WRAPPERS: dict[str, frozenset[str]] = {
    "builtin": frozenset(),
    "command": frozenset(),
    "exec": frozenset({"-a"}),
    "nice": frozenset({"-n", "--adjustment"}),
    "nohup": frozenset(),
    "stdbuf": frozenset({"-i", "-o", "-e"}),
    "sudo": frozenset(
        {"-u", "-g", "-C", "-D", "-h", "-p", "-r", "-t", "-U", "-T"}
    ),
    "time": frozenset({"-f", "-o"}),
    "timeout": frozenset({"-s", "-k", "--signal", "--kill-after"}),
    "xargs": frozenset(
        {
            "-a",
            "-d",
            "-E",
            "-I",
            "-L",
            "-n",
            "-P",
            "-s",
            "--arg-file",
            "--delimiter",
        }
    ),
}
POSITIONAL = {"timeout": 1}
# env's options that take the next word as their value.
ENV_VALUE_OPTIONS = frozenset(
    {"-u", "--unset", "-C", "--chdir", "-S", "--split-string"}
)
# Tools whose ``run`` subcommand starts the program that follows.
RUNNERS = frozenset({"poetry", "pipenv", "pdm", "hatch", "rye"})
# uv options that take a value as the next word (``--name=value`` needs
# no entry). Global options are accepted before and after the
# subcommand.
UV_VALUE_OPTIONS = frozenset(
    {
        "--allow-insecure-host",
        "--build-constraints",
        "--cache-dir",
        "--color",
        "--config-file",
        "--config-setting",
        "--config-settings-package",
        "--constraints",
        "--default-index",
        "--directory",
        "--env-file",
        "--exclude-newer",
        "--exclude-newer-package",
        "--extra",
        "--extra-index-url",
        "--find-links",
        "--fork-strategy",
        "--from",
        "--group",
        "--index",
        "--index-strategy",
        "--index-url",
        "--keyring-provider",
        "--link-mode",
        "--no-binary-package",
        "--no-build-package",
        "--no-extra",
        "--no-group",
        "--only-group",
        "--overrides",
        "--package",
        "--prerelease",
        "--project",
        "--python",
        "--python-platform",
        "--python-preference",
        "--refresh-package",
        "--reinstall-package",
        "--resolution",
        "--upgrade-package",
        "--with",
        "--with-editable",
        "--with-requirements",
        "-C",
        "-P",
        "-b",
        "-c",
        "-f",
        "-i",
        "-p",
        "-r",
        "-w",
    }
)
INFO_FLAGS = frozenset(
    {
        "-h",
        "-?",
        "--help",
        "--help-all",
        "--help-env",
        "--help-xoptions",
        "-V",
        "-VV",
        "--version",
    }
)
PARTIAL = (
    "partial: -P/PYTHONSAFEPATH protect only on Python 3.11+ and leave "
    "empty PYTHONPATH entries in place; use -I"
)
# What removes each uv finding, by rule and subcommand.
UV_FIXES = {
    ("PPA006", "run"): (
        "uv run takes its interpreter from a .python-version the workspace "
        "can plant; pass --no-config, or --python"
    ),
    ("PPA006", "venv"): (
        "uv venv takes its interpreter from a .python-version the workspace "
        "can plant; pass --no-config, or --python"
    ),
    ("PPA006", "python"): (
        "uv python find reads a .python-version the workspace can plant; "
        "pass --no-config"
    ),
    ("PPA007", "run"): (
        "uv run uses a .venv in the workspace or any parent; pass --no-project "
        "with --python set to an absolute path, or set UV_PROJECT_ENVIRONMENT "
        "outside the workspace"
    ),
    ("PPA007", "export"): (
        "uv export uses the project's .venv in the workspace; set "
        "UV_PROJECT_ENVIRONMENT outside the workspace"
    ),
    ("PPA007", "python"): (
        "uv python find returns a .venv interpreter in the workspace or any "
        "parent; pass --system"
    ),
    ("PPA007", "pip"): (
        "uv pip uses a .venv in the workspace or any parent; pass --system, or "
        "--python set to an absolute path outside the workspace"
    ),
}


@dataclass
class Invocation:
    """What a single Python command line will do with sys.path."""

    mode: str
    flags: set[str]


@dataclass
class UvEnv:
    """What the environment of one uv process sets, as far as is known.

    Each flag is true only when every path through the shell sets it:
    a setting that is only sometimes present protects nothing.
    """

    no_config: bool = False
    system: bool = False
    no_project: bool = False
    any_python: bool = False
    python_path: bool = False
    venv: bool = False
    project_env: bool = False


@dataclass
class UvCommand:
    """A uv command line: subcommand, its own options, and their values.

    ``values`` maps an option to the index of the word holding its
    value, and whether that word is the option's own ``--name=value``.
    """

    subcommand: list[str]
    options: set[str]
    values: dict[str, tuple[int, bool]]


def program_name(word: str) -> str:
    """A program word as the name it runs: ``/usr/local/bin/uv`` is ``uv``."""
    return os.path.basename(word) if "/" in word else word


def literal_invocation(words: list[str]) -> Invocation | None:
    """The Python invocation a simple command makes, if it makes one.

    Looks past wrappers (``exec``, ``env``, ``timeout``, ``uv run``,
    ``uvx`` and similar, by name or path) to the program the command
    runs.
    """
    index = 0
    while index < len(words):
        word = program_name(words[index])
        if word in PREFIXES or ASSIGNMENT.match(words[index]):
            index += 1
        elif word in WRAPPERS:
            index = skip_wrapper(words, index)
        elif word == "env":
            index = _skip_env(words, index + 1)
        elif word in RUNNERS and words[index + 1 : index + 2] == ["run"]:
            index += 2
        elif word in ("uv", "uvx"):
            index, module = _uv_program(words, index)
            if module:
                return Invocation("module", set())
            if index < 0:
                return None
        elif INTERPRETER_NAME.match(os.path.basename(word)) or (
            INTERPRETER_EXPR.match(word)
        ):
            return parse_invocation(words[index + 1 :])
        else:
            return None
    return None


def skip_wrapper(words: list[str], index: int) -> int:
    """The index of the program a wrapper at ``index`` runs.

    ``command -v`` and ``command -V`` only look a name up: they run
    nothing, so the index returned is past the end.
    """
    name = program_name(words[index])
    takes_value = WRAPPERS[name]
    positional = POSITIONAL.get(name, 0)
    index += 1
    while index < len(words) and words[index].startswith("-"):
        if words[index] == "--":
            index += 1
            break
        if name == "command" and set(words[index][1:]) & {"v", "V"}:
            return len(words)
        index += 2 if words[index] in takes_value else 1
    return index + positional


def _uv_program(words: list[str], index: int) -> tuple[int, bool]:
    """Where the program ``uv run``, ``uv tool run`` or ``uvx`` starts.

    Returns -1 for any other uv command, and True when ``-m`` names a
    module to run instead. uv's global options may come first.
    """
    subcommand: list[str] = (
        [] if program_name(words[index]) == "uv" else ["tool", "run"]
    )
    index += 1
    while index < len(words) and subcommand in ([], ["tool"]):
        word = words[index]
        if word.startswith("-"):
            index += 2 if word in UV_VALUE_OPTIONS else 1
        else:
            subcommand.append(word)
            index += 1
    if subcommand not in (["run"], ["tool", "run"]):
        return -1, False
    return _uv_run_program(words, index)


def program_positions(words: list[str]) -> set[int]:
    """The indices where a command line names a program to run.

    The first program, and each program a wrapper (``env``, ``sudo``,
    ``uv run`` and the like) runs in turn.
    """
    found: set[int] = set()
    index = 0
    while index < len(words):
        word = program_name(words[index])
        if word in PREFIXES or ASSIGNMENT.match(words[index]):
            index += 1
            continue
        found.add(index)
        if word in WRAPPERS:
            index = skip_wrapper(words, index)
        elif word == "env":
            index = _skip_env(words, index + 1)
        elif word in RUNNERS and words[index + 1 : index + 2] == ["run"]:
            index += 2
        elif word in ("uv", "uvx"):
            index, module = _uv_program(words, index)
            if index < 0 or module:
                break
        else:
            break
    return found


def env_assignments(words: list[str]) -> list[int]:
    """Where the ``env`` calls in a command's wrapper chain assign variables.

    Follows the same wrappers as :func:`literal_invocation`, nested
    ``env`` included, and returns the index of each ``NAME=value`` word
    an ``env`` passes to the program it runs.
    """
    found: list[int] = []
    index = 0
    while index < len(words):
        word = program_name(words[index])
        if word in PREFIXES or ASSIGNMENT.match(words[index]):
            index += 1
        elif word in WRAPPERS:
            index = skip_wrapper(words, index)
        elif word == "env":
            index += 1
            while index < len(words) and words[index] != "--":
                if ASSIGNMENT.match(words[index]):
                    found.append(index)
                elif not words[index].startswith("-"):
                    break
                index += 2 if words[index] in ENV_VALUE_OPTIONS else 1
            index += 1 if index < len(words) and words[index] == "--" else 0
        else:
            break
    return found


def _skip_env(words: list[str], index: int) -> int:
    """The index of the program after ``env`` and its options."""
    while index < len(words):
        word = words[index]
        if word == "--":
            return index + 1
        if not (word.startswith("-") or ASSIGNMENT.match(word)):
            return index
        index += 2 if word in ENV_VALUE_OPTIONS else 1
    return index


def _uv_run_program(words: list[str], index: int) -> tuple[int, bool]:
    """Where ``uv run``'s program starts; True when ``-m`` names a module."""
    while index < len(words) and words[index].startswith("-"):
        word = words[index]
        if word == "--":
            return index + 1, False
        if word in ("-m", "--module"):
            return index + 1, True
        index += 2 if word in UV_VALUE_OPTIONS else 1
    return index, False


def parse_invocation(words: list[str]) -> Invocation:
    """Work out the mode and options of ``python <words>``.

    Mirrors CPython's option parser closely enough for this purpose:
    short options combine (``-Im``), ``-m`` and ``-c`` take the rest
    of their word or the next one, and ``-W``/``-X`` take a value.
    Redirections are not among the words: with no script, code comes
    from standard input, whether a heredoc, a pipe or a file feeds it.
    """
    flags: set[str] = set()
    index = 0
    while index < len(words):
        mode, skip = _next_argument(words, index, flags)
        if mode:
            return Invocation(mode, flags)
        index += skip
    return Invocation("stdin", flags)


def _next_argument(
    words: list[str], index: int, flags: set[str]
) -> tuple[str, int]:
    """Read the argument at ``index``: the mode it settles, or how far to skip.

    A value the scan cannot know (``$x``) is a script or options: read
    as options when ``-c`` or ``-m`` follows, which a script rarely
    takes, so the riskier reading is reported.
    """
    word = words[index]
    fixed = {"-": "stdin", **dict.fromkeys(INFO_FLAGS, "info")}
    if word in fixed:
        return fixed[word], 0
    if word == "--":
        following = words[index + 1 : index + 2]
        return ("stdin" if following in ([], ["-"]) else "script"), 0
    if word.startswith("--"):
        return "", 2 if word == "--check-hash-based-pycs" else 1
    if word.startswith("-") and len(word) > 1:
        return _short_options(word, flags)
    if word.startswith("$"):
        rest = parse_invocation(words[index + 1 :])
        if rest.mode in ("module", "command"):
            flags.update(rest.flags)
            return rest.mode, 0
    return "script", 0


def _short_options(word: str, flags: set[str]) -> tuple[str, int]:
    """Read one word of combined short options into ``flags``.

    Returns the mode when ``-m`` or ``-c`` ends the options, and how
    many words the options use (two when ``-W``/``-X`` take the next).
    """
    for position, letter in enumerate(word[1:], start=1):
        if letter in "mc":
            return ("module" if letter == "m" else "command"), 1
        if letter in "WX":
            return "", 2 if position == len(word) - 1 else 1
        flags.add(letter)
    return "", 1


def uv_command(words: list[str]) -> UvCommand:
    """Split ``uv``'s arguments (the words after ``uv``).

    Options are read up to ``--`` and, for ``uv run``, up to the
    program it launches: the program's own arguments are not uv's.
    Other subcommands take options after their positional arguments
    too (``uv pip install six --system``).
    """
    command = UvCommand([], set(), {})
    position = 0
    while position < len(words):
        word = words[position]
        running = command.subcommand[:1] == ["run"]
        if word == "--" or (running and not word.startswith("-")):
            break
        if not word.startswith("-"):
            if len(command.subcommand) < 2:
                command.subcommand.append(word)
            position += 1
            continue
        name = word.split("=", 1)[0]
        name = "--python" if name == "-p" else name
        command.options.add(name)
        if running and name in ("-m", "--module"):
            break
        if "=" in word:
            command.values.setdefault(name, (position, True))
        elif word in UV_VALUE_OPTIONS:
            command.values.setdefault(name, (position + 1, False))
            position += 1
        position += 1
    return command


def uv_problem(
    command: UvCommand, env: UvEnv, places: dict[str, str]
) -> list[tuple[str, str]]:
    """The rules a uv command breaks by taking its Python from the cwd.

    ``places`` says where the value of ``--python`` points: "path" for
    an absolute path outside the workspace. The caller has already
    applied ``--directory``, which moves uv to another directory, and
    calls this only when uv's directory is not trusted.

    Measured with a marker the planted interpreter writes as it starts
    (uv 0.11 and 0.13; uv skips an interpreter that fails, so a run
    that "works" proves nothing):

    - PPA006, a workspace .python-version: 'uv run', 'uv venv' and
      'uv python find' use it unless given --no-config (or
      UV_NO_CONFIG) or, for run and venv, any --python or UV_PYTHON.
    - PPA007, a workspace .venv, in the working directory or any
      parent: 'uv run' uses it unless given --python or UV_PYTHON as a
      path, or VIRTUAL_ENV naming an environment together with
      --active or outside project mode; 'uv python find' unless
      --system or UV_SYSTEM_PYTHON; every 'uv pip' subcommand unless
      --system, UV_SYSTEM_PYTHON, a --python path or VIRTUAL_ENV. An
      explicit --python overrides UV_PYTHON. --no-config, --isolated,
      --no-project, --project and a version request do not help. 'uv
      venv', 'uv sync --project', uvx and 'uv tool' do not use it. A
      relative path, or one in the workspace, protects nothing: it
      names the workspace's own files.
    """
    options = command.options
    no_config = "--no-config" in options or env.no_config
    # An explicit --python overrides UV_PYTHON, protecting or not.
    if "--python" in options:
        python_path = places.get("--python") == "path"
    else:
        python_path = env.python_path
    any_python = "--python" in options or env.any_python
    system = "--system" in options or env.system
    no_project = "--no-project" in options or env.no_project
    # In project mode 'uv run' uses the project's environment, not an
    # active one, unless --active asks for it (measured on uv 0.11).
    active = env.venv and (no_project or "--active" in options)
    head = command.subcommand[:1]
    found: list[tuple[str, str]] = []
    if head in (["run"], ["venv"]) and not (no_config or any_python):
        found.append(("PPA006", UV_FIXES["PPA006", head[0]]))
    if head == ["run"]:
        # In a project, 'uv run' uses the project's environment (a .venv
        # there) whatever --python says, unless UV_PROJECT_ENVIRONMENT
        # points outside the workspace or --no-project leaves project
        # mode. '--script' alone does not count: uv 0.11 still uses the
        # project's .venv for a script without inline metadata.
        if not ((python_path and (no_project or env.project_env)) or active):
            found.append(("PPA007", UV_FIXES["PPA007", "run"]))
    elif head == ["export"]:
        if not env.project_env:
            found.append(("PPA007", UV_FIXES["PPA007", "export"]))
    elif head == ["python"] and command.subcommand[1:2] == ["find"]:
        if not no_config:
            found.append(("PPA006", UV_FIXES["PPA006", "python"]))
        if not system:
            found.append(("PPA007", UV_FIXES["PPA007", "python"]))
    elif head == ["pip"]:
        # An explicit --python selects the interpreter over VIRTUAL_ENV too.
        venv = env.venv and "--python" not in options
        if not (system or python_path or venv):
            found.append(("PPA007", UV_FIXES["PPA007", "pip"]))
    return found
