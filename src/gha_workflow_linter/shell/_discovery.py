# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Which files a shell scan reads, and what kind each one is.

Composite action metadata, workflows under ``.github/workflows``, and
shell scripts: ``*.sh``, ``*.bash`` and extensionless files whose
shebang names a shell.
"""

from __future__ import annotations

import os
import re
from typing import TYPE_CHECKING

import yaml

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator

ACTION_NAMES = ("action.yml", "action.yaml")
# Shells whose scripts the scan reads, as a shebang names them.
SHELLS = frozenset({"sh", "bash", "zsh", "dash", "ksh"})
# env's split-string option, cut to any prefix getopt accepts.
SPLIT_STRING = re.compile(
    r"-[i0v]*S|--s(?:p(?:l(?:i(?:t(?:-(?:s(?:t(?:r(?:i(?:ng?)?)?)?)?)?)?)?)?)?)?(?:=|$)"
)
# How much of a file the shebang probe reads: Linux reads 255 bytes of
# a shebang line, macOS 512.
SHEBANG_BYTES = 512
SCRIPT_SUFFIXES = (".sh", ".bash")
PRUNE_DIRS = {
    ".git",
    ".hg",
    ".venv",
    "venv",
    ".tox",
    ".nox",
    "node_modules",
    "__pycache__",
    ".mypy_cache",
    ".ruff_cache",
    ".pytest_cache",
    "site-packages",
    ".wt",
}


def classify_kind(relpath: str) -> str | None:
    """Return the kind of file, or None when it is not scanned.

    ``relpath`` may use either separator, as ``os.path.relpath`` gives
    it on Windows.
    """
    relpath = relpath.replace("\\", "/")
    folder, _sep, name = f"/{relpath}".rpartition("/")
    # GitHub runs every YAML file directly in .github/workflows as a
    # workflow, action.yml included; one in a folder below is an action.
    in_workflows = folder.endswith("/.github/workflows")
    if name in ACTION_NAMES and not in_workflows:
        return "action"
    if "/.github/workflows/" in f"/{relpath}" and name.endswith(
        (".yml", ".yaml")
    ):
        return "workflow"
    if name.endswith(SCRIPT_SUFFIXES):
        return "script"
    return None


def has_shell_shebang(path: str, problems: list[str]) -> bool:
    """True for an extensionless file that starts with a shell shebang.

    The shell may follow env's options and NAME=value words, as in
    ``#!/usr/bin/env -S bash -eu``, and may be quoted. A file the scan
    cannot read is added to ``problems``: whether it is shell is then
    unknown, so the scan is incomplete.
    """
    try:
        with open(path, "rb") as handle:
            first = handle.readline(SHEBANG_BYTES)
    except OSError as error:
        problems.append(f"{path}: {error.strerror}")
        return False
    return shebang_names_shell(first.decode("utf-8", "replace"))


def shebang_names_shell(line: str) -> bool:
    """Whether a shebang line runs a shell, directly or through env.

    Reads the line word by word, each once, so a crafted line costs
    no more than its length: the interpreter, then (for env) its
    options with their operands, ``NAME=value`` words, and the shell,
    by name or path, quoted or not. The kernel splits the line on
    spaces only; env's ``-S`` then splits its operand with quotes and
    backslashes, which ``env_program`` reads.
    """
    if not line.startswith("#!"):
        return False
    words = line[2:].split()
    if not words:
        return False
    if os.path.basename(words[0]) != "env":
        return os.path.basename(words[0]) in SHELLS
    program = env_program(words[1:])
    return program is not None and os.path.basename(program) in SHELLS


# env's long options that take an operand, for unique-prefix matching.
ENV_OPERAND_LONG = ("--unset", "--chdir")


def env_split(text: str) -> list[str] | None:
    """Split an ``env -S`` operand as GNU env does; None when unbalanced.

    Quotes group (inside single quotes only ``\\'`` and ``\\\\`` are
    escapes), a backslash escapes the next character, ``\\_`` is a
    word separator outside quotes and a space within double quotes,
    ``\\c`` outside quotes ends the string, and ``#`` starts a comment.
    """
    words: list[str] = []
    current: list[str] = []
    quote = ""
    index = 0
    while index < len(text):
        char = text[index]
        escaped = quote == "'" and text[index + 1 : index + 2] in ("'", "\\")
        if char == "\\" and (quote != "'" or escaped):
            index += 1
            if index >= len(text):
                return None
            if text[index] == "_" and not quote:
                # A word separator outside quotes, a space within.
                if current:
                    words.append("".join(current))
                    current = []
            elif text[index] == "c" and not quote:
                break  # \c ends the string, as in echo -e
            else:
                current.append(" " if text[index] == "_" else text[index])
        elif quote:
            if char == quote:
                quote = ""
            else:
                current.append(char)
        elif char in "\"'":
            quote = char
        elif char == "#" and not current:
            break
        elif char.isspace():
            if current:
                words.append("".join(current))
                current = []
        else:
            current.append(char)
        index += 1
    if quote:
        return None
    if current:
        words.append("".join(current))
    return words


def env_program(words: list[str]) -> str | None:
    """The program env runs, past its options and assignments; None if none.

    An ``-S``/``--split-string`` word splits its operand (attached, or
    the next word, with the rest of the line) into further words env
    reads; short options cluster (``-iC DIR``), and a long option may
    be cut to a unique prefix (``--chd DIR``).
    """
    index = 0
    while index < len(words):
        word = words[index]
        split = SPLIT_STRING.match(word)
        if split:
            attached = split.end() < len(word)
            rest = [word[split.end() :]] if attached else []
            rest += words[index + 1 :]
            parts = env_split(" ".join(rest))
            if parts is None:
                return None
            words = [*words[:index], *parts]
            if not parts:
                return None
            continue
        if word.startswith("--"):
            name = word.split("=", 1)[0]
            matches = [o for o in ENV_OPERAND_LONG if o.startswith(name)]
            index += 2 if len(matches) == 1 and "=" not in word else 1
        elif word == "-":
            index += 1  # ignore-environment, as -i
        elif word.startswith("-"):
            # A cluster: the first letter taking an operand uses the
            # rest of the word, or else the next word.
            letters = word[1:]
            takes = next((n for n, c in enumerate(letters) if c in "uC"), -1)
            index += 2 if takes == len(letters) - 1 else 1
        elif "=" in word:
            index += 1
        else:
            return word
    return None


def explicit_kind(path: str) -> str:
    """Kind of a file named on the command line, whatever its name.

    A file the user asked for is always scanned: a YAML file with a
    top-level ``jobs:`` key is a workflow, any other YAML file an
    action, and anything else a script.
    """
    kind = classify_kind(path)
    if kind:
        return kind
    if not path.endswith((".yml", ".yaml")):
        return "script"
    try:
        with open(path, encoding="utf-8", errors="replace") as handle:
            document = yaml.compose(handle, Loader=yaml.SafeLoader)
    except (OSError, yaml.YAMLError, RecursionError):
        # Unreadable, not YAML, or nested too deeply: the guarded scan
        # that follows reports the file as not scanned.
        return "action"
    # Composed, not constructed: no value is built, so a bad scalar or
    # an alias that expands widely costs nothing here.
    is_workflow = isinstance(document, yaml.MappingNode) and any(
        isinstance(key, yaml.ScalarNode) and key.value == "jobs"
        for key, _value in document.value
    )
    return "workflow" if is_workflow else "action"


def is_repository_root(path: str) -> bool:
    """Whether a directory holds a ``.git`` entry, file or directory.

    A clone has a ``.git`` directory; a worktree or submodule has a
    ``.git`` file pointing at its git directory.
    """
    return os.path.exists(os.path.join(path, ".git"))


def candidate_files(
    root: str,
    problems: list[str] | None = None,
    skip: Callable[[str], bool] | None = None,
    *,
    stop_at_repositories: bool = False,
) -> Iterator[tuple[str, str]]:
    """Yield (path, kind) for every file the scan reads under root.

    A root that does not exist, and a directory that cannot be listed,
    are added to ``problems`` when it is given. ``skip``, when given,
    is asked about each directory below the root, spelled with a
    trailing separator, and each file (the root too, when it is one)
    before its shebang is probed: a directory it skips is not entered,
    so nothing beneath it is read.

    With ``stop_at_repositories``, a directory below the root that is
    the root of a git repository (a clone, worktree or submodule) is
    not entered either, as ``WorkflowScanner`` walks: what lies beneath
    belongs to another repository, or another checkout of this one.
    The root itself is never a boundary.
    """
    missed = problems if problems is not None else []
    if os.path.isfile(root):
        if not (skip and skip(root)):
            yield root, explicit_kind(root)
        return
    if not os.path.isdir(root):
        missed.append(f"{root}: no such file or directory")
        return

    def unreadable(error: OSError) -> None:
        missed.append(f"{error.filename}: {error.strerror}")

    for directory, subdirs, files in os.walk(root, onerror=unreadable):
        subdirs[:] = sorted(
            d
            for d in subdirs
            if d not in PRUNE_DIRS
            and not (skip and skip(os.path.join(directory, d, "")))
            and not (
                stop_at_repositories
                and is_repository_root(os.path.join(directory, d))
            )
        )
        for name in sorted(files):
            path = os.path.join(directory, name)
            if skip and skip(path):
                continue
            # A symlink, a FIFO, a socket or a device is not scanned: a
            # read of a FIFO would wait for a writer.
            if os.path.islink(path) or not os.path.isfile(path):
                continue
            # The whole path: a root of .github or .github/workflows
            # still holds workflows.
            kind = classify_kind(os.path.abspath(path))
            probe = kind is None and "." not in name
            if probe and has_shell_shebang(path, missed):
                kind = "script"
            if kind:
                yield path, kind
