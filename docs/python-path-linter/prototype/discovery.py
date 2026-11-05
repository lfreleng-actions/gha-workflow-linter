# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""File discovery for the prototype: copied from the engine on PR #434."""

from __future__ import annotations

import os
import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterator

ACTION_NAMES = ("action.yml", "action.yaml")
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
    """Return the kind of file, or None when it is not scanned."""
    name = os.path.basename(relpath)
    if name in ACTION_NAMES:
        return "action"
    if "/.github/workflows/" in f"/{relpath}" and name.endswith(
        (".yml", ".yaml")
    ):
        return "workflow"
    if name.endswith(SCRIPT_SUFFIXES):
        return "script"
    return None


def has_shell_shebang(path: str) -> bool:
    """True for an extensionless file that starts with a shell shebang."""
    try:
        with open(path, "rb") as handle:
            first = handle.readline(128)
    except OSError:
        return False
    return bool(re.match(rb"#!\s*\S*(?:/|\s)(?:ba|z|da|k)?sh\b", first))


def repo_root_of(path: str, root: str) -> str:
    """The git work tree holding ``path``, else the scan root.

    Under a directory root, the search stops at the root, which may be
    a folder of repositories. A file named on its own may sit anywhere
    in its repository, so every ancestor is searched.
    """
    root = os.path.abspath(root)
    single = not os.path.isdir(root)
    top = os.path.dirname(root) if single else root
    directory = os.path.dirname(os.path.abspath(path))
    while True:
        if os.path.exists(os.path.join(directory, ".git")):
            return directory
        at_top = directory == top and not single
        if at_top or os.path.dirname(directory) == directory:
            return top
        directory = os.path.dirname(directory)


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
            is_workflow = any(line.startswith("jobs:") for line in handle)
    except OSError:
        return "action"
    return "workflow" if is_workflow else "action"


def candidate_files(
    root: str, problems: list[str] | None = None
) -> Iterator[tuple[str, str]]:
    """Yield (path, kind) for every file the scan reads under root.

    A root that does not exist, and a directory that cannot be listed,
    are added to ``problems`` when it is given.
    """
    missed = problems if problems is not None else []
    if os.path.isfile(root):
        yield root, explicit_kind(root)
        return
    if not os.path.isdir(root):
        missed.append(f"{root}: no such file or directory")
        return

    def unreadable(error: OSError) -> None:
        missed.append(f"{error.filename}: {error.strerror}")

    for directory, subdirs, files in os.walk(root, onerror=unreadable):
        subdirs[:] = sorted(d for d in subdirs if d not in PRUNE_DIRS)
        for name in sorted(files):
            path = os.path.join(directory, name)
            if os.path.islink(path):
                continue
            relpath = os.path.relpath(path, root)
            kind = classify_kind(relpath)
            if kind is None and "." not in name and has_shell_shebang(path):
                kind = "script"
            if kind:
                yield path, kind
