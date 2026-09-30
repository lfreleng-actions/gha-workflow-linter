# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Which discovered files git ignores.

Discovery walks the tree, so without this it finds whatever sits in a
gitignored directory: a JavaScript repository's ``node_modules/`` holds
every dependency's workflows and ``action.yml``, and linting them
rewrites third-party files with automatic fixes (issue #378).

The filter removes only what git reports as *ignored*. The alternative,
keeping only what git lists, fails the unsafe way: on a case-insensitive
filesystem a rename without ``git mv`` leaves the index and the disk
spelled differently, and the renamed workflow would silently drop out.
Removing the ignored set instead means any mismatch keeps the file, as
the walk always did.

Git is asked about the directory's *own* repository. A commit hook
inherits variables such as ``GIT_DIR`` and ``GIT_INDEX_FILE``; left in
place, they make git answer for another repository, whose private
excludes then hide real workflows here. The variables stripped are the
ones git itself names in ``rev-parse --local-env-vars``, the set it
clears when moving between repositories.

Anything that stops git answering leaves the walk exactly as it was.
"""

from __future__ import annotations

import functools
import logging
import os
from pathlib import Path, PurePosixPath
import subprocess
from typing import TYPE_CHECKING

from .git_refs import git_environment

if TYPE_CHECKING:
    from collections.abc import Iterable

logger = logging.getLogger(__name__)

#: What ``git rev-parse --local-env-vars`` lists as of git 2.55, for a
#: git that cannot be asked. Merged with its answer rather than replaced
#: by it, so an older git that lists fewer still loses these.
_FALLBACK_LOCAL_VARIABLES = (
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_CONFIG",
    "GIT_CONFIG_PARAMETERS",
    "GIT_CONFIG_COUNT",
    "GIT_OBJECT_DIRECTORY",
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_IMPLICIT_WORK_TREE",
    "GIT_GRAFT_FILE",
    "GIT_INDEX_FILE",
    "GIT_NO_REPLACE_OBJECTS",
    "GIT_REPLACE_REF_BASE",
    "GIT_PREFIX",
    "GIT_SHALLOW_FILE",
    "GIT_COMMON_DIR",
)


@functools.cache
def _local_variables() -> tuple[str, ...]:
    """Name the variables through which a parent steers a child git.

    Returns:
        Git's own list merged with the fallback, in that order.
    """
    try:
        listed = subprocess.run(
            ["git", "rev-parse", "--local-env-vars"],
            capture_output=True,
            text=True,
            check=True,
            env=git_environment(),
            timeout=30,
        ).stdout.split()
    except (OSError, subprocess.SubprocessError):
        listed = []
    return tuple(dict.fromkeys([*listed, *_FALLBACK_LOCAL_VARIABLES]))


def _environment() -> dict[str, str]:
    """The environment for asking git about one directory's repository.

    Returns:
        ``git_environment()`` without git's local variables.
    """
    env = git_environment()
    for name in _local_variables():
        env.pop(name, None)
    return env


def _git(directory: Path, *args: str, timeout: int) -> bytes | None:
    """Run a read-only git command in ``directory``.

    Args:
        directory: Where git runs; its repository answers.
        args: Arguments after ``git -C directory``.
        timeout: Seconds to allow.

    Returns:
        Standard output, or None when git exited non-zero or could not
        run at all.
    """
    try:
        result = subprocess.run(
            ["git", "-C", str(directory), *args],
            capture_output=True,
            check=False,
            env=_environment(),
            timeout=timeout,
        )
    except (OSError, subprocess.SubprocessError) as error:
        logger.debug(f"git unavailable in {directory}: {error}")
        return None
    if result.returncode != 0:
        return None
    return result.stdout


class IgnoredPaths:
    """Git's ignored set beneath one directory, asked for once.

    The answer is collapsed to directories where git can (``--directory``),
    so a ``node_modules/`` of twenty thousand files is one entry, and a
    candidate is ignored when it is, or lies below, a listed path.
    """

    def __init__(self, root: Path, timeout: int) -> None:
        """Ask git which paths beneath ``root`` it ignores.

        Args:
            root: Directory whose repository answers.
            timeout: Seconds to allow each git command.
        """
        self.root = root
        self._files: frozenset[str] = frozenset()
        self._directories: tuple[str, ...] = ()
        self.active = False

        # An ignored directory named as the root is the caller's choice,
        # and git cannot list beneath one ("directory entry not superset
        # of prefix"). Outside a work tree check-ignore exits 128.
        if _git(root, "check-ignore", "-q", ".", timeout=timeout) is not None:
            logger.debug(f"{root} is itself ignored; linting it as named")
            return
        listed = _git(
            root,
            "ls-files",
            "-z",
            "--others",
            "--ignored",
            "--exclude-standard",
            "--directory",
            timeout=timeout,
        )
        if listed is None:
            logger.debug(f"No ignore answer for {root}; walking unfiltered")
            return

        files: set[str] = set()
        directories: list[str] = []
        for raw in listed.split(b"\0"):
            if not raw:
                continue
            entry = os.fsdecode(raw)
            if entry.endswith("/"):
                directories.append(entry)
            else:
                files.add(entry)
        self._files = frozenset(files)
        self._directories = tuple(directories)
        self.active = True

    def ignores(self, path: Path) -> bool:
        """Report whether git ignores ``path``.

        Args:
            path: A path at or below the root.

        Returns:
            True when git reported the path, or a directory above it.
            False for anything outside the root, or with no answer.
        """
        if not self.active:
            return False
        try:
            relative = PurePosixPath(path.relative_to(self.root).as_posix())
        except ValueError:
            return False
        text = relative.as_posix()
        if text in self._files:
            return True
        return any(text.startswith(prefix) for prefix in self._directories)

    def keep(self, paths: Iterable[Path]) -> list[Path]:
        """Drop the paths git ignores, preserving order.

        Args:
            paths: Candidates at or below the root.

        Returns:
            The candidates git does not ignore.
        """
        kept: list[Path] = []
        for path in paths:
            if self.ignores(path):
                logger.debug(f"Skipping gitignored file: {path}")
            else:
                kept.append(path)
        return kept
