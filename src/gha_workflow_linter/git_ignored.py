# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Which paths git ignores, for discovery to leave out.

Discovery walks the tree, so without this it finds whatever sits in a
gitignored directory: a JavaScript repository's ``node_modules/`` holds
every dependency's workflows and ``action.yml``, and linting them
rewrites third-party files with automatic fixes (issue #378).

Paths are dropped when git reports them *ignored*. The alternative,
keeping only what git lists, fails the unsafe way: on a case-insensitive
filesystem a rename without ``git mv`` leaves the index and the disk
spelled differently, and the renamed workflow would silently drop out.
Removing the ignored set instead means any mismatch keeps the file, as
the walk always did.

Each repository is asked once, from its top level. A path from a glob is
judged one component at a time, shallowest first, each by the repository
holding it, as named, with only the part above resolved. So an ignored
link such as ``.github/workflows`` is judged as itself rather than
followed out of the repository, two spellings of one directory compare
equal, and a glob meets an ignored component wherever it leads: into
``node_modules/`` and a repository installed there, out of the scan root
through ``..``, or into another repository through a link.

Two exemptions, each narrow. A repository strictly enclosing the scan
root's own is never consulted, or even listed: a home directory kept as
a repository that ignores ``*`` must not hide the scan. And when the
repository owning the scan root ignores the root, the caller named it
anyway, so that repository's rules do not apply around it; a repository
nested inside the root still applies its own.

Git is asked about each repository with the variables it names in
``rev-parse --local-env-vars`` removed. A commit hook inherits several;
left in place, they make git answer for another repository, whose
private excludes then hide real workflows here.

Anything that stops git answering leaves the path in, as it always was.
"""

from __future__ import annotations

import functools
import logging
import os
from pathlib import Path, PurePath
import subprocess
from typing import TYPE_CHECKING

from .git_refs import git_environment

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator

logger = logging.getLogger(__name__)

#: How many links one path may pass through before it counts as a loop.
#: Linux's own limit (MAXSYMLINKS), so no chain the system would follow
#: is cut short.
_MAX_LINKS = 40

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
    """The environment for asking git about one repository.

    Returns:
        ``git_environment()`` without git's local variables.
    """
    env = git_environment()
    for name in _local_variables():
        env.pop(name, None)
    return env


class _Repository:
    """One work tree's ignored set, listed once from its top level.

    ``--directory`` collapses a directory holding nothing tracked into a
    single ``dir/`` entry, so a ``node_modules/`` of twenty thousand files
    is one entry. A directory that does hold a tracked file is never
    collapsed; its ignored files are listed one by one instead. So a
    collapsed entry is exactly a directory safe to leave unwalked.
    """

    def __init__(
        self, top: Path, listing: bytes, *, fold_case: bool = False
    ) -> None:
        """Parse git's ignored listing for the work tree at ``top``.

        Args:
            top: The work tree's top level, resolved.
            listing: ``ls-files -z --others --ignored --directory`` output.
            fold_case: Match names whatever their case, as git does where
                ``core.ignorecase`` is set: on a case-insensitive
                filesystem ``NODE_MODULES`` is ``node_modules``.
        """
        self.top = top
        self.fold_case = fold_case
        files: set[str] = set()
        directories: set[str] = set()
        for raw in listing.split(b"\0"):
            if raw:
                entry = self._spelled(os.fsdecode(raw))
                if entry.endswith("/"):
                    directories.add(entry.rstrip("/"))
                else:
                    files.add(entry)
        self._files = frozenset(files)
        self._directories = frozenset(directories)

    def _spelled(self, name: str) -> str:
        """Spell a name as the lookup compares it.

        ``str.lower`` rather than ``casefold``: no filesystem treats
        ``ß`` and ``ss`` as one name.

        Args:
            name: A path relative to the top level.

        Returns:
            The name, lowered when case is folded.
        """
        return name.lower() if self.fold_case else name

    def ignores(self, relative: str) -> bool:
        """Report whether a path relative to the top level is ignored.

        The path and each ancestor are looked up in sets, so the cost
        follows the path's depth rather than how many entries are
        ignored. Ancestors are checked against file entries as well as
        directories: git records a symbolic link as a file even when it
        stands for a directory, so an ignored ``.github/workflows`` link
        is a file entry that everything beneath it must inherit.

        Args:
            relative: POSIX path relative to the top level; ``.`` for it.

        Returns:
            True when git listed the path or an entry above it.
        """
        relative = self._spelled(relative)
        while relative not in ("", "."):
            if relative in self._files or relative in self._directories:
                return True
            relative = relative.rpartition("/")[0]
        return False


class IgnoreIndex:
    """Git's ignore answers, asked for once per repository."""

    def __init__(self, timeout: int) -> None:
        """Start an empty index.

        Args:
            timeout: Seconds to allow each git command.
        """
        self._timeout = timeout
        self._tops: dict[Path, Path | None] = {}
        self._repositories: dict[Path, _Repository | None] = {}

    def top(self, directory: Path) -> Path | None:
        """Find the work tree holding a resolved directory.

        The nearest directory at or above it with a ``.git`` entry, which
        is a clone's directory or a worktree's or submodule's pointer
        file: the same test discovery uses for repository boundaries.
        Ancestors are climbed in a loop rather than by recursion, which
        failed for a directory more than about a thousand levels deep,
        and every directory passed on the way is cached.

        Args:
            directory: A resolved directory.

        Returns:
            The top level, or None outside any work tree.
        """
        passed: list[Path] = []
        current = directory
        while current not in self._tops:
            passed.append(current)
            try:
                here = (current / ".git").exists()
            except OSError:
                here = False
            if here:
                self._tops[current] = current
            elif current.parent == current:
                self._tops[current] = None
            else:
                current = current.parent
        found = self._tops[current]
        for path in passed:
            self._tops[path] = found
        return found

    def repository(self, top: Path) -> _Repository | None:
        """Ask one work tree, once, which paths it ignores.

        Args:
            top: The work tree's top level, resolved.

        Returns:
            Its ignored set, or None when git gave no answer.
        """
        if top not in self._repositories:
            self._repositories[top] = self._list(top)
        return self._repositories[top]

    def matches_rule(self, top: Path, relative: str) -> bool | None:
        """Report whether a path matches an ignore rule, index aside.

        The ignored listing cannot answer this for a directory holding a
        tracked file: git lists such a directory's ignored contents one by
        one rather than the directory itself. ``--no-index`` judges the
        rules alone, so a directory under ``vendored/`` is ignored whether
        or not something inside it was force-added.

        Args:
            top: The work tree's top level, resolved.
            relative: POSIX path relative to the top level.

        Returns:
            Whether a rule matches, or None when git could not answer.
        """
        command = ["git", "-C", str(top), "check-ignore", "--no-index"]
        try:
            result = subprocess.run(
                [*command, "-q", "--", relative],
                capture_output=True,
                check=False,
                env=_environment(),
                timeout=self._timeout,
            )
        except (OSError, subprocess.SubprocessError) as error:
            logger.debug(f"git unavailable in {top}: {error}")
            return None
        if result.returncode in (0, 1):
            return result.returncode == 0
        return None

    def _list(self, top: Path) -> _Repository | None:
        """Run git's ignored listing at a top level.

        Args:
            top: The work tree's top level, resolved.

        Returns:
            The parsed answer, or None when git could not give one.
        """
        command = [
            "git",
            "-C",
            str(top),
            "ls-files",
            "-z",
            "--others",
            "--ignored",
            "--exclude-standard",
            "--directory",
        ]
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                check=False,
                env=_environment(),
                timeout=self._timeout,
            )
        except (OSError, subprocess.SubprocessError) as error:
            logger.debug(f"git unavailable in {top}: {error}")
            return None
        if result.returncode != 0:
            logger.debug(f"No ignore answer for {top}; leaving paths in")
            return None
        return _Repository(
            top, result.stdout, fold_case=self._ignores_case(top)
        )

    def _ignores_case(self, top: Path) -> bool:
        """Read whether git matches names whatever their case.

        ``git init`` and ``git clone`` set ``core.ignorecase`` by probing
        the filesystem, and git's own ignore matching follows it.

        Args:
            top: The work tree's top level, resolved.

        Returns:
            True when ``core.ignorecase`` is set; False when it is not,
            or git cannot say.
        """
        try:
            result = subprocess.run(
                ["git", "-C", str(top), "config", "--type=bool"]
                + ["--get", "core.ignorecase"],
                capture_output=True,
                text=True,
                check=False,
                env=_environment(),
                timeout=self._timeout,
            )
        except (OSError, subprocess.SubprocessError) as error:
            logger.debug(f"git unavailable in {top}: {error}")
            return False
        return result.stdout.strip() == "true"


class IgnoreScope:
    """What discovery beneath one scan root leaves out.

    An ignored directory named as the root is the caller's choice and is
    linted whole; so is a root git cannot answer for, as it always was.
    """

    def __init__(self, index: IgnoreIndex, root: Path) -> None:
        """Place ``root`` in its repository.

        Args:
            index: The shared index.
            root: Scan root, in the caller's spelling.
        """
        self.root = root
        self._index = index
        self._root = root.resolve()
        self._top = index.top(self._root)
        self._repository = (
            index.repository(self._top) if self._top is not None else None
        )
        self._prefix = (
            self._root.relative_to(self._top).as_posix()
            if self._top is not None
            else "."
        )
        self._steps: dict[Path, bool] = {}
        # Paths are compared as the scan repository's git matches names,
        # so on a case-insensitive filesystem any spelling of the root,
        # or of a repository above it, is recognised as the same place.
        self._fold_case = (
            self._repository is not None and self._repository.fold_case
        )
        self._named_ignored = (
            self._repository is not None and self._root_ignored()
        )
        self.active = self._repository is not None and not self._named_ignored
        if self._named_ignored:
            logger.debug(f"{root} is itself ignored; linting it as named")

    def _root_ignored(self) -> bool:
        """Report whether the scan root itself matches an ignore rule.

        Judged by the rules alone, so the answer does not depend on
        whether something beneath the root happens to be force-added.
        Falls back to the listing when git cannot answer.

        Returns:
            True when the root is ignored.
        """
        if self._top is None or self._repository is None or self._prefix == ".":
            return False
        rule = self._index.matches_rule(self._top, self._prefix)
        if rule is None:
            return self._repository.ignores(self._prefix)
        return rule

    def ignores_relative(self, relative: str) -> bool:
        """Report whether a path beneath the root, found by a walk, is ignored.

        Only valid for a walk that does not follow links or cross into a
        nested repository, since the answer comes from the root's own.

        Args:
            relative: POSIX path relative to the root.

        Returns:
            True when the root's repository ignores it.
        """
        if not self.active or self._repository is None:
            return False
        if self._prefix == ".":
            return self._repository.ignores(relative)
        return self._repository.ignores(f"{self._prefix}/{relative}")

    def ignores(self, path: Path) -> bool:
        """Report whether a path from anywhere, such as a glob, is ignored.

        Each component is judged as named, shallowest first, by the
        repository holding it, with only the part above it resolved:
        resolving the whole path first would follow an ignored link such
        as ``.github/workflows`` out of the repository and judge its
        target instead. A glob that leaves the scan root, through ``..``
        or a link, is judged by each repository it enters.

        A link is followed one hop at a time, each immediate target
        judged as named before the next link is read. Resolving a chain
        in one go would collapse it past an ignored hop: with
        ``node_modules/pkg`` a link elsewhere, a tracked link through it
        would be judged only at the far end, where nothing ignores it.
        A chain that loops, runs too long or dangles is treated as
        ignored, since it names nothing that could be read, and it never
        reaches ``Path.resolve``, which raises on a loop before 3.13.
        Every link met while expanding one path, however nested, draws
        on one budget, as the kernel counts them; a budget per component
        let links within links multiply the work without limit.

        Args:
            path: Any spelling of a path.

        Returns:
            True when a component is ignored by the repository holding
            it. See ``_judge`` for the two exemptions.
        """
        return self._walk(path.absolute(), _MAX_LINKS) is None

    def _walk(self, absolute: Path, budget: int) -> tuple[Path, int] | None:
        """Judge an absolute path component by component, following links.

        Args:
            absolute: The path to judge.
            budget: Links that may still be followed before giving up.

        Returns:
            The path with every link followed and the budget left, or
            None when a component is ignored or the links loop, run out
            or dangle.
        """
        current = Path(absolute.anchor)
        for name in absolute.parts[1:]:
            if name == ".":
                continue
            if name == "..":
                current = current.parent
                continue
            candidate = current / name
            if self._judged(candidate):
                return None
            # os.path.islink answers False where a parent cannot be
            # searched; Path.is_symlink raises there before Python 3.14.
            # Judged as named, the path is kept for the reader to report
            # unreadable, as on 3.14.
            if not os.path.islink(candidate):
                current = candidate
                continue
            if budget <= 0:
                return None
            try:
                link = Path(os.readlink(candidate))
            except OSError:
                return None
            followed = self._walk(
                link if link.is_absolute() else current / link, budget - 1
            )
            if followed is None:
                return None
            current, budget = followed
        return current, budget

    def _judged(self, candidate: Path) -> bool:
        """Judge one component as named, once per scope.

        Args:
            candidate: A directory with every link followed, joined with
                a name as named.

        Returns:
            Whether the repository holding it ignores it.
        """
        cached = self._steps.get(candidate)
        if cached is None:
            cached = self._judge(candidate)
            self._steps[candidate] = cached
        return cached

    def _judge(self, candidate: Path) -> bool:
        """Judge one component by the repository holding it.

        Two exemptions, each narrow:

        - A repository strictly enclosing the scan root's own is never
          consulted, or even listed: a home directory kept as a
          repository that ignores ``*`` must not hide the scan.
        - When the repository owning the scan root ignores the root, the
          caller named it anyway, so that repository's rules do not
          apply on the way down to it or beneath it. A repository nested
          inside the root still applies its own.

        Args:
            candidate: A resolved directory joined with a name as named.

        Returns:
            True when the holding repository ignores the component.
        """
        top = self._index.top(candidate.parent)
        if top is None:
            return False
        own = self._top
        if own is not None and self._encloses(top, own):
            return False
        if (
            own is not None
            and self._named_ignored
            and self._within(top, own)
            and self._within(own, top)
            and (
                self._within(candidate, self._root)
                or self._within(self._root, candidate)
            )
        ):
            return False
        repository = self._index.repository(top)
        return repository is not None and repository.ignores(
            candidate.relative_to(top).as_posix()
        )

    def _within(self, path: Path, base: Path) -> bool:
        """Report whether a path is a base or lies beneath it.

        Args:
            path: The path to place.
            base: The directory it may lie in.

        Returns:
            Whether it does, comparing names as the scan repository does.
        """
        inner, outer = path.parts, base.parts
        if self._fold_case:
            inner = tuple(part.lower() for part in inner)
            outer = tuple(part.lower() for part in outer)
        return inner[: len(outer)] == outer

    def _encloses(self, outer: Path, inner: Path) -> bool:
        """Report whether one directory strictly encloses another.

        Args:
            outer: The possible ancestor.
            inner: The possible descendant.

        Returns:
            True when ``inner`` lies beneath ``outer`` and is not it.
        """
        return self._within(inner, outer) and not self._within(outer, inner)

    def keep(self, paths: Iterable[Path]) -> Iterator[Path]:
        """Pass on the paths git does not ignore, as they arrive.

        Args:
            paths: Candidates, in any spelling.

        Yields:
            Each candidate git does not ignore, in order.
        """
        for path in paths:
            if self.ignores(path):
                logger.debug(f"Skipping gitignored file: {path}")
            else:
                yield path

    def glob(self, base: Path, pattern: str) -> Iterator[Path]:
        """Expand a glob as ``Path.glob`` does, without entering ignored trees.

        Only the directories a ``**`` component stands for are walked
        here, and a directory judged ignored is not entered: everything
        beneath it would be judged ignored too, since judgement runs
        component by component. The parts before and after the ``**``
        are matched by ``Path.glob`` itself, so case and hidden-name
        matching stay as each Python version has them. Everything else
        goes to ``Path.glob`` unchanged: a pattern without a whole ``**``
        component, ending in one (3.13 added files to what that
        returns), absolute, or ending in a separator.

        Args:
            base: Directory the pattern is relative to.
            pattern: The glob.

        Yields:
            Each match once, unfiltered; pass them through ``keep``.
        """
        seen: set[Path] = set()
        for path in self._glob(base, pattern):
            if path not in seen:
                seen.add(path)
                yield path

    def _glob(self, base: Path, pattern: str) -> Iterator[Path]:
        """Expand a glob, splitting it at its first ``**`` component.

        Args:
            base: Directory the pattern is relative to.
            pattern: The glob.

        Yields:
            Each match, possibly more than once.
        """
        parts = PurePath(pattern).parts
        if (
            "**" not in parts
            or parts[-1] == "**"
            or PurePath(pattern).is_absolute()
            or pattern.endswith(("/", os.sep))
        ):
            yield from base.glob(pattern)
            return
        split = parts.index("**")
        tail = str(PurePath(*parts[split + 1 :]))
        starts = base.glob(str(PurePath(*parts[:split]))) if split else [base]
        for start in starts:
            # A start reached through a directory that cannot be searched,
            # such as locked/.., is passed over as a native ``**`` passes
            # over it; Python 3.12's glob raises from inside one.
            if not os.path.isdir(start):
                continue
            for directory in self._directories(start):
                yield from self._glob(directory, tail)

    def _directories(self, start: Path) -> Iterator[Path]:
        """Walk the directories a ``**`` stands for, leaving ignored ones out.

        As ``Path.glob`` expands ``**`` on every supported version: the
        start and each directory beneath it, hidden ones included, links
        to directories not entered, and a directory that cannot be listed
        still yielded, since a literal name inside it may be reachable.

        Args:
            start: Where the ``**`` begins.

        Yields:
            Each directory not ignored, depth first.
        """
        pending = [start]
        while pending:
            directory = pending.pop()
            if self.ignores(directory):
                continue
            yield directory
            try:
                with os.scandir(directory) as entries:
                    names = [
                        entry.name
                        for entry in entries
                        if _is_real_directory(entry)
                    ]
            except OSError:
                continue
            pending.extend(directory / name for name in reversed(names))


def _is_real_directory(entry: os.DirEntry[str]) -> bool:
    """Report whether a listed entry is a directory and not a link.

    Args:
        entry: A directory entry.

    Returns:
        True for a directory ``**`` descends into.
    """
    try:
        return entry.is_dir(follow_symlinks=False)
    except OSError:
        return False
