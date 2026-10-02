# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

"""Workflow scanner for finding and parsing GitHub Actions workflows."""

from __future__ import annotations

import errno
import logging
import os
from pathlib import Path, PurePath
import stat
from typing import TYPE_CHECKING, NamedTuple, cast

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable, Iterator

    from rich.progress import Progress, TaskID

    from .models import ActionCall, Config

import yaml

from .action_call_scanner import ActionCallPatterns
from .git_ignored import IgnoreIndex, IgnoreScope

#: Errors that mean a path names nothing, which ``Path.is_dir`` and
#: ``is_file`` answer False for quietly on every supported Python.
_ABSENT = frozenset({errno.ENOENT, errno.ENOTDIR, errno.EBADF, errno.ELOOP})


def _is_glob(pattern: str) -> bool:
    """Report whether a ``--files`` pattern is a glob rather than a path.

    Args:
        pattern: A pattern as the caller passed it.

    Returns:
        True when the pattern holds a wildcard.
    """
    return "*" in pattern or "?" in pattern


class _ComposeResult(NamedTuple):
    """
    Outcome of composing a single YAML document.

    Attributes:
        valid: True when the document parsed without a YAML error.
        node: Root of the composed node tree, or None when the document
            was invalid or empty.
    """

    valid: bool
    node: yaml.nodes.Node | None


class WorkflowScanner:
    """Scanner for GitHub Actions workflow files."""

    def __init__(self, config: Config) -> None:
        """
        Initialize the workflow scanner.

        Args:
            config: Configuration object
        """
        self.config = config
        self.logger = logging.getLogger(__name__)
        self._patterns = ActionCallPatterns()
        # Memoises "is this directory a repository root?" for the life of
        # the scanner; a deep tree asks about the same ancestors often.
        self._repository_roots: dict[Path, bool] = {}
        # Git's ignore answers, asked for once per repository however many
        # roots and globs reach it, so discovery and every caller reading
        # the same tree agree.
        self._ignore_index = IgnoreIndex(config.git.timeout_seconds)
        self._ignored: dict[Path, IgnoreScope] = {}

    def ignored_paths(self, root_path: Path) -> IgnoreScope:
        """What discovery beneath ``root_path`` leaves out as gitignored.

        Discovery leaves these out: a gitignored ``node_modules/`` holds
        third-party workflows that are not the repository's to lint or
        rewrite (issue #378). Callers that glob for files the scan will
        read, such as ``allow_list.extra_globs``, use the same answer.

        Args:
            root_path: Scan root.

        Returns:
            The scope, inactive when git gave no answer.
        """
        ignored = self._ignored.get(root_path)
        if ignored is None:
            ignored = IgnoreScope(self._ignore_index, root_path)
            self._ignored[root_path] = ignored
        return ignored

    def find_workflow_files(
        self,
        root_path: Path,
        progress: Progress | None = None,
        task_id: TaskID | None = None,
    ) -> Iterator[Path]:
        """
        Find all GitHub workflow files and action definition files in directory tree.

        Args:
            root_path: Root directory to scan
            progress: Optional progress bar
            task_id: Optional task ID for progress updates

        Yields:
            Path objects for workflow files and action definition files
        """
        self.logger.debug(f"Scanning for workflows and actions in: {root_path}")
        ignored = self.ignored_paths(root_path)

        # Look for .github/workflows directories
        workflow_dirs = self._find_workflow_directories(root_path)

        total_files = 0
        for workflow_dir in workflow_dirs:
            if not workflow_dir.exists() or not workflow_dir.is_dir():
                continue

            for ext in self.config.scan_extensions:
                pattern = f"*{ext}"
                for workflow_file in workflow_dir.glob(pattern):
                    # Judged component by component rather than as a
                    # walk path: a tracked .github/workflows link can
                    # lead into an ignored node_modules, whose files
                    # only the destination's rules cover.
                    if ignored.ignores(workflow_file):
                        self.logger.debug(
                            f"Skipping gitignored file: {workflow_file}"
                        )
                        continue
                    if self._should_exclude_file(workflow_file):
                        self.logger.debug(f"Excluding file: {workflow_file}")
                        continue

                    total_files += 1
                    if progress and task_id:
                        progress.update(
                            task_id,
                            description=f"Scanning {workflow_file.name}...",
                        )

                    self.logger.debug(f"Found workflow file: {workflow_file}")
                    yield workflow_file

        # Look for action.yaml/action.yml files (unless skip_actions is enabled)
        if not self.config.skip_actions:
            for action_file in self._find_action_files(root_path):
                if self._should_exclude_file(action_file):
                    self.logger.debug(f"Excluding file: {action_file}")
                    continue

                total_files += 1
                if progress and task_id:
                    progress.update(
                        task_id,
                        description=f"Scanning {action_file.name}...",
                    )

                self.logger.debug(f"Found action file: {action_file}")
                yield action_file

        self.logger.debug(f"Found {total_files} workflow and action files")

    def _walk(
        self, root_path: Path
    ) -> Iterator[tuple[Path, list[str], list[str]]]:
        """Walk the scan tree, pruning what discovery never reads.

        Pruned as it goes rather than filtered afterwards, so a gitignored
        ``node_modules/`` costs one directory entry rather than a descent
        through every package (issue #378). Left unwalked:

        - a directory git reports ignored with nothing tracked inside it;
          git lists such a directory as one ``dir/`` entry, and lists the
          ignored files of a directory holding tracked ones individually
        - a nested repository: git worktrees, submodules and vendored
          clones each place a ``.git`` entry (a directory for a clone, a
          gitdir pointer file for a worktree or submodule) at their root,
          so whatever lies beneath belongs to a different repository, or
          to a second checkout of this one. Without this, a repository
          keeping worktrees under ``.worktrees/`` reports every finding
          once per checked-out branch, against files its working tree
          does not contain, and remediation rewrites stale duplicates.
          The scan root itself is never a boundary.
        - ``.git``, which holds git's metadata rather than the tree

        Links to directories are reported but not followed, and an
        unreadable directory is logged and skipped, as with the recursive
        glob this replaces. A root that can be searched but not listed
        (mode ``0111``) yields only the names discovery looks for there,
        tried directly, as the finders this replaces probed the root's
        ``.github/workflows`` by name. Git cannot list beneath such a root
        either, so it reports nothing there ignored, and discovery is the
        walk those finders made, as whenever git cannot answer.

        Args:
            root_path: Scan root.

        Yields:
            Each directory walked, the names of its subdirectories kept
            (links included), and the names of its files.
        """
        scope = self.ignored_paths(root_path)
        listed = False

        def report(error: OSError) -> None:
            """Log a directory the walk could not read.

            Args:
                error: The failure.
            """
            self.logger.warning(
                f"Error scanning directory {root_path}: {error}"
            )

        for directory, subdirectories, files in os.walk(
            root_path, onerror=report
        ):
            listed = True
            here = Path(directory)
            relative = here.relative_to(root_path).as_posix()
            kept: list[str] = []
            for name in subdirectories:
                child_relative = (
                    name if relative == "." else f"{relative}/{name}"
                )
                if name == ".git" or scope.ignores_relative(child_relative):
                    continue
                if self._is_repository_root(here / name):
                    continue
                kept.append(name)
            subdirectories[:] = kept
            yield here, kept, files
        if not listed:
            # Judged as a listing would be, by exact name and the
            # boundary rule; git can see nothing here to ignore, and a
            # missing .github fails the workflows probe quietly.
            github = root_path / ".github"
            kept_github = (
                [] if self._is_repository_root(github) else [github.name]
            )
            names = [f"action{ext}" for ext in self.config.scan_extensions]
            yield root_path, kept_github, names

    def _find_workflow_directories(self, root_path: Path) -> set[Path]:
        """
        Find all .github/workflows directories in the tree.

        ``.github`` is matched by its exact name, as GitHub reads it. The
        recursive glob this replaces also matched ``.GitHub`` on a
        case-insensitive filesystem, but only under some Python versions.

        Args:
            root_path: Root directory to scan

        Returns:
            Set of workflow directory paths
        """
        workflow_dirs: set[Path] = set()
        scope = self.ignored_paths(root_path)
        for directory, subdirectories, _files in self._walk(root_path):
            if ".github" in subdirectories:
                workflows = directory / ".github" / "workflows"
                # An ignored workflows link, or a tracked one leading into
                # an ignored directory, must not be listed: the walk
                # prunes neither, since this path is built from the level
                # above and links are not followed.
                if self._is(workflows, stat.S_ISDIR) and not scope.ignores(
                    workflows
                ):
                    workflow_dirs.add(workflows)
        return workflow_dirs

    def _is(self, path: Path, kind: Callable[[int], bool]) -> bool:
        """Report whether a path is of a kind, logging one it cannot read.

        ``os.walk`` reports only directories it cannot list. A probe of a
        path built from a listing is separate, and ``Path.is_dir`` and
        ``is_file`` raise from it before Python 3.14 where a parent cannot
        be searched, and answer False silently from 3.14. Here the path
        is passed over and logged on every version, rather than ending
        the scan.

        Args:
            path: Path to test, following links.
            kind: A mode test, such as ``stat.S_ISDIR``.

        Returns:
            True when the path exists, can be read and is of the kind.
        """
        try:
            mode = path.stat().st_mode
        except OSError as error:
            if error.errno not in _ABSENT:
                self.logger.warning(f"Cannot read {path}: {error}")
            return False
        return kind(mode)

    def _is_repository_root(self, path: Path) -> bool:
        """Report whether a directory is the root of a Git repository.

        Results are cached for the lifetime of the scanner: a deep tree
        asks about the same ancestors repeatedly.

        Args:
            path: Directory to test.

        Returns:
            True when the directory contains a ``.git`` entry.
        """
        cached = self._repository_roots.get(path)
        if cached is None:
            try:
                cached = (path / ".git").exists()
            except OSError:
                cached = False
            self._repository_roots[path] = cached
        return cached

    def _find_action_files(self, root_path: Path) -> Iterator[Path]:
        """
        Find all action.yaml and action.yml files in directory tree.

        One walk serves every configured extension, and each file is
        yielded as it is found.

        Args:
            root_path: Root directory to scan

        Yields:
            Path objects for action definition files
        """
        self.logger.debug(
            f"Scanning for action definition files in: {root_path}"
        )
        names = {f"action{ext}" for ext in self.config.scan_extensions}
        scope = self.ignored_paths(root_path)
        for directory, _subdirectories, files in self._walk(root_path):
            for name in files:
                if name not in names:
                    continue
                action_file = directory / name
                # Paths under .github/workflows are workflow files.
                if self._is_in_workflows_dir(action_file) or not self._is(
                    action_file, stat.S_ISREG
                ):
                    continue
                # Judged component by component, and a link where it
                # lands too: a tracked action.yml link can point into an
                # ignored node_modules.
                if scope.ignores(action_file):
                    self.logger.debug(
                        f"Skipping gitignored file: {action_file}"
                    )
                    continue
                self.logger.debug(f"Found action file: {action_file}")
                yield action_file

    @staticmethod
    def _is_in_workflows_dir(path: PurePath) -> bool:
        """
        Return True if ``path`` lives under a ``.github/workflows`` directory.

        Uses ``PurePath.parts`` so the check works on Windows (where the
        path separator is ``\\``) as well as POSIX-like systems. Accepts any
        ``PurePath`` subclass (``Path``, ``PurePosixPath``,
        ``PureWindowsPath``).
        """
        parts = path.parts
        return any(
            parts[i] == ".github" and parts[i + 1] == "workflows"
            for i in range(len(parts) - 1)
        )

    def _should_exclude_file(self, file_path: Path) -> bool:
        """
        Check if file should be excluded based on patterns.

        Args:
            file_path: File path to check

        Returns:
            True if file should be excluded
        """
        if not self.config.exclude_patterns:
            return False

        file_str = str(file_path)
        for pattern in self.config.exclude_patterns:
            if pattern in file_str:
                return True

        return False

    def parse_workflow_file(self, file_path: Path) -> dict[int, ActionCall]:
        """
        Parse a workflow file and extract action calls.

        Args:
            file_path: Path to the workflow file

        Returns:
            Dictionary mapping line numbers to ActionCall objects
        """
        self.logger.debug(f"Parsing workflow file: {file_path}")

        try:
            content = file_path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as e:
            self.logger.error(f"Error reading file {file_path}: {e}")
            return {}

        if not self._is_valid_yaml(content, file_path):
            return {}

        action_calls = self._patterns.extract_action_calls(content)

        self.logger.debug(
            f"Found {len(action_calls)} action calls in {file_path}"
        )

        return action_calls

    def compose_workflow_file(self, file_path: Path) -> yaml.nodes.Node | None:
        """
        Return the composed YAML node tree for a workflow file.

        Where :meth:`parse_workflow_file` returns action calls recovered
        by the line-oriented pattern matcher, this returns PyYAML's node
        tree. Every node carries ``start_mark`` and ``end_mark`` with
        0-based ``line`` and ``column`` attributes, so a caller can map
        document structure back onto source positions without reading and
        parsing the workflow a second time.

        Composition uses ``yaml.SafeLoader``, so no arbitrary Python
        objects are constructed from the document.

        Note:
            An empty document composes to ``None``. That is
            indistinguishable from the failure result, so a caller that
            must tell the two apart has to check the file separately.

        Note:
            Comments are lexical, not structural: PyYAML discards them
            while scanning, and they are absent from the returned tree.
            Version-pin comments such as ``# v5.0.0`` cannot be recovered
            from these nodes.

        Note:
            Under YAML 1.1 resolution, which ``SafeLoader`` implements, a
            bare ``on:`` key resolves to the boolean ``True`` rather than
            the string ``"on"``. Callers walking a workflow's top-level
            mapping must accept both.

        Args:
            file_path: Path to the workflow file

        Returns:
            Root node of the composed tree, or None when the file cannot
            be read, is not valid YAML, or is empty. Never raises.
        """
        try:
            content = file_path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as e:
            self.logger.warning(f"Error reading file {file_path}: {e}")
            return None

        return self._compose(content, file_path).node

    def _is_valid_yaml(self, content: str, file_path: Path) -> bool:
        """
        Validate YAML syntax of workflow file.

        Args:
            content: File content
            file_path: Path to file (for logging)

        Returns:
            True if valid YAML, False otherwise
        """
        return self._compose(content, file_path).valid

    def _compose(self, content: str, file_path: Path) -> _ComposeResult:
        """
        Compose already-read content into a YAML node tree.

        Shared by the syntax gate in :meth:`parse_workflow_file` and by
        :meth:`compose_workflow_file`, so content that has already been
        read is parsed once rather than once per concern.

        Composing stops after the resolution stage, so unlike
        ``yaml.safe_load`` it never reports construction failures (an
        unknown ``!!tag``, for example). Workflow files carry no custom
        tags, and every syntax error a workflow can realistically hold is
        raised by the scanner, parser or composer this does run.

        Args:
            content: File content
            file_path: Path to file (for logging)

        Returns:
            The validity verdict paired with the composed tree, which is
            None for an empty or invalid document.
        """
        try:
            node = yaml.compose(content, Loader=yaml.SafeLoader)
        except yaml.YAMLError as e:
            self.logger.warning(f"Invalid YAML in {file_path}: {e}")
            return _ComposeResult(valid=False, node=None)

        return _ComposeResult(
            valid=True, node=cast("yaml.nodes.Node | None", node)
        )

    def scan_directory(
        self,
        root_path: Path,
        progress: Progress | None = None,
        task_id: TaskID | None = None,
        specific_files: list[str] | None = None,
    ) -> dict[Path, dict[int, ActionCall]]:
        """
        Scan directory for workflows and parse all action calls.

        Args:
            root_path: Root directory to scan
            progress: Optional progress bar
            task_id: Optional task ID for progress updates
            specific_files: Optional list of specific files to scan (supports wildcards)

        Returns:
            Dictionary mapping file paths to their action calls
        """

        results: dict[Path, dict[int, ActionCall]] = {}

        # If specific files are provided, scan only those files
        if specific_files:
            workflow_files = self.resolve_specific_files(
                root_path, specific_files
            )
            for workflow_file in workflow_files:
                if progress and task_id:
                    progress.update(
                        task_id,
                        description=f"Scanning {workflow_file.name}...",
                    )
                try:
                    action_calls = self.parse_workflow_file(workflow_file)
                    if action_calls:
                        results[workflow_file] = action_calls
                except Exception as e:
                    self.logger.error(
                        f"Error processing workflow file {workflow_file}: {e}"
                    )
                    continue
        else:
            # Default behavior: scan all workflow files
            for workflow_file in self.find_workflow_files(
                root_path, progress, task_id
            ):
                try:
                    action_calls = self.parse_workflow_file(workflow_file)
                    if action_calls:
                        results[workflow_file] = action_calls
                except Exception as e:
                    self.logger.error(
                        f"Error processing workflow file {workflow_file}: {e}"
                    )
                    continue

        total_calls = sum(len(calls) for calls in results.values())
        self.logger.debug(
            f"Scan complete: {len(results)} files, {total_calls} action/workflow calls"
        )

        return results

    def resolve_specific_files(
        self, root_path: Path, file_patterns: list[str]
    ) -> list[Path]:
        """
        Resolve specific file patterns to actual file paths.

        Supports:
        - Absolute paths
        - Relative paths (resolved from root_path)
        - Wildcards (glob patterns)

        Args:
            root_path: Root directory for resolving relative paths
            file_patterns: List of file patterns (can include wildcards)

        Returns:
            List of resolved file paths
        """
        resolved_files: list[Path] = []
        seen: set[Path] = set()

        for pattern in file_patterns:
            for match in self._resolve_file_pattern(root_path, pattern):
                if match not in seen:
                    seen.add(match)
                    resolved_files.append(match)

        if not resolved_files:
            self.logger.warning(
                f"No workflow or action files found matching patterns: {file_patterns}"
            )

        return resolved_files

    def _resolve_file_pattern(
        self, root_path: Path, pattern: str
    ) -> list[Path]:
        """Resolve a single file pattern to workflow/action file paths.

        A literal path is the caller's word and is honoured as named, even
        inside a gitignored directory. A glob selects as discovery does,
        so it leaves out what git ignores: its recursive fallback would
        otherwise reach into ``node_modules/`` (issue #378).
        """
        pattern_path = Path(pattern)
        if not _is_glob(pattern):
            if pattern_path.is_absolute():
                return self._resolve_absolute_pattern(pattern, pattern_path)
            return self._resolve_relative_file(root_path, pattern)
        if pattern_path.is_absolute():
            matches = self._resolve_absolute_pattern(pattern, pattern_path)
        else:
            matches = self._resolve_glob_pattern(root_path, pattern)
        return list(self.ignored_paths(root_path).keep(matches))

    def _resolve_absolute_pattern(
        self, pattern: str, pattern_path: Path
    ) -> list[Path]:
        """Resolve an absolute path or absolute glob pattern."""
        if _is_glob(pattern):
            parent = pattern_path.parent
            if not parent.exists():
                return []
            return self._filter_workflow_files(parent.glob(pattern_path.name))
        if pattern_path.is_file():
            if self._is_workflow_or_action_file(pattern_path):
                return [pattern_path]
            self.logger.warning(
                f"File {pattern_path} is not a workflow or action file"
            )
            return []
        self.logger.warning(f"File not found: {pattern_path}")
        return []

    def _resolve_glob_pattern(
        self, root_path: Path, pattern: str
    ) -> list[Path]:
        """Resolve a relative glob pattern, including a recursive fallback."""
        matches = self._filter_workflow_files(root_path.glob(pattern))
        if not pattern.startswith("**"):
            matches.extend(
                self._filter_workflow_files(root_path.glob(f"**/{pattern}"))
            )
        return matches

    def _resolve_relative_file(
        self, root_path: Path, pattern: str
    ) -> list[Path]:
        """Resolve a direct relative file path from ``root_path``."""
        full_path = root_path / pattern
        if full_path.is_file():
            if self._is_workflow_or_action_file(full_path):
                return [full_path]
            self.logger.warning(
                f"File {full_path} is not a workflow or action file"
            )
            return []
        self.logger.warning(f"File not found: {full_path}")
        return []

    def _filter_workflow_files(self, candidates: Iterable[Path]) -> list[Path]:
        """Keep only existing files that are workflow or action files."""
        return [
            match
            for match in candidates
            if match.is_file() and self._is_workflow_or_action_file(match)
        ]

    def _is_workflow_or_action_file(self, file_path: Path) -> bool:
        """
        Check if a file is a workflow or action definition file.

        Args:
            file_path: Path to check

        Returns:
            True if file is a workflow or action file
        """
        if file_path.suffix not in self.config.scan_extensions:
            return False

        # Check if it's an action file
        if file_path.name in ["action.yml", "action.yaml"]:
            return True

        # Check if it's in a workflows directory (cross-platform).
        return self._is_in_workflows_dir(file_path)

    def get_scan_summary(
        self, results: dict[Path, dict[int, ActionCall]]
    ) -> dict[str, int]:
        """
        Generate summary statistics for scan results.

        Args:
            results: Scan results from scan_directory

        Returns:
            Dictionary with summary statistics
        """
        total_files = len(results)
        total_calls = sum(len(calls) for calls in results.values())

        # Count by call type
        action_calls = 0
        workflow_calls = 0

        # Count by reference type
        sha_refs = 0
        tag_refs = 0
        branch_refs = 0

        for file_calls in results.values():
            for action_call in file_calls.values():
                if action_call.call_type.value == "action":
                    action_calls += 1
                elif action_call.call_type.value == "workflow":
                    workflow_calls += 1

                if action_call.reference_type.value == "commit_sha":
                    sha_refs += 1
                elif action_call.reference_type.value == "tag":
                    tag_refs += 1
                elif action_call.reference_type.value == "branch":
                    branch_refs += 1

        return {
            "total_files": total_files,
            "total_calls": total_calls,
            "action_calls": action_calls,
            "workflow_calls": workflow_calls,
            "sha_references": sha_refs,
            "tag_references": tag_refs,
            "branch_references": branch_refs,
        }
