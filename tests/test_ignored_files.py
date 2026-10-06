# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Discovery leaves out files git ignores (issue #378).

Discovery walks the tree, so in a JavaScript repository where ``npm ci``
has run it found every dependency's workflows and ``action.yml`` files
under ``node_modules/``, linted them, and rewrote them with automatic
fixes. The pre-commit hook runs ``lint .`` with ``pass_filenames:
false``, so every developer commit walked the whole tree.

Each test builds a real repository, because the question is what git
says, not what a stand-in says. Fixtures never commit: the developers'
global ``commit.gpgsign`` would try to sign, and ``git add`` is all an
index needs.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
import subprocess
from typing import TYPE_CHECKING, Any
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from gha_workflow_linter.action_call_fix import AutoFixer
from gha_workflow_linter.cli import _allow_list_paths, app
from gha_workflow_linter.git_ignored import (
    IgnoreIndex,
    IgnoreScope,
    _Repository,
)
from gha_workflow_linter.models import CLIOptions, Config
from gha_workflow_linter.scanner import WorkflowScanner
from tests.conftest import SHA_ANSWERING_EVERY_LOOKUP

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator

#: A workflow with a tag-pinned call, which automatic fixes rewrite.
WORKFLOW = """\
name: CI
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
"""

#: An action definition with the same call.
ACTION = """\
name: Dependency action
description: Stands in for a published npm package's action
runs:
  using: composite
  steps:
    - uses: actions/checkout@v4
"""


def _git(root: Path, *args: str) -> None:
    """Run a local git command in ``root``, isolated from the caller.

    Args:
        root: Directory to run in.
        args: Arguments after ``git -C root``.
    """
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    subprocess.run(
        ["git", "-C", str(root), *args],
        check=True,
        capture_output=True,
        env=env,
    )


def _write(path: Path, content: str) -> Path:
    """Write ``content`` to ``path``, creating parent directories.

    Args:
        path: File to write.
        content: Text to write.

    Returns:
        The path written.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)
    return path


def _repository(root: Path, ignore: str = "node_modules/\n") -> Path:
    """Build the issue's layout: our workflow, and ignored dependencies.

    Args:
        root: Directory to make the repository in.
        ignore: Contents of ``.gitignore``.

    Returns:
        The repository root.
    """
    root.mkdir(parents=True, exist_ok=True)
    _git(root, "init", "-q")
    _write(root / ".gitignore", ignore)
    _write(root / ".github" / "workflows" / "ci.yml", WORKFLOW)
    _write(
        root / "node_modules" / "pkg" / ".github" / "workflows" / "ci.yml",
        WORKFLOW,
    )
    _write(root / "node_modules" / "pkg2" / "action.yml", ACTION)
    _git(root, "add", ".gitignore", ".github")
    return root


def _found(scanner: WorkflowScanner, root: Path) -> set[str]:
    """Discover files under ``root``, as POSIX paths relative to it.

    Args:
        scanner: Scanner to discover with.
        root: Scan root.

    Returns:
        The discovered paths.
    """
    return {
        path.relative_to(root).as_posix()
        for path in scanner.find_workflow_files(root)
    }


@pytest.fixture
def scanner() -> WorkflowScanner:
    """A scanner with the default configuration.

    Returns:
        The scanner.
    """
    return WorkflowScanner(Config())


class TestDiscoveryLeavesOutIgnoredFiles:
    """The two tree walks consult git's ignore rules."""

    def test_ignored_workflows_and_actions_are_not_discovered(
        self, tmp_path: Path, scanner: WorkflowScanner
    ) -> None:
        """Both walks leave out ``node_modules/``, and keep our workflow."""
        root = _repository(tmp_path / "repo")

        assert _found(scanner, root) == {".github/workflows/ci.yml"}

    def test_an_untracked_workflow_that_is_not_ignored_is_discovered(
        self, tmp_path: Path, scanner: WorkflowScanner
    ) -> None:
        """A workflow not yet added is still ours to lint.

        Filtering to *tracked* files instead of *unignored* ones would
        silently skip a workflow a developer is still writing.
        """
        root = _repository(tmp_path / "repo")
        _write(root / ".github" / "workflows" / "draft.yml", WORKFLOW)

        assert ".github/workflows/draft.yml" in _found(scanner, root)

    def test_a_tracked_file_inside_an_ignored_directory_is_discovered(
        self, tmp_path: Path, scanner: WorkflowScanner
    ) -> None:
        """``git add -f`` makes a file the repository's, ignore or not."""
        root = _repository(tmp_path / "repo", "vendored/\nnode_modules/\n")
        _write(root / "vendored" / "action.yml", ACTION)
        _git(root, "add", "-f", "vendored/action.yml")

        assert "vendored/action.yml" in _found(scanner, root)

    def test_a_case_only_rename_is_not_dropped(
        self, tmp_path: Path, scanner: WorkflowScanner
    ) -> None:
        """An index spelling that differs from the disk keeps the file.

        On a case-insensitive filesystem a rename without ``git mv``
        leaves ``ci.yml`` in the index and ``CI.yml`` on disk. A filter
        keeping only what git *lists* would drop the workflow; dropping
        only what git *ignores* keeps it.
        """
        root = _repository(tmp_path / "repo")
        workflows = root / ".github" / "workflows"
        (workflows / "ci.yml").rename(workflows / "tmp.yml")
        (workflows / "tmp.yml").rename(workflows / "CI.yml")

        assert ".github/workflows/CI.yml" in _found(scanner, root)

    def test_a_subdirectory_scan_applies_the_repository_rules(
        self, tmp_path: Path, scanner: WorkflowScanner
    ) -> None:
        """Rules from the repository root apply below a scanned subtree."""
        root = _repository(tmp_path / "repo")
        _write(root / "sub" / ".github" / "workflows" / "ci.yml", WORKFLOW)
        _write(
            root
            / "sub"
            / "node_modules"
            / "p"
            / ".github"
            / "workflows"
            / "x.yml",
            WORKFLOW,
        )

        assert _found(scanner, root / "sub") == {".github/workflows/ci.yml"}

    def test_scanning_an_ignored_directory_by_name_lints_it(
        self, tmp_path: Path, scanner: WorkflowScanner
    ) -> None:
        """Naming an ignored directory as the root is explicit intent.

        Filtering it would lint nothing and report success.
        """
        root = _repository(tmp_path / "repo")
        package = root / "node_modules" / "pkg"

        assert _found(scanner, package) == {".github/workflows/ci.yml"}

    def test_a_forced_descendant_does_not_change_a_named_root(
        self, tmp_path: Path, scanner: WorkflowScanner
    ) -> None:
        """A root matching an ignore rule is linted whole, forced file or not.

        Git reports a directory holding a force-added file entry by entry
        rather than as the directory, so judging the root by the listing
        let one unrelated ``git add -f`` decide what ``lint vendored``
        covered. The root is judged by the rules alone instead.
        """
        root = _repository(tmp_path / "repo", "vendored/\nnode_modules/\n")
        _write(root / "vendored" / "kept" / "action.yml", ACTION)
        _write(root / "vendored" / "other" / "action.yml", ACTION)
        _git(root, "add", "-f", "vendored/kept/action.yml")

        assert _found(scanner, root / "vendored") == {
            "kept/action.yml",
            "other/action.yml",
        }

    def test_an_ignored_workflows_link_does_not_lead_out_of_the_repository(
        self, tmp_path: Path, scanner: WorkflowScanner
    ) -> None:
        """An ignored ``.github/workflows`` link to elsewhere is not followed.

        With ``.github/`` holding tracked files, git lists only the link
        as ignored, and as a file. Discovery builds the workflows path
        from the level above, so the walk's pruning never judged it, and
        automatic fixes would have rewritten files outside the repository.
        """
        external = tmp_path / "external"
        _write(external / "outside.yml", WORKFLOW)
        root = tmp_path / "repo"
        _write(root / ".github" / "dependabot.yml", "version: 2\n")
        (root / ".github" / "workflows").symlink_to(external)
        _git(root, "init", "-q")
        _write(root / ".gitignore", ".github/workflows\n")
        _git(root, "add", ".gitignore", ".github/dependabot.yml")

        assert _found(scanner, root) == set()

    def test_an_ignored_workflows_link_is_not_listed_at_all(
        self,
        tmp_path: Path,
        scanner: WorkflowScanner,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The external directory is never enumerated, not merely filtered.

        Each file found there would be dropped anyway; not globbing a
        directory outside the repository in the first place is the
        stronger guarantee, and does not rest on the per-file check.
        """
        external = tmp_path / "external"
        _write(external / "outside.yml", WORKFLOW)
        root = tmp_path / "repo"
        _write(root / ".github" / "dependabot.yml", "version: 2\n")
        (root / ".github" / "workflows").symlink_to(external)
        _git(root, "init", "-q")
        _write(root / ".gitignore", ".github/workflows\n")
        _git(root, "add", ".gitignore", ".github/dependabot.yml")

        assert scanner._find_workflow_directories(root) == set()

    def test_a_tracked_link_into_an_ignored_directory_is_left_out(
        self, tmp_path: Path, scanner: WorkflowScanner
    ) -> None:
        """A link git tracks is judged where it lands as well.

        Judged only by name, a tracked ``.github/workflows`` link into
        ``node_modules/`` passed, and fixes would rewrite the dependency's
        workflow through it. The same holds for an ``action.yml`` link to
        a file inside the ignored directory.
        """
        root = _repository(tmp_path / "repo")
        package = root / "node_modules" / "pkg"
        (root / ".github" / "workflows" / "ci.yml").unlink()
        (root / ".github" / "workflows").rmdir()
        _write(root / ".github" / "dependabot.yml", "version: 2\n")
        (root / ".github" / "workflows").symlink_to(
            package / ".github" / "workflows"
        )
        _write(package / "action.yml", ACTION)
        (root / "tools").mkdir()
        (root / "tools" / "action.yml").symlink_to(package / "action.yml")
        _git(root, "add", ".github", "tools")

        assert _found(scanner, root) == set()
        assert scanner._find_workflow_directories(root) == set()

    def test_a_tracked_link_to_a_tracked_file_is_discovered(
        self, tmp_path: Path, scanner: WorkflowScanner
    ) -> None:
        """Judging a link's destination does not drop links in general."""
        root = _repository(tmp_path / "repo")
        _write(root / "shared" / "action.yml", ACTION)
        (root / "alias").mkdir()
        (root / "alias" / "action.yml").symlink_to(
            root / "shared" / "action.yml"
        )
        _git(root, "add", "shared", "alias")

        assert {"shared/action.yml", "alias/action.yml"} <= _found(
            scanner, root
        )

    def test_an_intermediate_link_into_a_nested_ignored_repository(
        self, tmp_path: Path, scanner: WorkflowScanner
    ) -> None:
        """A link mid-path is judged along its whole destination.

        A tracked ``.github`` link into ``node_modules/gitdep``, where
        ``gitdep`` is a repository of its own, used to pass: the parts
        after the link were judged by ``gitdep`` alone, which ignores
        nothing of its own, and the enclosing ``node_modules/`` rule was
        never consulted. A link to a tracked directory is still followed.
        """
        root = _repository(tmp_path / "repo")
        (root / ".github" / "workflows" / "ci.yml").unlink()
        (root / ".github" / "workflows").rmdir()
        (root / ".github").rmdir()
        dependency = root / "node_modules" / "gitdep"
        _write(dependency / ".github" / "workflows" / "ci.yml", WORKFLOW)
        _git(dependency, "init", "-q")
        (root / ".github").symlink_to(dependency / ".github")
        _write(root / "shared" / ".github" / "workflows" / "own.yml", WORKFLOW)
        (root / "alias").mkdir()
        (root / "alias" / ".github").symlink_to(root / "shared" / ".github")
        _git(root, "add", ".github", "shared", "alias")
        kept = {
            "shared/.github/workflows/own.yml",
            "alias/.github/workflows/own.yml",
        }

        found = scanner.resolve_specific_files(
            root, [".github/workflows/*.yml"]
        )

        assert _found(scanner, root) == kept
        assert {p.relative_to(root).as_posix() for p in found} == kept

    def test_a_chain_of_links_is_judged_at_every_hop(
        self, tmp_path: Path, scanner: WorkflowScanner
    ) -> None:
        """A link chain cannot collapse past an ignored hop.

        ``node_modules/pkg`` links outside the repository. Resolving a
        tracked link through it in one go judged only the far end, which
        nothing ignores, so the external files reached discovery, globs
        and fixes. Each hop is now judged as named before the next.
        """
        external = tmp_path / "external"
        _write(external / "wf" / "ci.yml", WORKFLOW)
        _write(external / "action.yml", ACTION)
        root = _repository(tmp_path / "repo")
        (root / ".github" / "workflows" / "ci.yml").unlink()
        (root / ".github" / "workflows").rmdir()
        _write(root / ".github" / "dependabot.yml", "version: 2\n")
        (root / "node_modules" / "chain").symlink_to(external)
        linked = root / "node_modules" / "chain"
        (root / ".github" / "workflows").symlink_to(linked / "wf")
        (root / "tools").mkdir()
        (root / "tools" / "action.yml").symlink_to(linked / "action.yml")
        _git(root, "add", ".github", "tools")

        found = scanner.resolve_specific_files(
            root, [".github/workflows/*.yml", "tools/*.yml"]
        )

        assert _found(scanner, root) == set()
        assert found == []

    def test_an_ignored_hop_in_a_chain_is_judged(
        self, tmp_path: Path, scanner: WorkflowScanner
    ) -> None:
        """A link that is itself ignored still stops the chain through it."""
        external = tmp_path / "external"
        _write(external / "ci.yml", WORKFLOW)
        root = _repository(tmp_path / "repo", "node_modules/\nhop\n")
        (root / ".github" / "workflows" / "ci.yml").unlink()
        (root / ".github" / "workflows").rmdir()
        _write(root / ".github" / "dependabot.yml", "version: 2\n")
        (root / "hop").symlink_to(external)
        (root / ".github" / "workflows").symlink_to(root / "hop")
        _git(root, "add", ".github")

        assert _found(scanner, root) == set()

    def test_a_link_loop_does_not_stop_discovery(
        self, tmp_path: Path, scanner: WorkflowScanner
    ) -> None:
        """A looping link is left out, and the rest is still found.

        ``Path.resolve`` raises on a loop before Python 3.13, which took
        the whole scan down with it. Links are now followed one hop at a
        time under a limit, and a loop names nothing readable.
        """
        root = _repository(tmp_path / "repo")
        workflows = root / ".github" / "workflows"
        (workflows / "a.yml").symlink_to(workflows / "b.yml")
        (workflows / "b.yml").symlink_to(workflows / "a.yml")

        assert _found(scanner, root) == {".github/workflows/ci.yml"}

    def test_branching_links_share_one_budget(
        self,
        tmp_path: Path,
        scanner: WorkflowScanner,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Links within links spend one budget, as the kernel counts them.

        ``hopN`` links to ``hopN-1/hopN-1``, so ``hop8`` stands for 255
        links, past any kernel's limit. With a budget per component the
        walk followed all of them, 512 reads growing twofold per level,
        and kept a path the kernel rejects. ``hop2`` is a control: seven
        links, readable, and kept.
        """
        root = _repository(tmp_path / "repo")
        workflows = root / ".github" / "workflows"
        (workflows / "hop0").symlink_to(".")
        for level in range(1, 9):
            (workflows / f"hop{level}").symlink_to(
                f"hop{level - 1}/hop{level - 1}"
            )
        (workflows / "near.yml").symlink_to("hop2/ci.yml")
        (workflows / "far.yml").symlink_to("hop8/ci.yml")
        reads: list[str] = []
        real_readlink = os.readlink

        def counting(path: Any, *args: Any, **kwargs: Any) -> Any:
            """Record a link read, then read it.

            Args:
                path: The link.
                args: Positional arguments, passed through.
                kwargs: Keyword arguments, passed through.

            Returns:
                The link's target.
            """
            reads.append(str(path))
            return real_readlink(path, *args, **kwargs)

        monkeypatch.setattr(os, "readlink", counting)
        found = _found(scanner, root)

        assert found == {
            ".github/workflows/ci.yml",
            ".github/workflows/near.yml",
        }
        assert len(reads) < 200

    def test_git_is_asked_once_per_repository(
        self,
        tmp_path: Path,
        scanner: WorkflowScanner,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Discovery and every glob reaching one repository share an answer.

        Asking from the repository's top level, not from each directory
        scanned, also keeps git out of an ignored directory, where it
        fails with "directory entry not superset of prefix".
        """
        root = _repository(tmp_path / "repo")
        _write(root / "sub" / ".github" / "workflows" / "ci.yml", WORKFLOW)
        guarded = subprocess.run
        listings: list[str] = []

        def counting(*args: Any, **kwargs: Any) -> Any:
            """Record where git lists ignored files, then run it.

            Args:
                args: Positional arguments as ``subprocess.run`` takes them.
                kwargs: Keyword arguments, passed through.

            Returns:
                The real result.
            """
            cmd = args[0] if args else kwargs.get("args", [])
            if isinstance(cmd, list) and "--ignored" in cmd:
                listings.append(cmd[2])
            return guarded(*args, **kwargs)

        monkeypatch.setattr(subprocess, "run", counting)
        _found(scanner, root)
        _found(scanner, root / "sub")
        _found(scanner, root / "node_modules" / "pkg")
        scanner.resolve_specific_files(root, [".github/workflows/*.yml"])

        assert listings == [str(root.resolve())]

    def test_an_ignored_directory_is_not_walked(
        self,
        tmp_path: Path,
        scanner: WorkflowScanner,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Discovery prunes ``node_modules`` rather than filtering after.

        A recursive glob descended through every package and dropped the
        results afterwards, so each commit paid for a walk of the whole
        dependency tree it then threw away.
        """
        root = _repository(tmp_path / "repo")
        walked: list[str] = []
        real_walk = os.walk

        def recording(top: Any, *args: Any, **kwargs: Any) -> Any:
            """Record every directory the walk enters.

            Args:
                top: Where the walk starts.
                args: Positional arguments, passed through.
                kwargs: Keyword arguments, passed through.

            Yields:
                What ``os.walk`` yields.
            """
            for entry in real_walk(top, *args, **kwargs):
                walked.append(Path(entry[0]).relative_to(root).as_posix())
                yield entry

        monkeypatch.setattr(os, "walk", recording)
        found = _found(scanner, root)

        assert found == {".github/workflows/ci.yml"}
        assert not [d for d in walked if d.startswith("node_modules")]

    def test_a_forced_file_keeps_its_ignored_directory_walked(
        self, tmp_path: Path, scanner: WorkflowScanner
    ) -> None:
        """Pruning spares a directory holding a tracked file.

        Git collapses a directory to one ``dir/`` entry only when nothing
        inside it is tracked, so the walk still reaches the forced file
        and still leaves out its ignored siblings.
        """
        root = _repository(tmp_path / "repo", "vendored/\nnode_modules/\n")
        _write(root / "vendored" / "kept" / "action.yml", ACTION)
        _write(root / "vendored" / "kept" / "notes.txt", "ignored\n")
        _write(root / "vendored" / "other" / "action.yml", ACTION)
        _git(root, "add", "-f", "vendored/kept/action.yml")

        found = _found(scanner, root)

        assert "vendored/kept/action.yml" in found
        assert "vendored/other/action.yml" not in found

    def test_individually_ignored_workflows_and_actions_are_left_out(
        self, tmp_path: Path, scanner: WorkflowScanner
    ) -> None:
        """A file ignored by name is left out, not only whole directories.

        Pruning covers an ignored directory; a single ignored file inside
        a walked directory is caught when it is found instead. ``tools/``
        needs a sibling git does not ignore: with nothing else in it, git
        reports ``tools/`` as one ignored entry and the walk prunes it
        before the file is ever found.
        """
        root = _repository(
            tmp_path / "repo",
            "node_modules/\n.github/workflows/local.yml\ntools/action.yml\n",
        )
        _write(root / ".github" / "workflows" / "local.yml", WORKFLOW)
        _write(root / "tools" / "action.yml", ACTION)
        _write(root / "tools" / "README.md", "kept\n")

        assert _found(scanner, root) == {".github/workflows/ci.yml"}

    def test_outside_a_work_tree_discovery_is_unchanged(
        self, tmp_path: Path, scanner: WorkflowScanner
    ) -> None:
        """Without git's answer, the walk is exactly what it was."""
        root = tmp_path / "plain"
        _write(root / ".gitignore", "node_modules/\n")
        _write(root / ".github" / "workflows" / "ci.yml", WORKFLOW)
        _write(
            root / "node_modules" / "pkg" / ".github" / "workflows" / "ci.yml",
            WORKFLOW,
        )

        assert _found(scanner, root) == {
            ".github/workflows/ci.yml",
            "node_modules/pkg/.github/workflows/ci.yml",
        }

    def test_without_git_discovery_is_unchanged(
        self,
        tmp_path: Path,
        scanner: WorkflowScanner,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """An absent git binary costs the filter, not the scan."""
        root = _repository(tmp_path / "repo")
        real_run = subprocess.run

        def no_git(*args: Any, **kwargs: Any) -> Any:
            """Fail to start git, pass anything else on.

            Args:
                args: Positional arguments as ``subprocess.run`` takes them.
                kwargs: Keyword arguments, passed through.

            Returns:
                The real result for a non-git command.

            Raises:
                FileNotFoundError: For any git command.
            """
            cmd = args[0] if args else kwargs.get("args", [])
            if isinstance(cmd, list) and cmd and cmd[0] == "git":
                raise FileNotFoundError(2, "No such file or directory: 'git'")
            return real_run(*args, **kwargs)

        monkeypatch.setattr(subprocess, "run", no_git)

        assert "node_modules/pkg/.github/workflows/ci.yml" in _found(
            scanner, root
        )


@pytest.fixture
def lock() -> Iterator[Callable[..., None]]:
    """Take permissions from directories, giving them back after.

    Yields:
        A function locking one directory, to mode 0 unless given another.
        It skips the test when the process ignores permissions, as root
        does.
    """
    locked: list[Path] = []

    def take(directory: Path, mode: int = 0) -> None:
        """Lock one directory.

        Args:
            directory: Directory to lock.
            mode: Mode to leave it in; every mode used withholds reading.
        """
        directory.chmod(mode)
        locked.append(directory)
        if os.access(directory, os.R_OK):
            pytest.skip("running with privileges that ignore permissions")

    yield take
    for directory in reversed(locked):
        directory.chmod(0o755)


def _unreadable(caplog: pytest.LogCaptureFixture) -> list[Path]:
    """List the paths discovery reported it could not read.

    Args:
        caplog: Captured log records.

    Returns:
        Each reported path, in order.
    """
    prefix = "Cannot read "
    return [
        Path(message[len(prefix) :].split(": ", 1)[0])
        for message in (record.getMessage() for record in caplog.records)
        if message.startswith(prefix)
    ]


class TestAnUnreadablePathDoesNotStopDiscovery:
    """One path discovery cannot read costs that path, not the scan.

    Before Python 3.14, ``Path.is_symlink``, ``is_dir`` and ``is_file``
    raise ``PermissionError`` where a parent lacks search permission;
    from 3.14 they answer False. The finders this replaced caught the
    error around the whole scan, which ended it, so a readable control
    sits beside each locked path.
    """

    def test_a_workflow_link_through_a_locked_directory_is_kept(
        self,
        tmp_path: Path,
        scanner: WorkflowScanner,
        lock: Callable[[Path], None],
    ) -> None:
        """The link is judged as named and kept, on every Python.

        It is not dropped as ignored: 3.14 keeps it, and so did the glob
        this replaced, leaving the reader to report it unreadable.
        """
        root = _repository(tmp_path / "repo")
        locked = tmp_path / "locked"
        _write(locked / "target.yml", WORKFLOW)
        workflows = root / ".github" / "workflows"
        (workflows / "linked.yml").symlink_to(locked / "target.yml")
        lock(locked)

        assert _found(scanner, root) == {
            ".github/workflows/ci.yml",
            ".github/workflows/linked.yml",
        }

    def test_a_locked_nested_github_is_reported_and_passed_over(
        self,
        tmp_path: Path,
        scanner: WorkflowScanner,
        lock: Callable[[Path], None],
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Its workflows are reported unreadable; the rest is found.

        A ``.github`` without workflows is absent, not unreadable, and
        stays quiet.
        """
        root = _repository(tmp_path / "repo")
        _write(root / "sub" / ".github" / "workflows" / "ci.yml", WORKFLOW)
        _write(root / "docs" / ".github" / "dependabot.yml", "version: 2\n")
        lock(root / "sub" / ".github")

        with caplog.at_level(logging.WARNING):
            found = _found(scanner, root)

        assert found == {".github/workflows/ci.yml"}
        assert _unreadable(caplog) == [root / "sub" / ".github" / "workflows"]

    def test_an_action_link_into_a_locked_directory_is_reported(
        self,
        tmp_path: Path,
        scanner: WorkflowScanner,
        lock: Callable[[Path], None],
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """The link is reported and passed over; a readable action is kept.

        Dangling and looping links name nothing, as they always did, and
        stay quiet.
        """
        root = _repository(tmp_path / "repo")
        _write(root / "tools" / "kept" / "action.yml", ACTION)
        locked = tmp_path / "locked"
        _write(locked / "action.yml", ACTION)
        for name in ("linked", "dangling", "looping"):
            (root / "tools" / name).mkdir()
        linked = root / "tools" / "linked" / "action.yml"
        linked.symlink_to(locked / "action.yml")
        dangling = root / "tools" / "dangling" / "action.yml"
        dangling.symlink_to(tmp_path / "missing.yml")
        looping = root / "tools" / "looping" / "action.yml"
        looping.symlink_to(looping)
        lock(locked)

        with caplog.at_level(logging.WARNING):
            found = _found(scanner, root)

        assert found == {".github/workflows/ci.yml", "tools/kept/action.yml"}
        assert _unreadable(caplog) == [linked]

    def test_a_root_that_cannot_be_listed_still_has_its_own_found(
        self,
        tmp_path: Path,
        scanner: WorkflowScanner,
        lock: Callable[..., None],
    ) -> None:
        """A root searchable but not listable keeps its direct workflows.

        The finders this replaced probed ``.github/workflows`` at the
        root by name, which needs no listing. The walk lists the root
        first, and found nothing there at all. The names discovery looks
        for at the root are now tried directly, and find what a listing
        would, once each.
        """
        root = _repository(tmp_path / "repo")
        _write(root / "action.yml", ACTION)
        listable = sorted(WorkflowScanner(Config()).find_workflow_files(root))
        lock(root, 0o111)

        assert sorted(scanner.find_workflow_files(root)) == listable
        assert listable == [
            root / ".github" / "workflows" / "ci.yml",
            root / "action.yml",
        ]

    def test_an_unlisted_root_keeps_the_repository_boundary(
        self,
        tmp_path: Path,
        scanner: WorkflowScanner,
        lock: Callable[..., None],
    ) -> None:
        """A ``.github`` that is a repository of its own is not entered."""
        root = _repository(tmp_path / "repo")
        _write(root / "action.yml", ACTION)
        (root / ".github" / ".git").mkdir()
        lock(root, 0o111)

        assert _found(scanner, root) == {"action.yml"}

    def test_the_probe_still_tells_kinds_apart(
        self, tmp_path: Path, scanner: WorkflowScanner
    ) -> None:
        """The probe tells kinds apart, as ``is_dir`` and ``is_file`` did.

        A file named ``workflows`` is not listed, nor, where the platform
        has named pipes, a pipe named ``action.yml``.
        """
        root = _repository(tmp_path / "repo")
        _write(root / "sub" / ".github" / "workflows", "not a directory\n")
        mkfifo = getattr(os, "mkfifo", None)
        if mkfifo is not None:
            (root / "tools").mkdir()
            mkfifo(root / "tools" / "action.yml")

        assert scanner._find_workflow_directories(root) == {
            root / ".github" / "workflows"
        }
        assert _found(scanner, root) == {".github/workflows/ci.yml"}


class TestTheIgnoredListingContract:
    """The lookup over git's listing answers for a path and its ancestors.

    Every current caller also checks ancestors itself, so this is tested
    directly: a future caller relying on the documented contract must
    not get a silently wrong answer.
    """

    def test_a_path_inherits_an_ignored_ancestor_of_either_kind(self) -> None:
        """Directory entries and file entries both cover what lies below.

        Git records a symbolic link as a file even when it stands for a
        directory, so ``.github/workflows`` arrives without a trailing
        slash and must still cover the files beneath it.
        """
        listing = b"node_modules/\0.github/workflows\0vendored/other.yml\0"
        repository = _Repository(Path("/repo"), listing)

        assert repository.ignores("node_modules")
        assert repository.ignores("node_modules/pkg/.github/workflows/ci.yml")
        assert repository.ignores(".github/workflows")
        assert repository.ignores(".github/workflows/outside.yml")
        assert repository.ignores("vendored/other.yml")
        assert not repository.ignores("vendored")
        assert not repository.ignores("vendored/kept/action.yml")
        assert not repository.ignores(".github/dependabot.yml")
        assert not repository.ignores("node_modules_like/x.yml")
        assert not repository.ignores(".")

    def test_case_is_folded_only_where_git_folds_it(self) -> None:
        """Names match whatever their case only when asked to.

        Git folds case where ``core.ignorecase`` is set, which ``git
        init`` sets on a case-insensitive filesystem, so ``NODE_MODULES``
        names the ignored directory there. Elsewhere it is another name.
        """
        listing = b"node_modules/\0.github/workflows\0Vendor/\0"
        folding = _Repository(Path("/repo"), listing, fold_case=True)
        exact = _Repository(Path("/repo"), listing)

        assert folding.ignores("NODE_MODULES/pkg/.github/workflows/ci.yml")
        assert folding.ignores(".GitHub/Workflows/outside.yml")
        assert folding.ignores("vendor/action.yml")
        assert not folding.ignores("node_modules_like/x.yml")
        assert not exact.ignores("NODE_MODULES/pkg/.github/workflows/ci.yml")
        assert not exact.ignores(".GitHub/Workflows/outside.yml")
        assert not exact.ignores("vendor/action.yml")
        assert exact.ignores("Vendor/action.yml")

    @pytest.mark.parametrize("ignorecase", ["true", "false"])
    def test_the_index_follows_core_ignorecase(
        self, tmp_path: Path, ignorecase: str
    ) -> None:
        """Each repository's own setting decides, on any filesystem.

        Args:
            tmp_path: Holds the repository.
            ignorecase: The value ``core.ignorecase`` is set to.
        """
        root = _repository(tmp_path / "repo")
        _git(root, "config", "core.ignorecase", ignorecase)
        repository = IgnoreIndex(30).repository(root.resolve())

        assert repository is not None
        assert repository.ignores("node_modules/pkg")
        assert repository.ignores("NODE_MODULES/pkg") == (ignorecase == "true")

    def test_a_named_root_is_recognised_in_any_case_git_folds(
        self, tmp_path: Path
    ) -> None:
        """The named-root exemption follows the repository's case policy.

        ``ignores`` judges spellings, so the mixed-case path need not
        exist, and this runs on a case-sensitive filesystem too, with
        ``core.ignorecase`` set as a case-insensitive one would have it.
        """
        root = _repository(tmp_path / "repo").resolve()
        _git(root, "config", "core.ignorecase", "true")
        package = root / "node_modules" / "pkg"
        scope = IgnoreScope(IgnoreIndex(30), package)
        workflow = Path(".github", "workflows", "ci.yml")

        assert not scope.ignores(package / workflow)
        assert not scope.ignores(root / "NODE_MODULES" / "pkg" / workflow)
        assert scope.ignores(root / "NODE_MODULES" / "other" / workflow)

    def test_a_deep_root_finds_its_repository(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The lookup climbs any depth without recursing per level.

        Recursing once per ancestor raised ``RecursionError`` for a root
        more than about a thousand directories below its repository, a
        layout Linux allows. Only ``.git`` entries are probed, so the
        levels need not exist. Every level passed is cached, so asking
        again, or about any level passed, probes nothing.
        """
        root = _repository(tmp_path / "repo")
        deep = root.resolve().joinpath(*(["d"] * 1100))
        index = IgnoreIndex(30)

        assert index.top(deep) == root.resolve()
        probes: list[Path] = []
        real_exists = Path.exists

        def counting(path: Path, *args: Any, **kwargs: Any) -> bool:
            """Record a probe, then make it.

            Args:
                path: The path probed.
                args: Positional arguments, passed through.
                kwargs: Keyword arguments, passed through.

            Returns:
                Whether the path exists.
            """
            probes.append(path)
            return real_exists(path, *args, **kwargs)

        monkeypatch.setattr(Path, "exists", counting)

        assert index.top(deep) == root.resolve()
        assert index.top(deep.parents[500]) == root.resolve()
        assert probes == []
        assert index.top(tmp_path.resolve()) is None


class TestTheOwningRepositoryAnswers:
    """Git is asked about the scanned repository, whatever it inherits."""

    def test_an_inherited_git_dir_does_not_leak_another_repositorys_rules(
        self,
        tmp_path: Path,
        scanner: WorkflowScanner,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A hook's ``GIT_DIR`` must not answer for the scanned repository.

        Repository A ignores ``lintme/`` in its private exclude file.
        Asked about B with A's ``GIT_DIR`` inherited, git reports
        ``lintme/`` ignored in B too, and B's workflow would vanish.
        """
        a = tmp_path / "a"
        a.mkdir()
        _git(a, "init", "-q")
        (a / ".git" / "info" / "exclude").write_text("lintme/\n")
        b = _repository(tmp_path / "b")
        _write(b / "lintme" / "action.yml", ACTION)
        monkeypatch.setenv("GIT_DIR", str(a / ".git"))

        assert _found(scanner, b) == {
            ".github/workflows/ci.yml",
            "lintme/action.yml",
        }


class TestPatternSelectionLeavesOutIgnoredFiles:
    """Globs select like discovery; literal paths are the caller's word."""

    def test_a_files_glob_does_not_reach_into_ignored_directories(
        self, tmp_path: Path, scanner: WorkflowScanner
    ) -> None:
        """The ``**/`` fallback no longer finds dependencies' workflows."""
        root = _repository(tmp_path / "repo")

        found = scanner.resolve_specific_files(
            root, [".github/workflows/*.yml"]
        )

        assert {p.relative_to(root).as_posix() for p in found} == {
            ".github/workflows/ci.yml"
        }

    def test_a_glob_spelling_an_ignored_directory_in_another_case(
        self, tmp_path: Path, scanner: WorkflowScanner
    ) -> None:
        """On a case-insensitive filesystem any spelling is the same name.

        Git's listing spells ``node_modules/`` as on disk, and a glob
        spelling it ``NODE_MODULES`` reached the dependency's workflow
        past a lookup that told case apart, where fixes would rewrite
        it. Relative, absolute and recursive globs alike.
        """
        root = _repository(tmp_path / "repo")
        if not (root / "NODE_MODULES").exists():
            pytest.skip("the filesystem tells case apart")

        for pattern in (
            "NODE_MODULES/pkg/.github/workflows/*.yml",
            f"{root.as_posix()}/Node_Modules/pkg/.github/workflows/*.yml",
            "NODE_MODULES/**/*.yml",
        ):
            assert scanner.resolve_specific_files(root, [pattern]) == [], (
                pattern
            )

    def test_a_name_differing_in_case_is_its_own_where_case_counts(
        self, tmp_path: Path, scanner: WorkflowScanner
    ) -> None:
        """On a case-sensitive filesystem ``Node_Modules`` is not ignored."""
        root = _repository(tmp_path / "repo")
        if (root / "NODE_MODULES").exists():
            pytest.skip("the filesystem does not tell case apart")
        _write(
            root / "Node_Modules" / "pkg" / ".github" / "workflows" / "ci.yml",
            WORKFLOW,
        )
        found = scanner.resolve_specific_files(root, ["Node_Modules/**/*.yml"])

        assert [p.relative_to(root).as_posix() for p in found] == [
            "Node_Modules/pkg/.github/workflows/ci.yml"
        ]
        assert "Node_Modules/pkg/.github/workflows/ci.yml" in _found(
            scanner, root
        )

    def test_a_glob_through_an_ignored_link_is_left_out(
        self, tmp_path: Path, scanner: WorkflowScanner
    ) -> None:
        """Each component is judged as named, not only the resolved path.

        Resolving the whole path first followed the ignored link out of
        the repository and judged its target, which nothing ignores.
        """
        external = tmp_path / "external"
        _write(external / "outside.yml", WORKFLOW)
        root = tmp_path / "repo"
        _write(root / ".github" / "dependabot.yml", "version: 2\n")
        (root / ".github" / "workflows").symlink_to(external)
        _git(root, "init", "-q")
        _write(root / ".gitignore", ".github/workflows\n")
        _git(root, "add", ".gitignore", ".github/dependabot.yml")

        found = scanner.resolve_specific_files(
            root, [".github/workflows/*.yml"]
        )

        assert found == []

    def test_a_named_ignored_root_is_honoured_under_another_spelling(
        self, tmp_path: Path, scanner: WorkflowScanner
    ) -> None:
        """A glob spelling a named ignored root differently still selects.

        The command resolves its root. A glob naming the same directory
        through a link must be recognised as inside it, or the ignored
        directory above would drop a file the caller asked for by name.
        """
        root = _repository(tmp_path / "real" / "repo")
        package = root / "node_modules" / "pkg"
        (tmp_path / "alias").symlink_to(tmp_path / "real")
        linked = tmp_path / "alias" / "repo" / "node_modules" / "pkg"
        pattern = f"{linked}/.github/workflows/*.yml"

        found = scanner.resolve_specific_files(package.resolve(), [pattern])

        assert [p.name for p in found] == ["ci.yml"]

    def test_globs_do_not_expand_into_ignored_directories(
        self,
        tmp_path: Path,
        scanner: WorkflowScanner,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """An ignored directory is passed over, not expanded and filtered.

        A ``**`` expanded through ``node_modules`` before the results
        were filtered, so ``--files`` and recursive ``extra_globs`` paid
        for every dependency they then dropped. Nothing beneath an
        ignored directory is now even produced; a negated directory is
        still entered.
        """
        root = _repository(
            tmp_path / "repo", "node_modules/\nvendor/*\n!vendor/kept/\n"
        ).resolve()
        for package in ("pkg", "pkg2", "deep/a/b"):
            _write(
                root / "node_modules" / package / "examples" / "x.yaml",
                WORKFLOW,
            )
        _write(root / "examples" / "caller.yaml", WORKFLOW)
        _write(root / "vendor" / "kept" / "examples" / "k.yaml", WORKFLOW)
        _write(root / "vendor" / "kept" / "action.yml", ACTION)
        _write(root / "vendor" / "drop" / "examples" / "d.yaml", WORKFLOW)
        judged: list[Path] = []
        real_ignores = IgnoreScope.ignores

        def recording(self: IgnoreScope, path: Path) -> bool:
            """Record a judgement, then make it.

            Args:
                self: The scope.
                path: The path judged.

            Returns:
                The real answer.
            """
            judged.append(path)
            return real_ignores(self, path)

        monkeypatch.setattr(IgnoreScope, "ignores", recording)
        files = scanner.resolve_specific_files(
            root,
            [
                ".github/workflows/*.yml",
                "**/.github/workflows/*.yml",
                "**/action.yml",
            ],
        )
        config = Config()
        config.allow_list.extra_globs = ["**/examples/*.yaml"]
        paths = _allow_list_paths(config, CLIOptions(path=root), scanner)

        assert {p.relative_to(root).as_posix() for p in files} == {
            ".github/workflows/ci.yml",
            "vendor/kept/action.yml",
        }
        assert {p.relative_to(root).as_posix() for p in paths} == {
            ".github/workflows/ci.yml",
            "examples/caller.yaml",
            "vendor/kept/action.yml",
            "vendor/kept/examples/k.yaml",
        }
        beneath = [
            path
            for path in judged
            for ignored in (root / "node_modules", root / "vendor" / "drop")
            if path != ignored and path.is_relative_to(ignored)
        ]
        assert beneath == []

    def test_a_pruned_glob_expands_exactly_as_path_glob_does(
        self,
        tmp_path: Path,
        lock: Callable[..., None],
    ) -> None:
        """With nothing ignored, the expansion is ``Path.glob``'s own.

        ``**`` enters hidden directories and does not follow links to
        directories, on every supported version; a directory that can be
        searched but not listed is still a place a literal name matches,
        and one that cannot be searched at all is passed over. Each match
        is produced once, however many ``**`` reach it.
        """
        root = (tmp_path / "plain").resolve()
        for rel in (
            "x.yml",
            "a/x.yml",
            "a/b/c/x.yml",
            ".hidden/x.yml",
            "real/x.yml",
            "search/x.yml",
        ):
            _write(root / rel, WORKFLOW)
        (root / "dirlink").symlink_to(root / "real")
        (root / "a" / "loop").symlink_to(root / "a")
        (root / "locked").mkdir()
        lock(root / "search", 0o111)
        lock(root / "locked")
        scope = IgnoreScope(IgnoreIndex(30), root)

        for pattern in (
            "**/x.yml",
            "a/**/x.yml",
            "*/**/x.yml",
            "**/**/x.yml",
            "**/c/x.yml",
            "**/search/x.yml",
            "dirlink/**/x.yml",
            "**/../x.yml",
            "*/../**/x.yml",
            "a/**",
        ):
            ours = list(scope.glob(root, pattern))
            assert len(ours) == len(set(ours)), pattern
            assert sorted(ours) == sorted(set(root.glob(pattern))), pattern

    def test_a_named_ignored_root_is_honoured_in_another_case(
        self, tmp_path: Path, scanner: WorkflowScanner
    ) -> None:
        """Where git folds case, so does the named-root exemption.

        The lookup matched ``NODE_MODULES`` to the ignored directory, but
        the exemption for a root named on purpose compared paths with
        case, so a glob spelling the named root otherwise was dropped.
        """
        root = _repository(tmp_path / "repo")
        if not (root / "NODE_MODULES").exists():
            pytest.skip("the filesystem tells case apart")
        package = root.resolve() / "node_modules" / "pkg"
        pattern = f"{root.resolve().as_posix()}/NODE_MODULES/pkg/.github/workflows/*.yml"

        found = scanner.resolve_specific_files(package, [pattern])

        assert [p.name for p in found] == ["ci.yml"]

    def test_a_literal_files_path_is_honoured_even_when_ignored(
        self, tmp_path: Path, scanner: WorkflowScanner
    ) -> None:
        """Naming one file is explicit intent, as naming a root is."""
        root = _repository(tmp_path / "repo")
        target = "node_modules/pkg/.github/workflows/ci.yml"

        found = scanner.resolve_specific_files(root, [target])

        assert [p.relative_to(root).as_posix() for p in found] == [target]

    def test_allow_list_extra_globs_leave_out_ignored_files(
        self, tmp_path: Path, scanner: WorkflowScanner
    ) -> None:
        """``allow-list: update`` rewrites what ``extra_globs`` returns."""
        root = _repository(tmp_path / "repo")
        _write(root / "examples" / "caller.yaml", WORKFLOW)
        _write(root / "node_modules" / "pkg" / "examples" / "x.yaml", WORKFLOW)
        config = Config()
        config.allow_list.extra_globs = ["**/examples/*.yaml"]

        paths = _allow_list_paths(config, CLIOptions(path=root), scanner)

        assert {p.relative_to(root).as_posix() for p in paths} == {
            ".github/workflows/ci.yml",
            "examples/caller.yaml",
        }

    def test_an_extra_glob_escaping_the_root_is_judged_by_its_repository(
        self, tmp_path: Path, scanner: WorkflowScanner
    ) -> None:
        """A glob reaching above the root still leaves out ignored files.

        Scanning ``sub/``, ``../node_modules/**`` lands in the enclosing
        repository's ignored directory, which a listing of ``sub/`` alone
        does not cover.
        """
        root = _repository(tmp_path / "repo")
        _write(root / "sub" / ".github" / "workflows" / "ci.yml", WORKFLOW)
        _write(root / "node_modules" / "pkg" / "examples" / "x.yaml", WORKFLOW)
        config = Config()
        config.allow_list.extra_globs = ["../node_modules/**/*.yaml"]
        sub = root / "sub"

        paths = _allow_list_paths(config, CLIOptions(path=sub), scanner)

        assert [p.relative_to(sub).as_posix() for p in paths] == [
            ".github/workflows/ci.yml"
        ]

    def test_a_glob_spelled_through_a_link_is_judged_as_resolved(
        self, tmp_path: Path, scanner: WorkflowScanner
    ) -> None:
        """Two spellings of one directory compare as the same path.

        The command resolves its root, so a glob naming the same tree
        through a symbolic link used to fall outside it, escape the
        check, and select the dependency's workflow.
        """
        root = _repository(tmp_path / "real" / "repo")
        (tmp_path / "alias").symlink_to(tmp_path / "real")
        through_link = tmp_path / "alias" / "repo"
        pattern = f"{through_link}/node_modules/pkg/.github/workflows/*.yml"

        found = scanner.resolve_specific_files(root.resolve(), [pattern])

        assert found == []

    def test_a_glob_into_a_nested_repository_inside_an_ignored_directory(
        self, tmp_path: Path, scanner: WorkflowScanner
    ) -> None:
        """A repository installed into ``node_modules`` is still ignored.

        A dependency installed from git keeps its own ``.git``, and does
        not ignore its own workflows. The enclosing repository does, so
        the answer has to come from further out.
        """
        root = _repository(tmp_path / "repo")
        dependency = root / "node_modules" / "gitdep"
        _write(dependency / ".github" / "workflows" / "ci.yml", WORKFLOW)
        _git(dependency, "init", "-q")

        found = scanner.resolve_specific_files(
            root, ["node_modules/gitdep/.github/workflows/*.yml"]
        )

        assert found == []

    def test_a_nested_repository_reached_through_a_link_is_judged_resolved(
        self, tmp_path: Path, scanner: WorkflowScanner
    ) -> None:
        """The search outward compares canonical paths.

        Spelled through a link, the nested repository's path never
        matched the resolved scan root, so the search stopped before
        reaching the repository that ignores it.
        """
        root = _repository(tmp_path / "real" / "repo")
        dependency = root / "node_modules" / "gitdep"
        _write(dependency / ".github" / "workflows" / "ci.yml", WORKFLOW)
        _git(dependency, "init", "-q")
        (tmp_path / "alias").symlink_to(tmp_path / "real")
        linked = tmp_path / "alias" / "repo" / "node_modules" / "gitdep"
        pattern = f"{linked}/.github/workflows/*.yml"

        found = scanner.resolve_specific_files(root.resolve(), [pattern])

        assert found == []

    def test_a_sibling_repository_is_not_judged_by_an_enclosing_one(
        self, tmp_path: Path, scanner: WorkflowScanner
    ) -> None:
        """A glob escaping to a sibling repository keeps its own rules.

        Under a home directory kept as a repository that ignores ``*``,
        the sibling itself ignores nothing; consulting the home
        repository as well would drop its file.
        """
        home = tmp_path / "home"
        home.mkdir()
        _git(home, "init", "-q")
        _write(home / ".gitignore", "*\n")
        root = _repository(home / "project")
        other = _repository(home / "other")
        _write(other / "examples" / "caller.yaml", WORKFLOW)
        config = Config()
        config.allow_list.extra_globs = ["../other/examples/*.yaml"]

        paths = _allow_list_paths(config, CLIOptions(path=root), scanner)

        assert (root / ".." / "other" / "examples" / "caller.yaml") in paths

    def test_a_sibling_repository_s_own_ignores_still_apply(
        self, tmp_path: Path, scanner: WorkflowScanner
    ) -> None:
        """A glob leaving the scan repository is judged where it lands.

        Skipping every repository but the scan root's let a glob into a
        sibling, through ``..`` or a link, select what the sibling
        ignores, and fixes could then rewrite it.
        """
        home = tmp_path / "home"
        home.mkdir()
        root = _repository(home / "project")
        other = _repository(home / "other")
        dependency = other / "node_modules" / "gitdep"
        _write(dependency / "examples" / "x.yaml", WORKFLOW)
        _git(dependency, "init", "-q")
        (root / "linked").symlink_to(other)
        config = Config()
        config.allow_list.extra_globs = [
            "../other/node_modules/gitdep/examples/*.yaml",
            "linked/node_modules/gitdep/examples/*.yaml",
        ]

        paths = _allow_list_paths(config, CLIOptions(path=root), scanner)

        assert [p.relative_to(root).as_posix() for p in paths] == [
            ".github/workflows/ci.yml"
        ]

    def test_a_container_root_does_not_switch_filtering_off(
        self, tmp_path: Path, scanner: WorkflowScanner
    ) -> None:
        """A root no repository owns is not an ignored root named on purpose.

        The exemption for a named ignored root once also fired when no
        repository owned the root at all, so a container of repositories
        let every glob keep what those repositories ignore.
        """
        container = tmp_path / "container"
        repo = _repository(container / "repo")
        dependency = repo / "node_modules" / "gitdep"
        _write(dependency / ".github" / "workflows" / "ci.yml", WORKFLOW)
        _git(dependency, "init", "-q")

        found = scanner.resolve_specific_files(
            container,
            [
                "repo/node_modules/gitdep/.github/workflows/*.yml",
                "repo/node_modules/pkg/.github/workflows/*.yml",
                "repo/.github/workflows/*.yml",
            ],
        )

        assert [p.relative_to(container).as_posix() for p in found] == [
            "repo/.github/workflows/ci.yml"
        ]

    def test_a_repository_inside_a_named_ignored_root_keeps_its_rules(
        self, tmp_path: Path, scanner: WorkflowScanner
    ) -> None:
        """Naming an ignored root exempts only the rules that ignore it.

        The root's own repository ignores it; a repository installed
        inside it has rules of its own, which still apply.
        """
        root = _repository(tmp_path / "repo")
        package = root / "node_modules" / "pkg"
        nested = package / "vendored"
        _write(nested / ".gitignore", "generated/\n")
        _write(
            nested / "generated" / ".github" / "workflows" / "g.yml", WORKFLOW
        )
        _write(nested / ".github" / "workflows" / "own.yml", WORKFLOW)
        _git(nested, "init", "-q")

        found = scanner.resolve_specific_files(
            package,
            [
                "vendored/generated/.github/workflows/*.yml",
                "vendored/.github/workflows/*.yml",
                ".github/workflows/*.yml",
            ],
        )

        assert sorted(p.relative_to(package).as_posix() for p in found) == [
            ".github/workflows/ci.yml",
            "vendored/.github/workflows/own.yml",
        ]

    def test_an_enclosing_repository_above_the_root_is_not_consulted(
        self, tmp_path: Path, scanner: WorkflowScanner
    ) -> None:
        """A home directory kept as a repository cannot hide the scan.

        Dotfile repositories often ignore ``*``. Judging paths by every
        enclosing repository would then drop every workflow beneath, so
        the search stops at the scan root's own repository.
        """
        home = tmp_path / "home"
        home.mkdir()
        _git(home, "init", "-q")
        _write(home / ".gitignore", "*\n")
        root = _repository(home / "project")
        _write(root / "examples" / "caller.yaml", WORKFLOW)
        config = Config()

        paths = _allow_list_paths(config, CLIOptions(path=root), scanner)

        assert {p.relative_to(root).as_posix() for p in paths} == {
            ".github/workflows/ci.yml",
            "examples/caller.yaml",
        }

    def test_an_enclosing_repository_in_another_case_is_not_consulted(
        self, tmp_path: Path, scanner: WorkflowScanner
    ) -> None:
        """Where git folds case, so does the guard against enclosing ones.

        A glob spelling the home directory ``HOME`` reaches the scan's
        repository through a path that compared unequal to the root's, so
        the home repository, ignoring ``*``, was consulted and hid it.
        """
        home = tmp_path / "home"
        home.mkdir()
        if not (tmp_path / "HOME").exists():
            pytest.skip("the filesystem tells case apart")
        _git(home, "init", "-q")
        _write(home / ".gitignore", "*\n")
        root = _repository(home / "project").resolve()
        pattern = f"{root.parent.parent.as_posix()}/HOME/project/.github/workflows/*.yml"

        found = scanner.resolve_specific_files(root, [pattern])

        assert [p.name for p in found] == ["ci.yml"]


@pytest.fixture
def run_real_git(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Answer ``ls-remote`` locally and let local git reach the binary.

    ``mock_git_commands`` answers every git command with exit 0 and no
    output. For the ignored listing that reads as "nothing ignored", so
    an end-to-end test built on it alone would pass while exercising
    none of the fix. This keeps its ``ls-remote`` answers for validation
    and hands every other command to ``subprocess.run`` as the network
    guard left it.

    Args:
        monkeypatch: Used to wrap ``subprocess.run``.
    """
    guarded = subprocess.run
    sha = SHA_ANSWERING_EVERY_LOOKUP

    def route(*args: Any, **kwargs: Any) -> Any:
        """Answer ``ls-remote``; pass anything else to the guarded run.

        Args:
            args: Positional arguments as ``subprocess.run`` takes them.
            kwargs: Keyword arguments, passed through.

        Returns:
            The completed process.
        """
        cmd = args[0] if args else kwargs.get("args", [])
        if isinstance(cmd, list) and "ls-remote" in cmd:
            text = bool(kwargs.get("text") or kwargs.get("universal_newlines"))
            requested = cmd[-1]
            out = f"{sha}\trefs/heads/main\n{sha}\t{requested}\n"
            return subprocess.CompletedProcess(
                cmd, 0, out if text else out.encode(), "" if text else b""
            )
        return guarded(*args, **kwargs)

    monkeypatch.setattr(subprocess, "run", route)


class TestIgnoredFilesAreNeverRewritten:
    """The issue's headline, through the command a hook runs."""

    def test_lint_fixes_ours_and_leaves_the_dependency_alone(
        self,
        tmp_path: Path,
        run_real_git: None,
        no_repository_redirect: None,
    ) -> None:
        """``lint .`` with fixes rewrites our workflow, not ``node_modules``.

        Asserting our own workflow *was* rewritten is the control: without
        it, a run that fixed nothing at all would pass this test too.
        """
        root = _repository(tmp_path / "repo")
        ours = root / ".github" / "workflows" / "ci.yml"
        theirs = (
            root / "node_modules" / "pkg" / ".github" / "workflows" / "ci.yml"
        )
        action = root / "node_modules" / "pkg2" / "action.yml"

        async def latest(keys: list[str]) -> dict[str, tuple[str, str]]:
            """Answer a fixed newer release for every repository.

            Args:
                keys: Repositories the fixer asked about.

            Returns:
                A version and SHA for each.
            """
            return dict.fromkeys(keys, ("v9.9.9", SHA_ANSWERING_EVERY_LOOKUP))

        async def shas(refs: dict[str, str]) -> dict[str, str]:
            """Resolve every reference to the stand-in SHA.

            Args:
                refs: Mapping of repository to reference.

            Returns:
                A SHA for each key.
            """
            return dict.fromkeys(refs, SHA_ANSWERING_EVERY_LOOKUP)

        with (
            patch.object(
                AutoFixer, "_get_latest_versions_batch", side_effect=latest
            ),
            patch.object(AutoFixer, "_get_shas_batch", side_effect=shas),
        ):
            result = CliRunner().invoke(
                app, ["lint", str(root), "--no-cache", "--auto-fix"]
            )

        assert "actions/checkout@v4" not in ours.read_text(), result.output
        assert theirs.read_text() == WORKFLOW
        assert action.read_text() == ACTION
        assert "node_modules" not in result.output
