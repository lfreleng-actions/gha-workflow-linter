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

import os
import subprocess
from typing import TYPE_CHECKING, Any
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from gha_workflow_linter.action_call_fix import AutoFixer
from gha_workflow_linter.cli import _allow_list_paths, app
from gha_workflow_linter.models import CLIOptions, Config
from gha_workflow_linter.scanner import WorkflowScanner
from tests.conftest import SHA_ANSWERING_EVERY_LOOKUP

if TYPE_CHECKING:
    from pathlib import Path

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

    @pytest.mark.xfail(strict=True, reason="issue #378")
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

    @pytest.mark.xfail(strict=True, reason="issue #378")
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


class TestTheOwningRepositoryAnswers:
    """Git is asked about the scanned repository, whatever it inherits."""

    @pytest.mark.xfail(strict=True, reason="issue #378")
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

    @pytest.mark.xfail(strict=True, reason="issue #378")
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

    def test_a_literal_files_path_is_honoured_even_when_ignored(
        self, tmp_path: Path, scanner: WorkflowScanner
    ) -> None:
        """Naming one file is explicit intent, as naming a root is."""
        root = _repository(tmp_path / "repo")
        target = "node_modules/pkg/.github/workflows/ci.yml"

        found = scanner.resolve_specific_files(root, [target])

        assert [p.relative_to(root).as_posix() for p in found] == [target]

    @pytest.mark.xfail(strict=True, reason="issue #378")
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


@pytest.fixture
def run_real_git(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Answer ``ls-remote`` locally and let local git reach the binary.

    ``mock_git_commands`` answers every git command with exit 0 and no
    output. For ``check-ignore -q .`` that reads as "the scan root is
    ignored", which switches the filter off, so an end-to-end test built
    on it alone would pass while exercising none of the fix. This keeps
    its ``ls-remote`` answers for validation and hands every other
    command to ``subprocess.run`` as the network guard left it.

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

    @pytest.mark.xfail(strict=True, reason="issue #378")
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
