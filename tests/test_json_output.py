# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""``--json-output``: one run, read by a person and a program alike.

The Action needs both a readable log and machine-readable outputs. It
used to get them by running the linter twice, once per format. Under a
fixing mode the second run examined a tree the first had repaired, so
its outputs reported zero errors for exactly what had been fixed. These
tests hold the option to the promise that removes the second run: the
file receives the document of *this* run, on every path that emits one.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
import stat
import threading
from typing import TYPE_CHECKING, Any

import pytest
from typer.testing import CliRunner

from gha_workflow_linter import cli, exit_codes
from gha_workflow_linter.check_modes import CheckMode
from gha_workflow_linter.cli import _DocumentSink, _vet_json_output, app
from gha_workflow_linter.exceptions import ConfigurationError
from gha_workflow_linter.models import CLIOptions, Config
from gha_workflow_linter.scanner import WorkflowScanner

if TYPE_CHECKING:
    from collections.abc import Iterator

BROKEN = """name: Test
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: nonexistent/action@v1
"""


def _workspace(root: Path, workflow: str = BROKEN) -> Path:
    """Write one workflow.

    Args:
        root: Directory to build the repository layout under.
        workflow: The workflow's contents.

    Returns:
        The directory to point the linter at.
    """
    path = root / ".github" / "workflows" / "test.yaml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(workflow, encoding="utf-8")
    return root


def _read(path: Path) -> Any:
    """Parse the document the run wrote.

    Args:
        path: The ``--json-output`` file.

    Returns:
        The document.
    """
    return json.loads(path.read_text(encoding="utf-8"))


def _said(result: Any) -> str:
    """Collapse a run's output, which Rich wraps to the terminal width.

    Args:
        result: The CliRunner result.

    Returns:
        Its output on one line.
    """
    return " ".join(result.output.split())


@pytest.mark.usefixtures("mock_git_commands")
class TestTheFileDescribesThisRun:
    """Whatever ``--format`` prints, the file holds the run's document."""

    def test_text_mode_writes_the_document_beside_the_text(
        self, temp_dir: Path
    ) -> None:
        """The reader's findings and the file's must be the same ones.

        Args:
            temp_dir: Scratch directory for the workspace and document.
        """
        document = temp_dir / "document.json"

        result = CliRunner().invoke(
            app,
            [
                "lint",
                str(_workspace(temp_dir / "repo")),
                "--action-calls",
                "report",
                "--allow-list",
                "off",
                "--validation-method",
                "git",
                "--json-output",
                str(document),
            ],
        )

        written = _read(document)
        assert result.exit_code == exit_codes.DEFECTS_FOUND, result.output
        assert written["validation_summary"]["total_errors"] == 1
        assert written["errors"][0]["repository"] == "action"
        # Standard output stays the reader's: no document mixed into it.
        assert "nonexistent/action" in result.stdout
        assert '"validation_summary"' not in result.stdout

    def test_json_mode_prints_and_writes_the_same_document(
        self, temp_dir: Path
    ) -> None:
        """Args:
        temp_dir: Scratch directory for the workspace and document.
        """
        document = temp_dir / "document.json"

        result = CliRunner().invoke(
            app,
            [
                "lint",
                str(_workspace(temp_dir / "repo")),
                "--action-calls",
                "report",
                "--allow-list",
                "off",
                "--validation-method",
                "git",
                "--format",
                "json",
                "--json-output",
                str(document),
            ],
        )

        assert json.loads(result.stdout) == _read(document)

    def test_a_scan_with_nothing_to_check_still_writes(
        self, temp_dir: Path
    ) -> None:
        """The short circuit owes the file a document too.

        Args:
            temp_dir: An empty repository, so the scan finds nothing.
        """
        document = temp_dir / "document.json"
        (temp_dir / "repo").mkdir()

        CliRunner().invoke(
            app,
            [
                "lint",
                str(temp_dir / "repo"),
                "--allow-list",
                "off",
                "--json-output",
                str(document),
            ],
        )

        assert _read(document)["scan_summary"]["total_calls"] == 0


class TestSetupFailuresStillWrite:
    """A refused run is when a consumer most needs to know why."""

    def test_a_configuration_error(self, temp_dir: Path) -> None:
        """``--allow-list fix`` is refused while settling the modes.

        Args:
            temp_dir: Scratch directory for the workspace and document.
        """
        document = temp_dir / "document.json"
        (temp_dir / "repo").mkdir()

        result = CliRunner().invoke(
            app,
            [
                "lint",
                str(temp_dir / "repo"),
                "--allow-list",
                "fix",
                "--json-output",
                str(document),
            ],
        )

        assert result.exit_code == exit_codes.RUNTIME_ERROR
        assert "Configuration error" in _read(document)["error"]

    def test_an_invalid_option_is_reported_in_the_file(
        self, temp_dir: Path
    ) -> None:
        """Option validation must not abort before the path is vetted.

        Args:
            temp_dir: Scratch directory for the workspace and document.
        """
        (temp_dir / "repo").mkdir()
        document = temp_dir / "document.json"

        result = CliRunner().invoke(
            app,
            [
                "lint",
                str(temp_dir / "repo"),
                "--format",
                "invalid",
                "--json-output",
                str(document),
            ],
        )

        assert result.exit_code == exit_codes.RUNTIME_ERROR
        assert "Configuration error" in _read(document)["error"]

    def test_files_with_a_sweep_is_reported_in_the_file(
        self, temp_dir: Path
    ) -> None:
        """Refused after the path is vetted, so the file is owed the reason.

        Args:
            temp_dir: Scratch directory for the container and document.
        """
        (temp_dir / "container").mkdir()
        document = temp_dir / "document.json"

        result = CliRunner().invoke(
            app,
            [
                "lint",
                str(temp_dir / "container"),
                "--multi-repo",
                "--files",
                "x.yaml",
                "--json-output",
                str(document),
            ],
        )

        assert result.exit_code == exit_codes.RUNTIME_ERROR
        assert "--files" in _read(document)["error"]

    def test_conflicting_verbosity_leaves_the_file_alone(
        self, temp_dir: Path
    ) -> None:
        """Refused before the configuration loads, so nothing is vetted.

        What the run reads is decided by its configuration. Until that
        is known the path cannot be shown safe, so nothing -- not even
        the refusal's document -- is written to it.

        Args:
            temp_dir: Scratch directory for the document.
        """
        document = temp_dir / "document.json"

        result = CliRunner().invoke(
            app,
            [
                "lint",
                str(temp_dir),
                "--verbose",
                "--quiet",
                "--json-output",
                str(document),
            ],
        )

        assert result.exit_code == exit_codes.RUNTIME_ERROR
        assert "cannot be used together" in result.output
        assert not document.exists()

    def test_an_unwritable_path_is_refused_up_front(
        self, temp_dir: Path
    ) -> None:
        """Before any scanning or network call, and saying which path.

        Args:
            temp_dir: Scratch directory lacking the named parent.
        """
        document = temp_dir / "missing" / "document.json"

        result = CliRunner().invoke(
            app,
            [
                "lint",
                str(_workspace(temp_dir / "repo")),
                "--action-calls",
                "off",
                "--allow-list",
                "off",
                "--json-output",
                str(document),
            ],
        )

        assert result.exit_code == exit_codes.RUNTIME_ERROR
        # Refused while configuring, not discovered after the whole run.
        assert "Refusing --json-output" in _said(result)
        assert "its directory does not exist" in _said(result)
        assert not document.exists()


class TestSweepsWriteOneDocument:
    """``--multi-repo`` assembles one document, in either format."""

    def test_text_mode(self, temp_dir: Path) -> None:
        """Args:
        temp_dir: Container holding two repositories.
        """
        for name in ("one", "two"):
            repository = _workspace(temp_dir / "container" / name)
            (repository / ".git").mkdir()
        document = temp_dir / "document.json"

        result = CliRunner().invoke(
            app,
            [
                "lint",
                str(temp_dir / "container"),
                "--multi-repo",
                "--action-calls",
                "off",
                "--allow-list",
                "off",
                "--json-output",
                str(document),
            ],
        )

        written = _read(document)
        assert result.exit_code == exit_codes.SUCCESS, result.output
        assert [r["repository"] for r in written["repositories"]] == [
            "one",
            "two",
        ]
        assert all(r["results"] for r in written["repositories"])
        assert written["summary"]["exit_code"] == exit_codes.SUCCESS

    def test_an_empty_sweep(self, temp_dir: Path) -> None:
        """Args:
        temp_dir: Container holding no repositories.
        """
        (temp_dir / "container").mkdir()
        document = temp_dir / "document.json"

        CliRunner().invoke(
            app,
            [
                "lint",
                str(temp_dir / "container"),
                "--multi-repo",
                "--json-output",
                str(document),
            ],
        )

        assert _read(document)["summary"]["repositories"] == 0


class TestTheFileCannotMislead:
    """A document in the file must be this run's, or nothing."""

    def test_nothing_is_written_before_the_run_has_read(
        self, temp_dir: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The document is published once, after every input is read.

        Emptying the file up front, to rule out a stale document, was
        itself a write before the scan -- and whatever the path turned
        out to alias became an altered input. The earlier file stays
        until the run publishes; the exit status says whose it is.

        Args:
            temp_dir: Scratch directory for the workspace and document.
            monkeypatch: Used to look at the file while the run is going.
        """
        (temp_dir / "repo").mkdir()
        document = temp_dir / "document.json"
        document.write_text("earlier", encoding="utf-8")
        seen: list[str] = []

        def looks(*_args: object, **_kwargs: object) -> int:
            seen.append(document.read_text(encoding="utf-8"))
            return exit_codes.SUCCESS

        monkeypatch.setattr(cli, "run_linter", looks)

        CliRunner().invoke(
            app,
            ["lint", str(temp_dir / "repo"), "--json-output", str(document)],
        )

        assert seen == ["earlier"]

    def test_claiming_an_unwritable_path_is_a_configuration_error(
        self, temp_dir: Path
    ) -> None:
        """Args:
        temp_dir: Scratch directory lacking the named parent.
        """
        with pytest.raises(ConfigurationError, match="--json-output"):
            _vet_json_output(
                Config(),
                CLIOptions(
                    path=temp_dir,
                    json_output=temp_dir / "missing" / "document.json",
                ),
            )

    def test_a_late_write_failure_is_raised(self, temp_dir: Path) -> None:
        """Swallowed, the run would exit clean with its document lost.

        Args:
            temp_dir: A directory, which cannot be written as a file.
        """
        sink = _DocumentSink(to_stdout=False, path=temp_dir)

        with pytest.raises(OSError, match="--json-output"):
            sink.publish({})

    def test_no_file_and_no_json_wants_nothing(self) -> None:
        assert not _DocumentSink.of("text", None).wanted


class TestTheFileIsNeverAnInput:
    """Writing the document must not destroy or alter what is scanned.

    The document is published once, after the run has read everything,
    so it cannot change an input before it is read. These tests hold the
    other half: the published file must not land on an input either --
    a named ``action.yaml``, a workflow, or the repository's ``.git``.
    """

    @staticmethod
    def _lint(*args: str) -> Any:
        """Invoke ``lint`` with both checks off, so nothing is fetched.

        Args:
            args: Arguments after the check modes.

        Returns:
            The CliRunner result.
        """
        return CliRunner().invoke(
            app,
            ["lint", "--action-calls", "off", "--allow-list", "off", *args],
        )

    @pytest.mark.parametrize("name", ["action.yaml", "action.yml", "A.YML"])
    def test_an_existing_yaml_file_is_left_intact(
        self, temp_dir: Path, name: str
    ) -> None:
        """Args:
        temp_dir: Scratch directory holding the file.
        name: The input the caller named as the output.
        """
        target = temp_dir / name
        target.write_text(BROKEN, encoding="utf-8")

        result = self._lint(str(temp_dir), "--json-output", str(target))

        assert result.exit_code == exit_codes.RUNTIME_ERROR
        assert "Refusing --json-output" in result.output
        assert target.read_text(encoding="utf-8") == BROKEN

    def test_no_workflow_file_is_created(self, temp_dir: Path) -> None:
        """Args:
        temp_dir: Scratch directory for the workspace.
        """
        workspace = _workspace(temp_dir / "repo")
        target = workspace / ".github" / "workflows" / "out.yaml"

        result = self._lint(str(workspace), "--json-output", str(target))

        assert result.exit_code == exit_codes.RUNTIME_ERROR
        assert not target.exists()

    def test_the_config_file_is_left_intact_whatever_its_name(
        self, temp_dir: Path
    ) -> None:
        """Args:
        temp_dir: Scratch directory holding the configuration.
        """
        config = temp_dir / "linter.cfg"
        config.write_text("log_level: INFO\n", encoding="utf-8")

        result = self._lint(
            str(temp_dir),
            "--config",
            str(config),
            "--json-output",
            str(config),
        )

        assert result.exit_code == exit_codes.RUNTIME_ERROR
        assert "--config file" in result.output
        assert config.read_text(encoding="utf-8") == "log_level: INFO\n"

    def test_a_directory_still_gets_the_json_document(
        self, temp_dir: Path
    ) -> None:
        """Refused as configuration, not as a Click usage error.

        A usage error exits 2 before the command runs, so a ``--format
        json`` consumer got no document to read the reason from.

        Args:
            temp_dir: A directory, named as the output.
        """
        result = self._lint(
            str(temp_dir), "--format", "json", "--json-output", str(temp_dir)
        )

        assert result.exit_code == exit_codes.RUNTIME_ERROR
        assert "it is a directory" in json.loads(result.stdout)["error"]

    @pytest.mark.parametrize(
        "relative",
        [".github/workflows/out.json", "results.json", ".git", ".git/config"],
        ids=["beside-workflows", "repo-root", "worktree-pointer", "git-config"],
    )
    def test_nothing_inside_the_linted_repository(
        self, temp_dir: Path, relative: str
    ) -> None:
        """The repository is out of bounds as a whole, ``.git`` included.

        Enumerating its inputs missed a new kind each time: a worktree's
        ``.git`` is a file, and ``.git/config`` holds the remotes the
        allow-list infers its organisation from.

        Args:
            temp_dir: Scratch directory for the repository.
            relative: Where in the repository the output is aimed.
        """
        workspace = _workspace(temp_dir / "repo")
        if relative == ".git":
            (workspace / ".git").write_text(
                "gitdir: /elsewhere\n", encoding="utf-8"
            )
        else:
            (workspace / ".git").mkdir()
            (workspace / ".git" / "config").write_text(
                "[core]\n", encoding="utf-8"
            )
        target = workspace / relative
        before = target.read_bytes() if target.is_file() else None

        result = self._lint(str(workspace), "--json-output", str(target))

        assert result.exit_code == exit_codes.RUNTIME_ERROR
        assert "which the run reads" in _said(result)
        assert (target.read_bytes() if target.is_file() else None) == before

    def test_the_enclosing_repository_when_a_subdirectory_is_linted(
        self, temp_dir: Path
    ) -> None:
        """Scanning part of a repository still guards all of it.

        Args:
            temp_dir: Scratch directory for the repository.
        """
        workspace = _workspace(temp_dir / "repo")
        (workspace / ".git").mkdir()
        (workspace / "sub").mkdir()
        target = workspace / "results.json"

        result = self._lint(
            str(workspace / "sub"), "--json-output", str(target)
        )

        assert result.exit_code == exit_codes.RUNTIME_ERROR
        assert "which the run reads" in _said(result)
        assert not target.exists()

    @staticmethod
    def _worktree(root: Path, *, absolute: bool) -> tuple[Path, Path]:
        """Lay out a main checkout and a linked worktree, as Git does.

        Written as files rather than by ``git worktree``: the layout is
        the contract, and it is the same one Git writes.

        Args:
            root: Directory to hold both.
            absolute: Whether the ``.git`` file names its gitdir by an
                absolute path rather than a relative one.

        Returns:
            The worktree, and the main checkout's ``.git`` directory.
        """
        common = root / "main" / ".git"
        gitdir = common / "worktrees" / "wt"
        gitdir.mkdir(parents=True)
        (common / "config").write_text("[remote]\n", encoding="utf-8")
        (gitdir / "commondir").write_text("../..\n", encoding="utf-8")
        worktree = _workspace(root / "wt")
        pointer = gitdir if absolute else "../main/.git/worktrees/wt"
        (worktree / ".git").write_text(f"gitdir: {pointer}\n", encoding="utf-8")
        return worktree, common

    @pytest.mark.parametrize("absolute", [False, True])
    @pytest.mark.parametrize(
        "relative",
        ["config", "worktrees/wt/state.json"],
        ids=["common", "gitdir"],
    )
    def test_a_worktrees_external_git_metadata(
        self, temp_dir: Path, absolute: bool, relative: str
    ) -> None:
        """The gitdir a ``.git`` file names, and its ``commondir``.

        ``git -C <worktree> remote get-url`` reads the main checkout's
        ``.git/config`` through them, although neither lies inside the
        worktree.

        Args:
            temp_dir: Scratch directory for both checkouts.
            absolute: Whether the ``.git`` file's path is absolute.
            relative: Where under the main ``.git`` the output is aimed.
        """
        worktree, common = self._worktree(temp_dir, absolute=absolute)
        target = common / relative
        before = target.read_bytes() if target.exists() else None

        result = self._lint(str(worktree), "--json-output", str(target))

        assert result.exit_code == exit_codes.RUNTIME_ERROR
        assert "which the run reads" in _said(result)
        assert (target.read_bytes() if target.exists() else None) == before

    def test_a_submodules_gitdir(self, temp_dir: Path) -> None:
        """A submodule's gitdir has no ``commondir`` to lead to it.

        Args:
            temp_dir: Scratch directory for both checkouts.
        """
        gitdir = temp_dir / "super" / ".git" / "modules" / "sub"
        gitdir.mkdir(parents=True)
        (gitdir / "config").write_text("[remote]\n", encoding="utf-8")
        submodule = _workspace(temp_dir / "checkout" / "sub")
        (submodule / ".git").write_text(f"gitdir: {gitdir}\n", encoding="utf-8")
        target = gitdir / "config"

        result = self._lint(str(submodule), "--json-output", str(target))

        assert result.exit_code == exit_codes.RUNTIME_ERROR
        assert "which the run reads" in _said(result)
        assert target.read_text(encoding="utf-8") == "[remote]\n"

    def test_a_swept_worktrees_external_git_metadata(
        self, temp_dir: Path
    ) -> None:
        """Each repository a sweep visits brings its own gitdir.

        Args:
            temp_dir: Scratch directory for the container and checkouts.
        """
        container = temp_dir / "container"
        container.mkdir()
        worktree, common = self._worktree(container, absolute=True)
        # Only the worktree is in the container; its main checkout is not.
        outside = temp_dir / "main"
        (container / "main").rename(outside)
        (worktree / ".git").write_text(
            f"gitdir: {outside / '.git' / 'worktrees' / 'wt'}\n",
            encoding="utf-8",
        )
        target = outside / ".git" / "config"

        result = self._lint(
            str(container), "--multi-repo", "--json-output", str(target)
        )

        assert result.exit_code == exit_codes.RUNTIME_ERROR
        assert "which the run reads" in _said(result)
        assert target.read_text(encoding="utf-8") == "[remote]\n"

    def test_a_swept_repository_linked_from_outside(
        self, temp_dir: Path
    ) -> None:
        """Discovery follows a link out of the container; so must this.

        A plain clone keeps its metadata in its own ``.git`` directory,
        so only its resolved root covers ``.git/config``.

        Args:
            temp_dir: Scratch directory for the container and clone.
        """
        clone = _workspace(temp_dir / "outside-clone")
        (clone / ".git").mkdir()
        (clone / ".git" / "config").write_text("[remote]\n", encoding="utf-8")
        container = temp_dir / "container"
        container.mkdir()
        (container / "linked").symlink_to(clone)
        target = clone / ".git" / "config"

        result = self._lint(
            str(container), "--multi-repo", "--json-output", str(target)
        )

        assert result.exit_code == exit_codes.RUNTIME_ERROR
        assert "which the run reads" in _said(result)
        assert target.read_text(encoding="utf-8") == "[remote]\n"

    def test_a_git_dir_naming_a_linked_worktrees_gitdir(
        self, temp_dir: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Git follows that gitdir's ``commondir`` to the common config.

        Only the gitdir itself was protected, so an output aimed at the
        main checkout's ``.git/config`` was accepted.

        Args:
            temp_dir: Scratch directory for both checkouts.
            monkeypatch: Used to set ``GIT_DIR`` for this test alone.
        """
        _, common = self._worktree(temp_dir, absolute=True)
        workspace = _workspace(temp_dir / "repo")
        (workspace / ".git").mkdir()
        monkeypatch.setenv("GIT_DIR", str(common / "worktrees" / "wt"))
        target = common / "config"

        result = self._lint(str(workspace), "--json-output", str(target))

        assert result.exit_code == exit_codes.RUNTIME_ERROR
        assert "which the run reads" in _said(result)
        assert target.read_text(encoding="utf-8") == "[remote]\n"

    def test_a_git_dir_the_environment_names(
        self, temp_dir: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """``GIT_DIR`` redirects every Git probe the run makes.

        Args:
            temp_dir: Scratch directory for the workspace and gitdir.
            monkeypatch: Used to set ``GIT_DIR`` for this test alone.
        """
        workspace = _workspace(temp_dir / "repo")
        gitdir = temp_dir / "elsewhere.git"
        gitdir.mkdir()
        monkeypatch.setenv("GIT_DIR", str(gitdir))
        target = gitdir / "config"

        result = self._lint(str(workspace), "--json-output", str(target))

        assert result.exit_code == exit_codes.RUNTIME_ERROR
        assert not target.exists()

    @pytest.mark.parametrize("with_git_dir", [True, False])
    def test_a_relative_git_common_dir(
        self,
        temp_dir: Path,
        monkeypatch: pytest.MonkeyPatch,
        with_git_dir: bool,
    ) -> None:
        """Git resolves it from the effective Git directory, not the cwd.

        Args:
            temp_dir: Scratch directory for the workspace and gitdirs.
            monkeypatch: Used to set the variables for this test alone.
            with_git_dir: Whether ``GIT_DIR`` names the effective Git
                directory, or the repository's own ``.git`` does.
        """
        workspace = _workspace(temp_dir / "repo")
        (workspace / ".git").mkdir()
        if with_git_dir:
            (temp_dir / "g.git").mkdir()
            monkeypatch.setenv("GIT_DIR", str(temp_dir / "g.git"))
            common = temp_dir / "common"
        else:
            common = workspace / "common"
        common.mkdir()
        monkeypatch.setenv("GIT_COMMON_DIR", "../common")
        target = common / "config"

        result = self._lint(str(workspace), "--json-output", str(target))

        assert result.exit_code == exit_codes.RUNTIME_ERROR
        assert not target.exists()

    @pytest.mark.parametrize("sweep", [False, True])
    def test_a_relative_git_dir_from_where_git_runs(
        self, temp_dir: Path, monkeypatch: pytest.MonkeyPatch, sweep: bool
    ) -> None:
        """``git -C <dir>`` reads a relative ``GIT_DIR`` from ``<dir>``.

        The working directory is the suite's checkout, so only resolving
        from the scanned path -- or, in a sweep, from each repository --
        finds the directory Git reads.

        Args:
            temp_dir: Scratch directory for the workspace and gitdir.
            monkeypatch: Used to set ``GIT_DIR`` for this test alone.
            sweep: Whether the repository is linted by a sweep, whose
                container resolves the value to somewhere else.
        """
        container = temp_dir / "container"
        workspace = _workspace(container / "repo")
        (workspace / ".git").mkdir()
        metadata = temp_dir / "metadata"
        metadata.mkdir()
        monkeypatch.setenv("GIT_DIR", "../../metadata")
        target = metadata / "config"
        args = [str(container), "--multi-repo"] if sweep else [str(workspace)]

        result = self._lint(*args, "--json-output", str(target))

        assert result.exit_code == exit_codes.RUNTIME_ERROR
        assert not target.exists()

    def test_a_relative_git_common_dir_from_a_worktrees_gitdir(
        self, temp_dir: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Without ``GIT_DIR``, the effective gitdir is the one ``.git`` names.

        Args:
            temp_dir: Scratch directory for both checkouts.
            monkeypatch: Used to set ``GIT_COMMON_DIR`` for this test alone.
        """
        worktree, common = self._worktree(temp_dir, absolute=True)
        shared = common / "worktrees" / "shared"
        shared.mkdir()
        monkeypatch.setenv("GIT_COMMON_DIR", "../shared")
        # Outside every tree the other rules protect: only the gitdir-
        # relative reading of GIT_COMMON_DIR can reach it.
        common.rename(temp_dir / "moved")
        gitdir = temp_dir / "moved" / "worktrees" / "wt"
        (gitdir / "commondir").unlink()
        (worktree / ".git").write_text(f"gitdir: {gitdir}\n", encoding="utf-8")
        target = temp_dir / "moved" / "worktrees" / "shared" / "config"

        result = self._lint(str(worktree), "--json-output", str(target))

        assert result.exit_code == exit_codes.RUNTIME_ERROR
        assert not target.exists()

    @pytest.mark.parametrize("sweep", [False, True])
    def test_a_dependabot_config_linked_from_outside(
        self, temp_dir: Path, sweep: bool
    ) -> None:
        """The cooldown lookup reads it, through the link.

        Args:
            temp_dir: Scratch directory for the workspace and target.
            sweep: Whether the repository is linted by a sweep.
        """
        target = temp_dir / "results.cfg"
        target.write_text("version: 2\n", encoding="utf-8")
        container = temp_dir / "container"
        workspace = _workspace(container / "repo")
        (workspace / ".git").mkdir()
        (workspace / ".github" / "dependabot.yml").symlink_to(target)
        args = [str(container), "--multi-repo"] if sweep else [str(workspace)]

        result = self._lint(*args, "--json-output", str(target))

        assert result.exit_code == exit_codes.RUNTIME_ERROR
        assert "through a link" in _said(result)
        assert target.read_text(encoding="utf-8") == "version: 2\n"

    def test_an_auto_discovered_config_linked_from_outside(
        self, temp_dir: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """No ``--config`` names it, yet the run loads it.

        Args:
            temp_dir: Scratch directory for the workspace and target.
            monkeypatch: Used to run from a directory holding a default.
        """
        workspace = _workspace(temp_dir / "repo")
        target = temp_dir / "config.real"
        target.write_text("log_level: INFO\n", encoding="utf-8")
        here = temp_dir / "cwd"
        here.mkdir()
        (here / "gha-workflow-linter.yaml").symlink_to(target)
        monkeypatch.chdir(here)

        result = self._lint(str(workspace), "--json-output", str(target))

        assert result.exit_code == exit_codes.RUNTIME_ERROR
        assert "--config file" in _said(result)
        assert target.read_text(encoding="utf-8") == "log_level: INFO\n"

    def test_vetting_parses_nothing(
        self, temp_dir: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Building the read set must not parse what the run will parse.

        Parsing ahead of the scan doubled the work and every diagnostic
        a malformed file produces.

        Args:
            temp_dir: Scratch directory for the workspace.
            monkeypatch: Used to count parses.
        """
        workspace = _workspace(temp_dir / "repo")
        parsed: list[Path] = []

        def parses(_self: object, path: Path) -> dict[int, object]:
            parsed.append(path)
            return {}

        monkeypatch.setattr(WorkflowScanner, "parse_workflow_file", parses)

        for files in ([".github/workflows/test.yaml"], None):
            found = cli._read_inputs(
                Config(), CLIOptions(path=workspace, files=files)
            )
            assert (
                workspace / ".github" / "workflows" / "test.yaml"
            ).resolve() in found

        assert parsed == []

    def test_silence_is_local_to_the_vetting_context(self) -> None:
        """Another thread's discovery diagnostics are never swallowed.

        ``Logger.disabled`` is process-global. Toggling it muted a run
        in another thread while one vetted, and two overlapping calls
        could leave the loggers disabled for good.
        """
        scanner_logger = logging.getLogger("gha_workflow_linter.scanner")
        records: list[str] = []

        class Records(logging.Handler):
            def emit(self, record: logging.LogRecord) -> None:
                records.append(record.getMessage())

        handler = Records(logging.WARNING)
        scanner_logger.addHandler(handler)
        entered, release = threading.Event(), threading.Event()

        def vets() -> None:
            with cli._discovery_silenced():
                scanner_logger.warning("from vetting")
                entered.set()
                release.wait(timeout=10)

        worker = threading.Thread(target=vets)
        try:
            worker.start()
            assert entered.wait(timeout=10)
            scanner_logger.warning("from the run")
            release.set()
            worker.join(timeout=10)
            scanner_logger.warning("afterwards")
        finally:
            release.set()
            scanner_logger.removeHandler(handler)

        assert records == ["from the run", "afterwards"]
        assert not scanner_logger.disabled

    def test_vetting_reports_nothing_the_run_will_report(
        self, temp_dir: Path
    ) -> None:
        """Each discovery warning appears once, as it does without the option.

        Vetting repeats the run's discovery, and discovery warns about a
        ``--files`` pattern that matches nothing. Every Action run names
        ``--json-output``, so every such warning was printed twice.

        The handler sits on the scanner's own logger: the command
        reconfigures the root logger, which detaches pytest's capture.

        Args:
            temp_dir: Scratch directory for the workspace and document.
        """
        workspace = _workspace(temp_dir / "repo")
        common = [str(workspace), "--files", "missing.yaml"]
        needle = "No workflow or action files found matching patterns"
        records: list[logging.LogRecord] = []

        class Records(logging.Handler):
            def emit(self, record: logging.LogRecord) -> None:
                records.append(record)

        scanner_logger = logging.getLogger("gha_workflow_linter.scanner")
        handler = Records(logging.WARNING)
        scanner_logger.addHandler(handler)

        def warnings() -> int:
            count = sum(needle in r.getMessage() for r in records)
            records.clear()
            return count

        try:
            self._lint(*common)
            without = warnings()
            self._lint(*common, "--json-output", str(temp_dir / "doc.json"))
            with_option = warnings()
        finally:
            scanner_logger.removeHandler(handler)

        assert without >= 1
        assert with_option == without
        assert not scanner_logger.disabled

    def test_a_sweep_reports_an_unreadable_directory_once(
        self, temp_dir: Path
    ) -> None:
        """Repository discovery warns too, and vetting walks it as well.

        Args:
            temp_dir: Holds a container with an unreadable directory.
        """
        container = temp_dir / "container"
        (container / "one" / ".git").mkdir(parents=True)
        locked = container / "locked"
        locked.mkdir()
        locked.chmod(0)
        if os.access(locked, os.R_OK):
            locked.chmod(0o755)
            pytest.skip("running with privileges that ignore permissions")
        records: list[logging.LogRecord] = []

        class Records(logging.Handler):
            def emit(self, record: logging.LogRecord) -> None:
                records.append(record)

        sweep_logger = logging.getLogger("gha_workflow_linter.multi_repo")
        handler = Records(logging.WARNING)
        sweep_logger.addHandler(handler)
        common = [str(container), "--multi-repo", "--repo-depth", "2"]

        def warnings() -> int:
            count = sum("Cannot read" in r.getMessage() for r in records)
            records.clear()
            return count

        try:
            self._lint(*common)
            without = warnings()
            self._lint(*common, "--json-output", str(temp_dir / "doc.json"))
            with_option = warnings()
        finally:
            sweep_logger.removeHandler(handler)
            locked.chmod(0o755)

        assert without >= 1
        assert with_option == without

    def test_an_explicit_file_with_no_action_calls(
        self, temp_dir: Path
    ) -> None:
        """``--files`` reads every selected file, calls or not.

        Discovery through ``scan_directory`` keeps only files that held
        action calls, so this one's target was missing from the set.

        Args:
            temp_dir: Scratch directory for the workspace and target.
        """
        quiet = "name: Quiet\non: [push]\njobs: {}\n"
        target = temp_dir / "results.json"
        target.write_text(quiet, encoding="utf-8")
        workspace = _workspace(temp_dir / "repo")
        (workspace / ".git").mkdir()
        workflows = workspace / ".github" / "workflows"
        (workflows / "quiet.yaml").symlink_to(target)

        result = self._lint(
            str(workspace),
            "--files",
            ".github/workflows/quiet.yaml",
            "--json-output",
            str(target),
        )

        assert result.exit_code == exit_codes.RUNTIME_ERROR
        assert "through a link" in _said(result)
        assert target.read_text(encoding="utf-8") == quiet

    def test_a_refusal_at_the_second_check_writes_nothing(
        self, temp_dir: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """``run_linter`` checks again; its refusal must not be published.

        The command's handler reports configuration errors by writing
        the document to the vetted path. A path the second check refuses
        is no longer one it may write.

        Args:
            temp_dir: Scratch directory for the workspace and target.
            monkeypatch: Used to make the second check refuse.
        """
        workspace = _workspace(temp_dir / "repo")
        target = temp_dir / "results.json"
        target.write_text("keep me\n", encoding="utf-8")
        verdicts = iter([None, "it changed under the run"])
        monkeypatch.setattr(
            cli, "_json_output_refusal", lambda *_args: next(verdicts)
        )

        result = self._lint(str(workspace), "--json-output", str(target))

        assert result.exit_code == exit_codes.RUNTIME_ERROR
        assert "it changed under the run" in _said(result)
        assert target.read_text(encoding="utf-8") == "keep me\n"

    @pytest.mark.parametrize("sweep", [False, True])
    def test_a_workflow_linked_from_outside(
        self, temp_dir: Path, sweep: bool
    ) -> None:
        """Discovery reads through a link; its target is an input.

        The output name is ordinary and lies outside every protected
        tree, so only the resolved read set can see it.

        Args:
            temp_dir: Scratch directory for the workspace and target.
            sweep: Whether the repository is linted by a sweep.
        """
        target = temp_dir / "results.json"
        target.write_text(BROKEN, encoding="utf-8")
        container = temp_dir / "container"
        workspace = container / "repo"
        workflows = workspace / ".github" / "workflows"
        workflows.mkdir(parents=True)
        (workspace / ".git").mkdir()
        (workflows / "check.yaml").symlink_to(target)
        args = [str(container), "--multi-repo"] if sweep else [str(workspace)]

        result = self._lint(*args, "--json-output", str(target))

        assert result.exit_code == exit_codes.RUNTIME_ERROR
        assert "through a link" in _said(result)
        assert target.read_text(encoding="utf-8") == BROKEN

    def test_a_workflow_linked_to_itself_does_not_become_fatal(
        self, temp_dir: Path
    ) -> None:
        """The scan skips an unresolvable file; vetting must too.

        Resolving a link loop raises ``RuntimeError`` before Python 3.13,
        which escaped vetting, so ``--json-output`` turned a run that
        exits cleanly into a fatal one with no document. The other files
        in the repository must still count as read.

        Args:
            temp_dir: Scratch directory for the workspace and document.
        """
        workspace = _workspace(temp_dir / "repo")
        loop = workspace / ".github" / "workflows" / "loop.yaml"
        loop.symlink_to(loop)
        document = temp_dir / "doc.json"

        result = self._lint(str(workspace), "--json-output", str(document))
        found = cli._read_inputs(Config(), CLIOptions(path=workspace))

        assert result.exit_code == exit_codes.SUCCESS, result.output
        assert document.exists()
        assert (
            workspace / ".github" / "workflows" / "test.yaml"
        ).resolve() in found

    @pytest.mark.parametrize(
        "where", ["gitdir", "commondir", "GIT_DIR", "GIT_COMMON_DIR"]
    )
    def test_unresolvable_git_metadata_does_not_become_fatal(
        self, temp_dir: Path, monkeypatch: pytest.MonkeyPatch, where: str
    ) -> None:
        """The run survives a looping gitdir; asking for a document must too.

        ``git remote get-url`` treats such metadata as unavailable. Its
        resolution raised during vetting, so ``--json-output`` turned a
        survivable run into a fatal one with no document. Each case must
        end exactly as the same run without the option does.

        Args:
            temp_dir: Scratch directory for the workspace and loop.
            monkeypatch: Used to set the environment variable cases.
            where: Which piece of Git metadata names the loop.
        """
        workspace = _workspace(temp_dir / "repo")
        loop = temp_dir / "loop"
        loop.symlink_to(loop)
        if where == "gitdir":
            (workspace / ".git").write_text(
                f"gitdir: {loop}\n", encoding="utf-8"
            )
        elif where == "commondir":
            gitdir = temp_dir / "gitdir"
            gitdir.mkdir()
            (gitdir / "commondir").write_text(f"{loop}\n", encoding="utf-8")
            (workspace / ".git").write_text(
                f"gitdir: {gitdir}\n", encoding="utf-8"
            )
        else:
            (workspace / ".git").mkdir()
            monkeypatch.setenv(where, str(loop))
        document = temp_dir / "doc.json"

        without = self._lint(str(workspace))
        result = self._lint(str(workspace), "--json-output", str(document))

        assert result.exit_code == without.exit_code, result.output
        assert document.exists()

    def test_a_parent_that_cannot_resolve_is_a_refusal(
        self, temp_dir: Path
    ) -> None:
        """A link loop above the output is refused, not fatal.

        Resolving it raised, which reached the generic handler, so a
        ``--format json`` caller got no document naming the reason. The
        unwritable-directory check now runs first, and a loop fails it.

        Args:
            temp_dir: Holds a link to itself, named as the directory.
        """
        loop = temp_dir / "loop"
        loop.symlink_to(loop)

        result = self._lint(
            str(_workspace(temp_dir / "repo")),
            "--format",
            "json",
            "--json-output",
            str(loop / "doc.json"),
        )

        assert result.exit_code == exit_codes.RUNTIME_ERROR
        assert "Refusing --json-output" in json.loads(result.stdout)["error"]

    @pytest.mark.parametrize(
        "window", ["_preflight_backend", "_run_one_repository"]
    )
    def test_publication_goes_where_vetting_looked(
        self, temp_dir: Path, monkeypatch: pytest.MonkeyPatch, window: str
    ) -> None:
        """A link above the output, retargeted mid-run, is not followed.

        The run publishes to the directory as it resolved when vetted.
        Following the link again at the end would write wherever it then
        pointed, including into a tree vetting would have refused. Both
        windows count: pre-flight's network calls, between the command's
        vetting and the run's, and the run itself.

        Args:
            temp_dir: Holds the link and the two directories.
            monkeypatch: Used to retarget the link during the run.
            window: The stage during which the link is retargeted.
        """
        vetted, elsewhere = temp_dir / "vetted", temp_dir / "elsewhere"
        vetted.mkdir()
        elsewhere.mkdir()
        link = temp_dir / "out"
        link.symlink_to(vetted)
        original = getattr(cli, window)

        def retargets(*args: Any, **kwargs: Any) -> Any:
            link.unlink()
            link.symlink_to(elsewhere)
            return original(*args, **kwargs)

        monkeypatch.setattr(cli, window, retargets)

        result = self._lint(
            str(_workspace(temp_dir / "repo")),
            "--json-output",
            str(link / "doc.json"),
        )

        assert result.exit_code == exit_codes.SUCCESS, result.output
        assert _read(vetted / "doc.json")["scan_summary"]["total_files"] == 1
        assert not (elsewhere / "doc.json").exists()

    @pytest.mark.parametrize("link", ["symlink", "hardlink"])
    def test_a_link_to_an_input_is_replaced_not_written_through(
        self, temp_dir: Path, link: str
    ) -> None:
        """A JSON name can alias a workflow; the suffix check cannot see it.

        Opening the named path follows a symbolic link and shares a hard
        link's inode, so emptying ``results.json`` would empty the
        workflow behind it before the scan read it.

        Args:
            temp_dir: Scratch directory for the workspace and the link.
            link: Which kind of alias to name as the output.
        """
        workspace = _workspace(temp_dir / "repo")
        workflow = workspace / ".github" / "workflows" / "test.yaml"
        alias = temp_dir / "results.json"
        if link == "symlink":
            alias.symlink_to(workflow)
        else:
            alias.hardlink_to(workflow)

        result = self._lint(str(workspace), "--json-output", str(alias))

        assert result.exit_code == exit_codes.SUCCESS, result.output
        assert workflow.read_text(encoding="utf-8") == BROKEN
        assert not alias.is_symlink()
        assert _read(alias)["scan_summary"]["total_files"] == 1

    def test_a_failed_write_leaves_no_temporary_file(
        self, temp_dir: Path
    ) -> None:
        """Args:
        temp_dir: Holds a directory that cannot be replaced by a file.
        """
        target = temp_dir / "occupied"
        (target / "child").mkdir(parents=True)

        with pytest.raises(OSError, match="--json-output"):
            _DocumentSink(to_stdout=False, path=target).publish({})

        assert sorted(p.name for p in temp_dir.iterdir()) == ["occupied"]

    def test_publishing_replaces_a_link_too(self, temp_dir: Path) -> None:
        """Not only the up-front claim: a library caller skips that.

        ``run_linter`` takes options directly, and a link can appear
        between the claim and the end of the run.

        Args:
            temp_dir: Scratch directory for the workflow and the link.
        """
        workflow = temp_dir / "test.yaml"
        workflow.write_text(BROKEN, encoding="utf-8")
        alias = temp_dir / "results.json"
        alias.symlink_to(workflow)

        _DocumentSink(to_stdout=False, path=alias).publish({"a": 1})

        assert workflow.read_text(encoding="utf-8") == BROKEN
        assert _read(alias) == {"a": 1}


class TestTheFileKeepsItsPermissions:
    """Publishing replaces the file, but never widens who can read it.

    The Action names a private ``mktemp`` file. A replacement created by
    the umask alone turned its ``0600`` into ``0644``, readable by every
    local user. A regular file keeps its bits, as a shell redirect into
    it would; anything else gets the umask default.
    """

    @pytest.fixture(autouse=True)
    def _umask(self) -> Iterator[None]:
        """Pin the common ``022`` umask, so the default is known.

        Yields:
            Nothing; the previous umask is restored afterwards.
        """
        previous = os.umask(0o022)
        try:
            yield
        finally:
            os.umask(previous)

    def test_a_private_file_stays_private(self, temp_dir: Path) -> None:
        """Args:
        temp_dir: Holds the document, created as ``mktemp`` makes it.
        """
        target = temp_dir / "doc.json"
        os.close(os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600))

        _DocumentSink(to_stdout=False, path=target).publish({"a": 1})

        assert stat.S_IMODE(target.stat().st_mode) == 0o600
        assert _read(target) == {"a": 1}

    def test_a_private_file_is_never_briefly_readable(
        self, temp_dir: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The replacement is created private, not narrowed afterwards.

        POSIX checks permission when a file is opened. Created ``0666``
        and narrowed by ``fchmod``, the temporary file is ``0644`` for
        an instant, and another local user who opens it then keeps a
        readable descriptor however private it later becomes.

        Args:
            temp_dir: Holds the document, created as ``mktemp`` makes it.
            monkeypatch: Records the mode each file is created with.
        """
        target = temp_dir / "doc.json"
        os.close(os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600))
        created: list[int] = []
        real_open = os.open

        def records(
            path: Any, flags: int, mode: int = 0o777, **kwargs: Any
        ) -> int:
            """Note the mode of a file being created, then open it.

            Args:
                path: What to open.
                flags: How to open it.
                mode: The permissions to create it with.
                kwargs: Passed through, such as the ``dir_fd`` that
                    ``shutil.rmtree`` uses on Python 3.11 and later.

            Returns:
                The descriptor.
            """
            if flags & os.O_CREAT:
                created.append(mode)
            return real_open(path, flags, mode, **kwargs)

        monkeypatch.setattr(os, "open", records)

        _DocumentSink(to_stdout=False, path=target).publish({"a": 1})

        assert created == [0o600]

    def test_an_existing_file_keeps_its_own_bits(self, temp_dir: Path) -> None:
        """Args:
        temp_dir: Holds a group-readable document.
        """
        target = temp_dir / "doc.json"
        target.write_text("{}", encoding="utf-8")
        target.chmod(0o640)

        _DocumentSink(to_stdout=False, path=target).publish({"a": 1})

        assert stat.S_IMODE(target.stat().st_mode) == 0o640

    def test_a_new_file_gets_the_umask_default(self, temp_dir: Path) -> None:
        """Args:
        temp_dir: Where the document is created.
        """
        target = temp_dir / "doc.json"

        _DocumentSink(to_stdout=False, path=target).publish({"a": 1})

        assert stat.S_IMODE(target.stat().st_mode) == 0o644

    def test_a_link_s_own_mode_is_never_copied(self, temp_dir: Path) -> None:
        """A link reports ``0o777``; copying it would open the file wide.

        Args:
            temp_dir: Holds a private file and a link named as the output.
        """
        private = temp_dir / "private.json"
        private.write_text("{}", encoding="utf-8")
        private.chmod(0o600)
        alias = temp_dir / "doc.json"
        alias.symlink_to(private)

        _DocumentSink(to_stdout=False, path=alias).publish({"a": 1})

        assert not alias.is_symlink()
        assert stat.S_IMODE(alias.stat().st_mode) == 0o644
        assert stat.S_IMODE(private.stat().st_mode) == 0o600

    def test_a_platform_without_fchmod_still_keeps_the_bits(
        self, temp_dir: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Windows before Python 3.13 has no ``os.fchmod``.

        The package declares itself OS independent, and calling the
        missing function raised ``AttributeError`` -- not an ``OSError``,
        so it escaped the publishing error handling -- whenever the
        output file already existed.

        Args:
            temp_dir: Holds a group-readable document.
            monkeypatch: Removes ``os.fchmod`` for the test.
        """
        monkeypatch.delattr(os, "fchmod", raising=False)
        target = temp_dir / "doc.json"
        target.write_text("{}", encoding="utf-8")
        # 0640, not 0600: the replacement is created 0600, so a 0600
        # target would pass even if the bits were never applied.
        target.chmod(0o640)

        _DocumentSink(to_stdout=False, path=target).publish({"a": 1})

        assert stat.S_IMODE(target.stat().st_mode) == 0o640
        assert _read(target) == {"a": 1}

    def test_a_failed_mode_change_closes_the_temporary_file(
        self, temp_dir: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The descriptor is owned before anything can raise.

        ``fchmod`` ran on the raw descriptor before ``fdopen`` took it,
        so a failure unlinked the file but left it open, and a library
        caller retrying the publish leaked one descriptor per attempt.

        Args:
            temp_dir: Holds the document.
            monkeypatch: Makes ``os.fchmod`` fail.
        """
        if not Path("/dev/fd").is_dir():
            pytest.skip("needs /dev/fd to count open descriptors")
        target = temp_dir / "doc.json"
        target.write_text("{}", encoding="utf-8")
        target.chmod(0o640)

        def refuse(_descriptor: int, _mode: int) -> None:
            """Fail as a filesystem refusing the change would.

            Args:
                _descriptor: Ignored.
                _mode: Ignored.

            Raises:
                OSError: Always.
            """
            raise PermissionError(1, "Operation not permitted")

        monkeypatch.setattr(os, "fchmod", refuse)
        sink = _DocumentSink(to_stdout=False, path=target)
        before = len(list(Path("/dev/fd").iterdir()))
        for _ in range(10):
            with pytest.raises(OSError, match="--json-output"):
                sink.publish({"a": 1})

        assert len(list(Path("/dev/fd").iterdir())) == before
        assert sorted(p.name for p in temp_dir.iterdir()) == ["doc.json"]


class TestALongNameStillPublishes:
    """The temporary name does not grow with the output's name."""

    def test_a_name_at_the_filesystem_limit(self, temp_dir: Path) -> None:
        """Deriving the temporary name from the target's added 14 bytes.

        A 250-byte name is valid on a 255-byte filesystem; the temporary
        name beside it was not, and ``os.open`` failed with
        ``ENAMETOOLONG``.

        Args:
            temp_dir: Holds the long-named document.
        """
        target = temp_dir / ("x" * 250 + ".json")

        _DocumentSink(to_stdout=False, path=target).publish({"a": 1})

        assert _read(target) == {"a": 1}


class TestTheReadSetComesFromTheConfiguration:
    """What the run reads is configurable, so the vetting must be too.

    A fixed list of YAML suffixes missed a scan configured to read
    ``.json``, the allow-list's ``extra_globs``, and the cache.
    """

    @staticmethod
    def _lint(root: Path, config: Path, target: Path) -> Any:
        """Invoke ``lint`` with both checks off and a configuration.

        Args:
            root: The path to scan.
            config: The ``--config`` file.
            target: The ``--json-output`` file.

        Returns:
            The CliRunner result.
        """
        return CliRunner().invoke(
            app,
            [
                "lint",
                str(root),
                "--action-calls",
                "off",
                "--allow-list",
                "off",
                "--config",
                str(config),
                "--json-output",
                str(target),
            ],
        )

    @staticmethod
    def _config(root: Path, text: str) -> Path:
        """Write a configuration file outside the scanned tree.

        Args:
            root: Directory to hold it.
            text: Its YAML.

        Returns:
            Its path.
        """
        path = root / "linter.cfg"
        path.write_text(text, encoding="utf-8")
        return path

    def test_a_configured_scan_extension(self, temp_dir: Path) -> None:
        """Args:
        temp_dir: Scratch directory for the workspace.
        """
        workspace = _workspace(temp_dir / "repo")
        config = self._config(
            temp_dir, 'scan_extensions: [".yml", ".yaml", ".json"]\n'
        )
        target = workspace / ".github" / "workflows" / "result.json"

        result = self._lint(workspace, config, target)

        assert result.exit_code == exit_codes.RUNTIME_ERROR
        assert "reads names ending '.json'" in _said(result)
        assert not target.exists()

    @pytest.mark.parametrize(
        ("extension", "name"),
        [
            (".workflow.json", "result.workflow.json"),
            ("json", "resultjson"),
            (".JSON", "result.json"),
        ],
        ids=["multi-part", "no-dot", "case"],
    )
    def test_an_extension_as_the_scan_globs_it(
        self, temp_dir: Path, extension: str, name: str
    ) -> None:
        """Discovery globs ``*{ext}``: a name ending with it is read.

        ``Path.suffix`` sees only the last dotted part, so it passed
        ``result.workflow.json`` for ``.workflow.json`` and anything for
        a dot-less ``json``.

        Args:
            temp_dir: Scratch directory for the workspace.
            extension: The configured scan extension.
            name: An output name the scan would read.
        """
        workspace = _workspace(temp_dir / "repo")
        config = self._config(
            temp_dir, f'scan_extensions: [".yml", "{extension}"]\n'
        )
        target = workspace / ".github" / "workflows" / name

        result = self._lint(workspace, config, target)

        assert result.exit_code == exit_codes.RUNTIME_ERROR
        assert "reads names ending" in _said(result)
        assert not target.exists()

    def test_yaml_even_when_the_scan_reads_none(self, temp_dir: Path) -> None:
        """Configuration and Dependabot files are YAML whatever is scanned.

        Args:
            temp_dir: Scratch directory for the workspace.
        """
        workspace = _workspace(temp_dir / "repo")
        config = self._config(temp_dir, 'scan_extensions: [".yml"]\n')
        target = workspace / ".github" / "dependabot.yaml"

        result = self._lint(workspace, config, target)

        assert result.exit_code == exit_codes.RUNTIME_ERROR
        assert "reads names ending '.yaml'" in _said(result)
        assert not target.exists()

    def test_an_extra_glob_inside_the_tree(self, temp_dir: Path) -> None:
        """Args:
        temp_dir: Scratch directory for the workspace.
        """
        workspace = _workspace(temp_dir / "repo")
        config = self._config(
            temp_dir, 'allow_list:\n  extra_globs: ["docs/*.pins"]\n'
        )
        target = workspace / "docs" / "harden.pins"
        target.parent.mkdir()
        target.write_text("keep me\n", encoding="utf-8")

        result = self._lint(workspace, config, target)

        assert result.exit_code == exit_codes.RUNTIME_ERROR
        assert "extra_globs reads 'docs/*.pins'" in _said(result)
        assert target.read_text(encoding="utf-8") == "keep me\n"

    def test_an_extra_glob_name_outside_the_tree(self, temp_dir: Path) -> None:
        """A pattern can escape the tree: ``../outside/*.pins``, or a link.

        Args:
            temp_dir: Scratch directory for the workspace and output.
        """
        workspace = _workspace(temp_dir / "repo")
        config = self._config(
            temp_dir, 'allow_list:\n  extra_globs: ["../outside/*.pins"]\n'
        )
        (temp_dir / "outside").mkdir()
        target = temp_dir / "outside" / "harden.pins"
        target.write_text("keep me\n", encoding="utf-8")

        result = self._lint(workspace, config, target)

        assert result.exit_code == exit_codes.RUNTIME_ERROR
        assert "extra_globs reads" in _said(result)
        assert target.read_text(encoding="utf-8") == "keep me\n"

    def test_an_unrelated_name_outside_the_tree_is_written(
        self, temp_dir: Path
    ) -> None:
        """Args:
        temp_dir: Scratch directory for the workspace and output.
        """
        workspace = _workspace(temp_dir / "repo")
        config = self._config(
            temp_dir, 'allow_list:\n  extra_globs: ["docs/*.pins"]\n'
        )
        target = temp_dir / "results.json"

        result = self._lint(workspace, config, target)

        assert result.exit_code == exit_codes.SUCCESS, result.output
        assert _read(target)["scan_summary"]["total_files"] == 1

    @pytest.mark.parametrize("link", ["symlink", "hardlink"])
    def test_a_link_to_the_caches_temporary_file(
        self, temp_dir: Path, link: str
    ) -> None:
        """The cache writes through that name; so would an alias's file change.

        A hard link shares the inode under another name, which no path
        comparison sees.

        Args:
            temp_dir: Scratch directory for the workspace, cache and alias.
            link: Which kind of alias to name as the output.
        """
        workspace = _workspace(temp_dir / "repo")
        cache = temp_dir / "cache"
        cache.mkdir()
        (cache / "c.tmp").write_text("{}", encoding="utf-8")
        config = self._config(
            temp_dir,
            f'cache:\n  cache_dir: "{cache}"\n  cache_file: "c.json"\n',
        )
        alias = temp_dir / "results.json"
        if link == "symlink":
            alias.symlink_to(cache / "c.tmp")
        else:
            alias.hardlink_to(cache / "c.tmp")

        result = self._lint(workspace, config, alias)

        assert result.exit_code == exit_codes.RUNTIME_ERROR
        assert "temporary file" in _said(result)
        assert (cache / "c.tmp").read_text(encoding="utf-8") == "{}"

    @pytest.mark.parametrize("linked", ["workflow", "dependabot"])
    def test_a_failing_glob_does_not_unprotect_other_inputs(
        self, temp_dir: Path, linked: str
    ) -> None:
        """Each discovery source fails alone.

        One suppression around a repository's whole discovery meant an
        absolute extra_globs pattern, raising after the workflows were
        found, discarded them and skipped the Dependabot lookup -- so a
        linked workflow's target could be overwritten after all.

        Args:
            temp_dir: Scratch directory for the workspace and target.
            linked: Which input is a link to the named output.
        """
        target = temp_dir / "results.json"
        target.write_text("version: 2\n", encoding="utf-8")
        workspace = _workspace(temp_dir / "repo")
        (workspace / ".git").mkdir()
        if linked == "workflow":
            link = workspace / ".github" / "workflows" / "check.yaml"
        else:
            link = workspace / ".github" / "dependabot.yml"
        link.symlink_to(target)
        config = self._config(
            temp_dir, f'allow_list:\n  extra_globs: ["{temp_dir}/*.pins"]\n'
        )

        result = self._lint(workspace, config, target)

        assert result.exit_code == exit_codes.RUNTIME_ERROR
        assert "through a link" in _said(result)
        assert target.read_text(encoding="utf-8") == "version: 2\n"

    def test_an_extra_glob_file_linked_from_outside(
        self, temp_dir: Path
    ) -> None:
        """The allow-list check reads what its globs match, through links.

        The default pattern ``examples/**/*.yaml`` matched a link whose
        target has an ordinary name outside every tree, which neither the
        name check nor workflow discovery could see.

        Args:
            temp_dir: Scratch directory for the workspace and target.
        """
        target = temp_dir / "results.json"
        target.write_text(BROKEN, encoding="utf-8")
        workspace = _workspace(temp_dir / "repo")
        (workspace / ".git").mkdir()
        (workspace / "examples").mkdir()
        (workspace / "examples" / "caller.yaml").symlink_to(target)

        result = CliRunner().invoke(
            app,
            [
                "lint",
                str(workspace),
                "--action-calls",
                "off",
                "--allow-list",
                "off",
                "--json-output",
                str(target),
            ],
        )

        assert result.exit_code == exit_codes.RUNTIME_ERROR
        assert "through a link" in _said(result)
        assert target.read_text(encoding="utf-8") == BROKEN

    def test_a_source_that_fails_midway_keeps_what_it_found(
        self, temp_dir: Path
    ) -> None:
        """A walk that raises partway still protects the files it reached.

        Args:
            temp_dir: Holds the file the source yields before failing.
        """
        reached = temp_dir / "reached.yaml"
        reached.write_text("", encoding="utf-8")

        def walk() -> Iterator[Path]:
            yield reached
            raise PermissionError(13, "Permission denied")

        assert cli._gathered(walk) == {reached.resolve()}

    def test_globbed_directories_are_not_files(self, temp_dir: Path) -> None:
        """The allow-list stage reads files; a matching directory is not one.

        Args:
            temp_dir: Holds a file and a directory the pattern matches.
        """
        (temp_dir / "a.yaml").write_text("", encoding="utf-8")
        (temp_dir / "b.yaml").mkdir()

        assert list(cli._glob_files(temp_dir, "*.yaml")) == [
            temp_dir / "a.yaml"
        ]

    def test_an_invalid_extra_glob_does_not_become_fatal(
        self, temp_dir: Path
    ) -> None:
        """Asking for a document must not change the run's outcome.

        An absolute pattern makes ``Path.glob`` raise. The allow-list
        stage treats that as advisory; vetting now does too.

        Args:
            temp_dir: Scratch directory for the workspace and document.
        """
        workspace = _workspace(temp_dir / "repo")
        config = self._config(
            temp_dir, f'allow_list:\n  extra_globs: ["{temp_dir}/*.pins"]\n'
        )
        target = temp_dir / "results.json"

        result = self._lint(workspace, config, target)

        assert result.exit_code == exit_codes.SUCCESS, result.output
        assert _read(target)["scan_summary"]["total_files"] == 1

    def test_the_validation_caches_temporary_file(self, temp_dir: Path) -> None:
        """Each cache save writes it and renames it over the cache.

        Args:
            temp_dir: Scratch directory for the workspace and cache.
        """
        workspace = _workspace(temp_dir / "repo")
        cache = temp_dir / "cache"
        cache.mkdir()
        config = self._config(
            temp_dir,
            f'cache:\n  cache_dir: "{cache}"\n  cache_file: "c.json"\n',
        )

        result = self._lint(workspace, config, cache / "c.tmp")

        assert result.exit_code == exit_codes.RUNTIME_ERROR
        assert "temporary file" in _said(result)
        assert not (cache / "c.tmp").exists()

    def test_the_validation_cache(self, temp_dir: Path) -> None:
        """Args:
        temp_dir: Scratch directory for the workspace and cache.
        """
        workspace = _workspace(temp_dir / "repo")
        cache = temp_dir / "cache"
        config = self._config(
            temp_dir,
            f'cache:\n  cache_dir: "{cache}"\n  cache_file: "c.json"\n',
        )
        cache.mkdir()
        (cache / "c.json").write_text("{}", encoding="utf-8")

        result = self._lint(workspace, config, cache / "c.json")

        assert result.exit_code == exit_codes.RUNTIME_ERROR
        assert "validation cache" in _said(result)
        assert (cache / "c.json").read_text(encoding="utf-8") == "{}"

    def test_the_file_a_config_link_points_at(self, temp_dir: Path) -> None:
        """``--config`` may name a link; the file behind it is the input.

        Args:
            temp_dir: Scratch directory for the workspace and files.
        """
        workspace = _workspace(temp_dir / "repo")
        real = self._config(temp_dir, "log_level: INFO\n")
        link = temp_dir / "link.cfg"
        link.symlink_to(real)

        result = self._lint(workspace, link, real)

        assert result.exit_code == exit_codes.RUNTIME_ERROR
        assert "--config file" in _said(result)
        assert real.read_text(encoding="utf-8") == "log_level: INFO\n"

    def test_a_configuration_that_fails_to_load_writes_nothing(
        self, temp_dir: Path
    ) -> None:
        """Without the configuration the path cannot be shown safe.

        Args:
            temp_dir: Scratch directory for the workspace and files.
        """
        workspace = _workspace(temp_dir / "repo")
        config = self._config(temp_dir, "- not a mapping\n")
        target = temp_dir / "document.json"

        result = self._lint(workspace, config, target)

        assert result.exit_code == exit_codes.RUNTIME_ERROR
        assert not target.exists()

    def test_a_library_caller_writes_nothing_before_the_run(
        self, temp_dir: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """``run_linter`` publishes once, at the end, as the command does.

        Args:
            temp_dir: Scratch directory for the workspace and document.
            monkeypatch: Used to look at the file while the run is going.
        """
        workspace = _workspace(temp_dir / "repo")
        document = temp_dir / "document.json"
        document.write_text("earlier", encoding="utf-8")
        seen: list[str] = []

        def looks(*_args: object, **_kwargs: object) -> None:
            seen.append(document.read_text(encoding="utf-8"))
            raise RuntimeError("stop here")

        monkeypatch.setattr(cli, "_run_one_repository", looks)

        with pytest.raises(RuntimeError):
            cli.run_linter(
                Config(), CLIOptions(path=workspace, json_output=document)
            )

        assert seen == ["earlier"]

    def test_a_library_caller_with_a_looping_root(self, temp_dir: Path) -> None:
        """The run tolerates a looping scan root; vetting must as well.

        Discovery helpers resolve internally -- the Dependabot lookup
        first of all -- and a loop raises ``RuntimeError`` there before
        Python 3.13. Requesting a document made that fatal for a direct
        ``run_linter`` caller.

        Args:
            temp_dir: Holds the looping root and the document.
        """
        (temp_dir / "scan").mkdir()
        (temp_dir / "out").mkdir()
        loop = temp_dir / "scan" / "loop"
        loop.symlink_to(loop)
        document = temp_dir / "out" / "doc.json"
        config = Config(action_calls_mode=CheckMode.OFF)

        without = cli.run_linter(config, CLIOptions(path=loop))
        result = cli.run_linter(
            config, CLIOptions(path=loop, json_output=document)
        )

        assert result == without

    def test_a_library_caller_is_refused_too(self, temp_dir: Path) -> None:
        """``run_linter`` takes options directly, skipping the command.

        Args:
            temp_dir: Scratch directory for the workspace.
        """
        workspace = _workspace(temp_dir / "repo")
        target = workspace / ".github" / "workflows" / "result.json"

        with pytest.raises(
            ConfigurationError, match="reads names ending '.json'"
        ):
            cli.run_linter(
                Config(scan_extensions=[".yml", ".yaml", ".json"]),
                CLIOptions(path=workspace, json_output=target),
            )

        assert not target.exists()
