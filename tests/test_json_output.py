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
from typing import TYPE_CHECKING, Any

import pytest
from typer.testing import CliRunner

from gha_workflow_linter import cli, exit_codes
from gha_workflow_linter.cli import _DocumentSink, _vet_json_output, app
from gha_workflow_linter.exceptions import ConfigurationError
from gha_workflow_linter.models import CLIOptions, Config

if TYPE_CHECKING:
    from pathlib import Path

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
                temp_dir / "missing" / "document.json",
                Config(),
                None,
                temp_dir,
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

    Emptying the target up front, as the run does to rule out a stale
    document, would erase a named ``action.yaml`` before it was read, and
    would create an empty workflow file that the scan then examines.
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
