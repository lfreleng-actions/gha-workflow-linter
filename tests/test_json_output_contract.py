# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""``--format json`` owes a document on every path it can reach.

A run that promises machine-readable output and then returns without
printing anything leaves its consumer with an empty stream and no way to
tell that from a crash. #324 fixed the rate-limited instance of this;
these tests cover the rest, which were pre-existing and applied to every
run rather than only throttled ones:

* a repository the scan examined and found no action calls in;
* a scan that failed outright;
* a sweep that could not read its root, or was given a depth it could
  not use.

Each case is paired with the distinction it has to support. "Nothing to
check" and "could not look" both report no findings, so a document that
does not say which is no better than no document at all -- the reason
``error`` is present on every document rather than only on failures.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any
from unittest import mock

import pytest
from typer.testing import CliRunner

from gha_workflow_linter import exit_codes
from gha_workflow_linter.check_modes import CheckMode
from gha_workflow_linter.cli import app, run_linter
from gha_workflow_linter.exceptions import ConfigurationError
from gha_workflow_linter.models import (
    CacheConfig,
    CLIOptions,
    Config,
    GitHubAPIConfig,
    ValidationMethod,
)

if TYPE_CHECKING:
    from pathlib import Path

#: A workflow with no action call in it at all. The scan succeeds and
#: legitimately finds nothing, which is the case that used to return
#: before emitting anything.
WORKFLOW_WITHOUT_CALLS = """---
name: CI
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo hello
"""


def _repository(root: Path) -> Path:
    """Write a repository whose workflow makes no action calls.

    Args:
        root: Directory to populate.

    Returns:
        The repository root.
    """
    workflows = root / ".github" / "workflows"
    workflows.mkdir(parents=True, exist_ok=True)
    (workflows / "ci.yaml").write_text(WORKFLOW_WITHOUT_CALLS)
    (root / ".git").mkdir(exist_ok=True)
    return root


def _config(tmp_path: Path) -> Config:
    """Build a configuration that neither caches nor reaches the API.

    Args:
        tmp_path: Directory to hold the disabled cache.

    Returns:
        A configuration safe to run offline.
    """
    return Config(
        validation_method=ValidationMethod.GIT,
        github_api=GitHubAPIConfig(token=None),
        cache=CacheConfig(enabled=False, cache_dir=tmp_path / "cache"),
    )


def _options(path: Path, **kwargs: Any) -> CLIOptions:
    """Build JSON-mode CLI options rooted at ``path``.

    Args:
        path: Repository or container to scan.
        kwargs: Overrides applied on top.

    Returns:
        The resolved options.
    """
    base: dict[str, Any] = {
        "path": path,
        "quiet": True,
        "output_format": "json",
    }
    base.update(kwargs)
    return CLIOptions(**base)


def _document(capsys: pytest.CaptureFixture[str]) -> dict[str, Any]:
    """Parse the document the run printed, failing clearly if it did not.

    Args:
        capsys: Capture fixture holding the run's standard output.

    Returns:
        The parsed document.
    """
    out = capsys.readouterr().out
    if not out.strip():
        pytest.fail(
            "the run emitted nothing at all; a --format json consumer "
            "cannot tell that from a crash"
        )
    document: dict[str, Any] = json.loads(out)
    return document


class TestNothingToCheck:
    """A scan that found no action calls still examined the repository."""

    def test_it_emits_a_document(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """This path returned before printing anything.

        Args:
            tmp_path: Repository root.
            capsys: Captures standard output.
        """
        code = run_linter(_config(tmp_path), _options(_repository(tmp_path)))

        document = _document(capsys)
        assert code == exit_codes.SUCCESS
        assert document["scan_summary"]["total_calls"] == 0

    def test_it_is_reported_as_clean_rather_than_failed(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Finding nothing is a result, and must not read as an error.

        Args:
            tmp_path: Repository root.
            capsys: Captures standard output.
        """
        run_linter(_config(tmp_path), _options(_repository(tmp_path)))

        assert _document(capsys)["error"] is None

    def test_no_markup_reaches_standard_output(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """The console note on this path used to print beside the document.

        ``console`` is standard output, so a non-quiet JSON run emitted
        Rich markup where the document belongs. Driving ``run_linter``
        directly is what exposes it: the command layer coerces JSON mode
        to quiet, so the CLI hid the defect rather than avoiding it.

        Args:
            tmp_path: Repository root.
            capsys: Captures standard output.
        """
        options = _options(_repository(tmp_path), quiet=False)

        run_linter(_config(tmp_path), options)

        # Parses at all, which it would not with markup prepended.
        assert _document(capsys)["error"] is None


class TestScanFailure:
    """A scan that failed has a reason, and the document must carry it."""

    def test_it_emits_a_document(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Args:
        tmp_path: Repository root.
        capsys: Captures standard output.
        """
        with mock.patch(
            "gha_workflow_linter.cli.WorkflowScanner.scan_directory",
            side_effect=PermissionError("Permission denied"),
        ):
            code = run_linter(
                _config(tmp_path), _options(_repository(tmp_path))
            )

        document = _document(capsys)
        assert code == exit_codes.RUNTIME_ERROR
        assert "Permission denied" in document["error"]

    def test_the_reason_separates_it_from_a_clean_run(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Both report no findings; only ``error`` tells them apart.

        This is the acceptance criterion stated as an assertion. Without
        the key the two documents agree about everything a consumer
        reads, so a failure is indistinguishable from a clean result.

        Args:
            tmp_path: Repository root.
            capsys: Captures standard output.
        """
        repository = _repository(tmp_path)

        with mock.patch(
            "gha_workflow_linter.cli.WorkflowScanner.scan_directory",
            side_effect=PermissionError("Permission denied"),
        ):
            run_linter(_config(tmp_path), _options(repository))
        failed = _document(capsys)

        run_linter(_config(tmp_path), _options(repository))
        clean = _document(capsys)

        assert failed["errors"] == clean["errors"] == []
        assert failed["error"] is not None
        assert clean["error"] is None


class TestSweepDiscoveryFailure:
    """A sweep that never got as far as looking owes a document too.

    These drive ``run_linter`` rather than the CLI, and deliberately.
    The common shapes of this failure never reach the linter: an
    unreadable ``path`` and an out-of-range ``--repo-depth`` are refused
    by the argument parser, which exits ``2`` with usage text. That is
    the code reserved for a usage error and never produced by the
    linter's own logic, so a consumer seeing it knows the invocation was
    wrong -- a different question from anything a document answers.

    What remains is the programmatic entry point, which the GitHub
    Action and the tests both use, and where the same failures arrive
    with no parser in front of them.
    """

    @pytest.mark.parametrize(
        ("failure", "expected"),
        [
            (OSError("Permission denied"), "Cannot read"),
            (ValueError("negative depth"), "Invalid repository depth"),
        ],
    )
    def test_it_emits_a_document_naming_the_reason(
        self,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
        failure: Exception,
        expected: str,
    ) -> None:
        """Args:
        tmp_path: Container directory.
        capsys: Captures standard output.
        failure: What discovery raises.
        expected: Text the document's reason must contain.
        """
        options = _options(tmp_path, multi_repo=True)

        with mock.patch(
            "gha_workflow_linter.cli.find_repositories", side_effect=failure
        ):
            code = run_linter(_config(tmp_path), options)

        document = _document(capsys)
        assert code == exit_codes.RUNTIME_ERROR
        assert expected in document["error"]
        assert document["summary"]["exit_code"] == code

    def test_the_parser_refuses_a_bad_invocation_before_the_linter(
        self, tmp_path: Path
    ) -> None:
        """The boundary of the every-path claim, stated as a test.

        A depth the parser rejects never reaches ``_discover_or_report``,
        so no document is emitted and none is owed: the run exits ``2``,
        which the exit-code contract reserves for exactly this and which
        the linter never produces itself. Pinned so that the claim in
        the README stays true, and so that anyone tempted to route this
        through the document has to change the test that says why not.

        Args:
            tmp_path: Directory to point the run at.
        """
        result = CliRunner().invoke(
            app,
            [
                "lint",
                str(tmp_path),
                "--multi-repo",
                "--repo-depth",
                "-1",
                "--format",
                "json",
            ],
        )

        assert result.exit_code == exit_codes.CLI_USAGE_ERROR
        assert result.stdout.strip() == "" or "--repo-depth" in result.stdout

    def test_an_empty_container_is_not_reported_as_a_failure(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """The inverse, and the distinction the key exists to draw.

        A sweep that read its root and found no repositories produces
        the same empty ``repositories`` list as one that could not read
        it at all.

        Args:
            tmp_path: Empty container directory.
            capsys: Captures standard output.
        """
        code = run_linter(
            _config(tmp_path), _options(tmp_path, multi_repo=True)
        )

        document = _document(capsys)
        assert code == exit_codes.SUCCESS
        assert document["repositories"] == []
        assert document["error"] is None


class TestRefusedInvocation:
    """A run refused before it starts has still promised a document.

    ``--files`` with ``--multi-repo`` is rejected outright, which is
    right -- the two ask for different things -- but the rejection used
    to reach the caller as an exit code and a log line, with nothing on
    standard output.
    """

    def test_a_refused_sweep_emits_a_document(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Args:
        tmp_path: Container directory.
        capsys: Captures standard output.
        """
        options = _options(
            tmp_path, multi_repo=True, files=[".github/workflows/ci.yaml"]
        )

        with pytest.raises(ConfigurationError):
            run_linter(_config(tmp_path), options)

        document = _document(capsys)
        assert "Configuration error" in document["error"]
        assert document["summary"]["exit_code"] == exit_codes.RUNTIME_ERROR

    def test_the_command_reports_it_too(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """The command refuses this earlier than the sweep does.

        Both routes have to answer, since the command layer checks
        before pre-flight while the sweep checks again for a library
        caller. Only one document may be printed either way.

        Args:
            tmp_path: Container directory.
            capsys: Captures standard output.
        """
        result = CliRunner().invoke(
            app,
            [
                "lint",
                str(tmp_path),
                "--multi-repo",
                "--files",
                ".github/workflows/ci.yaml",
                "--format",
                "json",
                "--validation-method",
                "git",
            ],
        )

        assert result.exit_code == exit_codes.RUNTIME_ERROR
        document = json.loads(result.stdout)
        assert "Configuration error" in document["error"]

    def test_a_conflicting_flag_pair_reports_it_too(
        self, tmp_path: Path
    ) -> None:
        """Refused earlier still than the others, and owed the same thing.

        ``--verbose --quiet`` is rejected before the command reaches its
        own error handling, so it needed the emitter wiring in
        separately. The Rich message it used to print went to standard
        output, which in this mode belongs to the document.

        Args:
            tmp_path: Directory to point the run at.
        """
        result = CliRunner().invoke(
            app,
            [
                "lint",
                str(tmp_path),
                "--verbose",
                "--quiet",
                "--format",
                "json",
            ],
        )

        assert result.exit_code == exit_codes.RUNTIME_ERROR
        document = json.loads(result.stdout)
        assert "verbose" in document["error"]


class TestStderrMergeIsAlwaysPresent:
    """Every document carries ``stderr_merge``, run or not.

    ``checked`` separates a check that ran and found nothing from one
    that was switched off or never reached, which otherwise read alike.
    """

    MERGE = 'out=$(curl -s x 2>&1)\njq . <<< "$out"\n'

    def _with_script(self, root: Path) -> Path:
        repository = _repository(root)
        (repository / "fetch.sh").write_text(self.MERGE)
        return repository

    def test_a_short_circuit_still_runs_the_check(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """No action calls to validate does not skip an offline check.

        Args:
            tmp_path: Repository root.
            capsys: Captures standard output.
        """
        run_linter(_config(tmp_path), _options(self._with_script(tmp_path)))

        section = _document(capsys)["stderr_merge"]
        assert section["checked"] is True
        assert [f["rule"] for f in section["findings"]] == ["SEM002"]
        assert section["summary"]["by_confidence"]["high"] == 1

    def test_a_full_run_carries_it(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Args:
        tmp_path: Repository root.
        capsys: Captures standard output.
        """
        config = _config(tmp_path)
        config.action_calls_mode = CheckMode.OFF

        run_linter(config, _options(self._with_script(tmp_path)))

        document = _document(capsys)
        assert document["checks"]["stderr-merge"] == {
            "mode": "report",
            "ran": True,
        }
        assert document["stderr_merge"]["findings"][0]["path"] == "fetch.sh"

    def test_a_scan_failure_carries_it(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Args:
        tmp_path: Repository root.
        capsys: Captures standard output.
        """
        with mock.patch(
            "gha_workflow_linter.cli.WorkflowScanner.scan_directory",
            side_effect=PermissionError("Permission denied"),
        ):
            run_linter(_config(tmp_path), _options(self._with_script(tmp_path)))

        assert _document(capsys)["stderr_merge"]["checked"] is True

    def test_off_reports_checked_false(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Args:
        tmp_path: Repository root.
        capsys: Captures standard output.
        """
        config = _config(tmp_path)
        config.stderr_merge.mode = CheckMode.OFF

        run_linter(config, _options(self._with_script(tmp_path)))

        section = _document(capsys)["stderr_merge"]
        assert section["checked"] is False
        assert section["findings"] == []
        assert section["summary"]["total"] == 0

    def test_a_refused_invocation_carries_it(self, tmp_path: Path) -> None:
        """Args:
        tmp_path: Directory to point the run at.
        """
        result = CliRunner().invoke(
            app,
            [
                "lint",
                str(tmp_path),
                "--stderr-merge",
                "fix",
                "--format",
                "json",
            ],
        )

        assert result.exit_code == exit_codes.RUNTIME_ERROR
        document = json.loads(result.stdout)
        assert "needs a person" in document["error"]
        assert document["stderr_merge"]["checked"] is False


class TestPythonPathIsAlwaysPresent:
    """Every document carries ``python_path``, run or not.

    Its shape mirrors ``stderr_merge``: ``checked``, ``summary`` with
    counts by rule and by kind and the ``enforced`` count, ``findings``
    and ``problems``. ``verify`` adds the setting the run enforced.
    """

    SCRIPT = "python3 -m json.tool f\n"

    def _with_script(self, root: Path) -> Path:
        repository = _repository(root)
        (repository / "fmt.sh").write_text(self.SCRIPT)
        return repository

    def test_a_short_circuit_still_runs_the_check(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """No action calls to validate does not skip an offline check.

        Args:
            tmp_path: Repository root.
            capsys: Captures standard output.
        """
        run_linter(_config(tmp_path), _options(self._with_script(tmp_path)))

        section = _document(capsys)["python_path"]
        assert section["checked"] is True
        assert section["verify"] is False
        assert section["problems"] == []
        assert section["findings"] == [
            {
                "repo": tmp_path.name,
                "path": "fmt.sh",
                "line": 1,
                "kind": "script",
                "rule": "PPA001",
                "detail": (
                    "python -m without -I: the working directory leads sys.path"
                ),
                "snippet": "python3 -m json.tool f",
                "suppressed": False,
            }
        ]
        summary = section["summary"]
        assert summary["total"] == 1
        assert summary["enforced"] == 1
        assert summary["suppressed"] == 0
        assert summary["by_rule"]["PPA001"] == 1
        assert set(summary["by_rule"]) == {f"PPA{n:03d}" for n in range(1, 11)}
        assert summary["by_kind"] == {"action": 0, "workflow": 0, "script": 1}

    def test_a_full_run_carries_it(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Args:
        tmp_path: Repository root.
        capsys: Captures standard output.
        """
        config = _config(tmp_path)
        config.action_calls_mode = CheckMode.OFF

        run_linter(config, _options(self._with_script(tmp_path)))

        document = _document(capsys)
        assert document["checks"]["python-path"] == {
            "mode": "report",
            "ran": True,
        }
        assert document["python_path"]["findings"][0]["path"] == "fmt.sh"

    def test_a_scan_failure_carries_it(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Args:
        tmp_path: Repository root.
        capsys: Captures standard output.
        """
        with mock.patch(
            "gha_workflow_linter.cli.WorkflowScanner.scan_directory",
            side_effect=PermissionError("Permission denied"),
        ):
            run_linter(_config(tmp_path), _options(self._with_script(tmp_path)))

        assert _document(capsys)["python_path"]["checked"] is True

    def test_off_reports_checked_false(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Args:
        tmp_path: Repository root.
        capsys: Captures standard output.
        """
        config = _config(tmp_path)
        config.python_path.mode = CheckMode.OFF

        run_linter(config, _options(self._with_script(tmp_path)))

        section = _document(capsys)["python_path"]
        assert section["checked"] is False
        assert section["verify"] is False
        assert section["findings"] == []
        assert section["problems"] == []
        assert section["summary"]["total"] == 0
        assert section["summary"]["enforced"] == 0

    def test_an_unreadable_file_is_a_problem(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Args:
        tmp_path: Repository root.
        capsys: Captures standard output.
        """
        repository = _repository(tmp_path)
        (repository / "action.yaml").write_text("runs: [unclosed\n")

        run_linter(_config(tmp_path), _options(repository))

        problems = _document(capsys)["python_path"]["problems"]
        assert [p.split(":")[0] for p in problems] == ["action.yaml"]

    def test_a_refused_invocation_carries_it(self, tmp_path: Path) -> None:
        """Args:
        tmp_path: Directory to point the run at.
        """
        result = CliRunner().invoke(
            app,
            [
                "lint",
                str(tmp_path),
                "--python-path",
                "fix",
                "--format",
                "json",
            ],
        )

        assert result.exit_code == exit_codes.RUNTIME_ERROR
        document = json.loads(result.stdout)
        assert "needs a person" in document["error"]
        assert document["python_path"]["checked"] is False
