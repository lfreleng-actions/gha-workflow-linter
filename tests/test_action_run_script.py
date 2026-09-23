# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Execute the Action's ``run:`` script and check what it passes on.

:mod:`tests.test_action_contract` proves every flag the script *can*
emit is a real option. It cannot prove the bash maps inputs to the right
ones, and nothing else exercised that mapping: CI runs the Action with
its defaults only.

So the script is taken verbatim from ``action.yaml`` and run under the
shell GitHub uses for ``shell: bash`` -- ``bash --noprofile --norc -eo
pipefail`` -- against a stub linter that records its arguments and
answers with a chosen document. Every input is given the value GitHub
would supply: the caller's, else the declared default, else empty.

The legacy mappings are checked against the CLI's own derivation
functions rather than against expectations written here, so the Action
and the CLI cannot come to disagree about what a deprecated input means.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from typing import Any

import pytest
import yaml

from gha_workflow_linter.check_modes import ACTION_CALLS, ALLOW_LIST
from gha_workflow_linter.cli import (
    _mode_from_action_call_flags,
    _mode_from_allow_list_flags,
)
from gha_workflow_linter.models import Config

ROOT = Path(__file__).resolve().parent.parent
ACTION = yaml.safe_load((ROOT / "action.yaml").read_text(encoding="utf-8"))

#: GitHub's invocation for ``shell: bash``. ``-e`` and ``pipefail``
#: change which failures stop the script, so testing under a laxer
#: shell would pass scripts that fail in production.
GITHUB_BASH = ["bash", "--noprofile", "--norc", "-eo", "pipefail"]

pytestmark = pytest.mark.skipif(
    shutil.which("bash") is None or shutil.which("jq") is None,
    reason="the Action's script needs bash and jq",
)

#: A clean result from a run in which every check executed.
CLEAN = {
    "rate_limited": False,
    "checks": {
        "action-calls": {"mode": "fix", "ran": True},
        "allow-list": {"mode": "report", "ran": True},
    },
    "scan_summary": {"total_calls": 7},
    "validation_summary": {"total_errors": 0},
}

_STUB = """#!{python}
import json, os, sys
with open(os.environ["STUB_LOG"], "a", encoding="utf-8") as log:
    log.write(json.dumps(sys.argv[1:]) + "\\n")
args = sys.argv[1:]
if "--format" in args and args[args.index("--format") + 1] == "json":
    with open(os.environ["STUB_DOCUMENT"], encoding="utf-8") as document:
        sys.stdout.write(document.read())
else:
    print("linter text output")
"""


def _script() -> str:
    """Return the linter step's ``run:`` block, verbatim.

    Returns:
        The shell source.
    """
    (step,) = [
        s
        for s in ACTION["runs"]["steps"]
        if s.get("id") == "gha-workflow-linter"
    ]
    return str(step["run"])


class Run:
    """The outcome of one execution of the script.

    Attributes:
        returncode: The script's exit status.
        stdout: What the script wrote, including workflow commands.
        invocations: Argument lists the linter received, in order.
        summary: What was written to the step summary.
    """

    def __init__(
        self,
        returncode: int,
        stdout: str,
        invocations: list[list[str]],
        summary: str,
    ) -> None:
        """Record a run.

        Args:
            returncode: The script's exit status.
            stdout: What the script wrote.
            invocations: Argument lists the linter received.
            summary: The step summary contents.
        """
        self.returncode = returncode
        self.stdout = stdout
        self.invocations = invocations
        self.summary = summary

    @property
    def args(self) -> list[str]:
        """The first invocation's arguments: the one a reader sees.

        Returns:
            The argument list.
        """
        return self.invocations[0]

    def value_of(self, flag: str) -> str | None:
        """Return the value passed with a flag, if it was passed.

        Args:
            flag: The option, such as ``--action-calls``.

        Returns:
            Its value, or None when the flag was not given.
        """
        if flag not in self.args:
            return None
        return self.args[self.args.index(flag) + 1]

    @property
    def warnings(self) -> list[str]:
        """The ``::warning`` workflow commands the script issued.

        Returns:
            Their message text.
        """
        return [
            line.split("::", 2)[-1]
            for line in self.stdout.splitlines()
            if line.startswith("::warning")
        ]


@pytest.fixture
def run_action(tmp_path: Path) -> Any:
    """Provide a function that runs the script with chosen inputs.

    Args:
        tmp_path: Scratch directory for the stub, logs and outputs.

    Returns:
        A callable taking input values by Action name, and optionally
        the document the stub linter should answer with.
    """
    stub_dir = tmp_path / "bin"
    stub_dir.mkdir()
    stub = stub_dir / "gha-workflow-linter"
    stub.write_text(_STUB.format(python=sys.executable), encoding="utf-8")
    stub.chmod(0o755)

    script = tmp_path / "run.sh"
    script.write_text(_script(), encoding="utf-8")

    def run(
        inputs: dict[str, str] | None = None,
        document: dict[str, Any] | None = None,
    ) -> Run:
        """Execute the script.

        Args:
            inputs: Values keyed by Action input name. Unnamed inputs get
                their declared default, else empty -- what GitHub passes.
            document: What the stub returns for ``--format json``.

        Returns:
            What the run produced.
        """
        given = inputs or {}
        unknown = set(given) - set(ACTION["inputs"])
        assert not unknown, f"no such inputs: {sorted(unknown)}"

        log = tmp_path / "invocations.jsonl"
        log.write_text("", encoding="utf-8")
        output = tmp_path / "github_output"
        output.write_text("", encoding="utf-8")
        summary = tmp_path / "step_summary"
        summary.write_text("", encoding="utf-8")
        answer = tmp_path / "document.json"
        answer.write_text(json.dumps(document or CLEAN), encoding="utf-8")

        env = {
            "PATH": f"{stub_dir}{os.pathsep}{os.environ['PATH']}",
            "USE_UVX": "false",
            "GITHUB_OUTPUT": str(output),
            "GITHUB_STEP_SUMMARY": str(summary),
            "STUB_LOG": str(log),
            "STUB_DOCUMENT": str(answer),
        }
        for name, spec in ACTION["inputs"].items():
            value = given.get(name, spec.get("default"))
            env["INPUT_" + name.upper().replace("-", "_")] = (
                "" if value is None else str(value)
            )

        completed = subprocess.run(
            [*GITHUB_BASH, str(script)],
            env=env,
            capture_output=True,
            text=True,
            check=False,
            cwd=tmp_path,
        )
        invocations = [
            json.loads(line)
            for line in log.read_text(encoding="utf-8").splitlines()
            if line
        ]
        return Run(
            completed.returncode,
            completed.stdout,
            invocations,
            summary.read_text(encoding="utf-8"),
        )

    return run


class TestDefaultsPassNothingExtra:
    """An unconfigured Action must not override the configuration file."""

    def test_no_mode_or_tuning_flag_is_passed(self, run_action: Any) -> None:
        result = run_action()

        assert result.returncode == 0, result.stdout
        for flag in (
            "--action-calls",
            "--allow-list",
            "--verify-action-calls",
            "--workers",
        ):
            assert flag not in result.args, f"{flag} passed by default"

    def test_worker_count_is_left_to_auto_detection(
        self, run_action: Any
    ) -> None:
        """The former default of '4' overrode detection on every run."""
        assert run_action().value_of("--workers") is None
        assert run_action({"workers": "8"}).value_of("--workers") == "8"

    def test_nothing_deprecated_is_reported(self, run_action: Any) -> None:
        """Defaults are not deprecated usage, so they must not warn."""
        assert run_action().warnings == []


class TestModeInputsReachTheLinter:
    """Each check's mode input passes straight through."""

    @pytest.mark.parametrize("mode", ["off", "report", "fix", "update"])
    def test_action_calls(self, run_action: Any, mode: str) -> None:
        """Args:
        mode: The mode requested.
        """
        assert (
            run_action({"action-calls": mode}).value_of("--action-calls")
            == mode
        )

    @pytest.mark.parametrize("mode", ["off", "report", "update"])
    def test_allow_list(self, run_action: Any, mode: str) -> None:
        """Args:
        mode: The mode requested.
        """
        assert run_action({"allow-list": mode}).value_of("--allow-list") == mode

    def test_an_unsupported_rung_is_left_to_the_cli(
        self, run_action: Any
    ) -> None:
        """'fix' reaches the CLI, which refuses it with the reason.

        A second copy of that refusal here would be a second place to
        keep in step with ``check_modes``.
        """
        assert (
            run_action({"allow-list": "fix"}).value_of("--allow-list") == "fix"
        )

    def test_verify_action_calls(self, run_action: Any) -> None:
        result = run_action({"verify-action-calls": "true"})
        assert "--verify-action-calls" in result.args

    def test_a_value_that_is_no_mode_is_refused(self, run_action: Any) -> None:
        """Refused before the linter runs, as a usage error."""
        result = run_action({"allow-list": "sometimes"})

        assert result.returncode == 2
        assert result.invocations == []
        assert "::error" in result.stdout


class TestDeprecatedInputsMeanWhatTheCliSays:
    """The Action's translation is pinned to the CLI's own derivation.

    Expectations come from ``_mode_from_*_flags`` rather than from this
    file, so the two cannot disagree about a deprecated input. A value
    that derives the check's default mode passes nothing, leaving the
    configuration file in charge exactly as before.
    """

    @pytest.mark.parametrize("auto_fix", ["true", "false"])
    @pytest.mark.parametrize("update_actions", ["true", "false"])
    def test_action_call_inputs(
        self, run_action: Any, auto_fix: str, update_actions: str
    ) -> None:
        """Args:
        auto_fix: The deprecated 'auto-fix' value.
        update_actions: The deprecated 'update-actions' value.
        """
        derived = _mode_from_action_call_flags(
            Config(
                auto_fix=auto_fix == "true",
                update_actions=update_actions == "true",
            )
        )
        expected = (
            None if derived is ACTION_CALLS.default_mode else derived.value
        )

        result = run_action(
            {"auto-fix": auto_fix, "update-actions": update_actions}
        )

        assert result.returncode == 0, result.stdout
        assert result.value_of("--action-calls") == expected

    @pytest.mark.parametrize("allow_list", ["", "true", "false"])
    @pytest.mark.parametrize("update_allow_list", ["true", "false"])
    def test_allow_list_inputs(
        self, run_action: Any, allow_list: str, update_allow_list: str
    ) -> None:
        """Args:
        allow_list: The deprecated boolean 'allow-list' value, or unset.
        update_allow_list: The deprecated 'update-allow-list' value.
        """
        config = Config()
        config.allow_list.enabled = allow_list != "false"
        config.allow_list.update = update_allow_list == "true"
        derived = _mode_from_allow_list_flags(config)
        expected = None if derived is ALLOW_LIST.default_mode else derived.value

        result = run_action(
            {"allow-list": allow_list, "update-allow-list": update_allow_list}
        )

        assert result.returncode == 0, result.stdout
        assert result.value_of("--allow-list") == expected

    def test_warnings_name_inputs_not_flags(self, run_action: Any) -> None:
        """The point of translating: advice an Action user can follow."""
        (warning,) = run_action({"auto-fix": "false"}).warnings

        assert "'action-calls: report'" in warning
        assert "--" not in warning

    def test_a_mode_input_settles_the_whole_behaviour(
        self, run_action: Any
    ) -> None:
        """And says which deprecated input it overrode."""
        result = run_action(
            {"action-calls": "report", "update-actions": "true"}
        )

        assert result.value_of("--action-calls") == "report"
        assert any("ignored" in warning for warning in result.warnings)


class TestTheSummaryOnlyClaimsWhatRan:
    """The step summary is read by people who never open the log."""

    def test_a_clean_run_is_reported_clean(self, run_action: Any) -> None:
        assert "All 7 action calls are valid" in run_action().summary

    def test_a_check_that_was_off_is_not_reported_valid(
        self, run_action: Any
    ) -> None:
        """No errors, because nothing looked -- not because all passed."""
        document = json.loads(json.dumps(CLEAN))
        document["checks"]["action-calls"] = {"mode": "off", "ran": False}

        summary = run_action({"action-calls": "off"}, document).summary

        assert "valid" not in summary
        assert "did not run" in summary

    def test_a_throttled_run_is_not_reported_valid(
        self, run_action: Any
    ) -> None:
        document = json.loads(json.dumps(CLEAN))
        document["rate_limited"] = True
        document["checks"]["action-calls"]["ran"] = False

        summary = run_action(document=document).summary

        assert "valid" not in summary
        assert "rate-limited" in summary

    def test_an_older_tool_is_summarised_as_before(
        self, run_action: Any
    ) -> None:
        """A document without the newer keys must not read as a failure.

        External callers run the latest release from PyPI, which need
        not be the release this ``action.yaml`` shipped with.
        """
        document = {
            "scan_summary": {"total_calls": 3},
            "validation_summary": {"total_errors": 0},
        }

        assert (
            "All 3 action calls are valid"
            in run_action(document=document).summary
        )
