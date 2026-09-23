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

#: The step summary's claim of success. Asserted against by marker
#: rather than by the word "valid", which also appears inside the
#: "validation errors" of honest failure messages.
SUCCESS = "✅"

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
with open(os.environ["STUB_LOG"], encoding="utf-8") as log:
    invocation = sum(1 for line in log if line.strip())
args = sys.argv[1:]
status = int(os.environ.get("STUB_EXIT", "0"))
if "STUB_JSON_RAW" in os.environ:
    document = os.environ["STUB_JSON_RAW"]
else:
    source = os.environ["STUB_DOCUMENT"]
    if invocation > 1 and "STUB_LATER_DOCUMENT" in os.environ:
        source = os.environ["STUB_LATER_DOCUMENT"]
    with open(source, encoding="utf-8") as answer:
        document = answer.read()
if "--json-output" in args and "STUB_NO_JSON_OUTPUT" not in os.environ:
    target = args[args.index("--json-output") + 1]
    with open(target, "w", encoding="utf-8") as written:
        written.write(document)
if "--format" in args and args[args.index("--format") + 1] == "json":
    sys.stdout.write(document)
else:
    print("linter text output")
sys.exit(status)
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
        outputs: Step outputs, by name.
    """

    def __init__(
        self,
        returncode: int,
        stdout: str,
        invocations: list[list[str]],
        summary: str,
        outputs: dict[str, str],
    ) -> None:
        """Record a run.

        Args:
            returncode: The script's exit status.
            stdout: What the script wrote.
            invocations: Argument lists the linter received.
            summary: The step summary contents.
            outputs: Step outputs written to ``GITHUB_OUTPUT``.
        """
        self.returncode = returncode
        self.stdout = stdout
        self.invocations = invocations
        self.summary = summary
        self.outputs = outputs

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


def _parse_outputs(text: str) -> dict[str, str]:
    """Parse ``GITHUB_OUTPUT`` in both of its forms.

    Args:
        text: The file's contents: ``name=value`` lines, and
            ``name<<DELIM`` blocks ended by a line reading ``DELIM``.

    Returns:
        Output values by name.
    """
    outputs: dict[str, str] = {}
    lines = iter(text.splitlines())
    for line in lines:
        if "<<" in line:
            name, delimiter = line.split("<<", 1)
            block = []
            for inner in lines:
                if inner == delimiter:
                    break
                block.append(inner)
            outputs[name] = "\n".join(block)
        elif "=" in line:
            name, value = line.split("=", 1)
            outputs[name] = value
    return outputs


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
        exit_status: int = 0,
        json_raw: str | None = None,
        later_document: dict[str, Any] | None = None,
        writes_json_output: bool = True,
    ) -> Run:
        """Execute the script.

        Args:
            inputs: Values keyed by Action input name. Unnamed inputs get
                their declared default, else empty -- what GitHub passes.
            document: What the stub reports, both in the ``--json-output``
                file and on stdout under ``--format json``.
            exit_status: What every stub invocation exits with.
            json_raw: Raw text to report in place of ``document``, such
                as nothing, or something that is not JSON.
            later_document: What any invocation after the first reports:
                the tree as a fixing run left it. A script that asks
                twice then publishes the second, wrong, answer.
            writes_json_output: False to impersonate a linter that
                accepts no ``--json-output`` and leaves the file empty.

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
        runner_temp = tmp_path / "runner_temp"
        runner_temp.mkdir(exist_ok=True)

        env = {
            "PATH": f"{stub_dir}{os.pathsep}{os.environ['PATH']}",
            "USE_UVX": "false",
            "RUNNER_TEMP": str(runner_temp),
            "GITHUB_OUTPUT": str(output),
            "GITHUB_STEP_SUMMARY": str(summary),
            "STUB_LOG": str(log),
            "STUB_DOCUMENT": str(answer),
            "STUB_EXIT": str(exit_status),
        }
        if json_raw is not None:
            env["STUB_JSON_RAW"] = json_raw
        if later_document is not None:
            later = tmp_path / "later_document.json"
            later.write_text(json.dumps(later_document), encoding="utf-8")
            env["STUB_LATER_DOCUMENT"] = str(later)
        if not writes_json_output:
            env["STUB_NO_JSON_OUTPUT"] = "1"
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
            _parse_outputs(output.read_text(encoding="utf-8")),
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


class TestCallerDataCannotIssueWorkflowCommands:
    """An input value must never become a workflow command.

    GitHub reads every stdout line beginning ``::`` as a command. An
    input echoed verbatim can therefore carry a newline and a command of
    its own, forging an annotation. zizmor does not catch this: its
    template-injection audit concerns ``${{ }}`` in ``run:``, and here
    the value arrives safely through the environment and is only
    dangerous once echoed.
    """

    PAYLOAD = "bad\n::warning title=Injected::payload"

    def test_an_invalid_value_cannot_inject_a_command(
        self, run_action: Any
    ) -> None:
        result = run_action({"allow-list": self.PAYLOAD})

        assert result.returncode == 2
        forged = [
            line
            for line in result.stdout.splitlines()
            if "Injected" in line and line.startswith("::warning")
        ]
        assert not forged, f"injected command survived: {forged}"

    def test_escaping_preserves_what_the_value_said(
        self, run_action: Any
    ) -> None:
        """``%`` is escaped first, so a newline's escape survives intact.

        This is fidelity, not security. The runner splits stdout into
        commands on *raw* newlines before decoding, so no raw newline
        reaching stdout is the whole of the security property, and both
        orders achieve it. Escaping ``%`` last, though, turns the
        ``%0A`` written for a newline into ``%250A``, which GitHub
        renders as the literal text ``%0A`` -- the reader sees a value
        that was never given.
        """
        result = run_action({"allow-list": "a\nb"})

        (error,) = [
            line
            for line in result.stdout.splitlines()
            if line.startswith("::error")
        ]
        assert "a%0Ab" in error
        assert "%250A" not in error

    def test_the_refusal_still_says_what_was_wrong(
        self, run_action: Any
    ) -> None:
        """Escaping must not cost the reader the actual value."""
        result = run_action({"allow-list": "sometimes"})

        (error,) = [
            line
            for line in result.stdout.splitlines()
            if line.startswith("::error")
        ]
        assert "sometimes" in error
        assert "off, report or update" in error

    def test_every_command_is_a_single_line(self, run_action: Any) -> None:
        """No output line may start a command it did not intend to.

        Across every deprecation path, each ``::`` line must be one this
        script meant to write -- a warning or the one error -- so a
        future message that echoes caller data trips this too.
        """
        for inputs in (
            {"auto-fix": "false", "update-actions": "true"},
            {"allow-list": "false", "update-allow-list": "true"},
            {"action-calls": "report", "auto-fix": "false"},
            {"allow-list": self.PAYLOAD},
        ):
            commands = [
                line
                for line in run_action(inputs).stdout.splitlines()
                if line.startswith("::")
            ]
            assert all(
                line.startswith(
                    (
                        "::warning title=Deprecated input::",
                        "::error title=Invalid input::",
                        "::error title=No results::",
                    )
                )
                for line in commands
            ), f"unexpected workflow command from {inputs}: {commands}"


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


class TestAFailingRunStillReports:
    """The linter failing is when the outputs matter most.

    Under GitHub's ``bash -e``, a failing lint invocation used to abort
    the step on the spot, so ``errors-found`` and the step summary were
    only ever written when there was nothing to report. The linter's
    status must still be the step's -- so the job fails -- but only
    after the outputs are recorded.
    """

    DEFECTS = {
        **CLEAN,
        "validation_summary": {"total_errors": 2},
    }

    @pytest.mark.parametrize("output_format", ["text", "json"])
    @pytest.mark.parametrize("status", [1, 5])
    def test_outputs_and_summary_are_written(
        self, run_action: Any, output_format: str, status: int
    ) -> None:
        """Defects exit 1; outdated calls under verification exit 5.

        Args:
            output_format: The Action's 'output-format' input.
            status: What the linter exits with.
        """
        result = run_action(
            {"output-format": output_format},
            self.DEFECTS,
            exit_status=status,
        )

        assert result.returncode == status
        assert result.outputs["errors-found"] == "2"
        assert result.outputs["total-calls"] == "7"
        assert "Found 2 validation errors" in result.summary

    def test_the_scan_summary_is_the_real_document(
        self, run_action: Any
    ) -> None:
        """A failing JSON run must not append a fallback to its output.

        ``$(linter || echo '{}')`` captures the linter's document *and*
        the fallback when the linter fails, producing two JSON values
        that no consumer of 'scan-summary' can parse.
        """
        result = run_action(document=self.DEFECTS, exit_status=1)

        assert json.loads(result.outputs["scan-summary"]) == self.DEFECTS

    def test_success_still_exits_zero(self, run_action: Any) -> None:
        assert run_action().returncode == 0


class TestOutputsNeverComeFromNothing:
    """No success is claimed without a document to base it on.

    The ``--json-output`` file is the only source of the machine-readable
    outputs. A linter that leaves it empty -- one that crashed, or an
    older release that refuses the option -- must not have its silence
    read as a clean result: an empty object yields "All 0 action calls
    are valid".
    """

    @pytest.mark.parametrize("output_format", ["text", "json"])
    def test_a_linter_that_writes_no_document_fails_the_step(
        self, run_action: Any, output_format: str
    ) -> None:
        """Even when the linter itself exits zero.

        Args:
            output_format: The Action's 'output-format' input.
        """
        result = run_action(
            {"output-format": output_format}, writes_json_output=False
        )

        assert result.returncode != 0
        assert SUCCESS not in result.summary
        assert "::error title=No results::" in result.stdout
        assert json.loads(result.outputs["scan-summary"]) == {}

    def test_the_linter_status_is_kept_when_the_document_is_missing(
        self, run_action: Any
    ) -> None:
        """A refused option exits 2; that, not a generic 1, is reported."""
        result = run_action(exit_status=2, writes_json_output=False)

        assert result.returncode == 2

    @pytest.mark.parametrize("output_format", ["text", "json"])
    @pytest.mark.parametrize(
        "raw",
        [
            "",
            "not json",
            "[]",
            "{}",
            "{}\n{}",
            '{"scan_summary": {"total_calls": 1}}',
        ],
        ids=[
            "empty",
            "malformed",
            "array",
            "empty-object",
            "two-objects",
            "no-validation-summary",
        ],
    )
    def test_an_unusable_document_is_not_a_clean_result(
        self, run_action: Any, output_format: str, raw: str
    ) -> None:
        """Anything but one linter document means no answer.

        ``{}`` is an object, and passed a type check, yet it yields zero
        errors from zero calls -- "all valid". ``{}`` twice is a stream
        of two values that each passed, and would have been published as
        an unparsable 'scan-summary'. So a document must be exactly one
        object, carrying the summaries the outputs are read from.

        Args:
            output_format: The Action's 'output-format' input.
            raw: What the JSON run printed, with a zero status.
        """
        result = run_action({"output-format": output_format}, json_raw=raw)

        assert result.returncode != 0
        assert SUCCESS not in result.summary
        assert result.outputs["errors-found"] == "0"
        # Whatever is published must be one value a consumer can parse.
        assert json.loads(result.outputs["scan-summary"]) == {}


class TestOneRunServesBothOutputs:
    """The reader and the outputs must describe the same run.

    Text mode used to run the linter a second time, with ``--format
    json``, for the outputs. Under ``fix`` or ``update`` the first run
    rewrote the tree, so the second examined the repaired files and
    published zero errors, zero stale pins and zero fixes for exactly the
    findings the step had acted on.
    """

    @pytest.mark.parametrize("output_format", ["text", "json"])
    def test_the_linter_runs_once(
        self, run_action: Any, output_format: str
    ) -> None:
        """Args:
        output_format: The Action's 'output-format' input.
        """
        result = run_action({"output-format": output_format})

        assert len(result.invocations) == 1
        assert result.value_of("--format") == output_format
        assert result.value_of("--json-output")

    @pytest.mark.parametrize("output_format", ["text", "json"])
    @pytest.mark.parametrize("mode", ["fix", "update"])
    def test_outputs_describe_the_run_that_fixed(
        self, run_action: Any, output_format: str, mode: str
    ) -> None:
        """Any later look at the tree would find it already repaired.

        Args:
            output_format: The Action's 'output-format' input.
            mode: A mode that rewrites files.
        """
        before = {
            **CLEAN,
            "validation_summary": {"total_errors": 2},
            "allow_list": {"summary": {"stale": 3, "fixed": 3}},
        }
        after = {
            **CLEAN,
            "allow_list": {"summary": {"stale": 0, "fixed": 0}},
        }

        result = run_action(
            {
                "output-format": output_format,
                "action-calls": mode,
                "allow-list": "update",
            },
            before,
            exit_status=1,
            later_document=after,
        )

        assert result.outputs["errors-found"] == "2"
        assert result.outputs["allow-list-stale"] == "3"
        assert result.outputs["allow-list-fixed"] == "3"
        assert json.loads(result.outputs["scan-summary"]) == before
        assert "Found 2 validation errors" in result.summary

    def test_an_argument_spelled_text_survives(self, run_action: Any) -> None:
        """Arguments once were filtered by value, deleting any ``text``."""
        result = run_action({"exclude": "text"})

        assert result.value_of("--exclude") == "text"

    def test_the_document_file_is_removed(
        self, run_action: Any, tmp_path: Path
    ) -> None:
        """The runner's temporary directory outlives the step.

        Args:
            tmp_path: The fixture's scratch directory, which holds the
                ``RUNNER_TEMP`` it provides.
        """
        result = run_action()

        written = result.value_of("--json-output") or ""
        assert written.startswith(str(tmp_path / "runner_temp"))
        assert not list((tmp_path / "runner_temp").iterdir())


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

        assert SUCCESS not in summary
        assert "did not run" in summary

    def test_a_throttled_run_is_not_reported_valid(
        self, run_action: Any
    ) -> None:
        document = json.loads(json.dumps(CLEAN))
        document["rate_limited"] = True
        document["checks"]["action-calls"]["ran"] = False

        summary = run_action(document=document).summary

        assert SUCCESS not in summary
        assert "rate-limited" in summary

    @pytest.mark.parametrize("status", [1, 3, 4, 5])
    def test_a_failing_step_never_claims_success(
        self, run_action: Any, status: int
    ) -> None:
        """Zero validation errors is not a pass when the step fails.

        Outdated calls under ``verify-action-calls`` exit 5, and stale or
        unresolved allow-list pins exit 3 and 4, all with
        ``total_errors`` at 0: those findings live elsewhere in the
        document, or nowhere in it. A fixer that rewrote files exits 1,
        also with no validation errors left. The summary is keyed on the
        status rather than on one count, so every such status is covered
        without this file restating the exit-code table.

        Args:
            status: A failing exit status with no validation errors.
        """
        summary = run_action(exit_status=status).summary

        assert SUCCESS not in summary
        assert f"exit status {status}" in summary

    def test_a_setup_failure_is_reported_as_a_failure(
        self, run_action: Any
    ) -> None:
        """Not as a check that quietly did not run.

        A refused invocation emits a real document whose checks all
        report ``ran: false``. Consulting that before the status told
        the reader a check had been skipped, above a job that had failed.
        """
        document = {
            "rate_limited": False,
            "checks": {
                "action-calls": {"mode": None, "ran": False},
                "allow-list": {"mode": None, "ran": False},
            },
            "error": "Configuration error: unsupported mode",
            "scan_summary": {},
            "validation_summary": {},
        }

        summary = run_action(document=document, exit_status=1).summary

        assert SUCCESS not in summary
        assert "exit status 1" in summary
        assert "did not run" not in summary

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
