# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""The GitHub Action, the CLI and the README must describe one tool.

Three surfaces describe how the linter is driven -- ``action.yaml``, the
``lint`` command's options, and the README's input and output tables --
and they drift independently. By v1.6.0 they disagreed on four
defaults, the README omitted two outputs, and the Action could reach
neither of the per-check modes the CLI had just gained.

Nothing here restates any of the three. Each test reads the real
artefacts and cross-checks them, so adding a CLI option, an Action input
or a README row without the others fails the suite and names what is
missing. :data:`NOT_EXPOSED` is the one place a deliberate asymmetry is
recorded, with its reason, so omitting an option from the Action is a
decision rather than an oversight.
"""

from __future__ import annotations

from pathlib import Path
import re
from typing import Any

import pytest
import typer.main
import yaml

from gha_workflow_linter.check_modes import SPECS
from gha_workflow_linter.cli import app

ROOT = Path(__file__).resolve().parent.parent
ACTION = yaml.safe_load((ROOT / "action.yaml").read_text(encoding="utf-8"))
README = (ROOT / "README.md").read_text(encoding="utf-8")

#: The step that runs the linter, identified by its ``id``.
RUN_STEP_ID = "gha-workflow-linter"

#: ``lint`` options the Action deliberately does not offer, by parameter
#: name, with the reason. A new CLI option must either become reachable
#: from an input or be added here; there is no third state.
NOT_EXPOSED: dict[str, str] = {
    "github_token": (
        "read from the GITHUB_TOKEN environment variable, the documented "
        "way to authenticate the Action; an input would route the secret "
        "through the workflow's inputs"
    ),
    "verbose": "verbosity is set with the 'log-level' input",
    "quiet": "verbosity is set with the 'log-level' input",
    "cache_ttl": (
        "the Action always runs with --no-cache, so a TTL has nothing to govern"
    ),
    "files": (
        "serves pre-commit style invocations; the Action scans the 'path' input"
    ),
    "show_suppressed": (
        "diagnostic detail for interactive use; suppressed pins are still "
        "counted in the JSON summary"
    ),
    "multi_repo": "the Action runs against a single checkout",
    "repo_depth": "only meaningful with --multi-repo",
    "auto_fix": "deprecated spelling; the Action emits --action-calls",
    "update_actions": "deprecated spelling; the Action emits --action-calls",
    "auto_latest": "deprecated spelling; the Action emits --action-calls",
    "verify_actions_legacy": (
        "deprecated spelling; the Action emits --verify-action-calls"
    ),
    "no_allow_list": "deprecated spelling; the Action emits --allow-list",
    "update_allow_list": "deprecated spelling; the Action emits --allow-list",
    "_help": "not an operational option",
}

#: Flags placed in an argument array, or given on the ``lint``
#: invocation itself. Scoped to those forms on purpose: the script also
#: runs ``uvx --from ...``, and ``--from`` is not a linter option. The
#: script is matched after joining ``\``-continued lines, since a long
#: invocation is wrapped across several.
_ARRAY_LITERAL = re.compile(r"\b\w+\+?=\(([^)]*)\)")
_LINT_INVOCATION = re.compile(r"\$cmd_prefix lint ([^\n]*)")
_FLAG = re.compile(r"(?<![\w-])--[a-z][a-z0-9-]*")

_INPUT_BINDING = re.compile(r"^\$\{\{ inputs\.([a-z0-9-]+) \}\}$")


def _run_step() -> dict[str, Any]:
    """Return the composite step that runs the linter.

    Returns:
        The step mapping.
    """
    steps = ACTION["runs"]["steps"]
    matches = [step for step in steps if step.get("id") == RUN_STEP_ID]
    assert len(matches) == 1, f"expected one step with id {RUN_STEP_ID!r}"
    step: dict[str, Any] = matches[0]
    return step


def _emitted_flags() -> set[str]:
    """Return every linter flag the run script can pass.

    Returns:
        Flag spellings such as ``--no-parallel``.
    """
    script = _run_step()["run"].replace("\\\n", " ")
    fragments = [m.group(1) for m in _ARRAY_LITERAL.finditer(script)]
    fragments += [m.group(1) for m in _LINT_INVOCATION.finditer(script)]
    return {flag for text in fragments for flag in _FLAG.findall(text)}


def _lint_params() -> dict[str, Any]:
    """Return the ``lint`` command's parameters, by name.

    Read from the Typer command itself, so the CLI's surface is never
    restated in this file.

    Returns:
        Click parameters keyed by their Python name.
    """
    command = typer.main.get_command(app).commands["lint"]  # type: ignore[attr-defined]
    return {param.name: param for param in command.params}


def _spellings(param: Any) -> set[str]:
    """Return every command-line spelling of a parameter.

    Args:
        param: A Click parameter.

    Returns:
        Its long and short options, positive and negative.
    """
    return {*param.opts, *getattr(param, "secondary_opts", [])}


def _readme_table(heading: str) -> dict[str, list[str]]:
    """Parse one README table into rows keyed by their first cell.

    Args:
        heading: The level-two heading the table sits under.

    Returns:
        Remaining cells of each row, stripped, keyed by the unquoted
        first cell.
    """
    match = re.search(
        rf"^## {re.escape(heading)}\n(.*?)(?=^## )", README, re.M | re.S
    )
    assert match, f"README has no '## {heading}' section"
    rows: dict[str, list[str]] = {}
    for line in match.group(1).splitlines():
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if len(cells) < 2 or not cells[0].startswith("`"):
            continue
        rows[cells[0].strip("`")] = cells[1:]
    return rows


def _readme_default(cell: str) -> str | None:
    """Normalise a README default cell to the value it documents.

    Args:
        cell: The cell text, such as ``\\`true\\``` or empty.

    Returns:
        The value without code quoting, or None for an empty cell.
    """
    value = cell.strip().strip("`")
    return value or None


class TestInputsAreWired:
    """Every input reaches the script, and nothing else does."""

    def test_every_input_is_bound_to_the_run_step(self) -> None:
        """An unbound input is accepted from callers and silently ignored."""
        bound = {
            match.group(1)
            for value in _run_step()["env"].values()
            if (match := _INPUT_BINDING.match(str(value)))
        }
        unbound = set(ACTION["inputs"]) - bound
        assert not unbound, f"inputs never reach the script: {sorted(unbound)}"

    def test_every_binding_names_a_real_input(self) -> None:
        """A misspelt binding evaluates to empty, which looks like 'unset'."""
        for name, value in _run_step()["env"].items():
            match = _INPUT_BINDING.match(str(value))
            if match:
                assert match.group(1) in ACTION["inputs"], (
                    f"{name} binds unknown input {match.group(1)!r}"
                )

    def test_the_script_contains_no_expressions(self) -> None:
        """Inputs arrive through the environment, never by interpolation.

        An expression inside ``run:`` is substituted into the shell
        source before it executes, so a crafted input becomes code. The
        bindings above are the safe route, and this keeps it the only one.
        """
        assert "${{" not in _run_step()["run"]


class TestEmittedFlagsExist:
    """The Action cannot pass a flag the CLI does not accept."""

    def test_every_emitted_flag_is_a_lint_option(self) -> None:
        """A typo here fails every run that sets the input, at runtime."""
        known = {
            spelling
            for param in _lint_params().values()
            for spelling in _spellings(param)
        }
        unknown = _emitted_flags() - known
        assert not unknown, (
            f"the Action passes unknown flags: {sorted(unknown)}"
        )

    def test_no_deprecated_spelling_is_emitted(self) -> None:
        """The Action translates its deprecated inputs itself.

        Passing the CLI's deprecated flags through made the CLI tell
        Action users to write a flag no Action input could set.
        """
        params = _lint_params()
        deprecated = {
            spelling
            for name, reason in NOT_EXPOSED.items()
            if reason.startswith("deprecated")
            for spelling in _spellings(params[name])
        }
        leaked = _emitted_flags() & deprecated
        assert not leaked, f"deprecated flags still emitted: {sorted(leaked)}"


class TestEveryCliOptionIsAccountedFor:
    """Adding a CLI option forces a decision about the Action."""

    def test_every_option_is_reachable_or_exempt(self) -> None:
        emitted = _emitted_flags()
        unaccounted = [
            name
            for name, param in _lint_params().items()
            if param.param_type_name == "option"
            and name not in NOT_EXPOSED
            and not (_spellings(param) & emitted)
        ]
        assert not unaccounted, (
            f"lint options the Action neither exposes nor exempts: "
            f"{sorted(unaccounted)} -- add an input, or record the reason "
            f"in NOT_EXPOSED"
        )

    def test_exemptions_name_real_options(self) -> None:
        """A stale exemption would quietly outlive the option it excused."""
        stale = set(NOT_EXPOSED) - set(_lint_params())
        assert not stale, f"NOT_EXPOSED names no such option: {sorted(stale)}"

    def test_nothing_is_both_reachable_and_exempt(self) -> None:
        """An exemption for a reachable option is a wrong reason on record."""
        params = _lint_params()
        emitted = _emitted_flags()
        contradictory = sorted(
            name
            for name in NOT_EXPOSED
            if name in params and _spellings(params[name]) & emitted
        )
        assert not contradictory, f"exempt yet emitted: {contradictory}"

    def test_every_positional_argument_has_an_input(self) -> None:
        """``path`` is positional, so no flag can show it is reached."""
        for name, param in _lint_params().items():
            if param.param_type_name == "argument":
                assert name.replace("_", "-") in ACTION["inputs"]

    @pytest.mark.parametrize("spec", list(SPECS.values()), ids=str)
    def test_every_check_has_a_mode_input(self, spec: Any) -> None:
        """Each check's mode is reachable, under the name the CLI uses.

        Registered from :mod:`gha_workflow_linter.check_modes`, so a new
        check fails here until the Action can switch it.

        Args:
            spec: The check's specification.
        """
        assert spec.id.value in ACTION["inputs"], (
            f"no Action input for {spec.flag}"
        )
        assert spec.flag in _emitted_flags(), (
            f"input {spec.id.value!r} never emits {spec.flag}"
        )


class TestReadmeMatchesAction:
    """The README tables describe the Action that ships."""

    def test_inputs_table_lists_exactly_the_inputs(self) -> None:
        documented = set(_readme_table("GitHub Action Inputs"))
        declared = set(ACTION["inputs"])
        assert documented == declared, (
            f"undocumented: {sorted(declared - documented)}; "
            f"documented but absent: {sorted(documented - declared)}"
        )

    def test_documented_defaults_are_the_real_ones(self) -> None:
        """Four of these disagreed at v1.6.0, silently."""
        rows = _readme_table("GitHub Action Inputs")
        wrong = {
            name: (
                _readme_default(rows[name][-1]),
                ACTION["inputs"][name].get("default"),
            )
            for name in ACTION["inputs"]
            if name in rows
            and _readme_default(rows[name][-1])
            != ACTION["inputs"][name].get("default")
        }
        assert not wrong, f"README default vs action.yaml: {wrong}"

    def test_outputs_table_lists_exactly_the_outputs(self) -> None:
        documented = set(_readme_table("GitHub Action Outputs"))
        declared = set(ACTION["outputs"])
        assert documented == declared, (
            f"undocumented: {sorted(declared - documented)}; "
            f"documented but absent: {sorted(documented - declared)}"
        )
