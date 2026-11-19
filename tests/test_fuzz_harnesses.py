# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Replay the fuzz harnesses' seeds, and show each oracle can fail.

The harnesses under ``tests/fuzz`` run under Atheris; this runs their
seeds through the same checks without it, and feeds each oracle a
deliberately wrong result to prove it rejects one.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
import sys
from typing import TYPE_CHECKING

import pytest

from gha_workflow_linter.allow_list_spec import resolve_spec
from gha_workflow_linter.directives import (
    Directive,
    Suppression,
    SuppressionSource,
    parse_trailing_comment,
)
from gha_workflow_linter.shell import _yaml
from gha_workflow_linter.stderr_merge import StderrMergeResult
from tests.fuzz import (
    fuzz_grammars,
    fuzz_shell_analyses,
    fuzz_yaml_reader,
)
from tests.fuzz._common import ContractBreach, fuzzer_args

if TYPE_CHECKING:
    from collections.abc import Callable

HARNESSES = (fuzz_yaml_reader, fuzz_shell_analyses, fuzz_grammars)
ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize(
    ("check", "seed"),
    [
        pytest.param(h.check, seed, id=f"{h.__name__.rsplit('.')[-1]}-{n}")
        for h in HARNESSES
        for n, seed in enumerate(h.SEEDS)
    ],
)
def test_seed_holds(check: Callable[[bytes], None], seed: bytes) -> None:
    """Every seed meets the contract its harness checks."""
    check(seed)


def test_harnesses_import_without_the_fuzzer() -> None:
    """Importing a harness loads no fuzzing engine."""
    assert "atheris" not in sys.modules


def test_only_harnesses_name_the_fuzzer() -> None:
    """The discovery text appears in the harness files alone."""
    text = "import " + "atheris"
    named = {
        path.relative_to(ROOT).as_posix()
        for top in ("src", "tests", "scripts", "examples", "docs")
        for path in (ROOT / top).rglob("*.py")
        if text in path.read_text(encoding="utf-8")
    }
    assert named == {
        f"tests/fuzz/{h.__name__.rsplit('.')[-1]}.py" for h in HARNESSES
    }


def test_fuzzer_args_append_seeds_unless_a_file_is_named(
    tmp_path: Path,
) -> None:
    """Seeds follow any corpus directory, and a named file runs alone."""
    seed = tmp_path / "input"
    seed.write_bytes(b"x")
    assert fuzzer_args(["h"], "seeds") == ["h", "seeds"]
    assert fuzzer_args(["h", "-runs=0", str(tmp_path)], "seeds") == [
        "h",
        "-runs=0",
        str(tmp_path),
        "seeds",
    ]
    assert fuzzer_args(["h", str(seed)], "seeds") == ["h", str(seed)]


def rejects(call: Callable[[], object]) -> None:
    """``call`` raises the harnesses' contract breach."""
    with pytest.raises(ContractBreach):
        call()


class TestYamlReaderOracles:
    """Each ``fuzz_yaml_reader`` oracle rejects a wrong result."""

    def test_scrub_that_keeps_a_marker(self) -> None:
        rejects(lambda: fuzz_yaml_reader.verify_scrub("a\ue000", "a\ue000"))

    def test_scrub_that_changes_other_text(self) -> None:
        rejects(lambda: fuzz_yaml_reader.verify_scrub("ab", "a\ufffd"))

    def test_expression_missed(self) -> None:
        rejects(lambda: fuzz_yaml_reader.verify_expressions("${{ a }}", []))

    def test_expression_run_past_its_end(self) -> None:
        text = "${{ a }} b }}"
        found = [(0, len(text), "a }} b")]
        rejects(lambda: fuzz_yaml_reader.verify_expressions(text, found))

    def test_expression_closed_inside_quotes(self) -> None:
        text = "${{ 'a}}' }}"
        found = [(0, 8, "'a")]
        rejects(lambda: fuzz_yaml_reader.verify_expressions(text, found))

    def test_round_trip_that_loses_an_expression(self) -> None:
        rejects(lambda: fuzz_yaml_reader.verify_round_trip("a${{ x }}", "a"))

    def test_block_mapped_past_the_file(self) -> None:
        text = "jobs:\n  a:\n    steps:\n      - run: echo\n"
        found = _yaml.read(text, "workflow")
        found.blocks[0].starts = [(0, 9)]
        rejects(lambda: fuzz_yaml_reader.verify_read(text, found))

    def test_text_mapped_to_the_line_after_the_file(self) -> None:
        text = "jobs:\n  a:\n    steps:\n      - run: echo"
        found = _yaml.read(text, "workflow")
        found.blocks[0].starts = [(0, 5)]
        rejects(lambda: fuzz_yaml_reader.verify_read(text, found))

    def test_block_text_that_is_not_its_value(self) -> None:
        text = "jobs:\n  a:\n    steps:\n      - run: echo\n"
        found = _yaml.read(text, "workflow")
        found.blocks[0].text = "echo something else"
        rejects(lambda: fuzz_yaml_reader.verify_read(text, found))


class TestShellAnalysesOracles:
    """Each ``fuzz_shell_analyses`` oracle rejects a wrong result."""

    def test_finding_past_the_last_line(self) -> None:
        rejects(lambda: fuzz_shell_analyses.verify_lines("a\nb", [3], "x"))

    def test_finding_before_the_first_line(self) -> None:
        rejects(lambda: fuzz_shell_analyses.verify_lines("a", [0], "x"))

    def test_finding_with_another_path(self) -> None:
        rejects(lambda: fuzz_shell_analyses.verify_paths(["b.sh"], "x"))

    def test_scan_that_read_no_file(self) -> None:
        result = StderrMergeResult([], 0)
        rejects(lambda: fuzz_shell_analyses.verify_repository(result))

    def test_problem_naming_another_file(self) -> None:
        result = StderrMergeResult([], 1, ("b.sh: broken",))
        rejects(lambda: fuzz_shell_analyses.verify_repository(result))

    def test_problem_reported_twice(self) -> None:
        problem = f"{fuzz_shell_analyses.PATH}: broken"
        result = StderrMergeResult([], 1, (problem, problem))
        rejects(lambda: fuzz_shell_analyses.verify_repository(result))


class TestGrammarOracles:
    """Each ``fuzz_grammars`` oracle rejects a wrong result."""

    def test_source_form_that_changes_the_spec(self) -> None:
        rejects(
            lambda: fuzz_grammars.verify_source_form("lfit@main", "lfit@ma")
        )

    def test_source_form_that_drops_the_ref(self) -> None:
        rejects(
            lambda: fuzz_grammars.verify_source_form("lfit@main #c", "lfit")
        )

    def test_rendered_spec_that_does_not_resolve(self) -> None:
        rejects(lambda: fuzz_grammars.resolve_again("lfit@a@b"))

    def test_ref_bump_that_misses_the_ref(self) -> None:
        resolved = resolve_spec("lfit@main", workflow_org="lfit")
        again = resolve_spec("lfit@v3", workflow_org="lfit")
        rejects(lambda: fuzz_grammars.verify_ref_bump(resolved, "v2", again))

    def test_ref_bump_that_moves_the_repository(self) -> None:
        resolved = resolve_spec("lfit@main", workflow_org="lfit")
        again = resolve_spec("lfit/other@v2", workflow_org="lfit")
        rejects(lambda: fuzz_grammars.verify_ref_bump(resolved, "v2", again))

    def test_comment_that_loses_a_directive(self) -> None:
        parsed = parse_trailing_comment("v1 allow-list-pin-ok -- why")
        again = parse_trailing_comment("v1 -- why")
        rejects(lambda: fuzz_grammars.verify_comment(parsed, "v1", again))

    def test_comment_that_keeps_the_old_version(self) -> None:
        parsed = parse_trailing_comment("v1 extra")
        again = replace(parsed)
        rejects(lambda: fuzz_grammars.verify_comment(parsed, "v2", again))

    def test_preceding_directive_the_line_does_not_name(self) -> None:
        line = "# gha-workflow-linter: stderr-merge-ok"
        found = Suppression(
            frozenset({Directive.STDERR_MERGE_OK, Directive.PYTHON_PATH_OK}),
            SuppressionSource.PRECEDING_LINE,
            None,
        )
        rejects(lambda: fuzz_grammars.verify_preceding(line, found))

    def test_preceding_reason_the_line_does_not_hold(self) -> None:
        line = "# gha-workflow-linter: stderr-merge-ok"
        found = Suppression(
            frozenset({Directive.STDERR_MERGE_OK}),
            SuppressionSource.PRECEDING_LINE,
            "invented",
        )
        rejects(lambda: fuzz_grammars.verify_preceding(line, found))
