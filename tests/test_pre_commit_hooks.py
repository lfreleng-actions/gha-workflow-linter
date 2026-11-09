# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""The published pre-commit hooks run what they claim to."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from typer.testing import CliRunner
import yaml

from gha_workflow_linter import exit_codes
from gha_workflow_linter.cli import app

ROOT = Path(__file__).resolve().parent.parent
HOOKS: dict[str, dict[str, Any]] = {
    hook["id"]: hook
    for hook in yaml.safe_load(
        (ROOT / ".pre-commit-hooks.yaml").read_text(encoding="utf-8")
    )
}


def _run_hook(hook_id: str, root: Path) -> int:
    args = [
        root.as_posix() if arg == "." else arg for arg in HOOKS[hook_id]["args"]
    ]
    return CliRunner().invoke(app, args).exit_code


class TestStderrMergeHook:
    """``gha-stderr-merge`` fails a commit on a merged stream used as data."""

    def test_it_runs_offline(self) -> None:
        """Both checks that reach the GitHub API are switched off."""
        args = HOOKS["gha-stderr-merge"]["args"]

        assert args[args.index("--action-calls") + 1] == "off"
        assert args[args.index("--allow-list") + 1] == "off"

    def test_it_fails_on_a_finding(self, tmp_path: Path) -> None:
        (tmp_path / ".git").mkdir()
        (tmp_path / "fetch.sh").write_text("curl -s x 2>&1 | jq .\n")

        code = _run_hook("gha-stderr-merge", tmp_path)

        assert code == exit_codes.STDERR_MERGE_FOUND

    def test_it_passes_a_clean_tree(self, tmp_path: Path) -> None:
        (tmp_path / ".git").mkdir()
        (tmp_path / "fetch.sh").write_text("curl -s x 2>/dev/null | jq .\n")

        assert _run_hook("gha-stderr-merge", tmp_path) == exit_codes.SUCCESS

    def test_it_triggers_on_shell_and_yaml(self) -> None:
        hook = HOOKS["gha-stderr-merge"]

        assert set(hook["types_or"]) == {"yaml", "shell"}
        assert hook["pass_filenames"] is False
