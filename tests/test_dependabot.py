# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Tests for Dependabot cooldown discovery and parsing."""

from __future__ import annotations

import textwrap
from typing import TYPE_CHECKING

from gha_workflow_linter.dependabot import (
    DependabotCooldown,
    find_dependabot_config,
    resolve_cooldown,
)

if TYPE_CHECKING:
    from pathlib import Path

GITHUB_ACTIONS_CONFIG = textwrap.dedent(
    """\
    version: 2
    updates:
      - package-ecosystem: "github-actions"
        directory: "/"
        schedule:
          interval: "weekly"
        cooldown:
          default-days: 7
    """
)


def _write_dependabot(
    repo_root: Path, content: str, filename: str = "dependabot.yml"
) -> Path:
    github_dir = repo_root / ".github"
    github_dir.mkdir(parents=True, exist_ok=True)
    config_path = github_dir / filename
    config_path.write_text(content, encoding="utf-8")
    return config_path


class TestFindDependabotConfig:
    """Tests for locating the Dependabot configuration file."""

    def test_finds_yml_in_same_directory(self, tmp_path: Path) -> None:
        config_path = _write_dependabot(tmp_path, GITHUB_ACTIONS_CONFIG)
        assert find_dependabot_config(tmp_path) == config_path

    def test_finds_yaml_extension(self, tmp_path: Path) -> None:
        config_path = _write_dependabot(
            tmp_path, GITHUB_ACTIONS_CONFIG, filename="dependabot.yaml"
        )
        assert find_dependabot_config(tmp_path) == config_path

    def test_walks_up_directory_hierarchy(self, tmp_path: Path) -> None:
        config_path = _write_dependabot(tmp_path, GITHUB_ACTIONS_CONFIG)
        nested = tmp_path / "a" / "b" / "c"
        nested.mkdir(parents=True)
        assert find_dependabot_config(nested) == config_path

    def test_accepts_file_as_start_path(self, tmp_path: Path) -> None:
        config_path = _write_dependabot(tmp_path, GITHUB_ACTIONS_CONFIG)
        workflow = tmp_path / ".github" / "workflows" / "ci.yml"
        workflow.parent.mkdir(parents=True, exist_ok=True)
        workflow.write_text("name: ci\n", encoding="utf-8")
        assert find_dependabot_config(workflow) == config_path

    def test_returns_none_when_absent(self, tmp_path: Path) -> None:
        assert find_dependabot_config(tmp_path) is None

    def test_prefers_yml_over_yaml(self, tmp_path: Path) -> None:
        yml = _write_dependabot(tmp_path, GITHUB_ACTIONS_CONFIG)
        _write_dependabot(
            tmp_path, GITHUB_ACTIONS_CONFIG, filename="dependabot.yaml"
        )
        assert find_dependabot_config(tmp_path) == yml


class TestResolveCooldown:
    """Tests for resolving the cooldown value from configuration."""

    def test_resolves_github_actions_cooldown(self, tmp_path: Path) -> None:
        config_path = _write_dependabot(tmp_path, GITHUB_ACTIONS_CONFIG)
        result = resolve_cooldown(tmp_path)
        assert result == DependabotCooldown(
            days=7, source=config_path, ecosystem="github-actions"
        )

    def test_prefers_github_actions_over_other_ecosystems(
        self, tmp_path: Path
    ) -> None:
        content = textwrap.dedent(
            """\
            version: 2
            updates:
              - package-ecosystem: "uv"
                directory: "/"
                cooldown:
                  default-days: 3
              - package-ecosystem: "github-actions"
                directory: "/"
                cooldown:
                  default-days: 14
            """
        )
        _write_dependabot(tmp_path, content)
        result = resolve_cooldown(tmp_path)
        assert result is not None
        assert result.days == 14
        assert result.ecosystem == "github-actions"

    def test_falls_back_to_other_ecosystem(self, tmp_path: Path) -> None:
        content = textwrap.dedent(
            """\
            version: 2
            updates:
              - package-ecosystem: "uv"
                directory: "/"
                cooldown:
                  default-days: 5
            """
        )
        _write_dependabot(tmp_path, content)
        result = resolve_cooldown(tmp_path)
        assert result is not None
        assert result.days == 5
        assert result.ecosystem == "uv"

    def test_returns_none_without_cooldown(self, tmp_path: Path) -> None:
        content = textwrap.dedent(
            """\
            version: 2
            updates:
              - package-ecosystem: "github-actions"
                directory: "/"
                schedule:
                  interval: "weekly"
            """
        )
        _write_dependabot(tmp_path, content)
        assert resolve_cooldown(tmp_path) is None

    def test_returns_none_without_config(self, tmp_path: Path) -> None:
        assert resolve_cooldown(tmp_path) is None

    def test_ignores_invalid_default_days(self, tmp_path: Path) -> None:
        content = textwrap.dedent(
            """\
            version: 2
            updates:
              - package-ecosystem: "github-actions"
                directory: "/"
                cooldown:
                  default-days: "not-a-number"
            """
        )
        _write_dependabot(tmp_path, content)
        assert resolve_cooldown(tmp_path) is None

    def test_ignores_malformed_yaml(self, tmp_path: Path) -> None:
        _write_dependabot(tmp_path, "::: not valid yaml :::\n")
        assert resolve_cooldown(tmp_path) is None

    def test_zero_days_is_respected(self, tmp_path: Path) -> None:
        content = textwrap.dedent(
            """\
            version: 2
            updates:
              - package-ecosystem: "github-actions"
                directory: "/"
                cooldown:
                  default-days: 0
            """
        )
        _write_dependabot(tmp_path, content)
        result = resolve_cooldown(tmp_path)
        assert result is not None
        assert result.days == 0
