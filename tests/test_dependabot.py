# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Tests for Dependabot cooldown discovery and parsing."""

from __future__ import annotations

import textwrap
import time
from typing import TYPE_CHECKING

import pytest

from gha_workflow_linter.dependabot import (
    DependabotCooldown,
    cooldown_applies,
    dependency_name,
    find_dependabot_config,
    fnmatch_ruby,
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


class TestRepositoryBoundary:
    """A cooldown is the scanned repository's own release policy.

    The search walks upwards, which is right within a checkout but wrong
    past its root: a sweep container carrying a Dependabot file would
    otherwise impose its cooldown on every repository beneath it, and a
    lone checkout would answer differently depending on where it was
    cloned.
    """

    @staticmethod
    def _make_repository(path: Path) -> Path:
        """Create a directory that looks like a checkout.

        Args:
            path: Directory to create; parents are created as needed.

        Returns:
            The same path, now carrying a ``.git`` directory.
        """
        (path / ".git").mkdir(parents=True)
        return path

    def test_a_checkout_does_not_inherit_its_containers_cooldown(
        self, tmp_path: Path
    ) -> None:
        """The container's policy stops at the repository boundary.

        Args:
            tmp_path: Container directory, carrying a Dependabot file.
        """
        _write_dependabot(tmp_path, GITHUB_ACTIONS_CONFIG)
        repository = self._make_repository(tmp_path / "checkout")

        assert find_dependabot_config(repository) is None

    def test_a_checkouts_own_configuration_is_still_found(
        self, tmp_path: Path
    ) -> None:
        """The boundary is checked after the directory's own file.

        Args:
            tmp_path: Container directory, carrying a Dependabot file.
        """
        _write_dependabot(tmp_path, GITHUB_ACTIONS_CONFIG)
        repository = self._make_repository(tmp_path / "checkout")
        own = _write_dependabot(repository, GITHUB_ACTIONS_CONFIG)

        assert find_dependabot_config(repository) == own

    def test_a_subdirectory_still_reaches_the_repository_root(
        self, tmp_path: Path
    ) -> None:
        """Walking up within a checkout is the behaviour being kept.

        Args:
            tmp_path: Container directory.
        """
        repository = self._make_repository(tmp_path / "checkout")
        own = _write_dependabot(repository, GITHUB_ACTIONS_CONFIG)
        nested = repository / "a" / "b"
        nested.mkdir(parents=True)

        assert find_dependabot_config(nested) == own

    def test_a_worktree_marker_file_is_also_a_boundary(
        self, tmp_path: Path
    ) -> None:
        """Worktrees and submodules mark their root with a ``.git`` file.

        Args:
            tmp_path: Container directory, carrying a Dependabot file.
        """
        _write_dependabot(tmp_path, GITHUB_ACTIONS_CONFIG)
        worktree = tmp_path / "wt"
        worktree.mkdir()
        (worktree / ".git").write_text(
            "gitdir: ../.git/worktrees/wt\n", encoding="utf-8"
        )

        assert find_dependabot_config(worktree) is None


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

    def test_reads_exclude_and_include(self, tmp_path: Path) -> None:
        content = textwrap.dedent(
            """\
            version: 2
            updates:
              - package-ecosystem: "uv"
                directory: "/"
                cooldown:
                  default-days: 3
                  exclude: ["uv-only/*"]
              - package-ecosystem: "github-actions"
                directory: "/"
                cooldown:
                  default-days: 7
                  exclude:
                    - "lfreleng-actions/*"
                  include:
                    - "actions/*"
            """
        )
        _write_dependabot(tmp_path, content)
        result = resolve_cooldown(tmp_path)
        assert result is not None
        assert result.days == 7
        assert result.exclude == ("lfreleng-actions/*",)
        assert result.include == ("actions/*",)

    def test_lists_default_to_empty(self, tmp_path: Path) -> None:
        _write_dependabot(tmp_path, GITHUB_ACTIONS_CONFIG)
        result = resolve_cooldown(tmp_path)
        assert result is not None
        assert result.exclude == ()
        assert result.include == ()

    @pytest.mark.parametrize(
        "value",
        ['"lfreleng-actions/*"', "[1, 2]", '["ok", 3]', "{a: b}"],
    )
    def test_ignores_a_list_that_is_not_strings(
        self, tmp_path: Path, value: str
    ) -> None:
        content = textwrap.dedent(
            f"""\
            version: 2
            updates:
              - package-ecosystem: "github-actions"
                directory: "/"
                cooldown:
                  default-days: 7
                  exclude: {value}
                  include: {value}
            """
        )
        _write_dependabot(tmp_path, content)
        result = resolve_cooldown(tmp_path)
        assert result is not None
        assert result.days == 7
        assert result.exclude == ()
        assert result.include == ()


SHA = "0123456789abcdef0123456789abcdef01234567"


class TestDependencyName:
    """Names match Dependabot's ``github_dependency``."""

    @pytest.mark.parametrize(
        ("organization", "repository", "reference", "expected"),
        [
            pytest.param(
                "lfreleng-actions",
                "harden-runner-block-action",
                SHA,
                "lfreleng-actions/harden-runner-block-action",
                id="action",
            ),
            pytest.param(
                "lfreleng-actions",
                "security-workflows/.github/workflows/openssf-scorecard.yaml",
                SHA,
                "lfreleng-actions/security-workflows/.github/workflows/"
                "openssf-scorecard.yaml",
                id="reusable-workflow-sha",
            ),
            pytest.param(
                "org",
                "repo/.github/workflows/ci.yml",
                "v1",
                "org/repo/.github/workflows/ci.yml",
                id="reusable-workflow-tag",
            ),
            pytest.param(
                "github",
                "codeql-action/upload-sarif",
                SHA,
                "github/codeql-action/upload-sarif",
                id="subdirectory-sha",
            ),
            pytest.param(
                "github",
                "codeql-action/upload-sarif",
                "v3",
                "github/codeql-action",
                id="subdirectory-tag",
            ),
            pytest.param(
                "org",
                "repo",
                "component/v1",
                "org/repo@component/v1",
                id="path-based-reference",
            ),
            pytest.param(
                "org",
                "repo/sub",
                "releases/2.0",
                "org/repo/sub@releases/2.0",
                id="path-based-reference-subdirectory",
            ),
            pytest.param(
                "org",
                "repo",
                "feature/topic",
                "org/repo",
                id="slash-reference-not-path-based",
            ),
        ],
    )
    def test_names(
        self,
        organization: str,
        repository: str,
        reference: str,
        expected: str,
    ) -> None:
        assert dependency_name(organization, repository, reference) == expected


class TestCooldownApplies:
    """Matching follows ``ReleaseCooldownOptions#included?``."""

    def test_no_lists_cools_everything(self) -> None:
        assert cooldown_applies("actions/checkout", (), ())

    @pytest.mark.parametrize(
        ("name", "applies"),
        [
            ("lfreleng-actions/harden-runner-block-action", False),
            (
                "lfreleng-actions/security-workflows/.github/workflows/"
                "openssf-scorecard.yaml",
                False,
            ),
            ("github/codeql-action/upload-sarif", True),
            ("LFRELENG-ACTIONS/tag-push-verify-action", True),
        ],
    )
    def test_exclude(self, name: str, applies: bool) -> None:
        assert cooldown_applies(name, ("lfreleng-actions/*",), ()) is applies

    def test_include_limits_the_cooldown(self) -> None:
        assert cooldown_applies("actions/checkout", (), ("actions/*",))
        assert not cooldown_applies("github/codeql-action", (), ("actions/*",))

    def test_path_based_reference_matches_full_call(self) -> None:
        name = dependency_name("org", "repo", "component/v1")
        assert not cooldown_applies(name, ("org/repo@component/*",), ())

    def test_exclude_wins_over_include(self) -> None:
        assert not cooldown_applies(
            "actions/checkout", ("actions/checkout",), ("actions/*",)
        )

    @pytest.mark.parametrize("pattern", ["actions/[^c]*", "actions/[!c]*"])
    def test_negated_bracket_in_either_list(self, pattern: str) -> None:
        assert cooldown_applies("actions/checkout", (pattern,), ())
        assert not cooldown_applies("actions/setup-python", (pattern,), ())
        assert not cooldown_applies("actions/checkout", (), (pattern,))
        assert cooldown_applies("actions/setup-python", (), (pattern,))


class TestFnmatchRuby:
    """Results agree with Ruby 3.3's ``File.fnmatch?`` with no flags."""

    @pytest.mark.parametrize(
        ("pattern", "name", "expected"),
        [
            ("lfreleng-actions/*", "lfreleng-actions/a/b.yaml", True),
            ("Actions/*", "actions/checkout", False),
            ("org/a\\-b", "org/a-b", True),
            ("org/[]a]", "org/a", False),
            ("org/[]a]", "org/]", False),
            ("org/[!]", "org/x", True),
            ("org/[z-a]", "org/m", False),
            ("org/[z-a]", "org/a", True),
            ("org/[ab", "org/[ab", False),
            ("org/x\\", "org/x", True),
            ("*", ".x/y", False),
            (".*", ".x/y", True),
        ],
    )
    def test_matches_ruby(
        self, pattern: str, name: str, expected: bool
    ) -> None:
        assert fnmatch_ruby(name, pattern) is expected

    def test_repeated_wildcards_do_not_backtrack(self) -> None:
        pattern = "org/" + "*a" * 25 + "b"
        name = "org/" + "a" * 60
        started = time.monotonic()
        assert not fnmatch_ruby(name, pattern)
        assert fnmatch_ruby(name + "b", pattern)
        assert time.monotonic() - started < 1
