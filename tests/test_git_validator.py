# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

"""Tests for Git-based validation of subdirectory (monorepo) action calls."""

from __future__ import annotations

import pytest

from gha_workflow_linter import git_validator
from gha_workflow_linter.git_validator import (
    _base_repository,
    _validate_repository_exists,
)
from gha_workflow_linter.models import GitConfig, ValidationResult


@pytest.mark.parametrize(
    ("repository", "expected"),
    [
        ("actions/checkout", "actions/checkout"),
        ("anchore/scan-action/download-grype", "anchore/scan-action"),
        ("github/codeql-action/init", "github/codeql-action"),
        ("owner/repo/nested/path", "owner/repo"),
        ("owner/repo", "owner/repo"),
        ("single", "single"),
    ],
)
def test_base_repository_strips_subpath(repository: str, expected: str) -> None:
    """The owner/repo base is returned, dropping any trailing action subpath."""
    assert _base_repository(repository) == expected


def test_validate_repository_exists_uses_base_repo_url(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Subdirectory actions validate against the owner/repo remote URL.

    Regression test: ``anchore/scan-action/download-grype`` previously built
    ``https://github.com/anchore/scan-action/download-grype.git`` and failed
    with INVALID_REPOSITORY under the token-less Git validation path, because
    a Git remote only exists for the ``owner/repo`` portion.
    """
    seen_urls: list[str] = []

    def fake_ls_remote(url: str, _config: GitConfig) -> bool:
        seen_urls.append(url)
        return True

    monkeypatch.setattr(git_validator, "_run_git_ls_remote", fake_ls_remote)

    result = _validate_repository_exists(
        "anchore/scan-action/download-grype", GitConfig()
    )

    assert result == ValidationResult.VALID
    assert seen_urls == ["https://github.com/anchore/scan-action.git"]
    assert "download-grype" not in seen_urls[0]
