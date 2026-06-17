# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Tests for the shared repository path / subpath helpers."""

from __future__ import annotations

import pytest

from gha_workflow_linter.paths import (
    ACTION_METADATA_FILENAMES,
    action_subpath,
    action_subpath_candidates,
    base_repository,
    has_action_subpath,
    split_repository_subpath,
)


@pytest.mark.parametrize(
    ("repository", "expected_base", "expected_subpath"),
    [
        ("actions/checkout", "actions/checkout", None),
        (
            "anchore/scan-action/download-grype",
            "anchore/scan-action",
            "download-grype",
        ),
        ("github/codeql-action/init", "github/codeql-action", "init"),
        ("owner/repo/nested/path", "owner/repo", "nested/path"),
        ("owner/repo", "owner/repo", None),
        ("single", "single", None),
    ],
)
def test_split_repository_subpath(
    repository: str, expected_base: str, expected_subpath: str | None
) -> None:
    """Identifiers split into ``(owner/repo, subpath)`` correctly."""
    base, subpath = split_repository_subpath(repository)
    assert base == expected_base
    assert subpath == expected_subpath


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
def test_base_repository(repository: str, expected: str) -> None:
    """The owner/repo base is returned, dropping any trailing subpath."""
    assert base_repository(repository) == expected


@pytest.mark.parametrize(
    ("repository", "expected"),
    [
        ("actions/checkout", None),
        ("github/codeql-action/init", "init"),
        ("owner/repo/nested/path", "nested/path"),
        ("single", None),
    ],
)
def test_action_subpath(repository: str, expected: str | None) -> None:
    """The trailing subpath (or None) is returned."""
    assert action_subpath(repository) == expected


@pytest.mark.parametrize(
    ("repository", "expected"),
    [
        ("actions/checkout", False),
        ("github/codeql-action/init", True),
        ("owner/repo/nested/path", True),
        ("owner/repo", False),
        ("single", False),
    ],
)
def test_has_action_subpath(repository: str, expected: bool) -> None:
    """Subdirectory actions are detected by path-segment count."""
    assert has_action_subpath(repository) is expected


def test_action_subpath_candidates_order_and_content() -> None:
    """Candidates prefer action metadata files, then the directory itself."""
    candidates = action_subpath_candidates("init")
    assert candidates == [
        "init/action.yml",
        "init/action.yaml",
        "init",
    ]
    # Metadata filenames are sourced from the shared constant.
    assert candidates[: len(ACTION_METADATA_FILENAMES)] == [
        f"init/{name}" for name in ACTION_METADATA_FILENAMES
    ]


def test_action_subpath_candidates_strips_surrounding_slashes() -> None:
    """Leading/trailing slashes in the subpath are normalised away."""
    assert action_subpath_candidates("/nested/path/") == [
        "nested/path/action.yml",
        "nested/path/action.yaml",
        "nested/path",
    ]
