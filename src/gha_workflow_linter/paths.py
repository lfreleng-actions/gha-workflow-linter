# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Shared helpers for GitHub Actions repository path / subpath handling.

A GitHub Action can be referenced either as a top-level repository
(``owner/repo@ref``) or as a *subdirectory* (monorepo / composite) action
that lives in a directory within a repository (``owner/repo/path@ref``,
for example ``github/codeql-action/init`` or
``anchore/scan-action/download-grype``).

A Git remote only exists for the ``owner/repo`` portion; the trailing path
is a directory inside the repository at a given ref. These helpers provide a
single, shared definition of how an action identifier is split into its base
repository and subdirectory subpath, and of how a subpath's existence is
probed, so the GitHub API and Git validation paths stay consistent.
"""

from __future__ import annotations

# Action metadata filenames recognised by GitHub for composite / Docker /
# JavaScript actions. By GitHub's rules a directory containing one of these is
# a real action, so their presence is the strongest legitimacy signal for a
# subpath. Subpath validation prefers them but also accepts the directory
# itself as a fallback (see ``action_subpath_candidates``); this constant
# therefore documents the preferred signal, not a hard requirement enforced by
# the validators.
ACTION_METADATA_FILENAMES: tuple[str, ...] = ("action.yml", "action.yaml")


def split_repository_subpath(repository: str) -> tuple[str, str | None]:
    """Split an action identifier into its base repository and subpath.

    Monorepo / subdirectory actions are referenced as ``owner/repo/path``.
    A Git remote only exists for the ``owner/repo`` portion; the trailing
    path is a directory within the repository.

    Args:
        repository: Repository identifier, possibly including a subpath.

    Returns:
        A ``(base_repository, subpath)`` tuple. ``base_repository`` is the
        ``owner/repo`` portion (first two path segments). ``subpath`` is the
        remaining path (everything after ``owner/repo``) or ``None`` when no
        subpath is present.
    """
    parts = repository.split("/")
    if len(parts) > 2:
        return "/".join(parts[:2]), "/".join(parts[2:])
    return repository, None


def base_repository(repository: str) -> str:
    """Return the ``owner/repo`` base, stripping any action subpath.

    Args:
        repository: Repository identifier, possibly including a subpath.

    Returns:
        The ``owner/repo`` portion when a subpath is present, otherwise the
        input unchanged.
    """
    return split_repository_subpath(repository)[0]


def action_subpath(repository: str) -> str | None:
    """Return the subdirectory subpath of an action identifier, if any.

    Args:
        repository: Repository identifier, possibly including a subpath.

    Returns:
        The subpath (everything after ``owner/repo``) or ``None`` when the
        identifier refers to a top-level repository.
    """
    return split_repository_subpath(repository)[1]


def has_action_subpath(repository: str) -> bool:
    """Report whether an action identifier includes a subdirectory subpath.

    Args:
        repository: Repository identifier, possibly including a subpath.

    Returns:
        ``True`` when the identifier has more than two path segments
        (``owner/repo/path``), ``False`` otherwise.
    """
    return split_repository_subpath(repository)[1] is not None


def action_subpath_candidates(subpath: str) -> list[str]:
    """Return the candidate paths whose existence proves a subdir action.

    The list is ordered from the strongest legitimacy signal to the weakest:

    1. ``<subpath>/action.yml`` and ``<subpath>/action.yaml`` -- a directory
       containing one of these is, by definition, a GitHub Action.
    2. ``<subpath>`` -- the directory (or file) itself, used as a fallback so
       that a path which genuinely exists at the ref is never reported as
       bogus even if its action metadata is named unusually.

    Both the GitHub API (GraphQL tree lookup) and Git (``ls-tree``) paths
    consume this single definition so their results stay consistent.

    Args:
        subpath: The subdirectory path within the repository.

    Returns:
        Ordered list of candidate paths to probe at the referenced ref.
    """
    sub = subpath.strip("/")
    candidates = [f"{sub}/{name}" for name in ACTION_METADATA_FILENAMES]
    candidates.append(sub)
    return candidates
