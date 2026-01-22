# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

"""Auto-fix functionality for GitHub Actions workflow issues."""

from __future__ import annotations

import asyncio
from collections import defaultdict
from contextlib import nullcontext
import logging
from pathlib import Path
import re
import time
from typing import Any

import httpx
from rich.console import Console
from rich.live import Live
from rich.text import Text

from .cache import ValidationCache
from .exceptions import GitError
from .git_validator import (
    GitValidationClient,
    _get_remote_branches,
    _get_remote_tags,
)
from .github_api import GitHubGraphQLClient
from .models import (
    ActionCall,
    Config,
    ReferenceType,
    ValidationError,
    ValidationMethod,
    ValidationResult,
)
from .patterns import ActionCallPatterns
from .utils import has_test_comment


def _parse_version(tag: str) -> tuple[int, int, int]:
    """Extract major, minor, patch from a version tag for sorting.

    Args:
        tag: A version tag (e.g., 'v4.31.0', 'v4.31', '1.2.3', '0.9')

    Returns:
        A tuple of (major, minor, patch) as integers

    Raises:
        ValueError: If version segments contain non-numeric characters
    """
    # Strip optional 'v' prefix and any pre-release/metadata suffixes
    version = tag.lstrip("v").split("-")[0].split("+")[0]
    parts = version.split(".")

    # Parse and validate version components
    try:
        major = int(parts[0]) if len(parts) > 0 else 0
        minor = int(parts[1]) if len(parts) > 1 else 0
        patch = int(parts[2]) if len(parts) > 2 else 0
    except ValueError as e:
        raise ValueError(
            f"Invalid version tag '{tag}': version segments must be numeric. "
            f"Found non-numeric value in '{version}'"
        ) from e

    return (major, minor, patch)


def _get_version_specificity(tag: str) -> int:
    """
    Get the specificity level of a version tag.

    Returns:
        3 for full semver (v1.2.3), 2 for major.minor (v1.2), 1 for major only (v1)

    This helps prefer v8.0.0 over v8 when both point to the same SHA.
    """
    version = tag.lstrip("v").split("-")[0].split("+")[0]
    parts = version.split(".")
    return len([p for p in parts if p])


def _find_most_specific_version_tag(
    tag: str, sha: str, all_tags: list[tuple[str, str]]
) -> str:
    """
    Find the most specific semantic version tag for a given SHA.

    For example, if we get 'v8' but 'v8.0.0' also points to the same SHA,
    return 'v8.0.0' as it's more specific.

    Args:
        tag: The tag we found (e.g., 'v8')
        sha: The commit SHA
        all_tags: List of (tag_name, sha) tuples from the repository

    Returns:
        The most specific version tag pointing to the same SHA
    """
    # Find all tags pointing to the same SHA
    matching_tags = [t for t, s in all_tags if s == sha]

    if not matching_tags:
        return tag

    # Parse the base version from the original tag
    try:
        base_version = _parse_version(tag)
    except ValueError:
        return tag

    # Find all tags with the same base version
    same_version_tags = []
    for t in matching_tags:
        try:
            if _parse_version(t) == base_version:
                same_version_tags.append(t)
        except ValueError:
            continue

    if not same_version_tags:
        return tag

    # Sort by specificity (most specific first)
    sorted_by_specificity = sorted(
        same_version_tags,
        key=_get_version_specificity,
        reverse=True
    )

    return sorted_by_specificity[0]


class AutoFixer:
    """Auto-fixes GitHub Actions workflow issues."""

    def __init__(self, config: Config, base_path: Path | None = None) -> None:
        """
        Initialize the auto-fixer.

        Args:
            config: Configuration object
            base_path: Base path for making file paths relative in output
        """
        self.config = config
        self.base_path = base_path or Path.cwd()
        self.logger = logging.getLogger(__name__)
        self._http_client: httpx.AsyncClient | None = None
        self._graphql_client: GitHubGraphQLClient | None = None
        self._cache = ValidationCache(config.cache)
        self._git_client: GitValidationClient | None = None

        # Caching for batch operations (session-level cache)
        self._latest_versions_cache: dict[
            str, tuple[str, str, float]
        ] = {}  # {repo: (tag, sha, timestamp)}
        self._cache_ttl = 300  # 5 minutes

        # Redirect tracking
        self._redirects_seen: set[str] = (
            set()
        )  # Track redirects we've already displayed
        self._redirects_found: set[str] = (
            set()
        )  # Track unique redirected actions
        self._redirect_updates: int = (
            0  # Count of action calls updated due to redirects
        )

    async def __aenter__(self) -> AutoFixer:
        """Async context manager entry."""
        # Initialize HTTP client for redirect detection (works for both validation methods)
        # Uses GitHub web URLs (not API) to avoid rate limits
        headers = {
            "User-Agent": "gha-workflow-linter",
        }

        # Add authentication if available (helps with private repos)
        if self.config.effective_github_token:
            headers["Authorization"] = (
                f"token {self.config.effective_github_token}"
            )

        self._http_client = httpx.AsyncClient(
            timeout=self.config.network.timeout_seconds,
            follow_redirects=False,  # Don't follow, we want to detect redirects
            headers=headers,
        )

        # Use the same validation method as the main validation process
        if self.config.validation_method == ValidationMethod.GITHUB_API:
            # Initialize GraphQL client for batch queries
            self._graphql_client = GitHubGraphQLClient(self.config.github_api)
            await self._graphql_client.__aenter__()
        else:
            # Using Git validation method - initialize Git client
            self._git_client = GitValidationClient(self.config.git)

        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Async context manager exit."""
        if self._graphql_client:
            await self._graphql_client.__aexit__(exc_type, exc_val, exc_tb)
        if self._http_client:
            await self._http_client.aclose()

        # Save cache to persist repository redirects
        self._cache.save()

    async def fix_validation_errors(
        self,
        errors: list[ValidationError],
        all_action_calls: dict[Path, dict[int, ActionCall]],
        check_for_updates: bool = False,
    ) -> tuple[
        dict[Path, list[dict[str, str]]],
        dict[str, int],
        dict[str, list[dict[str, Any]]],
    ]:
        """
        Fix validation errors in workflow files using efficient batch processing.

        Args:
            errors: List of validation errors to fix
            all_action_calls: Dict of all action calls to check for updates/fixes (required for batch processing)
            check_for_updates: If True, check all actions and update to latest versions (--auto-latest)
                              If False, only fix validation errors and report outdated versions

        Returns:
            Tuple of:
            - Dictionary mapping file paths to lists of change dictionaries
              Each change dict has 'old_line', 'new_line', and 'line_number' keys
              For skipped items, dict will have 'skipped': True
            - Dictionary with redirect statistics: 'actions_moved' and 'calls_updated'
            - Dictionary mapping relative file paths to lists of outdated action info (for reporting)
        """
        if not self.config.auto_fix:
            # Even if auto_fix is disabled, still collect skipped testing items if fix_test_calls is disabled
            if not self.config.fix_test_calls:
                return (
                    self._collect_skipped_testing_items(errors),
                    {"actions_moved": 0, "calls_updated": 0},
                    {},
                )
            return {}, {"actions_moved": 0, "calls_updated": 0}, {}

        fixes_by_file: dict[Path, dict[int, tuple[str, str]]] = {}
        skipped_by_file: dict[Path, dict[int, str]] = {}
        stale_actions_summary: dict[str, list[dict[str, Any]]] = {}

        # Reset redirect tracking for this run
        self._redirects_found.clear()
        self._redirect_updates = 0

        # Create a set of validation error action calls that need fixing
        # These are actions with validation errors that should always be fixed when auto_fix is enabled
        validation_error_calls: set[tuple[Path, int]] = set()
        for error in errors:
            # Determine if this error should trigger a fix
            should_fix = False

            if error.result == ValidationResult.INVALID_REFERENCE:
                # Invalid reference (SHA/tag/branch doesn't exist) - ALWAYS FIX
                should_fix = True
            elif error.result == ValidationResult.INVALID_REPOSITORY:
                # Invalid repository (might be redirected) - ALWAYS TRY TO FIX
                should_fix = True
            elif error.result == ValidationResult.NOT_PINNED_TO_SHA:
                # Not pinned to SHA - FIX ONLY IF require_pinned_sha is enabled
                should_fix = self.config.require_pinned_sha
            elif error.result == ValidationResult.TEST_REFERENCE:
                # Test reference - skip (unless fix_test_calls is enabled, handled below)
                should_fix = False
            elif error.result in [
                ValidationResult.INVALID_SYNTAX,
                ValidationResult.NETWORK_ERROR,
                ValidationResult.TIMEOUT,
            ]:
                # Cannot auto-fix these - skip
                should_fix = False

            if should_fix:
                # Check if this action should be skipped due to fix_test_calls flag
                if not self.config.fix_test_calls and has_test_comment(
                    error.action_call
                ):
                    # Track as skipped
                    if error.file_path not in skipped_by_file:
                        skipped_by_file[error.file_path] = {}
                    skipped_by_file[error.file_path][
                        error.action_call.line_number
                    ] = error.action_call.raw_line.strip()
                    file_name = error.file_path.name
                    self.logger.debug(
                        f"Skipped testing action {error.action_call.organization}/{error.action_call.repository} in {file_name} (line {error.action_call.line_number})"
                    )
                    continue

                # Track this as a validation error that should be fixed
                validation_error_calls.add(
                    (error.file_path, error.action_call.line_number)
                )

        # Use batch processing for efficient fixes
        # validation_error_calls will be fixed regardless of check_for_updates setting
        # Non-error updates only applied when check_for_updates=True (--auto-latest)
        console = Console()
        if check_for_updates:
            self.logger.debug(
                "Checking all action calls for updates (--auto-latest enabled)"
            )
        else:
            self.logger.debug(
                "Checking all action calls (will fix validation errors and report outdated versions)"
            )

        # Use batch processing for performance
        # Check if we should show live updates (not in quiet mode)
        show_live_updates = self.logger.getEffectiveLevel() < logging.ERROR

        # Use Live context only when not in quiet mode, otherwise use nullcontext
        live_context = Live("", console=console, refresh_per_second=4) if show_live_updates else nullcontext()

        with live_context as live:
            (
                version_fixes,
                version_skipped,
                stale_summary,
            ) = await self._process_action_calls_batch(
                all_action_calls,
                live if show_live_updates else None,
                check_for_updates=check_for_updates,
                validation_error_calls=validation_error_calls,
                validation_errors=errors,
                show_live_updates=show_live_updates,
            )
            # When check_for_updates=False, only validation errors are fixed (stale_summary populated for reporting)
            # When check_for_updates=True, all fixes are applied (validation errors + version updates)
            for file_path, line_fixes in version_fixes.items():
                if file_path not in fixes_by_file:
                    fixes_by_file[file_path] = {}
                fixes_by_file[file_path].update(line_fixes)

            for file_path, skipped_lines in version_skipped.items():
                if file_path not in skipped_by_file:
                    skipped_by_file[file_path] = {}
                skipped_by_file[file_path].update(skipped_lines)

            stale_actions_summary = stale_summary

        # Apply fixes to files
        applied_fixes: dict[Path, list[dict[str, str]]] = {}
        for file_path, line_fixes in fixes_by_file.items():
            try:
                changes = await self._apply_fixes_to_file(file_path, line_fixes)
                applied_fixes[file_path] = changes
            except Exception as e:
                self.logger.error(f"Failed to apply fixes to {file_path}: {e}")

        # Add skipped items to the output
        for file_path, skipped_lines in skipped_by_file.items():
            if file_path not in applied_fixes:
                applied_fixes[file_path] = []
            for line_num, old_line in skipped_lines.items():
                applied_fixes[file_path].append(
                    {
                        "old_line": old_line,
                        "new_line": old_line,
                        "line_number": str(line_num),
                        "skipped": "true",
                    }
                )

        # Return fixes and redirect statistics
        redirect_stats = {
            "actions_moved": len(self._redirects_found),
            "calls_updated": self._redirect_updates,
        }

        return applied_fixes, redirect_stats, stale_actions_summary

    def _collect_skipped_testing_items(
        self, errors: list[ValidationError]
    ) -> dict[Path, list[dict[str, str]]]:
        """
        Collect items that would be skipped due to testing comments.
        Used when auto_fix is disabled but fix_test_calls is disabled (default).

        Args:
            errors: List of validation errors

        Returns:
            Dictionary mapping file paths to lists of skipped items
        """
        skipped_by_file: dict[Path, list[dict[str, str]]] = {}

        for error in errors:
            # Collect actions with test comments
            if has_test_comment(error.action_call):
                if error.file_path not in skipped_by_file:
                    skipped_by_file[error.file_path] = []
                skipped_by_file[error.file_path].append(
                    {
                        "old_line": error.action_call.raw_line.strip(),
                        "new_line": error.action_call.raw_line.strip(),
                        "line_number": str(error.action_call.line_number),
                        "skipped": "true",
                    }
                )

        return skipped_by_file

    async def _process_action_calls_batch(
        self,
        all_action_calls: dict[Path, dict[int, ActionCall]],
        live: Live | None,
        check_for_updates: bool = False,
        validation_error_calls: set[tuple[Path, int]] | None = None,
        validation_errors: list[ValidationError] | None = None,
        show_live_updates: bool = True,
    ) -> tuple[
        dict[Path, dict[int, tuple[str, str]]],
        dict[Path, dict[int, str]],
        dict[str, list[dict[str, Any]]],
    ]:
        """
        Process all action calls in batch for checking updates and fixes.

        This is the high-performance batch processing implementation that:
        1. Deduplicates repos before fetching
        2. Fetches all latest versions in parallel/batch
        3. Handles INVALID_REFERENCE errors by finding valid references
        4. Fetches all SHAs in parallel/batch
        5. Applies fixes using pre-fetched data

        Args:
            all_action_calls: Dictionary mapping file paths to action calls
            live: Rich Live display for progress updates
            check_for_updates: If True, update to latest versions (--auto-latest)
                              If False, only fix validation errors and report outdated versions
            validation_error_calls: Set of (file_path, line_number) tuples for validation errors
                                   that should always be fixed
            validation_errors: List of ValidationError objects to extract error types from

        Returns:
            Tuple of (fixes_by_file, skipped_by_file, outdated_actions_summary)
        """
        fixes_by_file: dict[Path, dict[int, tuple[str, str]]] = {}
        skipped_by_file: dict[Path, dict[int, str]] = {}
        outdated_actions_summary: dict[str, list[dict[str, Any]]] = defaultdict(
            list
        )

        # Step 1: Collect unique repositories
        unique_repos: set[str] = set()
        action_call_list: list[tuple[Path, int, ActionCall]] = []

        for file_path, calls in all_action_calls.items():
            for line_num, action_call in calls.items():
                # Skip test actions if fix_test_calls is disabled
                if not self.config.fix_test_calls and has_test_comment(
                    action_call
                ):
                    if file_path not in skipped_by_file:
                        skipped_by_file[file_path] = {}
                    skipped_by_file[file_path][line_num] = (
                        action_call.raw_line.strip()
                    )
                    continue

                action_call_list.append((file_path, line_num, action_call))
                repo_key = (
                    f"{action_call.organization}/{action_call.repository}"
                )
                base_repo_key = self._get_base_repository(repo_key)
                unique_repos.add(base_repo_key)

        if not action_call_list:
            return fixes_by_file, skipped_by_file, {}

        # Step 1.5: Handle INVALID_REFERENCE and INVALID_REPOSITORY errors
        # Build a map of (file_path, line_num) -> ValidationResult for quick lookup
        validation_result_map: dict[tuple[Path, int], ValidationResult] = {}
        if validation_errors:
            for error in validation_errors:
                validation_result_map[
                    (error.file_path, error.action_call.line_number)
                ] = error.result

        # For INVALID_REFERENCE errors, find valid references
        invalid_ref_fixes: dict[tuple[Path, int], str] = {}
        if validation_errors:
            invalid_ref_errors = [
                (file_path, line_num, action_call)
                for file_path, line_num, action_call in action_call_list
                if validation_result_map.get((file_path, line_num))
                == ValidationResult.INVALID_REFERENCE
            ]

            if invalid_ref_errors and show_live_updates and live:
                live.update(
                    Text(
                        f"  Finding valid references for {len(invalid_ref_errors)} invalid references...",
                        style="dim",
                    )
                )

            # Find valid references for invalid ones
            for file_path, line_num, action_call in invalid_ref_errors:
                repo_key = (
                    f"{action_call.organization}/{action_call.repository}"
                )
                base_repo_key = self._get_base_repository(repo_key)

                # First priority: if there's a valid version comment, use that
                valid_ref = None
                if action_call.comment:
                    comment_text = action_call.comment.strip().lstrip("#").strip()
                    # If the comment looks like a version tag, use it
                    if ActionCallPatterns.VERSION_TAG_PATTERN.match(comment_text):
                        valid_ref = comment_text

                # Second priority: try to find a valid reference
                if not valid_ref:
                    valid_ref = await self._find_valid_reference(
                        base_repo_key, action_call.reference
                    )

                if not valid_ref:
                    # Fallback to _get_fallback_reference
                    valid_ref = await self._get_fallback_reference(
                        base_repo_key, action_call.reference
                    )

                if not valid_ref:
                    # Last resort: use default branch
                    repo_info = await self._get_repository_info(base_repo_key)
                    valid_ref = (
                        repo_info.get("default_branch", "main")
                        if repo_info
                        else "main"
                    )

                if valid_ref:
                    invalid_ref_fixes[(file_path, line_num)] = valid_ref

        if show_live_updates and live:
            live.update(
                Text(
                    f"  Fetching latest versions for {len(unique_repos)} unique repositories...",
                    style="dim",
                )
            )

        # Step 2: Batch-fetch latest versions for all unique repos
        latest_versions = await self._get_latest_versions_batch(
            list(unique_repos)
        )

        # Step 3: Collect refs that need SHA resolution and check redirects
        refs_to_resolve: list[tuple[str, str]] = []
        redirect_map: dict[str, str] = {}
        redirected_repos: list[str] = []

        # Check redirects in parallel with rate limiting
        semaphore = asyncio.Semaphore(20)  # Limit concurrent HEAD requests

        async def check_redirect_with_limit(
            repo_key: str,
        ) -> tuple[str, str | None]:
            """Check a single repository for redirects with rate limiting."""
            async with semaphore:
                new_repo = await self._detect_repository_redirect(repo_key)
                return repo_key, new_repo

        # Execute all redirect checks concurrently
        redirect_results = await asyncio.gather(
            *[check_redirect_with_limit(rk) for rk in unique_repos]
        )

        # Process results
        for repo_key, new_repo in redirect_results:
            if new_repo:
                redirect_map[repo_key] = new_repo
                redirected_repos.append(new_repo)
                # Track unique redirected actions
                self._redirects_found.add(repo_key)

                # Show redirect message
                if repo_key not in self._redirects_seen:
                    self._redirects_seen.add(repo_key)
                    if show_live_updates and live:
                        moved_msg = Text()
                        moved_msg.append("  Action has moved: ", style="dim")
                        moved_msg.append(repo_key, style="orange3")
                        live.update(moved_msg)
                        await asyncio.sleep(0.3)

                        new_location_msg = Text()
                        new_location_msg.append("  New location: ", style="dim")
                        new_location_msg.append(new_repo, style="green")
                        live.update(new_location_msg)
                        await asyncio.sleep(0.3)

        # Fetch latest versions for redirected repositories
        if redirected_repos:
            if show_live_updates and live:
                live.update(
                    Text(
                        f"  Fetching latest versions for {len(redirected_repos)} redirected repositories...",
                        style="dim",
                    )
                )
            redirected_versions = await self._get_latest_versions_batch(
                redirected_repos
            )
            latest_versions.update(redirected_versions)

        # Step 3c: Collect refs that need SHA resolution (use set for O(1) lookup)
        refs_to_resolve_set: set[tuple[str, str]] = set()

        # Add valid references from INVALID_REFERENCE fixes
        for (file_path, line_num), valid_ref in invalid_ref_fixes.items():
            # Find the action_call to get the repo
            for fp, ln, ac in action_call_list:
                if fp == file_path and ln == line_num:
                    repo_key = f"{ac.organization}/{ac.repository}"
                    base_repo_key = self._get_base_repository(repo_key)
                    effective_repo = redirect_map.get(base_repo_key, base_repo_key)
                    refs_to_resolve_set.add((effective_repo, valid_ref))
                    break

        for repo_key in unique_repos:
            effective_repo = redirect_map.get(repo_key, repo_key)

            # Check in latest_versions using effective (possibly redirected) repo
            if effective_repo in latest_versions:
                tag, sha = latest_versions[effective_repo]
                if not sha:  # SHA not available yet, need to resolve
                    refs_to_resolve_set.add((effective_repo, tag))

        # Step 3d: Collect existing version comments that need SHA verification
        # This avoids N individual API calls during the update loop
        for _file_path, _line_num, action_call in action_call_list:
            if (
                action_call.reference_type == ReferenceType.COMMIT_SHA
                and action_call.comment
            ):
                comment_text = action_call.comment.strip().lstrip("#").strip()
                # If the comment looks like a version tag, we'll need to verify it
                if ActionCallPatterns.VERSION_TAG_PATTERN.match(comment_text):
                    repo_key = (
                        f"{action_call.organization}/{action_call.repository}"
                    )
                    base_repo_key = self._get_base_repository(repo_key)
                    effective_repo = redirect_map.get(
                        base_repo_key, base_repo_key
                    )
                    # Add to batch resolution (set automatically handles duplicates)
                    refs_to_resolve_set.add((effective_repo, comment_text))

        # Convert set to list for batch processing
        refs_to_resolve = list(refs_to_resolve_set)

        # Step 4: Batch-fetch SHAs for all refs that need resolution
        if refs_to_resolve:
            if show_live_updates and live:
                live.update(
                    Text(
                        f"  Resolving SHAs for {len(refs_to_resolve)} references...",
                        style="dim",
                    )
                )
            sha_map = await self._get_shas_batch(refs_to_resolve)
        else:
            sha_map = {}

        # Step 5: Check for updates using pre-fetched data
        if show_live_updates and live:
            live.update(
                Text(
                    f"  Checking {len(action_call_list)} action calls for updates...",
                    style="dim",
                )
            )

        for file_path, line_num, action_call in action_call_list:
            try:
                repo_key = (
                    f"{action_call.organization}/{action_call.repository}"
                )
                base_repo_key = self._get_base_repository(repo_key)
                original_base_repo = (
                    base_repo_key  # Keep original for comparison
                )

                # Get relative path for reporting
                try:
                    relative_path = (
                        str(file_path.relative_to(self.base_path))
                        if self.base_path
                        else str(file_path)
                    )
                except ValueError:
                    # File is outside base_path (e.g., temp directory in tests)
                    relative_path = str(file_path)

                # Check if repo was redirected
                new_base_repo = redirect_map.get(base_repo_key)
                repo_was_redirected = False
                if new_base_repo:
                    repo_was_redirected = True
                    # Preserve any path component from original
                    if len(repo_key.split("/")) > 2:
                        # Has path component, append it to new base
                        path_component = "/".join(repo_key.split("/")[2:])
                        repo_key = f"{new_base_repo}/{path_component}"
                    else:
                        repo_key = new_base_repo
                    base_repo_key = new_base_repo
                    # Don't increment counter here - wait until we know a change is needed

                # Check if this has an INVALID_REFERENCE error with a valid ref fix
                has_invalid_ref = (file_path, line_num) in invalid_ref_fixes
                if has_invalid_ref:
                    # Use the valid reference we found earlier
                    valid_ref = invalid_ref_fixes[(file_path, line_num)]

                    # Get SHA for this valid reference
                    invalid_ref_sha: str | None = None
                    if (base_repo_key, valid_ref) in sha_map:
                        invalid_ref_sha = sha_map[(base_repo_key, valid_ref)]
                    else:
                        # Fallback to individual fetch
                        sha_info = await self._get_commit_sha_for_reference(
                            base_repo_key, valid_ref
                        )
                        invalid_ref_sha = sha_info["sha"] if sha_info else None

                    if invalid_ref_sha:
                        # Determine final ref based on config
                        invalid_ref_final = (
                            invalid_ref_sha
                            if self.config.require_pinned_sha
                            else valid_ref
                        )
                        invalid_ref_comment: str | None = (
                            valid_ref
                            if ActionCallPatterns.VERSION_TAG_PATTERN.match(valid_ref)
                            else None
                        )

                        # Build the fixed line
                        fixed_line = self._build_fixed_line(
                            action_call,
                            invalid_ref_final,
                            invalid_ref_comment,
                            repo_key if repo_was_redirected else None,
                        )

                        if (
                            fixed_line
                            and fixed_line != action_call.raw_line.strip()
                        ):
                            if file_path not in fixes_by_file:
                                fixes_by_file[file_path] = {}
                            fixes_by_file[file_path][line_num] = (
                                action_call.raw_line.strip(),
                                fixed_line,
                            )
                            file_name = file_path.name
                            if show_live_updates and live:
                                update_msg = f"  Fixed invalid ref: {action_call.organization}/{action_call.repository} in {file_name}"
                                live.update(Text(update_msg, style="dim"))
                    continue

                # Get latest version info (using the effective repo after redirect)
                effective_lookup_repo = (
                    base_repo_key  # Use the potentially redirected repo
                )
                if effective_lookup_repo in latest_versions:
                    target_ref, cached_sha = latest_versions[
                        effective_lookup_repo
                    ]

                    # Get SHA (from cache or batch-fetched)
                    target_sha: str | None = None
                    if cached_sha:
                        target_sha = cached_sha
                    elif (effective_lookup_repo, target_ref) in sha_map:
                        target_sha = sha_map[
                            (effective_lookup_repo, target_ref)
                        ]
                    else:
                        # Fallback to individual fetch (shouldn't happen often)
                        sha_info = await self._get_commit_sha_for_reference(
                            effective_lookup_repo, target_ref
                        )
                        target_sha = sha_info["sha"] if sha_info else None

                    if target_sha:
                        # Check if this is actually a change
                        final_ref = (
                            target_sha
                            if self.config.require_pinned_sha
                            else target_ref
                        )
                        version_comment: str | None = (
                            target_ref
                            if ActionCallPatterns.VERSION_TAG_PATTERN.match(target_ref)
                            else None
                        )

                        # Fix false update bug: Check if anything actually changed
                        existing_comment: str | None = None
                        if action_call.comment:
                            existing_comment = (
                                action_call.comment.strip().lstrip("#").strip()
                            )

                        # Check if current SHA doesn't match the version in its own comment (corrupted reference)
                        has_mismatched_sha = False
                        existing_version_sha: str | None = None
                        if (
                            existing_comment
                            and action_call.reference_type
                            == ReferenceType.COMMIT_SHA
                            and ActionCallPatterns.VERSION_TAG_PATTERN.match(existing_comment)
                        ):
                            # Use pre-fetched SHA from batch resolution (Step 3d)
                            existing_version_sha = sha_map.get(
                                (effective_lookup_repo, existing_comment)
                            )
                            if (
                                existing_version_sha
                                and action_call.reference
                                != existing_version_sha
                            ):
                                # If current SHA doesn't match what the comment claims, it's corrupted/mismatched
                                has_mismatched_sha = True

                        # Check if repository changed (compare new vs original)
                        repo_changed = repo_was_redirected or (
                            base_repo_key != original_base_repo
                        )
                        comment_changed = (
                            (version_comment != existing_comment)
                            if version_comment
                            else False
                        )
                        ref_changed = final_ref != action_call.reference

                        # When has_mismatched_sha is True, we should fix to the CURRENT version
                        # (from the comment), not upgrade to latest version
                        # This takes priority regardless of check_for_updates setting
                        if has_mismatched_sha:
                            # Use the existing comment version instead of latest
                            fix_ref = (
                                existing_version_sha
                                if self.config.require_pinned_sha and existing_version_sha
                                else existing_comment
                            )
                            fix_comment = existing_comment

                            # Only fix if we have a valid reference
                            if fix_ref:
                                # Build the fixed line with current version
                                fixed_line = self._build_fixed_line(
                                    action_call,
                                    fix_ref,
                                    fix_comment,
                                    repo_key if repo_was_redirected else None,
                                )

                                if (
                                    fixed_line
                                    and fixed_line != action_call.raw_line.strip()
                                ):
                                    if file_path not in fixes_by_file:
                                        fixes_by_file[file_path] = {}
                                    fixes_by_file[file_path][line_num] = (
                                        action_call.raw_line.strip(),
                                        fixed_line,
                                    )
                                    file_name = file_path.name
                                    if show_live_updates and live:
                                        update_msg = f"  Fixed mismatched SHA: {action_call.organization}/{action_call.repository} in {file_name}"
                                        live.update(Text(update_msg, style="dim"))
                        elif ref_changed or comment_changed or repo_changed:
                            # Build the fixed line
                            fixed_line = self._build_fixed_line(
                                action_call,
                                final_ref,
                                version_comment,
                                repo_key if repo_changed else None,
                            )

                            if (
                                fixed_line
                                and fixed_line != action_call.raw_line.strip()
                            ):
                                # Increment redirect counter if this change is due to a redirect
                                if repo_was_redirected:
                                    self._redirect_updates += 1

                                # Check if this is a validation error or has mismatched SHA (both considered "invalid")
                                is_validation_error = (
                                    validation_error_calls
                                    and (file_path, line_num)
                                    in validation_error_calls
                                )
                                # Note: has_mismatched_sha is already handled above, so it won't reach here
                                # when check_for_updates=False
                                is_invalid = is_validation_error

                                if not check_for_updates and not is_invalid:
                                    # When check_for_updates=False, only report non-invalid outdated actions
                                    # Invalid actions are always fixed
                                    outdated_actions_summary[
                                        relative_path
                                    ].append(
                                        {
                                            "line": line_num,
                                            "action": repo_key
                                            if repo_was_redirected
                                            else f"{action_call.organization}/{action_call.repository}",
                                            "current_ref": action_call.reference,
                                            "current_comment": action_call.comment,
                                            "latest_ref": target_sha,
                                            "latest_version": target_ref,
                                            "redirected": repo_was_redirected,
                                            "is_invalid": is_invalid,
                                        }
                                    )
                                    file_name = file_path.name
                                    if show_live_updates and live:
                                        check_msg = f"  Checking: {action_call.organization}/{action_call.repository} in {file_name}"
                                        live.update(Text(check_msg, style="dim"))
                                else:
                                    # When check_for_updates=True or for invalid items, apply the fix
                                    if file_path not in fixes_by_file:
                                        fixes_by_file[file_path] = {}
                                    fixes_by_file[file_path][line_num] = (
                                        action_call.raw_line.strip(),
                                        fixed_line,
                                    )
                                    file_name = file_path.name
                                    if show_live_updates and live:
                                        update_msg = f"  Updated: {action_call.organization}/{action_call.repository} in {file_name}"
                                        live.update(Text(update_msg, style="dim"))
            except Exception as e:
                self.logger.warning(
                    f"Failed to update {action_call.organization}/{action_call.repository}@{action_call.reference}: {e}"
                )

        return fixes_by_file, skipped_by_file, dict(outdated_actions_summary)

    async def _fix_action_call_with_redirect(
        self,
        action_call: ActionCall,
        validation_result: ValidationResult,
        live: Live | None = None,
        show_live_updates: bool = True,
    ) -> dict[str, Any] | None:
        """
        Fix a single action call and track redirects.

        Args:
            action_call: The action call to fix
            validation_result: The validation result that indicates what needs fixing
            live: Optional Rich Live display for showing redirect messages

        Returns:
            Dictionary with 'fixed_line' and optional redirect info, or None if couldn't be fixed
        """
        # For actions with paths (e.g., github/codeql-action/init), we need to use
        # the base repository for API calls but preserve the full path in the output
        repo_key = f"{action_call.organization}/{action_call.repository}"
        base_repo_key = self._get_base_repository(repo_key)

        # Check if repository has been redirected/moved
        new_base_repo = await self._detect_repository_redirect(base_repo_key)
        redirect_info = None
        if new_base_repo:
            # Repository has moved - update the repo key
            # Preserve any path component from original
            if len(repo_key.split("/")) > 2:
                # Has path component, append it to new base
                path_component = "/".join(repo_key.split("/")[2:])
                repo_key = f"{new_base_repo}/{path_component}"
            else:
                repo_key = new_base_repo
            base_repo_key = new_base_repo
            self.logger.debug(
                f"Using redirected repository: {action_call.organization}/{action_call.repository} -> {repo_key}"
            )

            # Track redirect for display and statistics
            old_repo = f"{action_call.organization}/{action_call.repository}"

            # Track unique redirected actions
            self._redirects_found.add(old_repo)

            if old_repo not in self._redirects_seen and live:
                self._redirects_seen.add(old_repo)
                # Show "Action has moved" message in orange
                moved_msg = Text()
                moved_msg.append("  Action has moved: ", style="dim")
                moved_msg.append(old_repo, style="orange3")
                live.update(moved_msg)
                await asyncio.sleep(
                    0.5
                )  # Brief pause so user can see the message

                # Show "New location" message in green
                new_location_msg = Text()
                new_location_msg.append("  New location: ", style="dim")
                new_location_msg.append(new_base_repo, style="green")
                live.update(new_location_msg)
                await asyncio.sleep(
                    0.5
                )  # Brief pause so user can see the message

            redirect_info = {"old_repo": old_repo, "new_repo": new_base_repo}

        # Get repository information (if API available) - use base repo
        repo_info = await self._get_repository_info(base_repo_key)
        default_branch = (
            repo_info.get("default_branch", "main") if repo_info else "main"
        )

        # Determine the target reference
        original_ref = action_call.reference
        if self.config.auto_latest:
            # Use latest release/tag if available - use base repo
            target_ref = await self._get_latest_release_or_tag(base_repo_key)
            if not target_ref:
                # Fall back to default branch
                target_ref = default_branch
        # Try to fix the current reference based on validation error type
        elif validation_result == ValidationResult.INVALID_REFERENCE:
            # Invalid reference, try to find a valid one - use base repo
            target_ref = await self._find_valid_reference(
                base_repo_key, action_call.reference
            )
            if not target_ref:
                target_ref = await self._get_fallback_reference(
                    base_repo_key, action_call.reference
                )

            if not target_ref:
                # Fall back to default branch
                target_ref = default_branch
        else:
            # Keep the current reference for NOT_PINNED_TO_SHA cases
            target_ref = action_call.reference

        # Get commit SHA for the target reference if we need to pin to SHA
        target_sha = None
        version_comment = None

        if (
            self.config.require_pinned_sha
            or action_call.reference_type != ReferenceType.COMMIT_SHA
        ):
            # Try to get SHA (API or Git) - use base repo
            sha_info = await self._get_commit_sha_for_reference(
                base_repo_key, target_ref
            )
            if sha_info:
                target_sha = sha_info["sha"]
                # If target_ref looks like a version tag, use it in comment
                if (
                    ActionCallPatterns.VERSION_TAG_PATTERN.match(target_ref)
                    or target_ref != default_branch
                ):
                    version_comment = target_ref
                elif (
                    original_ref != default_branch
                    and validation_result == ValidationResult.NOT_PINNED_TO_SHA
                ):
                    # Preserve original branch name when falling back to default branch
                    version_comment = original_ref
            # Without access to resolve SHAs, we can't fix NOT_PINNED_TO_SHA issues
            elif validation_result == ValidationResult.NOT_PINNED_TO_SHA:
                self.logger.debug(
                    f"Cannot resolve SHA for {base_repo_key}@{target_ref}, skipping SHA pinning"
                )
                return (
                    {"fixed_line": None, "redirect_info": redirect_info}
                    if redirect_info
                    else None
                )

            # If we couldn't get SHA but we have a target_ref that's a version tag, still set the comment
            # This handles cases where SHA resolution fails but we're still updating the version
            if (
                not target_sha
                and target_ref
                and ActionCallPatterns.VERSION_TAG_PATTERN.match(target_ref)
            ):
                version_comment = target_ref

        # Check if we actually have a change to make
        final_ref = target_sha or target_ref
        repo_changed = base_repo_key != self._get_base_repository(
            f"{action_call.organization}/{action_call.repository}"
        )

        # Fix false update bug: Check if version comment actually changed
        existing_comment = None
        if action_call.comment:
            existing_comment = action_call.comment.strip().lstrip("#").strip()
        comment_changed = (
            (version_comment != existing_comment) if version_comment else False
        )

        if (
            final_ref == action_call.reference
            and not comment_changed
            and not repo_changed
        ):
            # No actual change needed
            return (
                {"fixed_line": None, "redirect_info": redirect_info}
                if redirect_info
                else None
            )

        # Build the fixed line - pass new repo if it changed
        fixed_line = self._build_fixed_line(
            action_call,
            final_ref,
            version_comment,
            repo_key if repo_changed else None,
        )

        return {"fixed_line": fixed_line, "redirect_info": redirect_info}

    async def _get_repository_info(
        self, repo_key: str
    ) -> dict[str, Any] | None:
        """Get repository information using the configured validation method."""
        # Use API if we're in GitHub API validation mode
        if (
            self.config.validation_method == ValidationMethod.GITHUB_API
            and self._http_client
        ):
            try:
                response = await self._http_client.get(
                    f"https://api.github.com/repos/{repo_key}"
                )
                response.raise_for_status()
                return response.json()  # type: ignore[no-any-return]
            except Exception as e:
                self.logger.debug(
                    f"Failed to get repository info via API for {repo_key}: {e}"
                )

        # Use Git operations if we're in Git validation mode
        if (
            self.config.validation_method == ValidationMethod.GIT
            and self._git_client
        ):
            try:
                url = f"https://github.com/{repo_key}.git"
                branches = _get_remote_branches(url, self.config.git)

                # Determine default branch from available branches
                default_branch = "main"
                if "main" in branches:
                    default_branch = "main"
                elif "master" in branches:
                    default_branch = "master"
                elif branches:
                    # Use the first branch if neither main nor master exists
                    default_branch = sorted(branches)[0]

                return {"default_branch": default_branch}
            except GitError as e:
                self.logger.debug(
                    f"Failed to get repository info via Git for {repo_key}: {e}"
                )

        return None

    async def _get_fallback_reference(
        self, repo_key: str, invalid_ref: str
    ) -> str | None:
        """Get fallback reference using Git operations or cached data."""
        # First check cache for known valid references for this repository
        cached_entry = self._cache.get(repo_key, "main")
        if cached_entry and cached_entry.result == ValidationResult.VALID:
            return "main"

        cached_entry = self._cache.get(repo_key, "master")
        if cached_entry and cached_entry.result == ValidationResult.VALID:
            return "master"

        # Try Git operations if we have the client
        if self._git_client:
            try:
                url = f"https://github.com/{repo_key}.git"
                branches = _get_remote_branches(url, self.config.git)

                # Common fallbacks for invalid references
                if invalid_ref == "master" and "main" in branches:
                    return "main"
                elif invalid_ref == "main" and "master" in branches:
                    return "master"
                elif invalid_ref.startswith("invalid"):
                    # Return the first common default branch found
                    for default_branch in ["main", "master"]:
                        if default_branch in branches:
                            return default_branch

                # Try to find similar branch names
                for branch in branches:
                    if branch.endswith(invalid_ref) or invalid_ref in branch:
                        return branch

            except GitError as e:
                self.logger.debug(f"Git fallback failed for {repo_key}: {e}")

        # Final fallbacks without Git access
        if invalid_ref == "master":
            return "main"
        elif invalid_ref == "main":
            return "master"
        elif invalid_ref.startswith("invalid"):
            return "main"
        return None

    async def _get_latest_release_or_tag(self, repo_key: str) -> str | None:
        """Get the latest release or tag for a repository."""
        # Use API if we're in GitHub API validation mode
        if (
            self.config.validation_method == ValidationMethod.GITHUB_API
            and self._http_client
        ):
            # Try to get latest release first
            try:
                response = await self._http_client.get(
                    f"https://api.github.com/repos/{repo_key}/releases/latest"
                )
                if response.status_code == 200:
                    release_data = response.json()
                    return release_data.get("tag_name")  # type: ignore[no-any-return]
            except Exception:
                pass

            # Fall back to getting latest tag via API
            try:
                response = await self._http_client.get(
                    f"https://api.github.com/repos/{repo_key}/tags?per_page=1"
                )
                response.raise_for_status()
                tags = response.json()
                if tags:
                    return tags[0]["name"]  # type: ignore[no-any-return]
            except Exception as e:
                self.logger.debug(
                    f"Failed to get latest tag via API for {repo_key}: {e}"
                )

        # Use Git operations if we're in Git validation mode
        if (
            self.config.validation_method == ValidationMethod.GIT
            and self._git_client
        ):
            try:
                url = f"https://github.com/{repo_key}.git"
                git_tags = _get_remote_tags(url, self.config.git)

                if git_tags:
                    # Convert to sorted list (Git ls-remote doesn't guarantee order)
                    tag_list = sorted(git_tags, reverse=True)

                    # Try to find semantic version tags first
                    version_tags = [
                        tag for tag in tag_list if ActionCallPatterns.VERSION_TAG_PATTERN.match(tag)
                    ]
                    if version_tags:
                        return version_tags[0]

                    # Otherwise return the first tag
                    return tag_list[0]

            except GitError as e:
                self.logger.debug(
                    f"Git tag enumeration failed for {repo_key}: {e}"
                )

        return None

    async def _find_valid_reference(
        self, repo_key: str, invalid_ref: str
    ) -> str | None:
        """Try to find a valid reference similar to the invalid one."""
        # Check cache first for known references
        for potential_ref in [invalid_ref, "main", "master"]:
            cached_entry = self._cache.get(repo_key, potential_ref)
            if (
                cached_entry
                and cached_entry.result == ValidationResult.VALID
                and potential_ref != invalid_ref
            ):
                return potential_ref

        # Use API if we're in GitHub API validation mode
        if (
            self.config.validation_method == ValidationMethod.GITHUB_API
            and self._http_client
        ):
            # For common patterns like "main" vs "master"
            if invalid_ref in ["main", "master"]:
                alternative = "master" if invalid_ref == "main" else "main"
                if await self._check_reference_exists(repo_key, alternative):
                    return alternative

            # Try to find similar tags/branches
            try:
                # Check if it's a partial version match
                if re.match(r"^v?\d+", invalid_ref):
                    api_tags = await self._get_tags(repo_key, limit=50)
                    for api_tag in api_tags:
                        if api_tag["name"].startswith(invalid_ref):
                            return api_tag["name"]  # type: ignore[no-any-return]

                # Check branches for partial matches
                api_branches = await self._get_branches(repo_key, limit=20)
                for api_branch in api_branches:
                    if api_branch["name"] == invalid_ref or api_branch[
                        "name"
                    ].endswith(invalid_ref):
                        return api_branch["name"]  # type: ignore[no-any-return]

            except Exception as e:
                self.logger.debug(
                    f"Failed to find valid reference via API for {repo_key}@{invalid_ref}: {e}"
                )

        # Use Git operations if we're in Git validation mode
        if (
            self.config.validation_method == ValidationMethod.GIT
            and self._git_client
        ):
            try:
                url = f"https://github.com/{repo_key}.git"

                # Get all branches and tags
                git_branches = _get_remote_branches(url, self.config.git)
                git_tags = _get_remote_tags(url, self.config.git)

                # For common patterns like "main" vs "master"
                if invalid_ref == "main" and "master" in git_branches:
                    return "master"
                elif invalid_ref == "master" and "main" in git_branches:
                    return "main"

                # Check if it's a partial version match in tags
                if re.match(r"^v?\d+", invalid_ref):
                    for git_tag in sorted(git_tags, reverse=True):
                        if git_tag.startswith(invalid_ref):
                            return git_tag

                # Check branches for partial matches
                for git_branch in git_branches:
                    if git_branch == invalid_ref or git_branch.endswith(
                        invalid_ref
                    ):
                        return git_branch

            except GitError as e:
                self.logger.debug(
                    f"Git reference search failed for {repo_key}@{invalid_ref}: {e}"
                )

        return None

    async def _check_reference_exists(self, repo_key: str, ref: str) -> bool:
        """Check if a specific reference exists."""
        if (
            self.config.validation_method == ValidationMethod.GITHUB_API
            and self._http_client
        ):
            try:
                response = await self._http_client.get(
                    f"https://api.github.com/repos/{repo_key}/git/refs/heads/{ref}"
                )
                if response.status_code == 200:
                    return True

                response = await self._http_client.get(
                    f"https://api.github.com/repos/{repo_key}/git/refs/tags/{ref}"
                )
                return bool(response.status_code == 200)
            except Exception:
                pass

        # Use Git operations if we're in Git validation mode
        if (
            self.config.validation_method == ValidationMethod.GIT
            and self._git_client
        ):
            try:
                url = f"https://github.com/{repo_key}.git"
                git_branches = _get_remote_branches(url, self.config.git)
                git_tags = _get_remote_tags(url, self.config.git)
                return ref in git_branches or ref in git_tags
            except GitError:
                pass

        return False

    async def _get_tags(
        self, repo_key: str, limit: int = 30
    ) -> list[dict[str, Any]]:
        """Get repository tags."""
        if (
            self.config.validation_method == ValidationMethod.GITHUB_API
            and self._http_client
        ):
            try:
                response = await self._http_client.get(
                    f"https://api.github.com/repos/{repo_key}/tags?per_page={limit}"
                )
                response.raise_for_status()
                return response.json()  # type: ignore[no-any-return]
            except Exception:
                pass

        # Use Git operations if we're in Git validation mode - convert to API-like format
        if (
            self.config.validation_method == ValidationMethod.GIT
            and self._git_client
        ):
            try:
                url = f"https://github.com/{repo_key}.git"
                git_tags = _get_remote_tags(url, self.config.git)
                # Convert to API-like format for compatibility
                return [
                    {"name": tag}
                    for tag in sorted(git_tags, reverse=True)[:limit]
                ]
            except GitError:
                pass

        return []

    async def _get_branches(
        self, repo_key: str, limit: int = 20
    ) -> list[dict[str, Any]]:
        """Get repository branches."""
        if (
            self.config.validation_method == ValidationMethod.GITHUB_API
            and self._http_client
        ):
            try:
                response = await self._http_client.get(
                    f"https://api.github.com/repos/{repo_key}/branches?per_page={limit}"
                )
                response.raise_for_status()
                return response.json()  # type: ignore[no-any-return]
            except Exception:
                pass

        # Use Git operations if we're in Git validation mode - convert to API-like format
        if (
            self.config.validation_method == ValidationMethod.GIT
            and self._git_client
        ):
            try:
                url = f"https://github.com/{repo_key}.git"
                git_branches = _get_remote_branches(url, self.config.git)
                # Convert to API-like format for compatibility
                return [
                    {"name": branch} for branch in sorted(git_branches)[:limit]
                ]
            except GitError:
                pass

        return []

    async def _get_commit_sha_for_reference(
        self, repo_key: str, ref: str
    ) -> dict[str, Any] | None:
        """Get commit SHA for a specific reference."""
        # Use API if we're in GitHub API validation mode
        if (
            self.config.validation_method == ValidationMethod.GITHUB_API
            and self._http_client
        ):
            try:
                # Try as branch first
                response = await self._http_client.get(
                    f"https://api.github.com/repos/{repo_key}/git/refs/heads/{ref}"
                )
                if response.status_code == 200:
                    ref_data = response.json()
                    return {"sha": ref_data["object"]["sha"], "type": "branch"}

                # Try as tag
                response = await self._http_client.get(
                    f"https://api.github.com/repos/{repo_key}/git/refs/tags/{ref}"
                )
                if response.status_code == 200:
                    ref_data = response.json()
                    sha = ref_data["object"]["sha"]

                    # If it's an annotated tag, get the commit SHA
                    if ref_data["object"]["type"] == "tag":
                        tag_response = await self._http_client.get(
                            f"https://api.github.com/repos/{repo_key}/git/tags/{sha}"
                        )
                        if tag_response.status_code == 200:
                            tag_data = tag_response.json()
                            sha = tag_data["object"]["sha"]

                    return {"sha": sha, "type": "tag"}

                # Try as commit SHA
                response = await self._http_client.get(
                    f"https://api.github.com/repos/{repo_key}/commits/{ref}"
                )
                if response.status_code == 200:
                    commit_data = response.json()
                    return {"sha": commit_data["sha"], "type": "commit"}

            except Exception as e:
                self.logger.debug(
                    f"Failed to get commit SHA via API for {repo_key}@{ref}: {e}"
                )

        # Use Git operations if we're in Git validation mode
        if (
            self.config.validation_method == ValidationMethod.GIT
            and self._git_client
        ):
            try:
                url = f"https://github.com/{repo_key}.git"

                # Use git ls-remote to get the SHA for the reference
                import subprocess

                # Try as branch
                cmd = ["git", "ls-remote", "--heads", url, ref]
                try:
                    result = subprocess.run(
                        cmd,
                        capture_output=True,
                        text=True,
                        timeout=self.config.git.timeout_seconds,
                        check=True,
                    )
                    if result.stdout.strip():
                        sha = result.stdout.strip().split("\t")[0]
                        return {"sha": sha, "type": "branch"}
                except subprocess.CalledProcessError:
                    pass

                # Try as tag - need to dereference annotated tags
                # Query both the tag and the dereferenced commit
                cmd = [
                    "git",
                    "ls-remote",
                    "--tags",
                    url,
                    f"refs/tags/{ref}",
                    f"refs/tags/{ref}^{{}}",
                ]
                try:
                    result = subprocess.run(
                        cmd,
                        capture_output=True,
                        text=True,
                        timeout=self.config.git.timeout_seconds,
                        check=True,
                    )
                    if result.stdout.strip():
                        lines = result.stdout.strip().split("\n")
                        # Look for dereferenced tag first (ends with ^{})
                        for line in lines:
                            if line.endswith(f"refs/tags/{ref}^{{}}"):
                                sha = line.split("\t")[0]
                                return {"sha": sha, "type": "tag"}
                        # Fall back to tag object if no dereferenced version
                        if lines:
                            sha = lines[0].split("\t")[0]
                            return {"sha": sha, "type": "tag"}
                except subprocess.CalledProcessError:
                    pass

            except Exception as e:
                self.logger.debug(
                    f"Git SHA resolution failed for {repo_key}@{ref}: {e}"
                )

        return None

    async def _get_latest_versions_batch(
        self, repo_keys: list[str]
    ) -> dict[str, tuple[str, str]]:
        """
        Batch-fetch latest versions for multiple repositories.

        Returns dict mapping repo_key to (tag, sha) tuple.
        Uses both persistent disk cache and session cache for optimal performance.
        """
        results: dict[str, tuple[str, str]] = {}
        repos_to_fetch: list[str] = []
        session_cache_hits = 0
        disk_cache_hits = 0

        # Check session cache first (fastest)
        current_time = time.time()
        for repo_key in repo_keys:
            # Check in-memory session cache
            if repo_key in self._latest_versions_cache:
                tag, sha, timestamp = self._latest_versions_cache[repo_key]
                if current_time - timestamp < self._cache_ttl:
                    results[repo_key] = (tag, sha)
                    session_cache_hits += 1
                    continue

            # Check persistent disk cache
            cached_version = self._cache.get_latest_version(repo_key)
            if cached_version:
                tag, sha = cached_version
                results[repo_key] = (tag, sha)
                # Also populate session cache for faster subsequent access
                self._latest_versions_cache[repo_key] = (tag, sha, current_time)
                disk_cache_hits += 1
                continue

            repos_to_fetch.append(repo_key)

        if session_cache_hits > 0 or disk_cache_hits > 0:
            self.logger.debug(
                f"Latest version cache hits: {session_cache_hits} session, {disk_cache_hits} disk, "
                f"{len(repos_to_fetch)} to fetch"
            )

        if not repos_to_fetch:
            return results

        # Use GraphQL batch query if available
        if (
            self.config.validation_method == ValidationMethod.GITHUB_API
            and self._graphql_client
        ):
            try:
                graphql_results = await self._get_latest_versions_graphql_batch(
                    repos_to_fetch
                )

                for repo_key, (tag, sha) in graphql_results.items():
                    results[repo_key] = (tag, sha)
                    # Cache in both session and persistent storage
                    self._latest_versions_cache[repo_key] = (
                        tag,
                        sha,
                        current_time,
                    )
                    self._cache.put_latest_version(repo_key, tag, sha)

                # Check which repos didn't get results from GraphQL
                repos_to_fetch = [
                    repo
                    for repo in repos_to_fetch
                    if repo not in graphql_results
                ]
                if not repos_to_fetch:
                    return results

                self.logger.debug(
                    f"GraphQL returned results for {len(graphql_results)} repos, falling back to REST API for {len(repos_to_fetch)} repos"
                )
            except Exception as e:
                self.logger.debug(
                    f"GraphQL batch fetch failed, falling back to individual queries: {e}"
                )

        # Fallback to parallel REST API or Git operations
        if repos_to_fetch:
            tasks = [
                self._get_latest_version_single(repo_key)
                for repo_key in repos_to_fetch
            ]
            fetch_results = await asyncio.gather(*tasks, return_exceptions=True)
        else:
            fetch_results = []

        for repo_key, result in zip(repos_to_fetch, fetch_results):
            if isinstance(result, Exception):
                self.logger.debug(
                    f"Failed to fetch latest version for {repo_key}: {result}"
                )
                continue
            if result and isinstance(result, tuple):
                tag, sha = result
                results[repo_key] = (tag, sha)
                # Cache in both session and persistent storage
                self._latest_versions_cache[repo_key] = (tag, sha, current_time)
                self._cache.put_latest_version(repo_key, tag, sha)

        # Save persistent cache to disk after batch operation
        self._cache.save()

        return results

    async def _get_latest_versions_graphql_batch(
        self, repo_keys: list[str]
    ) -> dict[str, tuple[str, str]]:
        """
        Fetch latest releases for multiple repos using a single GraphQL query.

        Returns dict mapping repo_key to (tag, sha) tuple.
        """
        query_parts = []
        aliases = {}

        for i, repo_key in enumerate(repo_keys):
            try:
                owner, name = repo_key.split("/", 1)
                base_name = name.split("/")[0]
                alias = f"repo_{i}"
                aliases[alias] = repo_key

                query_parts.append(f"""
                    {alias}: repository(owner: "{owner}", name: "{base_name}") {{
                        latestRelease {{
                            tagName
                            tagCommit {{
                                oid
                            }}
                        }}
                        refs(refPrefix: "refs/tags/", first: 100, orderBy: {{field: TAG_COMMIT_DATE, direction: DESC}}) {{
                            nodes {{
                                name
                                target {{
                                    ... on Commit {{
                                        oid
                                    }}
                                    ... on Tag {{
                                        target {{
                                            ... on Commit {{
                                                oid
                                            }}
                                        }}
                                    }}
                                }}
                            }}
                        }}
                    }}
                """)
            except ValueError:
                self.logger.warning(f"Invalid repository format: {repo_key}")
                continue

        if not query_parts:
            return {}

        query = f"query {{ {' '.join(query_parts)} }}"

        # Execute GraphQL query using the client
        try:
            if not self._graphql_client:
                return {}
            response_data = await self._graphql_client._execute_graphql_query(
                query
            )

            results = {}
            for alias, repo_key in aliases.items():
                repo_data = response_data.get("data", {}).get(alias)
                if not repo_data:
                    continue

                # Collect all tags first for specificity resolution
                refs = repo_data.get("refs", {}).get("nodes", [])
                all_tags = []
                for ref in refs:
                    if ActionCallPatterns.VERSION_TAG_PATTERN.match(ref["name"]):
                        target = ref.get("target", {})
                        if "oid" in target:
                            all_tags.append((ref["name"], target["oid"]))
                        elif "target" in target and "oid" in target["target"]:
                            all_tags.append((ref["name"], target["target"]["oid"]))

                # Try latestRelease first, but only if prereleases are NOT allowed
                # (latestRelease excludes prereleases by GitHub's API design)
                # If allow_prerelease is True, skip latestRelease and check all tags
                if not self.config.allow_prerelease and repo_data.get(
                    "latestRelease"
                ):
                    tag = repo_data["latestRelease"]["tagName"]
                    sha = repo_data["latestRelease"]["tagCommit"]["oid"]
                    # Only use latestRelease if it matches our version patterns
                    if ActionCallPatterns.VERSION_TAG_PATTERN.match(tag):
                        # Find most specific version tag for this SHA (e.g., v8 -> v8.0.0)
                        specific_tag = _find_most_specific_version_tag(
                            tag, sha, all_tags
                        )
                        results[repo_key] = (specific_tag, sha)
                        continue

                # Fall back to tags with version pattern filtering
                if all_tags:
                    # Sort by specificity first, then version
                    sorted_tags = sorted(
                        all_tags,
                        key=lambda x: (
                            _get_version_specificity(x[0]),
                            _parse_version(x[0]),
                        ),
                        reverse=True,
                    )
                    tag, sha = sorted_tags[0]
                    results[repo_key] = (tag, sha)
                else:
                    # No clean version tags found, try fallback version-like tags (v1.2, v0.9, etc.)
                    fallback_pattern = re.compile(r"^v?\d+\.\d+")
                    fallback_tags = []
                    for ref in refs:
                        if fallback_pattern.match(ref["name"]):
                            # Handle both direct commits and annotated tags
                            target = ref.get("target", {})
                            if "oid" in target:
                                # Direct commit
                                fallback_tags.append(
                                    (ref["name"], target["oid"])
                                )
                            elif (
                                "target" in target
                                and "oid" in target["target"]
                            ):
                                # Annotated tag pointing to commit
                                fallback_tags.append(
                                    (ref["name"], target["target"]["oid"])
                                )
                    if fallback_tags:
                        # Just use the first one (already sorted by TAG_COMMIT_DATE DESC)
                        tag, sha = fallback_tags[0]
                        results[repo_key] = (tag, sha)

            return results
        except Exception as e:
            self.logger.debug(f"GraphQL batch query failed: {e}")
            return {}

    async def _get_latest_version_single(
        self, repo_key: str
    ) -> tuple[str, str] | None:
        """
        Fetch latest version for a single repository.

        Returns (tag, sha) tuple or None.
        Supports both REST API and Git operations.
        """
        # Try REST API first
        if (
            self.config.validation_method == ValidationMethod.GITHUB_API
            and self._http_client
        ):
            try:
                # Try latest release
                response = await self._http_client.get(
                    f"https://api.github.com/repos/{repo_key}/releases?per_page=100"
                )
                if response.status_code == 200:
                    releases = response.json()
                    # Filter releases based on allow_prerelease config
                    if self.config.allow_prerelease:
                        clean_releases = [
                            r
                            for r in releases
                            if ActionCallPatterns.VERSION_TAG_PATTERN.match(
                                r.get("tag_name", "")
                            )
                            and not r.get("draft", False)
                        ]
                    else:
                        clean_releases = [
                            r
                            for r in releases
                            if ActionCallPatterns.VERSION_TAG_PATTERN.match(
                                r.get("tag_name", "")
                            )
                            and not r.get("draft", False)
                            and not r.get("prerelease", False)
                        ]
                    if clean_releases:
                        sorted_releases = sorted(
                            clean_releases,
                            key=lambda r: _parse_version(r.get("tag_name", "")),
                            reverse=True,
                        )
                        tag = sorted_releases[0].get("tag_name")
                        # Get SHA for this tag
                        sha_info = await self._get_commit_sha_for_reference(
                            repo_key, tag
                        )
                        sha = sha_info["sha"] if sha_info else ""
                        return (tag, sha)

                # Fall back to tags
                response = await self._http_client.get(
                    f"https://api.github.com/repos/{repo_key}/tags?per_page=100"
                )
                if response.status_code == 200:
                    tags = response.json()
                    # Note: GitHub tags API doesn't include prerelease info
                    # Only the releases API has that metadata
                    # So when using tags endpoint, we can't filter prereleases
                    clean_tags = [
                        tag
                        for tag in tags
                        if ActionCallPatterns.VERSION_TAG_PATTERN.match(
                            tag.get("name", "")
                        )
                    ]
                    if clean_tags:
                        sorted_tags = sorted(
                            clean_tags,
                            key=lambda t: _parse_version(t.get("name", "")),
                            reverse=True,
                        )
                        tag = sorted_tags[0]["name"]
                        sha = sorted_tags[0]["commit"]["sha"]
                        return (tag, sha)
            except Exception as e:
                self.logger.debug(f"REST API fetch failed for {repo_key}: {e}")

        # Fall back to Git operations
        if (
            self.config.validation_method == ValidationMethod.GIT
            and self._git_client
        ):
            try:
                url = f"https://github.com/{repo_key}.git"
                git_tags = _get_remote_tags(url, self.config.git)

                if git_tags:
                    tag_list = sorted(git_tags, reverse=True)
                    clean_tags = [
                        tag
                        for tag in tag_list
                        if ActionCallPatterns.VERSION_TAG_PATTERN.match(tag)
                    ]
                    if clean_tags:
                        sorted_versions = sorted(
                            clean_tags, key=_parse_version, reverse=True
                        )
                        tag = sorted_versions[0]
                        # Get SHA for this tag
                        sha_info = await self._get_commit_sha_for_reference(
                            repo_key, tag
                        )
                        sha = sha_info["sha"] if sha_info else ""
                        return (tag, sha)
            except GitError as e:
                self.logger.debug(f"Git fetch failed for {repo_key}: {e}")

        return None

    async def _get_shas_batch(
        self, refs: list[tuple[str, str]]
    ) -> dict[tuple[str, str], str]:
        """
        Batch-fetch SHAs for multiple (repo, ref) pairs.

        Returns dict mapping (repo_key, ref) to SHA.
        Supports both GraphQL and parallel Git operations.
        """
        results: dict[tuple[str, str], str] = {}

        if not refs:
            return results

        # Use GraphQL batch query if available
        if (
            self.config.validation_method == ValidationMethod.GITHUB_API
            and self._graphql_client
        ):
            try:
                # Group refs by repository for efficient querying
                refs_by_repo: dict[str, list[str]] = defaultdict(list)
                for repo_key, ref in refs:
                    refs_by_repo[repo_key].append(ref)

                # Build batch query for all repos and their refs
                query_parts = []
                aliases = {}

                for repo_idx, (repo_key, repo_refs) in enumerate(
                    refs_by_repo.items()
                ):
                    owner, name = repo_key.split("/", 1)
                    base_name = name.split("/")[0]

                    ref_queries = []
                    for ref_idx, ref in enumerate(repo_refs):
                        ref_alias = f"ref_{ref_idx}"
                        aliases[f"repo_{repo_idx}_{ref_alias}"] = (
                            repo_key,
                            ref,
                        )
                        ref_queries.append(f"""
                            {ref_alias}: ref(qualifiedName: "refs/tags/{ref}") {{
                                target {{
                                    oid
                                    ... on Tag {{
                                        target {{
                                            oid
                                        }}
                                    }}
                                }}
                            }}
                        """)

                    repo_alias = f"repo_{repo_idx}"
                    query_parts.append(f"""
                        {repo_alias}: repository(owner: "{owner}", name: "{base_name}") {{
                            {' '.join(ref_queries)}
                        }}
                    """)

                query = f"query {{ {' '.join(query_parts)} }}"
                response_data = (
                    await self._graphql_client._execute_graphql_query(query)
                )

                # Parse results
                for full_alias, (repo_key, ref) in aliases.items():
                    # Extract repo_idx and ref_idx from format: "repo_{repo_idx}_ref_{ref_idx}"
                    match = re.match(r"repo_(\d+)_ref_(\d+)", full_alias)
                    if match:
                        repo_alias = f"repo_{match.group(1)}"
                        ref_alias = f"ref_{match.group(2)}"
                        repo_data = response_data.get("data", {}).get(
                            repo_alias, {}
                        )
                        ref_data = repo_data.get(ref_alias)
                        if ref_data:
                            target = ref_data.get("target")
                            # For annotated tags, the target has a nested target with the commit SHA
                            # For lightweight tags, the target directly has the commit SHA
                            if isinstance(target, dict):
                                nested_target = target.get("target")
                                if isinstance(nested_target, dict) and "oid" in nested_target:
                                    sha = nested_target["oid"]
                                elif "oid" in target:
                                    sha = target["oid"]
                                else:
                                    continue
                                results[(repo_key, ref)] = sha
                    else:
                        self.logger.warning(
                            f"Failed to parse alias format: {full_alias}"
                        )

                return results
            except Exception as e:
                self.logger.debug(
                    f"GraphQL batch SHA fetch failed, falling back: {e}"
                )

        # Fall back to parallel individual fetches
        tasks = [
            self._get_commit_sha_for_reference(repo_key, ref)
            for repo_key, ref in refs
        ]
        fetch_results = await asyncio.gather(*tasks, return_exceptions=True)

        for (repo_key, ref), result in zip(refs, fetch_results):
            if isinstance(result, Exception):
                self.logger.debug(
                    f"Failed to fetch SHA for {repo_key}@{ref}: {result}"
                )
                continue
            if result and isinstance(result, dict) and "sha" in result:
                results[(repo_key, ref)] = result["sha"]

        return results

    async def _detect_repository_redirect(self, repo_key: str) -> str | None:
        """
        Detect if a repository has been moved/redirected.

        Uses HTTP HEAD requests to the GitHub web URL (not API) to detect
        repository moves via HTTP 301 redirects. This avoids API rate limits
        and works for both validation methods.

        Args:
            repo_key: Repository in format "owner/repo"

        Returns:
            New repository location if redirected, None otherwise
        """
        # Check cache first
        cached = self._cache.get_redirect(repo_key)
        if cached:
            return cached

        # Use HTTP HEAD request to detect redirect via web URL (not API)
        if self._http_client:
            try:
                # Use web URL instead of API URL to avoid rate limits
                response = await self._http_client.head(
                    f"https://github.com/{repo_key}"
                )

                # Check for redirect (301 Moved Permanently)
                if (
                    response.status_code == 301
                    and "location" in response.headers
                ):
                    location = response.headers["location"]

                    # Extract new repository from location header
                    match = re.search(r"github\.com/([^/]+/[^/]+)", location)
                    if match:
                        new_repo = match.group(1)
                        if new_repo.lower() != repo_key.lower():
                            self.logger.debug(
                                f"Detected redirect: {repo_key} -> {new_repo}"
                            )
                            # Cache the redirect
                            self._cache.put_redirect(repo_key, new_repo)
                            return new_repo
            except Exception as e:
                self.logger.debug(
                    f"Redirect detection failed for {repo_key}: {e}"
                )

        return None

    def _get_base_repository(self, repo_key: str) -> str:
        """
        Extract base repository from a repo key that might include a path.

        For example:
        - "github/codeql-action/init" -> "github/codeql-action"
        - "actions/checkout" -> "actions/checkout"

        Args:
            repo_key: Repository key, possibly with path

        Returns:
            Base repository (owner/repo)
        """
        parts = repo_key.split("/")
        if len(parts) >= 2:
            return f"{parts[0]}/{parts[1]}"
        return repo_key

    def _build_fixed_line(
        self,
        action_call: ActionCall,
        new_ref: str,
        version_comment: str | None = None,
        new_repo: str | None = None,
    ) -> str:
        """Build the fixed action call line."""
        # Extract indentation and YAML structure from original line
        original_line = action_call.raw_line

        # Match the full structure with optional dash
        # First try: indentation + "- " + "uses: "
        structure_match = re.match(r"^(\s*-\s*uses:\s*)", original_line)
        if structure_match:
            prefix = structure_match.group(1)
        else:
            # Second try: indentation + "uses: " (no dash)
            structure_match = re.match(r"^(\s*uses:\s*)", original_line)
            if structure_match:
                prefix = structure_match.group(1)
            else:
                # Fallback: extract indentation and add basic "uses: "
                indent_match = re.match(r"^(\s*)", original_line)
                indent = indent_match.group(1) if indent_match else ""
                prefix = f"{indent}uses: "

        # Build the new action reference
        # Use new_repo if provided (for repository redirects), otherwise use original
        if new_repo:
            new_action_ref = f"{new_repo}@{new_ref}"
        else:
            new_action_ref = (
                f"{action_call.organization}/{action_call.repository}@{new_ref}"
            )

        # Add version comment if needed
        comment_part = ""
        if version_comment and self.config.require_pinned_sha:
            comment_spacing = "  " if self.config.two_space_comments else " "
            comment_part = f"{comment_spacing}# {version_comment}"
        elif action_call.comment:
            # Preserve existing comment (which already includes the # symbol)
            comment_spacing = "  " if self.config.two_space_comments else " "
            # Strip leading # if present to avoid duplication
            clean_comment = action_call.comment.lstrip("#").strip()
            comment_part = f"{comment_spacing}# {clean_comment}"

        final_line = f"{prefix}{new_action_ref}{comment_part}"
        return final_line

    async def _apply_fixes_to_file(
        self, file_path: Path, line_fixes: dict[int, tuple[str, str]]
    ) -> list[dict[str, str]]:
        """Apply fixes to a workflow file."""
        try:
            with open(file_path, encoding="utf-8") as f:
                lines = f.readlines()

            # Apply fixes (line numbers are 1-based)
            changes = []
            for i, _line in enumerate(lines, 1):
                if i in line_fixes:
                    old_line, new_line = line_fixes[i]
                    lines[i - 1] = new_line + "\n"
                    changes.append(
                        {
                            "line_number": str(i),
                            "old_line": old_line,
                            "new_line": new_line,
                        }
                    )

            # Write back to file
            with open(file_path, "w", encoding="utf-8") as f:
                f.writelines(lines)

            return changes

        except Exception as e:
            self.logger.error(f"Failed to apply fixes to {file_path}: {e}")
            raise
