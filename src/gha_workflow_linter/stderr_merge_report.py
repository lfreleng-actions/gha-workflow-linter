# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Running and rendering the stderr-merge check.

The check is offline: it reads shell from the checkout and never calls
the GitHub API. So it runs whatever the API's state, and whether or not
the workflow scan found anything for the action-call check to validate.

* :func:`run_stage` scans the repository when the check is on.
* :func:`render_text` writes a section per file, with each finding's
  rule, confidence, line, source line and fix.
* :func:`build_json` returns the ``stderr_merge`` object of the JSON
  document. It is always present, with ``checked: false`` when the
  check did not run, so a consumer can tell "off" from "clean".
* :func:`exit_code` applies ``--verify-stderr-merge``.
"""

from __future__ import annotations

from collections import defaultdict
import logging
from typing import TYPE_CHECKING, Any

from rich.markup import escape

from . import exit_codes
from .console import console
from .stderr_merge import StderrMergeResult, scan_repository

if TYPE_CHECKING:
    from collections.abc import Iterable

    from .models import CLIOptions, Config
    from .scanner import WorkflowScanner
    from .stderr_merge import StderrMergeFinding

__all__ = [
    "build_json",
    "exit_code",
    "render_text",
    "run_stage",
]

_STYLES = {"high": "red", "medium": "yellow", "low": "dim"}


def run_stage(
    config: Config, options: CLIOptions, scanner: WorkflowScanner
) -> StderrMergeResult | None:
    """Scan the repository for stderr merges, when the check is on.

    Args:
        config: Resolved configuration, for the mode and excludes.
        options: Resolved CLI options, for the path and named files.
        scanner: The run's scanner, for what discovery leaves out as
            gitignored. Asked inside the guard: placing a root that
            loops raises ``RuntimeError`` before Python 3.13.

    Returns:
        The result, or ``None`` when the check is off. A check that
        fails outright returns an empty result naming the failure in
        ``problems``, so the run goes on, as the allow-list check does.
    """
    if not config.stderr_merge.mode.runs:
        return None
    logger = logging.getLogger(__name__)
    try:
        result = scan_repository(
            options.path,
            files=options.files,
            exclude=config.exclude_patterns,
            ignored=scanner.ignored_paths(options.path),
        )
    except Exception as error:  # noqa: BLE001 - an advisory check must not stop the run
        logger.error(f"stderr-merge check failed: {error}")
        return StderrMergeResult([], 0, (f"check failed: {error}",))
    for problem in result.problems:
        logger.warning(f"stderr-merge could not read {problem}")
    return result


def exit_code(config: Config, result: StderrMergeResult | None) -> int:
    """Choose this check's contribution to the exit code.

    Args:
        config: Resolved configuration, for ``verify`` and the floor.
        result: The check's result, or ``None`` when it did not run.

    Returns:
        ``STDERR_MERGE_FOUND`` when enforcement was requested and an
        unsuppressed finding at or above the floor remains, and
        ``RUNTIME_ERROR`` when enforcement was requested and a file
        could not be read: a check that did not look must not pass.
        Without ``verify`` the check never changes the exit code.
    """
    settings = config.stderr_merge
    if result is None or not settings.verify:
        return exit_codes.SUCCESS
    codes = [exit_codes.SUCCESS]
    if result.enforced(settings.min_confidence.value):
        codes.append(exit_codes.STDERR_MERGE_FOUND)
    if result.problems:
        codes.append(exit_codes.RUNTIME_ERROR)
    return exit_codes.combine(*codes)


def _by_file(
    findings: Iterable[StderrMergeFinding],
) -> dict[str, list[StderrMergeFinding]]:
    grouped: dict[str, list[StderrMergeFinding]] = defaultdict(list)
    for finding in findings:
        grouped[finding.path].append(finding)
    return dict(sorted(grouped.items()))


def _print_finding(finding: StderrMergeFinding) -> None:
    style = _STYLES[finding.confidence]
    label = f"{finding.rule} {finding.confidence}"
    console.print(
        f"    line {finding.line}  [{style}]{label}[/{style}]  "
        f"{escape(finding.detail)}"
    )
    console.print(f"      [dim]{escape(finding.snippet)}[/dim]")
    if finding.suppressed:
        reason = finding.reason or "no reason given"
        console.print(f"      [dim]suppressed: {escape(reason)}[/dim]")
    else:
        console.print(f"      [cyan]fix: {escape(finding.fix)}[/cyan]")


def render_text(
    result: StderrMergeResult | None, *, show_suppressed: bool
) -> None:
    """Write the human-readable stderr-merge report to the console.

    Nothing is printed when the check did not run or found nothing.

    Args:
        result: The check's result, or ``None`` when it did not run.
        show_suppressed: List suppressed findings with their reasons.
    """
    if result is None:
        return
    shown = [
        finding
        for finding in result.findings
        if show_suppressed or not finding.suppressed
    ]
    summary = result.summary()
    if shown:
        console.print(
            "[bold yellow]stderr merged into output used as data"
            "[/bold yellow]\n"
        )
        for path, findings in _by_file(shown).items():
            console.print(f"  [bold]{escape(path)}[/bold]")
            for finding in findings:
                _print_finding(finding)
            console.print()
    if summary["suppressed"] and not show_suppressed:
        console.print(
            f"[dim]{summary['suppressed']} stderr merge(s) suppressed — "
            "use --show-suppressed for detail[/dim]\n"
        )


def _empty_summary() -> dict[str, Any]:
    return StderrMergeResult([], files_scanned=0).summary()


def build_json(result: StderrMergeResult | None) -> dict[str, Any]:
    """Build the ``stderr_merge`` object of the JSON report.

    Suppressed findings are always included, carrying
    ``"suppressed": true``.

    Args:
        result: The check's result, or ``None`` when it did not run.

    Returns:
        A single-key dictionary, ready to merge into the document.
    """
    if result is None:
        return {
            "stderr_merge": {
                "checked": False,
                "findings": [],
                "summary": _empty_summary(),
                "problems": [],
            }
        }
    return {
        "stderr_merge": {
            "checked": True,
            "findings": [finding.to_dict() for finding in result.findings],
            "summary": result.summary(),
            "problems": list(result.problems),
        }
    }
