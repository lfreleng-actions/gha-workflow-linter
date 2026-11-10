# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Scan files for stderr merges: blocks, line numbers, tags, suppression."""

from __future__ import annotations

from bisect import bisect_right
from dataclasses import dataclass
from pathlib import Path
import re
from typing import TYPE_CHECKING, Any

import yaml

from gha_workflow_linter.directives import (
    Directive,
    Suppression,
    find_suppression,
)
from gha_workflow_linter.shell import _yaml
from gha_workflow_linter.shell._discovery import candidate_files, explicit_kind

from ._analysis import BlockAnalysis
from ._rules import CONFIDENCES, RULES, rank

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable

    from gha_workflow_linter.git_ignored import IgnoreScope

# The triggers that make a workflow's defects reach further.
TRIGGER_TAGS = ("workflow_call", "pull_request_target", "workflow_run")
SECRETS = re.compile(r"\$\{\{[^}]*\bsecrets\.|^\s*secrets:\s*inherit\b", re.M)
CHECKOUT = re.compile(r"uses:\s*['\"]?actions/checkout@")
# The text a ${{ }} expression becomes: one plain shell word.
EXPRESSION_WORD = "GHA_EXPRESSION"


@dataclass(frozen=True)
class StderrMergeFinding:
    """One stderr merge whose output a step uses as data."""

    path: str
    line: int
    rule: str
    detail: str
    snippet: str
    variable: str | None = None
    tags: tuple[str, ...] = ()
    suppressed: bool = False
    reason: str | None = None

    @property
    def confidence(self) -> str:
        """How sure the rule is: high, medium or low."""
        return RULES[self.rule].confidence

    @property
    def fix(self) -> str:
        """The fix the rule suggests."""
        return RULES[self.rule].fix

    def to_dict(self) -> dict[str, Any]:
        """The finding as the JSON document reports it."""
        return {
            "path": self.path,
            "line": self.line,
            "rule": self.rule,
            "confidence": self.confidence,
            "detail": self.detail,
            "snippet": self.snippet,
            "variable": self.variable,
            "tags": list(self.tags),
            "suppressed": self.suppressed,
        }


@dataclass
class StderrMergeResult:
    """What one scan found, and what it could not read."""

    findings: list[StderrMergeFinding]
    files_scanned: int = 0
    problems: tuple[str, ...] = ()

    def enforced(
        self, min_confidence: str = "medium"
    ) -> list[StderrMergeFinding]:
        """Unsuppressed findings at or above ``min_confidence``."""
        floor = rank(min_confidence)
        return [
            f
            for f in self.findings
            if not f.suppressed and rank(f.confidence) >= floor
        ]

    def summary(self) -> dict[str, Any]:
        """Counts by rule and by confidence, suppressed findings apart."""
        active = [f for f in self.findings if not f.suppressed]
        return {
            "total": len(active),
            "suppressed": len(self.findings) - len(active),
            "files_scanned": self.files_scanned,
            "by_rule": {
                rule: sum(1 for f in active if f.rule == rule) for rule in RULES
            },
            "by_confidence": {
                level: sum(1 for f in active if f.confidence == level)
                for level in reversed(CONFIDENCES)
            },
        }


def _line_finder(starts: list[tuple[int, int]]) -> Callable[[int], int]:
    """Map a byte offset in a block to its 1-based source line."""

    def line_at(offset: int) -> int:
        index = bisect_right(starts, offset, key=lambda start: start[0])
        return starts[max(index - 1, 0)][1]

    return line_at


def _script_starts(text: str) -> list[tuple[int, int]]:
    """Byte offset and number of each line of a script."""
    starts = [(0, 1)]
    offset = 0
    for number, line in enumerate(text.split("\n")[:-1], start=2):
        offset += len(line.encode()) + 1
        starts.append((offset, number))
    return starts


Shell = tuple[str, list[tuple[int, int]], dict[int, str]]


def _blocks(text: str, kind: str) -> list[Shell]:
    """Each block of shell in a file, with its byte line starts.

    The third part maps a line to the YAML comment after a one-line
    ``run:`` value, which YAML takes out of the shell's text.
    """
    if kind == "script":
        return [(text, _script_starts(text), {})]
    found = _yaml.read(text, kind)
    shells: list[Shell] = []
    for block in found.blocks:
        swapped, starts = _yaml.swapped_text(
            block, found.expressions, lambda _m: EXPRESSION_WORD
        )
        comments = dict([block.comment]) if block.comment else {}
        shells.append((swapped, starts, comments))
    return shells


def _triggers(document: dict[Any, Any]) -> set[str]:
    """The event names a workflow runs on."""
    # PyYAML reads an unquoted ``on`` key as True.
    events = document.get("on", document.get(True))
    if isinstance(events, str):
        return {events}
    if isinstance(events, (list, dict)):
        return {str(event) for event in events}
    return set()


def _writes(document: dict[Any, Any]) -> bool:
    """Whether the workflow or any job grants a write permission."""
    grants = [document.get("permissions")]
    jobs = document.get("jobs")
    if isinstance(jobs, dict):
        grants += [
            j.get("permissions") for j in jobs.values() if isinstance(j, dict)
        ]
    for grant in grants:
        if grant == "write-all":
            return True
        if isinstance(grant, dict) and "write" in grant.values():
            return True
    return False


def file_tags(text: str, kind: str) -> tuple[str, ...]:
    """Context tags for a file: what a defect in it puts at risk."""
    if kind == "action":
        return ("action",)
    if kind != "workflow":
        return ()
    try:
        document = yaml.safe_load(text)
    except (yaml.YAMLError, RecursionError, ValueError):
        # ValueError: a scalar safe_load cannot build, such as the
        # timestamp 2026-13-01. The shell is still read from the
        # composed nodes, so only the tags are lost.
        return ()
    if not isinstance(document, dict):
        return ()
    events = _triggers(document)
    tags = [tag for tag in TRIGGER_TAGS if tag in events]
    if SECRETS.search(text):
        tags.append("secrets")
    if _writes(document):
        tags.append("write-permissions")
    if not CHECKOUT.search(text):
        tags.append("no-checkout")
    return tuple(tags)


def _suppression(
    lines: list[str], number: int, comments: dict[int, str]
) -> Suppression | None:
    """A ``stderr-merge-ok`` directive above or on a finding's line."""
    above = lines[number - 2] if 1 < number <= len(lines) + 1 else None
    found = find_suppression(comment=comments.get(number), preceding_line=above)
    if found is None or Directive.STDERR_MERGE_OK not in found.directives:
        return None
    return found


def scan_text(text: str, kind: str, path: str) -> list[StderrMergeFinding]:
    """Every stderr merge used as data in one file's text.

    Raises ValueError when a workflow or action is not valid YAML.
    """
    text = _yaml.scrub(text)
    lines = text.split("\n") if kind == "script" else _yaml.split_lines(text)
    tags = file_tags(text, kind)
    findings: list[StderrMergeFinding] = []
    for block, starts, yaml_comments in _blocks(text, kind):
        line_at = _line_finder(starts)
        analysis = BlockAnalysis(block, line_at)
        comments = yaml_comments | {
            line_at(o): c for o, c in analysis.comments()
        }
        for hit in analysis.run():
            number = line_at(hit.offset)
            suppression = _suppression(lines, number, comments)
            snippet = lines[number - 1].strip() if number <= len(lines) else ""
            findings.append(
                StderrMergeFinding(
                    path=path,
                    line=number,
                    rule=hit.verdict.rule,
                    detail=hit.verdict.detail,
                    snippet=snippet[:200],
                    variable=hit.verdict.variable,
                    tags=tags,
                    suppressed=suppression is not None,
                    reason=suppression.reason if suppression else None,
                )
            )
    findings.sort(key=lambda f: f.line)
    return findings


def _relative(path: Path, root: Path) -> str:
    """A path as the report names it: from the root, with ``/``."""
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def _discovered(
    root: Path,
    exclude: Iterable[str],
    ignored: IgnoreScope | None,
    problems: list[str],
) -> list[tuple[Path, str]]:
    """Files discovery finds under the root, less excluded and ignored ones.

    Both filters prune the walk: an excluded or ignored directory is
    not entered, so an unreadable one beneath it is no problem. An
    exclude pattern matching a directory's path with a trailing
    separator matches every file beneath it. A nested repository (a
    directory below the root holding a ``.git`` entry) is not entered.
    """

    def skip(name: str) -> bool:
        if any(pattern in name for pattern in exclude):
            return True
        return ignored is not None and ignored.ignores(Path(name))

    return [
        (Path(name), kind)
        for name, kind in candidate_files(
            str(root), problems, skip, stop_at_repositories=True
        )
    ]


def _expand(root: Path, pattern: str) -> list[Path]:
    """The files one ``--files`` pattern names: itself, or its matches.

    An absolute pattern is expanded from its filesystem anchor, since
    ``Path.glob`` takes relative patterns only.
    """
    candidate = Path(pattern)
    if not candidate.is_absolute():
        candidate = root / pattern
    if candidate.is_file():
        return [candidate]
    base, relative = root, pattern
    if Path(pattern).is_absolute():
        base = Path(candidate.anchor)
        relative = candidate.relative_to(base).as_posix()
    if not relative:
        return []
    return sorted(p for p in base.glob(relative) if p.is_file())


def named_files(root: Path, patterns: Iterable[str]) -> list[Path]:
    """Every file the ``--files`` patterns select for the scan to read.

    Args:
        root: The scanned path, which relative patterns start from.
        patterns: The patterns, as given.

    Returns:
        The files, in the order the scan reads them.
    """
    return [path for path, _kind in _named(root, patterns)]


def _named(root: Path, patterns: Iterable[str]) -> list[tuple[Path, str]]:
    """Files named with ``--files``: always scanned, whatever they are."""
    found: list[tuple[Path, str]] = []
    seen: set[Path] = set()
    for pattern in patterns:
        matches = _expand(root, pattern)
        for match in matches:
            if match not in seen:
                seen.add(match)
                found.append((match, explicit_kind(str(match))))
    return found


def scan_repository(
    root: Path,
    *,
    files: Iterable[str] | None = None,
    exclude: Iterable[str] = (),
    ignored: IgnoreScope | None = None,
) -> StderrMergeResult:
    """Scan a repository, or the files named in it, for stderr merges.

    Discovery reads composite action metadata, workflows under
    ``.github/workflows`` and shell scripts, leaving out excluded and
    gitignored paths. Files named with ``files`` are always scanned.
    """
    problems: list[str] = []
    targets = (
        _named(root, files)
        if files
        else _discovered(root, list(exclude), ignored, problems)
    )
    findings: list[StderrMergeFinding] = []
    for path, kind in targets:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
            findings.extend(scan_text(text, kind, _relative(path, root)))
        except (OSError, ValueError, RecursionError) as error:
            problems.append(f"{_relative(path, root)}: {error}")
    return StderrMergeResult(findings, len(targets), tuple(problems))


__all__ = [
    "StderrMergeFinding",
    "StderrMergeResult",
    "file_tags",
    "named_files",
    "scan_repository",
    "scan_text",
]
