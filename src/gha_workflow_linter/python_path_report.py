# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Running and rendering the python-path check.

The check is offline: it reads shell from the checkout with the import
path engine in :mod:`gha_workflow_linter.python_path` and never calls
the GitHub API. It reads the files the stderr-merge check reads, found
the same way.

* :func:`run_stage` scans the repository when the check is on.
* :func:`render_text` writes a section per file, with each finding's
  rule, line, detail and command.
* :func:`build_json` returns the ``python_path`` object of the JSON
  document. It is always present, with ``checked: false`` when the
  check did not run, so a consumer can tell "off" from "clean", and
  ``verify`` says whether the run enforced the check, from the command
  line or the configuration file.
* :func:`exit_code` applies ``--verify-python-path``.

PPA009 and PPA010 say the scan could not prove a command safe, not that
it is unsafe, so they are reported but never fail a run.
"""

from __future__ import annotations

from bisect import bisect_right
from collections import defaultdict, deque
from dataclasses import dataclass
import logging
import os
from pathlib import Path
from typing import TYPE_CHECKING, Any, NamedTuple

from rich.markup import escape
from tree_sitter import Parser
import yaml

from . import exit_codes
from .console import console
from .directives import Directive, Suppression, find_suppression
from .python_path._block import BlockScan
from .python_path._engine import RULES, repo_root_of, scan_text, yaml_block
from .shell import _yaml
from .shell._discovery import candidate_files, explicit_kind
from .shell._tree import BASH, node_text
from .stderr_merge import named_files

if TYPE_CHECKING:
    from collections.abc import Iterable

    from .git_ignored import IgnoreScope
    from .models import CLIOptions, Config
    from .python_path._words import Finding
    from .scanner import WorkflowScanner

__all__ = [
    "ENFORCEABLE_RULES",
    "KINDS",
    "PythonPathFinding",
    "PythonPathResult",
    "build_json",
    "comments",
    "exit_code",
    "render_text",
    "run_stage",
    "scan_repository",
]

ENFORCEABLE_RULES = frozenset(f"PPA00{n}" for n in range(1, 9))
"""Rules ``--verify-python-path`` fails on. PPA009 and PPA010 are notices."""

KINDS = ("action", "workflow", "script")
"""The kinds of file the engine reads, as the summary counts them."""


@dataclass(frozen=True)
class PythonPathFinding:
    """One engine finding, with any ``python-path-ok`` directive on it."""

    repo: str
    path: str
    line: int
    kind: str
    rule: str
    detail: str
    snippet: str
    suppressed: bool = False
    reason: str | None = None

    @property
    def enforceable(self) -> bool:
        """Whether ``--verify-python-path`` fails on this rule."""
        return self.rule in ENFORCEABLE_RULES

    def to_dict(self) -> dict[str, Any]:
        """The finding as the JSON document reports it."""
        return {
            "repo": self.repo,
            "path": self.path,
            "line": self.line,
            "kind": self.kind,
            "rule": self.rule,
            "detail": self.detail,
            "snippet": self.snippet,
            "suppressed": self.suppressed,
        }


@dataclass
class PythonPathResult:
    """What one scan found, and what it could not read."""

    findings: list[PythonPathFinding]
    files_scanned: int = 0
    problems: tuple[str, ...] = ()
    verify: bool = False

    def enforced(self) -> list[PythonPathFinding]:
        """Unsuppressed findings of a rule from PPA001 to PPA008."""
        return [f for f in self.findings if f.enforceable and not f.suppressed]

    def summary(self) -> dict[str, Any]:
        """Counts by rule and by kind, suppressed findings apart."""
        active = [f for f in self.findings if not f.suppressed]
        return {
            "total": len(active),
            "suppressed": len(self.findings) - len(active),
            "enforced": len(self.enforced()),
            "files_scanned": self.files_scanned,
            "by_rule": {
                rule: sum(1 for f in active if f.rule == rule) for rule in RULES
            },
            "by_kind": {
                kind: sum(1 for f in active if f.kind == kind) for kind in KINDS
            },
        }


# A ``run:`` block as its comments know it: its value and where each of
# its lines starts. An alias repeats its anchor's key, and so do two
# steps whose values and lines match, whose comments match too.
BlockKey = tuple[str, tuple[tuple[int, int], ...]]

# The one block of shell a script is.
SCRIPT = 0


class Comments(NamedTuple):
    """The comments a file holds, by 1-based line.

    A line holds two comments when a quoted one-line ``run:`` value
    carries a shell comment and a YAML comment follows the value. A
    comment is held once on its line, however many YAML aliases repeat
    the step it is in.
    """

    by_line: dict[int, tuple[str, ...]]
    """Every comment on each line, the shell's before the YAML's."""
    leading: frozenset[int]
    """The lines a comment starts, before any other text on them."""
    yaml: dict[int, tuple[str, ...]]
    """The YAML comments alone: every finding on their line shares them."""
    shell: dict[int, dict[int, tuple[str, ...]]]
    """Each block's shell comments, by block id: its own findings alone
    share them."""
    yaml_leading: frozenset[int]
    """The lines a YAML comment starts."""
    shell_leading: dict[int, frozenset[int]]
    """The lines a shell comment starts, by block id."""


# Comments by line while they are collected: a dict keeps each line's
# comments in order and holds each once.
_Found = dict[int, dict[str, None]]

# The text a ``${{ }}`` expression becomes: one plain shell word.
EXPRESSION_WORD = "GHA_EXPRESSION"

# The columns of one line a scalar covers: from a start to an end, open
# when the end is ``None``.
Span = tuple[int, int | None]


def _script_starts(text: str) -> list[tuple[int, int]]:
    """Byte offset and number of each line of a script."""
    starts = [(0, 1)]
    offset = 0
    for number, line in enumerate(text.split("\n")[:-1], start=2):
        offset += len(line.encode()) + 1
        starts.append((offset, number))
    return starts


def _shell_comments(
    block: str,
    starts: list[tuple[int, int]],
    into: _Found,
) -> set[int]:
    """Add each comment the shell parser finds in a block, by line.

    Returns:
        The lines a comment starts, before any other text on them.
    """
    src = block.encode()
    leading: set[int] = set()
    pending = [Parser(BASH).parse(src).root_node]
    while pending:
        node = pending.pop()
        if node.type == "comment":
            index = bisect_right(
                starts, node.start_byte, key=lambda start: start[0]
            )
            offset, number = starts[max(index - 1, 0)]
            into.setdefault(number, {})[node_text(src, node)] = None
            if not src[offset : node.start_byte].strip():
                leading.add(number)
        pending.extend(node.children)
    return leading


def _scalar_spans(text: str) -> dict[int, list[Span]]:
    """The columns each 0-based line gives to scalar text.

    A ``#`` there is part of a value, not a comment. A block scalar's
    text starts on the line after its indicator, so a comment after the
    indicator stays a comment; its span ends at the start of the line
    after its last line, so the next line is not covered at all.
    """
    spans: dict[int, list[Span]] = defaultdict(list)
    pending: list[yaml.Node] = [
        document
        for document in yaml.compose_all(text, Loader=yaml.SafeLoader)
        if document is not None
    ]
    seen: set[int] = set()
    while pending:
        node = pending.pop()
        if id(node) in seen:  # an alias repeats its anchor's node
            continue
        seen.add(id(node))
        if isinstance(node, yaml.MappingNode):
            pending.extend(part for pair in node.value for part in pair)
        elif isinstance(node, yaml.SequenceNode):
            pending.extend(node.value)
        elif isinstance(node, yaml.ScalarNode):
            first, start = (
                int(node.start_mark.line),
                int(node.start_mark.column),
            )
            last, end = int(node.end_mark.line), int(node.end_mark.column)
            if node.style in ("|", ">"):
                first, start = first + 1, 0
            if first == last:
                spans[first].append((start, end))
                continue
            spans[first].append((start, None))
            for line in range(first + 1, last):
                spans[line].append((0, None))
            spans[last].append((0, end))
    return spans


def _yaml_comment(line: str, spans: Iterable[Span]) -> int | None:
    """The column a YAML comment opens on a line, if one does.

    A ``#`` opens one at the start of a line or after blank space,
    outside any scalar's text. The spans are sorted once and swept in
    step with the ``#`` columns, so a line of many quoted values costs
    no more than sorting them.
    """
    ordered = sorted(spans, key=lambda span: span[0])
    position = 0
    reach = -1  # the furthest end of a span opened so far
    for index, char in enumerate(line):
        if char != "#" or (index and line[index - 1] not in " \t"):
            continue
        while position < len(ordered) and ordered[position][0] <= index:
            end = ordered[position][1]
            reach = max(reach, len(line) if end is None else end)
            position += 1
        if index >= reach:
            return index
    return None


def _key(block: _yaml.Block) -> BlockKey:
    """The key a ``run:`` block's comments are held under."""
    return (block.text, tuple(block.starts))


def _block_ids(blocks: list[_yaml.Block]) -> list[int]:
    """The id each block's comments are held under.

    A block's id is the index of the first block with its key, so an
    alias shares its anchor's. Each key is built and hashed once, and
    the rest of the check passes the id around rather than rehash a
    long block's key for every line it covers.
    """
    first: dict[BlockKey, int] = {}
    return [
        first.setdefault(_key(block), index)
        for index, block in enumerate(blocks)
    ]


def comments(
    text: str, kind: str, yaml_file: _yaml.YamlFile | None = None
) -> Comments:
    """The comments a file holds, read with full quote context.

    Each ``run:`` value is parsed as decoded YAML, so a ``#`` inside a
    shell string, quoted or ANSI-C, opens no comment, and one inside a
    quoted YAML value does. Outside the shell, a ``#`` opens a comment
    only where no YAML scalar's text holds it, so directive-shaped text
    inside a block or quoted value is text.

    Args:
        text: The file's text, scrubbed.
        kind: ``action``, ``workflow`` or ``script``.
        yaml_file: The file as :func:`_yaml.read` reads it, when the
            caller has read it already.

    Returns:
        The comments on each line, all together, the YAML's alone and
        each block's shell comments alone, and the lines a comment
        starts, before any other text on them: only there does a
        directive suppress a finding on the line below.
    """
    if kind == "script":
        found: _Found = {}
        leading = _shell_comments(text, _script_starts(text), found)
        script = _frozen(found)
        return Comments(
            script,
            frozenset(leading),
            {},
            {SCRIPT: script},
            frozenset(),
            {SCRIPT: frozenset(leading)},
        )
    if yaml_file is None:
        yaml_file = _yaml.read(text, kind)
    lines = _yaml.split_lines(text)
    leading = set()
    merged: _Found = {}
    shells: dict[int, dict[int, tuple[str, ...]]] = {}
    shell_leading: dict[int, frozenset[int]] = {}
    for block, ident in zip(
        yaml_file.blocks, _block_ids(yaml_file.blocks), strict=True
    ):
        # An alias repeats its anchor's step, comments and all.
        if ident in shells:
            continue
        swapped, starts = _yaml.swapped_text(
            block, yaml_file.expressions, lambda _m: EXPRESSION_WORD
        )
        found = {}
        # A quoted or plain value's first line starts after its key.
        shell_leading[ident] = frozenset(
            number
            for number in _shell_comments(swapped, starts, found)
            if lines[number - 1].lstrip().startswith("#")
        )
        leading.update(shell_leading[ident])
        shells[ident] = _frozen(found)
        for number, texts in found.items():
            merged.setdefault(number, {}).update(texts)
    spans = _scalar_spans(text)
    yaml_found: _Found = {}
    yaml_leading: set[int] = set()
    for index, line in enumerate(lines):
        column = _yaml_comment(line, spans.get(index, ()))
        if column is not None:
            yaml_found.setdefault(index + 1, {})[line[column:]] = None
            merged.setdefault(index + 1, {})[line[column:]] = None
            if not line[:column].strip():
                yaml_leading.add(index + 1)
    return Comments(
        _frozen(merged),
        frozenset(leading | yaml_leading),
        _frozen(yaml_found),
        shells,
        frozenset(yaml_leading),
        shell_leading,
    )


def _frozen(found: _Found) -> dict[int, tuple[str, ...]]:
    """The comments collected on each line, in the order found."""
    return {number: tuple(texts) for number, texts in found.items()}


def _origins(
    found: list[Finding],
    yaml_file: _yaml.YamlFile | None,
    text: str,
    kind: str,
) -> list[int | None]:
    """The block id each finding came from, or ``None`` for a YAML line.

    A line one block alone covers needs no more. Where steps share a
    line, as in a flow sequence, or a step shares one with a setup-uv
    or ``env: PYTHONPATH`` finding, each block on it is scanned on its
    own, as the engine scans it, to tell their findings apart. The
    engine reports the blocks' findings in block order, then the YAML
    lines', and sorts them by line alone, so equal findings are matched
    in that order. A block's env decides what the engine finds in it,
    so equal blocks are scanned once per env they carry.

    Args:
        found: The engine's findings for the file, in its order.
        yaml_file: The file as :func:`_yaml.read` reads it; ``None``
            for a script, whose findings all come from its one block.
        text: The file's text, scrubbed.
        kind: ``action`` or ``workflow``.

    Returns:
        The origin of each finding, in the same order.
    """
    if yaml_file is None:
        return [SCRIPT] * len(found)
    ids = _block_ids(yaml_file.blocks)
    covering: dict[int, set[int]] = defaultdict(set)
    for block, ident in zip(yaml_file.blocks, ids, strict=True):
        for _offset, number in block.starts:
            covering[number].add(ident)
    yaml_lines = {number for number, _word in yaml_file.setup_uv}
    yaml_lines.update(number for number, _word in yaml_file.pythonpath)
    if all(
        len(keys) == 1 and number not in yaml_lines
        for number, keys in covering.items()
    ):
        return [
            next(iter(covering[f.line])) if f.line in covering else None
            for f in found
        ]
    if not found:
        return []
    lines = _yaml.split_lines(text)
    scanned: dict[
        tuple[int, tuple[tuple[str, str | None], ...]], list[Finding]
    ] = {}
    queued: dict[tuple[str, ...], deque[int]] = defaultdict(deque)
    for block, ident in zip(yaml_file.blocks, ids, strict=True):
        engine_block = yaml_block(block, yaml_file.expressions, kind)
        key = (ident, tuple(sorted(engine_block.env.items())))
        if key not in scanned:
            out: list[Finding] = []
            BlockScan(
                engine_block, found[0].repo, found[0].path, lines, out
            ).run()
            scanned[key] = out
        for finding in scanned[key]:
            queued[_identity(finding)].append(ident)
    origins: list[int | None] = []
    for finding in found:
        waiting = queued.get(_identity(finding))
        origins.append(waiting.popleft() if waiting else None)
    return origins


def _identity(finding: Finding) -> tuple[str, ...]:
    """What tells one finding from another in a file."""
    return (str(finding.line), finding.rule, finding.detail, finding.snippet)


def _suppression(
    number: int, found: Comments, origin: int | None
) -> Suppression | None:
    """A ``python-path-ok`` directive above or on a finding's line.

    On its line and the line above, a finding shares the YAML comments
    and its own block's shell comments, never another step's. A
    directive on the line above counts only where a comment starts that
    line: inside a shell string or a YAML value it is text.
    """
    previous = number - 1
    own = found.shell.get(origin, {}) if origin is not None else {}
    own_leading = (
        found.shell_leading.get(origin, frozenset())
        if origin is not None
        else frozenset()
    )
    above = (own.get(previous, ()) if previous in own_leading else ()) + (
        found.yaml.get(previous, ()) if previous in found.yaml_leading else ()
    )
    on_line = own.get(number, ()) + found.yaml.get(number, ())
    for comment in on_line or (None,):
        for preceding in above or (None,):
            suppression = find_suppression(
                comment=comment, preceding_line=preceding
            )
            if (
                suppression is not None
                and Directive.PYTHON_PATH_OK in suppression.directives
            ):
                return suppression
    return None


def _judged(
    finding: Finding,
    found: Comments,
    origin: int | None,
    cache: dict[tuple[int, int | None], Suppression | None],
) -> PythonPathFinding:
    """A finding with the directive on its line, read once per block.

    A line can hold one comment per step of a flow sequence, so each
    block's directive on a line is looked up once and shared by its
    findings, and by an alias's.
    """
    where = (finding.line, origin)
    if where not in cache:
        cache[where] = _suppression(finding.line, found, origin)
    suppression = cache[where]
    return PythonPathFinding(
        repo=finding.repo,
        path=finding.path,
        line=finding.line,
        kind=finding.kind,
        rule=finding.rule,
        detail=finding.detail,
        snippet=finding.snippet,
        suppressed=suppression is not None,
        reason=suppression.reason if suppression else None,
    )


def _relative(path: Path, root: Path) -> str:
    """A path as the report names it: from the root, with ``/``."""
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def _discovered(
    root: Path,
    exclude: list[str],
    ignored: IgnoreScope | None,
    problems: list[str],
) -> list[tuple[Path, str]]:
    """Files discovery finds under the root, less excluded and ignored ones.

    The same filter the stderr-merge check applies: both prune the
    walk, so nothing beneath an excluded or ignored directory is read.
    """

    def skip(name: str) -> bool:
        if any(pattern in name for pattern in exclude):
            return True
        return ignored is not None and ignored.ignores(Path(name))

    return [
        (Path(name), kind)
        for name, kind in candidate_files(str(root), problems, skip)
    ]


def scan_repository(
    root: Path,
    *,
    files: Iterable[str] | None = None,
    exclude: Iterable[str] = (),
    ignored: IgnoreScope | None = None,
) -> PythonPathResult:
    """Scan a repository, or the files named in it, for Python runs.

    Discovery reads composite action metadata, workflows under
    ``.github/workflows`` and shell scripts, leaving out excluded and
    gitignored paths. Files named with ``files`` are always scanned.

    Args:
        root: The scanned path.
        files: The ``--files`` patterns, when given.
        exclude: The exclude patterns.
        ignored: What discovery leaves out as gitignored.

    Returns:
        The findings, each with its suppression, and the files the
        engine could not read or parse.
    """
    problems: list[str] = []
    targets = (
        [(path, explicit_kind(str(path))) for path in named_files(root, files)]
        if files
        else _discovered(root, list(exclude), ignored, problems)
    )
    findings: list[PythonPathFinding] = []
    for path, kind in targets:
        relpath = _relative(path, root)
        repo = os.path.basename(repo_root_of(str(path), str(root)))
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
            found = scan_text(text, kind, repo, relpath)
            scrubbed = _yaml.scrub(text)
            yaml_file = None if kind == "script" else _yaml.read(scrubbed, kind)
            notes = comments(scrubbed, kind, yaml_file)
            origins = _origins(found, yaml_file, scrubbed, kind)
        except (OSError, ValueError, RecursionError) as error:
            problems.append(f"{relpath}: {error}")
            continue
        cache: dict[tuple[int, int | None], Suppression | None] = {}
        findings.extend(
            _judged(finding, notes, origin, cache)
            for finding, origin in zip(found, origins, strict=True)
        )
    return PythonPathResult(findings, len(targets), tuple(problems))


def run_stage(
    config: Config, options: CLIOptions, scanner: WorkflowScanner
) -> PythonPathResult | None:
    """Scan the repository for Python runs, when the check is on.

    Args:
        config: Resolved configuration, for the mode and excludes.
        options: Resolved CLI options, for the path and named files.
        scanner: The run's scanner, for what discovery leaves out as
            gitignored. Asked inside the guard: placing a root that
            loops raises ``RuntimeError`` before Python 3.13.

    Returns:
        The result, or ``None`` when the check is off. A check that
        fails outright returns an empty result naming the failure in
        ``problems``, so the run goes on, as the stderr-merge check does.
    """
    if not config.python_path.mode.runs:
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
        logger.error(f"python-path check failed: {error}")
        result = PythonPathResult([], 0, (f"check failed: {error}",))
    result.verify = config.python_path.verify
    for problem in result.problems:
        logger.warning(f"python-path could not read {problem}")
    return result


def exit_code(config: Config, result: PythonPathResult | None) -> int:
    """Choose this check's contribution to the exit code.

    Args:
        config: Resolved configuration, for ``verify``.
        result: The check's result, or ``None`` when it did not run.

    Returns:
        ``PYTHON_PATH_FOUND`` when enforcement was requested and an
        unsuppressed finding of a rule from PPA001 to PPA008 remains,
        and ``RUNTIME_ERROR`` when enforcement was requested and a file
        could not be read: a check that did not look must not pass.
        PPA009 and PPA010 never count. Without ``verify`` the check
        never changes the exit code.
    """
    if result is None or not config.python_path.verify:
        return exit_codes.SUCCESS
    codes = [exit_codes.SUCCESS]
    if result.enforced():
        codes.append(exit_codes.PYTHON_PATH_FOUND)
    if result.problems:
        codes.append(exit_codes.RUNTIME_ERROR)
    return exit_codes.combine(*codes)


def _by_file(
    findings: Iterable[PythonPathFinding],
) -> dict[str, list[PythonPathFinding]]:
    grouped: dict[str, list[PythonPathFinding]] = defaultdict(list)
    for finding in findings:
        grouped[finding.path].append(finding)
    return dict(sorted(grouped.items()))


def _print_finding(finding: PythonPathFinding) -> None:
    if finding.enforceable:
        label = f"[yellow]{finding.rule}[/yellow]"
    else:
        label = f"[dim]{finding.rule} notice[/dim]"
    console.print(f"    line {finding.line}  {label}  {escape(finding.detail)}")
    console.print(f"      [dim]{escape(finding.snippet)}[/dim]")
    if finding.suppressed:
        reason = finding.reason or "no reason given"
        console.print(f"      [dim]suppressed: {escape(reason)}[/dim]")


def render_text(
    result: PythonPathResult | None, *, show_suppressed: bool
) -> None:
    """Write the human-readable python-path report to the console.

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
            "[bold yellow]Python runs that take in workspace files"
            "[/bold yellow]\n"
        )
        for path, findings in _by_file(shown).items():
            console.print(f"  [bold]{escape(path)}[/bold]")
            for finding in findings:
                _print_finding(finding)
            console.print()
    if summary["suppressed"] and not show_suppressed:
        console.print(
            f"[dim]{summary['suppressed']} python-path finding(s) "
            "suppressed — use --show-suppressed for detail[/dim]\n"
        )


def build_json(result: PythonPathResult | None) -> dict[str, Any]:
    """Build the ``python_path`` object of the JSON report.

    Suppressed findings are always included, carrying
    ``"suppressed": true``. ``verify`` is the setting the run enforced,
    whether ``--verify-python-path`` or the configuration file chose
    it, so a reader such as the Action can grade findings as the exit
    code does.

    Args:
        result: The check's result, or ``None`` when it did not run.

    Returns:
        A single-key dictionary, ready to merge into the document.
    """
    if result is None:
        return {
            "python_path": {
                "checked": False,
                "verify": False,
                "findings": [],
                "summary": PythonPathResult([]).summary(),
                "problems": [],
            }
        }
    return {
        "python_path": {
            "checked": True,
            "verify": result.verify,
            "findings": [finding.to_dict() for finding in result.findings],
            "summary": result.summary(),
            "problems": list(result.problems),
        }
    }
