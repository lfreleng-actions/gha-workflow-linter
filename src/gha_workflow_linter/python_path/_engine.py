# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Python import-path scan: discovery, per-file scan and entry point.

Reports where a workflow, composite action or shell script starts
Python or ``uv`` so that files in the working directory take part in
what runs. Run as ``python -m gha_workflow_linter.python_path._engine
PATH...``: it exits 0 when the scan is clean, 1 with findings, and 2
when it could not read a file or a path.
"""

from __future__ import annotations

import argparse
from dataclasses import asdict
import json
import os
import re
import sys
from typing import TYPE_CHECKING

from gha_workflow_linter.shell import _yaml
from gha_workflow_linter.shell._discovery import (
    candidate_files,
    classify_kind,
    explicit_kind,
    shebang_names_shell,
)
from gha_workflow_linter.shell._yaml import Expr, Lit, swapped_text

from ._block import BlockScan
from ._invocation import (
    IGNORE_MARK,
    RULES,
    expression_marker,
    is_outside_path,
)
from ._pythonpath import SELF, TEXT, UNKNOWN, WORKSPACE, Token
from ._words import Block, Finding

if TYPE_CHECKING:
    from collections.abc import Sequence

# Discovery lives in the shared shell package; its entry points stay
# importable from here, where the scan's callers have always found them.
__all__ = [
    "RULES",
    "Finding",
    "candidate_files",
    "classify_kind",
    "explicit_kind",
    "main",
    "scan",
    "scan_text",
    "shebang_names_shell",
]


def repo_root_of(path: str, root: str) -> str:
    """The git work tree holding ``path``, else the scan root.

    Under a directory root, the search stops at the root, which may be
    a folder of repositories. A file named on its own may sit anywhere
    in its repository, so every ancestor is searched.
    """
    root = os.path.abspath(root)
    single = not os.path.isdir(root)
    top = os.path.dirname(root) if single else root
    directory = os.path.dirname(os.path.abspath(path))
    while True:
        if os.path.exists(os.path.join(directory, ".git")):
            return directory
        at_top = directory == top and not single
        if at_top or os.path.dirname(directory) == directory:
            return top
        directory = os.path.dirname(directory)


MARKER = re.compile(
    re.escape(_yaml.MARK_OPEN) + r"(\w+):(\d+)" + re.escape(_yaml.MARK_CLOSE)
)
MARKER_NAMES = {
    kind: expression_marker(kind.upper())
    for kind in ("action_path", "workspace", "pythonpath", "temp")
}
# An expression whose name says Python: setup-python's python-path
# output and the like, or any name ending in a py/python stem.
PYTHON_EXPRESSION = re.compile(
    r"python[-_](?:path|bin|executable)|python_path|pythonLocation"
    r"|\.(?:py|python\d*(?:\.\d+)?|[a-z_]*_py(?:thon)?)\s*\}\}$",
    re.I,
)
# setup-uv's uv-path output and similar: an expression that names uv.
UV_EXPRESSION = re.compile(r"(?<![A-Za-z])uvx?(?![A-Za-z])", re.I)


def scan_text(text: str, kind: str, repo: str, relpath: str) -> list[Finding]:
    """Every finding in one file's text; ValueError when it cannot be read."""
    try:
        return _scan_text(text, kind, repo, relpath)
    except RecursionError as error:
        raise ValueError("shell or YAML nested too deeply to scan") from error


def _scan_text(text: str, kind: str, repo: str, relpath: str) -> list[Finding]:
    """Every finding in one file's text."""
    out: list[Finding] = []
    text = _yaml.scrub(text)
    if kind == "script":
        lines = text.split("\n")
        starts = [(0, 1)]
        offset = 0
        for number, line in enumerate(lines[:-1], start=2):
            offset += len(line.encode()) + 1
            starts.append((offset, number))
        block = Block(text, 1, starts, kind)
        BlockScan(block, repo, relpath, lines, out).run()
        return out
    lines = _yaml.split_lines(text)
    found = _yaml.read(text, kind)
    for yblock in found.blocks:
        block = yaml_block(yblock, found.expressions, kind)
        BlockScan(block, repo, relpath, lines, out).run()
    for number, word in found.setup_uv:
        ok = word is not None and located_path(
            word.parts, {"action_path", "temp"}, kind
        )
        marks = lines[max(number - 2, 0) : number]
        if not ok and not any(IGNORE_MARK in line for line in marks):
            snippet = lines[number - 1].strip()
            out.append(
                Finding(
                    repo,
                    relpath,
                    number,
                    kind,
                    "PPA008",
                    RULES["PPA008"],
                    snippet,
                )
            )
    for number, word in found.pythonpath:
        probe = BlockScan(
            Block("", number, [(0, number)], kind), repo, relpath, lines, out
        )
        probe.judge_pythonpath(
            yaml_tokens(word, kind),
            probe.tree.root_node,
            tilde=False,
            swapped=False,
        )
    out.sort(key=lambda f: f.line)
    return out


def yaml_block(
    yblock: _yaml.Block,
    expressions: list[_yaml.Expression],
    kind: str,
) -> Block:
    """A run: step as a block: expressions marked and env read.

    Each ``${{ }}`` expression becomes a word the parser reads as
    plain text, named for what it is when that matters, between
    private-use characters no text in the file can be taken for.
    """

    def swap(m: re.Match[str]) -> str:
        name = MARKER_NAMES.get(m.group(1))
        if m.group(1) == "action_path" and kind == "workflow":
            # A workflow has no action path: the expression is empty.
            name = expression_marker("OTHER")
        if name is None:
            expr = expressions[int(m.group(2))].text
            if PYTHON_EXPRESSION.search(expr):
                marker = "PYTHON"
            elif UV_EXPRESSION.search(expr):
                marker = "UV"
            else:
                marker = "OTHER"
            name = expression_marker(marker)
        return name

    env: dict[str, str | None] = {}
    for name, word in yblock.env.items():
        literal = all(isinstance(p, Lit) for p in word.parts)
        env[name] = (
            "".join(p.text for p in word.parts if isinstance(p, Lit))
            if literal
            else None
        )
    text, starts = swapped_text(yblock, expressions, swap)
    return Block(text, yblock.starts[0][1], starts, kind, env)


def yaml_tokens(word: _yaml.Word, kind: str) -> list[Token]:
    """A YAML env: PYTHONPATH value as tokens: literal text and expressions."""
    tokens: list[Token] = []
    for part in word.parts:
        if isinstance(part, Lit):
            tokens.append(Token(TEXT, part.text))
        elif part.kind == "workspace":
            tokens.append(Token(WORKSPACE, "${{ github.workspace }}"))
        elif part.kind == "pythonpath":
            tokens.append(Token(SELF, "${{ env.PYTHONPATH }}"))
        elif part.kind == "action_path" and kind == "workflow":
            # Empty in a workflow: the text around it is all there is.
            tokens.append(Token(TEXT, ""))
        elif part.kind in ("action_path", "temp"):
            tokens.append(Token(UNKNOWN, "${{ ... }}"))
        else:
            tokens.append(Token("unresolved", "${{ ... }}"))
    return tokens


def located_path(parts: list[Lit | Expr], kinds: set[str], kind: str) -> bool:
    """A YAML path that stays outside the workspace.

    It starts with an expression of one of ``kinds`` (the action path,
    which a workflow has none of, or the runner's temp directory) and
    the literal rest is empty or a subpath that does not climb, or it
    is wholly a literal absolute path outside the runners' workspaces.
    """
    if not parts or not all(isinstance(p, Lit) for p in parts[1:]):
        return False
    head = parts[0]
    tail = "".join(p.text for p in parts if isinstance(p, Lit))
    if isinstance(head, Lit):
        return is_outside_path(tail)
    located = head.kind in kinds and not (
        head.kind == "action_path" and kind == "workflow"
    )
    subpath = tail == "" or tail.startswith("/")
    return located and subpath and ".." not in tail.split("/")


def scan(
    roots: Sequence[str], problems: list[str] | None = None
) -> list[Finding]:
    """Every finding in the files under ``roots``, in discovery order.

    A root may be a folder of repositories, one repository, or a file.
    Each finding names its repository (the git work tree holding the
    file, else the root) and its path within it. A path that cannot be
    read or scanned is added to ``problems`` when it is given.
    """
    missed = problems if problems is not None else []
    findings: list[Finding] = []
    for root in roots:
        for path, kind in candidate_files(root, missed):
            repo_root = repo_root_of(path, root)
            relpath = os.path.relpath(os.path.abspath(path), repo_root)
            repo = os.path.basename(repo_root)
            try:
                with open(path, encoding="utf-8", errors="replace") as handle:
                    text = handle.read()
                findings.extend(scan_text(text, kind, repo, relpath))
            except (OSError, ValueError) as error:
                missed.append(f"{path}: {error}")
    return findings


def main(argv: Sequence[str] | None = None) -> int:
    """Scan the paths named, print the findings, and return the exit code."""
    parser = argparse.ArgumentParser(
        prog="python -m gha_workflow_linter.python_path._engine",
        description="Report Python and uv runs that take in workspace files.",
    )
    parser.add_argument("paths", nargs="+", help="files or folders to scan")
    parser.add_argument(
        "--json", action="store_true", help="print the findings as JSON"
    )
    parser.add_argument(
        "--kinds",
        default="action,workflow,script",
        help="comma-separated kinds of file to report (default: all)",
    )
    options = parser.parse_args(argv)
    kinds = {k.strip() for k in options.kinds.split(",") if k.strip()}
    problems: list[str] = []
    findings = [f for f in scan(options.paths, problems) if f.kind in kinds]
    if options.json:
        print(json.dumps([asdict(f) for f in findings], indent=2))
    else:
        for f in findings:
            print(f"{f.repo}/{f.path}:{f.line}: {f.rule} {f.detail}")
            print(f"    {f.snippet}")
    for problem in problems:
        print(f"not scanned: {problem}", file=sys.stderr)
    if problems:
        return 2
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
