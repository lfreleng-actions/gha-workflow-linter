# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Scan one file: scripts directly, YAML through its run: steps."""

from __future__ import annotations

import re

from linter import BlockScan
from pythonpath_tokens import SELF, TEXT, UNKNOWN, WORKSPACE, Token
from tables import RULES
from words import Block, Finding
import yaml_steps
from yaml_steps import Expr, Lit

MARKER = re.compile(
    re.escape(yaml_steps.MARK_OPEN)
    + r"(\w+):(\d+)"
    + re.escape(yaml_steps.MARK_CLOSE)
)
MARKER_NAMES = {
    "action_path": "GHEXPR_ACTION_PATH",
    "workspace": "GHEXPR_WORKSPACE",
    "pythonpath": "GHEXPR_PYTHONPATH",
}
PYTHON_EXPRESSION = re.compile(
    r"python[-_](?:path|bin|executable)|python_path|pythonLocation|\.python\b"
)
SHEBANG_ERREXIT = re.compile(r"^#!.*\s-[a-zA-Z]*e[a-zA-Z]*(?:\s|$)")


def scan_text(text: str, kind: str, repo: str, relpath: str) -> list[Finding]:
    """Every finding in one file's text."""
    out: list[Finding] = []
    if kind == "script":
        lines = text.split("\n")
        starts = [(0, 1)]
        for m in re.finditer("\n", text):
            starts.append((m.end(), text.count("\n", 0, m.end()) + 1))
        errexit = bool(SHEBANG_ERREXIT.match(lines[0]))
        block = Block(text, 1, starts, kind, errexit=errexit)
        BlockScan(block, repo, relpath, lines, out).run()
        return out
    lines = yaml_steps.split_lines(text)
    found = yaml_steps.read(text, kind)
    for yblock in found.blocks:
        block = yaml_block(yblock, found.expressions, kind)
        BlockScan(block, repo, relpath, lines, out).run()
    for number, word in found.setup_uv:
        ok = word is not None and located_path(
            word.parts, {"action_path", "temp"}, kind
        )
        if not ok:
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
        probe.line_at = lambda node, number=number: number  # type: ignore[method-assign]
        probe.src = b""
        probe.judge_pythonpath(yaml_tokens(word), _Anchor(), tilde=False)
    out.sort(key=lambda f: f.line)
    return out


def yaml_block(
    yblock: yaml_steps.Block,
    expressions: list[yaml_steps.Expression],
    kind: str,
) -> Block:
    """A run: step as a block: expressions marked, env and trust read.

    Each ``${{ }}`` expression becomes a same-shaped word the parser
    reads as plain text, named for what it is when that matters.
    """

    def swap(m: re.Match[str]) -> str:
        name = MARKER_NAMES.get(m.group(1))
        if name is None:
            expr = expressions[int(m.group(2))].text
            name = (
                "GHEXPR_PYTHON"
                if PYTHON_EXPRESSION.search(expr)
                else "GHEXPR_OTHER"
            )
        return name

    env: dict[str, str | None] = {}
    for name, word in yblock.env.items():
        literal = all(isinstance(p, Lit) for p in word.parts)
        env[name] = (
            "".join(p.text for p in word.parts if isinstance(p, Lit))
            if literal
            else None
        )
    trusted = yblock.directory is not None and located_path(
        yblock.directory.parts, {"action_path"}, kind
    )
    return Block(
        MARKER.sub(swap, yblock.text),
        yblock.starts[0][1],
        list(yblock.starts),
        kind,
        env,
        trusted,
        yblock.errexit,
    )


def yaml_tokens(word: yaml_steps.Word) -> list[Token]:
    """A YAML env: PYTHONPATH value as tokens: literal text and expressions."""
    tokens: list[Token] = []
    for part in word.parts:
        if isinstance(part, Lit):
            tokens.append(Token(TEXT, part.text))
        elif part.kind == "workspace":
            tokens.append(Token(WORKSPACE, "${{ github.workspace }}"))
        elif part.kind == "pythonpath":
            tokens.append(Token(SELF, "${{ env.PYTHONPATH }}"))
        else:
            tokens.append(Token(UNKNOWN, "${{ ... }}"))
    return tokens


def located_path(parts: list[Lit | Expr], kinds: set[str], kind: str) -> bool:
    """A YAML path that stays outside the workspace.

    It starts with an expression of one of ``kinds`` (the action path,
    which a workflow has none of, or the runner's temp directory) or
    with ``/``, and the literal rest does not climb.
    """
    if not parts:
        return False
    head, rest = parts[0], parts[1:]
    if isinstance(head, Expr):
        located = head.kind in kinds and not (
            head.kind == "action_path" and kind == "workflow"
        )
    else:
        located = head.text.startswith("/")
    if not located or not all(isinstance(p, Lit) for p in rest):
        return False
    tail = "".join(p.text for p in rest if isinstance(p, Lit))
    return ".." not in tail.split("/")


class _Anchor:
    """A stand-in node for findings on YAML values."""

    start_byte = 0
    end_byte = 0
