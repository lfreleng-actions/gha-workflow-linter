# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""One block of shell: parsed, then walked command by command.

The block is a step's ``run:`` text or a whole script. The scan parses
it with tree-sitter-bash and hands each command to the per-command
judgement in ``_commands``. No fact is carried from one command to
another: no directory trust from a ``cd`` or the step's
``working-directory``. Variable values count in one place:
``_trust.ShellFacts`` reads a name assigned once that holds a trusted
interpreter (PPA013).
"""

from __future__ import annotations

from bisect import bisect_right
from typing import TYPE_CHECKING

from tree_sitter import Parser

from gha_workflow_linter.shell._tree import BASH
from gha_workflow_linter.shell._tree import node_text as _node_text

from ._commands import CommandChecks
from ._invocation import IGNORE_MARK, RULES
from ._trust import ShellFacts
from ._words import Finding

if TYPE_CHECKING:
    from collections.abc import Iterator

    from tree_sitter import Node

    from ._words import Block


class BlockScan(CommandChecks):
    """Scan one block of shell."""

    def __init__(
        self,
        block: Block,
        repo: str,
        path: str,
        lines: list[str],
        out: list[Finding],
    ):
        self.block = block
        self.repo = repo
        self.path = path
        self.lines = lines
        self.out = out
        self.src = block.text.encode()
        self.tree = Parser(BASH).parse(self.src)
        self.facts = ShellFacts(self.src, self.tree.root_node, block.env)
        self.seen: set[tuple[int, str, str]] = set()

    # -- reporting

    def line_at(self, node: Node) -> int:
        """The source line a node starts on, by binary search of the starts."""
        starts = self.block.line_of_offset
        index = bisect_right(starts, node.start_byte, key=lambda s: s[0])
        return starts[index - 1][1] if index else self.block.first_line

    def report(self, node: Node, rule: str, detail: str | None = None) -> None:
        number = self.line_at(node)
        here = self.lines[number - 1] if 0 < number <= len(self.lines) else ""
        above = (
            self.lines[number - 2] if 1 < number <= len(self.lines) + 1 else ""
        )
        if IGNORE_MARK in here or IGNORE_MARK in above:
            return
        snippet = " ".join(_node_text(self.src, node).split())[:160]
        key = (number, rule, snippet)
        if key in self.seen:
            return
        self.seen.add(key)
        self.out.append(
            Finding(
                self.repo,
                self.path,
                number,
                self.block.kind,
                rule,
                detail or RULES[rule],
                snippet,
            )
        )

    # -- walking

    def run(self) -> None:
        root = self.tree.root_node
        if root.has_error:
            for node in self.errors(root):
                self.report(node, "PPA010")
        self.visit(root, depth=0, sink=False)

    def errors(self, node: Node) -> Iterator[Node]:
        if node.type == "ERROR" or node.is_missing:
            yield node
            return
        for child in node.children:
            yield from self.errors(child)

    def visit(self, node: Node, depth: int, sink: bool) -> None:
        """Visit every command; ``sink``: its standard output reaches $GITHUB_ENV."""
        if depth > 200:
            self.report(node, "PPA010", "shell nested too deeply")
            return
        if node.type == "redirected_statement":
            body = node.children[0]
            redirects = node.children[1:]
            sink_here = self.stdout_to_env(redirects, sink)
            if body.type == "command":
                self.command(body, redirects, sink_here)
                self.visit_children(body, depth, sink)
                for r in redirects:
                    self.visit_children(r, depth, sink)
                return
            if body.type == "pipeline":
                # tree-sitter hangs the last stage's redirects on the
                # whole pipeline.
                fed = not self.stdin_replaced(redirects)
                self.visit_pipeline(body, depth + 1, sink_here, fed, redirects)
                for r in redirects:
                    self.visit(r, depth + 1, sink_here)
                return
            for child in node.children:
                self.visit(child, depth + 1, sink_here)
            return
        if node.type == "command":
            self.command(node, [], sink)
            self.visit_children(node, depth, sink)
            return
        if node.type == "pipeline":
            self.visit_pipeline(node, depth, sink, fed=True)
            return
        if node.type in ("variable_assignment", "declaration_command"):
            self.assignment(node)
        self.visit_children(node, depth, sink)

    def visit_pipeline(
        self,
        node: Node,
        depth: int,
        sink: bool,
        fed: bool,
        redirects: list[Node] | None = None,
    ) -> None:
        """Visit a pipeline's stages; ``sink``: the last stage's output reaches $GITHUB_ENV.

        A stage's output reaches the file through the stages after it,
        from the last stage's destination back; ``fed`` is false when
        the last stage reads other input. ``redirects`` are the last
        stage's, which tree-sitter hangs on the whole pipeline.
        """
        stages = [c for c in node.children if c.is_named]
        reaches = [sink]
        for index in range(len(stages) - 1, 0, -1):
            fed_here = fed or index < len(stages) - 1
            reached = fed_here and self.input_to_env(stages[index], reaches[-1])
            reaches.append(reached)
        for stage, reached in zip(stages, reversed(reaches), strict=True):
            if redirects and stage == stages[-1] and stage.type == "command":
                self.command(stage, redirects, reached)
                self.visit_children(stage, depth + 1, reached)
            else:
                self.visit(stage, depth + 1, reached)

    def visit_children(self, node: Node, depth: int, sink: bool) -> None:
        for child in node.children:
            # A command substitution's output is captured, not written
            # where the outer command's output goes; so is an input
            # process substitution's (<(...)), which the command reads.
            captured = child.type == "command_substitution" or (
                child.type == "process_substitution"
                and _node_text(self.src, child).startswith("<(")
            )
            self.visit(child, depth + 1, sink and not captured)
