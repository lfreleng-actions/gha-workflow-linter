# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Find stderr merges in one block of shell, and how their output is used.

A merge is a command whose stderr reaches the place its stdout goes:
``2>&1``, ``&>``, ``|&``, or any command after ``exec 2>&1``. The
merged stream matters when a pipe or a capture takes it as data; it is
harmless when it goes to the log or is discarded.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import TYPE_CHECKING

from tree_sitter import Parser

from gha_workflow_linter.shell._tree import BASH, node_text

from ._paths import SavedStatus, failure_path, status_after
from ._rules import (
    EXITS,
    READ_SHORT,
    RULES,
    SILENT,
    anchored,
    by_design,
    consumer_kind,
    input_fd,
    is_logger,
    overwritten_names,
    rank,
    read_names,
    readiness_test,
    reads_stdin,
    written_names,
)
from ._words import (
    OUTPUT_GROUPS,
    apply_redirects,
    argument_file,
    command_parts,
    destination_file,
    enclosing,
    file_redirects,
    first_command,
    github_file,
    input_descriptor,
    later_redirects,
    merges,
    misparsed_herestring,
    output_redirects,
    pipeline_stages,
    stdin_replaced,
    stdout_destination,
    sure_to_run,
    within,
    word_command,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from tree_sitter import Node

    # A capture a value was copied from, with the status saved after it.
    Origin = tuple[Node, SavedStatus | None]

# How deep a capture may feed another capture before the walk stops.
MAX_DEPTH = 4
ARITHMETIC_ASSIGNMENTS = frozenset(
    {"=", "+=", "-=", "*=", "/=", "%=", "<<=", ">>=", "&=", "^=", "|="}
)
EXPANSIONS = frozenset({"simple_expansion", "expansion"})
# Nodes whose bare variable names are read as numbers.
ARITHMETIC = frozenset(
    {
        "arithmetic_expansion",
        "binary_expression",
        "compound_statement",
        "parenthesized_expression",
        "postfix_expression",
        "ternary_expression",
        "unary_expression",
    }
)
# Nodes a use passes through on its way to the command that reads it.
WORD_PARTS = frozenset({"string", "concatenation", "expansion", "array"})
TESTS = frozenset(
    {
        "test_command",
        "case_statement",
        "arithmetic_expansion",
        "binary_expression",
        "unary_expression",
        "parenthesized_expression",
    }
)
# Commands that print their arguments. ``cat`` opens its arguments as
# files, so a value given to it is passed on, not printed.
FEEDERS = frozenset({"echo", "printf"})
# Statements whose commands share the stdin the statement is given.
GROUPS = frozenset({"compound_statement", "subshell"})
# As GROUPS, with control flow: every command in its conditions and
# bodies reads the stdin the statement is given.
READ_GROUPS = GROUPS | {
    "if_statement",
    "case_statement",
    "for_statement",
    "c_style_for_statement",
}
# Statements a here-document feeds as a whole, not by their first command.
FED_BODIES = READ_GROUPS | {"pipeline", "while_statement"}
# Nodes whose commands never read the stdin of the statement around them.
UNREAD = frozenset(
    {
        "function_definition",
        "command_substitution",
        "process_substitution",
        "heredoc_body",
        "comment",
    }
)
# Nodes whose body runs in a shell of its own: an assignment or an
# ``exec`` inside one leaves the rest of the block alone.
SHELLS = frozenset({"subshell", "command_substitution", "process_substitution"})
# As SHELLS, and a function, whose ``exec`` is read as its own.
EXEC_SCOPES = SHELLS | {"function_definition"}
# Nodes an assignment may sit in and still always replace the value.
INLINE = frozenset(
    {"variable_assignment", "declaration_command", "compound_statement"}
)
# Nodes a statement's stdout passes through on its way to a capture.
PASSES = OUTPUT_GROUPS | {"pipeline", "redirected_statement"}
# POSIX special built-ins: an assignment before one outlives it in
# ``sh`` and in Bash's POSIX mode, so it is still followed.
SPECIAL_BUILTINS = frozenset(
    {
        ":",
        ".",
        "break",
        "continue",
        "eval",
        "exec",
        "exit",
        "export",
        "readonly",
        "return",
        "set",
        "shift",
        "times",
        "trap",
        "unset",
    }
)
# Statement lists whose members all run, one after another.
SEQUENCES = frozenset(
    {"program", "compound_statement", "do_group", "subshell", "case_item"}
)
COMPARED = "$value is compared"
# Where a statement's stdout and stderr go before its own redirects.
START = {1: "out", 2: "err"}


@dataclass(frozen=True)
class Verdict:
    """What a merged stream is used for."""

    rule: str
    detail: str
    variable: str | None = None

    @property
    def confidence(self) -> str:
        """The rule's confidence."""
        return RULES[self.rule].confidence


# Uses whose context alone decides the rule.
CONTEXT_VERDICTS = {kind: Verdict("SEM002", COMPARED) for kind in TESTS} | {
    "for_statement": Verdict("SEM003", "$value is split by a for loop")
}


@dataclass(frozen=True)
class Hit:
    """One merge used as data, at a byte offset in the block."""

    offset: int
    verdict: Verdict


def _keep_surer(hits: dict[int, Hit], hit: Hit) -> None:
    """Record a hit at its offset, unless one as sure is already there."""
    held = hits.get(hit.offset)
    if held is None or rank(hit.verdict.confidence) > rank(
        held.verdict.confidence
    ):
        hits[hit.offset] = hit


def _surer(a: Verdict | None, b: Verdict | None) -> Verdict | None:
    """The more confident verdict, the first on a tie."""
    if a is None:
        return b
    if b is None:
        return a
    return b if rank(b.confidence) > rank(a.confidence) else a


class BlockAnalysis:
    """Every merge in one block of shell whose output is used as data."""

    def __init__(self, text: str, line_at: Callable[[int], int]) -> None:
        self.src = text.encode()
        self.line_at = line_at
        self.tree = Parser(BASH).parse(self.src)
        self.execs: list[Node] = []
        self.uses: dict[str, list[Node]] = {}
        self.assigns: dict[str, list[Node]] = {}
        self.writes: dict[str, list[int]] = {}
        self.overwrites: dict[str, list[Node]] = {}
        self.pipelines: list[Node] = []
        self.captures: list[Node] = []
        self._index(self.tree.root_node)

    def _index(self, root: Node) -> None:
        """Collect what the walk needs in one pass over the tree."""
        pending = [root]
        while pending:
            node = pending.pop()
            pending.extend(reversed(node.children))
            self._note(node)

    def _note(self, node: Node) -> None:
        """Record one node, if it is of a kind the walk needs."""
        kind = node.type
        if kind == "pipeline":
            self.pipelines.append(node)
        elif kind == "command_substitution":
            self.captures.append(node)
        elif kind in EXPANSIONS:
            name = next(
                (c for c in node.named_children if c.type == "variable_name"),
                None,
            )
            if name is not None:
                key = node_text(self.src, name)
                self.uses.setdefault(key, []).append(node)
        elif kind == "variable_assignment":
            name = node.child_by_field_name("name")
            if name is not None:
                key = node_text(self.src, name)
                self.assigns.setdefault(key, []).append(node)
        elif kind == "redirected_statement" and self._is_exec(node):
            self.execs.append(node)
        elif kind == "command":
            command, args = command_parts(self.src, node)
            for key in written_names(command, args):
                self.writes.setdefault(key, []).append(node.start_byte)
            reads = command in READ_SHORT
            if sure_to_run(self.src, node, reads, self.execs):
                for key in overwritten_names(command, args):
                    self.overwrites.setdefault(key, []).append(node)
        elif kind == "variable_name":
            key = node_text(self.src, node)
            if self._is_written(node):
                self.writes.setdefault(key, []).append(node.start_byte)
                overwrite = self._overwrite_of(node)
                if overwrite is not None:
                    self.overwrites.setdefault(key, []).append(overwrite)
            if self._is_arithmetic_read(node):
                self.uses.setdefault(key, []).append(node)

    def _is_written(self, node: Node) -> bool:
        """Whether a bare variable name is set or unset where it stands.

        As a loop variable, by ``unset`` or ``local``, or on the left of
        an arithmetic assignment, ``++`` or ``--``.
        """
        parent = node.parent
        if parent is None:
            return False
        kind = parent.type
        if kind == "for_statement":
            return parent.child_by_field_name("variable") == node
        if kind in ("unset_command", "declaration_command"):
            return True
        if kind == "binary_expression":
            operator = parent.child_by_field_name("operator")
            return (
                parent.child_by_field_name("left") == node
                and operator is not None
                and node_text(self.src, operator) in ARITHMETIC_ASSIGNMENTS
            )
        if kind in ("postfix_expression", "unary_expression"):
            return any(c.type in ("++", "--") for c in parent.children)
        return False

    def _overwrite_of(self, node: Node) -> Node | None:
        """The statement part that replaces a written name's value, if any.

        ``(( v = 3 ))`` and ``unset v`` do; ``v++``, ``v += 1``, a loop
        variable, which an empty list leaves alone, ``local v`` and
        ``unset -f v``, which unsets a function, do not.
        """
        parent = node.parent
        if parent is None:
            return None
        if parent.type == "unset_command":
            options = [
                node_text(self.src, c)
                for c in parent.named_children
                if c.type == "word"
            ]
            if any(o.startswith("-") and "f" in o for o in options):
                return None
            return parent
        if parent.type != "binary_expression":
            return None
        operator = parent.child_by_field_name("operator")
        if operator is None or node_text(self.src, operator) != "=":
            return None
        return parent

    def _is_arithmetic_read(self, node: Node) -> bool:
        """Whether a bare variable name is read as a number where it stands.

        In arithmetic a bare name is a use, as in ``(( count > 3 ))``,
        unless it is the target of a plain ``=``, which only sets it.
        ``count++`` and ``count += 1`` read it as well as set it.
        """
        parent = node.parent
        if parent is None or parent.type not in ARITHMETIC:
            return False
        if parent.type != "binary_expression":
            return True
        operator = parent.child_by_field_name("operator")
        return not (
            parent.child_by_field_name("left") == node
            and operator is not None
            and node_text(self.src, operator) == "="
        )

    def comments(self) -> list[tuple[int, str]]:
        """Each shell comment in the block, with its byte offset."""
        found: list[tuple[int, str]] = []
        pending = [self.tree.root_node]
        while pending:
            node = pending.pop()
            if node.type == "comment":
                found.append((node.start_byte, node_text(self.src, node)))
            pending.extend(node.children)
        return found

    def _is_exec(self, node: Node) -> bool:
        """Whether a statement is ``exec`` moving the shell's descriptors."""
        body = node.children[0]
        if body.type != "command":
            return False
        name, args = command_parts(self.src, body)
        return name == "exec" and not args

    # -- where merges are

    def run(self) -> list[Hit]:
        """Every merge used as data, in source order.

        One hit per offset, the surest: two captures in one assignment,
        as in ``v="$(a 2>&1)$(b 2>&1)"``, share the offset.
        """
        hits: dict[int, Hit] = {}
        for pipeline in self.pipelines:
            for piped in self._pipe_hits(pipeline):
                _keep_surer(hits, piped)
        for capture in self.captures:
            hit = self._capture_hit(capture)
            if hit is not None:
                _keep_surer(hits, hit)
        return sorted(hits.values(), key=lambda h: h.offset)

    def _exec_active(self, node: Node) -> bool:
        """Whether the ``exec`` statements before this node merge it.

        Each ``exec`` in scope, in source order, moves the descriptors
        the next one starts from: ``exec 2>&1`` merges every later
        command, and a later ``exec 2>/dev/null`` ends that. The scope
        is the innermost function, subshell or substitution holding the
        ``exec``: ``(exec 2>&1); cmd`` leaves ``cmd`` alone.
        """
        merged = False
        for statement in self.execs:
            if statement.end_byte > node.start_byte:
                continue
            scope = statement.parent
            while scope is not None and scope.type not in EXEC_SCOPES:
                scope = scope.parent
            if scope is None or within(node, scope):
                merged = merges(self.src, statement.children[1:], merged)
        return merged

    def _stage_merges(self, stage: Node, piped: bool = False) -> list[Node]:
        """Each command whose stderr a pipeline stage merges into the pipe.

        ``piped`` says the stage ends in ``|&``, which Bash applies as a
        ``2>&1`` after the stage's own redirects.
        """
        if not piped:
            return self._merging(stage, START)
        body, redirects = stage, []
        if stage.type == "redirected_statement":
            body, redirects = stage.children[0], stage.children[1:]
        fds = apply_redirects(self.src, redirects, START)
        fds[2] = fds[1]
        return self._merging(body, fds)

    def _merging(self, node: Node, fds: dict[int, str]) -> list[Node]:
        """Each command in a statement whose stdout and stderr both reach
        where the statement's stdout goes.

        ``fds`` holds where the statement's stdout and stderr go before
        its own redirects: ``out`` for the place in question, ``err``
        for the shell's stderr. Bash applies a group's redirects before
        those of each command in it, so ``{ tool 2>/dev/null; } 2>&1``
        keeps ``tool``'s stderr out. Groups and control flow pass on
        what every statement in them writes, conditions included; a
        pipeline passes on what its last stage writes.
        """
        kind = node.type
        if kind == "redirected_statement":
            moved = apply_redirects(self.src, node.children[1:], fds)
            return self._merging(node.children[0], moved)
        if kind == "command":
            own = [c for c in node.children if "redirect" in c.type]
            moved = apply_redirects(self.src, own, fds)
            if self._exec_active(node):
                moved = {
                    k: "out" if v == "err" else v for k, v in moved.items()
                }
            return [node] if moved[1] == moved[2] == "out" else []
        if kind == "pipeline":
            return self._merging(pipeline_stages(node)[-1][0], fds)
        if kind in OUTPUT_GROUPS:
            found: list[Node] = []
            for child in node.named_children:
                found += self._merging(child, fds)
            return found
        return []

    def _pipe_hits(self, pipeline: Node) -> list[Hit]:
        """Each merge into a pipe whose later stages read it as data."""
        hits: list[Hit] = []
        stages = pipeline_stages(pipeline)
        for index, (stage, operator) in enumerate(stages[:-1]):
            producers = self._stage_merges(stage, piped=operator == "|&")
            if not producers:
                continue
            verdict = self._pipe_verdict(pipeline, index + 1, False, 0)
            hit = self._best_hit(stage, producers, verdict)
            if hit is not None:
                hits.append(hit)
        return hits

    def _capture_hit(self, capture: Node) -> Hit | None:
        """A merge whose stream a ``$( )`` keeps.

        Every merging command the capture keeps counts, each capped on
        its own when it writes its data to stderr by design, and the
        surest of them decides the hit.
        """
        producers: list[Node] = []
        for statement in capture.named_children:
            producers += self._merging(statement, START)
        if not producers:
            return None
        verdict = self._capture_verdict(capture, 0)
        return self._best_hit(
            self._owner(capture) or capture, producers, verdict
        )

    def _best_hit(
        self, anchor: Node, producers: list[Node], verdict: Verdict | None
    ) -> Hit | None:
        """The surest hit among merging commands, each capped on its own."""
        best: Hit | None = None
        for merged in producers:
            hit = self._hit(anchor, merged, verdict)
            if hit is not None and (
                best is None
                or rank(hit.verdict.confidence) > rank(best.verdict.confidence)
            ):
                best = hit
        return best

    def _hit(
        self, anchor: Node, merged: Node | None, verdict: Verdict | None
    ) -> Hit | None:
        """A hit, capped at SEM004 when the command writes data to stderr."""
        if verdict is None:
            return None
        if merged is not None and verdict.rule != "SEM004":
            name, args = command_parts(self.src, merged)
            if by_design(name, args):
                verdict = replace(
                    verdict,
                    rule="SEM004",
                    detail=f"{verdict.detail}; {name} writes this output "
                    "to stderr by design",
                )
        return Hit(anchor.start_byte, verdict)

    # -- how a merged stream is used

    def _stage_kind(self, stage: Node) -> tuple[str | None, str, list[str]]:
        """What a pipeline stage does with its input, and its command."""
        if stage.type == "redirected_statement":
            stage = stage.children[0]
        if stage.type == "while_statement":
            return self._loop_kind(stage), "a while-read loop", []
        if stage.type != "command":
            return None, "", []
        name, args = command_parts(self.src, stage)
        if name == "tee" and argument_file(self.src, stage) is not None:
            return "github", name, args
        return consumer_kind(name, args), name, args

    def _loop_kind(self, loop: Node, fd: int = 0) -> str | None:
        """A ``while read`` loop extracts, unless its body only logs.

        Only a ``read`` of descriptor ``fd`` reads what the loop is fed:
        ``while read -u 3 l`` leaves a pipe into the loop unread.

        A body writing to a ``$GITHUB_*`` file exports what it reads,
        whatever command writes it. A body that only logs, but prints
        what it reads to the loop's stdout, passes the stream on, as
        ``cat`` does: in ``... | while read -r l; do echo "$l"; done |
        jq .`` the lines reach ``jq``.
        """
        condition = first_command(loop)
        if condition is None:
            return None
        name, args = command_parts(self.src, condition)
        if name != "read" or input_fd(name, args) != fd or readiness_test(args):
            return None
        body = loop.child_by_field_name("body")
        commands = [] if body is None else self._commands_in(body)
        names = [command_parts(self.src, c)[0] for c in commands]
        if any(
            github_file(self.src, c) is not None
            and not self._stores(c)
            and n not in SILENT
            for c, n in zip(commands, names, strict=True)
        ):
            return "github"
        if not all(is_logger(n) or n in EXITS for n in names):
            return "extractor"
        read = self._loop_copies(commands, read_names(args))
        loggers = [
            c for c, n in zip(commands, names, strict=True) if is_logger(n)
        ]
        if body is not None and any(
            not any(within(use, logger) for logger in loggers)
            for use in self._uses_in(body, read)
        ):
            return "extractor"
        return "pass" if self._prints_read(commands, read) else None

    def _loop_copies(self, commands: list[Node], names: list[str]) -> list[str]:
        """``names``, and every name a ``printf -v`` in the loop copies
        one of them into.

        In ``while read -r l; do printf -v msg '%s' "$l"; echo "$msg";
        done`` the loop prints what it reads through ``msg``.
        """
        found = list(names)
        stores = [c for c in commands if self._stores(c)]
        for _ in stores:
            added = [
                target
                for command in stores
                if self._uses_in(command, found)
                for target in written_names(*command_parts(self.src, command))
                if target not in found
            ]
            if not added:
                break
            found += dict.fromkeys(added)
        return found

    def _uses_in(self, node: Node, names: list[str]) -> list[Node]:
        """Every use of ``names`` under a node, arithmetic included.

        A test, a ``case`` selector or ``(( l > 3 ))`` reads the value
        as well as a command's argument does; in arithmetic a bare
        name is a use.
        """
        return [
            use
            for name in names
            for use in self.uses.get(name, [])
            if within(use, node)
        ]

    def _prints_read(self, commands: list[Node], names: list[str]) -> bool:
        """Whether a feeder prints a read variable to the loop's stdout."""
        uses = [use for name in names for use in self.uses.get(name, [])]
        return any(
            command_parts(self.src, command)[0] in FEEDERS
            and not self._stores(command)
            and self._stage_sink(command) is None
            and any(within(use, command) for use in uses)
            for command in commands
        )

    def _stores(self, command: Node) -> bool:
        """Whether a command is ``printf -v``, which prints nothing."""
        name, args = command_parts(self.src, command)
        return name == "printf" and bool(written_names(name, args))

    def _commands_in(self, node: Node) -> list[Node]:
        """Every simple command under a node."""
        found: list[Node] = []
        pending = [node]
        while pending:
            current = pending.pop()
            if current.type == "command":
                found.append(current)
            pending.extend(current.named_children)
        return found

    def _pipe_verdict(
        self, pipeline: Node, start: int, variable: bool, depth: int
    ) -> Verdict | None:
        """What the stages from ``start`` on do with the merged stream.

        A stream that reaches the pipeline's stdout unread goes on to
        what reads that, as in ``{ tool 2>&1 | cat; } | jq .``.
        """
        verdict, onward = self._pipe_flow(pipeline, start, variable, depth)
        if verdict is None and onward:
            return self._piped_on(pipeline, depth, variable)
        return verdict

    def _pipe_flow(
        self, pipeline: Node, start: int, variable: bool, depth: int
    ) -> tuple[Verdict | None, bool]:
        """What the stages from ``start`` on do with the merged stream,
        and whether it reaches the pipeline's stdout unread.

        A pipeline nested in a group stage, as in ``a 2>&1 | { cat |
        cat; } | jq .``, hands the stream on to the stages after the
        group when every stage of it passes the stream on.
        """
        capture = self._output_capture(pipeline)
        kept = capture is not None or self._tested(pipeline)
        stages = pipeline_stages(pipeline)
        for index, (stage, _operator) in enumerate(stages):
            if index < start:
                continue
            if self._own_stdin(pipeline, stage, index == len(stages) - 1):
                return None, False
            verdict, onward = self._readers_verdict(
                stage, kept, variable, depth
            )
            if verdict is not None or not onward:
                return verdict, False
        if capture is not None:
            return self._capture_verdict(capture, depth + 1), False
        return None, True

    def _readers_verdict(
        self, stage: Node, kept: bool, variable: bool, depth: int
    ) -> tuple[Verdict | None, bool]:
        """What the commands reading a stage's stdin do with the stream.

        The surest verdict among them, and whether any passes the stream
        on down the pipeline unread, as ``cat`` does. A ``cat`` naming a
        file reads that file, not the stream.
        """
        best: Verdict | None = None
        onward = False
        for reader in self._stage_readers(stage):
            if reader.type == "pipeline":
                inner, forwards = self._pipe_flow(reader, 0, variable, depth)
                best = _surer(best, inner)
                onward = onward or forwards
                continue
            kind, name, args = self._stage_kind(reader)
            if not reads_stdin(name, args):
                continue
            sink = self._stage_sink(reader)
            if sink == "github" and kind in ("pass", "picker", "extractor"):
                kind = "github"
            elif kind == "pass" or (kind == "picker" and not kept):
                onward = onward or sink is None
                continue
            best = _surer(
                best, self._stream_verdict(kind, name, args, variable)
            )
        return best, onward

    def _stage_readers(self, stage: Node) -> list[Node]:
        """The commands that read a pipeline stage's stdin.

        A stage is one command or loop, or a group, subshell or control
        flow whose commands share its stdin, as in ``a 2>&1 | { jq .; }``
        or ``a 2>&1 | if c; then jq .; fi``. A command
        there with a stdin of its own reads nothing from the pipe, and of
        a pipeline there only the first stage reads it; that pipeline is
        returned whole, to be followed on.
        """
        body = stage
        if body.type == "redirected_statement":
            body = body.children[0]
        if body.type not in READ_GROUPS:
            return [stage]
        found: list[Node] = []
        pending = list(reversed(body.named_children))
        while pending:
            node = pending.pop()
            if node.type in ("while_statement", "pipeline"):
                found.append(node)
            elif node.type == "command":
                own = [c for c in node.children if "redirect" in c.type]
                if not stdin_replaced(self.src, own):
                    found.append(node)
            elif node.type == "redirected_statement":
                if not stdin_replaced(self.src, node.children[1:]):
                    pending.append(node.children[0])
            elif node.type not in UNREAD:
                pending.extend(reversed(node.named_children))
        return found

    def _own_stdin(self, pipeline: Node, stage: Node, last: bool) -> bool:
        """Whether a stage reads a stdin of its own instead of the pipe.

        tree-sitter-bash gives a redirect after the last stage, as in
        ``a | jq . <<EOF``, to the whole pipeline; Bash gives it to the
        last stage.
        """
        redirects: list[Node] = []
        if stage.type == "redirected_statement":
            redirects += stage.children[1:]
            stage = stage.children[0]
        if stage.type == "command":
            redirects += [c for c in stage.children if "redirect" in c.type]
        parent = pipeline.parent
        if (
            last
            and parent is not None
            and parent.type == "redirected_statement"
            and parent.children[0] == pipeline
        ):
            redirects += parent.children[1:]
        return stdin_replaced(self.src, redirects)

    def _stage_sink(self, stage: Node) -> str | None:
        """Where a stage's stdout goes, when not on down the pipeline.

        ``github`` for a ``$GITHUB_*`` file, ``elsewhere`` for any other
        file or descriptor, None when it goes on.
        """
        if stage.type == "redirected_statement":
            stage = stage.children[0]
        dest = stdout_destination(self.src, output_redirects(stage))
        if dest == "out":
            return None
        exported = destination_file(dest) is not None
        return "github" if exported else "elsewhere"

    def _stream_verdict(
        self, kind: str | None, name: str, args: list[str], variable: bool
    ) -> Verdict | None:
        """The rule for a stream, or a captured value, read by ``name``."""
        reader = "$value" if variable else "the merged stream"
        if kind == "github":
            return Verdict(
                "SEM001", f"{reader} is written to $GITHUB_* by {name}"
            )
        tests = {
            "exists": f"{reader} is tested with {name} -q",
            "ready": f"{reader} is only tested for input by {name} -t 0",
        }
        if kind in tests:
            return Verdict("SEM004", tests[kind])
        if kind not in ("parser", "extractor", "picker"):
            return None
        if anchored(name, args):
            return Verdict(
                "SEM004", f"{reader} is read by {name} for one prefix"
            )
        if kind == "parser":
            rule = "SEM002" if variable else "SEM001"
            return Verdict(rule, f"{reader} is parsed by {name}")
        rule = "SEM002" if variable else "SEM003"
        return Verdict(rule, f"{reader} is read by {name}")

    def _output_capture(self, node: Node) -> Node | None:
        """The ``$( )`` that keeps a statement's stdout, if one does."""
        while node.parent is not None:
            parent = node.parent
            if parent.type == "command_substitution":
                return parent
            last = parent.type != "pipeline" or (
                pipeline_stages(parent)[-1][0] == node
            )
            body = parent.type != "redirected_statement" or (
                parent.children[0] == node
                and stdout_destination(
                    self.src, file_redirects(parent.children[1:])
                )
                == "out"
            )
            passes = parent.type in PASSES
            if not (passes and last and body):
                return None
            node = parent
        return None

    def _tested(self, pipeline: Node) -> bool:
        """Whether a pipeline's output is compared, as in a test."""
        parent = pipeline.parent
        return parent is not None and parent.type in TESTS

    def _owner(self, capture: Node) -> Node | None:
        """The assignment a capture is the value of, if any."""
        node = capture
        while node.parent is not None and node.parent.type in WORD_PARTS:
            node = node.parent
        parent = node.parent
        if parent is not None and parent.type == "variable_assignment":
            return parent
        return None

    def _capture_verdict(self, capture: Node, depth: int) -> Verdict | None:
        """What the script does with a merged capture."""
        if depth > MAX_DEPTH:
            return None
        assign = self._owner(capture)
        if assign is None:
            verdict = self._use_verdict(capture, depth)
            if verdict is None:
                return None
            detail = verdict.detail.replace("$value", "the captured output")
            return replace(verdict, detail=detail)
        name = assign.child_by_field_name("name")
        if name is None:
            return None
        return self._variable_verdict(assign, node_text(self.src, name), depth)

    def _variable_verdict(
        self,
        assign: Node,
        name: str,
        depth: int,
        origins: tuple[Origin, ...] = (),
    ) -> Verdict | None:
        """The surest success-path use of a variable holding a merge.

        ``assign`` is an assignment, or a ``printf -v`` storing the value.
        ``origins`` are the captures and saved statuses the value was
        copied from: a use on the failure path of any of them runs only
        when that capture failed, as in ``out=$(a 2>&1); s=$?; c=$out``
        then ``if [ "$s" -ne 0 ]; then jq . <<< "$c"; fi``.
        """
        if self._temporary(assign):
            return None
        scope = enclosing(assign, "function_definition")
        shell = self._shell_of(assign)
        end = self._reassigned(assign, name, scope)
        chain = origins
        if assign.type != "command":
            chain += ((assign, self._saved_status(assign)),)
        best: Verdict | None = None
        for use in self.uses.get(name, []):
            if use.start_byte < assign.end_byte or use.start_byte >= end:
                continue
            if enclosing(use, "function_definition") != scope:
                continue
            if shell is not None and not within(use, shell):
                continue
            if any(failure_path(self.src, use, a, s) for a, s in chain):
                continue
            # A bare name in arithmetic, as in ``(( count > 3 ))``, reads
            # the value as a number.
            verdict = (
                Verdict("SEM002", COMPARED)
                if use.type == "variable_name"
                else self._use_verdict(use, depth, chain)
            )
            if verdict is not None:
                line = self.line_at(use.start_byte)
                detail = verdict.detail.replace("$value", f"${name}")
                verdict = Verdict(verdict.rule, f"{detail} (line {line})", name)
            best = _surer(best, verdict)
        return best

    def _saved_status(self, assign: Node) -> SavedStatus | None:
        """The variable the capture's status is saved in, and until when.

        Any later write to that variable ends what it says about the
        capture: ``s=$?; s=1`` leaves ``$s`` unrelated to it, as do
        ``read s``, ``printf -v s``, ``((s++))`` and ``unset s``.
        """
        saved = status_after(self.src, assign)
        if saved is None:
            return None
        name = saved.child_by_field_name("name")
        if name is None:
            return None
        key = node_text(self.src, name)
        writes = [o.start_byte for o in self.assigns.get(key, [])]
        writes += self.writes.get(key, [])
        later = [start for start in writes if start >= saved.end_byte]
        return SavedStatus(
            key, saved.end_byte, min(later, default=len(self.src) + 1)
        )

    def _temporary(self, assign: Node) -> bool:
        """Whether an assignment only sets a command's environment.

        In ``v=$(a 2>&1) true`` the value lives as long as ``true`` runs,
        and the shell's own ``$v`` is untouched; the command's words are
        expanded before it is set. Before a POSIX special built-in, as in
        ``v=$(a 2>&1) :``, ``sh`` keeps it, so it is still followed.
        """
        parent = assign.parent
        if assign.type != "variable_assignment" or parent is None:
            return False
        if parent.type != "command":
            return False
        name, _args = command_parts(self.src, parent)
        return bool(name) and name not in SPECIAL_BUILTINS

    def _shell_of(self, assign: Node) -> Node | None:
        """The subshell or substitution an assignment is made in, if any.

        Its value stays there: ``(v=$(a 2>&1)); jq . <<< "$v"`` reads
        the parent's ``v``. A child shell still sees the parent's value.
        """
        node = assign.parent
        while node is not None and node.type not in SHELLS:
            node = node.parent
        return node

    def _reassigned(self, assign: Node, name: str, scope: Node | None) -> int:
        """Where a later write surely replaces the variable's value.

        An assignment counts, as do ``(( v = 3 ))``, ``printf -v v``,
        ``read v``, ``mapfile v`` and ``unset v``. Only a write that
        always runs after the capture, in the same shell, counts: one in
        a branch, a loop, after ``||`` or ``&&``, or in a subshell leaves
        the merged value in place, and an append (``v+=...``) keeps it,
        as does a write that expands the variable itself, as in
        ``(( v = v + 1 ))``; ``$output`` or a quoted ``'$v'`` does not.
        """
        writes = [
            other
            for other in self.assigns.get(name, [])
            if not any(child.type == "+=" for child in other.children)
        ]
        writes += self.overwrites.get(name, [])
        ends = [
            other.start_byte
            for other in writes
            if self._replaces(assign, other, name, scope)
        ]
        return min(ends, default=len(self.src) + 1)

    def _replaces(
        self, assign: Node, other: Node, name: str, scope: Node | None
    ) -> bool:
        """Whether a later write always runs and drops the earlier value."""
        if other.start_byte <= assign.end_byte:
            return False
        if enclosing(other, "function_definition") != scope:
            return False
        if not self._always_after(assign, other):
            return False
        value = (
            other.child_by_field_name("value")
            if other.type == "variable_assignment"
            else other
        )
        return value is None or not any(
            within(use, value) for use in self.uses.get(name, [])
        )

    def _always_after(self, assign: Node, other: Node) -> bool:
        """Whether ``other`` runs, in the same shell, whenever ``assign`` does.

        ``other`` must be a statement, through nothing but declarations
        and ``{ }`` groups, in a list of statements that run in turn and
        that also holds the capture.
        """
        node = other
        while node.parent is not None and not within(assign, node.parent):
            node = node.parent
            if node.type not in INLINE:
                return False
        common = node.parent
        return common is not None and common.type in SEQUENCES

    def _use_verdict(
        self, use: Node, depth: int, origins: tuple[Origin, ...] = ()
    ) -> Verdict | None:
        """What the command around one expansion does with the value.

        A value copied to another variable, as in ``copy="$out"`` or
        ``printf -v copy '%s' "$out"``, is followed through that
        variable's uses, keeping the ``origins`` it was copied from.
        """
        node = use
        while node.parent is not None and node.parent.type in WORD_PARTS:
            node = node.parent
        parent = node.parent
        if parent is None:
            return None
        kind = parent.type
        if kind == "herestring_redirect" or misparsed_herestring(
            self.src, parent
        ):
            return self._input_verdict(parent, depth)
        if kind == "heredoc_body" and parent.parent is not None:
            return self._input_verdict(parent.parent, depth)
        command = word_command(parent, node)
        if command is not None:
            return self._argument_verdict(command, node, use, depth, origins)
        if kind == "variable_assignment":
            return self._copy_verdict(parent, node, use, depth, origins)
        return CONTEXT_VERDICTS.get(kind)

    def _copy_verdict(
        self,
        assign: Node,
        value: Node,
        use: Node,
        depth: int,
        origins: tuple[Origin, ...] = (),
    ) -> Verdict | None:
        """A value copied into another variable, as in ``copy="$out"``.

        The copy's success-path uses decide, within the same depth limit
        as captures feeding captures. A value that expands the variable
        itself, as ``out="$out"``, keeps it tracked already.
        """
        name = assign.child_by_field_name("name")
        if (
            depth >= MAX_DEPTH
            or name is None
            or name.type != "variable_name"
            or assign.child_by_field_name("value") != value
        ):
            return None
        target = node_text(self.src, name)
        if self._expands(use, target):
            return None
        return self._variable_verdict(assign, target, depth + 1, origins)

    def _expands(self, use: Node, name: str) -> bool:
        """Whether an expansion reads ``name`` itself."""
        return any(
            node_text(self.src, c) == name
            for c in use.named_children
            if c.type == "variable_name"
        )

    def _stored_verdict(
        self,
        command: Node,
        target: str,
        use: Node,
        depth: int,
        origins: tuple[Origin, ...],
    ) -> Verdict | None:
        """A value ``printf -v TARGET`` stores rather than prints.

        It prints nothing, so only ``TARGET``'s uses decide, within the
        same depth limit as a copy. A pipeline stage runs in a subshell,
        so a ``printf -v`` there sets nothing the rest of the block reads.
        """
        if depth >= MAX_DEPTH or self._expands(use, target):
            return None
        node = command.parent
        while node is not None and node.type == "redirected_statement":
            node = node.parent
        if node is not None and node.type == "pipeline":
            return None
        return self._variable_verdict(command, target, depth + 1, origins)

    def _github_verdict(self, command: Node, name: str) -> Verdict | None:
        """SEM002 when a command writes the value to a ``$GITHUB_*`` file.

        ``true``, ``:`` and ``logger`` print nothing there, whatever
        their stdout is.
        """
        if name in SILENT:
            return None
        target = github_file(self.src, command)
        if target is None:
            return None
        return Verdict("SEM002", f"$value is written to ${target}")

    def _input_verdict(self, redirect: Node, depth: int) -> Verdict | None:
        """A value fed through a here-string or here-document.

        It feeds the descriptor the redirect names, 0 by default, and
        only when no later redirect replaces that descriptor: in
        ``jq . <<< "$v" <clean.json`` jq reads the file.
        """
        fd = input_descriptor(self.src, redirect)
        if stdin_replaced(self.src, later_redirects(redirect), fd):
            return None
        if redirect.type == "heredoc_redirect":
            return self._heredoc_verdict(redirect, depth, fd)
        return self._fed_verdict(redirect.parent, depth, fd)

    def _heredoc_verdict(
        self, redirect: Node, depth: int, fd: int
    ) -> Verdict | None:
        """A value written into a here-document."""
        statement = redirect.parent
        if statement is None:
            return None
        body = statement.children[0]
        if statement.type == "redirected_statement" and body.type in FED_BODIES:
            return self._fed_verdict(statement, depth, fd)
        return self._fed_verdict(first_command(statement), depth, fd)

    def _stdin_reader(self, target: Node | None) -> Node | None:
        """The statement that reads a stdin redirect on ``target``.

        tree-sitter-bash gives a redirect after the last stage of a
        pipeline, as in ``a | jq . <<EOF``, to the whole pipeline; Bash
        gives it to the last stage, which reads it.
        """
        if target is None or target.type != "redirected_statement":
            return target
        body = target.children[0]
        if body.type != "pipeline":
            return target
        return pipeline_stages(body)[-1][0]

    def _fed_verdict(
        self, target: Node | None, depth: int, fd: int = 0
    ) -> Verdict | None:
        """A value fed to a statement's descriptor ``fd``, stdin by default.

        A group, subshell or control flow is followed only for stdin.
        """
        target = self._stdin_reader(target)
        if target is not None and target.type == "redirected_statement":
            body = target.children[0]
            if body.type == "while_statement":
                return self._loop_verdict(body, depth, fd)
            if body.type in READ_GROUPS:
                return None if fd else self._group_fed_verdict(target, depth)
            target = body
        return self._command_fed_verdict(target, depth, fd)

    def _group_fed_verdict(self, statement: Node, depth: int) -> Verdict | None:
        """A value fed to a group or subshell, as in ``{ jq .; } <<< "$v"``.

        The surest verdict among the commands that read its stdin.
        """
        best: Verdict | None = None
        for reader in self._stage_readers(statement):
            if reader.type == "pipeline":
                verdict = self._pipe_verdict(reader, 0, True, depth)
            elif reader.type == "while_statement":
                verdict = self._loop_verdict(reader, depth)
            else:
                verdict = self._command_fed_verdict(reader, depth)
            best = _surer(best, verdict)
        return best

    def _command_fed_verdict(
        self, target: Node | None, depth: int, fd: int = 0
    ) -> Verdict | None:
        """A value fed to a simple command's descriptor ``fd``.

        The command must read that descriptor: ``jq . clean.json`` reads
        the file, and ``read -u 3`` reads descriptor 3, not stdin.
        """
        if target is None or target.type != "command":
            return None
        name, args = command_parts(self.src, target)
        if input_fd(name, args) != fd:
            return None
        written = self._github_verdict(target, name)
        if written is not None:
            return written
        teed = argument_file(self.src, target) if name == "tee" else None
        if teed is not None:
            return Verdict("SEM002", f"$value is written to ${teed}")
        kind = consumer_kind(name, args)
        if kind in ("pass", "picker"):
            return self._onward_verdict(target, kind, name, args, depth)
        return self._read_verdict(kind, name, args)

    def _onward_verdict(
        self, command: Node, kind: str, name: str, args: list[str], depth: int
    ) -> Verdict | None:
        """A value fed to a command that prints it, or a pick of it.

        ``cat`` passes the value on, and a picker is data only when its
        pick is kept: ``head -1 <<< "$v"`` prints a line for the log,
        while one captured, or piped on into a reader of data, is data.
        """
        if kind == "picker" and self._output_capture(command) is not None:
            return self._stream_verdict(kind, name, args, True)
        return self._piped_on(command, depth)

    def _loop_verdict(
        self, loop: Node, depth: int, fd: int = 0
    ) -> Verdict | None:
        """A value fed to a ``while read`` loop, on descriptor ``fd``."""
        kind = self._loop_kind(loop, fd)
        if kind == "pass":
            return self._piped_on(loop, depth)
        if kind == "github":
            return Verdict(
                "SEM002", "$value is written to $GITHUB_* by a while-read loop"
            )
        if kind != "extractor":
            return None
        return Verdict("SEM002", "$value is read by a while-read loop")

    def _read_verdict(
        self, kind: str | None, name: str, args: list[str]
    ) -> Verdict | None:
        """A value read by a command, as its input or an argument."""
        if kind is not None:
            return self._stream_verdict(kind, name, args, True)
        if is_logger(name):
            return None
        return Verdict("SEM003", f"$value is passed to {name}")

    def _piped_on(
        self, command: Node, depth: int, variable: bool = True
    ) -> Verdict | None:
        """What the script does with a value a command prints.

        The rest of a pipeline reads it, or a ``$( )`` keeps it, as in
        ``jq . <<< "$(printf '%s' "$v")"``, the last stage of a pipeline
        included. A command in a group, a subshell or control flow
        prints into that statement's stdout, so a group that is a
        pipeline stage, as in ``{ printf '%s' "$v"; } | jq .``, feeds
        the rest of the pipeline. Nothing does, when the command's own
        redirects, or those of what holds it, send its stdout elsewhere.
        """
        if self._stage_sink(command) is not None:
            return None
        parent = command.parent
        while parent is not None and (
            parent.type in OUTPUT_GROUPS
            or (
                parent.type == "redirected_statement"
                and parent.children[0] == command
            )
        ):
            command, parent = parent, parent.parent
        stages: list[Node] = []
        if parent is not None and parent.type == "pipeline":
            stages = [stage for stage, _op in pipeline_stages(parent)]
        if parent is None or not stages or stages[-1] == command:
            capture = self._output_capture(command)
            if capture is None:
                return None
            return self._capture_verdict(capture, depth + 1)
        if command not in stages:
            return None
        return self._pipe_verdict(
            parent, stages.index(command) + 1, variable, depth
        )

    def _argument_verdict(
        self,
        command: Node,
        word: Node,
        use: Node,
        depth: int,
        origins: tuple[Origin, ...] = (),
    ) -> Verdict | None:
        """A value given to a command as an argument.

        ``printf -v`` prints nothing, so where its stdout goes, even to
        a ``$GITHUB_*`` file, does not matter: its target's uses decide.
        """
        if word.type == "command_name":
            return None
        name, args = command_parts(self.src, command)
        stored = written_names(name, args) if name == "printf" else []
        if stored:
            return self._stored_verdict(command, stored[0], use, depth, origins)
        written = self._github_verdict(command, name)
        if written is not None:
            return written
        if name in ("test", "["):
            return Verdict("SEM002", COMPARED)
        if name in FEEDERS:
            return self._piped_on(command, depth)
        kind = consumer_kind(name, args)
        reads = kind in ("parser", "extractor", "exists")
        return self._read_verdict(kind if reads else None, name, args)


def analyse(text: str, line_at: Callable[[int], int]) -> list[Hit]:
    """Every merge used as data in one block of shell."""
    return BlockAnalysis(text, line_at).run()


__all__ = ["BlockAnalysis", "Hit", "Verdict", "analyse"]
