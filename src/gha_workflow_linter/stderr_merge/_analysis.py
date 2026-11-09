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
    RULES,
    anchored,
    by_design,
    consumer_kind,
    is_logger,
    rank,
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
    merges,
    output_redirects,
    pipeline_stages,
    stdin_replaced,
    stdout_destination,
    within,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from tree_sitter import Node

# How deep a capture may feed another capture before the walk stops.
MAX_DEPTH = 4
EXPANSIONS = frozenset({"simple_expansion", "expansion"})
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
FEEDERS = frozenset({"echo", "printf", "cat"})
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

    def _loop_kind(self, loop: Node) -> str | None:
        """A ``while read`` loop extracts, unless its body only logs.

        A body writing to a ``$GITHUB_*`` file exports what it reads,
        whatever command writes it.
        """
        condition = first_command(loop)
        if condition is None:
            return None
        name, _args = command_parts(self.src, condition)
        if name != "read":
            return None
        body = loop.child_by_field_name("body")
        commands = [] if body is None else self._commands_in(body)
        if any(github_file(self.src, c) is not None for c in commands):
            return "github"
        names = [command_parts(self.src, c)[0] for c in commands]
        return None if all(is_logger(n) for n in names) else "extractor"

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
        """What the stages from ``start`` on do with the merged stream."""
        capture = self._output_capture(pipeline)
        kept = capture is not None or self._tested(pipeline)
        stages = pipeline_stages(pipeline)
        for index, (stage, _operator) in enumerate(stages):
            if index < start:
                continue
            if self._own_stdin(pipeline, stage, index == len(stages) - 1):
                return None
            kind, name, args = self._stage_kind(stage)
            sink = self._stage_sink(stage)
            if sink == "github" and kind in ("pass", "picker", "extractor"):
                kind = "github"
            elif kind == "pass" or (kind == "picker" and not kept):
                if sink is not None:
                    return None
                continue
            return self._stream_verdict(kind, name, args, variable)
        if capture is not None:
            return self._capture_verdict(capture, depth + 1)
        return None

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
        if kind == "exists":
            return Verdict("SEM004", f"{reader} is tested with {name} -q")
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
        self, assign: Node, name: str, depth: int
    ) -> Verdict | None:
        """The surest success-path use of a variable holding a merge."""
        scope = enclosing(assign, "function_definition")
        shell = self._shell_of(assign)
        status = self._saved_status(assign)
        end = self._reassigned(assign, name, scope)
        best: Verdict | None = None
        for use in self.uses.get(name, []):
            if use.start_byte < assign.end_byte or use.start_byte >= end:
                continue
            if enclosing(use, "function_definition") != scope:
                continue
            if shell is not None and not within(use, shell):
                continue
            if failure_path(self.src, use, assign, status):
                continue
            verdict = self._use_verdict(use, depth)
            if verdict is not None:
                line = self.line_at(use.start_byte)
                detail = verdict.detail.replace("$value", f"${name}")
                verdict = Verdict(verdict.rule, f"{detail} (line {line})", name)
            best = _surer(best, verdict)
        return best

    def _saved_status(self, assign: Node) -> SavedStatus | None:
        """The variable the capture's status is saved in, and until when.

        Any later write to that variable ends what it says about the
        capture: ``s=$?; s=1`` leaves ``$s`` unrelated to it.
        """
        saved = status_after(self.src, assign)
        if saved is None:
            return None
        name = saved.child_by_field_name("name")
        if name is None:
            return None
        key = node_text(self.src, name)
        later = [
            other.start_byte
            for other in self.assigns.get(key, [])
            if other.start_byte >= saved.end_byte
        ]
        return SavedStatus(key, min(later, default=len(self.src) + 1))

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
        """Where a later assignment surely replaces the variable's value.

        Only an assignment that always runs after the capture, in the
        same shell, counts: one in a branch, a loop, after ``||`` or
        ``&&``, or in a subshell leaves the merged value in place, and
        an append (``v+=...``) keeps it.
        """
        for other in self.assigns.get(name, []):
            if other.start_byte <= assign.end_byte:
                continue
            if any(child.type == "+=" for child in other.children):
                continue
            if enclosing(other, "function_definition") != scope:
                continue
            if not self._always_after(assign, other):
                continue
            value = other.child_by_field_name("value")
            text = "" if value is None else node_text(self.src, value)
            if f"${name}" not in text and f"${{{name}" not in text:
                return other.start_byte
        return len(self.src) + 1

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

    def _use_verdict(self, use: Node, depth: int) -> Verdict | None:
        """What the command around one expansion does with the value."""
        node = use
        while node.parent is not None and node.parent.type in WORD_PARTS:
            node = node.parent
        parent = node.parent
        if parent is None:
            return None
        kind = parent.type
        if kind == "herestring_redirect":
            return self._fed_verdict(parent.parent, depth)
        if kind == "heredoc_body":
            return self._heredoc_verdict(parent.parent, depth)
        if kind == "command":
            return self._argument_verdict(parent, node, depth)
        return CONTEXT_VERDICTS.get(kind)

    def _github_verdict(self, command: Node) -> Verdict | None:
        """SEM002 when a command writes the value to a ``$GITHUB_*`` file."""
        target = github_file(self.src, command)
        if target is None:
            return None
        return Verdict("SEM002", f"$value is written to ${target}")

    def _heredoc_verdict(
        self, redirect: Node | None, depth: int
    ) -> Verdict | None:
        """A value written into a here-document."""
        statement = None if redirect is None else redirect.parent
        if statement is None:
            return None
        return self._fed_verdict(first_command(statement), depth)

    def _fed_verdict(self, target: Node | None, depth: int) -> Verdict | None:
        """A value fed to a command's stdin."""
        if target is not None and target.type == "redirected_statement":
            body = target.children[0]
            if body.type == "while_statement":
                return self._loop_verdict(body)
            target = body
        if target is None or target.type != "command":
            return None
        written = self._github_verdict(target)
        if written is not None:
            return written
        name, args = command_parts(self.src, target)
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

    def _loop_verdict(self, loop: Node) -> Verdict | None:
        """A value fed to a ``while read`` loop."""
        kind = self._loop_kind(loop)
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

    def _piped_on(self, command: Node, depth: int) -> Verdict | None:
        """What the script does with a value a command prints.

        The rest of a pipeline reads it, or a ``$( )`` keeps it, as in
        ``jq . <<< "$(printf '%s' "$v")"``, the last stage of a pipeline
        included. Nothing does, when the command's own redirects send
        its stdout elsewhere.
        """
        parent = command.parent
        if parent is not None and parent.type == "redirected_statement":
            command, parent = parent, parent.parent
        if self._stage_sink(command) is not None:
            return None
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
            parent, stages.index(command) + 1, True, depth
        )

    def _argument_verdict(
        self, command: Node, word: Node, depth: int
    ) -> Verdict | None:
        """A value given to a command as an argument."""
        if word.type == "command_name":
            return None
        written = self._github_verdict(command)
        if written is not None:
            return written
        name, args = command_parts(self.src, command)
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
