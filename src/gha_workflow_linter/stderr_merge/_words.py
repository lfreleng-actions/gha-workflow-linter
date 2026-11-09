# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Command words and redirects, read from the tree-sitter parse."""

from __future__ import annotations

from typing import TYPE_CHECKING

from gha_workflow_linter.shell._tree import node_text

from ._rules import WRAPPERS, runner_file

if TYPE_CHECKING:
    from tree_sitter import Node

# Each wrapper's options that take an operand of their own. The same
# letter differs between wrappers: ``nice -n 5`` takes one, while
# ``sudo -n`` is a flag.
WRAPPER_OPERANDS = {
    "timeout": frozenset({"-k", "-s", "--kill-after", "--signal"}),
    "sudo": frozenset(
        {
            "-u",
            "-g",
            "-C",
            "-p",
            "-r",
            "-t",
            "-U",
            "-D",
            "-T",
            "-R",
            "--user",
            "--group",
            "--close-from",
            "--prompt",
            "--role",
            "--type",
            "--other-user",
            "--chdir",
            "--command-timeout",
            "--chroot",
            "--host",
        }
    ),
    "env": frozenset(
        {"-u", "-C", "-S", "--unset", "--chdir", "--split-string"}
    ),
    "nice": frozenset({"-n", "--adjustment"}),
    "stdbuf": frozenset({"-i", "-o", "-e", "--input", "--output", "--error"}),
}
# Control flow whose bodies, and conditions, all write to the stdout of
# the statement: a redirect on it reaches every command in it.
CONTROL = frozenset(
    {
        "if_statement",
        "elif_clause",
        "else_clause",
        "case_statement",
        "case_item",
        "for_statement",
        "c_style_for_statement",
        "while_statement",
        "do_group",
    }
)
# Statements that pass on the stdout of the statements they hold.
OUTPUT_GROUPS = CONTROL | {
    "compound_statement",
    "subshell",
    "list",
    "negated_command",
}
# Statements whose children run one after another.
BODIES = frozenset(
    {
        "program",
        "compound_statement",
        "do_group",
        "if_statement",
        "elif_clause",
        "else_clause",
        "case_item",
        "subshell",
    }
)


def unquoted(src: bytes, node: Node) -> str:
    """A word's text with its quotes taken off."""
    text = node_text(src, node)
    if node.type in ("string", "raw_string") and len(text) >= 2:
        return text[1:-1]
    if node.type == "concatenation":
        return text.replace('"', "").replace("'", "")
    return text


def command_name(src: bytes, command: Node) -> str:
    """A command's name: its last path part, without quotes or ``$``."""
    name = command.child_by_field_name("name")
    if name is None:
        return ""
    text = unquoted(src, name.named_children[0]) if name.named_children else ""
    text = text.strip("${}\"'").rsplit("/", 1)[-1]
    return text.lower()


def command_parts(src: bytes, command: Node) -> tuple[str, list[str]]:
    """The command a step runs, past any wrapper, and its arguments."""
    args = [
        unquoted(src, child)
        for child in command.children_by_field_name("argument")
    ]
    return unwrap(command_name(src, command), args)


def _drop_options(wrapper: str, args: list[str]) -> list[str]:
    """The arguments after a wrapper's own options and assignments."""
    takes = WRAPPER_OPERANDS.get(wrapper, frozenset())
    rest = list(args)
    while rest and (rest[0].startswith("-") or "=" in rest[0]):
        option = rest.pop(0)
        if option == "--":
            break
        if option in takes and rest:
            rest.pop(0)
    return rest


def unwrap(name: str, args: list[str]) -> tuple[str, list[str]]:
    """See through ``timeout``, ``sudo``, ``env`` and the like."""
    for _ in range(4):
        if name not in WRAPPERS or (name == "command" and "-v" in args):
            break
        rest = _drop_options(name, args)
        if name == "timeout" and rest:
            rest = rest[1:]
        if not rest:
            break
        name = rest[0].strip("${}\"'").rsplit("/", 1)[-1].lower()
        args = rest[1:]
    return name, args


def _redirect_parts(src: bytes, redirect: Node) -> tuple[int | None, str, str]:
    """A file redirect's descriptor, operator and destination."""
    fd: int | None = None
    op = ""
    dest = ""
    for child in redirect.children:
        if child.type == "file_descriptor":
            fd = int(node_text(src, child))
        elif not child.is_named:
            op = child.type
        elif child.type == "raw_string":
            # Single quotes keep ``$NAME`` literal: no expansion to match.
            dest = node_text(src, child)
        else:
            dest = unquoted(src, child)
    return fd, op, dest


def _apply(src: bytes, redirect: Node, fds: dict[int, str]) -> None:
    """Move the descriptors one redirect moves.

    A descriptor sent to a file holds ``file:`` and the file's name.
    """
    fd, op, dest = _redirect_parts(src, redirect)
    both = op in ("&>", "&>>") or (
        op == ">&" and fd is None and not dest.isdigit() and dest != "-"
    )
    if both:
        fds[1] = fds[2] = f"file:{dest}"
    elif op in (">&", "<&"):
        target = fd if fd is not None else (1 if op == ">&" else 0)
        fds[target] = fds.get(int(dest), "fd") if dest.isdigit() else "closed"
    elif op in (">", ">>", ">|"):
        fds[fd if fd is not None else 1] = f"file:{dest}"


def apply_redirects(
    src: bytes, redirects: list[Node], fds: dict[int, str]
) -> dict[int, str]:
    """The descriptors after ``redirects``, from ``fds``, as a new map."""
    moved = dict(fds)
    for redirect in file_redirects(redirects):
        _apply(src, redirect, moved)
    return moved


def file_redirects(redirects: list[Node]) -> list[Node]:
    """The file redirects among ``redirects``, in order.

    A here-document carries the redirects written after its marker,
    as in ``cat <<EOF >>"$GITHUB_OUTPUT"``.
    """
    found: list[Node] = []
    for redirect in redirects:
        if redirect.type == "file_redirect":
            found.append(redirect)
        elif redirect.type in ("heredoc_redirect", "herestring_redirect"):
            found += [
                c for c in redirect.named_children if c.type == "file_redirect"
            ]
    return found


def stdout_destination(src: bytes, redirects: list[Node]) -> str:
    """Where stdout goes after ``redirects``.

    ``out`` when it still goes where it came from, ``err`` for stderr's
    destination, ``file:<name>`` for a file, ``fd`` or ``closed``.
    """
    return apply_redirects(src, redirects, {1: "out", 2: "err"})[1]


def stdin_replaced(src: bytes, redirects: list[Node]) -> bool:
    """Whether ``redirects`` give a command a stdin other than the pipe.

    A here-string, a here-document and a ``<`` or ``<&`` redirect all
    replace what a pipe would feed in.
    """
    for redirect in redirects:
        if redirect.type in ("herestring_redirect", "heredoc_redirect"):
            target = next(
                (
                    node_text(src, c)
                    for c in redirect.children
                    if c.type == "file_descriptor"
                ),
                "0",
            )
            if target == "0":
                return True
    for redirect in file_redirects(redirects):
        fd, op, dest = _redirect_parts(src, redirect)
        if op.startswith("<") and fd in (None, 0) and dest != "0":
            return True
    return False


def merges(
    src: bytes, redirects: list[Node], inherited: bool, piped: bool = False
) -> bool:
    """Whether stdout and stderr both reach stdout's destination.

    ``inherited`` says stderr already goes there, after ``exec 2>&1``.
    ``piped`` says the stage ends in ``|&``, which Bash applies as a
    ``2>&1`` after the explicit redirects. ``2>&1 >/dev/null`` keeps
    stderr alone, and ``>/dev/null 2>&1`` and ``>/dev/null |&`` discard
    both: none is a merge.
    """
    start = {1: "out", 2: "out" if inherited else "err"}
    fds = apply_redirects(src, redirects, start)
    if piped:
        fds[2] = fds[1]
    return fds[1] == "out" and fds[2] == "out"


def first_command(node: Node) -> Node | None:
    """The first simple command in a statement, depth first."""
    if node.type == "command":
        return node
    for child in node.named_children:
        found = first_command(child)
        if found is not None:
            return found
    return None


def enclosing(node: Node, kind: str) -> Node | None:
    """The nearest ancestor of a type."""
    parent = node.parent
    while parent is not None and parent.type != kind:
        parent = parent.parent
    return parent


def within(node: Node, outer: Node) -> bool:
    """Whether ``node`` lies inside ``outer``, or is it."""
    return (
        outer.start_byte <= node.start_byte and node.end_byte <= outer.end_byte
    )


def statement_of(node: Node) -> Node:
    """The statement holding ``node`` in a list of statements."""
    while node.parent is not None and node.parent.type not in BODIES:
        node = node.parent
    return node


def output_redirects(node: Node) -> list[Node]:
    """The redirects that decide where a statement's stdout goes.

    They come from the statement and from what encloses it, outermost
    first, as Bash applies them: a redirect on a group, on control flow
    or on a pipeline reaches the commands writing its stdout, as in
    ``if c; then echo "$v"; fi >> "$GITHUB_OUTPUT"``.
    """
    redirects = list(node.children_by_field_name("redirect"))
    while node.parent is not None:
        parent = node.parent
        if parent.type == "redirected_statement":
            if parent.children[0] != node:
                break
            redirects = list(parent.children[1:]) + redirects
        elif parent.type == "pipeline":
            if pipeline_stages(parent)[-1][0] != node:
                break
        elif parent.type not in OUTPUT_GROUPS:
            break
        node = parent
    return redirects


def destination_file(dest: str) -> str | None:
    """The ``$GITHUB_*`` file a descriptor's destination names, if any."""
    return runner_file(dest[5:]) if dest.startswith("file:") else None


def github_file(src: bytes, command: Node) -> str | None:
    """The ``$GITHUB_*`` file a command's stdout is written to, if any."""
    return destination_file(stdout_destination(src, output_redirects(command)))


def argument_file(src: bytes, command: Node) -> str | None:
    """The first ``$GITHUB_*`` file a command names as an argument.

    A single-quoted ``'$GITHUB_OUTPUT'`` names a file of that name.
    """
    for word in command.children_by_field_name("argument"):
        if word.type != "raw_string":
            found = runner_file(unquoted(src, word))
            if found is not None:
                return found
    return None


def pipeline_stages(pipeline: Node) -> list[tuple[Node, str]]:
    """Each stage of a pipeline with the operator after it."""
    stages: list[tuple[Node, str]] = []
    for child in pipeline.children:
        if child.is_named and child.type != "comment":
            stages.append((child, ""))
        elif stages and child.type in ("|", "|&"):
            stages[-1] = (stages[-1][0], child.type)
    return stages
