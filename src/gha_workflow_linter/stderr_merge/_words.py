# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Command words and redirects, read from the tree-sitter parse."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from gha_workflow_linter.shell._discovery import SPLIT_STRING, env_split
from gha_workflow_linter.shell._tree import (
    descriptor_word,
    node_text,
    redirect_words,
)

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
# Paths that reopen one of the shell's own descriptors.
DEVICE_ALIASES = {"/dev/stdin": 0, "/dev/stdout": 1, "/dev/stderr": 2}
FD_PATH = re.compile(r"/(?:dev|proc/self)/fd/([0-9]+)")
# Bytes that may come before a redirect's descriptor.
BLANKS = frozenset(bytes([c]) for c in b" \t\n;(")
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


def argument_nodes(command: Node) -> list[Node]:
    """A command's argument words, as bash reads them.

    Words tree-sitter hangs on a redirect after its target, as ``-c``
    in ``python3 2>/dev/null -c ...``, are the command's; a number it
    reads as the last argument, as ``0`` in ``python3 0< f``, is the
    redirect's descriptor.
    """
    words = list(command.children_by_field_name("argument"))
    if words and descriptor_word(command, words[-1]):
        words.pop()
    return words + [w for w in redirect_words(command) if w.type != "comment"]


def command_parts(src: bytes, command: Node) -> tuple[str, list[str]]:
    """The command a step runs, past any wrapper, and its arguments."""
    args = [unquoted(src, child) for child in argument_nodes(command)]
    return unwrap(command_name(src, command), args)


def _cluster_takes_next(option: str, takes: frozenset[str]) -> bool:
    """Whether a short-option cluster ends in an option taking the next word.

    In ``sudo -nu root`` the ``-u`` ends the cluster and takes ``root``;
    in ``sudo -uroot`` its value is attached.
    """
    for index, letter in enumerate(option[1:], start=1):
        if f"-{letter}" in takes:
            return index == len(option) - 1
    return False


def _drop_options(wrapper: str, args: list[str]) -> list[str]:
    """The arguments after a wrapper's own options and assignments."""
    takes = WRAPPER_OPERANDS.get(wrapper, frozenset())
    rest = list(args)
    while rest and (rest[0].startswith("-") or "=" in rest[0]):
        option = rest.pop(0)
        if option == "--":
            break
        if option.startswith("--") or not option.startswith("-"):
            if option in takes and rest:
                rest.pop(0)
        elif _cluster_takes_next(option, takes) and rest:
            rest.pop(0)
    return rest


def _looks_up(args: list[str]) -> bool:
    """Whether ``command``'s own options ask it to describe, not run.

    ``command -v jq`` and ``command -V jq`` print what ``jq`` is; a
    ``-v`` after the command it runs, as in ``command grep -v x``, is
    that command's.
    """
    for arg in args:
        if arg == "--" or not arg.startswith("-") or arg == "-":
            return False
        if "v" in arg[1:] or "V" in arg[1:]:
            return True
    return False


def _split_env(args: list[str]) -> list[str]:
    """``env``'s words with each ``-S``/``--split-string`` operand split.

    The operand holds the command env runs, as in ``env -S 'jq .'``,
    and GNU env splits it into words of its own, read on as env's. An
    operand env cannot split is left whole.
    """
    takes = WRAPPER_OPERANDS["env"]
    index = 0
    for _ in range(64):
        if index >= len(args):
            break
        word = args[index]
        if word == "--" or not word.startswith("-"):
            break
        split = SPLIT_STRING.match(word)
        if split is not None:
            attached = split.end() < len(word)
            after = index + 1 if attached else index + 2
            operand = (
                word[split.end() :]
                if attached
                else "".join(args[index + 1 : after])
            )
            parts = env_split(operand)
            if parts is None:
                break
            args = [*args[:index], *parts, *args[after:]]
        elif word.startswith("--"):
            index += 2 if word in takes else 1
        else:
            index += 2 if _cluster_takes_next(word, takes) else 1
    return args


def unwrap(name: str, args: list[str]) -> tuple[str, list[str]]:
    """See through ``timeout``, ``sudo``, ``env`` and the like.

    ``env -S`` splits its operand into the command it runs.
    """
    name, args, _wrappers = unwrap_chain(name, args)
    return name, args


def unwrap_chain(
    name: str, args: list[str]
) -> tuple[str, list[str], tuple[str, ...]]:
    """As ``unwrap``, with the wrappers seen through, outermost first."""
    wrappers: list[str] = []
    for _ in range(4):
        if name not in WRAPPERS or (name == "command" and _looks_up(args)):
            break
        if name == "env":
            args = _split_env(args)
        rest = _drop_options(name, args)
        if name == "timeout" and rest:
            rest = rest[1:]
        if not rest:
            break
        wrappers.append(name)
        name = rest[0].strip("${}\"'").rsplit("/", 1)[-1].lower()
        args = rest[1:]
    return name, args, tuple(wrappers)


def in_current_shell(src: bytes, command: Node) -> bool:
    """Whether a built-in a command runs can set the shell's variables.

    ``command`` runs the built-in in the shell; ``env``, ``sudo``,
    ``timeout`` and the other wrappers start a program, so in
    ``env printf -v out x`` no ``printf -v`` of the shell runs.
    """
    args = [unquoted(src, child) for child in argument_nodes(command)]
    _name, _args, wrappers = unwrap_chain(command_name(src, command), args)
    return all(wrapper == "command" for wrapper in wrappers)


def _redirect_parts(src: bytes, redirect: Node) -> tuple[int | None, str, str]:
    """A file redirect's descriptor, operator and destination.

    Only the first ``destination`` is the target: tree-sitter also
    hangs the command's later words on the redirect, as ``extra`` in
    ``printf x >> "$GITHUB_OUTPUT" extra``.
    """
    fd: int | None = None
    op = ""
    for child in redirect.children:
        if child.type == "file_descriptor":
            fd = int(node_text(src, child))
        elif not child.is_named and not op:
            op = child.type
    if fd is None:
        fd = _adjacent_descriptor(src, redirect)
    target = redirect.child_by_field_name("destination")
    if target is None:
        return fd, op, ""
    if target.type != "raw_string":
        return fd, op, unquoted(src, target)
    # Single quotes keep ``$NAME`` literal: no expansion to match. A
    # literal path such as '/dev/stdout', or a descriptor number or
    # ``-`` as in ``2>&'1'``, still names a descriptor.
    dest = node_text(src, target)
    inner = dest[1:-1]
    if inner.isdigit() or inner == "-" or descriptor_alias(inner) is not None:
        return fd, op, inner
    return fd, op, dest


def _adjacent_descriptor(src: bytes, redirect: Node) -> int | None:
    """The descriptor written just before a redirect tree-sitter split off.

    In ``exec 0>&-`` or ``read v 0>/dev/null`` tree-sitter reads the
    ``0`` as a word of the command; Bash reads a number that touches
    the operator, after a blank or an operator, as its descriptor.
    """
    end = start = redirect.start_byte
    while start > 0 and src[start - 1 : start].isdigit():
        start -= 1
    if start == end or (start > 0 and src[start - 1 : start] not in BLANKS):
        return None
    return int(src[start:end])


def descriptor_alias(dest: str) -> int | None:
    """The descriptor a path such as ``/dev/stdout`` reopens, if any.

    Writing to ``/dev/stdout``, ``/dev/fd/1`` or ``/proc/self/fd/1``
    reaches wherever descriptor 1 goes at that point, as ``>&1`` does.
    """
    if dest in DEVICE_ALIASES:
        return DEVICE_ALIASES[dest]
    found = FD_PATH.fullmatch(dest)
    return None if found is None else int(found.group(1))


def _apply(src: bytes, redirect: Node, fds: dict[int, str]) -> None:
    """Move the descriptors one redirect moves.

    A descriptor sent to a file holds ``file:`` and the file's name; one
    sent to a descriptor alias such as ``/dev/stdout`` takes that
    descriptor's current destination.
    """
    fd, op, dest = _redirect_parts(src, redirect)
    both = op in ("&>", "&>>") or (
        op == ">&" and fd is None and not dest.isdigit() and dest != "-"
    )
    alias = descriptor_alias(dest)
    opened = f"file:{dest}" if alias is None else fds.get(alias, "fd")
    if both:
        fds[1] = fds[2] = opened
    elif op in (">&", "<&"):
        target = fd if fd is not None else (1 if op == ">&" else 0)
        fds[target] = fds.get(int(dest), "fd") if dest.isdigit() else "closed"
    elif op in (">", ">>", ">|"):
        fds[fd if fd is not None else 1] = opened


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


def stdin_replaced(src: bytes, redirects: list[Node], target: int = 0) -> bool:
    """Whether ``redirects`` give a command a stdin other than the pipe.

    A here-string, a here-document and a ``<`` or ``<&`` redirect all
    replace what a pipe would feed in, except ``<&0``, which keeps it;
    ``<0`` opens a file named ``0``. ``target`` names another input
    descriptor to ask about, as ``3<<< "$v"`` feeds descriptor 3.
    """
    for redirect in redirects:
        if (
            redirect.type in ("herestring_redirect", "heredoc_redirect")
            and input_descriptor(src, redirect) == target
        ):
            return True
    for redirect in file_redirects(redirects):
        fd, op, dest = _redirect_parts(src, redirect)
        if (
            op.startswith("<")
            and (fd or 0) == target
            and not (op == "<&" and dest == str(target))
            and descriptor_alias(dest) != target
        ):
            return True
    return False


def redirect_may_fail(src: bytes, redirects: list[Node]) -> bool:
    """Whether a redirect among ``redirects`` may fail, or starve a read.

    Bash skips a command whose redirect fails. ``< file`` fails when
    the file is missing, ``> "$dest"`` when its directory is missing or
    not writable, and ``<&3`` or ``>&3`` when descriptor 3 is closed.
    ``<&-``, ``0>&-`` and ``0>/dev/null`` leave the command no stdin
    to read. Otherwise ``<&0``, ``>&1`` and the other standard
    descriptors, ``>&-``, ``/dev/null``, a here-string and a
    here-document always succeed.
    """
    if stdin_unreadable(src, redirects):
        return True
    for redirect in file_redirects(redirects):
        _fd, op, dest = _redirect_parts(src, redirect)
        if op.startswith("<"):
            if not (op == "<&" and dest == "0"):
                return True
        elif op == ">&" and dest in ("0", "1", "2", "-"):
            continue
        elif op != ">&-" and dest != "/dev/null":
            return True
    return False


def stdin_unreadable(src: bytes, redirects: list[Node]) -> bool:
    """Whether ``redirects`` leave descriptor 0 closed or write-only.

    ``0>&-`` and ``<&-`` close it, and ``0>file``, ``0>&1`` or
    ``0>/dev/null`` open it for writing alone: a ``read`` of it fails
    and sets nothing.
    """
    for redirect in file_redirects(redirects):
        fd, op, _dest = _redirect_parts(src, redirect)
        if op.startswith("<"):
            if (fd or 0) == 0 and op == "<&-":
                return True
        elif fd == 0:
            return True
    return False


def own_redirects(command: Node) -> list[Node]:
    """The redirects on a simple command, and on its statement."""
    found = [c for c in command.children if "redirect" in c.type]
    parent = command.parent
    if (
        parent is not None
        and parent.type == "redirected_statement"
        and parent.children[0] == command
    ):
        found += [c for c in parent.children[1:] if "redirect" in c.type]
    return found


def sure_to_run(
    src: bytes, command: Node, reads: bool, execs: list[Node]
) -> bool:
    """Whether a built-in surely runs in this shell and sets its names.

    A wrapper such as ``env`` or ``sudo`` runs a program in another
    process, and a redirect may fail. A built-in that ``reads`` stdin,
    as ``read`` and ``mapfile`` do, fails when one of the ``exec``
    statements in ``execs`` closed it or left it write-only.
    """
    if not in_current_shell(src, command):
        return False
    if redirect_may_fail(src, own_redirects(command)):
        return False
    return not reads or not any(
        stdin_unreadable(
            src, [c for c in e.children[1:] if "redirect" in c.type]
        )
        for e in execs
    )


def input_descriptor(src: bytes, redirect: Node) -> int:
    """The descriptor an input redirect feeds: its number, else 0."""
    for child in redirect.children:
        if child.type == "file_descriptor":
            return int(node_text(src, child))
    return 0


def later_redirects(redirect: Node) -> list[Node]:
    """The redirects Bash applies after ``redirect``, to the same statement.

    Those after it on its command or statement, those on a statement
    the command is the body of, and, for a here-document, those written
    after its marker.
    """
    found: list[Node] = []
    if redirect.type == "heredoc_redirect":
        found += [
            c for c in redirect.named_children if c.type == "file_redirect"
        ]
    parent = redirect.parent
    if parent is None:
        return found
    after = parent.children[parent.children.index(redirect) + 1 :]
    found += [c for c in after if "redirect" in c.type]
    outer = parent.parent
    if (
        parent.type == "command"
        and outer is not None
        and outer.type == "redirected_statement"
        and outer.children[0] == parent
    ):
        found += [c for c in outer.children[1:] if "redirect" in c.type]
    return found


def misparsed_herestring(src: bytes, node: Node) -> bool:
    """Whether a ``<`` redirect is the tail of a here-string.

    tree-sitter-bash reads ``{ jq .; } <<< "$v"`` and ``(jq .) <<< "$v"``
    as an error node holding ``<<`` and a ``<`` redirect from ``"$v"``,
    and ``read -u 3 l 3<<< "$v"`` as a ``3<`` redirect holding that
    error node.
    """
    if node.type != "file_redirect":
        return False
    previous = node.prev_sibling
    if previous is not None and previous.type == "ERROR":
        return node_text(src, previous) == "<<"
    return any(
        child.type == "ERROR" and node_text(src, child) == "<<"
        for child in node.children
    )


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
    for word in argument_nodes(command):
        if word.type != "raw_string":
            found = runner_file(unquoted(src, word))
            if found is not None:
                return found
    return None


def word_command(parent: Node, word: Node) -> Node | None:
    """The simple command ``word`` is an argument of, if any.

    tree-sitter hangs words after a redirect's target on the
    redirect, as ``"$out"`` in ``cmd 2>/dev/null "$out"``; they
    belong to the command the redirect follows, or to the last
    stage of a pipeline it follows.
    """
    if parent.type == "command":
        return parent
    statement = parent.parent
    if (
        parent.type != "file_redirect"
        or statement is None
        or statement.type != "redirected_statement"
    ):
        return None
    body = statement.children[0]
    if body.type == "pipeline":
        body = [c for c in body.children if c.is_named][-1]
    if body.type == "command" and word in redirect_words(body):
        return body
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
