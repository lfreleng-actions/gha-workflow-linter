# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""The trusted-interpreter model: values the caller's environment cannot steer.

A value is trusted when it is one of:

- ``${{ steps.<id>.outputs.python-path }}`` of an ``actions/setup-python``
  step earlier in the same job (``uv-path`` of ``astral-sh/setup-uv``
  for the uv program);
- ``${{ steps.<id>.outputs.<name> }}`` of a ``run:`` step earlier in
  the same job that writes ``<name>`` to ``$GITHUB_OUTPUT`` once, with
  its standard output, from a trusted shell variable;
- a shell variable the step's YAML ``env:`` binds to one of those, or
  that one top-level assignment sets from one of them, or from
  ``env -i … uv python find`` or ``env -i … uv python install`` with
  ``--managed-python``, or ``--system`` and ``--no-config``;
- a literal absolute path that ``is_outside_path()`` accepts.

A producer step with ``if:`` or ``continue-on-error:`` gives none: its
output may be empty. A value holding a control character is no path.

The model is lexical. A variable counts only when it is assigned at
most once anywhere in the block, at top level, before the word that
reads it; a block that runs ``eval``, ``source`` or ``.``, or sets a
``trap`` action, trusts no variable. ``"${arr[@]}"`` expands when one
top-level assignment sets ``arr`` to literal or trusted words.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
import os
import re
from typing import TYPE_CHECKING

from gha_workflow_linter.shell._tree import node_text as _node_text

from ._invocation import (
    TRUSTED_PYTHON,
    TRUSTED_UV,
    is_trusted_python,
    parse_env,
)
from ._uv import is_truthy, parse_uv, passed_selectors
from ._words import command_words, literal_of

if TYPE_CHECKING:
    from tree_sitter import Node


IDENTIFIER = re.compile(r"[A-Za-z_]\w*")
# Builtins that assign to the names they are given.
ASSIGNING = frozenset(
    {"read", "mapfile", "readarray", "getopts", "printf", "let", "unset"}
)
# Variables a builtin assigns when given no name: read and select set
# REPLY, mapfile and readarray MAPFILE.
IMPLICIT = {"read": "REPLY", "mapfile": "MAPFILE", "readarray": "MAPFILE"}
# What assigning_targets gives for a target the scan cannot read.
UNREAD_TARGET = ""
# A printf conversion that stores the count written so far in a variable.
PRINTF_N = re.compile(r"%[-+ #0'\d.*]*n")
# Characters that end an output record or cannot appear in one path.
CONTROL = re.compile(r"[\x00-\x1f\x7f]")
# Builtins that run text the scan does not read.
EVALUATING = frozenset({"eval", "source", "."})
# trap arguments that set no action: list, print or reset.
TRAP_NO_ACTION = frozenset({"-l", "-p", "-lp", "-pl", "-"})
# Declaration builtins: a command, not a declaration_command, when a
# wrapper or quoting hides them from the parser.
DECLARING = frozenset({"declare", "local", "typeset", "export", "readonly"})
# Words that run the builtin after them: builtin eval, command -p eval.
BUILTIN_WRAPPERS = frozenset({"builtin", "command"})
# Characters an unquoted expansion splits or globs on with the default
# IFS.
SPLITS = re.compile(r"[\s*?\[]")
OUTPUT_FILE = frozenset(
    {
        "$GITHUB_OUTPUT",
        "${GITHUB_OUTPUT}",
        '"$GITHUB_OUTPUT"',
        '"${GITHUB_OUTPUT}"',
    }
)
OUTPUT_NAME = re.compile(r"([A-Za-z_][\w-]*)=")
# Unnumbered redirect operators that point fd 1 at their target.
STDOUT_OPS = frozenset({">", ">>", ">|", "&>", "&>>", ">&"})
# uv's subcommands whose output is the interpreter they found.
FINDING = (["python", "find"], ["python", "install"])
MAX_DEPTH = 32


@dataclass
class Var:
    """A plain reference to a shell variable in a written line."""

    name: str
    at: int
    quoted: bool = False


def trusted_text(value: str | None) -> bool:
    """A trusted value as text: a traced marker or a path outside.

    A value holding a line break or other control character is not
    one path: written to ``$GITHUB_OUTPUT`` it starts a new record.
    """
    return (
        value is not None
        and CONTROL.search(value) is None
        and (value == TRUSTED_UV or is_trusted_python(value))
    )


class ShellFacts:
    """What one block of shell assigns, for the trusted-interpreter model.

    ``env`` is the step's YAML env, as the engine reads it.
    """

    def __init__(
        self, src: bytes, root: Node, env: dict[str, str | None]
    ) -> None:
        self.src = src
        self.env = env
        self.counts: Counter[str] = Counter()
        self.top: dict[str, Node] = {}
        # Set by eval, source, a trap action or an assigning builtin
        # whose target the scan cannot read: no variable of the block
        # keeps its trust.
        self.opaque = False
        self.writes: list[tuple[Node, Node]] = []  # (command, redirect)
        self.walk(root)

    def text(self, node: Node) -> str:
        return _node_text(self.src, node)

    def walk(self, root: Node) -> None:
        handlers = {
            "variable_assignment": self.assigned,
            "for_statement": self.loop_variable,
            "unset_command": self.unset,
            "declaration_command": self.declared,
            "expansion": self.default_assigned,
            "command": self.command,
            "redirected_statement": self.redirected,
        }
        stack = [root]
        while stack:
            node = stack.pop()
            stack.extend(node.children)
            handler = handlers.get(node.type)
            if handler is not None:
                handler(node)

    def loop_variable(self, node: Node) -> None:
        variable = node.child_by_field_name("variable")
        if variable is not None:
            self.counts[self.text(variable)] += 1
        if node.children and self.text(node.children[0]) == "select":
            self.counts["REPLY"] += 1

    def unset(self, node: Node) -> None:
        for c in node.children[1:]:
            if c.is_named and literal_of(self.src, c) is None:
                self.opaque = True
            for found in assigned_names(self.word_text(c)):
                self.counts[found] += 1

    def declared(self, node: Node) -> None:
        """Count the names a declaration builtin sets.

        ``declare``/``local``/``typeset NAME`` gives a function its own
        copy; ``export`` and ``readonly NAME`` keep the value. A quoted
        ``"NAME=value"`` assigns in either, and a word the scan cannot
        read may name anything.
        """
        keeps = self.text(node.children[0]) in ("export", "readonly")
        for c in node.children[1:]:
            if (
                c.is_named
                and c.type not in ("variable_name", "variable_assignment")
                and literal_of(self.src, c) is None
            ):
                self.opaque = True
            elif c.type == "variable_name" and not keeps:
                self.counts[self.text(c)] += 1
            elif c.type in ("string", "raw_string", "concatenation", "word"):
                text = self.word_text(c)
                if "=" in text or not keeps:
                    for found in assigned_names(text):
                        self.counts[found] += 1

    def word_text(self, node: Node) -> str:
        """A word's text after quote removal."""
        return unquoted(literal_of(self.src, node), self.text(node))

    def default_assigned(self, node: Node) -> None:
        """``${NAME:=value}`` assigns NAME."""
        named = [c for c in node.children if c.is_named]
        ops = [c.type for c in node.children if not c.is_named]
        if (
            named
            and named[0].type == "variable_name"
            and (":=" in ops or "=" in ops)
        ):
            self.counts[self.text(named[0])] += 1

    def redirected(self, node: Node) -> None:
        """Record a write whose standard output goes to ``$GITHUB_OUTPUT``.

        The last redirect of fd 1 decides where it goes: ``2>>`` or a
        later ``> /dev/null`` leaves the mention unrecorded, and an
        unrecorded mention trusts no output. So does a write inside a
        conditional, loop, function, list or subshell, which may never
        run: only a top-level statement counts.
        """
        parent = node.parent
        if parent is None or parent.type != "program":
            return
        stdout: Node | None = None
        for r in node.children[1:]:
            if r.type == "file_redirect" and self.sets_stdout(r):
                stdout = r
        if stdout is None:
            return
        target = stdout.child_by_field_name("destination")
        if target is not None and self.text(target) in OUTPUT_FILE:
            self.writes.append((node.children[0], stdout))

    def sets_stdout(self, redirect: Node) -> bool:
        """Whether a file redirect points fd 1 somewhere."""
        descriptor = redirect.child_by_field_name("descriptor")
        if descriptor is not None:
            return self.text(descriptor) == "1"
        ops = [c for c in redirect.children if not c.is_named]
        return bool(ops) and self.text(ops[0]) in STDOUT_OPS

    def assigned(self, node: Node) -> None:
        name = node.child_by_field_name("name")
        if name is None:
            return
        # A subscript (a[1]=x) names the array: it changes the name but
        # is no binding of its scalar value, element zero.
        found = IDENTIFIER.match(self.text(name))
        if found is None:
            return
        self.counts[found.group(0)] += 1
        if name.type != "variable_name":
            return
        parent = node.parent
        if parent is not None and parent.type == "declaration_command":
            parent = parent.parent
        if parent is not None and parent.type == "program":
            self.top[found.group(0)] = node

    def command(self, node: Node) -> None:
        if node.child_by_field_name("name") is None:
            return
        # Each word after quote removal: "eval" and 'source' run text
        # too, and printf -v "PY" assigns PY.
        _assigns, words = command_words(self.src, node)
        texts = [unquoted(w.text, w.source) for w in words]
        # builtin eval and command -p eval run the builtin they name.
        i = 0
        while i < len(texts) and (
            texts[i] in BUILTIN_WRAPPERS or (i > 0 and texts[i].startswith("-"))
        ):
            i += 1
        name = texts[i] if i < len(texts) else None
        if name in EVALUATING or (name == "trap" and sets_trap(texts[i + 1 :])):
            self.opaque = True
        if name not in ASSIGNING and name not in DECLARING:
            return
        literal = [w.text is not None for w in words[i + 1 :]]
        for found in assigning_targets(name, texts[i + 1 :], literal):
            if found == UNREAD_TARGET:
                self.opaque = True
            self.counts[found] += 1

    # -- values

    def binding(self, name: str, at: int) -> Node | None:
        """The one top-level assignment of ``name`` before ``at``; else None."""
        node = self.top.get(name)
        if (
            self.opaque
            or self.counts[name] != 1
            or node is None
            or node.end_byte > at
            or any(c.type == "+=" for c in node.children)
        ):
            return None
        return node

    def scalar(self, name: str, at: int, depth: int = 0) -> str | None:
        """The trusted value ``$name`` has at byte ``at``; None if untrusted."""
        if self.opaque or depth > MAX_DEPTH:
            return None
        if self.counts[name] == 0:
            bound = self.env.get(name)
            return bound if trusted_text(bound) else None
        node = self.binding(name, at)
        value = None if node is None else node.child_by_field_name("value")
        if node is None or value is None or value.type == "array":
            return None
        return self.word(value, node.start_byte, depth + 1)

    def array(self, name: str, at: int, depth: int = 0) -> list[str] | None:
        """The words ``"${name[@]}"`` expands to at ``at``; None if unknown."""
        node = self.binding(name, at)
        value = None if node is None else node.child_by_field_name("value")
        if value is None or value.type != "array" or depth > MAX_DEPTH:
            return None
        words: list[str] = []
        for c in value.children:
            if not c.is_named:
                continue
            text = literal_of(self.src, c)
            if text is None:
                text = self.word(c, value.start_byte, depth + 1)
            if text is None or not self.stays_one_word(c, text):
                return None
            words.append(text)
        return words

    def stays_one_word(self, node: Node, value: str) -> bool:
        """Whether a word reading ``value`` expands to that one word.

        A quoted or literal word does. An unquoted expansion does only
        when the value is literal text with no default-IFS or glob
        character and the block never sets ``IFS``: a traced marker
        stands for a path the scan cannot see.
        """
        if (
            node.type in ("string", "raw_string")
            or literal_of(self.src, node) is not None
        ):
            return True
        return self.unsplit(value)

    def unsplit(self, value: str) -> bool:
        """Whether an unquoted expansion of ``value`` stays one word."""
        return (
            value not in (TRUSTED_PYTHON, TRUSTED_UV)
            and SPLITS.search(value) is None
            and self.counts["IFS"] == 0
            and "IFS" not in self.env
        )

    def word(self, node: Node, at: int, depth: int) -> str | None:
        """A trusted value of a word node: literal, reference or lookup."""
        text = literal_of(self.src, node)
        if text is not None:
            return text if trusted_text(text) else None
        inner = sole_child(node)
        name = plain_name(self.src, inner)
        if name is not None:
            return self.scalar(name, at, depth)
        if inner.type == "command_substitution" and self.finds_python(
            inner, at, depth
        ):
            return TRUSTED_PYTHON
        return None

    def expand(self, node: Node) -> list[str] | None:
        """What a command word expands to when it reads a trusted variable.

        ``$V``, ``${V}`` or ``"$V"`` give the trusted value; a quoted
        ``"${arr[@]}"`` gives the array's words. None for anything else,
        and for an unquoted value that may split or glob.
        """
        at = node.start_byte
        inner = sole_child(node)
        name = plain_name(self.src, inner)
        if name is not None:
            value = self.scalar(name, at)
            if value is None or not self.stays_one_word(node, value):
                return None
            return [value]
        if node.type == "string" and inner is not node:
            array = array_name(self.src, inner)
            if array is not None:
                return self.array(array, at)
        return None

    def finds_python(self, node: Node, at: int, depth: int) -> bool:
        """``$(env -i … uv python find|install …)``, every word known.

        The lookup must pass the workspace rules of ``uv_findings()``
        itself, with ``--managed-python`` or ``--system`` and
        ``--no-config``, so it cannot return a workspace ``.venv``; and
        ``env -i`` may pass no interpreter selector outside
        ``CLEARED_ALLOWED``.
        """
        inner = [c for c in node.children if c.is_named]
        if len(inner) != 1 or inner[0].type != "command":
            return False
        assigns, words = command_words(self.src, inner[0])
        if assigns:
            return False
        texts: list[str] = []
        for w in words:
            if w.text is not None:
                texts.append(w.text)
                continue
            expanded = self.expand(w.node)
            if expanded is None or depth > MAX_DEPTH:
                return False
            texts.extend(expanded)
        if not texts or os.path.basename(texts[0]) != "env":
            return False
        return pinned_lookup(texts)

    # -- $GITHUB_OUTPUT

    def outputs(self) -> dict[str, str]:
        """Each output name written once from a trusted variable: its value.

        Every mention of ``GITHUB_OUTPUT`` must be one ``echo`` or
        ``printf`` write the scan reads; otherwise no output is trusted.
        """
        if self.opaque or self.src.count(b"GITHUB_OUTPUT") != len(self.writes):
            return {}
        written: dict[str, list[str | None]] = {}
        for body, _redirect in self.writes:
            found = self.output_line(body)
            if found is None:
                return {}
            name, var = found
            value = self.scalar(var.name, var.at)
            # Unquoted, a value may split into more than one record.
            if value is not None and not var.quoted and not self.unsplit(value):
                value = None
            written.setdefault(name.lower(), []).append(value)
        return {
            name: values[0]
            for name, values in written.items()
            if len(values) == 1 and values[0] is not None
        }

    def output_line(self, body: Node) -> tuple[str, Var] | None:
        """``echo "name=$V"`` or ``printf 'name=%s\\n' "$V"``: name and V.

        None when the template holds a line break, which starts another
        record, or any other control character.
        """
        if body.type != "command":
            return None
        line = self.written_line(body)
        if any(isinstance(p, str) and CONTROL.search(p) for p in line):
            return None
        if len(line) != 2 or not isinstance(line[0], str):
            return None
        name = OUTPUT_NAME.fullmatch(line[0])
        if name is None or not isinstance(line[1], Var):
            return None
        return name.group(1), line[1]

    def written_line(self, body: Node) -> list[str | Var]:
        """The line ``echo WORD`` or ``printf FORMAT WORD`` writes; else []."""
        assigns, words = command_words(self.src, body)
        if assigns or not words:
            return []
        args: list[list[str | Var]] = []
        for w in words[1:]:
            piece = self.pieces(w.node)
            if piece is None:
                return []
            args.append(piece)
        if words[0].text == "echo" and len(args) == 1:
            return args[0]
        if words[0].text == "printf" and len(args) == 2:
            return printf_line(*args)
        return []

    def pieces(
        self, node: Node, quoted: bool = False
    ) -> list[str | Var] | None:
        """A word as literal text and plain variable references."""
        text = literal_of(self.src, node)
        if text is not None:
            return [text]
        name = plain_name(self.src, node)
        if name is not None:
            return [Var(name, node.start_byte, quoted)]
        if node.type not in ("string", "concatenation"):
            return None
        inside = quoted or node.type == "string"
        out: list[str | Var] = []
        at = node.start_byte
        for c in node.children:
            # As literal_of() does, keep text no child covers, such as
            # a line break between two parts of a string.
            gap = self.src[at : c.start_byte] if node.type == "string" else b""
            at = c.end_byte
            piece = [] if c.type == '"' else self.pieces(c, inside)
            if piece is None:
                return None
            if gap:
                piece = [gap.decode("utf-8", "replace"), *piece]
            for p in piece:
                if out and isinstance(p, str) and isinstance(out[-1], str):
                    out[-1] += p
                else:
                    out.append(p)
        return out


def pinned_lookup(texts: list[str]) -> bool:
    """Whether ``env -i … uv python find|install …`` pins its result.

    ``texts`` starts at ``env``.
    """
    options = parse_env(texts, 1)
    rest = texts[options.end :] if options.end > 0 else []
    uv = bool(rest) and (
        rest[0] == TRUSTED_UV or os.path.basename(rest[0]) == "uv"
    )
    if not (options.cleared and not options.unsettled and uv):
        return False
    lookup = parse_uv(rest[1:])
    if lookup.subcommand[:2] not in FINDING or passed_selectors(options.names):
        return False
    no_config = "--no-config" in lookup.options or is_truthy(
        options.names.get("UV_NO_CONFIG")
    )
    return "--managed-python" in lookup.options or (
        "--system" in lookup.options and no_config
    )


def sets_trap(args: list[str]) -> bool:
    """Whether ``trap ARGS`` sets an action: text the scan does not read.

    ``trap``, ``trap -p``, ``trap -l``, ``trap - SIG`` and ``trap ''
    SIG`` set none.
    """
    if args[:1] == ["--"]:
        args = args[1:]
    return bool(args) and args[0] not in TRAP_NO_ACTION and args[0] != ""


def unquoted(text: str | None, source: str) -> str:
    """A word's text after quote removal, or its source without quotes."""
    if text is not None:
        return text
    # A spelling literal_of does not read, such as e\val.
    return re.sub(r"[\\'\"]", "", source)


def assigning_targets(
    name: str, args: list[str], literal: list[bool] | None = None
) -> list[str]:
    """The names an assigning builtin's arguments could assign.

    printf assigns through ``-v NAME`` (or ``-vNAME``), and through
    each argument after a format holding ``%n`` or one the scan cannot
    read; an ordinary ``%s`` format assigns nothing. For the others
    every argument counts, an option's attached operand included,
    and ``read``, ``mapfile`` and ``readarray`` count the variable
    they fill when given no name, whatever their arguments.
    ``literal`` marks the arguments whose text the scan read; a
    target among the others is ``UNREAD_TARGET``.
    """

    def names(at: int, skip: int = 0) -> list[str]:
        if at >= len(args):
            return []
        if literal is not None and not (at < len(literal) and literal[at]):
            return [UNREAD_TARGET]
        return assigned_names(args[at][skip:])

    if name != "printf":
        out = [n for at in range(len(args)) for n in names(at)]
        implicit = IMPLICIT.get(name)
        return out if implicit is None else [*out, implicit]
    out = []
    i = 0
    while i < len(args) and args[i].startswith("-") and args[i] != "--":
        if args[i].startswith("-v"):
            if args[i][2:]:
                out.extend(names(i, 2))
                i += 1
            else:
                out.extend(names(i + 1))
                i += 2
            continue
        i += 1
    i += 1 if i < len(args) and args[i] == "--" else 0
    if i >= len(args):
        return out
    read = literal is None or (i < len(literal) and literal[i])
    if not read or PRINTF_N.search(args[i].replace("%%", "")) is not None:
        out.extend(n for at in range(i + 1, len(args)) for n in names(at))
    return out


def assigned_names(text: str) -> list[str]:
    """The names an argument of an assigning builtin could assign.

    ``NAME``, ``NAME=value`` or ``NAME[i]``; for an option word, each
    name its letters could start (``-vPY`` gives ``vPY``, ``PY``, ``Y``).
    """
    if not text.startswith("-"):
        found = IDENTIFIER.match(text)
        return [] if found is None else [found.group(0)]
    out: list[str] = []
    for start in range(1, len(text)):
        found = IDENTIFIER.match(text, start)
        if found is not None:
            out.append(found.group(0))
    return out


def printf_line(
    fmt: list[str | Var], value: list[str | Var]
) -> list[str | Var]:
    """What ``printf '%s\\n' VALUE`` or ``printf 'NAME=%s\\n' VALUE`` writes."""
    head = fmt[0] if len(fmt) == 1 else None
    if not isinstance(head, str) or not head.endswith("%s\\n"):
        return []
    prefix = head[: -len("%s\\n")]
    if not prefix:
        return value
    return [prefix, *value] if prefix.endswith("=") else []


def sole_child(node: Node) -> Node:
    """The one part of a double-quoted word, or the word itself."""
    if node.type == "string":
        inner = [c for c in node.children if c.type != '"']
        if len(inner) == 1:
            return inner[0]
    return node


def plain_name(src: bytes, node: Node) -> str | None:
    """The name ``$V`` or ``${V}`` reads; None for any other node."""
    if node.type == "simple_expansion":
        named = [c for c in node.children if c.is_named]
        if len(named) == 1 and named[0].type == "variable_name":
            return _node_text(src, named[0])
        return None
    if node.type == "expansion":
        inner = [c for c in node.children if c.type not in ("${", "}")]
        if len(inner) == 1 and inner[0].type == "variable_name":
            return _node_text(src, inner[0])
    return None


def array_name(src: bytes, node: Node) -> str | None:
    """The array ``${arr[@]}`` reads; None for any other node."""
    if node.type != "expansion":
        return None
    inner = [c for c in node.children if c.type not in ("${", "}")]
    if len(inner) != 1 or inner[0].type != "subscript":
        return None
    match = re.fullmatch(r"([A-Za-z_]\w*)\[@\]", _node_text(src, inner[0]))
    return None if match is None else match.group(1)


# -- the file's trusted step outputs

STEP_OUTPUT = re.compile(
    r"\$\{\{\s*steps\.([A-Za-z_][\w-]*)\.outputs\.([A-Za-z_][\w-]*)\s*\}\}",
    re.I,
)
# What each trusted action's output gives, by lower-cased name.
ACTION_OUTPUTS = {
    "actions/setup-python": {"python-path": TRUSTED_PYTHON},
    "astral-sh/setup-uv": {"uv-path": TRUSTED_UV},
}


@dataclass
class Trust:
    """The step outputs a file's later steps may trust.

    Keyed by (job, lower-cased step id): the step's position and its
    trusted outputs, by lower-cased name, each the marker or literal
    path it stands for. A step id used twice in a job trusts nothing.
    """

    outputs: dict[tuple[str, str], tuple[int, dict[str, str]]] = field(
        default_factory=dict
    )

    def add(
        self, job: str, ident: str, step: int, found: dict[str, str]
    ) -> None:
        key = (job, ident.lower())
        self.outputs[key] = (step, {} if key in self.outputs else found)

    def resolve(self, expression: str, job: str, step: int) -> str | None:
        """What a whole ``${{ }}`` expression stands for, if trusted."""
        match = STEP_OUTPUT.fullmatch(expression.strip())
        if match is None:
            return None
        entry = self.outputs.get((job, match.group(1).lower()))
        if entry is None or entry[0] >= step:
            return None
        return entry[1].get(match.group(2).lower())
