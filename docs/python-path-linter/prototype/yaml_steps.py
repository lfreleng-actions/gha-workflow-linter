# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Workflow and action files, read as YAML (prototype copy of the engine's reader).

PyYAML gives each ``run:`` value exactly as the runner receives it:
comments dropped, quotes removed, folded blocks joined. Each step's
shell comes with a line map back to the file, its environment from the
scopes that apply to it, and its ``working-directory``.

YAML values reach the runner literally: GitHub substitutes ``${{ }}``
expressions in them but never shell-expands ``$name`` or ``~``. They
become words of quoted literal text and expression parts, which the
shell code then reads as the literals they are.
"""

from __future__ import annotations

from bisect import bisect_right
from dataclasses import dataclass, field
import re

import yaml

# The parts of a word the reader produces. ``Lit`` is literal text and
# ``Expr`` a ``${{ }}`` expression; ``Word`` is a sequence of them.
MARK_OPEN = "\ue000"
MARK_CLOSE = "\ue001"


@dataclass
class Lit:
    """Literal text; ``quoted`` when it came from quotes."""

    text: str
    quoted: bool = False


@dataclass
class Expr:
    """A GitHub expression, which reaches the shell as literal text."""

    kind: str
    index: int


Part = Lit | Expr


@dataclass
class Word:
    """One value: its parts, and where it sits in the text."""

    parts: list[Part]
    start: int = 0
    end: int = 0


EXPRESSION = re.compile(r"\$\{\{\s*(.*?)\s*\}\}")
EXPRESSION_KINDS = {
    "github.action_path": "action_path",
    "github.workspace": "workspace",
    "env.PYTHONPATH": "pythonpath",
    "runner.temp": "temp",
}
# Shells that do not read a step's run: text as POSIX-style shell.
NOT_SHELL = re.compile(r"^(?:python\d*(?:\.\d+)?|pwsh|powershell|cmd|node)$")
MARKER = re.compile(
    re.escape(MARK_OPEN) + r"(\w+):(\d+)" + re.escape(MARK_CLOSE)
)
# The line breaks PyYAML counts, so line numbers agree with its marks.
LINE_BREAK = re.compile("\r\n|[\r\n\x85\u2028\u2029]")
# Node visits allowed per file. Aliases let a small file name the same
# subtree many times over; real workflows use a few thousand visits.
VISIT_BUDGET = 200_000


@dataclass
class Expression:
    """One ``${{ }}`` expression: what it names, and its original text."""

    kind: str
    name: str
    text: str


@dataclass
class Block:
    """The shell of one ``run:`` step, or of a whole script.

    ``starts`` maps the text back to the file: the offset in the value
    (as written, before its ``${{ }}`` expressions are marked) where
    each source line's text starts, with the line's 1-based number, in
    order. ``errexit`` says whether the shell starts with ``-e``, as
    the runner's bash and sh defaults do.
    """

    text: str
    starts: list[tuple[int, int]]
    env: dict[str, Word] = field(default_factory=dict)
    directory: Word | None = None
    errexit: bool = True

    def line_at(self, offset: int) -> int:
        """The 1-based source line of an offset in the value."""
        index = bisect_right(self.starts, offset, key=lambda start: start[0])
        return self.starts[max(index - 1, 0)][1]


def line_starts(text: str, first: int) -> list[tuple[int, int]]:
    """Where each line of a text starts, numbered from ``first``."""
    starts = [(0, first)]
    for number, match in enumerate(re.finditer("\n", text), start=first + 1):
        starts.append((match.end(), number))
    return starts


@dataclass
class YamlFile:
    """What the scan reads from one workflow or action file."""

    blocks: list[Block] = field(default_factory=list)
    pythonpath: list[tuple[int, Word]] = field(default_factory=list)
    setup_uv: list[tuple[int, Word | None]] = field(default_factory=list)
    expressions: list[Expression] = field(default_factory=list)


def errexit_of(shell: str | None) -> bool:
    """Whether a step's shell starts with ``-e``.

    The runner's defaults do: ``bash -e {0}`` and ``sh -e {0}``, and
    ``bash --noprofile --norc -eo pipefail {0}`` for ``shell: bash``.
    A custom command line has it only when it says so.
    """
    if shell is None or "{0}" not in shell:
        return True
    words = shell.split()
    return any(re.fullmatch(r"-[a-z]*e[a-z]*", word) for word in words) or (
        any(words[i : i + 2] == ["-o", "errexit"] for i in range(len(words)))
    )


def split_lines(text: str) -> list[str]:
    """A YAML file's lines, split where PyYAML counts a new line."""
    return LINE_BREAK.split(text)


def mark_expressions(text: str, table: list[Expression]) -> str:
    """Swap each ``${{ }}`` expression for a marker indexing ``table``."""

    def swap(match: re.Match[str]) -> str:
        inner = match.group(1)
        compact = inner.replace(" ", "")
        if not compact.startswith("env."):
            compact = compact.lower()
        kind = EXPRESSION_KINDS.get(compact, "other")
        name = re.sub(r"\W+", "_", inner).strip("_").lower()
        table.append(Expression(kind, name, match.group(0)))
        return f"{MARK_OPEN}{kind}:{len(table) - 1}{MARK_CLOSE}"

    return EXPRESSION.sub(swap, text)


def restore_expressions(text: str, table: list[Expression]) -> str:
    """Put the original ``${{ }}`` text back in place of each marker."""

    def swap(match: re.Match[str]) -> str:
        index = int(match.group(2))
        return table[index].text if index < len(table) else match.group(0)

    return MARKER.sub(swap, text)


def literal_word(text: str, table: list[Expression]) -> Word:
    """A YAML value as a word: quoted literal text and expressions."""
    marked = mark_expressions(text, table)
    parts: list[Part] = []
    position = 0
    for match in MARKER.finditer(marked):
        if match.start() > position:
            parts.append(Lit(marked[position : match.start()], quoted=True))
        parts.append(Expr(match.group(1), int(match.group(2))))
        position = match.end()
    if position < len(marked) or not parts:
        parts.append(Lit(marked[position:], quoted=True))
    return Word(parts)


def read(text: str, kind: str) -> YamlFile:
    """Read a workflow or action file. Raises ValueError if it is not YAML."""
    try:
        documents = list(yaml.compose_all(text, Loader=yaml.SafeLoader))
    except yaml.YAMLError as error:
        problem = str(error).splitlines()[0] if str(error) else "invalid"
        raise ValueError(f"not valid YAML: {problem}") from error
    found = YamlFile()
    reader = _Reader(split_lines(text), kind, found)
    for document in documents:
        if document is not None:
            reader.visit(document, [], ())
    return found


def scalar(node: yaml.Node | None) -> str | None:
    """A scalar node's value, or None for anything else."""
    if isinstance(node, yaml.ScalarNode):
        return str(node.value)
    return None


def child(node: yaml.Node | None, key: str) -> yaml.Node | None:
    """The value under ``key`` in a mapping node, if there is one."""
    if not isinstance(node, yaml.MappingNode):
        return None
    found = None
    for name, value in node.value:
        if scalar(name) == key:
            found = value
    return found


def key_line(node: yaml.MappingNode, key: str) -> int:
    """The 1-based line of ``key`` in a mapping node."""
    for name, _value in node.value:
        if scalar(name) == key:
            return int(name.start_mark.line) + 1
    return int(node.start_mark.line) + 1


class _Reader:
    """A walk over one file's YAML nodes, collecting what the scan needs."""

    def __init__(self, lines: list[str], kind: str, found: YamlFile) -> None:
        self.lines = lines
        self.kind = kind
        self.found = found
        self.active: set[int] = set()
        self.visits = 0

    def visit(
        self,
        node: yaml.Node,
        ancestors: list[yaml.MappingNode],
        path: tuple[str, ...],
    ) -> None:
        """Visit a node at ``path``: its keys, with ``[]`` for list entries.

        Raises ValueError when aliases make the file too large to walk.
        """
        if id(node) in self.active or len(path) > 64:
            return
        self.visits += 1
        if self.visits > VISIT_BUDGET:
            raise ValueError("too many YAML nodes once aliases are expanded")
        self.active.add(id(node))
        if isinstance(node, yaml.MappingNode):
            self.mapping(node, ancestors, path)
            for key, value in node.value:
                name = scalar(key) or ""
                self.visit(value, [*ancestors, node], (*path, name))
        elif isinstance(node, yaml.SequenceNode):
            for entry in node.value:
                self.visit(entry, ancestors, (*path, "[]"))
        self.active.discard(id(node))

    def mapping(
        self,
        node: yaml.MappingNode,
        ancestors: list[yaml.MappingNode],
        path: tuple[str, ...],
    ) -> None:
        """Collect PYTHONPATH settings, setup-uv use and a step's shell.

        A step is an entry of a ``steps`` list, or of a list at the top
        of the file; so a matrix entry or an input that happens to be
        called ``run`` is not read as shell.
        """
        table = self.found.expressions
        env = child(node, "env")
        if isinstance(env, yaml.MappingNode):
            for name, value in env.value:
                text = scalar(value)
                if scalar(name) == "PYTHONPATH" and text is not None:
                    line = int(name.start_mark.line) + 1
                    self.found.pythonpath.append(
                        (line, literal_word(text, table))
                    )
        if path[-1:] != ("[]",) or path[-2:-1] not in ((), ("steps",)):
            return
        uses = scalar(child(node, "uses")) or ""
        if uses.startswith("astral-sh/setup-uv@"):
            directory = scalar(child(child(node, "with"), "working-directory"))
            word = None if directory is None else literal_word(directory, table)
            self.found.setup_uv.append((key_line(node, "uses"), word))
        run = child(node, "run")
        if isinstance(run, yaml.ScalarNode) and self.is_shell(node, ancestors):
            self.found.blocks.append(self.block(node, run, ancestors))

    def scopes(
        self, node: yaml.MappingNode, ancestors: list[yaml.MappingNode]
    ) -> list[yaml.MappingNode]:
        """The mappings whose ``env`` and ``defaults`` reach a step.

        A workflow step gets the workflow's, its job's and its own; a
        composite action step only its own, as actions have no others.
        """
        if self.kind != "workflow" or not ancestors:
            return [node]
        root, job = ancestors[0], ancestors[-1]
        return [root, job, node] if job is not root else [root, node]

    def shell_of(
        self, node: yaml.MappingNode, ancestors: list[yaml.MappingNode]
    ) -> str | None:
        """The step's ``shell``, or the default that reaches it."""
        shell = scalar(child(node, "shell"))
        for scope in reversed(self.scopes(node, ancestors)[:-1]):
            if shell is None:
                defaults = child(child(scope, "defaults"), "run")
                shell = scalar(child(defaults, "shell"))
        return shell

    def is_shell(
        self, node: yaml.MappingNode, ancestors: list[yaml.MappingNode]
    ) -> bool:
        """False when the step's shell, or its default, is not POSIX-style."""
        shell = self.shell_of(node, ancestors)
        if not shell or not shell.split():
            return True
        return not NOT_SHELL.match(shell.split()[0].rsplit("/", 1)[-1])

    def block(
        self,
        node: yaml.MappingNode,
        run: yaml.ScalarNode,
        ancestors: list[yaml.MappingNode],
    ) -> Block:
        table = self.found.expressions
        env: dict[str, Word] = {}
        directory: Word | None = None
        for scope in self.scopes(node, ancestors):
            values = child(scope, "env")
            if isinstance(values, yaml.MappingNode):
                for name, value in values.value:
                    key, text = scalar(name), scalar(value)
                    if key is not None and text is not None:
                        env[key] = literal_word(text, table)
            default = child(
                child(child(scope, "defaults"), "run"), "working-directory"
            )
            own = child(scope, "working-directory") if scope is node else None
            for setting in (default, own):
                text = scalar(setting)
                if text is not None:
                    directory = literal_word(text, table)
        value = str(run.value)
        return Block(
            mark_expressions(value, table),
            self.line_map(run, value),
            env,
            directory,
            errexit_of(self.shell_of(node, ancestors)),
        )

    def line_map(
        self, run: yaml.ScalarNode, value: str
    ) -> list[tuple[int, int]]:
        """Where each source line of a ``run:`` value starts in the value.

        A ``|`` block keeps its lines. Other styles join lines, so each
        line's text is found in the value in turn, past the one before;
        from a line not found as written (one with escapes) on, the
        value maps to the last line found.
        """
        first = int(run.start_mark.line)
        if run.style == "|":
            return line_starts(value, first + 2)
        last = int(run.end_mark.line)
        pieces = list(self.lines[first : last + 1]) or [""]
        pieces[-1] = pieces[-1][: int(run.end_mark.column)]
        pieces[0] = pieces[0][int(run.start_mark.column) :]
        if run.style in ("'", '"'):
            pieces[0] = pieces[0][1:]
            pieces[-1] = pieces[-1][:-1]
        number = first + 1
        if run.style == ">":
            pieces, number = pieces[1:], first + 2
        starts: list[tuple[int, int]] = []
        position = 0
        for offset, piece in enumerate(pieces):
            text = piece.strip()
            text = text.replace("''", "'") if run.style == "'" else text
            found = value.find(text, position) if text else position
            if found < 0 or (run.style == '"' and "\\" in text):
                break
            if text:
                starts.append((found, number + offset))
                position = found + len(text)
        return starts or [(0, number)]
