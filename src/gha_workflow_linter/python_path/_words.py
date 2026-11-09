# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Words of a parsed command: literal text, quoting, and the command's shape."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from gha_workflow_linter.shell._tree import node_text as _node_text
from gha_workflow_linter.shell._tree import statement_redirects

from ._invocation import WORD_TYPES

if TYPE_CHECKING:
    from tree_sitter import Node


@dataclass
class Finding:
    repo: str
    path: str
    line: int
    kind: str
    rule: str
    detail: str
    snippet: str


@dataclass
class Word:
    """One command word: its literal text when every part is literal."""

    node: Node
    text: str | None  # None when any part is not literal
    quoted: bool  # wholly quoted: cannot split or vanish
    source: str  # as written

    @property
    def literal(self) -> bool:
        return self.text is not None


@dataclass
class Block:
    """One shell block: a step's run text or a whole script."""

    text: str
    first_line: int  # 1-based source line of text[0]
    line_of_offset: list[tuple[int, int]]  # (byte offset, source line)
    kind: str
    env: dict[str, str | None] = field(
        default_factory=dict
    )  # literal YAML env; None = expression


def literal_of(src: bytes, node: Node) -> str | None:
    """The literal text of a word node, or None if it holds an expansion.

    An unquoted word that could glob or brace-expand is not literal,
    nor is one holding a backslash: the scan does not decode unusual
    spellings.
    """
    t = node.type
    text = _node_text(src, node)
    if t in ("word", "number"):
        expands = any(c in text for c in "*?[{~") and not text.startswith("-")
        return None if expands or "\\" in text else text
    if t == "raw_string":
        return text[1:-1]
    if t == "string_content":
        return (
            text.replace("\\$", "$").replace('\\"', '"').replace("\\\\", "\\")
        )
    if t in ("string", "concatenation"):
        parts: list[str] = []
        for child in node.children:
            if child.type == '"':
                continue
            piece = literal_of(src, child)
            if piece is None:
                return None
            parts.append(piece)
        return "".join(parts)
    return None


def word_of(src: bytes, node: Node) -> Word:
    quoted = node.type in ("string", "raw_string") or (
        node.type == "concatenation"
        and all(c.type in ("string", "raw_string") for c in node.children)
    )
    return Word(node, literal_of(src, node), quoted, _node_text(src, node))


def command_words(src: bytes, command: Node) -> tuple[list[Node], list[Word]]:
    """A command's prefix assignments and its words (name first).

    tree-sitter attaches a word after a redirect's target to the
    redirect (``python3 < f -I``); bash reads it as the command's. Such
    words are appended.
    """
    assigns: list[Node] = []
    words: list[Word] = []
    for child in command.children:
        if child.type == "variable_assignment":
            assigns.append(child)
        elif child.type == "command_name":
            words.append(word_of(src, child.children[0]))
        elif child.type in WORD_TYPES:
            words.append(word_of(src, child))
    redirects = statement_redirects(command)
    # ``python3 0< file``: the descriptor is a number word before the
    # redirect, whatever words the redirect carries after its target.
    following = redirects[:1]
    if (
        words
        and words[-1].node.type == "number"
        and following
        and following[0].type == "file_redirect"
        and following[0].start_byte == words[-1].node.end_byte
    ):
        words.pop()
    for redirect in redirects:
        if redirect.type == "file_redirect":
            target = redirect.child_by_field_name("destination")
            after = target.end_byte if target is not None else 0
            for extra in redirect.children:
                if extra.start_byte >= after and extra.type in WORD_TYPES:
                    words.append(word_of(src, extra))
    return assigns, words
