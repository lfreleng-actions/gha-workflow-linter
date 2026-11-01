# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""PYTHONPATH values: what they can expand to, and which entries are unsafe.

A value is judged three ways, since a step cannot know what it
inherits: with PYTHONPATH unset, set but empty, and set to a path.
Python ignores a PYTHONPATH that is empty as a whole, but an empty
entry in a longer value names the working directory.

Values come in as parsed words, so quoting is kept: a ``$`` inside
single quotes, or in a YAML value (which the runner never expands), is
a literal character, not a variable. Part of the engine in ``_engine``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from ._shell import Expr, Lit, Param, Word

if TYPE_CHECKING:
    from collections.abc import Callable

    from ._shell import Part

TEXT = "text"
SELF = "self"
# What an expansion the scan cannot resolve stands for: some non-empty
# absolute path. Taking it as empty would flag nearly every assignment.
UNKNOWN = "unknown"
WORKSPACE = "workspace"
WORKDIR = "workdir"
RELATIVE = "relative"
# How PYTHONPATH reads in each inherited state, and how a finding says so.
STATES = (
    ("/inherited", ""),
    (None, " when PYTHONPATH is unset"),
    ("", " when PYTHONPATH is set but empty"),
)
APPEND_HINT = "; append with ${PYTHONPATH:+:$PYTHONPATH}"


@dataclass
class Token:
    """A piece of a PYTHONPATH value: literal text, or what an expansion names.

    ``kind`` is "text", "self" (PYTHONPATH or a copy of it), or what
    an expansion names: "workdir" (the working directory),
    "workspace", "relative" (a relative path), or "unknown". A
    ``self`` token keeps its operator and operand.
    """

    kind: str
    text: str = ""
    op: str = ""
    arg: list[Token] | None = None


def word_tokens(
    word: Word,
    copies: set[str],
    tilde: bool,
    classify: Callable[[Part], str],
) -> list[Token]:
    """The tokens of a PYTHONPATH value written as a shell or YAML word.

    ``copies`` names variables holding a copy of PYTHONPATH. ``tilde``
    applies the shell's tilde expansion in assignments: an unquoted
    ``~`` that starts an entry is a home directory. ``classify`` says
    what any other expansion names.
    """
    tokens: list[Token] = []
    for part in word.parts:
        if isinstance(part, Lit):
            tokens.extend(_literal(part, tilde, tokens))
        elif isinstance(part, Param) and (
            part.name == "PYTHONPATH" or part.name in copies
        ):
            inner = (
                word_tokens(part.arg, copies, False, classify)
                if part.arg
                else None
            )
            tokens.append(Token(SELF, "$" + part.name, part.op, inner))
        elif isinstance(part, Expr) and part.kind == "pythonpath":
            tokens.append(Token(SELF, "${{ env.PYTHONPATH }}"))
        else:
            tokens.append(Token(classify(part), "$..."))
    return tokens


def _literal(part: Lit, tilde: bool, before: list[Token]) -> list[Token]:
    """Literal text, with an unquoted leading ``~`` read as a home directory."""
    if part.quoted or not tilde or "~" not in part.text:
        return [Token(TEXT, part.text)]
    found: list[Token] = []
    entry_start = not before or (
        before[-1].kind == TEXT and before[-1].text.endswith(":")
    )
    for index, entry in enumerate(part.text.split(":")):
        if index:
            found.append(Token(TEXT, ":"))
        if entry.startswith("~") and (entry_start or index):
            head, slash, rest = entry.partition("/")
            found.append(Token(UNKNOWN, head))
            if slash:
                found.append(Token(TEXT, slash + rest))
        elif entry:
            found.append(Token(TEXT, entry))
    return found


def expand(tokens: list[Token], inherited: str | None) -> list[Token]:
    """The tokens with every PYTHONPATH expansion resolved.

    ``inherited`` is the PYTHONPATH already in the environment, or
    None when it is unset. ``:+``/``:-`` test for a non-empty value,
    ``+``/``-`` only for a set one.
    """
    resolved: list[Token] = []
    for token in tokens:
        if token.kind != SELF:
            resolved.append(token)
            continue
        present = inherited is not None
        filled = bool(inherited)
        operand = expand(token.arg or [], inherited)
        own = [Token(UNKNOWN, token.text)] if filled else []
        resolved.extend(
            {
                ":+": operand if filled else [],
                "+": operand if present else [],
                ":-": own if filled else operand,
                ":=": own if filled else operand,
                "-": own if present else operand,
                "=": own if present else operand,
            }.get(token.op, own)
        )
    return resolved


def entries(tokens: list[Token]) -> list[list[Token]]:
    """Split resolved tokens into colon-separated entries."""
    found: list[list[Token]] = [[]]
    for token in tokens:
        if token.kind != TEXT:
            found[-1].append(token)
            continue
        for index, piece in enumerate(token.text.split(":")):
            if index:
                found.append([])
            if piece:
                found[-1].append(Token(TEXT, piece))
    return found


def pythonpath_problems(
    tokens: list[Token], kind: str
) -> list[tuple[str, str]]:
    """Rule and detail for each unsafe entry a PYTHONPATH value can hold."""
    problems: list[tuple[str, str]] = []
    for inherited, when in STATES:
        resolved = expand(tokens, inherited)
        filled = any(token.kind != TEXT or token.text for token in resolved)
        if filled and not all(entries(resolved)):
            hint = APPEND_HINT if when else ""
            problems.append(("PPA004", f"empty entry{when}{hint}"))
            break
    if kind == "action":
        detail = _action_problem(tokens)
        if detail:
            problems.append(("PPA005", detail))
    return problems


def _action_problem(tokens: list[Token]) -> str:
    """Why an action's PYTHONPATH can name the caller's checkout, if it can.

    An action's working directory is the caller's workspace, so a
    relative entry names a path in the caller's checkout too.
    """
    every = [
        entry
        for inherited, _when in STATES
        for entry in entries(expand(tokens, inherited))
    ]
    kinds = {token.kind for entry in every for token in entry}
    if WORKSPACE in kinds:
        return "workspace entry: the caller's checkout"
    if WORKDIR in kinds:
        return "working-directory entry: the caller's checkout"
    for entry in every:
        head = entry[0] if entry else None
        if head is not None and (
            head.kind == RELATIVE
            or (head.kind == TEXT and not head.text.startswith("/"))
        ):
            text = "".join(token.text for token in entry)
            return f"relative entry {text!r}"
    return ""
