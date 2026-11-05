# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""PYTHONPATH values as tokens, and lines written to $GITHUB_ENV."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from pythonpath_tokens import (
    RELATIVE,
    SELF,
    TEXT,
    UNKNOWN,
    WORKDIR,
    WORKSPACE,
    Token,
    pythonpath_problems,
)
from words import Word, _node_text, command_words

if TYPE_CHECKING:
    from collections.abc import Callable

    from tree_sitter import Node
    from words import Block


ENV_PREFIX = "written to GITHUB_ENV, so every later step gets it: "
PRINTF_CONVERSION = re.compile(r"(%%|%[-+ #0]*\d*(?:\.\d+)?[sbdiqxXoucfeEgG])")


def is_text_line(line: list[Token], text: str) -> bool:
    """True when a line is the one literal text ``text``."""
    return len(line) == 1 and line[0].kind == TEXT and line[0].text == text


class PythonpathChecks:
    """PYTHONPATH judgement, mixed into the block scan.

    Uses the scan's ``src``, ``block``, ``constants``,
    ``pythonpath_copies``, ``report`` and ``skip_wrappers``.
    """

    src: bytes
    block: Block
    constants: dict[str, list[Word]]
    pythonpath_copies: set[str]
    report: Callable[..., None]
    skip_wrappers: Callable[[list[str]], int]

    def check_pythonpath(
        self, value: Node, at: Node, prefix_self: bool
    ) -> None:
        """Judge ``PYTHONPATH=value`` (``+=`` when ``prefix_self``)."""
        tokens = self.pythonpath_tokens(value)
        if prefix_self:
            tokens = [Token(SELF, "$PYTHONPATH"), *tokens]
        self.judge_pythonpath(tokens, at, tilde=True)

    def check_pythonpath_word(self, word: Word, at: Node) -> None:
        """Judge a ``PYTHONPATH=value`` word passed to env or export."""
        tokens = self.pythonpath_tokens(word.node)
        if (
            not tokens
            or tokens[0].kind != TEXT
            or not tokens[0].text.startswith("PYTHONPATH=")
        ):
            self.report(
                at, "PPA009", "PYTHONPATH set from a value the scan cannot read"
            )
            return
        tokens[0] = Token(TEXT, tokens[0].text[len("PYTHONPATH=") :])
        self.judge_pythonpath(tokens, at, tilde=False)

    def judge_pythonpath(
        self, tokens: list[Token], at: Node, tilde: bool, prefix: str = ""
    ) -> None:
        tokens = flatten_groups(tokens)
        if tilde:
            tokens = self.tilde_tokens(tokens)
        if any(t.kind == "unresolved" for t in tokens):
            self.report(
                at,
                "PPA009",
                prefix + "PYTHONPATH set from a value the scan cannot read",
            )
            return
        for rule, detail in pythonpath_problems(tokens, self.block.kind):
            self.report(at, rule, prefix + detail)

    @staticmethod
    def tilde_tokens(tokens: list[Token]) -> list[Token]:
        """An unquoted ``~`` starting an entry is a home directory (unknown, absolute)."""
        out: list[Token] = []
        at_entry_start = True
        for token in tokens:
            if (
                token.kind == TEXT
                and token.op == "unquoted"
                and "~" in token.text
            ):
                pieces = token.text.split(":")
                for index, entry in enumerate(pieces):
                    if index:
                        out.append(Token(TEXT, ":"))
                    starts = at_entry_start or index > 0
                    if entry.startswith("~") and starts:
                        head, slash, rest = entry.partition("/")
                        out.append(Token(UNKNOWN, head))
                        if slash:
                            out.append(Token(TEXT, slash + rest))
                    elif entry:
                        out.append(Token(TEXT, entry))
                at_entry_start = token.text.endswith(":")
                continue
            out.append(token)
            at_entry_start = token.kind == TEXT and token.text.endswith(":")
        return out

    def pythonpath_tokens(self, node: Node) -> list[Token]:
        """Tokens of a PYTHONPATH value written as a shell word.

        A reference to PYTHONPATH (with its operator and operand) is a
        "self" token; a single-assignment constant is put in as its own
        tokens; $GITHUB_WORKSPACE, $PWD and $(pwd) name the workspace;
        any other expansion is "unknown" (some absolute path), except
        one that can plainly be relative or empty, which is
        "unresolved".
        """
        t = node.type
        text = _node_text(self.src, node)
        if t in ("string", "concatenation"):
            out: list[Token] = []
            for child in node.children:
                if child.type not in ('"', "'"):
                    out.extend(self.pythonpath_tokens(child))
            return out
        if t in ("simple_expansion", "expansion"):
            return [self.expansion_token(node)]
        if t == "command_substitution":
            prints_cwd = re.fullmatch(r"\$\(\s*pwd\s*\)", text)
            return [Token(WORKDIR if prints_cwd else UNKNOWN, text)]
        literal = {
            "word": lambda: Token(TEXT, text, "unquoted"),
            "number": lambda: Token(TEXT, text, "unquoted"),
            "raw_string": lambda: Token(TEXT, text[1:-1]),
            "string_content": lambda: Token(
                TEXT, text.replace("\\$", "$").replace("\\\\", "\\")
            ),
        }
        make = literal.get(t, lambda: Token("unresolved", text))
        return [make()]

    def expansion_token(self, node: Node) -> Token:
        """The token of ``$name`` or ``${...}``."""
        src = _node_text(self.src, node)
        if node.type == "simple_expansion":
            return self.named_token(_node_text(self.src, node.children[1]), src)
        named = [c for c in node.children if c.is_named]
        anonymous = [
            c
            for c in node.children
            if not c.is_named and c.type not in ("${", "}")
        ]
        if not named or named[0].type != "variable_name":
            # ${a[i]}, ${#x}, ${!x}: a subscript, length or indirection.
            mentions_self = "PYTHONPATH" in src
            return Token("unresolved" if mentions_self else UNKNOWN, src)
        name = _node_text(self.src, named[0])
        op = anonymous[0].type if anonymous else ""
        if len(named) == 1 and not anonymous:
            return self.named_token(name, src)
        if name == "PYTHONPATH" and op in (":+", "+", ":-", "-", ":=", "="):
            operand = named[1] if len(named) > 1 else None
            arg = self.pythonpath_tokens(operand) if operand is not None else []
            return Token(SELF, "$PYTHONPATH", op, arg)
        # ${PYTHONPATH//x/}: PYTHONPATH changed in a way the scan does
        # not follow; ${x:+text}: empty or the operand, both to judge.
        unresolved = name == "PYTHONPATH" or op in (":+", "+")
        return Token("unresolved" if unresolved else UNKNOWN, src)

    def named_token(self, name: str, src: str) -> Token:
        """The token of a plain reference to ``name``."""
        fixed = {
            "PYTHONPATH": Token(SELF, "$PYTHONPATH"),
            "GITHUB_WORKSPACE": Token(WORKSPACE, src),
            "PWD": Token(WORKDIR, src),
        }
        if name in fixed:
            return fixed[name]
        if name in self.constants and len(self.constants[name]) == 1:
            element = self.constants[name][0]
            plain = element.node.type in ("word", "number")
            relative = not (element.text or "").startswith("/")
            if plain and relative and self.block.kind == "action":
                return Token(RELATIVE, element.text or "")
            tokens = self.pythonpath_tokens(element.node)
            return (
                tokens[0]
                if len(tokens) == 1
                else Token("group", src, arg=tokens)
            )
        kind = "unresolved" if name in self.pythonpath_copies else UNKNOWN
        return Token(kind, src)

    def env_writes(
        self, node: Node, texts: list[str], redirects: list[Node], writes: bool
    ) -> None:
        """PYTHONPATH lines a command writes to $GITHUB_ENV.

        From echo or printf whose output goes there, a heredoc into
        cat, or a pipe into tee naming the file.
        """
        start = self.skip_wrappers(texts)
        if start < 0 or start >= len(texts):
            return
        name = texts[start]
        tee = name == "tee" and any(
            t.strip('"') in ("$GITHUB_ENV", "${GITHUB_ENV}")
            for t in texts[start + 1 :]
        )
        if not (writes or tee):
            return
        lines: list[list[Token]] = []
        if name in ("echo", "printf"):
            _a, words = command_words(self.src, node)
            args = words[
                self.skip_wrappers([w.text or "\x00" + w.source for w in words])
                + 1 :
            ]
            written = self.written_lines(node, name, args)
            if written is None:
                return
            lines = written
        for redirect in redirects:
            if redirect.type == "heredoc_redirect":
                lines.extend(self.heredoc_redirect_lines(redirect))
        self.judge_env_lines(node, lines)

    def written_lines(
        self, node: Node, name: str, args: list[Word]
    ) -> list[list[Token]] | None:
        """The lines echo or printf writes, as tokens; None if unreadable."""
        if name == "echo":
            while (
                args
                and args[0].literal
                and re.fullmatch(r"-[neE]+", args[0].text or "")
            ):
                args.pop(0)
            joined: list[Token] = []
            for index, word in enumerate(args):
                if index:
                    joined.append(Token(TEXT, " "))
                joined.extend(self.pythonpath_tokens(word.node))
            return split_token_lines(joined)
        if not args:
            return []
        if not args[0].literal:
            self.report(
                node,
                "PPA009",
                ENV_PREFIX + "printf format the scan cannot read",
            )
            return None
        fmt = args[0].text or ""
        values = list(args[1:])
        out: list[Token] = []
        while True:
            used = 0
            for piece in PRINTF_CONVERSION.split(fmt):
                if piece == "%%":
                    out.append(Token(TEXT, "%"))
                elif PRINTF_CONVERSION.fullmatch(piece):
                    used += 1
                    if values:
                        out.extend(self.pythonpath_tokens(values.pop(0).node))
                elif piece:
                    text = piece.replace("\\n", "\n").replace("\\t", "\t")
                    out.append(Token(TEXT, text))
            if not values or used == 0:
                return split_token_lines(out)

    def heredoc_redirect_lines(self, redirect: Node) -> list[list[Token]]:
        """A heredoc's body as lines of tokens; a quoted one is all text."""
        quoted = any(
            c.type == "heredoc_start"
            and _node_text(self.src, c).startswith(("'", '"'))
            for c in redirect.children
        )
        lines: list[list[Token]] = []
        for child in redirect.children:
            if child.type != "heredoc_body":
                continue
            if quoted:
                body = _node_text(self.src, child)
                lines.extend([Token(TEXT, ln)] for ln in body.split("\n"))
            else:
                lines.extend(self.heredoc_lines(child))
        return lines

    def judge_env_lines(self, node: Node, lines: list[list[Token]]) -> None:
        """Judge each PYTHONPATH line or NAME<<DELIMITER record written."""
        i = 0
        while i < len(lines):
            line = lines[i]
            i += 1
            head = line[0].text if line and line[0].kind == TEXT else ""
            record = (
                re.match(r"^PYTHONPATH<<(.+)$", head)
                if len(line) == 1
                else None
            )
            if record:
                end = i
                while end < len(lines) and not is_text_line(
                    lines[end], record.group(1)
                ):
                    end += 1
                value: list[Token] = []
                for n, ln in enumerate(lines[i:end]):
                    if n:
                        value.append(Token(TEXT, "\n"))
                    value.extend(ln)
                self.judge_pythonpath(
                    value, node, tilde=False, prefix=ENV_PREFIX
                )
                i = end + 1
            elif head.startswith("PYTHONPATH="):
                tokens = [Token(TEXT, head[len("PYTHONPATH=") :]), *line[1:]]
                self.judge_pythonpath(
                    tokens, node, tilde=False, prefix=ENV_PREFIX
                )
            elif (
                line
                and line[0].kind != TEXT
                and any("PYTHONPATH" in t.text for t in line)
            ):
                self.report(
                    node,
                    "PPA009",
                    ENV_PREFIX
                    + "a line mentions PYTHONPATH and cannot be read",
                )

    def heredoc_lines(self, body: Node) -> list[list[Token]]:
        """An unquoted heredoc body's lines as tokens: text and expansions."""
        tokens: list[Token] = []
        position = body.start_byte
        for child in body.children:
            if child.start_byte > position:
                tokens.append(
                    Token(TEXT, self.src[position : child.start_byte].decode())
                )
            if child.type in (
                "simple_expansion",
                "expansion",
                "command_substitution",
            ):
                tokens.extend(self.pythonpath_tokens(child))
            else:
                tokens.append(Token(TEXT, _node_text(self.src, child)))
            position = child.end_byte
        if body.end_byte > position:
            tokens.append(
                Token(TEXT, self.src[position : body.end_byte].decode())
            )
        return split_token_lines(tokens)


def flatten_groups(tokens: list[Token]) -> list[Token]:
    """Expand "group" tokens (a constant's own tokens) in place."""
    out: list[Token] = []
    for token in tokens:
        if token.kind == "group":
            out.extend(flatten_groups(token.arg or []))
        else:
            out.append(token)
    return out


def split_token_lines(tokens: list[Token]) -> list[list[Token]]:
    """Split tokens into lines at newlines in their text."""
    lines: list[list[Token]] = [[]]
    for token in tokens:
        if token.kind != TEXT or "\n" not in token.text:
            lines[-1].append(token)
            continue
        for index, piece in enumerate(token.text.split("\n")):
            if index:
                lines.append([])
            if piece:
                lines[-1].append(Token(TEXT, piece))
    return [line for line in lines if line]
