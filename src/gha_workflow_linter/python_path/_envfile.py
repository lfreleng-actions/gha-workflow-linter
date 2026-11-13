# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""PYTHONPATH values as tokens, and lines written to $GITHUB_ENV."""

from __future__ import annotations

from dataclasses import replace
import posixpath
import re
from typing import TYPE_CHECKING

from gha_workflow_linter.shell._tree import node_text as _node_text

from ._invocation import EXPR_CLOSE, EXPR_OPEN, expression_marker
from ._pythonpath import (
    SELF,
    TEXT,
    UNKNOWN,
    WORKDIR,
    WORKSPACE,
    Token,
    pythonpath_problems,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from tree_sitter import Node

    from ._words import Block, Word


# ${{ }} expressions as the reader swaps them.
EXPRESSION = re.compile(f"{EXPR_OPEN}[A-Z_]+{EXPR_CLOSE}")
# The text of a token standing for an expression.
EXPRESSION_TEXT = "${{ ... }}"
# The action path and runner.temp are absolute paths; any other
# expression is unresolved.
EXPRESSION_KINDS = {
    expression_marker("WORKSPACE"): WORKSPACE,
    expression_marker("PYTHONPATH"): SELF,
    expression_marker("ACTION_PATH"): UNKNOWN,
    expression_marker("TEMP"): UNKNOWN,
}
# Runner variables that always hold an absolute path.
ABSOLUTE_NAMES = frozenset(
    {"GITHUB_ACTION_PATH", "RUNNER_TEMP", "RUNNER_TOOL_CACHE", "HOME"}
    | {"pythonLocation"}
)
# An unusual spelling the scan does not decode: an unquoted backslash,
# an ANSI-C string, a printf conversion other than %s and %%, an
# escape other than \n in a printf format or echo -e.
SPELLING = "spelling"
# How a command names the env file.
ENV_FILE = ("$GITHUB_ENV", "${GITHUB_ENV}")
ENV_PREFIX = "written to GITHUB_ENV, so every later step gets it: "
PRINTF_CONVERSION = re.compile(r"(%%|%[-+ #0]*\d*(?:\.\d+)?[a-zA-Z])")
ESCAPE = re.compile(r"(\\.?)", re.S)


def forwards_stdin(name: str, args: list[str]) -> bool:
    """Whether ``cat`` or ``tee`` with ``args`` copies its standard input out.

    tee always does; cat when it has no file operand, or one of them
    is ``-``. A word the scan cannot read may be a file.
    """
    if name == "tee":
        return True
    operands: list[str] = []
    options = True
    for arg in args:
        if options and arg == "--":
            options = False
        elif not (options and arg.startswith("-") and arg != "-"):
            operands.append(arg)
    return name == "cat" and (not operands or "-" in operands)


def is_text_line(line: list[Token], text: str) -> bool:
    """True when a line is the one literal text ``text``."""
    return len(line) == 1 and line[0].kind == TEXT and line[0].text == text


class PythonpathChecks:
    """PYTHONPATH judgement, mixed into the block scan.

    Uses the scan's ``src``, ``block``, ``report``, ``skip_wrappers``
    and ``dash_before_heredoc``.
    """

    src: bytes
    block: Block
    report: Callable[..., None]
    skip_wrappers: Callable[[list[str], list[str]], int]
    dash_before_heredoc: Callable[[Node], bool]
    uv_env_lines: Callable[[Node, list[list[Token]]], None]
    uv_env_unread: Callable[[Node, list[str]], None]

    def check_pythonpath(
        self, value: Node, at: Node, prefix_self: bool
    ) -> None:
        """Judge ``PYTHONPATH=value`` (``+=`` when ``prefix_self``)."""
        tokens = self.pythonpath_tokens(value)
        if prefix_self:
            tokens = [Token(SELF, "$PYTHONPATH"), *tokens]
        self.judge_pythonpath(tokens, at, tilde=True)

    def check_pythonpath_word(
        self,
        node: Node,
        at: Node,
        declared: bool = False,
        tilde: bool = False,
    ) -> None:
        """Judge a ``PYTHONPATH=value`` word passed to env or export.

        A declaration (``export``) also reads ``PYTHONPATH+=value``,
        which appends to the inherited value. ``tilde`` marks a word
        the shell itself assigns (after ``time`` or ``coproc``), where
        it expands a leading ``~`` as in any assignment.
        """
        tokens = self.pythonpath_tokens(node)
        head = tokens[0].text if tokens and tokens[0].kind == TEXT else ""
        name = re.match(r"PYTHONPATH\+?=" if declared else "PYTHONPATH=", head)
        if name is None:
            self.report(
                at, "PPA009", "PYTHONPATH set from a value the scan cannot read"
            )
            return
        tokens[0] = Token(TEXT, head[name.end() :], tokens[0].op)
        if "+" in name[0]:
            tokens.insert(0, Token(SELF, "$PYTHONPATH"))
        self.judge_pythonpath(tokens, at, tilde=tilde)

    def judge_pythonpath(
        self,
        tokens: list[Token],
        at: Node,
        tilde: bool,
        prefix: str = "",
        swapped: bool = True,
    ) -> None:
        """Report what a PYTHONPATH value's tokens allow.

        ``swapped`` says the text holds the words that stand for
        ``${{ }}`` expressions in shell; a YAML value's tokens already
        carry them, and its text is only text.
        """
        if swapped:
            tokens = expression_tokens(tokens)
        if tilde:
            tokens = self.tilde_tokens(tokens)
        if any_unresolved(tokens):
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
        for position, token in enumerate(tokens):
            if (
                token.kind == TEXT
                and token.op == "unquoted"
                and "~" in token.text
            ):
                # A tilde prefix cut short by a quoted fragment
                # (~'root'/lib) is not expanded; bash keeps it as text.
                following = (
                    tokens[position + 1] if position + 1 < len(tokens) else None
                )
                ends_prefix = re.search(r"~[^/:]*$", token.text)
                interrupted = following is not None and not (
                    following.kind == TEXT and following.op == "unquoted"
                )
                if ends_prefix and interrupted:
                    out.append(token)
                    at_entry_start = False
                    continue
                pieces = token.text.split(":")
                for index, entry in enumerate(pieces):
                    if index:
                        out.append(Token(TEXT, ":"))
                    starts = at_entry_start or index > 0
                    if entry.startswith("~") and starts:
                        head, slash, rest = entry.partition("/")
                        # ~+ is $PWD, ~- is $OLDPWD and ~N, ~+N, ~-N
                        # name directory-stack entries: any may be it.
                        stack = re.fullmatch(r"~[+-]?\d*", head) and head != "~"
                        # ~ is $HOME; ~user is that user's home, or the
                        # literal text when no such user exists.
                        if stack:
                            kind = WORKDIR
                        elif head == "~":
                            kind = UNKNOWN
                        else:
                            kind = "unresolved"
                        out.append(Token(kind, head))
                        if slash:
                            out.append(Token(TEXT, slash + rest))
                    elif entry:
                        out.append(Token(TEXT, entry))
                at_entry_start = token.text.endswith(":")
                continue
            out.append(token)
            at_entry_start = token.kind == TEXT and token.text.endswith(":")
        return out

    def pythonpath_tokens(self, node: Node, quoted: bool = True) -> list[Token]:
        """Tokens of a PYTHONPATH value written as a shell word.

        A reference to PYTHONPATH (with its operator and operand) is a
        "self" token; $GITHUB_WORKSPACE, $PWD and $(pwd) name the
        workspace; a runner variable in ``ABSOLUTE_NAMES`` is "unknown"
        (some absolute path); any other expansion is "unresolved", and
        an unusual spelling is a "spelling" token. A command's argument
        is ``quoted`` False: an expansion outside double quotes, which
        may split or glob, has the op "unquoted".
        """
        t = node.type
        text = _node_text(self.src, node)
        if t in ("string", "concatenation"):
            out: list[Token] = []
            gap = node.start_byte
            for child in node.children:
                if t == "string" and child.start_byte > gap:
                    # Quoted text no child covers, such as a newline.
                    piece = self.src[gap : child.start_byte].decode(
                        "utf-8", "replace"
                    )
                    out.append(Token(TEXT, piece))
                gap = child.end_byte
                if child.type not in ('"', "'"):
                    out.extend(
                        self.pythonpath_tokens(child, quoted or t == "string")
                    )
            return out
        if t in ("simple_expansion", "expansion"):
            token = self.expansion_token(node)
            # A SELF token's op is its operator; a plain $PYTHONPATH
            # has none, and splits as any other reference.
            if not quoted and (token.kind != SELF or not token.op):
                token = replace(token, op="unquoted")
            return [token]
        if t == "command_substitution":
            prints_cwd = re.fullmatch(r"\$\(\s*pwd\s*\)|`\s*pwd\s*`", text)
            return [Token(WORKDIR if prints_cwd else "unresolved", text)]
        if t in ("word", "number") and "\\" in text or t == "ansi_c_string":
            return [Token(SPELLING, text)]
        literal: dict[str, Callable[[], Token]] = {
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
            return Token("unresolved", src)
        name = _node_text(self.src, named[0])
        op = anonymous[0].type if anonymous else ""
        if len(named) == 1 and not anonymous:
            return self.named_token(name, src)
        if name == "PYTHONPATH" and op in (":+", "+", ":-", "-", ":=", "="):
            operand = named[1] if len(named) > 1 else None
            arg = self.pythonpath_tokens(operand) if operand is not None else []
            return Token(SELF, "$PYTHONPATH", op, arg)
        # ${PYTHONPATH//x/}, ${x:-y}, ${x:+y}: a value the scan does
        # not follow.
        return Token("unresolved", src)

    @staticmethod
    def named_token(name: str, src: str) -> Token:
        """The token of a plain reference to ``name``."""
        fixed = {
            "PYTHONPATH": Token(SELF, "$PYTHONPATH"),
            "GITHUB_WORKSPACE": Token(WORKSPACE, src),
            "PWD": Token(WORKDIR, src),
        }
        if name in fixed:
            return fixed[name]
        return Token(UNKNOWN if name in ABSOLUTE_NAMES else "unresolved", src)

    def env_writes(
        self,
        node: Node,
        texts: list[str],
        origins: list[Word],
        redirects: list[Node],
        writes: bool,
    ) -> None:
        """PYTHONPATH lines a command writes to $GITHUB_ENV.

        From echo or printf whose output goes there, a heredoc or
        here-string into cat or tee, or a pipe into tee naming the
        file. ``texts`` and
        ``origins`` are the command's words.
        """
        start = self.skip_wrappers(texts, [w.source for w in origins])
        if start < 0 or start >= len(texts):
            return
        name = texts[start]
        name = "" if name.startswith("\x00") else posixpath.basename(name)
        tee = name == "tee" and any(
            w.source.strip('"') in ENV_FILE for w in origins[start + 1 :]
        )
        if not (writes or tee):
            return
        lines: list[list[Token]] = []
        if name in ("echo", "printf"):
            written = self.written_lines(node, name, list(origins[start + 1 :]))
            if written is None:
                return
            lines = written
        # A heredoc or here-string is standard input: only cat and tee
        # copy it out, and a program the scan cannot read might.
        args = texts[start + 1 :]
        if self.dash_before_heredoc(node):
            args = [*args, "-"]
        if not name or forwards_stdin(name, args):
            stdin = self.effective_stdin(node, redirects)
            if stdin is not None and stdin.type == "heredoc_redirect":
                lines.extend(self.heredoc_redirect_lines(stdin))
            elif stdin is not None and stdin.type == "herestring_redirect":
                lines.extend(self.herestring_lines(stdin))
        self.uv_env_lines(node, lines)
        self.judge_env_lines(node, lines)

    def effective_stdin(self, node: Node, redirects: list[Node]) -> Node | None:
        """The redirect that feeds standard input: the last one, in source order.

        A heredoc, a here-string or a ``<`` file; bash applies them in
        order, so a later one replaces an earlier one.
        """
        candidates = [
            c for c in node.children if c.type == "herestring_redirect"
        ]
        for redirect in redirects:
            candidates.append(redirect)
            # tree-sitter nests the redirects written after a heredoc's
            # operator, on the same line, inside the heredoc node.
            candidates.extend(
                c for c in redirect.children if c.type == "file_redirect"
            )
        feeding: Node | None = None
        for redirect in sorted(candidates, key=lambda n: n.start_byte):
            if redirect.type in ("heredoc_redirect", "herestring_redirect"):
                feeding = redirect
            elif redirect.type == "file_redirect":
                op = _node_text(self.src, redirect.children[0])
                if op in ("<", "0<", "<>", "0<>"):
                    feeding = redirect
        return feeding

    def written_lines(
        self, node: Node, name: str, args: list[Word]
    ) -> list[list[Token]] | None:
        """The lines echo or printf writes, as tokens; None if unreadable.

        Only ``\\n`` escapes and ``%s``/``%%`` conversions are read;
        any other is a "spelling" token.
        """
        if name == "echo":
            escapes = False
            while (
                args
                and args[0].literal
                and re.fullmatch(r"-[neE]+", args[0].text or "")
            ):
                for letter in (args.pop(0).text or "")[1:]:
                    escapes = {"e": True, "E": False}.get(letter, escapes)
            joined: list[Token] = []
            for index, word in enumerate(args):
                if index:
                    joined.append(Token(TEXT, " "))
                joined.extend(self.pythonpath_tokens(word.node, False))
            return split_token_lines(unescape(joined) if escapes else joined)
        if args and args[0].literal and args[0].text == "--":
            args = args[1:]
        if not args:
            return []
        if not args[0].literal:
            if any("PYTHONPATH" in word.source for word in args):
                self.report(
                    node,
                    "PPA009",
                    ENV_PREFIX + "printf format the scan cannot read",
                )
            self.uv_env_unread(node, [word.source for word in args])
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
                    value = values.pop(0) if values else None
                    if piece != "%s":
                        # The conversion changes the operand in ways the
                        # scan does not read; the text it carries stays.
                        out.append(Token(SPELLING, piece))
                    if value is not None:
                        out.extend(self.pythonpath_tokens(value.node, False))
                elif "%" in piece:
                    out.append(Token(SPELLING, piece))
                elif piece:
                    out.extend(unescape([Token(TEXT, piece)]))
            if not values or used == 0:
                return split_token_lines(out)

    def herestring_lines(self, redirect: Node) -> list[list[Token]]:
        """A here-string's operand as lines of tokens."""
        tokens: list[Token] = []
        for operand in redirect.children:
            if operand.is_named:
                tokens.extend(self.pythonpath_tokens(operand))
        return split_token_lines(tokens)

    def heredoc_redirect_lines(self, redirect: Node) -> list[list[Token]]:
        """A heredoc's body as lines of tokens; a quoted one is all text."""
        quoted = any(
            c.type == "heredoc_start"
            and _node_text(self.src, c).startswith(("'", '"'))
            for c in redirect.children
        )
        strip_tabs = any(c.type == "<<-" for c in redirect.children)
        lines: list[list[Token]] = []
        for child in redirect.children:
            if child.type != "heredoc_body":
                continue
            if quoted:
                body = _node_text(self.src, child)
                lines.extend([Token(TEXT, ln)] for ln in body.split("\n"))
            else:
                lines.extend(self.heredoc_lines(child))
        if strip_tabs:
            lines = [strip_leading_tabs(line) for line in lines]
        return lines

    def judge_env_lines(self, node: Node, lines: list[list[Token]]) -> None:
        """Judge each PYTHONPATH line or record written; skip other records."""
        # An expression at a line's start could write any name.
        lines = [merge_text(expression_tokens(line)) for line in lines]
        i = 0
        while i < len(lines):
            line = lines[i]
            i += 1
            head = line[0].text if line and line[0].kind == TEXT else ""
            # The runner reads NAME=value when "=" comes before "<<".
            record = (
                re.match(r"^([^=]+?)<<(.+)$", head) if len(line) == 1 else None
            )
            if len(line) > 1 and re.match(r"^PYTHONPATH<<", head):
                self.report(
                    node,
                    "PPA009",
                    ENV_PREFIX
                    + "a PYTHONPATH record has a delimiter the scan cannot read",
                )
                return
            if record:
                end = i
                while end < len(lines) and not is_text_line(
                    lines[end], record.group(2)
                ):
                    end += 1
                if record.group(1) != "PYTHONPATH":
                    # Another variable's value, whatever it holds.
                    i = end + 1
                    continue
                if end == len(lines):
                    self.report(
                        node,
                        "PPA009",
                        ENV_PREFIX
                        + "a PYTHONPATH record goes on past this command",
                    )
                    return
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
            elif may_name_pythonpath(line) or (
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
        # An unescaped backslash before a newline joins the lines, as
        # in a double-quoted string.
        joined = [
            Token(
                t.kind,
                re.sub(r"(?<!\\)((?:\\\\)*)\\\n", r"\1", t.text)
                if t.kind == TEXT
                else t.text,
                t.op,
                t.arg,
            )
            for t in tokens
        ]
        return split_token_lines(joined)


def any_unresolved(tokens: list[Token]) -> bool:
    """Whether a token, or one in an operand, cannot be read."""
    return any(
        t.kind in ("unresolved", SPELLING) or any_unresolved(t.arg or [])
        for t in tokens
    )


def may_name_pythonpath(line: list[Token]) -> bool:
    """Whether a line with an unusual spelling or unread name could set PYTHONPATH.

    The text before the first spelling or unresolved token could still
    begin ``PYTHONPATH``, or already does. A line opened by a shell
    expansion (``echo "$line"``) counts only when its text mentions
    PYTHONPATH (DESIGN.md, Known limits); one opened by a ``${{ }}``
    expression always does.
    """
    head = ""
    for token in line:
        opens = token.kind == "unresolved" and not head
        if opens and token.text != EXPRESSION_TEXT:
            return any("PYTHONPATH" in t.text for t in line)
        if token.kind in (SPELLING, "unresolved"):
            # The spelling may decode to a newline (\x0a, \012, \u000a),
            # putting later text on a line of its own.
            later = "".join(t.text for t in line[line.index(token) + 1 :])
            return (
                "PYTHONPATH".startswith(head)
                or head.startswith("PYTHONPATH")
                or "PYTHONPATH" in later
            )
        head += token.text
    return False


def expression_tokens(tokens: list[Token]) -> list[Token]:
    """Text holding ``${{ }}`` expressions split into their own tokens.

    ``env.PYTHONPATH`` is PYTHONPATH itself and ``github.workspace``
    the workspace, as in a YAML ``env:`` value; the action path and
    ``runner.temp`` are absolute paths; any other is unresolved.
    """
    out: list[Token] = []
    for token in tokens:
        if token.kind != TEXT or not EXPRESSION.search(token.text):
            out.append(
                replace(token, arg=expression_tokens(token.arg))
                if token.arg
                else token
            )
            continue
        position = 0
        for match in EXPRESSION.finditer(token.text):
            if match.start() > position:
                piece = token.text[position : match.start()]
                out.append(Token(TEXT, piece, token.op))
            kind = EXPRESSION_KINDS.get(match.group(0), "unresolved")
            out.append(Token(kind, EXPRESSION_TEXT))
            position = match.end()
        if position < len(token.text):
            out.append(Token(TEXT, token.text[position:], token.op))
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
    # Blank lines stay: inside a NAME<<DELIMITER record they are part
    # of the value.
    return [merge_text(line) for line in lines]


def merge_text(line: list[Token]) -> list[Token]:
    """Join neighbouring text tokens, as printf's fields join on output."""
    out: list[Token] = []
    for token in line:
        if out and token.kind == TEXT and out[-1].kind == TEXT:
            out[-1] = Token(TEXT, out[-1].text + token.text)
        else:
            out.append(token)
    return out


def unescape(tokens: list[Token]) -> list[Token]:
    """Text with ``\\n`` escapes applied, as ``echo -e`` and printf do.

    Any other escape is a "spelling" token, not decoded.
    """
    out: list[Token] = []
    for token in tokens:
        if token.kind != TEXT or "\\" not in token.text:
            out.append(token)
            continue
        for piece in ESCAPE.split(token.text):
            if piece == "\\n":
                out.append(Token(TEXT, "\n", token.op))
            elif piece.startswith("\\"):
                out.append(Token(SPELLING, piece))
            elif piece:
                out.append(Token(TEXT, piece, token.op))
    return out


def strip_leading_tabs(line: list[Token]) -> list[Token]:
    """A ``<<-`` heredoc line without its leading tabs."""
    if line and line[0].kind == TEXT:
        rest = line[0].text.lstrip("\t")
        return ([Token(TEXT, rest)] if rest else []) + line[1:]
    return line
