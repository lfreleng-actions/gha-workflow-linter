# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Shell parsing for the Python import-path scan.

A recursive-descent parser for the bash that ``run:`` steps and shell
scripts are written in. It keeps what the scan needs: words with their
quoting, parameter expansions, command and process substitutions,
assignments, redirections, heredocs, and the compound commands that
decide which shell a command runs in (subshells, groups, ``if``,
``case``, loops and functions).

Heredoc bodies are read from the line after the one that opens them,
wherever the opening operator sits: a heredoc started inside ``$( )``
within double quotes has its body read before the quote resumes.

The parser does not reject bad syntax. Text it cannot make sense of is
skipped a character at a time, so badly broken shell may be read
differently from how bash would reject it. Only nesting deeper than a
fixed limit stops it, with a ValueError, so a crafted file cannot
exhaust the interpreter's stack.

GitHub expressions (``${{ }}``) are replaced before the shell runs,
whatever the quoting around them. ``_yaml`` swaps each for a marker,
which the parser reads as an :class:`Expr` part in any context.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import re
from typing import TYPE_CHECKING, TypeAlias

if TYPE_CHECKING:
    from collections.abc import Iterator

MARK_OPEN = "\ue000"
MARK_CLOSE = "\ue001"
METACHARS = frozenset(" \t\r\n;&|<>()")
PLAIN = re.compile(r"[^\s;&|<>()'\"\\$`\ue000]+")
NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
ASSIGNMENT = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)(\[[^\]]*\])?(\+?)=")
FUNCTION_PARENS = re.compile(r"[ \t]*\([ \t]*\)")
REDIRECT = re.compile(
    r"(\{[A-Za-z_][A-Za-z0-9_]*\}|\d*)(&>>|&>|<<<|<<-|<<|<>|<&|>>|>&|>\||<|>)"
)
# Longest first, so ":-" is not read as ":" and "##" not as "#".
PARAM_OPS = (
    ":-",
    ":=",
    ":+",
    ":?",
    "-",
    "=",
    "+",
    "?",
    "##",
    "#",
    "%%",
    "%",
    "//",
    "/#",
    "/%",
    "/",
    "^^",
    "^",
    ",,",
    ",",
    ":",
    "@",
)
SPECIAL_PARAMS = "@*#?-$!0123456789"
TEST_OPERATORS = ("&&", "||", "=~", "<", ">", "(", ")", "!")
DECLARATIONS = frozenset({"declare", "typeset", "local", "readonly", "export"})
ANSI_ESCAPES = {
    "n": "\n",
    "t": "\t",
    "r": "\r",
    "e": "\x1b",
    "\\": "\\",
    "'": "'",
    '"': '"',
}
# How deeply commands and expansions may nest. Real scripts stay well
# under it; it keeps a crafted file from exhausting the stack, both
# here and in the walk over the parsed text.
MAX_DEPTH = 32


@dataclass
class Lit:
    """Literal text; ``quoted`` when it came from quotes or an escape."""

    text: str
    quoted: bool = False


@dataclass
class Param:
    """A parameter expansion, ``$name`` or ``${...}``.

    ``fixed`` is set on a reference kept in a stored value: the place
    it named when the value was stored (base and depth) and what it
    was as a PYTHONPATH entry, so a later change to the variable does
    not change how the value is judged.
    """

    name: str
    quoted: bool = False
    op: str = ""
    arg: Word | None = None
    index: str = ""
    prefix: str = ""
    fixed: tuple[str, int, str] | None = None


@dataclass(eq=False)
class Sub:
    """A command substitution; a process substitution when ``process``.

    Compared by identity, so the walk can key what it learns by it.
    """

    body: list[AndOr]
    quoted: bool = False
    process: bool = False


@dataclass
class Arith:
    """An arithmetic expansion: only the substitutions in it run."""

    subs: list[Sub]


@dataclass
class Expr:
    """A GitHub expression, which reaches the shell as literal text."""

    kind: str
    index: int


Part: TypeAlias = "Lit | Param | Sub | Arith | Expr"


@dataclass
class Word:
    """One shell word: its parts, and where it sits in the text."""

    parts: list[Part]
    start: int = 0
    end: int = 0

    def literal(self) -> str | None:
        """The word's text when every part is literal, else None."""
        texts: list[str] = []
        for part in self.parts:
            if not isinstance(part, Lit):
                return None
            texts.append(part.text)
        return "".join(texts)

    def plain(self) -> str | None:
        """The text of an unquoted, all-literal word: a keyword candidate."""
        texts: list[str] = []
        for part in self.parts:
            if not isinstance(part, Lit) or part.quoted:
                return None
            texts.append(part.text)
        return "".join(texts) if texts else None


@dataclass
class Heredoc:
    """A heredoc's body; ``word`` holds it when the shell expands it.

    ``strip`` marks ``<<-``, which removes leading tabs from each line.
    """

    quoted: bool
    body: str = ""
    start: int = 0
    word: Word | None = None
    strip: bool = False


@dataclass
class Redirect:
    """One redirection: operator, optional descriptor, target."""

    op: str
    fd: str = ""
    target: Word | None = None
    heredoc: Heredoc | None = None


@dataclass
class Assign:
    """``name=value``, ``name+=value``, ``name[index]=value`` or ``name=(words)``."""

    name: str
    value: Word | None = None
    array: list[Word] | None = None
    append: bool = False
    start: int = 0
    index: str | None = None


@dataclass
class Simple:
    """A simple command: assignments, words and redirections.

    ``declared`` holds the assignments given as arguments to a
    declaration builtin (``export``, ``local``, ``declare`` and the
    like), which the shell also performs.
    """

    assigns: list[Assign]
    words: list[Word]
    redirects: list[Redirect]
    declared: list[Assign] = field(default_factory=list)
    start: int = 0
    end: int = 0


@dataclass
class Group:
    """``( list )`` when ``subshell``, else ``{ list; }``."""

    body: list[AndOr]
    subshell: bool
    redirects: list[Redirect] = field(default_factory=list)
    start: int = 0
    end: int = 0


@dataclass
class If:
    """``if``/``elif`` conditions with their bodies, and any ``else``."""

    branches: list[tuple[list[AndOr], list[AndOr]]]
    otherwise: list[AndOr] | None
    redirects: list[Redirect] = field(default_factory=list)
    start: int = 0
    end: int = 0


@dataclass
class Loop:
    """``for``/``select`` over words, or ``while``/``until`` a condition.

    ``arith`` holds the expressions of a ``for ((...))`` loop.
    """

    keyword: str
    name: str
    items: list[Word] | None
    condition: list[AndOr]
    body: list[AndOr]
    redirects: list[Redirect] = field(default_factory=list)
    start: int = 0
    end: int = 0
    arith: list[Word] = field(default_factory=list)


@dataclass
class Case:
    """``case word in`` with its arms: patterns, body and terminator.

    The terminator is ``;;``, or ``;&`` (run the next arm's body too)
    or ``;;&`` (go on testing the next arms' patterns).
    """

    word: Word
    arms: list[tuple[list[Word], list[AndOr], str]]
    redirects: list[Redirect] = field(default_factory=list)
    start: int = 0
    end: int = 0


@dataclass
class Function:
    """A function definition; its body runs only when it is called."""

    name: str
    body: Command
    start: int = 0
    end: int = 0


@dataclass
class Test:
    """``[[ ... ]]`` or ``(( ... ))``: words that are not a command."""

    words: list[Word]
    redirects: list[Redirect] = field(default_factory=list)
    start: int = 0
    end: int = 0


Command: TypeAlias = "Simple | Group | If | Loop | Case | Function | Test"


@dataclass
class Pipeline:
    """Commands joined by ``|``; with two or more, each runs in a subshell.

    ``negated`` marks a leading ``!``, which inverts the status.
    """

    commands: list[Command]
    negated: bool = False


@dataclass
class AndOr:
    """Pipelines joined by ``&&``/``||``; ``background`` when ended by ``&``."""

    pipelines: list[Pipeline]
    operators: list[str] = field(default_factory=list)
    background: bool = False


def parse(text: str, base: int = 0, depth: int = 0) -> list[AndOr]:
    """Parse shell text into its command lists."""
    parser = _Parser(text, base, depth)
    items: list[AndOr] = []
    while parser.pos < len(parser.text):
        items.extend(parser.parse_list())
        if parser.pos < len(parser.text):
            parser.pos += 1
    return items


def expandable_word(text: str, base: int = 0, depth: int = 0) -> Word:
    """Read text the shell expands without splitting it into words.

    That is how a heredoc body with an unquoted delimiter is read: only
    backslash, ``$`` and backquotes are special, and quotes are literal.
    """
    parser = _Parser(text, base, depth)
    parts: list[Part] = []
    buffer: list[str] = []
    while parser.pos < len(text):
        char = text[parser.pos]
        if char == "\\" and parser.next_in("$`\\\n"):
            if parser.peek(1) != "\n":
                buffer.append(parser.peek(1))
            parser.pos += 2
        elif char in "$`" or char == MARK_OPEN:
            _flush(buffer, parts, quoted=True)
            parts.append(parser.expansion(quoted=True))
        else:
            buffer.append(char)
            parser.pos += 1
    _flush(buffer, parts, quoted=True)
    return Word(parts, base, base + len(text))


def word_subs(word: Word) -> Iterator[Sub]:
    """Every command or process substitution in a word, in order."""
    for part in word.parts:
        if isinstance(part, Sub):
            yield part
        elif isinstance(part, Arith):
            yield from part.subs
        elif isinstance(part, Param) and part.arg is not None:
            yield from word_subs(part.arg)


def declares(words: list[Word]) -> bool:
    """True when a command's words so far start a declaration builtin.

    The name is read after quote removal, and may follow ``builtin``
    or ``command``.
    """
    names = [word.literal() for word in words[:2]]
    if names[0] in ("builtin", "command") and len(names) > 1:
        return names[1] in DECLARATIONS
    return names[0] in DECLARATIONS


def heredoc_delimiter(word: Word | None) -> tuple[str, bool]:
    """A heredoc's delimiter, and whether quoting stops body expansion."""
    if word is None:
        return "", True
    text: list[str] = []
    quoted = False
    for part in word.parts:
        if isinstance(part, Lit):
            text.append(part.text)
            quoted = quoted or part.quoted
        elif isinstance(part, Param):
            text.append("$" + part.name)
    return "".join(text), quoted


def _flush(buffer: list[str], parts: list[Part], quoted: bool) -> None:
    if buffer:
        parts.append(Lit("".join(buffer), quoted))
        buffer.clear()


class _Parser:
    """The parser's position in one text, and heredocs awaiting a body."""

    def __init__(self, text: str, base: int = 0, depth: int = 0) -> None:
        self.text = text
        self.pos = 0
        self.base = base
        self.depth = depth
        self.pending: list[tuple[Heredoc, str, bool]] = []

    def peek(self, ahead: int = 0) -> str:
        index = self.pos + ahead
        return self.text[index] if index < len(self.text) else ""

    def next_in(self, chars: str) -> bool:
        """True when the character after the current one is in ``chars``."""
        char = self.peek(1)
        return bool(char) and char in chars

    def at(self, prefix: str) -> bool:
        return self.text.startswith(prefix, self.pos)

    def offset(self) -> int:
        return self.base + self.pos

    def peek_plain(self) -> str:
        """The next word when it is plain text, without consuming it."""
        match = PLAIN.match(self.text, self.pos)
        if not match:
            return ""
        end = match.end()
        if end < len(self.text) and self.text[end] not in METACHARS:
            return ""
        return match.group()

    def take(self, word: str) -> bool:
        """Consume ``word`` when it is the next plain word."""
        if self.peek_plain() == word:
            self.pos += len(word)
            return True
        return False

    def skip_blanks(self) -> None:
        while self.pos < len(self.text):
            if self.text[self.pos] in " \t\r":
                self.pos += 1
            elif self.at("\\\n"):
                self.pos += 2
            else:
                break

    def skip_separators(self) -> None:
        """Skip blanks, comments and newlines, reading heredoc bodies."""
        while True:
            self.skip_blanks()
            if self.peek() == "#":
                end = self.text.find("\n", self.pos)
                self.pos = len(self.text) if end < 0 else end
            if self.peek() != "\n":
                return
            self.newline()

    def newline(self) -> None:
        """Consume a newline, then the heredoc bodies its line opened."""
        self.pos += 1
        while self.pending:
            heredoc, delimiter, strip = self.pending.pop(0)
            self.read_heredoc(heredoc, delimiter, strip)

    def read_heredoc(
        self, heredoc: Heredoc, delimiter: str, strip: bool
    ) -> None:
        start = self.pos
        body_end = len(self.text)
        while self.pos < len(self.text):
            end = self.text.find("\n", self.pos)
            end = len(self.text) if end < 0 else end
            line = self.text[self.pos : end]
            self.pos = min(end + 1, len(self.text))
            if (line.lstrip("\t") if strip else line) == delimiter:
                body_end = end - len(line)
                break
        heredoc.body = self.text[start:body_end]
        heredoc.start = self.base + start
        if not heredoc.quoted:
            heredoc.word = expandable_word(
                heredoc.body, heredoc.start, self.depth + 1
            )

    def parse_list(
        self, stops: frozenset[str] = frozenset(), close: bool = False
    ) -> list[AndOr]:
        """Commands up to a stop word, ``)`` when ``close``, or the end."""
        items: list[AndOr] = []
        self.depth += 1
        if self.depth > MAX_DEPTH:
            raise ValueError("shell commands nested too deeply")
        while True:
            self.skip_separators()
            if self.pos >= len(self.text) or (close and self.peek() == ")"):
                break
            if self.at(";;") or self.at(";&") or self.peek_plain() in stops:
                break
            before = self.pos
            items.append(self.and_or())
            self.skip_blanks()
            if self.peek() == "&" and not self.at("&&"):
                items[-1].background = True
                self.pos += 1
            elif self.peek() == ";" and not (self.at(";;") or self.at(";&")):
                self.pos += 1
            if self.pos == before:
                self.pos += 1
        self.depth -= 1
        return items

    def and_or(self) -> AndOr:
        item = AndOr([self.pipeline()])
        while True:
            self.skip_blanks()
            if not (self.at("&&") or self.at("||")):
                return item
            item.operators.append(self.text[self.pos : self.pos + 2])
            self.pos += 2
            self.skip_separators()
            item.pipelines.append(self.pipeline())

    def pipeline(self) -> Pipeline:
        self.skip_blanks()
        negated = False
        while True:
            if self.take("!"):
                negated = not negated
            elif self.take("time"):
                self.skip_blanks()
                self.take("-p")
            else:
                break
            self.skip_blanks()
        commands = [self.command()]
        while True:
            self.skip_blanks()
            if self.at("||") or not self.at("|"):
                return Pipeline(commands, negated)
            self.pos += 2 if self.at("|&") else 1
            self.skip_separators()
            commands.append(self.command())

    def command(self) -> Command:
        self.skip_blanks()
        start = self.offset()
        if self.at("(("):
            return self.arith_command(start)
        if self.peek() == "(":
            self.pos += 1
            body = self.parse_list(close=True)
            self.pos += 1 if self.peek() == ")" else 0
            return self.finish(Group(body, subshell=True, start=start))
        compound = {
            "{": self.group,
            "if": self.if_command,
            "while": self.loop,
            "until": self.loop,
            "for": self.loop,
            "select": self.loop,
            "case": self.case,
            "[[": self.test,
            "function": self.function,
        }.get(self.peek_plain())
        if compound is not None:
            return compound(start)
        return self.simple(start)

    def finish(self, command: Group | If | Loop | Case | Test) -> Command:
        """Attach trailing redirections and the end offset."""
        while True:
            self.skip_blanks()
            redirect = self.redirect()
            if redirect is None:
                break
            command.redirects.append(redirect)
        command.end = self.offset()
        return command

    def group(self, start: int) -> Command:
        self.take("{")
        body = self.parse_list(frozenset({"}"}))
        self.take("}")
        return self.finish(Group(body, subshell=False, start=start))

    def if_command(self, start: int) -> Command:
        self.take("if")
        branches: list[tuple[list[AndOr], list[AndOr]]] = []
        otherwise: list[AndOr] | None = None
        while True:
            condition = self.parse_list(frozenset({"then"}))
            self.take("then")
            body = self.parse_list(frozenset({"elif", "else", "fi"}))
            branches.append((condition, body))
            if self.take("elif"):
                continue
            if self.take("else"):
                otherwise = self.parse_list(frozenset({"fi"}))
            self.take("fi")
            return self.finish(If(branches, otherwise, start=start))

    def loop(self, start: int) -> Command:
        keyword = self.peek_plain()
        self.take(keyword)
        self.skip_blanks()
        name = ""
        items: list[Word] | None = None
        condition: list[AndOr] = []
        arith: list[Word] = []
        if keyword in ("while", "until"):
            condition = self.parse_list(frozenset({"do"}))
        elif self.at("(("):
            self.pos += 2
            arith = [Word([Arith(self.arith_body())], self.offset())]
        else:
            name, items = self.loop_items()
        self.skip_separators()
        if self.peek() == ";":
            self.pos += 1
            self.skip_separators()
        self.take("do")
        body = self.parse_list(frozenset({"done"}))
        self.take("done")
        return self.finish(
            Loop(
                keyword, name, items, condition, body, start=start, arith=arith
            )
        )

    def loop_items(self) -> tuple[str, list[Word] | None]:
        """A ``for`` loop's variable, and its words when ``in`` is given."""
        word = self.read_word()
        name = (word.literal() or "") if word else ""
        self.skip_separators()
        if not self.take("in"):
            return name, None
        items: list[Word] = []
        while True:
            self.skip_blanks()
            if self.pos >= len(self.text) or self.peek() in ";\n#":
                return name, items
            item = self.read_word()
            if item is None:
                return name, items
            items.append(item)

    def case(self, start: int) -> Command:
        self.take("case")
        self.skip_blanks()
        subject = self.read_word() or Word([])
        self.skip_separators()
        self.take("in")
        arms: list[tuple[list[Word], list[AndOr], str]] = []
        while True:
            self.skip_separators()
            if self.pos >= len(self.text) or self.take("esac"):
                break
            before = self.pos
            patterns = self.case_patterns()
            body = self.parse_list(frozenset({"esac"}))
            terminator = ";;"
            for candidate in (";;&", ";;", ";&"):
                if self.at(candidate):
                    self.pos += len(candidate)
                    terminator = candidate
                    break
            arms.append((patterns, body, terminator))
            if self.pos == before:
                self.pos += 1
        return self.finish(Case(subject, arms, start=start))

    def case_patterns(self) -> list[Word]:
        patterns: list[Word] = []
        if self.peek() == "(":
            self.pos += 1
        while self.pos < len(self.text):
            self.skip_blanks()
            pattern = self.read_word()
            if pattern is not None:
                patterns.append(pattern)
            self.skip_blanks()
            if self.peek() == "|":
                self.pos += 1
            elif self.peek() == ")":
                self.pos += 1
                break
            elif pattern is None:
                break
        return patterns

    def test(self, start: int) -> Command:
        self.take("[[")
        words: list[Word] = []
        while self.pos < len(self.text):
            self.skip_blanks()
            if self.take("]]") or self.peek() in ("\n", ""):
                break
            operator = next((op for op in TEST_OPERATORS if self.at(op)), None)
            if operator is not None:
                words.append(Word([Lit(operator)], self.offset()))
                self.pos += len(operator)
                continue
            word = self.read_word()
            if word is None:
                self.pos += 1
                continue
            words.append(word)
        return self.finish(Test(words, start=start))

    def arith_command(self, start: int) -> Command:
        self.pos += 2
        subs = self.arith_body()
        return self.finish(Test([Word([Arith(subs)], start)], start=start))

    def arith_body(self) -> list[Sub]:
        """Read to the closing ``))``; return the substitutions inside."""
        begin = self.pos
        depth = 0
        end = len(self.text)
        while self.pos < len(self.text):
            char = self.text[self.pos]
            if char == "(":
                depth += 1
            elif char == ")" and depth:
                depth -= 1
            elif char == ")":
                end = self.pos
                self.pos += 2 if self.at("))") else 1
                break
            self.pos += 1
        inner = expandable_word(
            self.text[begin:end], self.base + begin, self.depth + 1
        )
        return list(word_subs(inner))

    def function(self, start: int) -> Command:
        self.take("function")
        self.skip_blanks()
        word = self.read_word()
        name = (word.literal() or "") if word else ""
        match = FUNCTION_PARENS.match(self.text, self.pos)
        if match:
            self.pos = match.end()
        return self.function_body(name, start)

    def function_body(self, name: str, start: int) -> Command:
        self.skip_separators()
        body = self.command()
        return Function(name, body, start, self.offset())

    def simple(self, start: int) -> Command:
        command = Simple([], [], [], start=start)
        while self.pos < len(self.text):
            self.skip_blanks()
            if self.peek() == "#":
                break
            process = self.at("<(") or self.at(">(")
            redirect = None if process else self.redirect()
            if redirect is not None:
                command.redirects.append(redirect)
                continue
            if not self.peek() or (self.peek() in METACHARS and not process):
                break
            word = self.read_word()
            if word is None:
                break
            if self.add_word(command, word):
                return self.function_body(word.literal() or "", start)
        command.end = self.offset()
        return command

    def add_word(self, command: Simple, word: Word) -> bool:
        """Add a word to a simple command; True when it names a function."""
        words = command.words
        if words and not declares(words):
            words.append(word)
            return False
        assign = self.assignment(word, declared=bool(words))
        if assign is not None and words:
            command.declared.append(assign)
            words.append(word)
        elif assign is not None:
            command.assigns.append(assign)
        elif not command.assigns and not words and word.plain():
            match = FUNCTION_PARENS.match(self.text, self.pos)
            if match:
                self.pos = match.end()
                return True
            words.append(word)
        else:
            words.append(word)
        return False

    def assignment(self, word: Word, declared: bool = False) -> Assign | None:
        """Read ``NAME=value`` from a word, if it is one.

        A prefix assignment needs an unquoted name. A declaration
        builtin (``export``, ``local``...) sees its operands after
        quote removal, so ``export "NAME=value"`` assigns too.
        """
        first = word.parts[0] if word.parts else None
        if not isinstance(first, Lit) or (first.quoted and not declared):
            return None
        match = ASSIGNMENT.match(first.text)
        if not match:
            return None
        append = match.group(3) == "+"
        index = match.group(2)[1:-1] if match.group(2) else None
        rest = first.text[match.end() :]
        parts: list[Part] = [Lit(rest, first.quoted)] if rest else []
        parts.extend(word.parts[1:])
        if not parts and self.peek() == "(" and index is None:
            return Assign(
                match.group(1), None, self.array_words(), append, word.start
            )
        value = Word(parts, word.start + match.end(), word.end)
        return Assign(match.group(1), value, None, append, word.start, index)

    def array_words(self) -> list[Word]:
        self.pos += 1
        words: list[Word] = []
        while self.pos < len(self.text):
            self.skip_separators()
            if self.peek() == ")":
                self.pos += 1
                break
            word = self.read_word()
            if word is None:
                self.pos += 1
            else:
                words.append(word)
        return words

    def redirect(self) -> Redirect | None:
        match = REDIRECT.match(self.text, self.pos)
        if not match:
            return None
        descriptor, op = match.group(1), match.group(2)
        self.pos = match.end()
        self.skip_blanks()
        target = self.read_word()
        if op not in ("<<", "<<-"):
            return Redirect(op, descriptor, target)
        delimiter, quoted = heredoc_delimiter(target)
        heredoc = Heredoc(quoted, strip=op == "<<-")
        self.pending.append((heredoc, delimiter, op == "<<-"))
        return Redirect(op, descriptor, target, heredoc)

    def read_word(self) -> Word | None:
        """Read one word, or return None at a metacharacter or the end."""
        start = self.pos
        parts: list[Part] = []
        buffer: list[str] = []
        while self.pos < len(self.text):
            char = self.text[self.pos]
            if char in "<>" and self.peek(1) == "(":
                _flush(buffer, parts, quoted=False)
                parts.append(self.process_substitution())
            elif char in METACHARS:
                break
            elif char == "\\":
                _flush(buffer, parts, quoted=False)
                if self.peek(1) and self.peek(1) != "\n":
                    parts.append(Lit(self.peek(1), quoted=True))
                self.pos += 2
            elif char in "'\"" or (char == "$" and self.next_in("'\"")):
                _flush(buffer, parts, quoted=False)
                parts.extend(self.quoted())
            elif char in "$`" or char == MARK_OPEN:
                _flush(buffer, parts, quoted=False)
                parts.append(self.expansion(quoted=False))
            else:
                buffer.append(char)
                self.pos += 1
        _flush(buffer, parts, quoted=False)
        if self.pos == start:
            return None
        return Word(parts, self.base + start, self.offset())

    def process_substitution(self) -> Sub:
        self.pos += 2
        body = self.parse_list(close=True)
        self.pos += 1 if self.peek() == ")" else 0
        return Sub(body, process=True)

    def quoted(self) -> list[Part]:
        """``'...'``, ``"..."``, ``$'...'`` or ``$"..."``."""
        if self.at('"') or self.at('$"'):
            self.pos += 1 if self.at('"') else 2
            return self.double_quoted()
        ansi = self.at("$'")
        self.pos += 2 if ansi else 1
        parts: list[Part] = []
        buffer: list[str] = []
        while self.pos < len(self.text):
            char = self.text[self.pos]
            if char == "'":
                self.pos += 1
                break
            if char == MARK_OPEN:
                _flush(buffer, parts, quoted=True)
                parts.append(self.marker())
                continue
            if ansi and char == "\\" and self.peek(1):
                buffer.append(ANSI_ESCAPES.get(self.peek(1), self.peek(1)))
                self.pos += 2
                continue
            buffer.append(char)
            self.pos += 1
        _flush(buffer, parts, quoted=True)
        return parts or [Lit("", quoted=True)]

    def double_quoted(self) -> list[Part]:
        """The rest of a double-quoted string, its opening quote consumed."""
        parts: list[Part] = []
        buffer: list[str] = []
        while self.pos < len(self.text):
            char = self.text[self.pos]
            if char == '"':
                self.pos += 1
                break
            if char == "\\" and self.next_in('$`"\\\n'):
                if self.peek(1) != "\n":
                    buffer.append(self.peek(1))
                self.pos += 2
            elif char in "$`" or char == MARK_OPEN:
                _flush(buffer, parts, quoted=True)
                parts.append(self.expansion(quoted=True))
            else:
                buffer.append(char)
                self.pos += 1
        _flush(buffer, parts, quoted=True)
        return parts or [Lit("", quoted=True)]

    def expansion(self, quoted: bool) -> Part:
        """The expansion at ``$``, a backquote, or an expression marker."""
        if self.peek() == "`":
            return self.backquote(quoted)
        if self.peek() == MARK_OPEN:
            return self.marker()
        if self.at("$(("):
            self.pos += 3
            return Arith(self.arith_body())
        if self.at("$("):
            self.pos += 2
            body = self.parse_list(close=True)
            self.pos += 1 if self.peek() == ")" else 0
            return Sub(body, quoted)
        if self.at("${"):
            return self.braced(quoted)
        return self.simple_parameter(quoted)

    def simple_parameter(self, quoted: bool) -> Part:
        """``$name`` or a special parameter such as ``$0``; else a lone ``$``."""
        match = NAME.match(self.text, self.pos + 1)
        if match:
            self.pos = match.end()
            return Param(match.group(), quoted)
        if self.next_in(SPECIAL_PARAMS):
            self.pos += 2
            return Param(self.text[self.pos - 1], quoted)
        self.pos += 1
        return Lit("$", quoted)

    def braced(self, quoted: bool) -> Part:
        self.depth += 1
        if self.depth > MAX_DEPTH:
            raise ValueError("shell expansions nested too deeply")
        part = self.braced_parameter(quoted)
        self.depth -= 1
        return part

    def braced_parameter(self, quoted: bool) -> Part:
        """``${...}``: prefix, name, subscript, operator and operand."""
        self.pos += 2
        prefix = ""
        if self.peek() in ("#", "!") and self.peek(1) not in ("}", ""):
            prefix = self.peek()
            self.pos += 1
        match = NAME.match(self.text, self.pos)
        name = ""
        if match:
            name = match.group()
            self.pos = match.end()
        elif self.peek() and self.peek() in SPECIAL_PARAMS:
            name = self.peek()
            self.pos += 1
        index = ""
        if self.peek() == "[":
            end = self.text.find("]", self.pos)
            end = len(self.text) if end < 0 else end
            index = self.text[self.pos + 1 : end]
            self.pos = min(end + 1, len(self.text))
        op = next((op for op in PARAM_OPS if self.at(op)), "")
        self.pos += len(op)
        arg = self.brace_word() if op else None
        if not op and self.peek() != "}":
            self.brace_word()
            name = ""
        self.pos += 1 if self.peek() == "}" else 0
        return Param(name, quoted, op, arg, index, prefix)

    def brace_word(self) -> Word:
        """The word inside ``${name<op>word}``, up to its closing brace."""
        start = self.pos
        parts: list[Part] = []
        buffer: list[str] = []
        while self.pos < len(self.text) and self.peek() != "}":
            char = self.peek()
            if char == "\\" and self.peek(1):
                _flush(buffer, parts, quoted=False)
                parts.append(Lit(self.peek(1), quoted=True))
                self.pos += 2
            elif char in "'\"" or (char == "$" and self.next_in("'\"")):
                _flush(buffer, parts, quoted=False)
                parts.extend(self.quoted())
            elif char in "$`" or char == MARK_OPEN:
                _flush(buffer, parts, quoted=False)
                parts.append(self.expansion(quoted=False))
            else:
                buffer.append(char)
                self.pos += 1
        _flush(buffer, parts, quoted=False)
        return Word(parts, self.base + start, self.offset())

    def backquote(self, quoted: bool) -> Sub:
        self.pos += 1
        begin = self.pos
        chars: list[str] = []
        while self.pos < len(self.text):
            char = self.text[self.pos]
            if char == "`":
                self.pos += 1
                break
            if char == "\\" and self.next_in("`\\$"):
                chars.append(self.peek(1))
                self.pos += 2
                continue
            chars.append(char)
            self.pos += 1
        body = parse("".join(chars), self.base + begin, self.depth + 1)
        return Sub(body, quoted)

    def marker(self) -> Part:
        end = self.text.find(MARK_CLOSE, self.pos)
        if end < 0:
            self.pos += 1
            return Lit(MARK_OPEN)
        kind, _, index = self.text[self.pos + 1 : end].partition(":")
        self.pos = end + 1
        index = index.strip()
        return Expr(kind, int(index) if index.isdigit() else -1)
