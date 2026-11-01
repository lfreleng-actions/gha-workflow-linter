# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""What variables hold, and what words become once they expand.

A value is taken when it is assigned: ``CMD=$PY`` copies what ``PY``
holds then, so a later change to ``PY`` does not reach ``CMD``. A
reference to a variable whose values are all known text is replaced by
that text; any other reference is kept, and read as an expansion.

A command's words expand the same way before the command is judged:
``$opts`` in ``python3 $opts -c ...`` becomes the options it holds.
Unquoted, and as ``"${array[@]}"``, a value splits into words; quoted,
it stays one.
"""

from __future__ import annotations

from dataclasses import replace
import re
from typing import TYPE_CHECKING

from ._invocation import program_positions
from ._places import Places
from ._pythonpath import RELATIVE, UNKNOWN, WORKDIR, WORKSPACE
from ._shell import Arith, Expr, Lit, Param, Sub, Word
from ._state import (
    LOCATED,
    MAX_ALTERNATIVES,
    UNKNOWN_PLACE,
    UNKNOWN_VALUE,
    Place,
    Value,
    prints_directory,
    reference,
)

if TYPE_CHECKING:
    from ._shell import Assign, Part
    from ._state import State

VERSION_NAME = re.compile(r"VER(SION)?\b|_VER|VERSION", re.I)
MAX_LINES = 32
PRINTF_CONVERSION = re.compile(r"(%%|%[-+ #0]*\d*(?:\.\d+)?[sbdiqxXoucfeEgG])")
PRINTF_ESCAPES = {"n": "\n", "t": "\t", "\\": "\\", '"': '"', "'": "'"}
ECHO_ESCAPES = {
    "n": "\n",
    "t": "\t",
    "r": "\r",
    "a": "\a",
    "b": "\b",
    "e": "\x1b",
    "f": "\f",
    "v": "\v",
    "\\": "\\",
}


def written_lines(name: str, arguments: list[Word], start: int) -> list[Word]:
    """The lines ``echo`` or ``printf`` writes, each as a word.

    ``echo`` writes its arguments joined by spaces, decoding escapes
    in literal text after ``-e`` (bash's last ``-e``/``-E`` wins; off by
    default). ``printf`` fills its format's conversions with the
    arguments in turn, and reuses the format while any remain. A format
    that is not plain text cannot be followed, so then every word is
    read as a line of its own.
    """
    if name == "echo":
        words = list(arguments)
        escapes = False
        while words and re.fullmatch(r"-[neE]+", words[0].literal() or ""):
            flags = (words.pop(0).literal() or "").replace("n", "")
            escapes = flags[-1] == "e" if flags[1:] else escapes
        joined: list[Part] = []
        for index, word in enumerate(words):
            if index:
                joined.append(Lit(" ", quoted=True))
            joined.extend(word.parts)
        return output_lines(_echo_escapes(joined) if escapes else joined, start)
    template = arguments[0].literal() if arguments else None
    if template is None:
        return [
            line
            for word in arguments
            for line in output_lines(word.parts, start)
        ]
    return output_lines(_printf(template, arguments[1:]), start)


def _echo_escapes(parts: list[Part]) -> list[Part]:
    """Decode ``echo -e`` escapes in literal text; ``\\c`` ends the output."""
    decoded: list[Part] = []
    for part in parts:
        if not isinstance(part, Lit):
            decoded.append(part)
            continue
        text, stop, _ = part.text.partition("\\c")
        text = re.sub(
            r"\\(.)", lambda m: ECHO_ESCAPES.get(m.group(1), m.group(0)), text
        )
        decoded.append(Lit(text, part.quoted))
        if stop:
            break
    return decoded


def _printf(template: str, arguments: list[Word]) -> list[Part]:
    """What ``printf template arguments...`` writes, as parts."""
    parts: list[Part] = []
    remaining = list(arguments)
    while True:
        used = False
        for piece in PRINTF_CONVERSION.split(template):
            if piece == "%%":
                parts.append(Lit("%", quoted=True))
            elif PRINTF_CONVERSION.fullmatch(piece):
                used = True
                if remaining:
                    operand = remaining.pop(0).parts
                    parts.extend(
                        _echo_escapes(operand)
                        if piece.endswith("b")
                        else operand
                    )
            elif piece:
                text = re.sub(
                    r"\\(.)",
                    lambda m: PRINTF_ESCAPES.get(m.group(1), m.group(0)),
                    piece,
                )
                parts.append(Lit(text, quoted=True))
        if not remaining or not used:
            return parts


def array_value(elements: tuple[tuple[int, Word], ...]) -> Value:
    """An array value from its indexed elements; its words are them in order."""
    ordered = tuple(sorted(elements, key=lambda pair: pair[0]))
    words = tuple(word for _index, word in ordered)
    return Value(words, UNKNOWN_PLACE, None, elements=ordered)


def indexed(
    words: tuple[Word, ...] | list[Word],
) -> tuple[tuple[int, Word], ...]:
    """Words as array elements numbered from zero."""
    return tuple(enumerate(words))


def output_lines(parts: list[Part], start: int) -> list[Word]:
    """Split parts into lines at the newlines in their literal text."""
    lines: list[list[Part]] = [[]]
    for part in parts:
        if not isinstance(part, Lit) or "\n" not in part.text:
            lines[-1].append(part)
            continue
        for index, piece in enumerate(part.text.split("\n")):
            if index:
                lines.append([])
            if piece:
                lines[-1].append(Lit(piece, part.quoted))
    return [Word(line, start, start) for line in lines if line]


class Values(Places):
    """Variable values and word expansion, on top of path classification."""

    def values_of(self, word: Word, state: State) -> tuple[Value, ...]:
        """The values a word gives a variable it is assigned to.

        A copy of a variable takes its values; of an array, its first
        element, as the shell does.
        """
        name = reference(word)
        head = word.parts[0] if word.parts else None
        if name in state.vars and isinstance(head, Param) and not head.index:
            return tuple(
                self.scalar(value, state) for value in state.vars[name]
            )
        found: list[Value] = []
        for alternative in self.snapshots(word, state):
            value = self.value_of(alternative, state, word)
            if value not in found:
                found.append(value)
        return tuple(found[:MAX_ALTERNATIVES]) or (UNKNOWN_VALUE,)

    def scalar(self, value: Value, state: State) -> Value:
        """A value as a scalar: an array's element 0, else itself."""
        if value.elements is None:
            return value
        first = next(
            (word for index, word in value.elements if index == 0), Word([])
        )
        return self.value_of(first, state, first)

    def value_of(self, word: Word, state: State, written: Word) -> Value:
        """One value of a word whose known references are already replaced.

        ``written`` is the word as written, which says whether the
        value copies PYTHONPATH.
        """
        text = word.literal()
        head = word.parts[0] if word.parts else None
        tilde = isinstance(head, Lit) and not head.quoted
        if (
            text
            and not text.startswith("/")
            and not (tilde and text.startswith("~"))
        ):
            place = Place("relative")
        else:
            place = self.place_of(word, state)
        words = self.split_words(word)
        return Value(
            None if words is None else tuple(words),
            place,
            text,
            self.mentions_pythonpath(written, state),
            self.python_kind(word, state),
            self.frozen(word, state),
        )

    def frozen(self, word: Word, state: State) -> Word:
        """A stored word, each plain reference fixed to what it names now.

        PYTHONPATH and its copies stay live: they are read as PYTHONPATH
        wherever the value ends up.
        """
        copies = self.copies(state)
        parts: list[Part] = []
        for part in word.parts:
            kept = part
            if (
                isinstance(part, Param)
                and not (part.op or part.prefix or part.fixed)
                and part.name != "PYTHONPATH"
                and part.name not in copies
            ):
                place = self.part_place(part, state)
                kind = self.pythonpath_kind(part, state)
                kept = replace(part, fixed=(place.base, place.depth, kind))
            parts.append(kept)
        return Word(parts, word.start, word.end)

    def pythonpath_kind(self, part: Part, state: State) -> str:
        """What an expansion in a PYTHONPATH value names.

        A reference kept in a stored value names what it did when the
        value was stored.
        """
        if isinstance(part, Param) and part.fixed is not None:
            return part.fixed[2]
        untrusted = state.cwd.base not in LOCATED
        if isinstance(part, Sub) and prints_directory(part):
            return WORKDIR if untrusted else UNKNOWN
        if isinstance(part, Param) and part.name == "PWD" and not part.op:
            return WORKDIR if untrusted else UNKNOWN
        if isinstance(part, Param) and not part.op and part.name in state.vars:
            bases = {value.place.base for value in state.vars[part.name]}
            if "workspace" in bases:
                return WORKSPACE
            return RELATIVE if "relative" in bases else UNKNOWN
        place = self.part_place(part, state)
        return WORKSPACE if place.base == "workspace" else UNKNOWN

    def snapshots(self, word: Word, state: State) -> list[Word]:
        """The word with each reference to known text replaced by that text."""
        alternatives: list[list[Part]] = [[]]
        for part in word.parts:
            choices: list[list[Part]] = [[part]]
            texts = self.known_texts(part, state)
            if texts is not None:
                choices = [[Lit(text, quoted=True)] for text in texts]
            alternatives = [a + c for a in alternatives for c in choices]
            alternatives = alternatives[:MAX_ALTERNATIVES]
        return [Word(parts, word.start, word.end) for parts in alternatives]

    def sources(self, word: Word, state: State) -> list[Word]:
        """The word with each reference to a known variable replaced by its word.

        Unlike :meth:`snapshots`, a value that is only partly known is
        put in as written, so its literal parts (a PYTHONPATH's colons)
        still count. A copy of PYTHONPATH stays a reference.
        """
        alternatives: list[list[Part]] = [[]]
        for part in word.parts:
            choices: list[list[Part]] = [[part]]
            values = self.plain_values(part, state)
            if values:
                choices = [
                    list(value.source.parts) if value.source else []
                    for value in values
                ]
            alternatives = [a + c for a in alternatives for c in choices]
            alternatives = alternatives[:MAX_ALTERNATIVES]
        return [Word(parts, word.start, word.end) for parts in alternatives]

    @staticmethod
    def plain_values(part: Part, state: State) -> tuple[Value, ...]:
        """The values a plain reference stands for, when each has a word.

        A value built from PYTHONPATH counts too: its word keeps the
        reference, which is then read as PYTHONPATH, around its own
        text and colons.
        """
        if not isinstance(part, Param) or part.op or part.prefix or part.index:
            return ()
        values = state.vars.get(part.name, ())
        if not values or any(v.source is None for v in values):
            return ()
        return values

    @staticmethod
    def known_texts(part: Part, state: State) -> list[str] | None:
        """The texts a plain reference can expand to, when all are known."""
        if not isinstance(part, Param) or part.op or part.prefix or part.index:
            return None
        values = state.vars.get(part.name)
        if not values:
            return None
        texts = [value.text for value in values]
        if any(text is None for text in texts):
            return None
        return list(dict.fromkeys(text for text in texts if text is not None))

    def split_words(self, word: Word) -> list[Word] | None:
        """The words a value splits into on a command line, or None if unknown.

        A command lookup (``$(command -v python3)``) stands for the
        program it finds; any other substitution is unknown.
        """
        if len(word.parts) == 1 and isinstance(word.parts[0], Sub):
            result = self.subs.get(word.parts[0])
            return list(result.words) if result and result.words else None
        if any(isinstance(part, (Sub, Arith)) for part in word.parts):
            return None
        words: list[Word] = []
        current: list[Part] = []
        for part in word.parts:
            if not isinstance(part, Lit):
                current.append(part)
                continue
            for piece in re.split(r"(\s+)", part.text):
                if piece.isspace():
                    if current:
                        words.append(Word(current))
                    current = []
                elif piece:
                    current.append(Lit(piece, part.quoted))
        if current:
            words.append(Word(current))
        return words

    def array_values(
        self, words: list[Word], state: State
    ) -> tuple[Value, ...]:
        """The values of ``name=(words)``: each a tuple of elements."""
        lines: list[list[Word]] = [[]]
        for word in words:
            options = self.expand_word(word, state)
            lines = [line + option for line in lines for option in options]
            lines = lines[:MAX_ALTERNATIVES]
        return tuple(array_value(indexed(line)) for line in lines)

    def assign_values(self, assign: Assign, state: State) -> tuple[Value, ...]:
        if assign.array is not None:
            return self.array_values(assign.array, state)
        return self.values_of(assign.value or Word([]), state)

    @staticmethod
    def with_element(before: Value | None, index: str, value: Value) -> Value:
        """An array after ``name[index]=value``, from one value it had before.

        Elements keep their indices, so an array can have gaps.
        """
        if not index.isdigit() or value.source is None:
            return UNKNOWN_VALUE
        if before is None:
            elements: dict[int, Word] = {}
        elif before.elements is not None:
            elements = dict(before.elements)
        elif before.source is not None:
            elements = {0: before.source}
        else:
            return UNKNOWN_VALUE
        elements[int(index)] = value.source
        return array_value(tuple(elements.items()))

    def appended(self, before: Value, value: Value, state: State) -> Value:
        """The value after ``name+=value``, from one value it had before."""
        if before.elements is not None and value.elements is not None:
            start = (
                max((index for index, _word in before.elements), default=-1) + 1
            )
            added = tuple(
                (start + n, word) for n, (_i, word) in enumerate(value.elements)
            )
            return array_value(before.elements + added)
        scalars = before.elements is None and value.elements is None
        if scalars and before.text is not None and value.text is not None:
            joined = Word([Lit(before.text + value.text, quoted=True)])
            return self.value_of(joined, state, joined)
        return UNKNOWN_VALUE

    @staticmethod
    def selected(value: Value, index: str) -> tuple[Word, ...] | None:
        """The words a reference with subscript ``index`` takes from a value.

        ``@`` and ``*`` take every element in index order, a number the
        element with that index (if any), and no subscript element 0
        (all a scalar's words). None when the subscript is not known.
        """
        if value.elements is None:
            if index in ("", "@", "*", "0"):
                return value.words
            return () if index.isdigit() else None
        if index in ("@", "*"):
            return tuple(word for _index, word in value.elements)
        if index and not index.isdigit():
            return None
        position = int(index or "0")
        return tuple(
            word for number, word in value.elements if number == position
        )

    @staticmethod
    def may_vanish(word: Word, state: State) -> bool:
        """True when an unquoted word can expand to nothing and so be removed.

        That is a single unquoted ``${name<op>word}`` whose variable may
        be empty or unset and whose operand may be empty too, as in
        ``${opts:-}``, or one with ``:+``/``+`` whose variable may be
        empty or unset.
        """
        if len(word.parts) != 1:
            return False
        part = word.parts[0]
        if not isinstance(part, Param) or part.quoted or not part.op:
            return False
        values = state.vars.get(part.name)
        empty = values is None or any(
            value.text in (None, "") for value in values
        )
        operand = part.arg.literal() if part.arg is not None else ""
        if part.op in (":-", "-", ":=", "="):
            return empty and operand == ""
        return part.op in (":+", "+") and empty

    def expand_word(
        self, word: Word, state: State, program: bool = True
    ) -> list[list[Word]]:
        """The word lists one command word can become, its variable expanded.

        Only a word that is wholly a reference to a variable the walk
        knows expands. In the program's place every known value counts
        (a lookup such as ``$(command -v python3)`` names its program);
        elsewhere only values of known text or known elements, such as
        options. A quoted scalar stays one word.
        """
        name = reference(word)
        values = state.vars.get(name) if name else None
        head = word.parts[0] if word.parts else None
        if self.may_vanish(word, state):
            return [[], [word]]
        if not values or not isinstance(head, Param):
            return [[word]]
        if not program and any(
            value.text is None and value.elements is None for value in values
        ):
            return [[word]]
        options: list[list[Word]] = []
        index = "@" if head.name in ("@", "*") else head.index
        for value in values:
            chosen = self.selected(value, index)
            if chosen is None:
                option = [word]
            elif (
                value.elements is None
                and head.quoted
                and value.text is not None
                and len(chosen) > 1
            ):
                option = [
                    Word([Lit(value.text, quoted=True)], word.start, word.end)
                ]
            elif value.elements is not None and not head.quoted:
                option = [
                    piece
                    for element in chosen
                    for piece in self.split_words(element) or [element]
                ]
            else:
                option = list(chosen)
            if option not in options:
                options.append(option)
        return options[:MAX_ALTERNATIVES]

    def alternatives(self, words: list[Word], state: State) -> list[list[Word]]:
        """The command lines ``words`` can become once known variables expand.

        Where a program is named (the first, and each one a wrapper
        such as ``env`` runs), every known value counts; elsewhere
        only known text.
        """
        positions = program_positions([self.render(word) for word in words])
        lines: list[list[Word]] = [[]]
        for index, word in enumerate(words):
            options = self.expand_word(word, state, index in positions)
            lines = [line + option for line in lines for option in options]
            lines = lines[:MAX_LINES]
        return lines

    def mentions_pythonpath(self, word: Word, state: State) -> bool:
        """True when a value copies PYTHONPATH, directly or through a copy."""
        copies = self.copies(state)
        for part in word.parts:
            if isinstance(part, Expr) and part.kind == "pythonpath":
                return True
            if isinstance(part, Param) and (
                part.name in copies
                or part.name == "PYTHONPATH"
                or (
                    part.arg is not None
                    and self.mentions_pythonpath(part.arg, state)
                )
            ):
                return True
        return False

    @staticmethod
    def copies(state: State) -> set[str]:
        return {
            name
            for name, values in state.vars.items()
            if any(value.copy for value in values)
        }

    def python_kind(
        self, word: Word, state: State, cwd: Place | None = None
    ) -> str:
        """A uv ``--python``-style value: "path", "version" or "other".

        A path counts only outside the workspace: a relative one names
        the workspace's own files, resolved from ``cwd`` when given (the
        directory uv runs in). A variable the block does not assign
        is judged by its name: one that mentions a version
        (PYTHON_VERSION, py_ver) is a version request, any other a
        path. That is a heuristic, and the reason a finding names the
        variable.
        """
        if self.place_of(word, state, cwd).base in LOCATED:
            return "path"
        head = word.parts[0] if word.parts else None
        if (
            not isinstance(head, Param)
            or head.prefix
            or head.name in state.vars
            or self.special_place(head.name, state) != UNKNOWN_PLACE
        ):
            return "other"
        rest = self.render(Word(word.parts[1:]))
        if "/" in rest or not VERSION_NAME.search(head.name):
            return "path"
        return "version"
