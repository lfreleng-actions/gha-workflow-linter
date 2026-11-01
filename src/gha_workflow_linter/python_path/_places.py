# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Where shell words point, and how they read as text.

A path is trusted while it stays in the action's or the script's own
directory tree: from the base its first part names (the action path,
the script's directory, a variable holding one), every later part must
be known text, and ``..`` may climb no higher than the root of the
repository that holds the file. An unknown part, or a transformation
such as ``${dir%/*}``, could lead anywhere, so it loses the trust.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ._shell import Expr, Lit, Param, Sub, Word
from ._state import (
    LOCATED,
    MAX_ALTERNATIVES,
    OUTSIDE,
    UNKNOWN_PLACE,
    WORKSPACE_PLACE,
    Place,
    State,
    SubResult,
    Value,
    last_simple,
    lookup_name,
    merge_places,
)

if TYPE_CHECKING:
    from ._shell import Part, Simple
    from ._yaml import Expression

OUTSIDE_VARIABLES = frozenset(
    {"RUNNER_TEMP", "RUNNER_TOOL_CACHE", "HOME", "TMPDIR"}
)
EXPRESSION_TEXT = {
    "action_path": "${GITHUB_ACTION_PATH}",
    "workspace": "${GITHUB_WORKSPACE}",
    "pythonpath": "${PYTHONPATH}",
    "temp": "${RUNNER_TEMP}",
}
DEFAULTING = frozenset({":-", "-", ":=", "="})
# The running script: one below the script's own directory.
SCRIPT_FILE = Place("script", 1)


class Places:
    """Path classification and rendering for one file's shell.

    ``kind`` and ``relpath`` decide what is trusted: the action path
    only in actions and the scripts they run, the script's directory
    only in scripts, each up to the root of the file's repository.
    """

    def __init__(
        self, kind: str, relpath: str, expressions: list[Expression]
    ) -> None:
        self.kind = kind
        self.expressions = expressions
        depth = relpath.count("/")
        self.allowance = {
            "action": depth if kind == "action" else 0,
            "script": depth if kind == "script" else 0,
            "outside": 0,
        }
        self.subs: dict[Sub, SubResult] = {}

    def directory(self, word: Word) -> Place:
        """Where a YAML path value, such as ``working-directory``, points.

        The runner resolves a relative one against the workspace.
        """
        return self.place_of(word, State(WORKSPACE_PLACE))

    def render(self, word: Word) -> str:
        """A word as text: literal parts as they are, expansions in shell syntax."""
        return "".join(self.render_part(part) for part in word.parts)

    def render_part(self, part: Part) -> str:
        if isinstance(part, Lit):
            return part.text
        if isinstance(part, Param):
            if not (part.op or part.index or part.prefix):
                return "$" + part.name
            subscript = f"[{part.index}]" if part.index else ""
            operand = self.render(part.arg) if part.arg is not None else ""
            return (
                "${"
                + part.prefix
                + part.name
                + subscript
                + part.op
                + operand
                + "}"
            )
        if isinstance(part, Expr):
            return self.render_expression(part)
        result = self.subs.get(part) if isinstance(part, Sub) else None
        if result is not None and result.words:
            return " ".join(self.render(word) for word in result.words)
        return "$(...)" if isinstance(part, Sub) else "$((...))"

    def render_expression(self, part: Expr) -> str:
        """An expression as the variable it matches, or as one opaque word."""
        if part.kind in EXPRESSION_TEXT:
            return EXPRESSION_TEXT[part.kind]
        known = 0 <= part.index < len(self.expressions)
        name = self.expressions[part.index].name if known else "expression"
        return f"__GH_{name}__"

    def place_of(
        self, word: Word, state: State, cwd: Place | None = None
    ) -> Place:
        """Where a word points as a path, when the shell expands it here.

        ``cwd`` is the directory a relative path starts from, when a
        wrapper such as ``env -C`` has moved the program elsewhere.
        """
        base = state.cwd if cwd is None else cwd
        if not word.parts:
            return base
        head, rest = word.parts[0], word.parts[1:]
        if not isinstance(head, Lit):
            return self.with_suffix(
                self.part_place(head, state, cwd), rest, state
            )
        if head.text.startswith("/"):
            return self.with_suffix(OUTSIDE, word.parts, state)
        if head.text.startswith("~") and not head.quoted:
            slash = head.text.find("/")
            user = head.text[1:slash] if slash >= 0 else head.text[1:]
            home = OUTSIDE if user else self.variable_place("HOME", state)
            tail: list[Part] = [Lit(head.text[slash:])] if slash >= 0 else []
            return self.with_suffix(home, [*tail, *rest], state)
        return self.with_suffix(base, [Lit("/"), *word.parts], state)

    def with_suffix(
        self, base: Place, parts: list[Part], state: State
    ) -> Place:
        """Follow the path text after a base; trusted only if it cannot climb out.

        Text that does not start with ``/`` joins the base's last
        component (``${dir}-cache`` is a sibling of ``$dir``), which is
        a step up and back down.
        """
        if base.base not in LOCATED or not parts:
            return base
        texts = self.suffix_texts(parts, state)
        if texts is None:
            return base if base.base == "outside" else UNKNOWN_PLACE
        joined = [
            text if text.startswith("/") or not text else "../_" + text
            for text in texts
        ]
        return merge_places([self.descend(base, text) for text in joined])

    def suffix_texts(self, parts: list[Part], state: State) -> list[str] | None:
        """Every text the parts can expand to, or None when any is unknown."""
        texts = [""]
        for part in parts:
            if isinstance(part, Lit):
                choices = [part.text]
            elif isinstance(part, Param) and not (part.op or part.prefix):
                values = state.vars.get(part.name, ())
                choices = [
                    value.text for value in values if value.text is not None
                ]
                if not values or len(choices) != len(values):
                    return None
            else:
                return None
            texts = [text + choice for text in texts for choice in choices]
            if len(texts) > MAX_ALTERNATIVES:
                return None
        return texts

    def descend(self, place: Place, text: str) -> Place:
        """Follow path text from a place; climbing out of its tree loses it."""
        if place.base not in LOCATED:
            return place
        depth = place.depth
        for segment in text.split("/"):
            if segment in ("", "."):
                continue
            depth += -1 if segment == ".." else 1
            if depth < -self.allowance[place.base]:
                return UNKNOWN_PLACE
        return Place(place.base, depth)

    def part_place(
        self, part: Part, state: State, cwd: Place | None = None
    ) -> Place:
        if isinstance(part, Param) and part.fixed is not None:
            base, depth, _kind = part.fixed
            return Place(base, depth)
        if isinstance(part, Param):
            return self.param_place(part, state, cwd)
        if isinstance(part, Expr):
            return self.expression_place(part.kind)
        if isinstance(part, Sub) and part in self.subs:
            return self.subs[part].place
        return UNKNOWN_PLACE

    def param_place(
        self, param: Param, state: State, cwd: Place | None = None
    ) -> Place:
        if param.prefix:
            return UNKNOWN_PLACE
        own = self.variable_place(param.name, state, cwd)
        if not param.op:
            return own
        if param.op in DEFAULTING:
            fallback = self.place_of(param.arg or Word([]), state, cwd)
            return merge_places([own, fallback])
        operand = param.arg.literal() if param.arg is not None else None
        if param.op in ("%", "%%") and operand == "/*":
            return self.descend(own, "..")
        return UNKNOWN_PLACE

    def variable_place(
        self, name: str, state: State, cwd: Place | None = None
    ) -> Place:
        """Where a variable points; a relative value from ``cwd`` when given."""
        values = state.vars.get(name)
        if values is None:
            return self.special_place(name, state)
        return merge_places(
            [self.value_place(value, state, cwd) for value in values]
        )

    def value_place(
        self, value: Value, state: State, cwd: Place | None = None
    ) -> Place:
        if value.place.base == "relative":
            return self.descend(
                state.cwd if cwd is None else cwd, value.text or ""
            )
        return value.place

    def special_place(self, name: str, state: State) -> Place:
        """Where a variable the block does not assign points."""
        places = {
            "GITHUB_ACTION_PATH": self.expression_place("action_path"),
            "PWD": state.cwd,
            "GITHUB_WORKSPACE": WORKSPACE_PLACE,
        }
        if self.kind == "script":
            places["0"] = places["BASH_SOURCE"] = SCRIPT_FILE
        if name in places:
            return places[name]
        return OUTSIDE if name in OUTSIDE_VARIABLES else UNKNOWN_PLACE

    def expression_place(self, kind: str) -> Place:
        places = {"temp": OUTSIDE, "workspace": WORKSPACE_PLACE}
        if self.kind != "workflow":
            places["action_path"] = Place("action")
        return places.get(kind, UNKNOWN_PLACE)

    def sub_output(self, sub: Sub, inner: State) -> SubResult:
        """What a substitution prints, judged by the command that ends it.

        ``inner`` is the substitution's own state after it ran. Only a
        command that is not a function of the same name is read.
        """
        last = last_simple(sub.body)
        if last is None or not last.words:
            return SubResult(UNKNOWN_PLACE)
        name = self.render(last.words[0])
        if name in inner.functions:
            return SubResult(UNKNOWN_PLACE)
        texts = [self.render(word) for word in last.words[1:]]
        looked_up = lookup_name(name, texts)
        if looked_up:
            return SubResult(OUTSIDE, (Word([Lit(looked_up)]),))
        if name == "pwd":
            return SubResult(inner.cwd)
        if name == "mktemp" or (
            name == "uv" and texts[:2] == ["python", "find"]
        ):
            return SubResult(OUTSIDE)
        return SubResult(self.filtered_place(name, last, inner))

    def filtered_place(self, name: str, last: Simple, inner: State) -> Place:
        """The path ``dirname``, ``echo``, ``realpath`` or ``readlink`` prints.

        ``realpath`` and ``readlink`` follow symbolic links, which can
        lead anywhere: what they print is unknown, except for the
        running script itself (``$0``, ``${BASH_SOURCE[...]}``), whose
        resolved path is where its code is.
        """
        operands = [
            w for w in last.words[1:] if not (w.plain() or "").startswith("-")
        ]
        if not operands:
            return UNKNOWN_PLACE
        place = self.place_of(operands[-1], inner)
        if name == "dirname":
            return self.descend(place, "..")
        if name == "echo" and len(operands) == 1:
            return place
        if name in ("realpath", "readlink") and self.names_script(operands[-1]):
            return place
        return UNKNOWN_PLACE

    def names_script(self, word: Word) -> bool:
        """True when a word is exactly the running script's own path."""
        if self.kind != "script" or len(word.parts) != 1:
            return False
        part = word.parts[0]
        return (
            isinstance(part, Param)
            and part.name in ("0", "BASH_SOURCE")
            and not part.op
            and not part.prefix
            and part.index in ("", "0")
        )
