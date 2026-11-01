# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""What the walk in ``_walk`` knows at one point of a shell block.

A :class:`State` holds the working directory as a :class:`Place`, each
variable's possible :class:`Value` objects, and which variables are
exported. :func:`merge` combines the states that can follow a branch:
a directory stays trusted, and a variable exported, only when every
path agrees.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from ._shell import (
    AndOr,
    Heredoc,
    Lit,
    Param,
    Simple,
    Sub,
    Word,
    expandable_word,
)

if TYPE_CHECKING:
    from ._invocation import Invocation
    from ._shell import Command, Part

TRUSTED = frozenset({"action", "script"})
LOCATED = frozenset({"action", "script", "outside"})
TRUTHY = frozenset({"1", "true", "t", "yes", "y", "on"})
MAX_ALTERNATIVES = 16


@dataclass(frozen=True)
class Place:
    """Where a path points: a base, and how many directories below it.

    ``base`` is "action" (the action's directory), "script" (the
    script's), "outside" (an absolute path outside the workspace),
    "workspace" (the workspace, or a path relative to it), "relative"
    (a stored relative path, resolved where it is used) or "unknown".
    ``depth`` goes negative when ``..`` climbs above the base.
    """

    base: str
    depth: int = 0


UNKNOWN_PLACE = Place("unknown")
WORKSPACE_PLACE = Place("workspace")
OUTSIDE = Place("outside")


@dataclass(frozen=True)
class Value:
    """One value a variable can hold, compared by content.

    ``words`` is what the value becomes as part of a command line, or
    None when that is unknown. ``elements`` holds an array's elements,
    each one word with its index, in index order (arrays can have
    gaps), or None for a scalar. ``source`` is the assigned
    word, its known references already replaced, or None when there
    was none. ``python`` says what the value is as a uv ``--python``
    request: "path" (outside the workspace), "version", or "other".
    ``copy`` marks a copy of PYTHONPATH.
    """

    words: tuple[Word, ...] | None
    place: Place
    text: str | None
    copy: bool = False
    python: str = "other"
    source: Word | None = None
    elements: tuple[tuple[int, Word], ...] | None = None

    def __hash__(self) -> int:
        return hash((self.place, self.text, self.copy, self.python))


UNKNOWN_VALUE = Value(None, UNKNOWN_PLACE, None)


@dataclass(frozen=True)
class Saved:
    """A binding a function call hid, to put back when it returns.

    ``values`` is None when the name was unset. ``partial`` marks a
    binding hidden on only some of the paths merged here: on return the
    name can then hold either the saved value or the current one.
    """

    values: tuple[Value, ...] | None
    exported: bool
    partial: bool = False


@dataclass
class SubResult:
    """What a command substitution prints, as far as the walk can tell."""

    place: Place
    words: tuple[Word, ...] | None = None


@dataclass
class State:
    """What the shell has established at one point of the walk.

    ``exported`` holds only names exported on every path here.
    ``functions`` maps each function name to the bodies it can have;
    None among them means it may not be defined, so the name runs the
    builtin or program of that name.
    ``dead`` is set once the shell can no longer get here by running
    on: "exit", "return", "break", "continue", or "assumed" for a
    failure the walk assumes does not happen. ``errexit`` is ``set -e``.
    ``saved`` holds, for each function call in progress, what its
    ``local`` declarations, arguments and prefix assignments hid.
    """

    cwd: Place
    vars: dict[str, tuple[Value, ...]] = field(default_factory=dict)
    exported: frozenset[str] = frozenset()
    allexport: bool = False
    dirs: tuple[Place, ...] = ()
    dead: str = ""
    functions: dict[str, tuple[Command | None, ...]] = field(
        default_factory=dict
    )
    errexit: bool = True
    saved: tuple[dict[str, Saved], ...] = ()

    def copy(self) -> State:
        return State(
            self.cwd,
            dict(self.vars),
            self.exported,
            self.allexport,
            self.dirs,
            self.dead,
            dict(self.functions),
            self.errexit,
            tuple(dict(frame) for frame in self.saved),
        )

    def dead_copy(self, reason: str) -> State:
        """A copy marked as a path the shell does not continue on."""
        copy = self.copy()
        copy.dead = reason
        return copy

    def become(self, other: State) -> None:
        """Take on another state's contents, in place."""
        self.cwd, self.vars = other.cwd, other.vars
        self.exported, self.allexport = other.exported, other.allexport
        self.dirs, self.dead = other.dirs, other.dead
        self.functions, self.errexit = other.functions, other.errexit
        self.saved = other.saved

    def same(self, other: State) -> bool:
        """True when two states hold the same facts."""
        mine = (self.cwd, self.exported, self.allexport, self.dirs, self.dead)
        theirs = (
            other.cwd,
            other.exported,
            other.allexport,
            other.dirs,
            other.dead,
        )
        return (
            mine == theirs
            and self.errexit == other.errexit
            and self.vars == other.vars
            and self.saved == other.saved
            and _function_ids(self) == _function_ids(other)
        )


def _function_ids(state: State) -> dict[str, tuple[int, ...]]:
    return {
        name: tuple(map(id, bodies)) for name, bodies in state.functions.items()
    }


def merge_places(places: list[Place]) -> Place:
    """A place that holds on every path: one base, at the shallowest depth."""
    if not places:
        return UNKNOWN_PLACE
    first = places[0]
    if all(place == first for place in places):
        return first
    if first.base in LOCATED and all(
        place.base == first.base for place in places
    ):
        return Place(first.base, min(place.depth for place in places))
    return UNKNOWN_PLACE


def merge(states: list[State]) -> State:
    """The state after one of several paths, when any could have run."""
    live = [state for state in states if not state.dead]
    if len(live) <= 1:
        return (live or states)[0].copy()
    merged = State(merge_places([state.cwd for state in live]))
    names: set[str] = set()
    for state in live:
        names.update(state.vars)
    for name in sorted(names):
        values: list[Value] = []
        for state in live:
            for value in state.vars.get(name, (UNKNOWN_VALUE,)):
                if value not in values:
                    values.append(value)
        too_many = len(values) > MAX_ALTERNATIVES
        merged.vars[name] = (UNKNOWN_VALUE,) if too_many else tuple(values)
    merged.exported = frozenset.intersection(
        *(state.exported for state in live)
    )
    merged.allexport = all(state.allexport for state in live)
    merged.errexit = all(state.errexit for state in live)
    same_dirs = all(state.dirs == live[0].dirs for state in live)
    merged.dirs = live[0].dirs if same_dirs else ()
    names = set().union(*(state.functions for state in live))
    for name in sorted(names):
        bodies: list[Command | None] = []
        for state in live:
            for body in state.functions.get(name, (None,)):
                if all(body is not known for known in bodies):
                    bodies.append(body)
        merged.functions[name] = tuple(bodies)
    merged.saved = merge_saved([state.saved for state in live])
    return merged


def merge_saved(
    stacks: list[tuple[dict[str, Saved], ...]],
) -> tuple[dict[str, Saved], ...]:
    """The hidden bindings after paths merge, call frame by call frame.

    A name hidden on only some paths is marked partial, so its return
    keeps the value it holds on the others too.
    """
    depth = min(len(stack) for stack in stacks)
    merged: list[dict[str, Saved]] = []
    for level in range(depth):
        frames = [stack[level] for stack in stacks]
        frame: dict[str, Saved] = {}
        for name in sorted(set().union(*frames)):
            found = [f[name] for f in frames if name in f]
            first = found[0]
            same = all(saved == first for saved in found)
            everywhere = len(found) == len(frames)
            frame[name] = Saved(
                first.values, first.exported, not (same and everywhere)
            )
        merged.append(frame)
    return tuple(merged)


def widen(before: State, after: State) -> State:
    """A state that covers further changes: what still changes becomes unknown."""
    wide = after.copy()
    if before.cwd != after.cwd:
        wide.cwd = UNKNOWN_PLACE
    if before.dirs != after.dirs:
        wide.dirs = ()
    for name, values in after.vars.items():
        if before.vars.get(name) != values:
            wide.vars[name] = (UNKNOWN_VALUE,)
    wide.exported = before.exported & after.exported
    return wide


def reference(word: Word) -> str | None:
    """The variable a word wholly consists of (``$x``, ``"${x[@]}"``), if any."""
    if len(word.parts) != 1:
        return None
    part = word.parts[0]
    if isinstance(part, Param) and not part.op and not part.prefix:
        return part.name
    return None


def is_truthy(value: Value) -> bool:
    return (value.text or "").strip().lower() in TRUTHY


def is_set(value: Value) -> bool:
    """True for a value known to be set and not empty.

    A value the walk knows nothing about, such as the stand-in for a
    variable unset on another path, proves nothing.
    """
    if value.text is not None:
        return value.text != ""
    return value.source is not None and bool(value.source.parts)


def is_path(value: Value) -> bool:
    return value.python == "path"


def risky(invocation: Invocation) -> bool:
    """True when an invocation reads code with the cwd first on sys.path."""
    return "I" not in invocation.flags and invocation.mode not in (
        "info",
        "script",
    )


def lookup_name(name: str, texts: list[str]) -> str:
    """The program ``command -v X``, ``which X`` or ``type -P X`` looks up."""
    if name in ("command", "type") and texts[:1] in (["-v"], ["-P"]):
        return texts[1] if len(texts) > 1 else ""
    if name == "which" and texts:
        return texts[-1]
    return ""


def last_simple(body: list[AndOr]) -> Simple | None:
    """The simple command a list ends with, if it ends with one."""
    if not body or not body[-1].pipelines:
        return None
    command = body[-1].pipelines[-1].commands[-1]
    return command if isinstance(command, Simple) else None


def prints_directory(sub: Sub) -> bool:
    """True for ``$(pwd)``: a substitution that prints the working directory."""
    last = last_simple(sub.body)
    return bool(last and last.words and last.words[0].plain() == "pwd")


def split_assignment(word: Word) -> Word:
    """The value of a ``NAME=value`` word."""
    head = word.parts[0] if word.parts else None
    if not isinstance(head, Lit) or "=" not in head.text:
        return word
    rest = head.text.partition("=")[2]
    parts: list[Part] = [Lit(rest, head.quoted)] if rest else []
    parts.extend(word.parts[1:])
    return Word(parts, word.start, word.end)


def heredoc_lines(heredoc: Heredoc) -> list[tuple[int, Word]]:
    """Each line of a heredoc body as a word, with its offset in the block.

    ``<<-`` strips each line's leading tabs, so the walk does too.
    """
    found: list[tuple[int, Word]] = []
    offset = heredoc.start
    for line in heredoc.body.split("\n"):
        text = line.lstrip("\t") if heredoc.strip else line
        start = offset + len(line) - len(text)
        if heredoc.quoted:
            word = Word([Lit(text, quoted=True)], start, start + len(text))
        else:
            word = expandable_word(text, start)
        found.append((start, word))
        offset += len(line) + 1
    return found
