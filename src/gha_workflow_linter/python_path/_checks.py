# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""PYTHONPATH values a command sets, passes to a program or writes to
``$GITHUB_ENV``, judged where the walk in ``_walk`` reaches them.

A value is judged with the variables the walk knows put in, so its
colons and literal text count wherever they came from.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ._invocation import env_assignments
from ._pythonpath import (
    pythonpath_problems,
    word_tokens,
)
from ._shell import Param, Word
from ._state import heredoc_lines, split_assignment
from ._values import Values, output_lines, written_lines

if TYPE_CHECKING:
    from collections.abc import Callable

    from ._shell import Heredoc, Part, Redirect, Simple
    from ._state import State

ENV_TARGETS = frozenset({"$GITHUB_ENV", "__GH_env_github_env__"})
ENV_WRITE = "written to GITHUB_ENV, so every later step gets it: "


class PythonpathChecks(Values):
    """Checks of PYTHONPATH values, mixed into the walk."""

    report: Callable[[int, int, str, str | None], None]
    sink: int

    def check_assigns(
        self, command: Simple, before: State, state: State
    ) -> None:
        """Report PYTHONPATH values the command assigns or passes to ``env``.

        An assignment is judged in ``before``, the state the command
        started in. ``+=`` is judged as the value it leaves:
        PYTHONPATH as it was, then the appended text.
        """
        for assign in [*command.assigns, *command.declared]:
            if assign.name != "PYTHONPATH" or assign.value is None:
                continue
            value = assign.value
            if assign.append:
                value = Word(
                    [Param("PYTHONPATH"), *value.parts], value.start, value.end
                )
            self.check_pythonpath(value, assign.start, command.end, before, "")
        for line in self.alternatives(command.words, state):
            texts = [self.render(word) for word in line]
            for index in env_assignments(texts):
                if texts[index].startswith("PYTHONPATH="):
                    word = line[index]
                    start = (
                        word.start
                        if command.start <= word.start < command.end
                        else command.start
                    )
                    value = split_assignment(word)
                    self.check_pythonpath(value, start, command.end, state, "")

    def check_pythonpath(
        self, value: Word, start: int, end: int, state: State, prefix: str
    ) -> None:
        """Report the problems a PYTHONPATH value can have, each rule once."""

        def classify(part: Part) -> str:
            return self.pythonpath_kind(part, state)

        reported: set[str] = set()
        for alternative in self.sources(value, state):
            tokens = word_tokens(
                alternative, self.copies(state), not prefix, classify
            )
            for rule, detail in pythonpath_problems(tokens, self.kind):
                if rule not in reported:
                    reported.add(rule)
                    self.report(start, end, rule, prefix + detail)

    def check_env_writes(self, command: Simple, state: State) -> None:
        """Report PYTHONPATH values a command writes to ``$GITHUB_ENV``.

        Each command line the words can expand to is read, so a writer
        held in a variable or array counts too.
        """
        writes = self.sink > 0 or any(
            self.writes_env(r) for r in command.redirects
        )
        heredocs = False
        for words in self.alternatives(command.words, state):
            if not words:
                continue
            name = self.render(words[0])
            arguments = words[1:]
            if writes and name in ("echo", "printf"):
                lines = written_lines(name, arguments, command.start)
                for line in self.resolved_lines(lines, state):
                    if self.render(line).startswith("PYTHONPATH="):
                        value = split_assignment(line)
                        self.check_pythonpath(
                            value, command.start, command.end, state, ENV_WRITE
                        )
            tees = name == "tee" and any(
                self.render(w) in ENV_TARGETS for w in arguments
            )
            heredocs = heredocs or (writes and name == "cat") or tees
        if heredocs:
            for redirect in command.redirects:
                if redirect.heredoc is not None:
                    self.check_heredoc(redirect.heredoc, state)

    def check_heredoc(self, heredoc: Heredoc, state: State) -> None:
        lines = [line for _start, line in heredoc_lines(heredoc)]
        for line in self.resolved_lines(lines, state):
            text = self.render(line)
            if text.startswith("PYTHONPATH="):
                value = split_assignment(line)
                self.check_pythonpath(
                    value, line.start, line.start + len(text), state, ENV_WRITE
                )

    def resolved_lines(self, lines: list[Word], state: State) -> list[Word]:
        """Written lines with known variables replaced, split again at newlines."""
        found: list[Word] = []
        for line in lines:
            for alternative in self.sources(line, state):
                found.extend(output_lines(alternative.parts, line.start))
        return found

    def writes_env(self, redirect: Redirect) -> bool:
        return (
            redirect.op in (">", ">>", ">|")
            and redirect.fd in ("", "1")
            and redirect.target is not None
            and self.render(redirect.target) in ENV_TARGETS
        )
