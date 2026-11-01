# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""The walk through one block of shell, in the order it runs.

At each command the walk knows (see ``_state``):

- the working directory, as a place: inside the action's or the
  script's own directory tree (trusted), or not;
- each variable's possible values, taken when they were assigned;
- which variables are exported, and so reach the programs it starts;
- the functions defined so far.

A subshell, a command or process substitution, each command of a
pipeline and a background job run with a copy of that state, so what
they change does not outlast them. Where the shell may or may not run
something (a branch, a loop body, the commands around ``&&`` and
``||``) the states that can follow are merged: a directory is trusted,
and a setting present, only when every path agrees. A loop is walked
until another round changes nothing, or, after a few rounds, with what
still changes made unknown.

A command's failure is followed wherever execution goes on after it:
into the command after ``||``, out of a condition, and wherever bash
ignores ``-e``. That is in a condition list or command substitution,
before the last pipeline of a ``&&``/``||`` list, under ``!``, and in
any function or group run in one of those places. Elsewhere, with
``bash -e`` (the runner's default), a failure ends the step.

A function's body is walked where the function is called, with the
caller's state, its arguments as ``$1``... and ``$@``, and its prefix
assignments; those, and ``local`` variables, are restored when it
returns. A function the block defines but never calls (a library for
other scripts) is walked from the block's final state. Code run another
way (``source``, ``eval``, ``bash -c``) is not followed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import re
from typing import TYPE_CHECKING

from ._checks import PythonpathChecks
from ._invocation import (
    ASSIGNMENT,
    PARTIAL,
    PREFIXES,
    WRAPPERS,
    Invocation,
    UvEnv,
    literal_invocation,
    program_name,
    skip_wrapper,
    uv_command,
    uv_problem,
)
from ._shell import (
    NAME,
    Case,
    Function,
    Group,
    If,
    Lit,
    Loop,
    Simple,
    Test,
    Word,
    parse,
    word_subs,
)
from ._state import (
    LOCATED,
    MAX_ALTERNATIVES,
    TRUSTED,
    UNKNOWN_PLACE,
    UNKNOWN_VALUE,
    WORKSPACE_PLACE,
    Saved,
    State,
    Value,
    is_path,
    is_set,
    is_truthy,
    merge,
    risky,
    split_assignment,
    widen,
)
from ._values import array_value, indexed

if TYPE_CHECKING:
    from collections.abc import Callable

    from ._shell import (
        AndOr,
        Assign,
        Command,
        Pipeline,
        Redirect,
    )
    from ._state import Place
    from ._yaml import Block, Expression

    Report = Callable[[int, int, str, str | None], None]
    Env = dict[str, tuple[Value, ...]]


INTERPRETER_RULES = {"module": "PPA001", "command": "PPA002", "stdin": "PPA003"}
# How deep function calls may nest, and how many commands one block
# may visit in all. Real scripts stay far below both; reaching either
# makes the scan of the file incomplete rather than wrong.
MAX_CALL_DEPTH = 32
VISIT_LIMIT = 500_000
LOOP_ROUNDS = 4


@dataclass
class Frame:
    """A function call or loop being walked, and the ways out of it.

    ``returns`` pairs each state a ``return`` leaves with its status:
    "ok", "fail" or "either". What a call hides (``local`` names, its
    arguments and prefix assignments) is kept in the shell state, per
    path, not here.
    """

    kind: str
    returns: list[tuple[State, str]] = field(default_factory=list)
    breaks: list[State] = field(default_factory=list)
    continues: list[State] = field(default_factory=list)


def _drop(_start: int, _end: int, _rule: str, _detail: str | None) -> None:
    """A report callback that keeps nothing."""


def return_status(command: Simple) -> str:
    """What a ``return`` returns: "ok" for 0, "fail" for another number."""
    argument = command.words[1].literal() if len(command.words) > 1 else None
    if argument is None or not argument.isdigit():
        return "either"
    return "ok" if int(argument) == 0 else "fail"


class Walker(PythonpathChecks):
    """The walk through one block, reporting findings as it goes."""

    def __init__(
        self,
        block: Block,
        kind: str,
        relpath: str,
        expressions: list[Expression],
        report: Report,
    ) -> None:
        super().__init__(kind, relpath, expressions)
        self.block = block
        self.report = report
        self.frames: list[Frame] = []
        self.defined: list[Command] = []
        self.called: set[int] = set()
        self.calls: list[int] = []
        self.sink = 0
        self.visits = 0
        self.lenient = 0
        self.builtins: dict[str, Callable[[Simple, State], State | None]] = {
            "cd": self.change_directory,
            "pushd": self.change_directory,
            "popd": self.pop_directory,
            "export": self.declaration,
            "declare": self.declaration,
            "typeset": self.declaration,
            "local": self.declaration,
            "readonly": self.declaration,
            "unset": self.unset,
            "set": self.set_options,
            "exit": self.leave,
            "return": self.leave,
            "break": self.leave,
            "continue": self.leave,
            "exec": self.replace_shell,
            "read": self.assigns_unknown,
            "mapfile": self.assigns_unknown,
            "readarray": self.assigns_unknown,
            "printf": self.assigns_unknown,
            "getopts": self.assigns_unknown,
        }

    def run(self) -> None:
        """Walk the block, then any function it defines but never calls.

        A function no one calls here runs from the block's final state.
        Its globals can come from other such functions, so they are
        walked twice: once to gather what each assigns, then to report.
        """
        state = State(WORKSPACE_PLACE, errexit=self.block.errexit)
        for name, word in self.block.env.items():
            state.vars[name] = self.values_of(word, state)
        state.exported = frozenset(self.block.env)
        if self.block.directory is not None:
            state.cwd = self.place_of(self.block.directory, state)
        self.walk_list(parse(self.block.text), state)
        uncalled = [
            body for body in self.defined if id(body) not in self.called
        ]
        if not uncalled:
            return
        state.dead = ""
        report, self.report = self.report, _drop
        ends = [state]
        for body in uncalled:
            end = state.copy()
            self.call(body, end)
            ends.append(end)
        shared = merge(ends)
        shared.cwd = state.cwd
        self.report = report
        for body in uncalled:
            self.call(body, shared.copy())

    def walk_list(
        self, items: list[AndOr], state: State, condition: bool = False
    ) -> State:
        """Walk a command list in place; return the state when it fails.

        In a condition, ``-e`` is off for the whole list, and the last
        command's failure is kept apart from its success.
        """
        failed = state.dead_copy("none")
        self.lenient += condition
        for index, item in enumerate(items):
            if state.dead:
                break
            last = condition and index == len(items) - 1
            failed = self.walk_and_or(item, state, last)
        self.lenient -= condition
        return failed

    def walk_and_or(self, item: AndOr, state: State, condition: bool) -> State:
        """Walk one list item; return the state when it fails.

        Execution goes on after a failure that ``-e`` ignores: one
        before the list's last pipeline, or any where ``-e`` is off.
        A failure of the last pipeline elsewhere ends the step.
        """
        if item.background:
            self.walk_chain(item, state.copy())
            return state.dead_copy("none")
        early, last = self.walk_chain(item, state)
        failed = merge([early, last])
        if not condition:
            going_on = [state, early]
            negated = item.pipelines[-1].negated
            if self.lenient or negated or not state.errexit:
                going_on.append(last)
            state.become(merge(going_on))
        return failed

    def walk_chain(self, item: AndOr, state: State) -> tuple[State, State]:
        """Walk ``a && b || c`` in place as the path on which it succeeds.

        Returns the failures that end the list from before its last
        pipeline (which ``-e`` ignores), and the last pipeline's own.
        Every pipeline but the last runs with ``-e`` off.
        """
        count = len(item.pipelines)
        early = state.dead_copy("none")
        failed = self.walk_pipeline(item.pipelines[0], state, count > 1)
        for index, (operator, pipeline) in enumerate(
            zip(item.operators, item.pipelines[1:], strict=True), start=1
        ):
            lenient = index < count - 1
            if operator == "&&":
                early = merge([early, failed])
                failed = state.dead_copy("none")
                if not state.dead:
                    failed = self.walk_pipeline(pipeline, state, lenient)
                continue
            runner = merge([early, failed])
            early = state.dead_copy("none")
            failed = state.dead_copy("none")
            if runner.dead:
                continue
            succeeded = state.copy()
            failed = self.walk_pipeline(pipeline, runner, lenient)
            state.become(merge([succeeded, runner]))
        return early, failed

    def walk_pipeline(
        self, pipeline: Pipeline, state: State, lenient: bool = False
    ) -> State:
        """Walk a pipeline in place as its success; return its failure.

        ``lenient`` turns ``-e`` off while it runs, as does ``!``.
        """
        lenient = lenient or pipeline.negated
        self.lenient += lenient
        if len(pipeline.commands) > 1:
            for command in pipeline.commands:
                self.walk_command(command, state.copy())
            failed = state.copy()
        else:
            result = self.walk_command(pipeline.commands[0], state)
            failed = state.copy() if result is None else result
        self.lenient -= lenient
        if pipeline.negated:
            succeeded = state.copy()
            state.become(failed)
            return succeeded
        return failed

    def walk_command(self, command: Command, state: State) -> State | None:
        """Walk one command in place; return its failure when that differs.

        Raises ValueError once the block has visited more commands than
        the walk allows, as the result would be incomplete.
        """
        self.visits += 1
        if self.visits > VISIT_LIMIT:
            raise ValueError("shell too large to follow in full")
        if isinstance(command, Simple):
            return self.walk_simple(command, state)
        if isinstance(command, Function):
            state.functions[command.name] = (command.body,)
            self.defined.append(command.body)
            return None
        return self.walk_compound(command, state)

    def walk_compound(
        self, command: Group | If | Loop | Case | Test, state: State
    ) -> State | None:
        for redirect in command.redirects:
            self.walk_redirect(redirect, state)
        sink = int(any(self.writes_env(r) for r in command.redirects))
        self.sink += sink
        failed: State | None = None
        match command:
            case Group(subshell=True):
                self.walk_list(command.body, state.copy())
            case Group():
                failed = self.walk_list(command.body, state)
            case If():
                self.walk_if(command, state)
            case Loop():
                self.walk_loop(command, state)
            case Case():
                self.walk_case(command, state)
            case Test():
                for word in command.words:
                    self.walk_word(word, state)
        self.sink -= sink
        return failed

    def walk_if(self, command: If, state: State) -> None:
        exits: list[State] = []
        current = state.copy()
        for condition, body in command.branches:
            failed = self.walk_list(condition, current, condition=True)
            self.walk_list(body, current)
            exits.append(current)
            current = failed
        if command.otherwise is not None:
            self.walk_list(command.otherwise, current)
        exits.append(current)
        state.become(merge(exits))

    def walk_case(self, command: Case, state: State) -> None:
        """Walk each arm; ``;&`` falls into the next arm, ``;;&`` tests on."""
        self.walk_word(command.word, state)
        entry = state.copy()
        exits: list[State] = []
        falling: State | None = None
        catch_all = False
        for patterns, body, terminator in command.arms:
            for pattern in patterns:
                self.walk_word(pattern, entry)
            branch = (
                entry.copy() if falling is None else merge([entry, falling])
            )
            self.walk_list(body, branch)
            falling = branch if terminator == ";&" else None
            if terminator == ";;&":
                entry = merge([entry, branch])
            elif terminator != ";&":
                exits.append(branch)
            catch_all = catch_all or any(p.plain() == "*" for p in patterns)
        if falling is not None:
            exits.append(falling)
        if not catch_all:
            exits.append(entry)
        state.become(merge(exits))

    def walk_loop(self, loop: Loop, state: State) -> None:
        """Walk a loop as run any number of times, until a round changes nothing.

        After a few rounds, what still changes becomes unknown.
        """
        if loop.name:
            values: list[Value] = []
            for item in loop.items or []:
                self.walk_word(item, state)
                values.extend(self.values_of(item, state))
            state.vars[loop.name] = tuple(values[:MAX_ALTERNATIVES]) or (
                UNKNOWN_VALUE,
            )
        for expression in loop.arith:
            self.walk_word(expression, state)
        loops = sum(frame.kind == "loop" for frame in self.frames)
        rounds = LOOP_ROUNDS if loops < 2 else 2
        exits: list[State] = []
        start = state.copy()
        for round_number in range(rounds):
            end = self.loop_round(loop, start.copy(), exits)
            following = merge([start, end])
            if following.same(start):
                break
            last = round_number >= rounds - 2
            start = widen(start, following) if last else following
        state.become(merge(exits))

    def loop_round(self, loop: Loop, state: State, exits: list[State]) -> State:
        """Walk one round of a loop; add where it can leave to ``exits``."""
        frame = Frame("loop")
        self.frames.append(frame)
        if loop.keyword in ("while", "until"):
            failed = self.walk_list(loop.condition, state, condition=True)
            if loop.keyword == "until":
                failed, state = state, failed
            exits.append(failed)
        else:
            exits.append(state.copy())
        self.walk_list(loop.body, state)
        self.frames.pop()
        exits.extend(frame.breaks)
        return merge([state, *frame.continues])

    def walk_word(self, word: Word, state: State) -> None:
        """Run the substitutions in a word, each in its own subshell.

        Bash does not apply ``-e`` inside a substitution. What it prints
        is judged from the state its last command ran in, so that
        command's failure is kept apart.
        """
        for sub in word_subs(word):
            inner = state.copy()
            self.walk_list(sub.body, inner, condition=True)
            self.subs[sub] = self.sub_output(sub, inner)

    def walk_redirect(self, redirect: Redirect, state: State) -> None:
        if redirect.target is not None:
            self.walk_word(redirect.target, state)
        heredoc = redirect.heredoc
        if heredoc is not None and heredoc.word is not None:
            self.walk_word(heredoc.word, state)

    def walk_simple(self, command: Simple, state: State) -> State | None:
        for word in command.words:
            self.walk_word(word, state)
        for assign in command.assigns:
            for word in self.assign_words(assign):
                self.walk_word(word, state)
        for assign in command.declared:
            for word in assign.array or []:
                self.walk_word(word, state)
        for redirect in command.redirects:
            self.walk_redirect(redirect, state)
        failed: State | None = None
        sets_pythonpath = any(
            assign.name == "PYTHONPATH"
            for assign in [*command.assigns, *command.declared]
        )
        before = state.copy() if sets_pythonpath else state
        if command.words:
            failed = self.dispatch(command, state)
        else:
            for assign in command.assigns:
                self.assign(assign, state, export=False)
        self.check_assigns(command, before, state)
        self.check_env_writes(command, state)
        return failed

    def dispatch(self, command: Simple, state: State) -> State | None:
        """Run a command as bash looks it up: a function, a builtin, a program.

        Known variables in the command's words expand first, so a
        variable holding ``cd`` runs the builtin. Each command line
        they can give runs on its own copy, and the outcomes merge.
        """
        lines = self.alternatives(command.words, state)
        if len(lines) == 1:
            return self.dispatch_line(command, lines[0], state)
        ends: list[State] = []
        failures: list[State] = []
        for line in lines:
            branch = state.copy()
            result = self.dispatch_line(command, line, branch)
            failures.append(branch.copy() if result is None else result)
            ends.append(branch)
        state.become(merge(ends))
        return merge(failures)

    def dispatch_line(
        self, command: Simple, words: list[Word], state: State
    ) -> State | None:
        """Run one expanded command line. ``builtin`` and ``command`` skip functions."""
        if not words:
            return None
        name = self.render(words[0])
        rest = words[1:]
        bypass = (
            name in ("builtin", "command")
            and bool(rest)
            and not (rest[0].literal() or "-").startswith("-")
        )
        if bypass:
            name = self.render(rest[0])
            words = rest
        line = Simple(
            command.assigns,
            words,
            command.redirects,
            command.declared,
            command.start,
            command.end,
        )
        bodies = None if bypass else state.functions.get(name)
        if bodies:
            return self.call_any(name, bodies, line, state)
        return self.run_unshadowed(name, line, state)

    def run_builtin_with(
        self,
        builtin: Callable[[Simple, State], State | None],
        command: Simple,
        state: State,
    ) -> State | None:
        """Run a builtin with its prefix assignments, then restore them."""
        state.saved = (*state.saved, {})
        self.hide(state, [assign.name for assign in command.assigns])
        for assign in command.assigns:
            state.vars[assign.name] = self.assign_values(assign, state)
        failed = builtin(command, state)
        for outcome in (state, failed):
            if outcome is not None:
                self.restore(outcome)
        return failed

    def run_unshadowed(
        self, name: str, command: Simple, state: State
    ) -> State | None:
        """Run a builtin, or a program, ignoring any function of that name.

        A builtin sees the command's prefix assignments while it runs;
        they are then restored, but what the builtin did stays.
        """
        builtin = self.builtins.get(name)
        if builtin is not None and command.assigns:
            return self.run_builtin_with(builtin, command, state)
        if builtin is not None:
            return builtin(command, state)
        self.external(command, state)
        return None

    def call_any(
        self,
        name: str,
        bodies: tuple[Command | None, ...],
        command: Simple,
        state: State,
    ) -> State | None:
        """Call a function that may have any of several bodies, or none."""
        if len(bodies) == 1 and bodies[0] is not None:
            return self.call(bodies[0], state, command)
        ends: list[State] = []
        failures: list[State] = []
        for body in bodies:
            branch = state.copy()
            if body is None:
                result = self.run_unshadowed(name, command, branch)
            else:
                result = self.call(body, branch, command)
            failures.append(branch.copy() if result is None else result)
            ends.append(branch)
        state.become(merge(ends))
        return merge(failures)

    def call(
        self, body: Command, state: State, command: Simple | None = None
    ) -> State | None:
        """Walk a function's body as a call to it, in the caller's shell.

        The call's arguments become ``$1``, ``$@`` and the rest, and its
        prefix assignments hold only while it runs. Returns the state
        when the call fails: the body's own failure, or a ``return``
        with a non-zero status. What the call hid is restored on every
        way out.
        """
        if id(body) in self.calls:
            # A recursive call: what it changes is not followed, so the
            # directory it leaves is unknown.
            state.cwd = UNKNOWN_PLACE
            return state.copy()
        if len(self.calls) >= MAX_CALL_DEPTH:
            raise ValueError("function calls nested too deeply to follow")
        self.called.add(id(body))
        self.calls.append(id(body))
        frame = Frame("function")
        state.saved = (*state.saved, {})
        if command is not None:
            self.bind_call(command, state)
        self.frames.append(frame)
        result = self.walk_command(body, state)
        self.frames.pop()
        self.calls.pop()
        body_failed = state.copy() if result is None else result
        successes = [state] + [
            s for s, status in frame.returns if status != "fail"
        ]
        failures = [body_failed] + [
            s for s, status in frame.returns if status != "ok"
        ]
        succeeded, failed = merge(successes), merge(failures)
        for outcome in (succeeded, failed):
            self.restore(outcome)
            outcome.dead = "" if outcome.dead == "return" else outcome.dead
        state.become(succeeded)
        return failed

    def bind_call(self, command: Simple, state: State) -> None:
        """Bind a call's arguments and prefix assignments, saving what they hide.

        Arguments past ``$9`` are kept in ``$@`` and ``$*`` only.
        """
        arguments = command.words[1:]
        positional = [str(number) for number in range(1, 10)] + ["@", "*", "#"]
        self.hide(
            state, [*positional, *(assign.name for assign in command.assigns)]
        )
        values = [self.values_of(word, state) for word in arguments]
        prefixes = [(a, self.assign_values(a, state)) for a in command.assigns]
        for name in positional:
            state.vars.pop(name, None)
        for number, value in enumerate(values[:9], start=1):
            state.vars[str(number)] = value
        state.vars["@"] = state.vars["*"] = (array_value(indexed(arguments)),)
        count = Word([Lit(str(len(arguments)), quoted=True)])
        state.vars["#"] = self.values_of(count, state)
        for assign, assigned in prefixes:
            state.vars[assign.name] = assigned
            state.exported = state.exported | {assign.name}

    @staticmethod
    def hide(state: State, names: list[str]) -> None:
        """Save each name's binding in the innermost call frame, once."""
        if not state.saved:
            return
        frame = dict(state.saved[-1])
        for name in names:
            if name not in frame:
                frame[name] = Saved(
                    state.vars.get(name), name in state.exported
                )
        state.saved = (*state.saved[:-1], frame)

    @staticmethod
    def restore(state: State) -> None:
        """Put back what the innermost call hid, and drop its frame.

        A binding hidden on only some paths merged here comes back as
        either the saved value or the one the name holds now.
        """
        if not state.saved:
            return
        frame, state.saved = state.saved[-1], state.saved[:-1]
        for name, saved in frame.items():
            current = state.vars.get(name)
            if saved.values is None and not saved.partial:
                state.vars.pop(name, None)
            elif saved.partial:
                restored = list(saved.values or (UNKNOWN_VALUE,))
                restored += [
                    v for v in current or (UNKNOWN_VALUE,) if v not in restored
                ]
                state.vars[name] = tuple(restored)
            else:
                state.vars[name] = saved.values or (UNKNOWN_VALUE,)
            if saved.exported and not saved.partial:
                state.exported = state.exported | {name}
            elif not saved.exported:
                state.exported = state.exported - {name}

    def innermost(self, kind: str) -> Frame | None:
        """The innermost frame of a kind; a loop only within the current function."""
        for frame in reversed(self.frames):
            if frame.kind == kind:
                return frame
            if frame.kind == "function":
                return None
        return None

    def leave(self, command: Simple, state: State) -> State | None:
        """``exit``, ``return``, ``break`` and ``continue``."""
        keyword = self.render(command.words[0])
        frame = self.innermost("function" if keyword == "return" else "loop")
        if keyword == "return" and frame is not None:
            frame.returns.append((state.copy(), return_status(command)))
        elif keyword == "break" and frame is not None:
            frame.breaks.append(state.copy())
        elif keyword == "continue" and frame is not None:
            frame.continues.append(state.copy())
        elif keyword in ("break", "continue"):
            return None
        state.dead = keyword if frame is not None else "exit"
        return None

    def replace_shell(self, command: Simple, state: State) -> State | None:
        """``exec program`` replaces the shell; ``exec`` alone only redirects."""
        if len(command.words) > 1:
            self.external(command, state)
            state.dead = "exit"
        return None

    def external(self, command: Simple, state: State) -> None:
        """Report what a program this command starts can import."""
        env = self.child_env(command.assigns, state)
        reported: set[str] = set()
        chosen: tuple[Invocation, bool] | None = None
        for words in self.alternatives(command.words, state):
            texts = [self.render(word) for word in words]
            index, child, cwd = self.program(words, texts, env, state)
            if program_name(texts[index] if index < len(texts) else "") == "uv":
                cwd = self.uv_directory(words[index + 1 :], cwd, state)
                for rule, detail in self.uv_rules(
                    words[index + 1 :], child, cwd, state
                ):
                    if rule not in reported:
                        reported.add(rule)
                        self.report(command.start, command.end, rule, detail)
            invocation = literal_invocation(texts)
            if invocation is None or cwd.base in TRUSTED:
                continue
            if chosen is None or (risky(invocation) and not risky(chosen[0])):
                safepath = self.every(child, "PYTHONSAFEPATH", is_set)
                chosen = (invocation, "P" in invocation.flags or safepath)
        if chosen is None or not risky(chosen[0]):
            return
        invocation, partial = chosen
        rule = INTERPRETER_RULES[invocation.mode]
        self.report(
            command.start, command.end, rule, PARTIAL if partial else None
        )

    def program(
        self, words: list[Word], texts: list[str], env: Env, state: State
    ) -> tuple[int, Env, Place]:
        """Where the program starts past wrappers, its environment and directory."""
        child = dict(env)
        cwd = state.cwd
        index = 0
        while index < len(texts):
            text = program_name(texts[index])
            if text in PREFIXES:
                index += 1
            elif text == "sudo":
                # sudo starts its program with a fresh environment unless
                # told to keep it.
                options: set[str] = set()
                for word in texts[index + 1 : skip_wrapper(texts, index)]:
                    options.update(word[1:] if word[:1] == "-" else "")
                if "E" not in options:
                    child.clear()
                index = skip_wrapper(texts, index)
            elif text in WRAPPERS:
                index = skip_wrapper(texts, index)
            elif text == "env":
                index, cwd = self.env_arguments(
                    words, texts, index + 1, child, cwd, state
                )
            else:
                break
        return index, child, cwd

    def env_arguments(
        self,
        words: list[Word],
        texts: list[str],
        index: int,
        env: Env,
        cwd: Place,
        state: State,
    ) -> tuple[int, Place]:
        """Apply ``env``'s options and assignments; return the program's index."""
        while index < len(texts):
            text = texts[index]
            following = words[index + 1] if index + 1 < len(words) else None
            if text == "--":
                return index + 1, cwd
            if text in ("-i", "-", "--ignore-environment"):
                env.clear()
            elif text in ("-u", "--unset") and following is not None:
                env.pop(texts[index + 1], None)
                index += 1
            elif text.startswith("--unset="):
                env.pop(text.split("=", 1)[1], None)
            elif text in ("-C", "--chdir") and following is not None:
                cwd = self.place_of(following, state, cwd)
                index += 1
            elif text.startswith("--chdir="):
                cwd = self.place_of(split_assignment(words[index]), state, cwd)
            elif text in ("-S", "--split-string"):
                index += 1
            elif ASSIGNMENT.match(text):
                env[text.split("=", 1)[0]] = self.values_of(
                    split_assignment(words[index]), state
                )
            elif not text.startswith("-"):
                return index, cwd
            index += 1
        return index, cwd

    def uv_directory(
        self, words: list[Word], cwd: Place, state: State
    ) -> Place:
        """Where uv works: its ``--directory``, else the directory it starts in."""
        command = uv_command([self.render(word) for word in words])
        position, inline = command.values.get("--directory", (-1, False))
        if not 0 <= position < len(words):
            return cwd
        word = words[position]
        return self.place_of(
            split_assignment(word) if inline else word, state, cwd
        )

    def uv_rules(
        self, words: list[Word], env: Env, cwd: Place, state: State
    ) -> list[tuple[str, str]]:
        if cwd.base in TRUSTED:
            return []
        command = uv_command([self.render(word) for word in words])
        places: dict[str, str] = {}
        position, inline = command.values.get("--python", (-1, False))
        if 0 <= position < len(words):
            word = words[position]
            value = split_assignment(word) if inline else word
            places["--python"] = self.python_kind(value, state, cwd)

        def located(value: Value) -> bool:
            # uv resolves a relative path from the directory it runs in.
            if value.place.base == "relative":
                return self.value_place(value, state, cwd).base in LOCATED
            return is_path(value)

        uv_env = UvEnv(
            no_config=self.every(env, "UV_NO_CONFIG", is_truthy),
            system=self.every(env, "UV_SYSTEM_PYTHON", is_truthy),
            no_project=self.every(env, "UV_NO_PROJECT", is_truthy),
            any_python=self.every(env, "UV_PYTHON", is_set),
            python_path=self.every(env, "UV_PYTHON", located),
            venv=self.every(env, "VIRTUAL_ENV", located),
            project_env=self.every(env, "UV_PROJECT_ENVIRONMENT", located),
        )
        return uv_problem(command, uv_env, places)

    @staticmethod
    def every(env: Env, name: str, test: Callable[[Value], bool]) -> bool:
        """True when ``name`` is in the environment and every value passes."""
        values = env.get(name, ())
        return bool(values) and all(test(value) for value in values)

    def child_env(self, assigns: list[Assign], state: State) -> Env:
        """A program's environment: the exports, then its own assignments."""
        env = {
            name: state.vars.get(name, (UNKNOWN_VALUE,))
            for name in state.exported
        }
        for assign in assigns:
            env[assign.name] = self.assign_values(assign, state)
        return env

    def change_directory(self, command: Simple, state: State) -> State | None:
        """``cd`` and ``pushd``; the state returned is where a failure leaves.

        A bare ``cd`` goes to ``$HOME``. A bare ``pushd`` swaps the top
        two directories, and ``pushd +N``/``-N`` rotates the stack,
        which the walk does not follow.
        """
        before = state.copy()
        keyword = self.render(command.words[0])
        target = self.cd_target(command.words[1:])
        rotate = (
            keyword == "pushd"
            and target is not None
            and bool(re.fullmatch(r"[+-]\d+", target.literal() or ""))
        )
        if target is None and keyword == "pushd":
            state.cwd = state.dirs[0] if state.dirs else UNKNOWN_PLACE
            state.dirs = (before.cwd, *state.dirs[1:])
        elif target is None:
            state.cwd = self.variable_place("HOME", state)
        elif rotate:
            state.cwd = UNKNOWN_PLACE
            state.dirs = ()
        elif target.literal() == "-":
            state.cwd = self.variable_place("OLDPWD", state)
        elif self.cdpath_applies(target, state):
            state.cwd = UNKNOWN_PLACE
        else:
            state.cwd = self.place_of(target, state)
        state.vars["OLDPWD"] = (Value(None, before.cwd, None),)
        if keyword == "pushd" and target is not None and not rotate:
            state.dirs = (before.cwd, *state.dirs)
        return before

    @staticmethod
    def cd_target(arguments: list[Word]) -> Word | None:
        """The directory operand of ``cd`` or ``pushd``, past its options."""
        for index, word in enumerate(arguments):
            text = word.literal()
            if text == "--":
                return (
                    arguments[index + 1] if index + 1 < len(arguments) else None
                )
            if (
                text is None
                or text == "-"
                or not text.startswith("-")
                or (re.fullmatch(r"-\d+", text))
            ):
                return word
        return None

    def cdpath_applies(self, target: Word, state: State) -> bool:
        """True when CDPATH may redirect a ``cd`` to a relative name.

        ``cd`` searches CDPATH, when it is set and not empty, for a name
        whose first component is not ``.`` or ``..`` and that is not
        absolute.
        """
        values = state.vars.get("CDPATH")
        if not values or all(value.text == "" for value in values):
            return False
        head = target.parts[0] if target.parts else None
        if not isinstance(head, Lit):
            return False
        first = head.text.split("/", 1)[0]
        tilde = head.text.startswith("~") and not head.quoted
        return not (head.text.startswith("/") or first in (".", "..") or tilde)

    def pop_directory(self, command: Simple, state: State) -> State | None:
        """``popd``: back to the top of the stack; ``+N``/``-N`` is not followed."""
        before = state.copy()
        if any(
            re.fullmatch(r"[+-]\d+", w.literal() or "")
            for w in command.words[1:]
        ):
            state.cwd = UNKNOWN_PLACE
            state.dirs = ()
            return before
        state.cwd = state.dirs[0] if state.dirs else UNKNOWN_PLACE
        state.dirs = state.dirs[1:]
        return before

    def declaration(self, command: Simple, state: State) -> State | None:
        """``export``, ``declare``, ``local`` and the like.

        Arguments are read after quote removal, as the builtin sees them.
        """
        keyword = self.render(command.words[0])
        texts = [word.literal() or "" for word in command.words[1:]]
        options = "".join(text for text in texts if text.startswith("-"))
        removed = "".join(text for text in texts if text.startswith("+"))
        export = keyword == "export" or "x" in options
        unexport = (keyword == "export" and "n" in options) or (
            keyword in ("declare", "typeset", "local") and "x" in removed
        )
        frame = self.innermost("function")
        local = frame is not None and (
            keyword == "local"
            or (keyword in ("declare", "typeset") and "g" not in options)
        )
        assigned = {assign.name for assign in command.declared}
        names = {
            text
            for text in texts
            if text not in assigned and NAME.fullmatch(text)
        }
        if local:
            self.hide(state, sorted(assigned | names))
            state.vars.update((name, (UNKNOWN_VALUE,)) for name in names)
        for assign in command.declared:
            self.assign(assign, state, export=export and not unexport)
        if unexport:
            state.exported = state.exported - names - assigned
        elif export:
            state.exported = state.exported | names
        return None

    def unset(self, command: Simple, state: State) -> State | None:
        texts = [word.literal() or "" for word in command.words[1:]]
        functions = "-f" in texts
        for text in texts:
            if not NAME.fullmatch(text):
                continue
            if functions:
                state.functions.pop(text, None)
            else:
                state.vars.pop(text, None)
                state.exported = state.exported - {text}
        return None

    def assigns_unknown(self, command: Simple, state: State) -> State | None:
        """``read``, ``mapfile``, ``printf -v`` and ``getopts``: names set from input.

        What they assign is not known, so each name they set becomes
        unknown. ``printf`` without ``-v`` only writes output.
        """
        keyword = self.render(command.words[0])
        texts = [word.literal() or "" for word in command.words[1:]]
        names: list[str] = []
        if keyword == "printf":
            names = [
                texts[i + 1] for i, t in enumerate(texts[:-1]) if t == "-v"
            ]
        elif keyword == "getopts":
            names = texts[1:2]
        else:
            operands = self.read_operands(texts)
            names = operands or (
                ["REPLY"] if keyword == "read" else ["MAPFILE"]
            )
        for name in names:
            base = name.split("[", 1)[0]
            if NAME.fullmatch(base):
                state.vars[base] = (UNKNOWN_VALUE,)
        return None

    @staticmethod
    def read_operands(texts: list[str]) -> list[str]:
        """The names ``read`` or ``mapfile`` assigns, past their options."""
        takes_value = {
            "-a",
            "-d",
            "-i",
            "-n",
            "-N",
            "-p",
            "-t",
            "-u",
            "-c",
            "-C",
            "-O",
            "-s",
        }
        names: list[str] = []
        index = 0
        while index < len(texts):
            text = texts[index]
            if text == "-a" and index + 1 < len(texts):
                names.append(texts[index + 1])
                index += 2
            elif text in takes_value:
                index += 2
            elif text.startswith("-") and text != "-":
                index += 1
            else:
                names.append(text)
                index += 1
        return names

    def set_options(self, command: Simple, state: State) -> State | None:
        """Follow ``set -a``/``-e`` and ``-o allexport``/``errexit``, and ``+``.

        Options end at ``--`` or ``-``; what follows are positional
        parameters.
        """
        texts = [word.literal() or "" for word in command.words[1:]]
        for index, text in enumerate(texts):
            if text in ("--", "-"):
                break
            if len(text) < 2 or text[0] not in "-+" or text[1] in "-+":
                continue
            on = text.startswith("-")
            letters = text[1:]
            if letters == "o":
                option = texts[index + 1] if index + 1 < len(texts) else ""
                letters = {"allexport": "a", "errexit": "e"}.get(option, "")
            if "a" in letters:
                state.allexport = on
            if "e" in letters:
                state.errexit = on
        return None

    def assign(self, assign: Assign, state: State, export: bool) -> None:
        values = self.assign_values(assign, state)
        old = state.vars.get(assign.name)
        if assign.index is not None:
            values = tuple(
                self.with_element(before, assign.index, value)
                for before in (old or (None,))
                for value in values
            )
        elif assign.append and old:
            values = tuple(
                self.appended(before, value, state)
                for before in old
                for value in values
            )
        state.vars[assign.name] = values[:MAX_ALTERNATIVES]
        if export or state.allexport:
            state.exported = state.exported | {assign.name}

    @staticmethod
    def assign_words(assign: Assign) -> list[Word]:
        if assign.array is not None:
            return assign.array
        return [assign.value] if assign.value is not None else []
