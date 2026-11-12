# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Read a uv or uvx command line, judge it, and read the settings a program sees.

uv settings from the environment count only from the step's YAML
``env:``, the command's own prefix assignments and its env wrappers.
Only the command's own words exempt it: ``--directory`` and
``--project`` move nothing out of reach of the rules.

PPA013 asks where uv's interpreter comes from: only a trusted
``--python`` or ``UV_PYTHON`` value (``_trust``), or ``env -i``,
keeps the caller's environment from choosing it.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
import os
import re
from typing import TYPE_CHECKING

from gha_workflow_linter.shell._tree import node_text as _node_text

from ._envfile import PythonpathChecks, is_text_line
from ._invocation import (
    EXPR_OPEN,
    UNKNOWN_EXPRESSION,
    UNREAD_WRAPPER,
    UNSETTLED_ENV,
    EnvOptions,
    env_of,
    is_outside_path,
    is_trusted_python,
)
from ._pythonpath import TEXT
from ._words import literal_of

if TYPE_CHECKING:
    from collections.abc import Callable

    from tree_sitter import Node

    from ._pythonpath import Token
    from ._trust import ShellFacts
    from ._words import Word


UV_VALUE = frozenset(
    {
        "--directory",
        "--project",
        "--python",
        "-p",
        "--with",
        "--with-editable",
        "--with-requirements",
        "--from",
        "--extra",
        "--group",
        "--index",
        "--index-url",
        "--extra-index-url",
        "--find-links",
        "--cache-dir",
        "--config-file",
        "--constraints",
        "-c",
        "--overrides",
        "--package",
        "--env-file",
        "--color",
        "-w",
        "-i",
        "-f",
        "-C",
        "--config-setting",
        "--resolution",
        "--prerelease",
        "--exclude-newer",
        "--link-mode",
        "--python-preference",
        "--python-platform",
        "--only-group",
        "--no-group",
        "--no-extra",
        "--keyring-provider",
        "--allow-insecure-host",
        "--default-index",
        "--index-strategy",
        "--fork-strategy",
        "--build-constraints",
        "-b",
        "--refresh-package",
        "--upgrade-package",
        "-P",
        "--reinstall-package",
        "--no-binary-package",
        "--no-build-package",
    }
)
UV_INFO = frozenset({"-h", "--help", "-V", "--version"})
# Subcommands that find an interpreter by discovery (PPA013).
UV_DISCOVERS = (["run"], ["venv"], ["sync"], ["export"], ["pip"])
# Subcommands that look one up and print or install it (PPA013).
UV_FINDS = (["python", "find"], ["python", "install"])
STEERED_BY = "UV_PYTHON, VIRTUAL_ENV or CONDA_PREFIX"
# The variables uv 0.13.5 reads to choose an interpreter (#448's
# Evidence); README.md lists them under "setup-uv and the caller's
# environment" and cites this definition.
INTERPRETER_SELECTORS = frozenset(
    {
        "PATH",
        "UV_PYTHON",
        "UV_PYTHON_SEARCH_PATH",
        "VIRTUAL_ENV",
        "CONDA_PREFIX",
        "CONDA_DEFAULT_ENV",
        "CONDA_ROOT",
        "UV_INTERNAL__PARENT_INTERPRETER",
        "UV_INTERNAL__TEST_PYTHON_MANAGED",
        "PYTHONEXECUTABLE",
        "__PYVENV_LAUNCHER__",
        "UV_SYSTEM_PYTHON",
        "UV_MANAGED_PYTHON",
        "UV_PYTHON_PREFERENCE",
        "UV_PROJECT_ENVIRONMENT",
    }
)
# Names a cleared wrapper (env -i, sudo) may pass explicitly and keep
# its exemption: the pinned lookup of lfreleng-actions/pypi-version-
# check-action#181 needs them, and PATH is the author's literal there.
CLEARED_ALLOWED = frozenset(
    {
        "PATH",
        "HOME",
        "UV_NO_CONFIG",
        "UV_PYTHON_INSTALL_DIR",
        "UV_CACHE_DIR",
        "UV_NO_PROGRESS",
    }
)
# Values uv reads as false for a boolean setting.
FALSY = frozenset({"", "0", "false", "no", "off"})
TRUTHY = frozenset({"1", "true", "yes", "on"})
# What inherits a uv setting, by the scope that sets it.
INHERITS = {
    "step": "the step's uv commands inherit it",
    "job": "the job's uv commands inherit it",
    "file": "every job's uv commands inherit it",
    "env_file": "later uv commands in the job inherit it",
}
ENV_FILE_NAME = re.compile(
    r"UV_PYTHON|UV_SYSTEM_PYTHON|UV_MANAGED_PYTHON", re.I
)
ENV_FILE_SETTING = re.compile(
    rf"^({ENV_FILE_NAME.pattern})(=|<<)(.*)$", re.I | re.S
)
# A uv interpreter setting named anywhere in a write's text.
ENV_FILE_MENTION = re.compile(
    rf"(?<!\w)(?:{ENV_FILE_NAME.pattern})(?!\w)", re.I
)
UNREAD_UV_ENV = (
    "a uv interpreter setting written to GITHUB_ENV in a form the scan "
    "cannot read; later uv commands in the job may inherit it"
)
REFERENCE = re.compile(r'^"?\$(?:\{(\w+)\}|(\w+))"?$')


def shown(value: str) -> str:
    """A value for a finding's detail: expressions as written, kept short."""
    text = re.sub(f"{EXPR_OPEN}[A-Z_]+\ue003", "${{ ... }}", value)
    return text if len(text) <= 60 else text[:57] + "..."


def python_value_problem(source: str, value: str) -> str | None:
    """Why a ``--python`` or ``UV_PYTHON`` value lets the caller choose.

    None when it is trusted; an expression is not judged here.
    """
    if is_trusted_python(value):
        return None
    if "/" not in value and "\\" not in value:
        return (
            f"{source} {shown(value)} is a request, not a path: "
            "VIRTUAL_ENV, CONDA_PREFIX or the caller's PATH choose"
        )
    return (
        f"{source} {shown(value)} is neither a trusted step output nor "
        "an absolute path outside the workspace"
    )


def passed_selectors(names: dict[str, str | None]) -> list[str]:
    """The interpreter selectors a wrapper passes outside the allow list.

    The allow list covers a literal value alone: an allowed name whose
    value the scan cannot read (``PATH="$PATH"``, an expression) counts
    as a passed selector, failing closed.
    """
    return sorted(
        n
        for n, v in names.items()
        if (n in INTERPRETER_SELECTORS and n not in CLEARED_ALLOWED)
        or (n in CLEARED_ALLOWED and (v is None or EXPR_OPEN in v))
    )


def is_truthy(value: str | None) -> bool:
    """Whether uv reads a boolean setting's literal value as true."""
    return (value or "").strip().lower() in TRUTHY


def uv_env_problem(name: str, value: str | None, scope: str) -> str | None:
    """PPA013's detail for a uv interpreter setting in an env scope.

    ``value`` is None when the scan cannot read it. UV_SYSTEM_PYTHON
    and UV_MANAGED_PYTHON count unless literally false; UV_PYTHON
    unless empty or one trusted line.
    """
    inherits = INHERITS[scope]
    written = " written to GITHUB_ENV" if scope == "env_file" else ""
    if name != "UV_PYTHON":
        if value is not None and value.strip().lower() in FALSY:
            return None
        return f"{name}{written or ' is set'}; {inherits}"
    if value == "" or (
        value is not None and "\n" not in value and is_trusted_python(value)
    ):
        return None
    return f"UV_PYTHON{written} is not a trusted interpreter; {inherits}"


# uv options whose value decides what interpreter or directory uv uses.
UV_DECIDING = frozenset({"--python", "--directory", "--project"})
# uv's short flags that take no value; one may lead a cluster (-qp X).
UV_SHORT_FLAGS = "qvnU"


def uv_option(word: str) -> tuple[str, str | None]:
    """An option word's name and the value written in it, if any.

    ``--name=value``, ``-p=value``, ``-pvalue`` and a cluster of flags
    before a short option that takes a value (``-qp.venv/bin/python``)
    all carry their value in the word, as uv's parser reads them.
    """
    if not word.startswith("--"):
        rest = word[1:].lstrip(UV_SHORT_FLAGS)
        if rest and "-" + rest[0] in UV_VALUE:
            value = rest[1:]
            value = value[1:] if value.startswith("=") else value
            return "-" + rest[0], value if rest[1:] else None
    name, equals, value = word.partition("=")
    return name, value if equals else None


@dataclass
class UvCommand:
    subcommand: list[str]
    options: set[str]
    values: dict[str, int]  # option -> index of the word holding its value
    program: int  # index where uv run's program starts, or -1
    # Options whose value is written in the option word itself.
    inline: set[str] = field(default_factory=set)

    def value(self, args: list[str], name: str) -> str | None:
        """The value of option ``name`` among ``args``; None when absent."""
        index = self.values.get(name, -1)
        if not 0 <= index < len(args):
            return None
        word = args[index]
        return uv_option(word)[1] if name in self.inline else word

    def option(self, words: list[str], i: int) -> int:
        """Record the option ``words[i]``; the index past it and its value."""
        raw, attached = uv_option(words[i])
        name = "--python" if raw == "-p" else raw
        self.options.add(name)
        if attached is not None:
            self.values[name] = i
            self.inline.add(name)
        elif raw in UV_VALUE:
            self.values[name] = i + 1
            return i + 2
        return i + 1


def parse_uv(words: list[str]) -> UvCommand:
    command = UvCommand([], set(), {}, -1)
    i = 0
    while i < len(words):
        word = words[i]
        running = command.subcommand[:1] == ["run"] or command.subcommand[
            :2
        ] == ["tool", "run"]
        if word == "--":
            command.program = i + 1 if running else -1
            break
        if not word.startswith("-") or (running and word == "-"):
            if running:
                command.program = i
                break
            if len(command.subcommand) < 2:
                command.subcommand.append(word)
            i += 1
            continue
        clustered = not word.startswith("--") and word[1:].lstrip(
            UV_SHORT_FLAGS
        ).startswith("m")
        if running and (word in ("-m", "--module") or clustered):
            command.options.add("-m")
            command.program = -2  # module: uv itself runs python -m
            break
        i = command.option(words, i)
    return command


def parse_uvx(words: list[str]) -> UvCommand:
    """Split ``uvx``'s arguments: its options, then the program."""
    command = UvCommand(["tool", "run"], set(), {}, 0)
    i = 0
    while i < len(words) and words[i].startswith("-"):
        i = command.option(words, i)
    command.program = i
    return command


def uv_findings(
    command: UvCommand, settings: dict[str, bool], is_uvx: bool
) -> list[str]:
    """The rules a uv command breaks, from its subcommand and settings.

    Measured on uv 0.11 and 0.13 with planted interpreters (see the
    oracle tests on #434): 'uv run' and 'uv venv' read a workspace
    .python-version unless --no-config or any --python; 'uv run' uses
    a workspace .venv unless --python names a path outside it and
    project mode is off (or the project environment is elsewhere), or
    VIRTUAL_ENV is active; 'uv python find' needs --no-config and
    --system; 'uv pip' needs --system, a --python path or VIRTUAL_ENV.
    VIRTUAL_ENV counts only with no Python request (--python or
    UV_PYTHON), which wins over it. uvx and 'uv tool' use neither.
    """
    head = command.subcommand[:1]
    options = command.options
    found: list[str] = []
    if is_uvx:
        return found
    if head in (["run"], ["venv"]) and not (
        settings["no_config"] or settings["any_python"]
    ):
        found.append("PPA006")
    # An explicit Python request wins over the active environment.
    venv = settings["venv"] and not settings["python_request"]
    if head == ["run"]:
        active = venv and (settings["no_project"] or "--active" in options)
        isolated = settings["python_path"] and (
            settings["no_project"] or settings["project_env"]
        )
        if not (isolated or active):
            found.append("PPA007")
    elif head == ["export"] and not settings["project_env"]:
        found.append("PPA007")
    elif head == ["python"] and command.subcommand[1:2] == ["find"]:
        if not settings["no_config"]:
            found.append("PPA006")
        if not settings["system"]:
            found.append("PPA007")
    elif head == ["pip"] and not (
        settings["system"] or settings["python_path"] or venv
    ):
        found.append("PPA007")
    return found


class UvChecks(PythonpathChecks):
    """uv judgement, mixed into the block scan.

    Uses the per-command ``program`` and ``declares_pythonpath``
    besides what ``PythonpathChecks`` names.
    """

    # What env wrappers do to the command being judged.
    wrapper_env: EnvOptions | None = None
    facts: ShellFacts
    program: Callable[..., None]
    python: Callable[..., None]
    declares_pythonpath: Callable[..., bool]

    def env_truthy(self, name: str, assigns: list[Node]) -> bool:
        return is_truthy(self.env_setting(name, assigns))

    def env_setting(self, name: str, assigns: list[Node]) -> str | None:
        """A setting's literal value the program sees; None when unset or not literal."""
        return self.env_lookup(name, assigns)[1]

    def env_lookup(
        self, name: str, assigns: list[Node]
    ) -> tuple[bool, str | None]:
        """Whether the program sees a setting, and its literal value.

        A wrapper's NAME=value words come first, then the command's
        prefix assignments (the last one winning), then the step's
        env; the last two only when sudo or ``exec -c`` keeps them. A
        prefix ``NAME+=value`` appends to a value the scan does not
        follow, so its value is not literal.
        """
        wrapper = self.wrapper_env
        if wrapper is not None and name in wrapper.names:
            return True, wrapper.names[name]
        if (
            wrapper is not None
            and wrapper.kept is not None
            and name not in wrapper.kept
        ):
            return False, None
        for assign in reversed(assigns):
            n = assign.child_by_field_name("name")
            if n is not None and _node_text(self.src, n) == name:
                v = assign.child_by_field_name("value")
                if any(c.type == "+=" for c in assign.children):
                    return True, None
                if v is None:
                    return True, ""
                value = literal_of(self.src, v)
                if value is None:
                    value = self.facts.word(v, assign.start_byte, 0)
                return True, value
        return self.inherited(name)

    def inherited(self, name: str) -> tuple[bool, str | None]:
        """Whether the step's env sets a name, and its literal value.

        An inherited ``UV_PYTHON`` that the block may change (an
        assignment, ``unset``, or an opaque block) has no value the
        scan can read.
        """
        if name == "UV_PYTHON" and (
            self.facts.opaque or self.facts.counts[name]
        ):
            return True, None
        return name in self.block.env, self.block.env.get(name)

    def uv(
        self,
        node: Node,
        texts: list[str],
        start: int,
        assigns: list[Node],
        origins: list[Word],
    ) -> None:
        """Judge a uv or uvx command from its options and the step's env."""
        is_uvx = os.path.basename(texts[start]).startswith("uvx")
        args = texts[start + 1 :]
        arg_origins = origins[start + 1 :]
        cmd = parse_uvx(args) if is_uvx else parse_uv(args)
        if not self.uv_readable(node, args, is_uvx):
            return
        if cmd.options & UV_INFO:
            return
        if self.wrapper_env is not None and self.wrapper_env.unsettled:
            self.report(node, "PPA009", UNSETTLED_ENV)
        else:
            settings = self.uv_settings(cmd, args, assigns)
            for rule in uv_findings(cmd, settings, is_uvx):
                self.report(node, rule)
        # Unread wrapper settings leave PPA006 to PPA008 unknown, not
        # whether the caller's environment reaches uv: env -u keeps it.
        if self.block.kind != "script":
            self.uv_steered(node, cmd, args, assigns, is_uvx)
        self.uv_program(node, args, arg_origins, cmd, assigns)

    def uv_steered(
        self,
        node: Node,
        cmd: UvCommand,
        args: list[str],
        assigns: list[Node],
        is_uvx: bool,
    ) -> None:
        """PPA013: whether the caller's environment chooses uv's interpreter.

        ``env -i`` (or ``env -``) around the command leaves the caller
        nothing to steer, unless it passes an interpreter selector
        itself. Otherwise ``uv python find`` and ``install`` always
        let it; the discovering subcommands unless ``--python`` or
        ``UV_PYTHON`` is trusted. A value the scan cannot trace is
        PPA009.
        """
        passed = self.passed_into_cleared()
        if self.env_cleared() and not passed:
            return
        selected = (
            f"{', '.join(passed)} passed into the cleared environment "
            "chooses uv's interpreter"
        )
        head = cmd.subcommand[:2]
        if not is_uvx and head in UV_FINDS:
            self.report(
                node,
                "PPA013",
                selected
                if passed
                else "runs without env -i: PATH and UV_* from the caller choose",
            )
            return
        if not (is_uvx or head == ["tool", "run"] or head[:1] in UV_DISCOVERS):
            return
        if "--python" in cmd.options:
            source, value = "--python", cmd.value(args, "--python")
        else:
            present, value = self.env_lookup("UV_PYTHON", assigns)
            source = "UV_PYTHON"
            if not present or value == "":
                value = ""
            elif value is None:
                self.report(
                    node,
                    "PPA009",
                    "UV_PYTHON is a value the scan cannot trace to a "
                    "trusted interpreter",
                )
                return
        if value is not None and UNKNOWN_EXPRESSION.search(value):
            self.report(
                node,
                "PPA009",
                f"{source} is {shown(value)}, which the scan cannot trace "
                "to a trusted interpreter",
            )
            return
        if value:
            detail = python_value_problem(source, value)
        elif passed:
            detail = selected
        elif "--system" in cmd.options:
            detail = "--system searches the caller's PATH"
        elif self.env_truthy("UV_SYSTEM_PYTHON", assigns):
            detail = "UV_SYSTEM_PYTHON searches the caller's PATH"
        elif "--managed-python" in cmd.options or self.env_truthy(
            "UV_MANAGED_PYTHON", assigns
        ):
            detail = f"--managed-python: {STEERED_BY} still choose"
        else:
            detail = f"no --python: {STEERED_BY} choose"
        if detail is not None:
            self.report(node, "PPA013", detail)

    def env_cleared(self) -> bool:
        """Whether wrappers keep the caller's interpreter settings out.

        ``env -i`` or ``env -`` clears them all; ``exec -c`` and sudo
        do unless they keep an ``INTERPRETER_SELECTORS`` or UV_* name.
        """
        wrapper = self.wrapper_env
        if wrapper is None:
            return False
        return wrapper.cleared or (
            wrapper.kept is not None
            and not any(
                name in INTERPRETER_SELECTORS or name.startswith("UV_")
                for name in wrapper.kept
            )
        )

    def passed_into_cleared(self) -> list[str]:
        """The selectors a cleared wrapper's own NAME=value words set.

        Every wrapper's words count, sudo's and nested env's included;
        ``CLEARED_ALLOWED`` names do not.
        """
        if not self.env_cleared() or self.wrapper_env is None:
            return []
        return passed_selectors(self.wrapper_env.names)

    def uv_env_lines(self, node: Node, lines: list[list[Token]]) -> None:
        """PPA013 for a uv interpreter setting written to $GITHUB_ENV.

        Read by record, as ``judge_env_lines`` reads them: a line
        inside another variable's ``NAME<<DELIMITER`` record sets
        nothing, and a uv setting's record is one value.
        """
        if self.block.kind == "script":
            return
        i = 0
        while i < len(lines):
            line = lines[i]
            i += 1
            head = line[0].text if line and line[0].kind == TEXT else ""
            record = (
                re.match(r"^([^=]+?)<<(.+)$", head) if len(line) == 1 else None
            )
            if record:
                end = i
                while end < len(lines) and not is_text_line(
                    lines[end], record.group(2)
                ):
                    end += 1
                setting = ENV_FILE_NAME.fullmatch(record.group(1))
                if setting is not None:
                    self.report_uv_env(
                        node,
                        setting.group(0),
                        None
                        if end == len(lines)
                        else self.record_value(node, lines[i:end]),
                    )
                i = end + 1
                continue
            found = ENV_FILE_SETTING.match(head)
            if found is None:
                # A line whose name the scan cannot read (a printf
                # conversion before it, or an expansion inside it).
                if (len(line) > 1 or head == "") and not re.search(
                    "=|<<", head
                ):
                    self.uv_env_unread(node, [t.text for t in line])
                continue
            value: str | None = None
            if found.group(2) == "=" and len(line) == 1:
                value = found.group(3)
            elif (
                found.group(2) == "=" and not found.group(3) and len(line) == 2
            ):
                value = self.reference_value(node, line[1])
            self.report_uv_env(node, found.group(1), value)
            if found.group(2) == "<<":
                # A record whose delimiter the scan cannot read: where
                # it ends is unknown.
                return

    def uv_env_unread(self, node: Node, texts: list[str]) -> None:
        """PPA009 for a GITHUB_ENV write the scan cannot read that names a uv setting.

        An unreadable value never earns a pass: the write may set
        UV_PYTHON, UV_SYSTEM_PYTHON or UV_MANAGED_PYTHON.
        """
        if self.block.kind != "script" and any(
            ENV_FILE_MENTION.search(t) for t in texts
        ):
            self.report(node, "PPA009", UNREAD_UV_ENV)

    def report_uv_env(self, node: Node, name: str, value: str | None) -> None:
        detail = uv_env_problem(name.upper(), value, "env_file")
        if detail is not None:
            self.report(node, "PPA013", detail)

    def reference_value(self, node: Node, token: Token) -> str | None:
        """The trusted value of a token that reads one variable; else None."""
        ref = REFERENCE.match(token.text)
        if ref is None:
            return None
        return self.facts.scalar(ref.group(1) or ref.group(2), node.start_byte)

    def record_value(self, node: Node, body: list[list[Token]]) -> str | None:
        """A record's value: its lines of text, or one variable's value."""
        if len(body) == 1 and len(body[0]) == 1 and body[0][0].kind != TEXT:
            return self.reference_value(node, body[0][0])
        if any(t.kind != TEXT for ln in body for t in ln):
            return None
        return "\n".join("".join(t.text for t in ln) for ln in body)

    def uv_program(
        self,
        node: Node,
        args: list[str],
        origins: list[Word],
        cmd: UvCommand,
        assigns: list[Node],
    ) -> None:
        """Judge the program uv run launches, as any other command's."""
        if cmd.program == -2:
            self.report(node, "PPA001")
        if not 0 <= cmd.program < len(args):
            return
        if args[cmd.program] == "-":
            # uv run - runs Python on its standard input.
            self.python(node, ["-"], [], assigns)
            return
        rest, rest_origins = args[cmd.program :], origins[cmd.program :]
        rest_sources = [w.source for w in rest_origins]
        inner = self.skip_wrappers(rest, rest_sources)
        if inner == -1:
            self.report(node, "PPA009", UNREAD_WRAPPER)
            return
        if self.declares_pythonpath(node, rest, rest_origins, inner):
            return
        # The launched program's env wrappers act on the environment
        # uv itself was given.
        outer = self.wrapper_env
        base = outer or EnvOptions()
        self.wrapper_env = env_of(
            rest[:inner],
            rest_sources,
            replace(base, names=dict(base.names), words=[]),
        )
        try:
            if inner < len(rest):
                self.program(node, rest, rest_origins, inner, assigns)
        finally:
            self.wrapper_env = outer

    def uv_readable(self, node: Node, args: list[str], is_uvx: bool) -> bool:
        """False, with PPA009 reported, when a deciding uv word is unknown.

        Only option values that decide the outcome need to be known,
        and the subcommand itself. uvx's options end at its program,
        whose own arguments are left to ``uv_program``.
        """
        masked = [
            a
            if not a.startswith("\x00")
            else "--UNKNOWN"
            if a[1:].lstrip("\"'").startswith("-")
            else "UNKNOWN"
            for a in args
        ]
        probe = parse_uvx(masked) if is_uvx else parse_uv(masked)
        for name, index in probe.values.items():
            if name not in UV_DECIDING:
                continue
            if index >= len(args):
                self.report(node, "PPA009", f"uv {name} has no value")
                return False
            if args[index].startswith("\x00"):
                self.report(
                    node,
                    "PPA009",
                    f"uv {name} is {args[index][1:]}, which the scan cannot read",
                )
                return False
        # An option word the scan cannot read whole (--python="$X",
        # -p"$X") still names its option in its text.
        limit = probe.program if probe.program >= 0 else len(args)
        operands = set(probe.values.values())
        for position, word in enumerate(args[:limit]):
            marker = word[:1] != "\x00" and EXPR_OPEN in word
            # A known option's separate operand; an option word with an
            # inline value records its own index, and is still an option.
            if position in operands and not word.startswith("-"):
                continue
            if word[:1] != "\x00" and not marker:
                continue
            # The word as written, past the quote or $' that hides it.
            written = word[1:].lstrip("$\"'") if word[:1] == "\x00" else word
            if not written.startswith("-"):
                continue  # an unread operand, such as a package name
            raw = uv_option(written)[0] if not marker else ""
            name = "--python" if raw == "-p" else raw
            # A deciding option, or one the scan cannot read at all
            # ($'-p...', --${{ inputs.option }}), which may be one.
            label = f"uv {name}" if name in UV_DECIDING else "uv option"
            shown = "${{ ... }}" if marker else word[1:]
            self.report(
                node,
                "PPA009",
                f"{label} is {shown}, which the scan cannot read",
            )
            return False
        command = parse_uv(args)
        program = (
            args[command.program] if 0 <= command.program < len(args) else ""
        )
        # A ${{ }} expression here may hold options, like a variable,
        # unless it names a path (the workspace, action path or temp).
        if (
            not is_uvx
            and (
                program.startswith("\x00") or UNKNOWN_EXPRESSION.match(program)
            )
            and args[command.program - 1 : command.program] != ["--"]
        ):
            shown = program[1:] if program[0] == "\x00" else "${{ ... }}"
            self.report(
                node,
                "PPA009",
                f"{shown} may hold uv options; the scan cannot read it",
            )
            return False
        # A ${{ }} expression may stand for any subcommand, too.
        unknown = [
            w if w.startswith("\x00") else "\x00" + w
            for w in command.subcommand
            if w.startswith("\x00") or EXPR_OPEN in w
        ]
        if not is_uvx and unknown:
            self.report(
                node,
                "PPA009",
                f"uv subcommand is {unknown[0][1:]}, which the scan cannot read",
            )
            return False
        return True

    def uv_settings(
        self, cmd: UvCommand, args: list[str], assigns: list[Node]
    ) -> dict[str, bool]:
        """What protects this uv command: from its options, else the env.

        A path protects only as a literal absolute path outside the
        workspace.
        """
        options = cmd.options
        if "--python" in options:
            python_path = is_trusted_python(cmd.value(args, "--python") or "")
            any_python = request = True
        else:
            present, env_py = self.env_lookup("UV_PYTHON", assigns)
            python_path = env_py is not None and is_trusted_python(env_py)
            any_python = bool(env_py)
            # A request the scan cannot read still overrides VIRTUAL_ENV.
            request = present and env_py != ""
        return {
            "no_config": "--no-config" in options
            or self.env_truthy("UV_NO_CONFIG", assigns),
            "system": "--system" in options
            or self.env_truthy("UV_SYSTEM_PYTHON", assigns),
            "no_project": "--no-project" in options
            or self.env_truthy("UV_NO_PROJECT", assigns),
            "python_path": python_path,
            "any_python": any_python,
            "python_request": request,
            "venv": is_outside_path(
                self.env_setting("VIRTUAL_ENV", assigns) or ""
            ),
            "project_env": is_outside_path(
                self.env_setting("UV_PROJECT_ENVIRONMENT", assigns) or ""
            ),
        }
