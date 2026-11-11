# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""How a command line reads: rule texts, option tables, Python and uv arguments."""

from __future__ import annotations

from dataclasses import dataclass, field
import posixpath
import re

RULES = {
    "PPA001": "python -m without -I: the working directory leads sys.path",
    "PPA002": "python -c without -I: the working directory leads sys.path",
    "PPA003": "python reading stdin without -I: the working directory leads sys.path",
    "PPA004": "PYTHONPATH may hold an empty entry",
    "PPA005": "PYTHONPATH names the caller's checkout",
    "PPA006": "uv reads .python-version from the workspace",
    "PPA007": "uv uses a .venv in the workspace",
    "PPA008": "setup-uv works in the workspace",
    "PPA009": "unresolved: the command's effect depends on a value the scan cannot read",
    "PPA010": "not fully scanned: shell the parser could not read",
    "PPA011": "setup-uv runs an interpreter the caller's environment chooses",
    "PPA012": "setup-uv adds a directory from the caller's environment to PATH",
}
INTERPRETER = re.compile(r"^(?:.*/)?python(?:3(?:\.\d+t?)?)?$")
# Each ${{ }} expression in a run: block reaches the parser as a word
# made of its kind between two private-use characters, which no text
# in a file can be mistaken for: \ue002TEMP\ue003.
EXPR_OPEN = "\ue002"
EXPR_CLOSE = "\ue003"


def expression_marker(kind: str) -> str:
    """The word a ``${{ }}`` expression of ``kind`` becomes."""
    return f"{EXPR_OPEN}{kind}{EXPR_CLOSE}"


# A ${{ }} expression whose text the scan cannot know (not a path).
# env.PYTHONPATH is one too as a command's word: only the PYTHONPATH
# token reader treats it as the variable's own earlier value.
UNKNOWN_EXPRESSION = re.compile(
    f"{EXPR_OPEN}(?:OTHER|PYTHON|PYTHONPATH|UV){EXPR_CLOSE}"
)
# Node types that may appear as one word of a command.
WORD_TYPES = {
    "word",
    "string",
    "raw_string",
    "concatenation",
    "number",
    "simple_expansion",
    "expansion",
    "command_substitution",
    "process_substitution",
    "ansi_c_string",
    "translated_string",
    "arithmetic_expansion",
    "brace_expression",
}


@dataclass(frozen=True)
class Wrapper:
    """A wrapper's options, as its documentation lists them.

    ``values`` are the short letters that take a value (the rest of
    the word, or the next word), ``flags`` the short letters that take
    none, and ``attached`` the letters whose optional value can only
    be the rest of the word. ``long`` maps each long option to whether
    it takes a value in the next word; one written ``--name=value``
    never does. Any other option is unknown, so its arity is too.
    """

    values: str = ""
    flags: str = ""
    long: dict[str, bool] = field(default_factory=dict)
    attached: str = ""


_GNU = {"--help": False, "--version": False}
# Wrappers whose program follows their options.
WRAPPERS: dict[str, Wrapper] = {
    "command": Wrapper("", "pvV"),
    "coproc": Wrapper(),
    "builtin": Wrapper(),
    "exec": Wrapper("a", "cl"),
    "nice": Wrapper("n", "", {"--adjustment": True, **_GNU}),
    "nohup": Wrapper("", "", _GNU),
    # The bash keyword takes -p; GNU time's own options follow.
    "time": Wrapper(
        "of",
        "apqvV",
        {
            "--format": True,
            "--output": True,
            "--append": False,
            "--portability": False,
            "--quiet": False,
            "--verbose": False,
            **_GNU,
        },
    ),
    "sudo": Wrapper(
        # -h is --help alone and --host with a value: unknown either way.
        "CDgprRtTUu",
        "ABbEeHiKklNnPSsVv",
        {
            **dict.fromkeys(
                (
                    "--user",
                    "--group",
                    "--close-from",
                    "--chdir",
                    "--chroot",
                    "--host",
                    "--prompt",
                    "--role",
                    "--type",
                    "--other-user",
                    "--command-timeout",
                ),
                True,
            ),
            **dict.fromkeys(
                (
                    "--askpass",
                    "--background",
                    "--bell",
                    "--edit",
                    "--preserve-env",
                    "--preserve-groups",
                    "--set-home",
                    "--login",
                    "--no-update",
                    "--non-interactive",
                    "--remove-timestamp",
                    "--reset-timestamp",
                    "--shell",
                    "--stdin",
                    "--validate",
                    "--list",
                ),
                False,
            ),
            **_GNU,
        },
    ),
    "timeout": Wrapper(
        "sk",
        "fpv",
        {
            "--signal": True,
            "--kill-after": True,
            "--foreground": False,
            "--preserve-status": False,
            "--verbose": False,
            **_GNU,
        },
    ),
    "xargs": Wrapper(
        "adEILnPs",
        "0oprtx",
        {
            **dict.fromkeys(
                (
                    "--arg-file",
                    "--delimiter",
                    "--max-args",
                    "--max-procs",
                    "--max-chars",
                    "--process-slot-var",
                ),
                True,
            ),
            # Their values are optional, so only ever written with "=".
            **dict.fromkeys(
                (
                    "--eof",
                    "--replace",
                    "--max-lines",
                    "--null",
                    "--interactive",
                    "--no-run-if-empty",
                    "--exit",
                    "--verbose",
                    "--show-limits",
                    "--open-tty",
                ),
                False,
            ),
            **_GNU,
        },
        attached="eil",
    ),
    "stdbuf": Wrapper(
        "ioe", "", {"--input": True, "--output": True, "--error": True, **_GNU}
    ),
}
POSITIONAL = {"timeout": 1}


def wrapper_option(wrapper: Wrapper, word: str) -> int | None:
    """How many words option ``word`` uses, or None when it is unknown.

    A long option may be cut to any prefix that names one option,
    as getopt allows. In a cluster of short letters, a letter that
    takes a value takes the rest of the word, or the next word; a
    letter the table does not list makes the whole word unknown.
    """
    if word.startswith("--"):
        name = word.split("=", 1)[0]
        found = [k for k in wrapper.long if k.startswith(name)]
        exact = name in wrapper.long
        if not exact and len(found) != 1:
            return None
        takes = wrapper.long[name if exact else found[0]]
        return 2 if takes and "=" not in word else 1
    used: int | None = 1 if len(word) > 1 else None
    for position, letter in enumerate(word[1:], start=1):
        if letter in wrapper.values:
            used = 2 if position == len(word) - 1 else 1
            break
        if letter in wrapper.attached or letter not in wrapper.flags:
            used = 1 if letter in wrapper.attached else None
            break
    return used


# env's options, as the short letter each stands for ("" for none).
ENV_LONG = {
    "--chdir": "C",
    "--unset": "u",
    "--split-string": "S",
    "--ignore-environment": "i",
    "--null": "0",
    "--debug": "v",
    "--help": "",
    "--version": "",
}
ENV_FLAGS = "i0v"
ENV_VALUES = "CuS"
RUNNERS = frozenset({"poetry", "pipenv", "pdm", "hatch", "rye"})
PY_INFO = frozenset(
    {
        "-h",
        "-?",
        "--help",
        "--help-all",
        "--help-env",
        "--help-xoptions",
        "-V",
        "-VV",
        "--version",
    }
)
# Builtins that assign their NAME=value words.
DECLARATIONS = frozenset({"export", "declare", "typeset", "local", "readonly"})
IGNORE_MARK = "python-path-audit: ignore"
UNREAD_WRAPPER = (
    "the command a wrapper runs is not read (env -S, or an option the "
    "scan does not know)"
)
UNSETTLED_ENV = (
    "env -i, -u, - or a NAME= word the scan cannot read changes the uv settings"
)
# A NAME=value word the scan cannot read keeps its source, quotes and
# all, behind a leading NUL.
UNREAD_ASSIGNMENT = re.compile(r"\x00[\"']?([A-Za-z_]\w*)=")
# A shell prefix assignment as written: an unquoted name, perhaps a
# subscript, then = or +=.
SHELL_ASSIGNMENT = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)(\[[^]]*\])?(\+?)=")


def reads_assignments(word: str) -> str | None:
    """How NAME=value words after wrapper ``word`` are read, if at all.

    "sudo": sudo reads any word holding "=" (``assigned_name``).
    "shell": after the bash keywords ``time`` and ``coproc`` a word is
    a prefix assignment only when, as written, it opens with a name
    and "=" or "+="; ``/opt/runtime=3/bin/python3`` is the program.
    None: any other wrapper runs such a word as its program.
    """
    if word.rsplit("/", 1)[-1] == "sudo":
        return "sudo"
    return "shell" if word in ("time", "coproc") else None


def wrapper_assignment(
    mode: str | None, text: str, source: str
) -> tuple[str, str | None] | None:
    """The (name, value) a word after a wrapper sets; None if it sets none.

    ``mode`` is what ``reads_assignments`` gave for the wrapper,
    ``text`` the word as the scan reads it and ``source`` as written.
    The value is None when the scan cannot read it, a += or an array
    element included.
    """
    unread = text.startswith("\x00")
    if mode == "shell":
        found = SHELL_ASSIGNMENT.match(source)
        if found is None:
            return None
        appends = bool(found.group(2) or found.group(3))
        value = None if unread or appends else text.partition("=")[2]
        return found.group(1), value
    name = assigned_name(text) if mode == "sudo" else None
    if name is None:
        return None
    return name, None if unread else text.partition("=")[2]


def assigned_name(word: str) -> str | None:
    """The name a NAME=value word sets for env or sudo; None if not one.

    Both read any word holding "=" as an assignment. A literal word's
    quotes are already gone, so its name is kept exactly as written:
    ``"'UV_PYTHON=x"`` sets a name starting with an apostrophe. Only
    the source of an unread word may open with a quote.
    """
    if word.startswith("\x00"):
        found = UNREAD_ASSIGNMENT.match(word)
        return found.group(1) if found else None
    name, equals, _value = word.partition("=")
    return name if equals else None


@dataclass
class EnvOptions:
    """What one or more ``env`` wrappers do to the program they run.

    ``names`` holds each NAME=value word, the last one winning, with
    None for a value the scan cannot read. ``unsettled`` is set by
    ``-i``, ``-u``, ``-`` and an unread NAME= word: they change uv
    settings in ways the scan does not follow, but cannot add to
    Python's ``sys.path``.
    """

    end: int = 0  # index past the options and NAME=value words; -1: unread
    unsettled: bool = False
    names: dict[str, str | None] = field(default_factory=dict)
    # Names that reach the program from outside the wrappers; None: all.
    kept: frozenset[str] | None = None
    # Indices of the NAME=value words env or sudo reads, in order.
    words: list[int] = field(default_factory=list)
    # Those the shell itself assigns (after time or coproc): it
    # expands a leading ~ in them, as in any assignment.
    shell_words: frozenset[int] = frozenset()


def env_long(option: str) -> str | None:
    """The letter of an env long option or a getopt abbreviation; None if unknown."""
    name = option.split("=", 1)[0]
    if name in ENV_LONG:
        return ENV_LONG[name]
    found = [v for k, v in ENV_LONG.items() if k.startswith(name)]
    return found[0] if len(name) > 2 and len(found) == 1 else None


def parse_env(
    texts: list[str], i: int, into: EnvOptions | None = None
) -> EnvOptions:
    """Read env's options and NAME=value words from ``texts[i]`` on.

    ``end`` is -1 when env's program cannot be found: ``-S`` in any
    spelling, or an option env does not have. A word the scan cannot
    read starts with NUL and ends the options.
    """
    out = into if into is not None else EnvOptions()
    while i < len(texts):
        t = texts[i]
        if t == "--":
            i += 1
            break
        if t == "-":
            out.unsettled = True
            i += 1
            continue
        if not t.startswith("-"):
            break
        i += 1
        if t.startswith("--"):
            letter = env_long(t)
            if letter is None or letter == "S":
                out.end = -1
                return out
            if letter in ("C", "u") and "=" not in t:
                i += 1
            out.unsettled |= letter in ("i", "u")
            continue
        for position, letter in enumerate(t[1:], start=1):
            if letter in ENV_VALUES:
                if letter == "S":
                    out.end = -1
                    return out
                out.unsettled |= letter == "u"
                i += 0 if t[position + 1 :] else 1
                break
            if letter not in ENV_FLAGS:
                out.end = -1
                return out
            out.unsettled |= letter == "i"
    while i < len(texts):
        found = assigned_name(texts[i])
        if found is None:
            break
        unread = texts[i].startswith("\x00")
        out.unsettled |= unread
        out.names[found] = None if unread else texts[i].partition("=")[2]
        out.words.append(i)
        i += 1
    out.end = i
    return out


def kept_names(name: str, options: list[str]) -> frozenset[str] | None:
    """The names ``sudo`` or ``exec -c`` lets through; None when all pass.

    sudo resets the environment unless told to keep it (``-E``,
    ``--preserve-env[=LIST]``); ``exec -c`` clears it.
    """
    wrapper = WRAPPERS[name]
    kept: set[str] = set()
    cleared = name == "sudo"
    i = 0
    while i < len(options) and options[i].startswith("-"):
        word = options[i]
        if word == "--":
            break
        option, equals, listed = word.partition("=")
        if option.startswith("--"):
            found = [k for k in wrapper.long if k.startswith(option)]
            if found == ["--preserve-env"] and not equals:
                return None
            if found == ["--preserve-env"]:
                kept.update(listed.split(","))
        else:
            letters = re.split(f"[{wrapper.values}]", word[1:])[0]
            if name == "sudo" and "E" in letters:
                return None
            cleared |= "c" in letters
        i += wrapper_option(wrapper, word) or 1
    return frozenset(kept) if cleared else None


def env_of(
    texts: list[str], sources: list[str], into: EnvOptions | None = None
) -> EnvOptions:
    """What the wrappers among ``texts`` do to the environment, merged into ``into``.

    env's options and NAME=value words, those after sudo, ``time`` or
    ``coproc`` (``reads_assignments``), and
    the environment sudo or ``exec -c`` drops. A wrapper's options and
    their operands are skipped by its table, so ``exec -a NAME=1``
    sets nothing. ``sources`` holds each word as written.
    """
    out = into if into is not None else EnvOptions()
    i = 0
    assigns: str | None = None  # how the wrapper read last takes NAME=value
    while i < len(texts):
        # An assignment comes first: sudo's A=b/env sets A, as in
        # skip_wrappers, and runs no env.
        found = wrapper_assignment(assigns, texts[i], sources[i])
        if found is not None:
            out.unsettled |= found[1] is None
            out.names[found[0]] = found[1]
            out.words.append(i)
            if assigns == "shell":
                out.shell_words = out.shell_words | {i}
            i += 1
            continue
        name = texts[i].rsplit("/", 1)[-1]
        if name == "env":
            i = parse_env(texts, i + 1, out).end
            assigns = None
            if i < 0:
                break
            continue
        if name in WRAPPERS:
            if name in ("sudo", "exec"):
                kept = kept_names(name, texts[i + 1 :])
                if kept is not None:
                    out.names = {
                        k: v for k, v in out.names.items() if k in kept
                    }
                    out.kept = kept if out.kept is None else kept & out.kept
            assigns = reads_assignments(texts[i])
            if name == "xargs":
                slot = process_slot_var(texts, i + 1)
                if slot is not None:
                    # xargs gives the variable a number of its own: a
                    # value the scan does not read, for that name.
                    out.names[slot] = None
            i = skip_options(name, texts, i + 1)
            continue
        i += 1
    return out


def process_slot_var(texts: list[str], i: int) -> str | None:
    """The variable ``xargs --process-slot-var`` names, walking its options.

    Options are read by their table arities, so an earlier option's
    operand is not mistaken for one; the long name may be abbreviated
    and its value attached or separate.
    """
    xargs = WRAPPERS["xargs"]
    while i < len(texts) and texts[i].startswith("-"):
        word = texts[i]
        if word == "--":
            return None
        used = wrapper_option(xargs, word)
        if word.startswith("--"):
            name, equals, value = word.partition("=")
            if "--process-slot-var".startswith(name) and len(name) > 2:
                if equals:
                    return value
                return texts[i + 1] if i + 1 < len(texts) else None
        i += used or 1
    return None


def skip_options(name: str, texts: list[str], i: int) -> int:
    """Index past wrapper ``name``'s options and operands from ``texts[i]``."""
    while i < len(texts) and texts[i].startswith("-"):
        if texts[i] == "--":
            return i + 1
        i += wrapper_option(WRAPPERS[name], texts[i]) or 1
    return i + POSITIONAL.get(name, 0)


def looks_like_python(name: str, arguments: list[str]) -> bool:
    """Whether an unknown program name is probably Python.

    From its first argument (``-m``, ``-c``, ``-``, an interpreter
    option, or Python or uv itself, as after ``$SUDO``), a ``.py``
    file among the first four, or the name itself, whatever its case.
    """
    first = arguments[:1]
    looks = any(
        t in ("-m", "-c", "-", "-I", "-E", "-B", "-u", "-s")
        or re.fullmatch(r"-[a-zA-Z]*[mcI][a-zA-Z]*", t)
        or INTERPRETER.match(t)
        or posixpath.basename(t) in ("uv", "uvx")
        for t in first
    ) or any(t.endswith(".py") for t in arguments[:4])
    return looks or bool(re.search(r"py(?:thon)?\b|python", name, re.I))


def looks_like_uv(name: str) -> bool:
    """Whether an unknown program name is probably uv or uvx (``"$UV"``)."""
    return bool(re.search(r"(?<![A-Za-z])uvx?(?![A-Za-z])", name, re.I))


# Where hosted runners and job containers keep the workspace.
WORKSPACE_ROOTS = (
    "/home/runner/work",
    "/Users/runner/work",
    "/__w",
    "/github/workspace",
)


def is_outside_path(value: str) -> bool:
    """A literal absolute path that is surely outside the workspace.

    It starts with one ``/``, ``posixpath.normpath`` leaves it as it
    is (no ``//``, ``.`` or ``..`` parts), and it is not under a
    workspace root. An expansion or a ``${{ }}`` expression is not
    literal, whatever it names.
    """
    if not value.startswith("/") or value.startswith("//"):
        return False
    if posixpath.normpath(value) != value.rstrip("/") or EXPR_OPEN in value:
        return False
    return not any(
        value == root or value.startswith(root + "/")
        for root in WORKSPACE_ROOTS
    )


def parse_python(words: list[str]) -> tuple[str, set[str]]:
    """Mode ("module", "command", "stdin", "script", "info") and flags of ``python <words>``."""
    flags: set[str] = set()
    index = 0
    while index < len(words):
        word = words[index]
        if word in PY_INFO or word == "-":
            return ("info" if word in PY_INFO else "stdin"), flags
        if word == "--":
            following = words[index + 1 : index + 2]
            return ("stdin" if following in ([], ["-"]) else "script"), flags
        if word.startswith("--"):
            index += 2 if word == "--check-hash-based-pycs" else 1
            continue
        if not word.startswith("-") or len(word) == 1:
            return "script", flags
        mode, used = _short_options(word, flags)
        if mode:
            return mode, flags
        index += used
    return "stdin", flags


def _short_options(word: str, flags: set[str]) -> tuple[str, int]:
    """Read one word of combined short options into ``flags``.

    Returns the mode it settles ("module", "command" or "info", as
    ``-m``, ``-c``, ``-h``/``-V``/``-?`` do, in that order of reading)
    and how many words the options use: two when ``-W``/``-X`` ends
    the word and takes the next.
    """
    for position, letter in enumerate(word[1:], start=1):
        if letter in "mc":
            return ("module" if letter == "m" else "command"), 1
        if letter in "hV?":
            return "info", 1  # -BV, -Bh: print and exit
        if letter in "WX":
            return "", 2 if position == len(word) - 1 else 1
        flags.add(letter)
    return "", 1


def risky(mode: str, flags: set[str]) -> bool:
    return "I" not in flags and mode not in ("info", "script")
