# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""The stderr-merge rules, and the command tables they read."""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable

# Confidence levels, weakest first.
CONFIDENCES = ("low", "medium", "high")

FIX_ELSEWHERE = (
    'send stderr elsewhere: 2>"$err" (print it on failure) '
    "or leave it on the log"
)
FIX_CAPTURE = "capture stdout only; keep stderr in a file for the error message"
FIX_BY_DESIGN = (
    "merge only if the tool writes the wanted text to stderr; "
    'otherwise send stderr elsewhere: 2>"$err"'
)


@dataclass(frozen=True)
class Rule:
    """One rule: what it reports, how sure it is, and the fix it suggests."""

    title: str
    confidence: str
    fix: str


# Keep these identifiers stable once released.
RULES = {
    "SEM001": Rule(
        "merged stream piped into a structured parser", "high", FIX_ELSEWHERE
    ),
    "SEM002": Rule(
        "merged capture parsed, compared or written to $GITHUB_*",
        "high",
        FIX_CAPTURE,
    ),
    "SEM003": Rule(
        "merged stream piped into a field extractor or passed on",
        "medium",
        FIX_ELSEWHERE,
    ),
    "SEM004": Rule(
        "merged stream tested, anchored, or from a command that writes "
        "its data to stderr",
        "low",
        FIX_BY_DESIGN,
    ),
}


def rank(confidence: str) -> int:
    """A confidence's place in CONFIDENCES: higher is surer."""
    return CONFIDENCES.index(confidence)


PARSERS = frozenset({"jq", "yq", "xq", "tomlq", "xmllint"})
AWKS = frozenset({"awk", "gawk", "mawk", "nawk"})
GREPS = frozenset({"grep", "egrep", "fgrep"})
EXTRACTORS = AWKS | {"cut", "read", "mapfile", "readarray", "xargs"}
# Commands whose output is data only when it is captured or compared.
PICKERS = frozenset({"sort", "uniq"})
# Commands that pass the stream on unchanged, for display.
PASSTHROUGH = frozenset({"tee", "cat"})
LOGGERS = frozenset({"echo", "printf", "logger", ":", "true", "exit", "return"})
LOG_FUNCTION = re.compile(r"^(?:log|warn|error|die|fail|info|debug)(?:_|$)")
# Commands that run the command after their own options.
WRAPPERS = frozenset({"timeout", "sudo", "env", "nice", "stdbuf", "command"})
PYTHON = re.compile(r"^python[0-9.]*$")
# The files under these variables are read back by the runner. A word
# names one only when the whole word is the expansion, as in
# ``"$GITHUB_OUTPUT"`` or ``${GITHUB_ENV}``: ``logs/GITHUB_OUTPUT.log``
# is an ordinary file.
RUNNER_FILE = re.compile(
    r"\$(?:\{(GITHUB_(?:OUTPUT|ENV|STATE|PATH))\}"
    r"|(GITHUB_(?:OUTPUT|ENV|STATE|PATH)))"
)
# A sed script with a p command, or an s command carrying the p flag.
SED_PRINT = re.compile(
    r"(?:^|[;{}\s])(?:/[^/]*/|\d+|\$)?\s*p\s*(?:[;}]|$)"
    r"|s(.)(?:(?!\1).)*\1(?:(?!\1).)*\1[0-9gIiMme]*p"
)


def runner_file(word: str) -> str | None:
    """The ``$GITHUB_*`` file a word expands to, if it is one."""
    found = RUNNER_FILE.fullmatch(word)
    return None if found is None else found.group(1) or found.group(2)


def _has_flag(args: list[str], *flags: str) -> bool:
    """Whether any argument is one of ``flags``."""
    return any(arg in flags for arg in args)


def _first_is(args: list[str], word: str) -> bool:
    """Whether the first argument is ``word``."""
    return bool(args) and args[0] == word


def _short_flag(args: list[str], letter: str) -> bool:
    """Whether a short-option cluster (``-zv``) holds ``letter``."""
    return any(
        arg.startswith("-") and not arg.startswith("--") and letter in arg[1:]
        for arg in args
    )


def _python_version(args: list[str]) -> bool:
    """Whether python's own options ask for its version.

    A ``-V`` or ``--version`` after the script, ``-c``, ``-m`` or ``-``
    belongs to the program python runs, not to python.
    """
    rest = iter(args)
    for arg in rest:
        if arg in ("-V", "--version"):
            return True
        if arg == "--" or not arg.startswith("-") or arg == "-":
            return False
        if arg.startswith("--"):
            if arg == "--check-hash-based-pycs":
                next(rest, None)
            continue
        for index, letter in enumerate(arg[1:], start=1):
            if letter == "V":
                return True
            if letter in "cm":
                return False
            if letter in "WX":
                if index == len(arg) - 1:
                    next(rest, None)
                break
    return False


@dataclass(frozen=True)
class ByDesign:
    """A command that writes the data a step wants to stderr."""

    names: re.Pattern[str]
    applies: Callable[[list[str]], bool]


# Commands whose wanted output is on stderr, so a merge is needed.
BY_DESIGN = (
    # Java prints -version and -XshowSettings reports on stderr.
    ByDesign(
        re.compile(r"^javac?$"),
        lambda a: (
            _has_flag(a, "-version")
            or any(x.startswith("-XshowSettings") for x in a)
        ),
    ),
    # Python 2 and some Python 3 builds print the version on stderr.
    ByDesign(PYTHON, _python_version),
    # Some libcs' ldd prints its version on stderr.
    ByDesign(re.compile(r"^ldd$"), lambda a: _has_flag(a, "--version")),
    # OpenSSH prints its version on stderr only.
    ByDesign(re.compile(r"^ssh$"), lambda a: _has_flag(a, "-V")),
    # mkcert prints its version on stderr.
    ByDesign(re.compile(r"^mkcert$"), lambda a: _has_flag(a, "-version")),
    # s_client writes the handshake and certificate chain on stderr.
    ByDesign(re.compile(r"^openssl$"), lambda a: _first_is(a, "s_client")),
    # nc reports whether a port answered on stderr.
    ByDesign(
        re.compile(r"^(?:nc|ncat|netcat)$"),
        lambda a: _short_flag(a, "z") or _short_flag(a, "v"),
    ),
    # A container's stderr is part of the log docker returns.
    ByDesign(
        re.compile(r"^(?:docker|podman)$"), lambda a: _first_is(a, "logs")
    ),
)


def by_design(name: str, args: list[str]) -> bool:
    """Whether ``name args`` writes its wanted output to stderr."""
    return any(e.names.match(name) and e.applies(args) for e in BY_DESIGN)


def is_logger(name: str) -> bool:
    """Whether a command only prints for the log."""
    return name in LOGGERS or bool(LOG_FUNCTION.match(name))


def operands(args: list[str]) -> list[str]:
    """The arguments that are not options."""
    return [a for a in args if not a.startswith("-")]


def _python_parses(args: list[str]) -> bool:
    """Whether python reads its input as a program or as JSON."""
    if _has_flag(args, "-c", "-"):
        return True
    return any(
        a == "-m" and b == "json.tool"
        for a, b in zip(args, args[1:], strict=False)
    )


def _sed_extracts(args: list[str]) -> bool:
    """Whether sed prints only what its script selects."""
    if _has_flag(args, "--quiet", "--silent") or _short_flag(args, "n"):
        return True
    return any(SED_PRINT.search(script) for script in operands(args))


def _grep_options(args: list[str]) -> list[str]:
    """grep's options: what comes before ``--``, less option operands.

    The pattern given to ``-e`` and the file given to ``-f`` are not
    options, whatever letters they hold.
    """
    found: list[str] = []
    skip = False
    for arg in args:
        if skip:
            skip = False
            continue
        if arg == "--":
            break
        if arg in ("-e", "-f", "--regexp", "--file"):
            skip = True
            continue
        found.append(arg)
    return found


def _grep_kind(args: list[str]) -> str:
    """What grep does with its input: test it, extract from it, or filter it."""
    options = _grep_options(args)
    if _short_flag(options, "q") or _has_flag(options, "--quiet", "--silent"):
        return "exists"
    if _short_flag(options, "o") or _has_flag(options, "--only-matching"):
        return "extractor"
    return "picker"


def _lines_kind(args: list[str]) -> str:
    """Head or tail: one line is a pick, more lines are for the log."""
    joined = " ".join(args)
    one = re.search(r"(?:^|\s)-(?:n\s*)?1(?:\s|$)|--lines=1\b", joined)
    return "picker" if one else "pass"


def _parser_if(
    test: Callable[[list[str]], bool],
) -> Callable[[list[str]], str | None]:
    """A kind test: ``parser`` when ``test`` holds, else unknown."""
    return lambda args: "parser" if test(args) else None


# Kinds that depend on the command's options as well as its name.
OPTION_KINDS: dict[str, Callable[[list[str]], str | None]] = {
    "node": _parser_if(lambda a: _has_flag(a, "-e", "--eval", "-p")),
    "nodejs": _parser_if(lambda a: _has_flag(a, "-e", "--eval", "-p")),
    "base64": _parser_if(lambda a: _has_flag(a, "-d", "--decode", "-D")),
    "sed": lambda a: "extractor" if _sed_extracts(a) else "pass",
    "head": _lines_kind,
    "tail": _lines_kind,
} | dict.fromkeys(GREPS, _grep_kind)


def _named_kind(name: str, args: list[str]) -> str | None:
    """Kinds that depend on the command's options as well as its name."""
    if PYTHON.match(name):
        return "parser" if _python_parses(args) else None
    kind = OPTION_KINDS.get(name)
    return None if kind is None else kind(args)


def consumer_kind(name: str, args: list[str]) -> str | None:
    """What a command does with the stream it reads.

    ``parser``, ``extractor``, ``exists`` (a ``grep -q`` test),
    ``picker`` (data only when its own output is kept), ``pass`` (the
    stream goes on for display), or None when the command is unknown.
    """
    if name in PARSERS:
        return "parser"
    if name in EXTRACTORS:
        return "extractor"
    if name in PICKERS:
        return "picker"
    if name in PASSTHROUGH:
        return "pass"
    return _named_kind(name, args)


# An address range, /^a/,/^b/: it selects every line from the first
# match to the second, whatever they start with, so it is not a fixed
# prefix even when both ends are anchored.
RANGE = re.compile(r"/\^(?:[^/\\]|\\.)*/\s*,")


def anchored(name: str, args: list[str]) -> bool:
    """Whether the command selects only lines with a fixed prefix."""
    texts = operands(args)
    if not texts:
        return False
    script = texts[0].lstrip()
    if name in GREPS:
        return script.startswith("^")
    if name in AWKS:
        return script.startswith("/^") and not RANGE.match(script)
    if name == "sed":
        return bool(re.match(r"s(.)\^|/\^", script)) and not RANGE.match(script)
    return False
