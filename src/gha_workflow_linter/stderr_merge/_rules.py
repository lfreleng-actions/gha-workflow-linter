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
LOGGERS = frozenset({"echo", "printf", "logger", ":", "true"})
# Loggers that print nothing on stdout: ``:`` and ``true`` ignore their
# words, and ``logger`` sends them to the system log.
SILENT = frozenset({"logger", ":", "true"})
# Commands that end a loop or script; their argument is a status, so a
# merged value passed to one is data, but a loop body may run them.
EXITS = frozenset({"exit", "return"})
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
# A backslash escapes the next character, a delimiter included, as in
# ``s/a\/b/x/p``.
SED_PRINT = re.compile(
    r"(?:^|[;{}\s])(?:/(?:\\.|[^/\\])*/|\d+|\$)?\s*p\s*(?:[;}]|$)"
    r"|s([^\\\n])(?:\\.|(?!\1)[^\\])*\1(?:\\.|(?!\1)[^\\])*\1[0-9gIiMme]*p"
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


def _own_options(
    args: list[str], operands: frozenset[str], ends: frozenset[str]
) -> list[str]:
    """A tool's own options, before the program or command it runs.

    They stop at the first operand, at ``--``, and at an option in
    ``ends`` that names the program, such as ``java -jar app.jar``;
    the operand of an option in ``operands`` is skipped.
    """
    found: list[str] = []
    rest = iter(args)
    for arg in rest:
        if arg == "--" or not arg.startswith("-") or arg in ends:
            break
        found.append(arg)
        if arg in operands:
            next(rest, None)
    return found


# java's options that take the next word as their value.
JAVA_OPERANDS = frozenset(
    {
        "-cp",
        "-classpath",
        "--class-path",
        "-p",
        "--module-path",
        "--upgrade-module-path",
        "--add-modules",
        "--enable-native-access",
        "--add-reads",
        "--add-exports",
        "--add-opens",
        "--limit-modules",
        "--patch-module",
        "--source",
    }
)
# java options after which the words belong to the application.
JAVA_ENDS = frozenset({"-jar", "-m", "--module"})
# ssh's own options that take a value; all its other letters are flags.
SSH_OPERANDS = "BbcDEeFIiJLlmOoPpQRSWw"


def _java_reports(args: list[str]) -> bool:
    """Whether java's own options ask for its version or settings."""
    own = _own_options(args, JAVA_OPERANDS, JAVA_ENDS)
    return _has_flag(own, "-version") or any(
        x.startswith("-XshowSettings") for x in own
    )


def _javac_reports(args: list[str]) -> bool:
    """Whether javac is asked for its version or java's settings."""
    return _has_flag(args, "-version") or any(
        x.startswith("-XshowSettings") for x in args
    )


def _ssh_version(args: list[str]) -> bool:
    """Whether ssh's own options, before the destination, hold ``-V``.

    A ``-V`` after the destination belongs to the remote command.
    """
    rest = iter(args)
    for arg in rest:
        if arg == "--" or not arg.startswith("-") or arg == "-":
            return False
        for index, letter in enumerate(arg[1:], start=1):
            if letter == "V":
                return True
            if letter in SSH_OPERANDS:
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
    # Java prints -version and -XshowSettings reports on stderr, when
    # they are java's own options and not the application's.
    ByDesign(re.compile(r"^java$"), _java_reports),
    ByDesign(re.compile(r"^javac$"), _javac_reports),
    # Python 2 and some Python 3 builds print the version on stderr.
    ByDesign(PYTHON, _python_version),
    # Some libcs' ldd prints its version on stderr.
    ByDesign(re.compile(r"^ldd$"), lambda a: _has_flag(a, "--version")),
    # OpenSSH prints its version on stderr only.
    ByDesign(re.compile(r"^ssh$"), _ssh_version),
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


def _python_mode(args: list[str]) -> tuple[str, str, list[str]]:
    """What python runs, read from its own options as python reads them.

    ``("c", code, rest)`` for ``-c``, ``("m", module, rest)`` for ``-m``,
    ``("-", "", rest)`` for a program on stdin, ``("script", path,
    rest)`` for a file, and ``("", "", [])`` for none. A value may be
    attached, as in ``-mjson.tool`` or ``-c'print(1)'``, or follow in
    the next word; ``-W`` and ``-X`` take one the same way.
    """
    rest = iter(args)
    for arg in rest:
        if arg == "--":
            break
        if arg == "-":
            return "-", "", list(rest)
        if not arg.startswith("-"):
            return "script", arg, list(rest)
        if arg.startswith("--"):
            if arg == "--check-hash-based-pycs":
                next(rest, None)
            continue
        for index, letter in enumerate(arg[1:], start=1):
            if letter not in "cmWX":
                continue
            value = arg[index + 1 :] or next(rest, "")
            if letter in "cm":
                return letter, value, list(rest)
            break
    found = list(rest)
    if not found:
        return "", "", []
    if found[0] == "-":
        return "-", "", found[1:]
    return "script", found[0], found[1:]


def _python_parses(args: list[str]) -> bool:
    """Whether python reads its input as a program or as JSON."""
    mode, value, _ = _python_mode(args)
    return mode in ("c", "-") or (mode == "m" and value == "json.tool")


def _node_evaluates(args: list[str]) -> bool:
    """Whether node's own options give it a program to run, as ``-e``."""
    seen = scan_options(args, NODE_INPUTS_SPEC).seen
    return bool(seen & {"-e", "-p", "--eval", "--print"})


def _base64_decodes(args: list[str]) -> bool:
    """Whether base64's options, clusters such as ``-di`` included, decode."""
    seen = scan_options(args, INPUTS["base64"]).seen
    return bool(seen & {"-d", "-D", "--decode"})


def _sed_extracts(args: list[str]) -> bool:
    """Whether sed prints only what its script selects.

    A script attached to ``-e``, as in ``-e's/^/warning: /'``, is the
    script, not a cluster of option letters.
    """
    scan = scan_options(args, INPUTS["sed"])
    if scan.seen & {"-n", "--quiet", "--silent"}:
        return True
    return any(SED_PRINT.search(script) for script in programs("sed", args))


def _grep_kind(args: list[str]) -> str:
    """What grep does with its input: test it, extract from it, or filter it."""
    seen = scan_options(args, INPUTS["grep"]).seen
    if seen & {"-q", "--quiet", "--silent"}:
        return "exists"
    if seen & {"-o", "--only-matching"}:
        return "extractor"
    return "picker"


def _line_count(args: list[str]) -> str | None:
    """The count head or tail prints, from the last count option given.

    ``-1``, ``-n 1``, ``-n1``, ``--lines 1`` and ``--lines=1`` all give
    one line; ``head -n 1 -n 10`` prints ten, as the last one wins. A
    later byte count (``-c``, ``--bytes``) replaces a line count, so it
    gives None, as does no count at all.
    """
    count: str | None = None
    rest = iter(args)
    for arg in rest:
        if arg == "--":
            break
        if arg == "-" or not arg.startswith("-"):
            continue
        if arg.startswith("--"):
            name, equals, value = arg.partition("=")
            if name in ("--lines", "--bytes"):
                value = value if equals else next(rest, "")
                count = value if name == "--lines" else None
            continue
        if arg[1:].isdigit():
            count = arg[1:]
            continue
        for index, letter in enumerate(arg[1:], start=1):
            if letter in "nc":
                value = arg[index + 1 :] or next(rest, "")
                count = value if letter == "n" else None
                break
    return count


def _lines_kind(args: list[str]) -> str:
    """Head or tail: one line is a pick, more lines are for the log."""
    return "picker" if _line_count(args) == "1" else "pass"


def _parser_if(
    test: Callable[[list[str]], bool],
) -> Callable[[list[str]], str | None]:
    """A kind test: ``parser`` when ``test`` holds, else unknown."""
    return lambda args: "parser" if test(args) else None


# Kinds that depend on the command's options as well as its name.
OPTION_KINDS: dict[str, Callable[[list[str]], str | None]] = {
    "node": _parser_if(_node_evaluates),
    "nodejs": _parser_if(_node_evaluates),
    "base64": _parser_if(_base64_decodes),
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
    ``ready`` (a ``read -t 0`` test for input), ``picker`` (data only
    when its own output is kept), ``pass`` (the stream goes on for
    display), or None when the command is unknown.
    """
    if name == "read" and readiness_test(args):
        return "ready"
    if name in PARSERS:
        return "parser"
    if name in EXTRACTORS:
        return "extractor"
    if name in PICKERS:
        return "picker"
    if name in PASSTHROUGH:
        return "pass"
    return _named_kind(name, args)


@dataclass(frozen=True)
class Inputs:
    """How a command's words say where it reads its input from.

    ``short`` holds the letters of short options that take an operand,
    and ``long`` the long options with how many operands each takes.
    A letter in ``attached`` takes an optional operand, only from the
    rest of its cluster, as sed's ``-i.bak``. The first ``program``
    operands are the filter, pattern or script, unless an option in
    ``from_option`` supplies it; the value of an option in ``inline``
    is that text itself, as grep's ``-e PATTERN``. An option in
    ``null`` means the command reads no input, unless ``explicit`` is
    set and its filter reads input itself, as jq's ``inputs``; one in
    ``stdin`` means its operands are not files. At most ``inputs``
    operands are read, when it is set: ``uniq in out`` writes to
    ``out``, and every operand of ``xargs`` is the command it runs.
    With ``ordered``, options end at the first operand, as for
    ``xargs``, whose options stop where its command begins.
    """

    short: str = ""
    long: tuple[tuple[str, int], ...] = ()
    attached: str = ""
    program: int = 0
    from_option: frozenset[str] = frozenset()
    inline: frozenset[str] = frozenset()
    null: frozenset[str] = frozenset()
    explicit: bool = False
    stdin: frozenset[str] = frozenset()
    inputs: int | None = None
    ordered: bool = False


# A name in a jq filter, which may call ``input`` or ``inputs`` and so
# read input under ``-n``, or a mark that says whether it is a key.
JQ_TOKEN = re.compile(
    r"(?<![\w$.@])(?P<name>[A-Za-z_]\w*)|(?P<mark>[{}()\[\],:])"
)
JQ_INPUTS = Inputs(
    short="fL",
    long=(
        ("--arg", 2),
        ("--argjson", 2),
        ("--slurpfile", 2),
        ("--rawfile", 2),
        ("--from-file", 1),
        ("--indent", 1),
        ("--library-path", 1),
    ),
    program=1,
    from_option=frozenset({"-f", "--from-file"}),
    null=frozenset({"-n", "--null-input"}),
    explicit=True,
    stdin=frozenset({"--args", "--jsonargs"}),
)
GREP_INPUTS = Inputs(
    short="efmABCdD",
    long=(
        ("--regexp", 1),
        ("--file", 1),
        ("--max-count", 1),
        ("--after-context", 1),
        ("--before-context", 1),
        ("--context", 1),
        ("--include", 1),
        ("--exclude", 1),
        ("--exclude-from", 1),
        ("--exclude-dir", 1),
        ("--label", 1),
        ("--binary-files", 1),
        ("--devices", 1),
        ("--directories", 1),
        ("--group-separator", 1),
    ),
    program=1,
    from_option=frozenset({"-e", "-f", "--regexp", "--file"}),
    inline=frozenset({"-e", "--regexp"}),
)
AWK_INPUTS = Inputs(
    short="fvFeEi",
    long=(
        ("--file", 1),
        ("--assign", 1),
        ("--field-separator", 1),
        ("--source", 1),
        ("--exec", 1),
        ("--include", 1),
    ),
    program=1,
    from_option=frozenset({"-f", "--file", "-e", "--source", "-E", "--exec"}),
    inline=frozenset({"-e", "--source"}),
)
# Where each command that names input files finds them. A command not
# here is taken to read its stdin.
INPUTS: dict[str, Inputs] = (
    {
        "jq": JQ_INPUTS,
        "xq": JQ_INPUTS,
        "tomlq": JQ_INPUTS,
        # mikefarah's yq and the Python yq read their options differently,
        # so only null input and a filter file are read from their words:
        # any operand may be the expression.
        "yq": Inputs(
            short="f",
            long=(("--from-file", 1),),
            from_option=frozenset({"-f", "--from-file"}),
            null=frozenset({"-n", "--null-input"}),
            explicit=True,
            inputs=0,
        ),
        "sed": Inputs(
            short="efl",
            long=(("--expression", 1), ("--file", 1), ("--line-length", 1)),
            attached="i",
            program=1,
            from_option=frozenset({"-e", "-f", "--expression", "--file"}),
            inline=frozenset({"-e", "--expression"}),
        ),
        "cut": Inputs(
            short="bcdf",
            long=(
                ("--bytes", 1),
                ("--characters", 1),
                ("--delimiter", 1),
                ("--fields", 1),
                ("--output-delimiter", 1),
            ),
        ),
        "sort": Inputs(
            short="kotST",
            long=(
                ("--key", 1),
                ("--output", 1),
                ("--field-separator", 1),
                ("--buffer-size", 1),
                ("--temporary-directory", 1),
            ),
        ),
        "uniq": Inputs(
            short="fsw",
            long=(
                ("--skip-fields", 1),
                ("--skip-chars", 1),
                ("--check-chars", 1),
            ),
            inputs=1,
        ),
        "head": Inputs(short="nc", long=(("--lines", 1), ("--bytes", 1))),
        "tail": Inputs(short="nc", long=(("--lines", 1), ("--bytes", 1))),
        "base64": Inputs(short="w", long=(("--wrap", 1),)),
        "cat": Inputs(),
        "xmllint": Inputs(
            short="o",
            long=(
                ("--xpath", 1),
                ("--schema", 1),
                ("--relaxng", 1),
                ("--dtdvalid", 1),
                ("--dtdvalidfpi", 1),
                ("--schematron", 1),
                ("--output", 1),
                ("--encode", 1),
                ("--path", 1),
                ("--pattern", 1),
                ("--maxmem", 1),
            ),
        ),
        # Every operand of xargs is the command it runs, and the options
        # after it are that command's.
        "xargs": Inputs(
            short="aEdILnPs",
            long=(
                ("--arg-file", 1),
                ("--delimiter", 1),
                ("--max-args", 1),
                ("--max-chars", 1),
                ("--max-procs", 1),
                ("--process-slot-var", 1),
            ),
            attached="eil",
            null=frozenset({"-a", "--arg-file"}),
            inputs=0,
            ordered=True,
        ),
    }
    | dict.fromkeys(GREPS, GREP_INPUTS)
    | dict.fromkeys(AWKS, AWK_INPUTS)
)
# node's own options; those taking a value take the next word, and its
# options end at the script it runs.
NODE_INPUTS_SPEC = Inputs(
    short="eprC",
    long=(
        ("--eval", 1),
        ("--print", 1),
        ("--require", 1),
        ("--import", 1),
        ("--conditions", 1),
        ("--input-type", 1),
        ("--loader", 1),
        ("--experimental-loader", 1),
    ),
    ordered=True,
)
# The options of read and mapfile that take an operand, as letters.
READ_SHORT = {"read": "adinNptu", "mapfile": "dnOsuCc", "readarray": "dnOsuCc"}
# Their options and operands, read as bash reads them: options end at
# the first operand.
READ_OPTIONS = {
    name: Inputs(short=letters, ordered=True)
    for name, letters in READ_SHORT.items()
}
ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")


@dataclass(frozen=True)
class Scan:
    """A command's words, read against its :class:`Inputs`.

    ``seen`` holds the options given, ``operands`` the other words in
    order, and ``values`` each option's operands, in order, as
    (option, value) pairs.
    """

    seen: frozenset[str]
    operands: list[str]
    values: list[tuple[str, str]]


def scan_options(args: list[str], spec: Inputs) -> Scan:
    """Read a command's options and operands, as its parser would.

    Options may come anywhere before ``--``, unless ``spec.ordered``
    ends them at the first operand. A short option taking an operand
    takes the rest of its cluster, or the next word, so the letters of
    an attached operand, as in ``grep -equery``, are not options.
    """
    long = dict(spec.long)
    seen: set[str] = set()
    found: list[str] = []
    values: list[tuple[str, str]] = []
    rest = iter(args)
    for arg in rest:
        if arg == "-" or not arg.startswith("-"):
            found.append(arg)
            if spec.ordered:
                found += list(rest)
        elif arg == "--":
            found += list(rest)
        elif arg.startswith("--"):
            name, equals, value = arg.partition("=")
            seen.add(name)
            if equals:
                values.append((name, value))
            for _ in range(0 if equals else long.get(name, 0)):
                values.append((name, next(rest, "")))
        else:
            for index, letter in enumerate(arg[1:], start=1):
                option = f"-{letter}"
                seen.add(option)
                if letter in spec.short:
                    values.append((option, arg[index + 1 :] or next(rest, "")))
                    break
                if letter in spec.attached:
                    break
    return Scan(frozenset(seen), found, values)


def programs(name: str, args: list[str]) -> list[str]:
    """The filter, pattern or script texts a command's words give it.

    Empty when they come from a file, as ``sed -f script.sed``, or the
    command takes none.
    """
    spec = INPUTS.get(name)
    if spec is None:
        return operands(args)[:1]
    scan = scan_options(args, spec)
    if scan.seen & spec.from_option:
        return [value for option, value in scan.values if option in spec.inline]
    return scan.operands[: spec.program] if spec.program else scan.operands


def _read_fd(name: str, args: list[str]) -> int:
    """The descriptor ``read`` or ``mapfile`` reads: ``-u N``, else 0.

    Bash takes the last ``-u``, so ``read -u 3 -u 0`` reads stdin. A
    descriptor held in a variable cannot be known, so it counts as 0.
    """
    scan = scan_options(args, READ_OPTIONS[name])
    given = [value for option, value in scan.values if option == "-u"]
    if not given:
        return 0
    return int(given[-1]) if given[-1].isdigit() else 0


# File operands that name descriptor 0 rather than a file of their own.
STDIN_PATH = re.compile(r"-|/dev/stdin|/(?:dev|proc/self)/fd/0+")


def names_stdin(operand: str) -> bool:
    """Whether a file operand reads stdin: ``-``, ``/dev/stdin`` and the like."""
    return bool(STDIN_PATH.fullmatch(operand))


# json.tool's options that take the next word as their value.
JSON_TOOL_INPUTS = Inputs(long=(("--indent", 1),))


def _python_input(args: list[str]) -> int | None:
    """What python reads: ``-m json.tool``'s first operand, else stdin."""
    mode, module, rest = _python_mode(args)
    if mode != "m" or module != "json.tool":
        return 0
    files = scan_options(rest, JSON_TOOL_INPUTS).operands
    return 0 if not files or names_stdin(files[0]) else None


def _jq_code(text: str) -> str:
    """A jq filter with its string literals and comments blanked out.

    An interpolation, as in ``"\\(input)"``, is code: it stays, inside
    parentheses, so ``"a\\(input)"`` still reads input.
    """
    out: list[str] = []
    # How many parentheses each open interpolation holds.
    depths: list[int] = []
    in_string = False
    index = 0
    while index < len(text):
        char = text[index]
        pair = text[index : index + 2]
        if in_string and pair == "\\(":
            out.append(" (")
            depths.append(0)
            in_string = False
            index += 2
        elif in_string and char == "\\":
            out.append(" " * len(pair))
            index += 2
        elif in_string:
            in_string = char != '"'
            out.append(" ")
            index += 1
        elif char == "#":
            end = text.find("\n", index)
            end = len(text) if end < 0 else end
            out.append(" " * (end - index))
            index = end
        else:
            if char == '"':
                in_string, char = True, " "
            elif depths and char == "(":
                depths[-1] += 1
            elif depths and char == ")":
                depths[-1] -= 1
                if depths[-1] < 0:
                    depths.pop()
                    in_string = True
            out.append(char)
            index += 1
    return "".join(out)


def _jq_reads(text: str) -> bool:
    """Whether a jq filter calls ``input`` or ``inputs``.

    A name in a string literal, a comment or an object key, as in
    ``{input: 1}`` or ``{input}``, is not a call; one in a value or in
    a computed key, as in ``{(input): 1}``, is.
    """
    # Per open bracket: ``key`` or ``value`` in an object, else ``other``.
    frames: list[str] = []
    for token in JQ_TOKEN.finditer(_jq_code(text)):
        mark = token.group("mark")
        if mark is None:
            key = bool(frames) and frames[-1] == "key"
            if token.group("name") in ("input", "inputs") and not key:
                return True
        elif mark in "{([":
            frames.append("key" if mark == "{" else "other")
        elif mark in "})]":
            if frames:
                frames.pop()
        elif frames and frames[-1] != "other":
            frames[-1] = "key" if mark == "," else "value"
    return False


def _reads_explicitly(scan: Scan, spec: Inputs) -> bool:
    """Whether a null-input filter reads input itself, as ``[inputs]``.

    A filter read from a file cannot be seen, so it counts as reading.
    """
    if not spec.explicit:
        return False
    if scan.seen & spec.from_option:
        return True
    filters = scan.operands[: spec.program] if spec.program else scan.operands
    return any(_jq_reads(text) for text in filters)


def input_fd(name: str, args: list[str]) -> int | None:
    """The descriptor a command reads its input from, if any.

    None when it reads only files it names, as ``jq . clean.json``, or
    nothing, as ``jq -n``. ``-`` names stdin. ``read -u 3`` reads
    descriptor 3. A command whose words the check cannot read is taken
    to read its stdin.
    """
    if name in READ_SHORT:
        return _read_fd(name, args)
    if PYTHON.match(name):
        return _python_input(args)
    spec = INPUTS.get(name)
    if spec is None:
        return 0
    scan = scan_options(args, spec)
    seen, found = scan.seen, scan.operands
    if seen & spec.null and not _reads_explicitly(scan, spec):
        return None
    if seen & spec.stdin:
        return 0
    files = found[0 if seen & spec.from_option else spec.program :]
    if spec.inputs is not None:
        files = files[: spec.inputs]
    if name in AWKS:
        files = [f for f in files if not ASSIGNMENT.match(f)]
    return 0 if not files or any(names_stdin(f) for f in files) else None


def reads_stdin(name: str, args: list[str]) -> bool:
    """Whether a command reads its stdin rather than files it names.

    In ``a | cat clean.json`` or ``a | jq . clean.json`` the pipe goes
    unread, as it does for ``jq -n`` and ``read -u 3``.
    """
    return input_fd(name, args) == 0


def read_names(args: list[str]) -> list[str]:
    """The variables a ``read`` command sets, ``REPLY`` when it names none.

    ``-a NAME`` sets an array, attached as in ``-as`` or in the next
    word, and then the names after the options are left alone: ``read
    -a arr s`` sets only ``arr``. Bash takes the last ``-a``. The other
    options' operands, as ``-p PROMPT``, set nothing.
    """
    scan = scan_options(args, READ_OPTIONS["read"])
    arrays = [value for option, value in scan.values if option == "-a"]
    return arrays[-1:] or scan.operands or ["REPLY"]


def _mapfile_names(name: str, args: list[str]) -> list[str]:
    """The array ``mapfile`` or ``readarray`` fills, ``MAPFILE`` by default.

    Option operands, as the ``1`` of ``-n 1``, are not the array.
    """
    return scan_options(args, READ_OPTIONS[name]).operands[:1] or ["MAPFILE"]


IDENTIFIER = re.compile(r"(?<![\w$])[A-Za-z_][A-Za-z0-9_]*")


def written_names(name: str, args: list[str]) -> list[str]:
    """The variables a built-in sets through its words, not ``v=...``.

    ``read``, ``mapfile``, ``printf -v`` and ``getopts`` set the names
    they are given; every name in the words of ``let`` and ``eval`` is
    taken to be set, since their text is code.
    """
    if name == "read":
        return read_names(args)
    if name in ("mapfile", "readarray"):
        return _mapfile_names(name, args)
    if name == "printf":
        return _printf_target(args)
    if name == "getopts":
        return operands(args)[1:2]
    if name in ("let", "eval"):
        return [found for arg in args for found in IDENTIFIER.findall(arg)]
    return []


# A literal ``read -t`` timeout above zero: ``-t 0`` only tests for input.
POSITIVE_TIMEOUT = re.compile(r"^(?=.*[1-9])[0-9]*\.?[0-9]*$")
# A literal ``read -t`` timeout of zero, as ``0`` or ``0.0``.
ZERO_TIMEOUT = re.compile(r"^(?=.*0)0*\.?0*$")


def _timeout(args: list[str]) -> str | None:
    """The timeout ``read -t`` is given, the last one winning."""
    scan = scan_options(args, READ_OPTIONS["read"])
    timeouts = [value for option, value in scan.values if option == "-t"]
    return timeouts[-1] if timeouts else None


def readiness_test(args: list[str]) -> bool:
    """Whether a ``read`` only tests for input, as ``read -t 0`` does.

    With a zero timeout Bash neither consumes the input nor sets a
    name; it returns whether input is waiting.
    """
    timeout = _timeout(args)
    return timeout is not None and bool(ZERO_TIMEOUT.match(timeout))


def overwritten_names(name: str, args: list[str]) -> list[str]:
    """The variables a built-in surely replaces, whatever it reads.

    ``read`` and ``mapfile`` clear the names they set even when they
    read nothing, and ``printf -v`` always sets its name. ``read -t 0``
    only tests for input and sets nothing, so a timeout that is not a
    literal above zero makes the write a possible one. ``mapfile -O N``
    keeps the elements it does not reach, ``N`` 0 included when nothing
    is read. ``-u N`` names a descriptor that may be closed, and then
    the built-in fails and sets nothing, so only stdin makes the write
    a sure one.
    """
    if name in READ_SHORT:
        scan = scan_options(args, READ_OPTIONS[name])
        given = [value for option, value in scan.values if option == "-u"]
        if given and given[-1] != "0":
            return []
    if name == "read":
        timeout = _timeout(args)
        if timeout is not None and not POSITIVE_TIMEOUT.match(timeout):
            return []
    elif name in ("mapfile", "readarray"):
        if "-O" in scan_options(args, READ_OPTIONS[name]).seen:
            return []
    elif name != "printf":
        return []
    return written_names(name, args)


# printf's one option that takes a value; its options end at the format.
PRINTF_OPTIONS = Inputs(short="v", ordered=True)


def _printf_target(args: list[str]) -> list[str]:
    """The variable ``printf -v NAME`` sets, if it is given one.

    Options end at the format string or ``--``: ``printf '%s' -v s``
    prints ``-v s`` and sets nothing.
    """
    scan = scan_options(args, PRINTF_OPTIONS)
    return [value for option, value in scan.values if option == "-v"][-1:]


# A regular expression anchored at the start of the line, with no
# alternation that could match elsewhere: ``^a|b`` matches any ``b``.
ANCHORED_REGEX = r"/\^(?:[^/\\|\n]|\\[^|\n])*/"


def _sed_substitute(group: str, pattern: str) -> str:
    """A sed s command whose pattern matches ``pattern``.

    Its flags may print or repeat it, but not run the line as a command
    (``e``) or write it to a file (``w``).
    """
    delimiter = f"(?P={group})"
    body = rf"(?:(?!{delimiter})[^\\\n]|\\[^\n])*"
    return (
        rf"s(?P<{group}>[^\\\n\s]){pattern}{delimiter}{body}{delimiter}"
        r"[0-9gIiMmp]*"
    )


def _sed_action(group: str) -> str:
    """A sed command that prints, edits or drops the line it is given.

    Each keeps to that line: ``n``, ``N``, ``G`` and the like bring in
    another one, which need not carry the prefix.
    """
    body = rf"(?:(?!(?P={group}))[^\\\n]|\\[^\n])*"
    return rf"(?:[pPd=]|[qQ]\s*\d*|{_sed_substitute(group, body)})"


# One sed command that acts only on lines with a fixed prefix: an s
# command whose pattern starts with ^, or a /^.../ address, not negated,
# with the command or block of such commands it governs.
ANCHORED_SED_PATTERN = r"\^(?:(?!(?P=a))[^|\\\n]|\\[^|\n])*"
SED_COMMAND = re.compile(
    rf"\s*(?:{_sed_substitute('a', ANCHORED_SED_PATTERN)}"
    rf"|{ANCHORED_REGEX}\s*(?:\{{(?:\s*{_sed_action('b')}\s*;?)+\s*\}}"
    rf"|{_sed_action('c')}))"
)
# One awk rule that prints nothing from a line without the prefix: a
# /^.../ pattern, with or without an action, or a BEGIN block.
AWK_RULE = re.compile(
    rf"\s*(?:BEGIN\s*\{{[^{{}}]*\}}|{ANCHORED_REGEX}\s*(?:\{{[^{{}}]*\}})?)"
)
# awk text that reads a line no pattern tested, or changes what a
# line is: ``getline`` and the record separator.
AWK_UNANCHORED = re.compile(r"\bgetline\b|\bRS\b")
SEPARATOR = re.compile(r"\s*[;\n]?")


def _only(command: re.Pattern[str], text: str) -> bool:
    """Whether ``text`` is one or more ``command``, separated by ; or lines."""
    position = 0
    end = len(text.rstrip())
    while position < end:
        found = command.match(text, position)
        if found is None or found.end() == position:
            return False
        gap = SEPARATOR.match(text, found.end())
        position = found.end() if gap is None else gap.end()
    return end > 0


# grep options under which a leading ^ does not limit what is printed:
# inverted and fixed-string matching, patterns read from a file, the
# context lines around a match, and NUL-separated records, which hold
# many lines each.
GREP_UNANCHORED = frozenset(
    {
        "-v",
        "--invert-match",
        "-F",
        "--fixed-strings",
        "-f",
        "--file",
        "-A",
        "--after-context",
        "-B",
        "--before-context",
        "-C",
        "--context",
        "-z",
        "--null-data",
    }
)
# sed options that read a script from a file or join lines into one
# NUL-separated record.
SED_UNANCHORED = frozenset({"-f", "--file", "-z", "--null-data"})
# awk options that read a program from a file, or a library beside it.
AWK_FILES = frozenset({"-f", "--file", "-E", "--exec", "-i", "--include"})


def _grep_anchored(name: str, args: list[str]) -> bool:
    """Whether every pattern grep matches starts with ``^``.

    ``-NUM`` is a context length, as ``-C NUM``. Leading whitespace is
    part of a pattern, so ``' ^key:'`` is not anchored.
    """
    if name == "fgrep":
        return False
    seen = scan_options(args, INPUTS[name]).seen
    if seen & GREP_UNANCHORED or any(s[1:2].isdigit() for s in seen):
        return False
    texts = programs(name, args)
    return bool(texts) and all(
        line.startswith("^") and "|" not in line
        for text in texts
        for line in text.split("\n")
    )


def _sed_anchored(args: list[str]) -> bool:
    """Whether a quiet sed prints only lines with a fixed prefix.

    Without ``-n`` sed prints every line; each of its scripts must be
    made of anchored commands alone, and none may come from a file.
    """
    seen = scan_options(args, INPUTS["sed"]).seen
    if not seen & {"-n", "--quiet", "--silent"} or seen & SED_UNANCHORED:
        return False
    texts = programs("sed", args)
    return bool(texts) and all(_only(SED_COMMAND, t) for t in texts)


def _awk_anchored(args: list[str]) -> bool:
    """Whether every awk rule that reads a line needs the fixed prefix.

    A rule that reads another line with ``getline``, or a record
    separator set anywhere, prints lines no pattern tested.
    """
    scan = scan_options(args, AWK_INPUTS)
    if scan.seen & AWK_FILES:
        return False
    assigned = [v for o, v in scan.values if o in ("-v", "--assign")]
    if any(a.startswith("RS=") for a in assigned + scan.operands[1:]):
        return False
    texts = programs("awk", args)
    return (
        len(texts) == 1
        and "/^" in texts[0]
        and not AWK_UNANCHORED.search(texts[0])
        and _only(AWK_RULE, texts[0])
    )


def anchored(name: str, args: list[str]) -> bool:
    """Whether the command prints only lines with a fixed prefix.

    Every path that prints must be limited to the prefix: an inverted,
    fixed-string, file-fed or context-printing grep, a sed without
    ``-n``, a sed or awk that reads another line after the match, or a
    further unanchored sed command or awk rule prints other lines too.
    """
    if name in GREPS:
        return _grep_anchored(name, args)
    if name in AWKS:
        return _awk_anchored(args)
    if name == "sed":
        return _sed_anchored(args)
    return False
