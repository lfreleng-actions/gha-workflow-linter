# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Python import-path scan: discovery, per-file scan and entry point.

Reports where a workflow, composite action or shell script starts
Python or ``uv`` so that files in the working directory take part in
what runs. Run as ``python -m gha_workflow_linter.python_path._engine
PATH...``: it exits 0 when the scan is clean, 1 with findings, and 2
when it could not read a file or a path.
"""

from __future__ import annotations

import argparse
from dataclasses import asdict
import json
import os
import re
import sys
from typing import TYPE_CHECKING

import yaml

from . import _yaml
from ._block import BlockScan
from ._invocation import (
    IGNORE_MARK,
    RULES,
    expression_marker,
    is_outside_path,
)
from ._pythonpath import SELF, TEXT, UNKNOWN, WORKSPACE, Token
from ._words import Block, Finding
from ._yaml import Expr, Lit

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator, Sequence

__all__ = ["RULES", "Finding", "main", "scan", "scan_text"]

ACTION_NAMES = ("action.yml", "action.yaml")
# Shells whose scripts the scan reads, as a shebang names them.
SHELLS = frozenset({"sh", "bash", "zsh", "dash", "ksh"})
# env's split-string option, cut to any prefix getopt accepts.
SPLIT_STRING = re.compile(
    r"-[i0v]*S|--s(?:p(?:l(?:i(?:t(?:-(?:s(?:t(?:r(?:i(?:ng?)?)?)?)?)?)?)?)?)?)?(?:=|$)"
)
# How much of a file the shebang probe reads: Linux reads 255 bytes of
# a shebang line, macOS 512.
SHEBANG_BYTES = 512
SCRIPT_SUFFIXES = (".sh", ".bash")
PRUNE_DIRS = {
    ".git",
    ".hg",
    ".venv",
    "venv",
    ".tox",
    ".nox",
    "node_modules",
    "__pycache__",
    ".mypy_cache",
    ".ruff_cache",
    ".pytest_cache",
    "site-packages",
    ".wt",
}


def classify_kind(relpath: str) -> str | None:
    """Return the kind of file, or None when it is not scanned.

    ``relpath`` may use either separator, as ``os.path.relpath`` gives
    it on Windows.
    """
    relpath = relpath.replace("\\", "/")
    folder, _sep, name = f"/{relpath}".rpartition("/")
    # GitHub runs every YAML file directly in .github/workflows as a
    # workflow, action.yml included; one in a folder below is an action.
    in_workflows = folder.endswith("/.github/workflows")
    if name in ACTION_NAMES and not in_workflows:
        return "action"
    if "/.github/workflows/" in f"/{relpath}" and name.endswith(
        (".yml", ".yaml")
    ):
        return "workflow"
    if name.endswith(SCRIPT_SUFFIXES):
        return "script"
    return None


def has_shell_shebang(path: str, problems: list[str]) -> bool:
    """True for an extensionless file that starts with a shell shebang.

    The shell may follow env's options and NAME=value words, as in
    ``#!/usr/bin/env -S bash -eu``, and may be quoted. A file the scan
    cannot read is added to ``problems``: whether it is shell is then
    unknown, so the scan is incomplete.
    """
    try:
        with open(path, "rb") as handle:
            first = handle.readline(SHEBANG_BYTES)
    except OSError as error:
        problems.append(f"{path}: {error.strerror}")
        return False
    return shebang_names_shell(first.decode("utf-8", "replace"))


def shebang_names_shell(line: str) -> bool:
    """Whether a shebang line runs a shell, directly or through env.

    Reads the line word by word, each once, so a crafted line costs
    no more than its length: the interpreter, then (for env) its
    options with their operands, ``NAME=value`` words, and the shell,
    by name or path, quoted or not. The kernel splits the line on
    spaces only; env's ``-S`` then splits its operand with quotes and
    backslashes, which ``env_program`` reads.
    """
    if not line.startswith("#!"):
        return False
    words = line[2:].split()
    if not words:
        return False
    if os.path.basename(words[0]) != "env":
        return os.path.basename(words[0]) in SHELLS
    program = env_program(words[1:])
    return program is not None and os.path.basename(program) in SHELLS


# env's long options that take an operand, for unique-prefix matching.
ENV_OPERAND_LONG = ("--unset", "--chdir")


def env_split(text: str) -> list[str] | None:
    """Split an ``env -S`` operand as GNU env does; None when unbalanced.

    Quotes group (inside single quotes only ``\\'`` and ``\\\\`` are
    escapes), a backslash escapes the next character, ``\\_`` is a
    word separator outside quotes and a space within double quotes,
    ``\\c`` outside quotes ends the string, and ``#`` starts a comment.
    """
    words: list[str] = []
    current: list[str] = []
    quote = ""
    index = 0
    while index < len(text):
        char = text[index]
        escaped = quote == "'" and text[index + 1 : index + 2] in ("'", "\\")
        if char == "\\" and (quote != "'" or escaped):
            index += 1
            if index >= len(text):
                return None
            if text[index] == "_" and not quote:
                # A word separator outside quotes, a space within.
                if current:
                    words.append("".join(current))
                    current = []
            elif text[index] == "c" and not quote:
                break  # \c ends the string, as in echo -e
            else:
                current.append(" " if text[index] == "_" else text[index])
        elif quote:
            if char == quote:
                quote = ""
            else:
                current.append(char)
        elif char in "\"'":
            quote = char
        elif char == "#" and not current:
            break
        elif char.isspace():
            if current:
                words.append("".join(current))
                current = []
        else:
            current.append(char)
        index += 1
    if quote:
        return None
    if current:
        words.append("".join(current))
    return words


def env_program(words: list[str]) -> str | None:
    """The program env runs, past its options and assignments; None if none.

    An ``-S``/``--split-string`` word splits its operand (attached, or
    the next word, with the rest of the line) into further words env
    reads; short options cluster (``-iC DIR``), and a long option may
    be cut to a unique prefix (``--chd DIR``).
    """
    index = 0
    while index < len(words):
        word = words[index]
        split = SPLIT_STRING.match(word)
        if split:
            attached = split.end() < len(word)
            rest = [word[split.end() :]] if attached else []
            rest += words[index + 1 :]
            parts = env_split(" ".join(rest))
            if parts is None:
                return None
            words = [*words[:index], *parts]
            if not parts:
                return None
            continue
        if word.startswith("--"):
            name = word.split("=", 1)[0]
            matches = [o for o in ENV_OPERAND_LONG if o.startswith(name)]
            index += 2 if len(matches) == 1 and "=" not in word else 1
        elif word == "-":
            index += 1  # ignore-environment, as -i
        elif word.startswith("-"):
            # A cluster: the first letter taking an operand uses the
            # rest of the word, or else the next word.
            letters = word[1:]
            takes = next((n for n, c in enumerate(letters) if c in "uC"), -1)
            index += 2 if takes == len(letters) - 1 else 1
        elif "=" in word:
            index += 1
        else:
            return word
    return None


def repo_root_of(path: str, root: str) -> str:
    """The git work tree holding ``path``, else the scan root.

    Under a directory root, the search stops at the root, which may be
    a folder of repositories. A file named on its own may sit anywhere
    in its repository, so every ancestor is searched.
    """
    root = os.path.abspath(root)
    single = not os.path.isdir(root)
    top = os.path.dirname(root) if single else root
    directory = os.path.dirname(os.path.abspath(path))
    while True:
        if os.path.exists(os.path.join(directory, ".git")):
            return directory
        at_top = directory == top and not single
        if at_top or os.path.dirname(directory) == directory:
            return top
        directory = os.path.dirname(directory)


def explicit_kind(path: str) -> str:
    """Kind of a file named on the command line, whatever its name.

    A file the user asked for is always scanned: a YAML file with a
    top-level ``jobs:`` key is a workflow, any other YAML file an
    action, and anything else a script.
    """
    kind = classify_kind(path)
    if kind:
        return kind
    if not path.endswith((".yml", ".yaml")):
        return "script"
    try:
        with open(path, encoding="utf-8", errors="replace") as handle:
            document = yaml.compose(handle, Loader=yaml.SafeLoader)
    except (OSError, yaml.YAMLError, RecursionError):
        # Unreadable, not YAML, or nested too deeply: the guarded scan
        # that follows reports the file as not scanned.
        return "action"
    # Composed, not constructed: no value is built, so a bad scalar or
    # an alias that expands widely costs nothing here.
    is_workflow = isinstance(document, yaml.MappingNode) and any(
        isinstance(key, yaml.ScalarNode) and key.value == "jobs"
        for key, _value in document.value
    )
    return "workflow" if is_workflow else "action"


def candidate_files(
    root: str, problems: list[str] | None = None
) -> Iterator[tuple[str, str]]:
    """Yield (path, kind) for every file the scan reads under root.

    A root that does not exist, and a directory that cannot be listed,
    are added to ``problems`` when it is given.
    """
    missed = problems if problems is not None else []
    if os.path.isfile(root):
        yield root, explicit_kind(root)
        return
    if not os.path.isdir(root):
        missed.append(f"{root}: no such file or directory")
        return

    def unreadable(error: OSError) -> None:
        missed.append(f"{error.filename}: {error.strerror}")

    for directory, subdirs, files in os.walk(root, onerror=unreadable):
        subdirs[:] = sorted(d for d in subdirs if d not in PRUNE_DIRS)
        for name in sorted(files):
            path = os.path.join(directory, name)
            # A symlink, a FIFO, a socket or a device is not scanned: a
            # read of a FIFO would wait for a writer.
            if os.path.islink(path) or not os.path.isfile(path):
                continue
            # The whole path: a root of .github or .github/workflows
            # still holds workflows.
            kind = classify_kind(os.path.abspath(path))
            probe = kind is None and "." not in name
            if probe and has_shell_shebang(path, missed):
                kind = "script"
            if kind:
                yield path, kind


MARKER = re.compile(
    re.escape(_yaml.MARK_OPEN) + r"(\w+):(\d+)" + re.escape(_yaml.MARK_CLOSE)
)
MARKER_NAMES = {
    kind: expression_marker(kind.upper())
    for kind in ("action_path", "workspace", "pythonpath", "temp")
}
# An expression whose name says Python: setup-python's python-path
# output and the like, or any name ending in a py/python stem.
PYTHON_EXPRESSION = re.compile(
    r"python[-_](?:path|bin|executable)|python_path|pythonLocation"
    r"|\.(?:py|python\d*(?:\.\d+)?|[a-z_]*_py(?:thon)?)\s*\}\}$",
    re.I,
)
# setup-uv's uv-path output and similar: an expression that names uv.
UV_EXPRESSION = re.compile(r"(?<![A-Za-z])uvx?(?![A-Za-z])", re.I)


def scan_text(text: str, kind: str, repo: str, relpath: str) -> list[Finding]:
    """Every finding in one file's text; ValueError when it cannot be read."""
    try:
        return _scan_text(text, kind, repo, relpath)
    except RecursionError as error:
        raise ValueError("shell or YAML nested too deeply to scan") from error


def _scan_text(text: str, kind: str, repo: str, relpath: str) -> list[Finding]:
    """Every finding in one file's text."""
    out: list[Finding] = []
    text = _yaml.scrub(text)
    if kind == "script":
        lines = text.split("\n")
        starts = [(0, 1)]
        offset = 0
        for number, line in enumerate(lines[:-1], start=2):
            offset += len(line.encode()) + 1
            starts.append((offset, number))
        block = Block(text, 1, starts, kind)
        BlockScan(block, repo, relpath, lines, out).run()
        return out
    lines = _yaml.split_lines(text)
    found = _yaml.read(text, kind)
    for yblock in found.blocks:
        block = yaml_block(yblock, found.expressions, kind)
        BlockScan(block, repo, relpath, lines, out).run()
    for number, word in found.setup_uv:
        ok = word is not None and located_path(
            word.parts, {"action_path", "temp"}, kind
        )
        marks = lines[max(number - 2, 0) : number]
        if not ok and not any(IGNORE_MARK in line for line in marks):
            snippet = lines[number - 1].strip()
            out.append(
                Finding(
                    repo,
                    relpath,
                    number,
                    kind,
                    "PPA008",
                    RULES["PPA008"],
                    snippet,
                )
            )
    for number, word in found.pythonpath:
        probe = BlockScan(
            Block("", number, [(0, number)], kind), repo, relpath, lines, out
        )
        probe.judge_pythonpath(
            yaml_tokens(word, kind),
            probe.tree.root_node,
            tilde=False,
            swapped=False,
        )
    out.sort(key=lambda f: f.line)
    return out


def yaml_block(
    yblock: _yaml.Block,
    expressions: list[_yaml.Expression],
    kind: str,
) -> Block:
    """A run: step as a block: expressions marked and env read.

    Each ``${{ }}`` expression becomes a word the parser reads as
    plain text, named for what it is when that matters, between
    private-use characters no text in the file can be taken for.
    """

    def swap(m: re.Match[str]) -> str:
        name = MARKER_NAMES.get(m.group(1))
        if m.group(1) == "action_path" and kind == "workflow":
            # A workflow has no action path: the expression is empty.
            name = expression_marker("OTHER")
        if name is None:
            expr = expressions[int(m.group(2))].text
            if PYTHON_EXPRESSION.search(expr):
                marker = "PYTHON"
            elif UV_EXPRESSION.search(expr):
                marker = "UV"
            else:
                marker = "OTHER"
            name = expression_marker(marker)
        return name

    env: dict[str, str | None] = {}
    for name, word in yblock.env.items():
        literal = all(isinstance(p, Lit) for p in word.parts)
        env[name] = (
            "".join(p.text for p in word.parts if isinstance(p, Lit))
            if literal
            else None
        )
    text, starts = swapped_text(yblock, expressions, swap)
    return Block(text, yblock.starts[0][1], starts, kind, env)


def swapped_text(
    yblock: _yaml.Block,
    expressions: list[_yaml.Expression],
    swap: Callable[[re.Match[str]], str],
) -> tuple[str, list[tuple[int, int]]]:
    """The block text with markers swapped, and its line starts in bytes.

    The YAML reader maps lines by offsets into the value as written,
    with each ``${{ }}`` in full; the parser counts bytes of the
    swapped text. Both are walked once, in step, so each character is
    encoded a single time. A line that starts inside a multi-line
    expression starts, in the swapped text, where the expression's
    replacement ends, so text after the expression belongs to its
    closing line.
    """
    original = _yaml.restore_expressions(yblock.text, expressions)
    pieces: list[str] = []
    starts: list[tuple[int, int]] = []
    lines = iter(yblock.starts)
    pending = next(lines, None)
    # The walk's position: characters of the original, bytes of the
    # swapped text.
    char = byte = 0
    position = 0  # in the marked text

    def map_literal(limit: int) -> None:
        """Place the line starts in the literal text up to ``limit``.

        A line that starts exactly at ``limit`` (where an expression
        opens) maps there too, before the expression's marker.
        """
        nonlocal pending, char, byte
        while pending is not None and pending[0] <= limit:
            byte += len(original[char : pending[0]].encode())
            char = pending[0]
            starts.append((byte, pending[1]))
            pending = next(lines, None)
        byte += len(original[char:limit].encode())
        char = limit

    for match in MARKER.finditer(yblock.text):
        literal = yblock.text[position : match.start()]
        name = swap(match)
        pieces += [literal, name]
        map_literal(char + len(literal))
        expression_end = char + len(expressions[int(match.group(2))].text)
        byte += len(name.encode())
        # A line starting inside the expression lands after its marker.
        while pending is not None and pending[0] < expression_end:
            starts.append((byte, pending[1]))
            pending = next(lines, None)
        char = expression_end
        position = match.end()
    tail = yblock.text[position:]
    pieces.append(tail)
    map_literal(char + len(tail))
    while pending is not None:  # a start past the text's end
        starts.append((byte, pending[1]))
        pending = next(lines, None)
    return "".join(pieces), starts


def yaml_tokens(word: _yaml.Word, kind: str) -> list[Token]:
    """A YAML env: PYTHONPATH value as tokens: literal text and expressions."""
    tokens: list[Token] = []
    for part in word.parts:
        if isinstance(part, Lit):
            tokens.append(Token(TEXT, part.text))
        elif part.kind == "workspace":
            tokens.append(Token(WORKSPACE, "${{ github.workspace }}"))
        elif part.kind == "pythonpath":
            tokens.append(Token(SELF, "${{ env.PYTHONPATH }}"))
        elif part.kind == "action_path" and kind == "workflow":
            # Empty in a workflow: the text around it is all there is.
            tokens.append(Token(TEXT, ""))
        elif part.kind in ("action_path", "temp"):
            tokens.append(Token(UNKNOWN, "${{ ... }}"))
        else:
            tokens.append(Token("unresolved", "${{ ... }}"))
    return tokens


def located_path(parts: list[Lit | Expr], kinds: set[str], kind: str) -> bool:
    """A YAML path that stays outside the workspace.

    It starts with an expression of one of ``kinds`` (the action path,
    which a workflow has none of, or the runner's temp directory) and
    the literal rest is empty or a subpath that does not climb, or it
    is wholly a literal absolute path outside the runners' workspaces.
    """
    if not parts or not all(isinstance(p, Lit) for p in parts[1:]):
        return False
    head = parts[0]
    tail = "".join(p.text for p in parts if isinstance(p, Lit))
    if isinstance(head, Lit):
        return is_outside_path(tail)
    located = head.kind in kinds and not (
        head.kind == "action_path" and kind == "workflow"
    )
    subpath = tail == "" or tail.startswith("/")
    return located and subpath and ".." not in tail.split("/")


def scan(
    roots: Sequence[str], problems: list[str] | None = None
) -> list[Finding]:
    """Every finding in the files under ``roots``, in discovery order.

    A root may be a folder of repositories, one repository, or a file.
    Each finding names its repository (the git work tree holding the
    file, else the root) and its path within it. A path that cannot be
    read or scanned is added to ``problems`` when it is given.
    """
    missed = problems if problems is not None else []
    findings: list[Finding] = []
    for root in roots:
        for path, kind in candidate_files(root, missed):
            repo_root = repo_root_of(path, root)
            relpath = os.path.relpath(os.path.abspath(path), repo_root)
            repo = os.path.basename(repo_root)
            try:
                with open(path, encoding="utf-8", errors="replace") as handle:
                    text = handle.read()
                findings.extend(scan_text(text, kind, repo, relpath))
            except (OSError, ValueError) as error:
                missed.append(f"{path}: {error}")
    return findings


def main(argv: Sequence[str] | None = None) -> int:
    """Scan the paths named, print the findings, and return the exit code."""
    parser = argparse.ArgumentParser(
        prog="python -m gha_workflow_linter.python_path._engine",
        description="Report Python and uv runs that take in workspace files.",
    )
    parser.add_argument("paths", nargs="+", help="files or folders to scan")
    parser.add_argument(
        "--json", action="store_true", help="print the findings as JSON"
    )
    parser.add_argument(
        "--kinds",
        default="action,workflow,script",
        help="comma-separated kinds of file to report (default: all)",
    )
    options = parser.parse_args(argv)
    kinds = {k.strip() for k in options.kinds.split(",") if k.strip()}
    problems: list[str] = []
    findings = [f for f in scan(options.paths, problems) if f.kind in kinds]
    if options.json:
        print(json.dumps([asdict(f) for f in findings], indent=2))
    else:
        for f in findings:
            print(f"{f.repo}/{f.path}:{f.line}: {f.rule} {f.detail}")
            print(f"    {f.snippet}")
    for problem in problems:
        print(f"not scanned: {problem}", file=sys.stderr)
    if problems:
        return 2
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
