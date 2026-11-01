# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Find Python invocations that import from the working directory.

GitHub Actions run steps in ``$GITHUB_WORKSPACE``, which often holds
an untrusted checkout. Python puts the working directory first on
``sys.path`` for ``-m``, ``-c`` and code read from standard input,
and an empty ``PYTHONPATH`` entry does the same in every mode. A
change under review can then plant ``json.py`` or a package named
like the caller's own and run in its place.

Only ``-I`` closes every route on every supported Python. ``-P`` and
``PYTHONSAFEPATH`` exist from 3.11 alone, and neither removes an
empty ``PYTHONPATH`` entry, so they are reported as partial.

The scan reads composite action metadata, workflow ``run:`` steps and
shell scripts, offline. YAML files are read with PyYAML; shell is
parsed and walked in the order it runs (see ``_walk``). An interpreter
reached through a variable the walk cannot resolve is not seen.

Add ``python-path-audit: ignore`` to a line, or the line above it, to
accept a finding.
"""

from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass, field
import json
import os
import re
import sys
from typing import TYPE_CHECKING

from ._places import Places
from ._pythonpath import pythonpath_problems, word_tokens
from ._shell import Expr
from ._state import TRUSTED
from ._walk import Walker
from ._yaml import Block, read, restore_expressions, split_lines

if TYPE_CHECKING:
    from collections.abc import Iterator

    from ._shell import Part
    from ._yaml import Expression

ACTION_NAMES = ("action.yml", "action.yaml")
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
MAX_BYTES = 2_000_000
KIND_ORDER = {"action": 0, "workflow": 1, "script": 2}
IGNORE_MARK = "python-path-audit: ignore"
# A shebang that starts the shell with -e, as "#!/bin/bash -eu" does.
SHEBANG_ERREXIT = re.compile(r"^#!.*\s-[a-zA-Z]*e[a-zA-Z]*(?:\s|$)")

RULES = {
    "PPA001": "-m puts the working directory first on sys.path",
    "PPA002": "-c puts the working directory first on sys.path",
    "PPA003": "code from stdin puts the working directory first on sys.path",
    "PPA004": "PYTHONPATH can hold an empty entry, which means the working directory",
    "PPA005": "PYTHONPATH holds a relative or workspace entry",
    "PPA006": (
        "uv takes its interpreter from a .python-version the workspace can "
        "plant; the detail names the fix for the subcommand"
    ),
    "PPA007": (
        "uv uses the interpreter of a .venv in the workspace or any parent; "
        "the detail names the fix for the subcommand"
    ),
    "PPA008": (
        "setup-uv works in the workspace: it starts the interpreter 'uv python find' "
        "returns there and reads uv.toml/pyproject.toml settings; set working-directory "
        "to the action path or runner.temp"
    ),
}


@dataclass
class Finding:
    """One place a Python process can import from the working directory."""

    repo: str
    path: str
    line: int
    kind: str
    rule: str
    detail: str
    snippet: str
    tags: list[str] = field(default_factory=list)


def classify_kind(relpath: str) -> str | None:
    """Return the kind of file, or None when it is not scanned."""
    name = os.path.basename(relpath)
    if name in ACTION_NAMES:
        return "action"
    if "/.github/workflows/" in f"/{relpath}" and name.endswith(
        (".yml", ".yaml")
    ):
        return "workflow"
    if name.endswith(SCRIPT_SUFFIXES):
        return "script"
    return None


def has_shell_shebang(path: str) -> bool:
    """True for an extensionless file that starts with a shell shebang."""
    try:
        with open(path, "rb") as handle:
            first = handle.readline(128)
    except OSError:
        return False
    return bool(re.match(rb"#!\s*\S*(?:/|\s)(?:ba|z|da|k)?sh\b", first))


def ignored(lines: list[str], number: int) -> bool:
    """True when the line or the one above carries the ignore mark."""
    here = lines[number - 1] if 0 < number <= len(lines) else ""
    above = lines[number - 2] if 1 < number <= len(lines) + 1 else ""
    return IGNORE_MARK in here or IGNORE_MARK in above


def triggers(text: str) -> set[str]:
    """The events in a workflow's own top-level ``on:`` block.

    Only that block counts: event names also appear in comments,
    embedded scripts and payloads of workflows they do not trigger.
    """
    lines = text.splitlines()
    for index, line in enumerate(lines):
        match = re.match(r"^(?:on|['\"]on['\"]|true)\s*:\s*(.*)$", line)
        if not match:
            continue
        inline = uncomment(match.group(1)).strip()
        if inline:
            return set(re.findall(r"[A-Za-z_]+", inline))
        found: set[str] = set()
        indent = None
        for body in lines[index + 1 :]:
            if body.strip() and not body[0].isspace():
                break
            key = re.match(r"^(\s+)([A-Za-z_]+)\s*:", uncomment(body))
            if key and (indent is None or len(key.group(1)) == indent):
                indent = len(key.group(1))
                found.add(key.group(2))
        return found
    return set()


def uncomment(line: str) -> str:
    """A YAML line without its comment: a ``#`` that starts a word, unquoted."""
    quote = ""
    escaped = False
    for index, char in enumerate(line):
        if escaped:
            escaped = False
        elif quote == '"' and char == "\\":
            escaped = True
        elif quote:
            quote = "" if char == quote else quote
        elif char in "'\"":
            quote = char
        elif char == "#" and (index == 0 or line[index - 1].isspace()):
            return line[:index]
    return line


def reusable(text: str) -> bool:
    """True when a workflow's own ``on:`` block lists workflow_call."""
    return "workflow_call" in triggers(text)


def uses_secrets(text: str) -> bool:
    """True when a workflow reads a secret other than GITHUB_TOKEN.

    Only the ``secrets`` context counts: inside a ``${{ }}`` expression,
    or a reusable-workflow call passing ``secrets: inherit``. A file name
    such as ``secrets.py`` in a script is not a secret.
    """
    if re.search(r"^\s*secrets:\s*inherit\b", text, re.M):
        return True
    for expr in re.findall(r"\$\{\{(.*?)\}\}", text, re.S):
        for ref in re.finditer(r"(?<![\w.-])secrets\b(?:\s*\.\s*(\w+))?", expr):
            if ref.group(1) != "GITHUB_TOKEN":
                return True
    return False


def file_tags(text: str, kind: str) -> list[str]:
    """Context that raises or lowers a workflow finding's priority."""
    if kind != "workflow":
        return []
    text = "\n".join(uncomment(line) for line in text.splitlines())
    events = triggers(text)
    tags = sorted(
        events & {"workflow_call", "pull_request_target", "workflow_run"}
    )
    if uses_secrets(text):
        tags.append("secrets")
    if re.search(r":\s*write\b", text):
        tags.append("write-permissions")
    if not re.search(r"actions/checkout@|checkout-gerrit-change-action@", text):
        tags.append("no-checkout")
    return tags


@dataclass
class _Scan:
    """One file being scanned: what it says, and the findings so far."""

    lines: list[str]
    kind: str
    repo: str
    relpath: str
    tags: list[str]
    expressions: list[Expression] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    seen: set[tuple[int, str, str, str]] = field(default_factory=set)

    def add(
        self, number: int, rule: str, detail: str | None, snippet: str = ""
    ) -> None:
        """Record a finding, unless it is ignored or already recorded."""
        if ignored(self.lines, number):
            return
        if not snippet:
            snippet = (
                self.lines[number - 1].strip()
                if 0 < number <= len(self.lines)
                else ""
            )
        snippet = " ".join(snippet.split())[:160]
        detail = detail or RULES[rule]
        key = (number, rule, detail, snippet)
        if key in self.seen:
            return
        self.seen.add(key)
        self.findings.append(
            Finding(
                self.repo,
                self.relpath,
                number,
                self.kind,
                rule,
                detail,
                snippet,
                list(self.tags),
            )
        )

    def walk(self, block: Block) -> None:
        """Report every finding in one block of shell."""

        def report(start: int, end: int, rule: str, detail: str | None) -> None:
            index = block.text.count("\n", 0, start)
            number = block.lines[min(index, len(block.lines) - 1)]
            snippet = restore_expressions(
                block.text[start:end], self.expressions
            )
            self.add(number, rule, detail, snippet)

        Walker(block, self.kind, self.relpath, self.expressions, report).run()


def scan_text(text: str, kind: str, repo: str, relpath: str) -> list[Finding]:
    """Every finding in one file's text.

    Raises ValueError when the file cannot be read: a workflow or action
    file that is not valid YAML, or shell nested beyond the parser's
    limit.
    """
    tags = file_tags(text, kind)
    if kind == "script":
        lines = text.split("\n")
        scan = _Scan(lines, kind, repo, relpath, tags)
        errexit = bool(SHEBANG_ERREXIT.match(lines[0]))
        scan.walk(Block(text, list(range(1, len(lines) + 1)), errexit=errexit))
        return scan.findings
    scan = _Scan(split_lines(text), kind, repo, relpath, tags)
    found = read(text, kind)
    scan.expressions = found.expressions
    for block in found.blocks:
        scan.walk(block)
    places = Places(kind, relpath, found.expressions)
    for number, word in found.setup_uv:
        place = None if word is None else places.directory(word)
        if place is None or place.base not in (*TRUSTED, "outside"):
            scan.add(number, "PPA008", None)
    for number, word in found.pythonpath:
        tokens = word_tokens(word, set(), False, _yaml_part)
        for rule, detail in pythonpath_problems(tokens, kind):
            scan.add(number, rule, detail)
    scan.findings.sort(key=lambda finding: finding.line)
    return scan.findings


def _yaml_part(part: Part) -> str:
    """What an expression in a YAML PYTHONPATH value names."""
    if isinstance(part, Expr) and part.kind == "workspace":
        return "workspace"
    return "unknown"


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
            is_workflow = any(line.startswith("jobs:") for line in handle)
    except OSError:
        return "action"
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
            if os.path.islink(path):
                continue
            relpath = os.path.relpath(path, root)
            kind = classify_kind(relpath)
            if kind is None and "." not in name and has_shell_shebang(path):
                kind = "script"
            if kind:
                yield path, kind


def scan(roots: list[str], problems: list[str] | None = None) -> list[Finding]:
    """Scan every root and return the findings, most urgent first.

    A file that cannot be read, or is not valid YAML, is skipped, and
    why is added to ``problems`` when it is given: the scan of that
    file is missing, so the caller must not treat it as clean.
    """
    skipped = problems if problems is not None else []
    findings: list[Finding] = []
    for root in roots:
        for path, kind in candidate_files(root, skipped):
            try:
                if os.path.getsize(path) > MAX_BYTES:
                    skipped.append(f"{path}: larger than {MAX_BYTES} bytes")
                    continue
                with open(path, encoding="utf-8", errors="replace") as handle:
                    text = handle.read()
                repo_root = repo_root_of(path, root)
                relpath = os.path.relpath(os.path.abspath(path), repo_root)
                findings.extend(
                    scan_text(text, kind, os.path.basename(repo_root), relpath)
                )
            except (OSError, ValueError, RecursionError) as error:
                skipped.append(f"{path}: {error}")
    findings.sort(
        key=lambda f: (KIND_ORDER[f.kind], f.repo, f.path, f.line, f.rule)
    )
    return findings


def render_text(findings: list[Finding]) -> str:
    """Human-readable report, grouped by kind and repository."""
    if not findings:
        return "No findings."
    out: list[str] = []
    current = None
    for finding in findings:
        heading = (finding.kind, finding.repo)
        if heading != current:
            current = heading
            out.append(f"\n[{finding.kind}] {finding.repo}")
        tags = f" [{', '.join(finding.tags)}]" if finding.tags else ""
        out.append(f"  {finding.path}:{finding.line} {finding.rule}{tags}")
        out.append(f"    {finding.snippet}")
        out.append(f"    -> {finding.detail}")
    repos = {(f.kind, f.repo) for f in findings}
    counts = {k: sum(1 for f in findings if f.kind == k) for k in KIND_ORDER}
    out.append(
        f"\n{len(findings)} findings in {len({f.repo for f in findings})} repositories "
        f"(action {counts['action']}, workflow {counts['workflow']}, "
        f"script {counts['script']}; {len(repos)} repository/kind groups)"
    )
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    """Command-line entry point.

    Exits 2 when a file could not be scanned, so the result is
    incomplete; otherwise 1 when anything is found, else 0.
    """
    parser = argparse.ArgumentParser(
        description=(__doc__ or "").split("\n\n")[0],
        epilog="exit status: 0 clean, 1 findings, 2 a file could not be scanned",
    )
    parser.add_argument(
        "paths", nargs="+", help="files, repositories, or folders of them"
    )
    parser.add_argument("--json", action="store_true", help="emit JSON")
    parser.add_argument(
        "--kinds",
        default="action,workflow,script",
        help="comma-separated kinds to report (default: all)",
    )
    args = parser.parse_args(argv)
    kinds = {k.strip() for k in args.kinds.split(",") if k.strip()}
    unknown = kinds - set(KIND_ORDER)
    if unknown:
        parser.error(f"unknown kind(s): {', '.join(sorted(unknown))}")
    problems: list[str] = []
    findings = [f for f in scan(args.paths, problems) if f.kind in kinds]
    for problem in problems:
        print(f"error: cannot scan {problem}", file=sys.stderr)
    if args.json:
        print(json.dumps([asdict(f) for f in findings], indent=2))
    else:
        print(render_text(findings))
    if problems:
        return 2
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
