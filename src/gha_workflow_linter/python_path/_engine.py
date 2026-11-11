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

from gha_workflow_linter.shell import _yaml
from gha_workflow_linter.shell._discovery import (
    candidate_files,
    classify_kind,
    explicit_kind,
    shebang_names_shell,
)
from gha_workflow_linter.shell._yaml import Expr, Lit, swapped_text

from ._block import BlockScan
from ._invocation import (
    IGNORE_MARK,
    RULES,
    expression_marker,
    is_outside_path,
)
from ._pythonpath import SELF, TEXT, UNKNOWN, WORKSPACE, Token
from ._words import Block, Finding

if TYPE_CHECKING:
    from collections.abc import Sequence

# Discovery lives in the shared shell package; its entry points stay
# importable from here, where the scan's callers have always found them.
__all__ = [
    "RULES",
    "Finding",
    "candidate_files",
    "classify_kind",
    "explicit_kind",
    "main",
    "scan",
    "scan_text",
    "shebang_names_shell",
]


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
    for step in found.setup_uv:
        marks = lines[max(step.line - 2, 0) : step.line]
        if any(IGNORE_MARK in line for line in marks):
            continue
        snippet = lines[step.line - 1].strip()
        refused = any(
            position < step.step and refuses_no_modify_path(run)
            for position, run in found.runs
        )
        for rule, detail in setup_uv_problems(step, kind, refused=refused):
            out.append(
                Finding(repo, relpath, step.line, kind, rule, detail, snippet)
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


# The preferences uv accepts. Any other literal makes uv refuse its
# arguments before it looks up an interpreter.
UV_PYTHON_PREFERENCES = frozenset(
    {"only-managed", "managed", "system", "only-system"}
)
UNREADABLE = "is an expression the scan cannot read"
# setup-uv hands tool-bin-dir to core.addPath(), which writes it to
# $GITHUB_PATH as one line and prepends it to PATH: a line break adds
# a second entry through the file, and ':' or ';' (Windows) a second
# entry through PATH itself.
PATH_BREAKS = frozenset(":;\r\n")
# Windows splits a path on either slash.
PATH_SLASHES = re.compile(r"[/\\]")
EXIT_ONE = re.compile(r"\bexit 1\b")


def refuses_no_modify_path(run: str) -> bool:
    """A ``run:`` text that names ``UV_NO_MODIFY_PATH`` and ``exit 1``.

    A literal match, not shell analysis: it does not prove the step
    refuses the variable, only that it reads as a refusal step.
    """
    return "UV_NO_MODIFY_PATH" in run and EXIT_ONE.search(run) is not None


def setup_uv_problems(
    step: _yaml.SetupUv, kind: str, *, refused: bool = False
) -> list[tuple[str, str]]:
    """The rules a setup-uv step breaks, each with its detail.

    PPA008: its working directory is not the action path or the
    runner's temp directory. PPA011: its interpreter lookup is not
    disabled, so the caller's environment chooses what it runs.
    PPA012: its tool bin directory, which it adds to ``PATH``, is not
    one of those two places. ``refused`` says an earlier ``run:`` step
    of the same file reads as a refusal of ``UV_NO_MODIFY_PATH``.
    """
    problems: list[tuple[str, str]] = []
    directory = step.directory
    if directory is None or not located_path(
        directory.parts, {"action_path", "temp"}, kind
    ):
        problems.append(("PPA008", RULES["PPA008"]))
    lookup = interpreter_lookup(step, kind, refused=refused)
    if lookup is not None:
        problems.append(("PPA011", lookup))
    tool_bin = step.inputs.get("tool-bin-dir")
    if tool_bin is None:
        problems.append(
            (
                "PPA012",
                "no tool-bin-dir: setup-uv adds a bin directory the "
                "caller's HOME or XDG_* settings name to PATH",
            )
        )
    else:
        placement = path_placement(tool_bin, kind)
        if placement == "separator":
            problems.append(
                (
                    "PPA012",
                    "tool-bin-dir holds a PATH separator or line break, "
                    "so setup-uv adds more than one directory to PATH",
                )
            )
        elif placement == "outside":
            problems.append(
                (
                    "PPA012",
                    "tool-bin-dir is outside the runner's temp directory "
                    "and the action path",
                )
            )
    return problems


def path_placement(word: _yaml.Word, kind: str) -> str | None:
    """Whether a directory setup-uv adds to ``PATH`` stays the action's.

    None when it starts with the ``${{ runner.temp }}`` or
    ``${{ github.action_path }}`` expression; ``separator`` when its
    literal text holds a ``PATH`` separator or a line break, which
    ``core.addPath()`` would turn into a second entry; ``outside``
    otherwise. A literal path never holds, however absolute: a
    drive-less one such as ``/a/repo/repo/bin`` resolves on a Windows
    runner to the working directory's drive, inside the checkout.
    """
    if any(
        isinstance(p, Lit) and PATH_BREAKS.intersection(p.text)
        for p in word.parts
    ):
        return "separator"
    if not word.parts or isinstance(word.parts[0], Lit):
        return "outside"
    if any(
        isinstance(p, Lit) and any(map(climbs, PATH_SLASHES.split(p.text)))
        for p in word.parts
    ):
        return "outside"
    if not located_path(word.parts, {"action_path", "temp"}, kind):
        return "outside"
    return None


def climbs(component: str) -> bool:
    """A path component that may name the parent directory.

    ``..``, or, conservatively, any run of dots and spaces holding
    one, since Windows trims trailing dots and spaces from a name.
    """
    return ".." in component and not component.strip(". ")


def env_spellings(step: _yaml.SetupUv, name: str) -> list[str]:
    """The step ``env:`` names Windows reads as ``name``, in any case."""
    return [key for key in step.env if key.upper() == name]


def env_guard(
    step: _yaml.SetupUv, name: str
) -> tuple[_yaml.Word | None, str | None]:
    """A guarding step ``env:`` value under its exact name.

    Linux reads only the exact name, so another spelling guards
    nothing; Windows reads either, so a step that sets the name in
    more than one case fails the guard, whichever value it holds.
    """
    if len(env_spellings(step, name)) > 1:
        return None, f"{name} is set in more than one case"
    return step.env.get(name), None


def literal_value(word: _yaml.Word | None) -> str | None:
    """A word's text when it is wholly literal, else None."""
    if word is None or not all(isinstance(p, Lit) for p in word.parts):
        return None
    return "".join(p.text for p in word.parts if isinstance(p, Lit))


def interpreter_lookup(
    step: _yaml.SetupUv, kind: str, *, refused: bool
) -> str | None:
    """Why a setup-uv step runs an interpreter the caller chooses.

    None when every guard holds: an invalid ``UV_PYTHON_PREFERENCE``,
    an empty ``UV_PYTHON_ARCH`` with no ``python-arch`` input, the
    cache off, no environment activated, no ``UV_NO_MODIFY_PATH`` on
    the step (and, in a composite action, an earlier step refusing an
    inherited one), and a ``UV_PYTHON_INSTALL_DIR`` under the runner's
    temp directory or the action path. Otherwise the first guard that
    fails, with ``searches PATH`` added when the step sets
    ``UV_SYSTEM_PYTHON``.
    """
    reason = first_failed_guard(step, kind, refused=refused)
    if reason is not None and env_spellings(step, "UV_SYSTEM_PYTHON"):
        reason += "; searches PATH"
    return reason


def first_failed_guard(
    step: _yaml.SetupUv, kind: str, *, refused: bool
) -> str | None:
    """The first of the PPA011 guards a setup-uv step does not meet."""
    guards = (
        preference_guard,
        arch_guard,
        cache_guard,
        activate_guard,
    )
    for guard in guards:
        failed = guard(step)
        if failed is not None:
            return failed
    failed = modify_path_guard(step, kind, refused=refused)
    if failed is not None:
        return failed
    return install_dir_guard(step, kind)


def preference_guard(step: _yaml.SetupUv) -> str | None:
    """Fails unless ``UV_PYTHON_PREFERENCE`` is a literal uv refuses."""
    preference, twice = env_guard(step, "UV_PYTHON_PREFERENCE")
    if twice is not None:
        return twice
    value = literal_value(preference)
    if value is not None and value not in UV_PYTHON_PREFERENCES:
        return None
    if "python-version" in step.inputs:
        return "exports UV_PYTHON to later steps of the caller's job"
    if preference is None:
        return "UV_PYTHON_PREFERENCE is not set to an invalid value"
    if value is None:
        return f"UV_PYTHON_PREFERENCE {UNREADABLE}"
    return f"UV_PYTHON_PREFERENCE {value!r} lets uv look up an interpreter"


def arch_guard(step: _yaml.SetupUv) -> str | None:
    """Fails unless ``UV_PYTHON_ARCH`` is ``''`` and no input sets one."""
    arch, twice = env_guard(step, "UV_PYTHON_ARCH")
    if twice is not None:
        return twice
    value = literal_value(arch)
    if arch is None:
        return "UV_PYTHON_ARCH is not set to ''"
    if value is None:
        return f"UV_PYTHON_ARCH {UNREADABLE}"
    if value:
        return "UV_PYTHON_ARCH is not ''"
    if "python-arch" in step.inputs:
        return "the python-arch input is set"
    return None


def cache_guard(step: _yaml.SetupUv) -> str | None:
    """Fails unless ``enable-cache`` is the literal ``false``."""
    cache = step.inputs.get("enable-cache")
    value = literal_value(cache)
    if cache is not None and value is None:
        return f"enable-cache {UNREADABLE}"
    if value is None or value.lower() != "false":
        return "enable-cache is not false"
    return None


def activate_guard(step: _yaml.SetupUv) -> str | None:
    """Fails when ``activate-environment`` is set to anything but false."""
    activate = step.inputs.get("activate-environment")
    value = literal_value(activate)
    if activate is not None and value is None:
        return f"activate-environment {UNREADABLE}"
    if value is not None and value.lower() != "false":
        return "activate-environment is not false"
    return None


def modify_path_guard(
    step: _yaml.SetupUv, kind: str, *, refused: bool
) -> str | None:
    """Fails when ``UV_NO_MODIFY_PATH`` may reach setup-uv.

    The step must not set it, in any case or value. A composite action
    also inherits its caller's, which no step can unset, so an earlier
    ``run:`` step must refuse it; a workflow job's environment is its
    own, so there the step alone decides.
    """
    if env_spellings(step, "UV_NO_MODIFY_PATH"):
        return "UV_NO_MODIFY_PATH is set on the step"
    if kind == "action" and not refused:
        return (
            "UV_NO_MODIFY_PATH may be inherited; refuse it in an earlier step"
        )
    return None


def install_dir_guard(step: _yaml.SetupUv, kind: str) -> str | None:
    """Fails unless ``UV_PYTHON_INSTALL_DIR`` is the action's own.

    setup-uv prepends that directory to ``PATH`` after its own uv and
    before it runs a bare ``uv python find``, so an inherited one can
    hold the ``uv`` that runs. The step must set it under the runner's
    temp directory or the action path expression, as ``tool-bin-dir``.
    """
    install_dir, twice = env_guard(step, "UV_PYTHON_INSTALL_DIR")
    if twice is not None:
        return twice
    if install_dir is None or path_placement(install_dir, kind) is not None:
        return "UV_PYTHON_INSTALL_DIR comes from the caller"
    return None


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
