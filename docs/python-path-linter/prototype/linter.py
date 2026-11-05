# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Prototype: a linter for Python started with the working directory on
sys.path, built on tree-sitter-bash, judging each command from what is
written in it.

Design (the "linter" model):

- No interpretation of the shell. Each simple command is judged from
  its own literal words. A word that is not literal (an expansion, a
  substitution) in a position that decides the outcome is reported as
  unresolved (PPA009), never trusted.
- A whole step or script is trusted only on a syntactic condition that
  bash cannot alter: the step's YAML ``working-directory`` is the action
  path (an expression, which bash does not see), or the block's first
  command is ``cd "$GITHUB_ACTION_PATH"`` (optionally with a literal
  subpath) under a shell that starts with ``-e``, and the block holds no
  other ``cd``, ``pushd``, ``popd``, ``exec``, ``eval``, ``source``,
  ``.``, no command whose name is not a literal word, and no function
  definition.
- A variable is substituted into a command only under single
  assignment: exactly one assignment anywhere in the block, at top
  level (not in a function, loop, branch, subshell or substitution),
  before every use, to a literal scalar or array of literal words.
- uv settings from the environment count only from the step's YAML
  ``env:`` and the command's own prefix assignments. ``export`` is not
  followed (a reader can move it to ``env:``).
- A parse error anywhere in a block makes that block "not fully
  scanned" (PPA010), not clean.

Rules PPA001-PPA008 keep their meaning from the engine on PR #434.
"""

from __future__ import annotations

from dataclasses import dataclass
import os
import re
from typing import TYPE_CHECKING

from args import (
    UvCommand,
    parse_python,
    parse_uv,
    parse_uvx,
    risky,
    uv_findings,
)
from pythonpath_checks import PythonpathChecks
from pythonpath_tokens import (
    TEXT,
    Token,
)
from tables import (
    DECLARATIONS,
    ENV_VALUE,
    IGNORE_MARK,
    INTERPRETER,
    POSITIONAL,
    RULES,
    RUNNERS,
    TRUST_BREAKERS,
    UV_DECIDING,
    UV_INFO,
    WORD_TYPES,
    WRAPPERS,
)
from tree_sitter import Language, Node, Parser
import tree_sitter_bash
from words import (
    Block,
    Finding,
    Word,
    _node_text,
    command_words,
    literal_of,
    word_of,
)

if TYPE_CHECKING:
    from collections.abc import Iterator

BASH = Language(tree_sitter_bash.language())


@dataclass
# ------------------------------------------------------------------- analysis


class BlockScan(PythonpathChecks):
    """Scan one block of shell."""

    def __init__(
        self,
        block: Block,
        repo: str,
        path: str,
        lines: list[str],
        out: list[Finding],
    ):
        self.block = block
        self.repo = repo
        self.path = path
        self.lines = lines
        self.out = out
        self.src = block.text.encode()
        self.tree = Parser(BASH).parse(self.src)
        self.constants: dict[str, list[Word]] = {}
        self.pythonpath_copies: set[str] = set()
        self.trusted = block.directory_trusted
        self.trusted_nodes: set[int] = set()
        self.seen: set[tuple[int, str, str]] = set()

    # -- reporting

    def line_at(self, node: Node) -> int:
        offset = node.start_byte
        line = self.block.first_line
        for start, number in self.block.line_of_offset:
            if start <= offset:
                line = number
        return line

    def report(self, node: Node, rule: str, detail: str | None = None) -> None:
        number = self.line_at(node)
        here = self.lines[number - 1] if 0 < number <= len(self.lines) else ""
        above = (
            self.lines[number - 2] if 1 < number <= len(self.lines) + 1 else ""
        )
        if IGNORE_MARK in here or IGNORE_MARK in above:
            return
        snippet = " ".join(_node_text(self.src, node).split())[:160]
        key = (number, rule, snippet)
        if key in self.seen:
            return
        self.seen.add(key)
        self.out.append(
            Finding(
                self.repo,
                self.path,
                number,
                self.block.kind,
                rule,
                detail or RULES[rule],
                snippet,
            )
        )

    # -- walking

    def run(self) -> None:
        root = self.tree.root_node
        if root.has_error:
            for node in self.errors(root):
                self.report(node, "PPA010")
        self.collect_constants(root)
        if not self.trusted:
            self.trusted = self.leading_cd_trust(root)
        self.visit(root, depth=0, sink=False)

    def errors(self, node: Node) -> Iterator[Node]:
        if node.type == "ERROR" or node.is_missing:
            yield node
            return
        for child in node.children:
            yield from self.errors(child)

    def collect_constants(self, root: Node) -> None:
        """Variables assigned exactly once, at top level, as the words assigned."""
        counts: dict[str, int] = {}
        values: dict[str, list[Word]] = {}
        top_level: dict[str, bool] = {}

        def walk(node: Node, top: bool) -> None:
            if node.type == "variable_assignment":
                name_node = node.child_by_field_name("name")
                if name_node is None:
                    return
                name = _node_text(self.src, name_node)
                subscript = name_node.type == "subscript"
                if subscript:
                    name = _node_text(self.src, name_node.children[0])
                counts[name] = counts.get(name, 0) + 1
                top_level[name] = (
                    top_level.get(name, True)
                    and top
                    and not subscript
                    and "+=" not in _node_text(self.src, node)[: len(name) + 2]
                )
                value = node.child_by_field_name("value")
                if value is not None and "PYTHONPATH" in _node_text(
                    self.src, value
                ):
                    self.pythonpath_copies.add(name)
                if value is None:
                    values[name] = []
                elif value.type == "array":
                    values[name] = [
                        word_of(self.src, c)
                        for c in value.children
                        if c.type in WORD_TYPES
                    ]
                else:
                    values[name] = [word_of(self.src, value)]
            # Commands that assign by name make the name non-constant.
            if node.type in ("command", "declaration_command", "unset_command"):
                name_node = node.child_by_field_name("name")
                cmd = (
                    _node_text(self.src, name_node)
                    if name_node
                    else _node_text(self.src, node.children[0])
                )
                if cmd in (
                    "read",
                    "mapfile",
                    "readarray",
                    "getopts",
                    "printf",
                    "unset",
                    "export",
                    "declare",
                    "local",
                    "typeset",
                    "readonly",
                    "eval",
                    "source",
                    ".",
                ):
                    for child in node.children:
                        if child.type == "word":
                            token = _node_text(self.src, child)
                            if re.fullmatch(r"[A-Za-z_]\w*", token):
                                counts[token] = counts.get(token, 0) + 2
                        if child.type == "variable_assignment":
                            walk(child, False)
            nested = node.type in (
                "function_definition",
                "if_statement",
                "for_statement",
                "c_style_for_statement",
                "while_statement",
                "case_statement",
                "subshell",
                "command_substitution",
                "process_substitution",
                "pipeline",
                "list",
                "compound_statement",
                "negated_command",
            )
            for child in node.children:
                walk(child, top and not nested)

        walk(root, True)
        for name, count in counts.items():
            if count == 1 and top_level.get(name) and name in values:
                self.constants[name] = values[name]

    def leading_cd_trust(self, root: Node) -> bool:
        """True when the block starts with cd into the action path and never leaves it.

        The cd may follow ``set -e``, and may be ``cd X || exit``; without
        either, a failed cd would leave the shell in the workspace.
        """
        if self.block.kind == "workflow":
            return False
        statements = [
            c for c in root.children if c.is_named and c.type != "comment"
        ]
        if not statements:
            return False
        errexit = self.block.errexit
        first = statements[0]
        if (
            first.type == "command"
            and self.is_set_e(first)
            and len(statements) > 1
        ):
            errexit = True
            first = statements[1]
        guarded = False
        if first.type == "list":
            parts = [c for c in first.children if c.is_named]
            ops = [c.type for c in first.children if not c.is_named]
            if len(parts) == 2 and ops == ["||"] and parts[1].type == "command":
                _a, words = command_words(self.src, parts[1])
                guarded = bool(words) and words[0].text in ("exit", "return")
                first = parts[0]
        if first.type != "command" or not (errexit or guarded):
            return False
        if not self.is_action_cd(first):
            return False
        return self.no_trust_breakers(root, first)

    def is_action_cd(self, command: Node) -> bool:
        """``cd "$GITHUB_ACTION_PATH"`` or ``cd -- "$GITHUB_ACTION_PATH/sub"``."""
        assigns, words = command_words(self.src, command)
        if assigns or not words or words[0].text != "cd":
            return False
        rest = [w for w in words[1:] if w.text != "--"]
        if len(rest) != 1 or rest[0].node.type not in (
            "string",
            "concatenation",
        ):
            return False
        source = rest[0].source
        if not re.fullmatch(
            r'"\$\{?GITHUB_ACTION_PATH\}?(/[A-Za-z0-9_./-]*)?"', source
        ):
            return False
        suffix = re.sub(r'^"\$\{?GITHUB_ACTION_PATH\}?', "", source)[:-1]
        return not any(part == ".." for part in suffix.split("/"))

    def no_trust_breakers(self, scope: Node, first: Node) -> bool:
        """No command in ``scope`` but ``first`` changes directory or hides code."""
        for node in self.descendants(scope):
            if node.type != "command" or node is first:
                continue
            _a, cwords = command_words(self.src, node)
            if not cwords:
                continue
            name = cwords[0]
            if not name.literal or name.text in TRUST_BREAKERS:
                return False
            if (
                name.text in ("command", "builtin")
                and not any(
                    (w.text or "").startswith("-")
                    and set(w.text or "") & {"v", "V"}
                    for w in cwords[1:2]
                )
                and any(w.text in TRUST_BREAKERS for w in cwords[1:3])
            ):
                return False
        return True

    def is_set_e(self, command: Node) -> bool:
        _a, words = command_words(self.src, command)
        return (
            bool(words)
            and words[0].text == "set"
            and all(
                w.literal
                and w.text
                and re.fullmatch(
                    r"-[a-zA-Z]*e[a-zA-Z]*|-o|errexit|pipefail|-u|-x", w.text
                )
                for w in words[1:]
            )
            and any(
                w.text and re.fullmatch(r"-[a-zA-Z]*e[a-zA-Z]*", w.text)
                for w in words[1:]
            )
        )

    def descendants(self, node: Node) -> Iterator[Node]:
        for child in node.children:
            yield child
            yield from self.descendants(child)

    def all_commands(self, root: Node) -> Iterator[Node]:
        for node in self.descendants(root):
            if node.type == "command":
                yield node

    def visit(self, node: Node, depth: int, sink: bool) -> None:
        """Visit every command; ``sink`` is true inside a group redirected to $GITHUB_ENV."""
        if depth > 200:
            self.report(node, "PPA010", "shell nested too deeply")
            return
        if node.type == "redirected_statement":
            body = node.children[0]
            redirects = node.children[1:]
            sink_here = sink or any(self.redirect_to_env(r) for r in redirects)
            if body.type == "command":
                self.command(body, redirects, sink_here)
                for r in redirects:
                    self.visit_children(r, depth, sink)
                return
            for child in node.children:
                self.visit(child, depth + 1, sink_here)
            return
        if node.type == "command":
            self.command(node, [], sink)
            self.visit_children(node, depth, sink)
            return
        if node.type == "list" and self.block.kind != "workflow":
            # cd "$GITHUB_ACTION_PATH" && a && b: the chain runs in the
            # action directory, when nothing in it changes directory.
            parts = [c for c in node.children if c.is_named]
            ops = [c.type for c in node.children if not c.is_named]
            if (
                parts
                and parts[0].type == "command"
                and all(op == "&&" for op in ops)
                and self.is_action_cd(parts[0])
                and self.no_trust_breakers(node, parts[0])
            ):
                was = self.trusted
                self.trusted = True
                self.visit_children(node, depth, sink)
                self.trusted = was
                return
        if node.type == "pipeline":
            commands = [c for c in node.children if c.is_named]
            for index, child in enumerate(commands):
                feeds = any(
                    self.is_tee_env(n) for n in commands[index + 1 : index + 2]
                )
                self.visit(child, depth + 1, sink or feeds)
            return
        if node.type in ("variable_assignment", "declaration_command"):
            self.assignment(node)
        self.visit_children(node, depth, sink)

    def visit_children(self, node: Node, depth: int, sink: bool) -> None:
        for child in node.children:
            self.visit(child, depth + 1, sink)

    def redirect_to_env(self, node: Node) -> bool:
        if node.type != "file_redirect":
            return False
        op = _node_text(self.src, node.children[0])
        if op not in (">", ">>", ">|", "1>", "1>>"):
            return False
        target = node.children[-1]
        return _node_text(self.src, target).strip('"') in (
            "$GITHUB_ENV",
            "${GITHUB_ENV}",
        )

    def is_tee_env(self, node: Node) -> bool:
        body = node.children[0] if node.type == "redirected_statement" else node
        if body.type != "command":
            return False
        _a, words = command_words(self.src, body)
        texts = [w.source.strip('"') for w in words]
        texts = texts[self.skip_wrappers([w.text or w.source for w in words]) :]
        return (
            bool(texts)
            and texts[0] == "tee"
            and any(t in ("$GITHUB_ENV", "${GITHUB_ENV}") for t in texts[1:])
        )

    # -- assignments

    def assignment(self, node: Node) -> None:
        nodes = (
            [node]
            if node.type == "variable_assignment"
            else [c for c in node.children if c.type == "variable_assignment"]
        )
        for assign in nodes:
            name_node = assign.child_by_field_name("name")
            if (
                name_node is None
                or _node_text(self.src, name_node) != "PYTHONPATH"
            ):
                continue
            value = assign.child_by_field_name("value")
            if value is None:
                continue
            append = "+=" in _node_text(self.src, assign)[:12]
            self.check_pythonpath(value, assign, prefix_self=append)
        if node.type == "declaration_command":
            # export "PYTHONPATH=...": the assignment is one word.
            for child in node.children:
                if child.type in ("string", "concatenation", "word"):
                    tokens = self.pythonpath_tokens(child)
                    text = "".join(t.text for t in tokens if t.kind == TEXT)
                    if (
                        tokens
                        and tokens[0].kind == TEXT
                        and tokens[0].text.startswith("PYTHONPATH=")
                    ):
                        tokens[0] = Token(
                            TEXT, tokens[0].text[len("PYTHONPATH=") :]
                        )
                        self.judge_pythonpath(tokens, child, tilde=False)
                    elif "PYTHONPATH=" in text[:12]:
                        self.report(
                            child,
                            "PPA009",
                            "PYTHONPATH set from a value the scan cannot read",
                        )

    # -- commands

    def skip_wrappers(self, texts: list[str]) -> int:
        """Index of the real program past wrappers; len(texts) if none runs."""
        i = 0
        while i < len(texts):
            name = os.path.basename(texts[i]) if "/" in texts[i] else texts[i]
            if re.match(r"^[A-Za-z_]\w*=", texts[i]):
                i += 1
            elif name in WRAPPERS:
                takes = WRAPPERS[name]
                i += 1
                while i < len(texts) and texts[i].startswith("-"):
                    if texts[i] == "--":
                        i += 1
                        break
                    if name == "command" and set(texts[i][1:]) & {"v", "V"}:
                        return len(texts)
                    i += 2 if texts[i] in takes else 1
                i += POSITIONAL.get(name, 0)
            elif name == "env":
                i += 1
                while i < len(texts):
                    t = texts[i]
                    if t == "--":
                        i += 1
                        break
                    if t.startswith("-") and t != "-":
                        if (
                            t in ("-S", "--split-string")
                            or t.startswith("--split-string=")
                            or re.fullmatch(r"-[a-zA-Z]*S.*", t)
                        ):
                            return -1  # env -S: not followed
                        i += 2 if t in ENV_VALUE else 1
                    elif t == "-":
                        i += 1
                    else:
                        break
                while i < len(texts) and re.match(r"^[A-Za-z_]\w*=", texts[i]):
                    i += 1
            elif name in RUNNERS and texts[i + 1 : i + 2] == ["run"]:
                i += 2
            else:
                return i
        return i

    def expand(self, words: list[Word]) -> tuple[list[str], list[Word]]:
        """Literal texts of the words, constants substituted.

        Returns (texts, origin words); an unknown word is kept as its
        source with a leading marker. ``"$(command -v X)"`` stands for
        the program X.
        """
        texts: list[str] = []
        origins: list[Word] = []
        for word in words:
            node = word.node
            if word.literal:
                texts.append(word.text or "")
                origins.append(word)
                continue
            inner = node
            if (
                node.type == "string"
                and len(node.children) == 3
                and node.children[1].type
                in ("simple_expansion", "expansion", "command_substitution")
            ):
                inner = node.children[1]
            lookup = self.command_lookup(inner)
            if lookup is not None:
                texts.append(lookup)
                origins.append(word)
                continue
            name = self.plain_reference(inner)
            if name is not None and name in self.constants:
                value = self.constants[name]
                whole = self.is_array_all(inner)
                chosen = value if whole else value[:1]
                for element in chosen:
                    if not element.literal:
                        texts.append("\x00" + element.source)
                        origins.append(element)
                    elif word.quoted:
                        texts.append(element.text or "")
                        origins.append(element)
                    else:
                        for field_ in (element.text or "").split():
                            texts.append(field_)
                            origins.append(element)
                if not chosen and word.quoted:
                    texts.append("")
                    origins.append(word)
                continue
            texts.append("\x00" + word.source)
            origins.append(word)
        return texts, origins

    def command_lookup(self, node: Node) -> str | None:
        """The program ``$(command -v X)``, ``$(which X)`` or ``$(type -P X)`` finds."""
        if node.type != "command_substitution":
            return None
        inner = [c for c in node.children if c.is_named]
        if len(inner) != 1 or inner[0].type != "command":
            return None
        _a, words = command_words(self.src, inner[0])
        texts = [w.text for w in words]
        if any(t is None for t in texts):
            return None
        if texts[:2] in (["command", "-v"], ["type", "-P"]) and len(texts) == 3:
            return texts[2]
        if texts[:1] == ["which"] and len(texts) == 2:
            return texts[1]
        return None

    def plain_reference(self, node: Node) -> str | None:
        """The variable a bare $name / ${name} / ${name[@]} names, else None."""
        if node.type == "simple_expansion":
            child = node.children[1]
            return (
                _node_text(self.src, child)
                if child.type == "variable_name"
                else None
            )
        if node.type == "expansion":
            named = [c for c in node.children if c.is_named]
            if len(named) == 1 and named[0].type == "variable_name":
                return _node_text(self.src, named[0])
            if len(named) == 1 and named[0].type == "subscript":
                sub = named[0]
                index = _node_text(self.src, sub.children[2])
                if index in ("@", "*"):
                    return _node_text(self.src, sub.children[0])
        return None

    def is_array_all(self, node: Node) -> bool:
        return (
            node.type == "expansion"
            and "[@]" in _node_text(self.src, node)
            or "[*]" in _node_text(self.src, node)
        )

    def command(self, node: Node, redirects: list[Node], sink: bool) -> None:
        """Judge one simple command from its words."""
        assigns, words = command_words(self.src, node)
        for assign in assigns:
            self.assignment(assign)
        if not words:
            return
        texts, origins = self.expand(words)
        writes = sink or any(self.redirect_to_env(r) for r in redirects)
        self.env_writes(node, texts, redirects, writes)
        start = self.skip_wrappers(texts)
        if start == -1:
            self.report(
                node, "PPA009", "env -S: the command it runs is not read"
            )
            return
        if self.declares_pythonpath(node, texts, origins, start):
            return
        if start < len(texts):
            self.program(node, texts, origins, start, assigns)

    def declares_pythonpath(
        self, node: Node, texts: list[str], origins: list[Word], start: int
    ) -> bool:
        """Check PYTHONPATH words given to env, or to a quoted ``export``.

        Returns True when the command is a declaration builtin reached
        as a plain word (``"export"``, ``builtin export``), which
        tree-sitter does not read as one: it assigns and runs nothing.
        """
        declaring = start < len(texts) and texts[start] in DECLARATIONS
        for i, text in enumerate(texts):
            if i == 0 and not declaring:
                continue
            written = text[1:].lstrip('"') if text.startswith("\x00") else text
            if written.startswith("PYTHONPATH=") and (declaring or i > 0):
                self.check_pythonpath_word(origins[i], node)
        return declaring

    def program(
        self,
        node: Node,
        texts: list[str],
        origins: list[Word],
        start: int,
        assigns: list[Node],
    ) -> None:
        """Judge the program a command runs, past its wrappers."""
        name = texts[start]
        arguments, origin = texts[start + 1 :], origins[start + 1 :]
        if name.startswith("\x00"):
            # A path whose last segment is an interpreter name runs
            # Python wherever the directory part points.
            tail_name = name[1:].rstrip('"').rsplit("/", 1)[-1]
            if "/" in name and INTERPRETER.match(tail_name):
                self.python(node, arguments, origin, assigns)
            elif self.looks_like_python(name[1:], arguments):
                self.report(
                    node,
                    "PPA009",
                    f"program is {name[1:]!r}, which the scan cannot resolve",
                )
            return
        base = os.path.basename(name) if "/" in name else name
        if base in ("uv", "uvx"):
            self.uv(node, texts, start, assigns, origins)
        elif INTERPRETER.match(name) or name.startswith("GHEXPR_"):
            self.python(node, arguments, origin, assigns)

    @staticmethod
    def looks_like_python(name: str, arguments: list[str]) -> bool:
        """Whether an unknown program name is probably Python.

        From its arguments (``-m``, ``-c``, ``-``, an interpreter
        option, a ``.py`` file) or from the name itself.
        """
        looks = any(
            t in ("-m", "-c", "-", "-I", "-E", "-B", "-u", "-s")
            or re.fullmatch(r"-[a-zA-Z]*[mcI][a-zA-Z]*", t)
            or t.endswith(".py")
            for t in arguments[:4]
        )
        return looks or bool(re.search(r"py(thon)?\b|PY\b|PYTHON|python", name))

    def python(
        self,
        node: Node,
        args: list[str],
        origins: list[Word],
        assigns: list[Node],
    ) -> None:
        if self.trusted:
            return
        # Unknown words among the options decide the outcome; a word
        # once the mode is settled (a script's arguments) does not, and
        # a word that ends in .py is read as the script.
        clean = list(args)
        for i, a in enumerate(clean):
            if not a.startswith("\x00"):
                continue
            mode, flags = parse_python(clean[:i])
            settled = i > 0 and (clean[i - 1] == "-" or mode != "stdin")
            if "I" in flags or settled:
                clean = (
                    clean[:i]
                    if clean[i - 1 : i] == ["-"]
                    else clean[:i] + ["x.py"]
                )
                break
            if re.search(r"\.py[\"']?$", a):
                clean = clean[:i] + ["x.py"]
                break
            self.report(
                node,
                "PPA009",
                f"{a[1:]} may hold options; the scan cannot read it",
            )
            return
        mode, flags = parse_python(clean)
        if not risky(mode, flags):
            return
        safepath = "P" in flags or self.env_truthy("PYTHONSAFEPATH", assigns)
        rule = {"module": "PPA001", "command": "PPA002", "stdin": "PPA003"}[
            mode
        ]
        detail = RULES[rule] + (
            "; -P/PYTHONSAFEPATH protect only on 3.11+, use -I"
            if safepath
            else ""
        )
        self.report(node, rule, detail)

    def env_truthy(self, name: str, assigns: list[Node]) -> bool:
        for assign in assigns:
            n = assign.child_by_field_name("name")
            if n is not None and _node_text(self.src, n) == name:
                v = assign.child_by_field_name("value")
                return v is not None and (
                    literal_of(self.src, v) or ""
                ).strip().lower() in ("1", "true", "yes", "on")
        value = self.block.env.get(name)
        return value is not None and value.strip().lower() in (
            "1",
            "true",
            "yes",
            "on",
        )

    def env_setting(self, name: str, assigns: list[Node]) -> str | None:
        """A uv setting's literal value from prefix assignments or step env; None when unset or not literal."""
        for assign in assigns:
            n = assign.child_by_field_name("name")
            if n is not None and _node_text(self.src, n) == name:
                v = assign.child_by_field_name("value")
                return None if v is None else literal_of(self.src, v)
        if name in self.block.env:
            return self.block.env[name]
        return None

    def uv(
        self,
        node: Node,
        texts: list[str],
        start: int,
        assigns: list[Node],
        origins: list[Word] | None = None,
    ) -> None:
        """Judge a uv or uvx command from its options and the step's env."""
        if self.trusted:
            return
        is_uvx = os.path.basename(texts[start]).startswith("uvx")
        args = texts[start + 1 :]
        arg_origins = (origins or [])[start + 1 :]
        if not self.uv_readable(node, args, is_uvx):
            return
        cmd = parse_uvx(args) if is_uvx else parse_uv(args)
        if cmd.options & UV_INFO:
            return
        if "--directory" in cmd.values:
            directory = args[cmd.values["--directory"]].split("=", 1)[-1]
            if re.match(r"^(GHEXPR_|\$\{?GITHUB_ACTION_PATH\}?)", directory):
                return  # moved into the action path: trusted
        settings = self.uv_settings(cmd, args, arg_origins, assigns)
        for rule in uv_findings(cmd, settings, is_uvx):
            self.report(node, rule)
        # The program uv run launches.
        if cmd.program == -2:
            self.report(node, "PPA001")
        elif 0 <= cmd.program < len(args):
            rest = args[cmd.program :]
            inner = self.skip_wrappers(rest)
            if 0 <= inner < len(rest) and INTERPRETER.match(rest[inner]):
                self.python(node, rest[inner + 1 :], [], assigns)

    def uv_readable(self, node: Node, args: list[str], is_uvx: bool) -> bool:
        """False, with PPA009 reported, when a deciding uv word is unknown.

        Only option values that decide the outcome need to be known,
        and the subcommand itself.
        """
        probe = parse_uv(
            [a if not a.startswith("\x00") else "UNKNOWN" for a in args]
        )
        for name, index in probe.values.items():
            unknown = index < len(args) and args[index].startswith("\x00")
            if name in UV_DECIDING and unknown:
                self.report(
                    node,
                    "PPA009",
                    f"uv {name} is {args[index][1:]}, which the scan cannot read",
                )
                return False
        if (
            not is_uvx
            and not probe.subcommand
            and args
            and args[0].startswith("\x00")
        ):
            self.report(
                node,
                "PPA009",
                f"uv subcommand is {args[0][1:]}, which the scan cannot read",
            )
            return False
        return True

    def uv_settings(
        self,
        cmd: UvCommand,
        args: list[str],
        arg_origins: list[Word],
        assigns: list[Node],
    ) -> dict[str, bool]:
        """What protects this uv command: from its options, else the env."""
        options = cmd.options
        if "--python" in options:
            index = cmd.values.get("--python", -1)
            value = args[index] if 0 <= index < len(args) else ""
            value = re.sub(r"^(--python|-p)=", "", value)
            origin = (
                arg_origins[index] if 0 <= index < len(arg_origins) else None
            )
            looked_up = (
                origin is not None
                and self.command_lookup(self.unwrap_string(origin.node))
                is not None
            )
            python_path = looked_up or self.is_outside_path(value)
            any_python = True
        else:
            env_py = self.env_setting("UV_PYTHON", assigns)
            python_path = env_py is not None and self.is_outside_path(env_py)
            any_python = bool(env_py)
        return {
            "no_config": "--no-config" in options
            or self.env_truthy("UV_NO_CONFIG", assigns),
            "system": "--system" in options
            or self.env_truthy("UV_SYSTEM_PYTHON", assigns),
            "no_project": "--no-project" in options
            or self.env_truthy("UV_NO_PROJECT", assigns),
            "python_path": python_path,
            "any_python": any_python,
            "venv": self.is_outside_path(
                self.env_setting("VIRTUAL_ENV", assigns) or ""
            ),
            "project_env": self.is_outside_path(
                self.env_setting("UV_PROJECT_ENVIRONMENT", assigns) or ""
            ),
        }

    @staticmethod
    def unwrap_string(node: Node) -> Node:
        """The single part of ``"$x"`` or ``"$(...)"``, else the node itself."""
        if node.type == "string" and len(node.children) == 3:
            return node.children[1]
        return node

    @staticmethod
    def is_outside_path(value: str) -> bool:
        """An absolute path that is surely outside the workspace (prototype: /opt, /usr, $RUNNER_TEMP, $HOME...)."""
        if value.startswith("\x00"):
            return False
        return bool(
            re.match(
                r"^(/(?!home/runner/work)|\$\{?(RUNNER_TEMP|RUNNER_TOOL_CACHE|HOME|pythonLocation|Python_ROOT_DIR|GITHUB_ACTION_PATH)\}?/|GHEXPR_)",
                value,
            )
        )
