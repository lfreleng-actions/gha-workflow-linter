# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Judge each simple command from what is written in it.

The scan is a linter, not an interpreter of the shell:

- Each simple command is judged from its own literal words. A word
  that is not literal (an expansion, a substitution, an unquoted
  backslash, an ANSI-C string) in a position that decides the outcome
  is reported as unresolved (PPA009), never taken as safe.
- Nothing outside the command exempts it: no ``cd`` before it, no
  step ``working-directory`` and no variable's value. The one source
  besides the command's own words is the step's YAML ``env:``, for uv
  settings.
- Wrapper options are read from tables; an option a table does not
  list is PPA009, since its arity is unknown.
- A parse error anywhere in a block makes that block "not fully
  scanned" (PPA010), not clean.

A program the scan cannot name is reported only when the command
looks like Python; see DESIGN.md, Known limits.
"""

from __future__ import annotations

import os
import re
from typing import TYPE_CHECKING

from ._envfile import ENV_FILE, forwards_stdin
from ._invocation import (
    DECLARATIONS,
    EXPR_OPEN,
    INTERPRETER,
    POSITIONAL,
    RULES,
    RUNNERS,
    UNKNOWN_EXPRESSION,
    UNREAD_WRAPPER,
    WRAPPERS,
    env_of,
    expression_marker,
    looks_like_python,
    looks_like_uv,
    parse_env,
    parse_python,
    reads_assignments,
    risky,
    wrapper_assignment,
    wrapper_option,
)
from ._pythonpath import TEXT
from ._uv import UvChecks
from ._words import Word, _node_text, command_words, statement_redirects

if TYPE_CHECKING:
    from tree_sitter import Node


class CommandChecks(UvChecks):
    """Per-command judgement, mixed into the block scan."""

    def stdout_to_env(self, redirects: list[Node], out: bool) -> bool:
        """Whether standard output reaches $GITHUB_ENV after ``redirects``.

        ``out`` says whether it did before them. The last redirect of
        standard output wins; one to a destination the scan cannot
        read leaves ``out`` as it was.
        """
        for node in redirects:
            if node.type == "heredoc_redirect":
                # cat <<EOF >> "$GITHUB_ENV": the grammar nests the file redirect.
                nested = [c for c in node.children if c.type == "file_redirect"]
                out = self.stdout_to_env(nested, out)
                continue
            if node.type != "file_redirect":
                continue
            # A descriptor comes before the operator; words after the
            # destination are the command's arguments.
            ops = [c.type for c in node.children if not c.is_named]
            descriptor = [
                _node_text(self.src, c)
                for c in node.children
                if c.type == "file_descriptor"
            ]
            target = node.child_by_field_name("destination")
            if descriptor not in ([], ["1"]) or target is None:
                continue
            text = _node_text(self.src, target)
            if ops[:1] == [">&"] and (text.isdigit() or text == "-"):
                out = out if text == "1" else False
            elif ops[:1] in ([">"], [">>"], [">|"], ["&>"], ["&>>"], [">&"]):
                if text.strip('"') in ENV_FILE:
                    out = True
                elif not re.search(f"[$`\\\\{EXPR_OPEN}]", text):
                    out = False
        return out

    def stdin_replaced(self, redirects: list[Node]) -> bool:
        """Whether ``redirects`` give a command other standard input."""
        for node in redirects:
            if node.type in ("heredoc_redirect", "herestring_redirect"):
                return True
            ops = [c.type for c in node.children if not c.is_named]
            descriptor = [
                c for c in node.children if c.type == "file_descriptor"
            ]
            target = node.child_by_field_name("destination")
            same = ops[:1] == ["<&"] and (
                target is not None and _node_text(self.src, target) == "0"
            )
            if (
                node.type == "file_redirect"
                and ops[:1] in (["<"], ["<&"], ["<>"])
                and not (descriptor or same)
            ):
                return True
        return False

    def input_to_env(self, node: Node, out: bool, depth: int = 0) -> bool:
        """Whether what ``node`` reads on standard input reaches $GITHUB_ENV.

        ``out`` says whether its piped standard output does. tee naming
        the file writes its input there; cat and tee pass it on to
        their output. A pipeline passes it back stage by stage from its
        last; a group or subshell of one command is that command.
        """
        if depth > 200:
            return False
        if node.type == "redirected_statement":
            redirects = node.children[1:]
            if self.stdin_replaced(redirects):
                return False
            return self.input_to_env(
                node.children[0], self.stdout_to_env(redirects, out), depth + 1
            )
        if node.type == "pipeline":
            for stage in reversed([c for c in node.children if c.is_named]):
                out = self.input_to_env(stage, out, depth + 1)
            return out
        if node.type in ("subshell", "compound_statement"):
            inner = [
                c for c in node.children if c.is_named and c.type != "comment"
            ]
            return len(inner) == 1 and self.input_to_env(
                inner[0], out, depth + 1
            )
        return node.type == "command" and self.passes_input(node, out)

    def passes_input(self, node: Node, out: bool) -> bool:
        """Whether a simple command copies its input into $GITHUB_ENV."""
        if self.stdin_replaced(node.children_by_field_name("redirect")):
            return False
        _a, words = command_words(self.src, node)
        texts = [
            (w.text or "") if w.literal else "\x00" + w.source for w in words
        ]
        start = self.skip_wrappers(texts, [w.source for w in words])
        if not 0 <= start < len(words) or not words[start].literal:
            return False
        name = os.path.basename(texts[start])
        tee = name == "tee" and any(
            w.source.strip('"') in ENV_FILE for w in words[start + 1 :]
        )
        return tee or (out and forwards_stdin(name, texts[start + 1 :]))

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
            # export "PYTHONPATH=..." or 'PYTHONPATH+=...': one word.
            for child in node.children:
                if child.type in (
                    "string",
                    "raw_string",
                    "concatenation",
                    "word",
                ):
                    tokens = self.pythonpath_tokens(child)
                    text = "".join(t.text for t in tokens if t.kind == TEXT)
                    if re.match(r"PYTHONPATH\+?=", text):
                        self.check_pythonpath_word(child, child, declared=True)

    # -- commands

    def skip_wrappers(self, texts: list[str], sources: list[str]) -> int:
        """Index of the real program past wrappers; len(texts) if none runs.

        A word holding ``=`` is an assignment only after a wrapper that
        reads one (env's are read by ``parse_env``), and after ``time``
        or ``coproc`` only when it opens with a name as written
        (``sources``); elsewhere it is the program, as in
        ``/opt/runtime=3/bin/python3``.
        """
        i = 0
        assigns: str | None = None  # how the wrapper read last takes NAME=
        while i < len(texts):
            name = os.path.basename(texts[i]) if "/" in texts[i] else texts[i]
            if wrapper_assignment(assigns, texts[i], sources[i]) is not None:
                i += 1
            elif name in WRAPPERS:
                assigns = reads_assignments(texts[i])
                i += 1
                while i < len(texts) and texts[i].startswith("-"):
                    if texts[i] == "--":
                        i += 1
                        break
                    if name == "command" and set(texts[i][1:]) & {"v", "V"}:
                        return len(texts)
                    used = wrapper_option(WRAPPERS[name], texts[i])
                    if used is None:
                        return -1  # an option the scan does not know
                    i += used
                i += POSITIONAL.get(name, 0)
            elif name == "env":
                assigns = None
                i = parse_env(texts, i + 1).end
                if i < 0:
                    return -1  # env -S: not followed
            elif name in RUNNERS and texts[i + 1 : i + 2] == ["run"]:
                assigns = None
                i += 2
                if texts[i : i + 1] == ["--"]:
                    i += 1
            else:
                return i
        return i

    def expand(self, words: list[Word]) -> tuple[list[str], list[Word]]:
        """Literal texts of the words.

        Returns (texts, origin words); an unknown word is kept as its
        source with a leading marker. ``"$(command -v X)"`` stands for
        the program X.
        """
        texts: list[str] = []
        for word in words:
            if word.literal:
                texts.append(word.text or "")
                continue
            node = word.node
            inner = node
            if (
                node.type == "string"
                and len(node.children) == 3
                and node.children[1].type == "command_substitution"
            ):
                inner = node.children[1]
            lookup = self.command_lookup(inner)
            texts.append("\x00" + word.source if lookup is None else lookup)
        return texts, list(words)

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

    def command(self, node: Node, redirects: list[Node], sink: bool) -> None:
        """Judge one simple command from its words."""
        assigns, words = command_words(self.src, node)
        for assign in assigns:
            self.assignment(assign)
        if not words:
            return
        texts, origins = self.expand(words)
        sources = [w.source for w in origins]
        self.env_writes(node, texts, origins, redirects, sink)
        start = self.skip_wrappers(texts, sources)
        if start == -1:
            self.report(node, "PPA009", UNREAD_WRAPPER)
            return
        if self.declares_pythonpath(node, texts, origins, start):
            return
        if start < len(texts):
            self.wrapper_env = env_of(texts[:start], sources)
            try:
                self.program(node, texts, origins, start, assigns)
            finally:
                self.wrapper_env = None

    def declares_pythonpath(
        self, node: Node, texts: list[str], origins: list[Word], start: int
    ) -> bool:
        """Check PYTHONPATH words given to env or sudo, or to a quoted ``export``.

        Returns True when the command is a declaration builtin reached
        as a plain word (``"export"``, ``builtin export``), which
        tree-sitter does not read as one: it assigns and runs nothing.
        Only the words env or sudo reads as assignments count before
        the program; a wrapper option's operand (``exec -a``) does not.
        """
        declaring = start < len(texts) and texts[start] in DECLARATIONS
        wrapped = env_of(texts[:start], [w.source for w in origins])
        authored = {
            texts[i].lstrip("\x00\"'").split("=", 1)[0] for i in wrapped.words
        }
        if "PYTHONPATH" in wrapped.names and "PYTHONPATH" not in authored:
            # Set by a wrapper itself (xargs --process-slot-var) to a
            # number: a relative entry the scan does not see written.
            self.report(
                node,
                "PPA009",
                "PYTHONPATH set by a wrapper to a value the scan cannot read",
            )
        positions = range(start + 1, len(texts)) if declaring else wrapped.words
        for i in positions:
            text = texts[i]
            written = (
                text[1:].lstrip("\"'") if text.startswith("\x00") else text
            )
            # Only a declaration reads PYTHONPATH+=; env would set a
            # variable named "PYTHONPATH+".
            name = re.match(r"PYTHONPATH\+?=", written)
            if name and (declaring or "+" not in name[0]):
                self.check_pythonpath_word(
                    origins[i].node,
                    node,
                    declared=declaring,
                    tilde=declaring or i in wrapped.shell_words,
                )
        return declaring

    def program(
        self,
        node: Node,
        texts: list[str],
        origins: list[Word],
        start: int,
        assigns: list[Node],
    ) -> None:
        """Judge the program a command runs, past its wrappers.

        A program name the scan cannot read is PPA009 only when the
        command looks like Python or uv; a path whose last segment it
        can read is judged by that segment.
        """
        name = texts[start]
        arguments, origin = texts[start + 1 :], origins[start + 1 :]
        unread = name.startswith("\x00")
        written = name[1:] if unread else name
        tail = os.path.basename(written.strip("\"'"))
        if tail in ("uv", "uvx"):
            self.uv(node, texts, start, assigns, origins)
        elif INTERPRETER.match(tail) or written.startswith(
            expression_marker("PYTHON")
        ):
            self.python(node, arguments, origin, assigns)
        elif unread or EXPR_OPEN in written:
            shown = [
                a[1:].strip("\"'") if a[:1] == "\x00" else a for a in arguments
            ]
            shown = ["-", *shown] if self.dash_before_heredoc(node) else shown
            if looks_like_python(written, shown) or looks_like_uv(written):
                self.report(
                    node,
                    "PPA009",
                    f"program is {written!r}, which the scan cannot resolve",
                )

    def dash_before_heredoc(self, node: Node) -> bool:
        """Whether a ``-`` stands last before a heredoc (``"$X" - <<EOF``).

        tree-sitter-bash drops that word from the command.
        """
        following = statement_redirects(node)[:1]
        if not following or following[0].type != "heredoc_redirect":
            return False
        gap = self.src[node.end_byte : following[0].start_byte]
        return gap.split() == [b"-"]

    def python(
        self,
        node: Node,
        args: list[str],
        origins: list[Word],
        assigns: list[Node],
    ) -> None:
        # Unknown words among the options decide the outcome; a word
        # once the mode is settled (a script's arguments) does not, and
        # a word that ends in .py is read as the script. An expression
        # that is not a path is as unknown as a variable.
        clean = [
            "\x00" + a
            if UNKNOWN_EXPRESSION.search(a) and not a.startswith("\x00")
            else a
            for a in args
        ]
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
            # A word ending in .py is the script, unless it opens with an
            # option as written (-X"...${x}.py").
            opens = a[1:].lstrip("\"'")
            # bash decodes $'...' and backslashes; the scan does not.
            decoded = a[1:].startswith("$'") or "\\" in opens
            script = re.search(r"\.py[\"']?$", a) and not opens.startswith("-")
            if script and not decoded:
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
            "; -P/PYTHONSAFEPATH protection is partial (3.11+ only), use -I"
            if safepath
            else ""
        )
        self.report(node, rule, detail)
