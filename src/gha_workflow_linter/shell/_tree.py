# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""The tree-sitter-bash parse, and helpers over its nodes."""

from __future__ import annotations

from typing import TYPE_CHECKING

from tree_sitter import Language
import tree_sitter_bash

if TYPE_CHECKING:
    from tree_sitter import Node

BASH = Language(tree_sitter_bash.language())


def node_text(src: bytes, node: Node) -> str:
    """The source text of a node."""
    return src[node.start_byte : node.end_byte].decode("utf-8", "replace")


def statement_redirects(command: Node) -> list[Node]:
    """The redirects tree-sitter hangs on the statement around ``command``.

    They follow a command directly, or a pipeline whose last stage it
    is (``true | cat <<EOF``): they belong to that stage.
    """
    parent = command.parent
    if parent is not None and parent.type == "pipeline":
        stages = [c for c in parent.children if c.is_named]
        if stages[-1:] != [command]:
            return []
        command, parent = parent, parent.parent
    if (
        parent is None
        or parent.type != "redirected_statement"
        or parent.children[0] != command
    ):
        return []
    return parent.children[1:]
