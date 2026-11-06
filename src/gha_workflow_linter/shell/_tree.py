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


def descriptor_word(command: Node, last: Node) -> bool:
    """Whether ``last``, a command's last word, is its redirect's descriptor.

    In ``python3 0< file`` tree-sitter reads ``0`` as an argument; bash
    reads it as the descriptor of the redirect that follows it directly.
    """
    following = statement_redirects(command)[:1]
    return (
        last.type == "number"
        and bool(following)
        and following[0].type == "file_redirect"
        and following[0].start_byte == last.end_byte
    )


def redirect_words(command: Node) -> list[Node]:
    """The words tree-sitter hangs on a command's redirects, in order.

    A word after a redirect's target, as ``-I`` in ``python3 < f -I``
    or ``-c`` in ``python3 2>/dev/null -c ...``, is attached to the
    redirect; bash reads it as the command's.
    """
    found: list[Node] = []
    for redirect in statement_redirects(command):
        if redirect.type == "file_redirect":
            target = redirect.child_by_field_name("destination")
            after = target.end_byte if target is not None else 0
            found += [
                child
                for child in redirect.named_children
                if child.start_byte >= after and child.type != "file_descriptor"
            ]
    return found
