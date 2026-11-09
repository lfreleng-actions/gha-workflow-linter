# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Whether a use of a capture runs only when the captured command failed.

The model is lexical, within one block or function:

- ``if ! v=$(...); then A; else B; fi``: ``A`` is the failure path;
- ``if v=$(...); then A; else B; fi``: ``B`` is the failure path;
- ``v=$(...) || A``: ``A`` is the failure path, as is ``B`` in
  ``v=$(...) || A || B``;
- ``v=$(...); s=$?`` then ``if [ "$s" -eq 0 ]``: the zero branch is the
  success path and the other branches, ``elif`` included, the failure
  path; ``-ne 0`` turns that round, as does ``!``, and a test joined
  to anything else by ``&&``, ``||`` or a pipe is left unclassified.
  The test must be the ``if``'s last condition statement, and ``s``
  must not have been written to since it saved ``$?``.

A capture joined to anything else in an ``if`` condition, or negated
before an ``||``, is left unclassified too: ``if v=$(...) && b`` runs
its ``else`` when ``b`` fails after the capture succeeded.

Anything else, including code after the ``fi``, is the success path.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, NamedTuple

from gha_workflow_linter.shell._tree import node_text

from ._words import statement_of, unquoted, within

if TYPE_CHECKING:
    from tree_sitter import Node


class SavedStatus(NamedTuple):
    """The variable a capture's ``$?`` is saved in.

    ``until`` is the byte offset of its next write, after which it no
    longer says whether the capture succeeded.
    """

    name: str
    until: int


ZERO_THEN = frozenset({"-eq", "=", "=="})
NONZERO_THEN = frozenset({"-ne", "!=", "-gt"})
FLIPPED = {"then-success": "then-failure", "then-failure": "then-success"}
# Nodes a status test passes through without changing its sense.
TRANSPARENT = frozenset(
    {"test_command", "parenthesized_expression", "redirected_statement"}
)


def _assignment_of(node: Node | None) -> Node | None:
    """The assignment a statement makes, through ``local`` and the like."""
    if node is None:
        return None
    if node.type == "variable_assignment":
        return node
    if node.type == "declaration_command":
        found = [
            c for c in node.named_children if c.type == "variable_assignment"
        ]
        return found[0] if len(found) == 1 else None
    return None


def status_after(src: bytes, assign: Node) -> Node | None:
    """The assignment the next statement saves ``$?`` in, if it does."""
    following = statement_of(assign).next_named_sibling
    while following is not None and following.type == "comment":
        following = following.next_named_sibling
    saved = _assignment_of(following)
    if saved is None:
        return None
    value = saved.child_by_field_name("value")
    if value is None or saved.child_by_field_name("name") is None:
        return None
    if unquoted(src, value) != "$?":
        return None
    return saved


def _conditions(if_statement: Node) -> list[Node]:
    """The condition statements of an ``if``, before its ``then``."""
    found: list[Node] = []
    for child in if_statement.children:
        if child.type == "then":
            break
        if child.is_named and child.type != "comment":
            found.append(child)
    return found


def _branch(if_statement: Node, child: Node) -> str:
    """Which part of an ``if`` a direct child is: cond, then or else."""
    if child.type in ("elif_clause", "else_clause"):
        return "else"
    if any(child == c for c in _conditions(if_statement)):
        return "cond"
    return "then"


def _capture_polarity(if_statement: Node, assign: Node) -> str | None:
    """Which branch is success when the capture is the condition.

    Only a condition that is the capture alone, or the capture under
    ``!``, decides it; anything joined to the capture leaves it open.
    """
    conditions = _conditions(if_statement)
    if not conditions or not within(assign, conditions[-1]):
        return None
    polarity = "then-success"
    node = assign
    while node != conditions[-1]:
        parent = node.parent
        if parent is None or parent.type != "negated_command":
            return None
        node = parent
        polarity = FLIPPED[polarity]
    return polarity


def _names_status(src: bytes, node: Node, status: str) -> bool:
    """Whether a word is ``$status`` or ``${status}``."""
    return unquoted(src, node) in (f"${status}", f"${{{status}}}")


def _status_test(src: bytes, expression: Node, status: str) -> str | None:
    """Which branch a test of ``$status`` against 0 makes the success path."""
    left = expression.child_by_field_name("left")
    right = expression.child_by_field_name("right")
    operator = expression.child_by_field_name("operator")
    if left is None or right is None or operator is None:
        return None
    if _names_status(src, right, status):
        left, right = right, left
    if not _names_status(src, left, status) or unquoted(src, right) != "0":
        return None
    op = node_text(src, operator)
    if op in ZERO_THEN:
        return "then-success"
    if op in NONZERO_THEN:
        return "then-failure"
    return None


def _status_polarity(src: bytes, if_statement: Node, status: str) -> str | None:
    """Which branch is success when the condition tests the saved status.

    Only the last condition statement decides the branch, so the test
    must be there. The test's polarity is read up through it: ``!``
    turns it round, and any other construct between the test and the
    ``if`` (``&&``, ``||``, a pipeline) leaves the branches unclassified.
    """
    conditions = _conditions(if_statement)
    pending = conditions[-1:]
    while pending:
        node = pending.pop()
        if node.type == "binary_expression":
            found = _status_test(src, node, status)
            if found:
                return _through_condition(node, if_statement, found)
        pending.extend(node.named_children)
    return None


def _through_condition(
    test: Node, if_statement: Node, polarity: str
) -> str | None:
    """A test's polarity as the whole condition of an ``if`` gives it."""
    node = test.parent
    while node is not None and node != if_statement:
        negation = node.type == "negated_command" or (
            node.type == "unary_expression" and node.children[0].type == "!"
        )
        if negation:
            polarity = FLIPPED[polarity]
        elif node.type not in TRANSPARENT:
            return None
        node = node.parent
    return polarity


def _on_failure_branch(
    src: bytes,
    if_statement: Node,
    child: Node,
    assign: Node,
    status: SavedStatus | None,
) -> bool:
    """Whether a child of an ``if`` runs only when the capture failed."""
    branch = _branch(if_statement, child)
    if branch == "cond":
        return False
    polarity = _capture_polarity(if_statement, assign)
    if (
        polarity is None
        and status is not None
        and if_statement.start_byte < status.until
    ):
        polarity = _status_polarity(src, if_statement, status.name)
    if polarity == "then-success":
        return branch == "else"
    if polarity == "then-failure":
        return branch == "then"
    return False


def _fails_with(left: Node, assign: Node) -> bool:
    """Whether ``left`` fails only when the capture failed.

    That holds for the capture itself and for ``capture || A``, which
    fails only when both did; not for ``! capture`` or ``capture && A``.
    """
    if left == assign:
        return True
    if left.type == "declaration_command":
        return assign.parent == left
    parts = left.children
    return (
        left.type == "list"
        and len(parts) == 3
        and parts[1].type == "||"
        and _fails_with(parts[0], assign)
    )


def _after_or(parent: Node, child: Node, assign: Node) -> bool:
    """Whether ``child`` is the right of an ``||`` whose left captures."""
    parts = parent.children
    return (
        len(parts) == 3
        and parts[1].type == "||"
        and child == parts[2]
        and _fails_with(parts[0], assign)
    )


def failure_path(
    src: bytes, use: Node, assign: Node, status: SavedStatus | None
) -> bool:
    """Whether ``use`` runs only when the captured command failed."""
    node = use
    while node.parent is not None:
        parent = node.parent
        if parent.type == "if_statement" and _on_failure_branch(
            src, parent, node, assign, status
        ):
            return True
        if parent.type == "list" and _after_or(parent, node, assign):
            return True
        node = parent
    return False
