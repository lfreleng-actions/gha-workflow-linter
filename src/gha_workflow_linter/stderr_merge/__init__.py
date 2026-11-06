# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""The stderr-merge check: shell that merges stderr into data.

A command run with ``2>&1`` (or ``&>``, ``|&``, or after ``exec 2>&1``)
mixes any diagnostic it prints into its output. When a step then
parses, compares or extracts from that output, or writes it to a
``$GITHUB_*`` file, a harmless warning corrupts the value. The check
reads ``run:`` steps of workflows and composite actions, and shell
scripts, offline, with the tree-sitter-bash parse the other shell scan
uses.
"""

from ._rules import CONFIDENCES, RULES, Rule
from ._scan import (
    StderrMergeFinding,
    StderrMergeResult,
    file_tags,
    named_files,
    scan_repository,
    scan_text,
)

__all__ = [
    "CONFIDENCES",
    "RULES",
    "Rule",
    "StderrMergeFinding",
    "StderrMergeResult",
    "file_tags",
    "named_files",
    "scan_repository",
    "scan_text",
]
