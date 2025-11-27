# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

"""Utility functions shared across modules."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .models import ActionCall


def has_test_comment(action_call: ActionCall) -> bool:
    """
    Check if an action call has 'test' in its comment (case-insensitive).

    This function checks for the word 'test' at the beginning of a word boundary,
    which matches 'test', 'testing', 'tested', etc., but not substrings like
    'latest' or 'contest'.

    Args:
        action_call: The action call to check

    Returns:
        True if the comment contains 'test' as a word prefix, False otherwise

    Examples:
        >>> # Returns True for:
        >>> # - "# test"
        >>> # - "# Testing"
        >>> # - "# TEST version"
        >>> # - "# testing new feature"
        >>> # Returns False for:
        >>> # - "# latest"
        >>> # - "# v4"
        >>> # - "# stable"
    """
    if not action_call.comment:
        return False
    # Remove the leading '#' and whitespace, then check for 'test' as a word prefix
    comment_text = action_call.comment.lstrip("#").strip()
    # Use word boundary to match 'test' at start of word (includes testing, tested, etc.)
    return bool(re.search(r"\btest", comment_text, re.IGNORECASE))
