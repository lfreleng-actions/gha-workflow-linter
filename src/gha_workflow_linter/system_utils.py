# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

"""System utilities for gha-workflow-linter.

This module provides system-level utilities for detecting hardware capabilities
and optimizing parallel processing.
"""

from __future__ import annotations

import logging
import os

logger = logging.getLogger(__name__)


def get_default_worker_count() -> int:
    """Get the recommended default worker count for I/O-bound parallel tasks.

    For I/O-bound workloads (GitHub API calls, file operations), the optimal
    worker count is typically equal to or higher than the CPU count, since
    workers spend most of their time waiting on I/O rather than consuming CPU.

    This function uses os.cpu_count() directly, which returns the number of
    logical CPUs (includes hyperthreading/SMT). This is appropriate because:
    - I/O-bound tasks benefit from high parallelism
    - Workers are mostly waiting, not computing
    - Async I/O operations can handle many concurrent requests efficiently
    - The limiting factor is network/disk I/O, not CPU cores

    Returns:
        int: Recommended number of parallel workers (minimum 2, default 4)

    Examples:
        >>> workers = get_default_worker_count()
        >>> # On a system with 8 logical CPUs: returns 8
        >>> # On a system with 16 logical CPUs: returns 16
        >>> # On a system where cpu_count() fails: returns 4
    """
    cpu_count = os.cpu_count()

    if cpu_count is None:
        # Fallback if os.cpu_count() returns None (rare)
        logger.debug("Could not detect CPU count, using default of 4 workers")
        return 4

    # For I/O-bound tasks, use the full logical CPU count
    # Minimum of 2 to ensure some parallelism even on very limited systems
    workers = max(2, cpu_count)
    logger.debug(f"Using {workers} parallel workers (logical CPUs: {cpu_count})")
    return workers


def get_default_workers() -> int:
    """Get default worker count for parallel I/O operations.

    This is the recommended function to use for determining the default
    number of parallel workers for I/O-bound tasks like GitHub API calls.

    Returns:
        int: Recommended default number of workers

    Examples:
        >>> workers = get_default_workers()
        >>> # Use in CLI: default=get_default_workers()
    """
    return get_default_worker_count()
