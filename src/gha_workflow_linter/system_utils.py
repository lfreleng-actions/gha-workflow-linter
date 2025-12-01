# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

"""System utilities for gha-workflow-linter.

This module provides system-level utilities for detecting hardware capabilities
and optimizing parallel processing.
"""

from __future__ import annotations

import logging
import os
import subprocess
import sys

logger = logging.getLogger(__name__)


def get_performance_core_count() -> int:
    """Get the number of performance cores available on the system.

    This function attempts to detect the actual number of performance cores
    (P-cores) rather than the total logical CPU count which includes:
    - Efficiency cores (E-cores) on hybrid architectures
    - Hyperthreading/SMT virtual cores

    Detection methods by platform:
    - macOS: Uses sysctl to query hw.perflevel0.physicalcpu
    - Linux: Parses /sys/devices/system/cpu/ to count physical cores
    - Windows: Future enhancement could use WMI queries
    - Fallback: Uses half of total CPU count (assumes hyperthreading)

    Returns:
        int: Number of performance cores, minimum of 2

    Examples:
        >>> cores = get_performance_core_count()
        >>> # On a M1 Max with 10 cores: returns 8 (performance cores)
        >>> # On a 16-thread Intel CPU: returns 8 (physical cores)
    """
    cpu_count = os.cpu_count() or 4

    # macOS: Try to get performance core count directly
    if sys.platform == "darwin":
        try:
            result = subprocess.run(
                ["sysctl", "-n", "hw.perflevel0.physicalcpu"],
                capture_output=True,
                text=True,
                check=True,
                timeout=1,
            )
            perf_cores = int(result.stdout.strip())
            if perf_cores > 0:
                logger.debug(f"Detected {perf_cores} performance cores on macOS")
                return perf_cores
        except (subprocess.SubprocessError, ValueError, OSError) as e:
            logger.debug(
                f"Could not detect macOS performance cores: {e}, using fallback"
            )

    # Linux: Try to detect physical cores (excluding hyperthreading)
    # This is a reasonable approximation of performance cores
    if sys.platform.startswith("linux"):
        try:
            # Read physical core IDs from sysfs
            core_ids = set()
            cpu_dirs = os.listdir("/sys/devices/system/cpu/")
            for cpu_dir in cpu_dirs:
                if cpu_dir.startswith("cpu") and cpu_dir[3:].isdigit():
                    core_id_path = f"/sys/devices/system/cpu/{cpu_dir}/topology/core_id"
                    if os.path.exists(core_id_path):
                        with open(core_id_path) as f:
                            core_ids.add(int(f.read().strip()))

            if core_ids:
                phys_cores = len(core_ids)
                logger.debug(f"Detected {phys_cores} physical cores on Linux")
                return max(2, phys_cores)
        except (OSError, ValueError) as e:
            logger.debug(f"Could not detect Linux physical cores: {e}, using fallback")

    # Windows: Future enhancement
    # Could use: wmic cpu get NumberOfCores
    # Or: Get-CimInstance Win32_Processor | Select-Object NumberOfCores

    # Fallback: Use half of total CPU count
    # This assumes hyperthreading (2 threads per core) which is common
    # on modern CPUs. For CPUs without hyperthreading, this will
    # underestimate, but it's a safe conservative default.
    fallback_cores = max(2, cpu_count // 2)
    logger.debug(f"Using fallback: {fallback_cores} cores (total CPUs: {cpu_count})")
    return fallback_cores


def get_default_workers() -> int:
    """Get default worker count based on CPU performance cores.

    This is the recommended function to use for determining the default
    number of parallel workers for I/O-bound tasks like GitHub API calls.

    For I/O-bound workloads (which is what these tools primarily do),
    the performance core count is a good default as it:
    - Maximizes parallelism without oversubscribing the CPU
    - Avoids excessive context switching
    - Works well with async I/O operations

    Returns:
        int: Recommended default number of workers

    Examples:
        >>> workers = get_default_workers()
        >>> # Use in CLI: default=get_default_workers()
    """
    return get_performance_core_count()
