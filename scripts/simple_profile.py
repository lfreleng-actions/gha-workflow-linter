#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

"""
Simple profiling script that directly profiles the linter.
"""

import cProfile
from pathlib import Path
import pstats
import sys

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))


def run_linter() -> None:
    """Run the linter."""
    from gha_workflow_linter.cli import app

    # Set up arguments
    original_argv = sys.argv
    sys.argv = ["gha-workflow-linter", "lint", ".", "--quiet"]

    try:
        app()
    except SystemExit:
        pass
    finally:
        sys.argv = original_argv


if __name__ == "__main__":
    print("Starting profiling...")
    print("=" * 70)

    # Profile the linter
    profiler = cProfile.Profile()
    profiler.enable()

    run_linter()

    profiler.disable()

    print("\n" + "=" * 70)
    print("PROFILING RESULTS")
    print("=" * 70)

    # Create stats
    stats = pstats.Stats(profiler)

    # Save to file
    output_file = "profiling_results/profile.prof"
    Path("profiling_results").mkdir(exist_ok=True)
    stats.dump_stats(output_file)
    print(f"\n✓ Profile saved to: {output_file}")

    # Print top functions by cumulative time
    print("\n" + "=" * 70)
    print("TOP 30 FUNCTIONS BY CUMULATIVE TIME")
    print("=" * 70)
    stats.sort_stats(pstats.SortKey.CUMULATIVE)
    stats.print_stats(30)

    # Print top functions by self time
    print("\n" + "=" * 70)
    print("TOP 30 FUNCTIONS BY SELF TIME")
    print("=" * 70)
    stats.sort_stats(pstats.SortKey.TIME)
    stats.print_stats(30)

    print("\n" + "=" * 70)
    print("ANALYSIS")
    print("=" * 70)
    print("\nLook for:")
    print("  • High cumtime with low tottime = coordination overhead")
    print("  • Functions with many calls = batching opportunities")
    print("  • Network/IO operations (urllib3, requests, http)")
    print("\nVisualize with: snakeviz profiling_results/profile.prof")
