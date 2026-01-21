#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation
# pyright: reportAny=false, reportUnknownMemberType=false, reportUnknownArgumentType=false, reportUnknownVariableType=false, reportDeprecated=false

"""
Performance profiling script for GHA Workflow Linter.

This script profiles the linter to identify bottlenecks and opportunities
for parallelization. It uses cProfile for function-level profiling and
provides detailed analysis of where time is spent.
"""

import argparse
import contextlib
import cProfile
import io
from pathlib import Path
import pstats
from pstats import SortKey
import sys
import time
from typing import Optional

# Add parent directory to path to import the linter
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from gha_workflow_linter.cli import app as cli_app


def profile_with_cprofile(
    args: list[str], output_file: Optional[str] = None
) -> pstats.Stats:
    """Profile the linter using cProfile."""
    profiler = cProfile.Profile()

    print(f"\n{'=' * 60}")
    print("Starting cProfile profiling...")
    print(f"Arguments: {' '.join(args)}")
    print(f"{'=' * 60}\n")

    # Backup sys.argv and replace it
    original_argv = sys.argv
    sys.argv = ["gha-workflow-linter"] + args

    try:
        # Profile the execution
        profiler.enable()
        start_time = time.perf_counter()

        with contextlib.suppress(SystemExit):
            cli_app()

        end_time = time.perf_counter()
        profiler.disable()

        elapsed = end_time - start_time
        print(f"\n{'=' * 60}")
        print(f"Profiling completed in {elapsed:.3f}s")
        print(f"{'=' * 60}\n")

        # Create stats object
        stats = pstats.Stats(profiler)

        # Save to file if requested
        if output_file:
            stats.dump_stats(output_file)
            print(f"Profile data saved to: {output_file}")

        return stats

    finally:
        sys.argv = original_argv


def print_profile_report(stats: pstats.Stats, limit: int = 50) -> None:
    """Print detailed profile report."""
    print(f"\n{'=' * 60}")
    print("TOP FUNCTIONS BY CUMULATIVE TIME")
    print(f"{'=' * 60}\n")

    _ = stats.sort_stats(SortKey.CUMULATIVE)
    _ = stats.print_stats(limit)

    print(f"\n{'=' * 60}")
    print("TOP FUNCTIONS BY TOTAL TIME (excluding subcalls)")
    print(f"{'=' * 60}\n")

    _ = stats.sort_stats(SortKey.TIME)
    _ = stats.print_stats(limit)

    print(f"\n{'=' * 60}")
    print("FUNCTIONS WITH MOST CALLS")
    print(f"{'=' * 60}\n")

    _ = stats.sort_stats(SortKey.CALLS)
    _ = stats.print_stats(limit)


def analyze_bottlenecks(stats: pstats.Stats) -> None:
    """Analyze the profile data for common bottlenecks."""
    print(f"\n{'=' * 60}")
    print("BOTTLENECK ANALYSIS")
    print(f"{'=' * 60}\n")

    # Get the raw stats
    _ = stats.sort_stats(SortKey.CUMULATIVE)

    # Capture stats output to analyze it
    import sys as sys_module

    old_stdout = sys_module.stdout
    stream = io.StringIO()
    sys_module.stdout = stream
    _ = stats.print_stats()
    sys_module.stdout = old_stdout

    output = stream.getvalue()

    # Analyze for common patterns
    issues: list[str] = []

    if "urllib3" in output or "requests" in output or "http" in output.lower():
        issues.append(
            "🌐 NETWORK I/O: Significant time in HTTP/network operations"
        )

    if "json.loads" in output or "json.dumps" in output:
        issues.append("📄 JSON PARSING: Time spent parsing/serializing JSON")

    if "open" in output or "read" in output or "write" in output:
        issues.append("💾 FILE I/O: Time spent on file operations")

    if "sleep" in output or "wait" in output:
        issues.append("⏱️  BLOCKING: Code is using sleep/wait operations")

    if "_lock" in output or "Lock" in output or "Semaphore" in output:
        issues.append("🔒 SYNCHRONIZATION: Time spent in locks/synchronization")

    # Check for serial GraphQL operations
    if "github_api" in output or "graphql" in output.lower():
        issues.append("📊 GRAPHQL: GraphQL queries detected (check if serial)")

    if "validator" in output or "validate" in output:
        issues.append(
            "✅ VALIDATION: Validation logic (check if parallelizable)"
        )

    if "git" in output.lower():
        issues.append("🔧 GIT OPERATIONS: Git-related operations detected")

    if issues:
        print("Detected potential bottlenecks:\n")
        for issue in issues:
            print(f"  {issue}")
    else:
        print("No obvious bottlenecks detected in common areas.")

    print(f"\n{'=' * 60}")
    print("RECOMMENDATIONS")
    print(f"{'=' * 60}\n")

    print("""
Based on typical async Python patterns, consider:

1. 🚀 PARALLELIZATION OPPORTUNITIES:
   - GraphQL queries: Batch multiple queries or use asyncio.gather()
   - File scanning: Process multiple files concurrently
   - Validation: Validate multiple actions in parallel
   - Network requests: Use connection pooling and concurrent requests

2. 🎯 OPTIMIZATION TARGETS:
   - Functions with high cumulative time but low self-time = coordination overhead
   - Functions with high self-time = CPU-bound work (good parallel candidates)
   - Functions with many calls = potential caching opportunities

3. 🔍 NEXT STEPS:
   - Look at top cumulative time functions for serial bottlenecks
   - Check if async/await is actually running concurrently (asyncio.gather vs serial await)
   - Measure actual network/I/O wait time vs CPU time
   - Profile with different worker counts to see if parallelism helps
    """)


def print_call_graph_hints(
    stats: pstats.Stats, focus_functions: list[str]
) -> None:
    """Print call graph information for specific functions."""
    print(f"\n{'=' * 60}")
    print("CALL GRAPH ANALYSIS")
    print(f"{'=' * 60}\n")

    for func_name in focus_functions:
        print(f"\nCalls TO/FROM functions matching '{func_name}':\n")
        _ = stats.print_callers(func_name)
        print("\n" + "-" * 40 + "\n")
        _ = stats.print_callees(func_name)
        print("\n" + "=" * 60 + "\n")


def compare_profiles(profile1_path: str, profile2_path: str) -> None:
    """Compare two profile runs."""
    print(f"\n{'=' * 60}")
    print("COMPARING PROFILES")
    print(f"{'=' * 60}\n")

    print(f"Profile 1: {profile1_path}")
    print(f"Profile 2: {profile2_path}\n")

    # This would need custom logic to compare specific metrics
    print("Note: Use tools like snakeviz or gprof2dot for visual comparison")
    print(f"  snakeviz {profile1_path}")
    print(f"  snakeviz {profile2_path}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Profile GHA Workflow Linter performance"
    )
    _ = parser.add_argument(
        "path",
        nargs="?",
        default=".",
        help="Path to scan (default: current directory)",
    )
    _ = parser.add_argument(
        "--output",
        "-o",
        help="Save profile data to file (.prof)",
    )
    _ = parser.add_argument(
        "--limit",
        type=int,
        default=50,
        help="Number of functions to show in reports (default: 50)",
    )
    _ = parser.add_argument(
        "--no-parallel",
        action="store_true",
        help="Run without parallel workers",
    )
    _ = parser.add_argument(
        "--workers",
        type=int,
        help="Number of parallel workers",
    )
    _ = parser.add_argument(
        "--clear-cache",
        action="store_true",
        help="Clear cache before profiling",
    )
    _ = parser.add_argument(
        "--focus",
        nargs="+",
        help="Functions to focus call graph analysis on",
    )
    _ = parser.add_argument(
        "--compare",
        nargs=2,
        metavar=("PROFILE1", "PROFILE2"),
        help="Compare two existing profile files",
    )

    args = parser.parse_args()

    # Handle comparison mode
    if args.compare and isinstance(args.compare, list):
        compare_profiles(str(args.compare[0]), str(args.compare[1]))
        return

    # Build CLI arguments
    cli_args = [str(args.path)]

    if hasattr(args, "no_parallel") and args.no_parallel:
        cli_args.append("--no-parallel")
    elif hasattr(args, "workers") and args.workers is not None:
        cli_args.extend(["--workers", str(int(args.workers))])

    if hasattr(args, "clear_cache") and args.clear_cache:
        cli_args.append("--clear-cache")

    # Run profiling
    output_file_arg = (
        str(args.output) if hasattr(args, "output") and args.output else None
    )
    stats = profile_with_cprofile(cli_args, output_file=output_file_arg)

    # Print reports
    limit_arg = int(args.limit) if hasattr(args, "limit") and args.limit else 50
    print_profile_report(stats, limit_arg)

    # Analyze bottlenecks
    analyze_bottlenecks(stats)

    # Print call graph for specific functions if requested
    if hasattr(args, "focus") and args.focus:
        focus_list = (
            [str(f) for f in args.focus] if isinstance(args.focus, list) else []
        )
        print_call_graph_hints(stats, focus_list)

    # Print usage hints
    print(f"\n{'=' * 60}")
    print("VISUALIZATION OPTIONS")
    print(f"{'=' * 60}\n")

    if hasattr(args, "output") and args.output:
        output_str = str(args.output)
        print("To visualize this profile, you can use:\n")
        print("  # Interactive visualization")
        print("  pip install snakeviz")
        print(f"  snakeviz {output_str}\n")
        print("  # Or generate a call graph")
        print("  pip install gprof2dot")
        print(
            f"  gprof2dot -f pstats {output_str} | dot -Tpng -o profile.png\n"
        )
    else:
        print("Use --output to save profile data for visualization tools")

    print("\nTo focus analysis on specific functions:")
    print("  python scripts/profile_performance.py --focus validate github_api")


if __name__ == "__main__":
    main()
