#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

# Benchmark script for testing parallel worker performance
# Tests different worker configurations with cold cache each time

set -e

CACHE_FILE="$HOME/.cache/gha-workflow-linter/validation_cache.json"
RESULTS_FILE="benchmark_results.txt"

echo "========================================="
echo "GHA Workflow Linter - Worker Benchmark"
echo "========================================="
echo ""
echo "This benchmark will test different worker configurations"
echo "with a cold cache for each run."
echo ""
echo "Test configurations:"
echo "  1. --no-parallel (sequential processing)"
echo "  2. --workers 1 (1 parallel worker)"
echo "  3. --workers 2 (2 parallel workers)"
echo "  4. --workers 4 (4 parallel workers)"
echo "  5. --workers 10 (10 parallel workers)"
echo ""

# Clear any existing results
true > "$RESULTS_FILE"

echo "Results will be saved to: $RESULTS_FILE"
echo ""

# Function to run benchmark with cold cache
run_benchmark() {
    local config_name="$1"
    local args="$2"

    echo "========================================="
    echo "Testing: $config_name"
    echo "Arguments: $args"
    echo "========================================="

    # Clear cache for cold start
    if [ -f "$CACHE_FILE" ]; then
        rm -f "$CACHE_FILE"
        echo "✓ Cache cleared"
    fi

    # Run the linter and capture timing
    echo "Running linter..."
    START_TIME=$(date +%s.%N)

    # Run with --auto-fix to exercise the full workflow including latest version fetching
    if uv run gha-workflow-linter lint . --auto-fix "$args" > /dev/null 2>&1; then
        END_TIME=$(date +%s.%N)
        DURATION=$(echo "$END_TIME - $START_TIME" | bc)

        echo "✓ Completed in ${DURATION}s"
        echo ""

        # Log results
        echo "$config_name: ${DURATION}s" >> "$RESULTS_FILE"
    else
        echo "✗ Failed to run benchmark"
        echo "$config_name: FAILED" >> "$RESULTS_FILE"
    fi
}

# Test 1: No parallel processing
run_benchmark "No Parallel (Sequential)" "--no-parallel"

# Test 2: 1 worker
run_benchmark "1 Worker" "--workers 1"

# Test 3: 2 workers
run_benchmark "2 Workers" "--workers 2"

# Test 4: 4 workers
run_benchmark "4 Workers" "--workers 4"

# Test 5: 10 workers
run_benchmark "10 Workers" "--workers 10"

# Display summary
echo "========================================="
echo "Benchmark Summary"
echo "========================================="
cat "$RESULTS_FILE"
echo ""

# Calculate and display speedup
echo "========================================="
echo "Performance Analysis"
echo "========================================="

# Get baseline (no parallel) time
BASELINE=$(grep "No Parallel" "$RESULTS_FILE" | cut -d: -f2 | tr -d 's ')

if [ -n "$BASELINE" ] && [ "$BASELINE" != "FAILED" ]; then
    echo "Baseline (--no-parallel): ${BASELINE}s"
    echo ""
    echo "Speedup compared to baseline:"

    while IFS=: read -r config time; do
        config=$(echo "$config" | xargs)
        time=$(echo "$time" | tr -d 's ' | xargs)

        if [ "$config" != "No Parallel (Sequential)" ] && [ "$time" != "FAILED" ]; then
            speedup=$(echo "scale=2; $BASELINE / $time" | bc)
            improvement=$(echo "scale=1; ($BASELINE - $time) / $BASELINE * 100" | bc)
            echo "  $config: ${speedup}x faster (${improvement}% improvement)"
        fi
    done < "$RESULTS_FILE"
fi

echo ""
echo "Benchmark complete! Results saved to: $RESULTS_FILE"
