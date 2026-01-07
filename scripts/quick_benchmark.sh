#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

# Quick benchmark script to test performance with different configurations
# This provides a fast way to measure impact of code changes

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}╔════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║   GHA Workflow Linter - Quick Benchmark                       ║${NC}"
echo -e "${CYAN}╚════════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Default values
TARGET_PATH="."
ITERATIONS=3
CLEAR_CACHE=false

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -p|--path)
            TARGET_PATH="$2"
            shift 2
            ;;
        -n|--iterations)
            ITERATIONS="$2"
            shift 2
            ;;
        --clear-cache)
            CLEAR_CACHE=true
            shift
            ;;
        -h|--help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Quick benchmark to test different worker configurations."
            echo ""
            echo "Options:"
            echo "  -p, --path PATH          Path to scan (default: current directory)"
            echo "  -n, --iterations N       Number of iterations per test (default: 3)"
            echo "  --clear-cache            Clear cache before each test (cold cache)"
            echo "  -h, --help               Show this help message"
            echo ""
            echo "Examples:"
            echo "  $0 --path /path/to/workflows"
            echo "  $0 --iterations 5 --clear-cache"
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            exit 1
            ;;
    esac
done

echo -e "${BLUE}Configuration:${NC}"
echo -e "  Target path:    ${TARGET_PATH}"
echo -e "  Iterations:     ${ITERATIONS}"
echo -e "  Clear cache:    ${CLEAR_CACHE}"
echo ""

# Test configurations
CONFIGS=(
    "sequential:--no-parallel"
    "1_worker:--workers 1"
    "2_workers:--workers 2"
    "4_workers:--workers 4"
    "8_workers:--workers 8"
)

# Results storage
declare -A results
declare -A best_times
declare -A avg_times

# Function to run a single test
run_test() {
    local name=$1
    local args=$2
    # iter parameter kept for API compatibility but not used

    # Clear cache if requested
    if [ "$CLEAR_CACHE" = true ]; then
        python -m gha_workflow_linter cache clear >/dev/null 2>&1 || true
    fi

    # Run the linter and capture time
    local start
    start=$(date +%s.%N)
    python -m gha_workflow_linter "$TARGET_PATH" "$args" --quiet >/dev/null 2>&1 || true
    local end
    end=$(date +%s.%N)

    # Calculate duration
    local duration
    duration=$(echo "$end - $start" | bc)

    echo "$duration"
}

# Function to calculate average
calculate_avg() {
    local sum=0
    local count=0

    for time in "$@"; do
        sum=$(echo "$sum + $time" | bc)
        count=$((count + 1))
    done

    if [ $count -gt 0 ]; then
        echo "scale=3; $sum / $count" | bc
    else
        echo "0"
    fi
}

# Function to find minimum
find_min() {
    local min=$1
    shift

    for time in "$@"; do
        if (( $(echo "$time < $min" | bc -l) )); then
            min=$time
        fi
    done

    echo "$min"
}

echo -e "${YELLOW}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${YELLOW}Running benchmarks...${NC}"
echo -e "${YELLOW}═══════════════════════════════════════════════════════════════${NC}"
echo ""

# Run tests
for config in "${CONFIGS[@]}"; do
    IFS=':' read -r name args <<< "$config"

    echo -e "${CYAN}Testing: ${name//_/ }${NC}"
    echo -e "${BLUE}Arguments: ${args}${NC}"

    times=()
    for ((i=1; i<=ITERATIONS; i++)); do
        echo -n "  Iteration $i/$ITERATIONS... "
        time=$(run_test "$name" "$args" "$i")
        times+=("$time")
        echo -e "${GREEN}${time}s${NC}"
    done

    # Calculate statistics
    avg=$(calculate_avg "${times[@]}")
    best=$(find_min "${times[@]}")

    # Store results for potential future use
    # shellcheck disable=SC2034
    results["$name"]="${times[*]}"
    best_times["$name"]=$best
    avg_times["$name"]=$avg

    echo -e "  ${YELLOW}Best: ${best}s, Avg: ${avg}s${NC}"
    echo ""
done

# Display results
echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}Benchmark Results${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
echo ""

echo -e "${CYAN}Average Times:${NC}"
printf "%-20s %10s\n" "Configuration" "Avg Time"
printf "%-20s %10s\n" "--------------------" "----------"

# Find baseline (sequential)
baseline_avg=${avg_times["sequential"]}

for config in "${CONFIGS[@]}"; do
    IFS=':' read -r name args <<< "$config"
    avg=${avg_times["$name"]}
    printf "%-20s %10.3fs\n" "${name//_/ }" "$avg"
done

echo ""
echo -e "${CYAN}Best Times:${NC}"
printf "%-20s %10s\n" "Configuration" "Best Time"
printf "%-20s %10s\n" "--------------------" "----------"

# shellcheck disable=SC2034
baseline_best=${best_times["sequential"]}

for config in "${CONFIGS[@]}"; do
    IFS=':' read -r name args <<< "$config"
    best=${best_times["$name"]}
    printf "%-20s %10.3fs\n" "${name//_/ }" "$best"
done

echo ""
echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}Performance Analysis${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
echo ""

echo -e "${CYAN}Speedup vs Sequential (using average times):${NC}"
printf "%-20s %10s %10s\n" "Configuration" "Speedup" "% Change"
printf "%-20s %10s %10s\n" "--------------------" "----------" "----------"

for config in "${CONFIGS[@]}"; do
    IFS=':' read -r name args <<< "$config"

    if [ "$name" = "sequential" ]; then
        printf "%-20s %10s %10s\n" "${name//_/ }" "1.00x" "baseline"
        continue
    fi

    avg=${avg_times["$name"]}
    speedup=$(echo "scale=2; $baseline_avg / $avg" | bc)
    pct_change=$(echo "scale=1; ($baseline_avg - $avg) / $baseline_avg * 100" | bc)

    # Color based on performance
    if (( $(echo "$speedup >= 1.2" | bc -l) )); then
        color=$GREEN
    elif (( $(echo "$speedup >= 0.95" | bc -l) )); then
        color=$YELLOW
    else
        color=$RED
    fi

    printf "%-20s ${color}%10.2fx %9.1f%%${NC}\n" "${name//_/ }" "$speedup" "$pct_change"
done

echo ""
echo -e "${CYAN}Parallel Efficiency:${NC}"
echo ""

# Calculate efficiency for worker configurations
for config in "${CONFIGS[@]}"; do
    IFS=':' read -r name args <<< "$config"

    # Extract worker count
    if [[ $name =~ ^([0-9]+)_workers$ ]]; then
        workers="${BASH_REMATCH[1]}"
        avg=${avg_times["$name"]}
        speedup=$(echo "scale=2; $baseline_avg / $avg" | bc)
        efficiency=$(echo "scale=1; $speedup / $workers * 100" | bc)

        # Color based on efficiency
        if (( $(echo "$efficiency >= 80" | bc -l) )); then
            color=$GREEN
            status="Excellent"
        elif (( $(echo "$efficiency >= 50" | bc -l) )); then
            color=$YELLOW
            status="Good"
        elif (( $(echo "$efficiency >= 25" | bc -l) )); then
            color=$YELLOW
            status="Poor"
        else
            color=$RED
            status="Very Poor"
        fi

        printf "${color}%-12s: %5.1f%% efficiency (%s)${NC}\n" "${workers} workers" "$efficiency" "$status"
    fi
done

echo ""
echo -e "${CYAN}💡 Recommendations:${NC}"
echo ""

# Find best configuration
best_config=""
best_config_time=999999
for config in "${CONFIGS[@]}"; do
    IFS=':' read -r name args <<< "$config"
    avg=${avg_times["$name"]}
    if (( $(echo "$avg < $best_config_time" | bc -l) )); then
        best_config=$name
        best_config_time=$avg
    fi
done

echo -e "🏆 Best configuration: ${GREEN}${best_config//_/ }${NC} (${best_config_time}s avg)"
echo ""

# Check if parallelism is helping
# shellcheck disable=SC2034
speedup_2w=$(echo "scale=2; $baseline_avg / ${avg_times['2_workers']}" | bc)
speedup_4w=$(echo "scale=2; $baseline_avg / ${avg_times['4_workers']}" | bc)

if (( $(echo "$speedup_4w < 1.5" | bc -l) )); then
    echo -e "${RED}⚠️  WARNING: Parallelism is not providing significant speedup!${NC}"
    echo ""
    echo "This suggests:"
    echo "  • The code may not be using parallel workers effectively"
    echo "  • Most time is spent in serial operations"
    echo "  • Overhead of coordination exceeds benefits"
    echo ""
    echo "Recommended actions:"
    echo "  1. Run profiling: ./scripts/run_profiling.sh"
    echo "  2. Look for serial await patterns"
    echo "  3. Check if asyncio.gather() is being used"
    echo "  4. Review PERFORMANCE_ANALYSIS.md for optimization strategies"
    echo ""
elif (( $(echo "$speedup_4w >= 2.0" | bc -l) )); then
    echo -e "${GREEN}✅ Good parallel scaling detected!${NC}"
    echo ""
    echo "Performance is improving with more workers."
    echo "Consider testing with 8 or 16 workers for larger workloads."
    echo ""
else
    echo -e "${YELLOW}⚡ Moderate parallel scaling${NC}"
    echo ""
    echo "Some benefit from parallelism, but room for improvement."
    echo "Run profiling to identify remaining serial bottlenecks:"
    echo "  ./scripts/run_profiling.sh"
    echo ""
fi

echo -e "${CYAN}📁 Next Steps:${NC}"
echo ""
echo "1. Review detailed analysis: cat docs/PERFORMANCE_ANALYSIS.md"
echo "2. Run full profiling: ./scripts/run_profiling.sh"
echo "3. Check for serial patterns: python scripts/trace_async_execution.py ."
echo ""

exit 0
