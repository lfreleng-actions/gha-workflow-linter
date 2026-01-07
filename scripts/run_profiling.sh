#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${CYAN}╔════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║   GHA Workflow Linter - Performance Profiling Suite          ║${NC}"
echo -e "${CYAN}╔════════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Default values
TARGET_PATH="."
CLEAR_CACHE=false
WORKERS=""
OUTPUT_DIR="profiling_results"
RUN_CPROFILE=true
RUN_ASYNC_TRACE=true
RUN_PYSPY=false

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -p|--path)
            TARGET_PATH="$2"
            shift 2
            ;;
        -w|--workers)
            WORKERS="$2"
            shift 2
            ;;
        --clear-cache)
            CLEAR_CACHE=true
            shift
            ;;
        -o|--output)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        --cprofile-only)
            RUN_ASYNC_TRACE=false
            shift
            ;;
        --async-only)
            RUN_CPROFILE=false
            shift
            ;;
        --with-pyspy)
            RUN_PYSPY=true
            shift
            ;;
        -h|--help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  -p, --path PATH          Path to scan (default: current directory)"
            echo "  -w, --workers N          Number of workers to use"
            echo "  --clear-cache            Clear cache before profiling"
            echo "  -o, --output DIR         Output directory (default: profiling_results)"
            echo "  --cprofile-only          Only run cProfile (skip async trace)"
            echo "  --async-only             Only run async trace (skip cProfile)"
            echo "  --with-pyspy             Also run py-spy sampling profiler"
            echo "  -h, --help               Show this help message"
            echo ""
            echo "Examples:"
            echo "  $0 --path /path/to/workflows --workers 4"
            echo "  $0 --clear-cache --cprofile-only"
            echo "  $0 --with-pyspy --output results"
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            exit 1
            ;;
    esac
done

# Create output directory
mkdir -p "$OUTPUT_DIR"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

echo -e "${BLUE}📋 Configuration:${NC}"
echo -e "  Target path:    ${TARGET_PATH}"
echo -e "  Workers:        ${WORKERS:-auto-detect}"
echo -e "  Clear cache:    ${CLEAR_CACHE}"
echo -e "  Output dir:     ${OUTPUT_DIR}"
echo -e "  cProfile:       ${RUN_CPROFILE}"
echo -e "  Async trace:    ${RUN_ASYNC_TRACE}"
echo -e "  py-spy:         ${RUN_PYSPY}"
echo ""

# Build common arguments as array
COMMON_ARGS=("$TARGET_PATH")
if [ "$CLEAR_CACHE" = true ]; then
    COMMON_ARGS+=("--clear-cache")
fi
if [ -n "$WORKERS" ]; then
    COMMON_ARGS+=("--workers" "$WORKERS")
fi

# Function to run cProfile
run_cprofile() {
    echo -e "${YELLOW}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${YELLOW}║ Running cProfile - Function-level profiling                 ║${NC}"
    echo -e "${YELLOW}═══════════════════════════════════════════════════════════════${NC}"
    echo ""

    PROFILE_FILE="$OUTPUT_DIR/cprofile_${TIMESTAMP}.prof"
    PROFILE_TXT="$OUTPUT_DIR/cprofile_${TIMESTAMP}.txt"

    python scripts/profile_performance.py "${COMMON_ARGS[@]}" \
        --output "$PROFILE_FILE" \
        --limit 100 \
        | tee "$PROFILE_TXT"

    echo ""
    echo -e "${GREEN}✓ cProfile results saved:${NC}"
    echo -e "  Binary: ${PROFILE_FILE}"
    echo -e "  Text:   ${PROFILE_TXT}"
    echo ""
    echo -e "${CYAN}💡 To visualize interactively:${NC}"
    echo -e "  snakeviz ${PROFILE_FILE}"
    echo ""
}

# Function to run async trace
run_async_trace() {
    echo -e "${YELLOW}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${YELLOW}║ Running Async Trace - Identify serial bottlenecks           ║${NC}"
    echo -e "${YELLOW}═══════════════════════════════════════════════════════════════${NC}"
    echo ""

    TRACE_FILE="$OUTPUT_DIR/async_trace_${TIMESTAMP}.txt"

    python scripts/trace_async_execution.py "${COMMON_ARGS[@]}" \
        | tee "$TRACE_FILE"

    echo ""
    echo -e "${GREEN}✓ Async trace results saved:${NC}"
    echo -e "  ${TRACE_FILE}"
    echo ""
}

# Function to run py-spy
run_pyspy() {
    echo -e "${YELLOW}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${YELLOW}║ Running py-spy - Sampling profiler (no code changes)        ║${NC}"
    echo -e "${YELLOW}═══════════════════════════════════════════════════════════════${NC}"
    echo ""

    if ! command -v py-spy &> /dev/null; then
        echo -e "${YELLOW}⚠️  py-spy not found. Install with: pip install py-spy${NC}"
        echo ""
        return
    fi

    PYSPY_SPEEDSCOPE="$OUTPUT_DIR/pyspy_speedscope_${TIMESTAMP}.json"

    echo -e "${CYAN}Note: py-spy may require sudo on some systems${NC}"
    echo ""

    # Run with flamegraph output
    py-spy record \
        --format speedscope \
        --output "$PYSPY_SPEEDSCOPE" \
        -- python -m gha_workflow_linter "${COMMON_ARGS[@]}" \
        || echo -e "${YELLOW}⚠️  py-spy failed (may need sudo)${NC}"

    echo ""
    echo -e "${GREEN}✓ py-spy results saved:${NC}"
    echo -e "  Speedscope: ${PYSPY_SPEEDSCOPE}"
    echo ""
    echo -e "${CYAN}💡 To visualize:${NC}"
    echo -e "  Open https://www.speedscope.app/ and upload ${PYSPY_SPEEDSCOPE}"
    echo ""
}

# Run profiling sessions
if [ "$RUN_CPROFILE" = true ]; then
    run_cprofile
fi

if [ "$RUN_ASYNC_TRACE" = true ]; then
    run_async_trace
fi

if [ "$RUN_PYSPY" = true ]; then
    run_pyspy
fi

# Generate summary
echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}║ Profiling Complete!                                          ║${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "${CYAN}📁 All results saved to: ${OUTPUT_DIR}/${NC}"
echo ""
echo -e "${CYAN}📊 Next Steps:${NC}"
echo ""
echo -e "1. ${BLUE}Review text output for quick insights${NC}"
echo -e "   cat ${OUTPUT_DIR}/*_${TIMESTAMP}.txt"
echo ""
echo -e "2. ${BLUE}Visualize cProfile with snakeviz${NC}"
if [ "$RUN_CPROFILE" = true ]; then
    echo -e "   snakeviz ${OUTPUT_DIR}/cprofile_${TIMESTAMP}.prof"
fi
echo ""
echo -e "3. ${BLUE}Look for these patterns:${NC}"
echo -e "   • High cumulative time = coordination overhead"
echo -e "   • High call count = potential for batching"
echo -e "   • Network/IO functions = parallelization opportunities"
echo ""
echo -e "4. ${BLUE}Refer to performance analysis guide${NC}"
echo -e "   cat docs/PERFORMANCE_ANALYSIS.md"
echo ""
echo -e "${GREEN}Happy optimizing! 🚀${NC}"
