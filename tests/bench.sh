#!/usr/bin/env bash
# Benchmark secrets-filter implementations with filter modes
# Usage: ./bench.sh [iterations] [implementation]
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"

# Source helpers
source "$SCRIPT_DIR/lib/helpers.sh"

ITERATIONS=${1:-50}
IMPL_FILTER="${2:-}"
CORPUS="$SCRIPT_DIR/corpus/logs/combined.txt"

# Generate corpus if needed
if [[ ! -f "$CORPUS" ]]; then
    echo "Generating test corpus..."
    chmod +x "$SCRIPT_DIR/corpus/generate-corpus.sh"
    "$SCRIPT_DIR/corpus/generate-corpus.sh"
    echo
fi

CORPUS_LINES=$(wc -l < "$CORPUS")
CORPUS_SIZE=$(du -h "$CORPUS" | cut -f1)

echo "Benchmarking secrets-filter implementations"
echo "============================================"
echo "Iterations: $ITERATIONS"
echo "Corpus: $CORPUS_LINES lines ($CORPUS_SIZE)"
echo

# Find implementations
readarray -t IMPLS < <(find_implementations "$IMPL_FILTER")

if [[ ${#IMPLS[@]} -eq 0 ]]; then
    echo "No implementations found!"
    exit 1
fi

# CSV header for machine-readable output
CSV_FILE="$SCRIPT_DIR/benchmark-results.csv"
echo "implementation,mode,iterations,total_ms,per_call_ms,lines_per_sec" > "$CSV_FILE"

# Benchmark function
benchmark() {
    local impl="$1"
    local mode="$2"
    local name="$impl/$mode"

    # Build env for this mode
    local -a env_vars=("PATH=$PATH" "HOME=/nonexistent" "TMPDIR=/tmp")
    if [[ "$mode" == "values" || "$mode" == "all" ]]; then
        while IFS= read -r line; do
            [[ -n "$line" ]] && env_vars+=("$line")
        done < <(load_test_env)
    fi

    local filter_arg=""
    [[ "$mode" != "all" ]] && filter_arg="--filter=$mode"

    # Warmup (3 iterations)
    for _ in {1..3}; do
        env -i "${env_vars[@]}" "$ROOT_DIR/$impl/secrets-filter" $filter_arg < "$CORPUS" > /dev/null 2>&1 || true
    done

    # Benchmark
    local start end elapsed per_call lines_per_sec
    start=$(date +%s.%N)

    for ((i = 0; i < ITERATIONS; i++)); do
        env -i "${env_vars[@]}" "$ROOT_DIR/$impl/secrets-filter" $filter_arg < "$CORPUS" > /dev/null 2>&1 || true
    done

    end=$(date +%s.%N)
    elapsed=$(echo "scale=3; ($end - $start) * 1000" | bc)
    per_call=$(echo "scale=2; $elapsed / $ITERATIONS" | bc)
    lines_per_sec=$(echo "scale=0; $CORPUS_LINES * $ITERATIONS * 1000 / $elapsed" | bc)

    printf "  %-20s %8s ms/call  (%s lines/sec)\n" "$name:" "$per_call" "$lines_per_sec"

    # Write to CSV
    echo "$impl,$mode,$ITERATIONS,$elapsed,$per_call,$lines_per_sec" >> "$CSV_FILE"
}

# Run benchmarks
for impl in "${IMPLS[@]}"; do
    echo "=== $impl ==="
    for mode in patterns values all; do
        benchmark "$impl" "$mode"
    done
    echo
done

echo "============================================"
echo "Results saved to: $CSV_FILE"
echo
echo "Summary: Lower ms/call is better"
echo "Compiled languages (Go, Rust, Swift) are typically fastest"
