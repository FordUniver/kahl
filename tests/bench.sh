#!/usr/bin/env bash
# Benchmark kahl implementations
# Usage: ./bench.sh [iterations] [implementation]
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"

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

CORPUS_LINES=$(wc -l < "$CORPUS" | tr -d ' ')

# Prepare scenario inputs
SHORT_INPUT="normal output line with no secrets"
head -100 "$CORPUS" > /tmp/bench-medium.txt
head -1000 "$CORPUS" > /tmp/bench-large.txt

echo "kahl Benchmark (${ITERATIONS} iterations)"
echo "======================================================"
echo

# Find implementations
readarray -t IMPLS < <(find_implementations "$IMPL_FILTER")

if [[ ${#IMPLS[@]} -eq 0 ]]; then
    echo "No implementations found!"
    exit 1
fi

# CSV output
CSV_FILE="$SCRIPT_DIR/benchmark-results.csv"
echo "implementation,scenario,lines,iterations,per_call_ms" > "$CSV_FILE"

# Benchmark function for scenarios
bench_scenario() {
    local impl="$1"
    local scenario="$2"
    local input_file="$3"
    local lines="$4"

    local start end per_call

    # Warmup
    for _ in {1..3}; do
        if [[ "$input_file" == "-" ]]; then
            echo "$SHORT_INPUT" | "$ROOT_DIR/build/kahl-$impl" > /dev/null 2>&1 || true
        else
            "$ROOT_DIR/build/kahl-$impl" < "$input_file" > /dev/null 2>&1 || true
        fi
    done

    # Benchmark
    start=$(gdate +%s.%N 2>/dev/null || date +%s.%N)
    for ((i = 0; i < ITERATIONS; i++)); do
        if [[ "$input_file" == "-" ]]; then
            echo "$SHORT_INPUT" | "$ROOT_DIR/build/kahl-$impl" > /dev/null 2>&1 || true
        else
            "$ROOT_DIR/build/kahl-$impl" < "$input_file" > /dev/null 2>&1 || true
        fi
    done
    end=$(gdate +%s.%N 2>/dev/null || date +%s.%N)

    per_call=$(echo "scale=1; ($end - $start) * 1000 / $ITERATIONS" | bc)
    echo "$per_call"

    # CSV
    echo "$impl,$scenario,$lines,$ITERATIONS,$per_call" >> "$CSV_FILE"
}

# === Scenario Benchmark (default mode: values+patterns) ===
echo "Scenario Benchmark (default mode: values+patterns)"
echo "---------------------------------------------------"
echo "Scenarios: Short=1 line, Medium=100, Large=1000, Corpus=${CORPUS_LINES}"
echo

printf "%-10s %12s %12s %12s %12s\n" "Impl" "Short(1)" "Med(100)" "Large(1K)" "Corpus"
printf "%-10s %12s %12s %12s %12s\n" "----" "--------" "--------" "---------" "------"

for impl in "${IMPLS[@]}"; do
    short=$(bench_scenario "$impl" "short" "-" 1)
    med=$(bench_scenario "$impl" "medium" "/tmp/bench-medium.txt" 100)
    large=$(bench_scenario "$impl" "large" "/tmp/bench-large.txt" 1000)
    corpus=$(bench_scenario "$impl" "corpus" "$CORPUS" "$CORPUS_LINES")

    printf "%-10s %12s %12s %12s %12s\n" "$impl" "${short}ms" "${med}ms" "${large}ms" "${corpus}ms"
done

echo
echo "======================================================"
echo "Results saved to: $CSV_FILE"
echo
echo "Interpretation:"
echo "  Short/Medium: Typical command output (startup-dominated)"
echo "  Large/Corpus: Build logs, npm install (throughput-dominated)"
echo "  Go/Rust best for startup; Python competitive at throughput"

# Cleanup
rm -f /tmp/bench-medium.txt /tmp/bench-large.txt
