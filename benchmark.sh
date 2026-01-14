#!/usr/bin/env bash
# Benchmark kahl implementations
# Usage: ./benchmark.sh [iterations] [mode]
# Modes: default, values, patterns, entropy, all
set -euo pipefail
cd "$(dirname "$0")"

ITERATIONS=${1:-100}
MODE=${2:-default}

# Test inputs for different filter modes
SIMPLE='hello world with no secrets'
GITHUB_PAT="ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789"
MULTILINE=$'-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA\ndata\n-----END RSA PRIVATE KEY-----'
MIXED="Token: $GITHUB_PAT and password=secret123"
HIGH_ENTROPY="api_key=xK9mNpL2qR5tW8vY1zA4bC7dE0fG3hJ6"

echo "Benchmarking kahl implementations"
echo "Iterations: $ITERATIONS"
echo "Mode: $MODE"
echo "========================================"
echo

# Find implementations
declare -a IMPLS=()
[[ -x python/kahl ]] && IMPLS+=(python/kahl)
[[ -x perl/kahl ]] && IMPLS+=(perl/kahl)
[[ -x go/kahl ]] && IMPLS+=(go/kahl)
[[ -x ruby/kahl ]] && IMPLS+=(ruby/kahl)
[[ -x rust/kahl ]] && IMPLS+=(rust/kahl)
[[ -x bun/kahl ]] && IMPLS+=(bun/kahl)
[[ -x swift/kahl ]] && IMPLS+=(swift/kahl)

benchmark() {
    local name="$1"
    local input="$2"
    local filter_arg="${3:-}"

    echo "=== $name ==="
    for impl in "${IMPLS[@]}"; do
        # Warmup
        if [[ -n "$filter_arg" ]]; then
            echo "$input" | ./"$impl" --filter="$filter_arg" >/dev/null 2>&1 || true
        else
            echo "$input" | ./"$impl" >/dev/null 2>&1 || true
        fi

        # Benchmark
        local start end elapsed per_call
        start=$(perl -MTime::HiRes=time -e 'print time')
        for ((i=0; i<ITERATIONS; i++)); do
            if [[ -n "$filter_arg" ]]; then
                echo "$input" | ./"$impl" --filter="$filter_arg" >/dev/null 2>&1
            else
                echo "$input" | ./"$impl" >/dev/null 2>&1
            fi
        done
        end=$(perl -MTime::HiRes=time -e 'print time')

        elapsed=$(echo "$end - $start" | bc -l)
        per_call=$(echo "scale=2; $elapsed * 1000 / $ITERATIONS" | bc)
        printf "  %-12s %6s ms/call  (total: %.2fs)\n" "$(basename "$(dirname "$impl")"):" "$per_call" "$elapsed"
    done
    echo
}

case "$MODE" in
    values)
        echo ">>> Filter mode: --filter=values (env value redaction only)"
        echo
        benchmark "Simple (no secrets)" "$SIMPLE" "values"
        benchmark "Mixed content" "$MIXED" "values"
        ;;

    patterns)
        echo ">>> Filter mode: --filter=patterns (pattern matching only)"
        echo
        benchmark "Simple (no secrets)" "$SIMPLE" "patterns"
        benchmark "GitHub PAT" "$GITHUB_PAT" "patterns"
        benchmark "Multiline private key" "$MULTILINE" "patterns"
        benchmark "Mixed content" "$MIXED" "patterns"
        ;;

    entropy)
        echo ">>> Filter mode: --filter=entropy (entropy detection only)"
        echo
        benchmark "Simple (no secrets)" "$SIMPLE" "entropy"
        benchmark "High entropy string" "$HIGH_ENTROPY" "entropy"
        benchmark "Mixed content" "$MIXED" "entropy"
        ;;

    all)
        echo ">>> Filter mode: --filter=all (values + patterns + entropy)"
        echo
        benchmark "Simple (no secrets)" "$SIMPLE" "all"
        benchmark "GitHub PAT" "$GITHUB_PAT" "all"
        benchmark "High entropy string" "$HIGH_ENTROPY" "all"
        benchmark "Mixed content" "$MIXED" "all"
        ;;

    default|*)
        echo ">>> Default mode (no --filter arg): values + patterns"
        echo
        benchmark "Simple (no secrets)" "$SIMPLE"
        benchmark "GitHub PAT" "$GITHUB_PAT"
        benchmark "Multiline private key" "$MULTILINE"
        benchmark "Mixed content" "$MIXED"
        ;;
esac

echo "========================================"
echo "Summary: Lower ms/call is better"
echo "Rust/Go are typically fastest (compiled binaries)"
echo
echo "Available modes:"
echo "  ./benchmark.sh 100 default   # (no --filter): values + patterns"
echo "  ./benchmark.sh 100 values    # --filter=values only"
echo "  ./benchmark.sh 100 patterns  # --filter=patterns only"
echo "  ./benchmark.sh 100 entropy   # --filter=entropy only"
echo "  ./benchmark.sh 100 all       # --filter=all (all three filters)"
