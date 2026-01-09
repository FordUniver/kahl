#!/usr/bin/env bash
# Benchmark secrets-filter implementations
# Usage: ./benchmark.sh [iterations]
set -euo pipefail
cd "$(dirname "$0")"

ITERATIONS=${1:-100}

# Test inputs
SIMPLE='hello world with no secrets'
GITHUB_PAT="ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789"
MULTILINE=$'-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA\ndata\n-----END RSA PRIVATE KEY-----'
MIXED="Token: $GITHUB_PAT and password=secret123"

echo "Benchmarking secrets-filter implementations"
echo "Iterations: $ITERATIONS"
echo "========================================"
echo

# Find implementations
declare -a IMPLS=()
[[ -x python/secrets-filter ]] && IMPLS+=(python/secrets-filter)
[[ -x perl/secrets-filter ]] && IMPLS+=(perl/secrets-filter)
[[ -x go/secrets-filter ]] && IMPLS+=(go/secrets-filter)
[[ -x bash/secrets-filter ]] && IMPLS+=(bash/secrets-filter)
[[ -x ruby/secrets-filter ]] && IMPLS+=(ruby/secrets-filter)
[[ -x rust/secrets-filter ]] && IMPLS+=(rust/secrets-filter)
[[ -x gawk/secrets-filter ]] && IMPLS+=(gawk/secrets-filter)
[[ -x bun/secrets-filter ]] && IMPLS+=(bun/secrets-filter)
[[ -x swift/secrets-filter ]] && IMPLS+=(swift/secrets-filter)

benchmark() {
    local name="$1"
    local input="$2"

    echo "=== $name ==="
    for impl in "${IMPLS[@]}"; do
        # Warmup
        echo "$input" | ./"$impl" >/dev/null 2>&1 || true

        # Benchmark
        local start end elapsed per_call
        start=$(perl -MTime::HiRes=time -e 'print time')
        for ((i=0; i<ITERATIONS; i++)); do
            echo "$input" | ./"$impl" >/dev/null 2>&1
        done
        end=$(perl -MTime::HiRes=time -e 'print time')

        elapsed=$(echo "$end - $start" | bc -l)
        per_call=$(echo "scale=2; $elapsed * 1000 / $ITERATIONS" | bc)
        printf "  %-12s %6s ms/call  (total: %.2fs)\n" "$(basename "$(dirname "$impl")"):" "$per_call" "$elapsed"
    done
    echo
}

benchmark "Simple (no secrets)" "$SIMPLE"
benchmark "GitHub PAT" "$GITHUB_PAT"
benchmark "Multiline private key" "$MULTILINE"
benchmark "Mixed content" "$MIXED"

echo "========================================"
echo "Summary: Lower ms/call is better"
echo "Go is typically fastest due to compiled binary"
