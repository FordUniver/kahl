#!/usr/bin/env bash
# Generate expected outputs from Python reference implementation
# Run once, review outputs, then commit as static reference files
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
FIXTURES_DIR="$SCRIPT_DIR/fixtures"
EXPECTED_DIR="$SCRIPT_DIR/expected"

# Source helpers
source "$SCRIPT_DIR/lib/helpers.sh"

echo "Generating expected outputs using Python implementation"
echo "======================================================="
echo

# Verify Python implementation exists
if [[ ! -x "$ROOT_DIR/python/secrets-filter" ]]; then
    echo "ERROR: Python implementation not found at $ROOT_DIR/python/secrets-filter"
    exit 1
fi

# Build env command with test secrets
build_env() {
    local mode="$1"
    local cmd="env -i PATH=$PATH HOME=/nonexistent TMPDIR=/tmp"
    if [[ "$mode" == "values" || "$mode" == "all" ]]; then
        local env_args
        env_args=$(yq -r '.secrets | to_entries | .[] | "\(.key)=\(.value)"' "$FIXTURES_DIR/env.yaml" | tr '\n' ' ')
        cmd+=" $env_args"
    fi
    echo "$cmd"
}

# Generate expected output for a fixture file
generate() {
    local input_file="$1"
    local output_file="$2"
    local mode="$3"

    local filter_arg="--filter=$mode"

    local env_cmd
    env_cmd=$(build_env "$mode")

    mkdir -p "$(dirname "$output_file")"

    # Run Python implementation
    # shellcheck disable=SC2086
    $env_cmd "$ROOT_DIR/python/secrets-filter" $filter_arg < "$input_file" > "$output_file"

    echo "  Generated: $output_file"
}

# Generate pattern test expected outputs (--filter=patterns)
echo "=== Pattern tests (--filter=patterns) ==="
for f in "$FIXTURES_DIR"/patterns/*.txt; do
    [[ -f "$f" ]] || continue
    name=$(basename "$f")
    generate "$f" "$EXPECTED_DIR/patterns/$name" "patterns"
done
echo

# Generate value test expected outputs (--filter=values)
echo "=== Value tests (--filter=values) ==="
for f in "$FIXTURES_DIR"/values/*.txt; do
    [[ -f "$f" ]] || continue
    name=$(basename "$f")
    generate "$f" "$EXPECTED_DIR/values/$name" "values"
done
echo

# Generate combined test expected outputs (--filter=all / default)
echo "=== Combined tests (--filter=all) ==="
for f in "$FIXTURES_DIR"/combined/*.txt; do
    [[ -f "$f" ]] || continue
    name=$(basename "$f")
    generate "$f" "$EXPECTED_DIR/combined/$name" "all"
done
echo

# Generate passthrough tests (filter disabled for that type)
echo "=== Passthrough tests ==="
# Pattern fixtures with --filter=values should pass through unchanged (no env values in those files)
for f in "$FIXTURES_DIR"/patterns/*.txt; do
    [[ -f "$f" ]] || continue
    name=$(basename "$f")
    generate "$f" "$EXPECTED_DIR/passthrough/patterns-valuesonly-$name" "values"
done
# Value fixtures with --filter=patterns should pass through with only patterns caught
for f in "$FIXTURES_DIR"/values/*.txt; do
    [[ -f "$f" ]] || continue
    name=$(basename "$f")
    generate "$f" "$EXPECTED_DIR/passthrough/values-patternsonly-$name" "patterns"
done
echo

echo "======================================================="
echo "Generation complete!"
echo
echo "Next steps:"
echo "1. Review generated files in $EXPECTED_DIR/"
echo "2. Verify outputs are correct"
echo "3. Commit as static reference files"
echo "4. Run test.sh to verify all implementations match"
