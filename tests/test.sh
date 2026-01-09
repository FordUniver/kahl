#!/usr/bin/env bash
# Test suite for secrets-filter implementations
# Tests pattern, value, and combined filtering modes
# allow-secrets - bypass secrets-filter for test data
set -uo pipefail
# Note: not using -e to allow tests to fail without exiting

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"

# Source helpers
source "$SCRIPT_DIR/lib/helpers.sh"

# Parse arguments
IMPL_FILTER=""
VERBOSE=0
QUIET=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        -v|--verbose) VERBOSE=1; shift ;;
        -q|--quiet) QUIET=1; shift ;;
        -h|--help)
            echo "Usage: $0 [options] [implementation]"
            echo "Options:"
            echo "  -v, --verbose   Show diff on failures"
            echo "  -q, --quiet     Only show summary"
            echo "  -h, --help      Show this help"
            echo "Implementation: python, perl, go, ruby, rust, bun, swift"
            exit 0
            ;;
        *) IMPL_FILTER="$1"; shift ;;
    esac
done

# Clear CLAUDE_CODE_SHELL_PREFIX to avoid filtering test data
unset CLAUDE_CODE_SHELL_PREFIX

# Find implementations
readarray -t IMPLS < <(find_implementations "$IMPL_FILTER")

if [[ ${#IMPLS[@]} -eq 0 ]]; then
    echo "No implementations found!"
    [[ -n "$IMPL_FILTER" ]] && echo "Filter: $IMPL_FILTER"
    exit 1
fi

[[ $QUIET -eq 0 ]] && echo "Testing: ${IMPLS[*]}"
[[ $QUIET -eq 0 ]] && echo "========================================"
[[ $QUIET -eq 0 ]] && echo

reset_counters

# Run a single test
# Args: impl mode input_rel expected_rel test_name
run_test() {
    local impl="$1"
    local mode="$2"
    local input_rel="$3"
    local expected_rel="$4"
    local test_name="$5"

    local input_file="$FIXTURES_DIR/$input_rel"
    local expected_file="$EXPECTED_DIR/$expected_rel"

    if [[ ! -f "$input_file" ]]; then
        print_result skip "$impl" "$test_name" "Input file not found"
        record_skip
        return
    fi

    if [[ ! -f "$expected_file" ]]; then
        print_result skip "$impl" "$test_name" "Expected file not found"
        record_skip
        return
    fi

    local result
    result=$(run_impl "$impl" "$mode" < "$input_file" 2>/dev/null) || {
        print_result fail "$impl" "$test_name" "Implementation error"
        record_fail
        return
    }

    local expected
    expected=$(cat "$expected_file")

    if [[ "$result" == "$expected" ]]; then
        [[ $QUIET -eq 0 ]] && print_result pass "$impl" "$test_name"
        record_pass
    else
        print_result fail "$impl" "$test_name"
        record_fail
        if [[ $VERBOSE -eq 1 ]]; then
            echo "--- Diff (expected vs actual) ---"
            diff -u "$expected_file" <(printf '%s' "$result") | head -30 || true
            echo "---"
        fi
    fi
}

# Test category: patterns (--filter=patterns)
run_pattern_tests() {
    [[ $QUIET -eq 0 ]] && echo "=== Pattern Tests (--filter=patterns) ==="
    for impl in "${IMPLS[@]}"; do
        for f in "$FIXTURES_DIR"/patterns/*.txt; do
            [[ -f "$f" ]] || continue
            name=$(basename "$f" .txt)
            run_test "$impl" "patterns" "patterns/$name.txt" "patterns/$name.txt" "patterns/$name"
        done
    done
    [[ $QUIET -eq 0 ]] && echo
}

# Test category: values (--filter=values)
run_value_tests() {
    [[ $QUIET -eq 0 ]] && echo "=== Value Tests (--filter=values) ==="
    for impl in "${IMPLS[@]}"; do
        for f in "$FIXTURES_DIR"/values/*.txt; do
            [[ -f "$f" ]] || continue
            name=$(basename "$f" .txt)
            run_test "$impl" "values" "values/$name.txt" "values/$name.txt" "values/$name"
        done
    done
    [[ $QUIET -eq 0 ]] && echo
}

# Test category: combined (--filter=all / default)
run_combined_tests() {
    [[ $QUIET -eq 0 ]] && echo "=== Combined Tests (--filter=all) ==="
    for impl in "${IMPLS[@]}"; do
        for f in "$FIXTURES_DIR"/combined/*.txt; do
            [[ -f "$f" ]] || continue
            name=$(basename "$f" .txt)
            run_test "$impl" "all" "combined/$name.txt" "combined/$name.txt" "combined/$name"
        done
    done
    [[ $QUIET -eq 0 ]] && echo
}

# Test category: passthrough (verify filter modes are independent)
run_passthrough_tests() {
    [[ $QUIET -eq 0 ]] && echo "=== Passthrough Tests (filter independence) ==="
    for impl in "${IMPLS[@]}"; do
        # Pattern files with --filter=values should mostly pass through
        # (except any text that happens to match patterns)
        for f in "$FIXTURES_DIR"/patterns/*.txt; do
            [[ -f "$f" ]] || continue
            name=$(basename "$f" .txt)
            expected_name="patterns-valuesonly-$name.txt"
            run_test "$impl" "values" "patterns/$name.txt" "passthrough/$expected_name" "passthrough/patterns-as-values/$name"
        done

        # Value files with --filter=patterns
        for f in "$FIXTURES_DIR"/values/*.txt; do
            [[ -f "$f" ]] || continue
            name=$(basename "$f" .txt)
            expected_name="values-patternsonly-$name.txt"
            run_test "$impl" "patterns" "values/$name.txt" "passthrough/$expected_name" "passthrough/values-as-patterns/$name"
        done
    done
    [[ $QUIET -eq 0 ]] && echo
}

# Test category: entropy (--filter=entropy)
run_entropy_tests() {
    [[ $QUIET -eq 0 ]] && echo "=== Entropy Tests (--filter=entropy) ==="
    for impl in "${IMPLS[@]}"; do
        for f in "$FIXTURES_DIR"/entropy/*.txt; do
            [[ -f "$f" ]] || continue
            name=$(basename "$f" .txt)
            run_test "$impl" "entropy" "entropy/$name.txt" "entropy/$name.txt" "entropy/$name"
        done
    done
    [[ $QUIET -eq 0 ]] && echo
}

# Test category: CLI argument parsing
run_cli_tests() {
    [[ $QUIET -eq 0 ]] && echo "=== CLI Argument Tests ==="

    local test_input="ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789"
    local redacted_pattern='\[REDACTED:GITHUB_PAT:'
    local entropy_input="xK9mNpL2qR5tW8vY1zA4bC7dE0fG3hJ6"
    local entropy_redacted='\[REDACTED:HIGH_ENTROPY:'

    for impl in "${IMPLS[@]}"; do
        local -a base_env=("PATH=$PATH" "HOME=/nonexistent" "TMPDIR=/tmp")

        # Test --filter=all (should redact patterns)
        local result
        result=$(echo "$test_input" | run_impl "$impl" "all" 2>/dev/null) || result=""
        if [[ "$result" =~ $redacted_pattern ]]; then
            [[ $QUIET -eq 0 ]] && print_result pass "$impl" "cli/--filter=all-patterns"
            record_pass
        else
            print_result fail "$impl" "cli/--filter=all-patterns"
            record_fail
        fi

        # Test --filter=all includes entropy (key behavior change)
        result=$(env -i "${base_env[@]}" "$ROOT_DIR/$impl/secrets-filter" --filter=all <<< "$entropy_input" 2>/dev/null) || result=""
        if [[ "$result" =~ $entropy_redacted ]]; then
            [[ $QUIET -eq 0 ]] && print_result pass "$impl" "cli/--filter=all-entropy"
            record_pass
        else
            print_result fail "$impl" "cli/--filter=all-entropy" "all should include entropy"
            record_fail
        fi

        # Test explicit --filter=values,patterns does NOT include entropy
        result=$(env -i "${base_env[@]}" "$ROOT_DIR/$impl/secrets-filter" --filter=values,patterns <<< "$entropy_input" 2>/dev/null) || result=""
        if [[ "$result" == "$entropy_input" ]]; then
            [[ $QUIET -eq 0 ]] && print_result pass "$impl" "cli/--filter=values,patterns-no-entropy"
            record_pass
        else
            print_result fail "$impl" "cli/--filter=values,patterns-no-entropy" "explicit combo should not include entropy"
            record_fail
        fi

        # Test -f short form (need direct invocation)
        result=$(env -i "${base_env[@]}" "$ROOT_DIR/$impl/secrets-filter" -f patterns <<< "$test_input" 2>/dev/null) || result=""
        if [[ "$result" =~ $redacted_pattern ]]; then
            [[ $QUIET -eq 0 ]] && print_result pass "$impl" "cli/-f patterns"
            record_pass
        else
            print_result fail "$impl" "cli/-f patterns"
            record_fail
        fi

        # Test invalid filter (should error)
        result=$(env -i "${base_env[@]}" "$ROOT_DIR/$impl/secrets-filter" --filter=invalid <<< "$test_input" 2>&1) || true
        # Some implementations might have exit_code captured differently
        if [[ "$result" == *"no valid filters"* ]] || [[ "$result" == *"unknown filter"* ]]; then
            [[ $QUIET -eq 0 ]] && print_result pass "$impl" "cli/invalid-filter-error"
            record_pass
        else
            print_result fail "$impl" "cli/invalid-filter-error" "Expected error message"
            record_fail
        fi
    done
    [[ $QUIET -eq 0 ]] && echo
}

# Test category: ENV variable configuration
run_env_tests() {
    [[ $QUIET -eq 0 ]] && echo "=== ENV Variable Tests ==="

    # Use a known test secret value in input that won't trigger pattern matching
    # (avoid "token:", "password:", etc. prefixes that patterns catch)
    local test_value="test_gh_token_value_1234567890"
    local test_input="The config value is $test_value here"

    for impl in "${IMPLS[@]}"; do
        # Build base env array
        local -a base_env=("PATH=$PATH" "HOME=/nonexistent" "TMPDIR=/tmp")

        # Add test secrets
        local -a env_with_secrets=("${base_env[@]}")
        while IFS= read -r line; do
            [[ -n "$line" ]] && env_with_secrets+=("$line")
        done < <(load_test_env)

        # Test SECRETS_FILTER_VALUES=0 (should NOT redact values)
        local result
        result=$(env -i "${env_with_secrets[@]}" SECRETS_FILTER_VALUES=0 \
            "$ROOT_DIR/$impl/secrets-filter" <<< "$test_input" 2>/dev/null) || result=""

        if [[ "$result" == *"$test_value"* ]]; then
            [[ $QUIET -eq 0 ]] && print_result pass "$impl" "env/SECRETS_FILTER_VALUES=0"
            record_pass
        else
            print_result fail "$impl" "env/SECRETS_FILTER_VALUES=0" "Value should not be redacted"
            record_fail
        fi

        # Test SECRETS_FILTER_PATTERNS=0 with a pattern
        local pattern_input="ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789"
        result=$(env -i "${base_env[@]}" SECRETS_FILTER_PATTERNS=0 \
            "$ROOT_DIR/$impl/secrets-filter" <<< "$pattern_input" 2>/dev/null) || result=""

        if [[ "$result" == "$pattern_input" ]]; then
            [[ $QUIET -eq 0 ]] && print_result pass "$impl" "env/SECRETS_FILTER_PATTERNS=0"
            record_pass
        else
            print_result fail "$impl" "env/SECRETS_FILTER_PATTERNS=0" "Pattern should not be redacted"
            record_fail
        fi

        # Test CLI overrides ENV
        result=$(env -i "${base_env[@]}" SECRETS_FILTER_PATTERNS=0 \
            "$ROOT_DIR/$impl/secrets-filter" --filter=patterns <<< "$pattern_input" 2>/dev/null) || result=""

        if [[ "$result" =~ \[REDACTED:GITHUB_PAT: ]]; then
            [[ $QUIET -eq 0 ]] && print_result pass "$impl" "env/cli-overrides-env"
            record_pass
        else
            print_result fail "$impl" "env/cli-overrides-env" "CLI should override ENV"
            record_fail
        fi

        # Test SECRETS_FILTER_ENTROPY=1 (enables entropy by default)
        local entropy_input="xK9mNpL2qR5tW8vY1zA4bC7dE0fG3hJ6"
        result=$(env -i "${base_env[@]}" SECRETS_FILTER_ENTROPY=1 \
            "$ROOT_DIR/$impl/secrets-filter" <<< "$entropy_input" 2>/dev/null) || result=""

        if [[ "$result" =~ \[REDACTED:HIGH_ENTROPY: ]]; then
            [[ $QUIET -eq 0 ]] && print_result pass "$impl" "env/SECRETS_FILTER_ENTROPY=1"
            record_pass
        else
            print_result fail "$impl" "env/SECRETS_FILTER_ENTROPY=1" "Entropy should be enabled"
            record_fail
        fi

        # Test entropy is off by default (no --filter=entropy, no env var)
        result=$(env -i "${base_env[@]}" \
            "$ROOT_DIR/$impl/secrets-filter" <<< "$entropy_input" 2>/dev/null) || result=""

        if [[ "$result" == "$entropy_input" ]]; then
            [[ $QUIET -eq 0 ]] && print_result pass "$impl" "env/entropy-off-by-default"
            record_pass
        else
            print_result fail "$impl" "env/entropy-off-by-default" "Entropy should be off by default"
            record_fail
        fi
    done
    [[ $QUIET -eq 0 ]] && echo
}

# Test category: streaming behavior
run_streaming_tests() {
    [[ $QUIET -eq 0 ]] && echo "=== Streaming Tests ==="

    for impl in "${IMPLS[@]}"; do
        # Test preserves newlines
        local result
        result=$(printf 'line1\nline2\nline3\n' | run_impl "$impl" "all" 2>/dev/null) || result=""
        local expected=$'line1\nline2\nline3'

        if [[ "$result" == "$expected" || "$result" == "$expected"$'\n' ]]; then
            [[ $QUIET -eq 0 ]] && print_result pass "$impl" "streaming/preserves-newlines"
            record_pass
        else
            print_result fail "$impl" "streaming/preserves-newlines"
            record_fail
        fi

        # Test immediate output (should complete quickly)
        local start end elapsed
        start=$(date +%s.%N)
        result=$(echo "test line" | run_impl "$impl" "all" 2>/dev/null) || result=""
        end=$(date +%s.%N)
        elapsed=$(echo "$end - $start" | bc)

        if [[ "$result" == "test line" ]] && (( $(echo "$elapsed < 2" | bc -l) )); then
            [[ $QUIET -eq 0 ]] && print_result pass "$impl" "streaming/immediate-output (${elapsed}s)"
            record_pass
        else
            print_result fail "$impl" "streaming/immediate-output (${elapsed}s)"
            record_fail
        fi
    done
    [[ $QUIET -eq 0 ]] && echo
}

# Test category: edge cases
run_edge_tests() {
    [[ $QUIET -eq 0 ]] && echo "=== Edge Case Tests ==="

    for impl in "${IMPLS[@]}"; do
        # Empty input
        local result
        result=$(echo -n "" | run_impl "$impl" "all" 2>/dev/null) || result=""
        if [[ -z "$result" ]]; then
            [[ $QUIET -eq 0 ]] && print_result pass "$impl" "edge/empty-input"
            record_pass
        else
            print_result fail "$impl" "edge/empty-input"
            record_fail
        fi

        # No secrets
        result=$(echo "hello world" | run_impl "$impl" "all" 2>/dev/null) || result=""
        if [[ "$result" == "hello world" ]]; then
            [[ $QUIET -eq 0 ]] && print_result pass "$impl" "edge/no-secrets"
            record_pass
        else
            print_result fail "$impl" "edge/no-secrets"
            record_fail
        fi

        # Multiple secrets same line
        local input="ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789 and glpat-abcdefghij1234567890"
        result=$(echo "$input" | run_impl "$impl" "patterns" 2>/dev/null) || result=""
        if [[ "$result" =~ \[REDACTED:GITHUB_PAT: ]] && [[ "$result" =~ \[REDACTED:GITLAB_PAT: ]]; then
            [[ $QUIET -eq 0 ]] && print_result pass "$impl" "edge/multiple-secrets"
            record_pass
        else
            print_result fail "$impl" "edge/multiple-secrets"
            record_fail
        fi
    done
    [[ $QUIET -eq 0 ]] && echo
}

# Main test execution
main() {
    run_pattern_tests
    run_value_tests
    run_combined_tests
    run_passthrough_tests
    run_entropy_tests
    run_cli_tests
    run_env_tests
    run_streaming_tests
    run_edge_tests

    print_summary
    get_exit_code
}

main
