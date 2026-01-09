#!/usr/bin/env bash
# Shared test utilities for secrets-filter test suite
# Source this file, don't execute it

# Paths relative to tests/ directory
TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ROOT_DIR="$(dirname "$TESTS_DIR")"
FIXTURES_DIR="$TESTS_DIR/fixtures"
EXPECTED_DIR="$TESTS_DIR/expected"

# Colors (disabled if not tty or NO_COLOR set)
if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[0;33m'
    RESET='\033[0m'
else
    RED='' GREEN='' YELLOW='' RESET=''
fi

# Find all implementations
find_implementations() {
    local -a impls=()
    local impl_filter="${1:-}"

    for dir in python perl go bash ruby rust gawk bun swift; do
        if [[ -x "$ROOT_DIR/$dir/secrets-filter" ]]; then
            if [[ -z "$impl_filter" || "$dir" == "$impl_filter" ]]; then
                impls+=("$dir")
            fi
        fi
    done

    printf '%s\n' "${impls[@]}"
}

# Load test environment from env.yaml as KEY=VALUE lines
# Usage: eval "$(load_test_env)"
# Or: env_args=$(load_test_env_args) then use in env command
load_test_env() {
    yq -r '.secrets | to_entries | .[] | "\(.key)=\(.value)"' "$FIXTURES_DIR/env.yaml"
}

# Load test environment as space-separated assignments for env command
load_test_env_args() {
    yq -r '.secrets | to_entries | .[] | "\(.key)=\(.value)"' "$FIXTURES_DIR/env.yaml" | tr '\n' ' '
}

# Build isolated env command prefix
# Args: mode (values|patterns|all)
# Outputs: env command prefix string
build_env_cmd() {
    local mode="$1"
    # Note: PATH must be quoted when used
    local cmd="env -i PATH=\"$PATH\" HOME=/nonexistent TMPDIR=/tmp"

    # Only load test secrets for values or all modes
    if [[ "$mode" == "values" || "$mode" == "all" ]]; then
        local env_args
        env_args=$(load_test_env_args)
        cmd+=" $env_args"
    fi

    echo "$cmd"
}

# Run command in isolated environment
# Args: mode impl_path [args...]
# Stdin: passed through
# Stdout: command output
run_in_env() {
    local mode="$1"
    local impl_path="$2"
    shift 2

    # Build env array - include LANG for Unicode support
    local -a env_vars=("PATH=$PATH" "HOME=/nonexistent" "TMPDIR=/tmp" "LANG=en_US.UTF-8" "LC_ALL=en_US.UTF-8")

    # Add test secrets for values or all modes
    if [[ "$mode" == "values" || "$mode" == "all" ]]; then
        while IFS= read -r line; do
            [[ -n "$line" ]] && env_vars+=("$line")
        done < <(load_test_env)
    fi

    env -i "${env_vars[@]}" "$impl_path" "$@"
}

# Run implementation with filter mode
# Args: impl mode [extra_args...]
# Stdin: input data
# Stdout: filtered output
# Stderr: passed through
run_impl() {
    local impl="$1"
    local mode="$2"
    shift 2

    local -a args=()
    [[ "$mode" != "all" ]] && args+=("--filter=$mode")
    args+=("$@")

    run_in_env "$mode" "$ROOT_DIR/$impl/secrets-filter" "${args[@]}"
}

# Compare output with expected file
# Args: actual_output expected_file
# Returns: 0 if match, 1 if differ
compare_output() {
    local actual="$1"
    local expected_file="$2"

    if [[ ! -f "$expected_file" ]]; then
        echo "Expected file not found: $expected_file" >&2
        return 1
    fi

    local expected
    expected=$(cat "$expected_file")

    if [[ "$actual" == "$expected" ]]; then
        return 0
    else
        return 1
    fi
}

# Show diff between actual and expected
# Args: actual_output expected_file
show_diff() {
    local actual="$1"
    local expected_file="$2"

    diff -u "$expected_file" <(printf '%s' "$actual") || true
}

# Print test result
# Args: status (pass|fail|skip) impl test_name [message]
print_result() {
    local status="$1"
    local impl="$2"
    local test_name="$3"
    local message="${4:-}"

    case "$status" in
        pass)
            printf "  ${GREEN}PASS${RESET}  %-10s %s\n" "$impl" "$test_name"
            ;;
        fail)
            printf "  ${RED}FAIL${RESET}  %-10s %s\n" "$impl" "$test_name"
            [[ -n "$message" ]] && printf "        %s\n" "$message"
            ;;
        skip)
            printf "  ${YELLOW}SKIP${RESET}  %-10s %s\n" "$impl" "$test_name"
            [[ -n "$message" ]] && printf "        %s\n" "$message"
            ;;
    esac
}

# Counters for test results
PASS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0

reset_counters() {
    PASS_COUNT=0
    FAIL_COUNT=0
    SKIP_COUNT=0
}

record_pass() {
    ((PASS_COUNT++)) || true
}

record_fail() {
    ((FAIL_COUNT++)) || true
}

record_skip() {
    ((SKIP_COUNT++)) || true
}

print_summary() {
    local total=$((PASS_COUNT + FAIL_COUNT + SKIP_COUNT))
    echo
    echo "========================================"
    printf "Results: ${GREEN}%d passed${RESET}, ${RED}%d failed${RESET}" "$PASS_COUNT" "$FAIL_COUNT"
    [[ $SKIP_COUNT -gt 0 ]] && printf ", ${YELLOW}%d skipped${RESET}" "$SKIP_COUNT"
    printf " (total: %d)\n" "$total"
    echo "========================================"
}

# Return exit code based on results
get_exit_code() {
    [[ $FAIL_COUNT -eq 0 ]]
}
