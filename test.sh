#!/usr/bin/env bash
# Test suite for kahl implementations
# Tests Python, Perl, Go, Ruby, Rust, Bun, Swift versions
# allow-secrets - bypass kahl for test data
set -euo pipefail
cd "$(dirname "$0")"

# Clear CLAUDE_CODE_SHELL_PREFIX to avoid filtering test data
unset CLAUDE_CODE_SHELL_PREFIX

# Find implementations
declare -a IMPLS=()
[[ -x python/kahl ]] && IMPLS+=(python/kahl)
[[ -x perl/kahl ]] && IMPLS+=(perl/kahl)
[[ -x go/kahl ]] && IMPLS+=(go/kahl)
[[ -x ruby/kahl ]] && IMPLS+=(ruby/kahl)
[[ -x rust/kahl ]] && IMPLS+=(rust/kahl)
[[ -x bun/kahl ]] && IMPLS+=(bun/kahl)
[[ -x swift/kahl ]] && IMPLS+=(swift/kahl)

if [[ ${#IMPLS[@]} -eq 0 ]]; then
    echo "No implementations found!"
    exit 1
fi

echo "Testing: ${IMPLS[*]}"
echo "========================================"
echo

PASS=0
FAIL=0

# Test helper - checks if output matches pattern
test_case() {
    local name="$1"
    local input="$2"
    local expect="$3"  # regex pattern to match

    echo "=== $name ==="
    for impl in "${IMPLS[@]}"; do
        local result
        result=$(echo -n "$input" | ./"$impl" 2>/dev/null) || result="[ERROR]"

        if echo "$result" | grep -qE "$expect"; then
            printf "  %-25s pass\n" "$(basename "$(dirname "$impl")"):"
            ((PASS++)) || true
        else
            printf "  %-25s FAIL\n" "$(basename "$(dirname "$impl")"):"
            printf "    expected: %s\n" "$expect"
            printf "    got:      %s\n" "$result"
            ((FAIL++)) || true
        fi
    done
    echo
}

# Test helper for exact match
test_exact() {
    local name="$1"
    local input="$2"
    local expect="$3"

    echo "=== $name ==="
    for impl in "${IMPLS[@]}"; do
        local result
        result=$(echo -n "$input" | ./"$impl" 2>/dev/null) || result="[ERROR]"

        if [[ "$result" == "$expect" ]]; then
            printf "  %-25s pass\n" "$(basename "$(dirname "$impl")"):"
            ((PASS++)) || true
        else
            printf "  %-25s FAIL\n" "$(basename "$(dirname "$impl")"):"
            printf "    expected: %s\n" "$expect"
            printf "    got:      %s\n" "$result"
            ((FAIL++)) || true
        fi
    done
    echo
}

#############################################
# GitHub Patterns
#############################################

test_case "GitHub PAT (classic)" \
    "token: ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789" \
    '\[REDACTED:GITHUB_PAT:'

test_case "GitHub PAT (fine-grained)" \
    "github_pat_11ABCDEFGH0123456789_abcdefghijklmnop" \
    '\[REDACTED:GITHUB_PAT:'

test_case "GitHub OAuth" \
    "gho_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789" \
    '\[REDACTED:GITHUB_OAUTH:'

test_case "GitHub Server" \
    "ghs_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789" \
    '\[REDACTED:GITHUB_SERVER:'

test_case "GitHub Refresh" \
    "ghr_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789" \
    '\[REDACTED:GITHUB_REFRESH:'

#############################################
# GitLab Patterns
#############################################

test_case "GitLab PAT" \
    "glpat-abcdefghij1234567890" \
    '\[REDACTED:GITLAB_PAT:'

#############################################
# Slack Patterns
#############################################

test_case "Slack Bot Token" \
    "xoxb-123456789012-1234567890123-abcdefghij" \
    '\[REDACTED:SLACK_BOT:'

test_case "Slack User Token" \
    "xoxp-123456789012-1234567890123-abcdefghij" \
    '\[REDACTED:SLACK_USER:'

test_case "Slack App Token" \
    "xoxa-123456789012-1234567890123-abcdefghij" \
    '\[REDACTED:SLACK_APP:'

#############################################
# OpenAI / Anthropic Patterns
#############################################

test_case "OpenAI Key" \
    "sk-abcdefghijklmnopqrstuvwxyz01234567890123456789AB" \
    '\[REDACTED:OPENAI_KEY:'

test_case "OpenAI Project Key" \
    "sk-proj-abcdefghij1234567890" \
    '\[REDACTED:OPENAI_PROJECT_KEY:'

test_case "Anthropic Key" \
    "sk-ant-$(printf 'a%.0s' {1..90})" \
    '\[REDACTED:ANTHROPIC_KEY:'

#############################################
# Cloud Provider Patterns
#############################################

test_case "AWS Access Key" \
    "AKIAIOSFODNN7EXAMPLE" \
    '\[REDACTED:AWS_ACCESS_KEY:'

test_case "Google API Key" \
    "AIzaSyDaGmWKa4JsXZ-HjGw7ISLn_3namBGewQe" \
    '\[REDACTED:GOOGLE_API_KEY:'

test_case "age Secret Key" \
    "AGE-SECRET-KEY-$(printf 'A%.0s' {1..59})" \
    '\[REDACTED:AGE_SECRET_KEY:'

#############################################
# Payment Patterns
#############################################

test_case "Stripe Secret (live)" \
    "sk_live_abcdefghijklmnopqrstuvwx" \
    '\[REDACTED:STRIPE_SECRET:'

test_case "Stripe Secret (test)" \
    "sk_test_abcdefghijklmnopqrstuvwx" \
    '\[REDACTED:STRIPE_TEST:'

#############################################
# Other Service Patterns
#############################################

test_case "Twilio Key" \
    "SK$(printf 'a%.0s' {1..32})" \
    '\[REDACTED:TWILIO_KEY:'

test_case "SendGrid Key" \
    "SG.abcdefghijk.lmnopqrstuvwxyz123456" \
    '\[REDACTED:SENDGRID_KEY:'

test_case "npm Token" \
    "npm_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789" \
    '\[REDACTED:NPM_TOKEN:'

test_case "JWT Token" \
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N" \
    '\[REDACTED:JWT_TOKEN:'

#############################################
# netrc / authinfo Patterns
#############################################

test_case "netrc password" \
    "machine github.com login user password supersecret123" \
    '\[REDACTED:NETRC_PASSWORD'

test_case "netrc passwd" \
    "machine github.com login user passwd anothersecret" \
    '\[REDACTED:NETRC_PASSWORD'

#############################################
# Generic Key=Value Patterns
#############################################

test_case "password=" \
    "connection password=mysecretpassword" \
    '\[REDACTED:PASSWORD_VALUE'

test_case "password:" \
    "password: mysecretvalue" \
    '\[REDACTED:PASSWORD_VALUE'

test_case "token=" \
    "config token=abc123xyz" \
    '\[REDACTED:TOKEN_VALUE'

test_case "secret:" \
    "secret: verysecretvalue" \
    '\[REDACTED:SECRET_VALUE'

#############################################
# Context-Preserving Patterns
#############################################

test_case "Git credential URL" \
    "https://user:mypassword123@github.com/repo.git" \
    '\[REDACTED:GIT_CREDENTIAL:'

test_case "Docker config auth" \
    '{"auths": {"registry": {"auth": "dXNlcm5hbWU6cGFzc3dvcmQ="}}}' \
    '\[REDACTED:DOCKER_AUTH:'

#############################################
# Private Key State Machine
#############################################

test_case "RSA Private Key" \
    $'-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA\ndata\n-----END RSA PRIVATE KEY-----' \
    '\[REDACTED:PRIVATE_KEY:multiline\]'

test_case "EC Private Key" \
    $'-----BEGIN EC PRIVATE KEY-----\nMHQCAQEEIBYr\n-----END EC PRIVATE KEY-----' \
    '\[REDACTED:PRIVATE_KEY:multiline\]'

test_case "Generic Private Key" \
    $'-----BEGIN PRIVATE KEY-----\ndata\n-----END PRIVATE KEY-----' \
    '\[REDACTED:PRIVATE_KEY:multiline\]'

# Private key with surrounding text - check output preserves context
echo "=== Private key with surrounding text ==="
for impl in "${IMPLS[@]}"; do
    result=$(printf '%s' $'before\n-----BEGIN RSA PRIVATE KEY-----\ndata\n-----END RSA PRIVATE KEY-----\nafter' | ./"$impl" 2>/dev/null) || result="[ERROR]"
    if echo "$result" | grep -q 'before' && echo "$result" | grep -q '\[REDACTED:PRIVATE_KEY:multiline\]' && echo "$result" | grep -q 'after'; then
        printf "  %-25s pass\n" "$(basename "$(dirname "$impl")"):"
        ((PASS++)) || true
    else
        printf "  %-25s FAIL\n" "$(basename "$(dirname "$impl")"):"
        printf "    got: %s\n" "$result"
        ((FAIL++)) || true
    fi
done
echo

#############################################
# Edge Cases
#############################################

test_exact "Empty input" \
    "" \
    ""

test_exact "No secrets" \
    "hello world" \
    "hello world"

test_case "Multiple secrets same line" \
    "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789 and glpat-abcdefghij1234567890" \
    '\[REDACTED:GITHUB_PAT:.*\[REDACTED:GITLAB_PAT:'

test_exact "UUID not redacted" \
    "id: 550e8400-e29b-41d4-a716-446655440000" \
    "id: 550e8400-e29b-41d4-a716-446655440000"

test_exact "Git SHA not redacted" \
    "commit abc123def456789012345678901234567890" \
    "commit abc123def456789012345678901234567890"

test_exact "Short sk- not redacted" \
    "sk-shortkey123" \
    "sk-shortkey123"

#############################################
# Boundary Tests
#############################################

test_case "GitHub PAT exactly 36 chars" \
    "ghp_$(printf 'a%.0s' {1..36})" \
    '\[REDACTED:GITHUB_PAT:'

test_exact "GitHub PAT 35 chars (too short)" \
    "ghp_$(printf 'a%.0s' {1..35})" \
    "ghp_$(printf 'a%.0s' {1..35})"

test_case "GitLab PAT exactly 20 chars" \
    "glpat-$(printf 'a%.0s' {1..20})" \
    '\[REDACTED:GITLAB_PAT:'

test_exact "GitLab PAT 19 chars (too short)" \
    "glpat-$(printf 'a%.0s' {1..19})" \
    "glpat-$(printf 'a%.0s' {1..19})"

#############################################
# Streaming Tests
#############################################

echo "=== Streaming: preserves newlines ==="
for impl in "${IMPLS[@]}"; do
    result=$(printf 'line1\nline2\nline3\n' | ./"$impl" 2>/dev/null) || result="[ERROR]"
    expected=$'line1\nline2\nline3'

    if [[ "$result" == "$expected" || "$result" == "$expected"$'\n' ]]; then
        printf "  %-25s pass\n" "$(basename "$(dirname "$impl")"):"
        ((PASS++))
    else
        printf "  %-25s FAIL\n" "$(basename "$(dirname "$impl")"):"
        printf "    expected 3 lines, got: %s\n" "$(echo "$result" | wc -l | tr -d ' ') lines"
        ((FAIL++))
    fi
done
echo

echo "=== Streaming: immediate output ==="
for impl in "${IMPLS[@]}"; do
    # Test that first line appears quickly (within 1 second)
    start=$(perl -MTime::HiRes=time -e 'print time')
    result=$(echo "test line" | ./"$impl" 2>/dev/null) || result="[ERROR]"
    endtime=$(perl -MTime::HiRes=time -e 'print time')
    elapsed=$(echo "$endtime - $start" | bc)

    if [[ "$result" == "test line" ]] && (( $(echo "$elapsed < 1" | bc -l) )); then
        printf "  %-25s pass (%.2fs)\n" "$(basename "$(dirname "$impl")"):" "$elapsed"
        ((PASS++))
    else
        printf "  %-25s FAIL (%.2fs)\n" "$(basename "$(dirname "$impl")"):" "$elapsed"
        ((FAIL++))
    fi
done
echo

#############################################
# Summary
#############################################

echo "========================================"
echo "Results: $PASS passed, $FAIL failed"
echo "========================================"

if [[ $FAIL -gt 0 ]]; then
    exit 1
fi
