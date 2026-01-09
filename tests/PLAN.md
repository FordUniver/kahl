# Testing & Benchmarking Redesign Plan

## Current State

**test.sh** (367 LOC):
- 45 inline test cases, pattern-based only
- Two helpers: `test_case` (regex) and `test_exact` (exact match)
- No env-value testing, no filter mode testing
- No environment isolation

**benchmark.sh** (64 LOC):
- 4 hardcoded inputs
- No filter mode benchmarking
- No realistic corpus

## Goals

1. **Test filter modes independently**: `--filter=values`, `--filter=patterns`, `--filter=all`
2. **Environment isolation**: Tests don't depend on real secrets
3. **Externalized test cases**: YAML/text files, not inline
4. **Realistic benchmark corpus**: Generated/sanitized log data
5. **CI-ready**: Proper exit codes, optional TAP output

## New Structure

```
tests/
├── fixtures/
│   ├── env.yaml                    # Test secrets definition
│   ├── patterns/                   # Pattern test inputs
│   │   ├── github.txt
│   │   ├── gitlab.txt
│   │   ├── slack.txt
│   │   ├── openai-anthropic.txt
│   │   ├── cloud.txt
│   │   ├── payment.txt
│   │   ├── services.txt
│   │   ├── netrc.txt
│   │   ├── key-value.txt
│   │   ├── private-keys.txt
│   │   └── edge-cases.txt
│   ├── values/                     # Value-based test inputs
│   │   └── env-values.txt          # Contains literal TEST_* secret values
│   └── combined/                   # Tests requiring both filters
│       └── mixed.txt
├── expected/
│   ├── patterns/                   # Expected when --filter=patterns
│   │   ├── github.txt
│   │   └── ...
│   ├── values/                     # Expected when --filter=values
│   │   └── env-values.txt
│   ├── combined/                   # Expected when --filter=all (default)
│   │   └── mixed.txt
│   └── passthrough/                # Expected when filter disabled
│       ├── patterns-values-only.txt    # patterns.txt with --filter=values (no change)
│       └── values-patterns-only.txt    # values.txt with --filter=patterns (no change)
├── corpus/
│   ├── generate-corpus.sh          # Generate realistic test data
│   └── logs/                       # Generated corpus files
│       ├── ci-output.txt           # Simulated CI/CD logs
│       ├── git-operations.txt      # Git command outputs
│       └── app-logs.txt            # Application logs with injected secrets
├── lib/
│   └── helpers.sh                  # Shared test utilities
├── test.sh                         # Main test runner (new)
├── bench.sh                        # Benchmarking (new)
└── generate-expected.sh            # One-time: generate expected from Python
```

## env.yaml Format

```yaml
# Test environment configuration
# These secrets are exported during test runs

secrets:
  # Match explicit env var names from load_secrets()
  TEST_GITHUB_TOKEN: "test_github_token_value_12345"
  TEST_API_KEY: "test_api_key_abcdefghij"

  # Match suffix patterns (*_SECRET, *_PASSWORD, etc.)
  MY_APP_SECRET: "myappsecretvalue99"
  DATABASE_PASSWORD: "dbpass!@#$%^&*()_+"
  AUTH_TOKEN: "authtokenXYZ123456789"
  PRIVATE_KEY: "privatekeycontents000"
  OAUTH_AUTH: "oauthcredentialvalue"
  API_CREDENTIAL: "apicredentialstring"

# Minimum length filter: values < 8 chars are ignored
# All test secrets above are >= 8 chars
```

## Test Categories

### 1. Pattern Tests (`--filter=patterns`)

Input: Text with pattern-matchable tokens (GitHub PAT, AWS keys, etc.)
Expected: Patterns redacted
Env: Doesn't matter (values filter disabled)

Test files migrate from current inline tests:
- github.txt: PAT classic, fine-grained, OAuth, Server, Refresh
- gitlab.txt: PAT
- slack.txt: Bot, User, App tokens
- etc.

### 2. Value Tests (`--filter=values`)

Input: Text containing literal env var values from env.yaml
Expected: Env values redacted, patterns NOT redacted
Env: Must export secrets from env.yaml

Example input (values/env-values.txt):
```
Config loaded with token: test_github_token_value_12345
Database connection using password dbpass!@#$%^&*()_+
Also has a GitHub PAT: ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789
```

Expected with `--filter=values`:
```
Config loaded with token: [REDACTED:TEST_GITHUB_TOKEN:25X]
Database connection using password [REDACTED:DATABASE_PASSWORD:20X]
Also has a GitHub PAT: ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789
```
(GitHub PAT NOT redacted because patterns filter is disabled)

### 3. Combined Tests (`--filter=all` / default)

Input: Mix of env values and patterns
Expected: Both redacted
Env: Must export secrets from env.yaml

### 4. Passthrough Tests

Verify that disabling a filter truly passes through:
- patterns.txt with `--filter=values` → unchanged (no env values present)
- values.txt with `--filter=patterns` → unchanged (values not caught by patterns)

### 5. Error Handling Tests

- `--filter=invalid` → exit 1, error message
- `--filter=values,invalid` → warning, continues with values
- `SECRETS_FILTER_VALUES=0 SECRETS_FILTER_PATTERNS=0` → both disabled, passthrough

## Test Runner Design (test.sh)

```bash
#!/usr/bin/env bash
set -euo pipefail

# Load helpers
source "$(dirname "$0")/lib/helpers.sh"

# Parse args
IMPL_FILTER=""
VERBOSE=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        -v|--verbose) VERBOSE=1; shift ;;
        *) IMPL_FILTER="$1"; shift ;;
    esac
done

# Load test environment from YAML
load_test_env() {
    yq -r '.secrets | to_entries | .[] | "\(.key)=\(.value)"' fixtures/env.yaml
}

# Run single test
run_test() {
    local impl=$1 mode=$2 input_file=$3 expected_file=$4

    local filter_arg=""
    [[ "$mode" != "all" ]] && filter_arg="--filter=$mode"

    # Build isolated environment
    local env_cmd="env -i PATH=$PATH HOME=/nonexistent"
    if [[ "$mode" == "values" || "$mode" == "all" ]]; then
        while IFS= read -r line; do
            env_cmd+=" $line"
        done < <(load_test_env)
    fi

    # Run and compare
    local result expected
    result=$($env_cmd ./"$impl"/secrets-filter $filter_arg < "fixtures/$input_file" 2>/dev/null)
    expected=$(cat "expected/$expected_file")

    if [[ "$result" == "$expected" ]]; then
        return 0
    else
        [[ $VERBOSE -eq 1 ]] && diff -u "expected/$expected_file" <(echo "$result")
        return 1
    fi
}

# Test matrix
run_all_tests() {
    local pass=0 fail=0

    for impl in "${IMPLS[@]}"; do
        # Pattern tests with --filter=patterns
        for f in fixtures/patterns/*.txt; do
            name=$(basename "$f" .txt)
            if run_test "$impl" patterns "patterns/$name.txt" "patterns/$name.txt"; then
                ((pass++))
            else
                ((fail++))
                echo "FAIL: $impl patterns/$name"
            fi
        done

        # Value tests with --filter=values
        # ... etc
    done

    echo "Results: $pass passed, $fail failed"
    [[ $fail -eq 0 ]]
}
```

## Benchmark Design (bench.sh)

```bash
#!/usr/bin/env bash
# Benchmarks with realistic corpus and filter modes

ITERATIONS=${1:-100}
CORPUS="corpus/logs/ci-output.txt"

# Ensure corpus exists
[[ -f "$CORPUS" ]] || ./corpus/generate-corpus.sh

for impl in "${IMPLS[@]}"; do
    for mode in values patterns all; do
        # Load env only for values/all modes
        local env_cmd="env -i PATH=$PATH"
        [[ "$mode" != "patterns" ]] && env_cmd+=" $(load_test_env | tr '\n' ' ')"

        # Warmup
        $env_cmd ./"$impl"/secrets-filter --filter=$mode < "$CORPUS" >/dev/null

        # Benchmark
        start=$(date +%s.%N)
        for ((i=0; i<ITERATIONS; i++)); do
            $env_cmd ./"$impl"/secrets-filter --filter=$mode < "$CORPUS" >/dev/null
        done
        end=$(date +%s.%N)

        elapsed=$(echo "$end - $start" | bc)
        per_call=$(echo "scale=2; $elapsed * 1000 / $ITERATIONS" | bc)
        echo "$impl,$mode,$per_call"
    done
done
```

## Corpus Generation (corpus/generate-corpus.sh)

Generate realistic log data with injected secrets:

```bash
#!/usr/bin/env bash
# Generate realistic test corpus with injected secrets

mkdir -p logs

# CI/CD output simulation
cat > logs/ci-output.txt << 'EOF'
[2024-01-15 10:23:45] Starting build...
[2024-01-15 10:23:46] Cloning repository...
[2024-01-15 10:23:47] Setting up environment...
[2024-01-15 10:23:48] GITHUB_TOKEN=ghp_reallyLongTokenThatShouldBeRedacted123
[2024-01-15 10:23:49] Installing dependencies...
... (500+ lines of realistic CI output)
EOF

# Git operations
cat > logs/git-operations.txt << 'EOF'
$ git remote -v
origin  https://user:ghp_secrettoken123456789012345678901234@github.com/org/repo.git
...
EOF

# Application logs with occasional leaked secrets
# Mix of normal logs with random secret injections
```

## Migration Plan

### Phase 1: Infrastructure
1. Create `tests/` directory structure
2. Create `fixtures/env.yaml` with test secrets
3. Create `tests/lib/helpers.sh` with shared utilities

### Phase 2: Extract Test Cases
1. Extract current inline tests to `fixtures/patterns/*.txt`
2. Create `fixtures/values/env-values.txt` with test secret values
3. Create `fixtures/combined/mixed.txt`

### Phase 3: Generate Expected Outputs
1. Run `generate-expected.sh` using Python implementation
2. Review generated outputs for correctness
3. Commit as static reference files

### Phase 4: New Test Runner
1. Write new `tests/test.sh` with matrix approach
2. Add filter mode testing
3. Add environment isolation
4. Add CI-friendly output (exit codes, optional TAP)

### Phase 5: New Benchmark
1. Write `corpus/generate-corpus.sh`
2. Write new `tests/bench.sh` with mode support
3. Add CSV output for tracking over time

### Phase 6: Cleanup
1. Remove old `test.sh` and `benchmark.sh` (or rename to `test-legacy.sh`)
2. Update README with new testing instructions
3. Add CI configuration

## CI Integration

```yaml
# .gitlab-ci.yml
test:
  script:
    - cd tests && ./test.sh
  artifacts:
    reports:
      junit: tests/results.xml  # if TAP-to-JUnit conversion added

benchmark:
  script:
    - cd tests && ./bench.sh > benchmark.csv
  artifacts:
    paths:
      - tests/benchmark.csv
```

## Open Questions

1. **Corpus size**: How large should the benchmark corpus be? (Suggestion: 10K-100K lines)
2. **TAP output**: Worth adding Test Anything Protocol for CI? (Nice-to-have)
3. **Backward compatibility**: Keep old test.sh during transition? (Yes, rename to test-legacy.sh)
