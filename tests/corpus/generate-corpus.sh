#!/usr/bin/env bash
# Generate realistic test corpus with injected secrets
# allow-secrets - bypass kahl for test data
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOGS_DIR="$SCRIPT_DIR/logs"

mkdir -p "$LOGS_DIR"

echo "Generating test corpus..."

# CI/CD output simulation (~5000 lines)
cat > "$LOGS_DIR/ci-output.txt" << 'CIEOF'
[2024-01-15 10:23:45] === Build Started ===
[2024-01-15 10:23:45] Fetching repository...
[2024-01-15 10:23:46] Cloning into '/workspace/project'...
[2024-01-15 10:23:47] HEAD is now at abc1234 Fix: update dependencies
[2024-01-15 10:23:48] Setting up environment variables...
CIEOF

# Add normal log lines
for i in $(seq 1 1000); do
    echo "[2024-01-15 10:24:$((i % 60))] Step $i: Installing package-$i..."
    echo "[2024-01-15 10:24:$((i % 60))] Package package-$i installed successfully"
    echo "[2024-01-15 10:24:$((i % 60))] Running tests for module-$i..."
    echo "[2024-01-15 10:24:$((i % 60))] All 42 tests passed for module-$i"
    if ((i % 100 == 0)); then
        echo "[2024-01-15 10:24:$((i % 60))] Checkpoint: $i packages processed"
    fi
done >> "$LOGS_DIR/ci-output.txt"

# Inject secrets at various positions
cat >> "$LOGS_DIR/ci-output.txt" << 'CIEOF'
[2024-01-15 10:30:00] === Environment dump (DEBUG) ===
GITHUB_TOKEN=ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
OPENAI_API_KEY=sk-abcdefghijklmnopqrstuvwxyz01234567890123456789AB
[2024-01-15 10:30:01] === End environment dump ===
[2024-01-15 10:30:02] Deploying to production...
[2024-01-15 10:30:03] Using registry: https://deploy:ghp_secrettoken123456789012345678901234@registry.example.com
[2024-01-15 10:30:04] Deployment complete
CIEOF

# Add more normal lines
for i in $(seq 1 500); do
    echo "[2024-01-15 10:31:$((i % 60))] Cleanup step $i..."
done >> "$LOGS_DIR/ci-output.txt"

echo "  Generated: $LOGS_DIR/ci-output.txt ($(wc -l < "$LOGS_DIR/ci-output.txt") lines)"

# Git operations (~1000 lines)
cat > "$LOGS_DIR/git-operations.txt" << 'GITEOF'
$ git status
On branch main
Your branch is up to date with 'origin/main'.

Changes not staged for commit:
  (use "git add <file>..." to update what will be committed)
  (use "git restore <file>..." to discard changes in working directory)
        modified:   src/app.js
        modified:   src/config.js

$ git remote -v
origin  https://github.com/org/project.git (fetch)
origin  https://github.com/org/project.git (push)
upstream        https://user:ghp_reallyLongTokenThatShouldBeRedacted123@github.com/upstream/project.git (fetch)

$ git log --oneline -20
GITEOF

# Add git log entries
for i in $(seq 1 500); do
    hash=$(printf '%07x' $i)
    echo "$hash Fix: update component-$i with improvements"
done >> "$LOGS_DIR/git-operations.txt"

# Add a credential leak in git config
cat >> "$LOGS_DIR/git-operations.txt" << 'GITEOF'

$ git config --list
user.name=Developer
user.email=dev@example.com
credential.helper=store
remote.origin.url=https://github.com/org/project.git
http.https://github.com.extraheader=AUTHORIZATION: bearer ghp_leakedTokenInGitConfig12345678901234

$ git diff --stat
GITEOF

for i in $(seq 1 200); do
    echo " src/component-$i.js | $((RANDOM % 100)) ++++"
done >> "$LOGS_DIR/git-operations.txt"

echo "  Generated: $LOGS_DIR/git-operations.txt ($(wc -l < "$LOGS_DIR/git-operations.txt") lines)"

# Application logs (~3000 lines)
cat > "$LOGS_DIR/app-logs.txt" << 'APPEOF'
2024-01-15T10:00:00.000Z INFO  Application starting...
2024-01-15T10:00:00.100Z INFO  Loading configuration from environment
2024-01-15T10:00:00.200Z DEBUG Config: { "port": 3000, "env": "production" }
2024-01-15T10:00:00.300Z INFO  Connecting to database...
2024-01-15T10:00:00.400Z INFO  Database connected
APPEOF

# Normal request logs
for i in $(seq 1 1000); do
    ts="2024-01-15T10:$((i / 60 % 60)):$((i % 60)).000Z"
    method=$(echo "GET POST PUT DELETE" | tr ' ' '\n' | shuf -n1)
    path="/api/v1/resource/$((RANDOM % 1000))"
    status=$(echo "200 201 204 400 404 500" | tr ' ' '\n' | shuf -n1)
    echo "$ts INFO  $method $path - $status - $((RANDOM % 500))ms"
done >> "$LOGS_DIR/app-logs.txt"

# Inject some leaked credentials in logs
cat >> "$LOGS_DIR/app-logs.txt" << 'APPEOF'
2024-01-15T11:00:00.000Z ERROR Authentication failed for request
2024-01-15T11:00:00.100Z DEBUG Request headers: { "Authorization": "Bearer sk-ant-api03-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" }
2024-01-15T11:00:00.200Z WARN  Retrying with fallback credentials
2024-01-15T11:00:00.300Z DEBUG Fallback token: xoxb-123456789012-1234567890123-abcdefghijklmnop
2024-01-15T11:00:00.400Z INFO  Fallback succeeded
APPEOF

# More normal logs
for i in $(seq 1 1000); do
    ts="2024-01-15T12:$((i / 60 % 60)):$((i % 60)).000Z"
    echo "$ts INFO  Background job $i completed successfully"
done >> "$LOGS_DIR/app-logs.txt"

# Private key leak
cat >> "$LOGS_DIR/app-logs.txt" << 'APPEOF'
2024-01-15T13:00:00.000Z ERROR Certificate validation failed
2024-01-15T13:00:00.100Z DEBUG Private key dump for debugging:
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy0AHB7MmjMgNdHwzujQNTp
kLsLwLxA1HjKdQcasNxMq7r1MXbPCEz9WsLw5JkMwMJYP2HJ7yXMtlrX0pyXHj/d
fake_key_data_here_for_testing_purposes_only_not_a_real_key
-----END RSA PRIVATE KEY-----
2024-01-15T13:00:00.200Z INFO  Regenerating certificate...
APPEOF

for i in $(seq 1 500); do
    ts="2024-01-15T14:$((i / 60 % 60)):$((i % 60)).000Z"
    echo "$ts INFO  Healthcheck passed - uptime: $((i * 60))s"
done >> "$LOGS_DIR/app-logs.txt"

echo "  Generated: $LOGS_DIR/app-logs.txt ($(wc -l < "$LOGS_DIR/app-logs.txt") lines)"

# Combined corpus
cat "$LOGS_DIR/ci-output.txt" "$LOGS_DIR/git-operations.txt" "$LOGS_DIR/app-logs.txt" > "$LOGS_DIR/combined.txt"
echo "  Generated: $LOGS_DIR/combined.txt ($(wc -l < "$LOGS_DIR/combined.txt") lines)"

echo
echo "Corpus generation complete!"
echo "Total lines: $(wc -l < "$LOGS_DIR/combined.txt")"
