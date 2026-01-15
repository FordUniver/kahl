#!/usr/bin/env bash
# Legacy build script - forwards to build-all.sh
# Use build-all.sh directly for more options.

set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

exec "$REPO_ROOT/build-all.sh" --mode standalone "$@"
