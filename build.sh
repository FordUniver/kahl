#!/usr/bin/env bash
# Build all kahl implementations (standalone mode)
# See build-all.sh for more options.

set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

exec "$REPO_ROOT/build-all.sh" --mode standalone "$@"
