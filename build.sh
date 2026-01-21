#!/usr/bin/env bash
# Build kahl for current platform
set -euo pipefail
cd "$(dirname "$0")"

# Generate patterns from YAML
./generate.sh

# Build release binary
cargo build --release

# Copy to build/ for test.sh compatibility
mkdir -p build
cp target/release/kahl build/kahl

echo "Built: build/kahl"
ls -lh build/kahl
