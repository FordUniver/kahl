#!/usr/bin/env bash
# Clean generated files and build artifacts
#
# Usage:
#   ./clean.sh          # Clean all generated files
#   ./clean.sh --all    # Also remove build/ directory

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "Cleaning generated files..."

# Generated pattern files
rm -f "$REPO_ROOT/go/patterns_gen.go"
rm -f "$REPO_ROOT/rust/src/patterns_gen.rs"
rm -f "$REPO_ROOT/swift/patterns_gen.swift"
# Note: swift/version_gen.swift is tracked with a default fallback value
rm -f "$REPO_ROOT/ruby/patterns_gen.rb"
rm -f "$REPO_ROOT/perl/Patterns.pm"
rm -f "$REPO_ROOT/bun/patterns_gen.ts"
rm -f "$REPO_ROOT/python/patterns_gen.py"

# Generated standalone scripts
rm -f "$REPO_ROOT/python/kahl-standalone"
rm -f "$REPO_ROOT/ruby/kahl-standalone"
rm -f "$REPO_ROOT/perl/kahl-standalone"
rm -f "$REPO_ROOT/bun/kahl-standalone"

# Compiled binaries in source dirs
rm -f "$REPO_ROOT/go/kahl"
rm -f "$REPO_ROOT/rust/kahl"
rm -f "$REPO_ROOT/swift/kahl"

echo "  Removed generated pattern files"
echo "  Removed standalone scripts"
echo "  Removed compiled binaries"

if [[ "${1:-}" == "--all" ]]; then
  echo "Cleaning build directory..."
  rm -rf "$REPO_ROOT/build"
  echo "  Removed build/"
fi

echo "Done."
