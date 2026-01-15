#!/usr/bin/env bash
# Build all kahl implementations and place them in build/

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="$REPO_ROOT/build"

echo "Building kahl implementations..."
mkdir -p "$BUILD_DIR"

# Copy VERSION file to build directory for script implementations
cp "$REPO_ROOT/VERSION" "$BUILD_DIR/"

# Python: Generate patterns and create standalone
echo "  Python..."
(cd "$REPO_ROOT/python" && python3 generate.py)
cp "$REPO_ROOT/python/kahl-standalone" "$BUILD_DIR/kahl-python"
chmod +x "$BUILD_DIR/kahl-python"

# Perl: Copy script and patterns module
echo "  Perl..."
cp "$REPO_ROOT/perl/main.pl" "$BUILD_DIR/kahl-perl"
cp "$REPO_ROOT/perl/Patterns.pm" "$BUILD_DIR/" 2>/dev/null || true
chmod +x "$BUILD_DIR/kahl-perl"

# Go: Build binary
echo "  Go..."
(cd "$REPO_ROOT/go" && go build -ldflags="-s -w" -o "$BUILD_DIR/kahl-go" main.go patterns_gen.go)

# Ruby: Copy script and patterns
echo "  Ruby..."
cp "$REPO_ROOT/ruby/main.rb" "$BUILD_DIR/kahl-ruby"
cp "$REPO_ROOT/ruby/patterns_gen.rb" "$BUILD_DIR/" 2>/dev/null || true
chmod +x "$BUILD_DIR/kahl-ruby"

# Rust: Build binary
echo "  Rust..."
(cd "$REPO_ROOT/rust" && cargo build --release --quiet)
cp "$REPO_ROOT/rust/target/release/kahl" "$BUILD_DIR/kahl-rust"

# Bun: Copy script and patterns (TypeScript)
echo "  Bun..."
cp "$REPO_ROOT/bun/main.js" "$BUILD_DIR/kahl-bun"
cp "$REPO_ROOT/bun/patterns_gen.ts" "$BUILD_DIR/" 2>/dev/null || true
chmod +x "$BUILD_DIR/kahl-bun"

# Swift: Build binary
echo "  Swift..."
(cd "$REPO_ROOT/swift" && swiftc -O -whole-module-optimization -o "$BUILD_DIR/kahl-swift" main.swift patterns_gen.swift)

echo ""
echo "Build complete. Artifacts in $BUILD_DIR:"
ls -lh "$BUILD_DIR"/kahl-*
