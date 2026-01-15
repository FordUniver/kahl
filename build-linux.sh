#!/usr/bin/env bash
# Build Rust, Go, and Swift binaries inside Linux container
# Called by build-all.sh via: container run ... /src/build-linux.sh <platform>

set -euo pipefail

VERSION=$(cat /src/VERSION)
PLATFORM="${1:-linux-amd64}"

echo "=== Building kahl for $PLATFORM ==="
echo ""

# Generate patterns
echo "Generating patterns..."
echo "  Rust..."
(cd /src/rust && ./generate.sh)
echo "  Go..."
(cd /src/go && go run generate.go)
echo "  Swift..."
(cd /src/swift && swift generate.swift)

# Build Rust
echo ""
echo "Building Rust..."
mkdir -p /src/build/rust/standalone
(cd /src/rust && cargo build --release --quiet)
cp /src/rust/target/release/kahl "/src/build/rust/standalone/kahl-rust-$PLATFORM-$VERSION"
echo "  -> kahl-rust-$PLATFORM-$VERSION"

# Build Go
echo ""
echo "Building Go..."
mkdir -p /src/build/go/standalone
(cd /src/go && go build -ldflags="-s -w -X main.version=$VERSION" \
  -o "/src/build/go/standalone/kahl-go-$PLATFORM-$VERSION" \
  main.go patterns_gen.go)
echo "  -> kahl-go-$PLATFORM-$VERSION"

# Build Swift
echo ""
echo "Building Swift..."
mkdir -p /src/build/swift/standalone
echo "let version = \"$VERSION\"" > /src/swift/version_gen.swift
(cd /src/swift && swiftc -O -whole-module-optimization \
  -o "/src/build/swift/standalone/kahl-swift-$PLATFORM-$VERSION" \
  main.swift patterns_gen.swift version_gen.swift)
echo "  -> kahl-swift-$PLATFORM-$VERSION"

echo ""
echo "=== Linux build complete for $PLATFORM ==="
