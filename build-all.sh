#!/usr/bin/env bash
# Build all kahl implementations with proper directory structure
#
# Usage:
#   ./build-all.sh                       # Build all for current platform
#   ./build-all.sh --platform all        # Build for all platforms
#   ./build-all.sh --platform linux-amd64,darwin-amd64
#   ./build-all.sh --mode standalone     # Build only standalone artifacts
#   ./build-all.sh --mode package        # Build only package artifacts
#   ./build-all.sh --lang rust,python    # Build only specific languages
#   ./build-all.sh --checksums           # Generate checksums after build
#
# Platforms: native (default), darwin-arm64, darwin-amd64, linux-amd64, linux-arm64, all
#
# Output structure:
#   build/<language>/standalone/kahl-<lang>[-<platform>]-<version>
#   build/<language>/package/...

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VERSION=$(cat "$REPO_ROOT/VERSION")

# Detect platform
case "$(uname -s)-$(uname -m)" in
  Darwin-arm64)  PLATFORM="darwin-arm64" ;;
  Darwin-x86_64) PLATFORM="darwin-amd64" ;;
  Linux-x86_64)  PLATFORM="linux-amd64" ;;
  Linux-aarch64) PLATFORM="linux-arm64" ;;
  *) echo "Unsupported platform: $(uname -s)-$(uname -m)" >&2; exit 1 ;;
esac

# Defaults
BUILD_MODE="all"  # standalone, package, or all
LANGUAGES="rust,go,swift,python,ruby,perl,bun"
PLATFORMS="native"  # native, all, or comma-separated list
GENERATE_CHECKSUMS=false

# Parse arguments
while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode)
      [[ $# -lt 2 || "$2" == --* ]] && { echo "Error: --mode requires a value" >&2; exit 1; }
      BUILD_MODE="$2"
      shift 2
      ;;
    --lang|--languages)
      [[ $# -lt 2 || "$2" == --* ]] && { echo "Error: --lang requires a value" >&2; exit 1; }
      LANGUAGES="$2"
      shift 2
      ;;
    --platform|--platforms)
      [[ $# -lt 2 || "$2" == --* ]] && { echo "Error: --platform requires a value" >&2; exit 1; }
      PLATFORMS="$2"
      shift 2
      ;;
    --checksums)
      GENERATE_CHECKSUMS=true
      shift
      ;;
    -h|--help)
      head -22 "$0" | tail -17
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      exit 1
      ;;
  esac
done

# Convert comma-separated languages to array (trim spaces)
IFS=',' read -ra LANG_ARRAY <<< "$LANGUAGES"
LANG_ARRAY=("${LANG_ARRAY[@]// /}")

should_build() {
  local lang="$1"
  for l in "${LANG_ARRAY[@]}"; do
    [[ "$l" == "$lang" ]] && return 0
  done
  return 1
}

# ============================================================================
# Platform-specific build functions
# ============================================================================

build_native() {
  # Build for current platform (existing behavior)
  build_for_platform "$PLATFORM"
}

build_darwin_arm64() {
  if [[ "$PLATFORM" == "darwin-arm64" ]]; then
    build_for_platform "darwin-arm64"
  else
    echo "Warning: darwin-arm64 native build only available on ARM Mac" >&2
  fi
}

build_darwin_amd64() {
  echo "Cross-compiling for darwin-amd64..."

  if should_build "rust"; then
    echo "  Rust (x86_64-apple-darwin)..."
    rustup target add x86_64-apple-darwin 2>/dev/null || true
    OUT_DIR="$REPO_ROOT/build/rust/standalone"
    mkdir -p "$OUT_DIR"
    (cd "$REPO_ROOT/rust" && cargo build --release --quiet --target x86_64-apple-darwin)
    cp "$REPO_ROOT/rust/target/x86_64-apple-darwin/release/kahl" "$OUT_DIR/kahl-rust-darwin-amd64-$VERSION"
  fi

  if should_build "go"; then
    echo "  Go (GOARCH=amd64)..."
    OUT_DIR="$REPO_ROOT/build/go/standalone"
    mkdir -p "$OUT_DIR"
    (cd "$REPO_ROOT/go" && GOOS=darwin GOARCH=amd64 go build -ldflags="-s -w -X main.version=$VERSION" \
      -o "$OUT_DIR/kahl-go-darwin-amd64-$VERSION" main.go patterns_gen.go)
  fi

  if should_build "swift"; then
    echo "  Swift (x86_64-apple-macosx)..."
    OUT_DIR="$REPO_ROOT/build/swift/standalone"
    mkdir -p "$OUT_DIR"
    echo "let version = \"$VERSION\"" > "$REPO_ROOT/swift/version_gen.swift"
    (cd "$REPO_ROOT/swift" && swiftc -O -target x86_64-apple-macosx10.15 \
      -o "$OUT_DIR/kahl-swift-darwin-amd64-$VERSION" main.swift patterns_gen.swift version_gen.swift)
  fi
}

build_linux_amd64() {
  echo "Building for linux-amd64 via Apple Containers..."

  if ! command -v container &>/dev/null; then
    echo "Error: 'container' CLI not found. Install Apple Containers." >&2
    return 1
  fi

  if ! container image list | grep -q "kahl-builder.*amd64"; then
    echo "Error: kahl-builder:amd64 image not found. Run ./build-container.sh first." >&2
    return 1
  fi

  container run --rm \
    --arch amd64 \
    --mount type=bind,source="$REPO_ROOT",target=/src \
    kahl-builder:amd64 \
    /src/build-linux.sh linux-amd64
}

build_linux_arm64() {
  echo "Building for linux-arm64 via Apple Containers..."

  if ! command -v container &>/dev/null; then
    echo "Error: 'container' CLI not found. Install Apple Containers." >&2
    return 1
  fi

  if ! container image list | grep -q "kahl-builder.*arm64"; then
    echo "Error: kahl-builder:arm64 image not found. Run ./build-container.sh first." >&2
    return 1
  fi

  container run --rm \
    --arch arm64 \
    --mount type=bind,source="$REPO_ROOT",target=/src \
    kahl-builder:arm64 \
    /src/build-linux.sh linux-arm64
}

build_for_platform() {
  local plat="$1"
  echo "Building for $plat..."

  # Compiled languages
  if should_build "rust"; then
    echo "  Rust..."
    OUT_DIR="$REPO_ROOT/build/rust/standalone"
    mkdir -p "$OUT_DIR"
    (cd "$REPO_ROOT/rust" && cargo build --release --quiet)
    cp "$REPO_ROOT/rust/target/release/kahl" "$OUT_DIR/kahl-rust-$plat-$VERSION"
  fi

  if should_build "go"; then
    echo "  Go..."
    OUT_DIR="$REPO_ROOT/build/go/standalone"
    mkdir -p "$OUT_DIR"
    (cd "$REPO_ROOT/go" && go build -ldflags="-s -w -X main.version=$VERSION" \
      -o "$OUT_DIR/kahl-go-$plat-$VERSION" main.go patterns_gen.go)
  fi

  if should_build "swift"; then
    echo "  Swift..."
    OUT_DIR="$REPO_ROOT/build/swift/standalone"
    mkdir -p "$OUT_DIR"
    echo "let version = \"$VERSION\"" > "$REPO_ROOT/swift/version_gen.swift"
    (cd "$REPO_ROOT/swift" && swiftc -O -whole-module-optimization \
      -o "$OUT_DIR/kahl-swift-$plat-$VERSION" main.swift patterns_gen.swift version_gen.swift)
  fi
}

SCRIPTS_BUILT=false
build_scripts_once() {
  if [[ "$SCRIPTS_BUILT" == "true" ]]; then
    return
  fi
  SCRIPTS_BUILT=true

  if should_build "python"; then
    echo "  Python..."
    OUT_DIR="$REPO_ROOT/build/python/standalone"
    mkdir -p "$OUT_DIR"
    cp "$REPO_ROOT/python/kahl-standalone" "$OUT_DIR/kahl-python-$VERSION"
    chmod +x "$OUT_DIR/kahl-python-$VERSION"
  fi

  if should_build "ruby"; then
    echo "  Ruby..."
    OUT_DIR="$REPO_ROOT/build/ruby/standalone"
    mkdir -p "$OUT_DIR"
    cp "$REPO_ROOT/ruby/kahl-standalone" "$OUT_DIR/kahl-ruby-$VERSION"
    chmod +x "$OUT_DIR/kahl-ruby-$VERSION"
  fi

  if should_build "perl"; then
    echo "  Perl..."
    OUT_DIR="$REPO_ROOT/build/perl/standalone"
    mkdir -p "$OUT_DIR"
    cp "$REPO_ROOT/perl/kahl-standalone" "$OUT_DIR/kahl-perl-$VERSION"
    chmod +x "$OUT_DIR/kahl-perl-$VERSION"
  fi

  if should_build "bun"; then
    echo "  Bun..."
    OUT_DIR="$REPO_ROOT/build/bun/standalone"
    mkdir -p "$OUT_DIR"
    cp "$REPO_ROOT/bun/kahl-standalone" "$OUT_DIR/kahl-bun-$VERSION"
    chmod +x "$OUT_DIR/kahl-bun-$VERSION"
  fi
}

# ============================================================================
# Resolve platforms to build
# ============================================================================

resolve_platforms() {
  case "$PLATFORMS" in
    native)
      echo "$PLATFORM"
      ;;
    all)
      echo "darwin-arm64 darwin-amd64 linux-amd64 linux-arm64"
      ;;
    *)
      echo "$PLATFORMS" | tr ',' ' '
      ;;
  esac
}

PLATFORM_LIST=$(resolve_platforms)

echo "Building kahl v$VERSION (mode: $BUILD_MODE)"
echo "Platforms: $PLATFORM_LIST"
echo ""

# ============================================================================
# Generate patterns for all implementations
# ============================================================================

echo "Generating patterns..."

if should_build "python"; then
  echo "  Python..."
  (cd "$REPO_ROOT/python" && python3 generate.py)
fi

if should_build "ruby"; then
  echo "  Ruby..."
  (cd "$REPO_ROOT/ruby" && ruby generate.rb)
fi

if should_build "perl"; then
  echo "  Perl..."
  (cd "$REPO_ROOT/perl" && perl generate.pl)
fi

if should_build "bun"; then
  echo "  Bun..."
  (cd "$REPO_ROOT/bun" && bun run generate.ts)
fi

if should_build "go"; then
  echo "  Go..."
  (cd "$REPO_ROOT/go" && go run generate.go)
fi

if should_build "rust"; then
  echo "  Rust..."
  (cd "$REPO_ROOT/rust" && ./generate.sh)
fi

if should_build "swift"; then
  echo "  Swift..."
  (cd "$REPO_ROOT/swift" && swift generate.swift)
fi

echo ""

# ============================================================================
# Build standalone artifacts
# ============================================================================

if [[ "$BUILD_MODE" == "standalone" || "$BUILD_MODE" == "all" ]]; then
  echo "Building standalone artifacts..."
  echo ""

  # Build script languages first (platform-independent, only once)
  build_scripts_once

  for plat in $PLATFORM_LIST; do
    case "$plat" in
      darwin-arm64)
        if [[ "$PLATFORM" == "darwin-arm64" ]]; then
          build_for_platform "darwin-arm64"
        else
          echo "Skipping darwin-arm64 (not on ARM Mac)"
        fi
        ;;
      darwin-amd64)
        build_darwin_amd64
        ;;
      linux-amd64)
        build_linux_amd64
        ;;
      linux-arm64)
        build_linux_arm64
        ;;
      *)
        echo "Unknown platform: $plat" >&2
        ;;
    esac
    echo ""
  done

  # Create symlinks for test.sh compatibility (expects build/kahl-<lang>)
  echo "Creating test.sh compatibility symlinks..."
  for lang in rust go swift python ruby perl bun; do
    if should_build "$lang"; then
      # Prefer native platform artifact, fallback to any platform
      artifact=""
      # Try native platform first (compiled languages)
      if [[ -f "$REPO_ROOT/build/$lang/standalone/kahl-$lang-$PLATFORM-$VERSION" ]]; then
        artifact="$REPO_ROOT/build/$lang/standalone/kahl-$lang-$PLATFORM-$VERSION"
      # Try platform-independent (script languages)
      elif [[ -f "$REPO_ROOT/build/$lang/standalone/kahl-$lang-$VERSION" ]]; then
        artifact="$REPO_ROOT/build/$lang/standalone/kahl-$lang-$VERSION"
      # Fallback to any available
      else
        artifact=$(find "$REPO_ROOT/build/$lang/standalone" -name "kahl-$lang-*-$VERSION" 2>/dev/null | head -1)
      fi
      if [[ -n "$artifact" && -f "$artifact" ]]; then
        ln -sf "$artifact" "$REPO_ROOT/build/kahl-$lang"
        echo "  build/kahl-$lang -> $(basename "$artifact")"
      fi
    fi
  done
  echo ""
fi

# ============================================================================
# Build package artifacts
# ============================================================================

if [[ "$BUILD_MODE" == "package" || "$BUILD_MODE" == "all" ]]; then
  echo "Building package artifacts..."

  if should_build "rust"; then
    echo "  Rust (cargo package)..."
    OUT_DIR="$REPO_ROOT/build/rust/package"
    mkdir -p "$OUT_DIR"
    # Create package but don't publish
    (cd "$REPO_ROOT/rust" && cargo package --quiet --allow-dirty 2>/dev/null || echo "    (skipped - cargo package requires clean git state)")
  fi

  # Python, Bun packages will be added when pyproject.toml and package.json are created
  echo "  (Python/npm packages pending metadata files)"

  echo ""
fi

# ============================================================================
# Generate checksums
# ============================================================================

if [[ "$GENERATE_CHECKSUMS" == "true" ]]; then
  echo "Generating checksums..."
  CHECKSUM_FILE="$REPO_ROOT/build/checksums-$VERSION.txt"

  # Find all built artifacts for this version and generate checksums
  (cd "$REPO_ROOT/build" && find . -type f -name "*-$VERSION" | sort | while read -r f; do
    shasum -a 256 "$f"
  done) > "$CHECKSUM_FILE"

  echo "  Written to: $CHECKSUM_FILE"
  echo ""
fi

# ============================================================================
# Summary
# ============================================================================

echo "Build complete. Artifacts:"
echo ""

# List all built files with sizes (for this version)
find "$REPO_ROOT/build" -type f -name "*-$VERSION" -exec ls -lh {} \; 2>/dev/null | while read -r line; do
  echo "  $line"
done

echo ""
echo "Directory structure:"
(cd "$REPO_ROOT/build" && find . -type d | head -20 | sed 's/^/  /')
