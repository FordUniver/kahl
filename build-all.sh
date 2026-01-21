#!/usr/bin/env bash
# Build kahl for multiple platforms
#
# Usage:
#   ./build-all.sh                       # Build for current platform
#   ./build-all.sh --platform all        # Build for all platforms
#   ./build-all.sh --platform linux-amd64,darwin-amd64
#   ./build-all.sh --checksums           # Generate checksums after build
#
# Platforms: native (default), darwin-arm64, darwin-amd64, linux-amd64, linux-arm64, all
#
# Output structure:
#   build/kahl-<platform>-<version>

set -euo pipefail
cd "$(dirname "$0")"

VERSION=$(cat VERSION)

# Detect current platform
case "$(uname -s)-$(uname -m)" in
  Darwin-arm64)  PLATFORM="darwin-arm64" ;;
  Darwin-x86_64) PLATFORM="darwin-amd64" ;;
  Linux-x86_64)  PLATFORM="linux-amd64" ;;
  Linux-aarch64) PLATFORM="linux-arm64" ;;
  *) echo "Unsupported platform: $(uname -s)-$(uname -m)" >&2; exit 1 ;;
esac

# Defaults
PLATFORMS="native"
GENERATE_CHECKSUMS=false

# Parse arguments
while [[ $# -gt 0 ]]; do
  case "$1" in
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
      head -13 "$0" | tail -10
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      exit 1
      ;;
  esac
done

# Resolve platforms
resolve_platforms() {
  case "$PLATFORMS" in
    native) echo "$PLATFORM" ;;
    all)    echo "darwin-arm64 darwin-amd64 linux-amd64 linux-arm64" ;;
    *)      echo "$PLATFORMS" | tr ',' ' ' ;;
  esac
}

PLATFORM_LIST=$(resolve_platforms)

echo "Building kahl v$VERSION"
echo "Platforms: $PLATFORM_LIST"
echo

# Generate patterns
echo "Generating patterns..."
./generate.sh
echo

mkdir -p build

# Build for each platform
for plat in $PLATFORM_LIST; do
  echo "Building for $plat..."

  case "$plat" in
    darwin-arm64)
      if [[ "$PLATFORM" == "darwin-arm64" ]]; then
        cargo build --release --quiet
        cp target/release/kahl "build/kahl-darwin-arm64-$VERSION"
      else
        echo "  Skipping darwin-arm64 (not on ARM Mac)"
      fi
      ;;
    darwin-amd64)
      rustup target add x86_64-apple-darwin 2>/dev/null || true
      cargo build --release --quiet --target x86_64-apple-darwin
      cp target/x86_64-apple-darwin/release/kahl "build/kahl-darwin-amd64-$VERSION"
      ;;
    linux-amd64)
      if command -v cross &>/dev/null; then
        cross build --release --quiet --target x86_64-unknown-linux-musl
        cp target/x86_64-unknown-linux-musl/release/kahl "build/kahl-linux-amd64-$VERSION"
      else
        echo "  Skipping linux-amd64 (cross not installed)"
      fi
      ;;
    linux-arm64)
      if command -v cross &>/dev/null; then
        cross build --release --quiet --target aarch64-unknown-linux-musl
        cp target/aarch64-unknown-linux-musl/release/kahl "build/kahl-linux-arm64-$VERSION"
      else
        echo "  Skipping linux-arm64 (cross not installed)"
      fi
      ;;
    *)
      echo "  Unknown platform: $plat" >&2
      ;;
  esac
done

# Create symlink for test.sh
if [[ -f "build/kahl-$PLATFORM-$VERSION" ]]; then
  ln -sf "kahl-$PLATFORM-$VERSION" build/kahl
fi

echo

# Generate checksums
if [[ "$GENERATE_CHECKSUMS" == "true" ]]; then
  echo "Generating checksums..."
  CHECKSUM_FILE="build/checksums-$VERSION.txt"
  (cd build && find . -type f -name "kahl-*-$VERSION" | sort | while read -r f; do
    shasum -a 256 "$f"
  done) > "$CHECKSUM_FILE"
  echo "  Written to: $CHECKSUM_FILE"
  echo
fi

# Summary
echo "Build complete:"
find build -type f -name "kahl-*-$VERSION" -exec ls -lh {} \;
