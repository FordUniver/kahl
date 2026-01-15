#!/usr/bin/env bash
# Build container images for Linux cross-compilation
# Run this once before using: ./build-all.sh --platform linux-amd64

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "Building kahl-builder container images..."
echo ""

echo "Building linux/amd64 image..."
container build \
  --platform linux/amd64 \
  -t kahl-builder:amd64 \
  -f "$REPO_ROOT/Containerfile.build" \
  "$REPO_ROOT"

echo ""
echo "Building linux/arm64 image..."
container build \
  --platform linux/arm64 \
  -t kahl-builder:arm64 \
  -f "$REPO_ROOT/Containerfile.build" \
  "$REPO_ROOT"

echo ""
echo "Done. Available images:"
container image list | grep kahl-builder || echo "  (none found - build may have failed)"
