#!/usr/bin/env bash
# Create a release of kahl
#
# Usage:
#   ./release.sh 0.2.0                    # Full release (all platforms)
#   ./release.sh --dry-run 0.2.0          # Show what would happen
#   ./release.sh --platform native 0.2.0  # Only current platform
#   ./release.sh --skip-bump 0.2.0        # Skip version bump (if already done)
#   ./release.sh --no-push 0.2.0          # Don't push to remote
#   ./release.sh --no-gitlab-release 0.2.0  # Skip GitLab release creation
#
# This script:
# 1. Bumps version (via bump-version.sh) if not skipped
# 2. Builds all implementations for all platforms
# 3. Generates SHA256 checksums
# 4. Signs checksums with GPG
# 5. Creates signed git tag
# 6. Pushes to remote (commit + tag)
# 7. Creates GitLab release with artifacts
# 8. Optionally publishes to package registries

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Defaults
DRY_RUN=false
SKIP_BUMP=false
NO_PUSH=false
NO_GITLAB_RELEASE=false
PLATFORMS="all"
PUBLISH_CARGO=false
PUBLISH_PYPI=false
PUBLISH_NPM=false

# Parse arguments
while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run|-n)
      DRY_RUN=true
      shift
      ;;
    --skip-bump)
      SKIP_BUMP=true
      shift
      ;;
    --no-push)
      NO_PUSH=true
      shift
      ;;
    --no-gitlab-release)
      NO_GITLAB_RELEASE=true
      shift
      ;;
    --platform)
      PLATFORMS="$2"
      shift 2
      ;;
    --publish-cargo)
      PUBLISH_CARGO=true
      shift
      ;;
    --publish-pypi)
      PUBLISH_PYPI=true
      shift
      ;;
    --publish-npm)
      PUBLISH_NPM=true
      shift
      ;;
    --publish-all)
      PUBLISH_CARGO=true
      PUBLISH_PYPI=true
      PUBLISH_NPM=true
      shift
      ;;
    -h|--help)
      head -20 "$0" | tail -17
      exit 0
      ;;
    *)
      VERSION="$1"
      shift
      ;;
  esac
done

if [[ -z "${VERSION:-}" ]]; then
  echo "Usage: $0 [options] <version>" >&2
  echo "Run '$0 --help' for options" >&2
  exit 1
fi

# Validate version format
if ! [[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.]+)?$ ]]; then
  echo "Error: Invalid version format: $VERSION" >&2
  exit 1
fi

echo "=== kahl Release $VERSION ==="
echo ""

if [[ "$DRY_RUN" == "true" ]]; then
  echo "[DRY RUN MODE - no changes will be made]"
  echo ""
fi

# ============================================================================
# Step 1: Version bump
# ============================================================================

if [[ "$SKIP_BUMP" == "false" ]]; then
  echo "Step 1: Bumping version..."

  CURRENT_VERSION=$(cat "$REPO_ROOT/VERSION" | tr -d '\n')
  if [[ "$CURRENT_VERSION" == "$VERSION" ]]; then
    echo "  Version already at $VERSION, skipping bump"
  else
    if [[ "$DRY_RUN" == "true" ]]; then
      echo "  Would run: ./bump-version.sh $VERSION"
    else
      "$REPO_ROOT/bump-version.sh" "$VERSION"
    fi
  fi
else
  echo "Step 1: Skipping version bump (--skip-bump)"
fi

echo ""

# ============================================================================
# Step 2: Build all implementations
# ============================================================================

echo "Step 2: Building all implementations for platforms: $PLATFORMS..."

if [[ "$DRY_RUN" == "true" ]]; then
  echo "  Would run: ./build-all.sh --platform $PLATFORMS --checksums"
else
  "$REPO_ROOT/build-all.sh" --platform "$PLATFORMS" --checksums
fi

echo ""

# ============================================================================
# Step 3: Generate checksums
# ============================================================================

echo "Step 3: Generating checksums..."

CHECKSUM_FILE="$REPO_ROOT/build/checksums-$VERSION.txt"

if [[ "$DRY_RUN" == "true" ]]; then
  echo "  Would generate: $CHECKSUM_FILE"
else
  # build-all.sh already generates checksums, but let's be explicit (filter by version)
  (cd "$REPO_ROOT/build" && find . -type f -name "*-$VERSION" | sort | while read -r f; do
    shasum -a 256 "$f"
  done) > "$CHECKSUM_FILE"
  echo "  Generated: $CHECKSUM_FILE"
fi

echo ""

# ============================================================================
# Step 4: Sign checksums with GPG
# ============================================================================

echo "Step 4: Signing checksums with GPG..."

if [[ "$DRY_RUN" == "true" ]]; then
  echo "  Would run: gpg --armor --detach-sign $CHECKSUM_FILE"
else
  if command -v gpg &>/dev/null; then
    gpg --armor --detach-sign "$CHECKSUM_FILE"
    echo "  Created: $CHECKSUM_FILE.asc"
  else
    echo "  Warning: gpg not found, skipping signature"
  fi
fi

echo ""

# ============================================================================
# Step 5: Create signed git tag
# ============================================================================

echo "Step 5: Creating git tag v$VERSION..."

if [[ "$DRY_RUN" == "true" ]]; then
  echo "  Would run: git tag -s v$VERSION -m 'Release v$VERSION'"
else
  if git -C "$REPO_ROOT" tag | grep -q "^v$VERSION$"; then
    echo "  Tag v$VERSION already exists, skipping"
  else
    if command -v gpg &>/dev/null; then
      git -C "$REPO_ROOT" tag -s "v$VERSION" -m "Release v$VERSION"
    else
      git -C "$REPO_ROOT" tag -a "v$VERSION" -m "Release v$VERSION"
    fi
    echo "  Created tag: v$VERSION"
  fi
fi

echo ""

# ============================================================================
# Step 6: Push to remote
# ============================================================================

if [[ "$NO_PUSH" == "false" ]]; then
  echo "Step 6: Pushing to remote..."

  if [[ "$DRY_RUN" == "true" ]]; then
    echo "  Would run: git push && git push --tags"
  else
    git -C "$REPO_ROOT" push
    git -C "$REPO_ROOT" push --tags
    echo "  Pushed commit and tags"
  fi
else
  echo "Step 6: Skipping push (--no-push)"
fi

echo ""

# ============================================================================
# Step 7: Create GitLab release with artifacts
# ============================================================================

if [[ "$NO_GITLAB_RELEASE" == "false" && "$NO_PUSH" == "false" ]]; then
  echo "Step 7: Creating GitLab release..."

  # Extract project path from remote URL (strip .git suffix if present)
  REMOTE_URL=$(git -C "$REPO_ROOT" remote get-url origin 2>/dev/null || echo "")
  if [[ "$REMOTE_URL" =~ git\.zib\.de[:/](.+)$ ]]; then
    PROJECT_PATH="${BASH_REMATCH[1]%.git}"
  else
    echo "  Error: Could not parse GitLab project path from remote URL" >&2
    echo "  Remote URL: $REMOTE_URL" >&2
    exit 1
  fi

  if [[ "$DRY_RUN" == "true" ]]; then
    echo "  Would run: glab release create v$VERSION --repo $PROJECT_PATH ..."
    echo "  Would attach:"
    find "$REPO_ROOT/build" -type f \( -path "*/standalone/*-$VERSION" -o -name "checksums-$VERSION*" \) 2>/dev/null | sort | while read -r f; do
      echo "    - $(basename "$f")"
    done
  else
    # Collect all artifacts: versioned binaries in */standalone/ and checksums
    ARTIFACTS=()
    while IFS= read -r -d '' f; do
      ARTIFACTS+=("$f")
    done < <(find "$REPO_ROOT/build" -type f \( -path "*/standalone/*-$VERSION" -o -name "checksums-$VERSION*" \) -print0 2>/dev/null | sort -z)

    if [[ ${#ARTIFACTS[@]} -eq 0 ]]; then
      echo "  Warning: No artifacts found in build/"
    else
      echo "  Uploading ${#ARTIFACTS[@]} artifacts..."
      glab release create "v$VERSION" \
        --title "v$VERSION" \
        --notes "Release v$VERSION" \
        --repo "$PROJECT_PATH" \
        "${ARTIFACTS[@]}"
      echo "  Created release: v$VERSION"
    fi
  fi
else
  echo "Step 7: Skipping GitLab release (--no-gitlab-release or --no-push)"
fi

echo ""

# ============================================================================
# Step 8: Publish to package registries
# ============================================================================

echo "Step 8: Package publishing..."

if [[ "$PUBLISH_CARGO" == "true" ]]; then
  echo "  Publishing to crates.io..."
  if [[ "$DRY_RUN" == "true" ]]; then
    echo "    Would run: cargo publish"
  else
    (cd "$REPO_ROOT/rust" && cargo publish)
  fi
fi

if [[ "$PUBLISH_PYPI" == "true" ]]; then
  echo "  Publishing to PyPI..."
  if [[ "$DRY_RUN" == "true" ]]; then
    echo "    Would run: python -m build && twine upload dist/*"
  else
    (cd "$REPO_ROOT/python" && python -m build && twine upload dist/*)
  fi
fi

if [[ "$PUBLISH_NPM" == "true" ]]; then
  echo "  Publishing to npm..."
  if [[ "$DRY_RUN" == "true" ]]; then
    echo "    Would run: npm publish"
  else
    (cd "$REPO_ROOT/bun" && npm publish)
  fi
fi

if [[ "$PUBLISH_CARGO" == "false" && "$PUBLISH_PYPI" == "false" && "$PUBLISH_NPM" == "false" ]]; then
  echo "  No registries selected. Use --publish-cargo, --publish-pypi, --publish-npm, or --publish-all"
fi

echo ""

# ============================================================================
# Summary
# ============================================================================

echo "=== Release Summary ==="
echo ""
echo "Version: $VERSION"
echo "Tag: v$VERSION"
echo ""
echo "Artifacts:"
find "$REPO_ROOT/build" -type f -path "*/standalone/*-$VERSION" -exec ls -lh {} \; 2>/dev/null | sort | while read -r line; do
  echo "  $line"
done
echo ""
echo "Checksums: $CHECKSUM_FILE"
[[ -f "$CHECKSUM_FILE.asc" ]] && echo "Signature: $CHECKSUM_FILE.asc"
echo ""

if [[ -n "${PROJECT_PATH:-}" ]]; then
  echo "GitLab Release: https://git.zib.de/$PROJECT_PATH/-/releases/v$VERSION"
fi
echo ""

if [[ "$DRY_RUN" == "true" ]]; then
  echo "[DRY RUN COMPLETE - no changes were made]"
else
  echo "Release v$VERSION complete!"
fi
