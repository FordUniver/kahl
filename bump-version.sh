#!/usr/bin/env bash
# Bump version across all files, build, test, and commit
#
# Usage:
#   ./bump-version.sh 0.2.0           # Bump to specific version
#   ./bump-version.sh --dry-run 0.2.0 # Show what would change without modifying
#
# This script:
# 1. Updates VERSION file and all language-specific version references
# 2. Runs full build (./build-all.sh)
# 3. Runs full test suite (./test.sh)
# 4. If any step fails: restores all files, exits 1
# 5. If all pass: creates git commit with version bump

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DRY_RUN=false

# Parse arguments
while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run|-n)
      DRY_RUN=true
      shift
      ;;
    -h|--help)
      head -15 "$0" | tail -10
      exit 0
      ;;
    *)
      NEW_VERSION="$1"
      shift
      ;;
  esac
done

if [[ -z "${NEW_VERSION:-}" ]]; then
  echo "Usage: $0 [--dry-run] <version>" >&2
  echo "Example: $0 0.2.0" >&2
  exit 1
fi

# Validate version format (semver)
if ! [[ "$NEW_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.]+)?$ ]]; then
  echo "Error: Invalid version format: $NEW_VERSION" >&2
  echo "Expected semver format: X.Y.Z or X.Y.Z-suffix" >&2
  exit 1
fi

OLD_VERSION=$(cat "$REPO_ROOT/VERSION" | tr -d '\n')

echo "Bumping version: $OLD_VERSION -> $NEW_VERSION"
echo ""

# Files to update with their sed patterns
declare -A VERSION_FILES=(
  ["VERSION"]="s/.*/$NEW_VERSION/"
  ["rust/Cargo.toml"]="s/^version = \".*\"/version = \"$NEW_VERSION\"/"
)

# Add optional files if they exist
[[ -f "$REPO_ROOT/python/pyproject.toml" ]] && VERSION_FILES["python/pyproject.toml"]="s/^version = \".*\"/version = \"$NEW_VERSION\"/"
[[ -f "$REPO_ROOT/bun/package.json" ]] && VERSION_FILES["bun/package.json"]="s/\"version\": \".*\"/\"version\": \"$NEW_VERSION\"/"

# Track modified files for rollback
MODIFIED_FILES=()

rollback() {
  echo ""
  echo "Rolling back changes..."
  for file in "${MODIFIED_FILES[@]}"; do
    git -C "$REPO_ROOT" checkout -- "$file" 2>/dev/null || true
    echo "  Restored: $file"
  done
  echo ""
  echo "Version bump failed. All changes have been rolled back."
  exit 1
}

trap 'rollback' ERR

# ============================================================================
# Update version in all files
# ============================================================================

echo "Updating version files..."

for file in "${!VERSION_FILES[@]}"; do
  full_path="$REPO_ROOT/$file"
  pattern="${VERSION_FILES[$file]}"

  if [[ ! -f "$full_path" ]]; then
    echo "  Skipping (not found): $file"
    continue
  fi

  if [[ "$DRY_RUN" == "true" ]]; then
    echo "  Would update: $file"
    gsed -n "$pattern p" "$full_path" 2>/dev/null || true
  else
    gsed -i "$pattern" "$full_path"
    MODIFIED_FILES+=("$file")
    echo "  Updated: $file"
  fi
done

echo ""

if [[ "$DRY_RUN" == "true" ]]; then
  echo "Dry run complete. No files were modified."
  exit 0
fi

# ============================================================================
# Build all implementations
# ============================================================================

echo "Building all implementations..."
echo ""

if ! "$REPO_ROOT/build-all.sh"; then
  echo ""
  echo "Build failed!"
  rollback
fi

echo ""

# ============================================================================
# Run test suite
# ============================================================================

echo "Running test suite..."
echo ""

if ! "$REPO_ROOT/test.sh"; then
  echo ""
  echo "Tests failed!"
  rollback
fi

echo ""

# ============================================================================
# Commit changes
# ============================================================================

echo "All checks passed. Creating commit..."

# Stage modified files
for file in "${MODIFIED_FILES[@]}"; do
  git -C "$REPO_ROOT" add "$file"
done

# Create commit
git -C "$REPO_ROOT" commit -m "$(cat <<EOF
Bump version to $NEW_VERSION

Updated version in:
$(printf '  - %s\n' "${MODIFIED_FILES[@]}")
EOF
)"

echo ""
echo "Version bumped to $NEW_VERSION successfully!"
echo ""
echo "Next steps:"
echo "  1. Review the commit: git log -1"
echo "  2. Push when ready: git push"
echo "  3. Create release: ./release.sh $NEW_VERSION"
