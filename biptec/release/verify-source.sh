#!/usr/bin/env bash
set -euo pipefail

ROOT=$(git rev-parse --show-toplevel)
cd "$ROOT"
"$ROOT/biptec/release/verify-release-metadata.sh"
# shellcheck disable=SC1091
source "$ROOT/BIPTEC-RELEASE"

fail() { echo "ERROR: $*" >&2; exit 1; }

[[ "$(git rev-parse "$UPSTREAM_TAG^{}")" == "$UPSTREAM_COMMIT" ]] || fail "upstream tag mismatch"
[[ "$(git rev-parse "$PATCH_BASE")" == "$UPSTREAM_COMMIT" ]] || fail "patch base mismatch"
git merge-base --is-ancestor "$PATCH_BASE" "$PATCH_HEAD" || fail "patch head is not based on upstream"
git merge-base --is-ancestor "$PATCH_HEAD" HEAD || fail "release metadata points outside current history"

actual_count=$(git rev-list --count "$PATCH_BASE..$PATCH_HEAD")
[[ "$actual_count" == "$PATCH_COUNT" ]] || fail "expected $PATCH_COUNT patches, found $actual_count"
merge_count=$(git rev-list --count --merges "$PATCH_BASE..$PATCH_HEAD")
[[ "$merge_count" == "0" ]] || fail "patch stack contains merge commits"

tree=$(git rev-parse "$PATCH_HEAD^{tree}")
[[ "$tree" == "$VALIDATED_TREE" ]] || fail "validated source tree changed: $tree"

git diff --check "$PATCH_BASE..$PATCH_HEAD"

if ! git diff --quiet "$PATCH_HEAD" HEAD -- . \
  ':(exclude)README-BIPTEC.md' \
  ':(exclude)BIPTEC-RELEASE' \
  ':(exclude)biptec/release/**' \
  ':(exclude).github/workflows/**'; then
    fail "source changes exist after PATCH_HEAD; update patch stack metadata"
fi

mapfile -t pyfiles < <(git diff --name-only "$PATCH_BASE..$PATCH_HEAD" -- '*.py' | sort -u)
for file in "${pyfiles[@]}"; do
    [[ -f "$file" ]] && python3 -m py_compile "$file"
done

echo "BIPTEC source verification passed"
echo "upstream=$UPSTREAM_TAG ($UPSTREAM_COMMIT)"
echo "patches=$PATCH_COUNT"
echo "tree=$tree"
