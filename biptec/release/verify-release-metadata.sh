#!/usr/bin/env bash
set -euo pipefail

ROOT=$(git rev-parse --show-toplevel)
METADATA="$ROOT/BIPTEC-RELEASE"

fail() { echo "ERROR: $*" >&2; exit 1; }

[[ -f "$METADATA" ]] || fail "missing BIPTEC-RELEASE"

required=(
    FORMAT
    UPSTREAM_TAG
    UPSTREAM_COMMIT
    FEDORA_BRANCH
    FEDORA_DISTGIT_COMMIT
    TARGET_FEDORA
    TARGET_ARCH
    PACKAGE_VERSION
    FEDORA_PACKAGE_RELEASE
    RELEASE_REVISION
    PATCH_BASE
    PATCH_HEAD
    PATCH_COUNT
    VALIDATED_TREE
    VALIDATED_DEVELOPMENT_HEAD
)

declare -A seen=()
while IFS='=' read -r key value; do
    [[ -n "$key" ]] || continue
    [[ "$key" =~ ^[A-Z0-9_]+$ ]] || fail "invalid metadata key: $key"
    [[ -z "${seen[$key]+x}" ]] || fail "duplicate metadata key: $key"
    seen["$key"]=1
    [[ -n "$value" ]] || fail "empty metadata value: $key"
done < "$METADATA"

for key in "${required[@]}"; do
    [[ -n "${seen[$key]+x}" ]] || fail "missing required metadata key: $key"
done

# shellcheck disable=SC1090
source "$METADATA"

[[ "$FORMAT" == "1" ]] || fail "unsupported BIPTEC-RELEASE format: $FORMAT"
[[ "$TARGET_FEDORA" =~ ^[0-9]+$ ]] || fail "TARGET_FEDORA must be numeric"
[[ "$RELEASE_REVISION" =~ ^[1-9][0-9]*$ ]] || fail "RELEASE_REVISION must be a positive integer"
[[ "$PATCH_COUNT" =~ ^[1-9][0-9]*$ ]] || fail "PATCH_COUNT must be a positive integer"
[[ "$TARGET_ARCH" =~ ^[A-Za-z0-9_]+$ ]] || fail "invalid TARGET_ARCH"
[[ "$PACKAGE_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail "invalid PACKAGE_VERSION"
[[ "$FEDORA_PACKAGE_RELEASE" =~ ^[0-9]+([.][0-9]+)*$ ]] || fail "invalid FEDORA_PACKAGE_RELEASE"

expected_tag="release-${PACKAGE_VERSION//./-}"
[[ "$UPSTREAM_TAG" == "$expected_tag" ]] ||     fail "UPSTREAM_TAG $UPSTREAM_TAG does not match PACKAGE_VERSION $PACKAGE_VERSION"
[[ "$FEDORA_BRANCH" == "f${TARGET_FEDORA}" ]] ||     fail "FEDORA_BRANCH $FEDORA_BRANCH does not match TARGET_FEDORA $TARGET_FEDORA"

for key in UPSTREAM_COMMIT FEDORA_DISTGIT_COMMIT PATCH_BASE PATCH_HEAD VALIDATED_TREE VALIDATED_DEVELOPMENT_HEAD; do
    value=${!key}
    [[ "$value" =~ ^[0-9a-f]{40}$ ]] || fail "$key must be a full lowercase 40-character Git object ID"
done

[[ "$PATCH_BASE" == "$UPSTREAM_COMMIT" ]] ||     fail "PATCH_BASE must equal UPSTREAM_COMMIT"
[[ "$VALIDATED_DEVELOPMENT_HEAD" == "$PATCH_HEAD" ]] ||     fail "VALIDATED_DEVELOPMENT_HEAD must equal PATCH_HEAD"

echo "BIPTEC release metadata contract passed"
echo "upstream=$UPSTREAM_TAG ($UPSTREAM_COMMIT)"
echo "fedora_distgit=$FEDORA_DISTGIT_COMMIT"
echo "patch_stack=$PATCH_BASE..$PATCH_HEAD ($PATCH_COUNT commits)"
echo "validated_tree=$VALIDATED_TREE"
