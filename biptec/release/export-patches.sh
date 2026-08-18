#!/usr/bin/env bash
set -euo pipefail

ROOT=$(git rev-parse --show-toplevel)
cd "$ROOT"
# shellcheck disable=SC1091
source "$ROOT/BIPTEC-RELEASE"

OUT=${1:-"$ROOT/dist/biptec-patches"}
rm -rf "$OUT"
mkdir -p "$OUT"

"$ROOT/biptec/release/verify-source.sh"
git format-patch --no-signature --start-number=9001 \
    --output-directory "$OUT" "$PATCH_BASE..$PATCH_HEAD" >/dev/null

mapfile -t patches < <(find "$OUT" -maxdepth 1 -type f -name '*.patch' -printf '%f\n' | sort)
[[ ${#patches[@]} -eq $PATCH_COUNT ]] || {
    echo "ERROR: expected $PATCH_COUNT patch files, got ${#patches[@]}" >&2
    exit 1
}
printf '%s\n' "${patches[@]}" > "$OUT/series"
(
    cd "$OUT"
    sha256sum "${patches[@]}" > SHA256SUMS
)
printf 'Exported %s BIPTEC patches to %s\n' "$PATCH_COUNT" "$OUT"
