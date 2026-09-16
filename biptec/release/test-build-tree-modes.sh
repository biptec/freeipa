#!/usr/bin/env bash
set -euo pipefail

ROOT=$(git rev-parse --show-toplevel)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM

parent="$tmp/setgid-parent"
child="$parent/rpmbuild"
mkdir -p "$parent"
chmod 2775 "$parent"
mkdir -p "$child"

before=$(stat -c '%a' "$child")
(( (8#$before & 8#2000) != 0 )) || {
    echo "ERROR: test setup did not reproduce inherited setgid mode: $before" >&2
    exit 1
}

"$ROOT/biptec/release/normalize-build-tree-modes.sh" "$child"
after=$(stat -c '%a' "$child")
(( (8#$after & 8#2000) == 0 )) || {
    echo "ERROR: setgid mode survived normalization: $after" >&2
    exit 1
}

echo "Build-tree mode normalization passed: $before -> $after"
