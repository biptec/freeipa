#!/usr/bin/env bash
set -euo pipefail

(($# > 0)) || {
    echo "usage: normalize-build-tree-modes.sh DIR..." >&2
    exit 2
}

for dir in "$@"; do
    [[ -d "$dir" ]] || {
        echo "ERROR: build directory does not exist: $dir" >&2
        exit 1
    }
    chmod g-s -- "$dir"
    mode=$(stat -c '%a' -- "$dir")
    if (( (8#$mode & 8#2000) != 0 )); then
        echo "ERROR: setgid bit remains on build directory: $dir ($mode)" >&2
        exit 1
    fi
done
