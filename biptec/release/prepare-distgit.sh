#!/usr/bin/env bash
set -euo pipefail

ROOT=$(git rev-parse --show-toplevel)
cd "$ROOT"
# shellcheck disable=SC1091
source "$ROOT/BIPTEC-RELEASE"

DISTGIT=${1:?usage: prepare-distgit.sh DISTGIT PATCH_DIR}
PATCH_DIR=${2:?usage: prepare-distgit.sh DISTGIT PATCH_DIR}
SPEC="$DISTGIT/freeipa.spec"

[[ "$(git -C "$DISTGIT" rev-parse HEAD)" == "$FEDORA_DISTGIT_COMMIT" ]] || {
    echo "ERROR: Fedora dist-git commit mismatch" >&2
    exit 1
}

mapfile -t patches < "$PATCH_DIR/series"
for patch in "${patches[@]}"; do
    cp "$PATCH_DIR/$patch" "$DISTGIT/$patch"
done

python3 - "$SPEC" "$FEDORA_PACKAGE_RELEASE" "$RELEASE_REVISION" "${patches[@]}" <<'PY'
import pathlib, re, sys
spec = pathlib.Path(sys.argv[1])
fedora_release, release_revision = sys.argv[2:4]
patches = sys.argv[4:]
text = spec.read_text()
release_re = re.compile(r'^Release:\s+.*$', re.M)
replacement = f'Release:        {fedora_release}%{{?rc_version:.%rc_version}}.{release_revision}%{{?dist}}'
text, n = release_re.subn(replacement, text, count=1)
if n != 1:
    raise SystemExit('could not replace Release line')

marker = 'BuildRequires:  openldap-devel'
if marker not in text:
    raise SystemExit('could not find BuildRequires insertion point')
lines = ['# BIPTEC downstream patch stack (generated from source release branch)']
for patch in patches:
    number = patch.split('-', 1)[0]
    if not number.isdigit():
        raise SystemExit(f'invalid patch filename: {patch}')
    lines.append(f'Patch{number}:      {patch}')
insert = '\n'.join(lines) + '\n\n'
text = text.replace(marker, insert + marker, 1)
spec.write_text(text)
PY

echo "Prepared Fedora dist-git at $FEDORA_DISTGIT_COMMIT"
echo "RPM release: $FEDORA_PACKAGE_RELEASE.$RELEASE_REVISION%dist"
grep -E '^Version:|^Release:|^Patch900[0-9]:' "$SPEC"
