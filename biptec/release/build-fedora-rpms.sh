#!/usr/bin/env bash
set -euo pipefail

ROOT=$(git rev-parse --show-toplevel)
cd "$ROOT"
# shellcheck disable=SC1091
source "$ROOT/BIPTEC-RELEASE"

OUT=${1:-"$ROOT/dist/biptec-release"}
WORK=${BIPTEC_BUILD_WORKDIR:-"$ROOT/.biptec-build"}
DISTGIT="$WORK/freeipa-distgit"
PATCH_DIR="$WORK/patches"
RPMTOP="$WORK/rpmbuild"

rm -rf "$OUT" "$WORK"
mkdir -p "$OUT" "$WORK" "$RPMTOP"/{BUILD,BUILDROOT,RPMS,SOURCES,SPECS,SRPMS}

"$ROOT/biptec/release/verify-source.sh"
"$ROOT/biptec/release/export-patches.sh" "$PATCH_DIR"

git clone --quiet --branch "$FEDORA_BRANCH" https://src.fedoraproject.org/rpms/freeipa.git "$DISTGIT"
git -C "$DISTGIT" checkout --quiet "$FEDORA_DISTGIT_COMMIT"
(
    cd "$DISTGIT"
    fedpkg sources
)
"$ROOT/biptec/release/prepare-distgit.sh" "$DISTGIT" "$PATCH_DIR"
dnf -y builddep "$DISTGIT/freeipa.spec"

cp "$DISTGIT"/* "$RPMTOP/SOURCES/" 2>/dev/null || true
cp "$DISTGIT/freeipa.spec" "$RPMTOP/SPECS/freeipa.spec"

rpmbuild -ba \
    --define "_topdir $RPMTOP" \
    --define "_sourcedir $RPMTOP/SOURCES" \
    "$RPMTOP/SPECS/freeipa.spec"

mkdir -p "$OUT/rpms" "$OUT/srpm" "$OUT/repo"
find "$RPMTOP/RPMS" -type f -name '*.rpm' -exec cp -t "$OUT/rpms" {} +
find "$RPMTOP/SRPMS" -type f -name '*.src.rpm' -exec cp -t "$OUT/srpm" {} +
cp "$OUT/rpms"/*.rpm "$OUT/repo/"
createrepo_c "$OUT/repo"

VERSION_ID="${PACKAGE_VERSION}-${FEDORA_PACKAGE_RELEASE}.fc${TARGET_FEDORA}.biptec.${BIPTEC_RELEASE}"
REPO_TAR="biptec-freeipa-${VERSION_ID}-${TARGET_ARCH}-repo.tar.gz"
PATCH_TAR="biptec-freeipa-${VERSION_ID}-patches.tar.gz"

tar -C "$OUT" -czf "$OUT/$REPO_TAR" repo
tar -C "$PATCH_DIR" -czf "$OUT/$PATCH_TAR" .
cat > "$OUT/BUILD-METADATA.txt" <<EOF
BIPTEC FreeIPA build
source_commit=$(git rev-parse HEAD)
source_tree=$(git rev-parse "$PATCH_HEAD^{tree}")
upstream_tag=$UPSTREAM_TAG
upstream_commit=$UPSTREAM_COMMIT
fedora_branch=$FEDORA_BRANCH
fedora_distgit_commit=$FEDORA_DISTGIT_COMMIT
package_version=$PACKAGE_VERSION
package_release=$FEDORA_PACKAGE_RELEASE.fc$TARGET_FEDORA.biptec.$BIPTEC_RELEASE
patch_count=$PATCH_COUNT
target_arch=$TARGET_ARCH
EOF

cat > "$OUT/README-INSTALL.txt" <<EOF
BIPTEC FreeIPA ${VERSION_ID}

The repo/ directory contains the complete BIPTEC-built FreeIPA RPM set and DNF metadata.
For a local installation, extract ${REPO_TAR} and either serve repo/ over HTTP(S)
or configure a file:// DNF repository pointing at the extracted repo directory.
Do not mix BIPTEC FreeIPA server RPMs with a different FreeIPA server build on the same host.
EOF

(
    cd "$OUT"
    sha256sum "$REPO_TAR" "$PATCH_TAR" BUILD-METADATA.txt README-INSTALL.txt > SHA256SUMS
)

rpm -qp --qf '%{NAME} %{VERSION}-%{RELEASE} %{ARCH}\n' "$OUT/rpms"/*.rpm | sort > "$OUT/RPM-MANIFEST.txt"
echo "Build artifacts are in $OUT"
cat "$OUT/BUILD-METADATA.txt"
