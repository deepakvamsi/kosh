#!/usr/bin/env bash
# Assemble a .deb from an already-built Linux binary (cmd/localvault/build/bin/Kosh).
#
# Usage:  packaging/linux/package-deb.sh [VERSION]
#   VERSION may be a bare version (0.1.0) or a git tag (v0.1.0); a leading "v" is stripped.
#   Build the binary first:  cd cmd/localvault && wails build -platform linux/amd64
set -euo pipefail

VERSION="${1:-0.1.0}"
VERSION="${VERSION#v}"

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
BIN="$REPO/cmd/localvault/build/bin/Kosh"
[ -f "$BIN" ] || { echo "binary not found: $BIN (run: cd cmd/localvault && wails build -platform linux/amd64)"; exit 1; }

STAGE="$(mktemp -d)/kosh_${VERSION}_amd64"
mkdir -p "$STAGE/DEBIAN" "$STAGE/usr/local/bin" "$STAGE/usr/share/applications"

# Control file, with the requested version substituted in.
sed "s/^Version:.*/Version: ${VERSION}/" "$REPO/packaging/linux/deb/DEBIAN/control" > "$STAGE/DEBIAN/control"

install -m 0755 "$BIN" "$STAGE/usr/local/bin/Kosh"
install -m 0644 "$REPO/packaging/linux/kosh.desktop" "$STAGE/usr/share/applications/kosh.desktop"

OUT="$REPO/kosh_${VERSION}_amd64.deb"
dpkg-deb --build --root-owner-group "$STAGE" "$OUT"
echo "built: $OUT"
