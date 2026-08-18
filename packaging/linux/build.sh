#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# Kosh — Linux packaging script
# Produces:  build/bin/Kosh-linux-amd64.AppImage
#            build/bin/localvault_1.0.0_amd64.deb
#
# Run on:    Ubuntu 22.04 / Debian 12 (or compatible) x86_64
# Requires:  go 1.25+, node 20+, appimage-builder (pip), dpkg-deb, fakeroot
#
# Usage:
#   chmod +x packaging/linux/build.sh
#   ./packaging/linux/build.sh [VERSION]       # default: 1.0.0
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

VERSION="${1:-1.0.0}"
APPNAME="Kosh"
BINARY="Kosh-linux-amd64"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"   # cmd/localvault
REPO="$(cd "$ROOT/../.." && pwd)"             # repo root
OUTDIR="$ROOT/build/bin"

echo "==> Building Go binary for Linux…"
cd "$ROOT"
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  go build -ldflags "-X main.version=$VERSION -s -w" -o "$OUTDIR/$BINARY" .

echo "==> Building React frontend…"
cd "$ROOT/frontend"
npm ci --silent
npm run build --silent

echo ""
echo "──────────────────────────────────────────────────"
echo "  Binary:  $OUTDIR/$BINARY"
echo "  Version: $VERSION"
echo ""
echo "  Next steps:"
echo "  1. Build AppImage with Wails natively:"
echo "     cd cmd/localvault && wails build -platform linux/amd64"
echo ""
echo "  2. Build .deb (manual):"
echo "     See packaging/linux/deb/ for the control file template."
echo ""
echo "  Security check — the binary must not listen on any port:"
echo "     strace -e trace=socket,bind,listen -f ./$BINARY 2>&1 | grep -E 'bind|listen'"
echo "     (Expected: no network socket calls)"
echo "──────────────────────────────────────────────────"
