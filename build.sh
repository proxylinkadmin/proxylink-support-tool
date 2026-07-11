#!/bin/bash
# Build the ProxyLink Support Tool for Windows (amd64).
#
# GUI app (lxn/walk) — no CGO needed for the Go build; mingw windres only compiles the
# resource (icon + UAC manifest + Common Controls). Produces dist/ProxyLinkSupport.exe.
#
# Requires: Go 1.22+ and x86_64-w64-mingw32-windres
#   (Debian/Ubuntu:  sudo apt install golang gcc-mingw-w64-x86-64 binutils-mingw-w64)
set -e

DIR="$(cd "$(dirname "$0")" && pwd)"
OUTDIR="$DIR/dist"
mkdir -p "$OUTDIR"

echo "[1/2] Compiling Windows resource (icon + manifest)..."
x86_64-w64-mingw32-windres "$DIR/cmd/plsupport/resource.rc" -O coff -o "$DIR/cmd/plsupport/resource.syso"

echo "[2/2] Building..."
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 \
  go build -trimpath -ldflags="-s -w -H windowsgui" \
  -o "$OUTDIR/ProxyLinkSupport.exe" "$DIR/cmd/plsupport"

echo "Done: $OUTDIR/ProxyLinkSupport.exe"
