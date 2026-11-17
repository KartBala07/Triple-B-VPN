#!/bin/bash
# Cross-compile the Windows client and package it for release.
#
# Needs llvm-mingw (clang + mingw-w64 sysroot) because Rust's windows-gnu target
# wants libgcc and the gnullvm target wants a mingw sysroot:
#   https://github.com/mstorsjo/llvm-mingw/releases  (macos-universal tarball)
#
# Usage: LLVM_MINGW=/path/to/llvm-mingw ./build-windows.sh
set -euo pipefail
PREFIX=$(cd "$(dirname "$0")" && pwd)
MINGW=${LLVM_MINGW:-/tmp/llvm-mingw-20261104-ucrt-macos-universal}
OUT="$PREFIX/dist/windows"
ZIP="$PREFIX/dist/TripleB-VPN-windows-alpha.zip"

[ -d "$MINGW" ] || { echo "llvm-mingw not found at $MINGW (set LLVM_MINGW=)"; exit 1; }
export PATH="$MINGW/bin:$PATH"
export CC_x86_64_pc_windows_gnullvm=x86_64-w64-mingw32-clang

echo "== building hvpn.exe"
cargo build --release --target x86_64-pc-windows-gnullvm

echo "== staging"
rm -rf "$OUT" "$ZIP"
mkdir -p "$OUT"
cp "$PREFIX/target/x86_64-pc-windows-gnullvm/release/hvpn.exe" "$OUT/"
cp "$PREFIX/windows/TripleBVPN.ps1" "$PREFIX/windows/README.txt" "$OUT/"

# wintun.dll: shipped from the official zip, never rebuilt here
WINTUN_DLL=${WINTUN_DLL:-/tmp/wintun/wintun/bin/amd64/wintun.dll}
if [ -f "$WINTUN_DLL" ]; then
  cp "$WINTUN_DLL" "$OUT/"
else
  echo "warning: wintun.dll not found ($WINTUN_DLL) — download wintun-0.14.1.zip from wintun.net"
fi

echo "== zipping"
( cd "$PREFIX/dist" && zip -qr "$(basename "$ZIP")" windows )
echo "zip: $ZIP ($(ls -lh "$ZIP" | awk '{print $5}'))"
shasum -a 256 "$ZIP"
