#!/bin/bash
# Build AppIcon.icns from the generated 1024px master.
set -euo pipefail
PREFIX=$(cd "$(dirname "$0")/.." && pwd)
MASTER=${1:-/tmp/tb-icon-1024.png}
SET="$PREFIX/build/AppIcon.iconset"
OUT="$PREFIX/build/AppIcon.icns"

mkdir -p "$SET" "$PREFIX/build"
swift "$PREFIX/tools/make-icon.swift" "$MASTER" >/dev/null

make() { sips -Z "$1" "$MASTER" --out "$SET/$2" >/dev/null 2>&1; }
make 16   icon_16x16.png
make 32   icon_16x16@2x.png
make 32   icon_32x32.png
make 64   icon_32x32@2x.png
make 128  icon_128x128.png
make 256  icon_128x128@2x.png
make 256  icon_256x256.png
make 512  icon_256x256@2x.png
make 512  icon_512x512.png
cp "$MASTER" "$SET/icon_512x512@2x.png"

iconutil -c icns "$SET" -o "$OUT"
echo "icon: $OUT ($(ls -l "$OUT" | awk '{print $5}') bytes)"
