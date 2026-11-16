#!/bin/bash
# Build HermesVPN.app from the Swift sources (no Xcode project needed).
set -euo pipefail
PREFIX=$(cd "$(dirname "$0")" && pwd)
APP="$PREFIX/build/HermesVPN.app"
BIN="$APP/Contents/MacOS/HermesVPN"

echo "building $APP"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"

swiftc -O \
  "$PREFIX/app/main.swift" \
  "$PREFIX/app/Model.swift" \
  "$PREFIX/app/ContentView.swift" \
  -framework AppKit -framework SwiftUI -framework Combine \
  -o "$BIN"

cp "$PREFIX/app/Info.plist" "$APP/Contents/Info.plist"
printf 'APPL????' > "$APP/Contents/PkgInfo"

# ad-hoc signature so macOS treats it as a stable app identity
codesign --force --sign - --timestamp=none "$APP" 2>/dev/null || \
  codesign --force --sign - "$APP" 2>/dev/null || echo "warning: ad-hoc codesign failed"

echo "built: $APP"
echo "run:   open '$APP'"
