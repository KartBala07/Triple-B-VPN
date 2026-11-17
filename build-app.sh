#!/bin/bash
# Build "Triple B VPN.app" from the Swift sources (no Xcode project needed) and
# embed everything the app needs to install its own privileged helper.
set -euo pipefail
PREFIX=$(cd "$(dirname "$0")" && pwd)
APP="$PREFIX/build/Triple B VPN.app"
BIN="$APP/Contents/MacOS/TripleBVPN"
RES="$APP/Contents/Resources"

echo "building $APP"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$RES"

swiftc -O \
  "$PREFIX/app/main.swift" \
  "$PREFIX/app/Model.swift" \
  "$PREFIX/app/ContentView.swift" \
  -framework AppKit -framework SwiftUI -framework Combine \
  -o "$BIN"

cp "$PREFIX/app/Info.plist" "$APP/Contents/Info.plist"
printf 'APPL????' > "$APP/Contents/PkgInfo"

# icon
"$PREFIX/tools/make-icns.sh" >/dev/null
cp "$PREFIX/build/AppIcon.icns" "$RES/AppIcon.icns"

# helper payload: the engine, its launchd plist, and the installer script
install -m 755 "$PREFIX/target/release/hvpn" "$RES/hvpn"
install -m 644 "$PREFIX/deploy/com.tripleb.vpn.plist" "$RES/com.tripleb.vpn.plist"
install -m 755 "$PREFIX/deploy/install-helper.sh" "$RES/install-helper.sh"

# ad-hoc signature so macOS treats it as a stable app identity
codesign --force --sign - "$APP" 2>/dev/null || echo "warning: ad-hoc codesign failed"

echo "built: $APP"
echo "run:   open '$APP'"
