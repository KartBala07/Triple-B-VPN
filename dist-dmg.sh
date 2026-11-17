#!/bin/bash
# Build a distributable DMG for Triple B VPN: drag the app to Applications.
set -euo pipefail
PREFIX=$(cd "$(dirname "$0")" && pwd)
VERSION=$(/usr/libexec/PlistBuddy -c "Print CFBundleShortVersionString" "$PREFIX/app/Info.plist")
APP="$PREFIX/build/Triple B VPN.app"
STAGE="$PREFIX/build/dmg-stage"
DMG="$PREFIX/dist/TripleB-VPN-$VERSION.dmg"

"$PREFIX/build-app.sh"

echo "staging"
rm -rf "$STAGE"
mkdir -p "$STAGE" "$PREFIX/dist"
cp -R "$APP" "$STAGE/Triple B VPN.app"
ln -s /Applications "$STAGE/Applications"

cat > "$STAGE/READ ME.txt" <<'TXT'
Triple B VPN
============

1. Drag "Triple B VPN.app" into the Applications folder.
2. Open it from Applications (or Spotlight).
3. Click "Enable VPN" once — macOS asks for your admin password to install the
   privileged helper that creates the tunnel. That is the only time it asks.
4. Paste the peer address of the Mac running the exit node, then press Connect.

If macOS refuses to open the app with "cannot be verified", right-click the app
and choose Open, or run:

   xattr -dr com.apple.quarantine "/Applications/Triple B VPN.app"

The app is signed ad-hoc (no paid Apple Developer ID), so Gatekeeper warns once.

The exit node must be a different machine — start one there with:

   /usr/local/bin/hvpn serve --key /var/run/hvpn/psk --nat auto --egress auto --peer-nat 10.66.200.0

or just use the same app on that Mac and flip the "Exit node" switch.
TXT

echo "creating $DMG"
hdiutil create -volname "Triple B VPN" -srcfolder "$STAGE" -ov -format UDZO -fs HFS+ "$DMG" >/dev/null
rm -rf "$STAGE"

echo "dmg: $DMG ($(ls -lh "$DMG" | awk '{print $5}'))"
shasum -a 256 "$DMG" | awk '{print "sha256:", $1}'
