#!/bin/bash
# Put the built app into /Applications (needs root because the previous copy was
# installed by root). Mirrors what the DMG install does by hand.
set -uo pipefail
SRC="/Users/bala/HermesVPN/build/Triple B VPN.app"
DST="/Applications/Triple B VPN.app"

[ "$(id -u)" = 0 ] || { echo "needs root"; exit 1; }
[ -d "$SRC" ] || { echo "source app missing: $SRC"; exit 1; }

rm -rf "/Applications/HermesVPN.app" "$DST"
cp -R "$SRC" "$DST"
chown -R root:wheel "$DST"
xattr -dr com.apple.quarantine "$DST" 2>/dev/null || true
echo "installed: $DST"
/usr/libexec/PlistBuddy -c "Print :CFBundleName" -c "Print :CFBundleIdentifier" "$DST/Contents/Info.plist"
