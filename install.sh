#!/bin/bash
# Install hvpn + hvpnctl into /usr/local/bin so they work from anywhere.
set -euo pipefail
PREFIX=$(cd "$(dirname "$0")" && pwd)

if [ "$(id -u)" != 0 ]; then
  echo "installing to /usr/local/bin needs root — run: sudo $0" >&2
  exit 1
fi

if [ ! -x "$PREFIX/target/release/hvpn" ]; then
  echo "no binary yet — run: cargo build --release (in $PREFIX)" >&2
  exit 1
fi

install -m 755 "$PREFIX/target/release/hvpn" /usr/local/bin/hvpn
install -m 755 "$PREFIX/bin/hvpnctl" /usr/local/bin/hvpnctl
echo "installed:"
echo "  /usr/local/bin/hvpn"
echo "  /usr/local/bin/hvpnctl"
echo
echo "try:  hvpnctl doctor   |   sudo hvpnctl node   |   sudo hvpnctl up --peer HOST --full"
