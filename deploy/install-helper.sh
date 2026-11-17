#!/bin/bash
# Installs the privileged helper for Triple B VPN. Runs as root, called by the
# app's "Enable VPN" button via osascript with administrator privileges, and by
# install-app.py.
set -uo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
LABEL=com.tripleb.vpn
LEGACY=com.hermes.vpn
SOCK=/var/run/hvpn/control.sock

[ "$(id -u)" = 0 ] || { echo "must run as root"; exit 1; }

echo "== installing $LABEL helper"
install -d /usr/local/bin
install -m 755 "$HERE/hvpn" /usr/local/bin/hvpn

# stop whatever is running (new or legacy label) before replacing the plist
if [ -S "$SOCK" ]; then
  python3 -c "
import socket,sys
try:
    s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM); s.settimeout(2)
    s.connect('$SOCK'); s.sendall(b'STOPALL\n'); s.recv(4096); s.close()
    s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM); s.settimeout(2)
    s.connect('$SOCK'); s.sendall(b'QUIT\n'); s.recv(4096); s.close()
except Exception:
    pass
" >/dev/null 2>&1 || true
  sleep 1
fi
launchctl bootout "system/$LABEL" 2>/dev/null || true
launchctl bootout "system/$LEGACY" 2>/dev/null || true
rm -f "/Library/LaunchDaemons/$LEGACY.plist"
sleep 0.5
/usr/local/bin/hvpn down >/dev/null 2>&1 || true
pfctl -f /etc/pf.conf >/dev/null 2>&1 || true
sysctl -w net.inet.ip.forwarding=0 >/dev/null 2>&1 || true
rm -f "$SOCK"

install -m 644 "$HERE/$LABEL.plist" "/Library/LaunchDaemons/$LABEL.plist"
chown root:wheel "/Library/LaunchDaemons/$LABEL.plist"
touch /var/log/tripleb-vpn.log
chown root:wheel /var/log/tripleb-vpn.log

launchctl bootstrap system "/Library/LaunchDaemons/$LABEL.plist" 2>&1 || true
launchctl enable "system/$LABEL" 2>/dev/null || true

for i in $(seq 1 40); do [ -S "$SOCK" ] && break; sleep 0.25; done
if [ -S "$SOCK" ]; then
  echo "helper ready"
else
  echo "helper failed to start:" >&2
  tail -5 /var/log/tripleb-vpn.log >&2 || true
  exit 1
fi
