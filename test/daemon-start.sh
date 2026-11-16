#!/bin/bash
# Start the privileged control daemon detached (for testing before installing
# the LaunchDaemon), then prove it answers on the socket.
HERE=/Users/bala/HermesVPN
BIN=$HERE/target/release/hvpn
DAEMON=$HERE/test/hvpn-daemon.sh
LOG=$HERE/test/daemon-start.log
SOCK=/var/run/hvpn/control.sock
exec > "$LOG" 2>&1
echo "=== daemon start $(date)"

pkill -f 'hvpn daemon' 2>/dev/null
pkill -f 'hvpn serve' 2>/dev/null
pkill -f 'hvpn up' 2>/dev/null
sleep 1
rm -f "$SOCK"
pfctl -f /etc/pf.conf >/dev/null 2>&1
sysctl -w net.inet.ip.forwarding=0 >/dev/null 2>&1
mkdir -p /var/run/hvpn

"$DAEMON" "$BIN" daemon > /var/run/hvpn/daemon.log 2>&1 &
for i in $(seq 1 40); do [ -S "$SOCK" ] && break; sleep 0.25; done
if [ -S "$SOCK" ]; then echo "socket up: $(ls -l $SOCK)"; else echo "SOCKET MISSING"; tail -5 /var/run/hvpn/daemon.log; fi
echo "daemon pid: $(pgrep -f 'hvpn daemon' | head -1)"
echo "--- PING"
python3 "$HERE/test/ctl.py" PING
echo "--- STATUS (fresh)"
python3 "$HERE/test/ctl.py" STATUS
chmod -R a+r /var/run/hvpn 2>/dev/null
chmod 644 "$LOG"; chown bala:staff "$LOG"
