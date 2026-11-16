#!/bin/bash
# Verify the user-facing wrapper (hvpnctl) works end to end, not just the binary.
HERE=/Users/bala/HermesVPN
CTL=$HERE/bin/hvpnctl
BIN=$HERE/target/release/hvpn
LAUNCH=$HERE/test/hvpn-launch.sh
RUN=/var/run/hvpn
LOG=$HERE/test/verify-ctl.log
exec > "$LOG" 2>&1
echo "=== hvpnctl verification $(date)"

cleanup() {
  pkill -KILL -f 'hvpn serve' 2>/dev/null; pkill -KILL -f 'hvpn up' 2>/dev/null; sleep 1
  for n in 10.66.0.0/24 10.66.200.0/24 1.1.1.1; do
    for i in $(ifconfig -l | tr ' ' '\n' | grep '^utun'); do
      route -n delete -net "$n" -interface "$i" >/dev/null 2>&1
      route -n delete -host "$n" -interface "$i" >/dev/null 2>&1
    done
  done
  pfctl -f /etc/pf.conf >/dev/null 2>&1
  sysctl -w net.inet.ip.forwarding=0 >/dev/null 2>&1
  rm -f $RUN/*.state
}
cleanup

echo "--- hvpnctl key (creates if missing)"
$CTL key | tail -2
echo "key file: $(ls -l $RUN/psk 2>&1)"

echo "--- hvpnctl node (background)"
$LAUNCH /bin/bash $CTL node --listen 127.0.0.1:51820 > $RUN/ctl-node.log 2>&1 &
NODEPID=$!
for i in $(seq 1 40); do grep -q "listening on udp" $RUN/ctl-node.log && break; sleep 0.25; done
echo "node log head:"; head -4 $RUN/ctl-node.log

echo "--- hvpnctl up (background, split tunnel)"
$LAUNCH /bin/bash $CTL up --peer 127.0.0.1 --route 1.1.1.1/32 > $RUN/ctl-client.log 2>&1 &
CLIPID=$!
for i in $(seq 1 80); do grep -q "route 1.1.1.1/32" $RUN/ctl-client.log && break; sleep 0.25; done
echo "client log head:"; head -5 $RUN/ctl-client.log

echo "--- hvpnctl status"
$CTL status

echo "--- traffic through the wrapper-managed tunnel"
echo "ping:  $(ping -c 3 -t 6 1.1.1.1 >/dev/null 2>&1 && echo OK || echo FAIL)"
echo "http:  $(curl -4 -s -o /dev/null -w '%{http_code}' --max-time 15 http://1.1.1.1/)"
echo "https: $(curl -4 -s -o /dev/null -w '%{http_code} %{size_download}' -L --max-time 20 https://1.1.1.1/cdn-cgi/trace)"
echo "route: $(route -n get 1.1.1.1 2>/dev/null | awk '/interface:/{print $2}')"

echo "--- hvpnctl down"
$CTL down
sleep 2
echo "1.1.1.1 route now: $(route -n get 1.1.1.1 2>/dev/null | awk '/interface:/{print $2}')"
echo "state files: $(ls $RUN/*.state 2>/dev/null || echo none)"
echo "pf tunnel nat: $(pfctl -s nat 2>/dev/null | grep -c 10.66.200)"
echo "forwarding: $(sysctl -n net.inet.ip.forwarding)"
echo "internet: $(curl -4 -s -o /dev/null -w '%{http_code}' --max-time 15 https://example.com)"

echo "--- doctor"
$CTL doctor

cleanup
chmod 644 "$LOG"; chown bala:staff "$LOG"; chown -R bala:staff $RUN
echo "=== done"
