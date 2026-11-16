#!/bin/bash
# Elevation wrapper: fresh-state cleanup, pf syntax probe, full e2e, hard restore.
# Everything is logged to /Users/bala/HermesVPN/test/e2e.log (world readable).
HERE=/Users/bala/HermesVPN
LOG=$HERE/test/e2e.log
BIN=$HERE/target/release/hvpn
RUN=/var/run/hvpn

exec > "$LOG" 2>&1
echo "=== elevated run $(date) as uid $(id -u)"

PF_OLD=$(pfctl -s info 2>/dev/null | awk '/Status:/{print $2}')
echo "=== pf was: ${PF_OLD:-unknown}"

echo "=== pre-clean: killing stale hvpn"
pkill -KILL -f 'hvpn serve' 2>/dev/null
pkill -KILL -f 'hvpn up' 2>/dev/null
pkill -KILL -f 'test/e2e.sh' 2>/dev/null
pkill -KILL -f 'tcpdump -n -i lo0' 2>/dev/null
sleep 1
for n in 0.0.0.0/1 128.0.0.0/1 10.66.0.0/24 10.66.200.0/24 1.1.1.1; do
  for i in $(ifconfig -l | tr ' ' '\n' | grep '^utun'); do
    route -n delete -net "$n" -interface "$i" >/dev/null 2>&1
    route -n delete -host "$n" -interface "$i" >/dev/null 2>&1
  done
done
rm -f $RUN/*.state
pfctl -f /etc/pf.conf >/dev/null 2>&1

echo "=== pf syntax probe of the ruleset hvpn generates (parse only)"
cat > /tmp/hvpn-probe.conf <<'EOF'
scrub-anchor "com.apple/*"
nat-anchor "com.apple/*"
nat on en0 inet from 10.66.200.0/24 to any -> (en0)
rdr-anchor "com.apple/*"
dummynet-anchor "com.apple/*"
anchor "com.apple/*"
EOF
pfctl -n -f /tmp/hvpn-probe.conf 2>&1 | grep -vE 'ALTQ|Use of -f option|^present in|^See /etc/pf.conf|^$' | head -5
echo "probe rc=$?"

echo "=== e2e (watchdog 220s)"
/bin/bash "$HERE/test/e2e.sh" &
P=$!
for i in $(seq 1 220); do
  kill -0 "$P" 2>/dev/null || break
  sleep 1
done
if kill -0 "$P" 2>/dev/null; then
  echo "WATCHDOG: e2e exceeded 220s, killing $P"
  kill -KILL "$P" 2>/dev/null
fi
wait "$P" 2>/dev/null
E2E_RC=$?
echo "=== e2e rc=$E2E_RC"

echo "=== post-clean"
pkill -KILL -f 'hvpn serve' 2>/dev/null
pkill -KILL -f 'hvpn up' 2>/dev/null
pkill -KILL -f 'tcpdump -n -i lo0' 2>/dev/null
for n in 0.0.0.0/1 128.0.0.0/1 10.66.0.0/24 10.66.200.0/24 1.1.1.1; do
  for i in $(ifconfig -l | tr ' ' '\n' | grep '^utun'); do
    route -n delete -net "$n" -interface "$i" >/dev/null 2>&1
    route -n delete -host "$n" -interface "$i" >/dev/null 2>&1
  done
done
pfctl -f /etc/pf.conf >/dev/null 2>&1
sysctl -w net.inet.ip.forwarding=0 >/dev/null 2>&1
rm -f $RUN/*.state

echo "=== default route now: $(route -n get default 2>/dev/null | awk '/interface:/{print $2}')"
echo "=== internet check: $(curl -4 -s -o /dev/null -w '%{http_code}' --max-time 15 https://example.com)"
chmod 644 "$LOG"
chown bala:staff "$LOG" 2>/dev/null
chown -R bala:staff $RUN 2>/dev/null
echo "=== runner finished rc=$E2E_RC"
exit 0
