#!/bin/bash
# Start a live node + client pair on this Mac and leave both running detached.
HERE=/Users/bala/HermesVPN
BIN=$HERE/target/release/hvpn
DAEMON=$HERE/test/hvpn-daemon.sh
RUN=/var/run/hvpn
LOG=$HERE/test/run-live.log
exec > "$LOG" 2>&1
echo "=== live run $(date)"

PHYS=""
for i in $(ifconfig -l); do
  case "$i" in utun*|lo*|gif*|stf*|awdl*|llw*|bridge*|ap*|anpi*) continue;; esac
  if [ -n "$(ipconfig getoption "$i" router 2>/dev/null)" ]; then PHYS="$i"; break; fi
done
[ -z "$PHYS" ] && PHYS=$(route -n get default | awk '/interface:/{print $2}')
echo "uplink: $PHYS"

echo "--- clearing any previous instance"
pkill -f 'hvpn serve' 2>/dev/null; pkill -f 'hvpn up' 2>/dev/null; sleep 1.5
for n in 10.66.0.0/24 10.66.200.0/24 1.1.1.1; do
  for i in $(ifconfig -l | tr ' ' '\n' | grep '^utun'); do
    route -n delete -net "$n" -interface "$i" >/dev/null 2>&1
    route -n delete -host "$n" -interface "$i" >/dev/null 2>&1
  done
done
pfctl -f /etc/pf.conf >/dev/null 2>&1
sysctl -w net.inet.ip.forwarding=0 >/dev/null 2>&1
rm -f $RUN/*.state
mkdir -p $RUN
[ -f $RUN/psk ] || $BIN keygen -o $RUN/psk >/dev/null

BULK_IP=$(dig +short speed.cloudflare.com A 2>/dev/null | grep -m1 -E '^[0-9]+\.')

echo "--- starting exit node (detached)"
"$DAEMON" "$BIN" serve --key $RUN/psk --listen 0.0.0.0:51820 --tun-ip 10.66.0.1 \
      --nat "$PHYS" --egress "$PHYS" --peer-nat 10.66.200.0 -v > $RUN/node.log 2>&1 &
for i in $(seq 1 40); do grep -q "listening on udp" $RUN/node.log && break; sleep 0.25; done
grep -q "listening on udp" $RUN/node.log && echo "node up" || { echo "node FAILED"; tail -5 $RUN/node.log; }

echo "--- starting client (detached, split tunnel)"
ROUTES=(--route 1.1.1.1/32)
[ -n "$BULK_IP" ] && ROUTES+=(--route "$BULK_IP/32")
echo "routes: ${ROUTES[*]}"
"$DAEMON" "$BIN" up --key $RUN/psk --peer 127.0.0.1:51820 --tun-ip 10.66.0.2 "${ROUTES[@]}" -v > $RUN/client.log 2>&1 &
for i in $(seq 1 80); do grep -q "route 1.1.1.1/32" $RUN/client.log && break; sleep 0.25; done
sleep 2

echo "--- liveness"
ps -o pid,ppid,stat,command -p $(pgrep -f 'hvpn serve' | head -1),$(pgrep -f 'hvpn up' | head -1) 2>/dev/null | sed 's/--key.*//'

echo "--- live traffic"
echo "route 1.1.1.1: $(route -n get 1.1.1.1 2>/dev/null | awk '/interface:/{print $2}')"
echo "ping:  $(ping -c 3 -t 6 1.1.1.1 >/dev/null 2>&1 && echo OK || echo FAIL)"
echo "dns:   $(dig @1.1.1.1 +short +time=5 example.com A 2>/dev/null | head -1)"
echo "https: $(curl -4 -s -o /dev/null -w '%{http_code} %{size_download}B' -L --max-time 20 https://1.1.1.1/cdn-cgi/trace)"
if [ -n "$BULK_IP" ]; then
  echo "bulk:  $(curl -4 -s -o /dev/null -w '%{size_download}B in %{time_total}s' --max-time 60 \
     --resolve speed.cloudflare.com:443:$BULK_IP 'https://speed.cloudflare.com/__down?bytes=1000000')"
fi
echo "client counters: $(grep -o 'tx [0-9]* pkts [0-9]* B | rx [0-9]* B' $RUN/client.log | tail -1)"
echo "--- left running: node pid $(pgrep -f 'hvpn serve' | head -1), client pid $(pgrep -f 'hvpn up' | head -1)"
chmod 644 "$LOG"; chown bala:staff "$LOG"; chown -R bala:staff $RUN
