#!/bin/bash
# Prove the exit node can chain into X-VPN's tunnel (utun4 / 172.21.0.1):
# client -> our encrypted tunnel -> exit node -> X-VPN tunnel -> X-VPN's servers.
HERE=/Users/bala/HermesVPN
BIN=$HERE/target/release/hvpn
DAEMON=$HERE/test/hvpn-launch.sh
RUN=/var/run/hvpn
LOG=$HERE/test/chain-test.log
exec > "$LOG" 2>&1
echo "=== chain-through-X-VPN test $(date)"

XV=""
for i in $(ifconfig -l | tr ' ' '\n' | grep '^utun'); do
  ip=$(ifconfig "$i" 2>/dev/null | awk '/inet /{print $2; exit}')
  case "$ip" in 172.21.*) XV="$i";; esac
done
echo "X-VPN tunnel: ${XV:-none}"
if [ -z "$XV" ]; then echo "X-VPN is not connected — aborting"; chmod 644 "$LOG"; chown bala:staff "$LOG"; exit 1; fi
echo "default route: $(route -n get default | awk '/interface:/{print $2}')"

cleanup() {
  pkill -f 'hvpn serve' 2>/dev/null; pkill -f 'hvpn up' 2>/dev/null; sleep 1
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
mkdir -p $RUN
[ -f $RUN/psk ] || $BIN keygen -o $RUN/psk >/dev/null

echo "--- pf parse check for route-to on a point-to-point tunnel"
printf 'pass in quick on utun5 route-to (%s) from 10.66.200.0/24 to any\n' "$XV" > /tmp/rt.conf
pfctl -n -f /tmp/rt.conf 2>&1 | grep -viE 'ALTQ|Use of -f|^present|^See /etc|^$' | head -2 || true

echo "--- starting exit node with egress = X-VPN ($XV)"
"$DAEMON" "$BIN" serve --key $RUN/psk --listen 127.0.0.1:51820 --tun-ip 10.66.0.1 \
      --nat "$XV" --egress "$XV" --peer-nat 10.66.200.0 -v > $RUN/node.log 2>&1 &
for i in $(seq 1 40); do grep -q "listening on udp" $RUN/node.log && break; sleep 0.25; done
grep -E "NAT|policy route|WARNING" $RUN/node.log | head -4
echo "pf nat: $(pfctl -s nat 2>/dev/null | grep -c "$XV")   route-to: $(pfctl -sr 2>/dev/null | grep -c route-to)"

echo "--- client through the tunnel"
"$DAEMON" "$BIN" up --key $RUN/psk --peer 127.0.0.1:51820 --tun-ip 10.66.0.2 --route 1.1.1.1/32 -v > $RUN/client.log 2>&1 &
for i in $(seq 1 60); do grep -q "route 1.1.1.1/32" $RUN/client.log && break; sleep 0.25; done
sleep 1

echo "route to 1.1.1.1: $(route -n get 1.1.1.1 | awk '/interface:/{print $2}')"
echo "ping through chain: $(ping -c 3 -t 8 1.1.1.1 >/dev/null 2>&1 && echo OK || echo FAIL)"
echo "https through chain: $(curl -4 -s -o /dev/null -w '%{http_code}' -L --max-time 20 https://1.1.1.1/cdn-cgi/trace)"
echo "exit IP seen by Cloudflare: $(curl -4 -s --max-time 20 https://1.1.1.1/cdn-cgi/trace | awk -F= '/^ip=/{print $2}')"

echo "--- proof the forwarded packet entered X-VPN's tunnel"
tcpdump -n -i "$XV" -c 6 -w /tmp/chain.pcap 'icmp and host 1.1.1.1' >/dev/null 2>&1 &
DUMP=$!
sleep 1
ping -c 3 -t 5 1.1.1.1 >/dev/null 2>&1
sleep 1
kill -INT $DUMP 2>/dev/null; sleep 0.5
tcpdump -nr /tmp/chain.pcap 2>/dev/null | head -6

echo "--- causal check: freeze the exit node, traffic must die"
NODEPID=$(pgrep -f 'hvpn serve' | head -1)
kill -STOP "$NODEPID" 2>/dev/null
echo "ping while frozen: $(ping -c 1 -t 3 1.1.1.1 >/dev/null 2>&1 && echo STILL-UP || echo DEAD)"
kill -CONT "$NODEPID" 2>/dev/null
sleep 1
echo "ping after resume: $(ping -c 2 -t 5 1.1.1.1 >/dev/null 2>&1 && echo OK || echo FAIL)"

echo "--- teardown"
cleanup
echo "internet after: $(curl -4 -s -o /dev/null -w '%{http_code}' --max-time 10 https://example.com)"
echo "default route after: $(route -n get default | awk '/interface:/{print $2}')"
chmod 644 "$LOG"; chown bala:staff "$LOG"; chown -R bala:staff $RUN
echo "=== done"
