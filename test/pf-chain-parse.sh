#!/bin/bash
# Which pf syntax works for policy-routing into a point-to-point tunnel (X-VPN)?
LOG=/Users/bala/HermesVPN/test/pf-chain-parse.log
exec > "$LOG" 2>&1
XV=""
for i in $(ifconfig -l | tr ' ' '\n' | grep '^utun'); do
  ip=$(ifconfig "$i" 2>/dev/null | awk '/inet /{print $2; exit}')
  case "$ip" in 172.21.*) XV="$i";; esac
done
PEER=$(ifconfig "$XV" 2>/dev/null | awk '/inet /{for(k=1;k<=NF;k++) if($k=="-->"){print $(k+1); exit}}')
ADDR=$(ifconfig "$XV" 2>/dev/null | awk '/inet /{print $2; exit}')
echo "xvpn=$XV addr=$ADDR peer=$PEER"
try() {
  printf '%s\n' "$1" > /tmp/c1.conf
  out=$(pfctl -n -f /tmp/c1.conf 2>&1 | grep -viE 'ALTQ|Use of -f|^present in|^See /etc|^$')
  if [ -z "$out" ]; then echo "OK   | $1"; else echo "FAIL | $1 ==> $(echo "$out" | head -1)"; fi
}
try "pass in quick on utun5 route-to ($XV $ADDR) from 10.66.200.0/24 to any"
[ -n "$PEER" ] && try "pass in quick on utun5 route-to ($XV $PEER) from 10.66.200.0/24 to any"
try "pass in quick on utun5 route-to ($XV 172.21.0.1) from 10.66.200.0/24 to any"
try "nat on $XV inet from 10.66.200.0/24 to any -> ($XV)"
try "scrub in on utun5 inet from 10.66.200.0/24 to any max-mss 1360
scrub in on $XV inet from any to 10.66.200.0/24 max-mss 1360
nat on $XV inet from 10.66.200.0/24 to any -> ($XV)
pass in quick on utun5 route-to ($XV 172.21.0.1) from 10.66.200.0/24 to any"
chmod 644 "$LOG"; chown bala:staff "$LOG"
