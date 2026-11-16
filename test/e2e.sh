#!/bin/bash
# HermesVPN end-to-end proof. Runs as root (utun + routes + pf).
#
# Topology: the exit node and the client are separate processes joined only by
# the encrypted UDP tunnel on 127.0.0.1:51820. The client routes 1.1.1.1/32 and
# one bulk-transfer host into the tunnel; the exit node decapsulates, source-NATs
# the peer into 10.66.200.0/24, and forwards to the internet with pf masquerading
# plus policy routing (route-to), so a host whose own FIB already points at a
# tunnel still forwards instead of looping.

HERE=/Users/bala/HermesVPN
BIN=$HERE/target/release/hvpn
LAUNCH=$HERE/test/hvpn-launch.sh
LOG=/var/run/hvpn
PCAP=/tmp/hvpn-ciphertext.pcap
PSK=$LOG/psk
FAILS=0
SRV=""
CLI=""

pass() { echo "PASS $*"; }
fail() { echo "FAIL $*"; FAILS=$((FAILS+1)); }
check_eq() { if [ "$2" = "$3" ]; then pass "$1 ($2)"; else fail "$1 (got '$2', want '$3')"; fi; }

cleanup() {
  echo "--- cleanup"
  [ -n "$CLI" ] && kill -INT "$CLI" 2>/dev/null
  [ -n "$SRV" ] && kill -INT "$SRV" 2>/dev/null
  sleep 1.5
  "$BIN" down >/dev/null 2>&1
  pkill -f 'hvpn serve' 2>/dev/null
  pkill -f 'hvpn up' 2>/dev/null
  sleep 0.5
  pfctl -f /etc/pf.conf >/dev/null 2>&1
  echo "--- cleanup done"
}
trap cleanup EXIT

mkdir -p "$LOG"
# Physical uplink = the non-tunnel interface that carries a DHCP router.
PHYS=""
for i in $(ifconfig -l); do
  case "$i" in utun*|lo*|gif*|stf*|awdl*|llw*|bridge*|ap*|anpi*) continue;; esac
  if [ -n "$(ipconfig getoption "$i" router 2>/dev/null)" ]; then PHYS="$i"; break; fi
done
[ -z "$PHYS" ] && PHYS=$(route -n get default | awk '/interface:/{print $2}')
echo "physical uplink: $PHYS (gateway $(ipconfig getoption "$PHYS" router 2>/dev/null))"
UNDERLAY=$(route -n get default | awk '/interface:/{print $2}')
echo "default route iface: $UNDERLAY"
DIRECT_IP=$(curl -4 -s --max-time 10 https://api.ipify.org)
echo "public IP before tunnel: ${DIRECT_IP:-<none>}"

# a real bulk-transfer target, routed into the tunnel by IP
BULK_IP=$(dig +short speed.cloudflare.com A 2>/dev/null | grep -m1 -E '^[0-9]+\.' )
echo "bulk transfer target: speed.cloudflare.com ${BULK_IP:-<unresolved>}"

"$BIN" keygen -o "$PSK" >/dev/null || { echo "keygen failed"; exit 1; }

# ---- guard: full tunnel on top of an existing VPN must be refused
echo "--- guard test: --default when the default route is already a tunnel"
"$BIN" up --key "$PSK" --peer 127.0.0.1:51820 --tun-ip 10.66.0.2 --default > "$LOG/guard.log" 2>&1
GRC=$?
if [ "$GRC" -ne 0 ] && grep -q "refusing --default" "$LOG/guard.log"; then
  pass "refused to stack full tunnels (encapsulation loop avoided)"
else
  fail "guard did not refuse --default (rc=$GRC)"
fi

echo "--- starting exit node"
$LAUNCH "$BIN" serve --key "$PSK" --listen 127.0.0.1:51820 --tun-ip 10.66.0.1 \
      --nat "$PHYS" --egress "$PHYS" --peer-nat 10.66.200.0 -v > "$LOG/server.log" 2>&1 &
SRV=$!
for i in $(seq 1 40); do grep -q "listening on udp" "$LOG/server.log" && break; sleep 0.25; done
grep -q "listening on udp" "$LOG/server.log" && pass "exit node started (pid $SRV)" || fail "exit node did not start"
grep -q "ip forwarding on, NAT" "$LOG/server.log" && pass "NAT rules loaded" || { fail "NAT rule failed"; grep -i "warn" "$LOG/server.log" | head -3; }
grep -q "policy route" "$LOG/server.log" && pass "policy route installed (survives a hijacked FIB)" || fail "policy route missing"
NATN=$(pfctl -s nat 2>/dev/null | grep -c '10.66.200.0/24')
[ "${NATN:-0}" -ge 1 ] && pass "pf masquerade active on $NATN interface(s)" || fail "pf masquerade missing"
pfctl -sr 2>/dev/null | grep -q 'route-to' && pass "pf route-to rule present" || fail "pf route-to rule missing"
pfctl -sa 2>/dev/null | grep -q 'max-mss' && pass "MSS clamped for the tunnel MTU" || fail "no MSS clamping"

echo "--- starting client"
ROUTES=(--route 1.1.1.1/32)
[ -n "$BULK_IP" ] && ROUTES+=(--route "$BULK_IP/32")
$LAUNCH "$BIN" up --key "$PSK" --peer 127.0.0.1:51820 --tun-ip 10.66.0.2 "${ROUTES[@]}" -v > "$LOG/client.log" 2>&1 &
CLI=$!
for i in $(seq 1 80); do grep -q "route 1.1.1.1/32" "$LOG/client.log" && break; sleep 0.25; done

grep -q "handshake OK" "$LOG/client.log" && pass "handshake completed (PSK authenticated)" || { fail "handshake failed"; tail -5 "$LOG/client.log"; }
grep -q "session id" "$LOG/client.log" && pass "session keyed ($(grep -m1 -o 'session id [0-9a-f]*' "$LOG/client.log"))" || fail "no session id"
grep -q "shows as 10.66.200.2" "$LOG/server.log" && pass "peer source-NATed to 10.66.200.2" || fail "peer NAT mapping missing"

CTUN=$(awk -F= '/^tun=/{print $2}' "$LOG/client.state" 2>/dev/null)
STUN=$(awk -F= '/^tun=/{print $2}' "$LOG/server.state" 2>/dev/null)
echo "client $CTUN  server $STUN"

check_eq "client tunnel IP" "$(ifconfig "$CTUN" 2>/dev/null | grep -c 'inet 10.66.0.2')" "1"
check_eq "server tunnel IP" "$(ifconfig "$STUN" 2>/dev/null | grep -c 'inet 10.66.0.1')" "1"
check_eq "1.1.1.1 routed into tunnel" "$(route -n get 1.1.1.1 2>/dev/null | awk '/interface:/{print $2}')" "$CTUN"
check_eq "tunnel MTU 1400 applied" "$(ifconfig "$CTUN" 2>/dev/null | grep -c 'mtu 1400')" "1"

# ---- the actual test: internet traffic through the encrypted tunnel
if ping -c 4 -t 6 1.1.1.1 >/dev/null 2>&1; then
  pass "ICMP 1.1.1.1 through tunnel + NAT"
else
  fail "ICMP 1.1.1.1 through tunnel"
fi

DNS=$(dig @1.1.1.1 +short +time=5 +tries=1 example.com A 2>/dev/null | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | head -1)
[ -n "$DNS" ] && pass "DNS via 1.1.1.1 through tunnel ($DNS)" || fail "DNS via tunnel"

CODE=$(curl -4 -s -o /dev/null -w '%{http_code}' --max-time 20 http://1.1.1.1/)
case "$CODE" in 200|301|302|403) pass "HTTP through tunnel (status $CODE)";; *) fail "HTTP through tunnel (status $CODE)";; esac

HTTPS=$(curl -4 -s -o /dev/null -w '%{http_code} %{size_download}' -L --max-time 25 https://1.1.1.1/cdn-cgi/trace)
set -- $HTTPS
case "$1" in 200) [ "${2:-0}" -gt 40 ] && pass "HTTPS/TLS through tunnel ($1, $2 B)" || fail "HTTPS through tunnel returned $2 B";; *) fail "HTTPS through tunnel (status $1)";; esac

if [ -n "$BULK_IP" ]; then
  BYTES=$(curl -4 -s -o /dev/null -w '%{size_download}' --max-time 60 \
      --resolve "speed.cloudflare.com:443:$BULK_IP" "https://speed.cloudflare.com/__down?bytes=500000")
  [ "${BYTES:-0}" -ge 400000 ] && pass "bulk TCP through tunnel: $BYTES B (large segments OK)" || fail "bulk TCP through tunnel: ${BYTES:-0} B"
fi

# ---- causal proof: freeze the exit node, the same request must fail
kill -STOP $SRV 2>/dev/null
CODE_F=$(curl -4 -s -o /dev/null -w '%{http_code}' --max-time 4 http://1.1.1.1/ 2>/dev/null)
[ "$CODE_F" = "000" ] && pass "traffic dies while the exit node is frozen" || fail "traffic survived a frozen exit node ($CODE_F)"
kill -CONT $SRV 2>/dev/null
sleep 1
CODE_B=$(curl -4 -s -o /dev/null -w '%{http_code}' --max-time 20 http://1.1.1.1/)
case "$CODE_B" in 200|301|302|403) pass "traffic resumes when the exit node resumes ($CODE_B)";; *) fail "no recovery after resume ($CODE_B)";; esac

# ---- ciphertext proof while the above traffic flows
: > "$PCAP"
tcpdump -n -i lo0 -s 0 -w "$PCAP" "udp port 51820" -c 400 >/dev/null 2>&1 &
DUMP=$!
sleep 1
curl -4 -s --max-time 20 -o /dev/null "http://1.1.1.1/"
curl -4 -sL --max-time 20 -o /dev/null "https://1.1.1.1/cdn-cgi/trace"
ping -c 3 -t 5 1.1.1.1 >/dev/null 2>&1
sleep 1
kill -INT $DUMP 2>/dev/null
sleep 0.5
PKTS=$(tcpdump -nr "$PCAP" 2>/dev/null | wc -l | tr -d ' ')
[ "${PKTS:-0}" -gt 5 ] && pass "captured $PKTS packets on the wire" || fail "captured ${PKTS:-0} packets"
if strings -a "$PCAP" | grep -qE "GET /|HTTP/1|cdn-cgi"; then
  fail "plaintext HTTP visible on the wire (NOT encrypted)"
else
  pass "no plaintext HTTP on the wire (payload encrypted)"
fi
if tcpdump -nr "$PCAP" 2>/dev/null | grep -q "10.66.0"; then
  fail "tunnel IPs visible in outer headers"
else
  pass "no tunnel IPs in outer headers (fully encapsulated)"
fi
echo "--- one captured packet (HVPN header + ciphertext):"
tcpdump -nX -r "$PCAP" -c 1 2>/dev/null | head -10

# ---- bidirectional counters
echo "client: $(grep -o 'tx [0-9]* pkts [0-9]* B | rx [0-9]* B' "$LOG/client.log" | tail -1)"
CRXP=$(grep -c "RX #" "$LOG/client.log")
SRXP=$(grep -c "RX #" "$LOG/server.log")
[ "${CRXP:-0}" -gt 0 ] && [ "${SRXP:-0}" -gt 0 ] && pass "both ends decrypted packets (client rx=$CRXP, server rx=$SRXP)" || fail "bidirectional decryption (client=$CRXP server=$SRXP)"

# ---- wrong PSK refused
"$BIN" keygen -o "$LOG/wrong.psk" >/dev/null
$LAUNCH "$BIN" up --key "$LOG/wrong.psk" --peer 127.0.0.1:51820 --tun-ip 10.66.0.9 > "$LOG/wrong.log" 2>&1 &
WR=$!
sleep 23
if grep -q "handshake FAILED" "$LOG/wrong.log"; then pass "client with wrong PSK rejected"; else fail "wrong PSK accepted"; fi
kill -INT $WR 2>/dev/null

# ---- teardown
echo "--- stopping client"
kill -INT $CLI 2>/dev/null
sleep 2
check_eq "1.1.1.1 route restored" "$(route -n get 1.1.1.1 2>/dev/null | awk '/interface:/{print $2}')" "$UNDERLAY"
CODE2=$(curl -4 -s -o /dev/null -w '%{http_code}' --max-time 15 https://example.com)
check_eq "normal internet unaffected after disconnect" "$CODE2" "200"

echo "--- stopping exit node"
kill -INT $SRV 2>/dev/null
sleep 2
check_eq "NAT rule removed" "$(pfctl -s nat 2>/dev/null | grep -c '10.66.200.0/24')" "0"
check_eq "peer-NAT pool route removed" "$(netstat -rn -f inet 2>/dev/null | grep -c '10.66.200')" "0"
check_eq "tunnel subnet route removed" "$(netstat -rn -f inet 2>/dev/null | grep -c '10.66.0.0/24')" "0"
CODE3=$(curl -4 -s -o /dev/null -w '%{http_code}' --max-time 15 https://example.com)
check_eq "internet healthy after full teardown" "$CODE3" "200"
check_eq "ip forwarding restored" "$(sysctl -n net.inet.ip.forwarding)" "0"

echo
echo "================ SUMMARY: $FAILS failure(s) ================"
exit $([ "$FAILS" -eq 0 ] && echo 0 || echo 1)
