# HermesVPN (hvpn)

A working point-to-point VPN for macOS, written from scratch in Rust with **zero
dependencies** — no OpenSSL, no WireGuard, no crates. One binary does both ends.

- **Crypto**: ChaCha20-Poly1305 (RFC 8439) with SHA-256 / HMAC / HKDF (RFC 5869),
  implemented here and checked against the official test vectors (`hvpn selftest`).
  Keys are derived per session from a 256-bit pre-shared key plus two ephemeral
  32-byte nonces, so the wire key never equals the PSK and every session is
  keyed differently.
- **Handshake**: PSK-authenticated request/response with a ±5 min timestamp window
  and a challenge nonce, so a captured handshake cannot be replayed.
- **Data path**: every packet is AEAD-sealed with a per-direction key and a
  64-bit counter; a 128-packet sliding replay window drops duplicates.
- **Tunnel**: real `utun` interface (root), 1400 MTU, split tunnel (`--route CIDR`)
  or full tunnel (`--default`), with a guard that refuses to stack a full tunnel
  on top of an existing one.
- **Exit node**: decapsulates, 1:1 source-NATs each peer into `10.66.200.0/24`,
  masquerades onto the uplink with pf, clamps MSS, and policy-routes forwarded
  traffic (`route-to`) so it still works when the host's own default route is
  another VPN.

## Quick start

Build once:

```bash
cd ~/HermesVPN && cargo build --release
```

### Same Mac (demo / smoke test)

```bash
sudo bash test/e2e.sh        # 30 checks: routing, crypto, NAT, teardown
```

### Real use — this Mac as the client, another machine as the exit node

On the exit node (a Mac with a public or LAN address):

```bash
bin/hvpnctl key                    # writes /var/run/hvpn/psk, prints it
bin/hvpnctl node                   # serves on 0.0.0.0:51820, NATs to the internet
```

Copy `/var/run/hvpn/psk` to this Mac, then:

```bash
bin/hvpnctl up --peer <node-ip> --full      # everything through the tunnel
bin/hvpnctl up --peer <node-ip> --route 10.0.0.0/8   # split tunnel
bin/hvpnctl status
sudo bin/hvpnctl down
```

`hvpnctl` re-execs itself under sudo, so you only authenticate once per command.

## Desktop app (menu bar)

A real SwiftUI app drives the tunnel through a privileged helper, so macOS only
asks for a password once (at install time), never per connection.

```bash
cargo build --release
./build-app.sh                        # builds build/HermesVPN.app (swiftc, no Xcode project)
sudo /usr/bin/python3 install-app.py  # helper daemon + /Applications/HermesVPN.app
open /Applications/HermesVPN.app
```

What's in the window:

- **Connect / Disconnect** — one button, ↩ also works. Connecting to a loopback
  peer with no exit node running starts the node automatically.
- **Live stats** — received / sent bytes, packet count, uptime, session id.
- **Peer + Mode** — `host:port`, full tunnel or split tunnel with a CIDR list.
- **Exit node** — turns this Mac into an exit node and shows the address to give
  other devices.
- **Key** — PSK fingerprint, Copy (whole 64-char key to the clipboard), New.
- **Recent tunnel log** — last lines of the active end's log.
- Menu-bar item colours by state (green connected, blue exit node, grey idle)
  with a right-click menu for connect / exit node / copy key / quit.

### How the privilege split works

```
HermesVPN.app  ── unix socket (/var/run/hvpn/control.sock, 0660 root:staff,
   (your user)     peer uid checked) ──▶  hvpn daemon (launchd, root)
                                              ├── hvpn serve   (utun, pf NAT)
                                              └── hvpn up      (utun, routes)
```

The app never runs as root and needs no entitlements; the daemon is the only
privileged part, starts at boot, and launchd restarts it if it dies. The daemon
also watches the uplink address/gateway and rebuilds the NAT + policy route when
you change networks, which is what keeps the tunnel working while roaming.

## Commands

```
hvpnctl key [--new]                          show / regenerate the shared key
hvpnctl node [--listen ADDR:PORT] [--no-internet]   run the exit node
hvpnctl up --peer HOST[:PORT] [--full|--route CIDR]...   connect as a client
hvpnctl down | status | selftest | doctor
```

Raw binary, if you prefer:

```
hvpn keygen [-o FILE]                      256-bit key
hvpn selftest                              crypto + protocol vectors
hvpn serve --key F [--listen A:P] [--tun-ip 10.66.0.1] [--nat auto|IF]...
           [--egress auto|IF[@GW]] [--peer-nat 10.66.200.0] [--mtu 1400] [-v]
hvpn up    --key F --peer H:P [--tun-ip 10.66.0.2] [--default] [--route CIDR]... [-v]
hvpn down | status
```

State lives in `/var/run/hvpn/` (`psk`, `client.state`, `server.state`, logs).

## What the end-to-end test actually proves

`test/e2e.sh` (run as root, restores all host networking on exit):

| Check | What it shows |
|---|---|
| handshake / session id / wrong-PSK rejected | only the holder of the key gets a session |
| ICMP, DNS, HTTP, HTTPS, 500 KB bulk TCP to `1.1.1.1` | real internet traffic crosses the tunnel |
| `pf -s state` / NAT + `route-to` rules | the exit node rewrites and forwards, not the host |
| tcpdump of `udp/51820` | 32 packets on the wire, no plaintext HTTP, no tunnel IPs |
| `kill -STOP` the exit node | traffic dies, and resumes when it resumes — causal, not cached |
| SIGINT teardown | routes, pf NAT, and `ip.forwarding` are all restored |

Last full run: **0 failures** (30 checks).

## Known limits

- macOS only (utun / `ifconfig` / `route` / pf APIs).
- The app is ad-hoc signed, not notarized: fine locally, but sign properly
  before handing the .app to anyone else.
- One session per peer IP; no multi-peer key database, no key rotation yet.
- PSK-only: anyone with the key can join. Treat it like an SSH key.
- Hand-rolled crypto, unaudited. It passes the RFC vectors and the wire is
  demonstrably encrypted, but for hostile-network threat models use WireGuard.
- A macOS full-tunnel client cannot be stacked under an already-active VPN
  (hvpn refuses rather than loop); quit the other VPN first.
