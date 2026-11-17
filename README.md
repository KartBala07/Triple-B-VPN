# Triple B VPN

A working point-to-point VPN you can actually install: a menu-bar app for macOS
on top of a from-scratch encrypted tunnel engine written in Rust with **zero
dependencies** — no OpenSSL, no WireGuard, no crates.

**[⬇︎ Download the DMG](https://github.com/KartBala07/Triple-B-VPN/releases/latest)**
· drag to Applications · click *Enable VPN* once · connect.

```
Triple B VPN.app  (your user, no root, no entitlements)
   │  unix socket · 0660 root:staff · peer uid checked
   ▼
hvpn daemon      (launchd, root, starts at boot, auto-restart)
   ├── hvpn serve  → utun + pf NAT + policy route   (exit node)
   └── hvpn up     → utun + routes                  (client)
```

## Install (macOS 13+)

1. Download `TripleB-VPN-1.0.dmg` from [Releases](https://github.com/KartBala07/Triple-B-VPN/releases/latest).
2. Open it, drag **Triple B VPN** into Applications.
3. Launch it → **Enable VPN** → approve the one macOS password prompt. That
   installs the privileged helper; you never see it again.
4. Paste the peer address of the machine running the exit node → **Connect**.

Gatekeeper: the app is signed ad-hoc (no paid Apple Developer ID), so the first
launch needs right-click → **Open**, or:

```bash
xattr -dr com.apple.quarantine "/Applications/Triple B VPN.app"
```

### Two Macs

On the Mac that should be the exit node, open the app and flip **Exit node** on
(it shows `10.0.0.x : 51820`). Press **Copy** next to PSK and send the 64-char
key to the other Mac — both ends need the same key. On the second Mac paste the
peer address, choose **Full tunnel** (everything) or **Split tunnel** with a CIDR
list, then **Connect**.

## What's in the app

- **Connect / Disconnect** with live received / sent bytes, packet count, uptime
  and session id.
- **Peer + Mode** — `host:port`, full tunnel or split tunnel with your own CIDRs.
- **Exit node** switch showing the address to give other devices, plus an
  **Exit via** control: *This Mac* (direct) or *X-VPN* (chain into X-VPN's tunnel).
- **PSK** fingerprint, **Copy** (whole key to clipboard), **New**.
- **Recent tunnel log** — the last lines from whichever end is active.
- Menu-bar glyph that follows the system appearance (template image, so it's
  legible in light *and* dark bars), left-click opens the panel, right-click
  gives connect / exit node / copy key / quit.
- The daemon watches the uplink address + gateway and rebuilds NAT and the
  policy route when you change networks, so the tunnel survives roaming.

## Routing through X-VPN's servers

Triple B VPN can hand its forwarded traffic to another VPN that is already
connected on the same Mac — in practice X-VPN. The exit node then forwards
through X-VPN's tunnel, so traffic that enters Triple B leaves from **X-VPN's
server**, not from this Mac's own uplink.

Pick **Exit via → X-VPN** in the app (or `hvpnctl ... --egress utun4`), then
connect. The daemon finds X-VPN's tunnel automatically (the point-to-point
`utun` carrying `172.21.0.0/16`), MASQs our peer pool onto it and policy-routes
forwarded packets with `route-to (utunN <interface address>)`.

Verified on this Mac with X-VPN connected:

```
route 1.1.1.1 -> utun6                     # our tunnel
ping 1.1.1.1            OK
https://1.1.1.1        200
ip=207.180.52.57  loc=US                   # X-VPN's server, not the ISP
tcpdump -i utun4  172.21.0.1 > 1.1.1.1     # our forwarded packet inside X-VPN
kill -STOP <exit node> -> traffic dies     # causal, not cached
```

What this is and is not:

- It **is** a real double-VPN chain: Triple B (ChaCha20-Poly1305, own PSK) →
  X-VPN (their protocol, their servers). Useful when you want your traffic to
  leave from X-VPN's exit while still using Triple B's app/tunnel on the LAN.
- It is **not** Triple B speaking X-VPN's protocol or using their credentials.
  Their client must be installed, logged in and connected; their service, their
  terms. Traffic still exits through their servers exactly as their own client
  would send it.
- If X-VPN is not connected, the app shows *X-VPN (not running)* and the chain
  command refuses instead of silently falling back to the direct uplink.

## What the engine does

- **Crypto**: ChaCha20-Poly1305 (RFC 8439) with SHA-256 / HMAC / HKDF (RFC 5869),
  implemented here and checked against the official test vectors
  (`hvpn selftest`). Session keys come from the 256-bit PSK plus two ephemeral
  32-byte nonces, so the wire key never equals the PSK.
- **Handshake**: PSK-authenticated request/response with a ±5 min timestamp
  window and a challenge nonce — a captured handshake cannot be replayed.
- **Data path**: every packet AEAD-sealed with a per-direction key and a 64-bit
  counter; a 128-packet sliding replay window drops duplicates.
- **Tunnel**: real `utun` interface, 1400 MTU, split (`--route CIDR`) or full
  (`--default`) tunnel, refusing to stack a full tunnel on an existing one.
- **Exit node**: 1:1 source-NAT per peer into `10.66.200.0/24`, pf masquerade,
  MSS clamp, and `route-to` policy routing so forwarding still works when the
  host's own default route is another VPN.

## Command line

The app is a front-end; the engine and a CLI ship with it.

```bash
hvpnctl key [--new]                               show / regenerate the shared key
hvpnctl node [--listen ADDR:PORT] [--no-internet] run the exit node
hvpnctl up --peer HOST[:PORT] [--full|--route CIDR]...
hvpnctl down | status | selftest | doctor

hvpn daemon [--socket PATH]                       privileged helper (launchd runs this)
hvpn selftest                                     crypto + protocol vectors
```

State lives in `/var/run/hvpn/` (`psk`, `client.state`, `server.state`, logs).

## Build from source

```bash
cargo build --release
./build-app.sh                        # Triple B VPN.app (swiftc, no Xcode project)
./dist-dmg.sh                         # dist/TripleB-VPN-<version>.dmg
sudo /usr/bin/python3 install-app.py  # helper + /Applications (dev convenience)
```

`tools/make-icon.swift` draws the icon with CoreGraphics; `tools/make-icns.sh`
turns it into `AppIcon.icns`. No design files, no external assets.

## Verified, not just compiled

`test/e2e.sh` runs as root and restores all host networking on exit:

| Check | What it shows |
|---|---|
| handshake / wrong-PSK rejected | only the key holder gets a session |
| ICMP, DNS, HTTP, HTTPS, 500 KB bulk TCP | real internet traffic crosses the tunnel |
| `pf -s nat`, `route-to`, `max-mss` | the exit node rewrites and forwards |
| tcpdump on `udp/51820` | no plaintext, no tunnel IPs in outer headers |
| `kill -STOP` the exit node | traffic dies, resumes on `CONT` — causal |
| SIGINT teardown | routes, pf NAT and `ip.forwarding` all restored |

Last full run: **30 checks, 0 failures**. The app flow was verified the same way:
UI click → node + client up, 5 MB bulk transfer, full-tunnel routing with
internet intact, clean teardown.

## Windows (alpha)

**[⬇︎ TripleB-VPN-windows-alpha.zip](https://github.com/KartBala07/Triple-B-VPN/releases)** —
`hvpn.exe` (Wintun client) + `wintun.dll` + a small WinForms launcher +
`README.txt`.

- **Client only.** It creates a Wintun adapter (`TripleBVPN`, 10.66.0.2/24),
  handshakes with an exit node, and routes either everything (`--default`) or
  the CIDRs you list. Same engine, same PSK, same protocol as macOS.
- **Windows cannot be an exit node yet** — that needs NAT (WinNAT/ICS) and is a
  separate piece of work.
- Routes are added with `netsh`, the peer's `/32` is pinned to your physical
  gateway so the tunnel cannot loop, and `hvpn down` / Ctrl-C removes every
  route it added.
- Build it yourself with `./build-windows.sh` (needs
  [llvm-mingw](https://github.com/mstorsjo/llvm-mingw/releases); the script
  pins `x86_64-pc-windows-gnullvm`).

**This build has not been run on Windows hardware.** There is no Windows machine
in this project's environment, so it is compiled and packaged but unverified:
the PE is valid (`PE32+ x86-64`, console), the code is the same engine the macOS
tests exercise, and the Wintun FFI follows the v0.14 header — but the first real
run is yours. `hvpn selftest` (no admin needed) verifies the crypto in one
command, and the launcher shows `hvpn.exe`'s live log so failures are visible.
Shout if anything breaks and it gets fixed against your report.

## Known limits

- macOS is the tested platform; the Windows client is an unverified alpha.
- One session per peer IP; no multi-peer key database, no key rotation.
- PSK-only: anyone with the key can join. Treat it like an SSH key.
- Hand-rolled crypto, unaudited. It passes the RFC vectors and the wire is
  demonstrably encrypted, but if you need an audited stack use WireGuard.
- A full-tunnel client can't be stacked under an already-active VPN — the client
  refuses rather than loop; quit the other VPN first.
- Ad-hoc signed, not notarized: fine for personal use, but a public release
  should get a Developer ID and notarization.
