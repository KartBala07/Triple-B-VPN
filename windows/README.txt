Triple B VPN — Windows client (alpha)
=====================================

WHAT THIS IS
  A Windows client for a Triple B VPN exit node. It creates a Wintun adapter,
  opens the same encrypted tunnel the macOS app uses, and routes the traffic
  you select through it. Same protocol, same pre-shared key.

  The exit node must run somewhere else (a Mac with the Triple B VPN app, or
  hvpn serve on macOS). Windows cannot be an exit node yet - that needs NAT
  (WinNAT/ICS) and is not implemented.

  ** This build has never been run on Windows hardware. ** It was compiled
  from the same engine as the verified macOS build, but treat it as an alpha:
  expect rough edges, and `hvpn status` / the log window are there to tell you
  what happened. Reports welcome.

REQUIREMENTS
  Windows 10 or 11, 64-bit. Administrator rights (the adapter is a driver view).
  wintun.dll ships in this folder - keep it next to hvpn.exe.

QUICK START
  1. Copy the exit node's key to psk.txt in this folder (64 hex chars, the same
     key the node uses). The GUI creates a random one if the file is missing.
  2. Start the exit node on the other machine:
        hvpnctl node            (macOS app: turn "Exit node" on)
  3. Run the GUI:
        powershell -ExecutionPolicy Bypass -File .\TripleBVPN.ps1
     Enter the node's address (host:port), pick Full or Split tunnel, Connect.
     Approve the admin prompt.

  Command line, if you prefer:
        hvpn.exe keygen -o psk.txt
        hvpn.exe up --key psk.txt --peer 192.168.1.20:51820 --default
        hvpn.exe up --key psk.txt --peer 192.168.1.20:51820 --route 1.1.1.1/32
        hvpn.exe down
        hvpn.exe status
        hvpn.exe selftest      (crypto/protocol vectors - no admin needed)

WHAT IT DOES
  - Creates a Wintun adapter named "TripleBVPN", address 10.66.0.2/24
  - Handshake: PSK + ephemeral nonces -> per-direction ChaCha20-Poly1305 keys
  - Full tunnel: routes 0.0.0.0/1 + 128.0.0.0/1 through the adapter, and pins
    the peer's /32 to your physical gateway so the tunnel itself does not loop
  - Split tunnel: only the CIDRs you list
  - Ctrl-C (or Disconnect) removes every route it added

KNOWN LIMITS / TROUBLESHOOTING
  - "wintun.dll not found"      -> keep wintun.dll beside hvpn.exe
  - "WintunCreateAdapter failed" -> you are not elevated; rerun as Administrator
  - "handshake failed"           -> wrong key, wrong peer address, or the node
                                   is not listening. UDP 51820 must be reachable
                                   (check the node's firewall).
  - DNS still uses your physical adapter. If you want the tunnel to resolve DNS,
    set the adapter's DNS server manually (e.g. 1.1.1.1) in ncpa.cpl.
  - No kill switch, no auto-start, no tray icon yet; the GUI is a launcher.
  - Window/WSL traffic is not routed (that needs a WFP layer, same as Wintun
    plus a filter driver).
