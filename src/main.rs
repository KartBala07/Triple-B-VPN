//! HermesVPN — a from-scratch, dependency-free encrypted VPN for macOS.
//!
//! Usage:
//!   hvpn keygen [-o file]                      generate a 256-bit pre-shared key
//!   hvpn selftest                              crypto + protocol test vectors
//!   hvpn serve  --key F [--listen A:P] [--tun-ip IP] [--subnet IP] [--nat IF] [-v]
//!   hvpn up     --key F --peer H:P [--tun-ip IP] [--subnet IP] [--default] [-v]
//!   hvpn down | status

mod crypto;
mod daemon;
mod netcfg;
mod proto;
mod tun;
mod tunnel;

use std::process::exit;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use proto::{parse_ipv4, show_ipv4};

static VERBOSE: AtomicBool = AtomicBool::new(false);

pub fn verbose() -> bool {
    VERBOSE.load(Ordering::Relaxed)
}

fn stamp() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!(
        "{:02}:{:02}:{:02}Z",
        (secs / 3600) % 24,
        (secs / 60) % 60,
        secs % 60
    )
}

pub fn logw(msg: &str) {
    println!("[{}] hvpn: {}", stamp(), msg);
    use std::io::Write;
    let _ = std::io::stdout().flush();
}

fn flag(args: &[String], name: &str) -> Option<String> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1).cloned())
}

fn has(args: &[String], name: &str) -> bool {
    args.iter().any(|a| a == name)
}

/// Collect every value given for a repeatable flag (e.g. --route a --route b).
fn flags(args: &[String], name: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < args.len() {
        if args[i] == name {
            if let Some(v) = args.get(i + 1) {
                out.push(v.clone());
            }
        }
        i += 1;
    }
    out
}

fn need_root(what: &str) {
    if !netcfg::run_as_root_args_check() {
        eprintln!("hvpn: {} needs root (utun + routes).", what);
        eprintln!("      run:  sudo hvpn ...");
        exit(1);
    }
}

fn load_key(path: &str) -> [u8; 32] {
    let raw = match std::fs::read(path) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("hvpn: cannot read key {}: {}", path, e);
            exit(1);
        }
    };
    let mut key = [0u8; 32];
    if raw.len() == 32 {
        key.copy_from_slice(&raw);
        return key;
    }
    let text = String::from_utf8_lossy(&raw);
    let hex: String = text.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if hex.len() != 64 {
        eprintln!("hvpn: key file {} must hold 32 raw bytes or 64 hex chars", path);
        exit(1);
    }
    let bytes = crypto::hex_decode(&hex).unwrap();
    key.copy_from_slice(&bytes);
    key
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        usage();
        exit(2);
    }
    if has(&args, "-v") || has(&args, "--verbose") {
        VERBOSE.store(true, Ordering::Relaxed);
    }
    let rest = &args[2..];
    match args[1].as_str() {
        "selftest" => {
            let bad = selftest();
            exit(if bad == 0 { 0 } else { 1 });
        }
        "keygen" => keygen(rest),
        "up" => up(rest),
        "serve" => serve(rest),
        "down" => down(),
        "daemon" => {
            let sock = flag(rest, "--socket").unwrap_or_else(|| daemon::DEFAULT_SOCKET.to_string());
            if let Err(e) = daemon::run_daemon(&sock) {
                eprintln!("hvpn: daemon error: {}", e);
                exit(1);
            }
        }
        "status" => status(),
        "help" | "-h" | "--help" => usage(),
        other => {
            eprintln!("hvpn: unknown command '{}'", other);
            usage();
            exit(2);
        }
    }
}

fn usage() {
    println!(
        "HermesVPN 1.0 — encrypted point-to-point VPN (macOS)\n\
         \n\
         \x20 hvpn keygen [-o FILE]        generate a 256-bit pre-shared key\n\
         \x20 hvpn selftest                run crypto + protocol test vectors\n\
         \x20 hvpn serve --key F [opts]    run the exit node (needs root)\n\
         \x20 hvpn up --key F --peer H:P   connect a client (needs root)\n\
         \x20 hvpn down                    tear down routes/NAT from state files\n\
         \x20 hvpn daemon [--socket S]     privileged control daemon (GUI/CLI driver)\n\
         \x20 hvpn status                  show tunnel state\n\
         \n\
         serve options: --listen A:P (default 0.0.0.0:51820), --tun-ip 10.66.0.1,\n\
         \x20              --subnet 10.66.0.0, --nat auto|IF (repeatable), --peer-nat BASE,\n\
         \x20              --egress auto|IF[@GW] (policy-route forwarded traffic),\n\
         \x20              --mtu 1400, -v\n\
         up options:    --peer H:P (required), --tun-ip 10.66.0.2, --default,\n\
         \x20              --route CIDR (repeatable, split tunnel), --force-default,\n\
         \x20              --subnet 10.66.0.0, --mtu 1400, -v"
    );
}

// ------------------------------------------------------------------ keygen

fn keygen(args: &[String]) {
    use std::io::Read;
    let mut k = [0u8; 32];
    let mut f = std::fs::File::open("/dev/urandom").expect("/dev/urandom");
    f.read_exact(&mut k).expect("urandom");
    let hex = crypto::hex_encode(&k);
    match flag(args, "-o").or_else(|| flag(args, "--out")) {
        Some(path) => {
            std::fs::write(&path, format!("{}\n", hex)).expect("write key");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
            }
            println!("wrote 256-bit key to {}", path);
        }
        None => println!("{}", hex),
    }
}

// ------------------------------------------------------------------ serve / up

fn common_cfg(args: &[String]) -> tunnel::CommonCfg {
    let key_path = match flag(args, "--key") {
        Some(k) => k,
        None => {
            eprintln!("hvpn: --key FILE is required");
            exit(2);
        }
    };
    let tun_ip = match flag(args, "--tun-ip") {
        Some(s) => parse_ipv4(&s).unwrap_or_else(|| {
            eprintln!("hvpn: bad --tun-ip {}", s);
            exit(2);
        }),
        None => [10, 66, 0, 2],
    };
    let subnet = match flag(args, "--subnet") {
        Some(s) => parse_ipv4(&s).unwrap_or_else(|| {
            eprintln!("hvpn: bad --subnet {}", s);
            exit(2);
        }),
        None => [10, 66, 0, 0],
    };
    let mtu = flag(args, "--mtu")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(1400);
    tunnel::CommonCfg { key: load_key(&key_path), tun_ip, subnet, mtu }
}

fn serve(args: &[String]) {
    need_root("serve");
    let mut cfg = common_cfg(args);
    if flag(args, "--tun-ip").is_none() {
        cfg.tun_ip = [10, 66, 0, 1];
    }
    let listen = match flag(args, "--listen") {
        Some(s) => s.parse().unwrap_or_else(|_| {
            eprintln!("hvpn: bad --listen {}", s);
            exit(2);
        }),
        None => "0.0.0.0:51820".parse().unwrap(),
    };
    let mut nat_ifs: Vec<String> = Vec::new();
    for v in flags(args, "--nat") {
        if v == "auto" {
            for cand in [netcfg::default_iface(), netcfg::physical_iface()].into_iter().flatten() {
                if !nat_ifs.contains(&cand) {
                    nat_ifs.push(cand);
                }
            }
        } else if !nat_ifs.contains(&v) {
            nat_ifs.push(v);
        }
    }
    let peer_nat = flag(args, "--peer-nat").map(|s| {
        let mut ip = parse_ipv4(&s).unwrap_or_else(|| {
            eprintln!("hvpn: bad --peer-nat {}", s);
            exit(2);
        });
        ip[3] = 0;
        ip
    });
    // --egress IF[@GW] | --egress auto : policy-route forwarded traffic out of a
    // specific interface instead of trusting the host routing table.
    let egress = flag(args, "--egress").map(|s| {
        let base = if s == "auto" {
            netcfg::physical_iface().or_else(netcfg::default_iface).unwrap_or_else(|| "en0".to_string())
        } else {
            s.split('@').next().unwrap_or(&s).to_string()
        };
        let explicit_gw = s.split_once('@').and_then(|(_, g)| {
            if g.is_empty() {
                None
            } else {
                Some(g.to_string())
            }
        });
        let gw = explicit_gw.or_else(|| netcfg::iface_router(&base));
        (base, gw)
    });
    let scfg = tunnel::ServerCfg { common: cfg, listen, nat_ifs, egress, peer_nat };
    if let Err(e) = tunnel::run_server(scfg) {
        eprintln!("hvpn: server error: {}", e);
        exit(1);
    }
}

fn up(args: &[String]) {
    need_root("up");
    let peer_s = match flag(args, "--peer") {
        Some(p) => p,
        None => {
            eprintln!("hvpn: --peer HOST:PORT is required");
            exit(2);
        }
    };
    let peer = peer_s.parse().unwrap_or_else(|_| {
        eprintln!("hvpn: bad --peer {}", peer_s);
        exit(2);
    });
    let cfg = tunnel::ClientCfg {
        common: common_cfg(args),
        peer,
        default_route: has(args, "--default"),
        force_default: has(args, "--force-default"),
        routes: flags(args, "--route"),
    };
    if let Err(e) = tunnel::run_client(cfg) {
        eprintln!("hvpn: client error: {}", e);
        exit(1);
    }
}

// ------------------------------------------------------------------ down / status

fn down() {
    let mut did = false;

    // client
    let cs = netcfg::load_state("client");
    if let Some(tun) = netcfg::state_get(&cs, "tun") {
        let routes = netcfg::state_get(&cs, "routes").unwrap_or_default();
        for net in routes.split(',').filter(|s| !s.is_empty()) {
            netcfg::del_route_net(net, &tun);
            logw(&format!("removed route {}", net));
            did = true;
        }
        if let Some(b) = netcfg::state_get(&cs, "peer_bypass") {
            if let Some((ip, gw)) = b.split_once(" via ") {
                netcfg::del_route_host(ip.trim(), gw.trim());
                logw(&format!("removed bypass route {}", b));
                did = true;
            }
        }
        if let Some(pid) = netcfg::state_get(&cs, "pid").and_then(|p| p.parse::<u32>().ok()) {
            netcfg::pid_kill(pid);
        }
        netcfg::clear_state("client");
    }

    // server
    let ss = netcfg::load_state("server");
    if let Some(tun) = netcfg::state_get(&ss, "tun") {
        let subnet = netcfg::state_get(&ss, "tun_ip")
            .and_then(|ip| parse_ipv4(&ip))
            .map(|ip| format!("{}.{}.{}.0/24", ip[0], ip[1], ip[2]))
            .unwrap_or_else(|| "10.66.0.0/24".to_string());
        netcfg::del_route_net(&subnet, &tun);
        if netcfg::state_get(&ss, "pf_on").as_deref() == Some("true") {
            let was = netcfg::state_get(&ss, "pf_was").as_deref() == Some("true");
            netcfg::pf_down(was);
            logw("NAT rules removed, pf restored");
            did = true;
        }
        if let Some(fwd) = netcfg::state_get(&ss, "fwd_was") {
            netcfg::forwarding_set(&fwd);
        }
        if let Some(pid) = netcfg::state_get(&ss, "pid").and_then(|p| p.parse::<u32>().ok()) {
            netcfg::pid_kill(pid);
        }
        netcfg::clear_state("server");
    }

    if !did {
        logw("nothing to tear down");
    }
}

fn status() {
    for kind in ["server", "client"] {
        let kv = netcfg::load_state(kind);
        if kv.is_empty() {
            println!("{}: not running (no state file)", kind);
            continue;
        }
        println!("{}:", kind);
        for (k, v) in kv.iter() {
            if k == "pid" {
                if let Ok(pid) = v.parse::<u32>() {
                    println!("  pid        {} ({})", v, if netcfg::pid_alive(pid) { "alive" } else { "dead" });
                    continue;
                }
            }
            println!("  {:<10} {}", k, v);
        }
        if let Some(tun) = netcfg::state_get(&kv, "tun") {
            let (code, out, _) = netcfg::run(&["ifconfig", &tun]).unwrap_or((1, String::new(), String::new()));
            if code == 0 {
                for line in out.lines() {
                    if line.contains("inet ") || line.contains("flags=") {
                        println!("  {}: {}", tun, line.trim());
                    }
                }
            }
        }
    }
    if let Some(gw) = netcfg::default_gateway() {
        println!("default gateway: {}", gw);
    }
    let (code, out, _) = netcfg::run(&["route", "-n", "get", "1.1.1.1"]).unwrap_or((1, String::new(), String::new()));
    if code == 0 {
        for line in out.lines() {
            if line.contains("interface:") || line.contains("gateway:") {
                println!("route to 1.1.1.1: {}", line.trim());
            }
        }
    }
    println!("public IP: {}", netcfg::run(&["sh", "-c", "curl -s --max-time 6 https://api.ipify.org"]).map(|(_, o, _)| o).unwrap_or_default());
}

// ------------------------------------------------------------------ selftest

fn selftest() -> usize {
    let mut fails = 0usize;
    macro_rules! check {
        ($name:expr, $got:expr, $want:expr) => {{
            let got: String = $got;
            let want: String = $want.to_string();
            let ok = got == want;
            println!("{} {}: {}", if ok { "PASS" } else { "FAIL" }, $name, got);
            if !ok {
                println!("     want: {}", want);
                fails += 1;
            }
        }};
    }
    macro_rules! assertc {
        ($name:expr, $cond:expr) => {{
            let ok = $cond;
            println!("{} {}", if ok { "PASS" } else { "FAIL" }, $name);
            if !ok {
                fails += 1;
            }
        }};
    }

    // ---- crypto KATs
    check!(
        "sha256(\"abc\")",
        crypto::hex_encode(&crypto::sha256(b"abc")),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    check!(
        "sha256(\"\")",
        crypto::hex_encode(&crypto::sha256(b"")),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    check!(
        "hmac-sha256 rfc4231#1",
        crypto::hex_encode(&crypto::hmac_sha256(&[0x0bu8; 20], b"Hi There")),
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
    );
    let ikm = [0x0bu8; 22];
    let salt: Vec<u8> = (0u8..=12).collect();
    let info: Vec<u8> = (0xf0u8..=0xf9).collect();
    let mut okm = [0u8; 42];
    crypto::hkdf_sha256(&salt, &ikm, &info, &mut okm);
    check!(
        "hkdf-sha256 rfc5869#1",
        crypto::hex_encode(&okm),
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
    );
    let mut key = [0u8; 32];
    for i in 0..32 {
        key[i] = i as u8;
    }
    let nonce12: [u8; 12] = [0, 0, 0, 9, 0, 0, 0, 0x4a, 0, 0, 0, 0];
    check!(
        "chacha20 block rfc8439",
        crypto::hex_encode(&crypto::chacha20_block(&key, &nonce12, 1)[..16]),
        "10f1e7e4d13b5915500fdd1fa32071c4"
    );
    let pkey = crypto::hex_decode("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b").unwrap();
    check!(
        "poly1305 rfc8439",
        crypto::hex_encode(&crypto::poly1305(&pkey, b"Cryptographic Forum Research Group")),
        "a8061dc1305136c6c22b8baf0c0127a9"
    );
    let akey: [u8; 32] = crypto::hex_decode("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
        .unwrap()
        .try_into()
        .unwrap();
    let anonce: [u8; 12] = crypto::hex_decode("070000004041424344454647").unwrap().try_into().unwrap();
    let aad = crypto::hex_decode("50515253c0c1c2c3c4c5c6c7").unwrap();
    let pt = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    let sealed = crypto::aead_seal(&akey, &anonce, &aad, pt);
    check!(
        "aead tag rfc8439",
        crypto::hex_encode(&sealed[sealed.len() - 16..]),
        "1ae10b594f09e26a7e902ecbd0600691"
    );

    // ---- protocol
    let psk = [0x42u8; 32];
    let cnonce = [0x11u8; 32];
    let req = proto::build_req(&psk, [10, 66, 0, 2], &cnonce);
    let parsed = proto::parse_req(&psk, &req);
    assertc!("handshake request parses + authenticates", parsed.is_some());
    if let Some((ip, cn)) = parsed {
        assertc!("handshake carries client IP", ip == [10, 66, 0, 2]);
        assertc!("handshake carries client nonce", cn == cnonce);
        let snonce = [0x22u8; 32];
        let resp = proto::build_resp(&psk, ip, &cn, &snonce);
        let pr = proto::parse_resp(&psk, &resp, &cnonce);
        assertc!("handshake response parses + authenticates", pr.is_some());
        let other = proto::derive(&psk, &cnonce, &snonce);
        if let Some((_, sn)) = pr {
            let cli = proto::derive(&psk, &cnonce, &sn);
            assertc!("both ends derive identical keys", cli.k_c2s == other.k_c2s && cli.k_s2c == other.k_s2c);
            assertc!("session ids match", cli.sid == other.sid);

            let payload = [0x45u8; 1200];
            let wire = proto::seal_data(&cli.k_c2s, &cli.sid, 0, 7, &payload);
            assertc!("data packet is longer than payload (header+tag)", wire.len() == payload.len() + proto::DATA_HDR + 16);
            let opened = proto::open_data(&other.k_c2s, 0, &wire);
            match opened {
                Some((sid, ctr, pt)) => {
                    assertc!("data decrypts to original payload", pt == payload.to_vec());
                    assertc!("session id round-trips", sid == other.sid);
                    assertc!("counter round-trips", ctr == 7);
                }
                None => {
                    println!("FAIL data packet did not authenticate");
                    fails += 1;
                }
            }
            assertc!("wrong direction key is rejected", proto::open_data(&other.k_s2c, 0, &wire).is_none());
            let mut tampered = wire.clone();
            let last = tampered.len() - 1;
            tampered[last] ^= 0x01;
            assertc!("tampered packet is rejected", proto::open_data(&other.k_c2s, 0, &tampered).is_none());
            let mut flipped = wire.clone();
            flipped[40] ^= 0x80;
            assertc!("bit-flipped ciphertext is rejected", proto::open_data(&other.k_c2s, 0, &flipped).is_none());
            let mut badreq = req.clone();
            badreq[30] ^= 0xff;
            assertc!("forged handshake is rejected", proto::parse_req(&psk, &badreq).is_none());
        }
        let wrong_psk = [0x43u8; 32];
        assertc!("wrong PSK cannot authenticate handshake", proto::parse_req(&wrong_psk, &req).is_none());
    }

    // replay window
    let mut rw = proto::ReplayWindow::new();
    assertc!("replay: first packet accepted", rw.check_and_mark(100));
    assertc!("replay: duplicate rejected", !rw.check_and_mark(100));
    assertc!("replay: in-window new packet accepted", rw.check_and_mark(99));
    assertc!("replay: jump forward accepted", rw.check_and_mark(1000));
    assertc!("replay: too-old packet rejected", !rw.check_and_mark(800));
    assertc!("replay: recent after jump accepted", rw.check_and_mark(980));
    assertc!("replay: duplicate after jump rejected", !rw.check_and_mark(980));

    // ipv4 helpers
    let pkt = {
        let mut v = vec![0u8; 20];
        v[0] = 0x45;
        v[12..16].copy_from_slice(&[10, 66, 0, 2]);
        v[16..20].copy_from_slice(&[1, 1, 1, 1]);
        v
    };
    assertc!("ipv4 dst parse", proto::ipv4_dst(&pkt) == Some([1, 1, 1, 1]));
    assertc!("ipv4 src parse", proto::ipv4_src(&pkt) == Some([10, 66, 0, 2]));
    assertc!("ipv4 string round-trip", show_ipv4(&[10, 66, 0, 2]) == "10.66.0.2");

    // ---- source NAT keeps IPv4 + UDP checksums valid
    let mut p = vec![0u8; 20 + 8 + 12];
    p[0] = 0x45;
    let plen = p.len() as u16;
    p[2..4].copy_from_slice(&plen.to_be_bytes());
    p[8] = 64;
    p[9] = 17;
    p[12..16].copy_from_slice(&[10, 66, 0, 2]);
    p[16..20].copy_from_slice(&[1, 1, 1, 1]);
    p[20..22].copy_from_slice(&32000u16.to_be_bytes());
    p[22..24].copy_from_slice(&53u16.to_be_bytes());
    p[24..26].copy_from_slice(&20u16.to_be_bytes());
    for b in p[28..].iter_mut() {
        *b = 0xab;
    }
    fn fold16(mut s: u32) -> u16 {
        while s >> 16 != 0 {
            s = (s & 0xffff) + (s >> 16);
        }
        !(s as u16)
    }
    // ip header checksum
    let mut s = 0u32;
    for i in (0..20).step_by(2) {
        s += u16::from_be_bytes([p[i], p[i + 1]]) as u32;
    }
    let ipc = fold16(s);
    p[10..12].copy_from_slice(&ipc.to_be_bytes());
    // udp checksum over pseudo-header + segment
    let mut s = 0u32;
    s += u16::from_be_bytes([p[12], p[13]]) as u32;
    s += u16::from_be_bytes([p[14], p[15]]) as u32;
    s += u16::from_be_bytes([p[16], p[17]]) as u32;
    s += u16::from_be_bytes([p[18], p[19]]) as u32;
    s += 17;
    s += 20;
    let mut i = 20;
    while i < p.len() {
        s += u16::from_be_bytes([p[i], p[i + 1]]) as u32;
        i += 2;
    }
    let udpc = fold16(s);
    p[26..28].copy_from_slice(&udpc.to_be_bytes());

    assertc!("crafted packet: ip checksum valid", proto::ipv4_checksum_ok(&p));
    assertc!("crafted packet: udp checksum valid", proto::transport_checksum_ok(&p));
    let before = p.clone();
    assertc!("rewrite src ok", proto::ipv4_rewrite_src(&mut p, [10, 66, 200, 2]));
    assertc!("src address changed", proto::ipv4_src(&p) == Some([10, 66, 200, 2]));
    assertc!("ip checksum still valid after SNAT", proto::ipv4_checksum_ok(&p));
    assertc!("udp checksum still valid after SNAT", proto::transport_checksum_ok(&p));
    assertc!("payload untouched by SNAT", p[28..] == before[28..]);
    assertc!("rewrite dst ok", proto::ipv4_rewrite_dst(&mut p, [10, 66, 0, 2]));
    assertc!("dst address changed", proto::ipv4_dst(&p) == Some([10, 66, 0, 2]));
    assertc!("ip checksum valid after DNAT", proto::ipv4_checksum_ok(&p));
    assertc!("udp checksum valid after DNAT", proto::transport_checksum_ok(&p));
    // Incremental checksum arithmetic can legitimately land on the other
    // representation of zero (0x0000 vs 0xffff), so compare accordingly.
    let zeroish = |a: &[u8], b: &[u8]| {
        a == b
            || (a.iter().all(|&x| x == 0) && b.iter().all(|&x| x == 0xff))
            || (a.iter().all(|&x| x == 0xff) && b.iter().all(|&x| x == 0))
    };
    assertc!("rewrite src back", proto::ipv4_rewrite_src(&mut p, [10, 66, 0, 2]));
    assertc!("rewrite dst back", proto::ipv4_rewrite_dst(&mut p, [1, 1, 1, 1]));
    assertc!("ip checksum valid after full restore", proto::ipv4_checksum_ok(&p));
    assertc!("udp checksum valid after full restore", proto::transport_checksum_ok(&p));
    assertc!(
        "round-trip rewrite restores addresses, payload and checksums",
        proto::ipv4_src(&p) == proto::ipv4_src(&before)
            && proto::ipv4_dst(&p) == proto::ipv4_dst(&before)
            && p[28..] == before[28..]
            && zeroish(&p[10..12], &before[10..12])
            && zeroish(&p[26..28], &before[26..28])
    );

    println!("\n{} failure(s)", fails);
    fails
}
