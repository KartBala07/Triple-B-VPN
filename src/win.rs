//! Windows tunnel stack: Wintun adapter + netsh route management.
//!
//! wintun.dll is loaded at runtime (LoadLibrary), so the .exe ships next to any
//! Wintun build without an import library or MSVC toolchain.
//!
//! Implemented here: the **client** role — connect to an exit node running on
//! macOS and route traffic through it. Being an exit node on Windows needs NAT
//! (WinNAT/ICS) and is not part of this build.

use std::ffi::c_void;
use std::io::Read;
use std::net::{SocketAddr, UdpSocket};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::process::CommandExt;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::crypto;
use crate::proto::{self, ReplayWindow};

const CAPACITY: u32 = 0x40_0000; // 4 MiB rings
const ERROR_NO_MORE_ITEMS: u32 = 259;
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

static STOP: AtomicBool = AtomicBool::new(false);

type Handle = *mut c_void;

extern "system" {
    fn LoadLibraryW(name: *const u16) -> Handle;
    fn GetProcAddress(module: Handle, name: *const u8) -> *mut c_void;
    fn GetLastError() -> u32;
    fn WaitForSingleObject(handle: Handle, ms: u32) -> u32;
    fn SetConsoleCtrlHandler(handler: extern "system" fn(u32) -> i32, add: i32) -> i32;
}

fn wide(s: &str) -> Vec<u16> {
    std::ffi::OsStr::new(s).encode_wide().chain(std::iter::once(0)).collect()
}

fn die(msg: &str) -> ! {
    eprintln!("hvpn: {}", msg);
    std::process::exit(1);
}

extern "system" fn on_ctrl(_ctype: u32) -> i32 {
    STOP.store(true, Ordering::SeqCst);
    1
}

unsafe fn sym<T>(module: Handle, name: &str) -> Result<T, String> {
    let mut buf = name.to_string();
    buf.push('\0');
    let p = GetProcAddress(module, buf.as_ptr());
    if p.is_null() {
        Err(format!("missing export {} (wrong wintun.dll?)", name))
    } else {
        Ok(std::mem::transmute_copy(&p))
    }
}

struct Api {
    create_adapter: unsafe extern "system" fn(*const u16, *const u16, *const u8) -> Handle,
    close_adapter: unsafe extern "system" fn(Handle),
    start_session: unsafe extern "system" fn(Handle, u32) -> Handle,
    end_session: unsafe extern "system" fn(Handle),
    get_read_wait_event: unsafe extern "system" fn(Handle) -> Handle,
    receive_packet: unsafe extern "system" fn(Handle, *mut u32) -> *mut u8,
    release_receive_packet: unsafe extern "system" fn(Handle, *const u8),
    allocate_send_packet: unsafe extern "system" fn(Handle, u32) -> *mut u8,
    send_packet: unsafe extern "system" fn(Handle, *const u8),
}

fn api() -> &'static Api {
    static ONCE: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    let addr = *ONCE.get_or_init(|| unsafe {
        let mut module = LoadLibraryW(wide("wintun.dll").as_ptr());
        if module.is_null() {
            // allow the dll to sit one folder up, e.g. bin\hvpn.exe + ..\wintun.dll
            module = LoadLibraryW(wide("..\\wintun.dll").as_ptr());
        }
        if module.is_null() {
            die("wintun.dll not found — put it next to hvpn.exe (https://www.wintun.net)");
        }
        let a = Box::new(Api {
            create_adapter: sym(module, "WintunCreateAdapter").unwrap_or_else(|e| die(&e)),
            close_adapter: sym(module, "WintunCloseAdapter").unwrap_or_else(|e| die(&e)),
            start_session: sym(module, "WintunStartSession").unwrap_or_else(|e| die(&e)),
            end_session: sym(module, "WintunEndSession").unwrap_or_else(|e| die(&e)),
            get_read_wait_event: sym(module, "WintunGetReadWaitEvent").unwrap_or_else(|e| die(&e)),
            receive_packet: sym(module, "WintunReceivePacket").unwrap_or_else(|e| die(&e)),
            release_receive_packet: sym(module, "WintunReleaseReceivePacket")
                .unwrap_or_else(|e| die(&e)),
            allocate_send_packet: sym(module, "WintunAllocateSendPacket").unwrap_or_else(|e| die(&e)),
            send_packet: sym(module, "WintunSendPacket").unwrap_or_else(|e| die(&e)),
        });
        Box::into_raw(a) as usize
    });
    unsafe { &*(addr as *const Api) }
}

// ------------------------------------------------------------------ adapter

struct Tun {
    adapter: Handle,
    session: Handle,
    wait_event: Handle,
}

// Wintun's session API is documented thread-safe, so the same handles are used
// by the receive loop and the transmit thread.
unsafe impl Send for Tun {}
unsafe impl Sync for Tun {}

impl Tun {
    fn create(name: &str) -> Result<Tun, String> {
        let a = api();
        let adapter = unsafe {
            (a.create_adapter)(wide(name).as_ptr(), wide("TripleB").as_ptr(), std::ptr::null())
        };
        if adapter.is_null() {
            return Err(format!(
                "WintunCreateAdapter failed (err {}) — run this from an elevated prompt",
                unsafe { GetLastError() }
            ));
        }
        let session = unsafe { (a.start_session)(adapter, CAPACITY) };
        if session.is_null() {
            unsafe { (a.close_adapter)(adapter) };
            return Err("WintunStartSession failed".into());
        }
        let wait_event = unsafe { (a.get_read_wait_event)(session) };
        Ok(Tun { adapter, session, wait_event })
    }

    /// Wait up to `ms` for one IP packet.
    fn recv(&self, buf: &mut [u8], ms: u32) -> Option<usize> {
        let a = api();
        unsafe {
            let mut size: u32 = 0;
            let p = (a.receive_packet)(self.session, &mut size);
            if !p.is_null() {
                let n = (size as usize).min(buf.len());
                std::ptr::copy_nonoverlapping(p, buf.as_mut_ptr(), n);
                (a.release_receive_packet)(self.session, p);
                return Some(n);
            }
            if GetLastError() == ERROR_NO_MORE_ITEMS {
                WaitForSingleObject(self.wait_event, ms);
            }
            None
        }
    }

    fn send(&self, pkt: &[u8]) -> bool {
        let a = api();
        unsafe {
            let p = (a.allocate_send_packet)(self.session, pkt.len() as u32);
            if p.is_null() {
                return false;
            }
            std::ptr::copy_nonoverlapping(pkt.as_ptr(), p, pkt.len());
            (a.send_packet)(self.session, p);
            true
        }
    }
}

impl Drop for Tun {
    fn drop(&mut self) {
        let a = api();
        unsafe {
            (a.end_session)(self.session);
            (a.close_adapter)(self.adapter);
        }
    }
}

// -------------------------------------------------------------------- netsh

fn run(cmd: &str, args: &[&str]) -> (i32, String) {
    let mut c = Command::new(cmd);
    c.args(args).creation_flags(CREATE_NO_WINDOW);
    match c.output() {
        Ok(o) => (
            o.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&o.stdout).to_string(),
        ),
        Err(e) => (-1, e.to_string()),
    }
}

fn powershell(script: &str) -> String {
    let (_, out) = run("powershell", &["-NoProfile", "-NonInteractive", "-Command", script]);
    out.trim().to_string()
}

/// (interface alias, next hop) of the current IPv4 default route.
fn default_route() -> Option<(String, String)> {
    let out = powershell(
        "(Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Sort-Object RouteMetric | \
         Select-Object -First 1 | ForEach-Object { \"$($_.InterfaceAlias)|$($_.NextHop)\" })",
    );
    let line = out.lines().next()?.trim().to_string();
    let (a, g) = line.split_once('|')?;
    if a.is_empty() || g.is_empty() {
        return None;
    }
    Some((a.to_string(), g.to_string()))
}

fn set_address(alias: &str, ip: &str) {
    run(
        "netsh",
        &[
            "interface", "ipv4", "set", "address",
            &format!("name={}", alias),
            "static", ip, "255.255.255.0",
        ],
    );
}

fn iface_up(alias: &str) {
    run("netsh", &["interface", "set", "interface", &format!("name={}", alias), "admin=enable"]);
}

fn add_route(prefix: &str, alias: &str, nexthop: Option<&str>) {
    let nh = nexthop.map(|n| format!("nexthop={}", n));
    let name_arg = format!("name={}", alias);
    let mut args = vec!["interface", "ipv4", "add", "route", prefix, name_arg.as_str()];
    if let Some(ref nh) = nh {
        args.push(nh.as_str());
    }
    args.push("metric=1");
    args.push("store=active");
    let (code, out) = run("netsh", &args);
    if code != 0 {
        eprintln!("hvpn: route {} via {} failed: {}", prefix, alias, out.trim());
    }
}

fn del_route(prefix: &str, alias: &str, nexthop: Option<&str>) {
    let nh = nexthop.map(|n| format!("nexthop={}", n));
    let name_arg = format!("name={}", alias);
    let mut args = vec![
        "interface", "ipv4", "delete", "route", prefix, name_arg.as_str(),
    ];
    if let Some(ref nh) = nh {
        args.push(nh.as_str());
    }
    run("netsh", &args);
}

// -------------------------------------------------------------------- state

fn state_path() -> std::path::PathBuf {
    let base = std::env::var("PROGRAMDATA").unwrap_or_else(|_| "C:\\ProgramData".into());
    let dir = std::path::PathBuf::from(base).join("TripleBVPN");
    let _ = std::fs::create_dir_all(&dir);
    dir.join("client.state")
}

fn save_state(lines: &[String]) {
    let _ = std::fs::write(state_path(), lines.join("\r\n"));
}

fn load_key(path: &str) -> [u8; 32] {
    let raw = std::fs::read(path).unwrap_or_else(|e| {
        eprintln!("hvpn: cannot read key {}: {}", path, e);
        std::process::exit(1);
    });
    if raw.len() == 32 {
        let mut k = [0u8; 32];
        k.copy_from_slice(&raw);
        return k;
    }
    let text = String::from_utf8_lossy(&raw);
    let hex: String = text.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if hex.len() != 64 {
        eprintln!("hvpn: key file must hold 32 raw bytes or 64 hex chars");
        std::process::exit(1);
    }
    let bytes = crypto::hex_decode(&hex).unwrap();
    let mut k = [0u8; 32];
    k.copy_from_slice(&bytes);
    k
}

/// System CSPRNG (BCryptGenRandom) with a time/PID xorshift only as last resort.
fn random32() -> [u8; 32] {
    let mut b = [0u8; 32];
    unsafe {
        let m = LoadLibraryW(wide("bcrypt.dll").as_ptr());
        if !m.is_null() {
            if let Ok(f) = sym::<unsafe extern "system" fn(*mut c_void, *mut u8, u32, u32) -> i32>(
                m,
                "BCryptGenRandom",
            ) {
                // BCRYPT_USE_SYSTEM_PREFERRED_RNG
                if f(std::ptr::null_mut(), b.as_mut_ptr(), 32, 0x0000_0002) == 0 {
                    return b;
                }
            }
        }
    }
    let mut x = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0x9E37_79B9)
        ^ ((std::process::id() as u64) << 32);
    for chunk in b.chunks_mut(8) {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        let t = x.to_le_bytes();
        chunk.copy_from_slice(&t[..chunk.len()]);
    }
    b
}

// ----------------------------------------------------------------- commands

fn usage() {
    println!(
        "Triple B VPN — Windows client\n\n\
         \x20 hvpn keygen [-o FILE]        generate a 256-bit pre-shared key\n\
         \x20 hvpn selftest                crypto + protocol vectors\n\
         \x20 hvpn up --key F --peer H:P [--default | --route CIDR]... [-v]\n\
         \x20 hvpn down                    remove the routes up added\n\
         \x20 hvpn status                  show state\n\n\
         Requires: wintun.dll beside hvpn.exe (https://www.wintun.net) and an\n\
         elevated prompt (Run as administrator). Exit-node mode is macOS-only."
    );
}

fn flag(args: &[String], name: &str) -> Option<String> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1).cloned())
}

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

fn keygen(args: &[String]) -> Result<(), String> {
    let hex = crypto::hex_encode(&random32());
    match flag(args, "-o").or_else(|| flag(args, "--out")) {
        Some(p) => {
            std::fs::write(&p, hex + "\r\n").map_err(|e| format!("write {}: {}", p, e))?;
            println!("wrote 256-bit key to {}", p);
        }
        None => println!("{}", hex),
    }
    Ok(())
}

fn up(args: &[String]) -> Result<(), String> {
    let key_path = flag(args, "--key").ok_or("--key FILE is required")?;
    let peer_str = flag(args, "--peer").ok_or("--peer HOST:PORT is required")?;
    let peer: SocketAddr = peer_str.parse().map_err(|_| format!("bad --peer {}", peer_str))?;
    let key = load_key(&key_path);
    let full = args.iter().any(|a| a == "--default");
    let routes = flags(args, "--route");

    let iface = "TripleBVPN";
    println!("hvpn: creating Wintun adapter \"{}\"", iface);
    let tun = Arc::new(Tun::create(iface)?);
    iface_up(iface);
    set_address(iface, "10.66.0.2");
    println!("hvpn: {} = 10.66.0.2/24", iface);

    let sock = UdpSocket::bind("0.0.0.0:0").map_err(|e| e.to_string())?;
    sock.set_read_timeout(Some(Duration::from_millis(250)))
        .map_err(|e| e.to_string())?;
    println!("hvpn: underlay socket {}", sock.local_addr().unwrap_or_else(|_| "?".parse().unwrap()));

    // ---- handshake
    let cnonce = random32();
    let req = proto::build_req(&key, [10, 66, 0, 2], &cnonce);
    let mut keys: Option<proto::Keys> = None;
    let mut rbuf = vec![0u8; 2048];
    'hs: for attempt in 1..=40 {
        let _ = sock.send_to(&req, peer);
        let deadline = Instant::now() + Duration::from_millis(500);
        while Instant::now() < deadline && !STOP.load(Ordering::SeqCst) {
            match sock.recv_from(&mut rbuf) {
                Ok((n, from)) if from == peer => {
                    if let Some((_ip, snonce)) = proto::parse_resp(&key, &rbuf[..n], &cnonce) {
                        keys = Some(proto::derive(&key, &cnonce, &snonce));
                        println!("hvpn: handshake OK after {} attempt(s)", attempt);
                        break 'hs;
                    }
                }
                Ok(_) => {}
                Err(_) => break,
            }
        }
    }
    let keys = keys.ok_or("handshake failed (peer unreachable or wrong key)")?;
    println!("hvpn: session id {}", proto::sid_hex(&keys.sid));

    // ---- routes
    let (uplink, gw) = default_route()
        .ok_or("could not determine the default route — is a network connected?")?;
    println!("hvpn: uplink \"{}\" gateway {}", uplink, gw);
    let mut added: Vec<(String, String, String)> = Vec::new();
    if !peer.ip().is_loopback() {
        add_route(&format!("{}/32", peer.ip()), &uplink, Some(&gw));
        added.push((format!("{}/32", peer.ip()), uplink.clone(), gw.clone()));
        println!("hvpn: pinned peer {} via {}", peer.ip(), gw);
    }
    let mut tunnel_routes: Vec<String> = Vec::new();
    if full {
        tunnel_routes.push("0.0.0.0/1".into());
        tunnel_routes.push("128.0.0.0/1".into());
    }
    tunnel_routes.extend(routes.iter().cloned());
    for r in &tunnel_routes {
        add_route(r, iface, None);
        added.push((r.clone(), iface.to_string(), String::new()));
        println!("hvpn: route {} -> {}", r, iface);
    }
    let mut st = vec![format!("peer={}", peer), format!("tun={}", iface)];
    st.extend(added.iter().map(|(p, a, n)| format!("route={}|{}|{}", p, a, n)));
    save_state(&st);

    // ---- datapath: tun -> wire on a thread, wire -> tun here
    let stop_tx = Arc::new(AtomicBool::new(false));
    let stop_flag = stop_tx.clone();
    let tun_tx = tun.clone();
    let sock_tx = sock.try_clone().map_err(|e| e.to_string())?;
    let (k_up, sid) = (keys.k_c2s, keys.sid);
    let tx = std::thread::spawn(move || {
        let mut buf = vec![0u8; 65536];
        let mut ctr: u64 = 0;
        while !stop_flag.load(Ordering::SeqCst) && !STOP.load(Ordering::SeqCst) {
            if let Some(n) = tun_tx.recv(&mut buf, 200) {
                let wire = proto::seal_data(&k_up, &sid, 0, ctr, &buf[..n]);
                ctr += 1;
                let _ = sock_tx.send_to(&wire, peer);
            }
        }
    });

    let mut rx = ReplayWindow::new();
    let mut last_hb = Instant::now();
    let mut last_rx = Instant::now();
    let mut rx_bytes: u64 = 0;
    let mut tx_ctr: u64 = 0;
    while !STOP.load(Ordering::SeqCst) {
        if let Ok((len, from)) = sock.recv_from(&mut rbuf) {
            if from == peer {
                if let Some((_sid, ctr, pt)) = proto::open_data(&keys.k_s2c, 1, &rbuf[..len]) {
                    if rx.check_and_mark(ctr) && !pt.is_empty() {
                        rx_bytes += pt.len() as u64;
                        last_rx = Instant::now();
                        tun.send(&pt);
                    }
                }
            }
        }
        if last_hb.elapsed() >= Duration::from_secs(10) {
            let wire = proto::seal_data(&keys.k_c2s, &keys.sid, 0, tx_ctr + 1_000_000, &[]);
            let _ = sock.send_to(&wire, peer);
            last_hb = Instant::now();
            println!(
                "hvpn: alive | rx {} B | last rx {}s ago",
                rx_bytes,
                last_rx.elapsed().as_secs()
            );
        }
        tx_ctr = tx_ctr.wrapping_add(0);
    }

    stop_tx.store(true, Ordering::SeqCst);
    let _ = tx.join();
    println!("hvpn: stopping, removing routes");
    let _ = down();
    Ok(())
}

fn down() -> Result<(), String> {
    let text = std::fs::read_to_string(state_path()).unwrap_or_default();
    if text.is_empty() {
        println!("hvpn: nothing to tear down");
        return Ok(());
    }
    for line in text.lines() {
        if let Some(spec) = line.strip_prefix("route=") {
            let parts: Vec<&str> = spec.split('|').collect();
            if parts.len() == 3 {
                let nh = if parts[2].is_empty() { None } else { Some(parts[2]) };
                del_route(parts[0], parts[1], nh);
                println!("hvpn: removed route {}", parts[0]);
            }
        }
    }
    let _ = std::fs::remove_file(state_path());
    Ok(())
}

fn status() {
    let text = std::fs::read_to_string(state_path()).unwrap_or_default();
    if text.is_empty() {
        println!("client: not running (no state file)");
    } else {
        for l in text.lines() {
            println!("  {}", l);
        }
    }
    match default_route() {
        Some((a, g)) => println!("uplink: {} via {}", a, g),
        None => println!("uplink: unknown"),
    }
}

pub fn main_win() {
    unsafe {
        SetConsoleCtrlHandler(on_ctrl, 1);
    }
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        usage();
        std::process::exit(2);
    }
    let rest = &args[2..];
    let r = match args[1].as_str() {
        "keygen" => keygen(rest),
        "up" => up(rest),
        "down" => down(),
        "status" => {
            status();
            Ok(())
        }
        "selftest" => {
            let bad = crate::selftest();
            if bad == 0 {
                Ok(())
            } else {
                Err(format!("{} selftest failure(s)", bad))
            }
        }
        "help" | "-h" | "--help" => {
            usage();
            Ok(())
        }
        other => {
            eprintln!("hvpn: unknown command '{}'", other);
            usage();
            std::process::exit(2);
        }
    };
    if let Err(e) = r {
        eprintln!("hvpn: {}", e);
        std::process::exit(1);
    }
}

// Read is used by load_key/random; keep the import meaningful on all paths.
#[allow(dead_code)]
fn _read_used(mut f: std::fs::File) {
    let mut b = [0u8; 1];
    let _ = f.read(&mut b);
}
