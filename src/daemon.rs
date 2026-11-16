//! Privileged control daemon: owns the tunnels, serves a local control socket
//! so the GUI (and hvpnctl) can drive the VPN without repeated elevation.
//!
//!   hvpn daemon [--socket /var/run/hvpn/control.sock]
//!
//! The daemon is started by launchd as root. It supervises `hvpn serve` and
//! `hvpn up` child processes and answers line-oriented requests on a Unix
//! socket, accepting only uid 0 and the console user.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::io::AsRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use crate::netcfg;
use crate::{logw, verbose};

pub const DEFAULT_SOCKET: &str = "/var/run/hvpn/control.sock";

static STOP: AtomicBool = AtomicBool::new(false);

extern "C" fn on_sig(_s: i32) {
    STOP.store(true, Ordering::SeqCst);
}

extern "C" {
    fn signal(sig: i32, handler: extern "C" fn(i32)) -> usize;
    fn sigprocmask(how: i32, set: *const u32, old: *mut u32) -> i32;
    fn getsockopt(fd: i32, level: i32, name: i32, val: *mut u8, len: *mut u32) -> i32;
}

const SIG_SETMASK: i32 = 3;
const SOL_LOCAL: i32 = 0;
const LOCAL_PEERCRED: i32 = 0x001;

#[repr(C)]
struct Xucred {
    cr_version: u32,
    cr_uid: u32,
    cr_ngroups: i16,
    cr_groups: [u32; 16],
}

/// launchd spawns daemons with signals blocked; clear the mask so both this
/// process and its children actually receive SIGTERM (teardown depends on it).
fn reset_sigmask() {
    let empty: u32 = 0;
    unsafe {
        sigprocmask(SIG_SETMASK, &empty, std::ptr::null_mut());
    }
}

fn peer_uid(stream: &UnixStream) -> Option<u32> {
    let fd = stream.as_raw_fd();
    let mut cred = Xucred {
        cr_version: 0,
        cr_uid: u32::MAX,
        cr_ngroups: 0,
        cr_groups: [0; 16],
    };
    let mut len = std::mem::size_of::<Xucred>() as u32;
    let rc = unsafe {
        getsockopt(
            fd,
            SOL_LOCAL,
            LOCAL_PEERCRED,
            &mut cred as *mut Xucred as *mut u8,
            &mut len,
        )
    };
    if rc == 0 {
        Some(cred.cr_uid)
    } else {
        None
    }
}

struct Job {
    child: Child,
    started: Instant,
    tun: String,
}

impl Job {
    fn alive(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
    }
    fn stop(&mut self) {
        let _ = self.child.kill(); // SIGKILL the wrapper if TERM was ignored
        let _ = self.child.wait();
    }
}

struct Daemon {
    node: Option<Job>,
    client: Option<Job>,
    bin: String,
    rundir: String,
    key: String,
    /// What the user asked the client to do, so it can be re-established after
    /// a network change: (peer, full_tunnel, routes).
    client_spec: Option<(String, bool, Vec<String>)>,
    /// (iface, ip, router) of the physical uplink; changes mean we must rebuild
    /// the NAT/policy-route ruleset with the new gateway.
    net_fp: String,
    last_net_check: Instant,
}

fn net_fingerprint() -> String {
    let iface = netcfg::physical_iface().unwrap_or_default();
    let ip = netcfg::iface_ipv4(&iface).unwrap_or_default();
    let gw = netcfg::iface_router(&iface).unwrap_or_default();
    format!("{}|{}|{}", iface, ip, gw)
}

fn spawn_logged(bin: &str, args: &[String], log: &str) -> std::io::Result<Child> {
    let f = std::fs::OpenOptions::new().create(true).append(true).open(log)?;
    let err = f.try_clone()?;
    let mut cmd = Command::new(bin);
    cmd.args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::from(f))
        .stderr(Stdio::from(err));
    // clear the inherited signal mask in the child before exec
    unsafe {
        cmd.pre_exec(|| {
            reset_sigmask();
            Ok(())
        });
    }
    cmd.spawn()
}

fn state_get(rundir: &str, kind: &str, key: &str) -> Option<String> {
    let path = format!("{}/{}.state", rundir, kind);
    let s = std::fs::read_to_string(path).ok()?;
    s.lines()
        .find_map(|l| l.split_once('=').filter(|(k, _)| *k == key).map(|(_, v)| v.to_string()))
}

/// Last line of the log if it explains why a process just died.
fn recent_error(path: &str) -> String {
    let s = match std::fs::read_to_string(path) {
        Ok(v) => v,
        Err(_) => return String::new(),
    };
    let lines: Vec<&str> = s.lines().collect();
    let tail = &lines[lines.len().saturating_sub(3)..];
    tail.iter()
        .rev()
        .find(|l| l.contains("error") || l.contains("FAILED"))
        .map(|l| {
            // strip the leading "[HH:MM:SSZ] hvpn: " for display
            match l.find("hvpn: ") {
                Some(i) => l[i + 6..].to_string(),
                None => l.to_string(),
            }
        })
        .unwrap_or_default()
}

fn last_line_containing(path: &str, needle: &str) -> Option<String> {
    let s = std::fs::read_to_string(path).ok()?;
    s.lines().rev().find(|l| l.contains(needle)).map(|l| l.to_string())
}

/// "keepalive | tx 2832 pkts 189962 B | rx 3760 B | last rx 3s ago"
/// -> (packets, tx_bytes, rx_bytes). First occurrence of each token wins, so the
/// trailing "last rx Ns ago" cannot be mistaken for the rx counter.
fn parse_counters(line: &str) -> (u64, u64, u64) {
    let toks: Vec<&str> = line.split_whitespace().collect();
    let mut pkts = 0u64;
    let mut tx = 0u64;
    let mut rx = 0u64;
    for (i, t) in toks.iter().enumerate() {
        let next = toks.get(i + 1).and_then(|s| s.parse::<u64>().ok());
        match *t {
            "tx" if pkts == 0 => pkts = next.unwrap_or(0),
            "pkts" if tx == 0 => tx = next.unwrap_or(0),
            "rx" if rx == 0 => rx = next.unwrap_or(0),
            _ => {}
        }
    }
    (pkts, tx, rx)
}

fn key_hex(rundir: &str) -> Option<String> {
    let s = std::fs::read_to_string(format!("{}/psk", rundir)).ok()?;
    let hex: String = s.trim().chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if hex.len() == 64 {
        Some(hex)
    } else {
        None
    }
}

impl Daemon {
    fn ensure_key(&mut self) -> std::io::Result<()> {
        if key_hex(&self.rundir).is_none() {
            let out = Command::new(&self.bin)
                .args(["keygen", "-o", &self.key])
                .output()?;
            if !out.status.success() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("keygen failed: {}", String::from_utf8_lossy(&out.stderr)),
                ));
            }
            logw("daemon: generated a new 256-bit pre-shared key");
        }
        Ok(())
    }

    fn reap(&mut self) {
        if let Some(j) = self.node.as_mut() {
            if !j.alive() {
                logw("daemon: exit node exited");
                self.node = None;
            }
        }
        if let Some(j) = self.client.as_mut() {
            if !j.alive() {
                logw("daemon: client exited");
                self.client = None;
            }
        }
    }

    fn node_start(&mut self, listen: &str) -> Result<String, String> {
        self.reap();
        if self.node.is_some() {
            return Err("exit node already running".into());
        }
        self.ensure_key().map_err(|e| e.to_string())?;
        let phys = netcfg::physical_iface().unwrap_or_else(|| "en0".to_string());
        let args: Vec<String> = vec![
            "serve".into(),
            "--key".into(),
            self.key.clone(),
            "--listen".into(),
            listen.to_string(),
            "--tun-ip".into(),
            "10.66.0.1".into(),
            "--peer-nat".into(),
            "10.66.200.0".into(),
            "--nat".into(),
            phys.clone(),
            "--egress".into(),
            phys.clone(),
            "-v".into(),
        ];
        let log = format!("{}/node.log", self.rundir);
        let child = spawn_logged(&self.bin, &args, &log).map_err(|e| e.to_string())?;
        let pid = child.id();
        self.node = Some(Job { child, started: Instant::now(), tun: String::new() });
        // give it a moment to create the interface, then report its address
        std::thread::sleep(std::time::Duration::from_millis(900));
        self.reap();
        let tun = state_get(&self.rundir, "server", "tun").unwrap_or_default();
        let ip = netcfg::iface_ipv4(&phys).unwrap_or_else(|| "0.0.0.0".into());
        let port = listen.rsplit(':').next().unwrap_or("51820");
        if let Some(j) = self.node.as_mut() {
            j.tun = tun.clone();
        }
        let _ = verbose();
        logw(&format!("daemon: exit node started pid {} on {}", pid, listen));
        Ok(format!("pid={}\ntun={}\nurl={}:{}", pid, tun, ip, port))
    }

    fn node_stop(&mut self) -> String {
        match self.node.take() {
            Some(mut j) => {
                let pid = j.child.id();
                j.stop();
                // let hvpn's own SIGTERM teardown run first
                std::thread::sleep(std::time::Duration::from_millis(300));
                netcfg::run_quiet(&["/usr/local/bin/hvpn", "down"]);
                logw(&format!("daemon: exit node stopped pid {}", pid));
                format!("pid={}", pid)
            }
            None => "pid=0".into(),
        }
    }

    fn client_start(&mut self, peer: &str, full: bool, routes: &[String]) -> Result<String, String> {
        self.reap();
        if self.client.is_some() {
            return Err("client already running".into());
        }
        self.ensure_key().map_err(|e| e.to_string())?;
        let mut args: Vec<String> = vec![
            "up".into(),
            "--key".into(),
            self.key.clone(),
            "--peer".into(),
            peer.to_string(),
            "--tun-ip".into(),
            "10.66.0.2".into(),
            "-v".into(),
        ];
        if full {
            args.push("--default".into());
        }
        for r in routes {
            if !r.trim().is_empty() {
                args.push("--route".into());
                args.push(r.trim().to_string());
            }
        }
        let log = format!("{}/client.log", self.rundir);
        let before = std::fs::metadata(&log).map(|m| m.len() as usize).unwrap_or(0);
        let child = spawn_logged(&self.bin, &args, &log).map_err(|e| e.to_string())?;
        let pid = child.id();
        self.client = Some(Job { child, started: Instant::now(), tun: String::new() });

        // Report success only once the handshake actually completed: a silent
        // 20-second failure is the worst possible UX for a "Connect" button.
        let deadline = Instant::now() + std::time::Duration::from_millis(4000);
        loop {
            let text = std::fs::read_to_string(&log).unwrap_or_default();
            let fresh = if text.len() > before { &text[before..] } else { "" };
            if fresh.contains("handshake OK") {
                break;
            }
            if !self.client.as_mut().map(|j| j.alive()).unwrap_or(false) {
                self.client = None;
                let why = recent_error(&log);
                return Err(if why.is_empty() {
                    "client exited during handshake".to_string()
                } else {
                    why
                });
            }
            if Instant::now() > deadline {
                let _ = self.client.take().map(|mut j| j.stop());
                return Err(format!(
                    "no handshake from {} — is an exit node listening there?",
                    peer
                ));
            }
            std::thread::sleep(std::time::Duration::from_millis(120));
        }
        self.reap();
        if self.client.is_none() {
            return Err("client exited right after the handshake".to_string());
        }
        let tun = state_get(&self.rundir, "client", "tun").unwrap_or_default();
        if let Some(j) = self.client.as_mut() {
            j.tun = tun.clone();
        }
        self.client_spec = Some((peer.to_string(), full, routes.to_vec()));
        logw(&format!("daemon: client started pid {} -> {}", pid, peer));
        Ok(format!("pid={}\ntun={}", pid, tun))
    }

    fn client_stop(&mut self) -> String {
        self.client_spec = None;
        self.stop_client_inner()
    }

    fn stop_client_inner(&mut self) -> String {
        match self.client.take() {
            Some(mut j) => {
                let pid = j.child.id();
                j.stop();
                std::thread::sleep(std::time::Duration::from_millis(300));
                logw(&format!("daemon: client stopped pid {}", pid));
                format!("pid={}", pid)
            }
            None => "pid=0".into(),
        }
    }

    /// Roaming: if the uplink's address or gateway changed, the pf ruleset still
    /// points at the old gateway (policy route + NAT), so rebuild both tunnels.
    fn check_network(&mut self) {
        if self.last_net_check.elapsed().as_secs() < 4 {
            return;
        }
        self.last_net_check = Instant::now();
        let fp = net_fingerprint();
        if fp == self.net_fp || fp.starts_with("|") {
            return;
        }
        logw(&format!("daemon: uplink changed ({} -> {}), re-establishing", self.net_fp, fp));
        self.net_fp = fp;
        let spec = self.client_spec.clone();
        let had_node = self.node.is_some();
        if spec.is_some() {
            self.stop_client_inner();
        }
        if had_node {
            self.node_stop();
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
        if had_node {
            match self.node_start("0.0.0.0:51820") {
                Ok(_) => logw("daemon: exit node back up on the new network"),
                Err(e) => logw(&format!("daemon: exit node restart failed: {}", e)),
            }
        }
        if let Some((peer, full, routes)) = spec {
            match self.client_start(&peer, full, &routes) {
                Ok(_) => logw("daemon: client reconnected after network change"),
                Err(e) => logw(&format!("daemon: client reconnect failed: {}", e)),
            }
        }
    }

    fn status(&mut self) -> String {
        self.reap();
        let mut o = String::new();
        let keyed = key_hex(&self.rundir).map(|k| k[..8].to_string()).unwrap_or_default();
        o.push_str(&format!("key_fingerprint={}\n", keyed));
        match self.node.as_ref() {
            Some(j) => {
                o.push_str("node=running\n");
                o.push_str(&format!("node_pid={}\n", j.child.id()));
                o.push_str(&format!("node_uptime={}\n", j.started.elapsed().as_secs()));
                o.push_str(&format!(
                    "node_tun={}\n",
                    state_get(&self.rundir, "server", "tun").unwrap_or_default()
                ));
                o.push_str(&format!(
                    "node_listen={}\n",
                    state_get(&self.rundir, "server", "listen").unwrap_or_default()
                ));
                o.push_str(&format!(
                    "node_nat={}\n",
                    state_get(&self.rundir, "server", "nat_ifs").unwrap_or_default()
                ));
                let ip = netcfg::physical_iface()
                    .and_then(|i| netcfg::iface_ipv4(&i))
                    .unwrap_or_default();
                o.push_str(&format!("node_ip={}\n", ip));
            }
            None => o.push_str("node=stopped\n"),
        }
        match self.client.as_ref() {
            Some(j) => {
                let log = format!("{}/client.log", self.rundir);
                let (pkts, txb, rxb) = last_line_containing(&log, "keepalive")
                    .map(|l| parse_counters(&l))
                    .unwrap_or((0, 0, 0));
                let session = state_get(&self.rundir, "client", "tun").unwrap_or_default();
                let _ = session;
                let sid = last_line_containing(&log, "session id")
                    .and_then(|l| l.split("session id ").nth(1).map(|s| s.trim().to_string()))
                    .unwrap_or_default();
                let routes = state_get(&self.rundir, "client", "routes").unwrap_or_default();
                o.push_str("client=running\n");
                o.push_str(&format!("client_pid={}\n", j.child.id()));
                o.push_str(&format!("client_uptime={}\n", j.started.elapsed().as_secs()));
                o.push_str(&format!(
                    "client_tun={}\n",
                    state_get(&self.rundir, "client", "tun").unwrap_or_default()
                ));
                o.push_str(&format!(
                    "client_tun_ip={}\n",
                    state_get(&self.rundir, "client", "tun_ip").unwrap_or_default()
                ));
                o.push_str(&format!(
                    "client_peer={}\n",
                    state_get(&self.rundir, "client", "peer").unwrap_or_default()
                ));
                o.push_str(&format!(
                    "client_full={}\n",
                    state_get(&self.rundir, "client", "default").unwrap_or_default()
                ));
                o.push_str(&format!("client_routes={}\n", routes));
                o.push_str(&format!("client_packets={}\n", pkts));
                o.push_str(&format!("client_tx_bytes={}\n", txb));
                o.push_str(&format!("client_rx_bytes={}\n", rxb));
                o.push_str(&format!("client_session={}\n", sid));
            }
            None => {
                o.push_str("client=stopped\n");
                let why = recent_error(&format!("{}/client.log", self.rundir));
                if !why.is_empty() {
                    o.push_str(&format!("client_error={}\n", why));
                }
            }
        }
        let phys = netcfg::physical_iface().unwrap_or_default();
        o.push_str(&format!("uplink={}\n", phys));
        o.push_str(&format!(
            "uplink_ip={}\n",
            netcfg::iface_ipv4(&phys).unwrap_or_default()
        ));
        o.push_str(&format!(
            "default_iface={}\n",
            netcfg::default_iface().unwrap_or_default()
        ));
        o
    }

    fn log_tail(&self, which: &str, lines: usize) -> String {
        let path = format!(
            "{}/{}.log",
            self.rundir,
            if which == "node" { "node" } else { "client" }
        );
        let s = std::fs::read_to_string(&path).unwrap_or_default();
        let all: Vec<&str> = s.lines().collect();
        let start = all.len().saturating_sub(lines);
        let mut o = String::new();
        for l in &all[start..] {
            o.push_str(&format!("line={}\n", l));
        }
        o
    }
}

fn handle(d: &mut Daemon, req: &str) -> String {
    let parts: Vec<&str> = req.split_whitespace().collect();
    let cmd = parts.first().copied().unwrap_or("").to_uppercase();
    match cmd.as_str() {
        "PING" => "pong=1\n".to_string(),
        "STATUS" => d.status(),
        "KEY" => match key_hex(&d.rundir) {
            Some(k) => format!("key={}\n", k),
            None => "err=no key\n".to_string(),
        },
        "KEYGEN" => match d.ensure_key() {
            Ok(()) => key_hex(&d.rundir)
                .map(|k| format!("key={}\n", k))
                .unwrap_or_else(|| "err=keygen failed\n".to_string()),
            Err(e) => format!("err={}\n", e),
        },
        "NODE" => match parts.get(1).map(|s| s.to_uppercase()).as_deref() {
            Some("START") => {
                let listen = parts.get(2).copied().unwrap_or("0.0.0.0:51820");
                match d.node_start(listen) {
                    Ok(v) => format!("{}\n", v),
                    Err(e) => format!("err={}\n", e),
                }
            }
            Some("STOP") => format!("{}\n", d.node_stop()),
            _ => "err=usage: NODE START|STOP\n".to_string(),
        },
        "CLIENT" => match parts.get(1).map(|s| s.to_uppercase()).as_deref() {
            Some("START") => {
                let peer = parts.get(2).copied().unwrap_or("127.0.0.1:51820");
                let mode = parts.get(3).copied().unwrap_or("full").to_lowercase();
                let routes: Vec<String> = parts
                    .get(4)
                    .map(|s| s.split(',').map(|x| x.to_string()).collect())
                    .unwrap_or_default();
                match d.client_start(peer, mode == "full", &routes) {
                    Ok(v) => format!("{}\n", v),
                    Err(e) => format!("err={}\n", e),
                }
            }
            Some("STOP") => format!("{}\n", d.client_stop()),
            _ => "err=usage: CLIENT START peer full|split [cidrs]\n".to_string(),
        },
        "STOPALL" => {
            let c = d.client_stop();
            let n = d.node_stop();
            format!("client_{}\nnode_{}\n", c, n)
        }
        "LOG" => {
            let which = parts.get(1).copied().unwrap_or("client");
            let n: usize = parts.get(2).and_then(|s| s.parse().ok()).unwrap_or(20);
            d.log_tail(which, n)
        }
        "QUIT" => {
            STOP.store(true, Ordering::SeqCst);
            "bye=1\n".to_string()
        }
        other => format!("err=unknown command {}\n", other),
    }
}

pub fn run_daemon(socket_path: &str) -> std::io::Result<()> {
    reset_sigmask();
    unsafe {
        signal(15, on_sig);
        signal(2, on_sig);
        signal(1, on_sig);
    }
    let rundir = netcfg::RUNDIR.to_string();
    netcfg::ensure_rundir();
    let exe = std::env::current_exe()?.to_string_lossy().to_string();

    // one daemon only
    let _ = std::fs::remove_file(socket_path);
    let listener = UnixListener::bind(socket_path)?;
    std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o660))?;
    logw(&format!("daemon: control socket {}", socket_path));
    logw(&format!("daemon: binary {}", exe));

    let mut d = Daemon {
        node: None,
        client: None,
        bin: exe,
        rundir: rundir.clone(),
        key: format!("{}/psk", rundir),
        client_spec: None,
        net_fp: net_fingerprint(),
        last_net_check: Instant::now(),
    };
    d.ensure_key().ok();

    listener.set_nonblocking(true)?;
    while !STOP.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((stream, _)) => {
                stream.set_nonblocking(false).ok();
                let uid = peer_uid(&stream);
                let ok = matches!(uid, Some(0)) || Some(501) == uid;
                let mut reader = BufReader::new(stream.try_clone()?);
                let mut line = String::new();
                if reader.read_line(&mut line).is_ok() {
                    let mut w = stream;
                    if !ok {
                        let _ = w.write_all(format!("err=unauthorized uid {:?}\nEND\n", uid).as_bytes());
                        let _ = w.flush();
                        continue;
                    }
                    let resp = handle(&mut d, line.trim());
                    let _ = w.write_all(resp.as_bytes());
                    let _ = w.write_all(b"END\n");
                    let _ = w.flush();
                }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(std::time::Duration::from_millis(120));
                d.reap();
                d.check_network();
            }
            Err(e) => {
                logw(&format!("daemon: accept error {}", e));
                std::thread::sleep(std::time::Duration::from_millis(200));
            }
        }
    }
    logw("daemon: shutting down, stopping tunnels");
    d.client_stop();
    d.node_stop();
    let _ = std::fs::remove_file(socket_path);
    Ok(())
}
