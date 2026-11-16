//! Client and server tunnel engines.

use std::collections::HashMap;
use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::netcfg;
use crate::proto::{self, ReplayWindow};
use crate::tun::Tun;
use crate::{logw, verbose};

pub static STOP: AtomicBool = AtomicBool::new(false);

extern "C" fn on_signal(_sig: i32) {
    STOP.store(true, Ordering::SeqCst);
}

extern "C" {
    fn signal(sig: i32, handler: usize) -> usize;
}

pub fn install_signal_handlers() {
    unsafe {
        signal(2, on_signal as usize); // SIGINT
        signal(15, on_signal as usize); // SIGTERM
        signal(1, on_signal as usize); // SIGHUP
    }
}

pub struct CommonCfg {
    pub key: [u8; 32],
    pub tun_ip: [u8; 4],
    pub subnet: [u8; 4],
    pub mtu: usize,
}

pub struct ClientCfg {
    pub common: CommonCfg,
    pub peer: SocketAddr,
    pub default_route: bool,
    pub force_default: bool,
    pub routes: Vec<String>,
}

pub struct ServerCfg {
    pub common: CommonCfg,
    pub listen: SocketAddr,
    pub nat_ifs: Vec<String>,
    /// Optional policy-routed egress for forwarded packets: (interface, gateway).
    /// Needed when the exit node's own routing table would send that traffic back
    /// into a tunnel (e.g. the host is already behind another VPN).
    pub egress: Option<(String, Option<String>)>,
    /// Optional base address for 1:1 source NAT of peers, e.g. 10.66.200.0.
    /// Peers then appear to the host as 10.66.200.<last octet of their tunnel IP>,
    /// which keeps their real tunnel addresses out of the host routing table
    /// (needed when the exit node's own network already owns those addresses).
    pub peer_nat: Option<[u8; 4]>,
}

fn random32() -> io::Result<[u8; 32]> {
    use std::io::Read;
    let mut f = std::fs::File::open("/dev/urandom")?;
    let mut b = [0u8; 32];
    f.read_exact(&mut b)?;
    Ok(b)
}

fn show(ip: &[u8; 4]) -> String {
    proto::show_ipv4(ip)
}

fn subnet_cidr(subnet: &[u8; 4]) -> String {
    format!("{}.{}.{}.0/24", subnet[0], subnet[1], subnet[2])
}

fn base24(b: &[u8; 4]) -> String {
    format!("{}.{}.{}.0/24", b[0], b[1], b[2])
}

fn with_last(base: &[u8; 4], last: u8) -> [u8; 4] {
    [base[0], base[1], base[2], last]
}

// ------------------------------------------------------------------ client

pub fn run_client(cfg: ClientCfg) -> io::Result<()> {
    install_signal_handlers();

    // Refuse to stack a full-tunnel default route on top of an existing VPN:
    // that VPN's own encapsulated packets get captured by our routes and
    // re-encapsulated forever (an encapsulation loop).
    if cfg.default_route && !cfg.force_default {
        if let Some(def) = netcfg::default_iface() {
            if netcfg::is_tunnel_iface(&def) {
                logw(&format!(
                    "client: refusing --default: default route already goes through tunnel {}",
                    def
                ));
                logw("client: stacking full tunnels recurses. Use --route CIDR for split tunnelling,");
                logw("client: or --force-default if you really want to try it.");
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "existing tunnel owns the default route",
                ));
            }
        }
    }

    let tun = Tun::create(0)?;
    logw(&format!("client: interface {} created", tun.name));
    netcfg::set_link(&tun.name, &cfg.common.tun_ip, cfg.common.mtu)?;
    logw(&format!(
        "client: {} configured {}/{}, mtu {}",
        tun.name,
        show(&cfg.common.tun_ip),
        show(&cfg.common.subnet),
        cfg.common.mtu
    ));

    let sock = UdpSocket::bind("0.0.0.0:0")?;
    sock.set_read_timeout(Some(Duration::from_millis(250)))?;
    logw(&format!("client: underlay socket {}", sock.local_addr()?));

    // ---- handshake
    let cnonce = random32()?;
    let req = proto::build_req(&cfg.common.key, cfg.common.tun_ip, &cnonce);
    let mut keys: Option<proto::Keys> = None;
    let mut rbuf = vec![0u8; 2048];
    'hs: for attempt in 1..=40 {
        sock.send_to(&req, cfg.peer)?;
        let deadline = Instant::now() + Duration::from_millis(500);
        while Instant::now() < deadline {
            match sock.recv_from(&mut rbuf) {
                Ok((n, from)) => {
                    if from != cfg.peer {
                        continue;
                    }
                    if let Some((_ip, snonce)) = proto::parse_resp(&cfg.common.key, &rbuf[..n], &cnonce)
                    {
                        keys = Some(proto::derive(&cfg.common.key, &cnonce, &snonce));
                        logw(&format!(
                            "client: handshake OK after {} attempt(s) with {}",
                            attempt, cfg.peer
                        ));
                        break 'hs;
                    }
                }
                Err(ref e)
                    if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut =>
                {
                    break
                }
                Err(e) => return Err(e),
            }
        }
    }
    let keys = match keys {
        Some(k) => k,
        None => {
            logw("client: handshake FAILED (peer unreachable or wrong key)");
            return Err(io::Error::new(io::ErrorKind::TimedOut, "handshake failed"));
        }
    };
    logw(&format!("client: session id {}", proto::sid_hex(&keys.sid)));

    // ---- routes
    let mut nets: Vec<String> = Vec::new();
    let mut bypass: Option<(String, String)> = None;

    for r in cfg.routes.iter() {
        netcfg::add_route_cidr(r, &tun.name)?;
        nets.push(r.clone());
        logw(&format!("client: route {} -> {}", r, tun.name));
    }

    if cfg.default_route {
        let peer_ip = cfg.peer.ip().to_string();
        if !cfg.peer.ip().is_loopback() {
            if let Some(gw) = netcfg::default_gateway() {
                netcfg::add_route_host(&peer_ip, &gw)?;
                logw(&format!("client: pinned peer {} via {} (bypasses tunnel)", peer_ip, gw));
                bypass = Some((peer_ip, gw));
            }
        }
        for net in ["0.0.0.0/1", "128.0.0.0/1"] {
            netcfg::add_route_net(net, &tun.name)?;
            nets.push(net.to_string());
        }
        logw(&format!("client: full tunnel active (0.0.0.0/1 + 128.0.0.0/1 -> {})", tun.name));
    }

    netcfg::save_state(
        "client",
        &[
            ("tun".to_string(), tun.name.clone()),
            ("peer".to_string(), cfg.peer.to_string()),
            ("tun_ip".to_string(), show(&cfg.common.tun_ip)),
            ("default".to_string(), cfg.default_route.to_string()),
            (
                "peer_bypass".to_string(),
                bypass.as_ref().map(|(ip, gw)| format!("{} via {}", ip, gw)).unwrap_or_default(),
            ),
            ("routes".to_string(), nets.join(",")),
            ("pid".to_string(), std::process::id().to_string()),
        ],
    );

    // ---- datapath: tun -> wire (thread)
    let mut rtun = tun.try_clone()?;
    let sock_tx = sock.try_clone()?;
    let peer = cfg.peer;
    let k_up = keys.k_c2s;
    let sid = keys.sid;
    let tx_ctr = Arc::new(AtomicU64::new(0));
    let tx_bytes = Arc::new(AtomicU64::new(0));
    let rx_bytes = Arc::new(AtomicU64::new(0));
    let ctr_t = tx_ctr.clone();
    let txb_t = tx_bytes.clone();

    let reader = std::thread::spawn(move || {
        let mut buf = vec![0u8; 65536];
        loop {
            if STOP.load(Ordering::SeqCst) {
                break;
            }
            match rtun.recv(&mut buf, 250) {
                Ok(Some(n)) if n > 0 => {
                    let ctr = ctr_t.fetch_add(1, Ordering::SeqCst);
                    let wire = proto::seal_data(&k_up, &sid, 0, ctr, &buf[..n]);
                    let _ = sock_tx.send_to(&wire, peer);
                    txb_t.fetch_add(n as u64, Ordering::Relaxed);
                    if verbose() && (ctr < 5 || ctr % 200 == 0) {
                        logw(&format!(
                            "client: TX #{} {} -> {} | {} B plaintext -> {} B on wire",
                            ctr,
                            show(&proto::ipv4_src(&buf[..n]).unwrap_or([0, 0, 0, 0])),
                            show(&proto::ipv4_dst(&buf[..n]).unwrap_or([0, 0, 0, 0])),
                            n,
                            wire.len()
                        ));
                    }
                }
                _ => continue,
            }
        }
    });

    // ---- datapath: wire -> tun (main)
    let mut tun_w = tun;
    let mut rx = ReplayWindow::new();
    let mut last_hb = Instant::now();
    let mut last_rx = Instant::now();
    while !STOP.load(Ordering::SeqCst) {
        match sock.recv_from(&mut rbuf) {
            Ok((len, from)) => {
                if from != peer {
                    continue;
                }
                if let Some((_sid, ctr, pt)) = proto::open_data(&keys.k_s2c, 1, &rbuf[..len]) {
                    if !rx.check_and_mark(ctr) {
                        logw(&format!("client: dropped replayed packet #{}", ctr));
                        continue;
                    }
                    last_rx = Instant::now();
                    if !pt.is_empty() {
                        rx_bytes.fetch_add(pt.len() as u64, Ordering::Relaxed);
                        let _ = tun_w.send(&pt);
                        if verbose() {
                            logw(&format!(
                                "client: RX #{} {} -> {} | {} B decrypted",
                                ctr,
                                show(&proto::ipv4_src(&pt).unwrap_or([0, 0, 0, 0])),
                                show(&proto::ipv4_dst(&pt).unwrap_or([0, 0, 0, 0])),
                                pt.len()
                            ));
                        }
                    }
                } else if rbuf[..5] == proto::MAGIC {
                    logw("client: dropped packet that failed authentication");
                }
            }
            Err(ref e)
                if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut => {}
            Err(e) => {
                logw(&format!("client: socket error: {}", e));
                break;
            }
        }

        if last_hb.elapsed() >= Duration::from_secs(10) {
            let ctr = tx_ctr.fetch_add(1, Ordering::SeqCst);
            let wire = proto::seal_data(&keys.k_c2s, &keys.sid, 0, ctr, &[]);
            let _ = sock.send_to(&wire, peer);
            last_hb = Instant::now();
            logw(&format!(
                "client: keepalive | tx {} pkts {} B | rx {} B | last rx {}s ago",
                tx_ctr.load(Ordering::Relaxed),
                tx_bytes.load(Ordering::Relaxed),
                rx_bytes.load(Ordering::Relaxed),
                last_rx.elapsed().as_secs()
            ));
        }
    }

    logw("client: shutting down");
    for net in nets.iter() {
        netcfg::del_route_cidr(net, &tun_w.name);
    }
    if let Some((ip, gw)) = bypass.as_ref() {
        netcfg::del_route_host(ip, gw);
    }
    netcfg::clear_state("client");
    let _ = reader.join();
    logw("client: routes removed, tunnel closed");
    Ok(())
}

// ------------------------------------------------------------------ server

struct Session {
    peer: SocketAddr,
    client_ip: [u8; 4],
    mapped: Option<[u8; 4]>,
    keys: proto::Keys,
    rx: ReplayWindow,
    tx_ctr: u64,
    last: Instant,
}

pub fn run_server(cfg: ServerCfg) -> io::Result<()> {
    install_signal_handlers();
    let tun = Tun::create(0)?;
    logw(&format!("server: interface {} created", tun.name));
    netcfg::set_link(&tun.name, &cfg.common.tun_ip, cfg.common.mtu)?;

    let cidr = subnet_cidr(&cfg.common.subnet);
    netcfg::add_route_net(&cidr, &tun.name)?;
    logw(&format!(
        "server: {} up as {}, {} routed into it, mtu {}",
        tun.name,
        show(&cfg.common.tun_ip),
        cidr,
        cfg.common.mtu
    ));

    // optional 1:1 source NAT pool for peers
    let nat_cidr = match cfg.peer_nat {
        Some(base) => {
            let b = with_last(&base, 0);
            let pool = base24(&b);
            netcfg::add_route_net(&pool, &tun.name)?;
            logw(&format!("server: peers masqueraded into {} (returns via {})", pool, tun.name));
            pool
        }
        None => cidr.clone(),
    };

    // ---- internet egress (NAT)
    let pf_was = netcfg::pf_enabled();
    let fwd_was = netcfg::forwarding_get();
    let mut pf_on = false;
    if !cfg.nat_ifs.is_empty() {
        netcfg::forwarding_set("1");
        let mss = cfg.common.mtu.saturating_sub(40);
        match netcfg::pf_nat_up(&cfg.nat_ifs, &nat_cidr, &tun.name, cfg.egress.as_ref(), mss) {
            Ok(()) => {
                pf_on = true;
                logw(&format!(
                    "server: ip forwarding on, NAT {} -> {}",
                    nat_cidr,
                    cfg.nat_ifs.join(",")
                ));
                if let Some((iface, gw)) = cfg.egress.as_ref() {
                    logw(&format!(
                        "server: policy route: forwarded traffic exits {} via {}",
                        iface,
                        gw.clone().unwrap_or_else(|| "interface default".to_string())
                    ));
                }
            }
            Err(e) => logw(&format!("server: WARNING NAT setup failed: {}", e)),
        }
    } else {
        logw("server: no --nat given (tunnel-only, no internet egress)");
    }

    let sock = UdpSocket::bind(cfg.listen)?;
    sock.set_read_timeout(Some(Duration::from_millis(10)))?;
    logw(&format!("server: listening on udp {}", cfg.listen));

    netcfg::save_state(
        "server",
        &[
            ("tun".to_string(), tun.name.clone()),
            ("listen".to_string(), cfg.listen.to_string()),
            ("tun_ip".to_string(), show(&cfg.common.tun_ip)),
            ("nat_ifs".to_string(), cfg.nat_ifs.join(",")),
            ("nat_cidr".to_string(), nat_cidr.clone()),
            ("peer_nat".to_string(), cfg.peer_nat.map(|b| show(&b)).unwrap_or_default()),
            (
                "egress".to_string(),
                cfg.egress
                    .as_ref()
                    .map(|(i, g)| format!("{}@{}", i, g.clone().unwrap_or_default()))
                    .unwrap_or_default(),
            ),
            ("pf_on".to_string(), pf_on.to_string()),
            ("pf_was".to_string(), pf_was.to_string()),
            ("fwd_was".to_string(), fwd_was.clone()),
            ("pid".to_string(), std::process::id().to_string()),
        ],
    );

    let mut sessions: HashMap<[u8; 4], Session> = HashMap::new();
    let rx_bytes = AtomicU64::new(0);
    let tx_bytes = AtomicU64::new(0);
    let mut buf = vec![0u8; 65536];
    let mut tbuf = vec![0u8; 65536];
    let mut tun_w = tun;
    let peer_nat = cfg.peer_nat;

    while !STOP.load(Ordering::SeqCst) {
        // ---- wire -> tun
        match sock.recv_from(&mut buf) {
            Ok((n, from)) => {
                let pkt = &buf[..n];
                if pkt.len() >= proto::REQ_LEN && pkt[..5] == proto::MAGIC && pkt[5] == proto::T_REQ {
                    if let Some((ip, cnonce)) = proto::parse_req(&cfg.common.key, pkt) {
                        let snonce = random32()?;
                        let keys = proto::derive(&cfg.common.key, &cnonce, &snonce);
                        let resp = proto::build_resp(&cfg.common.key, ip, &cnonce, &snonce);
                        sock.send_to(&resp, from)?;
                        let mapped = peer_nat.map(|b| with_last(&b, ip[3]));
                        logw(&format!(
                            "server: handshake from {} -> peer {} ({}) sid {}",
                            from,
                            show(&ip),
                            mapped.map(|m| format!("shows as {}", show(&m))).unwrap_or_default(),
                            proto::sid_hex(&keys.sid)
                        ));
                        sessions.insert(
                            ip,
                            Session {
                                peer: from,
                                client_ip: ip,
                                mapped,
                                keys,
                                rx: ReplayWindow::new(),
                                tx_ctr: 0,
                                last: Instant::now(),
                            },
                        );
                    } else {
                        logw(&format!("server: rejected handshake from {} (bad key or stale ts)", from));
                    }
                    continue;
                }
                if pkt.len() >= proto::DATA_HDR + 16
                    && pkt[..5] == proto::MAGIC
                    && pkt[5] == proto::T_DATA
                {
                    let ip = sessions.iter().find(|(_, s)| s.peer == from).map(|(ip, _)| *ip);
                    let Some(ip) = ip else {
                        logw(&format!("server: data from unknown peer {}", from));
                        continue;
                    };
                    let key = sessions.get(&ip).map(|s| s.keys.k_c2s).unwrap();
                    if let Some((_sid, ctr, pt)) = proto::open_data(&key, 0, pkt) {
                        let (ok, mapped) = match sessions.get_mut(&ip) {
                            Some(s) => {
                                s.last = Instant::now();
                                (s.rx.check_and_mark(ctr), s.mapped)
                            }
                            None => (false, None),
                        };
                        if ok && !pt.is_empty() {
                            rx_bytes.fetch_add(pt.len() as u64, Ordering::Relaxed);
                            let mut out = pt;
                            if let Some(m) = mapped {
                                proto::ipv4_rewrite_src(&mut out, m);
                            }
                            if verbose() {
                                logw(&format!(
                                    "server: RX #{} from {} {} -> {} | {} B",
                                    ctr,
                                    show(&ip),
                                    show(&proto::ipv4_src(&out).unwrap_or([0, 0, 0, 0])),
                                    show(&proto::ipv4_dst(&out).unwrap_or([0, 0, 0, 0])),
                                    out.len()
                                ));
                            }
                            let _ = tun_w.send(&out);
                        }
                    } else {
                        logw(&format!("server: bad MAC on data from {}", from));
                    }
                }
            }
            Err(ref e)
                if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut => {}
            Err(e) => {
                logw(&format!("server: socket error: {}", e));
                break;
            }
        }

        // ---- tun -> wire
        while let Ok(Some(n)) = tun_w.recv(&mut tbuf, 0) {
            if n == 0 {
                continue;
            }
            let dst = match proto::ipv4_dst(&tbuf[..n]) {
                Some(d) => d,
                None => continue,
            };
            // a mapped peer address maps back to the peer's tunnel address
            let owner = sessions
                .iter()
                .find(|(_, s)| s.mapped == Some(dst) || (s.mapped.is_none() && s.client_ip == dst))
                .map(|(ip, _)| *ip);
            let Some(owner) = owner else {
                continue;
            };
            let mut pkt = tbuf[..n].to_vec();
            {
                let s = sessions.get(&owner).unwrap();
                if s.mapped.is_some() {
                    proto::ipv4_rewrite_dst(&mut pkt, s.client_ip);
                }
            }
            let (peer, wire, ctr) = {
                let s = sessions.get_mut(&owner).unwrap();
                s.tx_ctr += 1;
                let ctr = s.tx_ctr;
                let wire = proto::seal_data(&s.keys.k_s2c, &s.keys.sid, 1, ctr, &pkt);
                (s.peer, wire, ctr)
            };
            let _ = sock.send_to(&wire, peer);
            tx_bytes.fetch_add(pkt.len() as u64, Ordering::Relaxed);
            if verbose() && (ctr < 5 || ctr % 200 == 0) {
                logw(&format!(
                    "server: TX #{} to {} {} -> {} | {} B plaintext -> {} B wire",
                    ctr,
                    show(&owner),
                    show(&proto::ipv4_src(&pkt).unwrap_or([0, 0, 0, 0])),
                    show(&proto::ipv4_dst(&pkt).unwrap_or([0, 0, 0, 0])),
                    pkt.len(),
                    wire.len()
                ));
            }
        }
    }

    logw(&format!(
        "server: stopping | {} B from peers, {} B to peers | {} session(s)",
        rx_bytes.load(Ordering::Relaxed),
        tx_bytes.load(Ordering::Relaxed),
        sessions.len()
    ));
    netcfg::del_route_net(&cidr, &tun_w.name);
    if peer_nat.is_some() {
        netcfg::del_route_net(&base24(&with_last(&peer_nat.unwrap(), 0)), &tun_w.name);
    }
    if pf_on {
        netcfg::pf_down(pf_was);
        logw("server: NAT rules removed, pf restored");
    }
    netcfg::forwarding_set(&fwd_was);
    netcfg::clear_state("server");
    Ok(())
}
