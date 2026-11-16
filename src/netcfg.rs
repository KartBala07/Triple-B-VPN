//! Host network configuration: interface setup, routes, NAT (pf), state files.

use std::io::{self, Write};
use std::process::{Command, Stdio};

use crate::proto::show_ipv4;

pub const RUNDIR: &str = "/var/run/hvpn";

pub fn run(args: &[&str]) -> io::Result<(i32, String, String)> {
    let out = Command::new(args[0]).args(&args[1..]).output()?;
    Ok((
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).trim().to_string(),
        String::from_utf8_lossy(&out.stderr).trim().to_string(),
    ))
}

pub fn run_quiet(args: &[&str]) {
    let _ = run(args);
}

pub fn ensure_rundir() {
    let _ = std::fs::create_dir_all(RUNDIR);
}

/// ifconfig <tun> inet <ip> <ip> netmask 255.255.255.255 mtu <mtu> up
pub fn set_link(name: &str, ip: &[u8; 4], mtu: usize) -> io::Result<()> {
    let ips = show_ipv4(ip);
    let mtu_s = mtu.to_string();
    let (code, _, err) = run(&[
        "ifconfig", name, "inet", &ips, &ips, "netmask", "255.255.255.255", "mtu", &mtu_s, "up",
    ])?;
    if code != 0 {
        return Err(io::Error::new(io::ErrorKind::Other, format!("ifconfig failed: {}", err)));
    }
    Ok(())
}

pub fn add_route_net(dst: &str, iface: &str) -> io::Result<()> {
    let (code, _, err) = run(&["route", "-n", "add", "-net", dst, "-interface", iface])?;
    if code != 0 && !err.contains("File exists") {
        return Err(io::Error::new(io::ErrorKind::Other, format!("route add {} failed: {}", dst, err)));
    }
    Ok(())
}

pub fn del_route_net(dst: &str, iface: &str) {
    run_quiet(&["route", "-n", "delete", "-net", dst, "-interface", iface]);
}

pub fn add_route_host(dst: &str, gw: &str) -> io::Result<()> {
    let (code, _, err) = run(&["route", "-n", "add", "-host", dst, gw])?;
    if code != 0 && !err.contains("File exists") {
        return Err(io::Error::new(io::ErrorKind::Other, format!("route add host failed: {}", err)));
    }
    Ok(())
}

pub fn del_route_host(dst: &str, gw: &str) {
    run_quiet(&["route", "-n", "delete", "-host", dst, gw]);
}

pub fn default_gateway() -> Option<String> {
    let (code, out, _) = run(&["route", "-n", "get", "default"]).ok()?;
    if code != 0 {
        return None;
    }
    for line in out.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("gateway:") {
            return Some(rest.trim().to_string());
        }
    }
    None
}

pub fn interface_exists(name: &str) -> bool {
    match run(&["ifconfig", name]) {
        Ok((code, _, _)) => code == 0,
        Err(_) => false,
    }
}

/// Interface that owns the current default route (physical or tunnel).
pub fn default_iface() -> Option<String> {
    let (code, out, _) = run(&["route", "-n", "get", "default"]).ok()?;
    if code != 0 {
        return None;
    }
    for line in out.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("interface:") {
            return Some(rest.trim().to_string());
        }
    }
    None
}

pub fn is_tunnel_iface(name: &str) -> bool {
    name.starts_with("utun")
        || name.starts_with("ipsec")
        || name.starts_with("ppp")
        || name.starts_with("tun")
        || name.starts_with("tap")
}

/// The physical uplink interface (the one carrying a DHCP router), if any.
pub fn physical_iface() -> Option<String> {
    let (_, out, _) = run(&["ifconfig", "-l"]).ok()?;
    for name in out.split_whitespace() {
        if name == "lo0" || is_tunnel_iface(name) {
            continue;
        }
        if iface_router(name).is_some() {
            return Some(name.to_string());
        }
    }
    None
}

/// Router (LAN gateway) advertised on a physical interface.
pub fn iface_router(iface: &str) -> Option<String> {
    match run(&["ipconfig", "getoption", iface, "router"]) {
        Ok((0, o, _)) if !o.trim().is_empty() => Some(o.trim().to_string()),
        _ => None,
    }
}

pub fn iface_ipv4(iface: &str) -> Option<String> {
    let (code, out, _) = run(&["ifconfig", iface]).ok()?;
    if code != 0 {
        return None;
    }
    for line in out.lines() {
        let t = line.trim();
        if let Some(rest) = t.strip_prefix("inet ") {
            if !rest.starts_with("127.") {
                return rest.split_whitespace().next().map(|s| s.to_string());
            }
        }
    }
    None
}

/// Add a route for a CIDR (host routes use -host, everything else -net).
pub fn add_route_cidr(cidr: &str, iface: &str) -> io::Result<()> {
    if let Some(host) = cidr.strip_suffix("/32") {
        let (code, _, err) = run(&["route", "-n", "add", "-host", host, "-interface", iface])?;
        if code != 0 && !err.contains("File exists") {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("route add host {} failed: {}", host, err),
            ));
        }
        Ok(())
    } else {
        add_route_net(cidr, iface)
    }
}

pub fn del_route_cidr(cidr: &str, iface: &str) {
    if let Some(host) = cidr.strip_suffix("/32") {
        run_quiet(&["route", "-n", "delete", "-host", host, "-interface", iface]);
    } else {
        del_route_net(cidr, iface);
    }
}

// ------------------------------------------------------------------ pf (NAT)

pub fn forwarding_get() -> String {
    match run(&["sysctl", "-n", "net.inet.ip.forwarding"]) {
        Ok((0, o, _)) => o.trim().to_string(),
        _ => "0".to_string(),
    }
}

pub fn forwarding_set(v: &str) {
    run_quiet(&["sysctl", "-w", &format!("net.inet.ip.forwarding={}", v)]);
}

pub fn pf_enabled() -> bool {
    match run(&["pfctl", "-s", "info"]) {
        Ok((_, o, e)) => {
            let all = format!("{}{}", o, e);
            all.contains("Status: Enabled")
        }
        Err(_) => false,
    }
}

/// Load a NAT ruleset that masquerades `cidr` on every egress interface.
/// pf requires translation rules before filtering anchors, hence the ordering.
///
/// `egress` adds policy routing (`route-to`) for packets the tunnel hands to the
/// kernel: without it the host routing table decides where a forwarded packet
/// goes, so a more specific route on the same host (or a default route that is
/// itself another tunnel) captures the packet and re-encapsulates it.
pub fn pf_nat_up(
    ifaces: &[String],
    cidr: &str,
    tun: &str,
    egress: Option<&(String, Option<String>)>,
    mss: usize,
) -> io::Result<()> {
    ensure_rundir();
    let mut rules = String::from("scrub-anchor \"com.apple/*\"\n");
    // Clamp MSS so peers never hand the tunnel a segment it cannot carry.
    rules.push_str(&format!(
        "scrub in on {} inet from {} to any max-mss {}\n",
        tun, cidr, mss
    ));
    for i in ifaces {
        rules.push_str(&format!(
            "scrub in on {} inet from any to {} max-mss {}\n",
            i, cidr, mss
        ));
    }
    rules.push_str("nat-anchor \"com.apple/*\"\n");
    for i in ifaces {
        rules.push_str(&format!("nat on {} inet from {} to any -> ({})\n", i, cidr, i));
    }
    rules.push_str("rdr-anchor \"com.apple/*\"\ndummynet-anchor \"com.apple/*\"\nanchor \"com.apple/*\"\n");
    if let Some((iface, gw)) = egress {
        let dest = match gw {
            Some(g) => format!("({} {})", iface, g),
            None => format!("({})", iface),
        };
        rules.push_str(&format!(
            "pass in quick on {} route-to {} from {} to any\n",
            tun, dest, cidr
        ));
    }
    let path = format!("{}/pf.conf", RUNDIR);
    {
        let mut f = std::fs::File::create(&path)?;
        f.write_all(rules.as_bytes())?;
    }
    // Snapshot the current ruleset so teardown can restore it exactly.
    if let Ok((_, o, _)) = run(&["pfctl", "-sr"]) {
        let _ = std::fs::write(format!("{}/pf.rules.backup", RUNDIR), o);
    }

    let (code, _, err) = run(&["pfctl", "-f", &path])?;
    if code != 0 {
        return Err(io::Error::new(io::ErrorKind::Other, format!("pfctl load failed: {}", err)));
    }
    let (code, _, err) = run(&["pfctl", "-E"])?;
    if code != 0 {
        return Err(io::Error::new(io::ErrorKind::Other, format!("pfctl enable failed: {}", err)));
    }
    Ok(())
}

pub fn pf_down(was_enabled: bool) {
    // Restore the stock ruleset (drops our nat rule).
    run_quiet(&["pfctl", "-f", "/etc/pf.conf"]);
    if !was_enabled {
        run_quiet(&["pfctl", "-d"]);
    }
}

// ------------------------------------------------------------------ state

pub fn state_path(kind: &str) -> String {
    format!("{}/{}.state", RUNDIR, kind)
}

pub fn save_state(kind: &str, kv: &[(String, String)]) {
    ensure_rundir();
    let mut s = String::new();
    for (k, v) in kv {
        s.push_str(&format!("{}={}\n", k, v));
    }
    let _ = std::fs::write(state_path(kind), s);
}

pub fn load_state(kind: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    if let Ok(s) = std::fs::read_to_string(state_path(kind)) {
        for line in s.lines() {
            if let Some((k, v)) = line.split_once('=') {
                out.push((k.to_string(), v.to_string()));
            }
        }
    }
    out
}

pub fn clear_state(kind: &str) {
    let _ = std::fs::remove_file(state_path(kind));
}

pub fn state_get(kv: &[(String, String)], key: &str) -> Option<String> {
    kv.iter().find(|(k, _)| k == key).map(|(_, v)| v.clone())
}

// ------------------------------------------------------------------ misc

pub fn pid_alive(pid: u32) -> bool {
    run(&["kill", "-0", &pid.to_string()]).map(|(c, _, _)| c == 0).unwrap_or(false)
}

pub fn pid_kill(pid: u32) {
    run_quiet(&["kill", "-TERM", &pid.to_string()]);
}

pub fn run_as_root_args_check() -> bool {
    extern "C" {
        fn geteuid() -> u32;
    }
    unsafe { geteuid() == 0 }
}
