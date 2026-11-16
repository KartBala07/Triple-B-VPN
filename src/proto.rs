//! HermesVPN wire protocol + session key schedule.
//!
//! Handshake (PSK-authenticated, ephemeral nonces, timestamp for anti-replay):
//!   REQ : "HVPN1" 01 | ts:u64be | ip:4 | cnonce:32 | mac:16
//!   RESP: "HVPN1" 02 | ts:u64be | ip:4 | cnonce:32 | snonce:32 | mac:16
//!
//! Data:
//!   "HVPN1" 03 | sid:8 | ctr:u64be | AEAD(k_c2s|k_s2c, nonce) -> payload
//!   The first 22 bytes are the AEAD associated data.

use crate::crypto;

pub const MAGIC: [u8; 5] = *b"HVPN1";
pub const T_REQ: u8 = 1;
pub const T_RESP: u8 = 2;
pub const T_DATA: u8 = 3;

pub const REQ_LEN: usize = 5 + 1 + 8 + 4 + 32 + 16;
pub const RESP_LEN: usize = 5 + 1 + 8 + 4 + 32 + 32 + 16;
pub const DATA_HDR: usize = 5 + 1 + 8 + 8;

const INFO_SESSION: &[u8] = b"hvpn-session-v1";
const INFO_SID: &[u8] = b"hvpn-sid-v1";

#[derive(Clone)]
pub struct Keys {
    pub sid: [u8; 8],
    pub k_c2s: [u8; 32],
    pub k_s2c: [u8; 32],
}

pub fn derive(p_psk: &[u8; 32], cnonce: &[u8; 32], snonce: &[u8; 32]) -> Keys {
    let mut salt = Vec::with_capacity(64);
    salt.extend_from_slice(cnonce);
    salt.extend_from_slice(snonce);
    let mut okm = [0u8; 64];
    crypto::hkdf_sha256(&salt, p_psk, INFO_SESSION, &mut okm);

    let mut k_c2s = [0u8; 32];
    let mut k_s2c = [0u8; 32];
    k_c2s.copy_from_slice(&okm[..32]);
    k_s2c.copy_from_slice(&okm[32..]);

    let mut idm = Vec::with_capacity(32);
    idm.extend_from_slice(INFO_SID);
    idm.extend_from_slice(cnonce);
    idm.extend_from_slice(snonce);
    let idh = crypto::sha256(&idm);
    let mut sid = [0u8; 8];
    sid.copy_from_slice(&idh[..8]);

    Keys { sid, k_c2s, k_s2c }
}

pub fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn req_mac(psk: &[u8; 32], ts: u64, ip: &[u8; 4], cnonce: &[u8; 32]) -> [u8; 32] {
    let mut m = Vec::with_capacity(80);
    m.extend_from_slice(b"hvpn-hs-req-v1");
    m.extend_from_slice(&ts.to_be_bytes());
    m.extend_from_slice(ip);
    m.extend_from_slice(cnonce);
    crypto::hmac_sha256(psk, &m)
}

fn resp_mac(psk: &[u8; 32], ts: u64, ip: &[u8; 4], cnonce: &[u8; 32], snonce: &[u8; 32]) -> [u8; 32] {
    let mut m = Vec::with_capacity(112);
    m.extend_from_slice(b"hvpn-hs-resp-v1");
    m.extend_from_slice(&ts.to_be_bytes());
    m.extend_from_slice(ip);
    m.extend_from_slice(cnonce);
    m.extend_from_slice(snonce);
    crypto::hmac_sha256(psk, &m)
}

pub fn build_req(psk: &[u8; 32], ip: [u8; 4], cnonce: &[u8; 32]) -> Vec<u8> {
    let ts = now_secs();
    let mut b = Vec::with_capacity(REQ_LEN);
    b.extend_from_slice(&MAGIC);
    b.push(T_REQ);
    b.extend_from_slice(&ts.to_be_bytes());
    b.extend_from_slice(&ip);
    b.extend_from_slice(cnonce);
    let mac = req_mac(psk, ts, &ip, cnonce);
    b.extend_from_slice(&mac[..16]);
    b
}

pub fn build_resp(psk: &[u8; 32], ip: [u8; 4], cnonce: &[u8; 32], snonce: &[u8; 32]) -> Vec<u8> {
    let ts = now_secs();
    let mut b = Vec::with_capacity(RESP_LEN);
    b.extend_from_slice(&MAGIC);
    b.push(T_RESP);
    b.extend_from_slice(&ts.to_be_bytes());
    b.extend_from_slice(&ip);
    b.extend_from_slice(cnonce);
    b.extend_from_slice(snonce);
    let mac = resp_mac(psk, ts, &ip, cnonce, snonce);
    b.extend_from_slice(&mac[..16]);
    b
}

fn get_u64(b: &[u8], off: usize) -> u64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(&b[off..off + 8]);
    u64::from_be_bytes(a)
}

/// Returns (ip, cnonce)
pub fn parse_req(psk: &[u8; 32], b: &[u8]) -> Option<([u8; 4], [u8; 32])> {
    if b.len() != REQ_LEN || b[..5] != MAGIC || b[5] != T_REQ {
        return None;
    }
    let ts = get_u64(b, 6);
    let now = now_secs();
    if ts.abs_diff(now) > 300 {
        return None; // stale / replayed
    }
    let mut ip = [0u8; 4];
    ip.copy_from_slice(&b[14..18]);
    let mut cnonce = [0u8; 32];
    cnonce.copy_from_slice(&b[18..50]);
    let mac = req_mac(psk, ts, &ip, &cnonce);
    if !crypto::ct_eq(&mac[..16], &b[50..66]) {
        return None;
    }
    Some((ip, cnonce))
}

/// Returns (ip, snonce)
pub fn parse_resp(psk: &[u8; 32], b: &[u8], cnonce_expect: &[u8; 32]) -> Option<([u8; 4], [u8; 32])> {
    if b.len() != RESP_LEN || b[..5] != MAGIC || b[5] != T_RESP {
        return None;
    }
    let ts = get_u64(b, 6);
    let now = now_secs();
    if ts.abs_diff(now) > 300 {
        return None;
    }
    let mut ip = [0u8; 4];
    ip.copy_from_slice(&b[14..18]);
    let mut cnonce = [0u8; 32];
    cnonce.copy_from_slice(&b[18..50]);
    if !crypto::ct_eq(&cnonce, cnonce_expect) {
        return None;
    }
    let mut snonce = [0u8; 32];
    snonce.copy_from_slice(&b[50..82]);
    let mac = resp_mac(psk, ts, &ip, &cnonce, &snonce);
    if !crypto::ct_eq(&mac[..16], &b[82..98]) {
        return None;
    }
    Some((ip, snonce))
}

fn nonce_for(direction: u32, ctr: u64) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[..4].copy_from_slice(&direction.to_be_bytes());
    n[4..].copy_from_slice(&ctr.to_be_bytes());
    n
}

/// Build a DATA packet. direction 0 = client->server, 1 = server->client.
pub fn seal_data(key: &[u8; 32], sid: &[u8; 8], direction: u32, ctr: u64, payload: &[u8]) -> Vec<u8> {
    let mut hdr = Vec::with_capacity(DATA_HDR);
    hdr.extend_from_slice(&MAGIC);
    hdr.push(T_DATA);
    hdr.extend_from_slice(sid);
    hdr.extend_from_slice(&ctr.to_be_bytes());
    let sealed = crypto::aead_seal(key, &nonce_for(direction, ctr), &hdr, payload);
    let mut out = hdr;
    out.extend_from_slice(&sealed);
    out
}

/// Returns (sid, ctr, payload) if authentic.
pub fn open_data(key: &[u8; 32], direction: u32, b: &[u8]) -> Option<([u8; 8], u64, Vec<u8>)> {
    if b.len() < DATA_HDR + 16 || b[..5] != MAGIC || b[5] != T_DATA {
        return None;
    }
    let mut sid = [0u8; 8];
    sid.copy_from_slice(&b[6..14]);
    let ctr = get_u64(b, 14);
    let (hdr, ct) = b.split_at(DATA_HDR);
    let pt = crypto::aead_open(key, &nonce_for(direction, ctr), hdr, ct)?;
    Some((sid, ctr, pt))
}

/// Sliding-window anti-replay (128 packets).
pub struct ReplayWindow {
    highest: u64,
    bitmap: u128,
    seen_any: bool,
}

impl ReplayWindow {
    pub fn new() -> Self {
        ReplayWindow { highest: 0, bitmap: 0, seen_any: false }
    }

    pub fn check_and_mark(&mut self, ctr: u64) -> bool {
        if !self.seen_any {
            self.seen_any = true;
            self.highest = ctr;
            self.bitmap = 1;
            return true;
        }
        if ctr > self.highest {
            let shift = ctr - self.highest;
            self.bitmap = if shift >= 128 { 1 } else { (self.bitmap << shift) | 1 };
            self.highest = ctr;
            true
        } else {
            let diff = self.highest - ctr;
            if diff >= 128 {
                return false;
            }
            let bit = 1u128 << diff;
            if self.bitmap & bit != 0 {
                false
            } else {
                self.bitmap |= bit;
                true
            }
        }
    }
}

/// One's-complement checksum adjustment after replacing two address words,
/// per RFC 1624 (incremental update, no payload rescan).
fn csum_adjust(csum: u16, old: [u8; 4], new: [u8; 4]) -> u16 {
    let ow0 = u16::from_be_bytes([old[0], old[1]]) as u32;
    let ow1 = u16::from_be_bytes([old[2], old[3]]) as u32;
    let nw0 = u16::from_be_bytes([new[0], new[1]]) as u32;
    let nw1 = u16::from_be_bytes([new[2], new[3]]) as u32;
    let mut sum = (!csum) as u32 + (!ow0 & 0xffff) + (!ow1 & 0xffff) + nw0 + nw1;
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn rewrite_addr(pkt: &mut [u8], off: usize, new: [u8; 4]) {
    let old = [pkt[off], pkt[off + 1], pkt[off + 2], pkt[off + 3]];
    if old == new {
        return;
    }
    // IPv4 header checksum
    let oc = u16::from_be_bytes([pkt[10], pkt[11]]);
    let nc = csum_adjust(oc, old, new);
    pkt[10..12].copy_from_slice(&nc.to_be_bytes());
    pkt[off..off + 4].copy_from_slice(&new);

    // Transport checksum covers the pseudo-header, so apply the same delta.
    let ihl = ((pkt[0] & 0x0f) as usize) * 4;
    let frag = u16::from_be_bytes([pkt[6], pkt[7]]);
    if frag & 0x1fff != 0 {
        return; // not the first fragment
    }
    let proto = pkt[9];
    let toff = match proto {
        6 => ihl + 16,
        17 => ihl + 6,
        _ => return,
    };
    if pkt.len() < toff + 2 {
        return;
    }
    let tc = u16::from_be_bytes([pkt[toff], pkt[toff + 1]]);
    if proto == 17 && tc == 0 {
        return; // checksum disabled
    }
    let ntc = csum_adjust(tc, old, new);
    pkt[toff..toff + 2].copy_from_slice(&ntc.to_be_bytes());
}

pub fn ipv4_rewrite_src(pkt: &mut [u8], new: [u8; 4]) -> bool {
    if pkt.len() < 20 || pkt[0] >> 4 != 4 || ((pkt[0] & 0x0f) as usize) * 4 > pkt.len() {
        return false;
    }
    rewrite_addr(pkt, 12, new);
    true
}

pub fn ipv4_rewrite_dst(pkt: &mut [u8], new: [u8; 4]) -> bool {
    if pkt.len() < 20 || pkt[0] >> 4 != 4 || ((pkt[0] & 0x0f) as usize) * 4 > pkt.len() {
        return false;
    }
    rewrite_addr(pkt, 16, new);
    true
}

fn fold(mut sum: u32) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum as u16
}

/// Verify the IPv4 header checksum (sum of the header must be 0xffff).
pub fn ipv4_checksum_ok(pkt: &[u8]) -> bool {
    let ihl = ((pkt[0] & 0x0f) as usize) * 4;
    if pkt.len() < ihl {
        return false;
    }
    let mut sum = 0u32;
    for i in (0..ihl).step_by(2) {
        sum += u16::from_be_bytes([pkt[i], pkt[i + 1]]) as u32;
    }
    fold(sum) == 0xffff
}

/// Verify the TCP/UDP checksum including the pseudo-header.
pub fn transport_checksum_ok(pkt: &[u8]) -> bool {
    let ihl = ((pkt[0] & 0x0f) as usize) * 4;
    let proto = pkt[9];
    if proto != 6 && proto != 17 {
        return true;
    }
    let total = u16::from_be_bytes([pkt[2], pkt[3]]) as usize;
    if pkt.len() < total || total < ihl {
        return false;
    }
    let seg = &pkt[ihl..total];
    if proto == 17 && seg.len() >= 8 && seg[6] == 0 && seg[7] == 0 {
        return true; // UDP checksum optional
    }
    let mut sum = 0u32;
    sum += u16::from_be_bytes([pkt[12], pkt[13]]) as u32;
    sum += u16::from_be_bytes([pkt[14], pkt[15]]) as u32;
    sum += u16::from_be_bytes([pkt[16], pkt[17]]) as u32;
    sum += u16::from_be_bytes([pkt[18], pkt[19]]) as u32;
    sum += proto as u32;
    sum += seg.len() as u32;
    let mut i = 0;
    while i + 1 < seg.len() {
        sum += u16::from_be_bytes([seg[i], seg[i + 1]]) as u32;
        i += 2;
    }
    if i < seg.len() {
        sum += (seg[i] as u32) << 8;
    }
    fold(sum) == 0xffff
}

pub fn sid_hex(sid: &[u8; 8]) -> String {
    crypto::hex_encode(sid)
}

/// Minimal IPv4 helpers.
pub fn ipv4_dst(pkt: &[u8]) -> Option<[u8; 4]> {
    if pkt.len() < 20 || (pkt[0] >> 4) != 4 {
        return None;
    }
    let mut d = [0u8; 4];
    d.copy_from_slice(&pkt[16..20]);
    Some(d)
}

pub fn ipv4_src(pkt: &[u8]) -> Option<[u8; 4]> {
    if pkt.len() < 20 || (pkt[0] >> 4) != 4 {
        return None;
    }
    let mut d = [0u8; 4];
    d.copy_from_slice(&pkt[12..16]);
    Some(d)
}

pub fn parse_ipv4(s: &str) -> Option<[u8; 4]> {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    let mut ip = [0u8; 4];
    for (i, p) in parts.iter().enumerate() {
        ip[i] = p.parse::<u8>().ok()?;
    }
    Some(ip)
}

pub fn show_ipv4(ip: &[u8; 4]) -> String {
    format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3])
}
