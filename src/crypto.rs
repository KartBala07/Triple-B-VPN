//! Dependency-free crypto primitives for HermesVPN.
//!
//! Implements, from the RFCs:
//!   * SHA-256            (FIPS 180-4)
//!   * HMAC-SHA256        (RFC 2104)
//!   * HKDF-SHA256        (RFC 5869)
//!   * ChaCha20           (RFC 8439 §2.3)
//!   * Poly1305           (RFC 8439 §2.5)
//!   * AEAD_CHACHA20_POLY1305 (RFC 8439 §2.8)
//!
//! `hvpn selftest` checks every primitive against the official test vectors.

use core::convert::TryInto;

// ---------------------------------------------------------------- SHA-256

const K256: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ];
    let mut msg = data.to_vec();
    let bitlen = (data.len() as u64).wrapping_mul(8);
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bitlen.to_be_bytes());

    for block in msg.chunks_exact(64) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes(block[i * 4..i * 4 + 4].try_into().unwrap());
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh) =
            (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K256[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }

    let mut out = [0u8; 32];
    for i in 0..8 {
        out[i * 4..i * 4 + 4].copy_from_slice(&h[i].to_be_bytes());
    }
    out
}

// ---------------------------------------------------------------- HMAC-SHA256

pub fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut k = [0u8; 64];
    if key.len() > 64 {
        k[..32].copy_from_slice(&sha256(key));
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for i in 0..64 {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }
    let mut inner = ipad.to_vec();
    inner.extend_from_slice(msg);
    let ih = sha256(&inner);
    let mut outer = opad.to_vec();
    outer.extend_from_slice(&ih);
    sha256(&outer)
}

/// RFC 5869 HKDF-SHA256.
pub fn hkdf_sha256(salt: &[u8], ikm: &[u8], info: &[u8], out: &mut [u8]) {
    let prk = hmac_sha256(salt, ikm);
    let mut t: Vec<u8> = Vec::new();
    let mut pos = 0usize;
    let mut counter: u8 = 1;
    while pos < out.len() {
        let mut m = t.clone();
        m.extend_from_slice(info);
        m.push(counter);
        t = hmac_sha256(&prk, &m).to_vec();
        let n = core::cmp::min(t.len(), out.len() - pos);
        out[pos..pos + n].copy_from_slice(&t[..n]);
        pos += n;
        counter = counter.wrapping_add(1);
    }
}

// ---------------------------------------------------------------- ChaCha20

fn quarter_round(s: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    s[a] = s[a].wrapping_add(s[b]);
    s[d] = (s[d] ^ s[a]).rotate_left(16);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_left(12);
    s[a] = s[a].wrapping_add(s[b]);
    s[d] = (s[d] ^ s[a]).rotate_left(8);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_left(7);
}

pub fn chacha20_block(key: &[u8; 32], nonce: &[u8; 12], counter: u32) -> [u8; 64] {
    let mut s = [0u32; 16];
    s[0] = 0x61707865;
    s[1] = 0x3320646e;
    s[2] = 0x79622d32;
    s[3] = 0x6b206574;
    for i in 0..8 {
        s[4 + i] = u32::from_le_bytes(key[i * 4..i * 4 + 4].try_into().unwrap());
    }
    s[12] = counter;
    for i in 0..3 {
        s[13 + i] = u32::from_le_bytes(nonce[i * 4..i * 4 + 4].try_into().unwrap());
    }
    let init = s;
    for _ in 0..10 {
        quarter_round(&mut s, 0, 4, 8, 12);
        quarter_round(&mut s, 1, 5, 9, 13);
        quarter_round(&mut s, 2, 6, 10, 14);
        quarter_round(&mut s, 3, 7, 11, 15);
        quarter_round(&mut s, 0, 5, 10, 15);
        quarter_round(&mut s, 1, 6, 11, 12);
        quarter_round(&mut s, 2, 7, 8, 13);
        quarter_round(&mut s, 3, 4, 9, 14);
    }
    let mut out = [0u8; 64];
    for i in 0..16 {
        let v = s[i].wrapping_add(init[i]);
        out[i * 4..i * 4 + 4].copy_from_slice(&v.to_le_bytes());
    }
    out
}

pub fn chacha20_apply(key: &[u8; 32], nonce: &[u8; 12], counter: u32, data: &mut [u8]) {
    let mut ctr = counter;
    for chunk in data.chunks_mut(64) {
        let ks = chacha20_block(key, nonce, ctr);
        for i in 0..chunk.len() {
            chunk[i] ^= ks[i];
        }
        ctr = ctr.wrapping_add(1);
    }
}

// ---------------------------------------------------------------- Poly1305

fn le32(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

/// Poly1305 one-time authenticator (26-bit limb implementation).
pub fn poly1305(key: &[u8], msg: &[u8]) -> [u8; 16] {
    let t0 = le32(key, 0) as u64;
    let t1 = le32(key, 4) as u64;
    let t2 = le32(key, 8) as u64;
    let t3 = le32(key, 12) as u64;

    let r0 = t0 & 0x3ffffff;
    let r1 = ((t0 >> 26) | (t1 << 6)) & 0x3ffff03;
    let r2 = ((t1 >> 20) | (t2 << 12)) & 0x3ffc0ff;
    let r3 = ((t2 >> 14) | (t3 << 18)) & 0x3f03fff;
    let r4 = (t3 >> 8) & 0x00fffff;

    let s1 = r1 * 5;
    let s2 = r2 * 5;
    let s3 = r3 * 5;
    let s4 = r4 * 5;

    let mut h0: u64 = 0;
    let mut h1: u64 = 0;
    let mut h2: u64 = 0;
    let mut h3: u64 = 0;
    let mut h4: u64 = 0;

    for chunk in msg.chunks(16) {
        let mut block = [0u8; 16];
        block[..chunk.len()].copy_from_slice(chunk);
        let hibit: u64 = if chunk.len() == 16 {
            1u64 << 24
        } else {
            block[chunk.len()] = 1;
            0
        };
        let m0 = le32(&block, 0) as u64;
        let m1 = le32(&block, 4) as u64;
        let m2 = le32(&block, 8) as u64;
        let m3 = le32(&block, 12) as u64;

        h0 += m0 & 0x3ffffff;
        h1 += ((m0 >> 26) | (m1 << 6)) & 0x3ffffff;
        h2 += ((m1 >> 20) | (m2 << 12)) & 0x3ffffff;
        h3 += ((m2 >> 14) | (m3 << 18)) & 0x3ffffff;
        h4 += (m3 >> 8) | hibit;

        let d0 = h0 * r0 + h1 * s4 + h2 * s3 + h3 * s2 + h4 * s1;
        let d1 = h0 * r1 + h1 * r0 + h2 * s4 + h3 * s3 + h4 * s2;
        let d2 = h0 * r2 + h1 * r1 + h2 * r0 + h3 * s4 + h4 * s3;
        let d3 = h0 * r3 + h1 * r2 + h2 * r1 + h3 * r0 + h4 * s4;
        let d4 = h0 * r4 + h1 * r3 + h2 * r2 + h3 * r1 + h4 * r0;

        let mut c = d0 >> 26;
        h0 = d0 & 0x3ffffff;
        let d1 = d1 + c;
        c = d1 >> 26;
        h1 = d1 & 0x3ffffff;
        let d2 = d2 + c;
        c = d2 >> 26;
        h2 = d2 & 0x3ffffff;
        let d3 = d3 + c;
        c = d3 >> 26;
        h3 = d3 & 0x3ffffff;
        let d4 = d4 + c;
        c = d4 >> 26;
        h4 = d4 & 0x3ffffff;
        h0 += c * 5;
        c = h0 >> 26;
        h0 &= 0x3ffffff;
        h1 += c;
    }

    // full carry
    let mut c = h1 >> 26;
    h1 &= 0x3ffffff;
    h2 += c;
    c = h2 >> 26;
    h2 &= 0x3ffffff;
    h3 += c;
    c = h3 >> 26;
    h3 &= 0x3ffffff;
    h4 += c;
    c = h4 >> 26;
    h4 &= 0x3ffffff;
    h0 += c * 5;
    c = h0 >> 26;
    h0 &= 0x3ffffff;
    h1 += c;

    // compute h + -p
    let mut g0 = h0 + 5;
    c = g0 >> 26;
    g0 &= 0x3ffffff;
    let mut g1 = h1 + c;
    c = g1 >> 26;
    g1 &= 0x3ffffff;
    let mut g2 = h2 + c;
    c = g2 >> 26;
    g2 &= 0x3ffffff;
    let mut g3 = h3 + c;
    c = g3 >> 26;
    g3 &= 0x3ffffff;
    let g4 = (h4 + c).wrapping_sub(1u64 << 26);

    // select h if h < p, else g  (mask = all-ones when g4 did not underflow)
    let mask = (g4 >> 63).wrapping_sub(1);
    h0 = (h0 & !mask) | (g0 & mask);
    h1 = (h1 & !mask) | (g1 & mask);
    h2 = (h2 & !mask) | (g2 & mask);
    h3 = (h3 & !mask) | (g3 & mask);
    h4 = (h4 & !mask) | (g4 & mask);

    // h = h + pad
    let mut f: u64;
    let mut o = [0u8; 16];
    f = h0 | (h1 << 26);
    let w0 = f as u32;
    f = (f >> 32) | (h2 << 20);
    let w1 = f as u32;
    f = (f >> 32) | (h3 << 14);
    let w2 = f as u32;
    f = (f >> 32) | (h4 << 8);
    let w3 = f as u32;

    let mut f = w0 as u64 + le32(key, 16) as u64;
    o[0..4].copy_from_slice(&(f as u32).to_le_bytes());
    f >>= 32;
    f += w1 as u64 + le32(key, 20) as u64;
    o[4..8].copy_from_slice(&(f as u32).to_le_bytes());
    f >>= 32;
    f += w2 as u64 + le32(key, 24) as u64;
    o[8..12].copy_from_slice(&(f as u32).to_le_bytes());
    f >>= 32;
    f += w3 as u64 + le32(key, 28) as u64;
    o[12..16].copy_from_slice(&(f as u32).to_le_bytes());
    o
}

// ---------------------------------------------------------------- AEAD

fn pad16(v: &mut Vec<u8>) {
    while v.len() % 16 != 0 {
        v.push(0);
    }
}

/// Encrypt+authenticate. Returns ciphertext || 16-byte tag.
pub fn aead_seal(key: &[u8; 32], nonce: &[u8; 12], aad: &[u8], pt: &[u8]) -> Vec<u8> {
    let block = chacha20_block(key, nonce, 0);
    let mut poly_key = [0u8; 32];
    poly_key.copy_from_slice(&block[..32]);

    let mut ct = pt.to_vec();
    chacha20_apply(key, nonce, 1, &mut ct);

    let mut mac = Vec::with_capacity(aad.len() + ct.len() + 48);
    mac.extend_from_slice(aad);
    pad16(&mut mac);
    mac.extend_from_slice(&ct);
    pad16(&mut mac);
    mac.extend_from_slice(&(aad.len() as u64).to_le_bytes());
    mac.extend_from_slice(&(ct.len() as u64).to_le_bytes());

    let tag = poly1305(&poly_key, &mac);
    ct.extend_from_slice(&tag);
    ct
}

pub fn aead_open(key: &[u8; 32], nonce: &[u8; 12], aad: &[u8], sealed: &[u8]) -> Option<Vec<u8>> {
    if sealed.len() < 16 {
        return None;
    }
    let (ct, tag) = sealed.split_at(sealed.len() - 16);
    let block = chacha20_block(key, nonce, 0);
    let mut poly_key = [0u8; 32];
    poly_key.copy_from_slice(&block[..32]);

    let mut mac = Vec::with_capacity(aad.len() + ct.len() + 48);
    mac.extend_from_slice(aad);
    pad16(&mut mac);
    mac.extend_from_slice(ct);
    pad16(&mut mac);
    mac.extend_from_slice(&(aad.len() as u64).to_le_bytes());
    mac.extend_from_slice(&(ct.len() as u64).to_le_bytes());

    let expect = poly1305(&poly_key, &mac);
    // constant-time compare
    let mut diff = 0u8;
    for i in 0..16 {
        diff |= expect[i] ^ tag[i];
    }
    if diff != 0 {
        return None;
    }
    let mut pt = ct.to_vec();
    chacha20_apply(key, nonce, 1, &mut pt);
    Some(pt)
}

// ---------------------------------------------------------------- helpers

pub fn hex_encode(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push_str(&format!("{:02x}", x));
    }
    s
}

pub fn hex_decode(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    for i in (0..s.len()).step_by(2) {
        let hi = (bytes[i] as char).to_digit(16)?;
        let lo = (bytes[i + 1] as char).to_digit(16)?;
        out.push((hi * 16 + lo) as u8);
    }
    Some(out)
}

pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut d = 0u8;
    for i in 0..a.len() {
        d |= a[i] ^ b[i];
    }
    d == 0
}
