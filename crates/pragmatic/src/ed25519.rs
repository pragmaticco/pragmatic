//! Ed25519 signature verification (RFC 8032 section 5.1.7), verify only.
//!
//! Pragmatic Server signs every checkpoint with an Ed25519 key, witnesses
//! cosign checkpoints with theirs, and an evidence bundle may be signed by
//! the server. The CLI, the Python native module and the server itself must
//! check those signatures against pinned public keys, and the core crate is
//! zero-dependency, so verification lives here. Signing does not: it needs
//! secret keys, constant-time code and a vetted implementation, and only
//! the server signs, using an audited crate.
//!
//! # What is accepted
//!
//! A signature `(R, S)` on message `M` under public key `A` is accepted if
//! and only if all of the following hold:
//!
//! 1. `A` and `R` are canonical point encodings (the y coordinate is below
//!    p = 2^255 - 19, and x = 0 is not encoded with the sign bit set) and
//!    decompress to points on the curve;
//! 2. neither `A` nor `R` has small order (order 1, 2, 4 or 8), checked by
//!    multiplying by the cofactor 8 and comparing with the identity;
//! 3. `S` is canonical: `S < L`, the order of the base point;
//! 4. `[S]B = R + [k]A`, where `k = SHA-512(R ‖ A ‖ M) mod L`.
//!
//! Step 4 is the *cofactorless* equation. RFC 8032 permits either it or the
//! cofactored `[8][S]B = [8]R + [8][k]A`; the two only disagree on inputs
//! with a small-order component, which an honest signer never produces.
//! Go's `crypto/ed25519`, which signs and verifies for Go's `sumdb/note`
//! (the reference signed-note implementation), uses the same equation,
//! reduces `k` mod L the same way and also requires `S < L`. It is more
//! lenient in two ways: it accepts small-order `A` and `R`, and it accepts
//! non-canonical encodings of `A`. Neither can come from an honest signer.
//! Rejecting them matters for pinned keys: with `A` of small order, one
//! `(R, S)` verifies for many messages (with `A` and `R` the identity and
//! `S = 0`, for every message), which is exactly what a log or witness key
//! must never allow.
//!
//! Rejecting non-canonical `S` (step 3) removes the classic malleability
//! where `S + L` also verifies, so nobody without the secret key can turn
//! one valid signature into another.
//!
//! # Not constant time
//!
//! Everything here is variable time: scalar multiplication branches on
//! scalar bits and decompression branches on square roots. That is safe
//! only because verification handles nothing secret (the public key, the
//! message and the signature are all public). Do not reuse this field or
//! group code for signing or key generation.
//!
//! # Implementation
//!
//! Field elements mod p use five 51-bit limbs in `u64` with `u128`
//! products, the usual representation on 64-bit targets. Points use
//! extended twisted Edwards coordinates (Hisil, Wong, Carter and Dawson,
//! 2008) with the complete `a = -1` addition formula, so there are no
//! exceptional cases. `[S]B - [k]A` is computed in one joint
//! double-and-add pass (Straus's method) and compared with `R`
//! projectively, without an inversion. Nothing is precomputed; one
//! verification takes about 55 microseconds in an optimized build on a
//! current laptop, far below the cost of fetching what it verifies.

use crate::sha512::Sha512;

/// Length of an Ed25519 public key in bytes.
pub const PUBLIC_KEY_LEN: usize = 32;

/// Length of an Ed25519 signature (`R ‖ S`) in bytes.
pub const SIGNATURE_LEN: usize = 64;

/// Verify an Ed25519 signature (RFC 8032 section 5.1.7, cofactorless, with
/// canonical encodings and small-order points rejected; see the module
/// documentation for the exact rules).
pub fn verify(public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
    verify_parts(public_key, &[message], signature)
}

/// [`verify`] for a message given as consecutive parts, so callers that
/// sign a prefix plus a body (such as `cosignature/v1`) need not copy them
/// into one buffer.
pub(crate) fn verify_parts(public_key: &[u8; 32], message: &[&[u8]], signature: &[u8; 64]) -> bool {
    let r_bytes: &[u8; 32] = signature[..32].try_into().expect("32 bytes");
    let s_bytes: &[u8; 32] = signature[32..].try_into().expect("32 bytes");
    if !scalar_is_canonical(s_bytes) {
        return false;
    }
    let Some(a) = decode_prime_order_point(public_key) else {
        return false;
    };
    let Some(r) = decode_prime_order_point(r_bytes) else {
        return false;
    };

    let mut h = Sha512::new();
    h.update(r_bytes);
    h.update(public_key);
    for part in message {
        h.update(part);
    }
    let k = reduce_scalar_wide(&h.finalize());

    // [S]B - [k]A must equal R.
    let check = double_scalar_mul(s_bytes, &base_point(), &k, &a.neg());
    check.equals(&r)
}

/// True if `public_key` is a key [`verify`] could ever accept: a canonical
/// encoding of a curve point whose order is not small. Useful for refusing
/// a bad pinned key when it is configured rather than at every check.
pub fn is_valid_public_key(public_key: &[u8; 32]) -> bool {
    decode_prime_order_point(public_key).is_some()
}

/// Decode a point and reject non-canonical encodings and small-order
/// points.
fn decode_prime_order_point(bytes: &[u8; 32]) -> Option<Point> {
    let p = Point::decode(bytes)?;
    if p.has_small_order() {
        return None;
    }
    Some(p)
}

// ---------------------------------------------------------------------------
// Field arithmetic mod p = 2^255 - 19
// ---------------------------------------------------------------------------

const MASK51: u64 = (1 << 51) - 1;

/// An element of GF(2^255 - 19) as five 51-bit limbs, least significant
/// first. Limbs may exceed 51 bits slightly between reductions; every
/// operation accepts inputs with limbs below 2^54 and returns limbs below
/// 2^52.
#[derive(Clone, Copy, Debug)]
struct Fe([u64; 5]);

/// d = -121665 / 121666, the Edwards curve constant.
const D: Fe = Fe([
    0x34dca135978a3,
    0x1a8283b156ebd,
    0x5e7a26001c029,
    0x739c663a03cbb,
    0x52036cee2b6ff,
]);

/// 2d, used by the addition formula.
const D2: Fe = Fe([
    0x69b9426b2f159,
    0x35050762add7a,
    0x3cf44c0038052,
    0x6738cc7407977,
    0x2406d9dc56dff,
]);

/// sqrt(-1) = 2^((p-1)/4), used to finish square roots.
const SQRT_M1: Fe = Fe([
    0x61b274a0ea0b0,
    0x0d5a5fc8f189d,
    0x7ef5e9cbd0c60,
    0x78595a6804c9e,
    0x2b8324804fc1d,
]);

impl Fe {
    const ZERO: Fe = Fe([0; 5]);
    const ONE: Fe = Fe([1, 0, 0, 0, 0]);

    /// Load 255 bits, little endian, ignoring bit 255. The value may be
    /// p or more; callers that need canonical input compare
    /// [`Fe::to_bytes`] with the input.
    fn from_bytes(b: &[u8; 32]) -> Fe {
        let w = |i: usize| u64::from_le_bytes(b[i * 8..i * 8 + 8].try_into().expect("8 bytes"));
        let (w0, w1, w2, w3) = (w(0), w(1), w(2), w(3));
        Fe([
            w0 & MASK51,
            (w0 >> 51 | w1 << 13) & MASK51,
            (w1 >> 38 | w2 << 26) & MASK51,
            (w2 >> 25 | w3 << 39) & MASK51,
            (w3 >> 12) & MASK51,
        ])
    }

    /// The canonical (fully reduced) 32-byte little-endian encoding.
    fn to_bytes(self) -> [u8; 32] {
        let mut l = self.carry().0;
        // Now l < 2^255 + small. Add 19 and see whether the sum reaches
        // 2^255: that happens exactly when the value is at least p, and
        // then the value minus p is the value plus 19 minus 2^255.
        let mut q = (l[0] + 19) >> 51;
        q = (l[1] + q) >> 51;
        q = (l[2] + q) >> 51;
        q = (l[3] + q) >> 51;
        q = (l[4] + q) >> 51;
        l[0] += 19 * q;
        l[1] += l[0] >> 51;
        l[0] &= MASK51;
        l[2] += l[1] >> 51;
        l[1] &= MASK51;
        l[3] += l[2] >> 51;
        l[2] &= MASK51;
        l[4] += l[3] >> 51;
        l[3] &= MASK51;
        // Dropping bit 255 subtracts the 2^255 added above.
        l[4] &= MASK51;

        let words = [
            l[0] | l[1] << 51,
            l[1] >> 13 | l[2] << 38,
            l[2] >> 26 | l[3] << 25,
            l[3] >> 39 | l[4] << 12,
        ];
        let mut out = [0u8; 32];
        for (i, w) in words.iter().enumerate() {
            out[i * 8..i * 8 + 8].copy_from_slice(&w.to_le_bytes());
        }
        out
    }

    /// Propagate carries so every limb is below 2^51, except that limb 0
    /// may exceed it by the folded top carry (19 times a small number).
    fn carry(self) -> Fe {
        let mut l = self.0;
        l[1] += l[0] >> 51;
        l[0] &= MASK51;
        l[2] += l[1] >> 51;
        l[1] &= MASK51;
        l[3] += l[2] >> 51;
        l[2] &= MASK51;
        l[4] += l[3] >> 51;
        l[3] &= MASK51;
        l[0] += 19 * (l[4] >> 51);
        l[4] &= MASK51;
        Fe(l)
    }

    fn add(self, rhs: Fe) -> Fe {
        let (a, b) = (self.0, rhs.0);
        Fe([
            a[0] + b[0],
            a[1] + b[1],
            a[2] + b[2],
            a[3] + b[3],
            a[4] + b[4],
        ])
        .carry()
    }

    fn sub(self, rhs: Fe) -> Fe {
        // Add 16p before subtracting so no limb goes negative for inputs
        // with limbs below 2^54.
        let (a, b) = (self.0, rhs.0);
        const P16_0: u64 = 16 * ((1 << 51) - 19);
        const P16_N: u64 = 16 * ((1 << 51) - 1);
        Fe([
            a[0] + P16_0 - b[0],
            a[1] + P16_N - b[1],
            a[2] + P16_N - b[2],
            a[3] + P16_N - b[3],
            a[4] + P16_N - b[4],
        ])
        .carry()
    }

    fn neg(self) -> Fe {
        Fe::ZERO.sub(self)
    }

    fn mul(self, rhs: Fe) -> Fe {
        let (a, b) = (self.0, rhs.0);
        let m = |x: u64, y: u64| u128::from(x) * u128::from(y);
        // 2^255 = 19 mod p, so limb products that land at 2^255 or above
        // fold back multiplied by 19.
        let b1 = b[1] * 19;
        let b2 = b[2] * 19;
        let b3 = b[3] * 19;
        let b4 = b[4] * 19;
        let c0 = m(a[0], b[0]) + m(a[4], b1) + m(a[3], b2) + m(a[2], b3) + m(a[1], b4);
        let c1 = m(a[1], b[0]) + m(a[0], b[1]) + m(a[4], b2) + m(a[3], b3) + m(a[2], b4);
        let c2 = m(a[2], b[0]) + m(a[1], b[1]) + m(a[0], b[2]) + m(a[4], b3) + m(a[3], b4);
        let c3 = m(a[3], b[0]) + m(a[2], b[1]) + m(a[1], b[2]) + m(a[0], b[3]) + m(a[4], b4);
        let c4 = m(a[4], b[0]) + m(a[3], b[1]) + m(a[2], b[2]) + m(a[1], b[3]) + m(a[0], b[4]);
        Fe::reduce_wide([c0, c1, c2, c3, c4])
    }

    fn square(self) -> Fe {
        self.mul(self)
    }

    /// Carry 128-bit limb sums (each below 2^115) down to 51-bit limbs.
    fn reduce_wide(c: [u128; 5]) -> Fe {
        let mask = u128::from(MASK51);
        let c1 = c[1] + (c[0] >> 51);
        let c2 = c[2] + (c1 >> 51);
        let c3 = c[3] + (c2 >> 51);
        let c4 = c[4] + (c3 >> 51);
        // The top carry can reach 2^64, so fold it in 128-bit arithmetic.
        let c0 = (c[0] & mask) + 19 * (c4 >> 51);
        let l0 = (c0 & mask) as u64;
        let l1 = (c1 & mask) as u64 + (c0 >> 51) as u64;
        Fe([
            l0,
            l1,
            (c2 & mask) as u64,
            (c3 & mask) as u64,
            (c4 & mask) as u64,
        ])
    }

    /// Square `k` times.
    fn pow2k(self, k: u32) -> Fe {
        let mut x = self;
        for _ in 0..k {
            x = x.square();
        }
        x
    }

    /// `(x^(2^250 - 1), x^11)`, the shared prefix of the inversion and
    /// square-root exponent chains (ref10's `pow22523` and `invert`).
    fn pow22501(self) -> (Fe, Fe) {
        let t0 = self.square(); // 2
        let t1 = t0.pow2k(2); // 8
        let t2 = self.mul(t1); // 9
        let t3 = t0.mul(t2); // 11
        let t4 = t3.square(); // 22
        let t5 = t2.mul(t4); // 31 = 2^5 - 1
        let t7 = t5.pow2k(5).mul(t5); // 2^10 - 1
        let t9 = t7.pow2k(10).mul(t7); // 2^20 - 1
        let t11 = t9.pow2k(20).mul(t9); // 2^40 - 1
        let t13 = t11.pow2k(10).mul(t7); // 2^50 - 1
        let t15 = t13.pow2k(50).mul(t13); // 2^100 - 1
        let t17 = t15.pow2k(100).mul(t15); // 2^200 - 1
        let t19 = t17.pow2k(50).mul(t13); // 2^250 - 1
        (t19, t3)
    }

    /// `x^((p - 5) / 8) = x^(2^252 - 3)`.
    fn pow_p58(self) -> Fe {
        let (t19, _) = self.pow22501();
        t19.pow2k(2).mul(self)
    }

    /// `x^(p - 2)`, the inverse of a nonzero `x`. Used only by tests: the
    /// verifier compares points projectively.
    #[cfg(test)]
    fn invert(self) -> Fe {
        let (t19, t3) = self.pow22501();
        t19.pow2k(5).mul(t3)
    }

    fn equals(self, rhs: Fe) -> bool {
        self.to_bytes() == rhs.to_bytes()
    }

    fn is_zero(self) -> bool {
        self.to_bytes() == [0u8; 32]
    }

    /// RFC 8032 calls x "negative" when its canonical value is odd.
    fn is_negative(self) -> bool {
        self.to_bytes()[0] & 1 == 1
    }
}

// ---------------------------------------------------------------------------
// Points on -x^2 + y^2 = 1 + d x^2 y^2 in extended coordinates
// ---------------------------------------------------------------------------

/// A point `(X : Y : Z : T)` with `x = X/Z`, `y = Y/Z` and `xy = T/Z`.
#[derive(Clone, Copy, Debug)]
struct Point {
    x: Fe,
    y: Fe,
    z: Fe,
    t: Fe,
}

/// Canonical encoding of the base point B: y = 4/5, x even.
const BASE_POINT_BYTES: [u8; 32] = [
    0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
];

fn base_point() -> Point {
    Point::decode(&BASE_POINT_BYTES).expect("the base point decodes")
}

impl Point {
    const IDENTITY: Point = Point {
        x: Fe::ZERO,
        y: Fe::ONE,
        z: Fe::ONE,
        t: Fe::ZERO,
    };

    /// Decompress per RFC 8032 section 5.1.3, rejecting non-canonical
    /// encodings: y must be below p, and x = 0 must not carry the sign
    /// bit (that would be a second encoding of the same point).
    fn decode(bytes: &[u8; 32]) -> Option<Point> {
        let x_sign = bytes[31] >> 7 == 1;
        let y = Fe::from_bytes(bytes);
        let mut masked = *bytes;
        masked[31] &= 0x7f;
        if y.to_bytes() != masked {
            return None; // y >= p
        }

        // x^2 = (y^2 - 1) / (d y^2 + 1) = u / v.
        let y2 = y.square();
        let u = y2.sub(Fe::ONE);
        let v = D.mul(y2).add(Fe::ONE);
        // Candidate root x = u v^3 (u v^7)^((p-5)/8).
        let v3 = v.square().mul(v);
        let v7 = v3.square().mul(v);
        let mut x = u.mul(v3).mul(u.mul(v7).pow_p58());
        let vx2 = v.mul(x.square());
        if vx2.equals(u) {
            // x is a root.
        } else if vx2.equals(u.neg()) {
            x = x.mul(SQRT_M1);
        } else {
            return None; // u/v is not a square: not on the curve.
        }

        if x.is_zero() && x_sign {
            return None;
        }
        if x.is_negative() != x_sign {
            x = x.neg();
        }
        Some(Point {
            x,
            y,
            z: Fe::ONE,
            t: x.mul(y),
        })
    }

    /// Canonical encoding. Tests only: verification never encodes.
    #[cfg(test)]
    fn encode(&self) -> [u8; 32] {
        let zinv = self.z.invert();
        let x = self.x.mul(zinv);
        let y = self.y.mul(zinv);
        let mut out = y.to_bytes();
        out[31] |= u8::from(x.is_negative()) << 7;
        out
    }

    /// Complete addition for a = -1 ("add-2008-hwcd-3").
    fn add(&self, q: &Point) -> Point {
        let a = self.y.sub(self.x).mul(q.y.sub(q.x));
        let b = self.y.add(self.x).mul(q.y.add(q.x));
        let c = self.t.mul(D2).mul(q.t);
        let d = self.z.add(self.z).mul(q.z);
        let e = b.sub(a);
        let f = d.sub(c);
        let g = d.add(c);
        let h = b.add(a);
        Point {
            x: e.mul(f),
            y: g.mul(h),
            z: f.mul(g),
            t: e.mul(h),
        }
    }

    /// Doubling for a = -1 ("dbl-2008-hwcd").
    fn double(&self) -> Point {
        let a = self.x.square();
        let b = self.y.square();
        let c = self.z.square().add(self.z.square());
        let h = a.add(b);
        let e = h.sub(self.x.add(self.y).square());
        let g = a.sub(b);
        let f = c.add(g);
        Point {
            x: e.mul(f),
            y: g.mul(h),
            z: f.mul(g),
            t: e.mul(h),
        }
    }

    fn neg(&self) -> Point {
        Point {
            x: self.x.neg(),
            y: self.y,
            z: self.z,
            t: self.t.neg(),
        }
    }

    /// Projective equality: `X1 Z2 = X2 Z1` and `Y1 Z2 = Y2 Z1`.
    fn equals(&self, q: &Point) -> bool {
        self.x.mul(q.z).equals(q.x.mul(self.z)) && self.y.mul(q.z).equals(q.y.mul(self.z))
    }

    fn is_identity(&self) -> bool {
        self.equals(&Point::IDENTITY)
    }

    /// True if `[8]P` is the identity, so the order of P divides 8.
    fn has_small_order(&self) -> bool {
        self.double().double().double().is_identity()
    }
}

/// `[s]P + [k]Q` by joint double-and-add over the 256 bits of both
/// little-endian scalars. Variable time.
fn double_scalar_mul(s: &[u8; 32], p: &Point, k: &[u8; 32], q: &Point) -> Point {
    let pq = p.add(q);
    let bit = |n: &[u8; 32], i: usize| (n[i / 8] >> (i % 8)) & 1 == 1;
    let mut acc = Point::IDENTITY;
    for i in (0..256).rev() {
        acc = acc.double();
        match (bit(s, i), bit(k, i)) {
            (true, true) => acc = acc.add(&pq),
            (true, false) => acc = acc.add(p),
            (false, true) => acc = acc.add(q),
            (false, false) => {}
        }
    }
    acc
}

// ---------------------------------------------------------------------------
// Scalars mod L = 2^252 + 27742317777372353535851937790883648493
// ---------------------------------------------------------------------------

/// L as four little-endian 64-bit words.
const L_WORDS: [u64; 4] = [
    0x5812631a5cf5d3ed,
    0x14def9dea2f79cd6,
    0x0000000000000000,
    0x1000000000000000,
];

/// True if the little-endian scalar is below L.
fn scalar_is_canonical(s: &[u8; 32]) -> bool {
    let w = |i: usize| u64::from_le_bytes(s[i * 8..i * 8 + 8].try_into().expect("8 bytes"));
    let words = [w(0), w(1), w(2), w(3)];
    // Compare from the most significant word down.
    for i in (0..4).rev() {
        if words[i] != L_WORDS[i] {
            return words[i] < L_WORDS[i];
        }
    }
    false // equal to L
}

/// Reduce a 512-bit little-endian integer mod L.
///
/// Bit-serial: the remainder `r < L < 2^253` is doubled and the next bit
/// added (which stays below 2^254), then L subtracted once if needed. That
/// is 512 cheap steps, negligible next to the scalar multiplication, and
/// simple enough to check by eye. Variable time, like the rest of this
/// module.
fn reduce_scalar_wide(h: &[u8; 64]) -> [u8; 32] {
    let mut r = [0u64; 4];
    for i in (0..512).rev() {
        let bit = u64::from((h[i / 8] >> (i % 8)) & 1);
        // r = 2r + bit.
        r = [
            r[0] << 1 | bit,
            r[1] << 1 | r[0] >> 63,
            r[2] << 1 | r[1] >> 63,
            r[3] << 1 | r[2] >> 63,
        ];
        if !words_below(&r, &L_WORDS) {
            r = words_sub(&r, &L_WORDS);
        }
    }
    let mut out = [0u8; 32];
    for (i, w) in r.iter().enumerate() {
        out[i * 8..i * 8 + 8].copy_from_slice(&w.to_le_bytes());
    }
    out
}

fn words_below(a: &[u64; 4], b: &[u64; 4]) -> bool {
    for i in (0..4).rev() {
        if a[i] != b[i] {
            return a[i] < b[i];
        }
    }
    false
}

/// `a - b` for `a >= b`.
fn words_sub(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
    let mut out = [0u64; 4];
    let mut borrow = false;
    for i in 0..4 {
        let (d1, b1) = a[i].overflowing_sub(b[i]);
        let (d2, b2) = d1.overflowing_sub(u64::from(borrow));
        out[i] = d2;
        borrow = b1 || b2;
    }
    debug_assert!(!borrow);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoding::{hex_decode, hex_decode_exact, hex_encode};
    use crate::json::Json;

    struct RfcVector {
        name: &'static str,
        public_key: &'static str,
        message: &'static str,
        signature: &'static str,
    }

    /// RFC 8032 section 7.1, every Ed25519 test vector, extracted
    /// mechanically from the RFC text.
    const RFC8032: &[RfcVector] = &[
        RfcVector {
            name: "1",
            public_key: "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
            message: "",
            signature: concat!(
                "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155",
                "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
            ),
        },
        RfcVector {
            name: "2",
            public_key: "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
            message: "72",
            signature: concat!(
                "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da",
                "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
            ),
        },
        RfcVector {
            name: "3",
            public_key: "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
            message: "af82",
            signature: concat!(
                "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac",
                "18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
            ),
        },
        RfcVector {
            name: "1024",
            public_key: "278117fc144c72340f67d0f2316e8386ceffbf2b2428c9c51fef7c597f1d426e",
            message: concat!(
                "08b8b2b733424243760fe426a4b54908632110a66c2f6591eabd3345e3e4eb98",
                "fa6e264bf09efe12ee50f8f54e9f77b1e355f6c50544e23fb1433ddf73be84d8",
                "79de7c0046dc4996d9e773f4bc9efe5738829adb26c81b37c93a1b270b20329d",
                "658675fc6ea534e0810a4432826bf58c941efb65d57a338bbd2e26640f89ffbc",
                "1a858efcb8550ee3a5e1998bd177e93a7363c344fe6b199ee5d02e82d522c4fe",
                "ba15452f80288a821a579116ec6dad2b3b310da903401aa62100ab5d1a36553e",
                "06203b33890cc9b832f79ef80560ccb9a39ce767967ed628c6ad573cb116dbef",
                "efd75499da96bd68a8a97b928a8bbc103b6621fcde2beca1231d206be6cd9ec7",
                "aff6f6c94fcd7204ed3455c68c83f4a41da4af2b74ef5c53f1d8ac70bdcb7ed1",
                "85ce81bd84359d44254d95629e9855a94a7c1958d1f8ada5d0532ed8a5aa3fb2",
                "d17ba70eb6248e594e1a2297acbbb39d502f1a8c6eb6f1ce22b3de1a1f40cc24",
                "554119a831a9aad6079cad88425de6bde1a9187ebb6092cf67bf2b13fd65f270",
                "88d78b7e883c8759d2c4f5c65adb7553878ad575f9fad878e80a0c9ba63bcbcc",
                "2732e69485bbc9c90bfbd62481d9089beccf80cfe2df16a2cf65bd92dd597b07",
                "07e0917af48bbb75fed413d238f5555a7a569d80c3414a8d0859dc65a46128ba",
                "b27af87a71314f318c782b23ebfe808b82b0ce26401d2e22f04d83d1255dc51a",
                "ddd3b75a2b1ae0784504df543af8969be3ea7082ff7fc9888c144da2af58429e",
                "c96031dbcad3dad9af0dcbaaaf268cb8fcffead94f3c7ca495e056a9b47acdb7",
                "51fb73e666c6c655ade8297297d07ad1ba5e43f1bca32301651339e22904cc8c",
                "42f58c30c04aafdb038dda0847dd988dcda6f3bfd15c4b4c4525004aa06eeff8",
                "ca61783aacec57fb3d1f92b0fe2fd1a85f6724517b65e614ad6808d6f6ee34df",
                "f7310fdc82aebfd904b01e1dc54b2927094b2db68d6f903b68401adebf5a7e08",
                "d78ff4ef5d63653a65040cf9bfd4aca7984a74d37145986780fc0b16ac451649",
                "de6188a7dbdf191f64b5fc5e2ab47b57f7f7276cd419c17a3ca8e1b939ae49e4",
                "88acba6b965610b5480109c8b17b80e1b7b750dfc7598d5d5011fd2dcc5600a3",
                "2ef5b52a1ecc820e308aa342721aac0943bf6686b64b2579376504ccc493d97e",
                "6aed3fb0f9cd71a43dd497f01f17c0e2cb3797aa2a2f256656168e6c496afc5f",
                "b93246f6b1116398a346f1a641f3b041e989f7914f90cc2c7fff357876e506b5",
                "0d334ba77c225bc307ba537152f3f1610e4eafe595f6d9d90d11faa933a15ef1",
                "369546868a7f3a45a96768d40fd9d03412c091c6315cf4fde7cb68606937380d",
                "b2eaaa707b4c4185c32eddcdd306705e4dc1ffc872eeee475a64dfac86aba41c",
                "0618983f8741c5ef68d3a101e8a3b8cac60c905c15fc910840b94c00a0b9d0",
            ),
            signature: concat!(
                "0aab4c900501b3e24d7cdf4663326a3a87df5e4843b2cbdb67cbf6e460fec350",
                "aa5371b1508f9f4528ecea23c436d94b5e8fcd4f681e30a6ac00a9704a188a03",
            ),
        },
        RfcVector {
            name: "SHA(abc)",
            public_key: "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf",
            message: concat!(
                "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a",
                "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
            ),
            signature: concat!(
                "dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b589",
                "09351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704",
            ),
        },
    ];

    fn decode_vector(v: &RfcVector) -> ([u8; 32], Vec<u8>, [u8; 64]) {
        (
            hex_decode_exact(v.public_key).unwrap(),
            hex_decode(v.message).unwrap(),
            hex_decode_exact(v.signature).unwrap(),
        )
    }

    #[test]
    fn rfc8032_vectors_verify() {
        assert_eq!(RFC8032.len(), 5);
        for v in RFC8032 {
            let (pk, msg, sig) = decode_vector(v);
            assert!(verify(&pk, &msg, &sig), "TEST {}", v.name);
            assert!(is_valid_public_key(&pk), "TEST {}", v.name);
        }
        // The 1024 vector's message is 1023 bytes and SHA(abc)'s is the
        // SHA-512 of "abc".
        let (_, msg, _) = decode_vector(&RFC8032[3]);
        assert_eq!(msg.len(), 1023);
        let (_, msg, _) = decode_vector(&RFC8032[4]);
        assert_eq!(msg, crate::sha512::sha512(b"abc"));
    }

    #[test]
    fn rfc8032_vectors_reject_every_single_bit_flip_in_r_s_and_a() {
        // Flipping any bit of R, S or A must fail. For S, flips of the top
        // bits make S >= L; the rest change the equation.
        for v in &RFC8032[..3] {
            let (pk, msg, sig) = decode_vector(v);
            for bit in 0..512 {
                let mut bad = sig;
                bad[bit / 8] ^= 1 << (bit % 8);
                assert!(!verify(&pk, &msg, &bad), "TEST {} sig bit {bit}", v.name);
            }
            for bit in 0..256 {
                let mut bad = pk;
                bad[bit / 8] ^= 1 << (bit % 8);
                assert!(!verify(&bad, &msg, &sig), "TEST {} key bit {bit}", v.name);
            }
        }
    }

    #[test]
    fn rfc8032_vectors_reject_altered_messages() {
        for v in RFC8032 {
            let (pk, msg, sig) = decode_vector(v);
            // Append a byte.
            let mut longer = msg.clone();
            longer.push(0);
            assert!(!verify(&pk, &longer, &sig), "TEST {}", v.name);
            // Flip a bit in the first and last byte.
            if !msg.is_empty() {
                for i in [0, msg.len() - 1] {
                    let mut bad = msg.clone();
                    bad[i] ^= 0x01;
                    assert!(!verify(&pk, &bad, &sig), "TEST {} byte {i}", v.name);
                }
                // Truncate.
                assert!(!verify(&pk, &msg[..msg.len() - 1], &sig), "TEST {}", v.name);
            }
            // Signatures do not transfer between vectors.
            for other in RFC8032 {
                if other.name != v.name {
                    let (pk2, _, _) = decode_vector(other);
                    assert!(!verify(&pk2, &msg, &sig), "{} vs {}", v.name, other.name);
                }
            }
        }
    }

    #[test]
    fn rejects_non_canonical_s() {
        // S + L is the classic malleated signature: the same equation holds
        // because [L]B is the identity, and a lenient verifier accepts it.
        let (pk, msg, sig) = decode_vector(&RFC8032[0]);
        let s: [u8; 32] = sig[32..].try_into().unwrap();
        let mut s_words = [0u64; 4];
        for (i, w) in s_words.iter_mut().enumerate() {
            *w = u64::from_le_bytes(s[i * 8..i * 8 + 8].try_into().unwrap());
        }
        let mut sum = [0u64; 4];
        let mut carry = 0u64;
        for i in 0..4 {
            let (a, c1) = s_words[i].overflowing_add(L_WORDS[i]);
            let (b, c2) = a.overflowing_add(carry);
            sum[i] = b;
            carry = u64::from(c1 || c2);
        }
        assert_eq!(carry, 0);
        let mut malleated = sig;
        for (i, w) in sum.iter().enumerate() {
            malleated[32 + i * 8..32 + i * 8 + 8].copy_from_slice(&w.to_le_bytes());
        }
        assert!(!verify(&pk, &msg, &malleated));
        // The group equation alone would accept it: with S + L reduced
        // back, it is the original signature.
        let mut wide = [0u8; 64];
        wide[..32].copy_from_slice(&malleated[32..]);
        assert_eq!(reduce_scalar_wide(&wide), s);
        assert!(verify(&pk, &msg, &sig));

        // S = L and S = 2^256 - 1 are rejected outright.
        let mut at_l = sig;
        at_l[32..].copy_from_slice(&hex_decode_exact::<32>(L_HEX).unwrap());
        assert!(!verify(&pk, &msg, &at_l));
        let mut max = sig;
        max[32..].copy_from_slice(&[0xff; 32]);
        assert!(!verify(&pk, &msg, &max));
    }

    const L_HEX: &str = "edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010";

    #[test]
    fn scalar_helpers() {
        let l = hex_decode_exact::<32>(L_HEX).unwrap();
        assert!(!scalar_is_canonical(&l));
        let mut below = l;
        below[0] -= 1;
        assert!(scalar_is_canonical(&below));
        assert!(scalar_is_canonical(&[0; 32]));
        // L mod L = 0, (L - 1) mod L = L - 1, 2^512 - 1 mod L.
        let mut wide = [0u8; 64];
        wide[..32].copy_from_slice(&l);
        assert_eq!(reduce_scalar_wide(&wide), [0; 32]);
        wide[..32].copy_from_slice(&below);
        assert_eq!(reduce_scalar_wide(&wide), below);
        // (2^512 - 1) mod L, from Python: (2**512 - 1) % L.
        assert_eq!(
            hex_encode(&reduce_scalar_wide(&[0xff; 64])),
            "000f9c44e31106a447938568a71b0ed065bef517d273ecce3d9a307c1b419903"
        );
    }

    /// The eight points of order dividing 8, canonically encoded: the
    /// identity, the point of order 2, two of order 4 and four of order 8.
    const SMALL_ORDER: [&str; 8] = [
        "0100000000000000000000000000000000000000000000000000000000000000",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000080",
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
    ];

    #[test]
    fn small_order_points_are_the_eight_torsion_points() {
        // Generate the torsion subgroup from one point of order 8 and check
        // it is exactly the list above.
        let p8 = Point::decode(&hex_decode_exact(SMALL_ORDER[4]).unwrap()).unwrap();
        let mut multiples = Vec::new();
        let mut acc = Point::IDENTITY;
        for _ in 0..8 {
            multiples.push(hex_encode(&acc.encode()));
            acc = acc.add(&p8);
        }
        assert!(acc.is_identity(), "order 8");
        multiples.sort();
        let mut expected: Vec<String> = SMALL_ORDER.iter().map(|s| s.to_string()).collect();
        expected.sort();
        assert_eq!(multiples, expected);
        for s in SMALL_ORDER {
            let p = Point::decode(&hex_decode_exact(s).unwrap()).expect(s);
            assert!(p.has_small_order(), "{s}");
            assert!(!is_valid_public_key(&hex_decode_exact(s).unwrap()), "{s}");
        }
        assert!(!base_point().has_small_order());
    }

    #[test]
    fn rejects_small_order_public_keys_and_r() {
        // With A and R the identity and S = 0, the cofactorless equation
        // [0]B = R + [k]A holds for every message. A verifier that does not
        // reject small-order points accepts this "signature" on anything.
        let identity: [u8; 32] = hex_decode_exact(SMALL_ORDER[0]).unwrap();
        let mut sig = [0u8; 64];
        sig[..32].copy_from_slice(&identity);
        for msg in [&b""[..], b"anything", b"pay mallory"] {
            assert!(!verify(&identity, msg, &sig));
        }
        // The equation itself does hold, so the rejection is the
        // small-order check and not an accident.
        let a = Point::decode(&identity).unwrap();
        let check = double_scalar_mul(&[0; 32], &base_point(), &[5; 32], &a.neg());
        assert!(check.equals(&a));

        // Every small-order key, with R = identity and S = 0, and with R
        // equal to the key itself.
        for s in SMALL_ORDER {
            let pk: [u8; 32] = hex_decode_exact(s).unwrap();
            assert!(!verify(&pk, b"m", &sig), "{s}");
            let mut sig2 = [0u8; 64];
            sig2[..32].copy_from_slice(&pk);
            assert!(!verify(&pk, b"m", &sig2), "{s}");
        }

        // A valid key with a small-order R is rejected before the equation
        // is evaluated.
        let (pk, msg, sig) = decode_vector(&RFC8032[0]);
        for s in SMALL_ORDER {
            let mut bad = sig;
            bad[..32].copy_from_slice(&hex_decode_exact::<32>(s).unwrap());
            assert!(!verify(&pk, &msg, &bad), "{s}");
        }
    }

    #[test]
    fn rejects_non_canonical_point_encodings() {
        // y = p, p + 1 and 2^255 - 1 (all >= p), with both sign bits; the
        // ones with y = p + 1 would otherwise be the identity (y = 1).
        for y in [
            "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        ] {
            let b: [u8; 32] = hex_decode_exact(y).unwrap();
            assert!(Point::decode(&b).is_none(), "{y}");
        }
        // x = 0 with the sign bit set: (0, 1) and (0, -1) written as -0.
        for y in [
            "0100000000000000000000000000000000000000000000000000000000000080",
            "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        ] {
            let b: [u8; 32] = hex_decode_exact(y).unwrap();
            assert!(Point::decode(&b).is_none(), "{y}");
        }
        // y = 2 is not on the curve (u/v is not a square).
        let mut two = [0u8; 32];
        two[0] = 2;
        assert!(Point::decode(&two).is_none());
    }

    #[test]
    fn decoding_round_trips() {
        assert_eq!(base_point().encode(), BASE_POINT_BYTES);
        for v in RFC8032 {
            let (pk, _, sig) = decode_vector(v);
            assert_eq!(Point::decode(&pk).unwrap().encode(), pk);
            let r: [u8; 32] = sig[..32].try_into().unwrap();
            assert_eq!(Point::decode(&r).unwrap().encode(), r);
        }
        // [L]B is the identity; [L - 1]B = -B.
        let l = hex_decode_exact::<32>(L_HEX).unwrap();
        let b = base_point();
        let lb = double_scalar_mul(&l, &b, &[0; 32], &Point::IDENTITY);
        assert!(lb.is_identity());
        let mut l1 = l;
        l1[0] -= 1;
        let mut one = [0u8; 32];
        one[0] = 1;
        assert!(double_scalar_mul(&l1, &b, &one, &b).is_identity());
        assert!(double_scalar_mul(&l1, &b, &[0; 32], &b).equals(&b.neg()));
    }

    #[test]
    fn field_constants() {
        let small = |n: u64| Fe([n, 0, 0, 0, 0]);
        // d * 121666 = -121665.
        assert!(D.mul(small(121666)).equals(small(121665).neg()));
        assert!(D.add(D).equals(D2));
        assert!(SQRT_M1.square().equals(Fe::ONE.neg()));
        // Inversion and reduction of p - 1 and p.
        let p_minus_1 = Fe::ONE.neg();
        assert_eq!(
            hex_encode(&p_minus_1.to_bytes()),
            "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"
        );
        let p = Fe::from_bytes(
            &hex_decode_exact("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f")
                .unwrap(),
        );
        assert!(p.is_zero());
        assert!(D.mul(D.invert()).equals(Fe::ONE));
        let x = small(7);
        assert!(x.invert().mul(x).equals(Fe::ONE));
        // Fermat: x^(p-1) = 1, with p - 1 = 8 (2^252 - 3) + 4.
        assert!(x.pow_p58().pow2k(3).mul(x.pow2k(2)).equals(Fe::ONE));
        // Euler's criterion through the square-root exponent: 7 is not a
        // square mod p, so x^((p-1)/2) = -1, with (p-1)/2 = 4 (2^252 - 3) + 2.
        assert!(x.pow_p58().pow2k(2).mul(x.square()).equals(Fe::ONE.neg()));
        // Limbs at the top of their allowed range still reduce correctly.
        let big = Fe([(1 << 52) - 1; 5]);
        assert_eq!(hex_encode(&big.to_bytes()), BIG_HEX);
        assert_eq!(hex_encode(&big.square().to_bytes()), BIG_SQUARED_HEX);
        assert_eq!(
            hex_encode(&big.mul(big.neg()).neg().to_bytes()),
            BIG_SQUARED_HEX
        );
    }

    /// v = (2^52 - 1)(1 + 2^51 + 2^102 + 2^153 + 2^204) mod p and v^2 mod p,
    /// from Python.
    const BIG_HEX: &str = "2500000000000800000000004000000000000002000000000010000000000000";
    const BIG_SQUARED_HEX: &str =
        "a50500000000180400000000401c0000000000be0000000000d0040000000000";

    /// Wycheproof's EdDSA verification vectors (C2SP/wycheproof,
    /// `testvectors_v1/ed25519_test.json`), committed as a fixture. Every
    /// case must get exactly the expected result.
    #[test]
    fn wycheproof_vectors() {
        let text = include_str!("../tests/fixtures/wycheproof/ed25519_test.json");
        let doc = Json::parse(text).expect("fixture parses as strict JSON");
        let groups = doc.get("testGroups").and_then(Json::as_array).unwrap();
        let mut counts = (0usize, 0usize);
        for group in groups {
            let pk_hex = group
                .get("publicKey")
                .and_then(|k| k.get("pk"))
                .and_then(Json::as_str)
                .unwrap();
            let pk: [u8; 32] = hex_decode_exact(pk_hex).unwrap();
            for test in group.get("tests").and_then(Json::as_array).unwrap() {
                let id = test.get("tcId").and_then(Json::as_u64).unwrap();
                let msg = hex_decode(test.get("msg").and_then(Json::as_str).unwrap()).unwrap();
                let sig = hex_decode(test.get("sig").and_then(Json::as_str).unwrap()).unwrap();
                let expected = match test.get("result").and_then(Json::as_str).unwrap() {
                    "valid" => true,
                    "invalid" => false,
                    other => panic!("tcId {id}: unexpected result {other}"),
                };
                // Signatures of the wrong length cannot be passed to
                // `verify` at all, which is a rejection.
                let got = match <[u8; 64]>::try_from(sig.as_slice()) {
                    Ok(sig) => verify(&pk, &msg, &sig),
                    Err(_) => false,
                };
                assert_eq!(got, expected, "tcId {id}");
                if expected {
                    counts.0 += 1;
                } else {
                    counts.1 += 1;
                }
            }
        }
        let total = doc.get("numberOfTests").and_then(Json::as_u64).unwrap();
        assert_eq!((counts.0 + counts.1) as u64, total);
        assert_eq!(counts, (88, 63));
    }
}
