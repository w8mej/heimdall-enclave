//! `Poseidon2` width-16 sponge over the `KoalaBear` field `p = 2^31 - 2^24 + 1`
//! (FS-705 §3.5.1: rate 8, capacity 8), used for the algebraic
//! `prev_poseidon2` receipt chain in `EnclaveAuditEnvelopeV1`.
//!
//! The permutation and its round constants are Plonky3's
//! `default_koalabear_poseidon2_16()` so in-circuit `Poseidon2` chips and this
//! native implementation agree bit-for-bit.
//!
//! Byte absorption follows FS-705 §3.2 constraint 1: **3 bytes (24 bits) per
//! field element** (24-bit values are always canonical, `< p`), preceded by a
//! domain tag and the byte length decomposed into four 16-bit limbs, so no
//! two distinct `(domain, message)` pairs absorb the same element sequence.

use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_koala_bear::{default_koalabear_poseidon2_16, KoalaBear, Poseidon2KoalaBear};
use p3_symmetric::Permutation;
use std::sync::OnceLock;

/// Sponge width.
pub const WIDTH: usize = 16;
/// Sponge rate.
pub const RATE: usize = 8;
/// Digest length in field elements (8 x 31-bit ≈ 248 bits).
pub const DIGEST_ELEMS: usize = 8;
/// The KoalaBear prime.
pub const KOALABEAR_P: u32 = (1u32 << 31) - (1u32 << 24) + 1;

/// A Poseidon2 digest: 8 canonical KoalaBear limbs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct Poseidon2Digest(pub [u32; DIGEST_ELEMS]);

impl Poseidon2Digest {
    /// The all-zero genesis digest.
    pub const ZERO: Poseidon2Digest = Poseidon2Digest([0; DIGEST_ELEMS]);

    /// Big-endian hex of the 8 limbs (64 hex chars, schema `prev_poseidon2`).
    pub fn to_hex(&self) -> String {
        let mut s = String::with_capacity(64);
        for l in self.0 {
            s.push_str(&format!("{l:08x}"));
        }
        s
    }
    /// Parse the 64-hex form; every limb must be canonical (`< p`).
    pub fn from_hex(h: &str) -> Option<Self> {
        if h.len() != 64
            || !h
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            return None;
        }
        let mut out = [0u32; DIGEST_ELEMS];
        for (i, l) in out.iter_mut().enumerate() {
            let v = u32::from_str_radix(&h[i * 8..i * 8 + 8], 16).ok()?;
            if v >= KOALABEAR_P {
                return None;
            }
            *l = v;
        }
        Some(Poseidon2Digest(out))
    }
    /// Field-element view.
    pub fn to_field(&self) -> [KoalaBear; DIGEST_ELEMS] {
        self.0.map(KoalaBear::from_u32)
    }
    /// Parse from big-endian 32-byte representation.
    pub fn from_bytes(b: &[u8; 32]) -> Self {
        let mut out = [0u32; DIGEST_ELEMS];
        for (i, chunk) in b.as_chunks::<4>().0.iter().enumerate() {
            out[i] = u32::from_be_bytes(*chunk);
        }
        Poseidon2Digest(out)
    }
    /// Convert to big-endian 32-byte representation.
    pub fn to_bytes(&self) -> [u8; 32] {
        let mut b = [0u8; 32];
        for (i, limb) in self.0.iter().enumerate() {
            b[i * 4..(i + 1) * 4].copy_from_slice(&limb.to_be_bytes());
        }
        b
    }
}

fn perm() -> &'static Poseidon2KoalaBear<WIDTH> {
    static P: OnceLock<Poseidon2KoalaBear<WIDTH>> = OnceLock::new();
    P.get_or_init(default_koalabear_poseidon2_16)
}

/// Incremental sponge (overwrite-free additive absorption, rate 8).
#[derive(Clone, Debug)]
pub struct Poseidon2Sponge {
    state: [KoalaBear; WIDTH],
    pos: usize,
}

impl Default for Poseidon2Sponge {
    fn default() -> Self {
        Self::new()
    }
}

impl Poseidon2Sponge {
    /// Fresh sponge with a zero state.
    pub fn new() -> Self {
        Self {
            state: [KoalaBear::ZERO; WIDTH],
            pos: 0,
        }
    }
    /// Absorb one field element.
    pub fn absorb(&mut self, x: KoalaBear) {
        self.state[self.pos] += x;
        self.pos += 1;
        if self.pos == RATE {
            perm().permute_mut(&mut self.state);
            self.pos = 0;
        }
    }
    /// Absorb a canonical u32 (`< p`).
    pub fn absorb_u32(&mut self, x: u32) {
        debug_assert!(x < KOALABEAR_P);
        self.absorb(KoalaBear::from_u32(x));
    }
    /// Absorb a u64 as four little-endian 16-bit limbs (range-checkable in-circuit).
    pub fn absorb_u64(&mut self, x: u64) {
        for i in 0..4 {
            self.absorb_u32(((x >> (16 * i)) & 0xffff) as u32);
        }
    }
    /// Absorb a domain tag + length-framed byte string packed 24 bits per element.
    pub fn absorb_bytes(&mut self, domain: &[u8], bytes: &[u8]) {
        self.absorb_u64(domain.len() as u64);
        for c in domain.chunks(3) {
            self.absorb_u32(pack24(c));
        }
        self.absorb_u64(bytes.len() as u64);
        for c in bytes.chunks(3) {
            self.absorb_u32(pack24(c));
        }
    }
    /// Finalize: pad with a single `1` then zeros to the rate boundary, permute, squeeze 8.
    pub fn finalize(mut self) -> Poseidon2Digest {
        self.absorb(KoalaBear::ONE);
        if self.pos != 0 {
            perm().permute_mut(&mut self.state);
        }
        let mut out = [0u32; DIGEST_ELEMS];
        for (o, s) in out.iter_mut().zip(self.state.iter()) {
            *o = s.as_canonical_u32();
        }
        Poseidon2Digest(out)
    }
}

/// Pack up to 3 bytes little-endian into a 24-bit canonical element.
pub fn pack24(c: &[u8]) -> u32 {
    let mut v = 0u32;
    for (i, b) in c.iter().enumerate() {
        v |= (*b as u32) << (8 * i);
    }
    v
}

/// One-shot domain-separated hash of a byte string.
pub fn hash_bytes(domain: &[u8], bytes: &[u8]) -> Poseidon2Digest {
    let mut s = Poseidon2Sponge::new();
    s.absorb_bytes(domain, bytes);
    s.finalize()
}

/// 2-to-1 compression of two digests (Merkle inner node), domain separated.
pub fn compress(domain: &[u8], left: &Poseidon2Digest, right: &Poseidon2Digest) -> Poseidon2Digest {
    let mut s = Poseidon2Sponge::new();
    s.absorb_bytes(domain, &[]);
    for l in left.0.iter().chain(right.0.iter()) {
        s.absorb_u32(*l);
    }
    s.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_and_domain_separated() {
        let a = hash_bytes(b"MCPMac-Audit-v1", b"hello");
        let b = hash_bytes(b"MCPMac-Audit-v1", b"hello");
        assert_eq!(a, b);
        assert_ne!(a, hash_bytes(b"MCPMac-Audit-v2", b"hello"));
        assert_ne!(a, hash_bytes(b"MCPMac-Audit-v1", b"hello\0"));
        // Length framing: moving bytes between domain and message changes the digest.
        assert_ne!(hash_bytes(b"ab", b"c"), hash_bytes(b"a", b"bc"));
    }

    #[test]
    fn hex_roundtrip_and_canonical_limbs() {
        let d = hash_bytes(b"d", &[7u8; 1000]);
        let h = d.to_hex();
        assert_eq!(h.len(), 64);
        assert_eq!(Poseidon2Digest::from_hex(&h), Some(d));
        assert!(d.0.iter().all(|l| *l < KOALABEAR_P));
        // A non-canonical limb (>= p) is rejected.
        assert!(
            Poseidon2Digest::from_hex(&format!("{:08x}{}", KOALABEAR_P, "0".repeat(56))).is_none()
        );
    }

    #[test]
    fn pack24_is_injective_on_triples() {
        assert_eq!(pack24(&[1, 2, 3]), 0x030201);
        assert!(pack24(&[0xff, 0xff, 0xff]) < KOALABEAR_P);
    }
}
