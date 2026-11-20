//! FastCDC-v2020 content-defined chunking with a **pinned** 256-entry gear
//! table (FS-702 §3.1, F-028): `min = 16 KiB`, `avg = 64 KiB`, `max = 256 KiB`,
//! normalization level 1. Different `fastcdc` crates ship different default
//! gear tables and so produce different boundaries; depot derives its table
//! deterministically from BLAKE3-XOF(`"depot-FastCDC-Gear-v1"`) and pins its
//! SHA-256 in `enclave.lock.toml` (`tuf.fastcdc_gear_table_sha256`).

use sha2::{Digest, Sha256};
use std::sync::OnceLock;

/// Minimum chunk.
pub const MIN: usize = 16 * 1024;
/// Average chunk.
pub const AVG: usize = 64 * 1024;
/// Maximum chunk.
pub const MAX: usize = 256 * 1024;
/// Gear seed domain.
pub const GEAR_SEED: &[u8] = b"depot-FastCDC-Gear-v1";
/// Pinned SHA-256 of the gear table (big-endian u64 entries).
pub const GEAR_TABLE_SHA256: &str =
    "8b257b2c3c0b61aee68d89e9f83ec618fd2326fe26e898c4b05a69e945a4ab5f";

fn mask(bits: u32) -> u64 {
    // High bits of a left-shifting gear hash are the best mixed.
    ((1u64 << bits) - 1) << (64 - bits)
}

/// Normalization level 1: stricter mask before `avg`, looser after.
const MASK_S: u32 = 17; // log2(64 KiB) + 1
const MASK_L: u32 = 15; // log2(64 KiB) - 1

/// The gear table.
pub fn gear() -> &'static [u64; 256] {
    static G: OnceLock<[u64; 256]> = OnceLock::new();
    G.get_or_init(|| {
        let mut out = [0u64; 256];
        let mut x = blake3::Hasher::new_derive_key("depot-FastCDC-Gear-v1").finalize_xof();
        let mut buf = [0u8; 8];
        for g in out.iter_mut() {
            x.fill(&mut buf);
            *g = u64::from_be_bytes(buf);
        }
        out
    })
}

/// SHA-256 of the gear table serialised as 256 big-endian u64.
pub fn gear_table_sha256() -> String {
    let mut h = Sha256::new();
    for g in gear() {
        h.update(g.to_be_bytes());
    }
    hex::encode(h.finalize())
}

/// Length of the next chunk starting at `data[0]`.
pub fn cut_point(data: &[u8]) -> usize {
    let n = data.len();
    if n <= MIN {
        return n;
    }
    let end = n.min(MAX);
    let normal = end.min(AVG);
    let g = gear();
    let (ms, ml) = (mask(MASK_S), mask(MASK_L));
    let mut h: u64 = 0;
    let mut i = MIN;
    while i < normal {
        h = (h << 1).wrapping_add(g[data[i] as usize]);
        if h & ms == 0 {
            return i + 1;
        }
        i += 1;
    }
    while i < end {
        h = (h << 1).wrapping_add(g[data[i] as usize]);
        if h & ml == 0 {
            return i + 1;
        }
        i += 1;
    }
    end
}

/// Chunk boundaries `(offset, len)`.
pub fn chunks(data: &[u8]) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let mut off = 0;
    while off < data.len() {
        let l = cut_point(&data[off..]);
        out.push((off, l));
        off += l;
    }
    out
}

/// Deterministic conformance input (1 MiB BLAKE3-XOF stream).
pub fn test_vector_input() -> Vec<u8> {
    let mut v = vec![0u8; 1024 * 1024];
    blake3::Hasher::new_derive_key("depot-FastCDC-TestVector-v1")
        .finalize_xof()
        .fill(&mut v);
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Conformance vector, cross-checked against an independent Python
    /// implementation (BLAKE3 `derive_key` + the same gear recurrence).
    pub const VECTOR_1MIB: &[(usize, usize)] = &[
        (0, 66807),
        (66807, 82156),
        (148963, 16797),
        (165760, 139457),
        (305217, 76591),
        (381808, 68627),
        (450435, 120198),
        (570633, 91342),
        (661975, 81553),
        (743528, 109441),
        (852969, 85696),
        (938665, 60730),
        (999395, 49181),
    ];

    #[test]
    fn gear_table_and_test_vector_are_pinned() {
        assert_eq!(gear_table_sha256(), GEAR_TABLE_SHA256);
        let d = test_vector_input();
        assert_eq!(chunks(&d), VECTOR_1MIB);
        assert_eq!(
            blake3::hash(&d).to_hex().as_str(),
            "56d5e01b8c389d8b6ac8734968a88c0c5c80ef0aaba2b8ea3a927db198c3ba7b"
        );
    }

    #[test]
    fn bounds_respected_and_covering() {
        let d = test_vector_input();
        let cs = chunks(&d);
        let mut total = 0;
        for (i, (o, l)) in cs.iter().enumerate() {
            assert_eq!(*o, total);
            assert!(*l <= MAX);
            if i + 1 < cs.len() {
                assert!(*l > MIN);
            }
            total += l;
        }
        assert_eq!(total, d.len());
    }

    #[test]
    fn local_edit_preserves_most_boundaries() {
        let mut d = test_vector_input();
        d.extend(test_vector_input());
        let before: Vec<usize> = chunks(&d).iter().map(|(o, _)| *o).collect();
        d[1_500_000] ^= 0xff;
        let after: Vec<usize> = chunks(&d).iter().map(|(o, _)| *o).collect();
        let shared = before.iter().filter(|o| after.contains(o)).count();
        assert!(shared + 2 >= before.len(), "{shared} of {}", before.len());
    }
}
