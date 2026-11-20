//! OS CSPRNG access (getrandom via `rand_core::OsRng`). Panics are impossible
//! to recover from safely here, so a CSPRNG failure aborts the process
//! (fail closed) rather than returning predictable bytes.

use rand_core::{OsRng, RngCore};

/// Fill `buf` from the OS CSPRNG.
pub fn fill(buf: &mut [u8]) {
    if OsRng.try_fill_bytes(buf).is_err() {
        // A daemon without entropy must not mint keys, nonces or surrogates.
        std::process::abort();
    }
}

/// 32 random bytes.
pub fn bytes32() -> [u8; 32] {
    let mut b = [0u8; 32];
    fill(&mut b);
    b
}

/// A random u64.
pub fn u64() -> u64 {
    let mut b = [0u8; 8];
    fill(&mut b);
    u64::from_le_bytes(b)
}
