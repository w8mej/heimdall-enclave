//! FS-703 §3.2.2 4-word BIP-39 visual short-authentication string: the top
//! 44 bits of `d_JCS` map to four 11-bit English words shown inside the
//! SIP-protected `CoreAuthUI` prompt.

use std::sync::OnceLock;

const WORDLIST: &str = include_str!("../data/bip39-english.txt");
/// SHA-256 of the canonical BIP-39 English list (bitcoin/bips).
pub const WORDLIST_SHA256: &str =
    "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda";

fn words() -> &'static [&'static str] {
    static W: OnceLock<Vec<&'static str>> = OnceLock::new();
    W.get_or_init(|| WORDLIST.lines().collect())
}

/// Four words from the top 44 bits of a 32-byte digest, joined by `-`.
pub fn sas_words(d: &[u8; 32]) -> String {
    let top = u64::from_be_bytes([d[0], d[1], d[2], d[3], d[4], d[5], 0, 0]) >> 20; // 44 bits
    let w = words();
    (0..4)
        .map(|i| w[((top >> (33 - 11 * i)) & 0x7ff) as usize])
        .collect::<Vec<_>>()
        .join("-")
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    #[test]
    fn wordlist_is_the_canonical_bip39_list() {
        assert_eq!(words().len(), 2048);
        assert_eq!(
            hex::encode(Sha256::digest(WORDLIST.as_bytes())),
            WORDLIST_SHA256
        );
    }

    #[test]
    fn deterministic_and_sensitive_to_top_bits() {
        let a = sas_words(&[0u8; 32]);
        assert_eq!(a, "abandon-abandon-abandon-abandon");
        let mut d = [0u8; 32];
        d[0] = 0xff;
        d[1] = 0xff;
        d[2] = 0xff;
        d[3] = 0xff;
        d[4] = 0xff;
        d[5] = 0xf0;
        assert_eq!(sas_words(&d), "zoo-zoo-zoo-zoo");
        d[5] = 0xe0; // bit 44 from the top flips the last word
        assert_ne!(sas_words(&d), "zoo-zoo-zoo-zoo");
    }
}
