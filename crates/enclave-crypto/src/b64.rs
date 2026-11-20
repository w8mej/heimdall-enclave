//! base64url (no padding) helpers.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;

/// Encode base64url without padding.
pub fn enc(b: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(b)
}

/// Decode base64url without padding (padding or standard alphabet is rejected).
pub fn dec(s: &str) -> Option<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(s).ok()
}
