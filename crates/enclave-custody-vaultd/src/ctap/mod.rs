//! FIDO2 `CTAP 2.1+` stack (FS-703 §3.3, ADR-013): CTAPHID framing, CTAP2
//! CBOR commands, `pinUvAuthProtocol = 2`, `hmac-secret`, assertion
//! verification, FIDO MDS allowlisting, and a software authenticator that
//! speaks the same wire protocol for hermetic CI.

pub mod assertion;
pub mod asset_enrollment;
pub mod cbor;
pub mod client;
pub mod diagnostic;
#[cfg(any(test, feature = "ctap-emulator"))]
pub mod emulator;
pub mod hid;
#[cfg(all(target_os = "macos", feature = "macos-hid"))]
pub mod macos_hid;
pub mod mds;
pub mod pin;
pub mod selected_owner;
pub mod selected_transport_lifetime;
pub mod transport;
#[cfg(any(test, feature = "simulation", feature = "ctap-emulator"))]
pub mod virtual_device;
pub mod x509;

/// Relying-party ID pinned by the enclave.
pub const RP_ID: &str = "enclave.local.internal";

/// CTAP2 command bytes.
pub mod cmd {
    /// authenticatorMakeCredential.
    pub const MAKE_CREDENTIAL: u8 = 0x01;
    /// authenticatorGetAssertion.
    pub const GET_ASSERTION: u8 = 0x02;
    /// authenticatorGetInfo.
    pub const GET_INFO: u8 = 0x04;
    /// authenticatorClientPIN.
    pub const CLIENT_PIN: u8 = 0x06;
}

/// CTAP2 status codes used here.
pub mod status {
    /// Success.
    pub const OK: u8 = 0x00;
    /// Invalid CBOR.
    pub const INVALID_CBOR: u8 = 0x12;
    /// Missing parameter.
    pub const MISSING_PARAMETER: u8 = 0x14;
    /// No credentials.
    pub const NO_CREDENTIALS: u8 = 0x2E;
    /// User action timeout.
    pub const USER_ACTION_TIMEOUT: u8 = 0x2F;
    /// Operation denied.
    pub const OPERATION_DENIED: u8 = 0x27;
    /// Invalid parameter.
    pub const INVALID_PARAMETER: u8 = 0x02;
    /// Unsupported algorithm.
    pub const UNSUPPORTED_ALGORITHM: u8 = 0x26;
    /// PIN auth invalid.
    pub const PIN_AUTH_INVALID: u8 = 0x33;
    /// Channel busy.
    pub const CHANNEL_BUSY: u8 = 0x06;
}

/// SHA-256 of the pinned RP ID.
pub fn rp_id_hash() -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(RP_ID.as_bytes()).into()
}

/// COSE algorithm identifiers.
pub mod alg {
    /// EdDSA (Ed25519), YubiKey firmware >= 5.7.
    pub const EDDSA: i64 = -8;
    /// ES256, YubiKey firmware >= 5.4.
    pub const ES256: i64 = -7;
    /// ECDH-ES + HKDF-256 (key agreement).
    pub const ECDH_ES_HKDF_256: i64 = -25;
}

pub(crate) mod selected_owner_runtime;
