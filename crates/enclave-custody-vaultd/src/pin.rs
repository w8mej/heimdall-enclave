//! L3-only trusted existing-PIN input. The provider never caches/retries a PIN
//! and never places it in diagnostics, command arguments or process environment.

use std::{io::Write, path::PathBuf};
use enclave_core::{error::EnclaveResult, secret::SecretBytes, err, fail};
use serde::{Deserialize, Serialize};
use crate::biometric::{connect_helper_stream, BiometricPrompt, MAX_HELPER_FRAME};

/// Existing-PIN input boundary. Callers enforce L3 and the original ceremony
/// budget; cancellation/absence must return before any authenticator PIN attempt.
pub trait ExistingPinProvider: std::fmt::Debug + Send {
    /// Collect exactly one existing PIN for this fresh trusted intent.
    fn read_existing_pin(&mut self, prompt: &BiometricPrompt) -> EnclaveResult<SecretBytes>;
    /// Observe lifecycle cancellation while awaiting trusted input. Native
    /// providers interrupt their local reads and disconnect the prompt.
    fn read_existing_pin_cancellable(&mut self, prompt: &BiometricPrompt,
        cancelled: &std::sync::atomic::AtomicBool) -> EnclaveResult<SecretBytes> {
        if cancelled.load(std::sync::atomic::Ordering::Acquire) { fail!(EACCES, "FIDO_PIN_CEREMONY_CANCELLED"); }
        let pin = self.read_existing_pin(prompt)?;
        if cancelled.load(std::sync::atomic::Ordering::Acquire) { fail!(EACCES, "FIDO_PIN_CEREMONY_CANCELLED"); }
        Ok(pin)
    }
}

/// On-demand current-console provider with reciprocal code/session verification.
#[derive(Debug)]
pub struct NativeExistingPinProvider { socket_path: PathBuf }

impl NativeExistingPinProvider {
    /// Use the configured protected per-console intent socket.
    pub fn new(socket_path: PathBuf) -> Self { Self { socket_path } }
}

#[derive(Serialize)]
struct PinRequest<'a> {
    pin_protocol: &'static str,
    #[serde(with="serde_bytes")]
    nonce: &'a [u8],
    t_start_ns: u64,
    reason: &'a str,
}

fn secret_pin<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<Option<SecretBytes>, D::Error> {
    Option::<serde_bytes::ByteBuf>::deserialize(deserializer)
        .map(|bytes| bytes.map(|bytes| SecretBytes::new(bytes.into_vec())))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PinReply {
    pin_protocol: String,
    #[serde(with="serde_bytes")]
    nonce: Vec<u8>,
    #[serde(deserialize_with="secret_pin")]
    pin: Option<SecretBytes>,
}

fn decode_reply(bytes: &[u8], nonce: &[u8]) -> EnclaveResult<SecretBytes> {
    let mut cursor = std::io::Cursor::new(bytes);
    let reply: PinReply = ciborium::from_reader(&mut cursor)
        .map_err(|_| err!(EACCES, "FIDO_PIN_HELPER_PROTOCOL"))?;
    if cursor.position() != bytes.len() as u64 || reply.pin_protocol != "enclave.pin.v1" || reply.nonce != nonce {
        fail!(EACCES, "FIDO_PIN_HELPER_PROTOCOL");
    }
    let pin = reply.pin.ok_or_else(|| err!(EACCES, "FIDO_PIN_USER_CANCELLED"))?;
    if !(4..=63).contains(&pin.len()) || pin.expose().contains(&0)
        || std::str::from_utf8(pin.expose()).is_err()
    { fail!(EACCES, "FIDO_PIN_INPUT_INVALID"); }
    Ok(pin)
}

impl ExistingPinProvider for NativeExistingPinProvider {
    fn read_existing_pin(&mut self, prompt: &BiometricPrompt) -> EnclaveResult<SecretBytes> {
        self.read_existing_pin_cancellable(prompt, &std::sync::atomic::AtomicBool::new(false))
    }

    fn read_existing_pin_cancellable(&mut self, prompt: &BiometricPrompt,
        cancelled: &std::sync::atomic::AtomicBool) -> EnclaveResult<SecretBytes> {
        if cancelled.load(std::sync::atomic::Ordering::Acquire) { fail!(EACCES, "FIDO_PIN_CEREMONY_CANCELLED"); }
        if prompt.d_jcs.len() != 32 || prompt.nonce.len() != 32 { fail!(EINVAL, "FIDO_PIN_CHALLENGE_LENGTH"); }
        let mut stream = connect_helper_stream(&self.socket_path, prompt)?;
        let request = PinRequest { pin_protocol: "enclave.pin.v1", nonce: &prompt.nonce,
            t_start_ns: prompt.t_start_ns, reason: &prompt.localized_reason };
        let mut body = Vec::new();
        ciborium::into_writer(&request, &mut body).map_err(|_| err!(EIO, "FIDO_PIN_HELPER_PROTOCOL"))?;
        if body.len() > MAX_HELPER_FRAME { fail!(E2BIG, "FIDO_PIN_HELPER_PROTOCOL"); }
        stream.write_all(&(body.len() as u32).to_be_bytes()).and_then(|_| stream.write_all(&body))
            .map_err(|_| err!(EIO, "FIDO_PIN_HELPER_IO"))?;
        let mut length = [0; 4];
        let read_error = |_| if cancelled.load(std::sync::atomic::Ordering::Acquire) {
            err!(EACCES, "FIDO_PIN_CEREMONY_CANCELLED")
        } else { err!(EIO, "FIDO_PIN_HELPER_IO") };
        stream.read_exact_cancellable(&mut length, cancelled).map_err(read_error)?;
        let length = u32::from_be_bytes(length) as usize;
        if length == 0 || length > 256 { fail!(E2BIG, "FIDO_PIN_HELPER_PROTOCOL"); }
        let mut response = zeroize::Zeroizing::new(vec![0; length]);
        stream.read_exact_cancellable(&mut response, cancelled).map_err(read_error)?;
        decode_reply(&response, &prompt.nonce)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn reply(protocol: &str, nonce: &[u8], pin: Option<&[u8]>) -> Vec<u8> {
        #[derive(Serialize)]
        struct Reply<'a> { pin_protocol: &'a str, #[serde(with="serde_bytes")] nonce: &'a [u8], pin: Option<serde_bytes::ByteBuf> }
        let mut bytes = Vec::new();
        ciborium::into_writer(&Reply { pin_protocol: protocol, nonce, pin: pin.map(|pin| serde_bytes::ByteBuf::from(pin.to_vec())) }, &mut bytes).unwrap();
        bytes
    }
    #[test]
    fn pin_reply_is_typed_bound_single_value_and_redacted() {
        let nonce = [3; 32];
        let valid = reply("enclave.pin.v1", &nonce, Some(b"synthetic-test-pin"));
        let pin = decode_reply(&valid, &nonce).unwrap();
        assert_eq!(pin.expose(), b"synthetic-test-pin");
        assert!(!format!("{pin:?}").contains("synthetic"));
        assert!(decode_reply(&valid, &[4; 32]).is_err());
        assert!(decode_reply(&reply("enclave.pin.v0", &nonce, Some(b"synthetic")), &nonce).is_err());
        for input in [b"".as_slice(), b"123", b"synthetic\0pin", &[0xff; 4], &[b'x'; 64]] {
            assert!(decode_reply(&reply("enclave.pin.v1", &nonce, Some(input)), &nonce).unwrap_err().is("FIDO_PIN_INPUT_INVALID"));
        }
        assert!(decode_reply(&reply("enclave.pin.v1", &nonce, None), &nonce).unwrap_err().is("FIDO_PIN_USER_CANCELLED"));
        let mut trailing = valid; trailing.push(0);
        assert!(decode_reply(&trailing, &nonce).is_err());
    }
}
