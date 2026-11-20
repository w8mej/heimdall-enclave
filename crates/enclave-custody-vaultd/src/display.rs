//! Native display protocol v1. Preparation carries no plaintext and precedes
//! the final release serial. Final write and shown acknowledgement share one
//! absolute two-second bound. Disconnect revokes the helper's live presentation.

use std::{io::{Read, Write}, os::unix::net::UnixStream, path::PathBuf};
use enclave_core::{codesign::{self, CodeRequirement}, error::EnclaveResult,
    ipc::Client, secret::SecretBytes, err, fail};
use crate::{biometric::DeadlineHelperStream, service::HumanDisplay};

const READY: &[u8] = b"depotMDISP/READY/1\0";
const SHOWN: &[u8] = b"depotMDISP/SHOWN/1\0";

/// Per-console native display. A connected receiver is never authority by itself;
/// custody still checks its lifecycle generation while holding the release serial.
#[derive(Debug)]
pub struct NativeHelperDisplay {
    socket_path: PathBuf,
    stream: Option<UnixStream>,
    nonce: Option<[u8; 32]>,
    ceremony_deadline: Option<u64>,
    revocation: std::sync::Arc<std::sync::Mutex<Option<UnixStream>>>,
}

impl NativeHelperDisplay {
    /// Connect on demand to this configured per-console helper endpoint.
    pub fn new(socket_path: PathBuf) -> Self {
        Self { socket_path, stream: None, nonce: None, ceremony_deadline: None,
            revocation: std::sync::Arc::default() }
    }
}

fn acknowledgement(stream: &mut DeadlineHelperStream, kind: &[u8], nonce: &[u8; 32]) -> EnclaveResult<()> {
    let mut length = [0; 4];
    stream.read_exact(&mut length).map_err(|_| err!(EIO, "DISPLAY_ACK_UNCONFIRMED"))?;
    if u32::from_be_bytes(length) as usize != kind.len() + nonce.len() {
        fail!(EACCES, "DISPLAY_ACK_PROTOCOL");
    }
    let mut body = vec![0; kind.len() + nonce.len()];
    stream.read_exact(&mut body).map_err(|_| err!(EIO, "DISPLAY_ACK_UNCONFIRMED"))?;
    if body[..kind.len()] != *kind || body[kind.len()..] != *nonce {
        fail!(EACCES, "DISPLAY_ACK_PROTOCOL");
    }
    Ok(())
}

impl HumanDisplay for NativeHelperDisplay {
    fn revocation_handle(&self) -> Option<std::sync::Arc<dyn Fn() -> EnclaveResult<()> + Send + Sync>> {
        let control = self.revocation.clone();
        Some(std::sync::Arc::new(move || {
            let stream = control.lock().map_err(|_| err!(EIO, "DISPLAY_REVOCATION_LOCK"))?.take();
            if let Some(stream) = stream {
                stream.shutdown(std::net::Shutdown::Both).map_err(|_| err!(EIO, "DISPLAY_REVOCATION_UNCONFIRMED"))?;
            }
            Ok(())
        }))
    }

    fn prepare(&mut self) -> EnclaveResult<()> {
        self.prepare_before(None)
    }

    fn prepare_before(&mut self, ceremony_deadline: Option<u64>) -> EnclaveResult<()> {
        self.clear()?;
        self.ceremony_deadline = ceremony_deadline;
        let uid = enclave_core::runtime_paths::console_uid()
            .ok_or_else(|| err!(EACCES, "NO_CONSOLE_USER"))?;
        let path = if self.socket_path == std::path::Path::new("/var/run/enclave/intent/intent.sock") {
            enclave_core::runtime_paths::intent_socket(std::path::Path::new("/var/run/enclave"), uid)
        } else { self.socket_path.clone() };
        let requirement = if codesign::enforced() {
            Some(CodeRequirement::pinned_boundary(codesign::INTENT_IDENTIFIER)?)
        } else { None };
        let now = enclave_core::clock::boot_clock_ns();
        let deadline = now.checked_add(2_000_000_000)
            .ok_or_else(|| err!(ETIMEDOUT, "DISPLAY_PREPARE_DEADLINE"))?;
        let deadline = ceremony_deadline.map_or(deadline, |ceiling| deadline.min(ceiling));
        if now >= deadline { fail!(ETIMEDOUT, "DISPLAY_PREPARE_DEADLINE"); }
        let client = Client::connect_verified_deadline(&path, uid, requirement.as_ref(),
            std::time::Duration::from_nanos(deadline - now))?;
        if enclave_core::runtime_paths::console_uid() != Some(uid) {
            fail!(EACCES, "CONSOLE_SESSION_CHANGED");
        }
        let mut stream = DeadlineHelperStream::new(client.into_authenticated_stream(), deadline)
            .map_err(|_| err!(EIO, "DISPLAY_PREPARE_IO"))?;
        let mut nonce = [0; 32]; enclave_core::rng::fill(&mut nonce);
        #[derive(serde::Serialize)]
        struct Prepare<'a> { display_protocol: &'a str, #[serde(with="serde_bytes")] nonce: &'a [u8] }
        let mut body = Vec::new();
        ciborium::into_writer(&Prepare { display_protocol: "enclave.display.v1", nonce: &nonce }, &mut body)
            .map_err(|_| err!(EIO, "DISPLAY_PREPARE_ENCODE"))?;
        stream.write_all(&(body.len() as u32).to_be_bytes()).and_then(|_| stream.write_all(&body))
            .map_err(|_| err!(EIO, "DISPLAY_PREPARE_IO"))?;
        acknowledgement(&mut stream, READY, &nonce)?;
        let stream = stream.into_stream();
        let control = stream.try_clone().map_err(|_| err!(EIO, "DISPLAY_REVOCATION_CONTROL"))?;
        *self.revocation.lock().map_err(|_| err!(EIO, "DISPLAY_REVOCATION_LOCK"))? = Some(control);
        self.stream = Some(stream); self.nonce = Some(nonce);
        Ok(())
    }

    fn clear(&mut self) -> EnclaveResult<()> {
        self.nonce = None;
        self.ceremony_deadline = None;
        if let Some(control) = self.revocation.lock().map_err(|_| err!(EIO, "DISPLAY_REVOCATION_LOCK"))?.take() {
            let _ = control.shutdown(std::net::Shutdown::Both);
        }
        if let Some(stream) = self.stream.take() { let _ = stream.shutdown(std::net::Shutdown::Both); }
        Ok(())
    }

    fn show(&mut self, _: &[SecretBytes]) -> EnclaveResult<()> {
        fail!(EPERM, "DISPLAY_REQUIRES_PREPARED_FRAME")
    }

    fn show_prepared(&mut self, _: &[SecretBytes], encoded: &[u8]) -> EnclaveResult<()> {
        let result = (|| {
        let nonce = self.nonce.take().ok_or_else(|| err!(EPERM, "DISPLAY_NOT_PREPARED"))?;
        let stream = self.stream.take().ok_or_else(|| err!(EIO, "DISPLAY_STREAM_UNAVAILABLE"))?;
        if encoded.is_empty() || encoded.len() > enclave_core::ipc::MAX_FRAME { fail!(E2BIG, "DISPLAY_FRAME_TOO_LARGE"); }
        let deadline = enclave_core::clock::boot_clock_ns().checked_add(2_000_000_000)
            .ok_or_else(|| err!(ETIMEDOUT, "DISPLAY_RELEASE_DEADLINE"))?;
        let deadline = self.ceremony_deadline.map_or(deadline, |ceiling| deadline.min(ceiling));
        let mut stream = DeadlineHelperStream::new(stream, deadline)
            .map_err(|_| err!(EIO, "DISPLAY_RELEASE_IO"))?;
        stream.write_all(&(encoded.len() as u32).to_be_bytes()).and_then(|_| stream.write_all(encoded))
            .map_err(|_| err!(EIO, "DISPLAY_RELEASE_UNCERTAIN"))?;
        acknowledgement(&mut stream, SHOWN, &nonce)?;
        self.stream = Some(stream.into_stream());
        Ok(())
        })();
        if result.is_err() { let _ = self.clear(); }
        result
    }
}

impl Drop for NativeHelperDisplay {
    fn drop(&mut self) { let _ = self.clear(); }
}

#[cfg(test)]
#[path = "display_tests.rs"]
mod tests;
