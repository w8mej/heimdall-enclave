//! Bounded L1 OCI blob downloads. The endpoint and TLS trust anchor come only
//! from a separately TUF-signed configuration target. The blob digest and size
//! come only from the requested signed target, never a fetched OCI manifest.
//! This transport has no cleartext, redirect, bearer-token or proxy fallback.
use std::collections::BTreeMap;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::{Duration, Instant};
use enclave_core::error::EnclaveResult;
use enclave_core::{err, fail};
use enclave_crypto::tuf::TargetFile;
use rustls::pki_types::{CertificateDer, ServerName};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Local payload whose endpoint and trust anchors must be authenticated by TUF.
pub const DISTRIBUTION_CONFIG_TARGET: &str = "enclave-distribution-v1.json";
/// Upper bound on the complete signed distribution configuration.
pub const MAX_CONFIG_BYTES: u64 = 64 * 1024;
const MAX_HEADERS: usize = 16 * 1024;
/// Versioned signed distribution configuration. Only L1 is implemented here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DistributionConfig {
    /// Exactly one for this wire format.
    pub version: u32,
    /// Explicit L1 registry. Absence leaves network hydration unavailable.
    pub l1: Option<RegistryConfig>,
    /// Explicit encrypted OHTTP relay. Never used as a direct-origin fallback.
    #[serde(default)]
    pub l3: Option<super::oblivious::ObliviousConfig>,
    /// Explicit capability-gated QUIC peer; no origin fallback.
    #[serde(default)]
    pub l2:Option<super::quic::L2QuicConfig>,
}
/// An explicitly provisioned, TUF-authenticated TLS registry endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryConfig {
    /// Numeric socket address; avoids unbounded DNS resolution or proxy lookup.
    pub address: String,
    /// Certificate DNS name and HTTP authority (ASCII, without a port/path).
    pub server_name: String,
    /// OCI repository, without a leading slash.
    pub repository: String,
    /// One to four hex DER trust anchors. No ambient system trust is used.
    pub tls_roots_der: Vec<String>,
    /// Total TCP/TLS/header/body deadline, between 100 and 30000 milliseconds.
    pub timeout_ms: u64,
}
impl DistributionConfig {
    /// Decode a bounded signed payload and validate all supplied settings.
    pub fn parse(bytes: &[u8]) -> EnclaveResult<Self> {
        if bytes.len() as u64 > MAX_CONFIG_BYTES { fail!(E2BIG, "DISTRIBUTION_CONFIG_SIZE"); }
        let value: Self = serde_json::from_slice(bytes).map_err(|e| err!(EINVAL, "DISTRIBUTION_CONFIG", "{e}"))?;
        if value.version != 1 { fail!(EINVAL, "DISTRIBUTION_CONFIG_VERSION"); }
        if let Some(cfg) = &value.l1 { cfg.validate()?; }
        if let Some(cfg) = &value.l3 { cfg.validate()?; }
        if let Some(cfg) = &value.l2 { cfg.validate()?; }
        Ok(value)
    }
}
impl RegistryConfig {
    pub(crate) fn validate(&self) -> EnclaveResult<(SocketAddr, ServerName<'static>, Arc<rustls::ClientConfig>)> {
        let address: SocketAddr = self.address.parse().map_err(|_| err!(EINVAL, "REGISTRY_ADDRESS"))?;
        if address.port() == 0 || address.ip().is_unspecified() || address.ip().is_multicast()
            || self.server_name.is_empty() || self.server_name.len() > 253
            || !self.server_name.bytes().all(|b| b.is_ascii_alphanumeric() || b".-".contains(&b))
            || !(100..=30_000).contains(&self.timeout_ms)
        { fail!(EINVAL, "REGISTRY_CONFIG"); }
        let name = ServerName::try_from(self.server_name.clone()).map_err(|_| err!(EINVAL, "REGISTRY_SERVER_NAME"))?;
        if self.repository.is_empty() || self.repository.len() > 200
            || self.repository.split('/').any(|s| s.is_empty() || s == "." || s == ".."
                || !s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b)))
            || self.tls_roots_der.is_empty() || self.tls_roots_der.len() > 4
        { fail!(EINVAL, "REGISTRY_CONFIG"); }
        let mut roots = rustls::RootCertStore::empty();
        for der in &self.tls_roots_der {
            if der.is_empty() || der.len() > 16 * 1024 { fail!(EINVAL, "REGISTRY_TLS_ROOT"); }
            let decoded = hex::decode(der).map_err(|_| err!(EINVAL, "REGISTRY_TLS_ROOT"))?;
            roots.add(CertificateDer::from(decoded)).map_err(|_| err!(EINVAL, "REGISTRY_TLS_ROOT"))?;
        }
        let tls = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions().map_err(|_| err!(EINVAL, "REGISTRY_TLS_CONFIG"))?
            .with_root_certificates(roots).with_no_client_auth();
        Ok((address, name, Arc::new(tls)))
    }
}
// The deadline wraps the raw socket, so even a partial TLS record/handshake or
// slow-drip header cannot repeatedly reset a per-read timeout indefinitely.
pub(crate) struct DeadlineSocket { pub(crate) socket: TcpStream, pub(crate) deadline: Instant }
impl DeadlineSocket {
    fn remaining(&self) -> io::Result<Duration> {
        let left = self.deadline.saturating_duration_since(Instant::now());
        if left.is_zero() { Err(io::Error::new(io::ErrorKind::TimedOut, "registry deadline")) } else { Ok(left) }
    }
}
impl Read for DeadlineSocket {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        self.socket.set_read_timeout(Some(self.remaining()?))?;
        self.socket.read(out)
    }
}
impl Write for DeadlineSocket {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.socket.set_write_timeout(Some(self.remaining()?))?;
        self.socket.write(bytes)
    }
    fn flush(&mut self) -> io::Result<()> { self.socket.flush() }
}
/// Stream one exact signed blob into an unpublished admission stage. Every
/// callback is at most 64 KiB. The callback must discard its stage on any error.
/// Success requires TLS, strict fixed-length HTTP framing, exact EOF and both
/// complete-file digests; it is still not a publication acknowledgement.
pub fn fetch_blob(cfg: &RegistryConfig, tf: &TargetFile,
    mut accept: impl FnMut(&[u8]) -> EnclaveResult<()>) -> EnclaveResult<()> {
    crate::streaming::validate_target(tf)?;
    if tf.length == 0 { fail!(EINVAL, "REGISTRY_EMPTY_MODEL"); }
    let (address, name, tls) = cfg.validate()?;
    let deadline = Instant::now() + Duration::from_millis(cfg.timeout_ms);
    let socket = TcpStream::connect_timeout(&address, Duration::from_millis(cfg.timeout_ms))
        .map_err(|e| err!(EIO, "REGISTRY_CONNECT", "{e}"))?;
    let transport = DeadlineSocket { socket, deadline };
    let connection = rustls::ClientConnection::new(tls, name).map_err(|_| err!(EIO, "REGISTRY_TLS"))?;
    let mut stream = rustls::StreamOwned::new(connection, transport);
    // Complete authentication before writing any HTTP application bytes.
    while stream.conn.is_handshaking() {
        stream.conn.complete_io(&mut stream.sock).map_err(|e| err!(EACCES, "REGISTRY_TLS", "{e}"))?;
    }
    let sha = &tf.hashes["sha256"];
    let request = format!("GET /v2/{}/blobs/sha256:{} HTTP/1.1\r\nHost: {}:{}\r\nConnection: close\r\nAccept: application/octet-stream\r\n\r\n",
        cfg.repository, sha, cfg.server_name, address.port());
    stream.write_all(request.as_bytes()).map_err(|e| err!(EIO, "REGISTRY_WRITE", "{e}"))?;
    stream.flush().map_err(|e| err!(EIO, "REGISTRY_WRITE", "{e}"))?;
    let mut reader = stream;
    let mut header = Vec::with_capacity(1024);
    while !header.ends_with(b"\r\n\r\n") {
        if header.len() == MAX_HEADERS { fail!(E2BIG, "REGISTRY_HEADERS_SIZE"); }
        let mut byte = [0u8; 1];
        reader.read_exact(&mut byte).map_err(|e| err!(EIO, "REGISTRY_HEADERS", "{e}"))?;
        header.push(byte[0]);
    }
    let header = std::str::from_utf8(&header).map_err(|_| err!(EINVAL, "REGISTRY_HEADERS"))?;
    let mut lines = header[..header.len()-4].split("\r\n");
    let status = lines.next().ok_or_else(|| err!(EINVAL, "REGISTRY_STATUS"))?;
    let mut parts = status.splitn(3, ' ');
    if !matches!(parts.next(), Some("HTTP/1.1" | "HTTP/1.0")) || parts.next() != Some("200") {
        fail!(EACCES, "REGISTRY_STATUS");
    }
    let mut headers = BTreeMap::new();
    for (i, line) in lines.enumerate() {
        if i >= 128 { fail!(E2BIG, "REGISTRY_HEADERS_SIZE"); }
        let (key, value) = line.split_once(':').ok_or_else(|| err!(EINVAL, "REGISTRY_HEADERS"))?;
        if key.is_empty() || !key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            || value.bytes().any(|b| b.is_ascii_control() && b != b'\t')
            || headers.insert(key.to_ascii_lowercase(), value.trim()).is_some()
        { fail!(EINVAL, "REGISTRY_HEADERS"); }
    }
    if headers.contains_key("transfer-encoding")
        || headers.get("content-encoding").is_some_and(|v| *v != "identity")
    { fail!(EACCES, "REGISTRY_ENCODING"); }
    let declared = headers.get("content-length").filter(|v| !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit()))
        .and_then(|v| v.parse::<u64>().ok()).ok_or_else(|| err!(EINVAL, "REGISTRY_CONTENT_LENGTH"))?;
    if declared != tf.length { fail!(EACCES, "REGISTRY_CONTENT_LENGTH"); }
    if headers.get("docker-content-digest").is_some_and(|v| *v != format!("sha256:{sha}")) {
        fail!(EACCES, "REGISTRY_CONTENT_DIGEST");
    }
    copy_verified_body(&mut reader, tf, &mut accept, RegistryScratch::new())
}

const REGISTRY_SCRATCH_BYTES: usize = 64 * 1024;

// This current scratch span is initialized before TLS-decrypted body bytes are
// copied into it, and stays guarded through every read/hash/callback/return.
// BufReader, rustls/provider/hash state, kernel and caller stages are separate.
struct RegistryScratch {
    bytes: zeroize::Zeroizing<[u8; REGISTRY_SCRATCH_BYTES]>,
    #[cfg(test)]
    cleanup_observer: Option<Box<dyn FnOnce(&[u8])>>,
}
impl RegistryScratch {
    fn new() -> Self {
        Self {
            bytes: zeroize::Zeroizing::new([0; REGISTRY_SCRATCH_BYTES]),
            #[cfg(test)]
            cleanup_observer: None,
        }
    }
}
impl Drop for RegistryScratch {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.bytes.zeroize();
        // Only still-owned initialized storage, after wipe/fence and before
        // field cleanup; the synthetic observer never reads freed memory.
        #[cfg(test)]
        if let Some(observer) = self.cleanup_observer.take() { observer(&self.bytes[..]); }
    }
}

// Called only after the unchanged target/TLS/HTTP checks in fetch_blob. The
// private extraction keeps exact body ordering, bounds, errors and digests.
fn copy_verified_body(reader: &mut impl Read, tf: &TargetFile,
    mut accept: impl FnMut(&[u8]) -> EnclaveResult<()>, mut scratch: RegistryScratch,
) -> EnclaveResult<()> {
    let sha = &tf.hashes["sha256"];
    let mut received = 0u64;
    let mut b3 = blake3::Hasher::new(); let mut sh = Sha256::new();
    loop {
        let bound = (tf.length.saturating_sub(received) + 1).min(scratch.bytes.len() as u64) as usize;
        let n = reader.read(&mut scratch.bytes[..bound]).map_err(|e| err!(EIO, "REGISTRY_READ", "{e}"))?;
        if n == 0 { break; }
        received += n as u64;
        if received > tf.length { fail!(EACCES, "REGISTRY_LENGTH"); }
        b3.update(&scratch.bytes[..n]); sh.update(&scratch.bytes[..n]); accept(&scratch.bytes[..n])?;
    }
    if received != tf.length || blake3::Hasher::finalize(&b3).to_hex().as_str() != tf.hashes["blake3"]
        || hex::encode(sh.finalize()) != *sha
    { fail!(EACCES, "REGISTRY_CONTENT_MISMATCH"); }
    Ok(())
}

#[cfg(test)]
mod scratch_owner_tests {
    use super::*;
    use std::{cell::RefCell, rc::Rc};

    type Observations = Rc<RefCell<Vec<(usize, bool)>>>;
    fn observed() -> (RegistryScratch, Observations) {
        let events = Rc::new(RefCell::new(Vec::new()));
        let copy = events.clone();
        let mut scratch = RegistryScratch::new();
        scratch.cleanup_observer = Some(Box::new(move |bytes| {
            copy.borrow_mut().push((bytes.len(), bytes.iter().all(|byte| *byte == 0)));
        }));
        (scratch, events)
    }
    fn assert_clean(events: &Observations) {
        assert_eq!(&*events.borrow(), &[(REGISTRY_SCRATCH_BYTES, true)]);
    }
    fn payload(length: usize) -> Vec<u8> {
        (0..length).map(|i| (i % 251 + 1) as u8).collect()
    }
    fn target(bytes: &[u8]) -> TargetFile {
        TargetFile { length: bytes.len() as u64, hashes: BTreeMap::from([
            ("blake3".into(), blake3::hash(bytes).to_hex().to_string()),
            ("sha256".into(), hex::encode(Sha256::digest(bytes))),
        ]), custom: None }
    }
    struct Parts { input: io::Cursor<Vec<u8>>, chunk: usize, reads: usize, first: Option<*const u8> }
    impl Read for Parts {
        fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
            if self.reads == 0 {
                assert!(output.iter().all(|byte| *byte == 0));
                self.first = Some(output.as_ptr());
            } else { assert!(Some(output.as_ptr()) == self.first, "fixed scratch address across body reads"); }
            self.reads += 1;
            let bound = output.len().min(self.chunk);
            self.input.read(&mut output[..bound])
        }
    }
    struct FaultAfter { input: io::Cursor<Vec<u8>>, cutoff: usize, kind: io::ErrorKind, unwind: bool }
    impl Read for FaultAfter {
        fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
            let position = self.input.position() as usize;
            if position >= self.cutoff {
                output.fill(0xb9); // Cleanup covers dirty error/unwind buffers too.
                if self.unwind { panic!("synthetic registry read unwind"); }
                return Err(self.kind.into());
            }
            let bound = output.len().min(self.cutoff - position);
            self.input.read(&mut output[..bound])
        }
    }

    #[test]
    fn valid_boundary_and_multichunk_bodies_preserve_bytes_hashes_and_callback_bound() {
        for length in [1, 65535, 65536, 65537, 131089] {
            let bytes = payload(length); let tf = target(&bytes);
            for chunk in [7, REGISTRY_SCRATCH_BYTES] {
                let mut reader = Parts { input: io::Cursor::new(bytes.clone()), chunk, reads: 0, first: None };
                let (scratch, events) = observed(); let mut accepted = Vec::new();
                copy_verified_body(&mut reader, &tf, |part| {
                    assert!(!part.is_empty() && part.len() <= REGISTRY_SCRATCH_BYTES);
                    accepted.extend_from_slice(part); Ok(())
                }, scratch).unwrap();
                assert!(accepted == bytes); assert_clean(&events);
            }
        }
    }

    #[test]
    fn partial_postbody_interrupted_and_timeout_read_errors_scrub_full_stale_span() {
        let bytes = payload(65553); let tf = target(&bytes);
        for cutoff in [8, REGISTRY_SCRATCH_BYTES, bytes.len()] {
            for kind in [io::ErrorKind::Other, io::ErrorKind::Interrupted, io::ErrorKind::TimedOut] {
                let mut reader = FaultAfter { input: io::Cursor::new(bytes.clone()), cutoff, kind, unwind: false };
                let (scratch, events) = observed(); let mut accepted = 0;
                let error = copy_verified_body(&mut reader, &tf, |part| { accepted += part.len(); Ok(()) }, scratch).unwrap_err();
                assert!(error.is("REGISTRY_READ"));
                assert_eq!(accepted, cutoff); assert_clean(&events);
            }
        }
    }

    #[test]
    fn callback_cancellation_preserves_prior_handoffs_and_stops_before_another_read() {
        let bytes = payload(3 * REGISTRY_SCRATCH_BYTES + 17); let tf = target(&bytes);
        for cancelled_at in [1, 2] {
            let mut reader = Parts { input: io::Cursor::new(bytes.clone()), chunk: REGISTRY_SCRATCH_BYTES, reads: 0, first: None };
            let (scratch, events) = observed(); let mut calls = 0; let mut completed = 0;
            let error = copy_verified_body(&mut reader, &tf, |part| {
                calls += 1;
                if calls == cancelled_at { return Err(err!(EACCES, "DOWNLOAD_WIPED")); }
                completed += part.len(); Ok(())
            }, scratch).unwrap_err();
            assert!(error.is("DOWNLOAD_WIPED")); assert_eq!(calls, cancelled_at);
            assert_eq!(reader.reads, cancelled_at);
            assert_eq!(completed, (cancelled_at - 1) * REGISTRY_SCRATCH_BYTES);
            assert_clean(&events);
        }
    }

    #[test]
    fn reader_and_callback_unwind_scrub_initialized_scratch_before_deallocation() {
        let bytes = payload(65553); let tf = target(&bytes);
        let (scratch, events) = observed();
        let mut reader = FaultAfter { input: io::Cursor::new(bytes.clone()), cutoff: 8,
            kind: io::ErrorKind::Other, unwind: true };
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = copy_verified_body(&mut reader, &tf, |_| Ok(()), scratch);
        })).is_err()); assert_clean(&events);
        let (scratch, events) = observed();
        let mut reader = io::Cursor::new(bytes);
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = copy_verified_body(&mut reader, &tf, |_| panic!("synthetic registry callback unwind"), scratch);
        })).is_err()); assert_clean(&events);
    }

    #[test]
    fn short_overlong_and_independent_digest_refusals_keep_original_reasons_and_cleanup() {
        let bytes = payload(65537); let tf = target(&bytes);
        for long in [false, true] {
            let mut input = bytes.clone();
            if long { input.push(0xa7); } else { input.pop(); }
            let mut reader = io::Cursor::new(input);
            let (scratch, events) = observed(); let mut accepted = 0;
            let error = copy_verified_body(&mut reader, &tf, |part| { accepted += part.len(); Ok(()) }, scratch).unwrap_err();
            assert!(error.is(if long { "REGISTRY_LENGTH" } else { "REGISTRY_CONTENT_MISMATCH" }));
            assert!(accepted <= tf.length as usize); assert_clean(&events);
        }
        for hash in ["blake3", "sha256"] {
            let mut changed = tf.clone(); changed.hashes.insert(hash.into(), "0".repeat(64));
            let mut reader = io::Cursor::new(bytes.clone());
            let (scratch, events) = observed(); let mut accepted = 0;
            let error = copy_verified_body(&mut reader, &changed, |part| { accepted += part.len(); Ok(()) }, scratch).unwrap_err();
            assert!(error.is("REGISTRY_CONTENT_MISMATCH")); assert_eq!(accepted, bytes.len());
            assert_clean(&events);
        }
    }
}
