//! Darwin `CoreAuthUI` / `LAContext` bridge (ADR-010, FS-703 §3.4 step 1).
//!
//! `UID 703` never renders UI. The stateless `_enclaveintent` helper
//! (`uid=501`) shows the anti-occluded intent sheet, evaluates `LAContext`
//! against the SEP `.biometryCurrentSet` P-256 key owned by `UID 703`, and
//! returns a [`BiometricOutcome`]. Whatever the transport, the daemon trusts
//! only the **SEP signature** `σ_SEP = Sign_SEP(d_JCS ‖ nonce ‖ t_start_ns)`
//! verified against the enrolled public key — never a boolean.
//!
//! [`ScriptedCoreAuthUi`] is the CI provider: it holds a software P-256 key
//! and produces genuine signatures for scripted outcomes. [`HelperBridge`]
//! is the production transport to `_enclaveintent` over a length-prefixed
//! CBOR stream.

#[cfg(any(test, feature = "simulation"))]
use std::collections::VecDeque;
use std::io::{Read, Write};

use enclave_core::error::EnclaveResult;
use enclave_core::{err, fail};
use p256::ecdsa::signature::Verifier;
#[cfg(any(test, feature = "simulation"))]
use p256::ecdsa::{signature::Signer, SigningKey};
use p256::ecdsa::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// Mandatory unoccluded human-read dwell before arming (FS-703 §5.1.3).
pub const DWELL_NS: u64 = 500_000_000;

/// What the helper is asked to show and sign.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BiometricPrompt {
    /// `LAContext.localizedReason` (includes the SAS words).
    pub localized_reason: String,
    /// `d_JCS`.
    #[serde(with = "serde_bytes")]
    pub d_jcs: Vec<u8>,
    /// Enclave nonce.
    #[serde(with = "serde_bytes")]
    pub nonce: Vec<u8>,
    /// Ceremony start (`mach_continuous_time` ns).
    pub t_start_ns: u64,
    /// Encrypted SEP key blob (`kSecAttrTokenOID`), handed to the helper per request (Design D2).
    #[serde(default, with = "serde_bytes")]
    pub bio_key_blob: Vec<u8>,
}

impl BiometricPrompt {
    /// Bytes signed by the SEP key.
    pub fn signed_message(&self) -> Vec<u8> {
        let mut m = self.d_jcs.clone();
        m.extend_from_slice(&self.nonce);
        m.extend_from_slice(&self.t_start_ns.to_be_bytes());
        m
    }
}

mod opt_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(opt: &Option<Vec<u8>>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match opt {
            Some(b) => serializer.serialize_bytes(b),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Vec<u8>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        Option::<serde_bytes::ByteBuf>::deserialize(deserializer)
            .map(|opt| opt.map(|b| b.into_vec()))
    }
}

/// Helper outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BiometricOutcome {
    /// Live fingerprint match; SEP signature over the prompt.
    Approved {
        /// DER or raw `r‖s` P-256 signature.
        #[serde(with = "serde_bytes")]
        sep_signature: Vec<u8>,
        /// When the sheet became unoccluded and visible.
        visible_at_ns: u64,
        /// When the biometric completed.
        approved_at_ns: u64,
        /// Enrolled public key (present during custodian enrollment).
        #[serde(default, skip_serializing_if = "Option::is_none", with = "opt_bytes")]
        enrolled_pubkey: Option<Vec<u8>>,
        /// Enrolled SEP token-object blob (present during custodian enrollment).
        #[serde(default, skip_serializing_if = "Option::is_none", with = "opt_bytes")]
        enrolled_blob: Option<Vec<u8>>,
    },
    /// User cancelled.
    Cancelled,
    /// No interaction before the deadline.
    TimedOut,
    /// Another window overlapped the sheet (`UI_OCCLUSION_ABORT`).
    Occluded,
    /// User pressed "Report Suspicious Prompt".
    ReportSuspicious,
}

/// A biometric provider.
pub trait BiometricProvider: std::fmt::Debug {
    /// Present the prompt and return the outcome.
    fn evaluate(&mut self, prompt: &BiometricPrompt) -> BiometricOutcome;
}

/// Verify an approved outcome against the enrolled `.biometryCurrentSet` key.
/// Returns `σ_SEP` (the bytes chained into the YubiKey `clientDataHash`).
pub fn verify_approval(
    enrolled: &VerifyingKey,
    prompt: &BiometricPrompt,
    outcome: &BiometricOutcome,
) -> EnclaveResult<Vec<u8>> {
    if prompt.d_jcs.len() != 32 || prompt.nonce.len() != 32 {
        fail!(EINVAL, "BIOMETRIC_CHALLENGE_LENGTH");
    }
    match outcome {
        BiometricOutcome::Approved {
            sep_signature,
            visible_at_ns,
            approved_at_ns,
            ..
        } => {
            if approved_at_ns.saturating_sub(*visible_at_ns) < DWELL_NS
                || *visible_at_ns < prompt.t_start_ns
            {
                fail!(
                    EPERM,
                    "DWELL_GATE_VIOLATION",
                    "biometric armed before the 500 ms unoccluded dwell"
                );
            }
            let sig = Signature::from_der(sep_signature)
                .or_else(|_| Signature::from_slice(sep_signature))
                .map_err(|_| err!(EACCES, "SEP_SIGNATURE_MALFORMED"))?;
            enrolled
                .verify(&prompt.signed_message(), &sig)
                .map_err(|_| {
                    err!(
                        EACCES,
                        "SEP_SIGNATURE_INVALID",
                        "not signed by the enrolled .biometryCurrentSet key"
                    )
                })?;
            Ok(sep_signature.clone())
        }
        BiometricOutcome::Cancelled => fail!(EACCES, "TOUCH_ID_CANCELLED"),
        BiometricOutcome::TimedOut => fail!(ETIMEDOUT, "TOUCH_ID_TIMEOUT"),
        BiometricOutcome::Occluded => fail!(EPERM, "UI_OCCLUSION_ABORT"),
        BiometricOutcome::ReportSuspicious => fail!(EPERM, "USER_REPORTED_SUSPICIOUS_PROMPT"),
    }
}

/// Scripted step for the CI provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg(any(test, feature = "simulation"))]
pub enum Scripted {
    /// Approve after the dwell.
    Approve,
    /// Approve too fast (dwell violation).
    ApproveWithoutDwell,
    /// Cancel.
    Cancel,
    /// Time out.
    Timeout,
    /// Occluded.
    Occlude,
    /// Report suspicious.
    Report,
    /// Sign with a different (re-enrolled fingerprint ⇒ invalidated) key.
    WrongKey,
}

/// CI / headless `CoreAuthUI` provider with a software SEP stand-in.
#[derive(Debug)]
#[cfg(any(test, feature = "simulation"))]
pub struct ScriptedCoreAuthUi {
    sep_key: SigningKey,
    script: VecDeque<Scripted>,
    /// Prompts shown (reason strings), for assertions in tests.
    pub shown: Vec<String>,
}

#[cfg(any(test, feature = "simulation"))]
impl ScriptedCoreAuthUi {
    /// New provider with a fresh key.
    pub fn new(script: impl IntoIterator<Item = Scripted>) -> Self {
        Self {
            sep_key: SigningKey::random(&mut rand_core::OsRng),
            script: script.into_iter().collect(),
            shown: vec![],
        }
    }
    /// The enrolled public key.
    pub fn enrolled_key(&self) -> VerifyingKey {
        *self.sep_key.verifying_key()
    }
    /// Append steps.
    pub fn push(&mut self, s: Scripted) {
        self.script.push_back(s);
    }
}

#[cfg(any(test, feature = "simulation"))]
impl BiometricProvider for ScriptedCoreAuthUi {
    fn evaluate(&mut self, p: &BiometricPrompt) -> BiometricOutcome {
        self.shown.push(p.localized_reason.clone());
        let visible = p.t_start_ns + 1_000_000;
        match self.script.pop_front().unwrap_or(Scripted::Timeout) {
            Scripted::Approve => {
                let s: Signature = self.sep_key.sign(&p.signed_message());
                let pub_bytes = self
                    .sep_key
                    .verifying_key()
                    .to_encoded_point(false)
                    .as_bytes()
                    .to_vec();
                BiometricOutcome::Approved {
                    sep_signature: s.to_der().as_bytes().to_vec(),
                    visible_at_ns: visible,
                    approved_at_ns: visible + DWELL_NS + 1,
                    enrolled_pubkey: p.bio_key_blob.is_empty().then_some(pub_bytes),
                    enrolled_blob: p.bio_key_blob.is_empty().then_some(vec![0x42; 32]),
                }
            }
            Scripted::ApproveWithoutDwell => {
                let s: Signature = self.sep_key.sign(&p.signed_message());
                BiometricOutcome::Approved {
                    sep_signature: s.to_der().as_bytes().to_vec(),
                    visible_at_ns: visible,
                    approved_at_ns: visible + 10_000_000,
                    enrolled_pubkey: None,
                    enrolled_blob: None,
                }
            }
            Scripted::WrongKey => {
                let k = SigningKey::random(&mut rand_core::OsRng);
                let s: Signature = k.sign(&p.signed_message());
                BiometricOutcome::Approved {
                    sep_signature: s.to_der().as_bytes().to_vec(),
                    visible_at_ns: visible,
                    approved_at_ns: visible + DWELL_NS + 1,
                    enrolled_pubkey: None,
                    enrolled_blob: None,
                }
            }
            Scripted::Cancel => BiometricOutcome::Cancelled,
            Scripted::Timeout => BiometricOutcome::TimedOut,
            Scripted::Occlude => BiometricOutcome::Occluded,
            Scripted::Report => BiometricOutcome::ReportSuspicious,
        }
    }
}

/// Production bridge to `_enclaveintent`: `u32` big-endian length-prefixed
/// CBOR `BiometricPrompt` → `BiometricOutcome` over a connected stream whose
/// peer identity was already pinned (`LOCAL_PEERTOKEN` + code-signing
/// requirement) by the IPC layer.
#[derive(Debug)]
pub struct HelperBridge<S: Read + Write + std::fmt::Debug> {
    stream: S,
}

/// Max frame accepted from the helper.
pub const MAX_HELPER_FRAME: usize = 16 * 1024;

impl<S: Read + Write + std::fmt::Debug> HelperBridge<S> {
    /// Wrap a connected stream.
    pub fn new(stream: S) -> Self {
        Self { stream }
    }
    fn exchange(&mut self, p: &BiometricPrompt) -> EnclaveResult<BiometricOutcome> {
        let mut body = Zeroizing::new(Vec::new());
        ciborium::into_writer(p, &mut *body).map_err(|e| err!(EINVAL, "HELPER_ENCODE", "{e}"))?;
        if body.len() > MAX_HELPER_FRAME {
            fail!(E2BIG, "HELPER_FRAME_TOO_LARGE");
        }
        self.stream
            .write_all(&(body.len() as u32).to_be_bytes())
            .map_err(|e| err!(EIO, "HELPER_IO", "{e}"))?;
        self.stream
            .write_all(&body)
            .map_err(|e| err!(EIO, "HELPER_IO", "{e}"))?;
        let mut len = [0u8; 4];
        self.stream
            .read_exact(&mut len)
            .map_err(|e| err!(EIO, "HELPER_IO", "{e}"))?;
        let n = u32::from_be_bytes(len) as usize;
        if n == 0 || n > MAX_HELPER_FRAME {
            fail!(E2BIG, "HELPER_FRAME_TOO_LARGE");
        }
        let mut buf = Zeroizing::new(vec![0u8; n]);
        self.stream
            .read_exact(&mut buf)
            .map_err(|e| err!(EIO, "HELPER_IO", "{e}"))?;
        let mut cursor = std::io::Cursor::new(buf.as_slice());
        let outcome = ciborium::from_reader(&mut cursor).map_err(|e| err!(EINVAL, "HELPER_DECODE", "{e}"))?;
        if cursor.position() != n as u64 {
            fail!(EINVAL, "HELPER_TRAILING_BYTES");
        }
        Ok(outcome)
    }
}

impl<S: Read + Write + std::fmt::Debug> BiometricProvider for HelperBridge<S> {
    fn evaluate(&mut self, prompt: &BiometricPrompt) -> BiometricOutcome {
        // Any transport failure is a timeout: fail closed, YubiKey never armed.
        self.exchange(prompt).unwrap_or(BiometricOutcome::TimedOut)
    }
}

#[cfg(unix)]
/// A helper stream whose every fragment shares the original ceremony deadline.
#[derive(Debug)]
pub struct DeadlineHelperStream {
    stream: std::os::unix::net::UnixStream,
    deadline_ns: u64,
}

#[cfg(unix)]
impl DeadlineHelperStream {
    pub(crate) fn new(stream: std::os::unix::net::UnixStream, deadline_ns: u64) -> std::io::Result<Self> {
        stream.set_nonblocking(true)?;
        Ok(Self { stream, deadline_ns })
    }

    pub(crate) fn into_stream(self) -> std::os::unix::net::UnixStream { self.stream }

    fn remaining_ns(&self) -> std::io::Result<u64> {
        let now = enclave_core::clock::boot_clock_ns();
        if now >= self.deadline_ns {
            return Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "original ceremony deadline"));
        }
        Ok(self.deadline_ns - now)
    }

    fn wait(&self, events: libc::c_short) -> std::io::Result<()> {
        self.wait_cancellable(events, None)
    }

    fn wait_cancellable(&self, events: libc::c_short, cancelled: Option<&std::sync::atomic::AtomicBool>) -> std::io::Result<()> {
        use std::os::fd::AsRawFd;
        loop {
            if cancelled.is_some_and(|signal| signal.load(std::sync::atomic::Ordering::Acquire)) {
                return Err(std::io::Error::new(std::io::ErrorKind::Interrupted, "ceremony cancelled"));
            }
            // Short polls recheck the continuous clock promptly after suspend;
            // neither partial frames nor EINTR establish a fresh timeout.
            let remaining = self.remaining_ns()?;
            let millis = remaining.div_ceil(1_000_000).min(50) as libc::c_int;
            let mut poll = libc::pollfd { fd: self.stream.as_raw_fd(), events, revents: 0 };
            // SAFETY: one initialized pollfd is valid for the duration of poll.
            let ready = unsafe { libc::poll(&mut poll, 1, millis) };
            self.remaining_ns()?;
            if ready > 0 { return Ok(()); }
            if ready < 0 {
                let error = std::io::Error::last_os_error();
                if error.kind() != std::io::ErrorKind::Interrupted { return Err(error); }
            }
        }
    }

    pub(crate) fn read_exact_cancellable(&mut self, mut bytes: &mut [u8], cancelled: &std::sync::atomic::AtomicBool) -> std::io::Result<()> {
        while !bytes.is_empty() {
            self.wait_cancellable(libc::POLLIN, Some(cancelled))?;
            match self.stream.read(bytes) {
                Ok(0) => return Err(std::io::ErrorKind::UnexpectedEof.into()),
                Ok(count) => bytes = &mut bytes[count..],
                Err(error) if matches!(error.kind(), std::io::ErrorKind::Interrupted | std::io::ErrorKind::WouldBlock) => continue,
                Err(error) => return Err(error),
            }
        }
        self.remaining_ns()?;
        if cancelled.load(std::sync::atomic::Ordering::Acquire) {
            return Err(std::io::ErrorKind::Interrupted.into());
        }
        Ok(())
    }
}

#[cfg(unix)]
impl Read for DeadlineHelperStream {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        loop {
            self.wait(libc::POLLIN)?;
            match self.stream.read(bytes) {
                Err(error) if matches!(error.kind(), std::io::ErrorKind::Interrupted | std::io::ErrorKind::WouldBlock) => continue,
                result => { self.remaining_ns()?; return result; }
            }
        }
    }
}

#[cfg(unix)]
impl Write for DeadlineHelperStream {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        loop {
            self.wait(libc::POLLOUT)?;
            match self.stream.write(bytes) {
                Err(error) if matches!(error.kind(), std::io::ErrorKind::Interrupted | std::io::ErrorKind::WouldBlock) => continue,
                result => { self.remaining_ns()?; return result; }
            }
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.remaining_ns()?;
        self.stream.flush()
    }
}

#[cfg(unix)]
/// Connect to the `_enclaveintent` LaunchAgent socket, verifying peer UID and code identity.
/// Connection, challenge writes and reply reads share the prompt's original 10 s budget.
pub fn connect_helper(
    socket_path: &std::path::Path,
    prompt: &BiometricPrompt,
) -> EnclaveResult<HelperBridge<DeadlineHelperStream>> {
    Ok(HelperBridge::new(connect_helper_stream(socket_path, prompt)?))
}

#[cfg(unix)]
pub(crate) fn connect_helper_stream(
    socket_path: &std::path::Path,
    prompt: &BiometricPrompt,
) -> EnclaveResult<DeadlineHelperStream> {
    use enclave_core::codesign::{self, CodeRequirement};
    use enclave_core::ipc::Client;

    let deadline_ns = prompt.t_start_ns.checked_add(10_000_000_000)
        .ok_or_else(|| err!(ETIMEDOUT, "HELPER_IO_DEADLINE"))?;
    let now = enclave_core::clock::boot_clock_ns();
    if prompt.t_start_ns > now || now >= deadline_ns {
        fail!(ETIMEDOUT, "HELPER_IO_DEADLINE");
    }

    let selected;
    let socket_path = if let Some(target) = enclave_core::deployment::selected() {
        let root = &target.target().layout.socket_root;
        let uid = enclave_core::runtime_paths::console_uid().ok_or_else(|| err!(EACCES, "NO_CONSOLE_USER"))?;
        selected = enclave_core::runtime_paths::intent_socket(root, uid);
        if socket_path != root.join("intent/intent.sock") && socket_path != selected {
            fail!(EACCES, "DEPLOYMENT_HELPER_SOCKET_MISMATCH");
        }
        selected.as_path()
    } else if socket_path == std::path::Path::new("/var/run/enclave/intent/intent.sock") {
        let uid = enclave_core::runtime_paths::console_uid().ok_or_else(|| err!(EACCES, "NO_CONSOLE_USER"))?;
        selected = enclave_core::runtime_paths::intent_socket(std::path::Path::new("/var/run/enclave"),uid);
        selected.as_path()
    } else { socket_path };
    #[cfg(target_os = "macos")]
    let console_uid = enclave_core::runtime_paths::console_uid()
        .ok_or_else(|| err!(EACCES, "NO_CONSOLE_USER"))?;
    #[cfg(not(target_os = "macos"))]
    let console_uid = unsafe { libc::geteuid() };
    let requirement = if codesign::enforced() {
        Some(CodeRequirement::pinned_boundary(codesign::INTENT_IDENTIFIER)?)
    } else { None };
    let client = Client::connect_verified_deadline(socket_path, console_uid,
        requirement.as_ref(), std::time::Duration::from_nanos(deadline_ns - now))?;
    #[cfg(target_os = "macos")]
    if enclave_core::runtime_paths::console_uid() != Some(console_uid) {
        fail!(EACCES, "CONSOLE_SESSION_CHANGED");
    }
    let stream = DeadlineHelperStream::new(client.into_authenticated_stream(), deadline_ns)
        .map_err(|_| err!(EIO, "HELPER_IO_DEADLINE"))?;
    stream.remaining_ns().map_err(|_| err!(ETIMEDOUT, "HELPER_IO_DEADLINE"))?;
    Ok(stream)
}

/// Helper provider that connects to the `_enclaveintent` LaunchAgent on demand.
#[derive(Debug)]
pub struct IntentHelperProvider {
    socket_path: std::path::PathBuf,
}

impl IntentHelperProvider {
    /// Create for the given socket path.
    pub fn new(socket_path: std::path::PathBuf) -> Self {
        Self { socket_path }
    }
}

impl BiometricProvider for IntentHelperProvider {
    fn evaluate(&mut self, prompt: &BiometricPrompt) -> BiometricOutcome {
        #[cfg(unix)]
        {
            match connect_helper(&self.socket_path, prompt) {
                Ok(mut bridge) => bridge.evaluate(prompt),
                Err(e) => {
                    eprintln!("IntentHelperProvider: connect failed: {e}");
                    BiometricOutcome::TimedOut
                }
            }
        }
        #[cfg(not(unix))]
        {
            let _ = prompt;
            BiometricOutcome::TimedOut
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn prompt() -> BiometricPrompt {
        BiometricPrompt {
            localized_reason: "[A3] t (1 rows) | SAS: a-b-c-d".into(),
            d_jcs: vec![1; 32],
            nonce: vec![2; 32],
            t_start_ns: 1000,
            bio_key_blob: Vec::new(),
        }
    }

    #[test]
    fn only_enrolled_key_with_dwell_is_accepted() {
        let mut ui = ScriptedCoreAuthUi::new([
            Scripted::Approve,
            Scripted::WrongKey,
            Scripted::ApproveWithoutDwell,
            Scripted::Cancel,
        ]);
        let k = ui.enrolled_key();
        let p = prompt();
        assert!(verify_approval(&k, &p, &ui.evaluate(&p)).is_ok());
        assert!(verify_approval(&k, &p, &ui.evaluate(&p))
            .unwrap_err()
            .is("SEP_SIGNATURE_INVALID"));
        assert!(verify_approval(&k, &p, &ui.evaluate(&p))
            .unwrap_err()
            .is("DWELL_GATE_VIOLATION"));
        assert!(verify_approval(&k, &p, &ui.evaluate(&p))
            .unwrap_err()
            .is("TOUCH_ID_CANCELLED"));
    }

    #[test]
    fn signature_is_bound_to_the_prompt() {
        let mut ui = ScriptedCoreAuthUi::new([Scripted::Approve]);
        let k = ui.enrolled_key();
        let p = prompt();
        let o = ui.evaluate(&p);
        let mut other = p.clone();
        other.d_jcs = vec![9; 32];
        assert!(verify_approval(&k, &other, &o).is_err());
    }

    #[test]
    fn signed_challenge_requires_unambiguous_fixed_width_fields() {
        for (digest_len, nonce_len) in [(31, 33), (33, 31), (32, 0)] {
            let mut ui = ScriptedCoreAuthUi::new([Scripted::Approve]);
            let k = ui.enrolled_key();
            let mut p = prompt();
            p.d_jcs.resize(digest_len, 1);
            p.nonce.resize(nonce_len, 2);
            // Even a genuine signature over malformed challenge bytes refuses.
            let outcome = ui.evaluate(&p);
            assert!(verify_approval(&k, &p, &outcome).unwrap_err().is("BIOMETRIC_CHALLENGE_LENGTH"));
        }
    }

    #[test]
    fn helper_protocol_bounds_both_directions_and_rejects_trailing_data() {
        #[derive(Debug, Default)]
        struct FramedIo { input: std::io::Cursor<Vec<u8>>, output: Vec<u8> }
        impl Read for FramedIo {
            fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> { self.input.read(bytes) }
        }
        impl Write for FramedIo {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> { self.output.extend_from_slice(bytes); Ok(bytes.len()) }
            fn flush(&mut self) -> std::io::Result<()> { Ok(()) }
        }
        let p = prompt();
        let mut encoded = Vec::new();
        ciborium::into_writer(&BiometricOutcome::Cancelled, &mut encoded).unwrap();
        let response = |body: &[u8]| {
            let mut frame = (body.len() as u32).to_be_bytes().to_vec();
            frame.extend_from_slice(body);
            FramedIo { input: std::io::Cursor::new(frame), output: Vec::new() }
        };
        assert_eq!(HelperBridge::new(response(&encoded)).exchange(&p).unwrap(), BiometricOutcome::Cancelled);
        encoded.push(0);
        assert!(HelperBridge::new(response(&encoded)).exchange(&p).unwrap_err().is("HELPER_TRAILING_BYTES"));
        assert!(HelperBridge::new(response(&[])).exchange(&p).unwrap_err().is("HELPER_FRAME_TOO_LARGE"));
        let mut bridge = HelperBridge::new(FramedIo::default());
        let mut huge = p;
        huge.bio_key_blob.resize(MAX_HELPER_FRAME, 0x42);
        assert!(bridge.exchange(&huge).unwrap_err().is("HELPER_FRAME_TOO_LARGE"));
        assert!(bridge.stream.output.is_empty(), "no partial outbound frame before admission");
    }

    #[cfg(unix)]
    #[test]
    fn helper_fragments_share_original_absolute_deadline() {
        use std::{os::unix::net::UnixStream, time::{Duration, Instant}};
        for (delay_ms, budget_ms, allowed) in [(1, 500, true), (30, 85, false)] {
            let (client, mut server) = UnixStream::pair().unwrap();
            let worker = std::thread::spawn(move || {
                let mut size = [0; 4];
                server.read_exact(&mut size).unwrap();
                let mut request = vec![0; u32::from_be_bytes(size) as usize];
                server.read_exact(&mut request).unwrap();
                let mut body = Vec::new();
                ciborium::into_writer(&BiometricOutcome::Cancelled, &mut body).unwrap();
                let mut frame = (body.len() as u32).to_be_bytes().to_vec();
                frame.extend_from_slice(&body);
                for byte in frame {
                    std::thread::sleep(Duration::from_millis(delay_ms));
                    if server.write_all(&[byte]).is_err() { break; }
                }
            });
            let deadline = enclave_core::clock::boot_clock_ns() + budget_ms * 1_000_000;
            let mut bridge = HelperBridge::new(DeadlineHelperStream::new(client, deadline).unwrap());
            let started = Instant::now();
            let result = bridge.exchange(&prompt());
            if allowed {
                assert_eq!(result.unwrap(), BiometricOutcome::Cancelled);
            } else {
                assert!(result.unwrap_err().is("HELPER_IO"));
                assert!(started.elapsed() < Duration::from_millis(500), "fragment delivery cannot renew the deadline");
            }
            drop(bridge);
            worker.join().unwrap();
        }
    }

    #[cfg(unix)]
    #[test]
    fn helper_backpressure_and_stale_prompt_cannot_extend_budget() {
        use std::{os::unix::net::UnixStream, time::{Duration, Instant}};
        let (client, _unread_peer) = UnixStream::pair().unwrap();
        let deadline = enclave_core::clock::boot_clock_ns() + 40_000_000;
        let mut stream = DeadlineHelperStream::new(client, deadline).unwrap();
        let started = Instant::now();
        let error = stream.write_all(&vec![0; 4 * 1024 * 1024]).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
        assert!(started.elapsed() < Duration::from_secs(1));
        let error = connect_helper(std::path::Path::new("/nonexistent-intent-socket"), &prompt()).unwrap_err();
        assert!(error.is("HELPER_IO_DEADLINE"), "stale origin refuses before connecting");
        let mut future = prompt();
        future.t_start_ns = u64::MAX;
        assert!(connect_helper(std::path::Path::new("/nonexistent-intent-socket"), &future).unwrap_err().is("HELPER_IO_DEADLINE"));
    }

    #[cfg(unix)]
    #[test]
    fn helper_pin_read_observes_lifecycle_cancel_and_disconnects() {
        use std::{sync::{Arc, atomic::{AtomicBool, Ordering}}, time::{Duration, Instant}, os::unix::net::UnixStream};
        let (client, mut helper) = UnixStream::pair().unwrap();
        let cancelled = Arc::new(AtomicBool::new(false));
        let signal = cancelled.clone();
        let worker = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(10));
            signal.store(true, Ordering::Release);
        });
        let mut stream = DeadlineHelperStream::new(client, enclave_core::clock::boot_clock_ns() + 2_000_000_000).unwrap();
        let started = Instant::now();
        assert_eq!(stream.read_exact_cancellable(&mut [0; 4], &cancelled).unwrap_err().kind(), std::io::ErrorKind::Interrupted);
        assert!(started.elapsed() < Duration::from_millis(500));
        drop(stream);
        helper.set_read_timeout(Some(Duration::from_millis(500))).unwrap();
        assert_eq!(helper.read(&mut [0]).unwrap(), 0, "cancellation closes the helper's live request");
        worker.join().unwrap();
    }

    #[test]
    fn helper_bridge_scripted_coreauthui_parity_all_outcomes() {
        let key = p256::ecdsa::SigningKey::random(&mut rand_core::OsRng);
        let pubkey = *key.verifying_key();
        let p = prompt();
        let msg = p.signed_message();
        let valid_sig: p256::ecdsa::Signature = key.sign(&msg);
        let sig_bytes = valid_sig.to_der().as_bytes().to_vec();

        let visible = p.t_start_ns + 1_000_000;
        let test_cases = vec![
            (
                Scripted::Approve,
                BiometricOutcome::Approved {
                    sep_signature: sig_bytes.clone(),
                    visible_at_ns: visible,
                    approved_at_ns: visible + DWELL_NS + 1,
                    enrolled_pubkey: None,
                    enrolled_blob: None,
                },
                None, // Ok
            ),
            (
                Scripted::ApproveWithoutDwell,
                BiometricOutcome::Approved {
                    sep_signature: sig_bytes,
                    visible_at_ns: visible,
                    approved_at_ns: visible + 10_000_000,
                    enrolled_pubkey: None,
                    enrolled_blob: None,
                },
                Some("DWELL_GATE_VIOLATION"),
            ),
            (
                Scripted::Cancel,
                BiometricOutcome::Cancelled,
                Some("TOUCH_ID_CANCELLED"),
            ),
            (
                Scripted::Timeout,
                BiometricOutcome::TimedOut,
                Some("TOUCH_ID_TIMEOUT"),
            ),
            (
                Scripted::Occlude,
                BiometricOutcome::Occluded,
                Some("UI_OCCLUSION_ABORT"),
            ),
            (
                Scripted::Report,
                BiometricOutcome::ReportSuspicious,
                Some("USER_REPORTED_SUSPICIOUS_PROMPT"),
            ),
        ];

        for (scripted_op, expected_outcome, expected_err) in test_cases {
            // 1. ScriptedCoreAuthUi baseline
            let mut ui = ScriptedCoreAuthUi {
                sep_key: key.clone(),
                script: VecDeque::from([scripted_op]),
                shown: vec![],
            };
            let direct_outcome = ui.evaluate(&p);
            let direct_res = verify_approval(&pubkey, &p, &direct_outcome);
            if let Some(err_code) = expected_err {
                assert!(
                    direct_res.as_ref().unwrap_err().is(err_code),
                    "direct expected {err_code}, got {:?}",
                    direct_res
                );
            } else {
                assert!(direct_res.is_ok());
            }

            // 2. HelperBridge over socketpair
            let (client_sock, mut server_sock) = std::os::unix::net::UnixStream::pair().unwrap();
            let outcome_to_send = expected_outcome.clone();
            let expected_d_jcs = p.d_jcs.clone();
            let helper_thread = std::thread::spawn(move || {
                let mut len = [0u8; 4];
                server_sock.read_exact(&mut len).unwrap();
                let mut buf = vec![0u8; u32::from_be_bytes(len) as usize];
                server_sock.read_exact(&mut buf).unwrap();
                let received_prompt: BiometricPrompt =
                    ciborium::from_reader(buf.as_slice()).unwrap();
                assert_eq!(received_prompt.d_jcs, expected_d_jcs);

                let mut out = Vec::new();
                ciborium::into_writer(&outcome_to_send, &mut out).unwrap();
                server_sock
                    .write_all(&(out.len() as u32).to_be_bytes())
                    .unwrap();
                server_sock.write_all(&out).unwrap();
            });

            let mut bridge = HelperBridge::new(client_sock);
            let bridge_outcome = bridge.evaluate(&p);
            assert_eq!(bridge_outcome, expected_outcome);
            let bridge_res = verify_approval(&pubkey, &p, &bridge_outcome);
            if let Some(err_code) = expected_err {
                assert!(
                    bridge_res.as_ref().unwrap_err().is(err_code),
                    "bridge expected {err_code}, got {:?}",
                    bridge_res
                );
            } else {
                assert!(bridge_res.is_ok());
            }
            helper_thread.join().unwrap();
        }
    }

    #[test]
    fn cbor_wire_encoding_pinned() {
        // Pin unit variants: serialized as CBOR text strings.
        let mut b_cancel = Vec::new();
        ciborium::into_writer(&BiometricOutcome::Cancelled, &mut b_cancel).unwrap();
        // 0x69 = text string of length 9: "Cancelled"
        assert_eq!(
            b_cancel,
            &[0x69, b'C', b'a', b'n', b'c', b'e', b'l', b'l', b'e', b'd']
        );

        let mut b_timeout = Vec::new();
        ciborium::into_writer(&BiometricOutcome::TimedOut, &mut b_timeout).unwrap();
        // 0x68 = text string of length 8: "TimedOut"
        assert_eq!(
            b_timeout,
            &[0x68, b'T', b'i', b'm', b'e', b'd', b'O', b'u', b't']
        );

        let mut b_occluded = Vec::new();
        ciborium::into_writer(&BiometricOutcome::Occluded, &mut b_occluded).unwrap();
        // 0x68 = text string of length 8: "Occluded"
        assert_eq!(
            b_occluded,
            &[0x68, b'O', b'c', b'c', b'l', b'u', b'd', b'e', b'd']
        );

        let mut b_suspicious = Vec::new();
        ciborium::into_writer(&BiometricOutcome::ReportSuspicious, &mut b_suspicious).unwrap();
        // 0x70 = text string of length 16: "ReportSuspicious"
        assert_eq!(
            b_suspicious,
            &[
                0x70, b'R', b'e', b'p', b'o', b'r', b't', b'S', b'u', b's', b'p', b'i', b'c', b'i',
                b'o', b'u', b's'
            ]
        );

        // Pin Approved variant: 1-entry map {"Approved": {"sep_signature": ..., "visible_at_ns": ..., "approved_at_ns": ...}}
        let approved = BiometricOutcome::Approved {
            sep_signature: vec![0x11, 0x22, 0x33],
            visible_at_ns: 100,
            approved_at_ns: 600,
            enrolled_pubkey: None,
            enrolled_blob: None,
        };
        let mut b_app = Vec::new();
        ciborium::into_writer(&approved, &mut b_app).unwrap();
        let decoded: BiometricOutcome = ciborium::from_reader(b_app.as_slice()).unwrap();
        assert_eq!(decoded, approved);

        // Verify deserialization from manual canonical bytes
        let mut manual = Vec::new();
        // Map of 1 entry: 0xa1
        manual.push(0xa1);
        // Key: "Approved" (0x68 + "Approved")
        manual.extend_from_slice(&[0x68, b'A', b'p', b'p', b'r', b'o', b'v', b'e', b'd']);
        // Value: map of 3 entries (0xa3)
        manual.push(0xa3);
        // Entry 1: "approved_at_ns" -> uint 600 (0x19 0x02 0x58)
        manual.extend_from_slice(&[
            0x6e, b'a', b'p', b'p', b'r', b'o', b'v', b'e', b'd', b'_', b'a', b't', b'_', b'n',
            b's',
        ]);
        manual.extend_from_slice(&[0x19, 0x02, 0x58]);
        // Entry 2: "sep_signature" -> byte string of 3 bytes (0x43 0x11 0x22 0x33)
        manual.extend_from_slice(&[
            0x6d, b's', b'e', b'p', b'_', b's', b'i', b'g', b'n', b'a', b't', b'u', b'r', b'e',
        ]);
        manual.extend_from_slice(&[0x43, 0x11, 0x22, 0x33]);
        // Entry 3: "visible_at_ns" -> uint 100 (0x18 0x64)
        manual.extend_from_slice(&[
            0x6d, b'v', b'i', b's', b'i', b'b', b'l', b'e', b'_', b'a', b't', b'_', b'n', b's',
        ]);
        manual.extend_from_slice(&[0x18, 0x64]);

        let decoded_manual: BiometricOutcome = ciborium::from_reader(manual.as_slice()).unwrap();
        assert_eq!(decoded_manual, approved);
    }

    #[test]
    fn helper_bridge_roundtrip_over_socketpair() {
        let (a, mut b) = std::os::unix::net::UnixStream::pair().unwrap();
        let helper = std::thread::spawn(move || {
            let mut len = [0u8; 4];
            b.read_exact(&mut len).unwrap();
            let mut buf = vec![0u8; u32::from_be_bytes(len) as usize];
            b.read_exact(&mut buf).unwrap();
            let p: BiometricPrompt = ciborium::from_reader(buf.as_slice()).unwrap();
            assert!(p.localized_reason.contains("SAS"));
            let mut out = Vec::new();
            ciborium::into_writer(&BiometricOutcome::Cancelled, &mut out).unwrap();
            b.write_all(&(out.len() as u32).to_be_bytes()).unwrap();
            b.write_all(&out).unwrap();
        });
        let mut bridge = HelperBridge::new(a);
        assert_eq!(bridge.evaluate(&prompt()), BiometricOutcome::Cancelled);
        helper.join().unwrap();
    }
}
