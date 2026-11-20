//! Bounded L2 QUIC adapter. Certificate identities and RFC9266 exporters come
//! from the actual mutually authenticated connection, never request fields.
//! Independent HTTPS issuer grants precede every stream's inventory/bytes.
use super::{
    iroh::{
        L2AuthenticatedPeer, L2ChunkRequest, L2ChunkResponse, L2SwarmNode, CAS_SWARM_ALPN,
        L2_READ_TOOL,
    },
    oblivious::{verify_encrypted_streams, EncryptedTarget},
    registry::{DeadlineSocket, RegistryConfig},
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use enclave_core::{
    err,
    error::EnclaveResult,
    fail,
    secret::{SecretBytes, SecretKey32},
};
use enclave_crypto::{
    biscuit_auth::{builder::Term, Biscuit, KeyPair},
    pop_biscuit::{self, Transport, WireClock},
    tuf::TargetFile,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeSet, HashMap},
    io::{self, Read, Write},
    net::SocketAddr,
    path::Path,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
const FRAME: usize = 32 * 1024;
/// One bounded encoded-stream segment per capability call.
pub const SEGMENT: usize = 16 * 1024;
const EXPORTER_LABEL: &[u8] = b"EXPORTER-Channel-Binding";
const EXPORTER_CONTEXT: &[u8] = b""; // RFC9266 tls-exporter: zero-length context
const CAPABILITY_LIFETIME_MS: u64 = 30_000;
const CAPABILITY_REFRESH_MS: u64 = 7_000;
fn default_total_timeout_ms() -> u64 {
    7_200_000
}
/// Public signed L2 configuration. Files hold local credentials; keys never
/// occur in signed configuration, argv, Debug output or peer requests.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct L2QuicConfig {
    /// Numeric QUIC peer, independent CA roots and certificate DNS name.
    pub peer: RegistryConfig,
    /// Independently authenticated HTTPS capability issuer.
    pub issuer: RegistryConfig,
    /// Local DER certificate (public), root-provisioned regular file.
    pub client_certificate_der_path: String,
    /// Local0600 Ed25519 seed. Hardware identities require a custody signer;
    /// software fixture execution cannot establish SEP-bound deployment.
    pub client_key_seed_path: String,
    /// Independently provisioned remote Ed25519 public key.
    pub peer_ed25519_hex: String,
    /// Independent Biscuit issuer public key, never learned from a peer.
    pub issuer_public_key_hex: String,
    /// Exact authorized policy bundle digest.
    pub policy_blake3: String,
    /// EU, US or APAC; checked against actual TLS certificate SAN.
    pub shard: String,
    /// Existing daemon-owned0700 directory for durable signed poison quarantine.
    pub poison_state_dir: String,
    /// Explicit signed local seed endpoint/sources. No listener is implicit.
    #[serde(default)]
    pub seed: Option<super::quic_seed::SeedConfig>,
    /// Independently bounded whole-artifact deadline,100ms..8h; default2h.
    /// Each peer/issuer operation retains its own signed30s maximum timeout.
    #[serde(default = "default_total_timeout_ms")]
    pub total_timeout_ms: u64,
    /// Separate signed stable-principal namespace membership. Mandatory when
    /// serving in production; absence never falls back to certificate identity.
    #[serde(default)]
    pub enterprise_authority:Option<enclave_core::enterprise_authority::AuthorityConfig>,
}
impl L2QuicConfig {
    /// Validate public routing/authority and bounded credential paths before I/O.
    pub fn validate(&self) -> EnclaveResult<()> {
        self.peer.validate()?;
        self.issuer.validate()?;
        if let Some(authority)=&self.enterprise_authority {authority.validate()?;}
        if !(100..=28_800_000).contains(&self.total_timeout_ms) {
            fail!(EINVAL, "L2_TOTAL_DEADLINE_CONFIG");
        }
        for key in [
            &self.peer_ed25519_hex,
            &self.issuer_public_key_hex,
            &self.policy_blake3,
        ] {
            key32(key)?;
        }
        shard(&self.shard)?;
        if let Some(seed) = &self.seed {
            seed.validate()?;
        }
        for path in [
            &self.client_certificate_der_path,
            &self.client_key_seed_path,
            &self.poison_state_dir,
        ] {
            if path.len() > 4096
                || !Path::new(path).is_absolute()
                || Path::new(path)
                    .components()
                    .any(|c| matches!(c, std::path::Component::ParentDir))
                || path.bytes().any(|b| b == 0 || b.is_ascii_control())
            {
                fail!(EINVAL, "L2_CREDENTIAL_PATH");
            }
        }
        Ok(())
    }
}
fn key32(value: &str) -> EnclaveResult<[u8; 32]> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        fail!(EINVAL, "L2_KEY_PIN");
    }
    hex::decode(value)
        .map_err(|_| err!(EINVAL, "L2_KEY_PIN"))?
        .try_into()
        .map_err(|_| err!(EINVAL, "L2_KEY_PIN"))
}
fn shard(value: &str) -> EnclaveResult<()> {
    if !["EU", "US", "APAC"].contains(&value) {
        fail!(EINVAL, "L2_SHARD");
    }
    Ok(())
}
type FixedRefusal = enclave_core::enterprise_authority::FinalReleaseRefusal;
fn fixed(errno: enclave_core::error::Errno, reason: &'static str) -> FixedRefusal {
    FixedRefusal::new(errno, reason)
}
fn now_ms() -> EnclaveResult<u64> {
    now_ms_fixed().map_err(FixedRefusal::into_enclave)
}
fn now_ms_fixed() -> Result<u64, FixedRefusal> {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| fixed(enclave_core::error::Errno::EIO,"L2_CLOCK"))?
            .as_millis(),
    )
    .map_err(|_| fixed(enclave_core::error::Errno::EIO,"L2_CLOCK"))
}
pub(crate) fn credential(path: &str, secret: bool) -> EnclaveResult<SecretBytes> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let mut f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| err!(EACCES, "L2_CREDENTIAL_OPEN"))?;
    let m = f
        .metadata()
        .map_err(|_| err!(EACCES, "L2_CREDENTIAL_METADATA"))?;
    if !m.is_file()
        || (m.uid() != enclave_core::ipc::geteuid() && (secret || m.uid() != 0))
        || m.mode() & 0o022 != 0
        || (secret && m.mode() & 0o077 != 0)
        || m.len() == 0
        || m.len() > 16384
    {
        fail!(EACCES, "L2_CREDENTIAL_INSECURE");
    }
    CredentialReadBuffer::new(m.len() as usize)?.read(&mut f)
}

// Initialize the full cleanup owner before any private file byte. Neither its
// fixed slice nor the separate guarded lookahead slot can reallocate. Successful
// transfer keeps this same SecretBytes allocation; earlier allocator history,
// caller/TLS/provider/kernel copies remain separate owners.
struct CredentialReadBuffer {
    bytes: Option<SecretBytes>,
    extra: zeroize::Zeroizing<[u8; 1]>,
    #[cfg(test)]
    cleanup_observer: Option<Box<dyn FnOnce(Option<&[u8]>, &[u8])>>,
}

impl CredentialReadBuffer {
    fn new(length: usize) -> EnclaveResult<Self> {
        if !(1..=16384).contains(&length) {
            fail!(EACCES, "L2_CREDENTIAL_INSECURE");
        }
        Ok(Self {
            bytes: Some(SecretBytes::zeroed(length)),
            extra: zeroize::Zeroizing::new([0]),
            #[cfg(test)]
            cleanup_observer: None,
        })
    }

    fn read(mut self, reader: &mut impl Read) -> EnclaveResult<SecretBytes> {
        let bytes = self.bytes.as_mut().expect("credential owner before transfer");
        let mut offset = 0;
        while offset < bytes.len() {
            match reader.read(&mut bytes.expose_mut()[offset..]) {
                Ok(0) => fail!(EACCES, "L2_CREDENTIAL_CHANGED"),
                Ok(count) => offset += count,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) => fail!(EIO, "L2_CREDENTIAL_READ"),
            }
        }
        // Distinguish an observed short/grown file from a read error exactly as
        // before, while reading at most one additional private byte.
        loop {
            match reader.read(&mut self.extra[..]) {
                Ok(0) => break,
                Ok(_) => fail!(EACCES, "L2_CREDENTIAL_CHANGED"),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) => fail!(EIO, "L2_CREDENTIAL_READ"),
            }
        }
        Ok(self.bytes.take().expect("credential owner transferred once"))
    }
}

impl Drop for CredentialReadBuffer {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        if let Some(bytes) = self.bytes.as_mut() { bytes.wipe(); }
        self.extra.zeroize();
        // Tests observe only initialized, still-owned storage after cleanup and
        // before SecretBytes deallocation; they never inspect freed memory.
        #[cfg(test)]
        if let Some(observer) = self.cleanup_observer.take() {
            observer(self.bytes.as_ref().map(SecretBytes::expose), &self.extra[..]);
        }
    }
}

fn roots(cfg: &RegistryConfig) -> EnclaveResult<rustls::RootCertStore> {
    let mut roots = rustls::RootCertStore::empty();
    for der in &cfg.tls_roots_der {
        roots
            .add(CertificateDer::from(
                hex::decode(der).map_err(|_| err!(EINVAL, "L2_TLS_ROOT"))?,
            ))
            .map_err(|_| err!(EINVAL, "L2_TLS_ROOT"))?;
    }
    Ok(roots)
}
fn private_der(seed: &[u8; 32]) -> PrivateKeyDer<'static> {
    let mut bytes = hex::decode("302e020100300506032b657004220420").unwrap();
    bytes.extend_from_slice(seed);
    PrivatePkcs8KeyDer::from(bytes).into()
}
fn client_tls(
    cfg: &RegistryConfig,
    cert: &[u8],
    seed: &[u8; 32],
) -> EnclaveResult<rustls::ClientConfig> {
    let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .map_err(|_| err!(EINVAL, "L2_TLS_CONFIG"))?
    .with_root_certificates(roots(cfg)?)
    .with_client_auth_cert(vec![CertificateDer::from(cert.to_vec())], private_der(seed))
    .map_err(|_| err!(EINVAL, "L2_TLS_IDENTITY"))?;
    tls.alpn_protocols = vec![CAS_SWARM_ALPN.to_vec()];
    Ok(tls)
}
/// Parse a CA-verified certificate's Ed25519 key and exact corporate SPIFFE shard.
/// TLS path/expiry verification is performed by rustls before this function.
pub fn certificate_identity(der: &[u8]) -> EnclaveResult<([u8; 32], String)> {
    use x509_parser::{extensions::GeneralName, parse_x509_certificate};
    let (rest, cert) =
        parse_x509_certificate(der).map_err(|_| err!(EACCES, "L2_PEER_CERTIFICATE"))?;
    if !rest.is_empty() || cert.public_key().algorithm.algorithm.to_id_string() != "1.3.101.112" {
        fail!(EACCES, "L2_PEER_KEY_TYPE");
    }
    let public: [u8; 32] = cert
        .public_key()
        .subject_public_key
        .data
        .as_ref()
        .try_into()
        .map_err(|_| err!(EACCES, "L2_PEER_KEY_TYPE"))?;
    let sans = cert
        .subject_alternative_name()
        .map_err(|_| err!(EACCES, "L2_PEER_SPIFFE"))?
        .ok_or_else(|| err!(EACCES, "L2_PEER_SPIFFE"))?;
    let mut identity = None;
    for name in &sans.value.general_names {
        if let GeneralName::URI(uri) = name {
            if let Some(value) = uri.strip_prefix("spiffe://corporate.internal/shard/") {
                let (s, node) = value
                    .split_once("/node/")
                    .ok_or_else(|| err!(EACCES, "L2_PEER_SPIFFE"))?;
                shard(s)?;
                if node != hex::encode(public) || identity.is_some() {
                    fail!(EACCES, "L2_PEER_SPIFFE");
                }
                identity = Some(s.to_owned());
            }
        }
    }
    Ok((
        public,
        identity.ok_or_else(|| err!(EACCES, "L2_PEER_SPIFFE"))?,
    ))
}
fn connection_peer(connection: &quinn::Connection) -> EnclaveResult<([u8; 32], String, [u8; 32])> {
    let certs = connection
        .peer_identity()
        .and_then(|id| id.downcast::<Vec<CertificateDer<'static>>>().ok())
        .ok_or_else(|| err!(EACCES, "L2_TLS_PEER_REQUIRED"))?;
    let cert = certs
        .first()
        .ok_or_else(|| err!(EACCES, "L2_TLS_PEER_REQUIRED"))?;
    let (key, shard) = certificate_identity(cert.as_ref())?;
    let mut exporter = [0; 32];
    connection
        .export_keying_material(&mut exporter, EXPORTER_LABEL, EXPORTER_CONTEXT)
        .map_err(|_| err!(EACCES, "L2_TLS_EXPORTER"))?;
    if exporter == [0; 32] {
        fail!(EACCES, "L2_TLS_EXPORTER");
    }
    Ok((key, shard, exporter))
}
/// Authenticated session challenge. It reveals no artifact inventory.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionHello {
    /// Fresh server authorization epoch, invalidating prior restart capabilities.
    pub epoch: String,
    /// Actual server certificate key.
    pub server_key: [u8; 32],
    /// Actual client certificate key.
    pub client_key: [u8; 32],
    /// Actual TLS exporter for this connection and L2 protocol.
    pub exporter: [u8; 32],
    /// Certificate-verified jurisdiction shard.
    pub shard: String,
    /// Signature of all preceding session facts by the server certificate key.
    pub signature: Vec<u8>,
}
impl SessionHello {
    fn message(&self) -> EnclaveResult<Vec<u8>> {
        let mut hello = self.clone();
        hello.signature.clear();
        serde_json::to_vec(&hello).map_err(|_| err!(EINVAL, "L2_HELLO"))
    }
    fn verify(&self) -> EnclaveResult<()> {
        if self.epoch.is_empty() || self.epoch.len() > 128 || self.exporter == [0; 32] {
            fail!(EACCES, "L2_HELLO");
        }
        shard(&self.shard)?;
        VerifyingKey::from_bytes(&self.server_key)
            .map_err(|_| err!(EACCES, "L2_HELLO"))?
            .verify(
                &self.message()?,
                &Signature::from_slice(&self.signature).map_err(|_| err!(EACCES, "L2_HELLO"))?,
            )
            .map_err(|_| err!(EACCES, "L2_HELLO_SIGNATURE"))
    }
}
/// Issuer request. The HTTPS server must derive authenticated_client from TLS,
/// not this JSON. The challenge signature binds a real server-observed session.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantRequest {
    /// Server-signed connection facts.
    pub session: SessionHello,
    /// Exact requested namespace/root/index (proof absent until issuance).
    pub request: L2ChunkRequest,
}
/// Independent issuer policy. Exact client/namespace/root grants and pinned
/// server/shard pairs are provisioned out of band; never learned from a request.
pub struct IssuerPolicy {
    /// Private issuer authority belongs only to the issuer process.
    pub signing_key: KeyPair,
    /// Current policy bundle digest.
    pub policy: [u8; 32],
    /// Exact permitted (client public key hex, namespace, encrypted Bao root).
    pub grants: BTreeSet<(String, String, String)>,
    /// Pinned server certificate public keys and jurisdiction shards.
    pub servers: HashMap<[u8; 32], String>,
}
impl std::fmt::Debug for IssuerPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IssuerPolicy")
            .field("grant_count", &self.grants.len())
            .field("server_count", &self.servers.len())
            .finish_non_exhaustive()
    }
}
impl IssuerPolicy {
    /// Mint after mutual TLS authentication by the independently deployed issuer.
    pub fn issue(
        &self,
        authenticated_client: [u8; 32],
        request: &GrantRequest,
    ) -> EnclaveResult<Vec<u8>> {
        let hello = &request.session;
        hello.verify()?;
        request.request.capability_args()?;
        if hello.client_key != authenticated_client
            || request.request.client_node_id != hex::encode(authenticated_client)
            || self.servers.get(&hello.server_key) != Some(&hello.shard)
            || !self.grants.contains(&(
                hex::encode(authenticated_client),
                request.request.namespace_id.clone(),
                request.request.root_hash.clone(),
            ))
        {
            fail!(EACCES, "L2_ISSUER_SCOPE");
        }
        let mut p = HashMap::new();
        p.insert("epoch".into(), Term::Str(hello.epoch.clone()));
        p.insert("policy".into(), Term::Bytes(self.policy.to_vec()));
        p.insert("holder".into(), Term::Bytes(authenticated_client.to_vec()));
        p.insert("cb".into(), Term::Bytes(hello.exporter.to_vec()));
        p.insert("ns".into(), Term::Str(request.request.namespace_id.clone()));
        p.insert("root".into(), Term::Str(request.request.root_hash.clone()));
        p.insert("peer".into(), Term::Str(hex::encode(authenticated_client)));
        p.insert(
            "exp".into(),
            Term::Integer((now_ms()? + CAPABILITY_LIFETIME_MS) as i64),
        );
        p.insert("tool".into(), Term::Str(L2_READ_TOOL.into()));
        p.insert("shard".into(), Term::Str(hello.shard.clone()));
        Biscuit::builder().code_with_params("boot_uuid({epoch}); policy_bundle_blake3({policy}); pop_holder(0,{holder},{cb}); cas_read({ns},{root},{peer}); right(\"cas:pull\",{ns}); jurisdiction_shard({shard}); check if tool({tool}); check if utc_epoch_ms($ms), $ms <= {exp};",p,HashMap::new()).map_err(|_|err!(EINVAL,"L2_ISSUER_TOKEN"))?.build(&self.signing_key).map_err(|_|err!(EIO,"L2_ISSUER_TOKEN"))?.seal().map_err(|_|err!(EIO,"L2_ISSUER_SEAL"))?.to_vec().map_err(|_|err!(EIO,"L2_ISSUER_TOKEN"))
    }
}
async fn read_frame(stream: &mut quinn::RecvStream) -> EnclaveResult<Vec<u8>> {
    let mut length = [0; 4];
    stream
        .read_exact(&mut length)
        .await
        .map_err(|_| err!(EIO, "L2_FRAME_READ"))?;
    let n = u32::from_be_bytes(length) as usize;
    if n == 0 || n > FRAME {
        fail!(E2BIG, "L2_FRAME_SIZE");
    }
    let mut bytes = vec![0; n];
    stream
        .read_exact(&mut bytes)
        .await
        .map_err(|_| err!(EIO, "L2_FRAME_READ"))?;
    let mut extra = [0];
    if stream
        .read(&mut extra)
        .await
        .map_err(|_| err!(EIO, "L2_FRAME_READ"))?
        .is_some()
    {
        fail!(EACCES, "L2_FRAME_TRAILING");
    }
    Ok(bytes)
}
async fn write_frame(stream: &mut quinn::SendStream, bytes: &[u8]) -> EnclaveResult<()> {
    if bytes.is_empty() || bytes.len() > FRAME {
        fail!(E2BIG, "L2_FRAME_SIZE");
    }
    stream
        .write_all(&(bytes.len() as u32).to_be_bytes())
        .await
        .map_err(|_| err!(EIO, "L2_FRAME_WRITE"))?;
    stream
        .write_all(bytes)
        .await
        .map_err(|_| err!(EIO, "L2_FRAME_WRITE"))?;
    stream.finish().map_err(|_| err!(EIO, "L2_FRAME_WRITE"))?;
    Ok(())
}
// One action holds a fresh independent SH lease, serial, and every current-state
// try guard. No guard survives the real nonblocking method's return or Pending.
#[cfg(test)] thread_local! {
    static RELEASE_OPERATION: std::cell::Cell<u64 >= const {
        std::cell::Cell::new(0)
    };
}
#[cfg(test)]
fn next_release_operation() -> u64 {
    RELEASE_OPERATION.with(|value| {
        let next = value.get()+1;
        value.set(next);
        next
    })
}
#[cfg(test)]
fn final_now_ms(action: super::quic_fence_test_support::Action, operation: u64) -> Result<u64, FixedRefusal> {
    use super::quic_fence_test_support::{
        self as support,
        ClockResult,
        Fault,
        Note,
        Stage
    };
    support::hook(Stage::FinalClockAttempt, operation);
    let result = if support::fault(Fault::FinalClock, operation) {
        Err(fixed(enclave_core::error::Errno::EIO, "L2_CLOCK"))
    } else {
        now_ms_fixed()
    };
    support::note(Note::Clock {
        action,
        operation,
        final_read: true,
        result: match &result {
            Ok(value) => ClockResult::Value(*value),
            Err(_) => ClockResult::FixedError
        }
    });
    support::hook(Stage::FinalClockResult, operation);
    result
}
pub(crate) fn try_release_serial(serial: &std::sync::Mutex<()>) -> Result<std::sync::MutexGuard<'_, ()>, FixedRefusal> {
    serial.try_lock().map_err(|error|match error {
        std::sync::TryLockError::WouldBlock => fixed(enclave_core::error::Errno::EAGAIN, "L2_RELEASE_SERIAL_BUSY"),
        std::sync::TryLockError::Poisoned(_) => fixed(enclave_core::error::Errno::EIO, "L2_RELEASE_SERIAL_POISONED"),
    })
}
async fn write_authorized_frame(
    stream: &mut quinn::SendStream,
    bytes: &[u8],
    node: &L2SwarmNode,
    peer: &L2AuthenticatedPeer,
    authorization: &super::iroh::L2DataAuthorization,
    peers: &super::quic_seed::SeedPeerAuthority,
    data_started: &mut bool,
) -> EnclaveResult<()> {
    use std::task::Poll;
    if bytes.is_empty() || bytes.len()>FRAME {
        fail!(E2BIG, "L2_FRAME_SIZE");
    }
    let authority = node.enterprise_authority()?;
    let serial = authority.release_serial();
    let state = peers.peer(&peer.public_key)?;
    // All allocation, frame construction and key formatting precede leases.
    let peer_id = hex::encode(peer.public_key);
    let mut frame = Vec::with_capacity(4+bytes.len());
    frame.extend_from_slice(&(bytes.len()as u32).to_be_bytes());
    frame.extend_from_slice(bytes);
    let mut offset = 0;
    while offset<frame.len() {
        let count = std::future::poll_fn(|cx| {
            #[cfg(test)]
            let operation = next_release_operation();
            let attempt = ( || {
                let preflight = now_ms()?;
                #[cfg(test)]
                super::quic_fence_test_support::note(super::quic_fence_test_support::Note::Clock {
                    action: super::quic_fence_test_support::Action::Payload,
                    operation,
                    final_read: false,
                    result: super::quic_fence_test_support::ClockResult::Value(preflight)
                });
                authority.refresh((preflight/1000)as i64)?;
                #[cfg(test)]
                metered_handoff_tests::apply_host_update(node, metered_handoff_tests::Boundary::Payload);
                #[cfg(test)]
                super::quic_fence_test_support::hook(super::quic_fence_test_support::Stage::BeforeCleanLease, operation);
                let lease = state.clean_lease()?;
                #[cfg(test)]
                super::quic_fence_test_support::hook(super::quic_fence_test_support::Stage::AfterCleanLeaseBeforeSerial, operation);
                let protected = ( || {
                    let release = try_release_serial(&serial)?;
                    let guards = node.try_data_release_guard()?;
                    #[cfg(test)]
                    super::quic_fence_test_support::hook(super::quic_fence_test_support::Stage::AllFinalGuardsHeld, operation);
                    #[cfg(test)]
                    let final_time = final_now_ms(super::quic_fence_test_support::Action::Payload, operation)?;
                    #[cfg(not(test))]
                    let final_time = now_ms_fixed()?;
                    if state.is_stopped() {
                        return Err(fixed(enclave_core::error::Errno::EPERM, "PEER_QUARANTINED_BYZANTINE"));
                    }
                    guards.validate(&peer_id, authorization, final_time)?;
                    #[cfg(test)]
                    super::quic_fence_test_support::hook(super::quic_fence_test_support::Stage::BeforePayloadPoll, operation);
                    let result = std::pin::Pin::new(&mut *stream).poll_write(cx, &frame[offset..]);
                    #[cfg(test)]
                    super::quic_fence_test_support::note(super::quic_fence_test_support::Note::PayloadPoll {
                        operation,
                        result: match &result {
                            Poll::Pending => super::quic_fence_test_support::PollResult::Pending,
                            Poll::Ready(Ok(0)) => super::quic_fence_test_support::PollResult::Zero,
                            Poll::Ready(Ok(n)) => super::quic_fence_test_support::PollResult::Positive(*n),
                            Poll::Ready(Err(_)) => super::quic_fence_test_support::PollResult::Error
                        }
                    });
                    drop(guards);
                    drop(release);
                    Ok(result.map(|result|result.map_err(|_|fixed(enclave_core::error::Errno::EIO, "L2_FRAME_WRITE"))))
                })();
                drop(lease);
                protected.map(|poll|poll.map(|result|result.map_err(FixedRefusal::into_enclave))).map_err(FixedRefusal::into_enclave)
            })();
            match attempt {
                Err(error) => {
                    #[cfg(test)]
                    super::quic_fence_test_support::hook(super::quic_fence_test_support::Stage::FinalRefusalGuardsDropped, operation);
                    Poll::Ready(Err(error))
                },
                Ok(result) => {
                    #[cfg(test)] {
                        use super::quic_fence_test_support::{
                            self as support,
                            Stage
                        };
                        support::hook(Stage::AfterActionGuardsDropped, operation);
                        match &result {
                            Poll::Pending => {
                                fence_tests::probe_pending(node);
                                support::hook(Stage::PendingGuardsDropped, operation)
                            },
                            Poll::Ready(Ok(n))if *n>0 => support::hook(Stage::PositivePayloadReturned, operation),
                            _ => {
                            }
                        }
                    }
                    result
                },
            }
        }).await?;
        if count == 0 {
            fail!(EIO, "L2_FRAME_WRITE");
        }
        *data_started = true;
        offset+=count;
    }
    #[cfg(test)]
    let operation = next_release_operation();
    #[cfg(test)]
    super::quic_fence_test_support::hook(super::quic_fence_test_support::Stage::PayloadCompleteBeforeFinLease, operation);
    let result = ( || {
        let preflight = now_ms()?;
        #[cfg(test)]
        super::quic_fence_test_support::note(super::quic_fence_test_support::Note::Clock {
            action: super::quic_fence_test_support::Action::Fin,
            operation,
            final_read: false,
            result: super::quic_fence_test_support::ClockResult::Value(preflight)
        });
        authority.refresh((preflight/1000)as i64)?;
        #[cfg(test)]
        metered_handoff_tests::apply_host_update(node, metered_handoff_tests::Boundary::Fin);
        #[cfg(test)]
        super::quic_fence_test_support::hook(super::quic_fence_test_support::Stage::BeforeCleanLease, operation);
        let lease = state.clean_lease()?;
        #[cfg(test)]
        super::quic_fence_test_support::hook(super::quic_fence_test_support::Stage::AfterCleanLeaseBeforeSerial, operation);
        let protected = ( || {
            let release = try_release_serial(&serial)?;
            let guards = node.try_data_release_guard()?;
            #[cfg(test)]
            super::quic_fence_test_support::hook(super::quic_fence_test_support::Stage::AllFinalGuardsHeld, operation);
            #[cfg(test)]
            let final_time = final_now_ms(super::quic_fence_test_support::Action::Fin, operation)?;
            #[cfg(not(test))]
            let final_time = now_ms_fixed()?;
            if state.is_stopped() {
                return Err(fixed(enclave_core::error::Errno::EPERM, "PEER_QUARANTINED_BYZANTINE"));
            }
            guards.validate(&peer_id, authorization, final_time)?;
            #[cfg(test)]
            super::quic_fence_test_support::hook(super::quic_fence_test_support::Stage::BeforeFin, operation);
            let result = stream.finish().map_err(|_|fixed(enclave_core::error::Errno::EIO, "L2_FRAME_WRITE"));
            #[cfg(test)]
            super::quic_fence_test_support::note(super::quic_fence_test_support::Note::FinCall {
                operation,
                success: result.is_ok()
            });
            drop(guards);
            drop(release);
            result
        })();
        drop(lease);
        protected.map_err(FixedRefusal::into_enclave)
    })();
    #[cfg(test)]
    super::quic_fence_test_support::hook(if result.is_ok() {
        super::quic_fence_test_support::Stage::AfterActionGuardsDropped
    } else {
        super::quic_fence_test_support::Stage::FinalRefusalGuardsDropped
    }, operation);
    result
}
async fn exchange(connection: &quinn::Connection, bytes: &[u8]) -> EnclaveResult<Vec<u8>> {
    let (mut send, mut recv) = connection
        .open_bi()
        .await
        .map_err(|_| err!(EIO, "L2_STREAM"))?;
    write_frame(&mut send, bytes).await?;
    read_frame(&mut recv).await
}
fn issuer_grant(
    cfg: &L2QuicConfig,
    cert: &[u8],
    seed: &[u8; 32],
    request: &GrantRequest,
    deadline: Instant,
) -> EnclaveResult<Biscuit> {
    let (address, name, _) = cfg.issuer.validate()?;
    let deadline = deadline.min(Instant::now() + Duration::from_millis(cfg.issuer.timeout_ms));
    let tls = client_tls(&cfg.issuer, cert, seed)?;
    let left = deadline.saturating_duration_since(Instant::now());
    if left.is_zero() {
        fail!(ETIMEDOUT, "L2_DEADLINE");
    }
    let socket = std::net::TcpStream::connect_timeout(&address, left)
        .map_err(|_| err!(EIO, "L2_ISSUER_CONNECT"))?;
    let conn = rustls::ClientConnection::new(Arc::new(tls), name)
        .map_err(|_| err!(EIO, "L2_ISSUER_TLS"))?;
    let mut tls = rustls::StreamOwned::new(conn, DeadlineSocket { socket, deadline });
    let body = serde_json::to_vec(request).map_err(|_| err!(EINVAL, "L2_ISSUER_REQUEST"))?;
    if body.len() > FRAME {
        fail!(E2BIG, "L2_ISSUER_REQUEST");
    }
    let head=format!("POST /v1/cas/capability HTTP/1.1\r\nHost: {}:{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",cfg.issuer.server_name,address.port(),body.len());
    tls.write_all(head.as_bytes())
        .and_then(|_| tls.write_all(&body))
        .and_then(|_| tls.flush())
        .map_err(|_| err!(EIO, "L2_ISSUER_WRITE"))?;
    let mut header = Vec::new();
    while !header.ends_with(b"\r\n\r\n") {
        if header.len() >= 16384 {
            fail!(E2BIG, "L2_ISSUER_HEADERS");
        }
        let mut byte = [0];
        tls.read_exact(&mut byte)
            .map_err(|_| err!(EIO, "L2_ISSUER_READ"))?;
        header.push(byte[0]);
    }
    let text = std::str::from_utf8(&header).map_err(|_| err!(EINVAL, "L2_ISSUER_HEADERS"))?;
    let mut lines = text[..text.len() - 4].split("\r\n");
    if lines.next() != Some("HTTP/1.1 200 OK") {
        fail!(EACCES, "L2_ISSUER_STATUS");
    }
    let mut length = None;
    for line in lines {
        let (k, v) = line
            .split_once(':')
            .ok_or_else(|| err!(EINVAL, "L2_ISSUER_HEADERS"))?;
        match k.to_ascii_lowercase().as_str() {
            "content-length" => {
                if length.is_some() {
                    fail!(EINVAL, "L2_ISSUER_HEADERS");
                }
                length = Some(
                    v.trim()
                        .parse::<usize>()
                        .map_err(|_| err!(EINVAL, "L2_ISSUER_HEADERS"))?,
                );
            }
            "transfer-encoding" | "content-encoding" => fail!(EINVAL, "L2_ISSUER_HEADERS"),
            _ => (),
        }
    }
    let length = length
        .filter(|n| *n > 0 && *n <= FRAME)
        .ok_or_else(|| err!(E2BIG, "L2_ISSUER_SIZE"))?;
    let mut bytes = vec![0; length];
    tls.read_exact(&mut bytes)
        .map_err(|_| err!(EIO, "L2_ISSUER_READ"))?;
    let mut extra = [0];
    if tls
        .read(&mut extra)
        .map_err(|_| err!(EIO, "L2_ISSUER_READ"))?
        != 0
    {
        fail!(EINVAL, "L2_ISSUER_TRAILING");
    }
    let issuer = enclave_crypto::biscuit_auth::PublicKey::from_bytes(
        &key32(&cfg.issuer_public_key_hex)?,
        enclave_crypto::biscuit_auth::Algorithm::Ed25519,
    )
    .map_err(|_| err!(EINVAL, "L2_ISSUER_KEY"))?;
    let facts = pop_biscuit::parse_and_verify_token(&bytes, &issuer)?;
    if facts.tip_public_key != request.session.client_key
        || facts.policy_bundle_blake3 != key32(&cfg.policy_blake3)?
    {
        fail!(EACCES, "L2_ISSUER_POLICY_OR_HOLDER");
    }
    Biscuit::from(&bytes, issuer).map_err(|_| err!(EACCES, "L2_ISSUER_TOKEN"))
}
struct QuicReader<'a> {
    runtime: &'a tokio::runtime::Runtime,
    connection: &'a quinn::Connection,
    request: L2ChunkRequest,
    token: Biscuit,
    holder: &'a SigningKey,
    exporter: [u8; 32],
    offset: u64,
    total: u64,
    seq: u64,
    buffer: io::Cursor<Vec<u8>>,
    deadline: Instant,
    observation: Arc<std::sync::Mutex<super::quic_poison::Observation>>,
    cfg: &'a L2QuicConfig,
    certificate: &'a [u8],
    seed: &'a [u8; 32],
    session: &'a SessionHello,
    renew_at: Instant,
}
impl Read for QuicReader<'_> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        if self.buffer.position() as usize == self.buffer.get_ref().len() {
            if self.offset == self.total {
                return Ok(0);
            }
            let result = (|| -> EnclaveResult<Vec<u8>> {
                self.request.slice_index = self.offset / SEGMENT as u64;
                if Instant::now() >= self.renew_at {
                    self.request.pop_biscuit_token = None;
                    self.token = issuer_grant(
                        self.cfg,
                        self.certificate,
                        self.seed,
                        &GrantRequest {
                            session: self.session.clone(),
                            request: self.request.clone(),
                        },
                        self.deadline,
                    )?;
                    self.renew_at = Instant::now() + Duration::from_millis(CAPABILITY_REFRESH_MS);
                    self.seq = 0;
                }
                let wire = pop_biscuit::make_call_sealed(
                    &self.token,
                    self.holder,
                    &self.exporter,
                    &self.request.capability_args()?,
                    self.seq,
                    Transport::MtlsExporter,
                    WireClock {
                        utc_epoch_ms_expiry: Some(now_ms()? + 30_000),
                        max_ttl_ms: Some(30_000),
                        skew_ms: Some(2_000),
                        ..Default::default()
                    },
                )?;
                self.request.pop_biscuit_token = Some(wire.to_cbor()?);
                self.seq = self
                    .seq
                    .checked_add(1)
                    .ok_or_else(|| err!(E2BIG, "L2_SEQUENCE"))?;
                let mut bytes = Vec::new();
                ciborium::into_writer(&self.request, &mut bytes)
                    .map_err(|_| err!(EINVAL, "L2_REQUEST"))?;
                let left = self
                    .deadline
                    .saturating_duration_since(Instant::now())
                    .min(Duration::from_millis(self.cfg.peer.timeout_ms));
                let response = self
                    .runtime
                    .block_on(async {
                        tokio::time::timeout(left, exchange(self.connection, &bytes)).await
                    })
                    .map_err(|_| err!(ETIMEDOUT, "L2_DEADLINE"))??;
                if super::constant_time::is_unavailable_frame(&response) {
                    fail!(EACCES, "CHUNK_UNAVAILABLE");
                }
                let expected = (self.total - self.offset).min(SEGMENT as u64) as usize;
                {
                    let mut observation = self
                        .observation
                        .lock()
                        .map_err(|_| err!(EIO, "L2_OBSERVATION"))?;
                    observation.last = Some((
                        self.request.root_hash.clone(),
                        self.request.slice_index,
                        response.clone(),
                    ));
                }
                if response.len() != expected + 8
                    || u64::from_be_bytes(response[..8].try_into().unwrap())
                        != self.request.slice_index
                {
                    self.observation
                        .lock()
                        .map_err(|_| err!(EIO, "L2_OBSERVATION"))?
                        .malformed = true;
                    fail!(EACCES, "L2_RESPONSE_LENGTH");
                }
                let payload = response[8..].to_vec();
                self.observation
                    .lock()
                    .map_err(|_| err!(EIO, "L2_OBSERVATION"))?
                    .last = Some((
                    self.request.root_hash.clone(),
                    self.request.slice_index,
                    payload.clone(),
                ));
                Ok(payload)
            })();
            if let Err(error) = &result {
                if error.reason != "L2_RESPONSE_LENGTH" {
                    if let Ok(mut observation) = self.observation.lock() {
                        observation.transport_failed = true;
                    }
                }
            }
            let bytes = result
                .map_err(|e| io::Error::new(io::ErrorKind::PermissionDenied, e.to_string()))?;
            self.offset += bytes.len() as u64;
            self.buffer = io::Cursor::new(bytes);
        }
        self.buffer.read(out)
    }
}
/// Download through a real mutually authenticated QUIC connection and the
/// independent live-session issuer, then verify/decrypt into a private stage.
/// Publication and key/metadata revalidation remain the caller's transaction.
pub fn fetch(
    cfg: &L2QuicConfig,
    tf: &TargetFile,
    target: &EncryptedTarget,
    key: &SecretKey32,
    accept: impl FnMut(&[u8]) -> EnclaveResult<()>,
) -> EnclaveResult<()> {
    fetch_with_peer_stops(cfg,tf,target,key,accept,super::quic_poison::process_peer_stops())
}
pub(crate) fn fetch_with_peer_stops(
    cfg:&L2QuicConfig,tf:&TargetFile,target:&EncryptedTarget,key:&SecretKey32,
    accept:impl FnMut(&[u8])->EnclaveResult<()>,stops:Arc<super::quic_poison::ProcessPeerStops>,
)->EnclaveResult<()> {
    cfg.validate()?;
    crate::streaming::validate_target(tf)?;
    let cert = credential(&cfg.client_certificate_der_path, false)?;
    let seed = credential(&cfg.client_key_seed_path, true)?;
    let seed = zeroize::Zeroizing::new(
        <[u8; 32]>::try_from(seed.expose()).map_err(|_| err!(EACCES, "L2_IDENTITY_SEED"))?,
    );
    let holder = SigningKey::from_bytes(&seed);
    let (client_key, client_shard) = certificate_identity(cert.expose())?;
    if client_key != holder.verifying_key().to_bytes() || client_shard != cfg.shard {
        fail!(EACCES, "L2_CLIENT_IDENTITY");
    }
    let domain=stops.reserve_domain(&cfg.poison_state_dir,client_key,&[key32(&cfg.peer_ed25519_hex)?])?;
    let poison=domain.peer(&key32(&cfg.peer_ed25519_hex)?)?;
    // Refuse known local poison before establishing a new network session.
    drop(poison.clean_lease()?);
    let ciphertext_observation = Arc::new(std::sync::Mutex::new(
        super::quic_poison::Observation::default(),
    ));
    let key_observation = Arc::new(std::sync::Mutex::new(
        super::quic_poison::Observation::default(),
    ));
    let tls = client_tls(&cfg.peer, cert.expose(), &seed)?;
    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls)
        .map_err(|_| err!(EINVAL, "L2_QUIC_CONFIG"))?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| err!(EIO, "L2_RUNTIME"))?;
    let deadline = Instant::now() + Duration::from_millis(cfg.total_timeout_ms);
    let address: SocketAddr = cfg
        .peer
        .address
        .parse()
        .map_err(|_| err!(EINVAL, "L2_ADDRESS"))?;
    let (endpoint, connection, hello) = runtime.block_on(async {
        let mut endpoint = quinn::Endpoint::client(
            if address.is_ipv4() {
                "0.0.0.0:0"
            } else {
                "[::]:0"
            }
            .parse()
            .unwrap(),
        )
        .map_err(|_| err!(EIO, "L2_ENDPOINT"))?;
        endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(crypto)));
        let connecting = endpoint
            .connect(address, &cfg.peer.server_name)
            .map_err(|_| err!(EIO, "L2_CONNECT"))?;
        let connection = tokio::time::timeout(
            deadline
                .saturating_duration_since(Instant::now())
                .min(Duration::from_millis(cfg.peer.timeout_ms)),
            connecting,
        )
        .await
        .map_err(|_| err!(ETIMEDOUT, "L2_DEADLINE"))?
        .map_err(|_| err!(EACCES, "L2_HANDSHAKE"))?;
        let (peer, peer_shard, exporter) = connection_peer(&connection)?;
        if peer != key32(&cfg.peer_ed25519_hex)? || peer_shard != cfg.shard {
            fail!(EACCES, "L2_PEER_PIN_OR_SHARD");
        }
        let bytes = tokio::time::timeout(
            deadline
                .saturating_duration_since(Instant::now())
                .min(Duration::from_millis(cfg.peer.timeout_ms)),
            exchange(&connection, b"hello"),
        )
        .await
        .map_err(|_| err!(ETIMEDOUT, "L2_DEADLINE"))??;
        let hello: SessionHello =
            serde_json::from_slice(&bytes).map_err(|_| err!(EACCES, "L2_HELLO"))?;
        hello.verify()?;
        if hello.server_key != peer
            || hello.client_key != client_key
            || hello.exporter != exporter
            || hello.shard != cfg.shard
        {
            fail!(EACCES, "L2_HELLO_BINDING");
        }
        Ok::<_, enclave_core::error::EnclaveError>((endpoint, connection, hello))
    })?;
    let reader = |root: &str,
                  total: u64,
                  observation: Arc<std::sync::Mutex<super::quic_poison::Observation>>|
     -> EnclaveResult<QuicReader<'_>> {
        let request = L2ChunkRequest {
            namespace_id: target.key.namespace.clone(),
            root_hash: root.into(),
            slice_index: 0,
            pop_biscuit_token: None,
            client_node_id: hex::encode(client_key),
        };
        let token = issuer_grant(
            cfg,
            cert.expose(),
            &seed,
            &GrantRequest {
                session: hello.clone(),
                request: request.clone(),
            },
            deadline,
        )?;
        Ok(QuicReader {
            runtime: &runtime,
            connection: &connection,
            request,
            token,
            holder: &holder,
            exporter: hello.exporter,
            offset: 0,
            total,
            seq: 0,
            buffer: io::Cursor::new(vec![]),
            deadline,
            observation,
            cfg,
            certificate: cert.expose(),
            seed: &seed,
            session: &hello,
            renew_at: Instant::now() + Duration::from_millis(CAPABILITY_REFRESH_MS),
        })
    };
    let ciphertext = reader(
        &target.ciphertext_bao_root,
        EncryptedTarget::encoded_length(target.ciphertext_length)?,
        ciphertext_observation.clone(),
    )?;
    let keys = reader(
        &target.key_index_bao_root,
        EncryptedTarget::encoded_length(target.key_index_length)?,
        key_observation.clone(),
    )?;
    let result = verify_encrypted_streams(tf, target, key, ciphertext, keys, accept);
    if let Err(error) = &result {
        let cipher = ciphertext_observation
            .lock()
            .map_err(|_| err!(EIO, "L2_OBSERVATION"))?;
        let keys = key_observation
            .lock()
            .map_err(|_| err!(EIO, "L2_OBSERVATION"))?;
        // Retain separate evidence because Bao decoding interleaves both streams.
        // A local decryption failure never creates a peer poisoning allegation.
        let seen = if cipher.malformed {
            Some(&*cipher)
        } else if keys.malformed {
            Some(&*keys)
        } else {
            match error.reason.as_str() {
                "BAO_SLICE_CORRUPT" => Some(&*cipher),
                "BAO_KEY_INDEX_CORRUPT" | "BAO_KEY_INDEX_TRAILING" => Some(&*keys),
                _ => None,
            }
        };
        if let Some(seen) = seen {
            if !seen.transport_failed {
                if let Some((root, index, bytes)) = &seen.last {
                    poison.record(&holder, root, *index, bytes, &hello.exporter, now_ms).map_err(|failure|failure.into_enclave())?;
                }
            }
        }
    }
    connection.close(0u32.into(), b"finished");
    runtime.block_on(async {
        let _ = tokio::time::timeout(Duration::from_secs(1), endpoint.wait_idle()).await;
    });
    drop(endpoint);
    result
}
/// Production QUIC serving loop. The caller supplies current signed storage
/// authorization through its retrieval closure; the callback is invoked only
/// after mTLS peer/shard, allowlist, independent issuer, PoP and replay checks.
/// All returned segments must be bounded encoded Bao stream bytes.
pub async fn serve(
    endpoint: quinn::Endpoint,
    node: Arc<L2SwarmNode>,
    server_key: Arc<SigningKey>,
    get_slice: Arc<dyn Fn(&str, &str, u64) -> Option<Vec<u8>> + Send + Sync>,
    peer_authority: Arc<super::quic_seed::SeedPeerAuthority>,
    mut stop: tokio::sync::watch::Receiver<bool>,
) -> EnclaveResult<()> {
    let slots = Arc::new(tokio::sync::Semaphore::new(32));
    loop {
        tokio::select! {
            _ = stop.changed() => {
                endpoint.close(0u32.into(), b"stopped");
                return Ok(());
            },
            incoming = endpoint.accept() => {
                let Some(incoming) = incoming else {
                    return Ok(());
                };
                let Ok(slot) = slots.clone().try_acquire_owned() else {
                    incoming.refuse();
                    continue;
                };
                let node = node.clone();
                let signer = server_key.clone();
                let get = get_slice.clone();
                let admitted = peer_authority.clone();
                tokio::spawn(async move {
                    let _slot = slot;
                    let result = async {
                        let connection = tokio::time::timeout(Duration::from_secs(5), incoming).await.map_err(|_|err!(ETIMEDOUT, "L2_HANDSHAKE"))?.map_err(|_|err!(EACCES, "L2_HANDSHAKE"))?;
                        let (public, remote_shard, exporter) = connection_peer(&connection)?;
                        let allowed_at_handshake = admitted.currently_clean(&public);
                        let local_shard = match node.shard {
                            crate::governance::Shard::EU => "EU",
                            crate::governance::Shard::US => "US",
                            crate::governance::Shard::APAC => "APAC"
                        };
                        if remote_shard != local_shard {
                            fail!(EACCES, "L2_SHARD");
                        }
                        let peer = L2AuthenticatedPeer {
                            public_key: public,
                            channel_binding: exporter
                        };
                        let (mut send, mut recv) = tokio::time::timeout(Duration::from_secs(5), connection.accept_bi()).await.map_err(|_|err!(ETIMEDOUT, "L2_HELLO"))?.map_err(|_|err!(EIO, "L2_STREAM"))?;
                        if tokio::time::timeout(Duration::from_secs(5), read_frame(&mut recv)).await.map_err(|_|err!(ETIMEDOUT, "L2_HELLO"))?? != b"hello" {
                            fail!(EACCES, "L2_HELLO");
                        }
                        let mut hello = SessionHello {
                            epoch: node.authorization_epoch().into(),
                            server_key: signer.verifying_key().to_bytes(),
                            client_key: public,
                            exporter,
                            shard: local_shard.into(),
                            signature: vec![]
                        };
                        hello.signature = signer.sign(&hello.message()?).to_bytes().to_vec();
                        write_frame(&mut send, &serde_json::to_vec(&hello).map_err(|_|err!(EIO, "L2_HELLO"))?).await?;
                        for _ in 0..1_048_576 {
                            let streams = tokio::time::timeout(Duration::from_secs(30), connection.accept_bi()).await;
                            let Ok(Ok((mut send, mut recv))) = streams else {
                                break;
                            };
                            let request = tokio::time::timeout(Duration::from_millis(500), read_frame(&mut recv)).await.map_err(|_|err!(ETIMEDOUT, "L2_REQUEST_FRAME"))??;
                            let mut cursor = io::Cursor::new(&request);
                            let req: L2ChunkRequest = ciborium::from_reader(&mut cursor).map_err(|_|err!(EINVAL, "L2_REQUEST"))?;
                            if cursor.position() as usize != request.len() {
                                fail!(EINVAL, "L2_REQUEST_TRAILING");
                            }
                            let locally_allowed = allowed_at_handshake && admitted.currently_clean(&public);
                            let (response, authorization) = node.handle_request_authorized(&peer, &req, |root, index|if locally_allowed {
                                let bytes = get(&req.namespace_id, root, index).filter(|b|b.len() <= SEGMENT)?;
                                if admitted.currently_clean(&public) {
                                    Some(bytes)
                                } else {
                                    None
                                }
                            } else {
                                None
                            })?;
                            let bytes = match response {
                                L2ChunkResponse::Unavailable(frame) => frame,
                                L2ChunkResponse::Data {
                                    slice_index,
                                    slice_bytes
                                } => {
                                    let mut bytes = slice_index.to_be_bytes().to_vec();
                                    bytes.extend_from_slice(&slice_bytes);
                                    bytes
                                }
                            };
                            if let Some(authorization) = authorization {
                                let release_started = Instant::now();
                                let mut data_started = false;
                                let outcome = tokio::time::timeout(Duration::from_millis(500), write_authorized_frame(&mut send, &bytes, &node, &peer, &authorization, admitted.as_ref(), &mut data_started)).await.map_err(|_|err!(ETIMEDOUT, "L2_RELEASE_DEADLINE")).and_then(|result|result);
                                #[cfg(test)]
                                fence_tests::record_release_result(&node, &peer, authorization.expires_ms, &outcome);
                                if let Err(error) = outcome {
                                    if data_started {
                                        let _ = send.reset(1u32.into());
                                    } else {
                                        // A refusal before any DATA write retains the established
                                        // fixed padded unavailable response and exposes no reason.
                                        super::constant_time::pad_to_budget(release_started, node.pad_budget);
                                        let unavailable = super::constant_time::generate_unavailable_frame(&key32(&req.root_hash)?, req.slice_index);
                                        write_frame(&mut send, &unavailable).await?;
                                    }
                                    #[cfg(test)]
                                    fence_tests::record_refusal_complete(&node, &peer);
                                    let _ = error;
                                }
                            } else {
                                write_frame(&mut send, &bytes).await?;
                            }
                        }
                        Ok::<(),
                        enclave_core::error::EnclaveError>(())
                    }.await;
                    if result.is_err() {
                        /* no peer-controlled bytes or credentials in logs */
                    }
                });
            }
        }
    }
}
/// Build a mandatory-client-auth server endpoint from explicitly provisioned
/// certificate/key material and roots. ALPN is fixed; no unauthenticated mode.
pub fn server_endpoint(
    address: SocketAddr,
    cert: Vec<u8>,
    seed: &[u8; 32],
    roots_der: &[Vec<u8>],
) -> EnclaveResult<quinn::Endpoint> {
    let cfg=server_configuration(cert,seed,roots_der)?;
    quinn::Endpoint::server(cfg,address).map_err(|_|err!(EIO,"L2_ENDPOINT"))
}
fn server_configuration(cert:Vec<u8>,seed:&[u8;32],roots_der:&[Vec<u8>])->EnclaveResult<quinn::ServerConfig> {
    let mut roots = rustls::RootCertStore::empty();
    for der in roots_der {
        roots
            .add(CertificateDer::from(der.clone()))
            .map_err(|_| err!(EINVAL, "L2_TLS_ROOT"))?;
    }
    let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
        Arc::new(roots),
        Arc::new(rustls::crypto::ring::default_provider()),
    )
    .build()
    .map_err(|_| err!(EINVAL, "L2_CLIENT_VERIFIER"))?;
    let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .map_err(|_| err!(EINVAL, "L2_TLS_CONFIG"))?
    .with_client_cert_verifier(verifier)
    .with_single_cert(vec![CertificateDer::from(cert)], private_der(seed))
    .map_err(|_| err!(EINVAL, "L2_TLS_IDENTITY"))?;
    tls.alpn_protocols = vec![CAS_SWARM_ALPN.to_vec()];
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls)
        .map_err(|_| err!(EINVAL, "L2_QUIC_CONFIG"))?;
    let mut cfg = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    let mut limits = quinn::TransportConfig::default();
    limits.max_concurrent_bidi_streams(2u32.into());
    limits.max_concurrent_uni_streams(0u32.into());
    limits.max_idle_timeout(Some(
        Duration::from_secs(30)
            .try_into()
            .map_err(|_| err!(EINVAL, "L2_QUIC_CONFIG"))?,
    ));
    cfg.transport = Arc::new(limits);
    Ok(cfg)
}
/// Mandatory mTLS1.3 HTTPS issuer configuration. The same root verification as
/// QUIC applies, while its certificate/authority remains independently pinned.
pub fn issuer_server_config(
    cert: Vec<u8>,
    seed: &[u8; 32],
    roots_der: &[Vec<u8>],
) -> EnclaveResult<Arc<rustls::ServerConfig>> {
    let mut roots = rustls::RootCertStore::empty();
    for der in roots_der {
        roots
            .add(CertificateDer::from(der.clone()))
            .map_err(|_| err!(EINVAL, "L2_TLS_ROOT"))?;
    }
    let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
        Arc::new(roots),
        Arc::new(rustls::crypto::ring::default_provider()),
    )
    .build()
    .map_err(|_| err!(EINVAL, "L2_CLIENT_VERIFIER"))?;
    let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .map_err(|_| err!(EINVAL, "L2_TLS_CONFIG"))?
    .with_client_cert_verifier(verifier)
    .with_single_cert(vec![CertificateDer::from(cert)], private_der(seed))
    .map_err(|_| err!(EINVAL, "L2_TLS_IDENTITY"))?;
    tls.alpn_protocols = vec![CAS_SWARM_ALPN.to_vec()];
    Ok(Arc::new(tls))
}
/// Serve one bounded HTTPS capability request using the actual TLS client key.
/// Caller owns admission/concurrency limits and the child socket lifecycle.
/// Every rejection is an equal256B body with no scope/inventory diagnostics.
pub fn serve_issuer_connection(
    socket: std::net::TcpStream,
    tls: Arc<rustls::ServerConfig>,
    policy: &IssuerPolicy,
) -> EnclaveResult<()> {
    let deadline = Instant::now() + Duration::from_secs(5);
    let conn = rustls::ServerConnection::new(tls).map_err(|_| err!(EIO, "L2_ISSUER_TLS"))?;
    let mut stream = rustls::StreamOwned::new(conn, DeadlineSocket { socket, deadline });
    while stream.conn.is_handshaking() {
        stream
            .conn
            .complete_io(&mut stream.sock)
            .map_err(|_| err!(EACCES, "L2_ISSUER_TLS"))?;
    }
    let certificate = stream
        .conn
        .peer_certificates()
        .and_then(|c| c.first())
        .ok_or_else(|| err!(EACCES, "L2_ISSUER_CLIENT"))?;
    let (client, client_shard) = certificate_identity(certificate.as_ref())?;
    let result = (|| -> EnclaveResult<Vec<u8>> {
        let mut header = Vec::new();
        while !header.ends_with(b"\r\n\r\n") {
            if header.len() >= 16384 {
                fail!(E2BIG, "L2_ISSUER_HEADERS");
            }
            let mut b = [0];
            stream
                .read_exact(&mut b)
                .map_err(|_| err!(EIO, "L2_ISSUER_READ"))?;
            header.push(b[0]);
        }
        let text = std::str::from_utf8(&header).map_err(|_| err!(EINVAL, "L2_ISSUER_HEADERS"))?;
        let mut lines = text[..text.len() - 4].split("\r\n");
        if lines.next() != Some("POST /v1/cas/capability HTTP/1.1") {
            fail!(EACCES, "L2_ISSUER_ROUTE");
        }
        let mut length = None;
        let mut headers = BTreeSet::new();
        for (i, line) in lines.enumerate() {
            let (k, v) = line
                .split_once(':')
                .ok_or_else(|| err!(EINVAL, "L2_ISSUER_HEADERS"))?;
            let k = k.to_ascii_lowercase();
            if i >= 128
                || !headers.insert(k.clone())
                || k == "transfer-encoding"
                || k == "content-encoding"
            {
                fail!(EINVAL, "L2_ISSUER_HEADERS");
            }
            if k == "content-length" {
                length = Some(
                    v.trim()
                        .parse::<usize>()
                        .map_err(|_| err!(EINVAL, "L2_ISSUER_HEADERS"))?,
                );
            }
        }
        let length = length
            .filter(|n| *n > 0 && *n <= FRAME)
            .ok_or_else(|| err!(E2BIG, "L2_ISSUER_SIZE"))?;
        let mut body = vec![0; length];
        stream
            .read_exact(&mut body)
            .map_err(|_| err!(EIO, "L2_ISSUER_READ"))?;
        let request: GrantRequest =
            serde_json::from_slice(&body).map_err(|_| err!(EINVAL, "L2_ISSUER_REQUEST"))?;
        if request.session.shard != client_shard {
            fail!(EACCES, "L2_ISSUER_SHARD");
        }
        policy.issue(client, &request)
    })();
    let (status, body) = match result {
        Ok(bytes) => ("200 OK", bytes),
        Err(_) => ("403 Forbidden", vec![0; 256]),
    };
    let header=format!("HTTP/1.1 {status}\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",body.len());
    stream
        .write_all(header.as_bytes())
        .and_then(|_| stream.write_all(&body))
        .and_then(|_| stream.flush())
        .map_err(|_| err!(EIO, "L2_ISSUER_WRITE"))?;
    stream.conn.send_close_notify();
    stream.flush().map_err(|_| err!(EIO, "L2_ISSUER_WRITE"))?;
    Ok(())
}

#[cfg(test)]
#[path="quic_fence_tests.rs"]
pub(crate) mod fence_tests;

#[cfg(test)]
#[path = "served_quota_quic_tests.rs"]
mod quota_acceptance_tests;

#[cfg(test)]
#[path = "quic_metered_handoff_tests.rs"]
mod metered_handoff_tests;

#[cfg(test)]
mod credential_owner_tests {
    use super::*;
    use std::{cell::RefCell, rc::Rc};
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};

    type Cleanup = (Option<usize>, bool, bool);
    type Observations = Rc<RefCell<Vec<Cleanup>>>;

    fn observed(length: usize) -> (CredentialReadBuffer, Observations) {
        let events = Rc::new(RefCell::new(Vec::new()));
        let copy = events.clone();
        let mut owner = CredentialReadBuffer::new(length).unwrap();
        owner.cleanup_observer = Some(Box::new(move |bytes, extra| {
            copy.borrow_mut().push((bytes.map(<[u8]>::len),
                bytes.map_or(true, |value| value.iter().all(|byte| *byte == 0)),
                extra.iter().all(|byte| *byte == 0)));
        }));
        (owner, events)
    }

    struct Chunks {
        input: io::Cursor<Vec<u8>>,
        interrupted: bool,
        probe_interrupted: bool,
        first: Option<*const u8>,
    }
    impl Read for Chunks {
        fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
            if self.first.is_none() {
                assert!(output.iter().all(|byte| *byte == 0), "initialized before first read");
                self.first = Some(output.as_ptr());
            }
            if !self.interrupted {
                self.interrupted = true;
                return Err(io::ErrorKind::Interrupted.into());
            }
            if self.input.position() as usize == self.input.get_ref().len() && !self.probe_interrupted {
                self.probe_interrupted = true;
                return Err(io::ErrorKind::Interrupted.into());
            }
            let count = output.len().min(7);
            self.input.read(&mut output[..count])
        }
    }

    struct FaultAfter { cutoff: usize, written: usize, unwind: bool }
    impl Read for FaultAfter {
        fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
            if self.written < self.cutoff {
                let count = output.len().min(self.cutoff - self.written);
                output[..count].fill(0xa7);
                self.written += count;
                return Ok(count);
            }
            // Also cover a reader dirtying a buffer before an error/unwind,
            // including the private lookahead slot after a complete body.
            output.fill(0xb9);
            if self.unwind { panic!("synthetic credential reader unwind"); }
            Err(io::Error::other("synthetic credential reader error"))
        }
    }

    struct Fixture(std::path::PathBuf);
    impl Fixture {
        fn new() -> Self {
            let path = std::env::temp_dir().canonicalize().unwrap().join(format!(
                "mcpmac-quic-credential-owner-{:016x}", enclave_core::rng::u64()));
            std::fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
            Self(path)
        }
        fn file(&self, name: &str, length: usize, mode: u32) -> std::path::PathBuf {
            let path = self.0.join(name);
            let mut file = std::fs::OpenOptions::new().create_new(true).write(true)
                .mode(0o600).open(&path).unwrap();
            file.write_all(&vec![0xa7; length]).unwrap();
            file.set_permissions(std::fs::Permissions::from_mode(mode)).unwrap();
            path
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.0); }
    }

    #[test]
    fn fixed_initialized_owner_preserves_chunked_bytes_and_same_allocation_on_success() {
        for length in [1, 32, 16384] {
            let expected = vec![0xa7; length];
            let mut reader = Chunks { input: io::Cursor::new(expected.clone()), interrupted: false, probe_interrupted: false, first: None };
            let (owner, events) = observed(length);
            let secret = owner.read(&mut reader).unwrap();
            assert!(secret.expose() == expected.as_slice());
            assert!(Some(secret.expose().as_ptr()) == reader.first, "same allocation transferred");
            assert_eq!(&*events.borrow(), &[(None, true, true)]);
        }
    }

    #[test]
    fn partial_and_lookahead_read_errors_wipe_full_live_owner_and_probe() {
        for cutoff in [8, 32] {
            let (owner, events) = observed(32);
            let error = owner.read(&mut FaultAfter { cutoff, written: 0, unwind: false }).unwrap_err();
            assert!(error.is("L2_CREDENTIAL_READ"));
            assert_eq!(&*events.borrow(), &[(Some(32), true, true)]);
        }
    }

    #[test]
    fn short_and_grown_reads_preserve_change_reason_and_cleanup_every_initialized_byte() {
        for actual in [0, 7, 31, 33, 16385] {
            let (owner, events) = observed(32);
            let mut reader = io::Cursor::new(vec![0xa7; actual]);
            assert!(owner.read(&mut reader).unwrap_err().is("L2_CREDENTIAL_CHANGED"));
            assert!(reader.position() <= 33, "only one extra byte is read");
            assert_eq!(&*events.borrow(), &[(Some(32), true, true)]);
        }
    }

    #[test]
    fn reader_unwind_scrubs_body_and_probe_and_invalid_bounds_refuse_before_read() {
        for cutoff in [8, 32] {
            let (owner, events) = observed(32);
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _ = owner.read(&mut FaultAfter { cutoff, written: 0, unwind: true });
            }));
            assert!(result.is_err());
            assert_eq!(&*events.borrow(), &[(Some(32), true, true)]);
        }
        for length in [0, 16385, usize::MAX] {
            assert!(CredentialReadBuffer::new(length).err().unwrap().is("L2_CREDENTIAL_INSECURE"));
        }
    }

    #[test]
    fn actual_file_descriptor_truncation_and_growth_after_metadata_refuse_and_scrub() {
        let fixture = Fixture::new();
        for (name, changed) in [("short", 7), ("grown", 33)] {
            let path = fixture.file(name, 32, 0o600);
            let mut file = std::fs::File::open(&path).unwrap();
            let observed_length = file.metadata().unwrap().len() as usize;
            std::fs::write(&path, vec![0xa7; changed]).unwrap();
            let (owner, events) = observed(observed_length);
            assert!(owner.read(&mut file).unwrap_err().is("L2_CREDENTIAL_CHANGED"));
            assert_eq!(&*events.borrow(), &[(Some(32), true, true)]);
        }
    }

    #[test]
    fn actual_loader_preserves_secure_file_policy_and_nonregular_symlink_refusals() {
        let fixture = Fixture::new();
        let secret = fixture.file("seed", 32, 0o600);
        let bytes = credential(secret.to_str().unwrap(), true).unwrap();
        assert!(bytes.expose() == [0xa7; 32]);
        let maximum = fixture.file("maximum", 16384, 0o600);
        assert_eq!(credential(maximum.to_str().unwrap(), true).unwrap().len(), 16384);
        let public = fixture.file("certificate", 32, 0o644);
        assert!(credential(public.to_str().unwrap(), false).is_ok());
        assert!(credential(public.to_str().unwrap(), true).unwrap_err().is("L2_CREDENTIAL_INSECURE"));
        for (name, length, mode) in [("empty", 0, 0o600), ("large", 16385, 0o600), ("writable", 32, 0o622)] {
            let path = fixture.file(name, length, mode);
            assert!(credential(path.to_str().unwrap(), false).unwrap_err().is("L2_CREDENTIAL_INSECURE"));
        }
        let link = fixture.0.join("symlink");
        std::os::unix::fs::symlink(&secret, &link).unwrap();
        assert!(credential(link.to_str().unwrap(), true).unwrap_err().is("L2_CREDENTIAL_OPEN"));
        assert!(credential(fixture.0.to_str().unwrap(), true).unwrap_err().is("L2_CREDENTIAL_INSECURE"));
        let fifo = fixture.0.join("fifo");
        use std::os::unix::ffi::OsStrExt;
        let fifo_c = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
        // SAFETY: a live NUL-terminated path in this exclusively owned fixture;
        // mkfifo creates only that synthetic path and does not read credentials.
        assert_eq!(unsafe { libc::mkfifo(fifo_c.as_ptr(), 0o600) }, 0);
        assert!(credential(fifo.to_str().unwrap(), true).unwrap_err().is("L2_CREDENTIAL_INSECURE"));
    }
}
