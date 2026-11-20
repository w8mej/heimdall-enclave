//! Explicit, owned L2 seed lifecycle. Signed configuration never implies L3
//! listeners. Sources are reauthenticated and authority/hardware rechecked on
//! every bounded retrieval; source paths are not peer supplied.
use super::{
    iroh::{L2CapabilityPolicy, L2SwarmNode},
    quic::{self, SEGMENT},
};
use crate::{
    governance::Shard,
    seedgate::{HostConditions, SeedGateFSM, Thermal},
    service::CasService,
};
use ed25519_dalek::SigningKey;
use enclave_core::{err, error::EnclaveResult, fail, profile::Profile};
use serde::{Deserialize, Serialize};
use std::{
    io::{Read, Seek, SeekFrom},
    os::unix::{
        fs::{MetadataExt, OpenOptionsExt},
        io::{AsRawFd, FromRawFd},
    },
    path::{Component, Path},
    sync::Arc,
};
const MAX_PLAINTEXT: u64 = 8 * 1024 * 1024 * 1024;
// Preserve the full8GiB plaintext envelope after per-leaf AEAD expansion.
const MAX_SOURCE: u64 = MAX_PLAINTEXT
    + MAX_PLAINTEXT.div_ceil(enclave_crypto::namespace::PLAINTEXT_SIZE as u64)
        * enclave_crypto::namespace::CHUNK_OVERHEAD as u64;
const CACHE_BUDGET: u64 = MAX_PLAINTEXT + MAX_PLAINTEXT / 8;
/// Signed bounded local seed configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SeedConfig {
    /// Explicit numeric local UDP bind address.
    pub bind: String,
    /// Independently signed exact certificate public-key allowlist.
    pub authorized_peer_keys: Vec<String>,
    /// Ciphertext and key-index Bao sources, never plaintext.
    pub sources: Vec<SeedSource>,
}
/// Signed raw encrypted-data length and full Bao-encoded source path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SeedSource {
    /// Exact signed artifact namespace.
    pub namespace: String,
    /// Signed ciphertext or key-index Bao root.
    pub root: String,
    /// Absolute trusted local full-range Bao encoding.
    pub path: String,
    /// Original encrypted payload length before Bao encoding.
    pub payload_length: u64,
}
fn valid_key(key: &str) -> bool {
    key.len() == 64
        && key
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
impl SeedConfig {
    /// Validate finite source/peer inventory and canonical paths.
    pub fn validate(&self) -> EnclaveResult<()> {
        let bind: std::net::SocketAddr = self
            .bind
            .parse()
            .map_err(|_| err!(EINVAL, "L2_SEED_BIND"))?;
        // Installed L2 Seatbelt policy has one dedicated listener port.
        if bind.port() != 4433 {
            fail!(EINVAL, "L2_SEED_BIND_PORT");
        }
        if self.sources.is_empty()
            || self.sources.len() > 64
            || self.authorized_peer_keys.is_empty()
            || self.authorized_peer_keys.len() > 1024
        {
            fail!(E2BIG, "L2_SEED_CONFIG");
        }
        let mut keys = std::collections::BTreeSet::new();
        for key in &self.authorized_peer_keys {
            if !valid_key(key) || !keys.insert(key) {
                fail!(EINVAL, "L2_SEED_PEER");
            }
        }
        let mut sources = std::collections::BTreeSet::new();
        for source in &self.sources {
            if source.namespace.is_empty()
                || source.namespace.len() > 256
                || source.namespace.bytes().any(|b| b.is_ascii_control())
                || !valid_key(&source.root)
                || source.payload_length == 0
                || source.payload_length > MAX_SOURCE
                || !Path::new(&source.path).is_absolute()
                || source.path.len() > 4096
                || !Path::new(&source.path)
                    .components()
                    .all(|c| matches!(c, Component::RootDir | Component::Normal(_)))
                || !sources.insert((&source.namespace, &source.root))
            {
                fail!(EINVAL, "L2_SEED_SOURCE");
            }
        }
        Ok(())
    }
}
/// Opaque configured peer authority, reserved before any operational listener.
/// Standalone adapters and daemon listeners share the process-lifetime stops.
#[derive(Debug)]
pub struct SeedPeerAuthority {
    domain: super::quic_poison::PeerDomain,
}
impl SeedPeerAuthority {
    /// Provision only independently trusted configured peer and detector keys.
    pub fn from_trusted_peers(path: &str, detector: [u8; 32], peers: &[[u8; 32]]) -> EnclaveResult<Arc<Self>> {
        Self::with_peer_stops(path, detector, peers, super::quic_poison::process_peer_stops())
    }
    pub(crate) fn with_peer_stops(path: &str, detector: [u8; 32], peers: &[[u8; 32]], stops: Arc<super::quic_poison::ProcessPeerStops>) -> EnclaveResult<Arc<Self>> {
        Ok(Arc::new(Self {
            domain: stops.reserve_domain(path, detector, peers)?
        }))
    }
    pub(crate) fn peer(&self, peer: &[u8; 32]) -> EnclaveResult<&Arc<super::quic_poison::PoisonState>> {
        self.domain.peer(peer)
    }
    pub(crate) fn currently_clean(&self, peer: &[u8; 32]) -> bool {
        self.peer(peer).and_then(|state|state.clean_lease()).is_ok()
    }
}
/// Observe AC, network cost/constraint and thermal/low-power state through SDKs.
/// Any unsupported platform, timeout or missing measurement is pull-only.
pub fn observed_conditions() -> EnclaveResult<HostConditions> {
    #[cfg(target_os = "macos")]
    {
        unsafe extern "C" {
            fn mcpmac_seed_conditions(flags: *mut u32) -> i32;
        }
        let mut flags = 0;
        if unsafe { mcpmac_seed_conditions(&mut flags) } != 0 {
            fail!(EAGAIN, "SEED_OBSERVATION_UNAVAILABLE");
        }
        Ok(HostConditions {
            ac_power: flags & 1 != 0,
            unmetered: flags & 2 != 0,
            hotspot: flags & 2 == 0,
            thermal: if flags & 4 != 0 {
                Thermal::Nominal
            } else {
                Thermal::Serious
            },
            low_power: flags & 8 != 0,
        })
    }
    #[cfg(not(target_os = "macos"))]
    {
        fail!(ENOSYS, "SEED_OBSERVATION_UNAVAILABLE")
    }
}
/// Walk held directory descriptors without following any source/ancestor link.
fn source_file(path: &str) -> EnclaveResult<std::fs::File> {
    let mut dir = std::fs::File::open("/").map_err(|_| err!(EACCES, "SEED_SOURCE_PARENT"))?;
    let parts: Vec<_> = Path::new(path)
        .components()
        .filter_map(|c| {
            if let Component::Normal(p) = c {
                Some(p)
            } else {
                None
            }
        })
        .collect();
    for (i, part) in parts.iter().enumerate() {
        let name = std::ffi::CString::new(std::os::unix::ffi::OsStrExt::as_bytes(*part))
            .map_err(|_| err!(EINVAL, "SEED_SOURCE_PATH"))?;
        let last = i + 1 == parts.len();
        let flags = libc::O_RDONLY
            | libc::O_NOFOLLOW
            | libc::O_CLOEXEC
            | libc::O_NONBLOCK
            | if last { 0 } else { libc::O_DIRECTORY };
        let fd = unsafe { libc::openat(dir.as_raw_fd(), name.as_ptr(), flags) };
        if fd < 0 {
            fail!(EACCES, "SEED_SOURCE_OPEN");
        }
        dir = unsafe { std::fs::File::from_raw_fd(fd) };
        let m = dir
            .metadata()
            .map_err(|_| err!(EACCES, "SEED_SOURCE_METADATA"))?;
        if (m.uid() != 0 && m.uid() != enclave_core::ipc::geteuid())
            || (m.mode() & 0o022 != 0 && !(m.is_dir() && m.uid() == 0 && m.mode() & 0o1000 != 0))
            || (!last && !m.is_dir())
            || (last && !m.is_file())
        {
            fail!(EACCES, "SEED_SOURCE_ANCESTRY");
        }
    }
    Ok(dir)
}
fn identity(m: &std::fs::Metadata) -> (u64, u64, u64, i64, i64, i64, i64) {
    (
        m.dev(),
        m.ino(),
        m.len(),
        m.mtime(),
        m.mtime_nsec(),
        m.ctime(),
        m.ctime_nsec(),
    )
}
fn verify_source(file: &mut std::fs::File, source: &SeedSource) -> EnclaveResult<()> {
    use bao_tree::{io::sync::DecodeResponseIter, BaoTree, ChunkRanges};
    file.seek(SeekFrom::Start(0))
        .map_err(|_| err!(EIO, "SEED_SOURCE_READ"))?;
    let encoded = super::oblivious::EncryptedTarget::encoded_length(source.payload_length)?;
    if file
        .metadata()
        .map_err(|_| err!(EIO, "SEED_SOURCE_METADATA"))?
        .len()
        != encoded
    {
        fail!(EACCES, "SEED_SOURCE_SIZE");
    }
    let root = bao_tree::blake3::Hash::from_hex(&source.root)
        .map_err(|_| err!(EINVAL, "SEED_SOURCE_ROOT"))?;
    let all = ChunkRanges::all();
    for item in DecodeResponseIter::new(
        root,
        BaoTree::new(source.payload_length, crate::bao::block_size()),
        &mut *file,
        &all,
    ) {
        item.map_err(|_| err!(EACCES, "SEED_SOURCE_CORRUPT"))?;
    }
    if file
        .read(&mut [0])
        .map_err(|_| err!(EIO, "SEED_SOURCE_READ"))?
        != 0
    {
        fail!(EACCES, "SEED_SOURCE_TRAILING");
    }
    Ok(())
}
fn read_segment(file: &mut std::fs::File, encoded: u64, index: u64) -> EnclaveResult<Vec<u8>> {
    let offset = index
        .checked_mul(SEGMENT as u64)
        .filter(|o| *o < encoded)
        .ok_or_else(|| err!(EINVAL, "SEED_SOURCE_INDEX"))?;
    file.seek(SeekFrom::Start(offset))
        .map_err(|_| err!(EIO, "SEED_SOURCE_READ"))?;
    let mut bytes = vec![0; (encoded - offset).min(SEGMENT as u64) as usize];
    file.read_exact(&mut bytes)
        .map_err(|_| err!(EIO, "SEED_SOURCE_READ"))?;
    Ok(bytes)
}
/// Authenticate a complete encoding on one pinned FD before returning a segment.
/// This direct helper is used by source-boundary regression fixtures; production
/// listeners use the immutable RO cache below to authenticate each source once.
pub fn authenticated_slice(source: &SeedSource, index: u64) -> EnclaveResult<Vec<u8>> {
    let mut file = source_file(&source.path)?;
    let before = file
        .metadata()
        .map_err(|_| err!(EIO, "SEED_SOURCE_METADATA"))?;
    verify_source(&mut file, source)?;
    let bytes = read_segment(
        &mut file,
        super::oblivious::EncryptedTarget::encoded_length(source.payload_length)?,
        index,
    )?;
    if identity(&before)
        != identity(
            &file
                .metadata()
                .map_err(|_| err!(EIO, "SEED_SOURCE_METADATA"))?,
        )
    {
        fail!(EACCES, "SEED_SOURCE_CHANGED");
    }
    Ok(bytes)
}
type SourceIdentity = (u64, u64, u64, i64, i64, i64, i64);
struct VerifiedSource {
    file: std::fs::File,
    source_identity: SourceIdentity,
    length: u64,
}
/// Finite disk-backed cache. Every file is unlinked while first opened, then
/// verified completely and retained only through a read-only descriptor. No
/// writable descriptor remains when any bytes are returned. Process exit/Drop
/// releases disk space automatically, including interrupted copies.
struct SourceCache {
    directory: std::fs::File,
    _lock: std::fs::File,
    path: std::path::PathBuf,
    staging: super::quota::ArtifactStaging,
    sources: std::collections::BTreeMap<(String, String), VerifiedSource>,
    used: u64,
}
impl SourceCache {
    fn new(path: &str) -> EnclaveResult<Self> {
        let directory = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
            .map_err(|_| err!(EACCES, "SEED_CACHE_DIRECTORY"))?;
        let metadata = directory
            .metadata()
            .map_err(|_| err!(EACCES, "SEED_CACHE_DIRECTORY"))?;
        if metadata.uid() != enclave_core::ipc::geteuid() || metadata.mode() & 0o777 != 0o700 {
            fail!(EACCES, "SEED_CACHE_DIRECTORY");
        }
        let lock=std::fs::File::options().read(true).write(true).create(true).truncate(false).mode(0o600)
            .custom_flags(libc::O_NOFOLLOW|libc::O_NONBLOCK|libc::O_CLOEXEC).open(Path::new(path).join(".seed-cache.lock"))
            .map_err(|_|err!(EACCES,"SEED_CACHE_LOCK"))?;
        let lm=lock.metadata().map_err(|_|err!(EACCES,"SEED_CACHE_LOCK"))?;
        if !lm.is_file() || lm.uid()!=metadata.uid() || lm.nlink()!=1 || lm.mode()&0o777!=0o600
            || unsafe{libc::flock(lock.as_raw_fd(),libc::LOCK_EX|libc::LOCK_NB)}!=0 {fail!(EACCES,"SEED_CACHE_LOCK");}
        // A named file exists only when unlink failed before any bytes were
        // accepted. Reconcile exclusively owned legacy/new random names only
        // after the per-directory singleton; never touch another live cache.
        for entry in std::fs::read_dir(path).map_err(|_|err!(EIO,"SEED_CACHE_CLEANUP"))? {
            let entry=entry.map_err(|_|err!(EIO,"SEED_CACHE_CLEANUP"))?;let leaf=entry.file_name();let leaf=leaf.to_string_lossy();
            if !leaf.strip_prefix(".seed-").is_some_and(|tail|!tail.is_empty() && tail.bytes().all(|b|b.is_ascii_hexdigit())) {continue;}
            let m=std::fs::symlink_metadata(entry.path()).map_err(|_|err!(EIO,"SEED_CACHE_CLEANUP"))?;
            if !m.is_file() || m.uid()!=metadata.uid() || m.nlink()!=1 || !matches!(m.mode()&0o777,0o600|0o400) {fail!(EACCES,"SEED_CACHE_CLEANUP_IDENTITY");}
            let file=std::fs::File::options().read(true).custom_flags(libc::O_NOFOLLOW|libc::O_NONBLOCK|libc::O_CLOEXEC)
                .open(entry.path()).map_err(|_|err!(EIO,"SEED_CACHE_CLEANUP"))?;
            super::quota::remove_owned(&entry.path(),&file)?;
        }
        Ok(Self {
            directory,
            _lock: lock,
            path: path.into(),
            staging: Default::default(),
            sources: std::collections::BTreeMap::new(),
            used: 0,
        })
    }
    fn slice(&mut self, source: &SeedSource, index: u64) -> EnclaveResult<Vec<u8>> {
        self.staging.retry_cleanup()?;
        let mut original = source_file(&source.path)?;
        let before = original
            .metadata()
            .map_err(|_| err!(EIO, "SEED_SOURCE_METADATA"))?;
        let encoded = super::oblivious::EncryptedTarget::encoded_length(source.payload_length)?;
        if source.payload_length > MAX_SOURCE || before.len() != encoded {
            fail!(E2BIG, "SEED_SOURCE_SIZE");
        }
        if index
            .checked_mul(SEGMENT as u64)
            .is_none_or(|offset| offset >= encoded)
        {
            fail!(EINVAL, "SEED_SOURCE_INDEX");
        }
        let key = (source.namespace.clone(), source.root.clone());
        if self.sources.get(&key).is_some_and(|cached| {
            cached.source_identity != identity(&before) || cached.length != encoded
        }) {
            if let Some(old) = self.sources.remove(&key) {
                self.used -= old.length;
            }
        }
        if !self.sources.contains_key(&key) {
            // This ledger concerns the signed encrypted Bao representation,
            // not its unrelated plaintext CAS root/length. One full encoding
            // is transient until authentication promotes it to retained cache.
            let reservation=self.staging.reserve(&source.root,encoded,encoded)?;
            if self
                .used
                .checked_add(encoded)
                .is_none_or(|n| n > CACHE_BUDGET)
            {
                fail!(ENOMEM, "SEED_CACHE_BUDGET");
            }
            let mut capacity = std::mem::MaybeUninit::<libc::statvfs>::uninit();
            if unsafe { libc::fstatvfs(self.directory.as_raw_fd(), capacity.as_mut_ptr()) } != 0 {
                fail!(EIO, "SEED_CACHE_CAPACITY");
            }
            let capacity = unsafe { capacity.assume_init() };
            let available = (capacity.f_bavail as u64)
                .checked_mul(capacity.f_frsize as u64)
                .ok_or_else(|| err!(E2BIG, "SEED_CACHE_CAPACITY"))?;
            if encoded
                .checked_add(256 * 1024 * 1024)
                .is_none_or(|required| required > available)
            {
                fail!(ENOMEM, "SEED_CACHE_CAPACITY");
            }
            let leaf =
                std::ffi::CString::new(format!(".seed-{:x}", enclave_core::rng::u64())).unwrap();
            let fd = unsafe {
                libc::openat(
                    self.directory.as_raw_fd(),
                    leaf.as_ptr(),
                    libc::O_RDWR
                        | libc::O_CREAT
                        | libc::O_EXCL
                        | libc::O_NOFOLLOW
                        | libc::O_CLOEXEC,
                    // The creator's O_RDWR descriptor remains writable until
                    // verification; no later writer can open this private name.
                    0o400,
                )
            };
            if fd < 0 {
                fail!(EIO, "SEED_CACHE_CREATE");
            }
            let mut writer = unsafe { std::fs::File::from_raw_fd(fd) };
            let read_fd = unsafe {
                libc::openat(
                    self.directory.as_raw_fd(),
                    leaf.as_ptr(),
                    libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
            // Unlink even if reopening fails; all later errors leave no name.
            let removed = unsafe { libc::unlinkat(self.directory.as_raw_fd(), leaf.as_ptr(), 0) };
            if read_fd < 0 || removed != 0 {
                if read_fd >= 0 {
                    drop(unsafe { std::fs::File::from_raw_fd(read_fd) });
                }
                if removed != 0 { reservation.defer_cleanup(self.path.join(leaf.to_str().unwrap()),writer); }
                fail!(EIO, "SEED_CACHE_UNLINK");
            }
            let mut reader = unsafe { std::fs::File::from_raw_fd(read_fd) };
            enclave_core::staging::preallocate(&writer,encoded)?;
            let copied = std::io::copy(&mut (&mut original).take(encoded), &mut writer)
                .map_err(|_| err!(EIO, "SEED_CACHE_COPY"))?;
            if copied != encoded
                || original.read(&mut [0]).map_err(|_|err!(EIO,"SEED_CACHE_COPY"))? != 0
                || identity(&before)
                    != identity(
                        &original
                            .metadata()
                            .map_err(|_| err!(EIO, "SEED_SOURCE_METADATA"))?,
                    )
            {
                fail!(EACCES, "SEED_SOURCE_CHANGED");
            }
            writer
                .sync_all()
                .map_err(|_| err!(EIO, "SEED_CACHE_SYNC"))?;
            drop(writer);
            verify_source(&mut reader, source)?;
            // Immutable authenticated bytes now belong to CACHE_BUDGET, rather
            // than transient staging. There is no extra copy at promotion.
            drop(reservation);
            self.used += encoded;
            self.sources.insert(
                key.clone(),
                VerifiedSource {
                    file: reader,
                    source_identity: identity(&before),
                    length: encoded,
                },
            );
        }
        let cached = self
            .sources
            .get_mut(&key)
            .ok_or_else(|| err!(EIO, "SEED_CACHE_STATE"))?;
        let bytes = read_segment(&mut cached.file, cached.length, index)?;
        let after = source_file(&source.path)?
            .metadata()
            .map_err(|_| err!(EIO, "SEED_SOURCE_METADATA"))?;
        if identity(&before) != identity(&after) {
            if let Some(old) = self.sources.remove(&key) {
                self.used -= old.length;
            }
            fail!(EACCES, "SEED_SOURCE_CHANGED");
        }
        Ok(bytes)
    }
}
/// Owns stop signal and thread. Drop cancels listeners and joins all runtime work.
#[derive(Debug)]
pub struct SeedListener {
    stop: tokio::sync::watch::Sender<bool>,
    thread: Option<std::thread::JoinHandle<()>>,
}
impl Drop for SeedListener {
    fn drop(&mut self) {
        let _ = self.stop.send(true);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}
impl SeedListener {
    /// Start only an explicitly configured signed L2 listener. A missing config
    /// keeps pull-only behavior. Bind/setup failures propagate before IPC serve.
    pub fn start(service: Arc<CasService>) -> EnclaveResult<Option<Self>> {
        let Some(cfg) = service.l2_seed_config()? else {
            return Ok(None);
        };
        let Some(seed_cfg) = cfg.seed.clone() else {
            return Ok(None);
        };
        cfg.validate()?;
        let certificate = quic::credential(&cfg.client_certificate_der_path, false)?;
        let bytes = quic::credential(&cfg.client_key_seed_path, true)?;
        let seed = zeroize::Zeroizing::new(
            <[u8; 32]>::try_from(bytes.expose()).map_err(|_| err!(EACCES, "L2_IDENTITY_SEED"))?,
        );
        let signer = Arc::new(SigningKey::from_bytes(&seed));
        let (id, cert_shard) = quic::certificate_identity(certificate.expose())?;
        if id != signer.verifying_key().to_bytes() || cert_shard != cfg.shard {
            fail!(EACCES, "L2_CLIENT_IDENTITY");
        }
        let issuer = enclave_crypto::biscuit_auth::PublicKey::from_bytes(
            &hex::decode(&cfg.issuer_public_key_hex).map_err(|_| err!(EINVAL, "L2_ISSUER_KEY"))?,
            enclave_crypto::biscuit_auth::Algorithm::Ed25519,
        )
        .map_err(|_| err!(EINVAL, "L2_ISSUER_KEY"))?;
        let policy = hex::decode(&cfg.policy_blake3)
            .map_err(|_| err!(EINVAL, "L2_POLICY"))?
            .try_into()
            .map_err(|_| err!(EINVAL, "L2_POLICY"))?;
        let shard = match cfg.shard.as_str() {
            "EU" => Shard::EU,
            "US" => Shard::US,
            "APAC" => Shard::APAC,
            _ => return Err(err!(EINVAL, "L2_SHARD")),
        };
        let node = Arc::new(L2SwarmNode::new(
            (*signer).clone(),
            shard,
            SeedGateFSM::new(Profile::L2),
            L2CapabilityPolicy::new(issuer, policy).with_enterprise_authority(
                enclave_core::enterprise_authority::EnterpriseAuthority::open(
                    cfg.enterprise_authority.clone().ok_or_else(||err!(EACCES,"ENTERPRISE_AUTHORITY_REQUIRED"))?,
                    &std::path::Path::new(&cfg.poison_state_dir).join("enterprise-authority-state"),
                )?),
        ));
        for key in &seed_cfg.authorized_peer_keys {
            node.authorize_peer(key);
        }
        let configured_peers=seed_cfg.authorized_peer_keys.iter().map(|peer|enclave_core::enterprise_authority::key32(peer)).collect::<EnclaveResult<Vec<_>>>()?;
        let peer_authority=SeedPeerAuthority::with_peer_stops(&cfg.poison_state_dir,id,&configured_peers,service.process_peer_stops())?;
        let roots: Vec<Vec<u8>> = cfg
            .peer
            .tls_roots_der
            .iter()
            .map(|s| hex::decode(s).map_err(|_| err!(EINVAL, "L2_TLS_ROOT")))
            .collect::<EnclaveResult<_>>()?;
        let cache = Arc::new(std::sync::Mutex::new(SourceCache::new(
            &cfg.poison_state_dir,
        )?));
        let (stop, receiver) = tokio::sync::watch::channel(false);
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        let thread = std::thread::Builder::new()
            .name("cas-l2-seed".into())
            .spawn(move || {
                let result = (|| -> EnclaveResult<()> {
                    let runtime = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .map_err(|_| err!(EIO, "L2_RUNTIME"))?;
                    runtime.block_on(async {
                        let endpoint = quic::server_endpoint(
                            seed_cfg
                                .bind
                                .parse()
                                .map_err(|_| err!(EINVAL, "L2_SEED_BIND"))?,
                            certificate.expose().to_vec(),
                            &seed,
                            &roots,
                        )?;
                        let _ = tx.send(Ok(()));
                        let update_node = node.clone();
                        let updater = tokio::spawn(async move {
                            let mut tick = tokio::time::interval(std::time::Duration::from_secs(1));
                            loop {
                                tick.tick().await;
                                let conditions=observed_conditions().ok();
                                let _=update_node.update_host_conditions(conditions);
                            }
                        });
                        let gate_node = node.clone();
                        let expected = cfg.clone();
                        let get = Arc::new(move |namespace: &str, root: &str, index: u64| {
                            let source = seed_cfg
                                .sources
                                .iter()
                                .find(|s| s.namespace == namespace && s.root == root)?;
                            let conditions = observed_conditions().ok()?;
                            gate_node.update_host_conditions(Some(conditions)).ok()?;
                            service
                                .authorize_seed(namespace, root, source.payload_length, &expected)
                                .ok()?;
                            let bytes = cache.lock().ok()?.slice(source, index).ok()?;
                            service
                                .authorize_seed(namespace, root, source.payload_length, &expected)
                                .ok()?;
                            let mut gate = SeedGateFSM::new(Profile::L2);
                            gate.update(observed_conditions().ok()?);
                            gate.assert_can_seed().ok()?;
                            Some(bytes)
                        });
                        let result =
                            quic::serve(endpoint, node, signer, get, peer_authority, receiver)
                                .await;
                        updater.abort();
                        let _ = updater.await;
                        result
                    })
                })();
                if let Err(error) = result {
                    let _ = tx.send(Err(error));
                }
            })
            .map_err(|_| err!(EIO, "L2_SEED_THREAD"))?;
        match rx.recv().map_err(|_| err!(EIO, "L2_SEED_START"))? {
            Ok(()) => Ok(Some(Self {
                stop,
                thread: Some(thread),
            })),
            Err(error) => {
                let _ = thread.join();
                Err(error)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    #[test]
    fn authenticated_seed_source_refuses_corruption_trailing_symlinks_and_wrong_lengths() {
        let dir = std::env::temp_dir().join(format!("cas-seed-{}", enclave_core::rng::u64()));
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let dir = std::fs::canonicalize(dir).unwrap();
        let payload = vec![42; 65536];
        let encoded = crate::bao::encode_bao_stream(&payload).unwrap();
        let path = dir.join("ciphertext");
        std::fs::write(&path, &encoded).unwrap();
        let mut source = SeedSource {
            namespace: "models".into(),
            root: crate::bao::bao_root(&payload),
            path: path.display().to_string(),
            payload_length: payload.len() as u64,
        };
        let result = authenticated_slice(&source, 0);
        assert_eq!(result.unwrap(), encoded[..SEGMENT]);
        source.payload_length += 1;
        assert!(authenticated_slice(&source, 0).is_err());
        source.payload_length -= 1;
        let mut corrupt = encoded.clone();
        corrupt[100] ^= 1;
        std::fs::write(&path, &corrupt).unwrap();
        assert!(authenticated_slice(&source, 0).is_err());
        let mut trailing = encoded;
        trailing.push(0);
        std::fs::write(&path, &trailing).unwrap();
        assert!(authenticated_slice(&source, 0).is_err());
        let link = dir.join("linked");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        source.path = link.display().to_string();
        assert!(authenticated_slice(&source, 0).is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn verified_cache_unlinks_stages_and_rejects_source_replacement() {
        let dir = std::env::temp_dir().join(format!("cas-cache-{}", enclave_core::rng::u64()));
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let dir = std::fs::canonicalize(dir).unwrap();
        let payload = vec![42; 65536];
        let encoded = crate::bao::encode_bao_stream(&payload).unwrap();
        let path = dir.join("ciphertext");
        std::fs::write(&path, &encoded).unwrap();
        let source = SeedSource {
            namespace: "models".into(),
            root: crate::bao::bao_root(&payload),
            path: path.display().to_string(),
            payload_length: payload.len() as u64,
        };
        let mut cache = SourceCache::new(dir.to_str().unwrap()).unwrap();
        assert_eq!(cache.slice(&source, 0).unwrap(), encoded[..SEGMENT]);
        assert_eq!(
            cache.slice(&source, 1).unwrap(),
            encoded[SEGMENT..SEGMENT * 2]
        );
        assert_eq!(cache.sources.len(), 1);
        assert_eq!(cache.staging.reserved().unwrap(),0);
        assert!(SourceCache::new(dir.to_str().unwrap()).is_err());
        #[cfg(target_os="linux")]
        assert!(cache.sources.values().next().unwrap().file.metadata().unwrap().blocks()>0);
        let cached = cache.sources.values().next().unwrap();
        assert_eq!(
            unsafe { libc::fcntl(cached.file.as_raw_fd(), libc::F_GETFL) } & libc::O_ACCMODE,
            libc::O_RDONLY
        );
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 2); // source + singleton lock
        let mut corrupt = encoded.clone();
        corrupt[100] ^= 1;
        let replacement = dir.join("replace");
        std::fs::write(&replacement, corrupt).unwrap();
        std::fs::rename(replacement, &path).unwrap();
        assert!(cache.slice(&source, 0).is_err());
        assert!(cache.sources.is_empty());
        assert_eq!(cache.used, 0);
        drop(cache);
        std::fs::write(&path, &encoded).unwrap();
        let stale=dir.join(".seed-123abc");std::fs::write(&stale,b"interrupted").unwrap();std::fs::set_permissions(&stale,std::fs::Permissions::from_mode(0o600)).unwrap();
        let mut restarted = SourceCache::new(dir.to_str().unwrap()).unwrap();
        assert!(!stale.exists());
        assert_eq!(restarted.slice(&source, 0).unwrap(), encoded[..SEGMENT]);
        drop(restarted);
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 2); // source + singleton lock
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn seed_configuration_bounds_and_l3_latch_remain_closed() {
        let mut config = SeedConfig {
            bind: "127.0.0.1:4433".into(),
            authorized_peer_keys: vec!["ab".repeat(32)],
            sources: vec![SeedSource {
                namespace: "models".into(),
                root: "ab".repeat(32),
                path: "/opt/cas/source".into(),
                payload_length: 65536,
            }],
        };
        config.validate().unwrap();
        config.bind = "127.0.0.1:4444".into();
        assert!(config.validate().unwrap_err().is("L2_SEED_BIND_PORT"));
        config.bind = "127.0.0.1:4433".into();
        config.sources[0].path = "/opt/cas/../source".into();
        assert!(config.validate().is_err());
        config.sources[0].path = "/opt/cas/source".into();
        config.sources[0].payload_length = MAX_SOURCE + 1;
        assert!(config.validate().is_err());
        let mut gate = SeedGateFSM::new(Profile::L3);
        gate.update(HostConditions::default());
        assert!(gate.assert_can_seed().is_err());
    }
}
