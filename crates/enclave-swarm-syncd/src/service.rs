//! UID 702 daemon service.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use enclave_core::audit::AuditJournal;
use enclave_core::daemon::DaemonId;
use enclave_core::error::EnclaveResult;
use enclave_core::ipc::{DaemonStatus, PeerCredentials};
use enclave_core::profile::Profile;
use enclave_core::sealed::{Loaded, SealedStore};
use enclave_core::seq::RpcSequencer;
use enclave_core::{err, fail};
use enclave_crypto::ohttp::{bhttp_post, KeyConfig};
use enclave_crypto::tuf::{TrustedClock, TufClient, TufTrustedState};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::admission::{admit, lookup, resolve};
use crate::cas::ContentStore;
use crate::cas_uri::CasUri;
use crate::governance::{may_seed, Classification};
use crate::revocation::Enforcement;

/// IPC requests.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CasRequest {
    /// Read fixed local stage diagnostics without advancing service state.
    SyncDiagnostics,
    /// Read configured outbox metadata without changing state or custody.
    OutboxDiagnostics,
    /// Status.
    Status,
    /// Bootstrap trust from a pinned `root.json`.
    TufBootstrap {
        /// Root bytes.
        root: serde_bytes::ByteBuf,
    },
    /// Refresh timestamp → snapshot → targets.
    TufRefresh {
        /// Optional root rotations, in order.
        roots: Vec<serde_bytes::ByteBuf>,
        /// Timestamp.
        timestamp: serde_bytes::ByteBuf,
        /// Snapshot.
        snapshot: serde_bytes::ByteBuf,
        /// Targets.
        targets: serde_bytes::ByteBuf,
    },
    /// Admit downloaded target bytes.
    Admit {
        /// Target name.
        target: String,
        /// Bytes.
        bytes: serde_bytes::ByteBuf,
    },
    /// Begin a bounded, peer-bound upload of an authenticated target.
    AdmitBegin {
        /// Signed target name.
        target: String,
    },
    /// Append one sequential chunk to an admission session.
    AdmitChunk {
        /// Opaque session handle.
        session: String,
        /// Exact next byte offset.
        offset: u64,
        /// At most 256 KiB of actual artifact bytes.
        bytes: serde_bytes::ByteBuf,
    },
    /// Verify signed metadata, digests and format, then publish the manifest.
    AdmitCommit {
        /// Opaque session handle.
        session: String,
    },
    /// Discard an unfinished admission session.
    AdmitAbort {
        /// Opaque session handle.
        session: String,
    },
    /// Export a verified named signed target as one private read-only FD.
    OpenTarget {
        /// Signed target name.
        target: String,
    },
    /// Resolve a `cas://` URI; read-only FDs follow via `SCM_RIGHTS`.
    Resolve {
        /// URI.
        cas_uri: String,
    },
    /// Fetch verified bytes (admin / UID 701 small artifacts).
    Fetch {
        /// URI.
        cas_uri: String,
    },
    /// May this host seed the target?
    SeedDecision {
        /// URI.
        cas_uri: String,
    },
    /// Queue a padded `ComplianceRollupProofV1` frame for OHTTP relay.
    RelayRollup {
        /// Frame.
        frame: serde_bytes::ByteBuf,
    },
    /// Fetch the signed host configuration (GAP-20).
    FetchHostConfig,
    /// Fetch an arbitrary named TUF target payload (GAP-32).
    FetchTarget {
        /// Target name.
        target: String,
    },
    /// Live fixed FIDO allowlist, trusted refresh clock and signed-chain expiry.
    /// Only authenticated custody (UID 703), or explicit development same UID.
    FetchCustodyMetadata,
    /// Fixed OIDC or envelope policy with authenticated TUF lifetime.
    /// Only custody (UID 703), or explicitly configured development same UID.
    FetchCustodyTarget {
        /// Closed target selector; arbitrary names are not admitted.
        target: enclave_core::custody_metadata::CustodyTarget,
    },
    /// Wipe in-flight fetch keys / sessions (supervisor or operator only).
    Wipe,
    /// Hydrate an authenticated artifact (configured TLS registry on L1;
    /// cached-only on L2/L3 until their authenticated adapters are provisioned).
    Hydrate {
        /// Target CAS URI.
        cas_uri: String,
    },
}

/// IPC responses.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CasResponse {
    /// Bounded local call-result counters; no synchronization SLO claim.
    SyncDiagnostics(crate::sync_diagnostics::SyncDiagnosticsSnapshot),
    /// Bounded configured outbox metadata; no delivery/receipt assertion.
    OutboxDiagnostics(crate::outbox::OutboxDiagnosticsSnapshot),
    /// Status.
    Status(DaemonStatus),
    /// Wiped.
    Wiped,
    /// Versions `(timestamp, snapshot, targets)`.
    Tuf {
        /// Versions.
        versions: (u64, u64, u64),
    },
    /// Admitted root.
    Admitted {
        /// Root hex.
        root: String,
    },
    /// Signed parameters and opaque handle for a new admission session.
    Admission {
        /// Opaque peer-bound session handle.
        session: String,
        /// Signed complete artifact length.
        length: u64,
        /// Signed BLAKE3 digest.
        blake3: String,
        /// Signed SHA-256 digest.
        sha256: String,
        /// Maximum bytes accepted in one chunk.
        max_chunk_bytes: usize,
    },
    /// Accepted cumulative upload length.
    AdmissionProgress {
        /// Total bytes received so far.
        received: u64,
    },
    /// Verified snapshot metadata; exactly one read-only FD follows.
    TargetFile {
        /// Signed complete artifact length.
        length: u64,
        /// Signed BLAKE3 digest.
        blake3: String,
        /// Signed SHA-256 digest.
        sha256: String,
        /// Descriptor count, always one.
        fds: u32,
    },
    /// Resolution metadata; FDs follow.
    Resolved {
        /// Effective profile.
        effective_profile: Profile,
        /// SHA-256.
        sha256: String,
        /// Number of FDs that follow.
        fds: usize,
    },
    /// Exact verified FIDO metadata and its independent freshness authority.
    CustodyMetadata(enclave_core::custody_metadata::CustodyMetadataReceipt),
    /// Exact fixed policy target and its captured independent freshness limits.
    CustodyTarget(enclave_core::custody_metadata::CustodyTargetReceipt),
    /// Bytes.
    Bytes(serde_bytes::ByteBuf),
    /// Seeding allowed.
    SeedAllowed,
    /// Relay queued.
    Queued,
}

/// Configuration.
#[derive(Debug, Clone)]
pub struct CasConfig {
    /// Trusted startup selection of same-UID development authorization.
    pub dev_same_uid: bool,
    /// Workstation Cedar `min_profile`.
    pub profile: Profile,
    /// Store root.
    pub store_dir: PathBuf,
    /// Audit path.
    pub audit_path: Option<PathBuf>,
    /// Pinned TUF root shipped with the install (bootstraps at start).
    pub tuf_root: Option<Vec<u8>>,
    /// Ledger OHTTP gateway key configuration (TUF-distributed). Without it
    /// rollups are refused rather than sent in the clear.
    pub ohttp_gateway: Option<KeyConfig>,
    /// Persistent state (`<state>/cas`): sealed TUF trusted metadata and the
    /// trusted-clock high-water mark (GAP-30). This daemon-private directory
    /// must have trusted ancestors and a leaf owned by this UID with no
    /// group/other access; symlink and parent-traversal components are refused.
    /// Relative paths are resolved against the process working directory.
    /// TUF is the only named sealed store sharing this directory's seed;
    /// independent authorities must use child directories and their own seeds.
    /// `None` keeps this state in memory (tests only).
    pub state_dir: Option<PathBuf>,
    /// Who terminates holders of revoked artifacts (GAP-21).
    pub revocation: Enforcement,
}

/// FS-702 §7.3.2 hard offline TTL: without a successful TUF refresh for this
/// long, everything except `public_l1` artifacts locks (Safe-Fail Lockdown).
pub const OFFLINE_TTL_S: i64 = 168 * 3600;

/// The persisted clock high-water mark is refreshed at most this often.
const CLOCK_PERSIST_S: i64 = 300;

/// Sealed UID 702 trust state (GAP-30).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct TrustState {
    tuf: Option<TufTrustedState>,
    clock_high_water: i64,
    /// Trusted time of the last successful `TufRefresh`.
    refreshed_at: Option<i64>,
}

/// Shared with the actual ledger gateway and compliance-frame codec.
pub use enclave_zk_auditor::rollup::{LEDGER_AUTHORITY, LEDGER_PATH};

struct State {
    required_profile: Option<Profile>,
    ohttp_gateway: Option<KeyConfig>,
    profile: Profile,
    store: ContentStore,
    sessions: crate::streaming::Sessions,
    // Cancels whole download plans, including gaps with no active session.
    cancellation: Arc<DownloadCancellation>,
    tuf: Option<TufClient>,
    clock: TrustedClock,
    wall: fn() -> i64,
    refreshed_at: Option<i64>,
    bootstrap_at: i64,
    trust_store: Option<SealedStore>,
    persisted_high_water: i64,
    revocation: Enforcement,
    seq: RpcSequencer,
    journal: Option<AuditJournal>,
    outbox: PathBuf,
}

#[derive(Debug, Clone)]
struct DownloadArtifact {
    target: String,
    metadata: enclave_crypto::tuf::TargetFile,
}
#[derive(Debug)]
enum DownloadTransport {
    Registry(crate::transport::registry::RegistryConfig),
    Oblivious(crate::transport::oblivious::ObliviousConfig),
    Quic(crate::transport::quic::L2QuicConfig),
}
impl DownloadTransport {fn profile(&self)->Profile {match self {Self::Registry(_)=>Profile::L1,Self::Oblivious(_)=>Profile::L3,Self::Quic(_)=>Profile::L2}}}
#[derive(Debug)]
struct DownloadPlan {
    uri: String,
    wipe_generation: u64,
    artifacts: Vec<DownloadArtifact>,
    main_metadata: enclave_crypto::tuf::TargetFile,
    config_metadata: enclave_crypto::tuf::TargetFile,
    config: DownloadTransport,
    missing: Vec<DownloadArtifact>,
    leases:Vec<enclave_crypto::namespace::CasKeyLease>,
}

struct DownloadReservation<'a> {active:&'a Mutex<std::collections::BTreeSet<String>>,roots:Vec<String>}
impl Drop for DownloadReservation<'_> {fn drop(&mut self){if let Ok(mut active)=self.active.lock(){for root in &self.roots{active.remove(root);}}}}

#[derive(Default)]
struct DownloadCancellation {release:Arc<Mutex<()>>,generation:std::sync::atomic::AtomicU64,pending:std::sync::atomic::AtomicUsize,blocked:std::sync::atomic::AtomicBool}
struct PendingWipe<'a>(&'a DownloadCancellation);
impl Drop for PendingWipe<'_>{fn drop(&mut self){self.0.pending.fetch_sub(1,std::sync::atomic::Ordering::SeqCst);}}
impl DownloadCancellation {
    fn observe(&self)->EnclaveResult<u64>{
        let generation=self.generation.load(std::sync::atomic::Ordering::SeqCst);
        if self.blocked.load(std::sync::atomic::Ordering::SeqCst)||self.pending.load(std::sync::atomic::Ordering::SeqCst)!=0||generation==u64::MAX{fail!(EACCES,"DOWNLOAD_WIPED");}Ok(generation)
    }
    fn validate(&self,generation:u64)->EnclaveResult<()>{if self.observe()?!=generation{fail!(EACCES,"DOWNLOAD_WIPED");}Ok(())}
    fn advance(&self)->EnclaveResult<()>{self.generation.try_update(std::sync::atomic::Ordering::SeqCst,std::sync::atomic::Ordering::SeqCst,|value|value.checked_add(1)).map(|_|()).map_err(|_|err!(E2BIG,"DOWNLOAD_GENERATION_EXHAUSTED"))}
    fn begin(&self)->EnclaveResult<PendingWipe<'_>>{
        self.pending.try_update(std::sync::atomic::Ordering::SeqCst,std::sync::atomic::Ordering::SeqCst,|value|value.checked_add(1)).map_err(|_|err!(E2BIG,"DOWNLOAD_WIPE_LIMIT"))?;
        self.blocked.store(true,std::sync::atomic::Ordering::SeqCst);
        let guard=PendingWipe(self);
        // pending/blocked close admission before waiting for the bounded IPC
        // handoff. The generation advance is the observable Wipe fence.
        let _release=self.release.lock().map_err(|_|err!(EIO,"RELEASE_LOCK"))?;
        self.advance()?;Ok(guard)
    }
    // Called only while State serializes a fully successful cleanup/receipt.
    fn finish(&self){self.blocked.store(false,std::sync::atomic::Ordering::SeqCst);}
}

/// The service.
pub struct CasService {
    dev_same_uid: bool,
    process_peer_stops: Arc<crate::transport::quic_poison::ProcessPeerStops>,
    diagnostics: crate::sync_diagnostics::SyncDiagnostics,
    outbox_diagnostics: crate::outbox::OutboxDiagnostics,
    // Shared with State so authority checks observe cancellation immediately,
    // even while a slow owned publication holds the State mutex.
    cancellation: Arc<DownloadCancellation>,
    namespace_custody:Mutex<Option<Arc<dyn crate::transport::custody::NamespaceCustody>>>,
    snapshot_publisher_override:Mutex<Option<Arc<dyn crate::snapshot_publication::SnapshotPublisher>>>,
    active_downloads:Mutex<std::collections::BTreeSet<String>>,
    published:Mutex<std::collections::BTreeMap<String,(Arc<dyn crate::snapshot_publication::SnapshotPublisher>,enclave_crypto::tuf::TargetFile,Option<Arc<crate::transport::quota::StagingReservation>>)>>,
    state: Mutex<State>,
}

impl std::fmt::Debug for CasService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CasService")
    }
}

/// Complete encoded compliance frame size, shared with every consumer.
pub use enclave_zk_auditor::rollup::L3_FRAME_BYTES as L3_FRAME;

impl CasService {
    pub(crate) fn process_peer_stops(&self)->Arc<crate::transport::quic_poison::ProcessPeerStops> { self.process_peer_stops.clone() }
    /// Existing cancellation/final-FD fence, also used by accepted independent
    /// namespace-policy updates in the production custody provider.
    pub fn namespace_release_serial(&self)->Arc<Mutex<()>> {self.cancellation.release.clone()}

    /// Configure the custody transport before serving requests. Production entry
    /// supplies the standard authenticated UID703 client; tests may supply an
    /// explicit software fixture, which establishes no hardware acceptance.
    pub fn set_namespace_custody(&self,provider:Arc<dyn crate::transport::custody::NamespaceCustody>)->EnclaveResult<()> {
        *self.namespace_custody.lock().map_err(|_|err!(EIO,"NAMESPACE_CUSTODY_POISONED"))?=Some(provider);Ok(())
    }


    /// Explicit software fixture injection; production constructs its publisher
    /// only from authenticated distribution configuration.
    pub fn set_snapshot_publisher(&self,publisher:Arc<dyn crate::snapshot_publication::SnapshotPublisher>)->EnclaveResult<()> {
        *self.snapshot_publisher_override.lock().map_err(|_|err!(EIO,"SEALED_LOCK"))?=Some(publisher);Ok(())
    }
    fn snapshot_publisher(&self,config:crate::snapshot_publication::SealedConfig)->EnclaveResult<Arc<dyn crate::snapshot_publication::SnapshotPublisher>> {
        if let Some(p)=self.snapshot_publisher_override.lock().map_err(|_|err!(EIO,"SEALED_LOCK"))?.clone(){return Ok(p);}
        config.validate()?;
        Ok(Arc::new(crate::snapshot_broker::BrokerClient))
    }
    fn revalidate_leases(&self,leases:&[enclave_crypto::namespace::CasKeyLease])->EnclaveResult<()> {
        if leases.is_empty(){return Ok(());}
        let provider=self.namespace_custody.lock().map_err(|_|err!(EIO,"NAMESPACE_CUSTODY_POISONED"))?.clone().ok_or_else(||err!(EACCES,"NAMESPACE_CUSTODY_UNAVAILABLE"))?;
        for lease in leases {provider.revalidate(lease)?;}Ok(())
    }
    fn guarded_model(st:&State,tf:&enclave_crypto::tuf::TargetFile)->bool {
        st.profile!=Profile::L1 && (tf.custom.as_ref().is_some_and(|v|v.get("encrypted_transport").is_some())
            || (st.required_profile.is_some() && tf.custom.as_ref().is_some_and(|v|v.get("classification").is_some())))
    }
    fn model_lease(&self,st:&State,tf:&enclave_crypto::tuf::TargetFile)->EnclaveResult<Option<enclave_crypto::namespace::CasKeyLease>> {
        if !Self::guarded_model(st,tf){return Ok(None);}
        let namespace=tf.custom.as_ref().and_then(|v|v.get("encrypted_transport")).and_then(|v|v.get("key")).and_then(|v|v.get("namespace")).and_then(|v|v.as_str()).ok_or_else(||err!(EACCES,"ENCRYPTED_TRANSPORT_REQUIRED"))?;
        let descriptor=crate::transport::oblivious::EncryptedTarget::from_target(tf,namespace)?;
        let provider=self.namespace_custody.lock().map_err(|_|err!(EIO,"NAMESPACE_CUSTODY_POISONED"))?.clone().ok_or_else(||err!(EACCES,"NAMESPACE_CUSTODY_UNAVAILABLE"))?;
        Ok(Some(provider.unwrap(&descriptor.key)?.lease))
    }
    fn cached_publisher(&self,st:&State,now:i64)->EnclaveResult<Arc<dyn crate::snapshot_publication::SnapshotPublisher>> {
        let tuf=st.tuf.as_ref().ok_or_else(||err!(EPERM,"TUF_NOT_BOOTSTRAPPED"))?;
        if !["root","targets"].iter().all(|role|tuf.root().roles.get(*role).is_some_and(|keys|keys.threshold>=2&&keys.keyids.len()>=keys.threshold as usize)){fail!(EACCES,"L3_PUBLISHER_QUORUM_REQUIRED");}
        let tf=st.tuf.as_ref().ok_or_else(||err!(EPERM,"TUF_NOT_BOOTSTRAPPED"))?.target(crate::transport::registry::DISTRIBUTION_CONFIG_TARGET,now)?;
        if tf.length>crate::transport::registry::MAX_CONFIG_BYTES {fail!(E2BIG,"DISTRIBUTION_CONFIG_SIZE");}
        let mut file=st.sessions.export(&st.store,crate::transport::registry::DISTRIBUTION_CONFIG_TARGET,tf)?;
        use std::io::Read;
        let mut bytes=Vec::new();(&mut file).take(crate::transport::registry::MAX_CONFIG_BYTES+1).read_to_end(&mut bytes).map_err(|e|err!(EIO,"DISTRIBUTION_CONFIG_READ","{e}"))?;
        let config=crate::transport::registry::DistributionConfig::parse(&bytes)?.l3.ok_or_else(||err!(EIO,"HYDRATION_TRANSPORT_UNAVAILABLE"))?;
        self.snapshot_publisher(config.sealed)
    }
    fn guard_closure(&self,st:&State,main:&enclave_crypto::tuf::TargetFile,policy:&crate::governance::TargetPolicy,now:i64)->EnclaveResult<(Vec<enclave_crypto::namespace::CasKeyLease>,Option<Vec<std::fs::File>>)> {
        let mut metadata=vec![main];
        for companion in policy.companion_safety_layers.iter().filter(|c|c.eager_hydrate_required) {
            let tf=st.tuf.as_ref().and_then(|t|t.targets()).and_then(|t|t.values().find(|tf|tf.hashes.get("blake3")==Some(&companion.blake3))).ok_or_else(||err!(EACCES,"COMPANION_NOT_SIGNED"))?;
            metadata.push(tf);
        }
        let mut leases=Vec::new();for tf in &metadata {if let Some(lease)=self.model_lease(st,tf)?{leases.push(lease);}}
        if st.profile==Profile::L2 && metadata.iter().any(|tf|Self::guarded_model(st,tf)) {
            let tf=st.tuf.as_ref().ok_or_else(||err!(EPERM,"TUF_NOT_BOOTSTRAPPED"))?.target(crate::transport::registry::DISTRIBUTION_CONFIG_TARGET,now)?;
            if tf.length>crate::transport::registry::MAX_CONFIG_BYTES {fail!(E2BIG,"DISTRIBUTION_CONFIG_SIZE");}
            let mut file=st.sessions.export(&st.store,crate::transport::registry::DISTRIBUTION_CONFIG_TARGET,tf)?;use std::io::Read;let mut bytes=Vec::new();(&mut file).take(crate::transport::registry::MAX_CONFIG_BYTES+1).read_to_end(&mut bytes).map_err(|_|err!(EIO,"DISTRIBUTION_CONFIG_READ"))?;
            let config=crate::transport::registry::DistributionConfig::parse(&bytes)?.l2.ok_or_else(||err!(EIO,"HYDRATION_TRANSPORT_UNAVAILABLE"))?;
            for tf in &metadata {let policy:crate::governance::TargetPolicy=serde_json::from_value(tf.custom.clone().unwrap_or_default()).map_err(|_|err!(EINVAL,"TARGET_POLICY"))?;let shard=match policy.jurisdiction_shard{Some(crate::governance::Shard::EU)=>"EU",Some(crate::governance::Shard::US)=>"US",Some(crate::governance::Shard::APAC)=>"APAC",None=>return Err(err!(EACCES,"L2_SHARD_REQUIRED"))};if shard!=config.shard {fail!(EACCES,"JURISDICTION_SHARD_MISMATCH");}}
        }
        let files=if st.profile==Profile::L3 && metadata.iter().any(|tf|Self::guarded_model(st,tf)) {
            let publisher=self.cached_publisher(st,now)?;let mut files=Vec::new();for tf in metadata {files.push(publisher.reopen(tf)?);self.published.lock().map_err(|_|err!(EIO,"SEALED_LOCK"))?.entry(tf.hashes["blake3"].clone()).or_insert((publisher.clone(),tf.clone(),None));}Some(files)
        } else {None};
        self.revalidate_leases(&leases)?;Ok((leases,files))
    }
    fn revoke_snapshots(&self,st:&mut State)->EnclaveResult<()> {
        let targets:Vec<_>=st.tuf.as_ref().and_then(TufClient::targets).into_iter().flat_map(|targets|targets.values()).filter(|tf|tf.custom.as_ref().and_then(|v|v.get("revoked")).and_then(|v|v.as_bool())==Some(true)).cloned().collect();
        for target in targets {
            let Some(root)=target.hashes.get("blake3") else {continue;};
            let existing=self.published.lock().map_err(|_|err!(EIO,"SEALED_LOCK"))?.get(root).cloned();
            if let Some((publisher,original,_quota))=existing {publisher.revoke(&original)?;self.published.lock().map_err(|_|err!(EIO,"SEALED_LOCK"))?.remove(root);}
            else if st.profile==Profile::L3 && target.custom.as_ref().is_some_and(|v|v.get("encrypted_transport").is_some()) {
                let now=st.clock.high_water();let publisher=self.cached_publisher(st,now)?;
                let mut original=target.clone();original.custom=None;publisher.revoke(&original)?;
            }
        }Ok(())
    }
    fn revoke_all_snapshots(&self,st:&State)->EnclaveResult<()> {
        let mut roots=self.published.lock().map_err(|_|err!(EIO,"SEALED_LOCK"))?;
        let mut revoked=std::collections::BTreeSet::new();
        for (root,(publisher,target,_quota)) in roots.iter(){publisher.revoke(target)?;revoked.insert(root.clone());}
        if st.profile==Profile::L3 {
            let targets:Vec<_>=st.tuf.as_ref().and_then(TufClient::targets).into_iter().flat_map(|t|t.values()).filter(|tf|tf.custom.as_ref().is_some_and(|v|v.get("encrypted_transport").is_some())&&!revoked.contains(&tf.hashes["blake3"])).collect();
            if !targets.is_empty(){let publisher=self.cached_publisher(st,st.clock.high_water())?;for tf in targets {let mut tf=tf.clone();tf.custom=None;publisher.revoke(&tf)?;}}
        }
        roots.clear();Ok(())
    }
    /// Current signed seed configuration. L3 never starts an IP listener.
    pub fn l2_seed_config(&self)->EnclaveResult<Option<crate::transport::quic::L2QuicConfig>> {
        let mut guard=self.state.lock().map_err(|_|err!(EIO,"STATE_POISONED"))?;let st=&mut *guard;
        if st.profile!=Profile::L2 {return Ok(None);}
        // No listener authority exists during configuration-only recovery.
        // Absence is inert; a present stale/invalid target must still refuse.
        if !st.tuf.as_ref().and_then(TufClient::targets).is_some_and(|targets|targets.contains_key(crate::transport::registry::DISTRIBUTION_CONFIG_TARGET)) {return Ok(None);}
        let now=Self::download_now(st)?;Self::host_profile_gate(st,&CasRequest::SeedDecision{cas_uri:String::new()},now)?;Self::offline_gate(st,now,None)?;
        let tf=st.tuf.as_ref().ok_or_else(||err!(EPERM,"TUF_NOT_BOOTSTRAPPED"))?.target(crate::transport::registry::DISTRIBUTION_CONFIG_TARGET,now)?;
        if tf.length>crate::transport::registry::MAX_CONFIG_BYTES {fail!(E2BIG,"DISTRIBUTION_CONFIG_SIZE");}
        let mut file=st.sessions.export(&st.store,crate::transport::registry::DISTRIBUTION_CONFIG_TARGET,tf)?;use std::io::Read;let mut bytes=Vec::new();(&mut file).take(crate::transport::registry::MAX_CONFIG_BYTES+1).read_to_end(&mut bytes).map_err(|_|err!(EIO,"DISTRIBUTION_CONFIG_READ"))?;
        Ok(crate::transport::registry::DistributionConfig::parse(&bytes)?.l2)
    }
    /// Recheck signed license, shard, freshness and exact listener authority for
    /// each capability-authorized ciphertext request before opening source data.
    pub fn authorize_seed(&self,namespace:&str,root:&str,payload_length:u64,expected:&crate::transport::quic::L2QuicConfig)->EnclaveResult<()> {
        let cancellation=self.cancellation.observe()?;
        if self.l2_seed_config()?.as_ref()!=Some(expected) {fail!(EACCES,"SEED_AUTHORITY_CHANGED");}
        let mut guard=self.state.lock().map_err(|_|err!(EIO,"STATE_POISONED"))?;let st=&mut *guard;let now=Self::download_now(st)?;
        let targets=st.tuf.as_ref().and_then(TufClient::targets).ok_or_else(||err!(EPERM,"TUF_NOT_BOOTSTRAPPED"))?;
        for tf in targets.values() {
            let Some(signed_namespace)=tf.custom.as_ref().and_then(|v|v.get("encrypted_transport")).and_then(|v|v.get("key")).and_then(|v|v.get("namespace")).and_then(|v|v.as_str()) else {continue;};
            if signed_namespace!=namespace {continue;}
            let Ok(descriptor)=crate::transport::oblivious::EncryptedTarget::from_target(tf,namespace) else {continue;};
            if !((root==descriptor.ciphertext_bao_root && payload_length==descriptor.ciphertext_length)||(root==descriptor.key_index_bao_root && payload_length==descriptor.key_index_length)) {continue;}
            Self::artifact_authority(st,tf,now)?;let policy:crate::governance::TargetPolicy=serde_json::from_value(tf.custom.clone().unwrap_or_default()).map_err(|_|err!(EINVAL,"TARGET_POLICY"))?;may_seed(&policy,Profile::L2)?;
            let shard=match policy.jurisdiction_shard {Some(crate::governance::Shard::EU)=>"EU",Some(crate::governance::Shard::US)=>"US",Some(crate::governance::Shard::APAC)=>"APAC",None=>return Err(err!(EACCES,"L2_SHARD_REQUIRED"))};if shard!=expected.shard {fail!(EACCES,"JURISDICTION_SHARD_MISMATCH");}self.cancellation.validate(cancellation)?;return Ok(());
        }fail!(EACCES,"SEED_TARGET_NOT_SIGNED")
    }
    fn download_now(st: &mut State) -> EnclaveResult<i64> {
        let wall_now = (st.wall)();
        let now = st.clock.now(wall_now);
        if st.trust_store.is_some() && now >= st.persisted_high_water.saturating_add(CLOCK_PERSIST_S) {
            Self::persist(st)?;
        }
        st.sessions.sweep(now);
        Ok(now)
    }

    fn artifact_authority(st: &State, metadata: &enclave_crypto::tuf::TargetFile, now: i64) -> EnclaveResult<()> {
        crate::streaming::validate_target(metadata)?;
        if let Some(custom) = &metadata.custom {
            if custom.get("classification").is_some() || custom.get("min_profile").is_some() {
                let policy: crate::governance::TargetPolicy = serde_json::from_value(custom.clone())
                    .map_err(|_| err!(EINVAL, "TARGET_POLICY"))?;
                Self::offline_gate(st, now, Some(policy.classification))?;
                if policy.min_profile.max(policy.classification.floor()) > st.profile {
                    fail!(EPERM, "PROFILE_FLOOR_EXCEEDED");
                }
            }
        }
        Ok(())
    }

    fn canonical_bytes(st: &State, main: Option<&str>, policy: &crate::governance::TargetPolicy) -> EnclaveResult<u64> {
        let mut roots = std::collections::BTreeSet::new();
        if let Some(root) = main { roots.insert(root); }
        roots.extend(policy.companion_safety_layers.iter().filter(|c| c.eager_hydrate_required).map(|c| c.blake3.as_str()));
        let mut bytes = 0u64;
        for root in roots {
            if st.store.object_inode(root).is_some() { continue; }
            let manifest = st.store.manifest(root).map_err(|error| {
                if Some(root) == main { error } else { err!(EACCES, "COMPANION_NOT_HYDRATED") }
            })?;
            bytes = bytes.checked_add(manifest.len).ok_or_else(|| err!(E2BIG, "ADMISSION_DISK_RESERVE"))?;
        }
        Ok(bytes)
    }

    fn reserve_resolution(st: &State, main: Option<&str>, policy: &crate::governance::TargetPolicy) -> EnclaveResult<()> {
        st.sessions.reserve_materialization(Self::canonical_bytes(st, main, policy)?)
    }

    fn download_authority(st: &State, uri: &CasUri, plan: &DownloadPlan,
        now: i64) -> EnclaveResult<()> {
        st.cancellation.validate(plan.wipe_generation)?;
        Self::host_profile_gate(st, &CasRequest::Hydrate { cas_uri: plan.uri.clone() }, now)?;
        if st.profile != plan.config.profile() { fail!(EPERM, "DOWNLOAD_PROFILE_CHANGED"); }
        let tuf = st.tuf.as_ref().ok_or_else(|| err!(EPERM, "TUF_NOT_BOOTSTRAPPED"))?;
        let (main, policy) = lookup(tuf, uri, now)?;
        Self::offline_gate(st, now, Some(policy.classification))?;
        let floor = policy.min_profile.max(policy.classification.floor()).max(uri.min_profile.unwrap_or(Profile::L1));
        if floor > st.profile { fail!(EPERM, "PROFILE_FLOOR_EXCEEDED"); }
        if main != &plan.main_metadata
            || tuf.target(crate::transport::registry::DISTRIBUTION_CONFIG_TARGET, now)? != &plan.config_metadata
        { fail!(EACCES, "DOWNLOAD_AUTHORITY_CHANGED"); }
        // Freeze the entire eager closure, including already cached/published
        // companions. A later artifact cannot acknowledge an earlier policy.
        for artifact in &plan.artifacts {
            let current = tuf.target(&artifact.target, now)?;
            Self::artifact_authority(st, current, now)?;
            if current != &artifact.metadata { fail!(EACCES, "DOWNLOAD_AUTHORITY_CHANGED"); }
        }
        Ok(())
    }

    fn hydrate_request(&self, peer: &PeerCredentials, cas_uri: &str) -> EnclaveResult<CasResponse> {
        // Keep the existing cached-target/profile/companion/corruption contract.
        match self.handle_local(peer, CasRequest::Hydrate { cas_uri: cas_uri.into() }) {
            Ok(value) => return Ok(value),
            Err(e) if e.is("HYDRATION_TRANSPORT_UNAVAILABLE") || e.is("COMPANION_NOT_HYDRATED") => (),
            Err(e) => return Err(e),
        }
        let plan = self.prepare_download(cas_uri)?;
        self.execute_download(peer, plan)
    }

    fn prepare_download(&self, cas_uri: &str) -> EnclaveResult<DownloadPlan> {
        let uri = CasUri::parse(cas_uri)?;
        let plan = {
            let mut guard = self.state.lock().map_err(|_| err!(EIO, "STATE_POISONED"))?;
            let st = &mut *guard;
            let now = Self::download_now(st)?;
            Self::host_profile_gate(st, &CasRequest::Hydrate { cas_uri: cas_uri.into() }, now)?;
            let tuf = st.tuf.as_ref().ok_or_else(|| err!(EPERM, "TUF_NOT_BOOTSTRAPPED"))?;
            let (main, policy) = lookup(tuf, &uri, now)?;
            Self::offline_gate(st, now, Some(policy.classification))?;
            let floor = policy.min_profile.max(policy.classification.floor()).max(uri.min_profile.unwrap_or(Profile::L1));
            if floor > st.profile { fail!(EPERM, "PROFILE_FLOOR_EXCEEDED"); }
            // L2 must use an authenticated QUIC peer adapter; L3 must use OHTTP.
            // Neither may silently fall back to a direct L1 registry request.

            if !tuf.targets().is_some_and(|t| t.contains_key(crate::transport::registry::DISTRIBUTION_CONFIG_TARGET)) {
                fail!(EIO, "HYDRATION_TRANSPORT_UNAVAILABLE");
            }
            let config_metadata = tuf.target(crate::transport::registry::DISTRIBUTION_CONFIG_TARGET, now)?.clone();
            if config_metadata.length > crate::transport::registry::MAX_CONFIG_BYTES { fail!(E2BIG, "DISTRIBUTION_CONFIG_SIZE"); }
            let main_metadata = main.clone();
            let mut missing = Vec::new();
            let mut seen = std::collections::BTreeSet::new();
            if policy.companion_safety_layers.iter().filter(|c| c.eager_hydrate_required).count() > 15 {
                fail!(E2BIG, "DOWNLOAD_COMPANION_LIMIT");
            }
            // Direct eager companions match the existing Resolve contract;
            // download them before the main object becomes available.
            let mut artifacts = Vec::new();
            for companion in policy.companion_safety_layers.iter().filter(|c| c.eager_hydrate_required) {
                let (name, tf) = tuf.targets().and_then(|t| t.iter().find(|(_, tf)| tf.hashes.get("blake3") == Some(&companion.blake3)))
                    .ok_or_else(|| err!(EACCES, "COMPANION_NOT_SIGNED"))?;
                Self::artifact_authority(st, tf, now)?;
                artifacts.push(DownloadArtifact { target: name.clone(), metadata: tf.clone() });
            }
            artifacts.push(DownloadArtifact { target: uri.target.clone(), metadata: main_metadata.clone() });
            for artifact in &artifacts {
                crate::streaming::validate_target(&artifact.metadata)?;
                let hash = &artifact.metadata.hashes["blake3"];
                if !seen.insert(hash.clone()) { continue; }
                if st.store.contains(hash) {
                    let manifest = st.store.manifest(hash)?;
                    if manifest.len != artifact.metadata.length || manifest.sha256 != artifact.metadata.hashes["sha256"] {
                        fail!(EACCES, "HYDRATION_CACHE_MISMATCH");
                    }
                    // A poisoned cached canonical object is an error, never a
                    // reason to acknowledge or bypass normal revocation state.
                    if st.store.object_inode(hash).is_none() { st.sessions.reserve_materialization(manifest.len)?; }
                    drop(st.store.open_readonly(hash)?);
                } else { missing.push(artifact.clone()); }
            }
            let mut config_file = st.sessions.export(&st.store, crate::transport::registry::DISTRIBUTION_CONFIG_TARGET, &config_metadata)?;
            use std::io::Read;
            let mut config_bytes = Vec::new();
            (&mut config_file).take(crate::transport::registry::MAX_CONFIG_BYTES + 1).read_to_end(&mut config_bytes)
                .map_err(|e| err!(EIO, "DISTRIBUTION_CONFIG_READ", "{e}"))?;
            let configs = crate::transport::registry::DistributionConfig::parse(&config_bytes)?;
            let config=match st.profile {
                Profile::L1=>DownloadTransport::Registry(configs.l1.ok_or_else(||err!(EIO,"HYDRATION_TRANSPORT_UNAVAILABLE"))?),
                Profile::L3=> {
                    // Both publisher root and targets must enforce a real quorum.
                    // This does not certify the signers' physical hardware custody.
                    if !["root","targets"].iter().all(|r|tuf.root().roles.get(*r).is_some_and(|role|role.threshold>=2 && role.keyids.len()>=role.threshold as usize)) {fail!(EACCES,"L3_PUBLISHER_QUORUM_REQUIRED");}
                    for artifact in &artifacts {crate::transport::oblivious::EncryptedTarget::from_target(&artifact.metadata,&uri.ns)?;}
                    DownloadTransport::Oblivious(configs.l3.ok_or_else(||err!(EIO,"HYDRATION_TRANSPORT_UNAVAILABLE"))?)
                },
                Profile::L2=>{
                    let config=configs.l2.ok_or_else(||err!(EIO,"HYDRATION_TRANSPORT_UNAVAILABLE"))?;
                    for artifact in &artifacts {
                        let policy:crate::governance::TargetPolicy=serde_json::from_value(artifact.metadata.custom.clone().ok_or_else(||err!(EACCES,"TARGET_POLICY"))?).map_err(|_|err!(EINVAL,"TARGET_POLICY"))?;
                        crate::governance::may_seed(&policy,Profile::L2)?;
                        let shard=match policy.jurisdiction_shard {Some(crate::governance::Shard::EU)=>"EU",Some(crate::governance::Shard::US)=>"US",Some(crate::governance::Shard::APAC)=>"APAC",None=>return Err(err!(EACCES,"L2_SHARD_REQUIRED"))};
                        if shard!=config.shard {fail!(EACCES,"JURISDICTION_SHARD_MISMATCH");}
                        crate::transport::oblivious::EncryptedTarget::from_target(&artifact.metadata,&uri.ns)?;
                    }
                    DownloadTransport::Quic(config)
                },
            };
            DownloadPlan { uri: cas_uri.into(), wipe_generation: st.cancellation.observe()?, artifacts, main_metadata, config_metadata, config, missing, leases:Vec::new() }
        };
        Ok(plan)
    }

    fn execute_download(&self, peer: &PeerCredentials, mut plan: DownloadPlan) -> EnclaveResult<CasResponse> {
        let uri=CasUri::parse(&plan.uri)?;
        let roots:Vec<_>=plan.artifacts.iter().map(|a|a.metadata.hashes["blake3"].clone()).collect();
        {let mut active=self.active_downloads.lock().map_err(|_|err!(EIO,"DOWNLOAD_LOCK"))?;
            if roots.iter().any(|root|active.contains(root)){fail!(EAGAIN,"DOWNLOAD_ALREADY_ACTIVE");}
            active.extend(roots.iter().cloned());}
        let _reservation=DownloadReservation{active:&self.active_downloads,roots};
        let provider=self.namespace_custody.lock().map_err(|_|err!(EIO,"NAMESPACE_CUSTODY_POISONED"))?.clone();
        let publisher=match &plan.config{DownloadTransport::Oblivious(config)=>Some(self.snapshot_publisher(config.sealed.clone())?),_=>None};
        let mut sessions=Vec::new();let mut prepared=Vec::new();let mut published_roots=Vec::new();
        let result=(|| {
            // Network I/O only writes private sessions. No member of the eager
            // closure is visible until every artifact has authenticated.
            for artifact in plan.missing.clone() {
                // Reconcile any earlier broker work before allocating a new
                // same-root stage, including CAS restart/lost-reply cases.
                if let Some(publisher)=&publisher {publisher.prepare_staging(&artifact.metadata)?;}
                let session={let mut st=self.state.lock().map_err(|_|err!(EIO,"STATE_POISONED"))?;let now=Self::download_now(&mut st)?;Self::download_authority(&st,&uri,&plan,now)?;st.sessions.begin(peer,artifact.target.clone(),artifact.metadata.clone(),now)?};
                sessions.push(session.clone());
                let encrypted=if matches!(&plan.config,DownloadTransport::Registry(_)){None}else{Some(crate::transport::oblivious::EncryptedTarget::from_target(&artifact.metadata,&uri.ns)?)};
                let release=match (&provider,&encrypted){(Some(provider),Some(encrypted))=>Some(provider.unwrap(&encrypted.key)?),(None,Some(_))=>return Err(err!(EACCES,"NAMESPACE_CUSTODY_UNAVAILABLE")),_=>None};
                let mut offset=0;
                let mut accept=|bytes:&[u8]| {
                    if let (Some(provider),Some(release))=(&provider,&release){provider.revalidate(&release.lease)?;}
                    let mut st=self.state.lock().map_err(|_|err!(EIO,"STATE_POISONED"))?;let now=Self::download_now(&mut st)?;Self::download_authority(&st,&uri,&plan,now)?;offset=st.sessions.chunk(peer,&session,offset,bytes,now)?;Ok(())
                };
                match &plan.config {
                    DownloadTransport::Registry(config)=>{
                        let stage=self.diagnostics.start(crate::sync_diagnostics::Stage::RegistryFetch);
                        let fetched=crate::transport::registry::fetch_blob(config,&artifact.metadata,&mut accept);
                        stage.finish(fetched.is_ok());fetched?;
                    },
                    DownloadTransport::Quic(config)=>{
                        let encrypted=encrypted.as_ref().ok_or_else(||err!(EIO,"ENCRYPTED_TRANSPORT_REQUIRED"))?;
                        let key=&release.as_ref().ok_or_else(||err!(EIO,"NAMESPACE_CUSTODY_UNAVAILABLE"))?.key;
                        let stage=self.diagnostics.start(crate::sync_diagnostics::Stage::QuicFetch);
                        let fetched=crate::transport::quic::fetch_with_peer_stops(config,&artifact.metadata,encrypted,key,&mut accept,self.process_peer_stops());
                        stage.finish(fetched.is_ok());fetched?;
                    },
                    DownloadTransport::Oblivious(config)=>{
                        let encrypted=encrypted.as_ref().ok_or_else(||err!(EIO,"ENCRYPTED_TRANSPORT_REQUIRED"))?;
                        let key=&release.as_ref().ok_or_else(||err!(EIO,"NAMESPACE_CUSTODY_UNAVAILABLE"))?.key;
                        let stage=self.diagnostics.start(crate::sync_diagnostics::Stage::OhttpFetch);
                        let fetched=crate::transport::oblivious::fetch(config,&artifact.metadata,encrypted,key,&mut accept);
                        stage.finish(fetched.is_ok());fetched?;
                    },
                }
                if let Some(release)=release {plan.leases.push(release.lease);}
                let sealed={let mut st=self.state.lock().map_err(|_|err!(EIO,"STATE_POISONED"))?;let now=Self::download_now(&mut st)?;let current=Self::download_authority(&st,&uri,&plan,now).map(|()|artifact.metadata.clone());st.sessions.prepare(peer,&session,|_|current)?};
                prepared.push((artifact,sealed));
            }
            // Local publication, rollback and receipt hold one state lock. Other
            // requests cannot observe a partly committed eager closure.
            let mut st=self.state.lock().map_err(|_|err!(EIO,"STATE_POISONED"))?;let now=Self::download_now(&mut st)?;Self::download_authority(&st,&uri,&plan,now)?;self.revalidate_leases(&plan.leases)?;
            let transaction=(|| {
                for (artifact,sealed) in prepared.drain(..) {
                    let current=Self::download_authority(&st,&uri,&plan,now).and_then(|()|{self.revalidate_leases(&plan.leases)?;Ok(artifact.metadata.clone())});
                    let state=&mut *st;
                    let staging=state.store.staging();
                    let (_,root)=state.sessions.commit_prepared(sealed,|_|current,&state.store,|file,tf|{
                        self.revalidate_leases(&plan.leases)?;
                        if let Some(publisher)=&publisher {
                            let root=tf.hashes["blake3"].clone();
                            // A prior failed cleanup retains its exact original
                            // authority. Never overwrite it with new routing.
                            let previous=self.published.lock().map_err(|_|err!(EIO,"SEALED_LOCK"))?.get(&root).cloned();
                            if let Some((previous,original,_quota))=previous {previous.revoke(&original)?;self.published.lock().map_err(|_|err!(EIO,"SEALED_LOCK"))?.remove(&root);}
                            // The broker may durably publish and then lose its
                            // reply. Register the attempt before crossing RPC so
                            // rollback/Wipe still owns the required retraction.
                            let quota=Arc::new(staging.reserve(&root,tf.length,tf.length)?);
                            self.published.lock().map_err(|_|err!(EIO,"SEALED_LOCK"))?.insert(root.clone(),(publisher.clone(),tf.clone(),Some(quota)));published_roots.push(root.clone());
                            drop(publisher.publish(file,tf)?);
                            // A successful reply proves the broker's private
                            // stage is gone. A lost reply keeps this charge
                            // until original-authority retraction succeeds.
                            if let Some(record)=self.published.lock().map_err(|_|err!(EIO,"SEALED_LOCK"))?.get_mut(&root) {record.2=None;}
                        }
                        self.revalidate_leases(&plan.leases)
                    })?;
                    if root!=artifact.metadata.hashes["blake3"]{fail!(EACCES,"DOWNLOAD_ROOT_MISMATCH");}
                }
                Self::download_authority(&st,&uri,&plan,now)?;self.revalidate_leases(&plan.leases)?;
                self.handle_locked(&mut st,peer,CasRequest::Hydrate{cas_uri:plan.uri.clone()})
            })();
            if transaction.is_err(){self.rollback_publications(&mut st,&published_roots)?;}
            transaction
        })();
        if result.is_err(){let mut st=self.state.lock().map_err(|_|err!(EIO,"STATE_POISONED"))?;for session in sessions{let _=st.sessions.abort(peer,&session);}}
        result
    }
    fn rollback_publications(&self,st:&mut State,roots:&[String])->EnclaveResult<()> {
        for root in roots {
            let existing=self.published.lock().map_err(|_|err!(EIO,"SEALED_LOCK"))?.get(root).cloned();
            if let Some((publisher,target,_quota))=existing {publisher.revoke(&target)?;if st.store.contains(root){st.store.revoke(root)?;}self.published.lock().map_err(|_|err!(EIO,"SEALED_LOCK"))?.remove(root);}
        }Ok(())
    }

    /// Start.
    pub fn start(cfg: CasConfig) -> EnclaveResult<Arc<Self>> {
        Self::start_with_wall_clock(cfg, enclave_crypto::time::now_unix)
    }

    /// Start with an explicit wall-clock source (tests drive time with it;
    /// the trusted clock still never moves backwards).
    pub fn start_with_wall_clock(cfg: CasConfig, wall: fn() -> i64) -> EnclaveResult<Arc<Self>> {
        // GAP-30: trusted TUF metadata, the clock high-water mark and the
        // last refresh time survive restarts. A deleted, edited or
        // rolled-back store refuses to start rather than re-trusting the
        // install-time root at version 1.
        let (trust_store, saved) = match &cfg.state_dir {
            None => (None, None),
            Some(d) => match (|| {
                // Preserve relative development configuration without following
                // arbitrary symlinks or weakening the trusted-directory walk.
                let resolved = if d.is_absolute() { d.clone() } else {
                    std::env::current_dir().map_err(|e| err!(EIO, "STATE_PRIVATE_PATH", "{e}"))?.join(d)
                };
                SealedStore::open_required(&resolved, "tuf")
            })()
                .map_err(|e: enclave_core::EnclaveError| err!(EACCES, "TUF_STATE", "{e}; restore or explicitly re-provision UID 702 trust"))?
            {
                (st, Loaded::Fresh) => (Some(st), None),
                (st, Loaded::State(b)) => (
                    Some(st),
                    Some(enclave_core::sealed::decode::<TrustState>(&b)?),
                ),
            },
        };
        let restored = match saved.as_ref().and_then(|s| s.tuf.as_ref()) {
            Some(t) => Some(TufClient::restore(t)?),
            None => None,
        };
        let tuf = match (restored, &cfg.tuf_root) {
            (Some(c), Some(pin)) if !c.chain_contains(pin) => {
                fail!(EACCES, "TUF_ROOT_PIN_CHANGED", "the configured root is not in the persisted trust chain; rotate via signed root metadata")
            }
            (Some(c), _) => Some(c),
            (None, Some(pin)) => Some(TufClient::bootstrap(pin)?),
            (None, None) => None,
        };
        let high_water = saved.as_ref().map_or(i64::MIN, |s| s.clock_high_water);
        let mut clock = TrustedClock::resumed(wall(), high_water);
        let epoch = enclave_core::seq::new_boot_epoch_id();
        let journal = match &cfg.audit_path {
            Some(p) => Some(AuditJournal::open(p, DaemonId::SwarmSync, epoch.clone())?),
            None => None,
        };
        let outbox = cfg.store_dir.join("ohttp-outbox");
        // Do not inherit a permissive caller umask for queued ciphertext.
        // Existing unsafe directories remain refused by OutboxNamespace.
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new().recursive(true).mode(0o700).create(&outbox)
            .map_err(|e| err!(EIO, "OUTBOX", "{e}"))?;
        let store = ContentStore::open(&cfg.store_dir)?;
        let sessions = crate::streaming::Sessions::open_with_staging(&cfg.store_dir, store.staging())?;
        store.reconcile_staging(&sessions)?;

        // Adopt profile floor from host config if present in TUF (GAP-20, DEFECT-F-58)
        let mut eff_profile = cfg.profile;
        let bootstrap_at = wall();
        let now = clock.now(bootstrap_at);
        if let Some(tuf_client) = &tuf {
            if let Ok(bytes) = crate::config::get_host_config(store.root(), tuf_client, now) {
                if let Ok(host_cfg) =
                    enclave_core::host_config::EnclaveHostConfig::from_json_bytes(&bytes)
                {
                    eff_profile = eff_profile.max(host_cfg.profile_floor);
                }
            }
        }

        // FS-702 §4.3 cl. 1, GAP-19: In Profile L3, assert zero listening sockets at startup.
        if eff_profile == Profile::L3 {
            crate::transport::ohttp_fetch::assert_l3_zero_listeners()?;
        }

        let cancellation=Arc::new(DownloadCancellation::default());
        Ok(Arc::new(Self {
            process_peer_stops:crate::transport::quic_poison::process_peer_stops(),
            dev_same_uid: cfg.dev_same_uid,
            diagnostics:crate::sync_diagnostics::SyncDiagnostics::new(epoch.clone(),cfg.dev_same_uid),
            outbox_diagnostics:crate::outbox::OutboxDiagnostics::new(outbox.clone(),epoch.clone(),cfg.dev_same_uid),
            cancellation:cancellation.clone(),
            namespace_custody:Mutex::new(None),
            snapshot_publisher_override:Mutex::new(None),
            active_downloads:Mutex::new(std::collections::BTreeSet::new()),
            published:Mutex::new(std::collections::BTreeMap::new()),
            state: Mutex::new(State {
                required_profile: None,
                ohttp_gateway: cfg.ohttp_gateway,
                profile: eff_profile,
                store,
                sessions,
                cancellation,

                tuf,
                persisted_high_water: clock.high_water(),
                clock,
                wall,
                refreshed_at: saved.as_ref().and_then(|s| s.refreshed_at),
                bootstrap_at,
                trust_store,
                revocation: cfg.revocation,
                seq: RpcSequencer::new(epoch, 0),
                journal,
                outbox,
            }),
        }))
        .and_then(|svc| {
            // Seal the initial state now, so a later deletion is
            // STATE_MISSING rather than a first boot.
            {
                let mut g = svc.state.lock().map_err(|_| err!(EIO, "STATE_POISONED"))?;
                // Adopt profile floor from host config if present in TUF (GAP-20).
                let wall_now = (g.wall)();
                let now = g.clock.now(wall_now);
                if let Some(tuf_client) = g.tuf.as_ref() {
                    if let Ok(bytes) =
                        crate::config::get_host_config(g.store.root(), tuf_client, now)
                    {
                        if let Ok(cfg) =
                            enclave_core::host_config::EnclaveHostConfig::from_json_bytes(&bytes)
                        {
                            g.profile = g.profile.max(cfg.profile_floor);
                        }
                    }
                }
                Self::persist(&mut g)?;
                // A revocation adopted before a restart is enforced again if
                // the artifact is still here.
                let seq = g.seq.next()?;
                svc.revoke_snapshots(&mut g)?;
                Self::apply_revocations(&mut g, seq)?;
            }
            Ok(svc)
        })
    }

    pub(crate) fn initial_tuf_root_version(&self)->EnclaveResult<u64> {let st=self.state.lock().map_err(|_|err!(EIO,"STATE_POISONED"))?;Ok(st.tuf.as_ref().ok_or_else(||err!(EPERM,"TUF_NOT_BOOTSTRAPPED"))?.root().version)}

    /// Preflight provisioned metadata without adopting it. Startup may recover
    /// from a stale transport, but must never swallow a later persistence or
    /// revocation-enforcement failure from the committing handle call.
    pub(crate) fn validate_initial_tuf_refresh(&self, request: &CasRequest) -> EnclaveResult<()> {
        let CasRequest::TufRefresh { roots, timestamp, snapshot, targets } = request else {
            fail!(EINVAL, "TUF_REFRESH_REQUIRED");
        };
        let mut st = self.state.lock().map_err(|_| err!(EIO, "STATE_POISONED"))?;
        let wall_now = (st.wall)();
        let now = st.clock.now(wall_now);
        let mut next = st.tuf.as_ref().ok_or_else(|| err!(EPERM, "TUF_NOT_BOOTSTRAPPED"))?.clone();
        for root in roots { next.update_root(root)?; }
        next.refresh(timestamp, snapshot, targets, now)
    }

    /// Enable the production entry's mandatory signed-floor admission. CAS may
    /// expose only signed-config management while bootstrapping; it must not
    /// depend on its own not-yet-bound socket. Raw service fixtures opt in.
    pub fn enable_host_profile_floor(&self, requested: Profile) -> EnclaveResult<()> {
        let mut st = self.state.lock().map_err(|_| err!(EIO, "STATE_POISONED"))?;
        st.required_profile = Some(requested);
        let wall_now = (st.wall)();
        let now = st.clock.now(wall_now);
        if let Some(tuf) = st.tuf.as_ref() {
            if let Ok(bytes) = crate::config::get_host_config(st.store.root(), tuf, now) {
                enclave_core::host_config::EnclaveHostConfig::from_json_bytes(&bytes)?
                    .admit_profile(requested)?;
            }
        }
        Ok(())
    }

    /// Both this gate and the request execute under the same State lock. A
    /// refresh cannot race admission of a normal CAS request. Management still
    /// verifies metadata and payloads through its existing TUF checks.
    fn host_profile_gate(st: &State, req: &CasRequest, now: i64) -> EnclaveResult<()> {
        let Some(requested) = st.required_profile else { return Ok(()); };
        let config_only = match req {
            CasRequest::TufBootstrap { .. } | CasRequest::TufRefresh { .. }
                | CasRequest::FetchHostConfig | CasRequest::Wipe => true,
            CasRequest::Admit { target, .. } | CasRequest::FetchTarget { target } =>
                target == enclave_core::host_config::HOST_CONFIG_TARGET,
            _ => false,
        };
        if config_only { return Ok(()); }
        let tuf = st.tuf.as_ref().ok_or_else(|| err!(EACCES, "HOST_CONFIG_REQUIRED"))?;
        let bytes = crate::config::get_host_config(st.store.root(), tuf, now)?;
        enclave_core::host_config::EnclaveHostConfig::from_json_bytes(&bytes)?
            .admit_profile(requested)
    }

    /// Seal the trust state (before any response that depends on it).
    fn persist(st: &mut State) -> EnclaveResult<()> {
        let Some(store) = st.trust_store.as_mut() else {
            return Ok(());
        };
        let body = TrustState {
            tuf: st.tuf.as_ref().map(TufClient::export).transpose()?,
            clock_high_water: st.clock.high_water(),
            refreshed_at: st.refreshed_at,
        };
        store.save_json(&body)?;
        st.persisted_high_water = body.clock_high_water;
        Ok(())
    }

    /// FS-702 §7.3.2 Safe-Fail Lockdown: past the offline TTL only
    /// `public_l1` artifacts stay usable. `class = None` (admission) always
    /// locks.
    fn offline_gate(st: &State, now: i64, class: Option<Classification>) -> EnclaveResult<()> {
        let t = st.refreshed_at.unwrap_or(st.bootstrap_at);
        if now.saturating_sub(t) > OFFLINE_TTL_S && class != Some(Classification::PublicL1) {
            fail!(
                ESTALE,
                "TUF_OFFLINE_TTL",
                "no TUF refresh for {} h (limit 168 h)",
                now.saturating_sub(t) / 3600
            );
        }
        Ok(())
    }

    /// Shred every stored artifact whose signed target is revoked and have
    /// its holders terminated; journal `REVOKE` and `KILL` (or
    /// `REVOCATION_UNENFORCED`) under the triggering `rpc_seq_u64` (RB-202).
    fn apply_revocations(st: &mut State, seq: u64) -> EnclaveResult<usize> {
        let revoked: Vec<(String, String)> = st
            .tuf
            .as_ref()
            .and_then(TufClient::targets)
            .map(|t| {
                t.iter()
                    .filter(|(_, tf)| {
                        tf.custom
                            .as_ref()
                            .and_then(|c| c.get("revoked"))
                            .and_then(serde_json::Value::as_bool)
                            == Some(true)
                    })
                    .filter_map(|(name, tf)| {
                        tf.hashes.get("blake3").map(|r| (name.clone(), r.clone()))
                    })
                    .collect()
            })
            .unwrap_or_default();
        let mut n = 0;
        for (target, root) in revoked {
            if !st.store.contains(&root) {
                continue;
            }
            let held=st.store.prepare_revocation(&root).map_err(|error|{st.cancellation.blocked.store(true,std::sync::atomic::Ordering::SeqCst);error})?;
            let enforcement=match &held {
                Some(file)=>match st.revocation.enforce_file(file,&root) {
                    Ok(Some(report)) if report.complete && report.incomplete.is_empty() && report.refused.is_empty()=>Ok(Some(report)),
                    Ok(Some(report))=>Err(err!(EIO,"REVOCATION_INCOMPLETE","holders={} uncertain={} refused={}",report.holders.len(),report.incomplete.len(),report.refused.len())),
                    Ok(None)=>Err(err!(EIO,"REVOCATION_UNENFORCED")),Err(e)=>Err(e),
                },
                None=>Ok(None), // no canonical inode was handed to a consumer
            };
            if let Some(j)=st.journal.as_mut() {
                j.append(seq,json!({"event":if enforcement.is_ok(){"HOLDERS_RELEASED"}else{"REVOCATION_INCOMPLETE"},"target":target,"root":root,"enforcement":st.revocation.name(),"reason":enforcement.as_ref().err().map(|e|e.reason.as_str())}))?;
                if let Ok(Some(report))=&enforcement {
                    let mut event=serde_json::to_value(report).map_err(|_|err!(EIO,"REVOCATION_REPORT"))?;
                    event["event"]=json!("KILL");event["root"]=json!(root);j.append(seq,event)?;
                }
            }
            if let Err(error)=enforcement {
                st.cancellation.blocked.store(true,std::sync::atomic::Ordering::SeqCst);
                return Err(error); // name + manifest survive for startup/Wipe retry
            }
            let chunks=st.store.revoke(&root).map_err(|error|{st.cancellation.blocked.store(true,std::sync::atomic::Ordering::SeqCst);error})?;n+=1;
            if let Some(j)=st.journal.as_mut() {j.append(seq,json!({"event":"REVOKE","target":target,"root":root,"chunks":chunks,"enforcement":st.revocation.name()}))?;}
        }
        Ok(n)
    }

    fn lockdown(st: &State, now: i64) -> bool {
        st.refreshed_at
            .is_some_and(|t| now.saturating_sub(t) > OFFLINE_TTL_S)
    }

    /// Handle a request. Network hydration releases the service lock around
    /// TLS I/O and rechecks signed configuration/profile authority at each stage.
    pub fn handle(&self, peer: &PeerCredentials, req: CasRequest) -> EnclaveResult<CasResponse> {
        if matches!(&req, CasRequest::FetchCustodyMetadata) && peer.uid != DaemonId::CustodyVault.uid()
            && !(self.dev_same_uid && peer.uid == enclave_core::ipc::geteuid()) {
            fail!(EACCES, "CUSTODY_METADATA_PEER_REJECTED");
        }
        if matches!(&req, CasRequest::FetchCustodyTarget { .. }) && peer.uid != DaemonId::CustodyVault.uid()
            && !(self.dev_same_uid && peer.uid == enclave_core::ipc::geteuid()) {
            fail!(EACCES, "CUSTODY_TARGET_PEER_REJECTED");
        }
        match req {
            CasRequest::SyncDiagnostics=>self.sync_diagnostics(peer),
            CasRequest::OutboxDiagnostics=>self.outbox_diagnostics(peer),
            CasRequest::Wipe=>{
                // Authenticate before cancellation without waiting for State.
                // Publication/cleanup can take much longer than the immediate
                // authority fence. Pending Wipes also block new plans while
                // this Wipe waits for State and completes cleanup.
                Self::wipe_peer(peer)?;let _cancellation=self.cancellation.begin()?;
                self.handle_local(peer,CasRequest::Wipe)
            },
            CasRequest::Status=>{
                let response=self.handle_local(peer,CasRequest::Status)?;
                if let CasResponse::Status(mut status)=response {
                    let l3=status.state.starts_with("profile=L3 ");
                    if l3 {
                        // The independent helper must answer through the real
                        // UID/code-pinned channel. Perform this outside State.
                        let injected=self.snapshot_publisher_override.lock().map_err(|_|err!(EIO,"SEALED_LOCK"))?.is_some();
                        let ready=!injected&&crate::snapshot_broker::BrokerClient.require_ready().is_ok();
                        status.state.push_str(if ready{" apfs_broker_ready=true"}else{" apfs_broker_ready=false"});
                    }
                    Ok(CasResponse::Status(status))
                }else{Err(err!(EIO,"STATUS_RESPONSE"))}
            }
            CasRequest::Hydrate { cas_uri } => self.hydrate_request(peer, &cas_uri),
            CasRequest::OpenTarget { target } => {
                let result = self.handle_local(peer, CasRequest::OpenTarget { target: target.clone() });
                match result {
                    Err(e) if e.is("TARGET_UNAVAILABLE") || e.is("COMPANION_NOT_HYDRATED") => {
                        // The production F13 worker uses OpenTarget. A missing
                        // model can therefore reach the same authenticated
                        // dispatcher; generic/config targets need model policy.
                        let uri = {
                            let mut guard = self.state.lock().map_err(|_| err!(EIO, "STATE_POISONED"))?;
                            let st = &mut *guard;
                            let now = Self::download_now(st)?;
                            Self::host_profile_gate(st, &CasRequest::OpenTarget { target: target.clone() }, now)?;
                            let tf = st.tuf.as_ref().ok_or_else(|| err!(EPERM, "TUF_NOT_BOOTSTRAPPED"))?.target(&target, now)?;
                            crate::streaming::validate_target(tf)?;
                            let namespace=tf.custom.as_ref().and_then(|v|v.get("encrypted_transport")).and_then(|v|v.get("key")).and_then(|v|v.get("namespace")).and_then(|v|v.as_str()).unwrap_or("models");
                            format!("cas://blake3-bao-v1/{}?target={target}&ns={namespace}", tf.hashes["blake3"])
                        };
                        self.hydrate_request(peer, &uri)?;
                        self.handle_local(peer, CasRequest::OpenTarget { target })
                    },
                    other => other,
                }
            },
            other => self.handle_local(peer, other),
        }
    }

    fn wipe_peer(peer:&PeerCredentials)->EnclaveResult<()> {
        if peer.uid!=0&&peer.uid!=enclave_core::ipc::geteuid(){fail!(EPERM,"WIPE_PEER_REJECTED");}Ok(())
    }

    fn outbox_diagnostics(&self,peer:&PeerCredentials)->EnclaveResult<CasResponse> {
        // Exact existing diagnostics reader policy: production signed-root CLI
        // via outer IPC, development actual same UID only. No State mutation.
        if !self.diagnostics.authorized(peer.uid){fail!(EACCES,"OUTBOX_DIAGNOSTICS_PEER_REJECTED");}
        Ok(CasResponse::OutboxDiagnostics(self.outbox_diagnostics.snapshot()))
    }

    fn sync_diagnostics(&self,peer:&PeerCredentials)->EnclaveResult<CasResponse> {
        // This authorization is additional to existing outer IPC admission.
        // It deliberately reads neither State nor any authority backend.
        if !self.diagnostics.authorized(peer.uid){fail!(EACCES,"SYNC_DIAGNOSTICS_PEER_REJECTED");}
        Ok(CasResponse::SyncDiagnostics(self.diagnostics.snapshot()))
    }

    fn handle_local(&self, peer: &PeerCredentials, req: CasRequest) -> EnclaveResult<CasResponse> {
        let access=self.access_epoch(&req)?;
        let mut g = self.state.lock().map_err(|_| err!(EIO, "STATE_POISONED"))?;
        self.handle_locked_access(&mut g, peer, req,access)
    }

    fn handle_locked(&self, st: &mut State, peer: &PeerCredentials, req: CasRequest) -> EnclaveResult<CasResponse> {
        let access=self.access_epoch(&req)?;self.handle_locked_access(st,peer,req,access)
    }
    fn access_epoch(&self,req:&CasRequest)->EnclaveResult<Option<u64>> {
        if matches!(req,CasRequest::Hydrate{..}|CasRequest::OpenTarget{..}|CasRequest::Resolve{..}|CasRequest::Fetch{..}|CasRequest::FetchTarget{..}|CasRequest::FetchCustodyMetadata|CasRequest::FetchCustodyTarget{..}|CasRequest::SeedDecision{..}|CasRequest::Admit{..}|CasRequest::AdmitBegin{..}|CasRequest::AdmitChunk{..}|CasRequest::AdmitCommit{..}){Ok(Some(self.cancellation.observe()?))}else{Ok(None)}
    }
    fn handle_locked_access(&self,st:&mut State,peer:&PeerCredentials,req:CasRequest,access:Option<u64>)->EnclaveResult<CasResponse>{
        // Also preserve read-only behavior for internal callers of this helper.
        if matches!(&req,CasRequest::SyncDiagnostics){return self.sync_diagnostics(peer);}
        if matches!(&req,CasRequest::OutboxDiagnostics){return self.outbox_diagnostics(peer);}
        let mut tuf_stage=None;
        let result=(|| {
        let wipe=matches!(&req,CasRequest::Wipe);
        // Each serialized Wipe must own its outcome: a preceding successful
        // Wipe may have cleared the latch while this one was already pending.
        if wipe{Self::wipe_peer(peer)?;st.cancellation.blocked.store(true,std::sync::atomic::Ordering::SeqCst);}
        if let Some(generation)=access{st.cancellation.validate(generation)?;}
        let seq = st.seq.next()?;
        let release_started=std::time::Instant::now();
        let now = st.clock.now((st.wall)());
        if st.trust_store.is_some()
            && now >= st.persisted_high_water.saturating_add(CLOCK_PERSIST_S)
        {
            Self::persist(st)?;
        }
        st.sessions.sweep(now);
        Self::host_profile_gate(st, &req, now)?;
        let mut release_leases=Vec::new();
        let (resp, ev) = match req {
            CasRequest::SyncDiagnostics=>return self.sync_diagnostics(peer),
            CasRequest::OutboxDiagnostics=>return self.outbox_diagnostics(peer),
            CasRequest::Status => (
                CasResponse::Status(DaemonStatus {
                    daemon_uid: DaemonId::SwarmSync.uid(),
                    binary: DaemonId::SwarmSync.binary().into(),
                    pid: std::process::id(),
                    rss_bytes: enclave_core::resource::current_rss_bytes().unwrap_or(0),
                    rss_ceiling_bytes: DaemonId::SwarmSync.rss_ceiling_bytes(),
                    boot_epoch_id: st.seq.boot_epoch_id().into(),
                    rpc_seq_u64: st.seq.current(),
                    state: format!(
                        "profile={} tuf={:?} tuf_state={} offline_lockdown={} revocation={} staging_reserved_bytes={}",
                        st.profile,
                        st.tuf.as_ref().map(TufClient::versions),
                        if st.trust_store.is_some() {
                            "sealed"
                        } else {
                            "volatile"
                        },
                        Self::lockdown(st, now),
                        st.revocation.name(),
                        st.sessions.staging_reserved()?
                    ),
                    phys_footprint_bytes: enclave_core::resource::current_phys_footprint_bytes()
                        .unwrap_or(0),
                    phys_footprint_source: enclave_core::resource::current_phys_footprint_source(),
                }),
                None,
            ),
            CasRequest::TufBootstrap { root } => {
                // Trust-on-first-use of the pinned root, once per process and
                // only from an administrator: later root changes must arrive
                // as a signed rotation chain through `TufRefresh`.
                if peer.uid != 0 && peer.uid != enclave_core::ipc::geteuid() {
                    fail!(EPERM, "TUF_BOOTSTRAP_ADMIN_ONLY");
                }
                if st.tuf.is_some() {
                    fail!(
                        EALREADY,
                        "TUF_ALREADY_BOOTSTRAPPED",
                        "rotate via signed root metadata instead"
                    );
                }
                let c = TufClient::bootstrap(&root)?;
                let v = c.root().version;
                st.tuf = Some(c);
                Self::persist(st)?;
                (
                    CasResponse::Tuf {
                        versions: (0, 0, 0),
                    },
                    Some(json!({"event": "TUF_BOOTSTRAP", "root_version": v})),
                )
            }
            CasRequest::TufRefresh {
                roots,
                timestamp,
                snapshot,
                targets,
            } => {
                if peer.uid != 0 && peer.uid != 702 && peer.uid != enclave_core::ipc::geteuid() {
                    fail!(
                        EPERM,
                        "TUF_REFRESH_PEER_REJECTED",
                        "only root, UID 702, or self can refresh TUF metadata"
                    );
                }
                tuf_stage=Some(self.diagnostics.start(crate::sync_diagnostics::Stage::TufRefresh));
                let c = st
                    .tuf
                    .as_mut()
                    .ok_or_else(|| err!(EPERM, "TUF_NOT_BOOTSTRAPPED"))?;
                let old_v = c.versions();
                let mut next = c.clone();
                for r in roots {
                    next.update_root(&r)?;
                }
                next.refresh(&timestamp, &snapshot, &targets, now)?;
                // Metadata adoption and final handoff share the same fence.
                // Expensive signature verification/persistence stay outside.
                {let _release=st.cancellation.release.lock().map_err(|_|err!(EIO,"RELEASE_LOCK"))?;
                    st.cancellation.advance()?; *c = next;}
                let v = c.versions();
                if v != old_v {
                    st.refreshed_at = Some(now);
                }
                if let Ok(bytes) = crate::config::get_host_config(st.store.root(), c, now) {
                    if let Ok(cfg) =
                        enclave_core::host_config::EnclaveHostConfig::from_json_bytes(&bytes)
                    {
                        st.profile = st.profile.max(cfg.profile_floor);
                    }
                }
                // The new rollback floor is durable before the reply leaves.
                Self::persist(st)?;
                // GAP-21: revocations arrive only as signed metadata.
                self.revoke_snapshots(st)?;
                Self::apply_revocations(st, seq)?;
                (
                    CasResponse::Tuf { versions: v },
                    Some(json!({"event": "TUF_REFRESH", "versions": v})),
                )
            }
            CasRequest::Admit { target, bytes } => {
                Self::offline_gate(st, now, None)?;
                let tuf = st
                    .tuf
                    .as_ref()
                    .ok_or_else(|| err!(EPERM, "TUF_NOT_BOOTSTRAPPED"))?;
                if Self::guarded_model(st,tuf.target(&target,now)?) {fail!(EACCES,"AUTHENTICATED_DOWNLOAD_REQUIRED");}
                let root = admit(&st.store, tuf, &target, &bytes, now)?;
                (
                    CasResponse::Admitted { root: root.clone() },
                    Some(json!({"event": "ADMIT", "target": target, "root": root})),
                )
            }
            CasRequest::AdmitBegin { target } => {
                Self::offline_gate(st, now, None)?;
                let tf = st.tuf.as_ref().ok_or_else(|| err!(EPERM, "TUF_NOT_BOOTSTRAPPED"))?
                    .target(&target, now)?.clone();
                if Self::guarded_model(st,&tf) {fail!(EACCES,"AUTHENTICATED_DOWNLOAD_REQUIRED");}
                let session = st.sessions.begin(peer, target.clone(), tf.clone(), now)?;
                (CasResponse::Admission {
                    session, length: tf.length, blake3: tf.hashes["blake3"].clone(),
                    sha256: tf.hashes["sha256"].clone(),
                    max_chunk_bytes: crate::streaming::MAX_CHUNK_BYTES,
                }, Some(json!({"event": "ADMIT_BEGIN", "target": target, "length": tf.length})))
            }
            CasRequest::AdmitChunk { session, offset, bytes } => {
                let received = st.sessions.chunk(peer, &session, offset, &bytes, now)?;
                (CasResponse::AdmissionProgress { received }, None)
            }
            CasRequest::AdmitAbort { session } => {
                st.sessions.abort(peer, &session)?;
                (CasResponse::Wiped, None)
            }
            CasRequest::AdmitCommit { session } => {
                // Re-evaluate the fresh metadata and offline gate INSIDE the
                // consuming commit closure so every owned failure cleans up.
                let gate = Self::offline_gate(st, now, None);
                let tuf = st.tuf.as_ref();
                let (target, root) = st.sessions.commit(peer, &session, |target| {
                    gate?;
                    let tf=tuf.ok_or_else(||err!(EPERM,"TUF_NOT_BOOTSTRAPPED"))?.target(target,now)?.clone();
                    if tf.custom.as_ref().is_some_and(|v|v.get("encrypted_transport").is_some()) {fail!(EACCES,"AUTHENTICATED_DOWNLOAD_REQUIRED");}
                    Ok(tf)
                }, &st.store)?;
                (CasResponse::Admitted { root: root.clone() },
                    Some(json!({"event": "ADMIT", "target": target, "root": root})))
            }
            CasRequest::OpenTarget { target } => {
                let tf = st.tuf.as_ref().ok_or_else(|| err!(EPERM, "TUF_NOT_BOOTSTRAPPED"))?
                    .target(&target, now)?;
                crate::streaming::validate_target(tf)?;
                // Generic configuration targets may have custom {}. When a
                // signed model policy is supplied, enforce its classification
                // and host floor exactly as Resolve does.
                let class = if tf.custom.as_ref().is_some_and(|c| {
                    ["classification", "min_profile", "license_policy", "jurisdiction_shard", "lazy_fuse_t", "companion_safety_layers", "encrypted_transport"]
                        .iter().any(|key| c.get(*key).is_some())
                }) {
                    let pol: crate::governance::TargetPolicy = serde_json::from_value(tf.custom.clone().unwrap_or_default())
                        .map_err(|e| err!(EINVAL, "TARGET_POLICY", "{e}"))?;
                    let required_floor = pol.min_profile.max(pol.classification.floor());
                    if required_floor > st.profile { fail!(EPERM, "PROFILE_FLOOR_EXCEEDED"); }
                    for companion in pol.companion_safety_layers.iter().filter(|c| c.eager_hydrate_required) {
                        let metadata = st.tuf.as_ref().and_then(|tuf| tuf.targets()).and_then(|targets| targets.values().find(|tf| tf.hashes.get("blake3") == Some(&companion.blake3)))
                            .ok_or_else(|| err!(EACCES, "COMPANION_NOT_SIGNED"))?;
                        Self::artifact_authority(st, metadata, now)?;
                    }
                    Self::reserve_resolution(st, None, &pol)?;
                    drop(crate::admission::open_companions(&st.store, st.tuf.as_ref().expect("checked TUF"), &pol, st.profile)?);
                    Some(pol.classification)
                } else { None };
                Self::offline_gate(st, now, class)?;
                // An absent encrypted model is a hydration request, not a
                // failed attempt to reopen a snapshot that never existed.
                if Self::guarded_model(st,tf) && !st.store.contains(&tf.hashes["blake3"]) {fail!(EINVAL,"TARGET_UNAVAILABLE");}
                let (leases,sealed)=if class.is_some() {
                    let policy=serde_json::from_value(tf.custom.clone().unwrap_or_default()).map_err(|_|err!(EINVAL,"TARGET_POLICY"))?;
                    self.guard_closure(st,tf,&policy,now)?
                } else {(Vec::new(),None)};
                let file=if let Some(mut files)=sealed {files.remove(0)} else {
                    let (file,reservation)=st.sessions.export(&st.store,&target,tf)?.into_parts();
                    if let Some(reservation)=reservation {enclave_core::ipc::attach_reply_guard(reservation);}
                    file
                };
                self.revalidate_leases(&leases)?;release_leases.extend(leases.clone());
                let response = CasResponse::TargetFile { length: tf.length,
                    blake3: tf.hashes["blake3"].clone(), sha256: tf.hashes["sha256"].clone(), fds: 1 };
                // Export snapshots are explicit authorized copies, not the
                // canonical revocable Resolve inode. No writable FD escapes.
                enclave_core::ipc::attach_fds(vec![file.into()]);
                (response, Some(json!({"event": "OPEN_TARGET", "target": target})))
            }
            CasRequest::Resolve { cas_uri } => {
                let tuf = st
                    .tuf
                    .as_ref()
                    .ok_or_else(|| err!(EPERM, "TUF_NOT_BOOTSTRAPPED"))?;
                let (_, pol) = lookup(tuf, &CasUri::parse(&cas_uri)?, now)?;
                Self::offline_gate(st, now, Some(pol.classification))?;
                for companion in pol.companion_safety_layers.iter().filter(|c| c.eager_hydrate_required) {
                    let metadata = tuf.targets().and_then(|targets| targets.values().find(|tf| tf.hashes.get("blake3") == Some(&companion.blake3)))
                        .ok_or_else(|| err!(EACCES, "COMPANION_NOT_SIGNED"))?;
                    Self::artifact_authority(st, metadata, now)?;
                }
                let uri = CasUri::parse(&cas_uri)?;
                Self::reserve_resolution(st, Some(&uri.root), &pol)?;
                let mut r = resolve(&st.store, tuf, &cas_uri, st.profile, now)?;
                let (tf,_)=lookup(tuf,&uri,now)?;
                let (leases,sealed)=self.guard_closure(st,tf,&pol,now)?;
                if let Some(files)=sealed {r.fds=files;}
                self.revalidate_leases(&leases)?;release_leases.extend(leases.clone());
                let required_floor = r.policy.min_profile.max(r.policy.classification.floor());
                if required_floor > st.profile {
                    fail!(
                        EPERM,
                        "PROFILE_FLOOR_EXCEEDED",
                        "artifact required floor {required_floor:?} exceeds host profile {:?}",
                        st.profile
                    );
                }
                let n = r.fds.len();
                let fds = r
                    .fds
                    .into_iter()
                    .map(std::os::unix::io::OwnedFd::from)
                    .collect();
                enclave_core::ipc::attach_fds(fds);
                let ev = json!({"event": "RESOLVE", "caller_uid": peer.uid, "cas_uri": cas_uri, "sha256": r.sha256,
                                "effective_profile": r.effective_profile, "jurisdiction_shard": r.policy.jurisdiction_shard});
                (
                    CasResponse::Resolved {
                        effective_profile: r.effective_profile,
                        sha256: r.sha256,
                        fds: n,
                    },
                    Some(ev),
                )
            }
            CasRequest::Fetch { cas_uri } => {
                let tuf = st
                    .tuf
                    .as_ref()
                    .ok_or_else(|| err!(EPERM, "TUF_NOT_BOOTSTRAPPED"))?;
                let uri = CasUri::parse(&cas_uri)?;
                let (target_meta, pol) = lookup(tuf, &uri, now)?;
                Self::offline_gate(st, now, Some(pol.classification))?;
                if target_meta.length > 512 * 1024 {
                    fail!(
                        E2BIG,
                        "FETCH_TOO_LARGE",
                        "use Resolve (SCM_RIGHTS) for large artifacts"
                    );
                }
                let (leases,sealed)=self.guard_closure(st,target_meta,&pol,now)?;
                let b=if let Some(mut files)=sealed {use std::io::Read;let mut b=Vec::new();files[0].read_to_end(&mut b).map_err(|e|err!(EIO,"FETCH_READ","{e}"))?;b} else {st.store.get(&uri.root)?};
                self.revalidate_leases(&leases)?;release_leases.extend(leases.clone());
                if b.len() > 512 * 1024 {
                    fail!(
                        E2BIG,
                        "FETCH_TOO_LARGE",
                        "use Resolve (SCM_RIGHTS) for large artifacts"
                    );
                }
                (
                    CasResponse::Bytes(serde_bytes::ByteBuf::from(b)),
                    Some(json!({"event": "FETCH", "cas_uri": cas_uri})),
                )
            }
            CasRequest::SeedDecision { cas_uri } => {
                let tuf = st
                    .tuf
                    .as_ref()
                    .ok_or_else(|| err!(EPERM, "TUF_NOT_BOOTSTRAPPED"))?;
                let uri = CasUri::parse(&cas_uri)?;
                let (_, pol) = lookup(tuf, &uri, now)?;
                Self::offline_gate(st, now, Some(pol.classification))?;
                let eff = Profile::effective(st.profile, pol.min_profile, &[]);
                may_seed(&pol, eff)?;
                (CasResponse::SeedAllowed, None)
            }
            CasRequest::FetchHostConfig => {
                let tuf = st
                    .tuf
                    .as_ref()
                    .ok_or_else(|| err!(EPERM, "TUF_NOT_BOOTSTRAPPED"))?;
                let bytes = crate::config::get_host_config(st.store.root(), tuf, now)?;
                (
                    CasResponse::Bytes(serde_bytes::ByteBuf::from(bytes)),
                    Some(json!({"event": "FETCH_HOST_CONFIG"})),
                )
            }
            CasRequest::FetchTarget { target } => {
                let metadata=st.tuf.as_ref().ok_or_else(||err!(EPERM,"TUF_NOT_BOOTSTRAPPED"))?.target(&target,now)?;
                if metadata.custom.as_ref().is_some_and(|c|["classification","min_profile","license_policy","jurisdiction_shard","companion_safety_layers","encrypted_transport"].iter().any(|key|c.get(*key).is_some())) {
                    fail!(EACCES,"MODEL_DESCRIPTOR_REQUIRED");
                }
                let tuf = st
                    .tuf
                    .as_ref()
                    .ok_or_else(|| err!(EPERM, "TUF_NOT_BOOTSTRAPPED"))?;
                let bytes = if target == enclave_core::host_config::HOST_CONFIG_TARGET {
                    crate::config::get_host_config(st.store.root(), tuf, now)?
                } else {
                    crate::config::get_target_bytes(st.store.root(), tuf, &target, now)?
                };
                (
                    CasResponse::Bytes(serde_bytes::ByteBuf::from(bytes)),
                    Some(json!({"event": "FETCH_TARGET", "target": target})),
                )
            }
            CasRequest::FetchCustodyTarget { target } => {
                use enclave_core::custody_metadata::CustodyTargetReceipt;
                if peer.uid != DaemonId::CustodyVault.uid()
                    && !(self.dev_same_uid && peer.uid == enclave_core::ipc::geteuid()) {
                    fail!(EACCES, "CUSTODY_TARGET_PEER_REJECTED");
                }
                let tuf = st.tuf.as_ref().ok_or_else(|| err!(EPERM, "TUF_NOT_BOOTSTRAPPED"))?;
                let metadata = tuf.target(target.target_name(), now)?;
                if metadata.custom.as_ref().is_some_and(|c|["classification","min_profile","license_policy","jurisdiction_shard","companion_safety_layers","encrypted_transport"].iter().any(|key|c.get(*key).is_some())) {
                    fail!(EACCES, "MODEL_DESCRIPTOR_REQUIRED");
                }
                let bytes = crate::config::get_target_bytes_with_limit(st.store.root(), tuf,
                    target.target_name(), now, target.max_bytes() as u64)?;
                let config = crate::config::get_host_config(st.store.root(), tuf, now)?;
                let config = enclave_core::host_config::EnclaveHostConfig::from_json_bytes(&config)?;
                let receipt = CustodyTargetReceipt { v: 1, target: target.target_name().into(),
                    blake3: blake3::hash(&bytes).to_hex().to_string(), bytes: bytes.into(),
                    refreshed_at: st.refreshed_at.ok_or_else(|| err!(ESTALE, "CUSTODY_TARGET_STALE"))?,
                    expires_at: tuf.fresh_until()?, verified_now: now,
                    effective_profile: st.profile.max(config.profile_floor), versions: tuf.versions() };
                receipt.validate(now, st.profile.max(config.profile_floor), target)?;
                (CasResponse::CustodyTarget(receipt), Some(json!({"event": "FETCH_CUSTODY_TARGET", "target": target.target_name()})))
            }
            CasRequest::FetchCustodyMetadata => {
                use enclave_core::custody_metadata::{CustodyMetadataReceipt, FIDO_MDS_TARGET, MAX_MDS_BYTES};
                if peer.uid != DaemonId::CustodyVault.uid()
                    && !(self.dev_same_uid && peer.uid == enclave_core::ipc::geteuid()) {
                    fail!(EACCES, "CUSTODY_METADATA_PEER_REJECTED");
                }
                let tuf = st.tuf.as_ref().ok_or_else(|| err!(EPERM, "TUF_NOT_BOOTSTRAPPED"))?;
                let metadata = tuf.target(FIDO_MDS_TARGET, now)?;
                if metadata.length > MAX_MDS_BYTES as u64 { fail!(E2BIG, "CUSTODY_METADATA_TOO_LARGE"); }
                let bytes = crate::config::get_target_bytes_with_limit(st.store.root(), tuf, FIDO_MDS_TARGET, now, MAX_MDS_BYTES as u64)?;
                let config = crate::config::get_host_config(st.store.root(), tuf, now)?;
                let config = enclave_core::host_config::EnclaveHostConfig::from_json_bytes(&config)?;
                let digest = blake3::hash(&bytes).to_hex().to_string();
                if config.fido_mds_allowlist_digest != digest { fail!(EACCES, "CUSTODY_METADATA_CONFIG_DIGEST"); }
                let receipt = CustodyMetadataReceipt { v: 1, target: FIDO_MDS_TARGET.into(), bytes: bytes.into(),
                    refreshed_at: st.refreshed_at.ok_or_else(|| err!(ESTALE, "CUSTODY_METADATA_STALE"))?,
                    expires_at: tuf.fresh_until()?, verified_now: now,
                    effective_profile: st.profile.max(config.profile_floor), versions: tuf.versions(), blake3: digest };
                receipt.validate(now, st.profile.max(config.profile_floor))?;
                (CasResponse::CustodyMetadata(receipt), Some(json!({"event": "FETCH_CUSTODY_METADATA"})))
            }
            CasRequest::RelayRollup { frame } => {
                // Peer must be UID 705 (_enclavezk), root (0), or self (DEFECT-F-54)
                if peer.uid != 0
                    && peer.uid != DaemonId::ZkAuditor.uid()
                    && peer.uid != enclave_core::ipc::geteuid()
                {
                    fail!(
                        EPERM,
                        "RELAY_ROLLUP_PEER_REJECTED",
                        "only UID 705 (_enclavezk) or root may queue rollups (caller: {})",
                        peer.uid
                    );
                }
                if frame.len() > enclave_zk_auditor::rollup::MAX_FRAME_BYTES { fail!(E2BIG, "ROLLUP_FRAME_TOO_LARGE"); }
                if st.profile == Profile::L3 && frame.len() != L3_FRAME {
                    fail!(
                        EACCES,
                        "L3_FRAME_NOT_PADDED",
                        "{} != {L3_FRAME}",
                        frame.len()
                    );
                }
                let gw = st
                    .ohttp_gateway
                    .as_ref()
                    .ok_or_else(|| err!(EPERM, "OHTTP_GATEWAY_UNCONFIGURED"))?;
                let tuf = st.tuf.as_ref().ok_or_else(|| err!(EPERM, "TUF_NOT_BOOTSTRAPPED"))?;
                crate::rollup_relay::verify_for_relay(&frame, st.profile, st.store.root(), tuf, now)?;
                let enc = enclave_crypto::ohttp::encapsulate_for_profile(
                    gw,
                    &bhttp_post(LEDGER_AUTHORITY, LEDGER_PATH, "application/cbor", &frame),
                    st.profile,
                )?;
                crate::outbox::enqueue_rollup(&st.outbox, &enc)?;
                (
                    CasResponse::Queued,
                    Some(json!({"event": "ROLLUP_QUEUED", "bytes": enc.len()})),
                )
            }
            CasRequest::Wipe => {
                Self::wipe_peer(peer)?;
                st.ohttp_gateway = None;
                st.sessions.clear();
                st.store.retry_staging_cleanup()?;
                self.revoke_all_snapshots(st)?;
                Self::apply_revocations(st,seq)?;
                (
                    CasResponse::Wiped,
                    Some(json!({"event": "FETCH_KEYS_WIPED"})),
                )
            }
            CasRequest::Hydrate { cas_uri } => {
                let tuf = st
                    .tuf
                    .as_ref()
                    .ok_or_else(|| err!(EPERM, "TUF_NOT_BOOTSTRAPPED"))?;
                let uri = CasUri::parse(&cas_uri)?;
                let (meta, pol) = lookup(tuf, &uri, now)?;
                Self::offline_gate(st, now, Some(pol.classification))?;
                let required_floor = pol.min_profile.max(pol.classification.floor()).max(uri.min_profile.unwrap_or(Profile::L1));
                for companion in pol.companion_safety_layers.iter().filter(|c| c.eager_hydrate_required) {
                    let metadata = tuf.targets().and_then(|targets| targets.values().find(|tf| tf.hashes.get("blake3") == Some(&companion.blake3)))
                        .ok_or_else(|| err!(EACCES, "COMPANION_NOT_SIGNED"))?;
                    Self::artifact_authority(st, metadata, now)?;
                }
                if required_floor > st.profile {
                    fail!(
                        EPERM,
                        "PROFILE_FLOOR_EXCEEDED",
                        "artifact required floor {required_floor:?} exceeds host profile {:?}",
                        st.profile
                    );
                }

                if !st.store.contains(&uri.root) {
                    // The public dispatcher may fetch missing L1 objects.
                    // This cached acknowledgement never fabricates success.
                    fail!(EIO, "HYDRATION_TRANSPORT_UNAVAILABLE", "{:?}", st.profile);
                }
                Self::reserve_resolution(st, Some(&uri.root), &pol)?;
                let mut resolved = resolve(&st.store, tuf, &cas_uri, st.profile, now)?;
                let (leases,sealed)=self.guard_closure(st,meta,&pol,now)?;
                if let Some(files)=sealed {resolved.fds=files;}
                // Verify the actual materialized object too: manifest presence
                // alone cannot establish that a cached artifact is usable.
                // Hash with fixed scratch space rather than loading a model.
                use sha2::Digest;
                use std::io::Read;
                let mut file = &resolved.fds[0];
                let mut reader = file.by_ref().take(meta.length.saturating_add(1));
                let mut sha = sha2::Sha256::new();
                let mut b3 = blake3::Hasher::new();
                let mut length = 0u64;
                let mut buffer = [0u8; 64 * 1024];
                loop {
                    let n = reader
                        .read(&mut buffer)
                        .map_err(|e| err!(EIO, "HYDRATION_CACHE_READ", "{e}"))?;
                    if n == 0 {
                        break;
                    }
                    length += n as u64;
                    sha.update(&buffer[..n]);
                    b3.update(&buffer[..n]);
                }
                if length != meta.length
                    || blake3::Hasher::finalize(&b3).to_hex().as_str() != uri.root
                    || meta.hashes.get("sha256") != Some(&hex::encode(sha.finalize()))
                {
                    fail!(EACCES, "HYDRATION_CACHE_MISMATCH");
                }
                self.revalidate_leases(&leases)?;release_leases.extend(leases.clone());
                (
                    CasResponse::Admitted {
                        root: uri.root.clone(),
                    },
                    Some(
                        json!({"event": "HYDRATED", "cas_uri": cas_uri, "profile": format!("{:?}", st.profile)}),
                    ),
                )
            }
        };
        if let Some(generation)=access{st.cancellation.validate(generation)?;}
        if let (Some(j), Some(mut e)) = (st.journal.as_mut(), ev) {
            if let Some(generation)=access {
                // Durable preparation is not an externally released success.
                // fsync must never hold the release mutex. The actual response
                // and SCM_RIGHTS are committed together under the IPC permit.
                e["operation"]=e["event"].clone();
                e["event"]=json!("RELEASE_PREPARED");
                e["generation"]=json!(generation);
            }
            j.append(seq, e)?;
        }
        let _release=if access.is_some(){Some(st.cancellation.release.lock().map_err(|_|err!(EIO,"RELEASE_LOCK"))?)}else{None};
        if let Some(generation)=access {
            st.cancellation.validate(generation)?;
            let cancellation=st.cancellation.clone();
            let expires=release_leases.iter().map(|l|l.expires_unix).min();
            let metadata_expires=st.tuf.as_ref().map(TufClient::fresh_until).transpose()?;
            let provider=self.namespace_custody.lock().map_err(|_|err!(EIO,"NAMESPACE_CUSTODY_POISONED"))?.clone();
            let local_provider=provider.clone();let local_leases=release_leases.clone();
            let wall=st.wall;
            let permit=enclave_core::ipc::ReleasePermit::new(cancellation.release.clone(),Arc::new(move || {
                cancellation.validate(generation)?;
                let duration=release_started.elapsed();
                let elapsed=i64::try_from(duration.as_secs().saturating_add(u64::from(duration.subsec_nanos()!=0))).unwrap_or(i64::MAX);
                let current=(wall)().max(now.saturating_add(elapsed));
                if metadata_expires.is_some_and(|expiry|current>=expiry) {fail!(ESTALE,"TUF_EXPIRED");}
                if expires.is_some_and(|expiry|current>=expiry) {fail!(EACCES,"NAMESPACE_LEASE_EXPIRED");}
                if !local_leases.is_empty() {let provider=local_provider.as_ref().ok_or_else(||err!(EACCES,"NAMESPACE_CUSTODY_UNAVAILABLE"))?;for lease in &local_leases {provider.validate_local_release(lease)?;}}
                Ok(())
            })).with_preflight(Arc::new(move || {
                if !release_leases.is_empty() {
                    let provider=provider.as_ref().ok_or_else(||err!(EACCES,"NAMESPACE_CUSTODY_UNAVAILABLE"))?;
                    for lease in &release_leases {provider.revalidate_for_release(lease)?;}
                }
                Ok(())
            }));
            enclave_core::ipc::attach_release_permit(permit);
        }
        if wipe{st.cancellation.finish();}
        Ok(resp)
        })();
        // Include every fallible post-match step, especially journal append.
        // During unwinding the unfinished outer guard records unknown instead.
        if let Some(stage)=tuf_stage{stage.finish(result.is_ok());}
        result
    }
}

#[cfg(test)]
mod sync_diagnostics_service_tests {
    use super::*;
    use crate::sync_diagnostics::{CounterAvailability,StageCounters,StageRecords,SyncDiagnosticsSnapshot};
    use std::collections::BTreeMap;
    use std::os::unix::fs::DirBuilderExt;
    const NOW:i64=1_793_884_860;
    const EXP:&str="2030-01-01T00:00:00Z";
    fn wall()->i64 {NOW}
    struct Fixture {base:PathBuf,service:Arc<CasService>,peer:PeerCredentials,repo:enclave_crypto::tuf::RepoBuilder}
    impl Fixture {
        fn new(profile:Profile,root:bool)->Self {
            let base=PathBuf::from("/tmp").join(format!("mc-sync-diag-{}",hex::encode(&enclave_core::rng::bytes32()[..10])));
            std::fs::DirBuilder::new().mode(0o700).create(&base).unwrap();
            let repo=enclave_crypto::tuf::RepoBuilder::new(3,2);
            let service=CasService::start_with_wall_clock(CasConfig {dev_same_uid:true,profile,store_dir:base.join("store"),
                audit_path:Some(base.join("audit.jsonl")),tuf_root:root.then(||repo.root(EXP).unwrap()),
                ohttp_gateway:None,state_dir:None,revocation:Enforcement::Unavailable},wall).unwrap();
            Self {base,service,peer:PeerCredentials::local(enclave_core::ipc::geteuid(),0),repo}
        }
        fn request(&self,version:u64,expiry:&str)->CasRequest {
            let targets=self.repo.targets(version,EXP,BTreeMap::new()).unwrap();
            let snapshot=self.repo.snapshot(version,EXP,version,&targets).unwrap();
            let timestamp=self.repo.timestamp(version,expiry,version,&snapshot).unwrap();
            CasRequest::TufRefresh {roots:vec![],timestamp:timestamp.into(),snapshot:snapshot.into(),targets:targets.into()}
        }
        fn snapshot(&self)->SyncDiagnosticsSnapshot {
            let CasResponse::SyncDiagnostics(snapshot)=self.service.handle(&self.peer,CasRequest::SyncDiagnostics).unwrap() else {panic!("typed snapshot");};
            assert!(snapshot.valid_measurement());snapshot
        }
        fn tuf(&self)->StageCounters {let snapshot=self.snapshot();assert_eq!(snapshot.availability,CounterAvailability::Current);snapshot.stages.unwrap().tuf_refresh}
    }
    impl Drop for Fixture {fn drop(&mut self){let _=std::fs::remove_dir_all(&self.base);}}

    #[test]
    fn sync_diagnostics_real_tuf_valid_nochange_bad_signature_rollback_expiry_and_dryrun_reconcile() {
        let f=Fixture::new(Profile::L1,true);let valid=f.request(1,EXP);
        f.service.validate_initial_tuf_refresh(&valid).unwrap();assert_eq!(f.tuf(),StageCounters::default());
        f.service.handle(&f.peer,valid.clone()).unwrap();f.service.handle(&f.peer,valid.clone()).unwrap();
        assert_eq!(f.tuf(),StageCounters {started:2,returned_ok:2,..StageCounters::default()});
        let CasRequest::TufRefresh {roots,mut timestamp,snapshot,targets}=valid else {unreachable!()};
        // Keep signed JSON structurally valid but replace its signature bytes.
        // Timestamp has no parent metadata hash that could mask this failure.
        let mut value:serde_json::Value=serde_json::from_slice(&timestamp).unwrap();
        value["signatures"][0]["sig"]=json!("0".repeat(128));value["signatures"][1]["sig"]=json!("0".repeat(128));
        timestamp=serde_json::to_vec(&value).unwrap().into();
        assert!(f.service.handle(&f.peer,CasRequest::TufRefresh {roots,timestamp,snapshot,targets}).unwrap_err().is("TUF_THRESHOLD_NOT_MET"));
        assert!(f.service.handle(&f.peer,f.request(0,EXP)).unwrap_err().is("TUF_ROLLBACK"));
        assert!(f.service.handle(&f.peer,f.request(2,"2020-01-01T00:00:00Z")).unwrap_err().is("TUF_METADATA_EXPIRED"));
        assert_eq!(f.tuf(),StageCounters {started:5,returned_ok:2,returned_err:3,..StageCounters::default()});
        let empty=Fixture::new(Profile::L1,false);
        assert!(empty.service.handle(&empty.peer,f.request(1,EXP)).unwrap_err().is("TUF_NOT_BOOTSTRAPPED"));
        assert_eq!(empty.tuf(),StageCounters {started:1,returned_err:1,..StageCounters::default()});
    }

    #[test]
    fn sync_diagnostics_real_tuf_post_adoption_journal_and_state_write_errors_stay_errors() {
        for durability in [false,true] {
            let f=Fixture::new(Profile::L1,true);f.service.handle(&f.peer,f.request(1,EXP)).unwrap();
            if durability {
                let path=f.base.join("owned-trust");let (store,_)=SealedStore::open(&path,"diagnostic-fixture").unwrap();
                f.service.state.lock().unwrap().trust_store=Some(store);
                // An owned directory at the final sealed-file name makes the
                // real durable rename refuse after metadata adoption.
                std::fs::create_dir(path.join("diagnostic-fixture.sealed")).unwrap();
            } else {
                std::fs::rename(f.base.join("audit.jsonl"),f.base.join("saved-audit")).unwrap();
                std::fs::create_dir(f.base.join("audit.jsonl")).unwrap();
            }
            let error=f.service.handle(&f.peer,f.request(2,EXP)).unwrap_err();
            assert!(error.is(if durability {"STATE_RENAME"}else{"AUDIT_OPEN"}),"{error}");
            assert_eq!(f.service.state.lock().unwrap().tuf.as_ref().unwrap().versions(),(2,2,2),"must reach post-adoption failure");
            assert_eq!(f.tuf(),StageCounters {started:2,returned_ok:1,returned_err:1,..StageCounters::default()});
        }
    }

    #[test]
    fn sync_diagnostics_real_tuf_post_adoption_revocation_refusal_is_not_a_success() {
        let f=Fixture::new(Profile::L1,true);f.service.handle(&f.peer,f.request(1,EXP)).unwrap();
        let bytes=b"DATA owned revocation diagnostic fixture";
        let target=enclave_crypto::tuf::target_file(bytes,Some(json!({"revoked":true})));
        // Owned local CAS preparation is an explicit fixture, not a claimed
        // authenticated download or payload delivery. Materialize its inode so
        // the real Unavailable revocation enforcer must refuse after adoption.
        {let state=f.service.state.lock().unwrap();let manifest=state.store.put(bytes).unwrap();drop(state.store.open_readonly(&manifest.blake3).unwrap());}
        let mut targets=BTreeMap::new();targets.insert("fixture.bin".into(),target);
        let targets=f.repo.targets(2,EXP,targets).unwrap();let snapshot=f.repo.snapshot(2,EXP,2,&targets).unwrap();
        let timestamp=f.repo.timestamp(2,EXP,2,&snapshot).unwrap();
        let error=f.service.handle(&f.peer,CasRequest::TufRefresh {roots:vec![],timestamp:timestamp.into(),snapshot:snapshot.into(),targets:targets.into()}).unwrap_err();
        assert!(error.is("REVOCATION_UNENFORCED"),"{error}");
        assert_eq!(f.service.state.lock().unwrap().tuf.as_ref().unwrap().versions(),(2,2,2));
        assert_eq!(f.tuf(),StageCounters {started:2,returned_ok:1,returned_err:1,..StageCounters::default()});
    }

    #[test]
    fn sync_diagnostics_common_or_peer_refusals_do_not_start_tuf_and_reads_do_not_advance_state() {
        let f=Fixture::new(Profile::L1,true);
        // Establish actual journal bytes before checking read-only exports.
        f.service.handle(&f.peer,f.request(1,EXP)).unwrap();let before=f.snapshot();
        let foreign=PeerCredentials::local(if f.peer.uid==70_000 {70_001}else{70_000},0);
        assert!(f.service.handle(&foreign,f.request(1,EXP)).unwrap_err().is("TUF_REFRESH_PEER_REJECTED"));
        assert_eq!(f.snapshot(),before);
        let mut state=f.service.state.lock().unwrap();let epoch=state.seq.boot_epoch_id().to_owned();
        state.seq=RpcSequencer::new(epoch,u64::MAX);let seq=state.seq.current();
        let audit=std::fs::read(f.base.join("audit.jsonl")).unwrap();let reserved=state.sessions.staging_reserved().unwrap();
        // Holding State proves this direct early export cannot acquire it.
        for _ in 0..3 {assert_eq!(f.snapshot(),before);}
        assert_eq!(state.seq.current(),seq);assert_eq!(state.sessions.staging_reserved().unwrap(),reserved);
        assert_eq!(std::fs::read(f.base.join("audit.jsonl")).unwrap(),audit);drop(state);
        assert!(f.service.handle(&f.peer,f.request(1,EXP)).unwrap_err().is("RPC_SEQ_EXHAUSTED"));
        assert_eq!(f.snapshot(),before);
    }

    #[derive(Debug)]
    struct NoBackend;
    impl crate::snapshot_publication::SnapshotPublisher for NoBackend {
        fn publish(&self,_:&std::fs::File,_:&enclave_crypto::tuf::TargetFile)->EnclaveResult<std::fs::File>{panic!("diagnostics reached publisher")}
        fn reopen(&self,_:&enclave_crypto::tuf::TargetFile)->EnclaveResult<std::fs::File>{panic!("diagnostics reached unseal/broker reopen")}
        fn revoke(&self,_:&enclave_crypto::tuf::TargetFile)->EnclaveResult<()>{panic!("diagnostics reached broker revoke")}
        fn prepare_staging(&self,_:&enclave_crypto::tuf::TargetFile)->EnclaveResult<()>{panic!("diagnostics reached network staging")}
    }
    impl crate::transport::custody::NamespaceCustody for NoBackend {
        fn unwrap(&self,_:&enclave_crypto::namespace::WrappedNamespaceKey)->EnclaveResult<crate::transport::custody::NamespaceRelease>{panic!("diagnostics reached custody unwrap")}
        fn revalidate(&self,_:&enclave_crypto::namespace::CasKeyLease)->EnclaveResult<()>{panic!("diagnostics reached custody revalidation")}
    }

    #[test]
    fn sync_diagnostics_initialized_l3_export_ignores_backend_and_state_poison_preserves_startup_gate() {
        // Direct owned L3 fixture, not production startup/broker readiness.
        let f=Fixture::new(Profile::L3,false);
        f.service.set_snapshot_publisher(Arc::new(NoBackend)).unwrap();f.service.set_namespace_custody(Arc::new(NoBackend)).unwrap();
        let before=f.snapshot();assert_eq!(before.stages,Some(StageRecords::default()));
        f.service.enable_host_profile_floor(Profile::L3).unwrap();
        let service=f.service.clone();let poisoned=std::thread::spawn(move||{let _state=service.state.lock().unwrap();panic!("owned State poison proves no State read");});assert!(poisoned.join().is_err());
        for _ in 0..3 {assert_eq!(f.snapshot(),before);}
        let foreign=PeerCredentials::local(if f.peer.uid==70_000 {70_001}else{70_000},0);
        assert!(f.service.handle(&foreign,CasRequest::SyncDiagnostics).unwrap_err().is("SYNC_DIAGNOSTICS_PEER_REJECTED"));
        assert_eq!(f.snapshot(),before);
    }

    #[test]
    fn sync_diagnostics_measurement_poison_never_changes_real_tuf_return_or_authorization() {
        let f=Fixture::new(Profile::L1,true);f.service.diagnostics.poison_for_test();
        assert!(matches!(f.service.handle(&f.peer,f.request(1,EXP)).unwrap(),CasResponse::Tuf {..}));
        let snapshot=f.snapshot();assert_eq!(snapshot.availability,CounterAvailability::Unavailable);
        assert!(snapshot.measurement_fault.poisoned&&snapshot.stages.is_none());
        assert!(f.service.handle(&f.peer,f.request(0,EXP)).is_err());assert_eq!(f.snapshot(),snapshot);
    }
    include!("outbox_diagnostics_service_tests.rs");
}

#[cfg(test)]
mod download_race_tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::os::unix::fs::DirBuilderExt;
    use enclave_crypto::tuf::{RepoBuilder, TargetFile, target_file};
    use crate::transport::registry::{DistributionConfig, RegistryConfig, DISTRIBUTION_CONFIG_TARGET};

    const NOW: i64 = 1_793_884_860;
    const EXP: &str = "2030-01-01T00:00:00Z";
    const MAIN: &[u8] = b"DATA private deterministic plan race";
    const COMPANION: &[u8] = b"{\"private\":true}";
    fn wall() -> i64 { NOW }
    fn policy() -> serde_json::Value {
        json!({"classification":"public_l1","min_profile":"L1","license_policy":{"spdx_id":"LicenseRef-fixture","allow_p2p_seeding":false}})
    }
    struct Fixture {
        base: PathBuf, svc: Arc<CasService>, peer: PeerCredentials,
        repo: RepoBuilder, targets: BTreeMap<String, TargetFile>,
    }
    impl Fixture {
        fn new() -> Self {
            let base=std::env::temp_dir().join(format!("mc-f38-plan-{}",hex::encode(&enclave_core::rng::bytes32()[..12])));
            std::fs::DirBuilder::new().mode(0o700).create(&base).unwrap();
            let repo=RepoBuilder::new(3,2);
            let svc=CasService::start_with_wall_clock(CasConfig {dev_same_uid: true, profile:Profile::L1,store_dir:base.join("store"),audit_path:Some(base.join("audit.jsonl")),tuf_root:Some(repo.root(EXP).unwrap()),ohttp_gateway:None,state_dir:None,revocation:Enforcement::InProcess},wall).unwrap();
            let ca=rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
            // A numeric closed endpoint makes any accidental attempt fail;
            // DOWNLOAD_WIPED must precede socket/session creation entirely.
            let config=DistributionConfig {version:1,l2:None,l3:None,l1:Some(RegistryConfig {address:"127.0.0.1:1".into(),server_name:"localhost".into(),repository:"private/race".into(),tls_roots_der:vec![hex::encode(ca.serialize_der().unwrap())],timeout_ms:100})};
            let config=serde_json::to_vec(&config).unwrap();
            std::fs::write(base.join("store").join(DISTRIBUTION_CONFIG_TARGET),&config).unwrap();
            let mut main=policy();main["companion_safety_layers"]=json!([{"role":"fixture","blake3":blake3::hash(COMPANION).to_hex().as_str(),"eager_hydrate_required":true}]);
            let targets=BTreeMap::from([
                ("model.bin".into(),target_file(MAIN,Some(main))),
                ("companion.json".into(),target_file(COMPANION,Some(policy()))),
                (DISTRIBUTION_CONFIG_TARGET.into(),target_file(&config,Some(json!({})))),
            ]);
            let mut peer=PeerCredentials::local(enclave_core::ipc::geteuid(),0);peer.pid=Some(std::process::id() as i32);
            let f=Self {base,svc,peer,repo,targets};f.refresh(1,f.targets.clone());f
        }
        fn refresh(&self,version:u64,targets:BTreeMap<String,TargetFile>) {
            let targets=self.repo.targets(version,EXP,targets).unwrap();
            let snapshot=self.repo.snapshot(version,EXP,version,&targets).unwrap();
            let timestamp=self.repo.timestamp(version,EXP,version,&snapshot).unwrap();
            self.svc.handle(&self.peer,CasRequest::TufRefresh {roots:vec![],timestamp:timestamp.into(),snapshot:snapshot.into(),targets:targets.into()}).unwrap();
        }
        fn uri(&self)->String {format!("cas://blake3-bao-v1/{}?target=model.bin&ns=models",blake3::hash(MAIN).to_hex())}
        fn admit(&self,target:&str,bytes:&[u8]) {
            self.svc.handle(&self.peer,CasRequest::Admit {target:target.into(),bytes:bytes.to_vec().into()}).unwrap();
        }
        fn no_receipt_or_stages(&self) {
            assert!(!std::fs::read_to_string(self.base.join("audit.jsonl")).unwrap().contains("\"event\":\"HYDRATED\""));
            assert!(std::fs::read_dir(self.base.join("store/streaming-stages")).unwrap().all(|e|!e.unwrap().file_name().to_string_lossy().starts_with("stage-")));
        }
    }
    impl Drop for Fixture {fn drop(&mut self) {let _=std::fs::remove_dir_all(&self.base);}}

    struct TestIpc {
        socket: PathBuf,
        stop: Arc<std::sync::atomic::AtomicBool>,
        thread: Option<std::thread::JoinHandle<EnclaveResult<()>>>,
    }
    impl TestIpc {
        fn start(f: &Fixture, gate: Option<(std::sync::mpsc::Sender<()>, std::sync::mpsc::Receiver<()>)>) -> Self {
            use enclave_core::ipc::{self, PeerPolicy, SocketAccess};
            let socket = f.base.join("cas.sock");
            let listener = ipc::bind(&socket, SocketAccess::OwnerOnly).unwrap();
            let service = f.svc.clone();
            let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let stopped = stop.clone();
            let gate = Mutex::new(gate);
            let thread = std::thread::spawn(move || ipc::serve(listener, PeerPolicy::allow([ipc::geteuid()]), Arc::new(move |peer: &PeerCredentials, request| {
                let result = service.handle(peer, request);
                if let Some((prepared, continuation)) = gate.lock().unwrap().take() {
                    assert!(result.is_ok(), "{result:?}");
                    prepared.send(()).unwrap();
                    continuation.recv_timeout(std::time::Duration::from_secs(5)).unwrap();
                }
                result
            }), stopped));
            Self { socket, stop, thread: Some(thread) }
        }
        fn client(&self) -> enclave_core::ipc::Client {
            let mut client = enclave_core::ipc::Client::connect(&self.socket, enclave_core::ipc::geteuid()).unwrap();
            client.set_timeout(Some(std::time::Duration::from_secs(5))).unwrap();
            client
        }
    }
    impl Drop for TestIpc {
        fn drop(&mut self) {
            self.stop.store(true, std::sync::atomic::Ordering::SeqCst);
            if let Some(thread) = self.thread.take() { let _ = thread.join(); }
        }
    }

    #[derive(Debug)]
    struct ReleaseCustody {
        denied_epoch: std::sync::atomic::AtomicU64,
        preflight: Mutex<Vec<u64>>,
        release_gate: Mutex<Option<(u64, std::sync::mpsc::Sender<()>, std::sync::mpsc::Receiver<()>)>>,
    }
    impl crate::transport::custody::NamespaceCustody for ReleaseCustody {
        fn unwrap(&self, key: &enclave_crypto::namespace::WrappedNamespaceKey) -> EnclaveResult<crate::transport::custody::NamespaceRelease> {
            Ok(crate::transport::custody::NamespaceRelease {
                key: enclave_core::secret::SecretKey32::new([7; 32]),
                lease: enclave_crypto::namespace::CasKeyLease {
                    enterprise:None,
                    id: format!("release-fixture-{}", key.epoch), namespace: key.namespace.clone(), key_epoch: key.epoch,
                    boot_epoch: "fixture".into(), generation: 1, expires_unix: NOW + 60,
                },
            })
        }
        fn revalidate(&self, lease: &enclave_crypto::namespace::CasKeyLease) -> EnclaveResult<()> {
            if self.denied_epoch.load(std::sync::atomic::Ordering::SeqCst) == lease.key_epoch { fail!(EACCES, "FIXTURE_LEASE_REVOKED"); }
            Ok(())
        }
        fn revalidate_for_release(&self, lease: &enclave_crypto::namespace::CasKeyLease) -> EnclaveResult<()> {
            self.preflight.lock().unwrap().push(lease.key_epoch);
            let gate = {
                let mut gate = self.release_gate.lock().unwrap();
                if gate.as_ref().is_some_and(|g| g.0 == lease.key_epoch) { gate.take() } else { None }
            };
            if let Some((_, prepared, continuation)) = gate {
                prepared.send(()).unwrap();
                continuation.recv_timeout(std::time::Duration::from_secs(5)).unwrap();
            }
            self.revalidate(lease)
        }
    }
    impl Fixture {
        // Valid encrypted metadata for already cached bytes. This fixture tests
        // the common protected release boundary, not a network/hardware claim.
        fn protect_cached(&mut self) -> Arc<ReleaseCustody> {
            use crate::transport::{oblivious::EncryptedTarget, quic::L2QuicConfig};
            use enclave_crypto::namespace;
            let key = enclave_core::secret::SecretKey32::new([7; 32]);
            for (name, bytes, epoch) in [("model.bin", MAIN, 1), ("companion.json", COMPANION, 2)] {
                let root = *blake3::hash(bytes).as_bytes();
                let (ciphertext, records) = namespace::encrypt_chunk(&key, &root, 0, true, bytes).unwrap();
                let descriptor = EncryptedTarget {
                    version: 1, ciphertext_bao_root: crate::bao::bao_root(&ciphertext), ciphertext_length: ciphertext.len() as u64,
                    key_index_bao_root: crate::bao::bao_root(&records), key_index_length: records.len() as u64,
                    key: namespace::wrap("models", epoch, 1, key.expose(), &key).unwrap(),
                };
                let custom = self.targets.get_mut(name).unwrap().custom.as_mut().unwrap();
                custom["encrypted_transport"] = serde_json::to_value(descriptor).unwrap();
                custom["jurisdiction_shard"] = json!("EU");
            }
            let registry = RegistryConfig { address: "127.0.0.1:1".into(), server_name: "localhost".into(), repository: "private/race".into(),
                tls_roots_der: vec![hex::encode(rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap().serialize_der().unwrap())], timeout_ms: 100 };
            let path = self.base.canonicalize().unwrap();
            let config = serde_json::to_vec(&DistributionConfig { version: 1, l1: None, l3: None, l2: Some(L2QuicConfig {
                peer: registry.clone(), issuer: registry, client_certificate_der_path: path.join("cert.der").display().to_string(),
                client_key_seed_path: path.join("key").display().to_string(), peer_ed25519_hex: "11".repeat(32), issuer_public_key_hex: "22".repeat(32),
                policy_blake3: "33".repeat(32), shard: "EU".into(), poison_state_dir: path.display().to_string(), seed: None, total_timeout_ms: 100,enterprise_authority:None,
            }) }).unwrap();
            std::fs::write(self.base.join("store").join(DISTRIBUTION_CONFIG_TARGET), &config).unwrap();
            self.targets.insert(DISTRIBUTION_CONFIG_TARGET.into(), target_file(&config, Some(json!({}))));
            self.refresh(2, self.targets.clone());
            self.svc.state.lock().unwrap().profile = Profile::L2;
            let custody = Arc::new(ReleaseCustody { denied_epoch: 0.into(), preflight: Mutex::new(Vec::new()), release_gate: Mutex::new(None) });
            self.svc.set_namespace_custody(custody.clone()).unwrap();
            custody
        }
    }

    #[test]
    fn phase1_actual_service_protected_main_and_companion_lease_cuts() {
        use std::sync::atomic::{AtomicI64, Ordering};
        use std::io::{Read, Write};
        static CLOCK: AtomicI64 = AtomicI64::new(NOW);
        fn release_wall() -> i64 { CLOCK.load(Ordering::SeqCst) }
        // Resolve, OpenTarget, Fetch and cached Hydrate share this boundary.
        // Revoke main, revoke companion, and expire exactly at the lease limit.
        for (route, cut) in (0..4).flat_map(|r| (1..=3).map(move |c| (r, c))) {
            CLOCK.store(NOW, Ordering::SeqCst);
            let mut f = Fixture::new(); f.admit("companion.json", COMPANION); f.admit("model.bin", MAIN);
            let custody = f.protect_cached(); f.svc.state.lock().unwrap().wall = release_wall;
            let request = match route {
                0 => CasRequest::Resolve { cas_uri: f.uri() }, 1 => CasRequest::OpenTarget { target: "model.bin".into() },
                2 => CasRequest::Fetch { cas_uri: f.uri() }, _ => CasRequest::Hydrate { cas_uri: f.uri() },
            };
            let (prepared_tx, prepared_rx) = std::sync::mpsc::channel();
            let (continue_tx, continue_rx) = std::sync::mpsc::channel();
            let server = TestIpc::start(&f, Some((prepared_tx, continue_rx)));
            let mut queued = server.client(); let sent = request.clone();
            let caller = std::thread::spawn(move || queued.call::<_, CasResponse>(&sent));
            prepared_rx.recv_timeout(std::time::Duration::from_secs(5)).unwrap();
            if cut == 3 { CLOCK.store(NOW + 60, Ordering::SeqCst); }
            else { custody.denied_epoch.store(cut, Ordering::SeqCst); }
            continue_tx.send(()).unwrap();
            assert!(caller.join().unwrap().is_err(), "protected route={route} cut={cut} escaped");
            if cut != 3 { assert_eq!(*custody.preflight.lock().unwrap(), if cut == 1 {vec![1]} else {vec![1, 2]}); }
            custody.denied_epoch.store(0, Ordering::SeqCst); CLOCK.store(NOW, Ordering::SeqCst);
            let mut retry = server.client(); let response: CasResponse = retry.call(&request).unwrap();
            match route {
                0 | 1 => {
                    assert!(matches!(response, CasResponse::Resolved {..} | CasResponse::TargetFile {..}));
                    let files = retry.recv_fds(if route == 0 {2} else {1}).unwrap();
                    assert_eq!(files.len(), if route == 0 {2} else {1});
                    let mut main = std::fs::File::from(files.into_iter().next().unwrap());
                    let mut bytes = Vec::new(); main.read_to_end(&mut bytes).unwrap(); assert_eq!(bytes, MAIN);
                    assert!(main.write_all(b"denied").is_err());
                },
                2 => assert!(matches!(response, CasResponse::Bytes(bytes) if bytes.as_slice() == MAIN)),
                _ => assert!(matches!(response, CasResponse::Admitted {..})),
            }
            assert!(matches!(retry.call::<_, CasResponse>(&CasRequest::Status).unwrap(), CasResponse::Status(_)));
            assert_eq!(f.svc.state.lock().unwrap().store.staging().reserved().unwrap(), 0);
            drop(retry); drop(server);
        }
    }

    #[test]
    fn phase1_actual_service_rechecks_after_custody_preflight_without_blocking_wipe_or_status() {
        use std::sync::atomic::{AtomicI64, Ordering};
        static CLOCK: AtomicI64 = AtomicI64::new(NOW);
        fn release_wall() -> i64 { CLOCK.load(Ordering::SeqCst) }
        for (route, cut) in (0..4).flat_map(|r| (1..=5).map(move |c| (r, c))) {
            CLOCK.store(NOW, Ordering::SeqCst);
            let mut f = Fixture::new(); f.admit("companion.json", COMPANION); f.admit("model.bin", MAIN);
            let custody = f.protect_cached(); f.svc.state.lock().unwrap().wall = release_wall;
            let (prepared_tx, prepared_rx) = std::sync::mpsc::channel();
            let (continue_tx, continue_rx) = std::sync::mpsc::channel();
            *custody.release_gate.lock().unwrap() = Some((if cut == 1 {1} else {2}, prepared_tx, continue_rx));
            let request = match route {
                0 => CasRequest::Resolve { cas_uri: f.uri() }, 1 => CasRequest::OpenTarget { target: "model.bin".into() },
                2 => CasRequest::Fetch { cas_uri: f.uri() }, _ => CasRequest::Hydrate { cas_uri: f.uri() },
            };
            let server = TestIpc::start(&f, None); let mut queued = server.client(); let sent = request.clone();
            let caller = std::thread::spawn(move || queued.call::<_, CasResponse>(&sent));
            prepared_rx.recv_timeout(std::time::Duration::from_secs(5)).unwrap();
            let mut status = server.client();
            assert!(matches!(status.call::<_, CasResponse>(&CasRequest::Status).unwrap(), CasResponse::Status(_)));
            // Remote observation holds neither State nor the release mutex.
            assert!(f.svc.cancellation.release.try_lock().is_ok());
            match cut {
                1 | 2 => custody.denied_epoch.store(cut, Ordering::SeqCst),
                3 => CLOCK.store(NOW + 60, Ordering::SeqCst),
                4 => assert!(matches!(f.svc.handle(&f.peer, CasRequest::Wipe).unwrap(), CasResponse::Wiped)),
                _ => f.refresh(3, f.targets.clone()),
            }
            continue_tx.send(()).unwrap();
            assert!(caller.join().unwrap().is_err(), "preflight route={route} cut={cut} escaped");
            custody.denied_epoch.store(0, Ordering::SeqCst); CLOCK.store(NOW, Ordering::SeqCst);
            let mut retry = server.client(); assert!(retry.call::<_, CasResponse>(&request).is_ok());
            if route < 2 { assert_eq!(retry.recv_fds(if route == 0 {2} else {1}).unwrap().len(), if route == 0 {2} else {1}); }
            assert!(matches!(retry.call::<_, CasResponse>(&CasRequest::Status).unwrap(), CasResponse::Status(_)));
            assert_eq!(f.svc.state.lock().unwrap().store.staging().reserved().unwrap(), 0);
            drop(retry); drop(status); drop(server);
        }
    }

    #[test]
    fn phase1_actual_service_journal_failure_blocks_reply_and_wipe_recovery_until_reopen() {
        use std::os::{unix::{ffi::OsStrExt, fs::OpenOptionsExt}, fd::AsRawFd};
        use std::io::Read;
        // Linux refuses fsync on a private FIFO after accepting the journal
        // line. Darwin accepts that sync, so its native fixture covers open
        // refusal only. Neither fixture establishes physical-media failure.
        for (route, fsync) in (0..4).flat_map(|r| [false, true].into_iter().filter(|s| !*s || cfg!(target_os = "linux")).map(move |s| (r, s))) {
            let mut f = Fixture::new(); f.admit("companion.json", COMPANION); f.admit("model.bin", MAIN);
            let _custody = f.protect_cached();
            let server = TestIpc::start(&f, None);
            let path = f.base.join("audit.jsonl"); let saved = f.base.join("saved-audit");
            let anchor = f.svc.state.lock().unwrap().journal.as_ref().unwrap().anchor();
            std::fs::rename(&path, &saved).unwrap();
            let mut sink = if fsync {
                let name = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
                assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
                Some(std::fs::OpenOptions::new().read(true).custom_flags(libc::O_NONBLOCK).open(&path).unwrap())
            } else { std::fs::create_dir(&path).unwrap(); None };
            let request = match route {
                0 => CasRequest::Resolve { cas_uri: f.uri() }, 1 => CasRequest::OpenTarget { target: "model.bin".into() },
                2 => CasRequest::Fetch { cas_uri: f.uri() }, _ => CasRequest::Hydrate { cas_uri: f.uri() },
            };
            let mut client = server.client();
            let error = client.call::<_, CasResponse>(&request).unwrap_err();
            assert!(error.is(if fsync {"AUDIT_FSYNC"} else {"AUDIT_OPEN"}), "route={route} fsync={fsync}: {error}");
            assert_eq!(f.svc.state.lock().unwrap().journal.as_ref().unwrap().anchor(), anchor);
            if let Some(reader) = sink.as_mut() {
                let mut bytes = Vec::new(); reader.read_to_end(&mut bytes).unwrap();
                assert!(bytes.ends_with(b"\n"));
                let line: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
                assert!(line.to_string().contains("RELEASE_PREPARED"));
                // The refusal is independently observable on that same sink.
                assert_eq!(unsafe { libc::fsync(reader.as_raw_fd()) }, -1);
            }
            // A following Status on the same connection proves no FD packet or
            // stale success from the failed handler leaked into this response.
            assert!(matches!(client.call::<_, CasResponse>(&CasRequest::Status).unwrap(), CasResponse::Status(_)));
            assert_eq!(f.svc.state.lock().unwrap().store.staging().reserved().unwrap(), 0);
            drop(sink);
            if fsync { std::fs::remove_file(&path).unwrap(); } else { std::fs::remove_dir(&path).unwrap(); }
            std::fs::rename(&saved, &path).unwrap();
            assert!(client.call::<_, CasResponse>(&request).unwrap_err().is("AUDIT_WRITE_UNCERTAIN"));
            assert!(client.call::<_, CasResponse>(&CasRequest::Wipe).unwrap_err().is("AUDIT_WRITE_UNCERTAIN"));
            assert!(client.call::<_, CasResponse>(&request).unwrap_err().is("DOWNLOAD_WIPED"));
            assert_eq!(enclave_core::audit::verify_journal(&path, Some(anchor)).unwrap().entries, anchor.entries);
            // Reopen verifies disk state; only a fully journaled Wipe clears
            // the failed-Wipe latch. Repairing a pathname alone cannot do it.
            {
                let mut st = f.svc.state.lock().unwrap();
                st.journal = Some(AuditJournal::open(&path, DaemonId::SwarmSync, st.seq.boot_epoch_id().into()).unwrap());
            }
            assert!(matches!(client.call::<_, CasResponse>(&CasRequest::Wipe).unwrap(), CasResponse::Wiped));
            let response = client.call::<_, CasResponse>(&request).unwrap();
            match route {
                0 | 1 => {
                    assert!(matches!(response, CasResponse::Resolved {..} | CasResponse::TargetFile {..}));
                    let files = client.recv_fds(if route == 0 {2} else {1}).unwrap();
                    let mut main = std::fs::File::from(files.into_iter().next().unwrap());
                    let mut bytes = Vec::new(); main.read_to_end(&mut bytes).unwrap(); assert_eq!(bytes, MAIN);
                },
                2 => assert!(matches!(response, CasResponse::Bytes(bytes) if bytes.as_slice() == MAIN)),
                _ => assert!(matches!(response, CasResponse::Admitted {..})),
            }
            assert!(matches!(client.call::<_, CasResponse>(&CasRequest::Status).unwrap(), CasResponse::Status(_)));
            drop(client); drop(server);
            enclave_core::audit::verify_journal(&path, None).unwrap();
        }
    }

    #[test]
    fn phase1_actual_service_ipc_queued_fd_reply_is_fenced_by_wipe_or_metadata_adoption() {
        use enclave_core::ipc::{self,Client,PeerPolicy,SocketAccess};
        use std::{io::{Read,Write},sync::atomic::{AtomicBool,AtomicI64,Ordering},time::Duration};
        static CLOCK:AtomicI64=AtomicI64::new(NOW);
        fn release_wall()->i64 {CLOCK.load(Ordering::SeqCst)}
        for (mode,export) in (0..3).flat_map(|mode|[false,true].map(move|export|(mode,export))) {
            let f=Fixture::new();f.admit("companion.json",COMPANION);f.admit("model.bin",MAIN);
            if mode==2 {CLOCK.store(NOW,Ordering::SeqCst);f.svc.state.lock().unwrap().wall=release_wall;}
            let socket=f.base.join("cas.sock");let listener=ipc::bind(&socket,SocketAccess::OwnerOnly).unwrap();
            let (prepared_tx,prepared_rx)=std::sync::mpsc::channel();let (continue_tx,continue_rx)=std::sync::mpsc::channel();
            let continuation=Mutex::new(continue_rx);let delayed=AtomicBool::new(false);let service=f.svc.clone();
            let stop=Arc::new(AtomicBool::new(false));let stopped=stop.clone();
            let server=std::thread::spawn(move||ipc::serve(listener,PeerPolicy::allow([ipc::geteuid()]),Arc::new(move|peer:&PeerCredentials,request:CasRequest| {
                let result=service.handle(peer,request);
                if !delayed.swap(true,Ordering::SeqCst) {assert!(result.is_ok());prepared_tx.send(()).unwrap();continuation.lock().unwrap().recv_timeout(Duration::from_secs(5)).unwrap();}
                result
            }),stopped));
            let queued_socket=socket.clone();let uri=f.uri();
            let queued=std::thread::spawn(move|| {let mut client=Client::connect(&queued_socket,ipc::geteuid()).unwrap();client.call::<_,CasResponse>(&if export{CasRequest::OpenTarget{target:"model.bin".into()}}else{CasRequest::Resolve{cas_uri:uri}})});
            prepared_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            if export {assert_eq!(f.svc.state.lock().unwrap().store.staging().reserved().unwrap(),MAIN.len() as u64);}
            match mode {0=>assert!(matches!(f.svc.handle(&f.peer,CasRequest::Wipe).unwrap(),CasResponse::Wiped)),1=>f.refresh(2,f.targets.clone()),_=>CLOCK.store(2_000_000_000,Ordering::SeqCst)}
            continue_tx.send(()).unwrap();assert!(queued.join().unwrap().is_err(),"queued success must never cross the fence");
            CLOCK.store(NOW,Ordering::SeqCst);
            if export {assert_eq!(f.svc.state.lock().unwrap().store.staging().reserved().unwrap(),0);}
            let mut client=Client::connect(&socket,ipc::geteuid()).unwrap();
            let response=client.call::<_,CasResponse>(&if export{CasRequest::OpenTarget{target:"model.bin".into()}}else{CasRequest::Resolve{cas_uri:f.uri()}}).unwrap();
            assert!(matches!(response,CasResponse::Resolved{..}|CasResponse::TargetFile{..}));
            let count=if export{1}else{2};let mut files=client.recv_fds(count).unwrap().into_iter().map(std::fs::File::from).collect::<Vec<_>>();assert_eq!(files.len(),count);
            let mut actual=Vec::new();files[0].read_to_end(&mut actual).unwrap();assert_eq!(actual,MAIN);
            assert!(files[0].write_all(b"denied").is_err());
            drop(client);stop.store(true,Ordering::SeqCst);server.join().unwrap().unwrap();
            let journal=std::fs::read_to_string(f.base.join("audit.jsonl")).unwrap();assert!(journal.contains("RELEASE_PREPARED"));assert!(!journal.contains("\"event\":\"RESOLVED\""));
        }
    }

    #[test]
    fn f38_download_reservation_aggregates_only_missing_canonical_copies() {
        let f=Fixture::new();f.admit("companion.json",COMPANION);f.admit("model.bin",MAIN);
        let root=blake3::hash(MAIN).to_hex().to_string();
        let companion=blake3::hash(COMPANION).to_hex().to_string();
        let st=f.svc.state.lock().unwrap();
        let policy:crate::governance::TargetPolicy=serde_json::from_value(f.targets["model.bin"].custom.clone().unwrap()).unwrap();
        assert!(st.store.object_inode(&root).is_none());assert!(st.store.object_inode(&companion).is_none());
        assert_eq!(CasService::canonical_bytes(&st,Some(&root),&policy).unwrap(),(MAIN.len()+COMPANION.len()) as u64);
        assert_eq!(CasService::canonical_bytes(&st,None,&policy).unwrap(),COMPANION.len() as u64);
        // Use valid bounded manifests and tiny actual copies. The streaming
        // reserve test separately checks denial against synthetic outstanding
        // stage obligations without invalid manifests or giant disk writes.
        CasService::reserve_resolution(&st,Some(&root),&policy).unwrap();
        drop(st.store.open_readonly(&root).unwrap());
        assert_eq!(CasService::canonical_bytes(&st,Some(&root),&policy).unwrap(),COMPANION.len() as u64);
        drop(st);f.no_receipt_or_stages();
    }

    #[test]
    fn f38_download_wipe_between_plan_and_first_or_next_session_and_final_receipt() {
        for cached in 0..3 {
            let f=Fixture::new();
            if cached>=1 {f.admit("companion.json",COMPANION);}
            if cached==2 {f.admit("model.bin",MAIN);}
            let plan=f.svc.prepare_download(&f.uri()).unwrap();
            assert_eq!(plan.missing.len(),2-cached);
            f.svc.handle(&f.peer,CasRequest::Wipe).unwrap();
            assert!(f.svc.execute_download(&f.peer,plan).unwrap_err().is("DOWNLOAD_WIPED"));
            f.no_receipt_or_stages();
            // Wipe cancels the old plan; a newly authorized operation can
            // start under the new generation without resetting any authority.
            let fresh=f.svc.prepare_download(&f.uri()).unwrap();
            let st=f.svc.state.lock().unwrap();
            CasService::download_authority(&st,&CasUri::parse(&f.uri()).unwrap(),&fresh,NOW).unwrap();
        }
    }

    #[test]
    fn f38_authorized_wipe_cancels_before_state_lock_and_refuses_receipt_or_handoff() {
        use std::sync::atomic::Ordering;
        use std::time::{Duration,Instant};
        let f=Fixture::new();f.admit("companion.json",COMPANION);f.admit("model.bin",MAIN);
        let plan=f.svc.prepare_download(&f.uri()).unwrap();assert!(plan.missing.is_empty());
        let mut state=f.svc.state.lock().unwrap();let original=state.cancellation.observe().unwrap();
        let foreign=enclave_core::ipc::PeerCredentials::local(if enclave_core::ipc::geteuid()==9999{9998}else{9999},0);
        let (foreign_tx,foreign_rx)=std::sync::mpsc::channel();let service=f.svc.clone();let foreign_worker=std::thread::spawn(move||{foreign_tx.send(service.handle(&foreign,CasRequest::Wipe)).unwrap();});
        assert!(foreign_rx.recv_timeout(Duration::from_secs(2)).unwrap().unwrap_err().is("WIPE_PEER_REJECTED"));foreign_worker.join().unwrap();
        assert_eq!(state.cancellation.observe().unwrap(),original,"unauthorized callers must not cancel");
        let (done_tx,done_rx)=std::sync::mpsc::channel();let service=f.svc.clone();let peer=f.peer.clone();
        let worker=std::thread::spawn(move||{done_tx.send(service.handle(&peer,CasRequest::Wipe)).unwrap();});
        let deadline=Instant::now()+Duration::from_secs(2);
        while state.cancellation.generation.load(Ordering::SeqCst)==original&&Instant::now()<deadline {std::thread::yield_now();}
        assert_ne!(state.cancellation.generation.load(Ordering::SeqCst),original,"Wipe must cancel while State is held");
        assert!(matches!(done_rx.try_recv(),Err(std::sync::mpsc::TryRecvError::Empty)),"owned cleanup must still be waiting for State");
        assert!(CasService::download_authority(&state,&CasUri::parse(&f.uri()).unwrap(),&plan,NOW).unwrap_err().is("DOWNLOAD_WIPED"));
        for request in [CasRequest::FetchCustodyMetadata,CasRequest::FetchCustodyTarget{target:enclave_core::custody_metadata::CustodyTarget::EnvelopePolicy},CasRequest::FetchCustodyTarget{target:enclave_core::custody_metadata::CustodyTarget::OidcAuthority},CasRequest::Hydrate{cas_uri:f.uri()},CasRequest::OpenTarget{target:"model.bin".into()},CasRequest::Resolve{cas_uri:f.uri()},CasRequest::Fetch{cas_uri:f.uri()},CasRequest::FetchTarget{target:"model.bin".into()},CasRequest::Admit{target:"model.bin".into(),bytes:MAIN.to_vec().into()},CasRequest::AdmitBegin{target:"model.bin".into()},CasRequest::AdmitChunk{session:"pending-fixture".into(),offset:0,bytes:MAIN.to_vec().into()},CasRequest::AdmitCommit{session:"pending-fixture".into()}] {
            assert!(f.svc.handle_locked(&mut state,&f.peer,request).unwrap_err().is("DOWNLOAD_WIPED"),"queued Wipe must prevent cached receipts and descriptors");
        }
        drop(state);assert!(matches!(done_rx.recv_timeout(Duration::from_secs(2)).unwrap().unwrap(),CasResponse::Wiped));worker.join().unwrap();
        assert_eq!(f.svc.cancellation.pending.load(Ordering::SeqCst),0);
        {let mut state=f.svc.state.lock().unwrap();assert!(f.svc.handle_locked_access(&mut state,&f.peer,CasRequest::OpenTarget{target:"model.bin".into()},Some(original)).unwrap_err().is("DOWNLOAD_WIPED"),"a cached request queued before Wipe must retain its original epoch");}
        assert!(f.svc.execute_download(&f.peer,plan).unwrap_err().is("DOWNLOAD_WIPED"));f.no_receipt_or_stages();
        let fresh=f.svc.prepare_download(&f.uri()).unwrap();assert!(matches!(f.svc.execute_download(&f.peer,fresh).unwrap(),CasResponse::Admitted{..}),"fresh authorized use must recover after cleanup");
    }

    #[test]
    fn f38_overlapping_or_exhausted_wipe_fences_never_reenable_old_or_pending_plans() {
        let cancellation=DownloadCancellation::default();let old=cancellation.observe().unwrap();
        let first=cancellation.begin().unwrap();let second=cancellation.begin().unwrap();
        assert!(cancellation.observe().is_err());drop(first);assert!(cancellation.observe().is_err());drop(second);
        assert!(cancellation.validate(old).is_err());assert!(cancellation.observe().is_err());cancellation.finish();assert!(cancellation.observe().is_ok());
        cancellation.generation.store(u64::MAX,std::sync::atomic::Ordering::SeqCst);
        assert!(cancellation.begin().is_err());assert!(cancellation.observe().is_err());assert_eq!(cancellation.pending.load(std::sync::atomic::Ordering::SeqCst),0);
    }

    #[test]
    fn f38_failed_owned_cleanup_keeps_artifact_release_blocked_until_successful_wipe_retry() {
        use std::sync::atomic::{AtomicBool,Ordering};
        #[derive(Debug)]struct Publisher(AtomicBool);
        impl crate::snapshot_publication::SnapshotPublisher for Publisher {
            fn publish(&self,_:&std::fs::File,_:&TargetFile)->EnclaveResult<std::fs::File>{Err(err!(EIO,"FIXTURE_UNUSED"))}
            fn reopen(&self,_:&TargetFile)->EnclaveResult<std::fs::File>{Err(err!(EIO,"FIXTURE_UNUSED"))}
            fn revoke(&self,_:&TargetFile)->EnclaveResult<()>{if self.0.load(Ordering::SeqCst){fail!(EIO,"FIXTURE_RETRACTION");}Ok(())}
        }
        for overlap in [false,true] {
        let f=Fixture::new();f.admit("companion.json",COMPANION);f.admit("model.bin",MAIN);
        let pending=if overlap {
            // Both requests have crossed the actual pre-State cancellation
            // boundary. The first completes while the second is still queued.
            let first=f.svc.cancellation.begin().unwrap();let second=f.svc.cancellation.begin().unwrap();
            {let mut state=f.svc.state.lock().unwrap();assert!(matches!(f.svc.handle_locked(&mut state,&f.peer,CasRequest::Wipe).unwrap(),CasResponse::Wiped));}
            drop(first);Some(second)
        }else{None};
        let publisher=Arc::new(Publisher(AtomicBool::new(true)));let target=f.targets["model.bin"].clone();let root=target.hashes["blake3"].clone();
        f.svc.published.lock().unwrap().insert(root.clone(),(publisher.clone(),target,None));
        let failed=if overlap {let mut state=f.svc.state.lock().unwrap();f.svc.handle_locked(&mut state,&f.peer,CasRequest::Wipe)}else{f.svc.handle(&f.peer,CasRequest::Wipe)};
        assert!(failed.unwrap_err().is("FIXTURE_RETRACTION"));drop(pending);assert!(f.svc.published.lock().unwrap().contains_key(&root));
        assert_eq!(f.svc.cancellation.pending.load(Ordering::SeqCst),0);
        assert!(f.svc.handle(&f.peer,CasRequest::Hydrate{cas_uri:f.uri()}).unwrap_err().is("DOWNLOAD_WIPED"));f.no_receipt_or_stages();
        publisher.0.store(false,Ordering::SeqCst);assert!(matches!(f.svc.handle(&f.peer,CasRequest::Wipe).unwrap(),CasResponse::Wiped));
        assert!(f.svc.published.lock().unwrap().is_empty());assert!(matches!(f.svc.handle(&f.peer,CasRequest::Hydrate{cas_uri:f.uri()}).unwrap(),CasResponse::Admitted{..}));
        }
    }

    #[test]
    fn f38_download_all_companion_authority_checked_before_receipt_and_cached_export() {
        for mode in 0..6 {
            let f=Fixture::new();f.admit("companion.json",COMPANION);f.admit("model.bin",MAIN);
            let plan=f.svc.prepare_download(&f.uri()).unwrap();
            let mut changed=f.targets.clone();
            let custom=changed.get_mut("companion.json").unwrap().custom.as_mut().unwrap();
            match mode {0=>custom["min_profile"]=json!("L3"),1=>custom["classification"]=json!("restricted_l3"),2=>custom["revoked"]=json!(true),_=>custom["license_policy"]["spdx_id"]=json!("LicenseRef-rotated")}
            if mode==4 {changed.get_mut("companion.json").unwrap().length+=1;}
            if mode==5 {changed.get_mut("companion.json").unwrap().hashes.insert("sha256".into(),"0".repeat(64));}
            f.refresh(2,changed);
            assert!(f.svc.execute_download(&f.peer,plan).is_err(),"mode {mode}");
            if mode!=3 {
                assert!(f.svc.handle(&f.peer,CasRequest::Resolve {cas_uri:f.uri()}).is_err());
                assert!(f.svc.handle(&f.peer,CasRequest::Hydrate {cas_uri:f.uri()}).is_err());
                assert!(f.svc.handle(&f.peer,CasRequest::OpenTarget {target:"model.bin".into()}).is_err());
            }
            f.no_receipt_or_stages();
        }
    }
}
