//! UID 705 daemon service. `_enclavezk` holds **zero** network sockets:
//! tombstone co-signatures are fetched from UIDs 703 and 704 over
//! peer-credential-checked UDS, and finished frames are handed to UID 702 for
//! OHTTP relay.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use ed25519_dalek::VerifyingKey;
use enclave_core::audit::AuditJournal;
use enclave_core::daemon::DaemonId;
use enclave_core::error::EnclaveResult;
use enclave_core::ipc::{DaemonStatus, PeerCredentials, PreparedCall, ReleasePermit};
use enclave_core::poseidon2::{hash_bytes, Poseidon2Digest};
use enclave_core::profile::Profile;
use enclave_core::seq::RpcSequencer;
use enclave_core::{err, fail};
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use serde_json::json;
use zeroize::{Zeroize, Zeroizing};

use crate::quarantine::{FaultReport, Quarantine, Response};
use crate::relation::{
    journal_fold, prove_rollup, prove_rollup_series, EpochChunk, EpochPublic, HardwareWitness,
    SlotWitness, MAX_SLOTS_PER_FRAME,
};
use crate::rollup::ComplianceRollupProofV1;
use crate::retained::{RetainedWitnessCache, WitnessLease, WITNESS_CAPACITY_LIMIT};
use crate::slab::{EmteGate, SecureSlabAllocator, SiliconMemoryMode};
use crate::thermal::ThermalQueue;
use crate::tombstone::{Tombstone, TombstoneKeys};
use crate::witness::WitnessFold;
use crate::zk::engine::hiding_vk_digest as vk_digest;

/// `ProveEpoch` body. The caller names only *which* slots to prove (epoch, s_start, s_end);
/// their contents, QIF charges and journal lines are derived by UID 705 from the
/// journals and UID 703's fold witnesses (GAP-10).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProveEpochRequest {
    /// The sequence authority's (UID 703) boot epoch.
    pub boot_epoch_id: String,
    /// First slot.
    pub s_start: u64,
    /// Last slot (inclusive).
    pub s_end: u64,
}

/// IPC requests.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ZkRequest {
    /// Status.
    Status,
    /// Root operator's bounded physical-memory report; auditor recomputes fixed
    /// policy and acknowledges only after its own journal append/fsync.
    ReportMemoryBreach(Box<enclave_core::memory_budget::MemoryObservations>),
    /// Evaluate `R_epoch`, prove, and relay through UID 702.
    ProveEpoch(Box<ProveEpochRequest>),
    /// Verify a rollup frame (ledger / self-check).
    VerifyFrame {
        /// Frame.
        frame: ByteBuf,
    },
    /// Verify a multi-frame rollup series (ledger / self-check, GAP-24).
    VerifySeries {
        /// Frames.
        frames: Vec<ByteBuf>,
    },
    /// Report a hardware-integrity fault from any daemon.
    ReportFault(FaultReport),
    /// Defer a witness under `.serious` thermal pressure.
    DeferWitness {
        /// Witness bytes.
        witness: ByteBuf,
    },
    /// Wipe witnesses (yank / lid-close).
    Wipe,
    /// Synchronously gate an L3 egress chunk (GAP-25).
    GateEgress {
        /// Canonical JCS representation of the request/decision envelope or payload metadata.
        d_jcs: ByteBuf,
        /// The payload chunk to gate (up to 64 KiB).
        chunk: ByteBuf,
    },
    /// Generate and relay an L3 constant-rate heartbeat cover frame (GAP-26).
    Heartbeat,
    /// Clear hardware integrity quarantine with a custodian k-of-n grant.
    UnquarantineQuorum {
        /// Enrolled public keys (if specifying custom policy).
        enrolled_keys: Option<Vec<Vec<u8>>>,
        /// Quorum threshold.
        threshold: Option<usize>,
        /// Target host ID.
        host_id: String,
        /// Target binary cdhash.
        cdhash: String,
        /// Expected state generation counter.
        generation: u64,
        /// Grant expiration timestamp in ms.
        expires_at_ms: u64,
        /// Custodian signatures.
        sigs: Vec<enclave_crypto::multisig::QuorumSignature>,
        /// Current timestamp in ms.
        now_ms: u64,
    },
    /// Clear hardware integrity quarantine with a TUF fleet grant.
    UnquarantineFleet {
        /// Signed fleet grant bytes.
        grant_bytes: ByteBuf,
        /// Running binary cdhash.
        running_cdhash: String,
        /// Current epoch timestamp in seconds.
        now: i64,
    },
}

/// IPC responses.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ZkResponse {
    /// Status.
    Status(DaemonStatus),
    /// A measured breach was durably recorded in the auditor's journal.
    MemoryBreachRecorded { /// Fsynced journal line number.
        log_seq:u64 },
    /// Unquarantine succeeded.
    Unquarantined {
        /// New state generation after reset.
        new_generation: u64,
    },
    /// Frames produced.
    Proven {
        /// Frames.
        frames: Vec<ByteBuf>,
        /// Whether UID 702 accepted every frame for relay.
        relayed: bool,
        /// Journal state after the epoch (hex).
        j_curr: String,
    },
    /// Verified frame summary.
    Verified {
        /// Profile.
        profile: u8,
        /// Slots.
        slots: u64,
    },
    /// Verified series summary (GAP-24).
    SeriesVerified {
        /// Profile.
        profile: u8,
        /// Total slots across all frames.
        total_slots: u64,
        /// Final exiting QIF used millibits.
        used_out: u32,
    },
    /// Fault response.
    Fault(Response),
    /// Egress gate verification result (GAP-25).
    EgressGated {
        /// Whether the chunk was approved.
        approved: bool,
        /// Blake3 hash of the chunk.
        chunk_hash: [u8; 32],
        /// Blake3 hash of d_jcs.
        d_jcs_hash: [u8; 32],
        /// Succinct pi_redact proof bytes.
        pi_redact: ByteBuf,
    },
    /// Ack.
    Ok,
}

/// Authenticated access to sibling daemons.
pub trait Peers: Send + Sync {
    /// Ask `who` (703 or 704) to co-sign a tombstone; returns `(signature, public_key)`.
    fn cosign(
        &self,
        who: DaemonId,
        slot: u64,
        boot_epoch_id: &str,
    ) -> EnclaveResult<(Vec<u8>, Vec<u8>)>;
    /// Prepare an authenticated, serialized relay request without emitting bytes.
    /// The service performs its bounded handoff under the cancellation fence.
    fn prepare_relay(&self, frame: &[u8]) -> EnclaveResult<PreparedCall>;
    /// UID 703's fold witnesses for released slots in `s_start..=s_end` of
    /// `boot_epoch_id`, and its next unissued slot.
    fn fetch_witness(
        &self,
        boot_epoch_id: &str,
        s_start: u64,
        s_end: u64,
    ) -> EnclaveResult<(Vec<WitnessFold>, u64)>;
    /// UID 703's current SEP-signed epoch (GAP-27).
    fn boot_epoch(&self) -> EnclaveResult<enclave_core::seq::BootEpoch>;
}

/// Configuration.
#[derive(Debug, Clone)]
pub struct ZkConfig {
    /// Profile.
    pub profile: Profile,
    /// Sealed quarantine state directory (GAP-12; `quarantine.sealed`,
    /// `quarantine.gen`, `sealing.key`).
    pub quarantine_dir: PathBuf,
    /// Audit path.
    pub audit_path: Option<PathBuf>,
    /// Audit root holding every daemon's journal (read-only, GAP-10).
    pub journal_dir: Option<PathBuf>,
    /// Mesh socket directory (GAP-10).
    pub socket_dir: Option<PathBuf>,
    /// Accounting entity (GAP-10).
    pub entity: String,
    /// Enclave ID (GAP-10).
    pub id_enclave: [u8; 32],
    /// Policy BLAKE3 digest (GAP-10).
    pub policy_blake3: [u8; 32],
    /// TUF snapshot root (GAP-10).
    pub tuf_snapshot_root: [u8; 32],
    /// L3 hardware witness (GAP-10).
    pub hardware: Option<HardwareWitness>,
    /// L2 batch anchor signatures (hex).
    pub hardware_batch_anchor_sigs: Option<Vec<String>>,
    /// Independently configured receive-side issuer/cohort authority. Missing
    /// authority denies VerifyFrame/VerifySeries without affecting proving APIs.
    pub receiver_trust: Option<crate::receiver_trust::ReceiverTrust>,
    /// L3 heartbeat (cover-traffic) flag.
    pub heartbeat: bool,
}

impl ZkConfig {
    /// Create default config with profile and quarantine directory.
    pub fn new(profile: Profile, quarantine_dir: PathBuf) -> Self {
        Self {
            profile,
            quarantine_dir,
            audit_path: None,
            journal_dir: None,
            socket_dir: None,
            entity: "enclave".into(),
            id_enclave: [0u8; 32],
            policy_blake3: [0u8; 32],
            tuf_snapshot_root: [0u8; 32],
            hardware: None,
            hardware_batch_anchor_sigs: None,
            receiver_trust: None,
            heartbeat: false,
        }
    }
}

// Owns this fold's three buffers, including fetched and derived candidates.
// Explicit cleanup does not erase independent proof/wire or historical copies.
struct RetainedWitness(WitnessFold);

impl RetainedWitness {
    fn wipe(&mut self) {
        // zeroize Vec/String covers current initialized and spare capacity.
        // Historical reallocations and copies outside this owner are excluded.
        self.0.scrubbed.zeroize();
        self.0.c_raw.zeroize();
        self.0.h_ingress_mac.zeroize();
    }
}

impl Drop for RetainedWitness {
    fn drop(&mut self) {
        self.wipe();
    }
}

struct State {
    profile: Profile,
    quarantine: Quarantine,
    slab: SecureSlabAllocator,
    thermal: ThermalQueue,
    seq: RpcSequencer,
    j_state: Poseidon2Digest,
    pinned: HashMap<u32, Vec<u8>>,
    journal_dir: Option<PathBuf>,
    anchors: HashMap<u32, enclave_core::audit::ChainAnchor>,
    /// Highest slot proven per sequence-authority epoch (no re-proving).
    proven: HashMap<String, u64>,
    entity: String,
    id_enclave: [u8; 32],
    policy_blake3: [u8; 32],
    tuf_snapshot_root: [u8; 32],
    hardware: Option<HardwareWitness>,
    hardware_batch_anchor_sigs: Option<Vec<String>>,
    receiver_trust: Option<crate::receiver_trust::ReceiverTrust>,
    heartbeat: bool,
    streamed_witnesses: RetainedWitnessCache,
    egress_streams: HashMap<[u8; 32], u32>,
}

impl State {
    // The State mutex serializes cache lookup/insertion and purge. Already
    // cloned prover data and later authenticated reingress remain outside this
    // bounded cache teardown; this is not a proof-wide release fence.
    fn wipe_retained_witnesses(&mut self) {
        self.thermal.wipe();
        self.streamed_witnesses.wipe();
    }
}

/// The service.
pub struct ZkService {
    state: Mutex<State>,
    journal: Mutex<Option<AuditJournal>>,
    memory_audit_failed: Arc<AtomicBool>,
    memory_audit_pending: Arc<AtomicBool>,
    release_serial: Arc<Mutex<()>>,
    release_generation: Arc<AtomicU64>,
    fence_pending: Arc<AtomicU64>,
    relay_failed: Arc<AtomicBool>,
    relay_debt_path: PathBuf,
    fence_debt_path: PathBuf,
    proof_operation: Mutex<()>,
    memory_debt_path: PathBuf,
    memory_debt_lock:Mutex<()>,
    #[cfg(test)]
    memory_cleanup_barrier:Mutex<Option<Arc<std::sync::Barrier>>>,
    #[cfg(test)]
    memory_busy_barrier:Mutex<Option<Arc<std::sync::Barrier>>>,
    peers: Box<dyn Peers>,
    /// UID 703's epoch signer, pinned on first verified epoch (GAP-27).
    epochs: enclave_crypto::epoch::EpochVerifier,
    /// Pre-egress redaction proof authority key (GAP-25).
    redact_key: ed25519_dalek::SigningKey,
    // LAST: persistent resources and peer destructors finish before ownership
    // is released. Arc clones (including heartbeat workers) retain this lease.
    _state_lease: enclave_core::sealed::StateDirectoryLease,
}

// Pending stays raised through purge/quarantine persistence, but the release
// serial is held only for the generation change. No State or I/O under serial.
struct FenceGuard(Arc<AtomicU64>);
impl Drop for FenceGuard {
    fn drop(&mut self) { self.0.fetch_sub(1, Ordering::SeqCst); }
}

struct DeliveryGuard<'a> { failed: &'a AtomicBool, committed: bool }
impl Drop for DeliveryGuard<'_> {
    fn drop(&mut self) { if !self.committed { self.failed.store(true, Ordering::SeqCst); } }
}

fn validate_release(generation: &AtomicU64, captured: u64, pending: &AtomicU64,
    relay_failed: &AtomicBool, memory_failed: &AtomicBool, memory_pending: &AtomicBool) -> EnclaveResult<()> {
    if generation.load(Ordering::SeqCst) != captured || pending.load(Ordering::SeqCst) != 0 {
        fail!(ESTALE, "PROOF_RELEASE_FENCED");
    }
    if relay_failed.load(Ordering::SeqCst) { fail!(EIO, "PROOF_DELIVERY_UNCERTAIN"); }
    if memory_failed.load(Ordering::SeqCst) || memory_pending.load(Ordering::SeqCst) {
        fail!(EIO, "MEMORY_AUDIT_ADMISSION_BLOCKED");
    }
    Ok(())
}

impl std::fmt::Debug for ZkService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ZkService")
    }
}

/// Largest range one `ProveEpoch` may cover (FS-705 §11.2 / Rev 1.4: 4,096 slots).
pub const MAX_SLOTS_PER_EPOCH: u64 = MAX_SLOTS_PER_FRAME as u64;

/// A slot as derived by UID 705.
enum Derived {
    Fold {
        seq: u64,
        scrubbed: Vec<u8>,
        qif_delta_mb: u32,
    },
    Tombstone(u64),
}

// Data owners drop before their snapshot capacity charge on every return path.
struct DerivedBatch {
    chunks: Vec<(Vec<Derived>, Vec<Vec<u8>>)>,
    anchors: HashMap<u32, enclave_core::audit::ChainAnchor>,
    _lease: WitnessLease,
}

/// Genesis journal state.
pub fn genesis() -> Poseidon2Digest {
    hash_bytes(b"MCPMac-JournalGenesis-v1", b"")
}

impl ZkService {
    /// Start; refuse overlapping owners before persistent initialization.
    /// A latched quarantine refuses all proving work. Relative configuration
    /// resolves against the current directory, then undergoes a strict trusted
    /// no-follow walk; parent traversal and arbitrary symlinks are refused.
    pub fn start(mut cfg: ZkConfig, peers: Box<dyn Peers>) -> EnclaveResult<Arc<Self>> {
        cfg.quarantine_dir=std::path::absolute(&cfg.quarantine_dir)
            .map_err(|e|err!(EIO,"AUDITOR_STATE_PATH","{e}"))?;
        let state_lease=enclave_core::sealed::StateDirectoryLease::acquire(&cfg.quarantine_dir)
            .map_err(|error|if error.is("STATE_DIRECTORY_BUSY") {err!(EAGAIN,"AUDITOR_STATE_BUSY")} else {error})?;
        // Move the parameter into a later local: startup-error unwinding must
        // finish peer cleanup before dropping the earlier-acquired lease.
        let peers=peers;
        let epoch = enclave_core::seq::new_boot_epoch_id();
        let quarantine = Quarantine::open(cfg.profile, &cfg.quarantine_dir)?;
        let journal = match &cfg.audit_path {
            Some(p) => Some(AuditJournal::open(p, DaemonId::ZkAuditor, epoch.clone())?),
            None => None,
        };
        let memory_debt_path=cfg.quarantine_dir.join("memory-breach.pending");
        let relay_debt_path=cfg.quarantine_dir.join("proof-release.pending");
        let fence_debt_path=cfg.quarantine_dir.join("proof-fence-audit.pending");
        let relay_failed=[&relay_debt_path,&fence_debt_path].iter().any(|path|
            !matches!(std::fs::symlink_metadata(path),Err(error) if error.kind()==std::io::ErrorKind::NotFound));
        // An observed debt marker cannot disappear merely because following
        // a dangling link would report its target as absent.
        let memory_audit_failed=match std::fs::symlink_metadata(&memory_debt_path) {
            Ok(_)=>true,
            Err(error) if error.kind()==std::io::ErrorKind::NotFound=>false,
            Err(_)=>true,
        };
        Ok(Arc::new(Self {
            journal:Mutex::new(journal),
            memory_audit_failed:Arc::new(AtomicBool::new(memory_audit_failed)),
            memory_audit_pending:Arc::new(AtomicBool::new(false)),
            release_serial:Arc::new(Mutex::new(())),
            release_generation:Arc::new(AtomicU64::new(0)),
            fence_pending:Arc::new(AtomicU64::new(0)),
            relay_failed:Arc::new(AtomicBool::new(relay_failed)),
            relay_debt_path,
            fence_debt_path,
            proof_operation:Mutex::new(()),
            memory_debt_path,
            memory_debt_lock:Mutex::new(()),
            #[cfg(test)]
            memory_cleanup_barrier:Mutex::new(None),
            #[cfg(test)]
            memory_busy_barrier:Mutex::new(None),
            state: Mutex::new(State {
                profile: cfg.profile,
                quarantine,
                slab: SecureSlabAllocator::new(&EmteGate::default()),
                thermal: ThermalQueue::default(),
                seq: RpcSequencer::new(epoch, 0),
                j_state: genesis(),
                pinned: HashMap::new(),
                journal_dir: cfg.journal_dir,
                anchors: HashMap::new(),
                proven: HashMap::new(),
                entity: cfg.entity,
                id_enclave: cfg.id_enclave,
                policy_blake3: cfg.policy_blake3,
                tuf_snapshot_root: cfg.tuf_snapshot_root,
                hardware: cfg.hardware,
                hardware_batch_anchor_sigs: cfg.hardware_batch_anchor_sigs,
                receiver_trust: cfg.receiver_trust,
                heartbeat: cfg.heartbeat,
                streamed_witnesses: RetainedWitnessCache::new(WITNESS_CAPACITY_LIMIT),
                egress_streams: HashMap::new(),
            }),
            peers,
            epochs: enclave_crypto::epoch::EpochVerifier::open(Some(&cfg.quarantine_dir))?,
            redact_key: ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng),
            _state_lease: state_lease,
        }))
    }

    /// Verifying key for synchronous pre-egress pi_redact proofs (GAP-25).
    pub fn redact_verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        self.redact_key.verifying_key()
    }

    fn lock(&self) -> EnclaveResult<std::sync::MutexGuard<'_, State>> {
        self.state.lock().map_err(|_| err!(EIO, "STATE_POISONED"))
    }

    fn fence(&self) -> EnclaveResult<FenceGuard> {
        if self.fence_pending.try_update(Ordering::SeqCst, Ordering::SeqCst,
            |value| value.checked_add(1)).is_err() {
            self.relay_failed.store(true, Ordering::SeqCst);
            fail!(EIO,"PROOF_FENCE_COUNT_EXHAUSTED");
        }
        let pending = FenceGuard(self.fence_pending.clone());
        let _serial = self.release_serial.lock().map_err(|_| err!(EIO, "PROOF_RELEASE_LOCK"))?;
        // Overflow leaves admission permanently closed rather than reusing a token.
        if self.release_generation.try_update(Ordering::SeqCst, Ordering::SeqCst,
            |value| value.checked_add(1)).is_err() {
            self.relay_failed.store(true, Ordering::SeqCst);
            fail!(EIO, "PROOF_GENERATION_EXHAUSTED");
        }
        Ok(pending)
    }

    fn release_permit(&self, captured: u64) -> ReleasePermit {
        let generation = self.release_generation.clone();
        let pending = self.fence_pending.clone();
        let failed = self.relay_failed.clone();
        let memory_failed = self.memory_audit_failed.clone();
        let memory_pending = self.memory_audit_pending.clone();
        ReleasePermit::new(self.release_serial.clone(), Arc::new(move ||
            validate_release(&generation, captured, &pending, &failed, &memory_failed, &memory_pending)))
    }

    fn check_release(&self, captured: u64) -> EnclaveResult<()> {
        validate_release(&self.release_generation, captured, &self.fence_pending,
            &self.relay_failed, &self.memory_audit_failed, &self.memory_audit_pending)
    }

    fn sync_relay_debt(&self) -> EnclaveResult<()> {
        let parent = self.relay_debt_path.parent().ok_or_else(|| err!(EIO,"PROOF_DEBT_PARENT"))?;
        std::fs::File::open(parent).and_then(|dir| dir.sync_all())
            .map_err(|_| err!(EIO,"PROOF_DEBT_DIRECTORY_SYNC"))
    }

    fn latch_fence_debt(&self, reason: &[u8]) {
        self.relay_failed.store(true, Ordering::SeqCst);
        // Separate from relay intent: a concurrent fault must never overwrite
        // the identities of frames which may already be in receiver custody.
        let _ = enclave_core::fsutil::write_private(&self.fence_debt_path, reason);
        let _ = self.sync_relay_debt();
    }

    fn begin_relay_intent(&self, generation: u64, frames: &[Vec<u8>]) -> EnclaveResult<()> {
        // A crash anywhere after this durable intent must require reconciliation.
        // Include the generation for diagnosis; never put private witnesses here.
        let intent = serde_json::to_vec(&json!({"schema":1,"generation":generation,
            "disposition":"pending_or_uncertain_no_automatic_retry",
            "frames":frames.iter().map(|frame|json!({"bytes":frame.len(),
                "blake3":blake3::hash(frame).to_hex().to_string()})).collect::<Vec<_>>()}))
            .map_err(|_| err!(EIO,"PROOF_INTENT_ENCODE"))?;
        let result = enclave_core::fsutil::write_private(&self.relay_debt_path, &intent)
            .and_then(|_| self.sync_relay_debt());
        if result.is_err() { self.relay_failed.store(true, Ordering::SeqCst); }
        result
    }

    fn clear_relay_intent(&self) -> EnclaveResult<()> {
        let result = std::fs::remove_file(&self.relay_debt_path)
            .map_err(|_| err!(EIO,"PROOF_DEBT_REMOVE"))
            .and_then(|_| self.sync_relay_debt());
        if result.is_err() { self.relay_failed.store(true, Ordering::SeqCst); }
        result
    }

    fn relay_frames(&self, generation: u64, frames: &[Vec<u8>]) -> EnclaveResult<DeliveryGuard<'_>> {
        #[derive(Deserialize)]
        enum RelayAck { Queued }
        let mut attempted = false;
        self.begin_relay_intent(generation, frames)?;
        let result = (|| {
            for frame in frames {
                self.check_release(generation)?;
                let prepared = self.peers.prepare_relay(frame)?;
                let pending = {
                    let _serial = self.release_serial.lock().map_err(|_| err!(EIO,"PROOF_RELEASE_LOCK"))?;
                    self.check_release(generation)?;
                    attempted = true;
                    prepared.handoff()?
                };
                let _: RelayAck = pending.receive()?;
            }
            Ok(())
        })();
        if result.is_err() {
            if attempted { self.relay_failed.store(true, Ordering::SeqCst); }
            else { self.clear_relay_intent()?; }
        }
        result.map(|()| DeliveryGuard { failed: &self.relay_failed, committed: false })
    }

    /// Ingest streamed witnesses from UID 703 (GAP-10).
    pub fn ingest_witnesses(&self, epoch: &str, folds: Vec<WitnessFold>) -> EnclaveResult<()> {
        // Wrap before fallible admission so a refused batch's owned cache
        // candidates are also zeroized on normal return/unwind.
        let folds: Vec<_> = folds.into_iter().map(RetainedWitness).collect();
        let mut st = self.lock()?;
        st.quarantine.ensure_clear()?;
        let floor = st.proven.get(epoch).copied();
        let folds = folds.into_iter().map(|mut fold| WitnessFold {
            rpc_seq_u64: fold.0.rpc_seq_u64,
            scrubbed: std::mem::take(&mut fold.0.scrubbed),
            c_raw: std::mem::take(&mut fold.0.c_raw),
            h_ingress_mac: std::mem::take(&mut fold.0.h_ingress_mac),
        }).collect();
        st.streamed_witnesses.ingest(epoch, folds, floor)
    }

    /// Set host config / proving context (GAP-10).
    ///
    /// Refuses while proof/heartbeat construction, relay or commit is active.
    /// This process-local exclusion does not define durable context rotation.
    #[allow(clippy::too_many_arguments)]
    pub fn set_context(
        &self,
        entity: String,
        id_enclave: [u8; 32],
        policy_blake3: [u8; 32],
        tuf_snapshot_root: [u8; 32],
        hardware: Option<HardwareWitness>,
        hardware_batch_anchor_sigs: Option<Vec<String>>,
        heartbeat: bool,
    ) -> EnclaveResult<()> {
        // Match prove/heartbeat lock order and never wait behind peer/prover I/O.
        let _operation = self.proof_operation.try_lock().map_err(|_| err!(EAGAIN,"PROOF_OPERATION_BUSY"))?;
        let mut st = self.lock()?;
        st.entity = entity;
        st.id_enclave = id_enclave;
        st.policy_blake3 = policy_blake3;
        st.tuf_snapshot_root = tuf_snapshot_root;
        st.hardware = hardware;
        st.hardware_batch_anchor_sigs = hardware_batch_anchor_sigs;
        st.heartbeat = heartbeat;
        Ok(())
    }

    /// Fetch a co-signature and pin the signer's key for this process lifetime.
    fn cosign(
        &self,
        who: DaemonId,
        slot: u64,
        epoch: &str,
    ) -> EnclaveResult<(Vec<u8>, VerifyingKey)> {
        let (sig, pk) = self.peers.cosign(who, slot, epoch)?;
        let mut st = self.lock()?;
        let pinned = st.pinned.entry(who.uid()).or_insert_with(|| pk.clone());
        if *pinned != pk {
            fail!(
                EACCES,
                "TOMBSTONE_KEY_CHANGED",
                "UID {} presented a different key",
                who.uid()
            );
        }
        let b: [u8; 32] = pk
            .as_slice()
            .try_into()
            .map_err(|_| err!(EINVAL, "TOMBSTONE_KEY"))?;
        Ok((
            sig,
            VerifyingKey::from_bytes(&b).map_err(|_| err!(EINVAL, "TOMBSTONE_KEY"))?,
        ))
    }

    /// GAP-10: derive every slot of `r`'s range from the journals and UID
    /// 703's witnesses; the caller supplies none of it.
    #[allow(clippy::type_complexity)]
    fn derive_chunks(
        &self,
        r: &ProveEpochRequest,
    ) -> EnclaveResult<DerivedBatch> {
        enclave_core::seq::validate_epoch_id(&r.boot_epoch_id)?;
        if r.s_end < r.s_start || r.s_end - r.s_start >= MAX_SLOTS_PER_EPOCH {
            fail!(EINVAL, "EPOCH_RANGE", "{}..={}", r.s_start, r.s_end);
        }
        let (dir, mut anchors) = {
            let st = self.lock()?;
            if let Some(p) = st.proven.get(&r.boot_epoch_id) {
                if r.s_start <= *p {
                    fail!(
                        EACCES,
                        "EPOCH_ALREADY_PROVEN",
                        "slots up to {p} of {} are proven",
                        r.boot_epoch_id
                    );
                }
                // FS-705 section 4.2: later ranges of this same signed epoch
                // must extend its committed prefix without skipping a slot.
                // A first range still needs a separately defined origin policy.
                let next = p.checked_add(1)
                    .ok_or_else(|| err!(EACCES, "EPOCH_SLOT_EXHAUSTED"))?;
                if r.s_start != next {
                    fail!(EACCES, "EPOCH_RANGE_GAP", "expected slot {next}, got {}", r.s_start);
                }
            }
            (
                st.journal_dir.clone().ok_or_else(|| {
                    err!(
                        EPERM,
                        "ZK_NO_JOURNALS",
                        "UID 705 proves only what the journals record"
                    )
                })?,
                st.anchors.clone(),
            )
        };
        let lease;
        let (folds, next_slot) = {
            let (f, ns) = self
                .peers
                .fetch_witness(&r.boot_epoch_id, r.s_start, r.s_end)?;
            // Own every fetched buffer before locking or reserving a streamed
            // snapshot: either can refuse before derivation takes ownership.
            let mut f: Vec<_> = f.into_iter().map(RetainedWitness).collect();
            let st = self.lock()?;
            let (streamed, snapshot_lease) = st.streamed_witnesses
                .snapshot_range(&r.boot_epoch_id, r.s_start, r.s_end)?.into_parts();
            lease = snapshot_lease;
            for fold in streamed.into_iter().map(RetainedWitness) {
                if !f.iter().any(|existing| existing.0.rpc_seq_u64 == fold.0.rpc_seq_u64) {
                    f.push(fold);
                }
            }
            (f, ns)
        };
        if r.s_end >= next_slot {
            fail!(
                EACCES,
                "EPOCH_SLOT_UNISSUED",
                "slot {} not yet issued by UID 703 (next {next_slot})",
                r.s_end
            );
        }
        let jr =
            crate::witness::read_epoch(&dir, &r.boot_epoch_id, r.s_start, r.s_end, &mut anchors)?;
        let mut vault: HashMap<u64, RetainedWitness> = HashMap::new();
        for f in folds {
            let slot = f.0.rpc_seq_u64;
            if !(r.s_start..=r.s_end).contains(&slot) || vault.contains_key(&slot)
            {
                fail!(EACCES, "WITNESS_OUT_OF_RANGE", "slot {}", slot);
            }
            // A witness UID 703 never journaled is not evidence.
            if !jr.vault.contains_key(&slot) {
                fail!(EACCES, "WITNESS_UNJOURNALED", "slot {}", slot);
            }
            if f.0.c_raw.len() != 64
                || f.0.h_ingress_mac.len() != 64
                || f.0.h_ingress_mac.chars().all(|c| c == '0')
            {
                fail!(EACCES, "WITNESS_INGRESS_MAC", "slot {}", slot);
            }
            vault.insert(slot, f);
        }
        let mut chunks = Vec::new();
        let mut slots = Vec::new();
        let mut lines = Vec::new();
        for seq in r.s_start..=r.s_end {
            let d = match (vault.remove(&seq), jr.ifc.get(&seq)) {
                (Some(_), Some(_)) => fail!(
                    EACCES,
                    "SLOT_DOUBLE_CLAIM",
                    "slot {seq} journaled by UID 703 and UID 704"
                ),
                (Some(mut w), None) => Derived::Fold {
                    seq,
                    scrubbed: std::mem::take(&mut w.0.scrubbed),
                    qif_delta_mb: 0,
                },
                (None, Some(mb)) => Derived::Fold {
                    seq,
                    scrubbed: Vec::new(),
                    qif_delta_mb: *mb,
                },
                (None, None) => Derived::Tombstone(seq),
            };
            slots.push(d);
            if let Some(l) = jr.lines.get(&seq) {
                lines.extend(l.iter().cloned());
            }
            if slots.len() == MAX_SLOTS_PER_FRAME {
                chunks.push((std::mem::take(&mut slots), std::mem::take(&mut lines)));
            }
        }
        if !slots.is_empty() {
            chunks.push((slots, lines));
        }
        Ok(DerivedBatch { chunks, anchors, _lease: lease })
    }

    fn prove(&self, r: &ProveEpochRequest) -> EnclaveResult<(ZkResponse, u64)> {
        let _operation = self.proof_operation.try_lock().map_err(|_| err!(EAGAIN,"PROOF_OPERATION_BUSY"))?;
        let generation = self.release_generation.load(Ordering::SeqCst);
        self.check_release(generation)?;
        // GAP-27: only UID 703's current, SEP-signed epoch is proven, and its
        // signer must be the pinned epoch key.
        let be = self.peers.boot_epoch()?;
        self.epochs.check(&be)?;
        if be.boot_epoch_id != r.boot_epoch_id {
            fail!(
                ESTALE,
                "EPOCH_NOT_CURRENT",
                "{} is not UID 703's signed epoch {}",
                r.boot_epoch_id,
                be.boot_epoch_id
            );
        }
        let (profile, j_prev) = {
            let st = self.lock()?;
            st.quarantine.ensure_clear()?;
            (st.profile, st.j_state)
        };
        let profile_n = match profile {
            Profile::L2 => 2,
            Profile::L3 => 3,
            Profile::L1 => fail!(
                EPERM,
                "ROLLUP_PROFILE",
                "L1 hosts do not emit compliance rollups"
            ),
        };
        let derived = self.derive_chunks(r)?;
        let mut keys: Option<TombstoneKeys> = None;
        let mut out = Vec::with_capacity(derived.chunks.len());
        for (slots, journal_lines) in derived.chunks {
            let mut ws = Vec::with_capacity(slots.len());
            for s in slots {
                ws.push(match s {
                    Derived::Fold {
                        seq,
                        scrubbed,
                        qif_delta_mb,
                    } => SlotWitness::Fold {
                        seq,
                        scrubbed,
                        qif_delta_mb,
                    },
                    Derived::Tombstone(seq) => {
                        // Each co-signer refuses a slot it released (GAP-11).
                        let (s703, k703) =
                            self.cosign(DaemonId::CustodyVault, seq, &r.boot_epoch_id)?;
                        let (s704, k704) =
                            self.cosign(DaemonId::AgentRuntime, seq, &r.boot_epoch_id)?;
                        keys = Some(TombstoneKeys { k703, k704 });
                        SlotWitness::Tombstone(Tombstone {
                            slot: seq,
                            boot_epoch_id: r.boot_epoch_id.clone(),
                            sig_703: s703,
                            sig_704: s704,
                        })
                    }
                });
            }
            out.push(EpochChunk {
                slots: ws,
                journal_lines,
            });
        }
        let chunks = out;
        // With no tombstones in the epoch the key set is never consulted; a
        // fresh throwaway key verifies nothing anyone else signed.
        let keys = match keys {
            Some(k) => k,
            None => {
                let z = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng).verifying_key();
                TombstoneKeys { k703: z, k704: z }
            }
        };
        let (policy_blake3, tuf_snapshot_root, id_enclave, entity, hw, hw_batch_sigs, heartbeat) = {
            let st = self.lock()?;
            (
                st.policy_blake3,
                st.tuf_snapshot_root,
                st.id_enclave,
                st.entity.clone(),
                st.hardware.clone(),
                st.hardware_batch_anchor_sigs.clone(),
                st.heartbeat,
            )
        };
        let public = EpochPublic {
            profile: profile_n,
            policy_blake3,
            tuf_snapshot_root,
            j_prev,
        };
        let frames = prove_rollup_series(
            &public,
            &id_enclave,
            &entity,
            &chunks,
            &keys,
            hw.as_ref(),
            hw_batch_sigs,
            heartbeat,
        )?;
        let j_curr = chunks
            .iter()
            .fold(j_prev, |j, c| journal_fold(j, &c.journal_lines));
        let mut delivery = self.relay_frames(generation, &frames)?;
        let mut st = self.lock()?;
        st.proven.try_reserve(1).map_err(|_|err!(ENOMEM,"PROOF_PROGRESS_ALLOCATION"))?;
        let epoch_key = r.boot_epoch_id.clone();
        let old_anchors;
        {
            let _serial = self.release_serial.lock().map_err(|_| err!(EIO,"PROOF_RELEASE_LOCK"))?;
            if let Err(error) = self.check_release(generation) {
                self.relay_failed.store(true, Ordering::SeqCst);
                return Err(error);
            }
            st.j_state = j_curr;
            old_anchors = std::mem::replace(&mut st.anchors, derived.anchors);
            if let Some(floor) = st.proven.get_mut(&epoch_key) { *floor = r.s_end; }
            else { st.proven.insert(epoch_key, r.s_end); }
        }
        drop(old_anchors);
        let relayed = true;
        let jc = hex::encode(crate::cohort::digest_bytes(&j_curr));
        let seq = st.seq.next()?;
        let audit_result = (|| { if let Some(j) = self.journal_writer()?.as_mut() {
            j.append(seq, json!({"event": "ROLLUP_PROVEN", "frames": frames.len(), "relayed": relayed, "j_curr": jc,
                "epoch": r.boot_epoch_id, "s_start": r.s_start, "s_end": r.s_end, "redaction_checked": "native"}))?;
        } Ok(()) })();
        if let Err(error) = audit_result { self.relay_failed.store(true, Ordering::SeqCst); return Err(error); }
        self.clear_relay_intent()?;
        st.streamed_witnesses.retire_range(&r.boot_epoch_id, r.s_start, r.s_end);
        delivery.committed = true;
        Ok((ZkResponse::Proven {
            frames: frames.into_iter().map(ByteBuf::from).collect(),
            relayed,
            j_curr: jc,
        }, generation))
    }

    /// Generate and relay an L3 constant-rate heartbeat cover frame (GAP-26).
    pub fn prove_heartbeat(&self) -> EnclaveResult<ZkResponse> {
        self.heartbeat_inner().map(|(response, _)| response)
    }

    fn heartbeat_inner(&self) -> EnclaveResult<(ZkResponse, u64)> {
        let _operation = self.proof_operation.try_lock().map_err(|_| err!(EAGAIN,"PROOF_OPERATION_BUSY"))?;
        let generation = self.release_generation.load(Ordering::SeqCst);
        self.check_release(generation)?;
        let (j_prev, policy_blake3, tuf_snapshot_root, id_enclave, entity, hw) = {
            let st = self.lock()?;
            st.quarantine.ensure_clear()?;
            if st.profile != Profile::L3 {
                fail!(
                    EINVAL,
                    "HEARTBEAT_L3_ONLY",
                    "Heartbeats are only scheduled in L3 profile"
                );
            }
            (
                st.j_state,
                st.policy_blake3,
                st.tuf_snapshot_root,
                st.id_enclave,
                st.entity.clone(),
                st.hardware.clone(),
            )
        };
        let hw_ref = hw.as_ref().ok_or_else(|| {
            err!(
                EPERM,
                "L3_REQUIRES_COHORT_MEMBERSHIP",
                "Heartbeat requires hardware cohort membership"
            )
        })?;
        let seq = self.lock()?.seq.next()?;
        let dummy_slot = SlotWitness::Fold {
            seq,
            scrubbed: b"{\"cover\":true}".to_vec(),
            qif_delta_mb: 0,
        };
        let dummy_line = b"{\"cover\":true}".to_vec();
        let z = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng).verifying_key();
        let keys = TombstoneKeys { k703: z, k704: z };
        let public = EpochPublic {
            profile: 3,
            policy_blake3,
            tuf_snapshot_root,
            j_prev,
        };
        let frame = prove_rollup(
            &public,
            &id_enclave,
            &entity,
            &[dummy_slot],
            std::slice::from_ref(&dummy_line),
            &keys,
            Some(hw_ref),
            None,
            true,
        )?;
        let j_curr = journal_fold(j_prev, &[dummy_line]);
        let mut delivery = self.relay_frames(generation, std::slice::from_ref(&frame))?;
        let relayed = true;
        let mut st = self.lock()?;
        {
            let _serial = self.release_serial.lock().map_err(|_| err!(EIO,"PROOF_RELEASE_LOCK"))?;
            self.check_release(generation)?;
            st.j_state = j_curr;
        }
        let jc = hex::encode(crate::cohort::digest_bytes(&j_curr));
        if let Some(j) = self.journal_writer()?.as_mut() {
            j.append(
                seq,
                json!({
                    "event": "HEARTBEAT_PROVEN",
                    "relayed": relayed,
                    "j_curr": jc,
                    "slot": seq,
                }),
            )?;
        }
        self.clear_relay_intent()?;
        delivery.committed = true;
        Ok((ZkResponse::Proven {
            frames: vec![ByteBuf::from(frame)],
            relayed,
            j_curr: jc,
        }, generation))
    }

    // Never wait for another writer while holding State. In particular, a
    // blocked memory-report append must leave Status available.
    fn journal_writer(&self)->EnclaveResult<std::sync::MutexGuard<'_,Option<AuditJournal>>> {
        self.journal.try_lock().map_err(|_|err!(EIO,"AUDIT_WRITER_BUSY"))
    }

    fn memory_audit_status(&self)->&'static str {
        if self.memory_audit_failed.load(Ordering::SeqCst){"failed"}
        else if self.memory_audit_pending.load(Ordering::SeqCst){"pending"}
        else {"ok"}
    }

    fn sync_memory_debt_directory(&self)->EnclaveResult<()> {
        let parent=self.memory_debt_path.parent().ok_or_else(||err!(EIO,"MEMORY_DEBT_PARENT"))?;
        let directory=std::fs::File::open(parent).map_err(|_|err!(EIO,"MEMORY_DEBT_DIRECTORY"))?;
        directory.sync_all().map_err(|_|err!(EIO,"MEMORY_DEBT_DIRECTORY_SYNC"))
    }

    fn record_memory_breach(&self,peer:&PeerCredentials,observations:&enclave_core::memory_budget::MemoryObservations)->EnclaveResult<ZkResponse> {
        // Production IPC additionally requires the operator's code identity;
        // daemon peers cannot inject another process's resource observation.
        if peer.uid!=0 {fail!(EPERM,"MEMORY_BREACH_OPERATOR_ONLY");}
        let budget=observations.evaluate();
        if !budget.has_breach(){fail!(EINVAL,"MEMORY_BREACH_NOT_OBSERVED");}
        let _fence = self.fence()?;
        let seq=self.lock()?.seq.next()?;
        // Acquiring the writer before setting pending serializes marker lifetime.
        // A concurrent report is rejected. Persisting its debt may wait for
        // marker I/O; neither that wait nor journal I/O holds State.
        let mut writer=match self.journal_writer() {
            Ok(writer)=>writer,
            Err(error)=>{
                #[cfg(test)]
                if let Some(barrier)=self.memory_busy_barrier.lock().unwrap().as_ref(){barrier.wait();}
                let _debt=self.memory_debt_lock.lock().map_err(|_|err!(EIO,"MEMORY_DEBT_LOCK"))?;
                self.memory_audit_failed.store(true,Ordering::SeqCst);
                let _=enclave_core::fsutil::write_private(&self.memory_debt_path,b"memory breach delivery uncertain\n");
                let _=self.sync_memory_debt_directory();
                return Err(error);
            }
        };
        self.memory_audit_pending.store(true,Ordering::SeqCst);
        let result=(|| {
            // A restart must retain uncertain delivery debt. This marker carries
            // no observations; failures to persist it still never acknowledge.
            {
                let _debt=self.memory_debt_lock.lock().map_err(|_|err!(EIO,"MEMORY_DEBT_LOCK"))?;
                enclave_core::fsutil::write_private(&self.memory_debt_path,b"memory breach delivery pending\n")?;
                self.sync_memory_debt_directory()?;
            }
            let journal=writer.as_mut().ok_or_else(||err!(EIO,"MEMORY_BREACH_JOURNAL_REQUIRED"))?;
            let entry=journal.append(seq,json!({"event":"MEMORY_BUDGET_BREACH","observer_uid":peer.uid,
                "observation_authority":"authenticated_root_operator_report","memory":budget}))?;
            let parent=journal.path().parent().ok_or_else(||err!(EIO,"MEMORY_JOURNAL_PARENT"))?;
            std::fs::File::open(parent).and_then(|directory|directory.sync_all())
                .map_err(|_|err!(EIO,"MEMORY_JOURNAL_DIRECTORY_SYNC"))?;
            // Prior failure debt is latched; a later sample cannot erase it.
            let _debt=self.memory_debt_lock.lock().map_err(|_|err!(EIO,"MEMORY_DEBT_LOCK"))?;
            if !self.memory_audit_failed.load(Ordering::SeqCst) {
                #[cfg(test)]
                if let Some(barrier)=self.memory_cleanup_barrier.lock().unwrap().as_ref() {barrier.wait();barrier.wait();}
                std::fs::remove_file(&self.memory_debt_path).map_err(|_|err!(EIO,"MEMORY_DEBT_REMOVE"))?;
                self.sync_memory_debt_directory()?;
            }
            Ok(entry.log_seq_u64)
        })();
        if result.is_err(){
            self.memory_audit_failed.store(true,Ordering::SeqCst);
            if let Ok(_debt)=self.memory_debt_lock.lock(){
                let _=enclave_core::fsutil::write_private(&self.memory_debt_path,b"memory breach delivery uncertain\n");
                let _=self.sync_memory_debt_directory();
            }
        }
        self.memory_audit_pending.store(false,Ordering::SeqCst);
        result.map(|log_seq|ZkResponse::MemoryBreachRecorded{log_seq})
    }

    // Own decoded candidate storage before any fallible State/sequence/policy
    // work. Earlier IPC/decoder copies are outside this ownership boundary.
    fn defer_witness(&self, witness: Zeroizing<Vec<u8>>) -> EnclaveResult<ZkResponse> {
        let mut st = self.lock()?;
        let _seq = st.seq.next()?;
        st.quarantine.ensure_clear()?;
        st.thermal.push_guarded(witness)?;
        debug_assert_eq!(
            st.slab.mode,
            SiliconMemoryMode::PacGuarded,
            "EMTE gate has no verified citation"
        );
        Ok(ZkResponse::Ok)
    }

    /// Handle one request.
    pub fn handle(&self, peer: &PeerCredentials, req: ZkRequest) -> EnclaveResult<ZkResponse> {
        if matches!(&req, ZkRequest::UnquarantineQuorum { .. } | ZkRequest::UnquarantineFleet { .. }) {
            // Legacy requests contain caller-selected trust, time and code
            // claims. Root CLI transport identity cannot authenticate those
            // claims or approve the unfinished YKD-12 recovery protocol.
            if peer.uid != 0 && !(cfg!(feature = "simulation") && peer.uid == enclave_core::ipc::geteuid()) {
                fail!(EPERM, "UNQUARANTINE_PEER_REJECTED");
            }
            if !cfg!(feature = "simulation") {
                fail!(EACCES, "RECOVERY_PROTOCOL_REVIEW_PENDING",
                    "legacy recovery lacks authenticated host/boot/incident/release and hardware quorum authority");
            }
        }
        let req = match req {
            ZkRequest::DeferWitness { witness } => {
                return self.defer_witness(Zeroizing::new(witness.into_vec()));
            }
            other => other,
        };
        if let ZkRequest::ReportMemoryBreach(observations)=&req {return self.record_memory_breach(peer,observations);}
        if let ZkRequest::ProveEpoch(r) = &req {
            let (response, generation) = self.prove(r)?;
            enclave_core::ipc::attach_release_permit(self.release_permit(generation));
            return Ok(response);
        }
        if let ZkRequest::Heartbeat = &req {
            let (response, generation) = self.heartbeat_inner()?;
            enclave_core::ipc::attach_release_permit(self.release_permit(generation));
            return Ok(response);
        }
        let _fence = if matches!(&req, ZkRequest::Wipe | ZkRequest::ReportFault(_)) {
            if peer.uid != 0 && peer.uid != enclave_core::ipc::geteuid() {
                if matches!(&req, ZkRequest::Wipe) { fail!(EPERM,"WIPE_PEER_REJECTED"); }
                fail!(EPERM,"FAULT_REPORTER_REJECTED");
            }
            Some(self.fence()?)
        } else { None };
        let mut g = self.lock()?;
        let st = &mut *g;
        let generation = self.release_generation.load(Ordering::SeqCst);
        // Authorized teardown must not depend on obtaining another audit
        // sequence. The fence is already established, and State is held.
        if _fence.is_some() { st.wipe_retained_witnesses(); }
        let seq = st.seq.next().map_err(|error| {
            if _fence.is_some() {
                self.latch_fence_debt(b"authorized teardown audit sequence unavailable; reconcile before proving\n");
            }
            error
        })?;
        let (resp, ev) = match req {
            ZkRequest::ReportMemoryBreach(_) | ZkRequest::ProveEpoch(_) | ZkRequest::Heartbeat | ZkRequest::DeferWitness { .. } => fail!(EINVAL, "UNREACHABLE"),
            ZkRequest::Status => (
                ZkResponse::Status(DaemonStatus {
                    daemon_uid: DaemonId::ZkAuditor.uid(),
                    binary: DaemonId::ZkAuditor.binary().into(),
                    pid: std::process::id(),
                    rss_bytes: enclave_core::resource::current_rss_bytes().unwrap_or(0),
                    rss_ceiling_bytes: DaemonId::ZkAuditor.rss_ceiling_bytes(),
                    boot_epoch_id: st.seq.boot_epoch_id().into(),
                    rpc_seq_u64: st.seq.current(),
                    state: format!(
                        "profile={} quarantine_latched={} quarantine_integrity={} silicon={:?} root_keys={} vk={} memory_breach_audit={} proof_generation={} proof_delivery_debt={} fence_pending={} witness_registered_capacity={} witness_retained_capacity={} witness_capacity_limit={} thermal_entries={} thermal_payload_bytes={} thermal_payload_registered_capacity={} thermal_metadata_capacity={} thermal_registered_capacity={} thermal_capacity_limit={}",
                        st.profile,
                        st.quarantine.is_latched(),
                        if st.quarantine.integrity_failure().is_some() { "failed" } else { "ok" },
                        st.slab.mode,
                        st.slab.root_keys(),
                        hex::encode(vk_digest()),
                        self.memory_audit_status(), generation,
                        self.relay_failed.load(Ordering::SeqCst), self.fence_pending.load(Ordering::SeqCst),
                        st.streamed_witnesses.usage().registered_capacity_bytes,
                        st.streamed_witnesses.usage().retained_capacity_bytes,
                        st.streamed_witnesses.usage().limit_bytes,
                        st.thermal.resource_usage().entries,
                        st.thermal.resource_usage().payload_bytes,
                        st.thermal.resource_usage().payload_registered_capacity_bytes,
                        st.thermal.resource_usage().metadata_capacity_bytes,
                        st.thermal.resource_usage().registered_capacity_bytes,
                        st.thermal.resource_usage().limit_bytes
                    ),
                    phys_footprint_bytes: enclave_core::resource::current_phys_footprint_bytes().unwrap_or(0),
                    phys_footprint_source: enclave_core::resource::current_phys_footprint_source(),
                }),
                None,
            ),
            ZkRequest::VerifyFrame { frame } => {
                st.quarantine.ensure_clear()?;
                let trust=st.receiver_trust.as_ref().ok_or_else(||err!(EACCES,"ROLLUP_RECEIVER_TRUST_REQUIRED"))?;
                let f = trust.verify(&frame, &[vk_digest()])?;
                (
                    ZkResponse::Verified {
                        profile: f.profile,
                        slots: f.s_end - f.s_start + 1,
                    },
                    Some(json!({"event": "ROLLUP_VERIFIED", "profile": f.profile})),
                )
            }
            ZkRequest::VerifySeries { frames } => {
                st.quarantine.ensure_clear()?;
                let raw: Vec<&[u8]> = frames.iter().map(|f| f.as_slice()).collect();
                let trust=st.receiver_trust.as_ref().ok_or_else(||err!(EACCES,"ROLLUP_RECEIVER_TRUST_REQUIRED"))?;
                let list = trust.verify_series(&raw, &[vk_digest()])?;
                let total_slots = list.iter().map(|f| f.s_end - f.s_start + 1).sum();
                let last_used = list.last().map(|f| f.public_inputs.used_out).unwrap_or(0);
                let prof = list.first().map(|f| f.profile).unwrap_or(2);
                (
                    ZkResponse::SeriesVerified {
                        profile: prof,
                        total_slots,
                        used_out: last_used,
                    },
                    Some(json!({
                        "event": "ROLLUP_SERIES_VERIFIED",
                        "frames": list.len(),
                        "profile": prof,
                        "used_out": last_used,
                    })),
                )
            }
            ZkRequest::ReportFault(f) => {
                // GAP-12: daemons never self-report and peers cannot latch
                // the fleet. Only root (the ADR-012 supervisor's identity,
                // code-pinned per GAP-02) or the single dev-mode UID.
                if peer.uid != 0 && peer.uid != enclave_core::ipc::geteuid() {
                    fail!(EPERM, "FAULT_REPORTER_REJECTED", "uid {} may not report integrity faults", peer.uid);
                }
                // FS-705 §5.3 teardown already ran before sequence allocation,
                // for benign throttled restarts as well as strikes. It also
                // precedes this fallible quarantine persistence.
                let r = st.quarantine.report(f).map_err(|error| {
                    // A failed persistence attempt cannot become clear merely
                    // through daemon restart. Failure of this marker also
                    // remains an error and admission stays closed in memory.
                    self.latch_fence_debt(b"integrity-fault persistence uncertain; reconcile quarantine and relay state\n");
                    error
                })?;
                (
                    ZkResponse::Fault(r),
                    Some(json!({"event": "INTEGRITY_FAULT", "kind": f.kind, "response": r})),
                )
            }
            ZkRequest::Wipe => {
                // GAP-39: wiping is for the supervisor / operator, never a peer daemon.
                if peer.uid != 0 && peer.uid != enclave_core::ipc::geteuid() {
                    fail!(EPERM, "WIPE_PEER_REJECTED");
                }
                (ZkResponse::Ok, Some(json!({"event": "WITNESS_WIPED"})))
            }
            ZkRequest::GateEgress { d_jcs, chunk } => {
                st.quarantine.ensure_clear()?;
                self.check_release(generation)?;
                let ts_ns = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos() as u64;
                let d_jcs_hash: [u8; 32] = *blake3::hash(&d_jcs).as_bytes();
                let init_state = st.egress_streams.get(&d_jcs_hash).copied().unwrap_or(0);
                let proof = match crate::zk::redact::evaluate_and_prove_chunk_with_state(
                    &self.redact_key,
                    &d_jcs,
                    &chunk,
                    init_state,
                    ts_ns,
                ) {
                    Ok(p) => p,
                    Err(e) => {
                        st.egress_streams.remove(&d_jcs_hash);
                        return Err(e);
                    }
                };
                if chunk.is_empty() {
                    st.egress_streams.remove(&d_jcs_hash);
                } else {
                    st.egress_streams.insert(d_jcs_hash, proof.dfa_final_state);
                }
                let pi_redact = proof.to_bytes()?;
                (
                    ZkResponse::EgressGated {
                        approved: true,
                        chunk_hash: proof.chunk_hash,
                        d_jcs_hash: proof.d_jcs_hash,
                        pi_redact: ByteBuf::from(pi_redact),
                    },
                    Some(json!({
                        "event": "EGRESS_GATED",
                        "chunk_len": chunk.len(),
                        "d_jcs_hash": hex::encode(proof.d_jcs_hash),
                        "chunk_hash": hex::encode(proof.chunk_hash),
                    })),
                )
            }
            ZkRequest::UnquarantineQuorum {
                enrolled_keys,
                threshold,
                host_id,
                cdhash,
                generation,
                expires_at_ms,
                sigs,
                now_ms,
            } => {
                if peer.uid != 0 && peer.uid != enclave_core::ipc::geteuid() {
                    fail!(EPERM, "UNQUARANTINE_PEER_REJECTED", "Only root operator CLI may submit unquarantine grants");
                }
                let pol = if let (Some(keys), Some(th)) = (enrolled_keys, threshold) {
                    let vks: Vec<ed25519_dalek::VerifyingKey> = keys
                        .iter()
                        .filter_map(|k| <[u8; 32]>::try_from(k.as_slice()).ok())
                        .filter_map(|b| ed25519_dalek::VerifyingKey::from_bytes(&b).ok())
                        .collect();
                    enclave_crypto::multisig::QuorumPolicy::new(vks, th)?
                } else {
                    let pol_path = st.quarantine.dir().join("quorum_policy.json");
                    if pol_path.exists() {
                        let data = std::fs::read(&pol_path).map_err(|e| err!(EIO, "POLICY_READ", "{e}"))?;
                        #[derive(Deserialize)]
                        struct StoredPolicy {
                            keys: Vec<String>,
                            threshold: usize,
                        }
                        let stored: StoredPolicy = serde_json::from_slice(&data)
                            .map_err(|e| err!(EINVAL, "POLICY_PARSE", "{e}"))?;
                        let vks: Vec<ed25519_dalek::VerifyingKey> = stored
                            .keys
                            .iter()
                            .filter_map(|h| hex::decode(h).ok())
                            .filter_map(|k| <[u8; 32]>::try_from(k.as_slice()).ok())
                            .filter_map(|b| ed25519_dalek::VerifyingKey::from_bytes(&b).ok())
                            .collect();
                        enclave_crypto::multisig::QuorumPolicy::new(vks, stored.threshold)?
                    } else {
                        fail!(EINVAL, "MISSING_QUORUM_POLICY", "No quorum policy provided and none found in state");
                    }
                };
                st.quarantine.unquarantine_quorum_v2(
                    &pol,
                    &host_id,
                    &cdhash,
                    generation,
                    expires_at_ms,
                    &sigs,
                    now_ms,
                )?;
                let new_gen = st.quarantine.generation();
                (
                    ZkResponse::Unquarantined { new_generation: new_gen },
                    Some(json!({
                        "event": "UNQUARANTINE_QUORUM",
                        "host_id": host_id,
                        "new_generation": new_gen,
                    })),
                )
            }
            ZkRequest::UnquarantineFleet {
                grant_bytes,
                running_cdhash,
                now,
            } => {
                if peer.uid != 0 && peer.uid != enclave_core::ipc::geteuid() {
                    fail!(EPERM, "UNQUARANTINE_PEER_REJECTED", "Only root operator CLI may submit fleet unquarantine grants");
                }
                let tuf_root_path = st.quarantine.dir().join("tuf").join("root.json");
                let root_bytes = if tuf_root_path.exists() {
                    std::fs::read(&tuf_root_path).map_err(|e| err!(EIO, "TUF_ROOT_READ", "{e}"))?
                } else {
                    let support_root = std::path::Path::new("/Library/Application Support/EnterpriseEnclave/tuf/root.json");
                    if support_root.exists() {
                        std::fs::read(support_root).map_err(|e| err!(EIO, "TUF_ROOT_READ", "{e}"))?
                    } else {
                        fail!(EINVAL, "TUF_ROOT_MISSING", "TUF root.json not found in quarantine state or support dir");
                    }
                };
                let tuf = enclave_crypto::tuf::TufClient::bootstrap(&root_bytes)?;
                st.quarantine.unquarantine_fleet(
                    &tuf,
                    grant_bytes.as_slice(),
                    &running_cdhash,
                    now,
                )?;
                let new_gen = st.quarantine.generation();
                (
                    ZkResponse::Unquarantined { new_generation: new_gen },
                    Some(json!({
                        "event": "UNQUARANTINE_FLEET",
                        "new_generation": new_gen,
                    })),
                )
            }
        };
        debug_assert_eq!(
            st.slab.mode,
            SiliconMemoryMode::PacGuarded,
            "EMTE gate has no verified citation"
        );
        if let Some(e)=ev {
            let audited = (|| { if let Some(j)=self.journal_writer()?.as_mut() {j.append(seq,e)?;} Ok(()) })();
            if let Err(error) = audited {
                if _fence.is_some() { self.latch_fence_debt(b"authorized wipe/fault audit append uncertain; reconcile before proving\n"); }
                return Err(error);
            }
        }
        if matches!(&resp, ZkResponse::EgressGated { .. }) {
            enclave_core::ipc::attach_release_permit(self.release_permit(generation));
        }
        Ok(resp)
    }
}

#[cfg(test)]
#[path="memory_breach_tests.rs"]
mod memory_breach_tests;

#[cfg(test)]
#[path="retained_witness_tests.rs"]
mod retained_witness_tests;

#[cfg(test)]
#[path="release_fence_tests.rs"]
mod release_fence_tests;

#[cfg(test)]
#[path="controller_reply_tests.rs"]
mod controller_reply_tests;

#[cfg(test)]
#[path="retained_resource_service_tests.rs"]
mod retained_resource_service_tests;

#[cfg(test)]
#[path="thermal_service_tests.rs"]
mod thermal_service_tests;
