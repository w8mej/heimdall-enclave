//! UID 701 daemon service. `_llmagent` holds **no network sockets**: weights
//! arrive as read-only `SCM_RIGHTS` FDs from UID 702, only typed primitives,
//! byte strings and opaque handles cross the RPC boundary (no raw float,
//! KV-cache or recurrent-state tensor — `F-027`), and every class gate fails
//! closed.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use enclave_core::audit::AuditJournal;
use enclave_core::daemon::DaemonId;
use enclave_core::error::EnclaveResult;
use enclave_core::ipc::{DaemonStatus, PeerCredentials};
use enclave_core::label::{Conf, Label};
use enclave_core::profile::Profile;
use enclave_core::secret::SecretKey32;
use enclave_core::seq::RpcSequencer;
use enclave_core::{err, fail};
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use serde_json::json;

use crate::adapter::{CalibrationInput, EnclaveModelAdapter, Engine};
use crate::arena::{WeightBytes, WipeReport, ZeroizeTrigger};
use crate::classes::byte_concept::SurrogateVerifier;
use crate::classes::rlcd::{RlcdMode, RlcdOutput, RlcdRequest};
use crate::classes::speculative::ThermalProvider;
use crate::classes::world::{Action, Actuator, Frame, MicroCapabilities, Rect};
use crate::dfa::{ArgSchema, Dfa};
use crate::manifest::{ExecutionClass, ModelManifestV1};

/// IPC requests.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RunnerRequest {
    /// Status.
    Status,
    /// Bind a model: UID 701 resolves `cas_uri` from UID 702 (`SCM_RIGHTS`).
    Bind {
        /// Signed manifest JSON.
        manifest: ByteBuf,
        /// `cas://` URI of the weights.
        cas_uri: String,
        /// `enclave-calib-eval-v1` corpus (Class 1).
        calibration_corpus: Option<ByteBuf>,
    },
    /// UID 704 `declassify_enum` back end (Class 1, `Choice` mode).
    Declassify {
        /// Payload.
        payload: ByteBuf,
        /// `K`.
        cardinality: u64,
        /// Schema name.
        schema: String,
        /// The governed slot this release occupies (UID 703's signed epoch
        /// and `rpc_seq_u64`), journaled here under that epoch (GAP-27).
        #[serde(default)]
        slot: Option<enclave_core::seq::GovernedSlot>,
    },
    /// Class 1 with explicit mode / provenance.
    Classify {
        /// Payload.
        payload: ByteBuf,
        /// Mode.
        mode: RlcdMode,
        /// `K`.
        cardinality: u64,
        /// Entity keys.
        entities: Vec<String>,
        /// Confidentiality.
        conf: Conf,
    },
    /// Class 2 / AR: schema-constrained structured output.
    GenerateStructured {
        /// Tool-argument schema.
        schema: ArgSchema,
        /// Block length.
        len: u32,
        /// Optional prompt text (token-level AR backends only; byte-level
        /// reference engines refuse a non-empty prompt).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        prompt: Option<ByteBuf>,
    },
    /// Class 3: fork a session.
    SsmFork {
        /// Initial label.
        label: Label,
    },
    /// Class 3: ingest.
    SsmIngest {
        /// Session.
        session: u64,
        /// Label of these bytes.
        label: Label,
        /// Bytes.
        bytes: ByteBuf,
    },
    /// Class 3: generate.
    SsmGenerate {
        /// Session.
        session: u64,
        /// Bytes to generate.
        n: u32,
    },
    /// Class 3: exit.
    SsmExit {
        /// Session.
        session: u64,
    },
    /// Class 3: idempotently fork a runtime-minted turn scope. Only the
    /// authenticated runtime may assert the verified input label.
    SsmForkOwned {
        /// Random 256-bit runtime scope, recorded before sending this request.
        scope: [u8; 32],
        /// Provenance obtained by the runtime from its verified heap.
        label: Label,
    },
    /// Class 3: ingest into this authenticated runtime's scoped session.
    SsmIngestOwned {
        /// Runtime scope.
        scope: [u8; 32],
        /// Provenance obtained from the runtime's verified input handle.
        label: Label,
        /// Verified input bytes.
        bytes: ByteBuf,
    },
    /// Class 3: generate from this authenticated runtime's scoped session.
    SsmGenerateOwned {
        /// Runtime scope.
        scope: [u8; 32],
        /// Bytes to generate.
        n: u32,
    },
    /// Class 3: idempotently wipe a scope, including after an uncertain reply.
    SsmExitOwned {
        /// Runtime scope.
        scope: [u8; 32],
    },
    /// Class 4.
    Concept {
        /// Input.
        input: ByteBuf,
        /// Per-session surrogate MAC key (from UID 703 via 704).
        surrogate_key: Option<ByteBuf>,
    },
    /// Class 5: speculative / recurrent-depth decode.
    Think {
        /// Prompt.
        prompt: ByteBuf,
        /// Bytes.
        n: u32,
        /// Draft width.
        k: u32,
    },
    /// Class 6: plan one step.
    Plan {
        /// Frame width.
        w: u32,
        /// Frame height.
        h: u32,
        /// Gray pixels.
        px: ByteBuf,
        /// PII boxes (AX ∪ detector).
        pii_boxes: Vec<Rect>,
        /// Scroll velocity (px/s, integer).
        scroll_velocity: u32,
        /// Goal frame pixels (same size).
        goal_px: ByteBuf,
        /// Candidates.
        candidates: Vec<Action>,
        /// `B_micro` tool bitmask.
        tools_mask: u64,
        /// Allowed origins.
        origins: Vec<String>,
        /// Dispatch the selected action to the attached actuator. Absent means
        /// false: planning alone never acts, and leaves no observation owed.
        #[serde(default)]
        actuate: bool,
    },
    /// Class 6: observe after actuation (surprise gate).
    Observe {
        /// Width.
        w: u32,
        /// Height.
        h: u32,
        /// Pixels.
        px: ByteBuf,
        /// PII boxes.
        pii_boxes: Vec<Rect>,
    },
    /// Synchronous zeroization trigger.
    Zeroize(ZeroizeTrigger),
    /// UID 704 stops its own in-flight generation: output is withheld and
    /// nothing is wiped or unbound. Answered without the operation lock.
    CancelGeneration,
    /// Drop the bound model.
    Unbind,
}

// Move only world pixels out of the public movable request before admission.
// The private owner remains live across every early error and class mismatch;
// the dispatched enum keeps its metadata and empty pixel fields.
#[derive(Default)]
struct WorldPixels {
    input: ByteBuf,
    goal: ByteBuf,
}

// Rust drops struct fields in declaration order. Admitted pixels therefore
// scrub before the operation serial is released, including error returns.
// This does not drain requests still queued before serial admission.
struct WorldOperation<'a> {
    pixels: WorldPixels,
    _serial: Option<std::sync::MutexGuard<'a, ()>>,
}

impl WorldPixels {
    fn take(request: &mut RunnerRequest) -> Self {
        match request {
            RunnerRequest::Plan { px, goal_px, .. } => Self {
                input: std::mem::take(px), goal: std::mem::take(goal_px),
            },
            RunnerRequest::Observe { px, .. } => Self {
                input: std::mem::take(px), goal: ByteBuf::new(),
            },
            _ => Self::default(),
        }
    }
}

fn wipe_world_bytes(values: &mut [u8], _owner: &'static str) {
    for value in values.iter_mut() {
        // SAFETY: valid exclusively borrowed initialized byte.
        unsafe { std::ptr::write_volatile(value, 0); }
    }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    #[cfg(test)]
    world_owner_tests::observe(_owner, values.len(), values.iter().all(|v| *v == 0));
}

fn wipe_world_floats(values: &mut [f32], _owner: &'static str) {
    for value in values.iter_mut() {
        // SAFETY: valid exclusively borrowed initialized float.
        unsafe { std::ptr::write_volatile(value, 0.0); }
    }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    #[cfg(test)]
    world_owner_tests::observe(_owner, values.len(), values.iter().all(|v| v.to_bits() == 0));
}

impl Drop for WorldPixels {
    fn drop(&mut self) {
        wipe_world_bytes(self.input.as_mut(), "input");
        wipe_world_bytes(self.goal.as_mut(), "goal");
    }
}

// These latents are borrowed by the planner/comparison and never returned.
struct WorldLatent(Vec<f32>);
impl std::ops::Deref for WorldLatent {
    type Target = [f32];
    fn deref(&self) -> &[f32] { &self.0 }
}
impl Drop for WorldLatent {
    fn drop(&mut self) { wipe_world_floats(&mut self.0, "latent"); }
}

/// IPC responses (integers, bytes, handles and enums only).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RunnerResponse {
    /// Status.
    Status(DaemonStatus),
    /// Bound.
    Bound {
        /// Model id.
        model_id: String,
        /// Class.
        class: ExecutionClass,
        /// ECE in millionths (Class 1).
        ece_ppm: Option<u32>,
        /// Topology fingerprint.
        topology_fingerprint: String,
    },
    /// `declassify_enum` result.
    Declassified(u64),
    /// Class 1 typed output.
    Rlcd {
        /// Output.
        output: RlcdOutput,
        /// Millibits charged.
        millibits: i64,
    },
    /// Byte output.
    Text(ByteBuf),
    /// Session handle.
    Session(u64),
    /// Class 3 generation.
    Ssm {
        /// Session provenance; receivers must attach it to the output handle.
        label: Label,
        /// Output.
        output: ByteBuf,
        /// Anchors applied.
        anchors: u32,
        /// Boundary anchor applied.
        boundary_anchor: bool,
    },
    /// Class 6 plan.
    Planned {
        /// Action to execute.
        action: Action,
        /// Barrier vetoes.
        vetoes: u32,
        /// Whether UID 701 actuated it through the CDP sandbox.
        actuated: bool,
    },
    /// Arenas wiped.
    Wiped(u32),
    /// Ack.
    Ok,
}

/// Resolved weights: primary artifact bytes + companion layers (GAP-33).
#[derive(Debug)]
pub struct ResolvedWeights {
    /// Primary model weights (`safetensors`).
    pub primary: WeightBytes,
    /// Eagerly hydrated companion layers (e.g. `ece_calibration_lut`).
    pub companions: Vec<WeightBytes>,
}

/// Weight provider (UID 702 in production).
pub trait WeightSource: Send + Sync {
    /// Resolve a `cas://` URI to primary and companion read-only bytes.
    fn resolve(&self, cas_uri: &str) -> EnclaveResult<ResolvedWeights>;
    /// Fetch an independently TUF-verified model manifest by local target name.
    /// Implementations must not derive trust from the request manifest itself.
    fn fetch_manifest(&self, _model_id: &str) -> EnclaveResult<Vec<u8>> {
        fail!(EACCES, "MODEL_MANIFEST_TARGET_UNAVAILABLE")
    }
    /// Fetch corpus bytes by pinned digest if available.
    fn fetch_corpus(&self, _digest: &str) -> EnclaveResult<Vec<u8>> {
        Err(enclave_core::err!(EIO, "CORPUS_NOT_FOUND"))
    }
}

/// Configuration.
pub struct RunnerConfig {
    /// Explicit development IPC mode. Production admits only UID 704 for SSM;
    /// this mode additionally permits the current UID for isolated fixtures.
    pub dev_same_uid: bool,
    /// Profile.
    pub profile: Profile,
    /// Audit journal (`adapter-audit.jsonl`).
    pub audit_path: Option<PathBuf>,
    /// TUF-pinned BLAKE3 of `enclave-calib-eval-v1`.
    pub calib_corpus_blake3: Option<String>,
    /// Thermal telemetry factory.
    pub thermal: Box<dyn Fn() -> Box<dyn ThermalProvider> + Send + Sync>,
    /// Sandboxed CDP actuator, if a browser pipe was provided.
    pub actuator: Option<Box<dyn Actuator + Send>>,
    /// Persistent state (`<state>/adapter`): the pinned UID 703 epoch signer
    /// (GAP-27). `None` keeps the pin in memory.
    pub state_dir: Option<PathBuf>,
}

impl std::fmt::Debug for RunnerConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RunnerConfig")
            .field("profile", &self.profile)
            .finish()
    }
}

struct PendingStep {
    predicted: Vec<f32>,
}
impl Drop for PendingStep {
    fn drop(&mut self) { wipe_world_floats(&mut self.predicted, "pending"); }
}

struct SsmOwner {
    peer: PeerCredentials,
    scope: Option<[u8; 32]>,
    initial_label: Label,
}

struct State {
    dev_same_uid: bool,
    // Entries exist only while the corresponding task arena is live, so this
    // map has the same eight-session bound as the actual recurrent engine.
    ssm_owners: BTreeMap<u64, SsmOwner>,
    profile: Profile,
    adapter: Option<EnclaveModelAdapter>,
    busy: Option<String>,
    pending: Option<PendingStep>,
    seq: RpcSequencer,
    journal: Option<AuditJournal>,
    calib: Option<String>,
    thermal: Box<dyn Fn() -> Box<dyn ThermalProvider> + Send + Sync>,
    actuator: Option<Box<dyn Actuator + Send>>,
    vetoes: u64,
    surprise_aborts: u64,
    // Daemon-lifetime, durable release budget, independent of model bindings.
    release_ledger: enclave_core::qif::QifLedger,
    release_store: Option<enclave_core::sealed::SealedStore>,
    // Keep the exclusive OS lock for the complete service lifetime. Different
    // processes must never settle against independently loaded ledger copies.
    _release_lock: Option<std::fs::File>,
    release_fault: bool,
    // Retain actual measurements if their append fails. The journal's chain
    // may already have advanced, so fail closed until daemon restart rather
    // than retrying an ambiguous append or silently losing its measurements.
    ssm_expiry_audit_fault: Option<Vec<WipeReport>>,
}

/// The service.
pub struct RunnerService {
    state: Mutex<State>,
    operation: Mutex<()>,
    cancel: std::sync::atomic::AtomicBool,
    /// Stops the current generation's compute loop: set by every wipe and
    /// by the runtime's `CancelGeneration`, reset as each generation takes
    /// the operation lock (to the wipe flag, so a pending wipe still counts).
    generation_cancel: std::sync::atomic::AtomicBool,
    release_fence: Arc<ModelReleaseFence>,
    weights: Box<dyn WeightSource>,
    /// UID 703's epoch signer, pinned on first verified epoch (GAP-27).
    epochs: enclave_crypto::epoch::EpochVerifier,
}

// The serial covers fence establishment, core's bounded final socket handoff,
// and explicitly prepared bounded browser dispatch. Never acquire State or run
// model work, journal I/O, connection authentication or unbounded RPC under it.
// State's own mutex makes admission/cancellation transitions atomic.
#[derive(Default)]
struct ModelReleaseFence {
    serial: Arc<Mutex<()>>,
    state: Mutex<ModelReleaseState>,
    broken: std::sync::atomic::AtomicBool,
}
#[derive(Default)]
struct ModelReleaseState {
    epoch: u64,
    pending: usize,
    cleanup_fault: bool,
}
impl ModelReleaseFence {
    fn state(&self) -> EnclaveResult<std::sync::MutexGuard<'_, ModelReleaseState>> {
        self.state.lock().map_err(|_| {
            self.broken.store(true, std::sync::atomic::Ordering::Release);
            err!(EIO, "MODEL_RELEASE_STATE_POISONED")
        })
    }
    fn check(&self, state: &ModelReleaseState, epoch: u64) -> EnclaveResult<()> {
        if self.broken.load(std::sync::atomic::Ordering::Acquire)
            || state.cleanup_fault || state.pending != 0 || state.epoch != epoch
        {
            fail!(EAGAIN, "MODEL_RELEASE_FENCED");
        }
        Ok(())
    }
    fn capture(&self) -> EnclaveResult<u64> {
        let state = self.state()?;
        self.check(&state, state.epoch)?;
        Ok(state.epoch)
    }
    fn validate(&self, epoch: u64) -> EnclaveResult<()> {
        let state = self.state()?;
        self.check(&state, epoch)
    }
}

struct PendingWipe<'a> {
    service: &'a RunnerService,
    registered: bool,
    succeeded: bool,
    fence_error: Option<enclave_core::error::EnclaveError>,
}
impl Drop for PendingWipe<'_> {
    fn drop(&mut self) {
        use std::sync::atomic::Ordering;
        let fence = &self.service.release_fence;
        // Poison/overflow cannot be repaired by a later cleanup acknowledgment.
        // An ordinary failed cleanup stays latched until a complete retry.
        if let Ok(mut state) = fence.state() {
            let pending = if self.registered { state.pending.checked_sub(1) } else { Some(state.pending) };
            if let Some(pending) = pending {
                state.pending = pending;
                state.cleanup_fault = !self.succeeded;
                self.service.cancel.store(
                    state.pending != 0 || state.cleanup_fault || fence.broken.load(Ordering::Acquire),
                    Ordering::Release,
                );
            } else {
                fence.broken.store(true, Ordering::Release);
                self.service.cancel.store(true, Ordering::Release);
            }
        } else {
            self.service.cancel.store(true, Ordering::Release);
        }
    }
}

impl std::fmt::Debug for RunnerService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RunnerService")
    }
}

/// Open the configured private state before reading its keys or snapshots.
/// Existing permissions are validated rather than silently repaired. The
/// trusted directory owner/root can still replace the whole directory; this
/// does not provide an external anti-rollback authority.
fn lock_release_state(dir: &std::path::Path) -> EnclaveResult<std::fs::File> {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    enclave_core::fsutil::private_dir(dir)?;
    let metadata = std::fs::symlink_metadata(dir)
        .map_err(|error| err!(EIO, "RUNNER_STATE_OPEN", "{error}"))?;
    if !metadata.is_dir() || metadata.uid() != enclave_core::ipc::geteuid()
        || metadata.mode() & 0o777 != 0o700
    {
        fail!(EACCES, "RUNNER_STATE_UNSAFE");
    }
    let lock = std::fs::OpenOptions::new().read(true).write(true).create(true)
        .mode(0o600).custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(dir.join("runner-qif-ledger.lock"))
        .map_err(|error| err!(EIO, "RUNNER_STATE_OPEN", "{error}"))?;
    let metadata = lock.metadata().map_err(|error| err!(EIO, "RUNNER_STATE_OPEN", "{error}"))?;
    if !metadata.is_file() || metadata.uid() != enclave_core::ipc::geteuid()
        || metadata.mode() & 0o777 != 0o600 || metadata.nlink() != 1
    {
        fail!(EACCES, "RUNNER_STATE_UNSAFE");
    }
    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        fail!(EACCES, "RUNNER_QIF_BUSY");
    }
    // Reads inside SealedStore must not traverse attacker-provided leaf links.
    // The private directory excludes other daemon UIDs during subsequent I/O.
    for name in ["sealing.key", "runner-qif-ledger.sealed", "runner-qif-ledger.gen", "epoch-signer.sealed", "epoch-signer.gen"] {
        match std::fs::symlink_metadata(dir.join(name)) {
            Ok(m) if m.is_file() && m.uid() == enclave_core::ipc::geteuid()
                && m.mode() & 0o777 == 0o600 && m.nlink() == 1 => {},
            Ok(_) => fail!(EACCES, "RUNNER_STATE_UNSAFE"),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {},
            Err(error) => return Err(err!(EIO, "RUNNER_STATE_OPEN", "{error}")),
        }
    }
    Ok(lock)
}

fn frame(w: u32, h: u32, px: &[u8]) -> EnclaveResult<Frame> {
    if w == 0
        || h == 0
        || (w as usize).checked_mul(h as usize) != Some(px.len())
        || px.len() > 4 << 20
    {
        fail!(EINVAL, "FRAME_SHAPE");
    }
    Ok(Frame {
        w: w as usize,
        h: h as usize,
        px: px.to_vec(),
    })
}

impl RunnerService {
    // Authentication happens in the caller before this changes any state. An
    // already executing IPC handoff may complete within core's absolute timeout
    // before we acquire serial; no old handoff can succeed after this fence.
    fn begin_wipe(&self) -> PendingWipe<'_> {
        use std::sync::atomic::Ordering;
        let mut fence_error = None;
        let _release = self.release_fence.serial.lock().unwrap_or_else(|poison| {
            self.release_fence.broken.store(true, Ordering::Release);
            fence_error = Some(err!(EIO, "MODEL_RELEASE_LOCK_POISONED"));
            poison.into_inner()
        });
        let mut state = self.release_fence.state.lock().unwrap_or_else(|poison| {
            self.release_fence.broken.store(true, Ordering::Release);
            fence_error = Some(err!(EIO, "MODEL_RELEASE_STATE_POISONED"));
            poison.into_inner()
        });
        self.cancel.store(true, Ordering::Release);
        self.generation_cancel.store(true, Ordering::Release);
        if let Some(epoch) = state.epoch.checked_add(1) {
            state.epoch = epoch;
        } else {
            self.release_fence.broken.store(true, Ordering::Release);
            fence_error = Some(err!(EIO, "MODEL_RELEASE_EXHAUSTED"));
        }
        let registered = if let Some(pending) = state.pending.checked_add(1) {
            state.pending = pending;
            true
        } else {
            self.release_fence.broken.store(true, Ordering::Release);
            fence_error = Some(err!(EIO, "MODEL_RELEASE_EXHAUSTED"));
            false
        };
        // A terminal bookkeeping error denies the acknowledgment but must not
        // prevent the authorized wipe itself. Its permanent broken latch keeps
        // every previously captured epoch invalid even if it cannot advance.
        PendingWipe { service: self, registered, succeeded: false, fence_error }
    }

    fn check_release(&self, epoch: Option<u64>) -> EnclaveResult<()> {
        if let Some(epoch) = epoch { self.release_fence.validate(epoch)?; }
        Ok(())
    }

    fn release_response(&self, epoch: Option<u64>, response: RunnerResponse) -> EnclaveResult<RunnerResponse> {
        if let Some(epoch) = epoch {
            self.release_fence.validate(epoch)?;
            let fence = self.release_fence.clone();
            enclave_core::ipc::attach_release_permit(enclave_core::ipc::ReleasePermit::new(
                fence.serial.clone(), Arc::new(move || fence.validate(epoch)),
            ));
        }
        Ok(response)
    }

    /// Start.
    pub fn start(cfg: RunnerConfig, weights: Box<dyn WeightSource>) -> EnclaveResult<Arc<Self>> {
        let release_lock = cfg.state_dir.as_deref().map(lock_release_state).transpose()?;
        let epoch = enclave_core::seq::new_boot_epoch_id();
        let journal = match &cfg.audit_path {
            Some(p) => Some(AuditJournal::open(p, DaemonId::ModelRunner, epoch.clone())?),
            None => None,
        };
        let (release_ledger, release_store) = match cfg.state_dir.as_deref() {
            None => (enclave_core::qif::QifLedger::new(cfg.profile), None),
            Some(dir) => {
                let (mut store, loaded) =
                    enclave_core::sealed::SealedStore::open(dir, "runner-qif-ledger")?;
                let ledger = match loaded {
                    enclave_core::sealed::Loaded::Fresh => {
                        let ledger = enclave_core::qif::QifLedger::new(cfg.profile);
                        store.save_json(&ledger)?;
                        ledger
                    }
                    enclave_core::sealed::Loaded::State(bytes) => {
                        enclave_core::sealed::decode::<enclave_core::qif::QifLedger>(&bytes)?
                    }
                };
                if ledger.profile() != cfg.profile {
                    fail!(EACCES, "RUNNER_QIF_PROFILE_CHANGED");
                }
                (ledger, Some(store))
            }
        };
        let service = Arc::new(Self {
            state: Mutex::new(State {
                dev_same_uid: cfg.dev_same_uid,
                ssm_owners: BTreeMap::new(),
                profile: cfg.profile,
                adapter: None,
                busy: None,
                pending: None,
                seq: RpcSequencer::new(epoch, 0),
                journal,
                calib: cfg.calib_corpus_blake3,
                thermal: cfg.thermal,
                actuator: cfg.actuator,
                vetoes: 0,
                surprise_aborts: 0,
                release_ledger,
                release_store,
                _release_lock: release_lock,
                release_fault: false,
                ssm_expiry_audit_fault: None,
            }),
            weights,
            operation: Mutex::new(()),
            cancel: std::sync::atomic::AtomicBool::new(false),
            generation_cancel: std::sync::atomic::AtomicBool::new(false),
            release_fence: Arc::new(ModelReleaseFence::default()),
            epochs: enclave_crypto::epoch::EpochVerifier::open(cfg.state_dir.as_deref())?,
        });
        // A weak reference cannot keep the daemon/service alive. Never hold an
        // Arc or either service lock while sleeping between sweeps.
        let weak = Arc::downgrade(&service);
        std::thread::Builder::new().name("ssm-session-reaper".into())
            .spawn(move || {
                let mut reported_fault = false;
                loop {
                    std::thread::sleep(std::time::Duration::from_secs(1));
                    let Some(service) = weak.upgrade() else { break; };
                    if let Err(error) = service.reap_expired_ssm() {
                        if !reported_fault {
                            eprintln!("SSM session maintenance failed: {error}");
                            reported_fault = true;
                        }
                        // An audit fault blocks new work, never later cleanup.
                        // Continue measuring expired younger arenas without
                        // retrying an append whose durable outcome is unknown.
                    }
                }
            }).map_err(|error| err!(EIO, "SSM_REAPER_START", "{error}"))?;
        Ok(service)
    }

    fn reap_expired_ssm(&self) -> EnclaveResult<()> {
        let mut state = self.state.lock().map_err(|_| err!(EIO, "STATE_POISONED"))?;
        Self::reap_expired_ssm_locked(&mut state)
    }

    fn reap_expired_ssm_locked(st: &mut State) -> EnclaveResult<()> {
        let reports = match st.adapter.as_mut().map(|a| &mut a.engine) {
            Some(Engine::Ssm(dag)) => dag.reap_expired(),
            _ => Vec::new(),
        };
        Self::prune_ssm_owners(st);
        if let Some(retained) = st.ssm_expiry_audit_fault.as_mut() {
            retained.extend(reports);
            fail!(EIO, "SSM_LIFECYCLE_AUDIT_FAILED");
        }
        Self::record_ssm_expiry(st, reports)
    }

    fn prune_ssm_owners(st: &mut State) {
        match st.adapter.as_ref().map(|a| &a.engine) {
            Some(Engine::Ssm(dag)) => st.ssm_owners.retain(|id, _| dag.label(*id).is_some()),
            _ => st.ssm_owners.clear(),
        }
    }

    // `peer` comes from the kernel-verified IPC policy, never from a request
    // field. Production IPC also pins UID 704's code identity. Root operators
    // may perform emergency wipes, but cannot assert input provenance here.
    fn authorize_ssm(st: &State, peer: &PeerCredentials, req: &RunnerRequest)
        -> EnclaveResult<Option<u64>>
    {
        let (scope, raw_session, fork_label, is_exit) = match req {
            RunnerRequest::SsmFork { .. } => (None, None, None, false),
            RunnerRequest::SsmIngest { session, .. }
                | RunnerRequest::SsmGenerate { session, .. }
                | RunnerRequest::SsmExit { session } => (None, Some(*session), None, false),
            RunnerRequest::SsmForkOwned { scope, label } => (Some(scope), None, Some(*label), false),
            RunnerRequest::SsmIngestOwned { scope, .. }
                | RunnerRequest::SsmGenerateOwned { scope, .. } => (Some(scope), None, None, false),
            RunnerRequest::SsmExitOwned { scope } => (Some(scope), None, None, true),
            _ => return Ok(None),
        };
        if !is_runtime_peer(peer, st.dev_same_uid) {
            fail!(EACCES, "SSM_RUNTIME_REQUIRED");
        }
        if let Some(id) = raw_session {
            let owner = st.ssm_owners.get(&id).ok_or_else(|| err!(EINVAL, "UNKNOWN_SESSION"))?;
            if owner.scope.is_some() || owner.peer != *peer {
                fail!(EACCES, "SSM_SESSION_OWNER_MISMATCH");
            }
            return Ok(Some(id));
        }
        let Some(scope) = scope else { return Ok(None); };
        if let Some((id, owner)) = st.ssm_owners.iter().find(|(_, owner)| owner.scope.as_ref() == Some(scope)) {
            if owner.peer != *peer { fail!(EACCES, "SSM_SESSION_OWNER_MISMATCH"); }
            if fork_label.is_some_and(|label| label != owner.initial_label) {
                fail!(EACCES, "SSM_SCOPE_LABEL_MISMATCH");
            }
            return Ok(Some(*id));
        }
        if fork_label.is_some() || is_exit { return Ok(None); }
        fail!(EINVAL, "UNKNOWN_SESSION")
    }

    fn record_ssm_expiry(st: &mut State, reports: Vec<WipeReport>) -> EnclaveResult<()> {
        if reports.is_empty() { return Ok(()); }
        if let Some(retained) = st.ssm_expiry_audit_fault.as_mut() {
            retained.extend(reports);
            fail!(EIO, "SSM_LIFECYCLE_AUDIT_FAILED");
        }
        let record = (|| -> EnclaveResult<()> {
            if st.journal.is_some() {
                let seq = st.seq.next()?;
                let mut payload = json!({
                    "event": "SSM_SESSIONS_EXPIRED", "expired_sessions": reports.len(),
                });
                stamp_backend(&mut payload, st.adapter.as_ref());
                append_wipe_reports(&mut payload, &reports);
                st.journal.as_mut().unwrap().append(seq, payload)?;
            }
            Ok(())
        })();
        if record.is_err() { st.ssm_expiry_audit_fault = Some(reports); }
        record
    }

    /// Bind directly from bytes (CLI dev path and tests).
    pub fn bind_bytes(
        &self,
        manifest: &[u8],
        weights: &[u8],
        corpus: Option<&[u8]>,
    ) -> EnclaveResult<RunnerResponse> {
        let epoch = self.release_fence.capture()?;
        let _operation = self
            .operation
            .lock()
            .map_err(|_| err!(EIO, "OPERATION_POISONED"))?;
        self.release_fence.validate(epoch)?;
        let mut st = self.state.lock().map_err(|_| err!(EIO, "STATE_POISONED"))?;
        let response = Self::bind_locked(&mut st, manifest, weights, &[], corpus)?;
        self.release_fence.validate(epoch)?;
        Ok(response)
    }

    /// Bind directly from bytes with companion safety layers (GAP-33).
    pub fn bind_bytes_with_companions(
        &self,
        manifest: &[u8],
        weights: &[u8],
        companions: &[&[u8]],
        corpus: Option<&[u8]>,
    ) -> EnclaveResult<RunnerResponse> {
        let epoch = self.release_fence.capture()?;
        let _operation = self
            .operation
            .lock()
            .map_err(|_| err!(EIO, "OPERATION_POISONED"))?;
        self.release_fence.validate(epoch)?;
        let mut st = self.state.lock().map_err(|_| err!(EIO, "STATE_POISONED"))?;
        let response = Self::bind_locked(&mut st, manifest, weights, companions, corpus)?;
        self.release_fence.validate(epoch)?;
        Ok(response)
    }

    fn bind_locked(
        st: &mut State,
        manifest: &[u8],
        weights: &[u8],
        companions: &[&[u8]],
        corpus: Option<&[u8]>,
    ) -> EnclaveResult<RunnerResponse> {
        if st.ssm_expiry_audit_fault.is_some() {
            fail!(EIO, "SSM_LIFECYCLE_AUDIT_FAILED");
        }
        let m = ModelManifestV1::from_json(manifest)?;
        let calib = match (corpus, st.calib.as_deref()) {
            (Some(c), Some(p)) => Some(CalibrationInput {
                corpus: c,
                pinned_blake3: p,
            }),
            (Some(_), None) => fail!(EACCES, "ECE_CORPUS_UNPINNED"),
            (None, _) => None,
        };
        // Replacing a model wipes the previous one's arenas first.
        let replaced_wipes = st
            .adapter
            .take()
            .map(|mut old| wipe_engine_reports(&mut old.engine, ZeroizeTrigger::TaskExit))
            .unwrap_or_default();
        // The old model is dropped: hand its freed pages back before the new
        // one parses its header and tokenizer, so they never stack up.
        release_freed_memory();
        // Explicit replacement ends the old model's observation obligation,
        // including when admission of the new model subsequently refuses.
        st.pending = None;
        st.ssm_owners.clear();
        let admission = (|| -> EnclaveResult<_> {
            let a = EnclaveModelAdapter::bind_with_companions(
                m,
                weights,
                companions,
                st.profile,
                calib,
                (st.thermal)(),
            )?;
            let fp = a.topology_fingerprint.clone();
            Ok((a, fp))
        })();
        let (a, fp) = match admission {
            Ok(bound) => bound,
            Err(error) => {
                record_failed_wipes(
                    st,
                    None,
                    "MODEL_BIND_FAILED",
                    &error.reason,
                    &replaced_wipes,
                )?;
                return Err(error);
            }
        };
        let resp = RunnerResponse::Bound {
            model_id: a.manifest.model_id.clone(),
            class: a.manifest.execution_class,
            ece_ppm: a.ece.map(|e| (e * 1e6).round() as u32),
            topology_fingerprint: fp.clone(),
        };
        st.adapter = Some(a);
        // Bind-time parsing (header JSON, tokenizer) is freed by now.
        release_freed_memory();
        let seq = st.seq.next()?;
        if let Some(j) = st.journal.as_mut() {
            j.append(seq, {
                let mut payload = json!({"event": "MODEL_BOUND", "topology_fingerprint_blake3": fp,
                    "phys_footprint_bytes": own_footprint()});
                append_wipe_reports(&mut payload, &replaced_wipes);
                payload
            })?;
        }
        Ok(resp)
    }

    // Caller holds operation through restoration. Bind/unbind/other generation
    // cannot race the temporarily extracted adapter; Zeroize signals cancel first.
    /// A wipe or the runtime's cancel has asked the current generation to stop.
    fn generation_cancelled(&self) -> bool {
        use std::sync::atomic::Ordering;
        self.cancel.load(Ordering::Acquire) || self.generation_cancel.load(Ordering::Acquire)
    }

    fn generate_outside_state(
        &self,
        req: RunnerRequest,
        pace: impl FnOnce(std::time::Duration),
    ) -> EnclaveResult<RunnerResponse> {
        if self.generation_cancelled() {
            fail!(EAGAIN, "GENERATION_CANCELLED");
        }
        let mut st = self.state.lock().map_err(|_| err!(EIO, "STATE_POISONED"))?;
        if st.ssm_expiry_audit_fault.is_some() { fail!(EIO, "SSM_LIFECYCLE_AUDIT_FAILED"); }
        let mut a = st
            .adapter
            .take()
            .ok_or_else(|| err!(EPERM, "MODEL_NOT_BOUND"))?;
        st.busy = Some(format!(
            "busy model={} class={}",
            a.manifest.model_id,
            a.manifest.execution_class.name()
        ));
        drop(st);
        let now = enclave_core::audit::now_utc_ms();
        let mut reports = Vec::new();
        let result = (|| -> EnclaveResult<RunnerResponse> {
            let output = match (req, &mut a.engine) {
                (RunnerRequest::GenerateStructured { schema, len, prompt }, Engine::Diffusion(g)) => {
                    let dfa = Dfa::compile(&schema)?;
                    let (result, wipe) = if g.is_token_level() {
                        // `len` counts token positions for a real checkpoint.
                        g.generate_tokens_cancellable_with_wipe(
                            &dfa,
                            len as usize,
                            prompt.as_ref().map(|p| p.as_slice()).unwrap_or_default(),
                            &mut a.attest,
                            &self.generation_cancel,
                        )
                    } else {
                        if prompt.is_some_and(|p| !p.is_empty()) {
                            fail!(EINVAL, "PROMPT_UNSUPPORTED_BY_BACKEND");
                        }
                        g.generate_cancellable_with_wipe(
                            &dfa,
                            len as usize,
                            &mut a.attest,
                            &self.generation_cancel,
                        )
                    };
                    reports.extend(wipe);
                    let r = result?;
                    r.output
                }
                (RunnerRequest::GenerateStructured { schema, len, prompt }, Engine::Ar(b)) => {
                    let dfa = Dfa::compile(&schema)?;
                    crate::classes::ar::decode_prompted_cancellable(
                        b.as_ref(),
                        prompt.as_ref().map(|p| p.as_slice()).unwrap_or_default(),
                        &dfa,
                        len as usize,
                        a.controls.max_output_bytes,
                        &mut a.attest,
                        Some(&self.generation_cancel),
                    )?
                }
                (RunnerRequest::Think { prompt, n, k }, Engine::Depth(g)) => {
                    let (result, wipes) = g.speculate_cancellable_with_wipes(
                        &prompt,
                        n as usize,
                        k as usize,
                        &mut a.attest,
                        &self.generation_cancel,
                    );
                    reports.extend(wipes);
                    result?.0
                }
                _ => fail!(EACCES, "REQUEST_CLASS_MISMATCH"),
            };
            if self.generation_cancelled() {
                fail!(EAGAIN, "GENERATION_CANCELLED");
            }
            Ok(RunnerResponse::Text(ByteBuf::from(output)))
        })();
        let mut st = self.state.lock().map_err(|_| err!(EIO, "STATE_POISONED"))?;
        let class = a.manifest.execution_class.name();
        let digest = a.attest.operator_family_log_digest();
        let cadence = a.controls.cadence_ms;
        st.adapter = Some(a);
        st.busy = None;
        drop(st);
        if result.is_ok() {
            if let Some(tick) = cadence {
                let wait = tick - enclave_core::audit::now_utc_ms().saturating_sub(now) % tick;
                pace(std::time::Duration::from_millis(wait));
            }
        }
        // Cadence is part of the request lifetime. A wipe may signal while we
        // wait without the state lock; journal the final release decision with
        // every measurement retained, including cancellation during that wait.
        let mut st = self.state.lock().map_err(|_| err!(EIO, "STATE_POISONED"))?;
        let result = if self.generation_cancelled() {
            Err(err!(EAGAIN, "GENERATION_CANCELLED"))
        } else {
            result
        };
        // Per-request buffers (logits rows, token arrays) are freed by now;
        // return their pages so the ceiling does not count retained heap.
        release_freed_memory();
        let seq = st.seq.next()?;
        let mut payload = json!({"event":"GENERATION", "execution_class_declared":class,
            "reference_operator_family_log_blake3":digest, "succeeded":result.is_ok(),
            "phys_footprint_bytes": own_footprint()});
        stamp_backend(&mut payload, st.adapter.as_ref());
        if let Some(j) = st.journal.as_mut() {
            append_wipe_reports(&mut payload, &reports);
            j.append(seq, payload)?;
        }
        result
    }

    /// Handle one request.
    pub fn handle(
        &self,
        peer: &PeerCredentials,
        req: RunnerRequest,
    ) -> EnclaveResult<RunnerResponse> {
        self.handle_with_deadline_and_pacer(peer, req, None, std::thread::sleep)
    }

    /// Handle with a trusted local absolute actuation deadline. This can only
    /// shorten the inherited bounded transport window; it never grants authority
    /// or extends inference, enrollment or the complete critical ceremony cap.
    pub fn handle_before(
        &self, peer: &PeerCredentials, req: RunnerRequest, deadline: std::time::Instant,
    ) -> EnclaveResult<RunnerResponse> {
        self.handle_with_deadline_and_pacer(peer, req, Some(deadline), std::thread::sleep)
    }

    #[cfg(test)]
    fn handle_with_pacer(
        &self, peer: &PeerCredentials, req: RunnerRequest, pace: impl FnOnce(std::time::Duration),
    ) -> EnclaveResult<RunnerResponse> {
        self.handle_with_deadline_and_pacer(peer, req, None, pace)
    }

    // Production always uses thread::sleep. A private per-call pacer lets the
    // concurrency regression synchronize precisely inside the cadence wait.
    fn handle_with_deadline_and_pacer(
        &self,
        peer: &PeerCredentials,
        mut req: RunnerRequest,
        caller_deadline: Option<std::time::Instant>,
        pace: impl FnOnce(std::time::Duration),
    ) -> EnclaveResult<RunnerResponse> {
        let world_pixels = WorldPixels::take(&mut req);
        if matches!(&req, RunnerRequest::Bind { .. } | RunnerRequest::Unbind)
            && peer.uid != 0
            && peer.uid != enclave_core::ipc::geteuid()
        {
            fail!(EPERM, "MODEL_ADMIN_REQUIRED");
        }
        // Generation is reachable only through UID 704's turn lifecycle, which
        // sources prompts from verified handles and seals every output.
        if matches!(&req, RunnerRequest::GenerateStructured { .. } | RunnerRequest::Think { .. }
            | RunnerRequest::Plan { .. } | RunnerRequest::Concept { .. })
        {
            let dev_same_uid = self.state.lock().map_err(|_| err!(EIO, "STATE_POISONED"))?.dev_same_uid;
            if !is_runtime_peer(peer, dev_same_uid) {
                fail!(EACCES, "GENERATION_RUNTIME_REQUIRED");
            }
        }
        // The runtime's own cancel: a flag, never the operation lock or a wipe.
        if matches!(&req, RunnerRequest::CancelGeneration) {
            let dev_same_uid = self.state.lock().map_err(|_| err!(EIO, "STATE_POISONED"))?.dev_same_uid;
            if !is_runtime_peer(peer, dev_same_uid) {
                fail!(EPERM, "CANCEL_RUNTIME_REQUIRED");
            }
            self.generation_cancel.store(true, std::sync::atomic::Ordering::Release);
            return Ok(RunnerResponse::Ok);
        }
        // Wipe signals cancellation before waiting for the active generation.
        // Status never takes this operation lock and can read the short-lived state lock.
        let _pending_wipe = if matches!(&req, RunnerRequest::Zeroize(_)) {
            if peer.uid != 0 && peer.uid != enclave_core::ipc::geteuid() {
                fail!(EPERM, "WIPE_PEER_REJECTED");
            }
            Some(self.begin_wipe())
        } else {
            None
        };
        // Capture before waiting for operation: a queued request must not gain
        // fresh authority merely because a complete wipe ran while it waited.
        let epoch = if matches!(&req, RunnerRequest::Status | RunnerRequest::Zeroize(_)
            | RunnerRequest::Unbind | RunnerRequest::SsmExit { .. } | RunnerRequest::SsmExitOwned { .. })
        { None } else { Some(self.release_fence.capture()?) };
        #[cfg(test)]
        release_fence_tests::after_capture();
        let operation = if matches!(&req, RunnerRequest::Status) {
            None
        } else {
            Some(
                self.operation
                    .lock()
                    .map_err(|_| err!(EIO, "OPERATION_POISONED"))?,
            )
        };
        let world_operation = WorldOperation { pixels: world_pixels, _serial: operation };
        // Drop cleanup registration before operation unlock, including errors;
        // only the fully journaled successful Zeroize clears a previous fault.
        let mut pending_wipe = _pending_wipe;
        self.check_release(epoch)?;
        if matches!(&req, RunnerRequest::GenerateStructured { .. } | RunnerRequest::Think { .. }
            | RunnerRequest::Plan { .. } | RunnerRequest::Concept { .. }
            | RunnerRequest::SsmGenerate { .. } | RunnerRequest::SsmGenerateOwned { .. })
        {
            use std::sync::atomic::Ordering;
            self.generation_cancel.store(self.cancel.load(Ordering::Acquire), Ordering::Release);
        }
        if matches!(
            &req,
            RunnerRequest::GenerateStructured { .. } | RunnerRequest::Think { .. }
        ) {
            let response = self.generate_outside_state(req, pace)?;
            return self.release_response(epoch, response);
        }
        // Bind performs IPC to UID 702 before taking the state lock.
        if let RunnerRequest::Bind {
            manifest,
            cas_uri,
            calibration_corpus,
        } = &req
        {
            {
                let state = self.state.lock().map_err(|_| err!(EIO, "STATE_POISONED"))?;
                if state.ssm_expiry_audit_fault.is_some() { fail!(EIO, "SSM_LIFECYCLE_AUDIT_FAILED"); }
            }
            let candidate = ModelManifestV1::from_json(manifest)?;
            model_manifest_target(&candidate.model_id)?;
            let signed = self.weights.fetch_manifest(&candidate.model_id)?;
            if signed != manifest.as_ref() {
                fail!(
                    EACCES,
                    "MODEL_MANIFEST_UNSIGNED",
                    "inline manifest must match the TUF target bytes"
                );
            }
            if cas_uri != &candidate.artifact.cas_uri {
                fail!(EACCES, "MODEL_ARTIFACT_URI_MISMATCH");
            }
            let res = self.weights.resolve(cas_uri)?;
            let comp_slices: Vec<&[u8]> = res.companions.iter().map(|c| c.as_slice()).collect();
            let mut st = self.state.lock().map_err(|_| err!(EIO, "STATE_POISONED"))?;
            let corpus_bytes = match calibration_corpus.as_deref() {
                Some(c) => Some(c.to_vec()),
                None => {
                    if let Some(pin) = &st.calib {
                        Some(self.weights.fetch_corpus(pin)?)
                    } else {
                        None
                    }
                }
            };
            self.check_release(epoch)?;
            let response = Self::bind_locked(
                &mut st,
                manifest,
                res.primary.as_slice(),
                &comp_slices,
                corpus_bytes.as_deref(),
            )?;
            return self.release_response(epoch, response);
        }
        let mut g = self.state.lock().map_err(|_| err!(EIO, "STATE_POISONED"))?;
        let st = &mut *g;
        // Record expired arenas before request dispatch, so a later request
        // error cannot discard their actual reports. Emergency cleanup remains
        // available after an ambiguous journal failure; new work stays blocked.
        // Check ownership before either ordinary dispatch or fault-latched
        // cleanup; a guessed handle must never wipe another caller's arena.
        // Reaping is independent trusted maintenance, including after faults.
        if st.ssm_expiry_audit_fault.is_some() {
            // Faulted requests also reclaim newly expired arenas; discard only
            // the already-known fault result, retaining every actual report.
            let _ = Self::reap_expired_ssm_locked(st);
        } else {
            Self::reap_expired_ssm_locked(st)?;
        }
        let owned_session = if st.ssm_expiry_audit_fault.is_some()
            && !matches!(&req, RunnerRequest::SsmExit { .. } | RunnerRequest::SsmExitOwned { .. })
        {
            // New work remains fault-latched, even if its session expired in
            // this sweep. Only cleanup needs a live-owner lookup on this path.
            None
        } else {
            Self::authorize_ssm(st, peer, &req)?
        };
        let fork_scope = match &req {
            RunnerRequest::SsmForkOwned { scope, .. } => Some(*scope),
            _ => None,
        };
        if st.ssm_expiry_audit_fault.is_some() {
            let reports = match &req {
                RunnerRequest::Zeroize(t) => {
                    st.pending = None;
                    st.adapter.as_mut().map(|a| wipe_engine_reports(&mut a.engine, *t)).unwrap_or_default()
                }
                RunnerRequest::Unbind => {
                    st.pending = None;
                    st.adapter.take().map(|mut a| wipe_engine_reports(&mut a.engine, ZeroizeTrigger::TaskExit)).unwrap_or_default()
                }
                RunnerRequest::SsmExit { session } => match st.adapter.as_mut().map(|a| &mut a.engine) {
                    Some(Engine::Ssm(dag)) => dag.exit(*session).ok().into_iter().collect(),
                    _ => Vec::new(),
                },
                RunnerRequest::SsmExitOwned { .. } => match (owned_session, st.adapter.as_mut().map(|a| &mut a.engine)) {
                    (Some(session), Some(Engine::Ssm(dag))) => dag.exit(session).ok().into_iter().collect(),
                    _ => Vec::new(),
                },
                _ => Vec::new(),
            };
            Self::prune_ssm_owners(st);
            st.ssm_expiry_audit_fault.as_mut().unwrap().extend(reports);
            if !matches!(&req, RunnerRequest::Status) { fail!(EIO, "SSM_LIFECYCLE_AUDIT_FAILED"); }
        }
        let seq = st.seq.next()?;
        // GAP-27: a declassification is a governed release; it is journaled
        // under UID 703's verified epoch and slot.
        let governed = match &req {
            RunnerRequest::Declassify { slot: Some(s), .. } => {
                self.epochs.check(&s.epoch)?;
                Some((s.epoch.boot_epoch_id.clone(), s.rpc_seq_u64))
            }
            RunnerRequest::Declassify { slot: None, .. } => fail!(
                EINVAL,
                "DECLASSIFY_SLOT_REQUIRED",
                "declassification occupies a UID 703 slot"
            ),
            _ => None,
        };
        let now_ms = enclave_core::audit::now_utc_ms();
        let mut qif_mb = 0i64;
        let mut boundary = false;
        let mut wipe_reports = Vec::new();
        let resp = match req {
            RunnerRequest::Bind { .. } => fail!(EINVAL, "UNREACHABLE"),
            // An already exited/expired scope, including after daemon restart
            // or Unbind, is safe to acknowledge without requiring a model.
            RunnerRequest::SsmExitOwned { .. } if owned_session.is_none() => RunnerResponse::Wiped(0),
            RunnerRequest::Status => {
                let mut state = match &st.adapter {
                    Some(a) => format!(
                        "model={} class={} profile={}",
                        a.manifest.model_id,
                        a.manifest.execution_class.name(),
                        st.profile
                    ),
                    None => st
                        .busy
                        .clone()
                        .unwrap_or_else(|| format!("unbound profile={}", st.profile)),
                };
                if st.ssm_expiry_audit_fault.is_some() { state.push_str(" ssm_lifecycle=audit_failed"); }
                return Ok(RunnerResponse::Status(DaemonStatus {
                    daemon_uid: DaemonId::ModelRunner.uid(),
                    binary: DaemonId::ModelRunner.binary().into(),
                    pid: std::process::id(),
                    rss_bytes: enclave_core::resource::current_rss_bytes().unwrap_or(0),
                    rss_ceiling_bytes: DaemonId::ModelRunner.rss_ceiling_bytes(),
                    boot_epoch_id: st.seq.boot_epoch_id().into(),
                    rpc_seq_u64: st.seq.current(),
                    state,
                    phys_footprint_bytes: enclave_core::resource::current_phys_footprint_bytes()
                        .unwrap_or(0),
                    phys_footprint_source: enclave_core::resource::current_phys_footprint_source(),
                }));
            }
            RunnerRequest::Zeroize(t) => {
                // GAP-39: wiping is for the supervisor / operator, never a peer daemon.
                if peer.uid != 0 && peer.uid != enclave_core::ipc::geteuid() {
                    fail!(EPERM, "WIPE_PEER_REJECTED");
                }
                let n = match st.adapter.as_mut() {
                    Some(a) => {
                        wipe_reports = wipe_engine_reports(&mut a.engine, t);
                        wipe_reports.len() as u32
                    }
                    None => 0,
                };
                st.pending = None;
                RunnerResponse::Wiped(n)
            }
            RunnerRequest::Unbind => {
                if let Some(mut a) = st.adapter.take() {
                    wipe_reports = wipe_engine_reports(&mut a.engine, ZeroizeTrigger::TaskExit);
                }
                st.pending = None;
                release_freed_memory();
                RunnerResponse::Ok
            }
            other => {
                let owners = &mut st.ssm_owners;
                let a = st
                    .adapter
                    .as_mut()
                    .ok_or_else(|| err!(EPERM, "MODEL_NOT_BOUND"))?;
                match (other, &mut a.engine) {
                    (
                        RunnerRequest::Declassify {
                            payload,
                            cardinality,
                            schema,
                            ..
                        },
                        Engine::Rlcd(g),
                    ) => {
                        if schema.is_empty() || schema.len() > 128 {
                            fail!(EINVAL, "DECLASSIFY_SCHEMA");
                        }
                        let (o, mb) = g.evaluate(
                            &RlcdRequest {
                                input: &payload,
                                cardinality,
                                mode: RlcdMode::Choice,
                                entities: &[],
                                conf: Conf::C3,
                            },
                            now_ms,
                        )?;
                        qif_mb = mb;
                        RunnerResponse::Declassified(o.index())
                    }
                    (
                        RunnerRequest::Classify {
                            payload,
                            mode,
                            cardinality,
                            entities,
                            conf,
                        },
                        Engine::Rlcd(g),
                    ) => {
                        let (output, millibits) = g.evaluate(
                            &RlcdRequest {
                                input: &payload,
                                cardinality,
                                mode,
                                entities: &entities,
                                conf,
                            },
                            now_ms,
                        )?;
                        qif_mb = millibits;
                        RunnerResponse::Rlcd { output, millibits }
                    }
                    (ssm @ (RunnerRequest::SsmFork { .. } | RunnerRequest::SsmIngest { .. }
                        | RunnerRequest::SsmGenerate { .. } | RunnerRequest::SsmExit { .. }
                        | RunnerRequest::SsmForkOwned { .. } | RunnerRequest::SsmIngestOwned { .. }
                        | RunnerRequest::SsmGenerateOwned { .. } | RunnerRequest::SsmExitOwned { .. }), Engine::Ssm(d)) => {
                        let used_session = match &ssm {
                            RunnerRequest::SsmIngest { session, .. } | RunnerRequest::SsmGenerate { session, .. } => Some(*session),
                            RunnerRequest::SsmIngestOwned { .. } | RunnerRequest::SsmGenerateOwned { .. } => owned_session,
                            _ => None,
                        };
                        let result = (|| -> EnclaveResult<RunnerResponse> {
                            Ok(match ssm {
                                RunnerRequest::SsmFork { label } | RunnerRequest::SsmForkOwned { label, .. } => {
                                    if let Some(id) = owned_session { RunnerResponse::Session(id) }
                                    else {
                                        let id = d.fork(label)?;
                                        owners.insert(id, SsmOwner {
                                            peer: peer.clone(), scope: fork_scope, initial_label: label,
                                        });
                                        RunnerResponse::Session(id)
                                    }
                                }
                                RunnerRequest::SsmIngest { session, label, bytes } => {
                                    d.ingest(session, label, &bytes, &mut a.attest)?;
                                    RunnerResponse::Ok
                                }
                                RunnerRequest::SsmIngestOwned { label, bytes, .. } => {
                                    d.ingest(owned_session.expect("authorized live scope"), label, &bytes, &mut a.attest)?;
                                    RunnerResponse::Ok
                                }
                                RunnerRequest::SsmGenerate { n, .. }
                                    | RunnerRequest::SsmGenerateOwned { n, .. } => {
                                    let session = owned_session.expect("authorized live session");
                                    let r = d.generate_cancellable(session, n as usize, &mut a.attest, Some(&self.generation_cancel))?;
                                    boundary = r.hispa_boundary_anchor_applied;
                                    RunnerResponse::Ssm { label: r.label, output: ByteBuf::from(r.output),
                                        anchors: r.anchors, boundary_anchor: r.hispa_boundary_anchor_applied }
                                }
                                RunnerRequest::SsmExit { session } => {
                                    wipe_reports.push(d.exit(session)?);
                                    RunnerResponse::Wiped(1)
                                }
                                RunnerRequest::SsmExitOwned { .. } => {
                                    match owned_session {
                                        Some(session) => { wipe_reports.push(d.exit(session)?); RunnerResponse::Wiped(1) }
                                        None => RunnerResponse::Wiped(0),
                                    }
                                }
                                _ => unreachable!(),
                            })
                        })();
                        // A deadline may pass inside a recurrent operation. Reap
                        // before propagating its error or releasing any output.
                        let expired = d.reap_expired();
                        let used_session = used_session.or_else(|| match &result {
                            Ok(RunnerResponse::Session(id)) => Some(*id),
                            _ => None,
                        });
                        let used_session_expired = used_session.is_some_and(|id| d.label(id).is_none());
                        Self::prune_ssm_owners(st);
                        Self::record_ssm_expiry(st, expired)?;
                        let response = result?;
                        if used_session_expired { fail!(EAGAIN, "SSM_SESSION_EXPIRED"); }
                        response
                    }
                    (
                        RunnerRequest::Concept {
                            input,
                            surrogate_key,
                        },
                        Engine::Concept(g),
                    ) => {
                        let v = match surrogate_key {
                            Some(k) => Some(SurrogateVerifier::new(SecretKey32::new(
                                <[u8; 32]>::try_from(&k[..])
                                    .map_err(|_| err!(EINVAL, "SURROGATE_KEY"))?,
                            ))),
                            None => None,
                        };
                        let (result, wipe) = g.run_with_wipe(&input, v.as_ref(), &mut a.attest);
                        wipe_reports.extend(wipe);
                        let r = match result {
                            Ok(result) => result,
                            Err(error) => {
                                record_failed_wipes(
                                    st,
                                    Some(seq),
                                    "CONCEPT_FAILED",
                                    &error.reason,
                                    &wipe_reports,
                                )?;
                                return Err(error);
                            }
                        };
                        RunnerResponse::Text(ByteBuf::from(r.output))
                    }
                    (
                        RunnerRequest::Plan {
                            w,
                            h,
                            px: _,
                            pii_boxes,
                            scroll_velocity,
                            goal_px: _,
                            candidates,
                            tools_mask,
                            origins,
                            actuate,
                        },
                        Engine::World(g),
                    ) => {
                        // One released step owns one surprise comparison. A new
                        // plan cannot replace that prediction or actuate again
                        // before its observation (or an explicit episode reset).
                        if st.pending.is_some() {
                            fail!(EAGAIN, "WORLD_OBSERVATION_REQUIRED");
                        }
                        let s = WorldLatent(g.observe(frame(w, h, &world_operation.pixels.input)?, &pii_boxes, scroll_velocity as f32)?);
                        let goal = WorldLatent(g.observe(frame(w, h, &world_operation.pixels.goal)?, &[], 0.0)?);
                        let policy = MicroCapabilities {
                            tools: tools_mask,
                            origins,
                        };
                        let mut plan = g.plan(&s, &goal, &candidates, &policy, &mut a.attest)?;
                        let pending = PendingStep {
                            predicted: std::mem::take(&mut plan.predicted),
                        };
                        self.check_release(epoch)?;
                        st.vetoes += plan.vetoes as u64;
                        // A generic actuator error cannot prove that no effect
                        // occurred. Keep the obligation even on preflight errors
                        // or a lost reply; only observation/reset can clear it.
                        // A plan that does not ask to act owes no observation.
                        if actuate { st.pending = Some(pending); }
                        let actuator = if actuate { st.actuator.as_mut() } else { None };
                        let actuated = match actuator {
                            Some(act) => {
                                // Authentication/connection may wait, so preparation
                                // stays outside serial. The inherited core handoff
                                // cap starts here, after inference, and can only be
                                // shortened by the caller's trusted local deadline.
                                let inherited = std::time::Instant::now() + enclave_core::ipc::RELEASE_TIMEOUT;
                                let deadline = caller_deadline.map_or(inherited, |end| end.min(inherited));
                                if std::time::Instant::now() >= deadline { fail!(ETIMEDOUT, "CDP_DEADLINE"); }
                                self.check_release(epoch)?;
                                let dispatch = (|| {
                                    act.prepare_bounded(&plan.action, deadline)?;
                                    let _release = self.release_fence.serial.lock().map_err(|_| {
                                        self.release_fence.broken.store(true, std::sync::atomic::Ordering::Release);
                                        err!(EIO, "MODEL_RELEASE_LOCK_POISONED")
                                    })?;
                                    self.check_release(epoch)?;
                                    if std::time::Instant::now() >= deadline { fail!(ETIMEDOUT, "CDP_DEADLINE"); }
                                    // Only implementations explicitly providing a whole
                                    // nonblocking absolute deadline can enter this gate.
                                    // An accepted pre-fence command may be observed by
                                    // the browser later; it cannot be recalled.
                                    act.execute_bounded(deadline)
                                })();
                                if dispatch.is_err() { act.cancel_bounded(); }
                                dispatch?;
                                true
                            }
                            None => false,
                        };
                        RunnerResponse::Planned {
                            action: plan.action,
                            vetoes: plan.vetoes,
                            actuated,
                        }
                    }
                    (
                        RunnerRequest::Observe {
                            w,
                            h,
                            px: _,
                            pii_boxes,
                        },
                        Engine::World(g),
                    ) => {
                        let p = st
                            .pending
                            .as_ref()
                            .ok_or_else(|| err!(EINVAL, "NO_PENDING_STEP"))?;
                        // Invalid frames/PII boxes and encoder failures must not
                        // erase a released step's required comparison. Consume
                        // its prediction only after the comparison completes.
                        let obs = WorldLatent(g.observe(frame(w, h, &world_operation.pixels.input)?, &pii_boxes, 0.0)?);
                        let comparison = g.surprise(&p.predicted, &obs);
                        st.pending = None;
                        if let Err(e) = comparison {
                            st.surprise_aborts += 1;
                            wipe_reports.extend(g.end_episode());
                            record_failed_wipes(
                                st,
                                Some(seq),
                                "WORLD_SURPRISE_ABORT",
                                &e.reason,
                                &wipe_reports,
                            )?;
                            return Err(e);
                        }
                        RunnerResponse::Ok
                    }
                    (r, e) => fail!(
                        EACCES,
                        "REQUEST_CLASS_MISMATCH",
                        "{} cannot serve {:?}",
                        engine_class(e),
                        std::mem::discriminant(&r)
                    ),
                }
            }
        };
        Self::prune_ssm_owners(st);
        if qif_mb > 0 {
            if st.release_fault {
                fail!(EACCES, "RUNNER_QIF_PERSISTENCE_FAULT");
            }
            let cap = st
                .adapter
                .as_ref()
                .map_or(12_000, |a| a.controls.qif_cap_mb);
            st.release_ledger = st.release_ledger.clone().with_entity_cap(cap)?;
            st.release_ledger.charge(
                &enclave_core::qif::QifCharge {
                    entities: vec!["ek_00000000000000000000000000000000".into()],
                    conf: Conf::C3,
                    unstructured: true,
                    millibits: qif_mb,
                },
                now_ms,
            )?;
            if let Some(store) = st.release_store.as_mut() {
                if let Err(e) = store.save_json(&st.release_ledger) {
                    st.release_fault = true;
                    return Err(e);
                }
            }
        }
        if let Some(j) = st.journal.as_mut() {
            let (class, ir) = st
                .adapter
                .as_ref()
                .map(|a| {
                    (
                        a.manifest.execution_class.name(),
                        a.attest.operator_family_log_digest(),
                    )
                })
                .unwrap_or(("NONE", String::new()));
            let mut payload = json!({
                "execution_class_declared": class,
                "reference_operator_family_log_blake3": ir,
                "qif_millibits_charged": qif_mb,
                "hispa_boundary_anchor_applied": boundary,
                "ebm_intrinsic_barrier_vetoes": st.vetoes,
                "world_model_surprise_aborts": st.surprise_aborts
            });
            stamp_backend(&mut payload, st.adapter.as_ref());
            append_wipe_reports(&mut payload, &wipe_reports);
            match &governed {
                Some((e, slot)) => {
                    if let Some(o) = payload.as_object_mut() {
                        o.insert("event".into(), json!("DECLASSIFY"));
                        o.insert("slot".into(), json!(slot));
                    }
                    j.append_at(e, *slot, payload)?;
                }
                None => {
                    j.append(seq, payload)?;
                }
            }
        }
        drop(g);
        if let Some(wipe) = pending_wipe.as_mut() {
            if let Some(error) = wipe.fence_error.take() { return Err(error); }
            wipe.succeeded = true;
        }
        self.release_response(epoch, resp)
    }
}

/// UID 704, or the same-UID development fleet when explicitly enabled.
/// `peer` is kernel-verified; production IPC also pins 704's code identity.
/// Return pages the allocator holds for freed blocks to the system. UID 701
/// runs under a physical-footprint ceiling (48 MiB) that counts freed but
/// retained heap: a model swap (one tokenizer dropped, the next parsed)
/// otherwise stacks both models' high-water marks. No effect on contents;
/// wiped data was already zeroed before being freed.
fn release_freed_memory() {
    #[cfg(target_os = "macos")]
    {
        extern "C" {
            fn malloc_zone_pressure_relief(zone: *mut std::ffi::c_void, goal: usize) -> usize;
        }
        // SAFETY: a null zone means every zone; goal 0 means release all
        // possible. The call only returns free pages to the kernel.
        unsafe { malloc_zone_pressure_relief(std::ptr::null_mut(), 0) };
    }
}

/// This process's physical footprint, the quantity UID 701's ceiling counts.
fn own_footprint() -> Option<u64> {
    enclave_core::resource::phys_footprint_of_pid(std::process::id())
}

fn is_runtime_peer(peer: &PeerCredentials, dev_same_uid: bool) -> bool {
    peer.uid == DaemonId::AgentRuntime.uid() || (dev_same_uid && peer.uid == enclave_core::ipc::geteuid())
}

fn engine_class(e: &Engine) -> &'static str {
    match e {
        Engine::Ar(_) => "AR_CAUSAL",
        Engine::Rlcd(_) => "DISCRIMINATIVE_RLCD",
        Engine::Diffusion(_) => "DISCRETE_DIFFUSION",
        Engine::Ssm(_) => "RECURRENT_SSM_TTT",
        Engine::Concept(_) => "BYTE_OR_CONCEPT",
        Engine::Depth(_) => "SPECULATIVE_OR_RECURRENT_DEPTH",
        Engine::World(_) => "JEPA_EBM_WORLD_PLANNER",
    }
}

/// Wipe every live arena of an engine; returns the number wiped.
pub fn wipe_engine(e: &mut Engine, t: ZeroizeTrigger) -> u32 {
    wipe_engine_reports(e, t).len() as u32
}

/// Identity reported while no model is bound.
fn unbound_identity() -> crate::adapter::BackendIdentity {
    crate::adapter::BackendIdentity { backend: "none".into(), architecture: "none".into(), checkpoint_sha256: String::new() }
}

/// Name the real backend, architecture and checkpoint digest in a receipt.
fn stamp_backend(payload: &mut serde_json::Value, adapter: Option<&EnclaveModelAdapter>) {
    let identity = adapter.map(|a| a.identity.clone()).unwrap_or_else(unbound_identity);
    payload["inference_backend"] = json!(identity.backend);
    payload["architecture"] = json!(identity.architecture);
    payload["checkpoint_sha256"] = json!(identity.checkpoint_sha256);
}

// These engines currently allocate CPU guarded arenas, not Metal heaps.
fn append_wipe_reports(payload: &mut serde_json::Value, reports: &[WipeReport]) {
    if !reports.is_empty() {
        payload["wipe_reports"] = json!({"backend": "cpu_guarded_arena", "reports": reports});
    }
}

// An unsuccessful request can still have performed a real wipe. Preserve that
// measurement and the original error without reporting a wipe on preflight errors.
fn record_failed_wipes(
    st: &mut State,
    seq: Option<u64>,
    event: &str,
    reason: &str,
    reports: &[WipeReport],
) -> EnclaveResult<()> {
    if reports.is_empty() || st.journal.is_none() {
        return Ok(());
    }
    let seq = match seq {
        Some(seq) => seq,
        None => st.seq.next()?,
    };
    let mut payload = json!({
        "event": event,
        "succeeded": false,
        "error_reason": reason,
    });
    stamp_backend(&mut payload, st.adapter.as_ref());
    append_wipe_reports(&mut payload, reports);
    if let Some(journal) = st.journal.as_mut() {
        journal.append(seq, payload)?;
    }
    Ok(())
}

/// Measured reports for live arenas actually wiped by a service trigger.
pub fn wipe_engine_reports(e: &mut Engine, t: ZeroizeTrigger) -> Vec<WipeReport> {
    match e {
        Engine::Ssm(d) => d.on_trigger(t),
        Engine::World(g) => g.end_episode().into_iter().collect(),
        _ => Vec::new(),
    }
}

/// Reserved model-manifest target with a bounded, non-path model identifier.
pub fn model_manifest_target(model_id: &str) -> EnclaveResult<String> {
    if model_id.is_empty()
        || model_id.len() > 128
        || !model_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))
    {
        fail!(EINVAL, "MODEL_MANIFEST_ID");
    }
    Ok(format!("models/{model_id}/enclave-model.manifest.json"))
}

#[cfg(test)]
mod world_owner_tests {
    use super::*;
    use std::cell::RefCell;
    use std::sync::atomic::{AtomicBool, Ordering};
    use crate::classes::speculative::{FixedThermal, PowerSource, ThermalState};
    use crate::classes::world::{ResolvedTarget, WorldGate, WorldModel};
    use crate::manifest::WorldPlannerCaps;

    thread_local! {
        static OBSERVED: RefCell<Option<Vec<(&'static str, usize, bool)>>> = const { RefCell::new(None) };
        static SERIAL: RefCell<Option<std::sync::Weak<RunnerService>>> = const { RefCell::new(None) };
    }
    // Test-only observation after wiping initialized storage, while its owner
    // still holds the allocation. No freed reads or production observer.
    pub(super) fn observe(owner: &'static str, len: usize, zero: bool) {
        if len != 0 {
            if owner == "input" || owner == "goal" {
                SERIAL.with(|serial| {
                    if let Some(service) = serial.borrow().as_ref() {
                        let service = service.upgrade().expect("live request's service");
                        assert!(matches!(service.operation.try_lock(),
                            Err(std::sync::TryLockError::WouldBlock)),
                            "admitted input must wipe before operation serial releases");
                    }
                });
            }
            OBSERVED.with(|records| {
                if let Some(records) = records.borrow_mut().as_mut() {
                    records.push((owner, len, zero));
                }
            });
        }
    }
    fn begin() { OBSERVED.with(|records| *records.borrow_mut() = Some(Vec::new())); }
    fn begin_admitted(service: &Arc<RunnerService>) {
        begin();
        SERIAL.with(|serial| *serial.borrow_mut() = Some(Arc::downgrade(service)));
    }
    fn finish(expected: &[(&'static str, usize)]) {
        SERIAL.with(|serial| { serial.borrow_mut().take(); });
        let records = OBSERVED.with(|records| records.borrow_mut().take().unwrap());
        assert!(records.iter().all(|record| record.2), "every live owner must be zero before deallocation");
        let mut actual: Vec<_> = records.into_iter().map(|(kind, len, _)| (kind, len)).collect();
        let mut expected = expected.to_vec(); actual.sort_unstable(); expected.sort_unstable();
        assert_eq!(actual, expected);
    }

    struct NoWeights;
    impl WeightSource for NoWeights {
        fn resolve(&self, _: &str) -> EnclaveResult<ResolvedWeights> { fail!(EPERM, "NO_WEIGHTS"); }
    }
    #[derive(Debug)]
    struct Model { fail: Arc<AtomicBool> }
    impl WorldModel for Model {
        fn width(&self) -> usize { 1 }
        fn encode(&self, frame: &Frame) -> EnclaveResult<Vec<f32>> {
            if self.fail.load(Ordering::SeqCst) { fail!(EIO, "OWNER_ENCODER_FAILURE"); }
            Ok(vec![frame.px[0] as f32 / 255.0])
        }
        fn predict(&self, _: &[f32], _: &Action) -> EnclaveResult<Vec<f32>> { Ok(vec![64.0 / 255.0]) }
        fn cost(&self, _: &[f32], _: &[f32]) -> f32 { 0.0 }
        fn cone(&self, _: &[f32]) -> f32 { 0.0 }
    }
    fn unbound() -> Arc<RunnerService> {
        RunnerService::start(RunnerConfig {
            dev_same_uid: true, profile: Profile::L2, audit_path: None,
            calib_corpus_blake3: None, state_dir: None, actuator: None,
            thermal: Box::new(|| Box::new(FixedThermal(ThermalState::Nominal, PowerSource::Ac))),
        }, Box::new(NoWeights)).unwrap()
    }
    fn bound() -> (Arc<RunnerService>, Arc<AtomicBool>) {
        let service = unbound();
        let package = crate::zoo::package(ExecutionClass::JepaEbmWorldPlanner).unwrap();
        service.bind_bytes(&package.manifest_bytes(), &package.weights, None).unwrap();
        let fail = Arc::new(AtomicBool::new(false));
        service.state.lock().unwrap().adapter.as_mut().unwrap().engine = Engine::World(
            WorldGate::new(Box::new(Model { fail: fail.clone() }), WorldPlannerCaps {
                max_horizon: 1, max_candidates: 1, max_cem_iters: 1, e_max: 1.0,
                step_wallclock_ms: 100, tau_surprise: 0.1, actuation_sandbox: None,
            }, 0.5, 1.0).unwrap());
        (service, fail)
    }
    fn peer() -> PeerCredentials {
        PeerCredentials::local(enclave_core::ipc::geteuid(), enclave_core::ipc::geteuid())
    }
    fn plan() -> RunnerRequest {
        RunnerRequest::Plan { actuate: true, w: 8, h: 8, px: vec![91; 64].into(), goal_px: vec![64; 64].into(),
            pii_boxes: vec![], scroll_velocity: 0, tools_mask: 2,
            origins: vec!["https://owned.invalid".into()], candidates: vec![Action {
                tool_id: 1, params_q: vec![0], target: ResolvedTarget {
                    app_bundle_id: "org.example.browser".into(), ax_role: "AXButton".into(),
                    ax_title: "Continue".into(), url_origin: "https://owned.invalid".into(),
                    dom_selector: "#owned".into(),
                },
            }],
        }
    }
    fn observation(pixel: u8) -> RunnerRequest {
        RunnerRequest::Observe { w: 8, h: 8, px: vec![pixel; 64].into(), pii_boxes: vec![] }
    }

    #[test]
    fn yk11_world_original_pixels_scrub_on_predispatch_and_class_refusal() {
        let service = unbound();
        for request in [plan(), observation(91)] {
            let expected = if matches!(&request, RunnerRequest::Plan { .. }) {
                vec![("input", 64), ("goal", 64)]
            } else { vec![("input", 64)] };
            begin();
            assert!(service.handle(&peer(), request).unwrap_err().is("MODEL_NOT_BOUND"));
            finish(&expected);
        }
        let package = crate::zoo::package(ExecutionClass::DiscreteDiffusion).unwrap();
        service.bind_bytes(&package.manifest_bytes(), &package.weights, None).unwrap();
        begin();
        assert!(service.handle(&peer(), plan()).unwrap_err().is("REQUEST_CLASS_MISMATCH"));
        finish(&[("input", 64), ("goal", 64)]);
    }

    #[test]
    fn yk11_world_plan_and_failed_observe_keep_owned_cleanup_and_obligation() {
        let (service, fail) = bound();
        let mut invalid_goal = plan();
        if let RunnerRequest::Plan { goal_px, .. } = &mut invalid_goal { *goal_px = vec![64; 63].into(); }
        begin_admitted(&service);
        assert!(service.handle(&peer(), invalid_goal).unwrap_err().is("FRAME_SHAPE"));
        finish(&[("input", 64), ("goal", 63), ("latent", 1)]);
        let mut denied = plan();
        if let RunnerRequest::Plan { tools_mask, .. } = &mut denied { *tools_mask = 0; }
        begin();
        assert!(service.handle(&peer(), denied).unwrap_err().is("NO_SAFE_ACTION"));
        finish(&[("input", 64), ("goal", 64), ("latent", 1), ("latent", 1)]);
        begin_admitted(&service);
        assert!(matches!(service.handle(&peer(), plan()).unwrap(), RunnerResponse::Planned { .. }));
        finish(&[("input", 64), ("goal", 64), ("latent", 1), ("latent", 1)]);
        assert_eq!(service.state.lock().unwrap().pending.as_ref().unwrap().predicted, vec![64.0 / 255.0]);
        begin();
        assert!(service.handle(&peer(), plan()).unwrap_err().is("WORLD_OBSERVATION_REQUIRED"));
        finish(&[("input", 64), ("goal", 64)]);
        let mut invalid = observation(91);
        if let RunnerRequest::Observe { px, .. } = &mut invalid { *px = vec![91; 63].into(); }
        begin();
        assert!(service.handle(&peer(), invalid).unwrap_err().is("FRAME_SHAPE"));
        finish(&[("input", 63)]);
        fail.store(true, Ordering::SeqCst);
        begin();
        assert!(service.handle(&peer(), observation(91)).unwrap_err().is("OWNER_ENCODER_FAILURE"));
        finish(&[("input", 64)]);
        assert_eq!(service.state.lock().unwrap().pending.as_ref().unwrap().predicted, vec![64.0 / 255.0]);
        service.handle(&peer(), RunnerRequest::Zeroize(ZeroizeTrigger::TaskExit)).unwrap();
    }

    #[test]
    fn yk11_world_observation_success_and_surprise_scrub_latent_and_consumed_prediction() {
        for pixel in [64, 128] {
            let (service, _) = bound();
            service.handle(&peer(), plan()).unwrap();
            begin();
            let result = service.handle(&peer(), observation(pixel));
            if pixel == 64 { assert!(matches!(result.unwrap(), RunnerResponse::Ok)); }
            else { assert!(result.unwrap_err().is("WORLD_MODEL_SURPRISE_ABORT")); }
            finish(&[("input", 64), ("latent", 1), ("pending", 1)]);
            assert!(service.state.lock().unwrap().pending.is_none());
        }
    }

    #[test]
    fn yk11_world_explicit_model_teardowns_scrub_pending_prediction() {
        for mode in 0..4 {
            let (service, _) = bound();
            service.handle(&peer(), plan()).unwrap();
            begin();
            match mode {
                0 => { service.handle(&peer(), RunnerRequest::Zeroize(ZeroizeTrigger::TaskExit)).unwrap(); },
                1 => { service.handle(&peer(), RunnerRequest::Unbind).unwrap(); },
                _ => {
                    let package = crate::zoo::package(ExecutionClass::JepaEbmWorldPlanner).unwrap();
                    let result = service.bind_bytes(&package.manifest_bytes(), if mode == 2 { &package.weights } else { &[] }, None);
                    assert_eq!(result.is_ok(), mode == 2);
                },
            }
            finish(&[("pending", 1)]);
            assert!(service.state.lock().unwrap().pending.is_none());
            if mode == 1 || mode == 3 { assert!(service.state.lock().unwrap().adapter.is_none()); }
        }
    }
}

#[cfg(test)]
mod generation_control_tests {
    use super::*;
    use crate::classes::diffusion::{DiffusionBackend, DiffusionGate, ReferenceProbe};
    use crate::classes::speculative::{FixedThermal, PowerSource, ThermalState};
    struct NoWeights;
    impl WeightSource for NoWeights {
        fn resolve(&self, _: &str) -> EnclaveResult<ResolvedWeights> {
            fail!(EPERM, "NO_WEIGHTS")
        }
    }
    #[derive(Debug)]
    struct PausedBackend {
        entered: std::sync::mpsc::Sender<()>,
        resume: Mutex<std::sync::mpsc::Receiver<()>>,
    }
    impl DiffusionBackend for PausedBackend {
        fn logits(&self, x: &[Option<u8>], _: u32, _: u32) -> EnclaveResult<Vec<[f32; 256]>> {
            self.entered.send(()).unwrap();
            self.resume.lock().unwrap().recv().unwrap();
            Ok(vec![[0.0; 256]; x.len()])
        }
    }
    /// UID 704 sends `CancelGeneration` as the bare variant name (pinned on
    /// its side too); it must decode to this request.
    #[test]
    fn runtime_cancel_decodes_from_the_bare_variant_name() {
        let mut bytes = Vec::new();
        ciborium::into_writer(&ciborium::Value::Text("CancelGeneration".into()), &mut bytes).unwrap();
        let req: RunnerRequest = enclave_core::ipc::from_cbor(&bytes).unwrap();
        assert!(matches!(req, RunnerRequest::CancelGeneration));
    }

    /// UID 704 can stop its own in-flight generation without the operator's
    /// wipe: the request withholds output, nothing is wiped or unbound, any
    /// other peer is refused, and the next generation is not pre-cancelled.
    #[test]
    fn runtime_cancel_stops_the_inflight_generation_without_a_wipe() {
        let svc = RunnerService::start(
            RunnerConfig {
                dev_same_uid: true,
                profile: Profile::L2,
                audit_path: None,
                calib_corpus_blake3: None,
                thermal: Box::new(|| Box::new(FixedThermal(ThermalState::Nominal, PowerSource::Ac))),
                actuator: None,
                state_dir: None,
            },
            Box::new(NoWeights),
        )
        .unwrap();
        let p = crate::zoo::package(ExecutionClass::DiscreteDiffusion).unwrap();
        svc.bind_bytes(&serde_json::to_vec(&p.manifest).unwrap(), &p.weights, None).unwrap();
        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        let (resume_tx, resume_rx) = std::sync::mpsc::channel();
        svc.state.lock().unwrap().adapter.as_mut().unwrap().engine = Engine::Diffusion(
            DiffusionGate::new(
                Box::new(PausedBackend { entered: entered_tx, resume: Mutex::new(resume_rx) }),
                Box::new(ReferenceProbe),
                1,
                64,
            )
            .unwrap(),
        );
        let runtime = || PeerCredentials::local(enclave_core::ipc::geteuid(), 0);
        let generate = |svc: Arc<RunnerService>| std::thread::spawn(move || {
            svc.handle(&runtime(), RunnerRequest::GenerateStructured { schema: ArgSchema::Bool, len: 8, prompt: None })
        });
        let generation = generate(svc.clone());
        entered_rx.recv_timeout(std::time::Duration::from_secs(2)).unwrap();
        let stranger = PeerCredentials::local(enclave_core::ipc::geteuid().wrapping_add(1), 0);
        assert!(svc.handle(&stranger, RunnerRequest::CancelGeneration).unwrap_err().is("CANCEL_RUNTIME_REQUIRED"));
        // Answered while the generation still holds the operation lock.
        let started = std::time::Instant::now();
        assert!(matches!(svc.handle(&runtime(), RunnerRequest::CancelGeneration), Ok(RunnerResponse::Ok)));
        assert!(started.elapsed() < std::time::Duration::from_millis(500));
        resume_tx.send(()).unwrap();
        assert!(generation.join().unwrap().unwrap_err().is("GENERATION_CANCELLED"));
        assert!(!svc.cancel.load(std::sync::atomic::Ordering::Acquire), "no wipe was signalled");
        assert!(svc.state.lock().unwrap().adapter.is_some(), "the model stays bound");
        // The next generation starts clean.
        resume_tx.send(()).unwrap();
        let next = generate(svc.clone()).join().unwrap();
        assert!(!next.as_ref().is_err_and(|e| e.is("GENERATION_CANCELLED")), "{next:?}");
    }
    #[test]
    fn f139_status_remains_live_and_zeroize_cancels_worker_before_release() {
        let audit =
            std::env::temp_dir().join(format!("f107-cancel-{}.jsonl", enclave_core::rng::u64()));
        let svc = RunnerService::start(
            RunnerConfig {
                dev_same_uid: true,
                profile: Profile::L2,
                audit_path: Some(audit.clone()),
                calib_corpus_blake3: None,
                thermal: Box::new(|| {
                    Box::new(FixedThermal(ThermalState::Nominal, PowerSource::Ac))
                }),
                actuator: None,
                state_dir: None,
            },
            Box::new(NoWeights),
        )
        .unwrap();
        let p = crate::zoo::package(ExecutionClass::DiscreteDiffusion).unwrap();
        svc.bind_bytes(&serde_json::to_vec(&p.manifest).unwrap(), &p.weights, None)
            .unwrap();
        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        let (resume_tx, resume_rx) = std::sync::mpsc::channel();
        svc.state.lock().unwrap().adapter.as_mut().unwrap().engine = Engine::Diffusion(
            DiffusionGate::new(
                Box::new(PausedBackend {
                    entered: entered_tx,
                    resume: Mutex::new(resume_rx),
                }),
                Box::new(ReferenceProbe),
                1,
                64,
            )
            .unwrap(),
        );
        let peer = || PeerCredentials {
            uid: enclave_core::ipc::geteuid(),
            gid: 0,
            pid: None,
            audit_token: None,
            code_identity: None,
            tls_channel_binding: None,
        };
        let worker = svc.clone();
        let generation = std::thread::spawn(move || {
            worker.handle(
                &peer(),
                RunnerRequest::GenerateStructured {
                    schema: ArgSchema::Bool,
                    len: 8,
                    prompt: None,
                },
            )
        });
        entered_rx
            .recv_timeout(std::time::Duration::from_secs(2))
            .unwrap();
        let start = std::time::Instant::now();
        let RunnerResponse::Status(status) = svc.handle(&peer(), RunnerRequest::Status).unwrap()
        else {
            panic!()
        };
        assert!(status.state.starts_with("busy model="));
        assert!(start.elapsed() < std::time::Duration::from_millis(500));
        let wipe_svc = svc.clone();
        let wipe = std::thread::spawn(move || {
            wipe_svc.handle(&peer(), RunnerRequest::Zeroize(ZeroizeTrigger::TaskExit))
        });
        let deadline = std::time::Instant::now();
        while !svc.cancel.load(std::sync::atomic::Ordering::Acquire) {
            assert!(deadline.elapsed() < std::time::Duration::from_secs(2));
            std::thread::yield_now();
        }
        resume_tx.send(()).unwrap();
        assert!(generation
            .join()
            .unwrap()
            .unwrap_err()
            .is("GENERATION_CANCELLED"));
        assert!(matches!(
            wipe.join().unwrap().unwrap(),
            RunnerResponse::Wiped(_)
        ));
        assert!(svc.state.lock().unwrap().adapter.is_some());
        let entries = audit_entries(&audit);
        let generation = entries.iter().find(|p| p["event"] == "GENERATION").unwrap();
        assert_eq!(generation["succeeded"], false);
        assert_one_measured_wipe(generation);
        std::fs::remove_file(audit).unwrap();
    }

    fn audit_entries(path: &std::path::Path) -> Vec<serde_json::Value> {
        std::fs::read_to_string(path)
            .unwrap()
            .lines()
            .map(|line| {
                let entry: serde_json::Value = serde_json::from_str(line).unwrap();
                entry["payload"].clone()
            })
            .collect()
    }

    fn assert_one_measured_wipe(payload: &serde_json::Value) {
        assert!(payload.get("mtlheap_dual_zeroize_verified").is_none());
        assert_eq!(payload["wipe_reports"]["backend"], "cpu_guarded_arena");
        let reports = payload["wipe_reports"]["reports"]
            .as_array()
            .expect("actual wipe receipt must survive the error");
        assert_eq!(reports.len(), 1);
        assert!(reports[0]["bytes"].as_u64().unwrap() > 0);
        assert_eq!(reports[0]["residual"], 0);
    }

    fn audited_service(class: ExecutionClass) -> (Arc<RunnerService>, std::path::PathBuf) {
        let audit =
            std::env::temp_dir().join(format!("f107-error-{}.jsonl", enclave_core::rng::u64()));
        let svc = RunnerService::start(
            RunnerConfig {
                dev_same_uid: true,
                profile: Profile::L2,
                audit_path: Some(audit.clone()),
                calib_corpus_blake3: None,
                thermal: Box::new(|| {
                    Box::new(FixedThermal(ThermalState::Nominal, PowerSource::Ac))
                }),
                actuator: None,
                state_dir: None,
            },
            Box::new(NoWeights),
        )
        .unwrap();
        let p = crate::zoo::package(class).unwrap();
        svc.bind_bytes(&p.manifest_bytes(), &p.weights, None)
            .unwrap();
        (svc, audit)
    }

    #[derive(Debug)]
    struct FailingBackend;
    impl DiffusionBackend for FailingBackend {
        fn logits(&self, _: &[Option<u8>], _: u32, _: u32) -> EnclaveResult<Vec<[f32; 256]>> {
            fail!(EIO, "F107_DIFFUSION_BACKEND")
        }
    }
    impl crate::classes::byte_concept::ConceptBackend for FailingBackend {
        fn width(&self) -> usize {
            2
        }
        fn encode(&self, _: &str) -> EnclaveResult<Vec<f32>> {
            fail!(EIO, "F107_CONCEPT_BACKEND")
        }
        fn denoise(&self, _: &mut [f32]) -> EnclaveResult<()> {
            unreachable!()
        }
        fn decode(&self, _: &[f32]) -> EnclaveResult<Vec<u8>> {
            unreachable!()
        }
    }

    #[test]
    fn f107_diffusion_error_records_current_wipe_but_preflight_does_not_replay_it() {
        let (svc, audit) = audited_service(ExecutionClass::DiscreteDiffusion);
        svc.state.lock().unwrap().adapter.as_mut().unwrap().engine = Engine::Diffusion(
            DiffusionGate::new(Box::new(FailingBackend), Box::new(ReferenceProbe), 1, 64).unwrap(),
        );
        let peer = PeerCredentials::local(enclave_core::ipc::geteuid(), 0);
        assert!(svc
            .handle(
                &peer,
                RunnerRequest::GenerateStructured {
                    schema: ArgSchema::Bool,
                    len: 8,
                    prompt: None,
                }
            )
            .unwrap_err()
            .is("F107_DIFFUSION_BACKEND"));
        let entries = audit_entries(&audit);
        let failed = entries.last().unwrap();
        assert_eq!(failed["event"], "GENERATION");
        assert_eq!(failed["succeeded"], false);
        assert_one_measured_wipe(failed);
        assert!(svc
            .handle(
                &peer,
                RunnerRequest::GenerateStructured {
                    schema: ArgSchema::Bool,
                    len: 0,
                    prompt: None,
                }
            )
            .is_err());
        let entries = audit_entries(&audit);
        assert!(
            entries.last().unwrap().get("wipe_reports").is_none(),
            "no stale receipt on a call that allocates no arena"
        );
        std::fs::remove_file(audit).unwrap();
    }

    #[test]
    fn f107_concept_error_records_wipe_and_keeps_original_error() {
        use crate::classes::byte_concept::{ConceptGate, ConceptParams, Leace};
        let (svc, audit) = audited_service(ExecutionClass::ByteOrConcept);
        svc.state.lock().unwrap().adapter.as_mut().unwrap().engine = Engine::Concept(
            ConceptGate::new(
                Box::new(FailingBackend),
                Leace::new(&[vec![1.0, 0.0]]).unwrap(),
                vec![vec![0.0, 1.0]],
                ConceptParams {
                    sigma: 0.1,
                    sigma_min: 0.1,
                    max_norm: 1.0,
                    canary_cos: 0.99,
                    max_output_bytes: 64,
                },
            )
            .unwrap(),
        );
        let peer = PeerCredentials::local(enclave_core::ipc::geteuid(), 0);
        assert!(svc
            .handle(
                &peer,
                RunnerRequest::Concept {
                    input: ByteBuf::from(b"normal".to_vec()),
                    surrogate_key: None
                }
            )
            .unwrap_err()
            .is("F107_CONCEPT_BACKEND"));
        let entries = audit_entries(&audit);
        let failed = entries.last().unwrap();
        assert_eq!(failed["event"], "CONCEPT_FAILED");
        assert_eq!(failed["succeeded"], false);
        assert_one_measured_wipe(failed);
        let count = entries.len();
        assert!(svc
            .handle(
                &peer,
                RunnerRequest::Concept {
                    input: ByteBuf::from(vec![0xff]),
                    surrogate_key: None
                }
            )
            .is_err());
        assert_eq!(
            audit_entries(&audit).len(),
            count,
            "pre-arena failure must not reuse a prior receipt"
        );
        std::fs::remove_file(audit).unwrap();
    }

    #[test]
    fn f107_failed_rebind_records_prior_live_arena_and_leaves_model_unbound() {
        let (svc, audit) = audited_service(ExecutionClass::RecurrentSsmTtt);
        let peer = PeerCredentials::local(enclave_core::ipc::geteuid(), 0);
        svc.handle(
            &peer,
            RunnerRequest::SsmFork {
                label: Label::BOTTOM,
            },
        )
        .unwrap();
        let p = crate::zoo::package(ExecutionClass::RecurrentSsmTtt).unwrap();
        assert!(svc
            .bind_bytes(&p.manifest_bytes(), b"invalid weights", None)
            .is_err());
        assert!(svc.state.lock().unwrap().adapter.is_none());
        let entries = audit_entries(&audit);
        assert_eq!(entries.last().unwrap()["event"], "MODEL_BIND_FAILED");
        assert_one_measured_wipe(entries.last().unwrap());
        assert!(svc
            .bind_bytes(&p.manifest_bytes(), b"invalid weights", None)
            .is_err());
        assert_eq!(
            audit_entries(&audit).len(),
            entries.len(),
            "no live arena means no measured failure receipt"
        );
        std::fs::remove_file(audit).unwrap();
    }

    #[test]
    fn f107_surprise_abort_records_actual_episode_wipe_and_clears_pending() {
        let (svc, audit) = audited_service(ExecutionClass::JepaEbmWorldPlanner);
        {
            let mut state = svc.state.lock().unwrap();
            let Engine::World(world) = &mut state.adapter.as_mut().unwrap().engine else {
                panic!("expected bound world model")
            };
            // Derive the latent shape from the actual bound encoder, rather than
            // substituting the concept/depth fixture's unrelated width.
            let mut predicted = world.observe(frame(1, 1, &[0]).unwrap(), &[], 0.0).unwrap();
            assert!(!predicted.is_empty());
            for value in &mut predicted {
                *value += 1000.0;
            }
            state.pending = Some(PendingStep { predicted });
        }
        let peer = PeerCredentials::local(enclave_core::ipc::geteuid(), 0);
        let observe = || RunnerRequest::Observe {
            w: 1,
            h: 1,
            px: ByteBuf::from(vec![0]),
            pii_boxes: vec![],
        };
        let error = svc.handle(&peer, observe()).unwrap_err();
        assert!(
            error.is("WORLD_MODEL_SURPRISE_ABORT"),
            "expected actual distance-based surprise abort, got {error:?}"
        );
        let entries = audit_entries(&audit);
        assert_eq!(entries.last().unwrap()["event"], "WORLD_SURPRISE_ABORT");
        assert_one_measured_wipe(entries.last().unwrap());
        assert!(svc.state.lock().unwrap().pending.is_none());
        assert!(svc
            .handle(&peer, observe())
            .unwrap_err()
            .is("NO_PENDING_STEP"));
        assert_eq!(audit_entries(&audit).len(), entries.len());
        assert!(matches!(
            svc.handle(&peer, RunnerRequest::Zeroize(ZeroizeTrigger::TaskExit))
                .unwrap(),
            RunnerResponse::Wiped(0)
        ));
        assert!(audit_entries(&audit)
            .last()
            .unwrap()
            .get("wipe_reports")
            .is_none());
        std::fs::remove_file(audit).unwrap();
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum DelayedDepthCall { Prelude, Core, Coda }

    #[derive(Debug)]
    struct DelayedDepthBackend {
        phase: DelayedDepthCall,
        delayed: std::sync::atomic::AtomicBool,
    }
    impl DelayedDepthBackend {
        fn delay_once(&self, phase: DelayedDepthCall) {
            if self.phase == phase && !self.delayed.swap(true, std::sync::atomic::Ordering::AcqRel) {
                // Exercise the actual server-owned deadline, without a public
                // clock override or any installed service/hardware changes.
                std::thread::sleep(std::time::Duration::from_millis(2100));
            }
        }
    }
    impl crate::classes::speculative::DepthBackend for DelayedDepthBackend {
        fn width(&self) -> usize { 2 }
        fn prelude(&self, _: &[u8], h: &mut [f32]) -> EnclaveResult<()> {
            h.copy_from_slice(&[1.0, 0.0]);
            self.delay_once(DelayedDepthCall::Prelude);
            Ok(())
        }
        fn core(&self, _: &mut [f32]) -> EnclaveResult<()> {
            self.delay_once(DelayedDepthCall::Core);
            Ok(())
        }
        fn coda(&self, _: &[f32]) -> EnclaveResult<Vec<f32>> {
            self.delay_once(DelayedDepthCall::Coda);
            let mut logits = vec![0.0; 256];
            logits[b'a' as usize] = 10.0;
            Ok(logits)
        }
        fn draft(&self, _: u8) -> u8 { b'a' }
    }

    fn assert_late_depth_call_is_discarded_and_fast_retry_survives(phase: DelayedDepthCall) {
        use crate::classes::speculative::{DepthGate, LatentProbe};
        let (svc, audit) = audited_service(ExecutionClass::SpeculativeOrRecurrentDepth);
        {
            let mut state = svc.state.lock().unwrap();
            let adapter = state.adapter.as_mut().unwrap();
            adapter.engine = Engine::Depth(DepthGate::new(
                Box::new(DelayedDepthBackend { phase, delayed: std::sync::atomic::AtomicBool::new(false) }),
                LatentProbe { w: vec![0.0, 1.0], tau: 0.99 },
                Box::new(FixedThermal(ThermalState::Nominal, PowerSource::Ac)), 2, 2, 64,
            ).unwrap());
            adapter.controls.cadence_ms = None;
        }
        let peer = PeerCredentials::local(enclave_core::ipc::geteuid(), 0);
        let result = svc.handle(&peer, one_byte_think());
        assert!(result.unwrap_err().is("GENERATION_DEADLINE"), "late {phase:?} result must not leave the service");
        let entries = audit_entries(&audit);
        let generated = entries.last().unwrap();
        assert_eq!(generated["event"], "GENERATION");
        assert_eq!(generated["succeeded"], false);
        assert_eq!(generated["wipe_reports"]["backend"], "cpu_guarded_arena");
        let reports = generated["wipe_reports"]["reports"].as_array().unwrap();
        assert_eq!(reports.len(), 2, "both target and draft are actually wiped after the late call");
        assert!(reports.iter().all(|r| r["bytes"].as_u64().unwrap() > 0 && r["residual"] == 0));
        assert!(svc.state.lock().unwrap().adapter.is_some(), "the model must be restored on timeout");
        let RunnerResponse::Status(status) = svc.handle(&peer, RunnerRequest::Status).unwrap() else { panic!() };
        assert!(!status.state.starts_with("busy"));
        // The same backend delays only once. No model reset, weaker assertion,
        // clock adjustment or daemon restart is needed for legitimate output.
        let RunnerResponse::Text(output) = svc.handle(&peer, one_byte_think()).unwrap() else { panic!() };
        assert_eq!(output.as_ref(), b"a");
        assert_eq!(audit_entries(&audit).last().unwrap()["succeeded"], true);
        std::fs::remove_file(audit).unwrap();
    }

    #[test]
    fn f139_late_final_prelude_discards_output_and_wipes_before_fast_retry() {
        assert_late_depth_call_is_discarded_and_fast_retry_survives(DelayedDepthCall::Prelude);
    }
    #[test]
    fn f139_late_final_core_discards_output_and_wipes_before_fast_retry() {
        assert_late_depth_call_is_discarded_and_fast_retry_survives(DelayedDepthCall::Core);
    }
    #[test]
    fn f139_late_final_coda_discards_output_and_wipes_before_fast_retry() {
        assert_late_depth_call_is_discarded_and_fast_retry_survives(DelayedDepthCall::Coda);
    }

    #[derive(Debug, Default)]
    struct DelayedFinalProbe(std::sync::atomic::AtomicBool);
    impl crate::classes::diffusion::StepProbe for DelayedFinalProbe {
        fn inspect(&self, _: &[Option<u8>], _: u32) -> crate::classes::diffusion::ProbeVerdict {
            if !self.0.swap(true, std::sync::atomic::Ordering::AcqRel) {
                std::thread::sleep(std::time::Duration::from_millis(2100));
            }
            crate::classes::diffusion::ProbeVerdict::Clean
        }
    }

    #[test]
    fn f139_late_final_diffusion_probe_discards_output_and_preserves_wipe() {
        let (svc, audit) = audited_service(ExecutionClass::DiscreteDiffusion);
        {
            let mut state = svc.state.lock().unwrap();
            let adapter = state.adapter.as_mut().unwrap();
            adapter.engine = Engine::Diffusion(DiffusionGate::new(
                Box::new(crate::classes::diffusion::BigramDenoiser::from_table(vec![0.0; 256 * 256]).unwrap()),
                Box::new(DelayedFinalProbe::default()), 1, 64,
            ).unwrap());
            adapter.controls.cadence_ms = None;
        }
        let request = || RunnerRequest::GenerateStructured { schema: ArgSchema::Bool, len: 8, prompt: None };
        let peer = PeerCredentials::local(enclave_core::ipc::geteuid(), 0);
        assert!(svc.handle(&peer, request()).unwrap_err().is("GENERATION_DEADLINE"));
        let entries = audit_entries(&audit);
        let generated = entries.last().unwrap();
        assert_eq!(generated["event"], "GENERATION");
        assert_eq!(generated["succeeded"], false);
        assert_one_measured_wipe(generated);
        assert!(svc.state.lock().unwrap().adapter.is_some());
        let RunnerResponse::Text(output) = svc.handle(&peer, request()).unwrap() else { panic!() };
        assert!(Dfa::compile(&ArgSchema::Bool).unwrap().accepts(&output));
        assert_eq!(audit_entries(&audit).last().unwrap()["succeeded"], true);
        std::fs::remove_file(audit).unwrap();
    }

    #[derive(Debug)]
    struct MeasuredDepthBackend {
        fail: bool,
    }
    impl crate::classes::speculative::DepthBackend for MeasuredDepthBackend {
        fn width(&self) -> usize {
            2
        }
        fn prelude(&self, _: &[u8], h: &mut [f32]) -> EnclaveResult<()> {
            h.copy_from_slice(&[1.0, 0.0]);
            if self.fail {
                fail!(EIO, "F107_DEPTH_BACKEND");
            }
            Ok(())
        }
        fn core(&self, _: &mut [f32]) -> EnclaveResult<()> {
            Ok(())
        }
        fn coda(&self, _: &[f32]) -> EnclaveResult<Vec<f32>> {
            let mut logits = vec![0.0; 256];
            logits[b'a' as usize] = 10.0;
            Ok(logits)
        }
        fn draft(&self, _: u8) -> u8 {
            b'a'
        }
    }

    fn cadence_service() -> (Arc<RunnerService>, std::path::PathBuf) {
        use crate::classes::speculative::{DepthGate, LatentProbe};
        let (svc, audit) = audited_service(ExecutionClass::SpeculativeOrRecurrentDepth);
        let mut state = svc.state.lock().unwrap();
        let adapter = state.adapter.as_mut().unwrap();
        adapter.engine = Engine::Depth(
            DepthGate::new(
                Box::new(MeasuredDepthBackend { fail: false }),
                LatentProbe {
                    w: vec![0.0, 1.0],
                    tau: 0.99,
                },
                Box::new(FixedThermal(ThermalState::Nominal, PowerSource::Ac)),
                2,
                2,
                64,
            )
            .unwrap(),
        );
        adapter.controls.cadence_ms = Some(120);
        drop(state);
        (svc, audit)
    }

    fn one_byte_think() -> RunnerRequest {
        RunnerRequest::Think {
            prompt: ByteBuf::from(b"seed".to_vec()),
            n: 1,
            k: 1,
        }
    }

    #[test]
    fn f107_cadence_cancellation_records_final_failure_and_all_completed_wipes() {
        let (svc, audit) = cadence_service();
        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        let (resume_tx, resume_rx) = std::sync::mpsc::channel();
        let worker = svc.clone();
        let generation = std::thread::spawn(move || {
            worker.handle_with_pacer(
                &PeerCredentials::local(enclave_core::ipc::geteuid(), 0),
                one_byte_think(),
                move |wait| {
                    entered_tx.send(wait).unwrap();
                    resume_rx
                        .recv_timeout(std::time::Duration::from_secs(2))
                        .unwrap();
                },
            )
        });
        assert!(!entered_rx
            .recv_timeout(std::time::Duration::from_secs(2))
            .unwrap()
            .is_zero());
        // The handshake pins execution inside cadence, after both actual wipes.
        // Status must still acquire the state lock while generation is waiting.
        let started = std::time::Instant::now();
        assert!(matches!(
            svc.handle(
                &PeerCredentials::local(enclave_core::ipc::geteuid(), 0),
                RunnerRequest::Status
            )
            .unwrap(),
            RunnerResponse::Status(_)
        ));
        assert!(started.elapsed() < std::time::Duration::from_millis(500));
        let wipe_worker = svc.clone();
        let wipe = std::thread::spawn(move || {
            wipe_worker.handle(
                &PeerCredentials::local(enclave_core::ipc::geteuid(), 0),
                RunnerRequest::Zeroize(ZeroizeTrigger::ScreenLocked),
            )
        });
        let started = std::time::Instant::now();
        while !svc.cancel.load(std::sync::atomic::Ordering::Acquire) {
            assert!(started.elapsed() < std::time::Duration::from_secs(2));
            std::thread::yield_now();
        }
        resume_tx.send(()).unwrap();
        assert!(generation
            .join()
            .unwrap()
            .unwrap_err()
            .is("GENERATION_CANCELLED"));
        assert!(matches!(
            wipe.join().unwrap().unwrap(),
            RunnerResponse::Wiped(0)
        ));
        let entries = audit_entries(&audit);
        let generated = entries.iter().find(|p| p["event"] == "GENERATION").unwrap();
        assert_eq!(generated["succeeded"], false);
        assert_eq!(generated["wipe_reports"]["backend"], "cpu_guarded_arena");
        let reports = generated["wipe_reports"]["reports"].as_array().unwrap();
        assert_eq!(reports.len(), 2, "one target and one draft were wiped");
        for report in reports {
            assert!(report["bytes"].as_u64().unwrap() > 0);
            assert_eq!(report["residual"], 0);
        }
        assert!(generated.get("mtlheap_dual_zeroize_verified").is_none());
        std::fs::remove_file(audit).unwrap();
    }

    #[test]
    fn f107_legitimate_cadence_reply_and_measurements_remain_successful() {
        let (svc, audit) = cadence_service();
        let started = std::time::Instant::now();
        let response = svc
            .handle(
                &PeerCredentials::local(enclave_core::ipc::geteuid(), 0),
                one_byte_think(),
            )
            .unwrap();
        assert!(started.elapsed() >= std::time::Duration::from_millis(100));
        assert!(started.elapsed() < std::time::Duration::from_secs(2));
        let RunnerResponse::Text(output) = response else {
            panic!("expected legitimate cadence output")
        };
        assert_eq!(output.as_ref(), b"a");
        let entries = audit_entries(&audit);
        let generated = entries.iter().find(|p| p["event"] == "GENERATION").unwrap();
        assert_eq!(generated["succeeded"], true);
        assert_eq!(generated["wipe_reports"]["backend"], "cpu_guarded_arena");
        let reports = generated["wipe_reports"]["reports"].as_array().unwrap();
        assert_eq!(reports.len(), 2);
        for report in reports {
            assert!(report["bytes"].as_u64().unwrap() > 0);
            assert_eq!(report["residual"], 0);
        }
        std::fs::remove_file(audit).unwrap();
    }

    #[test]
    fn f107_speculation_records_each_target_and_draft_wipe_on_success_and_error() {
        use crate::classes::speculative::{DepthGate, LatentProbe};
        for fail in [false, true] {
            let (svc, audit) = audited_service(ExecutionClass::SpeculativeOrRecurrentDepth);
            svc.state.lock().unwrap().adapter.as_mut().unwrap().engine = Engine::Depth(
                DepthGate::new(
                    Box::new(MeasuredDepthBackend { fail }),
                    LatentProbe {
                        w: vec![0.0, 1.0],
                        tau: 0.99,
                    },
                    Box::new(FixedThermal(ThermalState::Nominal, PowerSource::Ac)),
                    2,
                    2,
                    64,
                )
                .unwrap(),
            );
            let peer = PeerCredentials::local(enclave_core::ipc::geteuid(), 0);
            let result = svc.handle(
                &peer,
                RunnerRequest::Think {
                    prompt: ByteBuf::from(b"seed".to_vec()),
                    n: 2,
                    k: 1,
                },
            );
            if fail {
                assert!(result.unwrap_err().is("F107_DEPTH_BACKEND"));
            } else {
                let RunnerResponse::Text(output) = result.unwrap() else {
                    panic!()
                };
                assert_eq!(output.as_ref(), b"aa");
            }
            let entries = audit_entries(&audit);
            let payload = entries.last().unwrap();
            assert_eq!(payload["event"], "GENERATION");
            assert_eq!(payload["succeeded"], !fail);
            assert!(payload.get("mtlheap_dual_zeroize_verified").is_none());
            assert_eq!(payload["wipe_reports"]["backend"], "cpu_guarded_arena");
            let reports = payload["wipe_reports"]["reports"]
                .as_array()
                .expect("all target and draft wipe receipts must be journaled");
            assert_eq!(reports.len(), if fail { 2 } else { 3 });
            for report in reports {
                assert!(report["bytes"].as_u64().unwrap() > 0);
                assert_eq!(report["residual"], 0);
            }
            assert!(svc
                .handle(
                    &peer,
                    RunnerRequest::Think {
                        prompt: ByteBuf::from(b"seed".to_vec()),
                        n: 1,
                        k: 0
                    }
                )
                .is_err());
            assert!(audit_entries(&audit)
                .last()
                .unwrap()
                .get("wipe_reports")
                .is_none());
            std::fs::remove_file(audit).unwrap();
        }
    }
}

#[cfg(test)]
mod ssm_lifecycle_tests {
    use super::*;
    use crate::classes::speculative::{FixedThermal, PowerSource, ThermalState};
    use crate::classes::ssm::{RecurrentBackend, StateSnapshotDag};
    use enclave_core::label::Taint;
    use std::time::{Duration, Instant};

    struct NoWeights;
    impl WeightSource for NoWeights {
        fn resolve(&self, _: &str) -> EnclaveResult<ResolvedWeights> {
            fail!(EPERM, "NO_WEIGHTS")
        }
    }

    #[derive(Debug)]
    struct Retaining;
    impl RecurrentBackend for Retaining {
        fn width(&self) -> usize { 1 }
        fn system_state(&self) -> Vec<f32> { vec![0.0] }
        fn step(&self, h: &mut [f32], b: u8) -> EnclaveResult<()> {
            h[0] += b as f32;
            Ok(())
        }
        fn logits(&self, h: &[f32]) -> EnclaveResult<[f32; 256]> {
            let mut out = [0.0; 256];
            out[if h[0] > 0.0 { b'x' } else { b'.' } as usize] = 1.0;
            Ok(out)
        }
    }

    fn low() -> Label { Label::new(Conf::C1, Taint::T0) }
    fn high() -> Label { Label::new(Conf::C4, Taint::T3) }
    fn peer() -> PeerCredentials { PeerCredentials::local(enclave_core::ipc::geteuid(), 0) }

    struct Fixture {
        service: Arc<RunnerService>,
        clock: Arc<Mutex<Instant>>,
        audit: PathBuf,
    }
    impl Fixture {
        fn new() -> Self {
            let audit = std::env::temp_dir().join(format!("f140-{}.jsonl", enclave_core::rng::u64()));
            let service = RunnerService::start(RunnerConfig {
                dev_same_uid: true,
                profile: Profile::L2, audit_path: Some(audit.clone()),
                calib_corpus_blake3: None,
                thermal: Box::new(|| Box::new(FixedThermal(ThermalState::Nominal, PowerSource::Ac))),
                actuator: None, state_dir: None,
            }, Box::new(NoWeights)).unwrap();
            let p = crate::zoo::package(ExecutionClass::RecurrentSsmTtt).unwrap();
            service.bind_bytes(&p.manifest_bytes(), &p.weights, None).unwrap();
            let clock = Arc::new(Mutex::new(Instant::now()));
            let driver = clock.clone();
            let mut dag = StateSnapshotDag::new(Box::new(Retaining), 64, 0.5, 64).unwrap();
            dag.set_clock(move || *driver.lock().unwrap());
            service.state.lock().unwrap().adapter.as_mut().unwrap().engine = Engine::Ssm(dag);
            Self { service, clock, audit }
        }
        fn advance(&self, elapsed: Duration) { *self.clock.lock().unwrap() += elapsed; }
        fn call(&self, req: RunnerRequest) -> EnclaveResult<RunnerResponse> { self.service.handle(&peer(), req) }
        fn fork(&self) -> u64 {
            let RunnerResponse::Session(id) = self.call(RunnerRequest::SsmFork { label: low() }).unwrap() else { panic!() };
            id
        }
        fn ingest(&self, id: u64) {
            assert!(matches!(self.call(RunnerRequest::SsmIngest { session: id, label: high(), bytes: b"z".to_vec().into() }).unwrap(), RunnerResponse::Ok));
        }
        fn generate(&self, id: u64) {
            let RunnerResponse::Ssm { label, output, boundary_anchor, .. } = self.call(RunnerRequest::SsmGenerate { session: id, n: 1 }).unwrap() else { panic!() };
            assert_eq!(label, high());
            assert_eq!(output.as_ref(), b"x");
            assert!(boundary_anchor);
        }
        fn expired(&self, count: usize) {
            let entries: Vec<serde_json::Value> = std::fs::read_to_string(&self.audit).unwrap().lines().map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap()["payload"].clone()).filter(|p| p["event"] == "SSM_SESSIONS_EXPIRED").collect();
            assert_eq!(entries.len(), 1, "exactly one actual expiration batch");
            let entry = &entries[0];
            assert_eq!(entry["expired_sessions"].as_u64(), Some(count as u64));
            assert_eq!(entry["wipe_reports"]["backend"], "cpu_guarded_arena");
            let reports = entry["wipe_reports"]["reports"].as_array().unwrap();
            assert_eq!(reports.len(), count);
            assert!(reports.iter().all(|r| r["bytes"].as_u64().unwrap() > 0 && r["residual"] == 0));
            assert!(entry.get("mtlheap_dual_zeroize_verified").is_none());
        }
        fn sessions(&self) -> usize {
            let state = self.service.state.lock().unwrap();
            let Engine::Ssm(dag) = &state.adapter.as_ref().unwrap().engine else { panic!() };
            dag.sessions()
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            if self.audit.is_dir() { let _ = std::fs::remove_dir(&self.audit); }
            else { let _ = std::fs::remove_file(&self.audit); }
        }
    }

    #[test]
    fn f140_owned_scope_binds_full_owner_and_cannot_be_reached_by_raw_id() {
        let f = Fixture::new();
        let scope = [0x14; 32];
        let mut owner = peer();
        owner.pid = Some(140);
        owner.audit_token = Some([1, 2, 3, 4, 5, 6, 7, 8]);
        let call = |p: &PeerCredentials, req| f.service.handle(p, req);
        let fork = || RunnerRequest::SsmForkOwned { scope, label: low() };
        let RunnerResponse::Session(id) = call(&owner, fork()).unwrap() else { panic!() };
        assert!(matches!(call(&owner, fork()).unwrap(), RunnerResponse::Session(retry) if retry == id));
        assert_eq!(f.sessions(), 1);
        assert!(call(&owner, RunnerRequest::SsmForkOwned { scope, label: high() }).unwrap_err().is("SSM_SCOPE_LABEL_MISMATCH"));
        for index in 0..8 {
            let mut foreign = owner.clone();
            foreign.audit_token.as_mut().unwrap()[index] ^= 1;
            for req in [fork(),
                RunnerRequest::SsmIngestOwned { scope, label: low(), bytes: b"x".to_vec().into() },
                RunnerRequest::SsmGenerateOwned { scope, n: 1 },
                RunnerRequest::SsmExitOwned { scope },
            ] {
                assert!(call(&foreign, req).unwrap_err().is("SSM_SESSION_OWNER_MISMATCH"));
            }
        }
        for req in [
            RunnerRequest::SsmIngest { session: id, label: low(), bytes: b"x".to_vec().into() },
            RunnerRequest::SsmGenerate { session: id, n: 1 },
            RunnerRequest::SsmExit { session: id },
        ] {
            assert!(call(&owner, req).unwrap_err().is("SSM_SESSION_OWNER_MISMATCH"));
        }
        call(&owner, RunnerRequest::SsmIngestOwned { scope, label: high(), bytes: b"z".to_vec().into() }).unwrap();
        let RunnerResponse::Ssm { label, output, boundary_anchor, .. } = call(&owner, RunnerRequest::SsmGenerateOwned { scope, n: 1 }).unwrap() else { panic!() };
        assert_eq!(label, high());
        assert_eq!(output.as_ref(), b"x");
        assert!(boundary_anchor);
        assert!(matches!(call(&owner, RunnerRequest::SsmExitOwned { scope }).unwrap(), RunnerResponse::Wiped(1)));
        assert!(matches!(call(&owner, RunnerRequest::SsmExitOwned { scope }).unwrap(), RunnerResponse::Wiped(0)));
        assert!(f.service.state.lock().unwrap().ssm_owners.is_empty());
    }

    #[test]
    fn generation_is_refused_to_every_caller_but_the_agent_runtime() {
        let f = Fixture::new();
        f.service.state.lock().unwrap().dev_same_uid = false;
        let requests = || [
            RunnerRequest::GenerateStructured { schema: ArgSchema::Bool, len: 1, prompt: None },
            RunnerRequest::Think { prompt: b"seed".to_vec().into(), n: 1, k: 1 },
            RunnerRequest::Plan { w: 8, h: 8, px: vec![91; 64].into(), goal_px: vec![64; 64].into(),
                pii_boxes: vec![], scroll_velocity: 0, candidates: vec![], tools_mask: 0, origins: vec![], actuate: false },
            RunnerRequest::Concept { input: b"x".to_vec().into(), surrogate_key: None },
        ];
        for uid in [0, 701, 702, 703, 705, 501] {
            for req in requests() {
                let error = f.service.handle(&PeerCredentials::local(uid, uid), req).unwrap_err();
                assert!(error.is("GENERATION_RUNTIME_REQUIRED"), "uid {uid}: {error:?}");
            }
        }
        for req in requests() {
            let result = f.service.handle(&PeerCredentials::local(704, 704), req);
            assert!(!result.is_err_and(|e| e.is("GENERATION_RUNTIME_REQUIRED")));
        }
    }

    #[test]
    fn f140_only_runtime_asserts_labels_and_legacy_sessions_bind_their_owner() {
        let f = Fixture::new();
        f.service.state.lock().unwrap().dev_same_uid = false;
        let mut owner = PeerCredentials::local(704, 704);
        owner.pid = Some(1);
        let call = |p: &PeerCredentials, req| f.service.handle(p, req);
        let RunnerResponse::Session(id) = call(&owner, RunnerRequest::SsmFork { label: low() }).unwrap() else { panic!() };
        for uid in [0, 701, 702, 703, 705, 501] {
            let untrusted = PeerCredentials::local(uid, uid);
            for req in [RunnerRequest::SsmFork { label: low() },
                RunnerRequest::SsmForkOwned { scope: [uid as u8; 32], label: low() },
                RunnerRequest::SsmIngest { session: id, label: low(), bytes: b"x".to_vec().into() },
                RunnerRequest::SsmGenerate { session: id, n: 1 },
                RunnerRequest::SsmExit { session: id },
                RunnerRequest::SsmExitOwned { scope: [0; 32] },
            ] { assert!(call(&untrusted, req).unwrap_err().is("SSM_RUNTIME_REQUIRED")); }
        }
        let mut foreign = owner.clone();
        foreign.pid = Some(2);
        for req in [RunnerRequest::SsmIngest { session: id, label: high(), bytes: b"z".to_vec().into() },
            RunnerRequest::SsmGenerate { session: id, n: 1 }, RunnerRequest::SsmExit { session: id },
        ] { assert!(call(&foreign, req).unwrap_err().is("SSM_SESSION_OWNER_MISMATCH")); }
        call(&owner, RunnerRequest::SsmIngest { session: id, label: high(), bytes: b"z".to_vec().into() }).unwrap();
        let RunnerResponse::Ssm { label, output, .. } = call(&owner, RunnerRequest::SsmGenerate { session: id, n: 1 }).unwrap() else { panic!() };
        assert_eq!(label, high());
        assert_eq!(output.as_ref(), b"x");
        assert!(matches!(call(&owner, RunnerRequest::SsmExit { session: id }).unwrap(), RunnerResponse::Wiped(1)));
    }

    #[test]
    fn f140_owned_retry_does_not_renew_idle_and_stale_scope_exit_is_idempotent() {
        let f = Fixture::new();
        let scope = [0x40; 32];
        let fork = || RunnerRequest::SsmForkOwned { scope, label: low() };
        let RunnerResponse::Session(id) = f.call(fork()).unwrap() else { panic!() };
        f.advance(Duration::from_secs(240));
        assert!(matches!(f.call(fork()).unwrap(), RunnerResponse::Session(retry) if retry == id));
        f.advance(Duration::from_secs(60));
        assert!(matches!(f.call(RunnerRequest::SsmExitOwned { scope }).unwrap(), RunnerResponse::Wiped(0)));
        assert_eq!(f.sessions(), 0);
        f.expired(1);
        assert!(f.service.state.lock().unwrap().ssm_owners.is_empty());
        f.call(fork()).unwrap();
        f.call(RunnerRequest::Unbind).unwrap();
        assert!(matches!(f.call(RunnerRequest::SsmExitOwned { scope }).unwrap(), RunnerResponse::Wiped(0)));
        let restarted = RunnerService::start(RunnerConfig {
            dev_same_uid: true, profile: Profile::L2, audit_path: None,
            calib_corpus_blake3: None,
            thermal: Box::new(|| Box::new(FixedThermal(ThermalState::Nominal, PowerSource::Ac))),
            actuator: None, state_dir: None,
        }, Box::new(NoWeights)).unwrap();
        assert!(matches!(restarted.handle(&peer(), RunnerRequest::SsmExitOwned { scope }).unwrap(), RunnerResponse::Wiped(0)));
        assert!(restarted.handle(&peer(), RunnerRequest::SsmGenerateOwned { scope, n: 1 }).unwrap_err().is("UNKNOWN_SESSION"));
    }

    #[test]
    fn f140_owned_and_legacy_fault_cleanup_require_owner_and_retain_actual_wipes() {
        let f = Fixture::new();
        let scope = [0x41; 32];
        f.call(RunnerRequest::SsmForkOwned { scope, label: high() }).unwrap();
        let raw = f.fork();
        f.service.state.lock().unwrap().ssm_expiry_audit_fault = Some(Vec::new());
        let mut foreign = peer();
        foreign.pid = Some(999);
        for req in [RunnerRequest::SsmExitOwned { scope }, RunnerRequest::SsmExit { session: raw }] {
            assert!(f.service.handle(&foreign, req).unwrap_err().is("SSM_SESSION_OWNER_MISMATCH"));
        }
        assert_eq!(f.sessions(), 2);
        for req in [RunnerRequest::SsmExitOwned { scope }, RunnerRequest::SsmExit { session: raw }] {
            assert!(f.call(req).unwrap_err().is("SSM_LIFECYCLE_AUDIT_FAILED"));
        }
        assert_eq!(f.sessions(), 0);
        assert!(f.call(RunnerRequest::SsmExitOwned { scope }).unwrap_err().is("SSM_LIFECYCLE_AUDIT_FAILED"));
        let state = f.service.state.lock().unwrap();
        assert!(state.ssm_owners.is_empty());
        let retained = state.ssm_expiry_audit_fault.as_ref().unwrap();
        assert_eq!(retained.len(), 2);
        assert!(retained.iter().all(|r| r.bytes > 0 && r.residual == 0));
    }

    #[test]
    fn f140_idle_expiry_reclaims_eight_abandoned_sessions_and_reports_once() {
        let f = Fixture::new();
        let mut old = Vec::new();
        for _ in 0..8 { let id = f.fork(); f.ingest(id); old.push(id); }
        let full = || RunnerRequest::SsmFork { label: low() };
        assert!(f.call(full()).unwrap_err().is("ENCLAVE_MEMORY_PRESSURE"));
        f.advance(Duration::from_secs(300) - Duration::from_nanos(1));
        assert!(f.call(full()).unwrap_err().is("ENCLAVE_MEMORY_PRESSURE"));
        f.advance(Duration::from_nanos(1));
        let replacement = f.fork();
        f.expired(8);
        for id in old {
            assert!(f.call(RunnerRequest::SsmGenerate { session: id, n: 1 }).unwrap_err().is("UNKNOWN_SESSION"));
            assert!(f.call(RunnerRequest::SsmIngest { session: id, label: low(), bytes: b"new".to_vec().into() }).unwrap_err().is("UNKNOWN_SESSION"));
        }
        assert_eq!(f.sessions(), 1);
        assert!(matches!(f.call(RunnerRequest::SsmExit { session: replacement }).unwrap(), RunnerResponse::Wiped(1)));
        assert!(matches!(f.call(RunnerRequest::Zeroize(ZeroizeTrigger::TaskExit)).unwrap(), RunnerResponse::Wiped(0)));
        f.expired(8);
        let text = std::fs::read_to_string(&f.audit).unwrap();
        let last: serde_json::Value = serde_json::from_str(text.lines().last().unwrap()).unwrap();
        assert!(last["payload"].get("wipe_reports").is_none(), "empty trigger must not replay expiration reports");
    }

    #[test]
    fn f140_active_session_keeps_joined_label_while_other_session_expires() {
        let f = Fixture::new();
        let abandoned = f.fork();
        f.ingest(abandoned);
        let active = f.fork();
        f.advance(Duration::from_secs(240));
        f.ingest(active);
        f.advance(Duration::from_secs(60));
        f.call(RunnerRequest::Status).unwrap();
        assert_eq!(f.sessions(), 1);
        f.generate(active);
        f.expired(1);
        f.advance(Duration::from_secs(299));
        f.generate(active);
        assert!(matches!(f.call(RunnerRequest::SsmExit { session: active }).unwrap(), RunnerResponse::Wiped(1)));
        assert_eq!(f.sessions(), 0);
        f.expired(1);
    }

    #[test]
    fn f140_empty_and_failed_requests_cannot_refresh_session_idle_timeout() {
        for probe in 0..4 {
            let f = Fixture::new();
            let id = f.fork();
            f.ingest(id);
            if probe == 3 { f.generate(id); }
            f.advance(Duration::from_secs(240));
            match probe {
                0 => { assert!(f.call(RunnerRequest::SsmGenerate { session: id, n: 65 }).unwrap_err().is("OUTPUT_CAP_EXCEEDED")); }
                1 => { f.call(RunnerRequest::SsmGenerate { session: id, n: 0 }).unwrap(); }
                2 => { f.call(RunnerRequest::SsmIngest { session: id, label: high(), bytes: Vec::new().into() }).unwrap(); }
                _ => { assert!(f.call(RunnerRequest::SsmIngest { session: id, label: high(), bytes: b"bad phase".to_vec().into() }).unwrap_err().is("SSM_PHASE")); }
            }
            f.advance(Duration::from_secs(60));
            f.call(RunnerRequest::Status).unwrap();
            assert!(f.call(RunnerRequest::SsmGenerate { session: id, n: 1 }).unwrap_err().is("UNKNOWN_SESSION"));
            assert_eq!(f.sessions(), 0);
            f.expired(1);
        }
    }

    #[test]
    fn f140_absolute_lifetime_expires_even_continuously_active_session() {
        let f = Fixture::new();
        let id = f.fork();
        f.ingest(id);
        for _ in 0..7 { f.advance(Duration::from_secs(240)); f.generate(id); }
        f.advance(Duration::from_secs(120) - Duration::from_nanos(1));
        f.generate(id);
        f.advance(Duration::from_nanos(1));
        assert!(f.call(RunnerRequest::SsmGenerate { session: id, n: 1 }).unwrap_err().is("UNKNOWN_SESSION"));
        f.expired(1);
        let clean = f.fork();
        let RunnerResponse::Ssm { label, output, .. } = f.call(RunnerRequest::SsmGenerate { session: clean, n: 1 }).unwrap() else { panic!() };
        assert_eq!(label, low());
        assert_eq!(output.as_ref(), b".");
    }

    #[test]
    fn f140_background_expiry_wipes_without_another_rpc_and_does_not_own_service() {
        let f = Fixture::new();
        let id = f.fork();
        f.ingest(id);
        f.advance(Duration::from_secs(300));
        let start = Instant::now();
        while f.sessions() != 0 {
            assert!(start.elapsed() < Duration::from_secs(2), "abandoned state requires a daemon-owned reaper, not another RPC");
            std::thread::sleep(Duration::from_millis(5));
        }
        f.expired(1);
        let weak = Arc::downgrade(&f.service);
        drop(f);
        let start = Instant::now();
        while weak.upgrade().is_some() {
            assert!(start.elapsed() < Duration::from_secs(2), "reaper retained the service");
            std::thread::yield_now();
        }
    }

    #[test]
    fn f140_expiry_during_recurrent_work_preserves_error_and_measured_cleanup() {
        #[derive(Debug)]
        struct Crossing {
            clock: Arc<Mutex<Instant>>,
            armed: Arc<std::sync::atomic::AtomicBool>,
            fail: bool,
        }
        impl RecurrentBackend for Crossing {
            fn width(&self) -> usize { 1 }
            fn system_state(&self) -> Vec<f32> { vec![0.0] }
            fn logits(&self, _: &[f32]) -> EnclaveResult<[f32; 256]> {
                let mut out = [0.0; 256]; out[b'x' as usize] = 1.0; Ok(out)
            }
            fn step(&self, h: &mut [f32], b: u8) -> EnclaveResult<()> {
                h[0] += b as f32;
                if self.armed.swap(false, std::sync::atomic::Ordering::AcqRel) {
                    *self.clock.lock().unwrap() += Duration::from_secs(300);
                    if self.fail { fail!(EIO, "F140_BACKEND_ERROR"); }
                }
                Ok(())
            }
        }
        for fail in [false, true] {
            let f = Fixture::new();
            let armed = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let mut dag = StateSnapshotDag::new(Box::new(Crossing {
                clock: f.clock.clone(), armed: armed.clone(), fail,
            }), 64, 0.5, 64).unwrap();
            let driver = f.clock.clone();
            dag.set_clock(move || *driver.lock().unwrap());
            f.service.state.lock().unwrap().adapter.as_mut().unwrap().engine = Engine::Ssm(dag);
            let id = f.fork();
            f.ingest(id);
            armed.store(true, std::sync::atomic::Ordering::Release);
            let error = f.call(RunnerRequest::SsmGenerate { session: id, n: 1 }).unwrap_err();
            assert!(error.is(if fail { "F140_BACKEND_ERROR" } else { "SSM_SESSION_EXPIRED" }), "{error:?}");
            assert_eq!(f.sessions(), 0);
            f.expired(1);
            assert!(f.call(RunnerRequest::SsmGenerate { session: id, n: 1 }).unwrap_err().is("UNKNOWN_SESSION"));
            f.expired(1);
        }
    }

    #[test]
    fn f140_background_cleanup_survives_audit_fault_without_retrying_append() {
        let f = Fixture::new();
        let old = f.fork();
        f.ingest(old);
        f.advance(Duration::from_secs(240));
        let younger = f.fork();
        f.ingest(younger);
        std::fs::remove_file(&f.audit).unwrap();
        std::fs::create_dir(&f.audit).unwrap();
        f.advance(Duration::from_secs(60));
        let error = f.call(RunnerRequest::SsmFork { label: low() }).unwrap_err();
        assert!(error.is("AUDIT_OPEN") || error.is("SSM_LIFECYCLE_AUDIT_FAILED"), "{error:?}");
        assert_eq!(f.sessions(), 1);
        // An attempted retry would recreate this path. The timer must instead
        // wipe the younger arena and retain both actual measurements in memory.
        std::fs::remove_dir(&f.audit).unwrap();
        f.advance(Duration::from_secs(240));
        let start = Instant::now();
        while f.sessions() != 0 {
            assert!(start.elapsed() < Duration::from_secs(2), "audit fault stopped cleanup of younger abandoned sessions");
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(!f.audit.exists(), "ambiguous failed append must never be retried");
        let state = f.service.state.lock().unwrap();
        let retained = state.ssm_expiry_audit_fault.as_ref().unwrap();
        assert_eq!(retained.len(), 2);
        assert!(retained.iter().all(|report| report.bytes > 0 && report.residual == 0));
        drop(state);
        assert!(f.call(RunnerRequest::SsmGenerate { session: younger, n: 1 }).unwrap_err().is("SSM_LIFECYCLE_AUDIT_FAILED"));
        let retained_count = f.service.state.lock().unwrap().ssm_expiry_audit_fault.as_ref().unwrap().len();
        assert_eq!(retained_count, 2, "faulted requests must not duplicate old measurements");
    }

    #[test]
    fn f140_expiry_audit_failure_blocks_new_sessions_and_output_until_restart() {
        let f = Fixture::new();
        let id = f.fork();
        f.ingest(id);
        std::fs::remove_file(&f.audit).unwrap();
        std::fs::create_dir(&f.audit).unwrap();
        f.advance(Duration::from_secs(240));
        // Keep a second, younger arena live to verify emergency cleanup after
        // the expiration append fails. Restore the journal only afterward.
        std::fs::remove_dir(&f.audit).unwrap();
        let younger = f.fork();
        f.ingest(younger);
        std::fs::remove_file(&f.audit).unwrap();
        std::fs::create_dir(&f.audit).unwrap();
        f.advance(Duration::from_secs(60));
        let error = f.call(RunnerRequest::SsmFork { label: low() }).unwrap_err();
        // The real periodic worker may win the same state lock and encounter
        // AUDIT_OPEN first. Both schedules must leave the identical sticky fault.
        assert!(error.is("AUDIT_OPEN") || error.is("SSM_LIFECYCLE_AUDIT_FAILED"), "{error:?}");
        assert_eq!(f.sessions(), 1, "the expired arena was actually wiped even when audit failed");
        std::fs::remove_dir(&f.audit).unwrap();
        assert!(f.call(RunnerRequest::SsmFork { label: low() }).unwrap_err().is("SSM_LIFECYCLE_AUDIT_FAILED"));
        assert!(f.call(RunnerRequest::SsmGenerate { session: id, n: 1 }).unwrap_err().is("SSM_LIFECYCLE_AUDIT_FAILED"));
        for request in [
            RunnerRequest::Think { prompt: b"seed".to_vec().into(), n: 1, k: 1 },
            RunnerRequest::GenerateStructured { schema: ArgSchema::Bool, len: 1, prompt: None },
            RunnerRequest::Bind { manifest: b"invalid".to_vec().into(), cas_uri: "cas://invalid".into(), calibration_corpus: None },
        ] {
            assert!(f.call(request).unwrap_err().is("SSM_LIFECYCLE_AUDIT_FAILED"));
        }
        let package = crate::zoo::package(ExecutionClass::RecurrentSsmTtt).unwrap();
        assert!(f.service.bind_bytes(&package.manifest_bytes(), &package.weights, None).unwrap_err().is("SSM_LIFECYCLE_AUDIT_FAILED"));
        assert!(f.service.bind_bytes_with_companions(&package.manifest_bytes(), &package.weights, &[], None).unwrap_err().is("SSM_LIFECYCLE_AUDIT_FAILED"));
        let RunnerResponse::Status(status) = f.call(RunnerRequest::Status).unwrap() else { panic!() };
        assert!(status.state.contains("ssm_lifecycle=audit_failed"));
        assert!(f.call(RunnerRequest::Zeroize(ZeroizeTrigger::TaskExit)).unwrap_err().is("SSM_LIFECYCLE_AUDIT_FAILED"));
        assert_eq!(f.sessions(), 0, "audit fault must not block actual emergency cleanup");
        let state = f.service.state.lock().unwrap();
        let retained = state.ssm_expiry_audit_fault.as_ref().unwrap();
        assert_eq!(retained.len(), 2, "preserve actual expired and emergency wipe measurements without claiming durable recording");
        assert!(retained.iter().all(|r| r.bytes > 0 && r.residual == 0));
    }
}

#[cfg(test)]
mod release_fence_tests {
    use super::*;
    use crate::classes::speculative::{FixedThermal, PowerSource, ThermalState};
    use crate::classes::world::{ResolvedTarget, WorldGate, WorldModel};
    use crate::manifest::WorldPlannerCaps;
    use enclave_core::ipc::{self, PeerPolicy, Reply, ServeLimits, ServeStats};
    use std::cell::RefCell;
    use std::io::Read;
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::mpsc::{self, Receiver, Sender};
    use std::time::{Duration, Instant};

    const WAIT: Duration = Duration::from_secs(2);
    thread_local! {
        // Per-thread rendezvous only: no production hook or secret observation.
        static CAPTURE: RefCell<Option<(Sender<()>, Receiver<()>)>> = const { RefCell::new(None) };
    }
    pub(super) fn after_capture() {
        let rendezvous = CAPTURE.with(|hook| hook.borrow_mut().take());
        if let Some((entered, resume)) = rendezvous {
            entered.send(()).unwrap();
            resume.recv_timeout(WAIT).unwrap();
        }
    }
    fn until(mut ready: impl FnMut() -> bool) {
        let start = Instant::now();
        while !ready() {
            assert!(start.elapsed() < WAIT, "bounded test rendezvous");
            std::thread::yield_now();
        }
    }
    struct NoWeights;
    impl WeightSource for NoWeights {
        fn resolve(&self, _: &str) -> EnclaveResult<ResolvedWeights> { fail!(EPERM, "NO_WEIGHTS"); }
    }
    fn peer() -> PeerCredentials { PeerCredentials::local(ipc::geteuid(), 0) }
    fn service(class: ExecutionClass, audit_path: Option<PathBuf>) -> Arc<RunnerService> {
        let service = RunnerService::start(RunnerConfig {
            dev_same_uid: true, profile: Profile::L2, audit_path,
            calib_corpus_blake3: None, state_dir: None, actuator: None,
            thermal: Box::new(|| Box::new(FixedThermal(ThermalState::Nominal, PowerSource::Ac))),
        }, Box::new(NoWeights)).unwrap();
        let package = crate::zoo::package(class).unwrap();
        service.bind_bytes(&package.manifest_bytes(), &package.weights, None).unwrap();
        service
    }
    fn fork() -> RunnerRequest { RunnerRequest::SsmFork { label: Label::BOTTOM } }
    fn session(service: &RunnerService) -> u64 {
        let RunnerResponse::Session(id) = service.handle(&peer(), fork()).unwrap() else { panic!() };
        id
    }
    fn sessions(service: &RunnerService) -> usize {
        let state = service.state.lock().unwrap();
        let Engine::Ssm(dag) = &state.adapter.as_ref().unwrap().engine else { panic!() };
        dag.sessions()
    }
    fn wipe(service: &RunnerService) -> EnclaveResult<RunnerResponse> {
        service.handle(&peer(), RunnerRequest::Zeroize(ZeroizeTrigger::TaskExit))
    }

    #[test]
    fn yk03_authorized_pending_wipe_fences_before_blocked_state_and_unauthorized_is_inert() {
        let service = service(ExecutionClass::RecurrentSsmTtt, None);
        session(&service);
        let epoch = service.release_fence.capture().unwrap();
        let state = service.state.lock().unwrap();
        let stranger = PeerCredentials::local(701_777, 0);
        assert!(service.handle(&stranger, RunnerRequest::Zeroize(ZeroizeTrigger::TaskExit))
            .unwrap_err().is("WIPE_PEER_REJECTED"));
        assert!(!service.cancel.load(Ordering::Acquire));
        assert_eq!(service.release_fence.capture().unwrap(), epoch);
        let worker = service.clone();
        let wipe = std::thread::spawn(move || wipe(&worker));
        until(|| service.cancel.load(Ordering::Acquire));
        assert!(service.release_fence.validate(epoch).unwrap_err().is("MODEL_RELEASE_FENCED"));
        assert!(service.handle(&peer(), fork()).unwrap_err().is("MODEL_RELEASE_FENCED"));
        assert_eq!(service.release_fence.state().unwrap().pending, 1);
        drop(state);
        assert!(matches!(wipe.join().unwrap().unwrap(), RunnerResponse::Wiped(_)));
        assert_eq!(sessions(&service), 0);
        assert!(!service.cancel.load(Ordering::Acquire));
        assert!(service.release_fence.validate(epoch).is_err());
        session(&service);
    }

    #[test]
    fn yk03_request_captured_before_completed_wipe_cannot_gain_fresh_admission() {
        let service = service(ExecutionClass::RecurrentSsmTtt, None);
        let (captured_tx, captured_rx) = mpsc::channel();
        let (resume_tx, resume_rx) = mpsc::channel();
        let worker = service.clone();
        let request = std::thread::spawn(move || {
            CAPTURE.with(|hook| *hook.borrow_mut() = Some((captured_tx, resume_rx)));
            worker.handle(&peer(), fork())
        });
        captured_rx.recv_timeout(WAIT).unwrap();
        // The old call is paused precisely after capture and before operation
        // acquisition. A full wipe, including cancellation clearing, runs first.
        wipe(&service).unwrap();
        assert!(!service.cancel.load(Ordering::Acquire));
        resume_tx.send(()).unwrap();
        assert!(request.join().unwrap().unwrap_err().is("MODEL_RELEASE_FENCED"));
        assert_eq!(sessions(&service), 0, "old request must not create a handle");
        session(&service);
    }

    #[test]
    fn yk03_overlapping_wipes_keep_admission_closed_until_all_complete() {
        let service = service(ExecutionClass::RecurrentSsmTtt, None);
        session(&service);
        let epoch = service.release_fence.capture().unwrap();
        let operation = service.operation.lock().unwrap();
        let wipes: Vec<_> = (0..2).map(|_| {
            let worker = service.clone();
            std::thread::spawn(move || wipe(&worker))
        }).collect();
        until(|| service.release_fence.state().unwrap().pending == 2);
        assert!(service.cancel.load(Ordering::Acquire));
        assert!(service.release_fence.validate(epoch).is_err());
        assert!(service.handle(&peer(), fork()).unwrap_err().is("MODEL_RELEASE_FENCED"));
        drop(operation);
        for wipe in wipes { wipe.join().unwrap().unwrap(); }
        assert_eq!(service.release_fence.state().unwrap().pending, 0);
        assert!(!service.cancel.load(Ordering::Acquire));
        assert!(service.release_fence.validate(epoch).is_err());
        assert_eq!(sessions(&service), 0);
        session(&service);
    }

    #[test]
    fn yk03_uncompleted_cleanup_latches_until_actual_successful_retry() {
        let service = service(ExecutionClass::RecurrentSsmTtt, None);
        let epoch = service.release_fence.capture().unwrap();
        // Inject a cleanup return before completion, using the real production
        // registration guard. Its destructor must never clear cancellation.
        drop(service.begin_wipe());
        assert!(service.cancel.load(Ordering::Acquire));
        assert!(service.handle(&peer(), fork()).unwrap_err().is("MODEL_RELEASE_FENCED"));
        assert!(matches!(service.handle(&peer(), RunnerRequest::Status).unwrap(), RunnerResponse::Status(_)));
        wipe(&service).unwrap();
        assert!(!service.cancel.load(Ordering::Acquire));
        assert!(service.release_fence.validate(epoch).is_err());
        session(&service);
    }

    #[test]
    fn yk03_actual_cleanup_audit_error_retains_latch_and_never_retries_uncertain_journal() {
        let path = std::env::temp_dir().join(format!("yk03-audit-{}.jsonl", enclave_core::rng::u64()));
        let service = service(ExecutionClass::RecurrentSsmTtt, Some(path.clone()));
        session(&service);
        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir(&path).unwrap();
        assert!(wipe(&service).unwrap_err().is("AUDIT_OPEN"));
        assert_eq!(sessions(&service), 0, "actual cleanup precedes journal failure");
        assert!(service.cancel.load(Ordering::Acquire));
        assert_eq!(service.release_fence.state().unwrap().pending, 0);
        assert!(service.handle(&peer(), fork()).unwrap_err().is("MODEL_RELEASE_FENCED"));
        std::fs::remove_dir(&path).unwrap();
        assert!(wipe(&service).unwrap_err().is("AUDIT_WRITE_UNCERTAIN"));
        assert!(!path.exists(), "an ambiguous journal append is never retried");
        assert!(service.cancel.load(Ordering::Acquire));
        assert!(service.release_fence.capture().is_err());
    }

    #[test]
    fn yk03_epoch_or_pending_exhaustion_still_cleans_and_permanently_denies_authority() {
        for exhaust_epoch in [true, false] {
            let service = service(ExecutionClass::RecurrentSsmTtt, None);
            session(&service);
            let old_epoch = service.release_fence.capture().unwrap();
            {
                let mut state = service.release_fence.state().unwrap();
                if exhaust_epoch { state.epoch = u64::MAX; } else { state.pending = usize::MAX; }
            }
            for _ in 0..2 {
                assert!(wipe(&service).unwrap_err().is("MODEL_RELEASE_EXHAUSTED"));
                assert_eq!(sessions(&service), 0);
                assert!(service.cancel.load(Ordering::Acquire));
                assert!(service.release_fence.broken.load(Ordering::Acquire));
                assert!(service.release_fence.validate(old_epoch).is_err());
                assert!(service.handle(&peer(), fork()).unwrap_err().is("MODEL_RELEASE_FENCED"));
            }
        }
    }

    #[test]
    fn yk03_poisoned_fence_still_cleans_and_never_revives() {
        for poison_serial in [true, false] {
            let service = service(ExecutionClass::RecurrentSsmTtt, None);
            session(&service);
            let fence = service.release_fence.clone();
            assert!(std::thread::spawn(move || {
                if poison_serial {
                    let _guard = fence.serial.lock().unwrap();
                    panic!("synthetic release-lock poison");
                } else {
                    let _guard = fence.state.lock().unwrap();
                    panic!("synthetic fence-state poison");
                }
            }).join().is_err());
            let error = wipe(&service).unwrap_err();
            assert!(error.is(if poison_serial { "MODEL_RELEASE_LOCK_POISONED" } else { "MODEL_RELEASE_STATE_POISONED" }));
            assert_eq!(sessions(&service), 0);
            assert!(service.cancel.load(Ordering::Acquire));
            assert!(service.release_fence.broken.load(Ordering::Acquire));
            assert!(service.release_fence.capture().is_err());
        }
    }

    // Uses the public production IPC server, its real kernel peer credentials,
    // actual CBOR serialization and final ReleasePermit socket handoff.
    struct Wire {
        path: PathBuf,
        stop: Arc<AtomicBool>,
        server: Option<std::thread::JoinHandle<EnclaveResult<()>>>,
    }
    impl Wire {
        fn start(handler: impl Fn(&PeerCredentials, RunnerRequest) -> EnclaveResult<RunnerResponse> + Send + Sync + 'static) -> Self {
            let path = std::env::temp_dir().join(format!("yk03-{}.sock", enclave_core::rng::u64()));
            let listener = UnixListener::bind(&path).unwrap();
            let stop = Arc::new(AtomicBool::new(false));
            let stopping = stop.clone();
            let server = std::thread::spawn(move || ipc::serve_with(
                listener, PeerPolicy::allow([ipc::geteuid()]), ServeLimits::default(),
                Arc::new(ServeStats::default()), Arc::new(handler), stopping,
            ));
            Self { path, stop, server: Some(server) }
        }
        fn connect(&self) -> UnixStream {
            let stream = UnixStream::connect(&self.path).unwrap();
            stream.set_read_timeout(Some(WAIT)).unwrap();
            stream.set_write_timeout(Some(WAIT)).unwrap();
            stream
        }
    }
    impl Drop for Wire {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Release);
            self.server.take().unwrap().join().unwrap().unwrap();
            std::fs::remove_file(&self.path).unwrap();
        }
    }
    fn send(stream: &mut UnixStream, request: &RunnerRequest) {
        ipc::write_frame(stream, &ipc::to_cbor(request).unwrap()).unwrap();
    }
    fn receive(stream: &mut UnixStream) -> Reply<RunnerResponse> {
        ipc::from_cbor(&ipc::read_frame(stream).unwrap()).unwrap()
    }

    #[test]
    fn yk03_actual_wire_withholds_delayed_handle_and_output_after_completed_wipe() {
        for output in [false, true] {
            let service = service(ExecutionClass::RecurrentSsmTtt, None);
            let (returned_tx, returned_rx) = mpsc::channel();
            let (resume_tx, resume_rx) = mpsc::channel();
            let resume_rx = Mutex::new(resume_rx);
            let worker = service.clone();
            let wire = Wire::start(move |peer, request| {
                let hold = matches!((&request, output),
                    (RunnerRequest::SsmFork { .. }, false) | (RunnerRequest::SsmGenerate { .. }, true));
                let response = worker.handle(peer, request);
                if hold {
                    returned_tx.send(response.as_ref().map(|_| ()).map_err(Clone::clone)).unwrap();
                    if response.is_ok() { resume_rx.lock().unwrap().recv_timeout(WAIT).unwrap(); }
                }
                response
            });
            let mut stream = wire.connect();
            let request = if output {
                // SSM ownership includes the kernel PID. Create and use this
                // session on the same authenticated wire, never a pid=None
                // synthetic caller followed by a real kernel-attested caller.
                send(&mut stream, &fork());
                let Reply::Ok(RunnerResponse::Session(id)) = receive(&mut stream) else { panic!() };
                RunnerRequest::SsmGenerate { session: id, n: 1 }
            } else { fork() };
            send(&mut stream, &request);
            returned_rx.recv_timeout(WAIT).unwrap().unwrap();
            // Cancellation has completely cleared by the time the already
            // successful handler response proceeds into serialization/handoff.
            wipe(&service).unwrap();
            assert!(!service.cancel.load(Ordering::Acquire));
            assert_eq!(sessions(&service), 0);
            resume_tx.send(()).unwrap();
            let mut first = [0u8; 1];
            assert_eq!(stream.read(&mut first).unwrap(), 0, "no stale success byte may cross the actual wire");
            drop(stream);
            drop(wire);
            session(&service);
        }
    }

    #[test]
    fn yk03_actual_wire_completed_release_stands_and_fresh_later_request_succeeds() {
        let service = service(ExecutionClass::RecurrentSsmTtt, None);
        let worker = service.clone();
        let wire = Wire::start(move |peer, request| worker.handle(peer, request));
        let mut stream = wire.connect();
        send(&mut stream, &fork());
        let Reply::Ok(RunnerResponse::Session(old)) = receive(&mut stream) else { panic!() };
        wipe(&service).unwrap();
        // Previously delivered bytes remain a valid observation; the handle's
        // backing session is gone and the same connection needs fresh capture.
        send(&mut stream, &RunnerRequest::SsmGenerate { session: old, n: 1 });
        let Reply::Err(error) = receive(&mut stream) else { panic!() };
        assert!(error.is("UNKNOWN_SESSION"));
        send(&mut stream, &fork());
        let Reply::Ok(RunnerResponse::Session(fresh)) = receive(&mut stream) else { panic!() };
        assert_ne!(old, fresh);
        drop(stream);
    }

    #[derive(Debug)]
    struct PausedModel { entered: Sender<()>, resume: Mutex<Receiver<()>> }
    impl WorldModel for PausedModel {
        fn width(&self) -> usize { 1 }
        fn encode(&self, _: &Frame) -> EnclaveResult<Vec<f32>> { Ok(vec![0.25]) }
        fn predict(&self, _: &[f32], _: &Action) -> EnclaveResult<Vec<f32>> {
            self.entered.send(()).unwrap();
            self.resume.lock().unwrap().recv_timeout(WAIT).unwrap();
            Ok(vec![0.25])
        }
        fn cost(&self, _: &[f32], _: &[f32]) -> f32 { 0.0 }
        fn cone(&self, _: &[f32]) -> f32 { 0.0 }
    }
    struct CountActuator(Arc<AtomicUsize>);
    impl Actuator for CountActuator {
        fn prepare_bounded(&mut self, _: &Action, _: Instant) -> EnclaveResult<()> { Ok(()) }
        fn execute_bounded(&mut self, deadline: Instant) -> EnclaveResult<()> {
            assert!(Instant::now() < deadline);
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
        fn execute(&mut self, _: &Action) -> EnclaveResult<()> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }
    #[test]
    fn yk03_fence_during_planning_rejects_before_actuator_dispatch() {
        let service = service(ExecutionClass::JepaEbmWorldPlanner, None);
        let (entered_tx, entered_rx) = mpsc::channel();
        let (resume_tx, resume_rx) = mpsc::channel();
        let calls = Arc::new(AtomicUsize::new(0));
        {
            let mut state = service.state.lock().unwrap();
            state.adapter.as_mut().unwrap().engine = Engine::World(WorldGate::new(
                Box::new(PausedModel { entered: entered_tx, resume: Mutex::new(resume_rx) }),
                WorldPlannerCaps { max_horizon: 1, max_candidates: 1, max_cem_iters: 1,
                    e_max: 1.0, step_wallclock_ms: 150, tau_surprise: 1.0, actuation_sandbox: None },
                0.5, 1.0,
            ).unwrap());
            state.actuator = Some(Box::new(CountActuator(calls.clone())));
        }
        let worker = service.clone();
        let plan = std::thread::spawn(move || worker.handle(&peer(), RunnerRequest::Plan { actuate: true,
            w: 8, h: 8, px: vec![17; 64].into(), goal_px: vec![23; 64].into(),
            pii_boxes: vec![], scroll_velocity: 0, tools_mask: 2,
            origins: vec!["https://fence.invalid".into()], candidates: vec![Action {
                tool_id: 1, params_q: vec![0], target: ResolvedTarget {
                    app_bundle_id: "org.example.browser".into(), ax_role: "AXButton".into(),
                    ax_title: "Continue".into(), url_origin: "https://fence.invalid".into(),
                    dom_selector: "#fenced".into(),
                },
            }],
        }));
        entered_rx.recv_timeout(WAIT).unwrap();
        let worker = service.clone();
        let wipe = std::thread::spawn(move || wipe(&worker));
        until(|| service.cancel.load(Ordering::Acquire));
        resume_tx.send(()).unwrap();
        assert!(plan.join().unwrap().unwrap_err().is("MODEL_RELEASE_FENCED"));
        wipe.join().unwrap().unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert!(service.state.lock().unwrap().pending.is_none());
    }
    #[derive(Debug)]
    struct ReadyModel;
    impl WorldModel for ReadyModel {
        fn width(&self) -> usize { 1 }
        fn encode(&self, _: &Frame) -> EnclaveResult<Vec<f32>> { Ok(vec![0.25]) }
        fn predict(&self, _: &[f32], _: &Action) -> EnclaveResult<Vec<f32>> { Ok(vec![0.25]) }
        fn cost(&self, _: &[f32], _: &[f32]) -> f32 { 0.0 }
        fn cone(&self, _: &[f32]) -> f32 { 0.0 }
    }
    fn bounded_service(actuator: Box<dyn Actuator + Send>) -> Arc<RunnerService> {
        let service = service(ExecutionClass::JepaEbmWorldPlanner, None);
        {
            let mut state = service.state.lock().unwrap();
            state.adapter.as_mut().unwrap().engine = Engine::World(WorldGate::new(
                Box::new(ReadyModel), WorldPlannerCaps { max_horizon: 1, max_candidates: 1,
                    max_cem_iters: 1, e_max: 1.0, step_wallclock_ms: 150,
                    tau_surprise: 1.0, actuation_sandbox: None }, 0.5, 1.0,
            ).unwrap());
            state.actuator = Some(actuator);
        }
        service
    }
    fn bounded_plan() -> RunnerRequest {
        RunnerRequest::Plan { actuate: true, w: 8, h: 8, px: vec![17;64].into(), goal_px: vec![23;64].into(),
            pii_boxes: vec![], scroll_velocity: 0, tools_mask: 2,
            origins: vec!["https://fence.invalid".into()], candidates: vec![Action {
                tool_id: 1, params_q: vec![0], target: ResolvedTarget {
                    app_bundle_id: "org.example.browser".into(), ax_role: "AXButton".into(),
                    ax_title: "Continue".into(), url_origin: "https://fence.invalid".into(), dom_selector: "#fenced".into(),
                },
            }],
        }
    }
    struct LegacyActuator(Arc<AtomicUsize>);
    impl Actuator for LegacyActuator {
        fn execute(&mut self, _: &Action) -> EnclaveResult<()> { self.0.fetch_add(1, Ordering::SeqCst); Ok(()) }
    }
    #[test]
    fn plan_without_actuate_never_reaches_the_actuator_and_owes_no_observation() {
        let calls = Arc::new(AtomicUsize::new(0));
        let service = bounded_service(Box::new(CountActuator(calls.clone())));
        let mut plan = bounded_plan();
        if let RunnerRequest::Plan { actuate, .. } = &mut plan { *actuate = false; }
        for _ in 0..2 {
            let reply = service.handle(&peer(), plan.clone()).unwrap();
            assert!(matches!(reply, RunnerResponse::Planned { actuated: false, .. }));
        }
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert!(service.state.lock().unwrap().pending.is_none());
        wipe(&service).unwrap();
    }

    #[test]
    fn plan_actuate_defaults_to_false_on_the_wire() {
        #[derive(serde::Serialize)]
        enum Legacy { Plan { w: u32, h: u32, px: ByteBuf, pii_boxes: Vec<Rect>, scroll_velocity: u32,
            goal_px: ByteBuf, candidates: Vec<Action>, tools_mask: u64, origins: Vec<String> } }
        let legacy = Legacy::Plan { w: 8, h: 8, px: vec![0; 64].into(), pii_boxes: vec![], scroll_velocity: 0,
            goal_px: vec![0; 64].into(), candidates: vec![], tools_mask: 0, origins: vec![] };
        let decoded: RunnerRequest = enclave_core::ipc::from_cbor(&enclave_core::ipc::to_cbor(&legacy).unwrap()).unwrap();
        assert!(matches!(decoded, RunnerRequest::Plan { actuate: false, .. }));
    }

    #[test]
    fn bounded_gate_default_refuses_legacy_actuator_without_calling_execute() {
        let calls = Arc::new(AtomicUsize::new(0));
        let service = bounded_service(Box::new(LegacyActuator(calls.clone())));
        assert!(service.handle(&peer(), bounded_plan()).unwrap_err().is("ACTUATOR_BOUNDED_UNSUPPORTED"));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert!(service.state.lock().unwrap().pending.is_some());
        assert!(service.handle(&peer(), bounded_plan()).unwrap_err().is("WORLD_OBSERVATION_REQUIRED"));
        wipe(&service).unwrap();
    }
    #[test]
    fn bounded_gate_expired_trusted_caller_deadline_sends_no_effect() {
        let calls = Arc::new(AtomicUsize::new(0));
        let service = bounded_service(Box::new(CountActuator(calls.clone())));
        assert!(service.handle_before(&peer(), bounded_plan(), Instant::now()).unwrap_err().is("CDP_DEADLINE"));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert!(service.state.lock().unwrap().pending.is_some());
        wipe(&service).unwrap();
    }
    struct RendezvousActuator {
        in_prepare: bool, entered: Sender<Instant>, resume: Receiver<()>, calls: Arc<AtomicUsize>,
    }
    impl Actuator for RendezvousActuator {
        fn execute(&mut self, _: &Action) -> EnclaveResult<()> { panic!("legacy execute must not run") }
        fn prepare_bounded(&mut self, _: &Action, deadline: Instant) -> EnclaveResult<()> {
            if self.in_prepare { self.entered.send(deadline).unwrap(); self.resume.recv_timeout(WAIT).unwrap(); }
            Ok(())
        }
        fn execute_bounded(&mut self, deadline: Instant) -> EnclaveResult<()> {
            assert!(Instant::now() < deadline);
            if !self.in_prepare { self.entered.send(deadline).unwrap(); self.resume.recv_timeout(deadline.saturating_duration_since(Instant::now())).unwrap(); }
            assert!(Instant::now() < deadline);
            self.calls.fetch_add(1, Ordering::SeqCst); Ok(())
        }
    }
    #[test]
    fn bounded_prepare_stall_never_holds_fence_and_captured_epoch_cannot_dispatch() {
        let (entered_tx, entered_rx) = mpsc::channel(); let (resume_tx, resume_rx) = mpsc::channel();
        let calls = Arc::new(AtomicUsize::new(0));
        let service = bounded_service(Box::new(RendezvousActuator { in_prepare: true,
            entered: entered_tx, resume: resume_rx, calls: calls.clone() }));
        let worker = service.clone(); let plan = std::thread::spawn(move || worker.handle(&peer(), bounded_plan()));
        entered_rx.recv_timeout(WAIT).unwrap();
        let worker = service.clone(); let cleanup = std::thread::spawn(move || wipe(&worker));
        until(|| service.cancel.load(Ordering::Acquire));
        // Wipe established its epoch while prepare still owns State/operation.
        // begin_wipe sets `cancel` just before releasing serial, so wait
        // (bounded) for the release while prepare is still stalled.
        until(|| service.release_fence.serial.try_lock().is_ok());
        resume_tx.send(()).unwrap();
        assert!(plan.join().unwrap().unwrap_err().is("MODEL_RELEASE_FENCED"));
        cleanup.join().unwrap().unwrap(); assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert!(service.state.lock().unwrap().pending.is_none());
    }
    #[test]
    fn bounded_dispatch_accepted_before_fence_completes_before_fence_establishment() {
        let (entered_tx, entered_rx) = mpsc::channel(); let (resume_tx, resume_rx) = mpsc::channel();
        let calls = Arc::new(AtomicUsize::new(0));
        let service = bounded_service(Box::new(RendezvousActuator { in_prepare: false,
            entered: entered_tx, resume: resume_rx, calls: calls.clone() }));
        let worker = service.clone(); let plan = std::thread::spawn(move || worker.handle(&peer(), bounded_plan()));
        let deadline = entered_rx.recv_timeout(WAIT).unwrap();
        assert!(matches!(service.release_fence.serial.try_lock(), Err(std::sync::TryLockError::WouldBlock)));
        let (started_tx, started_rx) = mpsc::channel(); let worker = service.clone();
        let cleanup = std::thread::spawn(move || { started_tx.send(()).unwrap(); wipe(&worker) });
        started_rx.recv_timeout(WAIT).unwrap();
        assert!(!service.cancel.load(Ordering::Acquire), "fence cannot pass accepted in-flight dispatch");
        assert!(Instant::now() < deadline); resume_tx.send(()).unwrap();
        let result = plan.join().unwrap();
        // The final response can win before the fence or be refused afterward;
        // the already completed pre-fence dispatch stands in either schedule.
        match result { Ok(RunnerResponse::Planned { actuated: true, .. }) => {},
            Err(error) if error.is("MODEL_RELEASE_FENCED") => {}, other => panic!("{other:?}") }
        cleanup.join().unwrap().unwrap(); assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(service.state.lock().unwrap().pending.is_none());
    }

    #[test]
    fn bounded_prepare_carries_shorter_caller_deadline_and_does_not_refresh_after_wait() {
        let (entered_tx, entered_rx) = mpsc::channel(); let (resume_tx, resume_rx) = mpsc::channel();
        let calls = Arc::new(AtomicUsize::new(0));
        let service = bounded_service(Box::new(RendezvousActuator { in_prepare: true,
            entered: entered_tx, resume: resume_rx, calls: calls.clone() }));
        let deadline = Instant::now() + Duration::from_millis(80);
        let worker = service.clone();
        let plan = std::thread::spawn(move || worker.handle_before(&peer(), bounded_plan(), deadline));
        assert_eq!(entered_rx.recv_timeout(WAIT).unwrap(), deadline);
        std::thread::sleep(deadline.saturating_duration_since(Instant::now()) + Duration::from_millis(1));
        resume_tx.send(()).unwrap();
        assert!(plan.join().unwrap().unwrap_err().is("CDP_DEADLINE"));
        assert_eq!(calls.load(Ordering::SeqCst), 0); assert!(service.state.lock().unwrap().pending.is_some());
        wipe(&service).unwrap();
    }

}
