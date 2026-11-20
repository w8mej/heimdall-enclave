//! The conjunctive policy decision point (FS-704 §4.2, ADR-008, ADR-015):
//!
//! `Allow ⇔ Cedar.is_authorized() ∧ Biscuit.authorize()`
//!
//! Both engines are always evaluated (no short-circuit), so audit receipts
//! record both verdicts. Label facts (`input_c`, `input_t`, `ast_taint`) are
//! computed from the capability heap, never taken from the caller, and the
//! Biba slot rule fails closed *before* either engine runs.

#![forbid(unsafe_code)]

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, RwLock};
use std::time::Instant;

use enclave_core::error::EnclaveResult;
use enclave_core::ipc::PeerCredentials;
use enclave_core::label::{Label, SlotKind};
use enclave_core::profile::Profile;
use enclave_core::qif::{millibits_for_outcomes, QifCharge, QifLedger};
use enclave_core::{err, fail};
use enclave_crypto::biscuit_auth::{AuthorizerLimits, KeyPair, PublicKey};
use enclave_crypto::pop_biscuit::{
    parse_and_verify_token, verify_call_with_facts, PopBiscuitWireV1, RequestFacts,
    VerifiedTokenFacts, VerifyContext, MAX_DEPTH,
};
use enclave_crypto::replay::ReplayWindow;
use serde::{Deserialize, Serialize};

use crate::cedar_engine::{CallFacts, CedarAction, CedarEngine, ToolResource};
use crate::heap::CapabilityHeap;
use crate::policy_sli::{ClockSample, PolicySli, PolicySliSnapshot};

/// Verified token LRU cache capacity (GAP-22).
pub const TOKEN_CACHE_CAPACITY: usize = 1024;

/// LRU cache of verified token facts (GAP-22).
#[derive(Debug)]
pub struct VerifiedTokenCache {
    entries: HashMap<[u8; 32], VerifiedTokenFacts>,
    order: VecDeque<[u8; 32]>,
    capacity: usize,
}

impl VerifiedTokenCache {
    /// Create a cache with specified capacity.
    pub fn new(capacity: usize) -> Self {
        Self {
            entries: HashMap::new(),
            order: VecDeque::new(),
            capacity,
        }
    }

    /// Retrieve verified token facts by `chain_blake3`.
    pub fn get(&mut self, chain: &[u8; 32]) -> Option<&VerifiedTokenFacts> {
        if self.entries.contains_key(chain) {
            if let Some(pos) = self.order.iter().position(|k| k == chain) {
                self.order.remove(pos);
                self.order.push_back(*chain);
            }
            self.entries.get(chain)
        } else {
            None
        }
    }

    /// Insert verified token facts.
    pub fn insert(&mut self, chain: [u8; 32], facts: VerifiedTokenFacts) {
        if self.entries.len() >= self.capacity {
            if let Some(oldest) = self.order.pop_front() {
                self.entries.remove(&oldest);
            }
        }
        self.order.push_back(chain);
        self.entries.insert(chain, facts);
    }

    /// Evict a single token by its `chain_blake3`.
    pub fn evict(&mut self, chain: &[u8; 32]) {
        self.entries.remove(chain);
        self.order.retain(|k| k != chain);
    }

    /// Clear all cached token facts (e.g. on revocation / policy swap).
    pub fn clear(&mut self) {
        self.entries.clear();
        self.order.clear();
    }
}

/// A tool call **as resolved by the service** from the signed MCP lock, the
/// heap and the enclave clock (GAP-04). No field is taken from an IPC peer.
#[derive(Debug, Clone)]
pub struct ToolCallRequest {
    /// Calling agent role (`orchestrator`, `db_researcher`, ...).
    pub agent: String,
    /// Target tool.
    pub tool: ToolResource,
    /// RFC 8785 JCS bytes of the arguments.
    pub args_jcs: Vec<u8>,
    /// Argument handles and the slot each occupies.
    pub arg_slots: Vec<(SlotKind, String)>,
    /// Whether caller-authored argument values occupy structural slots. This
    /// is resolved from the signed lock, never accepted as an IPC assertion.
    pub literal_structural: bool,
    /// Requested rows.
    pub row_count: u64,
    /// QIF charge.
    pub qif_mb: i64,
    /// A verified hardware intent grant (`d_JCS`) accompanies the call.
    pub hw_grant: bool,
    /// `PoPBiscuitWireV1` CBOR frame.
    pub wire_cbor: Vec<u8>,
}

/// Decision record (zero-PII).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Decision {
    /// Cedar verdict.
    pub cedar_allow: bool,
    /// Biscuit verdict.
    pub biscuit_allow: bool,
    /// Conjunction.
    pub allow: bool,
    /// Determining Cedar policies.
    pub cedar_reasons: Vec<String>,
    /// Biscuit failure reason.
    pub biscuit_error: Option<String>,
    /// Delegation depth.
    pub depth: Option<u32>,
    /// End-to-end evaluation time (ns).
    pub eval_ns: u64,
    /// Joined input label.
    pub input_label: Label,
}

/// Grace window for token policy bundle mismatch (FS-704 §11 / GAP-32).
pub const POLICY_SWAP_GRACE_WINDOW_NS: u64 = 60_000_000_000; // 60 seconds

/// Swap record for grace window evaluation (GAP-32).
#[derive(Debug, Clone, Copy)]
pub struct PolicySwapRecord {
    /// Previous bundle BLAKE3 digest.
    pub previous_bundle_blake3: [u8; 32],
    /// Continuous nanoseconds when the swap took place.
    pub swap_mach_ns: u64,
}

/// The PDP.
#[derive(Debug)]
pub struct Pdp {
    /// Cedar engine (atomic hot-swap, GAP-32).
    cedar: Arc<RwLock<Arc<CedarEngine>>>,
    /// Swap history for grace window check.
    swap_history: Arc<RwLock<Option<PolicySwapRecord>>>,
    root: KeyPair,
    boot_epoch_id: String,
    profile: Profile,
    replay: HashMap<[u8; 32], ReplayWindow>,
    /// Verified token LRU cache (GAP-22).
    token_cache: Arc<RwLock<VerifiedTokenCache>>,
    policy_sli: PolicySli,
    /// Biscuit authorizer limits.
    pub limits: AuthorizerLimits,
}

impl Pdp {
    /// New PDP with a fresh per-boot Biscuit root key.
    pub fn new(
        cedar: CedarEngine,
        boot_epoch_id: String,
        profile: Profile,
        limits: AuthorizerLimits,
    ) -> Self {
        Self {
            cedar: Arc::new(RwLock::new(Arc::new(cedar))),
            swap_history: Arc::new(RwLock::new(None)),
            root: KeyPair::new(),
            boot_epoch_id,
            profile,
            replay: HashMap::new(),
            token_cache: Arc::new(RwLock::new(VerifiedTokenCache::new(TOKEN_CACHE_CAPACITY))),
            limits,
            policy_sli: PolicySli::new(ClockSample::now()),
        }
    }
    /// Biscuit root key pair (authority block signer).
    pub fn root(&self) -> &KeyPair {
        &self.root
    }
    /// Root public key.
    pub fn root_public(&self) -> PublicKey {
        self.root.public()
    }
    /// Boot epoch.
    pub fn boot_epoch_id(&self) -> &str {
        &self.boot_epoch_id
    }
    /// Profile.
    pub fn profile(&self) -> Profile {
        self.profile
    }

    /// Read snapshot of the active Cedar engine.
    pub fn cedar(&self) -> Arc<CedarEngine> {
        self.cedar.read().unwrap().clone()
    }

    /// BLAKE3 digest of the active Cedar bundle.
    pub fn cedar_bundle_blake3(&self) -> [u8; 32] {
        self.cedar.read().unwrap().bundle_blake3()
    }

    /// Atomically hot-swap the Cedar engine and record swap timestamp (GAP-32).
    pub fn swap_cedar(&self, new_engine: CedarEngine, now_mach_ns: u64) {
        let prev_hash = self.cedar.read().unwrap().bundle_blake3();
        *self.swap_history.write().unwrap() = Some(PolicySwapRecord {
            previous_bundle_blake3: prev_hash,
            swap_mach_ns: now_mach_ns,
        });
        *self.cedar.write().unwrap() = Arc::new(new_engine);
        // Evict token cache on policy swap (GAP-22)
        self.token_cache.write().unwrap().clear();
    }

    /// Evict a specific token from the cache on revocation (GAP-22).
    pub fn evict_token(&self, chain: &[u8; 32]) {
        self.token_cache.write().unwrap().evict(chain);
    }

    /// Clear all cached verified tokens (GAP-22).
    pub fn clear_token_cache(&self) {
        self.token_cache.write().unwrap().clear();
    }

    /// Read per-boot latency telemetry without changing policy/replay state.
    pub fn policy_sli_snapshot(&mut self) -> PolicySliSnapshot {
        let mut snapshot = self.policy_sli.snapshot(ClockSample::now());
        snapshot.boot_epoch_id = self.boot_epoch_id.clone();
        snapshot.profile = self.profile.to_string();
        snapshot.cedar_bundle_blake3 = hex::encode(self.cedar_bundle_blake3());
        snapshot
    }

    /// Authorize one MCP/A2A `tools/call`.
    pub fn authorize(
        &mut self,
        heap: &CapabilityHeap,
        peer: &PeerCredentials,
        req: &ToolCallRequest,
        now_mach_ns: u64,
        now_utc_ms: u64,
    ) -> EnclaveResult<Decision> {
        let t0 = Instant::now();
        let result = self.authorize_inner(heap, peer, req, now_mach_ns, now_utc_ms);
        let elapsed_ns = u64::try_from(t0.elapsed().as_nanos()).ok();
        self.policy_sli.observe(ClockSample::now(), elapsed_ns, result.is_ok());
        result.map(|mut decision| {
            decision.eval_ns = elapsed_ns.unwrap_or(u64::MAX);
            decision
        })
    }

    fn authorize_inner(
        &mut self,
        heap: &CapabilityHeap,
        peer: &PeerCredentials,
        req: &ToolCallRequest,
        now_mach_ns: u64,
        now_utc_ms: u64,
    ) -> EnclaveResult<Decision> {
        // Labels come from the heap; the Biba slot rule fails closed first.
        let ast_taint = heap.admit_slots(&req.arg_slots)?.max(
            if req.literal_structural { heap.literal_exposure().t.rank() } else { 0 });
        let handles: Vec<String> = req.arg_slots.iter().map(|(_, h)| h.clone()).collect();
        // F66: opaque handle metadata does not prove that the same admitted
        // peer has forgotten previously supplied plaintext. Include the trusted
        // exposure floor even if handles are omitted, values are transformed,
        // nested objects are used, or the argument document is empty. Reading
        // it here (under the service lock) also prevents an ingest racing the
        // earlier intent-resolution phase from lowering the actual decision.
        let (input, _ents, _) = heap.join(&handles, heap.literal_exposure())?;
        let wire = PopBiscuitWireV1::from_cbor(&req.wire_cbor)?;
        let pk = self.root.public();
        let ctx = VerifyContext {
            root_public_key: &pk,
            local_boot_id: &self.boot_epoch_id,
            now_mach_ns,
            now_utc_ms,
            observed_channel_binding: peer.channel_binding(),
            allow_mtls: self.profile == Profile::L2,
            received_args_blake3: *blake3::hash(&req.args_jcs).as_bytes(),
            request: RequestFacts {
                tool: req.tool.name.clone(),
                target_namespace: req.tool.namespace.clone(),
                row_count_bound: req.row_count,
                qif_call_millibits: req.qif_mb,
                arg_taint_in_ast_slot: ast_taint,
                input_confidentiality: input.c.rank(),
                sink_clearance: req.tool.sink_clearance.rank(),
            },
            limits: self.limits.clone(),
        };

        // GAP-22: Verified token LRU cache lookup
        let chain = *blake3::hash(&wire.sealed_biscuit).as_bytes();
        let facts = {
            let mut cache = self.token_cache.write().unwrap();
            if let Some(cached_facts) = cache.get(&chain) {
                cached_facts.clone()
            } else {
                let computed = parse_and_verify_token(&wire.sealed_biscuit, &pk)?;
                cache.insert(chain, computed.clone());
                computed
            }
        };

        let mut biscuit = verify_call_with_facts(&wire, &facts, &ctx, &mut self.replay);
        if let Ok(ref v) = biscuit {
            let active_blake3 = self.cedar_bundle_blake3();
            if v.policy_bundle_blake3 != active_blake3 {
                let within_grace = {
                    let hist = self.swap_history.read().unwrap();
                    if let Some(rec) = *hist {
                        v.policy_bundle_blake3 == rec.previous_bundle_blake3
                            && now_mach_ns.saturating_sub(rec.swap_mach_ns)
                                <= POLICY_SWAP_GRACE_WINDOW_NS
                    } else {
                        false
                    }
                };
                if !within_grace {
                    biscuit = Err(err!(
                        EACCES,
                        "POLICY_BUNDLE_MISMATCH",
                        "token minted under bundle {} does not match active bundle {} (outside grace window)",
                        hex::encode(&v.policy_bundle_blake3[..8]),
                        hex::encode(&active_blake3[..8]),
                    ));
                }
            }
        }
        let depth = biscuit.as_ref().ok().map(|v| v.depth);
        let facts = CallFacts {
            input,
            ast_taint,
            row_count: req.row_count,
            qif_mb: req.qif_mb,
            profile: self.profile,
            hw_grant: req.hw_grant,
            target_namespace: req.tool.namespace.clone(),
        };
        // Cedar is evaluated independently of the Biscuit verdict: it uses the
        // verified depth when available, otherwise the (unverified) wire hop —
        // which can only make Cedar stricter, never grant anything on its own.
        let cedar_depth = depth.unwrap_or_else(|| wire.hop.map_or(MAX_DEPTH + 1, u32::from));
        // GAP-04: the Cedar principal is the verified delegation chain, never
        // a caller-chosen name.
        let principal = match &biscuit {
            Ok(v) => format!("chain:{}", hex::encode(&v.chain_blake3[..8])),
            Err(_) => "unverified".to_owned(),
        };
        let cedar = self.cedar();
        let (cedar_allow, cedar_reasons) = cedar.is_authorized(
            &principal,
            cedar_depth,
            CedarAction::InvokeTool,
            &req.tool,
            &facts,
        )?;
        let biscuit_allow = biscuit.is_ok();
        Ok(Decision {
            cedar_allow,
            biscuit_allow,
            allow: cedar_allow && biscuit_allow,
            cedar_reasons,
            biscuit_error: biscuit.err().map(|e| e.to_string()),
            depth,
            eval_ns: 0,
            input_label: input,
        })
    }

    /// FIDES `declassify_enum`: reveal one of `cardinality` outcomes computed by
    /// a deterministic enclave declassifier (`jev` / `DINGO`, UID 701), charging
    /// `ceil(1000·log2 (K+1))` millibits atomically to every constituent entity.
    /// The extra outcome is a single public failure value: backend errors and
    /// out-of-range indices must not become an unbounded disclosure alphabet.
    /// Exceeding 12.0 bits returns `EACCES: QIF_BUDGET_EXCEEDED` (⇒ `A3` step-up).
    #[allow(clippy::too_many_arguments)]
    pub fn declassify_enum(
        &mut self,
        heap: &mut CapabilityHeap,
        ledger: &mut QifLedger,
        agent: &str,
        handle: &str,
        cardinality: u64,
        classifier: impl FnOnce(&[u8]) -> EnclaveResult<u64>,
        now_ms: u64,
    ) -> EnclaveResult<enclave_core::ifc_envelope::IfcEnvelopeV1> {
        if !(2..=4096).contains(&cardinality) {
            fail!(EINVAL, "ENUM_CARDINALITY", "1 < K <= 4096");
        }
        let (label, ents, unstructured) = heap.join(&[handle.to_owned()], Label::BOTTOM)?;
        let mb = millibits_for_outcomes(cardinality + 1);
        let tool = ToolResource {
            name: "jev.enum".into(),
            action_class: enclave_core::profile::ActionClass::A1,
            sink_clearance: enclave_core::label::Conf::C2,
            namespace: "enclave".into(),
            mutates_root: false,
        };
        let facts = CallFacts {
            input: label,
            ast_taint: 0,
            row_count: 1,
            qif_mb: mb,
            profile: self.profile,
            hw_grant: false,
            target_namespace: "enclave".into(),
        };
        let cedar = self.cedar();
        let (ok, reasons) = cedar.is_authorized(agent, 0, CedarAction::DeclassifyEnum, &tool, &facts)?;
        if !ok {
            // Policy ids only; no data facts or label contents are included.
            fail!(EACCES, "CEDAR_DENY_DECLASSIFY", "{}", reasons.join(","));
        }
        ledger.charge(
            &QifCharge {
                entities: ents.clone(),
                conf: label.c,
                unstructured,
                millibits: mb,
            },
            now_ms,
        )?;
        let idx = match classifier(heap.payload(handle)?) {
            Ok(idx) if idx < cardinality => idx,
            _ => fail!(EIO, "DECLASSIFIER_FAILED"),
        };
        heap.store_declassified(handle, idx.to_le_bytes().to_vec(), ents)
            .map_err(|_| err!(EIO, "DECLASSIFIER_FAILED"))
    }
}
