//! In-process L2 swarm request/response helpers (FS-702 §4.2, D-19c, D-19g).
//!
//! No Iroh endpoint, QUIC connection or network caller is implemented here.
//! The historical module name is retained for API compatibility. An unused
//! Iroh crate dependency did not supply transport behavior and has been removed.
//! These helpers/tests must not be cited as authenticated network distribution.
//!
//! Protocol intent and partial helpers (not production network assurance):
//! - ALPN: `enclave-cas-v2`
//! - Independently pinned issuer and exact authority-signed namespace/root/peer grant.
//! - Caller must supply the authenticated transport peer key and TLS exporter.
//! - Existing PoP-Biscuit verifier checks signature, attenuation, expiry and replay.
//! - No real QUIC caller or production issuer provisioning is supplied by this helper.
//! - Fixed-shape 256-byte rejection, padded to a minimum budget (no timing proof)
//! - Byzantine quarantine: `PoisonReceipt` emitted and peer banned if corrupted slice served
//! - Dual-socket QoS integration: interactive vs scavenger traffic classes

use std::collections::{BTreeSet, HashMap};
use std::sync::{Arc, Mutex, MutexGuard, TryLockError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ed25519_dalek::SigningKey;
use enclave_crypto::biscuit_auth::PublicKey;
use enclave_crypto::pop_biscuit::{self, PopBiscuitWireV1, RequestFacts, Transport, VerifyContext};
use enclave_crypto::replay::ReplayWindow;
use serde::{Deserialize, Serialize};

use enclave_core::error::EnclaveResult;
use enclave_core::{err, fail};

use crate::governance::{PeerTable, Shard};
use crate::seedgate::{SeedGateFSM,HostConditions};
use crate::transport::constant_time::{
    generate_unavailable_frame, is_unavailable_frame, pad_to_budget, UNAVAILABLE_FRAME_SIZE,
};
use crate::transport::qos::LedbatController;
use crate::transport::receipt::PoisonReceipt;

/// ALPN identifier for L2 swarm capabilities.
pub const CAS_SWARM_ALPN: &[u8] = b"enclave-cas-v2";
/// Capability operation for a single authenticated CAS slice read.
pub const L2_READ_TOOL: &str = "mcp://cas/read_slice";
const MAX_REPLAY_CHAINS: usize = 4096;

#[cfg(test)]
#[path = "served_quota_test_support.rs"]
pub(crate) mod quota_test_support;

/// Issuer policy supplied by trusted node configuration, never by a request.
#[derive(Debug, Clone)]
pub struct L2CapabilityPolicy {
    issuer_public_key: PublicKey,
    policy_bundle_blake3: [u8; 32],
    enterprise_authority:Option<Arc<enclave_core::enterprise_authority::EnterpriseAuthority>>,
}

impl L2CapabilityPolicy {
    /// Pin the independent fleet issuer and policy revision.
    pub fn new(issuer_public_key: PublicKey, policy_bundle_blake3: [u8; 32]) -> Self {
        Self { issuer_public_key, policy_bundle_blake3,enterprise_authority:None }
    }
    /// Bind separate current engineer membership; absence denies every read.
    pub fn with_enterprise_authority(mut self,authority:Arc<enclave_core::enterprise_authority::EnterpriseAuthority>)->Self {
        self.enterprise_authority=Some(authority);self
    }
}

/// Facts obtained by the caller from its authenticated transport session.
///
/// Neither field may come from the request body. The eventual QUIC adapter must
/// extract the verified remote public key and a domain-separated TLS exporter
/// for `CAS_SWARM_ALPN` from the actual connection. Constructing this value in a
/// fixture does not establish that a network adapter implements those checks.
#[derive(Debug, Clone)]
pub struct L2AuthenticatedPeer {
    /// Verified Ed25519 public key of the connected peer.
    pub public_key: [u8; 32],
    /// Observed session exporter bound to this protocol and connection.
    pub channel_binding: [u8; 32],
}

#[derive(Debug, Default)]
struct L2ReplayState {
    windows: HashMap<[u8; 32], ReplayWindow>,
    expiries: HashMap<[u8; 32], u64>,
    last_utc_ms: u64,
}
/// Local-only authority carried from verified dispatch to nonblocking handoff.
#[derive(Debug,Clone)]
pub(crate) struct L2DataAuthorization {
    pub(crate) membership:enclave_core::enterprise_authority::EnterpriseLease,
    pub(crate) expires_ms:u64,
    pub(crate) started_ms:u64,
}

/// Opaque retained current-state locks for one actual nonblocking DATA action.
/// Acquired after the file lease and enterprise serial, in this field order.
#[derive(Debug)]
pub(crate) struct L2DataReleaseGuard<'a> {
    quarantine: super::receipt::QuarantineReadGuard<'a>,
    peers: MutexGuard<'a, BTreeSet<String>>,
    seed: MutexGuard<'a, SeedGateFSM>,
    enterprise: enclave_core::enterprise_authority::EnterpriseCurrentGuard<'a>,
}
impl L2DataReleaseGuard<'_> {
    /// Validate against a fresh post-acquisition clock, without another lock,
    /// allocation, callback, signature check or filesystem access.
    pub(crate) fn validate(
        &self,
        peer_id: &str,
        authorization: &L2DataAuthorization,
        now_ms: u64,
    ) -> Result<(), enclave_core::enterprise_authority::FinalReleaseRefusal> {
        use enclave_core::{
            enterprise_authority::FinalReleaseRefusal,
            error::Errno
        };
        if now_ms<authorization.started_ms || now_ms>authorization.expires_ms || self.quarantine.contains(peer_id) || !self.peers.contains(peer_id) {
            return Err(FinalReleaseRefusal::new(Errno::EACCES, "L2_RELEASE_REVOKED"));
        }
        use crate::seedgate::SeedState;
        match self.seed.state() {
            SeedState::ActiveLanOrMeshSeed => {
            },
            SeedState::PullOnlyScavenger => return Err(FinalReleaseRefusal::new(Errno::EAGAIN, "SEEDING_SCAVENGER_ONLY")),
            SeedState::PausedMeteringShield => return Err(FinalReleaseRefusal::new(Errno::EAGAIN, "SEEDING_METERING_SHIELD")),
            SeedState::L3LockedZeroSeed => return Err(FinalReleaseRefusal::new(Errno::EPERM, "L3_ZERO_SEED")),
        }
        self.enterprise.validate(&authorization.membership, (now_ms/1000) as i64)
    }
}
/// Request for a CAS slice over L2 P2P swarm.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct L2ChunkRequest {
    /// Namespace identifier (e.g. "finance-guardrails").
    pub namespace_id: String,
    /// Logical plaintext or transport ciphertext root (hex64).
    pub root_hash: String,
    /// Slice index within the Bao Merkle tree.
    pub slice_index: u64,
    /// Optional complete CBOR PoP-Biscuit wire frame (raw Biscuit tokens refuse).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pop_biscuit_token: Option<Vec<u8>>,
    /// Client node ID (hex-encoded Ed25519 public key).
    pub client_node_id: String,
}

impl L2ChunkRequest {
    /// Exact versioned bytes covered by detached PoP, excluding the proof itself.
    ///
    /// All resource and peer fields are included. Length-prefixed UTF-8 strings
    /// and a fixed-width slice index prevent delimiter redistribution attacks.
    pub fn capability_args(&self) -> EnclaveResult<Vec<u8>> {
        if self.namespace_id.is_empty() || self.namespace_id.len() > 128
            || !self.namespace_id.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
            || !canonical_hex_key(&self.root_hash) || !canonical_hex_key(&self.client_node_id)
        {
            fail!(EINVAL, "L2_REQUEST_SHAPE");
        }
        let mut out = b"MCPMac-L2-read-slice-v1\0".to_vec();
        for field in [&self.namespace_id, &self.root_hash, &self.client_node_id] {
            out.extend_from_slice(&(field.len() as u32).to_be_bytes());
            out.extend_from_slice(field.as_bytes());
        }
        out.extend_from_slice(&self.slice_index.to_be_bytes());
        Ok(out)
    }
}

fn canonical_hex_key(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Response from an L2 swarm peer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum L2ChunkResponse {
    /// Slice successfully fetched.
    Data {
        /// Slice index within the Bao tree.
        slice_index: u64,
        /// Raw slice payload bytes.
        #[serde(with = "serde_bytes")]
        slice_bytes: Vec<u8>,
    },
    /// Fixed-shape 256-byte unavailable response.
    Unavailable(#[serde(with = "serde_bytes")] Vec<u8>),
}

/// Local node capability configuration for L2 swarm.
#[derive(Debug, Clone)]
pub struct L2SwarmNode {
    capability_policy: L2CapabilityPolicy,
    authorization_epoch: String,
    replay: Arc<Mutex<L2ReplayState>>,
    // Shared stable-principal budget survives certificate rekey. A separate
    // certificate budget bounds unverified token work before principal charging.
    rate_limiter: Arc<super::quota::PeerRateLimiter>,
    certificate_limiter: Arc<super::quota::PeerRateLimiter>,
    /// Node signing key for authenticating and signing PoisonReceipts.
    pub signing_key: SigningKey,
    /// Our node ID (hex public key).
    pub node_id: String,
    /// Our jurisdiction shard.
    pub shard: Shard,
    /// Pinned peer allowlist (authorized peer public keys).
    pub authorized_peers: Arc<Mutex<BTreeSet<String>>>,
    /// Bounded peer table with Sybil prefix and slow-loris tracking.
    pub peer_table: Arc<Mutex<PeerTable>>,
    /// SeedGate hardware state machine.
    pub seed_gate: Arc<Mutex<SeedGateFSM>>,
    /// Scavenger delay-based congestion controller.
    pub ledbat: Arc<Mutex<LedbatController>>,
    /// Minimum execution budget for rejection padding.
    pub pad_budget: Duration,
    /// Blacklisted Byzantine peers (DEFECT-F-59).
    pub quarantine_table: Arc<crate::transport::receipt::QuarantineTable>,
    /// Tamper-evidence poison receipts collected from peers (DEFECT-F-59).
    pub poison_receipts: Arc<Mutex<Vec<crate::transport::receipt::PoisonReceipt>>>,
}

impl L2SwarmNode {
    /// Install the existing quota clock only on a fresh, unused test node.
    #[cfg(test)]
    pub(crate) fn quota_test_clock(&mut self, clock: Arc<Mutex<Instant>>) {
        assert!(self.rate_limiter.test_snapshot().is_empty());
        assert!(self.certificate_limiter.test_snapshot().is_empty());
        self.rate_limiter = Arc::new(super::quota::PeerRateLimiter::with_clock(clock.clone()));
        self.certificate_limiter = Arc::new(super::quota::PeerRateLimiter::with_clock(clock));
    }

    /// Return actual principal/certificate state without changing either map.
    #[cfg(test)]
    pub(crate) fn quota_test_snapshots(&self) -> (
        std::collections::BTreeMap<String, (f64, f64, f64)>,
        std::collections::BTreeMap<String, (f64, f64, f64)>,
    ) {
        (self.rate_limiter.test_snapshot(), self.certificate_limiter.test_snapshot())
    }

    /// Create new L2 swarm node instance.
    pub fn new(
        signing_key: SigningKey,
        shard: Shard,
        seed_gate: SeedGateFSM,
        capability_policy: L2CapabilityPolicy,
    ) -> Self {
        let node_id = hex::encode(signing_key.verifying_key().as_bytes());
        Self {
            capability_policy,
            authorization_epoch: enclave_core::seq::new_boot_epoch_id(),
            replay: Arc::new(Mutex::new(L2ReplayState::default())),
            rate_limiter: Arc::new(super::quota::PeerRateLimiter::default()),
            certificate_limiter: Arc::new(super::quota::PeerRateLimiter::default()),
            signing_key,
            node_id,
            shard,
            authorized_peers: Arc::new(Mutex::new(BTreeSet::new())),
            peer_table: Arc::new(Mutex::new(PeerTable::default())),
            seed_gate: Arc::new(Mutex::new(seed_gate)),
            ledbat: Arc::new(Mutex::new(LedbatController::default_scavenger())),
            pad_budget: Duration::from_millis(5),
            quarantine_table: Arc::new(crate::transport::receipt::QuarantineTable::new()),
            poison_receipts: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Authorize a peer public key.
    pub fn authorize_peer(&self, peer_id: &str) {
        self.authorized_peers
            .lock()
            .unwrap()
            .insert(peer_id.to_string());
    }

    /// Fresh per-instance epoch the independent issuer must bind into tokens.
    /// A newly constructed node invalidates old tokens even after a restart.
    pub fn authorization_epoch(&self) -> &str {
        &self.authorization_epoch
    }

    /// Handle an incoming request after the network caller authenticates its peer.
    ///
    /// Storage is called only after the pinned issuer's authority block grants
    /// `cas_read(namespace, root, peer_hex)` and the PoP verifies on this session.
    /// Delegation checks are conjunctive and cannot add a read grant. All denied
    /// requests return the same 256-byte response shape before storage access.
    pub fn handle_request<F>(
        &self,
        peer: &L2AuthenticatedPeer,
        req: &L2ChunkRequest,
        mut get_slice: F,
    ) -> EnclaveResult<L2ChunkResponse>
    where
        F: FnMut(&str, u64) -> Option<Vec<u8>>,
    {
        self.handle_request_authorized(peer,req,&mut get_slice).map(|(response,_)|response)
    }
    /// Actual QUIC caller retains the authorization through final enqueue.
    pub(crate) fn handle_request_authorized<F>(&self,peer:&L2AuthenticatedPeer,req:&L2ChunkRequest,mut get_slice:F)->EnclaveResult<(L2ChunkResponse,Option<L2DataAuthorization>)>
    where F:FnMut(&str,u64)->Option<Vec<u8>> {
        let start = Instant::now();
        let mut root_arr = [0u8; 32];
        if canonical_hex_key(&req.root_hash) {
            if let Ok(root) = hex::decode(&req.root_hash) {
                root_arr.copy_from_slice(&root);
            }
        }
        let peer_id = hex::encode(peer.public_key);
        let enrolled = peer.channel_binding != [0;32]
            && self.authorized_peers.lock().map(|p| p.contains(&peer_id)).unwrap_or(false);
        // Charge before Biscuit/signature/replay work and before any storage
        // callback. Throttling has the same padded response as every other
        // unavailable result; the internal EAGAIN is not an inventory oracle.
        let authorization = (||->EnclaveResult<_>{
            if !enrolled {fail!(EACCES,"L2_PEER_DENIED");}
            self.certificate_limiter.check_rate_limit(&peer_id)?;
            let authority=self.capability_policy.enterprise_authority.as_ref().ok_or_else(||err!(EACCES,"ENTERPRISE_AUTHORITY_REQUIRED"))?;
            let membership=authority.authorize(&peer.public_key,&req.namespace_id,enclave_crypto::time::now_unix())?;
            self.rate_limiter.check_rate_limit(&membership.principal)?;
            let (expiry,started)=self.verify_read(peer,req)?;
            Ok(L2DataAuthorization{membership,expires_ms:expiry,started_ms:started})
        })().ok();
        let slice=if authorization.is_some(){get_slice(&req.root_hash,req.slice_index)} else{None};
        // First-source authentication can take time. Never release its bytes
        // after this verified call's authority expires or its peer is revoked.
        let authorized=authorization.and_then(|authorization|{
            let authority=self.capability_policy.enterprise_authority.as_ref()?;
            authority.revalidate(&authorization.membership,enclave_crypto::time::now_unix()).ok()?;
            let serial=authority.release_serial();let _release=serial.lock().ok()?;
            let now=SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_millis();
            let now=u64::try_from(now).ok()?;
            self.validate_data_release(peer,&authorization,now).ok()?;
            slice.map(|slice|(slice,authorization))
        });
        pad_to_budget(start, self.pad_budget);
        Ok(match authorized {
            Some((slice_bytes,authorization)) => (L2ChunkResponse::Data { slice_index: req.slice_index, slice_bytes },Some(authorization)),
            None => (L2ChunkResponse::Unavailable(generate_unavailable_frame(&root_arr, req.slice_index).to_vec()),None),
        })
    }
    pub(crate) fn enterprise_authority(&self)->EnclaveResult<&Arc<enclave_core::enterprise_authority::EnterpriseAuthority>> {
        self.capability_policy.enterprise_authority.as_ref().ok_or_else(||err!(EACCES,"ENTERPRISE_AUTHORITY_REQUIRED"))
    }
    pub(crate) fn validate_data_release(&self,peer:&L2AuthenticatedPeer,authorization:&L2DataAuthorization,now_ms:u64)->EnclaveResult<()> {
        let peer_id=hex::encode(peer.public_key);
        let result=(||{self.try_data_release_guard()?.validate(&peer_id,authorization,now_ms)})();
        result.map_err(enclave_core::enterprise_authority::FinalReleaseRefusal::into_enclave)
    }

    /// Acquire only with try operations, retaining all subordinate state until
    /// the caller finishes its one actual stream poll or FIN. The caller owns
    /// the enterprise serial already; time is read after this succeeds.
    pub(crate) fn try_data_release_guard(&self)->Result<L2DataReleaseGuard<'_>,enclave_core::enterprise_authority::FinalReleaseRefusal> {
        use enclave_core::{enterprise_authority::FinalReleaseRefusal,error::Errno};
        let authority=self.capability_policy.enterprise_authority.as_ref().ok_or(FinalReleaseRefusal::new(Errno::EACCES,"ENTERPRISE_AUTHORITY_REQUIRED"))?;
        let quarantine=self.quarantine_table.try_read_guard()?;
        let peers=self.authorized_peers.try_lock().map_err(|error|match error {
            TryLockError::WouldBlock=>FinalReleaseRefusal::new(Errno::EAGAIN,"PEERS_BUSY"),
            TryLockError::Poisoned(_)=>FinalReleaseRefusal::new(Errno::EIO,"PEERS_POISONED"),
        })?;
        let seed=self.seed_gate.try_lock().map_err(|error|match error {
            TryLockError::WouldBlock=>FinalReleaseRefusal::new(Errno::EAGAIN,"SEED_GATE_BUSY"),
            TryLockError::Poisoned(_)=>FinalReleaseRefusal::new(Errno::EIO,"SEED_GATE_POISONED"),
        })?;
        let enterprise=authority.try_current_guard()?;
        Ok(L2DataReleaseGuard{quarantine,peers,seed,enterprise})
    }

    /// Observe outside this method; only the bounded state transition shares
    /// the accepted-membership/final-enqueue fence.
    pub(crate) fn update_host_conditions(&self,conditions:Option<HostConditions>)->EnclaveResult<()> {
        let serial=self.enterprise_authority()?.release_serial();
        let _release=serial.lock().map_err(|_|err!(EIO,"ENTERPRISE_LOCK"))?;
        let mut gate=self.seed_gate.lock().map_err(|_|err!(EIO,"SEED_GATE_POISONED"))?;
        if let Some(conditions)=conditions {gate.update(conditions);} else{*gate=SeedGateFSM::new(enclave_core::profile::Profile::L2);}Ok(())
    }

    fn verify_read(&self, peer: &L2AuthenticatedPeer, req: &L2ChunkRequest) -> EnclaveResult<(u64,u64)> {
        let args = req.capability_args()?;
        let peer_id = hex::encode(peer.public_key);
        if req.client_node_id != peer_id || peer.channel_binding == [0u8; 32]
            || self.quarantine_table.is_quarantined(&peer_id)
            || !self.authorized_peers.lock().map_err(|_| err!(EIO, "PEERS_POISONED"))?.contains(&peer_id)
            || !self.seed_gate.lock().map_err(|_| err!(EIO, "SEED_GATE_POISONED"))?.can_seed()
        {
            fail!(EACCES, "L2_PEER_DENIED");
        }
        let bytes = req.pop_biscuit_token.as_deref().ok_or_else(|| err!(EACCES, "L2_PROOF_REQUIRED"))?;
        let wire = PopBiscuitWireV1::from_cbor(bytes)?;
        if wire.transport != Transport::MtlsExporter {
            fail!(EACCES, "L2_TRANSPORT_REQUIRED");
        }
        let facts = pop_biscuit::parse_and_verify_token(&wire.sealed_biscuit, &self.capability_policy.issuer_public_key)?;
        if facts.tip_public_key != peer.public_key || facts.policy_bundle_blake3 != self.capability_policy.policy_bundle_blake3 {
            fail!(EACCES, "L2_ISSUER_POLICY_OR_HOLDER");
        }
        // The token parser forbids all delegated ambient facts and rules.
        // Therefore only the independently signed authority can supply/derive
        // this scope fact. Querying it does not replace evaluating every token
        // check in verify_call_with_facts below.
        let mut scope = enclave_crypto::biscuit_auth::builder::AuthorizerBuilder::new()
            .set_limits(pop_biscuit::spec_limits())
            .build(&facts.token).map_err(|e| err!(EACCES, "L2_SCOPE_BUILD", "{e}"))?;
        let query=format!("read($ns, $root, $peer) <- cas_read($ns, $root, $peer), right(\"cas:pull\", $ns), jurisdiction_shard(\"{:?}\")",self.shard);
        let grants: Vec<(String, String, String)> = scope
            .query_all(query.as_str())
            .map_err(|e| err!(EACCES, "L2_SCOPE_QUERY", "{e}"))?;
        if !grants.iter().any(|(ns, root, holder)| ns == &req.namespace_id && root == &req.root_hash && holder == &peer_id) {
            fail!(EACCES, "L2_READ_SCOPE_DENIED");
        }
        let now = SystemTime::now().duration_since(UNIX_EPOCH).map_err(|_| err!(EIO, "L2_CLOCK"))?;
        let now_ms = u64::try_from(now.as_millis()).map_err(|_| err!(EIO, "L2_CLOCK"))?;
        let context = VerifyContext {
            root_public_key: &self.capability_policy.issuer_public_key,
            local_boot_id: &self.authorization_epoch,
            now_mach_ns: 0,
            now_utc_ms: now_ms,
            observed_channel_binding: peer.channel_binding,
            allow_mtls: true,
            received_args_blake3: *blake3::hash(&args).as_bytes(),
            request: RequestFacts {
                tool: L2_READ_TOOL.into(), target_namespace: req.namespace_id.clone(),
                row_count_bound: 1, qif_call_millibits: 0, arg_taint_in_ast_slot: 0,
                input_confidentiality: 4, sink_clearance: 4,
            },
            limits: pop_biscuit::spec_limits(),
        };
        let expiry = facts.mtls_expiry_utc_ms.ok_or_else(|| err!(EACCES, "L2_EXPIRY_REQUIRED"))?;
        let mut replay = self.replay.lock().map_err(|_| err!(EIO, "L2_REPLAY_POISONED"))?;
        if now_ms < replay.last_utc_ms { fail!(EACCES, "L2_CLOCK_ROLLBACK"); }
        replay.last_utc_ms = now_ms;
        let expired: Vec<_> = replay.expiries.iter().filter_map(|(k, exp)| (*exp < now_ms).then_some(*k)).collect();
        for chain in expired { replay.expiries.remove(&chain); replay.windows.remove(&chain); }
        if replay.windows.len() >= MAX_REPLAY_CHAINS && !replay.windows.contains_key(&facts.chain_blake3) {
            fail!(E2BIG, "L2_REPLAY_CAPACITY");
        }
        pop_biscuit::verify_call_with_facts(&wire, &facts, &context, &mut replay.windows)?;
        replay.expiries.insert(facts.chain_blake3, expiry);
        Ok((expiry.min(wire.clock.utc_epoch_ms_expiry.unwrap_or(expiry)),now_ms))
    }

    /// Process a received chunk response.
    ///
    /// Verifies slice against expected hash. If corrupted, emits a signed `PoisonReceipt`
    /// and immediately quarantines the peer.
    pub fn verify_slice_or_quarantine(
        &self,
        peer_id: &str,
        target_root: &str,
        slice_index: u64,
        expected_slice_hash: &[u8; 32],
        resp: L2ChunkResponse,
        session_binding: &str,
    ) -> EnclaveResult<Vec<u8>> {
        match resp {
            L2ChunkResponse::Unavailable(frame) => {
                if frame.len() == UNAVAILABLE_FRAME_SIZE && is_unavailable_frame(&frame) {
                    fail!(
                        EINVAL,
                        "CHUNK_UNAVAILABLE",
                        "peer reported chunk unavailable"
                    );
                }
                fail!(EINVAL, "MALFORMED_UNAVAILABLE_FRAME");
            }
            L2ChunkResponse::Data {
                slice_index: resp_idx,
                slice_bytes,
            } => {
                if resp_idx != slice_index {
                    fail!(EINVAL, "SLICE_INDEX_MISMATCH");
                }

                // Verify slice against expected BLAKE3 hash
                let actual_hash = *blake3::hash(&slice_bytes).as_bytes();
                if actual_hash != *expected_slice_hash {
                    // Byzantine violation detected! Emit signed PoisonReceipt
                    let evidence = crate::transport::receipt::PoisonEvidence {
                        peer_id,
                        target_root,
                        slice_index,
                        expected_hash: &hex::encode(expected_slice_hash),
                        corrupted_slice: &slice_bytes,
                        session_binding,
                        timestamp_utc_ms: enclave_core::clock::boot_clock_ns() / 1_000_000,
                    };
                    let receipt = PoisonReceipt::sign(&self.signing_key, &evidence);

                    // Remove from authorized peers, add to quarantine table, and persist receipt (DEFECT-F-59)
                    self.authorized_peers.lock().unwrap().remove(peer_id);
                    self.quarantine_table.quarantine_peer(peer_id);
                    self.poison_receipts.lock().unwrap().push(receipt.clone());

                    return Err(err!(
                        EACCES,
                        "BAO_SLICE_CORRUPT",
                        "PoisonReceipt emitted for peer {peer_id}: sig {}",
                        receipt.signature_hex
                    ));
                }

                Ok(slice_bytes)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seedgate::HostConditions;
    use enclave_core::profile::Profile;
    use enclave_crypto::biscuit_auth::{builder::Term, Biscuit, KeyPair};
    use enclave_crypto::pop_biscuit::{make_call, WireClock};
    use std::sync::atomic::{AtomicUsize, Ordering};

    const POLICY: [u8; 32] = [9; 32];
    struct Fixture { issuer: KeyPair, holder: SigningKey, node: L2SwarmNode, peer: L2AuthenticatedPeer }

    fn fixture() -> Fixture {
        let issuer = KeyPair::new();
        let holder = SigningKey::generate(&mut rand::thread_rng());
        use enclave_core::enterprise_authority::{EnterpriseAuthority,EnterpriseMember,EnterprisePolicy,SignedEnterprisePolicy};
        let membership_issuer=SigningKey::from_bytes(&[42;32]);let now=enclave_crypto::time::now_unix();
        let authority=EnterpriseAuthority::ephemeral(membership_issuer.verifying_key().to_bytes(),SignedEnterprisePolicy::sign(EnterprisePolicy{
            version:1,revision:1,trust_domain:"fixture.example".into(),issued_unix:now-1,expires_unix:now+3600,
            members:vec![EnterpriseMember{principal:"spiffe://fixture.example/engineer/alice".into(),generation:1,holder_public_keys:vec![hex::encode(holder.verifying_key().as_bytes())],namespaces:vec!["models".into()]}],
        },&membership_issuer).unwrap());
        let mut seed = SeedGateFSM::new(Profile::L2);
        seed.update(HostConditions { ac_power:true, unmetered:true, hotspot:false,
            thermal:crate::seedgate::Thermal::Nominal, low_power:false });
        let node = L2SwarmNode::new(SigningKey::generate(&mut rand::thread_rng()), Shard::EU,
            seed, L2CapabilityPolicy::new(issuer.public(), POLICY).with_enterprise_authority(authority));
        let peer = L2AuthenticatedPeer { public_key:holder.verifying_key().to_bytes(), channel_binding:[7;32] };
        node.authorize_peer(&hex::encode(peer.public_key));
        Fixture { issuer, holder, node, peer }
    }
    fn now_ms() -> u64 { SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64 }
    fn request(f: &Fixture) -> L2ChunkRequest {
        L2ChunkRequest { namespace_id:"models".into(), root_hash:"ab".repeat(32), slice_index:0,
            pop_biscuit_token:None, client_node_id:hex::encode(f.peer.public_key) }
    }
    fn grant(f: &Fixture, issuer: &KeyPair, scope: &L2ChunkRequest, expiry: u64) -> Biscuit {grant_scopes(f,issuer,scope,expiry,"cas:pull","EU")}
    fn grant_scopes(f:&Fixture,issuer:&KeyPair,scope:&L2ChunkRequest,expiry:u64,right:&str,shard:&str)->Biscuit {
        let mut p = HashMap::new();
        p.insert("epoch".into(),Term::Str(f.node.authorization_epoch().into()));
        p.insert("policy".into(),Term::Bytes(POLICY.to_vec()));
        p.insert("holder".into(),Term::Bytes(f.peer.public_key.to_vec()));
        p.insert("cb".into(),Term::Bytes(f.peer.channel_binding.to_vec()));
        p.insert("ns".into(),Term::Str(scope.namespace_id.clone()));
        p.insert("root".into(),Term::Str(scope.root_hash.clone()));
        p.insert("peer".into(),Term::Str(scope.client_node_id.clone()));
        p.insert("exp".into(),Term::Integer(expiry as i64));
        p.insert("right".into(),Term::Str(right.into()));p.insert("shard".into(),Term::Str(shard.into()));
        Biscuit::builder().code_with_params(
            "boot_uuid({epoch}); policy_bundle_blake3({policy}); pop_holder(0, {holder}, {cb}); \
             cas_read({ns}, {root}, {peer}); right({right}, {ns}); jurisdiction_shard({shard}); check if utc_epoch_ms($ms), $ms <= {exp};",
            p, HashMap::new()).unwrap().build(issuer).unwrap()
    }
    fn signed(f: &Fixture, token: &Biscuit, req: &L2ChunkRequest, seq: u64) -> L2ChunkRequest {
        let wire=make_call(token,&f.holder,&f.peer.channel_binding,&req.capability_args().unwrap(),seq,
            Transport::MtlsExporter,WireClock { utc_epoch_ms_expiry:Some(now_ms()+10_000),
                max_ttl_ms:Some(30_000),skew_ms:Some(2_000),..Default::default() }).unwrap();
        let mut req=req.clone(); req.pop_biscuit_token=Some(wire.to_cbor().unwrap()); req
    }
    fn denied(f: &Fixture, peer: &L2AuthenticatedPeer, req: &L2ChunkRequest) {
        let mut reads=0;
        let response=f.node.handle_request(peer,req,|_,_| { reads+=1; Some(b"private weights".to_vec()) }).unwrap();
        assert_eq!(reads,0,"denied requests must not touch storage");
        assert!(matches!(&response,L2ChunkResponse::Unavailable(frame) if frame.len()==UNAVAILABLE_FRAME_SIZE && is_unavailable_frame(frame)),"unexpected response: {response:?}");
    }
    fn enterprise_policy(revision:u64,members:Vec<enclave_core::enterprise_authority::EnterpriseMember>)->enclave_core::enterprise_authority::SignedEnterprisePolicy {
        use enclave_core::enterprise_authority::{EnterprisePolicy,SignedEnterprisePolicy};
        let now=enclave_crypto::time::now_unix();SignedEnterprisePolicy::sign(EnterprisePolicy{version:1,revision,trust_domain:"fixture.example".into(),issued_unix:now-1,expires_unix:now+3600,members},&SigningKey::from_bytes(&[42;32])).unwrap()
    }
    fn enterprise_member(name:&str,holders:Vec<[u8;32]>)->enclave_core::enterprise_authority::EnterpriseMember {
        enclave_core::enterprise_authority::EnterpriseMember{principal:format!("spiffe://fixture.example/engineer/{name}"),generation:1,holder_public_keys:holders.into_iter().map(hex::encode).collect(),namespaces:vec!["models".into()]}
    }
    #[test]
    fn enterprise_served_dispatch_requires_independent_membership_before_storage() {
        let mut f=fixture();f.node.pad_budget=Duration::ZERO;let req=request(&f);let token=grant(&f,&f.issuer,&req,now_ms()+10_000);
        f.node.capability_policy.enterprise_authority=None;
        denied(&f,&f.peer,&signed(&f,&token,&req,0));
    }
    #[test]
    fn enterprise_served_principal_budget_survives_certificate_rekey_and_other_principal_continues() {
        let mut f=fixture();f.node.pad_budget=Duration::ZERO;
        let clock=Arc::new(Mutex::new(Instant::now()));f.node.rate_limiter=Arc::new(super::super::quota::PeerRateLimiter::with_clock(clock.clone()));f.node.certificate_limiter=Arc::new(super::super::quota::PeerRateLimiter::with_clock(clock));
        let second=SigningKey::from_bytes(&[43;32]);let bob=SigningKey::from_bytes(&[44;32]);
        f.node.enterprise_authority().unwrap().replace_ephemeral(enterprise_policy(2,vec![enterprise_member("alice",vec![f.peer.public_key,second.verifying_key().to_bytes()]),enterprise_member("bob",vec![bob.verifying_key().to_bytes()])])).unwrap();
        let req=request(&f);let token=grant(&f,&f.issuer,&req,now_ms()+10_000);
        for seq in 0..50 {assert!(matches!(f.node.handle_request(&f.peer,&signed(&f,&token,&req,seq),|_,_|Some(vec![1])).unwrap(),L2ChunkResponse::Data{..}));}
        f.holder=second;f.peer.public_key=f.holder.verifying_key().to_bytes();f.peer.channel_binding=[8;32];f.node.authorize_peer(&hex::encode(f.peer.public_key));
        let req=request(&f);let token=grant(&f,&f.issuer,&req,now_ms()+10_000);denied(&f,&f.peer,&signed(&f,&token,&req,0));
        f.holder=bob;f.peer.public_key=f.holder.verifying_key().to_bytes();f.node.authorize_peer(&hex::encode(f.peer.public_key));
        let req=request(&f);let token=grant(&f,&f.issuer,&req,now_ms()+10_000);
        assert!(matches!(f.node.handle_request(&f.peer,&signed(&f,&token,&req,0),|_,_|Some(vec![2])).unwrap(),L2ChunkResponse::Data{..}));
    }
    #[test]
    fn enterprise_served_offboarding_during_storage_withholds_data_and_final_permit() {
        let mut f=fixture();f.node.pad_budget=Duration::ZERO;let req=request(&f);let token=grant(&f,&f.issuer,&req,now_ms()+10_000);
        let (response,permit)=f.node.handle_request_authorized(&f.peer,&signed(&f,&token,&req,0),|_,_|Some(vec![1])).unwrap();
        assert!(matches!(response,L2ChunkResponse::Data{..}));let permit=permit.unwrap();
        f.node.validate_data_release(&f.peer,&permit,now_ms()).unwrap();
        f.node.quarantine_table.quarantine_peer(&hex::encode(f.peer.public_key));
        assert!(f.node.validate_data_release(&f.peer,&permit,now_ms()).is_err());
        // Distinct permit/gate fixture preserves the old offboarding regression;
        // actual QUIC FIN behavior is exercised by the fence transport tests.
        let mut f=fixture();f.node.pad_budget=Duration::ZERO;let req=request(&f);let token=grant(&f,&f.issuer,&req,now_ms()+10_000);
        let (_,permit)=f.node.handle_request_authorized(&f.peer,&signed(&f,&token,&req,0),|_,_|Some(vec![1])).unwrap();let permit=permit.unwrap();
        let authority=f.node.enterprise_authority().unwrap().clone();
        f.node.update_host_conditions(None).unwrap();assert!(f.node.validate_data_release(&f.peer,&permit,now_ms()).is_err());
        f.node.update_host_conditions(Some(HostConditions::default())).unwrap();f.node.validate_data_release(&f.peer,&permit,now_ms()).unwrap();
        authority.replace_ephemeral(enterprise_policy(2,vec![])).unwrap();authority.refresh(enclave_crypto::time::now_unix()).unwrap();
        let serial=authority.release_serial();let _release=serial.lock().unwrap();assert!(f.node.validate_data_release(&f.peer,&permit,now_ms()).is_err());drop(_release);
        // A separately fresh fixture revokes after the first storage access.
        let mut f=fixture();f.node.pad_budget=Duration::ZERO;let req=request(&f);let token=grant(&f,&f.issuer,&req,now_ms()+10_000);
        let authority=f.node.enterprise_authority().unwrap().clone();let mut reads=0;
        let response=f.node.handle_request(&f.peer,&signed(&f,&token,&req,0),|_,_|{reads+=1;authority.replace_ephemeral(enterprise_policy(2,vec![])).unwrap();authority.refresh(enclave_crypto::time::now_unix()).unwrap();Some(vec![3])}).unwrap();
        assert_eq!(reads,1);assert!(matches!(response,L2ChunkResponse::Unavailable(_)));
    }

    #[test]
    fn phase3_actual_request_dispatch_shares_burst_across_sessions_and_clones() {
        let mut f = fixture();
        f.node.pad_budget = Duration::ZERO;
        let clock = Arc::new(Mutex::new(Instant::now()));
        f.node.rate_limiter = Arc::new(super::super::quota::PeerRateLimiter::with_clock(clock.clone()));
        f.node.certificate_limiter = Arc::new(super::super::quota::PeerRateLimiter::with_clock(clock.clone()));
        let base = request(&f);
        let token = grant(&f, &f.issuer, &base, now_ms() + 10_000);
        let reads = AtomicUsize::new(0);
        for seq in 0..50 {
            let response = f.node.handle_request(&f.peer, &signed(&f,&token,&base,seq), |_,_| {
                reads.fetch_add(1, Ordering::SeqCst); Some(vec![42])
            }).unwrap();
            assert!(matches!(response, L2ChunkResponse::Data { .. }));
        }
        denied(&f, &f.peer, &signed(&f,&token,&base,50));
        // A fresh channel and issuer grant for the same certificate identity
        // cannot manufacture another burst. The cloned node shares the budget.
        f.peer.channel_binding = [8;32];
        let token = grant(&f, &f.issuer, &base, now_ms() + 10_000);
        let cloned = f.node.clone();
        let response = cloned.handle_request(&f.peer,&signed(&f,&token,&base,51),|_,_| panic!("throttled storage")).unwrap();
        assert!(matches!(response,L2ChunkResponse::Unavailable(frame) if frame.len()==UNAVAILABLE_FRAME_SIZE));
        *clock.lock().unwrap() += Duration::from_millis(100);
        let response = f.node.handle_request(&f.peer,&signed(&f,&token,&base,52),|_,_| {
            reads.fetch_add(1,Ordering::SeqCst);Some(vec![43])
        }).unwrap();
        assert!(matches!(response,L2ChunkResponse::Data { slice_bytes,.. } if slice_bytes==vec![43]));
        assert_eq!(reads.load(Ordering::SeqCst),51);
        // Independent signed membership, rather than allowlisting alone,
        // authorizes this other principal's positive control.
        let alice_holder = f.peer.public_key;
        f.holder = SigningKey::generate(&mut rand::thread_rng());
        f.peer.public_key = f.holder.verifying_key().to_bytes();
        f.node.authorize_peer(&hex::encode(f.peer.public_key));
        let unregistered_base = request(&f);
        let unregistered_token = grant(&f, &f.issuer, &unregistered_base, now_ms() + 10_000);
        denied(&f, &f.peer, &signed(&f, &unregistered_token, &unregistered_base, 0));
        f.node.enterprise_authority().unwrap().replace_ephemeral(enterprise_policy(2, vec![
            enterprise_member("alice", vec![alice_holder]),
            enterprise_member("bob", vec![f.peer.public_key]),
        ])).unwrap();
        let base = request(&f);
        let token = grant(&f,&f.issuer,&base,now_ms()+10_000);
        assert!(matches!(f.node.handle_request(&f.peer,&signed(&f,&token,&base,0),|_,_| Some(vec![44])).unwrap(),L2ChunkResponse::Data {..}));
    }

    #[test]
    fn f39_untrusted_issuer_and_spoofed_request_must_not_receive_slice() {
        let f=fixture();
        let attacker=KeyPair::new();
        let mut req=request(&f);
        req.pop_biscuit_token=Some(Biscuit::builder().build(&attacker).unwrap().to_vec().unwrap());
        let response=f.node.handle_request(&f.peer,&req,|_,_| Some(b"private weights".to_vec())).unwrap();
        assert!(matches!(response,L2ChunkResponse::Unavailable(_)),"F39: an unrelated self-signed token and request-supplied peer identity received {response:?}");
        denied(&f,&f.peer,&req);
        let token=grant(&f,&attacker,&req,now_ms()+10_000);
        denied(&f,&f.peer,&signed(&f,&token,&req,0));
    }

    #[test]
    fn f39_authenticated_read_and_missing_slice_preserve_legitimate_use() {
        let f=fixture(); let base=request(&f); let token=grant(&f,&f.issuer,&base,now_ms()+10_000);
        let req=signed(&f,&token,&base,0);
        let response=f.node.handle_request(&f.peer,&req,|root,index| {
            assert_eq!(root,base.root_hash); assert_eq!(index,0); Some(vec![0x42;16_384]) }).unwrap();
        assert!(matches!(response,L2ChunkResponse::Data{slice_index:0,slice_bytes} if slice_bytes==vec![0x42;16_384]));
        denied(&f,&f.peer,&req); // replay never reaches storage
        let mut missing=base.clone();missing.slice_index=99;
        let response=f.node.handle_request(&f.peer,&signed(&f,&token,&missing,1),|_,_| None).unwrap();
        assert!(matches!(response,L2ChunkResponse::Unavailable(frame) if frame.len()==UNAVAILABLE_FRAME_SIZE));
    }

    #[test]
    fn f38_namespace_pull_right_and_signed_jurisdiction_are_mandatory_before_storage() {
        let f=fixture();let base=request(&f);
        for (right,shard) in [("cas:push","EU"),("cas:pull","US")] {
            let token=grant_scopes(&f,&f.issuer,&base,now_ms()+10_000,right,shard);denied(&f,&f.peer,&signed(&f,&token,&base,0));
        }
    }

    #[test]
    fn f38_expiry_is_rechecked_after_slow_source_authentication_before_returning_bytes() {
        let f=fixture();let base=request(&f);let token=grant(&f,&f.issuer,&base,now_ms()+250);let request=signed(&f,&token,&base,0);let mut reads=0;
        let response=f.node.handle_request(&f.peer,&request,|_,_|{reads+=1;std::thread::sleep(Duration::from_millis(350));Some(vec![42;128])}).unwrap();
        assert_eq!(reads,1);assert!(matches!(response,L2ChunkResponse::Unavailable(frame) if frame.len()==UNAVAILABLE_FRAME_SIZE));
    }

    #[test]
    fn f39_peer_session_resource_policy_and_expiry_cannot_be_swapped() {
        let f=fixture();let base=request(&f);let token=grant(&f,&f.issuer,&base,now_ms()+10_000);
        let good=signed(&f,&token,&base,0);
        let mut wrong=f.peer.clone();wrong.public_key=SigningKey::generate(&mut rand::thread_rng()).verifying_key().to_bytes();
        denied(&f,&wrong,&good);
        wrong=f.peer.clone();wrong.channel_binding=[8;32];denied(&f,&wrong,&good);
        wrong.channel_binding=[0;32];denied(&f,&wrong,&good);
        for field in 0..4 {
            let mut changed=good.clone();match field {
                0=>changed.namespace_id="other".into(),1=>changed.root_hash="cd".repeat(32),
                2=>changed.slice_index=1,_=>changed.client_node_id="ef".repeat(32) }
            denied(&f,&f.peer,&changed);
        }
        // Fresh PoP cannot expand the issuer-signed scope.
        for field in 0..3 {
            let mut scope=base.clone();match field {0=>scope.namespace_id="other".into(),
                1=>scope.root_hash="cd".repeat(32),_=>scope.client_node_id="ef".repeat(32)}
            let other_scope=grant(&f,&f.issuer,&scope,now_ms()+10_000);
            denied(&f,&f.peer,&signed(&f,&other_scope,&base,field));
        }
        for expiry in [now_ms()-1_000,now_ms()+60_000] {
            denied(&f,&f.peer,&signed(&f,&grant(&f,&f.issuer,&base,expiry),&base,0));
        }
        let mut wire=PopBiscuitWireV1::from_cbor(good.pop_biscuit_token.as_ref().unwrap()).unwrap();
        wire.pop_sig_ed25519[0]^=1;
        let mut tampered=good.clone();tampered.pop_biscuit_token=Some(wire.to_cbor().unwrap());denied(&f,&f.peer,&tampered);
        let mut foreign_policy=f.node.clone();foreign_policy.capability_policy.policy_bundle_blake3=[8;32];
        assert!(matches!(foreign_policy.handle_request(&f.peer,&good,|_,_| panic!("storage" )).unwrap(),L2ChunkResponse::Unavailable(_)));
        let mut restarted=f.node.clone();restarted.authorization_epoch=enclave_core::seq::new_boot_epoch_id();
        assert!(matches!(restarted.handle_request(&f.peer,&good,|_,_| panic!("storage")).unwrap(),L2ChunkResponse::Unavailable(_)));
    }

    #[test]
    fn f39_attenuation_is_conjunctive_and_missing_authority_scope_denies() {
        use enclave_crypto::pop_biscuit::{attenuate,ClockCaveat,DelegationCaveats};
        let f=fixture();let base=request(&f);let token=grant(&f,&f.issuer,&base,now_ms()+10_000);
        let mut caveats=DelegationCaveats {tools:vec![L2_READ_TOOL.into()],target_namespace:"models".into(),
            max_row_count:1,max_qif_call_millibits:0,clock:ClockCaveat::Mtls{utc_epoch_ms_expiry:now_ms()+5_000}};
        let delegated=attenuate(&token,&caveats,&f.peer.public_key,&f.peer.channel_binding).unwrap();
        let req=signed(&f,&delegated,&base,0);
        assert!(matches!(f.node.handle_request(&f.peer,&req,|_,_| Some(vec![1])).unwrap(),L2ChunkResponse::Data{..}));
        caveats.tools=vec!["mcp://cas/other".into()];
        let narrowed=attenuate(&token,&caveats,&f.peer.public_key,&f.peer.channel_binding).unwrap();
        denied(&f,&f.peer,&signed(&f,&narrowed,&base,1));
        let no_scope=pop_biscuit::mint_root(&f.issuer,&pop_biscuit::AuthorityClaims {
            boot_uuid:f.node.authorization_epoch().into(),effective_profile:2,policy_bundle_blake3:POLICY,
            max_c_clearance:4,total_qif_budget_millibits:12_000,allowed_tools:Some(vec![L2_READ_TOOL.into()])},
            &f.peer.public_key,&f.peer.channel_binding).unwrap();
        denied(&f,&f.peer,&signed(&f,&no_scope,&base,0));
    }

    #[test]
    fn f39_concurrent_replay_is_consumed_before_storage() {
        let f=Arc::new(fixture());let base=request(&f);let token=grant(&f,&f.issuer,&base,now_ms()+10_000);
        let req=Arc::new(signed(&f,&token,&base,0));let reads=Arc::new(AtomicUsize::new(0));
        let mut workers=Vec::new();for _ in 0..8 {let f=f.clone();let req=req.clone();let reads=reads.clone();
            workers.push(std::thread::spawn(move||f.node.handle_request(&f.peer,&req,|_,_| {reads.fetch_add(1,Ordering::SeqCst);Some(vec![1])}).unwrap()));}
        let passes=workers.into_iter().map(|w|w.join().unwrap()).filter(|r|matches!(r,L2ChunkResponse::Data{..})).count();
        assert_eq!(passes,1);assert_eq!(reads.load(Ordering::SeqCst),1);
    }

    #[test]
    fn f39_replay_capacity_clock_and_malformed_inputs_fail_closed() {
        let f=fixture();let base=request(&f);let token=grant(&f,&f.issuer,&base,now_ms()+10_000);
        let good=signed(&f,&token,&base,0);
        for value in ["", "../escape", "bad\\path", "has space"] {
            let mut bad=base.clone();bad.namespace_id=value.into();denied(&f,&f.peer,&bad);
        }
        {let mut replay=f.node.replay.lock().unwrap();replay.last_utc_ms=now_ms()+60_000;}
        denied(&f,&f.peer,&good);
        {let mut replay=f.node.replay.lock().unwrap();replay.last_utc_ms=0;
            for i in 0..MAX_REPLAY_CHAINS {let mut chain=[0;32];chain[..8].copy_from_slice(&(i as u64).to_be_bytes());
                replay.windows.insert(chain,ReplayWindow::new());replay.expiries.insert(chain,now_ms()+10_000);}}
        denied(&f,&f.peer,&good);
        assert_eq!(f.node.replay.lock().unwrap().windows.len(),MAX_REPLAY_CHAINS);
        {let mut replay=f.node.replay.lock().unwrap();for expiry in replay.expiries.values_mut(){*expiry=now_ms()-1;}}
        assert!(matches!(f.node.handle_request(&f.peer,&good,|_,_| Some(vec![1])).unwrap(),L2ChunkResponse::Data{..}));
        assert_eq!(f.node.replay.lock().unwrap().windows.len(),1);
    }

    include!("served_quota_handler_tests.rs");

    #[test]
    fn test_byzantine_quarantine_and_poison_receipt() {
        let key = SigningKey::generate(&mut rand::thread_rng());
        let fsm = SeedGateFSM::new(Profile::L2);
        let issuer = enclave_crypto::biscuit_auth::KeyPair::new();
        let node = L2SwarmNode::new(key, Shard::EU, fsm, L2CapabilityPolicy::new(issuer.public(), POLICY));

        let bad_peer = "malicious-peer-42";
        node.authorize_peer(bad_peer);
        assert!(node.authorized_peers.lock().unwrap().contains(bad_peer));

        let target_root = "abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd";
        let expected_bytes = vec![0x11u8; 16384];
        let expected_hash = *blake3::hash(&expected_bytes).as_bytes();

        let corrupted_bytes = vec![0x99u8; 16384]; // Corrupted slice!
        let resp = L2ChunkResponse::Data {
            slice_index: 3,
            slice_bytes: corrupted_bytes,
        };

        let res = node.verify_slice_or_quarantine(
            bad_peer,
            target_root,
            3,
            &expected_hash,
            resp,
            "session-bind-abc",
        );

        assert!(res.is_err(), "corrupted slice must fail");
        let err_s = format!("{:?}", res.err().unwrap());
        assert!(err_s.contains("BAO_SLICE_CORRUPT"));

        // Crucial verification: peer must be removed from authorized peers (quarantined)
        assert!(
            !node.authorized_peers.lock().unwrap().contains(bad_peer),
            "offending peer must be quarantined"
        );
    }
}

#[cfg(test)]
mod fence_tests {
    use super::*;
    use super::super::{
        quic_fence_test_support as support,
        quic_poison,
        quic_seed::SeedPeerAuthority
    };
    use enclave_core::enterprise_authority::{
        EnterpriseAuthority,
        EnterpriseMember,
        EnterprisePolicy,
        SignedEnterprisePolicy
    };
    use enclave_core::profile::Profile;
    use enclave_crypto::biscuit_auth::KeyPair;
    use std::{
        os::unix::{
            fs::{
                OpenOptionsExt,
                PermissionsExt,
                MetadataExt
            },
            io::AsRawFd
        },
        path::Path
    };
    const BUSY: &[&str] = &["serial_busy", "quarantine_busy", "peers_busy", "seed_busy", "current_busy", "serial_poison", "quarantine_poison", "peers_poison", "seed_poison", "current_poison"];
    fn node() -> (L2SwarmNode, L2AuthenticatedPeer, L2DataAuthorization) {
        let signer = SigningKey::from_bytes(&enclave_core::rng::bytes32());
        let holder = SigningKey::from_bytes(&enclave_core::rng::bytes32());
        let issuer = SigningKey::from_bytes(&enclave_core::rng::bytes32());
        let now = enclave_crypto::time::now_unix();
        let member = EnterpriseMember {
            principal: "spiffe://guard.example/engineer/alice".into(),
            generation: 1,
            holder_public_keys: vec![hex::encode(holder.verifying_key().as_bytes())],
            namespaces: vec!["models".into()]
        };
        let authority = EnterpriseAuthority::ephemeral(issuer.verifying_key().to_bytes(), SignedEnterprisePolicy::sign(EnterprisePolicy {
            version: 1,
            revision: 1,
            trust_domain: "guard.example".into(),
            issued_unix: now-1,
            expires_unix: now+3600,
            members: vec![member]
        }, &issuer).unwrap());
        let lease = authority.authorize(&holder.verifying_key().to_bytes(), "models", now).unwrap();
        let mut seed = SeedGateFSM::new(Profile::L2);
        seed.update(HostConditions::default());
        let node = L2SwarmNode::new(signer, Shard::EU, seed, L2CapabilityPolicy::new(KeyPair::new().public(), [9; 32]).with_enterprise_authority(authority));
        let peer = L2AuthenticatedPeer {
            public_key: holder.verifying_key().to_bytes(),
            channel_binding: [1; 32]
        };
        node.authorize_peer(&hex::encode(peer.public_key));
        let milliseconds = super::super::quic::fence_tests::wall_ms();
        (node, peer, L2DataAuthorization {
            membership: lease,
            started_ms: milliseconds,
            expires_ms: milliseconds+30_000
        })
    }
    pub(crate) fn probe_all(node: &L2SwarmNode) {
        let authority = node.enterprise_authority().unwrap();
        let serial = authority.release_serial();
        let s = serial.try_lock().unwrap();
        let q = node.quarantine_table.try_write_for_test().unwrap();
        let p = node.authorized_peers.try_lock().unwrap();
        let g = node.seed_gate.try_lock().unwrap();
        let a = authority.try_current_guard().unwrap();
        drop(a);
        drop(g);
        drop(p);
        drop(q);
        drop(s);
    }
    fn probe_preceding(node: &L2SwarmNode, which: usize) {
        let authority = node.enterprise_authority().unwrap();
        let serial = authority.release_serial();
        if which>0 {
            drop(serial.try_lock().unwrap());
        }
        if which>1 {
            drop(node.quarantine_table.try_write_for_test().unwrap());
        }
        if which>2 {
            drop(node.authorized_peers.try_lock().unwrap());
        }
        if which>3 {
            drop(node.seed_gate.try_lock().unwrap());
        }
    }
    fn attempt(node: &L2SwarmNode, state: &quic_poison::PoisonState) -> Result<(),
    enclave_core::enterprise_authority::FinalReleaseRefusal> {
        let lease = state.clean_lease().unwrap();
        let authority = node.enterprise_authority().unwrap();
        let serial = authority.release_serial();
        let result = ( || {
            let _s = super::super::quic::try_release_serial(&serial)?;
            let _g = node.try_data_release_guard()?;
            Ok(())
        })();
        drop(lease);
        result
    }
    fn raw_child(name: &str) -> bool {
        let Some(role) = support::child_role(name)else {
            return false;
        };
        assert_eq!(role, support::Role::LeaseHolder);
        raw_lease_probe();
        true
    }
    fn raw_lease_probe() {
        let path = support::fixture_path().join(format!("{}.json", support::case()));
        let value: serde_json::Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        let file = std::fs::OpenOptions::new().read(true).write(true).custom_flags(libc::O_NOFOLLOW|libc::O_NONBLOCK|libc::O_CLOEXEC).open(value["lock"].as_str().unwrap()).unwrap();
        let metadata = file.metadata().unwrap();
        assert_eq!(metadata.ino(), value["inode"].as_u64().unwrap());
        assert_eq!(unsafe {
            libc::flock(file.as_raw_fd(), libc::LOCK_EX|libc::LOCK_NB)
        }, 0);
        support::note(support::Note::GuardProbe {
            operation: 1,
            guard: support::Guard::FileExclusive,
            success: true
        });
        support::emit_child_receipt(&serde_json::json!( {
            "role": "independent_file_ex_probe",
            "inode": metadata.ino(),
            "notes": support::notes()
        }));
    }
    fn write_probe_config(path: impl AsRef<Path>, value: &serde_json::Value) {
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .write(true).create_new(true).mode(0o600).open(path).unwrap();
        file.write_all(&serde_json::to_vec(value).unwrap()).unwrap();
        file.sync_all().unwrap();
    }
    fn ex_probe(run: &mut support::Run, id: &str, directory: &Path, peer: &L2AuthenticatedPeer) {
        let lock = directory.join(format!("{}.qlock1", hex::encode(peer.public_key)));
        let metadata = std::fs::metadata(&lock).unwrap();
        write_probe_config(run.fixture.join(format!("{id}.json")), &serde_json::json!({
            "lock": lock,
            "inode": metadata.ino()
        }));
        let mut child = run.spawn(support::Role::LeaseHolder, id, &[], &[]);
        child.wait_success();
    }
    #[test]
    fn qf_final_try_guards_refuse_contention_and_poison_without_retaining_prior_guards() {
        const NAME: &str = "transport::iroh::fence_tests::qf_final_try_guards_refuse_contention_and_poison_without_retaining_prior_guards";
        if raw_child(NAME) {
            return;
        }
        let mut run = support::Run::new(NAME);
        run.expect(BUSY);
        for (index, id) in BUSY.iter().enumerate() {
            let which = index%5;
            let poisoned = index >= 5;
            let (node, peer, _) = node();
            let directory = run.fixture.join(id);
            std::fs::create_dir(&directory).unwrap();
            std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
            let peers = SeedPeerAuthority::from_trusted_peers(directory.to_str().unwrap(), node.signing_key.verifying_key().to_bytes(), &[peer.public_key]).unwrap();
            let state = peers.peer(&peer.public_key).unwrap();
            let authority = node.enterprise_authority().unwrap();
            let serial = authority.release_serial();
            let expected = match(which, poisoned) {
                (0, false) => "L2_RELEASE_SERIAL_BUSY",
                (1, false) => "QUARANTINE_BUSY",
                (2, false) => "PEERS_BUSY",
                (3, false) => "SEED_GATE_BUSY",
                (4, false) => "ENTERPRISE_CURRENT_BUSY",
                (0, true) => "L2_RELEASE_SERIAL_POISONED",
                (1, true) => "QUARANTINE_POISONED",
                (2, true) => "PEERS_POISONED",
                (3, true) => "SEED_GATE_POISONED",
                _ => "ENTERPRISE_CURRENT_POISONED"
            };
            if poisoned {
                let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe( || match which {
                    0 => {
                        let _g = serial.lock().unwrap();
                        panic!("owned serial poison")
                    },
                    1 => {
                        let _g = node.quarantine_table.try_write_for_test().unwrap();
                        panic!("owned quarantine poison")
                    },
                    2 => {
                        let _g = node.authorized_peers.lock().unwrap();
                        panic!("owned peers poison")
                    },
                    3 => {
                        let _g = node.seed_gate.lock().unwrap();
                        panic!("owned seed poison")
                    },
                    _ => {
                        let _g = authority.try_current_guard().unwrap();
                        panic!("owned current poison")
                    }
                }));
                assert!(caught.is_err());
                assert!(attempt(&node, state).unwrap_err().is(expected));
                probe_preceding(&node, which);
            } else {
                macro_rules! hold {
                    ($guard: expr) => {
                        {
                            let held = $guard;
                            assert!(attempt(&node, state).unwrap_err().is(expected));
                            probe_preceding(&node, which);
                            drop(held);
                        }
                    };
                }
                match which {
                    0 => hold!(serial.lock().unwrap()),
                    1 => hold!(node.quarantine_table.try_write_for_test().unwrap()),
                    2 => hold!(node.authorized_peers.lock().unwrap()),
                    3 => hold!(node.seed_gate.lock().unwrap()),
                    _ => hold!(authority.try_current_guard().unwrap())
                };
                probe_all(&node);
            }
            ex_probe(&mut run, id, &directory, &peer);
            run.complete(id);
        }
        run.finish();
    }
    fn retained_guard_child() {
        let id = support::case();
        let (node, peer, permit) = node();
        let directory = support::fixture_path().join(&id);
        std::fs::create_dir(&directory).unwrap();
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        let peers = SeedPeerAuthority::from_trusted_peers(directory.to_str().unwrap(), node.signing_key.verifying_key().to_bytes(), &[peer.public_key]).unwrap();
        let lock = directory.join(format!("{}.qlock1", hex::encode(peer.public_key)));
        let inode = std::fs::metadata(&lock).unwrap().ino();
        write_probe_config(support::fixture_path().join(format!("{id}.json")), &serde_json::json!({
            "lock": lock,
            "inode": inode
        }));
        let barrier = Arc::new(std::sync::Barrier::new(2));
        let signal = barrier.clone();
        let other = node.clone();
        let (writer_tx, writer_rx) = std::sync::mpsc::sync_channel(1);
        let writer = std::thread::spawn(move || {
            signal.wait();
            let authority = other.enterprise_authority().unwrap();
            let blocked = [other.quarantine_table.try_write_for_test().is_err(), other.authorized_peers.try_lock().is_err(), other.seed_gate.try_lock().is_err(), authority.try_current_guard().is_err()];
            writer_tx.send(blocked).unwrap();
        });
        let peer_id = hex::encode(peer.public_key);
        let lease = peers.peer(&peer.public_key).unwrap().clean_lease().unwrap();
        let authority = node.enterprise_authority().unwrap();
        let serial = authority.release_serial();
        let release = super::super::quic::try_release_serial(&serial).unwrap();
        let guard = node.try_data_release_guard().unwrap();
        barrier.wait();
        let blocked = writer_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        assert_eq!(blocked, [true; 4]);
        support::hook(support::Stage::AllFinalGuardsHeld, 1);
        guard.validate(&peer_id, &permit, permit.expires_ms).unwrap();
        assert!(guard.validate(&peer_id, &permit, permit.started_ms - 1).unwrap_err().is("L2_RELEASE_REVOKED"));
        let validation = guard.validate(&peer_id, &permit, if id == "early_refusal_drop" {
            permit.expires_ms+1
        } else {
            permit.started_ms
        });
        assert_eq!(validation.is_err(), id == "early_refusal_drop");
        // Unit disposal categories supplement the actual SendStream Pending
        // acceptance test; this unit Poll never stands in for a network result.
        let disposition = if id == "pending_drop" {
            std::task::Poll::Pending
        } else {
            std::task::Poll::Ready(validation)
        };
        drop(guard);
        drop(release);
        drop(lease);
        writer.join().unwrap();
        let other = node.clone();
        std::thread::spawn(move || probe_all(&other)).join().unwrap();
        support::hook(support::Stage::ProbeCompleted, 1);
        support::emit_child_receipt(&serde_json::json!( {
            "writer_try_refusals_while_held": blocked,
            "unit_disposition": format!("{disposition:?}"),
            "actual_quic_pending_claim": false,
            "notes": support::notes()
        }));
    }
    #[test]
    fn qf_try_guards_retain_quarantine_allowlist_seed_and_membership_through_action() {
        const NAME: &str = "transport::iroh::fence_tests::qf_try_guards_retain_quarantine_allowlist_seed_and_membership_through_action";
        if let Some(role) = support::child_role(NAME) {
            match role {
                support::Role::Sender => retained_guard_child(),
                support::Role::LeaseHolder => raw_lease_probe(),
                _ => panic!("unexpected guard proof role")
            };
            return;
        }
        let mut run = support::Run::new(NAME);
        run.expect(&["success_drop", "early_refusal_drop", "pending_drop"]);
        for id in ["success_drop", "early_refusal_drop", "pending_drop"] {
            let mut sender = run.spawn(support::Role::Sender, id, &[(support::Stage::AllFinalGuardsHeld, 1), (support::Stage::ProbeCompleted, 1)], &[]);
            sender.wait_reached(support::Stage::AllFinalGuardsHeld, 1);
            sender.resume();
            sender.wait_reached(support::Stage::ProbeCompleted, 1);
            let mut probe = run.spawn(support::Role::LeaseHolder, id, &[], &[]);
            probe.wait_success();
            sender.resume();
            sender.wait_success();
            run.complete(id);
        }
        run.finish();
    }
}
