//! UID 703 daemon service: IPC API, state, and hardware wiring.

use std::io::Write;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use enclave_core::audit::AuditJournal;
use enclave_core::daemon::DaemonId;
use enclave_core::error::EnclaveResult;
use enclave_core::ipc::{DaemonStatus, PeerCredentials};
use enclave_core::profile::{ActionClass, Profile};
use enclave_core::secret::{SecretBytes, SecretKey32};
use enclave_core::seq::RpcSequencer;
use enclave_core::{err, fail};
use enclave_crypto::hpke_envelope::KekShares;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::biometric::BiometricProvider;
#[cfg(any(test, feature = "simulation"))]
use crate::biometric::{BiometricOutcome, BiometricPrompt};
use crate::ceremony::{CeremonyEngine, CeremonyHardware, EgressGate, PrfTier};
use crate::clock::{Clock, SystemClock};
use crate::ctap::assertion::{EnrolledCredential, SignCountStore};
use crate::ctap::client::CtapClient;
use crate::ctap::hid::HidDevice;
use crate::ctap::mds::MdsState;
#[cfg(any(test, feature = "simulation"))]
use crate::ctap::mds::{MdsAllowlist, MdsEntry};
#[cfg(any(test, feature = "simulation"))]
use crate::ctap::virtual_device::VirtualAuthenticator;
use crate::intent::IntentPayloadV1;
use crate::lifecycle::{CustodyEvent, CustodyLifecycle};
use crate::pii::PiiKind;
use crate::sep::SepAgent;
#[cfg(any(test, feature = "simulation"))]
use crate::sep::SoftwareSep;
use crate::vault::{CustodyVault, ReversibleTokenizeGrant, TokenOutput};
use crate::zeroizer::{PanicZeroizer, TamperEvent, ZeroizeReport};

#[cfg(test)]
std::thread_local! {
    static INGRESS_PAIR_SNAPSHOT_FOR_TEST:std::cell::RefCell<Option<Box<dyn FnOnce(bool)>>>=std::cell::RefCell::new(None);
}

/// One value to tokenize.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenizeItem {
    /// Raw value (exists only in this request frame).
    pub value: String,
    /// Schema-declared kind.
    pub declared: Option<PiiKind>,
}

/// Record bytes on the wire for a reveal; `Debug` prints only the length.
#[derive(Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RevealBytes(#[serde(with = "serde_bytes")] pub Vec<u8>);

impl std::fmt::Debug for RevealBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "RevealBytes({} bytes)", self.0.len())
    }
}

/// IPC requests.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VaultRequest {
    /// Consume a signed replacement candidate into inactive durable Preparing.
    PrepareMemberReplacement {
        /// Closed inventory-signed candidate wire, at most64KiB.
        #[serde(with="serde_bytes")]
        candidate:Vec<u8>,
        /// Opaque server-staged validated enrollment; no raw pending/blob trust.
        enrollment_evidence_id:[u8;32],
        /// Strictly newer independent NEW receipt.
        replacement_receipt:crate::ctap::asset_enrollment::AssetEnrollmentReceipt,
        /// Optional strictly newer receipt for the actual surviving identity.
        survivor_receipt:Option<crate::ctap::asset_enrollment::AssetEnrollmentReceipt>,
    },
    /// Independently signed denial only; never supplies trust or factors.
    RecordMemberLoss {
        /// Closed signed inventory statement, at most64KiB.
        #[serde(with="serde_bytes")]
        statement:Vec<u8>,
    },
    /// Status.
    Status,
    /// Operator-only local enrollment of one namespace epoch under dual custody.
    WrapCasKey {
        /// Canonical namespace domain identifier.
        namespace:String,
        /// Immutable data-key epoch.
        epoch:u64,
        /// Current local wrapping authority epoch.
        wrapping_epoch:u64,
        /// Operator-provided DEK, accepted only over authenticated local IPC.
        key:enclave_crypto::namespace::SecretMaterial,
    },
    /// Operator imports an existing signed opaque envelope after dual-custody verification.
    ImportCasKey {
        /// Existing publisher envelope; no plaintext DEK enters the request.
        wrapped:enclave_crypto::namespace::WrappedNamespaceKey,
    },
    /// Operator rewraps a registered historical DEK without exposing it or changing ciphertext.
    RotateCasKey {
        /// Exact currently registered envelope.
        wrapped:enclave_crypto::namespace::WrappedNamespaceKey,
        /// Strictly newer local wrapping authority epoch.
        new_wrapping_epoch:u64,
    },
    /// Explicit original-primary A4 migration of every registered historical
    /// canonical envelope in one namespace to admitted-member capsule access.
    MigrateNamespaceBackup {
        /// Exact namespace; the daemon captures and authenticates its full history.
        namespace:String,
    },
    /// Explicit single-use signed SecOps authorization for bounded public-only
    /// L2 travel operation while the permanent configured floor remains L3.
    ActivateTravelRecovery {
        /// Exact signed token JSON; trust/roster/anchor never come from this RPC.
        #[serde(with="serde_bytes")]
        token:Vec<u8>,
    },
    /// Operator retires old wrapping authority after every historical DEK is rewrapped.
    AdvanceCasWrappingFloor {
        /// Namespace whose operator-controlled floor advances.
        namespace:String,
        /// Monotonic minimum authorized wrapping epoch.
        minimum_wrapping_epoch:u64,
    },
    /// UID702 releases a TUF-authenticated namespace envelope through actual custody.
    UnwrapCasKey {
        /// Exact TUF-authenticated opaque envelope to release under dual custody.
        wrapped:enclave_crypto::namespace::WrappedNamespaceKey,
    },
    /// Obtain a single-use exact-envelope challenge over authenticated UID702 IPC.
    NamespaceKeyChallenge {
        /// TUF-authenticated envelope to bind into a holder proof.
        wrapped:enclave_crypto::namespace::WrappedNamespaceKey,
    },
    /// Release with independent enterprise membership and holder possession.
    UnwrapCasKeyAuthorized {
        /// Exact envelope bound into the challenge and proof.
        wrapped:enclave_crypto::namespace::WrappedNamespaceKey,
        /// Stable engineer identity and challenge-bound holder signature.
        proof:enclave_core::enterprise_authority::NamespaceProof,
    },
    /// Recheck a lease before each verified chunk and publication.
    CheckCasKeyLease(enclave_crypto::namespace::CasKeyLease),
    /// (Re-)enroll the attached FIDO2 authenticator as this host's custodian
    /// credential (`L2`/`L3`; admin peers only).
    Enroll,
    /// `L1` only: register this Mac's Touch ID. One operator-run ceremony
    /// creates the biometry-bound Secure Enclave key in the helper; custody
    /// seals its public key and SEP-wrapped blob (no FIDO credential at `L1`).
    EnrollBiometricL1,
    /// Begin independently authorized native asset enrollment; returns public pending evidence only.
    BeginAssetEnrollment,
    /// Activate only the durable pending credential using an independent inventory receipt and fresh hardware approval.
    ActivateAssetEnrollment {
        /// Independent inventory signature over the exact durable pending evidence.
        receipt: crate::ctap::asset_enrollment::AssetEnrollmentReceipt,
    },
    /// Renew the exact active identity under its unchanged policy with a newer independent receipt and fresh factors.
    RenewAssetEnrollment {
        /// Strictly newer receipt over the original exact public pending evidence.
        receipt: crate::ctap::asset_enrollment::AssetEnrollmentReceipt,
    },
    /// Create genuine public backup evidence on the second selected attachment.
    BeginAssetBackupEnrollment,
    /// Admit the exact protected pending backup using fresh complete factors.
    AddAssetBackup {
        /// Strictly newer independently signed receipt over durable pending.
        receipt:crate::ctap::asset_enrollment::AssetEnrollmentReceipt,
    },
    /// Renew the exact two-member membership under newer independent receipts.
    RenewAssetMembership {
        /// Strictly newer independent receipt for the unchanged primary.
        primary_receipt:crate::ctap::asset_enrollment::AssetEnrollmentReceipt,
        /// Independent backup receipt strictly newer than the new primary.
        backup_receipt:crate::ctap::asset_enrollment::AssetEnrollmentReceipt,
    },
    /// Tokenize fields.
    Tokenize {
        /// Items.
        items: Vec<TokenizeItem>,
        /// Part of a > 1 row result set.
        bulk_set: bool,
        /// Cedar `Custody::ReversibleTokenize` grant.
        grant: Option<ReversibleTokenizeGrant>,
    },
    /// Scrub free text.
    ScrubText {
        /// Text.
        text: String,
        /// Bulk.
        bulk_set: bool,
        /// Grant.
        grant: Option<ReversibleTokenizeGrant>,
    },
    /// Run the chained ceremony and release plaintext to the trusted display.
    Detokenize {
        /// Surrogates.
        surrogates: Vec<String>,
        /// Structured facts; UID 703 builds the intent, its summary, factors,
        /// clock and sequence itself (GAP-09, FS-703 §3.2.1).
        draft: Box<enclave_core::intent_draft::IntentDraftV1>,
    },
    /// `A3` reveal of one record UID 704 holds (Track C): the ceremony binds
    /// this exact value, which is then shown only on the trusted display.
    RevealRecord {
        /// The record (at most `MAX_REVEAL_BYTES`); wrapped in `SecretBytes`
        /// as soon as it is decoded.
        value: RevealBytes,
        /// Structured facts; UID 703 builds the intent and binds the value's
        /// digests itself.
        draft: Box<enclave_core::intent_draft::IntentDraftV1>,
    },
    /// Tamper / power event.
    Tamper(TamperEvent),
    /// Co-sign an `AbortedPreEgressTombstone`.
    CoSignTombstone {
        /// Slot.
        slot_rpc_seq: u64,
        /// Epoch.
        boot_epoch_id: String,
    },
    /// Run the chained ceremony for a UID 704 tool call (GAP-04 / GAP-09).
    /// UID 703 builds the `IntentPayloadV1` itself from the structured draft:
    /// the trusted summary, the required factors, the clock and the sequence
    /// are all its own, so the CoreAuthUI text is never caller-authored.
    AuthorizeIntent(enclave_core::intent_draft::IntentDraftV1),
    /// Allocate the next governed slot of this boot epoch (UID 704 only).
    /// UID 703 is the single sequence authority for governed RPCs (GAP-27):
    /// every daemon's receipt for slot `s` carries the same
    /// `(boot_epoch_id, rpc_seq_u64)`.
    AllocateSlot,
    /// The SEP-signed boot epoch every other daemon adopts (GAP-27).
    BootEpoch,
    /// Fold witnesses of slots UID 703 released, for UID 705 (GAP-10):
    /// the scrubbed output and the ingress anchor
    /// `H_ingress_mac = Poseidon2(K_ingress ‖ rpc_seq ‖ C_raw)`, where UID 703
    /// computed `C_raw` itself over the raw input it received.
    FetchWitness {
        /// Epoch.
        boot_epoch_id: String,
        /// First slot.
        s_start: u64,
        /// Last slot.
        s_end: u64,
    },
    /// Create an RFC 9449 DPoP proof using the non-biometric SEP workload key (FS-703 §4.1).
    CreateDpopProof {
        /// HTTP method.
        htm: String,
        /// HTTP URI.
        htu: String,
        /// Access token to bind into `ath` claim (optional).
        access_token: Option<String>,
    },
}

fn required_intent_optional<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where D: serde::Deserializer<'de>, T: Deserialize<'de> {
    Option::<T>::deserialize(deserializer)
}

/// Public original lifetime facts; never a generation or revocation capability.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntentLifetimeV1 {
    /// Exact schema version, one.
    pub v: u8,
    /// Earliest independent exclusive wall expiry, if that authority has one.
    #[serde(deserialize_with="required_intent_optional")]
    pub valid_until_unix: Option<i64>,
    /// Original exclusive boot-clock endpoint, never restarted at IPC receipt.
    #[serde(deserialize_with="required_intent_optional")]
    pub deadline_boot_ns: Option<u64>,
}

/// Closed V2 ceremony response, authenticated by the existing custody channel.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntentAuthorizationV2 {
    /// `d_JCS` of the actual custody-built intent, in hex.
    pub d_jcs: String,
    /// Factors proven by the actual ceremony.
    pub factors: Vec<String>,
    /// Exact already checked original endpoints.
    pub lifetime: IntentLifetimeV1,
}

/// IPC responses.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VaultResponse {
    /// `L1` Touch ID registered; `sas` lets the operator confirm the key.
    BiometricEnrolled {
        /// SAS words of the enrolled biometric public key.
        sas: String,
    },
    /// Inactive burn acknowledgment, with no factor or commit capability.
    MemberReplacementPrepared {
        /// Canonical signed candidate identity consumed in this workflow.
        candidate_sha256:[u8;32],
        /// Monotonic consumed workflow attempt.
        attempt:u64,
        /// Highest consumed independent receipt generation.
        receipt_floor:u64,
    },
    /// Durable denial accepted by the required independently provisioned owner.
    MemberLossRecorded {
        /// Exact signed statement identity.
        statement_sha256:[u8;32],
        /// Monotonic workflow denial generation.
        loss_generation:u64,
        /// Exact actual surviving credential identity, with no factor proof.
        survivor_enrolled_sha256:[u8;32],
    },
    /// Explicit public-only temporary exception, with no A3/A4/C4 authority.
    TravelRecoveryActive {
        /// Consumed unsigned-body identity; no token, subject or device is echoed.
        token_sha256:[u8;32],
        /// Earliest token/authority/receipt/policy expiry, never beyond72h.
        valid_until_utc_ms:u64,
        /// Always L2; configured/permanent profile remains L3.
        effective_profile:Profile,
    },
    /// Exact unchanged membership renewed with fresh complete factors.
    AssetMembershipRenewed {
        /// Stable admitted member/wrapper identity.
        membership_id:String,
        /// Strictly advancing durable generation.
        generation:u64,
    },
    /// Both independent members were durably adopted in the authority ledger.
    AssetBackupAdded {
        /// Stable public identity of the exact admitted wrappers and members.
        membership_id:String,
        /// Monotonic durable membership generation.
        generation:u64,
    },
    /// Public evidence for the independently configured physical inventory issuer; conveys no custody authority.
    AssetEnrollmentPending {
        /// Exact public credential, attestation and setup disclosure evidence.
        pending: crate::ctap::asset_enrollment::PendingAssetEnrollment,
    },
    /// Opaque local enrollment output; no plaintext secret.
    WrappedCasKey(enclave_crypto::namespace::WrappedNamespaceKey),
    /// Secret travels only over the mutually authenticated local UID703 channel.
    CasKey {
        /// Released DEK, redacted in Debug and zeroized on drop.
        key:enclave_crypto::namespace::SecretMaterial,
        /// Short issued lease that must remain valid through publication.
        lease:enclave_crypto::namespace::CasKeyLease,
    },
    /// Complete historical namespace capsule migration was durably published.
    NamespaceBackupMigrated {
        /// Exact migrated namespace.
        namespace:String,
        /// Complete number of retained canonical envelopes.
        envelopes:usize,
    },
    /// Current lease is still live.
    CasKeyLeaseValid,
    /// Single-use bounded challenge; conveys no key or membership authority.
    NamespaceKeyChallenge {
        /// Random single-use nonce.
        challenge:String,
        /// Current custody boot identity.
        boot_epoch:String,
        /// Exclusive challenge/proof expiry.
        expires_unix:i64,
    },
    /// Status.
    Status(DaemonStatus),
    /// RFC 9449 DPoP proof.
    DpopProof(String),
    /// Tokens.
    Tokens(Vec<TokenOutput>),
    /// Scrubbed text.
    Text(String),
    /// Plaintext delivered to the trusted display only; the caller learns the count.
    Delivered {
        /// Rows.
        rows: usize,
        /// `d_JCS` hex.
        d_jcs: String,
    },
    /// Zeroization report.
    Zeroized(ZeroizeReport),
    /// Tombstone signature (Ed25519).
    TombstoneSignature {
        /// Signature.
        #[serde(with = "serde_bytes")]
        signature: Vec<u8>,
        /// Public key.
        #[serde(with = "serde_bytes")]
        public_key: Vec<u8>,
    },
    /// A governed slot.
    Slot {
        /// Epoch.
        boot_epoch_id: String,
        /// Slot.
        rpc_seq_u64: u64,
    },
    /// Boot epoch.
    Epoch(enclave_core::seq::BootEpoch),
    /// Fold witnesses + the epoch's issued high-water mark.
    Witness {
        /// Released slots.
        folds: Vec<FoldWitness>,
        /// Next unissued slot.
        next_slot: u64,
    },
    /// Completed ceremony with original exclusive lifetime. Old boundless
    /// consumers cannot decode this distinct variant and must refuse.
    IntentAuthorizedV2(IntentAuthorizationV2),
    /// Enrollment result.
    Enrolled {
        /// Credential id (hex).
        credential_id: String,
        /// AAGUID (hex).
        aaguid: String,
        /// Firmware version.
        firmware_version: u32,
        /// 4-word visual SAS over the credential public key.
        sas: String,
    },
}

/// One released slot as seen by UID 705 (GAP-10).
pub type FoldWitness = crate::ingress::WitnessFold;

/// Existing logical entry and scrubbed-length limits; not physical RSS bounds.
const WITNESS_MAX_ENTRIES: usize = 4096;
const WITNESS_MAX_BYTES: usize = 2 * 1024 * 1024;

/// Destination for detokenized plaintext (the `_enclaveintent` display).
pub trait HumanDisplay: std::fmt::Debug + Send {
    /// Independent local revocation control, suitable for the sensitive-owner
    /// register. The callback must not wait for the ceremony mutex.
    fn revocation_handle(&self) -> Option<Arc<dyn Fn() -> EnclaveResult<()> + Send + Sync>> { None }
    /// Authenticate and prepare a receiver without releasing plaintext.
    /// Called before acquiring the final release fence.
    fn prepare(&mut self) -> EnclaveResult<()> { Ok(()) }
    /// Prepare under the original host boot-clock deadline when the caller has
    /// a critical ceremony. Final display bytes/ACK retain this same ceiling.
    fn prepare_before(&mut self, _deadline_ns: Option<u64>) -> EnclaveResult<()> { self.prepare() }
    /// Revoke the live display connection on cancellation/removal/session loss.
    /// Completion is a local disconnect, not a physical remote-erasure claim.
    fn clear(&mut self) -> EnclaveResult<()> { Ok(()) }
    /// Show values to the human (never to a model).
    fn show(&mut self, values: &[SecretBytes]) -> EnclaveResult<()>;
    /// Release a frame already serialized by custody before taking its final
    /// release mutex. Custom simulation displays retain the existing interface.
    fn show_prepared(&mut self, values: &[SecretBytes], _encoded: &[u8]) -> EnclaveResult<()> {
        self.show(values)
    }
}

/// In-memory display (simulation / tests only, GAP-14).
#[derive(Debug)]
#[cfg(any(test, feature = "simulation"))]
pub struct MemoryDisplay {
    /// Marker string checked by `scripts/check-release-no-simulation.sh`.
    pub label: &'static str,
    /// Shown batches (zeroized on drop).
    pub shown: Vec<Vec<SecretBytes>>,
}

#[cfg(any(test, feature = "simulation"))]
impl Default for MemoryDisplay {
    fn default() -> Self {
        Self {
            label: "MCPMac MemoryDisplay (simulation)",
            shown: Vec::new(),
        }
    }
}

#[cfg(any(test, feature = "simulation"))]
impl HumanDisplay for MemoryDisplay {
    fn show(&mut self, values: &[SecretBytes]) -> EnclaveResult<()> {
        self.shown.push(
            values
                .iter()
                .map(|v| SecretBytes::from_slice(v.expose()))
                .collect(),
        );
        Ok(())
    }
}

/// Production display sending plaintext to `_enclaveintent` over a length-prefixed stream.
#[derive(Debug)]
pub struct HelperDisplay<S: Write + std::fmt::Debug + Send> {
    stream: Option<S>,
}

impl<S: Write + std::fmt::Debug + Send> HelperDisplay<S> {
    /// New display with a connected stream.
    pub fn new(stream: S) -> Self {
        Self {
            stream: Some(stream),
        }
    }
}

impl<S: Write + std::fmt::Debug + Send> Default for HelperDisplay<S> {
    fn default() -> Self {
        Self { stream: None }
    }
}

impl<S: Write + std::fmt::Debug + Send + 'static> HumanDisplay for HelperDisplay<S> {
    fn show(&mut self, values: &[SecretBytes]) -> EnclaveResult<()> {
        let encoded = encode_display(values)?;
        self.show_prepared(values, &encoded)
    }

    fn show_prepared(&mut self, _values: &[SecretBytes], encoded: &[u8]) -> EnclaveResult<()> {
        let stream = self.stream.as_mut().ok_or_else(|| err!(EIO, "DISPLAY_STREAM_UNAVAILABLE", "helper display stream is not connected"))?;
        // Only the actual local socket can provide the production deadline.
        // Preserve generic writers for existing software fixtures explicitly.
        let result = if let Some(socket) = (stream as &mut dyn std::any::Any).downcast_mut::<std::os::unix::net::UnixStream>() {
            enclave_core::ipc::write_release_frame(socket, encoded)
        } else {
            #[cfg(any(test, feature = "simulation"))]
            {
                let length = u32::try_from(encoded.len()).map_err(|_| err!(E2BIG, "DISPLAY_FRAME_TOO_LARGE"))?;
                stream.write_all(&length.to_be_bytes()).and_then(|_| stream.write_all(encoded)).and_then(|_| stream.flush())
                    .map_err(|error| err!(EIO, "DISPLAY_WRITE_FAILED", "{error}"))
            }
            #[cfg(not(any(test, feature = "simulation")))]
            { Err(err!(EACCES, "DISPLAY_BOUNDED_STREAM_REQUIRED")) }
        };
        if result.is_err() {
            // Never reuse a partially written frame/connection after failure.
            self.stream = None;
        }
        result
    }
}

/// Largest record one reveal may show (one sealed model output).
pub const MAX_REVEAL_BYTES: usize = 4096;
/// Tool name every reveal intent carries, whatever the caller drafted.
pub const REVEAL_TOOL: &str = "enclave://reveal/model-output";

fn encode_display(values: &[SecretBytes]) -> EnclaveResult<zeroize::Zeroizing<Vec<u8>>> {
    // CBOR byte strings: the helper refuses an array of integers.
    let items: Vec<&serde_bytes::Bytes> = values.iter().map(|value| serde_bytes::Bytes::new(value.expose())).collect();
    let mut encoded = zeroize::Zeroizing::new(Vec::new());
    ciborium::into_writer(&items, &mut *encoded).map_err(|error| err!(EIO, "DISPLAY_CBOR", "{error}"))?;
    if encoded.len() > enclave_core::ipc::MAX_FRAME { fail!(E2BIG, "DISPLAY_FRAME_TOO_LARGE"); }
    Ok(encoded)
}

/// Always-approving software Touch ID (simulation mode only, clearly labelled).
#[derive(Debug)]
#[cfg(any(test, feature = "simulation"))]
pub struct SimulatedTouchId {
    key: p256::ecdsa::SigningKey,
}

#[cfg(any(test, feature = "simulation"))]
impl SimulatedTouchId {
    /// New.
    pub fn new() -> Self {
        Self {
            key: p256::ecdsa::SigningKey::random(&mut rand_core::OsRng),
        }
    }
    /// Enrolled key.
    pub fn enrolled(&self) -> p256::ecdsa::VerifyingKey {
        *self.key.verifying_key()
    }
}

#[cfg(any(test, feature = "simulation"))]
impl Default for SimulatedTouchId {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(any(test, feature = "simulation"))]
impl BiometricProvider for SimulatedTouchId {
    fn evaluate(&mut self, p: &BiometricPrompt) -> BiometricOutcome {
        use p256::ecdsa::signature::Signer as _;
        let s: p256::ecdsa::Signature = self.key.sign(&p.signed_message());
        let v = p.t_start_ns + 1;
        let pub_bytes = self
            .key
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();
        BiometricOutcome::Approved {
            sep_signature: s.to_der().as_bytes().to_vec(),
            visible_at_ns: v,
            approved_at_ns: v + crate::biometric::DWELL_NS,
            enrolled_pubkey: p.bio_key_blob.is_empty().then_some(pub_bytes),
            enrolled_blob: p.bio_key_blob.is_empty().then_some(vec![0x77; 32]),
        }
    }
}

/// Simulation-mode egress gate (approves; production wires UID 705).
#[derive(Debug, Default)]
#[cfg(any(test, feature = "simulation"))]
pub struct SimulatedEgressGate;

#[cfg(any(test, feature = "simulation"))]
impl EgressGate for SimulatedEgressGate {
    fn approve(&mut self, _d: &[u8; 32]) -> EnclaveResult<()> {
        Ok(())
    }
}

/// Concrete owner of both attachments during a membership operation. Registry
/// continuity supplies no credential authority; fresh signed CTAP proofs must
/// authenticate the ordered device-to-credential mapping before any cutover.
#[derive(Debug)]
pub struct MembershipDevices {inner:MembershipDevicesInner}
#[derive(Debug)]
enum MembershipDevicesInner {
    #[allow(dead_code)]
    Unavailable,
    #[cfg(all(target_os="macos",feature="macos-hid"))]
    Native([crate::ctap::macos_hid::MacHidDevice;2]),
    #[cfg(any(test,feature="simulation"))]
    Simulated([Box<dyn HidDevice+Send>;2]),
}
impl MembershipDevices {
    /// Select two exact unbound native handles from the SAME enumeration owner.
    /// The singleton selection must already have been dropped/fenced. Selection
    /// order is untrusted until the service verifies both expected credentials.
    #[cfg(all(target_os="macos",feature="macos-hid"))]
    pub fn from_native(mut primary:crate::ctap::macos_hid::MacHidDevice,
        mut backup:crate::ctap::macos_hid::MacHidDevice)->EnclaveResult<Self> {
        primary.bind_selected_pair(&mut backup)?;primary.require_selected_pair(&backup)?;
        Ok(Self {inner:MembershipDevicesInner::Native([primary,backup])})
    }
    /// Explicit software fixture only, never a native attachment capability.
    #[cfg(any(test,feature="simulation"))]
    pub fn from_simulated(primary:Box<dyn HidDevice+Send>,backup:Box<dyn HidDevice+Send>)->Self {
        Self {inner:MembershipDevicesInner::Simulated([primary,backup])}
    }
    fn require_current(&self,simulated:bool)->EnclaveResult<()> {
        match &self.inner {
            #[cfg(all(target_os="macos",feature="macos-hid"))]
            MembershipDevicesInner::Native([primary,backup])=>primary.require_selected_pair(backup),
            #[cfg(any(test,feature="simulation"))]
            MembershipDevicesInner::Simulated(_) if simulated=>Ok(()),
            _=>Err(err!(EACCES,"MEMBERSHIP_NATIVE_PAIR_REQUIRED")),
        }
    }
    fn member(&mut self,index:usize)->EnclaveResult<&mut (dyn HidDevice+Send+'_)> {
        match &mut self.inner {
            #[cfg(all(target_os="macos",feature="macos-hid"))]
            MembershipDevicesInner::Native(devices)=>{
                let device=devices.get_mut(index).ok_or_else(||err!(EINVAL,"MEMBERSHIP_MEMBER_INDEX"))?;
                Ok(device)
            },
            #[cfg(any(test,feature="simulation"))]
            MembershipDevicesInner::Simulated(devices)=>{
                let device=devices.get_mut(index).ok_or_else(||err!(EINVAL,"MEMBERSHIP_MEMBER_INDEX"))?;
                Ok(device.as_mut())
            },
            _=>Err(err!(EACCES,"MEMBERSHIP_NATIVE_PAIR_REQUIRED")),
        }
    }
    fn require_topology(&mut self,profile:Profile)->EnclaveResult<()> {
        if profile==Profile::L3 {
            for index in 0..2 {if self.member(index)?.hub_depth()!=1 {fail!(EACCES,"USB_HUB_FORBIDDEN_L3");}}
        }Ok(())
    }
}

/// Hardware set.
#[derive(Debug)]
pub struct VaultHardware {
    /// SEP agent.
    pub sep: Box<dyn SepAgent>,
    /// Biometric provider.
    pub biometric: Box<dyn BiometricProvider + Send>,
    /// Enrolled SEP biometric key.
    pub sep_bio_key: p256::ecdsa::VerifyingKey,
    /// Encrypted SEP biometric key blob (Design D2).
    pub sep_bio_blob: Option<Vec<u8>>,
    /// YubiKey device.
    pub yubikey: Option<Box<dyn HidDevice + Send>>,
    /// Exact paired owner for the separate membership producer. Existing
    /// singleton enrollment/action paths never accept this as their selection.
    pub membership_devices:Option<MembershipDevices>,
    /// Enrolled credential.
    pub credential: Option<EnrolledCredential>,
    /// MDS state.
    pub mds: Option<MdsState>,
    /// Live authenticated metadata authority; absent only in software fixtures/L1.
    pub metadata_source: Option<crate::metadata_source::CustodyMetadataSource>,
    /// Independently configured issuer and local envelope scope.
    pub envelope_authority: Option<crate::metadata_source::EnvelopeAuthorityConfig>,
    /// Independent signed asset policy and inventory authority for native setup.
    pub asset_enrollment_authority: Option<AssetEnrollmentAuthority>,
    /// Stable vault identity admitted by the durable active asset transaction.
    pub asset_activation_binding: Option<[u8;32]>,
    /// Live independent asset admission, checked before and after factor waits.
    pub active_asset_guard: Option<asset_workflow::ActiveAssetGuard>,
    /// Separate exact-intent IdP acquisition, absent until explicitly configured.
    pub oidc_provider: Option<Box<dyn crate::oidc_acquisition::IntentOidcProvider>>,
    /// Trusted helper provider for the already configured FIDO2 PIN.
    pub existing_pin: Option<Box<dyn crate::pin::ExistingPinProvider>>,
    /// Egress gate.
    pub egress: Option<Box<dyn EgressGate + Send>>,
    /// Display.
    pub display: Box<dyn HumanDisplay>,
    /// Whether this is the simulated set.
    pub simulated: bool,
}

impl VaultHardware {
    fn refresh_metadata(&mut self, profile: Profile, action: ActionClass, now: i64)
        -> EnclaveResult<Option<crate::metadata_source::MetadataRevision>> {
        // A native L3 singleton is setup evidence only. The independent second
        // receipt and both full chains must commit before normal custody.
        if !self.simulated&&profile==Profile::L3&&action>=ActionClass::A3&&self.credential.is_some()
            &&!self.active_asset_guard.as_ref().is_some_and(|guard|guard.is_l3_membership()) {
            fail!(EACCES,"L3_TWO_MEMBER_ENROLLMENT_REQUIRED");
        }
        if let Some(guard)=&self.active_asset_guard {guard.check(now)?;}
        self.fetch_metadata(profile,action,now)
    }
    fn fetch_metadata(&mut self,profile:Profile,action:ActionClass,now:i64)
        ->EnclaveResult<Option<crate::metadata_source::MetadataRevision>> {
        if self.simulated || profile == Profile::L1 || action < ActionClass::A3 { return Ok(None); }
        let source = self.metadata_source.as_mut().ok_or_else(|| err!(EACCES, "CUSTODY_METADATA_AUTHORITY_REQUIRED"))?;
        let mds = source.fetch(profile, now)?;
        if let Some(credential) = self.credential.as_ref() {
            mds.check(&credential.aaguid, credential.firmware_version, credential.key.alg(), profile, action, now)?;
        }
        let revision = source.revision();
        self.mds = Some(mds);
        Ok(revision)
    }

    // Only the independently verified pending+new receipt may use this path.
    // An expired prior admission cannot authorize normal actions, but must not
    // prevent exact-identity renewal from checking fresh independent metadata.
    fn asset_metadata(&mut self,profile:Profile,credential:&EnrolledCredential,now:i64)
        ->EnclaveResult<Option<crate::metadata_source::MetadataRevision>> {
        let revision=self.fetch_metadata(profile,ActionClass::A4,now)?;
        self.mds.as_ref().ok_or_else(||err!(EACCES,"CUSTODY_METADATA_UNAVAILABLE"))?
            .check(&credential.aaguid,credential.firmware_version,credential.key.alg(),profile,ActionClass::A4,now)?;
        Ok(revision)
    }
    fn revalidate_asset_metadata(&mut self,before:Option<crate::metadata_source::MetadataRevision>,profile:Profile,credential:&EnrolledCredential,now:i64)->EnclaveResult<()> {
        if before!=self.asset_metadata(profile,credential,now)? {fail!(ESTALE,"CUSTODY_METADATA_CHANGED");}Ok(())
    }
    fn revalidate_metadata(&mut self, before: Option<crate::metadata_source::MetadataRevision>,
        profile: Profile, action: ActionClass, now: i64) -> EnclaveResult<()> {
        let after = self.refresh_metadata(profile, action, now)?;
        if before != after { fail!(ESTALE, "CUSTODY_METADATA_CHANGED"); }
        Ok(())
    }

    /// Fully simulated hardware: software SEP, auto-approving Touch ID, and a
    /// virtual YubiKey enrolled through the real CTAP path.
    #[cfg(any(test, feature = "simulation"))]
    pub fn simulated(profile: Profile, now: i64) -> EnclaveResult<Self> {
        Self::simulated_in(profile, now, None)
    }

    /// [`Self::simulated`] whose software SEP epoch key persists in
    /// `<state_dir>/sim-epoch.key`, so peers' epoch-signer pins survive a
    /// restart of UID 703 (GAP-27).
    #[cfg(any(test, feature = "simulation"))]
    pub fn simulated_in(
        profile: Profile,
        now: i64,
        state_dir: Option<&std::path::Path>,
    ) -> EnclaveResult<Self> {
        let touch = SimulatedTouchId::new();
        let sep_bio_key = touch.enrolled();
        let mut yubikey: Option<Box<dyn HidDevice + Send>> = None;
        let mut credential = None;
        let mut mds = None;
        if profile >= Profile::L2 {
            let aaguid = [0xee; 16];
            let mut dev = VirtualAuthenticator::new(aaguid);
            let m = MdsState {
                allowlist: MdsAllowlist {
                    entries: vec![MdsEntry {
                        aaguid: hex::encode(aaguid),
                        description: "MCPMac virtual authenticator (simulation)".into(),
                        min_firmware_version: 0x05_07_00,
                        status_reports: vec!["FIDO_CERTIFIED".into()],
                        attestation_public_keys: vec![dev.attestation_key_mds()],
                        attestation_root_certificates: Vec::new(),
                    }],
                },
                refreshed_at: now,
                expires_at: i64::MAX, // explicit software fixture, never native authority
            };
            let cred = crate::ctap::client::enroll_simulated(&mut dev, &m, profile, now)?;
            yubikey = Some(Box::new(dev));
            credential = Some(cred);
            mds = Some(m);
        }
        let sep = match state_dir {
            Some(d) => {
                enclave_core::fsutil::private_dir(d)?;
                SoftwareSep::with_epoch_seed(&enclave_core::fsutil::load_or_create_seed(
                    &d.join("sim-epoch.key"),
                )?)?
            }
            None => SoftwareSep::new(),
        };
        Ok(Self {
            sep: Box::new(sep),
            biometric: Box::new(touch),
            sep_bio_key,
            sep_bio_blob: None,
            yubikey,
            credential,
            mds,
            metadata_source: None,
            membership_devices:None,
            envelope_authority: None,
            asset_enrollment_authority: None,
            asset_activation_binding: None,
            active_asset_guard: None,
            oidc_provider: None,
            existing_pin: None,
            egress: (profile == Profile::L3)
                .then(|| Box::new(SimulatedEgressGate) as Box<dyn EgressGate + Send>),
            display: Box::new(MemoryDisplay::default()),
            simulated: true,
        })
    }
}

/// Tokenization and scrubbing are UID 704's ingress path (and the operator's
/// in development); UID 705 may co-sign tombstones but never handles raw PII.
fn require_vault_client(peer: &PeerCredentials) -> EnclaveResult<()> {
    if peer.uid != DaemonId::AgentRuntime.uid()
        && peer.uid != 0
        && peer.uid != enclave_core::ipc::geteuid()
    {
        fail!(EACCES, "VAULT_PEER_REJECTED");
    }
    Ok(())
}

/// Build the RFC 8785 intent from a UID 704 draft. Every display string is
/// synthesised here from structured fields (FS-703 §3.2.1).
pub fn intent_from_draft(
    d: &enclave_core::intent_draft::IntentDraftV1,
    profile: Profile,
    boot_epoch_id: &str,
    rpc_seq_u64: u64,
    now_unix: i64,
) -> EnclaveResult<IntentPayloadV1> {
    if d.profile != profile {
        fail!(
            EPERM,
            "PROFILE_MISMATCH",
            "draft {} vs effective {profile}",
            d.profile
        );
    }
    // A2 runs Touch ID too (its 15-minute lease spares repeat prompts); A1 never prompts.
    if d.action_class < ActionClass::A2 {
        fail!(EINVAL, "CEREMONY_NOT_REQUIRED");
    }
    let summary = crate::intent::synthesize_summary(
        &d.canonical_verb,
        d.row_count_bound,
        d.data_class,
        &d.tool_name,
    )?;
    let org_root = d.org_root_mutation
        || enclave_core::intent_draft::is_org_root_mutation(
            &d.tool_name,
            Some(&d.target_namespace),
        );
    let factors = crate::factors::required_factors(profile, d.action_class, org_root);
    let intent = IntentPayloadV1 {
        v: 1,
        schema_version: Some("enclave.intent.v1".into()),
        action_class: d.action_class,
        profile,
        data_class: Some(d.data_class),
        spiffe_id: DaemonId::AgentRuntime.spiffe_id(),
        tool_name: d.tool_name.clone(),
        target_namespace: Some(d.target_namespace.clone()),
        human_summary_trusted: Some(summary),
        row_count_bound: Some(d.row_count_bound),
        arguments_jcs_sha256: Some(d.arguments_jcs_sha256.clone()),
        canonical_arguments_blake3: d.canonical_arguments_blake3.clone(),
        model_blake3: None,
        policy_blake3: d.policy_blake3.clone(),
        qif_millibits_delta: Some(d.qif_millibits_delta),
        custody_grant: None,
        boot_epoch_id: boot_epoch_id.to_owned(),
        rpc_seq_u64,
        ts_utc_ms: u64::try_from(now_unix).unwrap_or(0).saturating_mul(1000),
        required_factors: factors.into_iter().collect(),
        user_turn: None,
    };
    intent.validate()?;
    Ok(intent)
}

/// Locally selected operation, bound with the complete namespace envelope.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "operation", rename_all = "snake_case")]
enum NamespaceCustodyOperation {
    Unwrap,
    Provision { key_blake3: String },
    Import,
    RotateFrom { new_wrapping_epoch: u64 },
    RotateTo { previous_envelope_blake3: String },
    MigratePrimary { canonical_envelope_blake3: Vec<String> },
}
impl NamespaceCustodyOperation {
    fn action(&self) -> ActionClass {
        match self { Self::Unwrap => ActionClass::A3, _ => ActionClass::A4 }
    }
    fn verb(&self) -> &'static str {
        match self { Self::Unwrap => "Unwrap", Self::Provision { .. } => "Provision", Self::Import => "Import", Self::RotateFrom { .. } | Self::RotateTo { .. } => "Rewrap", Self::MigratePrimary { .. } => "Migrate" }
    }
}

fn namespace_intent(wrapped: &enclave_crypto::namespace::WrappedNamespaceKey,
    operation: &NamespaceCustodyOperation, profile: Profile, caller_uid: u32,
    policy: [u8; 32], epoch: &str, sequence: u64, now: i64) -> EnclaveResult<IntentPayloadV1> {
    use sha2::Digest;
    wrapped.validate()?;
    let canonical = enclave_core::jcs::to_jcs_bytes(&json!({
        "domain": "MCPMac-namespace-custody-intent-v1", "operation": operation,
        "wrapped": wrapped, "caller_uid": caller_uid,
    }))?;
    let draft = enclave_core::intent_draft::IntentDraftV1 {
        action_class: operation.action(), profile, data_class: enclave_core::label::Conf::C4,
        tool_name: format!("mcp://custody/namespace-{}", operation.verb().to_ascii_lowercase()),
        target_namespace: wrapped.namespace.clone(), canonical_verb: operation.verb().into(),
        row_count_bound: match operation {NamespaceCustodyOperation::MigratePrimary {canonical_envelope_blake3}=>canonical_envelope_blake3.len() as u64,_=>1},
        arguments_jcs_sha256: hex::encode(sha2::Sha256::digest(&canonical)),
        canonical_arguments_blake3: blake3::hash(&canonical).to_hex().to_string(),
        policy_blake3: hex::encode(policy), qif_millibits_delta: 0,
        org_root_mutation: enclave_core::intent_draft::is_org_root_mutation("", Some(&wrapped.namespace)),
    };
    let mut intent = intent_from_draft(&draft, profile, epoch, sequence, now)?;
    intent.spiffe_id = if caller_uid == DaemonId::SwarmSync.uid() { DaemonId::SwarmSync.spiffe_id() }
        else { format!("spiffe://mcpmac.local/operator/uid-{caller_uid}") };
    intent.human_summary_trusted = Some(match operation {
        NamespaceCustodyOperation::MigratePrimary {canonical_envelope_blake3}=>format!("Migrate all {} registered historical envelopes in namespace {} for admitted backup access",canonical_envelope_blake3.len(),wrapped.namespace),
        _=>format!("{} namespace {} key epoch {} wrapping epoch {}", operation.verb(), wrapped.namespace, wrapped.epoch, wrapped.wrapping_epoch),
    });
    intent.validate()?;
    Ok(intent)
}

/// A sealed ADR-010 checkpoint: how far UID 703's slot sequence had got.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct EpochCheckpoint {
    boot_epoch_id: String,
    rpc_seq_high_water: u64,
    reason: String,
    at_ms: u64,
}

/// Daemon configuration.
#[derive(Debug, Clone)]
pub struct VaultConfig {
    /// Effective profile.
    pub profile: Profile,
    /// Audit journal path.
    pub audit_path: Option<PathBuf>,
    /// UID 704 policy key that signs `Custody::ReversibleTokenize` grants.
    pub grant_key: Option<VerifyingKey>,
    /// Persistent state (`<state>/custody`): egress registry, tombstone key.
    pub state_dir: Option<PathBuf>,
    /// Mesh socket directory (GAP-10: dedicated witness channel streaming).
    pub socket_dir: Option<PathBuf>,
    /// Explicit trusted same-UID development exception; false in production.
    pub dev_same_uid: bool,
}

impl Default for VaultConfig {
    fn default() -> Self {
        Self {
            profile: Profile::L2,
            audit_path: None,
            grant_key: None,
            state_dir: None,
            socket_dir: None,
            dev_same_uid: false,
        }
    }
}

/// Hardware, the ceremony engine and the `signCount` store: held only by
/// ceremonies (`AuthorizeIntent`, `Detokenize`, `Enroll`), on their own lock,
/// so a ceremony of up to 10 s never blocks `Tokenize`, `ScrubText` or slot
/// allocation (GAP-39). Lock order: `ceremony` before `state`.
struct Ceremony {
    engine: CeremonyEngine,
    hw: VaultHardware,
    counters: SignCountStore,
    leases: crate::lease::LeaseTable,
    authorization_generation: u64,
    setup_only:bool,
    /// Sealed `signCount` high-water marks (GAP-28; `None`: tests only).
    counter_store: Option<enclave_core::sealed::SealedStore>,
    clock: Box<dyn Clock>,
}

impl Ceremony {
    fn enter_generation(&mut self, generation: u64) {
        if self.authorization_generation != generation {
            self.leases.revoke_all();
            let _ = self.hw.display.clear();
            self.authorization_generation = generation;
        }
    }
    fn run(
        &mut self,
        intent: &IntentPayloadV1,
        tier: Option<PrfTier>,
        cancelled: Option<&std::sync::atomic::AtomicBool>,
    ) -> EnclaveResult<crate::ceremony::CeremonyGrant> {
        let start=self.clock.now_ns();self.run_started(intent,tier,cancelled,start)
    }

    fn run_started(&mut self,intent:&IntentPayloadV1,tier:Option<PrfTier>,
        cancelled:Option<&std::sync::atomic::AtomicBool>,t_start_ns:u64)
        ->EnclaveResult<crate::ceremony::CeremonyGrant> {
        if self.setup_only {fail!(EACCES,"ASSET_MEMBERSHIP_PENDING");}
        let never_cancelled = std::sync::atomic::AtomicBool::new(false);
        let cancelled = cancelled.unwrap_or(&never_cancelled);
        if !self.hw.simulated && intent.required_factors.contains(&crate::factors::Factor::KofnEd25519Quorum) {
            // No configured signer collection exists yet. Never spend physical
            // factors and then quietly waive an unavailable independent quorum.
            fail!(EPERM, "QUORUM_POLICY_UNAVAILABLE");
        }
        let revision = self.hw.refresh_metadata(intent.profile, intent.action_class, self.clock.now_unix())?;
        let mut source = self.hw.metadata_source.clone();
        let mut metadata_deadline=self.hw.metadata_source.as_ref().and_then(|source|source.deadline_ns());
        let credential = self.hw.credential.clone();
        let simulated = self.hw.simulated;
        let counter_store = &mut self.counter_store;
        let mut checkpoint = |counters: &SignCountStore| -> EnclaveResult<()> {
            // The signed assertion has already advanced the high-water mark.
            // A storage failure denies PRF use; never roll the counter back.
            if let Some(store) = counter_store.as_mut() { store.save_json(counters)?; }
            if !simulated && intent.profile >= Profile::L2 && intent.action_class >= ActionClass::A3 {
                let source = source.as_mut().ok_or_else(|| err!(EACCES, "CUSTODY_METADATA_AUTHORITY_REQUIRED"))?;
                let now = enclave_crypto::time::now_unix();
                let mds = source.fetch(intent.profile, now)?;
                let credential = credential.as_ref().ok_or_else(|| err!(EACCES, "YUBIKEY_NOT_ENROLLED"))?;
                mds.check(&credential.aaguid, credential.firmware_version, credential.key.alg(), intent.profile, intent.action_class, now)?;
                if source.revision() != revision { fail!(ESTALE, "CUSTODY_METADATA_CHANGED"); }
                metadata_deadline=[metadata_deadline,source.deadline_ns()].into_iter().flatten().min();
            }
            Ok(())
        };
        let hw = &mut self.hw;
        let member_index=hw.active_asset_guard.as_ref().and_then(|guard|guard.member_index());
        let selected_yubikey:Option<&mut dyn HidDevice>=if let Some(pair)=hw.membership_devices.as_mut() {
            pair.require_current(simulated)?;pair.require_topology(intent.profile)?;
            Some(pair.member(member_index.ok_or_else(||err!(EACCES,"ASSET_ACTIVE_REQUIRED"))?)?)
        } else {hw.yubikey.as_mut().map(|device|device.as_mut() as &mut dyn HidDevice)};
        let result=self.engine.run_with_counter_checkpoint(
            intent,
            tier,
            CeremonyHardware {
                biometric: Some(hw.biometric.as_mut()),
                existing_pin: hw.existing_pin.as_mut().map(|provider| provider.as_mut() as &mut dyn crate::pin::ExistingPinProvider),
                pin_cancelled: Some(cancelled),
                ceremony_start_ns: Some(t_start_ns),
                oidc_step_up: None,
                oidc_provider: hw.oidc_provider.as_mut().map(|provider| provider.as_mut() as &mut dyn crate::oidc_acquisition::IntentOidcProvider),
                sep_key: Some(hw.sep_bio_key),
                sep_bio_blob: hw.sep_bio_blob.clone(),
                yubikey: selected_yubikey,
                credential: hw.credential.as_ref(),
                mds: hw.mds.as_ref(),
                counters: Some(&mut self.counters),
                egress: hw
                    .egress
                    .as_mut()
                    .map(|g| g.as_mut() as &mut dyn EgressGate),
                leases: Some(&mut self.leases),
                is_yanked: false,
                oidc_verifier: None,
                oidc_token: None,
                quorum_policy: None,
                quorum_signatures: None,
            },
            self.clock.as_ref(),
            &mut checkpoint,
        );
        drop(checkpoint);
        let mut grant=result?;
        grant.valid_until_boot_ns=[grant.valid_until_boot_ns,metadata_deadline].into_iter().flatten().min();
        grant.check_valid_at_boot(self.clock.now_ns())?;
        Ok(grant)
    }

    /// GAP-28: a consumed counter is durable before any result leaves —
    /// including a failed ceremony that still consumed one.
    fn persist_counters(&mut self, before: &SignCountStore) -> EnclaveResult<()> {
        if &self.counters != before {
            if let Some(store) = self.counter_store.as_mut() {
                store.save_json(&self.counters)?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
#[path="enterprise_tests.rs"]
mod enterprise_tests;

/// Sealed `L1` Touch ID registration (`<state_dir>/custody/biometric-l1`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrolledBiometricL1 {
    /// Enrolled biometric P-256 public key (SEC1 uncompressed).
    pub bio_public_key: Vec<u8>,
    /// SEP-wrapped token-object blob; only this Mac's SEP can use it.
    pub bio_key_blob: Vec<u8>,
}

/// Sealed store name for [`EnrolledBiometricL1`] under `<state>/custody`.
pub const BIOMETRIC_L1_STORE: &str = "biometric-l1";

/// Persisted custodian enrollment (`L2`/`L3`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrolledCustodyState {
    /// Enrolled authenticator credential.
    pub credential: EnrolledCredential,
    /// Enrolled biometric P-256 public key (SEC1 uncompressed).
    pub bio_public_key: Vec<u8>,
    /// Encrypted SEP token-object blob (Design D2).
    pub bio_key_blob: Vec<u8>,
}

struct State {
    membership_sterile:bool,
    loss_attempted:bool,
    travel:Option<travel_workflow::TravelRuntime>,
    enterprise_authority:Option<std::sync::Arc<enclave_core::enterprise_authority::EnterpriseAuthority>>,
    namespace_challenges:std::collections::BTreeMap<String,(u32,String,String,i64)>,
    cas_keyring:crate::cas_keyring::CasKeyring,
    cas_key_leases:std::collections::BTreeMap<String,enclave_crypto::namespace::CasKeyLease>,
    cas_key_deadlines:std::collections::BTreeMap<String,u64>,
    profile: Profile,
    vault: CustodyVault,
    envelope_store: Option<enclave_core::sealed::SealedStore>,
    membership_checkpoint: Option<asset_workflow::CommittedMembership>,
    envelope_policy_digest: Option<[u8;32]>,
    envelope_valid_until_unix: Option<i64>,
    envelope_deadline_ns: Option<u64>,
    envelope_policy_source: Option<crate::metadata_source::CustodyMetadataSource>,
    envelope_authority: Option<crate::metadata_source::EnvelopeAuthorityConfig>,
    envelope_fault: bool,
    active_asset_guard: Option<asset_workflow::ActiveAssetGuard>,
    envelope_grant_key: Option<VerifyingKey>,
    lifecycle: CustodyLifecycle,
    zeroizer: PanicZeroizer,
    simulated: bool,
    seq: RpcSequencer,
    /// ADR-010 checkpoints of the epoch's slot high-water mark (GAP-27).
    checkpoint: enclave_core::seq::CheckpointPolicy,
    checkpoint_store: Option<enclave_core::sealed::SealedStore>,
    journal: Option<AuditJournal>,
    audit_path:Option<PathBuf>,
    _slab: enclave_core::slab::SecureSlabAllocator,
    tombstone_root_key: enclave_core::slab::RootKeyPage,
    tombstone_key: SigningKey,
    ingress_key: SecretKey32,
    clock: SystemClock,
    epoch: enclave_core::seq::BootEpoch,
    egress: enclave_core::egress::EgressRegistry,
    witness: std::collections::VecDeque<FoldWitness>,
    witness_bytes: usize,
    state_dir: Option<PathBuf>,
    socket_dir: Option<PathBuf>,
    dev_same_uid: bool,
}

impl State {
    fn requires_ingress_pair(&self)->bool {
        !self.travel_active()&&!self.simulated
            &&self.active_asset_guard.as_ref().is_some_and(|guard|guard.is_l3_membership())
    }
    fn release_deadline(&self, factor_deadline:Option<u64>)->Option<u64> {
        [factor_deadline,self.envelope_deadline_ns].into_iter().flatten().min()
    }
    fn release_valid_until(&self, factor_expiry: Option<i64>) -> Option<i64> {
        [factor_expiry, self.envelope_valid_until_unix,
            self.active_asset_guard.as_ref().map(|guard| guard.expires_unix())]
            .into_iter().flatten().min()
    }
    fn check_release_time(&self, now: i64) -> EnclaveResult<()> {
        self.require_membership_active()?;
        VaultService::check_authority_deadline(self.release_valid_until(None), now)?;
        if self.envelope_deadline_ns.is_some_and(|deadline|SystemClock::default().now_ns()>=deadline) {fail!(ESTALE,"ENVELOPE_TRANSPORT_EXPIRED");}
        if let Some(guard)=&self.active_asset_guard {guard.check_release(now)?;}
        Ok(())
    }
    fn refresh_envelope_policy(&mut self, now: i64) -> EnclaveResult<Option<i64>> {
        self.require_membership_active()?;
        if self.envelope_fault { fail!(EACCES, "VAULT_ENVELOPE_STATE_UNCERTAIN"); }
        if !self.simulated&&self.profile==Profile::L3&&self.vault.is_enrolled()
            &&!self.active_asset_guard.as_ref().is_some_and(|guard|guard.is_l3_membership()) {
            fail!(EACCES,"L3_TWO_MEMBER_ENROLLMENT_REQUIRED");
        }
        if let Some(guard)=&self.active_asset_guard {guard.check(now)?;}
        if self.simulated || !self.vault.is_enrolled() { return Ok(None); }
        let authority = self.envelope_authority.as_ref().ok_or_else(|| err!(EACCES, "ENVELOPE_POLICY_AUTHORITY_REQUIRED"))?;
        let context = self.envelope_policy_source.as_ref().ok_or_else(|| err!(EACCES, "ENVELOPE_POLICY_SOURCE_REQUIRED"))?
            .envelope_context(authority, self.profile, now)?;
        if Some(context.digest()) != self.envelope_policy_digest { fail!(ESTALE, "ENVELOPE_POLICY_CHANGED_MIGRATION_REQUIRED"); }
        self.vault.refresh_authorized_context(&context,now)?;
        self.envelope_deadline_ns=context.deadline_ns();
        Ok(Some(context.expires_unix()))
    }

    fn persist_envelopes(&mut self) -> EnclaveResult<()> {
        self.require_membership_active()?;
        if self.envelope_fault { fail!(EACCES, "VAULT_ENVELOPE_STATE_UNCERTAIN"); }
        if let Some(record)=self.membership_checkpoint.as_mut() {
            let state=self.state_dir.as_ref().ok_or_else(||err!(EACCES,"ENVELOPE_STATE_REQUIRED"))?;
            let result=self.vault.checkpoint().and_then(|checkpoint|asset_workflow::persist_checkpoint(state,record,checkpoint));
            if result.is_err() {self.envelope_fault=true;}
            result?;
        } else if let Some(store) = self.envelope_store.as_mut() {
            let result = self.vault.checkpoint().and_then(|checkpoint| store.save_json(&checkpoint));
            if result.is_err() { self.envelope_fault = true; }
            result?;
        }
        Ok(())
    }
}

// Private, single-use local admission. The exclusive State borrow prevents
// another admission or epoch change between preparation and consuming commit.
// This is not a receiver reservation or durable/final-output transaction.
struct PreparedLocalWitness<'a> {
    state: &'a mut State,
    epoch: &'a str,
    retained: FoldWitness,
    next_bytes: usize,
}

impl<'a> PreparedLocalWitness<'a> {
    fn prepare(state: &'a mut State, epoch: &'a str, seq: u64, raw: &[u8], scrubbed: Vec<u8>) -> EnclaveResult<Self> {
        // An observed persistence error is uncertain even if the path recovers.
        // Refuse before witness staging/display under this same State borrow.
        state.egress.ensure_healthy()?;
        // A terminal nonrelease accepted during the State-free ceremony must
        // fence actual display too. This State borrow spans display/commit;
        // keep the registry's final released() check as a separate defense.
        if state.egress.was_tombstoned(epoch, seq) { fail!(EACCES,"TOMBSTONE_SLOT_FINALIZED"); }
        // Preserve the existing entry/scrubbed-length policy. These are logical
        // limits, not a new allowance for capacity, metadata or physical memory.
        if state.witness.len() >= WITNESS_MAX_ENTRIES { fail!(EAGAIN,"WITNESS_RETENTION_CAPACITY"); }
        let next_bytes=state.witness_bytes.checked_add(scrubbed.len())
            .filter(|bytes|*bytes<=WITNESS_MAX_BYTES)
            .ok_or_else(||err!(EAGAIN,"WITNESS_RETENTION_CAPACITY"))?;
        state.witness.try_reserve(1).map_err(|_|err!(ENOMEM,"WITNESS_RETENTION_ALLOC"))?;
        let retained=crate::ingress::create_witness_fold(state.ingress_key.expose(),seq,raw,scrubbed);
        Ok(Self{state,epoch,retained,next_bytes})
    }

    fn commit(self) -> EnclaveResult<()> {
        let Self{state,epoch,retained,next_bytes}=self;
        // An append/fsync error can follow partial/complete disk R. Do not infer
        // rollback or safe retry/tombstone from Err; earlier local folds remain.
        state.egress.released(epoch,retained.rpc_seq_u64)?;
        // Preparation reserved the deque slot; exclusive borrowing prevented
        // intervening mutation. No local clone/reserve/eviction follows R.
        state.witness.push_back(retained);
        state.witness_bytes=next_bytes;
        if let Some(socket_dir)=&state.socket_dir {
            // push_back above guarantees a back entry. The exclusive State
            // borrow keeps it stable throughout this synchronous call. No new
            // local clone or fallible reservation follows R.
            let fold=state.witness.back().expect("just-inserted local witness");
            // Required receiver policy, State-free peer work, post-R encoding/
            // stream failure and authoritative retirement remain NEXT-08 work.
            let _=crate::ingress::WitnessStreamClient::stream_borrowed_with_mode(socket_dir,epoch,std::slice::from_ref(fold),state.dev_same_uid);
        }
        Ok(())
    }
}

/// The service.
pub struct VaultService {
    membership_authority:Option<MembershipAuthorityOwner>,
    replacement_preparing:Mutex<asset_workflow::ReplacementPreparingRuntime>,
    cas_key_release:std::sync::Arc<Mutex<()>>,
    cas_key_generation:std::sync::Arc<std::sync::atomic::AtomicU64>,
    cas_enrolled_generation:std::sync::Arc<std::sync::atomic::AtomicU64>,
    cas_keys_enabled:std::sync::Arc<std::sync::atomic::AtomicBool>,
    ceremony_cancelled:std::sync::atomic::AtomicBool,
    selected_owner_failure:Arc<std::sync::OnceLock<SelectedOwnerFailure>>,
    display_revoke: Option<std::sync::Arc<dyn Fn() -> EnclaveResult<()> + Send + Sync>>,
    ceremony: Mutex<Ceremony>,
    state: std::sync::Arc<Mutex<State>>,
}

impl std::fmt::Debug for VaultService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("VaultService")
    }
}

impl VaultService {
    /// Boot: sign the epoch, enroll the dual-key vault, open the journal.
    pub fn start(cfg: VaultConfig, hw: VaultHardware) -> EnclaveResult<Arc<Self>> {
        Self::start_inner(cfg,hw,None,None)
    }
    /// Start through an opaque independently anchored/audited keyless travel
    /// admission. Original membership/content/policy are rechecked at startup.
    pub fn start_with_travel(cfg:VaultConfig,hw:VaultHardware,travel:ValidatedTravelStartup)->EnclaveResult<Arc<Self>> {
        Self::start_inner(cfg,hw,Some(travel),None)
    }
    fn start_inner(cfg:VaultConfig,mut hw:VaultHardware,mut travel:Option<ValidatedTravelStartup>,membership_authority:Option<MembershipAuthorityOwner>)->EnclaveResult<Arc<Self>> {
        let membership_sterile=membership_authority.is_some();
        let loss_attempted=if let Some(owner)=membership_authority.as_ref() {
            if cfg.profile==Profile::L1||travel.is_some() {fail!(EACCES,"MEMBERSHIP_RECOVERY_STARTUP_PROFILE");}
            // REQUIRED provider check precedes USB, credentials, PRFs and boot
            // side effects in this explicitly sterile embedding API.
            let state=cfg.state_dir.as_deref().ok_or_else(||err!(EACCES,"ENROLLMENT_STATE_REQUIRED"))?;
            let lost=owner.check_startup(state,cfg.profile)?;
            hw.credential=None;hw.yubikey=None;hw.membership_devices=None;
            hw.active_asset_guard=None;hw.asset_activation_binding=None;hw.sep_bio_blob=None;
            lost
        } else {false};
        let travel_mode=travel.is_some();
        if travel.is_some()&&cfg.profile!=Profile::L3 {fail!(EACCES,"TRAVEL_PERMANENT_L3_REQUIRED");}
        if cfg.profile>=Profile::L2 && !hw.simulated && cfg.state_dir.is_none() {fail!(EACCES,"CAS_KEYRING_STATE_REQUIRED");}
        if !membership_sterile && cfg.profile == Profile::L3 && !hw.simulated && travel.is_none() {
            if let Some(pair)=hw.membership_devices.as_mut() {pair.require_current(false)?;pair.require_topology(cfg.profile)?;}
            else {enclave_core::power::require_selected_usb_instance()?;}
        }
        let epoch = enclave_core::seq::new_boot_epoch_id();
        let sig = hw
            .sep
            .sign_epoch(&enclave_core::seq::epoch_signing_message(&epoch))?;
        let boot = enclave_core::seq::BootEpoch {
            boot_epoch_id: epoch.clone(),
            signature: sig,
            signer_public_key: hw.sep.epoch_public_key(),
        };
        // GAP-11: the tombstone key and the egress registry survive restarts.
        let (tombstone_key, egress) = match &cfg.state_dir {
            Some(d) => (
                SigningKey::from_bytes(&enclave_core::fsutil::load_or_create_seed(
                    &d.join("tombstone.key"),
                )?),
                enclave_core::egress::EgressRegistry::open(&d.join("egress"))?,
            ),
            None => (
                SigningKey::generate(&mut rand_core::OsRng),
                enclave_core::egress::EgressRegistry::ephemeral(),
            ),
        };
        let mut slab =
            enclave_core::slab::SecureSlabAllocator::new(&enclave_core::slab::EmteGate::default());
        let tombstone_root_key = slab.alloc_root_key(&tombstone_key.to_bytes())?;
        // GAP-28: counters survive restarts; a deleted, edited or rolled-back
        // store refuses to start (re-enrollment), never "starts clean".
        let (mut counter_store, mut counters) = match &cfg.state_dir {
            None => (None, SignCountStore::default()),
            Some(d) => match enclave_core::sealed::SealedStore::open(d, "signcount")
                .map_err(|e| err!(EACCES, "SIGN_COUNT_STATE", "{e}; re-enroll the custodian"))?
            {
                (st, enclave_core::sealed::Loaded::Fresh) => (Some(st), SignCountStore::default()),
                (st, enclave_core::sealed::Loaded::State(b)) => {
                    (Some(st), enclave_core::sealed::decode(&b)?)
                }
            },
        };
        // Bind every restored credential to its normalized-key counter floor
        // before any compatible enrollment PRF or subsequent assertion.
        counters.bind_credentials(hw.credential.iter());
        let native_membership=if !membership_sterile&&cfg.profile>=Profile::L2&&hw.asset_enrollment_authority.is_some() {
            load_native_membership(cfg.state_dir.as_deref().ok_or_else(||err!(EACCES,"ENROLLMENT_STATE_REQUIRED"))?,
                hw.asset_enrollment_authority.as_ref(),cfg.profile,enclave_crypto::time::now_unix())?
        } else {None};
        if travel_mode&&native_membership.is_none() {fail!(EACCES,"TRAVEL_ORIGINAL_MEMBERSHIP_REQUIRED");}
        let membership_setup=if !membership_sterile&&native_membership.is_none()&&cfg.profile>=Profile::L2&&hw.asset_enrollment_authority.is_some() {
            load_native_membership_setup(cfg.state_dir.as_deref().ok_or_else(||err!(EACCES,"ENROLLMENT_STATE_REQUIRED"))?,
                hw.asset_enrollment_authority.as_ref(),cfg.profile,enclave_crypto::time::now_unix())?
        } else {None};
        let mut selected_membership_index=None;
        if let Some(setup)=membership_setup.as_ref() {
            let enrolled=setup.enrolled();
            if hw.credential.as_ref().map(enclave_core::jcs::to_jcs_bytes).transpose()?!=Some(enclave_core::jcs::to_jcs_bytes(&enrolled.credential)?)
                ||hw.sep_bio_blob.as_ref()!=Some(&enrolled.bio_key_blob)||hw.sep_bio_key.to_encoded_point(false).as_bytes()!=enrolled.bio_public_key.as_slice()
                ||hw.asset_activation_binding!=Some(setup.source_binding()) {fail!(EACCES,"ASSET_ACTIVE_BINDING");}
            hw.active_asset_guard=None;
        } else if let Some(membership)=native_membership.as_ref().filter(|_|travel.is_none()) {
            let credential=hw.credential.as_ref().ok_or_else(||err!(EACCES,"ASSET_ACTIVE_BINDING"))?;
            let encoded=enclave_core::jcs::to_jcs_bytes(credential)?;
            for index in 0..2 {if enclave_core::jcs::to_jcs_bytes(&membership.enrolled(index)?.credential)?==encoded {selected_membership_index=Some(index);}}
            let index=selected_membership_index.ok_or_else(||err!(EACCES,"ASSET_ACTIVE_BINDING"))?;
            let enrolled=membership.enrolled(index)?;
            if hw.sep_bio_blob.as_ref()!=Some(&enrolled.bio_key_blob)||hw.sep_bio_key.to_encoded_point(false).as_bytes()!=enrolled.bio_public_key.as_slice()
                ||hw.asset_activation_binding!=Some(membership.source_binding()) {fail!(EACCES,"ASSET_ACTIVE_BINDING");}
            counters.bind_credentials([&membership.enrolled(0)?.credential,&membership.enrolled(1)?.credential]);
            hw.active_asset_guard=Some(membership.guard(cfg.state_dir.clone().ok_or_else(||err!(EACCES,"ENROLLMENT_STATE_REQUIRED"))?,
                hw.asset_enrollment_authority.clone().ok_or_else(||err!(EACCES,"ASSET_AUTHORITY_REQUIRED"))?,index)?);
        } else if travel.is_some() {
            let membership=native_membership.as_ref().ok_or_else(||err!(EACCES,"TRAVEL_ORIGINAL_MEMBERSHIP_REQUIRED"))?;
            let verified=travel.as_ref().unwrap();
            if verified.session.original_scope!=membership.travel_scope()? {fail!(EACCES,"TRAVEL_ORIGINAL_SCOPE");}
            // Receipt authority is still current. No attached-key identity or
            // credential field is represented as a fresh factor in this mode.
            hw.active_asset_guard=Some(membership.guard(cfg.state_dir.clone().ok_or_else(||err!(EACCES,"ENROLLMENT_STATE_REQUIRED"))?,
                hw.asset_enrollment_authority.clone().ok_or_else(||err!(EACCES,"ASSET_AUTHORITY_REQUIRED"))?,0)?);
            hw.asset_activation_binding=Some(membership.source_binding());
            hw.credential=None;hw.yubikey=None;hw.membership_devices=None;
        } else if !hw.simulated&&cfg.profile>=Profile::L2 {
            if let Some(credential)=hw.credential.as_ref() {
                let guard=asset_workflow::ActiveAssetGuard::new(
                    cfg.state_dir.clone().ok_or_else(||err!(EACCES,"ENROLLMENT_STATE_REQUIRED"))?,
                    hw.asset_enrollment_authority.clone().ok_or_else(||err!(EACCES,"ASSET_AUTHORITY_REQUIRED"))?,
                    cfg.profile,hw.asset_activation_binding.ok_or_else(||err!(EACCES,"ASSET_VAULT_BINDING"))?,credential)?;
                guard.check(enclave_crypto::time::now_unix())?;hw.active_asset_guard=Some(guard);
            }
        }
        let is_enrolled = !membership_sterile && (cfg.profile == Profile::L1 || hw.credential.is_some() || hw.simulated || travel.is_some());
        let now = enclave_crypto::time::now_unix();
        let envelope_context = if (!hw.simulated||native_membership.is_some()||membership_setup.is_some()) && is_enrolled {
            let authority = hw.envelope_authority.as_ref().ok_or_else(|| err!(EACCES, "ENVELOPE_POLICY_AUTHORITY_REQUIRED"))?;
            Some(hw.metadata_source.as_ref().ok_or_else(|| err!(EACCES, "ENVELOPE_POLICY_SOURCE_REQUIRED"))?
                .envelope_context(authority, cfg.profile, now)?)
        } else { None };
        // Restore only authenticated public keys, wrapped keys and ciphertexts.
        // Public L2 ingestion must not rederive either tier PRF at every boot.
        let (mut envelope_store, restored, surrogate_seed) = if let Some(membership)=native_membership.as_ref() {
            let directory=cfg.state_dir.as_ref().ok_or_else(||err!(EACCES,"ENVELOPE_STATE_REQUIRED"))?.join("vault-envelopes");
            (None,Some(membership.checkpoint().clone()),Some(enclave_core::sealed::sealing_key(&directory,"custody-surrogate-v2")?))
        } else if let Some(setup)=membership_setup.as_ref() {
            let directory=cfg.state_dir.as_ref().ok_or_else(||err!(EACCES,"ENVELOPE_STATE_REQUIRED"))?.join("vault-envelopes");
            (None,Some(setup.checkpoint().clone()),Some(enclave_core::sealed::sealing_key(&directory,"custody-surrogate-v2")?))
        } else if !hw.simulated && is_enrolled {
            let directory = cfg.state_dir.as_ref().ok_or_else(|| err!(EACCES, "ENVELOPE_STATE_REQUIRED"))?.join("vault-envelopes");
            let (store, loaded) = enclave_core::sealed::SealedStore::open_bounded_required(&directory, "envelopes", 32 * 1024 * 1024)?;
            let seed = enclave_core::sealed::sealing_key(&directory, "custody-surrogate-v2")?;
            let restored = match loaded {
                enclave_core::sealed::Loaded::Fresh => None,
                enclave_core::sealed::Loaded::State(bytes) => Some(enclave_core::sealed::decode::<crate::vault::VaultEnvelopeCheckpoint>(&bytes)?),
            };
            (Some(store), restored, Some(seed))
        } else { (None, None, None) };
        let mut vault = if let Some(checkpoint) = restored {
            if let Some(expected)=hw.asset_activation_binding {
                if checkpoint.enrollment_binding()?!=expected {fail!(EACCES,"ASSET_VAULT_BINDING");}
            }
            CustodyVault::restore_authorized(checkpoint, cfg.profile, cfg.grant_key,
                envelope_context.as_ref().ok_or_else(|| err!(EACCES, "ENVELOPE_POLICY_REQUIRED"))?,
                surrogate_seed.ok_or_else(|| err!(EACCES, "SURROGATE_SEED_REQUIRED"))?, now)?
        } else if is_enrolled {
            // An existing authenticator enrollment cannot silently bootstrap a
            // replacement envelope authority through bare boot-time PRFs.
            if !hw.simulated && cfg.profile >= Profile::L2 {
                fail!(EACCES, "ENVELOPE_STATE_MIGRATION_REQUIRED");
            }
            // L1 has no custodian enrollment to create the SEP tier keys. Do it
            // here: no envelope checkpoint exists, so nothing is sealed under
            // any earlier key, and a restart restores instead of reaching this.
            if !hw.simulated && cfg.profile == Profile::L1 {
                hw.sep.create_tier_keys()?;
            }
            let a3 = hw.sep.ecdh_share(PrfTier::A3)?;
            let a4 = hw.sep.ecdh_share(PrfTier::A4)?;
            let (p3, p4) = if cfg.profile == Profile::L1 {
                (hw.sep.l1_secondary_share(PrfTier::A3)?, hw.sep.l1_secondary_share(PrfTier::A4)?)
            } else {
                (Self::enrollment_prf(&mut hw, cfg.profile, PrfTier::A3, &mut counters, &mut counter_store)?,
                 Self::enrollment_prf(&mut hw, cfg.profile, PrfTier::A4, &mut counters, &mut counter_store)?)
            };
            let a3_shares = KekShares { sep_ecdh_share: a3.expose(), yubikey_prf: &p3.expose()[..32] };
            let a4_shares = KekShares { sep_ecdh_share: a4.expose(), yubikey_prf: &p4.expose()[..32] };
            match envelope_context.as_ref() {
                Some(context) => CustodyVault::enroll_authorized(cfg.profile, &a3_shares, &a4_shares, cfg.grant_key,
                    context, surrogate_seed.ok_or_else(|| err!(EACCES, "SURROGATE_SEED_REQUIRED"))?, now)?,
                None if hw.simulated => CustodyVault::enroll(cfg.profile, &a3_shares, &a4_shares, cfg.grant_key)?,
                None => return Err(err!(EACCES, "ENVELOPE_POLICY_REQUIRED")),
            }
        } else { CustodyVault::unenrolled(cfg.profile, cfg.grant_key) };
        if let Some(membership)=native_membership.as_ref() {
            let context=envelope_context.as_ref().ok_or_else(||err!(EACCES,"ENVELOPE_POLICY_REQUIRED"))?;
            membership.backup_wrappers().validate_scope(membership.checkpoint(),&membership.enrolled(0)?.credential,&membership.enrolled(1)?.credential,context,now)?;
            if selected_membership_index==Some(1) {vault.select_backup_member(membership,context,now)?;}
        }
        if let Some(store) = envelope_store.as_mut() { store.save_json(&vault.checkpoint()?)?; }
        if !membership_sterile {if let Some(store) = counter_store.as_mut() { store.save_json(&counters)?; }}
        let mut lifecycle = CustodyLifecycle::boot(cfg.profile);
        if vault.is_enrolled() {
            match cfg.profile {
                Profile::L1 => { lifecycle.on(CustodyEvent::SepUnwrap)?; },
                Profile::L2 => { lifecycle.on(CustodyEvent::PublicIngestInit)?; },
                // A stored envelope or boot-time PRF is not a fresh Touch ID
                // approval. L3 activates only after a complete real ceremony.
                Profile::L3 => {},
            }
        }
        let journal = match &cfg.audit_path {
            Some(p) => Some(AuditJournal::open(
                p,
                DaemonId::CustodyVault,
                epoch.clone(),
            )?),
            None => None,
        };
        let (checkpoint_store, previous) = match &cfg.state_dir {
            None => (None, None),
            Some(d) => match enclave_core::sealed::SealedStore::open(d, "epoch-checkpoint")
                .map_err(|e| err!(EACCES, "EPOCH_CHECKPOINT_STATE", "{e}"))?
            {
                (s, enclave_core::sealed::Loaded::Fresh) => (Some(s), None),
                (s, enclave_core::sealed::Loaded::State(b)) => (
                    Some(s),
                    Some(enclave_core::sealed::decode::<EpochCheckpoint>(&b)?),
                ),
            },
        };
        let svc = Arc::new(Self {
            membership_authority,
            replacement_preparing:Mutex::new(Default::default()),
            cas_key_release:std::sync::Arc::new(Mutex::new(())),
            cas_key_generation:std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
            cas_enrolled_generation:std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
            cas_keys_enabled:std::sync::Arc::new(std::sync::atomic::AtomicBool::new(!membership_sterile&&!travel_mode&&membership_setup.is_none()&&(cfg.profile != Profile::L3 || hw.simulated))),
            ceremony_cancelled: std::sync::atomic::AtomicBool::new(false),
            selected_owner_failure: Arc::new(std::sync::OnceLock::new()),
            display_revoke: hw.display.revocation_handle(),
            state: std::sync::Arc::new(Mutex::new(State {
                membership_sterile,loss_attempted,
                travel:travel.take().map(|travel|travel_workflow::TravelRuntime::from_startup(travel,cfg.audit_path.clone())).transpose()?,
                enterprise_authority:None,
                namespace_challenges:std::collections::BTreeMap::new(),

                cas_keyring:crate::cas_keyring::CasKeyring::open(cfg.state_dir.as_deref())?,
                cas_key_leases:std::collections::BTreeMap::new(),
                cas_key_deadlines:std::collections::BTreeMap::new(),
                profile: cfg.profile,
                vault,
                envelope_store,
                membership_checkpoint:native_membership.as_ref().map(|membership|membership.record()),
                envelope_policy_digest: envelope_context.as_ref().map(|context| context.digest()),
                envelope_valid_until_unix: envelope_context.as_ref().map(|context| context.policy_expires_unix()),
                envelope_deadline_ns: envelope_context.as_ref().and_then(|context|context.deadline_ns()),
                envelope_policy_source: hw.metadata_source.clone(),
                envelope_authority: hw.envelope_authority.clone(),
                envelope_fault: membership_sterile||membership_setup.is_some(),
                active_asset_guard: hw.active_asset_guard.clone(),
                envelope_grant_key: cfg.grant_key,
                lifecycle,
                zeroizer: PanicZeroizer::new(),
                simulated: hw.simulated,
                seq: RpcSequencer::new(epoch, 0),
                checkpoint: enclave_core::seq::CheckpointPolicy::new(
                    enclave_core::audit::now_utc_ms(),
                ),
                checkpoint_store,
                journal,
                audit_path:cfg.audit_path.clone(),
                _slab: slab,
                tombstone_root_key,
                tombstone_key,
                ingress_key: SecretKey32::random(),
                clock: SystemClock::default(),
                epoch: boot,
                egress,
                witness: std::collections::VecDeque::new(),
                witness_bytes: 0,
                state_dir: cfg.state_dir.clone(),
                socket_dir: cfg.socket_dir.clone(),
                dev_same_uid: cfg.dev_same_uid,
            })),
            ceremony: Mutex::new(Ceremony {
                engine: CeremonyEngine::new(cfg.profile),
                hw,
                counters,
                leases: crate::lease::LeaseTable::new(),
                authorization_generation: 0,
                setup_only:membership_sterile||membership_setup.is_some()||travel_mode,
                counter_store,
                clock: Box::new(SystemClock::default()),
            }),
        });
        {
            // ADR-010: checkpoint at boot, naming where the previous epoch ended.
            let mut st = svc.lock_state()?;
            if travel_mode {
                st.current_travel()?;
                let mut lifecycle=CustodyLifecycle::boot(Profile::L2);lifecycle.on(CustodyEvent::PublicIngestInit)?;st.lifecycle=lifecycle;
            }
            Self::checkpoint(&mut st, false, previous.as_ref())?;
        }
        Ok(svc)
    }

    /// Obtain the tier PRF from the enrolled authenticator (same `uv` mode the
    /// profile's ceremonies use, so later outputs reproduce the same KEK).
    fn enrollment_prf(
        hw: &mut VaultHardware,
        profile: Profile,
        tier: PrfTier,
        counters: &mut SignCountStore,
        counter_store: &mut Option<enclave_core::sealed::SealedStore>,
    ) -> EnclaveResult<enclave_core::secret::SecretBytes> {
        let cred = hw
            .credential
            .clone()
            .ok_or_else(|| err!(EPERM, "YUBIKEY_NOT_ENROLLED"))?;
        Self::enrollment_prf_for_credential(hw,&cred,profile,tier,counters,counter_store)
    }
    fn enrollment_prf_for_credential(hw:&mut VaultHardware,cred:&EnrolledCredential,profile:Profile,tier:PrfTier,counters:&mut SignCountStore,counter_store:&mut Option<enclave_core::sealed::SealedStore>)->EnclaveResult<enclave_core::secret::SecretBytes> {
        use sha2::Digest;
        let now = enclave_crypto::time::now_unix();
        let revision = hw.refresh_metadata(profile, ActionClass::A4, now)?;
        hw.mds.as_ref().ok_or_else(|| err!(EACCES, "CUSTODY_METADATA_UNAVAILABLE"))?
            .check(&cred.aaguid, cred.firmware_version, cred.key.alg(), profile, ActionClass::A4, now)?;
        let dev = hw
            .yubikey
            .as_mut()
            .ok_or_else(|| err!(EPERM, "YUBIKEY_REQUIRED"))?;
        let mut c = CtapClient::open(dev.as_mut())?;
        let cdh: [u8; 32] =
            sha2::Sha256::digest(format!("MCPMac-MorningEnrollment-v1:{tier:?}")).into();
        let uv = profile == Profile::L3;
        let (resp, ss) = c.get_assertion(&cred.credential_id, &cdh, uv, Some(&tier.salt()))?;
        // The client owns a mutable transport borrow until its cleanup runs.
        // End it before consulting the independent live metadata authority.
        drop(c);
        let va = crate::ctap::assertion::verify_assertion(cred, &resp, &cdh, uv, counters)?;
        if let Some(store) = counter_store.as_mut() { store.save_json(counters)?; }
        hw.revalidate_metadata(revision, profile, ActionClass::A4, enclave_crypto::time::now_unix())?;
        let enc = va
            .hmac_secret_enc
            .ok_or_else(|| err!(EACCES, "PRF_MISSING"))?;
        crate::ctap::client::decrypt_prf(&ss.ok_or_else(|| err!(EACCES, "PRF_MISSING"))?, &enc)
    }

    /// Record a released slot: persisted egress record (before the reply
    /// leaves), ingress anchor and retained witness. Local capacity/storage is
    /// prepared before R; full retention refuses new work without eviction.
    fn release(
        st: &mut State,
        epoch: &str,
        seq: u64,
        raw: &[u8],
        scrubbed: Vec<u8>,
    ) -> EnclaveResult<()> {
        PreparedLocalWitness::prepare(st,epoch,seq,raw,scrubbed)?.commit()
    }

    /// Tombstone public key.
    pub fn tombstone_public_key(&self) -> EnclaveResult<VerifyingKey> {
        Ok(self
            .state
            .lock()
            .map_err(|_| err!(EIO, "LOCK"))?
            .tombstone_key
            .verifying_key())
    }

    /// Return the slab-allocated address range for the tombstone root key (tests).
    pub fn tombstone_root_key_range(&self) -> EnclaveResult<(usize, usize)> {
        let st = self.state.lock().map_err(|_| err!(EIO, "LOCK"))?;
        Ok((
            st.tombstone_root_key.key_addr(),
            st.tombstone_root_key.one_past_end(),
        ))
    }

    /// Handle one request.
    /// Write a checkpoint if the ADR-010 policy says one is due (boot,
    /// hourly, clean shutdown; never per RPC; `<= 30` per day).
    fn checkpoint(
        st: &mut State,
        shutdown: bool,
        previous: Option<&EpochCheckpoint>,
    ) -> EnclaveResult<()> {
        let now_ms = enclave_core::audit::now_utc_ms();
        let Some(reason) = st.checkpoint.poll(now_ms, shutdown) else {
            return Ok(());
        };
        let cp = EpochCheckpoint {
            boot_epoch_id: st.seq.boot_epoch_id().to_owned(),
            rpc_seq_high_water: st.seq.current(),
            reason: format!("{reason:?}"),
            at_ms: now_ms,
        };
        if let Some(s) = st.checkpoint_store.as_mut() {
            s.save_json(&cp)?;
        }
        let ev = json!({"event": "EPOCH_CHECKPOINT", "reason": cp.reason, "rpc_seq_high_water": cp.rpc_seq_high_water, "writes_today": st.checkpoint.writes_today(),
                        "previous_epoch": previous.map(|p| json!({"boot_epoch_id": p.boot_epoch_id, "rpc_seq_high_water": p.rpc_seq_high_water, "reason": p.reason}))});
        let (e, s) = (cp.boot_epoch_id.clone(), cp.rpc_seq_high_water);
        Self::journal(st, &e, s, Some(ev))
    }

    #[cfg(test)]
    pub(crate) fn register_synthetic_region(&self, region: Arc<enclave_core::guarded::GuardedRegion>) -> EnclaveResult<()> {
        self.lock_state()?.zeroizer.register(region);
        Ok(())
    }

    /// Revoke live authorization before the clean-shutdown checkpoint. Durable
    /// ciphertext, wrapped/public keys, counters and enrollment remain intact.
    pub fn shutdown(&self) -> EnclaveResult<()> {
        let cleanup = self.handle(&PeerCredentials::local(enclave_core::ipc::geteuid(), 0),
            VaultRequest::Tamper(TamperEvent::Shutdown));
        let checkpoint = Self::checkpoint(&mut *self.lock_state()?, true, None);
        cleanup?;
        checkpoint
    }

    fn lock_state(&self) -> EnclaveResult<std::sync::MutexGuard<'_, State>> {
        self.state.lock().map_err(|_| err!(EIO, "STATE_POISONED"))
    }

    // Sensitive dispatch must check after acquiring its actual ownership lock;
    // an earlier RPC preflight may have preceded a completed travel transition.
    fn lock_sensitive_state(&self)->EnclaveResult<std::sync::MutexGuard<'_,State>> {
        self.require_selected_owner()?;
        let state=self.lock_state()?;self.require_selected_owner()?;
        state.require_membership_active()?;state.require_no_travel()?;Ok(state)
    }
    fn lock_sensitive_ceremony(&self)->EnclaveResult<std::sync::MutexGuard<'_,Ceremony>> {
        let ceremony=self.lock_ceremony()?;
        drop(self.lock_sensitive_state()?);
        Ok(ceremony)
    }

    /// One ceremony at a time; a second caller fails fast instead of
    /// queueing behind a prompt (GAP-39, FS-703 §3.2.3 singleflight).
    fn lock_ceremony(&self) -> EnclaveResult<std::sync::MutexGuard<'_, Ceremony>> {
        match self.ceremony.try_lock() {
            Ok(g) => Ok(g),
            Err(std::sync::TryLockError::WouldBlock) => fail!(
                EAGAIN,
                "CEREMONY_IN_FLIGHT",
                "a custody ceremony is already running"
            ),
            Err(std::sync::TryLockError::Poisoned(_)) => fail!(EIO, "STATE_POISONED"),
        }
    }

    /// GAP-27: issue the next governed slot of UID 703's epoch.
    fn begin_governed(st: &mut State) -> EnclaveResult<(String, u64)> {
        let epoch_id = st.seq.boot_epoch_id().to_owned();
        let s = st.seq.next()?;
        st.egress.issued(&epoch_id, s)?;
        Ok((epoch_id, s))
    }

    fn journal(
        st: &mut State,
        epoch_id: &str,
        seq: u64,
        ev: Option<serde_json::Value>,
    ) -> EnclaveResult<()> {
        if let (Some(j), Some(mut ev)) = (st.journal.as_mut(), ev) {
            // GAP-03: every receipt from a simulated vault says so, so a
            // rollup or an auditor can never mistake it for hardware custody.
            if st.simulated {
                if let Some(o) = ev.as_object_mut() {
                    o.insert("simulated_hw".into(), serde_json::Value::Bool(true));
                }
            }
            j.append_at(epoch_id, seq, ev)?;
        }
        Ok(())
    }

    /// Handle one request.
    pub fn handle(
        &self,
        peer: &PeerCredentials,
        req: VaultRequest,
    ) -> EnclaveResult<VaultResponse> {
        if !matches!(&req, VaultRequest::Status | VaultRequest::Tamper(_)) { self.require_selected_owner()?; }
        let request_start=SystemClock::default().now_ns();
        let travel_generation=self.cas_key_generation.load(std::sync::atomic::Ordering::SeqCst);
        self.lock_state()?.check_member_loss_request(&req)?;
        if !matches!(&req,VaultRequest::RecordMemberLoss {..}|VaultRequest::PrepareMemberReplacement {..}) {self.preflight_travel_request(&req)?;}
        #[cfg(test)]
        travel_workflow::after_preflight_for_test();
        // Other sensitive replies already install their stronger factor,
        // lifetime and authority permits. Never overwrite those permits.
        let travel_sensitive=matches!(&req,VaultRequest::CreateDpopProof {..}|VaultRequest::NamespaceKeyChallenge {..}|VaultRequest::AdvanceCasWrappingFloor {..}|VaultRequest::CheckCasKeyLease(_));
        let travel_guarded=matches!(&req,VaultRequest::Tokenize {..}|VaultRequest::ScrubText {..}|VaultRequest::AllocateSlot);
        // The UID702 adjacency authorizes only model key custody and the existing
        // DPoP signer. It does not grant UID704 tokenization/egress authority.
        if peer.uid==DaemonId::SwarmSync.uid() && !matches!(&req,
            VaultRequest::UnwrapCasKey{..}|VaultRequest::NamespaceKeyChallenge{..}|VaultRequest::UnwrapCasKeyAuthorized{..}|VaultRequest::CheckCasKeyLease(_)|VaultRequest::CreateDpopProof{..}) {
            fail!(EACCES,"CAS_VAULT_RPC_FORBIDDEN");
        }
        let result=match req {
            VaultRequest::PrepareMemberReplacement {candidate,enrollment_evidence_id,replacement_receipt,survivor_receipt}=>self.prepare_member_replacement(peer,&candidate,enrollment_evidence_id,replacement_receipt,survivor_receipt,request_start),
            VaultRequest::RecordMemberLoss {statement}=>self.record_member_loss(peer,&statement,request_start),
            VaultRequest::ActivateTravelRecovery {token}=>self.activate_travel_recovery(peer,&token,request_start),
            VaultRequest::WrapCasKey {namespace,epoch,wrapping_epoch,key} => {
                let request_start=SystemClock::default().now_ns();
                if peer.uid!=0 && !(self.lock_state()?.simulated && peer.uid==enclave_core::ipc::geteuid()) {fail!(EACCES,"CAS_KEY_PROVISION_PEER");}
                let key=zeroize::Zeroizing::new(<[u8;32]>::try_from(key.0.as_slice()).map_err(|_|err!(EINVAL,"NAMESPACE_KEY_LENGTH"))?);
                let shape=enclave_crypto::namespace::WrappedNamespaceKey {namespace,epoch,wrapping_epoch,envelope_hex:"00".repeat(72)};
                let (kek,lease,_)=self.cas_key_custody_for_started(peer,&shape,NamespaceCustodyOperation::Provision { key_blake3: blake3::hash(key.as_slice()).to_hex().to_string() },request_start)?;
                let wrapped=enclave_crypto::namespace::wrap(&shape.namespace,shape.epoch,shape.wrapping_epoch,&key,&kek)?;
                self.register_cas_key(peer,&[&lease],wrapped.clone(),false,None,&kek)?;
                Ok(VaultResponse::WrappedCasKey(wrapped))
            }
            VaultRequest::ImportCasKey{wrapped}=>{
                let request_start=SystemClock::default().now_ns();
                self.cas_operator(peer)?;let (kek,lease,_)=self.cas_key_custody_for_started(peer,&wrapped,NamespaceCustodyOperation::Import,request_start)?;let _verified=enclave_crypto::namespace::unwrap(&wrapped,&kek)?;self.check_cas_lease(peer,&lease)?;
                self.register_cas_key(peer,&[&lease],wrapped.clone(),false,None,&kek)?;Ok(VaultResponse::WrappedCasKey(wrapped))
            }
            VaultRequest::RotateCasKey{wrapped,new_wrapping_epoch}=>{
                let request_start=SystemClock::default().now_ns();
                self.cas_operator(peer)?;self.lock_state()?.cas_keyring.verify(&wrapped)?;
                if new_wrapping_epoch<=wrapped.wrapping_epoch{fail!(EACCES,"CAS_KEY_ROTATION_ROLLBACK");}
                let (old,lease,_)=self.cas_key_custody_for_started(peer,&wrapped,NamespaceCustodyOperation::RotateFrom { new_wrapping_epoch },request_start)?;let key=enclave_crypto::namespace::unwrap(&wrapped,&old)?;
                let mut shape=wrapped.clone();shape.wrapping_epoch=new_wrapping_epoch;let (new,new_lease,_)=self.cas_key_custody_for_started(peer,&shape,NamespaceCustodyOperation::RotateTo { previous_envelope_blake3: Self::envelope_digest(&wrapped)? },request_start)?;self.check_cas_lease(peer,&lease)?;
                let rotated=enclave_crypto::namespace::wrap(&wrapped.namespace,wrapped.epoch,new_wrapping_epoch,key.expose(),&new)?;
                self.register_cas_key(peer,&[&lease,&new_lease],rotated.clone(),true,Some(&wrapped),&new)?;Ok(VaultResponse::WrappedCasKey(rotated))
            }
            VaultRequest::MigrateNamespaceBackup {namespace}=>self.migrate_namespace_backup(peer,&namespace),
            VaultRequest::AdvanceCasWrappingFloor{namespace,minimum_wrapping_epoch}=>{
                self.cas_operator(peer)?;let mut state=self.lock_sensitive_state()?;let result=state.cas_keyring.advance_floor(&namespace,minimum_wrapping_epoch);let state=self.finish_cas_keyring_write(state,result)?;drop(state);
                let _release=self.cas_key_release.lock().map_err(|_|err!(EIO,"CAS_RELEASE_LOCK"))?;self.lock_sensitive_state()?.cas_key_leases.retain(|_,lease|lease.namespace!=namespace);Ok(VaultResponse::CasKeyLeaseValid)
            }
            VaultRequest::UnwrapCasKey {wrapped} => {
                let request_start=SystemClock::default().now_ns();
                // Historical dual-custody fixtures remain explicitly simulated.
                // A daemon UID or root operator is not enterprise membership.
                {let state=self.lock_state()?;if !state.simulated || state.enterprise_authority.is_some(){fail!(EACCES,"ENTERPRISE_PROOF_REQUIRED");}}
                self.lock_state()?.cas_keyring.verify(&wrapped)?;
                let (kek,lease,_)=self.cas_key_custody_for_started(peer,&wrapped,NamespaceCustodyOperation::Unwrap,request_start)?;
                let key=enclave_crypto::namespace::unwrap(&wrapped,&kek)?;
                let state=self.lock_state()?;state.cas_keyring.verify(&wrapped)?;self.check_cas_lease_locked(&state,peer,&lease)?;
                Ok(VaultResponse::CasKey {key:enclave_crypto::namespace::SecretMaterial(key.expose().to_vec()),lease})
            }
            VaultRequest::NamespaceKeyChallenge{wrapped}=>self.namespace_key_challenge(peer,&wrapped),
            VaultRequest::UnwrapCasKeyAuthorized{wrapped,proof}=>self.unwrap_cas_key_authorized(peer,&wrapped,&proof),
            VaultRequest::CheckCasKeyLease(lease)=> {self.check_cas_lease(peer,&lease)?;Ok(VaultResponse::CasKeyLeaseValid)}
            VaultRequest::AuthorizeIntent(draft) => self.authorize_intent(peer, &draft),
            VaultRequest::Detokenize { surrogates, draft } => {
                self.detokenize(peer, &surrogates, &draft)
            }
            VaultRequest::RevealRecord { value, draft } => self.reveal(peer, &SecretBytes::new(value.0), &draft),
            VaultRequest::Enroll => self.enroll(peer),
            VaultRequest::EnrollBiometricL1 => self.enroll_biometric_l1(peer),
            VaultRequest::BeginAssetEnrollment=>self.begin_asset(peer),
            VaultRequest::ActivateAssetEnrollment {receipt}=>self.activate_asset(peer,receipt),
            VaultRequest::RenewAssetEnrollment {receipt}=>self.renew_asset(peer,receipt),
            VaultRequest::BeginAssetBackupEnrollment=>self.begin_asset_backup(peer),
            VaultRequest::AddAssetBackup {receipt}=>self.add_pending_asset_backup(peer,receipt),
            VaultRequest::RenewAssetMembership {primary_receipt,backup_receipt}=>self.renew_asset_membership(peer,primary_receipt,backup_receipt),
            VaultRequest::CreateDpopProof {
                htm,
                htu,
                access_token,
            } => {
                if peer.uid != DaemonId::AgentRuntime.uid()
                    && peer.uid != DaemonId::SwarmSync.uid()
                    && peer.uid != 0
                    && peer.uid != enclave_core::ipc::geteuid()
                {
                    fail!(
                        EPERM,
                        "DPOP_PEER_REJECTED",
                        "only agent-runtime (704), swarm-sync (702), or root may request DPoP proofs"
                    );
                }
                if !htu.starts_with("https://")
                    && !htu.starts_with("http://127.0.0.1")
                    && !htu.starts_with("http://localhost")
                {
                    fail!(
                        EINVAL,
                        "DPOP_HTU_INSECURE",
                        "HTU must begin with https:// or localhost"
                    );
                }
                let now = self.lock_state()?.clock.now_unix();
                let jti = format!("dpop-{}", enclave_core::rng::u64());
                let c = self.lock_sensitive_ceremony()?;
                let proof =
                    c.hw.sep
                        .create_dpop_proof(&htm, &htu, now, &jti, access_token.as_deref())?;
                Ok(VaultResponse::DpopProof(proof))
            }
            VaultRequest::Tamper(ev) => {
                if peer.uid!=0 && peer.uid!=enclave_core::ipc::geteuid() {fail!(EPERM,"WIPE_PEER_REJECTED");}
                let fence = self.revoke_cas_keys();
                let cleanup = self.cleanup_tamper_after_fence(peer, ev);
                fence?; cleanup
            }
            other => self.handle_state(peer, other),
        };
        if result.is_ok()&&travel_guarded&&self.lock_state()?.travel_active() {
            self.attach_travel_release(travel_generation,None)?;
        }
        if result.is_ok()&&travel_sensitive {self.attach_non_travel_release(travel_generation)?;}
        result
    }

    fn cas_operator(&self,peer:&PeerCredentials)->EnclaveResult<()> {let st=self.lock_state()?;if peer.uid!=0&&!(st.simulated&&peer.uid==enclave_core::ipc::geteuid()){fail!(EACCES,"CAS_KEY_PROVISION_PEER");}Ok(())}
    /// Configure an independently pinned authority before serving requests.
    /// This does not enroll a principal or create an issuer.
    pub fn set_enterprise_authority(&self,authority:std::sync::Arc<enclave_core::enterprise_authority::EnterpriseAuthority>)->EnclaveResult<()> {
        if !std::sync::Arc::ptr_eq(&self.cas_key_release,&authority.release_serial()){fail!(EACCES,"ENTERPRISE_RELEASE_FENCE_MISMATCH");}
        let mut state=self.lock_sensitive_state()?;if state.enterprise_authority.is_some(){fail!(EACCES,"ENTERPRISE_AUTHORITY_ALREADY_CONFIGURED");}state.enterprise_authority=Some(authority);state.cas_key_leases.clear();state.cas_key_deadlines.clear();state.namespace_challenges.clear();Ok(())
    }
    /// Single final-key/offboarding/wipe/enrollment order; no ceremony or
    /// persistence operation may retain this mutex.
    pub fn namespace_release_serial(&self)->std::sync::Arc<Mutex<()>> {self.cas_key_release.clone()}
    fn revoke_cas_keys(&self)->EnclaveResult<()> {
        self.revoke_cas_keys_with_generation().map(|_|())
    }
    fn cleanup_tamper_after_fence(&self,peer:&PeerCredentials,ev:TamperEvent)->EnclaveResult<VaultResponse> {
        // No release serial is retained while closing display control, trying
        // ceremony cleanup, or waiting for State and its actual region scrub.
        let display = self.display_revoke.as_ref().map(|revoke| revoke()).unwrap_or(Ok(()));
        let ceremony = if let Ok(mut ceremony)=self.lock_ceremony(){ceremony.leases.revoke_all();ceremony.hw.display.clear()}else{Ok(())};
        let cleanup = self.handle_state(peer, VaultRequest::Tamper(ev));
        // Attempt every existing cleanup even if an earlier owner failed.
        display?; ceremony?; cleanup
    }
    /// Return this revocation's generation while still holding the release
    /// serial. A later concurrent fence must never become a request's authority.
    fn revoke_cas_keys_with_generation(&self)->EnclaveResult<u64> {
        self.ceremony_cancelled.store(true, std::sync::atomic::Ordering::SeqCst);
        let _release=self.cas_key_release.lock().map_err(|_|err!(EIO,"CAS_RELEASE_LOCK"))?;
        self.ceremony_cancelled.store(true, std::sync::atomic::Ordering::SeqCst);
        self.cas_keys_enabled.store(false,std::sync::atomic::Ordering::SeqCst);
        let previous=self.cas_key_generation.try_update(std::sync::atomic::Ordering::SeqCst,std::sync::atomic::Ordering::SeqCst,|value|value.checked_add(1)).map_err(|_|err!(EIO,"CAS_KEY_GENERATION"))?;
        previous.checked_add(1).ok_or_else(||err!(EIO,"CAS_KEY_GENERATION"))
    }
    fn check_lifecycle_generation(&self, captured: u64) -> EnclaveResult<()> {
        self.require_selected_owner()?;
        if captured == u64::MAX { fail!(EACCES, "CUSTODY_GENERATION_EXHAUSTED"); }
        if !self.cas_keys_enabled.load(std::sync::atomic::Ordering::SeqCst)
            || self.cas_key_generation.load(std::sync::atomic::Ordering::SeqCst) != captured {
            fail!(EACCES, "CUSTODY_AUTHORIZATION_REVOKED");
        }
        Ok(())
    }

    fn prepare_fresh_authorization(&self, captured: u64) -> EnclaveResult<()> {
        self.require_selected_owner()?;
        self.lock_state()?.require_membership_active()?;
        if captured == u64::MAX { fail!(EACCES, "CUSTODY_GENERATION_EXHAUSTED"); }
        let _release = self.cas_key_release.lock().map_err(|_| err!(EIO, "CAS_RELEASE_LOCK"))?;
        if self.cas_key_generation.load(std::sync::atomic::Ordering::SeqCst) != captured {
            fail!(EACCES, "CUSTODY_AUTHORIZATION_REVOKED");
        }
        self.require_selected_owner()?;
        self.ceremony_cancelled.store(false, std::sync::atomic::Ordering::SeqCst);
        Ok(())
    }

    /// A dedicated inactive producer may clear cancellation for its OWN
    /// revocation after exact loss or live Preparing admission. This never enables custody and
    /// does not relax the ordinary active authorization helper above.
    fn prepare_sterile_replacement_enrollment(&self,captured:u64,profile:Profile)->EnclaveResult<()> {
        self.require_selected_owner()?;
        {let st=self.lock_state()?;
            if self.membership_authority.is_none()||!st.membership_sterile||!st.loss_attempted||st.profile!=profile||profile==Profile::L1 {
                fail!(EACCES,"REPLACEMENT_ENROLLMENT_STERILE_REQUIRED");
            }
        }
        let _release=self.cas_key_release.lock().map_err(|_|err!(EIO,"CAS_RELEASE_LOCK"))?;
        if captured==u64::MAX||self.cas_key_generation.load(std::sync::atomic::Ordering::SeqCst)!=captured
            ||self.cas_keys_enabled.load(std::sync::atomic::Ordering::SeqCst) {fail!(EACCES,"CAS_ENROLLMENT_REVOKED");}
        self.require_selected_owner()?;
        self.ceremony_cancelled.store(false,std::sync::atomic::Ordering::SeqCst);Ok(())
    }

    fn finish_fresh_authorization(&self, captured: u64, profile: Profile, action: ActionClass) -> EnclaveResult<()> {
        self.require_selected_owner()?;
        self.lock_state()?.require_membership_active()?;
        if captured == u64::MAX { fail!(EACCES, "CUSTODY_GENERATION_EXHAUSTED"); }
        let _release = self.cas_key_release.lock().map_err(|_| err!(EIO, "CAS_RELEASE_LOCK"))?;
        if self.ceremony_cancelled.load(std::sync::atomic::Ordering::SeqCst)
            || self.cas_key_generation.load(std::sync::atomic::Ordering::SeqCst) != captured {
            fail!(EACCES, "CUSTODY_AUTHORIZATION_REVOKED");
        }
        self.require_selected_owner()?;
        if profile >= Profile::L2 && action >= ActionClass::A3 {
            self.cas_enrolled_generation.store(captured, std::sync::atomic::Ordering::SeqCst);
        }
        self.cas_keys_enabled.store(true, std::sync::atomic::Ordering::SeqCst);
        Ok(())
    }

    fn check_authority_deadline(valid_until:Option<i64>,now:i64)->EnclaveResult<()> {
        if now<0||valid_until.is_some_and(|expiry|now>=expiry) {fail!(ESTALE,"CUSTODY_AUTHORITY_EXPIRED");}Ok(())
    }
    fn check_refreshed_envelope_bound(captured:Option<i64>,refreshed:Option<i64>)->EnclaveResult<()> {
        // A newly observed shorter transport chain needs fresh operation
        // admission. Never let slow preflight shorten authority underneath an
        // already prepared, longer socket-write deadline.
        if refreshed.is_some_and(|expiry|captured.is_none_or(|old|expiry<old)) {fail!(ESTALE,"ENVELOPE_TRANSPORT_BOUND_CHANGED");}
        Ok(())
    }
    fn check_refreshed_boot_bound(captured:Option<u64>,refreshed:Option<u64>)->EnclaveResult<()> {
        if refreshed.is_some_and(|deadline|captured.is_none_or(|old|deadline<old)) {fail!(ESTALE,"ENVELOPE_TRANSPORT_BOUND_CHANGED");}
        Ok(())
    }
    // Convert the signed wall boundary once without rounding its remaining
    // fraction upward. The native display retains this same boot-clock cap.
    fn release_boot_deadline(deadline_ns:Option<u64>,valid_until:Option<i64>)->EnclaveResult<Option<u64>> {
        let Some(expiry)=valid_until else {return Ok(deadline_ns)};
        let expiry=u64::try_from(expiry).map_err(|_|err!(ESTALE,"CUSTODY_AUTHORITY_EXPIRED"))?;
        let boot_before=SystemClock::default().now_ns();
        let now=std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_err(|_|err!(ESTALE,"CUSTODY_AUTHORITY_EXPIRED"))?;
        let remaining=std::time::Duration::from_secs(expiry).checked_sub(now).ok_or_else(||err!(ESTALE,"CUSTODY_AUTHORITY_EXPIRED"))?;
        let remaining=u64::try_from(remaining.as_nanos()).unwrap_or(u64::MAX);
        let bound=boot_before.saturating_add(remaining);
        Ok(Some(deadline_ns.map_or(bound,|previous|previous.min(bound))))
    }

    fn attach_lifecycle_release(&self, captured: u64, deadline_ns: Option<u64>, valid_until:Option<i64>, asset_guard:Option<asset_workflow::ActiveAssetGuard>) -> EnclaveResult<()> {
        self.check_lifecycle_generation(captured)?;
        let enabled = self.cas_keys_enabled.clone();
        let generation = self.cas_key_generation.clone();
        let final_asset=asset_guard.clone();
        let state=self.state.clone();
        let permit = self.selected_release_permit(
            self.cas_key_release.clone(), std::sync::Arc::new(move || {
                if captured == u64::MAX || !enabled.load(std::sync::atomic::Ordering::SeqCst)
                    || generation.load(std::sync::atomic::Ordering::SeqCst) != captured {
                    fail!(EACCES, "CUSTODY_AUTHORIZATION_REVOKED");
                }
                if deadline_ns.is_some_and(|deadline| SystemClock::default().now_ns() >= deadline) {
                    fail!(ETIMEDOUT, "CEREMONY_BUDGET_EXCEEDED");
                }
                let now=enclave_crypto::time::now_unix();
                Self::check_authority_deadline(valid_until,now)?;
                if let Some(guard)=&final_asset {guard.check_release(now)?;}
                Ok(())
            }), selected_owner_dependency::SelectedOwnerReply::Authority,
        ).with_preflight(std::sync::Arc::new(move ||{
            let mut state=state.lock().map_err(|_|err!(EIO,"VAULT_STATE_POISONED"))?;
            let refreshed=state.refresh_envelope_policy(enclave_crypto::time::now_unix())?;
            Self::check_refreshed_envelope_bound(valid_until,refreshed)?;
            Self::check_refreshed_boot_bound(deadline_ns,state.envelope_deadline_ns)
        }));
        let permit = if let Some(deadline) = Self::release_boot_deadline(deadline_ns,valid_until)? {
            let handoff_started=std::time::Instant::now();
            let remaining = deadline.saturating_sub(SystemClock::default().now_ns());
            permit.with_handoff_deadline(handoff_started + std::time::Duration::from_nanos(remaining))
        } else { permit };
        enclave_core::ipc::attach_release_permit(permit);
        Ok(())
    }

    fn attach_asset_release(&self,captured:u64,deadline_ns:Option<u64>,valid_until:Option<i64>,guard:asset_workflow::ActiveAssetGuard,boundary:selected_owner_dependency::SelectedOwnerReply)->EnclaveResult<()> {
        let final_guard=guard.clone();let generation=self.cas_key_generation.clone();
        let state=self.state.clone();
        let permit=self.selected_release_permit(self.cas_key_release.clone(),std::sync::Arc::new(move|| {
            if captured==u64::MAX||generation.load(std::sync::atomic::Ordering::SeqCst)!=captured {fail!(EACCES,"CUSTODY_AUTHORIZATION_REVOKED");}
            if deadline_ns.is_some_and(|deadline|SystemClock::default().now_ns()>=deadline) {fail!(ESTALE,"ENVELOPE_TRANSPORT_EXPIRED");}
            let now=enclave_crypto::time::now_unix();Self::check_authority_deadline(valid_until,now)?;
            final_guard.check_release(now)
        }),boundary)
            .with_preflight(std::sync::Arc::new(move||{
                let mut state=state.lock().map_err(|_|err!(EIO,"VAULT_STATE_POISONED"))?;
                let refreshed=state.refresh_envelope_policy(enclave_crypto::time::now_unix())?;
                Self::check_refreshed_envelope_bound(valid_until,refreshed)?;
                Self::check_refreshed_boot_bound(deadline_ns,state.envelope_deadline_ns)
            }));
        let permit=if let Some(deadline)=Self::release_boot_deadline(deadline_ns,valid_until)? {
            permit.with_handoff_deadline(std::time::Instant::now()+std::time::Duration::from_nanos(deadline.saturating_sub(SystemClock::default().now_ns())))
        }else {permit};
        enclave_core::ipc::attach_release_permit(permit);Ok(())
    }

    fn envelope_digest(wrapped:&enclave_crypto::namespace::WrappedNamespaceKey)->EnclaveResult<String> {
        wrapped.validate()?;Ok(hex::encode(blake3::hash(&enclave_core::jcs::to_jcs_bytes(wrapped)?).as_bytes()))
    }
    fn namespace_key_challenge(&self,peer:&PeerCredentials,wrapped:&enclave_crypto::namespace::WrappedNamespaceKey)->EnclaveResult<VaultResponse> {
        let digest=Self::envelope_digest(wrapped)?;
        let mut state=self.lock_sensitive_state()?;Self::namespace_peer(&state,peer)?;
        if state.enterprise_authority.is_none(){fail!(EACCES,"ENTERPRISE_AUTHORITY_REQUIRED");}
        state.cas_keyring.verify(wrapped)?;let now=state.clock.now_unix();state.namespace_challenges.retain(|_,(_,_,_,expiry)|*expiry>now);
        if state.namespace_challenges.len()>=128 {fail!(EAGAIN,"ENTERPRISE_CHALLENGE_LIMIT");}
        let challenge=hex::encode(enclave_core::rng::bytes32());let boot_epoch=state.seq.boot_epoch_id().to_owned();let expires_unix=now.saturating_add(30);
        state.namespace_challenges.insert(challenge.clone(),(peer.uid,boot_epoch.clone(),digest,expires_unix));
        Ok(VaultResponse::NamespaceKeyChallenge{challenge,boot_epoch,expires_unix})
    }
    fn unwrap_cas_key_authorized(&self,peer:&PeerCredentials,wrapped:&enclave_crypto::namespace::WrappedNamespaceKey,proof:&enclave_core::enterprise_authority::NamespaceProof)->EnclaveResult<VaultResponse> {
        let request_start=SystemClock::default().now_ns();
        let digest=Self::envelope_digest(wrapped)?;
        let (authority,now)={let mut state=self.lock_sensitive_state()?;Self::namespace_peer(&state,peer)?;
            let now=state.clock.now_unix();proof.verify(now)?;
            let expected=state.namespace_challenges.remove(&proof.challenge).ok_or_else(||err!(EACCES,"ENTERPRISE_CHALLENGE_REPLAY"))?;
            if expected!=(peer.uid,proof.boot_epoch.clone(),digest.clone(),proof.expires_unix) || proof.boot_epoch!=state.seq.boot_epoch_id() || proof.envelope_blake3!=digest {fail!(EACCES,"ENTERPRISE_CHALLENGE_BINDING");}
            (state.enterprise_authority.clone().ok_or_else(||err!(EACCES,"ENTERPRISE_AUTHORITY_REQUIRED"))?,now)};
        let membership=authority.authorize(&enclave_core::enterprise_authority::key32(&proof.holder_public_key)?,&wrapped.namespace,now)?;
        if membership.principal!=proof.principal {fail!(EACCES,"ENTERPRISE_PRINCIPAL_MISMATCH");}
        self.lock_sensitive_state()?.cas_keyring.verify(wrapped)?;
        let (kek,mut lease,deadline_ns)=self.cas_key_custody_for_started(peer,wrapped,NamespaceCustodyOperation::Unwrap,request_start)?;
        let key=enclave_crypto::namespace::unwrap(wrapped,&kek)?;
        let current_time={self.lock_sensitive_state()?.clock.now_unix()};authority.revalidate(&membership,current_time)?;
        lease.expires_unix=lease.expires_unix.min(membership.policy_expires_unix);
        lease.enterprise=Some(membership.clone());
        {let mut state=self.lock_sensitive_state()?;state.cas_keyring.verify(wrapped)?;
            let issued=state.cas_key_leases.get_mut(&lease.id).ok_or_else(||err!(EACCES,"CAS_KEY_LEASE_REVOKED"))?;
            if issued.generation!=lease.generation {fail!(EACCES,"CAS_KEY_LEASE_REVOKED");}*issued=lease.clone();
            let old_deadline=state.cas_key_deadlines.get(&lease.id).copied().ok_or_else(||err!(EACCES,"CAS_KEY_LEASE_REVOKED"))?;
            let bound=Self::release_boot_deadline(Some(old_deadline),Some(lease.expires_unix))?.ok_or_else(||err!(EACCES,"CAS_KEY_LEASE_REVOKED"))?;
            state.cas_key_deadlines.insert(lease.id.clone(),bound);self.check_cas_lease_locked(&state,peer,&lease)?;}
        // Local accepted offboarding is serialized with the actual key reply;
        // policy file I/O/fsync/signature work remains outside this mutex.
        let check_authority=authority.clone();let refresh_authority=authority.clone();let state=self.state.clone();
        let preflight_state=self.state.clone();
        let lease_expiry=lease.expires_unix;
        let generation=self.cas_key_generation.clone();let enabled=self.cas_keys_enabled.clone();let enrolled=self.cas_enrolled_generation.clone();let captured=lease.clone();
        let permit=self.selected_release_permit(authority.release_serial(),std::sync::Arc::new(move || {
            let state=match state.try_lock() {
                Ok(state)=>state,
                Err(std::sync::TryLockError::WouldBlock)=>fail!(EAGAIN,"CUSTODY_RELEASE_BUSY"),
                Err(std::sync::TryLockError::Poisoned(_))=>fail!(EIO,"VAULT_STATE_POISONED"),
            };let now=state.clock.now_unix();
            let current=generation.load(std::sync::atomic::Ordering::SeqCst);
            if current==u64::MAX||!enabled.load(std::sync::atomic::Ordering::SeqCst)||enrolled.load(std::sync::atomic::Ordering::SeqCst)!=current||captured.generation!=current
                ||state.cas_key_leases.get(&captured.id)!=Some(&captured)||captured.boot_epoch!=state.seq.boot_epoch_id()||captured.expires_unix<=now
                ||state.cas_key_deadlines.get(&captured.id).is_none_or(|deadline|SystemClock::default().now_ns()>=*deadline) {fail!(EACCES,"CAS_KEY_LEASE_REVOKED");}
            if deadline_ns.is_some_and(|deadline| SystemClock::default().now_ns() >= deadline) { fail!(ETIMEDOUT, "CEREMONY_BUDGET_EXCEEDED"); }
            state.check_release_time(now)?;
            check_authority.check_current(&membership,now)
        }),selected_owner_dependency::SelectedOwnerReply::Authority).with_preflight(std::sync::Arc::new(move ||{
            let now=enclave_crypto::time::now_unix();refresh_authority.refresh(now)?;
            let mut state=preflight_state.lock().map_err(|_|err!(EIO,"VAULT_STATE_POISONED"))?;
            let refreshed=state.refresh_envelope_policy(now)?;
            Self::check_refreshed_envelope_bound(Some(lease_expiry),refreshed)?;
            Self::check_refreshed_boot_bound(deadline_ns,state.envelope_deadline_ns)
        }));
        let permit = if let Some(deadline) = Self::release_boot_deadline(deadline_ns,Some(lease.expires_unix))? {
            permit.with_handoff_deadline(std::time::Instant::now() + std::time::Duration::from_nanos(deadline.saturating_sub(SystemClock::default().now_ns())))
        } else { permit };
        enclave_core::ipc::attach_release_permit(permit);
        Ok(VaultResponse::CasKey{key:enclave_crypto::namespace::SecretMaterial(key.expose().to_vec()),lease})
    }
    fn cas_keys_authorized(&self)->bool {
        self.require_selected_owner().is_ok()
            && self.cas_key_generation.load(std::sync::atomic::Ordering::SeqCst) != u64::MAX
            && self.cas_keys_enabled.load(std::sync::atomic::Ordering::SeqCst)
            && self.cas_enrolled_generation.load(std::sync::atomic::Ordering::SeqCst)==self.cas_key_generation.load(std::sync::atomic::Ordering::SeqCst)
    }
    fn namespace_peer(st:&State,peer:&PeerCredentials)->EnclaveResult<()> {
        st.require_no_travel()?;
        if peer.uid!=DaemonId::SwarmSync.uid() && peer.uid!=0 && !(st.simulated && peer.uid==enclave_core::ipc::geteuid()) {fail!(EACCES,"CAS_KEY_PEER_REJECTED");}
        if st.profile==Profile::L1 || !st.vault.is_enrolled() {fail!(EACCES,"CAS_KEY_CUSTODY_UNAVAILABLE");}Ok(())
    }
    fn check_cas_lease(&self,peer:&PeerCredentials,lease:&enclave_crypto::namespace::CasKeyLease)->EnclaveResult<()> {
        if !self.cas_keys_authorized() || lease.generation!=self.cas_key_generation.load(std::sync::atomic::Ordering::SeqCst) {fail!(EACCES,"CAS_KEY_LEASE_REVOKED");}
        if let Some(membership)=&lease.enterprise {
            let (authority,now)={let state=self.lock_sensitive_state()?;(state.enterprise_authority.clone().ok_or_else(||err!(EACCES,"ENTERPRISE_AUTHORITY_REQUIRED"))?,state.clock.now_unix())};
            authority.revalidate(membership,now)?;
        }
        let mut st=self.lock_sensitive_state()?;let now=st.clock.now_unix();let refreshed=st.refresh_envelope_policy(now)?;
        Self::check_refreshed_envelope_bound(Some(lease.expires_unix),refreshed)?;self.check_cas_lease_locked(&st,peer,lease)
    }
    fn check_cas_lease_locked(&self,st:&State,peer:&PeerCredentials,lease:&enclave_crypto::namespace::CasKeyLease)->EnclaveResult<()> {
        Self::namespace_peer(st,peer)?;
        st.check_release_time(st.clock.now_unix())?;
        if let Some(membership)=&lease.enterprise {st.enterprise_authority.as_ref().ok_or_else(||err!(EACCES,"ENTERPRISE_AUTHORITY_REQUIRED"))?.check_current(membership,st.clock.now_unix())?;}
        if !self.cas_keys_authorized() || st.cas_key_leases.get(&lease.id)!=Some(lease) || lease.boot_epoch!=st.seq.boot_epoch_id() || lease.generation!=self.cas_key_generation.load(std::sync::atomic::Ordering::SeqCst) || lease.expires_unix<=st.clock.now_unix()
            ||st.cas_key_deadlines.get(&lease.id).is_none_or(|deadline|SystemClock::default().now_ns()>=*deadline)
            || lease.expires_unix>st.clock.now_unix().saturating_add(60) {fail!(EACCES,"CAS_KEY_LEASE_REVOKED");}Ok(())
    }
    fn finish_cas_keyring_write<'a>(&self,mut state:std::sync::MutexGuard<'a,State>,result:EnclaveResult<()>)->EnclaveResult<std::sync::MutexGuard<'a,State>> {
        if state.cas_keyring.poisoned() {
            state.cas_key_leases.clear();state.cas_key_deadlines.clear();
            state.namespace_challenges.clear();
            // Never invert final permit's serial -> State order. Persistence
            // has finished; release State before establishing the revoke fence.
            drop(state);self.revoke_cas_keys()?;return Err(result.err().unwrap_or_else(||err!(EACCES,"CAS_KEYRING_POISONED")));
        }
        result?;Ok(state)
    }
    fn register_cas_key(&self,peer:&PeerCredentials,leases:&[&enclave_crypto::namespace::CasKeyLease],wrapped:enclave_crypto::namespace::WrappedNamespaceKey,replace:bool,previous:Option<&enclave_crypto::namespace::WrappedNamespaceKey>,kek:&SecretKey32)->EnclaveResult<()> {
        let mut state=self.lock_sensitive_state()?;
        for lease in leases {self.check_cas_lease_locked(&state,peer,lease)?;}
        if let Some(previous)=previous {state.cas_keyring.verify(previous)?;}
        let capsule=if state.membership_checkpoint.is_some() {
            let now=state.clock.now_unix();let context=state.namespace_context(now)?;
            Some(state.vault.seal_namespace_kek(&wrapped,kek,&context,now)?)
        } else {None};
        for lease in leases {self.check_cas_lease_locked(&state,peer,lease)?;}
        let result=if let Some(capsule)=capsule {state.cas_keyring.register_with_capsule(wrapped.clone(),capsule,replace)}
            else {state.cas_keyring.register(wrapped.clone(),replace)};
        let state=self.finish_cas_keyring_write(state,result)?;drop(state);
        let _release=self.cas_key_release.lock().map_err(|_|err!(EIO,"CAS_RELEASE_LOCK"))?;let mut state=self.lock_sensitive_state()?;
        // Tamper cancels before waiting for State. A cancellation during the
        // durable write cannot produce a successful registration response.
        for lease in leases {self.check_cas_lease_locked(&state,peer,lease)?;}
        state.cas_key_leases.retain(|_,lease|lease.namespace!=wrapped.namespace);Ok(())
    }
    #[cfg(test)]
    fn cas_key_custody(&self,peer:&PeerCredentials,wrapped:&enclave_crypto::namespace::WrappedNamespaceKey)->EnclaveResult<(SecretKey32,enclave_crypto::namespace::CasKeyLease)> {
        self.cas_key_custody_for(peer, wrapped, NamespaceCustodyOperation::Import).map(|(key, lease, _)| (key, lease))
    }

    fn authorize_intent(
        &self,
        peer: &PeerCredentials,
        draft: &enclave_core::intent_draft::IntentDraftV1,
    ) -> EnclaveResult<VaultResponse> {
        if peer.uid != DaemonId::AgentRuntime.uid() && peer.uid != enclave_core::ipc::geteuid() {
            fail!(
                EACCES,
                "INTENT_PEER_REJECTED",
                "only UID 704 requests tool step-ups"
            );
        }
        let captured_generation = self.cas_key_generation.load(std::sync::atomic::Ordering::SeqCst);
        let mut c = self.lock_sensitive_ceremony()?;
        c.enter_generation(captured_generation);
        self.prepare_fresh_authorization(captured_generation)?;
        let (epoch_id, seq, intent) = {
            let mut st = self.lock_sensitive_state()?;
            let (e, s) = Self::begin_governed(&mut st)?;
            let now = st.clock.now_unix();
            let i = intent_from_draft(draft, st.profile, &e, s, now)?;
            (e, s, i)
        };
        // The ceremony runs without the state lock.
        let before = c.counters.clone();
        // Every approval, A2 lease hits included, gets the same bounded
        // dispatch window; the lease only spares the prompt.
        let deadline_ns = (intent.action_class >= ActionClass::A2).then(|| c.clock.now_ns().saturating_add(crate::ceremony::CEREMONY_BUDGET_NS));
        let r = c.run(&intent, None, Some(&self.ceremony_cancelled));
        c.persist_counters(&before)?;
        let metadata_revision = c.hw.metadata_source.as_ref().and_then(|source| source.revision());
        c.hw.revalidate_metadata(metadata_revision, intent.profile, intent.action_class, enclave_crypto::time::now_unix())?;
        let mut grant = r?;
        let (valid_until,deadline_ns)={
            let mut state = self.lock_sensitive_state()?;let now=state.clock.now_unix();
            let transport_expiry=state.refresh_envelope_policy(now)?;
            grant.check_valid_at(now)?;grant.check_valid_at_boot(c.clock.now_ns())?;
            (state.release_valid_until([grant.valid_until_unix,transport_expiry].into_iter().flatten().min()),
                state.release_deadline([deadline_ns,grant.valid_until_boot_ns,c.hw.metadata_source.as_ref().and_then(|source|source.deadline_ns())].into_iter().flatten().min()))
        };
        if intent.action_class >= ActionClass::A2 && deadline_ns.is_none() {
            fail!(EACCES,"TOOL_AUTHORITY_LIFETIME_REQUIRED");
        }
        grant.consume()?;
        let d = hex::encode(grant.d_jcs);
        let factors: Vec<String> = grant.factors.iter().map(|f| format!("{f:?}")).collect();
        let ev = json!({"event": "TOOL_INTENT_APPROVED", "slot": seq, "d_jcs": d, "tool": intent.tool_name, "rows": intent.row_count_bound, "action": format!("{:?}", intent.action_class), "factors": factors});
        Self::journal(&mut *self.lock_sensitive_state()?, &epoch_id, seq, Some(ev))?;
        if deadline_ns.is_some_and(|deadline| c.clock.now_ns() >= deadline) { fail!(ETIMEDOUT, "CEREMONY_BUDGET_EXCEEDED"); }
        self.finish_fresh_authorization(captured_generation, intent.profile, intent.action_class)?;
        {
            let mut state = self.lock_sensitive_state()?;
            self.check_lifecycle_generation(captured_generation)?;
            if intent.profile == Profile::L3 && intent.action_class >= ActionClass::A3
                && state.lifecycle.state() == crate::lifecycle::CustodyState::SterileLocked {
                state.lifecycle.on(CustodyEvent::DualCustodyUnlock)?;
            }
        }
        self.attach_lifecycle_release(captured_generation, deadline_ns,valid_until,self.lock_sensitive_state()?.active_asset_guard.clone())?;
        Ok(VaultResponse::IntentAuthorizedV2(IntentAuthorizationV2 {d_jcs:d, factors,
            lifetime:IntentLifetimeV1 {v:1,valid_until_unix:valid_until,deadline_boot_ns:deadline_ns}}))
    }

    fn detokenize(
        &self,
        peer: &PeerCredentials,
        surrogates: &[String],
        draft: &enclave_core::intent_draft::IntentDraftV1,
    ) -> EnclaveResult<VaultResponse> {
        if peer.uid != DaemonId::AgentRuntime.uid()
            && peer.uid != 0
            && peer.uid != enclave_core::ipc::geteuid()
        {
            fail!(
                EACCES,
                "DETOKENIZE_PEER_REJECTED",
                "only UID 704 / the operator request detokenization"
            );
        }
        let digests = crate::intent::surrogate_digests(surrogates)?;
        let (rows, d_jcs) = self.release_to_display(draft, digests, None, true, "DETOKENIZE",
            |st, intent, grant, shares| {
                let (sep_share, l1) = shares.ok_or_else(|| err!(EIO, "DETOKENIZE_SHARES"))?;
                st.vault.detokenize(surrogates, intent, grant, sep_share.expose(), l1.map(SecretBytes::expose))
            })?;
        Ok(VaultResponse::Delivered { rows, d_jcs })
    }

    /// `A3` single-record reveal (Track C): the chained ceremony binds the
    /// intent to this exact value (custody computes its digests), then the
    /// value goes only to the trusted helper display. The journal records its
    /// length and BLAKE3, never the plaintext.
    fn reveal(
        &self,
        peer: &PeerCredentials,
        value: &SecretBytes,
        draft: &enclave_core::intent_draft::IntentDraftV1,
    ) -> EnclaveResult<VaultResponse> {
        if peer.uid != DaemonId::AgentRuntime.uid() && peer.uid != enclave_core::ipc::geteuid() {
            fail!(EACCES, "REVEAL_PEER_REJECTED", "only UID 704 requests a reveal");
        }
        if draft.action_class != ActionClass::A3 {
            fail!(EACCES, "REVEAL_ACTION_CLASS");
        }
        let bytes = value.expose();
        if bytes.is_empty() || bytes.len() > MAX_REVEAL_BYTES {
            fail!(E2BIG, "REVEAL_SIZE");
        }
        use sha2::Digest;
        let digests = (hex::encode(sha2::Sha256::digest(bytes)), blake3::hash(bytes).to_hex().to_string());
        // What the sheet says is custody's, not the caller's: one record of
        // sealed model output, revealed.
        let mut draft = draft.clone();
        draft.tool_name = REVEAL_TOOL.into();
        draft.canonical_verb = "Reveal".into();
        draft.row_count_bound = 1;
        // The caller leaves the argument digests empty; bind the value's
        // before the draft becomes an intent (which requires them).
        draft.arguments_jcs_sha256 = digests.0.clone();
        draft.canonical_arguments_blake3 = digests.1.clone();
        let (_, d_jcs) = self.release_to_display(&draft, digests, Some(1), false, "REVEAL",
            |_, _, _, _| Ok(vec![value.clone()]))?;
        Ok(VaultResponse::Delivered { rows: 1, d_jcs })
    }

    /// Run the chained ceremony for an `A3`/`A4` intent built from `draft`
    /// with argument `digests`, then release what `produce` yields to the
    /// trusted display only. Returns (rows shown, `d_jcs`).
    fn release_to_display<F>(
        &self,
        draft: &enclave_core::intent_draft::IntentDraftV1,
        digests: (String, String),
        row_count_bound: Option<u64>,
        sep_shares: bool,
        event: &'static str,
        produce: F,
    ) -> EnclaveResult<(usize, String)>
    where
        F: FnOnce(
            &mut State,
            &IntentPayloadV1,
            &mut crate::ceremony::CeremonyGrant,
            Option<(&SecretBytes, Option<&SecretBytes>)>,
        ) -> EnclaveResult<Vec<SecretBytes>>,
    {
        // Plaintext release always needs a full A3+ ceremony, never a lease.
        if draft.action_class < ActionClass::A3 {
            fail!(EINVAL, "CEREMONY_NOT_REQUIRED");
        }
        let captured_generation = self.cas_key_generation.load(std::sync::atomic::Ordering::SeqCst);
        let mut c = self.lock_sensitive_ceremony()?;
        c.enter_generation(captured_generation);
        self.prepare_fresh_authorization(captured_generation)?;
        let (arguments_sha, arguments_b3) = digests;
        let (epoch_id, seq, intent, profile) = {
            let mut st = self.lock_sensitive_state()?;
            let (e, s) = Self::begin_governed(&mut st)?;
            let now = st.clock.now_unix();
            let mut i = intent_from_draft(draft, st.profile, &e, s, now)?;
            i.canonical_arguments_blake3 = arguments_b3;
            i.arguments_jcs_sha256 = Some(arguments_sha);
            if let Some(bound) = row_count_bound {
                i.row_count_bound = Some(bound);
            }
            (e, s, Box::new(i), st.profile)
        };
        let tier = if intent.action_class == ActionClass::A4 {
            PrfTier::A4
        } else {
            PrfTier::A3
        };
        let before = c.counters.clone();
        let deadline_ns = (intent.action_class >= ActionClass::A3).then(|| c.clock.now_ns().saturating_add(crate::ceremony::CEREMONY_BUDGET_NS));
        let r = c.run(&intent, (profile >= Profile::L2).then_some(tier), Some(&self.ceremony_cancelled));
        c.persist_counters(&before)?;
        let metadata_revision = c.hw.metadata_source.as_ref().and_then(|source| source.revision());
        c.hw.revalidate_metadata(metadata_revision, intent.profile, intent.action_class, enclave_crypto::time::now_unix())?;
        let mut grant = r?;
        // Only a vault unwrap needs the SEP key shares; a reveal of a value
        // the caller already holds derives none.
        let shares = if sep_shares {
            let sep_share = c.hw.sep.ecdh_share(tier)?;
            let l1 = if profile == Profile::L1 {
                Some(c.hw.sep.l1_secondary_share(tier)?)
            } else {
                None
            };
            Some((sep_share, l1))
        } else {
            None
        };
        if self.ceremony_cancelled.load(std::sync::atomic::Ordering::SeqCst)
            || self.cas_key_generation.load(std::sync::atomic::Ordering::SeqCst) != captured_generation {
            fail!(EACCES, "CUSTODY_AUTHORIZATION_REVOKED");
        }
        let mut st = self.lock_sensitive_state()?;
        let now=st.clock.now_unix();let transport_expiry=st.refresh_envelope_policy(now)?;
        grant.check_valid_at(now)?;grant.check_valid_at_boot(c.clock.now_ns())?;
        let deadline_ns=st.release_deadline([deadline_ns,grant.valid_until_boot_ns,c.hw.metadata_source.as_ref().and_then(|source|source.deadline_ns())].into_iter().flatten().min());
        let valid_until=st.release_valid_until([grant.valid_until_unix,transport_expiry].into_iter().flatten().min());
        let deadline_ns=Self::release_boot_deadline(deadline_ns,valid_until)?;
        let values = produce(
            &mut st,
            &intent,
            &mut grant,
            shares.as_ref().map(|(sep_share, l1)| (sep_share, l1.as_ref())),
        )?;
        let rows = values.len();
        drop(st);
        // Encoding and all factor/PRF work finish outside the final handoff.
        let display_frame = encode_display(&values)?;
        c.hw.display.prepare_before(deadline_ns)?;
        if deadline_ns.is_some_and(|deadline| c.clock.now_ns() >= deadline) { fail!(ETIMEDOUT, "CEREMONY_BUDGET_EXCEEDED"); }
        self.finish_fresh_authorization(captured_generation, intent.profile, intent.action_class)?;
        let mut st = self.lock_sensitive_state()?;
        let now=st.clock.now_unix();let refreshed=st.refresh_envelope_policy(now)?;
        Self::check_refreshed_envelope_bound(valid_until,refreshed)?;
        Self::check_refreshed_boot_bound(deadline_ns,st.envelope_deadline_ns)?;
        // Reserve/hash/stage before entering the final handoff. Holding State
        // preserves admission, but never wait for the release serial in this
        // order: revocation holds that serial before acquiring State.
        let prepared=PreparedLocalWitness::prepare(&mut st,&epoch_id,seq,b"",Vec::new())?;
        let _release = match self.cas_key_release.try_lock() {
            Ok(guard) => guard,
            Err(std::sync::TryLockError::WouldBlock) => fail!(EAGAIN, "CUSTODY_RELEASE_BUSY"),
            Err(std::sync::TryLockError::Poisoned(_)) => fail!(EIO, "CAS_RELEASE_LOCK"),
        };
        self.check_lifecycle_generation(captured_generation)?;
        if deadline_ns.is_some_and(|deadline| c.clock.now_ns() >= deadline) { fail!(ETIMEDOUT, "CEREMONY_BUDGET_EXCEEDED"); }
        grant.check_valid_at(c.clock.now_unix())?;grant.check_valid_at_boot(c.clock.now_ns())?;
        prepared.state.check_release_time(c.clock.now_unix())?;
        if profile == Profile::L3 && prepared.state.lifecycle.state() == crate::lifecycle::CustodyState::SterileLocked {
            prepared.state.lifecycle.on(CustodyEvent::DualCustodyUnlock)?;
        }
        c.hw.display.show_prepared(&values, &display_frame)?;
        // The display handoff is complete. Persistence/receiver IPC below is
        // outside the release serial; an uncertain later failure cannot recall
        // plaintext already shown before the fence.
        drop(_release);
        prepared.commit()?;
        let d = hex::encode(grant.d_jcs);
        let ev = json!({"event": event, "slot": seq, "rows": rows, "d_jcs": d, "action": format!("{:?}", intent.action_class), "factors": grant.factors});
        Self::journal(&mut st, &epoch_id, seq, Some(ev))?;
        let asset_guard = st.active_asset_guard.clone();
        drop(st);
        // The already completed display remains a pre-fence effect. Its later
        // receipt still needs the original generation/factor/time authority at
        // actual IPC handoff; a failed receipt cannot recall shown plaintext.
        self.attach_lifecycle_release(captured_generation, deadline_ns, valid_until, asset_guard)?;
        Ok((rows, d))
    }

    /// `L1` Touch ID registration (Track C). The helper creates a fresh
    /// `.biometryCurrentSet` SEP key inside the approved Touch ID and signs
    /// custody's challenge with it; custody verifies that signature with the
    /// returned key, seals the key, and only then adopts it for later prompts.
    fn enroll_biometric_l1(&self, peer: &PeerCredentials) -> EnclaveResult<VaultResponse> {
        self.require_selected_owner()?;
        if peer.uid != 0 && peer.uid != enclave_core::ipc::geteuid() {
            fail!(EPERM, "ENROLL_ADMIN_ONLY");
        }
        let mut c = self.lock_sensitive_ceremony()?;
        let (profile, state_dir) = {
            let st = self.lock_sensitive_state()?;
            (st.profile, st.state_dir.clone())
        };
        if profile != Profile::L1 {
            fail!(EPERM, "BIOMETRIC_ENROLLMENT_L1_ONLY", "L2/L3 enroll through the asset workflow");
        }
        if c.hw.sep_bio_blob.is_some() && !c.hw.simulated {
            fail!(EPERM, "ALREADY_ENROLLED", "re-enrollment requires an explicit wipe");
        }
        if state_dir.is_none() && !c.hw.simulated {
            fail!(EINVAL, "STATE_DIR_REQUIRED");
        }
        let mut nonce = [0u8; 32];
        enclave_core::rng::fill(&mut nonce);
        use sha2::Digest;
        let prompt = crate::biometric::BiometricPrompt {
            localized_reason: "[Enrollment] Register this Mac's Touch ID for L1 custody".into(),
            d_jcs: sha2::Sha256::digest(b"mcpmac.l1-biometric-enrollment.v1").to_vec(),
            nonce: nonce.to_vec(),
            t_start_ns: c.clock.now_ns(),
            // Empty: the helper creates the key inside this approval.
            bio_key_blob: Vec::new(),
        };
        let outcome = c.hw.biometric.evaluate(&prompt);
        let (bio_pub, bio_blob) = match &outcome {
            crate::biometric::BiometricOutcome::Approved { enrolled_pubkey: Some(pk), enrolled_blob: Some(blob), .. }
                if !blob.is_empty() => (pk.clone(), blob.clone()),
            crate::biometric::BiometricOutcome::Approved { .. } => fail!(EACCES, "BIOMETRIC_ENROLLMENT_INCOMPLETE"),
            crate::biometric::BiometricOutcome::Cancelled => fail!(EACCES, "TOUCH_ID_CANCELLED"),
            crate::biometric::BiometricOutcome::TimedOut => fail!(ETIMEDOUT, "TOUCH_ID_TIMEOUT"),
            crate::biometric::BiometricOutcome::Occluded => fail!(EPERM, "UI_OCCLUSION_ABORT"),
            crate::biometric::BiometricOutcome::ReportSuspicious => fail!(EPERM, "USER_REPORTED_SUSPICIOUS_PROMPT"),
        };
        let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(&bio_pub)
            .map_err(|_| err!(EINVAL, "INVALID_BIO_PUBKEY"))?;
        crate::biometric::verify_approval(&vk, &prompt, &outcome)?;
        // Persist before adopting, as custodian enrollment does.
        if let Some(state_dir) = &state_dir {
            let (mut store, _) = enclave_core::sealed::SealedStore::open(&state_dir.join("custody"), BIOMETRIC_L1_STORE)?;
            store.save_json(&EnrolledBiometricL1 { bio_public_key: bio_pub.clone(), bio_key_blob: bio_blob.clone() })?;
        }
        c.hw.sep_bio_key = vk;
        c.hw.sep_bio_blob = Some(bio_blob);
        drop(c);
        let sas = enclave_crypto::sas::sas_words(blake3::hash(&bio_pub).as_bytes());
        let mut st = self.lock_sensitive_state()?;
        let (e, s) = (st.seq.boot_epoch_id().to_owned(), st.seq.current());
        Self::journal(&mut st, &e, s, Some(json!({"event": "BIOMETRIC_ENROLLED_L1", "sas": sas})))?;
        Ok(VaultResponse::BiometricEnrolled { sas })
    }

    fn enroll(&self, peer: &PeerCredentials) -> EnclaveResult<VaultResponse> {
        self.require_selected_owner()?;
        if peer.uid != 0 && peer.uid != enclave_core::ipc::geteuid() {
            fail!(EPERM, "ENROLL_ADMIN_ONLY");
        }
        let began=self.cas_key_generation.load(std::sync::atomic::Ordering::SeqCst);
        let mut c = self.lock_sensitive_ceremony()?;
        if c.hw.credential.is_some() && !c.hw.simulated {
            fail!(
                EPERM,
                "ALREADY_ENROLLED",
                "vault is already enrolled; re-enrollment requires explicit wipe"
            );
        }
        if !c.hw.simulated {
            // The compatible software flow below is not an independent asset
            // enrollment protocol. Native setup must persist the reviewed
            // one-use pending disclosure and inventory receipt before activation.
            fail!(EPERM, "ASSET_ENROLLMENT_ACTIVATION_REQUIRED");
        }
        let (profile, now) = {
            let st = self.lock_sensitive_state()?;
            (st.profile, st.clock.now_unix())
        };
        if profile == Profile::L1 {
            fail!(EPERM, "ENROLL_NOT_APPLICABLE_L1", "L1 uses Touch ID only");
        }
        let c = &mut *c;
        c.hw.refresh_metadata(profile, ActionClass::A4, now)?;
        let envelope_context = if c.hw.simulated { None } else {
            let authority = c.hw.envelope_authority.as_ref().ok_or_else(|| err!(EACCES, "ENVELOPE_POLICY_AUTHORITY_REQUIRED"))?;
            Some(c.hw.metadata_source.as_ref().ok_or_else(|| err!(EACCES, "ENVELOPE_POLICY_SOURCE_REQUIRED"))?.envelope_context(authority, profile, now)?)
        };
        let mds =
            c.hw.mds
                .clone()
                .ok_or_else(|| err!(EPERM, "CUSTODY_METADATA_UNAVAILABLE"))?;

        // Refused/busy/duplicate enrollment does not revoke a working session.
        // Once hardware mutation begins, CAS stays disabled on every failure.
        let generation=began.checked_add(1).ok_or_else(||err!(EIO,"CAS_KEY_GENERATION"))?;
        {let _release=self.cas_key_release.lock().map_err(|_|err!(EIO,"CAS_RELEASE_LOCK"))?;
            self.cas_key_generation.compare_exchange(began,generation,std::sync::atomic::Ordering::SeqCst,std::sync::atomic::Ordering::SeqCst).map_err(|_|err!(EACCES,"CAS_ENROLLMENT_REVOKED"))?;
            self.cas_keys_enabled.store(false,std::sync::atomic::Ordering::SeqCst);}
        // 1. Biometric Touch ID via helper (creates biometric SEP key and evaluates Touch ID)
        let mut nonce = [0u8; 32];
        enclave_core::rng::fill(&mut nonce);
        let bio_prompt = crate::biometric::BiometricPrompt {
            localized_reason: "[Enrollment] Register custodian biometric credential".into(),
            d_jcs: vec![0xEE; 32],
            nonce: nonce.to_vec(),
            t_start_ns: c.clock.now_ns(),
            bio_key_blob: Vec::new(),
        };
        let bio_outcome = c.hw.biometric.evaluate(&bio_prompt);
        if self.cas_key_generation.load(std::sync::atomic::Ordering::SeqCst)!=generation {fail!(EACCES,"CAS_ENROLLMENT_REVOKED");}
        let epoch_pub = c.hw.sep.epoch_public_key();
        let (bio_pub, bio_blob) = match &bio_outcome {
            crate::biometric::BiometricOutcome::Approved {
                enrolled_pubkey,
                enrolled_blob,
                ..
            } => {
                let pubkey = enrolled_pubkey.clone().unwrap_or(epoch_pub);
                let blob = enrolled_blob.clone().unwrap_or_else(|| vec![0xEE; 32]);
                (pubkey, blob)
            }
            crate::biometric::BiometricOutcome::Cancelled => fail!(EACCES, "TOUCH_ID_CANCELLED"),
            crate::biometric::BiometricOutcome::TimedOut => fail!(ETIMEDOUT, "TOUCH_ID_TIMEOUT"),
            crate::biometric::BiometricOutcome::Occluded => fail!(EPERM, "UI_OCCLUSION_ABORT"),
            crate::biometric::BiometricOutcome::ReportSuspicious => {
                fail!(EPERM, "USER_REPORTED_SUSPICIOUS_PROMPT")
            }
        };
        let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(&bio_pub)
            .map_err(|e| err!(EINVAL, "INVALID_BIO_PUBKEY", "SEC1 parse failed: {e}"))?;
        crate::biometric::verify_approval(&vk, &bio_prompt, &bio_outcome)?;

        // 2. YubiKey makeCredential
        let cred = {
            let dev =
                c.hw.yubikey
                    .as_mut()
                    .ok_or_else(|| err!(EIO, "AUTHENTICATOR_NOT_PRESENT"))?;
            #[cfg(any(test, feature = "simulation"))]
            if c.hw.simulated {
                let virtual_device = dev.virtual_authenticator().ok_or_else(|| err!(EACCES, "SIMULATED_ENROLLMENT_REQUIRES_VIRTUAL_TRANSPORT"))?;
                crate::ctap::client::enroll_simulated(virtual_device, &mds, profile, now)?
            } else {
                let mut cl = crate::ctap::client::CtapClient::open(dev.as_mut())?;
                crate::ctap::client::enroll(&mut cl, &mds, profile, now)?
            }
            #[cfg(not(any(test, feature = "simulation")))]
            {
                let mut cl = crate::ctap::client::CtapClient::open(dev.as_mut())?;
                crate::ctap::client::enroll(&mut cl, &mds, profile, now)?
            }
        };

        // 3. Create SEP tier keys
        c.hw.sep.create_tier_keys()?;

        // 4. Derive tier KEKs and complete vault reenrollment
        let a3s = c.hw.sep.ecdh_share(PrfTier::A3)?;
        let a4s = c.hw.sep.ecdh_share(PrfTier::A4)?;
        let before=c.counters.clone();
        let prfs=(||{
            let a3p=Self::enrollment_prf_for_credential(&mut c.hw,&cred,profile,PrfTier::A3,&mut c.counters,&mut c.counter_store)?;
            let a4p=Self::enrollment_prf_for_credential(&mut c.hw,&cred,profile,PrfTier::A4,&mut c.counters,&mut c.counter_store)?;
            Ok::<_,enclave_core::error::EnclaveError>((a3p,a4p))
        })();
        // An authenticator may consume a counter before the other PRF fails.
        // Persist every observed high-water mark, including failed enrollment.
        c.persist_counters(&before)?;
        let (a3p,a4p)=prfs?;

        let mut st = self.lock_sensitive_state()?;
        if self.cas_key_generation.load(std::sync::atomic::Ordering::SeqCst)!=generation {fail!(EACCES,"CAS_ENROLLMENT_REVOKED");}
        if st.cas_keyring.poisoned(){fail!(EACCES,"CAS_KEYRING_POISONED");}
        let a3_shares = KekShares {
            sep_ecdh_share: a3s.expose(), yubikey_prf: &a3p.expose()[..32],
        };
        let a4_shares = KekShares {
            sep_ecdh_share: a4s.expose(), yubikey_prf: &a4p.expose()[..32],
        };
        if let Some(context) = envelope_context.as_ref() {
            let directory = st.state_dir.as_ref().ok_or_else(|| err!(EACCES, "ENVELOPE_STATE_REQUIRED"))?.join("vault-envelopes");
            if st.envelope_store.is_none() {
                let (store, loaded) = enclave_core::sealed::SealedStore::open_bounded_required(&directory, "envelopes", 32 * 1024 * 1024)?;
                if !matches!(loaded, enclave_core::sealed::Loaded::Fresh) { fail!(EACCES, "ENVELOPE_STATE_MIGRATION_REQUIRED"); }
                st.envelope_store = Some(store);
            }
            let authority = c.hw.envelope_authority.as_ref().ok_or_else(|| err!(EACCES, "ENVELOPE_POLICY_AUTHORITY_REQUIRED"))?;
            let current = c.hw.metadata_source.as_ref().ok_or_else(|| err!(EACCES, "ENVELOPE_POLICY_SOURCE_REQUIRED"))?.envelope_context(authority, profile, enclave_crypto::time::now_unix())?;
            if current.digest() != context.digest() { fail!(ESTALE, "ENVELOPE_POLICY_CHANGED_MIGRATION_REQUIRED"); }
            let seed = enclave_core::sealed::sealing_key(&directory, "custody-surrogate-v2")?;
            st.vault = CustodyVault::enroll_authorized(profile, &a3_shares, &a4_shares, st.envelope_grant_key, context, seed, enclave_crypto::time::now_unix())?;
            st.envelope_policy_digest = Some(context.digest());
            st.envelope_valid_until_unix = Some(context.policy_expires_unix());
            st.envelope_deadline_ns=context.deadline_ns();
            st.persist_envelopes()?;
        } else if c.hw.simulated {
            st.vault.reenroll(&a3_shares, &a4_shares)?;
        } else { fail!(EACCES, "ENVELOPE_POLICY_REQUIRED"); }

        // 5. Persist enrollment in SealedStore before updating in-memory hardware state
        if let Some(state_dir) = &st.state_dir {
            let custody_dir = state_dir.join("custody");
            let enrolled_state = EnrolledCustodyState {
                credential: cred.clone(),
                bio_public_key: bio_pub.clone(),
                bio_key_blob: bio_blob.clone(),
            };
            let (mut store, _) =
                enclave_core::sealed::SealedStore::open(&custody_dir, "enrollment")?;
            store.save_json(&enrolled_state)?;
        }

        // 6. Update hardware state only after disk commit succeeds
        c.hw.credential = Some(cred.clone());
        c.hw.sep_bio_key = vk;
        c.hw.sep_bio_blob = Some(bio_blob.clone());

        let pk = cred.key.to_raw();
        let sas = enclave_crypto::sas::sas_words(blake3::hash(&pk).as_bytes());
        let out = VaultResponse::Enrolled {
            credential_id: hex::encode(&cred.credential_id),
            aaguid: hex::encode(cred.aaguid),
            firmware_version: cred.firmware_version,
            sas: sas.clone(),
        };
        let (e, s) = (st.seq.boot_epoch_id().to_owned(), st.seq.current());
        Self::journal(
            &mut st,
            &e,
            s,
            Some(json!({"event": "CUSTODIAN_ENROLLED", "sas": sas})),
        )?;
        drop(st);
        let _release=self.cas_key_release.lock().map_err(|_|err!(EIO,"CAS_RELEASE_LOCK"))?;
        if self.cas_key_generation.load(std::sync::atomic::Ordering::SeqCst)!=generation {fail!(EACCES,"CAS_ENROLLMENT_REVOKED");}
        self.require_selected_owner()?;
        if !c.hw.simulated { enclave_core::power::require_selected_usb_instance()?; }
        self.cas_enrolled_generation.store(generation,std::sync::atomic::Ordering::SeqCst);
        self.cas_keys_enabled.store(true,std::sync::atomic::Ordering::SeqCst);
        if self.cas_key_generation.load(std::sync::atomic::Ordering::SeqCst)!=generation {self.cas_keys_enabled.store(false,std::sync::atomic::Ordering::SeqCst);fail!(EACCES,"CAS_ENROLLMENT_REVOKED");}
        Ok(out)
    }

    fn handle_state(
        &self,
        peer: &PeerCredentials,
        req: VaultRequest,
    ) -> EnclaveResult<VaultResponse> {
        let selected_boundary=selected_owner_dependency::SelectedOwnerReply::for_request(&req);
        if !matches!(&req, VaultRequest::Status | VaultRequest::Tamper(_)) { self.require_selected_owner()?; }
        let captured_generation = self.cas_key_generation.load(std::sync::atomic::Ordering::SeqCst);
        let pair_requirement=if matches!(&req,VaultRequest::Tokenize {..}|VaultRequest::ScrubText {..}|VaultRequest::AllocateSlot) {
            // L1/L2 and explicit software fixtures do not use the hardware pair
            // here. Do not couple their nonauthorizing ingress to a live prompt.
            // Drop State before taking Ceremony, preserving ceremony->State order.
            Some(self.lock_state()?.requires_ingress_pair())
        } else {None};
        #[cfg(test)]
        if let Some(required)=pair_requirement {
            // A one-shot, thread-local scheduling point after the snapshot's
            // State guard is dropped. It supplies no admission result.
            let hook=INGRESS_PAIR_SNAPSHOT_FOR_TEST.with(|slot|slot.borrow_mut().take());
            if let Some(hook)=hook {hook(required);}
        }
        if pair_requirement==Some(true) {
            // Keep concrete native L3 pair admission unchanged. This path
            // still fails closed if a ceremony owns the pair; it is not a
            // claim of concurrent native L3 membership admission.
            let c=self.lock_ceremony()?;
            if c.hw.simulated||!c.hw.active_asset_guard.as_ref().is_some_and(|guard|guard.is_l3_membership()) {
                fail!(EAGAIN,"CUSTODY_INGRESS_ADMISSION_CHANGED");
            }
            if let Some(pair)=c.hw.membership_devices.as_ref() {pair.require_current(false)?;}
            else {enclave_core::power::require_selected_usb_instance()?;}
        }
        let mut st = self.lock_state()?;
        let st = &mut *st;
        if !matches!(selected_boundary, selected_owner_dependency::SelectedOwnerReply::Maintenance) { self.require_selected_owner()?; }
        // A membership activation or travel exit between the snapshot and this
        // actual State ownership must not skip newly required pair admission.
        // Refuse either change before any governed slot, checkpoint or ingress.
        if pair_requirement.is_some_and(|previous|previous!=st.requires_ingress_pair()) {
            fail!(EAGAIN,"CUSTODY_INGRESS_ADMISSION_CHANGED");
        }
        st.check_member_loss_request(&req)?;
        st.check_travel_request(&req)?;
        // GAP-27: only governed RPCs consume a slot, so the slot sequence
        // stays contiguous and every slot is either released or tombstonable.
        let governed = matches!(
            req,
            VaultRequest::Tokenize { .. }
                | VaultRequest::ScrubText { .. }
                | VaultRequest::AllocateSlot
        );
        let lifecycle_guarded = st.profile == Profile::L3 && governed && !st.travel_active();
        if lifecycle_guarded {
            self.check_lifecycle_generation(captured_generation)?;
            if !st.simulated && st.active_asset_guard.as_ref().and_then(|guard|guard.member_index()).is_none() { enclave_core::power::require_selected_usb_instance()?; }
        }
        if matches!(req, VaultRequest::AllocateSlot)
            && peer.uid != DaemonId::AgentRuntime.uid()
            && peer.uid != enclave_core::ipc::geteuid()
        {
            fail!(EACCES, "SLOT_PEER_REJECTED");
        }
        Self::checkpoint(st, false, None)?;
        let (epoch_id, seq) = if governed {
            Self::begin_governed(st)?
        } else {
            (st.seq.boot_epoch_id().to_owned(), st.seq.current())
        };
        let now = st.clock.now_unix();
        let mut operation_valid_until=None;
        let mut operation_deadline=None;
        let (resp, event) = match req {
            VaultRequest::Status => {
                let rss = enclave_core::resource::current_rss_bytes().unwrap_or(0);
                let s = DaemonStatus {
                    daemon_uid: DaemonId::CustodyVault.uid(),
                    binary: DaemonId::CustodyVault.binary().into(),
                    pid: std::process::id(),
                    rss_bytes: rss,
                    rss_ceiling_bytes: DaemonId::CustodyVault.rss_ceiling_bytes(),
                    boot_epoch_id: st.seq.boot_epoch_id().into(),
                    rpc_seq_u64: st.seq.current(),
                    state: format!(
                        "{} profile={} simulated_hw={} effective_profile={}",
                        if st.vault.is_enrolled() {
                            format!("{:?}", st.lifecycle.state())
                        } else {
                            "AwaitingEnrollment".to_string()
                        },
                        st.profile,
                        st.simulated
                        ,if st.travel_active() {Profile::L2}else{st.profile}
                    ),
                    phys_footprint_bytes: enclave_core::resource::current_phys_footprint_bytes()
                        .unwrap_or(0),
                    phys_footprint_source: enclave_core::resource::current_phys_footprint_source(),
                };
                (VaultResponse::Status(s), None)
            }
            VaultRequest::Tokenize {
                items,
                bulk_set,
                grant,
            } => {
                require_vault_client(peer)?;
                operation_valid_until=st.refresh_envelope_policy(now)?;operation_deadline=st.release_deadline(operation_deadline);
                let mut out = Vec::with_capacity(items.len());
                let result = (|| {
                    for i in &items {
                        out.push(st.vault.tokenize(
                        &i.value,
                        i.declared,
                        bulk_set,
                        grant.as_ref(),
                        now,
                        )?);
                    }
                    Ok::<_, enclave_core::error::EnclaveError>(())
                })();
                // Partial failures can consume sealing epochs too. Persist
                // those counts before returning either success or failure.
                st.persist_envelopes()?;
                result?;
                let now=st.clock.now_unix();let refreshed=st.refresh_envelope_policy(now)?;
                operation_valid_until=[operation_valid_until,refreshed].into_iter().flatten().min();operation_deadline=st.release_deadline(operation_deadline);
                let n = out.len();
                let raw = zeroize::Zeroizing::new(items
                    .iter()
                    .flat_map(|i| i.value.bytes().chain(*b"\n"))
                    .collect::<Vec<u8>>());
                let scrubbed: Vec<u8> = out
                    .iter()
                    .flat_map(|t| t.token.bytes().chain(*b"\n"))
                    .collect();
                Self::release(st, &epoch_id, seq, &raw, scrubbed)?;
                (
                    VaultResponse::Tokens(out),
                    Some(
                        json!({"event": "TOKENIZE", "slot": seq, "fields": n, "stats": st.vault.stats}),
                    ),
                )
            }
            VaultRequest::ScrubText {
                text,
                bulk_set,
                grant,
            } => {
                require_vault_client(peer)?;
                operation_valid_until=st.refresh_envelope_policy(now)?;operation_deadline=st.release_deadline(operation_deadline);
                let result = st.vault.scrub_text(&text, bulk_set, grant.as_ref(), now);
                st.persist_envelopes()?;
                let t = result?;
                let now=st.clock.now_unix();let refreshed=st.refresh_envelope_policy(now)?;
                operation_valid_until=[operation_valid_until,refreshed].into_iter().flatten().min();operation_deadline=st.release_deadline(operation_deadline);
                Self::release(st, &epoch_id, seq, text.as_bytes(), t.clone().into_bytes())?;
                (
                    VaultResponse::Text(t),
                    Some(json!({"event": "SCRUB_TEXT", "slot": seq, "stats": st.vault.stats})),
                )
            }
            VaultRequest::Tamper(ev) => {
                // GAP-39: wiping is for the supervisor / operator (and the
                // daemon's own IOKit observers), never a peer daemon.
                if peer.uid != 0 && peer.uid != enclave_core::ipc::geteuid() {
                    fail!(EPERM, "WIPE_PEER_REJECTED");
                }
                // The bounded generation/disable fence was established before
                // this handler acquired State; do not mutate it out of order.
                st.cas_key_leases.clear();st.cas_key_deadlines.clear();
                st.namespace_challenges.clear();
                let rep = st.zeroizer.handle(ev, || false);
                // Custody loss revokes live authority, never destroys durable
                // encrypted records or rotates their surrogate identity. Tier
                // private keys and PRFs are scoped to the cancelled ceremony;
                // the vault retains public/wrapped keys and ciphertext only,
                // plus its separately inventoried surrogate MAC authority.
                let _ = st.lifecycle.on(match ev {
                    TamperEvent::UsbYank { .. } => CustodyEvent::UsbYank,
                    _ => CustodyEvent::SleepOrLock,
                });
                let rep = rep?;
                // A completed scrub permanently closes the old L3 attachment;
                // no USB return/legacy reattestation event can revive it.
                if st.lifecycle.state() == crate::lifecycle::CustodyState::L3VmProtNoneFreeze {
                    st.lifecycle.on(CustodyEvent::ReattestFailed)?;
                }
                (
                    VaultResponse::Zeroized(rep.clone()),
                    Some(json!({"event": "ZEROIZE", "report": rep})),
                )
            }
            VaultRequest::CoSignTombstone {
                slot_rpc_seq,
                boot_epoch_id,
            } => {
                // GAP-11: only the prover asks, and only for a slot this
                // daemon issued and never released.
                if peer.uid != DaemonId::ZkAuditor.uid() && peer.uid != enclave_core::ipc::geteuid()
                {
                    fail!(EACCES, "TOMBSTONE_PEER_REJECTED");
                }
                enclave_core::seq::validate_epoch_id(&boot_epoch_id)?;
                st.egress.reserve_tombstone(&boot_epoch_id, slot_rpc_seq)?;
                let m = enclave_core::audit::tombstone_message(slot_rpc_seq, &boot_epoch_id);
                let sig = st.tombstone_key.sign(&m);
                (
                    VaultResponse::TombstoneSignature {
                        signature: sig.to_bytes().to_vec(),
                        public_key: st.tombstone_key.verifying_key().to_bytes().to_vec(),
                    },
                    Some(
                        json!({"event": "TOMBSTONE_COSIGN", "tombstone_slot": slot_rpc_seq, "tombstone_epoch": boot_epoch_id}),
                    ),
                )
            }
            VaultRequest::AllocateSlot => {
                // GAP-27: the issuance is journaled at the slot itself, so every
                // daemon's line for it shares `(boot_epoch_id, rpc_seq_u64)`. No
                // `payload.slot`: the holder (UID 704), not UID 703, claims it.
                (
                    VaultResponse::Slot {
                        boot_epoch_id: epoch_id.clone(),
                        rpc_seq_u64: seq,
                    },
                    Some(json!({"event": "SLOT_ISSUED", "holder_uid": peer.uid})),
                )
            }
            VaultRequest::BootEpoch => (VaultResponse::Epoch(st.epoch.clone()), None),
            VaultRequest::FetchWitness {
                boot_epoch_id,
                s_start,
                s_end,
            } => {
                if peer.uid != DaemonId::ZkAuditor.uid() && peer.uid != enclave_core::ipc::geteuid()
                {
                    fail!(EACCES, "WITNESS_PEER_REJECTED");
                }
                if boot_epoch_id != epoch_id {
                    fail!(
                        ESTALE,
                        "WITNESS_EPOCH_GONE",
                        "witnesses of {boot_epoch_id} did not survive a restart"
                    );
                }
                let folds = st
                    .witness
                    .iter()
                    .filter(|w| (s_start..=s_end).contains(&w.rpc_seq_u64))
                    .cloned()
                    .collect();
                (
                    VaultResponse::Witness {
                        folds,
                        next_slot: st.seq.current(),
                    },
                    None,
                )
            }
            VaultRequest::AuthorizeIntent(_)
            | VaultRequest::PrepareMemberReplacement {..}
            | VaultRequest::RecordMemberLoss {..}
            | VaultRequest::ActivateTravelRecovery {..}
            | VaultRequest::Detokenize { .. }
            | VaultRequest::RevealRecord { .. }
            | VaultRequest::Enroll
            | VaultRequest::EnrollBiometricL1
            | VaultRequest::BeginAssetEnrollment | VaultRequest::ActivateAssetEnrollment {..} | VaultRequest::RenewAssetEnrollment {..} | VaultRequest::BeginAssetBackupEnrollment | VaultRequest::AddAssetBackup {..} | VaultRequest::RenewAssetMembership {..}
            | VaultRequest::CreateDpopProof { .. }
            | VaultRequest::WrapCasKey {..} | VaultRequest::ImportCasKey{..} | VaultRequest::RotateCasKey{..} | VaultRequest::AdvanceCasWrappingFloor{..} | VaultRequest::MigrateNamespaceBackup {..} | VaultRequest::UnwrapCasKey {..} | VaultRequest::NamespaceKeyChallenge{..} | VaultRequest::UnwrapCasKeyAuthorized{..} | VaultRequest::CheckCasKeyLease(_) => fail!(EINVAL, "DISPATCH"),
        };
        Self::journal(st, &epoch_id, seq, event)?;
        if operation_valid_until.is_none()&&st.active_asset_guard.is_some() {let now=st.clock.now_unix();operation_valid_until=st.refresh_envelope_policy(now)?;operation_deadline=st.release_deadline(operation_deadline);}
        if lifecycle_guarded { self.attach_lifecycle_release(captured_generation, operation_deadline,st.release_valid_until(operation_valid_until),st.active_asset_guard.clone())?; }
        else if let Some(guard)=st.active_asset_guard.clone() {self.attach_asset_release(captured_generation,operation_deadline,st.release_valid_until(operation_valid_until),guard,selected_boundary)?;}
        else if self.selected_owner_failure.get().is_some()
            && !matches!(selected_boundary, selected_owner_dependency::SelectedOwnerReply::Maintenance) {
            self.attach_selected_dependency_release(captured_generation,operation_deadline,st.release_valid_until(operation_valid_until))?;
        }
        Ok(resp)
    }
}

#[cfg(test)]
mod cas_namespace_tests {
    use super::*;
    use enclave_crypto::namespace::SecretMaterial;
    #[test]
    fn namespace_lease_retains_earliest_envelope_review_and_final_factor_bound() {
        let now=enclave_crypto::time::now_unix();
        let service=VaultService::start(VaultConfig{profile:Profile::L2,..Default::default()},VaultHardware::simulated(Profile::L2,now).unwrap()).unwrap();
        let review=now+20;
        service.lock_state().unwrap().envelope_valid_until_unix=Some(review);
        let wrapped=enclave_crypto::namespace::WrappedNamespaceKey {namespace:"models".into(),epoch:1,wrapping_epoch:1,envelope_hex:"00".repeat(72)};
        let peer=PeerCredentials::local(0,0);
        let (_,lease)=service.cas_key_custody(&peer,&wrapped).unwrap();
        assert_eq!(lease.expires_unix,review);
        {let st=service.lock_state().unwrap();
            assert_eq!(st.release_valid_until(Some(now+10)),Some(now+10));
            assert_eq!(st.release_valid_until(Some(now+30)),Some(review));
            st.check_release_time(review-1).unwrap();
            assert!(st.check_release_time(review).unwrap_err().is("CUSTODY_AUTHORITY_EXPIRED"));}
        assert!(VaultService::release_boot_deadline(None,Some(now-1)).unwrap_err().is("CUSTODY_AUTHORITY_EXPIRED"));
        let original=SystemClock::default().now_ns()+1_000_000;
        assert_eq!(VaultService::release_boot_deadline(Some(original),Some(now+30)).unwrap(),Some(original));
    }

    #[test]
    fn namespace_lease_captures_boot_expiry_and_refresh_cannot_extend_it() {
        let now=enclave_crypto::time::now_unix();
        let service=VaultService::start(VaultConfig{profile:Profile::L2,..Default::default()},VaultHardware::simulated(Profile::L2,now).unwrap()).unwrap();
        let captured=SystemClock::default().now_ns()+30_000_000_000;
        service.lock_state().unwrap().envelope_deadline_ns=Some(captured);
        let wrapped=enclave_crypto::namespace::WrappedNamespaceKey {namespace:"models".into(),epoch:1,wrapping_epoch:1,envelope_hex:"00".repeat(72)};
        let peer=PeerCredentials::local(0,0);
        let (_,lease)=service.cas_key_custody(&peer,&wrapped).unwrap();
        {
            let mut state=service.lock_state().unwrap();
            assert_eq!(state.cas_key_deadlines.get(&lease.id),Some(&captured));
            state.envelope_deadline_ns=Some(captured+30_000_000_000);
        }
        service.check_cas_lease(&peer,&lease).unwrap();
        assert_eq!(service.lock_state().unwrap().cas_key_deadlines.get(&lease.id),Some(&captured),"refresh never renews captured lease");
        service.lock_state().unwrap().cas_key_deadlines.insert(lease.id.clone(),0);
        assert!(service.check_cas_lease(&peer,&lease).unwrap_err().is("CAS_KEY_LEASE_REVOKED"),"wall-valid lease with expired captured boot authority refuses");
        assert!(VaultService::check_refreshed_boot_bound(Some(100),Some(99)).unwrap_err().is("ENVELOPE_TRANSPORT_BOUND_CHANGED"));
        VaultService::check_refreshed_boot_bound(Some(100),Some(101)).unwrap();
    }

    #[test]
    fn actual_ipc_final_release_refuses_factor_expiry_while_waiting_for_serial() {
        use enclave_core::ipc::{self,PeerPolicy,SocketAccess};
        use std::{os::unix::fs::PermissionsExt,sync::atomic::{AtomicBool,Ordering},time::Duration};
        let now=enclave_crypto::time::now_unix();
        let service=VaultService::start(VaultConfig{profile:Profile::L2,..Default::default()},VaultHardware::simulated(Profile::L2,now).unwrap()).unwrap();
        let directory=std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target").canonicalize().unwrap().join(format!("expiry-{:x}",enclave_core::rng::u64()));
        std::fs::create_dir_all(&directory).unwrap();std::fs::set_permissions(&directory,std::fs::Permissions::from_mode(0o700)).unwrap();
        let current=std::env::current_dir().unwrap();let from:Vec<_>=current.components().collect();let to:Vec<_>=directory.components().collect();
        let common=from.iter().zip(&to).take_while(|(a,b)|a==b).count();let mut relative=std::path::PathBuf::new();
        for _ in common..from.len(){relative.push("..");}for component in &to[common..]{relative.push(component.as_os_str());}
        let socket=relative.join("vault.sock");let listener=ipc::bind(&socket,SocketAccess::OwnerOnly).unwrap();
        let stop=Arc::new(AtomicBool::new(false));let stopped=stop.clone();let worker=service.clone();
        let serial=service.cas_key_release.lock().unwrap();let (prepared_tx,prepared_rx)=std::sync::mpsc::channel();
        let expiry=enclave_crypto::time::now_unix()+2;
        let server=std::thread::spawn(move||ipc::serve(listener,PeerPolicy::allow([ipc::geteuid()]),Arc::new(move|_:&PeerCredentials,_:()| {
            worker.attach_lifecycle_release(worker.cas_key_generation.load(Ordering::SeqCst),None,Some(expiry),None)?;
            prepared_tx.send(()).unwrap();Ok::<_,enclave_core::EnclaveError>(true)
        }),stopped));
        let path=socket.clone();let client=std::thread::spawn(move||{
            let mut client=ipc::Client::connect(&path,ipc::geteuid()).unwrap();client.set_timeout(Some(Duration::from_secs(5))).unwrap();client.call::<_,bool>(&())
        });
        prepared_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        while enclave_crypto::time::now_unix()<expiry {std::thread::sleep(Duration::from_millis(10));}
        drop(serial);assert!(client.join().unwrap().is_err());
        stop.store(true,Ordering::SeqCst);server.join().unwrap().unwrap();std::fs::remove_dir_all(directory).unwrap();
    }
    #[test]
    fn yk_namespace_intent_binds_complete_envelope_operation_policy_and_caller() {
        let wrapped=enclave_crypto::namespace::WrappedNamespaceKey {namespace:"models".into(),epoch:1,wrapping_epoch:2,envelope_hex:"00".repeat(72)};
        let epoch=enclave_core::seq::new_boot_epoch_id();
        let make=|wrapped:&enclave_crypto::namespace::WrappedNamespaceKey,operation:&NamespaceCustodyOperation,uid,policy|namespace_intent(wrapped,operation,Profile::L3,uid,policy,&epoch,1,20).unwrap();
        let base=make(&wrapped,&NamespaceCustodyOperation::Unwrap,702,[1;32]);
        assert_eq!(base.spiffe_id,DaemonId::SwarmSync.spiffe_id());
        assert_eq!(base.action_class,ActionClass::A3);
        assert!(base.required_factors.contains(&crate::factors::Factor::TouchIdCoreauthui));
        assert!(base.required_factors.contains(&crate::factors::Factor::YubikeyPinUv));
        let mut changed=wrapped.clone();changed.envelope_hex.replace_range(..2,"01");
        assert_ne!(base.canonical_arguments_blake3,make(&changed,&NamespaceCustodyOperation::Unwrap,702,[1;32]).canonical_arguments_blake3);
        assert_ne!(base.canonical_arguments_blake3,make(&wrapped,&NamespaceCustodyOperation::Import,702,[1;32]).canonical_arguments_blake3);
        assert_ne!(base.canonical_arguments_blake3,make(&wrapped,&NamespaceCustodyOperation::Unwrap,0,[1;32]).canonical_arguments_blake3);
        assert_ne!(base.policy_blake3,make(&wrapped,&NamespaceCustodyOperation::Unwrap,702,[2;32]).policy_blake3);
        let provision=make(&wrapped,&NamespaceCustodyOperation::Provision{key_blake3:"12".repeat(32)},0,[1;32]);
        assert_eq!(provision.action_class,ActionClass::A4);
        assert!(provision.required_factors.contains(&crate::factors::Factor::OidcStepUp));
        let mut root=wrapped;root.namespace="root".into();
        assert!(make(&root,&NamespaceCustodyOperation::Import,0,[1;32]).required_factors.contains(&crate::factors::Factor::KofnEd25519Quorum));
    }

    #[test]
    fn yk_namespace_native_a4_refuses_missing_independent_authority_before_key_use() {
        let profile=Profile::L2;
        let service=VaultService::start(VaultConfig{profile,..VaultConfig::default()},VaultHardware::simulated(profile,enclave_crypto::time::now_unix()).unwrap()).unwrap();
        let before={let mut ceremony=service.lock_ceremony().unwrap();ceremony.hw.simulated=false;ceremony.hw.yubikey=None;ceremony.counters.clone()};
        let shape=enclave_crypto::namespace::WrappedNamespaceKey{namespace:"models".into(),epoch:1,wrapping_epoch:1,envelope_hex:"00".repeat(72)};
        let peer=PeerCredentials::local(0,0);
        assert!(service.cas_key_custody_for(&peer,&shape,NamespaceCustodyOperation::Import).unwrap_err().is("NAMESPACE_A4_AUTHORITY_REQUIRED"));
        assert_eq!(before,service.lock_ceremony().unwrap().counters);
        assert!(service.lock_state().unwrap().cas_key_leases.is_empty());
    }

    #[derive(Debug)]
    struct IndependentRevokeDisplay(Arc<std::sync::atomic::AtomicBool>);
    impl HumanDisplay for IndependentRevokeDisplay {
        fn show(&mut self,_:&[SecretBytes])->EnclaveResult<()> {Ok(())}
        fn revocation_handle(&self)->Option<Arc<dyn Fn()->EnclaveResult<()>+Send+Sync>> {
            let revoked=self.0.clone();Some(Arc::new(move||{revoked.store(true,std::sync::atomic::Ordering::SeqCst);Ok(())}))
        }
    }
    #[test]
    fn yk03_busy_ceremony_cannot_suppress_independent_display_revocation() {
        let revoked=Arc::new(std::sync::atomic::AtomicBool::new(false));
        let mut hardware=VaultHardware::simulated(Profile::L1,enclave_crypto::time::now_unix()).unwrap();
        hardware.display=Box::new(IndependentRevokeDisplay(revoked.clone()));
        let service=VaultService::start(VaultConfig{profile:Profile::L1,..VaultConfig::default()},hardware).unwrap();
        let ceremony=service.lock_ceremony().unwrap();
        let peer=PeerCredentials::local(enclave_core::ipc::geteuid(),0);
        assert!(matches!(service.handle(&peer,VaultRequest::Tamper(TamperEvent::ScreenLock)).unwrap(),VaultResponse::Zeroized(_)));
        assert!(revoked.load(std::sync::atomic::Ordering::SeqCst));
        assert!(service.ceremony_cancelled.load(std::sync::atomic::Ordering::SeqCst));
        drop(ceremony);
    }

    #[test]
    fn f38_real_custody_mode_requires_persistent_namespace_authority_before_startup() {
        for profile in [Profile::L2,Profile::L3] {
            // Software-created objects only; the gate runs before any provider
            // call and is the only production-mode behavior exercised here.
            let mut hardware=VaultHardware::simulated(profile,enclave_crypto::time::now_unix()).unwrap();hardware.simulated=false;
            assert!(VaultService::start(VaultConfig{profile,..VaultConfig::default()},hardware).unwrap_err().is("CAS_KEYRING_STATE_REQUIRED"));
        }
    }
    #[test]
    fn f38_custody_actual_orchestration_fixture_and_wipe_revokes_lease() {
        // Explicit software hardware fixture; no SEP/FIDO production claim.
        let cfg=VaultConfig {profile:Profile::L3,..VaultConfig::default()};
        let hw=VaultHardware::simulated(Profile::L3,enclave_crypto::time::now_unix()).unwrap();
        let service=VaultService::start(cfg,hw).unwrap();
        let operator=PeerCredentials::local(enclave_core::ipc::geteuid(),0);
        let wrapped=match service.handle(&operator,VaultRequest::WrapCasKey {namespace:"models".into(),epoch:1,wrapping_epoch:1,key:SecretMaterial(vec![7;32])}).unwrap() {VaultResponse::WrappedCasKey(v)=>v,_=>panic!("wrong response")};
        let lease=match service.handle(&operator,VaultRequest::UnwrapCasKey {wrapped:wrapped.clone()}).unwrap() {VaultResponse::CasKey {key,lease}=>{assert_eq!(key.0,vec![7;32]);lease},_=>panic!("wrong response")};
        assert!(matches!(service.handle(&operator,VaultRequest::CheckCasKeyLease(lease.clone())).unwrap(),VaultResponse::CasKeyLeaseValid));
        assert!(service.handle(&PeerCredentials::local(999,0),VaultRequest::UnwrapCasKey {wrapped:wrapped.clone()}).is_err());
        let mut wrong=wrapped;wrong.namespace="foreign".into();assert!(service.handle(&operator,VaultRequest::UnwrapCasKey {wrapped:wrong}).is_err());
        let cas=PeerCredentials::local(DaemonId::SwarmSync.uid(),0);
        for forbidden in [VaultRequest::BootEpoch,VaultRequest::Status,VaultRequest::AllocateSlot,VaultRequest::Enroll] {
            assert!(service.handle(&cas,forbidden).unwrap_err().is("CAS_VAULT_RPC_FORBIDDEN"));
        }
        {let ceremony=service.lock_ceremony().unwrap();assert!(service.handle(&operator,VaultRequest::Enroll).unwrap_err().is("CEREMONY_IN_FLIGHT"));assert!(service.handle(&operator,VaultRequest::CheckCasKeyLease(lease.clone())).is_ok());drop(ceremony);}
        {let mut ceremony=service.lock_ceremony().unwrap();ceremony.hw.simulated=false;}assert!(service.handle(&operator,VaultRequest::Enroll).unwrap_err().is("ALREADY_ENROLLED"));assert!(service.handle(&operator,VaultRequest::CheckCasKeyLease(lease.clone())).is_ok());{service.lock_ceremony().unwrap().hw.simulated=true;}
        // Hold the ceremony to model pending hardware. Atomic cancellation and
        // the actual state/region wipe must still run while hardware is busy.
        let ceremony=service.lock_ceremony().unwrap();let pending=service.clone();let peer=operator.clone();
        let thread=std::thread::spawn(move||pending.handle(&peer,VaultRequest::Tamper(TamperEvent::ScreenLock)));
        let deadline=std::time::Instant::now()+std::time::Duration::from_secs(1);
        while service.cas_keys_enabled.load(std::sync::atomic::Ordering::SeqCst) && std::time::Instant::now()<deadline {std::thread::yield_now();}
        assert!(!service.cas_keys_enabled.load(std::sync::atomic::Ordering::SeqCst));
        assert!(service.handle(&operator,VaultRequest::CheckCasKeyLease(lease.clone())).unwrap_err().is("CAS_KEY_LEASE_REVOKED"));
        let outcome=thread.join().unwrap().unwrap();assert!(matches!(outcome,VaultResponse::Zeroized(_)));drop(ceremony);
        assert!(service.handle(&operator,VaultRequest::CheckCasKeyLease(lease)).unwrap_err().is("CAS_KEY_LEASE_REVOKED"));
    }
    #[derive(Debug)]
    struct BlockedBiometric {inner:Box<dyn BiometricProvider+Send>,entered:Arc<std::sync::atomic::AtomicBool>,resume:std::sync::mpsc::Receiver<()>}
    impl BiometricProvider for BlockedBiometric {fn evaluate(&mut self,prompt:&BiometricPrompt)->BiometricOutcome {
        self.entered.store(true,std::sync::atomic::Ordering::SeqCst);
        if self.resume.recv_timeout(std::time::Duration::from_secs(3)).is_err(){return BiometricOutcome::TimedOut;}
        self.inner.evaluate(prompt)
    }}
    fn synthetic_intent_draft(profile: Profile) -> enclave_core::intent_draft::IntentDraftV1 {
        enclave_core::intent_draft::IntentDraftV1 {
            action_class: ActionClass::A3, profile, data_class: enclave_core::label::Conf::C3,
            tool_name: "detokenize_row".into(), target_namespace: "dev-billing".into(),
            canonical_verb: "Reveal".into(), row_count_bound: 1,
            arguments_jcs_sha256: "ab".repeat(32), canonical_arguments_blake3: "cd".repeat(32),
            policy_blake3: "ef".repeat(32), qif_millibits_delta: 0, org_root_mutation: false,
        }
    }

    #[test]
    fn yk03_tamper_during_blocked_prompt_never_returns_old_action_authority() {
        let profile = Profile::L3;
        let service = VaultService::start(VaultConfig { profile, ..VaultConfig::default() },
            VaultHardware::simulated(profile, enclave_crypto::time::now_unix()).unwrap()).unwrap();
        let entered = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (resume, rx) = std::sync::mpsc::sync_channel(1);
        { let mut ceremony = service.lock_ceremony().unwrap();
          let inner = std::mem::replace(&mut ceremony.hw.biometric, Box::new(SimulatedTouchId::new()));
          ceremony.hw.biometric = Box::new(BlockedBiometric { inner, entered: entered.clone(), resume: rx }); }
        let pending = service.clone();
        let peer = PeerCredentials::local(enclave_core::ipc::geteuid(), 0);
        let worker_peer = peer.clone();
        let worker = std::thread::spawn(move || pending.handle(&worker_peer,
            VaultRequest::AuthorizeIntent(synthetic_intent_draft(profile))));
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        while !entered.load(std::sync::atomic::Ordering::SeqCst) && std::time::Instant::now() < deadline {
            std::thread::yield_now();
        }
        assert!(entered.load(std::sync::atomic::Ordering::SeqCst));
        assert!(matches!(service.handle(&peer, VaultRequest::Tamper(TamperEvent::UsbYank { docked: true })).unwrap(), VaultResponse::Zeroized(_)));
        assert_eq!(service.lock_state().unwrap().lifecycle.state(), crate::lifecycle::CustodyState::SterileLocked);
        resume.send(()).unwrap();
        assert!(worker.join().unwrap().unwrap_err().is("CUSTODY_AUTHORIZATION_REVOKED"));
        // A complete new ceremony can unlock the sterile state; the cancelled
        // generation's result above remains denied permanently.
        resume.send(()).unwrap();
        assert!(matches!(service.handle(&peer, VaultRequest::AuthorizeIntent(synthetic_intent_draft(profile))).unwrap(), VaultResponse::IntentAuthorizedV2(_)));
    }

    #[test]
    fn yk03_saturated_generation_cannot_revive_after_failed_revoke_or_fresh_factors() {
        let profile=Profile::L3;
        let service=VaultService::start(VaultConfig{profile,..VaultConfig::default()},VaultHardware::simulated(profile,enclave_crypto::time::now_unix()).unwrap()).unwrap();
        service.cas_key_generation.store(u64::MAX,std::sync::atomic::Ordering::SeqCst);
        service.cas_enrolled_generation.store(u64::MAX,std::sync::atomic::Ordering::SeqCst);
        assert!(service.revoke_cas_keys().unwrap_err().is("CAS_KEY_GENERATION"));
        assert!(!service.cas_keys_enabled.load(std::sync::atomic::Ordering::SeqCst));
        assert!(service.prepare_fresh_authorization(u64::MAX).unwrap_err().is("CUSTODY_GENERATION_EXHAUSTED"));
        assert!(service.finish_fresh_authorization(u64::MAX,profile,ActionClass::A3).unwrap_err().is("CUSTODY_GENERATION_EXHAUSTED"));
        assert!(service.attach_lifecycle_release(u64::MAX,None,None,None).unwrap_err().is("CUSTODY_GENERATION_EXHAUSTED"));
        // Even an erroneous enabled write cannot make saturation authoritative.
        service.cas_keys_enabled.store(true,std::sync::atomic::Ordering::SeqCst);
        assert!(!service.cas_keys_authorized());
    }

    #[test]
    fn yk03_l3_ingress_after_fence_requires_fresh_authorization_and_keeps_old_data() {
        let profile=Profile::L3;
        let service=VaultService::start(VaultConfig{profile,..VaultConfig::default()},VaultHardware::simulated(profile,enclave_crypto::time::now_unix()).unwrap()).unwrap();
        let peer=PeerCredentials::local(enclave_core::ipc::geteuid(),0);
        let ingest=||service.handle(&peer,VaultRequest::Tokenize{items:vec![TokenizeItem{value:"jane@example.com".into(),declared:Some(PiiKind::Email)}],bulk_set:false,grant:None});
        ingest().unwrap();
        let retained=service.lock_state().unwrap().vault.stored_len();
        service.handle(&peer,VaultRequest::Tamper(TamperEvent::UsbYank{docked:false})).unwrap();
        assert_eq!(service.lock_state().unwrap().vault.stored_len(),retained);
        assert!(ingest().unwrap_err().is("CUSTODY_AUTHORIZATION_REVOKED"));
        service.handle(&peer,VaultRequest::AuthorizeIntent(synthetic_intent_draft(profile))).unwrap();
        ingest().unwrap();
        assert_eq!(service.lock_state().unwrap().vault.stored_len(),retained+1);
    }

    #[test]
    fn yk03_authorized_positive_still_completes_before_cancellation() {
        let profile = Profile::L3;
        let service = VaultService::start(VaultConfig { profile, ..VaultConfig::default() },
            VaultHardware::simulated(profile, enclave_crypto::time::now_unix()).unwrap()).unwrap();
        let peer = PeerCredentials::local(enclave_core::ipc::geteuid(), 0);
        assert!(matches!(service.handle(&peer, VaultRequest::AuthorizeIntent(synthetic_intent_draft(profile))).unwrap(), VaultResponse::IntentAuthorizedV2(_)));
    }

    #[test]
    fn f38_tamper_during_actual_enrollment_cannot_reenable_namespace_keys() {
        let service=VaultService::start(VaultConfig{profile:Profile::L3,..VaultConfig::default()},VaultHardware::simulated(Profile::L3,enclave_crypto::time::now_unix()).unwrap()).unwrap();
        let entered=Arc::new(std::sync::atomic::AtomicBool::new(false));let (resume,rx)=std::sync::mpsc::sync_channel(1);
        {let mut ceremony=service.lock_ceremony().unwrap();let inner=std::mem::replace(&mut ceremony.hw.biometric,Box::new(SimulatedTouchId::new()));ceremony.hw.biometric=Box::new(BlockedBiometric{inner,entered:entered.clone(),resume:rx});}
        let pending=service.clone();let operator=PeerCredentials::local(enclave_core::ipc::geteuid(),0);let peer=operator.clone();let worker=std::thread::spawn(move||pending.handle(&peer,VaultRequest::Enroll));
        let deadline=std::time::Instant::now()+std::time::Duration::from_secs(2);while !entered.load(std::sync::atomic::Ordering::SeqCst)&&std::time::Instant::now()<deadline{std::thread::yield_now();}assert!(entered.load(std::sync::atomic::Ordering::SeqCst));
        assert!(matches!(service.handle(&operator,VaultRequest::Tamper(TamperEvent::ScreenLock)).unwrap(),VaultResponse::Zeroized(_)));resume.send(()).unwrap();assert!(worker.join().unwrap().unwrap_err().is("CAS_ENROLLMENT_REVOKED"));assert!(!service.cas_keys_authorized());
    }

    #[derive(Debug)]
    struct SecondAssertionRefuses {inner:Box<dyn HidDevice+Send>,requests:usize}
    impl HidDevice for SecondAssertionRefuses {
        fn write_report(&mut self,report:&[u8;crate::ctap::hid::REPORT])->EnclaveResult<()> {
            if report[4]==(crate::ctap::hid::CMD_CBOR|0x80)&&report[7]==crate::ctap::cmd::GET_ASSERTION {
                self.requests+=1;if self.requests==2{fail!(EIO,"FIXTURE_SECOND_ASSERTION_REFUSED");}
            }self.inner.write_report(report)
        }
        fn read_report(&mut self)->EnclaveResult<[u8;crate::ctap::hid::REPORT]>{self.inner.read_report()}
        fn hub_depth(&self)->u8{self.inner.hub_depth()}
        fn virtual_authenticator(&mut self) -> Option<&mut VirtualAuthenticator> { self.inner.virtual_authenticator() }
    }
    #[test]
    fn f38_actual_enrollment_and_failed_second_prf_persist_consumed_signcounts() {
        use std::os::unix::fs::DirBuilderExt;
        use enclave_core::sealed::{SealedStore,Loaded};
        for fail_second in [false,true] {
            let directory=std::env::temp_dir().canonicalize().unwrap().join(format!("mc-enroll-counter-{:x}",enclave_core::rng::u64()));std::fs::DirBuilder::new().mode(0o700).create(&directory).unwrap();
            let service=VaultService::start(VaultConfig{profile:Profile::L3,..VaultConfig::default()},VaultHardware::simulated(Profile::L3,enclave_crypto::time::now_unix()).unwrap()).unwrap();
            let before={let mut ceremony=service.lock_ceremony().unwrap();ceremony.counter_store=Some(SealedStore::open_bounded(&directory,"counter",4096).unwrap().0);if fail_second{let inner=ceremony.hw.yubikey.take().unwrap();ceremony.hw.yubikey=Some(Box::new(SecondAssertionRefuses{inner,requests:0}));}ceremony.counters.clone()};
            let result=service.handle(&PeerCredentials::local(enclave_core::ipc::geteuid(),0),VaultRequest::Enroll);
            if fail_second {assert!(result.unwrap_err().is("FIXTURE_SECOND_ASSERTION_REFUSED"));assert!(!service.cas_keys_authorized());}else{assert!(matches!(result.unwrap(),VaultResponse::Enrolled{..}));assert!(service.cas_keys_authorized());}
            let current=service.lock_ceremony().unwrap().counters.clone();assert_ne!(current,before);
            let (_,loaded)=SealedStore::open_bounded(&directory,"counter",4096).unwrap();let Loaded::State(bytes)=loaded else{panic!("counter not persisted")};assert_eq!(enclave_core::sealed::decode::<SignCountStore>(&bytes).unwrap(),current);
            std::fs::remove_dir_all(directory).unwrap();
        }
        // Actual startup, before a service exists, must preserve the same
        // consumed first assertion when its second morning PRF fails.
        let directory=std::env::temp_dir().canonicalize().unwrap().join(format!("mc-boot-counter-{:x}",enclave_core::rng::u64()));std::fs::DirBuilder::new().mode(0o700).create(&directory).unwrap();
        let mut hardware=VaultHardware::simulated(Profile::L3,enclave_crypto::time::now_unix()).unwrap();let credential=hardware.credential.as_ref().unwrap().credential_id.clone();let inner=hardware.yubikey.take().unwrap();hardware.yubikey=Some(Box::new(SecondAssertionRefuses{inner,requests:0}));
        assert!(VaultService::start(VaultConfig{profile:Profile::L3,state_dir:Some(directory.clone()),..VaultConfig::default()},hardware).unwrap_err().is("FIXTURE_SECOND_ASSERTION_REFUSED"));
        let (_,loaded)=SealedStore::open(&directory,"signcount").unwrap();let Loaded::State(bytes)=loaded else{panic!("startup counter not persisted")};assert!(enclave_core::sealed::decode::<SignCountStore>(&bytes).unwrap().get(&credential)>0);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn f38_keyring_commit_rechecks_revocation_and_persistence_failure_revokes_all_service_leases() {
        use std::os::unix::fs::DirBuilderExt;
        let service=VaultService::start(VaultConfig{profile:Profile::L3,..VaultConfig::default()},VaultHardware::simulated(Profile::L3,enclave_crypto::time::now_unix()).unwrap()).unwrap();let operator=PeerCredentials::local(enclave_core::ipc::geteuid(),0);
        let wrapped=match service.handle(&operator,VaultRequest::WrapCasKey{namespace:"models".into(),epoch:1,wrapping_epoch:1,key:SecretMaterial(vec![7;32])}).unwrap(){VaultResponse::WrappedCasKey(key)=>key,_=>panic!("wrong response")};
        let lease=match service.handle(&operator,VaultRequest::UnwrapCasKey{wrapped:wrapped.clone()}).unwrap(){VaultResponse::CasKey{lease,..}=>lease,_=>panic!("wrong response")};
        let directory=std::env::temp_dir().canonicalize().unwrap().join(format!("mc-keyring-service-{:x}",enclave_core::rng::u64()));std::fs::DirBuilder::new().mode(0o700).create(&directory).unwrap();
        let mut ring=crate::cas_keyring::CasKeyring::open(Some(&directory)).unwrap();ring.register(wrapped.clone(),false).unwrap();service.lock_state().unwrap().cas_keyring=ring;
        let checkpoint=directory.join("cas-namespace-keyring/cas-namespace-keyring.gen");std::fs::remove_file(&checkpoint).unwrap();std::fs::create_dir(&checkpoint).unwrap();
        assert!(service.handle(&operator,VaultRequest::RotateCasKey{wrapped:wrapped.clone(),new_wrapping_epoch:2}).is_err());
        assert!(!service.cas_keys_authorized());assert!(service.handle(&operator,VaultRequest::CheckCasKeyLease(lease.clone())).unwrap_err().is("CAS_KEY_LEASE_REVOKED"));
        assert!(service.register_cas_key(&operator,&[&lease],wrapped,false,None,&SecretKey32::new([0;32])).unwrap_err().is("CAS_KEY_LEASE_REVOKED"));
        std::fs::remove_dir_all(directory).unwrap();
        // Actual Tamper after hardware custody but before registration must
        // also fail at the final commit boundary, preserving the old keyring.
        let service=VaultService::start(VaultConfig{profile:Profile::L3,..VaultConfig::default()},VaultHardware::simulated(Profile::L3,enclave_crypto::time::now_unix()).unwrap()).unwrap();
        let shape=enclave_crypto::namespace::WrappedNamespaceKey{namespace:"models".into(),epoch:1,wrapping_epoch:1,envelope_hex:"00".repeat(72)};
        let (kek,lease)=service.cas_key_custody(&operator,&shape).unwrap();let wrapped=enclave_crypto::namespace::wrap("models",1,1,&[7;32],&kek).unwrap();
        service.handle(&operator,VaultRequest::Tamper(TamperEvent::ScreenLock)).unwrap();
        assert!(service.register_cas_key(&operator,&[&lease],wrapped.clone(),false,None,&kek).unwrap_err().is("CAS_KEY_LEASE_REVOKED"));
        assert!(service.lock_state().unwrap().cas_keyring.verify(&wrapped).unwrap_err().is("CAS_KEY_NOT_REGISTERED"));
    }

    #[test]
    fn f38_actual_custody_keyring_rewrap_offboarding_and_opaque_migration_preserve_historical_ciphertext() {
        use enclave_crypto::namespace;
        let service=VaultService::start(VaultConfig{profile:Profile::L3,..VaultConfig::default()},VaultHardware::simulated(Profile::L3,enclave_crypto::time::now_unix()).unwrap()).unwrap();let operator=PeerCredentials::local(enclave_core::ipc::geteuid(),0);
        let wrap=|epoch,key|match service.handle(&operator,VaultRequest::WrapCasKey{namespace:"models".into(),epoch,wrapping_epoch:1,key:SecretMaterial(vec![key;32])}).unwrap(){VaultResponse::WrappedCasKey(key)=>key,_=>panic!("wrong response")};
        let first=wrap(1,7);let second=wrap(2,8);let original_lease=match service.handle(&operator,VaultRequest::UnwrapCasKey{wrapped:first.clone()}).unwrap(){VaultResponse::CasKey{lease,..}=>lease,_=>panic!("wrong response")};
        let plaintext=b"unchanged historical artifact";let root=*blake3::hash(plaintext).as_bytes();let (ciphertext,record)=namespace::encrypt_chunk(&SecretKey32::new([7;32]),&root,0,true,plaintext).unwrap();
        let rotate=|wrapped|match service.handle(&operator,VaultRequest::RotateCasKey{wrapped,new_wrapping_epoch:2}).unwrap(){VaultResponse::WrappedCasKey(key)=>key,_=>panic!("wrong response")};let rotated=rotate(first.clone());
        assert!(service.handle(&operator,VaultRequest::CheckCasKeyLease(original_lease)).is_err());assert!(service.handle(&operator,VaultRequest::UnwrapCasKey{wrapped:first}).is_err());
        assert!(service.handle(&operator,VaultRequest::AdvanceCasWrappingFloor{namespace:"models".into(),minimum_wrapping_epoch:2}).unwrap_err().is("CAS_KEYRING_REWRAP_REQUIRED"));rotate(second);
        service.handle(&operator,VaultRequest::AdvanceCasWrappingFloor{namespace:"models".into(),minimum_wrapping_epoch:2}).unwrap();
        let released=match service.handle(&operator,VaultRequest::UnwrapCasKey{wrapped:rotated}).unwrap(){VaultResponse::CasKey{key,..}=>SecretKey32::new(key.0.as_slice().try_into().unwrap()),_=>panic!("wrong response")};assert_eq!(&*namespace::decrypt_chunk(&released,&root,0,true,&ciphertext,&record).unwrap(),plaintext);
        assert!(service.handle(&operator,VaultRequest::AdvanceCasWrappingFloor{namespace:"models".into(),minimum_wrapping_epoch:1}).is_err());
        // Explicit migration authenticates an existing external opaque envelope
        // through the same hardware orchestration without exposing its DEK.
        let shape=namespace::WrappedNamespaceKey{namespace:"models".into(),epoch:3,wrapping_epoch:2,envelope_hex:"00".repeat(72)};let (kek,_)=service.cas_key_custody(&operator,&shape).unwrap();let imported=namespace::wrap("models",3,2,&[9;32],&kek).unwrap();service.handle(&operator,VaultRequest::ImportCasKey{wrapped:imported.clone()}).unwrap();assert!(matches!(service.handle(&operator,VaultRequest::UnwrapCasKey{wrapped:imported}).unwrap(),VaultResponse::CasKey{..}));
    }

}

#[cfg(test)]
mod envelope_lifecycle_tests {
    use super::*;
    use enclave_core::ipc;
    use enclave_crypto::hpke_envelope::{EnvelopePolicy, SignedEnvelopePolicy, VerifiedEnvelopeContext};
    use std::{os::unix::{fs::{DirBuilderExt, PermissionsExt}, net::UnixListener}, sync::atomic::{AtomicBool, Ordering}};
    use crate::ctap::asset_enrollment::{AssetEnrollmentPolicy, AssetEnrollmentReceipt, SignedAssetEnrollmentPolicy};

    struct Fixture {
        root: PathBuf, socket_dir: PathBuf, authority: crate::metadata_source::EnvelopeAuthorityConfig,
        context: VerifiedEnvelopeContext, stop: Arc<AtomicBool>, worker: Option<std::thread::JoinHandle<()>>,
        asset_authority: AssetEnrollmentAuthority,
    }
    impl Fixture {
        fn new() -> Self {
            let root=std::env::temp_dir().canonicalize().unwrap().join(format!("yk-envelope-{:x}",enclave_core::rng::u64()));
            std::fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
            let socket_dir=root.join("mesh");std::fs::DirBuilder::new().mode(0o700).create(&socket_dir).unwrap();
            let issuer=SigningKey::from_bytes(&[46;32]);
            let authority=crate::metadata_source::EnvelopeAuthorityConfig{issuer:issuer.verifying_key(),subject:"fixture-asset".into(),namespace:"fixture-data".into()};
            let now=enclave_crypto::time::now_unix();
            let policy=EnvelopePolicy{version:1,revision:1,subject:authority.subject.clone(),namespace:authority.namespace.clone(),issued_unix:now-1,expires_unix:now+3600,review_unix:now+3600,owner:"software-test".into(),profiles:vec![Profile::L2],data_classes:vec!["C3".into(),"C4".into()],purpose:"synthetic restore".into(),migration:"reviewed successor".into(),disclosure:None,classical_exception:false};
            let signature=issuer.sign(&policy.signing_message().unwrap()).to_bytes().to_vec();
            let signed=SignedEnvelopePolicy{policy,signature};
            let context=signed.verify(&authority.issuer,&authority.subject,&authority.namespace,now).unwrap();
            let policy_bytes=serde_json::to_vec(&signed).unwrap();
            let asset_issuer=SigningKey::from_bytes(&[47;32]);
            let inventory=SigningKey::from_bytes(&[48;32]);
            let asset_policy=AssetEnrollmentPolicy {version:1,revision:1,host_id:"fixture-asset".into(),
                asset_id:"fixture-key".into(),custodian_id:"fixture-user".into(),aaguid:[0xee;16],
                mode:crate::ctap::asset_enrollment::AttestationMode::BasicWithIndependentAsset,
                enterprise_leaf_sha256:None,rationale:"independent synthetic inventory".into(),issued_unix:now-1,expires_unix:now+3600};
            let signature=asset_issuer.sign(&asset_policy.signing_message().unwrap()).to_bytes().to_vec();
            let policy_file=root.join("asset-policy.json");
            std::fs::write(&policy_file,serde_json::to_vec(&SignedAssetEnrollmentPolicy {policy:asset_policy,signature}).unwrap()).unwrap();
            std::fs::set_permissions(&policy_file,std::fs::Permissions::from_mode(0o644)).unwrap();
            let asset_authority=AssetEnrollmentAuthority {policy_issuer:asset_issuer.verifying_key(),inventory_issuer:inventory.verifying_key(),
                policy_file,host:"fixture-asset".into(),asset:"fixture-key".into(),custodian:"fixture-user".into()};
            let path=socket_dir.join(DaemonId::SwarmSync.socket_name());
            enclave_core::fsutil::private_dir(path.parent().unwrap()).unwrap();
            let listener=UnixListener::bind(path).unwrap();listener.set_nonblocking(true).unwrap();
            let stop=Arc::new(AtomicBool::new(false));let stopping=stop.clone();
            let worker=std::thread::spawn(move||{
                use enclave_core::custody_metadata::{CustodyTarget,CustodyTargetReceipt};
                #[derive(Deserialize)] enum Request{FetchCustodyTarget{target:CustodyTarget}}
                #[derive(Serialize)] enum Response{CustodyTarget(CustodyTargetReceipt)}
                while !stopping.load(Ordering::SeqCst) {
                    match listener.accept() {
                        Ok((mut stream,_))=>{
                            stream.set_read_timeout(Some(std::time::Duration::from_secs(2))).unwrap();
                            let request=ipc::read_frame(&mut stream).unwrap();
                            let Request::FetchCustodyTarget{target}=ipc::from_cbor(&request).unwrap();
                            assert_eq!(target,CustodyTarget::EnvelopePolicy);
                            let receipt=CustodyTargetReceipt {v:1,effective_profile:Profile::L2,target:target.target_name().into(),bytes:policy_bytes.clone().into(),
                                refreshed_at:now,expires_at:now+3600,verified_now:enclave_crypto::time::now_unix(),versions:(1,1,1),blake3:blake3::hash(&policy_bytes).to_hex().to_string()};
                            ipc::write_frame(&mut stream,&ipc::to_cbor(&ipc::Reply::Ok(Response::CustodyTarget(receipt))).unwrap()).unwrap();
                        },
                        Err(error) if error.kind()==std::io::ErrorKind::WouldBlock=>std::thread::sleep(std::time::Duration::from_millis(2)),
                        Err(error)=>panic!("fixture listener failed: {error}"),
                    }
                }
            });
            Self{root,socket_dir,authority,context,stop,worker:Some(worker),asset_authority}
        }
        fn provision_checkpoint(&self) {
            // Exercise current independent asset admission before restoring a
            // native-shaped L2 fixture. Bare software credentials no longer
            // bypass the production asset guard added after these tests.
            let hw=VaultHardware::simulated(Profile::L2,enclave_crypto::time::now_unix()).unwrap();
            let service=VaultService::start(VaultConfig {profile:Profile::L2,state_dir:Some(self.root.clone()),..Default::default()},hw).unwrap();
            {
                let mut c=service.lock_ceremony().unwrap();c.hw.credential=None;
                c.hw.asset_enrollment_authority=Some(self.asset_authority.clone());
                c.hw.metadata_source=Some(crate::metadata_source::CustodyMetadataSource::new(self.socket_dir.clone(),true));
                c.hw.envelope_authority=Some(self.authority.clone());
            }
            service.lock_state().unwrap().vault=CustodyVault::unenrolled(Profile::L2,None);
            let peer=PeerCredentials::local(enclave_core::ipc::geteuid(),0);
            let pending=match service.begin_asset(&peer).unwrap() {VaultResponse::AssetEnrollmentPending {pending}=>pending,_=>panic!("pending required")};
            let now=enclave_crypto::time::now_unix();
            let mut receipt=AssetEnrollmentReceipt {version:1,pending_sha256:pending.digest().unwrap(),generation:1,issued_unix:now,expires_unix:now+120,signature:vec![]};
            receipt.signature=SigningKey::from_bytes(&[48;32]).sign(&receipt.signing_message().unwrap()).to_bytes().to_vec();
            service.activate_asset(&peer,receipt).unwrap();
            assert_eq!(service.lock_state().unwrap().envelope_policy_digest,Some(self.context.digest()));
            service.shutdown().unwrap();
        }
        fn start(&self)->EnclaveResult<Arc<VaultService>> {
            // Explicit same-UID CAS and software-created SEP/credential only;
            // native service restore branch executes with no authenticator.
            let mut hardware=VaultHardware::simulated(Profile::L2,enclave_crypto::time::now_unix()).unwrap();
            hardware.simulated=false;hardware.yubikey=None;hardware.mds=None;
            let (enrolled,binding)=load_native_enrollment(&self.root,Some(&self.asset_authority),Profile::L2,enclave_crypto::time::now_unix())?
                .ok_or_else(||err!(EACCES,"ASSET_ACTIVE_REQUIRED"))?;
            hardware.credential=Some(enrolled.credential);
            hardware.sep_bio_key=p256::ecdsa::VerifyingKey::from_sec1_bytes(&enrolled.bio_public_key).map_err(|_|err!(EACCES,"FIXTURE_BIO_KEY"))?;
            hardware.sep_bio_blob=Some(enrolled.bio_key_blob);
            hardware.asset_enrollment_authority=Some(self.asset_authority.clone());hardware.asset_activation_binding=Some(binding);
            hardware.metadata_source=Some(crate::metadata_source::CustodyMetadataSource::new(self.socket_dir.clone(),true));
            hardware.envelope_authority=Some(self.authority.clone());
            VaultService::start(VaultConfig{profile:Profile::L2,state_dir:Some(self.root.clone()),..VaultConfig::default()},hardware)
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self){self.stop.store(true,Ordering::SeqCst);if let Some(worker)=self.worker.take(){worker.join().unwrap();}let _=std::fs::remove_dir_all(&self.root);}
    }
    fn ingest(service:&VaultService,value:&str)->EnclaveResult<VaultResponse> {
        service.handle(&PeerCredentials::local(enclave_core::ipc::geteuid(),0),VaultRequest::Tokenize{items:vec![TokenizeItem{value:value.into(),declared:Some(PiiKind::Email)}],bulk_set:false,grant:None})
    }
    #[test]
    fn yk_envelope_actual_service_no_key_l2_ingests_and_preserves_ciphertext_on_yank_shutdown_restart() {
        let fixture=Fixture::new();fixture.provision_checkpoint();
        let service=fixture.start().unwrap();
        ingest(&service,"jane@example.com").unwrap();
        let before=serde_json::to_vec(&service.lock_state().unwrap().vault.checkpoint().unwrap()).unwrap();
        let peer=PeerCredentials::local(enclave_core::ipc::geteuid(),0);
        service.handle(&peer,VaultRequest::Tamper(TamperEvent::UsbYank{docked:false})).unwrap();
        assert_eq!(before,serde_json::to_vec(&service.lock_state().unwrap().vault.checkpoint().unwrap()).unwrap());
        service.shutdown().unwrap();drop(service);
        let restored=fixture.start().unwrap();
        assert_eq!(before,serde_json::to_vec(&restored.lock_state().unwrap().vault.checkpoint().unwrap()).unwrap());
        assert!(restored.lock_ceremony().unwrap().hw.yubikey.is_none());
        ingest(&restored,"john@example.com").unwrap();
        assert_eq!(restored.lock_state().unwrap().vault.stored_len(),2);
        restored.shutdown().unwrap();
    }
    #[test]
    fn yk_envelope_actual_service_save_failure_poison_denies_success_and_later_ingest() {
        let fixture=Fixture::new();fixture.provision_checkpoint();let service=fixture.start().unwrap();
        let path=fixture.root.join("vault-envelopes/envelopes.sealed");
        std::fs::remove_file(&path).unwrap();std::fs::create_dir(&path).unwrap();
        assert!(ingest(&service,"jane@example.com").is_err());
        std::fs::remove_dir(&path).unwrap();
        assert!(ingest(&service,"john@example.com").unwrap_err().is("VAULT_ENVELOPE_STATE_UNCERTAIN"));
        assert!(service.lock_state().unwrap().envelope_fault);
        assert!(service.lock_state().unwrap().witness.is_empty());
    }
    #[test]
    fn yk_envelope_existing_native_credential_without_checkpoint_refuses_before_prf() {
        let fixture=Fixture::new();fixture.provision_checkpoint();
        let checkpoint=fixture.root.join("vault-envelopes/envelopes.sealed");
        std::fs::remove_file(&checkpoint).unwrap();
        assert!(load_native_enrollment(&fixture.root,Some(&fixture.asset_authority),Profile::L2,enclave_crypto::time::now_unix())
            .unwrap().is_some(),"the independently admitted credential remains valid");
        // The surviving authenticated generation refuses deleted envelope
        // state before migration fallback or any boot-time authenticator PRF.
        let error=fixture.start().unwrap_err();
        assert!(error.is("STATE_MISSING"),"{error:?}");
        assert!(!checkpoint.exists(),"refused startup must not bootstrap replacement envelope state");
    }
}

#[cfg(test)]
mod simulation_receipt_tests {
    use super::*;
    use enclave_core::audit::{verify_journal, EnclaveAuditEnvelopeV1};
    use std::os::unix::fs::PermissionsExt;

    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!("mc-sim-receipts-{:x}", enclave_core::rng::u64()));
            std::fs::create_dir(&path).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
            Self(path)
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.0); }
    }

    #[test]
    fn f38_software_custody_receipts_are_marked_through_actual_service_and_journal() {
        // Explicit software providers only. These are actual service dispatch,
        // response and chained-receipt paths, never hardware acceptance.
        for profile in [Profile::L1, Profile::L2, Profile::L3] {
            let fixture = Fixture::new();
            let journal = fixture.0.join("custody-audit.jsonl");
            let service = VaultService::start(
                VaultConfig { profile, audit_path: Some(journal.clone()), ..VaultConfig::default() },
                VaultHardware::simulated(profile, enclave_crypto::time::now_unix()).unwrap(),
            ).unwrap();
            let peer = PeerCredentials::local(enclave_core::ipc::geteuid(), 0);
            let (epoch, issued) = match service.handle(&peer, VaultRequest::AllocateSlot).unwrap() {
                VaultResponse::Slot { boot_epoch_id, rpc_seq_u64 } => (boot_epoch_id, rpc_seq_u64),
                response => panic!("expected actual slot response: {response:?}"),
            };
            let status = match service.handle(&peer, VaultRequest::Status).unwrap() {
                VaultResponse::Status(status) => status,
                response => panic!("expected actual status response: {response:?}"),
            };
            assert!(status.state.contains("simulated_hw=true"));
            let before_rejection = std::fs::read(&journal).unwrap();
            assert!(service.handle(&PeerCredentials::local(DaemonId::SwarmSync.uid(), 0), VaultRequest::AllocateSlot).unwrap_err().is("CAS_VAULT_RPC_FORBIDDEN"));
            assert_eq!(std::fs::read(&journal).unwrap(), before_rejection, "a forbidden call must not fabricate a successful custody receipt");
            // A synthetic event invokes only the software service wipe; no host
            // screen lock, sleep, USB notification or physical device is used.
            assert!(matches!(service.handle(&peer, VaultRequest::Tamper(TamperEvent::ScreenLock)).unwrap(), VaultResponse::Zeroized(_)));
            service.shutdown().unwrap();
            drop(service);

            let summary = verify_journal(&journal, None).unwrap();
            let receipts: Vec<EnclaveAuditEnvelopeV1> = std::fs::read_to_string(&journal).unwrap().lines()
                .map(|line| serde_json::from_str(line).unwrap()).collect();
            assert_eq!(summary.entries as usize, receipts.len());
            assert!(receipts.len() >= 3, "boot, issued slot and wipe must emit real receipts");
            for receipt in &receipts {
                assert_eq!(receipt.daemon_uid, DaemonId::CustodyVault.uid());
                assert_eq!(receipt.boot_epoch_id, epoch);
                assert_eq!(receipt.payload.get("simulated_hw"), Some(&serde_json::Value::Bool(true)), "{profile}: every emitted software receipt must remain marked: {receipt:?}");
            }
            assert!(receipts.iter().any(|receipt| receipt.payload["event"] == "EPOCH_CHECKPOINT"));
            assert!(receipts.iter().any(|receipt| receipt.payload["event"] == "SLOT_ISSUED" && receipt.rpc_seq_u64 == issued));
            assert!(receipts.iter().any(|receipt| receipt.payload["event"] == "ZEROIZE"));
        }
    }
}

#[cfg(test)]
#[path="producer_retention_tests.rs"]
mod producer_retention_tests;

mod asset_workflow;
mod selected_owner_dependency;
pub(crate) use selected_owner_dependency::SelectedOwnerFailure;
pub use asset_workflow::{MembershipAuthorityOwner,MembershipWorkflowAnchor,MembershipAnchorPin,MembershipAnchorObservation,MembershipAuthorityConfig,ValidatedMemberLossSetup,MemberLossSurvivor,AssetEnrollmentAuthority,load_native_enrollment,load_native_membership,ValidatedNativeMembership,load_native_membership_setup,ValidatedMembershipSetup,read_asset_authority_file};

#[path="service/namespace_workflow.rs"]
mod namespace_workflow;

#[path="service/travel_workflow.rs"]
mod travel_workflow;
pub use travel_workflow::{TravelAnchorPin,TravelAnchorObservation,TravelRecoveryAnchor,TravelAuthorityConfig,
    ValidatedTravelStartup,load_travel_startup};

#[cfg(test)]
mod display_frame_tests {
    use super::*;

    /// The helper (SecureDisplayProtocol.strings) accepts exactly a CBOR array
    /// of byte strings; anything else is refused and nothing is shown.
    #[test]
    fn display_frame_is_an_array_of_cbor_byte_strings() {
        let values = [SecretBytes::from_slice(b"{\"priority\":\"urgent\"}"), SecretBytes::from_slice(b"ok")];
        let frame = encode_display(&values).unwrap();
        let mut expected = vec![0x82, 0x40 | 21];
        expected.extend_from_slice(b"{\"priority\":\"urgent\"}");
        expected.extend_from_slice(&[0x42, b'o', b'k']);
        assert_eq!(frame.as_slice(), expected.as_slice());
    }
}
