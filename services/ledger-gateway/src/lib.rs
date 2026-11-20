//! OHTTP gateway and compliance ledger verification service (GAP-26, FS-702 §4.3.2, FS-705 §4.2.2).
//!
//! Receives encapsulated OHTTP POST requests, decapsulates using the gateway private key,
//! parses the BHTTP request, and verifies the enclosed `ComplianceRollupProofV1` frame
//! against the current TUF `vk_manifest.json`.

#![deny(missing_docs)]

mod http;
pub mod key_store;
pub mod ledger;

use std::sync::{Arc, Mutex};

use enclave_core::error::EnclaveResult;
use enclave_core::{err, fail};
use enclave_crypto::ohttp::{
    bhttp_parse, bhttp_post, decapsulate, encapsulate, gateway_keypair, KeyConfig,
};
use enclave_zk_auditor::rollup::ComplianceRollupProofV1;
use enclave_zk_auditor::receiver_trust::ReceiverTrust;
use enclave_zk_auditor::zk::manifest::VkManifestV1;
use serde::{Deserialize, Serialize};

pub use ledger::{check_link, Admission, Ledger, VerifiedFrameSummary, DEFAULT_MAX_FRAMES};

/// Standard authority and path for compliance ledger rollups.
pub use enclave_zk_auditor::rollup::LEDGER_AUTHORITY;
/// Standard path for compliance ledger rollups.
pub use enclave_zk_auditor::rollup::LEDGER_PATH;

/// Ledger gateway response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerResponse {
    /// Whether the frame was newly recorded.
    pub accepted: bool,
    /// The frame is byte-identical to one already recorded; nothing was
    /// recorded (DEFECT-F-92). Answered with 200 so an honest retry after a
    /// lost acknowledgement leaves the host's outbox.
    #[serde(default)]
    pub duplicate: bool,
    /// Number of slots in the accepted frame.
    pub slots: u64,
    /// Profile of the frame.
    pub profile: u8,
    /// Whether this was an L3 heartbeat.
    pub heartbeat: bool,
}

#[derive(Debug)]
enum Verification {Unconfigured,Trusted(ReceiverTrust),AccountingFixture}

/// OHTTP compliance ledger gateway service.
pub struct LedgerGateway {
    key_config: KeyConfig,
    gateway_sk: Vec<u8>,
    manifest: VkManifestV1,
    ledger: Mutex<Ledger>,
    verification: Verification,
}

impl std::fmt::Debug for LedgerGateway {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LedgerGateway")
            .field("key_id", &self.key_config.key_id)
            .field("vk_digest", &self.manifest.vk_digest)
            .finish()
    }
}

impl LedgerGateway {
    /// Create a new ledger gateway with a freshly generated keypair, the given
    /// vk manifest and an in-memory ledger bounded to [`DEFAULT_MAX_FRAMES`].
    /// Starts unconfigured: admission fails until with_receiver_trust is called
    /// (or accounting_fixture is explicitly selected). Restart loses replay/order state.
    /// Durable services must use [`Self::with_ledger`] and [`Ledger::open_state_dir`]
    /// or [`Ledger::open`]. The binary selects a durable ledger by default.
    pub fn new(key_id: u8, manifest: VkManifestV1) -> (Self, KeyConfig) {
        let (key_config, gateway_sk) = gateway_keypair(key_id);
        let gw = Self::with_ledger(
            key_config.clone(),
            gateway_sk,
            manifest,
            Ledger::in_memory(DEFAULT_MAX_FRAMES),
        );
        (gw, key_config)
    }

    /// Create with explicit key configuration and private key (in-memory ledger).
    /// Development/test convenience only; use [`Self::with_ledger`] with a
    /// persistent ledger for a service that must retain replay state on restart.
    pub fn with_keys(key_config: KeyConfig, gateway_sk: Vec<u8>, manifest: VkManifestV1) -> Self {
        Self::with_ledger(
            key_config,
            gateway_sk,
            manifest,
            Ledger::in_memory(DEFAULT_MAX_FRAMES),
        )
    }

    /// Create with explicit keys and ledger (e.g. [`Ledger::open`] for a
    /// persistent journal). Admission remains disabled until receiver trust or
    /// explicit accounting-fixture mode is selected.
    pub fn with_ledger(
        key_config: KeyConfig,
        gateway_sk: Vec<u8>,
        manifest: VkManifestV1,
        ledger: Ledger,
    ) -> Self {
        Self {
            key_config,
            gateway_sk,
            manifest,
            ledger: Mutex::new(ledger),
            verification: Verification::Unconfigured,
        }
    }

    /// Require this independently configured authority for every received frame.
    pub fn with_receiver_trust(mut self,trust:ReceiverTrust)->Self {
        self.verification=Verification::Trusted(trust);self
    }

    /// Explicit accounting-only fixture. This bypasses issuer/cohort authority
    /// and must never be used for production compliance admission.
    pub fn accounting_fixture(mut self)->Self {
        self.verification=Verification::AccountingFixture;self
    }

    /// Create an explicitly named in-memory accounting fixture for tests.
    pub fn new_accounting_fixture(key_id:u8,manifest:VkManifestV1)->(Self,KeyConfig) {
        let (gateway,key)=Self::new(key_id,manifest);(gateway.accounting_fixture(),key)
    }

    /// Key configuration of this gateway.
    pub fn key_config(&self) -> &KeyConfig {
        &self.key_config
    }

    /// Verifier key manifest.
    pub fn manifest(&self) -> &VkManifestV1 {
        &self.manifest
    }

    /// Update the verifier key manifest (e.g. on TUF snapshot refresh).
    pub fn update_manifest(&mut self, manifest: VkManifestV1) {
        self.manifest = manifest;
    }

    /// Returns a copy of all verified frames accepted into the ledger.
    pub fn verified_frames(&self) -> Vec<VerifiedFrameSummary> {
        self.ledger
            .lock()
            .map(|l| l.frames().to_vec())
            .unwrap_or_default()
    }

    /// Handle one encapsulated OHTTP POST request from UID 702.
    ///
    /// Decapsulates the OHTTP payload, verifies that the path is `/v1/rollup`,
    /// decodes the frame, verifies the STARK proof against the TUF vk_manifest,
    /// ensures `vk_digest` matches the pinned manifest digest, and admits the
    /// frame to the ledger: byte-identical replays are reported as duplicates
    /// and not recorded, and the frame must extend its chain (`nullifier_e`)
    /// with no gap, overlap or state break ([`check_link`], DEFECT-F-92).
    pub fn handle_ohttp_post(&self, enc_request: &[u8]) -> EnclaveResult<LedgerResponse> {
        if matches!(&self.verification,Verification::Unconfigured) {fail!(EACCES,"ROLLUP_RECEIVER_TRUST_REQUIRED");}
        // 1. Decapsulate OHTTP layer
        let bhttp_req = decapsulate(self.key_config.key_id, &self.gateway_sk, enc_request)?;

        // 2. Parse BHTTP request
        let (path, frame_bytes) = bhttp_parse(&bhttp_req)?;
        if path != LEDGER_PATH {
            fail!(
                EINVAL,
                "INVALID_LEDGER_PATH",
                "Expected {LEDGER_PATH}, got {path}"
            );
        }

        self.manifest.validate_supported()?;

        let vk_bytes = self
            .manifest
            .vk_digest_bytes()
            .map_err(|e| err!(EINVAL, "MANIFEST_VK_DIGEST", "{e}"))?;

        // 3. Verify rollup frame against pinned TUF vk_manifest
        let frame = match &self.verification {
            Verification::Trusted(trust)=>trust.verify(&frame_bytes,&[vk_bytes]),
            Verification::AccountingFixture=>ComplianceRollupProofV1::verify(&frame_bytes,&[vk_bytes]),
            Verification::Unconfigured=>unreachable!("checked before decapsulation"),
        }.map_err(|e| err!(EACCES, "FRAME_VERIFY_FAILED", "{e}"))?;

        // 4. Assert vk_digest strictly matches current TUF manifest (GAP-26 requirement)
        let frame_vk_digest = &frame.public_inputs.vk_digest;
        if frame_vk_digest != &self.manifest.vk_digest {
            fail!(
                EACCES,
                "UNPINNED_VK_DIGEST",
                "Frame vk_digest ({}) does not match current TUF manifest ({})",
                frame_vk_digest,
                self.manifest.vk_digest
            );
        }

        let frame_digest: [u8; 32] = *blake3::hash(&frame_bytes).as_bytes();
        let slots = frame.s_end - frame.s_start + 1;
        let summary = VerifiedFrameSummary::of(&frame, frame_digest, vk_bytes);
        let heartbeat = summary.heartbeat;
        let admission = self
            .ledger
            .lock()
            .map_err(|_| err!(EIO, "LEDGER_LOCK_POISONED"))?
            .admit(summary)?;

        Ok(LedgerResponse {
            accepted: admission == Admission::Recorded,
            duplicate: admission == Admission::Duplicate,
            slots,
            profile: frame.profile,
            heartbeat,
        })
    }
}

/// Helper to construct and encapsulate an OHTTP rollup request.
pub fn create_ohttp_rollup_request(
    key_config: &KeyConfig,
    frame_bytes: &[u8],
) -> EnclaveResult<Vec<u8>> {
    let req = bhttp_post(
        LEDGER_AUTHORITY,
        LEDGER_PATH,
        "application/cbor",
        frame_bytes,
    );
    encapsulate(key_config, &req)
}

/// Serve TCP with bounded workers, request memory and an absolute read deadline.
pub fn serve_tcp(
    listener: std::net::TcpListener,
    gateway: Arc<LedgerGateway>,
    stop: Arc<std::sync::atomic::AtomicBool>,
) -> EnclaveResult<()> {
    http::serve(listener, gateway, stop)
}
