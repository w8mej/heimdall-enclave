//! Pre-egress redaction proxy for L3 tool outputs (GAP-25, FS-705 §4.3.1 / D-25a).
//!
//! Synchronously gates external sink transmission using pinned signed DFA scan
//! attestations and overlapping windows; this is not a succinct ZK proof claim. Fails closed with
//! `ZK_EGRESS_GATE_UNAVAILABLE` when UID 705 is down or unresponsive beyond 5 seconds.

use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::VerifyingKey;
use enclave_core::codesign::CodeRequirement;
use enclave_core::daemon::DaemonId;
use enclave_core::error::EnclaveResult;
use enclave_core::ipc::Client;
use enclave_core::{err, fail};
use enclave_zk_auditor::service::{ZkRequest, ZkResponse};
use enclave_zk_auditor::zk::lasso_dfa::CARRY_BYTES;
use enclave_zk_auditor::zk::redact::{RedactProofV1, MAX_CHUNK_SIZE};
use serde_bytes::ByteBuf;
use zeroize::Zeroize;

/// Default per-chunk idle timeout (5 seconds, FS-705 §4.3.1 / D-25a).
pub const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(5);

/// Client trait for synchronous pre-egress gating.
pub trait EgressGateClient: Send + Sync {
    /// Request gate approval and pi_redact proof for a chunk under context `d_jcs`.
    fn gate_chunk(&self, d_jcs: &[u8], chunk: &[u8]) -> EnclaveResult<RedactProofV1>;
}

/// Standard IPC client connecting to UID 705 (_enclavezk) over Unix domain socket.
#[derive(Debug, Clone)]
pub struct IpcEgressGateClient {
    socket_path: PathBuf,
    expected_uid: u32,
    zk_pubkey: VerifyingKey,
    timeout: Duration,
    peer_requirement: CodeRequirement,
}

impl IpcEgressGateClient {
    /// Create client targeting UID 705's socket with default 5-second timeout.
    pub fn new(socket_path: impl Into<PathBuf>, zk_pubkey: VerifyingKey) -> Self {
        Self {
            socket_path: socket_path.into(),
            expected_uid: DaemonId::ZkAuditor.uid(),
            zk_pubkey,
            timeout: DEFAULT_IDLE_TIMEOUT,
            peer_requirement: CodeRequirement::daemon(DaemonId::ZkAuditor),
        }
    }

    /// Create client with custom expected UID and timeout.
    pub fn with_options(
        socket_path: impl Into<PathBuf>,
        expected_uid: u32,
        zk_pubkey: VerifyingKey,
        timeout: Duration,
    ) -> Self {
        Self {
            socket_path: socket_path.into(),
            expected_uid,
            zk_pubkey,
            timeout,
            peer_requirement: CodeRequirement::daemon(DaemonId::ZkAuditor),
        }
    }

    /// Connect using an independently provisioned, trusted peer requirement.
    ///
    /// The requirement and proof key must come from operator configuration, never
    /// from a tool request or the peer's response. UID and native code identity
    /// are both checked before any request bytes are sent. Default constructors
    /// continue to require the production auditor identity and installed pins.
    pub fn with_peer_requirement(
        socket_path: impl Into<PathBuf>,
        expected_uid: u32,
        zk_pubkey: VerifyingKey,
        timeout: Duration,
        peer_requirement: CodeRequirement,
    ) -> Self {
        Self {
            socket_path: socket_path.into(),
            expected_uid,
            zk_pubkey,
            timeout,
            peer_requirement,
        }
    }
}

impl EgressGateClient for IpcEgressGateClient {
    fn gate_chunk(&self, d_jcs: &[u8], chunk: &[u8]) -> EnclaveResult<RedactProofV1> {
        let mut client = Client::connect_verified(
            &self.socket_path,
            self.expected_uid,
            Some(&self.peer_requirement),
        )
        .map_err(|e| {
            err!(
                EPERM,
                "ZK_EGRESS_GATE_UNAVAILABLE",
                "Failed to connect to UID 705 at {}: {e}",
                self.socket_path.display()
            )
        })?;

        client.set_timeout(Some(self.timeout))?;

        let mut req = ZkRequest::GateEgress {
            d_jcs: ByteBuf::from(d_jcs.to_vec()),
            chunk: ByteBuf::from(chunk.to_vec()),
        };

        let result = client.call::<_, ZkResponse>(&req);
        // This request owns a separate raw-window copy. Erase it on success,
        // rejection, disconnect and timeout before propagating the outcome.
        if let ZkRequest::GateEgress { chunk, .. } = &mut req { chunk.as_mut().zeroize(); }
        let resp: ZkResponse = result.map_err(|e| {
            if e.is("UNREDACTED_C4_IN_EGRESS") {
                e
            } else {
                err!(
                    EPERM,
                    "ZK_EGRESS_GATE_UNAVAILABLE",
                    "UID 705 call failed or timed out: {e}"
                )
            }
        })?;

        match resp {
            ZkResponse::EgressGated {
                approved,
                chunk_hash,
                d_jcs_hash,
                pi_redact,
            } => {
                if !approved {
                    fail!(
                        EPERM,
                        "ZK_EGRESS_GATE_REJECTED",
                        "UID 705 refused egress approval"
                    );
                }

                // Verify returned hashes match locally computed expected digests
                let expected_d_jcs_hash = blake3::hash(d_jcs);
                if d_jcs_hash.as_slice() != expected_d_jcs_hash.as_bytes() {
                    fail!(
                        EACCES,
                        "ZK_EGRESS_GATE_HASH_MISMATCH",
                        "d_jcs_hash returned by UID 705 does not match local d_jcs hash"
                    );
                }

                let expected_chunk_hash = blake3::hash(chunk);
                if chunk_hash.as_slice() != expected_chunk_hash.as_bytes() {
                    fail!(
                        EACCES,
                        "ZK_EGRESS_GATE_HASH_MISMATCH",
                        "chunk_hash returned by UID 705 does not match local chunk hash"
                    );
                }

                let proof = RedactProofV1::from_bytes(&pi_redact)
                    .map_err(|e| err!(EACCES, "INVALID_PI_REDACT", "Malformed pi_redact: {e}"))?;

                proof.verify(Some(&self.zk_pubkey), &d_jcs_hash, &chunk_hash)?;
                if proof.chunk_len as usize != chunk.len() {
                    fail!(EACCES, "CHUNK_LENGTH_MISMATCH");
                }

                Ok(proof)
            }
            _ => fail!(
                EPERM,
                "ZK_EGRESS_GATE_UNAVAILABLE",
                "Unexpected response from UID 705"
            ),
        }
    }
}

/// Tool host egress proxy enforcing synchronous pre-egress gating.
pub struct ToolEgressProxy {
    client: Arc<dyn EgressGateClient>,
    chunk_size: usize,
    zk_pubkey: VerifyingKey,
}

impl std::fmt::Debug for ToolEgressProxy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ToolEgressProxy")
            .field("chunk_size", &self.chunk_size)
            .finish()
    }
}

impl ToolEgressProxy {
    /// Create a proxy targeting UID 705's socket.
    pub fn new(socket_path: impl Into<PathBuf>, zk_pubkey: VerifyingKey) -> Self {
        Self {
            client: Arc::new(IpcEgressGateClient::new(socket_path, zk_pubkey)),
            chunk_size: MAX_CHUNK_SIZE,
            zk_pubkey,
        }
    }

    /// Create a proxy with a custom gate client implementation.
    pub fn with_client(client: Arc<dyn EgressGateClient>, zk_pubkey: VerifyingKey) -> Self {
        Self {
            client,
            chunk_size: MAX_CHUNK_SIZE,
            zk_pubkey,
        }
    }

    /// Stream verified output. Each release is scanned with 128 bytes of left
    /// context and right lookahead, so a boundary identifier is rejected before
    /// any of its bytes are released. This covers the current finite digit/hyphen
    /// DFA language (maximum matching span16 bytes); scanner changes must revisit
    /// this contract. Earlier clean prefixes may already be written on a later
    /// failure. Callers must treat errors as partial transmission, not retry the
    /// entire payload blindly. A scan window never exceeds64 KiB.
    pub fn stream_egress<W: Write>(
        &self,
        d_jcs: &[u8],
        payload: &[u8],
        sink: &mut W,
    ) -> EnclaveResult<usize> {
        if payload.is_empty() {
            self.verify_window(d_jcs, &[])?;
            return Ok(0);
        }
        let stride = self.chunk_size - 2 * CARRY_BYTES;
        let mut offset: usize = 0;
        while offset < payload.len() {
            let release_end = offset.saturating_add(stride).min(payload.len());
            let scan_start = offset.saturating_sub(CARRY_BYTES);
            let scan_end = release_end.saturating_add(CARRY_BYTES).min(payload.len());
            self.verify_window(d_jcs, &payload[scan_start..scan_end])?;
            sink.write_all(&payload[offset..release_end])
                .map_err(|e| err!(EIO, "SINK_WRITE", "{e}"))?;
            sink.flush().map_err(|e| err!(EIO, "SINK_FLUSH", "{e}"))?;
            offset = release_end;
        }
        Ok(offset)
    }

    fn verify_window(&self, context: &[u8], window: &[u8]) -> EnclaveResult<()> {
        let proof = self.client.gate_chunk(context, window)?;
        proof.verify(
            Some(&self.zk_pubkey),
            blake3::hash(context).as_bytes(),
            blake3::hash(window).as_bytes(),
        )?;
        if proof.chunk_len as usize != window.len() {
            fail!(EACCES, "CHUNK_LENGTH_MISMATCH");
        }
        Ok(())
    }
}
