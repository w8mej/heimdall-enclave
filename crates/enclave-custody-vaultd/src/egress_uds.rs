//! UDS client for the synchronous ZK pre-egress gate (GAP-25, FS-705 §4.3.1).

use std::path::PathBuf;
use std::time::Duration;

use ed25519_dalek::VerifyingKey;
use enclave_core::daemon::DaemonId;
use enclave_core::error::EnclaveResult;
use enclave_core::ipc::Client;
use enclave_core::{err, fail};
use enclave_zk_auditor::service::{ZkRequest, ZkResponse};
use enclave_zk_auditor::zk::redact::RedactProofV1;
use serde_bytes::ByteBuf;

use crate::ceremony::EgressGate;

/// The idle timeout per chunk or gate call (5 seconds, FS-705 §4.3.1 / D-25a).
pub const GATE_TIMEOUT: Duration = Duration::from_secs(5);

/// Production synchronous ZK egress gate communicating over Unix domain socket to UID 705.
#[derive(Debug, Clone)]
pub struct UdsEgressGate {
    socket_path: PathBuf,
    expected_uid: u32,
    zk_pubkey: Option<VerifyingKey>,
}

impl UdsEgressGate {
    /// Create a new UDS egress gate targeting UID 705's socket.
    pub fn new(socket_path: PathBuf) -> Self {
        Self {
            socket_path,
            expected_uid: DaemonId::ZkAuditor.uid(),
            zk_pubkey: None,
        }
    }

    /// Create with an explicit expected server UID and optional pinned verifying key.
    pub fn with_options(
        socket_path: PathBuf,
        expected_uid: u32,
        zk_pubkey: Option<VerifyingKey>,
    ) -> Self {
        Self {
            socket_path,
            expected_uid,
            zk_pubkey,
        }
    }
}

impl EgressGate for UdsEgressGate {
    fn approve(&mut self, d_jcs: &[u8; 32]) -> EnclaveResult<()> {
        self.approve_chunk(d_jcs, &[])
    }

    fn approve_chunk(&mut self, d_jcs: &[u8; 32], chunk: &[u8]) -> EnclaveResult<()> {
        let mut client = Client::connect(&self.socket_path, self.expected_uid).map_err(|e| {
            err!(
                EPERM,
                "ZK_EGRESS_GATE_UNAVAILABLE",
                "Failed to connect to UID 705: {e}"
            )
        })?;

        client.set_timeout(Some(GATE_TIMEOUT))?;

        let req = ZkRequest::GateEgress {
            d_jcs: ByteBuf::from(d_jcs.to_vec()),
            chunk: ByteBuf::from(chunk.to_vec()),
        };

        let resp: ZkResponse = client.call(&req).map_err(|e| {
            err!(
                EPERM,
                "ZK_EGRESS_GATE_UNAVAILABLE",
                "Call to UID 705 failed: {e}"
            )
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

                let zk_pubkey = self.zk_pubkey.as_ref().ok_or_else(|| {
                    err!(
                        EACCES,
                        "ZK_EGRESS_GATE_UNPINNED",
                        "Egress gate requires a pinned ZK verifying key (redact.pub)"
                    )
                })?;
                proof.verify(Some(zk_pubkey), &d_jcs_hash, &chunk_hash)?;

                Ok(())
            }
            _ => fail!(
                EPERM,
                "ZK_EGRESS_GATE_UNAVAILABLE",
                "Unexpected response from UID 705"
            ),
        }
    }
}
