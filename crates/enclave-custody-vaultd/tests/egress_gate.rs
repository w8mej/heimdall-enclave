//! Tests for synchronous ZK egress gate (GAP-25, FS-703 §3.1, FS-705 §4.3.1).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use ed25519_dalek::SigningKey;
use enclave_core::ipc::{bind, serve, PeerPolicy, SocketAccess};
use enclave_custody_vaultd::ceremony::EgressGate;
use enclave_custody_vaultd::egress_uds::UdsEgressGate;
use enclave_zk_auditor::service::{ZkRequest, ZkResponse};
use enclave_zk_auditor::zk::redact::evaluate_and_prove_chunk;
use serde_bytes::ByteBuf;

struct TestServer {
    stop: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = self.handle.take().map(|h| h.join());
    }
}

fn start_mock_zk_service(
    sock_path: &std::path::Path,
    sk: SigningKey,
) -> (TestServer, ed25519_dalek::VerifyingKey) {
    let vk = sk.verifying_key();
    let listener = bind(sock_path, SocketAccess::OwnerOnly).unwrap();
    listener
        .set_nonblocking(true)
        .expect("set nonblocking listener");
    let stop = Arc::new(AtomicBool::new(false));
    let stop_clone = stop.clone();

    let handler = Arc::new(
        move |_peer: &enclave_core::ipc::PeerCredentials,
              req: ZkRequest|
              -> enclave_core::error::EnclaveResult<ZkResponse> {
            match req {
                ZkRequest::GateEgress { d_jcs, chunk } => {
                    let ts_ns = 1_700_000_000_000_000_000;
                    let proof = evaluate_and_prove_chunk(&sk, &d_jcs, &chunk, ts_ns)?;
                    let pi_redact = proof.to_bytes()?;
                    Ok(ZkResponse::EgressGated {
                        approved: true,
                        chunk_hash: proof.chunk_hash,
                        d_jcs_hash: proof.d_jcs_hash,
                        pi_redact: ByteBuf::from(pi_redact),
                    })
                }
                _ => Err(enclave_core::err!(EINVAL, "UNEXPECTED_REQ")),
            }
        },
    );

    let handle = std::thread::spawn(move || {
        let _ = serve(
            listener,
            PeerPolicy::allow([enclave_core::ipc::geteuid()]),
            handler,
            stop_clone,
        );
    });

    (
        TestServer {
            stop,
            handle: Some(handle),
        },
        vk,
    )
}

static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn make_temp_dir() -> std::path::PathBuf {
    let count = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "depot-test-gate-{}-{}-{}",
        std::process::id(),
        count,
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = std::fs::create_dir_all(&dir);
    dir
}

#[test]
fn test_egress_gate_satisfies_zk_factor_with_verified_proof() {
    let dir = make_temp_dir();
    let sock = dir.join("zk.sock");
    let sk = SigningKey::generate(&mut rand_core::OsRng);

    let (_srv, vk) = start_mock_zk_service(&sock, sk);

    let mut gate =
        UdsEgressGate::with_options(sock.clone(), enclave_core::ipc::geteuid(), Some(vk));

    let d_jcs = [0x42; 32];
    gate.approve(&d_jcs).unwrap();

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_egress_gate_unavailable_fails_closed() {
    let dir = make_temp_dir();
    let missing_sock = dir.join("nonexistent_zk.sock");

    let mut gate = UdsEgressGate::new(missing_sock);
    let d_jcs = [0x42; 32];
    let err = gate.approve(&d_jcs).unwrap_err();
    assert!(
        err.is("ZK_EGRESS_GATE_UNAVAILABLE"),
        "Expected ZK_EGRESS_GATE_UNAVAILABLE, got {err}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_egress_gate_foreign_signer_key_rejected() {
    let dir = make_temp_dir();
    let sock = dir.join("zk.sock");
    let sk = SigningKey::generate(&mut rand_core::OsRng);

    let (_srv, _vk) = start_mock_zk_service(&sock, sk);

    // Provide a different (foreign) verifying key to the gate client
    let foreign_sk = SigningKey::generate(&mut rand_core::OsRng);
    let foreign_vk = foreign_sk.verifying_key();

    let mut gate =
        UdsEgressGate::with_options(sock.clone(), enclave_core::ipc::geteuid(), Some(foreign_vk));

    let d_jcs = [0x42; 32];
    let err = gate.approve(&d_jcs).unwrap_err();
    assert!(
        err.is("SIGNER_MISMATCH"),
        "Expected SIGNER_MISMATCH, got {err}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_egress_gate_spoofed_d_jcs_hash_rejected() {
    let dir = make_temp_dir();
    let sock = dir.join("zk.sock");
    let sk = SigningKey::generate(&mut rand_core::OsRng);
    let vk = sk.verifying_key();

    let listener = bind(&sock, SocketAccess::OwnerOnly).unwrap();
    listener.set_nonblocking(true).unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let stop_clone = stop.clone();

    // Mock service returns a proof for a DIFFERENT d_jcs
    let handler = Arc::new(
        move |_peer: &enclave_core::ipc::PeerCredentials,
              _req: ZkRequest|
              -> enclave_core::error::EnclaveResult<ZkResponse> {
            let spoofed_d_jcs = [0x99; 32];
            let proof =
                evaluate_and_prove_chunk(&sk, &spoofed_d_jcs, &[], 1_700_000_000_000_000_000)?;
            let pi_redact = proof.to_bytes()?;
            Ok(ZkResponse::EgressGated {
                approved: true,
                chunk_hash: proof.chunk_hash,
                d_jcs_hash: proof.d_jcs_hash, // Mismatched d_jcs_hash!
                pi_redact: ByteBuf::from(pi_redact),
            })
        },
    );

    let handle = std::thread::spawn(move || {
        let _ = serve(
            listener,
            PeerPolicy::allow([enclave_core::ipc::geteuid()]),
            handler,
            stop_clone,
        );
    });
    let _srv = TestServer {
        stop,
        handle: Some(handle),
    };

    let mut gate =
        UdsEgressGate::with_options(sock.clone(), enclave_core::ipc::geteuid(), Some(vk));
    let d_jcs = [0x42; 32];
    let err = gate.approve(&d_jcs).unwrap_err();
    assert!(
        err.is("ZK_EGRESS_GATE_HASH_MISMATCH"),
        "Expected ZK_EGRESS_GATE_HASH_MISMATCH, got {err}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_egress_gate_approve_chunk_with_payload() {
    let dir = make_temp_dir();
    let sock = dir.join("zk.sock");
    let sk = SigningKey::generate(&mut rand_core::OsRng);

    let (_srv, vk) = start_mock_zk_service(&sock, sk);

    let mut gate =
        UdsEgressGate::with_options(sock.clone(), enclave_core::ipc::geteuid(), Some(vk));
    let d_jcs = [0x11; 32];
    let chunk = b"Safe egress data without any C4 PII.";
    gate.approve_chunk(&d_jcs, chunk).unwrap();

    let _ = std::fs::remove_dir_all(&dir);
}
