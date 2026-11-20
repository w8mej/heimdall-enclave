//! The actual live service refuses legacy recovery before any state mutation.
#![cfg(not(feature = "simulation"))]
use enclave_core::{daemon::DaemonId, ipc::{self, PeerCredentials}, profile::Profile, seq::BootEpoch, EnclaveResult};
use enclave_zk_auditor::{quarantine::{FaultKind, FaultReport}, service::{Peers, ZkConfig, ZkRequest, ZkResponse, ZkService}, witness::WitnessFold};
use std::path::PathBuf;

struct Directory(PathBuf);
impl Drop for Directory { fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.0); } }
struct NoPeers;
impl Peers for NoPeers {
    fn cosign(&self, _: DaemonId, _: u64, _: &str) -> EnclaveResult<(Vec<u8>, Vec<u8>)> { panic!("unexpected cosign") }
    fn prepare_relay(&self, _: &[u8]) -> EnclaveResult<ipc::PreparedCall> { panic!("unexpected relay") }
    fn fetch_witness(&self, _: &str, _: u64, _: u64) -> EnclaveResult<(Vec<WitnessFold>, u64)> { panic!("unexpected witness") }
    fn boot_epoch(&self) -> EnclaveResult<BootEpoch> { panic!("unexpected epoch") }
}

#[test]
fn production_legacy_recovery_never_trusts_operator_supplied_authority() {
    let directory = Directory(std::env::temp_dir().join(format!("yk-recovery-{}-{:x}", std::process::id(), enclave_core::rng::u64())));
    let service = ZkService::start(ZkConfig::new(Profile::L3, directory.0.clone()), Box::new(NoPeers)).unwrap();
    let root = PeerCredentials::local(0, 0);
    service.handle(&root, ZkRequest::ReportFault(FaultReport {kind: FaultKind::HeapTag, fault_addr: 0x10000, at_ms: 1})).unwrap();
    let state = || match service.handle(&root, ZkRequest::Status).unwrap() {
        ZkResponse::Status(status) => status,
        _ => panic!("status positive control"),
    };
    let before = state();
    assert!(before.state.contains("quarantine_latched=true"));
    let mut files: Vec<_> = std::fs::read_dir(&directory.0).unwrap().map(|e| e.unwrap().path()).filter(|p| p.is_file()).collect();
    files.sort();
    let before_files: Vec<_> = files.iter().map(|p| std::fs::read(p).unwrap()).collect();
    for request in [
        ZkRequest::UnquarantineQuorum { enrolled_keys: Some(vec![vec![1; 32]]), threshold: Some(1), host_id: "caller-host".into(), cdhash: "caller-code".into(), generation: 0, expires_at_ms: u64::MAX, sigs: vec![], now_ms: 0 },
        ZkRequest::UnquarantineFleet { grant_bytes: serde_bytes::ByteBuf::from(b"{}".to_vec()), running_cdhash: "caller-code".into(), now: 0 },
    ] {
        let error = service.handle(&root, request).unwrap_err();
        assert!(error.is("RECOVERY_PROTOCOL_REVIEW_PENDING"), "{error}");
    }
    let after_files: Vec<_> = files.iter().map(|p| std::fs::read(p).unwrap()).collect();
    assert_eq!(before_files, after_files, "refusal must preserve sealed quarantine and evidence bytes");
    let after = state();
    assert!(after.state.contains("quarantine_latched=true"));
    assert_eq!(after.rpc_seq_u64, before.rpc_seq_u64 + 1, "only the second status consumes a sequence; rejected recovery does not");
    let stranger = PeerCredentials::local(501, 20);
    let error = service.handle(&stranger, ZkRequest::UnquarantineFleet { grant_bytes: serde_bytes::ByteBuf::from(vec![]), running_cdhash: String::new(), now: 0 }).unwrap_err();
    assert!(error.is("UNQUARANTINE_PEER_REJECTED"));
}
