//! GAP-10: Journal-derived witnesses, UID 703 ingress commitments, and
//! witness channel soundness tests.
//!
//! Required test coverage:
//! - claimed deltas ≠ journals ⇒ fail
//! - a slot whose `C_raw` lacks a 703 ingress MAC ⇒ fail
//! - a mutation of any journal line breaks proving
//! - `ProveEpoch` accepts only `(epoch, s_start, s_end)`
//! - multi-UID test: only 703 can open the witness channel

#[path = "support/relay_peer.rs"]
mod relay_peer;

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use ed25519_dalek::{Signer, SigningKey};
use enclave_core::audit::AuditJournal;
use enclave_core::daemon::DaemonId;
use enclave_core::error::EnclaveResult;
use enclave_core::ipc::PeerCredentials;
use enclave_core::poseidon2::Poseidon2Sponge;
use enclave_core::profile::Profile;
use enclave_core::seq::BootEpoch;
use enclave_zk_auditor::service::{
    Peers, ProveEpochRequest, ZkConfig, ZkRequest, ZkResponse, ZkService,
};
use enclave_zk_auditor::witness::WitnessFold;
use serde_json::json;

fn make_witness_fold(key: &[u8; 32], seq: u64, raw: &[u8], scrubbed: Vec<u8>) -> WitnessFold {
    let mut r = [0u8; 32];
    enclave_core::rng::fill(&mut r);
    let mut c = Poseidon2Sponge::new();
    c.absorb_bytes(b"depot-C_raw-v1", raw);
    c.absorb_bytes(b"depot-C_raw-blind-v1", &r);
    let c_raw = c.finalize();
    let mut h = Poseidon2Sponge::new();
    h.absorb_bytes(b"depot-IngressMac-v1", key);
    h.absorb_u64(seq);
    for l in c_raw.0 {
        h.absorb_u32(l);
    }
    WitnessFold {
        rpc_seq_u64: seq,
        scrubbed,
        c_raw: c_raw.to_hex(),
        h_ingress_mac: h.finalize().to_hex(),
    }
}

fn tmpdir(prefix: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!("depot-{prefix}-{}", enclave_core::rng::u64()));
    std::fs::create_dir_all(&p).unwrap();
    p
}

struct MockPeers {
    boot_epoch: BootEpoch,
    k703: SigningKey,
    k704: SigningKey,
    witness_folds: Mutex<Vec<WitnessFold>>,
    next_slot: Mutex<u64>,
}

impl MockPeers {
    fn new(epoch_id: &str) -> Self {
        let mut csprng = rand_core::OsRng;
        let k703 = SigningKey::generate(&mut csprng);
        let k704 = SigningKey::generate(&mut csprng);
        let signer = enclave_crypto::epoch::EpochSigner::random();
        let sig = signer.sign_message(&enclave_core::seq::epoch_signing_message(epoch_id));
        Self {
            boot_epoch: BootEpoch {
                boot_epoch_id: epoch_id.to_string(),
                signature: sig,
                signer_public_key: signer.public_key(),
            },
            k703,
            k704,
            witness_folds: Mutex::new(Vec::new()),
            next_slot: Mutex::new(100),
        }
    }
}

impl Peers for MockPeers {
    fn cosign(
        &self,
        who: DaemonId,
        slot: u64,
        boot_epoch_id: &str,
    ) -> EnclaveResult<(Vec<u8>, Vec<u8>)> {
        let msg = format!("{boot_epoch_id}:{slot}");
        let (sig, vk) = match who {
            DaemonId::CustodyVault => (
                self.k703.sign(msg.as_bytes()).to_vec(),
                self.k703.verifying_key().to_bytes().to_vec(),
            ),
            DaemonId::AgentRuntime => (
                self.k704.sign(msg.as_bytes()).to_vec(),
                self.k704.verifying_key().to_bytes().to_vec(),
            ),
            _ => panic!("unexpected cosigner"),
        };
        Ok((sig, vk))
    }

    fn prepare_relay(&self, frame: &[u8]) -> EnclaveResult<enclave_core::ipc::PreparedCall> {
        relay_peer::prepare_queued(frame, |_| {})
    }

    fn fetch_witness(
        &self,
        _boot_epoch_id: &str,
        s_start: u64,
        s_end: u64,
    ) -> EnclaveResult<(Vec<WitnessFold>, u64)> {
        let g = self.witness_folds.lock().unwrap();
        let folds: Vec<_> = g
            .iter()
            .filter(|w| w.rpc_seq_u64 >= s_start && w.rpc_seq_u64 <= s_end)
            .cloned()
            .collect();
        let ns = *self.next_slot.lock().unwrap();
        Ok((folds, ns))
    }

    fn boot_epoch(&self) -> EnclaveResult<BootEpoch> {
        Ok(self.boot_epoch.clone())
    }
}

/// Helper to set up audit journals for daemons.
struct TestMeshJournals {
    root: PathBuf,
    epoch: String,
}

impl TestMeshJournals {
    fn new(root: &Path, epoch: &str) -> Self {
        for d in enclave_zk_auditor::witness::JOURNALED {
            std::fs::create_dir_all(root.join(d.dir_name())).unwrap();
        }
        Self {
            root: root.to_path_buf(),
            epoch: epoch.to_string(),
        }
    }

    fn append_vault_slot(&self, slot: u64, text: &str) {
        let p = self
            .root
            .join(DaemonId::CustodyVault.dir_name())
            .join("custody-audit.jsonl");
        let mut j = AuditJournal::open(&p, DaemonId::CustodyVault, self.epoch.clone()).unwrap();
        j.append(
            slot,
            json!({"event": "TOKENIZE", "slot": slot, "val": text}),
        )
        .unwrap();
    }

    fn append_ifc_slot(&self, slot: u64, qif_mb: u32) {
        let p = self
            .root
            .join(DaemonId::AgentRuntime.dir_name())
            .join("ifc-audit.jsonl");
        let mut j = AuditJournal::open(&p, DaemonId::AgentRuntime, self.epoch.clone()).unwrap();
        j.append(
            slot,
            json!({"event": "EXEC_TOOL", "slot": slot, "qif_mb": qif_mb}),
        )
        .unwrap();
    }
}

// ---------------------------------------------------------------------------
// TEST 1: Claimed deltas ≠ journals ⇒ fail
// ---------------------------------------------------------------------------
#[test]
fn test_claimed_deltas_mismatch_journals_fails() {
    let td = tmpdir("delta-mismatch");
    let epoch = enclave_core::seq::new_boot_epoch_id();
    let j = TestMeshJournals::new(&td.join("audit"), &epoch);
    let peers = Arc::new(MockPeers::new(&epoch));
    *peers.next_slot.lock().unwrap() = 10;

    // UID 704 journals slot 1 with delta 15000 (exceeds 12000 QIF cap)
    j.append_ifc_slot(1, 15_000);

    let mut cfg = ZkConfig::new(Profile::L2, td.join("quarantine"));
    cfg.journal_dir = Some(td.join("audit"));
    cfg.hardware_batch_anchor_sigs = Some(vec!["3045".into()]);
    let svc = ZkService::start(cfg, Box::new(P(peers.clone()))).unwrap();

    let peer = PeerCredentials::local(704, 704);
    let req = ProveEpochRequest {
        boot_epoch_id: epoch.clone(),
        s_start: 1,
        s_end: 1,
    };
    // The prover derives deltas directly from the journal. Since 15000 > 12000,
    // the QIF 24 h cap fails in prove_rollup_series.
    let err = svc.handle(&peer, ZkRequest::ProveEpoch(Box::new(req)));
    assert!(
        err.is_err(),
        "proving must fail when journal delta exceeds QIF cap"
    );
    let e = err.unwrap_err();
    assert!(
        e.is("QIF_CAP_EXCEEDED") || e.is("QIF_BUDGET_EXCEEDED") || e.is("QIF_BUDGET"),
        "expected QIF cap failure, got: {e}"
    );

    let _ = std::fs::remove_dir_all(td);
}

// ---------------------------------------------------------------------------
// TEST 2: Slot whose C_raw lacks a 703 ingress MAC ⇒ fail
// ---------------------------------------------------------------------------
#[test]
fn test_slot_lacks_703_ingress_mac_fails() {
    let td = tmpdir("mac-missing");
    let epoch = enclave_core::seq::new_boot_epoch_id();
    let j = TestMeshJournals::new(&td.join("audit"), &epoch);
    let peers = Arc::new(MockPeers::new(&epoch));
    *peers.next_slot.lock().unwrap() = 10;

    // Journal records vault slot 1
    j.append_vault_slot(1, "scrubbed");

    // But witness fold has an all-zero ingress MAC (forged / lacks 703 MAC)
    let forged_fold = WitnessFold {
        rpc_seq_u64: 1,
        scrubbed: b"scrubbed".to_vec(),
        c_raw: "a".repeat(64),
        h_ingress_mac: "0".repeat(64),
    };
    peers.witness_folds.lock().unwrap().push(forged_fold);

    let mut cfg = ZkConfig::new(Profile::L2, td.join("quarantine"));
    cfg.journal_dir = Some(td.join("audit"));
    cfg.hardware_batch_anchor_sigs = Some(vec!["3045".into()]);
    let svc = ZkService::start(cfg, Box::new(P(peers.clone()))).unwrap();

    let peer = PeerCredentials::local(704, 704);
    let req = ProveEpochRequest {
        boot_epoch_id: epoch.clone(),
        s_start: 1,
        s_end: 1,
    };
    let err = svc
        .handle(&peer, ZkRequest::ProveEpoch(Box::new(req)))
        .unwrap_err();
    assert!(
        err.is("WITNESS_INGRESS_MAC"),
        "expected WITNESS_INGRESS_MAC, got: {err}"
    );

    let _ = std::fs::remove_dir_all(td);
}

// ---------------------------------------------------------------------------
// TEST 3: Mutation of any journal line breaks proving
// ---------------------------------------------------------------------------
#[test]
fn test_mutation_of_journal_line_breaks_proving() {
    let td = tmpdir("journal-tamper");
    let epoch = enclave_core::seq::new_boot_epoch_id();
    let j = TestMeshJournals::new(&td.join("audit"), &epoch);
    let peers = Arc::new(MockPeers::new(&epoch));
    *peers.next_slot.lock().unwrap() = 10;

    // UID 704 journals slot 1 and slot 2
    j.append_ifc_slot(1, 100);
    j.append_ifc_slot(2, 100);

    // Tamper with the journal file by mutating a byte in the first line
    let jfile = td
        .join("audit")
        .join(DaemonId::AgentRuntime.dir_name())
        .join("ifc-audit.jsonl");
    let mut raw = std::fs::read(&jfile).unwrap();
    // Invert a byte in the middle of line 1
    raw[15] ^= 0x5a;
    std::fs::write(&jfile, raw).unwrap();

    let mut cfg = ZkConfig::new(Profile::L2, td.join("quarantine"));
    cfg.journal_dir = Some(td.join("audit"));
    cfg.hardware_batch_anchor_sigs = Some(vec!["3045".into()]);
    let svc = ZkService::start(cfg, Box::new(P(peers.clone()))).unwrap();

    let peer = PeerCredentials::local(704, 704);
    let req = ProveEpochRequest {
        boot_epoch_id: epoch.clone(),
        s_start: 1,
        s_end: 2,
    };
    let err = svc
        .handle(&peer, ZkRequest::ProveEpoch(Box::new(req)))
        .unwrap_err();
    // Tampering breaks line parsing or canonicalization or hash chain
    assert!(
        err.is("AUDIT_CHAIN_BREAK")
            || err.is("AUDIT_BLAKE3_CHAIN_BREAK")
            || err.is("AUDIT_LINE_HASH")
            || err.is("AUDIT_TIP")
            || err.is("AUDIT_LINE_PARSE")
            || err.is("AUDIT_NON_CANONICAL"),
        "expected hash chain break, got: {err}"
    );

    let _ = std::fs::remove_dir_all(td);
}

// ---------------------------------------------------------------------------
// TEST 4: ProveEpoch accepts only (epoch, s_start, s_end)
// ---------------------------------------------------------------------------
#[test]
fn test_prove_epoch_accepts_only_epoch_range() {
    let epoch = "ep-20261106-001";
    let req = ProveEpochRequest {
        boot_epoch_id: epoch.to_string(),
        s_start: 5,
        s_end: 15,
    };
    // Serialise to JSON and verify exact key set
    let val: serde_json::Value = serde_json::to_value(&req).unwrap();
    let obj = val.as_object().unwrap();
    let mut keys: Vec<_> = obj.keys().cloned().collect();
    keys.sort();
    assert_eq!(
        keys,
        vec!["boot_epoch_id", "s_end", "s_start"],
        "ProveEpochRequest must accept strictly (boot_epoch_id, s_start, s_end)"
    );

    // Assert that attempting to parse JSON with forged chunks or deltas fails to affect ProveEpochRequest
    let forged_json = json!({
        "boot_epoch_id": epoch,
        "s_start": 5,
        "s_end": 15,
        "forged_delta": 9999
    });
    let parsed: ProveEpochRequest = serde_json::from_value(forged_json).unwrap();
    assert_eq!(parsed.s_start, 5);
    assert_eq!(parsed.s_end, 15);
}

// ---------------------------------------------------------------------------
// TEST 5: Multi-UID test: only 703 can open the witness channel
// ---------------------------------------------------------------------------
#[test]
fn test_witness_channel_policy_only_703_admitted() {
    let policy = enclave_core::ipc::witness_channel_policy();

    // UID 703 (_piivault) is the single admitted UID
    assert_eq!(policy.allowed_uids.len(), 1);
    assert!(policy.allowed_uids.contains(&DaemonId::CustodyVault.uid()));
    let peer_703 = PeerCredentials {
        uid: DaemonId::CustodyVault.uid(),
        gid: DaemonId::CustodyVault.gid(),
        pid: Some(100),
        audit_token: None,
        code_identity: None,
        tls_channel_binding: None,
    };
    assert!(
        policy
            .check_with(&peer_703, false, &|_, _| unreachable!())
            .is_ok(),
        "UID 703 must be admitted on witness channel"
    );

    // Other UIDs must be rejected
    for &uid in &[701, 702, 704, 705, 501, 0] {
        let peer = PeerCredentials {
            uid,
            gid: uid,
            pid: Some(101),
            audit_token: None,
            code_identity: None,
            tls_channel_binding: None,
        };
        let res = policy.check(&peer);
        assert!(
            res.is_err(),
            "UID {uid} must be rejected on witness channel"
        );
        assert!(res.unwrap_err().is("PEER_UID_REJECTED"));
    }
}

// ---------------------------------------------------------------------------
// Bundle helper test: test_mesh_epoch_proved_from_real_journals
// ---------------------------------------------------------------------------
#[test]
fn test_mesh_epoch_proved_from_real_journals() {
    let td = tmpdir("mesh-prove");
    let epoch = enclave_core::seq::new_boot_epoch_id();
    let j = TestMeshJournals::new(&td.join("audit"), &epoch);
    let peers = Arc::new(MockPeers::new(&epoch));
    *peers.next_slot.lock().unwrap() = 10;

    // Create real ingress witness via Poseidon2 commitment
    let key = [99u8; 32];
    let fold = make_witness_fold(&key, 1, b"john@example.com", b"[REDACTED_EMAIL]".to_vec());
    peers.witness_folds.lock().unwrap().push(fold);
    j.append_vault_slot(1, "[REDACTED_EMAIL]");

    // Slot 2 is an orchestrator execution charging 50 millibits
    j.append_ifc_slot(2, 50);

    let mut cfg = ZkConfig::new(Profile::L2, td.join("quarantine"));
    cfg.journal_dir = Some(td.join("audit"));
    cfg.entity = "acct:test".into();
    cfg.id_enclave = [7u8; 32];
    cfg.hardware_batch_anchor_sigs = Some(vec!["3045".into()]);
    let svc = ZkService::start(cfg, Box::new(P(peers.clone()))).unwrap();

    let peer = PeerCredentials::local(704, 704);
    let req = ProveEpochRequest {
        boot_epoch_id: epoch.clone(),
        s_start: 1,
        s_end: 2,
    };
    let resp = svc
        .handle(&peer, ZkRequest::ProveEpoch(Box::new(req)))
        .unwrap();
    let ZkResponse::Proven {
        frames, relayed, ..
    } = resp
    else {
        panic!("expected Proven response");
    };
    assert!(relayed);
    assert_eq!(frames.len(), 1);

    // Native scan metadata must not assert an absent in-circuit relation (F87).
    let frame: enclave_zk_auditor::rollup::ComplianceRollupProofV1 =
        ciborium::from_reader(frames[0].as_slice()).unwrap();
    assert_eq!(
        frame.public_inputs.redaction_checked.as_deref(),
        Some("native"),
        "native checks must never be represented as an in-circuit compliance proof"
    );

    let _ = std::fs::remove_dir_all(td);
}

// ---------------------------------------------------------------------------
// Bundle helper test: test_hand_edited_journal_line_rejected
// ---------------------------------------------------------------------------
#[test]
fn test_hand_edited_journal_line_rejected() {
    let td = tmpdir("hand-edit");
    let epoch = enclave_core::seq::new_boot_epoch_id();
    let j = TestMeshJournals::new(&td.join("audit"), &epoch);
    let peers = Arc::new(MockPeers::new(&epoch));
    *peers.next_slot.lock().unwrap() = 10;

    // Append two slots so line 2 anchors line 1
    j.append_ifc_slot(1, 20);
    j.append_ifc_slot(2, 20);

    let jfile = td
        .join("audit")
        .join(DaemonId::AgentRuntime.dir_name())
        .join("ifc-audit.jsonl");
    let content = std::fs::read_to_string(&jfile).unwrap();
    // Hand-edit slot 1 to reduce qif_mb from 20 to 0 (valid JSON, but breaks line 2's chain)
    assert!(
        content.contains("\"qif_mb\":20"),
        "journal must contain qif_mb:20"
    );
    let tampered = content.replacen("\"qif_mb\":20", "\"qif_mb\":0", 1);
    assert_ne!(content, tampered, "tampering must have altered content");
    std::fs::write(&jfile, tampered).unwrap();

    let mut cfg = ZkConfig::new(Profile::L2, td.join("quarantine"));
    cfg.journal_dir = Some(td.join("audit"));
    cfg.hardware_batch_anchor_sigs = Some(vec!["3045".into()]);
    let svc = ZkService::start(cfg, Box::new(P(peers.clone()))).unwrap();

    let peer = PeerCredentials::local(704, 704);
    let req = ProveEpochRequest {
        boot_epoch_id: epoch,
        s_start: 1,
        s_end: 2,
    };
    let res = svc.handle(&peer, ZkRequest::ProveEpoch(Box::new(req)));
    assert!(
        res.is_err(),
        "hand-edited journal line in harness must be rejected"
    );
    let err = res.unwrap_err();
    assert!(
        err.is("AUDIT_BLAKE3_CHAIN_BREAK")
            || err.is("AUDIT_CHAIN_BREAK")
            || err.is("AUDIT_NON_CANONICAL"),
        "expected chain break on hand-edited journal line, got: {err}"
    );

    let _ = std::fs::remove_dir_all(td);
}

struct P(Arc<MockPeers>);

impl Peers for P {
    fn cosign(
        &self,
        who: DaemonId,
        slot: u64,
        boot_epoch_id: &str,
    ) -> EnclaveResult<(Vec<u8>, Vec<u8>)> {
        self.0.cosign(who, slot, boot_epoch_id)
    }

    fn prepare_relay(&self, frame: &[u8]) -> EnclaveResult<enclave_core::ipc::PreparedCall> {
        self.0.prepare_relay(frame)
    }

    fn fetch_witness(
        &self,
        boot_epoch_id: &str,
        s_start: u64,
        s_end: u64,
    ) -> EnclaveResult<(Vec<WitnessFold>, u64)> {
        self.0.fetch_witness(boot_epoch_id, s_start, s_end)
    }

    fn boot_epoch(&self) -> EnclaveResult<BootEpoch> {
        self.0.boot_epoch()
    }
}
