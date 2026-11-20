use super::*;
use crate::ctap::assertion::CredentialKey;
use ed25519_dalek::{Signer, SigningKey};
use std::{
    os::unix::fs::{DirBuilderExt, PermissionsExt},
    path::PathBuf,
};

struct Root(PathBuf);
impl Root {
    fn new() -> Self {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target")
            .join(format!("quorum-progress-{:x}", enclave_core::rng::u64()));
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o755)
            .create(&path)
            .unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        Self(path.canonicalize().unwrap())
    }
}
impl Drop for Root {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn fixture() -> (CollectionSpec, Vec<SigningKey>) {
    let keys = vec![
        SigningKey::from_bytes(&[41; 32]),
        SigningKey::from_bytes(&[42; 32]),
    ];
    let enrolled = keys
        .iter()
        .enumerate()
        .map(|(i, key)| EnrolledCredential {
            credential_id: vec![i as u8 + 1],
            key: CredentialKey::Ed25519(key.verifying_key()),
            aaguid: [0; 16],
            firmware_version: 0,
        })
        .collect();
    (
        CollectionSpec {
            publication_sha256: [1; 32],
            grant_digest: [9; 32],
            policy_sha256: [2; 32],
            not_before_unix: 100,
            expires_unix: 200,
            threshold: 2,
            require_uv: true,
            enrolled,
        },
        keys,
    )
}
fn approval(spec: &CollectionSpec, key: &SigningKey, id: u8, count: u32) -> QuorumApproval {
    let mut auth_data = crate::ctap::rp_id_hash().to_vec();
    auth_data.push(0x05);
    auth_data.extend_from_slice(&count.to_be_bytes());
    let mut message = auth_data.clone();
    message.extend_from_slice(&spec.grant_digest);
    QuorumApproval {
        credential_id: vec![id],
        auth_data,
        signature: key.sign(&message).to_bytes().to_vec(),
        collected_at: 110,
    }
}

#[test]
fn partial_quorum_survives_restart_and_same_publication_retry_aggregates() {
    let root = Root::new();
    let (spec, keys) = fixture();
    let first = approval(&spec, &keys[0], 1, 1);
    let mut store = DurableQuorumCollector::open(&root.0).unwrap();
    let progress = store.collect(&spec, &[first.clone()], 110).unwrap();
    assert_eq!(progress.authenticated, 1);
    assert!(!progress.threshold_reached);
    assert_eq!(store.ledger.counters.get(&[1]), 1);
    drop(store);
    let mut store = DurableQuorumCollector::open(&root.0).unwrap();
    let progress = store
        .collect(&spec, &[first, approval(&spec, &keys[1], 2, 1)], 111)
        .unwrap();
    assert_eq!(progress.authenticated, 2);
    assert_eq!(progress.newly_authenticated, 1);
    assert!(progress.threshold_reached);
    assert_eq!(
        store
            .ledger
            .collections
            .values()
            .next()
            .unwrap()
            .approvals
            .len(),
        2
    );
}

#[test]
fn invalid_evidence_never_burns_counter_and_cross_publication_replay_refuses() {
    let root = Root::new();
    let (spec, keys) = fixture();
    let good = approval(&spec, &keys[0], 1, 1);
    let mut bad = good.clone();
    bad.signature[0] ^= 1;
    let mut store = DurableQuorumCollector::open(&root.0).unwrap();
    assert_eq!(store.collect(&spec, &[bad], 110).unwrap().authenticated, 0);
    assert_eq!(store.ledger.counters.get(&[1]), 0);
    store.collect(&spec, &[good.clone()], 110).unwrap();
    let mut other = spec.clone();
    other.publication_sha256 = [3; 32];
    assert_eq!(
        store.collect(&other, &[good], 110).unwrap().authenticated,
        0
    );
    assert_eq!(store.ledger.counters.get(&[1]), 1);
    let mut changed = spec.clone();
    changed.policy_sha256 = [4; 32];
    assert!(store
        .collect(&changed, &[], 110)
        .unwrap_err()
        .is("QUORUM_PUBLICATION_CONFLICT"));
}

#[test]
fn revocation_expiry_alias_and_concurrent_owner_remain_closed() {
    let root = Root::new();
    let (spec, keys) = fixture();
    let mut store = DurableQuorumCollector::open(&root.0).unwrap();
    assert!(DurableQuorumCollector::open(&root.0)
        .err()
        .unwrap()
        .is("STATE_DIRECTORY_BUSY"));
    store
        .collect(&spec, &[approval(&spec, &keys[0], 1, 1)], 110)
        .unwrap();
    store.revoke(&spec.publication_sha256).unwrap();
    drop(store);
    let mut store = DurableQuorumCollector::open(&root.0).unwrap();
    assert!(store
        .collect(&spec, &[approval(&spec, &keys[1], 2, 1)], 110)
        .unwrap_err()
        .is("QUORUM_COLLECTION_REVOKED"));
    assert!(store
        .collect(&spec, &[], 200)
        .unwrap_err()
        .is("QUORUM_COLLECTION_EXPIRED"));
    let mut alias = spec.clone();
    alias.enrolled[1].key = alias.enrolled[0].key.clone();
    assert!(store
        .collect(&alias, &[], 110)
        .unwrap_err()
        .is("QUORUM_DUPLICATE_ENROLLMENT"));
}

#[test]
fn checkpoint_io_failure_latches_then_reconciles_counter_and_approval_together() {
    let root = Root::new();
    let (spec, keys) = fixture();
    let mut store = DurableQuorumCollector::open(&root.0).unwrap();
    let checkpoint = root.0.join("quorum-progress.gen");
    let saved = root.0.join("old-checkpoint.fixture");
    std::fs::rename(&checkpoint, &saved).unwrap();
    std::fs::create_dir(&checkpoint).unwrap();
    let proof = approval(&spec, &keys[0], 1, 1);
    assert!(store.collect(&spec, &[proof.clone()], 110).is_err());
    assert!(store
        .collect(&spec, &[], 110)
        .unwrap_err()
        .is("QUORUM_PROGRESS_REOPEN_REQUIRED"));
    drop(store);
    std::fs::remove_dir(&checkpoint).unwrap();
    std::fs::rename(&saved, &checkpoint).unwrap();
    // State replacement reached disk before checkpoint replacement failed. A
    // surviving older authenticated floor loads the newer complete envelope.
    let mut store = DurableQuorumCollector::open(&root.0).unwrap();
    assert_eq!(store.ledger.counters.get(&[1]), 1);
    let progress = store.collect(&spec, &[proof], 110).unwrap();
    assert_eq!(progress.authenticated, 1);
    assert_eq!(progress.newly_authenticated, 0);
}

#[test]
fn missing_surviving_state_never_resets_and_unsigned_time_overflow_refuses() {
    let root = Root::new();
    let (spec, keys) = fixture();
    let mut store = DurableQuorumCollector::open(&root.0).unwrap();
    let mut bad = approval(&spec, &keys[0], 1, 1);
    bad.collected_at = i64::MIN;
    assert_eq!(store.collect(&spec, &[bad], 110).unwrap().authenticated, 0);
    let mut before_scope = approval(&spec, &keys[0], 1, 1);
    before_scope.collected_at = 99;
    assert_eq!(
        store
            .collect(&spec, &[before_scope], 110)
            .unwrap()
            .authenticated,
        0
    );
    drop(store);
    std::fs::remove_file(root.0.join("quorum-progress.sealed")).unwrap();
    assert!(DurableQuorumCollector::open(&root.0).is_err());
}

#[test]
fn restored_legacy_raw_key_floors_bind_all_enrolled_canonical_aliases() {
    use sha2::{Digest, Sha256};
    let (canonical, raw_alias) = (0u8..19)
        .find_map(|y| {
            let mut canonical = [0u8; 32];
            canonical[0] = y;
            let mut alias = [0xffu8; 32];
            alias[0] = 0xed + y;
            alias[31] = 0x7f;
            let first = ed25519_dalek::VerifyingKey::from_bytes(&canonical).ok()?;
            let second = ed25519_dalek::VerifyingKey::from_bytes(&alias).ok()?;
            (first.to_edwards().compress() == second.to_edwards().compress())
                .then_some((first, second))
        })
        .unwrap();
    let root = Root::new();
    let (mut spec, _) = fixture();
    spec.threshold = 1;
    spec.enrolled = vec![EnrolledCredential {
        credential_id: vec![91],
        key: CredentialKey::Ed25519(raw_alias),
        aaguid: [0; 16],
        firmware_version: 1,
    }];
    let mut hash = Sha256::new();
    hash.update((spec.enrolled[0].key.alg() as i32).to_be_bytes());
    hash.update(spec.enrolled[0].key.to_raw());
    let fingerprint = hex::encode(hash.finalize());
    let legacy = serde_json::json!({"counts":{},"key_counts":{fingerprint:49}});
    let mut store = DurableQuorumCollector::open(&root.0).unwrap();
    let mut ledger = store.ledger.clone();
    ledger.counters = serde_json::from_value(legacy).unwrap();
    ledger.collections.insert(
        hex::encode(spec.publication_sha256),
        Collection {
            scope_sha256: spec.identity().unwrap(),
            spec,
            approvals: vec![],
            revoked: false,
        },
    );
    store.commit(ledger).unwrap();
    drop(store);
    let store = DurableQuorumCollector::open(&root.0).unwrap();
    let canonical = EnrolledCredential {
        credential_id: vec![92],
        key: CredentialKey::Ed25519(canonical),
        aaguid: [0; 16],
        firmware_version: 1,
    };
    assert_eq!(store.ledger.counters.get_credential(&canonical), 49);
}
