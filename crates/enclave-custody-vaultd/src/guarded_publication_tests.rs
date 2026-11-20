use super::*;
use ed25519_dalek::{Signer, SigningKey};
use enclave_crypto::tuf::RepoBuilder;
use std::{
    os::unix::fs::{DirBuilderExt, PermissionsExt},
    path::PathBuf,
    sync::{Arc, Mutex},
};

struct Root(PathBuf);
impl Root {
    fn new() -> Self {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target")
            .join(format!(
                "guarded-publication-{:x}",
                enclave_core::rng::u64()
            ));
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
#[derive(Clone)]
struct FakeAnchor(Arc<Mutex<MemoryAnchor>>);
struct MemoryAnchor {
    scope: Option<JournalScope>,
    pin: AnchorPin,
    unavailable: bool,
    fail_cas: bool,
    apply_then_error: bool,
}
impl FakeAnchor {
    fn new() -> Self {
        Self(Arc::new(Mutex::new(MemoryAnchor {
            scope: None,
            pin: AnchorPin::genesis(),
            unavailable: false,
            fail_cas: false,
            apply_then_error: false,
        })))
    }
    fn boxed(&self) -> Box<dyn ExternalRecoveryAnchor> {
        Box::new(self.clone())
    }
    fn pin(&self) -> AnchorPin {
        self.0.lock().unwrap().pin
    }
}
// Pure trusted test fixture only. There is deliberately no production/local-file
// implementation of the independently protected external recovery authority.
impl ExternalRecoveryAnchor for FakeAnchor {
    fn load(&mut self, scope: &JournalScope) -> EnclaveResult<AnchorPin> {
        let mut state = self.0.lock().unwrap();
        if state.unavailable {
            fail!(EIO, "TEST_ANCHOR_UNAVAILABLE");
        }
        if let Some(old) = &state.scope {
            if old != scope {
                fail!(EACCES, "TEST_ANCHOR_SCOPE");
            }
        } else {
            state.scope = Some(scope.clone());
        }
        Ok(state.pin)
    }
    fn compare_and_advance(
        &mut self,
        scope: &JournalScope,
        expected: AnchorPin,
        next: AnchorPin,
    ) -> EnclaveResult<()> {
        let mut state = self.0.lock().unwrap();
        if state.unavailable || state.fail_cas {
            fail!(EIO, "TEST_ANCHOR_UNAVAILABLE");
        }
        if state.scope.as_ref() != Some(scope)
            || state.pin != expected
            || expected.generation.checked_add(1) != Some(next.generation)
        {
            fail!(EACCES, "TEST_ANCHOR_CAS");
        }
        state.pin = next;
        if state.apply_then_error {
            fail!(EIO, "TEST_ANCHOR_AMBIGUOUS");
        }
        Ok(())
    }
}
fn fixture() -> (JournalScope, PublicationBinding, TufClient, SigningKey) {
    let repo = RepoBuilder::new(1, 1);
    let root = repo.root("2035-01-01T00:00:00Z").unwrap();
    let client = TufClient::bootstrap(&root).unwrap();
    let signer = repo.keys[&Role::Targets][0].clone();
    let body = serde_json::json!({"_type":"targets","spec_version":enclave_crypto::tuf::SPEC_VERSION,"version":1,
        "expires":"2030-01-01T00:00:00Z","targets":{}});
    let body =
        String::from_utf8(enclave_crypto::canonical_json::to_canonical_json_bytes(&body).unwrap())
            .unwrap();
    let scope = JournalScope {
        repository_id: [1; 32],
        signer_public: signer.verifying_key().to_bytes(),
    };
    let binding = PublicationBinding {
        publication_id: [2; 32],
        intent_constraints_sha256: [3; 32],
        policy_sha256: [4; 32],
        authority_generation: 1,
        root_envelope_sha256: hash(&root),
        role: Role::Targets,
        metadata_version: 1,
        signed_body: body,
        valid_from_unix: 100,
        valid_until_unix: 200,
    };
    (scope, binding, client, signer)
}
fn sign(key: &SigningKey, binding: &PublicationBinding) -> Vec<u8> {
    key.sign(binding.signed_body.as_bytes()).to_bytes().to_vec()
}
fn next(binding: &PublicationBinding, version: u64) -> PublicationBinding {
    let mut binding = binding.clone();
    binding.publication_id[0] = (version as u8) ^ 0x80;
    binding.metadata_version = version;
    let mut body: serde_json::Value = serde_json::from_str(&binding.signed_body).unwrap();
    body["version"] = version.into();
    binding.signed_body =
        String::from_utf8(enclave_crypto::canonical_json::to_canonical_json_bytes(&body).unwrap())
            .unwrap();
    binding
}

#[test]
fn journal_durable_issuing_precedes_callback_and_restart_returns_only_recorded_signature() {
    let root = Root::new();
    let anchor = FakeAnchor::new();
    let (scope, binding, client, key) = fixture();
    let id = binding.publication_id;
    let mut journal =
        GuardedPublicationJournal::open(&root.0, scope.clone(), anchor.boxed()).unwrap();
    journal.prepare(binding.clone()).unwrap();
    let bytes = journal
        .issue(
            &id,
            &client,
            || Ok(110),
            |exact| {
                assert_eq!(exact, &binding);
                let (_, loaded) =
                    SealedStore::open_bounded_required(&root.0, STORE_NAME, 64 * 1024 * 1024)
                        .unwrap();
                let Loaded::State(saved)=loaded else {panic!()};
                let ledger: Ledger = enclave_core::sealed::decode(&saved).unwrap();
                assert_eq!(ledger.records[&hex::encode(id)].state, IssueState::Issuing);
                assert_eq!(
                    anchor.pin(),
                    AnchorPin {
                        generation: ledger.generation,
                        ledger_sha256: hash(&saved)
                    }
                );
                Ok(sign(&key, exact))
            },
        )
        .unwrap();
    assert_eq!(bytes, sign(&key, &binding));
    assert_eq!(journal.status(&id).unwrap(), PublicationStatus::Signed);
    drop(journal);
    let mut journal = GuardedPublicationJournal::open(&root.0, scope, anchor.boxed()).unwrap();
    assert_eq!(
        journal
            .issue(
                &id,
                &client,
                || Ok(111),
                |_| panic!("a retry must never reissue")
            )
            .unwrap(),
        bytes
    );
    assert!(journal
        .issue(&id, &client, || Ok(110), |_| panic!())
        .unwrap_err()
        .is("PUBLICATION_TIME_REGRESSION"));
}
#[test]
fn journal_callback_error_and_invalid_signature_require_exact_reconciliation_without_reissue() {
    for invalid in [false, true] {
        let root = Root::new();
        let anchor = FakeAnchor::new();
        let (scope, binding, client, key) = fixture();
        let id = binding.publication_id;
        let known = sign(&key, &binding);
        let mut journal =
            GuardedPublicationJournal::open(&root.0, scope.clone(), anchor.boxed()).unwrap();
        journal.prepare(binding.clone()).unwrap();
        assert!(journal
            .issue(
                &id,
                &client,
                || Ok(110),
                |_| if invalid {
                    Ok(vec![0; 64])
                } else {
                    Err(err!(EIO, "TEST_LOST_ACK"))
                }
            )
            .is_err());
        assert_eq!(journal.status(&id).unwrap(), PublicationStatus::Uncertain);
        assert!(journal
            .issue(
                &id,
                &client,
                || Ok(111),
                |_| panic!("uncertain must not invoke signer")
            )
            .unwrap_err()
            .is("PUBLICATION_RECONCILE_REQUIRED"));
        let higher = next(&binding, 2);
        assert!(journal
            .prepare(higher)
            .unwrap_err()
            .is("PUBLICATION_ROLE_CONFLICT"));
        drop(journal);
        let mut journal = GuardedPublicationJournal::open(&root.0, scope, anchor.boxed()).unwrap();
        assert!(journal.reconcile(&id, &[0; 64]).is_err());
        journal.reconcile(&id, &known).unwrap();
        journal.reconcile(&id, &known).unwrap();
        assert_eq!(
            journal
                .issue(&id, &client, || Ok(112), |_| panic!())
                .unwrap(),
            known
        );
    }
}
#[test]
fn journal_callback_panic_reopens_uncertain_and_never_blindly_replays() {
    let root = Root::new();
    let anchor = FakeAnchor::new();
    let (scope, binding, client, _) = fixture();
    let id = binding.publication_id;
    let mut journal =
        GuardedPublicationJournal::open(&root.0, scope.clone(), anchor.boxed()).unwrap();
    journal.prepare(binding).unwrap();
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| journal.issue(
            &id,
            &client,
            || Ok(110),
            |_| panic!("synthetic crash cut")
        )))
        .is_err()
    );
    assert_eq!(journal.status(&id).unwrap(), PublicationStatus::Issuing);
    drop(journal);
    let mut journal = GuardedPublicationJournal::open(&root.0, scope, anchor.boxed()).unwrap();
    assert_eq!(journal.status(&id).unwrap(), PublicationStatus::Uncertain);
    assert!(journal
        .issue(&id, &client, || Ok(111), |_| panic!())
        .unwrap_err()
        .is("PUBLICATION_RECONCILE_REQUIRED"));
}
#[test]
fn journal_known_signature_is_retained_on_late_or_unknown_final_clock_without_release() {
    for final_clock in [Ok(200), Ok(109), Err(err!(EIO, "TEST_UNKNOWN_TIME"))] {
        let root = Root::new();
        let anchor = FakeAnchor::new();
        let (scope, binding, client, key) = fixture();
        let id = binding.publication_id;
        let mut journal =
            GuardedPublicationJournal::open(&root.0, scope.clone(), anchor.boxed()).unwrap();
        journal.prepare(binding.clone()).unwrap();
        let mut times = vec![Ok(110), Ok(110), final_clock].into_iter();
        assert!(journal
            .issue(
                &id,
                &client,
                || times.next().unwrap(),
                |exact| Ok(sign(&key, exact))
            )
            .is_err());
        assert_eq!(journal.status(&id).unwrap(), PublicationStatus::Signed);
        drop(journal);
        let journal = GuardedPublicationJournal::open(&root.0, scope, anchor.boxed()).unwrap();
        assert_eq!(
            journal.ledger.records[&hex::encode(id)].state,
            IssueState::Signed(sign(&key, &binding))
        );
    }
}
#[test]
fn journal_external_anchor_unavailable_or_ambiguous_never_invokes_signer() {
    let root = Root::new();
    let anchor = FakeAnchor::new();
    let (scope, binding, client, _) = fixture();
    let id = binding.publication_id;
    anchor.0.lock().unwrap().unavailable = true;
    assert!(GuardedPublicationJournal::open(&root.0, scope.clone(), anchor.boxed()).is_err());
    assert_eq!(std::fs::read_dir(&root.0).unwrap().count(), 0);
    anchor.0.lock().unwrap().unavailable = false;
    let mut journal =
        GuardedPublicationJournal::open(&root.0, scope.clone(), anchor.boxed()).unwrap();
    journal.prepare(binding).unwrap();
    anchor.0.lock().unwrap().apply_then_error = true;
    assert!(journal
        .issue(
            &id,
            &client,
            || Ok(110),
            |_| panic!("anchor ambiguity forbids invocation")
        )
        .is_err());
    assert!(journal
        .status(&id)
        .unwrap_err()
        .is("PUBLICATION_REOPEN_REQUIRED"));
    drop(journal);
    anchor.0.lock().unwrap().apply_then_error = false;
    let journal = GuardedPublicationJournal::open(&root.0, scope, anchor.boxed()).unwrap();
    assert_eq!(journal.status(&id).unwrap(), PublicationStatus::Uncertain);
}
#[test]
fn journal_failed_local_checkpoint_latches_and_exact_successor_repairs_as_uncertain() {
    let root = Root::new();
    let anchor = FakeAnchor::new();
    let (scope, binding, client, _) = fixture();
    let id = binding.publication_id;
    let mut journal =
        GuardedPublicationJournal::open(&root.0, scope.clone(), anchor.boxed()).unwrap();
    journal.prepare(binding).unwrap();
    let old = anchor.pin();
    let gen = root.0.join(format!("{STORE_NAME}.gen"));
    let saved = root.0.join("old-gen.fixture");
    std::fs::rename(&gen, &saved).unwrap();
    std::fs::create_dir(&gen).unwrap();
    assert!(journal
        .issue(
            &id,
            &client,
            || Ok(110),
            |_| panic!("persistence failure must precede callback")
        )
        .is_err());
    assert_eq!(anchor.pin(), old);
    assert!(journal.status(&id).is_err());
    drop(journal);
    std::fs::remove_dir(&gen).unwrap();
    std::fs::rename(&saved, &gen).unwrap();
    let journal = GuardedPublicationJournal::open(&root.0, scope, anchor.boxed()).unwrap();
    assert_eq!(journal.status(&id).unwrap(), PublicationStatus::Uncertain);
    assert!(anchor.pin().generation > old.generation);
}
#[test]
fn journal_signature_checkpoint_failure_recovers_known_signature_without_callback() {
    let root = Root::new();
    let anchor = FakeAnchor::new();
    let (scope, binding, client, key) = fixture();
    let id = binding.publication_id;
    let mut journal =
        GuardedPublicationJournal::open(&root.0, scope.clone(), anchor.boxed()).unwrap();
    journal.prepare(binding.clone()).unwrap();
    let gen = root.0.join(format!("{STORE_NAME}.gen"));
    let saved = root.0.join("old-gen.fixture");
    assert!(journal
        .issue(
            &id,
            &client,
            || Ok(110),
            |exact| {
                std::fs::rename(&gen, &saved).unwrap();
                std::fs::create_dir(&gen).unwrap();
                Ok(sign(&key, exact))
            }
        )
        .is_err());
    drop(journal);
    std::fs::remove_dir(&gen).unwrap();
    std::fs::rename(&saved, &gen).unwrap();
    let mut journal = GuardedPublicationJournal::open(&root.0, scope, anchor.boxed()).unwrap();
    assert_eq!(journal.status(&id).unwrap(), PublicationStatus::Signed);
    assert_eq!(
        journal
            .issue(&id, &client, || Ok(111), |_| panic!())
            .unwrap(),
        sign(&key, &binding)
    );
}
#[test]
fn journal_whole_local_store_restore_or_anchor_hash_divergence_refuses() {
    for divergent_hash in [false, true] {
        let root = Root::new();
        let anchor = FakeAnchor::new();
        let (scope, binding, client, key) = fixture();
        let id = binding.publication_id;
        let mut journal =
            GuardedPublicationJournal::open(&root.0, scope.clone(), anchor.boxed()).unwrap();
        journal.prepare(binding).unwrap();
        let snapshot: Vec<_> = std::fs::read_dir(&root.0)
            .unwrap()
            .map(|entry| {
                let path = entry.unwrap().path();
                let bytes = std::fs::read(&path).unwrap();
                (path, bytes)
            })
            .collect();
        journal
            .issue(&id, &client, || Ok(110), |exact| Ok(sign(&key, exact)))
            .unwrap();
        drop(journal);
        if divergent_hash {
            anchor.0.lock().unwrap().pin.ledger_sha256[0] ^= 1;
        } else {
            for (path, bytes) in snapshot {
                std::fs::write(path, bytes).unwrap();
            }
        }
        assert!(
            GuardedPublicationJournal::open(&root.0, scope, anchor.boxed())
                .err()
                .unwrap()
                .is("PUBLICATION_ANCHOR_ROLLBACK")
        );
    }
}
#[test]
fn journal_immutable_binding_body_root_key_version_and_expiry_checks_precede_signing() {
    let root = Root::new();
    let anchor = FakeAnchor::new();
    let (scope, binding, client, key) = fixture();
    let id = binding.publication_id;
    let mut journal = GuardedPublicationJournal::open(&root.0, scope, anchor.boxed()).unwrap();
    journal.prepare(binding.clone()).unwrap();
    let mut changed = binding.clone();
    changed.policy_sha256[0] ^= 1;
    assert!(journal
        .prepare(changed)
        .unwrap_err()
        .is("PUBLICATION_BINDING_CONFLICT"));
    let unrelated = RepoBuilder::new(1, 1);
    let other = TufClient::bootstrap(&unrelated.root("2035-01-01T00:00:00Z").unwrap()).unwrap();
    assert!(journal
        .issue(&id, &other, || Ok(110), |_| panic!())
        .unwrap_err()
        .is("PUBLICATION_ROOT_CHANGED"));
    for mutation in 0..5 {
        let mut bad = next(&binding, 2);
        match mutation {
            0 => bad.signed_body.push(' '),
            1 => bad.metadata_version = 3,
            2 => bad.role = Role::Snapshot,
            3 => bad.valid_until_unix = i64::MAX,
            _ => {
                bad.signed_body =
                    bad.signed_body
                        .replacen("\"version\":2", "\"version\":1,\"version\":2", 1)
            }
        }
        assert!(journal.prepare(bad).is_err());
    }
    assert_eq!(journal.status(&id).unwrap(), PublicationStatus::Ready);
    let higher = next(&binding, 2);
    journal.prepare(higher.clone()).unwrap();
    assert!(journal
        .issue(&id, &client, || Ok(110), |_| panic!())
        .unwrap_err()
        .is("PUBLICATION_ROLE_CONFLICT"));
    journal
        .issue(
            &higher.publication_id,
            &client,
            || Ok(110),
            |exact| Ok(sign(&key, exact)),
        )
        .unwrap();
    let mut same_version = higher.clone();
    same_version.publication_id[0] ^= 64;
    assert!(journal
        .prepare(same_version)
        .unwrap_err()
        .is("PUBLICATION_ROLE_CONFLICT"));
    for now in [99, 200] {
        assert!(journal
            .issue(&id, &client, || Ok(now), |_| panic!())
            .is_err());
    }
}

#[test]
fn journal_anchor_rejection_before_callback_repairs_only_exact_saved_successor() {
    let root = Root::new();
    let anchor = FakeAnchor::new();
    let (scope, binding, client, _) = fixture();
    let id = binding.publication_id;
    let mut journal =
        GuardedPublicationJournal::open(&root.0, scope.clone(), anchor.boxed()).unwrap();
    journal.prepare(binding).unwrap();
    let before = anchor.pin();
    anchor.0.lock().unwrap().fail_cas = true;
    assert!(journal
        .issue(
            &id,
            &client,
            || Ok(110),
            |_| panic!("failed anchor must not invoke signer")
        )
        .is_err());
    assert_eq!(anchor.pin(), before);
    assert!(journal.status(&id).is_err());
    drop(journal);
    anchor.0.lock().unwrap().fail_cas = false;
    let journal = GuardedPublicationJournal::open(&root.0, scope, anchor.boxed()).unwrap();
    assert_eq!(journal.status(&id).unwrap(), PublicationStatus::Uncertain);
}
#[test]
fn journal_current_adopted_floor_and_exact_root_signed_preimage_refuse_stale_signing() {
    let repo = RepoBuilder::new(1, 1);
    let root_bytes = repo.root("2035-01-01T00:00:00Z").unwrap();
    let targets = repo
        .targets(2, "2030-01-01T00:00:00Z", BTreeMap::new())
        .unwrap();
    let snapshot = repo
        .snapshot(2, "2030-01-01T00:00:00Z", 2, &targets)
        .unwrap();
    let timestamp = repo
        .timestamp(2, "2030-01-01T00:00:00Z", 2, &snapshot)
        .unwrap();
    let mut client = TufClient::bootstrap(&root_bytes).unwrap();
    client
        .refresh(&timestamp, &snapshot, &targets, 110)
        .unwrap();
    let (mut scope, mut binding, _, _) = fixture();
    scope.signer_public = repo.keys[&Role::Targets][0].verifying_key().to_bytes();
    binding.root_envelope_sha256 = hash(&root_bytes);
    let root = Root::new();
    let anchor = FakeAnchor::new();
    let mut journal = GuardedPublicationJournal::open(&root.0, scope, anchor.boxed()).unwrap();
    journal.prepare(binding.clone()).unwrap();
    assert!(journal
        .issue(&binding.publication_id, &client, || Ok(110), |_| panic!())
        .unwrap_err()
        .is("PUBLICATION_ADOPTED_VERSION"));
    let mut raw: serde_json::Value = serde_json::from_slice(&root_bytes).unwrap();
    raw["signed"]["uncovered_root_member"] = true.into();
    let forged_bytes = serde_json::to_vec(&raw).unwrap();
    let forged = TufClient::bootstrap(&forged_bytes).unwrap();
    let mut next = next(&binding, 3);
    next.root_envelope_sha256 = hash(&forged_bytes);
    journal.prepare(next.clone()).unwrap();
    assert!(journal
        .issue(&next.publication_id, &forged, || Ok(110), |_| panic!())
        .unwrap_err()
        .is("PUBLICATION_ROOT_PREIMAGE"));
}

#[test]
fn journal_durable_io_consumes_original_time_window_before_callback_and_release() {
    for delay_before_callback in [false, true] {
        let root = Root::new();
        let anchor = FakeAnchor::new();
        let (scope, binding, client, key) = fixture();
        let id = binding.publication_id;
        let mut journal = GuardedPublicationJournal::open(&root.0, scope, anchor.boxed()).unwrap();
        journal.prepare(binding).unwrap();
        let mut times = if delay_before_callback {
            vec![110, 200]
        } else {
            vec![110, 110, 110, 200]
        }
        .into_iter();
        assert!(journal
            .issue(
                &id,
                &client,
                || Ok(times.next().unwrap()),
                |exact| {
                    assert!(
                        !delay_before_callback,
                        "expiry after issue persistence must precede callback"
                    );
                    Ok(sign(&key, exact))
                }
            )
            .unwrap_err()
            .is("PUBLICATION_EXPIRED"));
        assert_eq!(
            journal.status(&id).unwrap(),
            if delay_before_callback {
                PublicationStatus::Uncertain
            } else {
                PublicationStatus::Signed
            }
        );
    }
}

#[test]
fn journal_exclusive_owner_and_full_retained_history_never_reset_or_evict() {
    let root = Root::new();
    let anchor = FakeAnchor::new();
    let (scope, binding, _, _) = fixture();
    let mut journal =
        GuardedPublicationJournal::open(&root.0, scope.clone(), anchor.boxed()).unwrap();
    assert!(
        GuardedPublicationJournal::open(&root.0, scope.clone(), anchor.boxed())
            .err()
            .unwrap()
            .is("STATE_DIRECTORY_BUSY")
    );
    journal.prepare(binding.clone()).unwrap();
    for version in 2..=MAX_RECORDS as u64 {
        journal.prepare(next(&binding, version)).unwrap();
    }
    assert!(journal
        .prepare(next(&binding, MAX_RECORDS as u64 + 1))
        .unwrap_err()
        .is("PUBLICATION_RECORD_LIMIT"));
    let pin = anchor.pin();
    drop(journal);
    let journal = GuardedPublicationJournal::open(&root.0, scope.clone(), anchor.boxed()).unwrap();
    assert_eq!(journal.ledger.records.len(), MAX_RECORDS);
    assert_eq!(anchor.pin(), pin);
    drop(journal);
    std::fs::remove_file(root.0.join(format!("{STORE_NAME}.sealed"))).unwrap();
    assert!(GuardedPublicationJournal::open(&root.0, scope, anchor.boxed()).is_err());
    assert_eq!(anchor.pin(), pin);
}

#[test]
fn journal_final_clock_highwater_fences_live_regression_and_folds_into_next_checkpoint() {
    let root = Root::new();
    let anchor = FakeAnchor::new();
    let (scope, binding, client, key) = fixture();
    let id = binding.publication_id;
    let mut journal =
        GuardedPublicationJournal::open(&root.0, scope.clone(), anchor.boxed()).unwrap();
    journal.prepare(binding).unwrap();
    let mut times = vec![110, 120, 125, 130].into_iter();
    let known = journal
        .issue(
            &id,
            &client,
            || Ok(times.next().unwrap()),
            |exact| Ok(sign(&key, exact)),
        )
        .unwrap();
    assert_eq!(journal.ledger.last_observed_unix, 125);
    assert_eq!(journal.observed_unix.get(), 130);
    assert!(journal
        .issue(&id, &client, || Ok(127), |_| panic!())
        .unwrap_err()
        .is("PUBLICATION_TIME_REGRESSION"));
    assert_eq!(
        journal
            .issue(
                &id,
                &client,
                || Ok(131),
                |_| panic!("known signature must not reissue")
            )
            .unwrap(),
        known
    );
    assert_eq!(journal.ledger.last_observed_unix, 131);
    drop(journal);
    let mut journal = GuardedPublicationJournal::open(&root.0, scope, anchor.boxed()).unwrap();
    assert!(journal
        .issue(&id, &client, || Ok(130), |_| panic!())
        .unwrap_err()
        .is("PUBLICATION_TIME_REGRESSION"));
}
