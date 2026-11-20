//! Actual public-core retention admission regressions; exact execution recorded separately.
//! Only simulated hardware; no receiver, installed identity or physical budget claim.
use enclave_core::{daemon::DaemonId, ipc::{self, PeerCredentials}, profile::Profile};
use enclave_custody_vaultd::service::{VaultConfig, VaultHardware, VaultRequest, VaultResponse, VaultService};
use std::{fs, os::unix::fs::DirBuilderExt, path::PathBuf, sync::Arc};
const MAX_ENTRIES: usize = 4096;
const MAX_BYTES: usize = 2 * 1024 * 1024;
// Proposed stable named refusal; a string check uses no missing new API.
const CAPACITY: &str = "WITNESS_RETENTION_CAPACITY";
struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let path = std::env::temp_dir().canonicalize().unwrap()
            .join(format!("pr{}-{:x}", std::process::id(), enclave_core::rng::u64()));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap(); Self(path)
    }
}
impl Drop for Directory { fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); } }
struct Fixture { service: Arc<VaultService>, _directory: Directory, peer: PeerCredentials, epoch: String }
impl Fixture {
    fn new(persistent: bool) -> Self {Self::with_profile(persistent,Profile::L2)}
    fn with_profile(persistent:bool,profile:Profile)->Self {
        let directory = Directory::new();
        let service = VaultService::start(
            VaultConfig { profile, state_dir: persistent.then(|| directory.0.join("state")),
                socket_dir: None, ..VaultConfig::default() },
            VaultHardware::simulated(profile, enclave_crypto::time::now_unix()).unwrap(),
        ).unwrap();
        let peer = PeerCredentials::local(ipc::geteuid(), unsafe { libc::getegid() });
        // A real non-swarmesque in-process application peer; no forged UDS UID.
        assert_ne!(peer.uid, DaemonId::SwarmSync.uid());
        let VaultResponse::Epoch(epoch) = service.handle(&peer, VaultRequest::BootEpoch).unwrap() else { panic!("epoch response"); };
        Self { service, _directory: directory, peer, epoch: epoch.boot_epoch_id }
    }
    fn scrub(&self, text: String) -> enclave_core::EnclaveResult<VaultResponse> {
        self.service.handle(&self.peer, VaultRequest::ScrubText { text, bulk_set: false, grant: None })
    }
    fn accept(&self, text: String) {
        let expected_len = text.len();
        let response = self.scrub(text).unwrap();
        assert!(matches!(response, VaultResponse::Text(ref body) if body.len() == expected_len && body.bytes().all(|b|b == b'x')),
            "fixture must establish an ordinary successful no-PII public release");
    }
    fn snapshot(&self) -> Snapshot {
        let VaultResponse::Witness { folds, next_slot } = self.service.handle(&self.peer,
            VaultRequest::FetchWitness { boot_epoch_id: self.epoch.clone(), s_start: 0, s_end: u64::MAX }).unwrap()
            else { panic!("witness response"); };
        // Bounded synthetic fixture only. Never print bytes, commitments, MACs,
        // epoch, keys or this digest. Temporary fetched clones drop on return.
        assert!(folds.len() <= MAX_ENTRIES);
        let mut hash = blake3::Hasher::new(); let mut logical = 0usize;
        for fold in &folds {
            logical = logical.checked_add(fold.scrubbed.len()).unwrap();
            assert!(logical <= MAX_BYTES);
            hash.update(&fold.rpc_seq_u64.to_le_bytes());
            hash.update(&(fold.scrubbed.len() as u64).to_le_bytes());
            hash.update(&fold.scrubbed);
            hash.update(&(fold.c_raw.len() as u64).to_le_bytes()); hash.update(fold.c_raw.as_bytes());
            hash.update(&(fold.h_ingress_mac.len() as u64).to_le_bytes()); hash.update(fold.h_ingress_mac.as_bytes());
        }
        Snapshot { count: folds.len(), logical, digest: *hash.finalize().as_bytes(),
            first: folds.first().map(|w|w.rpc_seq_u64), next_slot }
    }
    fn tombstone_released_refused(&self, slot: u64) -> bool {
        self.service.handle(&self.peer, VaultRequest::CoSignTombstone {
            slot_rpc_seq: slot, boot_epoch_id: self.epoch.clone(),
        }).as_ref().is_err_and(|e|e.is("TOMBSTONE_SLOT_RELEASED"))
    }
    fn candidate_not_released(&self, slot: u64) -> bool {
        // A refused call may have issued this slot already; it may instead
        // refuse earlier. Either unknown or legitimate terminal nonrelease is
        // acceptable. This final check runs after witness preservation checks.
        match self.service.handle(&self.peer, VaultRequest::CoSignTombstone {
            slot_rpc_seq: slot, boot_epoch_id: self.epoch.clone(),
        }) {
            Ok(VaultResponse::TombstoneSignature { .. }) => true,
            Err(e) if e.is("TOMBSTONE_SLOT_UNKNOWN") => true,
            _ => false,
        }
    }
    fn assert_overflow(&self, kind: &str, before: Snapshot, payload: String) {
        let attempted = self.scrub(payload);
        let admitted = matches!(&attempted, Ok(VaultResponse::Text(_)));
        let refused = attempted.as_ref().is_err_and(|e|e.is(CAPACITY));
        drop(attempted);
        let after = self.snapshot();
        let preserved = (before.count, before.logical, before.digest) == (after.count, after.logical, after.digest);
        let prior_released = self.tombstone_released_refused(before.first.unwrap());
        let candidate_not_released = self.candidate_not_released(before.next_slot);
        // Preserve observations on old product before the intended assertion.
        println!("PRODUCER_RETENTION_CAPACITY kind={kind} admitted={admitted} refused={refused} before_entries={} after_entries={} before_bytes={} after_bytes={} prior_preserved={preserved} candidate_not_released={candidate_not_released} prior_release_tombstone_refused={prior_released}",
            before.count, after.count, before.logical, after.logical);
        assert_eq!((refused, preserved, candidate_not_released, prior_released), (true,true,true,true),
            "capacity must refuse new local release without losing any prior unproved witness or recording new release");
    }
}
#[derive(Debug)]
struct Snapshot { count: usize, logical: usize, digest: [u8;32], first: Option<u64>, next_slot: u64 }
fn actual_entry_limit(profile:Profile) {
    // Existing public ephemeral mode avoids4096fsyncs; byte case is persistent.
    let fixture=Fixture::with_profile(false,profile);
    for _ in 0..MAX_ENTRIES {fixture.accept(String::new());}
    for _ in 0..2 {
        let before=fixture.snapshot();assert_eq!((before.count,before.logical),(MAX_ENTRIES,0));
        fixture.assert_overflow("entry",before,String::new());
    }
}
#[test]
fn producer_retention_entry_overflow_refuses_and_preserves_all_prior_released_witnesses() {
    actual_entry_limit(Profile::L2);
}
#[test]
fn producer_retention_l1_actual_entry_limit_preserves_all_prior_witnesses_on_repeated_refusal() {
    actual_entry_limit(Profile::L1);
}
#[test]
fn producer_retention_l3_actual_entry_limit_preserves_all_prior_witnesses_on_repeated_refusal() {
    actual_entry_limit(Profile::L3);
}
#[test]
fn producer_retention_actual_tokenize_at_full_queue_refuses_without_witness_loss_or_new_release() {
    use enclave_custody_vaultd::service::TokenizeItem;
    let fixture=Fixture::new(false);
    for _ in 0..MAX_ENTRIES {fixture.accept(String::new());}
    let before=fixture.snapshot();
    let attempted=fixture.service.handle(&fixture.peer,VaultRequest::Tokenize {
        items:vec![TokenizeItem{value:"fixture@example.test".into(),declared:None}],
        bulk_set:false,grant:None,
    });
    assert!(attempted.as_ref().is_err_and(|e|e.is(CAPACITY)));
    let after=fixture.snapshot();
    assert!((before.count,before.logical,before.digest)==(after.count,after.logical,after.digest),"prior witness snapshot changed");
    assert!(fixture.candidate_not_released(before.next_slot));
    assert!(fixture.tombstone_released_refused(before.first.unwrap()));
    // Earlier slot issuance/vault entry/stat changes are outside this oracle.
}
#[test]
fn producer_retention_direct_public_api_exact_byte_boundary_then_excess_refuses_without_old_loss() {
    let fixture = Fixture::new(true);
    fixture.accept("x".to_owned());
    // Three total release calls isolate byte admission with the real2MiB
    // policy. This direct public-handle defense case intentionally exceeds
    // generic UID703's256KiB request cap; it claims no transport acceptance.
    fixture.accept("x".repeat(MAX_BYTES-1));
    let before = fixture.snapshot(); assert_eq!((before.count,before.logical),(2,MAX_BYTES));
    fixture.assert_overflow("byte-direct-public-api", before, "x".to_owned());
    drop(fixture);
}
