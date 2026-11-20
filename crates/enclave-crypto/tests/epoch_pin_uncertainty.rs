//! Public API save-failure tests on exclusively owned directories. Controlled
//! rename faults are not observed crashes, disk failures or SEP acceptance.
#![cfg(unix)]

use enclave_core::error::Errno;
use enclave_core::sealed::{Loaded, SealedStore};
use enclave_core::seq::new_boot_epoch_id;
use enclave_crypto::epoch::{EpochSigner, EpochVerifier};
use std::fs;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::PathBuf;
use std::sync::{Arc, Barrier};

struct OwnedDirectory(PathBuf);

impl OwnedDirectory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("mc-ep-{}", new_boot_epoch_id()));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }

    fn remove(self) -> bool { fs::remove_dir_all(&self.0).is_ok() }
}

impl Drop for OwnedDirectory {
    fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); }
}

// The file names, modes and exact bytes include failed-save temporary files.
// Never print the snapshot: sealing.key is software fixture key material.
fn snapshot(directory: &OwnedDirectory) -> Vec<(String, u32, Vec<u8>)> {
    let mut result = fs::read_dir(&directory.0).unwrap().map(|entry| {
        let entry = entry.unwrap();
        assert!(entry.file_type().unwrap().is_file());
        let mode = entry.metadata().unwrap().permissions().mode() & 0o7777;
        assert_eq!(mode, 0o600);
        (entry.file_name().into_string().unwrap(), mode, fs::read(entry.path()).unwrap())
    }).collect::<Vec<_>>();
    result.sort_by(|a, b| a.0.cmp(&b.0));
    result
}

fn sealed_generation(directory: &OwnedDirectory) -> Option<u64> {
    let path = directory.0.join("epoch-signer.sealed");
    if !path.is_file() { return None; }
    let envelope: serde_json::Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    Some(envelope["generation"].as_u64().unwrap())
}

fn failed_pin_retry(checkpoint: bool, different_signer: bool) {
    let directory = OwnedDirectory::new();
    let verifier = EpochVerifier::open(Some(&directory.0)).unwrap();
    let first = EpochSigner::random();
    let fault = directory.0.join(if checkpoint { "epoch-signer.gen" } else { "epoch-signer.sealed" });
    fs::DirBuilder::new().mode(0o700).create(&fault).unwrap();
    let initial_error = verifier.check(&first.sign(&new_boot_epoch_id())).unwrap_err();
    assert_eq!(initial_error.errno, Errno::EIO);
    assert!(initial_error.is("STATE_RENAME"), "fixture must reach actual rename failure");
    assert!(verifier.pinned().is_none());
    assert!(!directory.0.join("epoch-signer.gen").is_file());
    if checkpoint {
        let envelope: serde_json::Value = serde_json::from_slice(
            &fs::read(directory.0.join("epoch-signer.sealed")).unwrap()).unwrap();
        assert_eq!(envelope["generation"], 1);
        let body: serde_json::Value = serde_json::from_str(envelope["body"].as_str().unwrap()).unwrap();
        assert_eq!(body["signer_public_key"], hex::encode(first.public_key()));
    }
    fs::remove_dir(&fault).unwrap();
    let before = snapshot(&directory);
    let generation_before = sealed_generation(&directory);
    let second = EpochSigner::random();
    let retry = if different_signer { &second } else { &first };
    let result = verifier.check(&retry.sign(&new_boot_epoch_id()));
    let accepted = result.is_ok();
    let retry_reason = result.as_ref().err().map(|e| e.reason.clone()).unwrap_or_default();
    let fenced = result.as_ref().is_err_and(|e| e.errno == Errno::EIO && e.is("EPOCH_PIN_UNCERTAIN"));
    let preserved = snapshot(&directory) == before;
    let unpinned = verifier.pinned().is_none();
    // A second attempt cannot clear a live-object fence either.
    let again = verifier.check(&first.sign(&new_boot_epoch_id()));
    let still_fenced = again.as_ref().is_err_and(|e| e.is("EPOCH_PIN_UNCERTAIN"));
    let still_preserved = snapshot(&directory) == before;
    let generation_after = sealed_generation(&directory);
    drop(verifier);
    if checkpoint && preserved && still_preserved {
        // Existing restart rules refuse published generation1 without checkpoint.
        assert!(EpochVerifier::open(Some(&directory.0)).unwrap_err().is("EPOCH_PIN_STATE"));
    }
    let cleaned = directory.remove();
    eprintln!("EPOCH_PIN_ORACLE checkpoint={checkpoint} different={different_signer} initial=STATE_RENAME accepted={accepted} retry_reason={retry_reason} generation_before={generation_before:?} generation_after={generation_after:?} fenced={fenced} preserved={preserved} unpinned={unpinned} still_fenced={still_fenced} still_preserved={still_preserved} cleaned={cleaned}");
    assert!(cleaned, "owned fixture cleanup");
    assert!(fenced && preserved && unpinned && still_fenced && still_preserved,
        "failed persistent first pin must fence live retries without writes");
}

#[test]
fn checkpoint_failure_fences_same_signer_retry_without_rewriting() { failed_pin_retry(true, false); }

#[test]
fn checkpoint_failure_fences_different_signer_retry_without_repinning() { failed_pin_retry(true, true); }

#[test]
fn state_publication_failure_also_fences_live_retry() { failed_pin_retry(false, true); }

#[test]
fn uncertain_verifier_fences_all_concurrent_valid_retry_callers() {
    let directory = OwnedDirectory::new();
    let verifier = Arc::new(EpochVerifier::open(Some(&directory.0)).unwrap());
    let fault = directory.0.join("epoch-signer.gen");
    fs::DirBuilder::new().mode(0o700).create(&fault).unwrap();
    let first = EpochSigner::random();
    let initial_error = verifier.check(&first.sign(&new_boot_epoch_id())).unwrap_err();
    assert_eq!(initial_error.errno, Errno::EIO);
    assert!(initial_error.is("STATE_RENAME"));
    assert!(verifier.pinned().is_none());
    assert_eq!(sealed_generation(&directory), Some(1));
    let envelope: serde_json::Value = serde_json::from_slice(
        &fs::read(directory.0.join("epoch-signer.sealed")).unwrap()).unwrap();
    let body: serde_json::Value = serde_json::from_str(envelope["body"].as_str().unwrap()).unwrap();
    assert_eq!(body["signer_public_key"], hex::encode(first.public_key()));
    fs::remove_dir(&fault).unwrap();
    let before = snapshot(&directory);
    let barrier = Arc::new(Barrier::new(5));
    let workers = (0..4).map(|n| {
        let verifier = Arc::clone(&verifier);
        let barrier = Arc::clone(&barrier);
        let epoch = if n % 2 == 0 { first.sign(&new_boot_epoch_id()) }
            else { EpochSigner::random().sign(&new_boot_epoch_id()) };
        std::thread::spawn(move || { barrier.wait(); verifier.check(&epoch) })
    }).collect::<Vec<_>>();
    barrier.wait();
    let results = workers.into_iter().map(|w| w.join().unwrap()).collect::<Vec<_>>();
    let refused = results.iter().filter(|r| r.as_ref().is_err_and(|e| e.is("EPOCH_PIN_UNCERTAIN"))).count();
    let accepted = results.iter().filter(|r| r.is_ok()).count();
    let preserved = snapshot(&directory) == before;
    let unpinned = verifier.pinned().is_none();
    drop(verifier);
    let cleaned = directory.remove();
    eprintln!("EPOCH_PIN_CONCURRENT callers=4 refused={refused} accepted={accepted} preserved={preserved} unpinned={unpinned} cleaned={cleaned}");
    assert!(cleaned);
    assert!(refused == 4 && preserved && unpinned, "all valid concurrent retry callers must remain fenced");
}

#[test]
fn persistent_success_reloads_authenticated_pin_and_never_rewrites_on_checks() {
    let directory = OwnedDirectory::new();
    let first = EpochSigner::random();
    let verifier = EpochVerifier::open(Some(&directory.0)).unwrap();
    verifier.check(&first.sign(&new_boot_epoch_id())).unwrap();
    assert_eq!(verifier.pinned(), Some(first.public_key()));
    let before = snapshot(&directory);
    verifier.check(&first.sign(&new_boot_epoch_id())).unwrap();
    assert!(verifier.check(&EpochSigner::random().sign(&new_boot_epoch_id())).unwrap_err().is("EPOCH_SIGNER_CHANGED"));
    drop(verifier);
    let verifier = EpochVerifier::open(Some(&directory.0)).unwrap();
    assert_eq!(verifier.pinned(), Some(first.public_key()));
    verifier.check(&first.sign(&new_boot_epoch_id())).unwrap();
    assert!(snapshot(&directory) == before, "successful checks and reload preserve exact files");
    let (store, loaded) = SealedStore::open(&directory.0, "epoch-signer").unwrap();
    assert_eq!(store.generation(), 1);
    assert!(matches!(loaded, Loaded::State(_)));
    drop(store);
    drop(verifier);
    assert!(directory.remove());
}

#[test]
fn invalid_signature_does_not_pin_or_fence_and_volatile_success_still_pins() {
    let directory = OwnedDirectory::new();
    let verifier = EpochVerifier::open(Some(&directory.0)).unwrap();
    let signer = EpochSigner::random();
    let mut invalid = signer.sign(&new_boot_epoch_id());
    invalid.boot_epoch_id = new_boot_epoch_id();
    let before = snapshot(&directory);
    assert!(verifier.check(&invalid).unwrap_err().is("EPOCH_SIGNATURE_INVALID"));
    assert!(verifier.pinned().is_none());
    assert!(snapshot(&directory) == before);
    verifier.check(&signer.sign(&new_boot_epoch_id())).unwrap();
    let volatile = EpochVerifier::volatile();
    assert!(volatile.check(&invalid).unwrap_err().is("EPOCH_SIGNATURE_INVALID"));
    volatile.check(&signer.sign(&new_boot_epoch_id())).unwrap();
    volatile.check(&signer.sign(&new_boot_epoch_id())).unwrap();
    assert_eq!(volatile.pinned(), Some(signer.public_key()));
    assert!(volatile.check(&EpochSigner::random().sign(&new_boot_epoch_id())).unwrap_err().is("EPOCH_SIGNER_CHANGED"));
    drop(verifier);
    assert!(directory.remove());
}
