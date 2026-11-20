//! GAP-15 on hardware: the real Secure Enclave agent. Runs only on macOS with
//! `depot_HW=1` (CI's Apple-silicon VMs have no SEP), e.g.
//!
//! ```text
//! depot_HW=1 cargo test -p enclave-custody-vaultd --test hw_sep -- --nocapture
//! ```

#[cfg(target_os = "macos")]
#[test]
fn darwin_sep_epoch_key_persists_signs_and_rejects_foreign_blobs() {
    use enclave_custody_vaultd::ceremony::PrfTier;
    use enclave_custody_vaultd::darwin_sep::DarwinSep;
    use enclave_custody_vaultd::sep::SepAgent;
    if std::env::var("depot_HW").as_deref() != Ok("1") {
        eprintln!("hw_sep: skipped (set depot_HW=1 on an Apple-silicon Mac)");
        return;
    }
    let d = std::env::temp_dir().join(format!("depot-hw-sep-{}", enclave_core::rng::u64()));
    let sep = DarwinSep::open(&d).unwrap();
    let pk = sep.epoch_public_key();
    assert_eq!(pk.len(), 65, "SEC1 uncompressed P-256");
    // The real SEP signs a BootEpoch that the GAP-27 verifier accepts.
    let id = enclave_core::seq::new_boot_epoch_id();
    let be = enclave_core::seq::BootEpoch {
        boot_epoch_id: id.clone(),
        signature: sep
            .sign_epoch(&enclave_core::seq::epoch_signing_message(&id))
            .unwrap(),
        signer_public_key: pk.clone(),
    };
    enclave_crypto::epoch::verify(&be).unwrap();
    // The key survives a restart: the blob re-opens to the same key.
    drop(sep);
    let again = DarwinSep::open(&d).unwrap();
    assert_eq!(again.epoch_public_key(), pk);
    let id2 = enclave_core::seq::new_boot_epoch_id();
    let be2 = enclave_core::seq::BootEpoch {
        boot_epoch_id: id2.clone(),
        signature: again
            .sign_epoch(&enclave_core::seq::epoch_signing_message(&id2))
            .unwrap(),
        signer_public_key: pk.clone(),
    };
    enclave_crypto::epoch::verify(&be2).unwrap();
    // Tier keys wait for enrollment; they never fall back.
    assert!(again
        .ecdh_share(PrfTier::A3)
        .unwrap_err()
        .is("ENROLLMENT_REQUIRED"));
    // Another valid SEP key's blob in place of ours is refused (the stored
    // public key is the pin).
    let other = std::env::temp_dir().join(format!("depot-hw-sep-{}", enclave_core::rng::u64()));
    drop(DarwinSep::open(&other).unwrap());
    std::fs::copy(other.join("epoch.sepkey"), d.join("epoch.sepkey")).unwrap();
    assert!(DarwinSep::open(&d).unwrap_err().is("SEP_KEY_MISMATCH"));
    // A half-present key is refused rather than silently re-created.
    std::fs::remove_file(d.join("epoch.pub")).unwrap();
    assert!(DarwinSep::open(&d).unwrap_err().is("SEP_KEY_STATE"));
    for x in [d, other] {
        let _ = std::fs::remove_dir_all(x);
    }
}
