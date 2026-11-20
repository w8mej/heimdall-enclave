//! DEFECT-F-96: generation must commit to real inputs and actual grant authority.
use enclave_core::profile::Profile;
use mcp_enclave::ctl::tuf_generate_host_config_at;
#[test]
fn missing_inputs_fail_and_complete_inputs_hash_actual_bytes() {
    let root = std::env::temp_dir().join(format!("mcpmac-f96-{}", enclave_core::rng::u64()));
    std::fs::create_dir(&root).unwrap();
    let generate = |key| tuf_generate_host_config_at(Profile::L2, key, &root, &root);
    assert!(
        generate(None).is_err(),
        "never generate a throwaway grant key"
    );
    let paths = [
        "schemas/enclave.lock.toml",
        "assets/calibration.corpus",
        "packaging/fido-mds/yubico.json",
    ];
    for path in paths {
        assert!(generate(Some("42".repeat(32))).is_err());
        let file = root.join(path);
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        std::fs::write(file, format!("fixture for {path}")).unwrap();
    }
    let config = generate(Some("42".repeat(32))).unwrap();
    for (path, digest) in paths.into_iter().zip([
        config.mcp_lock_digest,
        config.calibration_corpus_digest,
        config.fido_mds_allowlist_digest,
    ]) {
        assert_eq!(
            digest,
            hex::encode(blake3::hash(&std::fs::read(root.join(path)).unwrap()).as_bytes())
        );
    }
    std::fs::write(root.join(paths[1]), b"").unwrap();
    assert!(generate(Some("42".repeat(32))).is_err());
    std::fs::remove_dir_all(root).unwrap();
}
