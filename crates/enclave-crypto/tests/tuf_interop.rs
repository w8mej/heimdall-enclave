//! Interoperability tests between Rust TUF client and python-tuf fixtures.
//! GAP-31 / Prompt 1A.

use std::fs;
use std::path::Path;
use std::process::Command;

use enclave_crypto::tuf::{RepoBuilder, TufClient};

const FIXTURES_DIR: &str = "tests/fixtures/tuf";
const NOW: i64 = 1_793_884_860; // 2026-11-05 (valid for future fixtures, expired for 2020)

fn fixture_path(sub: &str) -> String {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    format!("{manifest_dir}/{FIXTURES_DIR}/{sub}")
}

#[test]
fn test_fixture_keyid_matches_python_tuf() {
    let p = fixture_path("root_rotation/1.root.json");
    let bytes = fs::read(&p).unwrap();
    let root: enclave_crypto::tuf::Signed<enclave_crypto::tuf::RootMeta> =
        serde_json::from_slice(&bytes).unwrap();

    for (kid, key) in &root.signed.keys {
        assert_eq!(
            key.keyid().unwrap(),
            *kid,
            "Rust key ID must match python-tuf key ID in root"
        );
    }
}

#[test]
fn test_root_rotation() {
    let base = fixture_path("root_rotation");
    let r1 = fs::read(format!("{base}/1.root.json")).unwrap();
    let r2 = fs::read(format!("{base}/2.root.json")).unwrap();
    let r3 = fs::read(format!("{base}/3.root.json")).unwrap();
    let ts = fs::read(format!("{base}/timestamp.json")).unwrap();
    let snap = fs::read(format!("{base}/snapshot.json")).unwrap();
    let tg = fs::read(format!("{base}/targets.json")).unwrap();

    let mut client = TufClient::bootstrap(&r1).unwrap();
    assert_eq!(client.root().version, 1);

    client.update_root(&r2).unwrap();
    assert_eq!(client.root().version, 2);

    client.update_root(&r3).unwrap();
    assert_eq!(client.root().version, 3);

    client.refresh(&ts, &snap, &tg, NOW).unwrap();

    let target_bytes = fs::read(format!("{base}/model.safetensors")).unwrap();
    client
        .verify_target("model.safetensors", &target_bytes, NOW)
        .unwrap();
}

#[test]
fn test_delegations() {
    let base = fixture_path("delegations");
    let root = fs::read(format!("{base}/root.json")).unwrap();
    let ts = fs::read(format!("{base}/timestamp.json")).unwrap();
    let snap = fs::read(format!("{base}/snapshot.json")).unwrap();
    let tg = fs::read(format!("{base}/targets.json")).unwrap();
    let models_meta = fs::read(format!("{base}/models.json")).unwrap();

    let mut client = TufClient::bootstrap(&root).unwrap();
    client.refresh(&ts, &snap, &tg, NOW).unwrap();

    // Verify delegated targets metadata
    let del_targets = client
        .verify_delegated_targets("models", &models_meta, Some(NOW))
        .unwrap();
    assert_eq!(del_targets.signed.version, 1);

    let target_bytes = fs::read(format!("{base}/models/model.safetensors")).unwrap();
    let tf = del_targets
        .signed
        .targets
        .get("models/model.safetensors")
        .expect("target must exist in delegated metadata");
    assert_eq!(tf.length, target_bytes.len() as u64);
}

#[test]
fn test_threshold_2_of_3() {
    let base = fixture_path("threshold_2_of_3");
    let valid = fs::read(format!("{base}/root_valid.json")).unwrap();
    let insufficient = fs::read(format!("{base}/root_insufficient.json")).unwrap();

    // 2-of-3 threshold met
    let client = TufClient::bootstrap(&valid).unwrap();
    assert_eq!(client.root().roles.get("root").unwrap().threshold, 2);

    // 1-of-3 threshold fails
    let err = TufClient::bootstrap(&insufficient).unwrap_err();
    assert!(
        err.is("TUF_THRESHOLD_NOT_MET"),
        "expected TUF_THRESHOLD_NOT_MET, got: {err}"
    );
}

#[test]
fn test_expired_timestamp() {
    let base = fixture_path("expired_timestamp");
    let root = fs::read(format!("{base}/root.json")).unwrap();
    let ts = fs::read(format!("{base}/timestamp.json")).unwrap();
    let snap = fs::read(format!("{base}/snapshot.json")).unwrap();
    let tg = fs::read(format!("{base}/targets.json")).unwrap();

    let mut client = TufClient::bootstrap(&root).unwrap();
    let err = client.refresh(&ts, &snap, &tg, NOW).unwrap_err();
    assert!(
        err.is("TUF_METADATA_EXPIRED"),
        "expected TUF_METADATA_EXPIRED, got: {err}"
    );
}

#[test]
fn test_mix_and_match_rejection() {
    let base = fixture_path("mix_and_match");
    let root = fs::read(format!("{base}/root.json")).unwrap();
    let ts = fs::read(format!("{base}/timestamp.json")).unwrap();
    let snap = fs::read(format!("{base}/snapshot.json")).unwrap();
    let tg_v1 = fs::read(format!("{base}/targets_v1.json")).unwrap();
    let tg_v2 = fs::read(format!("{base}/targets_v2.json")).unwrap();

    let mut client = TufClient::bootstrap(&root).unwrap();
    // Serving targets v1 when snapshot pins v2 must fail mix-and-match
    let err = client.refresh(&ts, &snap, &tg_v1, NOW).unwrap_err();
    assert!(
        err.is("TUF_TARGETS_VERSION_MISMATCH"),
        "expected TUF_TARGETS_VERSION_MISMATCH, got: {err}"
    );

    // Serving matching targets v2 must succeed
    client.refresh(&ts, &snap, &tg_v2, NOW).unwrap();
}

#[test]
fn test_keyid_mismatch() {
    let base = fixture_path("keyid_mismatch");
    let root = fs::read(format!("{base}/root.json")).unwrap();

    let err = TufClient::bootstrap(&root).unwrap_err();
    assert!(
        err.is("TUF_THRESHOLD_NOT_MET"),
        "tampered keyid should fail threshold verification: {err}"
    );
}

#[test]
fn test_rust_signed_verifies_in_python_tuf() {
    let r = RepoBuilder::new(3, 2);
    let root_bytes = r.root("2035-01-01T00:00:00Z").unwrap();

    let tmp_path = format!("/tmp/tuf-rust-test-{}.json", std::process::id());
    fs::write(&tmp_path, root_bytes).unwrap();

    let script = format!(
        "{}/tests/fixtures/gen_tuf_fixtures.py",
        env!("CARGO_MANIFEST_DIR")
    );
    let venv_python = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join(".enclave-local/venv/bin/python3");

    let python_cmd = if venv_python.exists() {
        venv_python.to_str().unwrap().to_owned()
    } else {
        "python3".to_owned()
    };

    let status = Command::new(&python_cmd)
        .arg(&script)
        .arg("--verify-rust")
        .arg(&tmp_path)
        .status()
        .expect("failed to execute python verification");

    let _ = fs::remove_file(&tmp_path);

    assert!(
        status.success(),
        "python-tuf failed to verify metadata signed by Rust client"
    );
}
