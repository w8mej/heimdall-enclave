//! Private signed provisioning fixtures; no enrollment or installed authority.
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use enclave_crypto::tuf::{target_file, RepoBuilder, TufClient};
use enclave_swarm_syncd::{cas::ContentStore, config::get_target_bytes};

const NOW: i64 = 1_793_884_860;
const EXP: &str = "2030-01-01T00:00:00Z";
struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("depot-public-provisioning-{}", enclave_core::rng::u64()));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn path(&self) -> &Path { &self.0 }
}
impl Drop for Fixture { fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.0); } }
fn signed(name: &str, bytes: &[u8], custom: Option<serde_json::Value>) -> TufClient {
    let publisher = RepoBuilder::new(3, 2);
    let root = publisher.root(EXP).unwrap();
    let targets = publisher.targets(1, EXP, BTreeMap::from([(name.to_owned(), target_file(bytes, custom))])).unwrap();
    let snapshot = publisher.snapshot(1, EXP, 1, &targets).unwrap();
    let timestamp = publisher.timestamp(1, EXP, 1, &snapshot).unwrap();
    let mut client = TufClient::bootstrap(&root).unwrap();
    client.refresh(&timestamp, &snapshot, &targets, NOW).unwrap();
    client
}

#[test]
fn bounded_signed_payload_and_nested_target_preserve_exact_bytes() {
    let fixture = Fixture::new();
    let bytes = br#"{"fixture_public_authority":true}"#;
    std::fs::create_dir(fixture.path().join("policies")).unwrap();
    std::fs::write(fixture.path().join("policies/policy.json"), bytes).unwrap();
    let trust = signed("policies/policy.json", bytes, None);
    assert_eq!(get_target_bytes(fixture.path(), &trust, "policies/policy.json", NOW).unwrap(), bytes);
    std::fs::write(fixture.path().join("policies/policy.json"), vec![b'x'; bytes.len()]).unwrap();
    assert!(get_target_bytes(fixture.path(), &trust, "policies/policy.json", NOW).is_err());
}

#[test]
fn links_special_files_and_wrong_length_refuse_without_fallback() {
    use std::os::unix::{fs::symlink, ffi::OsStrExt};
    let fixture = Fixture::new();
    let outside = Fixture::new();
    let bytes = b"public verification manifest";
    std::fs::write(outside.path().join("target"), bytes).unwrap();
    let trust = signed("target", bytes, None);
    symlink(outside.path().join("target"), fixture.path().join("target")).unwrap();
    assert!(get_target_bytes(fixture.path(), &trust, "target", NOW).is_err());
    std::fs::remove_file(fixture.path().join("target")).unwrap();
    let fifo = std::ffi::CString::new(fixture.path().join("target").as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
    assert!(get_target_bytes(fixture.path(), &trust, "target", NOW).unwrap_err().is("TUF_TARGET_LENGTH"));
    std::fs::remove_file(fixture.path().join("target")).unwrap();
    std::fs::write(fixture.path().join("target"), vec![0; 1024 * 1024]).unwrap();
    assert!(get_target_bytes(fixture.path(), &trust, "target", NOW).unwrap_err().is("TUF_TARGET_LENGTH"));
    symlink(outside.path(), fixture.path().join("policies")).unwrap();
    let nested = signed("policies/target", bytes, None);
    assert!(get_target_bytes(fixture.path(), &nested, "policies/target", NOW).is_err());
}

#[test]
fn canonical_admission_supersedes_stale_loose_payload() {
    let fixture = Fixture::new();
    let bytes = b"authenticated rotated verification key";
    let trust = signed("vk_manifest.json", bytes, None);
    std::fs::write(fixture.path().join("vk_manifest.json"), b"stale").unwrap();
    let store = ContentStore::open(fixture.path()).unwrap();
    let _ = store.put(bytes).unwrap();
    assert_eq!(get_target_bytes(fixture.path(), &trust, "vk_manifest.json", NOW).unwrap(), bytes);
}

#[test]
fn signed_revocation_expiry_and_path_traversal_never_release_payload() {
    let fixture = Fixture::new();
    let bytes = b"public";
    std::fs::write(fixture.path().join("target"), bytes).unwrap();
    let revoked = signed("target", bytes, Some(serde_json::json!({"revoked":true})));
    assert!(get_target_bytes(fixture.path(), &revoked, "target", NOW).unwrap_err().is("TARGET_REVOKED"));
    let live = signed("target", bytes, None);
    assert!(get_target_bytes(fixture.path(), &live, "target", 2_000_000_000).is_err());
    for name in ["../target", "/target", "a/../target", "a//target", "./target", "a\\target", "target\n"] {
        assert!(get_target_bytes(fixture.path(), &live, name, NOW).unwrap_err().is("TARGET_PATH"), "{name:?}");
    }
}
