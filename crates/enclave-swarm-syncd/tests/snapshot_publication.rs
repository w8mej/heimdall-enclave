//! Private inert platform fixtures exercise the real publication orchestrator.
//! No native snapshot, mount, entitlement or installed enforcement claim.
use std::{fs::File, path::{Path, PathBuf}, sync::{Arc, Mutex}};
use enclave_core::{err, error::EnclaveResult};
use enclave_crypto::tuf::target_file;
use enclave_swarm_syncd::snapshot_publication::{SealedConfig, SnapshotPlatform, SnapshotPublisher, SystemSnapshotPublisher};

#[derive(Debug)]
struct Platform { calls: Mutex<Vec<&'static str>>, fail: &'static str }
impl Platform {
    fn step(&self, name: &'static str) -> EnclaveResult<()> {
        self.calls.lock().unwrap().push(name);
        if self.fail == name { Err(err!(EACCES, "FIXTURE_PLATFORM_REFUSAL")) } else { Ok(()) }
    }
}
impl SnapshotPlatform for Platform {
    fn validate_source(&self, _: &SealedConfig) -> EnclaveResult<()> { self.step("source") }
    fn clone_stage(&self, staged: &File, destination: &Path) -> EnclaveResult<()> {
        self.step("clone")?;
        let mut staged = staged.try_clone().unwrap();
        std::io::copy(&mut staged, &mut File::create(destination).unwrap()).unwrap();
        self.step("clone-after-effect")
    }
    fn enforce_holders(&self,file:&File,_:&str)->EnclaveResult<()> {assert!(file.metadata().unwrap().is_file());self.step("holders")}
    fn require_capacity(&self, _: &SealedConfig, _: u64) -> EnclaveResult<()> { self.step("capacity") }
    fn cleanup_mount(&self, _: &SealedConfig, _: &str, mount: &Path) -> EnclaveResult<()> {
        if mount.join("artifacts").exists() { self.unmount(mount)?; } Ok(())
    }
    fn create_snapshot(&self, _: &Path, _: &str) -> EnclaveResult<()> { self.step("snapshot") }
    fn mount_snapshot(&self, config: &SealedConfig, _: &str, mount: &Path) -> EnclaveResult<()> {
        self.step("mount")?;
        std::fs::create_dir(mount.join("artifacts")).unwrap();
        for file in std::fs::read_dir(config.source_mount.join("artifacts")).unwrap() {
            let file = file.unwrap(); std::fs::copy(file.path(), mount.join("artifacts").join(file.file_name())).unwrap();
        }
        self.step("mount-after-effect")
    }
    fn verify_mount(&self, _: &SealedConfig, _: &str, mount: &Path) -> EnclaveResult<()> {
        self.step("flags")?;
        if !mount.join("artifacts").is_dir() { return Err(err!(EACCES, "FIXTURE_NOT_MOUNTED")); } Ok(())
    }
    fn unmount(&self, mount: &Path) -> EnclaveResult<()> {
        self.step("unmount")?; std::fs::remove_dir_all(mount.join("artifacts")).unwrap(); Ok(())
    }
    fn delete_snapshot(&self, _: &Path, _: &str) -> EnclaveResult<()> { self.step("delete") }
}
struct Fixture { root: PathBuf, config: SealedConfig }
impl Fixture {
    fn new() -> Self {
        use std::os::unix::fs::PermissionsExt;
        let root = std::env::temp_dir().join(format!("mcpmac-sealed-orchestration-{:x}", enclave_core::rng::u64()));
        std::fs::create_dir(&root).unwrap();
        let config = SealedConfig { volume_device: "/dev/disk99s1".into(), source_mount: root.join("source"), mount_root: root.join("mounts") };
        for directory in [&config.source_mount, &config.mount_root] {
            std::fs::create_dir(directory).unwrap(); std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        Self { root, config }
    }
    fn stage(&self, bytes: &[u8]) -> File { let path = self.root.join("stage"); std::fs::write(&path, bytes).unwrap(); File::open(path).unwrap() }
}
impl Drop for Fixture { fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.root); } }

#[test]
fn private_snapshot_orchestration_authenticates_payload_before_publication_and_reopens() {
    use std::io::Read;
    let fixture = Fixture::new(); let bytes = b"verified plaintext fixture";
    let platform = Arc::new(Platform { calls: Mutex::new(vec![]), fail: "" });
    let publisher = SystemSnapshotPublisher::with_platform(fixture.config.clone(), platform.clone()).unwrap();
    let target = target_file(bytes, None);
    let mut published = publisher.publish(&fixture.stage(bytes), &target).unwrap();
    let mut received = Vec::new(); published.read_to_end(&mut received).unwrap(); assert_eq!(received, bytes);
    assert!(std::io::Write::write_all(&mut published, b"forbidden").is_err());
    assert_eq!(&*platform.calls.lock().unwrap(), &["source", "capacity", "clone", "clone-after-effect", "snapshot", "mount", "mount-after-effect", "flags"]);
    let mut reopened = publisher.reopen(&target).unwrap(); received.clear(); reopened.read_to_end(&mut received).unwrap(); assert_eq!(received, bytes);
    let after_restart = SystemSnapshotPublisher::with_platform(fixture.config.clone(), platform).unwrap();
    assert!(after_restart.reopen(&target).is_ok());
}

#[test]
fn private_snapshot_failure_paths_return_no_descriptor_and_clean_owned_work() {
    for fail in ["source", "capacity", "clone", "clone-after-effect", "snapshot", "mount", "mount-after-effect", "flags"] {
        let fixture = Fixture::new(); let bytes = b"authenticated fixture"; let target = target_file(bytes, None);
        let platform = Arc::new(Platform { calls: Mutex::new(vec![]), fail });
        let publisher = SystemSnapshotPublisher::with_platform(fixture.config.clone(), platform.clone()).unwrap();
        assert!(publisher.publish(&fixture.stage(bytes), &target).is_err(), "{fail}");
        let artifact = fixture.config.source_mount.join("artifacts").join(&target.hashes["blake3"]);
        if fail=="snapshot" {assert!(artifact.exists(),"ambiguous creation retains evidence");}else{assert!(!artifact.exists(), "{fail}: failed publication left a staged artifact");}
        let calls = platform.calls.lock().unwrap();
        if fail == "flags" || fail == "mount-after-effect" { assert!(calls.ends_with(&["unmount", "delete"])); }
        if fail == "mount" { assert!(calls.ends_with(&["delete"])); }
    }
}

#[test]
fn signed_payload_and_configuration_refusal_precede_platform_effects() {
    let fixture = Fixture::new(); let bytes = b"expected";
    let platform = Arc::new(Platform { calls: Mutex::new(vec![]), fail: "" });
    let publisher = SystemSnapshotPublisher::with_platform(fixture.config.clone(), platform.clone()).unwrap();
    assert!(publisher.publish(&fixture.stage(b"tampered"), &target_file(bytes, None)).is_err());
    assert!(platform.calls.lock().unwrap().is_empty());
    for path in ["/", "/System/Volumes/Data", "/tmp/../data", "relative"] {
        let mut config = fixture.config.clone(); config.source_mount = path.into();
        assert!(config.validate().is_err(), "{path}");
    }
    let mut overlap = fixture.config.clone(); overlap.mount_root = overlap.source_mount.join("nested"); assert!(overlap.validate().is_err());
}

#[test]
fn private_retraction_removes_mount_snapshot_and_artifact_before_restart_reuse() {
    let fixture = Fixture::new(); let bytes = b"retracted artifact"; let target = target_file(bytes, None);
    let platform = Arc::new(Platform { calls: Mutex::new(vec![]), fail: "" });
    let publisher = SystemSnapshotPublisher::with_platform(fixture.config.clone(), platform.clone()).unwrap();
    assert!(publisher.publish(&fixture.stage(bytes), &target).is_ok());
    let mut revoked = target.clone(); revoked.custom = Some(serde_json::json!({"revoked":true}));
    publisher.revoke(&revoked).unwrap();
    assert!(!fixture.config.source_mount.join("artifacts").join(&target.hashes["blake3"]).exists());
    assert!(publisher.reopen(&target).is_err());
    assert!(platform.calls.lock().unwrap().windows(2).any(|v| v == ["unmount", "delete"]));
}
