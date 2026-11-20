//! L3 publication on an explicitly provisioned dedicated APFS volume.
//! No snapshot or mount operation is executed merely by constructing a publisher.
//! Native mutating acceptance is prohibited on the personal development runner.
use std::{fs::File, io::{Read, Seek, SeekFrom}, path::{Path, PathBuf}, sync::{Arc, Mutex}};
use enclave_core::{err, fail, error::EnclaveResult};
use enclave_crypto::tuf::TargetFile;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Signed routing to a dedicated volume, never the host's boot/data volume.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SealedConfig {
    /// Exact APFS device (for example /dev/disk9s1), provisioned independently.
    pub volume_device: String,
    /// Existing private mount of that dedicated writable staging volume.
    pub source_mount: PathBuf,
    /// Existing private directory for read-only snapshot mounts.
    pub mount_root: PathBuf,
}
impl SealedConfig {
    /// Structural validation does not establish volume ownership or entitlements.
    pub fn validate(&self) -> EnclaveResult<()> {
        if [Path::new("/"), Path::new("/System"), Path::new("/System/Volumes/Data")].contains(&self.source_mount.as_path()) {
            fail!(EACCES, "SEALED_DEDICATED_VOLUME_REQUIRED");
        }
        if !self.volume_device.starts_with("/dev/disk") || self.volume_device.len() <= 9 || self.volume_device.len() > 64
            || !self.volume_device[9..].bytes().all(|b| b.is_ascii_digit() || b == b's')
        { fail!(EINVAL, "SEALED_DEVICE"); }
        for path in [&self.source_mount, &self.mount_root] {
            if !path.is_absolute() || path.as_os_str().len() > 1024 || path.components().count() < 4
                || path.components().any(|part| !matches!(part, std::path::Component::RootDir | std::path::Component::Normal(_)))
                || path.to_str().is_none_or(|s| s.bytes().any(|b| b == 0 || b.is_ascii_control()))
            { fail!(EINVAL, "SEALED_PATH"); }
        }
        if self.source_mount.starts_with(&self.mount_root) || self.mount_root.starts_with(&self.source_mount) {
            fail!(EINVAL, "SEALED_VOLUME_OVERLAP");
        }
        Ok(())
    }
}

/// Real production calls and explicitly injected software fixture publishers
/// share this interface. A fixture result is never installed mount evidence.
pub trait SnapshotPublisher: std::fmt::Debug + Send + Sync {
    /// Verify staged bytes and return a verified read-only snapshot descriptor.
    fn publish(&self, staged: &File, target: &TargetFile) -> EnclaveResult<File>;
    /// Serialize with earlier broker work before a new same-root stage exists.
    /// Inert publishers have no detached remote stage to reconcile.
    fn prepare_staging(&self, _target: &TargetFile) -> EnclaveResult<()> {Ok(())}
    /// Recheck the persisted mount's identity, flags and exact payload on reuse.
    fn reopen(&self, target: &TargetFile) -> EnclaveResult<File>;
    /// Retract this publisher's mount, snapshot and writable-volume artifact.
    /// Already transferred descriptors require the existing holder revocation.
    fn revoke(&self, target: &TargetFile) -> EnclaveResult<()>;
}

/// Narrow OS boundary for deterministic failure-ordering fixtures. Implementors
/// must not claim native enforcement unless they inspect real kernel state.
pub trait SnapshotPlatform: std::fmt::Debug + Send + Sync {
    /// Require the signed dedicated volume and private directories.
    fn validate_source(&self, config: &SealedConfig) -> EnclaveResult<()>;
    /// Clone the verified stage into an exclusively named volume object.
    fn clone_stage(&self, staged: &File, destination: &Path) -> EnclaveResult<()>;
    /// Refuse insufficient dedicated-volume capacity before any copy.
    fn require_capacity(&self, config: &SealedConfig, bytes: u64) -> EnclaveResult<()>;
    /// Terminate actual FD/mmap holders through the authenticated supervisor.
    /// Unknown/incomplete observations must return an error, never success.
    fn enforce_holders(&self, file: &File, root: &str) -> EnclaveResult<()>;
    /// Undo an owned mount even when the preceding mount call returned an error.
    /// Foreign mounts must cause refusal rather than unmounting them.
    fn cleanup_mount(&self, config: &SealedConfig, name: &str, mount: &Path) -> EnclaveResult<()>;
    /// Create a named snapshot on the dedicated volume.
    fn create_snapshot(&self, volume: &Path, name: &str) -> EnclaveResult<()>;
    /// Mount that snapshot with every required restriction.
    fn mount_snapshot(&self, config: &SealedConfig, name: &str, mount: &Path) -> EnclaveResult<()>;
    /// Inspect actual mount identity and flags before descriptor release.
    fn verify_mount(&self, config: &SealedConfig, name: &str, mount: &Path) -> EnclaveResult<()>;
    /// Unmount only the publisher's exact owned mount after failure.
    fn unmount(&self, mount: &Path) -> EnclaveResult<()>;
    /// Delete the publisher's named snapshot after failed publication.
    fn delete_snapshot(&self, volume: &Path, name: &str) -> EnclaveResult<()>;
}

// The platform is stateless; authority comes from the already checked process
// context, never from a publication request or its independently signed config.
#[cfg(any(target_os="macos",test))]
fn holder_supervisor_path(socket_root:Option<&Path>)->PathBuf {
    socket_root.map(enclave_core::supervisor::socket_path)
        .unwrap_or_else(||PathBuf::from("/var/run/enclave/supervisor/supervisor.sock"))
}
#[cfg(target_os="macos")]
fn selected_holder_supervisor_path()->PathBuf {
    holder_supervisor_path(enclave_core::deployment::selected().map(|checked|checked.target().layout.socket_root.as_path()))
}

/// Uses clonefile, APFS snapshots, mount_apfs and kernel statfs observations.
#[derive(Debug)]
pub struct SystemSnapshotPublisher {
    config: SealedConfig,
    platform: Arc<dyn SnapshotPlatform>,
    serial: Mutex<()>,
}
impl SystemSnapshotPublisher {
    /// Production construction; no software provider or mount fallback.
    pub fn new(config: SealedConfig) -> EnclaveResult<Self> {
        Self::with_platform(config, Arc::new(NativeSnapshotPlatform))
    }
    /// Explicit injection for reviewed private orchestration fixtures.
    pub fn with_platform(config: SealedConfig, platform: Arc<dyn SnapshotPlatform>) -> EnclaveResult<Self> {
        config.validate()?;
        Ok(Self { config, platform, serial: Mutex::new(()) })
    }
    fn paths(&self, target: &TargetFile) -> EnclaveResult<(String, PathBuf, PathBuf)> {
        crate::streaming::validate_target(target)?;
        let root = &target.hashes["blake3"];
        Ok((format!("cas-{root}"), self.config.source_mount.join("artifacts").join(root), self.config.mount_root.join(root)))
    }
    fn open_published(&self, target: &TargetFile) -> EnclaveResult<File> {
        let (name, _, mount) = self.paths(target)?;
        self.platform.verify_mount(&self.config, &name, &mount)?;
        let file = open_regular(&mount.join("artifacts").join(&target.hashes["blake3"]))?;
        verify_file(&file, target)?;
        Ok(file)
    }
}
impl SnapshotPublisher for SystemSnapshotPublisher {
    fn revoke(&self, target: &TargetFile) -> EnclaveResult<()> {
        self.revoke_with_holder_check(target, |file| {
            let file=file.ok_or_else(||err!(EACCES,"SEALED_HOLDER_IDENTITY_UNAVAILABLE"))?;
            self.platform.enforce_holders(&file,&target.hashes["blake3"])
        })
    }
    fn reopen(&self, target: &TargetFile) -> EnclaveResult<File> {
        let _serial = self.serial.lock().map_err(|_| err!(EIO, "SEALED_LOCK"))?;
        self.platform.validate_source(&self.config)?;
        let _cross_process = publication_lock(&self.config.source_mount)?;
        self.open_published(target)
    }
    fn publish(&self,staged:&File,target:&TargetFile)->EnclaveResult<File>{self.publish_tracked(staged,target).map_err(|failure|failure.error)}
}

/// Durable broker policy distinguishes proved ownership from an ambiguous
/// create outcome. An intent by itself never authorizes snapshot deletion.
#[derive(Debug,Clone,Copy,PartialEq,Eq)]
pub(crate) enum PublicationFailureKind { Cleaned, OwnedIncomplete, OwnershipUncertain }
#[derive(Debug)]
pub(crate) struct PublicationFailure {pub error:enclave_core::error::EnclaveError,pub kind:PublicationFailureKind}
impl From<enclave_core::error::EnclaveError> for PublicationFailure {fn from(error:enclave_core::error::EnclaveError)->Self{Self{error,kind:PublicationFailureKind::Cleaned}}}
impl SystemSnapshotPublisher {
    // The broker persists completed holder enforcement before allowing this
    // cleanup to remove the only reopenable snapshot identity. On crash/retry,
    // its callback distinguishes proved enforcement from never-exposed intent.
    pub(crate) fn revoke_with_holder_check(&self,target:&TargetFile,
        check:impl FnOnce(Option<File>)->EnclaveResult<()>)->EnclaveResult<()> {
        let _serial=self.serial.lock().map_err(|_|err!(EIO,"SEALED_LOCK"))?;
        self.platform.validate_source(&self.config)?;
        let _cross_process=publication_lock(&self.config.source_mount)?;
        let mut original=target.clone();original.custom=None;
        let (name,destination,mount)=self.paths(&original)?;
        let object=mount.join("artifacts").join(&target.hashes["blake3"]);
        let held=if object.try_exists().map_err(|_|err!(EIO,"SEALED_HOLDER_OBSERVATION"))? {
            self.platform.verify_mount(&self.config,&name,&mount)?;
            Some(open_regular(&object)?)
        } else {None};
        check(held)?;
        self.platform.cleanup_mount(&self.config,&name,&mount)?;
        self.platform.delete_snapshot(&self.config.source_mount,&name)?;
        remove_owned_file(&destination)?;
        match std::fs::remove_dir(&mount) {
            Ok(())=>(),Err(e) if e.kind()==std::io::ErrorKind::NotFound=>(),
            Err(e)=>return Err(err!(EIO,"SEALED_CLEANUP","{e}")),
        }
        Ok(())
    }
    pub(crate) fn publish_tracked(&self,staged:&File,target:&TargetFile)->Result<File,PublicationFailure> {
        let _serial=self.serial.lock().map_err(|_|err!(EIO,"SEALED_LOCK"))?;
        verify_file(staged,target)?;self.platform.validate_source(&self.config)?;
        let _cross_process=publication_lock(&self.config.source_mount)?;
        let (name,destination,mount)=self.paths(target)?;
        if mount.try_exists().map_err(|_|err!(EACCES,"SEALED_MOUNT_OBSERVATION"))? {return self.open_published(target).map_err(Into::into);}
        secure_directory(destination.parent().unwrap(),true)?;
        let mut created_file=false;let mut snapshot_created=false;let mut snapshot_uncertain=false;let mut mount_attempted=false;
        let result:EnclaveResult<File>=(||{
            if destination.try_exists().map_err(|_|err!(EACCES,"SEALED_STAGE_OBSERVATION"))? {verify_file(&open_regular(&destination)?,target)?;}
            else {self.platform.require_capacity(&self.config,target.length)?;created_file=true;self.platform.clone_stage(staged,&destination)?;}
            verify_file(&open_regular(&destination)?,target)?;secure_directory(&mount,true)?;
            match self.platform.create_snapshot(&self.config.source_mount,&name) {
                Ok(())=>snapshot_created=true,
                Err(error)=>{snapshot_uncertain=!error.is("SEALED_SNAPSHOT_FOREIGN_EXISTS");return Err(error);}
            }
            mount_attempted=true;self.platform.mount_snapshot(&self.config,&name,&mount)?;self.open_published(target)
        })();
        match result {
            Ok(file)=>Ok(file),
            Err(error)=>{
                // An unknown create result may have taken effect, or refer to
                // a foreign resource. Preserve evidence and require diagnosis.
                if snapshot_uncertain {return Err(PublicationFailure{error,kind:PublicationFailureKind::OwnershipUncertain});}
                let cleanup:EnclaveResult<()>=(||{
                    if mount_attempted {self.platform.cleanup_mount(&self.config,&name,&mount)?;}
                    if snapshot_created {self.platform.delete_snapshot(&self.config.source_mount,&name)?;}
                    match std::fs::remove_dir(&mount){Ok(())=>(),Err(e) if e.kind()==std::io::ErrorKind::NotFound=>(),Err(_)=>return Err(err!(EIO,"SEALED_CLEANUP"))}
                    if created_file {remove_owned_file(&destination)?;}Ok(())
                })();
                match cleanup {Ok(())=>Err(PublicationFailure{error,kind:PublicationFailureKind::Cleaned}),Err(cleanup)=>Err(PublicationFailure{error:cleanup,kind:if snapshot_created{PublicationFailureKind::OwnedIncomplete}else{PublicationFailureKind::OwnershipUncertain}})}
            }
        }
    }
}

fn remove_owned_file(path: &Path) -> EnclaveResult<()> {
    use std::os::unix::fs::MetadataExt;
    match std::fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(err!(EIO, "SEALED_CLEANUP", "{e}")),
        Ok(metadata) => {
            if !metadata.is_file() || metadata.uid() != enclave_core::ipc::geteuid() || metadata.nlink() != 1 {
                fail!(EACCES, "SEALED_CLEANUP_IDENTITY");
            }
            std::fs::remove_file(path).map_err(|e| err!(EIO, "SEALED_CLEANUP", "{e}"))
        }
    }
}
fn publication_lock(volume: &Path) -> EnclaveResult<File> {
    use std::os::{fd::AsRawFd, unix::fs::{OpenOptionsExt, MetadataExt}};
    let file = File::options().read(true).write(true).create(true).mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(volume.join(".publication.lock")).map_err(|e| err!(EIO, "SEALED_LOCK", "{e}"))?;
    let metadata = file.metadata().map_err(|e| err!(EIO, "SEALED_LOCK", "{e}"))?;
    if !metadata.is_file() || metadata.uid() != enclave_core::ipc::geteuid() || metadata.mode() & 0o077 != 0 || metadata.nlink() != 1 {
        fail!(EACCES, "SEALED_LOCK_IDENTITY");
    }
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 { fail!(EAGAIN, "SEALED_LOCK_BUSY"); }
    Ok(file)
}

pub(crate) fn verify_file(file: &File, target: &TargetFile) -> EnclaveResult<()> {
    crate::streaming::validate_target(target)?;
    let metadata = file.metadata().map_err(|e| err!(EIO, "SEALED_STAT", "{e}"))?;
    if !metadata.is_file() || metadata.len() != target.length { fail!(EACCES, "SEALED_LENGTH"); }
    let mut reader = file.try_clone().map_err(|e| err!(EIO, "SEALED_READ", "{e}"))?;
    reader.seek(SeekFrom::Start(0)).map_err(|e| err!(EIO, "SEALED_READ", "{e}"))?;
    let mut remaining = target.length;
    let mut scratch = [0u8; 65536]; let mut b3 = blake3::Hasher::new(); let mut sha = Sha256::new();
    while remaining != 0 {
        let capacity = remaining.min(scratch.len() as u64) as usize;
        let count = reader.read(&mut scratch[..capacity]).map_err(|e| err!(EIO, "SEALED_READ", "{e}"))?;
        if count == 0 { fail!(EACCES, "SEALED_LENGTH"); }
        b3.update(&scratch[..count]); sha.update(&scratch[..count]); remaining -= count as u64;
    }
    let mut extra = [0];
    if reader.read(&mut extra).map_err(|e| err!(EIO, "SEALED_READ", "{e}"))? != 0
        || blake3::Hasher::finalize(&b3).to_hex().as_str() != target.hashes["blake3"]
        || hex::encode(sha.finalize()) != target.hashes["sha256"]
    { fail!(EACCES, "SEALED_DIGEST"); }
    reader.seek(SeekFrom::Start(0)).map_err(|e| err!(EIO, "SEALED_READ", "{e}"))?;
    Ok(())
}
fn open_regular(path: &Path) -> EnclaveResult<File> {
    use std::os::unix::fs::OpenOptionsExt;
    File::options().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path).map_err(|e| err!(EIO, "SEALED_OPEN", "{e}"))
}
fn secure_directory(path: &Path, create: bool) -> EnclaveResult<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    if create {
        match std::fs::create_dir(path) {
            Ok(()) => std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).map_err(|e| err!(EIO, "SEALED_DIRECTORY", "{e}"))?,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => (),
            Err(e) => return Err(err!(EIO, "SEALED_DIRECTORY", "{e}")),
        }
    }
    let metadata = std::fs::symlink_metadata(path).map_err(|e| err!(EIO, "SEALED_DIRECTORY", "{e}"))?;
    if !metadata.is_dir() || metadata.uid() != enclave_core::ipc::geteuid() || metadata.mode() & 0o077 != 0 {
        fail!(EACCES, "SEALED_DIRECTORY_INSECURE");
    }
    Ok(())
}

/// Native operations are deliberately unsupported elsewhere, never substituted
/// by ordinary copies or an unconfined directory in production.
#[derive(Debug)]
pub struct NativeSnapshotPlatform;

#[cfg(all(test, target_os = "macos"))]
mod phase1_native_storage_tests {
    use super::*;
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, FileExt};

    #[test]
    fn phase1_native_preallocation_and_clone_preserve_payload_and_foreign_names() {
        // Ordinary private APFS files only: no snapshot, mount, privileged
        // operation, low-disk injection or claim of installed acceptance.
        let base = std::env::temp_dir().join(format!("p1-clone-{:x}", enclave_core::rng::u64()));
        std::fs::DirBuilder::new().mode(0o700).create(&base).unwrap();
        let base = base.canonicalize().unwrap();
        let source_path = base.join("source");
        let source = File::options().create_new(true).read(true).write(true).mode(0o600).open(&source_path).unwrap();
        let mut payload = vec![0; 64 * 1024 + 17];
        blake3::Hasher::new_derive_key("phase1 native private clone fixture").finalize_xof().fill(&mut payload);
        enclave_core::staging::preallocate(&source, payload.len() as u64).unwrap();
        let before = source.metadata().unwrap();
        assert_eq!(before.len(), payload.len() as u64);
        assert!(before.blocks() * 512 >= before.len(), "preallocation must allocate payload capacity before writing");
        source.write_all_at(&payload, 0).unwrap(); source.sync_all().unwrap();
        let destination = base.join("clone");
        NativeSnapshotPlatform.clone_stage(&source, &destination).unwrap();
        let cloned = File::open(&destination).unwrap(); let metadata = cloned.metadata().unwrap();
        assert_eq!(metadata.dev(), before.dev()); assert_ne!(metadata.ino(), before.ino());
        assert_eq!(metadata.mode() & 0o777, 0o400); assert_eq!(metadata.len(), before.len());
        assert_eq!(std::fs::read(&destination).unwrap(), payload);
        source.write_all_at(b"changed", 0).unwrap(); source.sync_all().unwrap();
        assert_eq!(std::fs::read(&destination).unwrap(), payload, "clone must survive source COW mutation");
        let foreign = base.join("foreign"); std::fs::write(&foreign, b"preserve this inode").unwrap();
        let foreign_inode = std::fs::metadata(&foreign).unwrap().ino();
        assert!(NativeSnapshotPlatform.clone_stage(&source, &foreign).unwrap_err().is("SEALED_CLONE"));
        assert_eq!(std::fs::read(&foreign).unwrap(), b"preserve this inode");
        assert_eq!(std::fs::metadata(&foreign).unwrap().ino(), foreign_inode);
        println!("ordinary native clone: payload={} preallocated_bytes={} clone_reported_bytes={}; shared extents and snapshot metadata are not measured", before.len(), before.blocks() * 512, metadata.blocks() * 512);
        drop(cloned); drop(source); std::fs::remove_dir_all(base).unwrap();
    }
}

/// mount_apfs(8)'s snapshot form takes the mounted base-volume root, rather
/// than the device operand used by its ordinary volume form. Keep arguments
/// separate so signed paths cannot become options or shell syntax.
fn snapshot_mount_command(config: &SealedConfig, name: &str, mount: &Path) -> EnclaveResult<std::process::Command> {
    config.validate()?;
    if name.len() != 68 || !name.starts_with("cas-") || !name[4..].bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        || mount != config.mount_root.join(&name[4..])
    { fail!(EINVAL, "SEALED_MOUNT_IDENTITY"); }
    let mut command = std::process::Command::new("/sbin/mount_apfs");
    command.env_clear().env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin").env("LC_ALL", "C").current_dir("/");
    command.args(["-o", "rdonly,noexec,nosuid,nodev,nobrowse", "-s", name])
        .arg(&config.source_mount).arg(mount)
        .stdin(std::process::Stdio::null()).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null());
    Ok(command)
}

#[cfg(test)]
mod mount_command_tests {
    #[test]
    fn deployment_snapshot_holder_request_stays_on_selected_supervisor() {
        use super::*;
        assert_eq!(holder_supervisor_path(None),Path::new("/var/run/enclave/supervisor/supervisor.sock"));
        assert_eq!(holder_supervisor_path(Some(Path::new("/fixture-a/run"))),Path::new("/fixture-a/run/supervisor/supervisor.sock"));
        assert_eq!(holder_supervisor_path(Some(Path::new("/fixture-b/deeper/run"))),Path::new("/fixture-b/deeper/run/supervisor/supervisor.sock"));
    }
    use super::*;
    #[test]
    fn f38_snapshot_mount_uses_base_volume_root_and_refuses_foreign_operands() {
        let config = SealedConfig { volume_device: "/dev/disk9s1".into(), source_mount: "/private/enclave/stage volume".into(), mount_root: "/private/enclave/readonly".into() };
        let root = "ab".repeat(32); let name = format!("cas-{root}"); let mount = config.mount_root.join(&root);
        let command = snapshot_mount_command(&config, &name, &mount).unwrap();
        assert_eq!(command.get_program(), "/sbin/mount_apfs");
        let args: Vec<_> = command.get_args().map(|arg| arg.to_string_lossy().into_owned()).collect();
        assert_eq!(args, vec!["-o", "rdonly,noexec,nosuid,nodev,nobrowse", "-s", &name, "/private/enclave/stage volume", mount.to_str().unwrap()]);
        assert!(snapshot_mount_command(&config, "-s", &mount).is_err());
        assert!(snapshot_mount_command(&config, &name, Path::new("/private/foreign/mount")).is_err());
    }
}
#[cfg(not(target_os = "macos"))]
impl SnapshotPlatform for NativeSnapshotPlatform {
    fn validate_source(&self, _: &SealedConfig) -> EnclaveResult<()> { fail!(ENOSYS, "SEALED_APFS_REQUIRED") }
    fn clone_stage(&self, _: &File, _: &Path) -> EnclaveResult<()> { fail!(ENOSYS, "SEALED_APFS_REQUIRED") }
    fn enforce_holders(&self, _: &File, _: &str) -> EnclaveResult<()> { fail!(ENOSYS, "SEALED_APFS_REQUIRED") }
    fn require_capacity(&self, _: &SealedConfig, _: u64) -> EnclaveResult<()> { fail!(ENOSYS, "SEALED_APFS_REQUIRED") }
    fn cleanup_mount(&self, _: &SealedConfig, _: &str, _: &Path) -> EnclaveResult<()> { fail!(ENOSYS, "SEALED_APFS_REQUIRED") }
    fn create_snapshot(&self, _: &Path, _: &str) -> EnclaveResult<()> { fail!(ENOSYS, "SEALED_APFS_REQUIRED") }
    fn mount_snapshot(&self, _: &SealedConfig, _: &str, _: &Path) -> EnclaveResult<()> { fail!(ENOSYS, "SEALED_APFS_REQUIRED") }
    fn verify_mount(&self, _: &SealedConfig, _: &str, _: &Path) -> EnclaveResult<()> { fail!(ENOSYS, "SEALED_APFS_REQUIRED") }
    fn unmount(&self, _: &Path) -> EnclaveResult<()> { fail!(ENOSYS, "SEALED_APFS_REQUIRED") }
    fn delete_snapshot(&self, _: &Path, _: &str) -> EnclaveResult<()> { fail!(ENOSYS, "SEALED_APFS_REQUIRED") }
}

#[cfg(target_os = "macos")]
mod native {
    use super::*;
    use std::{ffi::CString, os::{fd::AsRawFd, unix::{ffi::OsStrExt, fs::PermissionsExt}}};
    unsafe extern "C" {
        fn fclonefileat(source: i32, directory: i32, name: *const libc::c_char, flags: u32) -> i32;
        fn fs_snapshot_create(directory: i32, name: *const libc::c_char, flags: u32) -> i32;
        fn fs_snapshot_delete(directory: i32, name: *const libc::c_char, flags: u32) -> i32;
    }
    fn cpath(path: &Path) -> EnclaveResult<CString> { CString::new(path.as_os_str().as_bytes()).map_err(|_| err!(EINVAL, "SEALED_PATH")) }
    fn statfs(path: &Path) -> EnclaveResult<libc::statfs> {
        let path = cpath(path)?; let mut value = std::mem::MaybeUninit::<libc::statfs>::uninit();
        if unsafe { libc::statfs(path.as_ptr(), value.as_mut_ptr()) } != 0 { fail!(EIO, "SEALED_STATFS"); }
        Ok(unsafe { value.assume_init() })
    }
    fn same_fsid(a: &libc::statfs, b: &libc::statfs) -> bool {
        // fsid_t is deliberately opaque in libc. Compare the kernel-returned
        // object without inventing SDK field names or offsets.
        unsafe { libc::memcmp(std::ptr::addr_of!(a.f_fsid).cast(), std::ptr::addr_of!(b.f_fsid).cast(), std::mem::size_of::<libc::fsid_t>()) == 0 }
    }
    fn field(bytes: &[libc::c_char]) -> Vec<u8> { bytes.iter().take_while(|b| **b != 0).map(|b| *b as u8).collect() }
    fn directory(path: &Path) -> EnclaveResult<File> {
        use std::os::unix::fs::{OpenOptionsExt, MetadataExt};
        if !path.is_absolute() { fail!(EINVAL, "SEALED_PATH"); }
        let mut current = File::options().read(true).custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open("/").map_err(|e| err!(EIO, "SEALED_DIRECTORY", "{e}"))?;
        for component in path.components().skip(1) {
            let std::path::Component::Normal(name) = component else { fail!(EINVAL, "SEALED_PATH"); };
            let metadata = current.metadata().map_err(|e| err!(EIO, "SEALED_DIRECTORY", "{e}"))?;
            if (metadata.uid() != 0 && metadata.uid() != enclave_core::ipc::geteuid()) || metadata.mode() & 0o022 != 0 {
                fail!(EACCES, "SEALED_ANCESTOR_INSECURE");
            }
            let name = CString::new(name.as_bytes()).map_err(|_| err!(EINVAL, "SEALED_PATH"))?;
            let fd = unsafe { libc::openat(current.as_raw_fd(), name.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC) };
            if fd < 0 { fail!(EACCES, "SEALED_DIRECTORY"); }
            use std::os::fd::FromRawFd;
            current = unsafe { File::from_raw_fd(fd) };
        }
        let metadata = current.metadata().map_err(|e| err!(EIO, "SEALED_DIRECTORY", "{e}"))?;
        if (metadata.uid() != 0 && metadata.uid() != enclave_core::ipc::geteuid()) || metadata.mode() & 0o022 != 0 { fail!(EACCES, "SEALED_DIRECTORY_INSECURE"); }
        Ok(current)
    }
    impl SnapshotPlatform for NativeSnapshotPlatform {
        fn validate_source(&self, config: &SealedConfig) -> EnclaveResult<()> {
            if enclave_core::ipc::geteuid()!=0 { fail!(EACCES, "SEALED_ROOT_BROKER_REQUIRED"); }
            config.validate()?;
            let _source = directory(&config.source_mount)?;
            let _mounts = directory(&config.mount_root)?;
            secure_directory(&config.source_mount, false)?; secure_directory(&config.mount_root, false)?;
            if std::fs::canonicalize(&config.source_mount).map_err(|e| err!(EIO, "SEALED_PATH", "{e}"))? != config.source_mount
                || std::fs::canonicalize(&config.mount_root).map_err(|e| err!(EIO, "SEALED_PATH", "{e}"))? != config.mount_root { fail!(EACCES, "SEALED_PATH_ALIAS"); }
            let source = statfs(&config.source_mount)?;
            let root = statfs(Path::new("/"))?;
            let data = statfs(Path::new("/System/Volumes/Data"))?;
            if field(&source.f_fstypename) != b"apfs" || field(&source.f_mntonname) != config.source_mount.as_os_str().as_bytes()
                || field(&source.f_mntfromname) != config.volume_device.as_bytes()
                || same_fsid(&source, &root) || same_fsid(&source, &data)
            { fail!(EACCES, "SEALED_DEDICATED_VOLUME_REQUIRED"); }
            Ok(())
        }
        fn enforce_holders(&self,file:&File,root:&str)->EnclaveResult<()> {
            let supervisor=selected_holder_supervisor_path();
            let report=enclave_core::supervisor::request_held_enforcement(
                &supervisor,false,file,root,
                enclave_core::supervisor::HeldObjectKind::Snapshot)?;
            if !report.complete || !report.refused.is_empty() || !report.incomplete.is_empty() {
                fail!(EIO,"SEALED_HOLDER_REVOCATION_INCOMPLETE");
            }
            Ok(())
        }
        fn require_capacity(&self, config: &SealedConfig, bytes: u64) -> EnclaveResult<()> {
            let observed = statfs(&config.source_mount)?;
            let available = observed.f_bavail.checked_mul(observed.f_bsize as u64).ok_or_else(|| err!(EAGAIN, "SEALED_CAPACITY"))?;
            // Dedicated volume must hold the temporary copy, cloned extents and
            // metadata without consuming its last 256 MiB. No allocation probe.
            let required = bytes.checked_mul(2).and_then(|n| n.checked_add(256 * 1024 * 1024)).ok_or_else(|| err!(EAGAIN, "SEALED_CAPACITY"))?;
            if available < required { fail!(EAGAIN, "SEALED_CAPACITY"); } Ok(())
        }
        fn cleanup_mount(&self, config: &SealedConfig, name: &str, mount: &Path) -> EnclaveResult<()> {
            if !mount.try_exists().map_err(|_|err!(EACCES,"SEALED_CLEANUP_OBSERVATION"))? { return Ok(()); }
            let observed = statfs(mount)?;
            if field(&observed.f_mntonname) != mount.as_os_str().as_bytes() { return Ok(()); }
            if field(&observed.f_fstypename) != b"apfs" || field(&observed.f_mntfromname) != format!("{name}@{}", config.volume_device).as_bytes() {
                fail!(EACCES, "SEALED_CLEANUP_FOREIGN_MOUNT");
            }
            self.unmount(mount)
        }
        fn clone_stage(&self, staged: &File, destination: &Path) -> EnclaveResult<()> {
            let parent = directory(destination.parent().ok_or_else(|| err!(EINVAL, "SEALED_PATH"))?)?;
            let name = CString::new(destination.file_name().unwrap().as_bytes()).map_err(|_| err!(EINVAL, "SEALED_PATH"))?;
            // The root broker has already copied/verified into this dedicated
            // volume. A second full temporary copy would violate the shared
            // 2.5x payload staging budget. No EXDEV/copy fallback is allowed.
            if unsafe { fclonefileat(staged.as_raw_fd(),parent.as_raw_fd(),name.as_ptr(),0) }!=0 {
                fail!(EIO,"SEALED_CLONE","{}",std::io::Error::last_os_error());
            }
            let file = open_regular(destination)?;
            file.set_permissions(std::fs::Permissions::from_mode(0o400)).map_err(|e| err!(EIO, "SEALED_MODE", "{e}"))?;
            file.sync_all().map_err(|e| err!(EIO, "SEALED_FSYNC", "{e}"))?; parent.sync_all().map_err(|e| err!(EIO, "SEALED_FSYNC", "{e}"))
        }
        fn create_snapshot(&self, volume: &Path, name: &str) -> EnclaveResult<()> {
            let volume = directory(volume)?; let name = CString::new(name).map_err(|_| err!(EINVAL, "SEALED_NAME"))?;
            if unsafe { fs_snapshot_create(volume.as_raw_fd(), name.as_ptr(), 0) } != 0 {let error=std::io::Error::last_os_error();if error.raw_os_error()==Some(libc::EEXIST){fail!(EACCES,"SEALED_SNAPSHOT_FOREIGN_EXISTS");}fail!(EIO, "SEALED_SNAPSHOT_CREATE", "{}", error);} Ok(())
        }
        fn mount_snapshot(&self, config: &SealedConfig, name: &str, mount: &Path) -> EnclaveResult<()> {
            let mut child = snapshot_mount_command(config, name, mount)?
                .spawn().map_err(|e| err!(EIO, "SEALED_MOUNT", "{e}"))?;
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
            loop {
                match child.try_wait() {
                    Ok(Some(status)) => { if !status.success() { fail!(EPERM, "SEALED_MOUNT_REFUSED"); } return Ok(()); }
                    Ok(None) if std::time::Instant::now() < deadline => std::thread::sleep(std::time::Duration::from_millis(10)),
                    _ => { let _ = child.kill(); let _ = child.wait(); fail!(ETIMEDOUT, "SEALED_MOUNT_TIMEOUT"); }
                }
            }
        }
        fn verify_mount(&self, config: &SealedConfig, name: &str, mount: &Path) -> EnclaveResult<()> {
            let observed = statfs(mount)?;
            let required = (libc::MNT_RDONLY | libc::MNT_NOEXEC | libc::MNT_NOSUID | libc::MNT_NODEV) as u32;
            if field(&observed.f_fstypename) != b"apfs" || observed.f_flags & required != required
                || field(&observed.f_mntonname) != mount.as_os_str().as_bytes()
                || field(&observed.f_mntfromname) != format!("{name}@{}", config.volume_device).as_bytes()
            { fail!(EACCES, "SEALED_MOUNT_FLAGS"); } Ok(())
        }
        fn unmount(&self, mount: &Path) -> EnclaveResult<()> {
            let mount = cpath(mount)?;
            if unsafe { libc::unmount(mount.as_ptr(), 0) } != 0 { fail!(EIO, "SEALED_UNMOUNT"); } Ok(())
        }
        fn delete_snapshot(&self, volume: &Path, name: &str) -> EnclaveResult<()> {
            let volume = directory(volume)?; let name = CString::new(name).map_err(|_| err!(EINVAL, "SEALED_NAME"))?;
            if unsafe { fs_snapshot_delete(volume.as_raw_fd(), name.as_ptr(), 0) } != 0 {
                let error = std::io::Error::last_os_error();
                if error.raw_os_error() != Some(libc::ENOENT) { fail!(EIO, "SEALED_SNAPSHOT_DELETE", "{error}"); }
            } Ok(())
        }
    }
}
