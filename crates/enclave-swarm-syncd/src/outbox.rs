//! Outbox drainer for OHTTP compliance rollup frames (GAP-26, FS-702 §4.3.2, FS-702 §7.4.2).
//!
//! Drains queued `*.ohttp` rollup frames from disk to the central compliance ledger gateway
//! under background traffic class `SO_TC_BK_SYS`, gating transmission on AC power and
//! nominal battery conditions.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use enclave_core::error::EnclaveResult;
use enclave_core::{err, fail};
use serde::{Deserialize, Serialize};

pub use crate::seedgate::HostConditions;

/// Default maximum outbox disk budget (100 MiB, FS-702 §7.4.2).
pub const DEFAULT_MAX_OUTBOX_BYTES: u64 = 100 * 1024 * 1024;


// One bounded staging name survives uncertain publication. It is deliberately
// not a drainable suffix, and no automatic cleanup of a preexisting guard occurs.
const ENQUEUE_PENDING: &[u8] = b".enqueue.pending\0";
const MAX_OUTBOX_DIRECTORY_ENTRIES: usize = 65_536;

// Advisory serialization for cooperating publishers and drainer namespace
// mutations. The held directory anchors every publication operation. This does
// not authenticate the path's ancestors or constrain uncooperative writers.
struct OutboxNamespace { directory: fs::File }

// Deterministic test-only boundary observation/injection. No hook type, TLS,
// callback or branch is compiled into a non-test library/daemon.
#[cfg(test)]
#[derive(Clone, Copy, PartialEq, Eq)]
enum EnqueueTestBoundary { BeforeFileSync, BeforePublish, AfterPublish, AfterFirstDirectorySync, AfterStageUnlink }
#[cfg(test)]
type EnqueueTestHook = Box<dyn FnOnce(&OutboxNamespace, &std::ffi::CStr) -> EnclaveResult<()>>;
#[cfg(test)]
thread_local! {
    static ENQUEUE_TEST_HOOK: std::cell::RefCell<Option<(EnqueueTestBoundary, EnqueueTestHook)>> = std::cell::RefCell::new(None);
}
#[cfg(test)]
fn enqueue_test_boundary(point: EnqueueTestBoundary, namespace: &OutboxNamespace, final_name: &std::ffi::CStr) -> EnclaveResult<()> {
    let hook = ENQUEUE_TEST_HOOK.with(|slot| {
        let mut slot = slot.borrow_mut();
        if slot.as_ref().is_some_and(|(selected, _)| *selected == point) { slot.take().map(|(_, hook)| hook) }
        else { None }
    });
    if let Some(hook) = hook { hook(namespace, final_name)?; }
    Ok(())
}

impl OutboxNamespace {
    fn try_lock(dir: &Path) -> EnclaveResult<Self> {
        use std::os::unix::{fs::{OpenOptionsExt, MetadataExt}, io::AsRawFd};
        let directory = fs::OpenOptions::new().read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(dir).map_err(|e| err!(EIO, "OUTBOX_DIRECTORY", "{e}"))?;
        let metadata = directory.metadata().map_err(|e| err!(EIO, "OUTBOX_DIRECTORY", "{e}"))?;
        if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o022 != 0 {
            fail!(EACCES, "OUTBOX_DIRECTORY_AUTHORITY");
        }
        if unsafe { libc::flock(directory.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::WouldBlock {
                fail!(EAGAIN, "OUTBOX_NAMESPACE_BUSY");
            }
            return Err(err!(EIO, "OUTBOX_NAMESPACE_LOCK", "{error}"));
        }
        Ok(Self { directory })
    }

    fn remove_staging(&self) -> EnclaveResult<()> {
        use std::os::unix::io::AsRawFd;
        if unsafe { libc::unlinkat(self.directory.as_raw_fd(), ENQUEUE_PENDING.as_ptr().cast(), 0) } != 0 {
            fail!(EIO, "OUTBOX_STAGING_CLEANUP");
        }
        #[cfg(test)]
        enqueue_test_boundary(EnqueueTestBoundary::AfterStageUnlink, self, std::ffi::CStr::from_bytes_with_nul(ENQUEUE_PENDING).unwrap())?;
        enclave_core::fsutil::full_fsync(&self.directory)
    }

    fn open_description(&self) -> EnclaveResult<fs::File> {
        use std::os::unix::io::{AsRawFd, FromRawFd};
        let fd = unsafe { libc::openat(self.directory.as_raw_fd(), c".".as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC) };
        if fd < 0 { fail!(EIO, "OUTBOX_SCAN_OPEN"); }
        Ok(unsafe { fs::File::from_raw_fd(fd) })
    }

    fn require_no_stage(&self) -> EnclaveResult<()> {
        use std::os::unix::io::AsRawFd;
        let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
        if unsafe { libc::fstatat(self.directory.as_raw_fd(), ENQUEUE_PENDING.as_ptr().cast(),
            metadata.as_mut_ptr(), libc::AT_SYMLINK_NOFOLLOW) } == 0 {
            fail!(EIO, "OUTBOX_PUBLICATION_RECOVERY_REQUIRED");
        }
        if std::io::Error::last_os_error().kind() != std::io::ErrorKind::NotFound {
            fail!(EIO, "OUTBOX_STAGE_STAT");
        }
        Ok(())
    }

    fn identity(&self) -> EnclaveResult<(u64, u64)> {
        use std::os::unix::fs::MetadataExt;
        let metadata = self.directory.metadata().map_err(|e| err!(EIO, "OUTBOX_DIRECTORY", "{e}"))?;
        Ok((metadata.dev(), metadata.ino()))
    }

    fn require_directory(&self, expected: (u64, u64)) -> EnclaveResult<()> {
        if self.identity()? != expected { fail!(EIO, "OUTBOX_DIRECTORY_CHANGED"); }
        Ok(())
    }

    fn entry_identity(&self, name: &std::ffi::CStr) -> EnclaveResult<EntryIdentity> {
        use std::os::unix::io::AsRawFd;
        let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
        if unsafe { libc::fstatat(self.directory.as_raw_fd(), name.as_ptr(), metadata.as_mut_ptr(), libc::AT_SYMLINK_NOFOLLOW) } != 0 {
            fail!(EIO, "OUTBOX_ENTRY_CHANGED");
        }
        EntryIdentity::checked(&unsafe { metadata.assume_init() })
    }

    fn require_entry(&self, entry: &OutboxEntry, file: &fs::File) -> EnclaveResult<()> {
        if self.entry_identity(&entry.name)? != entry.identity || file_identity(file)? != entry.identity {
            fail!(EIO, "OUTBOX_ENTRY_CHANGED");
        }
        Ok(())
    }

    // The stage may only be ignored by the enqueue call that exclusively
    // created it. Readers never interpret uncertain publication as drainable.
    fn scan(&self, owns_stage: bool, publication_reserve: usize) -> EnclaveResult<OutboxInventory> {
        self.scan_with_collection(owns_stage, publication_reserve, true)
    }

    // Diagnostics need aggregate metadata only, without retaining names/paths.
    fn scan_with_collection(&self, owns_stage: bool, publication_reserve: usize, collect_pending: bool) -> EnclaveResult<OutboxInventory> {
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        { fail!(ENOSYS, "OUTBOX_DIRECTORY_SCAN_UNSUPPORTED"); }
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            use std::os::unix::io::AsRawFd;
            struct Entries(*mut libc::DIR);
            impl Drop for Entries { fn drop(&mut self) { unsafe { libc::closedir(self.0); } } }
            #[cfg(target_os = "linux")]
            unsafe fn errno_slot() -> *mut libc::c_int { unsafe { libc::__errno_location() } }
            #[cfg(target_os = "macos")]
            unsafe fn errno_slot() -> *mut libc::c_int { unsafe { libc::__error() } }
            // dup would share the directory cursor and silently shorten later
            // inventories. openat creates an independent open-file-description.
            use std::os::unix::io::IntoRawFd;
            let descriptor = self.open_description()?.into_raw_fd();
            let raw = unsafe { libc::fdopendir(descriptor) };
            if raw.is_null() { unsafe { libc::close(descriptor); } fail!(EIO, "OUTBOX_READDIR"); }
            let entries = Entries(raw);
            let mut inventory = OutboxInventory { total: 0, maximum: None, pending_frames: 0, dead_frames: 0, pending: Vec::new() };
            let mut count = 0usize;
            loop {
                unsafe { *errno_slot() = 0; }
                let entry = unsafe { libc::readdir(entries.0) };
                if entry.is_null() {
                    if unsafe { *errno_slot() } != 0 { fail!(EIO, "OUTBOX_READDIR"); }
                    break;
                }
                let name = unsafe { std::ffi::CStr::from_ptr((*entry).d_name.as_ptr()) };
                let bytes = name.to_bytes();
                if bytes == b"." || bytes == b".." { continue; }
                count = count.checked_add(1).ok_or_else(|| err!(E2BIG, "OUTBOX_ENTRY_LIMIT"))?;
                if count > MAX_OUTBOX_DIRECTORY_ENTRIES { fail!(E2BIG, "OUTBOX_ENTRY_LIMIT"); }
                if bytes == &ENQUEUE_PENDING[..ENQUEUE_PENDING.len()-1] {
                    if !owns_stage { fail!(EIO, "OUTBOX_PUBLICATION_RECOVERY_REQUIRED"); }
                    continue;
                }
                let text = std::str::from_utf8(bytes).map_err(|_| err!(EACCES, "OUTBOX_ENTRY_NAME"))?;
                let numeric = text.strip_suffix(".ohttp").or_else(|| text.strip_suffix(".dead"))
                    .ok_or_else(|| err!(EACCES, "OUTBOX_ENTRY_NAME"))?;
                if numeric.len() != 20 || !numeric.bytes().all(|byte| byte.is_ascii_digit()) {
                    fail!(EACCES, "OUTBOX_ENTRY_NAME");
                }
                let sequence: u64 = numeric.parse().map_err(|_| err!(EACCES, "OUTBOX_ENTRY_NAME"))?;
                let identity = self.entry_identity(name)?;
                inventory.total = inventory.total.checked_add(identity.size)
                    .ok_or_else(|| err!(E2BIG, "OUTBOX_DISK_FULL"))?;
                inventory.maximum = Some(inventory.maximum.map_or(sequence, |previous: u64| previous.max(sequence)));
                if text.ends_with(".ohttp") {
                    inventory.pending_frames = inventory.pending_frames.checked_add(1)
                        .ok_or_else(|| err!(E2BIG, "OUTBOX_ENTRY_LIMIT"))?;
                    if collect_pending { inventory.pending.push(OutboxEntry { name: name.to_owned(), identity }); }
                } else {
                    inventory.dead_frames = inventory.dead_frames.checked_add(1)
                        .ok_or_else(|| err!(E2BIG, "OUTBOX_ENTRY_LIMIT"))?;
                }
            }
            if count.checked_add(publication_reserve).map_or(true, |value| value > MAX_OUTBOX_DIRECTORY_ENTRIES) {
                fail!(E2BIG, "OUTBOX_ENTRY_LIMIT");
            }
            inventory.pending.sort_by(|a, b| a.name.cmp(&b.name));
            Ok(inventory)
        }
    }

    fn inventory(&self) -> EnclaveResult<(u64, Option<u64>)> {
        let inventory = self.scan(true, 1)?;
        Ok((inventory.total, inventory.maximum))
    }

    fn read_entry(&self, entry: &OutboxEntry) -> EnclaveResult<(fs::File, Vec<u8>)> {
        use std::io::Read;
        use std::os::unix::io::{AsRawFd, FromRawFd};
        if entry.identity.size > DEFAULT_MAX_OUTBOX_BYTES { fail!(E2BIG, "OUTBOX_FRAME_LIMIT"); }
        let fd = unsafe { libc::openat(self.directory.as_raw_fd(), entry.name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC) };
        if fd < 0 { fail!(EIO, "OUTBOX_ENTRY_OPEN"); }
        let mut file = unsafe { fs::File::from_raw_fd(fd) };
        self.require_entry(entry, &file)?;
        let length = usize::try_from(entry.identity.size).map_err(|_| err!(E2BIG, "OUTBOX_FRAME_LIMIT"))?;
        let mut data = Vec::new();
        data.try_reserve_exact(length).map_err(|_| err!(ENOMEM, "OUTBOX_READ_ALLOCATION"))?;
        data.resize(length, 0);
        file.read_exact(&mut data).map_err(|e| err!(EIO, "OUTBOX_READ", "{e}"))?;
        let mut excess = [0u8; 1];
        if file.read(&mut excess).map_err(|e| err!(EIO, "OUTBOX_READ", "{e}"))? != 0 {
            fail!(EIO, "OUTBOX_ENTRY_CHANGED");
        }
        self.require_entry(entry, &file)?;
        Ok((file, data))
    }

    fn retire(&self, entry: &OutboxEntry, file: &fs::File, dead: bool) -> EnclaveResult<()> {
        use std::os::unix::io::AsRawFd;
        self.require_entry(entry, file)?;
        if dead {
            let text = entry.name.to_str().map_err(|_| err!(EINVAL, "OUTBOX_ENTRY_NAME"))?;
            let name = std::ffi::CString::new(format!("{}.dead", text.strip_suffix(".ohttp").unwrap()))
                .map_err(|_| err!(EINVAL, "OUTBOX_ENTRY_NAME"))?;
            // Atomic no-clobber rename uses no extra entry or two-link
            // intermediate. Unsupported kernels/filesystems fail closed; there
            // is deliberately no replacing-rename or unlink fallback.
            #[cfg(target_os = "linux")]
            let result = unsafe { libc::renameat2(self.directory.as_raw_fd(), entry.name.as_ptr(),
                self.directory.as_raw_fd(), name.as_ptr(), libc::RENAME_NOREPLACE) };
            #[cfg(target_os = "macos")]
            let result = unsafe { libc::renameatx_np(self.directory.as_raw_fd(), entry.name.as_ptr(),
                self.directory.as_raw_fd(), name.as_ptr(), libc::RENAME_EXCL) };
            #[cfg(not(any(target_os = "linux", target_os = "macos")))]
            let result = -1;
            if result != 0 { fail!(EIO, "OUTBOX_DEAD_PUBLICATION_UNCERTAIN"); }
            #[cfg(test)]
            retirement_test_boundary(RetirementTestBoundary::AfterDeadRename, self, &entry.name)?;
        } else {
            #[cfg(test)]
            retirement_test_boundary(RetirementTestBoundary::BeforeUnlink, self, &entry.name)?;
            if unsafe { libc::unlinkat(self.directory.as_raw_fd(), entry.name.as_ptr(), 0) } != 0 {
                fail!(EIO, "OUTBOX_RETIREMENT_UNCERTAIN");
            }
            #[cfg(test)]
            retirement_test_boundary(RetirementTestBoundary::AfterUnlink, self, &entry.name)?;
        }
        enclave_core::fsutil::full_fsync(&self.directory)
    }

}

// These observations detect ordinary replacement/in-place changes. They are not
// an authenticated filesystem identity or protection against uncooperative UID
// peers racing fstatat/unlinkat. Trusted ancestors and cooperating writers apply.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct EntryIdentity {
    device: u64, inode: u64, size: u64, mode: u32, uid: u32, links: u64,
    modified: (i64, i64), changed: (i64, i64),
}
impl EntryIdentity {
    fn checked(metadata: &libc::stat) -> EnclaveResult<Self> {
        if metadata.st_mode & libc::S_IFMT != libc::S_IFREG
            || metadata.st_uid != unsafe { libc::geteuid() }
            || metadata.st_mode & 0o022 != 0 || metadata.st_nlink != 1 || metadata.st_size < 0 {
            fail!(EACCES, "OUTBOX_ENTRY_TYPE");
        }
        Ok(Self { device: metadata.st_dev as u64, inode: metadata.st_ino as u64,
            size: metadata.st_size as u64, mode: metadata.st_mode as u32, uid: metadata.st_uid,
            links: metadata.st_nlink as u64,
            modified: (metadata.st_mtime as i64, metadata.st_mtime_nsec as i64),
            changed: (metadata.st_ctime as i64, metadata.st_ctime_nsec as i64) })
    }
}
fn file_identity(file: &fs::File) -> EnclaveResult<EntryIdentity> {
    use std::os::unix::io::AsRawFd;
    let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe { libc::fstat(file.as_raw_fd(), metadata.as_mut_ptr()) } != 0 { fail!(EIO, "OUTBOX_ENTRY_STAT"); }
    EntryIdentity::checked(&unsafe { metadata.assume_init() })
}
#[derive(Debug)]
struct OutboxEntry { name: std::ffi::CString, identity: EntryIdentity }
#[derive(Debug)]
struct OutboxInventory { total: u64, maximum: Option<u64>, pending_frames: u32, dead_frames: u32, pending: Vec<OutboxEntry> }

#[cfg(test)]
#[derive(Clone, Copy, PartialEq, Eq)]
enum RetirementTestBoundary { BeforeUnlink, AfterUnlink, AfterDeadRename }
#[cfg(test)]
type RetirementTestHook = Box<dyn FnOnce(&OutboxNamespace, &std::ffi::CStr) -> EnclaveResult<()>>;
#[cfg(test)]
thread_local! {
    static RETIREMENT_TEST_HOOK: std::cell::RefCell<Option<(RetirementTestBoundary, RetirementTestHook)>> = std::cell::RefCell::new(None);
}
#[cfg(test)]
fn retirement_test_boundary(point: RetirementTestBoundary, namespace: &OutboxNamespace, name: &std::ffi::CStr) -> EnclaveResult<()> {
    let hook = RETIREMENT_TEST_HOOK.with(|slot| {
        let mut slot = slot.borrow_mut();
        if slot.as_ref().is_some_and(|(selected, _)| *selected == point) { slot.take().map(|(_, hook)| hook) }
        else { None }
    });
    if let Some(hook) = hook { hook(namespace, name)?; }
    Ok(())
}

/// Atomically queue complete encrypted bytes without overwriting pending work.
///
/// The 100MiB check counts retained .ohttp/.dead payload lengths plus this
/// candidate's single staged inode. It excludes filesystem block/metadata
/// overhead. Cooperating namespace mutations use the same directory flock;
/// uncooperative writers and multiple independent drainers remain unsupported.
/// Publication or later sync/cleanup failure may already be receiver custody:
/// preserve final bytes and never infer that a returned error permits retry.
/// A preexisting .enqueue.pending always requires recovery, never auto-unlink.
pub fn enqueue_rollup(dir: &Path, enc: &[u8]) -> EnclaveResult<PathBuf> {
    use std::io::Write;
    use std::os::unix::io::{AsRawFd, FromRawFd};
    let bytes = u64::try_from(enc.len()).map_err(|_| err!(E2BIG, "OUTBOX_DISK_FULL"))?;
    if bytes > DEFAULT_MAX_OUTBOX_BYTES { fail!(E2BIG, "OUTBOX_DISK_FULL"); }
    let namespace = OutboxNamespace::try_lock(dir)?;
    let fd = unsafe { libc::openat(namespace.directory.as_raw_fd(), ENQUEUE_PENDING.as_ptr().cast(),
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC, 0o600) };
    if fd < 0 {
        if std::io::Error::last_os_error().kind() == std::io::ErrorKind::AlreadyExists {
            fail!(EIO, "OUTBOX_PUBLICATION_RECOVERY_REQUIRED");
        }
        fail!(EIO, "OUTBOX_STAGING_CREATE");
    }
    let mut staging = unsafe { fs::File::from_raw_fd(fd) };
    let mut publication_attempted = false;
    let result = (|| {
        let (current, maximum) = namespace.inventory()?;
        if current.checked_add(bytes).map_or(true, |total| total > DEFAULT_MAX_OUTBOX_BYTES) {
            fail!(E2BIG, "OUTBOX_DISK_FULL");
        }
        let sequence = match maximum {
            Some(maximum) => maximum.checked_add(1).ok_or_else(|| err!(E2BIG, "OUTBOX_SEQUENCE_EXHAUSTED"))?,
            None => 0,
        };
        let final_name = format!("{sequence:020}.ohttp");
        let final_c = std::ffi::CString::new(final_name.as_bytes()).map_err(|_| err!(EINVAL, "OUTBOX_ENTRY_NAME"))?;
        staging.write_all(enc).map_err(|e| err!(EIO, "OUTBOX_WRITE", "{e}"))?;
        #[cfg(test)]
        enqueue_test_boundary(EnqueueTestBoundary::BeforeFileSync, &namespace, &final_c)?;
        enclave_core::fsutil::full_fsync(&staging)?;
        #[cfg(test)]
        enqueue_test_boundary(EnqueueTestBoundary::BeforePublish, &namespace, &final_c)?;
        publication_attempted = true;
        // linkat is an atomic no-clobber publication on the same filesystem.
        // The temporary and final names share one inode, not two payloads.
        if unsafe { libc::linkat(namespace.directory.as_raw_fd(), ENQUEUE_PENDING.as_ptr().cast(),
            namespace.directory.as_raw_fd(), final_c.as_ptr(), 0) } != 0 {
            fail!(EIO, "OUTBOX_PUBLISH_UNCERTAIN");
        }
        #[cfg(test)]
        enqueue_test_boundary(EnqueueTestBoundary::AfterPublish, &namespace, &final_c)?;
        enclave_core::fsutil::full_fsync(&namespace.directory)?;
        #[cfg(test)]
        enqueue_test_boundary(EnqueueTestBoundary::AfterFirstDirectorySync, &namespace, &final_c)?;
        namespace.remove_staging()?;
        Ok(dir.join(final_name))
    })();
    if result.is_err() && !publication_attempted {
        // Only this call's unpublished staging name can be retired here.
        // A failed cleanup/sync may or may not leave it present; never promise
        // marker presence after successful unlink followed by failed fsync.
        namespace.remove_staging().map_err(|_| err!(EIO, "OUTBOX_STAGING_CLEANUP_UNCERTAIN"))?;
    }
    result
}

/// Default maximum consecutive retries before backing off.
pub const DEFAULT_MAX_RETRIES: u32 = 5;

/// Apply macOS background traffic class `SO_TC_BK_SYS` to the socket (FS-702 §7.4.2).
#[cfg(target_os = "macos")]
pub fn apply_background_traffic_class(sock_fd: std::os::unix::io::RawFd) -> EnclaveResult<()> {
    const SO_TRAFFIC_CLASS: libc::c_int = 0x1086;
    const SO_TC_BK_SYS: libc::c_int = 100;
    let ret = unsafe {
        libc::setsockopt(
            sock_fd,
            libc::SOL_SOCKET,
            SO_TRAFFIC_CLASS,
            &SO_TC_BK_SYS as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if ret != 0 {
        let err = std::io::Error::last_os_error();
        fail!(EIO, "SO_TRAFFIC_CLASS", "{err}");
    }
    Ok(())
}

/// No-op on non-macOS platforms.
#[cfg(not(target_os = "macos"))]
pub fn apply_background_traffic_class(_sock_fd: std::os::unix::io::RawFd) -> EnclaveResult<()> {
    Ok(())
}

/// Status of an outbox drain attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DrainStatus {
    /// Outbox was completely or partially drained to gateway.
    Success,
    /// Draining was deferred due to running on battery or macOS Low Power Mode.
    DeferredOnBattery,
    /// No pending frames; retained .dead bytes may still occupy custody.
    Empty,
    /// Outbox disk usage exceeded the budget; new queuing must fail closed.
    DiskCapExceeded,
    /// Transient gateway network failure during transmission.
    NetworkError,
}

/// Report summarizing an outbox drain pass.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DrainReport {
    /// Outcome of the drain attempt.
    pub status: DrainStatus,
    /// Frames accepted by the supplied transport and retired with directory sync.
    pub frames_drained: usize,
    /// Bytes in successfully retired frames, excluding failed/uncertain sends.
    pub bytes_drained: u64,
    /// Number of frames remaining in outbox.
    pub frames_remaining: usize,
    /// Logical pending plus dead-letter payload lengths; excludes filesystem overhead.
    pub disk_bytes_used: u64,
}

/// Transport abstraction for transmitting encapsulated OHTTP payloads to the ledger gateway.
pub trait OutboxTransport: Send + Sync {
    /// Transmit one encapsulated OHTTP request payload to the gateway.
    ///
    /// `Ok(())` authorizes local retirement under this implementation contract.
    /// Implementors must supply the required acceptance authority; plaintext
    /// HTTP 200 and recording fixtures are not authenticated delivery receipts.
    fn transmit(&self, enc_payload: &[u8]) -> EnclaveResult<()>;
}

/// Determine whether conditions allow outbox transmission (AC / battery gating).
pub fn should_drain(cond: &HostConditions) -> bool {
    // Defers drain if on battery power or macOS Low Power Mode is active
    cond.ac_power && !cond.low_power
}

/// Measure bounded retained logical payload bytes (.ohttp AND .dead), with
/// sorted pending paths. Missing/unsafe directories and recovery residue fail
/// closed; this is a snapshot, not a reservation for a subsequent enqueue.
pub fn measure_outbox_disk(dir: &Path) -> EnclaveResult<(u64, Vec<PathBuf>)> {
    let namespace = OutboxNamespace::try_lock(dir)?;
    let inventory = namespace.scan(false, 0)?;
    Ok((inventory.total, inventory.pending.into_iter().map(|entry|
        dir.join(std::ffi::OsStr::new(entry.name.to_str().unwrap()))).collect()))
}

/// Fixed producer for service-owned configured outbox metadata.
pub const OUTBOX_DIAGNOSTICS_PRODUCER: &str = "uid702-configured-outbox-v1";

/// Fixed aggregate logical payload counts, never allocated filesystem blocks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutboxCounts {
    /// Canonical pending .ohttp entries.
    pub pending_frames: u32,
    /// Canonical retained .dead entries, still counted as custody.
    pub dead_frames: u32,
    /// Checked sum of pending plus dead logical payload lengths.
    pub retained_bytes: u64,
}
impl OutboxCounts {
    /// Validate independently bounded aggregate counts and empty consistency.
    pub fn valid(&self) -> bool {
        self.pending_frames.checked_add(self.dead_frames)
            .is_some_and(|entries| entries as usize <= MAX_OUTBOX_DIRECTORY_ENTRIES
                && (entries != 0 || self.retained_bytes == 0))
    }
}

/// Fixed privacy-safe classification; no backend error text or paths on wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutboxObservationFault {
    /// Cooperating enqueue/drain owns the nonblocking namespace lock.
    NamespaceBusy,
    /// Uncertain staged publication requires separately authorized recovery.
    PublicationRecoveryRequired,
    /// The bounded directory-entry limit was exceeded.
    EntryLimit,
    /// Retained logical length summation could not be represented.
    ArithmeticOverflow,
    /// Unsafe entry/directory metadata or noncanonical name was observed.
    InvalidNamespace,
    /// Includes missing/inaccessible configured directory and other I/O errors.
    Unavailable,
}

/// Observation provenance: unavailable values are absent, never replacement zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "availability", rename_all = "snake_case", deny_unknown_fields)]
pub enum OutboxObservation {
    /// Complete cooperative snapshot of the configured queue.
    Current {
        /// Safe exact aggregate metadata.
        counts: OutboxCounts,
    },
    /// No trustworthy complete observation; do not infer empty or below budget.
    Unavailable {
        /// Fixed cause, without untrusted backend text.
        fault: OutboxObservationFault,
    },
}

/// Authenticated service-owned snapshot; process metadata is not hardware attestation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutboxDiagnosticsSnapshot {
    /// Wire schema, exactly one.
    pub schema: u32,
    /// Exact fixed producer, checked independently by the consumer.
    pub producer: String,
    /// Existing daemon initialization epoch; not ledger freshness authority.
    pub process_epoch_id: String,
    /// Captured actual process effective UID.
    pub process_uid: u32,
    /// Captured actual process PID.
    pub process_pid: u32,
    /// Explicit trusted startup mode.
    pub dev_same_uid: bool,
    /// Current aggregate values or a fixed unavailable classification.
    pub observation: OutboxObservation,
}
impl OutboxDiagnosticsSnapshot {
    /// Validate strict schema/provenance bounds, separately from kernel identity.
    pub fn valid(&self) -> bool {
        self.schema == 1 && self.producer == OUTBOX_DIAGNOSTICS_PRODUCER
            && self.process_epoch_id.len() == 36
            && enclave_core::seq::validate_epoch_id(&self.process_epoch_id).is_ok()
            && self.process_pid > 0
            && match self.observation {
                OutboxObservation::Current { counts } => counts.valid(),
                OutboxObservation::Unavailable { .. } => true,
            }
    }
}

// Immutable configured scope/provenance: observing never needs mutable State,
// the trusted clock, sealed files, journal, RPC sequence or authority backends.
pub(crate) struct OutboxDiagnostics {
    directory: PathBuf,
    process_epoch_id: String,
    process_uid: u32,
    process_pid: u32,
    dev_same_uid: bool,
}
impl OutboxDiagnostics {
    pub(crate) fn new(directory: PathBuf, process_epoch_id: String, dev_same_uid: bool) -> Self {
        Self { directory, process_epoch_id, process_uid: enclave_core::ipc::geteuid(),
            process_pid: std::process::id(), dev_same_uid }
    }
    fn counts(&self) -> EnclaveResult<OutboxCounts> {
        let namespace = OutboxNamespace::try_lock(&self.directory)?;
        let inventory = namespace.scan_with_collection(false, 0, false)?;
        Ok(OutboxCounts { pending_frames: inventory.pending_frames,
            dead_frames: inventory.dead_frames, retained_bytes: inventory.total })
    }
    pub(crate) fn snapshot(&self) -> OutboxDiagnosticsSnapshot {
        let observation = match self.counts() {
            Ok(counts) => OutboxObservation::Current { counts },
            Err(error) => {
                let fault = match error.reason.as_str() {
                    "OUTBOX_NAMESPACE_BUSY" => OutboxObservationFault::NamespaceBusy,
                    "OUTBOX_PUBLICATION_RECOVERY_REQUIRED" => OutboxObservationFault::PublicationRecoveryRequired,
                    "OUTBOX_ENTRY_LIMIT" => OutboxObservationFault::EntryLimit,
                    "OUTBOX_DISK_FULL" => OutboxObservationFault::ArithmeticOverflow,
                    "OUTBOX_DIRECTORY_AUTHORITY" | "OUTBOX_ENTRY_TYPE" | "OUTBOX_ENTRY_NAME" => OutboxObservationFault::InvalidNamespace,
                    _ => OutboxObservationFault::Unavailable,
                };
                OutboxObservation::Unavailable { fault }
            },
        };
        OutboxDiagnosticsSnapshot { schema: 1, producer: OUTBOX_DIAGNOSTICS_PRODUCER.into(),
            process_epoch_id: self.process_epoch_id.clone(), process_uid: self.process_uid,
            process_pid: self.process_pid, dev_same_uid: self.dev_same_uid, observation }
    }
}

/// Explicitly invoked outbox drainer. Production scheduling remains unwired.
pub struct OutboxDrainer {
    outbox_dir: PathBuf,
    max_outbox_bytes: u64,
    max_retries: u32,
    transport: Arc<dyn OutboxTransport>,
    failed_attempts: std::sync::Mutex<std::collections::HashMap<PathBuf, (EntryIdentity, u32)>>,
}

impl std::fmt::Debug for OutboxDrainer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OutboxDrainer")
            .field("outbox_dir", &self.outbox_dir)
            .field("max_outbox_bytes", &self.max_outbox_bytes)
            .field("max_retries", &self.max_retries)
            .finish()
    }
}

impl OutboxDrainer {
    /// Create a new drainer targeting `outbox_dir` with a custom transport.
    pub fn new(outbox_dir: impl Into<PathBuf>, transport: Arc<dyn OutboxTransport>) -> Self {
        Self {
            outbox_dir: outbox_dir.into(),
            max_outbox_bytes: DEFAULT_MAX_OUTBOX_BYTES,
            max_retries: DEFAULT_MAX_RETRIES,
            transport,
            failed_attempts: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }

    /// Create with explicit configuration options.
    pub fn with_options(
        outbox_dir: impl Into<PathBuf>,
        max_outbox_bytes: u64,
        max_retries: u32,
        transport: Arc<dyn OutboxTransport>,
    ) -> Self {
        Self {
            outbox_dir: outbox_dir.into(),
            max_outbox_bytes,
            max_retries,
            transport,
            failed_attempts: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }

    /// Check if queuing another frame of `bytes_len` would exceed the disk budget.
    pub fn assert_can_enqueue(&self, bytes_len: u64) -> EnclaveResult<()> {
        let (current_bytes, _) = measure_outbox_disk(&self.outbox_dir)?;
        if current_bytes.checked_add(bytes_len).map_or(true, |total| total > self.max_outbox_bytes.min(DEFAULT_MAX_OUTBOX_BYTES)) {
            fail!(
                E2BIG,
                "OUTBOX_DISK_FULL",
                "Outbox usage {} + {} > limit {}",
                current_bytes,
                bytes_len,
                self.max_outbox_bytes
            );
        }
        Ok(())
    }

    /// Execute a bounded pass with process-local retry hints. Cooperating
    /// publishers never hold the namespace lock during transport. A successful
    /// report counts only exact-object retirement followed by directory sync;
    /// transport Ok is still only the supplied transport's acceptance contract.
    /// Multiple independent drainer instances/processes remain unsupported.
    pub fn drain_once(&self, cond: &HostConditions) -> EnclaveResult<DrainReport> {
        // Also prevents reentrant callbacks/concurrent passes on this instance.
        let mut attempts = self.failed_attempts.try_lock().map_err(|error| match error {
            std::sync::TryLockError::WouldBlock => err!(EAGAIN, "OUTBOX_DRAIN_BUSY"),
            std::sync::TryLockError::Poisoned(_) => err!(EIO, "OUTBOX_DRAIN_STATE"),
        })?;
        let namespace = OutboxNamespace::try_lock(&self.outbox_dir)?;
        let directory = namespace.identity()?;
        // Keep the original directory inode alive across unlocked transport so
        // a replacement cannot reuse its identity during this pass.
        let _held_directory = namespace.open_description()?;
        let inventory = namespace.scan(false, 0)?;
        drop(namespace);
        let files = inventory.pending;
        use std::os::unix::ffi::OsStrExt;
        attempts.retain(|path, (identity, _)| match path.file_name() {
            Some(name) => files.binary_search_by(|entry| entry.name.to_bytes().cmp(name.as_bytes()))
                .is_ok_and(|index| files[index].identity == *identity),
            None => false,
        });
        if files.is_empty() || !should_drain(cond) {
            return Ok(DrainReport {
                status: if files.is_empty() { DrainStatus::Empty } else { DrainStatus::DeferredOnBattery },
                frames_drained: 0, bytes_drained: 0, frames_remaining: files.len(), disk_bytes_used: inventory.total,
            });
        }
        let mut frames_drained = 0;
        let mut bytes_drained = 0u64;
        let mut failed = false;
        for entry in &files {
            let namespace = OutboxNamespace::try_lock(&self.outbox_dir)?;
            namespace.require_directory(directory)?;
            // A stage created after inventory remains uncertain, never consumed.
            namespace.require_no_stage()?;
            let (file, data) = namespace.read_entry(entry)?;
            drop(namespace);
            let path = self.outbox_dir.join(entry.name.to_str().unwrap());
            match self.transport.transmit(&data) {
                Ok(()) => {
                    let namespace = OutboxNamespace::try_lock(&self.outbox_dir)?;
                    namespace.require_directory(directory)?;
                    namespace.require_no_stage()?;
                    namespace.retire(entry, &file, false)?;
                    attempts.remove(&path);
                    frames_drained += 1;
                    bytes_drained = bytes_drained.checked_add(entry.identity.size)
                        .ok_or_else(|| err!(E2BIG, "OUTBOX_DRAIN_BYTES_OVERFLOW"))?;
                }
                Err(_) => {
                    failed = true;
                    let (_, count) = attempts.entry(path.clone()).or_insert((entry.identity, 0));
                    *count = count.saturating_add(1);
                    if *count < self.max_retries.max(1) { break; }
                    let namespace = OutboxNamespace::try_lock(&self.outbox_dir)?;
                    namespace.require_directory(directory)?;
                    namespace.require_no_stage()?;
                    namespace.retire(entry, &file, true)?;
                    attempts.remove(&path);
                }
            }
        }
        let namespace = OutboxNamespace::try_lock(&self.outbox_dir)?;
        namespace.require_directory(directory)?;
        let final_inventory = namespace.scan(false, 0)?;
        Ok(DrainReport {
            status: if failed { DrainStatus::NetworkError } else { DrainStatus::Success },
            frames_drained, bytes_drained, frames_remaining: final_inventory.pending.len(), disk_bytes_used: final_inventory.total,
        })
    }

}

/// TCP transport transmitting encapsulated OHTTP payloads to a gateway/relay.
#[derive(Debug, Clone)]
pub struct TcpOutboxTransport {
    addr: std::net::SocketAddr,
    host_header: String,
}

impl TcpOutboxTransport {
    /// Create a new TCP outbox transport targeting `addr`.
    pub fn new(addr: std::net::SocketAddr, host_header: impl Into<String>) -> Self {
        Self {
            addr,
            host_header: host_header.into(),
        }
    }
}

// Bounded software HTTP transport. HTTP 200 is not an authenticated receipt.
const GATEWAY_HEADER_LIMIT: usize = 16 * 1024;
const GATEWAY_HOST_LIMIT: usize = 1024;
const GATEWAY_TOTAL_BUDGET: std::time::Duration = std::time::Duration::from_secs(10);

struct GatewayDeadline(std::time::Instant);
impl GatewayDeadline {
    fn remaining(&self) -> EnclaveResult<std::time::Duration> {
        let remaining = self.0.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() { fail!(ETIMEDOUT, "GATEWAY_DEADLINE"); }
        Ok(remaining)
    }
    fn io_error(&self, error: std::io::Error, reason: &str) -> enclave_core::error::EnclaveError {
        // Blocking reads/writes use only the remaining total budget. Kernels
        // may round that timeout, so their timeout result also exhausts it.
        if self.remaining().is_err() || matches!(error.kind(),
            std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock) {
            err!(ETIMEDOUT, "GATEWAY_DEADLINE")
        } else { err!(EIO, reason, "{error}") }
    }
}

fn gateway_write_all(stream: &mut std::net::TcpStream, mut bytes: &[u8], deadline: &GatewayDeadline) -> EnclaveResult<()> {
    use std::io::Write;
    while !bytes.is_empty() {
        stream.set_write_timeout(Some(deadline.remaining()?))
            .map_err(|error| err!(EIO, "GATEWAY_SOCKET_SETUP", "{error}"))?;
        match stream.write(bytes) {
            Ok(0) => fail!(EIO, "GATEWAY_WRITE", "zero-length write"),
            Ok(count) => { deadline.remaining()?; bytes = &bytes[count..]; },
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => { deadline.remaining()?; },
            Err(error) => return Err(deadline.io_error(error, "GATEWAY_WRITE")),
        }
    }
    deadline.remaining()?;
    Ok(())
}

fn gateway_response_headers(stream: &mut std::net::TcpStream, deadline: &GatewayDeadline) -> EnclaveResult<Vec<u8>> {
    use std::io::Read;
    let mut headers = Vec::with_capacity(GATEWAY_HEADER_LIMIT);
    let mut chunk = [0u8; 1024];
    loop {
        let available = chunk.len().min(GATEWAY_HEADER_LIMIT - headers.len());
        if available == 0 { fail!(E2BIG, "GATEWAY_RESPONSE_HEADERS_TOO_LARGE"); }
        stream.set_read_timeout(Some(deadline.remaining()?))
            .map_err(|error| err!(EIO, "GATEWAY_SOCKET_SETUP", "{error}"))?;
        match stream.read(&mut chunk[..available]) {
            Ok(0) => fail!(EIO, "GATEWAY_RESPONSE_FORMAT", "incomplete HTTP headers"),
            Ok(count) => {
                deadline.remaining()?;
                // Scan the overlap plus newly read bytes, avoiding quadratic
                // rescans when a peer drips a single byte at a time.
                let scan = headers.len().saturating_sub(3);
                headers.extend_from_slice(&chunk[..count]);
                if let Some(position) = headers[scan..].windows(4).position(|part| part == b"\r\n\r\n") {
                    headers.truncate(scan + position + 4);
                    return Ok(headers);
                }
            },
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => { deadline.remaining()?; },
            Err(error) => return Err(deadline.io_error(error, "GATEWAY_READ")),
        }
    }
}

fn gateway_validate_response(headers: &[u8]) -> EnclaveResult<()> {
    // Strict ASCII HTTP/1.x framing; no lossy decoding, folded fields, bare
    // CR/LF or controls except field/reason HTAB. Never echo peer response text.
    if headers.len() > GATEWAY_HEADER_LIMIT || !headers.ends_with(b"\r\n\r\n") || !headers.is_ascii() {
        fail!(EIO, "GATEWAY_RESPONSE_FORMAT");
    }
    let text = std::str::from_utf8(&headers[..headers.len() - 4])
        .map_err(|_| err!(EIO, "GATEWAY_RESPONSE_FORMAT"))?;
    let mut lines = text.split("\r\n");
    let status = lines.next().ok_or_else(|| err!(EIO, "GATEWAY_RESPONSE_FORMAT"))?.as_bytes();
    if status.len() < 13 || !(status.starts_with(b"HTTP/1.1 ") || status.starts_with(b"HTTP/1.0 "))
        || !status[9..12].iter().all(u8::is_ascii_digit) || status[12] != b' '
        || !status[13..].iter().all(|byte| *byte == b'\t' || (0x20..=0x7e).contains(byte)) {
        fail!(EIO, "GATEWAY_RESPONSE_FORMAT");
    }
    for line in lines {
        let (name, value) = line.split_once(':').ok_or_else(|| err!(EIO, "GATEWAY_RESPONSE_FORMAT"))?;
        if name.is_empty() || !name.bytes().all(|byte| byte.is_ascii_alphanumeric()
            || b"!#$%&'*+-.^_`|~".contains(&byte))
            || !value.bytes().all(|byte| byte == b'\t' || (0x20..=0x7e).contains(&byte)) {
            fail!(EIO, "GATEWAY_RESPONSE_FORMAT");
        }
    }
    if &status[9..12] != b"200" { fail!(EIO, "GATEWAY_ERROR", "HTTP status not 200"); }
    Ok(())
}

impl TcpOutboxTransport {
    fn transmit_with_budget(&self, enc_payload: &[u8], budget: std::time::Duration) -> EnclaveResult<()> {
        // Caller/new() ownership may already allocate. These checks bound
        // request formatting and network work, not caller-owned allocations.
        if enc_payload.len() as u64 > DEFAULT_MAX_OUTBOX_BYTES { fail!(E2BIG, "GATEWAY_PAYLOAD_TOO_LARGE"); }
        if self.host_header.is_empty() || self.host_header.len() > GATEWAY_HOST_LIMIT
            || !self.host_header.bytes().all(|byte| (0x21..=0x7e).contains(&byte)) {
            fail!(EINVAL, "GATEWAY_HOST_HEADER");
        }
        let deadline = GatewayDeadline(std::time::Instant::now().checked_add(budget)
            .ok_or_else(|| err!(EINVAL, "GATEWAY_DEADLINE_BUDGET"))?);
        let connect_budget = deadline.remaining()?.min(std::time::Duration::from_secs(5));
        let mut stream = std::net::TcpStream::connect_timeout(&self.addr, connect_budget)
            .map_err(|error| if deadline.remaining().is_err() { err!(ETIMEDOUT, "GATEWAY_DEADLINE") }
                else { err!(EIO, "GATEWAY_CONNECT", "{error}") })?;
        deadline.remaining()?;
        #[cfg(target_os = "macos")]
        {
            use std::os::unix::io::AsRawFd;
            apply_background_traffic_class(stream.as_raw_fd())?;
        }
        let request = format!(
            "POST /v1/rollup HTTP/1.1\r\nHost: {}\r\nContent-Type: message/ohttp-req\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            self.host_header, enc_payload.len());
        gateway_write_all(&mut stream, request.as_bytes(), &deadline)?;
        gateway_write_all(&mut stream, enc_payload, &deadline)?;
        // TcpStream is unbuffered: successful writes require no flush syscall.
        let headers = gateway_response_headers(&mut stream, &deadline)?;
        gateway_validate_response(&headers)?;
        deadline.remaining()?;
        Ok(())
    }
}

impl OutboxTransport for TcpOutboxTransport {
    fn transmit(&self, enc_payload: &[u8]) -> EnclaveResult<()> {
        self.transmit_with_budget(enc_payload, GATEWAY_TOTAL_BUDGET)
    }
}

#[cfg(test)]
#[path = "outbox_atomic_boundary_tests.rs"]
mod atomic_boundary_tests;

#[cfg(test)]
#[path = "outbox_retirement_boundary_tests.rs"]
mod retirement_boundary_tests;

#[cfg(test)]
#[path = "outbox_tcp_boundary_tests.rs"]
mod tcp_boundary_tests;

#[cfg(test)]
#[path = "outbox_diagnostics_boundary_tests.rs"]
mod diagnostics_boundary_tests;
