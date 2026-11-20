//! Private staged streaming admission and verified snapshot export. Payload
//! memory is bounded independently of model length. No network transport lives
//! here; callers supply actual signed bytes.

use std::collections::BTreeMap;
use std::ffi::CString;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};

use enclave_core::error::EnclaveResult;
use enclave_core::ipc::PeerCredentials;
use enclave_core::{err, fail};
use enclave_crypto::tuf::TargetFile;
use crate::cas::{hex64, open_regular, verify_reader, ContentStore};

pub(crate) const MAX_ARTIFACT_BYTES: u64 = 8 * 1024 * 1024 * 1024;
pub(crate) const MAX_CHUNK_BYTES: usize = 256 * 1024;
const MAX_SESSIONS: usize = 4;
const MAX_DECLARED_BYTES: u64 = 16 * 1024 * 1024 * 1024;
const IDLE_TTL_S: i64 = 300;
const DISK_RESERVE: u64 = 4 * 1024 * 1024 * 1024;
// Conservative metadata/temp-file headroom beyond all payload copies.
const WRITE_OVERHEAD: u64 = 65 * 1024 * 1024;

pub(crate) fn validate_target(tf: &TargetFile) -> EnclaveResult<()> {
    if tf.length > MAX_ARTIFACT_BYTES { fail!(E2BIG, "ADMISSION_TOO_LARGE"); }
    for hash in ["blake3", "sha256"] {
        if !tf.hashes.get(hash).is_some_and(|h| hex64(h)) {
            fail!(EACCES, "ADMISSION_SIGNED_HASH_INVALID", "{hash}");
        }
    }
    if tf.custom.as_ref().and_then(|c| c.get("revoked")).and_then(|v| v.as_bool()) == Some(true) {
        fail!(EACCES, "TARGET_REVOKED");
    }
    Ok(())
}

struct Stage {
    path: PathBuf,
    writer: Option<File>,
    reservation: Option<crate::transport::quota::StagingReservation>,
}
impl Stage {
    fn create(dir: &Path) -> EnclaveResult<Self> {
        let path = dir.join(format!("stage-{:016x}{:016x}", enclave_core::rng::u64(), enclave_core::rng::u64()));
        let writer = OpenOptions::new().write(true).create_new(true).mode(0o600)
            .custom_flags(libc::O_NOFOLLOW).open(&path)
            .map_err(|e| err!(EIO, "ADMISSION_STAGE", "{e}"))?;
        Ok(Self { path, writer: Some(writer), reservation: None })
    }
    fn reserved(dir: &Path, tf: &TargetFile, quota: &crate::transport::quota::ArtifactStaging) -> EnclaveResult<Self> {
        let reservation = quota.reserve(&tf.hashes["blake3"], tf.length, tf.length)?;
        let mut stage = Self::create(dir)?;
        stage.reservation = Some(reservation);
        enclave_core::staging::preallocate(stage.writer.as_ref().unwrap(), tf.length)?;
        Ok(stage)
    }
    // The only constructor for SealedFile. The name is private and exclusive;
    // close ALL writable descriptors before the immutable mapping is possible.
    fn seal(mut self) -> EnclaveResult<SealedFile> {
        let writer = self.writer.as_ref().ok_or_else(|| err!(EIO, "ADMISSION_STAGE"))?;
        writer.sync_all().map_err(|e| err!(EIO, "ADMISSION_FSYNC", "{e}"))?;
        writer.set_permissions(fs::Permissions::from_mode(0o400))
            .map_err(|e| err!(EIO, "ADMISSION_CHMOD", "{e}"))?;
        let reader = open_regular(&self.path)?;
        fs::remove_file(&self.path).map_err(|e| err!(EIO, "ADMISSION_UNLINK", "{e}"))?;
        self.writer.take();
        Ok(SealedFile { file: reader, _reservation: self.reservation.take() })
    }
}
impl Drop for Stage {
    fn drop(&mut self) {
        // Logical removal, not a claim of physical erasure. An incomplete
        // stage is never published; truncate via its held FD before unlink.
        if let Some(file)=self.writer.take() {
            let _=file.set_len(0);
            if crate::transport::quota::remove_owned(&self.path,&file).is_err() {
                if let Some(reservation)=self.reservation.take() {reservation.defer_cleanup(self.path.clone(),file);}
            }
        }
    }
}

pub(crate) struct SealedFile { file: File, _reservation: Option<crate::transport::quota::StagingReservation> }
impl std::ops::Deref for SealedFile {type Target=File;fn deref(&self)->&File{&self.file}}
impl std::ops::DerefMut for SealedFile {fn deref_mut(&mut self)->&mut File{&mut self.file}}
impl Read for SealedFile {fn read(&mut self,bytes:&mut [u8])->std::io::Result<usize>{self.file.read(bytes)}}
impl SealedFile {
    pub(crate) fn into_parts(self)->(File,Option<crate::transport::quota::StagingReservation>){(self.file,self._reservation)}
    fn verify(&mut self, tf: &TargetFile) -> EnclaveResult<()> {
        self.file.rewind().map_err(|e| err!(EIO, "ADMISSION_SEEK", "{e}"))?;
        verify_reader(&mut self.file, tf.length, &tf.hashes["blake3"], &tf.hashes["sha256"])?;
        self.file.rewind().map_err(|e| err!(EIO, "ADMISSION_SEEK", "{e}"))?;
        Ok(())
    }
    fn sanitize(&mut self, target: &str, length: u64, require_format: bool) -> EnclaveResult<()> {
        let lower = target.to_ascii_lowercase();
        let mut prefix = [0u8; 16];
        let prefix_len = length.min(prefix.len() as u64) as usize;
        self.file.read_exact(&mut prefix[..prefix_len]).map_err(|e| err!(EIO, "ADMISSION_READ", "{e}"))?;
        crate::sanitizer::check_magic(target, &prefix[..prefix_len])?;
        self.file.rewind().map_err(|e| err!(EIO, "ADMISSION_SEEK", "{e}"))?;
        if lower.ends_with(".safetensors") {
            let mut prefix = [0u8; 8];
            self.file.read_exact(&mut prefix).map_err(|_| err!(EINVAL, "SAFETENSORS_SHORT"))?;
            let n = u64::from_le_bytes(prefix);
            if n > 64 * 1024 * 1024 || n.saturating_add(8) > length {
                fail!(E2BIG, "SAFETENSORS_HEADER_BOUNDS");
            }
            let mut header = Vec::with_capacity(8 + n as usize);
            header.extend_from_slice(&prefix);
            header.resize(8 + n as usize, 0);
            self.file.read_exact(&mut header[8..]).map_err(|_| err!(EINVAL, "SAFETENSORS_SHORT"))?;
            crate::sanitizer::check_safetensors_prefix(&header, length)?;
        } else if lower.ends_with(".mlpackage.zip") || lower.ends_with(".mlpackage") {
            // SAFETY: this inode was created privately by Stage, unlinked,
            // chmod 0400, and every writable FD closed before construction.
            // No caller can mutate it or obtain a handle until after munmap.
            // This preserves the complete ZIP/member/protobuf sanitizer without
            // allocating a Vec proportional to the artifact size.
            if length == 0 { fail!(EINVAL, "ZIP_SHORT"); }
            let len = usize::try_from(length).map_err(|_| err!(E2BIG, "ADMISSION_TOO_LARGE"))?;
            let ptr = unsafe { libc::mmap(std::ptr::null_mut(), len, libc::PROT_READ,
                libc::MAP_PRIVATE, self.file.as_raw_fd(), 0) };
            if ptr == libc::MAP_FAILED { fail!(EIO, "ADMISSION_MMAP"); }
            struct Mapping { ptr: *mut libc::c_void, len: usize }
            impl Drop for Mapping {
                fn drop(&mut self) { unsafe { libc::munmap(self.ptr, self.len); } }
            }
            let mapping = Mapping { ptr, len };
            let bytes = unsafe { std::slice::from_raw_parts(mapping.ptr.cast::<u8>(), mapping.len) };
            crate::sanitizer::check_mlpackage_zip(bytes, length)?;
        } else {
            let mut prefix = [0u8; 16];
            let n = self.file.read(&mut prefix).map_err(|e| err!(EIO, "ADMISSION_READ", "{e}"))?;
            if lower.ends_with(".gguf") {
                if n < 4 || &prefix[..4] != b"GGUF" { fail!(EINVAL, "GGUF_MAGIC_INVALID"); }
            } else if lower.ends_with(".bin") || lower.ends_with(".json") {
                crate::sanitizer::check_magic(target, &prefix[..n])?;
            } else if require_format {
                fail!(EACCES, "UNSUPPORTED_ARTIFACT_FORMAT");
            }
        }
        self.file.rewind().map_err(|e| err!(EIO, "ADMISSION_SEEK", "{e}"))?;
        Ok(())
    }
}

struct Session {
    peer: PeerCredentials,
    target: String,
    tf: TargetFile,
    received: u64,
    touched: i64,
    stage: Stage,
}

struct DetachedQuota {ledger:std::sync::Arc<std::sync::Mutex<(u64,u64)>>,bytes:u64}
impl Drop for DetachedQuota {fn drop(&mut self){if let Ok(mut ledger)=self.ledger.lock(){ledger.0=ledger.0.saturating_sub(self.bytes);ledger.1=ledger.1.saturating_sub(self.bytes+WRITE_OVERHEAD);}}}
pub(crate) struct PreparedAdmission {target:String,tf:TargetFile,sealed:SealedFile,_quota:DetachedQuota}
pub(crate) struct Sessions {
    detached:std::sync::Arc<std::sync::Mutex<(u64,u64)>>,
    staging: crate::transport::quota::ArtifactStaging,
    dir: PathBuf,
    sessions: BTreeMap<String, Session>,
    // Keep a process lock for the lifetime of the service: a concurrent
    // instance must never delete another live service's private stages.
    _lock: File,
}
impl Sessions {
    pub(crate) fn belongs_to(&self, root: &Path) -> bool { self.dir == root.join("streaming-stages") }
    pub(crate) fn open(root: &Path) -> EnclaveResult<Self> {
        Self::open_with_staging(root, crate::transport::quota::ArtifactStaging::default())
    }
    pub(crate) fn open_with_staging(root: &Path, staging: crate::transport::quota::ArtifactStaging) -> EnclaveResult<Self> {
        let dir = root.join("streaming-stages");
        match fs::create_dir(&dir) {
            Ok(()) => {},
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {},
            Err(e) => return Err(err!(EIO, "ADMISSION_STAGE_DIR", "{e}")),
        }
        let meta = fs::symlink_metadata(&dir).map_err(|e| err!(EIO, "ADMISSION_STAGE_DIR", "{e}"))?;
        if !meta.is_dir() || meta.file_type().is_symlink() || meta.uid() != enclave_core::ipc::geteuid() {
            fail!(EACCES, "ADMISSION_STAGE_DIR");
        }
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))
            .map_err(|e| err!(EIO, "ADMISSION_STAGE_DIR", "{e}"))?;
        let lock = OpenOptions::new().write(true).create(true).truncate(false).mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK).open(dir.join("lock"))
            .map_err(|e| err!(EIO, "ADMISSION_STAGE_LOCK", "{e}"))?;
        let lm = lock.metadata().map_err(|e| err!(EIO, "ADMISSION_STAGE_LOCK", "{e}"))?;
        if !lm.is_file() || lm.uid() != enclave_core::ipc::geteuid() || lm.nlink() != 1
            || lm.mode() & 0o777 != 0o600
            || unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            fail!(EACCES, "ADMISSION_STAGE_LOCK");
        }
        for entry in fs::read_dir(&dir).map_err(|e| err!(EIO, "ADMISSION_STAGE_DIR", "{e}"))? {
            let entry = entry.map_err(|e| err!(EIO, "ADMISSION_STAGE_DIR", "{e}"))?;
            if !entry.file_name().to_string_lossy().starts_with("stage-") { continue; }
            // Never follow a stale symlink or recursively delete a directory.
            let m = fs::symlink_metadata(entry.path()).map_err(|e| err!(EIO, "ADMISSION_CLEANUP", "{e}"))?;
            if m.uid() != enclave_core::ipc::geteuid() { fail!(EACCES, "ADMISSION_CLEANUP_UNSAFE"); }
            if m.is_file() {
                if m.nlink() != 1 || !matches!(m.mode() & 0o777, 0o600 | 0o400) {
                    fail!(EACCES, "ADMISSION_CLEANUP_UNSAFE");
                }
                let f = OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
                    .open(entry.path()).map_err(|e| err!(EIO, "ADMISSION_CLEANUP", "{e}"))?;
                let held = f.metadata().map_err(|e| err!(EIO, "ADMISSION_CLEANUP", "{e}"))?;
                if !held.is_file() || held.uid() != m.uid() || held.nlink() != 1
                    || held.mode() != m.mode() || held.dev() != m.dev() || held.ino() != m.ino() {
                    fail!(EACCES, "ADMISSION_CLEANUP_UNSAFE");
                }
                // A restart only unlinks stale private names. Never truncate
                // a pathname that might be an alias for unrelated user data.
            } else if !m.file_type().is_symlink() { fail!(EACCES, "ADMISSION_CLEANUP_UNSAFE"); }
            fs::remove_file(entry.path()).map_err(|e| err!(EIO, "ADMISSION_CLEANUP", "{e}"))?;
        }
        Ok(Self { dir, staging, sessions: BTreeMap::new(), detached:std::sync::Arc::new(std::sync::Mutex::new((0,0))), _lock: lock })
    }
    pub(crate) fn sweep(&mut self, now: i64) {
        self.sessions.retain(|_, s| now.saturating_sub(s.touched) <= IDLE_TTL_S);
    }
    pub(crate) fn clear(&mut self) { self.sessions.clear(); }
    pub(crate) fn staging_reserved(&self) -> EnclaveResult<u64> { self.staging.reserved() }
    fn outstanding(&self) -> u64 {
        // Includes remaining stage writes PLUS a full independent CAS chunk
        // copy at commit. Shared chunks may deduplicate but are not assumed.
        self.sessions.values().map(|s| 2 * s.tf.length - s.received + WRITE_OVERHEAD).sum::<u64>() + self.detached.lock().map(|ledger|ledger.1).unwrap_or(u64::MAX/2)
    }
    fn reserve(&self, extra: u64) -> EnclaveResult<()> {
        let required = required_disk(self.outstanding(), extra)?;
        let p = CString::new(self.dir.as_os_str().as_bytes()).map_err(|_| err!(EINVAL, "ADMISSION_STAGE_DIR"))?;
        let mut stat = std::mem::MaybeUninit::<libc::statvfs>::uninit();
        if unsafe { libc::statvfs(p.as_ptr(), stat.as_mut_ptr()) } != 0 { fail!(EIO, "ADMISSION_DISK_STAT"); }
        let stat = unsafe { stat.assume_init() };
        let free = (stat.f_bavail as u64).saturating_mul(stat.f_frsize as u64);
        if free < required { fail!(ENOMEM, "ADMISSION_DISK_RESERVE"); }
        Ok(())
    }
    /// Reserve canonical reassembly alongside every active stage/commit
    /// obligation. The service holds State while checking and materializing.
    pub(crate) fn reserve_materialization(&self, bytes: u64) -> EnclaveResult<()> {
        if bytes == 0 { return Ok(()); }
        let extra = bytes.checked_add(WRITE_OVERHEAD)
            .ok_or_else(|| err!(E2BIG, "ADMISSION_DISK_RESERVE"))?;
        self.reserve(extra)
    }
    pub(crate) fn begin(&mut self, peer: &PeerCredentials, target: String, tf: TargetFile, now: i64) -> EnclaveResult<String> {
        validate_target(&tf)?;
        if peer.pid.is_none_or(|pid| pid <= 0) { fail!(EPERM, "ADMISSION_PEER_PID_REQUIRED"); }
        if self.sessions.len() >= MAX_SESSIONS { fail!(E2BIG, "ADMISSION_SESSION_LIMIT"); }
        let declared: u64 = self.sessions.values().map(|s| s.tf.length).sum::<u64>() + self.detached.lock().map_err(|_|err!(EIO,"ADMISSION_QUOTA_LOCK"))?.0;
        if declared + tf.length > MAX_DECLARED_BYTES { fail!(E2BIG, "ADMISSION_DECLARED_LIMIT"); }
        self.reserve(2 * tf.length + WRITE_OVERHEAD)?;
        let stage = Stage::reserved(&self.dir, &tf, &self.staging)?;
        let session = loop {
            let id = hex::encode(enclave_core::rng::bytes32());
            if !self.sessions.contains_key(&id) { break id; }
        };
        self.sessions.insert(session.clone(), Session { peer: peer.clone(), target, tf, received: 0, touched: now, stage });
        Ok(session)
    }
    fn owned(&self, peer: &PeerCredentials, session: &str) -> EnclaveResult<()> {
        let s = self.sessions.get(session).ok_or_else(|| err!(EINVAL, "ADMISSION_SESSION_UNKNOWN"))?;
        // Full credentials preserve Darwin audit-token pidversion when present.
        // Without audit tokens, PID reuse inside the five-minute TTL remains
        // an explicit kernel-principal identity assumption.
        if &s.peer != peer { fail!(EPERM, "ADMISSION_SESSION_OWNER"); }
        Ok(())
    }
    pub(crate) fn chunk(&mut self, peer: &PeerCredentials, session: &str, offset: u64, bytes: &[u8], now: i64) -> EnclaveResult<u64> {
        self.owned(peer, session)?;
        let result = (|| {
            self.reserve(0)?;
            let s = self.sessions.get_mut(session).ok_or_else(|| err!(EINVAL, "ADMISSION_SESSION_UNKNOWN"))?;
            if bytes.is_empty() || bytes.len() > MAX_CHUNK_BYTES || offset != s.received
                || offset.checked_add(bytes.len() as u64).is_none_or(|end| end > s.tf.length) {
                fail!(EINVAL, "ADMISSION_CHUNK_BOUNDS");
            }
            s.stage.writer.as_mut().ok_or_else(|| err!(EIO, "ADMISSION_STAGE"))?
                .write_all(bytes).map_err(|e| err!(EIO, "ADMISSION_WRITE", "{e}"))?;
            s.received += bytes.len() as u64;
            s.touched = now;
            Ok(s.received)
        })();
        if result.is_err() { self.sessions.remove(session); }
        result
    }
    pub(crate) fn abort(&mut self, peer: &PeerCredentials, session: &str) -> EnclaveResult<()> {
        self.owned(peer, session)?;
        self.sessions.remove(session);
        Ok(())
    }
    pub(crate) fn commit(&mut self, peer: &PeerCredentials, session: &str,
        current: impl FnOnce(&str) -> EnclaveResult<TargetFile>, store: &ContentStore) -> EnclaveResult<(String, String)> {
        self.commit_with_publication(peer, session, current, store, |_, _| Ok(()))
    }
    pub(crate) fn commit_with_publication(&mut self, peer: &PeerCredentials, session: &str,
        current: impl FnOnce(&str) -> EnclaveResult<TargetFile>, store: &ContentStore,
        publish: impl FnOnce(&File, &TargetFile) -> EnclaveResult<()>) -> EnclaveResult<(String, String)> {
        let prepared=self.prepare(peer,session,current)?;
        let tf=prepared.tf.clone();self.commit_prepared(prepared,|_|Ok(tf),store,publish)
    }
    pub(crate) fn prepare(&mut self,peer:&PeerCredentials,session:&str,
        current:impl FnOnce(&str)->EnclaveResult<TargetFile>)->EnclaveResult<PreparedAdmission> {
        self.owned(peer,session)?;
        // Consuming a session closes its writable stage before detach. The
        // readonly unlinked result retains declaration/CAS-copy quota by RAII.
        let s=self.sessions.remove(session).ok_or_else(||err!(EINVAL,"ADMISSION_SESSION_UNKNOWN"))?;
        let tf=current(&s.target)?;validate_target(&tf)?;
        if tf!=s.tf {fail!(EACCES,"ADMISSION_TARGET_CHANGED");}
        if s.received!=tf.length {fail!(EACCES,"ADMISSION_LENGTH_MISMATCH");}
        self.reserve(tf.length+WRITE_OVERHEAD)?;
        let mut sealed=s.stage.seal()?;sealed.verify(&tf)?;sealed.sanitize(&s.target,tf.length,true)?;
        {let mut ledger=self.detached.lock().map_err(|_|err!(EIO,"ADMISSION_QUOTA_LOCK"))?;ledger.0+=tf.length;ledger.1+=tf.length+WRITE_OVERHEAD;}
        let bytes=tf.length;
        Ok(PreparedAdmission{target:s.target,tf,sealed,_quota:DetachedQuota{ledger:self.detached.clone(),bytes}})
    }
    pub(crate) fn commit_prepared(&self,mut prepared:PreparedAdmission,
        current:impl FnOnce(&str)->EnclaveResult<TargetFile>,store:&ContentStore,
        publish:impl FnOnce(&File,&TargetFile)->EnclaveResult<()>)->EnclaveResult<(String,String)> {
        let tf=current(&prepared.target)?;validate_target(&tf)?;
        if tf!=prepared.tf {fail!(EACCES,"ADMISSION_TARGET_CHANGED");}
        self.reserve(0)?;
        // One extra payload slot covers the broker's independently verified
        // private copy and then CAS temporary chunks, never concurrently.
        publish(&prepared.sealed.file,&tf)?;
        let _copy = self.staging.reserve(&tf.hashes["blake3"], tf.length, tf.length)?;
        prepared.sealed.file.rewind().map_err(|e|err!(EIO,"ADMISSION_SEEK","{e}"))?;
        let manifest=store.put_reader(&mut prepared.sealed.file)?;
        Ok((prepared.target,manifest.blake3))
    }
    pub(crate) fn export(&self, store: &ContentStore, target: &str, tf: &TargetFile) -> EnclaveResult<SealedFile> {
        validate_target(tf)?;
        self.reserve(tf.length + WRITE_OVERHEAD)?;
        let mut stage = Stage::reserved(&self.dir, tf, &self.staging)?;
        let destination = stage.writer.as_mut().ok_or_else(|| err!(EIO, "ADMISSION_STAGE"))?;
        if let Some(mut source) = open_named(store.root(), target)? {
            copy_exact(&mut source, destination, tf.length)?;
        } else if store.contains(&tf.hashes["blake3"]) {
            let m = store.manifest(&tf.hashes["blake3"])?;
            if m.len != tf.length || m.sha256 != tf.hashes["sha256"] {
                fail!(EACCES, "CAS_MANIFEST_MISMATCH");
            }
            store.copy_verified(&tf.hashes["blake3"], destination)?;
        } else {
            let hash = &tf.hashes["blake3"];
            let legacy = format!("chunks/{}/{}", &hash[..2], hash);
            let mut source = open_named(store.root(), &legacy)?.ok_or_else(|| err!(EINVAL, "TARGET_UNAVAILABLE"))?;
            copy_exact(&mut source, destination, tf.length)?;
        }
        let mut sealed = stage.seal()?;
        sealed.verify(tf)?;
        sealed.sanitize(target, tf.length, false)?;
        Ok(sealed)
    }
}

fn required_disk(outstanding: u64, extra: u64) -> EnclaveResult<u64> {
    DISK_RESERVE.checked_add(outstanding).and_then(|n| n.checked_add(extra))
        .ok_or_else(|| err!(E2BIG, "ADMISSION_DISK_RESERVE"))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn reservation_includes_all_declared_unwritten_commit_export_and_metadata_bytes() {
        let dir = std::env::temp_dir().join(format!("mcs-resource-{}",enclave_core::rng::u64()));
        fs::create_dir(&dir).unwrap();
        fs::set_permissions(&dir,fs::Permissions::from_mode(0o700)).unwrap();
        let mut sessions = Sessions::open(&dir).unwrap();
        let mut peer = PeerCredentials::local(enclave_core::ipc::geteuid(),0); peer.pid=Some(123);
        // Construct metadata-only sessions to test multi-GiB declared budgets
        // without writing or reserving those payloads on the personal runner.
        for (i,length,received) in [(0,8*1024*1024*1024,1024),(1,1024,0)] {
            let stage=Stage::create(&sessions.dir).unwrap();
            let tf=TargetFile { length, hashes: [("blake3".into(),"0".repeat(64)),("sha256".into(),"0".repeat(64))].into_iter().collect(), custom:None };
            sessions.sessions.insert(format!("session{i}"),Session {peer:peer.clone(),target:"x.bin".into(),tf,received,touched:0,stage});
        }
        let expected=16*1024*1024*1024-1024+2048+2*WRITE_OVERHEAD;
        assert_eq!(sessions.outstanding(),expected);
        assert_eq!(required_disk(sessions.outstanding(),4096+WRITE_OVERHEAD).unwrap(),DISK_RESERVE+expected+4096+WRITE_OVERHEAD);
        assert!(required_disk(u64::MAX,1).is_err());
        assert!(sessions.reserve_materialization(u64::MAX).unwrap_err().is("ADMISSION_DISK_RESERVE"));
        // Metadata-only outstanding obligations must remain charged when a
        // small canonical copy is requested; no huge file is allocated.
        sessions.sessions.get_mut("session0").unwrap().tf.length=u64::MAX/8;
        assert!(sessions.reserve_materialization(4096).unwrap_err().is("ADMISSION_DISK_RESERVE"));
        sessions.sessions.get_mut("session0").unwrap().tf.length=8*1024*1024*1024;
        // Aggregate declared-byte rejection is checked before consulting disk.
        sessions.sessions.get_mut("session1").unwrap().tf.length=8*1024*1024*1024;
        let tf=TargetFile {length:1, hashes:[("blake3".into(),"0".repeat(64)),("sha256".into(),"0".repeat(64))].into_iter().collect(),custom:None};
        assert!(sessions.begin(&peer,"x.bin".into(),tf,0).unwrap_err().is("ADMISSION_DECLARED_LIMIT"));
        sessions.clear(); drop(sessions);fs::remove_dir_all(dir).unwrap();
    }
}

// Resolve each component relative to a held root FD. No absolute/parent paths,
// symlink components, magic links, special files, or blocking FIFO opens.
fn open_named(root: &Path, target: &str) -> EnclaveResult<Option<File>> {
    if target.is_empty() || target.contains('\\') || target.as_bytes().contains(&0) {
        fail!(EINVAL, "TARGET_PATH");
    }
    let components: Vec<_> = Path::new(target).components().collect();
    if components.iter().any(|c| !matches!(c, Component::Normal(_))) { fail!(EINVAL, "TARGET_PATH"); }
    let mut dir = OpenOptions::new().read(true).custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(root).map_err(|e| err!(EIO, "TARGET_PATH", "{e}"))?;
    for (i, c) in components.iter().enumerate() {
        let Component::Normal(name) = c else { fail!(EINVAL, "TARGET_PATH"); };
        let name = CString::new(name.as_bytes()).map_err(|_| err!(EINVAL, "TARGET_PATH"))?;
        let final_component = i + 1 == components.len();
        let flags = libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK
            | if final_component { 0 } else { libc::O_DIRECTORY };
        let fd = unsafe { libc::openat(dir.as_raw_fd(), name.as_ptr(), flags) };
        if fd < 0 {
            let e = std::io::Error::last_os_error();
            if e.kind() == std::io::ErrorKind::NotFound { return Ok(None); }
            return Err(err!(EACCES, "TARGET_PATH", "{e}"));
        }
        let f = unsafe { File::from_raw_fd(fd) };
        if final_component {
            if !f.metadata().map_err(|e| err!(EIO, "TARGET_STAT", "{e}"))?.is_file() { fail!(EACCES, "TARGET_NOT_REGULAR"); }
            return Ok(Some(f));
        }
        dir = f;
    }
    fail!(EINVAL, "TARGET_PATH")
}

fn copy_exact(source: &mut File, destination: &mut File, length: u64) -> EnclaveResult<()> {
    let copied=std::io::copy(&mut (&mut *source).take(length), destination)
        .map_err(|e|err!(EIO,"TARGET_COPY","{e}"))?;
    let mut extra=[0];
    if copied!=length || source.read(&mut extra).map_err(|e|err!(EIO,"TARGET_COPY","{e}"))?!=0 {
        fail!(EACCES,"ADMISSION_LENGTH_MISMATCH");
    }
    Ok(())
}

#[cfg(test)]
mod phase1_tests {
    use super::*;
    use enclave_crypto::tuf::target_file;
    #[test]
    fn phase1_cleanup_retains_replaced_path_debt_and_startup_cannot_delete_live_work() {
        let dir=std::env::temp_dir().join(format!("p1-debt-{:x}",enclave_core::rng::u64()));fs::create_dir(&dir).unwrap();
        let store=ContentStore::open(&dir).unwrap();let quota=store.staging();let sessions=Sessions::open_with_staging(&dir,quota.clone()).unwrap();
        let tf=target_file(b"GGUF fixture",None);let stage=Stage::reserved(&sessions.dir,&tf,&quota).unwrap();let original=stage.path.clone();let moved=sessions.dir.join("held-original");
        fs::rename(&original,&moved).unwrap();fs::write(&original,b"foreign replacement").unwrap();drop(stage);
        assert_eq!(fs::read(&original).unwrap(),b"foreign replacement");assert!(quota.reserve("another",1,1).unwrap_err().is("STAGING_CLEANUP_REQUIRED"));assert!(quota.retry_cleanup().is_err());
        fs::remove_file(&original).unwrap();fs::rename(&moved,&original).unwrap();quota.retry_cleanup().unwrap();assert!(quota.reserve("another",1,1).is_ok());
        let temp=dir.join("chunks").join(format!("{}.tmp123",tf.hashes["blake3"]));fs::write(&temp,b"live temp").unwrap();fs::set_permissions(&temp,fs::Permissions::from_mode(0o600)).unwrap();
        let inspection=ContentStore::open(&dir).unwrap();assert!(temp.exists());assert!(Sessions::open(&dir).is_err());assert!(temp.exists());drop(inspection);
        store.reconcile_staging(&sessions).unwrap();assert!(!temp.exists());drop(sessions);drop(store);fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn phase1_real_sessions_preallocate_and_share_same_root_through_detach_and_failure() {
        use std::os::unix::fs::MetadataExt;
        let dir=std::env::temp_dir().join(format!("p1-stage-{:x}",enclave_core::rng::u64()));
        std::fs::create_dir(&dir).unwrap();
        let store=ContentStore::open(&dir).unwrap();
        let quota=store.staging();let mut sessions=Sessions::open_with_staging(&dir,quota.clone()).unwrap();
        let mut peer=PeerCredentials::local(enclave_core::ipc::geteuid(),0);peer.pid=Some(std::process::id() as i32);
        let bytes=b"GGUF bounded staging";let tf=target_file(bytes,None);
        let a=sessions.begin(&peer,"model.gguf".into(),tf.clone(),0).unwrap();
        let stage=&sessions.sessions[&a].stage;
        assert_eq!(stage.writer.as_ref().unwrap().metadata().unwrap().len(),bytes.len() as u64);
        #[cfg(target_os="linux")]
        assert!(stage.writer.as_ref().unwrap().metadata().unwrap().blocks()>0);
        let b=sessions.begin(&peer,"model.gguf".into(),tf.clone(),0).unwrap();
        let error=sessions.begin(&peer,"model.gguf".into(),tf.clone(),0).unwrap_err();
        assert!(error.is("STAGING_DISK_QUOTA_EXCEEDED"));assert_eq!(error.errno,enclave_core::error::Errno::EDQUOT);
        sessions.abort(&peer,&b).unwrap();
        sessions.chunk(&peer,&a,0,bytes,0).unwrap();
        let prepared=sessions.prepare(&peer,&a,|_|Ok(tf.clone())).unwrap();
        sessions.clear();assert_eq!(quota.reserved().unwrap(),tf.length);
        let b=sessions.begin(&peer,"model.gguf".into(),tf.clone(),0).unwrap();
        assert!(sessions.commit_prepared(prepared,|_|Ok(tf.clone()),&store,|_,_|Ok(())).unwrap_err().is("STAGING_DISK_QUOTA_EXCEEDED"));
        assert_eq!(quota.reserved().unwrap(),tf.length); // only b remains
        assert!(sessions.chunk(&peer,&b,1,bytes,0).is_err());
        assert_eq!(quota.reserved().unwrap(),0);
        let c=sessions.begin(&peer,"model.gguf".into(),tf.clone(),0).unwrap();
        sessions.chunk(&peer,&c,0,bytes,0).unwrap();
        sessions.commit(&peer,&c,|_|Ok(tf.clone()),&store).unwrap();
        assert_eq!(quota.reserved().unwrap(),0);
        let export=sessions.export(&store,"model.gguf",&tf).unwrap();assert_eq!(quota.reserved().unwrap(),tf.length);
        drop(export);assert_eq!(quota.reserved().unwrap(),0);
        let mut file=store.open_readonly(&tf.hashes["blake3"]).unwrap();let mut actual=vec![];file.read_to_end(&mut actual).unwrap();assert_eq!(actual,bytes);
        assert_eq!(quota.reserved().unwrap(),0);
        drop(sessions);drop(store);std::fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn phase1_zero_and_failed_preallocation_never_publish_a_stage() {
        let dir=std::env::temp_dir().join(format!("p1-alloc-{:x}",enclave_core::rng::u64()));std::fs::create_dir(&dir).unwrap();
        let file=dir.join("source");std::fs::write(&file,b"original").unwrap();
        let readonly=File::open(&file).unwrap();
        assert!(enclave_core::staging::preallocate(&readonly,8).unwrap_err().is("STAGING_DISK_QUOTA_EXCEEDED"));
        assert!(enclave_core::staging::preallocate(&readonly,u64::MAX).is_err());
        assert_eq!(std::fs::read(&file).unwrap(),b"original");
        let quota=crate::transport::quota::ArtifactStaging::default();
        let empty=target_file(b"",None);let stage=Stage::reserved(&dir,&empty,&quota).unwrap();
        assert_eq!(stage.writer.as_ref().unwrap().metadata().unwrap().len(),0);drop(stage);
        assert!(std::fs::read_dir(&dir).unwrap().all(|e|!e.unwrap().file_name().to_string_lossy().starts_with("stage-")));
        std::fs::remove_dir_all(dir).unwrap();
    }
}
