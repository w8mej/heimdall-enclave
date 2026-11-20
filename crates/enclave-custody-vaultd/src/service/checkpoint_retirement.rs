//! Bounded retirement of superseded APPLICATION runtime envelope checkpoints.
//! This is a private child of membership_cutover, not a generic path collector.
//! Every authoritative reference mutator must acquire this lease BEFORE reading
//! its source record/opening its store, including Preparing/Renewing that pin
//! recovery references. Retain through save_complete and publish/readback/retire.
//! No release serial may be held during any operation here. File operations
//! have bounded counts/lengths, not a kernel scheduling/latency guarantee.
use super::*;
use std::{
    collections::BTreeSet,
    ffi::{CStr, CString},
    fs::File,
    os::unix::{
        ffi::OsStrExt,
        fs::MetadataExt,
        io::{AsRawFd, FromRawFd},
    },
    path::{Component, PathBuf},
};

const MAX_SCAN: usize = 64;
const MAX_INSPECT: usize = 4;
const MAX_RETIRE: usize = 2;
const MAX_PROTECTED: usize = 32;
const FILES: [(&str, u64); 3] = [
    ("checkpoint.sealed", COMPLETE_LIMIT as u64),
    ("checkpoint.gen", 4096),
    ("sealing.key", 32),
];

/// Nonblocking publisher-wide inode lease. It is not independent rollback
/// protection against same-UID/privileged directory replacement or raw writers.
pub(in crate::service::asset_workflow) struct PublicationLease {
    _lease: enclave_core::sealed::StateDirectoryLease,
    state: PathBuf,
    parent: File,
}
impl std::fmt::Debug for PublicationLease {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PublicationLease").finish_non_exhaustive()
    }
}
/// Successful durable publication plus best-effort cleanup counts. Deferred
/// cleanup never downgrades a successful publication or authorizes old state.
#[derive(Debug, Default)]
pub(super) struct PublicationReport {
    pub(super) examined: usize,
    pub(super) retired: usize,
    pub(super) deferred: bool,
}
impl PublicationLease {
    pub(in crate::service::asset_workflow) fn acquire(state: &Path) -> EnclaveResult<Self> {
        let state = platform_path(state);
        let path = state.join("membership-checkpoints");
        let lease = enclave_core::sealed::StateDirectoryLease::acquire(&path)?;
        let parent = private_directory(&path)?;
        Ok(Self {
            _lease: lease,
            state,
            parent,
        })
    }
    fn namespace_current(&self) -> EnclaveResult<()> {
        let current = private_directory(&self.state.join("membership-checkpoints"))?;
        if inode(&current)? != inode(&self.parent)? {
            fail!(ESTALE, "CHECKPOINT_RETIREMENT_NAMESPACE_CHANGED");
        }
        Ok(())
    }
    /// Own the actual authoritative save: a caller cannot turn a failed save
    /// into retirement by supplying a success flag. Parent validation/factors
    /// remain mandatory; this wrapper supplies no admission or release grant.
    /// Preparing recovery content/counter stores are outside our namespace.
    pub(super) fn publish(
        &self,
        store: &mut SealedStore,
        next: &Ledger,
        previous: Option<&CommittedMembership>,
        additional_protected: &[[u8; 32]],
    ) -> EnclaveResult<PublicationReport> {
        if additional_protected.len() > MAX_PROTECTED {
            fail!(E2BIG, "CHECKPOINT_RETIREMENT_PROTECTED_LIMIT");
        }
        self.namespace_current()?;
        validate_v3(next)?;
        let Phase::MembershipCommitted {record}= &next.phase else {fail!(EACCES,"CHECKPOINT_RETIREMENT_COMMITTED_REQUIRED");};
        let successor = load_complete(&self.state, record)?;
        let mut protected: BTreeSet<[u8; 32]> = additional_protected.iter().copied().collect();
        protected.insert(record.checkpoint_sha256);
        if let Some(previous) = previous {
            let old = load_complete(&self.state, previous)?;
            if !preserves(&successor.primary, &old.primary)? {
                fail!(EACCES, "CHECKPOINT_RETIREMENT_CONTENT_LOSS");
            }
            protected.insert(previous.checkpoint_sha256);
        }
        // Refuse a store opened before competing publication. The required
        // parent hooks still acquire BEFORE their source read; this generation
        // check is defense in depth, not a substitute for complete exclusion.
        let (fresh, before) = open(&self.state)?;
        validate_v3_pins(&self.state, &before)?;
        if fresh.generation() != store.generation() {
            fail!(ESTALE, "CHECKPOINT_RETIREMENT_STALE_STORE");
        }
        // Explicit exhaustive recovery-reference inventory. Unknown phases
        // cannot opt in by passing only some hashes: publication may finish but
        // retirement stays deferred until that exact variant is reviewed.
        let references_known = match &before.phase {
            Phase::MembershipCommitted { record: old } => {
                protected.insert(old.checkpoint_sha256);
                if !preserves(
                    &successor.primary,
                    &load_complete(&self.state, old)?.primary,
                )? {
                    fail!(EACCES, "CHECKPOINT_RETIREMENT_CONTENT_LOSS");
                }
                true
            }
            Phase::MembershipPreparing { .. } => true, // fixed original content/counters live elsewhere
            Phase::MembershipRenewing { renewal, .. } => {
                protected.insert(renewal.previous.checkpoint_sha256);
                if !preserves(
                    &successor.primary,
                    &load_complete(&self.state, &renewal.previous)?.primary,
                )? {
                    fail!(EACCES, "CHECKPOINT_RETIREMENT_CONTENT_LOSS");
                }
                true
            }
            _ => false,
        };
        // Test-only one-shot OS fault occurs after the real fresh-store check,
        // at the actual save boundary. Production has no callback/fault state.
        #[cfg(test)]
        apply_save_fault()?;
        durable_then(store, next, || {
            let (_, current) = open(&self.state)?;
            if enclave_core::jcs::to_jcs_bytes(&current)? != enclave_core::jcs::to_jcs_bytes(next)?
            {
                fail!(ESTALE, "CHECKPOINT_RETIREMENT_REFERENCE_CHANGED");
            }
            validate_v3_pins(&self.state, &current)?;
            self.namespace_current()?;
            // Only this point follows successful save AND exact authenticated
            // readback. Any earlier error performs zero unlink operations.
            Ok(if references_known {
                self.retire(&successor, &protected)
            } else {
                PublicationReport {
                    deferred: true,
                    ..Default::default()
                }
            })
        })
    }
    /// Sterile recovery phase publication. This owns the real save, independent
    /// acceptance and exact authenticated readback. It never retires content.
    pub(in crate::service::asset_workflow) fn publish_sterile_recovery(
        &self,
        store: &mut SealedStore,
        before: &Ledger,
        next: &Ledger,
        accept: impl FnOnce() -> EnclaveResult<()>,
    ) -> EnclaveResult<()> {
        self.namespace_current()?;
        super::super::member_loss_workflow::validate_v4(next)?;
        let (fresh, current) = open(&self.state)?;
        if fresh.generation() != store.generation()
            || enclave_core::jcs::to_jcs_bytes(&current)?
                != enclave_core::jcs::to_jcs_bytes(before)?
        {
            fail!(ESTALE, "MEMBER_LOSS_SOURCE_CHANGED");
        }
        #[cfg(test)]
        apply_save_fault()?;
        store.save_json(next)?;
        accept()?;
        let (_, current) = open(&self.state)?;
        if enclave_core::jcs::to_jcs_bytes(&current)? != enclave_core::jcs::to_jcs_bytes(next)? {
            fail!(ESTALE, "MEMBER_LOSS_READBACK_CHANGED");
        }
        self.namespace_current()?;
        Ok(())
    }
    fn retire(
        &self,
        current: &CompleteMembershipCheckpoint,
        protected: &BTreeSet<[u8; 32]>,
    ) -> PublicationReport {
        let mut report = PublicationReport::default();
        let (names, limited) = match names(&self.parent, MAX_SCAN) {
            Ok(value) => value,
            Err(_) => {
                report.deferred = true;
                return report;
            }
        };
        report.deferred = limited;
        for name in names {
            let Some(hash)=hash_name(&name) else {report.deferred=true;continue;};
            if protected.contains(&hash) {
                continue;
            }
            if report.examined == MAX_INSPECT || report.retired == MAX_RETIRE {
                report.deferred = true;
                break;
            }
            report.examined += 1;
            let result = (|| -> EnclaveResult<bool> {
                self.namespace_current()?;
                let child = child_directory(&self.parent, &name)?;
                let identity = inode(&child)?;
                validate_files(&child)?;
                let (_, loaded) = complete_store(&self.state, &hash)?;
                let Loaded::State(bytes)=loaded else {fail!(EACCES,"CHECKPOINT_RETIREMENT_PARTIAL");};
                let old: CompleteMembershipCheckpoint = enclave_core::sealed::decode(&bytes)?;
                if complete_hash(&old)? != hash
                    || old.version != 3
                    || old.membership_generation == 0
                    || old.sequence == 0
                    || old.membership_generation > INTEGER_LIMIT
                    || old.sequence > INTEGER_LIMIT
                {
                    fail!(EACCES, "CHECKPOINT_RETIREMENT_CHECKPOINT");
                }
                let older = old.membership_generation < current.membership_generation
                    || (old.membership_generation == current.membership_generation
                        && old.sequence < current.sequence);
                if !older || !preserves(&current.primary, &old.primary)? {
                    return Ok(false);
                }
                self.namespace_current()?;
                if inode(&child_directory(&self.parent, &name)?)? != identity {
                    fail!(ESTALE, "CHECKPOINT_RETIREMENT_ENTRY_CHANGED");
                }
                // No recursive traversal. All three exact files are validated
                // before the first unlink, and again at the unlink boundary.
                remove_checkpoint(&self.parent, &name, &child)?;
                Ok(true)
            })();
            match result {
                Ok(true) => report.retired += 1,
                Ok(false) | Err(_) => report.deferred = true,
            }
        }
        report
    }
}

#[cfg(test)]
thread_local! {static NEXT_SAVE_OBSTRUCTION:std::cell::RefCell<Option<PathBuf>>=const {std::cell::RefCell::new(None)};}
#[cfg(test)]
#[derive(Debug)]
pub(super) struct SaveFaultGuard;
#[cfg(test)]
impl Drop for SaveFaultGuard {
    fn drop(&mut self) {
        NEXT_SAVE_OBSTRUCTION.with(|slot| {
            slot.borrow_mut().take();
        });
    }
}
#[cfg(test)]
pub(super) fn obstruct_next_save(path: PathBuf) -> SaveFaultGuard {
    NEXT_SAVE_OBSTRUCTION.with(|slot| {
        assert!(slot.borrow_mut().replace(path).is_none());
    });
    SaveFaultGuard
}
#[cfg(test)]
fn apply_save_fault() -> EnclaveResult<()> {
    if let Some(path) = NEXT_SAVE_OBSTRUCTION.with(|slot| slot.borrow_mut().take()) {
        std::fs::remove_file(&path).map_err(|_| err!(EIO, "CHECKPOINT_TEST_FAULT"))?;
        std::fs::create_dir(path).map_err(|_| err!(EIO, "CHECKPOINT_TEST_FAULT"))?;
    }
    Ok(())
}

// Private factoring lets fault tests exercise the SAME real save-before-effect
// ordering with small fixture bodies; it is not a public authority callback.
fn durable_then<T: Serialize, R>(
    store: &mut SealedStore,
    next: &T,
    after: impl FnOnce() -> EnclaveResult<R>,
) -> EnclaveResult<R> {
    store.save_json(next)?;
    after()
}
fn platform_path(path: &Path) -> PathBuf {
    #[cfg(target_os = "macos")]
    for (alias, real) in [("/var", "/private/var"), ("/tmp", "/private/tmp")] {
        if let Ok(suffix) = path.strip_prefix(alias) {
            return Path::new(real).join(suffix);
        }
    }
    path.to_path_buf()
}
fn inode(file: &File) -> EnclaveResult<(u64, u64)> {
    let metadata = file
        .metadata()
        .map_err(|_| err!(EIO, "CHECKPOINT_RETIREMENT_METADATA"))?;
    Ok((metadata.dev(), metadata.ino()))
}
fn private_directory(path: &Path) -> EnclaveResult<File> {
    if !path.is_absolute() {
        fail!(EACCES, "CHECKPOINT_RETIREMENT_PATH");
    }
    let components: Vec<_> = path.components().collect();
    if components.len() < 2 {
        fail!(EACCES, "CHECKPOINT_RETIREMENT_PATH");
    }
    let mut file = File::open("/").map_err(|_| err!(EIO, "CHECKPOINT_RETIREMENT_PATH"))?;
    for (index, part) in components.iter().enumerate().skip(1) {
        let Component::Normal(name)=part else {fail!(EACCES,"CHECKPOINT_RETIREMENT_PATH");};
        let name = CString::new(name.as_bytes())
            .map_err(|_| err!(EACCES, "CHECKPOINT_RETIREMENT_PATH"))?;
        file = open_dir_at(&file, &name)?;
        let m = file
            .metadata()
            .map_err(|_| err!(EIO, "CHECKPOINT_RETIREMENT_METADATA"))?;
        let uid = unsafe { libc::geteuid() };
        let sticky = m.uid() == 0 && m.mode() & 0o1000 != 0;
        if (m.uid() != 0 && m.uid() != uid)
            || (m.mode() & 0o022 != 0 && !sticky)
            || (index + 1 == components.len() && (m.uid() != uid || m.mode() & 0o077 != 0))
        {
            fail!(EACCES, "CHECKPOINT_RETIREMENT_PATH");
        }
    }
    Ok(file)
}
fn open_dir_at(parent: &File, name: &CStr) -> EnclaveResult<File> {
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        fail!(EACCES, "CHECKPOINT_RETIREMENT_DIRECTORY");
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}
fn child_directory(parent: &File, name: &[u8]) -> EnclaveResult<File> {
    if hash_name(name).is_none() {
        fail!(EACCES, "CHECKPOINT_RETIREMENT_NAME");
    }
    let name = CString::new(name).map_err(|_| err!(EACCES, "CHECKPOINT_RETIREMENT_NAME"))?;
    let file = open_dir_at(parent, &name)?;
    let m = file
        .metadata()
        .map_err(|_| err!(EIO, "CHECKPOINT_RETIREMENT_METADATA"))?;
    if m.uid() != unsafe { libc::geteuid() } || m.mode() & 0o077 != 0 {
        fail!(EACCES, "CHECKPOINT_RETIREMENT_DIRECTORY");
    }
    Ok(file)
}
fn hash_name(name: &[u8]) -> Option<[u8; 32]> {
    if name.len() != 64
        || !name
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    {
        return None;
    }
    let mut out = [0; 32];
    hex::decode_to_slice(name, &mut out).ok()?;
    Some(out)
}
struct DirectoryStream(*mut libc::DIR);
impl Drop for DirectoryStream {
    fn drop(&mut self) {
        unsafe { libc::closedir(self.0) };
    }
}
fn names(parent: &File, maximum: usize) -> EnclaveResult<(Vec<Vec<u8>>, bool)> {
    let fd = unsafe { libc::fcntl(parent.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
    if fd < 0 {
        fail!(EIO, "CHECKPOINT_RETIREMENT_SCAN");
    }
    let stream = unsafe { libc::fdopendir(fd) };
    if stream.is_null() {
        unsafe { libc::close(fd) };
        fail!(EIO, "CHECKPOINT_RETIREMENT_SCAN");
    }
    let stream = DirectoryStream(stream);
    unsafe { libc::rewinddir(stream.0) };
    let mut output = Vec::new();
    let mut steps = 0;
    while steps < maximum + 2 {
        #[cfg(target_os = "linux")]
        unsafe {
            *libc::__errno_location() = 0;
        }
        #[cfg(target_os = "macos")]
        unsafe {
            *libc::__error() = 0;
        }
        let entry = unsafe { libc::readdir(stream.0) };
        if entry.is_null() {
            if std::io::Error::last_os_error()
                .raw_os_error()
                .is_some_and(|code| code != 0)
            {
                fail!(EIO, "CHECKPOINT_RETIREMENT_SCAN");
            }
            return Ok((output, false));
        }
        steps += 1;
        let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
        if name == b"." || name == b".." {
            continue;
        }
        if output.len() == maximum {
            return Ok((output, true));
        }
        output.push(name.to_vec());
    }
    Ok((output, true))
}
fn opened_file(parent: &File, name: &str, maximum: u64) -> EnclaveResult<File> {
    let name = CString::new(name).map_err(|_| err!(EACCES, "CHECKPOINT_RETIREMENT_NAME"))?;
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        fail!(EACCES, "CHECKPOINT_RETIREMENT_FILE");
    }
    let file = unsafe { File::from_raw_fd(fd) };
    let m = file
        .metadata()
        .map_err(|_| err!(EIO, "CHECKPOINT_RETIREMENT_METADATA"))?;
    if !m.is_file()
        || m.uid() != unsafe { libc::geteuid() }
        || m.mode() & 0o077 != 0
        || m.nlink() != 1
        || m.len() > maximum
        || (maximum == 32 && m.len() != 32)
    {
        fail!(EACCES, "CHECKPOINT_RETIREMENT_FILE");
    }
    Ok(file)
}
fn validate_files(child: &File) -> EnclaveResult<()> {
    let (listed, limited) = names(child, 4)?;
    if limited
        || listed.len() != FILES.len()
        || listed
            .iter()
            .any(|name| !FILES.iter().any(|(allowed, _)| name == allowed.as_bytes()))
    {
        fail!(EACCES, "CHECKPOINT_RETIREMENT_PARTIAL");
    }
    for (name, maximum) in FILES {
        opened_file(child, name, maximum)?;
    }
    Ok(())
}
fn remove_checkpoint(parent: &File, name: &[u8], child: &File) -> EnclaveResult<()> {
    validate_files(child)?;
    for (file, maximum) in FILES {
        let held = opened_file(child, file, maximum)?;
        let path = CString::new(file).map_err(|_| err!(EACCES, "CHECKPOINT_RETIREMENT_NAME"))?;
        // Retain and compare the initialized file inode before unlink. Never
        // follow a swapped symlink or remove an unknown descendant.
        let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
        if unsafe {
            libc::fstatat(
                child.as_raw_fd(),
                path.as_ptr(),
                metadata.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } < 0
        {
            fail!(EIO, "CHECKPOINT_RETIREMENT_METADATA");
        }
        let metadata = unsafe { metadata.assume_init() };
        let identity = inode(&held)?;
        if (metadata.st_dev as u64, metadata.st_ino as u64) != identity {
            fail!(ESTALE, "CHECKPOINT_RETIREMENT_FILE_CHANGED");
        }
        if unsafe { libc::unlinkat(child.as_raw_fd(), path.as_ptr(), 0) } < 0 {
            fail!(EIO, "CHECKPOINT_RETIREMENT_UNLINK");
        }
    }
    enclave_core::fsutil::full_fsync(child)?;
    let name = CString::new(name).map_err(|_| err!(EACCES, "CHECKPOINT_RETIREMENT_NAME"))?;
    if unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), libc::AT_REMOVEDIR) } < 0 {
        fail!(EIO, "CHECKPOINT_RETIREMENT_UNLINK");
    }
    enclave_core::fsutil::full_fsync(parent)
}

// Compare typed serialization so unknown future fields default to exact
// equality. Only monotonic sealing statistics/counts and added unchanged
// ciphertext entries are allowed. This cannot authorize migration/deletion.
fn preserves(
    new: &crate::vault::VaultEnvelopeCheckpoint,
    old: &crate::vault::VaultEnvelopeCheckpoint,
) -> EnclaveResult<bool> {
    if new.enrollment_binding()? != old.enrollment_binding()? {
        return Ok(false);
    }
    let mut new =
        serde_json::to_value(new).map_err(|_| err!(EIO, "CHECKPOINT_RETIREMENT_ENCODE"))?;
    let mut old =
        serde_json::to_value(old).map_err(|_| err!(EIO, "CHECKPOINT_RETIREMENT_ENCODE"))?;
    let object = |value: &serde_json::Value,
                  key: &str|
     -> EnclaveResult<serde_json::Map<String, serde_json::Value>> {
        value
            .get(key)
            .and_then(|value| value.as_object())
            .cloned()
            .ok_or_else(|| err!(EACCES, "CHECKPOINT_RETIREMENT_SHAPE"))
    };
    let counts = |new: &serde_json::Value, old: &serde_json::Value| -> bool {
        new.as_u64()
            .zip(old.as_u64())
            .is_some_and(|(new, old)| new >= old)
    };
    let new_store = object(&new, "store")?;
    let old_store = object(&old, "store")?;
    if !old_store
        .iter()
        .all(|(key, value)| new_store.get(key) == Some(value))
    {
        return Ok(false);
    }
    if !counts(&new["a3_current"], &old["a3_current"]) {
        return Ok(false);
    }
    let new_pool = new["a3_pool"]
        .as_array_mut()
        .ok_or_else(|| err!(EACCES, "CHECKPOINT_RETIREMENT_SHAPE"))?;
    let old_pool = old["a3_pool"]
        .as_array_mut()
        .ok_or_else(|| err!(EACCES, "CHECKPOINT_RETIREMENT_SHAPE"))?;
    if new_pool.len() != old_pool.len() {
        return Ok(false);
    }
    for (new, old) in new_pool.iter_mut().zip(old_pool) {
        if !counts(&new["sealed_this_epoch"], &old["sealed_this_epoch"]) {
            return Ok(false);
        }
        new.as_object_mut()
            .ok_or_else(|| err!(EACCES, "CHECKPOINT_RETIREMENT_SHAPE"))?
            .remove("sealed_this_epoch");
        old.as_object_mut()
            .ok_or_else(|| err!(EACCES, "CHECKPOINT_RETIREMENT_SHAPE"))?
            .remove("sealed_this_epoch");
    }
    for key in ["sealed_a3", "sealed_a4"] {
        if !counts(&new["stats"][key], &old["stats"][key]) {
            return Ok(false);
        }
    }
    let new_erased = object(&new["stats"], "erased")?;
    let old_erased = object(&old["stats"], "erased")?;
    if !old_erased
        .iter()
        .all(|(key, value)| new_erased.get(key).is_some_and(|new| counts(new, value)))
    {
        return Ok(false);
    }
    for value in [&mut new, &mut old] {
        let stats = value["stats"]
            .as_object_mut()
            .ok_or_else(|| err!(EACCES, "CHECKPOINT_RETIREMENT_SHAPE"))?;
        for key in ["sealed_a3", "sealed_a4", "erased"] {
            stats.remove(key);
        }
        let fields = value
            .as_object_mut()
            .ok_or_else(|| err!(EACCES, "CHECKPOINT_RETIREMENT_SHAPE"))?;
        fields.remove("store");
        fields.remove("a3_current");
    }
    Ok(new == old)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::{CustodyVault, VaultEnvelopeCheckpoint};
    use enclave_crypto::hpke_envelope::{EnvelopePolicy, SignedEnvelopePolicy};
    use std::fs::OpenOptions;
    use std::os::unix::fs::{symlink, OpenOptionsExt, PermissionsExt};
    use std::sync::atomic::{AtomicBool, Ordering};

    struct Root(PathBuf);
    impl Root {
        fn new() -> Self {
            let path = std::env::temp_dir().canonicalize().unwrap().join(format!(
                "checkpoint-retirement-{}",
                enclave_core::rng::u64()
            ));
            std::fs::create_dir(&path).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
            Self(path)
        }
    }
    impl Drop for Root {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    fn credential(seed: u8) -> EnrolledCredential {
        EnrolledCredential {
            credential_id: vec![seed; 32],
            key: CredentialKey::Ed25519(SigningKey::from_bytes(&[seed; 32]).verifying_key()),
            aaguid: [8; 16],
            firmware_version: crate::ctap::mds::MIN_FW_ED25519,
        }
    }
    fn fixture() -> (CustodyVault, CompleteMembershipCheckpoint) {
        let issuer = SigningKey::from_bytes(&[39; 32]);
        let policy = EnvelopePolicy {
            version: 1,
            revision: 2,
            subject: "fixture-host".into(),
            namespace: "fixture-data".into(),
            issued_unix: 10,
            expires_unix: 100,
            review_unix: 90,
            owner: "fixture-inventory".into(),
            profiles: vec![Profile::L2],
            data_classes: vec!["C3".into(), "C4".into()],
            purpose: "retirement fixture".into(),
            migration: "none".into(),
            disclosure: None,
            classical_exception: false,
        };
        let signature = issuer
            .sign(&policy.signing_message().unwrap())
            .to_bytes()
            .to_vec();
        let context = SignedEnvelopePolicy { policy, signature }
            .verify(&issuer.verifying_key(), "fixture-host", "fixture-data", 20)
            .unwrap();
        let shares = |prf: &'static [u8; 32]| KekShares {
            sep_ecdh_share: &[11; 32],
            yubikey_prf: prf,
        };
        let vault = CustodyVault::enroll_authorized(
            Profile::L2,
            &shares(&[12; 32]),
            &shares(&[22; 32]),
            None,
            &context,
            SecretKey32::new([31; 32]),
            20,
        )
        .unwrap();
        let primary = vault.checkpoint().unwrap();
        let backup = crate::backup_envelope::StagedBackupEnvelopes::stage(
            &primary,
            &credential(41),
            &credential(42),
            &shares(&[12; 32]),
            &shares(&[22; 32]),
            &shares(&[13; 32]),
            &shares(&[23; 32]),
            &context,
            20,
        )
        .unwrap();
        (
            vault,
            CompleteMembershipCheckpoint {
                version: 3,
                membership_sha256: [9; 32],
                membership_generation: 3,
                sequence: 1,
                primary,
                backup,
            },
        )
    }
    fn checkpoint_dir(root: &Root, hash: &[u8; 32]) -> PathBuf {
        root.0
            .join("membership-checkpoints")
            .join(hex::encode(hash))
    }
    fn save(root: &Root, base: &CompleteMembershipCheckpoint, sequence: u64) -> [u8; 32] {
        let mut value = base.clone();
        value.sequence = sequence;
        save_complete(&root.0, &value).unwrap()
    }
    fn private_file(path: &Path, bytes: &[u8]) {
        use std::io::Write;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .unwrap();
        file.write_all(bytes).unwrap();
    }

    #[test]
    fn actual_encrypted_checkpoint_successor_retains_ciphertexts_and_every_count() {
        let (mut vault, base) = fixture();
        let empty = base.primary;
        vault
            .tokenize("first@example.invalid", None, false, None, 20)
            .unwrap();
        let first = vault.checkpoint().unwrap();
        vault
            .tokenize("second@example.invalid", None, true, None, 20)
            .unwrap();
        let second = vault.checkpoint().unwrap();
        assert!(preserves(&first, &empty).unwrap());
        assert!(preserves(&second, &first).unwrap());
        assert!(!preserves(&first, &second).unwrap());
        let old = serde_json::to_value(&first).unwrap();
        for change in ["ciphertext", "count", "stats", "session"] {
            let mut value = serde_json::to_value(&second).unwrap();
            match change {
                "ciphertext" => {
                    let token = old["store"].as_object().unwrap().keys().next().unwrap();
                    value["store"].as_object_mut().unwrap().remove(token);
                }
                "count" => value["a3_pool"][0]["sealed_this_epoch"] = serde_json::json!(0),
                "stats" => value["stats"]["sealed_a3"] = serde_json::json!(0),
                _ => {
                    value["session_id"][0] =
                        serde_json::json!(value["session_id"][0].as_u64().unwrap() ^ 1)
                }
            }
            let changed: VaultEnvelopeCheckpoint = serde_json::from_value(value).unwrap();
            assert!(!preserves(&changed, &first).unwrap(), "{change}");
        }
    }

    #[test]
    fn actual_retirement_keeps_current_predecessor_recovery_and_every_other_namespace() {
        let root = Root::new();
        let lease = PublicationLease::acquire(&root.0).unwrap();
        let (_, mut base) = fixture();
        base.sequence = 5;
        let old1 = save(&root, &base, 1);
        let recovery = save(&root, &base, 2);
        let old3 = save(&root, &base, 3);
        let previous = save(&root, &base, 4);
        let current = save(&root, &base, 5);
        let future = save(&root, &base, 9);
        let original = root.0.join("membership-cutover");
        std::fs::create_dir(&original).unwrap();
        private_file(
            &original.join("content.sealed"),
            b"retained original recovery content",
        );
        let protected = BTreeSet::from([current, previous, recovery]);
        let report = lease.retire(&base, &protected);
        assert_eq!(report.retired, 2);
        assert!(report.examined <= MAX_INSPECT);
        assert!(report.deferred, "future remains retained");
        assert!(!checkpoint_dir(&root, &old1).exists());
        assert!(!checkpoint_dir(&root, &old3).exists());
        for hash in [current, previous, recovery, future] {
            assert!(checkpoint_dir(&root, &hash)
                .join("checkpoint.sealed")
                .exists());
        }
        assert_eq!(
            std::fs::read(original.join("content.sealed")).unwrap(),
            b"retained original recovery content"
        );
    }

    #[test]
    fn hostile_symlink_hardlink_fifo_partial_and_unknown_children_never_recurse_or_delete() {
        let (_, mut base) = fixture();
        base.sequence = 9;
        for kind in [
            "directory-symlink",
            "file-symlink",
            "hardlink",
            "fifo",
            "partial",
            "unknown",
            "permissions",
        ] {
            let root = Root::new();
            let lease = PublicationLease::acquire(&root.0).unwrap();
            let hash = save(&root, &base, 1);
            let dir = checkpoint_dir(&root, &hash);
            let outside = root.0.join("outside");
            std::fs::create_dir(&outside).unwrap();
            private_file(&outside.join("keep"), b"outside untouched");
            match kind {
                "directory-symlink" => {
                    std::fs::rename(&dir, root.0.join("retained-directory")).unwrap();
                    symlink(&outside, &dir).unwrap();
                }
                "file-symlink" => {
                    std::fs::remove_file(dir.join("checkpoint.sealed")).unwrap();
                    symlink(outside.join("keep"), dir.join("checkpoint.sealed")).unwrap();
                }
                "hardlink" => {
                    std::fs::hard_link(dir.join("checkpoint.sealed"), outside.join("alias"))
                        .unwrap();
                }
                "fifo" => {
                    std::fs::remove_file(dir.join("checkpoint.gen")).unwrap();
                    let path =
                        CString::new(dir.join("checkpoint.gen").as_os_str().as_bytes()).unwrap();
                    assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
                }
                "partial" => {
                    std::fs::remove_file(dir.join("checkpoint.gen")).unwrap();
                }
                "unknown" => private_file(&dir.join("unknown-artifact"), b"preserved"),
                _ => {
                    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap()
                }
            }
            let report = lease.retire(&base, &BTreeSet::new());
            assert_eq!(report.retired, 0, "{kind}");
            assert!(report.deferred, "{kind}");
            assert!(std::fs::symlink_metadata(&dir).is_ok(), "{kind}");
            assert_eq!(
                std::fs::read(outside.join("keep")).unwrap(),
                b"outside untouched"
            );
            if kind != "directory-symlink" && kind != "file-symlink" {
                assert!(
                    dir.join("checkpoint.sealed").exists(),
                    "invalid child must be checked before any unlink"
                );
            }
        }
    }

    #[test]
    fn publication_save_uncertainty_or_readback_failure_performs_no_retirement_effect() {
        let root = Root::new();
        let _lease = PublicationLease::acquire(&root.0).unwrap();
        let (_, base) = fixture();
        let hash = save(&root, &base, 1);
        let workflow = root.0.join("workflow-fixture");
        let (mut store, _) =
            SealedStore::open_bounded_required(&workflow, "reference", 4096).unwrap();
        store.save_json(&1u64).unwrap();
        let checkpoint = std::fs::read(workflow.join("reference.gen")).unwrap();
        std::fs::remove_file(workflow.join("reference.gen")).unwrap();
        std::fs::create_dir(workflow.join("reference.gen")).unwrap();
        let entered = AtomicBool::new(false);
        assert!(durable_then(&mut store, &2u64, || {
            entered.store(true, Ordering::SeqCst);
            Ok(())
        })
        .is_err());
        assert!(!entered.load(Ordering::SeqCst));
        assert!(checkpoint_dir(&root, &hash)
            .join("checkpoint.sealed")
            .exists());
        std::fs::remove_dir(workflow.join("reference.gen")).unwrap();
        private_file(&workflow.join("reference.gen"), &checkpoint);
        drop(store);
        let (mut store, loaded) =
            SealedStore::open_bounded_required(&workflow, "reference", 4096).unwrap();
        let Loaded::State(bytes)=loaded else {panic!()};
        assert_eq!(enclave_core::sealed::decode::<u64>(&bytes).unwrap(), 2);
        // Real save succeeds, but post-save authenticated readback comparison
        // refuses. The production after closure checks equality BEFORE retire.
        assert!(durable_then(&mut store, &3u64, || -> EnclaveResult<()> {
            let (_, loaded) = SealedStore::open_bounded_required(&workflow, "reference", 4096)?;
            let Loaded::State(bytes)=loaded else {fail!(EIO,"FIXTURE_MISSING");};
            if enclave_core::sealed::decode::<u64>(&bytes)? != 4 {
                fail!(ESTALE, "CHECKPOINT_RETIREMENT_REFERENCE_CHANGED");
            }
            entered.store(true, Ordering::SeqCst);
            Ok(())
        })
        .unwrap_err()
        .is("CHECKPOINT_RETIREMENT_REFERENCE_CHANGED"));
        assert!(!entered.load(Ordering::SeqCst));
        assert!(checkpoint_dir(&root, &hash)
            .join("checkpoint.sealed")
            .exists());
    }

    #[test]
    fn lease_refuses_contention_symlink_ancestors_and_directory_replacement() {
        let root = Root::new();
        let lease = PublicationLease::acquire(&root.0).unwrap();
        assert!(PublicationLease::acquire(&root.0)
            .unwrap_err()
            .is("STATE_DIRECTORY_BUSY"));
        let (_, mut base) = fixture();
        base.sequence = 2;
        let hash = save(&root, &base, 1);
        let moved = root.0.join("held-checkpoints");
        std::fs::rename(root.0.join("membership-checkpoints"), &moved).unwrap();
        std::fs::create_dir(root.0.join("membership-checkpoints")).unwrap();
        std::fs::set_permissions(
            root.0.join("membership-checkpoints"),
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        assert!(lease
            .namespace_current()
            .unwrap_err()
            .is("CHECKPOINT_RETIREMENT_NAMESPACE_CHANGED"));
        assert_eq!(lease.retire(&base, &BTreeSet::new()).retired, 0);
        assert!(moved
            .join(hex::encode(hash))
            .join("checkpoint.sealed")
            .exists());
        let link = root.0.join("alias");
        symlink(&moved, &link).unwrap();
        assert!(PublicationLease::acquire(&link).is_err());
        assert!(PublicationLease::acquire(Path::new("relative")).is_err());
        assert!(hash_name(b"../outside").is_none());
        assert!(hash_name(&vec![b'A'; 64]).is_none());
    }

    #[test]
    fn malformed_authentication_and_nonpreserving_old_content_are_retained() {
        let root = Root::new();
        let lease = PublicationLease::acquire(&root.0).unwrap();
        let (mut vault, mut current) = fixture();
        current.sequence = 3;
        let malformed = save(&root, &current, 1);
        let path = checkpoint_dir(&root, &malformed).join("checkpoint.sealed");
        let mut bytes = std::fs::read(&path).unwrap();
        bytes[0] ^= 1;
        std::fs::write(&path, &bytes).unwrap();
        vault
            .tokenize("extra@example.invalid", None, false, None, 20)
            .unwrap();
        let mut old = current.clone();
        old.primary = vault.checkpoint().unwrap();
        old.sequence = 2;
        let nonpreserving = save_complete(&root.0, &old).unwrap();
        let report = lease.retire(&current, &BTreeSet::new());
        assert_eq!(report.retired, 0);
        assert!(report.deferred);
        assert_eq!(std::fs::read(path).unwrap(), bytes);
        assert!(checkpoint_dir(&root, &nonpreserving)
            .join("checkpoint.sealed")
            .exists());
    }

    #[test]
    fn scan_and_candidate_work_are_bounded_without_deleting_unknown_entries() {
        let root = Root::new();
        let lease = PublicationLease::acquire(&root.0).unwrap();
        let (_, base) = fixture();
        for index in 0u64..100 {
            let name = format!("{index:064x}");
            let path = root.0.join("membership-checkpoints").join(name);
            std::fs::create_dir(&path).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let (listed, limited) = names(&lease.parent, MAX_SCAN).unwrap();
        assert!(limited);
        assert!(listed.len() <= MAX_SCAN);
        let report = lease.retire(&base, &BTreeSet::new());
        assert!(report.deferred);
        assert!(report.examined <= MAX_INSPECT);
        assert_eq!(report.retired, 0);
        assert_eq!(
            std::fs::read_dir(root.0.join("membership-checkpoints"))
                .unwrap()
                .count(),
            100
        );
    }
}
