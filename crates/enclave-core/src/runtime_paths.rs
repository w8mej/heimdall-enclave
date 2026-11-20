//! Root-owned runtime directory recreation and per-console-user intent sockets.
use crate::{err, error::EnclaveResult};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

/// Actual console owner, with no guessed UID on missing/unsupported hosts.
pub fn console_uid() -> Option<u32> {
    #[cfg(target_os = "macos")]
    {
        std::fs::metadata("/dev/console")
            .ok()
            .map(|m| m.uid())
            .filter(|u| *u >= 500)
    }
    #[cfg(not(target_os = "macos"))]
    {
        None
    }
}

/// Path below the protected intent parent for an actual console session.
pub fn intent_socket(base: &Path, uid: u32) -> PathBuf {
    base.join("intent")
        .join(uid.to_string())
        .join("intent.sock")
}

fn directory(path: &Path, uid: u32, gid: u32, mode: u32) -> EnclaveResult<()> {
    match std::fs::create_dir(path) {
        Ok(()) => (),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => (),
        Err(e) => return Err(err!(EIO, "RUNTIME_MKDIR", "{}: {e}", path.display())),
    }
    // Work on the opened directory, refusing symlinks and non-directories.
    let f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY)
        .open(path)
        .map_err(|e| err!(EACCES, "RUNTIME_DIRECTORY", "{}: {e}", path.display()))?;
    use std::os::fd::AsRawFd;
    // SAFETY: fd is a live directory; numeric owner/mode values are fixed by caller.
    if unsafe { libc::fchown(f.as_raw_fd(), uid, gid) } != 0
        || unsafe { libc::fchmod(f.as_raw_fd(), mode as libc::mode_t) } != 0
    {
        return Err(err!(EACCES, "RUNTIME_PERMISSIONS", "{}", path.display()));
    }
    let applied = f.metadata().map_err(|e| err!(EIO, "RUNTIME_PERMISSIONS", "{e}"))?;
    if applied.uid() != uid || applied.gid() != gid || applied.mode() & 0o7777 != mode {
        return Err(err!(EACCES, "RUNTIME_PERMISSIONS", "{}", path.display()));
    }
    Ok(())
}

/// Recreate the runtime tree from the production peer identities, never staff write.
/// Caller must be root and `base` must be directly below a root-owned trusted parent.
pub fn prepare(base: &Path, console: Option<u32>, with_fido: bool) -> EnclaveResult<()> {
    if crate::ipc::geteuid() != 0 {
        return Err(err!(EPERM, "RUNTIME_ROOT_REQUIRED"));
    }
    let parent = base
        .parent()
        .ok_or_else(|| err!(EINVAL, "RUNTIME_PARENT"))?;
    let pm = std::fs::metadata(parent).map_err(|e| err!(EIO, "RUNTIME_PARENT", "{e}"))?;
    if pm.uid() != 0 || pm.mode() & 0o022 != 0 {
        return Err(err!(EACCES, "RUNTIME_PARENT_UNTRUSTED"));
    }
    directory(base, 0, 0, 0o755)?;
    for d in crate::daemon::DaemonId::ALL {
        directory(&base.join(d.dir_name()), d.uid(), d.client_gid(), 0o2750)?;
    }
    directory(
        &base.join("supervisor"),
        0,
        crate::supervisor::CLIENT_GID,
        0o2750,
    )?;
    directory(
        &base.join("browser"),
        crate::daemon::BROWSER_UID,
        crate::daemon::BROWSER_CLIENT_GID,
        0o2750,
    )?;
    directory(
        &base.join(crate::daemon::WITNESS_SOCKET_DIR),
        705,
        crate::daemon::WITNESS_CLIENT_GID,
        0o2750,
    )?;
    directory(
        &base.join("jobs"),
        702,
        crate::daemon::DaemonId::SwarmSync.gid(),
        0o700,
    )?;
    // Console clients may traverse/connect; the ingress authenticates UID+code
    // before frames, and only the dedicated service can replace its socket.
    directory(&base.join(crate::daemon::GATEWAY_SOCKET_DIR),
        crate::daemon::GATEWAY_UID, crate::daemon::GATEWAY_GID, 0o755)?;
    for helper in ["intent", "oidc"] {
        directory(&base.join(helper), 0, 0, 0o755)?;
        if let Some(uid) = console.filter(|u| *u >= 500 && *u != u32::MAX) {
            directory(
                &base.join(helper).join(uid.to_string()),
                uid,
                crate::daemon::DaemonId::CustodyVault.gid(),
                0o2710,
            )?;
        }
    }
    if with_fido {
        directory(&base.join("fido"), 706, 8717, 0o2750)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn console_paths_are_separate() {
        assert_eq!(
            intent_socket(Path::new("/var/run/enclave"), 501),
            Path::new("/var/run/enclave/intent/501/intent.sock")
        );
        assert_ne!(
            intent_socket(Path::new("/mesh"), 501),
            intent_socket(Path::new("/mesh"), 502)
        );
    }
    // Distinct-UID chown is not implemented by some Linux workspace mounts.
    // Native ownership acceptance must execute on Darwin, never become a
    // skipped Linux ownership claim. Portable nofollow/mode checks are below.
    #[cfg(target_os = "macos")]
    #[test]
    fn root_directory_modes_and_symlinks() {
        if crate::ipc::geteuid() != 0 {
            eprintln!("BLOCKED: directory ownership test requires root");
            return;
        }
        use std::os::unix::fs::{symlink, PermissionsExt};
        let parent = std::env::temp_dir().join(format!("mcpmac-f128-{}", crate::rng::u64()));
        std::fs::create_dir(&parent).unwrap();
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700)).unwrap();
        let base = parent.join("mesh");
        prepare(&base, Some(501), false).unwrap();
        for (suffix, uid, gid, mode) in [
            ("jobs", 702, 8702, 0o700),
            ("intent", 0, 0, 0o755),
            ("intent/501", 501, 8703, 0o2710),
            ("oidc", 0, 0, 0o755),
            ("oidc/501", 501, 8703, 0o2710),
        ] {
            let m = std::fs::metadata(base.join(suffix)).unwrap();
            assert_eq!((m.uid(), m.gid(), m.mode() & 0o7777), (uid, gid, mode));
        }
        std::fs::remove_dir(base.join("jobs")).unwrap();
        symlink(&parent, base.join("jobs")).unwrap();
        assert!(prepare(&base, Some(502), false).is_err());
        std::fs::remove_dir_all(parent).unwrap();
    }
    #[test]
    fn portable_directory_modes_and_nofollow() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let parent = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target")
            .join(format!("runtime-directory-{}", crate::rng::u64()));
        std::fs::create_dir(&parent).unwrap();
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700)).unwrap();
        let owner = std::fs::metadata(&parent).unwrap();
        let path = parent.join("oidc");
        directory(&path, owner.uid(), owner.gid(), 0o710).unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().mode() & 0o7777, 0o710);
        std::fs::remove_dir(&path).unwrap();
        symlink(&parent, &path).unwrap();
        assert!(directory(&path, owner.uid(), owner.gid(), 0o710).is_err());
        std::fs::remove_dir_all(parent).unwrap();
    }
}
