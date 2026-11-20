//! Small filesystem helpers for daemon state (`0700` directories, `0600`
//! key files written atomically).

use std::path::Path;

use crate::err;
use crate::error::EnclaveResult;

/// Create `dir` (and parents) if missing; the leaf is `0700`.
pub fn private_dir(dir: &Path) -> EnclaveResult<()> {
    use std::os::unix::fs::DirBuilderExt;
    if !dir.exists() {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
            .map_err(|e| err!(EIO, "STATE_MKDIR", "{}: {e}", dir.display()))?;
    }
    Ok(())
}

/// Write `bytes` to `path` atomically (`tmp` + `fsync` + `rename`), mode `0600`.
pub fn write_private(path: &Path, bytes: &[u8]) -> EnclaveResult<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    if let Some(d) = path.parent() {
        private_dir(d)?;
    }
    let tmp = path.with_extension(format!("{}.tmp", hex::encode(crate::rng::bytes32())));
    let mut f = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&tmp)
        .map_err(|e| err!(EIO, "STATE_WRITE", "{e}"))?;
    f.write_all(bytes)
        .map_err(|e| err!(EIO, "STATE_WRITE", "{e}"))?;
    full_fsync(&f)?;
    std::fs::rename(&tmp, path).map_err(|e| err!(EIO, "STATE_RENAME", "{e}"))
}

/// Flush file buffers through physical drive cache to non-volatile media.
/// On Darwin / macOS, this executes `fcntl(fd, F_FULLFSYNC)` to guarantee
/// APFS physical barrier persistence to Apple Silicon NAND storage (GAP-64).
/// On other platforms, it executes `sync_all()`.
pub fn full_fsync(f: &std::fs::File) -> EnclaveResult<()> {
    #[cfg(target_os = "macos")]
    {
        use std::os::unix::io::AsRawFd;
        let fd = f.as_raw_fd();
        let ret = unsafe { libc::fcntl(fd, libc::F_FULLFSYNC) };
        if ret == -1 {
            f.sync_all().map_err(|e| err!(EIO, "STATE_FSYNC", "{e}"))?;
        }
        Ok(())
    }
    #[cfg(not(target_os = "macos"))]
    {
        f.sync_all().map_err(|e| err!(EIO, "STATE_FSYNC", "{e}"))
    }
}

/// Load a 32-byte secret from `path`, creating it with fresh randomness the
/// first time. On hardware the file holds a SEP-wrapped blob (Phase 2); in
/// this build it is the raw seed, readable only by the daemon account.
pub fn load_or_create_seed(path: &Path) -> EnclaveResult<[u8; 32]> {
    match std::fs::read(path) {
        Ok(b) => <[u8; 32]>::try_from(b.as_slice())
            .map_err(|_| err!(EINVAL, "STATE_KEY_FILE", "{}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let k = crate::rng::bytes32();
            write_private(path, &k)?;
            Ok(k)
        }
        Err(e) => Err(err!(EIO, "STATE_KEY_FILE", "{e}")),
    }
}

/// The UID owning `/dev/console` (the Aqua GUI session user), or 501 fallback.
pub fn console_uid() -> u32 {
    #[cfg(target_os = "macos")]
    {
        use std::os::unix::fs::MetadataExt;
        std::fs::metadata("/dev/console")
            .map(|m| m.uid())
            .unwrap_or(501)
    }
    #[cfg(not(target_os = "macos"))]
    {
        501
    }
}
