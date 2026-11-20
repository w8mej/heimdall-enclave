//! APFS snapshot and zero-copy clonefile abstractions (FS-702 §4.3, §5.3; GAP-19 L1).
//!
//! Provides:
//! - `clonefile(src, dst)`: zero-copy Copy-on-Write APFS file materialisation (no entitlement required).
//! - `probe_fs_snapshot_capability(dir)`: capability probe for `fs_snapshot_create(2)`.
//!   Requires restricted Apple Developer Team ID entitlement `com.apple.developer.vfs.snapshot`.
//!   In unentitled builds, fails closed with `ENTITLEMENT_REQUIRED` (D-19f).
//! - `create_sealed_snapshot(dir, name)`: snapshot creation gated behind capability probe.

use enclave_core::{err, fail, EnclaveResult};
use std::path::Path;

/// APFS zero-copy file cloning via `libc::clonefile(2)` (macOS).
///
/// Materialises a verified CAS artifact or model chunk into the target path
/// using copy-on-write without allocating duplicate physical SSD extents.
///
/// On non-macOS platforms, falls back to standard file copy.
pub fn clonefile(src: &Path, dst: &Path) -> EnclaveResult<()> {
    #[cfg(target_os = "macos")]
    {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;

        let src_c = CString::new(src.as_os_str().as_bytes())
            .map_err(|e| err!(EINVAL, "CLONEFILE_PATH_INVALID", "{e}"))?;
        let dst_c = CString::new(dst.as_os_str().as_bytes())
            .map_err(|e| err!(EINVAL, "CLONEFILE_PATH_INVALID", "{e}"))?;

        let rc = unsafe { libc::clonefile(src_c.as_ptr(), dst_c.as_ptr(), 0) };
        if rc != 0 {
            let errno = std::io::Error::last_os_error();
            fail!(
                EIO,
                "CLONEFILE_FAILED",
                "clonefile failed for {src:?} -> {dst:?}: {errno}"
            );
        }
        Ok(())
    }

    #[cfg(not(target_os = "macos"))]
    {
        std::fs::copy(src, dst).map_err(|e| err!(EIO, "CLONEFILE_FAILED", "{e}"))?;
        Ok(())
    }
}

/// Probes whether the current process holds the restricted
/// `com.apple.developer.vfs.snapshot` entitlement required for `fs_snapshot_create(2)`.
///
/// Per D-19f, calling `fs_snapshot_create` on macOS without an Apple Developer Team ID
/// and the Apple-granted entitlement returns `errno == EPERM` (1). This probe
/// fails closed with `ENTITLEMENT_REQUIRED` rather than falling back to unsealed storage.
pub fn probe_fs_snapshot_capability(dir: &Path) -> EnclaveResult<()> {
    #[cfg(target_os = "macos")]
    {
        use std::ffi::CString;
        use std::fs::File;
        use std::os::unix::io::AsRawFd;

        extern "C" {
            fn fs_snapshot_create(
                dirfd: libc::c_int,
                name: *const libc::c_char,
                flags: u32,
            ) -> libc::c_int;
            fn fs_snapshot_delete(
                dirfd: libc::c_int,
                name: *const libc::c_char,
                flags: u32,
            ) -> libc::c_int;
        }

        static PROBED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
        if PROBED.load(std::sync::atomic::Ordering::Relaxed) {
            return Ok(());
        }

        let f = File::open(dir).map_err(|e| err!(EIO, "SNAPSHOT_PROBE_OPEN", "{e}"))?;
        let snap_id = enclave_core::rng::u64();
        let probe_name_str = format!("com_enterprise_enclave_snap_probe_{snap_id}");
        let probe_name = CString::new(probe_name_str)
            .map_err(|e| err!(EINVAL, "SNAPSHOT_PROBE_NAME", "{e}"))?;

        let rc = unsafe { fs_snapshot_create(f.as_raw_fd(), probe_name.as_ptr(), 0) };
        if rc != 0 {
            let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            if errno == libc::EPERM {
                fail!(
                    EPERM,
                    "ENTITLEMENT_REQUIRED",
                    "com.apple.developer.vfs.snapshot required for fs_snapshot_create (blocked on Apple Developer Team ID)"
                );
            }
            fail!(
                EIO,
                "SNAPSHOT_PROBE_FAILED",
                "fs_snapshot_create probe failed with unexpected errno {errno}"
            );
        }

        // Clean up test snapshot if created (e.g. running under entitled developer cert)
        let del_rc = unsafe { fs_snapshot_delete(f.as_raw_fd(), probe_name.as_ptr(), 0) };
        if del_rc != 0 {
            let errno = std::io::Error::last_os_error();
            fail!(
                EIO,
                "SNAPSHOT_DELETE_FAILED",
                "failed to delete probe snapshot: {errno}"
            );
        }
        PROBED.store(true, std::sync::atomic::Ordering::Relaxed);
        Ok(())
    }

    #[cfg(not(target_os = "macos"))]
    {
        let _ = dir;
        fail!(
            EPERM,
            "NOT_SUPPORTED",
            "APFS snapshots are supported only on macOS"
        );
    }
}

/// Creates a sealed APFS read-only snapshot over `dir` with the given snapshot `name`.
///
/// Fails closed if the `com.apple.developer.vfs.snapshot` entitlement is missing.
pub fn create_sealed_snapshot(dir: &Path, name: &str) -> EnclaveResult<()> {
    probe_fs_snapshot_capability(dir)?;

    #[cfg(target_os = "macos")]
    {
        use std::ffi::CString;
        use std::fs::File;
        use std::os::unix::io::AsRawFd;

        extern "C" {
            fn fs_snapshot_create(
                dirfd: libc::c_int,
                name: *const libc::c_char,
                flags: u32,
            ) -> libc::c_int;
        }

        let f = File::open(dir).map_err(|e| err!(EIO, "SNAPSHOT_OPEN", "{e}"))?;
        let snap_name = CString::new(name).map_err(|e| err!(EINVAL, "SNAPSHOT_NAME", "{e}"))?;
        let rc = unsafe { fs_snapshot_create(f.as_raw_fd(), snap_name.as_ptr(), 0) };
        if rc != 0 {
            let errno = std::io::Error::last_os_error();
            fail!(
                EIO,
                "SNAPSHOT_CREATE_FAILED",
                "fs_snapshot_create failed: {errno}"
            );
        }
        Ok(())
    }

    #[cfg(not(target_os = "macos"))]
    {
        let _ = name;
        let _ = dir;
        fail!(
            EPERM,
            "NOT_SUPPORTED",
            "APFS snapshots are supported only on macOS"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn temp_test_dir() -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("depot-snap-test-{}", enclave_core::rng::u64()));
        fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn test_clonefile_apfs() {
        let tmp = temp_test_dir();
        let src = tmp.join("source.dat");
        let dst = tmp.join("clone.dat");

        let original_data = b"depot zero-copy APFS clonefile test vector 2026";
        fs::write(&src, original_data).unwrap();

        clonefile(&src, &dst).expect("clonefile must succeed on APFS");
        assert_eq!(fs::read(&dst).unwrap(), original_data);

        // Mutating dst must not modify src (CoW isolation)
        fs::write(&dst, b"Mutated clone content").unwrap();
        assert_eq!(fs::read(&src).unwrap(), original_data);

        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_fs_snapshot_create_probe_entitlement_required() {
        let tmp = temp_test_dir();
        let res = probe_fs_snapshot_capability(&tmp);

        #[cfg(target_os = "macos")]
        {
            let err = res.expect_err("fs_snapshot_create must fail without Team ID entitlement");
            assert!(
                err.is("ENTITLEMENT_REQUIRED"),
                "Expected ENTITLEMENT_REQUIRED, got: {err:?}"
            );
        }

        #[cfg(not(target_os = "macos"))]
        {
            let err = res.expect_err("snapshots not supported on non-macos");
            assert!(err.is("NOT_SUPPORTED"));
        }

        let _ = fs::remove_dir_all(&tmp);
    }
}
