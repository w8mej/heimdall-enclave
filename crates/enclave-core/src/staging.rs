//! Payload preallocation before accepting unverified bytes. Allocation failure
//! never falls back to a sparse file or a free-space-only check.
use std::{fs::File, os::fd::AsRawFd};
use crate::{err, fail, error::EnclaveResult};

/// Reserve physical storage for exactly `bytes` payload bytes on a new private
/// file. Filesystem block rounding and metadata use the separate global reserve.
/// A caller must hold its logical staging reservation until deletion/promotion.
pub fn preallocate(file: &File, bytes: u64) -> EnclaveResult<()> {
    let length = i64::try_from(bytes).map_err(|_| err!(EDQUOT, "STAGING_DISK_QUOTA_EXCEEDED"))?;
    if bytes == 0 { return Ok(()); }
    #[cfg(target_os = "linux")]
    {
        // posix_fallocate returns an errno directly; it is not fallocate's -1.
        let code = unsafe { libc::posix_fallocate(file.as_raw_fd(), 0, length) };
        if code != 0 { fail!(EDQUOT, "STAGING_DISK_QUOTA_EXCEEDED", "preallocation errno={code}"); }
    }
    #[cfg(target_os = "macos")]
    {
        let mut store = libc::fstore_t { fst_flags: libc::F_ALLOCATEALL,
            fst_posmode: libc::F_PEOFPOSMODE, fst_offset: 0, fst_length: length,
            fst_bytesalloc: 0 };
        if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_PREALLOCATE, &mut store) } != 0
            || store.fst_bytesalloc < length {
            fail!(EDQUOT, "STAGING_DISK_QUOTA_EXCEEDED", "physical preallocation unavailable");
        }
        file.set_len(bytes).map_err(|e| err!(EDQUOT,"STAGING_DISK_QUOTA_EXCEEDED","{e}"))?;
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    { let _ = (file, length); fail!(EDQUOT,"STAGING_DISK_QUOTA_EXCEEDED","unsupported allocator"); }
    Ok(())
}
