//! Signed host configuration resolution and admission (GAP-20, ADR-007 §3).

use std::path::Path;

use enclave_core::error::EnclaveResult;
use enclave_core::host_config::{EnclaveHostConfig, HOST_CONFIG_TARGET};
use enclave_core::{err, fail};
use enclave_crypto::tuf::TufClient;

/// Retrieve and verify any target payload against TUF targets.
pub fn get_target_bytes(
    store_dir: &Path,
    tuf: &TufClient,
    target_name: &str,
    now: i64,
) -> EnclaveResult<Vec<u8>> {
    get_target_bytes_with_limit(store_dir, tuf, target_name, now, 64 * 1024 * 1024)
}

pub(crate) fn get_target_bytes_with_limit(store_dir: &Path, tuf: &TufClient, target_name: &str,
    now: i64, maximum: u64) -> EnclaveResult<Vec<u8>> {
    // Signed metadata is authority for bytes, never authority to traverse the
    // host filesystem. Validate names even when a publisher signed them.
    if target_name.is_empty() || target_name.len() > 1024
        || target_name.split('/').any(|part| part.is_empty() || part == "." || part == ".."
            || part.bytes().any(|b| b == 0 || b.is_ascii_control() || b == b'\\'))
    { fail!(EINVAL, "TARGET_PATH"); }
    let tf = tuf.target(target_name, now)?;
    if tf.length > maximum {
        fail!(
            E2BIG,
            "TARGET_TOO_LARGE",
            "target {target_name} length {} exceeds {maximum} byte limit",
            tf.length
        );
    }

    if tf.custom.as_ref().and_then(|c| c.get("revoked")).and_then(serde_json::Value::as_bool) == Some(true) {
        fail!(EACCES, "TARGET_REVOKED");
    }
    // Prefer the admitted canonical object so a stale provisioned loose payload
    // cannot shadow a rotated policy or verification-key manifest.
    let directory = std::fs::symlink_metadata(store_dir).map_err(|e| err!(EIO, "TARGET_DIRECTORY", "{e}"))?;
    if !directory.is_dir() || directory.file_type().is_symlink() { fail!(EACCES, "TARGET_DIRECTORY"); }
    // The configured store and its parent hierarchy are provisioned/owned by
    // the daemon; mutable target descendants still receive descriptor checks.
    let store = crate::cas::ContentStore::open(store_dir)?;
    let bytes = if let Some(root) = tf.hashes.get("blake3").filter(|root| store.contains(root)) {
        if store.manifest(root)?.len != tf.length { fail!(EACCES, "TUF_TARGET_LENGTH"); }
        let mut sink = BoundedTarget { bytes: Vec::new(), expected: tf.length };
        let manifest = store.copy_verified(root, &mut sink)?;
        if manifest.len != tf.length || sink.bytes.len() as u64 != tf.length { fail!(EACCES, "TUF_TARGET_LENGTH"); }
        sink.bytes
    } else {
        match read_relative_target(store_dir, target_name, tf.length) {
            Ok(bytes) => bytes,
            Err(error) if error.is("TARGET_NOT_FOUND") => {
                let root = tf.hashes.get("blake3").ok_or_else(|| err!(EACCES, "TARGET_NOT_FOUND"))?;
                if root.len() != 64 || !root.bytes().all(|b| b.is_ascii_hexdigit()) {
                    fail!(EINVAL, "TARGET_HASH");
                }
                read_relative_target(store_dir, &format!("chunks/{}/{}", &root[..2], root), tf.length)?
            }
            Err(error) => return Err(error),
        }
    };

    // 3. Verify length and dual-hash against TUF metadata
    let _ = tuf.verify_target(target_name, &bytes, now)?;

    Ok(bytes)
}

struct BoundedTarget { bytes: Vec<u8>, expected: u64 }
impl std::io::Write for BoundedTarget {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() as u64 > self.expected.saturating_sub(self.bytes.len() as u64) {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "signed target length exceeded"));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> { Ok(()) }
}

/// Open every path component relative to an owned directory descriptor. Reject
/// links, special files, short/long payloads and concurrent file growth without
/// blocking on a FIFO or allocating the untrusted filesystem length.
fn read_relative_target(base: &Path, name: &str, expected: u64) -> EnclaveResult<Vec<u8>> {
    use std::io::Read;
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::fs::OpenOptionsExt;
    let mut directory = std::fs::OpenOptions::new().read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY | libc::O_CLOEXEC)
        .open(base).map_err(|e| err!(EIO, "TARGET_DIRECTORY", "{e}"))?;
    let parts: Vec<_> = name.split('/').collect();
    for (index, part) in parts.iter().enumerate() {
        let component = std::ffi::CString::new(*part).map_err(|_| err!(EINVAL, "TARGET_PATH"))?;
        let last = index + 1 == parts.len();
        let flags = libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC
            | if last { libc::O_NONBLOCK } else { libc::O_DIRECTORY };
        // SAFETY: directory and component are live; a successful descriptor is
        // immediately owned by File and closed on every return path.
        let fd = unsafe { libc::openat(directory.as_raw_fd(), component.as_ptr(), flags) };
        if fd < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::NotFound { fail!(EACCES, "TARGET_NOT_FOUND"); }
            return Err(err!(EACCES, "TARGET_READ", "{error}"));
        }
        let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
        if !last { directory = file; continue; }
        let meta = file.metadata().map_err(|e| err!(EIO, "TARGET_READ", "{e}"))?;
        if !meta.is_file() || meta.len() != expected { fail!(EACCES, "TUF_TARGET_LENGTH"); }
        let mut bytes = Vec::new();
        (&mut file).take(expected + 1).read_to_end(&mut bytes)
            .map_err(|e| err!(EIO, "TARGET_READ", "{e}"))?;
        if bytes.len() as u64 != expected { fail!(EACCES, "TUF_TARGET_LENGTH"); }
        return Ok(bytes);
    }
    fail!(EINVAL, "TARGET_PATH");
}

/// Retrieve and verify the host configuration against TUF targets.
pub fn get_host_config(store_dir: &Path, tuf: &TufClient, now: i64) -> EnclaveResult<Vec<u8>> {
    // Keep the public host-config diagnostics used by admission/recovery callers.
    let metadata = tuf.target(HOST_CONFIG_TARGET, now)?;
    if metadata.length > enclave_core::host_config::MAX_HOST_CONFIG_BYTES as u64 {
        fail!(E2BIG, "HOST_CONFIG_TOO_LARGE");
    }
    if metadata.custom.as_ref().and_then(|c| c.get("revoked")).and_then(serde_json::Value::as_bool) == Some(true) {
        fail!(EACCES, "HOST_CONFIG_REVOKED");
    }
    let bytes = get_target_bytes_with_limit(store_dir, tuf, HOST_CONFIG_TARGET, now,
        enclave_core::host_config::MAX_HOST_CONFIG_BYTES as u64)?;
    EnclaveHostConfig::from_json_bytes(&bytes)?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn provisioning_canonical_sink_refuses_growth_before_allocation() {
        let mut sink = BoundedTarget { bytes: Vec::new(), expected: 3 };
        sink.write_all(b"ok").unwrap();
        assert!(sink.write_all(b"bad").is_err());
        assert_eq!(sink.bytes, b"ok");
        sink.write_all(b"!").unwrap();
        assert!(sink.write_all(b"x").is_err());
        assert_eq!(sink.bytes, b"ok!");
    }
}
