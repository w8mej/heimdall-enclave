//! Bounded model IPC: metadata stays in frames; verified bytes use chunks/FDs.
//! This authenticates the configured CAS daemon, not an independent publisher.
use std::fs::File;
use std::io::Read;
use std::os::fd::AsRawFd;
use enclave_core::{daemon::DaemonId, error::EnclaveResult, err, fail};
use enclave_swarm_syncd::service::{CasRequest, CasResponse};
use sha2::{Digest, Sha256};
use crate::ctl::Env;

/// Supported model bound; larger artifacts require a separately reviewed policy.
pub const MAX_MODEL_BYTES: u64 = 8 * 1024 * 1024 * 1024;
/// Maximum payload in one admission frame, below the existing IPC limit.
pub const MAX_CHUNK_BYTES: usize = 256 * 1024;
/// Metadata from the authenticated CAS and its read-only snapshot descriptor.
#[derive(Debug)]
pub struct VerifiedTarget {
    /// Signed byte length.
    pub length: u64,
    /// Signed BLAKE3 root.
    pub blake3: String,
    /// Signed SHA-256 digest.
    pub sha256: String,
    /// Read-only regular snapshot, positioned at its beginning.
    pub file: File,
}
fn hash_valid(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn check_metadata(length: u64, blake3: &str, sha256: &str) -> EnclaveResult<()> {
    if length > MAX_MODEL_BYTES || !hash_valid(blake3) || !hash_valid(sha256) {
        fail!(EACCES, "ARTIFACT_METADATA_INVALID");
    }
    Ok(())
}
/// Obtain a completely verified snapshot without transferring the model in CBOR.
pub fn fetch_verified_target(env: &Env, target: &str) -> EnclaveResult<VerifiedTarget> {
    let mut client = env.connect(DaemonId::SwarmSync)?;
    client.set_timeout(Some(std::time::Duration::from_secs(60)))?;
    let (length, blake3, sha256) = match client.call(&CasRequest::OpenTarget { target: target.into() })? {
        CasResponse::TargetFile { length, blake3, sha256, fds: 1 } => (length, blake3, sha256),
        _ => fail!(EACCES, "ARTIFACT_RESPONSE_INVALID"),
    };
    check_metadata(length, &blake3, &sha256)?;
    if length == 0 { fail!(EINVAL, "EMPTY_AUTHENTICATED_MODEL"); }
    // Receive the full protocol maximum so an unexpected second descriptor
    // is rejected instead of silently truncating its control message.
    let mut fds = client.recv_fds(16)?;
    if fds.len() != 1 { fail!(EACCES, "ARTIFACT_FD_COUNT"); }
    let file = File::from(fds.pop().unwrap());
    let meta = file.metadata().map_err(|e| err!(EIO, "ARTIFACT_STAT", "{e}"))?;
    // SAFETY: fcntl only inspects/sets flags on this owned live descriptor.
    let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
    if !meta.is_file() || meta.len() != length || flags < 0 || flags & libc::O_ACCMODE != libc::O_RDONLY {
        fail!(EACCES, "ARTIFACT_FD_INVALID");
    }
    let fd_flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFD) };
    if fd_flags < 0 || unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETFD, fd_flags | libc::FD_CLOEXEC) } < 0 {
        fail!(EIO, "ARTIFACT_CLOEXEC");
    }
    Ok(VerifiedTarget { length, blake3, sha256, file })
}
/// Floor for one admission commit (verify plus content-defined chunking).
const COMMIT_TIMEOUT_FLOOR_SECS: u64 = 600;
/// Slowest commit rate allowed for above the floor. UID 702 writes and syncs
/// one object per chunk: 5.5 GB (LLaDA-8B) took about 11 minutes on an M1 Pro.
const COMMIT_MIN_BYTES_PER_SEC: u64 = 2 * 1024 * 1024;

/// Bound on committing an artifact of `length` bytes: the floor plus the time
/// at the minimum rate, so a GB-sized model is not cut off mid-commit.
pub fn commit_timeout(length: u64) -> std::time::Duration {
    std::time::Duration::from_secs(COMMIT_TIMEOUT_FLOOR_SECS.saturating_add(length / COMMIT_MIN_BYTES_PER_SEC))
}

/// Upload a reader through authenticated, sequential, bounded admission frames.
/// Any incomplete transfer explicitly aborts; commit must confirm the pinned root.
pub fn admit_reader<R: Read>(env: &Env, target: &str, input: &mut R) -> EnclaveResult<String> {
    let mut client = env.connect(DaemonId::SwarmSync)?;
    client.set_timeout(Some(std::time::Duration::from_secs(60)))?;
    let (session, length, b3, sha, chunk) = match client.call(&CasRequest::AdmitBegin { target: target.into() })? {
        CasResponse::Admission { session, length, blake3, sha256, max_chunk_bytes } => (session, length, blake3, sha256, max_chunk_bytes),
        _ => fail!(EIO, "ADMISSION_RESPONSE_INVALID"),
    };
    let outcome = (|| {
        check_metadata(length, &b3, &sha)?;
        if session.len() != 64 || !hash_valid(&session) || chunk == 0 || chunk > MAX_CHUNK_BYTES {
            fail!(EACCES, "ADMISSION_LIMIT_INVALID");
        }
        let mut buffer = vec![0u8; chunk];
        let mut offset = 0u64; let mut bh = blake3::Hasher::new(); let mut sh = Sha256::new();
        loop {
            let n = input.read(&mut buffer).map_err(|e| err!(EIO, "ADMISSION_READ", "{e}"))?;
            if n == 0 { break; }
            let next = offset.checked_add(n as u64).ok_or_else(|| err!(E2BIG, "ADMISSION_LENGTH"))?;
            if next > length { fail!(EACCES, "ADMISSION_LENGTH"); }
            bh.update(&buffer[..n]); sh.update(&buffer[..n]);
            match client.call(&CasRequest::AdmitChunk { session: session.clone(), offset, bytes: buffer[..n].to_vec().into() })? {
                CasResponse::AdmissionProgress { received } if received == next => (),
                _ => fail!(EACCES, "ADMISSION_OFFSET_INVALID"),
            }
            offset = next;
        }
        if offset != length || blake3::Hasher::finalize(&bh).to_hex().as_str() != b3 || hex::encode(sh.finalize()) != sha {
            fail!(EACCES, "ADMISSION_CONTENT_MISMATCH");
        }
        // Commit re-verifies and chunks the whole staged artifact in UID 702;
        // a GB-sized model takes minutes, not the per-chunk minute.
        client.set_timeout(Some(commit_timeout(length)))?;
        match client.call(&CasRequest::AdmitCommit { session: session.clone() })? {
            CasResponse::Admitted { root } if root == b3 => Ok(root),
            _ => fail!(EACCES, "ADMISSION_ROOT_INVALID"),
        }
    })();
    if outcome.is_err() {
        let _: EnclaveResult<CasResponse> = client.call(&CasRequest::AdmitAbort { session });
    }
    outcome
}

#[cfg(test)]
mod commit_timeout_tests {
    use super::*;

    #[test]
    fn commit_timeout_grows_with_the_artifact() {
        assert_eq!(commit_timeout(0).as_secs(), 600);
        assert_eq!(commit_timeout(300 * 1024 * 1024).as_secs(), 750);
        // LLaDA-8B (5.52 GB): well past the 11 minutes it took.
        assert!(commit_timeout(5_519_716_336).as_secs() >= 3000);
        assert_eq!(commit_timeout(u64::MAX).as_secs(), 600 + u64::MAX / (2 * 1024 * 1024));
    }
}
