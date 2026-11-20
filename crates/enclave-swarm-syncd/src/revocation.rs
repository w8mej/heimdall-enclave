//! FS-702 §7.2 revocation (GAP-21).
//!
//! Revocation is driven only by signed TUF metadata: a target whose signed
//! policy carries `"revoked": true` is revoked on the refresh that adopts it
//! (and again at start, if the artifact is still present). There is no peer
//! `Revoke` RPC. UID 702 then
//!
//! 1. records the object's inode, shreds it (zero, `ftruncate(0)` — residual
//!    mappings fault with `SIGBUS`, reads return EOF — `fsync`, unlink) and
//!    garbage-collects its unshared chunks;
//! 2. asks the enforcer to terminate the inode's holders: the root
//!    supervisor in production (`enclave_core::supervisor`), which finds the
//!    holders itself and `SIGKILL`s any that still hold it after 500 ms.
//!
//! A target that is merely dropped from `targets.json` (an ordinary upgrade
//! or rollback) stops resolving but is not shredded, so running consumers of
//! the previous version are not killed.

use std::path::PathBuf;

use enclave_core::error::EnclaveResult;
use enclave_core::supervisor::{enforce_revocation, RevocationReport, RELEASE_GRACE};

/// Who terminates holders of a revoked inode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Enforcement {
    /// The root supervisor at this socket (production). `dev` expects the
    /// supervisor to run under the current UID instead of root.
    Supervisor {
        /// Socket path.
        socket: PathBuf,
        /// Development mesh.
        dev: bool,
    },
    /// This process signals holders of its own UID (development: every
    /// daemon shares one UID; tests).
    InProcess,
    /// No enforcer: the artifact is still shredded and truncated, but holders
    /// are not terminated (`REVOCATION_UNENFORCED` is journaled).
    Unavailable,
}

impl Enforcement {
    /// Short name for `Status`.
    pub fn name(&self) -> &'static str {
        match self {
            Enforcement::Supervisor { .. } => "supervisor",
            Enforcement::InProcess => "in-process",
            Enforcement::Unavailable => "unavailable",
        }
    }

    /// Enforce the kernel identity of a held canonical object. The caller keeps
    /// its durable name and manifest until a complete result is confirmed.
    pub fn enforce_file(&self,file:&std::fs::File,root:&str)->EnclaveResult<Option<RevocationReport>> {
        use std::os::unix::fs::MetadataExt;
        match self {
            Self::Supervisor{socket,dev}=>enclave_core::supervisor::request_held_enforcement(socket,*dev,file,root,enclave_core::supervisor::HeldObjectKind::Canonical).map(Some),
            Self::InProcess=>{let m=file.metadata().map_err(|_|enclave_core::err!(EIO,"REVOCATION_OBJECT"))?;self.enforce(m.dev(),m.ino())},
            Self::Unavailable=>Ok(None),
        }
    }
    /// Terminate the holders of `(dev, ino)`. `Ok(None)` when no enforcer is
    /// configured.
    pub fn enforce(&self, dev: u64, ino: u64) -> EnclaveResult<Option<RevocationReport>> {
        match self {
            Enforcement::Supervisor { socket, dev: d } => {
                enclave_core::supervisor::request_enforcement(socket, *d, dev, ino).map(Some)
            }
            Enforcement::InProcess => {
                let me = enclave_core::ipc::geteuid();
                Ok(Some(enforce_revocation(dev, ino, RELEASE_GRACE, |h| {
                    h.pid > 1 && h.uid == me
                })))
            }
            Enforcement::Unavailable => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unavailable_enforcer_reports_nothing() {
        assert_eq!(Enforcement::Unavailable.enforce(1, 1).unwrap(), None);
        assert_eq!(Enforcement::InProcess.name(), "in-process");
    }
}
