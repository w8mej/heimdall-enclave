//! Conservative liveness of a previously kernel-attested local incarnation.
//! This is a cleanup predicate, never a replacement for IPC authentication.
use crate::ipc::PeerCredentials;

/// What the kernel establishes about the saved process incarnation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessLiveness {
    /// The saved PID version is still current.
    Alive,
    /// A positive observation establishes that the saved incarnation ended.
    Dead,
    /// Missing attestation, denied query, unsupported host or unexpected result.
    Unknown,
}

/// Check consistency of a saved Darwin local IPC identity. This does not attest
/// caller-supplied credentials; only the trusted socket boundary may supply them.
pub fn has_local_process_identity(peer: &PeerCredentials) -> bool {
    let (Some(pid), Some(token)) = (peer.pid, peer.audit_token) else { return false; };
    pid > 0 && peer.tls_channel_binding.is_none() && token[5] == pid as u32
        && token[1] == peer.uid && token[2] == peer.gid
}

/// Query only process identity, without reading executable paths. Permission
/// failures never count as death. Linux development has no Darwin attestation
/// and conservatively preserves turns rather than guessing from a PID.
pub fn process_liveness(peer: &PeerCredentials) -> ProcessLiveness {
    #[cfg(target_os = "macos")]
    {
        if !has_local_process_identity(peer) { return ProcessLiveness::Unknown; }
        // Official XNU bsd/sys/proc_info_private.h defines flavor 17 and marks
        // this 56-byte structure "This structure is API". It is not in the
        // public SDK header. See the pinned ABI/source evidence in the F71 note.
        #[repr(C)]
        struct UniqueIdentifierInfo {
            uuid: [u8; 16], unique_id: u64, parent_unique_id: u64,
            idversion: i32, original_parent_idversion: i32,
            reserved2: u64, reserved3: u64,
        }
        const _: [(); 56] = [(); std::mem::size_of::<UniqueIdentifierInfo>()];
        let mut value = UniqueIdentifierInfo {uuid:[0;16],unique_id:0,parent_unique_id:0,
            idversion:0,original_parent_idversion:0,reserved2:0,reserved3:0};
        // SAFETY: fixed ABI-sized writable buffer; no pointer escapes the call.
        let n = unsafe { libc::proc_pidinfo(peer.pid.unwrap(), 17, 0,
            (&mut value as *mut UniqueIdentifierInfo).cast(), 56) };
        if n == 56 {
            return if value.idversion as u32 == peer.audit_token.unwrap()[7] {
                ProcessLiveness::Alive
            } else { ProcessLiveness::Dead };
        }
        // Even ESRCH may be a MAC visibility denial for a live process. No
        // negative lookup result is evidence of death.
    }
    let _ = peer;
    ProcessLiveness::Unknown
}

/// A kernel exit/exec observation registered while the exact incarnation was
/// positively confirmed on both sides of registration. Share at most one per
/// exact owner; dropping it releases the kernel knote and file descriptor.
#[derive(Debug)]
pub struct ProcessWatch {
    peer: PeerCredentials,
    #[cfg(target_os = "macos")]
    queue: std::os::fd::OwnedFd,
    ended: std::sync::atomic::AtomicBool,
}

impl ProcessWatch {
    /// Arm before allocating a recoverable turn. Ambiguous registration or
    /// post-registration identity never supplies a cleanup authority.
    pub fn capture(peer: &PeerCredentials) -> crate::EnclaveResult<Self> {
        #[cfg(target_os = "macos")]
        {
            use std::os::fd::{AsRawFd, FromRawFd};
            if process_liveness(peer) != ProcessLiveness::Alive {
                crate::fail!(EPERM,"PROCESS_WATCH_UNCONFIRMED");
            }
            // SAFETY: no pointers are passed; ownership is taken exactly once.
            let fd=unsafe {libc::kqueue()};
            if fd<0 {crate::fail!(EIO,"PROCESS_WATCH_CREATE");}
            let queue=unsafe {std::os::fd::OwnedFd::from_raw_fd(fd)};
            if unsafe {libc::fcntl(fd,libc::F_SETFD,libc::FD_CLOEXEC)}<0 {
                crate::fail!(EIO,"PROCESS_WATCH_CREATE");
            }
            let change=libc::kevent {ident:peer.pid.unwrap() as usize,filter:libc::EVFILT_PROC,
                flags:libc::EV_ADD|libc::EV_ENABLE|libc::EV_CLEAR|libc::EV_RECEIPT,
                fflags:libc::NOTE_EXIT|libc::NOTE_EXEC,data:0,udata:std::ptr::null_mut()};
            let mut receipt=change;
            let timeout=libc::timespec {tv_sec:0,tv_nsec:0};
            // NOTE_EXITSTATUS is deliberately absent: plain exit observation
            // does not require authority to signal the cross-UID process.
            let n=unsafe {libc::kevent(queue.as_raw_fd(),&change,1,&mut receipt,1,&timeout)};
            if n!=1 || receipt.flags&libc::EV_ERROR==0 || receipt.data!=0
                || process_liveness(peer)!=ProcessLiveness::Alive {
                crate::fail!(EPERM,"PROCESS_WATCH_UNCONFIRMED");
            }
            return Ok(Self {peer:peer.clone(),queue,
                ended:std::sync::atomic::AtomicBool::new(false)});
        }
        #[cfg(not(target_os = "macos"))]
        {let _=peer;crate::fail!(EPERM,"PROCESS_WATCH_UNSUPPORTED");}
    }

    /// Poll without waiting. A recorded exit/exec is sticky; failed queries,
    /// receipt errors and unsupported platforms preserve the old incarnation.
    pub fn liveness(&self) -> ProcessLiveness {
        use std::sync::atomic::Ordering;
        if self.ended.load(Ordering::SeqCst) {return ProcessLiveness::Dead;}
        #[cfg(target_os = "macos")]
        {
            use std::os::fd::AsRawFd;
            let mut event=libc::kevent {ident:0,filter:0,flags:0,fflags:0,data:0,udata:std::ptr::null_mut()};
            let timeout=libc::timespec {tv_sec:0,tv_nsec:0};
            let n=unsafe {libc::kevent(self.queue.as_raw_fd(),std::ptr::null(),0,&mut event,1,&timeout)};
            if n==1 && event.flags&libc::EV_ERROR==0 && event.filter==libc::EVFILT_PROC
                && event.ident==self.peer.pid.unwrap() as usize
                && event.fflags&(libc::NOTE_EXIT|libc::NOTE_EXEC)!=0 {
                self.ended.store(true,Ordering::SeqCst);
                return ProcessLiveness::Dead;
            }
        }
        let result=process_liveness(&self.peer);
        if result==ProcessLiveness::Dead {self.ended.store(true,Ordering::SeqCst);}
        result
    }
}
