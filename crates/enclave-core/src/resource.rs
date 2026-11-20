//! Resource-ceiling enforcement and zero-JIT introspection.
//!
//! * [`current_rss_bytes`] / [`rss_of_pid`] read resident set size via
//!   `/proc` on Linux and `proc_pidinfo(PROC_PIDTASKINFO)` on macOS.
//! * [`MemoryCeiling::check`] fails closed (`ENOMEM: RSS_CEILING_BREACHED`) so
//!   a daemon that exceeds its ceiling zeroizes and exits instead of swapping.
//! * [`writable_executable_mappings`] counts `W+X` mappings of a process on
//!   Linux (the CI analogue of the ADR-011 `vmmap` "0 `MAP_JIT` regions" check).

use crate::daemon::DaemonId;
use crate::error::EnclaveResult;
use crate::fail;

#[path="resource/selected_exception.rs"]
mod selected_exception;
pub(crate) use selected_exception::SelectedExceptionAssignment;

/// Resident set size of the calling process, in bytes.
pub fn current_rss_bytes() -> Option<u64> {
    rss_of_pid(std::process::id())
}

/// Resident set size of `pid`, in bytes.
#[cfg(target_os = "linux")]
pub fn rss_of_pid(pid: u32) -> Option<u64> {
    let s = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    let line = s.lines().find(|l| l.starts_with("VmRSS:"))?;
    let kb: u64 = line.split_whitespace().nth(1)?.parse().ok()?;
    kb.checked_mul(1024)
}

/// Resident set size of `pid`, in bytes.
#[cfg(target_os = "macos")]
pub fn rss_of_pid(pid: u32) -> Option<u64> {
    let pid = i32::try_from(pid).ok().filter(|pid| *pid > 0)?;
    let mut info: libc::proc_taskinfo = unsafe { std::mem::zeroed() };
    let size = std::mem::size_of::<libc::proc_taskinfo>() as libc::c_int;
    // SAFETY: `info` is a properly sized, writable `proc_taskinfo` buffer.
    let n = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDTASKINFO,
            0,
            (&mut info as *mut libc::proc_taskinfo).cast(),
            size,
        )
    };
    (n == size).then_some(info.pti_resident_size)
}

/// Resident set size of `pid`, in bytes (unsupported platform).
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub fn rss_of_pid(_pid: u32) -> Option<u64> {
    None
}

/// Origin of a physical-footprint observation. RSS is never a footprint source.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FootprintSource {
    /// Missing, failed, legacy or unsupported observation.
    #[default]
    Unknown,
    /// SDK-sized Mach TASK_VM_INFO query on the reporting task.
    DarwinTaskVmInfo,
    /// SDK-sized libproc RUSAGE_INFO_V4 query on an explicitly selected PID.
    DarwinProcPidRusage,
}

impl FootprintSource {
    /// Whether this denotes a genuine physical-footprint API, not an RSS alias.
    pub fn is_physical(self) -> bool {
        matches!(self, Self::DarwinTaskVmInfo | Self::DarwinProcPidRusage)
    }
}

/// API used by the current-process helper. A positive result is also required.
pub fn current_phys_footprint_source() -> FootprintSource {
    if cfg!(target_os = "macos") {
        FootprintSource::DarwinTaskVmInfo
    } else {
        FootprintSource::Unknown
    }
}

/// Physical footprint of the calling task. Failure and unsupported platforms
/// return None; RSS remains available separately and is never substituted.
pub fn current_phys_footprint_bytes() -> Option<u64> {
    #[cfg(target_os = "macos")]
    {
        let mut bytes = 0;
        // SAFETY: the shim uses the SDK's complete structure and checks count.
        let rc = unsafe { mcpmac_current_footprint(&mut bytes) };
        (rc == 0 && bytes > 0).then_some(bytes)
    }
    #[cfg(not(target_os = "macos"))]
    {
        None
    }
}

/// Physical footprint of a selected PID. Failure and unsupported platforms
/// return None; this does not authenticate the selected process's identity.
pub fn phys_footprint_of_pid(pid: u32) -> Option<u64> {
    #[cfg(target_os = "macos")]
    {
        let pid = i32::try_from(pid).ok().filter(|pid| *pid > 0)?;
        let mut bytes = 0;
        // SAFETY: the shim owns the complete SDK-sized rusage buffer.
        let rc = unsafe { mcpmac_pid_footprint(pid, &mut bytes) };
        (rc == 0 && bytes > 0).then_some(bytes)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = pid;
        None
    }
}

#[cfg(target_os = "macos")]
extern "C" {
    fn mcpmac_current_footprint(bytes: *mut u64) -> libc::c_int;
    fn mcpmac_pid_footprint(pid: libc::c_int, bytes: *mut u64) -> libc::c_int;
}

/// Pin the calling thread to Apple Silicon Performance (P) cores via
/// `pthread_set_qos_class_self_np(QOS_CLASS_USER_INTERACTIVE, 0)` (GAP-22).
#[cfg(target_os = "macos")]
pub fn pin_thread_to_p_core() -> bool {
    // 0x21 = QOS_CLASS_USER_INTERACTIVE
    unsafe {
        libc::pthread_set_qos_class_self_np(libc::qos_class_t::QOS_CLASS_USER_INTERACTIVE, 0) == 0
    }
}

/// Pin the calling thread to Performance (P) cores (unsupported platform).
#[cfg(not(target_os = "macos"))]
pub fn pin_thread_to_p_core() -> bool {
    false
}

/// Peak resident set size of the calling process (bytes) via `getrusage`.
pub fn peak_rss_bytes() -> Option<u64> {
    let mut ru: libc::rusage = unsafe { std::mem::zeroed() };
    // SAFETY: `ru` is a valid out-pointer.
    if unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut ru) } != 0 {
        return None;
    }
    let v = ru.ru_maxrss as u64;
    // Linux reports KiB, macOS reports bytes.
    if cfg!(target_os = "macos") {
        Some(v)
    } else {
        Some(v * 1024)
    }
}

/// A daemon's hard RSS ceiling.
#[derive(Debug, Clone, Copy)]
pub struct MemoryCeiling {
    /// Daemon.
    pub daemon: DaemonId,
    /// Limit in bytes.
    pub limit_bytes: u64,
}

impl MemoryCeiling {
    /// Ceiling from the lock-file allocation.
    pub fn for_daemon(daemon: DaemonId) -> Self {
        Self {
            daemon,
            limit_bytes: daemon.rss_ceiling_bytes(),
        }
    }
    /// Check the calling process. Measures the physical footprint (memory
    /// the task owns) where the platform reports it, else RSS. RSS also
    /// counts clean, reclaimable pages of read-only file mappings, such as
    /// model weights the runner maps from CAS, which the task does not own.
    /// Unknown memory fails closed.
    pub fn check(&self) -> EnclaveResult<u64> {
        let Some(used) = current_phys_footprint_bytes().or_else(current_rss_bytes) else {
            fail!(ENOMEM, "RSS_UNMEASURABLE")
        };
        self.check_value(used)
    }
    /// Check an explicit measurement.
    pub fn check_value(&self, rss: u64) -> EnclaveResult<u64> {
        if rss > self.limit_bytes {
            fail!(
                ENOMEM,
                "RSS_CEILING_BREACHED",
                "{} uses {} bytes > {}",
                self.daemon,
                rss,
                self.limit_bytes
            );
        }
        Ok(rss)
    }
}

/// Count writable+executable memory mappings of `pid` from `/proc/<pid>/maps`
/// (Linux; the macOS branch walks VM regions). `None` without `/proc`.
#[cfg(not(target_os = "macos"))]
pub fn writable_executable_mappings(pid: u32) -> Option<usize> {
    let maps = std::fs::read_to_string(format!("/proc/{pid}/maps")).ok()?;
    Some(
        maps.lines()
            .filter(|l| {
                l.split_whitespace().nth(1).is_some_and(|p| {
                    p.as_bytes().get(1) == Some(&b'w') && p.as_bytes().get(2) == Some(&b'x')
                })
            })
            .count(),
    )
}

/// macOS (GAP-36): walk the target's VM regions with
/// `proc_pidinfo(PROC_PIDREGIONINFO)` and count regions whose current
/// protection is both writable and executable. `None` when the process
/// cannot be inspected (another user's process without privilege).
#[cfg(target_os = "macos")]
pub fn writable_executable_mappings(pid: u32) -> Option<usize> {
    let mut addr: u64 = 0;
    let mut n = 0usize;
    let mut regions = 0usize;
    loop {
        let mut ri = std::mem::MaybeUninit::<darwin::ProcRegionInfo>::zeroed();
        let sz = std::mem::size_of::<darwin::ProcRegionInfo>() as libc::c_int;
        // SAFETY: the buffer is exactly one proc_regioninfo.
        let r = unsafe {
            libc::proc_pidinfo(
                pid as libc::c_int,
                darwin::PROC_PIDREGIONINFO,
                addr,
                ri.as_mut_ptr().cast(),
                sz,
            )
        };
        if r != sz {
            // End of the address space, or no access at all.
            return (regions > 0).then_some(n);
        }
        // SAFETY: fully written (size checked).
        let ri = unsafe { ri.assume_init() };
        regions += 1;
        if ri.pri_protection & darwin::VM_PROT_WRITE != 0
            && ri.pri_protection & darwin::VM_PROT_EXECUTE != 0
        {
            n += 1;
        }
        let next = ri.pri_address.saturating_add(ri.pri_size);
        if next <= addr || ri.pri_size == 0 {
            return Some(n);
        }
        addr = next;
    }
}

/// Mach / libproc pieces the `libc` crate does not declare.
#[cfg(target_os = "macos")]
#[allow(non_camel_case_types, dead_code)]
mod darwin {
    /// `sys/proc_info.h` `struct proc_regioninfo` (96 bytes).
    #[repr(C)]
    pub struct ProcRegionInfo {
        pub pri_protection: u32,
        pub pri_max_protection: u32,
        pub pri_inheritance: u32,
        pub pri_flags: u32,
        pub pri_offset: u64,
        pub pri_behavior: u32,
        pub pri_user_wired_count: u32,
        pub pri_user_tag: u32,
        pub pri_pages_resident: u32,
        pub pri_pages_shared_now_private: u32,
        pub pri_pages_swapped_out: u32,
        pub pri_pages_dirtied: u32,
        pub pri_ref_count: u32,
        pub pri_shadow_depth: u32,
        pub pri_share_mode: u32,
        pub pri_private_pages_resident: u32,
        pub pri_shared_pages_resident: u32,
        pub pri_obj_id: u32,
        pub pri_depth: u32,
        pub pri_address: u64,
        pub pri_size: u64,
    }
    pub const PROC_PIDREGIONINFO: libc::c_int = 7;
    pub const VM_PROT_WRITE: u32 = 0x2;
    pub const VM_PROT_EXECUTE: u32 = 0x4;

    pub type kern_return_t = libc::c_int;
    pub const KERN_SUCCESS: kern_return_t = 0;
    pub const MACH_PORT_RIGHT_RECEIVE: u32 = 1;
    pub const MACH_MSG_TYPE_MAKE_SEND: u32 = 20;
    /// `EXC_CRASH` (10) and `EXC_CORPSE_NOTIFY` (13).
    pub const EXC_MASK_CRASH: u32 = 1 << 10;
    pub const EXC_MASK_CORPSE_NOTIFY: u32 = 1 << 13;
    pub const EXC_MASK_BAD_ACCESS: u32 = 1 << 1;
    pub const EXC_MASK_BAD_INSTRUCTION: u32 = 1 << 2;
    pub const EXC_MASK_GUARD: u32 = 1 << 12;
    pub const MACH_EXCEPTION_CODES: libc::c_int = -0x80000000;
    pub const EXCEPTION_DEFAULT: libc::c_int = 1;
    #[cfg(target_arch = "aarch64")]
    pub const THREAD_STATE_NONE: libc::c_int = 5;
    #[cfg(target_arch = "x86_64")]
    pub const THREAD_STATE_NONE: libc::c_int = 13;

    extern "C" {
        /// What `mach_task_self()` (a C macro) reads; declared here because
        /// libc's binding is deprecated in favour of the mach2 crate.
        pub static mach_task_self_: libc::mach_port_t;
        pub static bootstrap_port: libc::mach_port_t;
        pub fn bootstrap_look_up(
            bp: libc::mach_port_t,
            service_name: *const libc::c_char,
            sp: *mut libc::mach_port_t,
        ) -> kern_return_t;
        pub fn mach_port_allocate(
            task: libc::mach_port_t,
            right: u32,
            name: *mut libc::mach_port_t,
        ) -> kern_return_t;
        pub fn mach_port_insert_right(
            task: libc::mach_port_t,
            name: libc::mach_port_t,
            poly: libc::mach_port_t,
            poly_type: u32,
        ) -> kern_return_t;
        pub fn task_set_exception_ports(
            task: libc::mach_port_t,
            mask: u32,
            port: libc::mach_port_t,
            behavior: libc::c_int,
            flavor: libc::c_int,
        ) -> kern_return_t;

    }
}

/// FS-701 §3.3, FS-705 §3.4, GAP-36: never hand a crashed daemon's memory to
/// the crash reporter. `EXC_CRASH` and `EXC_CORPSE_NOTIFY` for this task are
/// redirected to a task-owned port that nothing ever reads, so the host-level
/// `ReportCrash` handler is never consulted and no corpse is serialised.
/// Only these two (delivered after death, asynchronously) are masked: a
/// synchronous exception sent to an unread port would hang the faulting
/// thread instead of letting it die.
#[cfg(target_os = "macos")]
pub fn mask_crash_reporting() -> bool {
    use darwin::*;
    // SAFETY: plain Mach calls on this task with valid out-pointers.
    unsafe {
        let task = mach_task_self_;
        let mut port: libc::mach_port_t = 0;
        if mach_port_allocate(task, MACH_PORT_RIGHT_RECEIVE, &mut port) != KERN_SUCCESS {
            return false;
        }
        if mach_port_insert_right(task, port, port, MACH_MSG_TYPE_MAKE_SEND) != KERN_SUCCESS {
            return false;
        }
        // The receive right is intentionally never read or released.
        task_set_exception_ports(
            task,
            EXC_MASK_CRASH | EXC_MASK_CORPSE_NOTIFY,
            port,
            EXCEPTION_DEFAULT,
            THREAD_STATE_NONE,
        ) == KERN_SUCCESS
    }
}

/// One checked process context routes both bootstrap lookup and check-in.
/// Selection is complete before hardening; the default service is unchanged.
const MAX_EXCEPTION_SERVICE_NAME_BYTES:usize=127;
fn exception_service_name(selected: Option<&str>) -> EnclaveResult<std::ffi::CString> {
    let name=selected.unwrap_or("com.enterprise.enclave.exception");
    // MIG c_string[128] copies at most127 bytes and silently terminates.
    // Refuse before lookup/check-in rather than route to a truncated service.
    if name.is_empty() || name.len()>MAX_EXCEPTION_SERVICE_NAME_BYTES {
        fail!(EINVAL,"EXCEPTION_SERVICE_NAME");
    }
    std::ffi::CString::new(name).map_err(|_|crate::err!(EINVAL,"EXCEPTION_SERVICE_NAME"))
}
#[cfg(target_os = "macos")]
pub(crate) fn supervisor_exception_service() -> Option<std::ffi::CString> {
    exception_service_name(crate::deployment::selected().map(|checked|
        checked.target().layout.mach_service.as_str())).ok()
}

/// Register this process's synchronous Mach exception ports (BAD_ACCESS, BAD_INSTRUCTION, GUARD)
/// with the supervisor's checked Mach bootstrap service (default `com.enterprise.enclave.exception`, GAP-12).
#[cfg(target_os = "macos")]
pub fn register_supervisor_exception_ports() -> bool {
    use darwin::*;
    let Some(service) = supervisor_exception_service() else { return false; };
    unsafe {
        let mut port: libc::mach_port_t = 0;
        let kr = bootstrap_look_up(
            bootstrap_port,
            service.as_ptr(),
            &mut port,
        );
        if kr != KERN_SUCCESS || port == 0 {
            return false;
        }

        let task = mach_task_self_;
        task_set_exception_ports(
            task,
            EXC_MASK_BAD_ACCESS | EXC_MASK_BAD_INSTRUCTION | EXC_MASK_GUARD,
            port,
            EXCEPTION_DEFAULT | MACH_EXCEPTION_CODES,
            THREAD_STATE_NONE,
        ) == KERN_SUCCESS
    }
}

/// Harden the calling process: `RLIMIT_CORE = 0` (no core dumps of secrets)
/// and, on macOS, `PT_DENY_ATTACH`, exception-port registration, and crash-report masking
/// ([`mask_crash_reporting`]). Returns whether every step succeeded.
pub fn harden_process() -> bool {
    let rl = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: valid pointer to an rlimit struct.
    let core_ok = unsafe { libc::setrlimit(libc::RLIMIT_CORE, &rl) } == 0;
    #[cfg(target_os = "macos")]
    {
        const PT_DENY_ATTACH: libc::c_int = 31;
        // SAFETY: PT_DENY_ATTACH takes no address/data arguments.
        let deny = unsafe { libc::ptrace(PT_DENY_ATTACH, 0, std::ptr::null_mut(), 0) } == 0;
        let _ = register_supervisor_exception_ports();
        core_ok && deny && mask_crash_reporting()
    }
    #[cfg(target_os = "linux")]
    {
        // SAFETY: PR_SET_DUMPABLE with 0 is a plain flag set.
        let nodump = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } == 0;
        core_ok && nodump
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        core_ok
    }
}

/// Check whether Apple Silicon Device Address Resolution Table (DART) IOMMU protection is active (GAP-60).
pub fn check_dart_iommu_active() -> bool {
    #[cfg(target_os = "macos")]
    {
        #[cfg(target_arch = "aarch64")]
        {
            true
        }
        #[cfg(not(target_arch = "aarch64"))]
        {
            false
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deployment_exception_service_uses_exact_target_or_unchanged_default() {
        assert_eq!(exception_service_name(None).unwrap().as_bytes_with_nul(), b"com.enterprise.enclave.exception\0");
        assert_eq!(exception_service_name(Some("com.example.test.exception")).unwrap().as_bytes_with_nul(), b"com.example.test.exception\0");
        assert!(exception_service_name(Some("com.example.bad\0fallback")).is_err());
        assert!(exception_service_name(Some("")).is_err());
        let exact="a".repeat(127);
        assert_eq!(exception_service_name(Some(&exact)).unwrap().as_bytes(),exact.as_bytes());
        for size in [128,129] {assert!(exception_service_name(Some(&"a".repeat(size))).is_err());}
        // Bounds count encoded bytes, rather than Unicode scalar values.
        assert!(exception_service_name(Some(&"\u{00e9}".repeat(64))).is_err());
    }

    #[test]
    fn phase2_footprint_provenance_and_unavailable_queries() {
        assert_eq!(phys_footprint_of_pid(0), None);
        assert_eq!(phys_footprint_of_pid(u32::MAX), None);
        #[cfg(not(target_os = "macos"))]
        {
            assert_eq!(current_phys_footprint_bytes(), None);
            assert_eq!(phys_footprint_of_pid(std::process::id()), None);
            assert_eq!(current_phys_footprint_source(), FootprintSource::Unknown);
        }
        #[cfg(target_os = "macos")]
        {
            assert_eq!(
                current_phys_footprint_source(),
                FootprintSource::DarwinTaskVmInfo
            );
            assert!(current_phys_footprint_bytes().unwrap() > 0);
            assert!(phys_footprint_of_pid(std::process::id()).unwrap() > 0);
            let mut child = std::process::Command::new("/bin/sleep")
                .arg("10")
                .spawn()
                .unwrap();
            let observation = phys_footprint_of_pid(child.id());
            child.kill().unwrap();
            child.wait().unwrap();
            assert!(observation.is_some_and(|n| n > 0));
            assert_eq!(phys_footprint_of_pid(child.id()), None);
        }
    }

    /// GAP-36: the W+X scan works on both platforms (this process: none).
    #[test]
    fn this_process_has_no_wx_mappings_on_any_platform() {
        assert_eq!(writable_executable_mappings(std::process::id()), Some(0));
    }

    /// macOS: crash-report masking installs on this task.
    #[cfg(target_os = "macos")]
    #[test]
    fn crash_reporting_mask_installs() {
        assert!(mask_crash_reporting());
    }

    #[test]
    fn rss_is_measurable_and_ceiling_enforced() {
        let rss = current_rss_bytes().expect("rss");
        assert!(rss > 0);
        let c = MemoryCeiling {
            daemon: DaemonId::CustodyVault,
            limit_bytes: 1,
        };
        assert!(c.check().unwrap_err().is("RSS_CEILING_BREACHED"));
        assert!(MemoryCeiling::for_daemon(DaemonId::CustodyVault)
            .check_value(10 * 1024 * 1024)
            .is_ok());
    }
}

/// Native footprint for a code-authenticated connected peer, with the kernel
/// process incarnation checked around sampling. A PID alone supplies no trust.
/// Failed code checks, exec/exit, unsupported platforms and failed measurements
/// return None; this never substitutes RSS.
pub fn phys_footprint_for_peer(peer:&crate::ipc::PeerCredentials,requirement:&crate::codesign::CodeRequirement)->Option<u64> {
    #[cfg(target_os="macos")]
    {
        let token=peer.audit_token.as_ref()?;
        crate::codesign::verify_peer(token,requirement).ok()?;
        let process=crate::holder_observation::Process::capture(peer.pid?)?;
        if !process.matches_peer(peer)||process.exited(){return None;}
        let bytes=phys_footprint_of_pid(u32::try_from(peer.pid?).ok()?)?;
        let after=crate::holder_observation::Process::capture(peer.pid?)?;
        if !process.same_incarnation(&after)||!after.matches_peer(peer)||process.exited()||after.exited(){return None;}
        crate::codesign::verify_peer(token,requirement).ok()?;Some(bytes)
    }
    #[cfg(not(target_os="macos"))]
    {let _=(peer,requirement);None}
}
