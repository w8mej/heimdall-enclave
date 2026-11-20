//! Privileged revocation enforcement (FS-702 §7.2, RB-202, GAP-21).
//!
//! Canonical objects are truncated while their protected names remain available
//! for retries. Snapshot revocation passes the actual read-only snapshot FD via
//! a separate versioned, role-authenticated endpoint before unmount/deletion.
//! The enforcer observes both FDs and file-backed mappings, reports incomplete
//! kernel queries explicitly, and addresses signals to captured incarnations.
//! Production signals remain confined to daemon UIDs701–705. Native SPI/API and
//! mapped-vnode acceptance remain separately required; see the phase-one notes.

use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::error::EnclaveResult;
use crate::{err, fail};

#[path = "supervisor/restart_admission.rs"]
mod restart_admission;
pub use restart_admission::RespawnTracker;

#[path = "supervisor/pf_observation.rs"]
mod pf_observation;

#[path = "supervisor/pf_restore_input.rs"]
mod pf_restore_input;

#[path = "supervisor/pf_watch.rs"]
mod pf_watch;

#[path = "supervisor/selected_runtime.rs"]
mod selected_runtime;

#[path = "supervisor/selected_socket.rs"]
mod selected_socket;

#[path = "supervisor/selected_accept.rs"]
mod selected_accept;

#[path = "supervisor/mach_wire.rs"]
mod mach_wire;

#[cfg(any(test, target_os = "macos"))]
#[path = "supervisor/selected_mach_native.rs"]
mod selected_mach_native;
#[cfg(any(test, target_os = "macos"))]
pub(crate) use selected_mach_native::CertifiedReceivedTaskAudit;
#[cfg(any(test, target_os = "macos"))]
pub(crate) use selected_mach_native::SelectedFaultIoGuard;

#[path = "supervisor/readiness.rs"]
mod readiness;
pub use readiness::SelectedReadinessClient;
pub(crate) use readiness::SelectedReadinessIoGuard;

/// Grace period between `SIGHUP` and `SIGKILL`.
pub const RELEASE_GRACE: Duration = Duration::from_millis(500);

/// Supervisor socket sub-directory and name (`<socket_dir>/supervisor/supervisor.sock`).
pub const SOCKET_DIR: &str = "supervisor";
/// Client group of the supervisor socket (sole member: `_enclavecas`).
pub const CLIENT_GROUP: &str = "_enclave_sup_c";
/// GID of [`CLIENT_GROUP`] (87xx block, see [`crate::daemon::DaemonId::gid`]).
pub const CLIENT_GID: u32 = 8716;
/// Launchd label of the supervisor.
pub const LAUNCHD_LABEL: &str = "com.enterprise.enclave.supervisor";

/// The supervisor socket under a mesh directory.
pub fn socket_path(socket_dir: &std::path::Path) -> std::path::PathBuf {
    socket_dir.join(SOCKET_DIR).join("supervisor.sock")
}

/// Requests the supervisor serves.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SupervisorRequest {
    /// Liveness.
    Status,
    /// Terminate every holder of the (already truncated) inode.
    EnforceRevocation {
        /// `st_dev` of the revoked object.
        dev: u64,
        /// `st_ino` of the revoked object.
        ino: u64,
    },
    /// Session locked notification (from _enclaveintent helper).
    SessionLocked,
    /// Trigger system sleep / authenticator yank wipe fan-out.
    WipeFanout(crate::power::WipeTrigger),
    /// Forward an integrity fault report to UID 705 (GAP-12).
    ReportFault(crate::quarantine_types::FaultReport),
}

/// Responses.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SupervisorResponse {
    /// Liveness.
    Status(String),
    /// Enforcement result.
    Enforced(RevocationReport),
    /// Wipe receipts from daemon fan-out.
    WipeCompleted(Vec<crate::power::WipeReceipt>),
    /// Result of fault reporting.
    FaultHandled(crate::quarantine_types::Response),
}

/// What happened to the holders of a revoked inode.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevocationReport {
    /// Holders found at the start.
    pub holders: Vec<i32>,
    /// Released (closed the FD or exited) within the grace period.
    pub released: Vec<i32>,
    /// Killed after the grace period.
    pub killed: Vec<i32>,
    /// Holders the enforcer was not permitted to signal.
    pub refused: Vec<i32>,
    /// Time from `SIGHUP` to the end of enforcement (the grace window).
    pub elapsed_ms: u64,
    /// Time spent finding the holders before `SIGHUP`.
    #[serde(default)]
    pub scan_ms: u64,
    /// Every observation in the selected daemon scope completed; no remaining
    /// holder, refused signal or uncertain kernel query is hidden by success.
    #[serde(default)]
    pub complete: bool,
    /// PIDs with incomplete observations or unconfirmed signal completion.
    #[serde(default)]
    pub incomplete: Vec<i32>,
}

/// One process holding the inode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Holder {
    /// PID.
    pub pid: i32,
    /// Real UID of the process.
    pub uid: u32,
}

/// `(st_dev, st_ino)` of an open file or path.
pub fn inode_of(path: &std::path::Path) -> EnclaveResult<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    let m =
        std::fs::metadata(path).map_err(|e| err!(EIO, "INODE_STAT", "{}: {e}", path.display()))?;
    Ok((m.dev(), m.ino()))
}

/// Every process (other than this one) that has the inode open.
pub fn holders(dev: u64, ino: u64) -> Vec<Holder> {
    use crate::holder_observation::{census,Observation};
    census(|_|true).0.into_iter().filter(|p|p.observe(dev,ino)==Observation::Held).map(|p|p.holder).collect()
}

/// `SIGHUP` every permitted holder, wait up to `grace` for it to close the
/// inode or exit, then `SIGKILL` it. `may_signal` decides which holders this
/// enforcer is allowed to touch (the supervisor: enclave daemon UIDs only).
pub fn enforce_revocation(
    dev: u64,
    ino: u64,
    grace: Duration,
    may_signal: impl Fn(&Holder) -> bool,
) -> RevocationReport {
    enforce_observed(dev,ino,grace,&may_signal,false,None)
}

fn enforce_observed(dev:u64,ino:u64,grace:Duration,
    may_signal:&impl Fn(&Holder)->bool, scoped:bool,
    exclude:Option<&crate::holder_observation::Process>)->RevocationReport {
    use crate::holder_observation::{census,Observation};
    let scan=Instant::now();
    let operation_deadline=scan+Duration::from_secs(5);
    let (candidates,census_complete)=census(|h|!scoped || may_signal(h));
    let mut rep=RevocationReport {complete:census_complete,..Default::default()};
    let mut found=Vec::new();
    for p in candidates {
        if exclude.is_some_and(|e|p.same_incarnation(e)) {continue;}
        if scan.elapsed()>Duration::from_secs(2) {rep.complete=false;rep.incomplete.push(p.holder.pid);continue;}
        match p.observe(dev,ino) {
            Observation::Held=>{rep.holders.push(p.holder.pid);found.push(p);},
            Observation::Unknown=>{rep.complete=false;rep.incomplete.push(p.holder.pid);},
            Observation::Absent=>(),
        }
    }
    rep.scan_ms=scan.elapsed().as_millis() as u64;
    let mut pending=Vec::new();
    for p in found {
        if !may_signal(&p.holder) {rep.refused.push(p.holder.pid);rep.complete=false;continue;}
        if Instant::now()>=operation_deadline {rep.complete=false;rep.incomplete.push(p.holder.pid);continue;}
        if p.exited() {rep.released.push(p.holder.pid);continue;}
        if !p.signal(libc::SIGHUP) {rep.complete=false;rep.incomplete.push(p.holder.pid);}
        pending.push(p);
    }
    let t=Instant::now();let deadline=t+grace;
    while !pending.is_empty() && Instant::now()<deadline {
        pending.retain(|p| {
            if Instant::now()>=deadline || Instant::now()>=operation_deadline {return true;}
            if p.exited() || p.observe(dev,ino)==Observation::Absent {rep.released.push(p.holder.pid);false}else{true}
        });
        if !pending.is_empty() {std::thread::sleep(Duration::from_millis(5));}
    }
    let mut signalled=Vec::new();
    for p in pending {
        if Instant::now()>=operation_deadline {rep.complete=false;rep.incomplete.push(p.holder.pid);continue;}
        if p.exited() || p.observe(dev,ino)==Observation::Absent {rep.released.push(p.holder.pid);continue;}
        if p.signal(libc::SIGKILL) {
            rep.killed.push(p.holder.pid);
            signalled.push(p);
        } else {rep.complete=false;rep.incomplete.push(p.holder.pid);}
    }
    // One shared confirmation window, rather than100ms per holder. Kernel
    // queries themselves still require the separate installed timing gate.
    let until=(Instant::now()+Duration::from_millis(100)).min(operation_deadline);
    while signalled.iter().any(|p|!p.exited()) && Instant::now()<until {std::thread::sleep(Duration::from_millis(1));}
    for p in signalled {if !p.exited(){rep.complete=false;rep.incomplete.push(p.holder.pid);}}
    rep.elapsed_ms=t.elapsed().as_millis() as u64;
    // A fresh census detects a newly transferred/inherited descriptor. This is
    // bounded observation, not a universal guarantee against hostile fork/FD
    // transfer. An incomplete retry never deletes the owned publication record.
    let (after,complete)=census(|h|!scoped || may_signal(h));rep.complete &= complete;
    for p in after {
        if exclude.is_some_and(|e|p.same_incarnation(e)) {continue;}
        if Instant::now()>=operation_deadline || p.observe(dev,ino)!=Observation::Absent {
            rep.complete=false;rep.incomplete.push(p.holder.pid);
        }
    }
    rep.incomplete.sort_unstable();rep.incomplete.dedup();rep
}

/// Holders the production supervisor may signal: enclave daemon accounts
/// (UIDs 701–705) only, never `pid <= 1`.
pub fn production_may_signal(h: &Holder) -> bool {
    h.pid > 1 && crate::daemon::DaemonId::from_uid(h.uid).is_some()
}

/// Serve the supervisor until `stop`. Only UID 702 (pinned to its signing
/// identity in production) may connect; `dev` admits the current UID and
/// lets the supervisor signal processes of that UID.
pub fn serve(
    socket_dir: &std::path::Path,
    dev: bool,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> EnclaveResult<()> {
    serve_with_profile(socket_dir, dev, crate::profile::Profile::L1, stop)
}

/// Serve the production supervisor with profile-specific mandatory monitoring.
/// Legacy library callers retain L1's optional policy through [`serve`].
pub fn serve_with_profile(
    socket_dir: &std::path::Path,
    dev: bool,
    profile: crate::profile::Profile,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> EnclaveResult<()> {
    // This exact selected native shape must never reach legacy directory
    // repair or global PF restoration while its required runtime is absent.
    if selected_runtime::handles_selected(dev) {
        return selected_runtime::refuse_selected_start(socket_dir, profile);
    }
    serve_with_monitor(socket_dir, dev, stop, || crate::power::start_for_profile(profile, crate::power::darwin::PowerMonitor::start))
}

// Shared fixed legacy/selected request semantics; extraction changes no policy.
fn primary_peer_policy(dev:bool,me:u32,console_user:u32)->crate::ipc::PeerPolicy {
    use crate::{daemon::DaemonId,ipc::PeerPolicy};
    if dev {
        PeerPolicy::allow([me])
    } else {
        PeerPolicy::allow([])
            .require(
                DaemonId::SwarmSync.uid(),
                crate::codesign::CodeRequirement::daemon(DaemonId::SwarmSync),
            )
            .require(0, crate::codesign::CodeRequirement::ctl())
            .require(console_user, crate::codesign::CodeRequirement::intent())
    }
}
fn primary_handler(sock_dir_cl:std::path::PathBuf,dev:bool,me:u32,console_user:u32,
    tracker_cl:std::sync::Arc<RespawnTracker>,held_status:std::sync::Arc<std::sync::atomic::AtomicBool>)
    ->impl Fn(&crate::ipc::PeerCredentials,SupervisorRequest)->EnclaveResult<SupervisorResponse>+Send+Sync+'static {
    use crate::daemon::DaemonId;
    move |peer: &crate::ipc::PeerCredentials,
                        req: SupervisorRequest|
          -> EnclaveResult<SupervisorResponse> {
        if let Some(remaining) = tracker_cl.is_throttled(peer.uid) {
            fail!(
                EAGAIN,
                "DAEMON_RESPAWN_THROTTLED",
                "Daemon UID {} is currently throttled for another {} ms",
                peer.uid,
                remaining.as_millis()
            );
        }

        Ok(match req {
            SupervisorRequest::Status => {
                SupervisorResponse::Status(format!("supervisor dev={dev} held_v1={}",held_status.load(std::sync::atomic::Ordering::Acquire)))
            }
            SupervisorRequest::EnforceRevocation { dev: d, ino } => {
                if !dev {fail!(ENOSYS,"HELD_REVOCATION_V1_REQUIRED");}
                if peer.uid != DaemonId::SwarmSync.uid()
                    && peer.uid != 0
                    && (!dev || peer.uid != me)
                {
                    fail!(
                        EPERM,
                        "PERMISSION_DENIED",
                        "EnforceRevocation requires SwarmSync (UID 702) peer identity"
                    );
                }
                SupervisorResponse::Enforced(enforce_revocation(d, ino, RELEASE_GRACE, |h| {
                    if dev {
                        h.pid > 1 && h.uid == me
                    } else {
                        production_may_signal(h)
                    }
                }))
            }
            SupervisorRequest::SessionLocked => {
                if peer.uid != console_user && peer.uid != 0 && (!dev || peer.uid != me) {
                    fail!(
                        EPERM,
                        "PERMISSION_DENIED",
                        "SessionLocked requires console user intent helper identity"
                    );
                }
                let receipts =
                    fanout_wipe(&sock_dir_cl, dev, crate::power::WipeTrigger::SessionLocked);
                SupervisorResponse::WipeCompleted(receipts)
            }
            SupervisorRequest::WipeFanout(trigger) => {
                if peer.uid != 0 && (!dev || peer.uid != me) {
                    fail!(
                        EPERM,
                        "PERMISSION_DENIED",
                        "WipeFanout requires root CLI peer identity"
                    );
                }
                let receipts = fanout_wipe(&sock_dir_cl, dev, trigger);
                SupervisorResponse::WipeCompleted(receipts)
            }
            SupervisorRequest::ReportFault(f) => {
                if peer.uid != 0 && (!dev || peer.uid != me) {
                    fail!(
                        EPERM,
                        "PERMISSION_DENIED",
                        "ReportFault requires root CLI peer identity"
                    );
                }
                let target_uid = crate::daemon::DaemonId::ModelRunner.uid();
                let res = tracker_cl.report_fault(target_uid, || report_fault_to_zk(&sock_dir_cl, dev, f))?;
                if res == crate::quarantine_types::Response::StrikeDelayRespawn {
                    #[cfg(target_os = "macos")]
                    if !dev && me == 0 {
                        hold_down_daemon(target_uid, Duration::from_secs(300));
                    }
                }
                SupervisorResponse::FaultHandled(res)
            }
        })
    }
}

fn serve_with_monitor<G>(
    socket_dir: &std::path::Path,
    dev: bool,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    start_monitor: impl FnOnce() -> EnclaveResult<Option<G>>,
) -> EnclaveResult<()> {
    use crate::ipc;
    // This service has its own startup route, outside DaemonArgs. Keep the
    // check before runtime directories, monitors, listeners and threads.
    if crate::deployment::selected().is_some() {
        crate::deployment::startup_lease::retain_selected_startup_lease()?;
    }
    if !dev && crate::ipc::geteuid() != 0 {
        fail!(
            EPERM,
            "SUPERVISOR_NOT_ROOT",
            "the revocation supervisor runs as root"
        );
    }
    if !dev
        && cfg!(target_os = "macos")
        && crate::codesign::signing_mode() == crate::codesign::SigningMode::LocalPins
    {
        crate::codesign::pins::require(crate::codesign::CTL_IDENTIFIER)?;
    }
    // Recreate /var/run before binding after boot; root also prepares the
    // console user's private intent directory as login sessions change.
    #[cfg(target_os = "macos")]
    if !dev {
        let fido = std::path::Path::new("/Library/LaunchDaemons/com.enterprise.enclave.fido.plist").exists();
        crate::runtime_paths::prepare(socket_dir, crate::runtime_paths::console_uid(), fido)?;

    }
    let access = if dev {
        ipc::SocketAccess::OwnerOnly
    } else {
        ipc::SocketAccess::Group { gid: CLIENT_GID }
    };
    let me = crate::ipc::geteuid();
    let console_user = crate::fsutil::console_uid();
    let policy = primary_peer_policy(dev, me, console_user);
    let sock_dir_cl = socket_dir.to_path_buf();
    let respawn_tracker = std::sync::Arc::new(RespawnTracker::new());
    let tracker_cl = respawn_tracker.clone();
    let held_available=std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let held_status=held_available.clone();
    let handler = primary_handler(sock_dir_cl, dev, me, console_user, tracker_cl, held_status);
    let fanout_owner = std::sync::Arc::new((socket_dir.to_path_buf(), dev));
    let fanout = std::sync::Arc::downgrade(&fanout_owner);
    crate::power::registry().register("supervisor_fanout", move |trigger| {
        let Some(fanout) = fanout.upgrade() else { return Ok(()); };
        let receipts = fanout_wipe(&fanout.0, fanout.1, trigger);
        if receipts.len() != 5 || receipts.iter().any(|receipt| !receipt.success) {
            fail!(EIO, "SUPERVISOR_WIPE_INCOMPLETE");
        }
        Ok(())
    });
    let _power_mon = start_monitor()?;
    // Check-in/initial receive failure propagates before spawning other service
    // workers. Development has no launchd exception service requirement.
    #[cfg(target_os = "macos")]
    let _exc_listener = match mach_exception::start_exception_listener(
        socket_dir.to_path_buf(),
        dev,
        respawn_tracker,
        stop.clone(),
    ) {
        Ok(listener) => Some(listener),
        Err(error) if dev => {
            eprintln!("SUPERVISOR_MACH_UNAVAILABLE reason={}", error.reason);
            None
        }
        Err(error) => return Err(error),
    };
    let listener = ipc::bind(&socket_path(socket_dir), access)?;
    let held_policy=held_peer_policy(dev)?;
    let held_listener=ipc::bind(&held_socket_path(socket_dir),access)?;
    let held_stop=stop.clone();
    std::thread::Builder::new().name("held-revocation-v1".into()).spawn(move || {
        held_available.store(true,std::sync::atomic::Ordering::Release);
        if let Err(error)=serve_held_listener(held_listener,dev,held_policy,held_stop) {
            eprintln!("HELD_REVOCATION_UNAVAILABLE reason={}",error.reason);
        }
        held_available.store(false,std::sync::atomic::Ordering::Release);
    }).map_err(|e|err!(EIO,"HELD_REVOCATION_START","{e}"))?;
    #[cfg(target_os = "macos")]
    if !dev {
        let fido = std::path::Path::new("/Library/LaunchDaemons/com.enterprise.enclave.fido.plist").exists();
        let base = socket_dir.to_path_buf();
        let stopped = stop.clone();
        std::thread::spawn(move || {
            while !stopped.load(std::sync::atomic::Ordering::Relaxed) {
                if let Err(e) = crate::runtime_paths::prepare(&base, crate::runtime_paths::console_uid(), fido) {
                    eprintln!("runtime directory maintenance failed: {e}");
                }
                std::thread::sleep(Duration::from_secs(1));
            }
        });
    }
    #[cfg(target_os = "macos")]
    let _pf_watcher = start_pf_watcher(stop.clone(), dev);
    ipc::serve::<SupervisorRequest, SupervisorResponse, _>(
        listener,
        policy,
        std::sync::Arc::new(handler),
        stop,
    )
}

/// Check the Packet Filter anchor rules; if empty, reloads the anchor file within <= 1000ms
/// and records PF_ANCHOR_RESTORED (FS-706 §4.3, D-R12).
pub fn check_and_restore_pf_anchor(
    anchor_name: &str,
    anchor_file: &std::path::Path,
) -> EnclaveResult<Option<u64>> {
    #[cfg(target_os = "macos")]
    {
        if !anchor_file.exists() || unsafe { libc::geteuid() != 0 } {
            return Ok(None);
        }
        let out = std::process::Command::new("pfctl")
            .args(["-a", anchor_name, "-s", "rules"])
            .output();
        let needs_reload = match out {
            Ok(o) => {
                let s = String::from_utf8_lossy(&o.stdout);
                s.lines().filter(|l| !l.trim().is_empty()).count() == 0
            }
            Err(_) => false,
        };
        if needs_reload {
            let t0 = Instant::now();
            let reload_res = std::process::Command::new("pfctl")
                .args(["-a", anchor_name, "-f", &anchor_file.display().to_string()])
                .output();
            let elapsed_ms = t0.elapsed().as_millis() as u64;
            match reload_res {
                Ok(o) if o.status.success() => {
                    eprintln!(
                        r#"{{"event":"PF_ANCHOR_RESTORED","anchor":"{}","elapsed_ms":{}}}"#,
                        anchor_name, elapsed_ms
                    );
                    return Ok(Some(elapsed_ms));
                }
                Ok(o) => {
                    let err = String::from_utf8_lossy(&o.stderr);
                    fail!(
                        EIO,
                        "PF_RELOAD_FAILED",
                        "pfctl -a {anchor_name} -f failed: {err}"
                    );
                }
                Err(e) => {
                    fail!(EIO, "PF_SPAWN_FAILED", "failed to spawn pfctl: {e}");
                }
            }
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = anchor_name;
        let _ = anchor_file;
    }
    Ok(None)
}

/// Background watcher thread for Darwin Packet Filter anchor health (D-R12).
pub fn start_pf_watcher(
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    dev: bool,
) -> Option<std::thread::JoinHandle<()>> {
    if dev {
        return None;
    }
    Some(std::thread::spawn(move || {
        let anchor_file = std::path::PathBuf::from("/etc/pf.anchors/com.enterprise.llm.isolation");
        while !stop.load(std::sync::atomic::Ordering::Relaxed) {
            let _ = check_and_restore_pf_anchor("com.enterprise.llm.isolation", &anchor_file);
            std::thread::sleep(Duration::from_millis(500));
        }
    }))
}

/// Classify already-decoded Mach values for the current architecture.
///
/// Only ARM64 BAD_ACCESS PAC/MTE subtypes have verified integrity meanings
/// here. Other BAD_INSTRUCTION/GUARD values retain the conservative legacy
/// Redzone policy bucket; this does not establish allocator/guard provenance.
/// `code1` is passed through unchanged and is an address only where the actual
/// exception contract defines it as one. Message ABI, authenticated sender,
/// native delivery and stack-guard provenance require separate qualification.
pub fn classify_mach_exception(
    exception: i32,
    code0: i64,
    code1: i64,
) -> (crate::quarantine_types::FaultKind, u64) {
    let architecture = if cfg!(target_arch = "aarch64") {
        MachFaultArchitecture::Arm64
    } else {
        MachFaultArchitecture::Other
    };
    classify_mach_exception_for_arch(architecture, exception, code0, code1)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MachFaultArchitecture { Arm64, Other }

fn classify_mach_exception_for_arch(
    architecture: MachFaultArchitecture,
    exception: i32,
    code0: i64,
    code1: i64,
) -> (crate::quarantine_types::FaultKind, u64) {
    use crate::quarantine_types::FaultKind;
    const EXC_BAD_ACCESS: i32 = 1;
    const EXC_BAD_INSTRUCTION: i32 = 2;
    const EXC_GUARD: i32 = 12;

    // Public SDK 27.2 mach/arm/exception.h:72-75, source-bound in the
    // native-mach-sdk-read-attempt1 receipt. 0x102 is a debug fault, not PAC.
    const EXC_ARM_PAC_FAIL: i64 = 0x105;
    const EXC_ARM_MTE_TAGCHECK_FAIL: i64 = 0x106;
    const EXC_ARM_MTE_CANONICAL_FAIL: i64 = 0x107;

    let fault_addr = code1 as u64;

    match exception {
        EXC_BAD_ACCESS => {
            if architecture == MachFaultArchitecture::Arm64 {
                match code0 {
                    EXC_ARM_MTE_TAGCHECK_FAIL | EXC_ARM_MTE_CANONICAL_FAIL => return (FaultKind::HeapTag, fault_addr),
                    EXC_ARM_PAC_FAIL => return (FaultKind::Pac, fault_addr),
                    _ => {}
                }
            }
            (FaultKind::Segv, fault_addr)
        }
        // Neither guessed instruction subcodes, high address bits nor an
        // unverified guard-type encoding establish a PAC authentication fault.
        EXC_BAD_INSTRUCTION | EXC_GUARD => (FaultKind::Redzone, fault_addr),
        _ => (FaultKind::Segv, fault_addr),
    }
}

/// Forward an integrity fault report to UID 705 (enclave-zk-auditor).
pub fn report_fault_to_zk(
    socket_dir: &std::path::Path,
    dev: bool,
    report: crate::quarantine_types::FaultReport,
) -> EnclaveResult<crate::quarantine_types::Response> {
    use crate::daemon::DaemonId;
    let zk_sock = socket_dir
        .join(DaemonId::ZkAuditor.dir_name())
        .join(format!("{}.sock", DaemonId::ZkAuditor.dir_name()));

    #[derive(Serialize)]
    enum ZkReportFaultReq {
        ReportFault(crate::quarantine_types::FaultReport),
    }
    #[derive(Deserialize)]
    enum ZkReportFaultResp {
        Fault(crate::quarantine_types::Response),
    }

    let mut c = if dev {
        crate::ipc::Client::connect(&zk_sock, crate::ipc::geteuid())?
    } else {
        crate::ipc::Client::connect_verified(
            &zk_sock,
            DaemonId::ZkAuditor.uid(),
            Some(&crate::codesign::CodeRequirement::daemon(
                DaemonId::ZkAuditor,
            )),
        )?
    };

    let resp: ZkReportFaultResp = c.call(&ZkReportFaultReq::ReportFault(report))?;
    match resp {
        ZkReportFaultResp::Fault(r) => Ok(r),
    }
}

// Private per-instance health. Only the original receive-owning worker can
// answer a fresh request; this is an observation, never a readiness permit.
#[cfg(any(target_os = "macos", test))]
mod mach_readiness {
    use super::*;
    use std::sync::{Arc, Mutex, atomic::{AtomicBool, AtomicU8, Ordering}, mpsc};

    const INITIAL: u8 = 0;
    const ARMED: u8 = 1;
    const REVOKED: u8 = 2;
    pub(super) const RECEIVE_TIMED_OUT: i32 = 0x1000_4003;

    pub(super) fn receive_progress(result: i32) -> bool {
        result == 0 || result == RECEIVE_TIMED_OUT
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(super) enum FailureStage {
        ServiceName, CheckIn, WorkerStart, StartupWait, Receive, Reply, Forwarding,
        ReleaseThread, ReleaseTask, ReleaseReceive, RightType, ServiceChanged,
        TaskIdentity, ProcessIdentity,
        WorkerExit, WorkerUnwind, Stop, StopPending, Join, SelectedMessageUnsupported,
    }
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub(super) struct Failure {
        pub(super) stage: FailureStage,
        pub(super) code: Option<i32>,
        pub(super) source_errno: Option<crate::error::Errno>,
        pub(super) source_reason: Option<String>,
    }
    pub(super) struct Shared {
        phase: AtomicU8,
        failures: Mutex<Vec<Failure>>,
    }
    impl Shared {
        pub(super) fn refuse(&self, stage: FailureStage, code: Option<i32>) {
            // Revoke first, even if recording encounters a poisoned lock.
            self.phase.store(REVOKED, Ordering::Release);
            // No user/native text is retained. A worker terminates on its first
            // native failure; subsequent cleanup failures are also preserved.
            self.failures.lock().unwrap_or_else(|error| error.into_inner())
                .push(Failure { stage, code, source_errno: None, source_reason: None });
        }
        pub(super) fn refuse_forwarding(&self, error: crate::error::EnclaveError) {
            self.phase.store(REVOKED, Ordering::Release);
            // Keep typed source failure without copying a peer's free-form
            // detail, payload, PII, paths or a malformed machine reason.
            let reason = if matches!(error.reason.as_str(),
                "IPC_CONNECT" | "IPC_READ" | "IPC_WRITE" | "IPC_ENCODE" | "IPC_DECODE"
                | "IPC_FRAME_TOO_LARGE" | "IPC_FRAME_DEADLINE" | "IPC_FRAME_IDLE_TIMEOUT"
                | "PEER_UID_MISMATCH" | "SERVER_CODESIGN_REJECTED" | "IPC_CANCELLED"
                | "RESTART_FENCE_POISONED" | "RESTART_REPORT_EXHAUSTED" | "RESTART_REPORT_STATE"
                | "RESTART_REVISION_EXHAUSTED") {
                error.reason
            } else { "UNSTRUCTURED_REASON_REDACTED".into() };
            self.failures.lock().unwrap_or_else(|error| error.into_inner()).push(Failure {
                stage: FailureStage::Forwarding, code: None,
                source_errno: Some(error.errno), source_reason: Some(reason),
            });
        }
        pub(super) fn error(&self, reason: &'static str) -> crate::error::EnclaveError {
            match self.failures.lock() {
                Ok(failures) => err!(EIO, reason, "failures={failures:?}"),
                Err(error) => err!(EIO, reason, "failure_state=poisoned failures={:?}", error.into_inner()),
            }
        }
        pub(super) fn stop_failed(&self) -> bool {
            self.failures.lock().map(|failures| failures.iter().any(|failure|
                !matches!(failure.stage, FailureStage::Stop | FailureStage::WorkerExit)))
                .unwrap_or(true)
        }
    }
    pub(super) struct Health {
        pub(super) shared: Arc<Shared>,
        challenges: mpsc::SyncSender<Challenge>,
    }
    pub(super) struct Worker {
        pub(super) shared: Arc<Shared>,
        challenges: mpsc::Receiver<Challenge>,
    }
    pub(super) struct Challenge(mpsc::SyncSender<()>);
    pub(super) struct Armed(Arc<Shared>);
    impl Health {
        pub(super) fn pair() -> (Self, Worker) {
            let shared = Arc::new(Shared { phase: AtomicU8::new(INITIAL), failures: Mutex::new(Vec::new()) });
            let (send, receive) = mpsc::sync_channel(1);
            (Self { shared: shared.clone(), challenges: send }, Worker { shared, challenges: receive })
        }
        pub(super) fn current(&self, running: &AtomicBool, stop: &AtomicBool,
            worker: Option<&std::thread::JoinHandle<()>>, deadline: Instant) -> EnclaveResult<()> {
            if Instant::now() >= deadline { fail!(ETIMEDOUT, "SUPERVISOR_MACH_HEALTH_DEADLINE"); }
            if self.shared.phase.load(Ordering::Acquire) != ARMED
                || !running.load(Ordering::Acquire) || stop.load(Ordering::Acquire)
                || worker.is_none_or(std::thread::JoinHandle::is_finished) {
                return Err(self.shared.error("SUPERVISOR_MACH_HEALTH_UNAVAILABLE"));
            }
            Ok(())
        }
        pub(super) fn observe(&self, running: &AtomicBool, stop: &AtomicBool,
            worker: Option<&std::thread::JoinHandle<()>>, deadline: Instant) -> EnclaveResult<()> {
            self.current(running, stop, worker, deadline)?;
            let (reply, receive) = mpsc::sync_channel(1);
            match self.challenges.try_send(Challenge(reply)) {
                Ok(()) => (),
                Err(mpsc::TrySendError::Full(_)) => fail!(EAGAIN, "SUPERVISOR_MACH_HEALTH_BUSY"),
                Err(mpsc::TrySendError::Disconnected(_)) => return Err(self.shared.error("SUPERVISOR_MACH_HEALTH_UNAVAILABLE")),
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() { fail!(ETIMEDOUT, "SUPERVISOR_MACH_HEALTH_DEADLINE"); }
            match receive.recv_timeout(remaining) {
                Ok(()) => (),
                Err(mpsc::RecvTimeoutError::Timeout) => fail!(ETIMEDOUT, "SUPERVISOR_MACH_HEALTH_DEADLINE"),
                Err(mpsc::RecvTimeoutError::Disconnected) => return Err(self.shared.error("SUPERVISOR_MACH_HEALTH_UNAVAILABLE")),
            }
            self.current(running, stop, worker, deadline)
        }
    }
    impl Drop for Health {
        fn drop(&mut self) { self.shared.phase.store(REVOKED, Ordering::Release); }
    }
    impl Worker {
        pub(super) fn receive_outcome(&self, result: i32) -> bool {
            if receive_progress(result) { self.shared.phase.load(Ordering::Acquire) != REVOKED } else {
                self.shared.refuse(FailureStage::Receive, Some(result));
                false
            }
        }
        pub(super) fn arm(&self, running: &AtomicBool, stop: &AtomicBool) -> EnclaveResult<Armed> {
            if !running.load(Ordering::Acquire) || stop.load(Ordering::Acquire) {
                return Err(self.shared.error("SUPERVISOR_MACH_HEALTH_UNAVAILABLE"));
            }
            self.shared.phase.compare_exchange(INITIAL, ARMED, Ordering::AcqRel, Ordering::Acquire)
                .map_err(|_| self.shared.error("SUPERVISOR_MACH_HEALTH_UNAVAILABLE"))?;
            Ok(Armed(self.shared.clone()))
        }
        pub(super) fn next_challenge(&self) -> Option<Challenge> { self.challenges.try_recv().ok() }
        pub(super) fn acknowledge(&self, challenge: Challenge, running: &AtomicBool, stop: &AtomicBool) {
            if self.shared.phase.load(Ordering::Acquire) == ARMED
                && running.load(Ordering::Acquire) && !stop.load(Ordering::Acquire) {
                let _ = challenge.0.try_send(());
            }
        }
    }
    impl Drop for Armed {
        fn drop(&mut self) {
            self.0.refuse(if std::thread::panicking() { FailureStage::WorkerUnwind }
                else { FailureStage::WorkerExit }, None);
        }
    }
    impl Drop for Worker {
        fn drop(&mut self) { self.shared.phase.store(REVOKED, Ordering::Release); }
    }

    // Generic ownership machinery is shared by the actual native listener and
    // synthetic worker tests; it never manufactures a receive right.
    pub(super) struct Owner {
        pub(super) running: Arc<AtomicBool>,
        pub(super) stop: Arc<AtomicBool>,
        pub(super) worker: Option<std::thread::JoinHandle<()>>,
        pub(super) health: Health,
    }
    impl Owner {
        pub(super) fn observe(&self, deadline: Instant) -> EnclaveResult<()> {
            self.health.observe(&self.running, &self.stop, self.worker.as_ref(), deadline)
        }
        pub(super) fn stop(&mut self, deadline: Instant) -> EnclaveResult<()> {
            self.health.shared.refuse(FailureStage::Stop, None);
            self.running.store(false, Ordering::Release);
            while self.worker.as_ref().is_some_and(|worker| !worker.is_finished()) {
                if Instant::now() >= deadline {
                    self.health.shared.refuse(FailureStage::StopPending, None);
                    return Err(self.health.shared.error("SUPERVISOR_MACH_STOP_PENDING"));
                }
                std::thread::park_timeout(Duration::from_millis(1).min(deadline.saturating_duration_since(Instant::now())));
            }
            if self.worker.take().is_some_and(|worker| worker.join().is_err()) {
                self.health.shared.refuse(FailureStage::Join, None);
                return Err(self.health.shared.error("SUPERVISOR_MACH_JOIN_FAILED"));
            }
            if self.health.shared.stop_failed() { return Err(self.health.shared.error("SUPERVISOR_MACH_STOP_FAILED")); }
            Ok(())
        }
    }
    impl Drop for Owner {
        fn drop(&mut self) {
            if let Err(error) = self.stop(Instant::now()) {
                // A still-running worker retains its actual resource and
                // failure state until exit; never free it concurrently.
                eprintln!("SUPERVISOR_MACH_DROP_INCOMPLETE reason={}", error.reason);
            }
        }
    }
}

#[cfg(test)]
#[path = "supervisor/mach_readiness_tests.rs"]
mod mach_readiness_tests;

#[cfg(target_os = "macos")]
mod mach_exception {
    use super::*;
    use super::mach_readiness::{FailureStage, Health, Shared, Worker};
    use std::sync::{Arc, atomic::{AtomicBool, Ordering}};

    #[repr(C)]
    pub struct MachMsgHeader {
        pub msgh_bits: u32,
        pub msgh_size: u32,
        pub msgh_remote_port: u32,
        pub msgh_local_port: u32,
        pub msgh_voucher_port: u32,
        pub msgh_id: i32,
    }

    #[repr(C)]
    pub struct MachMsgBody {
        pub msgh_descriptor_count: u32,
    }

    #[repr(C)]
    pub struct MachMsgPortDescriptor {
        pub name: u32,
        pub pad1: u32,
        pub pad2: u16,
        pub disposition: u8,
        pub descriptor_type: u8,
    }

    #[repr(C)]
    pub struct MachExceptionRequest {
        pub header: MachMsgHeader,
        pub body: MachMsgBody,
        pub thread: MachMsgPortDescriptor,
        pub task: MachMsgPortDescriptor,
        pub ndr: [u8; 16],
        pub exception: i32,
        pub code_cnt: u32,
        pub codes: [i64; 2],
        pub trailer: [u8; 32],
    }

    #[repr(C)]
    pub struct MachExceptionReply {
        pub header: MachMsgHeader,
        pub ndr: [u8; 16],
        pub ret_code: i32,
    }

    extern "C" {
        static bootstrap_port: libc::mach_port_t;
        fn bootstrap_check_in(
            bp: libc::mach_port_t,
            service_name: *const libc::c_char,
            sp: *mut libc::mach_port_t,
        ) -> libc::c_int;
        fn mach_msg(
            msg: *mut libc::c_void,
            option: libc::c_int,
            send_size: u32,
            rcv_size: u32,
            rcv_name: libc::mach_port_t,
            timeout: u32,
            notify: libc::mach_port_t,
        ) -> libc::c_int;
        fn mach_port_deallocate(task: libc::mach_port_t, name: libc::mach_port_t) -> libc::c_int;
        fn mach_port_mod_refs(task: libc::mach_port_t, name: libc::mach_port_t,
            right: libc::c_uint, delta: libc::c_int) -> libc::c_int;
        fn mach_port_type(task: libc::mach_port_t, name: libc::mach_port_t,
            port_type: *mut libc::c_uint) -> libc::c_int;
        fn pid_for_task(task: libc::mach_port_t, pid: *mut libc::c_int) -> libc::c_int;
        static mach_task_self_: libc::mach_port_t;
    }

    const MACH_RCV_MSG: libc::c_int = 0x00000002;
    const MACH_RCV_TIMEOUT: libc::c_int = 0x00000100;
    const MACH_SEND_MSG: libc::c_int = 0x00000001;
    const MACH_SEND_TIMEOUT: libc::c_int = 0x00000010;
    const MACH_PORT_RIGHT_RECEIVE: libc::c_uint = 1;
    const MACH_PORT_TYPE_RECEIVE: libc::c_uint = 1 << 17;
    const MACH_MSGH_BITS_COMPLEX: u32 = 0x80000000;
    const KERN_SUCCESS: libc::c_int = 0;
    const KERN_FAILURE: libc::c_int = 5;

    // Use the SAME tested terminal lifetime algorithm as root construction.
    // Production fixes its session type to the actual opaque native allocation.
    pub(super) type SelectedLifetime=super::readiness::SessionLifetime<
        Arc<crate::power::selected_owner_session::SelectedOwnerSession>>;

    // The successful check-in transfers one receive right into this original
    // worker owner. No FD/right extraction, Clone or external constructor.
    pub(super) struct ReceiveRight {
        name: libc::mach_port_t,
        shared: Arc<Shared>,
        selected:Option<Arc<SelectedLifetime>>,
        actor_comparison:Option<crate::power::selected_owner_listener::RootSelectedOwnerActorComparison>,
    }
    impl ReceiveRight {
        // Intraparent-only view of the SAME retained receive owner/lifetime.
        // No public constructor, Clone, raw ownership transfer or provider.
        pub(super) fn selected_receive_context(&self)->EnclaveResult<(&SelectedLifetime,u32)> {
            let selected=self.selected.as_ref().ok_or_else(||err!(EACCES,"SUPERVISOR_MACH_SELECTED_REQUIRED"))?;
            let result=(|| {selected.current()?;self.observe()?;selected.current()?;Ok((selected.as_ref(),self.name))})();
            if result.is_err() {selected.stop();}result
        }
        pub(super) fn selected_actor_comparison(&self)->EnclaveResult<&crate::power::selected_owner_listener::RootSelectedOwnerActorComparison> {
            let (selected,_)=self.selected_receive_context()?;
            let result=(|| {
                let actor=self.actor_comparison.as_ref().ok_or_else(||err!(EACCES,"SUPERVISOR_MACH_ORIGINAL_ACTOR_REQUIRED"))?;
                actor.require_same_session(&selected.session,selected.end)?;
                selected.current()?;Ok(actor)
            })();
            if result.is_err() {selected.stop();}result
        }
        fn observe(&self) -> EnclaveResult<()> {
            if let Some(selected)=&self.selected {
                selected.current()?;
                self.actor_comparison.as_ref().ok_or_else(||err!(EACCES,"SUPERVISOR_MACH_ORIGINAL_ACTOR_REQUIRED"))?
                    .require_same_session(&selected.session,selected.end)?;
            }
            let mut kind = 0;
            let result = unsafe { mach_port_type(mach_task_self_, self.name, &mut kind) };
            if result != KERN_SUCCESS || kind & MACH_PORT_TYPE_RECEIVE == 0 {
                self.shared.refuse(FailureStage::RightType,
                    Some(if result != KERN_SUCCESS { result } else { kind as i32 }));
                return Err(self.shared.error("SUPERVISOR_MACH_RIGHT_UNAVAILABLE"));
            }
            if let Some(selected)=&self.selected {
                self.actor_comparison.as_ref().ok_or_else(||err!(EACCES,"SUPERVISOR_MACH_ORIGINAL_ACTOR_REQUIRED"))?
                    .require_same_session(&selected.session,selected.end)?;
                selected.current()?;
            }Ok(())
        }
    }
    impl Drop for ReceiveRight {
        fn drop(&mut self) {
            // Also covers failed thread spawn: the captured right is dropped
            // inside spawn before it can return its error to the root caller.
            if let Some(selected)=&self.selected {selected.stop();}
            let result = unsafe { mach_port_mod_refs(mach_task_self_, self.name, MACH_PORT_RIGHT_RECEIVE, -1) };
            if result != KERN_SUCCESS {
                self.shared.refuse(FailureStage::ReleaseReceive, Some(result));
                eprintln!("SUPERVISOR_MACH_CLEANUP_FAILED stage=receive code={result}");
            }
        }
    }

    pub(super) struct ExceptionListener {
        service: std::ffi::CString,
        owner: super::mach_readiness::Owner,
        selected:Option<Arc<SelectedLifetime>>,
        actor_comparison:Option<crate::power::selected_owner_listener::RootSelectedOwnerActorComparison>,
    }
    impl ExceptionListener {
        fn require_actor_context(&self,end:Instant)->EnclaveResult<()> {
            if let Some(selected)=&self.selected {
                let actor=self.actor_comparison.as_ref().ok_or_else(||err!(EACCES,"SUPERVISOR_MACH_ORIGINAL_ACTOR_REQUIRED"))?;
                actor.require_same_session(&selected.session,end.min(selected.end))?;
                selected.current()?;
            } else if self.actor_comparison.is_some() {fail!(EACCES,"SUPERVISOR_MACH_SELECTED_REQUIRED");}
            Ok(())
        }
        fn require_service(&self) -> EnclaveResult<()> {
            if crate::resource::supervisor_exception_service().as_ref() != Some(&self.service) {
                self.owner.health.shared.refuse(FailureStage::ServiceChanged, None);
                return Err(self.owner.health.shared.error("SUPERVISOR_MACH_SERVICE_CHANGED"));
            }
            Ok(())
        }
        /// Fresh observation of this original service/right-owning loop only.
        /// Required primary/held/PF/Begin predicates remain separate.
        pub(super) fn observe_health(&self, deadline: Instant) -> EnclaveResult<()> {
            let result=(|| {
                if let Some(selected)=&self.selected {selected.current()?;}
                self.require_service()?;
                let deadline=self.selected.as_ref().map_or(deadline,|selected|deadline.min(selected.end));
                self.require_actor_context(deadline)?;
                self.owner.observe(deadline)?;
                self.require_service()?;
                self.require_actor_context(deadline)?;
                if let Some(selected)=&self.selected {selected.current()?;}Ok(())
            })();
            if result.is_err() {if let Some(selected)=&self.selected {selected.stop();}}result
        }
        pub(super) fn require_selected(&self,
            session:&Arc<crate::power::selected_owner_session::SelectedOwnerSession>,
            stop:&Arc<AtomicBool>)->EnclaveResult<Instant> {
            let result=(|| {
                let selected=self.selected.as_ref().ok_or_else(||err!(EACCES,"SUPERVISOR_MACH_SELECTED_REQUIRED"))?;
                if !Arc::ptr_eq(&self.owner.stop,stop) || !Arc::ptr_eq(&selected.stop,stop)
                    || !Arc::ptr_eq(&selected.session,session) {
                    fail!(EACCES,"SUPERVISOR_MACH_SELECTED_INPUT_MISMATCH");
                }
                selected.current()?;self.require_actor_context(selected.end)?;Ok(selected.end)
            })();
            if result.is_err() {
                session.revoke();
                if let Some(selected)=&self.selected {selected.stop();}
            }
            result
        }
        /// Timeout keeps the actual handle in this live owner. Drop requests
        /// stop without destroying a receive right still used by the worker.
        pub(super) fn stop(&mut self, deadline: Instant) -> EnclaveResult<()> {
            if let Some(selected)=&self.selected {selected.stop();}
            self.owner.stop(deadline)
        }
    }
    impl Drop for ExceptionListener {
        fn drop(&mut self) {if let Some(selected)=&self.selected {selected.stop();}}
    }

    fn iteration_completed(right: &ReceiveRight, health: &Worker,
        running: &AtomicBool, stop: &AtomicBool,
        armed: &mut Option<super::mach_readiness::Armed>,
        started: &mut Option<std::sync::mpsc::SyncSender<()>>,
        challenge: Option<super::mach_readiness::Challenge>) -> bool {
        if right.observe().is_err() || !running.load(Ordering::Acquire) || stop.load(Ordering::Acquire) {
            return false;
        }
        if armed.is_none() {
            match health.arm(running, stop) {
                Ok(owner) => *armed = Some(owner),
                Err(_) => return false,
            }
            if started.take().is_none_or(|sender| sender.send(()).is_err()) { return false; }
        }
        if let Some(challenge) = challenge { health.acknowledge(challenge, running, stop); }
        true
    }

    pub fn start_exception_listener(
        socket_dir: std::path::PathBuf,
        dev: bool,
        tracker: std::sync::Arc<RespawnTracker>,
        stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    ) -> EnclaveResult<ExceptionListener> {
        let startup_deadline=Instant::now()+Duration::from_secs(5);
        start_exception_listener_bound(socket_dir,dev,tracker,stop,startup_deadline,None,None)
    }

    pub(super) fn start_selected_exception_listener(
        socket_dir:std::path::PathBuf,tracker:Arc<RespawnTracker>,stop:Arc<AtomicBool>,
        session:Arc<crate::power::selected_owner_session::SelectedOwnerSession>,end:Instant,
        actor_comparison:crate::power::selected_owner_listener::RootSelectedOwnerActorComparison,
    )->EnclaveResult<ExceptionListener> {
        let mut lifetime=SelectedLifetime::new(session,stop.clone());
        lifetime.shorten(end)?;
        let end=lifetime.end;
        let selected=Arc::new(lifetime);
        if crate::ipc::geteuid()!=0 {selected.stop();fail!(EPERM,"SUPERVISOR_MACH_SELECTED_ROOT_REQUIRED");}
        selected.current()?;
        actor_comparison.require_same_session(&selected.session,end)?;
        start_exception_listener_bound(socket_dir,false,tracker,stop,
            end.min(Instant::now()+Duration::from_secs(5)),Some(selected),Some(actor_comparison))
    }

    fn start_exception_listener_bound(socket_dir:std::path::PathBuf,dev:bool,
        tracker:Arc<RespawnTracker>,stop:Arc<AtomicBool>,startup_deadline:Instant,
        selected:Option<Arc<SelectedLifetime>>,
        actor_comparison:Option<crate::power::selected_owner_listener::RootSelectedOwnerActorComparison>,
    )->EnclaveResult<ExceptionListener> {
        if Instant::now()>=startup_deadline {fail!(ETIMEDOUT,"SUPERVISOR_MACH_STARTUP_UNAVAILABLE");}
        if let Some(selected)=&selected {
            selected.current()?;
            actor_comparison.as_ref().ok_or_else(||err!(EACCES,"SUPERVISOR_MACH_ORIGINAL_ACTOR_REQUIRED"))?
                .require_same_session(&selected.session,startup_deadline)?;
        } else if actor_comparison.is_some() {fail!(EACCES,"SUPERVISOR_MACH_SELECTED_REQUIRED");}
        let (health, health_worker) = Health::pair();
        let service = crate::resource::supervisor_exception_service().ok_or_else(|| {
            health.shared.refuse(FailureStage::ServiceName, None);
            health.shared.error("SUPERVISOR_MACH_SERVICE_UNAVAILABLE")
        })?;
        if Instant::now()>=startup_deadline {fail!(ETIMEDOUT,"SUPERVISOR_MACH_STARTUP_UNAVAILABLE");}
        if let Some(selected)=&selected {selected.current()?;}
        let mut server_port: libc::mach_port_t = 0;
        let kr = unsafe {
            bootstrap_check_in(
                bootstrap_port,
                service.as_ptr(),
                &mut server_port,
            )
        };
        if kr != KERN_SUCCESS || server_port == 0 {
            health.shared.refuse(FailureStage::CheckIn, Some(kr));
            return Err(health.shared.error("SUPERVISOR_MACH_CHECK_IN_FAILED"));
        }

        let right = ReceiveRight { name: server_port, shared: health.shared.clone(),selected:selected.clone(),
            actor_comparison:actor_comparison.clone() };
        if Instant::now()>=startup_deadline {fail!(ETIMEDOUT,"SUPERVISOR_MACH_STARTUP_UNAVAILABLE");}
        if let Some(selected)=&selected {selected.current()?;}
        let running = Arc::new(AtomicBool::new(true));
        let worker_running = running.clone();
        let worker_stop = stop.clone();
        let (started, startup) = std::sync::mpsc::sync_channel(1);
        let worker = std::thread::Builder::new().name("supervisor-mach".into()).spawn(move || {
            // Armed guard is declared after the original receive owner so
            // return/unwind revokes health before releasing that native right.
            let right = right;
            let mut armed = None;
            let mut started = Some(started);
            let mut req: MachExceptionRequest = unsafe { std::mem::zeroed() };
            while worker_running.load(Ordering::Acquire) && !worker_stop.load(Ordering::Acquire) {
                if right.observe().is_err() { break; }
                // The selected native adapter owns fresh aligned bytes and
                // actual result-specific message resources; its single report
                // uses these SAME root tracker/socket owners. No legacy PID,
                // reply or forwarding is reachable from this selected branch.
                if right.selected.is_some() {
                    let challenge=health_worker.next_challenge();
                    let outcome=super::selected_mach_native::receive_selected_once(
                        &right,&tracker,&socket_dir);
                    match outcome {
                        super::selected_mach_native::Outcome::TimeoutProgress => {
                            if !iteration_completed(&right,&health_worker,&worker_running,
                                &worker_stop,&mut armed,&mut started,challenge) {break;}
                            continue;
                        },
                        super::selected_mach_native::Outcome::Refused {stage,cleanup,..} => {
                            health_worker.shared.refuse(FailureStage::SelectedMessageUnsupported,outcome.native_result());
                            eprintln!("SUPERVISOR_SELECTED_MACH_REFUSED stage={stage:?} cleanup={cleanup:?}");
                            break;
                        },
                    }
                }
                let challenge = health_worker.next_challenge();
                let rcv_kr = unsafe {
                    mach_msg(
                        (&mut req as *mut MachExceptionRequest).cast(),
                        MACH_RCV_MSG | MACH_RCV_TIMEOUT,
                        0,
                        std::mem::size_of::<MachExceptionRequest>() as u32,
                        right.name,
                        500,
                        0,
                    )
                };
                if !health_worker.receive_outcome(rcv_kr) { break; }
                if rcv_kr == super::mach_readiness::RECEIVE_TIMED_OUT {
                    if !iteration_completed(&right, &health_worker, &worker_running,
                        &worker_stop, &mut armed, &mut started, challenge) { break; }
                    continue;
                }

                let is_complex = (req.header.msgh_bits & MACH_MSGH_BITS_COMPLEX) != 0;
                let is_valid_msg =
                    is_complex && req.header.msgh_id == 2405 && req.body.msgh_descriptor_count == 2;

                if !is_valid_msg {
                    let mut reply = MachExceptionReply {
                        header: MachMsgHeader {
                            msgh_bits: (req.header.msgh_bits & 0xff)
                                | ((req.header.msgh_bits >> 8) & 0xff),
                            msgh_size: std::mem::size_of::<MachExceptionReply>() as u32,
                            msgh_remote_port: req.header.msgh_remote_port,
                            msgh_local_port: 0,
                            msgh_voucher_port: 0,
                            msgh_id: req.header.msgh_id + 100,
                        },
                        ndr: req.ndr,
                        ret_code: KERN_FAILURE,
                    };
                    let sent = unsafe {
                        mach_msg(
                            (&mut reply as *mut MachExceptionReply).cast(),
                            MACH_SEND_MSG | MACH_SEND_TIMEOUT,
                            reply.header.msgh_size,
                            0,
                            0,
                            500,
                            0,
                        )
                    };
                    if sent != KERN_SUCCESS {
                        health_worker.shared.refuse(FailureStage::Reply, Some(sent));
                        break;
                    }
                    if !iteration_completed(&right, &health_worker, &worker_running,
                        &worker_stop, &mut armed, &mut started, challenge) { break; }
                    continue;
                }

                let mut pid: libc::c_int = 0;
                let pkr = unsafe { pid_for_task(req.task.name, &mut pid) };
                let mut proc_uid: u32 = u32::MAX;
                let mut identity_failed = false;
                if pkr == KERN_SUCCESS && pid > 0 {
                    let mut bi = std::mem::MaybeUninit::<libc::proc_bsdinfo>::zeroed();
                    let sz = std::mem::size_of::<libc::proc_bsdinfo>() as libc::c_int;
                    let r = unsafe {
                        libc::proc_pidinfo(
                            pid,
                            libc::PROC_PIDTBSDINFO,
                            0,
                            bi.as_mut_ptr().cast(),
                            sz,
                        )
                    };
                    if r == sz {
                        proc_uid = unsafe { bi.assume_init() }.pbi_ruid;
                    } else {
                        health_worker.shared.refuse(FailureStage::ProcessIdentity, Some(r));
                        identity_failed = true;
                    }
                } else {
                    health_worker.shared.refuse(FailureStage::TaskIdentity, Some(pkr));
                    identity_failed = true;
                }

                let is_daemon = crate::daemon::DaemonId::from_uid(proc_uid).is_some()
                    || (dev && proc_uid == crate::ipc::geteuid());

                let mut forwarding_failed = false;
                if is_daemon {
                    let (kind, fault_addr) =
                        classify_mach_exception(req.exception, req.codes[0], req.codes[1]);
                    let at_ms = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_millis() as u64;

                    let report = crate::quarantine_types::FaultReport {
                        kind,
                        fault_addr,
                        at_ms,
                    };
                    match tracker.report_fault(proc_uid, || report_fault_to_zk(&socket_dir, dev, report)) {
                        Ok(res) => {
                            if res == crate::quarantine_types::Response::StrikeDelayRespawn {
                                #[cfg(target_os = "macos")]
                                if !dev && crate::ipc::geteuid() == 0 {
                                    hold_down_daemon(proc_uid, Duration::from_secs(300));
                                }
                            }
                        }
                        Err(error) => {
                            health_worker.shared.refuse_forwarding(error);
                            forwarding_failed = true;
                        }
                    }
                }

                let mut reply = MachExceptionReply {
                    header: MachMsgHeader {
                        msgh_bits: (req.header.msgh_bits & 0xff)
                            | ((req.header.msgh_bits >> 8) & 0xff),
                        msgh_size: std::mem::size_of::<MachExceptionReply>() as u32,
                        msgh_remote_port: req.header.msgh_remote_port,
                        msgh_local_port: 0,
                        msgh_voucher_port: 0,
                        msgh_id: req.header.msgh_id + 100,
                    },
                    ndr: req.ndr,
                    ret_code: KERN_FAILURE,
                };

                let (sent, released_thread, released_task) = unsafe {
                    let sent = mach_msg(
                        (&mut reply as *mut MachExceptionReply).cast(),
                        MACH_SEND_MSG | MACH_SEND_TIMEOUT,
                        reply.header.msgh_size,
                        0,
                        0,
                        500,
                        0,
                    );
                    let thread = mach_port_deallocate(mach_task_self_, req.thread.name);
                    let task = mach_port_deallocate(mach_task_self_, req.task.name);
                    (sent, thread, task)
                };
                // Do not short-circuit later cleanup or replace earlier errors.
                for (stage, result) in [(FailureStage::Reply, sent),
                    (FailureStage::ReleaseThread, released_thread), (FailureStage::ReleaseTask, released_task)] {
                    if result != KERN_SUCCESS { health_worker.shared.refuse(stage, Some(result)); }
                }
                if identity_failed || forwarding_failed || sent != KERN_SUCCESS || released_thread != KERN_SUCCESS || released_task != KERN_SUCCESS { break; }
                if !iteration_completed(&right, &health_worker, &worker_running,
                    &worker_stop, &mut armed, &mut started, challenge) { break; }
            }
            drop(armed);
            drop(right);
            // Cleanup error codes are retained even if the public owner had
            // to abandon its wait while this worker was still blocked.
            if health_worker.shared.stop_failed() {
                eprintln!("SUPERVISOR_MACH_WORKER_FAILED {}", health_worker.shared.error("SUPERVISOR_MACH_WORKER_FAILED"));
            }
        }).map_err(|error| {
            health.shared.refuse(FailureStage::WorkerStart, error.raw_os_error());
            health.shared.error("SUPERVISOR_MACH_WORKER_START_FAILED")
        })?;
        let mut owner = ExceptionListener { service, owner: super::mach_readiness::Owner { running, stop, worker: Some(worker), health },selected,actor_comparison };
        match startup.recv_timeout(startup_deadline.saturating_duration_since(Instant::now())) {
            Ok(()) if Instant::now() < startup_deadline => {
                owner.owner.health.current(&owner.owner.running, &owner.owner.stop, owner.owner.worker.as_ref(), startup_deadline)?;
                if let Some(selected)=&owner.selected {selected.current()?;}
                Ok(owner)
            }
            _ => {
                owner.owner.health.shared.refuse(FailureStage::StartupWait, None);
                let _ = owner.stop(startup_deadline);
                Err(owner.owner.health.shared.error("SUPERVISOR_MACH_STARTUP_UNAVAILABLE"))
            }
        }
    }
}

/// Boot out a crashed PII daemon after a non-latching strike.
///
/// Automatic bootstrap is deliberately unavailable: neither a timer nor a
/// false status snapshot supplies protected current host/latch authority.
/// Callers record the minimum `duration` in the shared tracker. Legitimate
/// recovery and installed respawn qualification remain separate requirements.
#[cfg(target_os = "macos")]
pub fn hold_down_daemon(uid: u32, duration: Duration) {
    if !restart_admission::pii_uid(uid) { return; }
    if let Some(id) = crate::daemon::DaemonId::from_uid(uid) {
        let label = id.launchd_label();
        let result = restart_admission::bounded_bootout(&label);
        if let Err(error) = result {
            eprintln!("DAEMON_BOOTOUT_FAILED uid={uid} reason={}", error.reason);
        }
        eprintln!("DAEMON_AUTOMATIC_RESPAWN_REFUSED uid={uid} minimum_delay_ms={} reason=PROTECTED_RESTART_AUTHORITY_REQUIRED", duration.as_millis());
    }
}

/// Fan out a wipe request to all 5 daemons over local sockets.
pub fn fanout_wipe(
    socket_dir: &std::path::Path,
    dev: bool,
    trigger: crate::power::WipeTrigger,
) -> Vec<crate::power::WipeReceipt> {
    use crate::daemon::DaemonId;
    use crate::power::{continuous_time_ns, WipeReceipt, WipeTrigger};
    let mut receipts = Vec::new();

    // 1. ModelRunner (701) -> RunnerRequest::Zeroize
    #[derive(Serialize)]
    enum RunnerZeroizeReq {
        Zeroize(RunnerZeroizeTrigger),
    }
    #[derive(Serialize)]
    #[allow(dead_code)]
    enum RunnerZeroizeTrigger {
        TaskExit,
        SystemWillSleep,
        ScreenLocked,
        YubiKeyRemoved,
        TaintExit,
    }
    let runner_trigger = match trigger {
        WipeTrigger::SystemSleep => RunnerZeroizeTrigger::SystemWillSleep,
        WipeTrigger::SessionLocked => RunnerZeroizeTrigger::ScreenLocked,
        WipeTrigger::AuthenticatorYank => RunnerZeroizeTrigger::YubiKeyRemoved,
        WipeTrigger::ThunderboltHotPlugLocked => RunnerZeroizeTrigger::ScreenLocked,
    };
    let t_start = continuous_time_ns();
    let runner_sock = socket_dir
        .join(DaemonId::ModelRunner.dir_name())
        .join(format!("{}.sock", DaemonId::ModelRunner.dir_name()));
    let runner_res = (|| -> EnclaveResult<()> {
        let mut c = if dev {
            crate::ipc::Client::connect(&runner_sock, crate::ipc::geteuid())?
        } else {
            crate::ipc::Client::connect_verified(
                &runner_sock,
                DaemonId::ModelRunner.uid(),
                Some(&crate::codesign::CodeRequirement::daemon(
                    DaemonId::ModelRunner,
                )),
            )?
        };
        let _resp: serde_json::Value = c.call(&RunnerZeroizeReq::Zeroize(runner_trigger))?;
        Ok(())
    })();
    let t_end = continuous_time_ns();
    receipts.push(WipeReceipt {
        daemon_uid: Some(DaemonId::ModelRunner.uid()),
        trigger,
        t_start_ns: t_start,
        t_end_ns: t_end,
        duration_ns: t_end.saturating_sub(t_start),
        cpu_us: 0,
        success: runner_res.is_ok(),
    });

    // 2. CustodyVault (703) -> VaultRequest::Tamper
    #[derive(Serialize)]
    enum CustodyTamperReq {
        Tamper(CustodyTamperEvent),
    }
    #[derive(Serialize)]
    #[allow(dead_code)]
    enum CustodyTamperEvent {
        UsbYank { docked: bool },
        ScreenLock,
        LidSleep,
        KeepaliveFailure,
    }
    let custody_ev = match trigger {
        WipeTrigger::SystemSleep => CustodyTamperEvent::LidSleep,
        WipeTrigger::SessionLocked => CustodyTamperEvent::ScreenLock,
        WipeTrigger::AuthenticatorYank => CustodyTamperEvent::UsbYank { docked: false },
        WipeTrigger::ThunderboltHotPlugLocked => CustodyTamperEvent::ScreenLock,
    };
    let t_start = continuous_time_ns();
    let custody_sock = socket_dir
        .join(DaemonId::CustodyVault.dir_name())
        .join(format!("{}.sock", DaemonId::CustodyVault.dir_name()));
    let custody_res = (|| -> EnclaveResult<()> {
        let mut c = if dev {
            crate::ipc::Client::connect(&custody_sock, crate::ipc::geteuid())?
        } else {
            crate::ipc::Client::connect_verified(
                &custody_sock,
                DaemonId::CustodyVault.uid(),
                Some(&crate::codesign::CodeRequirement::daemon(
                    DaemonId::CustodyVault,
                )),
            )?
        };
        let _resp: serde_json::Value = c.call(&CustodyTamperReq::Tamper(custody_ev))?;
        Ok(())
    })();
    let t_end = continuous_time_ns();
    receipts.push(WipeReceipt {
        daemon_uid: Some(DaemonId::CustodyVault.uid()),
        trigger,
        t_start_ns: t_start,
        t_end_ns: t_end,
        duration_ns: t_end.saturating_sub(t_start),
        cpu_us: 0,
        success: custody_res.is_ok(),
    });

    // 3. AgentRuntime (704) -> IfcRequest::Wipe
    #[derive(Serialize)]
    enum UnitWipeReq {
        Wipe,
    }
    let t_start = continuous_time_ns();
    let ifc_sock = socket_dir
        .join(DaemonId::AgentRuntime.dir_name())
        .join(format!("{}.sock", DaemonId::AgentRuntime.dir_name()));
    let ifc_res = (|| -> EnclaveResult<()> {
        let mut c = if dev {
            crate::ipc::Client::connect(&ifc_sock, crate::ipc::geteuid())?
        } else {
            crate::ipc::Client::connect_verified(
                &ifc_sock,
                DaemonId::AgentRuntime.uid(),
                Some(&crate::codesign::CodeRequirement::daemon(
                    DaemonId::AgentRuntime,
                )),
            )?
        };
        let _resp: serde_json::Value = c.call(&UnitWipeReq::Wipe)?;
        Ok(())
    })();
    let t_end = continuous_time_ns();
    receipts.push(WipeReceipt {
        daemon_uid: Some(DaemonId::AgentRuntime.uid()),
        trigger,
        t_start_ns: t_start,
        t_end_ns: t_end,
        duration_ns: t_end.saturating_sub(t_start),
        cpu_us: 0,
        success: ifc_res.is_ok(),
    });

    // 4. ZkAuditor (705) -> ZkRequest::Wipe
    let t_start = continuous_time_ns();
    let zk_sock = socket_dir
        .join(DaemonId::ZkAuditor.dir_name())
        .join(format!("{}.sock", DaemonId::ZkAuditor.dir_name()));
    let zk_res = (|| -> EnclaveResult<()> {
        let mut c = if dev {
            crate::ipc::Client::connect(&zk_sock, crate::ipc::geteuid())?
        } else {
            crate::ipc::Client::connect_verified(
                &zk_sock,
                DaemonId::ZkAuditor.uid(),
                Some(&crate::codesign::CodeRequirement::daemon(
                    DaemonId::ZkAuditor,
                )),
            )?
        };
        let _resp: serde_json::Value = c.call(&UnitWipeReq::Wipe)?;
        Ok(())
    })();
    let t_end = continuous_time_ns();
    receipts.push(WipeReceipt {
        daemon_uid: Some(DaemonId::ZkAuditor.uid()),
        trigger,
        t_start_ns: t_start,
        t_end_ns: t_end,
        duration_ns: t_end.saturating_sub(t_start),
        cpu_us: 0,
        success: zk_res.is_ok(),
    });

    // 5. SwarmSync (702) -> CasRequest::Wipe
    let t_start = continuous_time_ns();
    let cas_sock = socket_dir
        .join(DaemonId::SwarmSync.dir_name())
        .join(format!("{}.sock", DaemonId::SwarmSync.dir_name()));
    let cas_res = (|| -> EnclaveResult<()> {
        let mut c = if dev {
            crate::ipc::Client::connect(&cas_sock, crate::ipc::geteuid())?
        } else {
            crate::ipc::Client::connect_verified(
                &cas_sock,
                DaemonId::SwarmSync.uid(),
                Some(&crate::codesign::CodeRequirement::daemon(
                    DaemonId::SwarmSync,
                )),
            )?
        };
        let _resp: serde_json::Value = c.call(&UnitWipeReq::Wipe)?;
        Ok(())
    })();
    let t_end = continuous_time_ns();
    receipts.push(WipeReceipt {
        daemon_uid: Some(DaemonId::SwarmSync.uid()),
        trigger,
        t_start_ns: t_start,
        t_end_ns: t_end,
        duration_ns: t_end.saturating_sub(t_start),
        cpu_us: 0,
        success: cas_res.is_ok(),
    });

    receipts
}

/// Notify the supervisor that the Aqua GUI session was locked.
pub fn request_session_locked(
    socket: &std::path::Path,
    dev: bool,
) -> EnclaveResult<Vec<crate::power::WipeReceipt>> {
    let mut c = if dev {
        crate::ipc::Client::connect(socket, crate::ipc::geteuid())?
    } else {
        crate::ipc::Client::connect_verified(
            socket,
            0,
            Some(&crate::codesign::CodeRequirement::ctl()),
        )?
    };
    match c.call(&SupervisorRequest::SessionLocked)? {
        SupervisorResponse::WipeCompleted(r) => Ok(r),
        _ => fail!(EIO, "SUPERVISOR_PROTOCOL"),
    }
}

/// Trigger an explicit wipe fanout from the supervisor.
pub fn request_wipe_fanout(
    socket: &std::path::Path,
    dev: bool,
    trigger: crate::power::WipeTrigger,
) -> EnclaveResult<Vec<crate::power::WipeReceipt>> {
    let mut c = if dev {
        crate::ipc::Client::connect(socket, crate::ipc::geteuid())?
    } else {
        crate::ipc::Client::connect_verified(
            socket,
            0,
            Some(&crate::codesign::CodeRequirement::ctl()),
        )?
    };
    match c.call(&SupervisorRequest::WipeFanout(trigger))? {
        SupervisorResponse::WipeCompleted(r) => Ok(r),
        _ => fail!(EIO, "SUPERVISOR_PROTOCOL"),
    }
}

/// UID 702's client: connect — verifying that the server is root running
/// the signed `depot-enclave` binary (GAP-02; the dev UID in development) —
/// and request enforcement.
pub fn request_enforcement(
    socket: &std::path::Path,
    dev: bool,
    d: u64,
    ino: u64,
) -> EnclaveResult<RevocationReport> {
    let mut c = if dev {
        crate::ipc::Client::connect(socket, crate::ipc::geteuid())?
    } else {
        crate::ipc::Client::connect_verified(
            socket,
            0,
            Some(&crate::codesign::CodeRequirement::ctl()),
        )?
    };
    match c.call(&SupervisorRequest::EnforceRevocation { dev: d, ino })? {
        SupervisorResponse::Enforced(r) => Ok(r),
        _ => fail!(EIO, "SUPERVISOR_PROTOCOL"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deployment_canonical_cas_layout_preserves_default_and_varied_depth() {
        let root="ab".repeat(32);
        let (path,depth)=canonical_object_layout(std::path::Path::new("/opt/enterprise/enclave/cas"),&root).unwrap();
        assert_eq!(path,format!("/opt/enterprise/enclave/cas/objects/{root}"));
        assert_eq!((depth-1,depth+1),(3,5));
        let (path,depth)=canonical_object_layout(std::path::Path::new("/fixture-cas"),&root).unwrap();
        assert_eq!(path,format!("/fixture-cas/objects/{root}"));
        assert_eq!((depth-1,depth+1),(0,2));
        let (path,depth)=canonical_object_layout(std::path::Path::new("/var/db/dedicated/deeper/cas"),&root).unwrap();
        assert_eq!(path,format!("/private/var/db/dedicated/deeper/cas/objects/{root}"));
        assert_eq!((depth-1,depth+1),(5,7));
        for unsafe_root in ["relative","/","/fixture/../cas","/fixture//cas","/fixture/cas/"] {
            assert!(canonical_object_layout(std::path::Path::new(unsafe_root),&root).is_err());
        }
    }

    use std::os::unix::process::ExitStatusExt;
    use std::process::{Child, Command, Stdio};

    #[test]
    fn mach_classifier_sdk_arm64_integrity_subtypes_preserve_exact_raw_address() {
        use crate::quarantine_types::FaultKind;
        // Current public SDK declarations, not the previous classifier's
        // self-repeating values: PAC105, MTE tagcheck106, canonical107.
        for (code, expected) in [(0x105, FaultKind::Pac), (0x106, FaultKind::HeapTag), (0x107, FaultKind::HeapTag)] {
            for address in [0, 8, 0x10000, 0x7f00_0001_0000_2000, -1] {
                assert_eq!(classify_mach_exception_for_arch(MachFaultArchitecture::Arm64, 1, code, address),
                    (expected, address as u64));
            }
        }
    }

    #[test]
    fn mach_classifier_debug_instruction_guard_and_tagged_address_cannot_fabricate_pac() {
        use crate::quarantine_types::FaultKind;
        for architecture in [MachFaultArchitecture::Arm64, MachFaultArchitecture::Other] {
            for code in [0, 1, 2, 0x100, 0x101, 0x102, 0x103, 0x104, 0x108, -1] {
                for address in [8, 0x20000, 0x7f00_0001_0000_2000, -1] {
                    assert_eq!(classify_mach_exception_for_arch(architecture, 1, code, address),
                        (FaultKind::Segv, address as u64));
                }
            }
            for exception in [2, 12] {
                for code in [0x100, 0x102, 0x105, 0x106, 0x107, (2i64 << 32) | 1, -1] {
                    assert_eq!(classify_mach_exception_for_arch(architecture, exception, code, 8),
                        (FaultKind::Redzone, 8));
                }
            }
        }
    }

    #[test]
    fn mach_classifier_other_architectures_do_not_interpret_arm_integrity_subtypes() {
        use crate::quarantine_types::FaultKind;
        for code in [0x105, 0x106, 0x107] {
            assert_eq!(classify_mach_exception_for_arch(MachFaultArchitecture::Other, 1, code, -1),
                (FaultKind::Segv, u64::MAX));
            for exception in [0, 3, 13, i32::MAX] {
                assert_eq!(classify_mach_exception_for_arch(MachFaultArchitecture::Arm64, exception, code, -1),
                    (FaultKind::Segv, u64::MAX));
            }
            let expected = if cfg!(target_arch = "aarch64") {
                if code == 0x105 { FaultKind::Pac } else { FaultKind::HeapTag }
            } else { FaultKind::Segv };
            assert_eq!(classify_mach_exception(1, code, 0x20000), (expected, 0x20000));
        }
    }

    /// Kills the child on drop, so a failed assertion never leaves it running.
    struct Guard(Child);
    impl Drop for Guard {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    fn spawn(script: String) -> Guard {
        Guard(
            Command::new("sh")
                .arg("-c")
                .arg(script)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        )
    }

    fn file() -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("depot-sup-{}", crate::rng::u64()));
        std::fs::write(&p, b"weights").unwrap();
        p
    }

    fn wait_for_holder(dev: u64, ino: u64) -> Vec<i32> {
        let t = Instant::now();
        loop {
            let h: Vec<i32> = holders(dev, ino).iter().map(|h| h.pid).collect();
            if !h.is_empty() || t.elapsed() > Duration::from_secs(5) {
                return h;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    fn holder_ignoring_sighup_is_killed_after_grace_and_bystanders_are_untouched() {
        let p = file();
        let (dev, ino) = inode_of(&p).unwrap();
        // One process holding the inode on fd 3 and ignoring SIGHUP (the
        // ignore disposition survives `exec`).
        let mut holder = spawn(format!(
            "exec 3<'{}'; trap '' HUP; exec sleep 30",
            p.display()
        ));
        let bystander = spawn("exec sleep 30".into());
        let pid = holder.0.id() as i32;
        assert_eq!(wait_for_holder(dev, ino), vec![pid]);
        let me = crate::ipc::geteuid();
        let rep = enforce_revocation(dev, ino, RELEASE_GRACE, |h| h.uid == me);
        assert_eq!(rep.killed, vec![pid]);
        assert!(
            rep.elapsed_ms >= 500 && rep.elapsed_ms < 700,
            "{}",
            rep.elapsed_ms
        );
        assert_eq!(holder.0.wait().unwrap().signal(), Some(libc::SIGKILL));
        let mut b = bystander;
        assert!(
            b.0.try_wait().unwrap().is_none(),
            "a process not holding the inode is never signalled"
        );
        let _ = std::fs::remove_file(p);
    }

    #[test]
    fn released_holders_are_not_killed_and_refused_ones_not_signalled() {
        let p = file();
        let (dev, ino) = inode_of(&p).unwrap();
        // Closes the inode on SIGHUP and keeps running.
        let mut h = Guard(
            Command::new("python3")
                .arg("-c")
                .arg(format!(
                    "import signal, time; f = open('{}'); signal.signal(signal.SIGHUP, lambda *a: f.close()); time.sleep(30)",
                    p.display()
                ))
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        );
        let pid = h.0.id() as i32;
        // The process holds the file descriptor until SIGHUP.
        assert!(wait_for_holder(dev, ino).contains(&pid));
        let rep = enforce_revocation(dev, ino, RELEASE_GRACE, |_| false);
        assert!(rep.refused.contains(&pid), "{rep:?}");
        assert!(rep.killed.is_empty());
        let rep = enforce_revocation(dev, ino, RELEASE_GRACE, |_| true);
        assert!(rep.released.contains(&pid), "{rep:?}");
        assert!(rep.killed.is_empty(), "{rep:?}");
        assert!(h.0.try_wait().unwrap().is_none());
        let _ = std::fs::remove_file(p);
    }

    #[test]
    fn supervisor_socket_round_trip_terminates_the_holder() {
        let p = file();
        let (dev, ino) = inode_of(&p).unwrap();
        // Short path: UNIX socket paths are limited to ~104 bytes on macOS,
        // whose per-user temp directory alone is ~50.
        let mesh =
            std::path::PathBuf::from(format!("/tmp/depotsup-{:x}", crate::rng::u64() & 0xffff_ffff));
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (m, st) = (mesh.clone(), stop.clone());
        let server = std::thread::spawn(move || serve(&m, true, st));
        let sock = socket_path(&mesh);
        let t = Instant::now();
        while !sock.exists() && t.elapsed() < Duration::from_secs(5) {
            std::thread::sleep(Duration::from_millis(10));
        }
        let mut holder = spawn(format!(
            "exec 3<'{}'; trap '' HUP; exec sleep 30",
            p.display()
        ));
        let pid = holder.0.id() as i32;
        assert_eq!(wait_for_holder(dev, ino), vec![pid]);
        let rep = request_enforcement(&sock, true, dev, ino).unwrap();
        assert_eq!(rep.killed, vec![pid]);
        assert_eq!(holder.0.wait().unwrap().signal(), Some(libc::SIGKILL));
        // A client expecting a root supervisor refuses a non-root server.
        if crate::ipc::geteuid() != 0 {
            assert!(request_enforcement(&sock, false, dev, ino)
                .unwrap_err()
                .is("SERVER_UID_MISMATCH"));
        }
        stop.store(true, std::sync::atomic::Ordering::SeqCst);
        let _ = server.join();
        let _ = std::fs::remove_dir_all(mesh);
        let _ = std::fs::remove_file(p);
    }

    #[test]
    fn production_policy_only_signals_daemon_accounts() {
        assert!(production_may_signal(&Holder {
            pid: 4242,
            uid: 701
        }));
        assert!(!production_may_signal(&Holder {
            pid: 4242,
            uid: 501
        }));
        assert!(!production_may_signal(&Holder { pid: 1, uid: 701 }));
    }

    #[test]
    fn fanout_wipe_tolerates_missing_daemons_gracefully() {
        let tmp = std::env::temp_dir().join(format!("depot-wipe-{}", crate::rng::u64()));
        std::fs::create_dir_all(&tmp).unwrap();
        let receipts = fanout_wipe(&tmp, true, crate::power::WipeTrigger::SessionLocked);
        assert_eq!(receipts.len(), 5);
        for r in &receipts {
            assert_eq!(r.trigger, crate::power::WipeTrigger::SessionLocked);
            // Non-existent daemon sockets report success: false without crashing
            assert!(!r.success);
        }
        let _ = std::fs::remove_dir_all(tmp);
    }

    #[test]
    fn f38_supervisor_fanout_receipts_identify_each_authenticated_target_without_legacy_decode_breakage() {
        let tmp = std::env::temp_dir().join(format!("depot-wipe-identity-{:x}", crate::rng::u64()));
        std::fs::create_dir(&tmp).unwrap();
        let receipts = fanout_wipe(&tmp, true, crate::power::WipeTrigger::SessionLocked);
        assert_eq!(receipts.len(), 5);
        let identities: std::collections::BTreeSet<_> = receipts.iter().map(|receipt| receipt.daemon_uid.expect("supervisor fixes target identity")).collect();
        assert_eq!(identities, (701..=705).collect());
        assert!(receipts.iter().all(|receipt| !receipt.success));
        let mut legacy = serde_json::to_value(&receipts[0]).unwrap();
        legacy.as_object_mut().unwrap().remove("daemon_uid");
        let decoded: crate::power::WipeReceipt = serde_json::from_value(legacy).unwrap();
        assert_eq!(decoded.daemon_uid, None);
        std::fs::remove_dir(tmp).unwrap();
    }

    #[test]
    fn f38_supervisor_required_monitor_failure_precedes_bind_and_success_guard_drops_on_bind_failure() {
        use std::sync::{Arc, atomic::{AtomicBool, AtomicUsize, Ordering}};
        let tmp = std::env::temp_dir().join(format!("depot-supervisor-monitor-{:x}", crate::rng::u64()));
        std::fs::create_dir(&tmp).unwrap();
        for profile in [crate::profile::Profile::L2, crate::profile::Profile::L3] {
            let path = tmp.join(profile.to_string());
            let error = serve_with_monitor::<()>(&path, true, Arc::new(AtomicBool::new(false)), || {
                crate::power::start_for_profile(profile, || Err(err!(EIO, "FIXTURE_MONITOR_REQUIRED")))
            }).unwrap_err();
            assert!(error.is("FIXTURE_MONITOR_REQUIRED"));
            assert!(!socket_path(&path).exists());
            assert!(!path.exists());
        }
        struct Guard(Arc<AtomicUsize>);
        impl Drop for Guard { fn drop(&mut self) { self.0.fetch_add(1, Ordering::SeqCst); } }
        let dropped = Arc::new(AtomicUsize::new(0));
        let path = tmp.join("ordinary-file");
        std::fs::write(&path, b"not a socket directory").unwrap();
        assert!(serve_with_monitor(&path, true, Arc::new(AtomicBool::new(false)), || Ok(Some(Guard(dropped.clone())))).is_err());
        assert_eq!(dropped.load(Ordering::SeqCst), 1);
        std::fs::remove_dir_all(tmp).unwrap();
    }

    #[test]
    fn supervisor_role_based_peer_authorization_and_throttling() {
        use crate::daemon::DaemonId;
        let tracker = std::sync::Arc::new(RespawnTracker::new());
        let dev = false;
        let me = 0;
        let console_user = 501;

        let tracker_cl = tracker.clone();
        let handler = move |peer: &crate::ipc::PeerCredentials,
                            req: SupervisorRequest|
              -> EnclaveResult<SupervisorResponse> {
            if let Some(remaining) = tracker_cl.is_throttled(peer.uid) {
                crate::fail!(
                    EAGAIN,
                    "DAEMON_RESPAWN_THROTTLED",
                    "Daemon UID {} is currently throttled for another {} ms",
                    peer.uid,
                    remaining.as_millis()
                );
            }

            Ok(match req {
                SupervisorRequest::Status => {
                    SupervisorResponse::Status(format!("supervisor dev={dev}"))
                }
                SupervisorRequest::EnforceRevocation { .. } => {
                    if peer.uid != DaemonId::SwarmSync.uid()
                        && peer.uid != 0
                        && (!dev || peer.uid != me)
                    {
                        crate::fail!(
                            EPERM,
                            "PERMISSION_DENIED",
                            "EnforceRevocation requires SwarmSync (UID 702) peer identity"
                        );
                    }
                    SupervisorResponse::Enforced(crate::supervisor::RevocationReport {
                        holders: vec![],
                        released: vec![],
                        killed: vec![],
                        refused: vec![],
                        elapsed_ms: 0,
                        scan_ms: 0,
                        complete: true,
                        incomplete: vec![],
                    })
                }
                SupervisorRequest::SessionLocked => {
                    if peer.uid != console_user && peer.uid != 0 && (!dev || peer.uid != me) {
                        crate::fail!(
                            EPERM,
                            "PERMISSION_DENIED",
                            "SessionLocked requires console user intent helper identity"
                        );
                    }
                    SupervisorResponse::WipeCompleted(vec![])
                }
                SupervisorRequest::WipeFanout(_) => {
                    if peer.uid != 0 && (!dev || peer.uid != me) {
                        crate::fail!(
                            EPERM,
                            "PERMISSION_DENIED",
                            "WipeFanout requires root CLI peer identity"
                        );
                    }
                    SupervisorResponse::WipeCompleted(vec![])
                }
                SupervisorRequest::ReportFault(_) => {
                    if peer.uid != 0 && (!dev || peer.uid != me) {
                        crate::fail!(
                            EPERM,
                            "PERMISSION_DENIED",
                            "ReportFault requires root CLI peer identity"
                        );
                    }
                    SupervisorResponse::FaultHandled(
                        crate::quarantine_types::Response::RestartThrottled,
                    )
                }
            })
        };

        // Peer 702 (SwarmSync) cannot call ReportFault or WipeFanout:
        let peer_702 = crate::ipc::PeerCredentials {
            pid: Some(100),
            uid: 702,
            gid: 702,
            audit_token: None,
            code_identity: None,
            tls_channel_binding: None,
        };
        let fault = crate::quarantine_types::FaultReport {
            kind: crate::quarantine_types::FaultKind::Pac,
            fault_addr: 0x1234,
            at_ms: 1000,
        };
        assert!(handler(&peer_702, SupervisorRequest::ReportFault(fault))
            .unwrap_err()
            .is("PERMISSION_DENIED"));
        assert!(handler(
            &peer_702,
            SupervisorRequest::WipeFanout(crate::power::WipeTrigger::SystemSleep)
        )
        .unwrap_err()
        .is("PERMISSION_DENIED"));
        assert!(handler(&peer_702, SupervisorRequest::SessionLocked)
            .unwrap_err()
            .is("PERMISSION_DENIED"));
        assert!(handler(
            &peer_702,
            SupervisorRequest::EnforceRevocation { dev: 1, ino: 2 }
        )
        .is_ok());

        // Console user (501) can call SessionLocked, but NOT WipeFanout or ReportFault:
        let peer_501 = crate::ipc::PeerCredentials {
            pid: Some(200),
            uid: 501,
            gid: 20,
            audit_token: None,
            code_identity: None,
            tls_channel_binding: None,
        };
        assert!(handler(&peer_501, SupervisorRequest::SessionLocked).is_ok());
        assert!(handler(&peer_501, SupervisorRequest::ReportFault(fault))
            .unwrap_err()
            .is("PERMISSION_DENIED"));
        assert!(handler(
            &peer_501,
            SupervisorRequest::WipeFanout(crate::power::WipeTrigger::SystemSleep)
        )
        .unwrap_err()
        .is("PERMISSION_DENIED"));

        // Throttling:
        tracker.record_delay(702, Duration::from_secs(60));
        assert!(handler(&peer_702, SupervisorRequest::Status)
            .unwrap_err()
            .is("DAEMON_RESPAWN_THROTTLED"));
    }
}

/// Restricted held-object protocol version. Legacy bare inode requests cannot
/// authorize production signaling.
pub const HELD_REVOCATION_VERSION: u8 = 1;
/// Signing identity allowed only on the separate snapshot-revocation endpoint.
pub const APFS_BROKER_IDENTIFIER: &str = "com.enterprise.enclave.apfs-broker";
/// Fixed held-object socket, sharing the protected supervisor directory.
pub fn held_socket_path(socket_dir:&std::path::Path)->std::path::PathBuf {
    socket_dir.join(SOCKET_DIR).join("held-v1.sock")
}
/// Kernel-derived object class; callers cannot supply a PID, path or dev/inode.
#[derive(Debug,Clone,Copy,Serialize,Deserialize,PartialEq,Eq)]
pub enum HeldObjectKind {
    /// UID702-owned canonical CAS inode, including an already-truncated inode.
    Canonical,
    /// Root-owned immutable APFS snapshot artifact, original mount still held.
    Snapshot,
}
/// Exactly one read-only regular FD follows this frame. This endpoint serves no
/// supervisor control verbs and does not admit the root CLI's signing identity.
#[derive(Debug,Clone,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HeldRevocationRequest {
    /// Must equal [`HELD_REVOCATION_VERSION`].
    pub version:u8,
    /// Signed content root, bound to the snapshot's kernel mount identity.
    pub root:String,
    /// Role-specific object eligibility.
    pub kind:HeldObjectKind,
}
/// Pure layout calculation; callers supply only the protected selected CAS
/// root (or the unchanged default). Native traversal still verifies every
/// component and the held inode, and derives ownership boundaries from depth.
#[cfg(any(target_os="macos",test))]
fn canonical_object_layout(cas_root:&std::path::Path,root:&str)->EnclaveResult<(String,usize)> {
    let cas_root=crate::deployment::normalized_path(cas_root)
        .map_err(|_|err!(EACCES,"HELD_CANONICAL_IDENTITY"))?;
    let depth=cas_root.components().filter(|c|matches!(c,std::path::Component::Normal(_))).count();
    let expected=cas_root.join("objects").join(root).into_os_string().into_string()
        .map_err(|_|err!(EACCES,"HELD_CANONICAL_IDENTITY"))?;
    Ok((expected,depth))
}
fn validate_held_object(file:&std::fs::File,req:&HeldRevocationRequest,dev_mode:bool)->EnclaveResult<(u64,u64)> {
    use std::os::{fd::AsRawFd,unix::fs::MetadataExt};
    if req.version!=HELD_REVOCATION_VERSION || req.root.len()!=64
        || !req.root.bytes().all(|b|b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        fail!(EINVAL,"HELD_REVOCATION_PROTOCOL");
    }
    let m=file.metadata().map_err(|_|err!(EIO,"HELD_OBJECT_STAT"))?;
    let flags=unsafe {libc::fcntl(file.as_raw_fd(),libc::F_GETFL)};
    if flags<0 || flags&libc::O_ACCMODE!=libc::O_RDONLY || !m.is_file() || m.nlink()>1 {
        fail!(EACCES,"HELD_OBJECT_ELIGIBILITY");
    }
    let owner=if dev_mode {crate::ipc::geteuid()} else if req.kind==HeldObjectKind::Snapshot {0} else {crate::daemon::DaemonId::SwarmSync.uid()};
    let mode=if req.kind==HeldObjectKind::Snapshot {0o400}else{0o444};
    if m.uid()!=owner || m.mode()&0o777!=mode {fail!(EACCES,"HELD_OBJECT_ELIGIBILITY");}
    #[cfg(target_os="linux")]
    if flags&libc::O_PATH!=0 {fail!(EACCES,"HELD_OBJECT_ELIGIBILITY");}
    #[cfg(target_os="macos")]
    if !dev_mode && req.kind==HeldObjectKind::Canonical {
        let mut path=[0i8;libc::PATH_MAX as usize];
        if unsafe{libc::fcntl(file.as_raw_fd(),libc::F_GETPATH,path.as_mut_ptr())}!=0 {fail!(EACCES,"HELD_CANONICAL_IDENTITY");}
        let actual=path.iter().take_while(|b|**b!=0).map(|b|*b as u8).collect::<Vec<_>>();
        let cas_root=crate::deployment::selected().map(|checked|checked.target().layout.cas_store_root.as_path())
            .unwrap_or_else(||std::path::Path::new("/opt/enterprise/enclave/cas"));
        let (expected,cas_depth)=canonical_object_layout(cas_root,&req.root)?;
        if actual!=expected.as_bytes() || m.nlink()!=1 {fail!(EACCES,"HELD_CANONICAL_IDENTITY");}
        // Check every component without following links; the held FD must
        // still be the exclusively named canonical inode, including on retry.
        let mut directory=std::fs::File::open("/").map_err(|_|err!(EACCES,"HELD_CANONICAL_IDENTITY"))?;
        for (index,name) in expected.split('/').filter(|s|!s.is_empty()).enumerate() {
            let final_component=index==cas_depth+1;
            let name=std::ffi::CString::new(name).map_err(|_|err!(EACCES,"HELD_CANONICAL_IDENTITY"))?;
            let fd=unsafe{libc::openat(directory.as_raw_fd(),name.as_ptr(),libc::O_RDONLY|libc::O_NOFOLLOW|libc::O_NONBLOCK|libc::O_CLOEXEC|if final_component{0}else{libc::O_DIRECTORY})};
            if fd<0 {fail!(EACCES,"HELD_CANONICAL_IDENTITY");}
            use std::os::fd::FromRawFd;
            directory=unsafe{std::fs::File::from_raw_fd(fd)};
            let part=directory.metadata().map_err(|_|err!(EACCES,"HELD_CANONICAL_IDENTITY"))?;
            if final_component {if (part.dev(),part.ino())!=(m.dev(),m.ino()) {fail!(EACCES,"HELD_CANONICAL_IDENTITY");}}
            else if part.mode()&0o022!=0 || part.uid()!=if index<cas_depth-1{0}else{owner} {fail!(EACCES,"HELD_CANONICAL_IDENTITY");}
        }
    }
    #[cfg(target_os="macos")]
    if !dev_mode && req.kind==HeldObjectKind::Snapshot {
        let mut fs=std::mem::MaybeUninit::<libc::statfs>::uninit();
        if unsafe{libc::fstatfs(file.as_raw_fd(),fs.as_mut_ptr())}!=0 {fail!(EACCES,"HELD_SNAPSHOT_IDENTITY");}
        let fs=unsafe{fs.assume_init()};
        let field=|v:&[libc::c_char]|v.iter().take_while(|b|**b!=0).map(|b|*b as u8).collect::<Vec<_>>();
        let required=(libc::MNT_RDONLY|libc::MNT_NOEXEC|libc::MNT_NOSUID|libc::MNT_NODEV) as u32;
        let source=field(&fs.f_mntfromname);
        if field(&fs.f_fstypename)!=b"apfs" || fs.f_flags&required!=required
            || !source.starts_with(format!("cas-{}@/dev/disk",req.root).as_bytes()) {
            fail!(EACCES,"HELD_SNAPSHOT_IDENTITY");
        }
        let mut path=[0i8;libc::PATH_MAX as usize];
        if unsafe{libc::fcntl(file.as_raw_fd(),libc::F_GETPATH,path.as_mut_ptr())}!=0
            || !field(&path).ends_with(format!("/artifacts/{}",req.root).as_bytes()) {
            fail!(EACCES,"HELD_SNAPSHOT_IDENTITY");
        }
    }
    #[cfg(not(target_os="macos"))]
    if !dev_mode {fail!(ENOSYS,"HELD_REVOCATION_NATIVE_REQUIRED");}
    Ok((m.dev(),m.ino()))
}
fn held_peer_policy(dev_mode:bool)->EnclaveResult<crate::ipc::PeerPolicy> {
    use crate::{ipc,daemon::DaemonId,codesign::CodeRequirement};
    let me=ipc::geteuid();
    Ok(if dev_mode {ipc::PeerPolicy::allow([me])}else{
        // Separate root endpoint avoids replacing the CLI's UID0 pin or
        // granting the broker WipeFanout/ReportFault authority.
        let policy=ipc::PeerPolicy::allow([]).require(DaemonId::SwarmSync.uid(),CodeRequirement::daemon(DaemonId::SwarmSync));
        if crate::codesign::pins::require(APFS_BROKER_IDENTIFIER).is_ok() {
            policy.require(0,CodeRequirement::pinned_boundary(APFS_BROKER_IDENTIFIER)?)
        }else{policy}
    })
}
fn held_handler(dev_mode:bool,me:u32)->std::sync::Arc<impl Fn(&crate::ipc::PeerCredentials,HeldRevocationRequest,
    Vec<std::os::fd::OwnedFd>)->EnclaveResult<RevocationReport>+Send+Sync+'static> {
    use crate::{ipc,daemon::DaemonId};
    std::sync::Arc::new(move|peer:&ipc::PeerCredentials,request:HeldRevocationRequest,mut fds:Vec<std::os::fd::OwnedFd>| {
        if !dev_mode && ((request.kind==HeldObjectKind::Snapshot && peer.uid!=0)
            || (request.kind==HeldObjectKind::Canonical && peer.uid!=DaemonId::SwarmSync.uid())) {
            fail!(EPERM,"HELD_OBJECT_ROLE");
        }
        if fds.len()!=1 {fail!(EINVAL,"HELD_OBJECT_FD_COUNT");}
        let file=std::fs::File::from(fds.pop().unwrap());
        let (device,inode)=validate_held_object(&file,&request,dev_mode)?;
        let issuer=peer.pid.and_then(crate::holder_observation::Process::capture)
            .filter(|p|p.matches_peer(peer)).ok_or_else(||err!(EACCES,"HELD_ISSUER_IDENTITY"))?;
        let report=enforce_observed(device,inode,RELEASE_GRACE,&|h|if dev_mode{h.pid>1&&h.uid==me}else{production_may_signal(h)},true,Some(&issuer));
        // Keep the actual held inode alive until census, signals and rescan
        // finish. Incomplete reports stay explicit; callers retain cleanup.
        drop(file);Ok(report)
    })
}
fn held_fd_classifier()->impl Fn(&HeldRevocationRequest)->Option<usize>+Send+Sync+'static {
    |_:&HeldRevocationRequest|Some(1)
}
fn serve_held_listener(listener:std::os::unix::net::UnixListener,dev_mode:bool,policy:crate::ipc::PeerPolicy,
    stop:std::sync::Arc<std::sync::atomic::AtomicBool>)->EnclaveResult<()> {
    use crate::ipc;
    let me=ipc::geteuid();
    let handler=held_handler(dev_mode,me);
    ipc::serve_with_fds(listener,policy,handler,std::sync::Arc::new(held_fd_classifier()),stop)
}
/// Request revocation of the actual object, over the independently authenticated
/// restricted endpoint. `legacy_socket` names the existing supervisor socket;
/// its sibling `held-v1.sock` is used, preserving current configuration routing.
pub fn request_held_enforcement(legacy_socket:&std::path::Path,dev_mode:bool,
    file:&std::fs::File,root:&str,kind:HeldObjectKind)->EnclaveResult<RevocationReport> {
    use std::os::fd::AsRawFd;
    let path=legacy_socket.with_file_name("held-v1.sock");
    let mut client=if dev_mode {crate::ipc::Client::connect(&path,crate::ipc::geteuid())?}
        else {crate::ipc::Client::connect_verified(&path,0,Some(&crate::codesign::CodeRequirement::ctl()))?};
    client.set_timeout(Some(Duration::from_secs(10)))?;
    client.call_with_fds(&HeldRevocationRequest{version:HELD_REVOCATION_VERSION,root:root.to_owned(),kind},&[file.as_raw_fd()])
}

#[cfg(all(test,target_os="linux"))]
mod phase1_holder_tests {
    use super::*;
    use std::{io::{BufRead,BufReader},os::unix::fs::PermissionsExt,process::{Command,Stdio}};
    struct Child(std::process::Child);
    impl Drop for Child {fn drop(&mut self){let _=self.0.kill();let _=self.0.wait();}}
    #[test]
    fn phase1_held_protocol_finds_mmap_after_fd_close_and_rejects_mutable_or_extra_fds() {
        let mesh=std::path::PathBuf::from(format!("target/p1h{:08x}",crate::rng::u64() as u32));
        std::fs::create_dir_all(&mesh).unwrap();let path=mesh.join("snapshot");
        std::fs::write(&path,b"immutable mapped artifact").unwrap();std::fs::set_permissions(&path,std::fs::Permissions::from_mode(0o400)).unwrap();
        let path=std::fs::canonicalize(path).unwrap();
        let mut child=Child(Command::new("python3").args(["-u","-c",r#"import mmap,os,signal,sys,time
f=open(sys.argv[1],'rb'); m=mmap.mmap(f.fileno(),0,access=mmap.ACCESS_READ);f.close()
signal.signal(signal.SIGHUP,signal.SIG_IGN)
print('READY',flush=True);time.sleep(30)
"#]).arg(&path).stdout(Stdio::piped()).spawn().unwrap());
        let mut ready=String::new();BufReader::new(child.0.stdout.take().unwrap()).read_line(&mut ready).unwrap();assert_eq!(ready.trim(),"READY");
        let held=std::fs::File::open(&path).unwrap();let (device,inode)=inode_of(&path).unwrap();
        assert!(holders(device,inode).iter().any(|h|h.pid==child.0.id() as i32));
        let stop=std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));let base=mesh.clone();let stopped=stop.clone();
        let server=std::thread::spawn(move||serve(&base,true,stopped));
        let socket=held_socket_path(&mesh);let deadline=Instant::now()+Duration::from_secs(3);
        while !socket.exists() && Instant::now()<deadline {std::thread::sleep(Duration::from_millis(5));}
        let legacy=socket_path(&mesh);
        let report=request_held_enforcement(&legacy,true,&held,&"ab".repeat(32),HeldObjectKind::Snapshot).unwrap();
        assert!(report.killed.contains(&(child.0.id() as i32)),"{report:?}");assert!(child.0.wait().unwrap().success()==false);
        let mut client=crate::ipc::Client::connect(&socket,crate::ipc::geteuid()).unwrap();
        let req=HeldRevocationRequest{version:HELD_REVOCATION_VERSION,root:"ab".repeat(32),kind:HeldObjectKind::Snapshot};
        use std::os::fd::AsRawFd;
        assert!(client.call_with_fds::<_,RevocationReport>(&req,&[held.as_raw_fd(),held.as_raw_fd()]).is_err());drop(client);
        std::fs::set_permissions(&path,std::fs::Permissions::from_mode(0o600)).unwrap();
        let writable=std::fs::File::options().read(true).write(true).open(&path).unwrap();
        std::fs::set_permissions(&path,std::fs::Permissions::from_mode(0o400)).unwrap();
        assert!(request_held_enforcement(&legacy,true,&writable,&req.root,req.kind).unwrap_err().is("HELD_OBJECT_ELIGIBILITY"));
        let mut bad=req;bad.version=0;
        let mut client=crate::ipc::Client::connect(&socket,crate::ipc::geteuid()).unwrap();
        assert!(client.call_with_fds::<_,RevocationReport>(&bad,&[held.as_raw_fd()]).unwrap_err().is("HELD_REVOCATION_PROTOCOL"));drop(client);
        stop.store(true,std::sync::atomic::Ordering::SeqCst);server.join().unwrap().unwrap();std::fs::remove_dir_all(mesh).unwrap();
    }
}
