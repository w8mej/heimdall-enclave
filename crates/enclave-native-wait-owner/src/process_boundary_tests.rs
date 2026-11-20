//! Test-only kernel parent boundary. This protocol is absent from normal main.
//! The public grandchild PID is used solely for WNOWAIT observations;
//! only each process's original Child may be reaped or killed by its owner.
use super::*;
use std::{
    io::{Error, ErrorKind, Write},
    os::{
        fd::{FromRawFd, OwnedFd},
        unix::net::UnixStream,
    },
    process::ExitStatus,
    sync::atomic::{AtomicUsize, Ordering},
};

const ENTRY_KEY: &str = "depot_PRIVATE_WAIT_OWNER_BOUNDARY_V2";
const END_KEY: &str = "depot_PRIVATE_WAIT_OWNER_BOUNDARY_END_NS";
const WORKER_SELECTOR: &str =
    "strict_command::tests::process_boundary::separate_owner_subprocess_worker";
const COMPETING_SELECTOR: &str =
    "strict_command::tests::process_boundary::same_process_competing_wait_worker";
const BUDGET_NS: u64 = 15_000_000_000;
const TEARDOWN_RESERVE_NS: u64 = 2_000_000_000;
const EXIT: i32 = 23;
static UNKNOWN_FIXTURE_OWNERS: AtomicUsize = AtomicUsize::new(0);

fn error(kind: ErrorKind, reason: &'static str) -> Error {
    Error::new(kind, reason)
}
fn require(condition: bool, reason: &'static str) -> io::Result<()> {
    if condition {
        Ok(())
    } else {
        Err(error(ErrorKind::InvalidData, reason))
    }
}
fn clock_ns() -> io::Result<u64> {
    let mut time = std::mem::MaybeUninit::<libc::timespec>::zeroed();
    // SAFETY: output is valid writable storage; this is the shared test clock.
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, time.as_mut_ptr()) } != 0 {
        return Err(Error::last_os_error());
    }
    let time = unsafe { time.assume_init() };
    let seconds = u64::try_from(time.tv_sec)
        .map_err(|_| error(ErrorKind::InvalidData, "negative fixture clock"))?;
    let nanos = u64::try_from(time.tv_nsec)
        .map_err(|_| error(ErrorKind::InvalidData, "negative fixture nanoseconds"))?;
    require(nanos < 1_000_000_000, "invalid fixture nanoseconds")?;
    seconds
        .checked_mul(1_000_000_000)
        .and_then(|value| value.checked_add(nanos))
        .ok_or_else(|| error(ErrorKind::InvalidData, "fixture clock overflow"))
}

/// One controller-created absolute test endpoint, inherited unchanged by worker.
/// This fixture-only clock encoding supplies no production deadline/admission ABI.
#[derive(Clone, Copy)]
struct End(u64);
impl End {
    fn create() -> io::Result<Self> {
        clock_ns()?
            .checked_add(BUDGET_NS)
            .map(Self)
            .ok_or_else(|| error(ErrorKind::InvalidData, "fixture endpoint overflow"))
    }
    fn inherited() -> io::Result<Self> {
        let value = std::env::var(END_KEY)
            .map_err(|_| error(ErrorKind::InvalidInput, "missing fixture endpoint"))?
            .parse::<u64>()
            .map_err(|_| error(ErrorKind::InvalidInput, "invalid fixture endpoint"))?;
        let now = clock_ns()?;
        require(
            value > now && value - now <= BUDGET_NS,
            "stale or unbounded fixture endpoint",
        )?;
        Ok(Self(value))
    }
    fn current(self) -> io::Result<()> {
        if clock_ns()? < self.0 {
            Ok(())
        } else {
            Err(error(ErrorKind::TimedOut, "original fixture endpoint"))
        }
    }
    fn work(self) -> Self {
        Self(self.0.saturating_sub(TEARDOWN_RESERVE_NS))
    }
    fn instant_within(self, cap: Duration) -> io::Result<Instant> {
        // Capture Instant BEFORE reading the shared clock: conversion cannot
        // grant a fresh cap after measuring the remaining original budget.
        let anchor = Instant::now();
        let remaining = self
            .0
            .checked_sub(clock_ns()?)
            .filter(|value| *value > 0)
            .ok_or_else(|| error(ErrorKind::TimedOut, "original fixture work endpoint"))?;
        anchor
            .checked_add(Duration::from_nanos(remaining).min(cap))
            .ok_or_else(|| {
                error(
                    ErrorKind::InvalidData,
                    "fixture Instant conversion overflow",
                )
            })
    }
    fn pause(self) -> io::Result<()> {
        self.current()?;
        std::thread::sleep(Duration::from_millis(1));
        self.current()
    }
}

fn write_bytes(writer: &mut impl Write, bytes: &[u8], end: End) -> io::Result<()> {
    let mut offset = 0;
    while offset < bytes.len() {
        end.current()?;
        match writer.write(&bytes[offset..]) {
            Ok(0) => return Err(error(ErrorKind::WriteZero, "fixture channel write zero")),
            Ok(count) => offset += count,
            Err(fault) if fault.kind() == ErrorKind::Interrupted => continue,
            Err(fault) if fault.kind() == ErrorKind::WouldBlock => end.pause()?,
            Err(fault) => return Err(fault),
        }
    }
    end.current()
}
fn read_bytes(reader: &mut impl Read, bytes: &mut [u8], end: End) -> io::Result<()> {
    let mut offset = 0;
    while offset < bytes.len() {
        end.current()?;
        match reader.read(&mut bytes[offset..]) {
            Ok(0) => return Err(error(ErrorKind::UnexpectedEof, "fixture channel closed")),
            Ok(count) => offset += count,
            Err(fault) if fault.kind() == ErrorKind::Interrupted => continue,
            Err(fault) if fault.kind() == ErrorKind::WouldBlock => end.pause()?,
            Err(fault) => return Err(fault),
        }
    }
    end.current()
}
fn require_eof(reader: &mut impl Read, end: End) -> io::Result<()> {
    let mut byte = [0];
    loop {
        end.current()?;
        match reader.read(&mut byte) {
            Ok(0) => return end.current(),
            Ok(_) => {
                return Err(error(
                    ErrorKind::InvalidData,
                    "unexpected synthetic child output",
                ))
            }
            Err(fault) if fault.kind() == ErrorKind::Interrupted => continue,
            Err(fault) if fault.kind() == ErrorKind::WouldBlock => end.pause()?,
            Err(fault) => return Err(fault),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
enum Phase {
    Hello = 1,
    Create = 2,
    Live = 3,
    Release = 4,
    Terminal = 5,
    Reobserve = 6,
    Held = 7,
    Reap = 8,
    Reaped = 9,
    Finish = 10,
    Done = 11,
    CompetingRefused = 12,
}
#[derive(Clone, Copy, Debug)]
struct Frame {
    phase: u32,
    pid: i32,
    value: i32,
}
impl Frame {
    fn new(phase: Phase, pid: i32, value: i32) -> Self {
        Self {
            phase: phase as u32,
            pid,
            value,
        }
    }
    fn expect(self, phase: Phase, pid: i32, value: i32) -> io::Result<()> {
        require(
            self.phase == phase as u32 && self.pid == pid && self.value == value,
            "fixture phase or original identity mismatch",
        )
    }
    fn send(self, link: &mut UnixStream, end: End) -> io::Result<()> {
        let mut bytes = [0u8; 16];
        bytes[..4].copy_from_slice(b"WOB2");
        bytes[4..8].copy_from_slice(&self.phase.to_le_bytes());
        bytes[8..12].copy_from_slice(&self.pid.to_le_bytes());
        bytes[12..].copy_from_slice(&self.value.to_le_bytes());
        write_bytes(link, &bytes, end)
    }
    fn read(link: &mut UnixStream, end: End) -> io::Result<Self> {
        let mut bytes = [0u8; 16];
        read_bytes(link, &mut bytes, end)?;
        require(&bytes[..4] == b"WOB2", "fixture protocol magic")?;
        Ok(Self {
            phase: u32::from_le_bytes(bytes[4..8].try_into().unwrap()),
            pid: i32::from_le_bytes(bytes[8..12].try_into().unwrap()),
            value: i32::from_le_bytes(bytes[12..].try_into().unwrap()),
        })
    }
}

struct Original {
    child: Option<Child>,
    end: End,
    status: Option<ExitStatus>,
    lost_wait: bool,
    kill_attempted: bool,
}
struct FixtureChild {
    original: Option<Box<Original>>,
}
impl FixtureChild {
    fn spawn(mut command: Command, end: End) -> io::Result<Self> {
        end.work().current()?;
        let mut owned = Self {
            original: Some(Box::new(Original {
                child: None,
                end,
                status: None,
                lost_wait: false,
                kill_attempted: false,
            })),
        };
        let child = command.spawn()?;
        owned.original.as_mut().unwrap().child = Some(child);
        Ok(owned)
    }
    fn child(&self) -> &Child {
        self.original.as_ref().unwrap().child.as_ref().unwrap()
    }
    fn child_mut(&mut self) -> &mut Child {
        self.original.as_mut().unwrap().child.as_mut().unwrap()
    }
    fn id(&self) -> io::Result<i32> {
        let pid = i32::try_from(self.child().id())
            .map_err(|_| error(ErrorKind::InvalidData, "fixture PID overflow"))?;
        require(pid > 1, "invalid fixture child PID")?;
        Ok(pid)
    }
    fn poll(&mut self) -> io::Result<Option<ExitStatus>> {
        let original = self.original.as_mut().unwrap();
        if let Some(status) = original.status {
            return Ok(Some(status));
        }
        match original.child.as_mut().unwrap().try_wait() {
            Ok(Some(status)) => {
                original.status = Some(status);
                Ok(Some(status))
            }
            Ok(None) => Ok(None),
            Err(fault) => {
                original.lost_wait = true;
                Err(fault)
            }
        }
    }
    fn alive(&mut self, end: End) -> io::Result<()> {
        end.current()?;
        require(
            self.poll()?.is_none(),
            "original fixture owner exited during a gated observation",
        )?;
        end.current()
    }
    fn reap(&mut self, end: End) -> io::Result<ExitStatus> {
        loop {
            end.current()?;
            if let Some(status) = self.poll()? {
                end.current()?;
                return Ok(status);
            }
            end.pause()?;
        }
    }
    fn snapshot(&self) -> (usize, i32, [i32; 3]) {
        let original = self.original.as_ref().unwrap();
        let child = self.child();
        (
            (&**original) as *const Original as usize,
            child.id() as i32,
            [
                child.stdin.as_ref().unwrap().as_raw_fd(),
                child.stdout.as_ref().unwrap().as_raw_fd(),
                child.stderr.as_ref().unwrap().as_raw_fd(),
            ],
        )
    }
}
impl Drop for FixtureChild {
    fn drop(&mut self) {
        let Some(mut original)=self.original.take() else {return;};
        if original.child.is_none() || original.status.is_some() {
            return;
        }
        if original.lost_wait || original.end.current().is_err() {
            UNKNOWN_FIXTURE_OWNERS.fetch_add(1, Ordering::SeqCst);
            std::mem::forget(original);
            return;
        }
        // Close only the exact original stdin pipe. The fixed synthetic shell
        // exits on EOF. Controller closes its original socket before this Drop.
        // No learned PID/group is ever signalled and no blocking wait is used.
        let _ = original.child.as_mut().unwrap().stdin.take();
        loop {
            if original.lost_wait || original.end.current().is_err() {
                break;
            }
            match original.child.as_mut().unwrap().try_wait() {
                Ok(Some(status)) => {
                    original.status = Some(status);
                    return;
                }
                Ok(None) => {}
                Err(_) => {
                    original.lost_wait = true;
                    break;
                }
            }
            // One original-Child kill, only while the same leader remains
            // unreaped and only within the original teardown endpoint. Nothing
            // signals after a successful reap or after an ECHILD/unknown wait.
            let now = match clock_ns() {
                Ok(now) => now,
                Err(_) => break,
            };
            if now >= original.end.0 {
                break;
            }
            if !original.kill_attempted
                && now >= original.end.0.saturating_sub(TEARDOWN_RESERVE_NS / 2)
            {
                original.kill_attempted = true;
                let _ = original.child.as_mut().unwrap().kill();
            }
            if original.end.pause().is_err() {
                break;
            }
        }
        // Unknown cleanup remains failure. Preserve the intact original frame
        // instead of dropping/reconstructing its Child/pipes or inventing retry.
        UNKNOWN_FIXTURE_OWNERS.fetch_add(1, Ordering::SeqCst);
        std::mem::forget(original);
    }
}

struct Controller {
    link: Option<UnixStream>,
    owner: FixtureChild,
}
impl Drop for Controller {
    fn drop(&mut self) {
        self.link.take();
    } // EOF requests owner-side bounded teardown first.
}
fn inherited_link() -> io::Result<UnixStream> {
    // SAFETY: duplicate the actual stdin descriptor installed by the controller,
    // creating a separately owned CLOEXEC descriptor, never adopting a report FD.
    let fd = unsafe { libc::fcntl(libc::STDIN_FILENO, libc::F_DUPFD_CLOEXEC, 3) };
    if fd < 0 {
        return Err(Error::last_os_error());
    }
    let descriptor = unsafe { OwnedFd::from_raw_fd(fd) };
    let link = UnixStream::from(descriptor);
    link.peer_addr()?;
    link.set_nonblocking(true)?;
    Ok(link)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Terminal {
    pid: i32,
    status: i32,
    code: i32,
}
fn observe_owned(child: &Child, end: End) -> io::Result<Option<Terminal>> {
    end.current()?;
    let mut info = std::mem::MaybeUninit::<libc::siginfo_t>::zeroed();
    // SAFETY: positive PID comes from this exact retained Child; WNOWAIT never reaps.
    let result = unsafe {
        libc::waitid(
            libc::P_PID,
            child.id() as libc::id_t,
            info.as_mut_ptr(),
            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
        )
    };
    let fault = if result < 0 {
        Some(Error::last_os_error())
    } else {
        None
    };
    if let Some(fault) = fault {
        return Err(fault);
    }
    end.current()?;
    let info = unsafe { info.assume_init() };
    if info.si_signo == 0 {
        return Ok(None);
    }
    require(
        info.si_signo == libc::SIGCHLD && info.si_code == libc::CLD_EXITED,
        "unexpected owner terminal event",
    )?;
    // SAFETY: successful nonzero SIGCHLD/CLD_EXITED event initializes these fields.
    let terminal = Terminal {
        pid: unsafe { info.si_pid() },
        status: unsafe { info.si_status() },
        code: info.si_code,
    };
    require(
        terminal.pid == child.id() as i32,
        "owner observed another child",
    )?;
    Ok(Some(terminal))
}
fn wait_owned_terminal(child: &Child, end: End) -> io::Result<Terminal> {
    loop {
        if let Some(terminal) = observe_owned(child, end)? {
            return Ok(terminal);
        }
        end.pause()?;
    }
}
fn nonchild_wnowait_is_echild(pid: i32, end: End) -> io::Result<()> {
    end.current()?;
    require(pid > 1, "invalid public fixture PID")?;
    let mut info = std::mem::MaybeUninit::<libc::siginfo_t>::zeroed();
    // SAFETY: output storage is valid; WNOWAIT excludes status consumption.
    let result = unsafe {
        libc::waitid(
            libc::P_PID,
            pid as libc::id_t,
            info.as_mut_ptr(),
            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
        )
    };
    let fault = if result < 0 {
        Error::last_os_error().raw_os_error()
    } else {
        None
    };
    require(
        result == -1 && fault == Some(libc::ECHILD),
        "controller waitid did not return ECHILD",
    )?;
    end.current()
}

fn run_owner() -> io::Result<()> {
    require(
        std::env::var(ENTRY_KEY).as_deref() == Ok("owner-v2"),
        "fixture worker requires controller invocation",
    )?;
    verify_child_policy()
        .map_err(|_| error(ErrorKind::Unsupported, "fixture requires default SIGCHLD"))?;
    let end = End::inherited()?;
    let work = end.work();
    let mut link = inherited_link()?;
    let me = i32::try_from(std::process::id())
        .map_err(|_| error(ErrorKind::InvalidData, "owner PID overflow"))?;
    Frame::new(Phase::Hello, me, 0).send(&mut link, work)?;
    Frame::read(&mut link, work)?.expect(Phase::Create, me, 0)?;
    let mut command = Command::new("/bin/sh");
    command.args(["-c","printf 'READY\\n'; IFS= read -r token || exit 91; case \"$token\" in GO) printf OUT; printf ERR >&2; exit 23;; *) exit 92;; esac"])
        .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).process_group(0);
    let mut child = FixtureChild::spawn(command, end)?;
    let pid = child.id()?;
    let original = child.snapshot();
    nonblocking(child.child().stdin.as_ref().unwrap().as_raw_fd())
        .map_err(|_| error(ErrorKind::Other, "fixture stdin flags"))?;
    nonblocking(child.child().stdout.as_ref().unwrap().as_raw_fd())
        .map_err(|_| error(ErrorKind::Other, "fixture stdout flags"))?;
    nonblocking(child.child().stderr.as_ref().unwrap().as_raw_fd())
        .map_err(|_| error(ErrorKind::Other, "fixture stderr flags"))?;
    let mut ready = [0u8; 6];
    read_bytes(child.child_mut().stdout.as_mut().unwrap(), &mut ready, work)?;
    require(
        &ready == b"READY\n",
        "synthetic child did not reach live phase",
    )?;
    require(
        observe_owned(child.child(), work)?.is_none(),
        "synthetic child was not live",
    )?;
    Frame::new(Phase::Live, pid, 0).send(&mut link, work)?;
    // The controller's live ECHILD observations happen before this explicit gate.
    Frame::read(&mut link, work)?.expect(Phase::Release, pid, 0)?;
    require(
        child.snapshot() == original,
        "live original Child or pipe identity changed",
    )?;
    require(
        observe_owned(child.child(), work)?.is_none(),
        "live child exited before release",
    )?;
    write_bytes(child.child_mut().stdin.as_mut().unwrap(), b"GO\n", work)?;
    let terminal = wait_owned_terminal(child.child(), work)?;
    require(
        terminal.status == EXIT,
        "unexpected synthetic terminal status",
    )?;
    Frame::new(Phase::Terminal, pid, terminal.status).send(&mut link, work)?;
    Frame::read(&mut link, work)?.expect(Phase::Reobserve, pid, EXIT)?;
    require(
        child.snapshot() == original,
        "terminal original Child or pipe identity changed",
    )?;
    require(
        observe_owned(child.child(), work)? == Some(terminal),
        "WNOWAIT terminal event was consumed or changed",
    )?;
    Frame::new(Phase::Held, pid, EXIT).send(&mut link, work)?;
    // The owner cannot reap until the controller finishes both terminal checks.
    Frame::read(&mut link, work)?.expect(Phase::Reap, pid, EXIT)?;
    require(
        observe_owned(child.child(), work)? == Some(terminal),
        "original terminal event lost before reap",
    )?;
    let status = child.reap(work)?;
    require(
        status.code() == Some(EXIT),
        "owner reaped wrong original exit",
    )?;
    require(
        child.snapshot() == original,
        "same original handles not retained through reap",
    )?;
    let mut out = [0u8; 3];
    read_bytes(child.child_mut().stdout.as_mut().unwrap(), &mut out, work)?;
    require(&out == b"OUT", "synthetic stdout mismatch")?;
    require_eof(child.child_mut().stdout.as_mut().unwrap(), work)?;
    let mut err = [0u8; 3];
    read_bytes(child.child_mut().stderr.as_mut().unwrap(), &mut err, work)?;
    require(&err == b"ERR", "synthetic stderr mismatch")?;
    require_eof(child.child_mut().stderr.as_mut().unwrap(), work)?;
    Frame::new(Phase::Reaped, pid, EXIT).send(&mut link, work)?;
    Frame::read(&mut link, work)?.expect(Phase::Finish, pid, EXIT)?;
    require(
        child.original.as_ref().unwrap().status.is_some(),
        "original reap fact missing",
    )?;
    require(
        !child.original.as_ref().unwrap().kill_attempted,
        "normal owner path signalled child",
    )?;
    drop(child);
    require(
        UNKNOWN_FIXTURE_OWNERS.load(Ordering::SeqCst) == 0,
        "owner teardown unknown",
    )?;
    Frame::new(Phase::Done, pid, EXIT).send(&mut link, work)
}

fn run_controller() -> io::Result<()> {
    let end = End::create()?;
    let work = end.work();
    let (link, inherited) = UnixStream::pair()?;
    link.set_nonblocking(true)?;
    inherited.set_nonblocking(true)?;
    let descriptor: OwnedFd = inherited.into();
    let mut command = Command::new(std::env::current_exe()?);
    command
        .args([
            "--exact",
            WORKER_SELECTOR,
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(ENTRY_KEY, "owner-v2")
        .env(END_KEY, end.0.to_string())
        .stdin(Stdio::from(descriptor))
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let owner = FixtureChild::spawn(command, end)?;
    let original_owner = owner.id()?;
    let mut controller = Controller {
        link: Some(link),
        owner,
    };
    Frame::read(controller.link.as_mut().unwrap(), work)?.expect(
        Phase::Hello,
        original_owner,
        0,
    )?;
    Frame::new(Phase::Create, original_owner, 0).send(controller.link.as_mut().unwrap(), work)?;
    let live = Frame::read(controller.link.as_mut().unwrap(), work)?;
    require(
        live.phase == Phase::Live as u32
            && live.pid > 1
            && live.pid != original_owner
            && live.value == 0,
        "invalid live grandchild report",
    )?;
    controller.owner.alive(work)?;
    nonchild_wnowait_is_echild(live.pid, work)?;
    controller.owner.alive(work)?;
    Frame::new(Phase::Release, live.pid, 0).send(controller.link.as_mut().unwrap(), work)?;
    Frame::read(controller.link.as_mut().unwrap(), work)?.expect(
        Phase::Terminal,
        live.pid,
        EXIT,
    )?;
    controller.owner.alive(work)?;
    nonchild_wnowait_is_echild(live.pid, work)?;
    controller.owner.alive(work)?;
    Frame::new(Phase::Reobserve, live.pid, EXIT).send(controller.link.as_mut().unwrap(), work)?;
    Frame::read(controller.link.as_mut().unwrap(), work)?.expect(Phase::Held, live.pid, EXIT)?;
    controller.owner.alive(work)?;
    nonchild_wnowait_is_echild(live.pid, work)?;
    controller.owner.alive(work)?;
    Frame::new(Phase::Reap, live.pid, EXIT).send(controller.link.as_mut().unwrap(), work)?;
    Frame::read(controller.link.as_mut().unwrap(), work)?.expect(Phase::Reaped, live.pid, EXIT)?;
    // The numeric grandchild identity is unpinned after its owner's reap. Do
    // not issue another wait or signal using that number after this boundary.
    controller.owner.alive(work)?;
    Frame::new(Phase::Finish, live.pid, EXIT).send(controller.link.as_mut().unwrap(), work)?;
    Frame::read(controller.link.as_mut().unwrap(), work)?.expect(Phase::Done, live.pid, EXIT)?;
    let status = controller.owner.reap(work)?;
    require(status.success(), "fixture owner subprocess failed")?;
    require(
        !controller.owner.original.as_ref().unwrap().kill_attempted,
        "normal controller path signalled owner",
    )?;
    drop(controller);
    require(
        UNKNOWN_FIXTURE_OWNERS.load(Ordering::SeqCst) == 0,
        "controller teardown unknown",
    )?;
    println!("WAIT_OWNER_BOUNDARY_V2 live=ECHILD terminal=ECHILD repeated_wnowait=HELD owner_exit=23 controller_owner_exit=0 same_original_handles=true");
    Ok(())
}

#[test]
fn separate_owner_process_keeps_live_and_terminal_child_waits_exclusive_to_original_parent() {
    run_controller().expect("gated separate-owner kernel boundary fixture");
}

#[test]
#[ignore = "Internal fixture worker; only controller supplies original IPC and endpoint"]
fn separate_owner_subprocess_worker() {
    run_owner().expect("separate-owner fixture worker");
}

#[test]
fn same_process_raw_wait_consumes_original_status_and_strict_owner_refuses_without_signal() {
    run_competing_controller().expect("same-process competing wait negative control");
}

fn run_competing_owner() -> io::Result<()> {
    require(
        std::env::var(ENTRY_KEY).as_deref() == Ok("competing-v2"),
        "competing worker requires controller invocation",
    )?;
    verify_child_policy()
        .map_err(|_| error(ErrorKind::Unsupported, "fixture requires default SIGCHLD"))?;
    let end = End::inherited()?;
    let work = end.work();
    let mut link = inherited_link()?;
    let me = i32::try_from(std::process::id())
        .map_err(|_| error(ErrorKind::InvalidData, "competing owner PID overflow"))?;
    Frame::new(Phase::Hello, me, 0).send(&mut link, work)?;
    Frame::read(&mut link, work)?.expect(Phase::Create, me, 0)?;
    // This exact isolated harness runs one fixture. No other child is created
    // in this process after the raw wait removes its sole original child pin.
    // Concurrent outer-harness fixtures therefore cannot create a same-parent
    // replacement PID that this intentional contract violation could observe.
    work.current()?;
    let retention = StrictRetention::new();
    let strict_end = work.instant_within(COMMAND_LIMIT)?;
    let mut attempt = StrictCommandAttempt::before_spawn(strict_end, &retention);
    let address = (&**attempt.original.as_ref().unwrap()) as *const StrictCommandResources;
    let mut command = Command::new("/bin/sh");
    command
        .args(["-c", "printf public; printf diagnostic >&2; exit 7"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    let mut fixture = FixtureChild::spawn(command, end)?;
    let pid = fixture.id()?;
    let terminal = wait_owned_terminal(fixture.child(), work)?;
    require(
        terminal.status == 7,
        "negative-control original terminal status",
    )?;
    let original_pipes = [
        fixture.child().stdout.as_ref().unwrap().as_raw_fd(),
        fixture.child().stderr.as_ref().unwrap().as_raw_fd(),
    ];
    let mut status = 0;
    // SAFETY: deliberately competing raw wait consumes only this fixture's
    // already-terminal direct child. The original Rust Child has not reaped it.
    let result = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
    if result == pid {
        // Record the exact successful raw reap immediately, before assertions.
        // The retained Rust Child's own cached wait status stays untouched.
        fixture.original.as_mut().unwrap().status =
            Some(<ExitStatus as std::os::unix::process::ExitStatusExt>::from_raw(status));
    }
    assert_eq!(result, pid);
    assert!(libc::WIFEXITED(status));
    assert_eq!(libc::WEXITSTATUS(status), 7);
    // Move this SAME Rust Child and pipes once; no PID-based reconstruction.
    // Before this transfer the bounded fixture guard owned every failure path.
    let same_child = fixture.original.as_mut().unwrap().child.take().unwrap();
    let original = attempt.original.as_mut().unwrap();
    original.child = Some(same_child);
    original.group = Some(pid);
    assert_eq!(original.child.as_ref().unwrap().id() as i32, pid);
    assert_eq!(
        [
            original
                .child
                .as_ref()
                .unwrap()
                .stdout
                .as_ref()
                .unwrap()
                .as_raw_fd(),
            original
                .child
                .as_ref()
                .unwrap()
                .stderr
                .as_ref()
                .unwrap()
                .as_raw_fd()
        ],
        original_pipes
    );
    drop(fixture);
    nonchild_wnowait_is_echild(pid, work)?;
    assert_eq!(
        attempt.original.as_ref().unwrap().terminal(),
        Err(CommandFailure::OwnershipUnknown)
    );
    let failure = attempt
        .complete(Err(CommandFailure::OutputLimit))
        .unwrap_err();
    assert_eq!(failure.operation, Some(CommandFailure::OutputLimit));
    assert_eq!(failure.cleanup, Some(CommandFailure::OwnershipUnknown));
    assert!(failure.original_retained);
    let original = retention.original.lock().unwrap().take().unwrap();
    assert_eq!((&*original) as *const StrictCommandResources, address);
    assert_eq!(original.signal_calls, 0);
    assert!(original.child.as_ref().unwrap().stdout.is_some());
    assert!(original.child.as_ref().unwrap().stderr.is_some());
    assert!(retention.refused());
    // Test-only teardown: the explicit raw waiter already reaped this fixture.
    // Dropping its retained frame closes pipes, with no retry, kill or wait.
    drop(original);
    let mut scope = strict_fixture_scope();
    let refused = strict_output_inner(
        Command::new("/no-such-competing-wait-fixture-executable"),
        strict_end,
        &mut scope,
        &retention,
    )
    .unwrap_err();
    assert_eq!(
        refused,
        StrictCommandFailure::before_spawn(CommandFailure::OwnershipUnknown)
    );
    work.current()?;
    Frame::new(Phase::CompetingRefused, me, 0).send(&mut link, work)?;
    Frame::read(&mut link, work)?.expect(Phase::Finish, me, 0)?;
    Frame::new(Phase::Done, me, 0).send(&mut link, work)
}

fn run_competing_controller() -> io::Result<()> {
    let end = End::create()?;
    let work = end.work();
    let (link, inherited) = UnixStream::pair()?;
    link.set_nonblocking(true)?;
    inherited.set_nonblocking(true)?;
    let descriptor: OwnedFd = inherited.into();
    let mut command = Command::new(std::env::current_exe()?);
    command
        .args([
            "--exact",
            COMPETING_SELECTOR,
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(ENTRY_KEY, "competing-v2")
        .env(END_KEY, end.0.to_string())
        .stdin(Stdio::from(descriptor))
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let owner = FixtureChild::spawn(command, end)?;
    let original_owner = owner.id()?;
    let mut controller = Controller {
        link: Some(link),
        owner,
    };
    Frame::read(controller.link.as_mut().unwrap(), work)?.expect(
        Phase::Hello,
        original_owner,
        0,
    )?;
    Frame::new(Phase::Create, original_owner, 0).send(controller.link.as_mut().unwrap(), work)?;
    Frame::read(controller.link.as_mut().unwrap(), work)?.expect(
        Phase::CompetingRefused,
        original_owner,
        0,
    )?;
    controller.owner.alive(work)?;
    Frame::new(Phase::Finish, original_owner, 0).send(controller.link.as_mut().unwrap(), work)?;
    Frame::read(controller.link.as_mut().unwrap(), work)?.expect(Phase::Done, original_owner, 0)?;
    require(
        controller.owner.reap(work)?.success(),
        "competing fixture subprocess failed",
    )?;
    require(
        !controller.owner.original.as_ref().unwrap().kill_attempted,
        "normal negative-control path signalled owner",
    )?;
    drop(controller);
    require(
        UNKNOWN_FIXTURE_OWNERS.load(Ordering::SeqCst) == 0,
        "negative-control owner teardown unknown",
    )?;
    println!("WAIT_OWNER_COMPETING_V2 raw_wait=CONSUMED subsequent_wnowait=ECHILD strict_cleanup=OwnershipUnknown strict_signal_calls=0 retained_original=true");
    Ok(())
}

#[test]
#[ignore = "Internal negative-control worker; only controller supplies original IPC and endpoint"]
fn same_process_competing_wait_worker() {
    run_competing_owner().expect("competing-wait fixture worker");
}
