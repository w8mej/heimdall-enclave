use super::*;
use crate::ipc::{self, PeerPolicy};
use std::{
    os::{fd::AsRawFd, unix::net::UnixStream},
    path::PathBuf,
    sync::mpsc,
};

fn endpoint() -> Instant {
    Instant::now() + Duration::from_secs(3)
}
struct Socket {
    path: PathBuf,
}
impl Socket {
    fn new() -> (Self, UnixListener) {
        // Relative names keep Darwin's sockaddr_un limit independent of the
        // configured checkout's absolute length. The harness cwd is captured.
        let parent = PathBuf::from("target");
        std::fs::create_dir_all(&parent).unwrap();
        let path = parent.join(format!(
            "progress-{}-{}",
            std::process::id(),
            crate::rng::u64()
        ));
        let listener = UnixListener::bind(&path).unwrap();
        (Self { path }, listener)
    }
}
impl Drop for Socket {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}
fn start() -> (Socket, ServerProgress, Arc<AtomicBool>) {
    let (socket, listener) = Socket::new();
    let stop = Arc::new(AtomicBool::new(false));
    let owner = ipc::spawn_monitored(
        listener,
        PeerPolicy::allow([ipc::geteuid()]),
        Arc::new(|_: &ipc::PeerCredentials, value: u64| Ok(value + 1)),
        stop.clone(),
    )
    .unwrap();
    (socket, owner, stop)
}
fn synthetic_worker() -> (ServerProgress, mpsc::Sender<()>, mpsc::Receiver<()>) {
    let (owner, progress) = prepare(Arc::new(AtomicBool::new(false)));
    let (release, wait) = mpsc::channel();
    let (dropped, observed) = mpsc::channel();
    let thread = std::thread::spawn(move || {
        // A synthetic held resource stays on this actual worker until released.
        let _progress = progress;
        wait.recv().unwrap();
        dropped.send(()).unwrap();
        Ok(())
    });
    (owner.attach(thread), release, observed)
}

#[test]
fn fresh_challenges_require_actual_accept_loop_iterations() {
    let (_socket, mut owner, _) = start();
    for _ in 0..4 {
        owner.observe_health(endpoint()).unwrap();
    }
    owner.stop(endpoint()).unwrap();
    assert!(owner.observe_health(endpoint()).is_err());
}
#[test]
fn serving_and_authentication_remain_on_original_path() {
    let (socket, mut owner, _) = start();
    owner.observe_health(endpoint()).unwrap();
    let mut stream = UnixStream::connect(&socket.path).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    ipc::write_frame(&mut stream, &ipc::to_cbor(&12u64).unwrap()).unwrap();
    let response: ipc::Reply<u64> = ipc::from_cbor(&ipc::read_frame(&mut stream).unwrap()).unwrap();
    assert!(matches!(response, ipc::Reply::Ok(13)));
    drop(stream);
    owner.observe_health(endpoint()).unwrap();
    owner.stop(endpoint()).unwrap();
}
#[test]
fn denied_peer_cannot_invoke_handler_or_forge_progress() {
    let (socket, listener) = Socket::new();
    let calls = Arc::new(AtomicBool::new(false));
    let seen = calls.clone();
    let mut owner = ipc::spawn_monitored(
        listener,
        PeerPolicy::allow([]),
        Arc::new(move |_: &ipc::PeerCredentials, _: u64| {
            seen.store(true, Ordering::SeqCst);
            Ok(0u64)
        }),
        Arc::new(AtomicBool::new(false)),
    )
    .unwrap();
    let mut stream = UnixStream::connect(&socket.path).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let response: ipc::Reply<u64> = ipc::from_cbor(&ipc::read_frame(&mut stream).unwrap()).unwrap();
    assert!(matches!(response, ipc::Reply::Err(_)));
    assert!(!calls.load(Ordering::SeqCst));
    owner.observe_health(endpoint()).unwrap();
    drop(stream);
    owner.stop(endpoint()).unwrap();
}
#[test]
fn accept_progress_does_not_claim_connection_handler_completion() {
    let (socket, listener) = Socket::new();
    let (entered, observed) = mpsc::sync_channel(1);
    let (release, wait) = mpsc::sync_channel(1);
    let wait = Mutex::new(wait);
    let mut owner = ipc::spawn_monitored(
        listener,
        PeerPolicy::allow([ipc::geteuid()]),
        Arc::new(move |_: &ipc::PeerCredentials, value: u64| {
            entered.send(()).unwrap();
            wait.lock().unwrap().recv().unwrap();
            Ok(value)
        }),
        Arc::new(AtomicBool::new(false)),
    )
    .unwrap();
    let mut stream = UnixStream::connect(&socket.path).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    ipc::write_frame(&mut stream, &ipc::to_cbor(&1u64).unwrap()).unwrap();
    observed.recv_timeout(Duration::from_secs(2)).unwrap();
    owner.observe_health(endpoint()).unwrap();
    release.send(()).unwrap();
    let _: ipc::Reply<u64> = ipc::from_cbor(&ipc::read_frame(&mut stream).unwrap()).unwrap();
    drop(stream);
    owner.stop(endpoint()).unwrap();
}
#[test]
fn external_stop_refuses_immediately_and_cannot_rearm() {
    let (_socket, mut owner, stop) = start();
    owner.observe_health(endpoint()).unwrap();
    stop.store(true, Ordering::SeqCst);
    assert!(owner.observe_health(endpoint()).is_err());
    stop.store(false, Ordering::SeqCst);
    assert!(owner.observe_health(endpoint()).is_err());
    owner.stop(endpoint()).unwrap();
}
#[test]
fn expired_probe_does_not_enqueue_or_allow_later_success() {
    let (mut owner, release, observed) = synthetic_worker();
    assert!(owner
        .observe_health(Instant::now())
        .unwrap_err()
        .is("IPC_PROGRESS_DEADLINE"));
    assert!(owner.observe_health(endpoint()).is_err());
    release.send(()).unwrap();
    observed.recv_timeout(Duration::from_secs(2)).unwrap();
    owner.stop(endpoint()).unwrap();
}
#[test]
fn stalled_original_worker_times_out_without_helper_ack() {
    let (mut owner, release, observed) = synthetic_worker();
    assert!(owner
        .observe_health(Instant::now() + Duration::from_millis(20))
        .is_err());
    assert!(owner.state.revoked.load(Ordering::SeqCst));
    release.send(()).unwrap();
    observed.recv_timeout(Duration::from_secs(2)).unwrap();
    owner.stop(endpoint()).unwrap();
}
#[test]
fn bounded_stop_retains_unfinished_handle_and_resource() {
    let (mut owner, release, observed) = synthetic_worker();
    assert!(owner
        .stop(Instant::now())
        .unwrap_err()
        .is("IPC_PROGRESS_STOP_PENDING"));
    assert!(owner.thread.is_some());
    assert!(observed.try_recv().is_err());
    release.send(()).unwrap();
    observed.recv_timeout(Duration::from_secs(2)).unwrap();
    owner.stop(endpoint()).unwrap();
}
#[test]
fn drop_leaves_blocked_resource_with_original_worker() {
    let (owner, release, observed) = synthetic_worker();
    let state = owner.state.clone();
    drop(owner);
    assert!(state.revoked.load(Ordering::SeqCst));
    assert!(observed.try_recv().is_err());
    release.send(()).unwrap();
    observed.recv_timeout(Duration::from_secs(2)).unwrap();
}
#[test]
fn old_instance_does_not_gain_health_from_replacement() {
    let (_first, mut old, _) = start();
    old.stop(endpoint()).unwrap();
    let (_second, mut replacement, _) = start();
    replacement.observe_health(endpoint()).unwrap();
    assert!(old.observe_health(endpoint()).is_err());
    replacement.stop(endpoint()).unwrap();
}
#[test]
fn loop_checks_original_listener_and_flags_before_acknowledgment() {
    let (_first, first) = Socket::new();
    let (_second, second) = Socket::new();
    first.set_nonblocking(true).unwrap();
    second.set_nonblocking(true).unwrap();
    let (owner, mut progress) = prepare(Arc::new(AtomicBool::new(false)));
    progress.bind(&first).unwrap();
    assert!(progress.current(&first, endpoint()).is_ok());
    assert!(progress
        .current(&second, endpoint())
        .unwrap_err()
        .is("IPC_PROGRESS_IDENTITY"));
    first.set_nonblocking(false).unwrap();
    assert!(progress.current(&first, endpoint()).is_err());
    drop(progress);
    assert!(owner.state.revoked.load(Ordering::SeqCst));
    // A socket descriptor alone is insufficient: only an actual listening
    // accept loop can ACK. An unbound/nonlistening socket must exit on accept.
    use std::os::fd::FromRawFd;
    let raw = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
    assert!(raw >= 0);
    let unlistening = unsafe { UnixListener::from_raw_fd(raw) };
    assert_eq!(
        unsafe { libc::fcntl(raw, libc::F_SETFD, libc::FD_CLOEXEC) },
        0
    );
    let mut owner = ipc::spawn_monitored(
        unlistening,
        PeerPolicy::allow([ipc::geteuid()]),
        Arc::new(|_: &ipc::PeerCredentials, value: u64| Ok(value)),
        Arc::new(AtomicBool::new(false)),
    )
    .unwrap();
    assert!(owner.observe_health(endpoint()).is_err());
    assert!(owner.stop(endpoint()).is_err());
}
#[test]
fn worker_exit_and_unwind_revoke_even_without_stop_flag() {
    for panic in [false, true] {
        let (owner, progress) = prepare(Arc::new(AtomicBool::new(false)));
        let thread = std::thread::spawn(move || {
            let _progress = progress;
            assert!(!panic, "synthetic accept-owner unwind");
            Ok(())
        });
        let mut owner = owner.attach(thread);
        while !owner.thread.as_ref().unwrap().is_finished() {
            std::thread::yield_now();
        }
        assert!(owner.state.revoked.load(Ordering::SeqCst));
        assert!(owner.observe_health(endpoint()).is_err());
        assert_eq!(owner.stop(endpoint()).is_err(), panic);
        assert_eq!(
            owner.stop(endpoint()).is_err(),
            panic,
            "terminal failure must survive a consumed handle"
        );
    }
}

#[test]
fn actual_worker_error_is_retained_with_only_closed_stage_and_errno() {
    let (owner, progress) = prepare(Arc::new(AtomicBool::new(false)));
    let terminal = owner.terminal_observer();
    let state = owner.state.clone();
    let thread = std::thread::spawn(move || {
        let _progress = progress;
        let result = Err(err!(
            EIO,
            "UNTRUSTED_HANDLER_REASON_WITH_SECRET",
            "synthetic private detail"
        ));
        terminal(&result);
        result
    });
    let mut owner = owner.attach(thread);
    while !owner.thread.as_ref().unwrap().is_finished() {
        std::thread::yield_now();
    }
    assert_eq!(
        *state.terminal.lock().unwrap(),
        Some(WorkerFailure::Other(Errno::EIO))
    );
    assert!(owner.observe_health(endpoint()).is_err());
    assert!(owner.stop(endpoint()).is_err());
    assert!(owner.stop(endpoint()).is_err());
    drop(owner);
    assert_eq!(
        *state.terminal.lock().unwrap(),
        Some(WorkerFailure::Other(Errno::EIO))
    );
}

#[test]
fn real_loop_ack_commits_before_intentional_stop_without_terminal_failure() {
    let (_socket, listener) = Socket::new();
    let stop = Arc::new(AtomicBool::new(false));
    let (owner, mut progress) = prepare(stop.clone());
    let (entered, paused) = mpsc::sync_channel(1);
    let (release, wait) = mpsc::sync_channel(1);
    progress.after_ack_pause = Some((entered, wait));
    let terminal = owner.terminal_observer();
    let worker_stop = stop.clone();
    let policy = PeerPolicy::allow([ipc::geteuid()]);
    let thread = std::thread::spawn(move || {
        // The production serve loop binds and observes its actual listener,
        // performs a real accept/WouldBlock iteration, and sends the ACK.
        let result = ipc::serve_owned_loop(
            listener,
            Arc::new(move |peer: &ipc::PeerCredentials| policy.check(peer)),
            ipc::ServeLimits::default(),
            Arc::new(ipc::ServeStats::default()),
            Arc::new(
                |_: &ipc::PeerCredentials, value: u64, _: Vec<std::os::fd::OwnedFd>| Ok(value + 1),
            ),
            Arc::new(|_: &u64| None),
            worker_stop,
            Some(progress),
        );
        terminal(&result);
        result
    });
    let mut owner = owner.attach(thread);
    owner.observe_health(endpoint()).unwrap();
    paused.recv_timeout(Duration::from_secs(2)).unwrap();
    // The actual worker cannot leave its post-ACK window until released.
    assert!(owner
        .stop(Instant::now())
        .unwrap_err()
        .is("IPC_PROGRESS_STOP_PENDING"));
    assert!(owner
        .thread
        .as_ref()
        .is_some_and(|thread| !thread.is_finished()));
    assert!(owner.state.terminal.lock().unwrap().is_none());
    assert!(
        owner.observe_health(endpoint()).is_err(),
        "stopped owner cannot gain health"
    );
    release.try_send(()).unwrap();
    owner.stop(endpoint()).unwrap();
    assert!(owner.thread.is_none());
    assert!(owner.state.terminal.lock().unwrap().is_none());
    assert!(owner.observe_health(endpoint()).is_err());
    // With the former post-ACK current(), this exact stop-before-release
    // handshake makes the worker retain IPC_PROGRESS_REVOKED as terminal EIO.
}

#[test]
fn stop_expiry_original_identity_and_flags_still_refuse_before_any_ack() {
    for case in 0..5 {
        let (_first, first) = Socket::new();
        let (_second, second) = Socket::new();
        first.set_nonblocking(true).unwrap();
        second.set_nonblocking(true).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let (owner, mut progress) = prepare(stop.clone());
        progress.bind(&first).unwrap();
        let until = if case == 1 {
            Instant::now()
        } else {
            endpoint()
        };
        let (reply, receive) = mpsc::sync_channel(1);
        assert!(owner.challenge.try_send(Challenge { until, reply }).is_ok());
        let flags = unsafe { libc::fcntl(first.as_raw_fd(), libc::F_GETFD) };
        assert!(flags >= 0);
        match case {
            0 => stop.store(true, Ordering::SeqCst),
            2 => (), // Pass a distinct actual listener to the original check below.
            3 => first.set_nonblocking(false).unwrap(),
            4 => assert_eq!(
                unsafe { libc::fcntl(first.as_raw_fd(), libc::F_SETFD, flags & !libc::FD_CLOEXEC) },
                0
            ),
            _ => (),
        }
        let error = progress
            .observe_iteration(if case == 2 { &second } else { &first })
            .unwrap_err();
        let expected = match case {
            0 => "IPC_PROGRESS_REVOKED",
            1 => "IPC_PROGRESS_DEADLINE",
            2 => "IPC_PROGRESS_IDENTITY",
            _ => "IPC_PROGRESS_LISTENER",
        };
        assert!(error.is(expected), "pre-ACK case {case}: {error}");
        assert!(
            receive.try_recv().is_err(),
            "invalid pre-ACK state emitted an ACK"
        );
        if case == 4 {
            assert_eq!(
                unsafe { libc::fcntl(first.as_raw_fd(), libc::F_SETFD, flags) },
                0
            );
        }
        drop(progress);
        assert!(owner.state.revoked.load(Ordering::SeqCst));
    }
}
