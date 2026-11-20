//! Real repository-private sockets, fixed extracted handlers and actual monitored
//! accept loops. Fixture ownership/admission is never a native selected permit.
use super::*;
use crate::supervisor::{
    HeldObjectKind, HeldRevocationRequest, RevocationReport, SupervisorRequest, SupervisorResponse,
};
use std::{
    fs::File,
    os::{
        fd::AsRawFd,
        unix::{
            fs::{MetadataExt, PermissionsExt},
            net::UnixStream,
        },
    },
    path::Path,
    time::Duration,
};

fn end() -> Instant {
    Instant::now() + Duration::from_secs(5)
}
fn mode(path: &Path, bits: u32) {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(bits)).unwrap();
}
fn identity(path: &Path) -> (u64, u64, u32) {
    let m = std::fs::symlink_metadata(path).unwrap();
    (m.dev(), m.ino(), m.mode())
}
struct Fixture {
    root: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        std::fs::create_dir_all("target").unwrap();
        let root = PathBuf::from("target").join(format!("sa-{:016x}", crate::rng::u64()));
        std::fs::create_dir(&root).unwrap();
        mode(&root, 0o700);
        Self { root }
    }
    fn socket(&self, role: Role) -> FixtureSocket {
        let path = self.root.join(match role {
            Role::Primary => "primary.sock",
            Role::Held => "held.sock",
        });
        let listener = UnixListener::bind(&path).unwrap();
        mode(&path, 0o600);
        listener.set_nonblocking(true).unwrap();
        FixtureSocket {
            stamp: identity(&path),
            parent: File::open(&self.root).unwrap(),
            parent_stamp: identity(&self.root),
            root: self.root.clone(),
            path,
            listener,
            taken: false,
            poisoned: false,
            checks: 0,
            takes: 0,
            fail_at: None,
            delay_at: None,
            dropped: Arc::new(AtomicBool::new(false)),
        }
    }
    fn config(&self, admission: Admission) -> Mode {
        Mode::Fixture {
            root: self.root.clone(),
            admission,
        }
    }
    fn primary(
        &self,
        stop: Arc<AtomicBool>,
        tracker: Arc<RespawnTracker>,
        held_status: Arc<AtomicBool>,
    ) -> WorkerOwner<FixtureSocket> {
        let mut owner = WorkerOwner::new(self.socket(Role::Primary), stop, Role::Primary);
        owner.start(
            &mut None,
            self.config(Admission::Local),
            Service::Primary {
                tracker,
                held_status,
            },
            end(),
        );
        owner
    }
    fn held(&self, admission: Admission) -> WorkerOwner<FixtureSocket> {
        let mut owner = WorkerOwner::new(
            self.socket(Role::Held),
            Arc::new(AtomicBool::new(false)),
            Role::Held,
        );
        owner.start(&mut None, self.config(admission), Service::Held, end());
        owner
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}
struct FixtureSocket {
    root: PathBuf,
    parent: File,
    parent_stamp: (u64, u64, u32),
    path: PathBuf,
    stamp: (u64, u64, u32),
    listener: UnixListener,
    taken: bool,
    poisoned: bool,
    checks: usize,
    takes: usize,
    fail_at: Option<usize>,
    delay_at: Option<(usize, Instant)>,
    dropped: Arc<AtomicBool>,
}
impl NamedSocket for FixtureSocket {
    fn current(
        &mut self,
        _: &mut Option<&mut SelectedRuntime>,
        deadline: Instant,
    ) -> EnclaveResult<()> {
        self.checks += 1;
        if let Some((call, until)) = self.delay_at {
            if self.checks == call {
                std::thread::sleep(until.saturating_duration_since(Instant::now()));
            }
        }
        let result = (|| {
            if self.poisoned || Instant::now() >= deadline || self.fail_at == Some(self.checks) {
                return Err(err!(EACCES, "FIXTURE_SOCKET_REFUSED"));
            }
            let parent = self
                .parent
                .metadata()
                .map_err(|_| err!(EIO, "FIXTURE_PARENT"))?;
            let named =
                std::fs::symlink_metadata(&self.path).map_err(|_| err!(EIO, "FIXTURE_NAME"))?;
            if (parent.dev(), parent.ino(), parent.mode()) != self.parent_stamp
                || identity(&self.root) != self.parent_stamp
                || (named.dev(), named.ino(), named.mode()) != self.stamp
            {
                return Err(err!(ESTALE, "FIXTURE_SOCKET_CHANGED"));
            }
            let descriptor = unsafe { libc::fcntl(self.listener.as_raw_fd(), libc::F_GETFD) };
            let flags = unsafe { libc::fcntl(self.listener.as_raw_fd(), libc::F_GETFL) };
            if descriptor < 0
                || descriptor & libc::FD_CLOEXEC == 0
                || flags < 0
                || flags & libc::O_NONBLOCK == 0
            {
                return Err(err!(EIO, "FIXTURE_FLAGS"));
            }
            Ok(())
        })();
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }
    fn take(
        &mut self,
        originals: &mut Option<&mut SelectedRuntime>,
        deadline: Instant,
    ) -> EnclaveResult<UnixListener> {
        self.current(originals, deadline)?;
        if self.taken {
            self.poisoned = true;
            return Err(err!(EACCES, "FIXTURE_ALREADY_TAKEN"));
        }
        let duplicate = self
            .listener
            .try_clone()
            .map_err(|_| err!(EIO, "FIXTURE_DUP"))?;
        self.taken = true;
        self.takes += 1;
        Ok(duplicate)
    }
}
impl Drop for FixtureSocket {
    fn drop(&mut self) {
        self.dropped.store(true, Ordering::SeqCst);
    }
}
fn client(path: &Path) -> ipc::Client {
    let mut client = ipc::Client::connect(path, ipc::geteuid()).unwrap();
    client.set_timeout(Some(Duration::from_secs(2))).unwrap();
    client
}
fn tracker() -> Arc<RespawnTracker> {
    Arc::new(RespawnTracker::new())
}
fn status() -> Arc<AtomicBool> {
    Arc::new(AtomicBool::new(false))
}
fn held_request() -> HeldRevocationRequest {
    HeldRevocationRequest {
        version: super::super::HELD_REVOCATION_VERSION,
        root: "ab".repeat(32),
        kind: HeldObjectKind::Canonical,
    }
}

#[test]
fn primary_real_status_and_progress_retain_named_owner_while_status_bool_is_only_descriptive() {
    let fixture = Fixture::new();
    let stop = Arc::new(AtomicBool::new(false));
    let held = status();
    let mut owner = fixture.primary(stop.clone(), tracker(), held.clone());
    assert!(!owner.poisoned);
    let mut connection = client(&owner.socket.path);
    let response: SupervisorResponse = connection.call(&SupervisorRequest::Status).unwrap();
    assert!(
        matches!(response,SupervisorResponse::Status(text) if text=="supervisor dev=true held_v1=false")
    );
    held.store(true, Ordering::SeqCst);
    let response: SupervisorResponse = connection.call(&SupervisorRequest::Status).unwrap();
    assert!(
        matches!(response,SupervisorResponse::Status(text) if text=="supervisor dev=true held_v1=true")
    );
    drop(connection);
    owner.observe(&mut None, end()).unwrap();
    let original = owner.socket.listener.as_raw_fd();
    owner.stop(&mut None, end()).unwrap();
    held.store(true, Ordering::SeqCst);
    stop.store(false, Ordering::SeqCst);
    assert!(owner.observe(&mut None, end()).is_err());
    assert_eq!(owner.socket.listener.as_raw_fd(), original);
    assert!(owner.socket.path.exists());
    assert!(!owner.status.load(Ordering::SeqCst));
}

#[test]
fn extracted_primary_handler_uses_same_actual_tracker_and_handler_refusal_is_not_loop_failure() {
    let fixture = Fixture::new();
    let tracker = tracker();
    let mut owner = fixture.primary(Arc::new(AtomicBool::new(false)), tracker.clone(), status());
    assert!(!owner.poisoned);
    let mut connection = client(&owner.socket.path);
    let _: SupervisorResponse = connection.call(&SupervisorRequest::Status).unwrap();
    tracker.record_delay(ipc::geteuid(), Duration::from_secs(60));
    assert!(connection
        .call::<_, SupervisorResponse>(&SupervisorRequest::Status)
        .unwrap_err()
        .is("DAEMON_RESPAWN_THROTTLED"));
    drop(connection);
    owner.observe(&mut None, end()).unwrap();
    owner.stop(&mut None, end()).unwrap();
}

#[test]
fn held_real_fd_request_reaches_fixed_protocol_and_eligibility_refusals_without_signaling() {
    let fixture = Fixture::new();
    let mut owner = fixture.held(Admission::Local);
    assert!(!owner.poisoned);
    let path = fixture.root.join("object");
    std::fs::write(&path, b"fixture public bytes").unwrap();
    mode(&path, 0o400);
    let file = File::open(&path).unwrap();
    let mut request = held_request();
    request.version = 0;
    let mut connection = client(&owner.socket.path);
    assert!(connection
        .call_with_fds::<_, RevocationReport>(&request, &[file.as_raw_fd()])
        .unwrap_err()
        .is("HELD_REVOCATION_PROTOCOL"));
    drop(connection);
    mode(&path, 0o600);
    let writable = File::options().read(true).write(true).open(&path).unwrap();
    mode(&path, 0o444);
    let mut connection = client(&owner.socket.path);
    assert!(connection
        .call_with_fds::<_, RevocationReport>(&held_request(), &[writable.as_raw_fd()])
        .unwrap_err()
        .is("HELD_OBJECT_ELIGIBILITY"));
    drop(connection);
    owner.observe(&mut None, end()).unwrap();
    owner.stop(&mut None, end()).unwrap();
}

#[test]
fn held_exact_one_fd_classifier_rejects_missing_and_extra_descriptor_packets() {
    let fixture = Fixture::new();
    let mut owner = fixture.held(Admission::Local);
    assert!(!owner.poisoned);
    let path = fixture.root.join("object");
    std::fs::write(&path, b"public").unwrap();
    let file = File::open(&path).unwrap();
    for fds in [Vec::new(), vec![file.as_raw_fd(), file.as_raw_fd()]] {
        let mut connection = client(&owner.socket.path);
        assert!(connection
            .call_with_fds::<_, RevocationReport>(&held_request(), &fds)
            .is_err());
        drop(connection);
    }
    owner.observe(&mut None, end()).unwrap();
    owner.stop(&mut None, end()).unwrap();
}

#[test]
fn held_authentication_refuses_before_reading_any_frame_or_scm_rights_packet() {
    let fixture = Fixture::new();
    let mut owner = fixture.held(Admission::Deny);
    assert!(!owner.poisoned);
    let mut stream = UnixStream::connect(&owner.socket.path).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    // Send neither frame nor FD marker. Any implementation reading either
    // before kernel-policy authentication would block instead of returning.
    let reply: ipc::Reply<RevocationReport> =
        ipc::from_cbor(&ipc::read_frame(&mut stream).unwrap()).unwrap();
    assert!(matches!(reply,ipc::Reply::Err(error) if error.is("PEER_UID_REJECTED")));
    drop(stream);
    owner.observe(&mut None, end()).unwrap();
    owner.stop(&mut None, end()).unwrap();
}

#[test]
fn held_cannot_decode_primary_control_verbs_and_never_waits_for_an_fd_for_them() {
    let fixture = Fixture::new();
    let mut owner = fixture.held(Admission::Local);
    assert!(!owner.poisoned);
    let mut stream = UnixStream::connect(&owner.socket.path).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    ipc::write_frame(
        &mut stream,
        &ipc::to_cbor(&SupervisorRequest::Status).unwrap(),
    )
    .unwrap();
    let reply: ipc::Reply<RevocationReport> =
        ipc::from_cbor(&ipc::read_frame(&mut stream).unwrap()).unwrap();
    assert!(matches!(reply, ipc::Reply::Err(_)));
    drop(stream);
    owner.observe(&mut None, end()).unwrap();
    owner.stop(&mut None, end()).unwrap();
}

#[test]
fn extracted_production_roles_and_legacy_bare_revocation_remain_restricted() {
    let fixture = Fixture::new();
    let primary =
        super::super::primary_handler(fixture.root.clone(), false, 0, 501, tracker(), status());
    let peer = ipc::PeerCredentials::local(702, 8702);
    assert!(primary(
        &peer,
        SupervisorRequest::EnforceRevocation { dev: 1, ino: 2 }
    )
    .unwrap_err()
    .is("HELD_REVOCATION_V1_REQUIRED"));
    assert!(primary(&peer, SupervisorRequest::SessionLocked)
        .unwrap_err()
        .is("PERMISSION_DENIED"));
    assert!(primary(
        &peer,
        SupervisorRequest::WipeFanout(crate::power::WipeTrigger::SystemSleep)
    )
    .unwrap_err()
    .is("PERMISSION_DENIED"));
    let held = super::super::held_handler(false, 0);
    let mut request = held_request();
    assert!(
        held(&ipc::PeerCredentials::local(0, 0), request.clone(), vec![])
            .unwrap_err()
            .is("HELD_OBJECT_ROLE")
    );
    request.kind = HeldObjectKind::Snapshot;
    assert!(held(&peer, request.clone(), vec![])
        .unwrap_err()
        .is("HELD_OBJECT_ROLE"));
    assert!(
        held(&ipc::PeerCredentials::local(0, 0), request.clone(), vec![])
            .unwrap_err()
            .is("HELD_OBJECT_FD_COUNT")
    );
    assert_eq!(super::super::held_fd_classifier()(&request), Some(1));
}

#[test]
fn named_socket_replacement_cannot_be_hidden_by_a_healthy_original_worker_or_restored_name() {
    let fixture = Fixture::new();
    let mut owner = fixture.held(Admission::Local);
    assert!(!owner.poisoned);
    let original = owner.socket.listener.as_raw_fd();
    let path = owner.socket.path.clone();
    std::fs::rename(&path, path.with_extension("saved")).unwrap();
    std::fs::write(&path, b"foreign").unwrap();
    assert!(owner.observe(&mut None, end()).is_err());
    assert!(owner.poisoned && owner.stop.load(Ordering::SeqCst));
    assert_eq!(owner.socket.listener.as_raw_fd(), original);
    assert_eq!(std::fs::read(&path).unwrap(), b"foreign");
    std::fs::remove_file(&path).unwrap();
    std::fs::rename(path.with_extension("saved"), &path).unwrap();
    owner.stop.store(false, Ordering::SeqCst);
    assert!(owner.observe(&mut None, end()).is_err());
    let _ = owner.stop(&mut None, end());
    owner.progress.as_mut().unwrap().stop(end()).unwrap();
}

#[test]
fn post_worker_probe_socket_loss_keeps_both_original_owners_and_never_reissues_a_listener() {
    let fixture = Fixture::new();
    let mut owner = fixture.held(Admission::Local);
    assert!(!owner.poisoned);
    owner.socket.fail_at = Some(owner.socket.checks + 2);
    let original = owner.socket.listener.as_raw_fd();
    assert!(owner.observe(&mut None, end()).is_err());
    assert!(owner.failures.iter().any(|f| f.stage == Stage::SocketAfter));
    assert!(owner.progress.is_some());
    assert_eq!(owner.socket.listener.as_raw_fd(), original);
    assert_eq!(owner.socket.takes, 1);
    owner.socket.fail_at = None;
    owner.stop.store(false, Ordering::SeqCst);
    assert!(owner.observe(&mut None, end()).is_err());
    let _ = owner.stop(&mut None, end());
    owner.progress.as_mut().unwrap().stop(end()).unwrap();
}

#[test]
fn expired_start_has_no_dup_or_worker_and_late_started_worker_is_retained_until_stop() {
    let fixture = Fixture::new();
    let mut early = WorkerOwner::new(
        fixture.socket(Role::Primary),
        Arc::new(AtomicBool::new(false)),
        Role::Primary,
    );
    early.start(
        &mut None,
        fixture.config(Admission::Local),
        Service::Primary {
            tracker: tracker(),
            held_status: status(),
        },
        Instant::now(),
    );
    assert!(early.poisoned && early.progress.is_none());
    assert_eq!(early.socket.takes, 0);
    let mut late = WorkerOwner::new(
        fixture.socket(Role::Held),
        Arc::new(AtomicBool::new(false)),
        Role::Held,
    );
    let deadline = Instant::now() + Duration::from_secs(1);
    late.socket.delay_at = Some((4, deadline));
    late.start(
        &mut None,
        fixture.config(Admission::Local),
        Service::Held,
        deadline,
    );
    assert!(late.poisoned && late.progress.is_some());
    assert_eq!(late.socket.takes, 1);
    assert!(!late.status.load(Ordering::SeqCst));
    let original = late.socket.listener.as_raw_fd();
    let _ = late.stop(&mut None, end());
    late.progress.as_mut().unwrap().stop(end()).unwrap();
    assert_eq!(late.socket.listener.as_raw_fd(), original);
    assert!(late.observe(&mut None, end()).is_err());
}

#[test]
fn bounded_stop_retains_original_socket_and_worker_owner_without_reviving_after_retry() {
    let fixture = Fixture::new();
    let mut owner = fixture.held(Admission::Local);
    assert!(!owner.poisoned);
    let dropped = owner.socket.dropped.clone();
    let original = owner.socket.listener.as_raw_fd();
    assert!(owner.stop(&mut None, Instant::now()).is_err());
    assert!(owner.progress.is_some() && !dropped.load(Ordering::SeqCst));
    let _ = owner.stop(&mut None, end());
    owner.progress.as_mut().unwrap().stop(end()).unwrap();
    assert_eq!(owner.socket.listener.as_raw_fd(), original);
    owner.stop.store(false, Ordering::SeqCst);
    assert!(owner.observe(&mut None, end()).is_err());
    drop(owner);
    assert!(dropped.load(Ordering::SeqCst));
}

#[test]
fn repeated_start_never_spawns_a_replacement_or_takes_another_listener() {
    let fixture = Fixture::new();
    let mut owner = fixture.held(Admission::Local);
    assert!(!owner.poisoned);
    let original = owner.socket.listener.as_raw_fd();
    owner.start(
        &mut None,
        fixture.config(Admission::Local),
        Service::Held,
        end(),
    );
    assert!(owner.poisoned && owner.progress.is_some());
    assert_eq!(owner.socket.takes, 1);
    assert!(owner
        .failures
        .iter()
        .any(|f| f.stage == Stage::AlreadyStarted));
    assert_eq!(owner.socket.listener.as_raw_fd(), original);
    owner.stop(&mut None, end()).unwrap();
    assert!(owner.observe(&mut None, end()).is_err());
}

#[test]
fn production_closed_constructors_cannot_spawn_from_refused_native_sockets_or_foreign_stop_owner() {
    if !cfg!(target_os = "macos") || ipc::geteuid() != 0 {
        let mut originals = SelectedRuntime::acquire_selected(
            Path::new("/unopened-selected-accept"),
            crate::Profile::L2,
            end(),
        );
        let socket = HeldSocket::bind(&mut originals, end());
        let stop = Arc::new(AtomicBool::new(false));
        let mut held = HeldAccept::start(socket, &mut originals, stop.clone(), end());
        assert!(held.inner.poisoned && held.inner.progress.is_none());
        let socket = PrimarySocket::bind(&mut originals, end());
        let mut primary = PrimaryAccept::start(
            socket,
            &mut originals,
            tracker(),
            &mut held,
            Arc::new(AtomicBool::new(false)),
            end(),
        );
        assert!(primary.inner.poisoned && primary.inner.progress.is_none());
        assert!(primary
            .inner
            .failures
            .iter()
            .any(|f| f.stage == Stage::HeldDependency));
        assert!(primary.observe_health(&mut originals, end()).is_err());
        assert!(held.observe_health(&mut originals, end()).is_err());
        let _ = primary.stop(&mut originals, end());
        let _ = held.stop(&mut originals, end());
    }
}
