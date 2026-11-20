//! SOFTWARE integration seams only. Registry is absent from production builds;
//! it cannot supply a native authenticated channel or any real readiness term.
use super::*;
use crate::{
    biometric::BiometricProvider,
    ctap::hid::{HidDevice, REPORT},
};
use std::{
    collections::BTreeMap,
    os::unix::net::{UnixListener, UnixStream},
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Mutex, OnceLock,
    },
    time::Instant,
};

#[derive(Default)]
struct State {
    probes: AtomicUsize,
    assignments: AtomicUsize,
    fail_at: AtomicUsize,
    fail_assignment: AtomicBool,
}
fn registry() -> &'static Mutex<BTreeMap<PathBuf, Arc<State>>> {
    static REGISTRY: OnceLock<Mutex<BTreeMap<PathBuf, Arc<State>>>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(BTreeMap::new()))
}
pub(super) fn selected(path: &Path) -> bool {
    registry().lock().unwrap().contains_key(path)
}
fn state(path: &Path) -> EnclaveResult<Arc<State>> {
    registry()
        .lock()
        .unwrap()
        .get(path)
        .cloned()
        .ok_or_else(|| err!(EACCES, "TEST_SUPERVISOR_GONE"))
}
pub(super) fn probe(path: &Path, end: Instant) -> EnclaveResult<()> {
    if Instant::now() >= end {
        fail!(ETIMEDOUT, "TEST_SUPERVISOR_DEADLINE");
    }
    let state = state(path)?;
    let sequence = state.probes.fetch_add(1, Ordering::SeqCst) + 1;
    if state.fail_at.load(Ordering::SeqCst) == sequence {
        fail!(EACCES, "TEST_SUPERVISOR_REFUSED");
    }
    Ok(())
}
pub(super) fn assign(path: &Path) -> EnclaveResult<()> {
    let state = state(path)?;
    state.assignments.fetch_add(1, Ordering::SeqCst);
    if state.fail_assignment.load(Ordering::SeqCst) {
        fail!(EACCES, "TEST_SUPERVISOR_ASSIGNMENT");
    }
    Ok(())
}
struct Registered {
    path: PathBuf,
    state: Arc<State>,
}
impl Registered {
    fn new(path: PathBuf, fail_at: usize) -> Self {
        let state = Arc::new(State::default());
        state.fail_at.store(fail_at, Ordering::SeqCst);
        assert!(registry()
            .lock()
            .unwrap()
            .insert(path.clone(), state.clone())
            .is_none());
        Self { path, state }
    }
}
impl Drop for Registered {
    fn drop(&mut self) {
        registry().lock().unwrap().remove(&self.path);
    }
}

#[derive(Debug)]
struct Bio {
    inner: Box<dyn BiometricProvider + Send>,
    calls: Arc<AtomicUsize>,
}
impl BiometricProvider for Bio {
    fn evaluate(&mut self, prompt: &BiometricPrompt) -> BiometricOutcome {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.evaluate(prompt)
    }
}
#[derive(Debug)]
struct NoBio;
impl BiometricProvider for NoBio {
    fn evaluate(&mut self, _: &BiometricPrompt) -> BiometricOutcome {
        panic!("placeholder provider used")
    }
}
#[derive(Debug)]
struct Device {
    inner: Box<dyn HidDevice + Send>,
    writes: Arc<AtomicUsize>,
}
impl HidDevice for Device {
    fn write_report(&mut self, report: &[u8; REPORT]) -> EnclaveResult<()> {
        self.writes.fetch_add(1, Ordering::SeqCst);
        self.inner.write_report(report)
    }
    fn read_report(&mut self) -> EnclaveResult<[u8; REPORT]> {
        self.inner.read_report()
    }
    fn hub_depth(&self) -> u8 {
        self.inner.hub_depth()
    }
    fn bind_selected_instance(&mut self) -> EnclaveResult<()> {
        self.inner.bind_selected_instance()
    }
    fn deadline_ns(&self) -> Option<u64> {
        self.inner.deadline_ns()
    }
    fn set_deadline_ns(&mut self, end: Option<u64>) -> EnclaveResult<()> {
        self.inner.set_deadline_ns(end)
    }
}
fn effects(service: &VaultService) -> (Arc<AtomicUsize>, Arc<AtomicUsize>) {
    let bio = Arc::new(AtomicUsize::new(0));
    let writes = Arc::new(AtomicUsize::new(0));
    let mut ceremony = service.lock_ceremony().unwrap();
    let inner = std::mem::replace(&mut ceremony.hw.biometric, Box::new(NoBio));
    ceremony.hw.biometric = Box::new(Bio {
        inner,
        calls: bio.clone(),
    });
    let inner = ceremony.hw.yubikey.take().unwrap();
    ceremony.hw.yubikey = Some(Box::new(Device {
        inner,
        writes: writes.clone(),
    }));
    (bio, writes)
}
#[test]
fn missing_initial_dependency_precedes_publication_ledger_ui_and_ctap() {
    let root = tests::Root::new();
    let (service, _, _) = tests::fixture(&root);
    let path = root.0.join("state");
    let dependency = Registered::new(path.clone(), 1);
    let (bio, writes) = effects(&service);
    assert!(!path.join("membership-checkpoints").exists());
    assert!(!path.join("asset-enrollment").exists());
    assert!(service
        .begin_asset(&PeerCredentials::local(0, 0))
        .unwrap_err()
        .is("TEST_SUPERVISOR_REFUSED"));
    assert!(!path.join("membership-checkpoints").exists());
    assert!(!path.join("asset-enrollment").exists());
    assert_eq!(bio.load(Ordering::SeqCst), 0);
    assert_eq!(writes.load(Ordering::SeqCst), 0);
    assert_eq!(dependency.state.assignments.load(Ordering::SeqCst), 0);
}
#[test]
fn actual_assignment_refusal_precedes_publication_and_factors() {
    let root = tests::Root::new();
    let (service, _, _) = tests::fixture(&root);
    let path = root.0.join("state");
    let dependency = Registered::new(path.clone(), 0);
    let (bio, writes) = effects(&service);
    dependency
        .state
        .fail_assignment
        .store(true, Ordering::SeqCst);
    assert!(service
        .begin_asset(&PeerCredentials::local(0, 0))
        .unwrap_err()
        .is("TEST_SUPERVISOR_ASSIGNMENT"));
    assert!(!path.join("membership-checkpoints").exists());
    assert!(!path.join("asset-enrollment").exists());
    assert_eq!(bio.load(Ordering::SeqCst), 0);
    assert_eq!(writes.load(Ordering::SeqCst), 0);
}
#[test]
fn loss_before_ui_after_ui_and_before_ctap_never_spends_the_next_factor() {
    for (fail_at, expected_bio) in [(3, 0), (4, 1), (5, 1)] {
        let root = tests::Root::new();
        let (service, _, _) = tests::fixture(&root);
        let path = root.0.join("state");
        let dependency = Registered::new(path.clone(), fail_at);
        let (bio, writes) = effects(&service);
        assert!(service
            .begin_asset(&PeerCredentials::local(0, 0))
            .unwrap_err()
            .is("TEST_SUPERVISOR_REFUSED"));
        assert_eq!(bio.load(Ordering::SeqCst), expected_bio);
        assert_eq!(writes.load(Ordering::SeqCst), 0);
        assert_eq!(dependency.state.probes.load(Ordering::SeqCst), fail_at);
        assert!(matches!(
            open(&path).unwrap().1.phase,
            Phase::Preparing { .. }
        ));
    }
}
#[test]
fn final_dependency_loss_retains_created_pending_and_no_activation() {
    let root = tests::Root::new();
    let (service, _, authority) = tests::fixture(&root);
    let path = root.0.join("state");
    let dependency = Registered::new(path.clone(), 6);
    let (bio, writes) = effects(&service);
    assert!(service
        .begin_asset(&PeerCredentials::local(0, 0))
        .unwrap_err()
        .is("TEST_SUPERVISOR_REFUSED"));
    assert_eq!(bio.load(Ordering::SeqCst), 1);
    assert!(writes.load(Ordering::SeqCst) > 0);
    assert!(matches!(open(&path).unwrap().1.phase, Phase::Pending(_)));
    assert!(load_native_enrollment(
        &path,
        Some(&authority),
        Profile::L2,
        enclave_crypto::time::now_unix()
    )
    .unwrap()
    .is_none());
    let before = writes.load(Ordering::SeqCst);
    dependency.state.fail_at.store(0, Ordering::SeqCst);
    assert!(matches!(
        service.begin_asset(&PeerCredentials::local(0, 0)).unwrap(),
        VaultResponse::AssetEnrollmentPending { .. }
    ));
    assert_eq!(writes.load(Ordering::SeqCst), before);
    assert_eq!(bio.load(Ordering::SeqCst), 1);
}
#[test]
fn actual_ipc_final_preflight_refuses_stale_pending_reply_and_positive_control_sends() {
    for fail_at in [0, 7] {
        let root = tests::Root::new();
        let (service, _, _) = tests::fixture(&root);
        let path = root.0.join("state");
        let dependency = Registered::new(path.clone(), fail_at);
        // sockaddr_un contains the supplied name, so keep it short even when
        // an immutable-source checkout has a long absolute manifest path.
        let socket =
            PathBuf::from("target").join(format!("asset-gate-{:x}.sock", enclave_core::rng::u64()));
        let listener = UnixListener::bind(&socket).unwrap();
        struct SocketName(PathBuf);
        impl Drop for SocketName {
            fn drop(&mut self) {
                let _ = std::fs::remove_file(&self.0);
            }
        }
        let _socket_name = SocketName(socket.clone());
        let stop = Arc::new(AtomicBool::new(false));
        let server_stop = stop.clone();
        let worker = std::thread::spawn(move || {
            enclave_core::ipc::serve_with_authenticator(
                listener,
                Arc::new(|peer: &PeerCredentials| Ok(peer.clone())),
                enclave_core::ipc::ServeLimits::default(),
                Arc::new(enclave_core::ipc::ServeStats::default()),
                Arc::new(move |_: &PeerCredentials, _: u8| {
                    service.begin_asset(&PeerCredentials::local(0, 0))
                }),
                server_stop,
            )
        });
        let mut client = UnixStream::connect(socket).unwrap();
        client
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        enclave_core::ipc::write_frame(&mut client, &enclave_core::ipc::to_cbor(&1u8).unwrap())
            .unwrap();
        if fail_at == 0 {
            let response = enclave_core::ipc::read_frame(&mut client).unwrap();
            assert!(matches!(
                enclave_core::ipc::from_cbor::<enclave_core::ipc::Reply<VaultResponse>>(&response)
                    .unwrap(),
                enclave_core::ipc::Reply::Ok(VaultResponse::AssetEnrollmentPending { .. })
            ));
        } else {
            use std::io::Read;
            assert_eq!(
                client.read(&mut [0u8; 1]).unwrap(),
                0,
                "stale preflight must emit zero reply bytes"
            );
        }
        drop(client);
        stop.store(true, Ordering::SeqCst);
        worker.join().unwrap().unwrap();
        assert_eq!(dependency.state.probes.load(Ordering::SeqCst), 7);
        assert!(matches!(open(&path).unwrap().1.phase, Phase::Pending(_)));
    }
}
#[test]
fn cached_pending_rechecks_dependency_before_reply_without_creating_another_credential() {
    let root = tests::Root::new();
    let (service, _, _) = tests::fixture(&root);
    let path = root.0.join("state");
    let (bio, writes) = effects(&service);
    service.begin_asset(&PeerCredentials::local(0, 0)).unwrap();
    let before = writes.load(Ordering::SeqCst);
    let _dependency = Registered::new(path, 3);
    assert!(service
        .begin_asset(&PeerCredentials::local(0, 0))
        .unwrap_err()
        .is("TEST_SUPERVISOR_REFUSED"));
    assert_eq!(bio.load(Ordering::SeqCst), 1);
    assert_eq!(writes.load(Ordering::SeqCst), before);
}
