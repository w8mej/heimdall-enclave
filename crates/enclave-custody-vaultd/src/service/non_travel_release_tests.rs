//! Actual service + real IPC final-release fixtures. Software SEP signing and
//! synthetic lock events establish no native/physical cancellation or erasure.
use super::*;
use enclave_core::ipc::{self, PeerPolicy, SocketAccess};
use std::{
    os::unix::{fs::PermissionsExt, net::UnixListener},
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        mpsc,
    },
    time::Duration,
};

const FIXTURE_WAIT: Duration = Duration::from_secs(5);
const URI: &str = "https://example.invalid/yk03/non-travel";
const TOKEN: &str = "synthetic-non-travel-test-token";
#[derive(Clone, Copy, PartialEq, Eq)]
enum Pause {
    None,
    AfterEntry,
    AfterPreparation,
}

struct SocketFixture {
    directory: PathBuf,
}
impl SocketFixture {
    fn bind() -> (Self, PathBuf, UnixListener) {
        let directory = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target")
            .join(format!("nt-{:x}", enclave_core::rng::u64()));
        std::fs::create_dir_all(&directory).unwrap();
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        let directory = directory.canonicalize().unwrap();
        // Keep the actual AF_UNIX address within the native path limit.
        let current = std::env::current_dir().unwrap();
        let from: Vec<_> = current.components().collect();
        let to: Vec<_> = directory.components().collect();
        let common = from.iter().zip(&to).take_while(|(a, b)| a == b).count();
        let mut relative = PathBuf::new();
        for _ in common..from.len() {
            relative.push("..");
        }
        for part in &to[common..] {
            relative.push(part.as_os_str());
        }
        let socket = relative.join("n.sock");
        let listener = ipc::bind(&socket, SocketAccess::OwnerOnly).unwrap();
        (Self { directory }, socket, listener)
    }
}
impl Drop for SocketFixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}
fn service() -> Arc<VaultService> {
    VaultService::start(
        VaultConfig {
            profile: Profile::L1,
            ..Default::default()
        },
        VaultHardware::simulated(Profile::L1, enclave_crypto::time::now_unix()).unwrap(),
    )
    .unwrap()
}
fn generation(service: &VaultService) -> u64 {
    service.cas_key_generation.load(Ordering::SeqCst)
}
fn complete_fence(service: &VaultService) {
    let before = generation(service);
    let reply = service
        .handle(
            &PeerCredentials::local(ipc::geteuid(), 0),
            VaultRequest::Tamper(TamperEvent::ScreenLock),
        )
        .unwrap();
    assert!(matches!(reply, VaultResponse::Zeroized(_)));
    assert_eq!(generation(service), before + 1);
    assert!(service.ceremony_cancelled.load(Ordering::SeqCst));
}

// The actual handler must complete one real DPoP operation even when final
// release is refused. Counting that completion prevents a blanket early refusal
// or a broken socket fixture from satisfying the cancellation assertions.
fn wire_dpop(
    service: &Arc<VaultService>,
    pause: Pause,
    during: impl FnOnce(&VaultService),
) -> (EnclaveResult<VaultResponse>, usize) {
    let (_fixture, socket, listener) = SocketFixture::bind();
    let stop = Arc::new(AtomicBool::new(false));
    let stopped = stop.clone();
    let completed = Arc::new(AtomicUsize::new(0));
    let count = completed.clone();
    let actual = service.clone();
    let (entered, ready) = mpsc::channel();
    let (release, wait) = mpsc::channel();
    let wait = Mutex::new(Some(wait));
    let server = std::thread::spawn(move || {
        ipc::serve(
            listener,
            PeerPolicy::allow([ipc::geteuid()]),
            Arc::new(move |peer: &PeerCredentials, request: VaultRequest| {
                if pause == Pause::AfterEntry {
                    let entered = entered.clone();
                    let wait = wait.lock().unwrap().take().expect("one fixture request");
                    // Existing production-code scheduling seam: after the SAME
                    // request-entry generation capture, before actual dispatch.
                    AFTER_PREFLIGHT.with(|slot| {
                        *slot.borrow_mut() = Some(Box::new(move || {
                            entered.send(()).unwrap();
                            wait.recv_timeout(FIXTURE_WAIT).unwrap();
                        }))
                    });
                }
                let result = actual.handle(peer, request);
                if matches!(&result, Ok(VaultResponse::DpopProof(_))) {
                    count.fetch_add(1, Ordering::SeqCst);
                }
                if pause == Pause::AfterPreparation {
                    entered.send(()).unwrap();
                    wait.lock()
                        .unwrap()
                        .take()
                        .expect("one fixture request")
                        .recv_timeout(FIXTURE_WAIT)
                        .unwrap();
                }
                result
            }),
            stopped,
        )
    });
    let client = std::thread::spawn(move || {
        let mut client = ipc::Client::connect(&socket, ipc::geteuid())?;
        client.set_timeout(Some(FIXTURE_WAIT))?;
        client.call::<_, VaultResponse>(&VaultRequest::CreateDpopProof {
            htm: "POST".into(),
            htu: URI.into(),
            access_token: Some(TOKEN.into()),
        })
    });
    if pause != Pause::None {
        ready.recv_timeout(FIXTURE_WAIT).unwrap();
        during(service);
        release.send(()).unwrap();
    }
    let result = client.join().unwrap();
    stop.store(true, Ordering::SeqCst);
    server.join().unwrap().unwrap();
    (result, completed.load(Ordering::SeqCst))
}

#[test]
fn non_travel_real_dpop_positive_completes_before_fence_and_completed_proof_stands() {
    let service = service();
    let jwk = service.lock_ceremony().unwrap().hw.sep.dpop_public_jwk();
    let thumbprint = enclave_crypto::dpop::jwk_thumbprint(&jwk).unwrap();
    let (reply, completed) = wire_dpop(&service, Pause::None, |_| {});
    let proof = match reply.unwrap() {
        VaultResponse::DpopProof(proof) => proof,
        _ => panic!("wrong response"),
    };
    assert_eq!(completed, 1);
    enclave_crypto::dpop::verify_egress_dpop(
        &proof,
        "POST",
        URI,
        Some(TOKEN),
        Some(&thumbprint),
        enclave_crypto::time::now_unix(),
    )
    .unwrap();
    complete_fence(&service);
    // Completed pre-fence bytes/signatures are real effects. A new verifier
    // still verifies them; cancellation cannot retroactively recall the proof.
    enclave_crypto::dpop::verify_egress_dpop(
        &proof,
        "POST",
        URI,
        Some(TOKEN),
        Some(&thumbprint),
        enclave_crypto::time::now_unix(),
    )
    .unwrap();
}
#[test]
fn non_travel_inflight_dpop_cannot_adopt_generation_after_completed_tamper() {
    for fences in [1, 2] {
        let service = service();
        let original = generation(&service);
        let (reply, completed) = wire_dpop(&service, Pause::AfterEntry, |service| {
            for _ in 0..fences {
                complete_fence(service);
            }
        });
        assert_eq!(completed, 1, "actual signing/handler must run exactly once");
        assert_eq!(generation(&service), original + fences);
        assert!(
            reply.is_err(),
            "old in-flight request cannot take a later fence generation"
        );
    }
}
#[test]
fn non_travel_prepared_dpop_cannot_cross_later_completed_fence() {
    let service = service();
    let original = generation(&service);
    let (reply, completed) = wire_dpop(&service, Pause::AfterPreparation, complete_fence);
    assert_eq!(completed, 1);
    assert_eq!(generation(&service), original + 1);
    assert!(
        reply.is_err(),
        "already prepared old-generation permit must still refuse"
    );
}
