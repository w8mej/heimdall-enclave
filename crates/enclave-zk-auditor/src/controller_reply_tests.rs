//! Real generic IPC response fencing after successful auditor dispatch.
//! Uses a signed software epoch, journal-derived QIF and the production prover.
//! Same-UID peers are owned fixtures, not installed daemon identity evidence.
use super::*;
use enclave_core::ipc::{self, Client, PeerPolicy, Reply, SocketAccess};
use enclave_core::seq::BootEpoch;
use std::io::Read;
use std::os::unix::fs::DirBuilderExt;
use std::os::unix::net::UnixStream;
use std::sync::atomic::AtomicUsize;
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::time::Duration;

#[path = "../tests/support/relay_peer.rs"]
mod relay_peer;

struct Directory(PathBuf);
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct ProofPeers {
    epoch: BootEpoch,
    received: Arc<AtomicUsize>,
}

impl Peers for ProofPeers {
    fn cosign(&self, _: DaemonId, _: u64, _: &str) -> EnclaveResult<(Vec<u8>, Vec<u8>)> {
        panic!("journaled QIF slot must not request a tombstone")
    }
    fn prepare_relay(&self, frame: &[u8]) -> EnclaveResult<PreparedCall> {
        let received = self.received.clone();
        relay_peer::prepare_queued(frame, move |bytes| {
            assert!(
                !bytes.is_empty(),
                "the production proof reached the local relay peer"
            );
            received.fetch_add(1, Ordering::SeqCst);
        })
    }
    fn fetch_witness(
        &self,
        epoch: &str,
        start: u64,
        end: u64,
    ) -> EnclaveResult<(Vec<WitnessFold>, u64)> {
        assert_eq!(epoch, self.epoch.boot_epoch_id);
        assert_eq!((start, end), (1, 1));
        Ok((Vec::new(), 2))
    }
    fn boot_epoch(&self) -> EnclaveResult<BootEpoch> {
        Ok(self.epoch.clone())
    }
}

struct Fixture {
    directory: Directory,
    service: Arc<ZkService>,
    epoch: String,
    received: Arc<AtomicUsize>,
}

impl Fixture {
    fn new() -> Self {
        let target = std::env::temp_dir();
        let directory = Directory(
            target
                .canonicalize()
                .unwrap()
                .join(format!("pr-{:x}", enclave_core::rng::u64())),
        );
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&directory.0)
            .unwrap();
        let epoch = enclave_core::seq::new_boot_epoch_id();
        let signed = enclave_crypto::epoch::EpochSigner::random().sign(&epoch);
        let received = Arc::new(AtomicUsize::new(0));
        let journal_root = directory.0.join("logs");
        let ifc = DaemonId::AgentRuntime;
        let path = journal_root
            .join(ifc.dir_name())
            .join(format!("{}-audit.jsonl", ifc.plist_suffix()));
        let mut journal = AuditJournal::open(&path, ifc, epoch.clone()).unwrap();
        journal
            .append(1, json!({"event":"EXEC_TOOL", "slot":1, "qif_mb":7}))
            .unwrap();
        drop(journal);
        let mut config = ZkConfig::new(Profile::L2, directory.0.join("state"));
        config.audit_path = Some(directory.0.join("auditor.jsonl"));
        config.journal_dir = Some(journal_root);
        config.hardware_batch_anchor_sigs = Some(vec!["3045".into()]);
        config.entity = "caller-response-release-fence".into();
        let service = ZkService::start(
            config,
            Box::new(ProofPeers {
                epoch: signed,
                received: received.clone(),
            }),
        )
        .unwrap();
        Self {
            directory,
            service,
            epoch,
            received,
        }
    }

    fn request(&self) -> ZkRequest {
        ZkRequest::ProveEpoch(Box::new(ProveEpochRequest {
            boot_epoch_id: self.epoch.clone(),
            s_start: 1,
            s_end: 1,
        }))
    }

    fn runtime(&self) -> PausedRuntime {
        // Keep sockets short on the native runner; journal and state fixtures
        // remain in the trusted private state fixture. This owner outlives the
        // listener and serve loop and removes only its own private directory.
        let socket_directory = Directory(
            std::env::temp_dir()
                .canonicalize()
                .unwrap()
                .join(format!("cr-{:x}", enclave_core::rng::u64())),
        );
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&socket_directory.0)
            .unwrap();
        let path = socket_directory.0.join("r");
        let listener = ipc::bind(&path, SocketAccess::OwnerOnly).unwrap();
        let service = self.service.clone();
        let (entered, ready) = mpsc::sync_channel(1);
        let (resume, blocked) = mpsc::sync_channel(1);
        let blocked = Mutex::new(blocked);
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = stop.clone();
        let handler = Arc::new(move |peer: &PeerCredentials, request: ZkRequest| {
            // Keep the permit attached by the actual service dispatch on this
            // exact IPC thread. Pause after handle success, before the generic
            // runtime takes resources, serializes or writes the reply.
            let response = service.handle(peer, request)?;
            let ZkResponse::Proven { frames, relayed, .. } = &response else {
                panic!("fixture dispatch must complete the real proof")
            };
            entered.send((frames.len(), *relayed)).unwrap();
            blocked
                .lock()
                .unwrap()
                .recv_timeout(Duration::from_secs(60))
                .unwrap();
            Ok(response)
        });
        let worker = std::thread::spawn(move || {
            ipc::serve::<ZkRequest, ZkResponse, _>(
                listener,
                PeerPolicy::allow([ipc::geteuid()]),
                handler,
                stopping,
            )
        });
        PausedRuntime {
            path,
            ready,
            resume,
            stop,
            worker: Some(worker),
            _socket_directory: socket_directory,
        }
    }

    fn assert_known_delivery(&self) {
        assert_eq!(self.received.load(Ordering::SeqCst), 1);
        assert_eq!(
            self.service.lock().unwrap().proven.get(&self.epoch),
            Some(&1)
        );
        assert!(!self.service.relay_failed.load(Ordering::SeqCst));
        assert!(!self.service.relay_debt_path.exists());
    }
}

struct PausedRuntime {
    path: PathBuf,
    ready: Receiver<(usize, bool)>,
    resume: SyncSender<()>,
    stop: Arc<AtomicBool>,
    worker: Option<std::thread::JoinHandle<EnclaveResult<()>>>,
    _socket_directory: Directory,
}

impl PausedRuntime {
    fn caller(&self, request: &ZkRequest) -> UnixStream {
        let mut caller = UnixStream::connect(&self.path).unwrap();
        // The raw fixture connection permits counting every reply byte. Check
        // the server's real kernel UID just as the same-UID Client fixture does.
        assert_eq!(ipc::peer_credentials(&caller).unwrap().uid, ipc::geteuid());
        caller
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        caller
            .set_write_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        ipc::write_frame(&mut caller, &ipc::to_cbor(request).unwrap()).unwrap();
        caller
    }
    fn await_proof(&self) {
        assert_eq!(
            self.ready.recv_timeout(Duration::from_secs(60)).unwrap(),
            (1, true)
        );
    }
}

impl Drop for PausedRuntime {
    fn drop(&mut self) {
        let _ = self.resume.try_send(());
        self.stop.store(true, Ordering::SeqCst);
        if let Some(worker) = self.worker.take() {
            assert!(worker.join().unwrap().is_ok());
        }
    }
}

fn root() -> PeerCredentials {
    PeerCredentials::local(0, 0)
}

#[test]
fn caller_proven_reply_queued_after_success_is_fenced_by_wipe_before_generic_runtime_send() {
    let fixture = Fixture::new();
    let runtime = fixture.runtime();
    let mut caller = runtime.caller(&fixture.request());
    runtime.await_proof();
    fixture.assert_known_delivery();
    let previous = fixture.service.release_generation.load(Ordering::SeqCst);
    let state_before = fixture.service.lock().unwrap().j_state;
    fixture.service.handle(&root(), ZkRequest::Wipe).unwrap();
    assert!(fixture.service.release_generation.load(Ordering::SeqCst) > previous);
    runtime.resume.send(()).unwrap();
    let mut wire = Vec::new();
    caller.read_to_end(&mut wire).unwrap();
    assert!(
        wire.is_empty(),
        "no response header, proof byte or success reaches the old caller"
    );
    assert_eq!(
        fixture.service.lock().unwrap().j_state,
        state_before,
        "already acknowledged pre-fence relay progress remains committed"
    );
    fixture.assert_known_delivery();
    let audit = std::fs::read_to_string(fixture.directory.0.join("auditor.jsonl")).unwrap();
    assert_eq!(audit.matches("ROLLUP_PROVEN").count(), 1);
    assert_eq!(audit.matches("WITNESS_WIPED").count(), 1);
}

#[test]
fn caller_proven_reply_completed_before_fence_remains_valid() {
    let fixture = Fixture::new();
    let runtime = fixture.runtime();
    // The typed client independently verifies the actual listening server UID.
    let mut caller = Client::connect(&runtime.path, ipc::geteuid()).unwrap();
    let request = fixture.request();
    let worker = std::thread::spawn(move || caller.call::<_, ZkResponse>(&request));
    runtime.await_proof();
    runtime.resume.send(()).unwrap();
    let ZkResponse::Proven { frames, relayed, .. } = worker.join().unwrap().unwrap() else {
        panic!("completed pre-fence response must remain successful")
    };
    assert!(relayed);
    assert_eq!(frames.len(), 1);
    assert!(!frames[0].is_empty());
    fixture.service.handle(&root(), ZkRequest::Wipe).unwrap();
    fixture.assert_known_delivery();
}

#[test]
fn unauthorized_wipe_cannot_cancel_an_already_prepared_caller_response() {
    let fixture = Fixture::new();
    let runtime = fixture.runtime();
    let mut caller = runtime.caller(&fixture.request());
    runtime.await_proof();
    let generation = fixture.service.release_generation.load(Ordering::SeqCst);
    let uid = if ipc::geteuid() == 703 { 704 } else { 703 };
    let denied = fixture
        .service
        .handle(&PeerCredentials::local(uid, 0), ZkRequest::Wipe)
        .unwrap_err();
    assert!(denied.is("WIPE_PEER_REJECTED"));
    assert_eq!(
        fixture.service.release_generation.load(Ordering::SeqCst),
        generation
    );
    runtime.resume.send(()).unwrap();
    let response =
        ipc::from_cbor::<Reply<ZkResponse>>(&ipc::read_frame(&mut caller).unwrap()).unwrap();
    assert!(matches!(
        response,
        Reply::Ok(ZkResponse::Proven { relayed: true, .. })
    ));
    fixture.assert_known_delivery();
}
