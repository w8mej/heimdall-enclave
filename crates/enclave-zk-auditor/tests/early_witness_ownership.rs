//! Public early-return ownership oracles using System, without daemon allocator wiping.
//!
//! Observations occur immediately BEFORE System.dealloc, while allocations remain
//! live. No freed storage is read. Decoder growth reallocations, partial decoding,
//! stack scratch, other witness copies and physical erasure are outside this test.
use enclave_core::{daemon::DaemonId, err, ipc::{self, PeerCredentials}, profile::Profile,
    seq::BootEpoch, EnclaveResult};
use enclave_zk_auditor::{service::{Peers, ProveEpochRequest, ZkConfig, ZkRequest, ZkResponse, ZkService},
    witness::{serve_witness_channel_with_mode_and_admission, WitnessChannelRequest,
        WitnessChannelResponse, WitnessFold}};
use std::{alloc::{GlobalAlloc, Layout, System}, cell::Cell, fs,
    io::{Read, Write}, os::unix::{fs::DirBuilderExt, net::{UnixListener, UnixStream}},
    path::{Path, PathBuf}, sync::{Arc, atomic::{AtomicBool, AtomicUsize, Ordering}, mpsc},
    thread::JoinHandle, time::{Duration, Instant}};

const MARKER: u8 = 0x6d;
const FETCH_BYTES: usize = 16 * 1024;
const CACHE_FOLDS: usize = 320;
const CACHE_BYTES: usize = 64 * 1024;
const WAIT: Duration = Duration::from_secs(5);

#[derive(Clone, Copy, Default)]
struct Target {
    address: usize,
    initialized: usize,
    expected: u8,
    frees: usize,
    zero_frees: usize,
    marker_frees: usize,
}

#[derive(Clone, Copy)]
struct Observation {
    enabled: bool,
    payload_size: usize,
    raw_frame_size: usize,
    frame_started: usize,
    payload_allocations: usize,
    targets: [Target; 3],
    invalid: bool,
}

impl Observation {
    const EMPTY: Self = Self { enabled: false, payload_size: 0, raw_frame_size: 0,
        frame_started: 0, payload_allocations: 0, targets: [Target {
            address: 0, initialized: 0, expected: 0, frees: 0, zero_frees: 0, marker_frees: 0,
        }; 3], invalid: false };

    fn allocation(&mut self, pointer: *mut u8, size: usize) {
        if size == self.raw_frame_size && self.frame_started != 0 {
            // The worker owns an Arc keeping this AtomicBool live until tracking
            // ends. Only its numeric address is stored in allocation-free TLS.
            unsafe { &*(self.frame_started as *const AtomicBool) }.store(true, Ordering::SeqCst);
        }
        if self.payload_size != 0 && size == self.payload_size {
            self.payload_allocations = match self.payload_allocations.checked_add(1) {
                Some(next) => next,
                None => { self.invalid = true; return; }
            };
            if self.payload_allocations != 1 { self.invalid = true; return; }
            self.targets[0] = Target { address: pointer as usize, initialized: size,
                expected: MARKER, ..Target::default() };
        }
    }

    unsafe fn before_free(&mut self, pointer: *mut u8, size: usize) {
        for target in &mut self.targets {
            // An address may later be reused for an unrelated allocation. The
            // selected owner's first deallocation consumes this observation.
            if target.address == 0 || target.address != pointer as usize || target.frees != 0 { continue; }
            if target.initialized > size {
                self.invalid = true;
                continue;
            }
            // The allocator callback owns this still-live allocation. Fetched
            // ranges were initialized by the fixture; listener allocations and
            // realloc growth tails were explicitly initialized below.
            let bytes = unsafe { std::slice::from_raw_parts(pointer, target.initialized) };
            target.frees += 1;
            target.zero_frees += usize::from(bytes.iter().all(|byte| *byte == 0));
            target.marker_frees += usize::from(bytes.iter().all(|byte| *byte == target.expected));
        }
    }
}

thread_local! {
    static OBSERVATION: Cell<Observation> = const { Cell::new(Observation::EMPTY) };
}

struct ObservedSystem;

// This integration binary deliberately does not install WipingAllocator. Its
// allocator initializes storage on allocation, never wipes it on deallocation.
unsafe impl GlobalAlloc for ObservedSystem {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() {
            let _ = OBSERVATION.try_with(|cell| {
                let mut observation = cell.get();
                if observation.enabled {
                    unsafe { std::ptr::write_bytes(pointer, 0, layout.size()) };
                    observation.allocation(pointer, layout.size());
                    cell.set(observation);
                }
            });
        }
        pointer
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc_zeroed(layout) };
        if !pointer.is_null() {
            let _ = OBSERVATION.try_with(|cell| {
                let mut observation = cell.get();
                if observation.enabled {
                    observation.allocation(pointer, layout.size());
                    cell.set(observation);
                }
            });
        }
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        let _ = OBSERVATION.try_with(|cell| {
            let mut observation = cell.get();
            if observation.enabled {
                unsafe { observation.before_free(pointer, layout.size()) };
                cell.set(observation);
            }
        });
        unsafe { System.dealloc(pointer, layout) };
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        let _ = OBSERVATION.try_with(|cell| {
            let mut observation = cell.get();
            if observation.enabled && observation.targets.iter().any(|target|
                target.address != 0 && target.address == pointer as usize && target.frees == 0)
            {
                // Neither selected final decoded payloads nor fetched fields
                // should reallocate. Do not classify an unexpected path as a pass.
                observation.invalid = true;
                cell.set(observation);
            }
        });
        let resized = unsafe { System.realloc(pointer, layout, size) };
        if !resized.is_null() {
            let _ = OBSERVATION.try_with(|cell| {
                let mut observation = cell.get();
                if observation.enabled {
                    if size > layout.size() {
                        // Preserve all existing decoded bytes. Only the new tail
                        // is initialized; this does not erase prior realloc copies.
                        unsafe { std::ptr::write_bytes(resized.add(layout.size()), 0, size - layout.size()) };
                    }
                    observation.allocation(resized, size);
                    cell.set(observation);
                }
            });
        }
        resized
    }
}

#[global_allocator]
static ALLOCATOR: ObservedSystem = ObservedSystem;

struct Tracking;
impl Tracking {
    fn start(payload_size: usize, raw_frame_size: usize, frame_started: Option<&AtomicBool>) -> Self {
        OBSERVATION.with(|cell| {
            assert!(!cell.get().enabled);
            cell.set(Observation { enabled: true, payload_size, raw_frame_size,
                frame_started: frame_started.map_or(0, |value| value as *const AtomicBool as usize),
                ..Observation::EMPTY });
        });
        Self
    }
    fn finish(self) -> Observation {
        let observation = OBSERVATION.with(Cell::get);
        drop(self);
        observation
    }
}
impl Drop for Tracking {
    fn drop(&mut self) { OBSERVATION.with(|cell| cell.set(Observation::EMPTY)); }
}

fn register_fetched(fold: &WitnessFold) {
    OBSERVATION.with(|cell| {
        let mut observation = cell.get();
        assert!(observation.enabled && observation.payload_size == 0);
        assert!(observation.targets.iter().all(|target| target.address == 0));
        observation.targets = [
            Target { address: fold.scrubbed.as_ptr() as usize, initialized: fold.scrubbed.len(), expected: MARKER, ..Target::default() },
            Target { address: fold.c_raw.as_ptr() as usize, initialized: fold.c_raw.len(), expected: b'a', ..Target::default() },
            Target { address: fold.h_ingress_mac.as_ptr() as usize, initialized: fold.h_ingress_mac.len(), expected: b'b', ..Target::default() },
        ];
        cell.set(observation);
    });
}

fn assert_erased(observation: Observation, targets: usize) {
    assert!(!observation.invalid, "allocator observations must remain exact and initialized");
    for target in &observation.targets[..targets] {
        assert_ne!(target.address, 0, "selected allocation was never observed");
        assert_eq!(target.frees, 1, "selected owner must actually be freed exactly once");
    }
    let zero: usize = observation.targets[..targets].iter().map(|target| target.zero_frees).sum();
    let marker: usize = observation.targets[..targets].iter().map(|target| target.marker_frees).sum();
    println!("EARLY_WITNESS_LIVE_FREE targets={targets} zero={zero} unchanged_marker={marker} invalid=false");
    assert_eq!(zero, targets, "selected witness owner must be zero before System.dealloc");
    assert_eq!(marker, 0, "witness marker must not survive owner teardown");
}

struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let path = std::env::temp_dir().canonicalize().unwrap().join(format!(
            "ew{}-{:x}", std::process::id(), enclave_core::rng::u64() & 0xfffffff));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }
    fn remove(self) {
        fs::remove_dir_all(&self.0).unwrap();
        assert!(!self.0.exists(), "owned fixture cleanup failed");
    }
}
impl Drop for Directory { fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); } }

fn fold(slot: u64, bytes: usize) -> WitnessFold {
    WitnessFold { rpc_seq_u64: slot, scrubbed: vec![MARKER; bytes],
        c_raw: "a".repeat(64), h_ingress_mac: "b".repeat(64) }
}
fn operator() -> PeerCredentials { PeerCredentials::local(ipc::geteuid(), unsafe { libc::getegid() }) }
fn capacity(service: &ZkService) -> (usize, usize, usize) {
    let ZkResponse::Status(status) = service.handle(&operator(), ZkRequest::Status).unwrap()
        else { panic!("actual Status response required") };
    let value = |key: &str| status.state.split_whitespace()
        .find_map(|part| part.strip_prefix(key)).unwrap().parse::<usize>().unwrap();
    (value("witness_registered_capacity="), value("witness_retained_capacity="), value("witness_capacity_limit="))
}

struct FetchedPeers {
    epoch: BootEpoch,
    fetched: Arc<AtomicUsize>,
    relays: Arc<AtomicUsize>,
}
impl Peers for FetchedPeers {
    fn cosign(&self, _: DaemonId, _: u64, _: &str) -> EnclaveResult<(Vec<u8>, Vec<u8>)> {
        panic!("early-refusal fixture must never cosign")
    }
    fn prepare_relay(&self, _: &[u8]) -> EnclaveResult<ipc::PreparedCall> {
        self.relays.fetch_add(1, Ordering::SeqCst);
        Err(err!(EIO, "FIXTURE_UNEXPECTED_RELAY"))
    }
    fn fetch_witness(&self, epoch: &str, start: u64, end: u64) -> EnclaveResult<(Vec<WitnessFold>, u64)> {
        assert_eq!(epoch, self.epoch.boot_epoch_id);
        assert_eq!(start, 1);
        assert!(end == 1 || end == CACHE_FOLDS as u64);
        self.fetched.fetch_add(1, Ordering::SeqCst);
        let witness = fold(1, FETCH_BYTES);
        register_fetched(&witness);
        Ok((vec![witness], CACHE_FOLDS as u64 + 1))
    }
    fn boot_epoch(&self) -> EnclaveResult<BootEpoch> { Ok(self.epoch.clone()) }
}

fn fetched_oracle(cache_full: bool) {
    let directory = Directory::new();
    let epoch = enclave_core::seq::new_boot_epoch_id();
    let fetched = Arc::new(AtomicUsize::new(0));
    let relays = Arc::new(AtomicUsize::new(0));
    let mut config = ZkConfig::new(Profile::L2, directory.0.join("state"));
    config.journal_dir = Some(directory.0.join("logs"));
    let service = ZkService::start(config, Box::new(FetchedPeers {
        epoch: enclave_crypto::epoch::EpochSigner::random().sign(&epoch),
        fetched: fetched.clone(), relays: relays.clone(),
    })).unwrap();
    if cache_full {
        service.ingest_witnesses(&epoch, (1..=CACHE_FOLDS as u64)
            .map(|slot| fold(slot, CACHE_BYTES)).collect()).unwrap();
    }
    let before = capacity(&service);
    if cache_full {
        assert!(before.0 >= CACHE_FOLDS * CACHE_BYTES && before.0 < before.2);
        assert!(before.0.checked_add(CACHE_FOLDS * CACHE_BYTES).unwrap() > before.2);
    } else { assert_eq!(before.0, 0); }
    let tracking = Tracking::start(0, 0, None);
    let result = service.handle(&operator(), ZkRequest::ProveEpoch(Box::new(ProveEpochRequest {
        boot_epoch_id: epoch, s_start: 1, s_end: if cache_full { CACHE_FOLDS as u64 } else { 1 },
    })));
    let observation = tracking.finish();
    let error = result.unwrap_err();
    assert!(error.is(if cache_full { "WITNESS_CAPACITY_FULL" } else { "WITNESS_UNJOURNALED" }), "{error}");
    assert_eq!(fetched.load(Ordering::SeqCst), 1);
    assert_eq!(relays.load(Ordering::SeqCst), 0);
    assert_eq!(capacity(&service), before, "refusal must preserve registered cache capacity");
    assert!(!directory.0.join("state/proof-release.pending").exists());
    assert!(!directory.0.join("state/proof-fence-audit.pending").exists());
    service.handle(&operator(), ZkRequest::Wipe).unwrap();
    assert_eq!(capacity(&service).0, 0, "authorized cleanup must release cache ownership");
    drop(service);
    directory.remove();
    println!("EARLY_FETCH_REFUSAL cache_full={cache_full} fetched=1 relays=0 capacity_preserved=true owned_cleanup=true");
    assert_erased(observation, 3);
}

#[test]
fn fetched_snapshot_capacity_refusal_erases_three_owners() { fetched_oracle(true); }
#[test]
fn fetched_later_journal_refusal_erases_three_owners_control() { fetched_oracle(false); }

struct NoPeers;
impl Peers for NoPeers {
    fn cosign(&self, _: DaemonId, _: u64, _: &str) -> EnclaveResult<(Vec<u8>, Vec<u8>)> { panic!("no cosign") }
    fn prepare_relay(&self, _: &[u8]) -> EnclaveResult<ipc::PreparedCall> { panic!("no relay") }
    fn fetch_witness(&self, _: &str, _: u64, _: u64) -> EnclaveResult<(Vec<WitnessFold>, u64)> { panic!("no fetch") }
    fn boot_epoch(&self) -> EnclaveResult<BootEpoch> { panic!("no epoch") }
}

struct Server {
    directory: Directory,
    path: PathBuf,
    stop: Arc<AtomicBool>,
    started: Arc<AtomicBool>,
    admitted: Arc<AtomicUsize>,
    done: mpsc::Receiver<()>,
    worker: Option<JoinHandle<(EnclaveResult<()>, Observation)>>,
}
impl Server {
    fn start(payload_size: usize, raw_frame_size: usize, refuse_first: bool) -> Self {
        let directory = Directory::new();
        let path = directory.0.join("w");
        let listener = UnixListener::bind(&path).unwrap();
        let service = ZkService::start(ZkConfig::new(Profile::L2, directory.0.join("state")), Box::new(NoPeers)).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = stop.clone();
        let started = Arc::new(AtomicBool::new(false));
        let worker_started = started.clone();
        let admitted = Arc::new(AtomicUsize::new(0));
        let worker_admitted = admitted.clone();
        let (sender, done) = mpsc::sync_channel(1);
        let worker = std::thread::spawn(move || {
            let tracking = Tracking::start(payload_size, raw_frame_size, Some(&worker_started));
            let result = serve_witness_channel_with_mode_and_admission(
                listener, service, worker_stop, true, move || {
                    let call = worker_admitted.fetch_add(1, Ordering::SeqCst);
                    if refuse_first && call == 0 { return Err(err!(EACCES, "FIXTURE_ADMISSION_REFUSED")); }
                    Ok(())
                });
            // The sole service Arc was consumed above: accepted cache allocations
            // have also been torn down on this observed worker before inspection.
            let observation = tracking.finish();
            let _ = sender.send(());
            (result, observation)
        });
        Self { directory, path, stop, started, admitted, done, worker: Some(worker) }
    }

    fn finish(mut self) -> (Observation, usize) {
        self.stop.store(true, Ordering::SeqCst);
        let prompt = self.done.recv_timeout(WAIT).is_ok();
        if !prompt { let _ = UnixStream::connect(&self.path); }
        let (result, observation) = self.worker.take().unwrap().join().unwrap();
        let admitted = self.admitted.load(Ordering::SeqCst);
        result.unwrap();
        assert!(prompt, "owned listener failed bounded shutdown");
        fs::remove_dir_all(&self.directory.0).unwrap();
        assert!(!self.directory.0.exists(), "owned server cleanup failed");
        (observation, admitted)
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        if let Some(worker) = self.worker.take() {
            self.stop.store(true, Ordering::SeqCst);
            let _ = UnixStream::connect(&self.path);
            let _ = worker.join();
        }
    }
}

fn request(payload: usize, slot: u64) -> Vec<u8> {
    let mut body = Vec::new();
    ciborium::into_writer(&WitnessChannelRequest::StreamWitness {
        boot_epoch_id: enclave_core::seq::new_boot_epoch_id(), folds: vec![fold(slot, payload)],
    }, &mut body).unwrap();
    body
}
fn connect(path: &Path) -> UnixStream {
    let stream = UnixStream::connect(path).unwrap();
    stream.set_nonblocking(false).unwrap();
    stream.set_read_timeout(Some(WAIT)).unwrap();
    stream.set_write_timeout(Some(WAIT)).unwrap();
    stream
}
fn send(stream: &mut UnixStream, body: &[u8]) {
    stream.write_all(&(body.len() as u32).to_be_bytes()).unwrap();
    stream.write_all(body).unwrap();
}
fn ack(stream: &mut UnixStream) -> bool {
    let mut header = [0; 4];
    if stream.read_exact(&mut header).is_err() { return false; }
    let length = u32::from_be_bytes(header) as usize;
    assert!(length <= 1024, "unexpected fixture response bound");
    let mut body = vec![0; length];
    stream.read_exact(&mut body).unwrap();
    matches!(ciborium::from_reader::<WitnessChannelResponse, _>(body.as_slice()), Ok(WitnessChannelResponse::Ack))
}

fn listener_refusal(payload: usize, stop_after_start: bool) {
    let body = request(payload, 1);
    assert!(body.len() > payload && body.len() < ipc::MAX_FRAME);
    let server = Server::start(payload, body.len(), !stop_after_start);
    let mut stream = connect(&server.path);
    if stop_after_start {
        // Header arrival causes the raw frame allocation. That exact allocator
        // event proves the server entered its current frame read before stop.
        stream.write_all(&(body.len() as u32).to_be_bytes()).unwrap();
        stream.write_all(&body[..1]).unwrap();
        let deadline = Instant::now() + WAIT;
        while !server.started.load(Ordering::SeqCst) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(1));
        }
        assert!(server.started.load(Ordering::SeqCst), "raw frame read was never established");
        server.stop.store(true, Ordering::SeqCst);
        stream.write_all(&body[1..]).unwrap();
    } else { send(&mut stream, &body); }
    assert!(!ack(&mut stream), "refused decoded request must not receive Ack");
    drop(stream);
    if !stop_after_start {
        let small = request(19, 2);
        let mut recovery = connect(&server.path);
        send(&mut recovery, &small);
        assert!(ack(&mut recovery), "next valid request must recover after admission refusal");
    }
    let (observation, admitted) = server.finish();
    assert_eq!(admitted, if stop_after_start { 0 } else { 2 });
    assert_eq!(observation.payload_allocations, 1, "exactly one final decoded payload allocation must be observed");
    println!("EARLY_LISTENER_REFUSAL payload={payload} stop_after_frame_start={stop_after_start} admitted={admitted} no_ack=true cleanup=true");
    assert_erased(observation, 1);
}

#[test]
fn listener_admission_refusal_erases_decoded_16k() { listener_refusal(16 * 1024, false); }
#[test]
fn listener_admission_refusal_erases_decoded_64k() { listener_refusal(64 * 1024, false); }
#[test]
fn listener_stop_after_frame_start_erases_decoded_16k() { listener_refusal(16 * 1024, true); }
#[test]
fn listener_stop_after_frame_start_erases_decoded_64k() { listener_refusal(64 * 1024, true); }

#[test]
fn listener_success_transfers_decoded_owner_and_erases_on_teardown_control() {
    let payload = 16 * 1024;
    let body = request(payload, 1);
    let server = Server::start(payload, body.len(), false);
    let mut stream = connect(&server.path);
    send(&mut stream, &body);
    assert!(ack(&mut stream), "healthy request must pass actual ingestion and Ack");
    drop(stream);
    let (observation, admitted) = server.finish();
    assert_eq!(admitted, 1);
    assert_eq!(observation.payload_allocations, 1);
    println!("EARLY_LISTENER_TRANSFER payload={payload} ack=true admitted=1 sole_service_teardown=true cleanup=true");
    assert_erased(observation, 1);
}
