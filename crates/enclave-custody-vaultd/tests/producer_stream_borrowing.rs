//! Public producer allocation-request and real-wire ownership regressions.
//! Synthetic software hardware only; no RSS, installed identity or retirement claim.
use enclave_core::{daemon::WITNESS_SOCKET_NAME, ipc::{self, PeerCredentials}, profile::Profile};
use enclave_custody_vaultd::{ingress::{WitnessChannelRequest, WitnessChannelResponse, WitnessFold},
    service::{VaultConfig, VaultHardware, VaultRequest, VaultResponse, VaultService}};
use std::{alloc::{GlobalAlloc, Layout, System}, cell::Cell, fs,
    os::unix::{fs::DirBuilderExt, net::UnixListener}, path::PathBuf, sync::Arc,
    time::{Duration, Instant}};

#[derive(Clone, Copy, Default, Debug)]
struct Requests { enabled: bool, payload: usize, exact: usize, total: usize, max: usize, overflow: bool }
thread_local! { static REQUESTS: Cell<Requests> = const { Cell::new(Requests {
    enabled: false, payload: 0, exact: 0, total: 0, max: 0, overflow: false,
}) }; }
struct MeasuredAllocator;
fn observe(bytes: usize) {
    // One fixed, allocation-free TLS cell. Never panic or allocate in callbacks.
    let _ = REQUESTS.try_with(|cell| {
        let mut value = cell.get();
        if value.enabled {
            value.max = value.max.max(bytes);
            match value.total.checked_add(bytes) {
                Some(total) => value.total = total,
                None => value.overflow = true,
            }
            if bytes == value.payload {
                match value.exact.checked_add(1) {
                    Some(exact) => value.exact = exact,
                    None => value.overflow = true,
                }
            }
            cell.set(value);
        }
    });
}
unsafe impl GlobalAlloc for MeasuredAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        observe(layout.size()); unsafe { System.alloc(layout) }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        observe(layout.size()); unsafe { System.alloc_zeroed(layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        observe(size); unsafe { System.realloc(ptr, layout, size) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) { unsafe { System.dealloc(ptr, layout) } }
}
#[global_allocator]
static ALLOCATOR: MeasuredAllocator = MeasuredAllocator;
struct Tracking;
impl Tracking {
    fn start(payload: usize) -> Self {
        REQUESTS.with(|cell| {
            assert!(!cell.get().enabled, "tracking must not nest");
            cell.set(Requests { enabled: true, payload, ..Requests::default() });
        });
        Self
    }
    fn finish(self) -> Requests { drop(self); REQUESTS.with(Cell::get) }
}
impl Drop for Tracking {
    fn drop(&mut self) { REQUESTS.with(|cell| { let mut value = cell.get(); value.enabled = false; cell.set(value); }); }
}

struct Directory(Option<PathBuf>);
impl Directory {
    fn new() -> Self {
        let path = std::env::temp_dir().canonicalize().unwrap()
            .join(format!("pb{}-{:x}", std::process::id(), enclave_core::rng::u64() & 0xfffffff));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(Some(path))
    }
    fn path(&self) -> &std::path::Path { self.0.as_ref().unwrap() }
    fn remove(mut self) {
        let path = self.0.as_ref().unwrap();
        fs::remove_dir_all(path).unwrap();
        assert!(!path.exists(), "owned cleanup must finish before terminal oracle");
        self.0.take();
    }
}
impl Drop for Directory {
    fn drop(&mut self) { if let Some(path) = &self.0 { let _ = fs::remove_dir_all(path); } }
}
struct Fixture { service: Arc<VaultService>, directory: Directory, peer: PeerCredentials, epoch: String }
impl Fixture {
    fn new(configured: bool) -> Self {
        let directory = Directory::new();
        let service = VaultService::start(VaultConfig { profile: Profile::L2,
            socket_dir: configured.then(|| directory.path().to_owned()), dev_same_uid: true,
            ..VaultConfig::default() },
            VaultHardware::simulated(Profile::L2, enclave_crypto::time::now_unix()).unwrap()).unwrap();
        let peer = PeerCredentials::local(ipc::geteuid(), unsafe { libc::getegid() });
        let VaultResponse::Epoch(epoch) = service.handle(&peer, VaultRequest::BootEpoch).unwrap()
            else { panic!("epoch response required"); };
        Self { service, directory, peer, epoch: epoch.boot_epoch_id }
    }
    fn scrub(&self, text: String) -> enclave_core::EnclaveResult<VaultResponse> {
        self.service.handle(&self.peer, VaultRequest::ScrubText { text, bulk_set: false, grant: None })
    }
    fn fetch(&self) -> (Vec<WitnessFold>, u64) {
        let VaultResponse::Witness { folds, next_slot } = self.service.handle(&self.peer,
            VaultRequest::FetchWitness { boot_epoch_id: self.epoch.clone(), s_start: 0, s_end: u64::MAX }).unwrap()
            else { panic!("authorized witness response required"); };
        (folds, next_slot)
    }
    fn finish(self) { let Self { service, directory, .. } = self; drop(service); directory.remove(); }
}
fn is_hex64(text: &str) -> bool { text.len() == 64 && text.bytes().all(|b| b.is_ascii_hexdigit()) }
fn measured_absent(configured: bool, bytes: usize) -> Requests {
    let fixture = Fixture::new(configured);
    assert!(!fixture.directory.path().join(WITNESS_SOCKET_NAME).exists());
    // Equal queue occupancy and lazy scanner/Poseidon/RNG initialization outside tracking.
    assert!(matches!(fixture.scrub(String::new()).unwrap(), VaultResponse::Text(ref text) if text.is_empty()));
    let text = "x".repeat(bytes);
    let tracking = Tracking::start(bytes);
    let response = fixture.scrub(text);
    let requests = tracking.finish();
    assert!(!requests.enabled && !requests.overflow, "invalid allocation measurement");
    assert!(matches!(response.unwrap(), VaultResponse::Text(ref text)
        if text.len() == bytes && text.bytes().all(|b| b == b'x')), "successful ordinary release required");
    let (folds, next_slot) = fixture.fetch();
    assert_eq!(folds.len(), 2, "warm and measured unproved folds must remain retained");
    assert!(folds[0].scrubbed.is_empty());
    assert!(folds[1].scrubbed.len() == bytes && folds[1].scrubbed.iter().all(|b| *b == b'x'));
    assert!(folds[0].rpc_seq_u64 < folds[1].rpc_seq_u64 && next_slot > folds[1].rpc_seq_u64);
    assert!(folds.iter().all(|fold| is_hex64(&fold.c_raw) && is_hex64(&fold.h_ingress_mac)));
    assert!(!fixture.directory.path().join(WITNESS_SOCKET_NAME).exists());
    drop(folds);
    fixture.finish();
    requests
}
fn absent_payload_oracle(bytes: usize) {
    // TLS and synthetic RNG initialized before either measured public call.
    REQUESTS.with(|cell| assert!(!cell.get().enabled));
    let _ = enclave_core::rng::u64();
    let none = measured_absent(false, bytes);
    let absent = measured_absent(true, bytes);
    println!("PRODUCER_STREAM_PAYLOAD_REQUESTS bytes={bytes} none_exact={} configured_absent_exact={} none_total={} configured_absent_total={} none_max={} configured_absent_max={} output_retention_setup_cleanup_valid=true",
        none.exact, absent.exact, none.total, absent.total, none.max, absent.max);
    assert!(none.exact > 0 && absent.exact > 0, "payload requests must actually be observed");
    assert_eq!(absent.exact, none.exact,
        "configured absent listener must not add an owned payload allocation");
}
#[test]
fn producer_configured_absent_stream_16k_has_no_extra_payload_owner() { absent_payload_oracle(16 * 1024); }
#[test]
fn producer_configured_absent_stream_64k_has_no_extra_payload_owner() { absent_payload_oracle(64 * 1024); }

#[test]
fn producer_streamed_fold_matches_authorized_local_retention() {
    let fixture = Fixture::new(true);
    let path = fixture.directory.path().join(WITNESS_SOCKET_NAME);
    fs::DirBuilder::new().recursive(true).mode(0o700).create(path.parent().unwrap()).unwrap();
    let listener = UnixListener::bind(&path).unwrap();
    listener.set_nonblocking(true).unwrap();
    let worker = std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut connection = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock && Instant::now() < deadline =>
                    std::thread::sleep(Duration::from_millis(2)),
                Err(error) => panic!("owned receiver accept: {error}"),
            }
        };
        connection.set_nonblocking(false).unwrap();
        connection.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        connection.set_write_timeout(Some(Duration::from_secs(3))).unwrap();
        let body = ipc::read_frame(&mut connection).unwrap();
        let request: WitnessChannelRequest = ciborium::from_reader(body.as_slice()).unwrap();
        let mut ack = Vec::new();
        ciborium::into_writer(&WitnessChannelResponse::Ack, &mut ack).unwrap();
        // Ack before any producer FetchWitness: producer holds State during stream.
        ipc::write_frame(&mut connection, &ack).unwrap();
        request
    });
    let response = fixture.scrub("x".repeat(16 * 1024));
    let received = worker.join().unwrap();
    assert!(matches!(response.unwrap(), VaultResponse::Text(ref text)
        if text.len() == 16 * 1024 && text.bytes().all(|b| b == b'x')));
    let WitnessChannelRequest::StreamWitness { boot_epoch_id, folds: received } = received
        else { panic!("actual StreamWitness required"); };
    assert!(boot_epoch_id == fixture.epoch, "same service epoch must cross actual wire");
    let (retained, next_slot) = fixture.fetch();
    assert_eq!((received.len(), retained.len()), (1, 1));
    let (wire, local) = (&received[0], &retained[0]);
    assert!(wire.rpc_seq_u64 == local.rpc_seq_u64 && next_slot > local.rpc_seq_u64);
    assert!(wire.scrubbed == local.scrubbed && local.scrubbed.len() == 16 * 1024);
    assert!(wire.c_raw == local.c_raw && is_hex64(&local.c_raw));
    assert!(wire.h_ingress_mac == local.h_ingress_mac && is_hex64(&local.h_ingress_mac));
    drop((received, retained, boot_epoch_id));
    fixture.finish();
    println!("PRODUCER_STREAM_REAL_WIRE same_epoch_slot_payload_commitment_mac=true local_retained=true ack=true cleanup=true");
}
