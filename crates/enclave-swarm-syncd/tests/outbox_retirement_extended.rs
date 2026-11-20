//! Proposed additional public custody regressions; not executed by this author.
//! All transport responses are owned software fixtures, not authenticated ACKs.
use std::{fs::{self, OpenOptions}, path::{Path, PathBuf}, sync::{Arc, Mutex, atomic::{AtomicUsize, Ordering}}, time::Duration};
use std::os::unix::{ffi::OsStrExt, fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt}};
use enclave_core::{err, EnclaveResult};
use enclave_swarm_syncd::outbox::{DrainStatus, HostConditions, OutboxDrainer, OutboxTransport, DEFAULT_MAX_OUTBOX_BYTES};

struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let path = std::env::temp_dir().canonicalize().unwrap().join(format!(
            "outbox-retire-extended-{}-{:x}", std::process::id(), enclave_core::rng::u64()));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap(); Self(path)
    }
    fn queue(&self) -> PathBuf {
        let path = self.0.join("queue"); fs::DirBuilder::new().mode(0o700).create(&path).unwrap(); path
    }
}
impl Drop for Directory { fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); } }
fn write(path: &Path, bytes: &[u8]) {
    use std::io::Write;
    OpenOptions::new().create_new(true).write(true).mode(0o600).open(path).unwrap().write_all(bytes).unwrap();
}
fn snapshot(dir: &Path) -> Vec<(Vec<u8>, u64, u64, u64, u32, u64)> {
    let mut entries: Vec<_> = fs::read_dir(dir).unwrap().map(|entry| {
        let entry = entry.unwrap(); let metadata = fs::symlink_metadata(entry.path()).unwrap();
        (entry.file_name().as_bytes().to_vec(), metadata.dev(), metadata.ino(), metadata.len(), metadata.mode(), metadata.nlink())
    }).collect(); entries.sort(); entries
}
fn small_regular_payloads(dir: &Path) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut contents = Vec::new();
    for entry in fs::read_dir(dir).unwrap() {
        let entry = entry.unwrap(); let metadata = fs::symlink_metadata(entry.path()).unwrap();
        // Owned small fixture files only; never follow links/open a FIFO or
        // read the sparse oversize payload as part of the test oracle.
        if metadata.file_type().is_file() && metadata.len() <= 64 {
            contents.push((entry.file_name().as_bytes().to_vec(), fs::read(entry.path()).unwrap()));
        }
    }
    contents.sort(); contents
}
#[derive(Default)]
struct Ack(AtomicUsize);
impl OutboxTransport for Ack {
    fn transmit(&self, _: &[u8]) -> EnclaveResult<()> { self.0.fetch_add(1, Ordering::SeqCst); Ok(()) }
}

#[test]
fn retirement_refuses_unsafe_or_uncertain_namespace_without_transmit_or_changed_fixture() {
    // The sparse case consumes only metadata and the bounded bytes written by
    // the filesystem; it does not fill the drive or allocate a giant Vec here.
    for kind in ["stage-file", "stage-directory", "symlink", "fifo", "directory", "hardlink", "writable", "malformed", "sparse-oversize"] {
        let fixture = Directory::new(); let dir = fixture.queue();
        let path = dir.join("00000000000000000001.ohttp");
        match kind {
            "stage-file" => { write(&path, b"retained"); write(&dir.join(".enqueue.pending"), b"uncertain-stage"); },
            "stage-directory" => { write(&path, b"retained"); fs::create_dir(dir.join(".enqueue.pending")).unwrap(); },
            "symlink" => {
                let target = fixture.0.join("outside-target"); write(&target, b"owned-target");
                std::os::unix::fs::symlink(target, &path).unwrap();
            },
            "fifo" => {
                let name = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
                assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
            },
            "directory" => fs::create_dir(&path).unwrap(),
            "hardlink" => {
                let target = fixture.0.join("outside-target"); write(&target, b"owned-target");
                fs::hard_link(target, &path).unwrap();
            },
            "writable" => { write(&path, b"retained"); fs::set_permissions(&path, fs::Permissions::from_mode(0o620)).unwrap(); },
            "malformed" => { write(&path, b"retained"); write(&dir.join("not-a-canonical-queue-name"), b"evidence"); },
            "sparse-oversize" => {
                OpenOptions::new().create_new(true).write(true).mode(0o600).open(&path).unwrap().set_len(DEFAULT_MAX_OUTBOX_BYTES + 1).unwrap();
            },
            _ => unreachable!(),
        }
        let before = snapshot(&dir);
        let small_before = small_regular_payloads(&dir);
        let outside_before = fs::read(fixture.0.join("outside-target")).ok();
        let ack = Arc::new(Ack::default());
        let result = OutboxDrainer::new(&dir, ack.clone()).drain_once(&HostConditions::default());
        assert_eq!((result.is_err(), ack.0.load(Ordering::SeqCst), snapshot(&dir) == before,
            small_regular_payloads(&dir) == small_before, fs::read(fixture.0.join("outside-target")).ok() == outside_before),
            (true, 0, true, true, true), "{kind}: refuse without transport or changed namespace metadata/small owned payloads");
    }
}

#[test]
fn retirement_dead_only_queue_reports_retained_bytes_without_transport() {
    let fixture = Directory::new(); let dir = fixture.queue();
    let dead = dir.join("00000000000000000001.dead"); write(&dead, b"dead-custody");
    let before = snapshot(&dir); let ack = Arc::new(Ack::default());
    let report = OutboxDrainer::new(&dir, ack.clone()).drain_once(&HostConditions::default()).unwrap();
    assert_eq!((report.status, report.frames_drained, report.bytes_drained, report.frames_remaining,
        report.disk_bytes_used, ack.0.load(Ordering::SeqCst), snapshot(&dir) == before, fs::read(dead).unwrap()),
        (DrainStatus::Empty, 0, 0, 0, 12, 0, true, b"dead-custody".to_vec()));
}

#[test]
fn retirement_dead_letter_keeps_bytes_and_allows_next_frame_after_retry_threshold() {
    struct FailFirst(Mutex<Vec<Vec<u8>>>);
    impl OutboxTransport for FailFirst {
        fn transmit(&self, bytes: &[u8]) -> EnclaveResult<()> {
            self.0.lock().unwrap().push(bytes.to_vec());
            if bytes == b"first-fails" { Err(err!(EIO, "OWNED_TEST_GATEWAY_FAILURE")) } else { Ok(()) }
        }
    }
    let fixture = Directory::new(); let dir = fixture.queue();
    let first = dir.join("00000000000000000001.ohttp"); write(&first, b"first-fails");
    let second = dir.join("00000000000000000002.ohttp"); write(&second, b"next-accepted");
    let transport = Arc::new(FailFirst(Mutex::new(Vec::new())));
    let drainer = OutboxDrainer::with_options(&dir, 1024, 1, transport.clone());
    let report = drainer.drain_once(&HostConditions::default()).unwrap();
    let dead = first.with_extension("dead");
    assert_eq!((report.status, report.frames_drained, report.bytes_drained, report.frames_remaining,
        report.disk_bytes_used, !first.exists(), !second.exists(), fs::read(dead).unwrap(), transport.0.lock().unwrap().clone()),
        (DrainStatus::NetworkError, 1, 13, 0, 11, true, true, b"first-fails".to_vec(), vec![b"first-fails".to_vec(), b"next-accepted".to_vec()]));
    let after = drainer.drain_once(&HostConditions::default()).unwrap();
    assert_eq!((after.status, after.disk_bytes_used, transport.0.lock().unwrap().len()), (DrainStatus::Empty, 11, 2));
}

#[test]
fn retirement_same_instance_concurrent_pass_refuses_while_transport_is_in_flight() {
    struct BlockingAck {
        entered: std::sync::mpsc::SyncSender<()>,
        release: Mutex<std::sync::mpsc::Receiver<()>>,
        callbacks: AtomicUsize,
    }
    impl OutboxTransport for BlockingAck {
        fn transmit(&self, _: &[u8]) -> EnclaveResult<()> {
            if self.callbacks.fetch_add(1, Ordering::SeqCst) == 0 {
                self.entered.send(()).unwrap();
                self.release.lock().unwrap().recv_timeout(Duration::from_secs(15))
                    .map_err(|_| err!(EIO, "OWNED_TEST_RELEASE_TIMEOUT"))?;
            }
            Ok(())
        }
    }
    let fixture = Directory::new(); let dir = fixture.queue();
    let path = dir.join("00000000000000000001.ohttp"); write(&path, b"retained-in-flight");
    let (entered_tx, entered_rx) = std::sync::mpsc::sync_channel(1);
    let (release_tx, release_rx) = std::sync::mpsc::sync_channel(1);
    let transport = Arc::new(BlockingAck { entered: entered_tx, release: Mutex::new(release_rx), callbacks: AtomicUsize::new(0) });
    let drainer = Arc::new(OutboxDrainer::new(&dir, transport.clone()));
    let first_drainer = drainer.clone();
    let first = std::thread::spawn(move || first_drainer.drain_once(&HostConditions::default()));
    entered_rx.recv_timeout(Duration::from_secs(10)).expect("first real transport callback must be reached");
    let (second_tx, second_rx) = std::sync::mpsc::sync_channel(1);
    let second_drainer = drainer.clone();
    let second = std::thread::spawn(move || {
        let result = second_drainer.drain_once(&HostConditions::default());
        second_tx.send(result.as_ref().is_err_and(|error| error.is("OUTBOX_DRAIN_BUSY"))).unwrap();
    });
    // Release the first worker even if the second incorrectly waits rather
    // than returning BUSY. Timed software coordination is not a latency SLO.
    let refused_while_first_in_flight = second_rx.recv_timeout(Duration::from_secs(3)).unwrap_or(false);
    let original_present_before_release = fs::read(&path).ok().as_deref() == Some(b"retained-in-flight".as_slice());
    release_tx.send(()).unwrap();
    let first_result = first.join().unwrap(); second.join().unwrap();
    let exactly_one_retired = first_result.as_ref().is_ok_and(|report| report.status == DrainStatus::Success && report.frames_drained == 1);
    assert_eq!((refused_while_first_in_flight, original_present_before_release, exactly_one_retired,
        transport.callbacks.load(Ordering::SeqCst), !path.exists()), (true, true, true, 1, true));
}

#[test]
fn retirement_directory_replacement_during_transport_preserves_both_queues() {
    struct Replace { dir:PathBuf, displaced:PathBuf }
    impl OutboxTransport for Replace {
        fn transmit(&self,_:&[u8])->EnclaveResult<()> {
            fs::rename(&self.dir,&self.displaced).unwrap();
            fs::DirBuilder::new().mode(0o700).create(&self.dir).unwrap();
            write(&self.dir.join("00000000000000000001.ohttp"),b"replacement-queue");Ok(())
        }
    }
    let fixture=Directory::new();let dir=fixture.queue();
    write(&dir.join("00000000000000000001.ohttp"),b"transmitted-original");
    let displaced=fixture.0.join("original-queue");
    let drainer=OutboxDrainer::new(&dir,Arc::new(Replace{dir:dir.clone(),displaced:displaced.clone()}));
    assert!(drainer.drain_once(&HostConditions::default()).unwrap_err().is("OUTBOX_DIRECTORY_CHANGED"));
    assert_eq!(fs::read(dir.join("00000000000000000001.ohttp")).unwrap(),b"replacement-queue");
    assert_eq!(fs::read(displaced.join("00000000000000000001.ohttp")).unwrap(),b"transmitted-original");
}

#[test]
fn retirement_inplace_change_during_transport_is_not_removed() {
    struct Change(PathBuf);
    impl OutboxTransport for Change {
        fn transmit(&self,_:&[u8])->EnclaveResult<()> {fs::write(&self.0,b"different-retained-ciphertext").unwrap();Ok(())}
    }
    let fixture=Directory::new();let dir=fixture.queue();let path=dir.join("00000000000000000001.ohttp");
    write(&path,b"old");let old=fs::metadata(&path).unwrap();
    let drainer=OutboxDrainer::new(&dir,Arc::new(Change(path.clone())));
    assert!(drainer.drain_once(&HostConditions::default()).unwrap_err().is("OUTBOX_ENTRY_CHANGED"));
    let new=fs::metadata(&path).unwrap();assert_eq!((old.dev(),old.ino()),(new.dev(),new.ino()));
    assert_eq!(fs::read(path).unwrap(),b"different-retained-ciphertext");
}

#[test]
fn retirement_cooperating_enqueue_in_callback_is_reported_without_namespace_lock() {
    struct Enqueue {dir:PathBuf,calls:AtomicUsize}
    impl OutboxTransport for Enqueue {
        fn transmit(&self,bytes:&[u8])->EnclaveResult<()> {
            assert_eq!(bytes,b"first");self.calls.fetch_add(1,Ordering::SeqCst);
            enclave_swarm_syncd::outbox::enqueue_rollup(&self.dir,b"new-during-send")?;Ok(())
        }
    }
    let fixture=Directory::new();let dir=fixture.queue();
    let first=enclave_swarm_syncd::outbox::enqueue_rollup(&dir,b"first").unwrap();
    let transport=Arc::new(Enqueue{dir:dir.clone(),calls:AtomicUsize::new(0)});
    let report=OutboxDrainer::new(&dir,transport.clone()).drain_once(&HostConditions::default()).unwrap();
    assert_eq!((report.status,report.frames_drained,report.frames_remaining,report.disk_bytes_used),
        (DrainStatus::Success,1,1,15));
    assert!(!first.exists());assert_eq!(transport.calls.load(Ordering::SeqCst),1);
    assert_eq!(fs::read(dir.join("00000000000000000001.ohttp")).unwrap(),b"new-during-send");
}

#[test]
fn retirement_retry_hint_resets_when_a_numeric_path_gets_a_fresh_inode() {
    struct Fail(AtomicUsize);
    impl OutboxTransport for Fail {
        fn transmit(&self,_:&[u8])->EnclaveResult<()> {self.0.fetch_add(1,Ordering::SeqCst);Err(err!(EIO,"OWNED_TEST_DOWN"))}
    }
    let fixture=Directory::new();let dir=fixture.queue();let path=dir.join("00000000000000000001.ohttp");
    write(&path,b"old");let transport=Arc::new(Fail(AtomicUsize::new(0)));
    let drainer=OutboxDrainer::with_options(&dir,1024,2,transport.clone());
    assert_eq!(drainer.drain_once(&HostConditions::default()).unwrap().frames_remaining,1);
    // Hold the old inode alive outside the queue before creating its replacement.
    fs::rename(&path,fixture.0.join("old-object")).unwrap();write(&path,b"fresh");
    assert_eq!(drainer.drain_once(&HostConditions::default()).unwrap().frames_remaining,1);
    assert_eq!(fs::read(&path).unwrap(),b"fresh");assert!(!path.with_extension("dead").exists());
    let report=drainer.drain_once(&HostConditions::default()).unwrap();
    assert_eq!((report.frames_drained,report.frames_remaining,report.disk_bytes_used),(0,0,5));
    assert_eq!(fs::read(path.with_extension("dead")).unwrap(),b"fresh");
    assert_eq!(transport.0.load(Ordering::SeqCst),3);
}

#[test]
fn retirement_saturated_budget_still_drains_pending_and_retains_dead_bytes() {
    let fixture=Directory::new();let dir=fixture.queue();
    write(&dir.join("00000000000000000001.ohttp"),b"pending");
    write(&dir.join("00000000000000000002.dead"),b"retained");
    let ack=Arc::new(Ack::default());let drainer=OutboxDrainer::with_options(&dir,1,1,ack.clone());
    assert!(drainer.assert_can_enqueue(0).is_err());
    let report=drainer.drain_once(&HostConditions::default()).unwrap();
    assert_eq!((report.status,report.frames_drained,report.frames_remaining,report.disk_bytes_used,ack.0.load(Ordering::SeqCst)),
        (DrainStatus::Success,1,0,8,1));
}
