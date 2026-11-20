//! Bounded filesystem/namespace regressions for actual atomic outbox APIs.
//! Opaque fixture bytes, cooperating local writers and a software ACK transport
//! establish no OHTTP validity, authenticated delivery or power-loss guarantee.
use std::{collections::BTreeMap, fs::{self, File, OpenOptions}, path::{Path, PathBuf},
    sync::{Arc, Barrier, Mutex, atomic::{AtomicBool, AtomicUsize, Ordering}}};
use std::os::unix::{ffi::{OsStrExt, OsStringExt}, fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt}, io::AsRawFd};
use enclave_swarm_syncd::outbox::{enqueue_rollup, measure_outbox_disk, DrainStatus,
    HostConditions, OutboxDrainer, OutboxTransport, DEFAULT_MAX_OUTBOX_BYTES};

struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let base = std::env::temp_dir().canonicalize().unwrap();
        let path = base.join(format!("outbox-atomic-{}-{:x}", std::process::id(), enclave_core::rng::u64()));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }
    fn outbox(&self) -> PathBuf {
        let path = self.0.join("outbox");
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        path
    }
}
impl Drop for Directory { fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); } }
fn write(path: &Path, bytes: &[u8]) {
    use std::io::Write;
    let mut file = OpenOptions::new().create_new(true).write(true).mode(0o600).open(path).unwrap();
    file.write_all(bytes).unwrap();
}
fn name(id: u64, extension: &str) -> String { format!("{id:020}.{extension}") }
fn snapshot(dir: &Path) -> BTreeMap<Vec<u8>, (u64,u64,u32,u64,u64)> {
    fs::read_dir(dir).unwrap().map(|entry| {
        let entry = entry.unwrap(); let m = fs::symlink_metadata(entry.path()).unwrap();
        (entry.file_name().as_bytes().to_vec(), (m.dev(),m.ino(),m.mode(),m.nlink(),m.len()))
    }).collect()
}
fn lock(dir: &Path) -> File {
    let file = File::open(dir).unwrap();
    assert_eq!(unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) }, 0);
    file
}
fn fifo(path: &Path) {
    let path = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
}

#[test]
fn outbox_atomic_complete_publish_preserves_pending_dead_and_numeric_fifo() {
    let fixture = Directory::new(); let dir = fixture.outbox();
    let old = dir.join(name(4,"ohttp")); write(&old,b"older-pending");
    let dead = dir.join(name(9,"dead")); write(&dead,b"retained-dead-letter");
    let first = enqueue_rollup(&dir,b"complete-new-first").unwrap();
    let second = enqueue_rollup(&dir,b"complete-new-second").unwrap();
    assert_eq!(first.file_name().unwrap().as_bytes(),name(10,"ohttp").as_bytes());
    assert_eq!(second.file_name().unwrap().as_bytes(),name(11,"ohttp").as_bytes());
    assert_eq!(fs::read(&old).unwrap(),b"older-pending");
    assert_eq!(fs::read(&dead).unwrap(),b"retained-dead-letter");
    assert_eq!(fs::read(&first).unwrap(),b"complete-new-first");
    assert_eq!(fs::read(&second).unwrap(),b"complete-new-second");
    for path in [&first,&second] {
        let metadata=fs::symlink_metadata(path).unwrap();
        assert!(metadata.is_file()); assert_eq!(metadata.nlink(),1);
        assert_eq!(metadata.mode()&0o777,0o600);
    }
    let (_,files)=measure_outbox_disk(&dir).unwrap();
    assert_eq!(files,vec![old,first,second]);
    assert!(!dir.join(".enqueue.pending").exists());
}

#[test]
fn outbox_atomic_dead_letter_bytes_count_at_exact_cap_and_excess_refuses() {
    use std::io::{Read,Seek,SeekFrom};
    let fixture=Directory::new();let dir=fixture.outbox();
    let dead=dir.join(name(7,"dead"));write(&dead,b"D");
    // Sparse logical length exercises the actual disk-accounting boundary
    // without filling the host or allocating/reading a 100-MiB buffer.
    let mut file=OpenOptions::new().read(true).write(true).open(&dead).unwrap();
    file.set_len(DEFAULT_MAX_OUTBOX_BYTES-4).unwrap();
    let before=fs::metadata(&dead).unwrap();
    let final_path=enqueue_rollup(&dir,b"next").unwrap();
    assert_eq!(final_path.file_name().unwrap().as_bytes(),name(8,"ohttp").as_bytes());
    assert_eq!(fs::read(&final_path).unwrap(),b"next");
    let stable=snapshot(&dir);
    assert!(enqueue_rollup(&dir,b"x").unwrap_err().is("OUTBOX_DISK_FULL"));
    assert_eq!(snapshot(&dir),stable);
    let after=fs::metadata(&dead).unwrap();
    assert_eq!((after.dev(),after.ino(),after.len()),(before.dev(),before.ino(),before.len()));
    file.seek(SeekFrom::Start(0)).unwrap();let mut sentinel=[0];file.read_exact(&mut sentinel).unwrap();
    assert_eq!(sentinel,[b'D']);
}

#[test]
fn outbox_atomic_maximum_retained_sequence_refuses_without_mutation() {
    for extension in ["ohttp","dead"] {
        let fixture=Directory::new();let dir=fixture.outbox();
        let retained=dir.join(name(u64::MAX,extension));write(&retained,b"do-not-overwrite");
        let before=snapshot(&dir);
        assert!(enqueue_rollup(&dir,b"new").unwrap_err().is("OUTBOX_SEQUENCE_EXHAUSTED"),"{extension}");
        assert_eq!(snapshot(&dir),before,"{extension}");
        assert_eq!(fs::read(retained).unwrap(),b"do-not-overwrite");
    }
}

#[test]
fn outbox_atomic_preexisting_stage_every_type_requires_recovery_and_preserves_evidence() {
    for kind in ["file","symlink","dangling","hardlink","directory","fifo","socket"] {
        let fixture=Directory::new();let dir=fixture.outbox();
        let outside=fixture.0.join("outside");write(&outside,b"outside-evidence");
        let retained=dir.join(name(4,"ohttp"));write(&retained,b"pending-evidence");
        let stage=dir.join(".enqueue.pending");
        let _socket=match kind {
            "file"=>{write(&stage,b"partial-or-uncertain-stage");None},
            "symlink"=>{std::os::unix::fs::symlink(&outside,&stage).unwrap();None},
            "dangling"=>{std::os::unix::fs::symlink(fixture.0.join("absent"),&stage).unwrap();None},
            "hardlink"=>{fs::hard_link(&outside,&stage).unwrap();None},
            "directory"=>{fs::create_dir(&stage).unwrap();None},
            "fifo"=>{fifo(&stage);None},
            "socket"=>Some(std::os::unix::net::UnixListener::bind(&stage).unwrap()),
            _=>unreachable!(),
        };
        let before=snapshot(&dir);
        assert!(enqueue_rollup(&dir,b"new").unwrap_err().is("OUTBOX_PUBLICATION_RECOVERY_REQUIRED"),"{kind}");
        assert_eq!(snapshot(&dir),before,"{kind}");
        assert_eq!(fs::read(&outside).unwrap(),b"outside-evidence","{kind}");
        assert_eq!(fs::read(&retained).unwrap(),b"pending-evidence","{kind}");
        if kind=="file" {assert_eq!(fs::read(&stage).unwrap(),b"partial-or-uncertain-stage");}
        assert!(!fixture.0.join("absent").exists());
    }
}

#[test]
fn outbox_atomic_noncanonical_namespace_names_refuse_without_clobber() {
    // These five valid-UTF8 namespace forms can be created on both APFS
    // and Linux filesystems and must exercise the actual helper refusal.
    let names:Vec<Vec<u8>>=vec![b"1.ohttp".to_vec(),b"00000000000000000001.tmp".to_vec(),
        b"99999999999999999999.ohttp".to_vec(),b"0000000000000000000x.dead".to_vec(),
        b"unrelated".to_vec()];
    for bytes in names {
        let fixture=Directory::new();let dir=fixture.outbox();
        let path=dir.join(std::ffi::OsString::from_vec(bytes));write(&path,b"name-evidence");
        let before=snapshot(&dir);
        assert!(enqueue_rollup(&dir,b"new").unwrap_err().is("OUTBOX_ENTRY_NAME"));
        assert_eq!(snapshot(&dir),before);
        assert_eq!(fs::read(&path).unwrap(),b"name-evidence");
    }
    // A separate platform-specific coverage observation: Linux permits this
    // entry and must reach the helper. APFS can reject its creation with
    // EILSEQ; that is filesystem refusal, never a fabricated helper result.
    let fixture=Directory::new();let dir=fixture.outbox();
    let path=dir.join(std::ffi::OsString::from_vec(vec![0xff,b'.',b'o',b'h',b't',b't',b'p']));
    match OpenOptions::new().create_new(true).write(true).mode(0o600).open(&path) {
        Ok(mut file)=>{
            use std::io::Write;
            file.write_all(b"invalid-name-evidence").unwrap();drop(file);
            let before=snapshot(&dir);
            assert!(enqueue_rollup(&dir,b"new").unwrap_err().is("OUTBOX_ENTRY_NAME"));
            assert_eq!(snapshot(&dir),before);
            assert_eq!(fs::read(&path).unwrap(),b"invalid-name-evidence");
            println!("INVALID_UTF8_ENTRY_CREATED_ACTUAL_HELPER_REFUSED");
        },
        Err(error)=>{
            #[cfg(target_os="macos")]
            {
                assert_eq!(error.raw_os_error(),Some(libc::EILSEQ),"unexpected invalid-name fixture failure: {error}");
                assert!(snapshot(&dir).is_empty(),"filesystem-refused name left a namespace entry");
                println!("INVALID_UTF8_NAME_FILESYSTEM_EILSEQ_HELPER_CASE_UNREACHED");
            }
            #[cfg(not(target_os="macos"))]
            panic!("invalid-UTF8 helper case could not be constructed: {error}");
        },
    }
}

#[test]
fn outbox_atomic_unsafe_final_types_and_modes_refuse_without_following_or_truncating() {
    for kind in ["symlink","dangling","hardlink","directory","fifo","socket","writable"] {
        let fixture=Directory::new();let dir=fixture.outbox();
        let outside=fixture.0.join("outside");write(&outside,b"outside-evidence");
        let final_path=dir.join(name(5,"ohttp"));
        let _socket=match kind {
            "symlink"=>{std::os::unix::fs::symlink(&outside,&final_path).unwrap();None},
            "dangling"=>{std::os::unix::fs::symlink(fixture.0.join("absent"),&final_path).unwrap();None},
            "hardlink"=>{fs::hard_link(&outside,&final_path).unwrap();None},
            "directory"=>{fs::create_dir(&final_path).unwrap();None},
            "fifo"=>{fifo(&final_path);None},
            "socket"=>Some(std::os::unix::net::UnixListener::bind(&final_path).unwrap()),
            "writable"=>{write(&final_path,b"writable-evidence");fs::set_permissions(&final_path,fs::Permissions::from_mode(0o620)).unwrap();None},
            _=>unreachable!(),
        };
        let before=snapshot(&dir);
        assert!(enqueue_rollup(&dir,b"new").unwrap_err().is("OUTBOX_ENTRY_TYPE"),"{kind}");
        assert_eq!(snapshot(&dir),before,"{kind}");
        assert_eq!(fs::read(&outside).unwrap(),b"outside-evidence","{kind}");
        assert!(!fixture.0.join("absent").exists());
    }
}

#[test]
fn outbox_atomic_unsafe_directory_leaf_refuses_and_preserves_targets() {
    let fixture=Directory::new();let actual=fixture.outbox();
    let sentinel=actual.join(name(2,"ohttp"));write(&sentinel,b"target-evidence");
    let link=fixture.0.join("linked-outbox");std::os::unix::fs::symlink(&actual,&link).unwrap();
    assert!(enqueue_rollup(&link,b"new").unwrap_err().is("OUTBOX_DIRECTORY"));
    let ordinary=fixture.0.join("ordinary");write(&ordinary,b"ordinary-evidence");
    assert!(enqueue_rollup(&ordinary,b"new").unwrap_err().is("OUTBOX_DIRECTORY"));
    fs::set_permissions(&actual,fs::Permissions::from_mode(0o720)).unwrap();
    assert!(enqueue_rollup(&actual,b"new").unwrap_err().is("OUTBOX_DIRECTORY_AUTHORITY"));
    assert_eq!(fs::read(&sentinel).unwrap(),b"target-evidence");
    assert_eq!(fs::read(&ordinary).unwrap(),b"ordinary-evidence");
    assert_eq!(fs::read_link(&link).unwrap(),actual);
    assert!(!actual.join(".enqueue.pending").exists());
}

#[test]
fn outbox_atomic_oversize_refuses_before_namespace_access_without_payload_allocation() {
    // A bounded read-only zero mapping supplies a valid slice of logical size
    // cap+1 without touching its pages, copying it or filling the filesystem.
    struct Mapping(*mut libc::c_void,usize);
    impl Drop for Mapping {fn drop(&mut self){assert_eq!(unsafe{libc::munmap(self.0,self.1)},0);}}
    let fixture=Directory::new();let missing=fixture.0.join("never-created");
    let size=usize::try_from(DEFAULT_MAX_OUTBOX_BYTES).unwrap()+1;
    let raw=unsafe{libc::mmap(std::ptr::null_mut(),size,libc::PROT_READ,libc::MAP_PRIVATE|libc::MAP_ANONYMOUS,-1,0)};
    assert_ne!(raw,libc::MAP_FAILED);let mapping=Mapping(raw,size);
    let bytes=unsafe{std::slice::from_raw_parts(mapping.0.cast::<u8>(),mapping.1)};
    assert!(enqueue_rollup(&missing,bytes).unwrap_err().is("OUTBOX_DISK_FULL"));
    assert!(!missing.exists());
}

#[test]
fn outbox_atomic_busy_namespace_refuses_without_stage_and_fresh_retry_succeeds() {
    let fixture=Directory::new();let dir=fixture.outbox();
    let retained=dir.join(name(3,"ohttp"));write(&retained,b"retained");let before=snapshot(&dir);
    let held=lock(&dir);
    assert!(enqueue_rollup(&dir,b"new").unwrap_err().is("OUTBOX_NAMESPACE_BUSY"));
    assert_eq!(snapshot(&dir),before);
    drop(held);
    let final_path=enqueue_rollup(&dir,b"new").unwrap();
    assert_eq!(final_path.file_name().unwrap().as_bytes(),name(4,"ohttp").as_bytes());
    assert_eq!(fs::read(&retained).unwrap(),b"retained");
    assert_eq!(fs::read(&final_path).unwrap(),b"new");
}

#[test]
fn outbox_atomic_concurrent_cooperating_publishers_preserve_every_success() {
    let fixture=Directory::new();let dir=fixture.outbox();
    let retained=dir.join(name(20,"ohttp"));write(&retained,b"retained");
    let start=Arc::new(Barrier::new(3));let mut workers=Vec::new();
    for marker in [0x11u8,0x22] {
        let dir=dir.clone();let start=start.clone();
        workers.push(std::thread::spawn(move||{start.wait();(marker,enqueue_rollup(&dir,&[marker;8192]))}));
    }
    start.wait();
    // Join every competing publisher before a refused caller starts a fresh
    // attempt; otherwise that fresh attempt could legitimately still be busy.
    let outcomes:Vec<_>=workers.into_iter().map(|worker|worker.join().unwrap()).collect();
    let mut published=Vec::new();
    for (marker,result) in outcomes {
        let path=match result {
            Ok(path)=>path,
            Err(error)=>{
                // Only a known prepublication busy refusal permits this fresh
                // retry. No uncertain publication error is retried.
                assert!(error.is("OUTBOX_NAMESPACE_BUSY"),"{error}");
                enqueue_rollup(&dir,&[marker;8192]).unwrap()
            },
        };
        assert_eq!(fs::read(&path).unwrap(),vec![marker;8192]);published.push(path);
    }
    assert_ne!(published[0],published[1]);
    let (_,pending)=measure_outbox_disk(&dir).unwrap();
    assert_eq!(pending.len(),3);assert_eq!(pending[0],retained);
    assert_eq!(pending[1].file_name().unwrap().as_bytes(),name(21,"ohttp").as_bytes());
    assert_eq!(pending[2].file_name().unwrap().as_bytes(),name(22,"ohttp").as_bytes());
    assert_eq!(fs::read(&retained).unwrap(),b"retained");
    assert!(!dir.join(".enqueue.pending").exists());
}

#[test]
fn outbox_atomic_drainer_ack_runs_outside_namespace_lock_and_busy_retains_custody() {
    struct Ack {dir:PathBuf,first:AtomicBool,calls:AtomicUsize,held:Mutex<Option<File>>,seen:Mutex<Vec<Vec<u8>>>}
    impl OutboxTransport for Ack {
        fn transmit(&self,bytes:&[u8])->enclave_core::EnclaveResult<()> {
            self.calls.fetch_add(1,Ordering::SeqCst);self.seen.lock().unwrap().push(bytes.to_vec());
            if self.first.swap(false,Ordering::SeqCst) {
                // Taking the same actual directory lock in the callback proves
                // no namespace lock spans this simulated network operation.
                *self.held.lock().unwrap()=Some(lock(&self.dir));
            }
            Ok(())
        }
    }
    let fixture=Directory::new();let dir=fixture.outbox();
    let path=enqueue_rollup(&dir,b"complete-ciphertext").unwrap();let before=snapshot(&dir);
    let ack=Arc::new(Ack {dir:dir.clone(),first:AtomicBool::new(true),calls:AtomicUsize::new(0),held:Mutex::new(None),seen:Mutex::new(Vec::new())});
    let drainer=OutboxDrainer::new(&dir,ack.clone());
    assert!(drainer.drain_once(&HostConditions::default()).unwrap_err().is("OUTBOX_NAMESPACE_BUSY"));
    assert_eq!(snapshot(&dir),before);assert_eq!(fs::read(&path).unwrap(),b"complete-ciphertext");
    assert_eq!(ack.calls.load(Ordering::SeqCst),1);
    drop(ack.held.lock().unwrap().take());
    let report=drainer.drain_once(&HostConditions::default()).unwrap();
    assert_eq!(report.status,DrainStatus::Success);assert_eq!(report.frames_drained,1);assert_eq!(report.frames_remaining,0);
    assert_eq!(ack.calls.load(Ordering::SeqCst),2,"software ACK plus lock failure can lead to a second send");
    assert_eq!(*ack.seen.lock().unwrap(),vec![b"complete-ciphertext".to_vec();2]);
    assert!(!path.exists());
}
