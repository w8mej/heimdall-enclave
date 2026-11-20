//! Deterministic boundary observations. Hook errors are synthetic, never media faults.
use super::*;
use std::os::unix::{fs::{DirBuilderExt, OpenOptionsExt}, io::AsRawFd};
struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let path=std::env::temp_dir().canonicalize().unwrap().join(format!("retirement-boundary-{}-{:x}",std::process::id(),enclave_core::rng::u64()));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap(); Self(path)
    }
}
impl Drop for Directory { fn drop(&mut self) {
    RETIREMENT_TEST_HOOK.with(|slot|slot.borrow_mut().take()); let _=fs::remove_dir_all(&self.0);
}}
fn write(path:&Path,bytes:&[u8]) {
    use std::io::Write;
    fs::OpenOptions::new().create_new(true).write(true).mode(0o600).open(path).unwrap().write_all(bytes).unwrap();
}
struct Transport(bool);
impl OutboxTransport for Transport {
    fn transmit(&self,_:&[u8])->EnclaveResult<()> {
        if self.0 { Ok(()) } else { Err(err!(EIO,"RETIREMENT_TEST_NETWORK_FAILURE")) }
    }
}
fn install(point:RetirementTestBoundary,hook:RetirementTestHook) {
    RETIREMENT_TEST_HOOK.with(|slot|{assert!(slot.borrow().is_none());*slot.borrow_mut()=Some((point,hook));});
}
fn consumed(){RETIREMENT_TEST_HOOK.with(|slot|assert!(slot.borrow().is_none(),"selected boundary unreached"));}
fn injected()->EnclaveResult<()> {Err(err!(EIO,"RETIREMENT_TEST_SYNTHETIC"))}

#[test]
fn retirement_boundary_repeated_scan_on_one_held_directory_is_complete() {
    let fixture=Directory::new();write(&fixture.0.join("00000000000000000001.ohttp"),b"pending");
    write(&fixture.0.join("00000000000000000002.dead"),b"dead");
    let namespace=OutboxNamespace::try_lock(&fixture.0).unwrap();
    for _ in 0..3 { let inventory=namespace.scan(false,0).unwrap();
        assert_eq!(inventory.total,11);assert_eq!(inventory.maximum,Some(2));assert_eq!(inventory.pending.len(),1);
    }
}

#[test]
fn retirement_boundary_real_unlink_enoent_is_not_reported_as_success() {
    let fixture=Directory::new();let path=enqueue_rollup(&fixture.0,b"already-transmitted").unwrap();let dir=fixture.0.clone();
    install(RetirementTestBoundary::BeforeUnlink,Box::new(move|_,name|{
        // Explicit fixture interference bypasses advisory locking. The next
        // production unlinkat really fails with ENOENT, including as root.
        fs::remove_file(dir.join(name.to_str().unwrap())).unwrap();Ok(())
    }));
    let drainer=OutboxDrainer::new(&fixture.0,Arc::new(Transport(true)));
    assert!(drainer.drain_once(&HostConditions::default()).unwrap_err().is("OUTBOX_RETIREMENT_UNCERTAIN"));
    consumed();assert!(!path.exists());
}

#[test]
fn retirement_boundary_synthetic_preunlink_error_preserves_pending_without_success() {
    let fixture=Directory::new();let path=enqueue_rollup(&fixture.0,b"pending-custody").unwrap();
    install(RetirementTestBoundary::BeforeUnlink,Box::new(|_,_|injected()));
    let drainer=OutboxDrainer::new(&fixture.0,Arc::new(Transport(true)));
    assert!(drainer.drain_once(&HostConditions::default()).unwrap_err().is("RETIREMENT_TEST_SYNTHETIC"));
    consumed();assert_eq!(fs::read(path).unwrap(),b"pending-custody");
}

#[test]
fn retirement_boundary_synthetic_postunlink_error_may_leave_no_name() {
    let fixture=Directory::new();let path=enqueue_rollup(&fixture.0,b"accepted-before-uncertainty").unwrap();
    install(RetirementTestBoundary::AfterUnlink,Box::new(|namespace,_|{
        assert!(unsafe{libc::fcntl(namespace.directory.as_raw_fd(),libc::F_GETFD)}>=0);injected()
    }));
    let drainer=OutboxDrainer::new(&fixture.0,Arc::new(Transport(true)));
    assert!(drainer.drain_once(&HostConditions::default()).unwrap_err().is("RETIREMENT_TEST_SYNTHETIC"));
    consumed();assert!(!path.exists());assert_eq!(fs::read_dir(&fixture.0).unwrap().count(),0);
}

#[test]
fn retirement_boundary_synthetic_postrename_error_preserves_only_exact_dead_bytes() {
    let fixture=Directory::new();let path=enqueue_rollup(&fixture.0,b"retained-not-delivered").unwrap();
    install(RetirementTestBoundary::AfterDeadRename,Box::new(|_,_|injected()));
    let drainer=OutboxDrainer::with_options(&fixture.0,1024,1,Arc::new(Transport(false)));
    assert!(drainer.drain_once(&HostConditions::default()).unwrap_err().is("RETIREMENT_TEST_SYNTHETIC"));
    consumed();assert!(!path.exists());let dead=path.with_extension("dead");
    assert_eq!(fs::read(&dead).unwrap(),b"retained-not-delivered");
    let (bytes,pending)=measure_outbox_disk(&fixture.0).unwrap();assert_eq!(bytes,22);assert!(pending.is_empty());
}

#[test]
fn retirement_boundary_dead_destination_file_directory_and_symlink_are_never_clobbered() {
    use std::os::unix::fs::MetadataExt;
    for kind in ["file","directory","symlink"] {
        let fixture=Directory::new();let path=enqueue_rollup(&fixture.0,b"pending").unwrap();let dead=path.with_extension("dead");
        // Deliberately use private retire to reach the actual no-clobber syscall
        // for unsafe destinations that ordinary inventory already refuses.
        let namespace=OutboxNamespace::try_lock(&fixture.0).unwrap();
        let entry=namespace.scan(false,0).unwrap().pending.pop().unwrap();
        let (file,_)=namespace.read_entry(&entry).unwrap();
        match kind {
            "file"=>write(&dead,b"old-dead"),"directory"=>fs::create_dir(&dead).unwrap(),
            "symlink"=>std::os::unix::fs::symlink(path.file_name().unwrap(),&dead).unwrap(),_=>unreachable!(),
        }
        let before=fs::symlink_metadata(&dead).unwrap();
        assert!(namespace.retire(&entry,&file,true).unwrap_err().is("OUTBOX_DEAD_PUBLICATION_UNCERTAIN"));
        let after=fs::symlink_metadata(&dead).unwrap();
        assert_eq!((before.dev(),before.ino(),before.mode(),before.len()),(after.dev(),after.ino(),after.mode(),after.len()));
        assert_eq!(fs::read(&path).unwrap(),b"pending");
        if kind=="file" {assert_eq!(fs::read(&dead).unwrap(),b"old-dead");}
        if kind=="symlink" {assert_eq!(fs::read_link(&dead).unwrap(),PathBuf::from(path.file_name().unwrap()));}
    }
}

#[test]
fn retirement_boundary_changed_entry_after_inventory_refuses_before_read() {
    let fixture=Directory::new();let path=enqueue_rollup(&fixture.0,b"old").unwrap();
    let namespace=OutboxNamespace::try_lock(&fixture.0).unwrap();let entry=namespace.scan(false,0).unwrap().pending.pop().unwrap();
    fs::write(&path,b"changed-length").unwrap();
    assert!(namespace.read_entry(&entry).unwrap_err().is("OUTBOX_ENTRY_CHANGED"));
    assert_eq!(fs::read(path).unwrap(),b"changed-length");
}

#[test]
fn retirement_boundary_full_production_entry_limit_remains_measurable_and_drainable() {
    // Actual production limit, not a reduced synthetic bound. Empty dead
    // fixtures consume directory metadata only; one pending byte is drained.
    let fixture=Directory::new();
    for sequence in 0..MAX_OUTBOX_DIRECTORY_ENTRIES-1 {
        fs::OpenOptions::new().create_new(true).write(true).mode(0o600)
            .open(fixture.0.join(format!("{sequence:020}.dead"))).unwrap();
    }
    let pending=fixture.0.join(format!("{:020}.ohttp",MAX_OUTBOX_DIRECTORY_ENTRIES-1));write(&pending,b"x");
    let namespace=OutboxNamespace::try_lock(&fixture.0).unwrap();
    let inventory=namespace.scan(false,0).unwrap();assert_eq!(inventory.total,1);assert_eq!(inventory.pending.len(),1);
    assert!(namespace.scan(false,1).unwrap_err().is("OUTBOX_ENTRY_LIMIT"));drop(namespace);
    let drainer=OutboxDrainer::new(&fixture.0,Arc::new(Transport(true)));
    let report=drainer.drain_once(&HostConditions::default()).unwrap();
    assert_eq!((report.status,report.frames_drained,report.frames_remaining,report.disk_bytes_used),(DrainStatus::Success,1,0,0));
    assert!(!pending.exists());
    write(&fixture.0.join("00000000000000065536.dead"),b"");
    write(&fixture.0.join("00000000000000065537.dead"),b"");
    assert!(measure_outbox_disk(&fixture.0).unwrap_err().is("OUTBOX_ENTRY_LIMIT"));
}
