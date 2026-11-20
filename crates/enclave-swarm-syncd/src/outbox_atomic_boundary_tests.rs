//! Actual syscall collision/cleanup plus explicitly synthetic boundary errors.
//! No error returned by a test hook is claimed as a real media/fsync failure.
use super::*;
use std::{fs::OpenOptions, os::unix::{fs::{DirBuilderExt, OpenOptionsExt, MetadataExt}, io::AsRawFd}, sync::Mutex};

struct Directory(PathBuf);
impl Directory {
    fn new()->Self {
        let path=std::env::temp_dir().canonicalize().unwrap().join(format!("outbox-boundary-{}-{:x}",std::process::id(),enclave_core::rng::u64()));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();Self(path)
    }
}
impl Drop for Directory {fn drop(&mut self){ENQUEUE_TEST_HOOK.with(|slot|slot.borrow_mut().take());let _=fs::remove_dir_all(&self.0);}}
fn write(path:&Path,bytes:&[u8]) {
    use std::io::Write;
    OpenOptions::new().write(true).create_new(true).mode(0o600).open(path).unwrap().write_all(bytes).unwrap();
}
fn install(point:EnqueueTestBoundary,hook:EnqueueTestHook) {
    ENQUEUE_TEST_HOOK.with(|slot|{assert!(slot.borrow().is_none());*slot.borrow_mut()=Some((point,hook));});
}
fn injected()->EnclaveResult<()> {Err(err!(EIO,"OUTBOX_TEST_BOUNDARY_INJECTED"))}
fn assert_consumed(){ENQUEUE_TEST_HOOK.with(|slot|assert!(slot.borrow().is_none(),"selected boundary was unreached"));}
fn old(dir:&Path)->PathBuf {let path=dir.join("00000000000000000004.ohttp");write(&path,b"old-custody");path}
fn assert_old(path:&Path){assert_eq!(fs::read(path).unwrap(),b"old-custody");}

#[test]
fn atomic_boundary_prepublication_synthetic_failures_clean_only_owned_stage() {
    for point in [EnqueueTestBoundary::BeforeFileSync,EnqueueTestBoundary::BeforePublish] {
        let fixture=Directory::new();let retained=old(&fixture.0);
        install(point,Box::new(|_,_|injected()));
        assert!(enqueue_rollup(&fixture.0,b"new-complete").unwrap_err().is("OUTBOX_TEST_BOUNDARY_INJECTED"));
        assert_consumed();assert_old(&retained);
        assert!(!fixture.0.join(".enqueue.pending").exists());
        let (_,files)=measure_outbox_disk(&fixture.0).unwrap();assert_eq!(files,vec![retained]);
    }
}

#[test]
fn atomic_boundary_real_linkat_eexist_preserves_file_directory_and_symlink() {
    for kind in ["file","directory","symlink"] {
        let fixture=Directory::new();let retained=old(&fixture.0);let directory=fixture.0.clone();
        install(EnqueueTestBoundary::BeforePublish,Box::new(move|_,name|{
            let final_path=directory.join(name.to_str().unwrap());
            match kind {
                "file"=>write(&final_path,b"collision-evidence"),
                "directory"=>fs::create_dir(&final_path).unwrap(),
                "symlink"=>std::os::unix::fs::symlink("00000000000000000004.ohttp",&final_path).unwrap(),
                _=>unreachable!(),
            }
            Ok(())
        }));
        assert!(enqueue_rollup(&fixture.0,b"candidate-ciphertext").unwrap_err().is("OUTBOX_PUBLISH_UNCERTAIN"),"{kind}");
        assert_consumed();assert_old(&retained);
        let final_path=fixture.0.join("00000000000000000005.ohttp");
        match kind {
            "file"=>assert_eq!(fs::read(&final_path).unwrap(),b"collision-evidence"),
            "directory"=>assert!(fs::symlink_metadata(&final_path).unwrap().is_dir()),
            "symlink"=>assert_eq!(fs::read_link(&final_path).unwrap(),PathBuf::from("00000000000000000004.ohttp")),
            _=>unreachable!(),
        }
        assert_eq!(fs::read(fixture.0.join(".enqueue.pending")).unwrap(),b"candidate-ciphertext");
        assert!(enqueue_rollup(&fixture.0,b"never-retry-uncertain").unwrap_err().is("OUTBOX_PUBLICATION_RECOVERY_REQUIRED"));
        assert_old(&retained);
    }
}

#[test]
fn atomic_boundary_postpublication_synthetic_errors_keep_complete_final_and_exact_residue() {
    for point in [EnqueueTestBoundary::AfterPublish,EnqueueTestBoundary::AfterFirstDirectorySync,EnqueueTestBoundary::AfterStageUnlink] {
        let fixture=Directory::new();let retained=old(&fixture.0);
        install(point,Box::new(|_,_|injected()));
        assert!(enqueue_rollup(&fixture.0,b"published-ciphertext").unwrap_err().is("OUTBOX_TEST_BOUNDARY_INJECTED"));
        assert_consumed();assert_old(&retained);
        let final_path=fixture.0.join("00000000000000000005.ohttp");
        assert_eq!(fs::read(&final_path).unwrap(),b"published-ciphertext");
        let metadata=fs::metadata(&final_path).unwrap();let stage=fixture.0.join(".enqueue.pending");
        if point==EnqueueTestBoundary::AfterStageUnlink {
            assert!(!stage.exists());assert_eq!(metadata.nlink(),1);
            // Missing stage after completed unlink plus synthetic next-sync
            // failure is not evidence of nonpublication or permission to retry.
        } else {
            let staging=fs::metadata(&stage).unwrap();
            assert_eq!((metadata.dev(),metadata.ino(),metadata.nlink()),(staging.dev(),staging.ino(),2));
            assert_eq!(fs::read(&stage).unwrap(),b"published-ciphertext");
            assert!(enqueue_rollup(&fixture.0,b"never-retry-uncertain").unwrap_err().is("OUTBOX_PUBLICATION_RECOVERY_REQUIRED"));
        }
    }
    assert_real_staging_unlink_failure_keeps_final_even_without_marker();
}

#[test]
fn atomic_boundary_published_reader_and_real_drainer_observe_only_complete_bytes() {
    struct Ack(Mutex<Vec<Vec<u8>>>);
    impl OutboxTransport for Ack {
        fn transmit(&self,bytes:&[u8])->EnclaveResult<()> {self.0.lock().unwrap().push(bytes.to_vec());Ok(())}
    }
    let fixture=Directory::new();let directory=fixture.0.clone();
    let ack=Arc::new(Ack(Mutex::new(Vec::new())));let observed=ack.clone();
    install(EnqueueTestBoundary::AfterPublish,Box::new(move|namespace,name|{
        assert!(unsafe{libc::fcntl(namespace.directory.as_raw_fd(),libc::F_GETFD)}>=0);
        let path=directory.join(name.to_str().unwrap());assert_eq!(fs::read(path).unwrap(),b"whole-ciphertext-visible");
        // Writer still owns namespace flock. The direct diagnostic above sees
        // complete bytes; the safer drainer refuses before reading or sending.
        let drainer=OutboxDrainer::new(&directory,observed);
        assert!(drainer.drain_once(&HostConditions::default()).unwrap_err().is("OUTBOX_NAMESPACE_BUSY"));
        injected()
    }));
    assert!(enqueue_rollup(&fixture.0,b"whole-ciphertext-visible").unwrap_err().is("OUTBOX_TEST_BOUNDARY_INJECTED"));
    assert_consumed();assert!(ack.0.lock().unwrap().is_empty());
    assert!(measure_outbox_disk(&fixture.0).unwrap_err().is("OUTBOX_PUBLICATION_RECOVERY_REQUIRED"));
    assert_eq!(fs::read(fixture.0.join("00000000000000000000.ohttp")).unwrap(),b"whole-ciphertext-visible");
    assert_eq!(fs::read(fixture.0.join(".enqueue.pending")).unwrap(),b"whole-ciphertext-visible");
}

fn assert_real_staging_unlink_failure_keeps_final_even_without_marker() {
    let fixture=Directory::new();let retained=old(&fixture.0);let directory=fixture.0.clone();
    install(EnqueueTestBoundary::AfterFirstDirectorySync,Box::new(move|_,_|{
        // Explicit simulated interference bypasses advisory namespace locking;
        // the production unlinkat then really returns ENOENT, even as root.
        fs::remove_file(directory.join(".enqueue.pending")).unwrap();Ok(())
    }));
    assert!(enqueue_rollup(&fixture.0,b"already-published").unwrap_err().is("OUTBOX_STAGING_CLEANUP"));
    assert_consumed();assert_old(&retained);
    assert_eq!(fs::read(fixture.0.join("00000000000000000005.ohttp")).unwrap(),b"already-published");
    assert!(!fixture.0.join(".enqueue.pending").exists());
}
