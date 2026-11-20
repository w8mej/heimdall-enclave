//! Public drainer custody regressions with owned private filesystem fixtures.
//! Recording/failing transports are software ACKs, not authenticated receipts.
use std::{fs::{self, OpenOptions}, path::{Path, PathBuf}, sync::{Arc, Mutex}};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use enclave_core::{err, EnclaveResult};
use enclave_swarm_syncd::outbox::{measure_outbox_disk, HostConditions, OutboxDrainer, OutboxTransport};

struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let path = std::env::temp_dir().canonicalize().unwrap().join(format!(
            "outbox-retire-{}-{:x}", std::process::id(), enclave_core::rng::u64()));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }
    fn queue(&self) -> PathBuf {
        let path = self.0.join("queue");
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
fn name(sequence: u64, extension: &str) -> String { format!("{sequence:020}.{extension}") }
fn bytes_equal(path: &Path, expected: &[u8]) -> bool {
    fs::read(path).ok().as_deref() == Some(expected)
}
fn snapshot(dir: &Path) -> Vec<(String, u64, u64, u64, u32)> {
    let mut entries: Vec<_> = fs::read_dir(dir).unwrap().map(|entry| {
        let entry = entry.unwrap(); let metadata = fs::symlink_metadata(entry.path()).unwrap();
        (entry.file_name().into_string().unwrap(), metadata.dev(), metadata.ino(), metadata.len(), metadata.mode())
    }).collect();
    entries.sort(); entries
}
#[derive(Default)]
struct Ack;
impl OutboxTransport for Ack {
    fn transmit(&self, _: &[u8]) -> EnclaveResult<()> { Ok(()) }
}

#[test]
fn retirement_replacement_during_ack_keeps_new_inode_and_refuses_success() {
    struct ReplaceDuringAck { path: PathBuf, displaced: PathBuf, sent: Mutex<Vec<Vec<u8>>> }
    impl OutboxTransport for ReplaceDuringAck {
        fn transmit(&self, bytes: &[u8]) -> EnclaveResult<()> {
            self.sent.lock().unwrap().push(bytes.to_vec());
            // Explicit owned-fixture interference bypasses advisory locking.
            // The transmitted inode and later pathname now identify different
            // ciphertexts; retirement must not delete this replacement.
            fs::rename(&self.path, &self.displaced).unwrap();
            write(&self.path, b"replacement-custody");
            Ok(())
        }
    }
    let fixture = Directory::new(); let dir = fixture.queue();
    let path = dir.join(name(1, "ohttp")); write(&path, b"original-ciphertext");
    let displaced = fixture.0.join("displaced-original");
    let old = fs::metadata(&path).unwrap();
    let transport = Arc::new(ReplaceDuringAck { path: path.clone(), displaced: displaced.clone(), sent: Mutex::new(Vec::new()) });
    let drainer = OutboxDrainer::new(&dir, transport.clone());
    let result = drainer.drain_once(&HostConditions::default());
    let replacement_is_distinct = fs::symlink_metadata(&path).ok().is_some_and(|m|
        (m.dev(), m.ino()) != (old.dev(), old.ino()));
    let sent_original_once = *transport.sent.lock().unwrap() == vec![b"original-ciphertext".to_vec()];
    assert_eq!((result.is_err(), bytes_equal(&path, b"replacement-custody"),
        replacement_is_distinct, bytes_equal(&displaced, b"original-ciphertext"), sent_original_once),
        (true, true, true, true, true),
        "ACK of the old inode must not retire or report success for a replacement pathname");
}

#[test]
fn retirement_failed_transport_does_not_clobber_colliding_dead_letter() {
    struct CollisionDuringFailure { dead: PathBuf, sent: Mutex<Vec<Vec<u8>>> }
    impl OutboxTransport for CollisionDuringFailure {
        fn transmit(&self, bytes: &[u8]) -> EnclaveResult<()> {
            self.sent.lock().unwrap().push(bytes.to_vec());
            // Create the collision after the initial inventory so this really
            // exercises the retirement boundary after an actual callback.
            write(&self.dead, b"preexisting-dead-custody");
            Err(err!(EIO, "OWNED_TEST_GATEWAY_UNAVAILABLE"))
        }
    }
    let fixture = Directory::new(); let dir = fixture.queue();
    let pending = dir.join(name(1, "ohttp")); write(&pending, b"failed-pending-custody");
    let dead = dir.join(name(1, "dead"));
    let transport = Arc::new(CollisionDuringFailure { dead: dead.clone(), sent: Mutex::new(Vec::new()) });
    let drainer = OutboxDrainer::with_options(&dir, 1024, 1, transport.clone());
    let result = drainer.drain_once(&HostConditions::default());
    let sent_original_once = *transport.sent.lock().unwrap() == vec![b"failed-pending-custody".to_vec()];
    assert_eq!((result.is_err(), bytes_equal(&pending, b"failed-pending-custody"),
        bytes_equal(&dead, b"preexisting-dead-custody"), sent_original_once),
        (true, true, true, true),
        "dead-letter collision must preserve both custody objects and surface retirement refusal");
}

#[test]
fn retirement_measurement_and_admission_count_dead_bytes_at_exact_cap() {
    let fixture = Directory::new(); let dir = fixture.queue();
    let pending = dir.join(name(1, "ohttp")); write(&pending, b"pending");
    let dead = dir.join(name(2, "dead")); write(&dead, b"dead-custody");
    let retained = b"pending".len() as u64 + b"dead-custody".len() as u64;
    let drainer = OutboxDrainer::with_options(&dir, retained + 3, 1, Arc::new(Ack));
    let before = snapshot(&dir);
    let (measured, files) = measure_outbox_disk(&dir).unwrap();
    let exact_allowed = drainer.assert_can_enqueue(3).is_ok();
    let excess_refused = drainer.assert_can_enqueue(4).is_err();
    assert_eq!((measured, files == vec![pending.clone()], exact_allowed, excess_refused,
        snapshot(&dir) == before, bytes_equal(&pending, b"pending"), bytes_equal(&dead, b"dead-custody")),
        (retained, true, true, true, true, true, true),
        "retained dead bytes must consume the same checked logical budget as pending bytes");
}

#[test]
fn retirement_admission_overflow_refuses_without_panic_or_namespace_change() {
    let fixture = Directory::new(); let dir = fixture.queue();
    let pending = dir.join(name(1, "ohttp")); write(&pending, b"x");
    let drainer = OutboxDrainer::with_options(&dir, u64::MAX, 1, Arc::new(Ack));
    let before = snapshot(&dir);
    // Old debug code panics at current+incoming; optimized wrapping may allow
    // admission. Both violate the same public refusal contract. Catching an
    // old panic does not call it a successful refusal or suppress its log.
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(||
        drainer.assert_can_enqueue(u64::MAX)));
    let refused_without_panic = matches!(result, Ok(Err(_)));
    assert_eq!((refused_without_panic, drainer.assert_can_enqueue(0).is_ok(),
        snapshot(&dir) == before, bytes_equal(&pending, b"x")),
        (true, true, true, true),
        "checked admission must refuse u64 overflow rather than panic, wrap or mutate custody");
}
