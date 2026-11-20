//! Independent consumer-protocol probes over real private same-UID Unix IPC.
//! The mock CAS is test authority, not a production publisher or signed daemon.
use enclave_core::{ipc::{self, PeerCredentials}, profile::Profile};
use enclave_swarm_syncd::service::{CasRequest, CasResponse};
use mcp_enclave::{artifact_stream::{self, MAX_CHUNK_BYTES, MAX_MODEL_BYTES}, ctl::Env,
    deploy::{hydrate::{HydrationJob, run_worker_job_with_env}, EXIT_SUCCESS}};
use sha2::{Digest, Sha256};
use std::{fs::{self, File, OpenOptions}, io::{self, Read, Seek, SeekFrom},
    os::{fd::AsRawFd, unix::fs::DirBuilderExt}, path::PathBuf,
    sync::{Arc, Mutex, atomic::{AtomicBool, Ordering}}};

const TARGET: &str = "audit-model.bin";
struct Fixture { base: PathBuf, env: Env, stop: Arc<AtomicBool>, thread: Option<std::thread::JoinHandle<()>> }
impl Fixture {
    fn new<H>(factory: impl FnOnce(&PathBuf) -> H) -> Self
    where H: Fn(&PeerCredentials, CasRequest) -> enclave_core::error::EnclaveResult<CasResponse> + Send + Sync + 'static {
        let base = PathBuf::from("/tmp").join(format!("mc-f13a-{}", hex::encode(&enclave_core::rng::bytes32()[..16])));
        fs::DirBuilder::new().mode(0o700).create(&base).unwrap();
        let env = Env::dev(&base, Profile::L1);
        let handler = factory(&base);
        let dir = env.socket_dir.join("cas"); fs::create_dir_all(&dir).unwrap();
        let listener = ipc::bind(&dir.join("cas.sock"), ipc::SocketAccess::OwnerOnly).unwrap();
        let stop = Arc::new(AtomicBool::new(false)); let flag = stop.clone();
        let thread = std::thread::spawn(move || ipc::serve::<CasRequest, CasResponse, _>(listener,
            ipc::PeerPolicy::allow([ipc::geteuid()]), Arc::new(handler), flag).unwrap());
        Self { base, env, stop, thread: Some(thread) }
    }
    fn run(&self) -> (i32, String, serde_json::Value) {
        run_worker_job_with_env(&HydrationJob { job_id: "audit-job".into(), target: TARGET.into(),
            profile: "L1".into(), created_at: 1, source: "r2".into(), dmg_path: None },
            &self.base.join("jobs"), &self.base.join("cache"), &self.env)
    }
    fn old_model(&self) -> PathBuf {
        let dir = self.base.join("cache/models"); fs::create_dir_all(&dir).unwrap();
        let path = dir.join(TARGET); fs::write(&path, b"previous verified model").unwrap(); path
    }
    fn assert_no_staging(&self) {
        for dir in ["cache/models", "cache/chunks"] {
            if let Ok(entries) = fs::read_dir(self.base.join(dir)) {
                for entry in entries { assert!(!entry.unwrap().file_name().to_string_lossy().starts_with(".hydrate-")); }
            }
        }
    }
}
impl Drop for Fixture { fn drop(&mut self) { self.stop.store(true, Ordering::SeqCst);
    self.thread.take().unwrap().join().unwrap(); let _ = fs::remove_dir_all(&self.base); } }
fn payload() -> Vec<u8> { let mut b = vec![0u8; 3 * 1024 * 1024 + 17];
    blake3::Hasher::new_derive_key("F13 independent consumer probes").finalize_xof().fill(&mut b); b }
fn hashes(b: &[u8]) -> (String, String) { (blake3::hash(b).to_hex().to_string(), hex::encode(Sha256::digest(b))) }
#[derive(Clone, Copy, Debug)]
enum Snapshot { Valid, Corrupt, Truncated, ExtraByte, Offset, Writable, Directory, ExtraFds,
    BadBlake3, BadSha256, ZeroLength, ExcessLength, DeclaredZeroFds, DeclaredTwoFds }
fn snapshot(case: Snapshot) -> Fixture {
    Fixture::new(move |base| {
        let bytes = payload(); let (mut b3, mut sha) = hashes(&bytes); let mut length = bytes.len() as u64;
        let path = base.join("snapshot"); let mut actual = bytes;
        match case { Snapshot::Corrupt => actual[131072] ^= 1, Snapshot::Truncated => { actual.pop(); },
            Snapshot::ExtraByte => actual.push(0), Snapshot::BadBlake3 => b3 = "F".repeat(64),
            Snapshot::BadSha256 => sha = "0".repeat(63), Snapshot::ZeroLength => length = 0,
            Snapshot::ExcessLength => length = MAX_MODEL_BYTES + 1, _ => () }
        if matches!(case, Snapshot::Directory) { fs::create_dir(&path).unwrap(); length = fs::metadata(&path).unwrap().len(); }
        else { fs::write(&path, actual).unwrap(); }
        move |_: &PeerCredentials, req| {
            assert!(matches!(req, CasRequest::OpenTarget { target } if target == TARGET));
            let mut file = OpenOptions::new().read(true).write(matches!(case, Snapshot::Writable)).open(&path).unwrap();
            if matches!(case, Snapshot::Offset) { file.seek(SeekFrom::Start(1)).unwrap(); }
            let mut fds = vec![file.into()];
            if matches!(case, Snapshot::ExtraFds) { for _ in 0..15 { fds.push(File::open(&path).unwrap().into()); } }
            ipc::attach_fds(fds);
            Ok(CasResponse::TargetFile { length, blake3: b3.clone(), sha256: sha.clone(),
                fds: if matches!(case, Snapshot::DeclaredZeroFds) { 0 } else if matches!(case, Snapshot::DeclaredTwoFds) { 2 } else { 1 } })
        }
    })
}
#[test]
fn independent_snapshot_large_positive_replaces_atomically_and_sets_cloexec() {
    let f = snapshot(Snapshot::Valid); let path = f.old_model();
    let target = artifact_stream::fetch_verified_target(&f.env, TARGET).unwrap();
    assert_eq!(target.length, payload().len() as u64);
    assert_ne!(unsafe { libc::fcntl(target.file.as_raw_fd(), libc::F_GETFD) } & libc::FD_CLOEXEC, 0);
    drop(target);
    let (code, message, result) = f.run(); assert_eq!(code, EXIT_SUCCESS, "{message}: {result}");
    assert_eq!(fs::read(path).unwrap(), payload());
    assert_eq!(fs::read(f.base.join("cache/chunks").join(hashes(&payload()).0)).unwrap(), payload());
    f.assert_no_staging();
}
#[test]
fn independent_snapshot_metadata_fd_and_content_failures_preserve_old_model() {
    for case in [Snapshot::Corrupt, Snapshot::Truncated, Snapshot::ExtraByte, Snapshot::Offset,
        Snapshot::Writable, Snapshot::Directory, Snapshot::ExtraFds, Snapshot::BadBlake3,
        Snapshot::BadSha256, Snapshot::ZeroLength, Snapshot::ExcessLength,
        Snapshot::DeclaredZeroFds, Snapshot::DeclaredTwoFds] {
        let f = snapshot(case); let path = f.old_model();
        let (code, message, result) = f.run(); assert_ne!(code, EXIT_SUCCESS, "{case:?}: {message}: {result}");
        assert_eq!(result["status"], "failed", "{case:?}");
        assert_eq!(fs::read(path).unwrap(), b"previous verified model", "{case:?}");
        assert!(!f.base.join("cache/chunks").join(hashes(&payload()).0).exists(), "{case:?}");
        f.assert_no_staging();
    }
}
#[test]
fn independent_snapshot_unsafe_cache_directory_cannot_publish_outside_cache() {
    let f = snapshot(Snapshot::Valid); let outside = f.base.join("outside"); fs::create_dir(&outside).unwrap();
    fs::create_dir(f.base.join("cache")).unwrap();
    std::os::unix::fs::symlink(&outside, f.base.join("cache/models")).unwrap();
    let (code, _, result) = f.run(); assert_ne!(code, EXIT_SUCCESS, "{result}");
    assert!(fs::read_dir(outside).unwrap().next().is_none()); f.assert_no_staging();
}
#[derive(Clone, Copy, Debug)]
enum Admission { Valid, WrongProgress, WrongRoot, BadSession, ZeroChunk, ExcessChunk, BadHash, ExcessLength }
#[derive(Default)]
struct Upload { received: Vec<u8>, offsets: Vec<u64>, chunks: Vec<usize>, aborted: bool, committed: bool }
fn admission(case: Admission) -> (Fixture, Arc<Mutex<Upload>>) {
    let state = Arc::new(Mutex::new(Upload::default())); let shared = state.clone();
    let f = Fixture::new(move |_| {
        let bytes = payload(); let (b3, sha) = hashes(&bytes); let session = "a".repeat(64);
        move |_: &PeerCredentials, req| {
            let mut s = shared.lock().unwrap();
            Ok(match req {
                CasRequest::AdmitBegin { target } => { assert_eq!(target, TARGET);
                    CasResponse::Admission { session: if matches!(case, Admission::BadSession) { "bad".into() } else { session.clone() },
                        length: if matches!(case, Admission::ExcessLength) { MAX_MODEL_BYTES + 1 } else { bytes.len() as u64 },
                        blake3: if matches!(case, Admission::BadHash) { "g".repeat(64) } else { b3.clone() }, sha256: sha.clone(),
                        max_chunk_bytes: match case { Admission::ZeroChunk => 0, Admission::ExcessChunk => MAX_CHUNK_BYTES + 1, _ => 65536 } } }
                CasRequest::AdmitChunk { session: id, offset, bytes } => { assert_eq!(id, session); assert_eq!(offset, s.received.len() as u64);
                    assert!(bytes.len() <= 65536); s.offsets.push(offset); s.chunks.push(bytes.len()); s.received.extend_from_slice(&bytes);
                    CasResponse::AdmissionProgress { received: s.received.len() as u64 + u64::from(matches!(case, Admission::WrongProgress)) } }
                CasRequest::AdmitCommit { session: id } => { assert_eq!(id, session); s.committed = true;
                    CasResponse::Admitted { root: if matches!(case, Admission::WrongRoot) { "0".repeat(64) } else { b3.clone() } } }
                CasRequest::AdmitAbort { .. } => { s.aborted = true; CasResponse::Wiped }
                _ => panic!("unexpected request"),
            })
        }
    }); (f, state)
}
struct BoundedReader { bytes: io::Cursor<Vec<u8>>, reads: usize, fail_after_first: bool }
impl Read for BoundedReader { fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
    assert!(buf.len() <= MAX_CHUNK_BYTES); self.reads += 1;
    if self.fail_after_first && self.reads > 1 { return Err(io::Error::other("fixture interrupted input")); }
    self.bytes.read(buf)
} }
#[test]
fn independent_admission_large_positive_uses_sequential_bounded_frames() {
    let (f, state) = admission(Admission::Valid);
    let mut input = BoundedReader { bytes: io::Cursor::new(payload()), reads: 0, fail_after_first: false };
    assert_eq!(artifact_stream::admit_reader(&f.env, TARGET, &mut input).unwrap(), hashes(&payload()).0);
    let s = state.lock().unwrap(); assert!(s.committed); assert!(!s.aborted); assert!(s.chunks.len() > 48);
    assert_eq!(s.received, payload()); assert!(input.reads > 48);
}
#[test]
fn independent_admission_protocol_failures_abort_without_success() {
    for case in [Admission::WrongProgress, Admission::WrongRoot, Admission::BadSession,
        Admission::ZeroChunk, Admission::ExcessChunk, Admission::BadHash, Admission::ExcessLength] {
        let (f, state) = admission(case);
        assert!(artifact_stream::admit_reader(&f.env, TARGET, &mut io::Cursor::new(payload())).is_err(), "{case:?}");
        let s = state.lock().unwrap(); assert!(s.aborted, "{case:?}");
        assert_eq!(s.committed, matches!(case, Admission::WrongRoot), "{case:?}");
    }
}
#[test]
fn independent_admission_truncated_extra_corrupt_or_interrupted_input_never_commits() {
    for mode in 0..4 {
        let (f, state) = admission(Admission::Valid); let mut bytes = payload();
        match mode { 0 => { bytes.pop(); }, 1 => bytes.push(1), 2 => bytes[100000] ^= 1, _ => () }
        let mut input = BoundedReader { bytes: io::Cursor::new(bytes), reads: 0, fail_after_first: mode == 3 };
        assert!(artifact_stream::admit_reader(&f.env, TARGET, &mut input).is_err(), "mode {mode}");
        let s = state.lock().unwrap(); assert!(s.aborted); assert!(!s.committed);
    }
}
