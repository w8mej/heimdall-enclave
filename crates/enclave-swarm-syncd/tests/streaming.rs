//! F13: real multi-frame admission, pinned CDC, authenticated immutable
//! snapshots, ownership/replay/freshness boundaries, and unchanged sanitizers.
use std::collections::BTreeMap;
use std::fs;
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::Arc;

use enclave_core::ipc::{self, PeerCredentials};
use enclave_core::profile::Profile;
use enclave_crypto::tuf::{target_file, RepoBuilder, TargetFile};
use enclave_swarm_syncd::cas::ContentStore;
use enclave_swarm_syncd::fastcdc;
use enclave_swarm_syncd::sanitizer::{build_safetensors, build_stored_zip};
use enclave_swarm_syncd::service::{CasConfig, CasRequest, CasResponse, CasService, OFFLINE_TTL_S};
use serde_json::json;

const NOW: i64 = 1_793_884_860;
const EXP: &str = "2030-01-01T00:00:00Z";
const CHUNK: usize = 256 * 1024;
static WALL: AtomicI64 = AtomicI64::new(NOW);
fn wall() -> i64 { WALL.load(Ordering::SeqCst) }
fn fixed_wall() -> i64 { NOW }

struct Fixture {
    dir: PathBuf,
    repo: RepoBuilder,
    root: Vec<u8>,
    svc: Arc<CasService>,
    peer: PeerCredentials,
}
impl Fixture {
    fn new(targets: BTreeMap<String, TargetFile>) -> Self { Self::with_clock(targets, fixed_wall) }
    fn with_clock(targets: BTreeMap<String, TargetFile>, clock: fn() -> i64) -> Self {
        let dir = PathBuf::from("/tmp").join(format!("mcs-{:016x}", enclave_core::rng::u64()));
        fs::create_dir(&dir).unwrap();
        fs::set_permissions(&dir,fs::Permissions::from_mode(0o700)).unwrap();
        let repo = RepoBuilder::new(3, 2);
        let root = repo.root(EXP).unwrap();
        let svc = CasService::start_with_wall_clock(config(&dir, &root), clock).unwrap();
        let mut peer = PeerCredentials::local(ipc::geteuid(), 0);
        peer.pid = Some(std::process::id() as i32);
        let f = Self { dir, repo, root, svc, peer };
        f.refresh(1, targets);
        f
    }
    fn refresh(&self, version: u64, targets: BTreeMap<String, TargetFile>) {
        let t = self.repo.targets(version, EXP, targets).unwrap();
        let s = self.repo.snapshot(version, EXP, version, &t).unwrap();
        let ts = self.repo.timestamp(version, EXP, version, &s).unwrap();
        self.svc.handle(&self.peer, CasRequest::TufRefresh {
            roots: vec![], timestamp: ts.into(), snapshot: s.into(), targets: t.into(),
        }).unwrap();
    }
    fn begin(&self, target: &str) -> String {
        let CasResponse::Admission { session, max_chunk_bytes, .. } = self.svc.handle(&self.peer,
            CasRequest::AdmitBegin { target: target.into() }).unwrap() else { panic!() };
        assert_eq!(max_chunk_bytes, CHUNK);
        assert_eq!(session.len(),64);
        assert!(session.bytes().all(|b| b.is_ascii_hexdigit()));
        session
    }
    fn upload(&self, session: &str, bytes: &[u8]) {
        for (i, chunk) in bytes.chunks(CHUNK).enumerate() {
            let req = CasRequest::AdmitChunk { session: session.into(), offset: (i*CHUNK) as u64, bytes: chunk.to_vec().into() };
            let encoded = ipc::to_cbor(&req).unwrap();
            assert!(encoded.len() < ipc::MAX_FRAME, "MAX_FRAME must remain one MiB");
            let req: CasRequest = ipc::from_cbor(&encoded).unwrap();
            let result = self.svc.handle(&self.peer, req).unwrap();
            assert!(matches!(result, CasResponse::AdmissionProgress { received } if received == (i*CHUNK+chunk.len()) as u64));
        }
    }
    fn commit(&self, session: &str) -> enclave_core::error::EnclaveResult<CasResponse> {
        self.svc.handle(&self.peer, CasRequest::AdmitCommit { session: session.into() })
    }
    fn stages(&self) -> Vec<PathBuf> {
        fs::read_dir(self.dir.join("store/streaming-stages")).unwrap()
            .map(|e| e.unwrap().path()).filter(|p| p.file_name().unwrap().to_string_lossy().starts_with("stage-")).collect()
    }
    fn store(&self) -> ContentStore { ContentStore::open(&self.dir.join("store")).unwrap() }
    fn socket(&self) -> Socket {
        let path = self.dir.join(format!("cas-{}.sock", enclave_core::rng::u64()));
        let listener = ipc::bind(&path, ipc::SocketAccess::OwnerOnly).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let (svc, thread_stop) = (self.svc.clone(), stop.clone());
        let thread = std::thread::spawn(move || ipc::serve::<CasRequest, CasResponse, _>(
            listener, ipc::PeerPolicy::allow([ipc::geteuid()]), Arc::new(move |p: &PeerCredentials, r| svc.handle(p, r)), thread_stop).unwrap());
        Socket { path, stop, thread: Some(thread) }
    }
}
fn config(dir: &Path, root: &[u8]) -> CasConfig {
    CasConfig {dev_same_uid: true,  profile: Profile::L2, store_dir: dir.join("store"), audit_path: None,
        tuf_root: Some(root.to_vec()), state_dir: None, ohttp_gateway: None,
        revocation: enclave_swarm_syncd::revocation::Enforcement::InProcess }
}
impl Drop for Fixture { fn drop(&mut self) { let _ = fs::remove_dir_all(&self.dir); } }
struct Socket { path: PathBuf, stop: Arc<AtomicBool>, thread: Option<std::thread::JoinHandle<()>> }
impl Socket {
    fn connect(&self) -> ipc::Client { ipc::Client::connect(&self.path, ipc::geteuid()).unwrap() }
    fn open(&self, target: &str) -> (CasResponse, fs::File) {
        let mut c = self.connect();
        let response: CasResponse = c.call(&CasRequest::OpenTarget { target: target.into() }).unwrap();
        assert!(matches!(response, CasResponse::TargetFile { fds: 1, .. }));
        let mut fds = c.recv_fds(4).unwrap();
        assert_eq!(fds.len(), 1);
        (response, fs::File::from(fds.pop().unwrap()))
    }
}
impl Drop for Socket {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        // The listener is nonblocking; the stop flag is checked between polls.
        if let Some(t) = self.thread.take() { t.join().unwrap(); }
    }
}
fn targets(name: &str, bytes: &[u8]) -> BTreeMap<String, TargetFile> {
    [(name.into(), target_file(bytes, Some(json!({}))))].into_iter().collect()
}
fn payload(length: usize) -> Vec<u8> {
    let mut bytes = vec![0; length];
    blake3::Hasher::new_derive_key("MCPMac F13 deterministic private artifact").finalize_xof().fill(&mut bytes);
    // Avoid an executable/pickle prefix in this intentionally inert fixture.
    bytes[..4].copy_from_slice(b"DATA");
    bytes
}

#[test]
fn multi_mib_admission_uses_real_frames_and_readonly_snapshot_fd() {
    assert_eq!(ipc::MAX_FRAME, 1024*1024);
    let bytes = payload(3*1024*1024+91);
    let f = Fixture::new(targets("large.bin", &bytes));
    let socket = f.socket();
    // Exercise actual generic IPC framing for every upload request as well as
    // the additive SCM_RIGHTS export. Each call may use a fresh connection.
    let mut client = socket.connect();
    let CasResponse::Admission { session, length, blake3: b3, sha256: sha, max_chunk_bytes } = client.call(&CasRequest::AdmitBegin { target: "large.bin".into() }).unwrap() else { panic!() };
    assert_eq!(length, bytes.len() as u64);
    assert_eq!(max_chunk_bytes, CHUNK);
    assert_eq!(b3, blake3::hash(&bytes).to_hex().as_str());
    use sha2::Digest;
    assert_eq!(sha, hex::encode(sha2::Sha256::digest(&bytes)));
    assert!(!f.store().contains(&b3));
    for (i, chunk) in bytes.chunks(CHUNK).enumerate() {
        let response: CasResponse = client.call(&CasRequest::AdmitChunk {
            session: session.clone(), offset: (i*CHUNK) as u64, bytes: chunk.to_vec().into(),
        }).unwrap();
        assert!(matches!(response, CasResponse::AdmissionProgress { received } if received == (i*CHUNK+chunk.len()) as u64));
        assert!(!f.store().contains(&b3));
    }
    let response: CasResponse = client.call(&CasRequest::AdmitCommit { session: session.clone() }).unwrap();
    assert!(matches!(response, CasResponse::Admitted { root } if root == b3));
    assert_eq!(f.store().get(&b3).unwrap(), bytes);
    assert!(f.stages().is_empty());
    assert!(f.commit(&session).unwrap_err().is("ADMISSION_SESSION_UNKNOWN"));
    let (meta, mut file) = socket.open("large.bin");
    assert!(matches!(meta, CasResponse::TargetFile { length, blake3, sha256, fds: 1 } if length == bytes.len() as u64 && blake3 == b3 && sha256 == sha));
    assert!(file.metadata().unwrap().is_file());
    assert_eq!(unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) } & libc::O_ACCMODE, libc::O_RDONLY);
    let mut got = Vec::new(); file.read_to_end(&mut got).unwrap();
    assert_eq!(got, bytes);
    assert!(file.write_all(b"write denied").is_err());
    assert!(f.stages().is_empty(), "snapshots must be unlinked before return");
}

#[test]
fn streaming_cdc_matches_pinned_boundaries_for_short_reads_and_repairs_poison() {
    struct Short<'a> { data: &'a [u8], step: usize }
    impl Read for Short<'_> {
        fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
            let n = out.len().min(self.step).min(self.data.len());
            out[..n].copy_from_slice(&self.data[..n]); self.data = &self.data[n..]; Ok(n)
        }
    }
    let data = fastcdc::test_vector_input();
    let f = Fixture::new(targets("x.bin", &data));
    let store = f.store();
    let expected: Vec<_> = fastcdc::chunks(&data).into_iter().map(|(o,n)| (blake3::hash(&data[o..o+n]).to_hex().to_string(), n as u64)).collect();
    for step in [1, 17, 65539, CHUNK+3] {
        let m = store.put_reader(Short { data: &data, step }).unwrap();
        assert_eq!(m.chunks.iter().map(|c| (c.blake3.clone(),c.len)).collect::<Vec<_>>(), expected);
        assert_eq!(store.get(&m.blake3).unwrap(), data);
    }
    let m = store.put(&data).unwrap();
    let victim = f.dir.join("store/chunks").join(&m.chunks[0].blake3);
    fs::set_permissions(&victim, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(&victim, b"poison").unwrap();
    let manifest = f.dir.join("store/manifests").join(format!("{}.json",m.blake3));
    fs::set_permissions(&manifest, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(&manifest, b"{}").unwrap();
    let session = f.begin("x.bin"); f.upload(&session,&data); f.commit(&session).unwrap();
    assert_eq!(store.get(&m.blake3).unwrap(), data, "existing entries must be checked/repaired");
    // Failure part way through a reader must never publish a new manifest.
    struct Fails { first: bool }
    impl Read for Fails {
        fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
            if !self.first { return Err(std::io::Error::other("injected read failure")); }
            self.first = false; out.fill(0x33); Ok(out.len())
        }
    }
    let before = store.roots().unwrap();
    assert!(store.put_reader(Fails { first: true }).is_err());
    assert_eq!(store.roots().unwrap(),before);
}

#[test]
fn owned_errors_truncation_digest_offset_oversize_and_replay_leave_no_manifest() {
    let bytes = payload(3*1024*1024);
    let f = Fixture::new(targets("large.bin", &bytes));
    let root = blake3::hash(&bytes).to_hex().to_string();
    for bad in [0,1,2,3] {
        let session = f.begin("large.bin");
        let result = match bad {
            0 => f.svc.handle(&f.peer, CasRequest::AdmitChunk { session:session.clone(), offset: 1, bytes: vec![1].into() }),
            1 => f.svc.handle(&f.peer, CasRequest::AdmitChunk { session:session.clone(), offset: 0, bytes: vec![1;CHUNK+1].into() }),
            2 => f.svc.handle(&f.peer, CasRequest::AdmitChunk { session:session.clone(), offset: 0, bytes: vec![].into() }),
            _ => { f.upload(&session,&bytes[..CHUNK]); f.commit(&session) },
        };
        assert!(result.is_err()); assert!(f.stages().is_empty());
        assert!(!f.store().contains(&root));
        assert!(f.commit(&session).unwrap_err().is("ADMISSION_SESSION_UNKNOWN"));
    }
    let session = f.begin("large.bin");
    let mut corrupt = bytes.clone(); corrupt[100] ^= 1;
    f.upload(&session,&corrupt);
    assert!(f.commit(&session).unwrap_err().is("CAS_ARTIFACT_DIGEST_MISMATCH"));
    assert!(f.stages().is_empty()); assert!(!f.store().contains(&root));
    let session = f.begin("large.bin");
    f.upload(&session,&bytes[..CHUNK]);
    assert!(f.svc.handle(&f.peer,CasRequest::AdmitChunk { session:session.clone(),offset:0,bytes:bytes[..CHUNK].to_vec().into() }).is_err());
    assert!(f.stages().is_empty());
    // Valid prior data remains available after a later failed streaming attempt
    // for the same signed target.
    let session = f.begin("large.bin"); f.upload(&session,&bytes); f.commit(&session).unwrap();
    let prior = f.store().manifest(&root).unwrap();
    let session = f.begin("large.bin"); f.upload(&session,&corrupt);
    assert!(f.commit(&session).is_err());
    assert_eq!(f.store().manifest(&root).unwrap(),prior);
    assert_eq!(f.store().get(&root).unwrap(),bytes);
}

#[test]
fn session_owner_bound_to_uid_gid_pid_and_abort_does_not_allow_foreign_destruction() {
    let bytes = payload(100);
    let f = Fixture::new(targets("x.bin", &bytes));
    let session = f.begin("x.bin");
    for kind in [0,1,2,3] {
        let mut foreign = f.peer.clone();
        match kind { 0 => foreign.uid ^= 1, 1 => foreign.gid ^= 1, 2 => foreign.pid = Some(foreign.pid.unwrap()+1), _ => foreign.audit_token=Some([1;8]) }
        for request in [CasRequest::AdmitChunk {session:session.clone(),offset:0,bytes:bytes.clone().into()},
            CasRequest::AdmitAbort { session:session.clone() }, CasRequest::AdmitCommit { session:session.clone() }] {
            assert!(f.svc.handle(&foreign,request).unwrap_err().is("ADMISSION_SESSION_OWNER"));
        }
    }
    assert_eq!(f.stages().len(),1);
    f.upload(&session,&bytes); f.commit(&session).unwrap();
    let session = f.begin("x.bin");
    f.svc.handle(&f.peer,CasRequest::AdmitAbort {session:session.clone()}).unwrap();
    assert!(f.stages().is_empty());
    assert!(f.commit(&session).unwrap_err().is("ADMISSION_SESSION_UNKNOWN"));
    let mut unbound = f.peer.clone(); unbound.pid=None;
    assert!(f.svc.handle(&unbound,CasRequest::AdmitBegin {target:"x.bin".into()}).unwrap_err().is("ADMISSION_PEER_PID_REQUIRED"));
}

#[test]
fn commit_rechecks_complete_signed_target_and_revocation() {
    let bytes = payload(1000);
    let f = Fixture::new(targets("x.bin", &bytes));
    let session = f.begin("x.bin"); f.upload(&session,&bytes);
    let mut changed = targets("x.bin",&bytes);
    changed.get_mut("x.bin").unwrap().custom=Some(json!({"license_changed":true}));
    f.refresh(2,changed);
    assert!(f.commit(&session).unwrap_err().is("ADMISSION_TARGET_CHANGED"));
    assert!(f.stages().is_empty());
    let session = f.begin("x.bin"); f.upload(&session,&bytes);
    let mut revoked = targets("x.bin",&bytes);
    revoked.get_mut("x.bin").unwrap().custom=Some(json!({"revoked":true}));
    f.refresh(3,revoked);
    assert!(f.commit(&session).unwrap_err().is("TARGET_REVOKED"));
    assert!(f.stages().is_empty()); assert!(f.store().roots().unwrap().is_empty());
}

#[test]
fn idle_count_restart_cleanup_freshness_and_offline_boundaries() {
    // This is the only test using the mutable wall-clock fixture.
    WALL.store(NOW,Ordering::SeqCst);
    let bytes = payload(1000);
    let mut inventory=targets("x.bin",&bytes);
    for index in 1..4 {let mut distinct=bytes.clone();*distinct.last_mut().unwrap()^=index;inventory.extend(targets(&format!("x{index}.bin"),&distinct));}
    let mut f = Fixture::with_clock(inventory,wall);
    // The four-session global bound is independent of the stricter2.5N
    // same-root staging bound. Use distinct authenticated artifacts here.
    let sessions:Vec<_> = (0..4).map(|index| f.begin(&if index==0{"x.bin".into()}else{format!("x{index}.bin")})).collect();
    assert_eq!(f.stages().len(),4);
    assert!(f.svc.handle(&f.peer,CasRequest::AdmitBegin {target:"x.bin".into()}).unwrap_err().is("ADMISSION_SESSION_LIMIT"));
    WALL.store(NOW+301,Ordering::SeqCst);
    f.svc.handle(&f.peer,CasRequest::Status).unwrap();
    assert!(f.stages().is_empty());
    for s in sessions { assert!(f.commit(&s).unwrap_err().is("ADMISSION_SESSION_UNKNOWN")); }
    WALL.store(NOW+OFFLINE_TTL_S-1,Ordering::SeqCst);
    let session = f.begin("x.bin"); f.upload(&session,&bytes);
    WALL.store(NOW+OFFLINE_TTL_S+1,Ordering::SeqCst);
    assert!(f.commit(&session).unwrap_err().is("TUF_OFFLINE_TTL"));
    assert!(f.stages().is_empty());
    assert!(f.svc.handle(&f.peer,CasRequest::AdmitBegin {target:"x.bin".into()}).unwrap_err().is("TUF_OFFLINE_TTL"));
    // A second live service must not clean this service's stages.
    WALL.store(NOW,Ordering::SeqCst);
    let other = CasService::start_with_wall_clock(config(&f.dir,&f.root),wall).unwrap_err();
    assert!(other.is("ADMISSION_STAGE_LOCK"));
    // Drop the old service before restart (replace temporarily with an unrelated
    // service to release the only Arc without moving out of a Drop type).
    let replacement_dir=f.dir.join("replacement");
    let replacement=CasService::start_with_wall_clock(config(&replacement_dir,&f.root),fixed_wall).unwrap();
    let old=std::mem::replace(&mut f.svc,replacement); drop(old);
    let stage_dir=f.dir.join("store/streaming-stages");
    let stale=stage_dir.join("stage-crashed"); fs::write(&stale,b"incomplete").unwrap();
    fs::set_permissions(&stale,fs::Permissions::from_mode(0o600)).unwrap();
    let outside=f.dir.join("outside");fs::write(&outside,b"must survive").unwrap();
    fs::set_permissions(&outside,fs::Permissions::from_mode(0o600)).unwrap();
    symlink(&outside,stage_dir.join("stage-link")).unwrap();
    let hardlink=stage_dir.join("stage-hardlink");fs::hard_link(&outside,&hardlink).unwrap();
    let error=CasService::start_with_wall_clock(config(&f.dir,&f.root),fixed_wall).unwrap_err();
    assert!(error.is("ADMISSION_CLEANUP_UNSAFE"),"{error}");
    assert_eq!(fs::read(&outside).unwrap(),b"must survive");
    fs::remove_file(hardlink).unwrap();
    let restarted=CasService::start_with_wall_clock(config(&f.dir,&f.root),fixed_wall).unwrap();
    assert!(f.stages().is_empty());assert_eq!(fs::read(&outside).unwrap(),b"must survive");
    assert!(!stale.exists());
    drop(restarted);
    // A live session that crosses signed timestamp expiry must consume and
    // clean its stage even though its idle lifetime has not elapsed.
    WALL.store(NOW,Ordering::SeqCst);
    let fresh=Fixture::with_clock(targets("x.bin",&bytes),wall);
    let tg=fresh.repo.targets(2,EXP,targets("x.bin",&bytes)).unwrap();
    let snap=fresh.repo.snapshot(2,EXP,2,&tg).unwrap();
    let ts=fresh.repo.timestamp(2,"2026-11-05T13:21:30Z",2,&snap).unwrap();
    fresh.svc.handle(&fresh.peer,CasRequest::TufRefresh {roots:vec![],timestamp:ts.into(),snapshot:snap.into(),targets:tg.into()}).unwrap();
    let session=fresh.begin("x.bin");fresh.upload(&session,&bytes);
    WALL.store(NOW+31,Ordering::SeqCst);
    assert!(fresh.commit(&session).unwrap_err().is("TUF_METADATA_EXPIRED"));
    assert!(fresh.stages().is_empty());
    // Wipe discards active staging as well as the old key state.
    fresh.refresh(3,targets("x.bin",&bytes));
    let session=fresh.begin("x.bin");
    fresh.svc.handle(&fresh.peer,CasRequest::Wipe).unwrap();
    assert!(fresh.stages().is_empty());
    assert!(fresh.commit(&session).unwrap_err().is("ADMISSION_SESSION_UNKNOWN"));
}

#[test]
fn small_legacy_admit_and_fetch_apis_remain_compatible() {
    let bytes=b"{\"version\":1}";
    let f=Fixture::new(targets("config.json",bytes));
    let socket=f.socket(); let mut c=socket.connect();
    let reply:CasResponse=c.call(&CasRequest::Admit { target:"config.json".into(),bytes:bytes.to_vec().into() }).unwrap();
    assert!(matches!(reply,CasResponse::Admitted { root } if root==blake3::hash(bytes).to_hex().as_str()));
    fs::write(f.dir.join("store/config.json"),bytes).unwrap();
    let reply:CasResponse=c.call(&CasRequest::FetchTarget {target:"config.json".into()}).unwrap();
    assert!(matches!(reply,CasResponse::Bytes(b) if b.as_ref()==bytes));
}

#[test]
fn named_signed_snapshots_reject_changed_length_hash_symlinks_and_malformed_policy() {
    let bytes=payload(3*1024*1024);
    let mut signed=targets("nested/config",&bytes);
    for name in ["wrong-sha", "wrong-b3", "truncated", "extra", "link", "directory", "partial-policy", "floor.bin", "revoked.bin", "evil.pkl"] {
        signed.insert(name.into(),target_file(&bytes,Some(json!({}))));
    }
    signed.get_mut("wrong-sha").unwrap().hashes.insert("sha256".into(),"0".repeat(64));
    signed.get_mut("wrong-b3").unwrap().hashes.insert("blake3".into(),"0".repeat(64));
    signed.get_mut("partial-policy").unwrap().custom=Some(json!({"min_profile":"L3"}));
    signed.get_mut("floor.bin").unwrap().custom=Some(json!({"classification":"internal_l2","min_profile":"L3","license_policy":{"spdx_id":"LicenseRef-private","allow_p2p_seeding":false}}));
    signed.get_mut("revoked.bin").unwrap().custom=Some(json!({"revoked":true}));
    signed.insert("../escape".into(),target_file(&bytes,Some(json!({}))));
    let f=Fixture::new(signed);
    fs::create_dir(f.dir.join("store/nested")).unwrap();
    fs::write(f.dir.join("store/nested/config"),&bytes).unwrap();
    for name in ["wrong-sha","wrong-b3","partial-policy","floor.bin","revoked.bin","evil.pkl"] { fs::write(f.dir.join("store").join(name),&bytes).unwrap(); }
    fs::write(f.dir.join("store/truncated"),&bytes[..bytes.len()-1]).unwrap();
    let mut extra=bytes.clone();extra.push(0);fs::write(f.dir.join("store/extra"),extra).unwrap();
    fs::create_dir(f.dir.join("store/directory")).unwrap();
    symlink(f.dir.join("store/nested/config"),f.dir.join("store/link")).unwrap();
    let socket=f.socket();
    let (_,mut snapshot)=socket.open("nested/config");
    // Snapshot stays the verified original if the mutable source is changed.
    fs::write(f.dir.join("store/nested/config"),b"mutated source").unwrap();
    let mut got=Vec::new();snapshot.read_to_end(&mut got).unwrap();assert_eq!(got,bytes);
    for name in ["nested/config","wrong-sha","wrong-b3","truncated","extra","link","directory","partial-policy","floor.bin","revoked.bin","evil.pkl","../escape"] {
        let result=f.svc.handle(&f.peer,CasRequest::OpenTarget {target:name.into()});
        assert!(result.is_err(),"must refuse {name}: {result:?}");
        assert!(f.stages().is_empty());
    }
    // A symlink in an intermediate component must also fail closed.
    fs::remove_dir_all(f.dir.join("store/nested")).unwrap();
    symlink("/tmp",f.dir.join("store/nested")).unwrap();
    assert!(f.svc.handle(&f.peer,CasRequest::OpenTarget {target:"nested/config".into()}).is_err());
}

#[test]
fn malformed_signed_parameters_and_excessive_length_refuse_before_staging() {
    let bytes=payload(1000);
    let mut signed=targets("good.bin",&bytes);
    for name in ["bad.bin","huge.bin"] {signed.insert(name.into(),target_file(&bytes,Some(json!({}))));}
    signed.get_mut("bad.bin").unwrap().hashes.insert("blake3".into(),"../bad".into());
    signed.get_mut("huge.bin").unwrap().length=8*1024*1024*1024+1;
    let f=Fixture::new(signed.clone());
    // Missing mandatory digests are rejected while adopting signed metadata,
    // before any admission session can observe that malformed TargetFile.
    let mut missing=target_file(&bytes,Some(json!({})));
    missing.hashes.remove("sha256");signed.insert("missing.bin".into(),missing);
    let tg=f.repo.targets(2,EXP,signed).unwrap();
    let snap=f.repo.snapshot(2,EXP,2,&tg).unwrap();
    let ts=f.repo.timestamp(2,EXP,2,&snap).unwrap();
    let result=f.svc.handle(&f.peer,CasRequest::TufRefresh {roots:vec![],timestamp:ts.into(),snapshot:snap.into(),targets:tg.into()});
    assert!(result.unwrap_err().is("TUF_TARGET_SINGLE_HASH"));
    assert!(f.stages().is_empty());
    for name in ["missing.bin","bad.bin","huge.bin"] {
        for request in [CasRequest::AdmitBegin {target:name.into()},CasRequest::OpenTarget {target:name.into()}] {
            assert!(f.svc.handle(&f.peer,request).is_err());assert!(f.stages().is_empty());
        }
    }
}

#[test]
fn streamed_safetensors_and_zip_keep_structural_sanitizer_semantics() {
    let tensor=build_safetensors(&[("weight","U8",vec![3*1024*1024],vec![3;3*1024*1024])],&[]);
    let zip=build_stored_zip(&[("Data/weights.bin",&tensor,false),("Manifest.json",b"{}",false)]);
    let mut trailing=tensor.clone();trailing.push(0);
    let malicious=build_stored_zip(&[("../escape",b"x",false)]);
    let custom=build_stored_zip(&[("model.mlmodel",&[0xa2,0x1f,0],false)]);
    let cases=[("good.safetensors",tensor,true),("good.mlpackage.zip",zip,true),
        ("trailing.safetensors",trailing,false),("bad.mlpackage.zip",malicious,false),("custom.mlpackage",custom,false)];
    let mut signed=BTreeMap::new();
    for (name,bytes,_) in &cases {signed.insert((*name).into(),target_file(bytes,Some(json!({}))));}
    let f=Fixture::new(signed);
    let socket=f.socket();
    for (name,bytes,valid) in cases {
        let old=if name.ends_with(".safetensors") {
            enclave_swarm_syncd::sanitizer::check_safetensors(&bytes).map(|_| ())
        } else {enclave_swarm_syncd::sanitizer::check_mlpackage_zip(&bytes,bytes.len() as u64).map(|_| ())};
        assert_eq!(old.is_ok(),valid,"fixture sanitizer expectation {name}: {old:?}");
        let session=f.begin(name);f.upload(&session,&bytes);
        let result=f.commit(&session);
        assert_eq!(result.is_ok(),valid,"streamed sanitizer result {name}: {result:?}");
        if let (Err(old),Err(new))=(old,result) {assert_eq!(old.reason,new.reason);}
        assert!(f.stages().is_empty());
        // Direct named exports undergo equivalent sanitizer checks even without
        // prior Admit; malformed signed bytes must never yield an FD.
        fs::write(f.dir.join("store").join(name),&bytes).unwrap();
        if valid {
            let (_,mut file)=socket.open(name);let mut got=Vec::new();file.read_to_end(&mut got).unwrap();assert_eq!(got,bytes);
        } else {assert!(f.svc.handle(&f.peer,CasRequest::OpenTarget {target:name.into()}).is_err());}
    }
}

#[test]
fn corrupted_cas_or_materialized_cache_never_exports_unverified_bytes() {
    let bytes=payload(3*1024*1024);
    let f=Fixture::new(targets("x.bin",&bytes));
    let session=f.begin("x.bin");f.upload(&session,&bytes);f.commit(&session).unwrap();
    let store=f.store();let root=blake3::hash(&bytes).to_hex().to_string();
    let canonical=store.open_readonly(&root).unwrap();drop(canonical);
    let object=f.dir.join("store/objects").join(&root);
    fs::set_permissions(&object,fs::Permissions::from_mode(0o600)).unwrap();fs::write(&object,b"poison cached object").unwrap();
    let socket=f.socket();
    // OpenTarget reconstructs a fresh verified snapshot from chunks instead of
    // trusting a mutable cached canonical object.
    let (_,mut fd)=socket.open("x.bin");let mut got=Vec::new();fd.read_to_end(&mut got).unwrap();assert_eq!(got,bytes);
    let m=store.manifest(&root).unwrap();
    let chunk=f.dir.join("store/chunks").join(&m.chunks[0].blake3);
    fs::set_permissions(&chunk,fs::Permissions::from_mode(0o600)).unwrap();fs::write(&chunk,b"poison chunk").unwrap();
    assert!(f.svc.handle(&f.peer,CasRequest::OpenTarget {target:"x.bin".into()}).is_err());
    assert!(f.stages().is_empty());
}
