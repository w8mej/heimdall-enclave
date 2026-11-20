//! Permanent local quarantine registration and one-action release leases.
//! This is a cooperating local protocol, not remote recall or fleet revocation.
use super::receipt::{
    PoisonEvidence,
    PoisonReceipt
};
use ed25519_dalek::SigningKey;
use enclave_core::{
    err,
    error::{
        EnclaveError,
        EnclaveResult
    },
    fail
};
use serde::Serialize;
use std::{
    collections::{
        BTreeMap,
        BTreeSet
    },
    fs::File,
    io::{
        Read,
        Write
    },
    os::unix::{
        fs::{
            FileExt,
            MetadataExt,
            OpenOptionsExt
        },
        io::{
            AsRawFd,
            FromRawFd
        }
    },
    path::{
        Component,
        Path,
        PathBuf
    },
    sync::{
        atomic::{
            AtomicBool,
            Ordering
        },
        Arc,
        Mutex,
        OnceLock
    },
    time::{
        Duration,
        Instant
    },
};
const REG_SIZE: usize = 256;
const LOCK_SIZE: usize = 128;
const MAX_PEERS: usize = 4096;
const MAX_DOMAINS: usize = 64;
const MAX_RECEIPT: usize = 8192;
macro_rules! stage {
    ($name:ident) => {{
        #[cfg(test)]
        super::quic_fence_test_support::hook(super::quic_fence_test_support::Stage::$name, 1);
    }};
}
macro_rules! fault {
    ($name:ident) => {{
        #[cfg(test)] { super::quic_fence_test_support::fault(super::quic_fence_test_support::Fault::$name, 1) }
        #[cfg(not(test))] { false }
    }};
}

#[derive(Debug, Default)]
struct Registry {
    peers: BTreeMap<[u8; 32], Arc<AtomicBool>>,
    domains: BTreeMap<[u8; 32], Arc<DomainPin>>,
}
/// Strongly owned for process lifetime; entries are never removed or reset.
#[derive(Debug)]
pub(crate) struct ProcessPeerStops {
    registry: Mutex<Registry>
}
static PROCESS_STOPS: OnceLock<Arc<ProcessPeerStops>> = OnceLock::new();
pub(crate) fn process_peer_stops() -> Arc<ProcessPeerStops> {
    PROCESS_STOPS.get_or_init(|| Arc::new(ProcessPeerStops{registry:Mutex::new(Registry::default())})).clone()
}
#[derive(Debug)]
struct DomainPin {
    path: PathBuf,
    dir: Arc<File>,
    identity: (u64, u64),
    detector: [u8; 32],
    ready_bindings: Mutex<BTreeMap<[u8;32], Arc<OnceLock<((u64, u64), (u64, u64))>>>>,
}
#[derive(Debug)]
pub(crate) struct PeerDomain {
    peers: BTreeMap<[u8; 32], Arc<PoisonState>>
}
impl PeerDomain {
    pub(crate) fn peer(&self, peer: &[u8; 32]) -> EnclaveResult<&Arc<PoisonState>> {
        self.peers.get(peer).ok_or_else(|| err!(EACCES, "L2_PEER_DENIED"))
    }
}
fn normalized(path: &str) -> EnclaveResult<PathBuf> {
    if path.len() > 4096 || !Path::new(path).is_absolute() || path.bytes().any(|b| b == 0 || b.is_ascii_control()) {
        fail!(EINVAL, "L2_POISON_DIRECTORY");
    }
    let mut out = PathBuf::new();
    for part in Path::new(path).components() {
        match part {
            Component::RootDir | Component::Normal(_) => out.push(part.as_os_str()),
            Component::CurDir => {
            },
            _ => fail!(EINVAL, "L2_POISON_DIRECTORY")
        }
    }
    Ok(out)
}
fn identity(file: &File) -> EnclaveResult<(u64, u64)> {
    let m = file.metadata().map_err(|_| err!(EIO, "L2_POISON_STATE"))?;
    Ok((m.dev(), m.ino()))
}
fn open_directory(path: &Path) -> EnclaveResult<File> {
    let file = std::fs::OpenOptions::new().read(true) .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK) .open(path).map_err(|_| err!(EACCES, "L2_POISON_DIRECTORY"))?;
    let m=file.metadata().map_err(|_|err!(EIO, "L2_POISON_DIRECTORY"))?;
    if !m.is_dir() || m.uid()!=enclave_core::ipc::geteuid() || m.mode()&0o7777!=0o700 {
        fail!(EACCES, "L2_POISON_DIRECTORY");
    }
    Ok(file)
}
impl ProcessPeerStops {
    /// Only trusted configured keys may reach this method. Reservation is
    /// atomic before any new authority can become operational.
    pub(crate) fn reserve_domain(self: &Arc<Self>, path: &str, detector: [u8;32], peers: &[[u8;32]]) -> EnclaveResult<PeerDomain> {
        let candidate_path=normalized(path)?;
        let candidate=open_directory(&candidate_path)?;
        let candidate_identity=identity(&candidate)?;
        let (pin, slots)=self.reserve(candidate_path, candidate, candidate_identity, detector, peers)?;
        pin.check_path()?;
        let mut states=BTreeMap::new();
        for (peer, stop) in slots {
            let binding={
                let mut bindings=pin.ready_bindings.lock().map_err(|_|err!(EIO, "L2_POISON_REGISTRY"))?;
                if !bindings.contains_key(&peer)&&bindings.len()>=MAX_PEERS{
                    fail!(E2BIG, "L2_POISON_REGISTRY_CAPACITY");
                }
                bindings.entry(peer).or_insert_with(||Arc::new(OnceLock::new())).clone()
            };
            let state=Arc::new(PoisonState{
                pin:pin.clone(),
                peer,
                stop,
                ready_binding:binding
            });
            state.provision_or_attach()?;
            states.insert(peer, state);
        }
        Ok(PeerDomain{
            peers:states
        })
    }
    // Shared real reservation primitive. Tests of registry capacity use this
    // exact primitive without claiming thousands of filesystem provisions.
    fn reserve(&self, path:PathBuf, dir:File, id:(u64, u64), detector:[u8;32], peers:&[[u8;32]]) -> EnclaveResult<(Arc<DomainPin>, BTreeMap<[u8;32], Arc<AtomicBool>>)> {
        if peers.is_empty() || peers.len()>1024 {
            fail!(E2BIG, "L2_POISON_PEER_CONFIG");
        }
        let unique:BTreeSet<_>=peers.iter().copied().collect();
        if unique.len()!=peers.len(){
            fail!(EINVAL, "L2_POISON_PEER_CONFIG");
        }
        let mut r=self.registry.lock().map_err(|_|err!(EIO, "L2_POISON_REGISTRY"))?;
        if let Some(pin)=r.domains.get(&detector) {
            if pin.path!=path || pin.identity!=id {
                fail!(EACCES, "L2_POISON_DOMAIN_REBOUND");
            }
        }
        let missing=unique.iter().filter(|key|!r.peers.contains_key(*key)).count();
        if r.peers.len()+missing>MAX_PEERS || (!r.domains.contains_key(&detector)&&r.domains.len()>=MAX_DOMAINS) {
            fail!(E2BIG, "L2_POISON_REGISTRY_CAPACITY");
        }
        let candidate=Arc::new(DomainPin{
            path,
            dir:Arc::new(dir),
            identity:id,
            detector,
            ready_bindings:Mutex::new(BTreeMap::new())
        });
        let pin=if let Some(pin)=r.domains.get(&detector){
            pin.clone()
        }
        else{
            r.domains.insert(detector, candidate.clone());
            candidate.clone()
        };
        let slots=unique.into_iter().map(|key|{
            let stop=r.peers.entry(key).or_insert_with(||Arc::new(AtomicBool::new(false))).clone();
            (key, stop)
        }).collect();
        drop(r);
        drop(candidate);
        // rejected open descriptions close only after registry unlock
        Ok((pin, slots))
    }
}
impl DomainPin {
    fn check_path(&self)->EnclaveResult<()> {
        let current=open_directory(&self.path)?;
        if identity(&current)?!=self.identity || identity(&self.dir)?!=self.identity {
            fail!(EACCES, "L2_POISON_DOMAIN_REBOUND");
        }
        Ok(())
    }
}
#[derive(Debug)]
pub(crate) struct PoisonState {
    pin:Arc<DomainPin>,
    peer:[u8;32],
    stop:Arc<AtomicBool>,
    ready_binding:Arc<OnceLock<((u64, u64), (u64, u64))>>
}
/// One independent open description; deliberately not Clone or duplicable.
#[derive(Debug)]
pub(crate) struct CleanPeerLease {
    _file:File
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub(crate) enum PublishOutcome {
    CreatedOriginalDurablyFenced{
        original_blake3:[u8;32]
    },
    ExistingOriginalDurablyFenced{
        original_blake3:[u8;32]
    },
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub(crate) enum PublishReason {
    Timestamp,
    Serialization,
    ReceiptSize,
    Registration,
    MarkerCreate,
    ExistingInvalid,
    Write,
    FileSync,
    DirectorySync,
    FenceTimeout,
    FenceIo,
    FenceIdentity
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub(crate) enum MarkerProgress {
    NotObserved,
    PresentUnverified,
    ValidatedUnsynced,
    FileSynced,
    FileAndDirectorySynced
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub(crate) struct PublishFailure {
    pub(crate) reason:PublishReason,
    pub(crate) marker_progress:MarkerProgress
}
impl PublishFailure {
    pub(crate) fn into_enclave(self)->EnclaveError {
        let reason=match self.reason {
            PublishReason::Timestamp=>"L2_POISON_TIMESTAMP",
            PublishReason::Serialization=>"L2_POISON_SERIALIZATION",
            PublishReason::ReceiptSize=>"L2_POISON_RECEIPT_SIZE",
            PublishReason::Registration=>"L2_POISON_REGISTRATION",
            PublishReason::MarkerCreate=>"L2_POISON_MARKER_CREATE",
            PublishReason::ExistingInvalid=>"L2_POISON_EXISTING_INVALID",
            PublishReason::Write=>"L2_POISON_WRITE",
            PublishReason::FileSync=>"L2_POISON_FILE_SYNC",
            PublishReason::DirectorySync=>"L2_POISON_DIRECTORY_SYNC",
            PublishReason::FenceTimeout=>"L2_POISON_FENCE_TIMEOUT",
            PublishReason::FenceIo=>"L2_POISON_FENCE_IO",
            PublishReason::FenceIdentity=>"L2_POISON_FENCE_IDENTITY"
        };
        err!(EIO, reason)
    }
}
fn publication_error(reason:PublishReason, marker_progress:MarkerProgress)->PublishFailure {
    PublishFailure{
        reason,
        marker_progress
    }
}
#[derive(Clone, Copy)]
struct LeafFacts {
    uid:u32,
    mode:u32,
    nlink:u64,
    len:u64,
    regular:bool
}
impl LeafFacts {
    fn from(m:&std::fs::Metadata)->Self {
        Self{
            uid:m.uid(),
            mode:m.mode(),
            nlink:m.nlink(),
            len:m.len(),
            regular:m.is_file()
        }
    }
    fn valid(&self, size:Option<usize>)->bool {
        self.regular&&self.uid==enclave_core::ipc::geteuid()&&self.mode&0o7777==0o600&&self.nlink==1 &&size.map_or(self.len>0&&self.len<=MAX_RECEIPT as u64, |n|self.len==n as u64)
    }
}
impl PoisonState {
    fn name(&self, suffix:&str)->std::ffi::CString {
        std::ffi::CString::new(format!("{}{}", hex::encode(self.peer), suffix)).expect("fixed canonical leaf")
    }
    fn present(&self, suffix:&str)->EnclaveResult<bool> {
        let mut st=std::mem::MaybeUninit::<libc::stat>::uninit();
        let result=unsafe{
            libc::fstatat(self.pin.dir.as_raw_fd(), self.name(suffix).as_ptr(), st.as_mut_ptr(), libc::AT_SYMLINK_NOFOLLOW)
        };
        if result==0 {
            return Ok(true);
        }
        if std::io::Error::last_os_error().raw_os_error()==Some(libc::ENOENT){
            Ok(false)
        }
        else{
            Err(err!(EACCES, "L2_POISON_STATE"))
        }
    }
    fn same_entry(&self, suffix:&str, file:&File)->EnclaveResult<()> {
        let m=file.metadata().map_err(|_|err!(EIO, "L2_POISON_STATE"))?;
        let mut st=std::mem::MaybeUninit::<libc::stat>::uninit();
        if unsafe{
            libc::fstatat(self.pin.dir.as_raw_fd(), self.name(suffix).as_ptr(), st.as_mut_ptr(), libc::AT_SYMLINK_NOFOLLOW)
        }
        !=0 {
            fail!(EACCES, "L2_POISON_STATE");
        }
        let st=unsafe{
            st.assume_init()
        };
        if st.st_dev as u64!=m.dev()||st.st_ino as u64!=m.ino()||st.st_mode as u32!=m.mode() ||st.st_uid!=m.uid()||st.st_nlink as u64!=m.nlink()||st.st_size as u64!=m.len(){
            fail!(EACCES, "L2_POISON_STATE");
        }
        Ok(())
    }
    fn open_leaf(&self, suffix:&str, create:bool)->std::io::Result<File> {
        let flags=libc::O_RDWR|libc::O_NOFOLLOW|libc::O_NONBLOCK|libc::O_CLOEXEC |if create{
            libc::O_CREAT|libc::O_EXCL
        }
        else{
            0
        };
        let fd=unsafe{
            libc::openat(self.pin.dir.as_raw_fd(), self.name(suffix).as_ptr(), flags, 0o600)
        };
        if fd<0{
            Err(std::io::Error::last_os_error())
        }
        else{
            Ok(unsafe{
                File::from_raw_fd(fd)
            })
        }
    }
    fn checked(&self, suffix:&str, size:Option<usize>)->EnclaveResult<File> {
        let file=self.open_leaf(suffix, false).map_err(|_|err!(EACCES, "L2_POISON_STATE"))?;
        if !LeafFacts::from(&file.metadata().map_err(|_|err!(EIO, "L2_POISON_STATE"))?).valid(size){
            fail!(EACCES, "L2_POISON_STATE");
        }
        self.same_entry(suffix, &file)?;
        Ok(file)
    }
    fn bytes<const N:usize>(&self, file:&File)->EnclaveResult<[u8;N]> {
        let mut out=[0;N];
        let mut offset=0;
        while offset<N {
            let n=file.read_at(&mut out[offset..], offset as u64).map_err(|_|err!(EIO, "L2_POISON_STATE"))?;
            if n==0{
                fail!(EACCES, "L2_POISON_STATE");
            }
            offset+=n;
        }
        let mut extra=[0];
        if file.read_at(&mut extra, N as u64).map_err(|_|err!(EIO, "L2_POISON_STATE"))?!=0{
            fail!(EACCES, "L2_POISON_STATE");
        }
        Ok(out)
    }
    fn registration(&self, state:u32, nonce:[u8;32], lock:Option<&File>, header:Option<&[u8;128]>)->EnclaveResult<[u8;REG_SIZE]> {
        let mut reg=[0;REG_SIZE];
        reg[..8].copy_from_slice(b"depotQREG1");
        reg[8..12].copy_from_slice(&1u32.to_be_bytes());
        reg[12..16].copy_from_slice(&state.to_be_bytes());
        reg[16..48].copy_from_slice(&self.peer);
        reg[48..80].copy_from_slice(&self.pin.detector);
        reg[80..112].copy_from_slice(&nonce);
        reg[112..120].copy_from_slice(&self.pin.identity.0.to_be_bytes());
        reg[120..128].copy_from_slice(&self.pin.identity.1.to_be_bytes());
        if let (Some(lock), Some(header))=(lock, header){
            let id=identity(lock)?;
            reg[128..136].copy_from_slice(&id.0.to_be_bytes());
            reg[136..144].copy_from_slice(&id.1.to_be_bytes());
            reg[144..176].copy_from_slice(blake3::hash(header).as_bytes());
        }
        let hash=blake3::hash(&reg[..224]);
        reg[224..].copy_from_slice(hash.as_bytes());
        Ok(reg)
    }
    fn lock_header(&self, nonce:[u8;32])->[u8;LOCK_SIZE] {
        let mut h=[0;LOCK_SIZE];
        h[..8].copy_from_slice(b"depotQLOK1");
        h[8..12].copy_from_slice(&1u32.to_be_bytes());
        h[16..48].copy_from_slice(&self.peer);
        h[48..80].copy_from_slice(&self.pin.detector);
        h[80..112].copy_from_slice(&nonce);
        h
    }
    fn ready(&self)->EnclaveResult<(File, File)> {
        let reg=self.checked(".qreg1", Some(REG_SIZE))?;
        let r=self.bytes::<REG_SIZE>(&reg)?;
        let lock=self.checked(".qlock1", Some(LOCK_SIZE))?;
        let h=self.bytes::<LOCK_SIZE>(&lock)?;
        let nonce:[u8;32]=r[80..112].try_into().expect("fixed interval");
        if r!=self.registration(2, nonce, Some(&lock), Some(&h))?||h!=self.lock_header(nonce){
            fail!(EACCES, "L2_POISON_STATE");
        }
        let ids=(identity(&reg)?, identity(&lock)?);
        if *self.ready_binding.get_or_init(||ids)!=ids{
            fail!(EACCES, "L2_POISON_STATE");
        }
        Ok((reg, lock))
    }
    fn validate_ready_identity(&self, reg:&File, lock:&File)->EnclaveResult<()> {
        self.same_entry(".qreg1", reg)?;
        self.same_entry(".qlock1", lock)?;
        if !LeafFacts::from(&reg.metadata().map_err(|_|err!(EIO, "L2_POISON_STATE"))?).valid(Some(REG_SIZE)) ||!LeafFacts::from(&lock.metadata().map_err(|_|err!(EIO, "L2_POISON_STATE"))?).valid(Some(LOCK_SIZE)){
            fail!(EACCES, "L2_POISON_STATE");
        }
        Ok(())
    }
    fn write_at_all(file:&File, mut bytes:&[u8], mut offset:u64)->EnclaveResult<()> {
        while !bytes.is_empty(){
            let n=file.write_at(bytes, offset).map_err(|_|err!(EIO, "L2_POISON_STATE"))?;
            if n==0{
                fail!(EIO, "L2_POISON_STATE");
            }
            bytes=&bytes[n..];
            offset+=n as u64;
        }
        Ok(())
    }
    fn provision_or_attach(&self)->EnclaveResult<()> {
        self.pin.check_path()?;
        if self.present(".qreg1")? {
            let (reg, lock)=self.ready()?;
            // No flock or service mutex spans these attachment syncs.
            lock.sync_all().and_then(|_|reg.sync_all()).and_then(|_|self.pin.dir.sync_all()).map_err(|_|err!(EIO, "L2_POISON_STATE"))?;
            let (reg2, lock2)=self.ready()?;
            self.validate_ready_identity(&reg, &lock)?;
            if identity(&reg)?!=identity(&reg2)?||identity(&lock)?!=identity(&lock2)?{
                fail!(EACCES, "L2_POISON_STATE");
            }
            self.pin.check_path()?;
            return Ok(());
        }
        if self.present(".json")?||self.present(".qlock1")?{
            fail!(EACCES, "L2_POISON_STATE");
        }
        stage!(BeforeRegistrationCreate);
        let reg=match self.open_leaf(".qreg1", true){
            Ok(file)=>file,
            Err(e) if e.raw_os_error()==Some(libc::EEXIST)=>{
                // A losing creator may conservatively refuse any provisioning race.
                let existing=self.checked(".qreg1", Some(REG_SIZE))?;
                if unsafe{
                    libc::flock(existing.as_raw_fd(), libc::LOCK_SH|libc::LOCK_NB)
                }
                !=0{
                    fail!(EACCES, "L2_POISON_STATE");
                }
                drop(existing);
                return self.attach_existing();
            },
            Err(_)=>return Err(err!(EACCES, "L2_POISON_STATE"))
        };
        stage!(RegistrationCreated);
        if unsafe{
            libc::flock(reg.as_raw_fd(), libc::LOCK_EX|libc::LOCK_NB)
        }
        !=0{
            fail!(EACCES, "L2_POISON_STATE");
        }
        let nonce=enclave_core::rng::bytes32();
        let pending=self.registration(1, nonce, None, None)?;
        Self::write_at_all(&reg, &pending, 0)?;
        stage!(PendingWritten);
        reg.sync_all().and_then(|_|self.pin.dir.sync_all()).map_err(|_|err!(EIO, "L2_POISON_STATE"))?;
        stage!(PendingSynced);
        let lock=self.open_leaf(".qlock1", true).map_err(|_|err!(EACCES, "L2_POISON_STATE"))?;
        if unsafe{
            libc::flock(lock.as_raw_fd(), libc::LOCK_EX|libc::LOCK_NB)
        }
        !=0{
            fail!(EACCES, "L2_POISON_STATE");
        }
        stage!(LockCreated);
        let header=self.lock_header(nonce);
        Self::write_at_all(&lock, &header, 0)?;
        lock.sync_all().and_then(|_|self.pin.dir.sync_all()).map_err(|_|err!(EIO, "L2_POISON_STATE"))?;
        stage!(LockSynced);
        let ready=self.registration(2, nonce, Some(&lock), Some(&header))?;
        #[cfg(test)] if super::quic_fence_test_support::selected(Stage::ReadyPrefixWritten, 1) {
            Self::write_at_all(&reg, &ready[..128], 0)?;
            stage!(ReadyPrefixWritten);
        }
        Self::write_at_all(&reg, &ready, 0)?;
        stage!(ReadyWritten);
        reg.sync_all().and_then(|_|self.pin.dir.sync_all()).map_err(|_|err!(EIO, "L2_POISON_STATE"))?;
        self.validate_ready_identity(&reg, &lock)?;
        let (_r, _l)=self.ready()?;
        self.pin.check_path()?;
        stage!(ReadySynced);
        drop(lock);
        drop(reg);
        Ok(())
    }
    fn attach_existing(&self)->EnclaveResult<()> {
        let (reg, lock)=self.ready()?;
        lock.sync_all().and_then(|_|reg.sync_all()).and_then(|_|self.pin.dir.sync_all()).map_err(|_|err!(EIO, "L2_POISON_STATE"))?;
        self.validate_ready_identity(&reg, &lock)?;
        let (r, l)=self.ready()?;
        if identity(&r)?!=identity(&reg)?||identity(&l)?!=identity(&lock)?{
            fail!(EACCES, "L2_POISON_STATE");
        }
        self.pin.check_path()
    }
    pub(crate) fn is_stopped(&self)->bool {
        self.stop.load(Ordering::SeqCst)
    }
    pub(crate) fn clean_lease(&self)->EnclaveResult<CleanPeerLease> {
        if self.is_stopped(){
            fail!(EPERM, "PEER_QUARANTINED_BYZANTINE");
        }
        self.pin.check_path()?;
        let (reg, lock)=self.ready()?;
        if unsafe{
            libc::flock(lock.as_raw_fd(), libc::LOCK_SH|libc::LOCK_NB)
        }
        !=0{
            fail!(EACCES, "L2_POISON_LEASE");
        }
        self.validate_ready_identity(&reg, &lock)?;
        // Re-read complete binding under SH, not merely the old entry metadata.
        let r=self.bytes::<REG_SIZE>(&reg)?;
        let h=self.bytes::<LOCK_SIZE>(&lock)?;
        let nonce=r[80..112].try_into().expect("fixed interval");
        if r!=self.registration(2, nonce, Some(&lock), Some(&h))?||h!=self.lock_header(nonce)||self.is_stopped()||self.present(".json")?{
            fail!(EPERM, "PEER_QUARANTINED_BYZANTINE");
        }
        Ok(CleanPeerLease{
            _file:lock
        })
    }
    /// Latch first. The clock callback runs only outside file/action guards.
    pub(crate) fn record(&self, signer:&SigningKey, root:&str, index:u64, bytes:&[u8], exporter:&[u8;32], clock:impl FnOnce()->EnclaveResult<u64>) ->Result<PublishOutcome,
    PublishFailure> {
        use MarkerProgress::*;
        use PublishReason::*;
        self.stop.store(true, Ordering::SeqCst);
        #[cfg(test)]super::quic_fence_test_support::note(super::quic_fence_test_support::Note::PublicationObservation{
            peer:self.peer,
            detector:self.pin.detector,
            exporter:*exporter,
            observed_blake3:*blake3::hash(bytes).as_bytes(),
            stopped:self.is_stopped()
        });
        if fault!(PublisherTimestamp){
            return Err(publication_error(Timestamp, NotObserved));
        }
        let timestamp=clock().map_err(|_|publication_error(Timestamp, NotObserved))?;
        if signer.verifying_key().to_bytes()!=self.pin.detector{
            return Err(publication_error(Registration, NotObserved));
        }
        let receipt=PoisonReceipt::sign(signer, &PoisonEvidence{
            peer_id:&hex::encode(self.peer),
            target_root:root,
            slice_index:index,
            expected_hash:root,
            corrupted_slice:bytes,
            session_binding:&hex::encode(exporter),
            timestamp_utc_ms:timestamp
        });
        if fault!(Serialization){
            return Err(publication_error(Serialization, NotObserved));
        }
        let bytes=serde_json::to_vec(&receipt).map_err(|_|publication_error(Serialization, NotObserved))?;
        if bytes.is_empty()||bytes.len()>MAX_RECEIPT{
            return Err(publication_error(ReceiptSize, NotObserved));
        }
        self.pin.check_path().and_then(|_|self.ready().map(|_|())).map_err(|_|publication_error(Registration, NotObserved))?;
        #[cfg(test)] if super::quic_fence_test_support::selected(Stage::PublicationPrepared, 1) {
            assert!(self.is_stopped()&&self.clean_lease().is_err(), "live pre-marker local refusal");
        }
        stage!(PublicationPrepared);
        if fault!(MarkerCreate){
            return Err(publication_error(MarkerCreate, NotObserved));
        }
        let (mut marker, created)=match self.open_leaf(".json", true) {
            Ok(file)=>(file, true),
            Err(e) if e.raw_os_error()==Some(libc::EEXIST)=> (self.checked(".json", None).map_err(|_|publication_error(ExistingInvalid, PresentUnverified))?, false),
            Err(_)=>return Err(publication_error(MarkerCreate, NotObserved)),
        };
        let mut progress=PresentUnverified;
        let original=if created {
            stage!(MarkerCreated);
            // A real first write exposes a real prefix before continuation.
            let first=marker.write(&bytes[..bytes.len().min(64)]).map_err(|error|{#[cfg(test)]super::quic_fence_test_support::note(super::quic_fence_test_support::Note::PublicationWriteError{errno:error.raw_os_error()});let _=error;publication_error(Write,progress)})?;
            if first==0{
                return Err(publication_error(Write, progress));
            }
            stage!(MarkerPrefixWritten);
            marker.write_all(&bytes[first..]).map_err(|error|{#[cfg(test)]super::quic_fence_test_support::note(super::quic_fence_test_support::Note::PublicationWriteError{errno:error.raw_os_error()});let _=error;publication_error(Write,progress)})?;
            bytes
        }
        else {
            let mut original=Vec::new();
            (&mut marker).take((MAX_RECEIPT+1)as u64).read_to_end(&mut original).map_err(|_|publication_error(ExistingInvalid, progress))?;
            if original.is_empty()||original.len()>MAX_RECEIPT{
                return Err(publication_error(ExistingInvalid, progress));
            }
            let prior:PoisonReceipt=serde_json::from_slice(&original).map_err(|_|publication_error(ExistingInvalid, progress))?;
            prior.verify().map_err(|_|publication_error(ExistingInvalid, progress))?;
            if prior.peer_id!=hex::encode(self.peer)||prior.detector_id!=hex::encode(self.pin.detector){
                return Err(publication_error(ExistingInvalid, progress));
            }
            original
        };
        self.same_entry(".json", &marker).map_err(|_|publication_error(ExistingInvalid, progress))?;
        if !LeafFacts::from(&marker.metadata().map_err(|_|publication_error(ExistingInvalid, progress))?).valid(None){
            return Err(publication_error(ExistingInvalid, progress));
        }
        progress=ValidatedUnsynced;
        if fault!(FileSync){
            return Err(publication_error(FileSync, progress));
        }
        marker.sync_all().map_err(|_|publication_error(FileSync, progress))?;
        progress=FileSynced;
        stage!(MarkerFileSynced);
        if fault!(DirectorySync){
            return Err(publication_error(DirectorySync, progress));
        }
        self.pin.dir.sync_all().map_err(|_|publication_error(DirectorySync, progress))?;
        progress=FileAndDirectorySynced;
        stage!(MarkerDirectorySynced);
        let hash=*blake3::hash(&original).as_bytes();
        self.fence(&marker).map_err(|reason|publication_error(reason, progress))?;
        stage!(FenceValidated);
        let outcome=if created{
            PublishOutcome::CreatedOriginalDurablyFenced{
                original_blake3:hash
            }
        }
        else{
            PublishOutcome::ExistingOriginalDurablyFenced{
                original_blake3:hash
            }
        };
        Ok(outcome)
    }
    fn fence(&self, marker:&File)->Result<(),
    PublishReason> {
        let mut deadline=None;
        loop {
            if deadline.is_some_and(|d|Instant::now()>=d){
                return Err(PublishReason::FenceTimeout);
            }
            self.pin.check_path().map_err(|_|PublishReason::FenceIdentity)?;
            let (reg, lock)=self.ready().map_err(|_|PublishReason::FenceIdentity)?;
            self.same_entry(".json", marker).map_err(|_|PublishReason::FenceIdentity)?;
            if deadline.is_some_and(|d|Instant::now()>=d){
                return Err(PublishReason::FenceTimeout);
            }
            let limit=*deadline.get_or_insert_with(||Instant::now()+Duration::from_millis(500));
            let result=unsafe{
                libc::flock(lock.as_raw_fd(), libc::LOCK_EX|libc::LOCK_NB)
            };
            if result==0 {
                self.validate_ready_identity(&reg, &lock).and_then(|_|self.same_entry(".json", marker)).map_err(|_|PublishReason::FenceIdentity)?;
                if Instant::now()>=limit{
                    return Err(PublishReason::FenceTimeout);
                }
                drop(lock);
                return Ok(());
            }
            let errno=std::io::Error::last_os_error().raw_os_error();
            drop(lock);
            drop(reg);
            if errno!=Some(libc::EWOULDBLOCK)&&errno!=Some(libc::EAGAIN){
                return Err(PublishReason::FenceIo);
            }
            stage!(ExclusiveWouldBlock);
            let now=Instant::now();
            if now>=limit{
                return Err(PublishReason::FenceTimeout);
            }
            let delay=Duration::from_millis(2).min(limit.saturating_duration_since(now));
            #[cfg(test)]super::quic_fence_test_support::note(super::quic_fence_test_support::Note::RetrySleepNanos(delay.as_nanos()as u64));
            std::thread::sleep(delay);
        }
    }
}
// Conditional macros remove every scheduling/fault control from non-test code.
#[cfg(test)] use super::quic_fence_test_support::Stage;

#[derive(Default)]
pub(crate) struct Observation {
    pub transport_failed:bool,
    pub malformed:bool,
    pub last:Option<(String, u64, Vec<u8>)>
}
#[cfg(test)]mod fence_tests;
#[cfg(test)]mod tests {
    use super::*;
    #[test] fn persisted_poison_denies_restart_and_unsafe_or_tampered_markers_fail_closed(){
        let fixture=fence_tests::Fixture::new();
        let domain=fixture.open();
        let state=domain.peer(&fixture.peer).unwrap();
        let original=state.record(&fixture.signer, &"cd".repeat(32), 3, b"authenticated corrupt bytes", &[4;32], ||Ok(1)).unwrap();
        assert!(matches!(original, PublishOutcome::CreatedOriginalDurablyFenced{
            ..
        }));
        let marker=fixture.path.join(format!("{}.json", hex::encode(fixture.peer)));
        let bytes=std::fs::read(&marker).unwrap();
        let receipt:PoisonReceipt=serde_json::from_slice(&bytes).unwrap();
        receipt.verify().unwrap();
        assert_eq!(receipt.session_binding, hex::encode([4;32]));
        assert!(fixture.open().peer(&fixture.peer).unwrap().clean_lease().is_err());
        std::fs::write(&marker, b"{").unwrap();
        assert!(fixture.open().peer(&fixture.peer).unwrap().clean_lease().is_err());
        std::fs::write(&marker, &bytes).unwrap();
        std::fs::set_permissions(&marker, std::os::unix::fs::PermissionsExt::from_mode(0o666)).unwrap();
        assert!(fixture.open().peer(&fixture.peer).unwrap().clean_lease().is_err());
    }
}
#[cfg(test)]pub(crate) mod service_binding_tests;
