//! Library-test-only causal scheduling and owned process support.
//! No environment, socket, fault or scheduling entry point exists in production.
use serde::{
    Deserialize,
    Serialize
};
use std::{
    cell::RefCell,
    fs::{
        File,
        OpenOptions
    },
    io::{
        Read,
        Write
    },
    os::fd::AsRawFd,
    os::unix::{
        fs::{
            MetadataExt,
            OpenOptionsExt,
            PermissionsExt
        },
        net::{
            UnixListener,
            UnixStream
        },
        process::ExitStatusExt
    },
    path::{
        Path,
        PathBuf
    },
    process::{
        Child,
        Command,
        Stdio
    },
    sync::{
        atomic::{AtomicBool,Ordering},
        Arc,
        Mutex,
        OnceLock
    },
    time::{
        Duration,
        Instant
    }
};
const MAX_CONTROL:usize=4096;
const MAX_NOTES:usize=4096;
const IO_TIMEOUT:Duration=Duration::from_secs(5);
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum Role {
    Sender,
    Receiver,
    Publisher,
    LeaseHolder,
    Opener
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum Stage {
    BeforeRegistrationCreate,
    RegistrationCreated,
    PendingWritten,
    PendingSynced,
    LockCreated,
    LockSynced,
    ReadyPrefixWritten,
    ReadyWritten,
    ReadySynced,
    ProvisionAcknowledged,
    PublicationPrepared,
    MarkerCreated,
    MarkerPrefixWritten,
    MarkerFileSynced,
    MarkerDirectorySynced,
    ExclusiveWouldBlock,
    FenceValidated,
    PublicationAcknowledged,
    BeforeCleanLease,
    AfterCleanLeaseBeforeSerial,
    AllFinalGuardsHeld,
    BeforePayloadPoll,
    PositivePayloadReturned,
    PendingGuardsDropped,
    PayloadCompleteBeforeFinLease,
    BeforeFin,
    FinalClockAttempt,
    FinalClockResult,
    FinalRefusalGuardsDropped,
    AfterActionGuardsDropped,
    ChildReady,
    LeaseAcquired,
    LeaseReleased,
    ProbeCompleted,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum Fault {
    Serialization,
    FileSync,
    DirectorySync,
    MarkerCreate,
    PublisherTimestamp,
    FinalClock
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum Action {
    Payload,
    Fin
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum ClockResult {
    Value(u64),
    FixedError
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum PollResult {
    Pending,
    Positive(usize),
    Zero,
    Error
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum Guard {
    Serial,
    Quarantine,
    AuthorizedPeers,
    SeedGate,
    EnterpriseCurrent,
    FileExclusive
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum Note {
    Stage{
        stage:Stage,
        operation:u64
    },
    Clock{
        action:Action,
        operation:u64,
        final_read:bool,
        result:ClockResult
    },
    PayloadPoll{
        operation:u64,
        result:PollResult
    },
    FinCall{
        operation:u64,
        success:bool
    },
    GuardProbe{
        operation:u64,
        guard:Guard,
        success:bool
    },
    RetrySleepNanos(u64),
    PublicationWriteError{errno:Option<i32>},
    PublicationObservation{
        peer:[u8;32],
        detector:[u8;32],
        exporter:[u8;32],
        observed_blake3:[u8;32],
        stopped:bool
    },
}
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Selection {
    stage:Stage,
    operation:u64
}
#[derive(Debug, Clone, Serialize, Deserialize)]
struct FaultSelection {
    fault:Fault,
    operation:u64
}
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Config {
    outer:String,
    role:Role,
    case:String,
    fixture:PathBuf,
    socket:PathBuf,
    parent:u32,
    pauses:Vec<Selection>,
    faults:Vec<FaultSelection>
}
#[derive(Debug, Serialize, Deserialize)]
enum Message {
    Hello{
        role:Role,
        case:String,
        outer:String
    },
    HelloAccepted{
        role:Role,
        case:String,
        outer:String
    },
    Reached{
        role:Role,
        stage:Stage,
        operation:u64,
        sequence:u64
    },
    Resume{
        stage:Stage,
        operation:u64,
        sequence:u64
    }
}
struct Context {
    config:Config,
    stream:UnixStream,
    sequence:u64,
    consumed:Vec<(Fault, u64)>,
    resumed:Vec<(Stage, u64)>
}
static CONTEXT:OnceLock<Mutex<Context>>=OnceLock::new();
static CONFIG:OnceLock<Config>=OnceLock::new();
thread_local!{
    static NOTES:RefCell<Vec<Note>>=const{
        RefCell::new(Vec::new())
    };
}
pub(crate) fn initialize_notes(){
    NOTES.with(|v|{
        let mut v=v.borrow_mut();
        if v.capacity()==0{
            v.reserve_exact(MAX_NOTES);
        }
    });
}
/// This only touches preallocated thread-local memory. Failure is explicit.
pub(crate) fn note(value:Note){
    if CONTEXT.get().is_none(){
        return;
    }
    NOTES.with(|v|{
        let mut v=v.try_borrow_mut().expect("reentrant bounded note buffer");
        assert!(v.capacity()>=MAX_NOTES, "initialize notes before protected actions");
        assert!(v.len()<MAX_NOTES, "bounded note buffer full");
        v.push(value);
    });
}
pub(crate) fn notes()->Vec<Note>{
    NOTES.with(|v|v.borrow().clone())
}
fn write_message(stream:&mut UnixStream, message:&Message){
    let body=serde_json::to_vec(message).unwrap();
    assert!(body.len()<=MAX_CONTROL);
    enclave_core::ipc::write_frame(stream, &body).unwrap();
}
fn read_until(stream:&mut UnixStream, mut bytes:&mut[u8], deadline:Instant){
    while !bytes.is_empty(){
        let remaining=deadline.checked_duration_since(Instant::now()).expect("absolute control read deadline");
        stream.set_read_timeout(Some(remaining)).unwrap();
        let n=stream.read(bytes).expect("bounded control read");
        assert!(n>0, "control EOF");
        bytes=&mut bytes[n..];
    }
    assert!(Instant::now()<deadline, "control read overrun");
}
fn read_message(stream:&mut UnixStream)->Message{
    // Shared IPC framing with a stricter preallocation and absolute-time bound.
    let deadline=Instant::now()+stream.read_timeout().unwrap().unwrap_or(IO_TIMEOUT).min(IO_TIMEOUT);
    let mut len=[0;4];
    read_until(stream, &mut len, deadline);
    let n=u32::from_be_bytes(len)as usize;
    assert!(n<=MAX_CONTROL);
    let mut body=vec![0;n];
    read_until(stream, &mut body, deadline);
    serde_json::from_slice(&body).unwrap()
}
fn timeouts(stream:&UnixStream){
    // BSD accept may inherit the listener's O_NONBLOCK, unlike Linux.
    // SO_RCVTIMEO does not make a nonblocking descriptor wait for input.
    let before=unsafe{libc::fcntl(stream.as_raw_fd(),libc::F_GETFL)};
    assert!(before>=0,"control F_GETFL before blocking normalization");
    stream.set_nonblocking(false).unwrap();
    let after=unsafe{libc::fcntl(stream.as_raw_fd(),libc::F_GETFL)};
    assert!(after>=0,"control F_GETFL after blocking normalization");
    assert_eq!(after&libc::O_NONBLOCK,0,"control descriptor must be blocking");
    assert_eq!(before&!libc::O_NONBLOCK,after&!libc::O_NONBLOCK);
    eprintln!("QF_CONTROL_BLOCKING {{\"flags_before\":{before},\"flags_after\":{after},\"blocking_verified\":true}}");
    stream.set_read_timeout(Some(IO_TIMEOUT)).unwrap();
    stream.set_write_timeout(Some(IO_TIMEOUT)).unwrap();
}
pub(crate) fn child_role(outer:&str)->Option<Role>{
    let raw=match std::env::var("MCPMAC_QF_CHILD_CONFIG"){
        Ok(v)=>v,
        Err(_)=>return None
    };
    assert!(raw.len()<=MAX_CONTROL);
    // Owned process only; its normal exit also ends this watchdog thread.
    std::thread::spawn(||{
        std::thread::sleep(Duration::from_secs(15));
        eprintln!("QF_OWNED_CHILD_DEADLINE");
        unsafe{
            libc::_exit(124)
        }
    });
    let config:Config=serde_json::from_str(&raw).unwrap();
    assert_eq!(config.outer, outer);
    assert!(config.pauses.len()<=64&&config.faults.len()<=16);
    assert!(config.case.len()<=80&&config.case.bytes().all(|b|b.is_ascii_alphanumeric()||b==b'_'||b==b'-'));
    let until=Instant::now()+IO_TIMEOUT;
    let mut stream=loop{
        match UnixStream::connect(&config.socket){
            Ok(s)=>break s,
            Err(_)=>{
                assert!(Instant::now()<until);
                std::thread::sleep(Duration::from_millis(2));
            }
        }
    };
    timeouts(&stream);
    let peer=enclave_core::ipc::peer_credentials(&stream).unwrap();
    assert_eq!(peer.uid, enclave_core::ipc::geteuid());
    assert_eq!(peer.pid, Some(config.parent as i32));
    eprintln!("QF_CONTROL_AUTH {{\"endpoint\":\"child\",\"stage\":\"peer_credentials_verified\"}}");
    write_message(&mut stream, &Message::Hello{
        role:config.role,
        case:config.case.clone(),
        outer:config.outer.clone()
    });
    // Keep this owned process alive until the parent has read its actual
    // kernel credentials. Darwin LOCAL_PEERTOKEN may fail after peer exit.
    // The existing absolute connect deadline also bounds this handshake.
    let remaining=until.checked_duration_since(Instant::now()).expect("child control handshake deadline");
    stream.set_read_timeout(Some(remaining.min(IO_TIMEOUT))).unwrap();
    match read_message(&mut stream){
        Message::HelloAccepted{role,case,outer}=>{
            assert_eq!(role, config.role);
            assert_eq!(case, config.case);
            assert_eq!(outer, config.outer);
        },
        other=>panic!("invalid parent hello acknowledgment {other:?}")
    }
    assert!(Instant::now()<until,"child control handshake overrun");
    eprintln!("QF_CONTROL_AUTH {{\"endpoint\":\"child\",\"stage\":\"hello_acknowledgment_verified\"}}");
    stream.set_read_timeout(Some(IO_TIMEOUT)).unwrap();
    let role=config.role;
    initialize_notes();
    assert!(CONFIG.set(config.clone()).is_ok());
    assert!(CONTEXT.set(Mutex::new(Context{
        config,
        stream,
        sequence:0,
        consumed:Vec::with_capacity(16),
        resumed:Vec::with_capacity(64)
    })).is_ok());
    unsafe{
        let limit=libc::rlimit{
            rlim_cur:0,
            rlim_max:0
        };
        assert_eq!(libc::setrlimit(libc::RLIMIT_CORE, &limit), 0);
    }
    Some(role)
}
pub(crate) fn case()->String{
    CONTEXT.get().unwrap().lock().unwrap().config.case.clone()
}
pub(crate) fn fixture_path()->PathBuf{
    CONTEXT.get().unwrap().lock().unwrap().config.fixture.clone()
}
pub(crate) fn selected(stage:Stage, operation:u64)->bool{
    let Some(config)=CONFIG.get()else{
        return false;
    };
    if !config.pauses.iter().any(|s|s.stage==stage&&s.operation==operation){
        return false;
    }
    let c=CONTEXT.get().unwrap().try_lock().expect("selection control contention");
    !c.resumed.contains(&(stage, operation))
}
pub(crate) fn hook(stage:Stage, operation:u64){
    if CONTEXT.get().is_none(){
        return;
    }
    note(Note::Stage{
        stage,
        operation
    });
    if !CONFIG.get().unwrap().pauses.iter().any(|s|s.stage==stage&&s.operation==operation){
        return;
    }
    let mut c=CONTEXT.get().unwrap().try_lock().expect("hook control contention");
    if !c.config.pauses.iter().any(|s|s.stage==stage&&s.operation==operation)||c.resumed.contains(&(stage, operation)){
        return;
    }
    c.sequence+=1;
    let sequence=c.sequence;
    let role=c.config.role;
    write_message(&mut c.stream, &Message::Reached{
        role,
        stage,
        operation,
        sequence
    });
    c.stream.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    match read_message(&mut c.stream){
        Message::Resume{
            stage:s,
            operation:o,
            sequence:q
        }
        =>{
            assert_eq!((s, o, q), (stage, operation, sequence));
        },
        other=>panic!("invalid coordinator reply {other:?}")
    }
    c.stream.set_read_timeout(Some(IO_TIMEOUT)).unwrap();
    assert!(c.resumed.len()<64);
    c.resumed.push((stage, operation));
}
pub(crate) fn fault(fault:Fault, operation:u64)->bool{
    let Some(config)=CONFIG.get()else{
        return false;
    };
    if !config.faults.iter().any(|f|f.fault==fault&&f.operation==operation){
        return false;
    }
    let mut c=CONTEXT.get().unwrap().try_lock().expect("fault control contention");
    if c.config.faults.iter().any(|f|f.fault==fault&&f.operation==operation)&&!c.consumed.contains(&(fault, operation)){
        assert!(c.consumed.len()<16);
        c.consumed.push((fault, operation));
        true
    }
    else{
        false
    }
}
pub(crate) fn emit_child_receipt(value:&impl Serialize){
    let c=CONTEXT.get().unwrap().lock().unwrap();
    let body=serde_json::to_vec_pretty(value).unwrap();
    assert!(body.len()<=1024*1024);
    let path=c.config.fixture.join(format!("{}-{:?}-receipt.json", c.config.case, c.config.role));
    let mut f=OpenOptions::new().write(true).create_new(true).mode(0o600).open(path).unwrap();
    f.write_all(&body).unwrap();
    f.sync_all().unwrap();
}
/// Each outer coordinator owns only its own random private directory/children.
pub(crate) struct Run {
    pub(crate) fixture:PathBuf,
    pub(crate) evidence:PathBuf,
    outer:String,
    sequence:u64,
    expected:Vec<String>,
    completed:Vec<String>,
    children:Arc<Mutex<Vec<serde_json::Value>>>,
    finished:bool,
    deadline:Instant,
    active:Arc<AtomicBool>
}
impl Run {
    pub(crate) fn new(outer:&str)->Self{
        let crash_matrix=matches!(outer,
            "transport::quic_poison::fence_tests::qf_registration_concurrent_creator_and_genesis_crash_states_fail_closed" |
            "transport::quic_poison::fence_tests::qf_publication_crash_markers_and_io_failures_preserve_exact_progress");
        let deadline=Instant::now()+Duration::from_secs(if crash_matrix{90}else{30});
        let fixture=PathBuf::from("/tmp").join(format!("mcqf-{:016x}", enclave_core::rng::u64()));
        std::fs::create_dir(&fixture).unwrap();
        std::fs::set_permissions(&fixture, std::fs::Permissions::from_mode(0o700)).unwrap();
        let fixture=fixture.canonicalize().unwrap();
        let evidence_root=PathBuf::from(std::env::var_os("MCPMAC_QUARANTINE_FENCE_EVIDENCE_DIR").expect("explicit repository-local fence evidence directory required"));
        assert!(evidence_root.is_absolute());
        let root_meta=std::fs::symlink_metadata(&evidence_root).unwrap();
        assert!(root_meta.is_dir()&&!root_meta.file_type().is_symlink()&&root_meta.uid()==enclave_core::ipc::geteuid()&&root_meta.mode()&0o7777==0o700);
        let canonical=evidence_root.canonicalize().unwrap();
        assert_eq!(canonical, evidence_root);
        let repository=Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().parent().unwrap().canonicalize().unwrap();
        assert!(evidence_root.parent()==Some(repository.join("target").as_path()));
        let root_name=evidence_root.file_name().unwrap().to_str().unwrap();
        assert!(root_name.starts_with("qf-evidence-")&&root_name.len()<=128&&root_name.bytes().all(|b|b.is_ascii_alphanumeric()||b==b'-'));
        let evidence_name=format!("{}-{:016x}", outer.rsplit("::").next().unwrap(), enclave_core::rng::u64());
        assert!(evidence_name.len()<=128&&evidence_name.bytes().all(|b|b.is_ascii_alphanumeric()||b==b'_'||b==b'-'));
        let evidence=evidence_root.join(evidence_name);
        std::fs::create_dir(&evidence).unwrap();
        std::fs::set_permissions(&evidence, std::fs::Permissions::from_mode(0o700)).unwrap();
        let active=Arc::new(AtomicBool::new(true));
        let watched=active.clone();
        std::thread::spawn(move||{
            std::thread::sleep(deadline.saturating_duration_since(Instant::now()));
            if watched.load(Ordering::SeqCst){
                eprintln!("QF_OWNED_OUTER_DEADLINE");
                // The controller retains and reaps its owned process group.
                // This cannot promise Rust cleanup or hard syscall latency.
                unsafe{libc::_exit(124)}
            }
        });
        Self{
            fixture,
            evidence,
            outer:outer.into(),
            sequence:0,
            expected:Vec::new(),
            completed:Vec::new(),
            children:Arc::new(Mutex::new(Vec::new())),
            finished:false,
            deadline,
            active
        }
    }
    fn budget(&self){assert!(Instant::now()<self.deadline,"owned outer deadline");}
    pub(crate) fn spawn(&mut self, role:Role, case:&str, pauses:&[(Stage, u64)], faults:&[(Fault, u64)])->OwnedChild{
        self.budget();
        assert!(case.len()<=80&&case.bytes().all(|b|b.is_ascii_alphanumeric()||b==b'_'||b==b'-'));
        assert!(pauses.len()<=64&&faults.len()<=16);
        self.sequence+=1;
        let socket=self.fixture.join(format!("c{}.sock", self.sequence));
        let listener=UnixListener::bind(&socket).unwrap();
        std::fs::set_permissions(&socket,std::fs::Permissions::from_mode(0o700)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let stem=format!("{}-{:?}-{}", case, role, self.sequence);
        let stdout_path=self.evidence.join(format!("{stem}.stdout"));
        let stderr_path=self.evidence.join(format!("{stem}.stderr"));
        let stdout=OpenOptions::new().write(true).create_new(true).mode(0o600).open(&stdout_path).unwrap();
        let stderr=OpenOptions::new().write(true).create_new(true).mode(0o600).open(&stderr_path).unwrap();
        let config=Config{
            outer:self.outer.clone(),
            role,
            case:case.into(),
            fixture:self.fixture.clone(),
            socket,
            parent:std::process::id(),
            pauses:pauses.iter().map(|&(stage, operation)|Selection{
                stage,
                operation
            }).collect(),
            faults:faults.iter().map(|&(fault, operation)|FaultSelection{
                fault,
                operation
            }).collect()
        };
        let started=Instant::now();
        let child=Command::new(std::env::current_exe().unwrap()).arg(&self.outer).arg("--exact").arg("--nocapture").arg("--test-threads=1") .env("MCPMAC_QF_CHILD_CONFIG", serde_json::to_string(&config).unwrap()).stdout(Stdio::from(stdout)).stderr(Stdio::from(stderr)).spawn().unwrap();
        let mut owned=OwnedChild{
            child,
            stream:None,
            role,
            sequence:0,
            reached:None,
            started,
            stdout_path,
            stderr_path,
            evidence:self.evidence.clone(),
            fixture:self.fixture.clone(),
            case:case.into(),
            credentials_verified:false,
            finished:false,
            children:self.children.clone(),
            outer_deadline:self.deadline
        };
        let until=(Instant::now()+IO_TIMEOUT).min(self.deadline).min(started+Duration::from_secs(15));
        let(mut stream, _)=loop{
            match listener.accept(){
                Ok(pair)=>break pair,
                Err(e)if e.kind()==std::io::ErrorKind::WouldBlock=>{
                    assert!(Instant::now()<until, "owned child control connect timeout");
                    assert!(owned.child.try_wait().unwrap().is_none(), "child exited before control");
                    std::thread::sleep(Duration::from_millis(2));
                },
                Err(e)=>panic!("{e}")
            }
        };
        timeouts(&stream);
        let remaining=owned.remaining().min(IO_TIMEOUT);stream.set_read_timeout(Some(remaining)).unwrap();stream.set_write_timeout(Some(remaining)).unwrap();
        let peer=enclave_core::ipc::peer_credentials(&stream).unwrap();
        assert_eq!(peer.uid, enclave_core::ipc::geteuid());
        assert_eq!(peer.pid, Some(owned.child.id()as i32));
        eprintln!("QF_CONTROL_AUTH {{\"endpoint\":\"parent\",\"stage\":\"peer_credentials_verified\"}}");
        match read_message(&mut stream){
            Message::Hello{
                role:r,
                case:c,
                outer:o
            }
            =>{
                assert_eq!(r, role);
                assert_eq!(c, case);
                assert_eq!(o, self.outer);
            },
            other=>panic!("invalid child hello {other:?}")
        }
        owned.credentials_verified=true;
        eprintln!("QF_CONTROL_AUTH {{\"endpoint\":\"parent\",\"stage\":\"hello_identity_verified\"}}");
        stream.set_write_timeout(Some(owned.remaining().min(IO_TIMEOUT))).unwrap();
        write_message(&mut stream, &Message::HelloAccepted{
            role,
            case:case.into(),
            outer:self.outer.clone()
        });
        eprintln!("QF_CONTROL_AUTH {{\"endpoint\":\"parent\",\"stage\":\"hello_acknowledgment_sent\"}}");
        owned.stream=Some(stream);
        owned
    }
    pub(crate) fn expect(&mut self, cases:&[&str]){
        self.budget();
        assert!(self.expected.is_empty());
        for case in cases{
            assert!(!case.is_empty()&&case.len()<=128&&case.bytes().all(|b|b.is_ascii_alphanumeric()||b==b'-'||b==b'_'));
            assert!(!self.expected.iter().any(|old|old==case));
            self.expected.push((*case).into());
        }
    }
    pub(crate) fn complete(&mut self, case:&str){
        self.budget();
        assert!(self.expected.iter().any(|v|v==case));
        assert!(!self.completed.iter().any(|v|v==case));
        self.completed.push(case.into());
    }
    pub(crate) fn finish(&mut self){
        self.budget();
        let mut a=self.expected.clone();
        let mut b=self.completed.clone();
        a.sort();
        b.sort();
        assert!(!a.is_empty());
        assert_eq!(a, b);
        std::fs::remove_dir_all(&self.fixture).expect("owned ephemeral cleanup before PASS");
        self.budget();
        self.outer_receipt("PASS");
        self.budget();
        self.finished=true;
        self.active.store(false,Ordering::SeqCst);
    }
    fn outer_receipt(&self, status:&str){
        let value=serde_json::json!({
            "schema":1,
            "outer_test":self.outer,
            "status":status,
            "expected_subcases":self.expected,
            "completed_subcases":self.completed,
            "children":*self.children.lock().unwrap()
        });
        let body=serde_json::to_vec_pretty(&value).unwrap();
        assert!(body.len()<=1024*1024);
        let mut file=OpenOptions::new().write(true).create_new(true).mode(0o600).open(self.evidence.join("outer-receipt.json")).unwrap();
        file.write_all(&body).unwrap();
        file.sync_all().unwrap();
    }
    pub(crate) fn record(&self, name:&str, value:&impl Serialize){
        self.budget();
        assert!(name.len()<=123&&name.bytes().all(|b|b.is_ascii_alphanumeric()||b==b'-'||b==b'_'));
        let body=serde_json::to_vec_pretty(value).unwrap();
        assert!(body.len()<=1024*1024);
        let mut file=OpenOptions::new().write(true).create_new(true).mode(0o600).open(self.evidence.join(format!("{name}.json"))).unwrap();
        file.write_all(&body).unwrap();
        file.sync_all().unwrap();
    }
}
impl Drop for Run{
    fn drop(&mut self){
        if !self.finished{
            let _=std::panic::catch_unwind(std::panic::AssertUnwindSafe(||self.outer_receipt("FAIL")));
        }
        let _=std::fs::remove_dir_all(&self.fixture);
        self.active.store(false,Ordering::SeqCst);
    }
}
pub(crate) struct OwnedChild {
    child:Child,
    stream:Option<UnixStream>,
    role:Role,
    sequence:u64,
    reached:Option<(Stage, u64, u64)>,
    started:Instant,
    stdout_path:PathBuf,
    stderr_path:PathBuf,
    evidence:PathBuf,
    fixture:PathBuf,
    case:String,
    credentials_verified:bool,
    finished:bool,
    children:Arc<Mutex<Vec<serde_json::Value>>>,
    outer_deadline:Instant
}
impl OwnedChild {
    fn remaining(&self)->Duration{
        let child=Duration::from_secs(15).checked_sub(self.started.elapsed()).expect("owned child deadline");
        let outer=self.outer_deadline.checked_duration_since(Instant::now()).expect("owned outer deadline");
        let remaining=child.min(outer);assert!(!remaining.is_zero());remaining
    }
    pub(crate) fn pid(&self)->u32{
        self.child.id()
    }
    pub(crate) fn wait_reached(&mut self, stage:Stage, operation:u64){
        assert!(self.reached.is_none());
        assert!(self.started.elapsed()<Duration::from_secs(15));
        let remaining=self.remaining();
        self.stream.as_ref().unwrap().set_read_timeout(Some(IO_TIMEOUT.min(remaining))).unwrap();
        let message=read_message(self.stream.as_mut().unwrap());
        assert!(self.started.elapsed()<Duration::from_secs(15), "owned child deadline after control read");let _=self.remaining();
        match message{
            Message::Reached{
                role,
                stage:s,
                operation:o,
                sequence:q
            }
            =>{
                assert_eq!(role, self.role);
                assert_eq!((s, o), (stage, operation));
                assert_eq!(q, self.sequence+1);
                self.sequence=q;
                self.reached=Some((s, o, q));
            },
            other=>panic!("unexpected child event {other:?}")
        }
    }
    pub(crate) fn resume(&mut self){
        self.stream.as_ref().unwrap().set_write_timeout(Some(self.remaining().min(IO_TIMEOUT))).unwrap();
        let(stage, operation, sequence)=self.reached.take().expect("only coordinator resumes a reached stage");
        write_message(self.stream.as_mut().unwrap(), &Message::Resume{
            stage,
            operation,
            sequence
        });
    }
    pub(crate) fn wait_success(&mut self){
        assert!(self.reached.is_none());
        let status=loop{
            let _=self.remaining();
            if let Some(s)=self.child.try_wait().unwrap(){
                break s;
            }
            assert!(self.started.elapsed()<Duration::from_secs(15), "owned child deadline");
            std::thread::sleep(Duration::from_millis(2));
        };
        self.finished=true;
        self.retain_logs(Some(status.code()), status.signal(), false);
        assert!(status.success(), "owned child failed: see {}", self.stderr_path.display());
    }
    pub(crate) fn kill_at_stage(&mut self){
        assert!(self.reached.is_some());
        self.child.kill().unwrap();
        let status=self.child.wait().unwrap();
        self.finished=true;
        self.retain_logs(Some(status.code()), status.signal(), true);
    }
    fn retain_logs(&self, code:Option<Option<i32>>, signal:Option<i32>, killed:bool){
        let mut logs=Vec::new();
        for path in [&self.stdout_path, &self.stderr_path]{
            let bytes=std::fs::read(path).unwrap();
            assert!(bytes.len()<=256*1024, "owned raw log too large");
            logs.push(serde_json::json!({
                "path":path.file_name().unwrap().to_str().unwrap(),
                "bytes":bytes.len(),
                "blake3":blake3::hash(&bytes).to_hex().to_string()
            }));
        }
        for entry in std::fs::read_dir(&self.fixture).unwrap(){
            let entry=entry.unwrap();
            let name=entry.file_name();
            let name=name.to_str().unwrap();
            if name==format!("{}-{:?}-receipt.json", self.case, self.role){
                let metadata=std::fs::symlink_metadata(entry.path()).unwrap();
                assert!(metadata.is_file()&&metadata.nlink()==1&&metadata.mode()&0o7777==0o600&&metadata.len()<=1024*1024);
                let bytes=std::fs::read(entry.path()).unwrap();
                let mut out=OpenOptions::new().write(true).create_new(true).mode(0o600).open(self.evidence.join(format!("{}-{}", self.pid(), name))).unwrap();
                out.write_all(&bytes).unwrap();
                out.sync_all().unwrap();
            }
        }
        let receipt=serde_json::json!({
            "pid":self.pid(),
            "kernel_control_pid_uid_checked":self.credentials_verified,
            "role":self.role,
            "case":self.case,
            "exit_code":code,
            "signal":signal,
            "cleanup_kill_requested":killed,
            "killed_at_reached_stage":killed&&self.reached.is_some(),
            "reached":self.reached,
            "raw_logs":logs
        });
        self.children.lock().unwrap().push(receipt.clone());
        let mut file=OpenOptions::new().write(true).create_new(true).mode(0o600).open(self.evidence.join(format!("child-{}.json", self.pid()))).unwrap();
        file.write_all(&serde_json::to_vec_pretty(&receipt).unwrap()).unwrap();
        file.sync_all().unwrap();
    }
}
impl Drop for OwnedChild{
    fn drop(&mut self){
        if !self.finished{
            let requested=self.child.kill().is_ok();
            let status=self.child.wait().ok();
            self.finished=true;
            let _=std::panic::catch_unwind(std::panic::AssertUnwindSafe(||self.retain_logs(status.as_ref().map(|s|s.code()), status.and_then(|s|s.signal()), requested)));
        }
    }
}
