// Test-only support for the actual broker connection matrix. Included below
// snapshot_broker::tests; no product authenticator or platform is replaced.
use super::*;
use std::{collections::BTreeSet, io::ErrorKind, os::unix::fs::FileExt,
    process::{Child, Command, Stdio},
    thread, time::Instant};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const EVIDENCE_ENV: &str = "MCPMAC_ADMISSION_BROKER_EVIDENCE_DIR";
const CHILD_ENV: &str = "MCPMAC_BROKER_CONNECTION_CHILD";
const DIRECTORY_ENV: &str = "MCPMAC_BROKER_CONNECTION_DIRECTORY";
const PARSER_ENV: &str = "MCPMAC_BROKER_CONNECTION_PARSER";
const MAX_LOG: u64 = 512 * 1024;

fn private_directory(path: &Path) {
    let m = std::fs::symlink_metadata(path).unwrap();
    assert!(m.is_dir() && !m.file_type().is_symlink());
    assert_eq!(m.uid(), ipc::geteuid());
    assert_eq!(m.mode() & 0o777, 0o700);
}
fn new_directory(path: &Path) {
    std::fs::create_dir(path).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
    private_directory(path);
}
fn new_file(path: &Path) -> File {
    let file = File::options().write(true).create_new(true).mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC).open(path).unwrap();
    let m = file.metadata().unwrap();
    assert!(m.is_file()); assert_eq!(m.uid(), ipc::geteuid());
    assert_eq!(m.nlink(), 1); assert_eq!(m.mode() & 0o777, 0o600);
    file
}
fn write_json(path: &Path, value: &Value) {
    let bytes = serde_json::to_vec_pretty(value).unwrap();
    assert!(bytes.len() < 1024 * 1024);
    let mut file = new_file(path);
    file.write_all(&bytes).unwrap(); file.write_all(b"\n").unwrap();
    file.sync_all().unwrap();
}
fn read_json(path: &Path) -> Value {
    let m = std::fs::symlink_metadata(path).unwrap();
    assert!(m.is_file() && !m.file_type().is_symlink());
    assert_eq!(m.uid(), ipc::geteuid()); assert_eq!(m.nlink(), 1);
    assert_eq!(m.mode() & 0o777, 0o600); assert!(m.len() <= 1024 * 1024);
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}
fn watchdog(seconds: u64) {
    unsafe {
        let limit = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        assert_eq!(libc::setrlimit(libc::RLIMIT_CORE, &limit), 0);
    }
    thread::spawn(move || {
        thread::sleep(Duration::from_secs(seconds));
        eprintln!("BROKER_CONNECTION_OWNED_CHILD_DEADLINE");
        unsafe { libc::_exit(124) }
    });
}
fn sha(path: &Path) -> String { hex::encode(Sha256::digest(std::fs::read(path).unwrap())) }

struct OwnedChild { child: Child, reaped: bool }
impl Drop for OwnedChild {
    fn drop(&mut self) {
        if !self.reaped { let _ = self.child.kill(); let _ = self.child.wait(); }
    }
}
fn execute_child(directory: &Path, outer: &str, parser: Option<&str>, label: &str,
    seconds: u64) -> Value {
    let stdout = directory.join(format!("{label}.stdout"));
    let stderr = directory.join(format!("{label}.stderr"));
    let mut command = Command::new(std::env::current_exe().unwrap());
    command.args(["--exact", outer, "--nocapture", "--test-threads=1"])
        .env(CHILD_ENV, outer).env(DIRECTORY_ENV, directory)
        .stdout(Stdio::from(new_file(&stdout))).stderr(Stdio::from(new_file(&stderr)));
    if let Some(case) = parser { command.env(PARSER_ENV, case); }
    else { command.env_remove(PARSER_ENV); }
    // No setsid: all cooperating children remain in the owning controller's
    // anchored process group. The parent also owns and reaps this exact PID.
    let mut owned = OwnedChild { child: command.spawn().unwrap(), reaped: false };
    let pid = owned.child.id(); let start = Instant::now(); let mut stop = None;
    let status = loop {
        if let Some(status) = owned.child.try_wait().unwrap() {
            owned.reaped = true; break status;
        }
        if start.elapsed() >= Duration::from_secs(seconds) { stop = Some("CHILD_DEADLINE"); }
        if std::fs::metadata(&stdout).unwrap().len() > MAX_LOG ||
            std::fs::metadata(&stderr).unwrap().len() > MAX_LOG { stop = Some("CHILD_OUTPUT_LIMIT"); }
        if stop.is_some() {
            // A natural exit can race this exact owned-PID kill. Always reap;
            // the reached policy stop remains non-PASS even if it exited first.
            let _ = owned.child.kill(); let status = owned.child.wait().unwrap();
            owned.reaped = true; break status;
        }
        thread::sleep(Duration::from_millis(5));
    };
    use std::os::unix::process::ExitStatusExt;
    // Bound before reading/hashing even if output raced the sampled monitor.
    assert!(std::fs::metadata(&stdout).unwrap().len() <= MAX_LOG);
    assert!(std::fs::metadata(&stderr).unwrap().len() <= MAX_LOG);
    let result = json!({"pid":pid,"outer_test":outer,"parser_case":parser,
        "exit_code":status.code(),"signal":status.signal(),"reaped":owned.reaped,
        "stop_reason":stop,"elapsed_ms":start.elapsed().as_millis() as u64,
        "stdout":stdout.file_name().unwrap().to_str().unwrap(),"stdout_sha256":sha(&stdout),
        "stdout_bytes":std::fs::metadata(&stdout).unwrap().len(),
        "stderr":stderr.file_name().unwrap().to_str().unwrap(),"stderr_sha256":sha(&stderr),
        "stderr_bytes":std::fs::metadata(&stderr).unwrap().len(),
        "scope":"owned cooperating child; fixture authentication, no installed identity"});
    assert!(std::fs::metadata(&stdout).unwrap().len() <= MAX_LOG);
    assert!(std::fs::metadata(&stderr).unwrap().len() <= MAX_LOG);
    result
}

pub(super) struct Book {
    directory: PathBuf, outer: &'static str, expected: &'static [&'static str],
    completed: Vec<&'static str>, failures: Vec<Value>, children: Vec<Value>,
}
impl Book {
    pub(super) fn run(&mut self, case: &'static str, body: impl FnOnce(&mut Self) -> Value) {
        assert!(self.expected.contains(&case));
        assert!(!self.completed.contains(&case));
        let guard = FdGuard::new();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let observed = body(self); guard.verify(); observed
        }));
        match result {
            Ok(observed) => {
                write_json(&self.directory.join(format!("case-{case}.json")),
                    &json!({"schema":1,"case":case,"status":"PASS","observed":observed,
                        "fd_inventory_and_sentinel":"PASS","fixture_authentication":true,
                        "installed_authority":false}));
                self.completed.push(case);
            }
            Err(error) => {
                let reason = if let Some(s) = error.downcast_ref::<String>() { s.clone() }
                    else if let Some(s) = error.downcast_ref::<&str>() { (*s).to_owned() }
                    else { "non-string panic".to_owned() };
                let failure = json!({"case":case,"status":"FAIL","panic":reason});
                write_json(&self.directory.join(format!("case-{case}.json")), &failure);
                self.failures.push(failure);
            }
        }
    }
    pub(super) fn parser(&mut self, case: &str) -> Value {
        assert!(["declared_text_u64_max","declared_array_u64_max","declared_map_u64_max"].contains(&case));
        let child = execute_child(&self.directory, self.outer, Some(case), case, 12);
        self.children.push(child.clone());
        assert_eq!(child["exit_code"], 0); assert!(child["signal"].is_null());
        assert!(child["stop_reason"].is_null());
        let result = read_json(&self.directory.join(format!("parser-{case}.json")));
        assert_eq!(result["case"], case); assert_eq!(result["status"], "PASS");
        assert_eq!(result["parser_child_local_fd_inventory_and_sentinel"], "PASS");
        result
    }
}
pub(super) fn run_outer(outer: &'static str, expected: &'static [&'static str], group: fn(&mut Book)) {
    assert!(expected.len() == expected.iter().copied().collect::<BTreeSet<_>>().len());
    if let Ok(selected) = std::env::var(CHILD_ENV) {
        assert_eq!(selected, outer);
        let directory = PathBuf::from(std::env::var_os(DIRECTORY_ENV).unwrap());
        private_directory(&directory);
        if let Ok(case) = std::env::var(PARSER_ENV) {
            watchdog(10);
            // Parent FD inventory cannot observe descriptors leaked in this
            // process. Span the actual parser/recovery fixture locally and
            // verify after its function-scoped resources have all dropped.
            let descriptor_guard = FdGuard::new();
            let observed = super::broker_parser_case(&case);
            descriptor_guard.verify();
            write_json(&directory.join(format!("parser-{case}.json")),
                &json!({"schema":1,"case":case,"status":"PASS","observed":observed,
                    "parser_child_local_fd_inventory_and_sentinel":"PASS"}));
            return;
        }
        watchdog(50);
        let mut book = Book { directory:directory.clone(),outer,expected,
            completed:vec![],failures:vec![],children:vec![] };
        group(&mut book);
        let complete = book.failures.is_empty() && book.completed.len() == expected.len();
        write_json(&directory.join("child-result.json"), &json!({"schema":1,
            "outer_test":outer,"status":if complete {"PASS"} else {"FAIL"},
            "expected_subcases":expected,"completed_subcases":book.completed,
            "children":book.children,"failures":book.failures}));
        assert!(complete, "broker connection mandatory cases incomplete");
        return;
    }
    let root = if let Some(root) = std::env::var_os(EVIDENCE_ENV) { PathBuf::from(root) }
        else {
            let root = std::env::temp_dir().join(format!("broker-connection-evidence-{:x}",enclave_core::rng::u64()));
            new_directory(&root); root
        };
    assert!(root.is_absolute());
    assert!(!root.components().any(|c| matches!(c,std::path::Component::ParentDir)));
    private_directory(&root);
    let basename = outer.rsplit("::").next().unwrap();
    let directory = root.join(format!("{basename}-{:x}",enclave_core::rng::u64()));
    assert!(directory.file_name().unwrap().len() <= 128);
    new_directory(&directory);
    let child = execute_child(&directory, outer, None, "outer-child", 55);
    let path = directory.join("child-result.json");
    let result = if path.is_file() { read_json(&path) } else { json!({}) };
    let mut children = result.get("children").and_then(Value::as_array).cloned().unwrap_or_default();
    children.push(child.clone());
    let completed = result.get("completed_subcases").and_then(Value::as_array).cloned().unwrap_or_default();
    let matches = completed.iter().filter_map(Value::as_str).collect::<BTreeSet<_>>() ==
        expected.iter().copied().collect::<BTreeSet<_>>() && completed.len() == expected.len();
    let pass = child["exit_code"] == 0 && child["signal"].is_null() &&
        child["stop_reason"].is_null() && result["status"] == "PASS" &&
        result["outer_test"] == outer && result["expected_subcases"] == json!(expected) && matches;
    write_json(&directory.join("outer-receipt.json"), &json!({"schema":1,"outer_test":outer,
        "status":if pass {"PASS"} else {"FAIL"},"expected_subcases":expected,
        "completed_subcases":completed,"children":children}));
    assert!(pass,"broker connection child failed; retained evidence {}",directory.display());
}

pub(super) struct FdGuard { sentinel: File, identity: (u64,u64), inventory: BTreeSet<String>, lowest: i32 }
fn inventory() -> BTreeSet<String> {
    let path = if cfg!(target_os="macos") { "/dev/fd" } else { "/proc/self/fd" };
    std::fs::read_dir(path).unwrap().map(|e| e.unwrap().file_name().to_str().unwrap().to_owned()).collect()
}
fn lowest(file: &File) -> i32 {
    let fd = unsafe { libc::fcntl(file.as_raw_fd(),libc::F_DUPFD,0) };
    assert!(fd >= 0); assert_eq!(unsafe { libc::close(fd) },0); fd
}
impl FdGuard {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("broker-fd-sentinel-{:x}",enclave_core::rng::u64()));
        let mut sentinel = File::options().read(true).write(true).create_new(true).mode(0o600).open(&path).unwrap();
        sentinel.write_all(b"unrelated broker sentinel").unwrap();
        std::fs::remove_file(path).unwrap();
        let m = sentinel.metadata().unwrap();
        let lowest = lowest(&sentinel); let inventory = inventory();
        Self {sentinel,identity:(m.dev(),m.ino()),inventory,lowest}
    }
    fn verify(&self) {
        let m = self.sentinel.metadata().unwrap(); assert_eq!((m.dev(),m.ino()),self.identity);
        let mut bytes = [0;25]; assert_eq!(self.sentinel.read_at(&mut bytes,0).unwrap(),25);
        assert_eq!(&bytes,b"unrelated broker sentinel");
        assert_eq!(lowest(&self.sentinel),self.lowest);
        assert_eq!(inventory(),self.inventory);
    }
}

pub(super) fn flags(file: &File) -> i32 {
    let value = unsafe {libc::fcntl(file.as_raw_fd(),libc::F_GETFL)}; assert!(value >= 0); value
}
pub(super) fn identity(file: &File) -> Value {
    let m=file.metadata().unwrap();
    let descriptor_flags=unsafe{libc::fcntl(file.as_raw_fd(),libc::F_GETFD)};assert!(descriptor_flags>=0);
    json!({"dev":m.dev(),"ino":m.ino(),"mode":m.mode(),"uid":m.uid(),
        "length":m.len(),"status_flags":flags(file),"descriptor_flags":descriptor_flags})
}
fn blocking(stream: &UnixStream) {
    let before=unsafe{libc::fcntl(stream.as_raw_fd(),libc::F_GETFL)}; assert!(before>=0);
    stream.set_nonblocking(false).unwrap();
    let after=unsafe{libc::fcntl(stream.as_raw_fd(),libc::F_GETFL)}; assert!(after>=0);
    assert_eq!(after & libc::O_NONBLOCK,0);
    assert_eq!(before & !libc::O_NONBLOCK,after & !libc::O_NONBLOCK);
    stream.set_read_timeout(Some(Duration::from_secs(7))).unwrap();
    stream.set_write_timeout(Some(Duration::from_secs(7))).unwrap();
}
pub(super) fn pair() -> (UnixStream,UnixStream) {
    let (a,b)=UnixStream::pair().unwrap(); blocking(&a); blocking(&b); (a,b)
}
pub(super) enum Outcome { Connection(String), Refused(String), Revoked, Descriptor(File) }
fn no_more(stream:&mut UnixStream) {
    let mut byte=[0]; match stream.read(&mut byte) {
        Ok(0)=>(), Err(e) if matches!(e.kind(),ErrorKind::ConnectionReset|ErrorKind::BrokenPipe)=>(),
        other=>panic!("unexpected success bytes/descriptor after result: {other:?}"),
    }
}
pub(super) fn finish(result:EnclaveResult<()>,mut client:UnixStream)->Outcome {
    if let Err(error)=result { no_more(&mut client); return Outcome::Connection(error.reason.to_string()); }
    let reply:ipc::Reply<Response>=ipc::from_cbor(&ipc::read_frame(&mut client).unwrap()).unwrap();
    let outcome=match reply {
        ipc::Reply::Err(error)=>Outcome::Refused(error.reason.to_string()),
        ipc::Reply::Ok(Response::Revoked)=>Outcome::Revoked,
        ipc::Reply::Ok(Response::Descriptor)=>{
            let mut fds=ipc::recv_fds(&client,1).unwrap(); assert_eq!(fds.len(),1);
            let file=File::from(fds.remove(0));
            let descriptor_flags=unsafe{libc::fcntl(file.as_raw_fd(),libc::F_GETFD)};
            assert!(descriptor_flags>=0 && descriptor_flags & libc::FD_CLOEXEC != 0);
            Outcome::Descriptor(file)
        }
    };
    no_more(&mut client); outcome
}
pub(super) fn frame(bytes:&[u8])->Vec<u8> {
    assert!(bytes.len()<=4096); let mut wire=(bytes.len() as u32).to_be_bytes().to_vec();
    wire.extend_from_slice(bytes); wire
}
pub(super) enum Packet<'a> { Normal(&'a [i32]), Raw(u8,&'a [i32]), Missing }
pub(super) fn raw_packet(stream:&UnixStream,marker:u8,fds:&[i32]) {
    assert!(!fds.is_empty() && fds.len()<=64);
    let mut byte=[marker]; let mut iov=libc::iovec{iov_base:byte.as_mut_ptr().cast(),iov_len:1};
    let bytes=std::mem::size_of_val(fds);
    let space=unsafe{libc::CMSG_SPACE(bytes as u32)} as usize; let mut buffer=vec![0u8;space];
    let mut message:libc::msghdr=unsafe{std::mem::zeroed()};
    message.msg_iov=&mut iov; message.msg_iovlen=1;
    message.msg_control=buffer.as_mut_ptr().cast(); message.msg_controllen=space as _;
    unsafe {
        let c=libc::CMSG_FIRSTHDR(&message); assert!(!c.is_null());
        (*c).cmsg_level=libc::SOL_SOCKET; (*c).cmsg_type=libc::SCM_RIGHTS;
        (*c).cmsg_len=libc::CMSG_LEN(bytes as u32) as _;
        std::ptr::copy_nonoverlapping(fds.as_ptr().cast::<u8>(),libc::CMSG_DATA(c),bytes);
        assert_eq!(libc::sendmsg(stream.as_raw_fd(),&message,0),1,
            "actual kernel ancillary enqueue required; no receiver coverage otherwise");
    }
}
pub(super) fn wire(broker:&mut Broker,bytes:&[u8],packet:Packet<'_>,eof:bool)->Outcome {
    assert!(bytes.len()<=4100);
    let (server,mut client)=pair(); client.write_all(bytes).unwrap();
    match packet {Packet::Normal(fds)=>ipc::send_fd_packet(&client,fds).unwrap(),
        Packet::Raw(marker,fds)=>raw_packet(&client,marker,fds),Packet::Missing=>()}
    if eof {client.shutdown(std::net::Shutdown::Write).unwrap();}
    let result=connection(server,broker,|_|Ok(())); finish(result,client)
}
pub(super) fn request(broker:&mut Broker,request:&Request,fds:&[i32])->Outcome {
    wire(broker,&frame(&ipc::to_cbor(request).unwrap()),Packet::Normal(fds),false)
}
pub(super) fn connection_refusal(outcome:Outcome,reason:&str)->Value {
    match outcome {Outcome::Connection(actual)=>{assert_eq!(actual,reason);json!({"connection_error":actual,"reply_descriptor":false})},
        _=>panic!("expected connection-level {reason}")}
}
pub(super) fn reply_refusal(outcome:Outcome,reason:&str)->Value {
    match outcome {Outcome::Refused(actual)=>{assert_eq!(actual,reason);json!({"reply_error":actual,"reply_descriptor":false})},
        _=>panic!("expected typed reply {reason}")}
}
pub(super) fn exact_payload(outcome:Outcome)->Value {
    let Outcome::Descriptor(mut file)=outcome else {panic!("expected actual descriptor")};
    let observed=identity(&file); assert!(file.metadata().unwrap().is_file());
    assert_eq!(flags(&file)&libc::O_ACCMODE,libc::O_RDONLY);
    let mut bytes=vec![]; file.read_to_end(&mut bytes).unwrap(); assert_eq!(bytes,PAYLOAD);
    let target=enclave_crypto::tuf::target_file(PAYLOAD,None);
    crate::snapshot_publication::verify_file(&file,&target).unwrap();
    assert!(file.write_all(b"forbidden fixture write").is_err());
    json!({"returned_descriptor":observed,"payload_length":bytes.len(),"blake3":blake3::hash(&bytes).to_hex().to_string(),
        "sha256":hex::encode(Sha256::digest(&bytes)),"write_refused":true})
}
pub(super) fn no_descriptor(outcome:Outcome) {assert!(matches!(outcome,Outcome::Revoked));}
pub(super) fn fresh_effects(fixture:&Fixture,broker:&Broker) {
    assert!(broker.state.records.is_empty()); assert!(broker.state.stage_intent.is_none());
    for directory in [&fixture.paths.base,&fixture.config.source_mount] {
        assert!(std::fs::read_dir(directory).unwrap().all(|e|!e.unwrap().file_name().to_string_lossy().starts_with("stage-")));
    }
    let private=fixture.config.source_mount.join(".broker-stages");
    if private.exists() {assert!(private.is_dir());assert_eq!(std::fs::read_dir(private).unwrap().count(),0);}
    let artifacts=fixture.config.source_mount.join("artifacts");
    if artifacts.exists() {assert!(artifacts.is_dir());assert_eq!(std::fs::read_dir(artifacts).unwrap().count(),0);}
    assert_eq!(std::fs::read_dir(&fixture.config.mount_root).unwrap().count(),0);
    let calls=fixture.platform.calls.lock().unwrap();
    assert!(!calls.iter().any(|c|matches!(*c,"capacity"|"clone"|"clone-after"|"snapshot"|"mount"|"mount-after"|"flags"|"holders"|"unmount"|"delete")));
}
pub(super) fn progress(fixture:&Fixture,broker:&mut Broker)->Value {
    let root=fixture.root_hash(); let stage=fixture.stage(PAYLOAD); let original=identity(&stage);
    let published=exact_payload(request(broker,&Request::Publish{root:root.clone()},&[stage.as_raw_fd()]));
    assert_eq!(identity(&stage),original);
    let mut original_bytes=vec![0;PAYLOAD.len()];
    assert_eq!(stage.read_at(&mut original_bytes,0).unwrap(),PAYLOAD.len());
    assert_eq!(original_bytes,PAYLOAD);
    let reopened=exact_payload(request(broker,&Request::Reopen{root:root.clone()},&[]));
    let records=broker.state.records.len();
    no_descriptor(request(broker,&Request::Prepare{root:root.clone()},&[]));
    assert_eq!(broker.state.records.len(),records); assert!(broker.state.stage_intent.is_none());
    no_descriptor(request(broker,&Request::Revoke{root:root.clone()},&[]));
    assert!(broker.state.records.is_empty());
    no_descriptor(request(broker,&Request::Revoke{root},&[]));
    assert!(!fixture.config.source_mount.join("artifacts").join(fixture.root_hash()).exists());
    json!({"publish":published,"reopen":reopened,"prepare_no_descriptor":true,
        "revoke_and_absent_revoke":true,"sender_original_preserved":true})
}
