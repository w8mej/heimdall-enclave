//! Actual CLI dispatch over owned kernel-authenticated development IPC.
//! Mutated replies below are explicitly synthetic wire/refusal fixtures, never
//! measured stage history, installed signing, production SLO or resource proof.

use std::io;
use std::os::unix::fs::DirBuilderExt;
use std::os::unix::net::UnixListener;
use std::path::{Path,PathBuf};
use std::process::{Child,Command,Output,Stdio};
use std::thread;
use std::time::{Duration,Instant};
use enclave_core::{daemon::DaemonId,ipc::{self,Reply},profile::Profile};
use enclave_swarm_syncd::service::{CasConfig,CasRequest,CasResponse,CasService};
use mcp_enclave::ctl::{Env,SyncDiagnosticsExport};

const CANARY:&str="private-target/ns-secret/file:///private/path?token=secret-backend-exception";
const DEADLINE:Duration=Duration::from_secs(15);

struct Directory(PathBuf);
impl Directory {
    fn new()->Self {
        let path=Path::new("/tmp").join(format!("mc-sync-bin-{}",hex::encode(&enclave_core::rng::bytes32()[..8])));
        std::fs::DirBuilder::new().mode(0o700).create(&path).unwrap();Self(path)
    }
}
impl Drop for Directory {fn drop(&mut self){let _=std::fs::remove_dir_all(&self.0);}}
struct OwnedChild(Option<Child>);
impl OwnedChild {
    fn spawn(command:&mut Command)->Self {
        Self(Some(command.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap()))
    }
    fn output(mut self)->Output {
        let until=Instant::now()+DEADLINE;
        loop {
            if self.0.as_mut().unwrap().try_wait().unwrap().is_some(){return self.0.take().unwrap().wait_with_output().unwrap();}
            assert!(Instant::now()<until,"owned CLI exceeded deadline");thread::sleep(Duration::from_millis(5));
        }
    }
}
impl Drop for OwnedChild {fn drop(&mut self){if let Some(mut child)=self.0.take(){let _=child.kill();let _=child.wait();}}}
struct OwnedServer(Option<thread::JoinHandle<Option<i32>>>);
impl OwnedServer {fn join(mut self)->Option<i32>{self.0.take().unwrap().join().unwrap()}}
impl Drop for OwnedServer {fn drop(&mut self){if let Some(worker)=self.0.take(){let _=worker.join();}}}

fn command(base:&Path)->Command {
    let mut command=Command::new(env!("CARGO_BIN_EXE_mcp-enclave"));
    command.args(["--dev","--state-dir"]).arg(base).args(["--profile","L1","--json","swarm","sync-diagnostics"]);command
}

fn invoke_fixture(transform:impl FnOnce(Reply<CasResponse>)->Vec<u8>+Send+'static)->Output {
    let directory=Directory::new();let env=Env::dev(&directory.0,Profile::L1);
    let path=env.socket_dir.join(DaemonId::SwarmSync.socket_name());
    std::fs::DirBuilder::new().recursive(true).mode(0o700).create(path.parent().unwrap()).unwrap();
    let listener=UnixListener::bind(&path).unwrap();listener.set_nonblocking(true).unwrap();
    let service=CasService::start(CasConfig {dev_same_uid:true,profile:Profile::L1,store_dir:directory.0.join("store"),
        audit_path:None,tuf_root:None,ohttp_gateway:None,state_dir:None,
        revocation:enclave_swarm_syncd::revocation::Enforcement::Unavailable}).unwrap();
    let server=OwnedServer(Some(thread::spawn(move||{
        let until=Instant::now()+Duration::from_secs(5);
        let mut stream=loop {match listener.accept(){Ok((stream,_))=>break stream,
            Err(error) if error.kind()==io::ErrorKind::WouldBlock=>{assert!(Instant::now()<until,"owned CLI did not connect");thread::sleep(Duration::from_millis(5));},
            Err(error)=>panic!("owned listener: {error}")}};
        stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();stream.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
        let peer=ipc::peer_credentials(&stream).unwrap();assert_eq!(peer.uid,ipc::geteuid());
        let request:CasRequest=ipc::from_cbor(&ipc::read_frame(&mut stream).unwrap()).unwrap();assert!(matches!(request,CasRequest::SyncDiagnostics));
        let response=match service.handle(&peer,request){Ok(value)=>Reply::Ok(value),Err(error)=>Reply::Err(error)};
        ipc::write_frame(&mut stream,&transform(response)).unwrap();peer.pid
    })));
    let child=OwnedChild::spawn(&mut command(&directory.0));let pid=child.0.as_ref().unwrap().id();
    let output=child.output();assert_eq!(server.join(),Some(i32::try_from(pid).unwrap()),"actual kernel client PID");output
}
fn actual()->Output {invoke_fixture(|response|ipc::to_cbor(&response).unwrap())}
// serde_json's workspace-enabled arbitrary_precision Number serializer emits
// a private struct when passed to a non-JSON serializer. Emit fixture integers
// explicitly so malformed-wire cases change only their intended field.
struct WireValue<'a>(&'a serde_json::Value);
impl serde::Serialize for WireValue<'_> {
    fn serialize<S:serde::Serializer>(&self,serializer:S)->Result<S::Ok,S::Error> {
        use serde::ser::{Error,SerializeMap,SerializeSeq};
        match self.0 {
            serde_json::Value::Null=>serializer.serialize_unit(),
            serde_json::Value::Bool(value)=>serializer.serialize_bool(*value),
            serde_json::Value::Number(value)=>{
                if let Some(value)=value.as_u64(){serializer.serialize_u64(value)}
                else if let Some(value)=value.as_i64(){serializer.serialize_i64(value)}
                else{Err(S::Error::custom("fixture requires exact bounded integer"))}
            },
            serde_json::Value::String(value)=>serializer.serialize_str(value),
            serde_json::Value::Array(values)=>{let mut sequence=serializer.serialize_seq(Some(values.len()))?;
                for value in values {sequence.serialize_element(&WireValue(value))?;}sequence.end()},
            serde_json::Value::Object(values)=>{let mut map=serializer.serialize_map(Some(values.len()))?;
                for (key,value) in values {map.serialize_entry(key,&WireValue(value))?;}map.end()},
        }
    }
}
fn mutate(transform:impl FnOnce(&mut serde_json::Value)+Send+'static)->Output {
    invoke_fixture(move|response|{
        let mut value=serde_json::to_value(response).unwrap();
        // Every negative starts from a demonstrably decodable healthy wire
        // reply; a blanket fixture encoding error cannot satisfy the case.
        let healthy=ipc::to_cbor(&WireValue(&value)).unwrap();
        let decoded:Reply<CasResponse>=ipc::from_cbor(&healthy).expect("healthy fixture wire roundtrip");
        assert_eq!(serde_json::to_value(decoded).unwrap(),value);
        transform(&mut value["Ok"]["SyncDiagnostics"]);
        ipc::to_cbor(&WireValue(&value)).unwrap()
    })
}
fn success(output:Output)->SyncDiagnosticsExport {
    assert_eq!(output.status.code(),Some(0),"{}",String::from_utf8_lossy(&output.stderr));assert!(output.stderr.is_empty());
    serde_json::from_slice(&output.stdout).unwrap()
}
fn refused(output:Output,errno:&str,reason:&str) {
    assert_eq!(output.status.code(),Some(1));assert!(output.stdout.is_empty());
    let stderr=String::from_utf8(output.stderr).unwrap();assert!(stderr.starts_with("error: "));
    assert_eq!(stderr,format!("error: {errno}: {reason}\n"));assert!(!stderr.contains(CANARY));
    assert!(!stderr.contains("ns-secret")&&!stderr.contains("private-target")&&!stderr.contains("secret-backend"));
}

#[test]
fn sync_diagnostics_actual_binary_exports_fresh_real_service_without_slo_or_signing_claims() {
    // The second real CLI invocation is a healthy mutation-adapter control.
    for output in [actual(),mutate(|_|{})] {
        let export=success(output);assert_eq!(export.peer_uid,ipc::geteuid());assert_eq!(export.peer_pid,std::process::id());
        assert_eq!(export.snapshot.process_pid,std::process::id());assert!(export.snapshot.dev_same_uid);
        assert!(!export.server_code_verified&&export.peer_code_identity.is_none());assert!(export.snapshot.valid_measurement());
        assert_eq!(export.snapshot.stages.unwrap(),enclave_swarm_syncd::sync_diagnostics::StageRecords::default());
    }
}

#[test]
fn sync_diagnostics_actual_binary_refuses_private_or_ambiguous_metadata_and_negative_wire_pid() {
    for field in 0..12 {
        let (errno,reason)=match field {
            0|1|2|6=>("EACCES","SYNC_DIAGNOSTICS_IDENTITY"),
            3|4|5|9|10=>("EINVAL","SYNC_DIAGNOSTICS_METADATA"),
            _=>("EIO","SYNC_DIAGNOSTICS_ACQUIRE"),
        };
        refused(mutate(move|value|match field {
            0=>value["process_uid"]=serde_json::json!(ipc::geteuid()^1),
            1=>value["process_pid"]=serde_json::json!(std::process::id()^1),
            2=>value["dev_same_uid"]=serde_json::json!(false),
            3=>value["producer"]=serde_json::json!(CANARY),
            4=>value["process_epoch_id"]=serde_json::json!(CANARY),
            5=>value["schema"]=serde_json::json!(2),
            6=>value["process_pid"]=serde_json::json!(0),
            7=>value["process_pid"]=serde_json::json!(-1),
            8=>{value.as_object_mut().unwrap().remove("process_pid");},
            9=>value["stages"]["quic_fetch"]["started"]=serde_json::json!(1),
            10=>value["stages"]["registry_fetch"]["returned_ok"]=serde_json::json!(1_000_000_000_000_001_u64),
            _=>value["private_target_inventory"]=serde_json::json!(CANARY),
        }),errno,reason);
    }
}

#[test]
fn sync_diagnostics_actual_binary_formats_explicit_synthetic_fault_provenance_without_false_zero() {
    for poisoned in [false,true] {
        // Only these wire fields are synthetic; kernel identity and real
        // service epoch remain actual. They establish no measured event count.
        let export=success(invoke_fixture(move|mut response|{
            use enclave_swarm_syncd::sync_diagnostics::CounterAvailability;
            let Reply::Ok(CasResponse::SyncDiagnostics(value))=&mut response else {panic!("typed real-service reply");};
            if poisoned {value.measurement_fault.poisoned=true;
                value.availability=CounterAvailability::Unavailable;value.stages=None;}
            else {value.measurement_fault.overflow=true;value.availability=CounterAvailability::LastKnown;
                let counts=&mut value.stages.as_mut().unwrap().tuf_refresh;counts.started=1;counts.in_flight=1;}
            assert!(value.valid_measurement());
            let wire=ipc::to_cbor(&response).unwrap();
            let decoded:Reply<CasResponse>=ipc::from_cbor(&wire).expect("typed synthetic fault wire roundtrip");
            assert_eq!(serde_json::to_value(decoded).unwrap(),serde_json::to_value(response).unwrap());wire
        }));
        assert!(export.snapshot.measurement_fault.any());assert!(export.snapshot.valid_measurement());
        if poisoned {assert!(export.snapshot.stages.is_none());}else{assert_eq!(export.snapshot.stages.unwrap().tuf_refresh.in_flight,1);}
    }
}

#[test]
fn sync_diagnostics_actual_binary_sanitizes_hostile_error_wrong_variant_and_malformed_frames() {
    refused(invoke_fixture(|_|ipc::to_cbor(&Reply::<CasResponse>::Err(enclave_core::error::EnclaveError::with(
        enclave_core::error::Errno::EIO,CANARY,CANARY))).unwrap()),"EIO","SYNC_DIAGNOSTICS_ACQUIRE");
    refused(invoke_fixture(|_|ipc::to_cbor(&Reply::Ok(CasResponse::Wiped)).unwrap()),"EIO","SYNC_DIAGNOSTICS_RESPONSE");
    refused(invoke_fixture(|_|vec![0xff,0xff]),"EIO","SYNC_DIAGNOSTICS_ACQUIRE");
}

#[test]
fn sync_diagnostics_actual_binary_rejects_jsonl_reset_target_and_identity_arguments() {
    let directory=Directory::new();
    for argument in ["--jsonl","--reset","--target","--namespace","--process-epoch-id"] {
        let output=OwnedChild::spawn(command(&directory.0).arg(argument)).output();
        assert_eq!(output.status.code(),Some(2));assert!(output.stdout.is_empty());
    }
}

#[test]
fn sync_diagnostics_actual_daemon_process_repeated_reads_preserve_epoch_and_restart_resets() {
    let directory=Directory::new();let env=Env::dev(&directory.0,Profile::L1);let socket=env.socket_dir.join(DaemonId::SwarmSync.socket_name());
    let mut epochs=Vec::new();
    for _ in 0..2 {
        // Real existing entry/runtime in explicit development. No signed root
        // admission or production L3 startup bypass is asserted.
        let mut command=Command::new(env!("CARGO_BIN_EXE_mcp-enclave"));
        command.args(["__daemon","702","--dev-same-uid","--simulated-hardware","--profile","L1","--no-audit","--socket-dir"])
            .arg(&env.socket_dir).arg("--store-dir").arg(directory.0.join("store"));
        let mut daemon=OwnedChild::spawn(&mut command);let pid=daemon.0.as_ref().unwrap().id();let until=Instant::now()+DEADLINE;
        while !socket.exists() {assert!(daemon.0.as_mut().unwrap().try_wait().unwrap().is_none(),"owned daemon exited before IPC readiness");
            assert!(Instant::now()<until,"owned daemon readiness timeout");thread::sleep(Duration::from_millis(10));}
        let first=success(OwnedChild::spawn(&mut self::command(&directory.0)).output());
        let second=success(OwnedChild::spawn(&mut self::command(&directory.0)).output());
        assert_eq!(first,second);assert_eq!(first.peer_pid,pid);assert_eq!(first.snapshot.process_pid,pid);
        assert_eq!(first.snapshot.stages.unwrap(),enclave_swarm_syncd::sync_diagnostics::StageRecords::default());
        epochs.push(first.snapshot.process_epoch_id);drop(daemon);
        // The next actual entry may safely remove its owned stale IPC socket.
        if socket.exists(){std::fs::remove_file(&socket).unwrap();}
    }
    assert_ne!(epochs[0],epochs[1],"new actual process has a new local collector identity");
}

#[test]
fn sync_diagnostics_actual_output_is_rejected_by_real_metric_parser_and_empty_slo_stays_incomplete() {
    let output=actual();assert_eq!(output.status.code(),Some(0));let directory=Directory::new();
    let path=directory.0.join("actual-diagnostic.json");
    // Normalize only whitespace into one JSON record so the real metric parser
    // rejects this actual schema rather than merely pretty-print line breaks.
    let value:serde_json::Value=serde_json::from_slice(&output.stdout).unwrap();
    std::fs::write(&path,serde_json::to_vec(&value).unwrap()).unwrap();
    let script=Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/aggregate-sli.py");
    let program=r#"import importlib.util,json,pathlib,sys
spec=importlib.util.spec_from_file_location('aggregate',sys.argv[1]);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
try:m.read_input(pathlib.Path(sys.argv[2]),1800000000)
except (ValueError,RuntimeError):pass
else:raise AssertionError('diagnostic schema must not become metric rows')
r=m.aggregate([],1800000000);assert r['status']=='INCOMPLETE' and not r['complete'];assert all(d['state']=='UNKNOWN' for d in r['metrics']['swarm_sync']['decisions']);print('SYNC_DIAGNOSTICS_NOT_SLO=true')
"#;
    let output=OwnedChild::spawn(Command::new("python3").args(["-B","-c",program]).arg(script).arg(path)).output();
    assert_eq!(output.status.code(),Some(0),"{}",String::from_utf8_lossy(&output.stderr));
    assert_eq!(String::from_utf8(output.stdout).unwrap().trim(),"SYNC_DIAGNOSTICS_NOT_SLO=true");
}
