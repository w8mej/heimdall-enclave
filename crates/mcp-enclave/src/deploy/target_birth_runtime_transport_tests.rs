//! SOFTWARE private engine/mapping fixtures only. No native birth, protected
//! loaded provisioning, account/software approval, guard or EX is fabricated.
//! Unsigned/expired schema fixtures cannot satisfy the actual consuming API.
use super::*;
use serde_json::{json,Value};
use std::{cell::Cell,os::unix::fs::{PermissionsExt,symlink},sync::Mutex};
static SERIAL:Mutex<()>=Mutex::new(());
fn encode(v:Value)->Vec<u8>{serde_json::to_vec(&v).unwrap()}
fn sync(file:&File)->EnclaveResult<()>{file.sync_all().map_err(|_|err!(EIO,"RUNTIME_FIXTURE_SYNC"))}
fn template()->DeploymentTarget {
    DeploymentTarget::parse(&encode(json!({"version":1,"target_id":"runtime-fixture","role":"dedicated-test","profile":"L2",
        "signing_identity_mode":"local-pins","authority_config":"/template/support/custody.json",
        "expected_artifacts_manifest":"/template/config/inventory.json","codesign_pins_file":"/template/support/pins.json",
        "broker":null,"shared_read_only_inputs":[],"layout":{"binary_dir":"/template/bin","custody_bundle":"/template/support/Custody.app",
        "sandbox_dir":"/template/sandbox","socket_root":"/template/run","state_root":"/template/state","audit_root":"/template/audit",
        "cas_store_root":"/template/cas","staging_root":"/template/stage","support_root":"/template/support",
        "launchd_namespace":"com.depot.runtimefixture","mach_service":"com.depot.runtimefixture.exception"}}))).unwrap()
}
fn metadata(role:&str,version:u64)->Vec<u8> {
    let mut signed=json!({"_type":role,"spec_version":"1.0.31","version":version,"expires":"2000-01-01T00:00:00Z"});
    match role {"root"=>{signed["keys"]=json!({});signed["roles"]=json!({});},"targets"=>signed["targets"]=json!({}),
        _=>signed["meta"]=json!({})};encode(json!({"signed":signed,"signatures":[]}))
}
fn schema_files()->BTreeMap<PathBuf,Vec<u8>> {
    let mds=br#"{"entries":[]}"#.to_vec();
    let host=enclave_core::host_config::EnclaveHostConfig {profile_floor:Profile::L2,ifc_grant_public_key:"01".repeat(32),
        calibration_corpus_digest:"02".repeat(32),vk_digest:"03".repeat(32),depot_lock_digest:"04".repeat(32),
        fido_mds_allowlist_digest:blake3::hash(&mds).to_hex().to_string(),ohttp_key_config:None,codesign_pins:None};
    let envelope=encode(json!({"policy":{"version":1,"revision":1,"subject":"fixture-host","namespace":"fixture",
        "issued_unix":1,"expires_unix":2,"review_unix":2,"owner":"fixture","profiles":["L2"],"data_classes":["C3","C4"],
        "purpose":"fixture","migration":"fixture","disclosure":null,"classical_exception":false},"signature":[]}));
    BTreeMap::from([("root.json".into(),metadata("root",1)),("timestamp.json".into(),metadata("timestamp",1)),
        ("snapshot.json".into(),metadata("snapshot",1)),("targets.json".into(),metadata("targets",1)),
        ("enclave-host-config.json".into(),host.to_json_bytes().unwrap()),("fido-mds-allowlist.json".into(),mds),
        ("custody-envelope-policy-v1.json".into(),envelope)])
}
fn inventory(plan:&BirthPlan,files:&BTreeMap<PathBuf,Vec<u8>>)->Vec<u8> {
    let pins=&files[Path::new("codesign-pins.json")];
    encode(json!({"version":1,"kind":"depot-first-touch-artifact-inventory","target_id":plan.target.target_id,"profile":"L2",
        "signing_identity_mode":"local-pins","deployment_config_sha256":hex::encode(Sha256::digest(&plan.bytes)),
        "source_git_commit":"a".repeat(40),"source_manifest_sha256":"b".repeat(64),"source_input_count":files.len(),
        "codesign_pins_sha256":hex::encode(Sha256::digest(pins)),"staging_root":plan.target.layout.staging_root,
        "external_provenance":"UNKNOWN","files":files.iter().map(|(path,bytes)|json!({"path":path,
            "sha256":hex::encode(Sha256::digest(bytes)),"size":bytes.len()})).collect::<Vec<_>>()}))
}
struct Fixture {anchor:PathBuf,state:BirthState,approved:TargetInstallPlan,sources:Vec<RuntimeSource>}
impl Fixture {
    fn new(extra:Option<(String,Vec<u8>)>)->Self {
        let anchor=std::env::current_dir().unwrap().join(format!(".birth-runtime-{}",hex::encode(enclave_core::rng::bytes32())));
        std::fs::create_dir(&anchor).unwrap();std::fs::set_permissions(&anchor,std::fs::Permissions::from_mode(0o700)).unwrap();
        let original=BirthPlan::build(&template(),Path::new("/template"),Path::new("/runtime-birth"),&[0x52;16]).unwrap();
        let root=anchor.join(original.root.file_name().unwrap());let map=|p:&Path|root.join(p.strip_prefix(&original.root).unwrap());
        let raw=String::from_utf8(original.bytes.clone()).unwrap().replace(original.root.to_str().unwrap(),root.to_str().unwrap()).into_bytes();
        let plan=BirthPlan {root:root.clone(),target:DeploymentTarget::parse(&raw).unwrap(),descriptor:map(&original.descriptor),bytes:raw,
            seed_dirs:original.seed_dirs.iter().map(|p|map(p)).collect()};
        let protection=Protection {owner:(unsafe{libc::geteuid()},unsafe{libc::getegid()}),native_acl:false};
        let name=CString::new(anchor.as_os_str().as_bytes()).unwrap();
        let fd=unsafe{libc::open(name.as_ptr(),libc::O_RDONLY|libc::O_DIRECTORY|libc::O_NOFOLLOW|libc::O_NONBLOCK|libc::O_CLOEXEC)};
        assert!(fd>=0);let directory=Directory::capture(unsafe{File::from_raw_fd(fd)},None,false,protection).unwrap();
        let mut progress=BirthProgress::new();progress.root=Some(root.clone());progress.descriptor=Some(plan.descriptor.clone());progress.target_id=Some(plan.target.target_id.clone());
        let mut state=BirthState {plan,dirs:BTreeMap::from([(anchor.clone(),directory)]),files:BTreeMap::new(),protection,
            progress,poisoned:false,pending:None,private_load:None};
        state.create_directory(&root,&mut||Vec::new(),&mut Vec::new(),&mut sync).unwrap();state.prepare_seeds(&mut||Vec::new(),&mut sync).unwrap();
        let mut bodies=schema_files();if let Some((name,bytes))=extra {bodies.insert(name.into(),bytes);}
        // The real inventory parser requires pins AND this binary role before
        // returning its incomplete-package report. Bytes remain inert fixtures.
        let mut files=BTreeMap::from([(PathBuf::from("codesign-pins.json"),b"SOFTWARE nonauthority pins".to_vec()),
            (PathBuf::from("bin/depot-enclave"),b"SOFTWARE unadmitted binary".to_vec())]);
        for (name,bytes) in &bodies {files.insert(PathBuf::from("tuf/repo").join(name),bytes.clone());}
        let first=target_plan::describe(&state.plan.target,&hex::encode(Sha256::digest(&state.plan.bytes)),&inventory(&state.plan,&files)).unwrap();
        for name in first.missing_required_files {files.insert(name.into(),b"SOFTWARE unadmitted package body".to_vec());}
        let raw=inventory(&state.plan,&files);let approved=target_plan::describe(&state.plan.target,&hex::encode(Sha256::digest(&state.plan.bytes)),&raw).unwrap();
        assert!(approved.missing_required_files.is_empty());state.prepare_denial(&raw,&mut||Vec::new(),&mut sync).unwrap();
        let stage=state.plan.target.layout.staging_root.clone();
        for path in [stage.join("tuf"),stage.join("tuf/repo")] {state.create_directory(&path,&mut||Vec::new(),&mut Vec::new(),&mut sync).unwrap();}
        for (name,bytes) in bodies {let path=stage.join("tuf/repo").join(name);
            state.create_file(&path,&bytes,0o600,&mut||Vec::new(),&mut Vec::new(),&mut sync).unwrap();
            let source=state.files.get_mut(&path).unwrap();source.bytes.clear();source.streamed=Some(StreamedContent {length:bytes.len()as u64,
                sha256:hex::encode(Sha256::digest(bytes))});
        }
        let mut sources=Vec::new();for spec in source_specs(&state,&approved).unwrap() {
            let bytes=read_source(&state,&spec,&mut Vec::new()).unwrap();sources.push(RuntimeSource {spec,bytes});
        }Self {anchor,state,approved,sources}
    }
    fn plan(&self)->EnclaveResult<RuntimeTransportPlan>{RuntimeTransportPlan::build(&self.state,&self.approved,&self.sources)}
    fn directories(&mut self,plan:&RuntimeTransportPlan){for path in &plan.directories {
        self.state.create_directory(path,&mut||Vec::new(),&mut Vec::new(),&mut sync).unwrap();}}
    fn outputs(&mut self,plan:&RuntimeTransportPlan,pin:&[u8]) {
        self.state.create_file(&plan.pin,pin,0o644,&mut||Vec::new(),&mut Vec::new(),&mut sync).unwrap();
        for copy in &plan.copies {self.state.create_file_from_birth_stage(&copy.source,&copy.destination,copy.size,&copy.sha256,0o644,
            &mut||Vec::new(),&mut Vec::new(),&mut sync).unwrap();}
    }
}
impl Drop for Fixture {fn drop(&mut self){let _=std::fs::remove_dir_all(&self.anchor);}}
fn no_authority(state:&BirthState){assert!(state.private_load.is_none());assert!(!state.progress.activation_allowed&&!state.progress.mutation_allowed
    &&!state.progress.inactivity_proven&&!state.progress.installation_supported&&!state.progress.qualified);}

#[test]
fn closed_roles_and_numbered_roots_exclude_path_aliases_and_wrong_authorities() {
    for (name,bound) in [("root.json",4*1024*1024),("enclave-host-config.json",64*1024),
        ("fido-mds-allowlist.json",256*1024),("custody-envelope-policy-v1.json",16*1024),("2147483647.root.json",4*1024*1024)] {
        assert_eq!(source_bound(name),Some(bound));
    }
    for name in ["ROOT.json","0.root.json","01.root.json","+1.root.json","2147483648.root.json","1/root.json",
        "../root.json","fido-mds.json","custody-oidc-authority-v1.json","vk_manifest.json",""] {assert!(source_bound(name).is_none(),"{name}");}
}
#[test]
fn final_crypto_window_refuses_expiry_equality_crossing_and_backwards_time() {
    // Plain arithmetic timing observations only; no actual verification proof,
    // native owner, provisioning or report-to-capability constructor is made.
    within_crypto_window(100,110,100).unwrap();within_crypto_window(100,110,109).unwrap();
    for (checked,deadline,now) in [(100,110,110),(100,110,111),(100,110,99),
        (-1,110,100),(100,100,100),(100,99,100)] {
        assert!(within_crypto_window(checked,deadline,now).unwrap_err().is("BIRTH_RUNTIME_FINAL_CRYPTO_EXPIRED"));
    }
}
#[test]
fn actual_schema_report_and_local_seven_output_mapping_agree_without_authority() {
    let _serial=SERIAL.lock().unwrap_or_else(std::sync::PoisonError::into_inner);let f=Fixture::new(None);let before=f.state.progress.attempted.clone();
    let plan=f.plan().unwrap();plan.assert_absent(&f.state).unwrap();assert_eq!(plan.copies.len()+1,7);
    let report=target_runtime_trust::describe(&f.state.plan.target,&hex::encode(Sha256::digest(&f.state.plan.bytes)),&entries(&f.sources)).unwrap();
    assert!(report.supplied_inputs_complete);assert!(!report.apply_supported);assert_eq!(report.authentication,"UNVERIFIED");
    for entry in &report.inputs {assert_eq!(entry.proposed_transport_path,destination(&f.state.plan.target,&entry.name).unwrap());}
    assert!(plan.copies.iter().all(|copy|copy.source.file_name().unwrap()!="root.json"));
    assert_eq!(plan.pin,report.runtime_pin_file);assert_eq!(before,f.state.progress.attempted);no_authority(&f.state);
    let declared=f.approved.directories.iter().filter(|entry|runtime_roots(&f.state).iter().any(|r|entry.path.starts_with(r)))
        .map(|entry|entry.path.clone()).collect::<BTreeSet<_>>();
    let extra=plan.directories.iter().filter(|p|!declared.contains(*p)).cloned().collect::<BTreeSet<_>>();let l=&f.state.plan.target.layout;
    assert_eq!(extra,BTreeSet::from([l.support_root.join("tuf"),l.state_root.join("cas/tuf"),l.state_root.join("cas/tuf/repo")]));
    let root=&f.sources.iter().find(|s|s.spec.path.file_name().unwrap()=="root.json").unwrap().bytes;
    assert!(enclave_crypto::tuf::TufClient::bootstrap(root).is_err());
}
#[test]
fn original_streamed_sources_are_read_from_same_fd_including_small_and_large_empty_sentinels() {
    let _serial=SERIAL.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    for size in [17,64*1024+37,1024*1024+7,4*1024*1024] {
        let bytes=(0..size).map(|n|(n%251)as u8).collect::<Vec<_>>();let f=Fixture::new(Some(("2.root.json".into(),bytes.clone())));
        let source=f.sources.iter().find(|s|s.spec.path.file_name().unwrap()=="2.root.json").unwrap();
        assert!(f.state.files[&source.spec.path].bytes.is_empty());assert_eq!(source.bytes,bytes);
        assert_eq!(read_source(&f.state,&source.spec,&mut Vec::new()).unwrap(),bytes);no_authority(&f.state);
    }
}
#[test]
fn inventory_role_byte_rotation_count_and_chain_bounds_are_closed_before_effects() {
    let _serial=SERIAL.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    for kind in 0..5 {let mut f=Fixture::new(None);let before=f.state.progress.attempted.clone();
        match kind {
            0|1=>{let body=f.approved.retained_in_staging.iter_mut().find(|r|r.source.file_name().unwrap()=="fido-mds-allowlist.json").unwrap();
                body.size=if kind==0 {0}else{256*1024+1};},
            2=>{let body=f.approved.retained_in_staging.iter_mut().find(|r|r.source.file_name().unwrap()=="root.json").unwrap();body.sha256="AB".repeat(32);},
            3|4=>{let repository=f.state.plan.target.layout.staging_root.join("tuf/repo");let count=if kind==3{33}else{5};
                for version in 1..=count {f.approved.retained_in_staging.push(target_plan::RetainedEntry {source:repository.join(format!("{version}.root.json")),
                    size:if kind==3{1}else{4*1024*1024},sha256:"ab".repeat(32),reason:"SOFTWARE bound probe"});}},_=>unreachable!(),
        }
        assert!(source_specs(&f.state,&f.approved).is_err());assert_eq!(before,f.state.progress.attempted);no_authority(&f.state);
    }
}
#[test]
fn actual_private_creator_keeps_directories700_files644_and_candidate_root_untransported() {
    let _serial=SERIAL.lock().unwrap_or_else(std::sync::PoisonError::into_inner);let mut f=Fixture::new(Some(("2.root.json".into(),metadata("root",2))));
    let plan=f.plan().unwrap();f.directories(&plan);let pin=b"independent SOFTWARE operator bytes, never candidate";f.outputs(&plan,pin);
    assert!(plan.partial_current(&f.state,pin,true).is_empty());assert_eq!(plan.copies.len()+1,8);
    for path in &plan.directories {assert_eq!(std::fs::metadata(path).unwrap().mode()&0o7777,0o700);}
    for path in plan.copies.iter().map(|copy|&copy.destination).chain([&plan.pin]) {
        let output=&f.state.files[path];assert_eq!(output.file.metadata().unwrap().mode()&0o7777,0o644);assert_eq!(output.access,libc::O_RDONLY);
    }
    assert!(!f.state.plan.target.layout.state_root.join("cas/tuf/repo/root.json").exists());assert_eq!(std::fs::read(&plan.pin).unwrap(),pin);
    private_ancestry(&f.state).unwrap();no_authority(&f.state);
}
#[test]
fn retained_filesystem_root_observation_cannot_poison_valid_folded_plan() {
    let _serial=SERIAL.lock().unwrap_or_else(std::sync::PoisonError::into_inner);let mut f=Fixture::new(None);let before=f.plan().unwrap();
    let fd=unsafe{libc::open(c"/".as_ptr(),libc::O_RDONLY|libc::O_DIRECTORY|libc::O_NOFOLLOW|libc::O_NONBLOCK|libc::O_CLOEXEC)};
    assert!(fd>=0);let file=unsafe{File::from_raw_fd(fd)};let metadata=file.metadata().unwrap();
    let root=Directory::capture(file,None,false,Protection {owner:(metadata.uid(),metadata.gid()),native_acl:false}).unwrap();
    let identity=(root.stamp.dev,root.stamp.ino);f.state.dirs.insert(PathBuf::from("/"),root);let after=f.plan().unwrap();
    assert_eq!(before.directories,after.directories);assert_eq!((f.state.dirs[Path::new("/")].stamp.dev,f.state.dirs[Path::new("/")].stamp.ino),identity);
}
#[test]
fn inventory_digest_size_missing_duplicate_and_source_set_drift_refuse_before_effects() {
    let _serial=SERIAL.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    for change in 0..5 {let mut f=Fixture::new(None);let before=f.state.progress.attempted.clone();
        match change {0=>f.sources[0].spec.sha256="00".repeat(32),1=>f.sources[0].spec.size+=1,
            2=>{f.sources.pop();},3=>{let first=f.approved.retained_in_staging.iter().find(|r|source_bound(r.source.file_name().unwrap().to_str().unwrap()).is_some()).unwrap();
                f.approved.retained_in_staging.push(target_plan::RetainedEntry {source:first.source.clone(),sha256:first.sha256.clone(),size:first.size,reason:"SOFTWARE duplicate"});},
            _=>{f.sources.swap(0,1);}}
        assert!(f.plan().is_err());assert_eq!(before,f.state.progress.attempted);no_authority(&f.state);
    }
}
#[test]
fn preexisting_runtime_root_symlink_or_unowned_intermediate_is_never_adopted() {
    let _serial=SERIAL.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    for kind in 0..3 {let f=Fixture::new(None);let plan=f.plan().unwrap();let path=match kind {0|1=>f.state.plan.target.layout.state_root.clone(),_=>f.state.plan.target.layout.support_root.join("tuf")};
        if kind==1 {symlink(&f.state.plan.target.layout.staging_root,&path).unwrap();}else{std::fs::create_dir(&path).unwrap();}
        let before=f.state.progress.attempted.clone();assert!(plan.assert_absent(&f.state).is_err());assert!(!f.state.dirs.contains_key(&path));
        assert_eq!(before,f.state.progress.attempted);no_authority(&f.state);
    }
}
#[test]
fn folded_cached_names_reserved_files_and_node_limit_close_before_creation() {
    let _serial=SERIAL.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    for kind in 0..4 {let mut f=Fixture::new(None);let before=f.state.progress.attempted.clone();
        match kind {0=>{let path=f.state.plan.target.layout.state_root.clone();let original=f.state.dirs[&f.state.plan.root].file.try_clone().unwrap();
                let d=Directory::capture(original,None,true,f.state.protection).unwrap();f.state.dirs.insert(PathBuf::from(path.to_str().unwrap().to_ascii_uppercase()),d);},
            1=>{f.approved.directories.push(target_plan::DirectoryEntry {path:f.state.plan.target.layout.state_root.join("cas/tuf"),uid:0,gid:0,
                mode:"0755".into(),condition:"SOFTWARE collision"});},
            2=>{let copy=f.approved.copies.iter_mut().find(|c|c.destination!=f.approved.selected_pins_file).unwrap();
                copy.destination=f.state.plan.target.layout.state_root.join("cas/tuf/repo/targets.json");},
            _=>{while f.state.dirs.len()<MAX_NODES {let file=f.state.dirs[&f.state.plan.root].file.try_clone().unwrap();
                f.state.dirs.insert(f.anchor.join(format!("SOFTWARE{}",f.state.dirs.len())),Directory::capture(file,None,true,f.state.protection).unwrap());}}}
        assert!(f.plan().is_err());assert_eq!(before,f.state.progress.attempted);no_authority(&f.state);
    }
}
#[test]
fn original_source_mutation_replacement_mode_flags_and_length_drift_refuse() {
    let _serial=SERIAL.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    for kind in 0..5 {let f=Fixture::new(None);let source=&f.sources[0];let path=&source.spec.path;
        match kind {0=>{let mut bytes=source.bytes.clone();bytes[0]^=1;std::fs::write(path,bytes).unwrap();},
            1=>{std::fs::rename(path,path.with_extension("original")).unwrap();std::fs::write(path,&source.bytes).unwrap();
                std::fs::set_permissions(path,std::fs::Permissions::from_mode(0o600)).unwrap();},
            2=>std::fs::set_permissions(path,std::fs::Permissions::from_mode(0o644)).unwrap(),
            3=>{let file=&f.state.files[path].file;let flags=unsafe{libc::fcntl(file.as_raw_fd(),libc::F_GETFL)};
                assert!(unsafe{libc::fcntl(file.as_raw_fd(),libc::F_SETFL,flags&!libc::O_NONBLOCK)}>=0);},
            _=>{std::fs::OpenOptions::new().write(true).open(path).unwrap().set_len(source.spec.size-1).unwrap();}}
        assert!(read_source(&f.state,&source.spec,&mut Vec::new()).is_err());no_authority(&f.state);
    }
}
#[test]
fn completed_transport_checks_original_output_replacement_and_byte_mutation() {
    let _serial=SERIAL.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    for kind in 0..3 {let mut f=Fixture::new(None);let plan=f.plan().unwrap();f.directories(&plan);let pin=b"SOFTWARE independent pin";f.outputs(&plan,pin);
        let path=if kind==0{plan.pin.clone()}else{plan.copies[0].destination.clone()};let bytes=std::fs::read(&path).unwrap();
        if kind==2 {std::fs::rename(&path,path.with_extension("original")).unwrap();std::fs::write(&path,&bytes).unwrap();
            std::fs::set_permissions(&path,std::fs::Permissions::from_mode(0o644)).unwrap();}
        else {let mut changed=bytes;changed[0]^=1;std::fs::write(&path,changed).unwrap();}
        assert!(!plan.partial_current(&f.state,pin,true).is_empty());assert!(f.state.files.contains_key(&path));no_authority(&f.state);
    }
}
#[test]
fn failed_sync_retains_partial_names_original_owners_and_no_rollback_or_retry_authority() {
    let _serial=SERIAL.lock().unwrap_or_else(std::sync::PoisonError::into_inner);let mut f=Fixture::new(None);let plan=f.plan().unwrap();f.directories(&plan);
    let copy=&plan.copies[0];let writes=Cell::new(0);let mut observed=Vec::new();
    let result=f.state.create_file_from_birth_stage(&copy.source,&copy.destination,copy.size,&copy.sha256,0o644,&mut||Vec::new(),&mut observed,
        &mut|_|{writes.set(writes.get()+1);Err(err!(EIO,"SOFTWARE_INJECTED_SYNC_REFUSAL"))});
    assert!(result.is_err());assert_eq!(writes.get(),1);assert!(copy.destination.exists());assert!(f.state.files.contains_key(&copy.destination));
    assert!(f.state.files.contains_key(&copy.source));assert!(!plan.partial_current(&f.state,b"SOFTWARE pin",true).is_empty());
    assert!(f.state.create_file_from_birth_stage(&copy.source,&copy.destination,copy.size,&copy.sha256,0o644,&mut||Vec::new(),&mut Vec::new(),&mut sync).is_err());
    no_authority(&f.state);
}
#[test]
fn post_creation_guard_refusal_preserves_partial_directory_and_primary_error() {
    let _serial=SERIAL.lock().unwrap_or_else(std::sync::PoisonError::into_inner);let mut f=Fixture::new(None);let plan=f.plan().unwrap();let path=&plan.directories[0];
    let calls=Cell::new(0);let mut observed=Vec::new();let result=f.state.create_directory(path,&mut||{
        calls.set(calls.get()+1);if calls.get()>2{vec![err!(EACCES,"SOFTWARE_GUARD_REFUSAL")]}else{Vec::new()}
    },&mut observed,&mut sync);
    assert!(result.is_err());assert!(path.exists());assert!(f.state.dirs.contains_key(path));assert!(!observed.is_empty());no_authority(&f.state);
}
