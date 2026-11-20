//! Pure input checks and ignored actual protected SOFTWARE readers only.
//! No native payload/candidate, guard, accounts, SOFTWARE approval or startup EX
//! capability is constructed. Real native consuming success stays UNEXERCISED.
use super::*;
use serde_json::{json,Value};
use std::{fs::OpenOptions,os::unix::fs::{OpenOptionsExt,PermissionsExt,symlink}};

fn encoded(value:Value)->Vec<u8>{serde_json::to_vec(&value).unwrap()}
fn raw_target()->DeploymentTarget {
    let root=PathBuf::from(format!("/allocated/{}","a".repeat(32)));
    DeploymentTarget::parse(&encoded(json!({"version":1,"target_id":format!("ykft-{}","a".repeat(32)),
        "role":"dedicated-test","profile":"L2","signing_identity_mode":"local-pins",
        "authority_config":root.join("support/custody.json"),"expected_artifacts_manifest":root.join("config/inventory.json"),
        "codesign_pins_file":root.join("support/pins.json"),"broker":null,"shared_read_only_inputs":[],
        "layout":{"binary_dir":root.join("bin"),"custody_bundle":root.join("support/Custody.app"),
            "sandbox_dir":root.join("sandbox"),"socket_root":root.join("run"),"state_root":root.join("state"),
            "audit_root":root.join("audit"),"cas_store_root":root.join("cas"),"staging_root":root.join("stage"),
            "support_root":root.join("support"),"launchd_namespace":"com.mcpmac.runtimepinfixture",
            "mach_service":"com.mcpmac.runtimepinfixture.exception"}}))).unwrap()
}
fn scope()->PinScope {
    let target=raw_target();let root=PathBuf::from(format!("/allocated/{}","a".repeat(32)));
    dedicated_scope(&target,&root.join(DESCRIPTOR),&"b".repeat(64),&root).unwrap()
}
fn selection(scope:&PinScope,pin:&Path,digest:&str)->Value {
    json!({"version":1,"kind":RECORD_KIND,"purpose":RECORD_PURPOSE,"target_id":scope.target_id,
        "profile":"L2","descriptor_sha256":scope.descriptor_sha256,"pin_source_file":pin,"pin_sha256":digest})
}
fn denied<T>(result:EnclaveResult<T>,reason:&str) {
    let error=result.err().expect("must refuse");assert!(error.is(reason),"unexpected static reason {}",error.reason);
}
#[test]
fn closed_record_binds_exact_purpose_allocated_descriptor_and_external_choice_data_only() {
    let scope=scope();let pin=Path::new("/operator/runtime/root.json");
    let parsed=record(&encoded(selection(&scope,pin,&"c".repeat(64))),&scope,Path::new("/operator/selection.json")).unwrap();
    assert_eq!(parsed.target_id,scope.target_id);assert_eq!(parsed.descriptor_sha256,scope.descriptor_sha256);
    assert_eq!(parsed.pin_source_file,pin);assert_eq!(parsed.pin_sha256,"c".repeat(64));
    // Pure JSON has not produced a native wrapper, provenance flag or crypto
    // report. Equal candidate bytes are not evidence of independent choice.
}
#[test]
fn strict_record_rejects_unknown_missing_duplicate_escaped_float_trailing_and_oversize() {
    let scope=scope();let path=Path::new("/operator/selection.json");
    let base=selection(&scope,Path::new("/operator/root.json"),&"c".repeat(64));
    for variant in ["unknown","missing","null","array","float"] {
        let mut value=base.clone();match variant {
            "unknown"=>value["approved"]=json!(true),"missing"=>{value.as_object_mut().unwrap().remove("pin_sha256");},
            "null"=>value["purpose"]=Value::Null,"array"=>value=json!([value]),_=>value["version"]=json!(1.0),
        }
        denied(record(&encoded(value),&scope,path),"BIRTH_RUNTIME_PIN_RECORD_SCHEMA");
    }
    let raw=String::from_utf8(encoded(base)).unwrap();
    for bytes in [raw.replacen('{',"{\"version\":1,",1).into_bytes(),
        raw.replace("purpose","pur\\u0070ose").into_bytes(),format!("{raw} {{}}").into_bytes() ] {
        denied(record(&bytes,&scope,path),"BIRTH_RUNTIME_PIN_RECORD_SCHEMA");
    }
    denied(record(&[],&scope,path),"BIRTH_RUNTIME_PIN_RECORD_BOUND");
    denied(record(&vec![b' ';MAX_RECORD_BYTES as usize+1],&scope,path),"BIRTH_RUNTIME_PIN_RECORD_BOUND");
}
#[test]
fn record_scope_hashes_and_first_provisioning_purpose_cannot_be_substituted() {
    let scope=scope();let path=Path::new("/operator/selection.json");
    for (field,replacement) in [("version",json!(2)),("kind",json!("mcpmac-software-release-authority")),
        ("purpose",json!("software-release")),("target_id",json!("another-target")),("profile",json!("L3")),
        ("descriptor_sha256",json!("c".repeat(64))),("pin_sha256",json!("C".repeat(64))),
        ("pin_sha256",json!("c".repeat(63))),("pin_sha256",json!("g".repeat(64)))] {
        let mut value=selection(&scope,Path::new("/operator/root.json"),&"c".repeat(64));value[field]=replacement;
        denied(record(&encoded(value),&scope,path),"BIRTH_RUNTIME_PIN_RECORD_SCOPE");
    }
    let mut value=selection(&scope,Path::new("/operator/root.json"),&"c".repeat(64));
    value["purpose"]=json!("runtime-tuf-existing-upgrade");
    denied(record(&encoded(value),&scope,path),"BIRTH_RUNTIME_PIN_RECORD_SCOPE");
}
#[test]
fn allocated_scope_refuses_existing_upgrade_other_profiles_and_unbound_descriptors() {
    let target=raw_target();let root=PathBuf::from(format!("/allocated/{}","a".repeat(32)));
    for variant in ["role","profile","signing","target","descriptor","hash","root"] {
        let mut target=target.clone();let mut descriptor=root.join(DESCRIPTOR);let mut digest="b".repeat(64);let mut root=root.clone();
        match variant {
            "role"=>target.role=DeploymentRole::ExistingUpgrade,"profile"=>target.profile=Profile::L3,
            "signing"=>target.signing_identity_mode=DeploymentSigningMode::TeamId,"target"=>target.target_id="another-target".into(),
            "descriptor"=>descriptor=root.join("config/another.json"),"hash"=>digest="B".repeat(64),_=>root="/allocated/not-a-nonce".into(),
        }
        assert!(dedicated_scope(&target,&descriptor,&digest,&root).is_err(),"{variant}");
    }
}
#[test]
fn pin_and_record_routes_refuse_birth_stage_control_case_alias_and_os_aliases() {
    let scope=scope();let path=Path::new("/operator/selection.json");
    for pin in [scope.root.join("stage/tuf/repo/root.json"),scope.root.join("support/tuf/root.json"),
        scope.root.clone(),PathBuf::from("/operator/SELECTION.json"),path.join("child"),PathBuf::from("/operator"),
        PathBuf::from("/var/operator/root.json"),PathBuf::from("/operator/../root.json"),
        PathBuf::from("/operator//root.json"),PathBuf::from("relative/root.json"),
        PathBuf::from("/Library/LaunchDaemons/root.json"),PathBuf::from(format!("/operator/{}","x".repeat(256)))] {
        assert!(record(&encoded(selection(&scope,&pin,&"c".repeat(64))),&scope,path).is_err());
    }
    let pin=Path::new("/operator/root.json");
    assert!(record(&encoded(selection(&scope,pin,&"c".repeat(64))),&scope,&scope.root.join("config/selection.json")).is_err());
}
#[test]
fn administrative_reader_debug_redacts_all_input_bytes_and_routes() {
    let mut inputs=OperatorPinInputs::empty();inputs.record_bytes=b"raw-operator-record-and-pii".to_vec();
    inputs.pin_bytes=b"public-but-unrelated-pin-content".to_vec();let text=format!("{inputs:?}");
    assert!(!text.contains("operator-record")&&!text.contains("pin-content")&&!text.contains("/operator"));
    assert!(text.contains("<redacted>"));
}

struct RootFixture {base:PathBuf,record:PathBuf,pin:PathBuf,bytes:Vec<u8>}
impl RootFixture {
    fn new(bytes:Vec<u8>,digest:Option<&str>)->Self {
        assert_eq!(unsafe{libc::geteuid()},0);assert_eq!(unsafe{libc::getegid()},0);
        assert_eq!(std::env::var("ENCLAVE_TEST_STATE_ROOT").as_deref(),Ok("/state"),"explicit private /state SOFTWARE harness required");
        let base=PathBuf::from("/state").join(format!("runtime-pin-{}",hex::encode(enclave_core::rng::bytes32())));
        std::fs::create_dir(&base).unwrap();std::fs::set_permissions(&base,std::fs::Permissions::from_mode(0o700)).unwrap();
        let pin=base.join("root.json");let record=base.join("selection.json");
        Self::write(&pin,&bytes);
        let hash=hex::encode(Sha256::digest(&bytes));
        Self::write(&record,&encoded(selection(&scope(),&pin,digest.unwrap_or(&hash))));
        Self {base,record,pin,bytes}
    }
    fn write(path:&Path,bytes:&[u8]) {
        let mut file=OpenOptions::new().create_new(true).write(true).mode(0o600).open(path).unwrap();
        file.write_all(bytes).unwrap();file.set_permissions(std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    fn inputs(&self)->OperatorPinInputs {
        let mut inputs=OperatorPinInputs::empty();inputs.paths=Some(HeldPaths::new().unwrap());inputs
    }
    fn read(&self)->OperatorPinInputs {
        let mut inputs=self.inputs();let mut observed=Vec::new();
        inputs.read_record(&scope(),&self.record,&mut observed).unwrap();inputs.read_pin(&mut observed).unwrap();
        inputs.complete(&scope()).unwrap();assert!(observed.is_empty());inputs
    }
}
impl Drop for RootFixture {fn drop(&mut self){let _=std::fs::remove_dir_all(&self.base);}}

#[test]
#[ignore="requires explicit root /state protected SOFTWARE reader harness; no native candidate/guard authority"]
fn small_and_large_pin_reads_replace_empty_helper_sentinel_with_bounded_original_fd_bytes() {
    for length in [17,1024*1024+19,MAX_PIN_BYTES as usize] {
        let fixture=RootFixture::new((0..length).map(|i|(i%251)as u8).collect(),None);let before=std::fs::metadata(&fixture.pin).unwrap();
        let mut inputs=fixture.inputs();let mut observed=Vec::new();inputs.read_record(&scope(),&fixture.record,&mut observed).unwrap();
        {
            let paths=inputs.paths.as_mut().unwrap();let (held,sentinel)=HeldFile::open(paths,&fixture.pin,MAX_PIN_BYTES,Some(0o600)).unwrap();
            assert!(sentinel.is_empty());let original=held.file().as_raw_fd();
            assert_eq!(same_fd_pin_bytes(paths,&held,&mut observed).unwrap(),fixture.bytes);assert_eq!(held.file().as_raw_fd(),original);
        }
        inputs.read_pin(&mut observed).unwrap();inputs.complete(&scope()).unwrap();assert_eq!(inputs.pin_bytes,fixture.bytes);
        assert!(observed.is_empty());assert!(inputs.observations().is_empty());let after=std::fs::metadata(&fixture.pin).unwrap();
        assert_eq!((before.dev(),before.ino(),before.mode(),before.nlink(),before.len()),
            (after.dev(),after.ino(),after.mode(),after.nlink(),after.len()));assert_eq!(after.mode()&0o7777,0o600);
        assert_eq!(std::fs::read_dir(&fixture.base).unwrap().count(),2);
    }
}
#[test]
#[ignore="requires explicit root /state protected SOFTWARE reader harness"]
fn wrong_expected_hash_retains_both_originals_and_poison_survives_record_rewrite() {
    let fixture=RootFixture::new(b"independently chosen SOFTWARE fixture pin".to_vec(),Some(&"0".repeat(64)));
    let mut inputs=fixture.inputs();let mut observed=Vec::new();inputs.read_record(&scope(),&fixture.record,&mut observed).unwrap();
    denied(inputs.read_pin(&mut observed),"BIRTH_RUNTIME_PIN_EXPECTATION");
    assert!(inputs.paths.is_some()&&inputs.record.is_some()&&inputs.pin.is_some());assert_eq!(inputs.pin_bytes,fixture.bytes);
    let held=inputs.pin.as_ref().unwrap().file().as_raw_fd();
    std::fs::write(&fixture.record,encoded(selection(&scope(),&fixture.pin,&hex::encode(Sha256::digest(&fixture.bytes))))).unwrap();
    denied(inputs.read_pin(&mut observed),"BIRTH_RUNTIME_PIN_OWNER_POISONED");assert!(inputs.poisoned);
    assert_eq!(inputs.pin.as_ref().unwrap().file().as_raw_fd(),held);
}
#[test]
#[ignore="requires explicit root /state protected SOFTWARE reader harness"]
fn malformed_original_record_is_retained_before_parser_refusal_and_cannot_retry() {
    let fixture=RootFixture::new(b"fixture pin".to_vec(),None);std::fs::write(&fixture.record,b"{}").unwrap();
    let mut inputs=fixture.inputs();let mut observed=Vec::new();
    denied(inputs.read_record(&scope(),&fixture.record,&mut observed),"BIRTH_RUNTIME_PIN_RECORD_SCHEMA");
    assert!(inputs.paths.is_some()&&inputs.record.is_some()&&inputs.selection.is_none()&&inputs.pin.is_none());
    assert_eq!(inputs.record_bytes,b"{}");let inode=inputs.record.as_ref().unwrap().file().metadata().unwrap().ino();
    denied(inputs.read_record(&scope(),&fixture.record,&mut observed),"BIRTH_RUNTIME_PIN_OWNER_POISONED");
    assert_eq!(inputs.record.as_ref().unwrap().file().metadata().unwrap().ino(),inode);
}
#[test]
#[ignore="requires explicit root /state protected SOFTWARE reader harness"]
fn successful_pickup_is_one_shot_and_keeps_both_originals_on_a_later_retry_refusal() {
    let fixture=RootFixture::new(b"fixture pin".to_vec(),None);let mut inputs=fixture.read();
    let record=inputs.record.as_ref().unwrap().file().as_raw_fd();let pin=inputs.pin.as_ref().unwrap().file().as_raw_fd();
    let mut observed=Vec::new();denied(inputs.read_pin(&mut observed),"BIRTH_RUNTIME_PIN_NO_RETRY");
    assert!(inputs.poisoned);assert_eq!(inputs.record.as_ref().unwrap().file().as_raw_fd(),record);
    assert_eq!(inputs.pin.as_ref().unwrap().file().as_raw_fd(),pin);assert_eq!(std::fs::read(&fixture.pin).unwrap(),fixture.bytes);
    denied(inputs.complete(&scope()),"BIRTH_RUNTIME_PIN_OWNER_POISONED");
}
#[test]
#[ignore="requires explicit root /state protected SOFTWARE reader harness"]
fn original_record_or_pin_mutation_and_identical_named_replacement_are_terminal_without_adoption() {
    for role in ["record","pin"] {for replacement in [false,true] {
        let fixture=RootFixture::new(b"fixture pin".to_vec(),None);let mut inputs=fixture.read();
        let path=if role=="record"{&fixture.record}else{&fixture.pin};let bytes=std::fs::read(path).unwrap();
        let original=if role=="record"{inputs.record.as_ref().unwrap()}else{inputs.pin.as_ref().unwrap()};
        let identity=(original.file().metadata().unwrap().ino(),original.file().as_raw_fd());let moved=path.with_extension("original");
        if replacement {std::fs::rename(path,&moved).unwrap();RootFixture::write(path,&bytes);}
        else {std::fs::write(path,b"mutated").unwrap();}
        let mut observed=Vec::new();assert!(inputs.finish(Ok(()),&mut observed).is_err());assert!(!observed.is_empty()&&inputs.poisoned);
        let original=if role=="record"{inputs.record.as_ref().unwrap()}else{inputs.pin.as_ref().unwrap()};
        assert_eq!((original.file().metadata().unwrap().ino(),original.file().as_raw_fd()),identity);
        if replacement {std::fs::remove_file(path).unwrap();std::fs::rename(&moved,path).unwrap();}else{std::fs::write(path,&bytes).unwrap();}
        denied(inputs.complete(&scope()),"BIRTH_RUNTIME_PIN_OWNER_POISONED");
    }}
}
#[test]
#[ignore="requires explicit root /state protected SOFTWARE reader harness"]
fn unsafe_pin_source_types_modes_bounds_and_aliases_preserve_original_record_and_partial_paths() {
    for variant in ["mode","symlink","hardlink","directory","fifo","empty","large","parent"] {
        let fixture=RootFixture::new(b"fixture pin".to_vec(),None);let mut inputs=fixture.inputs();let mut observed=Vec::new();
        inputs.read_record(&scope(),&fixture.record,&mut observed).unwrap();
        match variant {
            "mode"=>std::fs::set_permissions(&fixture.pin,std::fs::Permissions::from_mode(0o644)).unwrap(),
            "symlink"=>{std::fs::remove_file(&fixture.pin).unwrap();symlink(&fixture.record,&fixture.pin).unwrap();},
            "hardlink"=>std::fs::hard_link(&fixture.pin,fixture.base.join("alias")).unwrap(),
            "directory"=>{std::fs::remove_file(&fixture.pin).unwrap();std::fs::create_dir(&fixture.pin).unwrap();},
            "fifo"=>{std::fs::remove_file(&fixture.pin).unwrap();let name=CString::new(fixture.pin.as_os_str().as_bytes()).unwrap();
                assert_eq!(unsafe{libc::mkfifo(name.as_ptr(),0o600)},0);},
            "empty"=>std::fs::write(&fixture.pin,b"").unwrap(),"large"=>std::fs::write(&fixture.pin,vec![0;MAX_PIN_BYTES as usize+1]).unwrap(),
            _=>std::fs::set_permissions(&fixture.base,std::fs::Permissions::from_mode(0o777)).unwrap(),
        }
        assert!(inputs.read_pin(&mut observed).is_err());assert!(inputs.record.is_some()&&inputs.paths.is_some()&&inputs.poisoned);
        denied(inputs.read_pin(&mut observed),"BIRTH_RUNTIME_PIN_OWNER_POISONED");
    }
}
#[test]
#[ignore="requires explicit root /state protected SOFTWARE reader harness"]
fn original_birth_inode_identity_and_duplicate_source_roles_are_refused_even_without_path_aliases() {
    let fixture=RootFixture::new(b"fixture pin".to_vec(),None);let inputs=fixture.read();
    let pin=inputs.pin.as_ref().unwrap();let record=inputs.record.as_ref().unwrap();
    independent_inodes(&[record,pin],&BTreeSet::new()).unwrap();
    denied(independent_inodes(&[pin,pin],&BTreeSet::new()),"BIRTH_RUNTIME_PIN_SOURCE_ALIAS");
    let m=pin.file().metadata().unwrap();
    denied(independent_inodes(&[record,pin],&BTreeSet::from([(m.dev(),m.ino())])),"BIRTH_RUNTIME_PIN_SOURCE_ALIAS");
}
#[test]
#[ignore="requires explicit root /state protected SOFTWARE reader harness"]
fn bounded_same_fd_reader_refuses_original_growth_truncation_and_descriptor_flag_drift() {
    for variant in ["growth","truncate","flags"] {
        let fixture=RootFixture::new(b"fixture pin".to_vec(),None);let mut inputs=fixture.read();
        let held=inputs.pin.as_ref().unwrap();let fd=held.file().as_raw_fd();let old_flags=unsafe{libc::fcntl(fd,libc::F_GETFD)};
        match variant {"growth"=>std::fs::write(&fixture.pin,b"fixture pin grew").unwrap(),
            "truncate"=>std::fs::write(&fixture.pin,b"x").unwrap(),_=>{assert!(old_flags>=0);
                assert_eq!(unsafe{libc::fcntl(fd,libc::F_SETFD,old_flags&!libc::FD_CLOEXEC)},0);}}
        let mut observed=Vec::new();assert!(same_fd_pin_bytes(inputs.paths.as_ref().unwrap(),held,&mut observed).is_err());
        assert!(!observed.is_empty());assert!(inputs.finish(Ok(()),&mut observed).is_err());assert!(inputs.poisoned);
        if variant=="flags"{assert_eq!(unsafe{libc::fcntl(fd,libc::F_SETFD,old_flags)},0);}
        denied(inputs.complete(&scope()),"BIRTH_RUNTIME_PIN_OWNER_POISONED");
    }
}
#[cfg(target_os="macos")]
#[test]
#[ignore="requires actual macOS root /state ACL fixture; no native payload/candidate wrapper is fabricated"]
fn native_extended_acl_on_record_pin_or_source_parent_is_terminal_and_never_repaired() {
    use crate::native_fs::acl_fixture;
    for role in ["record","pin","parent"] {
        let fixture=RootFixture::new(b"fixture pin".to_vec(),None);let mut inputs=fixture.read();
        let directory=OpenOptions::new().read(true).custom_flags(libc::O_DIRECTORY|libc::O_NOFOLLOW|libc::O_CLOEXEC)
            .open(&fixture.base).unwrap();
        let held=match role {"record"=>inputs.record.as_ref().unwrap().file(),"pin"=>inputs.pin.as_ref().unwrap().file(),_=>&directory};
        acl_fixture::set_allow(held);let mut observed=Vec::new();assert!(inputs.finish(Ok(()),&mut observed).is_err());
        let held=match role {"record"=>inputs.record.as_ref().unwrap().file(),"pin"=>inputs.pin.as_ref().unwrap().file(),_=>&directory};
        acl_fixture::set_empty(held);denied(inputs.complete(&scope()),"BIRTH_RUNTIME_PIN_OWNER_POISONED");
    }
}
