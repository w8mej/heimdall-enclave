//! Private plan/creator SOFTWARE fixtures only. No native birth, checked target,
//! account/SoftwareApproval, startup EX or activity authority is fabricated.
//! Source files are original readonly engine files; payload remains behind700.
use super::*;
use serde_json::{json,Value};
use std::{cell::Cell,os::unix::fs::{PermissionsExt,symlink},sync::Mutex};
static SERIAL:Mutex<()>=Mutex::new(());
fn encoded(value:Value)->Vec<u8>{serde_json::to_vec(&value).unwrap()}
fn sync(file:&File)->EnclaveResult<()>{file.sync_all().map_err(|_|err!(EIO,"PAYLOAD_FIXTURE_SYNC"))}
fn template()->DeploymentTarget {
    DeploymentTarget::parse(&encoded(json!({"version":1,"target_id":"payload-fixture","role":"dedicated-test","profile":"L2",
        "signing_identity_mode":"local-pins","authority_config":"/template/support/custody.json",
        "expected_artifacts_manifest":"/template/config/inventory.json","codesign_pins_file":"/template/support/pins.json",
        "broker":null,"shared_read_only_inputs":[],"layout":{"binary_dir":"/template/bin","custody_bundle":"/template/support/Custody.app",
            "sandbox_dir":"/template/sandbox","socket_root":"/template/run","state_root":"/template/state","audit_root":"/template/audit",
            "cas_store_root":"/template/cas","staging_root":"/template/stage","support_root":"/template/support",
            "launchd_namespace":"com.mcpmac.payloadfixture","mach_service":"com.mcpmac.payloadfixture.exception"}}))).unwrap()
}
fn inventory(plan:&BirthPlan,payloads:&BTreeMap<PathBuf,Vec<u8>>)->Vec<u8> {
    let pins=&payloads[Path::new("codesign-pins.json")];
    let files=payloads.iter().map(|(path,bytes)|json!({"path":path,"sha256":hex::encode(Sha256::digest(bytes)),"size":bytes.len()})).collect::<Vec<_>>();
    encoded(json!({"version":1,"kind":"mcpmac-first-touch-artifact-inventory","target_id":plan.target.target_id,"profile":"L2",
        "signing_identity_mode":"local-pins","deployment_config_sha256":hex::encode(Sha256::digest(&plan.bytes)),
        "source_git_commit":"a".repeat(40),"source_manifest_sha256":"b".repeat(64),"source_input_count":payloads.len(),
        "codesign_pins_sha256":hex::encode(Sha256::digest(pins)),"staging_root":plan.target.layout.staging_root,
        "external_provenance":"UNKNOWN","files":files}))
}
struct Fixture {anchor:PathBuf,state:BirthState,approved:TargetInstallPlan}
impl Fixture {
    fn new()->Self {
        let anchor=std::env::current_dir().unwrap().join(format!(".birth-payload-{}",hex::encode(enclave_core::rng::bytes32())));
        std::fs::create_dir(&anchor).unwrap();std::fs::set_permissions(&anchor,std::fs::Permissions::from_mode(0o700)).unwrap();
        let original=BirthPlan::build(&template(),Path::new("/template"),Path::new("/birth-payload"),&[0x46;16]).unwrap();
        let root=anchor.join(original.root.file_name().unwrap());let map=|path:&Path|root.join(path.strip_prefix(&original.root).unwrap());
        let raw=String::from_utf8(original.bytes.clone()).unwrap().replace(original.root.to_str().unwrap(),root.to_str().unwrap()).into_bytes();
        let plan=BirthPlan {root:root.clone(),target:DeploymentTarget::parse(&raw).unwrap(),descriptor:map(&original.descriptor),bytes:raw,
            seed_dirs:original.seed_dirs.iter().map(|path|map(path)).collect()};
        let protection=Protection {owner:(unsafe{libc::geteuid()},unsafe{libc::getegid()}),native_acl:false};
        let name=CString::new(anchor.as_os_str().as_bytes()).unwrap();
        let fd=unsafe{libc::open(name.as_ptr(),libc::O_RDONLY|libc::O_DIRECTORY|libc::O_NOFOLLOW|libc::O_NONBLOCK|libc::O_CLOEXEC)};
        assert!(fd>=0);let directory=Directory::capture(unsafe{File::from_raw_fd(fd)},None,false,protection).unwrap();
        let mut progress=BirthProgress::new();progress.root=Some(root.clone());progress.descriptor=Some(plan.descriptor.clone());progress.target_id=Some(plan.target.target_id.clone());
        let mut state=BirthState {plan,dirs:BTreeMap::from([(anchor.clone(),directory)]),files:BTreeMap::new(),protection,
            progress,poisoned:false,pending:None,private_load:None};
        state.create_directory(&root,&mut||Vec::new(),&mut Vec::new(),&mut sync).unwrap();state.prepare_seeds(&mut||Vec::new(),&mut sync).unwrap();
        let large=(0..(2*64*1024+37)).map(|i|(i%251)as u8).collect::<Vec<_>>();
        let mut payloads=BTreeMap::from([(PathBuf::from("bin/mcp-enclave"),large),(PathBuf::from("codesign-pins.json"),b"unadmitted fixture pins".to_vec())]);
        let first=target_plan::describe(&state.plan.target,&hex::encode(Sha256::digest(&state.plan.bytes)),&inventory(&state.plan,&payloads)).unwrap();
        for name in first.missing_required_files {payloads.insert(name.into(),b"unadmitted public SOFTWARE bytes".to_vec());}
        let raw=inventory(&state.plan,&payloads);let approved=target_plan::describe(&state.plan.target,
            &hex::encode(Sha256::digest(&state.plan.bytes)),&raw).unwrap();assert!(approved.missing_required_files.is_empty());
        state.prepare_denial(&raw,&mut||Vec::new(),&mut sync).unwrap();let inventory_path=state.plan.target.expected_artifacts_manifest.clone();
        state.create_file(&inventory_path,&raw,0o644,&mut||Vec::new(),&mut Vec::new(),&mut sync).unwrap();
        // Complete inert ORIGINAL controls for the real closed role parser;
        // no protected load, signature authority or native owner is invented.
        let support=&state.plan.target.layout.support_root;let public=support.join("public");
        let manifest=encoded(json!({"v":1,"profile":"L2","asset_policy_file":public.join("policy.json"),
            "asset_policy_key_file":public.join("policy.key"),"asset_inventory_key_file":public.join("inventory.key"),
            "envelope_policy_key_file":public.join("envelope.key"),"asset_host_id":"software-host",
            "asset_id":"software-asset","asset_custodian_id":"software-custodian",
            "envelope_policy_subject":"software-host","envelope_policy_namespace":"software-fixture"}));
        let controls=vec![(state.plan.target.authority_config.clone(),manifest),(public.join("policy.json"),b"{}".to_vec()),
            (public.join("policy.key"),"01".repeat(32).into_bytes()),(public.join("inventory.key"),"02".repeat(32).into_bytes()),
            (public.join("envelope.key"),"03".repeat(32).into_bytes()),
            (state.plan.target.codesign_pins_file.clone(),payloads[Path::new("codesign-pins.json")].clone())];
        state.create_directory(&public,&mut||Vec::new(),&mut Vec::new(),&mut sync).unwrap();
        for (path,bytes) in controls {state.create_file(&path,&bytes,0o644,&mut||Vec::new(),&mut Vec::new(),&mut sync).unwrap();}
        let staging=state.plan.target.layout.staging_root.clone();let mut directories=BTreeSet::new();
        for relative in payloads.keys(){let mut parent=staging.join(relative).parent().unwrap().to_owned();while parent!=staging {
            directories.insert(parent.clone());parent=parent.parent().unwrap().to_owned();}}
        let mut directories=directories.into_iter().collect::<Vec<_>>();directories.sort_by_key(|p|(p.components().count(),p.clone()));
        for directory in directories {state.create_directory(&directory,&mut||Vec::new(),&mut Vec::new(),&mut sync).unwrap();}
        for (relative,bytes) in payloads {
            let path=staging.join(relative);state.create_file(&path,&bytes,0o600,&mut||Vec::new(),&mut Vec::new(),&mut sync).unwrap();
            if path==staging.join("codesign-pins.json"){continue;}
            // Synthetic content tag, retaining actual original readonly inode,
            // exactly matches production staging's bounded digest storage.
            let seed=state.files.get_mut(&path).unwrap();seed.bytes.clear();seed.streamed=Some(StreamedContent {
                length:bytes.len()as u64,sha256:hex::encode(Sha256::digest(bytes))});
        }
        Self {anchor,state,approved}
    }
    fn plan(&self)->EnclaveResult<PrivatePayloadPlan>{PrivatePayloadPlan::build(&self.state,&self.approved)}
    fn directories(&mut self,plan:&PrivatePayloadPlan){for path in &plan.directories {if !self.state.dirs.contains_key(path){
        self.state.create_directory(path,&mut||Vec::new(),&mut Vec::new(),&mut sync).unwrap();}}}
    fn refresh_injected_links(&mut self){for directory in self.state.dirs.values_mut(){directory.links=directory.file.metadata().unwrap().nlink();}}
}
impl Drop for Fixture {fn drop(&mut self){let _=std::fs::remove_dir_all(&self.anchor);}}
fn no_authority(state:&BirthState){assert!(!state.progress.inactivity_proven&&!state.progress.mutation_allowed&&!state.progress.activation_allowed
    &&!state.progress.installation_supported&&!state.progress.qualified);}

#[test]
fn actual_complete_plan_closes_payload_subset_without_jobs_pins_runtime_or_visibility() {
    let _serial=SERIAL.lock().unwrap_or_else(std::sync::PoisonError::into_inner);let f=Fixture::new();let before=f.state.progress.attempted.clone();
    let plan=f.plan().unwrap();plan.assert_absent(&f.state).unwrap();assert!(!plan.copies.is_empty());
    for copy in &plan.copies {assert!(copy.destination.starts_with(&f.state.plan.root));assert_ne!(copy.destination,f.approved.selected_pins_file);
        assert!(!copy.destination.starts_with("/Library"));assert!(matches!(copy.mode,0o644|0o755));}
    assert!(f.approved.copies.iter().any(|copy|copy.destination.starts_with("/Library/LaunchDaemons")));
    assert_eq!(before,f.state.progress.attempted);assert!(f.state.private_load.is_none());private_ancestry(&f.state).unwrap();no_authority(&f.state);
}
#[test]
fn closed_public_controls_keep_all_staged_code_private_and_unknown_originals_refuse() {
    let _serial=SERIAL.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    {
        let f=Fixture::new();let controls=crate::deploy::target_birth::admit::original_modes(&f.state).unwrap();
        assert_eq!(controls.len(),11);let staging=&f.state.plan.target.layout.staging_root;
        let denial=f.state.plan.target.layout.support_root.join(UPGRADE_INHIBITION_LEAF);
        for (path,seed) in &f.state.files {
            let expected=if path.starts_with(staging)||path==&denial {0o600}else{0o644};
            assert_eq!(seed.file.metadata().unwrap().mode()&0o7777,expected);assert_eq!(seed.access,libc::O_RDONLY);
            if !controls.contains_key(path){assert!(path.starts_with(staging));assert!(seed.streamed.is_some());}
        }
        let staged=&f.state.files[&staging.join("codesign-pins.json")];
        let selected=&f.state.files[&f.state.plan.target.codesign_pins_file];
        assert_eq!(staged.bytes,selected.bytes);
        assert_ne!((staged.stamp.directory.dev,staged.stamp.directory.ino),(selected.stamp.directory.dev,selected.stamp.directory.ino));
        let before=f.state.files.iter().map(|(p,s)|(p.clone(),FileStamp::of(&s.file.metadata().unwrap()),s.file.as_raw_fd())).collect::<Vec<_>>();
        f.plan().unwrap();
        for (path,stamp,fd) in before {let seed=&f.state.files[&path];assert!(seed.stamp==stamp);assert_eq!(seed.file.as_raw_fd(),fd);}
        private_ancestry(&f.state).unwrap();no_authority(&f.state);
    }
    for mode in [0o600,0o644] {
        let mut f=Fixture::new();let unknown=f.state.plan.root.join("unknown-original");
        f.state.create_file(&unknown,b"not a closed control or staged source",mode,&mut||Vec::new(),&mut Vec::new(),&mut sync).unwrap();
        let before=f.state.progress.attempted.clone();let error=f.plan().err().expect("unknown original must refuse");
        assert!(error.is("BIRTH_PAYLOAD_UNPUBLISHED_ORIGINALS_REQUIRED"));assert_eq!(before,f.state.progress.attempted);
        assert_eq!(f.state.files[&unknown].file.metadata().unwrap().mode()&0o7777,mode);no_authority(&f.state);
    }
}
#[test]
fn pure_file_directory_aliases_and_combined_node_budget_refuse_before_effects() {
    let _serial=SERIAL.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    for variant in ["planned-case","cached-case","ancestor","nodes","mode","visibility"] {
        let mut f=Fixture::new();
        match variant {
            "planned-case"=>{let root=f.state.plan.root.join("Payload");f.approved.copies[0].destination=root.join("Keys/a");f.approved.copies[1].destination=root.join("keys/b");},
            "cached-case"=>{let directory=f.state.plan.root.join("BIN");f.state.create_directory(&directory,&mut||Vec::new(),&mut Vec::new(),&mut sync).unwrap();},
            "ancestor"=>{f.approved.copies[0].destination=f.state.plan.root.join("x");f.approved.copies[1].destination=f.state.plan.root.join("x/y");},
            "nodes"=>{let original=f.state.dirs.values().next().unwrap();let file=original.file.try_clone().unwrap();let stamp=original.stamp.clone();let links=original.links;
                while f.state.dirs.len()<MAX_NODES {let path=f.anchor.join(format!("synthetic{}",f.state.dirs.len()));f.state.dirs.insert(path,
                    Directory {file:file.try_clone().unwrap(),parent:None,stamp:stamp.clone(),links,private:true});}},
            "mode"=>{let path=f.state.plan.target.layout.staging_root.join("bin/mcp-enclave");f.state.files.get_mut(&path).unwrap().access=libc::O_RDWR;},
            _=>f.state.dirs.get_mut(&f.state.plan.root).unwrap().private=false,
        }
        let before=f.state.progress.attempted.clone();assert!(f.plan().is_err(),"{variant}");assert_eq!(before,f.state.progress.attempted);
    }
}
#[test]
fn original_source_to_new_payload_retains_both_inodes_bytes_and_private_ancestry() {
    let _serial=SERIAL.lock().unwrap_or_else(std::sync::PoisonError::into_inner);let mut f=Fixture::new();let plan=f.plan().unwrap();plan.assert_absent(&f.state).unwrap();
    let originals=f.state.files.iter().map(|(p,s)|(p.clone(),s.stamp.directory.ino)).collect::<Vec<_>>();f.directories(&plan);
    for copy in &plan.copies {f.state.create_file_from_birth_stage(&copy.source,&copy.destination,copy.size,&copy.sha256,copy.mode,
        &mut||Vec::new(),&mut Vec::new(),&mut sync).unwrap();}
    plan.assert_prepared(&f.state).unwrap();for (path,inode)in originals {assert_eq!(f.state.files[&path].stamp.directory.ino,inode);}
    for copy in &plan.copies {let source=&f.state.files[&copy.source];let destination=&f.state.files[&copy.destination];
        assert_ne!((source.stamp.directory.dev,source.stamp.directory.ino),(destination.stamp.directory.dev,destination.stamp.directory.ino));
        assert_eq!(std::fs::read(&copy.source).unwrap(),std::fs::read(&copy.destination).unwrap());assert_eq!(destination.access,libc::O_RDONLY);
        assert_eq!(destination.file.metadata().unwrap().mode()&0o7777,copy.mode);assert_eq!(destination.file.metadata().unwrap().nlink(),1);}
    private_ancestry(&f.state).unwrap();f.state.revalidate(&mut||Vec::new()).unwrap();no_authority(&f.state);
    for root in runtime_roots(&f.state){assert!(!root.exists());}
    // A later phase may create ONLY its own runtime name. The pristine-entry
    // check must now refuse, while exact original payload checks still work.
    let runtime=f.state.plan.target.layout.state_root.clone();
    f.state.create_directory(&runtime,&mut||Vec::new(),&mut Vec::new(),&mut sync).unwrap();
    assert!(plan.assert_prepared(&f.state).is_err());
    plan.assert_private_contents(&f.state).unwrap();
    f.state.revalidate(&mut||Vec::new()).unwrap();
    let changed=&plan.copies[0].destination;let original=f.state.files[changed].stamp.directory.ino;
    std::fs::write(changed,b"changed original payload bytes").unwrap();
    assert_eq!(std::fs::metadata(changed).unwrap().ino(),original);
    assert!(plan.assert_private_contents(&f.state).is_err());no_authority(&f.state);
}
#[test]
fn foreign_leaf_and_unowned_parent_or_runtime_names_are_never_adopted_or_repaired() {
    let _serial=SERIAL.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    for kind in ["file","symlink","fifo","directory","runtime"] {
        let mut f=Fixture::new();let plan=f.plan().unwrap();let path=if kind=="runtime"{f.state.plan.target.layout.state_root.clone()}
            else{plan.directories.iter().find(|p|!f.state.dirs.contains_key(*p)).unwrap().clone()};
        match kind {"file"=>std::fs::write(&path,b"foreign").unwrap(),"symlink"=>symlink("/nonexistent-payload-fixture",&path).unwrap(),
            "fifo"=>{let name=CString::new(path.as_os_str().as_bytes()).unwrap();assert_eq!(unsafe{libc::mkfifo(name.as_ptr(),0o600)},0);},
            _=>std::fs::create_dir(&path).unwrap(),}
        f.refresh_injected_links();let before=std::fs::symlink_metadata(&path).unwrap();assert!(plan.assert_absent(&f.state).is_err());
        let after=std::fs::symlink_metadata(&path).unwrap();assert_eq!((before.dev(),before.ino(),before.mode(),before.len()),(after.dev(),after.ino(),after.mode(),after.len()));
        assert!(!f.state.dirs.contains_key(&path)&&!f.state.files.contains_key(&path));
    }
}
#[test]
fn guard_or_source_loss_midstream_retains_private_partial_name_and_original_source() {
    let _serial=SERIAL.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    for variant in ["before-write","guard-midstream","source-midstream"] {
        let mut f=Fixture::new();let plan=f.plan().unwrap();f.directories(&plan);let copy=plan.copies.iter().find(|c|c.source.ends_with("bin/mcp-enclave")).unwrap();
        let source_inode=f.state.files[&copy.source].stamp.directory.ino;let lost=Cell::new(false);let original=std::fs::read(&copy.source).unwrap();let mut observed=Vec::new();
        let result=f.state.create_file_from_birth_stage(&copy.source,&copy.destination,copy.size,&copy.sha256,copy.mode,&mut|| {
            let length=std::fs::metadata(&copy.destination).ok().map(|m|m.len());
            let trip=if variant=="before-write"{length.is_some()}else{length.is_some_and(|n|n>=64*1024)};
            if trip&&!lost.get(){lost.set(true);if variant=="source-midstream"{let mut changed=original.clone();changed[0]^=1;std::fs::write(&copy.source,changed).unwrap();}}
            if lost.get()&&variant!="source-midstream"{vec![err!(EACCES,"FIXTURE_PAYLOAD_GUARD_LOST")]}else{Vec::new()}
        },&mut observed,&mut sync);
        assert!(result.is_err()&&lost.get());let length=std::fs::metadata(&copy.destination).unwrap().len();
        assert_eq!(length,if variant=="before-write"{0}else{64*1024});assert_eq!(f.state.files[&copy.source].stamp.directory.ino,source_inode);
        private_ancestry(&f.state).unwrap();if variant!="source-midstream"{assert_eq!(std::fs::read(&copy.source).unwrap(),original);assert!(!observed.is_empty());}
        no_authority(&f.state);
    }
}
#[test]
fn wrong_digest_and_sync_failure_preserve_source_and_never_claim_complete_payload() {
    let _serial=SERIAL.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    for variant in ["digest","sync"] {
        let mut f=Fixture::new();let plan=f.plan().unwrap();f.directories(&plan);let copy=plan.copies.iter().find(|c|c.source.ends_with("bin/mcp-enclave")).unwrap();
        let original=std::fs::read(&copy.source).unwrap();let mut observed=Vec::new();let wrong_digest="00".repeat(32);
        let result=f.state.create_file_from_birth_stage(&copy.source,&copy.destination,copy.size,
            if variant=="digest"{wrong_digest.as_str()}else{copy.sha256.as_str()},copy.mode,&mut||Vec::new(),&mut observed,&mut|file|{
                if variant=="sync"&&file.metadata().unwrap().is_file(){Err(err!(EIO,"FIXTURE_PAYLOAD_SYNC_FAIL"))}else{sync(file)}
            });
        assert!(result.is_err());assert_eq!(std::fs::read(&copy.source).unwrap(),original);
        if variant=="digest"{assert!(!copy.destination.exists());}else{assert!(copy.destination.exists());}
        assert!(plan.assert_prepared(&f.state).is_err());private_ancestry(&f.state).unwrap();no_authority(&f.state);
    }
}
