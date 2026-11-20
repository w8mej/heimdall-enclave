//! SOFTWARE original-engine fixtures only. No NativeDedicatedBirth, native
//! ACL/host guard, checked target, approval, source owner or installed state.
//! The pre-seal fixture uses the real private O_EXCL creator, then retains its
//! original writer to exercise the production readonly transition directly.
use super::*;
use std::{cell::{Cell,RefCell},os::unix::fs::PermissionsExt};
use serde_json::json;

fn sync(file:&File)->EnclaveResult<()> {file.sync_all().map_err(|_|err!(EIO,"FIXTURE_READONLY_SYNC"))}
fn template()->DeploymentTarget {
    DeploymentTarget::parse(&serde_json::to_vec(&json!({"version":1,"target_id":"readonly-fixture",
        "role":"dedicated-test","profile":"L2","signing_identity_mode":"local-pins",
        "authority_config":"/template/support/custody.json","expected_artifacts_manifest":"/template/config/inventory.json",
        "codesign_pins_file":"/template/support/pins.json","broker":null,"shared_read_only_inputs":[],
        "layout":{"binary_dir":"/template/bin","custody_bundle":"/template/support/Custody.app",
            "sandbox_dir":"/template/sandbox","socket_root":"/template/run","state_root":"/template/state",
            "audit_root":"/template/audit","cas_store_root":"/template/cas","staging_root":"/template/stage",
            "support_root":"/template/support","launchd_namespace":"com.depot.readonlyfixture",
            "mach_service":"com.depot.readonlyfixture.exception"}})).unwrap()).unwrap()
}
fn no_authority(progress:&BirthProgress) {
    assert!(!progress.mutation_allowed&&!progress.inactivity_proven&&!progress.activation_allowed
        &&!progress.installation_supported&&!progress.qualified);
}
fn refused(result:EnclaveResult<()>,reason:&str) {
    let error=result.unwrap_err();assert!(error.is(reason),"{} != {reason}",error.reason);
}
fn readonly(seed:&SeedFile) {
    assert_eq!(seed.access,libc::O_RDONLY);flags(&seed.file,libc::O_RDONLY).unwrap();
    let error=seed.file.write_at(b"must never write",0).unwrap_err();
    assert_eq!(error.raw_os_error(),Some(libc::EBADF));
}
fn original_writer_held(fd:i32,identity:(u64,u64))->bool {
    // Another parallel fixture can reuse a closed fd number. Match the actual
    // original inode AND write access, never infer ownership from the number.
    let mut raw=std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe{libc::fstat(fd,raw.as_mut_ptr())}!=0{return false;}
    let raw=unsafe{raw.assume_init()};let status=unsafe{libc::fcntl(fd,libc::F_GETFL)};
    (raw.st_dev as u64,raw.st_ino as u64)==identity&&status>=0&&status&libc::O_ACCMODE==libc::O_RDWR
}

struct Fixture {anchor:PathBuf,state:BirthState}
impl Fixture {
    fn new()->Self {
        let anchor=std::env::current_dir().unwrap().join(format!(".birth-readonly-{}",hex::encode(enclave_core::rng::bytes32())));
        std::fs::create_dir(&anchor).unwrap();
        std::fs::set_permissions(&anchor,std::fs::Permissions::from_mode(0o700)).unwrap();
        let original=BirthPlan::build(&template(),Path::new("/template"),Path::new("/birth-readonly"),&[0x61;16]).unwrap();
        let root=anchor.join(original.root.file_name().unwrap());
        let map=|p:&Path|root.join(p.strip_prefix(&original.root).unwrap());
        // Private test rebase avoids claiming native socket-qualified birth.
        let raw=String::from_utf8(original.bytes.clone()).unwrap()
            .replace(original.root.to_str().unwrap(),root.to_str().unwrap()).into_bytes();
        let plan=BirthPlan {root:root.clone(),target:DeploymentTarget::parse(&raw).unwrap(),
            descriptor:map(&original.descriptor),bytes:raw,seed_dirs:original.seed_dirs.iter().map(|p|map(p)).collect()};
        let protection=Protection {owner:(unsafe{libc::geteuid()},unsafe{libc::getegid()}),native_acl:false};
        let path=CString::new(anchor.as_os_str().as_bytes()).unwrap();
        let fd=unsafe{libc::open(path.as_ptr(),libc::O_RDONLY|libc::O_DIRECTORY|libc::O_NOFOLLOW|libc::O_NONBLOCK|libc::O_CLOEXEC)};
        assert!(fd>=0);let directory=Directory::capture(unsafe{File::from_raw_fd(fd)},None,false,protection).unwrap();
        let mut progress=BirthProgress::new();progress.root=Some(root.clone());
        progress.descriptor=Some(plan.descriptor.clone());progress.target_id=Some(plan.target.target_id.clone());
        let mut state=BirthState {plan,dirs:BTreeMap::from([(anchor.clone(),directory)]),files:BTreeMap::new(),
            protection,progress,poisoned:false,pending:None,private_load:None};
        state.create_directory(&root,&mut||Vec::new(),&mut Vec::new(),&mut sync).unwrap();
        state.prepare_seeds(&mut||Vec::new(),&mut sync).unwrap();Self {anchor,state}
    }
    fn path(&self,leaf:&str)->PathBuf {self.state.plan.target.layout.staging_root.join(leaf)}
    fn unsealed(&mut self,leaf:&str,payload:&[u8],streamed:bool)->PathBuf {
        let path=self.path(leaf);
        let mut created=self.state.begin_file(&path,0o600,libc::O_RDWR,false,&mut||Vec::new(),&mut Vec::new()).unwrap();
        created.file.write_all(payload).unwrap();
        self.state.active_boundary(Ok(()),&created,payload.len()as u64,false,
            &mut||Vec::new(),&mut Vec::new()).unwrap();
        let stamp=FileStamp::of(&created.file.metadata().unwrap());
        created.file.sync_all().unwrap();self.state.dirs[&created.parent].file.sync_all().unwrap();
        let content=streamed.then(||StreamedContent {length:payload.len()as u64,sha256:hex::encode(Sha256::digest(payload))});
        let seed=SeedFile {file:created.file,stamp,bytes:if streamed{Vec::new()}else{payload.to_vec()},
            access:libc::O_RDWR,streamed:content};
        self.state.files.insert(path.clone(),seed);path
    }
    fn seal(&mut self,path:&Path,full:bool)->EnclaveResult<()> {
        self.state.seal_file_readonly(path,full,&mut||Vec::new(),&mut Vec::new())
    }
}
impl Drop for Fixture {fn drop(&mut self){let _=std::fs::remove_dir_all(&self.anchor);}}

#[test]
fn common_finish_seals_exact_content_after_file_parent_sync_without_metadata_changes() {
    let mut f=Fixture::new();let path=f.path("exact.bin");let before=RefCell::new(None);let order=RefCell::new(Vec::new());
    f.state.create_file(&path,b"completed public input",0o600,&mut||Vec::new(),&mut Vec::new(),&mut|file| {
        let m=file.metadata().unwrap();order.borrow_mut().push(m.is_file());
        if m.is_file(){*before.borrow_mut()=Some((file.as_raw_fd(),FileStamp::of(&m)));}
        sync(file)
    }).unwrap();
    let seed=&f.state.files[&path];readonly(seed);
    let (writer,stamp)=before.into_inner().unwrap();assert_ne!(writer,seed.file.as_raw_fd());
    assert!(!original_writer_held(writer,(stamp.directory.dev,stamp.directory.ino)),"original writer must be closed");
    assert!(stamp==FileStamp::of(&seed.file.metadata().unwrap()));
    assert_eq!(order.into_inner(),vec![true,false]);assert_eq!(std::fs::read(&path).unwrap(),b"completed public input");
    assert_eq!(seed.file.metadata().unwrap().mode()&0o7777,0o600);
    f.state.revalidate(&mut||Vec::new()).unwrap();no_authority(&f.state.progress);
}

#[test]
fn already_readonly_empty_lifetime_is_a_checked_noop_and_every_completed_seed_is_readonly() {
    let mut f=Fixture::new();let path=f.state.plan.target.layout.support_root.join(STARTUP_LIFETIME_LEAF);
    let fd=f.state.files[&path].file.as_raw_fd();let stamp=FileStamp::of(&f.state.files[&path].file.metadata().unwrap());
    f.seal(&path,true).unwrap();let lease=&f.state.files[&path];
    assert_eq!(fd,lease.file.as_raw_fd());assert!(stamp==FileStamp::of(&lease.file.metadata().unwrap()));
    assert_eq!(lease.file.metadata().unwrap().mode()&0o7777,0o644);assert!(lease.bytes.is_empty());
    for seed in f.state.files.values(){readonly(seed);}
    no_authority(&f.state.progress);
}

#[test]
fn streamed_readonly_transition_retains_same_original_stamp_digest_and_empty_cache_sentinel() {
    let mut f=Fixture::new();let payload=(0..(2*64*1024+37)).map(|i|(i%251)as u8).collect::<Vec<_>>();
    let path=f.unsealed("stream.bin",&payload,true);let writer=f.state.files[&path].file.as_raw_fd();
    let stamp=FileStamp::of(&f.state.files[&path].file.metadata().unwrap());
    f.seal(&path,false).unwrap();let seed=&f.state.files[&path];readonly(seed);
    assert_ne!(seed.file.as_raw_fd(),writer);
    assert!(!original_writer_held(writer,(stamp.directory.dev,stamp.directory.ino)));
    assert!(stamp==FileStamp::of(&seed.file.metadata().unwrap()));
    assert!(seed.bytes.is_empty()&&seed.exact_bytes().is_none());
    assert_eq!(file_sha256(&seed.file,payload.len()as u64).unwrap(),hex::encode(Sha256::digest(&payload)));
    assert_eq!(std::fs::read(&path).unwrap(),payload);no_authority(&f.state.progress);
}

#[test]
fn guard_refusal_before_transition_preserves_original_writer_names_and_all_final_errors() {
    let mut f=Fixture::new();let path=f.unsealed("before.bin",b"original public bytes",false);
    let writer=f.state.files[&path].file.as_raw_fd();let mut observed=Vec::new();let calls=Cell::new(0);
    refused(f.state.seal_file_readonly(&path,true,&mut|| {
        calls.set(calls.get()+1);vec![err!(ESTALE,"FIXTURE_READONLY_GUARD_BEFORE")]
    },&mut observed),"FIXTURE_READONLY_GUARD_BEFORE");
    assert!(calls.get()>=6);assert!(observed.iter().filter(|e|e.is("FIXTURE_READONLY_GUARD_BEFORE")).count()>=6);
    assert_eq!(f.state.files[&path].file.as_raw_fd(),writer);assert_eq!(f.state.files[&path].access,libc::O_RDWR);
    assert!(f.state.poisoned);assert_eq!(std::fs::read(&path).unwrap(),b"original public bytes");
    assert!(f.state.revalidate(&mut||Vec::new()).unwrap_err().error.is("BIRTH_OWNER_POISONED"));
}

#[test]
fn after_swap_guard_refusal_retains_readonly_original_and_never_restores_writer() {
    let mut f=Fixture::new();let path=f.unsealed("after.bin",b"original public bytes",false);
    let writer=f.state.files[&path].file.as_raw_fd();let lost=Cell::new(false);let mut observed=Vec::new();
    let m=f.state.files[&path].file.metadata().unwrap();let identity=(m.dev(),m.ino());
    refused(f.state.seal_file_readonly(&path,true,&mut|| {
        // Test observes closure of the actual original writer, without a dup
        // or candidate-FD injection into the production interface.
        if !original_writer_held(writer,identity) {lost.set(true);}
        if lost.get(){vec![err!(ESTALE,"FIXTURE_READONLY_GUARD_AFTER")]}else{Vec::new()}
    },&mut observed),"FIXTURE_READONLY_GUARD_AFTER");
    assert!(lost.get());readonly(&f.state.files[&path]);assert!(f.state.poisoned);
    assert!(observed.iter().filter(|e|e.is("FIXTURE_READONLY_GUARD_AFTER")).count()>=4);
    assert_eq!(std::fs::read(&path).unwrap(),b"original public bytes");
    refused(f.seal(&path,true),"BIRTH_OWNER_POISONED");readonly(&f.state.files[&path]);
}

#[test]
fn same_byte_foreign_replacement_is_never_adopted_and_original_writer_survives_refusal() {
    let mut f=Fixture::new();let path=f.unsealed("replaced.bin",b"same bytes",false);
    let writer=f.state.files[&path].file.as_raw_fd();let original=f.state.files[&path].file.metadata().unwrap();
    std::fs::rename(&path,path.with_extension("original")).unwrap();std::fs::write(&path,b"same bytes").unwrap();
    std::fs::set_permissions(&path,std::fs::Permissions::from_mode(0o600)).unwrap();
    let foreign=std::fs::symlink_metadata(&path).unwrap();assert_ne!((original.dev(),original.ino()),(foreign.dev(),foreign.ino()));
    let mut observed=Vec::new();assert!(f.state.seal_file_readonly(&path,true,&mut||Vec::new(),&mut observed).is_err());
    assert!(observed.iter().any(|e|e.is("BIRTH_SEED_CHANGED")));assert!(f.state.poisoned);
    assert_eq!(f.state.files[&path].file.as_raw_fd(),writer);assert_eq!(f.state.files[&path].access,libc::O_RDWR);
    let after=std::fs::symlink_metadata(&path).unwrap();
    assert_eq!((foreign.dev(),foreign.ino(),foreign.mode(),foreign.len()),(after.dev(),after.ino(),after.mode(),after.len()));
}

#[test]
fn current_stream_full_digest_gate_refuses_corruption_even_in_metadata_transition_mode() {
    let mut f=Fixture::new();let path=f.unsealed("changed-stream.bin",&vec![0x51;64*1024+1],true);
    let writer=f.state.files[&path].file.as_raw_fd();std::fs::write(&path,vec![0x52;64*1024+1]).unwrap();
    // Test-only stable-metadata simulation isolates digest enforcement;
    // production has no stamp refresh/adoption or digest expectation reset.
    let seed=f.state.files.get_mut(&path).unwrap();seed.stamp=FileStamp::of(&seed.file.metadata().unwrap());
    assert!(f.state.metadata_checks(&mut||Vec::new()).is_empty());
    refused(f.seal(&path,false),"BIRTH_STREAM_DIGEST_CHANGED");
    assert_eq!(f.state.files[&path].file.as_raw_fd(),writer);assert_eq!(f.state.files[&path].access,libc::O_RDWR);
    assert!(f.state.poisoned);
}

#[test]
fn candidate_requires_readonly_nonblocking_cloexec_and_original_writer_flags_are_rechecked() {
    let mut f=Fixture::new();let path=f.unsealed("flags.bin",b"public flags fixture",false);
    let seed=&f.state.files[&path];let parent=&f.state.dirs[path.parent().unwrap()].file;
    refused(seed.current_on(&seed.file,libc::O_RDONLY,parent,&path,f.state.protection,true),"BIRTH_DESCRIPTOR_FLAGS");
    let candidate=open_at(parent,&path,false).unwrap();
    let status=unsafe{libc::fcntl(candidate.as_raw_fd(),libc::F_GETFL)};
    assert_eq!(unsafe{libc::fcntl(candidate.as_raw_fd(),libc::F_SETFL,status&!libc::O_NONBLOCK)},0);
    refused(seed.current_on(&candidate,libc::O_RDONLY,parent,&path,f.state.protection,true),"BIRTH_DESCRIPTOR_FLAGS");
    assert_eq!(unsafe{libc::fcntl(candidate.as_raw_fd(),libc::F_SETFL,status)},0);
    assert_eq!(unsafe{libc::fcntl(candidate.as_raw_fd(),libc::F_SETFD,0)},0);
    refused(seed.current_on(&candidate,libc::O_RDONLY,parent,&path,f.state.protection,true),"BIRTH_DESCRIPTOR_FLAGS");
    let writer=seed.file.as_raw_fd();let status=unsafe{libc::fcntl(writer,libc::F_GETFL)};
    assert_eq!(unsafe{libc::fcntl(writer,libc::F_SETFL,status&!libc::O_NONBLOCK)},0);
    refused(f.seal(&path,true),"BIRTH_DESCRIPTOR_FLAGS");assert!(f.state.poisoned);
}

#[test]
fn metadata_mode_seal_keeps_other_stream_hashes_for_full_outer_gate() {
    let mut f=Fixture::new();let a=f.unsealed("earlier.bin",&vec![0x61;64*1024+1],true);
    f.seal(&a,false).unwrap();std::fs::write(&a,vec![0x62;64*1024+1]).unwrap();
    // Synthetic stable-metadata earlier payload separates modes. Per-file
    // sealing may check earlier payload metadata, but full outer acceptance
    // MUST still discover its digest change before import succeeds.
    let seed=f.state.files.get_mut(&a).unwrap();seed.stamp=FileStamp::of(&seed.file.metadata().unwrap());
    let b=f.unsealed("current.bin",&vec![0x63;64*1024+37],true);f.seal(&b,false).unwrap();
    readonly(&f.state.files[&a]);readonly(&f.state.files[&b]);assert!(!f.state.poisoned);
    assert!(f.state.checks(&mut||Vec::new()).iter().any(|e|e.is("BIRTH_STREAM_DIGEST_CHANGED")));
    assert!(f.state.revalidate(&mut||Vec::new()).is_err());assert!(f.state.poisoned);
}

#[test]
fn exact_content_and_stream_eof_remain_mandatory_before_readonly_transition() {
    let mut f=Fixture::new();let path=f.unsealed("changed-exact.bin",b"AAAA",false);std::fs::write(&path,b"BBBB").unwrap();
    let seed=f.state.files.get_mut(&path).unwrap();seed.stamp=FileStamp::of(&seed.file.metadata().unwrap());
    refused(f.seal(&path,false),"BIRTH_SEED_CHANGED");assert!(f.state.poisoned);
    let mut f=Fixture::new();let path=f.unsealed("eof.bin",b"five!",true);let seed=&f.state.files[&path];
    refused(file_sha256(&seed.file,4).map(|_|()),"BIRTH_STREAM_LENGTH");
    refused(file_sha256(&seed.file,6).map(|_|()),"BIRTH_STREAM_TRUNCATED");
}
