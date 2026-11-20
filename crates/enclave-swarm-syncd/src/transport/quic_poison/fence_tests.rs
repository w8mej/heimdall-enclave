//! Finite storage/process tests. Every child is the exact owned test executable.
use super::*;
use crate::transport::quic_fence_test_support::{
    self as support,
    Role,
    Run,
    Stage,
    Fault
};
use serde::{
    Deserialize,
    Serialize
};
use std::os::unix::{
    fs::{
        symlink,
        FileTypeExt,
        PermissionsExt
    },
    net::UnixListener
};
pub(super) struct Fixture {
    pub(super) path:PathBuf,
    pub(super) peer:[u8;32],
    pub(super) signer:SigningKey,
    owned:bool
}
#[derive(Serialize, Deserialize)]struct FixtureWire{
    path:PathBuf,
    peer:[u8;32],
    seed:[u8;32]
}
impl Fixture {
    pub(super) fn new()->Self{
        let base=if std::env::var_os("depot_QF_CHILD_CONFIG").is_some(){
            support::fixture_path()
        }
        else{
            std::env::temp_dir()
        };
        let path=base.join(format!("mcqf-{:016x}", enclave_core::rng::u64()));
        Self::at(path, true)
    }
    fn at(path:PathBuf, owned:bool)->Self{
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        Self{
            path,
            peer:enclave_core::rng::bytes32(),
            signer:SigningKey::from_bytes(&enclave_core::rng::bytes32()),
            owned
        }
    }
    fn named(run:&Run, case:&str)->Self{
        let f=Self::at(run.fixture.join(format!("state-{case}")), false);
        f.save(run, case);
        f
    }
    fn save(&self, run:&Run, case:&str){
        let wire=FixtureWire{
            path:self.path.clone(),
            peer:self.peer,
            seed:self.signer.to_bytes()
        };
        let mut file=std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(run.fixture.join(format!("{case}.fixture.json"))).unwrap();
        file.write_all(&serde_json::to_vec(&wire).unwrap()).unwrap();
    }
    fn child()->Self{
        let path=support::fixture_path().join(format!("{}.fixture.json", support::case()));
        let wire:FixtureWire=serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        Self{
            path:wire.path,
            peer:wire.peer,
            signer:SigningKey::from_bytes(&wire.seed),
            owned:false
        }
    }
    pub(super) fn open(&self)->PeerDomain{
        self.try_open().unwrap()
    }
    fn try_open(&self)->EnclaveResult<PeerDomain>{
        process_peer_stops().reserve_domain(self.path.to_str().unwrap(), self.signer.verifying_key().to_bytes(), &[self.peer])
    }
    fn leaf(&self, suffix:&str)->PathBuf{
        self.path.join(format!("{}{suffix}", hex::encode(self.peer)))
    }
    fn publish(&self, state:&PoisonState)->Result<PublishOutcome,
    PublishFailure>{
        state.record(&self.signer, &"cd".repeat(32), 3, b"real authenticated fixture corruption", &[4;32], ||Ok(123))
    }
}
impl Drop for Fixture{
    fn drop(&mut self){
        if self.owned{
            let _=std::fs::remove_dir_all(&self.path);
        }
    }
}
fn child_receipt(run:&Run, case:&str, role:Role)->serde_json::Value{
    serde_json::from_slice(&std::fs::read(run.fixture.join(format!("{case}-{role:?}-receipt.json"))).unwrap()).unwrap()
}
fn ready_image(f:&Fixture)->serde_json::Value{
    let mut files=Vec::new();
    for suffix in [".qreg1", ".qlock1", ".json"]{
        let path=f.leaf(suffix);
        let entry=std::fs::symlink_metadata(&path).ok();
        let bytes=entry.as_ref().filter(|m|m.is_file()).map(|_|std::fs::read(&path).unwrap());
        files.push(serde_json::json!({
            "suffix":suffix,
            "present":entry.is_some(),
            "dev":entry.as_ref().map(|m|m.dev()),
            "ino":entry.as_ref().map(|m|m.ino()),
            "len":entry.as_ref().map(|m|m.len()),
            "blake3":bytes.map(|v|blake3::hash(&v).to_hex().to_string())
        }));
    }
    serde_json::json!(files)
}
fn raw_ex(f:&Fixture)->bool{
    let file=std::fs::OpenOptions::new().read(true).write(true).custom_flags(libc::O_NOFOLLOW|libc::O_NONBLOCK|libc::O_CLOEXEC).open(f.leaf(".qlock1")).unwrap();
    let result=unsafe{
        libc::flock(file.as_raw_fd(), libc::LOCK_EX|libc::LOCK_NB)
    };
    if result!=0{
        let e=std::io::Error::last_os_error().raw_os_error();
        assert!(e==Some(libc::EWOULDBLOCK)||e==Some(libc::EAGAIN));
    }
    result==0
}
fn emit(value:serde_json::Value){
    support::emit_child_receipt(&value);
}
fn open_child(){
    let f=Fixture::child();
    let before=ready_image(&f);
    let result=f.try_open();
    if result.is_ok(){
        support::hook(Stage::ProvisionAcknowledged, 1);
    }
    let clean=result.as_ref().ok().and_then(|d|d.peer(&f.peer).ok()).is_some_and(|s|s.clean_lease().is_ok());
    emit(serde_json::json!({
        "opened":result.is_ok(),
        "clean":clean,
        "error":result.err().map(|e|e.reason),
        "before":before,
        "after":ready_image(&f),
        "notes":support::notes()
    }));
}
#[test] fn qf_registration_exact_layout_ready_attach_and_legacy_receipt_refusal(){
    const NAME:&str="transport::quic_poison::fence_tests::qf_registration_exact_layout_ready_attach_and_legacy_receipt_refusal";
    if support::child_role(NAME).is_some(){
        open_child();
        return;
    }
    let mut run=Run::new(NAME);
    let cases=["exact_headers", "registration_mutations", "lock_mutations", "legacy_entry_refusal", "orphan_lock_refusal", "foreign_owner_metadata_control"];
    run.expect(&cases);
    let f=Fixture::named(&run, "layout");
    let domain=f.open();
    let state=domain.peer(&f.peer).unwrap();
    assert!(state.clean_lease().is_ok());
    let reg=std::fs::read(f.leaf(".qreg1")).unwrap();
    let lock=std::fs::read(f.leaf(".qlock1")).unwrap();
    assert_eq!(reg.len(), 256);
    assert_eq!(lock.len(), 128);
    assert_eq!(&reg[..8], b"depotQREG1");
    assert_eq!(&reg[8..12], &1u32.to_be_bytes());
    assert_eq!(&reg[12..16], &2u32.to_be_bytes());
    assert_eq!(&reg[224..], blake3::hash(&reg[..224]).as_bytes());
    assert_eq!(&reg[144..176], blake3::hash(&lock).as_bytes());
    assert_eq!(&reg[16..48], &f.peer);
    assert_eq!(&reg[48..80], f.signer.verifying_key().as_bytes());
    let directory=std::fs::metadata(&f.path).unwrap();let lock_metadata=std::fs::metadata(f.leaf(".qlock1")).unwrap();
    assert_eq!(u64::from_be_bytes(reg[112..120].try_into().unwrap()),directory.dev());assert_eq!(u64::from_be_bytes(reg[120..128].try_into().unwrap()),directory.ino());
    assert_eq!(u64::from_be_bytes(reg[128..136].try_into().unwrap()),lock_metadata.dev());assert_eq!(u64::from_be_bytes(reg[136..144].try_into().unwrap()),lock_metadata.ino());
    assert_eq!(&lock[..8],b"depotQLOK1");assert_eq!(&lock[8..12],&1u32.to_be_bytes());assert_eq!(&lock[16..48],&f.peer);assert_eq!(&lock[48..80],f.signer.verifying_key().as_bytes());assert_eq!(&lock[80..112],&reg[80..112]);
    assert!(reg[176..224].iter().all(|b|*b==0));
    assert!(lock[12..16].iter().chain(lock[112..].iter()).all(|b|*b==0));
    let before=ready_image(&f);
    f.save(&run, "attach");
    let mut opener=run.spawn(Role::Opener, "attach", &[], &[]);
    opener.wait_success();
    assert_eq!(child_receipt(&run, "attach", Role::Opener)["clean"], true);
    assert_eq!(ready_image(&f), before);
    run.record("exact-headers", &before);
    run.complete("exact_headers");
    let mut mutations=Vec::new();
    for offset in [0, 8, 12, 16, 48, 80, 112, 120, 128, 136, 144, 176, 224]{
        let mut bytes=reg.clone();
        bytes[offset]^=1;
        if offset!=224{
            let h=blake3::hash(&bytes[..224]);
            bytes[224..].copy_from_slice(h.as_bytes());
        }
        std::fs::write(f.leaf(".qreg1"), bytes).unwrap();
        assert!(state.clean_lease().is_err());
        mutations.push(format!("offset_{offset}"));
    }
    for size in [255, 257]{
        let mut bytes=reg.clone();
        bytes.resize(size, 0);
        std::fs::write(f.leaf(".qreg1"), bytes).unwrap();
        assert!(state.clean_lease().is_err());
        mutations.push(format!("length_{size}"));
    }
    std::fs::write(f.leaf(".qreg1"), &reg).unwrap();
    assert!(state.clean_lease().is_ok());
    run.record("registration-mutations", &mutations);
    run.complete("registration_mutations");
    let mut mutated=Vec::new();
    for offset in [0, 8, 12, 16, 48, 80, 112]{
        let mut bytes=lock.clone();
        bytes[offset]^=1;
        let mut rebound=reg.clone();rebound[144..176].copy_from_slice(blake3::hash(&bytes).as_bytes());let checksum=blake3::hash(&rebound[..224]);rebound[224..].copy_from_slice(checksum.as_bytes());std::fs::write(f.leaf(".qreg1"),rebound).unwrap();
        std::fs::write(f.leaf(".qlock1"), bytes).unwrap();
        assert!(state.clean_lease().is_err());
        mutated.push(format!("offset_{offset}"));
    }
    for size in [127, 129]{
        let mut bytes=lock.clone();
        bytes.resize(size, 0);
        let mut rebound=reg.clone();rebound[144..176].copy_from_slice(blake3::hash(&bytes).as_bytes());let checksum=blake3::hash(&rebound[..224]);rebound[224..].copy_from_slice(checksum.as_bytes());std::fs::write(f.leaf(".qreg1"),rebound).unwrap();
        std::fs::write(f.leaf(".qlock1"), bytes).unwrap();
        assert!(state.clean_lease().is_err());
        mutated.push(format!("length_{size}"));
    }
    std::fs::write(f.leaf(".qlock1"), &lock).unwrap();
    std::fs::write(f.leaf(".qreg1"),&reg).unwrap();
    assert!(state.clean_lease().is_ok());
    run.record("lock-mutations", &mutated);
    run.complete("lock_mutations");
    let mut legacy=Vec::new();
    for kind in ["valid", "empty", "partial", "invalid_signature", "wrong_detector", "symlink", "hardlink", "fifo", "directory"]{
        let f=Fixture::at(run.fixture.join(format!("legacy-{kind}")), false);
        let marker=f.leaf(".json");
        let mut receipt=PoisonReceipt::sign(&f.signer, &PoisonEvidence{
            peer_id:&hex::encode(f.peer),
            target_root:&"cd".repeat(32),
            slice_index:0,
            expected_hash:&"cd".repeat(32),
            corrupted_slice:b"bad",
            session_binding:&"11".repeat(32),
            timestamp_utc_ms:1
        });
        match kind{
            "valid"=>std::fs::write(&marker, serde_json::to_vec(&receipt).unwrap()).unwrap(),
            "empty"=>std::fs::write(&marker, b"").unwrap(),
            "partial"=>std::fs::write(&marker, b"{").unwrap(),
            "invalid_signature"=>{
                receipt.signature_hex="00".repeat(64);
                std::fs::write(&marker, serde_json::to_vec(&receipt).unwrap()).unwrap();
            },
            "wrong_detector"=>{
                receipt.detector_id="ab".repeat(32);
                std::fs::write(&marker, serde_json::to_vec(&receipt).unwrap()).unwrap();
            },
            "symlink"=>symlink("missing", &marker).unwrap(),
            "hardlink"=>{
                std::fs::write(f.path.join("other"), b"x").unwrap();
                std::fs::hard_link(f.path.join("other"), &marker).unwrap();
            },
            "fifo"=>{
                let name=std::ffi::CString::new(marker.as_os_str().as_encoded_bytes()).unwrap();
                assert_eq!(unsafe{
                    libc::mkfifo(name.as_ptr(), 0o600)
                }, 0);
            },
            "directory"=>std::fs::create_dir(&marker).unwrap(),
            _=>unreachable!()
        }
        if std::fs::symlink_metadata(&marker).unwrap().is_file(){std::fs::set_permissions(&marker,std::fs::Permissions::from_mode(0o600)).unwrap();}
        assert!(f.try_open().is_err());
        assert!(std::fs::symlink_metadata(&marker).is_ok());
        assert!(!f.leaf(".qreg1").exists());
        legacy.push(kind);
    }
    run.record("legacy-entries", &legacy);
    run.complete("legacy_entry_refusal");
    let orphan=Fixture::at(run.fixture.join("orphan-lock"),false);std::fs::write(orphan.leaf(".qlock1"),&lock).unwrap();std::fs::set_permissions(orphan.leaf(".qlock1"),std::fs::Permissions::from_mode(0o600)).unwrap();assert!(orphan.try_open().is_err());assert!(!orphan.leaf(".qreg1").exists());assert_eq!(std::fs::read(orphan.leaf(".qlock1")).unwrap(),lock);run.complete("orphan_lock_refusal");
    let good=LeafFacts::from(&std::fs::metadata(f.leaf(".qreg1")).unwrap());
    assert!(good.valid(Some(256)));
    let foreign=LeafFacts{
        uid:good.uid.wrapping_add(1),
        ..good
    };
    assert!(!foreign.valid(Some(256)));
    let mut chown_errno=None;
    let mut observed_owner=good.uid;
    let (actual_cross_uid,foreign_owner_status)=if enclave_core::ipc::geteuid()==0 {
        let file=state.open_leaf(".qreg1",false).unwrap();
        let result=unsafe{libc::fchown(file.as_raw_fd(),1,u32::MAX)};
        if result!=0 { chown_errno=std::io::Error::last_os_error().raw_os_error(); }
        observed_owner=file.metadata().unwrap().uid();
        if result==0 && observed_owner==1 {
            assert!(state.clean_lease().is_err());
            assert_eq!(unsafe{libc::fchown(file.as_raw_fd(),0,u32::MAX)},0);
            assert_eq!(file.metadata().unwrap().uid(),0,"restore actual owned fixture owner");
            assert!(state.clean_lease().is_ok());
            (true,"PASS_ACTUAL_FOREIGN_OWNER_REFUSAL")
        } else {
            assert_eq!(observed_owner,good.uid,"unexpected owner transition");
            assert!(state.clean_lease().is_ok());
            (false,if result==0{"BLOCKED_FILESYSTEM_IGNORES_CHOWN"}else{"BLOCKED_FCHOWN_ERROR"})
        }
    } else {
        (false,"BLOCKED_NO_CHOWN_AUTHORITY")
    };
    run.record("foreign-owner",&serde_json::json!({
        "synthetic_metadata_control":true,
        "actual_cross_uid":actual_cross_uid,
        "actual_foreign_owner_status":foreign_owner_status,
        "actual_fchown_errno":chown_errno,
        "observed_uid_after_attempt":observed_owner,
        "actual_cross_uid_coverage_blocked":!actual_cross_uid
    }));
    run.complete("foreign_owner_metadata_control");
    run.finish();
}
#[test] fn qf_registration_concurrent_creator_and_genesis_crash_states_fail_closed(){
    const NAME:&str="transport::quic_poison::fence_tests::qf_registration_concurrent_creator_and_genesis_crash_states_fail_closed";
    if support::child_role(NAME).is_some(){
        open_child();
        return;
    }
    let mut run=Run::new(NAME);
    let expected=["concurrent_creators", "before_registration", "registration_empty", "pending_written", "pending_synced", "lock_empty", "lock_synced", "ready_prefix", "ready_written", "ready_synced", "provision_acknowledged"];
    run.expect(&expected);
    let f=Fixture::named(&run, "race");
    f.save(&run, "race_two");
    let mut a=run.spawn(Role::Opener, "race", &[(Stage::BeforeRegistrationCreate, 1)], &[]);
    let mut b=run.spawn(Role::Opener, "race_two", &[(Stage::BeforeRegistrationCreate, 1)], &[]);
    a.wait_reached(Stage::BeforeRegistrationCreate, 1);
    b.wait_reached(Stage::BeforeRegistrationCreate, 1);
    a.resume();
    b.resume();
    a.wait_success();
    b.wait_success();
    let aa=child_receipt(&run, "race", Role::Opener);
    let bb=child_receipt(&run, "race_two", Role::Opener);
    assert!(aa["opened"].is_boolean()&&bb["opened"].is_boolean());
    let image=ready_image(&f);
    for result in [&aa, &bb]{
        if result["opened"]==true{
            assert_eq!(result["after"][0]["ino"], image[0]["ino"]);
            assert_eq!(result["after"][1]["ino"], image[1]["ino"]);
        }
    }
    assert_eq!(std::fs::metadata(f.leaf(".qreg1")).unwrap().nlink(), 1);
    assert!(!f.leaf(".json").exists());
    run.record("concurrent-creator-result", &serde_json::json!({
        "one":aa,
        "two":bb,
        "image":image
    }));
    run.complete("concurrent_creators");
    let stages=[Stage::BeforeRegistrationCreate, Stage::RegistrationCreated, Stage::PendingWritten, Stage::PendingSynced, Stage::LockCreated, Stage::LockSynced, Stage::ReadyPrefixWritten, Stage::ReadyWritten, Stage::ReadySynced, Stage::ProvisionAcknowledged];
    for (i, stage) in stages.into_iter().enumerate(){
        let case=format!("genesis_{i}");
        let f=Fixture::named(&run, &case);
        let fresh=format!("fresh_{i}");
        f.save(&run, &fresh);
        let mut creator=run.spawn(Role::Opener, &case, &[(stage, 1)], &[]);
        creator.wait_reached(stage, 1);
        creator.kill_at_stage();
        let before=ready_image(&f);
        let mut opener=run.spawn(Role::Opener, &fresh, &[], &[]);
        opener.wait_success();
        let receipt=child_receipt(&run, &fresh, Role::Opener);
        let may_open=i==0||i>=7;
        assert_eq!(receipt["opened"], may_open, "{stage:?}");
        if i!=0{
            assert_eq!(ready_image(&f), before, "fresh opener must not repair bytes/inodes");
        }
        run.record(&format!("genesis-{i}"), &serde_json::json!({
            "stage":stage,
            "before":before,
            "fresh":receipt
        }));
        run.complete(expected[i+1]);
    }
    run.finish();
}
#[test] fn qf_registered_lock_and_registration_replacement_controls_refuse(){
    const NAME:&str="transport::quic_poison::fence_tests::qf_registered_lock_and_registration_replacement_controls_refuse";
    let mut run=Run::new(NAME);
    run.expect(&["registration_replacements", "lock_replacements"]);
    let f=Fixture::named(&run, "replace");
    let d=f.open();
    let s=d.peer(&f.peer).unwrap();
    for (suffix, label) in [(".qreg1", "registration_replacements"), (".qlock1", "lock_replacements")]{
        let leaf=f.leaf(suffix);
        let backup=f.path.join("original");
        let mut seen=Vec::new();
        for kind in ["missing", "replacement", "symlink", "hardlink", "fifo", "directory", "socket"]{
            std::fs::rename(&leaf, &backup).unwrap();
            let mut socket=None;
            match kind{
                "missing"=>{
                },
                "replacement"=>{
                    std::fs::write(&leaf, std::fs::read(&backup).unwrap()).unwrap();
                    std::fs::set_permissions(&leaf, std::fs::Permissions::from_mode(0o600)).unwrap();
                },
                "symlink"=>symlink(&backup, &leaf).unwrap(),
                "hardlink"=>std::fs::hard_link(&backup, &leaf).unwrap(),
                "fifo"=>{
                    let name=std::ffi::CString::new(leaf.as_os_str().as_encoded_bytes()).unwrap();
                    assert_eq!(unsafe{
                        libc::mkfifo(name.as_ptr(), 0o600)
                    }, 0);
                },
                "directory"=>std::fs::create_dir(&leaf).unwrap(),
                "socket"=>{
                    // Bind below the short owned fixture root, then move the
                    // actual socket inode onto the full registered peer leaf.
                    // Its absolute registered path exceeds sockaddr_un limits.
                    let short=run.fixture.join(format!("s-{:016x}", enclave_core::rng::u64()));
                    let listener=UnixListener::bind(&short).unwrap();
                    std::fs::set_permissions(&short, std::fs::Permissions::from_mode(0o600)).unwrap();
                    let bound=std::fs::symlink_metadata(&short).unwrap();
                    assert!(bound.file_type().is_socket());
                    std::fs::rename(&short, &leaf).unwrap();
                    let placed=std::fs::symlink_metadata(&leaf).unwrap();
                    assert!(placed.file_type().is_socket());
                    assert_eq!((placed.dev(), placed.ino()), (bound.dev(), bound.ino()));
                    assert_eq!(placed.mode()&0o7777, 0o600);
                    assert!(!short.exists());
                    socket=Some(listener);
                },
                _=>unreachable!()
            };
            assert!(s.clean_lease().is_err(), "{suffix} {kind}");
            drop(socket);
            if kind=="directory"{
                std::fs::remove_dir(&leaf).unwrap();
            }
            else if kind!="missing"{
                std::fs::remove_file(&leaf).unwrap();
            }
            std::fs::rename(&backup, &leaf).unwrap();
            assert!(s.clean_lease().is_ok());
            seen.push(kind);
        }
        run.record(label, &seen);
        run.complete(label);
    }
    run.finish();
}
#[test] fn qf_directory_pin_survives_reconstruction_and_rejects_replacement(){
    const NAME:&str="transport::quic_poison::fence_tests::qf_directory_pin_survives_reconstruction_and_rejects_replacement";
    let mut run=Run::new(NAME);
    run.expect(&["replaced_path_refuses_live_and_reconstruction", "alternate_path_refuses_same_detector", "distinct_detector_shares_stop"]);
    let f=Fixture::named(&run, "directory");
    let d=f.open();
    let s=d.peer(&f.peer).unwrap();
    let held=s.pin.identity;
    let old=f.path.with_extension("old");
    std::fs::rename(&f.path, &old).unwrap();
    std::fs::create_dir(&f.path).unwrap();
    std::fs::set_permissions(&f.path, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert!(s.clean_lease().is_err());
    assert!(f.try_open().is_err());
    assert_eq!(identity(&s.pin.dir).unwrap(), held);
    run.complete("replaced_path_refuses_live_and_reconstruction");
    assert!(process_peer_stops().reserve_domain(old.to_str().unwrap(), f.signer.verifying_key().to_bytes(), &[f.peer]).is_err());
    run.complete("alternate_path_refuses_same_detector");
    s.stop.store(true, Ordering::SeqCst);
    let other=Fixture::named(&run, "different_detector");
    let other_domain=process_peer_stops().reserve_domain(other.path.to_str().unwrap(), other.signer.verifying_key().to_bytes(), &[f.peer]).unwrap();
    let other_state=other_domain.peer(&f.peer).unwrap();
    assert!(Arc::ptr_eq(&s.stop, &other_state.stop));
    assert!(other_state.clean_lease().is_err());
    run.record("pinned-directory", &serde_json::json!({
        "retained_original":held,
        "shared_stop":true
    }));
    run.complete("distinct_detector_shares_stop");
    std::fs::remove_dir_all(old).unwrap();
    run.finish();
}
#[test] fn qf_independent_open_descriptions_and_duplicate_close_controls(){
    const NAME:&str="transport::quic_poison::fence_tests::qf_independent_open_descriptions_and_duplicate_close_controls";
    if support::child_role(NAME).is_some(){
        let f=Fixture::child();
        let d=f.open();
        let s=d.peer(&f.peer).unwrap();
        if support::case()=="independent"{
            let a=s.clean_lease().unwrap();
            let b=s.clean_lease().unwrap();
            support::hook(Stage::LeaseAcquired, 1);
            drop(a);
            support::hook(Stage::LeaseReleased, 1);
            drop(b);
            support::hook(Stage::LeaseReleased, 2);
        }
        else{
            let file=s.open_leaf(".qlock1", false).unwrap();
            assert_eq!(unsafe{
                libc::flock(file.as_raw_fd(), libc::LOCK_SH|libc::LOCK_NB)
            }, 0);
            let dup=unsafe{
                libc::dup(file.as_raw_fd())
            };
            assert!(dup>=0);
            let alias=unsafe{
                File::from_raw_fd(dup)
            };
            drop(file);
            support::hook(Stage::LeaseReleased, 1);
            drop(alias);
            support::hook(Stage::LeaseReleased, 2);
        }
        emit(serde_json::json!({
            "notes":support::notes()
        }));
        return;
    }
    let mut run=Run::new(NAME);
    run.expect(&["independent_descriptions", "dup_shares_ownership"]);
    for case in ["independent", "duplicate"]{
        let f=Fixture::named(&run, case);
        let pauses=if case=="independent"{
            vec![(Stage::LeaseAcquired, 1), (Stage::LeaseReleased, 1), (Stage::LeaseReleased, 2)]
        }
        else{
            vec![(Stage::LeaseReleased, 1), (Stage::LeaseReleased, 2)]
        };
        let mut child=run.spawn(Role::LeaseHolder, case, &pauses, &[]);
        if case=="independent"{
            child.wait_reached(Stage::LeaseAcquired, 1);
            assert!(!raw_ex(&f));
            child.resume();
        }
        child.wait_reached(Stage::LeaseReleased, 1);
        assert!(!raw_ex(&f));
        child.resume();
        child.wait_reached(Stage::LeaseReleased, 2);
        assert!(raw_ex(&f));
        child.resume();
        child.wait_success();
        run.complete(if case=="independent"{
            "independent_descriptions"
        }
        else{
            "dup_shares_ownership"
        });
    }
    run.finish();
}
#[test] fn qf_first_receipt_race_preserves_original_and_typed_existing_outcome(){
    const NAME:&str="transport::quic_poison::fence_tests::qf_first_receipt_race_preserves_original_and_typed_existing_outcome";
    if support::child_role(NAME).is_some(){
        let f=Fixture::child();
        let d=f.open();
        let s=d.peer(&f.peer).unwrap();
        let value=if support::case()=="first"{
            b"first bytes".as_slice()
        }
        else{
            b"different second bytes".as_slice()
        };
        let outcome=s.record(&f.signer, &"cd".repeat(32), 3, value, &[4;32], ||Ok(123));
        emit(serde_json::json!({
            "outcome":outcome,
            "image":ready_image(&f),
            "notes":support::notes()
        }));
        return;
    }
    let mut run=Run::new(NAME);
    run.expect(&["first_writer_preserved", "existing_original_retry_hash"]);
    let f=Fixture::named(&run, "first");
    f.open();
    f.save(&run, "second");
    f.save(&run, "retry");
    let mut a=run.spawn(Role::Publisher, "first", &[(Stage::PublicationPrepared, 1)], &[]);
    let mut b=run.spawn(Role::Publisher, "second", &[(Stage::PublicationPrepared, 1)], &[]);
    a.wait_reached(Stage::PublicationPrepared, 1);
    b.wait_reached(Stage::PublicationPrepared, 1);
    a.resume();
    b.resume();
    a.wait_success();
    b.wait_success();
    let aa=child_receipt(&run, "first", Role::Publisher);
    let bb=child_receipt(&run, "second", Role::Publisher);
    let created=|v:&serde_json::Value|v["outcome"]["Ok"].get("CreatedOriginalDurablyFenced").is_some();
    assert_ne!(created(&aa), created(&bb));
    let original=std::fs::read(f.leaf(".json")).unwrap();
    let hash=*blake3::hash(&original).as_bytes();
    let winner=if created(&aa){
        &aa
    }
    else{
        &bb
    };
    assert_eq!(winner["outcome"]["Ok"]["CreatedOriginalDurablyFenced"]["original_blake3"], serde_json::json!(hash));
    let loser=if created(&aa){
        &bb
    }
    else{
        &aa
    };
    if let Some(existing)=loser["outcome"]["Ok"].get("ExistingOriginalDurablyFenced"){
        assert_eq!(existing["original_blake3"], serde_json::json!(hash));
    }
    else{
        assert_eq!(loser["outcome"]["Err"]["reason"], "ExistingInvalid");
    }
    run.record("first-writer-race", &serde_json::json!({
        "one":aa,
        "two":bb,
        "original_blake3":hash
    }));
    run.complete("first_writer_preserved");
    let before=ready_image(&f);
    let mut retry=run.spawn(Role::Publisher, "retry", &[], &[]);
    retry.wait_success();
    let value=child_receipt(&run, "retry", Role::Publisher);
    assert_eq!(value["outcome"]["Ok"]["ExistingOriginalDurablyFenced"]["original_blake3"], serde_json::json!(hash));
    assert_eq!(ready_image(&f), before);
    run.complete("existing_original_retry_hash");
    run.finish();
}
#[test] fn qf_publication_crash_markers_and_io_failures_preserve_exact_progress(){
    const NAME:&str="transport::quic_poison::fence_tests::qf_publication_crash_markers_and_io_failures_preserve_exact_progress";
    if let Some(role)=support::child_role(NAME){
        if role==Role::Opener{
            open_child();
            return;
        }
        let f=Fixture::child();
        let d=f.open();
        let s=d.peer(&f.peer).unwrap();
        let short=support::case()=="short_write";
        let mut old=std::mem::MaybeUninit::<libc::rlimit>::uninit();
        let mut old_signal=0;
        unsafe{
            if short{
                assert_eq!(libc::getrlimit(libc::RLIMIT_FSIZE, old.as_mut_ptr()), 0);
                old_signal=libc::signal(libc::SIGXFSZ, libc::SIG_IGN);
                let r=libc::rlimit{
                    rlim_cur:80,
                    rlim_max:(*old.as_ptr()).rlim_max
                };
                assert_eq!(libc::setrlimit(libc::RLIMIT_FSIZE, &r), 0);
            }
        }
        let outcome=f.publish(s);
        if outcome.is_ok(){
            support::hook(Stage::PublicationAcknowledged, 1);
        }
        unsafe{
            if short{
                assert_eq!(libc::setrlimit(libc::RLIMIT_FSIZE, old.as_ptr()), 0);
                libc::signal(libc::SIGXFSZ, old_signal);
            }
        }
        emit(serde_json::json!({
            "outcome":outcome,
            "stopped":s.is_stopped(),
            "local_refused":s.clean_lease().is_err(),
            "real_prefix_bytes":std::fs::metadata(f.leaf(".json")).ok().map(|m|m.len()),
            "notes":support::notes()
        }));
        return;
    }
    let mut run=Run::new(NAME);
    let expected=["prepared_no_marker", "marker_empty", "marker_prefix", "file_synced", "directory_synced", "fence_validated", "publication_acknowledged", "real_short_write_efbig", "synthetic_file_sync", "synthetic_directory_sync"];
    run.expect(&expected);
    let stages=[Stage::PublicationPrepared, Stage::MarkerCreated, Stage::MarkerPrefixWritten, Stage::MarkerFileSynced, Stage::MarkerDirectorySynced, Stage::FenceValidated, Stage::PublicationAcknowledged];
    for (i, stage)in stages.into_iter().enumerate(){
        let case=format!("publish_{i}");
        let f=Fixture::named(&run, &case);
        f.open();
        let fresh=format!("fresh_{i}");
        f.save(&run, &fresh);
        let mut p=run.spawn(Role::Publisher, &case, &[(stage, 1)], &[]);
        p.wait_reached(stage, 1);
        p.kill_at_stage();
        let before=ready_image(&f);
        let mut o=run.spawn(Role::Opener, &fresh, &[], &[]);
        o.wait_success();
        let receipt=child_receipt(&run, &fresh, Role::Opener);
        assert_eq!(receipt["clean"], i==0);
        assert_eq!(ready_image(&f), before);
        run.record(&format!("publisher-{i}"), &serde_json::json!({
            "stage":stage,
            "before":before,
            "fresh":receipt,
            "unwritten_fact_gap":i==0,
            "typed_ack_observed":i==6
        }));
        run.complete(expected[i]);
    }
    for (case, fault, reason, progress, label)in [("short_write", None, "Write", "PresentUnverified", "real_short_write_efbig"), ("file_sync", Some(Fault::FileSync), "FileSync", "ValidatedUnsynced", "synthetic_file_sync"), ("directory_sync", Some(Fault::DirectorySync), "DirectorySync", "FileSynced", "synthetic_directory_sync")]{
        let f=Fixture::named(&run, case);
        f.open();
        let faults=fault.map(|v|vec![(v, 1)]).unwrap_or_default();
        let mut p=run.spawn(Role::Publisher, case, &[], &faults);
        p.wait_success();
        let receipt=child_receipt(&run, case, Role::Publisher);
        assert_eq!(receipt["outcome"]["Err"]["reason"], reason);
        assert_eq!(receipt["outcome"]["Err"]["marker_progress"], progress);
        assert_eq!(receipt["stopped"], true);
        assert_eq!(receipt["local_refused"], true);
        if fault.is_none(){
            let n=receipt["real_prefix_bytes"].as_u64().unwrap();
            assert!(n>0&&n<=80);
            let actual_notes:Vec<support::Note>=serde_json::from_value(receipt["notes"].clone()).unwrap();assert!(actual_notes.iter().any(|note|matches!(note,support::Note::PublicationWriteError{errno:Some(code)}if *code==libc::EFBIG)),"observed real EFBIG at receipt write");
        }
        run.record(case, &receipt);
        run.complete(label);
    }
    run.finish();
}
#[test] fn qf_process_stop_precedes_timestamp_serialization_and_marker_failures(){
    const NAME:&str="transport::quic_poison::fence_tests::qf_process_stop_precedes_timestamp_serialization_and_marker_failures";
    if let Some(role)=support::child_role(NAME){
        if role==Role::Opener{
            open_child();
            return;
        }
        let f=Fixture::child();
        let d=f.open();
        let s=d.peer(&f.peer).unwrap();
        let honest=enclave_core::rng::bytes32();
        let honest_domain=process_peer_stops().reserve_domain(f.path.to_str().unwrap(), f.signer.verifying_key().to_bytes(), &[honest]).unwrap();
        let result=s.record(&f.signer, &"cd".repeat(32), 0, b"real fixture corruption", &[1;32], ||{
            assert!(s.is_stopped(), "stop must precede actual timestamp attempt");
            if support::case()=="timestamp"{
                Err(err!(EIO, "L2_CLOCK"))
            }
            else{
                Ok(1)
            }
        });
        let failure=result.unwrap_err();
        let expected=match support::case().as_str(){
            "timestamp"=>PublishReason::Timestamp,
            "serialization"=>PublishReason::Serialization,
            "marker_open"=>PublishReason::MarkerCreate,
            _=>panic!("unknown owned case")
        };
        assert_eq!(failure.reason, expected);
        assert_eq!(failure.marker_progress, MarkerProgress::NotObserved);
        assert!(s.is_stopped()&&s.clean_lease().is_err());
        assert!(!f.leaf(".json").exists());
        let reconstructed=f.open();
        let again=reconstructed.peer(&f.peer).unwrap();
        assert!(Arc::ptr_eq(&s.stop, &again.stop)&&again.clean_lease().is_err());
        let alternate=Fixture::at(support::fixture_path().join(format!("rotated-{}", support::case())), false);
        let rotated=process_peer_stops().reserve_domain(alternate.path.to_str().unwrap(), alternate.signer.verifying_key().to_bytes(), &[f.peer]).unwrap();
        let rotated=rotated.peer(&f.peer).unwrap();
        assert!(Arc::ptr_eq(&s.stop, &rotated.stop)&&rotated.clean_lease().is_err());
        assert!(honest_domain.peer(&honest).unwrap().clean_lease().is_ok());
        emit(serde_json::json!({
            "failure":failure,
            "synthetic_failure_control":true,
            "timestamp_attempt_asserted_stop":true,
            "marker_present":false,
            "reconstruction_shared_stop":true,
            "changed_path_detector_shared_stop":true,
            "unrelated_honest_lease":true
        }));
        return;
    }
    let mut run=Run::new(NAME);
    run.expect(&["timestamp_failure", "serialization_failure", "marker_open_failure", "reconstruction_and_rotation_share_stop", "fresh_process_unwritten_gap"]);
    for(case, fault, label)in [("timestamp", None, "timestamp_failure"), ("serialization", Some(Fault::Serialization), "serialization_failure"), ("marker_open", Some(Fault::MarkerCreate), "marker_open_failure")]{
        let f=Fixture::named(&run, case);
        let fresh=format!("fresh_{case}");
        f.save(&run, &fresh);
        let faults=fault.map(|v|vec![(v, 1)]).unwrap_or_default();
        let mut p=run.spawn(Role::Publisher, case, &[], &faults);
        p.wait_success();
        let value=child_receipt(&run, case, Role::Publisher);
        assert_eq!(value["marker_present"], false);
        assert_eq!(value["reconstruction_shared_stop"], true);
        assert_eq!(value["changed_path_detector_shared_stop"], true);
        assert_eq!(value["unrelated_honest_lease"], true);
        run.record(case, &value);
        run.complete(label);
        let mut o=run.spawn(Role::Opener, &fresh, &[], &[]);
        o.wait_success();
        assert_eq!(child_receipt(&run, &fresh, Role::Opener)["clean"], true);
    }
    run.complete("reconstruction_and_rotation_share_stop");
    run.complete("fresh_process_unwritten_gap");
    run.finish();
}
#[test] fn qf_peer_capacity_4096_isolated_child_is_atomic_and_preserves_existing(){
    const NAME:&str="transport::quic_poison::fence_tests::qf_peer_capacity_4096_isolated_child_is_atomic_and_preserves_existing";
    if support::child_role(NAME).is_some(){
        let f=Fixture::child();
        let d=f.open();
        let s=d.peer(&f.peer).unwrap();
        let stopped=enclave_core::rng::bytes32();
        let d2=process_peer_stops().reserve_domain(f.path.to_str().unwrap(), f.signer.verifying_key().to_bytes(), &[stopped]).unwrap();
        d2.peer(&stopped).unwrap().stop.store(true, Ordering::SeqCst);
        let owner=process_peer_stops();
        let mut next=2u64;
        loop{
            let count=owner.registry.lock().unwrap().peers.len();
            if count==MAX_PEERS{
                break;
            }
            let mut keys=Vec::new();
            for _ in 0..(MAX_PEERS-count).min(1024){
                let mut key=[0;32];
                key[..8].copy_from_slice(&next.to_be_bytes());
                next+=1;
                keys.push(key);
            }
            let dir=open_directory(&f.path).unwrap();
            let id=identity(&dir).unwrap();
            owner.reserve(normalized(f.path.to_str().unwrap()).unwrap(), dir, id, f.signer.verifying_key().to_bytes(), &keys).unwrap();
        }
        let before:BTreeMap<_,
        _>=owner.registry.lock().unwrap().peers.iter().map(|(k, v)|(*k, Arc::as_ptr(v)as usize)).collect();
        let fresh=enclave_core::rng::bytes32();
        let another=Fixture::new();
        assert!(owner.reserve_domain(another.path.to_str().unwrap(), another.signer.verifying_key().to_bytes(), &[f.peer, fresh]).unwrap_err().is("L2_POISON_REGISTRY_CAPACITY"));
        let registry=owner.registry.lock().unwrap();
        assert_eq!(registry.peers.len(), 4096);
        assert_eq!(registry.domains.len(), 1);
        for(k, p)in &before{
            assert_eq!(Arc::as_ptr(registry.peers.get(k).unwrap())as usize, *p);
        }
        drop(registry);
        assert!(s.clean_lease().is_ok());
        assert!(d2.peer(&stopped).unwrap().clean_lease().is_err());
        emit(serde_json::json!({
            "peer_count":4096,
            "domains":1,
            "atomic_refusal":true,
            "old_arcs_unchanged":true,
            "honest_lease":true,
            "stopped_refused":true,
            "filesystem_provisioned_peers":2
        }));
        return;
    }
    let mut run=Run::new(NAME);
    run.expect(&["isolated_real_registry_capacity_and_atomic_refusal"]);
    Fixture::named(&run, "capacity");
    let mut child=run.spawn(Role::Opener, "capacity", &[], &[]);
    child.wait_success();
    let receipt=child_receipt(&run, "capacity", Role::Opener);
    assert_eq!(receipt["peer_count"], 4096);
    assert_eq!(receipt["honest_lease"], true);
    run.record("capacity", &receipt);
    run.complete("isolated_real_registry_capacity_and_atomic_refusal");
    run.finish();
}
#[test] fn qf_domain_capacity_64_isolated_child_is_atomic_and_preserves_existing(){
    const NAME:&str="transport::quic_poison::fence_tests::qf_domain_capacity_64_isolated_child_is_atomic_and_preserves_existing";
    if support::child_role(NAME).is_some(){
        let f=Fixture::child();
        let d=f.open();
        let s=d.peer(&f.peer).unwrap();
        let stopped=enclave_core::rng::bytes32();
        let stopped_domain=process_peer_stops().reserve_domain(f.path.to_str().unwrap(), f.signer.verifying_key().to_bytes(), &[stopped]).unwrap();
        stopped_domain.peer(&stopped).unwrap().stop.store(true, Ordering::SeqCst);
        let mut fixtures=Vec::new();
        for _ in 1..64{
            let other=Fixture::new();
            process_peer_stops().reserve_domain(other.path.to_str().unwrap(), other.signer.verifying_key().to_bytes(), &[f.peer]).unwrap();
            fixtures.push(other);
        }
        let owner=process_peer_stops();
        let (pins, peers)={
            let r=owner.registry.lock().unwrap();
            (r.domains.clone(), r.peers.len())
        };
        let pins:BTreeMap<_,
        _>=pins.into_iter().map(|(k, v)|(k, (identity(&v.dir).unwrap(), v))).collect();
        let extra=Fixture::new();
        let newpeer=enclave_core::rng::bytes32();
        assert!(owner.reserve_domain(extra.path.to_str().unwrap(), extra.signer.verifying_key().to_bytes(), &[f.peer, newpeer]).unwrap_err().is("L2_POISON_REGISTRY_CAPACITY"));
        let after={
            let r=owner.registry.lock().unwrap();
            assert_eq!(r.domains.len(), 64);
            assert_eq!(r.peers.len(), peers);
            r.domains.clone()
        };
        for(k, (id, p))in pins{
            let pin=after.get(&k).unwrap();
            assert_eq!(identity(&pin.dir).unwrap(), id);
            assert!(Arc::ptr_eq(pin, &p));
        }
        assert!(s.clean_lease().is_ok());
        assert!(stopped_domain.peer(&stopped).unwrap().clean_lease().is_err());
        emit(serde_json::json!({
            "domain_count":64,
            "peer_count":peers,
            "atomic_refusal":true,
            "retained_original_fds":true,
            "honest_lease":true,
            "stopped_refused":true
        }));
        return;
    }
    let mut run=Run::new(NAME);
    run.expect(&["isolated_real_domain_capacity_and_atomic_refusal"]);
    Fixture::named(&run, "domains");
    let mut child=run.spawn(Role::Opener, "domains", &[], &[]);
    child.wait_success();
    let receipt=child_receipt(&run, "domains", Role::Opener);
    assert_eq!(receipt["domain_count"], 64);
    assert_eq!(receipt["honest_lease"], true);
    run.record("domains", &receipt);
    run.complete("isolated_real_domain_capacity_and_atomic_refusal");
    run.finish();
}
