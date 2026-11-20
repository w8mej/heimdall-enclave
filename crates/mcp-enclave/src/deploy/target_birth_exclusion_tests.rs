//! Ordinary SOFTWARE owned-outcome tests with actual OS flock files. These
//! exercise the private retention resolver used by the actual wrapper; no
//! NativeSelectedCandidateBirth, HostMaintenanceGuard, checked deployment,
//! accounts, SOFTWARE approval, core EX capability or excluded owner is faked.
//! Native public constructor positive acceptance remains UNEXERCISED.
use super::*;
use std::os::unix::fs::{OpenOptionsExt,PermissionsExt};

struct Fixture {root:PathBuf}
impl Fixture {
    fn new()->Self {
        let root=std::env::current_dir().unwrap().join(format!(".birth-exclusion-{}",hex::encode(enclave_core::rng::bytes32())));
        std::fs::create_dir(&root).unwrap();std::fs::set_permissions(&root,std::fs::Permissions::from_mode(0o700)).unwrap();
        let leaf=root.join(STARTUP_LIFETIME_LEAF);
        let file=std::fs::OpenOptions::new().write(true).create_new(true).mode(0o644).open(leaf).unwrap();
        file.set_permissions(std::fs::Permissions::from_mode(0o644)).unwrap();
        std::fs::write(root.join(UPGRADE_INHIBITION_LEAF),b"synthetic owned denial only").unwrap();Self {root}
    }
    fn open(&self)->File {
        std::fs::OpenOptions::new().read(true)
            .custom_flags(libc::O_NOFOLLOW|libc::O_NONBLOCK|libc::O_CLOEXEC)
            .open(self.root.join(STARTUP_LIFETIME_LEAF)).unwrap()
    }
    fn exclusive(&self)->File {
        let file=self.open();assert_eq!(unsafe{libc::flock(file.as_raw_fd(),libc::LOCK_EX|libc::LOCK_NB)},0);
        file
    }
    fn blocked(&self) {
        let observer=self.open();
        assert_eq!(unsafe{libc::flock(observer.as_raw_fd(),libc::LOCK_SH|libc::LOCK_NB)},-1);
        let error=std::io::Error::last_os_error().raw_os_error();
        assert!(error==Some(libc::EWOULDBLOCK)||error==Some(libc::EAGAIN));
    }
    fn names(&self)->(u64,u64,u32,u64,Vec<u8>) {
        let m=std::fs::symlink_metadata(self.root.join(STARTUP_LIFETIME_LEAF)).unwrap();
        (m.dev(),m.ino(),m.mode(),m.len(),std::fs::read(self.root.join(UPGRADE_INHIBITION_LEAF)).unwrap())
    }
}
impl Drop for Fixture {fn drop(&mut self){let _=std::fs::remove_dir_all(&self.root);}}

#[test]
fn operation_refusal_retains_actual_original_os_ex_until_opaque_refusal_is_dropped() {
    let fixture=Fixture::new();let owner=fixture.exclusive();let before=fixture.names();
    let refusal=resolve_owned(owner,Err(err!(EACCES,"EXCLUSION_FIXTURE_OPERATION")),Vec::new(),Vec::new())
        .err().expect("original refusal");
    assert!(refusal.error.is("EXCLUSION_FIXTURE_OPERATION"));fixture.blocked();
    assert_eq!(before,fixture.names());flags(&refusal.owner,libc::O_RDONLY).unwrap();
    assert_eq!((refusal.owner.metadata().unwrap().dev(),refusal.owner.metadata().unwrap().ino()),(before.0,before.1));
    drop(refusal);drop(fixture.exclusive());assert_eq!(before,fixture.names());
}

#[test]
fn successful_operation_with_final_refusal_keeps_ex_and_preserves_every_final_error() {
    let fixture=Fixture::new();let owner=fixture.exclusive();
    let refusal=resolve_owned(owner,Ok(()),Vec::new(),vec![err!(ESTALE,"EXCLUSION_FIXTURE_FINAL_FIRST"),
        err!(EACCES,"EXCLUSION_FIXTURE_FINAL_SECOND")]).err().expect("final refusal");
    assert!(refusal.error.is("EXCLUSION_FIXTURE_FINAL_FIRST"));assert_eq!(refusal.final_errors.len(),2);
    assert!(refusal.final_errors[0].is("EXCLUSION_FIXTURE_FINAL_FIRST"));
    assert!(refusal.final_errors[1].is("EXCLUSION_FIXTURE_FINAL_SECOND"));
    fixture.blocked();drop(refusal);drop(fixture.exclusive());
}

#[test]
fn original_error_precedes_final_errors_and_all_boundary_diagnostics_survive_with_owner() {
    let fixture=Fixture::new();let refusal=resolve_owned(fixture.exclusive(),
        Err(err!(EIO,"EXCLUSION_FIXTURE_PRIMARY")),vec![err!(ESTALE,"EXCLUSION_FIXTURE_BOUNDARY")],
        vec![err!(EACCES,"EXCLUSION_FIXTURE_FINAL")]).err().expect("primary refusal");
    assert!(refusal.error.is("EXCLUSION_FIXTURE_PRIMARY"));
    assert_eq!(refusal.boundary_errors.len(),1);assert!(refusal.boundary_errors[0].is("EXCLUSION_FIXTURE_BOUNDARY"));
    assert_eq!(refusal.final_errors.len(),1);assert!(refusal.final_errors[0].is("EXCLUSION_FIXTURE_FINAL"));
    fixture.blocked();drop(refusal);drop(fixture.exclusive());
}

#[test]
fn success_keeps_same_readonly_original_lock_without_name_permission_or_denial_changes() {
    let fixture=Fixture::new();let owner=fixture.exclusive();let fd=owner.as_raw_fd();let before=fixture.names();
    let retained=match resolve_owned(owner,Ok(()),Vec::new(),Vec::new()) {
        Ok(owner)=>owner,Err(_)=>panic!("actual synthetic lock should remain owned"),
    };
    assert_eq!(retained.as_raw_fd(),fd);flags(&retained,libc::O_RDONLY).unwrap();fixture.blocked();
    assert_eq!(fixture.names(),before);drop(retained);drop(fixture.exclusive());
}

#[test]
fn optional_actual_partial_lock_is_not_lost_when_later_step_refuses() {
    let fixture=Fixture::new();let before=fixture.names();
    let refusal=resolve_owned(Some(fixture.exclusive()),Err(err!(EACCES,"EXCLUSION_FIXTURE_POST_LOCK")),
        Vec::new(),vec![err!(ESTALE,"EXCLUSION_FIXTURE_POST_BINDING")]).err().expect("post-lock refusal");
    assert!(refusal.owner.is_some());fixture.blocked();assert_eq!(fixture.names(),before);
    assert!(refusal.error.is("EXCLUSION_FIXTURE_POST_LOCK"));assert_eq!(refusal.final_errors.len(),1);
    drop(refusal);drop(fixture.exclusive());
}

#[test]
fn nested_original_failure_owner_remains_owned_through_outer_refusal_without_unlock_or_reacquire() {
    let fixture=Fixture::new();let original=resolve_owned(fixture.exclusive(),
        Err(err!(EACCES,"EXCLUSION_FIXTURE_INNER")),Vec::new(),vec![err!(ESTALE,"EXCLUSION_FIXTURE_INNER_FINAL")])
        .err().expect("original post-lock refusal");
    let fd=original.owner.as_raw_fd();
    let outer=resolve_owned(original,Err(err!(EIO,"EXCLUSION_FIXTURE_OUTER")),
        vec![err!(ESTALE,"EXCLUSION_FIXTURE_OUTER_BOUNDARY")],Vec::new()).err().expect("outer refusal");
    fixture.blocked();assert_eq!(outer.owner.owner.as_raw_fd(),fd);
    assert!(outer.error.is("EXCLUSION_FIXTURE_OUTER"));assert!(outer.owner.error.is("EXCLUSION_FIXTURE_INNER"));
    assert!(outer.owner.final_errors[0].is("EXCLUSION_FIXTURE_INNER_FINAL"));
    drop(outer);drop(fixture.exclusive());
}
