//! Read-only native filesystem protection checks on original held descriptors.
//! No ACL is modified or repaired. Unsupported and ambiguous observations deny.

use std::fs::File;
use enclave_core::{error::EnclaveResult, fail};

#[cfg(any(target_os="macos",test))]
enum AclObservation {
    Missing {errno:i32},
    Allocated {valid:i32,first:i32,errno:i32,entry_null:bool,freed:i32},
}

#[cfg(any(target_os="macos",test))]
fn require_empty(observation:AclObservation)->EnclaveResult<()> {
    match observation {
        // Darwin filesec_get_property reports absent FILESEC_ACL as ENOENT.
        AclObservation::Missing {errno:libc::ENOENT}=>Ok(()),
        AclObservation::Missing {..}=>{fail!(EACCES,"NATIVE_ACL_INSPECTION_REQUIRED");},
        // Darwin returns -1/fresh EINVAL for empty FIRST, and 0 for an entry.
        AclObservation::Allocated {valid:0,first:-1,errno:libc::EINVAL,entry_null:true,freed:0}=>Ok(()),
        AclObservation::Allocated {..}=>{fail!(EACCES,"NATIVE_EXTENDED_ACL_REFUSED");},
    }
}

/// Require positively observed absence of every native extended ACL entry.
/// The caller separately checks original held/named identity, owner and mode.
/// A native call on another platform refuses; there is no permission fallback.
pub(crate) fn require_no_extended_acl(file:&File)->EnclaveResult<()> {
    #[cfg(target_os="macos")]
    {
        use std::{ffi::c_void,os::fd::AsRawFd};
        unsafe extern "C" {
            fn acl_get_fd_np(fd:libc::c_int,kind:libc::c_int)->*mut c_void;
            fn acl_valid(acl:*mut c_void)->libc::c_int;
            fn acl_get_entry(acl:*mut c_void,entry_id:libc::c_int,entry:*mut *mut c_void)->libc::c_int;
            fn acl_free(object:*mut c_void)->libc::c_int;
        }
        // Clear thread-local errno before EACH result whose exact failure
        // distinguishes confident absence from unknown inspection.
        unsafe {*libc::__error()=0;}
        let acl=unsafe {acl_get_fd_np(file.as_raw_fd(),0x100)}; // ACL_TYPE_EXTENDED.
        let get_errno=std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        if acl.is_null() {return require_empty(AclObservation::Missing {errno:get_errno});}
        let valid=unsafe {acl_valid(acl)};
        let mut entry=std::ptr::null_mut();
        let (first,errno)=if valid==0 {
            unsafe {*libc::__error()=0;}
            let first=unsafe {acl_get_entry(acl,0,&mut entry)}; // ACL_FIRST_ENTRY.
            (first,std::io::Error::last_os_error().raw_os_error().unwrap_or(0))
        }else{(0,0)}; // Never inspect entries from an invalid ACL.
        // Always free an allocated ACL, even when validation or lookup failed.
        let freed=unsafe {acl_free(acl)};
        require_empty(AclObservation::Allocated {valid,first,errno,entry_null:entry.is_null(),freed})
    }
    #[cfg(not(target_os="macos"))]
    {let _=file;fail!(ENOSYS,"NATIVE_ACL_UNSUPPORTED");}
}

// Native ACL mutations exist only as setup on each test's own original inode.
#[cfg(all(test,target_os="macos"))]
pub(crate) mod acl_fixture {
    use std::{ffi::c_void,fs::File,os::{fd::AsRawFd,unix::fs::MetadataExt}};
    unsafe extern "C" {
        fn acl_init(count:libc::c_int)->*mut c_void;
        fn acl_create_entry(acl:*mut *mut c_void,entry:*mut *mut c_void)->libc::c_int;
        fn acl_set_tag_type(entry:*mut c_void,tag:libc::c_int)->libc::c_int;
        fn acl_set_qualifier(entry:*mut c_void,qualifier:*const c_void)->libc::c_int;
        fn acl_get_permset(entry:*mut c_void,perms:*mut *mut c_void)->libc::c_int;
        fn acl_add_perm(perms:*mut c_void,permission:libc::c_int)->libc::c_int;
        fn acl_set_fd_np(fd:libc::c_int,acl:*mut c_void,kind:libc::c_int)->libc::c_int;
        fn acl_free(object:*mut c_void)->libc::c_int;
        fn mbr_uid_to_uuid(uid:libc::uid_t,uuid:*mut u8)->libc::c_int;
    }
    struct Acl(*mut c_void);
    impl Drop for Acl {fn drop(&mut self){if !self.0.is_null(){unsafe{acl_free(self.0);}}}}

    pub(crate) fn set_empty(file:&File) {install(file,false);}
    pub(crate) fn set_allow(file:&File) {install(file,true);}
    fn install(file:&File,present:bool) {
        let before=file.metadata().unwrap();
        assert_eq!(before.uid(),unsafe{libc::geteuid()},"only own original fixture inode may be changed");
        assert!(before.is_dir()||before.is_file());
        let mut acl=Acl(unsafe{acl_init(if present{1}else{0})});assert!(!acl.0.is_null());
        if present {
            let mut uuid=[0u8;16];assert_eq!(unsafe{mbr_uid_to_uuid(libc::geteuid(),uuid.as_mut_ptr())},0);
            let mut entry=std::ptr::null_mut();assert_eq!(unsafe{acl_create_entry(&mut acl.0,&mut entry)},0);
            assert!(!entry.is_null());assert_eq!(unsafe{acl_set_tag_type(entry,1)},0); // EXTENDED_ALLOW.
            assert_eq!(unsafe{acl_set_qualifier(entry,uuid.as_ptr().cast())},0);
            let mut perms=std::ptr::null_mut();assert_eq!(unsafe{acl_get_permset(entry,&mut perms)},0);
            assert!(!perms.is_null());assert_eq!(unsafe{acl_add_perm(perms,2)},0); // READ_DATA/LIST_DIRECTORY.
        }
        assert_eq!(unsafe{acl_set_fd_np(file.as_raw_fd(),acl.0,0x100)},0);
        let after=file.metadata().unwrap();
        assert_eq!((before.dev(),before.ino(),before.uid(),before.gid(),before.mode()),
            (after.dev(),after.ino(),after.uid(),after.gid(),after.mode()),"ACL setup must preserve original identity/uid/mode");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_fresh_native_absence_and_valid_empty_acl_are_accepted() {
        require_empty(AclObservation::Missing {errno:libc::ENOENT}).unwrap();
        require_empty(AclObservation::Allocated {valid:0,first:-1,errno:libc::EINVAL,entry_null:true,freed:0}).unwrap();
        for errno in [0,libc::EINVAL,libc::EIO,libc::EBADF,libc::ENOTSUP,libc::EACCES] {
            let error=require_empty(AclObservation::Missing {errno}).unwrap_err();
            assert!(error.is("NATIVE_ACL_INSPECTION_REQUIRED"));assert!(error.detail.is_empty());
        }
    }

    #[test]
    fn entries_invalid_acl_and_every_ambiguous_lookup_or_free_result_refuse() {
        for observation in [
            AclObservation::Allocated {valid:0,first:0,errno:0,entry_null:false,freed:0},
            AclObservation::Allocated {valid:0,first:0,errno:libc::EINVAL,entry_null:true,freed:0},
            AclObservation::Allocated {valid:0,first:1,errno:0,entry_null:false,freed:0},
            AclObservation::Allocated {valid:-1,first:-1,errno:libc::EINVAL,entry_null:true,freed:0},
            AclObservation::Allocated {valid:0,first:-1,errno:0,entry_null:true,freed:0},
            AclObservation::Allocated {valid:0,first:-1,errno:libc::ENOENT,entry_null:true,freed:0},
            AclObservation::Allocated {valid:0,first:-1,errno:libc::EIO,entry_null:true,freed:0},
            AclObservation::Allocated {valid:0,first:-1,errno:libc::EINVAL,entry_null:false,freed:0},
            AclObservation::Allocated {valid:0,first:-1,errno:libc::EINVAL,entry_null:true,freed:-1},
        ] {
            let error=require_empty(observation).unwrap_err();
            assert!(error.is("NATIVE_EXTENDED_ACL_REFUSED"));assert!(error.detail.is_empty());
        }
    }

    #[cfg(not(target_os="macos"))]
    #[test]
    fn explicit_native_acl_inspection_has_no_nonmacos_success_fallback() {
        let file=File::open(Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml")).unwrap();
        assert!(require_no_extended_acl(&file).unwrap_err().is("NATIVE_ACL_UNSUPPORTED"));
    }

    #[cfg(not(target_os="macos"))]
    use std::path::Path;

    #[cfg(target_os="macos")]
    #[test]
    fn actual_native_acl_absence_then_allow_refusal_uses_only_original_owned_file_and_directory() {
        use std::{fs::{DirBuilder,OpenOptions},io::Write,
            os::unix::fs::{DirBuilderExt,MetadataExt,OpenOptionsExt},path::{Path,PathBuf}};
        let parent=Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target");
        DirBuilder::new().recursive(true).mode(0o700).create(&parent).unwrap();
        let path=parent.join(format!("native-acl-{}",hex::encode(enclave_core::rng::bytes32())));
        DirBuilder::new().mode(0o700).create(&path).unwrap();
        struct Fixture(PathBuf);
        impl Drop for Fixture {fn drop(&mut self){let _=std::fs::remove_dir_all(&self.0);}}
        let _fixture=Fixture(path.clone());
        let directory=OpenOptions::new().read(true)
            .custom_flags(libc::O_DIRECTORY|libc::O_NOFOLLOW|libc::O_CLOEXEC).open(&path).unwrap();
        let original=directory.metadata().unwrap();let named=std::fs::symlink_metadata(&path).unwrap();
        assert_eq!((original.dev(),original.ino(),original.uid()),(named.dev(),named.ino(),unsafe{libc::geteuid()}));
        let file_path=path.join("public");
        let mut file=OpenOptions::new().read(true).write(true).create_new(true).mode(0o600)
            .custom_flags(libc::O_NOFOLLOW|libc::O_CLOEXEC).open(&file_path).unwrap();
        file.write_all(b"public ACL fixture").unwrap();
        for (held,named_path) in [(&directory,path.as_path()),(&file,file_path.as_path())] {
            let before=held.metadata().unwrap();
            acl_fixture::set_empty(held);require_no_extended_acl(held).unwrap();
            // A stale success-shaped errno must not hide a present ACL.
            acl_fixture::set_allow(held);
            unsafe{*libc::__error()=libc::ENOENT;}
            assert!(require_no_extended_acl(held).unwrap_err().is("NATIVE_EXTENDED_ACL_REFUSED"));
            let after=std::fs::symlink_metadata(named_path).unwrap();
            assert_eq!((before.dev(),before.ino(),before.uid(),before.gid(),before.mode()),
                (after.dev(),after.ino(),after.uid(),after.gid(),after.mode()));
            acl_fixture::set_empty(held);require_no_extended_acl(held).unwrap();
        }
    }
}
