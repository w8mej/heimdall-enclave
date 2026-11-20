//! Real kernel advisory ownership and strict path-policy checks.
use enclave_core::sealed::StateDirectoryLease;
use std::{fs, path::PathBuf, os::unix::{ffi::OsStrExt, fs::{DirBuilderExt, PermissionsExt, symlink}}};

struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let path=std::env::temp_dir().canonicalize().unwrap()
            .join(format!("dl{}-{:x}",std::process::id(),enclave_core::rng::u64()));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();Self(path)
    }
}
impl Drop for Directory {fn drop(&mut self){let _=fs::remove_dir_all(&self.0);}}
fn refused(path:&std::path::Path)->bool {
    StateDirectoryLease::acquire(path).as_ref().is_err_and(|e|e.is("STATE_PRIVATE_PATH"))
}

#[test]
fn directory_lease_conflicts_on_same_inode_and_releases_without_lockfile() {
    let root=Directory::new();let path=root.0.join("state");
    let first=StateDirectoryLease::acquire(&path).unwrap();
    let busy=StateDirectoryLease::acquire(&path.join("."));
    assert!(busy.as_ref().is_err_and(|e|e.is("STATE_DIRECTORY_BUSY")));
    assert_eq!(fs::read_dir(&path).unwrap().count(),0,"lease creates no state or lock file");
    drop(first);
    let reopened=StateDirectoryLease::acquire(&path);assert!(reopened.is_ok());
}

#[test]
fn directory_lease_independent_inodes_can_be_owned_together() {
    let root=Directory::new();let first=StateDirectoryLease::acquire(&root.0.join("a")).unwrap();
    let second=StateDirectoryLease::acquire(&root.0.join("b"));assert!(second.is_ok());drop(first);
}

#[test]
fn directory_lease_refuses_relative_parent_traversal_and_filesystem_root() {
    let root=Directory::new();
    assert!(refused(std::path::Path::new("relative-state")));
    assert!(refused(&root.0.join("../unopened-state")));
    assert!(refused(std::path::Path::new("/")));
    assert_eq!(fs::read_dir(&root.0).unwrap().count(),0);
}

#[test]
fn directory_lease_refuses_symlink_leaf_and_ancestor_without_target_mutation() {
    let root=Directory::new();let target=root.0.join("actual");
    fs::DirBuilder::new().mode(0o700).create(&target).unwrap();
    let link=root.0.join("link");symlink(&target,&link).unwrap();
    assert!(refused(&link));assert!(refused(&link.join("state")));
    assert_eq!(fs::read_dir(&target).unwrap().count(),0);
}

#[test]
fn directory_lease_refuses_public_leaf_and_writable_ancestor_without_repairing_modes() {
    let root=Directory::new();let leaf=root.0.join("public");
    fs::DirBuilder::new().mode(0o700).create(&leaf).unwrap();
    fs::set_permissions(&leaf,fs::Permissions::from_mode(0o755)).unwrap();
    assert!(refused(&leaf));
    let ancestor=root.0.join("writable");fs::create_dir(&ancestor).unwrap();
    fs::set_permissions(&ancestor,fs::Permissions::from_mode(0o770)).unwrap();
    assert!(refused(&ancestor.join("state")));assert!(!ancestor.join("state").exists());
    assert_eq!(fs::metadata(&leaf).unwrap().permissions().mode()&0o777,0o755);
    assert_eq!(fs::metadata(&ancestor).unwrap().permissions().mode()&0o777,0o770);
}

#[test]
fn directory_lease_refuses_file_and_fifo_leaf_without_waiting_for_fifo_peer() {
    let root=Directory::new();let file=root.0.join("file");let fifo=root.0.join("fifo");
    fs::write(&file,b"owned sentinel").unwrap();
    let name=std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe{libc::mkfifo(name.as_ptr(),0o600)},0);
    assert!(refused(&file));assert!(refused(&fifo));
    assert_eq!(fs::read(&file).unwrap(),b"owned sentinel");
}

#[cfg(target_os="macos")]
#[test]
fn directory_lease_darwin_fixed_tmp_alias_conflicts_with_held_private_tmp_inode() {
    let name=format!("dl-alias-{:x}",enclave_core::rng::u64());
    let root=Directory(PathBuf::from("/private/tmp").join(&name));
    fs::DirBuilder::new().mode(0o700).create(&root.0).unwrap();
    let first=StateDirectoryLease::acquire(&root.0).unwrap();
    assert!(StateDirectoryLease::acquire(&PathBuf::from("/tmp").join(name))
        .as_ref().is_err_and(|e|e.is("STATE_DIRECTORY_BUSY")));drop(first);
}
