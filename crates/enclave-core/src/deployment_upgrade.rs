//! Fixed selected-target start inhibition. Presence always denies activation.
//!
//! This read-only gate grants no upgrade, inactivity, release or resume power.
//! It never creates directories, opens private state or repairs a marker. Only
//! confident absence beneath the existing protected support parent can pass.
//! Callers must still enforce their normal activation authority and exclusion;
//! a past absence observation cannot authorize a later start after inhibition.

use super::{CheckedDeploymentTarget, MAX_DESCRIPTOR_BYTES};
use crate::{err, error::EnclaveResult, fail};
use sha2::{Digest, Sha256};
use std::{
    ffi::CString,
    fs::{File, Metadata},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{ffi::OsStrExt, fs::MetadataExt},
    },
    path::{Component, Path, PathBuf},
};

#[path = "deployment_directory_mode.rs"]
pub(super) mod directory_mode;

/// The sole supported marker name, relative to the selected support root.
pub const UPGRADE_INHIBITION_LEAF: &str = ".depot-upgrade-inhibited-v1.json";

#[derive(Clone, Copy, PartialEq, Eq)]
struct DirectoryStamp {
    dev: u64,
    ino: u64,
    uid: u32,
    gid: u32,
    mode: u32,
}
impl DirectoryStamp {
    fn of(m: &Metadata) -> Self {
        Self {
            dev: m.dev(),
            ino: m.ino(),
            uid: m.uid(),
            gid: m.gid(),
            mode: m.mode(),
        }
    }
}
struct Node {
    file: File,
    name: Option<CString>,
    stamp: DirectoryStamp,
    mode_change: Option<directory_mode::VerifiedModeChange>,
}
fn stat(file: &File) -> EnclaveResult<Metadata> {
    file.metadata()
        .map_err(|_| err!(EACCES, "UPGRADE_INHIBITION_PARENT"))
}
fn protected(m: &Metadata, owner: u32) -> bool {
    m.is_dir() && (m.uid() == 0 || m.uid() == owner) && m.mode() & 0o022 == 0
}
fn own(fd: i32) -> EnclaveResult<File> {
    if fd < 0 {
        fail!(EACCES, "UPGRADE_INHIBITION_PARENT");
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}
fn open_child(parent: &File, name: &CString) -> EnclaveResult<File> {
    own(unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY
                | libc::O_DIRECTORY
                | libc::O_NOFOLLOW
                | libc::O_NONBLOCK
                | libc::O_CLOEXEC,
        )
    })
}
struct Ancestry {
    nodes: Vec<Node>,
    owner: u32,
    base: PathBuf,
}
impl Ancestry {
    fn node(file: File, name: Option<CString>, owner: u32) -> EnclaveResult<Node> {
        let m = stat(&file)?;
        if !protected(&m, owner) {
            fail!(EACCES, "UPGRADE_INHIBITION_PARENT");
        }
        Ok(Node {
            file,
            name,
            stamp: DirectoryStamp::of(&m),
            mode_change: None,
        })
    }
    fn append(&mut self, part: &std::ffi::OsStr) -> EnclaveResult<()> {
        let name =
            CString::new(part.as_bytes()).map_err(|_| err!(EINVAL, "UPGRADE_INHIBITION_PATH"))?;
        let file = open_child(self.parent(), &name)?;
        self.nodes.push(Self::node(file, Some(name), self.owner)?);
        Ok(())
    }
    fn open(path: &Path) -> EnclaveResult<Self> {
        super::normal_path(path)?;
        #[cfg(target_os = "macos")]
        let path = super::normalized_path(path)?;
        #[cfg(not(target_os = "macos"))]
        let path = path.to_owned();
        let root = CString::new("/").expect("literal");
        let file = own(unsafe {
            libc::open(
                root.as_ptr(),
                libc::O_RDONLY
                    | libc::O_DIRECTORY
                    | libc::O_NOFOLLOW
                    | libc::O_NONBLOCK
                    | libc::O_CLOEXEC,
            )
        })?;
        let mut result = Self {
            nodes: vec![Self::node(file, None, 0)?],
            owner: 0,
            base: PathBuf::from("/"),
        };
        for component in path.components() {
            match component {
                Component::RootDir => (),
                Component::Normal(part) => result.append(part)?,
                _ => fail!(EINVAL, "UPGRADE_INHIBITION_PATH"),
            }
        }
        result.current()?;
        Ok(result)
    }
    fn parent(&self) -> &File {
        &self.nodes.last().expect("root node").file
    }
    fn current(&self) -> EnclaveResult<()> {
        self.current_with_mode(None)
    }
    #[cfg(test)]
    fn fixture(path: &Path, children: &[&str]) -> EnclaveResult<Self> {
        // Explicit private test anchor; production always starts at / with UID0.
        let name = CString::new(path.as_os_str().as_bytes()).unwrap();
        let owner = unsafe { libc::geteuid() };
        let file = own(unsafe {
            libc::open(
                name.as_ptr(),
                libc::O_RDONLY
                    | libc::O_DIRECTORY
                    | libc::O_NOFOLLOW
                    | libc::O_NONBLOCK
                    | libc::O_CLOEXEC,
            )
        })?;
        let mut result = Self {
            nodes: vec![Self::node(file, None, owner)?],
            owner,
            base: path.to_owned(),
        };
        for child in children {
            result.append(std::ffi::OsStr::new(child))?;
        }
        result.current()?;
        Ok(result)
    }
}
fn marker_absent(parent: &File) -> EnclaveResult<()> {
    let leaf = CString::new(UPGRADE_INHIBITION_LEAF).expect("literal");
    let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
    // Do not open a FIFO/device or follow even a dangling symlink. All existing
    // inode types, arbitrary bytes, partial writes and future schemas deny.
    let found = unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            leaf.as_ptr(),
            metadata.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if found == 0 {
        fail!(EACCES, "DEPLOYMENT_UPGRADE_INHIBITED");
    }
    if std::io::Error::last_os_error().raw_os_error() != Some(libc::ENOENT) {
        fail!(EACCES, "UPGRADE_INHIBITION_STATUS_UNKNOWN");
    }
    Ok(())
}
fn descriptor_current(path: &Path, digest: &str) -> EnclaveResult<()> {
    let bytes = super::read_protected_public(path, MAX_DESCRIPTOR_BYTES)?;
    if hex::encode(Sha256::digest(bytes)) != digest {
        fail!(ESTALE, "DEPLOYMENT_CHANGED");
    }
    Ok(())
}

/// Read-only held protected support ancestry for the fixed inhibition protocol.
/// There is no arbitrary-path constructor, deserializer or creation API. The
/// borrowed directory is for the trusted fixed-leaf native writer; this value
/// alone supplies no mutation, installation, activation or recovery authority.
pub struct HeldUpgradeDirectory {
    ancestry: Ancestry,
    config: PathBuf,
    descriptor: String,
    support: PathBuf,
}
impl HeldUpgradeDirectory {
    pub(super) fn retains_directory_identity(&self, dev: u64, ino: u64) -> bool {
        self.ancestry
            .nodes
            .iter()
            .any(|node| node.stamp.dev == dev && node.stamp.ino == ino)
    }
    pub(super) fn completed_mode_change(&self, path: &Path) -> bool {
        self.ancestry.completed_mode_change(path)
    }
    pub(super) fn unchanged_private_directory(&self, path: &Path) -> bool {
        self.ancestry.unchanged_private_directory(path)
    }
    pub(super) fn change_original_mode(
        &mut self,
        checked: &CheckedDeploymentTarget,
        path: &Path,
        check: &mut impl FnMut(&File) -> Vec<crate::error::EnclaveError>,
        observed: &mut Vec<crate::error::EnclaveError>,
        sync: &mut impl FnMut(&File) -> EnclaveResult<()>,
    ) -> directory_mode::ModeOutcome {
        let binding = if self.config != checked.config_path()
            || self.descriptor != checked.descriptor_sha256()
            || self.support != checked.target().layout.support_root
        {
            Err(err!(ESTALE, "DEPLOYMENT_CHANGED"))
        } else {
            Ok(())
        };
        if let Err(error) = binding {
            return directory_mode::ModeOutcome::refused(path, error);
        }
        let config = &self.config;
        let descriptor = &self.descriptor;
        self.ancestry.change_original_mode(
            path,
            (0, 0),
            true,
            &mut |parent| {
                let mut checks = check(parent);
                if let Err(error) = descriptor_current(config, descriptor) {
                    checks.push(error);
                }
                checks
            },
            observed,
            sync,
        )
    }
    /// Hold the existing selected support route under root-owned nofollow
    /// ancestry. Missing/unsafe parents refuse, including on a first install.
    pub fn open(checked: &CheckedDeploymentTarget) -> EnclaveResult<Self> {
        descriptor_current(checked.config_path(), checked.descriptor_sha256())?;
        let result = Self {
            ancestry: Ancestry::open(&checked.target().layout.support_root)?,
            config: checked.config_path().to_owned(),
            descriptor: checked.descriptor_sha256().into(),
            support: checked.target().layout.support_root.clone(),
        };
        result.assert_current(checked)?;
        Ok(result)
    }
    /// Recheck exact descriptor bytes and every held and named ancestor.
    pub fn assert_current(&self, checked: &CheckedDeploymentTarget) -> EnclaveResult<()> {
        if self.config != checked.config_path()
            || self.descriptor != checked.descriptor_sha256()
            || self.support != checked.target().layout.support_root
        {
            fail!(ESTALE, "DEPLOYMENT_CHANGED");
        }
        descriptor_current(&self.config, &self.descriptor)?;
        self.ancestry.current()
    }
    /// Borrow the held parent without returning ownership or a writable file.
    pub fn directory(&self) -> &File {
        self.ancestry.parent()
    }
    /// Require confidently absent fixed marker, with no parsing or repair.
    pub fn assert_marker_absent(&self) -> EnclaveResult<()> {
        self.ancestry.current()?;
        marker_absent(self.directory())?;
        self.ancestry.current()
    }
}

/// Universal selected-target activation check. Both roles are subject to any
/// marker. Equal old/candidate pins and unrecognized marker bytes cannot pass.
/// No selection/recheck/stop path should call this as general admission.
pub fn assert_start_allowed(checked: &CheckedDeploymentTarget) -> EnclaveResult<()> {
    let parent = HeldUpgradeDirectory::open(checked)?;
    parent.assert_marker_absent()?;
    parent.assert_current(checked)?;
    parent.assert_marker_absent()
}

#[cfg(test)]
#[path = "deployment_upgrade_tests.rs"]
mod tests;
