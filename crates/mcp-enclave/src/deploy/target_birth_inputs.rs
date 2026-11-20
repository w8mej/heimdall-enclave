//! Bounded, unadmitted public-package source snapshots for later private birth.
//!
//! This owner only opens existing sources and reads checked chunks. Supplied
//! roles, hashes and lengths are expectations, not provenance, publicness,
//! signature verification, destination admission or deployment authority.
//! No destination, guard, checked target, candidate execution or selection is
//! involved. Future importers must independently close the actual destination
//! set and verify all policy, inventory, software and native authority.

use std::{collections::BTreeSet, os::{fd::AsRawFd,unix::{ffi::OsStrExt,
    fs::{FileExt,MetadataExt}}}, path::{Component,Path,PathBuf}};
use enclave_core::{deployment::normalized_path,error::EnclaveResult,err,fail};
use crate::ctl::{HeldFile,HeldPaths};

const MAX_FILES:usize=128;
const MAX_COMPONENTS:usize=96;
const MAX_TOTAL_BYTES:u64=2*1024*1024*1024;
const MAX_FILE_BYTES:u64=512*1024*1024;
const MAX_PUBLIC_BYTES:u64=1024*1024;
const MAX_CONFIG_BYTES:u64=16*1024;
const MAX_KEY_BYTES:u64=128;
const MAX_CHUNK:usize=64*1024;

/// Inert source labels, never permission to create the corresponding target.
/// A staged label is relative to the independently supplied inventory's stage;
/// this reader does not parse or certify that inventory.
#[derive(Clone,PartialEq,Eq,PartialOrd,Ord)]
pub(crate) enum BirthSourceRole {
    Inventory,
    CustodyManifest,
    CustodyPolicy,
    PolicyIssuerKey,
    InventoryIssuerKey,
    EnvelopeIssuerKey,
    Staged(PathBuf),
}
impl BirthSourceRole {
    fn maximum(&self)->EnclaveResult<u64> {
        Ok(match self {
            Self::Inventory=>MAX_PUBLIC_BYTES,
            Self::CustodyManifest|Self::CustodyPolicy=>MAX_CONFIG_BYTES,
            Self::PolicyIssuerKey|Self::InventoryIssuerKey|Self::EnvelopeIssuerKey=>MAX_KEY_BYTES,
            Self::Staged(relative)=>{
                let text=relative.to_str().ok_or_else(||err!(EINVAL,"BIRTH_INPUT_ROLE"))?;
                if text.is_empty()||text.len()>4096||!text.is_ascii()
                    ||text.bytes().any(|b|b.is_ascii_control()||b"'\"`$;&|<>()\\".contains(&b))
                    ||!relative.components().all(|p|matches!(p,Component::Normal(_)))
                    ||relative.components().collect::<PathBuf>().as_os_str()!=relative.as_os_str() {
                    fail!(EINVAL,"BIRTH_INPUT_ROLE");
                }
                path_bound(relative)?;MAX_FILE_BYTES
            },
        })
    }
}

/// Caller-supplied inert expectations. No source is opened by construction.
/// No Debug/Serialize implementation exposes possibly linkable source routes.
pub(crate) struct BirthSourceSpec {
    pub(crate) role:BirthSourceRole,
    pub(crate) path:PathBuf,
    pub(crate) sha256:String,
    pub(crate) size:u64,
}
struct SourcePlan {package:PathBuf,specs:Vec<BirthSourceSpec>}
fn path_bound(path:&Path)->EnclaveResult<()> {
    if path.components().count()>MAX_COMPONENTS
        ||path.components().any(|p|matches!(p,Component::Normal(n) if n.as_bytes().len()>255)) {
        fail!(E2BIG,"BIRTH_INPUT_PATH_BOUND");
    }Ok(())
}
fn folded(path:&Path)->EnclaveResult<PathBuf> {
    Ok(PathBuf::from(path.to_str().ok_or_else(||err!(EINVAL,"BIRTH_INPUT_PATH"))?.to_ascii_lowercase()))
}
impl SourcePlan {
    fn build(package:&Path,specs:&[BirthSourceSpec])->EnclaveResult<Self> {
        let package=normalized_path(package)?;path_bound(&package)?;
        if specs.is_empty()||specs.len()>MAX_FILES {fail!(E2BIG,"BIRTH_INPUT_COUNT");}
        let mut roles=BTreeSet::new();let mut paths:Vec<PathBuf>=Vec::new();
        let mut total=0u64;let mut planned=Vec::new();
        for spec in specs {
            let path=normalized_path(&spec.path)?;path_bound(&path)?;
            let suffix=path.strip_prefix(&package).map_err(|_|err!(EACCES,"BIRTH_INPUT_PACKAGE_ESCAPE"))?;
            if suffix.as_os_str().is_empty(){fail!(EACCES,"BIRTH_INPUT_PACKAGE_ESCAPE");}
            let maximum=spec.role.maximum()?;
            if spec.size==0||spec.size>maximum {fail!(E2BIG,"BIRTH_INPUT_SIZE");}
            if spec.sha256.len()!=64||!spec.sha256.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b)) {
                fail!(EINVAL,"BIRTH_INPUT_DIGEST");
            }
            total=total.checked_add(spec.size).ok_or_else(||err!(E2BIG,"BIRTH_INPUT_TOTAL"))?;
            if total>MAX_TOTAL_BYTES {fail!(E2BIG,"BIRTH_INPUT_TOTAL");}
            // Roles and source names cannot alias, even on a case-sensitive
            // software host. The same staged pins may later be copied twice;
            // that must create two distinct destination inodes, not two source
            // owners or any hardlink adopted here.
            let role=match &spec.role {
                BirthSourceRole::Staged(path)=>BirthSourceRole::Staged(folded(path)?),
                other=>other.clone(),
            };
            let key=folded(&path)?;
            if !roles.insert(role)||paths.iter().any(|p|p.starts_with(&key)||key.starts_with(p)) {
                fail!(EINVAL,"BIRTH_INPUT_ALIAS");
            }
            paths.push(key);planned.push(BirthSourceSpec {role:spec.role.clone(),path,
                sha256:spec.sha256.clone(),size:spec.size});
        }
        Ok(Self {package,specs:planned})
    }
}
struct Member {role:BirthSourceRole,held:HeldFile}

/// Original read-only source files plus the same original nofollow ancestry.
/// Native construction requires actual root and absent extended ACLs on all
/// held/named source ancestors/files. No clone, receipt, File, FD or callback
/// export exists. Every established refusal is sticky until this owner drops.
pub(crate) struct UnadmittedBirthSources {paths:HeldPaths,members:Vec<Member>,poisoned:bool}
fn readonly(held:&HeldFile)->EnclaveResult<()> {
    let status=unsafe {libc::fcntl(held.file().as_raw_fd(),libc::F_GETFL)};
    let descriptor=unsafe {libc::fcntl(held.file().as_raw_fd(),libc::F_GETFD)};
    if status<0||status&libc::O_ACCMODE!=libc::O_RDONLY||status&libc::O_NONBLOCK==0
        ||descriptor<0||descriptor&libc::FD_CLOEXEC==0 {
        fail!(ESTALE,"BIRTH_INPUT_DESCRIPTOR_FLAGS");
    }Ok(())
}
impl UnadmittedBirthSources {
    pub(crate) fn open(package:&Path,specs:&[BirthSourceSpec])->EnclaveResult<Self> {
        let plan=SourcePlan::build(package,specs)?;
        // No platform/fixture fallback: the actual reusable walker is strict
        // for native ACLs, original names, modes, identities and byte hashes.
        let paths=HeldPaths::new_native_acl_protected()?;
        Self::open_plan(plan,paths)
    }
    /// Private software-fixture seam, absent from production builds. It uses
    /// the genuine held-FD reader without constructing native ACL authority.
    #[cfg(test)]
    pub(super) fn open_software_fixture(package:&Path,specs:&[BirthSourceSpec])->EnclaveResult<Self> {
        if unsafe {libc::geteuid()}!=0
            ||std::env::var("ENCLAVE_TEST_STATE_ROOT").as_deref()!=Ok("/state") {
            fail!(EACCES,"BIRTH_INPUT_PRIVATE_SOFTWARE_FIXTURE_REQUIRED");
        }
        let package=normalized_path(package)?;
        if !package.starts_with("/state")||package==Path::new("/state") {
            fail!(EACCES,"BIRTH_INPUT_PRIVATE_SOFTWARE_FIXTURE_REQUIRED");
        }
        Self::open_plan(SourcePlan::build(&package,specs)?,HeldPaths::new()?)
    }
    fn open_plan(plan:SourcePlan,mut paths:HeldPaths)->EnclaveResult<Self> {
        paths.hold_directory(&plan.package,None)?;
        let mut members=Vec::new();let mut inodes=BTreeSet::new();
        for spec in plan.specs {
            let (held,_)=HeldFile::open(&mut paths,&spec.path,spec.size,None)?;
            readonly(&held)?;
            if held.sha256()!=spec.sha256||held.size()!=spec.size {fail!(ESTALE,"BIRTH_INPUT_EXPECTATION");}
            let metadata=held.file().metadata().map_err(|_|err!(EIO,"BIRTH_INPUT_STAT"))?;
            if !inodes.insert((metadata.dev(),metadata.ino())) {fail!(ESTALE,"BIRTH_INPUT_INODE_ALIAS");}
            members.push(Member {role:spec.role,held});
        }
        let owner=Self {paths,members,poisoned:false};owner.current(true)?;Ok(owner)
    }
    fn current(&self,full_digest:bool)->EnclaveResult<()> {
        // Observe every retained member even after another fails. These are
        // read-only checks; there is no follow-up mutation on an error path.
        let files=self.members.iter().map(|member|&member.held).collect::<Vec<_>>();
        let mut first=if full_digest {self.paths.revalidate().err()}
            else {self.paths.revalidate_files_metadata(&files).err()};
        for member in &self.members {
            let binding=if full_digest {member.held.revalidate(&self.paths)}
                else {Ok(())}; // Batch above checks all ancestry once pre/post.
            for result in [readonly(&member.held),binding] {
                if let Err(error)=result {if first.is_none(){first=Some(error);}}
            }
        }
        if full_digest {if let Err(error)=self.paths.revalidate(){if first.is_none(){first=Some(error);}}}
        first.map_or(Ok(()),Err)
    }
    /// Full-set digest gate, required before and after any future import and
    /// before accepting its final bytes. Chunk reads alone cannot close import.
    pub(crate) fn assert_current(&mut self)->EnclaveResult<()> {
        if self.poisoned {fail!(EACCES,"BIRTH_INPUT_OWNER_POISONED");}
        let result=self.current(true);if result.is_err(){self.poisoned=true;}result
    }
    /// Inert metadata only. This never establishes current source admission.
    pub(crate) fn source_count(&self)->usize {self.members.len()}
    /// Original inert role, not destination admission or currentness evidence.
    pub(crate) fn role(&self,index:usize)->Option<&BirthSourceRole> {self.members.get(index).map(|m|&m.role)}
    /// Original observed size, not a receipt or permission to copy the source.
    pub(crate) fn size(&self,index:usize)->Option<u64> {self.members.get(index).map(|m|m.held.size())}
    /// Original digest expectation, never currentness or permission to import.
    pub(crate) fn sha256(&self,index:usize)->Option<&str> {self.members.get(index).map(|m|m.held.sha256())}
    /// Read at most 64KiB from the original protected inode under full-set
    /// identity/metadata/named/ACL pre/post checks. Whole-file hashes run at
    /// open and explicit assert_current gates, never once per chunk. Future
    /// importers MUST run the full gate before and after import and before
    /// accepting final bytes; chunks alone grant no acceptance. Failure clears
    /// the entire caller buffer and poisons this owner. Earlier delivered
    /// chunks cannot be recalled. Hostile/concurrent root remains excluded.
    pub(crate) fn read_chunk(&mut self,index:usize,offset:u64,buffer:&mut [u8])->EnclaveResult<usize> {
        buffer.fill(0);
        if self.poisoned {fail!(EACCES,"BIRTH_INPUT_OWNER_POISONED");}
        let operation=(|| {
            self.current(false)?;
            if buffer.is_empty()||buffer.len()>MAX_CHUNK {fail!(E2BIG,"BIRTH_INPUT_CHUNK_BOUND");}
            let member=self.members.get(index).ok_or_else(||err!(EINVAL,"BIRTH_INPUT_INDEX"))?;
            let remaining=member.held.size().checked_sub(offset).ok_or_else(||err!(EINVAL,"BIRTH_INPUT_OFFSET"))?;
            let count=remaining.min(buffer.len() as u64) as usize;let mut done=0;
            while done<count {
                let read=member.held.file().read_at(&mut buffer[done..count],offset+done as u64)
                    .map_err(|_|err!(EIO,"BIRTH_INPUT_READ"))?;
                if read==0 {fail!(ESTALE,"BIRTH_INPUT_TRUNCATED");}done+=read;
            }Ok(count)
        })();
        let final_check=self.current(false);
        if operation.is_err()||final_check.is_err() {self.poisoned=true;buffer.fill(0);}
        let count=operation?;final_check?;Ok(count)
    }
}

#[cfg(test)]
#[path="target_birth_inputs_tests.rs"]
mod tests;
