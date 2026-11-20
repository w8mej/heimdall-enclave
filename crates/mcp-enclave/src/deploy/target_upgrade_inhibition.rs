//! Denial-only durable upgrade marker publication. No payload or pin mutation,
//! activation, cleanup, marker adoption or resume API is supplied.

use std::{ffi::CString, fs::{File, Metadata}, io::Write,
    os::{fd::{AsRawFd, FromRawFd}, unix::fs::{FileExt, MetadataExt}}};
use enclave_core::{deployment::{self, CheckedDeploymentTarget, DeploymentRole,
    upgrade::{HeldUpgradeDirectory, UPGRADE_INHIBITION_LEAF}},
    error::{EnclaveError, EnclaveResult}, err, fail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use super::{HostMaintenanceGuard, MaintenanceExclusion};

const KIND:&str="mcpmac-upgrade-start-inhibition";
#[derive(Debug, Serialize)]
pub(crate) struct UpgradeInhibitionReceipt {
    pub(crate) target_id:String,
    pub(crate) descriptor_sha256:String,
    pub(crate) artifact_inventory_sha256:Option<String>,
    pub(crate) creation_attempted:bool,
    pub(crate) existing_marker_observed:bool,
    pub(crate) marker_created:bool,
    pub(crate) file_synced:bool,
    pub(crate) parent_synced:bool,
    pub(crate) marker_verified:bool,
    pub(crate) uncertain_effects:bool,
    pub(crate) complete:bool,
    pub(crate) mutation_allowed:bool,
    pub(crate) activation_allowed:bool,
    pub(crate) inactivity_proven:bool,
    pub(crate) installation_supported:bool,
    pub(crate) qualified:bool,
}
#[derive(Debug)]
pub(crate) struct UpgradeInhibitionFailure {
    pub(crate) receipt:UpgradeInhibitionReceipt,
    pub(crate) error:EnclaveError,
    pub(crate) boundary_errors:Vec<EnclaveError>,
    pub(crate) final_binding_error:Option<EnclaveError>,
    pub(crate) final_binding_errors:Vec<EnclaveError>,
}
type InhibitionResult=Result<UpgradeInhibitionReceipt,UpgradeInhibitionFailure>;
impl UpgradeInhibitionReceipt {
    fn new(target_id:&str,descriptor:&str)->Self {
        Self {target_id:target_id.into(),descriptor_sha256:descriptor.into(),artifact_inventory_sha256:None,
            creation_attempted:false,existing_marker_observed:false,marker_created:false,file_synced:false,
            parent_synced:false,marker_verified:false,uncertain_effects:false,complete:false,
            mutation_allowed:false,activation_allowed:false,inactivity_proven:false,
            installation_supported:false,qualified:false}
    }
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Marker {version:u8,kind:String,target_id:String,descriptor_sha256:String,artifact_inventory_sha256:String}
fn digest(value:&str)->bool {
    value.len()==64&&value.bytes().all(|c|c.is_ascii_digit()||(b'a'..=b'f').contains(&c))
}
fn marker_bytes(receipt:&UpgradeInhibitionReceipt)->EnclaveResult<Vec<u8>> {
    let inventory=receipt.artifact_inventory_sha256.as_ref().ok_or_else(||err!(EINVAL,"UPGRADE_INHIBITION_BINDING"))?;
    if receipt.target_id.is_empty()||receipt.target_id.len()>64||!digest(&receipt.descriptor_sha256)||!digest(inventory) {
        fail!(EINVAL,"UPGRADE_INHIBITION_BINDING");
    }
    serde_json::to_vec(&Marker {version:1,kind:KIND.into(),target_id:receipt.target_id.clone(),
        descriptor_sha256:receipt.descriptor_sha256.clone(),artifact_inventory_sha256:inventory.clone()})
        .map_err(|_|err!(EIO,"UPGRADE_INHIBITION_ENCODING"))
}
fn after<T>(operation:EnclaveResult<T>,check:&mut impl FnMut()->EnclaveResult<()>,
    errors:&mut Vec<EnclaveError>)->EnclaveResult<T> {
    let binding=check();
    if let Err(error)=&binding {errors.push(error.clone());}
    let value=operation?;binding?;Ok(value)
}
#[derive(PartialEq,Eq)]
struct Stamp {dev:u64,ino:u64,uid:u32,gid:u32,mode:u32,nlink:u64,len:u64,
    modified:(i64,i64),changed:(i64,i64)}
fn stamp(file:&File,owner:(u32,u32),length:usize)->EnclaveResult<Stamp> {
    let m:Metadata=file.metadata().map_err(|_|err!(EIO,"UPGRADE_INHIBITION_STAT"))?;
    if !m.is_file()||m.uid()!=owner.0||m.gid()!=owner.1||m.mode()&0o7777!=0o600
        ||m.nlink()!=1||m.len()!=length as u64 {fail!(EACCES,"UPGRADE_INHIBITION_PROTECTION");}
    Ok(Stamp {dev:m.dev(),ino:m.ino(),uid:m.uid(),gid:m.gid(),mode:m.mode(),nlink:m.nlink(),len:m.len(),
        modified:(m.mtime(),m.mtime_nsec()),changed:(m.ctime(),m.ctime_nsec())})
}
fn verify(parent:&File,file:&File,expected:&[u8],original:&Stamp,owner:(u32,u32))->EnclaveResult<()> {
    // The original exclusively created descriptor is authoritative. Named
    // observations may only compare against it, never reconstruct ownership.
    if stamp(file,owner,expected.len())?!=*original {fail!(ESTALE,"UPGRADE_INHIBITION_MARKER_CHANGED");}
    let leaf=CString::new(UPGRADE_INHIBITION_LEAF).expect("literal");
    let mut metadata=std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe {libc::fstatat(parent.as_raw_fd(),leaf.as_ptr(),metadata.as_mut_ptr(),libc::AT_SYMLINK_NOFOLLOW)}!=0 {
        fail!(ESTALE,"UPGRADE_INHIBITION_MARKER_CHANGED");
    }
    let metadata=unsafe {metadata.assume_init()};
    if metadata.st_mode as u32&libc::S_IFMT as u32!=libc::S_IFREG as u32
        ||metadata.st_dev as u64!=original.dev||metadata.st_ino as u64!=original.ino {
        fail!(ESTALE,"UPGRADE_INHIBITION_MARKER_CHANGED");
    }
    let fd=unsafe {libc::openat(parent.as_raw_fd(),leaf.as_ptr(),
        libc::O_RDONLY|libc::O_NOFOLLOW|libc::O_NONBLOCK|libc::O_CLOEXEC)};
    if fd<0 {fail!(ESTALE,"UPGRADE_INHIBITION_MARKER_CHANGED");}
    let named=unsafe {File::from_raw_fd(fd)};
    if stamp(file,owner,expected.len())?!=*original||stamp(&named,owner,expected.len())?!=*original {
        fail!(ESTALE,"UPGRADE_INHIBITION_MARKER_CHANGED");
    }
    let mut bytes=vec![0;expected.len()+1];
    let count=file.read_at(&mut bytes,0).map_err(|_|err!(EIO,"UPGRADE_INHIBITION_READ"))?;
    if count!=expected.len()||&bytes[..count]!=expected {fail!(ESTALE,"UPGRADE_INHIBITION_MARKER_CHANGED");}
    if stamp(file,owner,expected.len())?!=*original {fail!(ESTALE,"UPGRADE_INHIBITION_MARKER_CHANGED");}Ok(())
}
struct CreatedMarker {file:File,stamp:Stamp,bytes:Vec<u8>,owner:(u32,u32)}
impl CreatedMarker {
    fn assert_current(&self,parent:&File)->EnclaveResult<()> {
        let access=unsafe {libc::fcntl(self.file.as_raw_fd(),libc::F_GETFL)};
        let descriptor=unsafe {libc::fcntl(self.file.as_raw_fd(),libc::F_GETFD)};
        let flags=if access<0||access&libc::O_ACCMODE!=libc::O_RDWR||access&libc::O_NONBLOCK==0
            ||descriptor<0||descriptor&libc::FD_CLOEXEC==0 {Err(err!(ESTALE,"UPGRADE_INHIBITION_MARKER_CHANGED"))}else{Ok(())};
        let binding=verify(parent,&self.file,&self.bytes,&self.stamp,self.owner);flags?;binding
    }
}
fn publish_marker(parent:&File,receipt:&mut UpgradeInhibitionReceipt,owner:(u32,u32),
    check:&mut impl FnMut()->EnclaveResult<()>,errors:&mut Vec<EnclaveError>,
    sync:&mut impl FnMut(&File)->EnclaveResult<()>)->EnclaveResult<CreatedMarker> {
    let bytes=marker_bytes(receipt)?;
    after(Ok(()),check,errors)?;
    let leaf=CString::new(UPGRADE_INHIBITION_LEAF).expect("literal");
    receipt.creation_attempted=true;receipt.uncertain_effects=true;
    // Publish the fixed final denial name first. Empty/partial bytes deny too;
    // a crash must never leave an apparently absent temporary-only marker.
    let fd=unsafe {libc::openat(parent.as_raw_fd(),leaf.as_ptr(),libc::O_RDWR|libc::O_CREAT|libc::O_EXCL
        |libc::O_NOFOLLOW|libc::O_NONBLOCK|libc::O_CLOEXEC,0o600)};
    let opened=if fd<0 {
        if std::io::Error::last_os_error().raw_os_error()==Some(libc::EEXIST) {
            receipt.existing_marker_observed=true;receipt.uncertain_effects=false;
            Err(err!(EACCES,"DEPLOYMENT_UPGRADE_INHIBITED"))
        }else {Err(err!(EIO,"UPGRADE_INHIBITION_CREATE_UNCERTAIN"))}
    }else {
        receipt.marker_created=true;
        Ok(unsafe {File::from_raw_fd(fd)})
    };
    let mut file=after(opened,check,errors)?;
    // Only our exclusive newly created inode can receive metadata or bytes.
    let protection=if unsafe {libc::fchown(file.as_raw_fd(),owner.0,owner.1)}!=0
        ||unsafe {libc::fchmod(file.as_raw_fd(),0o600)}!=0 {
        Err(err!(EACCES,"UPGRADE_INHIBITION_PROTECTION"))
    }else {Ok(())};
    after(protection,check,errors)?;
    let written=file.write_all(&bytes).map_err(|_|err!(EIO,"UPGRADE_INHIBITION_WRITE_UNCERTAIN"));
    after(written,check,errors)?;
    let original=after(stamp(&file,owner,bytes.len()),check,errors)?;
    after(verify(parent,&file,&bytes,&original,owner),check,errors)?;
    let file_sync=sync(&file);if file_sync.is_ok() {receipt.file_synced=true;}
    after(file_sync,check,errors)?;
    let parent_sync=sync(parent);if parent_sync.is_ok() {receipt.parent_synced=true;}
    after(parent_sync,check,errors)?;
    after(verify(parent,&file,&bytes,&original,owner),check,errors)?;
    receipt.marker_verified=true;receipt.uncertain_effects=false;
    Ok(CreatedMarker {file,stamp:original,bytes,owner})
}
fn finish_all(mut receipt:UpgradeInhibitionReceipt,operation:EnclaveResult<()>,
    final_binding_errors:Vec<EnclaveError>,boundary_errors:Vec<EnclaveError>)->InhibitionResult {
    receipt.complete=operation.is_ok()&&final_binding_errors.is_empty();
    if receipt.marker_created&&!receipt.complete {receipt.uncertain_effects=true;}
    let final_binding_error=final_binding_errors.first().cloned();
    match (operation,final_binding_error) {
        (Ok(()),None)=>Ok(receipt),
        (Err(error),final_binding_error)=>Err(UpgradeInhibitionFailure {receipt,error,boundary_errors,
            final_binding_error,final_binding_errors}),
        (Ok(()),Some(error))=>Err(UpgradeInhibitionFailure {receipt,error,boundary_errors,
            final_binding_error:None,final_binding_errors}),
    }
}

fn selected_context(checked:&CheckedDeploymentTarget)->EnclaveResult<()> {
    require_native_root()?;
    if checked.target().role!=DeploymentRole::ExistingUpgrade {fail!(EACCES,"UPGRADE_INHIBITION_UPGRADE_REQUIRED");}
    let selected=deployment::selected().ok_or_else(||err!(EACCES,"DEPLOYMENT_CONTEXT_REQUIRED"))?;
    let fresh=deployment::load(checked.config_path())?;
    if selected.config_path()!=checked.config_path()||selected.target()!=checked.target()
        ||selected.descriptor_sha256()!=checked.descriptor_sha256()||fresh.target()!=checked.target()
        ||fresh.descriptor_sha256()!=checked.descriptor_sha256() {fail!(ESTALE,"DEPLOYMENT_CHANGED");}Ok(())
}

/// Original created-inode continuity only; no serialized construction, FD
/// export, adoption, unlock, clear or resume. Drop never changes the marker.
/// The native transaction must separately retain its genuine SAME host guard.
pub(crate) struct OwnedUpgradeInhibition {
    parent:HeldUpgradeDirectory,created:CreatedMarker,receipt:UpgradeInhibitionReceipt,poisoned:bool,
}
impl OwnedUpgradeInhibition {
    pub(crate) fn receipt(&self)->&UpgradeInhibitionReceipt {&self.receipt}
    pub(crate) fn assert_current(&mut self,checked:&CheckedDeploymentTarget)->EnclaveResult<()> {
        let selection=selected_context(checked);
        let directory=self.parent.assert_current(checked);
        let inventory=checked.read_artifact_inventory().and_then(|bytes| {
            let hash=hex::encode(Sha256::digest(bytes));
            if self.receipt.artifact_inventory_sha256.as_deref()!=Some(hash.as_str()) {
                fail!(ESTALE,"UPGRADE_INHIBITION_INVENTORY_CHANGED");
            }Ok(())
        });
        let marker=self.created.assert_current(self.parent.directory());
        let final_directory=self.parent.assert_current(checked);
        let result=(|| {
            if self.poisoned {fail!(EACCES,"UPGRADE_INHIBITION_OWNER_POISONED");}
            selection?;directory?;inventory?;marker?;final_directory
        })();
        if result.is_err(){self.poisoned=true;}result
    }
}
fn require_native_root()->EnclaveResult<()> {
    if !cfg!(target_os="macos")||unsafe {libc::geteuid()}!=0 {fail!(EACCES,"UPGRADE_INHIBITION_NATIVE_ROOT_REQUIRED");}Ok(())
}

/// Restrict only an actual checked ExistingUpgrade target as native root under
/// the caller's same real host guard. Denial requires no release/account grant;
/// the result cannot authorize replacement, service starts or marker removal.
pub(crate) fn begin_upgrade_inhibition(checked:&CheckedDeploymentTarget,guard:&mut HostMaintenanceGuard)->InhibitionResult {
    begin_upgrade_inhibition_owned(checked,guard).map(|owner|owner.receipt)
}

/// Retain the actual exclusively created marker descriptor across all final
/// checks and into the opaque result. A receipt is never reopened as an owner.
pub(crate) fn begin_upgrade_inhibition_owned(checked:&CheckedDeploymentTarget,guard:&mut HostMaintenanceGuard)
    ->Result<OwnedUpgradeInhibition,UpgradeInhibitionFailure> {
    let mut receipt=UpgradeInhibitionReceipt::new(&checked.target().target_id,checked.descriptor_sha256());
    let mut boundary_errors=Vec::new();
    let mut expected_inventory:Option<String>=None;
    let mut parent:Option<HeldUpgradeDirectory>=None;
    let mut created:Option<CreatedMarker>=None;
    let mut context=|| {
        let target=selected_context(checked);
        let exclusion=guard.assert_held();target?;exclusion
    };
    let operation=(|| {
        after(Ok(()),&mut context,&mut boundary_errors)?;
        let inventory=after(checked.read_artifact_inventory(),&mut context,&mut boundary_errors)?;
        let hash=hex::encode(Sha256::digest(&inventory));
        expected_inventory=Some(hash.clone());receipt.artifact_inventory_sha256=Some(hash.clone());
        parent=Some(after(HeldUpgradeDirectory::open(checked),&mut context,&mut boundary_errors)?);
        let held=parent.as_ref().expect("opened parent");
        let mut current=|| {
            let binding=context();let directory=held.assert_current(checked);
            let inventory=checked.read_artifact_inventory().and_then(|bytes| {
                if hex::encode(Sha256::digest(bytes))!=hash {fail!(ESTALE,"UPGRADE_INHIBITION_INVENTORY_CHANGED");}Ok(())
            });
            binding?;directory?;inventory
        };
        created=Some(publish_marker(held.directory(),&mut receipt,(0,0),&mut current,&mut boundary_errors,
            &mut enclave_core::fsutil::full_fsync)?);Ok(())
    })();
    // Every failure, including setup/create/sync errors, receives actual final
    // guard+descriptor/inventory/held-parent rechecks. Keep original errors.
    let binding=context();
    let directory=parent.as_ref().map(|held|held.assert_current(checked)).unwrap_or(Ok(()));
    let inventory=match expected_inventory.as_deref() {
        Some(hash)=>checked.read_artifact_inventory().and_then(|bytes| {
            if hex::encode(Sha256::digest(bytes))!=hash {fail!(ESTALE,"UPGRADE_INHIBITION_INVENTORY_CHANGED");}Ok(())
        }),None=>Ok(()),
    };
    let marker=match (&parent,&created) {(Some(parent),Some(created))=>created.assert_current(parent.directory()),_=>Ok(())};
    let final_errors=[binding,directory,inventory,marker].into_iter().filter_map(Result::err).collect();
    let receipt=finish_all(receipt,operation,final_errors,boundary_errors)?;
    Ok(OwnedUpgradeInhibition {parent:parent.expect("successful held parent"),
        created:created.expect("successful original marker"),receipt,poisoned:false})
}

#[cfg(test)]
#[path="target_upgrade_inhibition_tests.rs"]
mod tests;
