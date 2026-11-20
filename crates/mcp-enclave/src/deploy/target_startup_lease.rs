//! Explicit create-only startup lock preparation and inhibited native EX owner.
//!
//! Unwired primitives only. A permanent leaf prepares cooperative locking; it
//! never establishes old-code compatibility, process inactivity or permission
//! to publish payload/pins/jobs or activate/install. All actual native account,
//! software-release and candidate checks use the caller's SAME borrowed host
//! guard. ExistingUpgrade creates and retains its own denial marker; a receipt
//! supplied by a caller cannot become an owned-marker capability.
//!
//! Neither fixed name is removed, repaired or adopted, including on failure or
//! drop. The producer must retain candidate source ancestry/named bindings while
//! these borrowed views are in use. Native checks have their existing synchronous
//! timing limitations; release checks can persist their independent time floor.

use std::{ffi::CString,fs::{File,Metadata},os::{fd::{AsRawFd,FromRawFd},unix::fs::MetadataExt}};
use enclave_core::{deployment::{self,CheckedDeploymentTarget,DeploymentRole,
    upgrade::HeldUpgradeDirectory,
    startup_lease::{self,ExclusiveStartupLease,STARTUP_LIFETIME_LEAF}},
    error::{EnclaveError,EnclaveResult},err,fail};
use serde::Serialize;
use sha2::{Digest,Sha256};
use super::{target_accounts::FixedAccountAdmission,target_candidate::{self,CandidateFileView},
    target_plan::{self,TargetInstallPlan},target_release::SoftwareApproval,
    target_upgrade_inhibition::{self,OwnedUpgradeInhibition,UpgradeInhibitionFailure,UpgradeInhibitionReceipt},
    HostMaintenanceGuard,MaintenanceExclusion};

#[derive(Clone,Debug,Serialize)]
pub(crate) struct MarkerProgress {
    target_id:String,descriptor_sha256:String,artifact_inventory_sha256:Option<String>,
    creation_attempted:bool,existing_marker_observed:bool,marker_created:bool,
    file_synced:bool,parent_synced:bool,marker_verified:bool,uncertain_effects:bool,complete:bool,
    mutation_allowed:bool,activation_allowed:bool,inactivity_proven:bool,
    installation_supported:bool,qualified:bool,
}
impl From<&UpgradeInhibitionReceipt> for MarkerProgress {
    fn from(r:&UpgradeInhibitionReceipt)->Self {Self {target_id:r.target_id.clone(),
        descriptor_sha256:r.descriptor_sha256.clone(),artifact_inventory_sha256:r.artifact_inventory_sha256.clone(),
        creation_attempted:r.creation_attempted,
        existing_marker_observed:r.existing_marker_observed,marker_created:r.marker_created,
        file_synced:r.file_synced,parent_synced:r.parent_synced,marker_verified:r.marker_verified,
        uncertain_effects:r.uncertain_effects,complete:r.complete,mutation_allowed:r.mutation_allowed,
        activation_allowed:r.activation_allowed,inactivity_proven:r.inactivity_proven,
        installation_supported:r.installation_supported,qualified:r.qualified}}
}
/// Progress is reportable data, never a capability or proof of compatibility.
#[derive(Clone,Debug,Serialize)]
pub(crate) struct StartupLeaseProgress {
    pub(crate) operation:&'static str,
    pub(crate) target_id:String,
    pub(crate) descriptor_sha256:String,
    pub(crate) artifact_inventory_sha256:Option<String>,
    pub(crate) marker:Option<MarkerProgress>,
    pub(crate) owned_marker_held:bool,
    pub(crate) creation_attempted:bool,
    pub(crate) existing_lease_observed:bool,
    pub(crate) lease_created:bool,
    pub(crate) protection_verified:bool,
    pub(crate) file_synced:bool,
    pub(crate) parent_synced:bool,
    pub(crate) lease_verified:bool,
    pub(crate) maintenance_operations_attempted:u32,
    pub(crate) maintenance_operation_failed:bool,
    pub(crate) exclusive_attempted:bool,
    pub(crate) exclusive_acquired:bool,
    pub(crate) uncertain_effects:bool,
    pub(crate) complete:bool,
    pub(crate) mutation_allowed:bool,
    pub(crate) activation_allowed:bool,
    pub(crate) inactivity_proven:bool,
    pub(crate) installation_supported:bool,
    pub(crate) qualified:bool,
}
impl StartupLeaseProgress {
    fn new(target:&str,descriptor:&str)->Self {
        Self {operation:"prepare_context",target_id:target.into(),descriptor_sha256:descriptor.into(),artifact_inventory_sha256:None,
            marker:None,owned_marker_held:false,creation_attempted:false,existing_lease_observed:false,
            lease_created:false,protection_verified:false,file_synced:false,parent_synced:false,
            lease_verified:false,maintenance_operations_attempted:0,maintenance_operation_failed:false,
            exclusive_attempted:false,exclusive_acquired:false,uncertain_effects:false,complete:false,
            mutation_allowed:false,activation_allowed:false,inactivity_proven:false,
            installation_supported:false,qualified:false}
    }
}
#[derive(Debug)]
pub(crate) struct StartupLeaseFailure {
    pub(crate) error:EnclaveError,
    pub(crate) boundary_errors:Vec<EnclaveError>,
    pub(crate) final_errors:Vec<EnclaveError>,
    pub(crate) progress:StartupLeaseProgress,
    /// Preserve the original writer's full errors and exact progress too.
    pub(crate) inhibition_failure:Option<UpgradeInhibitionFailure>,
}
fn errors(results:impl IntoIterator<Item=EnclaveResult<()>>)->Vec<EnclaveError> {
    results.into_iter().filter_map(Result::err).collect()
}
fn first(values:&[EnclaveError])->EnclaveResult<()> {
    match values.first() {Some(error)=>Err(error.clone()),None=>Ok(())}
}
fn after<T>(operation:EnclaveResult<T>,check:&mut impl FnMut()->Vec<EnclaveError>,
    boundary_errors:&mut Vec<EnclaveError>)->EnclaveResult<T> {
    let checked=check();let current=first(&checked);boundary_errors.extend(checked);
    let value=operation?;current?;Ok(value)
}
fn outcome<T>(progress:&mut StartupLeaseProgress,operation:EnclaveResult<T>,
    boundary_errors:Vec<EnclaveError>,final_errors:Vec<EnclaveError>)->Result<T,StartupLeaseFailure> {
    progress.complete=operation.is_ok()&&final_errors.is_empty();
    if !progress.complete&&(progress.lease_created||progress.exclusive_acquired
        ||progress.maintenance_operations_attempted>0||progress.marker.as_ref().is_some_and(|m|m.marker_created)) {
        progress.uncertain_effects=true;
    }
    match operation {
        Err(error)=>Err(StartupLeaseFailure {error,boundary_errors,final_errors,progress:progress.clone(),inhibition_failure:None}),
        Ok(value)=>match first(&final_errors) {
            Err(error)=>Err(StartupLeaseFailure {error,boundary_errors,final_errors,progress:progress.clone(),inhibition_failure:None}),
            Ok(())=>Ok(value),
        },
    }
}
#[derive(Clone,PartialEq,Eq)]
struct Stamp {dev:u64,ino:u64,uid:u32,gid:u32,mode:u32,nlink:u64,size:u64,
    modified:(i64,i64),changed:(i64,i64)}
fn stamp(file:&File,owner:(u32,u32),mode:u32,size:u64)->EnclaveResult<Stamp> {
    let m:Metadata=file.metadata().map_err(|_|err!(EIO,"STARTUP_PREPARATION_STAT"))?;
    let access=unsafe {libc::fcntl(file.as_raw_fd(),libc::F_GETFL)};
    let descriptor=unsafe {libc::fcntl(file.as_raw_fd(),libc::F_GETFD)};
    if !m.is_file()||m.uid()!=owner.0||m.gid()!=owner.1||m.mode()&0o7777!=mode
        ||m.nlink()!=1||m.len()!=size||access<0||access&libc::O_ACCMODE!=libc::O_RDONLY
        ||access&libc::O_NONBLOCK==0||descriptor<0||descriptor&libc::FD_CLOEXEC==0 {
        fail!(EACCES,"STARTUP_PREPARATION_PROTECTION");
    }
    Ok(Stamp {dev:m.dev(),ino:m.ino(),uid:m.uid(),gid:m.gid(),mode:m.mode(),nlink:m.nlink(),size:m.len(),
        modified:(m.mtime(),m.mtime_nsec()),changed:(m.ctime(),m.ctime_nsec())})
}
fn open_fixed(parent:&File,leaf:&str)->EnclaveResult<File> {
    let name=CString::new(leaf).expect("fixed leaf");
    let mut metadata=std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe {libc::fstatat(parent.as_raw_fd(),name.as_ptr(),metadata.as_mut_ptr(),libc::AT_SYMLINK_NOFOLLOW)}!=0 {
        fail!(ESTALE,"STARTUP_PREPARATION_NAME_CHANGED");
    }
    let metadata=unsafe {metadata.assume_init()};
    if metadata.st_mode as u32&libc::S_IFMT as u32!=libc::S_IFREG as u32 {
        fail!(EACCES,"STARTUP_PREPARATION_PROTECTION");
    }
    let fd=unsafe {libc::openat(parent.as_raw_fd(),name.as_ptr(),
        libc::O_RDONLY|libc::O_NOFOLLOW|libc::O_NONBLOCK|libc::O_CLOEXEC)};
    if fd<0 {fail!(ESTALE,"STARTUP_PREPARATION_NAME_CHANGED");}
    Ok(unsafe {File::from_raw_fd(fd)})
}
fn verify(parent:&File,leaf:&str,file:&File,original:&Stamp,owner:(u32,u32),mode:u32,size:u64)->EnclaveResult<()> {
    let named=open_fixed(parent,leaf)?;
    if stamp(file,owner,mode,size)?!=*original||stamp(&named,owner,mode,size)?!=*original {
        fail!(ESTALE,"STARTUP_PREPARATION_NAME_CHANGED");
    }Ok(())
}
fn create_leaf(parent:&File,progress:&mut StartupLeaseProgress,owner:(u32,u32),
    check:&mut impl FnMut()->Vec<EnclaveError>,boundary_errors:&mut Vec<EnclaveError>,
    sync:&mut impl FnMut(&File)->EnclaveResult<()>)->EnclaveResult<()> {
    after(Ok(()),check,boundary_errors)?;
    let name=CString::new(STARTUP_LIFETIME_LEAF).expect("literal");
    progress.creation_attempted=true;progress.uncertain_effects=true;
    // The final fixed name is created exclusively; never open, adopt, sync,
    // chmod/chown or remove an existing entry, even if it already looks exact.
    let fd=unsafe {libc::openat(parent.as_raw_fd(),name.as_ptr(),libc::O_RDONLY|libc::O_CREAT|libc::O_EXCL
        |libc::O_NOFOLLOW|libc::O_NONBLOCK|libc::O_CLOEXEC,0o600)};
    let opened=if fd<0 {
        if std::io::Error::last_os_error().raw_os_error()==Some(libc::EEXIST) {
            progress.existing_lease_observed=true;progress.uncertain_effects=false;
            Err(err!(EALREADY,"STARTUP_PREPARATION_ALREADY_EXISTS"))
        }else {Err(err!(EIO,"STARTUP_PREPARATION_CREATE_UNCERTAIN"))}
    }else {progress.lease_created=true;Ok(unsafe {File::from_raw_fd(fd)})};
    let file=after(opened,check,boundary_errors)?;
    let protection=if unsafe {libc::fchown(file.as_raw_fd(),owner.0,owner.1)}!=0
        ||unsafe {libc::fchmod(file.as_raw_fd(),0o644)}!=0 {
        Err(err!(EACCES,"STARTUP_PREPARATION_PROTECTION"))
    }else {Ok(())};
    after(protection,check,boundary_errors)?;
    let original=after(stamp(&file,owner,0o644,0),check,boundary_errors)?;
    after(verify(parent,STARTUP_LIFETIME_LEAF,&file,&original,owner,0o644,0),check,boundary_errors)?;
    progress.protection_verified=true;
    let file_sync=sync(&file);if file_sync.is_ok(){progress.file_synced=true;}
    after(file_sync,check,boundary_errors)?;
    let parent_sync=sync(parent);if parent_sync.is_ok(){progress.parent_synced=true;}
    after(parent_sync,check,boundary_errors)?;
    after(verify(parent,STARTUP_LIFETIME_LEAF,&file,&original,owner,0o644,0),check,boundary_errors)?;
    progress.lease_verified=true;progress.uncertain_effects=false;Ok(())
}
fn require_native_root()->EnclaveResult<()> {
    if !cfg!(target_os="macos")||unsafe {libc::geteuid()}!=0 {fail!(EACCES,"STARTUP_PREPARATION_NATIVE_ROOT_REQUIRED");}Ok(())
}
fn selected(checked:&CheckedDeploymentTarget)->EnclaveResult<()> {
    let current=deployment::selected().ok_or_else(||err!(EACCES,"DEPLOYMENT_CONTEXT_REQUIRED"))?;
    let fresh=deployment::load(checked.config_path())?;
    if current.config_path()!=checked.config_path()||current.descriptor_sha256()!=checked.descriptor_sha256()
        ||current.target()!=checked.target()||fresh.descriptor_sha256()!=checked.descriptor_sha256()
        ||fresh.target()!=checked.target() {fail!(ESTALE,"STARTUP_PREPARATION_CONTEXT_CHANGED");}Ok(())
}
fn inventory(checked:&CheckedDeploymentTarget,expected:&str)->EnclaveResult<()> {
    if hex::encode(Sha256::digest(checked.read_artifact_inventory()?))!=expected {
        fail!(ESTALE,"STARTUP_PREPARATION_INVENTORY_CHANGED");
    }Ok(())
}
/// Retains actual borrowed admission owners. No receipt/FD/deserializer or
/// arbitrary authority callback can construct or replace this private state.
pub(crate) struct NativeStartupLeaseContext<'a> {
    checked:&'a CheckedDeploymentTarget,accounts:&'a FixedAccountAdmission,
    approval:&'a mut SoftwareApproval,guard:&'a mut HostMaintenanceGuard,
    files:&'a [CandidateFileView<'a>],plan:TargetInstallPlan,parent:HeldUpgradeDirectory,
    marker:Option<OwnedUpgradeInhibition>,progress:StartupLeaseProgress,poisoned:bool,
}
impl<'a> NativeStartupLeaseContext<'a> {
    fn checks(&mut self,heavy:bool)->Vec<EnclaveError> {
        let native=require_native_root();let can_use_native=native.is_ok();
        let mut observed=errors([native,selected(self.checked),self.guard.assert_held(),
            self.parent.assert_current(self.checked),inventory(self.checked,&self.plan.artifact_inventory_sha256)]);
        let denial=match &mut self.marker {
            Some(marker)=>marker.assert_current(self.checked),
            None=>self.parent.assert_marker_absent(),
        };
        observed.extend(errors([denial]));
        if can_use_native {
            // Actual authority, never a serialized/caller boolean. Account and
            // native candidate reobservation bracket each complete operation.
            if heavy {observed.extend(errors([self.accounts.assert_current(self.checked,self.guard)]));}
            observed.extend(errors([self.approval.assert_current(self.checked,self.guard)]));
            if heavy {observed.extend(errors([target_candidate::verify_candidate_native_and_rendered(
                self.checked,&self.plan,self.files,self.approval,self.guard)]));}
        }
        observed.extend(errors([self.parent.assert_current(self.checked),
            inventory(self.checked,&self.plan.artifact_inventory_sha256),self.guard.assert_held(),selected(self.checked)]));
        let denial=match &mut self.marker {Some(marker)=>marker.assert_current(self.checked),
            None=>self.parent.assert_marker_absent()};
        observed.extend(errors([denial]));observed
    }
    fn refused(&mut self,error:EnclaveError)->StartupLeaseFailure {
        let final_errors=self.checks(true);self.poisoned=true;
        outcome::<()>(&mut self.progress,Err(error),Vec::new(),final_errors).unwrap_err()
    }
    /// Create only the missing permanent leaf. ExistingUpgrade additionally
    /// requires this context's own exact durable denial marker. No mutation of
    /// a preexisting leaf and no compatibility/activation/install permission.
    pub(crate) fn create_only_permanent_leaf(&mut self)->Result<StartupLeaseProgress,StartupLeaseFailure> {
        self.progress.operation="create_permanent_leaf";
        if self.poisoned {return Err(self.refused(err!(EACCES,"STARTUP_PREPARATION_POISONED")));}
        let before=self.checks(true);
        let mut boundary_errors=before.clone();
        let operation=if let Err(error)=first(&before) {Err(error)}else {
            // Split only disjoint fields; one mutable guard/admission owner is
            // retained by this context throughout the private engine callback.
            let mut progress=self.progress.clone();
            let parent_fd=self.parent.directory().try_clone().map_err(|_|err!(EIO,"STARTUP_PREPARATION_PARENT_DUP"));
            let result=match parent_fd {
                Ok(parent)=>create_leaf(&parent,&mut progress,(0,0),&mut ||self.checks(false),
                    &mut boundary_errors,&mut enclave_core::fsutil::full_fsync),
                Err(error)=>Err(error),
            };
            self.progress=progress;result
        };
        let final_errors=self.checks(true);
        let result=outcome(&mut self.progress,operation,boundary_errors,final_errors);
        if result.is_err(){self.poisoned=true;}
        result.map(|()|self.progress.clone())
    }
    /// Checked stop/drain composition with the SAME genuine guard. The return
    /// value conveys no inactivity; no successful callback sets an authority.
    pub(crate) fn with_maintenance<T>(&mut self,
        operation:impl FnOnce(&CheckedDeploymentTarget,&mut HostMaintenanceGuard)->EnclaveResult<T>)
        ->Result<T,StartupLeaseFailure> {
        self.progress.operation="maintenance_callback";
        if self.poisoned {return Err(self.refused(err!(EACCES,"STARTUP_PREPARATION_POISONED")));}
        let before=self.checks(true);let boundary_errors=before.clone();
        let result=if let Err(error)=first(&before){Err(error)}else {
            self.progress.maintenance_operations_attempted=self.progress.maintenance_operations_attempted.saturating_add(1);
            let result=operation(self.checked,self.guard);
            if result.is_err(){self.progress.maintenance_operation_failed=true;}
            result
        };
        let final_errors=self.checks(true);let result=outcome(&mut self.progress,result,boundary_errors,final_errors);
        if result.is_err(){self.poisoned=true;}result
    }
    /// Consume only an inhibited ExistingUpgrade owner; NEVER provisions a
    /// missing leaf. An explicit compatible rollout remains separately needed.
    pub(crate) fn try_exclusive(mut self)->Result<NativeStartupExclusion<'a>,StartupLeaseFailure> {
        self.progress.operation="acquire_exclusive";
        if self.poisoned {return Err(self.refused(err!(EACCES,"STARTUP_PREPARATION_POISONED")));}
        if self.checked.target().role!=DeploymentRole::ExistingUpgrade||self.marker.is_none() {
            return Err(self.refused(err!(EACCES,"STARTUP_PREPARATION_OWNED_MARKER_REQUIRED")));
        }
        let before=self.checks(true);let boundary_errors=before.clone();
        let operation=if let Err(error)=first(&before){Err(error)}else {
            self.progress.exclusive_attempted=true;
            let result=startup_lease::try_exclusive_inhibited(self.checked);
            if result.is_ok(){self.progress.exclusive_acquired=true;}
            result
        };
        let mut final_errors=self.checks(true);
        let mut operation=operation;
        if let Ok(lease)=&mut operation {final_errors.extend(errors([lease.assert_current(self.checked)]));}
        let lease=outcome(&mut self.progress,operation,boundary_errors,final_errors)?;
        Ok(NativeStartupExclusion {context:self,lease})
    }
}

/// Prepare genuine current admission. ExistingUpgrade invokes the denial-only
/// writer itself; no passed receipt or old marker can satisfy that provenance.
pub(crate) fn prepare_native_startup_lease<'a>(checked:&'a CheckedDeploymentTarget,
    accounts:&'a FixedAccountAdmission,approval:&'a mut SoftwareApproval,
    files:&'a [CandidateFileView<'a>],guard:&'a mut HostMaintenanceGuard)
    ->Result<NativeStartupLeaseContext<'a>,StartupLeaseFailure> {
    let mut progress=StartupLeaseProgress::new(&checked.target().target_id,checked.descriptor_sha256());
    let mut plan=None;let mut parent=None;
    let setup=(|| {
        require_native_root()?;selected(checked)?;guard.assert_held()?;
        let current=target_plan::prepare(checked)?;
        if !current.missing_required_files.is_empty(){fail!(EACCES,"STARTUP_PREPARATION_COMPLETE_PLAN_REQUIRED");}
        progress.artifact_inventory_sha256=Some(current.artifact_inventory_sha256.clone());plan=Some(current);
        parent=Some(HeldUpgradeDirectory::open(checked)?);Ok(())
    })();
    if let Err(error)=setup {
        let mut final_errors=errors([require_native_root(),selected(checked),guard.assert_held()]);
        if let Some(plan)=&plan {final_errors.extend(errors([inventory(checked,&plan.artifact_inventory_sha256)]));}
        if let Some(parent)=&parent {final_errors.extend(errors([parent.assert_current(checked),parent.assert_marker_absent()]));}
        return Err(outcome::<()>(&mut progress,Err(error),Vec::new(),final_errors).unwrap_err());
    }
    let mut context=NativeStartupLeaseContext {checked,accounts,approval,guard,files,plan:plan.expect("set plan"),
        parent:parent.expect("held parent"),marker:None,progress,poisoned:false};
    let initial=context.checks(true);
    if let Err(error)=first(&initial) {
        let finals=context.checks(true);
        return Err(outcome::<()>(&mut context.progress,Err(error),initial,finals).unwrap_err());
    }
    if checked.target().role==DeploymentRole::ExistingUpgrade {
        match target_upgrade_inhibition::begin_upgrade_inhibition_owned(checked,context.guard) {
            Ok(marker)=>{
                context.progress.marker=Some(MarkerProgress::from(marker.receipt()));
                // The writer transfers its ORIGINAL created descriptor and
                // stamp; matching reopened receipt bytes cannot create this.
                context.marker=Some(marker);context.progress.owned_marker_held=true;
            },
            Err(failure)=>{
                context.progress.marker=Some(MarkerProgress::from(&failure.receipt));
                let original=failure.error.clone();let mut result=context.refused(original);
                result.inhibition_failure=Some(failure);return Err(result);
            },
        }
    }
    let finals=context.checks(true);
    outcome(&mut context.progress,Ok(()),Vec::new(),finals)?;Ok(context)
}

/// An exclusive kernel observation retaining the entire actual native context.
/// No FD/export/unlock/adoption or PublicPayloadAuthority implementation exists.
pub(crate) struct NativeStartupExclusion<'a> {context:NativeStartupLeaseContext<'a>,lease:ExclusiveStartupLease}
impl NativeStartupExclusion<'_> {
    pub(crate) fn assert_current(&mut self)->Result<StartupLeaseProgress,StartupLeaseFailure> {
        self.context.progress.operation="revalidate_exclusive";
        if self.context.poisoned {
            let mut finals=self.context.checks(true);
            finals.extend(errors([self.lease.assert_current(self.context.checked)]));
            return Err(outcome::<()>(&mut self.context.progress,Err(err!(EACCES,"STARTUP_PREPARATION_POISONED")),
                Vec::new(),finals).unwrap_err());
        }
        let operation=self.lease.assert_current(self.context.checked);
        let mut finals=self.context.checks(true);
        finals.extend(errors([self.lease.assert_current(self.context.checked)]));
        let result=outcome(&mut self.context.progress,operation,Vec::new(),finals);
        if result.is_err(){self.context.poisoned=true;}
        result.map(|()|self.context.progress.clone())
    }
}

#[cfg(test)]
#[path="target_startup_lease_tests.rs"]
mod tests;
