//! Consuming genuine native admission of a still-private Dedicated L2 birth.
//!
//! Successful wrapper construction requires actual accounts, independent
//! SOFTWARE release approval and concrete native/renderer verification. No
//! caller-supplied verifier, authority boolean, guard/FD/checked/view export or
//! startup/publication effect exists here. Every failure keeps actual owners.
use super::*;
use enclave_core::deployment::{self,CheckedDeploymentTarget};
use crate::deploy::{target_accounts::{self,FixedAccountAdmission},
    target_candidate::{self,CandidateFileView},target_plan::{self,TargetInstallPlan},
    target_release::{self,ReleaseStateMode,SoftwareApproval,SoftwareApprovalFailure}};

#[path="target_birth_exclusion.rs"]
mod exclusion;

fn checked(state:&BirthState)->EnclaveResult<&CheckedDeploymentTarget> {
    state.private_load.as_ref().map(|loaded|loaded.checked())
        .ok_or_else(||err!(EACCES,"BIRTH_CANDIDATE_PRIVATE_LOAD_REQUIRED"))
}
fn plan_binding(state:&BirthState,plan:&TargetInstallPlan)->EnclaveResult<()> {
    if state.plan.target.role!=DeploymentRole::DedicatedTest||state.plan.target.profile!=Profile::L2 {
        fail!(EACCES,"BIRTH_CANDIDATE_DEDICATED_L2_REQUIRED");
    }
    let pending=state.pending.as_ref().ok_or_else(||err!(EACCES,"BIRTH_CANDIDATE_DENIAL_REQUIRED"))?;
    pending.current(&state.plan)?;
    if !state.progress.seeds_complete||!state.progress.denial_prepared
        ||plan.target_id!=state.plan.target.target_id||plan.role!=DeploymentRole::DedicatedTest
        ||plan.profile!=Profile::L2||plan.deployment_config_sha256!=pending.descriptor_sha256
        ||plan.artifact_inventory_sha256!=pending.inventory_sha256 {
        fail!(ESTALE,"BIRTH_CANDIDATE_PLAN_BINDING");
    }
    if !plan.missing_required_files.is_empty(){fail!(EACCES,"BIRTH_CANDIDATE_PACKAGE_INCOMPLETE");}
    Ok(())
}
/// Borrowed diagnostics until the real native verifier consumes them. All
/// production calls remain within this private owner; no view leaves it.
fn staged_views<'a>(state:&'a BirthState,plan:&'a TargetInstallPlan)->EnclaveResult<Vec<CandidateFileView<'a>>> {
    plan_binding(state,plan)?;
    let staging=normalized_path(&state.plan.target.layout.staging_root)?;
    let mut expected=BTreeSet::new();let mut views=Vec::new();
    for (path,sha256,size) in plan.copies.iter().map(|f|(&f.source,&f.sha256,f.size))
        .chain(plan.retained_in_staging.iter().map(|f|(&f.source,&f.sha256,f.size))) {
        if normalized_path(path)?!=*path {fail!(EINVAL,"BIRTH_CANDIDATE_SOURCE_ALIAS");}
        below(path,&staging)?;
        if !expected.insert(path.clone()){fail!(EINVAL,"BIRTH_CANDIDATE_SOURCE_SET");}
        let seed=state.files.get(path).ok_or_else(||err!(EACCES,"BIRTH_CANDIDATE_ORIGINAL_SOURCE_REQUIRED"))?;
        if seed.access!=libc::O_RDONLY||seed.stamp.len!=size {
            fail!(EACCES,"BIRTH_CANDIDATE_READONLY_SOURCE_REQUIRED");
        }
        let parent=state.dirs.get(path.parent().ok_or_else(||err!(EINVAL,"BIRTH_CANDIDATE_SOURCE_PATH"))?)
            .ok_or_else(||err!(EACCES,"BIRTH_CANDIDATE_ORIGINAL_PARENT_REQUIRED"))?;
        if !parent.private {fail!(EACCES,"BIRTH_CANDIDATE_ORIGINAL_PARENT_REQUIRED");}
        seed.current(&parent.file,path,state.protection)?;
        let retained=if let Some(content)=&seed.streamed {
            if content.length!=size {fail!(ESTALE,"BIRTH_CANDIDATE_SOURCE_BINDING");}content.sha256.clone()
        }else {hex::encode(Sha256::digest(&seed.bytes))};
        if retained!=*sha256 {fail!(ESTALE,"BIRTH_CANDIDATE_SOURCE_BINDING");}
        views.push(CandidateFileView {path,file:&seed.file,sha256,size});
    }
    let original_stage=state.files.keys().filter(|path|path.starts_with(&staging)).cloned().collect::<BTreeSet<_>>();
    if original_stage!=expected {fail!(EACCES,"BIRTH_CANDIDATE_SOURCE_SET");}
    Ok(views)
}

#[derive(Clone,Copy)]
enum Selection {Before,After}
struct CandidateAttempt<'guard> {
    birth:NativeDedicatedBirth<'guard>,
    plan:Option<TargetInstallPlan>,accounts:Option<FixedAccountAdmission>,
    approval:Option<SoftwareApproval>,release_failure:Option<SoftwareApprovalFailure>,
}
impl CandidateAttempt<'_> {
    fn observations(&mut self,selection:Selection)->Vec<EnclaveError> {
        let mut observed=Vec::new();
        let birth=&mut self.birth;
        observed.extend(birth.state.checks(&mut ||errors([require_native_root(),birth.guard.assert_held()])));
        if birth.state.poisoned {observed.push(err!(EACCES,"BIRTH_OWNER_POISONED"));}
        if birth.state.files.values().any(|file|file.access!=libc::O_RDONLY) {
            observed.push(err!(EACCES,"BIRTH_CANDIDATE_READONLY_SOURCE_REQUIRED"));
        }
        let genuine=checked(&birth.state).cloned();
        if let Ok(checked)=&genuine {
            if checked.target()!=&birth.state.plan.target||checked.config_path()!=birth.state.plan.descriptor
                ||checked.descriptor_sha256()!=hex::encode(Sha256::digest(&birth.state.plan.bytes)) {
                observed.push(err!(ESTALE,"BIRTH_CANDIDATE_CHECKED_BINDING"));
            }
            match selection {
                Selection::Before=>if deployment::selected().is_some(){observed.push(err!(EACCES,"BIRTH_CANDIDATE_PRESELECTION_REQUIRED"));},
                Selection::After=>if !deployment::selected().is_some_and(|selected|
                    selected.target()==checked.target()&&selected.config_path()==checked.config_path()
                        &&selected.descriptor_sha256()==checked.descriptor_sha256()) {
                    observed.push(err!(ESTALE,"BIRTH_CANDIDATE_SELECTED_BINDING"));
                },
            }
            if let Some(plan)=&self.plan {observed.extend(errors([staged_views(&birth.state,plan).map(|_|())]));}
            // Every available actual authority receives its final check even
            // if another independent original/guard/account check refused.
            if let Some(accounts)=&self.accounts {observed.extend(errors([accounts.assert_current(checked,birth.guard)]));}
            if let Some(approval)=&mut self.approval {observed.extend(errors([approval.assert_current(checked,birth.guard)]));}
        }else if let Err(error)=genuine {observed.push(error);}
        if let Some(failure)=&self.release_failure {observed.extend(failure.retained_checks());}
        observed.extend(birth.state.checks(&mut ||errors([require_native_root(),birth.guard.assert_held()])));
        observed
    }
    fn gate(&mut self,selection:Selection,observed:&mut Vec<EnclaveError>)->EnclaveResult<()> {
        let checks=self.observations(selection);let result=first(&checks);observed.extend(checks);result
    }
    fn verify_candidate(&mut self)->EnclaveResult<()> {
        let checked=checked(&self.birth.state)?.clone();
        let plan=self.plan.as_ref().ok_or_else(||err!(EACCES,"BIRTH_CANDIDATE_PLAN_REQUIRED"))?;
        let files=staged_views(&self.birth.state,plan)?;
        let approval=self.approval.as_mut().ok_or_else(||err!(EACCES,"BIRTH_CANDIDATE_SOFTWARE_REQUIRED"))?;
        target_candidate::verify_candidate_native_and_rendered(&checked,plan,&files,approval,self.birth.guard)
    }
}

/// Failure retains the SAME birth/guard and every actual partial authority.
/// It has no extraction/retry/resume conversion into a successful candidate.
pub(crate) struct NativeCandidateFailure<'guard> {
    pub(crate) error:EnclaveError,
    pub(crate) boundary_errors:Vec<EnclaveError>,pub(crate) final_errors:Vec<EnclaveError>,
    pub(crate) progress:BirthProgress,
    pub(crate) selected_context_observed:bool,
    owner:CandidateAttempt<'guard>,
}
impl std::fmt::Debug for NativeCandidateFailure<'_> {
    fn fmt(&self,f:&mut std::fmt::Formatter<'_>)->std::fmt::Result {
        f.debug_struct("NativeCandidateFailure").field("error",&self.error)
            .field("boundary_errors",&self.boundary_errors).field("final_errors",&self.final_errors)
            .field("progress",&self.progress).field("selected_context_observed",&self.selected_context_observed)
            .field("release_failure",&self.owner.release_failure).finish_non_exhaustive()
    }
}
fn failure<'guard>(mut owner:CandidateAttempt<'guard>,error:EnclaveError,
    boundary_errors:Vec<EnclaveError>,final_errors:Vec<EnclaveError>)->NativeCandidateFailure<'guard> {
    owner.birth.state.poisoned=true;owner.birth.state.progress.complete=false;
    owner.birth.state.progress.uncertain_effects=true;
    NativeCandidateFailure {error,boundary_errors,final_errors,progress:owner.birth.state.progress.clone(),
        selected_context_observed:deployment::selected().is_some(),owner}
}

/// Constructed only after the actual same-invocation account/release/native
/// verifiers all succeed. This owner grants no inactivity or installation.
pub(crate) struct NativeCandidateBirth<'guard> {
    birth:NativeDedicatedBirth<'guard>,plan:TargetInstallPlan,
    accounts:FixedAccountAdmission,approval:SoftwareApproval,
}
impl std::fmt::Debug for NativeCandidateBirth<'_> {
    fn fmt(&self,f:&mut std::fmt::Formatter<'_>)->std::fmt::Result {f.debug_struct("NativeCandidateBirth").finish_non_exhaustive()}
}
impl<'guard> NativeDedicatedBirth<'guard> {
    pub(crate) fn approve_private_candidate(self,release_config:&Path)
        ->Result<NativeCandidateBirth<'guard>,NativeCandidateFailure<'guard>> {
        let mut owner=CandidateAttempt {birth:self,plan:None,accounts:None,approval:None,release_failure:None};
        owner.birth.state.progress.operation="approve_private_candidate";
        let mut boundary_errors=Vec::new();
        let operation=(|| {
            owner.gate(Selection::Before,&mut boundary_errors)?;
            let checked=checked(&owner.birth.state)?.clone();
            let plan=target_plan::prepare(&checked)?;
            // Complete original readonly source closure precedes ALL account
            // observations and software state/hardening side effects.
            staged_views(&owner.birth.state,&plan)?;owner.plan=Some(plan);
            owner.gate(Selection::Before,&mut boundary_errors)?;
            owner.accounts=Some(target_accounts::admit_fixed_accounts(&checked,owner.birth.guard)?);
            owner.gate(Selection::Before,&mut boundary_errors)?;
            match target_release::admit_software_approval(&checked,release_config,
                ReleaseStateMode::FirstProvisioning,owner.birth.guard) {
                Ok(approval)=>owner.approval=Some(approval),
                Err(error)=>{let original=error.error.clone();owner.release_failure=Some(error);return Err(original);},
            }
            owner.gate(Selection::Before,&mut boundary_errors)?;
            let verified=owner.verify_candidate();
            let final_gate=owner.gate(Selection::Before,&mut boundary_errors);
            verified?;final_gate?;Ok(())
        })();
        let final_errors=owner.observations(Selection::Before);
        let error=operation.err().or_else(||final_errors.first().cloned());
        if let Some(error)=error{return Err(failure(owner,error,boundary_errors,final_errors));}
        owner.birth.state.progress.complete=true;owner.birth.state.progress.uncertain_effects=false;
        Ok(NativeCandidateBirth {birth:owner.birth,plan:owner.plan.expect("verified original plan"),
            accounts:owner.accounts.expect("actual native accounts"),approval:owner.approval.expect("actual software owner")})
    }
}

/// Retains all original owners after exactly one immutable process selection.
/// No startup lease, inactivity, permission/publication or clear is implied.
pub(crate) struct NativeSelectedCandidateBirth<'guard> {owner:NativeCandidateBirth<'guard>}
impl std::fmt::Debug for NativeSelectedCandidateBirth<'_> {
    fn fmt(&self,f:&mut std::fmt::Formatter<'_>)->std::fmt::Result {f.debug_struct("NativeSelectedCandidateBirth").finish_non_exhaustive()}
}
impl<'guard> NativeCandidateBirth<'guard> {
    pub(crate) fn select_once(self)->Result<NativeSelectedCandidateBirth<'guard>,NativeCandidateFailure<'guard>> {
        let mut owner=CandidateAttempt {birth:self.birth,plan:Some(self.plan),accounts:Some(self.accounts),
            approval:Some(self.approval),release_failure:None};
        owner.birth.state.progress.operation="select_private_candidate";
        let mut boundary_errors=Vec::new();let mut selected=false;
        let operation=(|| {
            owner.gate(Selection::Before,&mut boundary_errors)?;
            // Genuine immutable source hashes/identities and authorities were
            // rechecked above; no caller receipt replaces native verification.
            let checked=checked(&owner.birth.state)?.clone();
            deployment::select(checked)?;selected=true;
            owner.gate(Selection::After,&mut boundary_errors)
        })();
        let final_errors=owner.observations(if selected{Selection::After}else{Selection::Before});
        let error=operation.err().or_else(||final_errors.first().cloned());
        if let Some(error)=error{return Err(failure(owner,error,boundary_errors,final_errors));}
        owner.birth.state.progress.complete=true;owner.birth.state.progress.uncertain_effects=false;
        Ok(NativeSelectedCandidateBirth {owner:NativeCandidateBirth {birth:owner.birth,
            plan:owner.plan.expect("same verified plan"),accounts:owner.accounts.expect("same actual accounts"),
            approval:owner.approval.expect("same actual software owner")}})
    }
}

#[cfg(test)]
#[path="target_birth_candidate_tests.rs"]
mod tests;
