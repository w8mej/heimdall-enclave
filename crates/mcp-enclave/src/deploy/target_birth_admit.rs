//! Protected configuration loading inside the SAME still-private birth owner.
//!
//! The real checked descriptor and real Layout stay private here. Successful
//! parsing and policy verification relative to supplied issuer pins do not
//! approve software, enroll assets, establish runtime trust or permit startup.
//! No selection, pin-cache lookup, guard export or permission change occurs.

use super::*;
use crate::launchd::Layout;
use enclave_core::deployment::{self, CheckedDeploymentTarget};
use enclave_custody_vaultd::provisioning::manifest_input_paths;
use super::input_import::InitialControlRole as InputRole;

const STAGED_PINS: &str = "codesign-pins.json";

#[derive(PartialEq, Eq)]
struct OriginalFile { role: InputRole, path: PathBuf, sha256: String, stamp: FileStamp }

// These values only bind observations to this parent's ORIGINAL retained
// inodes and pending bytes. They cannot construct deployment/issuer authority.
#[derive(PartialEq, Eq)]
struct OriginalInputs {
    root: PathBuf,
    target: DeploymentTarget,
    descriptor_sha256: String,
    inventory_sha256: String,
    files: Vec<OriginalFile>,
}

fn held<'a>(state: &'a BirthState, path: &Path) -> EnclaveResult<&'a SeedFile> {
    state.files.get(path).filter(|seed|seed.exact_bytes().is_some())
        .ok_or_else(||err!(EACCES,"BIRTH_LOAD_ORIGINAL_INPUT_REQUIRED"))
}

impl OriginalInputs {
    /// Parse only ORIGINAL retained public bytes before any protected path
    /// reader can follow a reference. Never accept pathname existence as birth.
    fn capture(state: &BirthState) -> EnclaveResult<Self> {
        Self::capture_with_owned_removal(state,None)
    }
    fn capture_with_owned_removal(state:&BirthState,removal:Option<&denial_handoff::OwnedDenialRemoval>)->EnclaveResult<Self> {
        if !state.progress.seeds_complete || !state.progress.denial_prepared {
            fail!(EACCES,"BIRTH_LOAD_DENIAL_REQUIRED");
        }
        let pending=state.pending.as_ref().ok_or_else(||err!(EACCES,"BIRTH_LOAD_DENIAL_REQUIRED"))?;
        pending.current(&state.plan)?;
        let target=&state.plan.target;
        let descriptor=held(state,&state.plan.descriptor)?;
        if descriptor.bytes!=state.plan.bytes {
            fail!(ESTALE,"BIRTH_LOAD_DESCRIPTOR_BINDING");
        }
        let lease=target.layout.support_root.join(STARTUP_LIFETIME_LEAF);
        let denial=target.layout.support_root.join(UPGRADE_INHIBITION_LEAF);
        if !held(state,&lease)?.bytes.is_empty()
            || held(state,&denial)?.bytes!=pending.marker_bytes(&state.plan)? {
            fail!(ESTALE,"BIRTH_LOAD_DENIAL_BINDING");
        }
        let inventory=held(state,&target.expected_artifacts_manifest)?;
        if inventory.bytes!=pending.bytes
            || hex::encode(Sha256::digest(&inventory.bytes))!=pending.inventory_sha256 {
            fail!(ESTALE,"BIRTH_LOAD_PENDING_INVENTORY");
        }
        let manifest=held(state,&target.authority_config)?;
        let nested=manifest_input_paths(&manifest.bytes,target.profile)?;
        let staged=target.layout.staging_root.join(STAGED_PINS);
        let plan=crate::deploy::target_plan::describe(target,&pending.descriptor_sha256,&pending.bytes)?;
        let mut copies=plan.copies.iter().filter(|copy|copy.source==staged);
        let pins=copies.next().ok_or_else(||err!(EINVAL,"BIRTH_LOAD_INVENTORY_PINS"))?;
        if copies.next().is_some() || pins.destination!=target.codesign_pins_file
            || pins.sha256!=plan.candidate_codesign_pins_sha256 {
            fail!(EINVAL,"BIRTH_LOAD_INVENTORY_PINS");
        }
        let staged_file=held(state,&staged)?;
        let selected_file=held(state,&target.codesign_pins_file)?;
        if staged_file.bytes!=selected_file.bytes || pins.size!=staged_file.bytes.len() as u64
            || pins.sha256!=hex::encode(Sha256::digest(&staged_file.bytes)) {
            fail!(ESTALE,"BIRTH_LOAD_PINS_BINDING");
        }
        if staged_file.stamp.directory.dev==selected_file.stamp.directory.dev
            && staged_file.stamp.directory.ino==selected_file.stamp.directory.ino {
            fail!(ESTALE,"BIRTH_LOAD_PIN_INODE_ALIAS");
        }
        use InputRole::*;
        let paths=vec![(Descriptor,state.plan.descriptor.clone()),(Lifetime,lease),(Denial,denial),
            (Inventory,target.expected_artifacts_manifest.clone()),(Manifest,target.authority_config.clone()),
            (Policy,nested.asset_policy_file().to_owned()),(PolicyIssuer,nested.asset_policy_key_file().to_owned()),
            (InventoryIssuer,nested.asset_inventory_key_file().to_owned()),
            (EnvelopeIssuer,nested.envelope_policy_key_file().to_owned()),
            (StagedPins,staged),(SelectedPins,target.codesign_pins_file.clone())];
        let mut files:Vec<OriginalFile>=Vec::new();
        for (role,path) in paths {
            if normalized_path(&path)?!=path {fail!(EINVAL,"BIRTH_LOAD_INPUT_ALIAS");}
            below(&path,&state.plan.root)?;
            if files.iter().any(|file|overlaps(&file.path,&path).unwrap_or(true)) {
                fail!(EACCES,"BIRTH_LOAD_INPUT_ROLE_ALIAS");
            }
            let seed=held(state,&path)?;
            let parent=path.parent().ok_or_else(||err!(EINVAL,"BIRTH_LOAD_INPUT_PARENT"))?;
            let parent=state.dirs.get(parent).ok_or_else(||err!(EACCES,"BIRTH_LOAD_ORIGINAL_PARENT_REQUIRED"))?;
            if !parent.private {fail!(EACCES,"BIRTH_LOAD_ORIGINAL_PARENT_REQUIRED");}
            let stamp=if role==InputRole::Denial {
                match removal {
                    Some(proof)=>proof.original_stamp(state,&path,seed)?,
                    None=>{seed.current(&parent.file,&path,state.protection)?;FileStamp::of(&stat(&seed.file)?)},
                }
            }else{seed.current(&parent.file,&path,state.protection)?;FileStamp::of(&stat(&seed.file)?)};
            let mode=role.mode();
            if stamp.directory.mode&0o7777!=mode {fail!(EACCES,"BIRTH_LOAD_INPUT_PROTECTION");}
            files.push(OriginalFile {role,path,sha256:hex::encode(Sha256::digest(&seed.bytes)),stamp});
        }
        Ok(Self {root:state.plan.root.clone(),target:target.clone(),
            descriptor_sha256:pending.descriptor_sha256.clone(),
            inventory_sha256:pending.inventory_sha256.clone(),files})
    }
    fn checked(&self, checked: &CheckedDeploymentTarget) -> EnclaveResult<()> {
        let descriptor=self.files.iter().find(|file|file.role==InputRole::Descriptor)
            .ok_or_else(||err!(ESTALE,"BIRTH_LOAD_DESCRIPTOR_BINDING"))?;
        if checked.config_path()!=descriptor.path.as_path() || checked.descriptor_sha256()!=self.descriptor_sha256
            || checked.target()!=&self.target {
            fail!(ESTALE,"BIRTH_LOAD_CHECKED_BINDING");
        }
        Ok(())
    }
    fn current(&self,state:&BirthState) -> EnclaveResult<()> {self.current_with_owned_removal(state,None)}
    fn current_with_owned_removal(&self,state:&BirthState,removal:Option<&denial_handoff::OwnedDenialRemoval>)->EnclaveResult<()> {
        if Self::capture_with_owned_removal(state,removal)?!=*self {fail!(ESTALE,"BIRTH_LOAD_ORIGINAL_BINDING_CHANGED");}
        Ok(())
    }
    fn layout(&self,layout:&Layout) -> EnclaveResult<()> {
        self.checked(layout.deployment.as_ref().ok_or_else(||err!(ESTALE,"BIRTH_LOAD_LAYOUT_BINDING"))?)?;
        let authority=layout.custody_authority.as_ref().ok_or_else(||err!(ESTALE,"BIRTH_LOAD_LAYOUT_BINDING"))?;
        let receipt=authority.receipt();
        let digest=|role|self.files.iter().find(|file|file.role==role).map(|file|file.sha256.as_str());
        if receipt.profile!=self.target.profile
            || Some(receipt.manifest_sha256.as_str())!=digest(InputRole::Manifest)
            || Some(receipt.asset_policy_sha256.as_str())!=digest(InputRole::Policy)
            || Some(receipt.asset_policy_key_sha256.as_str())!=digest(InputRole::PolicyIssuer)
            || Some(receipt.asset_inventory_key_sha256.as_str())!=digest(InputRole::InventoryIssuer)
            || Some(receipt.envelope_policy_key_sha256.as_str())!=digest(InputRole::EnvelopeIssuer) {
            fail!(ESTALE,"BIRTH_LOAD_LAYOUT_BINDING");
        }
        Ok(())
    }
}

// Public-mode exceptions come only from the real closed manifest/inventory
// paths and all ORIGINAL exact-byte controls. Unknown files get no exception.
pub(super) fn original_modes(state:&BirthState)->EnclaveResult<BTreeMap<PathBuf,u32>> {
    original_modes_with_owned_removal(state,None)
}
pub(super) fn original_modes_with_owned_removal(state:&BirthState,removal:Option<&denial_handoff::OwnedDenialRemoval>)
    ->EnclaveResult<BTreeMap<PathBuf,u32>> {
    Ok(OriginalInputs::capture_with_owned_removal(state,removal)?.files.into_iter().map(|file|(file.path,file.role.mode())).collect())
}

// Deliberately no Clone/Debug/Serialize/accessor: the original parent retains
// the actual protected observations, not a report later promoted to authority.
pub(super) struct PrivateLoadedInputs {
    originals: OriginalInputs,
    checked: CheckedDeploymentTarget,
    layout: Layout,
}
impl PrivateLoadedInputs {
    // Borrowed only within the private birth subtree. This is the actual
    // protected observation, never a reconstructed receipt or caller input.
    pub(super) fn checked(&self)->&CheckedDeploymentTarget {&self.checked}
    /// Borrow the same actual protected provisioning observation only inside
    /// the private birth subtree. Callers still run current(state) around each
    /// use; this grants no runtime TUF/receipt or operator pin authority.
    pub(super) fn custody_provisioning(&self)->EnclaveResult<&enclave_custody_vaultd::provisioning::CustodyProvisioning> {
        self.layout.custody_authority.as_ref().ok_or_else(||err!(EACCES,"BIRTH_LOAD_CUSTODY_PROVISIONING_REQUIRED"))
    }
    // Actual protected Layout/context/expiry only during the private native
    // kernel's own unlink/sync interval. That kernel independently checks the
    // exact original marker/parent and ALL disjoint original sources. This
    // supplies no source, absence, mode or native-removal capability.
    pub(super) fn layout_current(&self)->EnclaveResult<()> {
        let observed=errors([self.originals.checked(&self.checked),self.originals.layout(&self.layout),self.layout.validate()]);
        first(&observed)
    }
    pub(super) fn current(&self,state:&BirthState) -> EnclaveResult<()> {self.current_with_owned_removal(state,None)}
    pub(super) fn current_with_owned_removal(&self,state:&BirthState,removal:Option<&denial_handoff::OwnedDenialRemoval>)->EnclaveResult<()> {
        // Never call state.checks(): this is itself a parent checks hook.
        // Evaluate independent layout/expiry and both original-file gates even
        // when an earlier gate fails. The parent also checks every own inode.
        let observed=errors([self.originals.current_with_owned_removal(state,removal),self.originals.checked(&self.checked),
            self.originals.layout(&self.layout),self.layout.validate(),self.originals.current_with_owned_removal(state,removal)]);
        first(&observed)
    }
}

fn unselected() -> EnclaveResult<()> {
    if deployment::selected().is_some() {fail!(EACCES,"BIRTH_LOAD_PRESELECTION_REQUIRED");}
    Ok(())
}

impl BirthState {
    fn load_private_inputs(&mut self,check:&mut impl FnMut()->Vec<EnclaveError>)
        -> Result<BirthProgress,BirthFailure> {
        self.progress.operation="load_private_inputs";
        let mut boundary_errors=Vec::new();
        let operation=(|| {
            if self.poisoned {fail!(EACCES,"BIRTH_OWNER_POISONED");}
            self.boundary(unselected(),check,&mut boundary_errors)?;
            if self.private_load.is_some() {fail!(EALREADY,"BIRTH_LOAD_ALREADY_PREPARED");}
            let originals=OriginalInputs::capture(self)?;
            self.boundary(originals.current(self),check,&mut boundary_errors)?;
            self.boundary(unselected(),check,&mut boundary_errors)?;
            // Actual protected reads, not a test-created checked target. The
            // SAME original parent/guard is checked around each real reader.
            let checked=self.boundary(deployment::load(&self.plan.descriptor),check,&mut boundary_errors)?;
            self.boundary(originals.checked(&checked),check,&mut boundary_errors)?;
            self.boundary(originals.current(self),check,&mut boundary_errors)?;
            self.boundary(unselected(),check,&mut boundary_errors)?;
            let layout=self.boundary(Layout::for_target(checked.clone()),check,&mut boundary_errors)?;
            self.boundary(originals.layout(&layout),check,&mut boundary_errors)?;
            self.private_load=Some(PrivateLoadedInputs {originals,checked,layout});
            self.boundary(unselected(),check,&mut boundary_errors)?;
            Ok(())
        })();
        // All final parent/guard/private-layout checks run on success/refusal.
        // Original operation, observed boundary and final errors stay separate.
        let mut final_errors=self.checks(check);
        final_errors.extend(errors([unselected()]));
        final_errors.extend(self.checks(check));
        let result=outcome(&mut self.progress,operation,boundary_errors,final_errors);
        if result.is_err() {self.poisoned=true;}else{self.progress.uncertain_effects=false;}
        result.map(|()|self.progress.clone())
    }
}

impl NativeDedicatedBirth<'_> {
    /// Verify actual protected configuration without selecting it or exporting
    /// checked authority. Durable denial, private modes and original FDs stay.
    pub(crate) fn load_private_inputs(&mut self) -> Result<BirthProgress,BirthFailure> {
        self.state.load_private_inputs(&mut ||errors([require_native_root(),self.guard.assert_held()]))
    }
}

#[cfg(test)]
#[path="target_birth_admit_tests.rs"]
mod tests;
