//! Create-only initial PUBLIC inputs inside the same private birth owner.
//!
//! This child uses its parent's original directory/file engine and borrowed
//! guard. The source owner remains unadmitted: copying its exact bytes grants
//! no issuer, software, runtime trust, inactivity, selection or installation
//! authority. Public controls are born 0644 behind the same private 0700 ancestry;
//! the durable startup denial and all staged inputs remain 0600.

use super::*;
use crate::deploy::target_birth_inputs::{BirthSourceRole, UnadmittedBirthSources};
use enclave_custody_vaultd::provisioning::manifest_input_paths;

const MAX_INPUT_BYTES: usize = 1024 * 1024;
const SOURCE_CHUNK: usize = 64 * 1024;
const STAGED_PINS: &str = "codesign-pins.json";

fn roles() -> [BirthSourceRole; 7] {
    use BirthSourceRole::*;
    [Inventory, CustodyManifest, CustodyPolicy, PolicyIssuerKey, InventoryIssuerKey,
        EnvelopeIssuerKey, Staged(STAGED_PINS.into())]
}

// Bounded public byte observations, not an admitted source or copy capability.
// Only the actual source-owner reader constructs this in production. Private
// software fixtures can supply synthetic bytes without constructing native
// guard/source authority; those tests do not establish native admission.
struct PublicInputs { bytes: BTreeMap<BirthSourceRole, Vec<u8>> }
impl PublicInputs {
    fn read(sources: &mut UnadmittedBirthSources) -> EnclaveResult<Self> {
        if sources.source_count() != roles().len() { fail!(EINVAL, "BIRTH_IMPORT_SOURCE_SET"); }
        let allowed = roles().into_iter().collect::<BTreeSet<_>>();
        let mut bytes = BTreeMap::new();
        for index in 0..sources.source_count() {
            let role = sources.role(index).cloned().ok_or_else(||err!(EINVAL,"BIRTH_IMPORT_SOURCE_SET"))?;
            let size = sources.size(index).ok_or_else(||err!(EINVAL,"BIRTH_IMPORT_SOURCE_SET"))?;
            if !allowed.contains(&role) || bytes.contains_key(&role) {
                fail!(EINVAL, "BIRTH_IMPORT_SOURCE_SET");
            }
            if size == 0 || size > MAX_INPUT_BYTES as u64 { fail!(E2BIG, "BIRTH_IMPORT_SOURCE_BOUND"); }
            let mut payload = vec![0; size as usize];
            let mut offset = 0;
            while offset < payload.len() {
                let end = (offset + SOURCE_CHUNK).min(payload.len());
                let count = sources.read_chunk(index, offset as u64, &mut payload[offset..end])?;
                if count != end - offset { fail!(ESTALE, "BIRTH_IMPORT_SOURCE_LENGTH"); }
                offset = end;
            }
            // The explicit whole-owner full-digest gates are outside this
            // metadata-checked chunk loop. Chunks alone never accept import.
            bytes.insert(role, payload);
        }
        let inputs = Self { bytes }; inputs.validate_set()?; Ok(inputs)
    }
    fn validate_set(&self) -> EnclaveResult<()> {
        if self.bytes.keys().cloned().collect::<BTreeSet<_>>() != roles().into_iter().collect() {
            fail!(EINVAL, "BIRTH_IMPORT_SOURCE_SET");
        }
        if self.bytes.values().any(|b| b.is_empty() || b.len() > MAX_INPUT_BYTES) {
            fail!(E2BIG, "BIRTH_IMPORT_SOURCE_BOUND");
        }
        Ok(())
    }
    fn get(&self, role: &BirthSourceRole) -> EnclaveResult<&[u8]> {
        self.bytes.get(role).map(Vec::as_slice).ok_or_else(||err!(EINVAL,"BIRTH_IMPORT_SOURCE_SET"))
    }
}

// Closed destination roles, never a caller-selected mode or transport-role
// inference. The SAME public pins transport supplies two distinct modes.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum InitialControlRole { Descriptor, Lifetime, Denial, Inventory, Manifest, Policy,
    PolicyIssuer, InventoryIssuer, EnvelopeIssuer, StagedPins, SelectedPins }
impl InitialControlRole {
    pub(super) fn mode(self) -> u32 {
        use InitialControlRole::*;
        match self {
            Denial | StagedPins => 0o600,
            Descriptor | Lifetime | Inventory | Manifest | Policy | PolicyIssuer
                | InventoryIssuer | EnvelopeIssuer | SelectedPins => 0o644,
        }
    }
}

struct PlannedInput { role: BirthSourceRole, destination: PathBuf, destination_role: InitialControlRole }
struct InitialInputPlan { directories: Vec<PathBuf>, files: Vec<PlannedInput> }

fn fixed_support_roles(target: &DeploymentTarget) -> [PathBuf; 9] {
    let support = &target.layout.support_root;
    [support.join(STARTUP_LIFETIME_LEAF), support.join(UPGRADE_INHIBITION_LEAF),
        support.join("tuf/root.json"), support.join("fido-mds.json"),
        support.join("oidc-broker-identity.json"), support.join("oidc-oauth.json"),
        support.join("EnclaveOIDC.app"), support.join("browser/Google Chrome.app"),
        support.join("browser/Chromium.app")]
}

impl InitialInputPlan {
    /// Pure path/schema/hash plan over the SAME parent's pending bytes and
    /// cached directory identities. No filesystem lookup or mutation occurs.
    fn build(state: &BirthState, inputs: &PublicInputs) -> EnclaveResult<Self> {
        inputs.validate_set()?;
        if !state.progress.seeds_complete || !state.progress.denial_prepared
            || !state.files.contains_key(&state.plan.descriptor)
            || !state.files.contains_key(&state.plan.target.layout.support_root.join(STARTUP_LIFETIME_LEAF))
            || !state.files.contains_key(&state.plan.target.layout.support_root.join(UPGRADE_INHIBITION_LEAF)) {
            fail!(EACCES, "BIRTH_IMPORT_DENIAL_REQUIRED");
        }
        let pending = state.pending.as_ref().ok_or_else(||err!(EACCES,"BIRTH_IMPORT_DENIAL_REQUIRED"))?;
        pending.current(&state.plan)?;
        let raw_inventory = inputs.get(&BirthSourceRole::Inventory)?;
        if raw_inventory != pending.bytes.as_slice()
            || hex::encode(Sha256::digest(raw_inventory)) != pending.inventory_sha256 {
            fail!(ESTALE, "BIRTH_IMPORT_PENDING_INVENTORY");
        }
        // Reuse the actual closed inventory parser and its derived copy entry.
        // There is no second inventory schema or caller-selected pin route.
        let target = &state.plan.target;
        let inventory = crate::deploy::target_plan::describe(target, &pending.descriptor_sha256, raw_inventory)?;
        let stage_pins = target.layout.staging_root.join(STAGED_PINS);
        let mut candidates = inventory.copies.iter().filter(|c| c.source == stage_pins);
        let pins = candidates.next().ok_or_else(||err!(EINVAL,"BIRTH_IMPORT_INVENTORY_PINS"))?;
        if candidates.next().is_some() || pins.destination != target.codesign_pins_file
            || pins.sha256 != inventory.candidate_codesign_pins_sha256 {
            fail!(EINVAL, "BIRTH_IMPORT_INVENTORY_PINS");
        }
        let pin_bytes = inputs.get(&BirthSourceRole::Staged(STAGED_PINS.into()))?;
        if pins.size != pin_bytes.len() as u64 || pins.sha256 != hex::encode(Sha256::digest(pin_bytes)) {
            fail!(ESTALE, "BIRTH_IMPORT_PINS_BINDING");
        }
        // Paths come from the genuine closed custody manifest parser; bytes,
        // scopes, signatures and issuer key files are never rewritten here.
        let nested = manifest_input_paths(inputs.get(&BirthSourceRole::CustodyManifest)?, target.profile)?;
        use InitialControlRole as Destination;
        let files = vec![
            PlannedInput { role: BirthSourceRole::Inventory, destination: target.expected_artifacts_manifest.clone(), destination_role: Destination::Inventory },
            PlannedInput { role: BirthSourceRole::CustodyManifest, destination: target.authority_config.clone(), destination_role: Destination::Manifest },
            PlannedInput { role: BirthSourceRole::CustodyPolicy, destination: nested.asset_policy_file().to_owned(), destination_role: Destination::Policy },
            PlannedInput { role: BirthSourceRole::PolicyIssuerKey, destination: nested.asset_policy_key_file().to_owned(), destination_role: Destination::PolicyIssuer },
            PlannedInput { role: BirthSourceRole::InventoryIssuerKey, destination: nested.asset_inventory_key_file().to_owned(), destination_role: Destination::InventoryIssuer },
            PlannedInput { role: BirthSourceRole::EnvelopeIssuerKey, destination: nested.envelope_policy_key_file().to_owned(), destination_role: Destination::EnvelopeIssuer },
            PlannedInput { role: BirthSourceRole::Staged(STAGED_PINS.into()), destination: stage_pins, destination_role: Destination::StagedPins },
            PlannedInput { role: BirthSourceRole::Staged(STAGED_PINS.into()), destination: target.codesign_pins_file.clone(), destination_role: Destination::SelectedPins },
        ];
        let reserved = fixed_support_roles(target);
        let payload_runtime = [&target.layout.binary_dir, &target.layout.custody_bundle,
            &target.layout.sandbox_dir, &target.layout.socket_root, &target.layout.state_root,
            &target.layout.audit_root, &target.layout.cas_store_root];
        let mut destinations: Vec<PathBuf> = Vec::new();
        let mut directories = BTreeSet::new();
        for file in &files {
            // Reject path aliases rather than silently rewrite manifest bytes.
            if normalized_path(&file.destination)? != file.destination {
                fail!(EINVAL, "BIRTH_IMPORT_DESTINATION_ALIAS");
            }
            below(&file.destination, &state.plan.root)?;
            if file.destination.components().any(|c|matches!(c,Component::Normal(n) if n.as_bytes().len()>255)) {
                fail!(E2BIG, "BIRTH_IMPORT_PATH_BOUND");
            }
            if overlaps(&file.destination, &state.plan.descriptor)?
                || reserved.iter().any(|p|overlaps(&file.destination,p).unwrap_or(true))
                || payload_runtime.iter().any(|p|overlaps(&file.destination,p).unwrap_or(true)) {
                fail!(EACCES, "BIRTH_IMPORT_RESERVED_DESTINATION");
            }
            let staged_pin = file.role == BirthSourceRole::Staged(STAGED_PINS.into())
                && file.destination == target.layout.staging_root.join(STAGED_PINS);
            if overlaps(&file.destination,&target.layout.staging_root)? && !staged_pin {
                fail!(EACCES, "BIRTH_IMPORT_STAGING_ROLE");
            }
            for other in &destinations {
                if overlaps(&file.destination,other)? { fail!(EINVAL, "BIRTH_IMPORT_DESTINATION_ALIAS"); }
            }
            if state.files.contains_key(&file.destination) { fail!(EALREADY, "BIRTH_IMPORT_ALREADY_PREPARED"); }
            destinations.push(file.destination.clone());
            let mut parent = file.destination.parent().ok_or_else(||err!(EINVAL,"BIRTH_IMPORT_PATH"))?;
            while parent != state.plan.root {
                below(parent,&state.plan.root)?;
                if parent.components().count() > MAX_NODES { fail!(E2BIG, "BIRTH_DIRECTORY_LIMIT"); }
                directories.insert(parent.to_owned());
                parent = parent.parent().ok_or_else(||err!(EINVAL,"BIRTH_IMPORT_PATH"))?;
            }
        }
        // New directories may prepare only the closed input parents. Existing
        // support/staging/config parents are the original cached own inodes;
        // existence by pathname can never authorize adoption or repair.
        let mut directory_spellings = BTreeSet::new();
        for directory in &directories {
            let key = folded(directory)?;
            // Native ancestry includes "/", which cannot alias a strict
            // nonce descendant and is not itself a deployment path to fold.
            if !directory_spellings.insert(key.clone())
                || state.dirs.keys().any(|cached| cached.as_path() != Path::new("/") && cached != directory
                    && folded(cached).map_or(true,|cached|cached == key)) {
                fail!(EINVAL, "BIRTH_IMPORT_DIRECTORY_ALIAS");
            }
            if let Some(held) = state.dirs.get(directory) {
                if !held.private { fail!(EACCES, "BIRTH_IMPORT_OWN_PARENT_REQUIRED"); }
            }
            for file in &destinations {
                let dir = folded(directory)?; let file = folded(file)?;
                if dir == file || dir.starts_with(&file) { fail!(EINVAL, "BIRTH_IMPORT_DIRECTORY_ALIAS"); }
            }
            if folded(directory)? == folded(&state.plan.descriptor)?
                || folded(directory)?.starts_with(folded(&state.plan.descriptor)?) {
                fail!(EACCES, "BIRTH_IMPORT_RESERVED_DIRECTORY");
            }
            for prohibited in payload_runtime.into_iter().chain(reserved.iter()) {
                let own_support_parent = directory == &target.layout.support_root
                    && folded(prohibited)?.starts_with(folded(directory)?)
                    && folded(prohibited)? != folded(directory)?;
                if overlaps(directory,prohibited)? && !own_support_parent {
                    fail!(EACCES, "BIRTH_IMPORT_RESERVED_DIRECTORY");
                }
            }
            // Staging is permitted solely as its already-created exact root.
            if overlaps(directory,&target.layout.staging_root)?
                && !(directory == &target.layout.staging_root && state.dirs.contains_key(directory)) {
                fail!(EACCES, "BIRTH_IMPORT_STAGING_ROLE");
            }
        }
        let additional = directories.iter().filter(|p|!state.dirs.contains_key(*p)).count();
        if state.dirs.len().checked_add(additional).is_none_or(|n|n>MAX_NODES) {
            fail!(E2BIG, "BIRTH_DIRECTORY_LIMIT");
        }
        let mut directories = directories.into_iter().collect::<Vec<_>>();
        directories.sort_by_key(|p|(p.components().count(),p.clone()));
        Ok(Self {directories,files})
    }
}

impl BirthState {
    // No new writer/FD/provider seam: only the parent's original create-only
    // engine receives this private closed plan and its bounded public bytes.
    fn create_initial_inputs(&mut self, plan: &InitialInputPlan, inputs: &PublicInputs,
        check: &mut impl FnMut()->Vec<EnclaveError>, observed: &mut Vec<EnclaveError>,
        sync: &mut impl FnMut(&File)->EnclaveResult<()>) -> EnclaveResult<()> {
        for directory in &plan.directories {
            if !self.dirs.contains_key(directory) { self.create_directory(directory,check,observed,sync)?; }
        }
        for file in &plan.files {
            self.create_file(&file.destination,inputs.get(&file.role)?,file.destination_role.mode(),check,observed,sync)?;
        }
        // A single source of pins produces two O_EXCL own-inode files. Equal
        // content does not permit linking or aliasing the two destination roles.
        let staged = self.plan.target.layout.staging_root.join(STAGED_PINS);
        let selected = &self.plan.target.codesign_pins_file;
        let a = stat(&self.files[&staged].file)?; let b = stat(&self.files[selected].file)?;
        if (a.dev(),a.ino()) == (b.dev(),b.ino()) { fail!(ESTALE, "BIRTH_IMPORT_PIN_INODE_ALIAS"); }
        Ok(())
    }
    fn import_initial_public_inputs(&mut self, sources: &mut UnadmittedBirthSources,
        check: &mut impl FnMut()->Vec<EnclaveError>,
        sync: &mut impl FnMut(&File)->EnclaveResult<()>) -> Result<BirthProgress,BirthFailure> {
        self.progress.operation = "import_initial_public_inputs";
        let mut boundary_errors = Vec::new();
        let operation = (|| {
            if self.poisoned { fail!(EACCES, "BIRTH_OWNER_POISONED"); }
            self.boundary(Ok(()),check,&mut boundary_errors)?;
            self.boundary(sources.assert_current(),check,&mut boundary_errors)?;
            let inputs = PublicInputs::read(sources)?;
            let plan = InitialInputPlan::build(self,&inputs)?;
            // Full-set digest admission immediately before the first effect.
            self.boundary(sources.assert_current(),check,&mut boundary_errors)?;
            self.create_initial_inputs(&plan,&inputs,check,&mut boundary_errors,sync)?;
            self.boundary(sources.assert_current(),check,&mut boundary_errors)?;
            Ok(())
        })();
        // Evaluate ALL final gates even after read/copy/guard/sync refusal.
        // Preserve the original error and every independent final check error.
        let mut final_errors = self.checks(check);
        final_errors.extend(errors([sources.assert_current()]));
        final_errors.extend(self.checks(check));
        let result = outcome(&mut self.progress,operation,boundary_errors,final_errors);
        if result.is_err() { self.poisoned = true; } else { self.progress.uncertain_effects = false; }
        result.map(|()|self.progress.clone())
    }
}

impl NativeDedicatedBirth<'_> {
    /// Copy exactly the seven public source roles to eight closed private
    /// destinations under this SAME original birth owner, denial and guard.
    /// Public control files are initially 0644; all ancestors remain 0700. No
    /// protected load, selection, authority or activation occurs.
    pub(crate) fn import_initial_public_inputs(&mut self, sources: &mut UnadmittedBirthSources)
        -> Result<BirthProgress,BirthFailure> {
        self.state.import_initial_public_inputs(sources,
            &mut ||errors([require_native_root(),self.guard.assert_held()]),
            &mut enclave_core::fsutil::full_fsync)
    }
}

#[cfg(test)]
#[path = "target_birth_import_tests.rs"]
mod tests;
