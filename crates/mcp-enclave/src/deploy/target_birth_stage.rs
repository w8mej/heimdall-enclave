//! Stream only the actual inventory's remaining SOURCE files into original
//! private staging. Public install destinations, trust stores and jobs are not
//! touched. Transport integrity is never software/custody/runtime authority.
use super::*;
use crate::deploy::target_birth_inputs::{BirthSourceRole,UnadmittedBirthSources};
use enclave_custody_vaultd::provisioning::manifest_input_paths;

const PINS:&str="codesign-pins.json";
struct StagedSource {index:usize,relative:PathBuf,sha256:String,size:u64}
impl StagedSource {
    fn observe(sources:&UnadmittedBirthSources)->EnclaveResult<Vec<Self>> {
        (0..sources.source_count()).map(|index| {
            let relative=match sources.role(index) {
                Some(BirthSourceRole::Staged(path))=>path.clone(),
                _=>fail!(EINVAL,"BIRTH_STAGE_SOURCE_SET"),
            };
            Ok(Self {index,relative,sha256:sources.sha256(index)
                .ok_or_else(||err!(EINVAL,"BIRTH_STAGE_SOURCE_SET"))?.to_owned(),
                size:sources.size(index).ok_or_else(||err!(EINVAL,"BIRTH_STAGE_SOURCE_SET"))?})
        }).collect()
    }
}
struct StagedFile {index:usize,destination:PathBuf,sha256:String,size:u64}
struct StagePlan {directories:Vec<PathBuf>,files:Vec<StagedFile>}
fn exact<'a>(state:&'a BirthState,path:&Path)->EnclaveResult<&'a [u8]> {
    state.files.get(path).and_then(SeedFile::exact_bytes)
        .ok_or_else(||err!(EACCES,"BIRTH_STAGE_INITIAL_INPUTS_REQUIRED"))
}
impl StagePlan {
    /// Pure closed role/path/hash/size planning over retained originals and
    /// inert source metadata. Full actual-source and birth gates bracket effects.
    fn build(state:&BirthState,sources:&[StagedSource])->EnclaveResult<Self> {
        if state.private_load.is_some(){fail!(EACCES,"BIRTH_STAGE_AFTER_PRIVATE_LOAD");}
        if !state.progress.seeds_complete||!state.progress.denial_prepared {
            fail!(EACCES,"BIRTH_STAGE_INITIAL_INPUTS_REQUIRED");
        }
        let pending=state.pending.as_ref().ok_or_else(||err!(EACCES,"BIRTH_STAGE_INITIAL_INPUTS_REQUIRED"))?;
        pending.current(&state.plan)?;
        let target=&state.plan.target;
        if exact(state,&state.plan.descriptor)?!=state.plan.bytes
            ||exact(state,&target.expected_artifacts_manifest)?!=pending.bytes
            ||exact(state,&target.layout.support_root.join(UPGRADE_INHIBITION_LEAF))?!=pending.marker_bytes(&state.plan)? {
            fail!(ESTALE,"BIRTH_STAGE_INITIAL_BINDING");
        }
        exact(state,&target.layout.support_root.join(STARTUP_LIFETIME_LEAF))?;
        let nested=manifest_input_paths(exact(state,&target.authority_config)?,target.profile)?;
        for path in [nested.asset_policy_file(),nested.asset_policy_key_file(),
            nested.asset_inventory_key_file(),nested.envelope_policy_key_file()] {
            if exact(state,path)?.is_empty(){fail!(EACCES,"BIRTH_STAGE_INITIAL_INPUTS_REQUIRED");}
        }
        let inventory=crate::deploy::target_plan::describe(target,&pending.descriptor_sha256,&pending.bytes)?;
        let staging=normalized_path(&target.layout.staging_root)?;
        if staging!=target.layout.staging_root {fail!(EINVAL,"BIRTH_STAGE_DESTINATION_ALIAS");}
        below(&staging,&state.plan.root)?;
        let stage_pins=staging.join(PINS);
        let pins=exact(state,&stage_pins)?;
        if pins!=exact(state,&target.codesign_pins_file)?
            ||hex::encode(Sha256::digest(pins))!=inventory.candidate_codesign_pins_sha256 {
            fail!(ESTALE,"BIRTH_STAGE_PINS_BINDING");
        }
        let a=&state.files[&stage_pins].stamp.directory;
        let b=&state.files[&target.codesign_pins_file].stamp.directory;
        if (a.dev,a.ino)==(b.dev,b.ino){fail!(ESTALE,"BIRTH_STAGE_PIN_INODE_ALIAS");}
        let mut expected=BTreeMap::new();let mut pin_entries=0;
        for (source,sha256,size) in inventory.copies.iter().map(|f|(&f.source,&f.sha256,f.size))
            .chain(inventory.retained_in_staging.iter().map(|f|(&f.source,&f.sha256,f.size))) {
            if normalized_path(source)?!=*source {fail!(EINVAL,"BIRTH_STAGE_DESTINATION_ALIAS");}
            let relative=below(source,&staging)?;
            if source.components().any(|p|matches!(p,Component::Normal(n) if n.as_bytes().len()>255)) {
                fail!(E2BIG,"BIRTH_STAGE_PATH_BOUND");
            }
            if source==&stage_pins {
                pin_entries+=1;
                if size!=pins.len() as u64||sha256!=&inventory.candidate_codesign_pins_sha256 {
                    fail!(ESTALE,"BIRTH_STAGE_PINS_BINDING");
                }
                continue;
            }
            if expected.insert(relative,(source.clone(),sha256.clone(),size)).is_some() {
                fail!(EINVAL,"BIRTH_STAGE_SOURCE_SET");
            }
        }
        if pin_entries!=1||sources.len()!=expected.len()||sources.is_empty()||sources.len()>128 {
            fail!(EINVAL,"BIRTH_STAGE_SOURCE_SET");
        }
        let mut files=Vec::new();let mut seen=BTreeSet::new();let mut total=0u64;
        for source in sources {
            let (destination,sha256,size)=expected.get(&source.relative)
                .ok_or_else(||err!(EINVAL,"BIRTH_STAGE_SOURCE_SET"))?;
            if !seen.insert(source.relative.clone())||source.sha256!=*sha256||source.size!=*size {
                fail!(ESTALE,"BIRTH_STAGE_SOURCE_BINDING");
            }
            if *size==0||*size>512*1024*1024 {fail!(E2BIG,"BIRTH_STAGE_SOURCE_BOUND");}
            total=total.checked_add(*size).ok_or_else(||err!(E2BIG,"BIRTH_STAGE_SOURCE_BOUND"))?;
            if total>2*1024*1024*1024 {fail!(E2BIG,"BIRTH_STAGE_SOURCE_BOUND");}
            files.push(StagedFile {index:source.index,destination:destination.clone(),sha256:sha256.clone(),size:*size});
        }
        // The inventory parser closes file names. Explicitly close parent
        // spellings too, including cached originals, before any new directory.
        let mut destinations:Vec<PathBuf>=Vec::new();let mut directories=BTreeSet::new();
        for file in &files {
            if state.files.contains_key(&file.destination){fail!(EALREADY,"BIRTH_STAGE_ALREADY_PREPARED");}
            for other in state.files.keys().chain(destinations.iter()) {
                if overlaps(&file.destination,other)? {fail!(EINVAL,"BIRTH_STAGE_FILE_ALIAS");}
            }
            destinations.push(file.destination.clone());
            let mut parent=file.destination.parent().ok_or_else(||err!(EINVAL,"BIRTH_STAGE_PATH"))?;
            loop {
                if parent!=staging {below(parent,&staging)?;}
                directories.insert(parent.to_owned());
                if parent==staging {break;}
                parent=parent.parent().ok_or_else(||err!(EINVAL,"BIRTH_STAGE_PATH"))?;
            }
        }
        let mut spellings=BTreeSet::new();
        for directory in &directories {
            let key=folded(directory)?;
            if !spellings.insert(key.clone())||state.dirs.keys().any(|cached|
                cached.as_path()!=Path::new("/")&&cached!=directory
                    &&folded(cached).map_or(true,|cached|cached==key)) {
                fail!(EINVAL,"BIRTH_STAGE_DIRECTORY_ALIAS");
            }
            if let Some(held)=state.dirs.get(directory) {
                if !held.private {fail!(EACCES,"BIRTH_STAGE_OWN_PARENT_REQUIRED");}
            }
            for file in state.files.keys().chain(destinations.iter()) {
                let file=folded(file)?;
                if key==file||key.starts_with(file){fail!(EINVAL,"BIRTH_STAGE_DIRECTORY_ALIAS");}
            }
        }
        let additional=directories.iter().filter(|p|!state.dirs.contains_key(*p)).count();
        if state.dirs.len().checked_add(additional).is_none_or(|count|count>MAX_NODES) {
            fail!(E2BIG,"BIRTH_DIRECTORY_LIMIT");
        }
        let mut directories=directories.into_iter().collect::<Vec<_>>();
        directories.sort_by_key(|p|(p.components().count(),p.clone()));
        files.sort_by(|a,b|a.destination.cmp(&b.destination));
        Ok(Self {directories,files})
    }
}
impl BirthState {
    fn import_remaining_staging_sources(&mut self,sources:&mut UnadmittedBirthSources,
        check:&mut impl FnMut()->Vec<EnclaveError>,sync:&mut impl FnMut(&File)->EnclaveResult<()>)
        ->Result<BirthProgress,BirthFailure> {
        self.progress.operation="import_remaining_staging_sources";
        let mut boundary_errors=Vec::new();
        let operation=(|| {
            if self.poisoned{fail!(EACCES,"BIRTH_OWNER_POISONED");}
            if self.private_load.is_some(){fail!(EACCES,"BIRTH_STAGE_AFTER_PRIVATE_LOAD");}
            self.boundary(Ok(()),check,&mut boundary_errors)?;
            self.boundary(sources.assert_current(),check,&mut boundary_errors)?;
            let observed=StagedSource::observe(sources)?;
            let plan=StagePlan::build(self,&observed)?;
            self.boundary(sources.assert_current(),check,&mut boundary_errors)?;
            for directory in &plan.directories {
                if !self.dirs.contains_key(directory) {
                    self.create_directory(directory,check,&mut boundary_errors,sync)?;
                }
            }
            for file in &plan.files {
                self.metadata_boundary(Ok(()),check,&mut boundary_errors)?;
                self.create_file_from_source(&file.destination,sources,file.index,file.size,&file.sha256,
                    check,&mut boundary_errors,sync)?;
            }
            self.boundary(sources.assert_current(),check,&mut boundary_errors)?;Ok(())
        })();
        // Full digest checks always run, including after a copy/guard refusal;
        // successful metadata-only chunks cannot stand in for these gates.
        let mut final_errors=self.checks(check);
        final_errors.extend(errors([sources.assert_current()]));
        final_errors.extend(self.checks(check));
        let result=outcome(&mut self.progress,operation,boundary_errors,final_errors);
        if result.is_err(){self.poisoned=true;}else{self.progress.uncertain_effects=false;}
        result.map(|()|self.progress.clone())
    }
}
impl NativeDedicatedBirth<'_> {
    /// Transport the exact remaining inventory source set into private staging
    /// under the SAME original owner, pending denial and borrowed host guard.
    /// Must precede protected load; copying grants no authority or activation.
    pub(crate) fn import_remaining_staging_sources(&mut self,sources:&mut UnadmittedBirthSources)
        ->Result<BirthProgress,BirthFailure> {
        self.state.import_remaining_staging_sources(sources,
            &mut ||errors([require_native_root(),self.guard.assert_held()]),
            &mut enclave_core::fsutil::full_fsync)
    }
}
#[cfg(test)]
#[path="target_birth_stage_tests.rs"]
mod tests;
