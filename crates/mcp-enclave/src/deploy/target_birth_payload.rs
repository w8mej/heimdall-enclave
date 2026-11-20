//! Prepare only the fixed payload subset inside the still-inaccessible original
//! birth root. Genuine selected candidate, accounts, software owner, guard and
//! startup EX stay together. No generic inactivity provider, visibility change,
//! launchd job, pin replacement or runtime trust publication is implemented.
use super::*;

#[path="target_birth_runtime_pin.rs"]
mod runtime_pin;

struct PayloadCopy {source:PathBuf,destination:PathBuf,sha256:String,size:u64,mode:u32}
struct PrivatePayloadPlan {directories:Vec<PathBuf>,copies:Vec<PayloadCopy>}
fn runtime_roots(state:&BirthState)->[&Path;4] {
    let l=&state.plan.target.layout;[&l.socket_root,&l.state_root,&l.audit_root,&l.cas_store_root]
}
fn reserved_files(state:&BirthState)->[PathBuf;8] {
    let s=&state.plan.target.layout.support_root;
    [s.join(STARTUP_LIFETIME_LEAF),s.join(UPGRADE_INHIBITION_LEAF),s.join("tuf/root.json"),
        s.join("oidc-broker-identity.json"),s.join("oidc-oauth.json"),s.join("browser/Google Chrome.app"),
        s.join("browser/Chromium.app"),state.plan.descriptor.clone()]
}
fn private_ancestry(state:&BirthState)->EnclaveResult<()> {
    let root=state.dirs.get(&state.plan.root).ok_or_else(||err!(EACCES,"BIRTH_PAYLOAD_PRIVATE_ROOT_REQUIRED"))?;
    if !root.private||root.stamp.mode&0o7777!=0o700 {fail!(EACCES,"BIRTH_PAYLOAD_PRIVATE_ROOT_REQUIRED");}
    for (path,directory) in &state.dirs {
        if path.starts_with(&state.plan.root)&&(!directory.private||directory.stamp.mode&0o7777!=0o700) {
            fail!(EACCES,"BIRTH_PAYLOAD_PRIVATE_ANCESTRY_REQUIRED");
        }
    }Ok(())
}
impl PrivatePayloadPlan {
    /// Pure plan over the actual approved plan and original private birth.
    /// Construction history comes from the consuming native owner, never a
    /// caller assertion, receipt, EX/registration-absence boolean or this plan.
    fn build(state:&BirthState,plan:&TargetInstallPlan)->EnclaveResult<Self> {
        plan_binding(state,plan)?;private_ancestry(state)?;
        let controls=crate::deploy::target_birth::admit::original_modes(state)?;
        let staged=plan.copies.iter().map(|copy|copy.source.clone())
            .chain(plan.retained_in_staging.iter().map(|file|file.source.clone())).collect::<BTreeSet<_>>();
        for (path,file) in &state.files {
            let expected=controls.get(path).copied().or_else(||staged.contains(path).then_some(0o600))
                .ok_or_else(||err!(EACCES,"BIRTH_PAYLOAD_UNPUBLISHED_ORIGINALS_REQUIRED"))?;
            if file.access!=libc::O_RDONLY||file.stamp.directory.mode&0o7777!=expected {
                fail!(EACCES,"BIRTH_PAYLOAD_UNPUBLISHED_ORIGINALS_REQUIRED");
            }
        }
        // Actual source-map closure and readonly original identity are required
        // before any account/release/native owner could authorize this call.
        // This pure planner does not re-open or authenticate source bytes.
        let staging=&state.plan.target.layout.staging_root;
        let reserved=reserved_files(state);let mut copies=Vec::new();
        let mut destinations:Vec<PathBuf>=Vec::new();let mut directories=BTreeSet::new();
        for copy in &plan.copies {
            if copy.destination==plan.selected_pins_file {continue;}
            // Exact same subset as existing target_payload::payload_copy.
            // Jobs stay staged for a separate operation; never touch /Library.
            if copy.destination.starts_with("/Library/LaunchDaemons")
                ||copy.destination.starts_with("/Library/LaunchAgents") {continue;}
            if normalized_path(&copy.destination)?!=copy.destination {fail!(EINVAL,"BIRTH_PAYLOAD_DESTINATION_ALIAS");}
            below(&copy.destination,&state.plan.root)?;below(&copy.source,staging)?;
            if copy.destination.components().any(|p|matches!(p,Component::Normal(n)if n.as_bytes().len()>255)) {
                fail!(E2BIG,"BIRTH_PAYLOAD_PATH_BOUND");
            }
            if overlaps(&copy.destination,staging)?
                ||runtime_roots(state).iter().any(|p|overlaps(&copy.destination,p).unwrap_or(true))
                ||reserved.iter().any(|p|overlaps(&copy.destination,p).unwrap_or(true)) {
                fail!(EACCES,"BIRTH_PAYLOAD_RESERVED_DESTINATION");
            }
            for other in state.files.keys().chain(destinations.iter()) {
                if overlaps(&copy.destination,other)?{fail!(EINVAL,"BIRTH_PAYLOAD_FILE_ALIAS");}
            }
            let mode=match copy.mode.as_str(){"0644"=>0o644,"0755"=>0o755,_=>fail!(EINVAL,"BIRTH_PAYLOAD_MODE")};
            if copy.uid!=0||copy.gid!=0||copy.size==0||copy.size>512*1024*1024 {fail!(EACCES,"BIRTH_PAYLOAD_COPY_BOUND");}
            let source=state.files.get(&copy.source).ok_or_else(||err!(EACCES,"BIRTH_PAYLOAD_ORIGINAL_SOURCE_REQUIRED"))?;
            let digest=source.streamed.as_ref().map_or_else(||hex::encode(Sha256::digest(&source.bytes)),|s|s.sha256.clone());
            if source.stamp.len!=copy.size||source.streamed.as_ref().is_some_and(|s|s.length!=copy.size)
                ||digest!=copy.sha256 {fail!(ESTALE,"BIRTH_PAYLOAD_SOURCE_BINDING");}
            destinations.push(copy.destination.clone());
            copies.push(PayloadCopy {source:copy.source.clone(),destination:copy.destination.clone(),
                sha256:copy.sha256.clone(),size:copy.size,mode});
            let mut parent=copy.destination.parent().ok_or_else(||err!(EINVAL,"BIRTH_PAYLOAD_PATH"))?;
            while parent!=state.plan.root {
                below(parent,&state.plan.root)?;directories.insert(parent.to_owned());
                parent=parent.parent().ok_or_else(||err!(EINVAL,"BIRTH_PAYLOAD_PATH"))?;
            }
        }
        if copies.is_empty(){fail!(EACCES,"BIRTH_PAYLOAD_EMPTY");}
        let mut spellings=BTreeSet::new();
        for directory in &directories {
            let key=folded(directory)?;
            if !spellings.insert(key.clone())||state.dirs.keys().any(|cached|cached.as_path()!=Path::new("/")
                &&cached!=directory&&folded(cached).map_or(true,|cached|cached==key)) {
                fail!(EINVAL,"BIRTH_PAYLOAD_DIRECTORY_ALIAS");
            }
            if let Some(original)=state.dirs.get(directory){if !original.private{fail!(EACCES,"BIRTH_PAYLOAD_OWN_PARENT_REQUIRED");}}
            for file in state.files.keys().chain(destinations.iter()) {
                let file=folded(file)?;if key==file||key.starts_with(file){fail!(EINVAL,"BIRTH_PAYLOAD_DIRECTORY_ALIAS");}
            }
            for prohibited in runtime_roots(state).into_iter().chain([staging.as_path()]) {
                if overlaps(directory,prohibited)? {fail!(EACCES,"BIRTH_PAYLOAD_RESERVED_DIRECTORY");}
            }
            for prohibited in &reserved {
                let prohibited=folded(prohibited)?;
                if key==prohibited||key.starts_with(prohibited){fail!(EACCES,"BIRTH_PAYLOAD_RESERVED_DIRECTORY");}
            }
        }
        let additional=directories.iter().filter(|path|!state.dirs.contains_key(*path)).count();
        if state.dirs.len().checked_add(additional).is_none_or(|count|count>MAX_NODES){fail!(E2BIG,"BIRTH_DIRECTORY_LIMIT");}
        let mut directories=directories.into_iter().collect::<Vec<_>>();directories.sort_by_key(|p|(p.components().count(),p.clone()));
        copies.sort_by(|a,b|a.destination.cmp(&b.destination));Ok(Self {directories,copies})
    }
    fn assert_absent(&self,state:&BirthState)->EnclaveResult<()> {
        for root in runtime_roots(state){absent_from_original(state,root)?;}
        for path in &self.directories {if !state.dirs.contains_key(path){absent_from_original(state,path)?;}}
        for copy in &self.copies {absent_from_original(state,&copy.destination)?;}
        Ok(())
    }
    fn assert_prepared(&self,state:&BirthState)->EnclaveResult<()> {
        // One-time pristine entry: later genuine runtime creation must not
        // re-enter this absence gate or adopt preexisting runtime names.
        private_ancestry(state)?;
        for root in runtime_roots(state){absent_from_original(state,root)?;}
        self.assert_private_contents(state)
    }
    /// Read only the same original payload after a later owned runtime phase.
    /// All directories, including runtime additions, must still be private700.
    /// This supplies no provenance or permission for any added runtime name.
    fn assert_private_contents(&self,state:&BirthState)->EnclaveResult<()> {
        private_ancestry(state)?;
        self.assert_retained_copies(state)
    }
    /// Same original payload files only. A later concrete metadata owner must
    /// independently validate its exact directory expectations and original
    /// root700 before/after use. This grants no directory metadata authority.
    fn assert_retained_copies(&self,state:&BirthState)->EnclaveResult<()> {
        for copy in &self.copies {
            let file=state.files.get(&copy.destination).ok_or_else(||err!(ESTALE,"BIRTH_PAYLOAD_COPY_INCOMPLETE"))?;
            let source=state.files.get(&copy.source).ok_or_else(||err!(ESTALE,"BIRTH_PAYLOAD_ORIGINAL_SOURCE_REQUIRED"))?;
            if file.access!=libc::O_RDONLY||file.stamp.len!=copy.size||file.stamp.directory.mode&0o7777!=copy.mode
                ||file.streamed.as_ref().map(|s|(s.length,s.sha256.as_str()))!=Some((copy.size,copy.sha256.as_str()))
                ||(file.stamp.directory.dev,file.stamp.directory.ino)==(source.stamp.directory.dev,source.stamp.directory.ino) {
                fail!(ESTALE,"BIRTH_PAYLOAD_COPY_CHANGED");
            }
            let parent=copy.destination.parent().and_then(|path|state.dirs.get(path))
                .ok_or_else(||err!(ESTALE,"BIRTH_PAYLOAD_ORIGINAL_PARENT_REQUIRED"))?;
            file.current(&parent.file,&copy.destination,state.protection)?;
        }Ok(())
    }
}
// Read-only absence observation from the deepest ORIGINAL cached directory.
// An existing unowned intermediate entry is refusal; never open/adopt it merely
// to look below it. Actual mkdir/O_EXCL still rechecks every effect afterward.
fn absent_from_original(state:&BirthState,path:&Path)->EnclaveResult<()> {
    below(path,&state.plan.root)?;
    if state.files.contains_key(path)||state.dirs.contains_key(path){fail!(EALREADY,"BIRTH_PAYLOAD_EXISTING_NAME");}
    let mut ancestor=path.parent().ok_or_else(||err!(EINVAL,"BIRTH_PAYLOAD_PATH"))?;
    while !state.dirs.contains_key(ancestor){ancestor=ancestor.parent().ok_or_else(||err!(EACCES,"BIRTH_PAYLOAD_ORIGINAL_PARENT_REQUIRED"))?;}
    let directory=&state.dirs[ancestor];
    if !directory.private{fail!(EACCES,"BIRTH_PAYLOAD_OWN_PARENT_REQUIRED");}
    directory.current(&directory.file,state.protection,true)?;
    let part=path.strip_prefix(ancestor).map_err(|_|err!(EINVAL,"BIRTH_PAYLOAD_PATH"))?.components().next()
        .ok_or_else(||err!(EINVAL,"BIRTH_PAYLOAD_PATH"))?;
    let leaf=match part {Component::Normal(leaf)=>CString::new(leaf.as_bytes()).map_err(|_|err!(EINVAL,"BIRTH_PAYLOAD_PATH"))?,
        _=>fail!(EINVAL,"BIRTH_PAYLOAD_PATH")};
    let mut metadata=std::mem::MaybeUninit::<libc::stat>::uninit();
    let result=unsafe{libc::fstatat(directory.file.as_raw_fd(),leaf.as_ptr(),metadata.as_mut_ptr(),libc::AT_SYMLINK_NOFOLLOW)};
    let operation=if result==0 {Err(err!(EALREADY,"BIRTH_PAYLOAD_EXISTING_NAME"))}
        else if std::io::Error::last_os_error().raw_os_error()==Some(libc::ENOENT){Ok(())}
        else{Err(err!(EACCES,"BIRTH_PAYLOAD_ABSENCE_UNCERTAIN"))};
    let current=directory.current(&directory.file,state.protection,true);operation?;current
}

#[must_use="retain actual candidate, guard and inhibited EX on payload refusal"]
pub(crate) struct NativePayloadBirthFailure<'guard> {
    pub(crate) error:EnclaveError,pub(crate) boundary_errors:Vec<EnclaveError>,pub(crate) final_errors:Vec<EnclaveError>,
    pub(crate) progress:BirthProgress,owner:ExclusionAttempt<'guard>,plan:Option<PrivatePayloadPlan>,
}
impl std::fmt::Debug for NativePayloadBirthFailure<'_> {
    fn fmt(&self,f:&mut std::fmt::Formatter<'_>)->std::fmt::Result {f.debug_struct("NativePayloadBirthFailure")
        .field("error",&self.error).field("boundary_errors",&self.boundary_errors).field("final_errors",&self.final_errors)
        .field("progress",&self.progress).finish_non_exhaustive()}
}
pub(crate) struct NativePrivatePayloadBirth<'guard> {owner:ExclusionAttempt<'guard>,plan:PrivatePayloadPlan}
impl std::fmt::Debug for NativePrivatePayloadBirth<'_> {
    fn fmt(&self,f:&mut std::fmt::Formatter<'_>)->std::fmt::Result {f.debug_struct("NativePrivatePayloadBirth").finish_non_exhaustive()}
}
impl<'guard> NativeExcludedCandidateBirth<'guard> {
    pub(crate) fn prepare_private_payload(self)->Result<NativePrivatePayloadBirth<'guard>,NativePayloadBirthFailure<'guard>> {
        let mut owner=self.owner;let mut plan=None;let mut boundary_errors=Vec::new();
        owner.candidate.birth.state.progress.operation="prepare_private_payload";
        let operation=(|| {
            owner.gate(&mut boundary_errors)?;owner.native_gate(&mut boundary_errors)?;
            if owner.lease.is_none()||owner.acquisition_failure.is_some(){fail!(EACCES,"BIRTH_PAYLOAD_ACTUAL_EX_REQUIRED");}
            let approved=owner.candidate.plan.as_ref().ok_or_else(||err!(EACCES,"BIRTH_CANDIDATE_PLAN_REQUIRED"))?;
            plan=Some(PrivatePayloadPlan::build(&owner.candidate.birth.state,approved)?);
            let plan=plan.as_ref().expect("closed private plan");plan.assert_absent(&owner.candidate.birth.state)?;
            owner.native_gate(&mut boundary_errors)?;
            let checked=checked(&owner.candidate.birth.state)?.clone();
            for directory in &plan.directories {
                if !owner.candidate.birth.state.dirs.contains_key(directory) {
                    let lease=owner.lease.as_mut().expect("actual inhibited EX");let birth=&mut owner.candidate.birth;
                    birth.state.create_directory(directory,&mut||errors([require_native_root(),birth.guard.assert_held(),lease.assert_current(&checked)]),
                        &mut boundary_errors,&mut enclave_core::fsutil::full_fsync)?;
                }
            }
            for copy in &plan.copies {
                owner.native_gate(&mut boundary_errors)?;private_ancestry(&owner.candidate.birth.state)?;
                let lease=owner.lease.as_mut().expect("actual inhibited EX");let birth=&mut owner.candidate.birth;
                let copied=birth.state.create_file_from_birth_stage(&copy.source,&copy.destination,copy.size,&copy.sha256,copy.mode,
                    &mut||errors([require_native_root(),birth.guard.assert_held(),lease.assert_current(&checked)]),
                    &mut boundary_errors,&mut enclave_core::fsutil::full_fsync);
                let post=owner.native_gate(&mut boundary_errors);
                // Preserve a concrete native postcheck refusal even when the
                // earlier copy refusal remains primary and final checks pass.
                if let Err(error)=&post {boundary_errors.push(error.clone());}
                copied?;post?;
            }
            plan.assert_prepared(&owner.candidate.birth.state)?;owner.native_gate(&mut boundary_errors)
        })();
        let mut final_errors=owner.observations();
        if let Some(plan)=&plan {final_errors.extend(errors([plan.assert_prepared(&owner.candidate.birth.state)]));}
        final_errors.extend(errors([private_ancestry(&owner.candidate.birth.state)]));
        final_errors.extend(errors([owner.candidate.verify_candidate()]));final_errors.extend(owner.observations());
        match resolve_owned((owner,plan),operation,boundary_errors,final_errors) {
            Ok((mut owner,plan))=>{owner.candidate.birth.state.progress.complete=true;owner.candidate.birth.state.progress.uncertain_effects=false;
                Ok(NativePrivatePayloadBirth {owner,plan:plan.expect("completed closed private plan")})},
            Err(mut refusal)=>{refusal.owner.0.candidate.birth.state.poisoned=true;refusal.owner.0.candidate.birth.state.progress.complete=false;
                refusal.owner.0.candidate.birth.state.progress.uncertain_effects=true;
                Err(NativePayloadBirthFailure {error:refusal.error,boundary_errors:refusal.boundary_errors,final_errors:refusal.final_errors,
                    progress:refusal.owner.0.candidate.birth.state.progress.clone(),owner:refusal.owner.0,plan:refusal.owner.1})},
        }
    }
}
#[cfg(test)]
#[path="target_birth_payload_tests.rs"]
mod tests;
