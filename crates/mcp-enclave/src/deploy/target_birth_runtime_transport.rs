//! Create-only transport under the SAME private native birth and actual EX.
//! Independently held operator pin, genuine provisioning and concrete crypto
//! checks precede effects and final acceptance. Reports never become authority.
//! New directories stay root0700; public files are created0644 behind them.
//! No metadata handoff, CAS receipt, trust-state write, publication or start.
use super::*;

#[path="target_birth_metadata_native.rs"]
mod metadata_native;
use crate::deploy::{target_runtime_trust::{self,RuntimeTrustInput},target_runtime_preflight};

const REQUIRED:[&str;7]=["root.json","timestamp.json","snapshot.json","targets.json",
    "enclave-host-config.json","fido-mds-allowlist.json","custody-envelope-policy-v1.json"];
const MAX_SOURCES:usize=39;
const MAX_SOURCE_BYTES:u64=33*1024*1024;

#[derive(Clone,PartialEq,Eq)]
struct SourceSpec {path:PathBuf,size:u64,sha256:String,maximum:usize}
struct RuntimeSource {spec:SourceSpec,bytes:Vec<u8>}
struct RuntimeCopy {source:PathBuf,destination:PathBuf,size:u64,sha256:String}
struct RuntimeTransportPlan {directories:Vec<PathBuf>,copies:Vec<RuntimeCopy>,pin:PathBuf}

fn source_bound(name:&str)->Option<usize> {
    match name {
        "root.json"|"timestamp.json"|"snapshot.json"|"targets.json"=>Some(4*1024*1024),
        "enclave-host-config.json"=>Some(64*1024),"fido-mds-allowlist.json"=>Some(256*1024),
        "custody-envelope-policy-v1.json"=>Some(16*1024),
        _=>name.strip_suffix(".root.json").filter(|n|!n.is_empty()&&!n.starts_with('0')
            &&n.bytes().all(|b|b.is_ascii_digit()))
            .and_then(|n|n.parse::<u32>().ok()).filter(|n|*n<=2_147_483_647).map(|_|4*1024*1024),
    }
}
fn source_specs(state:&BirthState,approved:&TargetInstallPlan)->EnclaveResult<Vec<SourceSpec>> {
    plan_binding(state,approved)?;
    let repository=state.plan.target.layout.staging_root.join("tuf/repo");
    let mut specs=BTreeMap::new();let mut total=0u64;let mut rotations=0;let mut rotation_bytes=0u64;
    for (path,size,sha256) in approved.copies.iter().map(|f|(&f.source,f.size,&f.sha256))
        .chain(approved.retained_in_staging.iter().map(|f|(&f.source,f.size,&f.sha256))) {
        if path.parent()!=Some(repository.as_path()){continue;}
        let name=path.file_name().and_then(|n|n.to_str()).ok_or_else(||err!(EINVAL,"BIRTH_RUNTIME_SOURCE_ROUTE"))?;
        let Some(maximum)=source_bound(name) else {continue};
        exact_path(path)?;
        if size==0||size>maximum as u64||!lower_hex(sha256,64) {fail!(E2BIG,"BIRTH_RUNTIME_SOURCE_BOUND");}
        total=total.checked_add(size).ok_or_else(||err!(E2BIG,"BIRTH_RUNTIME_SOURCE_BOUND"))?;
        if !REQUIRED.contains(&name) {rotations+=1;rotation_bytes+=size;}
        if specs.insert(path.clone(),SourceSpec {path:path.clone(),size,sha256:sha256.clone(),maximum}).is_some() {
            fail!(EINVAL,"BIRTH_RUNTIME_SOURCE_DUPLICATE");
        }
        if specs.len()>MAX_SOURCES||total>MAX_SOURCE_BYTES||rotations>32||rotation_bytes>16*1024*1024 {
            fail!(E2BIG,"BIRTH_RUNTIME_SOURCE_BOUND");
        }
    }
    for name in REQUIRED {if !specs.contains_key(&repository.join(name)){fail!(EACCES,"BIRTH_RUNTIME_SOURCE_MISSING");}}
    Ok(specs.into_values().collect())
}
fn source_current(state:&BirthState,spec:&SourceSpec,full:bool)->EnclaveResult<()> {
    let source=state.files.get(&spec.path).ok_or_else(||err!(EACCES,"BIRTH_RUNTIME_ORIGINAL_SOURCE_REQUIRED"))?;
    let parent=spec.path.parent().and_then(|p|state.dirs.get(p))
        .ok_or_else(||err!(EACCES,"BIRTH_RUNTIME_ORIGINAL_PARENT_REQUIRED"))?;
    if !parent.private||source.access!=libc::O_RDONLY||source.stamp.len!=spec.size
        ||source.stamp.directory.mode&0o7777!=0o600 {
        fail!(EACCES,"BIRTH_RUNTIME_READONLY_SOURCE_REQUIRED");
    }
    let retained=source.streamed.as_ref().map_or_else(||hex::encode(Sha256::digest(&source.bytes)),|s|s.sha256.clone());
    if retained!=spec.sha256||source.streamed.as_ref().is_some_and(|s|s.length!=spec.size) {
        fail!(ESTALE,"BIRTH_RUNTIME_SOURCE_BINDING");
    }
    source.current_with_content(&parent.file,&spec.path,state.protection,full)
}
fn read_source(state:&BirthState,spec:&SourceSpec,observed:&mut Vec<EnclaveError>)->EnclaveResult<Vec<u8>> {
    let operation=(|| {
        source_current(state,spec,true)?;
        if spec.size==0||spec.size>spec.maximum as u64||spec.maximum>4*1024*1024 {
            fail!(E2BIG,"BIRTH_RUNTIME_SOURCE_BOUND");
        }
        let source=&state.files[&spec.path];let mut bytes=vec![0;spec.size as usize];let mut offset=0;
        while offset<bytes.len() {
            source_current(state,spec,false)?;let end=(offset+READ_CHUNK).min(bytes.len());
            let count=loop {match source.file.read_at(&mut bytes[offset..end],offset as u64) {
                Err(error) if error.kind()==std::io::ErrorKind::Interrupted=>continue,
                result=>break result.map_err(|_|err!(EIO,"BIRTH_RUNTIME_SOURCE_READ"))?,
            }};
            if count==0 {fail!(ESTALE,"BIRTH_RUNTIME_SOURCE_TRUNCATED");}offset+=count;
            source_current(state,spec,false)?;
        }
        let mut extra=[0];
        if source.file.read_at(&mut extra,spec.size).map_err(|_|err!(EIO,"BIRTH_RUNTIME_SOURCE_READ"))?!=0 {
            fail!(ESTALE,"BIRTH_RUNTIME_SOURCE_GROWTH");
        }
        if hex::encode(Sha256::digest(&bytes))!=spec.sha256 {fail!(ESTALE,"BIRTH_RUNTIME_SOURCE_DIGEST");}
        Ok(bytes)
    })();
    let finals=errors([source_current(state,spec,true)]);let current=first(&finals);observed.extend(finals);
    let bytes=operation?;current?;Ok(bytes)
}
fn entries(sources:&[RuntimeSource])->Vec<RuntimeTrustInput<'_>> {
    sources.iter().map(|source|RuntimeTrustInput {source:&source.spec.path,inventory_sha256:&source.spec.sha256,
        inventory_size:source.spec.size,bytes:&source.bytes}).collect()
}
// Closed local mapping. The descriptive report is checked separately and is
// never accepted as an effect-bearing plan or source of provenance.
fn destination(target:&DeploymentTarget,name:&str)->EnclaveResult<Option<PathBuf>> {
    if source_bound(name).is_none(){fail!(EINVAL,"BIRTH_RUNTIME_SOURCE_ROUTE");}
    Ok(match name {
        "root.json"=>None,
        "enclave-host-config.json"|"fido-mds-allowlist.json"|"custody-envelope-policy-v1.json"=>Some(target.layout.cas_store_root.join(name)),
        _=>Some(target.layout.state_root.join("cas/tuf/repo").join(name)),
    })
}
impl RuntimeTransportPlan {
    fn build(state:&BirthState,approved:&TargetInstallPlan,sources:&[RuntimeSource])->EnclaveResult<Self> {
        private_ancestry(state)?;
        let specs=source_specs(state,approved)?;
        if specs.len()!=sources.len()||specs.iter().zip(sources).any(|(spec,source)|spec!=&source.spec) {
            fail!(ESTALE,"BIRTH_RUNTIME_SOURCE_SET");
        }
        let target=&state.plan.target;let l=&target.layout;let mut directories=BTreeSet::new();
        for entry in &approved.directories {
            if runtime_roots(state).iter().any(|root|entry.path.starts_with(root)) {
                if !directories.insert(entry.path.clone()){fail!(EINVAL,"BIRTH_RUNTIME_DIRECTORY_ALIAS");}
            }
        }
        for root in runtime_roots(state) {if !directories.contains(root){fail!(EACCES,"BIRTH_RUNTIME_ROOT_DECLARATION_REQUIRED");}}
        for path in [l.support_root.join("tuf"),l.state_root.join("cas/tuf"),l.state_root.join("cas/tuf/repo")] {
            if !directories.insert(path){fail!(EINVAL,"BIRTH_RUNTIME_DIRECTORY_ALIAS");}
        }
        if state.dirs.len().checked_add(directories.len()).is_none_or(|n|n>MAX_NODES) {fail!(E2BIG,"BIRTH_DIRECTORY_LIMIT");}
        let pin=l.support_root.join("tuf/root.json");let mut copies=Vec::new();
        for source in sources {
            if let Some(destination)=destination(target,source.spec.path.file_name().and_then(|n|n.to_str())
                .ok_or_else(||err!(EINVAL,"BIRTH_RUNTIME_SOURCE_ROUTE"))?)? {
                copies.push(RuntimeCopy {source:source.spec.path.clone(),destination,size:source.spec.size,sha256:source.spec.sha256.clone()});
            }
        }
        let outputs=copies.iter().map(|copy|&copy.destination).chain([&pin]).collect::<Vec<_>>();
        if outputs.len()!=sources.len()||outputs.len()<7||outputs.len()>MAX_SOURCES {fail!(E2BIG,"BIRTH_RUNTIME_OUTPUT_BOUND");}
        let mut spellings=BTreeSet::new();
        for path in &directories {
            exact_path(path)?;below(path,&state.plan.root)?;let key=folded(path)?;
            if !spellings.insert(key.clone())||overlaps(path,&l.staging_root)? {fail!(EINVAL,"BIRTH_RUNTIME_DIRECTORY_ALIAS");}
            for cached in state.dirs.keys() {
                if cached.as_path()==Path::new("/"){continue;}
                if folded(cached)?==key {fail!(EALREADY,"BIRTH_RUNTIME_EXISTING_DIRECTORY");}
            }
            for file in state.files.keys().chain(approved.copies.iter().map(|c|&c.destination))
                .chain(reserved_files(state).iter()) {
                let file=folded(file)?;
                if key==file||key.starts_with(file){fail!(EINVAL,"BIRTH_RUNTIME_DIRECTORY_FILE_COLLISION");}
            }
            let parent=path.parent().ok_or_else(||err!(EINVAL,"BIRTH_RUNTIME_PATH"))?;
            if !directories.contains(parent)&&!state.dirs.contains_key(parent) {fail!(EACCES,"BIRTH_RUNTIME_UNDECLARED_PARENT");}
        }
        let mut file_spellings=BTreeSet::new();
        for path in &outputs {
            exact_path(path)?;below(path,&state.plan.root)?;let key=folded(path)?;
            if !file_spellings.insert(key.clone())||overlaps(path,&l.staging_root)? {fail!(EINVAL,"BIRTH_RUNTIME_FILE_ALIAS");}
            if !path.parent().is_some_and(|parent|directories.contains(parent)){fail!(EACCES,"BIRTH_RUNTIME_UNDECLARED_PARENT");}
            for other in state.files.keys().chain(approved.copies.iter().map(|c|&c.destination)) {
                if overlaps(path,other)? {fail!(EINVAL,"BIRTH_RUNTIME_FILE_ALIAS");}
            }
            for reserved in reserved_files(state) {if reserved!=pin&&overlaps(path,&reserved)? {fail!(EACCES,"BIRTH_RUNTIME_RESERVED_OUTPUT");}}
            for cached in state.dirs.keys().filter(|p|p.as_path()!=Path::new("/")) {
                let cached=folded(cached)?;if key==cached||cached.starts_with(&key){fail!(EINVAL,"BIRTH_RUNTIME_FILE_ALIAS");}
            }
            for directory in &directories {
                let directory=folded(directory)?;
                if key==directory||directory.starts_with(&key){fail!(EINVAL,"BIRTH_RUNTIME_FILE_ALIAS");}
            }
        }
        for (index,path) in outputs.iter().enumerate() {for other in &outputs[..index] {
            if overlaps(path,other)? {fail!(EINVAL,"BIRTH_RUNTIME_FILE_ALIAS");}
        }}
        let mut directories=directories.into_iter().collect::<Vec<_>>();directories.sort_by_key(|p|(p.components().count(),p.clone()));
        copies.sort_by(|a,b|a.destination.cmp(&b.destination));Ok(Self {directories,copies,pin})
    }
    fn assert_absent(&self,state:&BirthState)->EnclaveResult<()> {
        for path in &self.directories {absent_from_original(state,path)?;}
        for path in self.copies.iter().map(|copy|&copy.destination).chain([&self.pin]) {absent_from_original(state,path)?;}
        Ok(())
    }
    fn partial_current(&self,state:&BirthState,pin_bytes:&[u8],complete:bool)->Vec<EnclaveError> {
        let mut observed=errors([private_ancestry(state)]);
        for path in &self.directories {
            match state.dirs.get(path) {
                Some(directory)=>{
                    if !directory.private||directory.stamp.mode&0o7777!=0o700 {
                        observed.push(err!(ESTALE,"BIRTH_RUNTIME_DIRECTORY_CHANGED"));
                    }
                    observed.extend(errors([directory.current(&directory.file,state.protection,true)]));
                },
                None if complete=>observed.push(err!(ESTALE,"BIRTH_RUNTIME_DIRECTORY_INCOMPLETE")),_=>(),
            }
        }
        observed.extend(self.contents_current(state,pin_bytes,complete));observed
    }
    // Same original files/content only. A later consuming metadata phase must
    // separately enforce its genuine predicted directory stamps and root700.
    // This helper never accepts a metadata report or observed restamp.
    fn contents_current(&self,state:&BirthState,pin_bytes:&[u8],complete:bool)->Vec<EnclaveError> {
        let mut observed=Vec::new();
        for copy in &self.copies {
            let Some(file)=state.files.get(&copy.destination) else {
                if complete {observed.push(err!(ESTALE,"BIRTH_RUNTIME_COPY_INCOMPLETE"));}continue;
            };
            let operation=(|| {
                let source=state.files.get(&copy.source).ok_or_else(||err!(ESTALE,"BIRTH_RUNTIME_ORIGINAL_SOURCE_REQUIRED"))?;
                if file.access!=libc::O_RDONLY||file.stamp.len!=copy.size||file.stamp.directory.mode&0o7777!=0o644
                    ||file.streamed.as_ref().map(|s|(s.length,s.sha256.as_str()))!=Some((copy.size,copy.sha256.as_str()))
                    ||(file.stamp.directory.dev,file.stamp.directory.ino)==(source.stamp.directory.dev,source.stamp.directory.ino) {
                    fail!(ESTALE,"BIRTH_RUNTIME_COPY_CHANGED");
                }
                let parent=state.dirs.get(copy.destination.parent().expect("closed destination parent"))
                    .ok_or_else(||err!(ESTALE,"BIRTH_RUNTIME_ORIGINAL_PARENT_REQUIRED"))?;
                file.current(&parent.file,&copy.destination,state.protection)
            })();observed.extend(errors([operation]));
        }
        if let Some(file)=state.files.get(&self.pin) {
            let operation=(|| {
                if file.access!=libc::O_RDONLY||file.stamp.directory.mode&0o7777!=0o644
                    ||file.exact_bytes()!=Some(pin_bytes)||file.stamp.len!=pin_bytes.len()as u64 {
                    fail!(ESTALE,"BIRTH_RUNTIME_PIN_COPY_CHANGED");
                }
                let parent=state.dirs.get(self.pin.parent().expect("closed pin parent"))
                    .ok_or_else(||err!(ESTALE,"BIRTH_RUNTIME_ORIGINAL_PARENT_REQUIRED"))?;
                file.current(&parent.file,&self.pin,state.protection)
            })();observed.extend(errors([operation]));
        }else if complete {observed.push(err!(ESTALE,"BIRTH_RUNTIME_PIN_COPY_INCOMPLETE"));}
        observed
    }
}

struct RuntimeTransportAttempt<'guard> {pin:NativeRuntimePinBirth<'guard>,plan:Option<RuntimeTransportPlan>,sources:Vec<RuntimeSource>}
// The internal creator's callback borrows actual original authority owners;
// there is no caller/provider hook or reconstruction from a report. BirthState
// independently checks every original file, ancestry and private loaded input.
fn authority_boundary(checked:&CheckedDeploymentTarget,guard:&mut HostMaintenanceGuard,
    lease:&mut ExclusiveStartupLease,accounts:&FixedAccountAdmission,approval:&mut SoftwareApproval,
    inputs:&OperatorPinInputs,scope:&PinScope)->Vec<EnclaveError> {
    let mut observed=errors([require_native_root(),guard.assert_held(),lease.assert_current(checked),
        accounts.assert_current(checked,guard),approval.assert_current(checked,guard),inputs.complete(scope)]);
    observed.extend(inputs.observations());
    let sources=[&inputs.record,&inputs.pin].into_iter().flatten().map(|held|(held.path(),held.file())).collect::<Vec<_>>();
    observed.extend(errors([approval.assert_external_runtime_sources_separate(&sources)]));
    observed.extend(errors([require_native_root(),guard.assert_held(),lease.assert_current(checked)]));observed
}
impl RuntimeTransportAttempt<'_> {
    // This later phase deliberately does NOT call RuntimePinAttempt::gate or
    // observations: they require pristine runtime absence. Every genuine owner
    // gate is retained here, with same-original payload contents instead.
    fn observations(&mut self,complete:bool)->Vec<EnclaveError> {
        let original=&mut self.pin.owner;let mut observed=errors([require_native_root(),original.scope().map(|_|())]);
        observed.extend(original.payload.owner.observations());
        let state=&original.payload.owner.candidate.birth.state;
        observed.extend(errors([original.payload.plan.assert_private_contents(state),private_ancestry(state)]));
        if original.payload.owner.lease.is_none()||original.payload.owner.acquisition_failure.is_some() {
            observed.push(err!(EACCES,"BIRTH_RUNTIME_ACTUAL_EX_REQUIRED"));
        }
        observed.extend(original.inputs.observations());observed.extend(original.source_separation());
        observed.extend(errors([original.scope().and_then(|scope|original.inputs.complete(&scope))]));
        for source in &self.sources {observed.extend(errors([source_current(state,&source.spec,true)]));}
        if let Some(plan)=&self.plan {observed.extend(plan.partial_current(state,&original.inputs.pin_bytes,complete));}
        observed.extend(errors([original.payload.owner.candidate.verify_candidate()]));
        observed.extend(original.payload.owner.observations());observed
    }
    fn gate(&mut self,complete:bool,observed:&mut Vec<EnclaveError>)->EnclaveResult<()> {
        let checks=self.observations(complete);let current=first(&checks);observed.extend(checks);
        if current.is_err(){self.pin.owner.poison();}current
    }
    fn crypto(&self)->EnclaveResult<()> {
        self.crypto_expiry().map(|_|())
    }
    fn crypto_expiry(&self)->EnclaveResult<CryptoExpiryObservation> {self.crypto_expiry_with_owned_removal(None)}
    fn crypto_expiry_with_owned_removal(&self,removal:Option<&crate::deploy::target_birth::denial_handoff::OwnedDenialRemoval>)
        ->EnclaveResult<CryptoExpiryObservation> {
        let original=&self.pin.owner;let scope=original.scope()?;
        crypto_expiry_from_originals(&original.payload.owner.candidate.birth.state,&original.inputs,&self.sources,&scope,removal)
    }
    fn create_directory(&mut self,path:&Path,observed:&mut Vec<EnclaveError>)->EnclaveResult<()> {
        self.gate(false,observed)?;
        let original=&mut self.pin.owner;let scope=original.scope()?;
        let checked=checked(&original.payload.owner.candidate.birth.state)?.clone();
        let inputs=&original.inputs;let owner=&mut original.payload.owner;
        let lease=owner.lease.as_mut().ok_or_else(||err!(EACCES,"BIRTH_RUNTIME_ACTUAL_EX_REQUIRED"))?;
        let candidate=&mut owner.candidate;
        let accounts=candidate.accounts.as_ref().ok_or_else(||err!(EACCES,"BIRTH_RUNTIME_ACTUAL_ACCOUNTS_REQUIRED"))?;
        let approval=candidate.approval.as_mut().ok_or_else(||err!(EACCES,"BIRTH_RUNTIME_ACTUAL_SOFTWARE_REQUIRED"))?;
        let birth=&mut candidate.birth;
        let operation=birth.state.create_directory(path,&mut||authority_boundary(&checked,birth.guard,lease,accounts,approval,inputs,&scope),
            observed,&mut enclave_core::fsutil::full_fsync);
        let post=self.gate(false,observed);if let Err(error)=&post {observed.push(error.clone());}operation?;post
    }
    fn create_output(&mut self,index:Option<usize>,observed:&mut Vec<EnclaveError>)->EnclaveResult<()> {
        self.gate(false,observed)?;
        let original=&mut self.pin.owner;let scope=original.scope()?;
        let checked=checked(&original.payload.owner.candidate.birth.state)?.clone();
        let inputs=&original.inputs;let owner=&mut original.payload.owner;
        let lease=owner.lease.as_mut().ok_or_else(||err!(EACCES,"BIRTH_RUNTIME_ACTUAL_EX_REQUIRED"))?;
        let candidate=&mut owner.candidate;
        let accounts=candidate.accounts.as_ref().ok_or_else(||err!(EACCES,"BIRTH_RUNTIME_ACTUAL_ACCOUNTS_REQUIRED"))?;
        let approval=candidate.approval.as_mut().ok_or_else(||err!(EACCES,"BIRTH_RUNTIME_ACTUAL_SOFTWARE_REQUIRED"))?;
        let birth=&mut candidate.birth;let plan=self.plan.as_ref().expect("closed plan before effects");
        let mut check=||authority_boundary(&checked,birth.guard,lease,accounts,approval,inputs,&scope);
        let operation=match index {
            Some(index)=>{let copy=&plan.copies[index];birth.state.create_file_from_birth_stage(&copy.source,&copy.destination,
                copy.size,&copy.sha256,0o644,&mut check,observed,&mut enclave_core::fsutil::full_fsync)},
            None=>birth.state.create_file(&plan.pin,&inputs.pin_bytes,0o644,&mut check,observed,&mut enclave_core::fsutil::full_fsync),
        };
        let post=self.gate(false,observed);if let Err(error)=&post {observed.push(error.clone());}operation?;post
    }
}

// Same actual verifier, factored only for descendants borrowing the SAME
// guard separately. No report, deadline, callback or replacement source owner.
fn crypto_expiry_from_originals(state:&BirthState,inputs:&OperatorPinInputs,sources:&[RuntimeSource],scope:&PinScope,
    removal:Option<&crate::deploy::target_birth::denial_handoff::OwnedDenialRemoval>)->EnclaveResult<CryptoExpiryObservation> {
    let loaded=state.private_load.as_ref().ok_or_else(||err!(EACCES,"BIRTH_RUNTIME_PRIVATE_LOAD_REQUIRED"))?;
    loaded.current_with_owned_removal(state,removal)?;
    let actual=checked(state)?;
    if actual.target()!=&state.plan.target||actual.config_path()!=state.plan.descriptor
        ||actual.descriptor_sha256()!=hex::encode(Sha256::digest(&state.plan.bytes)) {
        fail!(ESTALE,"BIRTH_RUNTIME_PIN_CHECKED_BINDING");
    }
    let expected=dedicated_scope(actual.target(),actual.config_path(),actual.descriptor_sha256(),&state.plan.root)?;
    if scope.root!=expected.root||scope.target_id!=expected.target_id||scope.descriptor_sha256!=expected.descriptor_sha256 {
        fail!(ESTALE,"BIRTH_RUNTIME_PIN_CHECKED_BINDING");
    }
    inputs.complete(scope)?;
    let selection=inputs.selection.as_ref().ok_or_else(||err!(EACCES,"BIRTH_RUNTIME_PIN_RECORD_REQUIRED"))?;
    let input=entries(sources);
    let _diagnostic=target_runtime_trust::describe(&state.plan.target,&scope.descriptor_sha256,&input)?;
    // Fresh actual time on each successful genuine verification. Existing
    // trusted clock/version/enrollment floors are neither reset nor replaced.
    let now=enclave_crypto::time::now_unix();
    let conditional=target_runtime_preflight::preflight(&state.plan.target,&scope.descriptor_sha256,&input,
        &inputs.pin_bytes,&selection.pin_sha256,loaded.custody_provisioning()?,now)?;
    let not_after=conditional.metadata_expires_at.min(conditional.envelope_review_or_expiry)
        .min(loaded.custody_provisioning()?.receipt().asset_policy_expires_unix);
    loaded.current_with_owned_removal(state,removal)?;
    let observation=CryptoExpiryObservation {checked_at:now,not_after};observation.current()?;Ok(observation)
}

#[must_use="retain actual native birth, all operator sources, guard and EX"]
pub(crate) struct NativeRuntimeTransportBirth<'guard> {owner:RuntimeTransportAttempt<'guard>}
impl std::fmt::Debug for NativeRuntimeTransportBirth<'_> {
    fn fmt(&self,f:&mut std::fmt::Formatter<'_>)->std::fmt::Result {
        f.debug_struct("NativeRuntimeTransportBirth").field("observations",&"<redacted>").finish_non_exhaustive()
    }
}
#[must_use="retain same real owners and every partial runtime name on refusal"]
pub(crate) struct NativeRuntimeTransportFailure<'guard> {
    pub(crate) error:EnclaveError,pub(crate) boundary_errors:Vec<EnclaveError>,pub(crate) final_errors:Vec<EnclaveError>,
    pub(crate) progress:BirthProgress,owner:RuntimeTransportAttempt<'guard>,
}
impl std::fmt::Debug for NativeRuntimeTransportFailure<'_> {
    fn fmt(&self,f:&mut std::fmt::Formatter<'_>)->std::fmt::Result {
        f.debug_struct("NativeRuntimeTransportFailure").field("reason",&self.error.reason)
            .field("boundary_error_count",&self.boundary_errors.len()).field("final_error_count",&self.final_errors.len())
            .field("observations",&"<redacted>").finish_non_exhaustive()
    }
}
impl<'guard> NativeRuntimePinBirth<'guard> {
    pub(crate) fn prepare_private_runtime_transport(self)
        ->Result<NativeRuntimeTransportBirth<'guard>,NativeRuntimeTransportFailure<'guard>> {
        let mut owner=RuntimeTransportAttempt {pin:self,plan:None,sources:Vec::new()};let mut boundary_errors=Vec::new();
        owner.pin.owner.payload.owner.candidate.birth.state.progress.operation="prepare_private_runtime_transport";
        let operation=(|| {
            // Last pristine gate, before ANY runtime directory or file effect.
            owner.pin.owner.gate(&mut boundary_errors)?;
            let original=&owner.pin.owner;let candidate=&original.payload.owner.candidate;
            let approved=candidate.plan.as_ref().ok_or_else(||err!(EACCES,"BIRTH_RUNTIME_PLAN_REQUIRED"))?;
            let specs=source_specs(&candidate.birth.state,approved)?;
            for spec in specs {
                let bytes=read_source(&owner.pin.owner.payload.owner.candidate.birth.state,&spec,&mut boundary_errors)?;
                owner.sources.push(RuntimeSource {spec,bytes});owner.gate(false,&mut boundary_errors)?;
            }
            let candidate=&owner.pin.owner.payload.owner.candidate;
            owner.plan=Some(RuntimeTransportPlan::build(&candidate.birth.state,candidate.plan.as_ref().expect("actual approved plan"),&owner.sources)?);
            owner.plan.as_ref().expect("closed runtime plan").assert_absent(&candidate.birth.state)?;
            owner.crypto()?;owner.gate(false,&mut boundary_errors)?;
            let directories=owner.plan.as_ref().expect("closed plan").directories.clone();
            for path in directories {owner.create_directory(&path,&mut boundary_errors)?;}
            owner.create_output(None,&mut boundary_errors)?;
            for index in 0..owner.plan.as_ref().expect("closed plan").copies.len() {owner.create_output(Some(index),&mut boundary_errors)?;}
            owner.gate(true,&mut boundary_errors)?;owner.crypto()?;owner.gate(true,&mut boundary_errors)
        })();
        let mut final_errors=owner.observations(true);
        // Crypto is independently attempted even on an earlier operation or
        // original-owner refusal; missing/partial inputs remain concrete errors.
        let expiry=match owner.crypto_expiry() {Ok(expiry)=>Some(expiry),Err(error)=>{final_errors.push(error);None}};
        final_errors.extend(owner.observations(true));
        // Last practical acceptance boundary AFTER slow native/source checks
        // and software saves. Equality refuses; no old sampled now is reused.
        if let Some(expiry)=expiry {final_errors.extend(errors([expiry.current()]));}
        match resolve_owned(owner,operation,boundary_errors,final_errors) {
            Ok(mut owner)=>{let progress=&mut owner.pin.owner.payload.owner.candidate.birth.state.progress;
                progress.complete=true;progress.uncertain_effects=false;Ok(NativeRuntimeTransportBirth {owner})},
            Err(mut refusal)=>{refusal.owner.pin.owner.poison();Err(NativeRuntimeTransportFailure {error:refusal.error,
                boundary_errors:refusal.boundary_errors,final_errors:refusal.final_errors,
                progress:refusal.owner.pin.owner.payload.owner.candidate.birth.state.progress.clone(),owner:refusal.owner})},
        }
    }
}

#[cfg(test)]
#[path="target_birth_runtime_transport_tests.rs"]
mod tests;
