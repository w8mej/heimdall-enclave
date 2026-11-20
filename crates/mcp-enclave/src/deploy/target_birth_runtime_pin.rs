//! Current administrative runtime-pin input, conditional on a GENUINE external
//! operator choice for this allocated descriptor. Protected JSON/hash/ownership
//! does not establish that choice, cryptographic approval or runtime authority.
//! No record provisioning, runtime writes, TUF bootstrap, publication or start.
//!
//! This is a private child of payload; the coordinator supplies its module wire.
//! Every returned original HeldFile and captured HeldPaths is retained before
//! subsequent checks. HeldFile::open may drop an unreturned temporary descriptor
//! on its own internal refusal; that unadmitted temporary is not claimed held.
use super::*;

#[path="target_birth_runtime_transport.rs"]
mod runtime_transport;
use crate::ctl::{HeldFile,HeldPaths};
use serde::Deserialize;

const MAX_RECORD_BYTES:u64=64*1024;
const MAX_PIN_BYTES:u64=4*1024*1024;
const READ_CHUNK:usize=64*1024;
const RECORD_KIND:&str="mcpmac-operator-runtime-pin-selection";
const RECORD_PURPOSE:&str="runtime-tuf-first-provisioning";

// Plain scope data, never checked deployment or approval authority.
struct PinScope {root:PathBuf,target_id:String,descriptor_sha256:String}
fn lower_hex(text:&str,length:usize)->bool {
    text.len()==length&&text.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b))
}
fn exact_path(path:&Path)->EnclaveResult<()> {
    if normalized_path(path)?!=path||path.components().count()>96
        ||path.components().any(|c|matches!(c,Component::Normal(n)if n.as_bytes().len()>255)) {
        fail!(EINVAL,"BIRTH_RUNTIME_PIN_PATH");
    }Ok(())
}
fn dedicated_scope(target:&DeploymentTarget,descriptor:&Path,descriptor_sha256:&str,root:&Path)
    ->EnclaveResult<PinScope> {
    target.validate()?;exact_path(root)?;exact_path(descriptor)?;
    let token=root.file_name().and_then(|name|name.to_str()).unwrap_or("");
    if target.role!=DeploymentRole::DedicatedTest||target.profile!=Profile::L2
        ||target.signing_identity_mode!=DeploymentSigningMode::LocalPins||target.broker.is_some()
        ||!target.shared_read_only_inputs.is_empty()||!lower_hex(token,32)
        ||target.target_id!=format!("ykft-{token}")||descriptor!=root.join(DESCRIPTOR)
        ||!lower_hex(descriptor_sha256,64) {
        fail!(EACCES,"BIRTH_RUNTIME_PIN_ALLOCATED_DEDICATED_L2_REQUIRED");
    }
    for path in roots(target).into_iter().chain([target.authority_config.as_path(),
        target.expected_artifacts_manifest.as_path(),target.codesign_pins_file.as_path()]) {
        exact_path(path)?;below(path,root)?;
    }
    Ok(PinScope {root:root.to_owned(),target_id:target.target_id.clone(),descriptor_sha256:descriptor_sha256.into()})
}
fn external_route(scope:&PinScope,path:&Path)->EnclaveResult<()> {
    exact_path(path)?;
    if overlaps(path,&scope.root)?||overlaps(path,Path::new("/Library/LaunchAgents"))?
        ||overlaps(path,Path::new("/Library/LaunchDaemons"))? {
        fail!(EACCES,"BIRTH_RUNTIME_PIN_SOURCE_DOMAIN");
    }Ok(())
}

#[derive(Deserialize,PartialEq,Eq)]
#[serde(deny_unknown_fields)]
struct OperatorRecord {
    version:u8,kind:String,purpose:String,target_id:String,profile:Profile,
    descriptor_sha256:String,pin_source_file:PathBuf,pin_sha256:String,
}
fn record(bytes:&[u8],scope:&PinScope,record_path:&Path)->EnclaveResult<OperatorRecord> {
    if bytes.is_empty()||bytes.len()>MAX_RECORD_BYTES as usize {fail!(E2BIG,"BIRTH_RUNTIME_PIN_RECORD_BOUND");}
    // No escaped keys/paths, Unicode aliases, duplicate members, floating-point
    // version encodings or nonclosed schema. No bytes are normalized/rewritten.
    if !bytes.is_ascii()||bytes.contains(&b'\\') {fail!(EINVAL,"BIRTH_RUNTIME_PIN_RECORD_SCHEMA");}
    crate::deploy::target_release_json::strict(bytes,MAX_RECORD_BYTES as usize)
        .map_err(|_|err!(EINVAL,"BIRTH_RUNTIME_PIN_RECORD_SCHEMA"))?;
    let selection:OperatorRecord=serde_json::from_slice(bytes).map_err(|_|err!(EINVAL,"BIRTH_RUNTIME_PIN_RECORD_SCHEMA"))?;
    if selection.version!=1||selection.kind!=RECORD_KIND||selection.purpose!=RECORD_PURPOSE
        ||selection.profile!=Profile::L2||selection.target_id!=scope.target_id
        ||selection.descriptor_sha256!=scope.descriptor_sha256||!lower_hex(&selection.descriptor_sha256,64)
        ||!lower_hex(&selection.pin_sha256,64) {
        fail!(EACCES,"BIRTH_RUNTIME_PIN_RECORD_SCOPE");
    }
    external_route(scope,record_path)?;external_route(scope,&selection.pin_source_file)?;
    if overlaps(record_path,&selection.pin_source_file)? {fail!(EACCES,"BIRTH_RUNTIME_PIN_SOURCE_ALIAS");}
    Ok(selection)
}
fn original_protection(held:&HeldFile)->EnclaveResult<()> {
    let metadata=stat(held.file())?;
    if !metadata.is_file()||metadata.uid()!=0||metadata.gid()!=0||metadata.mode()&0o7777!=0o600
        ||metadata.nlink()!=1||metadata.len()!=held.size() {
        fail!(EACCES,"BIRTH_RUNTIME_PIN_SOURCE_PROTECTION");
    }
    flags(held.file(),libc::O_RDONLY)
}
fn independent_inodes(sources:&[&HeldFile],birth_originals:&BTreeSet<(u64,u64)>)->EnclaveResult<()> {
    let mut observed=BTreeSet::new();
    for held in sources {
        let metadata=stat(held.file())?;let identity=(metadata.dev(),metadata.ino());
        if !observed.insert(identity)||birth_originals.contains(&identity) {
            fail!(EACCES,"BIRTH_RUNTIME_PIN_SOURCE_ALIAS");
        }
    }Ok(())
}
fn same_fd_pin_bytes(paths:&HeldPaths,pin:&HeldFile,observed:&mut Vec<EnclaveError>)->EnclaveResult<Vec<u8>> {
    let before=errors([original_protection(pin),pin.revalidate(paths)]);
    let admission=first(&before);observed.extend(before);
    let operation=(|| {
        admission?;
        let length=usize::try_from(pin.size()).map_err(|_|err!(E2BIG,"BIRTH_RUNTIME_PIN_BOUND"))?;
        if length==0||length>MAX_PIN_BYTES as usize {fail!(E2BIG,"BIRTH_RUNTIME_PIN_BOUND");}
        let mut bytes=vec![0;length];let mut offset=0;
        while offset<length {
            let end=(offset+READ_CHUNK).min(length);
            let count=pin.file().read_at(&mut bytes[offset..end],offset as u64)
                .map_err(|_|err!(EIO,"BIRTH_RUNTIME_PIN_READ"))?;
            if count==0 {fail!(ESTALE,"BIRTH_RUNTIME_PIN_EARLY_EOF");}offset+=count;
        }
        let mut extra=[0];
        if pin.file().read_at(&mut extra,length as u64).map_err(|_|err!(EIO,"BIRTH_RUNTIME_PIN_READ"))?!=0 {
            fail!(ESTALE,"BIRTH_RUNTIME_PIN_GROWTH");
        }
        if hex::encode(Sha256::digest(&bytes))!=pin.sha256() {fail!(ESTALE,"BIRTH_RUNTIME_PIN_DIGEST");}
        Ok(bytes)
    })();
    let after=errors([original_protection(pin),pin.revalidate(paths),paths.revalidate()]);
    let current=first(&after);observed.extend(after);
    let bytes=operation?;current?;Ok(bytes)
}

// Partial reader state is installed in the enclosing owner before each later
// parser/digest/separation gate. No Clone, raw-record or FD export exists.
struct OperatorPinInputs {
    paths:Option<HeldPaths>,record:Option<HeldFile>,record_bytes:Vec<u8>,selection:Option<OperatorRecord>,
    pin:Option<HeldFile>,pin_bytes:Vec<u8>,record_attempted:bool,pin_attempted:bool,poisoned:bool,
}
impl std::fmt::Debug for OperatorPinInputs {
    fn fmt(&self,f:&mut std::fmt::Formatter<'_>)->std::fmt::Result {
        f.debug_struct("OperatorPinInputs").field("observations",&"<redacted>").field("poisoned",&self.poisoned).finish()
    }
}
impl OperatorPinInputs {
    fn empty()->Self {Self {paths:None,record:None,record_bytes:Vec::new(),selection:None,
        pin:None,pin_bytes:Vec::new(),record_attempted:false,pin_attempted:false,poisoned:false}}
    fn observations(&self)->Vec<EnclaveError> {
        let mut observed=Vec::new();
        if self.poisoned {observed.push(err!(EACCES,"BIRTH_RUNTIME_PIN_OWNER_POISONED"));}
        if let Some(paths)=&self.paths {
            observed.extend(errors([paths.revalidate()]));
            for held in [&self.record,&self.pin].into_iter().flatten() {
                observed.extend(errors([original_protection(held),held.revalidate(paths)]));
            }
            observed.extend(errors([paths.revalidate()]));
        }else if self.record.is_some()||self.pin.is_some(){observed.push(err!(ESTALE,"BIRTH_RUNTIME_PIN_PATHS_REQUIRED"));}
        observed
    }
    fn finish<T>(&mut self,operation:EnclaveResult<T>,observed:&mut Vec<EnclaveError>)->EnclaveResult<T> {
        let finals=self.observations();let current=first(&finals);observed.extend(finals);
        if operation.is_err()||current.is_err(){self.poisoned=true;}
        let value=operation?;current?;Ok(value)
    }
    fn read_record(&mut self,scope:&PinScope,path:&Path,observed:&mut Vec<EnclaveError>)->EnclaveResult<()> {
        let operation=(|| {
            if self.poisoned {fail!(EACCES,"BIRTH_RUNTIME_PIN_OWNER_POISONED");}
            if self.record_attempted {fail!(EALREADY,"BIRTH_RUNTIME_PIN_NO_RETRY");}self.record_attempted=true;
            external_route(scope,path)?;
            let paths=self.paths.as_mut().ok_or_else(||err!(EACCES,"BIRTH_RUNTIME_PIN_PATHS_REQUIRED"))?;
            let (held,bytes)=HeldFile::open(paths,path,MAX_RECORD_BYTES,Some(0o600))?;
            self.record=Some(held);self.record_bytes=bytes;
            self.selection=Some(record(&self.record_bytes,scope,path)?);Ok(())
        })();self.finish(operation,observed)
    }
    fn read_pin(&mut self,observed:&mut Vec<EnclaveError>)->EnclaveResult<()> {
        let operation=(|| {
            if self.poisoned {fail!(EACCES,"BIRTH_RUNTIME_PIN_OWNER_POISONED");}
            if self.pin_attempted {fail!(EALREADY,"BIRTH_RUNTIME_PIN_NO_RETRY");}self.pin_attempted=true;
            let selection=self.selection.as_ref().ok_or_else(||err!(EACCES,"BIRTH_RUNTIME_PIN_RECORD_REQUIRED"))?;
            let paths=self.paths.as_mut().ok_or_else(||err!(EACCES,"BIRTH_RUNTIME_PIN_PATHS_REQUIRED"))?;
            let (held,omitted)=HeldFile::open(paths,&selection.pin_source_file,MAX_PIN_BYTES,Some(0o600))?;
            self.pin=Some(held);drop(omitted); // >1MiB helper bound omits bytes even for small files.
            let pin=self.pin.as_ref().expect("original pin installed before later checks");
            let record=self.record.as_ref().ok_or_else(||err!(EACCES,"BIRTH_RUNTIME_PIN_RECORD_REQUIRED"))?;
            let a=stat(pin.file())?;let b=stat(record.file())?;
            if (a.dev(),a.ino())==(b.dev(),b.ino()){fail!(EACCES,"BIRTH_RUNTIME_PIN_SOURCE_ALIAS");}
            self.pin_bytes=same_fd_pin_bytes(paths,pin,observed)?;
            if pin.sha256()!=selection.pin_sha256 {fail!(EACCES,"BIRTH_RUNTIME_PIN_EXPECTATION");}Ok(())
        })();self.finish(operation,observed)
    }
    fn complete(&self,scope:&PinScope)->EnclaveResult<()> {
        if self.poisoned {fail!(EACCES,"BIRTH_RUNTIME_PIN_OWNER_POISONED");}
        let original=self.record.as_ref().ok_or_else(||err!(EACCES,"BIRTH_RUNTIME_PIN_RECORD_REQUIRED"))?;
        let selection=self.selection.as_ref().ok_or_else(||err!(EACCES,"BIRTH_RUNTIME_PIN_RECORD_REQUIRED"))?;
        let pin=self.pin.as_ref().ok_or_else(||err!(EACCES,"BIRTH_RUNTIME_PIN_REQUIRED"))?;
        if record(&self.record_bytes,scope,original.path())?!=*selection
            ||hex::encode(Sha256::digest(&self.record_bytes))!=original.sha256()
            ||self.record_bytes.len()as u64!=original.size()||pin.path()!=selection.pin_source_file
            ||pin.sha256()!=selection.pin_sha256||self.pin_bytes.is_empty()||self.pin_bytes.len()as u64>MAX_PIN_BYTES
            ||self.pin_bytes.len()as u64!=pin.size()||hex::encode(Sha256::digest(&self.pin_bytes))!=pin.sha256() {
            fail!(ESTALE,"BIRTH_RUNTIME_PIN_ORIGINAL_BINDING");
        }Ok(())
    }
}

struct RuntimePinAttempt<'guard> {
    payload:NativePrivatePayloadBirth<'guard>,inputs:OperatorPinInputs,later_errors:Vec<EnclaveError>,
}
impl RuntimePinAttempt<'_> {
    fn scope(&self)->EnclaveResult<PinScope> {
        let state=&self.payload.owner.candidate.birth.state;let checked=checked(state)?;
        if checked.target()!=&state.plan.target||checked.config_path()!=state.plan.descriptor
            ||checked.descriptor_sha256()!=hex::encode(Sha256::digest(&state.plan.bytes)) {
            fail!(ESTALE,"BIRTH_RUNTIME_PIN_CHECKED_BINDING");
        }
        dedicated_scope(checked.target(),checked.config_path(),checked.descriptor_sha256(),&state.plan.root)
    }
    fn source_separation(&self)->Vec<EnclaveError> {
        let state=&self.payload.owner.candidate.birth.state;
        let originals=state.files.values().map(|file|(file.stamp.directory.dev,file.stamp.directory.ino))
            .chain(state.dirs.values().map(|dir|(dir.stamp.dev,dir.stamp.ino))).collect::<BTreeSet<_>>();
        let held=[&self.inputs.record,&self.inputs.pin].into_iter().flatten().collect::<Vec<_>>();
        let mut observed=errors([independent_inodes(&held,&originals)]);
        let sources=held.into_iter().map(|file|(file.path(),file.file())).collect::<Vec<_>>();
        if !sources.is_empty() {
            // Required actual-owner predicate supplied by coordinator before
            // wiring: compare ORIGINAL SOFTWARE input paths/inodes + repository
            // and state domains, recheck inputs/trust disk, no clock/save/refresh.
            observed.extend(errors([self.payload.owner.candidate.approval.as_ref()
                .ok_or_else(||err!(EACCES,"BIRTH_RUNTIME_PIN_SOFTWARE_OWNER_REQUIRED"))
                .and_then(|approval|approval.assert_external_runtime_sources_separate(&sources))]));
        }observed
    }
    fn observations(&mut self)->Vec<EnclaveError> {
        let mut observed=errors([require_native_root(),self.scope().map(|_|())]);
        observed.extend(self.payload.owner.observations());
        let state=&self.payload.owner.candidate.birth.state;
        observed.extend(errors([self.payload.plan.assert_prepared(state),private_ancestry(state)]));
        if self.payload.owner.lease.is_none()||self.payload.owner.acquisition_failure.is_some() {
            observed.push(err!(EACCES,"BIRTH_RUNTIME_PIN_ACTUAL_EX_REQUIRED"));
        }
        observed.extend(self.inputs.observations());observed.extend(self.source_separation());
        observed.extend(errors([self.payload.owner.candidate.verify_candidate()]));
        observed.extend(self.payload.owner.observations());observed
    }
    fn gate(&mut self,observed:&mut Vec<EnclaveError>)->EnclaveResult<()> {
        let checks=self.observations();let current=first(&checks);observed.extend(checks);
        if current.is_err(){self.poison();}current
    }
    fn poison(&mut self) {
        self.inputs.poisoned=true;let state=&mut self.payload.owner.candidate.birth.state;
        state.poisoned=true;state.progress.complete=false;state.progress.uncertain_effects=true;
    }
}

/// Administrative input observation ONLY, conditional on genuine external
/// operator choice. No approval/crypto/runtime/installation authority results.
#[must_use="retain original payload, actual guard/EX and operator source owners"]
pub(crate) struct NativeRuntimePinBirth<'guard> {owner:RuntimePinAttempt<'guard>}
impl std::fmt::Debug for NativeRuntimePinBirth<'_> {
    fn fmt(&self,f:&mut std::fmt::Formatter<'_>)->std::fmt::Result {
        f.debug_struct("NativeRuntimePinBirth").field("observations",&"<redacted>").finish_non_exhaustive()
    }
}
#[must_use="retain same payload and every captured original operator input on refusal"]
pub(crate) struct NativeRuntimePinFailure<'guard> {
    pub(crate) error:EnclaveError,pub(crate) boundary_errors:Vec<EnclaveError>,pub(crate) final_errors:Vec<EnclaveError>,
    pub(crate) progress:BirthProgress,owner:RuntimePinAttempt<'guard>,
}
impl std::fmt::Debug for NativeRuntimePinFailure<'_> {
    fn fmt(&self,f:&mut std::fmt::Formatter<'_>)->std::fmt::Result {
        f.debug_struct("NativeRuntimePinFailure").field("reason",&self.error.reason)
            .field("boundary_error_count",&self.boundary_errors.len()).field("final_error_count",&self.final_errors.len())
            .field("observations",&"<redacted>").finish_non_exhaustive()
    }
}
impl<'guard> NativePrivatePayloadBirth<'guard> {
    /// Load an already independently chosen/provisioned operator record/pin.
    /// The caller MUST supply a genuine external runtime-purpose choice; no
    /// ownership, purpose string, digest, candidate or SOFTWARE approval proves
    /// it. Existing owner gates may persist their existing software time floor.
    pub(crate) fn pick_up_operator_runtime_pin(self,record_path:&Path)
        ->Result<NativeRuntimePinBirth<'guard>,NativeRuntimePinFailure<'guard>> {
        let mut owner=RuntimePinAttempt {payload:self,inputs:OperatorPinInputs::empty(),later_errors:Vec::new()};let mut boundary_errors=Vec::new();
        owner.payload.owner.candidate.birth.state.progress.operation="pick_up_operator_runtime_pin";
        let operation=(|| {
            owner.gate(&mut boundary_errors)?;let scope=owner.scope()?;external_route(&scope,record_path)?;
            owner.inputs.paths=Some(HeldPaths::new_native_acl_protected()?);
            owner.gate(&mut boundary_errors)?;
            let read=owner.inputs.read_record(&scope,record_path,&mut boundary_errors);
            let current=owner.gate(&mut boundary_errors);read?;current?;
            let read=owner.inputs.read_pin(&mut boundary_errors);
            let current=owner.gate(&mut boundary_errors);read?;current?;
            owner.inputs.complete(&scope)?;owner.gate(&mut boundary_errors)
        })();
        let mut final_errors=owner.observations();
        final_errors.extend(errors([owner.scope().and_then(|scope|owner.inputs.complete(&scope))]));
        final_errors.extend(owner.observations());
        match resolve_owned(owner,operation,boundary_errors,final_errors) {
            Ok(mut owner)=>{let progress=&mut owner.payload.owner.candidate.birth.state.progress;
                progress.complete=true;progress.uncertain_effects=false;Ok(NativeRuntimePinBirth {owner})},
            Err(mut refusal)=>{refusal.owner.poison();Err(NativeRuntimePinFailure {error:refusal.error,
                boundary_errors:refusal.boundary_errors,final_errors:refusal.final_errors,
                progress:refusal.owner.payload.owner.candidate.birth.state.progress.clone(),owner:refusal.owner})},
        }
    }
}
impl NativeRuntimePinBirth<'_> {
    // Payload-subtree borrow for a later ACTUAL crypto helper only. No FD,
    // checked target, guard, raw record or provenance/approval report escapes.
    pub(super) fn pin_bytes(&mut self)->EnclaveResult<(&[u8],&str)> {
        if self.owner.inputs.poisoned||self.owner.payload.owner.candidate.birth.state.poisoned {
            fail!(EACCES,"BIRTH_RUNTIME_PIN_OWNER_POISONED");
        }
        let mut observed=Vec::new();let operation=self.owner.gate(&mut observed)
            .and_then(|()|self.owner.scope()).and_then(|scope|self.owner.inputs.complete(&scope));
        let finals=self.owner.observations();let current=first(&finals);observed.extend(finals);
        if operation.is_err()||current.is_err(){
            if let Err(error)=&operation {observed.push(error.clone());}
            self.owner.later_errors.extend(observed);self.owner.poison();
        }
        operation?;current?;
        let selection=self.owner.inputs.selection.as_ref().ok_or_else(||err!(EACCES,"BIRTH_RUNTIME_PIN_RECORD_REQUIRED"))?;
        Ok((&self.owner.inputs.pin_bytes,&selection.pin_sha256))
    }
}

#[cfg(test)]
#[path="target_birth_runtime_pin_tests.rs"]
mod tests;
