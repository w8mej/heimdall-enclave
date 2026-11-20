//! Concrete same-invocation driver for the existing actual DedicatedL2 chain.
//! Public setup paths are data only. Every original native owner/refusal stays
//! alive through terminal output attempt; no adopted birth/resume/provider.
use super::*;
use crate::ctl::{HeldFile,HeldPaths};
use crate::deploy::target_birth_inputs::{BirthSourceRole,UnadmittedBirthSources};
use std::time::Instant;

#[path="target_birth_session_protocol.rs"]
mod protocol;
use protocol::{NativeStreams,Pickup,SetupCommand};

/// Paths for a new unpredictable native DedicatedL2 allocation only.
pub struct DedicatedBirthSessionArgs {
    /// Existing protected raw DedicatedL2/local-pins template, not authority.
    pub template:PathBuf,
    /// Strict ancestor of every declared raw template path.
    pub template_root:PathBuf,
    /// Existing native protected allocator parent; no existing root adopted.
    pub allocator_parent:PathBuf,
}
/// The driver already emitted its bounded terminal frame with owners retained.
pub struct DedicatedBirthSessionExit {
    /// Zero after actual explicit release; three after an emitted refusal.
    pub exit_code:u8,
}
/// Raw public data inputs for independent preparation; no protected selection.
pub struct DedicatedBirthRenderArgs {
    /// Exact final allocated descriptor PATH, not a read/adoption request.
    pub descriptor:PathBuf,
    /// External copy of exact public descriptor bytes from challenge.
    pub descriptor_input:PathBuf,
    /// External unadmitted custody manifest bytes; no raw scope identifiers output.
    pub custody_manifest:PathBuf,
}

#[derive(Clone,Default,Serialize)]
struct Effects {
    external_jobs_may_have_been_published:bool,
    namespace_visibility_may_have_changed:bool,
    denial_may_have_been_removed:bool,
    registration_may_have_changed:bool,
    explicit_startup_release_may_have_occurred:bool,
}
#[derive(Serialize)]
struct StableError {errno:enclave_core::error::Errno,reason:String}
impl From<&EnclaveError> for StableError {
    fn from(error:&EnclaveError)->Self{Self{errno:error.errno,reason:error.reason.clone()}}
}
#[derive(Serialize)]
struct Terminal {
    version:u8,kind:&'static str,status:&'static str,stage:&'static str,
    error:Option<StableError>,boundary_error_count:usize,boundary_errors:Vec<StableError>,final_errors:Vec<StableError>,
    progress:Option<BirthProgress>,effects:Effects,
    owner_lifetime:&'static str,exit_behavior:&'static str,runtime_readiness:&'static str,
    runtime_pin_provenance_verified:bool,qualified:bool,
}
impl Terminal {
    fn refused(stage:&'static str,error:&EnclaveError,boundary:&[EnclaveError],finals:&[EnclaveError],
        progress:Option<BirthProgress>,effects:Effects)->Self {
        Self{version:1,kind:"mcpmac-dedicated-birth-session-result",status:"refused",stage,
            error:Some(error.into()),boundary_error_count:boundary.len(),boundary_errors:boundary.iter().map(StableError::from).collect(),final_errors:finals.iter().map(StableError::from).collect(),
            progress,effects,owner_lifetime:"ACTUAL_OWNERS_RETAINED_THROUGH_TERMINAL_OUTPUT_ATTEMPT",
            exit_behavior:"TERMINAL_TEARDOWN_CLOSES_DESCRIPTORS_NO_ROLLBACK_OR_CONTINUING_INHIBITION_CLAIM",
            runtime_readiness:"UNKNOWN",runtime_pin_provenance_verified:false,qualified:false}
    }
}
// Generic only over an ACTUAL already-returned owner/refusal; this helper
// cannot construct, inspect, extract or certify one. Never map_err away owners.
fn terminal<O>(streams:&NativeStreams,owner:O,report:Terminal)->EnclaveResult<DedicatedBirthSessionExit> {
    let successful=report.status=="startup_exclusion_released";
    let emitted=streams.frame(&report,Instant::now()+protocol::OUTPUT_WAIT);
    // Retention spans success and terminal I/O refusal. Dropping after this
    // invocation is not retry/rollback and cannot recall startup after clear.
    drop(owner);emitted?;Ok(DedicatedBirthSessionExit{exit_code:if successful{0}else{3}})
}
fn before_birth(streams:&NativeStreams,guard:&mut HostMaintenanceGuard,error:EnclaveError,
    stage:&'static str)->EnclaveResult<DedicatedBirthSessionExit> {
    before_birth_errors(streams,guard,vec![error],stage)
}
fn before_birth_errors(streams:&NativeStreams,guard:&mut HostMaintenanceGuard,observed:Vec<EnclaveError>,
    stage:&'static str)->EnclaveResult<DedicatedBirthSessionExit> {
    let error=observed.first().cloned().unwrap_or_else(||err!(EIO,"BIRTH_SESSION_SETUP_REFUSED"));
    let mut finals=observed.iter().skip(1).cloned().collect::<Vec<_>>();
    finals.extend(errors([require_native_root(),guard.assert_held()]));
    let report=Terminal::refused(stage,&error,&[],&finals,None,Effects::default());
    terminal(streams,(guard,observed,finals),report)
}
fn with_birth(streams:&NativeStreams,birth:NativeDedicatedBirth<'_>,error:EnclaveError,
    stage:&'static str,effects:Effects)->EnclaveResult<DedicatedBirthSessionExit> {
    with_birth_errors(streams,birth,vec![error],stage,effects)
}
fn with_birth_errors(streams:&NativeStreams,mut birth:NativeDedicatedBirth<'_>,observed:Vec<EnclaveError>,
    stage:&'static str,effects:Effects)->EnclaveResult<DedicatedBirthSessionExit> {
    let error=observed.first().cloned().unwrap_or_else(||err!(EIO,"BIRTH_SESSION_SETUP_REFUSED"));
    let current=birth.assert_current();let mut finals=observed.iter().skip(1).cloned().collect::<Vec<_>>();
    if let Err(refusal)=&current {finals.push(refusal.error.clone());finals.extend(refusal.boundary_errors.iter().cloned());
        finals.extend(refusal.final_errors.iter().cloned());}
    let report=Terminal::refused(stage,&error,&[],&finals,Some(birth.progress().clone()),effects);
    terminal(streams,(birth,observed,current),report)
}
struct PublicReaders {
    template_paths:HeldPaths,template:HeldFile,
    pickup_paths:Option<HeldPaths>,pickup:Option<HeldFile>,
    initial:Option<UnadmittedBirthSources>,staged:Option<UnadmittedBirthSources>,
}
impl PublicReaders {
    fn current_template(&self)->Vec<EnclaveError> {
        // Every actually observed pre/file/post error survives with its original
        // order. The caller keeps the first primary and reports all later ones.
        errors([self.template_paths.revalidate(),self.template.revalidate(&self.template_paths),self.template_paths.revalidate()])
    }
}
fn public_inventory(sources:&mut UnadmittedBirthSources)->Result<Vec<u8>,Vec<EnclaveError>> {
    let operation=(|| {
        sources.assert_current()?;let mut inventory=None;
        for index in 0..sources.source_count() {
            if matches!(sources.role(index),Some(BirthSourceRole::Inventory)) {
                if inventory.replace(index).is_some(){fail!(EINVAL,"BIRTH_SESSION_INVENTORY_SET");}
            }
        }
        let index=inventory.ok_or_else(||err!(EINVAL,"BIRTH_SESSION_INVENTORY_SET"))?;
        let size=sources.size(index).ok_or_else(||err!(EINVAL,"BIRTH_SESSION_INVENTORY_SET"))?;
        if size==0||size>1024*1024{fail!(E2BIG,"BIRTH_SESSION_INVENTORY_BOUND");}
        let mut bytes=vec![0;size as usize];let mut offset=0;
        while offset<bytes.len(){let end=(offset+64*1024).min(bytes.len());
            let count=sources.read_chunk(index,offset as u64,&mut bytes[offset..end])?;
            if count==0{fail!(ESTALE,"BIRTH_SESSION_INVENTORY_EOF");}offset+=count;
        }Ok(bytes)
    })();
    let current=sources.assert_current();let mut observed=Vec::new();
    if let Err(error)=&operation{observed.push(error.clone());}
    if let Err(error)=current{observed.push(error);}
    if !observed.is_empty(){return Err(observed);}
    operation.map_err(|error|vec![error])
}

/// Real native side-effect command. Concrete inherited stdio must already be
/// nonblocking pipes/sockets; refusals occur before guard acquisition otherwise.
/// The one 900 second setup wait starts before challenge output. All factor and
/// lifecycle/crypto deadlines remain the original downstream methods' own.
pub fn run_dedicated_birth_session(args:DedicatedBirthSessionArgs)->EnclaveResult<DedicatedBirthSessionExit> {
    let streams=NativeStreams::standard()?;
    require_native_root()?;
    if enclave_core::deployment::selected().is_some(){fail!(EACCES,"BIRTH_SESSION_PRESELECTION_REQUIRED");}
    let mut guard=HostMaintenanceGuard::acquire()?;
    let template_paths=match HeldPaths::new_native_acl_protected(){Ok(paths)=>paths,Err(error)=>return before_birth(&streams,&mut guard,error,"template_paths")};
    let mut template_paths=template_paths;
    let (template,bytes)=match HeldFile::open(&mut template_paths,&args.template,65536,None){Ok(value)=>value,
        Err(error)=>return before_birth(&streams,&mut guard,error,"template_read")};
    let mut readers=PublicReaders{template_paths,template,pickup_paths:None,pickup:None,initial:None,staged:None};
    let template=match DeploymentTarget::parse(&bytes){Ok(template)=>template,Err(error)=>return before_birth(&streams,&mut guard,error,"template_parse")};
    let observed=readers.current_template();
    if !observed.is_empty(){return before_birth_errors(&streams,&mut guard,observed,"template_current");}
    let mut birth=match begin_dedicated_birth(&template,&args.template_root,&args.allocator_parent,&mut guard){Ok(birth)=>birth,Err(refusal)=>{
        let report=Terminal::refused("begin",&refusal.error,&refusal.boundary_errors,&refusal.final_errors,Some(refusal.progress.clone()),Effects::default());
        return terminal(&streams,refusal,report);
    }};
    macro_rules! mutable {
        ($expression:expr,$stage:literal)=>{match $expression{Ok(progress)=>progress,Err(refusal)=>{
            let report=Terminal::refused($stage,&refusal.error,&refusal.boundary_errors,&refusal.final_errors,Some(refusal.progress.clone()),Effects::default());
            return terminal(&streams,(birth,refusal),report);
        }}};
    }
    mutable!(birth.prepare_inert_seeds(),"inert_seeds");
    mutable!(birth.assert_current(),"before_challenge");
    let setup_until=Instant::now()+protocol::SETUP_WAIT;
    let target_id=birth.target().target_id.clone();let descriptor_sha256=hex::encode(Sha256::digest(birth.descriptor_bytes()));
    let root=match &birth.progress().root {Some(root)=>root.clone(),
        None=>return with_birth(&streams,birth,err!(EACCES,"BIRTH_SESSION_ACTUAL_ROOT_REQUIRED"),"challenge_root",Effects::default())};
    let descriptor_utf8=match std::str::from_utf8(birth.descriptor_bytes()) {
        Ok(text)=>text.to_owned(),Err(_)=>return with_birth(&streams,birth,err!(EIO,"BIRTH_SESSION_DESCRIPTOR_ENCODING"),"challenge_encoding",Effects::default()),
    };
    let challenge=serde_json::json!({"version":1,"kind":"mcpmac-dedicated-birth-public-challenge",
        "target_id":target_id.clone(),"root":root.clone(),"descriptor_path":birth.descriptor_path(),
        "descriptor_utf8":descriptor_utf8,
        "descriptor_sha256":descriptor_sha256.clone(),"setup_input_wait_seconds":900,
        "data_only":true,"runtime_readiness":"UNKNOWN","qualified":false});
    if let Err(error)=streams.frame(&challenge,Instant::now()+protocol::OUTPUT_WAIT){return with_birth(&streams,birth,error,"challenge_output",Effects::default());}
    let command=match streams.command(setup_until){Ok(command)=>command,Err(error)=>return with_birth(&streams,birth,error,"setup_input",Effects::default())};
    // A command returned near the poll deadline cannot extend setup into the
    // postwait gates or external pickup/source reads.
    if Instant::now()>=setup_until{return with_birth(&streams,birth,err!(ETIMEDOUT,"BIRTH_SESSION_SETUP_EXPIRED"),"setup_wait_endpoint",Effects::default());}
    mutable!(birth.assert_current(),"after_setup_input");
    let observed=readers.current_template();
    if !observed.is_empty(){return with_birth_errors(&streams,birth,observed,"template_after_input",Effects::default());}
    // Actual original-owner postwait checks may themselves consume time. The
    // same original endpoint must still hold before admitting external input.
    if Instant::now()>=setup_until{return with_birth(&streams,birth,err!(ETIMEDOUT,"BIRTH_SESSION_SETUP_EXPIRED"),"setup_admission_endpoint",Effects::default());}
    let input_manifest=match command {
        SetupCommand::Cancel{..}=>{let error=err!(EACCES,"BIRTH_SESSION_CANCELLED");return with_birth(&streams,birth,error,"cancelled",Effects::default());},
        SetupCommand::Continue{input_manifest,..}=>input_manifest,
    };
    let external=match overlaps(&input_manifest,&root) {Ok(external)=>external,Err(error)=>return with_birth(&streams,birth,error,"pickup_path",Effects::default())};
    if external{return with_birth(&streams,birth,err!(EACCES,"BIRTH_SESSION_EXTERNAL_INPUT_REQUIRED"),"pickup_path",Effects::default());}
    readers.pickup_paths=match HeldPaths::new_native_acl_protected(){Ok(paths)=>Some(paths),Err(error)=>return with_birth(&streams,birth,error,"pickup_paths",Effects::default())};
    let (pickup,bytes)=match HeldFile::open(readers.pickup_paths.as_mut().expect("actual paths"),&input_manifest,protocol::MAX_PICKUP,Some(0o600)){
        Ok(value)=>value,Err(error)=>return with_birth(&streams,birth,error,"pickup_read",Effects::default())};
    readers.pickup=Some(pickup);
    let pickup=match Pickup::parse(&bytes,&target_id,&descriptor_sha256,&root){Ok(pickup)=>pickup,
        Err(error)=>return with_birth(&streams,birth,error,"pickup_parse",Effects::default())};
    readers.initial=match UnadmittedBirthSources::open(&pickup.package_root,&pickup.initial()){Ok(sources)=>Some(sources),
        Err(error)=>return with_birth(&streams,birth,error,"initial_sources",Effects::default())};
    readers.staged=match UnadmittedBirthSources::open(&pickup.package_root,&pickup.staged()){Ok(sources)=>Some(sources),
        Err(error)=>return with_birth(&streams,birth,error,"remaining_sources",Effects::default())};
    let raw_inventory=match public_inventory(readers.initial.as_mut().expect("actual initial sources")){Ok(bytes)=>bytes,
        Err(observed)=>return with_birth_errors(&streams,birth,observed,"inventory",Effects::default())};
    // The pickup is data, not approval. Retain and recheck its exact original
    // readonly bytes/ancestry before the first admitted import/denial effect.
    let current=readers.pickup.as_ref().expect("actual pickup").revalidate(readers.pickup_paths.as_ref().expect("actual paths"));
    if let Err(error)=current{return with_birth(&streams,birth,error,"pickup_current",Effects::default());}
    if Instant::now()>=setup_until{return with_birth(&streams,birth,err!(ETIMEDOUT,"BIRTH_SESSION_SETUP_EXPIRED"),"setup_endpoint",Effects::default());}
    mutable!(birth.prepare_startup_denial(&raw_inventory),"startup_denial");
    mutable!(birth.import_initial_public_inputs(readers.initial.as_mut().expect("actual initial sources")),"initial_import");
    mutable!(birth.import_remaining_staging_sources(readers.staged.as_mut().expect("actual remaining sources")),"remaining_import");
    mutable!(birth.load_private_inputs(),"private_load");
    let mut effects=Effects::default();
    macro_rules! consume {
        ($expression:expr,$stage:literal)=>{match $expression{Ok(next)=>next,Err(refusal)=>{
            let report=Terminal::refused($stage,&refusal.error,&refusal.boundary_errors,&refusal.final_errors,Some(refusal.progress.clone()),effects.clone());
            return terminal(&streams,refusal,report);
        }}};
    }
    let candidate=consume!(birth.approve_private_candidate(&pickup.software_release_config),"candidate");
    let selected=consume!(candidate.select_once(),"select");
    let excluded=consume!(selected.retain_inhibited_exclusion(),"inhibited_exclusion");
    let payload=consume!(excluded.prepare_private_payload(),"private_payload");
    // Conditional on the external operator's genuine independent choice and
    // provisioning. This driver supplies no trust-root provenance evidence.
    let pin=consume!(payload.pick_up_operator_runtime_pin(&pickup.operator_runtime_pin_record),"operator_runtime_pin");
    let runtime=consume!(pin.prepare_private_runtime_transport(),"runtime_transport");
    let metadata=consume!(runtime.prepare_private_directory_metadata(),"directory_metadata");
    effects.external_jobs_may_have_been_published=true;
    let jobs=consume!(metadata.publish_fixed_target_jobs(),"fixed_jobs");
    let visible=match jobs.prepare_original_ancestor_visibility(){Ok(visible)=>{effects.namespace_visibility_may_have_changed=true;visible},Err(refusal)=>{
        effects.namespace_visibility_may_have_changed=refusal.namespace_visibility_may_have_changed();
        let report=Terminal::refused("visibility",&refusal.error,&refusal.boundary_errors,&refusal.final_errors,Some(refusal.progress.clone()),effects);
        return terminal(&streams,refusal,report);
    }};
    let cleared=match visible.clear_owned_startup_denial(){Ok(cleared)=>{effects.denial_may_have_been_removed=true;cleared},Err(refusal)=>{
        effects.denial_may_have_been_removed=refusal.denial_may_have_been_removed();
        let report=Terminal::refused("clear",&refusal.error,&refusal.boundary_errors,&refusal.final_errors,Some(refusal.progress.clone()),effects);
        return terminal(&streams,refusal,report);
    }};
    let registered=match cleared.register_core_jobs(){Ok(registered)=>{effects.registration_may_have_changed=true;registered},Err(refusal)=>{
        effects.registration_may_have_changed=refusal.registration_may_have_changed();
        let report=Terminal::refused("register",&refusal.error,&refusal.boundary_errors,&refusal.final_errors,Some(refusal.progress.clone()),effects);
        return terminal(&streams,refusal,report);
    }};
    let released=match registered.release_startup_exclusion(){Ok(released)=>{effects.explicit_startup_release_may_have_occurred=true;released},Err(refusal)=>{
        effects.explicit_startup_release_may_have_occurred=refusal.startup_exclusion_may_have_been_released();
        let report=Terminal::refused("release",&refusal.error,&refusal.boundary_errors,&refusal.final_errors,Some(refusal.progress.clone()),effects);
        return terminal(&streams,refusal,report);
    }};
    let report=Terminal{version:1,kind:"mcpmac-dedicated-birth-session-result",status:"startup_exclusion_released",stage:"release",
        error:None,boundary_error_count:0,boundary_errors:Vec::new(),final_errors:Vec::new(),progress:None,effects,
        owner_lifetime:"ACTUAL_OWNERS_RETAINED_THROUGH_TERMINAL_OUTPUT_ATTEMPT",
        exit_behavior:"TERMINAL_TEARDOWN_CLOSES_DESCRIPTORS_NO_ROLLBACK_OR_CONTINUING_INHIBITION_CLAIM",
        runtime_readiness:"UNKNOWN",runtime_pin_provenance_verified:false,qualified:false};
    // Public readers were not moved out of this frame; their lexical lifetime
    // includes this terminal attempt, alongside the actual released owner.
    let result=terminal(&streams,released,report);drop(readers);result
}

/// Read only bounded unadmitted public copies. No bytes are treated as checked
/// deployment/provisioning or logged on parser refusal. Rendering performs no
/// guard/selection/signing/root/installation effect and outputs public data only.
pub fn render_dedicated_birth_public_data(args:DedicatedBirthRenderArgs)->EnclaveResult<DedicatedBirthSessionExit> {
    use std::io::Read;
    fn read(path:&Path,maximum:u64)->EnclaveResult<Vec<u8>> {
        use std::os::unix::fs::OpenOptionsExt;
        let file=std::fs::OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW|libc::O_NONBLOCK|libc::O_CLOEXEC)
            .open(path).map_err(|_|err!(EACCES,"BIRTH_PUBLIC_RENDER_INPUT_READ"))?;
        let metadata=file.metadata().map_err(|_|err!(EIO,"BIRTH_PUBLIC_RENDER_INPUT_READ"))?;
        if !metadata.is_file()||metadata.len()==0||metadata.len()>maximum{fail!(E2BIG,"BIRTH_PUBLIC_RENDER_INPUT_BOUND");}
        let mut bytes=Vec::new();file.take(maximum+1).read_to_end(&mut bytes).map_err(|_|err!(EIO,"BIRTH_PUBLIC_RENDER_INPUT_READ"))?;
        if bytes.is_empty()||bytes.len()as u64>maximum{fail!(E2BIG,"BIRTH_PUBLIC_RENDER_INPUT_BOUND");}Ok(bytes)
    }
    let descriptor=read(&args.descriptor_input,65536)?;let manifest=read(&args.custody_manifest,16384)?;
    let files=crate::launchd::render_public_birth_artifacts(&descriptor,&args.descriptor,&manifest)?;
    protocol::public_frame(&serde_json::json!({"version":1,"kind":"mcpmac-dedicated-birth-public-rendering",
        "files":files,"data_only":true,"qualified":false}))?;
    Ok(DedicatedBirthSessionExit{exit_code:0})
}
