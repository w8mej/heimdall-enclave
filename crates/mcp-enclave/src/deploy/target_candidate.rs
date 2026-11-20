//! Concrete native-code and renderer verification of an approved candidate.
//!
//! The producer supplies read-only views of its protected, nofollow-held source
//! set and keeps that walk, its named-inode checks and the same real host guard
//! alive throughout verification and subsequent use. This module never opens a
//! candidate by pathname, executes candidate code/scripts, publishes files or
//! proves target inactivity. Security.framework's path observations use the
//! existing protected native verifier, also used by the core-five lifecycle.
//! No JSON boolean, cached/current pin union or injectable production verifier
//! can replace the genuine same-invocation software-release owner below.
//!
//! Native calls are synchronous and have no hard interruption guarantee. Any
//! public installation/activation authority remains a separate requirement.

use std::{collections::{BTreeMap, BTreeSet}, fs::{File, Metadata},
    os::{fd::AsRawFd, unix::fs::{FileExt, MetadataExt}}, path::{Path, PathBuf}};
use enclave_core::{codesign::{self, CodeRequirement}, daemon::DaemonId,
    deployment::{CheckedDeploymentTarget, DeploymentSigningMode, normalized_path},
    error::EnclaveResult, err, fail};
use sha2::{Digest, Sha256};
use super::{target_maintenance::HostMaintenanceGuard,
    target_native_code::{self, NativeCodeShape, NativeEntitlementPolicy, ProtectedNativeFile},
    target_plan::{self, TargetInstallPlan}, target_release::SoftwareApproval,
    target_release_json as json};

const MAX_FILES:usize=128;
const MAX_FILE:u64=512*1024*1024;
const MAX_TOTAL:u64=2*1024*1024*1024;
const MAX_CONFIG:usize=1024*1024;
const CUSTODY_TEMPLATE:&str=include_str!("../../../../packaging/EnclaveCustody.app/custody.teamid.entitlements.in");

/// Borrowed public inputs only. Construction is not an approval capability.
/// The producer retains its protected ancestry and named-inode binding owner.
#[derive(Clone, Copy)]
pub(crate) struct CandidateFileView<'a> {
    pub(crate) path:&'a Path,
    pub(crate) file:&'a File,
    pub(crate) sha256:&'a str,
    pub(crate) size:u64,
}
impl<'a> CandidateFileView<'a> {
    fn native(self)->ProtectedNativeFile<'a> {
        ProtectedNativeFile {path:self.path,file:self.file,sha256:self.sha256,size:self.size}
    }
}

// Fixed packaging map, not request-controlled identifiers or executable names.
const EXECUTABLES:[(&str,&str);9]=[
    ("bin/mcp-enclave","com.enterprise.enclave.ctl"),
    ("bin/enclave-model-runnerd","com.enterprise.enclave.adapter"),
    ("bin/enclave-swarm-syncd","com.enterprise.enclave.cas"),
    ("bin/enclave-apfs-broker","com.enterprise.enclave.apfs-broker"),
    ("bin/enclave-agent-runtime","com.enterprise.enclave.ifc"),
    ("bin/enclave-zk-auditor","com.enterprise.enclave.zk"),
    ("bin/enclave-cdp-browser","com.enterprise.enclave.browser"),
    ("bin/enclave-client-gateway","com.enterprise.enclave.gateway"),
    ("bin/enclave-intent","com.enterprise.enclave.intent"),
];
const BUNDLES:[(&str,&str,&str,NativeEntitlementPolicy);2]=[
    ("EnclaveCustody.app","enclave-custody-vaultd","com.enterprise.enclave.custody",
        NativeEntitlementPolicy::CustodyForCompiledSigningMode),
    ("EnclaveOIDC.app","enclave-oidc","com.enterprise.enclave.oidc-broker",
        NativeEntitlementPolicy::DaemonBaseline),
];

fn lower_digest(v:&str)->bool {
    v.len()==64 && v.bytes().all(|b|b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn mode_text(mode:DeploymentSigningMode)->&'static str {
    match mode {DeploymentSigningMode::LocalPins=>"local-pins",DeploymentSigningMode::TeamId=>"team-id"}
}
fn compiled_mode(mode:DeploymentSigningMode)->EnclaveResult<()> {
    let actual=match codesign::signing_mode() {
        codesign::SigningMode::LocalPins=>DeploymentSigningMode::LocalPins,
        codesign::SigningMode::TeamId=>DeploymentSigningMode::TeamId,
    };
    if mode!=actual || (!codesign::TEAM_ID.is_empty() && (codesign::TEAM_ID.len()!=10
        || !codesign::TEAM_ID.bytes().all(|b|b.is_ascii_uppercase() || b.is_ascii_digit()))) {
        fail!(EACCES,"CANDIDATE_COMPILED_SIGNING_MODE");
    }
    Ok(())
}
fn requirements(raw:&[u8],mode:DeploymentSigningMode)->EnclaveResult<BTreeMap<String,CodeRequirement>> {
    let value=json::strict(raw,MAX_CONFIG)?;
    json::closed(&value,&["v","mode","pins"],&[])?;
    if json::uint(&value,"v")?!=1 || json::text(&value,"mode")?!=mode_text(mode) {
        fail!(EACCES,"CANDIDATE_PIN_MODE");
    }
    let expected=EXECUTABLES.iter().map(|(_,id)|*id)
        .chain(BUNDLES.iter().map(|(_,_,id,_)|*id)).collect::<BTreeSet<_>>();
    let pins=json::object(value.get("pins").ok_or_else(||err!(EINVAL,"CANDIDATE_PINS"))?)?;
    if pins.keys().map(String::as_str).collect::<BTreeSet<_>>()!=expected {
        fail!(EACCES,"CANDIDATE_PIN_IDENTIFIERS");
    }
    // Reuse the actual pin parser after the stricter duplicate/schema pass.
    let parsed=codesign::pins::parse(raw)?;
    let mut result=BTreeMap::new();
    for (identifier,hashes) in parsed {
        let mut unique=BTreeSet::new();
        if hashes.is_empty() || hashes.len()>32 || hashes.iter().any(|h|h.len()!=40
            || !h.bytes().all(|b|b.is_ascii_hexdigit()) || !unique.insert(h.to_ascii_lowercase())) {
            fail!(EACCES,"CANDIDATE_PIN_HASHES");
        }
        result.insert(identifier.clone(),CodeRequirement {identifier,team_id:codesign::TEAM_ID.into(),
            cdhash_allowlist:hashes});
    }
    Ok(result)
}

#[derive(Clone, PartialEq, Eq)]
struct Stamp {dev:u64,ino:u64,uid:u32,gid:u32,mode:u32,links:u64,size:u64,
    modified:(i64,i64),changed:(i64,i64)}
fn stamp(m:&Metadata)->Stamp {Stamp {dev:m.dev(),ino:m.ino(),uid:m.uid(),gid:m.gid(),mode:m.mode(),
    links:m.nlink(),size:m.len(),modified:(m.mtime(),m.mtime_nsec()),changed:(m.ctime(),m.ctime_nsec())}}
fn io_error()->enclave_core::error::EnclaveError {err!(EIO,"CANDIDATE_READ")}
fn observed(view:CandidateFileView<'_>,owner:u32)->EnclaveResult<Stamp> {
    let m=view.file.metadata().map_err(|_|io_error())?;
    // SAFETY: F_GETFL reads descriptor flags and has no additional argument.
    let flags=unsafe {libc::fcntl(view.file.as_raw_fd(),libc::F_GETFL)};
    if flags<0 || flags&libc::O_ACCMODE!=libc::O_RDONLY || !m.is_file() || m.uid()!=owner
        || m.mode()&0o7022!=0 || m.nlink()!=1 || m.len()!=view.size
        || view.size==0 || view.size>MAX_FILE || !lower_digest(view.sha256) {
        fail!(EACCES,"CANDIDATE_FILE_VIEW");
    }
    Ok(stamp(&m))
}
fn read_at(file:&File,buf:&mut [u8],offset:u64)->EnclaveResult<usize> {
    loop {match file.read_at(buf,offset) {
        Ok(n)=>return Ok(n),Err(e) if e.kind()==std::io::ErrorKind::Interrupted=>continue,
        Err(_)=>return Err(io_error()),
    }}
}
fn verify_digest(view:CandidateFileView<'_>,owner:u32)->EnclaveResult<Stamp> {
    let before=observed(view,owner)?;let mut hash=Sha256::new();let mut offset=0u64;
    let mut buffer=[0u8;65536];
    while offset<view.size {
        let length=(view.size-offset).min(buffer.len() as u64) as usize;
        let n=read_at(view.file,&mut buffer[..length],offset)?;
        if n==0 {fail!(ESTALE,"CANDIDATE_FILE_CHANGED");}
        hash.update(&buffer[..n]);offset+=n as u64;
    }
    if read_at(view.file,&mut [0u8;1],offset)?!=0 || observed(view,owner)?!=before
        || hex::encode(hash.finalize())!=view.sha256 {fail!(ESTALE,"CANDIDATE_FILE_CHANGED");}
    Ok(before)
}
fn bytes(view:CandidateFileView<'_>,maximum:usize,owner:u32)->EnclaveResult<Vec<u8>> {
    if view.size>maximum as u64 {fail!(E2BIG,"CANDIDATE_CONFIG_SIZE");}
    let before=observed(view,owner)?;let mut value=vec![0u8;view.size as usize];let mut offset=0;
    while offset<value.len() {
        let n=read_at(view.file,&mut value[offset..],offset as u64)?;
        if n==0 {fail!(ESTALE,"CANDIDATE_FILE_CHANGED");}offset+=n;
    }
    if read_at(view.file,&mut [0u8;1],offset as u64)?!=0 || observed(view,owner)?!=before
        || hex::encode(Sha256::digest(&value))!=view.sha256 {fail!(ESTALE,"CANDIDATE_FILE_CHANGED");}
    Ok(value)
}

fn bind_views<'a>(expected:&BTreeMap<PathBuf,(String,u64)>,files:&[CandidateFileView<'a>])
    ->EnclaveResult<BTreeMap<PathBuf,CandidateFileView<'a>>> {
    if files.is_empty() || files.len()>MAX_FILES || files.len()!=expected.len() {
        fail!(EACCES,"CANDIDATE_SOURCE_SET");
    }
    let mut result=BTreeMap::new();let mut total=0u64;
    for view in files {
        let route=normalized_path(view.path)?;
        if expected.get(&route)!=Some(&(view.sha256.to_owned(),view.size))
            || result.insert(route,*view).is_some() {fail!(EACCES,"CANDIDATE_SOURCE_SET");}
        total=total.checked_add(view.size).ok_or_else(||err!(E2BIG,"CANDIDATE_SOURCE_SIZE"))?;
        if total>MAX_TOTAL {fail!(E2BIG,"CANDIDATE_SOURCE_SIZE");}
    }
    Ok(result)
}
fn expected_views(plan:&TargetInstallPlan)->EnclaveResult<BTreeMap<PathBuf,(String,u64)>> {
    let mut expected=BTreeMap::new();
    for (path,hash,size) in plan.copies.iter().map(|f|(&f.source,&f.sha256,f.size))
        .chain(plan.retained_in_staging.iter().map(|f|(&f.source,&f.sha256,f.size))) {
        if expected.insert(normalized_path(path)?,(hash.clone(),size)).is_some() {
            fail!(EACCES,"CANDIDATE_SOURCE_SET");
        }
    }
    Ok(expected)
}
fn file_at<'a>(files:&BTreeMap<PathBuf,CandidateFileView<'a>>,root:&Path,name:&str)
    ->EnclaveResult<CandidateFileView<'a>> {
    files.get(&normalized_path(&root.join(name))?).copied().ok_or_else(||err!(EACCES,"CANDIDATE_SOURCE_MISSING"))
}

fn rendered(layout:&crate::launchd::Layout,mode:DeploymentSigningMode)->EnclaveResult<BTreeMap<String,Vec<u8>>> {
    use crate::launchd;
    if layout.fido_emulator || !matches!(layout.profile.as_str(),"L2"|"L3") {
        fail!(EACCES,"CANDIDATE_PHYSICAL_LAYOUT");
    }
    let mut result=BTreeMap::new();
    let mut add=|name:String,value:String| {result.insert(name,value.into_bytes());};
    for daemon in DaemonId::ALL {
        add(format!("launchd/{}.plist",layout.job_label(&daemon.launchd_label())),launchd::plist(daemon,layout));
        add(format!("launchd/{}.sb",daemon.plist_suffix()),launchd::sandbox_profile(daemon,layout));
    }
    for (label,value) in [
        (enclave_core::supervisor::LAUNCHD_LABEL,launchd::supervisor_plist(layout)),
        (launchd::INTENT_LABEL,launchd::intent_plist(layout)),
        (launchd::OIDC_LABEL,launchd::oidc_plist_for_layout(layout)),
        (launchd::HYDRATE_LABEL,launchd::hydrate_plist(layout)),
        (launchd::BROWSER_LABEL,launchd::browser_plist(layout)),
        (enclave_core::daemon::GATEWAY_IDENTIFIER,launchd::gateway_plist(layout)),
    ] {add(format!("launchd/{}.plist",layout.job_label(label)),value);}
    if layout.profile=="L3" {
        add(format!("launchd/{}.plist",layout.job_label("com.enterprise.enclave.apfs-broker")),launchd::apfs_broker_plist(layout));
    }
    add("launchd/browser.sb".into(),launchd::browser_sandbox_profile(layout));
    add("launchd/gateway.sb".into(),launchd::gateway_sandbox_profile(layout));
    add("launchd/provision-accounts.sh".into(),launchd::provision_script(layout));
    add("launchd/enclave-daemon.entitlements".into(),launchd::entitlements());
    add("custody.entitlements".into(),match mode {
        DeploymentSigningMode::LocalPins=>launchd::entitlements(),
        DeploymentSigningMode::TeamId=>CUSTODY_TEMPLATE.replace("@TEAM_ID@",codesign::TEAM_ID),
    });
    add("yubikey-transport".into(),"hid\n".into());
    Ok(result)
}
fn compare_rendered(files:&BTreeMap<PathBuf,CandidateFileView<'_>>,root:&Path,
    expected:&BTreeMap<String,Vec<u8>>,owner:u32)->EnclaveResult<()> {
    for (name,want) in expected {
        let view=file_at(files,root,name)?;
        if bytes(view,MAX_CONFIG,owner)?!=*want {fail!(EACCES,"CANDIDATE_RENDERED_BYTES");}
    }
    Ok(())
}
fn plan_bound(checked:&CheckedDeploymentTarget,plan:&TargetInstallPlan,approval:&SoftwareApproval)->EnclaveResult<()> {
    if plan.deployment_config_sha256!=checked.descriptor_sha256()
        || plan.deployment_config_sha256!=approval.descriptor_sha256()
        || plan.artifact_inventory_sha256!=approval.inventory_sha256() || !plan.missing_required_files.is_empty() {
        fail!(EACCES,"CANDIDATE_RELEASE_BINDING");
    }
    let raw=checked.read_artifact_inventory()?;
    if hex::encode(Sha256::digest(&raw))!=approval.inventory_sha256() {fail!(ESTALE,"CANDIDATE_RELEASE_BINDING");}
    let genuine=target_plan::describe(checked.target(),checked.descriptor_sha256(),&raw)?;
    // No caller-mutated destination, mode, omitted retained input or plan flag
    // may piggyback on a genuine inventory digest.
    if serde_json::to_vec(&genuine).map_err(|_|io_error())?!=serde_json::to_vec(plan).map_err(|_|io_error())? {
        fail!(EACCES,"CANDIDATE_PLAN_BINDING");
    }
    Ok(())
}
fn native_step<T>(check:&mut impl FnMut()->EnclaveResult<()>,
    native:impl FnOnce()->EnclaveResult<T>)->EnclaveResult<T> {
    check()?;
    let result=native();
    // Evaluate the postcheck even when the actual native verifier refused.
    let current=check();current?;result
}

/// Actual same-invocation release, native and renderer verification only.
/// Both deployment roles use this exact authority; callers separately enforce
/// their mutation rules, complete inactivity and final pin-cutover policy.
pub(crate) fn verify_candidate_native_and_rendered(checked:&CheckedDeploymentTarget,
    plan:&TargetInstallPlan,files:&[CandidateFileView<'_>],approval:&mut SoftwareApproval,
    guard:&mut HostMaintenanceGuard)->EnclaveResult<()> {
    approval.assert_current(checked,guard)?;
    let operation=(|| {
        compiled_mode(checked.target().signing_identity_mode)?;
        plan_bound(checked,plan,approval)?;
        let views=bind_views(&expected_views(plan)?,files)?;
        let mut identities=BTreeSet::new();let mut stamps=BTreeMap::new();
        for (path,view) in &views {
            let observed=verify_digest(*view,0)?;
            if !identities.insert((observed.dev,observed.ino)) {fail!(EACCES,"CANDIDATE_SOURCE_ALIAS");}
            stamps.insert(path.clone(),observed);
        }
        let root=&checked.target().layout.staging_root;
        let pins=file_at(&views,root,"codesign-pins.json")?;
        if pins.sha256!=plan.candidate_codesign_pins_sha256 {fail!(EACCES,"CANDIDATE_PIN_BINDING");}
        let requirements=requirements(&bytes(pins,MAX_CONFIG,0)?,checked.target().signing_identity_mode)?;
        let layout=crate::launchd::Layout::for_target(checked.clone())?;
        compare_rendered(&views,root,&rendered(&layout,checked.target().signing_identity_mode)?,0)?;
        approval.assert_current(checked,guard)?;
        for (name,id) in EXECUTABLES {
            let executable=file_at(&views,root,name)?;
            let requirement=requirements.get(id).ok_or_else(||err!(EACCES,"CANDIDATE_PINS"))?;
            native_step(&mut ||approval.assert_current(checked,guard),
                ||target_native_code::verify_static_code(NativeCodeShape::Executable(executable.native()),
                    requirement,NativeEntitlementPolicy::DaemonBaseline))?;
        }
        for (bundle,binary,id,policy) in BUNDLES {
            let bundle_root=normalized_path(&root.join(bundle))?;
            let executable=file_at(&views,root,&format!("{bundle}/Contents/MacOS/{binary}"))?;
            let executable_path=normalized_path(executable.path)?;
            let members=views.iter().filter(|(path,_)|path.starts_with(&bundle_root) && path.as_path()!=executable_path.as_path())
                .map(|(_,view)|view.native()).collect::<Vec<_>>();
            let requirement=requirements.get(id).ok_or_else(||err!(EACCES,"CANDIDATE_PINS"))?;
            native_step(&mut ||approval.assert_current(checked,guard),
                ||target_native_code::verify_static_code(NativeCodeShape::Bundle {root:&bundle_root,
                    executable:executable.native(),members:&members},requirement,policy))?;
        }
        layout.validate()?;
        for (path,view) in &views {
            if Some(&observed(*view,0)?)!=stamps.get(path) {fail!(ESTALE,"CANDIDATE_FILE_CHANGED");}
        }
        plan_bound(checked,plan,approval)
    })();
    // Even native/parser/render refusals receive the actual release/guard
    // postcheck. A poisoned/expired owner can never authorize later use.
    let final_binding=approval.assert_current(checked,guard);
    final_binding?;operation
}

#[cfg(test)]
#[path="target_candidate_tests.rs"]
mod tests;
