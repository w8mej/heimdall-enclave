//! Restricted root APFS publisher. Requests contain only a signed content root;
//! dedicated volume paths and authority come exclusively from the root mirror.
use std::{collections::BTreeMap, fs::File, io::{Read, Seek, SeekFrom, Write}, os::{fd::{AsRawFd, FromRawFd}, unix::{fs::{MetadataExt, OpenOptionsExt, PermissionsExt}, net::UnixStream}}, path::{Path, PathBuf}, sync::Arc, time::{Duration, Instant}};
use enclave_core::{err, fail, error::EnclaveResult, ipc, codesign::CodeRequirement};
use enclave_crypto::tuf::{TargetFile,TufClient,TufTrustedState,TrustedClock};
use serde::{Serialize,Deserialize};
use crate::snapshot_publication::{SealedConfig,SnapshotPlatform,SnapshotPublisher,SystemSnapshotPublisher,NativeSnapshotPlatform};
/// Independent root-helper signing identifier.
pub const IDENTIFIER:&str="com.enterprise.enclave.apfs-broker";
/// Dedicated root-helper binary.
pub const BINARY:&str="enclave-apfs-broker";
/// Root-owned socket subdirectory; only the CAS primary group may connect.
pub const SOCKET_DIRECTORY:&str="apfs-broker";
/// Fixed independently pinned helper endpoint.
pub const SOCKET:&str="/var/run/enclave/apfs-broker/broker.sock";
/// Root-only persistent authority, journal and private stage directory.
pub const BASE:&str="/var/db/enclave/apfs-broker";
const ROOT_PIN:&str="/Library/Application Support/EnterpriseEnclave/tuf/root.json";
const MAX_RECORDS:usize=256;
const FRAME:usize=4096;
const META:u64=4*1024*1024;
const MAX_STATE:usize=32*1024*1024;
#[derive(Debug,Clone,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
enum Request {Publish{root:String},Reopen{root:String},Revoke{root:String},Prepare{root:String}}
impl Request {fn root(&self)->&str {match self {Self::Publish{root}|Self::Reopen{root}|Self::Revoke{root}|Self::Prepare{root}=>root}}}
#[derive(Debug,Serialize,Deserialize)]
enum Response {Descriptor,Revoked}
#[derive(Debug,Clone)]
struct Paths {base:PathBuf,pin:PathBuf,strict:bool,target:Option<TargetPaths>}
#[derive(Debug,Clone)]
struct TargetPaths {
    socket:PathBuf,supervisor:PathBuf,cas:PathBuf,binary_dir:PathBuf,public_inputs:Vec<PathBuf>,
}
impl Paths {
    fn production()->Self {Self{base:BASE.into(),pin:ROOT_PIN.into(),strict:true,target:None}}
    fn state(&self)->PathBuf{self.base.join("state")}
    fn repo(&self)->PathBuf{self.base.join("tuf/repo")}
    fn socket(&self)->PathBuf{self.target.as_ref().map(|t|t.socket.clone()).unwrap_or_else(||SOCKET.into())}
    // Inert derivation used by fixtures too. Production calls this only with
    // the opaque checked immutable process selection, never request data.
    fn for_target(target:&enclave_core::deployment::DeploymentTarget,descriptor:&Path)->EnclaveResult<Self> {
        target.validate()?;
        if target.profile!=enclave_core::profile::Profile::L3 {fail!(EACCES,"BROKER_DEPLOYMENT_L3_REQUIRED");}
        let broker=target.broker.as_ref().ok_or_else(||err!(EACCES,"BROKER_DEPLOYMENT_L3_REQUIRED"))?;
        let normalized=enclave_core::deployment::normalized_path;
        let references:[&Path;5]=[descriptor,&target.codesign_pins_file,&target.authority_config,&target.expected_artifacts_manifest,&broker.tuf_root_file];
        let public_inputs=references.into_iter().map(normalized).collect::<EnclaveResult<Vec<_>>>()?;
        Ok(Self{base:normalized(&broker.base_dir)?,pin:normalized(&broker.tuf_root_file)?,strict:true,
            target:Some(TargetPaths{socket:normalized(&target.broker_socket())?,supervisor:normalized(&target.supervisor_socket())?,
                cas:normalized(&target.layout.cas_store_root)?,binary_dir:normalized(&target.layout.binary_dir)?,public_inputs})})
    }
    fn for_process()->EnclaveResult<Self> {
        match enclave_core::deployment::selected(){Some(checked)=>Self::for_target(checked.target(),checked.config_path()),None=>Ok(Self::production())}
    }
    fn validate_sealed(&self,config:&SealedConfig)->EnclaveResult<()> {
        config.validate()?;
        if let Some(target)=&self.target {
            let source=enclave_core::deployment::normalized_path(&config.source_mount)
                .map_err(|_|err!(EACCES,"BROKER_DEPLOYMENT_SEALED_SCOPE"))?;
            let mounts=enclave_core::deployment::normalized_path(&config.mount_root)
                .map_err(|_|err!(EACCES,"BROKER_DEPLOYMENT_SEALED_SCOPE"))?;
            let base=enclave_core::deployment::normalized_path(&self.base)
                .map_err(|_|err!(EACCES,"BROKER_DEPLOYMENT_SEALED_SCOPE"))?;
            let cas=enclave_core::deployment::normalized_path(&target.cas)
                .map_err(|_|err!(EACCES,"BROKER_DEPLOYMENT_SEALED_SCOPE"))?;
            if source.starts_with(&mounts)||mounts.starts_with(&source)
                || [&source,&mounts].iter().any(|path|!path.starts_with(&base)&&!path.starts_with(&cas)) {
                fail!(EACCES,"BROKER_DEPLOYMENT_SEALED_SCOPE");
            }
        }
        Ok(())
    }
}
fn parse_run_arguments(arguments:&[std::ffi::OsString])->EnclaveResult<Option<PathBuf>> {
    match arguments {
        []=>Ok(None),
        [flag,path] if flag=="--deployment-target"=>{
            let path=PathBuf::from(path);enclave_core::deployment::normalized_path(&path)
                .map_err(|_|err!(EINVAL,"BROKER_ARGUMENTS"))?;Ok(Some(path))
        },
        _=>Err(err!(EINVAL,"BROKER_ARGUMENTS")),
    }
}
#[derive(Debug,Clone,Serialize,Deserialize)]
struct Record {target:TargetFile,config:SealedConfig,complete:bool,#[serde(default)] owned_snapshot:bool,#[serde(default)] holders_released:bool,#[serde(default)] retracting:bool}
#[derive(Debug,Clone,Serialize,Deserialize)]
struct Persisted {version:u8,trust:Option<TufTrustedState>,high_water:i64,records:BTreeMap<String,Record>,#[serde(default)] stage_intent:Option<SealedConfig>}
struct Broker {paths:Paths,owner:u32,platform:Arc<dyn SnapshotPlatform>,store:enclave_core::sealed::SealedStore,state:Persisted,clock:TrustedClock,poisoned:bool,_lock:File,operation:File}
fn root_valid(root:&str)->bool {root.len()==64&&root.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b))}
// Only immutable OS aliases are normalized. Every resulting component is
// opened relative to a held directory descriptor with O_NOFOLLOW.
fn directory(path:&Path,owner:u32,strict:bool)->EnclaveResult<File> {
    if !path.is_absolute()||path.components().any(|c|matches!(c,std::path::Component::ParentDir)){fail!(EACCES,"BROKER_DIRECTORY");}
    let normalized = if cfg!(target_os="macos") {
        if let Ok(rest)=path.strip_prefix("/var") {Path::new("/private/var").join(rest)}
        else if let Ok(rest)=path.strip_prefix("/tmp") {Path::new("/private/tmp").join(rest)} else {path.to_path_buf()}
    } else {path.to_path_buf()};
    let mut held=File::options().read(true).custom_flags(libc::O_DIRECTORY|libc::O_NOFOLLOW|libc::O_CLOEXEC).open("/").map_err(|_|err!(EACCES,"BROKER_DIRECTORY"))?;
    for p in normalized.components(){let std::path::Component::Normal(p)=p else{continue;};use std::os::unix::ffi::OsStrExt;let name=std::ffi::CString::new(p.as_bytes()).map_err(|_|err!(EACCES,"BROKER_DIRECTORY"))?;let fd=unsafe{libc::openat(held.as_raw_fd(),name.as_ptr(),libc::O_RDONLY|libc::O_DIRECTORY|libc::O_NOFOLLOW|libc::O_CLOEXEC)};if fd<0{fail!(EACCES,"BROKER_DIRECTORY");}held=unsafe{File::from_raw_fd(fd)};let m=held.metadata().map_err(|_|err!(EACCES,"BROKER_DIRECTORY"))?;if strict&&(m.uid()!=owner||m.mode()&0o022!=0){fail!(EACCES,"BROKER_DIRECTORY");}}
    let m=held.metadata().map_err(|_|err!(EACCES,"BROKER_DIRECTORY"))?;if m.uid()!=owner||m.mode()&0o022!=0{fail!(EACCES,"BROKER_DIRECTORY");}Ok(held)
}
fn trusted_read(path:&Path,maximum:u64,owner:u32,strict:bool)->EnclaveResult<Vec<u8>> {
    let parent=directory(path.parent().ok_or_else(||err!(EINVAL,"BROKER_FILE"))?,owner,strict)?;
    use std::os::unix::ffi::OsStrExt;let name=std::ffi::CString::new(path.file_name().ok_or_else(||err!(EINVAL,"BROKER_FILE"))?.as_bytes()).map_err(|_|err!(EINVAL,"BROKER_FILE"))?;
    let fd=unsafe{libc::openat(parent.as_raw_fd(),name.as_ptr(),libc::O_RDONLY|libc::O_NOFOLLOW|libc::O_NONBLOCK|libc::O_CLOEXEC)};if fd<0{fail!(EACCES,"BROKER_FILE");}let mut file=unsafe{File::from_raw_fd(fd)};let m=file.metadata().map_err(|_|err!(EACCES,"BROKER_FILE"))?;
    if !m.is_file()||m.uid()!=owner||m.mode()&0o022!=0||m.nlink()!=1||m.len()==0||m.len()>maximum{fail!(EACCES,"BROKER_FILE");}
    let mut bytes=Vec::new();(&mut file).take(maximum+1).read_to_end(&mut bytes).map_err(|_|err!(EIO,"BROKER_FILE"))?;if bytes.len() as u64!=m.len(){fail!(EACCES,"BROKER_FILE");}Ok(bytes)
}
impl Broker {
    fn open(paths:Paths,owner:u32,platform:Arc<dyn SnapshotPlatform>)->EnclaveResult<Self>{
        for path in [paths.base.clone(),paths.state(),paths.repo()]{let dir=directory(&path,owner,paths.strict)?;if dir.metadata().map_err(|_|err!(EIO,"BROKER_DIRECTORY"))?.mode()&0o077!=0{fail!(EACCES,"BROKER_PRIVATE_DIRECTORY");}}
        let lock=File::options().read(true).write(true).create(true).mode(0o600).custom_flags(libc::O_NOFOLLOW|libc::O_CLOEXEC|libc::O_NONBLOCK).open(paths.base.join("instance.lock")).map_err(|_|err!(EACCES,"BROKER_LOCK"))?;
        let m=lock.metadata().map_err(|_|err!(EACCES,"BROKER_LOCK"))?;if !m.is_file()||m.uid()!=owner||m.nlink()!=1||m.mode()&0o077!=0{fail!(EACCES,"BROKER_LOCK");}
        if unsafe{libc::flock(lock.as_raw_fd(),libc::LOCK_EX|libc::LOCK_NB)}!=0{fail!(EAGAIN,"BROKER_ALREADY_RUNNING");}
        for entry in std::fs::read_dir(&paths.base).map_err(|_|err!(EIO,"BROKER_STAGE"))?{let entry=entry.map_err(|_|err!(EIO,"BROKER_STAGE"))?;if entry.file_name().to_string_lossy().starts_with("stage-"){let m=std::fs::symlink_metadata(entry.path()).map_err(|_|err!(EIO,"BROKER_STAGE"))?;if !m.is_file()||m.uid()!=owner||m.nlink()!=1||m.mode()&0o077!=0{fail!(EACCES,"BROKER_STAGE");}std::fs::remove_file(entry.path()).map_err(|_|err!(EIO,"BROKER_STAGE"))?;}}
        for entry in std::fs::read_dir(paths.state()).map_err(|_|err!(EIO,"BROKER_STATE"))?{let entry=entry.map_err(|_|err!(EIO,"BROKER_STATE"))?;let m=std::fs::symlink_metadata(entry.path()).map_err(|_|err!(EIO,"BROKER_STATE"))?;if !m.is_file()||m.uid()!=owner||m.mode()&0o077!=0||m.nlink()!=1||m.len()>32*1024*1024{fail!(EACCES,"BROKER_STATE");}}
        let (store,loaded)=enclave_core::sealed::SealedStore::open_bounded_required(&paths.state(),"apfs-publications",MAX_STATE)?;
        let mut state:Persisted=match loaded{enclave_core::sealed::Loaded::Fresh=>Persisted{version:1,trust:None,high_water:0,records:BTreeMap::new(),stage_intent:None},enclave_core::sealed::Loaded::State(bytes)=>enclave_core::sealed::decode(&bytes)?};
        if !matches!(state.version,1|2)||state.records.len()>MAX_RECORDS||state.records.keys().any(|r|!root_valid(r)){fail!(EACCES,"BROKER_STATE");}
        for (root,record) in &state.records {crate::streaming::validate_target(&record.target)?;paths.validate_sealed(&record.config)?;if (record.complete&&!record.owned_snapshot)||record.target.hashes.get("blake3")!=Some(root){fail!(EACCES,"BROKER_STATE_BINDING");}platform.validate_source(&record.config)?;}
        if let Some(config)=state.stage_intent.take() {paths.validate_sealed(&config)?;platform.validate_source(&config)?;cleanup_stage_directory(&config,owner,paths.strict)?;}
        state.version=2;
        let clock=TrustedClock::resumed(enclave_crypto::time::now_unix(),state.high_water);let operation=operation_file(&paths,owner)?;let mut broker=Self{paths,owner,platform,store,state,clock,poisoned:false,_lock:lock,operation};broker.save()?;Ok(broker)
    }
    fn save(&mut self)->EnclaveResult<()> {self.save_with_limit(MAX_STATE)}
    fn save_with_limit(&mut self,maximum:usize)->EnclaveResult<()> {self.state.high_water=self.clock.high_water();let result=(||{let bytes=serde_json::to_vec(&self.state).map_err(|_|err!(EIO,"BROKER_STATE_ENCODING"))?;if bytes.len()>maximum{fail!(E2BIG,"BROKER_STATE_SIZE");}self.store.save(&bytes)})();if result.is_err(){self.poisoned=true;}result}
    fn read(&self,name:&str,maximum:u64)->EnclaveResult<Vec<u8>>{trusted_read(&self.paths.repo().join(name),maximum,self.owner,self.paths.strict)}
    fn refresh(&mut self)->EnclaveResult<(TufClient,SealedConfig,i64)>{
        let pin=trusted_read(&self.paths.pin,META,self.owner,self.paths.strict)?;
        let mut tuf=match &self.state.trust{Some(state)=>{let t=TufClient::restore(state)?;if !t.chain_contains(&pin){fail!(EACCES,"BROKER_BOOTSTRAP_PIN");}t},None=>TufClient::bootstrap(&pin)?};
        let mut roots=BTreeMap::new();let mut entries=0;let mut root_count=0;for entry in std::fs::read_dir(self.paths.repo()).map_err(|_|err!(EIO,"BROKER_REPO"))?{entries+=1;if entries>64{fail!(E2BIG,"BROKER_REPO_ENTRIES");}let entry=entry.map_err(|_|err!(EIO,"BROKER_REPO"))?;let name=entry.file_name();let name=name.to_str().ok_or_else(||err!(EINVAL,"BROKER_ROOT_CHAIN"))?;if let Some(v)=name.strip_suffix(".root.json"){root_count+=1;if root_count>32{fail!(E2BIG,"BROKER_ROOT_CHAIN");}let n=v.parse::<u64>().map_err(|_|err!(EINVAL,"BROKER_ROOT_CHAIN"))?;if n==0||n>2147483647||n.to_string()!=v{fail!(EINVAL,"BROKER_ROOT_CHAIN");}if n>tuf.root().version{if roots.len()>=32{fail!(E2BIG,"BROKER_ROOT_CHAIN");}roots.insert(n,name.to_owned());}}}
        for (n,name) in roots{if n!=tuf.root().version.checked_add(1).ok_or_else(||err!(EINVAL,"BROKER_ROOT_CHAIN"))?{fail!(EACCES,"BROKER_ROOT_CHAIN");}tuf.update_root(&self.read(&name,META)?)?;}
        let now=self.clock.now(enclave_crypto::time::now_unix());
        tuf.update_timestamp(&self.read("timestamp.json",META)?,now)?;tuf.update_snapshot(&self.read("snapshot.json",META)?,now)?;tuf.update_targets(&self.read("targets.json",META)?,now)?;
        if !["root","targets"].iter().all(|r|tuf.root().roles.get(*r).is_some_and(|k|k.threshold>=2&&k.keyids.len()>=k.threshold as usize)){fail!(EACCES,"BROKER_PUBLISHER_QUORUM");}
        // Persist verified floors before any later payload/configuration error.
        self.state.trust=Some(tuf.export()?);self.save()?;
        let host=self.read(enclave_core::host_config::HOST_CONFIG_TARGET,64*1024)?;tuf.verify_target(enclave_core::host_config::HOST_CONFIG_TARGET,&host,now)?;
        enclave_core::host_config::EnclaveHostConfig::from_json_bytes(&host)?.admit_profile(enclave_core::profile::Profile::L3)?;
        let bytes=self.read(crate::transport::registry::DISTRIBUTION_CONFIG_TARGET,crate::transport::registry::MAX_CONFIG_BYTES)?;tuf.verify_target(crate::transport::registry::DISTRIBUTION_CONFIG_TARGET,&bytes,now)?;
        let sealed=crate::transport::registry::DistributionConfig::parse(&bytes)?.l3.ok_or_else(||err!(EACCES,"BROKER_L3_REQUIRED"))?.sealed;
        self.paths.validate_sealed(&sealed)?;self.platform.validate_source(&sealed)?;Ok((tuf,sealed,now))
    }
    fn target(tuf:&TufClient,root:&str,now:i64)->EnclaveResult<TargetFile>{
        let targets=tuf.targets().ok_or_else(||err!(EACCES,"BROKER_TARGET"))?;let mut found=None;
        for (name,target) in targets{if target.hashes.get("blake3").is_some_and(|r|r==root){let target=tuf.target(name,now)?;crate::streaming::validate_target(target)?;
            let policy=target.custom.as_ref().ok_or_else(||err!(EACCES,"BROKER_L3_TARGET"))?;
            if policy.get("classification").and_then(|v|v.as_str())!=Some("restricted_l3")||policy.get("min_profile").and_then(|v|v.as_str())!=Some("L3"){fail!(EACCES,"BROKER_L3_TARGET");}if let Some(previous)=&found{if previous!=target{fail!(EACCES,"BROKER_TARGET_ALIAS");}}found=Some(target.clone());}}
        found.ok_or_else(||err!(EACCES,"BROKER_TARGET"))
    }
    fn publisher(&self,record:&Record)->EnclaveResult<SystemSnapshotPublisher>{self.paths.validate_sealed(&record.config)?;SystemSnapshotPublisher::with_platform(record.config.clone(),self.platform.clone())}
    fn execute(&mut self,request:Request,stage:Option<File>)->EnclaveResult<Option<File>>{
        if self.poisoned{fail!(EACCES,"BROKER_STATE_RESTART_REQUIRED");}
        if let Some(config)=self.state.stage_intent.clone() {
            self.paths.validate_sealed(&config)?;self.platform.validate_source(&config)?;cleanup_stage_directory(&config,self.owner,self.paths.strict)?;
            self.state.stage_intent=None;self.save()?;
        }
        if self.paths.base.join("deployment.quiesced").try_exists().map_err(|_|err!(EACCES,"BROKER_QUIESCED"))?{fail!(EAGAIN,"BROKER_QUIESCED");}
        if matches!(request,Request::Publish{..})!=stage.is_some(){fail!(EINVAL,"BROKER_FD_COUNT");}
        let root=request.root().to_owned();if !root_valid(&root){fail!(EINVAL,"BROKER_ROOT");}
        if let Some(file)=&stage {
            #[cfg(target_os="macos")] if self.paths.strict {let mut fs=std::mem::MaybeUninit::<libc::statfs>::uninit();if unsafe{libc::fstatfs(file.as_raw_fd(),fs.as_mut_ptr())}!=0{fail!(EACCES,"BROKER_STAGE_FILESYSTEM");}let fs=unsafe{fs.assume_init()};let kind:Vec<u8>=fs.f_fstypename.iter().take_while(|b|**b!=0).map(|b|*b as u8).collect();if kind!=b"apfs"||fs.f_flags&libc::MNT_LOCAL as u32==0{fail!(EACCES,"BROKER_STAGE_FILESYSTEM");}}
            let m=file.metadata().map_err(|_|err!(EACCES,"BROKER_STAGE"))?;if !m.is_file()||(self.paths.strict&&m.uid()!=enclave_core::daemon::DaemonId::SwarmSync.uid())||m.len()>crate::streaming::MAX_ARTIFACT_BYTES||unsafe{libc::fcntl(file.as_raw_fd(),libc::F_GETFL)}&libc::O_ACCMODE!=libc::O_RDONLY{fail!(EACCES,"BROKER_STAGE");}}
        if matches!(request,Request::Revoke{..}){
            if stage.is_some(){fail!(EINVAL,"BROKER_FD_UNEXPECTED");}
            // Stored authority remains usable for cleanup even when new metadata
            // revokes a model, expires, or routes to a different dedicated volume.
            let Some(record)=self.state.records.get(&root).cloned() else{return Ok(None);};
            if !record.owned_snapshot{fail!(EACCES,"BROKER_SNAPSHOT_OWNERSHIP_UNCERTAIN");}
            self.retract(&root,&record)?;return Ok(None);
        }
        let (tuf,config,now)=self.refresh()?;let target=Self::target(&tuf,&root,now)?;
        if matches!(request,Request::Prepare{..}) {
            if self.state.records.get(&root).is_some_and(|r|r.retracting || !r.complete) {fail!(EAGAIN,"BROKER_RETRACTION_PENDING");}
            return Ok(None);
        }
        if let Some(stage)=&stage {if stage.metadata().map_err(|_|err!(EIO,"BROKER_STAGE"))?.len()!=target.length{fail!(EACCES,"BROKER_STAGE_LENGTH");}}
        if let Some(record)=self.state.records.get(&root).cloned(){
            if record.config!=config||record.target!=target{fail!(EACCES,"BROKER_AUTHORITY_CHANGED");}
            if record.retracting {self.retract(&root,&record)?;if matches!(request,Request::Reopen{..}){fail!(EACCES,"BROKER_NOT_PUBLISHED");}}
            else if record.complete {let file=self.publisher(&record)?.reopen(&target)?;return Ok(Some(file));}
            if self.state.records.contains_key(&root) {
                if !record.owned_snapshot{fail!(EACCES,"BROKER_SNAPSHOT_OWNERSHIP_UNCERTAIN");}
                self.retract(&root,&record)?;
            }
        }
        if matches!(request,Request::Reopen{..}){fail!(EACCES,"BROKER_NOT_PUBLISHED");}
        if self.state.records.len()>=MAX_RECORDS{fail!(E2BIG,"BROKER_PUBLICATION_LIMIT");}
        self.platform.require_capacity(&config,target.length)?;let stage=stage.ok_or_else(||err!(EINVAL,"BROKER_FD_REQUIRED"))?;
        self.state.stage_intent=Some(config.clone());self.save()?;
        let private=self.copy_stage(&stage,&target,&config)?;
        // Revalidate signed authority after the potentially lengthy private copy.
        let (current,current_config,now)=self.refresh()?;if current_config!=config||Self::target(&current,&root,now)?!=target{fail!(EACCES,"BROKER_AUTHORITY_CHANGED");}
        // A new intent may not adopt an existing unjournaled artifact/mount.
        for path in [config.source_mount.join("artifacts").join(&root),config.mount_root.join(&root)]{match std::fs::symlink_metadata(path){Err(error) if error.kind()==std::io::ErrorKind::NotFound=>(),_=>return Err(err!(EACCES,"BROKER_UNOWNED_PUBLICATION"))}}
        let record=Record{target:target.clone(),config,complete:false,owned_snapshot:false,holders_released:false,retracting:false};self.state.records.insert(root.clone(),record.clone());self.save()?;
        let file=match self.publisher(&record)?.publish_tracked(&private,&target){
            Ok(file)=>{self.state.records.get_mut(&root).unwrap().owned_snapshot=true;self.save()?;file},
            Err(failure)=>{use crate::snapshot_publication::PublicationFailureKind::*;match failure.kind{Cleaned=>{self.state.records.remove(&root);self.save()?;},OwnedIncomplete=>{self.state.records.get_mut(&root).unwrap().owned_snapshot=true;self.save()?;},OwnershipUncertain=>{}}return Err(failure.error);}
        };
        let current=self.refresh().and_then(|(tuf,config,now)|{if config!=record.config||Self::target(&tuf,&root,now)?!=target{fail!(EACCES,"BROKER_AUTHORITY_CHANGED");}Ok(())});
        if let Err(error)=current {self.retract(&root,&record)?;return Err(error);}
        drop(private);self.state.stage_intent=None;
        self.state.records.get_mut(&root).unwrap().complete=true;self.save()?;Ok(Some(file))
    }

    fn retract(&mut self,root:&str,record:&Record)->EnclaveResult<()> {
        self.state.records.get_mut(root).ok_or_else(||err!(EIO,"BROKER_RECORD"))?.retracting=true;
        self.save()?;
        let publisher=self.publisher(record)?;
        publisher.revoke_with_holder_check(&record.target,|held| {
            if !self.state.records[root].holders_released {
                match held {
                    Some(file)=>self.platform.enforce_holders(&file,root)?,
                    None if record.complete=>fail!(EACCES,"BROKER_HOLDER_IDENTITY_UNAVAILABLE"),
                    None=>(), // persisted incomplete intent was never exposed
                }
                self.state.records.get_mut(root).unwrap().holders_released=true;
                self.save()?; // durable before unmount/deletion can start
            }
            Ok(())
        })?;
        self.state.records.remove(root);self.save()
    }
    fn lifecycle(&self,operation:&str,root:&str,result:&EnclaveResult<Option<File>>)->EnclaveResult<()> {
        let line=format!("operation={operation} root={} outcome={} reason={} persistence_poisoned={} incomplete_records={}\n",if root_valid(root){root}else{"invalid"},if result.is_ok(){"ok"}else{"refused"},result.as_ref().err().map(|e|e.reason.as_str()).unwrap_or("NONE"),self.poisoned,self.state.records.values().filter(|r|!r.complete).count());
        if line.len()>1024{fail!(E2BIG,"BROKER_AUDIT");}
        let directory=directory(&self.paths.base,self.owner,self.paths.strict)?;let path=self.paths.base.join("lifecycle.log");
        let open=||File::options().append(true).create(true).mode(0o600).custom_flags(libc::O_NOFOLLOW|libc::O_NONBLOCK|libc::O_CLOEXEC).open(&path).map_err(|_|err!(EIO,"BROKER_AUDIT"));
        let mut file=open()?;let m=file.metadata().map_err(|_|err!(EIO,"BROKER_AUDIT"))?;if !m.is_file()||m.uid()!=self.owner||m.nlink()!=1||m.mode()&0o077!=0{fail!(EACCES,"BROKER_AUDIT");}
        if m.len()+line.len() as u64>64*1024 {let previous=self.paths.base.join("lifecycle.previous.log");match std::fs::symlink_metadata(&previous){Ok(m) if m.is_file()&&m.uid()==self.owner&&m.nlink()==1&&m.mode()&0o077==0=>std::fs::remove_file(&previous).map_err(|_|err!(EIO,"BROKER_AUDIT"))?,Err(error) if error.kind()==std::io::ErrorKind::NotFound=>(),_=>return Err(err!(EACCES,"BROKER_AUDIT"))}drop(file);std::fs::rename(&path,&previous).map_err(|_|err!(EIO,"BROKER_AUDIT"))?;file=open()?;}
        file.write_all(line.as_bytes()).map_err(|_|err!(EIO,"BROKER_AUDIT"))?;file.sync_all().map_err(|_|err!(EIO,"BROKER_AUDIT"))?;directory.sync_all().map_err(|_|err!(EIO,"BROKER_AUDIT"))?;Ok(())
    }
    fn copy_stage(&self,stage:&File,target:&TargetFile,config:&SealedConfig)->EnclaveResult<File>{
        let m=stage.metadata().map_err(|_|err!(EIO,"BROKER_STAGE"))?;
        if !m.is_file()||m.len()!=target.length||unsafe{libc::fcntl(stage.as_raw_fd(),libc::F_GETFL)}&libc::O_ACCMODE!=libc::O_RDONLY{fail!(EACCES,"BROKER_STAGE");}
        // The verified root-private stage lives on the dedicated APFS volume
        // so publication clones it directly rather than creating a third copy.
        let stage_dir=cleanup_stage_directory(config,self.owner,self.paths.strict)?;
        let directory=directory(&stage_dir,self.owner,self.paths.strict)?;
        let mut available=std::mem::MaybeUninit::<libc::statvfs>::uninit();if unsafe{libc::fstatvfs(directory.as_raw_fd(),available.as_mut_ptr())}!=0{fail!(EIO,"BROKER_CAPACITY");}let available=unsafe{available.assume_init()};let free=(available.f_bavail as u64).checked_mul(available.f_frsize as u64).ok_or_else(||err!(E2BIG,"BROKER_CAPACITY"))?;
        if free<target.length.checked_add(4*1024*1024*1024).ok_or_else(||err!(E2BIG,"BROKER_CAPACITY"))?{fail!(EAGAIN,"BROKER_CAPACITY");}
        let path=stage_dir.join(format!("stage-{:x}{:x}",enclave_core::rng::u64(),enclave_core::rng::u64()));
        let result=(||{let mut writer=File::options().read(true).write(true).create_new(true).mode(0o600).custom_flags(libc::O_NOFOLLOW|libc::O_CLOEXEC).open(&path).map_err(|_|err!(EIO,"BROKER_STAGE"))?;
            enclave_core::staging::preallocate(&writer,target.length)?;
            let mut source=stage.try_clone().map_err(|_|err!(EIO,"BROKER_STAGE"))?;source.seek(SeekFrom::Start(0)).map_err(|_|err!(EIO,"BROKER_STAGE"))?;
            let deadline=Instant::now()+Duration::from_secs(300);let mut left=target.length;let mut buffer=[0u8;65536];while left>0{if Instant::now()>=deadline{fail!(ETIMEDOUT,"BROKER_STAGE_DEADLINE");}let bound=left.min(buffer.len() as u64) as usize;let n=source.read(&mut buffer[..bound]).map_err(|_|err!(EIO,"BROKER_STAGE"))?;if n==0{fail!(EACCES,"BROKER_STAGE_LENGTH");}writer.write_all(&buffer[..n]).map_err(|_|err!(EIO,"BROKER_STAGE"))?;left-=n as u64;}let mut trailing=[0];if source.read(&mut trailing).map_err(|_|err!(EIO,"BROKER_STAGE"))?!=0{fail!(EACCES,"BROKER_STAGE_LENGTH");}
            writer.sync_all().map_err(|_|err!(EIO,"BROKER_STAGE"))?;writer.set_permissions(std::fs::Permissions::from_mode(0o400)).map_err(|_|err!(EIO,"BROKER_STAGE"))?;let reader=File::options().read(true).custom_flags(libc::O_NOFOLLOW|libc::O_CLOEXEC).open(&path).map_err(|_|err!(EIO,"BROKER_STAGE"))?;std::fs::remove_file(&path).map_err(|_|err!(EIO,"BROKER_STAGE"))?;drop(writer);
            crate::snapshot_publication::verify_file(&reader,target)?;Ok(reader)})();let _=std::fs::remove_file(&path);result
    }
}
fn cleanup_stage_directory(config:&SealedConfig,owner:u32,strict:bool)->EnclaveResult<PathBuf> {
    let stage_dir=config.source_mount.join(".broker-stages");
    match std::fs::create_dir(&stage_dir) {Ok(())=>std::fs::set_permissions(&stage_dir,std::fs::Permissions::from_mode(0o700)).map_err(|_|err!(EIO,"BROKER_STAGE"))?,Err(e) if e.kind()==std::io::ErrorKind::AlreadyExists=>(),Err(_)=>return Err(err!(EIO,"BROKER_STAGE"))}
    let directory=directory(&stage_dir,owner,strict)?;
    if directory.metadata().map_err(|_|err!(EIO,"BROKER_STAGE"))?.mode()&0o077!=0 {fail!(EACCES,"BROKER_STAGE");}
    // The broker is serial and holds its process lock. Stale private names
    // from a crash are unlinked without truncating any possible alias.
    for entry in std::fs::read_dir(&stage_dir).map_err(|_|err!(EIO,"BROKER_STAGE"))? {
        let entry=entry.map_err(|_|err!(EIO,"BROKER_STAGE"))?;
        if !entry.file_name().to_string_lossy().starts_with("stage-") {fail!(EACCES,"BROKER_STAGE");}
        let m=std::fs::symlink_metadata(entry.path()).map_err(|_|err!(EIO,"BROKER_STAGE"))?;
        if !m.is_file() || m.uid()!=owner || m.nlink()!=1 || m.mode()&0o077!=0 {fail!(EACCES,"BROKER_STAGE");}
        std::fs::remove_file(entry.path()).map_err(|_|err!(EIO,"BROKER_STAGE"))?;
    }
    Ok(stage_dir)
}
fn operation_file(paths:&Paths,owner:u32)->EnclaveResult<File>{let file=File::options().read(true).write(true).create(true).mode(0o600).custom_flags(libc::O_NOFOLLOW|libc::O_NONBLOCK|libc::O_CLOEXEC).open(paths.base.join("operation.lock")).map_err(|_|err!(EACCES,"BROKER_OPERATION_LOCK"))?;let m=file.metadata().map_err(|_|err!(EACCES,"BROKER_OPERATION_LOCK"))?;if !m.is_file()||m.uid()!=owner||m.nlink()!=1||m.mode()&0o077!=0{fail!(EACCES,"BROKER_OPERATION_LOCK");}Ok(file)}
struct Operation(File);
impl Operation {fn acquire(file:File)->EnclaveResult<Self>{if unsafe{libc::flock(file.as_raw_fd(),libc::LOCK_EX|libc::LOCK_NB)}!=0{fail!(EAGAIN,"BROKER_OPERATION_BUSY");}Ok(Self(file))}}
impl Drop for Operation {fn drop(&mut self){unsafe{libc::flock(self.0.as_raw_fd(),libc::LOCK_UN)};}}
fn bounded_frame(stream:&mut UnixStream)->EnclaveResult<Vec<u8>>{
    bounded_frame_before(stream,Instant::now()+Duration::from_secs(5))
}
fn bounded_frame_before(stream:&mut UnixStream,deadline:Instant)->EnclaveResult<Vec<u8>>{
    fn exact(stream:&mut UnixStream,mut out:&mut [u8],deadline:Instant)->EnclaveResult<()>{while !out.is_empty(){let left=deadline.saturating_duration_since(Instant::now());if left.is_zero(){fail!(ETIMEDOUT,"BROKER_FRAME_DEADLINE");}stream.set_read_timeout(Some(left)).map_err(|_|err!(EIO,"BROKER_TIMEOUT"))?;let n=stream.read(out).map_err(|_|err!(EIO,"BROKER_FRAME"))?;if n==0{fail!(EIO,"BROKER_FRAME");}out=&mut out[n..];}Ok(())}
    let mut header=[0;4];exact(stream,&mut header,deadline)?;let n=u32::from_be_bytes(header) as usize;if n==0||n>FRAME{fail!(E2BIG,"BROKER_FRAME");}let mut bytes=vec![0;n];exact(stream,&mut bytes,deadline)?;stream.set_read_timeout(Some(deadline.saturating_duration_since(Instant::now()).max(Duration::from_millis(1)))).map_err(|_|err!(EIO,"BROKER_TIMEOUT"))?;Ok(bytes)
}
// The root administrative grammar is disjoint from the unchanged CAS grammar.
// None of these private wire values is an installer/inactivity capability.
#[derive(Clone,Debug,PartialEq,Eq,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
struct AdminBinding {target_id:String,descriptor_sha256:String,pins_sha256:String}
#[derive(Clone,Copy,Debug,PartialEq,Eq,Serialize,Deserialize)]
enum AdminAction {QuiesceIdle}
#[derive(Clone,Debug,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
struct AdminRequest {v:u8,action:AdminAction,binding:AdminBinding,challenge:[u8;32]}
#[derive(Debug,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
struct AdminResponse {v:u8,action:AdminAction,binding:AdminBinding,challenge:[u8;32]}
enum PeerRole {Cas,Maintenance(AdminBinding)}
struct CurrentAdmin {binding:AdminBinding,ctl:CodeRequirement,broker:CodeRequirement}

fn current_requirement(identifier:&str,manifest:&BTreeMap<String,Vec<String>>)->EnclaveResult<CodeRequirement> {
    // Do not call for_identifier/pinned_from_manifest: those consult legacy
    // caches on the way to constructing a requirement. These bytes are fresh.
    let hashes=manifest.get(identifier).filter(|hashes|!hashes.is_empty()&&hashes.len()<=32)
        .ok_or_else(||err!(EACCES,"BROKER_ADMIN_CURRENT_PINS"))?;
    let mut unique=std::collections::BTreeSet::new();
    if hashes.iter().any(|hash|hash.len()!=40||!hash.bytes().all(|b|b.is_ascii_hexdigit())
        ||!unique.insert(hash.to_ascii_lowercase())) {fail!(EACCES,"BROKER_ADMIN_CURRENT_PINS");}
    Ok(CodeRequirement {identifier:identifier.into(),team_id:enclave_core::codesign::TEAM_ID.into(),cdhash_allowlist:hashes.clone()})
}
fn current_admin(checked:&enclave_core::deployment::CheckedDeploymentTarget)->EnclaveResult<CurrentAdmin> {
    use enclave_core::deployment;
    use sha2::{Digest,Sha256};
    let selected=deployment::selected().ok_or_else(||err!(EACCES,"BROKER_ADMIN_SELECTED_REQUIRED"))?;
    if selected.config_path()!=checked.config_path()||selected.descriptor_sha256()!=checked.descriptor_sha256()
        ||selected.target()!=checked.target() {fail!(ESTALE,"BROKER_ADMIN_CONTEXT_CHANGED");}
    let current=deployment::load(checked.config_path())?;
    if current.descriptor_sha256()!=checked.descriptor_sha256()||current.target()!=checked.target()
        ||current.target().profile!=enclave_core::profile::Profile::L3 {fail!(ESTALE,"BROKER_ADMIN_CONTEXT_CHANGED");}
    let pin_path=deployment::normalized_path(&checked.target().codesign_pins_file)?;
    let raw=trusted_read(&pin_path,1024*1024,0,true)?;
    let manifest=enclave_core::codesign::pins::parse(&raw).map_err(|_|err!(EACCES,"BROKER_ADMIN_CURRENT_PINS"))?;
    Ok(CurrentAdmin {binding:AdminBinding {target_id:checked.target().target_id.clone(),
        descriptor_sha256:checked.descriptor_sha256().into(),pins_sha256:hex::encode(Sha256::digest(&raw))},
        ctl:current_requirement(enclave_core::codesign::CTL_IDENTIFIER,&manifest)?,
        broker:current_requirement(IDENTIFIER,&manifest)?})
}
fn recheck_admin(binding:&AdminBinding)->EnclaveResult<()> {
    let checked=enclave_core::deployment::selected().ok_or_else(||err!(EACCES,"BROKER_ADMIN_SELECTED_REQUIRED"))?;
    if current_admin(checked)?.binding!=*binding {fail!(ESTALE,"BROKER_ADMIN_CONTEXT_CHANGED");}Ok(())
}
fn admin_io(stream:&UnixStream,until:Instant)->EnclaveResult<()> {
    let remaining=until.saturating_duration_since(Instant::now());
    if remaining.is_zero() {fail!(ETIMEDOUT,"BROKER_ADMIN_DEADLINE");}
    stream.set_read_timeout(Some(remaining)).map_err(|_|err!(EIO,"BROKER_TIMEOUT"))?;
    stream.set_write_timeout(Some(remaining)).map_err(|_|err!(EIO,"BROKER_TIMEOUT"))?;Ok(())
}
fn admin_eof(stream:&mut UnixStream,until:Instant)->EnclaveResult<()> {
    loop {admin_io(stream,until)?;let mut byte=[0];match stream.read(&mut byte) {
        Ok(0)=>return Ok(()),Ok(_)=>fail!(EINVAL,"BROKER_ADMIN_TRAILING"),
        Err(error) if error.kind()==std::io::ErrorKind::Interrupted=>{},
        Err(_)=>fail!(EIO,"BROKER_ADMIN_EOF"),
    }}
}
fn decode_admin<T:serde::de::DeserializeOwned>(bytes:&[u8])->EnclaveResult<T> {
    let mut cursor=std::io::Cursor::new(bytes);
    let value=ciborium::from_reader(&mut cursor).map_err(|_|err!(EINVAL,"BROKER_ADMIN_REQUEST"))?;
    if cursor.position() as usize!=bytes.len() {fail!(EINVAL,"BROKER_ADMIN_TRAILING");}Ok(value)
}
fn authenticate(stream:&UnixStream)->EnclaveResult<PeerRole>{
    let peer=ipc::peer_credentials(stream)?;
    if peer.uid==0 {
        if !enclave_core::codesign::enforced(){fail!(EACCES,"BROKER_ADMIN_NATIVE_REQUIRED");}
        let checked=enclave_core::deployment::selected().ok_or_else(||err!(EACCES,"BROKER_ADMIN_SELECTED_REQUIRED"))?;
        let current=current_admin(checked)?;
        let token=peer.audit_token.ok_or_else(||err!(EACCES,"BROKER_AUDIT_TOKEN"))?;
        enclave_core::codesign::verify_peer(&token,&current.ctl)?;
        recheck_admin(&current.binding)?;
        return Ok(PeerRole::Maintenance(current.binding));
    }
    authenticate_cas(stream)?;Ok(PeerRole::Cas)
}
fn authenticate_cas(stream:&UnixStream)->EnclaveResult<()>{
    let peer=ipc::peer_credentials(stream)?;if peer.uid!=enclave_core::daemon::DaemonId::SwarmSync.uid(){fail!(EACCES,"BROKER_PEER_UID");}
    let token=peer.audit_token.ok_or_else(||err!(EACCES,"BROKER_AUDIT_TOKEN"))?;
    let identifier=enclave_core::daemon::DaemonId::SwarmSync.launchd_label();enclave_core::codesign::pins::require(&identifier)?;let requirement=CodeRequirement::pinned_boundary(&identifier)?;if requirement.cdhash_allowlist.is_empty(){fail!(EACCES,"BROKER_PEER_PIN");}enclave_core::codesign::verify_peer(&token,&requirement)?;Ok(())
}
fn connection_for_role(mut stream:UnixStream,broker:&mut Broker,
    auth:impl FnOnce(&UnixStream)->EnclaveResult<PeerRole>,
    check_admin:impl Fn(&AdminBinding)->EnclaveResult<()>)->EnclaveResult<()>{
    let _operation=Operation::acquire(broker.operation.try_clone().map_err(|_|err!(EIO,"BROKER_OPERATION_LOCK"))?)?;
    stream.set_read_timeout(Some(Duration::from_secs(5))).map_err(|_|err!(EIO,"BROKER_TIMEOUT"))?;stream.set_write_timeout(Some(Duration::from_secs(5))).map_err(|_|err!(EIO,"BROKER_TIMEOUT"))?;
    let role=auth(&stream)?; // kernel UID and pinned code checked BEFORE frame or FDs
    if let PeerRole::Maintenance(binding)=role {return administrative_connection(stream,broker,binding,check_admin);}
    let bytes=bounded_frame(&mut stream)?;let mut cursor=std::io::Cursor::new(&bytes);let request:Request=ciborium::from_reader(&mut cursor).map_err(|_|err!(EINVAL,"BROKER_REQUEST"))?;if cursor.position() as usize!=bytes.len(){fail!(EINVAL,"BROKER_REQUEST_TRAILING");}
    let mut fds=ipc::recv_fd_packet(&stream,1)?;let expected=usize::from(matches!(request,Request::Publish{..}));if fds.len()!=expected{fail!(EINVAL,"BROKER_FD_COUNT");}let stage=fds.pop().map(File::from);
    let root=request.root().to_owned();let operation=match &request {Request::Publish{..}=>"publish",Request::Reopen{..}=>"reopen",Request::Revoke{..}=>"revoke",Request::Prepare{..}=>"prepare"};
    let mut result=broker.execute(request,stage);if let Err(error)=broker.lifecycle(operation,&root,&result){result=Err(error);}
    match result{Ok(file)=>{let response=if file.is_some(){Response::Descriptor}else{Response::Revoked};ipc::write_frame(&mut stream,&ipc::to_cbor(&ipc::Reply::Ok(response))?)?;if let Some(file)=file{ipc::send_fds(&stream,&[file.as_raw_fd()])?;}Ok(())},Err(error)=>ipc::write_frame(&mut stream,&ipc::to_cbor(&ipc::Reply::<Response>::Err(error))?)}
}
// Existing CAS fixtures use the very same production role dispatcher. This
// authentication substitution is absent from non-test callers and binaries.
#[cfg(test)]
fn connection(stream:UnixStream,broker:&mut Broker,auth:impl FnOnce(&UnixStream)->EnclaveResult<()>)->EnclaveResult<()> {
    connection_for_role(stream,broker,|stream|auth(stream).map(|()|PeerRole::Cas),recheck_admin)
}
fn administrative_connection(mut stream:UnixStream,broker:&mut Broker,binding:AdminBinding,
    check:impl Fn(&AdminBinding)->EnclaveResult<()>)->EnclaveResult<()> {
    // The caller retains the accepted-operation lock across parsing, durable
    // inspection, marker publication, postchecks and the complete reply.
    let until=Instant::now()+Duration::from_secs(5);
    let request:AdminRequest=decode_admin(&bounded_frame_before(&mut stream,until)?)?;
    admin_io(&stream,until)?;ipc::recv_fd_packet(&stream,0)?;
    // Half-close is mandatory: a delayed extra frame/byte cannot hide behind
    // a successful peek. No effect occurs until exact end of request stream.
    admin_eof(&mut stream,until)?;
    let result=(|| {
        if request.v!=1||request.action!=AdminAction::QuiesceIdle||request.binding!=binding {
            fail!(EACCES,"BROKER_ADMIN_BINDING");
        }
        check(&binding)?;admin_io(&stream,until)?;
        if broker.poisoned {fail!(EACCES,"BROKER_STATE_RESTART_REQUIRED");}
        if !broker.state.records.is_empty()||broker.state.stage_intent.is_some() {
            fail!(EACCES,"BROKER_PUBLICATIONS_REQUIRE_RETRACTION");
        }
        quiesce_locked(&broker.paths,broker.owner)?;
        check(&binding)?;admin_io(&stream,until)?;
        Ok(AdminResponse {v:1,action:AdminAction::QuiesceIdle,binding,challenge:request.challenge})
    })();
    // Stable reasons only; no private ledger/path/parser detail crosses roles.
    let reply=match result {Ok(response)=>ipc::Reply::Ok(response),Err(error)=>
        ipc::Reply::Err(enclave_core::error::EnclaveError::new(error.errno,&error.reason))};
    admin_io(&stream,until)?;ipc::write_frame(&mut stream,&ipc::to_cbor(&reply)?)?;
    ipc::send_fd_packet(&stream,&[])?;
    stream.shutdown(std::net::Shutdown::Write).map_err(|_|err!(EIO,"BROKER_ADMIN_EOF"))?;Ok(())
}
// This compiled profile is constructed only from independently verified or
// durably retained authority. No request text can become Seatbelt source.
fn confinement(configs:&[SealedConfig])->EnclaveResult<String>{
    let mut paths=std::collections::BTreeSet::new();
    for config in configs {config.validate()?;for path in [&config.source_mount,&config.mount_root]{let value=path.to_str().ok_or_else(||err!(EINVAL,"BROKER_SANDBOX_PATH"))?;if value.bytes().any(|b|matches!(b,b'"'|b'\\')||b.is_ascii_control()){fail!(EINVAL,"BROKER_SANDBOX_PATH");}let resolved=if cfg!(target_os="macos"){if let Some(rest)=value.strip_prefix("/var/"){format!("/private/var/{rest}")}else if let Some(rest)=value.strip_prefix("/tmp/"){format!("/private/tmp/{rest}")}else{value.to_owned()}}else{value.to_owned()};paths.insert(resolved);}}
    let mut text=String::from(r#"(version 1)
(deny default)
(import "bsd.sb")
(allow sysctl-read)
(allow file-read-metadata (literal "/System/Volumes/Data"))
(allow file-read-data file-read-metadata (literal "/private"))
(allow signal (target self) (target children))
(allow process-fork)
(allow process-exec (literal "/sbin/mount_apfs"))
(allow file-read* (literal "/sbin/mount_apfs") (subpath "/usr/lib") (subpath "/System/Library") (literal "/dev/random") (literal "/dev/urandom") (literal "/dev/null"))
(allow file-read* (literal "/opt/enterprise/enclave/bin/enclave-swarm-syncd") (literal "/opt/enterprise/enclave/bin/enclave-apfs-broker") (literal "/Library/Application Support/EnterpriseEnclave/codesign-pins.json") (literal "/Library/Application Support/EnterpriseEnclave/tuf/root.json"))
(allow mach-lookup (global-name "com.apple.SecurityServer") (global-name "com.apple.securityd.xpc"))
(allow file-read* file-write* (subpath "/private/var/db/enclave/apfs-broker") (subpath "/private/var/run/enclave/apfs-broker"))
(allow network-bind network-inbound (local unix-socket (literal "/private/var/run/enclave/apfs-broker/broker.sock")))
(allow network-outbound (remote unix-socket (literal "/private/var/run/enclave/supervisor/held-v1.sock")))
(allow file-read* (literal "/opt/enterprise/enclave/bin/depot-enclave"))
"#);
    // Directory-only reads support the held-FD authority walker; these grant no
    // ability to read arbitrary child files or mutate their parent directories.
    let mut ancestors=std::collections::BTreeSet::new();
    for path in paths.iter().map(Path::new).chain([Path::new(BASE),Path::new(ROOT_PIN),Path::new(SOCKET),Path::new(enclave_core::codesign::PIN_FILE)]) {for parent in path.ancestors().skip(1){ancestors.insert(parent.to_string_lossy().into_owned());}}
    for path in ancestors {let path=if path=="/var"||path.starts_with("/var/"){format!("/private{path}")}else{path};text.push_str(&format!("(allow file-read-data file-read-metadata (literal \"{path}\"))\n"));}
    for config in configs {text.push_str(&format!("(allow file-read* (literal \"{}\"))\n",config.volume_device));}
    for path in paths {text.push_str(&format!("(allow file-read* file-write* file-mount file-unmount (subpath \"{path}\"))\n"));}
    Ok(text)
}
// Keep the legacy generator above byte-identical. Selected profiles enumerate
// only this checked target's executables, protected inputs and local endpoints.
fn confinement_for(paths:&Paths,configs:&[SealedConfig])->EnclaveResult<String> {
    let Some(target)=&paths.target else{return confinement(configs);};
    let normalized=enclave_core::deployment::normalized_path;
    let literal=|path:&Path|->EnclaveResult<String>{Ok(normalized(path)?.into_os_string().into_string().map_err(|_|err!(EINVAL,"BROKER_SANDBOX_PATH"))?)};
    let mut reads=std::collections::BTreeSet::new();
    for path in &target.public_inputs {reads.insert(literal(path)?);}
    for name in ["enclave-swarm-syncd",BINARY,"depot-enclave"] {reads.insert(literal(&target.binary_dir.join(name))?);}
    let base=literal(&paths.base)?;let socket=literal(&target.socket)?;
    let socket_parent=literal(target.socket.parent().ok_or_else(||err!(EINVAL,"BROKER_SANDBOX_PATH"))?)?;
    let held=literal(&target.supervisor.with_file_name("held-v1.sock"))?;
    let mut mounts=std::collections::BTreeSet::new();
    for config in configs {paths.validate_sealed(config)?;mounts.insert(literal(&config.source_mount)?);mounts.insert(literal(&config.mount_root)?);}
    let mut text=String::from(r#"(version 1)
(deny default)
(import "bsd.sb")
(allow sysctl-read)
(allow file-read-metadata (literal "/System/Volumes/Data"))
(allow file-read-data file-read-metadata (literal "/private"))
(allow signal (target self) (target children))
(allow process-fork)
(allow process-exec (literal "/sbin/mount_apfs"))
(allow file-read* (literal "/sbin/mount_apfs") (subpath "/usr/lib") (subpath "/System/Library") (literal "/dev/random") (literal "/dev/urandom") (literal "/dev/null"))
(allow mach-lookup (global-name "com.apple.SecurityServer") (global-name "com.apple.securityd.xpc"))
"#);
    text.push_str(&format!("(allow file-read* {})\n",reads.iter().map(|p|format!("(literal \"{p}\")")).collect::<Vec<_>>().join(" ")));
    text.push_str(&format!("(allow file-read* file-write* (subpath \"{base}\") (subpath \"{socket_parent}\"))\n"));
    text.push_str(&format!("(allow network-bind network-inbound (local unix-socket (literal \"{socket}\")))\n"));
    text.push_str(&format!("(allow network-outbound (remote unix-socket (literal \"{held}\")))\n"));
    let mut ancestors=std::collections::BTreeSet::new();
    for path in reads.iter().chain(mounts.iter()).map(Path::new).chain([Path::new(&base),Path::new(&socket),Path::new(&held)]) {
        for parent in path.ancestors().skip(1){ancestors.insert(parent.to_string_lossy().into_owned());}
    }
    for path in ancestors{text.push_str(&format!("(allow file-read-data file-read-metadata (literal \"{path}\"))\n"));}
    for config in configs{text.push_str(&format!("(allow file-read* (literal \"{}\"))\n",config.volume_device));}
    for path in mounts{text.push_str(&format!("(allow file-read* file-write* file-mount file-unmount (subpath \"{path}\"))\n"));}
    Ok(text)
}
fn apply_confinement(text:&str)->EnclaveResult<()> {
    #[cfg(target_os="macos")] {use std::ffi::{CString,CStr};unsafe extern "C" {fn sandbox_init(profile:*const libc::c_char,flags:u64,error:*mut *mut libc::c_char)->libc::c_int;fn sandbox_free_error(error:*mut libc::c_char);}
        let profile=CString::new(text).map_err(|_|err!(EINVAL,"BROKER_SANDBOX"))?;let mut error=std::ptr::null_mut();let result=unsafe{sandbox_init(profile.as_ptr(),0,&mut error)};if result!=0{if !error.is_null(){let _=unsafe{CStr::from_ptr(error)};unsafe{sandbox_free_error(error)};}fail!(EPERM,"BROKER_SANDBOX");}Ok(())
    }
    #[cfg(not(target_os="macos"))] {let _=text;fail!(ENOSYS,"BROKER_SANDBOX");}
}
/// Deployment-only inspection of the immutable selected target or default.
/// It never initializes missing state or mutates APFS; the caller must stop CAS
/// before inspecting and keep the broker available if publications remain.
pub fn check_idle()->EnclaveResult<()> {
    if !cfg!(target_os="macos")||ipc::geteuid()!=0{fail!(EACCES,"BROKER_PRODUCTION_ONLY");}
    inspect_idle(&Paths::for_process()?,0)
}
/// Deployment authorization barrier: serialize with the full accepted request,
/// inspect durable ownership, then forbid queued/new effects until redeployment.
/// This root-only fixed action changes only its protected coordination marker.
pub fn quiesce_idle()->EnclaveResult<()> {if !cfg!(target_os="macos")||ipc::geteuid()!=0{fail!(EACCES,"BROKER_PRODUCTION_ONLY");}quiesce(&Paths::for_process()?,0)}
fn quiesce(paths:&Paths,owner:u32)->EnclaveResult<()> {
    let _directory=directory(&paths.base,owner,paths.strict)?;
    let _operation=Operation::acquire(operation_file(paths,owner)?)?;quiesce_locked(paths,owner)
}
fn quiesce_locked(paths:&Paths,owner:u32)->EnclaveResult<()> {
    inspect_idle(paths,owner)?;
    publish_quiescence_marker(paths,owner,|file|enclave_core::fsutil::full_fsync(file))
}
fn marker_stamp(file:&File,owner:u32)->EnclaveResult<(u64,u64,u32,u32,u32,u64,u64,i64,i64,i64,i64)> {
    let m=file.metadata().map_err(|_|err!(EIO,"BROKER_QUIESCE"))?;
    if !m.is_file()||m.uid()!=owner||m.mode()&0o7777!=0o600||m.nlink()!=1||m.len()!=2 {
        fail!(EACCES,"BROKER_QUIESCE_MARKER");
    }
    Ok((m.dev(),m.ino(),m.uid(),m.gid(),m.mode(),m.nlink(),m.len(),m.mtime(),m.mtime_nsec(),m.ctime(),m.ctime_nsec()))
}
fn publish_quiescence_marker(paths:&Paths,owner:u32,mut sync:impl FnMut(&File)->EnclaveResult<()>)->EnclaveResult<()> {
    use std::os::unix::fs::FileExt;
    let directory=directory(&paths.base,owner,paths.strict)?;
    let leaf=b"deployment.quiesced\0";
    let flags=libc::O_RDWR|libc::O_NOFOLLOW|libc::O_NONBLOCK|libc::O_CLOEXEC;
    let created=unsafe {libc::openat(directory.as_raw_fd(),leaf.as_ptr().cast(),flags|libc::O_CREAT|libc::O_EXCL,0o600)};
    let (fd,new)=if created>=0 {(created,true)} else {
        if std::io::Error::last_os_error().kind()!=std::io::ErrorKind::AlreadyExists {fail!(EIO,"BROKER_QUIESCE");}
        (unsafe {libc::openat(directory.as_raw_fd(),leaf.as_ptr().cast(),flags)},false)
    };
    if fd<0 {fail!(EACCES,"BROKER_QUIESCE_MARKER");}
    let mut file=unsafe {File::from_raw_fd(fd)};
    if new {file.write_all(b"1\n").map_err(|_|err!(EIO,"BROKER_QUIESCE"))?;}
    let stamp=marker_stamp(&file,owner)?;
    let check=||->EnclaveResult<()> {
        let mut bytes=[0u8;3];let count=file.read_at(&mut bytes,0).map_err(|_|err!(EIO,"BROKER_QUIESCE"))?;
        if count!=2||&bytes[..2]!=b"1\n"||marker_stamp(&file,owner)?!=stamp {fail!(ESTALE,"BROKER_QUIESCE_MARKER");}
        let named=unsafe {libc::openat(directory.as_raw_fd(),leaf.as_ptr().cast(),libc::O_RDONLY|libc::O_NOFOLLOW|libc::O_NONBLOCK|libc::O_CLOEXEC)};
        if named<0 {fail!(ESTALE,"BROKER_QUIESCE_MARKER");}
        let named=unsafe {File::from_raw_fd(named)};
        if marker_stamp(&named,owner)?!=stamp {fail!(ESTALE,"BROKER_QUIESCE_MARKER");}
        let current=crate::snapshot_broker::directory(&paths.base,owner,paths.strict)?;
        let a=directory.metadata().map_err(|_|err!(EIO,"BROKER_QUIESCE"))?;
        let b=current.metadata().map_err(|_|err!(EIO,"BROKER_QUIESCE"))?;
        if (a.dev(),a.ino(),a.uid(),a.gid(),a.mode())!=(b.dev(),b.ino(),b.uid(),b.gid(),b.mode()) {
            fail!(ESTALE,"BROKER_QUIESCE_MARKER");
        }Ok(())
    };
    check()?;
    // Existing markers receive the same durability work as newly created ones.
    // Errors leave exact current state for diagnosis; never unlink or repair.
    sync(&file)?;sync(&directory)?;check()
}
fn inspect_idle(paths:&Paths,owner:u32)->EnclaveResult<()> {
    directory(&paths.state(),owner,paths.strict)?;
    for name in ["sealing.key","apfs-publications.sealed","apfs-publications.gen"]{trusted_read(&paths.state().join(name),32*1024*1024,owner,paths.strict)?;}
    let (_,loaded)=enclave_core::sealed::SealedStore::open_bounded_required(&paths.state(),"apfs-publications",MAX_STATE)?;
    let enclave_core::sealed::Loaded::State(bytes)=loaded else{fail!(EACCES,"BROKER_REQUIRED_STATE_MISSING");};let state:Persisted=enclave_core::sealed::decode(&bytes)?;
    if !matches!(state.version,1|2)||!state.records.is_empty()||state.stage_intent.is_some(){fail!(EACCES,"BROKER_PUBLICATIONS_REQUIRE_RETRACTION");}Ok(())
}
/// Production root entry point: default arguments or one protected deployment.
/// The descriptor selects routing only; signed TUF/config authority is separate.
/// Actual native mounting requires separately approved root entitlement deployment.
pub fn run()->EnclaveResult<()> {
    if !cfg!(target_os="macos")||ipc::geteuid()!=0{fail!(EACCES,"BROKER_PRODUCTION_ONLY");}
    let arguments:Vec<_>=std::env::args_os().skip(1).collect();
    if let Some(path)=parse_run_arguments(&arguments)? {
        let checked=enclave_core::deployment::load(&path)?;
        if checked.target().profile!=enclave_core::profile::Profile::L3 {fail!(EACCES,"BROKER_DEPLOYMENT_L3_REQUIRED");}
        enclave_core::deployment::upgrade::assert_start_allowed(&checked)?;
        enclave_core::deployment::select(checked)?;
    }
    // Startup only: existing restrictive admin/retraction must still work
    // after inhibition. Do not gate the live dispatcher or checked readers.
    if enclave_core::deployment::selected().is_some() {
        enclave_core::deployment::startup_lease::retain_selected_startup_lease()?;
    }
    let paths=Paths::for_process()?;
    if !enclave_core::resource::harden_process(){fail!(EACCES,"BROKER_HARDENING");}
    enclave_core::codesign::pins::require(IDENTIFIER)?;enclave_core::codesign::pins::require(&enclave_core::daemon::DaemonId::SwarmSync.launchd_label())?;
    let mut broker=Broker::open(paths,0,Arc::new(NativeSnapshotPlatform))?;
    let mut configs:Vec<_>=broker.state.records.values().map(|r|r.config.clone()).collect();
    match broker.refresh(){Ok((_,config,_))=>configs.push(config),Err(error) if configs.is_empty()=>return Err(error),Err(_)=>{eprintln!("APFS_BROKER cleanup_only=true current_authority=false");}}
    apply_confinement(&confinement_for(&broker.paths,&configs)?)?;
    let socket=broker.paths.socket();
    let listener=ipc::bind(&socket,ipc::SocketAccess::Group{gid:enclave_core::daemon::DaemonId::SwarmSync.gid()})?;
    // Serial requests bound memory, staging and privileged operations. Untrusted
    // sockets time out; each accepted connection gets exactly one request.
    for stream in listener.incoming(){match stream{Ok(stream)=>{let _=connection_for_role(stream,&mut broker,authenticate,recheck_admin);},Err(_)=>return Err(err!(EIO,"BROKER_ACCEPT"))}}
    Ok(())
}
/// Production CAS adapter. It never invokes privileged platform calls locally.
#[derive(Debug)]
pub struct BrokerClient;
/// Request only the live selected broker's restrictive administrative barrier.
/// Kernel root UID and fresh exact broker code pins authenticate the server;
/// its reciprocal root-CLI authentication grants no CAS publication operation.
/// The caller must retain genuine host maintenance exclusion through this call
/// and subsequent registration work. Success is neither whole-host inactivity
/// nor installation authority. No seed or private broker ledger enters the CLI.
/// A missing, default or older broker without this protocol refuses; never
/// infer quiescence from an absent launchd registration or installed executable.
pub fn request_selected_quiescence(checked:&enclave_core::deployment::CheckedDeploymentTarget,until:Instant)->EnclaveResult<()> {
    if !cfg!(target_os="macos")||ipc::geteuid()!=0||!enclave_core::codesign::enforced() {
        fail!(EACCES,"BROKER_ADMIN_NATIVE_ROOT_REQUIRED");
    }
    let before=current_admin(checked)?;
    let request=AdminRequest {v:1,action:AdminAction::QuiesceIdle,binding:before.binding.clone(),challenge:enclave_core::rng::bytes32()};
    let remaining=until.saturating_duration_since(Instant::now()).min(Duration::from_secs(2));
    if remaining.is_zero() {fail!(ETIMEDOUT,"BROKER_ADMIN_DEADLINE");}
    let client=ipc::Client::connect_verified_deadline(&checked.target().broker_socket(),0,Some(&before.broker),remaining)?;
    // Keep an explicit audit-token check: this boundary has no UID-only mode.
    let token=client.server.audit_token.ok_or_else(||err!(EACCES,"BROKER_AUDIT_TOKEN"))?;
    enclave_core::codesign::verify_peer(&token,&before.broker)?;
    recheck_admin(&before.binding)?;
    let mut stream=client.into_authenticated_stream();
    let exchange=admin_exchange(&mut stream,&request,until);
    // Evaluate selection/pin postcheck even when framing or the peer refused.
    let binding=recheck_admin(&before.binding);let time=admin_io(&stream,until);
    binding?;time?;exchange
}
fn admin_exchange(stream:&mut UnixStream,request:&AdminRequest,until:Instant)->EnclaveResult<()> {
    admin_io(stream,until)?;
    ipc::write_frame(stream,&ipc::to_cbor(&request)?)?;ipc::send_fd_packet(stream,&[])?;
    stream.shutdown(std::net::Shutdown::Write).map_err(|_|err!(EIO,"BROKER_ADMIN_EOF"))?;
    let exchange=(|| {
        let bytes=bounded_frame_before(stream,until)?;
        let reply:ipc::Reply<AdminResponse>=decode_admin(&bytes)?;
        admin_io(stream,until)?;ipc::recv_fd_packet(stream,0)?;admin_eof(stream,until)?;
        let response=match reply {ipc::Reply::Ok(response)=>response,ipc::Reply::Err(error)=>
            return Err(enclave_core::error::EnclaveError::new(error.errno,&error.reason))};
        if response.v!=1||response.action!=AdminAction::QuiesceIdle||response.binding!=request.binding
            ||response.challenge!=request.challenge {fail!(EACCES,"BROKER_ADMIN_REPLY_BINDING");}
        Ok(())
    })();
    exchange
}
impl BrokerClient {
    /// An authenticated, current-authority no-effect request. This is not native
    /// entitlement/mount acceptance and never creates a publication.
    pub fn require_ready(&self)->EnclaveResult<()> {match self.request_with_timeout(Request::Reopen{root:"0".repeat(64)},None,Duration::from_secs(2)){Err(error) if error.is("BROKER_TARGET")||error.is("BROKER_NOT_PUBLISHED")=>Ok(()),Err(error)=>Err(error),Ok(_)=>Err(err!(EACCES,"BROKER_READINESS_COLLISION"))}}

    fn request(&self,request:Request,stage:Option<&File>)->EnclaveResult<Option<File>>{self.request_with_timeout(request,stage,Duration::from_secs(330))}
    fn request_with_timeout(&self,request:Request,stage:Option<&File>,timeout:Duration)->EnclaveResult<Option<File>>{
        let paths=Paths::for_process()?;let socket=paths.socket();
        enclave_core::codesign::pins::require(IDENTIFIER)?;let requirement=CodeRequirement::apfs_broker()?;if requirement.cdhash_allowlist.is_empty(){fail!(EACCES,"BROKER_SERVER_PIN");}let mut client=ipc::Client::connect_verified_deadline(&socket,0,Some(&requirement),timeout.min(Duration::from_secs(2)))?;client.set_timeout(Some(timeout))?;
        let response:Response=client.call_with_fds(&request,&stage.map(|f|vec![f.as_raw_fd()]).unwrap_or_default())?;
        match response{Response::Revoked=>Ok(None),Response::Descriptor=>{let mut fds=client.recv_fds(1)?;if fds.len()!=1{fail!(EACCES,"BROKER_FD_COUNT");}let file=File::from(fds.remove(0));if unsafe{libc::fcntl(file.as_raw_fd(),libc::F_GETFL)}&libc::O_ACCMODE!=libc::O_RDONLY{fail!(EACCES,"BROKER_FD_ACCESS");}Ok(Some(file))}}
    }
}
impl SnapshotPublisher for BrokerClient {
    fn prepare_staging(&self,target:&TargetFile)->EnclaveResult<()> {
        let root=target.hashes.get("blake3").ok_or_else(||err!(EINVAL,"BROKER_ROOT"))?.clone();
        if self.request(Request::Prepare{root},None)?.is_some() {fail!(EIO,"BROKER_REPLY");}Ok(())
    }
    fn publish(&self,stage:&File,target:&TargetFile)->EnclaveResult<File>{let root=target.hashes.get("blake3").ok_or_else(||err!(EINVAL,"BROKER_ROOT"))?.clone();let file=self.request(Request::Publish{root},Some(stage))?.ok_or_else(||err!(EIO,"BROKER_REPLY"))?;crate::snapshot_publication::verify_file(&file,target)?;Ok(file)}
    fn reopen(&self,target:&TargetFile)->EnclaveResult<File>{let root=target.hashes.get("blake3").ok_or_else(||err!(EINVAL,"BROKER_ROOT"))?.clone();let file=self.request(Request::Reopen{root},None)?.ok_or_else(||err!(EIO,"BROKER_REPLY"))?;crate::snapshot_publication::verify_file(&file,target)?;Ok(file)}
    fn revoke(&self,target:&TargetFile)->EnclaveResult<()>{let root=target.hashes.get("blake3").ok_or_else(||err!(EINVAL,"BROKER_ROOT"))?.clone();if self.request(Request::Revoke{root},None)?.is_some(){fail!(EIO,"BROKER_REPLY");}Ok(())}
}
#[cfg(test)]
mod tests {
    use super::*;
    use enclave_crypto::tuf::{target_file,RepoBuilder};
    use std::sync::Mutex;
    const EXP:&str="2030-01-01T00:00:00Z";
    const PAYLOAD:&[u8]=b"independently authenticated broker fixture";
    fn deployment_target(id:&str)->enclave_core::deployment::DeploymentTarget {
        let root=Path::new("/broker-deployment-fixtures").join(id);
        let value=serde_json::json!({"version":1,"target_id":id,"role":"dedicated-test","profile":"L3",
            "authority_config":root.join("support/authority.json"),"expected_artifacts_manifest":root.join("support/artifacts.json"),
            "codesign_pins_file":root.join("support/pins.json"),"signing_identity_mode":"local-pins",
            "layout":{"binary_dir":root.join("bin"),"custody_bundle":root.join("support/Custody.app"),"sandbox_dir":root.join("sandbox"),
                "socket_root":root.join("run"),"state_root":root.join("state"),"audit_root":root.join("audit"),"cas_store_root":root.join("cas"),
                "staging_root":root.join("staging"),"support_root":root.join("support"),"launchd_namespace":format!("com.fixture.{id}"),"mach_service":format!("com.fixture.{id}.exception")},
            "broker":{"base_dir":root.join("state/apfs-broker"),"tuf_root_file":root.join("support/tuf-root.json")},"shared_read_only_inputs":[]});
        enclave_core::deployment::DeploymentTarget::parse(&serde_json::to_vec(&value).unwrap()).unwrap()
    }
    #[test]
    fn deployment_broker_arguments_admit_only_default_or_one_protected_descriptor() {
        let args=|values:&[&str]|values.iter().map(|value|std::ffi::OsString::from(*value)).collect::<Vec<_>>();
        assert!(parse_run_arguments(&[]).unwrap().is_none());
        assert_eq!(parse_run_arguments(&args(&["--deployment-target","/fixture/support/target.json"])).unwrap(),Some("/fixture/support/target.json".into()));
        for bad in [vec!["/fixture/target.json"],vec!["--deployment-target"],vec!["--deployment-target=/fixture/target.json"],
            vec!["--deployment-target","relative"],vec!["--deployment-target","/fixture/../target.json"],
            vec!["--deployment-target","/fixture/target.json","--dev"],vec!["--deployment-target","/fixture/target.json","--socket","/other/socket"],
            vec!["--deployment-target","/fixture/target.json","--deployment-target","/other/target.json"],vec!["--check-idle"],vec!["--quiesce-idle"]] {
            assert!(parse_run_arguments(&args(&bad)).is_err());
        }
    }
    #[test]
    fn deployment_broker_paths_and_l3_requirement_are_exact() {
        let default=Paths::production();assert_eq!(default.base,Path::new(BASE));assert_eq!(default.pin,Path::new(ROOT_PIN));assert_eq!(default.socket(),Path::new(SOCKET));
        for id in ["target-a","target-b"] {
            let target=deployment_target(id);let descriptor=target.layout.support_root.join("target.json");
            let paths=Paths::for_target(&target,&descriptor).unwrap();
            assert_eq!(paths.base,target.broker.as_ref().unwrap().base_dir);assert_eq!(paths.pin,target.broker.as_ref().unwrap().tuf_root_file);
            assert_eq!(paths.state(),paths.base.join("state"));assert_eq!(paths.repo(),paths.base.join("tuf/repo"));assert_eq!(paths.socket(),target.broker_socket());
            let routed=paths.target.unwrap();assert_eq!(routed.supervisor,target.supervisor_socket());assert_eq!(routed.cas,target.layout.cas_store_root);
            assert!(routed.public_inputs.contains(&descriptor));assert!(routed.public_inputs.contains(&target.codesign_pins_file));
        }
        let mut l2=deployment_target("target-l2");l2.profile=enclave_core::profile::Profile::L2;l2.broker=None;
        assert!(Paths::for_target(&l2,&l2.layout.support_root.join("target.json")).unwrap_err().is("BROKER_DEPLOYMENT_L3_REQUIRED"));
    }
    #[test]
    fn deployment_broker_confinement_has_only_selected_inputs_mutation_and_endpoints() {
        let target=deployment_target("target-a");let paths=Paths::for_target(&target,&target.layout.support_root.join("target.json")).unwrap();
        let config=SealedConfig{volume_device:"/dev/disk99s1".into(),source_mount:target.layout.cas_store_root.join("volume"),mount_root:paths.base.join("mounts")};
        let text=confinement_for(&paths,&[config.clone()]).unwrap();
        let executables=[target.layout.binary_dir.join(BINARY),target.layout.binary_dir.join("enclave-swarm-syncd"),target.layout.binary_dir.join("depot-enclave")];
        for path in paths.target.as_ref().unwrap().public_inputs.iter().chain(executables.iter()) {
            assert!(text.contains(&format!("(literal \"{}\")",path.display())));
        }
        assert_eq!(text.lines().filter(|l|l.contains("network-outbound")).collect::<Vec<_>>(),vec!["(allow network-outbound (remote unix-socket (literal \"/broker-deployment-fixtures/target-a/run/supervisor/held-v1.sock\")))"]);
        assert!(text.contains("(local unix-socket (literal \"/broker-deployment-fixtures/target-a/run/apfs-broker/broker.sock\"))"));
        assert_eq!(text.lines().filter(|l|l.contains("process-exec")).collect::<Vec<_>>(),vec!["(allow process-exec (literal \"/sbin/mount_apfs\"))"]);
        for forbidden in [BASE,ROOT_PIN,SOCKET,enclave_core::codesign::PIN_FILE,"/opt/enterprise/enclave/bin","target-b","remote tcp","remote udp"] {assert!(!text.contains(forbidden));}
        assert_eq!(confinement_for(&Paths::production(),&[config.clone()]).unwrap(),confinement(&[config]).unwrap());
    }
    #[test]
    fn deployment_broker_signed_sealed_paths_cannot_escape_or_alias_target_namespace() {
        let target=deployment_target("target-a");let paths=Paths::for_target(&target,&target.layout.support_root.join("target.json")).unwrap();
        let config=SealedConfig{volume_device:"/dev/disk99s1".into(),source_mount:target.layout.cas_store_root.join("volume"),mount_root:paths.base.join("mounts")};
        paths.validate_sealed(&config).unwrap();
        for outside in ["/broker-deployment-fixtures/target-b/cas/volume","/opt/enterprise/enclave/cas/volume","/broker-deployment-fixtures/target-a/cas-sibling/volume","/broker-deployment-fixtures/target-a/support/config","/broker-deployment-fixtures/target-a/cas/../outside"] {
            for source in [false,true] {let mut bad=config.clone();if source{bad.source_mount=outside.into();}else{bad.mount_root=outside.into();}assert!(paths.validate_sealed(&bad).is_err());assert!(confinement_for(&paths,&[bad]).is_err());}
        }
        let mut alias_target=target;alias_target.layout.cas_store_root="/var/db/depot-broker-fixture/cas".into();
        let aliases=Paths::for_target(&alias_target,&alias_target.layout.support_root.join("target.json")).unwrap();
        let mut alias=config;alias.source_mount="/var/db/depot-broker-fixture/cas/volume".into();aliases.validate_sealed(&alias).unwrap();
        alias.mount_root="/private/var/db/depot-broker-fixture/cas/volume/child".into();assert!(aliases.validate_sealed(&alias).is_err());
    }
    #[derive(Debug)]
    struct Platform {calls:Mutex<Vec<&'static str>>,fail:&'static str,once:Mutex<Option<&'static str>>}
    impl Platform {fn step(&self,name:&'static str)->EnclaveResult<()> {self.calls.lock().unwrap().push(name);let once={let mut once=self.once.lock().unwrap();if *once==Some(name){once.take();true}else{false}};if once||self.fail==name||(self.fail=="flags-unmount"&&matches!(name,"flags"|"unmount")){fail!(EACCES,"FIXTURE_PLATFORM");}Ok(())}}
    impl SnapshotPlatform for Platform {
        fn validate_source(&self,_:&SealedConfig)->EnclaveResult<()>{self.step("source")}
        fn require_capacity(&self,_:&SealedConfig,_:u64)->EnclaveResult<()>{self.step("capacity")}
        fn enforce_holders(&self,file:&File,_:&str)->EnclaveResult<()> {assert!(file.metadata().unwrap().is_file());self.step("holders")}
        fn clone_stage(&self,stage:&File,destination:&Path)->EnclaveResult<()>{self.step("clone")?;let mut reader=stage.try_clone().unwrap();reader.seek(SeekFrom::Start(0)).unwrap();std::io::copy(&mut reader,&mut File::create(destination).unwrap()).unwrap();self.step("clone-after")}
        fn create_snapshot(&self,volume:&Path,name:&str)->EnclaveResult<()>{if self.fail=="foreign"||self.fail=="foreign-cleanup"{if self.fail=="foreign-cleanup"{let path=volume.join("artifacts").join(&name[4..]);std::fs::remove_file(&path).unwrap();std::fs::create_dir(path).unwrap();}return Err(err!(EACCES,"SEALED_SNAPSHOT_FOREIGN_EXISTS"));}self.step("snapshot")}
        fn mount_snapshot(&self,config:&SealedConfig,_:&str,mount:&Path)->EnclaveResult<()>{self.step("mount")?;std::fs::create_dir(mount.join("artifacts")).unwrap();for entry in std::fs::read_dir(config.source_mount.join("artifacts")).unwrap(){let entry=entry.unwrap();std::fs::copy(entry.path(),mount.join("artifacts").join(entry.file_name())).unwrap();}self.step("mount-after")}
        fn verify_mount(&self,_:&SealedConfig,_:&str,mount:&Path)->EnclaveResult<()>{self.step("flags")?;if !mount.join("artifacts").is_dir(){fail!(EACCES,"FIXTURE_NOT_MOUNTED");}Ok(())}
        fn cleanup_mount(&self,_:&SealedConfig,_:&str,mount:&Path)->EnclaveResult<()>{if mount.join("artifacts").exists(){self.unmount(mount)?;}Ok(())}
        fn unmount(&self,mount:&Path)->EnclaveResult<()>{self.step("unmount")?;std::fs::remove_dir_all(mount.join("artifacts")).unwrap();Ok(())}
        fn delete_snapshot(&self,_:&Path,_:&str)->EnclaveResult<()>{self.step("delete")}
    }
    struct Fixture {root:PathBuf,paths:Paths,repo:RepoBuilder,targets:BTreeMap<String,TargetFile>,platform:Arc<Platform>,config:SealedConfig}
    impl Fixture {
        fn new(fail:&'static str)->Self {
            let root=std::env::temp_dir().join(format!("mc-f38-root-broker-{:x}",enclave_core::rng::u64()));
            let paths=Paths{base:root.join("broker"),pin:root.join("root.json"),strict:false,target:None};
            for path in [&root,&paths.base,&paths.state(),&paths.base.join("tuf"),&paths.repo(),&root.join("source"),&root.join("mounts")] {std::fs::create_dir(path).unwrap();std::fs::set_permissions(path,std::fs::Permissions::from_mode(0o700)).unwrap();}
            let repo=RepoBuilder::new(3,2);std::fs::write(&paths.pin,repo.root(EXP).unwrap()).unwrap();std::fs::set_permissions(&paths.pin,std::fs::Permissions::from_mode(0o600)).unwrap();
            let config=SealedConfig{volume_device:"/dev/disk99s1".into(),source_mount:root.join("source"),mount_root:root.join("mounts")};
            let host=enclave_core::host_config::EnclaveHostConfig{profile_floor:enclave_core::profile::Profile::L3,ifc_grant_public_key:"ab".repeat(32),ohttp_key_config:None,calibration_corpus_digest:"ab".repeat(32),vk_digest:"ab".repeat(32),depot_lock_digest:"ab".repeat(32),fido_mds_allowlist_digest:"ab".repeat(32),codesign_pins:None};
            let host=serde_json::to_vec(&host).unwrap();
            let certificate=rcgen::generate_simple_self_signed(vec!["relay.test".into()]).unwrap();
            let gateway=ohttp_rfc::KeyConfig::derive(7,ohttp_rfc::hpke::Kem::X25519Sha256,vec![ohttp_rfc::SymmetricSuite::new(ohttp_rfc::hpke::Kdf::HkdfSha256,ohttp_rfc::hpke::Aead::ChaCha20Poly1305)],&[7;32]).unwrap();
            let distribution=crate::transport::registry::DistributionConfig{version:1,l1:None,l2:None,l3:Some(crate::transport::oblivious::ObliviousConfig{relay:crate::transport::registry::RegistryConfig{address:"127.0.0.1:1".into(),server_name:"relay.test".into(),repository:"fixture".into(),tls_roots_der:vec![hex::encode(certificate.serialize_der().unwrap())],timeout_ms:1000},gateway_config_hex:hex::encode(gateway.encode().unwrap()),required_kem:0x20,gateway_authority:"gateway.test".into(),quantum:65536,sealed:config.clone()})};
            let distribution=serde_json::to_vec(&distribution).unwrap();
            let mut targets=BTreeMap::new();for (name,bytes) in [(enclave_core::host_config::HOST_CONFIG_TARGET,host),(crate::transport::registry::DISTRIBUTION_CONFIG_TARGET,distribution)]{std::fs::write(paths.repo().join(name),&bytes).unwrap();targets.insert(name.into(),target_file(&bytes,None));}
            targets.insert("model.bin".into(),target_file(PAYLOAD,Some(serde_json::json!({"classification":"restricted_l3","min_profile":"L3"}))));
            let fixture=Self{root,paths,repo,targets,platform:Arc::new(Platform{calls:Mutex::new(vec![]),fail,once:Mutex::new(None)}),config};fixture.metadata(1,&fixture.targets,EXP);fixture
        }
        fn metadata(&self,version:u64,targets:&BTreeMap<String,TargetFile>,expiry:&str){let targets=self.repo.targets(version,expiry,targets.clone()).unwrap();let snapshot=self.repo.snapshot(version,expiry,version,&targets).unwrap();let timestamp=self.repo.timestamp(version,expiry,version,&snapshot).unwrap();for (name,bytes) in [("targets.json",targets),("snapshot.json",snapshot),("timestamp.json",timestamp)]{std::fs::write(self.paths.repo().join(name),bytes).unwrap();}}
        fn broker(&self)->Broker {Broker::open(self.paths.clone(),ipc::geteuid(),self.platform.clone()).unwrap()}
        fn root_hash(&self)->String {self.targets["model.bin"].hashes["blake3"].clone()}
        fn stage(&self,bytes:&[u8])->File {let path=self.root.join(format!("input-{:x}",enclave_core::rng::u64()));std::fs::write(&path,bytes).unwrap();File::open(path).unwrap()}
        fn publish(&self,broker:&mut Broker)->EnclaveResult<Option<File>> {broker.execute(Request::Publish{root:self.root_hash()},Some(self.stage(PAYLOAD)))}
    }
    // Explicit software routing injection only; this never constructs a checked
    // deployment capability, selects process context, or changes native policy.
    fn isolated_fixture_paths(f:&Fixture)->Paths {
        let mut paths=f.paths.clone();paths.target=Some(TargetPaths{socket:f.root.join("run/broker.sock"),supervisor:f.root.join("run/supervisor.sock"),
            cas:f.root.join("allowed-cas"),binary_dir:f.root.join("bin"),public_inputs:vec![]});paths
    }
    #[test]
    fn deployment_broker_selected_namespace_signed_publish_reopen_revoke_progress() {
        let mut f=Fixture::new("");
        let source=f.paths.base.join("volume");let mounts=f.paths.base.join("mounts");
        std::fs::rename(&f.config.source_mount,&source).unwrap();std::fs::rename(&f.config.mount_root,&mounts).unwrap();
        f.config.source_mount=source;f.config.mount_root=mounts;
        let name=crate::transport::registry::DISTRIBUTION_CONFIG_TARGET;
        let mut distribution:crate::transport::registry::DistributionConfig=serde_json::from_slice(&std::fs::read(f.paths.repo().join(name)).unwrap()).unwrap();
        distribution.l3.as_mut().unwrap().sealed=f.config.clone();let bytes=serde_json::to_vec(&distribution).unwrap();
        std::fs::write(f.paths.repo().join(name),&bytes).unwrap();f.targets.insert(name.into(),target_file(&bytes,None));f.metadata(2,&f.targets,EXP);
        let mut broker=Broker::open(isolated_fixture_paths(&f),ipc::geteuid(),f.platform.clone()).unwrap();
        let published=f.publish(&mut broker).unwrap().unwrap();crate::snapshot_publication::verify_file(&published,&f.targets["model.bin"]).unwrap();drop(published);
        let reopened=broker.execute(Request::Reopen{root:f.root_hash()},None).unwrap().unwrap();crate::snapshot_publication::verify_file(&reopened,&f.targets["model.bin"]).unwrap();drop(reopened);
        assert!(broker.state.records[&f.root_hash()].complete);broker.execute(Request::Revoke{root:f.root_hash()},None).unwrap();assert!(broker.state.records.is_empty());
    }
    #[test]
    fn deployment_broker_signed_escape_refuses_before_platform_and_retains_tuf_floor() {
        let f=Fixture::new("");let mut broker=Broker::open(isolated_fixture_paths(&f),ipc::geteuid(),f.platform.clone()).unwrap();
        assert!(broker.refresh().unwrap_err().is("BROKER_DEPLOYMENT_SEALED_SCOPE"));
        assert!(broker.state.trust.is_some());assert!(f.platform.calls.lock().unwrap().is_empty());assert!(broker.state.records.is_empty());
    }
    #[test]
    fn deployment_broker_restart_refuses_escaping_record_or_stage_intent_before_cleanup() {
        for record in [false,true] {
            let f=Fixture::new("");let mut broker=f.broker();
            if record{drop(f.publish(&mut broker).unwrap());}else{broker.state.stage_intent=Some(f.config.clone());broker.save().unwrap();}
            drop(broker);f.platform.calls.lock().unwrap().clear();
            let result=Broker::open(isolated_fixture_paths(&f),ipc::geteuid(),f.platform.clone());
            assert!(result.err().unwrap().is("BROKER_DEPLOYMENT_SEALED_SCOPE"));
            assert!(f.platform.calls.lock().unwrap().is_empty());
            if record{assert!(f.config.mount_root.join(f.root_hash()).join("artifacts").join(f.root_hash()).exists());}
        }
    }
    impl Drop for Fixture {fn drop(&mut self){let _=std::fs::remove_dir_all(&self.root);}}
    #[test]
    fn phase1_holder_failure_lost_reply_and_post_unmount_restart_preserve_progress() {
        for failure in ["holders","unmount","delete"] {
            let f=Fixture::new("");let mut broker=f.broker();drop(f.publish(&mut broker).unwrap());
            *f.platform.once.lock().unwrap()=Some(failure);
            assert!(broker.execute(Request::Revoke{root:f.root_hash()},None).is_err());
            let record=&broker.state.records[&f.root_hash()];assert!(record.retracting);assert!(record.owned_snapshot);
            assert_eq!(record.holders_released,failure!="holders");
            let mounted=f.config.mount_root.join(f.root_hash()).join("artifacts");assert_eq!(mounted.exists(),failure!="delete");
            assert!(broker.execute(Request::Prepare{root:f.root_hash()},None).unwrap_err().is("BROKER_RETRACTION_PENDING"));
            drop(broker);let mut broker=f.broker();
            // Revoked/expired current authority cannot erase original cleanup
            // authority. Persisted holder progress survives a vanished mount.
            f.metadata(2,&f.targets,"2020-01-01T00:00:00Z");
            broker.execute(Request::Revoke{root:f.root_hash()},None).unwrap();assert!(broker.state.records.is_empty());
            let calls=f.platform.calls.lock().unwrap();assert_eq!(calls.iter().filter(|name|**name=="holders").count(),if failure=="holders"{2}else{1});
        }
    }
    #[test]
    fn phase1_lost_revoke_reply_is_idempotent_and_missing_unproved_identity_refuses() {
        let f=Fixture::new("");let mut broker=f.broker();drop(f.publish(&mut broker).unwrap());
        let mounted=f.config.mount_root.join(f.root_hash()).join("artifacts");std::fs::remove_dir_all(&mounted).unwrap();
        assert!(broker.execute(Request::Revoke{root:f.root_hash()},None).unwrap_err().is("BROKER_HOLDER_IDENTITY_UNAVAILABLE"));
        assert!(!broker.state.records[&f.root_hash()].holders_released);assert!(!f.platform.calls.lock().unwrap().contains(&"delete"));
        drop(broker);
        let f=Fixture::new("");let mut broker=f.broker();drop(f.publish(&mut broker).unwrap());let (a,mut b)=UnixStream::pair().unwrap();
        ipc::write_frame(&mut b,&ipc::to_cbor(&Request::Revoke{root:f.root_hash()}).unwrap()).unwrap();ipc::send_fd_packet(&b,&[]).unwrap();
        // Preserve request delivery, then observe loss at the caller. Darwin
        // may accept a write to a peer whose read half is already closed.
        b.shutdown(std::net::Shutdown::Read).unwrap();
        let _delivery=connection(a,&mut broker,|_|Ok(()));
        assert!(ipc::read_frame(&mut b).is_err());assert!(broker.state.records.is_empty());drop(b);drop(broker);
        let mut broker=f.broker();assert!(broker.execute(Request::Revoke{root:f.root_hash()},None).unwrap().is_none());
    }
    #[test]
    fn f38_broker_private_copy_exact_readonly_and_lost_reply_restart_reopen(){let f=Fixture::new("");let mut broker=f.broker();let file=f.publish(&mut broker).unwrap().unwrap();drop(file);assert!(broker.state.records[&f.root_hash()].complete);assert!(Broker::open(f.paths.clone(),ipc::geteuid(),f.platform.clone()).is_err());drop(broker);let mut broker=f.broker();let mut file=broker.execute(Request::Reopen{root:f.root_hash()},None).unwrap().unwrap();let mut bytes=vec![];file.read_to_end(&mut bytes).unwrap();assert_eq!(bytes,PAYLOAD);assert!(file.write_all(b"x").is_err());assert!(std::fs::read_dir(&f.paths.base).unwrap().all(|e|!e.unwrap().file_name().to_string_lossy().starts_with("stage-")));}
    #[test]
    fn f38_broker_revocation_and_expiry_preserve_original_cleanup_authority(){let f=Fixture::new("");let mut broker=f.broker();f.publish(&mut broker).unwrap();drop(broker);let mut targets=f.targets.clone();targets.get_mut("model.bin").unwrap().custom.as_mut().unwrap()["revoked"]=true.into();f.metadata(2,&targets,"2020-01-01T00:00:00Z");let mut broker=f.broker();assert!(broker.execute(Request::Reopen{root:f.root_hash()},None).is_err());assert!(broker.execute(Request::Revoke{root:f.root_hash()},None).unwrap().is_none());assert!(broker.state.records.is_empty());assert!(!f.config.source_mount.join("artifacts").join(f.root_hash()).exists());}
    #[test]
    fn f38_broker_rejects_mutable_special_wrong_length_digest_and_invalid_roots() {
        let f = Fixture::new(""); let mut broker = f.broker();
        for root in ["../x".into(), "AB".repeat(32), "0".repeat(64)] {
            assert!(broker.execute(Request::Publish {root}, Some(f.stage(PAYLOAD))).is_err());
        }
        let path = f.root.join("writable"); std::fs::write(&path, PAYLOAD).unwrap();
        let writable = File::options().read(true).write(true).open(path).unwrap();
        #[cfg(target_os = "linux")]
        let special = if std::env::var_os("depot_PHASE1_NULL_STDIN").as_deref() == Some(std::ffi::OsStr::new("1")) {
            // The isolated recorder opens the real device before entering its
            // child chroot. Duplicate that inherited FD, never a fake file.
            use std::os::unix::fs::FileTypeExt;
            let fd = unsafe { libc::fcntl(libc::STDIN_FILENO, libc::F_DUPFD_CLOEXEC, 3) };
            assert!(fd >= 0);
            let file = unsafe { File::from_raw_fd(fd) };
            assert!(file.metadata().unwrap().file_type().is_char_device());
            assert_eq!(unsafe { libc::fcntl(fd, libc::F_GETFL) } & libc::O_ACCMODE, libc::O_RDONLY);
            file
        } else { File::open("/dev/null").unwrap() };
        #[cfg(not(target_os = "linux"))]
        let special = File::open("/dev/null").unwrap();
        for stage in [writable, special, f.stage(b"short"), f.stage(&vec![b'X'; PAYLOAD.len()])] {
            assert!(broker.execute(Request::Publish {root: f.root_hash()}, Some(stage)).is_err());
        }
        assert!(!f.platform.calls.lock().unwrap().contains(&"clone"));
        assert!(broker.state.records.is_empty());
    }
    #[test]
    fn f38_broker_signed_alias_and_non_l3_refuse_before_effects(){let f=Fixture::new("");let mut targets=f.targets.clone();let mut alias=targets["model.bin"].clone();alias.custom.as_mut().unwrap()["different"]=true.into();targets.insert("alias.bin".into(),alias);f.metadata(2,&targets,EXP);let mut broker=f.broker();assert!(f.publish(&mut broker).is_err());drop(broker);targets=f.targets.clone();targets.get_mut("model.bin").unwrap().custom.as_mut().unwrap()["min_profile"]="L2".into();f.metadata(3,&targets,EXP);let mut broker=f.broker();assert!(f.publish(&mut broker).is_err());assert!(!f.platform.calls.lock().unwrap().contains(&"clone"));}
    #[test]
    fn f38_broker_pending_intent_restart_cleanup_and_retry(){let f=Fixture::new("");let mut broker=f.broker();f.publish(&mut broker).unwrap();broker.state.records.get_mut(&f.root_hash()).unwrap().complete=false;broker.save().unwrap();drop(broker);let mut broker=f.broker();assert!(f.publish(&mut broker).unwrap().is_some());assert!(f.platform.calls.lock().unwrap().contains(&"unmount"));}
    #[test]
    fn f38_broker_platform_partial_failure_cleanup_never_returns_descriptor(){for fail in ["clone-after","mount-after","flags"]{let f=Fixture::new(fail);let mut broker=f.broker();assert!(f.publish(&mut broker).is_err(),"{fail}");assert!(broker.state.records.is_empty(),"{fail}");assert!(!f.config.source_mount.join("artifacts").join(f.root_hash()).exists(),"{fail}");}}
    #[test]
    fn f38_broker_corrupt_persistence_and_public_symlink_refuse(){let f=Fixture::new("");let mut broker=f.broker();broker.refresh().unwrap();drop(broker);std::fs::write(f.paths.state().join("apfs-publications.sealed"),b"corrupt").unwrap();assert!(Broker::open(f.paths.clone(),ipc::geteuid(),f.platform.clone()).is_err());let f=Fixture::new("");std::fs::remove_file(f.paths.repo().join("timestamp.json")).unwrap();std::os::unix::fs::symlink(&f.paths.pin,f.paths.repo().join("timestamp.json")).unwrap();assert!(f.broker().refresh().is_err());}
    #[test]
    fn f38_broker_request_boundary_preauth_unknown_trailing_and_oversize(){let f=Fixture::new("");let mut broker=f.broker();let (a,_b)=UnixStream::pair().unwrap();let begin=Instant::now();assert!(connection(a,&mut broker,|_|Err(err!(EACCES,"FIXTURE_DENY"))).unwrap_err().is("FIXTURE_DENY"));assert!(begin.elapsed()<Duration::from_secs(1));for bytes in [vec![0;FRAME+1],b"garbage".to_vec(),{let mut b=ipc::to_cbor(&Request::Reopen{root:f.root_hash()}).unwrap();b.push(0);b},ipc::to_cbor(&serde_json::json!({"Reopen":{"root":f.root_hash(),"path":"/"}})).unwrap()]{let (a,mut b)=UnixStream::pair().unwrap();ipc::write_frame(&mut b,&bytes).unwrap();assert!(connection(a,&mut broker,|_|Ok(())).is_err());}}
    #[test]
    fn f38_broker_ipc_exact_fd_and_unexpected_fd_refusal(){let f=Fixture::new("");let mut broker=f.broker();let root=f.root_hash();let (a,mut b)=UnixStream::pair().unwrap();let request=ipc::to_cbor(&Request::Publish{root:root.clone()}).unwrap();ipc::write_frame(&mut b,&request).unwrap();let stage=f.stage(PAYLOAD);ipc::send_fd_packet(&b,&[stage.as_raw_fd()]).unwrap();connection(a,&mut broker,|_|Ok(())).unwrap();let reply:ipc::Reply<Response>=ipc::from_cbor(&ipc::read_frame(&mut b).unwrap()).unwrap();assert!(matches!(reply,ipc::Reply::Ok(Response::Descriptor)));let fds=ipc::recv_fds(&b,1).unwrap();let mut bytes=vec![];File::from(fds.into_iter().next().unwrap()).read_to_end(&mut bytes).unwrap();assert_eq!(bytes,PAYLOAD);let (a,mut b)=UnixStream::pair().unwrap();ipc::write_frame(&mut b,&ipc::to_cbor(&Request::Reopen{root}).unwrap()).unwrap();ipc::send_fds(&b,&[stage.as_raw_fd()]).unwrap();assert!(connection(a,&mut broker,|_|Ok(())).is_err());}
    #[test]
    fn f38_broker_confinement_has_no_internet_or_generic_exec_and_rejects_profile_injection(){let f=Fixture::new("");let text=confinement(&[f.config.clone()]).unwrap();assert!(text.contains("(deny default)"));assert!(!text.contains("remote tcp"));assert!(!text.contains("remote udp"));assert_eq!(text.lines().filter(|line|line.contains("network-outbound")).collect::<Vec<_>>(),vec!["(allow network-outbound (remote unix-socket (literal \"/private/var/run/enclave/supervisor/held-v1.sock\")))"]);assert!(text.contains("(allow process-exec (literal \"/sbin/mount_apfs\"))"));let mut unsafe_config=f.config.clone();unsafe_config.mount_root=f.root.join("quote\"injection");assert!(confinement(&[unsafe_config]).is_err());}
    #[test]
    fn f38_broker_delete_both_persistence_files_never_reinitializes_and_idle_checks_owned_records(){let f=Fixture::new("");let mut broker=f.broker();assert!(inspect_idle(&f.paths,ipc::geteuid()).is_ok());f.publish(&mut broker).unwrap();assert!(inspect_idle(&f.paths,ipc::geteuid()).is_err());broker.execute(Request::Revoke{root:f.root_hash()},None).unwrap();assert!(inspect_idle(&f.paths,ipc::geteuid()).is_ok());drop(broker);for name in ["apfs-publications.sealed","apfs-publications.gen"]{std::fs::remove_file(f.paths.state().join(name)).unwrap();}assert!(Broker::open(f.paths.clone(),ipc::geteuid(),f.platform.clone()).is_err());assert!(inspect_idle(&f.paths,ipc::geteuid()).is_err());}

    #[test]
    fn f38_broker_absent_revoke_is_idempotent_and_does_not_skip_owned_later_root(){let f=Fixture::new("");let mut broker=f.broker();f.publish(&mut broker).unwrap();assert!(broker.execute(Request::Revoke{root:"0".repeat(64)},None).unwrap().is_none());assert_eq!(broker.state.records.len(),1);broker.execute(Request::Revoke{root:f.root_hash()},None).unwrap();assert!(broker.state.records.is_empty());assert!(broker.execute(Request::Revoke{root:f.root_hash()},None).is_ok());}

    #[test]
    #[cfg(target_os="macos")]
    fn _f38_broker_confinement_worker(){let Some(input)=std::env::var_os("depot_PRIVATE_BROKER_SANDBOX")else{return;};let config:SealedConfig=serde_json::from_slice(&std::fs::read(&input).unwrap()).unwrap();apply_confinement(&confinement(&[config.clone()]).unwrap()).unwrap();std::fs::write(config.source_mount.join("allowed"),b"owned inert child").unwrap();assert!(std::fs::write(config.source_mount.parent().unwrap().join("forbidden"),b"denied").is_err());assert!(std::process::Command::new("/usr/bin/true").status().is_err());}
    #[test]
    #[cfg(target_os="macos")]
    fn f38_broker_actual_darwin_confinement_allows_private_route_and_denies_sibling_and_exec(){let f=Fixture::new("");let input=f.root.join("sandbox-input.json");std::fs::write(&input,serde_json::to_vec(&f.config).unwrap()).unwrap();let mut child=std::process::Command::new(std::env::current_exe().unwrap()).args(["--exact","snapshot_broker::tests::_f38_broker_confinement_worker","--nocapture"]).env("depot_PRIVATE_BROKER_SANDBOX",input).spawn().unwrap();let deadline=Instant::now()+Duration::from_secs(10);loop{match child.try_wait().unwrap(){Some(status)=>{assert!(status.success());break},None if Instant::now()<deadline=>std::thread::sleep(Duration::from_millis(10)),None=>{child.kill().unwrap();let _=child.wait();panic!("owned confinement child deadline");}}}assert_eq!(std::fs::read(f.config.source_mount.join("allowed")).unwrap(),b"owned inert child");assert!(!f.root.join("forbidden").exists());}

    #[test]
    fn f38_broker_quiescence_barrier_refuses_active_operation_and_blocks_queued_effects(){let f=Fixture::new("");let mut broker=f.broker();let active=Operation::acquire(broker.operation.try_clone().unwrap()).unwrap();assert!(quiesce(&f.paths,ipc::geteuid()).unwrap_err().is("BROKER_OPERATION_BUSY"));assert!(!f.paths.base.join("deployment.quiesced").exists());drop(active);quiesce(&f.paths,ipc::geteuid()).unwrap();assert!(f.publish(&mut broker).unwrap_err().is("BROKER_QUIESCED"));assert!(!f.platform.calls.lock().unwrap().contains(&"clone"));}

    #[test]
    fn f38_broker_fresh_pins_refuse_missing_stale_foreign_and_malformed_in_both_identity_modes(){use enclave_core::codesign::{pins,CodeIdentity};let id=IDENTIFIER;let old="ab".repeat(20);let fresh="cd".repeat(20);let manifest=|hash:&str|pins::parse(serde_json::to_vec(&serde_json::json!({"v":1,"pins":{id:[hash]}})).unwrap().as_slice()).unwrap();for team in ["","TESTTEAM"]{let mut requirement=CodeRequirement::pinned_from_manifest(id,&manifest(&old)).unwrap();requirement.team_id=team.into();let old_id=CodeIdentity{identifier:id.into(),team_id:team.into(),cdhash:old.clone()};assert!(requirement.matches(&old_id));let mut rotated=CodeRequirement::pinned_from_manifest(id,&manifest(&fresh)).unwrap();rotated.team_id=team.into();assert!(!rotated.matches(&old_id));let mut current=old_id.clone();current.cdhash=fresh.clone();assert!(rotated.matches(&current));current.identifier="com.foreign.helper".into();assert!(!rotated.matches(&current));}assert!(CodeRequirement::pinned_from_manifest(id,&BTreeMap::new()).is_err());for bytes in [b"garbage".to_vec(),br#"{"v":1,"pins":{"bad":["short"]}}"#.to_vec(),br#"{"v":1,"pins":{"bad":[]}}"#.to_vec(),vec![0;1024*1024+1]]{assert!(pins::parse(&bytes).is_err());}}

    #[test]
    fn f38_broker_real_lost_reply_retains_durable_owned_result_for_restart(){let f=Fixture::new("");let mut broker=f.broker();let (a,mut b)=UnixStream::pair().unwrap();ipc::write_frame(&mut b,&ipc::to_cbor(&Request::Publish{root:f.root_hash()}).unwrap()).unwrap();let stage=f.stage(PAYLOAD);ipc::send_fds(&b,&[stage.as_raw_fd()]).unwrap();b.shutdown(std::net::Shutdown::Read).unwrap();assert!(connection(a,&mut broker,|_|Ok(())).is_err());drop(b);assert!(broker.state.records[&f.root_hash()].complete);drop(broker);let mut broker=f.broker();assert!(broker.execute(Request::Reopen{root:f.root_hash()},None).unwrap().is_some());broker.execute(Request::Revoke{root:f.root_hash()},None).unwrap();}
    #[test]
    fn f38_broker_quiescence_serializes_with_real_accepted_connection(){let f=Fixture::new("");let mut broker=f.broker();let (a,b)=UnixStream::pair().unwrap();let (entered_tx,entered_rx)=std::sync::mpsc::channel();let (release_tx,release_rx)=std::sync::mpsc::channel();let thread=std::thread::spawn(move||connection(a,&mut broker,|_|{entered_tx.send(()).unwrap();release_rx.recv_timeout(Duration::from_secs(2)).unwrap();Ok(())}));entered_rx.recv_timeout(Duration::from_secs(2)).unwrap();assert!(quiesce(&f.paths,ipc::geteuid()).unwrap_err().is("BROKER_OPERATION_BUSY"));drop(b);release_tx.send(()).unwrap();assert!(thread.join().unwrap().is_err());quiesce(&f.paths,ipc::geteuid()).unwrap();assert!(f.paths.base.join("deployment.quiesced").exists());}

    #[test]
    fn f38_broker_lifecycle_is_bounded_and_omits_payload_and_error_details(){let f=Fixture::new("");let broker=f.broker();let error:EnclaveResult<Option<File>>=Err(enclave_core::error::EnclaveError::with(enclave_core::error::Errno::EIO,"FIXTURE_FAILURE","sensitive fixture detail"));for _ in 0..1000{broker.lifecycle("publish",&f.root_hash(),&error).unwrap();}let current=std::fs::read(f.paths.base.join("lifecycle.log")).unwrap();let previous=std::fs::read(f.paths.base.join("lifecycle.previous.log")).unwrap();assert!(current.len()<=64*1024&&previous.len()<=64*1024);for bytes in [current,previous]{let text=String::from_utf8(bytes).unwrap();assert!(text.contains("reason=FIXTURE_FAILURE"));assert!(!text.contains("sensitive fixture detail"));assert!(!text.contains(std::str::from_utf8(PAYLOAD).unwrap()));}}

    #[test]
    fn f38_broker_connection_backlog_is_bounded_before_authentication() {
        use std::os::fd::AsRawFd;
        let f = Fixture::new("");
        let absolute = f.root.join("queue.sock");
        // Keep the same private inode/config fixture while avoiding Darwin's
        // sockaddr_un length limit when TMPDIR is an exact runner checkout.
        let cwd = std::env::current_dir().unwrap();
        let socket = absolute.strip_prefix(&cwd).unwrap_or(&absolute);
        let listener = std::os::unix::net::UnixListener::bind(socket).unwrap();
        assert_eq!(unsafe { libc::listen(listener.as_raw_fd(), 1) }, 0);
        let mut held = Vec::new(); let mut refused = false; let start = Instant::now();
        for _ in 0..16 {
            match ipc::Client::connect_verified_deadline(socket, ipc::geteuid(), None, Duration::from_millis(25)) {
                Ok(client) => held.push(client),
                Err(error) => {
                    assert!(!held.is_empty(), "private listener must accept positive-control connections");
                    assert!(error.is("IPC_CONNECT_DEADLINE") || error.is("IPC_CONNECT"), "{error}");
                    refused = true; break;
                },
            }
        }
        assert!(refused); assert!(start.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn f38_broker_ambiguous_create_or_crash_never_authorizes_snapshot_delete_after_restart(){let f=Fixture::new("snapshot");let mut broker=f.broker();assert!(f.publish(&mut broker).is_err());assert!(!broker.state.records[&f.root_hash()].owned_snapshot);drop(broker);let mut broker=f.broker();assert!(broker.execute(Request::Revoke{root:f.root_hash()},None).unwrap_err().is("BROKER_SNAPSHOT_OWNERSHIP_UNCERTAIN"));assert!(f.publish(&mut broker).unwrap_err().is("BROKER_SNAPSHOT_OWNERSHIP_UNCERTAIN"));assert!(!f.platform.calls.lock().unwrap().contains(&"delete"));assert!(broker.state.records.contains_key(&f.root_hash()));}
    #[test]
    fn f38_broker_foreign_snapshot_collision_is_untouched_on_retry_restart_and_revoke(){let f=Fixture::new("foreign");let mut broker=f.broker();for _ in 0..2{assert!(f.publish(&mut broker).unwrap_err().is("SEALED_SNAPSHOT_FOREIGN_EXISTS"));assert!(broker.state.records.is_empty());}drop(broker);let mut broker=f.broker();assert!(broker.execute(Request::Revoke{root:f.root_hash()},None).is_ok());assert!(!f.platform.calls.lock().unwrap().contains(&"delete"));}
    #[test]
    fn f38_broker_unjournaled_existing_mount_or_artifact_is_never_adopted(){for mount in [false,true]{let f=Fixture::new("");if mount{std::fs::create_dir(f.config.mount_root.join(f.root_hash())).unwrap();}else{std::fs::create_dir(f.config.source_mount.join("artifacts")).unwrap();std::fs::write(f.config.source_mount.join("artifacts").join(f.root_hash()),PAYLOAD).unwrap();}let mut broker=f.broker();assert!(f.publish(&mut broker).unwrap_err().is("BROKER_UNOWNED_PUBLICATION"));assert!(broker.state.records.is_empty());assert!(!f.platform.calls.lock().unwrap().contains(&"clone"));}}

    #[test]
    fn f38_broker_foreign_collision_cleanup_failure_retains_no_delete_authority_across_restart(){let f=Fixture::new("foreign-cleanup");let mut broker=f.broker();assert!(f.publish(&mut broker).is_err());assert!(!broker.state.records[&f.root_hash()].owned_snapshot);drop(broker);let mut broker=f.broker();assert!(broker.execute(Request::Revoke{root:f.root_hash()},None).unwrap_err().is("BROKER_SNAPSHOT_OWNERSHIP_UNCERTAIN"));assert!(f.publish(&mut broker).is_err());assert!(!f.platform.calls.lock().unwrap().contains(&"delete"));assert!(broker.state.records.contains_key(&f.root_hash()));}

    #[test]
    fn f38_broker_proved_owned_incomplete_cleanup_survives_restart_and_original_authority_revoke(){let f=Fixture::new("flags-unmount");let mut broker=f.broker();assert!(f.publish(&mut broker).is_err());assert!(broker.state.records[&f.root_hash()].owned_snapshot);assert!(!broker.state.records[&f.root_hash()].complete);drop(broker);f.metadata(2,&f.targets,"2020-01-01T00:00:00Z");let healthy=Arc::new(Platform{calls:Mutex::new(vec![]),fail:"",once:Mutex::new(None)});let mut broker=Broker::open(f.paths.clone(),ipc::geteuid(),healthy.clone()).unwrap();assert!(broker.state.records[&f.root_hash()].owned_snapshot);broker.execute(Request::Revoke{root:f.root_hash()},None).unwrap();assert!(broker.state.records.is_empty());assert!(healthy.calls.lock().unwrap().contains(&"delete"));}
    #[test]
    fn f38_broker_tuf_rollback_floor_persists_and_foreign_bootstrap_pin_refuses(){let f=Fixture::new("");let mut broker=f.broker();f.metadata(2,&f.targets,EXP);broker.refresh().unwrap();drop(broker);f.metadata(1,&f.targets,EXP);let mut broker=f.broker();assert!(f.publish(&mut broker).is_err());assert!(!f.platform.calls.lock().unwrap().contains(&"clone"));let foreign=RepoBuilder::new(3,2).root(EXP).unwrap();std::fs::write(&f.paths.pin,foreign).unwrap();assert!(broker.refresh().unwrap_err().is("BROKER_BOOTSTRAP_PIN"));}
    #[test]
    fn f38_broker_independent_l3_quorum_and_root_replica_inventory_are_bounded(){let mut f=Fixture::new("");f.repo=RepoBuilder::new(3,1);std::fs::write(&f.paths.pin,f.repo.root(EXP).unwrap()).unwrap();f.metadata(1,&f.targets,EXP);let mut broker=f.broker();assert!(broker.refresh().unwrap_err().is("BROKER_PUBLISHER_QUORUM"));drop(broker);let f=Fixture::new("");for index in 1..=33{std::fs::write(f.paths.repo().join(format!("{index}.root.json")),b"unused").unwrap();}assert!(f.broker().refresh().is_err());}

    #[test]
    fn f38_broker_failed_state_capacity_preserves_durable_records_and_poisons_new_effects(){let f=Fixture::new("");let mut broker=f.broker();let before=std::fs::read(f.paths.state().join("apfs-publications.sealed")).unwrap();assert!(broker.save_with_limit(1).unwrap_err().is("BROKER_STATE_SIZE"));assert!(broker.poisoned);assert_eq!(std::fs::read(f.paths.state().join("apfs-publications.sealed")).unwrap(),before);assert!(f.publish(&mut broker).unwrap_err().is("BROKER_STATE_RESTART_REQUIRED"));assert!(!f.platform.calls.lock().unwrap().contains(&"clone"));}

    // Actual connection/SCM_RIGHTS matrix; all support remains cfg(test).
    include!("snapshot_broker_connection_tests.rs");

    mod administrative_tests {include!("snapshot_broker_admin_tests.rs");}

}
