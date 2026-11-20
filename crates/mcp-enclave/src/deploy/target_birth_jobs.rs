//! Fixed create-only job publication with the SAME genuine metadata birth.
//! External job names are visible and may affect later login/boot discovery.
//! Root0700 and inhibition remain mandatory; neither proves launchd inactivity.
//! No launchctl, start, root visibility, denial clear, rollback or repair exists.
use super::*;

#[path="target_birth_visibility.rs"]
mod visibility;

const JOB_ROLES:[&str;11]=["adapter","cas","custody","ifc","zk","supervisor","intent",
    "oidc-broker","hydrate","browser","gateway"];
const DAEMONS:&str="/Library/LaunchDaemons";
const AGENTS:&str="/Library/LaunchAgents";
const MAX_JOB_BYTES:u64=1024*1024;
const MAX_JOB_TOTAL:u64=11*MAX_JOB_BYTES;

#[derive(Clone)]
struct JobSpec {source:PathBuf,destination:PathBuf,pending:PathBuf,size:u64,sha256:String}
struct JobsPlan {copies:Vec<JobSpec>}
impl JobsPlan {
    fn build(state:&BirthState,approved:&TargetInstallPlan)->EnclaveResult<Self> {
        plan_binding(state,approved)?;metadata::hidden_root(state)?;
        if state.plan.target.signing_identity_mode!=DeploymentSigningMode::LocalPins {
            fail!(EACCES,"BIRTH_JOBS_LOCAL_PINS_REQUIRED");
        }
        let token=state.plan.root.file_name().and_then(|s|s.to_str()).unwrap_or("");
        let namespace=&state.plan.target.layout.launchd_namespace;
        if !lower_hex(token,32)||state.plan.target.target_id!=format!("ykft-{token}")
            ||namespace!=&format!("com.enterprise.enclave.ykft.n{token}") {
            fail!(EACCES,"BIRTH_JOBS_ALLOCATED_NAMESPACE_REQUIRED");
        }
        let staging=state.plan.target.layout.staging_root.join("launchd");
        let mut copies=Vec::new();let mut total=0u64;let mut names=BTreeSet::new();
        for role in JOB_ROLES {
            let leaf=format!("{namespace}.{role}.plist");
            let parent=Path::new(if ["intent","oidc-broker"].contains(&role){AGENTS}else{DAEMONS});
            let destination=parent.join(&leaf);let source=staging.join(&leaf);
            // A launchd-discoverable final name never contains partial bytes.
            let pending=parent.join(format!(".depot-birth-{namespace}.{role}.pending"));
            let mut matching=approved.copies.iter().filter(|copy|copy.source==source||copy.destination==destination);
            let copy=matching.next().ok_or_else(||err!(EACCES,"BIRTH_JOBS_REQUIRED_ROLE"))?;
            if matching.next().is_some()||copy.source!=source||copy.destination!=destination
                ||copy.uid!=0||copy.gid!=0||copy.mode!="0644"||copy.size==0||copy.size>MAX_JOB_BYTES
                ||!lower_hex(&copy.sha256,64) {fail!(EACCES,"BIRTH_JOBS_FIXED_MAPPING");}
            for path in [&source,&destination,&pending] {exact_path(path)?;}
            for path in [&destination,&pending] {
                if !names.insert(folded(path)?)||path.file_name().is_none_or(|n|n.as_bytes().len()>255) {
                    fail!(EINVAL,"BIRTH_JOBS_NAME_ALIAS");
                }
                if overlaps(path,&state.plan.root)? {fail!(EACCES,"BIRTH_JOBS_BIRTH_ROOT_ALIAS");}
                for original in state.files.keys() {
                    if overlaps(path,original)? {fail!(EACCES,"BIRTH_JOBS_ORIGINAL_ALIAS");}
                }
                // Original external ancestors such as / and /Library are
                // legitimate retained observations. An output cannot itself
                // alias or contain an original retained directory.
                let folded_output=folded(path)?;
                for original in state.dirs.keys() {
                    // The genuine cached filesystem root is an allowed
                    // ancestor, while normalized_path deliberately refuses
                    // '/' for selectable paths. Skip only that exact node.
                    if original.as_path()==Path::new("/"){continue;}
                    if folded(original)?.starts_with(&folded_output) {fail!(EACCES,"BIRTH_JOBS_ORIGINAL_ALIAS");}
                }
            }
            total=total.checked_add(copy.size).ok_or_else(||err!(E2BIG,"BIRTH_JOBS_TOTAL_BOUND"))?;
            let spec=JobSpec {source,destination,pending,size:copy.size,sha256:copy.sha256.clone()};
            job_source(state,&spec)?.current(&spec,true)?;copies.push(spec);
        }
        if total>MAX_JOB_TOTAL {fail!(E2BIG,"BIRTH_JOBS_TOTAL_BOUND");}
        for copy in &approved.copies {
            let destination=folded(&copy.destination)?;
            if ["/library/launchdaemons","/library/launchagents"].iter().any(|parent|destination.starts_with(parent))
                &&!copies.iter().any(|job|job.source==copy.source&&job.destination==copy.destination) {
                fail!(EACCES,"BIRTH_JOBS_UNKNOWN_EXTERNAL_COPY");
            }
        }
        copies.sort_by(|a,b|a.destination.cmp(&b.destination));Ok(Self {copies})
    }
    // Independent file-only gate for the later actual visibility descendant.
    // This supplies no directory event acceptance or root-mode authority.
    fn sources_current(&self,state:&BirthState,full:bool)->Vec<EnclaveError> {
        let mut observed=Vec::new();
        for spec in &self.copies {observed.extend(errors([job_source(state,spec).and_then(|source|source.current(spec,full))]));}
        observed
    }
}

struct JobSource<'a> {seed:&'a SeedFile,parent:&'a File,path:&'a Path,protection:Protection}
fn job_source<'a>(state:&'a BirthState,spec:&'a JobSpec)->EnclaveResult<JobSource<'a>> {
    let seed=state.files.get(&spec.source).ok_or_else(||err!(EACCES,"BIRTH_JOBS_ORIGINAL_SOURCE_REQUIRED"))?;
    let parent=spec.source.parent().and_then(|p|state.dirs.get(p))
        .ok_or_else(||err!(EACCES,"BIRTH_JOBS_ORIGINAL_PARENT_REQUIRED"))?;
    if !parent.private {fail!(EACCES,"BIRTH_JOBS_ORIGINAL_PARENT_REQUIRED");}
    Ok(JobSource {seed,parent:&parent.file,path:&spec.source,protection:state.protection})
}
impl JobSource<'_> {
    fn current(&self,spec:&JobSpec,full:bool)->EnclaveResult<()> {
        let seed=self.seed;
        if self.path!=spec.source||seed.access!=libc::O_RDONLY||seed.stamp.len!=spec.size
            ||seed.stamp.directory.mode&0o7777!=0o600||spec.size==0||spec.size>MAX_JOB_BYTES
            ||seed.streamed.as_ref().is_some_and(|s|s.length!=spec.size||s.sha256!=spec.sha256)
            ||seed.streamed.is_none()&&hex::encode(Sha256::digest(&seed.bytes))!=spec.sha256 {
            fail!(ESTALE,"BIRTH_JOBS_SOURCE_BINDING");
        }
        seed.current_with_content(self.parent,self.path,self.protection,full)
    }
}

#[derive(Clone,Debug,PartialEq,Eq)]
struct JobStamp {dev:u64,ino:u64,uid:u32,gid:u32,mode:u32,links:u64,len:u64,
    modified:(i64,i64),changed:(i64,i64)}
impl JobStamp {
    fn of(file:&File)->EnclaveResult<Self> {let m=stat(file)?;Ok(Self {dev:m.dev(),ino:m.ino(),uid:m.uid(),gid:m.gid(),
        mode:m.mode(),links:m.nlink(),len:m.len(),modified:(m.mtime(),m.mtime_nsec()),changed:(m.ctime(),m.ctime_nsec())})}
    fn same_object(&self,other:&Self)->bool {(self.dev,self.ino,self.uid,self.gid)==(other.dev,other.ino,other.uid,other.gid)}
    fn predicted(&self,after:&Self,mode:u32,links:u64,len:u64,wrote:bool)->bool {
        self.same_object(after)&&after.mode==(libc::S_IFREG as u32|mode)&&after.links==links&&after.len==len
            &&(wrote||after.modified==self.modified)
    }
}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
enum JobAction {Create,Write,Chmod,Seal,LinkFinal,RemovePending,SyncFile,SyncParent}
#[derive(Debug)]
struct JobEffect {action:JobAction,result:Option<Result<(),i32>>,before:Option<JobStamp>,after:Option<JobStamp>,verified:bool}
struct ExternalParent {file:File,original:Option<DirStamp>}
struct JobOutput {spec:JobSpec,writer:Option<File>,readonly:Option<File>,initial:Option<JobStamp>,expected:Option<JobStamp>,
    pending_present:bool,final_present:bool,content_complete:bool,durable:bool,effects:Vec<JobEffect>}
impl JobOutput {
    fn new(spec:JobSpec)->Self {Self {spec,writer:None,readonly:None,initial:None,expected:None,pending_present:false,
        final_present:false,content_complete:false,durable:false,effects:Vec::new()}}
    fn file(&self)->EnclaveResult<&File> {self.readonly.as_ref().or(self.writer.as_ref()).ok_or_else(||err!(EACCES,"BIRTH_JOBS_OUTPUT_NOT_HELD"))}
    fn record(&mut self,action:JobAction)->usize {
        self.effects.push(JobEffect {action,result:None,before:self.expected.clone(),after:None,verified:false});self.effects.len()-1
    }
    fn completed_history(&self)->EnclaveResult<()> {
        let actions=self.effects.iter().map(|effect|effect.action).collect::<Vec<_>>();
        let writes=actions.iter().skip(1).take_while(|action|**action==JobAction::Write).count();
        let tail=[JobAction::Chmod,JobAction::SyncFile,JobAction::Seal,JobAction::LinkFinal,
            JobAction::RemovePending,JobAction::SyncFile,JobAction::SyncParent];
        if actions.first()!=Some(&JobAction::Create)||writes==0||actions.len()!=1+writes+tail.len()
            ||actions[1+writes..]!=tail
            ||self.effects.iter().any(|effect|!effect.verified||effect.result!=Some(Ok(()))||effect.after.is_none()) {
            fail!(ESTALE,"BIRTH_JOBS_INCOMPLETE_HISTORY");
        }Ok(())
    }
    fn current(&self,parent:&File,p:Protection,complete:bool)->EnclaveResult<()> {
        if complete&&(!self.durable||!self.final_present||self.pending_present||!self.content_complete
            ||self.readonly.is_none()||self.writer.is_some()) {fail!(ESTALE,"BIRTH_JOBS_INCOMPLETE");}
        if complete {self.completed_history()?;}
        if self.writer.is_none()&&self.readonly.is_none(){return Ok(());}
        let expected=self.expected.as_ref().ok_or_else(||err!(ESTALE,"BIRTH_JOBS_UNPROVEN_POSTSTATE"))?;
        for (file,access) in self.writer.as_ref().map(|f|(f,libc::O_RDWR)).into_iter()
            .chain(self.readonly.as_ref().map(|f|(f,libc::O_RDONLY))) {
            flags(file,access)?;no_extended_acl(file,p)?;
            if JobStamp::of(file)?!=*expected {fail!(ESTALE,"BIRTH_JOBS_OUTPUT_CHANGED");}
        }
        for path in self.pending_present.then_some(&self.spec.pending).into_iter()
            .chain(self.final_present.then_some(&self.spec.destination)) {
            let named=open_at(parent,path,false)?;flags(&named,libc::O_RDONLY)?;no_extended_acl(&named,p)?;
            if JobStamp::of(&named)?!=*expected {fail!(ESTALE,"BIRTH_JOBS_OUTPUT_CHANGED");}
        }
        if !self.pending_present {absent_at(parent,&self.spec.pending)?;}
        if !self.final_present {absent_at(parent,&self.spec.destination)?;}
        if self.content_complete&&file_sha256(self.file()?,self.spec.size)?!=self.spec.sha256 {
            fail!(ESTALE,"BIRTH_JOBS_OUTPUT_DIGEST");
        }Ok(())
    }
}

/// Observable namespace effects only. This is never launchd or install authority.
#[derive(Clone,Debug)]
pub(crate) struct JobsProgress {pub(crate) pending_created:Vec<PathBuf>,pub(crate) final_link_attempts:Vec<PathBuf>,
    pub(crate) published:Vec<PathBuf>,pub(crate) pending_removed:Vec<PathBuf>,pub(crate) durable:Vec<PathBuf>}
impl JobsProgress {fn new()->Self {Self {pending_created:Vec::new(),final_link_attempts:Vec::new(),published:Vec::new(),
    pending_removed:Vec::new(),durable:Vec::new()}}}
struct ExternalJobs {parents:BTreeMap<PathBuf,ExternalParent>,outputs:Vec<JobOutput>,protection:Protection,
    progress:JobsProgress,poisoned:bool,#[cfg(test)] fault:Option<JobFault>}
#[cfg(test)]
#[derive(Clone,Copy)]
enum JobFault {AmbiguousLink,AmbiguousUnlink}
impl ExternalJobs {
    fn new(copies:&[JobSpec],protection:Protection)->Self {Self {parents:BTreeMap::new(),
        outputs:copies.iter().cloned().map(JobOutput::new).collect(),protection,progress:JobsProgress::new(),poisoned:false,
        #[cfg(test)] fault:None}}
    fn admit_parent(&mut self,path:&Path)->EnclaveResult<()> {
        let node=self.parents.get(path).ok_or_else(||err!(EACCES,"BIRTH_JOBS_PARENT_NOT_HELD"))?;
        let m=stat(&node.file)?;let p=self.protection;
        if !m.is_dir()||m.uid()!=p.owner.0||m.gid()!=p.owner.1||m.mode()&0o022!=0||m.nlink()==0 {
            fail!(EACCES,"BIRTH_JOBS_PARENT_PROTECTION");
        }
        flags(&node.file,libc::O_RDONLY)?;no_extended_acl(&node.file,p)?;
        self.parents.get_mut(path).expect("original installed before validation").original=Some(DirStamp::of(&m));Ok(())
    }
    fn hold_native_parents(&mut self,check:&mut impl FnMut()->Vec<EnclaveError>,observed:&mut Vec<EnclaveError>)->EnclaveResult<()> {
        for path in [Path::new("/"),Path::new("/Library"),Path::new(DAEMONS),Path::new(AGENTS)] {
            self.boundary(check,observed)?;
            let file=if path==Path::new("/") {
                let fd=unsafe{libc::open(c"/".as_ptr(),libc::O_RDONLY|libc::O_DIRECTORY|libc::O_NOFOLLOW|libc::O_NONBLOCK|libc::O_CLOEXEC)};
                if fd<0 {fail!(EACCES,"BIRTH_JOBS_PARENT_OPEN");}unsafe{File::from_raw_fd(fd)}
            }else{
                let parent=&self.parents.get(path.parent().expect("fixed parent"))
                    .ok_or_else(||err!(EACCES,"BIRTH_JOBS_PARENT_NOT_HELD"))?.file;
                open_at(parent,path,true)?
            };
            // Successful original opens remain owned even if admission refuses.
            self.parents.insert(path.to_owned(),ExternalParent {file,original:None});
            self.admit_parent(path)?;self.boundary(check,observed)?;
        }Ok(())
    }
    fn parent_current(&self,path:&Path)->EnclaveResult<()> {
        let node=self.parents.get(path).ok_or_else(||err!(EACCES,"BIRTH_JOBS_PARENT_NOT_HELD"))?;
        let original=node.original.as_ref().ok_or_else(||err!(ESTALE,"BIRTH_JOBS_PARENT_UNADMITTED"))?;
        let check=|file:&File|->EnclaveResult<()> {
            flags(file,libc::O_RDONLY)?;no_extended_acl(file,self.protection)?;
            let m=stat(file)?;
            if !m.is_dir()||m.nlink()==0||DirStamp::of(&m)!=*original {fail!(ESTALE,"BIRTH_JOBS_PARENT_CHANGED");}Ok(())
        };
        check(&node.file)?;
        if let Some(parent)=path.parent().and_then(|p|self.parents.get(p)) {check(&open_at(&parent.file,path,true)?)?;}
        Ok(())
    }
    fn observations(&self,complete:bool)->Vec<EnclaveError> {
        let mut observed=Vec::new();
        if self.poisoned {observed.push(err!(EACCES,"BIRTH_JOBS_OWNER_POISONED"));}
        for path in self.parents.keys(){observed.extend(errors([self.parent_current(path)]));}
        for output in &self.outputs {
            if let Some(parent)=output.spec.destination.parent().and_then(|p|self.parents.get(p)) {
                observed.extend(errors([output.current(&parent.file,self.protection,complete)]));
            }else if complete {observed.push(err!(EACCES,"BIRTH_JOBS_PARENT_NOT_HELD"));}
        }observed
    }
    fn boundary(&self,check:&mut impl FnMut()->Vec<EnclaveError>,observed:&mut Vec<EnclaveError>)->EnclaveResult<()> {
        let mut values=check();values.extend(self.observations(false));values.extend(check());
        let current=first(&values);observed.extend(values);current
    }
    fn all_absent(&self)->EnclaveResult<()> {
        for output in &self.outputs {for path in [&output.spec.pending,&output.spec.destination] {
            let parent=&self.parents.get(path.parent().ok_or_else(||err!(EINVAL,"BIRTH_JOBS_PATH"))?)
                .ok_or_else(||err!(EACCES,"BIRTH_JOBS_PARENT_NOT_HELD"))?.file;
            let mut m=std::mem::MaybeUninit::<libc::stat>::uninit();
            let found=unsafe{libc::fstatat(parent.as_raw_fd(),name(path)?.as_ptr(),m.as_mut_ptr(),libc::AT_SYMLINK_NOFOLLOW)};
            if found==0 {fail!(EALREADY,"BIRTH_JOBS_EXISTING_NAME");}
            if std::io::Error::last_os_error().raw_os_error()!=Some(libc::ENOENT) {fail!(EACCES,"BIRTH_JOBS_ABSENCE_UNKNOWN");}
        }}Ok(())
    }
    fn finish_effect(&mut self,index:usize,record:usize,status:Result<(),i32>,mode:u32,links:u64,len:u64,wrote:bool)->EnclaveResult<()> {
        let output=&mut self.outputs[index];
        output.effects[record].result=Some(status);
        let after=JobStamp::of(output.file()?);output.effects[record].after=after.as_ref().ok().cloned();
        // A reported syscall error NEVER adopts observed metadata, even if an
        // ambiguous kernel/test outcome has actually changed the namespace.
        if status.is_err(){fail!(EIO,"BIRTH_JOBS_SYSCALL_REFUSED");}
        let after=after?;let before=output.effects[record].before.as_ref().ok_or_else(||err!(ESTALE,"BIRTH_JOBS_OLD_STATE_REQUIRED"))?;
        if !before.predicted(&after,mode,links,len,wrote) {fail!(ESTALE,"BIRTH_JOBS_UNPROVEN_POSTSTATE");}
        let parent=&self.parents[output.spec.destination.parent().expect("closed parent")].file;
        for path in output.pending_present.then_some(&output.spec.pending).into_iter()
            .chain(output.final_present.then_some(&output.spec.destination)) {
            let named=open_at(parent,path,false)?;no_extended_acl(&named,self.protection)?;flags(&named,libc::O_RDONLY)?;
            if JobStamp::of(&named)?!=after {fail!(ESTALE,"BIRTH_JOBS_UNPROVEN_POSTSTATE");}
        }
        no_extended_acl(output.file()?,self.protection)?;
        output.expected=Some(after);output.effects[record].verified=true;Ok(())
    }
    fn copy_one(&mut self,index:usize,source:&JobSource<'_>,check:&mut impl FnMut()->Vec<EnclaveError>,
        observed:&mut Vec<EnclaveError>,sync:&mut impl FnMut(&File)->EnclaveResult<()>)->EnclaveResult<()> {
        let operation=(|| {
            self.boundary(check,observed)?;
            let spec=self.outputs[index].spec.clone();source.current(&spec,true)?;
            // A full original-source hash may cross expiry too. Complete the
            // actual endpoint gate again immediately before the first effect.
            self.boundary(check,observed)?;
            let record=self.outputs[index].record(JobAction::Create);
            let parent=&self.parents[spec.destination.parent().expect("closed parent")].file;
            let fd=unsafe{libc::openat(parent.as_raw_fd(),name(&spec.pending)?.as_ptr(),libc::O_RDWR|libc::O_CREAT|libc::O_EXCL
                |libc::O_NOFOLLOW|libc::O_NONBLOCK|libc::O_CLOEXEC,0o600)};
            if fd<0 {
                self.outputs[index].effects[record].result=Some(Err(std::io::Error::last_os_error().raw_os_error().unwrap_or(libc::EIO)));
                fail!(EALREADY,"BIRTH_JOBS_PENDING_CREATE_REFUSED");
            }
            self.outputs[index].writer=Some(unsafe{File::from_raw_fd(fd)});
            self.outputs[index].pending_present=true;self.progress.pending_created.push(spec.pending.clone());
            self.outputs[index].effects[record].result=Some(Ok(()));
            let initial=JobStamp::of(self.outputs[index].file()?)?;
            self.outputs[index].effects[record].after=Some(initial.clone());self.outputs[index].initial=Some(initial.clone());
            if initial.uid!=self.protection.owner.0||initial.gid!=self.protection.owner.1
                ||initial.mode!=(libc::S_IFREG as u32|0o600)||initial.links!=1||initial.len!=0 {
                fail!(EACCES,"BIRTH_JOBS_NEW_FILE_PROTECTION");
            }
            no_extended_acl(self.outputs[index].file()?,self.protection)?;flags(self.outputs[index].file()?,libc::O_RDWR)?;
            self.outputs[index].expected=Some(initial);self.outputs[index].effects[record].verified=true;
            self.outputs[index].current(parent,self.protection,false)?;self.boundary(check,observed)?;
            let mut offset=0u64;let mut hash=Sha256::new();let mut buffer=[0u8;64*1024];
            while offset<spec.size {
                self.boundary(check,observed)?;source.current(&spec,false)?;
                let wanted=(spec.size-offset).min(buffer.len()as u64)as usize;let mut done=0;
                while done<wanted {
                    let count=loop {match source.seed.file.read_at(&mut buffer[done..wanted],offset+done as u64) {
                        Err(e) if e.kind()==std::io::ErrorKind::Interrupted=>continue,
                        result=>break result.map_err(|_|err!(EIO,"BIRTH_JOBS_SOURCE_READ"))?,
                    }};
                    if count==0 {fail!(ESTALE,"BIRTH_JOBS_SOURCE_TRUNCATED");}done+=count;
                }
                source.current(&spec,false)?;self.boundary(check,observed)?;
                let record=self.outputs[index].record(JobAction::Write);
                let result=self.outputs[index].writer.as_mut().expect("own writer before sealing").write_all(&buffer[..wanted])
                    .map_err(|e|e.raw_os_error().unwrap_or(libc::EIO));
                self.finish_effect(index,record,result,0o600,1,offset+wanted as u64,true)?;
                hash.update(&buffer[..wanted]);offset+=wanted as u64;self.boundary(check,observed)?;
            }
            if hex::encode(hash.finalize())!=spec.sha256||file_sha256(&source.seed.file,spec.size)?!=spec.sha256
                ||file_sha256(self.outputs[index].file()?,spec.size)?!=spec.sha256 {fail!(ESTALE,"BIRTH_JOBS_COPY_DIGEST");}
            source.current(&spec,true)?;self.outputs[index].content_complete=true;self.boundary(check,observed)?;
            let record=self.outputs[index].record(JobAction::Chmod);let fd=self.outputs[index].file()?.as_raw_fd();
            let status=unsafe{libc::fchmod(fd,0o644)};
            self.finish_effect(index,record,syscall_result(status),0o644,1,spec.size,false)?;
            self.boundary(check,observed)?;self.sync_one(index,false,observed,sync)?;self.boundary(check,observed)?;
            let record=self.outputs[index].record(JobAction::Seal);
            let readonly=open_at(&self.parents[spec.destination.parent().expect("closed parent")].file,&spec.pending,false)?;
            // Retain BOTH descriptors until the readonly observation proves
            // this exact original created inode; no failure drops the writer.
            self.outputs[index].readonly=Some(readonly);
            self.outputs[index].current(&self.parents[spec.destination.parent().expect("closed parent")].file,self.protection,false)?;
            self.outputs[index].effects[record].result=Some(Ok(()));self.outputs[index].effects[record].verified=true;
            self.outputs[index].effects[record].after=self.outputs[index].expected.clone();
            self.outputs[index].writer.take(); // approved successful sealing, never an owner replacement
            self.boundary(check,observed)?;
            let record=self.outputs[index].record(JobAction::LinkFinal);
            self.progress.final_link_attempts.push(spec.destination.clone());
            let parent=&self.parents[spec.destination.parent().expect("closed parent")].file;
            let status=unsafe{libc::linkat(parent.as_raw_fd(),name(&spec.pending)?.as_ptr(),parent.as_raw_fd(),name(&spec.destination)?.as_ptr(),0)};
            let result=syscall_result(status);
            if result.is_ok(){self.outputs[index].final_present=true;self.progress.published.push(spec.destination.clone());}
            #[cfg(test)]
            let result=if result.is_ok()&&matches!(self.fault,Some(JobFault::AmbiguousLink)){Err(libc::EIO)}else{result};
            self.finish_effect(index,record,result,0o644,2,spec.size,false)?;self.boundary(check,observed)?;
            let record=self.outputs[index].record(JobAction::RemovePending);
            let parent=&self.parents[spec.destination.parent().expect("closed parent")].file;
            let status=unsafe{libc::unlinkat(parent.as_raw_fd(),name(&spec.pending)?.as_ptr(),0)};
            let result=syscall_result(status);
            if result.is_ok(){self.outputs[index].pending_present=false;self.progress.pending_removed.push(spec.pending.clone());}
            #[cfg(test)]
            let result=if result.is_ok()&&matches!(self.fault,Some(JobFault::AmbiguousUnlink)){Err(libc::EIO)}else{result};
            self.finish_effect(index,record,result,0o644,1,spec.size,false)?;
            absent_at(&self.parents[spec.destination.parent().expect("closed parent")].file,&spec.pending)?;
            self.boundary(check,observed)?;
            self.sync_one(index,false,observed,sync)?;self.boundary(check,observed)?;
            self.sync_one(index,true,observed,sync)?;self.boundary(check,observed)?;
            self.outputs[index].durable=true;self.progress.durable.push(spec.destination);Ok(())
        })();
        let mut finals=self.observations(false);finals.extend(check());
        let current=first(&finals);observed.extend(finals);
        if operation.is_err()||current.is_err(){self.poisoned=true;}
        operation?;current
    }
    fn sync_one(&mut self,index:usize,parent:bool,observed:&mut Vec<EnclaveError>,sync:&mut impl FnMut(&File)->EnclaveResult<()>)
        ->EnclaveResult<()> {
        let record=self.outputs[index].record(if parent{JobAction::SyncParent}else{JobAction::SyncFile});
        let file=if parent{&self.parents[self.outputs[index].spec.destination.parent().expect("closed parent")].file}
            else{self.outputs[index].file()?};
        let result=sync(file);
        // Preserve the actual rich sync refusal in observed; syscall-shaped
        // effect status uses EIO because EnclaveError is not an OS errno.
        self.outputs[index].effects[record].result=Some(result.as_ref().map(|_|()).map_err(|_|libc::EIO));
        self.outputs[index].effects[record].after=JobStamp::of(self.outputs[index].file()?).ok();
        if let Err(error)=&result {observed.push(error.clone());}
        self.outputs[index].effects[record].verified=result.is_ok();result
    }
}
fn syscall_result(status:i32)->Result<(),i32> {if status==0{Ok(())}else{Err(std::io::Error::last_os_error().raw_os_error().unwrap_or(libc::EIO))}}
fn absent_at(parent:&File,path:&Path)->EnclaveResult<()> {
    let mut metadata=std::mem::MaybeUninit::<libc::stat>::uninit();
    let status=unsafe{libc::fstatat(parent.as_raw_fd(),name(path)?.as_ptr(),metadata.as_mut_ptr(),libc::AT_SYMLINK_NOFOLLOW)};
    if status==0||std::io::Error::last_os_error().raw_os_error()!=Some(libc::ENOENT) {
        fail!(ESTALE,"BIRTH_JOBS_NAME_NOT_ABSENT");
    }Ok(())
}

struct JobsAttempt<'guard> {metadata:NativeMetadataBirth<'guard>,plan:Option<JobsPlan>,external:Option<ExternalJobs>}
impl JobsAttempt<'_> {
    fn observations(&mut self,complete:bool)->Vec<EnclaveError> {
        let mut observed=self.metadata.owner.observations();
        let state=&self.metadata.owner.transport.owner.pin.owner.payload.owner.candidate.birth.state;
        if let Some(plan)=&self.plan {observed.extend(plan.sources_current(state,true));}
        if let Some(external)=&self.external {observed.extend(external.observations(complete));}
        else if complete{observed.push(err!(EACCES,"BIRTH_JOBS_ACTUAL_OUTPUT_OWNER_REQUIRED"));}
        observed.extend(self.metadata.owner.observations());observed
    }
    fn gate(&mut self,complete:bool,observed:&mut Vec<EnclaveError>)->EnclaveResult<()> {
        // Capture only a genuine successful crypto/provisioning observation
        // before all slow source/native/owner checks, then recheck its actual
        // minimum deadline at the last practical acceptance endpoint.
        let expiry=self.metadata.owner.transport.owner.crypto_expiry();
        let mut checks=self.observations(complete);
        match expiry {Ok(expiry)=>checks.extend(errors([expiry.current()])),Err(error)=>checks.push(error)}
        let current=first(&checks);observed.extend(checks);
        if current.is_err(){self.metadata.owner.transport.owner.pin.owner.poison();}current
    }
    fn copy(&mut self,index:usize,observed:&mut Vec<EnclaveError>)->EnclaveResult<()> {
        self.gate(false,observed)?;
        let expiry=self.metadata.owner.transport.owner.crypto_expiry()?;
        let transport=&mut self.metadata.owner.transport.owner;let original=&mut transport.pin.owner;
        let scope=original.scope()?;let inputs=&original.inputs;let owner=&mut original.payload.owner;
        let checked=checked(&owner.candidate.birth.state)?.clone();
        let lease=owner.lease.as_mut().ok_or_else(||err!(EACCES,"BIRTH_JOBS_ACTUAL_EX_REQUIRED"))?;
        let candidate=&mut owner.candidate;
        let accounts=candidate.accounts.as_ref().ok_or_else(||err!(EACCES,"BIRTH_JOBS_ACTUAL_ACCOUNTS_REQUIRED"))?;
        let approval=candidate.approval.as_mut().ok_or_else(||err!(EACCES,"BIRTH_JOBS_ACTUAL_SOFTWARE_REQUIRED"))?;
        let birth=&mut candidate.birth;let state=&birth.state;
        let spec=&self.plan.as_ref().expect("closed actual jobs plan").copies[index];let source=job_source(state,spec)?;
        let mut check=|| {
            let mut values=state.metadata_checks(&mut||authority_boundary(&checked,birth.guard,lease,accounts,approval,inputs,&scope));
            values.extend(errors([metadata::hidden_root(state)]));
            for runtime in &transport.sources {values.extend(errors([source_current(state,&runtime.spec,false)]));}
            // Even metadata-only source gates may hash exact-byte fixtures;
            // no slow original-source observation follows this clock check.
            values.extend(errors([expiry.current()]));
            values
        };
        let result=self.external.as_mut().expect("original external output owner").copy_one(index,&source,&mut check,observed,
            &mut enclave_core::fsutil::full_fsync);
        let post=self.gate(false,observed);if let Err(error)=&post {observed.push(error.clone());}result?;post
    }
}

/// Same genuine metadata owner plus complete durable fixed external job files.
/// This is neither an accepted ancestor-event sequence nor permission to start.
#[must_use="retain same birth, jobs, guard, approval, EX and original sources"]
pub(crate) struct NativeJobsBirth<'guard> {owner:JobsAttempt<'guard>}
impl std::fmt::Debug for NativeJobsBirth<'_> {
    fn fmt(&self,f:&mut std::fmt::Formatter<'_>)->std::fmt::Result {f.debug_struct("NativeJobsBirth").finish_non_exhaustive()}
}
/// Terminal refusal retains every parent/output descriptor and partial name.
#[must_use="retain same actual owners and all partial external namespace effects"]
pub(crate) struct NativeJobsFailure<'guard> {
    pub(crate) error:EnclaveError,pub(crate) boundary_errors:Vec<EnclaveError>,pub(crate) final_errors:Vec<EnclaveError>,
    pub(crate) progress:BirthProgress,pub(crate) jobs:Option<JobsProgress>,owner:JobsAttempt<'guard>,
}
impl std::fmt::Debug for NativeJobsFailure<'_> {
    fn fmt(&self,f:&mut std::fmt::Formatter<'_>)->std::fmt::Result {f.debug_struct("NativeJobsFailure")
        .field("error",&self.error).field("boundary_errors",&self.boundary_errors).field("final_errors",&self.final_errors)
        .field("jobs",&self.jobs).finish_non_exhaustive()}
}
impl<'guard> NativeMetadataBirth<'guard> {
    pub(crate) fn publish_fixed_target_jobs(self)->Result<NativeJobsBirth<'guard>,NativeJobsFailure<'guard>> {
        let mut owner=JobsAttempt {metadata:self,plan:None,external:None};let mut boundary_errors=Vec::new();
        owner.metadata.owner.transport.owner.pin.owner.payload.owner.candidate.birth.state.progress.operation="publish_fixed_target_jobs";
        let operation=(|| {
            owner.gate(false,&mut boundary_errors)?;
            let candidate=&owner.metadata.owner.transport.owner.pin.owner.payload.owner.candidate;
            owner.plan=Some(JobsPlan::build(&candidate.birth.state,candidate.plan.as_ref().ok_or_else(||err!(EACCES,"BIRTH_JOBS_ACTUAL_PLAN_REQUIRED"))?)?);
            owner.external=Some(ExternalJobs::new(&owner.plan.as_ref().expect("closed plan").copies,
                Protection {owner:(0,0),native_acl:true}));
            // Parent-only acquisition has no source borrow; full actual gates
            // remain available around every original external-parent open.
            let metadata=&mut owner.metadata;let external=owner.external.as_mut().expect("retained output owner");
            external.hold_native_parents(&mut||metadata.owner.observations(),&mut boundary_errors)?;
            external.all_absent()?;owner.gate(false,&mut boundary_errors)?;
            for index in 0..owner.plan.as_ref().expect("closed plan").copies.len(){owner.copy(index,&mut boundary_errors)?;}
            owner.gate(true,&mut boundary_errors)
        })();
        let expiry=owner.metadata.owner.transport.owner.crypto_expiry();
        let mut final_errors=owner.observations(true);final_errors.extend(owner.observations(true));
        match expiry {Ok(expiry)=>final_errors.extend(errors([expiry.current()])),Err(error)=>final_errors.push(error)}
        match resolve_owned(owner,operation,boundary_errors,final_errors) {
            Ok(mut owner)=>{let progress=&mut owner.metadata.owner.transport.owner.pin.owner.payload.owner.candidate.birth.state.progress;
                progress.complete=true;progress.uncertain_effects=false;Ok(NativeJobsBirth {owner})},
            Err(mut refusal)=>{
                refusal.owner.metadata.owner.transport.owner.pin.owner.poison();
                if let Some(external)=&mut refusal.owner.external{external.poisoned=true;}
                Err(NativeJobsFailure {error:refusal.error,boundary_errors:refusal.boundary_errors,final_errors:refusal.final_errors,
                    progress:refusal.owner.metadata.owner.transport.owner.pin.owner.payload.owner.candidate.birth.state.progress.clone(),
                    jobs:refusal.owner.external.as_ref().map(|external|external.progress.clone()),owner:refusal.owner})
            },
        }
    }
}

#[cfg(test)]
#[path="target_birth_jobs_tests.rs"]
mod tests;
