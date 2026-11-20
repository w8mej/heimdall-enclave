//! Bounded FD and mapped-vnode census. Unknown observations never mean release.
//! Signals address a captured process incarnation, never a reused bare PID.
use std::{os::fd::{AsRawFd, FromRawFd, OwnedFd}, time::{Duration, Instant}};
#[cfg(target_os="linux")]
use std::fs;
use crate::supervisor::Holder;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Observation { Held, Absent, Unknown }

pub(crate) struct Process {
    pub(crate) holder: Holder,
    birth: u64,
    #[cfg(target_os="linux")]
    handle: OwnedFd,
    #[cfg(target_os="macos")]
    version: u32,
    #[cfg(target_os="macos")]
    watch: OwnedFd,
    #[cfg(target_os="macos")]
    ended: std::cell::Cell<bool>,
}
const MAX_PROCESSES: usize = 16384;
const MAX_FDS: usize = 65536;
const MAX_MAP_BYTES: u64 = 16 * 1024 * 1024;

#[cfg(target_os="linux")]
fn identity(pid: i32) -> Option<(u32,u64)> {
    let stat=fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let tail=stat.rsplit_once(')')?.1;
    let birth=tail.split_whitespace().nth(19)?.parse().ok()?;
    let status=fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    let uid=status.lines().find(|l|l.starts_with("Uid:"))?.split_whitespace().nth(2)?.parse().ok()?;
    Some((uid,birth))
}

impl Process {
    pub(crate) fn same_incarnation(&self, other:&Self)->bool {
        if self.holder!=other.holder || self.birth!=other.birth {return false;}
        // Darwin's pidversion changes across exec even when the unique process
        // ID is retained. Issuer exclusion must use the same selector as the
        // authenticated peer and signal paths, not exclude a replacement image.
        #[cfg(target_os="macos")]
        if self.version!=other.version {return false;}
        true
    }
    pub(crate) fn matches_peer(&self,peer:&crate::ipc::PeerCredentials)->bool {
        if peer.pid!=Some(self.holder.pid) || peer.uid!=self.holder.uid {return false;}
        #[cfg(target_os="macos")]
        {return peer.audit_token.is_some_and(|t|t[7]==self.version);}
        #[cfg(not(target_os="macos"))]
        {true}
    }
    #[cfg(target_os="linux")]
    pub(crate) fn capture(pid: i32) -> Option<Self> {
        let (uid,birth)=identity(pid)?;
        let raw=unsafe { libc::syscall(libc::SYS_pidfd_open,pid,0) } as i32;
        if raw<0 { return None; }
        let handle=unsafe { OwnedFd::from_raw_fd(raw) };
        if identity(pid)!=Some((uid,birth)) { return None; }
        Some(Self { holder:Holder {pid,uid}, birth, handle })
    }
    #[cfg(target_os="linux")]
    pub(crate) fn exited(&self) -> bool {
        let mut p=libc::pollfd {fd:self.handle.as_raw_fd(),events:libc::POLLIN,revents:0};
        unsafe { libc::poll(&mut p,1,0)==1 && p.revents&libc::POLLIN!=0 }
    }
    #[cfg(target_os="linux")]
    pub(crate) fn observe(&self, dev: u64, ino: u64) -> Observation {
        use std::{io::Read, os::unix::fs::MetadataExt};
        if self.exited() { return Observation::Absent; }
        if identity(self.holder.pid)!=Some((self.holder.uid,self.birth)) { return Observation::Unknown; }
        let outcome=(|| {
            let rd=fs::read_dir(format!("/proc/{}/fd",self.holder.pid)).ok()?;
            let mut incomplete=false;
            for (i,entry) in rd.enumerate() {
                if i>=MAX_FDS { return None; }
                let entry=match entry {Ok(e)=>e,Err(_)=>{incomplete=true;continue;}};
                match fs::metadata(entry.path()) {
                    Ok(m) if m.dev()==dev && m.ino()==ino=>return Some(Observation::Held),
                    Ok(_)=>(), Err(_)=>incomplete=true,
                }
            }
            let mut maps=String::new();
            fs::File::open(format!("/proc/{}/maps",self.holder.pid)).ok()?.take(MAX_MAP_BYTES+1).read_to_string(&mut maps).ok()?;
            if maps.len() as u64>MAX_MAP_BYTES { return None; }
            for line in maps.lines() {
                let fields:Vec<_>=line.split_whitespace().take(5).collect();
                if fields.len()!=5 { return None; }
                let (major,minor)=fields[3].split_once(':')?;
                let major=u32::from_str_radix(major,16).ok()?;
                let minor=u32::from_str_radix(minor,16).ok()?;
                let inode=fields[4].parse::<u64>().ok()?;
                if inode==ino && libc::makedev(major,minor)==dev {return Some(Observation::Held);}
            }
            Some(if incomplete {Observation::Unknown}else{Observation::Absent})
        })().unwrap_or(Observation::Unknown);
        if self.exited() {Observation::Absent}
        else if identity(self.holder.pid)!=Some((self.holder.uid,self.birth)) {Observation::Unknown}
        else {outcome}
    }
    #[cfg(target_os="linux")]
    pub(crate) fn signal(&self, signal: i32) -> bool {
        if identity(self.holder.pid)!=Some((self.holder.uid,self.birth)) { return false; }
        // The pidfd pins the process incarnation atomically through delivery.
        unsafe { libc::syscall(libc::SYS_pidfd_send_signal,self.handle.as_raw_fd(),signal,std::ptr::null::<libc::siginfo_t>(),0)==0 }
    }
    #[cfg(target_os="macos")]
    pub(crate) fn capture(pid: i32) -> Option<Self> {
        let mut uid=0;let mut birth=0;let mut version=0;
        if unsafe {native::mcpmac_holder_capture(pid,&mut uid,&mut birth,&mut version)}!=0 {return None;}
        let raw=unsafe {libc::kqueue()};if raw<0 {return None;}
        let watch=unsafe {OwnedFd::from_raw_fd(raw)};
        if unsafe {libc::fcntl(raw,libc::F_SETFD,libc::FD_CLOEXEC)}<0 {return None;}
        let change=libc::kevent {ident:pid as usize,filter:libc::EVFILT_PROC,
            flags:libc::EV_ADD|libc::EV_ENABLE|libc::EV_CLEAR|libc::EV_RECEIPT,
            fflags:libc::NOTE_EXIT|libc::NOTE_EXEC,data:0,udata:std::ptr::null_mut()};
        let mut receipt=change;let timeout=libc::timespec{tv_sec:0,tv_nsec:0};
        if unsafe {libc::kevent(raw,&change,1,&mut receipt,1,&timeout)}!=1
            || receipt.flags&libc::EV_ERROR==0 || receipt.data!=0 {return None;}
        let (mut current_uid,mut current_birth,mut current_version)=(0,0,0);
        if unsafe {native::mcpmac_holder_capture(pid,&mut current_uid,&mut current_birth,&mut current_version)}!=0
            || (current_uid,current_birth,current_version)!=(uid,birth,version) {return None;}
        Some(Self {holder:Holder {pid,uid},birth,version,watch,ended:std::cell::Cell::new(false)})
    }
    #[cfg(target_os="macos")]
    pub(crate) fn exited(&self) -> bool {
        // A different positively observed unique ID establishes old death;
        // denied/missing queries do not. Signal SPI separately refuses reuse.
        if self.ended.get() {return true;}
        let mut event=libc::kevent {ident:0,filter:0,flags:0,fflags:0,data:0,udata:std::ptr::null_mut()};
        let timeout=libc::timespec{tv_sec:0,tv_nsec:0};
        let n=unsafe {libc::kevent(self.watch.as_raw_fd(),std::ptr::null(),0,&mut event,1,&timeout)};
        if n==1 && event.flags&libc::EV_ERROR==0 && event.filter==libc::EVFILT_PROC
            && event.ident==self.holder.pid as usize && event.fflags&(libc::NOTE_EXIT|libc::NOTE_EXEC)!=0 {self.ended.set(true);return true;}
        let (mut uid,mut birth,mut version)=(0,0,0);
        (unsafe {native::mcpmac_holder_capture(self.holder.pid,&mut uid,&mut birth,&mut version)==0})
            && (birth!=self.birth || version!=self.version)
    }
    #[cfg(target_os="macos")]
    pub(crate) fn observe(&self,dev:u64,ino:u64)->Observation {
        match unsafe {native::mcpmac_holder_observe(self.holder.pid,self.holder.uid,self.birth,self.version,dev,ino)} {
            1=>Observation::Held,0=>Observation::Absent,_=>Observation::Unknown,
        }
    }
    #[cfg(target_os="macos")]
    pub(crate) fn signal(&self,signal:i32)->bool {
        unsafe {native::mcpmac_holder_signal(self.holder.pid,self.holder.uid,self.birth,self.version,signal)==0}
    }
    #[cfg(not(any(target_os="linux",target_os="macos")))]
    pub(crate) fn capture(_pid:i32)->Option<Self>{None}
    #[cfg(not(any(target_os="linux",target_os="macos")))]
    pub(crate) fn exited(&self)->bool{false}
    #[cfg(not(any(target_os="linux",target_os="macos")))]
    pub(crate) fn observe(&self,_dev:u64,_ino:u64)->Observation{Observation::Unknown}
    #[cfg(not(any(target_os="linux",target_os="macos")))]
    pub(crate) fn signal(&self,_signal:i32)->bool{false}
}

/// Returns all captured candidates and whether the candidate census completed.
/// The scan's authority is the explicitly allowed UID set, not all host users.
pub(crate) fn census(eligible: impl Fn(&Holder)->bool) -> (Vec<Process>,bool) {
    let started=Instant::now();
    let (pids,mut complete)=pids();
    let mut found=Vec::new();
    for (i,pid) in pids.into_iter().enumerate() {
        if i>=MAX_PROCESSES || started.elapsed()>Duration::from_secs(1) {complete=false;break;}
        if pid<=1 || pid==std::process::id() as i32 {continue;}
        if let Some(p)=Process::capture(pid) {
            if eligible(&p.holder) {found.push(p);}
        } else {
            // Linux can cheaply establish that a still-present candidate is
            // outside the selected UID domain; no inaccessible process is
            // silently counted as a released allowed daemon.
            #[cfg(target_os="linux")]
            if let Some((uid,_))=identity(pid) {if !eligible(&Holder{pid,uid}) {continue;}}
            // An exited process no longer has a /proc directory. Its absence
            // here is a census race, not a death claim for a saved holder.
            #[cfg(target_os="linux")]
            if !std::path::Path::new(&format!("/proc/{pid}")).exists() {continue;}
            complete=false;
        }
    }
    (found,complete)
}
#[cfg(target_os="linux")]
fn pids()->(Vec<i32>,bool){
    let Ok(rd)=fs::read_dir("/proc") else{return (vec![],false);};
    let mut pids=Vec::new();let mut complete=true;
    for entry in rd {match entry {Ok(e)=>{if let Some(pid)=e.file_name().to_str().and_then(|s|s.parse().ok()){pids.push(pid);}},Err(_)=>complete=false}}
    (pids,complete)
}
#[cfg(target_os="macos")]
fn pids()->(Vec<i32>,bool){
    let need=unsafe {libc::proc_listallpids(std::ptr::null_mut(),0)};
    if need<=0 || need as usize>MAX_PROCESSES {return (vec![],false);}
    let cap=(need as usize+64).min(MAX_PROCESSES);let mut pids=vec![0;cap];
    let got=unsafe{libc::proc_listallpids(pids.as_mut_ptr().cast(),(cap*4) as i32)};
    if got<=0 || got as usize>=cap {return (vec![],false);}
    pids.truncate(got as usize);(pids,true)
}
#[cfg(not(any(target_os="linux",target_os="macos")))]
fn pids()->(Vec<i32>,bool){(vec![],false)}

#[cfg(target_os="macos")]
mod native {
    unsafe extern "C" {
        pub(super) fn mcpmac_holder_capture(pid:i32,uid:*mut u32,birth:*mut u64,version:*mut u32)->i32;
        pub(super) fn mcpmac_holder_observe(pid:i32,uid:u32,birth:u64,version:u32,dev:u64,ino:u64)->i32;
        pub(super) fn mcpmac_holder_signal(pid:i32,uid:u32,birth:u64,version:u32,signal:i32)->i32;
    }
}

#[cfg(all(test,target_os="linux"))]
mod tests {
    use super::*;
    #[test]
    fn phase1_identity_mismatch_is_unknown_and_cannot_signal_a_reused_selector() {
        let mut child=std::process::Command::new("sleep").arg("10").spawn().unwrap();
        let mut process=Process::capture(child.id() as i32).unwrap();process.birth=process.birth.wrapping_add(1);
        assert_eq!(process.observe(1,1),Observation::Unknown);
        assert!(!process.signal(libc::SIGTERM));assert!(child.try_wait().unwrap().is_none());
        child.kill().unwrap();child.wait().unwrap();
    }
}

#[cfg(all(test,target_os="macos"))]
mod native_tests {
    use super::*;
    use std::{io::{BufRead, BufReader, Write}, process::{Command, Stdio}};

    struct Child(std::process::Child);
    impl Drop for Child {
        fn drop(&mut self) {let _=self.0.kill();let _=self.0.wait();}
    }

    #[test]
    fn phase1_exec_replaces_issuer_selector_and_old_signal_authority() {
        let mut child=Child(Command::new("sh").args(["-c", "echo READY; read command; exec sleep 30"])
            .stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().unwrap());
        let mut ready=String::new();
        BufReader::new(child.0.stdout.take().unwrap()).read_line(&mut ready).unwrap();
        assert_eq!(ready.trim(),"READY");
        let pid=child.0.id() as i32;
        let before=Process::capture(pid).unwrap();
        assert!(before.same_incarnation(&Process::capture(pid).unwrap()));
        child.0.stdin.take().unwrap().write_all(b"exec\n").unwrap();
        let deadline=Instant::now()+Duration::from_secs(5);
        let after=loop {
            if let Some(current)=Process::capture(pid) {
                if current.version!=before.version {break current;}
            }
            assert!(Instant::now()<deadline,"owned child did not exec");
            std::thread::sleep(Duration::from_millis(2));
        };
        assert_eq!(before.holder,after.holder);
        assert_eq!(before.birth,after.birth);
        assert!(!before.same_incarnation(&after),"new image must not inherit issuer exclusion");
        assert!(before.exited(),"exec must retire the saved image selector");
        assert!(!before.signal(libc::SIGTERM),"old image selector must never signal the new image");
        assert!(child.0.try_wait().unwrap().is_none());
        assert!(after.signal(libc::SIGTERM));
        use std::os::unix::process::ExitStatusExt;
        assert_eq!(child.0.wait().unwrap().signal(),Some(libc::SIGTERM));
    }
}

#[cfg(test)]
mod mapping_policy_tests {
    /// Exact SDK-independent policy called by the Darwin sampler; tests run the
    /// compiled C decision engine, rather than a second Rust implementation.
    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    struct Evidence {
        cursor:u64,address:u64,size:u64,mirror_address:u64,mirror_size:u64,
        metadata_address:u64,metadata_size:u64,device:u64,inode:u64,
        source_valid:u32,source_external:u32,source_submap:u32,source_share:u32,
        source_top_valid:u32,source_top_share:u32,metadata_from_mirror:u32,
        mirror_valid:u32,mirror_external:u32,mirror_submap:u32,
        mirror_current:u32,mirror_maximum:u32,metadata_valid:u32,metadata_flags:u32,
    }
    unsafe extern "C" {
        fn mcpmac_holder_mapping_verdict(e:*const Evidence,dev:u64,ino:u64)->i32;
        fn mcpmac_holder_donation_verdict(sender:*const u32,task:*const u32,task_pid:i32,
            captured_pid:i32,captured_uid:u32,captured_birth:u64,captured_version:u32)->i32;
    }
    fn file()->Evidence {
        Evidence{cursor:0x1000,address:0x1000,size:0x4000,
            metadata_address:0x1000,metadata_size:0x4000,device:7,inode:41,
            source_valid:1,source_external:1,source_share:4,metadata_valid:1,..Evidence::default()}
    }
    fn mirror()->Evidence {
        Evidence{metadata_from_mirror:1,mirror_address:0x8000,mirror_size:0x1000,
            metadata_address:0x8000,metadata_size:0x1000,
            mirror_valid:1,mirror_external:1,..file()}
    }
    fn verdict(e:&Evidence)->i32 {unsafe{mcpmac_holder_mapping_verdict(e,7,41)}}

    #[test]
    fn darwin_policy_valid_flat_and_nested_file_identity() {
        assert_eq!(std::mem::size_of::<Evidence>(),128);
        assert_eq!(verdict(&file()),1);
        assert_eq!(verdict(&Evidence{inode:42,..file()}),0);
        assert_eq!(verdict(&mirror()),1);
        assert_eq!(verdict(&Evidence{inode:42,..mirror()}),0);
        // Deleted/renamed paths are irrelevant: no pathname participates.
        assert_eq!(verdict(&Evidence{device:8,..mirror()}),0);
    }

    #[test]
    fn darwin_policy_internal_shadow_chain_and_empty_reservation() {
        for share in [1,2,4,5,6,7] {
            assert_eq!(verdict(&Evidence{source_external:0,source_share:share,
                metadata_valid:0,device:0,inode:0,..file()}),0);
        }
        let empty=Evidence{source_external:0,source_share:3,metadata_valid:0,device:0,inode:0,..file()};
        assert_eq!(verdict(&empty),-1,"physical/unknown object is not an empty reservation");
        assert_eq!(verdict(&Evidence{source_top_valid:1,source_top_share:3,..empty}),0);
        assert_eq!(verdict(&Evidence{source_top_valid:1,source_top_share:2,..empty}),-1);
        for share in [0,8,99] {
            assert_eq!(verdict(&Evidence{source_external:0,source_share:share,..file()}),-1);
        }
    }

    #[test]
    fn darwin_policy_failed_or_short_queries_and_zero_vnodes_remain_unknown() {
        for evidence in [Evidence{source_valid:0,..file()},Evidence{metadata_valid:0,..file()},
            Evidence{device:0,..file()},Evidence{inode:0,..file()},
            Evidence{source_submap:1,..file()},Evidence{metadata_flags:1,..file()},
            Evidence{source_external:2,..file()}] {
            assert_eq!(verdict(&evidence),-1);
        }
        assert_eq!(unsafe{mcpmac_holder_mapping_verdict(std::ptr::null(),7,41)},-1);
        assert_eq!(unsafe{mcpmac_holder_mapping_verdict(&file(),0,41)},-1);
        assert_eq!(unsafe{mcpmac_holder_mapping_verdict(&file(),7,0)},-1);
    }

    #[test]
    fn darwin_policy_remap_cannot_erase_external_backing_or_gain_permissions() {
        for evidence in [Evidence{mirror_valid:0,..mirror()},Evidence{mirror_external:0,..mirror()},
            Evidence{mirror_external:2,..mirror()},Evidence{mirror_submap:1,..mirror()},
            Evidence{mirror_current:1,..mirror()},Evidence{mirror_maximum:1,..mirror()},
            Evidence{mirror_size:0x8000,..mirror()},Evidence{metadata_from_mirror:2,..mirror()}] {
            assert_eq!(verdict(&evidence),-1);
        }
    }

    #[test]
    fn darwin_policy_address_overflow_nonprogress_and_unrelated_metadata_refuse() {
        for evidence in [Evidence{size:0,..file()},Evidence{address:0x800,..file()},
            Evidence{address:u64::MAX-1,size:2,..file()},
            Evidence{metadata_size:0,..file()},Evidence{metadata_address:0x2000,..file()},
            Evidence{metadata_size:0x2000,..file()},Evidence{metadata_address:u64::MAX-1,metadata_size:2,..file()},
            Evidence{mirror_size:0,..mirror()},Evidence{mirror_address:u64::MAX,mirror_size:1,..mirror()},
            Evidence{metadata_address:0x9000,..mirror()}] {
            assert_eq!(verdict(&evidence),-1);
        }
    }

    fn token()->[u32;8] {[501,702,8702,702,8702,1234,9,77]}
    fn donated(sender:&[u32;8],task:&[u32;8],pid:i32,uid:u32,birth:u64,version:u32)->bool {
        unsafe{mcpmac_holder_donation_verdict(sender.as_ptr(),task.as_ptr(),pid,1234,uid,birth,version)==1}
    }
    #[test]
    fn darwin_policy_task_donation_binds_kernel_sender_and_current_image() {
        assert!(donated(&token(),&token(),1234,702,99,77));
        let mut clean_child=token();clean_child[5]=1235;
        assert!(!donated(&token(),&clean_child,1235,702,99,77),"clean child cannot stand in for a hostile holder");
        let mut replaced=token();replaced[7]=78;
        assert!(!donated(&token(),&replaced,1234,702,99,77));
        assert!(!donated(&token(),&token(),1234,702,99,78));
        assert!(!donated(&token(),&token(),1234,701,99,77));
        assert!(!donated(&token(),&token(),1234,702,0,77));
        let mut changed_real_uid=token();changed_real_uid[3]=701;
        assert!(!donated(&changed_real_uid,&changed_real_uid,1234,702,99,77));
        for field in 0..8 {
            let mut forged=token();forged[field]^=1;
            assert!(!donated(&token(),&forged,1234,702,99,77));
        }
    }
}
