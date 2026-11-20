//! Sealed persistent state with rollback detection (GAP-08, GAP-12, GAP-28,
//! GAP-30).
//!
//! Security state that must survive a restart — the 24 h QIF ledger, YubiKey
//! `signCount` high-water marks, TUF trusted metadata, quarantine strikes —
//! is kept in a [`SealedStore`]: one file `<dir>/<name>.sealed` holding
//! `{v, domain, generation, body, mac}` with `mac = BLAKE3-keyed(K, domain ‖
//! generation ‖ body)`, replaced atomically (`tmp` + `fsync` + `rename`), and
//! a generation checkpoint `<dir>/<name>.gen` (also MAC'd) that only grows.
//!
//! Loading fails closed:
//!
//! * no state and no checkpoint — [`Loaded::Fresh`] for generic openers;
//!   required openers additionally refuse a surviving preexisting seed;
//! * checkpoint but no state — `STATE_MISSING` (deleted, not "clean");
//! * bad MAC or wrong domain — `STATE_TAMPERED`;
//! * state generation below the checkpoint — `STATE_ROLLBACK` (a backup
//!   restored over newer state).
//!
//! Scope of this build: the key comes from a `0600` seed file in the daemon's
//! own state directory and the checkpoint is a file beside the state, so the
//! guarantees hold against peers and partial file restoration, not against
//! root replacing the whole directory. On hardware (Phase 2) the key is
//! unwrapped by the SEP and the checkpoint is the ADR-010 SEP monotonic
//! checkpoint / NVRAM variable.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::EnclaveResult;
use crate::secret::SecretKey32;
use crate::{err, fail};

#[derive(Serialize, Deserialize)]
struct Envelope {
    v: u8,
    domain: String,
    generation: u64,
    body: String,
    mac: String,
}

#[derive(Serialize, Deserialize)]
struct Checkpoint {
    domain: String,
    generation: u64,
    mac: String,
}

/// Result of opening a store.
#[derive(Debug)]
pub enum Loaded {
    /// No state/checkpoint found. Required openers also establish that the
    /// directory's sealing seed was newly created; generic openers do not.
    Fresh,
    /// The last saved body.
    State(Vec<u8>),
}

/// One sealed, generation-checked state file.
pub struct SealedStore {
    path: PathBuf,
    ckpt: PathBuf,
    domain: String,
    key: SecretKey32,
    generation: u64,
    bounded: Option<BoundedDirectory>,
}

impl std::fmt::Debug for SealedStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SealedStore")
            .field("path", &self.path)
            .field("generation", &self.generation)
            .finish()
    }
}

fn mac(key: &SecretKey32, domain: &str, generation: u64, body: &[u8]) -> String {
    let mut m = Vec::with_capacity(domain.len() + body.len() + 16);
    m.extend_from_slice(b"MCPMac-SealedState-v1\0");
    m.extend_from_slice(domain.as_bytes());
    m.push(0);
    m.extend_from_slice(&generation.to_be_bytes());
    m.extend_from_slice(body);
    hex::encode(key.mac(&m))
}

/// The per-daemon sealing key for `domain`, derived from
/// `<dir>/sealing.key` (created on first use).
pub fn sealing_key(dir: &Path, domain: &str) -> EnclaveResult<SecretKey32> {
    let seed = crate::fsutil::load_or_create_seed(&dir.join("sealing.key"))?;
    Ok(SecretKey32::new(blake3::derive_key(
        &format!("MCPMac sealed state v1 {domain}"),
        &seed,
    )))
}

/// Exclusive, nonblocking ownership of one private directory inode.
///
/// Acquire before opening persistent state and retain through all resource
/// teardown. The absolute path uses the strict trusted-ancestor/no-follow walk
/// below; missing directories may be created before locking. On macOS only
/// the fixed `/tmp` and `/var` platform aliases are accepted. Closing the held
/// descriptor releases the advisory lock; there is no replaceable lock file.
///
/// This coordinates participating owners of the same inode. It does not stop
/// direct writers or privileged/same-UID directory replacement, authenticate
/// other state, or establish durable progress or freshness. `O_CLOEXEC` avoids
/// exec inheritance; a raw fork can retain the descriptor until that child exits.
#[must_use = "the lease must remain alive while persistent resources are in use"]
pub struct StateDirectoryLease { _directory: BoundedDirectory }

impl StateDirectoryLease {
    /// Refuse contention with `STATE_DIRECTORY_BUSY`; never wait for an owner.
    pub fn acquire(path: &Path) -> EnclaveResult<Self> {
        use std::os::unix::{fs::MetadataExt, io::AsRawFd};
        #[cfg(target_os="macos")]
        let platform_path=path.strip_prefix("/tmp").ok().map(|suffix|Path::new("/private/tmp").join(suffix));
        #[cfg(target_os="macos")]
        let path=platform_path.as_deref().unwrap_or(path);
        // The lease never reads/writes bounded envelopes. Reuse only the
        // existing path authority walk; no public envelope limit is bypassed.
        let directory=BoundedDirectory::open_private(path,0)?;
        if unsafe {libc::flock(directory.directory.as_raw_fd(),libc::LOCK_EX|libc::LOCK_NB)}<0 {
            let error=std::io::Error::last_os_error();
            if error.raw_os_error().is_some_and(|code|code==libc::EAGAIN || code==libc::EWOULDBLOCK) {
                fail!(EAGAIN,"STATE_DIRECTORY_BUSY");
            }
            return Err(err!(EIO,"STATE_DIRECTORY_LOCK","{error}"));
        }
        // Validate the held leaf again after lock acquisition. This is not a
        // promise that path-based downstream writers are immune to renames.
        let metadata=directory.directory.metadata().map_err(|e|err!(EIO,"STATE_PRIVATE_PATH","{e}"))?;
        if !metadata.is_dir() || metadata.uid()!=unsafe{libc::geteuid()} || metadata.mode()&0o077!=0 {
            fail!(EACCES,"STATE_PRIVATE_PATH");
        }
        Ok(Self{_directory:directory})
    }
}

// The strict path is deliberately opt-in: key authority must never follow a
// symlink, wait on a FIFO, or allocate an attacker-chosen state-file length.
struct BoundedDirectory { directory: std::fs::File, maximum: usize }
impl BoundedDirectory {
    fn open(path: &Path, maximum: usize) -> EnclaveResult<Self> {
        if !(4096..=64*1024*1024).contains(&maximum) { fail!(EINVAL, "STATE_PRIVATE_PATH"); }
        Self::open_private(path, maximum)
    }

    // The required authority opener preserves its caller's existing envelope
    // limit policy. Public bounded openers validate their finite limit above.
    fn open_private(path: &Path, maximum: usize) -> EnclaveResult<Self> {
        use std::os::unix::{ffi::OsStrExt, io::{AsRawFd, FromRawFd}, fs::MetadataExt};
        // macOS's fixed /var alias is used by the installed daemon defaults.
        // Resolve only that known platform prefix, never arbitrary symlinks.
        #[cfg(target_os="macos")]
        let platform_path=path.strip_prefix("/var").ok().map(|suffix|Path::new("/private/var").join(suffix));
        #[cfg(target_os="macos")]
        let path=platform_path.as_deref().unwrap_or(path);
        if !path.is_absolute() { fail!(EINVAL, "STATE_PRIVATE_PATH"); }
        let mut directory = std::fs::File::open("/").map_err(|e|err!(EIO,"STATE_PRIVATE_PATH","{e}"))?;
        let components: Vec<_> = path.components().collect();
        for (index, component) in components.iter().enumerate().skip(1) {
            let std::path::Component::Normal(component) = component else { fail!(EACCES,"STATE_PRIVATE_PATH"); };
            let name=std::ffi::CString::new(component.as_bytes()).map_err(|_|err!(EINVAL,"STATE_PRIVATE_PATH"))?;
            let fd=unsafe {libc::openat(directory.as_raw_fd(),name.as_ptr(),libc::O_RDONLY|libc::O_DIRECTORY|libc::O_NOFOLLOW|libc::O_CLOEXEC)};
            let fd=if fd<0 && std::io::Error::last_os_error().kind()==std::io::ErrorKind::NotFound {
                if unsafe {libc::mkdirat(directory.as_raw_fd(),name.as_ptr(),0o700)}<0 { return Err(err!(EIO,"STATE_MKDIR","{}",std::io::Error::last_os_error())); }
                let child=unsafe {libc::openat(directory.as_raw_fd(),name.as_ptr(),libc::O_RDONLY|libc::O_DIRECTORY|libc::O_NOFOLLOW|libc::O_CLOEXEC)};
                if child<0 { return Err(err!(EACCES,"STATE_PRIVATE_PATH")); }
                if let Err(error)=crate::fsutil::full_fsync(&directory) {unsafe{libc::close(child)};return Err(error);} child
            } else {fd};
            if fd<0 {return Err(err!(EACCES,"STATE_PRIVATE_PATH","{}",std::io::Error::last_os_error()));}
            let next=unsafe {std::fs::File::from_raw_fd(fd)};
            let metadata=next.metadata().map_err(|e|err!(EIO,"STATE_PRIVATE_PATH","{e}"))?;
            let uid=unsafe {libc::geteuid()};
            let final_component=index+1==components.len();
            // Root-owned sticky ancestors (e.g. /private/tmp) are safe because
            // entries owned by another UID cannot be replaced by unprivileged peers.
            let sticky_root=metadata.uid()==0 && metadata.mode()&0o1000!=0;
            if (metadata.uid()!=0 && metadata.uid()!=uid) || (metadata.mode()&0o022!=0 && !sticky_root)
                || (final_component && (metadata.uid()!=uid || metadata.mode()&0o077!=0)) {fail!(EACCES,"STATE_PRIVATE_PATH");}
            directory=next;
        }
        if components.len()<2 {fail!(EACCES,"STATE_PRIVATE_PATH");}
        Ok(Self{directory,maximum})
    }
    fn name(name:&str)->EnclaveResult<std::ffi::CString> {
        if name.is_empty() || name.contains('/') || name=="." || name==".." {fail!(EINVAL,"STATE_PRIVATE_NAME");}
        std::ffi::CString::new(name).map_err(|_|err!(EINVAL,"STATE_PRIVATE_NAME"))
    }
    fn read(&self,name:&str,maximum:usize)->EnclaveResult<Option<Vec<u8>>> {
        use std::{io::Read,os::unix::{io::{AsRawFd,FromRawFd},fs::MetadataExt}};
        let name=Self::name(name)?;
        let fd=unsafe{libc::openat(self.directory.as_raw_fd(),name.as_ptr(),libc::O_RDONLY|libc::O_NOFOLLOW|libc::O_NONBLOCK|libc::O_CLOEXEC)};
        if fd<0 {let error=std::io::Error::last_os_error();return if error.kind()==std::io::ErrorKind::NotFound{Ok(None)}else{Err(err!(EACCES,"STATE_READ","{error}"))};}
        let file=unsafe{std::fs::File::from_raw_fd(fd)};
        let metadata=file.metadata().map_err(|e|err!(EIO,"STATE_READ","{e}"))?;
        if !metadata.is_file() || metadata.uid()!=unsafe{libc::geteuid()} || metadata.mode()&0o077!=0 || metadata.nlink()!=1 || metadata.len()>maximum as u64 {fail!(EACCES,"STATE_FILE_BOUNDS");}
        let mut bytes=Vec::new(); file.take((maximum as u64).saturating_add(1)).read_to_end(&mut bytes).map_err(|e|err!(EIO,"STATE_READ","{e}"))?;
        if bytes.len()>maximum {fail!(E2BIG,"STATE_FILE_BOUNDS");} Ok(Some(bytes))
    }
    fn seed(&self)->EnclaveResult<([u8;32],bool)> {
        use std::{io::Write,os::unix::io::{AsRawFd,FromRawFd}};
        if let Some(bytes)=self.read("sealing.key",32)? {return bytes.try_into().map(|seed|(seed,true)).map_err(|_|err!(EACCES,"STATE_KEY_FILE"));}
        let name=Self::name("sealing.key")?;
        let fd=unsafe{libc::openat(self.directory.as_raw_fd(),name.as_ptr(),libc::O_WRONLY|libc::O_CREAT|libc::O_EXCL|libc::O_NOFOLLOW|libc::O_CLOEXEC,0o600)};
        if fd<0 {
            if std::io::Error::last_os_error().kind()==std::io::ErrorKind::AlreadyExists {return self.read("sealing.key",32)?.ok_or_else(||err!(EACCES,"STATE_KEY_FILE"))?.try_into().map(|seed|(seed,true)).map_err(|_|err!(EACCES,"STATE_KEY_FILE"));}
            return Err(err!(EIO,"STATE_KEY_FILE","{}",std::io::Error::last_os_error()));
        }
        let seed=crate::rng::bytes32();let mut file=unsafe{std::fs::File::from_raw_fd(fd)};
        file.write_all(&seed).map_err(|e|err!(EIO,"STATE_KEY_FILE","{e}"))?;
        crate::fsutil::full_fsync(&file)?;crate::fsutil::full_fsync(&self.directory)?;Ok((seed,false))
    }
    fn write(&self,name:&str,bytes:&[u8])->EnclaveResult<()> {
        use std::{io::Write,os::unix::io::{AsRawFd,FromRawFd}};
        if bytes.len()>self.maximum {fail!(E2BIG,"STATE_FILE_BOUNDS");}
        let name=Self::name(name)?;let temporary=Self::name(&format!(".state-{}.tmp",hex::encode(crate::rng::bytes32())))?;
        let fd=unsafe{libc::openat(self.directory.as_raw_fd(),temporary.as_ptr(),libc::O_WRONLY|libc::O_CREAT|libc::O_EXCL|libc::O_NOFOLLOW|libc::O_CLOEXEC,0o600)};
        if fd<0{return Err(err!(EIO,"STATE_WRITE","{}",std::io::Error::last_os_error()));}
        let result=(||{let mut file=unsafe{std::fs::File::from_raw_fd(fd)};file.write_all(bytes).map_err(|e|err!(EIO,"STATE_WRITE","{e}"))?;crate::fsutil::full_fsync(&file)?;
            if unsafe{libc::renameat(self.directory.as_raw_fd(),temporary.as_ptr(),self.directory.as_raw_fd(),name.as_ptr())}<0{return Err(err!(EIO,"STATE_RENAME","{}",std::io::Error::last_os_error()));}
            crate::fsutil::full_fsync(&self.directory)})();
        if result.is_err(){unsafe{libc::unlinkat(self.directory.as_raw_fd(),temporary.as_ptr(),0)};}
        result
    }
}

impl SealedStore {
    /// Open `<dir>/<name>.sealed` under the daemon's sealing key.
    pub fn open(dir: &Path, name: &str) -> EnclaveResult<(Self, Loaded)> {
        let key = sealing_key(dir, name)?;
        Self::open_with(dir, name, key)
    }

    /// Open required authority state without introducing an envelope-size cap.
    /// The absolute directory must have trusted ancestors and be private to this
    /// UID. The on-disk format is compatible with [`Self::open`], but a surviving
    /// sealing seed with no state/checkpoint is `STATE_MISSING`, including an
    /// interrupted first initialization. Restore/reprovision that authority;
    /// never delete its remaining seed to make startup appear fresh.
    ///
    /// This store must be the only named store using the directory's seed.
    /// Child directories may hold independent stores with independent seeds.
    /// Existing callers that initialize multiple stores sharing one seed must
    /// retain [`Self::open`] or adopt an explicit per-store initialization policy.
    /// Reads are nonblocking/no-follow and writes use the held directory. This
    /// API preserves the caller's existing memory policy; use the bounded variant
    /// when a complete serialized-envelope limit is part of its contract.
    pub fn open_required(dir: &Path, name: &str) -> EnclaveResult<(Self, Loaded)> {
        BoundedDirectory::name(name)?;
        let directory = BoundedDirectory::open_private(dir, usize::MAX)?;
        Self::open_authority_inner(dir, name, directory, true)
    }

    /// Open authority state with bounded, nonblocking, no-follow reads and
    /// durable held-directory writes. The absolute directory must have trusted
    /// ancestors and be owned by this UID with no group/other access. `maximum`
    /// bounds the complete serialized sealed envelope, not just its body (4KiB–64MiB).
    pub fn open_bounded(dir:&Path,name:&str,maximum:usize)->EnclaveResult<(Self,Loaded)> {
        Self::open_bounded_inner(dir,name,maximum,false)
    }

    /// As [`Self::open_bounded`], but refuse missing state after the sealing
    /// seed has been created. Requires a dedicated directory containing only
    /// this store: other stores must not share its initialization authority.
    /// Removing state and checkpoint together cannot silently reset its floor.
    pub fn open_bounded_required(dir:&Path,name:&str,maximum:usize)->EnclaveResult<(Self,Loaded)> {
        Self::open_bounded_inner(dir,name,maximum,true)
    }
    fn open_bounded_inner(dir:&Path,name:&str,maximum:usize,required:bool)->EnclaveResult<(Self,Loaded)> {
        BoundedDirectory::name(name)?;
        let bounded=BoundedDirectory::open(dir,maximum)?;
        Self::open_authority_inner(dir,name,bounded,required)
    }
    fn open_authority_inner(dir:&Path,name:&str,bounded:BoundedDirectory,required:bool)->EnclaveResult<(Self,Loaded)> {
        let (seed,preexisting)=bounded.seed()?;
        let key=SecretKey32::new(blake3::derive_key(&format!("MCPMac sealed state v1 {name}"),&seed));
        let (store,loaded)=Self::open_inner(dir,name,key,Some(bounded))?;
        if required&&preexisting&&matches!(&loaded,Loaded::Fresh){fail!(EACCES,"STATE_MISSING");}
        Ok((store,loaded))
    }

    /// As [`Self::open`] with an explicit key.
    pub fn open_with(dir: &Path, name: &str, key: SecretKey32) -> EnclaveResult<(Self, Loaded)> {
        Self::open_inner(dir,name,key,None)
    }

    fn open_inner(dir:&Path,name:&str,key:SecretKey32,bounded:Option<BoundedDirectory>)->EnclaveResult<(Self,Loaded)> {
        if bounded.is_none(){crate::fsutil::private_dir(dir)?;}
        let read=|path:&Path,limit:usize|->EnclaveResult<Option<Vec<u8>>>{if let Some(directory)=&bounded{directory.read(path.file_name().and_then(|s|s.to_str()).ok_or_else(||err!(EINVAL,"STATE_PRIVATE_NAME"))?,limit)}else{match std::fs::read(path){Ok(bytes)=>Ok(Some(bytes)),Err(error) if error.kind()==std::io::ErrorKind::NotFound=>Ok(None),Err(error)=>Err(err!(EIO,"STATE_READ","{error}"))}}};
        let path = dir.join(format!("{name}.sealed"));
        let ckpt = dir.join(format!("{name}.gen"));
        let checkpoint = match read(&ckpt,4096)? {
            Some(b) => {
                let c: Checkpoint = serde_json::from_slice(&b).map_err(|_| {
                    err!(EACCES, "STATE_TAMPERED", "{} checkpoint unreadable", name)
                })?;
                if c.domain != name
                    || !crate::secret::ct_eq(
                        mac(&key, name, c.generation, b"checkpoint").as_bytes(),
                        c.mac.as_bytes(),
                    )
                {
                    fail!(EACCES, "STATE_TAMPERED", "{name} checkpoint MAC");
                }
                Some(c.generation)
            }
            None => None,
        };
        let raw=read(&path,bounded.as_ref().map(|b|b.maximum).unwrap_or(usize::MAX))?;
        let mut s = Self {
            path,
            ckpt,
            domain: name.to_owned(),
            key,
            generation: 0,
            bounded,
        };
        let raw = match raw {
            Some(b) => b,
            None => {
                return match checkpoint {
                    None => Ok((s, Loaded::Fresh)),
                    Some(g) => Err(err!(
                        EACCES,
                        "STATE_MISSING",
                        "{name}: state deleted after generation {g}"
                    )),
                };
            }
        };
        let env: Envelope = serde_json::from_slice(&raw)
            .map_err(|_| err!(EACCES, "STATE_TAMPERED", "{name} unreadable"))?;
        if env.v != 1
            || env.domain != name
            || !crate::secret::ct_eq(
                mac(&s.key, name, env.generation, env.body.as_bytes()).as_bytes(),
                env.mac.as_bytes(),
            )
        {
            fail!(EACCES, "STATE_TAMPERED", "{name} MAC");
        }
        match checkpoint {
            Some(g) if env.generation < g => fail!(
                EACCES,
                "STATE_ROLLBACK",
                "{name}: generation {} < checkpoint {g}",
                env.generation
            ),
            // State without its checkpoint: the checkpoint was removed to
            // make an older state look first-generation.
            None if env.generation > 0 => {
                fail!(EACCES, "STATE_ROLLBACK", "{name}: checkpoint missing")
            }
            _ => {}
        }
        s.generation = env.generation;
        Ok((s, Loaded::State(env.body.into_bytes())))
    }

    /// Current generation.
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Replace the state (UTF-8 body), then advance the checkpoint. A crash
    /// between the two leaves state ahead of the checkpoint, which loads.
    pub fn save(&mut self, body: &[u8]) -> EnclaveResult<()> {
        let body = std::str::from_utf8(body)
            .map_err(|_| err!(EINVAL, "STATE_BODY_UTF8"))?
            .to_owned();
        let generation = self
            .generation
            .checked_add(1)
            .ok_or_else(|| err!(E2BIG, "STATE_GENERATION"))?;
        let env = Envelope {
            v: 1,
            domain: self.domain.clone(),
            generation,
            mac: mac(&self.key, &self.domain, generation, body.as_bytes()),
            body,
        };
        self.write(
            &self.path,
            &serde_json::to_vec(&env).map_err(|e| err!(EIO, "STATE_SERIALIZE", "{e}"))?,
        )?;
        let c = Checkpoint {
            domain: self.domain.clone(),
            generation,
            mac: mac(&self.key, &self.domain, generation, b"checkpoint"),
        };
        self.write(
            &self.ckpt,
            &serde_json::to_vec(&c).map_err(|e| err!(EIO, "STATE_SERIALIZE", "{e}"))?,
        )?;
        self.generation = generation;
        Ok(())
    }

    fn write(&self,path:&Path,bytes:&[u8])->EnclaveResult<()> {
        if let Some(directory)=&self.bounded {directory.write(path.file_name().and_then(|s|s.to_str()).ok_or_else(||err!(EINVAL,"STATE_PRIVATE_NAME"))?,bytes)}else{crate::fsutil::write_private(path,bytes)}
    }

    /// Serialize `v` as JSON and [`Self::save`] it.
    pub fn save_json<T: Serialize>(&mut self, v: &T) -> EnclaveResult<()> {
        self.save(&serde_json::to_vec(v).map_err(|e| err!(EIO, "STATE_SERIALIZE", "{e}"))?)
    }
}

/// Decode a JSON body.
pub fn decode<T: for<'de> Deserialize<'de>>(body: &[u8]) -> EnclaveResult<T> {
    serde_json::from_slice(body).map_err(|e| err!(EACCES, "STATE_TAMPERED", "body: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir() -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "sealed-{}-{}",
            std::process::id(),
            crate::rng::u64()
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn f38_bounded_authority_store_rejects_symlink_fifo_sparse_state_and_untrusted_directory() {
        use std::os::unix::{fs::{PermissionsExt,OpenOptionsExt},ffi::OsStrExt};
        for kind in ["symlink","fifo","sparse","checkpoint","seed","permissions"] {
            let directory=std::env::temp_dir().canonicalize().unwrap().join(format!("sealed-bounded-{}",crate::rng::u64()));
            std::fs::create_dir(&directory).unwrap();std::fs::set_permissions(&directory,std::fs::Permissions::from_mode(0o700)).unwrap();
            let (mut store,_)=SealedStore::open_bounded(&directory,"authority",4096).unwrap();store.save(b"{}").unwrap();drop(store);
            let path=directory.join("authority.sealed");
            match kind {
                "permissions"=>std::fs::set_permissions(&directory,std::fs::Permissions::from_mode(0o755)).unwrap(),
                "checkpoint"=>{let checkpoint=directory.join("authority.gen");std::fs::remove_file(&checkpoint).unwrap();std::os::unix::fs::symlink(&path,checkpoint).unwrap();},
                "seed"=>{let seed=directory.join("sealing.key");std::fs::remove_file(&seed).unwrap();std::os::unix::fs::symlink(&path,seed).unwrap();},
                _=>{std::fs::remove_file(&path).unwrap();match kind {
                    "symlink"=>std::os::unix::fs::symlink(directory.join("authority.gen"),&path).unwrap(),
                    "fifo"=>{let path=std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();assert_eq!(unsafe{libc::mkfifo(path.as_ptr(),0o600)},0);},
                    "sparse"=>{let file=std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&path).unwrap();file.set_len(4097).unwrap();},
                    _=>unreachable!()
                }}
            }
            assert!(SealedStore::open_bounded(&directory,"authority",4096).is_err(),"{kind}");
            std::fs::remove_dir_all(directory).unwrap();
        }
    }


    fn required_dir() -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let directory = dir();
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        directory.canonicalize().unwrap()
    }

    #[test]
    fn phase6_required_store_fresh_restart_and_each_partial_loss() {
        for missing in ["state", "checkpoint", "both"] {
            let directory = required_dir();
            let (mut store, loaded) = SealedStore::open_required(&directory, "authority").unwrap();
            assert!(matches!(loaded, Loaded::Fresh));
            store.save(b"{\"floor\":1}").unwrap();
            store.save(b"{\"floor\":7}").unwrap();
            drop(store);
            let (store, loaded) = SealedStore::open_required(&directory, "authority").unwrap();
            assert_eq!(store.generation(), 2);
            assert!(matches!(loaded, Loaded::State(body) if body == b"{\"floor\":7}"));
            drop(store);
            let seed = std::fs::read(directory.join("sealing.key")).unwrap();
            let state = std::fs::read(directory.join("authority.sealed")).unwrap();
            let checkpoint = std::fs::read(directory.join("authority.gen")).unwrap();
            if missing != "checkpoint" { std::fs::remove_file(directory.join("authority.sealed")).unwrap(); }
            if missing != "state" { std::fs::remove_file(directory.join("authority.gen")).unwrap(); }
            let error = SealedStore::open_required(&directory, "authority").unwrap_err();
            assert!(error.is(if missing == "checkpoint" { "STATE_ROLLBACK" } else { "STATE_MISSING" }), "{missing}: {error}");
            assert_eq!(std::fs::read(directory.join("sealing.key")).unwrap(), seed);
            for (name, retained, bytes) in [
                ("authority.sealed", missing == "checkpoint", state),
                ("authority.gen", missing == "state", checkpoint),
            ] {
                if retained { assert_eq!(std::fs::read(directory.join(name)).unwrap(), bytes); }
                else { assert!(!directory.join(name).exists(), "{missing}: recreated {name}"); }
            }
            std::fs::remove_dir_all(directory).unwrap();
        }
    }

    #[test]
    fn phase6_required_store_seed_only_interrupted_initialization_refuses_without_rewriting() {
        let directory = required_dir();
        let (store, loaded) = SealedStore::open_required(&directory, "authority").unwrap();
        assert!(matches!(loaded, Loaded::Fresh));
        drop(store); // Simulate interruption after key creation, before first save.
        let seed = std::fs::read(directory.join("sealing.key")).unwrap();
        for _ in 0..2 {
            assert!(SealedStore::open_required(&directory, "authority").unwrap_err().is("STATE_MISSING"));
            assert_eq!(std::fs::read(directory.join("sealing.key")).unwrap(), seed);
            assert!(!directory.join("authority.sealed").exists());
            assert!(!directory.join("authority.gen").exists());
        }
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn phase6_required_store_legacy_format_and_generic_named_store_initialization_remain_compatible() {
        let directory = required_dir();
        let (mut legacy, loaded) = SealedStore::open(&directory, "authority").unwrap();
        assert!(matches!(loaded, Loaded::Fresh));
        legacy.save(b"legacy-floor-7").unwrap();
        drop(legacy);
        let state = std::fs::read(directory.join("authority.sealed")).unwrap();
        let checkpoint = std::fs::read(directory.join("authority.gen")).unwrap();
        let seed = std::fs::read(directory.join("sealing.key")).unwrap();
        let (store, loaded) = SealedStore::open_required(&directory, "authority").unwrap();
        assert_eq!(store.generation(), 1);
        assert!(matches!(loaded, Loaded::State(body) if body == b"legacy-floor-7"));
        drop(store);
        // Other generic callers may still initialize independent named stores
        // with a shared seed; this patch does not change their existing API.
        let (mut second, loaded) = SealedStore::open(&directory, "other").unwrap();
        assert!(matches!(loaded, Loaded::Fresh));
        second.save(b"independent-existing-contract").unwrap();
        drop(second);
        assert_eq!(std::fs::read(directory.join("authority.sealed")).unwrap(), state);
        assert_eq!(std::fs::read(directory.join("authority.gen")).unwrap(), checkpoint);
        assert_eq!(std::fs::read(directory.join("sealing.key")).unwrap(), seed);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn phase6_required_store_does_not_relax_public_bounded_envelope_limits() {
        let directory = required_dir();
        for maximum in [0, 4095, 64 * 1024 * 1024 + 1, usize::MAX] {
            assert!(SealedStore::open_bounded(&directory, "authority", maximum).unwrap_err().is("STATE_PRIVATE_PATH"));
            assert!(SealedStore::open_bounded_required(&directory, "authority", maximum).unwrap_err().is("STATE_PRIVATE_PATH"));
        }
        let body = vec![b'x'; 4097];
        let (mut store, _) = SealedStore::open_required(&directory, "authority").unwrap();
        store.save(&body).unwrap();
        drop(store);
        assert!(SealedStore::open_bounded(&directory, "authority", 4096).unwrap_err().is("STATE_FILE_BOUNDS"));
        assert!(SealedStore::open_bounded_required(&directory, "authority", 4096).unwrap_err().is("STATE_FILE_BOUNDS"));
        let (_, loaded) = SealedStore::open_required(&directory, "authority").unwrap();
        assert!(matches!(loaded, Loaded::State(bytes) if bytes == body));
        let (_, loaded) = SealedStore::open_bounded_required(&directory, "authority", 65536).unwrap();
        assert!(matches!(loaded, Loaded::State(bytes) if bytes == body));
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn fresh_save_reload_tamper_delete_rollback() {
        let d = dir();
        let (mut s, l) = SealedStore::open(&d, "ledger").unwrap();
        assert!(matches!(l, Loaded::Fresh));
        s.save(b"{\"a\":1}").unwrap();
        let old = std::fs::read(d.join("ledger.sealed")).unwrap();
        s.save(b"{\"a\":2}").unwrap();
        let (s2, l) = SealedStore::open(&d, "ledger").unwrap();
        assert!(matches!(l, Loaded::State(b) if b == b"{\"a\":2}"));
        assert_eq!(s2.generation(), 2);
        // A restored older file is a rollback.
        let cur = std::fs::read(d.join("ledger.sealed")).unwrap();
        std::fs::write(d.join("ledger.sealed"), &old).unwrap();
        assert!(SealedStore::open(&d, "ledger")
            .unwrap_err()
            .is("STATE_ROLLBACK"));
        // ...also when the checkpoint is removed with it.
        let ck = std::fs::read(d.join("ledger.gen")).unwrap();
        std::fs::remove_file(d.join("ledger.gen")).unwrap();
        assert!(SealedStore::open(&d, "ledger")
            .unwrap_err()
            .is("STATE_ROLLBACK"));
        std::fs::write(d.join("ledger.gen"), &ck).unwrap();
        // Edited bytes are tampering.
        let mut t = cur.clone();
        let i = t.windows(3).position(|w| w == b"a\\\"").unwrap();
        t[i] = b'b';
        std::fs::write(d.join("ledger.sealed"), &t).unwrap();
        assert!(SealedStore::open(&d, "ledger")
            .unwrap_err()
            .is("STATE_TAMPERED"));
        // Deleted state is never "clean".
        std::fs::remove_file(d.join("ledger.sealed")).unwrap();
        assert!(SealedStore::open(&d, "ledger")
            .unwrap_err()
            .is("STATE_MISSING"));
        // A different store name (domain) cannot be swapped in.
        std::fs::write(d.join("ledger.sealed"), &cur).unwrap();
        std::fs::copy(d.join("ledger.sealed"), d.join("other.sealed")).unwrap();
        assert!(SealedStore::open(&d, "other")
            .unwrap_err()
            .is("STATE_TAMPERED"));
        let _ = std::fs::remove_dir_all(&d);
    }
}
