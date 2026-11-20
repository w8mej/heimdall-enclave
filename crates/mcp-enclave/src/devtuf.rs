//! Development TUF repository: 2-of-3 Ed25519 keys per role persisted as seeds
//! under the dev state directory, so successive CLI invocations can publish
//! new targets with monotonically increasing versions. Production fleets use
//! the organisation's TUF repository instead (`tuf refresh --repo`).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use ed25519_dalek::SigningKey;
use enclave_core::err;
use enclave_core::error::EnclaveResult;
use enclave_crypto::tuf::{target_file, RepoBuilder, Role, TargetFile};
use serde::{Deserialize, Serialize};
use serde_json::Value;

fn read_private_keys(path: &Path) -> std::io::Result<Vec<u8>> {
    use std::io::Read;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let file = std::fs::OpenOptions::new().read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC).open(path)?;
    let meta = file.metadata()?;
    if !meta.is_file() || meta.uid() != enclave_core::ipc::geteuid() || meta.mode() & 0o777 != 0o600 || meta.nlink() != 1 || meta.len() > 64 * 1024 {
        return Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "TUF seed file must be owned, private, single-link and bounded"));
    }
    let mut bytes=Vec::new();file.take(64*1024+1).read_to_end(&mut bytes)?;
    if bytes.len()>64*1024 { return Err(std::io::Error::new(std::io::ErrorKind::InvalidData,"TUF seed file exceeds64KiB")); }
    Ok(bytes)
}

/// Expiry of development metadata.
pub const DEV_EXPIRES: &str = "2030-01-01T00:00:00Z";

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct Persisted {
    seeds: BTreeMap<String, Vec<String>>,
    version: u64,
    targets: BTreeMap<String, TargetFile>,
}

/// The repository.
#[derive(Debug)]
pub struct DevRepo {
    keys_path: PathBuf,
    repo_dir: PathBuf,
    builder: RepoBuilder,
    p: Persisted,
}

const ROLES: [Role; 4] = [Role::Root, Role::Timestamp, Role::Snapshot, Role::Targets];

impl DevRepo {
    /// Open or create under `dir` (`keys.json` + `repo/*.json`).
    pub fn open(dir: &Path) -> EnclaveResult<Self> {
        Self::open_with_keys(&dir.join("keys.json"), &dir.join("repo"))
    }

    /// Open or create with explicit keys file and repo output directory.
    pub fn open_with_keys(keys_path: &Path, repo_dir: &Path) -> EnclaveResult<Self> {
        if let Some(p) = keys_path.parent() {
            std::fs::create_dir_all(p).map_err(|e| err!(EIO, "DEVTUF_MKDIR", "{e}"))?;
        }
        std::fs::create_dir_all(repo_dir).map_err(|e| err!(EIO, "DEVTUF_MKDIR", "{e}"))?;
        let p: Persisted = match read_private_keys(keys_path) {
            Ok(b) => serde_json::from_slice(&b).map_err(|e| err!(EINVAL, "DEVTUF_KEYS", "{e}"))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let mut seeds = BTreeMap::new();
                for r in ROLES {
                    seeds.insert(
                        r.name().to_owned(),
                        (0..3)
                            .map(|_| hex::encode(enclave_core::rng::bytes32()))
                            .collect(),
                    );
                }
                Persisted {
                    seeds,
                    version: 0,
                    targets: BTreeMap::new(),
                }
            }
            Err(e) => return Err(err!(EIO, "DEVTUF_KEYS_READ", "{e}")),
        };
        let mut b = RepoBuilder::new(3, 2);
        for r in ROLES {
            let role_seeds = p
                .seeds
                .get(r.name())
                .filter(|s| s.len() == 3)
                .ok_or_else(|| {
                    err!(
                        EINVAL,
                        "DEVTUF_ROLE_KEYS",
                        "{} requires three keys",
                        r.name()
                    )
                })?;
            let ks: Vec<SigningKey> = role_seeds
                .iter()
                .map(|h| {
                    hex::decode(h)
                        .ok()
                        .and_then(|v| <[u8; 32]>::try_from(v).ok())
                        .map(|s| SigningKey::from_bytes(&s))
                        .ok_or_else(|| err!(EINVAL, "DEVTUF_KEYS"))
                })
                .collect::<EnclaveResult<_>>()?;
            b.keys.insert(r, ks);
        }
        let mut repo = Self {
            keys_path: keys_path.to_owned(),
            repo_dir: repo_dir.to_owned(),
            builder: b,
            p,
        };
        if repo.p.version == 0 {
            repo.publish()?;
        }
        Ok(repo)
    }

    /// Repository metadata directory.
    pub fn repo_dir(&self) -> PathBuf {
        self.repo_dir.clone()
    }

    /// Current metadata version.
    pub fn version(&self) -> u64 {
        self.p.version
    }

    /// Add / replace a target and re-sign targets, snapshot and timestamp.
    pub fn add_target(&mut self, name: &str, bytes: &[u8], custom: Value) -> EnclaveResult<()> {
        self.p
            .targets
            .insert(name.to_owned(), target_file(bytes, Some(custom)));
        self.publish()
    }

    /// Sign a target from a bounded reader, without loading model bytes into RAM.
    /// This remains the explicit development signer, never production authority.
    pub fn add_target_reader<R: std::io::Read + std::io::Seek>(&mut self, name: &str, input: &mut R, custom: Value) -> EnclaveResult<()> {
        use sha2::{Digest, Sha256};
        use std::io::SeekFrom;
        input.seek(SeekFrom::Start(0)).map_err(|e| err!(EIO, "DEVTUF_READ", "{e}"))?;
        let mut buffer=[0u8;64*1024];let mut length=0u64;
        let mut bh=blake3::Hasher::new();let mut sh=Sha256::new();
        loop {
            let n=input.read(&mut buffer).map_err(|e|err!(EIO,"DEVTUF_READ","{e}"))?;
            if n==0 {break;}
            length=length.checked_add(n as u64).ok_or_else(||err!(E2BIG,"DEVTUF_TARGET_SIZE"))?;
            if length>crate::artifact_stream::MAX_MODEL_BYTES {return Err(err!(E2BIG,"DEVTUF_TARGET_SIZE"));}
            bh.update(&buffer[..n]);sh.update(&buffer[..n]);
        }
        let hashes=BTreeMap::from([("blake3".into(),blake3::Hasher::finalize(&bh).to_hex().to_string()),("sha256".into(),hex::encode(sh.finalize()))]);
        input.seek(SeekFrom::Start(0)).map_err(|e|err!(EIO,"DEVTUF_READ","{e}"))?;
        self.p.targets.insert(name.into(),TargetFile { length,hashes,custom:Some(custom) });
        self.publish()
    }

    /// Re-sign all repository metadata using TUF canonical JSON (GAP-31 migration).
    pub fn migrate_canonical(&mut self) -> EnclaveResult<u64> {
        self.publish()?;
        Ok(self.p.version)
    }

    fn publish(&mut self) -> EnclaveResult<()> {
        self.p.version += 1;
        let v = self.p.version;
        let w = |n: &str, b: &[u8]| {
            std::fs::write(self.repo_dir.join(n), b).map_err(|e| err!(EIO, "DEVTUF_WRITE", "{e}"))
        };
        w("root.json", &self.builder.root(DEV_EXPIRES)?)?;
        let t = self
            .builder
            .targets(v, DEV_EXPIRES, self.p.targets.clone())?;
        let s = self.builder.snapshot(v, DEV_EXPIRES, v, &t)?;
        let ts = self.builder.timestamp(v, DEV_EXPIRES, v, &s)?;
        w("targets.json", &t)?;
        w("snapshot.json", &s)?;
        w("timestamp.json", &ts)?;
        write_key_store(
            &self.keys_path,
            &serde_json::to_vec_pretty(&self.p).map_err(|e| err!(EIO, "DEVTUF_WRITE", "{e}"))?,
        )?;
        Ok(())
    }
}

// DEFECT-F-95: never expose seeds under the process umask or follow a preplaced
// temporary-file link. This secures the local fixture; it does not separate
// signing authority among independent parties.
fn write_key_store(path: &Path, bytes: &[u8]) -> EnclaveResult<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let tmp = path.with_extension(format!("{}.tmp", hex::encode(enclave_core::rng::bytes32())));
    let result = (|| {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)
            .map_err(|e| err!(EIO, "DEVTUF_KEY_CREATE", "{e}"))?;
        file.write_all(bytes)
            .map_err(|e| err!(EIO, "DEVTUF_KEY_WRITE", "{e}"))?;
        enclave_core::fsutil::full_fsync(&file)?;
        std::fs::rename(&tmp, path).map_err(|e| err!(EIO, "DEVTUF_KEY_RENAME", "{e}"))
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

#[cfg(test)]
mod f95_tests {
    use super::*;
    #[test]
    fn existing_seed_symlink_permissions_links_and_size_rejected() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let dir=std::env::temp_dir().join(format!("f95-existing-{}",hex::encode(enclave_core::rng::bytes32())));
        let keys=dir.join("keys.json");let repo=dir.join("repo");
        DevRepo::open_with_keys(&keys,&repo).unwrap();
        assert!(DevRepo::open_with_keys(&keys,&repo).is_ok());
        std::fs::set_permissions(&keys,std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(DevRepo::open_with_keys(&keys,&repo).is_err());
        std::fs::set_permissions(&keys,std::fs::Permissions::from_mode(0o600)).unwrap();
        let link=dir.join("link");symlink(&keys,&link).unwrap();assert!(DevRepo::open_with_keys(&link,&repo).is_err());
        let hard=dir.join("hard");std::fs::hard_link(&keys,&hard).unwrap();assert!(DevRepo::open_with_keys(&keys,&repo).is_err());
        std::fs::remove_file(&hard).unwrap();std::fs::write(&keys,vec![b' ';65537]).unwrap();
        assert!(DevRepo::open_with_keys(&keys,&repo).is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn key_store_is_private_at_publication_and_bad_roles_do_not_panic() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("mcpmac-f95-{}", enclave_core::rng::u64()));
        std::fs::create_dir(&dir).unwrap();
        let keys = dir.join("keys.json");
        DevRepo::open_with_keys(&keys, &dir.join("repo")).unwrap();
        assert_eq!(
            std::fs::metadata(&keys).unwrap().permissions().mode() & 0o777,
            0o600
        );
        std::fs::write(&keys, b"{\"seeds\":{},\"version\":1,\"targets\":{}}").unwrap();
        assert!(DevRepo::open_with_keys(&keys, &dir.join("repo")).is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }
}

/// `chmod 0600`.
pub fn restrict(p: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o600));
}

/// Metadata read from a repository directory.
#[derive(Debug, Clone)]
pub struct RepoFiles {
    /// `root.json`.
    pub root: Vec<u8>,
    /// `<n>.root.json` rotations in order.
    pub rotations: Vec<Vec<u8>>,
    /// `timestamp.json`.
    pub timestamp: Vec<u8>,
    /// `snapshot.json`.
    pub snapshot: Vec<u8>,
    /// `targets.json`.
    pub targets: Vec<u8>,
}

/// Read a TUF repository directory.
pub fn read_repo(dir: &Path) -> EnclaveResult<RepoFiles> {
    let r = |n: &str| {
        std::fs::read(dir.join(n))
            .map_err(|e| err!(EIO, "TUF_REPO_READ", "{}: {e}", dir.join(n).display()))
    };
    let mut rot: Vec<(u64, PathBuf)> = std::fs::read_dir(dir)
        .map_err(|e| err!(EIO, "TUF_REPO_READ", "{e}"))?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter_map(|p| {
            let n = p.file_name()?.to_str()?.to_owned();
            let v: u64 = n.strip_suffix(".root.json")?.parse().ok()?;
            Some((v, p))
        })
        .collect();
    rot.sort();
    Ok(RepoFiles {
        root: r("root.json")?,
        rotations: rot
            .into_iter()
            .map(|(_, p)| std::fs::read(p).map_err(|e| err!(EIO, "TUF_REPO_READ", "{e}")))
            .collect::<EnclaveResult<_>>()?,
        timestamp: r("timestamp.json")?,
        snapshot: r("snapshot.json")?,
        targets: r("targets.json")?,
    })
}
