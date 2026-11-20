//! Content-addressed store: pinned FastCDC chunks addressed by BLAKE3, with
//! dual-hash (BLAKE3 + SHA-256) artifact manifests (FS-702 §3.1), verified
//! reassembly (a corrupted chunk is rejected before any byte is returned),
//! reference-counted GC, and revocation shredding (`ftruncate` + unlink).

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use enclave_core::error::EnclaveResult;
use enclave_core::{err, fail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::fastcdc;

/// One chunk reference.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChunkRef {
    /// BLAKE3 of the chunk.
    pub blake3: String,
    /// Length.
    pub len: u64,
}

/// An artifact manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactManifest {
    /// `logical_plaintext_blake3_root` (BLAKE3 of the whole artifact).
    pub blake3: String,
    /// Linear SHA-256 (OCI / FIPS interoperability).
    pub sha256: String,
    /// Total length.
    pub len: u64,
    /// Chunks in order.
    pub chunks: Vec<ChunkRef>,
    /// Gear table digest used.
    pub gear_table_sha256: String,
}

/// The store.
#[derive(Debug)]
pub struct ContentStore {
    root: PathBuf,
    staging: crate::transport::quota::ArtifactStaging,
}

pub(crate) fn hex64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

impl ContentStore {
    pub(crate) fn staging(&self) -> crate::transport::quota::ArtifactStaging { self.staging.clone() }
    pub(crate) fn retry_staging_cleanup(&self)->EnclaveResult<()> {self.staging.retry_cleanup()}
    /// Store root directory.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Open (creating `chunks/` and `manifests/`, mode 0700).
    pub fn open(root: &Path) -> EnclaveResult<Self> {
        for d in ["chunks", "manifests"] {
            fs::create_dir_all(root.join(d)).map_err(|e| err!(EIO, "CAS_MKDIR", "{e}"))?;
        }
        fs::set_permissions(root, fs::Permissions::from_mode(0o700))
            .map_err(|e| err!(EIO, "CAS_CHMOD", "{e}"))?;
        Ok(Self {
            root: root.to_owned(),
            staging: Default::default(),
        })
    }

    /// Startup reconciliation is permitted only after the service owns its
    /// singleton. Opening a store for inspection must never delete live work.
    pub(crate) fn reconcile_staging(&self, sessions: &crate::streaming::Sessions) -> EnclaveResult<()> {
        if !sessions.belongs_to(&self.root) { fail!(EACCES,"CAS_TEMP_CLEANUP_LOCK"); }
        for (directory,object) in [("chunks",false),("manifests",false),("objects",true)] {
            let directory=self.root.join(directory);
            if !directory.exists() {continue;}
            for entry in fs::read_dir(&directory).map_err(|_|err!(EIO,"CAS_TEMP_CLEANUP"))? {
                let entry=entry.map_err(|_|err!(EIO,"CAS_TEMP_CLEANUP"))?;
                let name=entry.file_name();let name=name.to_string_lossy();
                let owned=if object {name.strip_prefix('.').and_then(|n|n.split_once('-')).is_some_and(|(hash,n)|hex64(hash)&&!n.is_empty()&&n.bytes().all(|b|b.is_ascii_digit()))}
                    else {name.split_once(".tmp").is_some_and(|(hash,n)|hex64(hash)&&!n.is_empty()&&n.bytes().all(|b|b.is_ascii_digit()))};
                if !owned {continue;}
                use std::os::unix::fs::MetadataExt;
                let m=fs::symlink_metadata(entry.path()).map_err(|_|err!(EIO,"CAS_TEMP_CLEANUP"))?;
                if !m.is_file() || m.uid()!=enclave_core::ipc::geteuid() || m.nlink()!=1 || !matches!(m.mode()&0o777,0o600|0o444) {fail!(EACCES,"CAS_TEMP_CLEANUP_IDENTITY");}
                fs::remove_file(entry.path()).map_err(|_|err!(EIO,"CAS_TEMP_CLEANUP"))?;
            }
        }
        Ok(())
    }

    fn chunk_path(&self, b3: &str) -> PathBuf {
        self.root.join("chunks").join(b3)
    }
    fn manifest_path(&self, root: &str) -> PathBuf {
        self.root.join("manifests").join(format!("{root}.json"))
    }

    fn write_immutable(&self, path: &Path, bytes: &[u8]) -> EnclaveResult<()> {
        // Existing entries are untrusted: never acknowledge poisoned chunks or
        // manifests merely because their address already exists.
        if let Ok(mut old) = OpenOptions::new().read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK).open(path)
        {
            if old.metadata().is_ok_and(|m| m.is_file() && m.len() == bytes.len() as u64) {
                let mut scratch = [0u8; 64 * 1024];
                let mut offset = 0;
                let mut equal = true;
                while offset < bytes.len() {
                    let n = scratch.len().min(bytes.len() - offset);
                    if old.read_exact(&mut scratch[..n]).is_err()
                        || scratch[..n] != bytes[offset..offset+n] {
                        equal = false;
                        break;
                    }
                    offset += n;
                }
                if equal { return Ok(()); }
            }
        }
        let tmp = path.with_extension(format!("tmp{}", enclave_core::rng::u64()));
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&tmp)
            .map_err(|e| err!(EIO, "CAS_WRITE", "{e}"))?;
        let result = (|| {
            enclave_core::staging::preallocate(&f, bytes.len() as u64)?;
            f.write_all(bytes).map_err(|e| err!(EIO, "CAS_WRITE", "{e}"))?;
            f.sync_all().map_err(|e| err!(EIO, "CAS_FSYNC", "{e}"))?;
            f.set_permissions(fs::Permissions::from_mode(0o444))
                .map_err(|e| err!(EIO, "CAS_CHMOD", "{e}"))?;
            fs::rename(&tmp, path).map_err(|e| err!(EIO, "CAS_RENAME", "{e}"))
        })();
        if result.is_err() {
            if crate::transport::quota::remove_owned(&tmp,&f).is_err() {self.staging.orphan(tmp,f);}
        }
        result
    }

    /// Chunk, hash and store an artifact.
    pub fn put(&self, data: &[u8]) -> EnclaveResult<ArtifactManifest> {
        let root=blake3::hash(data).to_hex().to_string();
        let _payload=self.staging.reserve(&root,data.len() as u64,data.len() as u64)?;
        self.put_reader(std::io::Cursor::new(data))
    }

    /// Stream an artifact using bounded payload scratch space and the pinned
    /// FastCDC lookahead. Only a complete input publishes its manifest.
    pub fn put_reader(&self, mut reader: impl Read) -> EnclaveResult<ArtifactManifest> {
        let mut chunks = Vec::new();
        let mut scratch = vec![0u8; fastcdc::MAX];
        let (mut used, mut eof, mut length) = (0usize, false, 0u64);
        let mut b3 = blake3::Hasher::new();
        let mut sha = Sha256::new();
        loop {
            while used < scratch.len() && !eof {
                let n = reader.read(&mut scratch[used..])
                    .map_err(|e| err!(EIO, "CAS_READ", "{e}"))?;
                if n == 0 { eof = true; } else { used += n; }
            }
            if used == 0 { break; }
            let n = fastcdc::cut_point(&scratch[..used]);
            length = length.checked_add(n as u64)
                .ok_or_else(|| err!(E2BIG, "CAS_LENGTH"))?;
            if length > crate::streaming::MAX_ARTIFACT_BYTES {
                fail!(E2BIG, "CAS_LENGTH");
            }
            let c = &scratch[..n];
            let h = blake3::hash(c).to_hex().to_string();
            self.write_immutable(&self.chunk_path(&h), c)?;
            b3.update(c);
            sha.update(c);
            chunks.push(ChunkRef { blake3: h, len: n as u64 });
            scratch.copy_within(n..used, 0);
            used -= n;
        }
        let m = ArtifactManifest {
            blake3: blake3::Hasher::finalize(&b3).to_hex().to_string(),
            sha256: hex::encode(sha.finalize()),
            len: length,
            chunks,
            gear_table_sha256: fastcdc::gear_table_sha256(),
        };
        let mj = serde_json::to_vec(&m).map_err(|e| err!(EIO, "CAS_MANIFEST", "{e}"))?;
        self.write_immutable(&self.manifest_path(&m.blake3), &mj)?;
        Ok(m)
    }

    /// Load a manifest.
    pub fn manifest(&self, root: &str) -> EnclaveResult<ArtifactManifest> {
        if !hex64(root) {
            fail!(EINVAL, "CAS_ROOT");
        }
        let mut f = open_regular(&self.manifest_path(root))
            .map_err(|_| err!(EACCES, "CAS_UNKNOWN_ROOT", "{root}"))?;
        if f.metadata().map_err(|e| err!(EIO, "CAS_MANIFEST", "{e}"))?.len() > 64 * 1024 * 1024 {
            fail!(E2BIG, "CAS_MANIFEST");
        }
        let mut b = Vec::new();
        (&mut f).take(64 * 1024 * 1024 + 1).read_to_end(&mut b)
            .map_err(|e| err!(EIO, "CAS_MANIFEST", "{e}"))?;
        if b.len() > 64 * 1024 * 1024 { fail!(E2BIG, "CAS_MANIFEST"); }
        let m: ArtifactManifest =
            serde_json::from_slice(&b).map_err(|e| err!(EINVAL, "CAS_MANIFEST", "{e}"))?;
        if m.blake3 != root || !hex64(&m.sha256)
            || m.len > crate::streaming::MAX_ARTIFACT_BYTES
            || m.gear_table_sha256 != fastcdc::gear_table_sha256()
            || m.chunks.len() > (crate::streaming::MAX_ARTIFACT_BYTES / fastcdc::MIN as u64 + 1) as usize
            || m.chunks.iter().any(|c| !hex64(&c.blake3) || c.len == 0 || c.len > fastcdc::MAX as u64)
            || m.chunks.iter().try_fold(0u64, |n,c| n.checked_add(c.len)) != Some(m.len)
        {
            fail!(EACCES, "CAS_MANIFEST_MISMATCH");
        }
        Ok(m)
    }

    /// Verified reassembly: each chunk's BLAKE3, then the whole artifact's
    /// BLAKE3 **and** SHA-256 are checked before any byte is returned.
    pub fn get(&self, root: &str) -> EnclaveResult<Vec<u8>> {
        let mut out = Vec::new();
        self.copy_verified(root, &mut out)?;
        Ok(out)
    }

    /// Reassemble into an unpublished destination, checking every chunk and
    /// both complete-file digests with at most one FastCDC chunk in memory.
    /// The caller must discard the destination if verification fails.
    pub fn copy_verified(&self, root: &str, mut out: impl Write) -> EnclaveResult<ArtifactManifest> {
        let m = self.manifest(root)?;
        let mut scratch = vec![0u8; fastcdc::MAX];
        let mut b3 = blake3::Hasher::new();
        let mut sha = Sha256::new();
        for c in &m.chunks {
            let mut f = open_regular(&self.chunk_path(&c.blake3))
                .map_err(|_| err!(EIO, "CAS_CHUNK_MISSING", "{}", c.blake3))?;
            let n = c.len as usize;
            if f.metadata().map_err(|e| err!(EIO, "CAS_READ", "{e}"))?.len() != c.len {
                fail!(EACCES, "CAS_CHUNK_CORRUPT");
            }
            f.read_exact(&mut scratch[..n]).map_err(|e| err!(EIO, "CAS_READ", "{e}"))?;
            if blake3::hash(&scratch[..n]).to_hex().as_str() != c.blake3 {
                fail!(EACCES, "CAS_CHUNK_CORRUPT", "{}", c.blake3);
            }
            b3.update(&scratch[..n]);
            sha.update(&scratch[..n]);
            out.write_all(&scratch[..n]).map_err(|e| err!(EIO, "CAS_WRITE", "{e}"))?;
        }
        if blake3::Hasher::finalize(&b3).to_hex().as_str() != m.blake3 || hex::encode(sha.finalize()) != m.sha256 {
            fail!(EACCES, "CAS_ARTIFACT_DIGEST_MISMATCH");
        }
        Ok(m)
    }

    /// Open a verified artifact as a read-only file descriptor for
    /// `SCM_RIGHTS` hand-off (materialised in `objects/`, mode 0444).
    pub fn open_readonly(&self, root: &str) -> EnclaveResult<File> {
        if !hex64(root) { fail!(EINVAL, "CAS_ROOT"); }
        let p = self.root.join("objects");
        fs::create_dir_all(&p).map_err(|e| err!(EIO, "CAS_MKDIR", "{e}"))?;
        let obj = p.join(root);
        if !obj.exists() {
            let manifest=self.manifest(root)?;
            let _canonical=self.staging.reserve(root,manifest.len,manifest.len)?;
            let tmp = p.join(format!(".{}-{}", root, enclave_core::rng::u64()));
            let mut owned=Some(OpenOptions::new().write(true).create_new(true).mode(0o600)
                .custom_flags(libc::O_NOFOLLOW).open(&tmp)
                .map_err(|e| err!(EIO,"CAS_OPEN","{e}"))?);
            let result = (|| {
                let f=owned.as_mut().unwrap();
                enclave_core::staging::preallocate(f, manifest.len)?;
                self.copy_verified(root, &mut *f)?;
                f.sync_all().map_err(|e| err!(EIO, "CAS_FSYNC", "{e}"))?;
                f.set_permissions(fs::Permissions::from_mode(0o444))
                    .map_err(|e| err!(EIO, "CAS_CHMOD", "{e}"))?;
                // The service serializes materialization and revocation. Keep
                // an existing canonical inode so held FDs remain revocable.
                fs::rename(&tmp, &obj).map_err(|e| err!(EIO, "CAS_RENAME", "{e}"))
            })();
            if result.is_err() {
                if let Some(file)=owned.take() {if crate::transport::quota::remove_owned(&tmp,&file).is_err(){self.staging.orphan(tmp,file);}}
            }
            result?;
        }
        let mut f = open_regular(&obj)?;
        let m = self.manifest(root)?;
        verify_reader(&mut f, m.len, &m.blake3, &m.sha256)
            .map_err(|_| err!(EACCES, "HYDRATION_CACHE_MISMATCH"))?;
        use std::io::{Seek, SeekFrom};
        f.seek(SeekFrom::Start(0)).map_err(|e| err!(EIO, "CAS_SEEK", "{e}"))?;
        Ok(f)
    }

    /// `(st_dev, st_ino)` of the materialised object handed to consumers,
    /// if it exists.
    pub fn object_inode(&self, root: &str) -> Option<(u64, u64)> {
        enclave_core::supervisor::inode_of(&self.root.join("objects").join(root)).ok()
    }

    /// Whether the store holds a manifest for `root`.
    pub fn contains(&self, root: &str) -> bool {
        hex64(root) && self.manifest_path(root).exists()
    }

    /// All manifest roots.
    pub fn roots(&self) -> EnclaveResult<Vec<String>> {
        let mut v = Vec::new();
        for e in fs::read_dir(self.root.join("manifests"))
            .map_err(|e| err!(EIO, "CAS_READDIR", "{e}"))?
        {
            let n = e
                .map_err(|e| err!(EIO, "CAS_READDIR", "{e}"))?
                .file_name()
                .to_string_lossy()
                .into_owned();
            if let Some(r) = n.strip_suffix(".json") {
                v.push(r.to_owned());
            }
        }
        Ok(v)
    }

    /// Reference-counted GC: delete manifests not in `keep` and every chunk
    /// no longer referenced by a kept manifest. Returns chunks removed.
    pub fn gc(&self, keep: &BTreeSet<String>) -> EnclaveResult<usize> {
        let mut refs: BTreeMap<String, u32> = BTreeMap::new();
        for r in self.roots()? {
            if keep.contains(&r) {
                if let Ok(m) = self.manifest(&r) {
                    for c in m.chunks {
                        *refs.entry(c.blake3).or_default() += 1;
                    }
                }
            } else {
                let _ = fs::remove_file(self.manifest_path(&r));
            }
        }
        let mut removed = 0;
        for e in
            fs::read_dir(self.root.join("chunks")).map_err(|e| err!(EIO, "CAS_READDIR", "{e}"))?
        {
            let p = e.map_err(|e| err!(EIO, "CAS_READDIR", "{e}"))?.path();
            let n = p
                .file_name()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_default();
            if !refs.contains_key(&n) {
                shred_file(&p)?;
                removed += 1;
            }
        }
        Ok(removed)
    }

    /// Truncate the canonical inode but retain its protected name until holder
    /// enforcement is confirmed. Restart/retry can reopen this exact object;
    /// a failed supervisor reply must not destroy its only durable identity.
    pub(crate) fn prepare_revocation(&self,root:&str)->EnclaveResult<Option<File>> {
        use std::os::unix::fs::MetadataExt;
        if !hex64(root) {fail!(EINVAL,"CAS_ROOT");}
        let path=self.root.join("objects").join(root);
        match fs::symlink_metadata(&path) {
            Err(e) if e.kind()==std::io::ErrorKind::NotFound=>return Ok(None),
            Err(e)=>return Err(err!(EIO,"REVOCATION_OBJECT","{e}")),
            Ok(m) if !m.is_file() || m.nlink()!=1 || m.uid()!=enclave_core::ipc::geteuid()=>fail!(EACCES,"REVOCATION_OBJECT_IDENTITY"),
            Ok(_)=>(),
        }
        let held=open_regular(&path)?;let original=held.metadata().map_err(|_|err!(EIO,"REVOCATION_OBJECT"))?;
        held.set_permissions(fs::Permissions::from_mode(0o600)).map_err(|_|err!(EIO,"REVOCATION_OBJECT"))?;
        let writer=OpenOptions::new().write(true).custom_flags(libc::O_NOFOLLOW|libc::O_NONBLOCK).open(&path).map_err(|_|err!(EIO,"REVOCATION_OBJECT"))?;
        let current=writer.metadata().map_err(|_|err!(EIO,"REVOCATION_OBJECT"))?;
        if (current.dev(),current.ino())!=(original.dev(),original.ino()) {fail!(EACCES,"REVOCATION_OBJECT_IDENTITY");}
        writer.set_len(0).map_err(|_|err!(EIO,"REVOCATION_TRUNCATE"))?;
        writer.sync_all().map_err(|_|err!(EIO,"REVOCATION_FSYNC"))?;
        writer.set_permissions(fs::Permissions::from_mode(0o444)).map_err(|_|err!(EIO,"REVOCATION_OBJECT"))?;
        Ok(Some(held))
    }
    /// Revoke: shred the artifact's materialised object, its manifest and
    /// every chunk not shared with a surviving artifact.
    pub fn revoke(&self, root: &str) -> EnclaveResult<usize> {
        let keep: BTreeSet<String> = self.roots()?.into_iter().filter(|r| r != root).collect();
        let obj = self.root.join("objects").join(root);
        if obj.exists() {
            shred_file(&obj)?;
        }
        self.gc(&keep)
    }
}

/// Open a regular, non-symlink file without blocking on special files.
pub(crate) fn open_regular(path: &Path) -> EnclaveResult<File> {
    let f = OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path).map_err(|e| err!(EIO, "CAS_OPEN", "{e}"))?;
    if !f.metadata().map_err(|e| err!(EIO, "CAS_STAT", "{e}"))?.is_file() {
        fail!(EACCES, "CAS_NOT_REGULAR");
    }
    Ok(f)
}

/// Hash a bounded-length reader, refusing trailing or missing bytes.
pub(crate) fn verify_reader(mut input: impl Read, length: u64, b3: &str, sha: &str) -> EnclaveResult<()> {
    let mut scratch = [0u8; 64 * 1024];
    let mut bh = blake3::Hasher::new();
    let mut sh = Sha256::new();
    let mut total = 0u64;
    loop {
        let n = input.read(&mut scratch).map_err(|e| err!(EIO, "CAS_READ", "{e}"))?;
        if n == 0 { break; }
        total += n as u64;
        if total > length { fail!(EACCES, "CAS_LENGTH_MISMATCH"); }
        bh.update(&scratch[..n]); sh.update(&scratch[..n]);
    }
    if total != length || blake3::Hasher::finalize(&bh).to_hex().as_str() != b3 || hex::encode(sh.finalize()) != sha {
        fail!(EACCES, "CAS_ARTIFACT_DIGEST_MISMATCH");
    }
    Ok(())
}

/// Overwrite with zeros, `ftruncate(fd, 0)` (forcing `SIGBUS` on any residual
/// mapping), `fsync`, unlink.
pub fn shred_file(p: &Path) -> EnclaveResult<()> {
    if let Ok(meta) = fs::symlink_metadata(p) {
        if meta.file_type().is_symlink() {
            return fs::remove_file(p).map_err(|e| err!(EIO, "SHRED_UNLINK", "{e}"));
        }
    }
    let _ = fs::set_permissions(p, fs::Permissions::from_mode(0o600));
    let f = OpenOptions::new()
        .write(true)
        .open(p)
        .map_err(|e| err!(EIO, "SHRED_OPEN", "{e}"))?;
    let len = f.metadata().map(|m| m.len()).unwrap_or(0);
    let mut w = &f;
    let zeros = vec![0u8; 64 * 1024];
    let mut left = len;
    while left > 0 {
        let n = left.min(zeros.len() as u64) as usize;
        w.write_all(&zeros[..n])
            .map_err(|e| err!(EIO, "SHRED_WRITE", "{e}"))?;
        left -= n as u64;
    }
    f.set_len(0)
        .map_err(|e| err!(EIO, "SHRED_TRUNCATE", "{e}"))?;
    f.sync_all().map_err(|e| err!(EIO, "SHRED_FSYNC", "{e}"))?;
    fs::remove_file(p).map_err(|e| err!(EIO, "SHRED_UNLINK", "{e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> (ContentStore, PathBuf) {
        let d = std::env::temp_dir().join(format!("depot-cas-{}", enclave_core::rng::u64()));
        (ContentStore::open(&d).unwrap(), d)
    }

    #[test]
    fn roundtrip_dedup_and_corruption() {
        let (s, d) = store();
        let a = fastcdc::test_vector_input();
        let m = s.put(&a).unwrap();
        assert_eq!(s.get(&m.blake3).unwrap(), a);
        // Dedup: a second version sharing most content reuses chunks.
        let mut b = a.clone();
        b[900_000] ^= 1;
        let m2 = s.put(&b).unwrap();
        let shared = m2.chunks.iter().filter(|c| m.chunks.contains(c)).count();
        assert!(shared >= m.chunks.len() - 2);
        // Corrupt one chunk on disk (attacker with write access): rejected.
        let victim = s.chunk_path(&m.chunks[3].blake3);
        fs::set_permissions(&victim, fs::Permissions::from_mode(0o600)).unwrap();
        let mut bytes = fs::read(&victim).unwrap();
        bytes[10] ^= 0xff;
        fs::write(&victim, &bytes).unwrap();
        assert!(s.get(&m.blake3).unwrap_err().is("CAS_CHUNK_CORRUPT"));
        fs::remove_dir_all(d).ok();
    }

    #[test]
    fn revoke_shreds_unshared_chunks_only() {
        let (s, d) = store();
        let a = fastcdc::test_vector_input();
        let mut b = a.clone();
        b.truncate(200_000);
        b.extend(vec![7u8; 300_000]);
        let ma = s.put(&a).unwrap();
        let mb = s.put(&b).unwrap();
        let _f = s.open_readonly(&mb.blake3).unwrap();
        let removed = s.revoke(&mb.blake3).unwrap();
        assert!(removed >= 1);
        assert!(s.get(&mb.blake3).is_err());
        assert_eq!(s.get(&ma.blake3).unwrap(), a, "shared chunks survive");
        assert!(!d.join("objects").join(&mb.blake3).exists());
        fs::remove_dir_all(d).ok();
    }
}
