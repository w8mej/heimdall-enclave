//! Shared harness for tests over the real-weight packages in target/*-pack.
#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use enclave_core::error::EnclaveResult;
use enclave_core::ipc::PeerCredentials;
use enclave_core::profile::Profile;
use enclave_model_runnerd::arena::WeightBytes;
use enclave_model_runnerd::classes::speculative::{FixedThermal, PowerSource, ThermalState};
use enclave_model_runnerd::service::{
    ResolvedWeights, RunnerConfig, RunnerRequest, RunnerResponse, RunnerService, WeightSource,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

/// Real packages load hundreds of MB each; run one model at a time.
pub static ONE_MODEL_AT_A_TIME: Mutex<()> = Mutex::new(());

/// One real package as published: manifest and artifact.
#[derive(Clone)]
pub struct Package {
    pub manifest: Value,
    artifact: Artifact,
}

/// Artifact bytes: in memory, or a file the UID 702 stand-in maps per
/// resolve (multi-GB models, as the real CAS path does).
#[derive(Clone)]
enum Artifact {
    Owned(Vec<u8>),
    Mapped(Arc<ArtifactFile>),
}

/// An artifact file; a patched copy is removed when the last user drops it.
struct ArtifactFile {
    path: PathBuf,
    temporary: bool,
}

impl Drop for ArtifactFile {
    fn drop(&mut self) {
        if self.temporary {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

fn package_files(dir: &str) -> Option<(Value, PathBuf)> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target")
        .join(dir);
    let file = |ext: &str| -> Option<PathBuf> {
        std::fs::read_dir(&dir)
            .ok()?
            .flatten()
            .map(|e| e.path())
            .find(|p| p.to_string_lossy().ends_with(ext))
    };
    let manifest = serde_json::from_slice(&std::fs::read(file(".manifest.json")?).ok()?).ok()?;
    Some((manifest, file(".safetensors")?))
}

impl Package {
    /// Load target/<dir>/{*.manifest.json, *.safetensors} into memory.
    pub fn load(dir: &str) -> Option<Self> {
        let (manifest, path) = package_files(dir)?;
        Some(Self {
            manifest,
            artifact: Artifact::Owned(std::fs::read(path).ok()?),
        })
    }

    /// As `load`, but the artifact stays on disk and is mapped read-only.
    pub fn load_mapped(dir: &str) -> Option<Self> {
        let (manifest, path) = package_files(dir)?;
        Some(Self {
            manifest,
            artifact: Artifact::Mapped(Arc::new(ArtifactFile {
                path,
                temporary: false,
            })),
        })
    }

    /// Manifest bytes as published.
    pub fn bytes(&self) -> Vec<u8> {
        serde_json::to_vec(&self.manifest).unwrap()
    }

    /// Artifact length in bytes.
    pub fn len(&self) -> usize {
        match &self.artifact {
            Artifact::Owned(w) => w.len(),
            Artifact::Mapped(f) => std::fs::metadata(&f.path).unwrap().len() as usize,
        }
    }

    /// The first `n` artifact bytes.
    pub fn prefix(&self, n: usize) -> Vec<u8> {
        match &self.artifact {
            Artifact::Owned(w) => w[..n].to_vec(),
            Artifact::Mapped(f) => {
                use std::io::Read;
                let mut out = vec![0u8; n];
                std::fs::File::open(&f.path)
                    .unwrap()
                    .read_exact(&mut out)
                    .unwrap();
                out
            }
        }
    }

    /// The artifact byte at `at`.
    pub fn byte_at(&self, at: usize) -> u8 {
        match &self.artifact {
            Artifact::Owned(w) => w[at],
            Artifact::Mapped(f) => {
                use std::os::unix::fs::FileExt;
                let mut b = [0u8; 1];
                std::fs::File::open(&f.path)
                    .unwrap()
                    .read_exact_at(&mut b, at as u64)
                    .unwrap();
                b[0]
            }
        }
    }

    /// The same package with `bytes` written over the artifact at `at`. A
    /// mapped artifact is patched in a copy-on-write clone of its file.
    pub fn patched(&self, at: usize, bytes: &[u8]) -> Self {
        let artifact = match &self.artifact {
            Artifact::Owned(w) => {
                let mut w = w.clone();
                w[at..at + bytes.len()].copy_from_slice(bytes);
                Artifact::Owned(w)
            }
            Artifact::Mapped(f) => {
                use std::os::unix::fs::FileExt;
                let path = std::env::temp_dir().join(format!(
                    "patched-{}.safetensors",
                    hex::encode(enclave_core::rng::bytes32())
                ));
                std::fs::copy(&f.path, &path).unwrap();
                let file = Arc::new(ArtifactFile {
                    path,
                    temporary: true,
                });
                std::fs::OpenOptions::new()
                    .write(true)
                    .open(&file.path)
                    .unwrap()
                    .write_all_at(bytes, at as u64)
                    .unwrap();
                Artifact::Mapped(file)
            }
        };
        Self {
            manifest: self.manifest.clone(),
            artifact,
        }
    }

    /// Re-digest the manifest for the current artifact bytes, as an honest
    /// publisher would after repackaging.
    pub fn redigest(mut self) -> Self {
        let (blake3, sha256) = match &self.artifact {
            Artifact::Owned(w) => (blake3::hash(w), Sha256::digest(w)),
            Artifact::Mapped(f) => {
                use std::io::Read;
                let (mut b, mut s) = (blake3::Hasher::new(), Sha256::new());
                let mut file = std::fs::File::open(&f.path).unwrap();
                let mut buf = vec![0u8; 1 << 24];
                loop {
                    let n = file.read(&mut buf).unwrap();
                    if n == 0 {
                        break;
                    }
                    b.update(&buf[..n]);
                    s.update(&buf[..n]);
                }
                (b.finalize(), s.finalize())
            }
        };
        let blake3 = blake3.to_hex().to_string();
        let artifact = &mut self.manifest["artifact"];
        artifact["sha256"] = json!(hex::encode(sha256));
        artifact["cas_uri"] = json!(format!("cas://blake3-bao-v1/{blake3}"));
        artifact["blake3"] = json!(blake3);
        self
    }

    pub fn cas_uri(&self) -> String {
        self.manifest["artifact"]["cas_uri"]
            .as_str()
            .unwrap()
            .to_owned()
    }

    /// A runner whose UID 702 stand-in publishes exactly this package.
    pub fn runner(&self) -> Arc<RunnerService> {
        RunnerService::start(
            RunnerConfig {
                dev_same_uid: true,
                profile: Profile::L1,
                audit_path: None,
                calib_corpus_blake3: None,
                thermal: Box::new(|| {
                    Box::new(FixedThermal(ThermalState::Nominal, PowerSource::Ac))
                }),
                actuator: None,
                state_dir: None,
            },
            Box::new(Published {
                signed_manifest: self.bytes(),
                artifact: self.artifact.clone(),
            }),
        )
        .unwrap()
    }

    /// Bind `inline` on `service` (whose source publishes this package).
    pub fn bind_on(&self, service: &RunnerService, inline: &[u8]) -> EnclaveResult<RunnerResponse> {
        service.handle(
            &operator(),
            RunnerRequest::Bind {
                manifest: inline.to_vec().into(),
                cas_uri: self.cas_uri(),
                calibration_corpus: None,
            },
        )
    }
}

/// UID 702 stand-in: serves exactly the signed manifest and artifact given.
struct Published {
    signed_manifest: Vec<u8>,
    artifact: Artifact,
}

impl WeightSource for Published {
    fn resolve(&self, _cas_uri: &str) -> EnclaveResult<ResolvedWeights> {
        let primary = match &self.artifact {
            Artifact::Mapped(f) => WeightBytes::map_fd(
                &std::fs::File::open(&f.path)
                    .expect("mapped artifact")
                    .into(),
            )?,
            Artifact::Owned(w) => WeightBytes::Owned(w.clone()),
        };
        Ok(ResolvedWeights {
            primary,
            companions: Vec::new(),
        })
    }
    fn fetch_manifest(&self, _model_id: &str) -> EnclaveResult<Vec<u8>> {
        Ok(self.signed_manifest.clone())
    }
}

impl Package {
    /// A runner whose UID 702 stand-in publishes all of `packages`, each
    /// resolved by its artifact digest and manifest model id (several
    /// models bound in turn on one runner, as in the fleet).
    pub fn runner_publishing(&self, packages: &[&Package]) -> Arc<RunnerService> {
        RunnerService::start(
            RunnerConfig {
                dev_same_uid: true,
                profile: Profile::L1,
                audit_path: None,
                calib_corpus_blake3: None,
                thermal: Box::new(|| {
                    Box::new(FixedThermal(ThermalState::Nominal, PowerSource::Ac))
                }),
                actuator: None,
                state_dir: None,
            },
            Box::new(Catalog(packages.iter().map(|p| (*p).clone()).collect())),
        )
        .unwrap()
    }
}

/// UID 702 stand-in serving several packages.
struct Catalog(Vec<Package>);

impl WeightSource for Catalog {
    fn resolve(&self, cas_uri: &str) -> EnclaveResult<ResolvedWeights> {
        let digest = |uri: &str| uri.split('?').next().unwrap_or_default().to_owned();
        let pack = self
            .0
            .iter()
            .find(|p| digest(&p.cas_uri()) == digest(cas_uri))
            .ok_or_else(|| enclave_core::err!(EINVAL, "CATALOG_UNKNOWN_ARTIFACT"))?;
        Published {
            signed_manifest: pack.bytes(),
            artifact: pack.artifact.clone(),
        }
        .resolve(cas_uri)
    }
    fn fetch_manifest(&self, model_id: &str) -> EnclaveResult<Vec<u8>> {
        self.0
            .iter()
            .find(|p| p.manifest["model_id"] == model_id)
            .map(Package::bytes)
            .ok_or_else(|| enclave_core::err!(EINVAL, "CATALOG_UNKNOWN_MODEL"))
    }
}

/// The local operator; with dev same-UID it also stands in for UID 704.
pub fn operator() -> PeerCredentials {
    let uid = enclave_core::ipc::geteuid();
    PeerCredentials::local(uid, uid)
}

/// The package if it and the native worker are present; otherwise a skip,
/// or a failure when `require_env` is set.
pub fn package_or_skip(dir: &str, require_env: &str, tag: &str) -> Option<Package> {
    or_skip(Package::load(dir), dir, require_env, tag)
}

/// A package loader (`package_or_skip` or `mapped_package_or_skip`).
pub type Loader = fn(&str, &str, &str) -> Option<Package>;

/// As `package_or_skip`, with the artifact mapped rather than read.
pub fn mapped_package_or_skip(dir: &str, require_env: &str, tag: &str) -> Option<Package> {
    or_skip(Package::load_mapped(dir), dir, require_env, tag)
}

fn or_skip(package: Option<Package>, dir: &str, require_env: &str, tag: &str) -> Option<Package> {
    let required = std::env::var_os(require_env).is_some();
    let worker = std::env::var_os("MCPMAC_MLX_WORKER").is_some();
    match package {
        Some(p) if worker => Some(p),
        _ => {
            assert!(!required, "{dir} package and MCPMAC_MLX_WORKER required");
            eprintln!("{tag}=false; {dir} package or native worker absent");
            None
        }
    }
}
