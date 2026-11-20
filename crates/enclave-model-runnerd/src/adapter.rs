//! `EnclaveModelAdapter::bind()` (FS-701 §3.3): validate the signed manifest,
//! re-verify the artifact digest over the read-only mapping, attest topology,
//! run the ECE gate, compute the lattice-join controls across the primary
//! class and its wrappers, and instantiate the class engine.
//!
//! Probe directions, erasure subspaces and statistical thresholds are trusted
//! publisher configuration, authenticated at the service Bind boundary (F110).
//! Numeric validation prevents null/invalid controls; it does not make probes
//! independent of a trusted publisher who chose inappropriate directions.

use enclave_core::error::EnclaveResult;
use enclave_core::profile::Profile;
use enclave_core::{err, fail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::classes::ar::{BigramLm, CausalBackend};
use crate::classes::byte_concept::{ConceptGate, ConceptParams, Leace, ReferenceConcept};
use crate::classes::diffusion::{BigramDenoiser, DiffusionGate, ReferenceProbe};
use crate::classes::rlcd::{LinearHead, RlcdBackend, RlcdGate};
use crate::classes::speculative::{DepthGate, LatentProbe, ReferenceDepth, ThermalProvider};
use crate::classes::ssm::{DiagonalSsm, StateSnapshotDag};
use crate::classes::world::{ReferenceJepa, WorldGate};
use crate::ece::{self, CalibrationLut};
use crate::manifest::{ExecutionClass, ModelManifestV1};
use crate::safetensors::{self, TensorIndex};
use crate::topology::{verify_declared, Features, OpAttestor};

/// Lattice-join (`⊔`) of controls across primary + wrappers: wrappers can only
/// tighten.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AdapterControls {
    /// Primary class.
    pub primary: ExecutionClass,
    /// Wrappers.
    pub wrappers: Vec<ExecutionClass>,
    /// Output cap.
    pub max_output_bytes: u32,
    /// Step cap (diffusion / depth).
    pub max_steps: u32,
    /// Constant-cadence release (ms) when a speculative wrapper is present.
    pub cadence_ms: Option<u64>,
    /// Nominal recurrent depth.
    pub r_max_nominal: u32,
    /// Fair-thermal / battery depth.
    pub r_max_fair: u32,
    /// Anchor window `W`.
    pub anchor_window: u32,
    /// `α`.
    pub anchor_alpha: f64,
    /// Cross-silicon margin.
    pub margin: f64,
    /// QIF per-record cap (mb).
    pub qif_cap_mb: i64,
    /// Minimum swarm profile.
    pub min_profile: Profile,
    /// Zeroize rejected drafts.
    pub zeroize_rejected_drafts: bool,
    /// Diffusion generation deadline (ms), checked against the profile at bind.
    pub diffusion_deadline_ms: u32,
}

impl AdapterControls {
    /// Compute from the manifest.
    pub fn bind(m: &ModelManifestV1) -> EnclaveResult<Self> {
        let sc = m.controls();
        let spec = m.execution_class == ExecutionClass::SpeculativeOrRecurrentDepth
            || m.wrappers()
                .contains(&ExecutionClass::SpeculativeOrRecurrentDepth);
        let default_steps = if m.execution_class == ExecutionClass::DiscreteDiffusion {
            64
        } else {
            32
        };
        let steps = [m.output_caps.max_diffusion_steps, m.output_caps.max_steps]
            .into_iter()
            .flatten()
            .min()
            .unwrap_or(default_steps);
        let nominal = sc.max_recurrent_depth_nominal.unwrap_or(32).min(32);
        Ok(Self {
            primary: m.execution_class,
            wrappers: m.wrappers().to_vec(),
            max_output_bytes: m.output_caps.max_output_bytes,
            max_steps: steps,
            cadence_ms: spec.then_some(20),
            r_max_nominal: nominal,
            r_max_fair: sc
                .max_recurrent_depth_fair_thermal
                .unwrap_or(8)
                .min(8)
                .min(nominal),
            anchor_window: sc.ssm_anchor_reinject_tokens.unwrap_or(2048),
            anchor_alpha: sc.anchor_mix_alpha.unwrap_or(1.0),
            margin: sc.threshold_margin_fail_closed.unwrap_or(1e-3).max(1e-3),
            qif_cap_mb: sc
                .qif_max_millibits_per_record
                .unwrap_or(12_000)
                .min(12_000),
            min_profile: m.min_profile()?,
            zeroize_rejected_drafts: spec,
            diffusion_deadline_ms: m
                .output_caps
                .diffusion_deadline_ms
                .unwrap_or(crate::manifest::DEFAULT_DIFFUSION_DEADLINE_MS),
        })
    }
}

/// Class engine.
#[derive(Debug)]
pub enum Engine {
    /// Baseline.
    Ar(Box<dyn CausalBackend>),
    /// Class 1.
    Rlcd(RlcdGate),
    /// Class 2.
    Diffusion(DiffusionGate),
    /// Class 3.
    Ssm(StateSnapshotDag),
    /// Class 4.
    Concept(ConceptGate),
    /// Class 5.
    Depth(DepthGate),
    /// Class 6.
    World(WorldGate),
}

/// Calibration inputs.
#[derive(Debug, Clone, Copy)]
pub struct CalibrationInput<'a> {
    /// `enclave-calib-eval-v1` JSONL bytes.
    pub corpus: &'a [u8],
    /// TUF-pinned BLAKE3 of the corpus.
    pub pinned_blake3: &'a str,
}

/// What actually computes for a bound model, as receipts name it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackendIdentity {
    /// Backend (`cpu_reference`, or the artifact's `enclave_adapter.backend`).
    pub backend: String,
    /// Model architecture the backend's closed graph implements.
    pub architecture: String,
    /// SHA-256 of the artifact bytes, verified at bind.
    pub checkpoint_sha256: String,
}

impl BackendIdentity {
    fn of(idx: &TensorIndex, manifest: &ModelManifestV1) -> Self {
        let backend = idx.metadata.get("enclave_adapter.backend").cloned().unwrap_or_else(|| "cpu_reference".into());
        let qwen = idx.metadata.get("enclave_adapter.llama.config").is_some_and(|c| c.contains("\"qk_norm\":true"));
        let architecture = match backend.as_str() {
            "mlx_llama_v1" if qwen => "qwen3",
            "mlx_llama_v1" => "llama",
            "mlx_rwkv7_v1" => "rwkv7",
            "mlx_eagle3_v1" => "qwen3+eagle3",
            "mlx_vjepa2_v1" => "vjepa2-vit",
            "mlx_llada_v1" => "llada",
            "mlx_bigram_v1" => "bigram",
            "coreml_linear_v1" => "linear",
            _ => "reference",
        };
        Self { backend, architecture: architecture.into(), checkpoint_sha256: manifest.artifact.sha256.clone() }
    }
}

/// A bound adapter.
#[derive(Debug)]
pub struct EnclaveModelAdapter {
    /// Manifest.
    pub manifest: ModelManifestV1,
    /// Controls.
    pub controls: AdapterControls,
    /// Engine.
    pub engine: Engine,
    /// Runtime attestor.
    pub attest: OpAttestor,
    /// Static features.
    pub features: Features,
    /// Measured ECE (Class 1).
    pub ece: Option<f64>,
    /// Backend, architecture and checkpoint digest for receipts.
    pub identity: BackendIdentity,
    /// BLAKE3 topology fingerprint of the artifact header, computed once at
    /// bind (a header can carry a multi-MB tokenizer; never parse it twice).
    pub topology_fingerprint: String,
}

fn rows(idx: &TensorIndex, file: &[u8], name: &str, d: usize) -> EnclaveResult<Vec<Vec<f32>>> {
    let r = idx
        .shape(name)
        .and_then(|s| s.first().copied())
        .ok_or_else(|| err!(EINVAL, "TENSOR_MISSING", "{name}"))?;
    Ok(idx
        .f32(file, name, &[r, d])?
        .chunks_exact(d)
        .map(<[f32]>::to_vec)
        .collect())
}

impl EnclaveModelAdapter {
    /// Bind over the read-only artifact bytes.
    pub fn bind(
        manifest: ModelManifestV1,
        file: &[u8],
        profile: Profile,
        calib: Option<CalibrationInput<'_>>,
        thermal: Box<dyn ThermalProvider>,
    ) -> EnclaveResult<Self> {
        Self::bind_with_companions(manifest, file, &[], profile, calib, thermal)
    }

    /// Bind over the read-only artifact bytes with companion safety layers (GAP-33).
    pub fn bind_with_companions(
        manifest: ModelManifestV1,
        file: &[u8],
        companions: &[&[u8]],
        profile: Profile,
        calib: Option<CalibrationInput<'_>>,
        thermal: Box<dyn ThermalProvider>,
    ) -> EnclaveResult<Self> {
        manifest.validate()?;
        let controls = AdapterControls::bind(&manifest)?;
        if profile < controls.min_profile {
            fail!(
                EPERM,
                "PROFILE_BELOW_MODEL_MINIMUM",
                "{profile} < {}",
                controls.min_profile
            );
        }
        let ceiling = crate::manifest::diffusion_deadline_ceiling_ms(profile);
        if controls.diffusion_deadline_ms > ceiling {
            fail!(
                EPERM,
                "DIFFUSION_DEADLINE_ABOVE_PROFILE",
                "{} ms > {ceiling} ms at {profile}",
                controls.diffusion_deadline_ms
            );
        }
        if hex::encode(Sha256::digest(file)) != manifest.artifact.sha256 {
            fail!(EACCES, "ARTIFACT_SHA256_MISMATCH");
        }
        if manifest
            .artifact
            .format
            .as_deref()
            .is_some_and(|f| f != "safetensors")
        {
            fail!(
                EPERM,
                "ARTIFACT_FORMAT_UNSUPPORTED",
                "the reference runtime loads safetensors only"
            );
        }

        // GAP-33: Consume companion FDs by declared role
        let mut companion_by_role: std::collections::BTreeMap<&str, &[u8]> =
            std::collections::BTreeMap::new();
        if let Some(cs) = &manifest.companion_safety_layers {
            let eager_layers: Vec<_> = cs.iter().filter(|c| c.eager_hydrate_required).collect();
            if eager_layers.len() > companions.len() {
                fail!(
                    EACCES,
                    "COMPANIONS_MISSING",
                    "manifest declared {} eager companions, but got {}",
                    eager_layers.len(),
                    companions.len()
                );
            }
            for (layer, &comp_bytes) in eager_layers.iter().zip(companions.iter()) {
                let expected_root = layer
                    .cas_uri
                    .strip_prefix("cas://blake3-bao-v1/")
                    .ok_or_else(|| err!(EINVAL, "COMPANION_URI_INVALID"))?;
                let got_digest = blake3::hash(comp_bytes).to_hex().to_string();
                if got_digest != expected_root {
                    fail!(
                        EACCES,
                        "COMPANION_DIGEST_MISMATCH",
                        "role {}: expected {}, got {}",
                        layer.role,
                        expected_root,
                        got_digest
                    );
                }
                companion_by_role.insert(&layer.role, comp_bytes);
            }
        }

        let mut idx = safetensors::parse(file)?;
        if let Some(backend) = idx.metadata.get("enclave_adapter.backend") {
            if !matches!((backend.as_str(), manifest.execution_class),
                ("coreml_linear_v1", ExecutionClass::DiscriminativeRlcd)
                | ("mlx_bigram_v1", ExecutionClass::ArCausal)
                | ("mlx_llama_v1", ExecutionClass::ArCausal)
                | ("mlx_rwkv7_v1", ExecutionClass::RecurrentSsmTtt)
                | ("mlx_eagle3_v1", ExecutionClass::SpeculativeOrRecurrentDepth)
                | ("mlx_vjepa2_v1", ExecutionClass::JepaEbmWorldPlanner)
                | ("mlx_llada_v1", ExecutionClass::DiscreteDiffusion)) {
                fail!(EACCES, "FRAMEWORK_BACKEND_CLASS_UNSUPPORTED");
            }
        }
        let features = verify_declared(&manifest, &idx)?;
        let mut attest = OpAttestor::new(manifest.execution_class, manifest.wrappers());
        let sc = manifest.controls();
        let mut ece_v = None;
        let engine = match manifest.execution_class {
            ExecutionClass::ArCausal => Engine::Ar(if idx.metadata.get("enclave_adapter.backend")
                .is_some_and(|name| name == crate::backends::mlx::llama::BACKEND) {
                Box::new(crate::backends::mlx::runtime::MlxLlama::load(&idx, file, &mut attest)?)
            } else if idx.metadata.get("enclave_adapter.backend")
                .is_some_and(|name| name == "mlx_bigram_v1") {
                Box::new(crate::backends::mlx::runtime::MlxBigram::load(&idx, file, &mut attest)?)
            } else { Box::new(BigramLm::load(&idx, file)?) }),
            ExecutionClass::DiscriminativeRlcd => {
                let lut = if let Some(lut_bytes) = companion_by_role.get("ece_calibration_lut") {
                    if lut_bytes.starts_with(b"{") || lut_bytes.len() > 60 {
                        let lut_idx = safetensors::parse(lut_bytes)?;
                        let tensor_name = if lut_idx
                            .tensors
                            .contains_key("enclave_adapter.ece_calibration_lut")
                        {
                            "enclave_adapter.ece_calibration_lut"
                        } else if lut_idx.tensors.contains_key("ece_calibration_lut") {
                            "ece_calibration_lut"
                        } else {
                            fail!(EINVAL, "COMPANION_LUT_TENSOR_MISSING");
                        };
                        let lut_v = lut_idx.f32(lut_bytes, tensor_name, &[ece::BINS])?;
                        CalibrationLut::from_tensor(&lut_v)?
                    } else if lut_bytes.len() == ece::BINS * 4 {
                        let mut v = Vec::with_capacity(ece::BINS);
                        for chunk in lut_bytes.as_chunks::<4>().0 {
                            v.push(f32::from_le_bytes(*chunk));
                        }
                        CalibrationLut::from_tensor(&v)?
                    } else {
                        fail!(EINVAL, "COMPANION_LUT_SHAPE");
                    }
                } else {
                    let lut_v =
                        idx.f32(file, "enclave_adapter.ece_calibration_lut", &[ece::BINS])?;
                    if let Some(d) = &manifest.calibration.ece_calibration_lut_blake3 {
                        let t = &idx.tensors["enclave_adapter.ece_calibration_lut"];
                        if blake3::hash(&file[t.range.0..t.range.1]).to_hex().as_str() != d {
                            fail!(EACCES, "ECE_LUT_DIGEST_MISMATCH");
                        }
                    }
                    CalibrationLut::from_tensor(&lut_v)?
                };

                let c = calib.ok_or_else(|| {
                    err!(
                        EACCES,
                        "ECE_CORPUS_REQUIRED",
                        "RLCD admission requires enclave-calib-eval-v1"
                    )
                })?;
                let backend: Box<dyn RlcdBackend> = if idx.metadata.get("enclave_adapter.backend")
                    .is_some_and(|name| name == "coreml_linear_v1") {
                    Box::new(crate::backends::coreml::runtime::CoreMlLinear::load(&idx, file, &mut attest)?)
                } else { Box::new(LinearHead::load(&idx, file)?) };
                ece_v = Some(ece::verify_with_model(
                    backend.as_ref(),
                    &lut,
                    c.corpus,
                    c.pinned_blake3,
                    manifest.calibration.ece_max,
                )?);
                let fanin = manifest.max_provenance_fanin.unwrap_or(64);
                attest.admit(crate::topology::OpFamily::ClassifierHead)?;
                Engine::Rlcd(RlcdGate::new(
                    backend,
                    lut,
                    profile,
                    controls.qif_cap_mb,
                    controls.margin,
                    fanin,
                )?)
            }
            ExecutionClass::DiscreteDiffusion => Engine::Diffusion(DiffusionGate::new(
                if idx.metadata.get("enclave_adapter.backend")
                    .is_some_and(|name| name == crate::backends::mlx::llada::BACKEND) {
                    // Moved out so the multi-MB JSON is freed once parsed,
                    // before the gate builds its vocabulary trie.
                    let tokenizer = idx.metadata.remove(crate::backends::mlx::llada::TOKENIZER_KEY)
                        .ok_or_else(|| err!(EACCES, "TOKENIZER_MISSING"))?;
                    Box::new(crate::backends::mlx::runtime::MlxLlada::load(&idx, tokenizer, file, &mut attest)?)
                } else { Box::new(BigramDenoiser::load(&idx, file)?) },
                Box::new(ReferenceProbe),
                controls.max_steps,
                controls.max_output_bytes,
            )?
            .with_deadline(std::time::Duration::from_millis(controls.diffusion_deadline_ms.into()))),
            ExecutionClass::RecurrentSsmTtt => Engine::Ssm(StateSnapshotDag::new(
                if idx.metadata.get("enclave_adapter.backend")
                    .is_some_and(|name| name == crate::backends::mlx::rwkv7::BACKEND) {
                    Box::new(crate::backends::mlx::rwkv7::MlxRwkv7::load(&idx, file, &mut attest)?)
                } else { Box::new(DiagonalSsm::load(&idx, file)?) },
                controls.anchor_window,
                controls.anchor_alpha,
                controls.max_output_bytes,
            )?),
            ExecutionClass::ByteOrConcept => {
                let backend = ReferenceConcept::load(&idx, file)?;
                let d = crate::classes::byte_concept::ConceptBackend::width(&backend);
                let leace = Leace::new(&rows(&idx, file, "enclave_adapter.leace_nullspace", d)?)?;
                let canaries = if idx.shape("enclave_adapter.sonar_canaries").is_some() {
                    rows(&idx, file, "enclave_adapter.sonar_canaries", d)?
                } else {
                    vec![]
                };
                let sigma_min = sc
                    .smooth_lcm_sigma_min
                    .ok_or_else(|| err!(EACCES, "SMOOTH_LCM_SIGMA_MIN_REQUIRED"))?
                    as f32;
                let params = ConceptParams {
                    sigma: sigma_min,
                    sigma_min,
                    max_norm: 4.0,
                    canary_cos: sc.sonar_canary_cos_threshold.unwrap_or(0.88) as f32,
                    max_output_bytes: controls.max_output_bytes,
                };
                Engine::Concept(ConceptGate::new(
                    Box::new(backend),
                    leace,
                    canaries,
                    params,
                )?)
            }
            ExecutionClass::SpeculativeOrRecurrentDepth if idx.metadata.get("enclave_adapter.backend")
                .is_some_and(|name| name == crate::backends::mlx::eagle3::BACKEND) => {
                Engine::Depth(DepthGate::speculative(
                    Box::new(crate::backends::mlx::eagle3::MlxEagle3::load(&idx, file, &mut attest)?),
                    thermal,
                    controls.r_max_nominal,
                    controls.r_max_fair,
                    controls.max_output_bytes,
                )?)
            }
            ExecutionClass::SpeculativeOrRecurrentDepth => {
                let backend = ReferenceDepth::load(&idx, file)?;
                let d = crate::classes::speculative::DepthBackend::width(&backend);
                let w = idx.f32(file, "enclave_adapter.latent_probe.weight", &[d])?;
                let tau = metadata_threshold(&idx, "enclave_adapter.latent_probe.tau", 0.9)?;
                Engine::Depth(DepthGate::new(
                    Box::new(backend),
                    LatentProbe { w, tau },
                    thermal,
                    controls.r_max_nominal,
                    controls.r_max_fair,
                    controls.max_output_bytes,
                )?)
            }
            ExecutionClass::JepaEbmWorldPlanner => {
                let caps = manifest
                    .world_planner_caps
                    .clone()
                    .ok_or_else(|| err!(EACCES, "WORLD_PLANNER_CAPS_REQUIRED"))?;
                let e_alpha = idx.f32(file, "enclave_adapter.conformal_energy_lut", &[1])?[0];
                let tau_cone = metadata_threshold(&idx, "enclave_adapter.safety_cone.tau", 0.5)?;
                let model: Box<dyn crate::classes::world::WorldModel> = if idx.metadata.get("enclave_adapter.backend")
                    .is_some_and(|name| name == crate::backends::mlx::vjepa2::BACKEND) {
                    Box::new(crate::backends::mlx::vjepa2::MlxVjepa2::load(&idx, file, &mut attest)?)
                } else { Box::new(ReferenceJepa::load(&idx, file)?) };
                Engine::World(WorldGate::new(
                    model,
                    caps,
                    tau_cone,
                    e_alpha,
                )?)
            }
        };
        let identity = BackendIdentity::of(&idx, &manifest);
        let topology_fingerprint = idx.fingerprint()?;
        Ok(Self {
            manifest,
            controls,
            engine,
            attest,
            features,
            ece: ece_v,
            identity,
            topology_fingerprint,
        })
    }
}

fn metadata_threshold(idx: &TensorIndex, name: &str, default: f32) -> EnclaveResult<f32> {
    match idx.metadata.get(name) {
        Some(value) => value
            .parse()
            .map_err(|_| err!(EINVAL, "SAFETY_THRESHOLD_INVALID", "{name}")),
        None => Ok(default),
    }
}
