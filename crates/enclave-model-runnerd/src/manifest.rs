//! `enclave-model.manifest.json` (FS-701 §3.2,
//! `schemas/enclave-model.manifest.schema.json`). Parsing rejects unknown
//! fields; [`ModelManifestV1::validate`] enforces every schema bound plus the
//! class-conditional requirements, failing closed with a reason code.

use enclave_core::error::EnclaveResult;
use enclave_core::profile::Profile;
use enclave_core::{err, fail};
use serde::{Deserialize, Serialize};

/// Largest diffusion deadline any manifest may sign: below the 30 s IPC
/// timeout of the runtime that waits on the runner, so the caller never
/// gives up on a generation that still holds the service mutex (F-139).
pub const MAX_DIFFUSION_DEADLINE_MS: u32 = 20_000;

/// Diffusion deadline when the manifest signs none.
pub const DEFAULT_DIFFUSION_DEADLINE_MS: u32 = 2_000;

/// Longest one diffusion generation may hold the runner at `profile`:
/// stricter profiles bound the stall one caller can impose on the rest.
pub fn diffusion_deadline_ceiling_ms(profile: Profile) -> u32 {
    match profile {
        Profile::L1 => MAX_DIFFUSION_DEADLINE_MS,
        Profile::L2 => 10_000,
        Profile::L3 => 5_000,
    }
}

/// Closed Tier-1 taxonomy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ExecutionClass {
    /// Baseline causal transformer.
    ArCausal,
    /// Class 1: `jev`-class typed classifiers / ANE guard heads.
    DiscriminativeRlcd,
    /// Class 2: `LLaDA` / `Dream` / `FS-DFM`.
    DiscreteDiffusion,
    /// Class 3: `Mamba-3` / `RWKV-7` / `Titans` / `TTT`.
    RecurrentSsmTtt,
    /// Class 4: `BLT` / `LCM`.
    ByteOrConcept,
    /// Class 5: `Huginn` / `COCONUT` / `EAGLE-3` / `Medusa`.
    SpeculativeOrRecurrentDepth,
    /// Class 6: `V-JEPA 2-AC` / `H-JEPA` + `EBM` planners.
    JepaEbmWorldPlanner,
}

impl ExecutionClass {
    /// Wire name.
    pub fn name(self) -> &'static str {
        match self {
            Self::ArCausal => "AR_CAUSAL",
            Self::DiscriminativeRlcd => "DISCRIMINATIVE_RLCD",
            Self::DiscreteDiffusion => "DISCRETE_DIFFUSION",
            Self::RecurrentSsmTtt => "RECURRENT_SSM_TTT",
            Self::ByteOrConcept => "BYTE_OR_CONCEPT",
            Self::SpeculativeOrRecurrentDepth => "SPECULATIVE_OR_RECURRENT_DEPTH",
            Self::JepaEbmWorldPlanner => "JEPA_EBM_WORLD_PLANNER",
        }
    }
    /// Parse the wire name (CLI `--class`); also accepts `1`..`6`.
    pub fn parse(s: &str) -> EnclaveResult<Self> {
        Ok(match s {
            "AR_CAUSAL" | "0" => Self::ArCausal,
            "DISCRIMINATIVE_RLCD" | "1" => Self::DiscriminativeRlcd,
            "DISCRETE_DIFFUSION" | "2" => Self::DiscreteDiffusion,
            "RECURRENT_SSM_TTT" | "3" => Self::RecurrentSsmTtt,
            "BYTE_OR_CONCEPT" | "4" => Self::ByteOrConcept,
            "SPECULATIVE_OR_RECURRENT_DEPTH" | "5" => Self::SpeculativeOrRecurrentDepth,
            "JEPA_EBM_WORLD_PLANNER" | "6" => Self::JepaEbmWorldPlanner,
            _ => fail!(EINVAL, "UNKNOWN_EXECUTION_CLASS", "{s}"),
        })
    }
}

/// Artifact block.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Artifact {
    /// `cas://blake3-bao-v1/<root>[?...]`.
    pub cas_uri: String,
    /// BLAKE3 root.
    pub blake3: String,
    /// SHA-256.
    pub sha256: String,
    /// Format.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
}

/// Output caps.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutputCaps {
    /// `<= 65536`.
    pub max_output_bytes: u32,
    /// `<= 64` (required for diffusion).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_diffusion_steps: Option<u32>,
    /// Diffusion generation deadline (ms), `1..=MAX_DIFFUSION_DEADLINE_MS`;
    /// diffusion only. Bind refuses a value above the profile's ceiling.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub diffusion_deadline_ms: Option<u32>,
    /// `<= 4096`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_concept_patches: Option<u32>,
    /// `<= 32`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_steps: Option<u32>,
}

/// Calibration block.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Calibration {
    /// `<= 0.015`.
    pub ece_max: f64,
    /// `15`.
    pub bins: u32,
    /// `equal_mass`.
    pub binning: String,
    /// `enclave-calib-eval-v1`.
    pub dataset: String,
    /// LUT digest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ece_calibration_lut_blake3: Option<String>,
}

/// `world_planner_caps`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorldPlannerCaps {
    /// `<= 5`.
    pub max_horizon: u32,
    /// `<= 64`.
    pub max_candidates: u32,
    /// `<= 4`.
    pub max_cem_iters: u32,
    /// `(0, 1000]`.
    pub e_max: f64,
    /// `<= 150`.
    pub step_wallclock_ms: u32,
    /// `> 0`.
    pub tau_surprise: f64,
    /// `cdp_browser`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actuation_sandbox: Option<String>,
}

/// Companion layer.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompanionLayer {
    /// Role.
    pub role: String,
    /// CAS URI.
    pub cas_uri: String,
    /// Eager hydration.
    pub eager_hydrate_required: bool,
    /// `<= 48`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_size_mib: Option<u32>,
}

/// License policy.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LicensePolicy {
    /// SPDX id.
    pub spdx_id: String,
    /// Seeding.
    pub allow_p2p_seeding: bool,
    /// Notice digest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attribution_notice_blake3: Option<String>,
}

/// Apple-silicon dispatch hints.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppleSiliconDispatch {
    /// `M1`..`M5`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_chip: Option<String>,
    /// `>= 8`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_unified_ram_gb: Option<u32>,
    /// Backend.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preferred_backend: Option<String>,
    /// ANE MIL subgraphs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ane_mil_subgraphs: Option<Vec<String>>,
}

/// Security controls.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityControls {
    /// Minimum swarm profile.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_swarm_profile: Option<String>,
    /// `<= 12000`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub qif_max_millibits_per_record: Option<i64>,
    /// `<= 2048`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssm_anchor_reinject_tokens: Option<u32>,
    /// Must be `true`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssm_zeroize_on_taint_exit: Option<bool>,
    /// `<= 32`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_recurrent_depth_nominal: Option<u32>,
    /// `<= 8`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_recurrent_depth_fair_thermal: Option<u32>,
    /// `[0.25, 1.0]`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub anchor_mix_alpha: Option<f64>,
    /// `> 0`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub smooth_lcm_sigma_min: Option<f64>,
    /// `[0.5, 1.0]`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sonar_canary_cos_threshold: Option<f64>,
    /// `>= 0.001`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub threshold_margin_fail_closed: Option<f64>,
}

/// The manifest.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelManifestV1 {
    /// `1`.
    pub v: u32,
    /// Model id.
    pub model_id: String,
    /// Primary class.
    pub execution_class: ExecutionClass,
    /// Upstream checkpoint (informational).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upstream_checkpoint: Option<String>,
    /// Artifact.
    pub artifact: Artifact,
    /// `enclave_adapter.*`.
    pub tensor_namespace: String,
    /// Must be `true` when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stateless_across_rpc: Option<bool>,
    /// Output caps.
    pub output_caps: OutputCaps,
    /// Calibration.
    pub calibration: Calibration,
    /// `<= 64`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_provenance_fanin: Option<u32>,
    /// Class 6 caps.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub world_planner_caps: Option<WorldPlannerCaps>,
    /// Companions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub companion_safety_layers: Option<Vec<CompanionLayer>>,
    /// License.
    pub license_policy: LicensePolicy,
    /// Wrappers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auxiliary_wrappers: Option<Vec<ExecutionClass>>,
    /// Topology fingerprint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub topology_fingerprint_blake3: Option<String>,
    /// Dispatch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub apple_silicon_dispatch: Option<AppleSiliconDispatch>,
    /// Controls.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub security_controls: Option<SecurityControls>,
}

fn is_hex64(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn cas_root(uri: &str) -> Option<&str> {
    let rest = uri.strip_prefix("cas://blake3-bao-v1/")?;
    let root = rest.split('?').next()?;
    is_hex64(root).then_some(root)
}

fn range<T: PartialOrd + Copy + std::fmt::Display>(
    v: T,
    lo: T,
    hi: T,
    reason: &str,
) -> EnclaveResult<()> {
    if v < lo || v > hi {
        fail!(EINVAL, reason, "{v} not in [{lo}, {hi}]");
    }
    Ok(())
}

impl ModelManifestV1 {
    /// Parse JSON (unknown fields rejected).
    pub fn from_json(b: &[u8]) -> EnclaveResult<Self> {
        let m: Self =
            serde_json::from_slice(b).map_err(|e| err!(EINVAL, "MANIFEST_SCHEMA", "{e}"))?;
        m.validate()?;
        Ok(m)
    }

    /// Wrappers (deduplicated by validation).
    pub fn wrappers(&self) -> &[ExecutionClass] {
        self.auxiliary_wrappers.as_deref().unwrap_or(&[])
    }

    /// Effective security controls.
    pub fn controls(&self) -> SecurityControls {
        self.security_controls.clone().unwrap_or_default()
    }

    /// Minimum swarm profile (default `L1`).
    pub fn min_profile(&self) -> EnclaveResult<Profile> {
        match self
            .security_controls
            .as_ref()
            .and_then(|c| c.min_swarm_profile.as_deref())
        {
            None => Ok(Profile::L1),
            Some(p) => Profile::parse(p),
        }
    }

    /// Enforce the schema and class-conditional rules.
    pub fn validate(&self) -> EnclaveResult<()> {
        if self.v != 1 {
            fail!(EINVAL, "MANIFEST_VERSION");
        }
        if self.model_id.is_empty() || self.model_id.len() > 128 {
            fail!(EINVAL, "MANIFEST_MODEL_ID");
        }
        if self
            .upstream_checkpoint
            .as_ref()
            .is_some_and(|u| u.len() > 256)
        {
            fail!(EINVAL, "MANIFEST_UPSTREAM");
        }
        let a = &self.artifact;
        let root = cas_root(&a.cas_uri).ok_or_else(|| err!(EINVAL, "MANIFEST_CAS_URI"))?;
        if !is_hex64(&a.blake3) || !is_hex64(&a.sha256) {
            fail!(EINVAL, "MANIFEST_DIGEST");
        }
        if root != a.blake3 {
            fail!(
                EACCES,
                "MANIFEST_CAS_ROOT_MISMATCH",
                "cas_uri root != artifact.blake3"
            );
        }
        if a.format
            .as_deref()
            .is_some_and(|f| !matches!(f, "safetensors" | "gguf" | "mlpackage"))
        {
            fail!(EINVAL, "MANIFEST_FORMAT");
        }
        let ns = self
            .tensor_namespace
            .strip_prefix("enclave_adapter.")
            .ok_or_else(|| err!(EACCES, "TENSOR_NAMESPACE_NOT_ENCLAVE_ADAPTER", "F-009"))?;
        if ns.is_empty()
            || !ns
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'.')
        {
            fail!(EACCES, "TENSOR_NAMESPACE_NOT_ENCLAVE_ADAPTER", "F-009");
        }
        if self.stateless_across_rpc == Some(false) {
            fail!(EACCES, "STATEFUL_ACROSS_RPC", "F-027");
        }
        let c = &self.output_caps;
        range(c.max_output_bytes, 1, 65_536, "OUTPUT_CAP_BYTES")?;
        if let Some(s) = c.max_diffusion_steps {
            range(s, 1, 64, "OUTPUT_CAP_DIFFUSION_STEPS")?;
        }
        if let Some(ms) = c.diffusion_deadline_ms {
            range(ms, 1, MAX_DIFFUSION_DEADLINE_MS, "OUTPUT_CAP_DIFFUSION_DEADLINE")?;
            if self.execution_class != ExecutionClass::DiscreteDiffusion {
                fail!(EINVAL, "DIFFUSION_DEADLINE_WITHOUT_DIFFUSION");
            }
        }
        if let Some(s) = c.max_concept_patches {
            range(s, 1, 4096, "OUTPUT_CAP_CONCEPT_PATCHES")?;
        }
        if let Some(s) = c.max_steps {
            range(s, 1, 32, "OUTPUT_CAP_STEPS")?;
        }
        let k = &self.calibration;
        if !k.ece_max.is_finite() || !(0.0..=0.015).contains(&k.ece_max) {
            fail!(EACCES, "ECE_MAX_ABOVE_0_015", "{}", k.ece_max);
        }
        if k.bins != 15 || k.binning != "equal_mass" || k.dataset != "enclave-calib-eval-v1" {
            fail!(
                EINVAL,
                "CALIBRATION_PROTOCOL",
                "15 equal-mass bins over enclave-calib-eval-v1"
            );
        }
        if k.ece_calibration_lut_blake3
            .as_ref()
            .is_some_and(|d| !is_hex64(d))
        {
            fail!(EINVAL, "MANIFEST_DIGEST");
        }
        if self.max_provenance_fanin.is_some_and(|f| f > 64) {
            fail!(E2BIG, "PROVENANCE_FANIN_EXCEEDED");
        }
        if let Some(w) = &self.world_planner_caps {
            range(w.max_horizon, 1, 5, "WORLD_PLANNER_HORIZON")?;
            range(w.max_candidates, 1, 64, "WORLD_PLANNER_CANDIDATES")?;
            range(w.max_cem_iters, 1, 4, "WORLD_PLANNER_CEM_ITERS")?;
            if !(w.e_max.is_finite() && w.e_max > 0.0 && w.e_max <= 1000.0) {
                fail!(EINVAL, "WORLD_PLANNER_E_MAX");
            }
            range(w.step_wallclock_ms, 1, 150, "WORLD_PLANNER_WALLCLOCK")?;
            if !(w.tau_surprise.is_finite() && w.tau_surprise > 0.0) {
                fail!(EINVAL, "WORLD_PLANNER_TAU_SURPRISE");
            }
            if w.actuation_sandbox
                .as_deref()
                .is_some_and(|s| s != "cdp_browser")
            {
                fail!(EACCES, "ACTUATION_SANDBOX_NOT_CDP", "OQ-21");
            }
        }
        if let Some(cs) = &self.companion_safety_layers {
            if cs.len() > 16 {
                fail!(E2BIG, "COMPANIONS_TOO_MANY");
            }
            for l in cs {
                if l.role.is_empty() || l.role.len() > 64 || cas_root(&l.cas_uri).is_none() {
                    fail!(EINVAL, "COMPANION_SCHEMA");
                }
                if let Some(m) = l.max_size_mib {
                    range(m, 1, 48, "COMPANION_SIZE")?;
                }
            }
        }
        let l = &self.license_policy;
        if l.spdx_id.is_empty()
            || l.spdx_id.len() > 64
            || l.attribution_notice_blake3
                .as_ref()
                .is_some_and(|d| !is_hex64(d))
        {
            fail!(EINVAL, "LICENSE_POLICY");
        }
        let w = self.wrappers();
        for (i, x) in w.iter().enumerate() {
            if *x != ExecutionClass::SpeculativeOrRecurrentDepth || w[..i].contains(x) {
                fail!(EINVAL, "AUXILIARY_WRAPPER");
            }
        }
        if self
            .topology_fingerprint_blake3
            .as_ref()
            .is_some_and(|d| !is_hex64(d))
        {
            fail!(EINVAL, "MANIFEST_DIGEST");
        }
        if let Some(d) = &self.apple_silicon_dispatch {
            if d.min_chip
                .as_deref()
                .is_some_and(|c| !matches!(c, "M1" | "M2" | "M3" | "M4" | "M5"))
            {
                fail!(EINVAL, "DISPATCH_MIN_CHIP");
            }
            if d.min_unified_ram_gb.is_some_and(|r| r < 8) {
                fail!(EINVAL, "DISPATCH_RAM");
            }
            if d.preferred_backend
                .as_deref()
                .is_some_and(|b| !matches!(b, "MLX_METAL" | "COREML_ANE" | "COREML_GPU"))
            {
                fail!(EINVAL, "DISPATCH_BACKEND");
            }
        }
        if let Some(s) = &self.security_controls {
            if let Some(p) = &s.min_swarm_profile {
                Profile::parse(p)?;
            }
            if let Some(q) = s.qif_max_millibits_per_record {
                range(q, 0, 12_000, "QIF_MAX_PER_RECORD")?;
            }
            if let Some(w) = s.ssm_anchor_reinject_tokens {
                range(w, 1, 2048, "SSM_ANCHOR_WINDOW")?;
            }
            if s.ssm_zeroize_on_taint_exit == Some(false) {
                fail!(EACCES, "SSM_ZEROIZE_REQUIRED");
            }
            if let Some(r) = s.max_recurrent_depth_nominal {
                range(r, 1, 32, "RECURRENT_DEPTH_NOMINAL")?;
            }
            if let Some(r) = s.max_recurrent_depth_fair_thermal {
                range(r, 1, 8, "RECURRENT_DEPTH_FAIR")?;
            }
            if let Some(a) = s.anchor_mix_alpha {
                if !(0.25..=1.0).contains(&a) {
                    fail!(EINVAL, "ANCHOR_MIX_ALPHA");
                }
            }
            if s.smooth_lcm_sigma_min
                .is_some_and(|x| !(x.is_finite() && x > 0.0))
            {
                fail!(EINVAL, "SMOOTH_LCM_SIGMA_MIN");
            }
            if let Some(t) = s.sonar_canary_cos_threshold {
                if !(0.5..=1.0).contains(&t) {
                    fail!(EINVAL, "SONAR_CANARY_THRESHOLD");
                }
            }
            if s.threshold_margin_fail_closed
                .is_some_and(|m| !(m.is_finite() && m >= 0.001))
            {
                fail!(EINVAL, "THRESHOLD_MARGIN");
            }
        }
        match self.execution_class {
            ExecutionClass::JepaEbmWorldPlanner if self.world_planner_caps.is_none() => {
                fail!(EACCES, "WORLD_PLANNER_CAPS_REQUIRED")
            }
            ExecutionClass::DiscreteDiffusion if self.output_caps.max_diffusion_steps.is_none() => {
                fail!(EACCES, "MAX_DIFFUSION_STEPS_REQUIRED")
            }
            _ => {}
        }
        Ok(())
    }
}
