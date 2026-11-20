//! `enclave-pack` reference model zoo: deterministic, tiny checkpoints for
//! every `ExecutionClass`, laid out in the `enclave_adapter.*` namespace with
//! the structural signatures the topology verifier expects. Used by the CLI
//! (`depot-enclave model admit --class`) in development mode and by tests.

use std::sync::OnceLock;

use enclave_core::error::EnclaveResult;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::manifest::ExecutionClass;
use crate::safetensors::build_f32;

/// Deterministic weights in `[-scale, scale]`.
pub fn weights(seed: &str, n: usize, scale: f32) -> Vec<f32> {
    let mut out = vec![0u8; n * 4];
    blake3::Hasher::new_derive_key("depot enclave-pack zoo v1")
        .update(seed.as_bytes())
        .finalize_xof()
        .fill(&mut out);
    out.as_chunks::<4>()
        .0
        .iter()
        .map(|c| (u32::from_le_bytes(*c) as f64 / u32::MAX as f64 * 2.0 - 1.0) as f32 * scale)
        .collect()
}

fn eye(d: usize, s: f32) -> Vec<f32> {
    (0..d * d)
        .map(|i| if i % (d + 1) == 0 { s } else { 0.0 })
        .collect()
}

/// Independently labelled synthetic routing-task fixture. Labels are determined
/// by the task schedule below, never by model predictions, confidence or ECE bins.
/// This is test data, not evidence of production/semantic calibration.
pub fn calibrated_corpus() -> Vec<u8> {
    static CORPUS: OnceLock<Vec<u8>> = OnceLock::new();
    CORPUS.get_or_init(|| {
        let mut bytes = Vec::new();
        for i in 0..900 {
            let y = match i % 30 { 0..=8 => 0, 9..=15 => 1, 16..=22 => 2, _ => 3 };
            let priority = ["routine", "important", "urgent", "critical"][y];
            let item = json!({"x": format!("synthetic routing ticket {i}: priority={priority}"), "y": y});
            serde_json::to_writer(&mut bytes, &item).expect("fixture JSON");
            bytes.push(b'\n');
        }
        bytes
    }).clone()
}

/// Constant-prior reference head for the synthetic routing task, not an NLP model.
pub fn rlcd_reference_weights() -> Vec<f32> {
    vec![0.0; 4 * 64]
}
/// Its class prior is (0.3, 7/30, 7/30, 7/30).
pub fn rlcd_reference_bias() -> Vec<f32> {
    vec![(9.0f32 / 7.0).ln(), 0.0, 0.0, 0.0]
}

/// Identity LUT (bin midpoints).
pub fn identity_lut() -> Vec<f32> {
    (0..15).map(|i| (i as f32 + 0.5) / 15.0).collect()
}

/// Bigram table that strongly prefers spelling `text` cyclically.
pub fn spelling_bigram(text: &[u8], strength: f32) -> Vec<f32> {
    let mut t = vec![0f32; 256 * 256];
    for w in text.windows(2) {
        t[w[0] as usize * 256 + w[1] as usize] += strength;
    }
    t
}

/// A packaged reference model.
#[derive(Debug, Clone)]
pub struct Packaged {
    /// `.safetensors` bytes.
    pub weights: Vec<u8>,
    /// Manifest (JSON value; artifact digests filled from `weights`).
    pub manifest: Value,
    /// Calibration corpus (Class 1).
    pub corpus: Option<Vec<u8>>,
}

impl Packaged {
    /// Point the manifest at a CAS root (after UID 702 admission).
    pub fn set_cas_root(&mut self, root: &str) {
        self.manifest["artifact"]["blake3"] = json!(root);
        self.manifest["artifact"]["cas_uri"] = json!(format!("cas://blake3-bao-v1/{root}"));
    }
    /// Manifest bytes.
    pub fn manifest_bytes(&self) -> Vec<u8> {
        serde_json::to_vec_pretty(&self.manifest).unwrap_or_default()
    }
}

/// Build the reference checkpoint for `class`.
pub fn package(class: ExecutionClass) -> EnclaveResult<Packaged> {
    let d = 16usize;
    type Spec<'a> = (
        Vec<(&'a str, Vec<usize>, Vec<f32>)>,
        Vec<(&'a str, &'a str)>,
        Value,
    );
    let (tensors, meta, extra): Spec<'_> = match class {
        ExecutionClass::ArCausal => (
            vec![
                (
                    "lm_head.weight",
                    vec![300, 8],
                    weights("ar.lm_head", 2400, 0.1),
                ),
                (
                    "enclave_adapter.ar.bigram",
                    vec![256, 256],
                    spelling_bigram(br#"{"ok":true}"#, 4.0),
                ),
            ],
            vec![],
            json!({}),
        ),
        ExecutionClass::DiscriminativeRlcd => (
            vec![
                (
                    "enclave_adapter.rlcd_head.weight",
                    vec![4, 64],
                    rlcd_reference_weights(),
                ),
                (
                    "enclave_adapter.rlcd_head.bias",
                    vec![4],
                    rlcd_reference_bias(),
                ),
                (
                    "enclave_adapter.ece_calibration_lut",
                    vec![15],
                    identity_lut(),
                ),
            ],
            vec![],
            json!({}),
        ),
        ExecutionClass::DiscreteDiffusion => (
            vec![
                (
                    "enclave_adapter.diffusion.bigram",
                    vec![256, 256],
                    spelling_bigram(br#"{"action":"close","ticket":12,"notify":false}"#, 2.0),
                ),
                (
                    "enclave_adapter.diffusion.t_embed.weight",
                    vec![64, 8],
                    weights("diff.t", 512, 0.1),
                ),
            ],
            vec![("is_causal", "false")],
            json!({"output_caps": {"max_output_bytes": 4096, "max_diffusion_steps": 16}}),
        ),
        ExecutionClass::RecurrentSsmTtt => (
            vec![
                ("backbone.mixer.A_log", vec![d], vec![-1.0; d]),
                (
                    "enclave_adapter.ssm.embed",
                    vec![256, d],
                    weights("ssm.e", 256 * d, 0.5),
                ),
                (
                    "enclave_adapter.ssm.out",
                    vec![d, 256],
                    weights("ssm.o", 256 * d, 0.5),
                ),
                (
                    "enclave_adapter.ssm.h_sys",
                    vec![d],
                    weights("ssm.h", d, 0.3),
                ),
            ],
            vec![],
            json!({"security_controls": {"ssm_anchor_reinject_tokens": 64, "ssm_zeroize_on_taint_exit": true, "anchor_mix_alpha": 1.0}}),
        ),
        ExecutionClass::ByteOrConcept => (
            vec![
                (
                    "enclave_adapter.lcm.sonar_encoder.proj",
                    vec![d, 64],
                    weights("lcm.p", 64 * d, 1.0),
                ),
                (
                    "enclave_adapter.lcm.concept_denoiser.weight",
                    vec![d, d],
                    eye(d, 1.0),
                ),
                (
                    "enclave_adapter.leace_nullspace",
                    vec![2, d],
                    weights("lcm.leace", 2 * d, 1.0),
                ),
                (
                    "enclave_adapter.sonar_canaries",
                    vec![1, d],
                    weights("lcm.canary", d, 1.0),
                ),
            ],
            vec![(
                "enclave_adapter.lcm.codebook",
                r#"["ticket closed","escalate to tier two","refund approved"]"#,
            )],
            json!({"security_controls": {"smooth_lcm_sigma_min": 0.01, "sonar_canary_cos_threshold": 0.88}}),
        ),
        ExecutionClass::SpeculativeOrRecurrentDepth => (
            vec![
                (
                    "enclave_adapter.recurrent_core.embed",
                    vec![256, d],
                    weights("depth.e", 256 * d, 0.5),
                ),
                (
                    "enclave_adapter.latent_thought_proj.weight",
                    vec![d, d],
                    weights("depth.c", d * d, 0.3),
                ),
                (
                    "enclave_adapter.recurrent_core.out",
                    vec![256, d],
                    weights("depth.o", 256 * d, 1.0),
                ),
                (
                    "enclave_adapter.eagle_fc.weight",
                    vec![256, 256],
                    spelling_bigram(b"ok ok ok ", 1.0),
                ),
                (
                    "enclave_adapter.latent_probe.weight",
                    vec![d],
                    weights("depth.probe", d, 1.0),
                ),
            ],
            vec![
                ("num_recurrent_steps", "8"),
                ("enclave_adapter.latent_probe.tau", "0.995"),
            ],
            json!({"security_controls": {"max_recurrent_depth_nominal": 8, "max_recurrent_depth_fair_thermal": 4}}),
        ),
        ExecutionClass::JepaEbmWorldPlanner => (
            vec![
                (
                    "enclave_adapter.context_encoder.weight",
                    vec![8, 64],
                    weights("jepa.enc", 512, 1.0),
                ),
                (
                    "enclave_adapter.predictor.weight",
                    vec![8, 16],
                    weights("jepa.pred", 128, 0.5),
                ),
                (
                    "enclave_adapter.ebm_cost_head.weight",
                    vec![8],
                    vec![1.0; 8],
                ),
                (
                    "enclave_adapter.safety_cone.weight",
                    vec![8],
                    weights("jepa.cone", 8, 0.1),
                ),
                ("enclave_adapter.conformal_energy_lut", vec![1], vec![50.0]),
            ],
            vec![("enclave_adapter.safety_cone.tau", "0.9")],
            json!({"output_caps": {"max_output_bytes": 4096}, "world_planner_caps": {"max_horizon": 3, "max_candidates": 16, "max_cem_iters": 2, "e_max": 100.0, "step_wallclock_ms": 150, "tau_surprise": 0.35, "actuation_sandbox": "cdp_browser"}}),
        ),
    };
    let w = build_f32(&tensors, &meta);
    let b3 = blake3::hash(&w).to_hex().to_string();
    let mut m = json!({
        "v": 1,
        "model_id": format!("zoo-{}", class.name().to_ascii_lowercase().replace('_', "-")),
        "execution_class": class.name(),
        "artifact": {"cas_uri": format!("cas://blake3-bao-v1/{b3}"), "blake3": b3, "sha256": hex::encode(Sha256::digest(&w)), "format": "safetensors"},
        "tensor_namespace": format!("enclave_adapter.zoo.{}", class.name().to_ascii_lowercase()),
        "stateless_across_rpc": true,
        "output_caps": {"max_output_bytes": 4096},
        "calibration": {"ece_max": 0.015, "bins": 15, "binning": "equal_mass", "dataset": "enclave-calib-eval-v1"},
        "max_provenance_fanin": 64,
        "license_policy": {"spdx_id": "Apache-2.0", "allow_p2p_seeding": false}
    });
    if let Value::Object(e) = extra {
        for (k, v) in e {
            m[k] = v;
        }
    }
    if class == ExecutionClass::SpeculativeOrRecurrentDepth {
        m["output_caps"]["max_steps"] = json!(16);
    }
    Ok(Packaged {
        weights: w,
        manifest: m,
        corpus: (class == ExecutionClass::DiscriminativeRlcd).then(calibrated_corpus),
    })
}
