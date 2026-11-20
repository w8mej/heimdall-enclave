//! Two-layer anti-misclassification attestation (FS-701 §3.1):
//!
//! 1. **Static** structural detection over tensor names, ranks, shapes and
//!    `__metadata__` — upstream signatures (`mixer.A_log`, `time_mix_*`, RWKV-7 `att.k_k`,
//!    bidirectional masks, ...) are matched structurally; depot adapter heads
//!    live under `enclave_adapter.*` (`F-009`).
//! 2. **Runtime** compute-graph operator attestation: every operator family
//!    the reference runtime instantiates passes [`OpAttestor::admit`], which
//!    faults (`EACCES`) unless the signed class (or wrapper) authorises it.

use std::collections::BTreeSet;

use enclave_core::error::EnclaveResult;
use enclave_core::{err, fail};
use serde::{Deserialize, Serialize};

use crate::manifest::{ExecutionClass, ModelManifestV1};
use crate::safetensors::TensorIndex;

/// Structural features found in a checkpoint.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Features {
    /// Generative `lm_head` `[vocab, d_model]` with `vocab > 260`.
    pub generative_lm_head: bool,
    /// State-space / linear-RNN / fast-weight tensors.
    pub recurrent_state: bool,
    /// Non-causal attention (`is_causal == false`) or absorbing mask slot.
    pub bidirectional: bool,
    /// Flow-matching timestep conditioning.
    pub diffusion_timestep: bool,
    /// `BLT` entropy patcher or 256..260 byte vocabulary.
    pub byte_level: bool,
    /// `LCM` / `SONAR` concept stack.
    pub concept: bool,
    /// Shared-weight recurrent depth (`num_recurrent_steps > 1`) or latent thought.
    pub recurrent_depth: bool,
    /// Speculative draft head.
    pub draft_head: bool,
    /// JEPA context encoder + predictor.
    pub jepa: bool,
    /// Scalar EBM cost head / configurator.
    pub ebm_head: bool,
    /// Typed classification / calibration heads.
    pub rlcd_head: bool,
    /// Calibration LUT tensor present.
    pub ece_lut: bool,
}

fn any(idx: &TensorIndex, pred: impl Fn(&str) -> bool) -> bool {
    idx.tensors.keys().any(|k| pred(k))
}

/// Detect features.
pub fn detect(idx: &TensorIndex) -> Features {
    let meta = |k: &str| idx.metadata.get(k).map(String::as_str);
    let byte_vocab = idx.tensors.iter().any(|(k, t)| {
        (k.ends_with("embed_tokens.weight") || k.ends_with("byte_embed.weight"))
            && t.shape.len() == 2
            && (256..=260).contains(&t.shape[0])
    });
    Features {
        generative_lm_head: idx
            .tensors
            .iter()
            .any(|(k, t)| k.ends_with("lm_head.weight") && t.shape.len() == 2 && t.shape[0] > 260),
        recurrent_state: any(idx, |k| {
            k.contains("mixer.A_log")
                || k.contains("dt_proj")
                || k.contains("time_mix_")
                || k.contains("neural_memory.fast_w")
                || k.contains(".ssm.")
                // RWKV-7: per-head key normalisation and decay LoRA base.
                || k.ends_with(".att.k_k")
                || k.ends_with(".att.w0")
        }),
        bidirectional: meta("is_causal") == Some("false")
            || any(idx, |k| {
                k.contains("mask_token") || k.contains("absorbing_embed")
            }),
        diffusion_timestep: any(idx, |k| k.contains(".t_embed.")),
        byte_level: byte_vocab || any(idx, |k| k.contains("entropy_patcher")),
        concept: any(idx, |k| {
            k.contains("sonar_encoder") || k.contains("concept_denoiser")
        }),
        recurrent_depth: meta("num_recurrent_steps")
            .and_then(|s| s.parse::<u32>().ok())
            .is_some_and(|r| r > 1)
            || any(idx, |k| {
                k.contains("latent_thought_proj") || k.contains("recurrent_core")
            }),
        draft_head: any(idx, |k| k.contains("eagle_fc") || k.contains("medusa_head")),
        jepa: (any(idx, |k| k.contains("context_encoder")) && any(idx, |k| k.contains("predictor")))
            // V-JEPA 2: tubelet patch encoder plus a mask-token latent predictor.
            || (any(idx, |k| k.starts_with("encoder.embeddings.patch_embeddings."))
                && any(idx, |k| k.starts_with("predictor.embeddings.mask_tokens"))),
        ebm_head: any(idx, |k| {
            k.contains("ebm_cost_head") || k.contains("configurator")
        }),
        rlcd_head: any(idx, |k| {
            k.contains("rlcd_head") || k.contains("choice_proj")
        }),
        ece_lut: any(idx, |k| k.contains("ece_calibration_lut")),
    }
}

/// The primary class the structure demands.
pub fn structural_class(f: &Features) -> EnclaveResult<ExecutionClass> {
    Ok(if f.recurrent_state {
        // Any single recurrent / TTT layer upgrades the whole (hybrid) graph.
        ExecutionClass::RecurrentSsmTtt
    } else if f.jepa || f.ebm_head {
        if f.generative_lm_head {
            fail!(EACCES, "JEPA_WITH_LM_HEAD");
        }
        ExecutionClass::JepaEbmWorldPlanner
    } else if f.byte_level || f.concept {
        ExecutionClass::ByteOrConcept
    } else if f.bidirectional || f.diffusion_timestep {
        ExecutionClass::DiscreteDiffusion
    } else if f.rlcd_head && !f.generative_lm_head {
        ExecutionClass::DiscriminativeRlcd
    } else if f.recurrent_depth && !f.generative_lm_head {
        ExecutionClass::SpeculativeOrRecurrentDepth
    } else if f.generative_lm_head {
        ExecutionClass::ArCausal
    } else {
        fail!(EACCES, "TOPOLOGY_UNCLASSIFIABLE")
    })
}

/// Static admission: the signed class must equal the structural class; depth /
/// draft structure requires the speculative wrapper; fingerprints must match.
pub fn verify_declared(m: &ModelManifestV1, idx: &TensorIndex) -> EnclaveResult<Features> {
    let f = detect(idx);
    if m.execution_class == ExecutionClass::DiscriminativeRlcd && f.generative_lm_head {
        fail!(EACCES, "GENERATIVE_LM_HEAD_IN_RLCD");
    }
    let s = structural_class(&f)?;
    let declared = m.execution_class;
    // A speculative / recurrent-depth backbone may be declared primarily as
    // SPECULATIVE when its base is causal.
    let ok = s == declared
        || (declared == ExecutionClass::SpeculativeOrRecurrentDepth
            && s == ExecutionClass::ArCausal
            && (f.recurrent_depth || f.draft_head));
    if !ok {
        fail!(
            EACCES,
            "EXECUTION_CLASS_MISMATCH",
            "signed {} but topology is {}",
            declared.name(),
            s.name()
        );
    }
    let spec_ok = declared == ExecutionClass::SpeculativeOrRecurrentDepth
        || m.wrappers()
            .contains(&ExecutionClass::SpeculativeOrRecurrentDepth);
    if (f.draft_head || (f.recurrent_depth && s != ExecutionClass::SpeculativeOrRecurrentDepth))
        && !spec_ok
    {
        fail!(EACCES, "SPECULATIVE_WRAPPER_REQUIRED");
    }
    let has_companion_lut = m
        .companion_safety_layers
        .as_ref()
        .is_some_and(|cs| cs.iter().any(|c| c.role == "ece_calibration_lut"));
    if declared == ExecutionClass::DiscriminativeRlcd && !f.ece_lut && !has_companion_lut {
        fail!(EACCES, "ECE_CALIBRATION_LUT_MISSING");
    }
    if let Some(fp) = &m.topology_fingerprint_blake3 {
        if *fp != idx.fingerprint()? {
            fail!(EACCES, "TOPOLOGY_FINGERPRINT_MISMATCH");
        }
    }
    Ok(f)
}

/// Runtime operator families.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum OpFamily {
    /// Causal attention / left-to-right decode.
    CausalDecode,
    /// Typed classification head.
    ClassifierHead,
    /// Non-causal mask (`is_causal == false`).
    BidirectionalMask,
    /// Iterative denoising.
    DenoiseStep,
    /// `scan` / persistent recurrent state carry-over.
    PersistentStateScan,
    /// Byte patcher / byte decode.
    ByteDecode,
    /// Concept encode / denoise / decode.
    ConceptDiffusion,
    /// Recurrent depth loop (`r > 1`) / hidden-to-embedding feedback.
    RecurrentDepthLoop,
    /// Speculative draft tree.
    DraftTree,
    /// JEPA encode / predict.
    JepaPredict,
    /// MPC / CEM rollout optimiser.
    MpcRollout,
}

/// Families each class authorises.
pub fn authorised(c: ExecutionClass) -> &'static [OpFamily] {
    use OpFamily::*;
    match c {
        ExecutionClass::ArCausal => &[CausalDecode],
        ExecutionClass::DiscriminativeRlcd => &[ClassifierHead],
        ExecutionClass::DiscreteDiffusion => &[BidirectionalMask, DenoiseStep],
        ExecutionClass::RecurrentSsmTtt => &[PersistentStateScan, CausalDecode],
        ExecutionClass::ByteOrConcept => &[ByteDecode, ConceptDiffusion],
        ExecutionClass::SpeculativeOrRecurrentDepth => {
            &[RecurrentDepthLoop, DraftTree, CausalDecode]
        }
        ExecutionClass::JepaEbmWorldPlanner => &[JepaPredict, MpcRollout],
    }
}

/// Runtime attestor bound to the signed class + wrappers.
#[derive(Debug, Clone)]
pub struct OpAttestor {
    allowed: BTreeSet<OpFamily>,
    log: Vec<OpFamily>,
}

impl OpAttestor {
    /// Bind.
    pub fn new(primary: ExecutionClass, wrappers: &[ExecutionClass]) -> Self {
        let allowed = std::iter::once(primary)
            .chain(wrappers.iter().copied())
            .flat_map(|c| authorised(c).iter().copied())
            .collect();
        Self {
            allowed,
            log: Vec::new(),
        }
    }
    /// Admit an operator instantiation.
    pub fn admit(&mut self, op: OpFamily) -> EnclaveResult<()> {
        if !self.allowed.contains(&op) {
            fail!(
                EACCES,
                "GRAPH_OP_NOT_AUTHORISED",
                "{op:?} not authorised by the signed ExecutionClass"
            );
        }
        if self.log.last() != Some(&op) && self.log.len() < 4096 {
            self.log.push(op);
        }
        Ok(())
    }
    /// Digest of the bounded, adjacent-deduplicated reference family log.
    /// This is not a graph IR, model identity or measurement of framework execution.
    pub fn operator_family_log_digest(&self) -> String {
        let b = serde_json::to_vec(&self.log).unwrap_or_default();
        blake3::hash(&b).to_hex().to_string()
    }
    /// Whether an op is allowed (no logging).
    pub fn allows(&self, op: OpFamily) -> bool {
        self.allowed.contains(&op)
    }
}

/// Convenience: fail unless `idx` holds tensor `name`.
pub fn require(idx: &TensorIndex, name: &str) -> EnclaveResult<()> {
    idx.tensors
        .get(name)
        .map(|_| ())
        .ok_or_else(|| err!(EINVAL, "TENSOR_MISSING", "{name}"))
}
