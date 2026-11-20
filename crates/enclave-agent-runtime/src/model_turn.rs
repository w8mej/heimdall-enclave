//! Turn-scoped UID 704 → UID 701 generation for the non-session classes
//! (AR, discrete diffusion, speculative depth, JEPA world planner).
//!
//! Prompts come only from verified heap handles the turn owns; output is
//! sealed into a new managed handle and never returned as plaintext. The wire
//! types mirror `enclave-model-runnerd` by serde shape, as `ssm.rs` does, so
//! this crate keeps no dependency on the runner.
use enclave_core::error::EnclaveResult;
use enclave_core::fail;
use serde::{Deserialize, Serialize};

/// Largest generation length a turn may request.
pub const MAX_MODEL_TURN_BYTES: u32 = 65536;
/// Largest speculative draft width a turn may request.
pub const MAX_DRAFT_WIDTH: u32 = 16;
/// Largest world-model frame side a turn may supply.
pub const MAX_FRAME_SIDE: u32 = 512;
/// Largest number of planner candidates or allowed origins.
pub const MAX_PLAN_ITEMS: usize = 64;

/// Tool-argument schema (mirrors `enclave_model_runnerd::dfa::ArgSchema`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ArgSchema {
    /// Object with fields in this exact key order.
    Object(Vec<(String, ArgSchema)>),
    /// One of these strings.
    Enum(Vec<String>),
    /// `true` / `false`.
    Bool,
    /// Unsigned integer.
    UInt {
        /// Maximum digits.
        max_digits: u8,
    },
}

/// PII box (mirrors `classes::world::Rect`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rect {
    /// x.
    pub x: usize,
    /// y.
    pub y: usize,
    /// w.
    pub w: usize,
    /// h.
    pub h: usize,
}

/// Resolved actuation target (mirrors `classes::world::ResolvedTarget`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedTarget {
    /// App bundle id.
    pub app_bundle_id: String,
    /// AX role.
    pub ax_role: String,
    /// AX title.
    pub ax_title: String,
    /// Origin.
    pub url_origin: String,
    /// DOM selector.
    pub dom_selector: String,
}

/// Planner candidate (mirrors `classes::world::Action`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Action {
    /// Tool id (bit index in the capability mask).
    pub tool_id: u8,
    /// Resolved target.
    pub target: ResolvedTarget,
    /// Quantized parameters.
    pub params_q: Vec<i8>,
}

/// World-model planning inputs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanInput {
    /// Frame width.
    pub w: u32,
    /// Frame height.
    pub h: u32,
    /// Gray pixels.
    pub px: serde_bytes::ByteBuf,
    /// Goal frame pixels (same size).
    pub goal_px: serde_bytes::ByteBuf,
    /// PII boxes.
    pub pii_boxes: Vec<Rect>,
    /// Scroll velocity (px/s).
    pub scroll_velocity: u32,
    /// Candidates.
    pub candidates: Vec<Action>,
    /// Tool bitmask.
    pub tools_mask: u64,
    /// Allowed origins.
    pub origins: Vec<String>,
}

/// What a turn asks the bound model to do. Prompts are turn-owned heap
/// handle names, never caller bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ModelTurnRequest {
    /// AR or discrete diffusion constrained to `schema`.
    Structured {
        /// Output schema.
        schema: ArgSchema,
        /// Bytes to generate.
        len: u32,
        /// Optional prompt handle (AR only; diffusion refuses prompts).
        prompt: Option<String>,
    },
    /// Speculative decoding.
    Think {
        /// Prompt handle.
        prompt: String,
        /// Bytes to generate.
        n: u32,
        /// Draft width.
        k: u32,
    },
    /// One world-model plan step.
    Plan(PlanInput),
}

impl ModelTurnRequest {
    /// Bounds checked before any lock, heap read or runner call.
    pub fn validate(&self) -> EnclaveResult<()> {
        match self {
            Self::Structured { len, .. } | Self::Think { n: len, .. } if !(1..=MAX_MODEL_TURN_BYTES).contains(len) => {
                fail!(E2BIG, "MODEL_TURN_OUTPUT_BOUNDS")
            }
            Self::Think { k, .. } if !(1..=MAX_DRAFT_WIDTH).contains(k) => fail!(EINVAL, "MODEL_TURN_DRAFT_WIDTH"),
            Self::Plan(p) => validate_plan(p),
            _ => Ok(()),
        }
    }

    /// The prompt handle this request reads, if any.
    pub fn prompt(&self) -> Option<&str> {
        match self {
            Self::Structured { prompt, .. } => prompt.as_deref(),
            Self::Think { prompt, .. } => Some(prompt),
            Self::Plan(_) => None,
        }
    }
}

fn validate_plan(p: &PlanInput) -> EnclaveResult<()> {
    let side_ok = |s: u32| (1..=MAX_FRAME_SIDE).contains(&s);
    if !side_ok(p.w) || !side_ok(p.h) {
        fail!(E2BIG, "MODEL_TURN_FRAME_BOUNDS");
    }
    let pixels = (p.w * p.h) as usize;
    if p.px.len() != pixels || p.goal_px.len() != pixels {
        fail!(EINVAL, "MODEL_TURN_FRAME_SIZE");
    }
    if p.candidates.is_empty() || p.candidates.len() > MAX_PLAN_ITEMS
        || p.origins.len() > MAX_PLAN_ITEMS || p.pii_boxes.len() > MAX_PLAN_ITEMS
    {
        fail!(E2BIG, "MODEL_TURN_PLAN_BOUNDS");
    }
    Ok(())
}

/// The runner call 704 actually sends, with prompt bytes resolved from the heap.
#[derive(Debug, Serialize)]
pub enum RunnerCall<'a> {
    /// `RunnerRequest::GenerateStructured`.
    GenerateStructured {
        /// Schema.
        schema: &'a ArgSchema,
        /// Length.
        len: u32,
        /// Prompt bytes.
        prompt: Option<&'a serde_bytes::Bytes>,
    },
    /// `RunnerRequest::Think`.
    Think {
        /// Prompt bytes.
        prompt: &'a serde_bytes::Bytes,
        /// Length.
        n: u32,
        /// Draft width.
        k: u32,
    },
    /// `RunnerRequest::Plan`.
    Plan {
        /// Width.
        w: u32,
        /// Height.
        h: u32,
        /// Pixels.
        px: &'a serde_bytes::ByteBuf,
        /// PII boxes.
        pii_boxes: &'a [Rect],
        /// Scroll velocity.
        scroll_velocity: u32,
        /// Goal pixels.
        goal_px: &'a serde_bytes::ByteBuf,
        /// Candidates.
        candidates: &'a [Action],
        /// Tool mask.
        tools_mask: u64,
        /// Origins.
        origins: &'a [String],
    },
}

impl<'a> RunnerCall<'a> {
    /// Build the runner call; `prompt` is the verified heap payload, if any.
    pub fn of(req: &'a ModelTurnRequest, prompt: Option<&'a [u8]>) -> EnclaveResult<Self> {
        let bytes = prompt.map(serde_bytes::Bytes::new);
        Ok(match req {
            ModelTurnRequest::Structured { schema, len, .. } => Self::GenerateStructured { schema, len: *len, prompt: bytes },
            ModelTurnRequest::Think { n, k, .. } => {
                let Some(prompt) = bytes else { fail!(EINVAL, "MODEL_TURN_PROMPT_REQUIRED") };
                Self::Think { prompt, n: *n, k: *k }
            }
            ModelTurnRequest::Plan(p) => Self::Plan {
                w: p.w, h: p.h, px: &p.px, pii_boxes: &p.pii_boxes, scroll_velocity: p.scroll_velocity,
                goal_px: &p.goal_px, candidates: &p.candidates, tools_mask: p.tools_mask, origins: &p.origins,
            },
        })
    }
}

/// The runner replies 704 accepts for these calls.
#[derive(Debug, Deserialize)]
pub enum RunnerReply {
    /// Generated bytes.
    Text(serde_bytes::ByteBuf),
    /// Planned action.
    Planned {
        /// Selected action.
        action: Action,
        /// Barrier vetoes.
        vetoes: u32,
        /// Whether UID 701 actuated it.
        actuated: bool,
    },
}

impl RunnerReply {
    /// Bytes to seal: generated text as-is, or a canonical JSON plan summary.
    pub fn into_sealed_bytes(self) -> EnclaveResult<Vec<u8>> {
        match self {
            Self::Text(b) => Ok(b.into_vec()),
            Self::Planned { action, vetoes, actuated } => serde_json::to_vec(&serde_json::json!({
                "tool_id": action.tool_id, "origin": action.target.url_origin,
                "vetoes": vetoes, "actuated": actuated,
            }))
            .map_err(|_| enclave_core::err!(EIO, "MODEL_TURN_PLAN_ENCODE")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan(w: u32, candidates: usize) -> PlanInput {
        let target = ResolvedTarget {
            app_bundle_id: "a".into(), ax_role: "r".into(), ax_title: "t".into(),
            url_origin: "https://owned.invalid".into(), dom_selector: "#x".into(),
        };
        PlanInput {
            w, h: w, px: vec![0; (w * w) as usize].into(), goal_px: vec![0; (w * w) as usize].into(),
            pii_boxes: vec![], scroll_velocity: 0,
            candidates: vec![Action { tool_id: 1, target, params_q: vec![0] }; candidates],
            tools_mask: 2, origins: vec![],
        }
    }

    #[test]
    fn output_length_bounds_are_enforced() {
        let structured = |len| ModelTurnRequest::Structured { schema: ArgSchema::Bool, len, prompt: None };
        for len in [0, MAX_MODEL_TURN_BYTES + 1] {
            assert!(structured(len).validate().unwrap_err().is("MODEL_TURN_OUTPUT_BOUNDS"));
        }
        assert!(structured(8).validate().is_ok());
        let think = |n, k| ModelTurnRequest::Think { prompt: "h".into(), n, k };
        assert!(think(0, 4).validate().unwrap_err().is("MODEL_TURN_OUTPUT_BOUNDS"));
        assert!(think(8, 0).validate().unwrap_err().is("MODEL_TURN_DRAFT_WIDTH"));
        assert!(think(8, MAX_DRAFT_WIDTH + 1).validate().unwrap_err().is("MODEL_TURN_DRAFT_WIDTH"));
    }

    #[test]
    fn plan_frames_and_lists_are_bounded() {
        assert!(ModelTurnRequest::Plan(plan(8, 1)).validate().is_ok());
        assert!(ModelTurnRequest::Plan(plan(0, 1)).validate().unwrap_err().is("MODEL_TURN_FRAME_BOUNDS"));
        assert!(ModelTurnRequest::Plan(plan(8, 0)).validate().unwrap_err().is("MODEL_TURN_PLAN_BOUNDS"));
        let mut short = plan(8, 1);
        short.goal_px = vec![0; 63].into();
        assert!(ModelTurnRequest::Plan(short).validate().unwrap_err().is("MODEL_TURN_FRAME_SIZE"));
    }

    #[test]
    fn think_without_prompt_bytes_is_refused() {
        let think = ModelTurnRequest::Think { prompt: "h".into(), n: 8, k: 4 };
        assert!(RunnerCall::of(&think, None).unwrap_err().is("MODEL_TURN_PROMPT_REQUIRED"));
        assert!(RunnerCall::of(&think, Some(b"hi")).is_ok());
    }

    #[test]
    fn plan_reply_seals_only_the_summary() {
        let p = plan(8, 1);
        let reply = RunnerReply::Planned { action: p.candidates[0].clone(), vetoes: 0, actuated: false };
        let sealed: serde_json::Value = serde_json::from_slice(&reply.into_sealed_bytes().unwrap()).unwrap();
        assert_eq!(sealed["origin"], "https://owned.invalid");
        assert_eq!(sealed["actuated"], false);
    }
}
