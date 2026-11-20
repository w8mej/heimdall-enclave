//! Development-only model run driver (L1 alpha).
//!
//! Runs the bound execution class once through the agent runtime (UID 704):
//! BeginTurn with the prompt as an attachment, one turn-scoped generation,
//! then FinishTurn. UID 704 resolves the prompt from its verified heap, UID
//! 701 applies every class gate and output guard, and the output is sealed
//! into a managed handle. This driver reports that handle as a receipt and
//! never sees model plaintext. It is refused outside the development fleet.

use enclave_agent_runtime::model_turn::{Action, ArgSchema, ModelTurnRequest, PlanInput, ResolvedTarget};
use enclave_agent_runtime::service::{IfcRequest, IfcResponse};
use enclave_core::daemon::DaemonId;
use enclave_core::error::EnclaveResult;
use enclave_core::ifc_envelope::IfcEnvelopeV1;
use enclave_core::ipc::Client;
use enclave_core::label::Label;
use enclave_core::user_turn::{AttachmentRef, UserTurnV1};
use enclave_core::{err, fail};
use enclave_model_runnerd::manifest::ExecutionClass;
use enclave_model_runnerd::service::{RunnerRequest, RunnerResponse};
use serde_json::{json, Value};

use crate::ctl::Env;

/// Largest generation length the driver will request.
pub const MAX_RUN_BYTES: u32 = 4096;
/// Draft width for speculative decoding requests.
const DRAFT_WIDTH: u32 = 4;
/// Side of the square synthetic world-model frame.
const FRAME_SIDE: u32 = 8;
/// Synthetic origin the world-model sample is confined to.
const SAMPLE_ORIGIN: &str = "https://owned.invalid";
/// Attachment name the prompt is submitted under.
const PROMPT_ATTACHMENT: &str = "$paste_0";
/// The driver declassifies nothing, so its turn needs no QIF budget.
const TURN_BUDGET_MB: i64 = 0;

/// Caller-supplied sample parameters.
#[derive(Debug, Clone, Default)]
pub struct RunInput {
    /// Prompt bytes for classes that take one.
    pub prompt: String,
    /// Bytes to generate (block length for structured classes).
    pub n: u32,
    /// Track C: take the `A2` session lease (one Touch ID) at turn start.
    pub lease: bool,
    /// Track C: `A3`-reveal the sealed output on the trusted display after
    /// one Touch ID. The plaintext never reaches this driver.
    pub reveal: bool,
}

/// Run one sample request against the bound model, which must be `class`.
pub fn model_run(env: &Env, class: ExecutionClass, input: &RunInput) -> EnclaveResult<Value> {
    if !env.dev {
        fail!(EPERM, "MODEL_RUN_DEVELOPMENT_ONLY");
    }
    if input.n == 0 || input.n > MAX_RUN_BYTES {
        fail!(EINVAL, "MODEL_RUN_LENGTH", "1..={MAX_RUN_BYTES}");
    }
    if input.prompt.is_empty() && needs_prompt(class) {
        fail!(EINVAL, "MODEL_RUN_PROMPT_REQUIRED", "{} takes a prompt", class.name());
    }
    // Status is an operator read; generation itself goes only through UID 704.
    let status: RunnerResponse = env.connect(DaemonId::ModelRunner)?.call(&RunnerRequest::Status)?;
    let bound = bound_class(&status)?;
    if bound != class.name() {
        fail!(EINVAL, "MODEL_RUN_CLASS_MISMATCH", "bound {bound}, requested {}", class.name());
    }
    let mut runtime = env.connect(DaemonId::AgentRuntime)?;
    let (turn_id, prompt) = begin_turn(&mut runtime, &input.prompt)?;
    let steps = turn_steps(&mut runtime, class, &turn_id, prompt, input);
    // Always end the lifetime; a failed step is reported as cancelled.
    let finished = ifc(&mut runtime, IfcRequest::FinishTurn { turn_id: turn_id.clone(), cancelled: steps.is_err() });
    let (lease, sealed, revealed) = steps?;
    finished?;
    let mut receipt = json!({ "class": class.name(), "route": "uid704-turn", "turn_id": turn_id, "result": render(&sealed) });
    if let Some(lease) = lease { receipt["lease"] = lease; }
    if let Some(revealed) = revealed { receipt["revealed"] = revealed; }
    Ok(receipt)
}

/// Lease (optional), generate, reveal (optional), all inside one turn.
type Steps = (Option<Value>, IfcEnvelopeV1, Option<Value>);

fn turn_steps(client: &mut Client, class: ExecutionClass, turn_id: &str, prompt: Option<String>, input: &RunInput)
    -> EnclaveResult<Steps>
{
    let lease = if input.lease {
        match ifc(client, IfcRequest::BeginSessionLease { turn_id: turn_id.to_owned() })? {
            IfcResponse::SessionLeased { d_jcs, factors } => Some(json!({ "action": "A2", "d_jcs": d_jcs, "factors": factors })),
            _ => fail!(EIO, "MODEL_RUN_LEASE_REPLY"),
        }
    } else { None };
    let sealed = generate(client, class, turn_id, prompt, input.n)?;
    let revealed = if input.reveal {
        let request = IfcRequest::RevealTurnHandle { turn_id: turn_id.to_owned(), handle: sealed.handle.clone() };
        match ifc(client, request)? {
            IfcResponse::Revealed { d_jcs } => Some(json!({ "action": "A3", "display": "helper-secure-sheet", "d_jcs": d_jcs })),
            _ => fail!(EIO, "MODEL_RUN_REVEAL_REPLY"),
        }
    } else { None };
    Ok((lease, sealed, revealed))
}

/// Classes whose sample request reads the prompt.
fn needs_prompt(class: ExecutionClass) -> bool {
    matches!(class, ExecutionClass::RecurrentSsmTtt | ExecutionClass::SpeculativeOrRecurrentDepth)
}

fn ifc(client: &mut Client, request: IfcRequest) -> EnclaveResult<IfcResponse> {
    client.call(&request)
}

/// Open a turn carrying the prompt (if any) as one attachment; returns the
/// turn id and the prompt's heap handle.
fn begin_turn(client: &mut Client, prompt: &str) -> EnclaveResult<(String, Option<String>)> {
    let bytes = prompt.as_bytes();
    let (refs, payloads) = if bytes.is_empty() {
        (Vec::new(), Vec::new())
    } else {
        let reference = AttachmentRef {
            handle: PROMPT_ATTACHMENT.into(), label: Label::ATTACHMENT_DEFAULT,
            blake3: blake3::hash(bytes).to_hex().to_string(), kind: None,
        };
        (vec![reference], vec![(PROMPT_ATTACHMENT.to_owned(), bytes.to_vec().into())])
    };
    let turn = UserTurnV1 { directive_short: "development model run".into(), attachments: refs };
    let request = IfcRequest::BeginTurn { turn, attachments: payloads, tools: Vec::new(), holder_pk: None, budget_mb: TURN_BUDGET_MB };
    let IfcResponse::TurnPlan { turn_id, context, .. } = ifc(client, request)? else {
        fail!(EIO, "MODEL_RUN_TURN_REPLY");
    };
    Ok((turn_id, context.attachment_stubs.into_iter().next()))
}

/// One turn-scoped generation for `class`, sealed by UID 704.
fn generate(client: &mut Client, class: ExecutionClass, turn_id: &str, prompt: Option<String>, n: u32)
    -> EnclaveResult<IfcEnvelopeV1>
{
    let turn_id = turn_id.to_owned();
    let model = |request| IfcRequest::ModelGenerateTurn { turn_id: turn_id.clone(), request };
    let required = |prompt: Option<String>| prompt.ok_or_else(|| err!(EINVAL, "MODEL_RUN_PROMPT_REQUIRED"));
    let reply = match class {
        // A prompt goes to whatever is bound: a real checkpoint (SmolLM2,
        // LLaDA) reads it; byte-level reference engines refuse a non-empty
        // one, so callers of those send none.
        ExecutionClass::ArCausal | ExecutionClass::DiscreteDiffusion => ifc(client, model(ModelTurnRequest::Structured {
            schema: sample_schema(), len: n, prompt,
        }))?,
        ExecutionClass::RecurrentSsmTtt => {
            let handles = vec![required(prompt)?];
            ifc(client, IfcRequest::SsmIngestTurnHandles { turn_id: turn_id.clone(), handles })?;
            ifc(client, IfcRequest::SsmGenerateTurn { turn_id: turn_id.clone(), n })?
        }
        ExecutionClass::SpeculativeOrRecurrentDepth => {
            ifc(client, model(ModelTurnRequest::Think { prompt: required(prompt)?, n, k: DRAFT_WIDTH }))?
        }
        ExecutionClass::JepaEbmWorldPlanner => ifc(client, model(ModelTurnRequest::Plan(sample_plan())))?,
        other => fail!(ENOSYS, "MODEL_RUN_CLASS_UNSUPPORTED", "{} is outside the L1 alpha", other.name()),
    };
    match reply {
        IfcResponse::Handle(sealed) => Ok(sealed),
        _ => fail!(EIO, "MODEL_RUN_GENERATE_REPLY"),
    }
}

/// Read the bound class from the runner status line (`... class=NAME ...`).
fn bound_class(status: &RunnerResponse) -> EnclaveResult<String> {
    let RunnerResponse::Status(status) = status else {
        fail!(EIO, "MODEL_RUN_STATUS");
    };
    status
        .state
        .split_whitespace()
        .find_map(|field| field.strip_prefix("class="))
        .map(str::to_owned)
        .ok_or_else(|| err!(EPERM, "MODEL_RUN_UNBOUND"))
}

/// Fixed tool-argument schema used for the structured classes.
fn sample_schema() -> ArgSchema {
    let levels = ["routine", "important", "urgent", "critical"];
    ArgSchema::Object(vec![(
        "priority".into(),
        ArgSchema::Enum(levels.iter().map(|level| (*level).to_owned()).collect()),
    )])
}

/// One plan step over a synthetic gray frame toward a synthetic goal frame.
fn sample_plan() -> PlanInput {
    let pixels = (FRAME_SIDE * FRAME_SIDE) as usize;
    let tool_id = 1;
    PlanInput {
        w: FRAME_SIDE,
        h: FRAME_SIDE,
        px: vec![91; pixels].into(),
        goal_px: vec![64; pixels].into(),
        pii_boxes: vec![],
        scroll_velocity: 0,
        tools_mask: 1 << tool_id,
        origins: vec![SAMPLE_ORIGIN.into()],
        candidates: vec![Action {
            tool_id,
            params_q: vec![0],
            target: ResolvedTarget {
                app_bundle_id: "org.example.browser".into(),
                ax_role: "AXButton".into(),
                ax_title: "Continue".into(),
                url_origin: SAMPLE_ORIGIN.into(),
                dom_selector: "#owned".into(),
            },
        }],
    }
}

/// Receipt for a sealed output: identity and label only, never the bytes.
fn render(sealed: &IfcEnvelopeV1) -> Value {
    json!({
        "kind": "sealed",
        "handle": sealed.handle,
        "value_type": sealed.value_type,
        "label": format!("{:?}", sealed.label),
        "provenance_parents": sealed.provenance_parents.as_ref().map_or(0, Vec::len),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use enclave_core::ipc::DaemonStatus;

    fn status(state: &str) -> RunnerResponse {
        RunnerResponse::Status(DaemonStatus {
            daemon_uid: 701,
            binary: "enclave-model-runnerd".into(),
            pid: 1,
            rss_bytes: 0,
            rss_ceiling_bytes: 0,
            boot_epoch_id: String::new(),
            rpc_seq_u64: 0,
            state: state.into(),
            phys_footprint_bytes: 0,
            phys_footprint_source: Default::default(),
        })
    }

    #[test]
    fn bound_class_reads_the_status_field() {
        let class = bound_class(&status("model=m class=AR_CAUSAL profile=L1")).unwrap();
        assert_eq!(class, "AR_CAUSAL");
    }

    #[test]
    fn unbound_runner_is_refused() {
        assert!(bound_class(&status("unbound profile=L1")).unwrap_err().is("MODEL_RUN_UNBOUND"));
    }

    #[test]
    fn sample_plan_is_a_valid_turn_request() {
        let plan = sample_plan();
        assert!(plan.candidates.iter().all(|a| plan.tools_mask & (1 << a.tool_id) != 0));
        assert!(ModelTurnRequest::Plan(plan).validate().is_ok());
    }

    #[test]
    fn production_environment_is_refused_before_any_connection() {
        let mut env = Env::dev(std::path::Path::new("/nonexistent-state"), enclave_core::profile::Profile::L1);
        env.dev = false;
        let input = RunInput { prompt: "x".into(), n: 8, ..Default::default() };
        let error = model_run(&env, ExecutionClass::ArCausal, &input).unwrap_err();
        assert!(error.is("MODEL_RUN_DEVELOPMENT_ONLY"));
    }

    #[test]
    fn out_of_range_length_is_refused_before_any_connection() {
        let env = Env::dev(std::path::Path::new("/nonexistent-state"), enclave_core::profile::Profile::L1);
        for n in [0, MAX_RUN_BYTES + 1] {
            let input = RunInput { prompt: "x".into(), n, ..Default::default() };
            assert!(model_run(&env, ExecutionClass::ArCausal, &input).unwrap_err().is("MODEL_RUN_LENGTH"));
        }
    }

    #[test]
    fn prompt_classes_refuse_an_empty_prompt_before_any_connection() {
        let env = Env::dev(std::path::Path::new("/nonexistent-state"), enclave_core::profile::Profile::L1);
        let input = RunInput { prompt: String::new(), n: 8, ..Default::default() };
        for class in [ExecutionClass::RecurrentSsmTtt, ExecutionClass::SpeculativeOrRecurrentDepth] {
            assert!(model_run(&env, class, &input).unwrap_err().is("MODEL_RUN_PROMPT_REQUIRED"));
        }
    }

    /// The runtime's mirrored wire types must decode as the runner's own
    /// requests and replies, field for field.
    #[test]
    fn runtime_wire_types_round_trip_through_the_runner_types() {
        use enclave_agent_runtime::model_turn::{RunnerCall, RunnerReply};
        let schema = sample_schema();
        let structured = ModelTurnRequest::Structured { schema: schema.clone(), len: 16, prompt: Some("h".into()) };
        let bytes = enclave_core::ipc::to_cbor(&RunnerCall::of(&structured, Some(b"hi")).unwrap()).unwrap();
        let RunnerRequest::GenerateStructured { schema: decoded, len, prompt } = enclave_core::ipc::from_cbor(&bytes).unwrap() else {
            panic!("GenerateStructured expected");
        };
        assert_eq!(enclave_core::ipc::to_cbor(&decoded).unwrap(), enclave_core::ipc::to_cbor(&schema).unwrap());
        assert_eq!((len, prompt.as_deref().map(|p| p.as_ref())), (16, Some(&b"hi"[..])));

        let think = ModelTurnRequest::Think { prompt: "h".into(), n: 8, k: 4 };
        let bytes = enclave_core::ipc::to_cbor(&RunnerCall::of(&think, Some(b"seed")).unwrap()).unwrap();
        assert!(matches!(enclave_core::ipc::from_cbor(&bytes).unwrap(), RunnerRequest::Think { n: 8, k: 4, .. }));

        let plan = ModelTurnRequest::Plan(sample_plan());
        let bytes = enclave_core::ipc::to_cbor(&RunnerCall::of(&plan, None).unwrap()).unwrap();
        let RunnerRequest::Plan { candidates, tools_mask, origins, actuate, .. } = enclave_core::ipc::from_cbor(&bytes).unwrap() else {
            panic!("Plan expected");
        };
        assert_eq!((candidates[0].target.url_origin.as_str(), tools_mask, origins.len()), (SAMPLE_ORIGIN, 2, 1));
        // A turn-scoped plan can never ask the runner to act.
        assert!(!actuate);

        let action = enclave_core::ipc::from_cbor(&enclave_core::ipc::to_cbor(&candidates[0]).unwrap()).unwrap();
        let reply = RunnerResponse::Planned { action, vetoes: 1, actuated: false };
        let decoded: RunnerReply = enclave_core::ipc::from_cbor(&enclave_core::ipc::to_cbor(&reply).unwrap()).unwrap();
        assert!(matches!(decoded, RunnerReply::Planned { vetoes: 1, actuated: false, .. }));
        let text: RunnerReply = enclave_core::ipc::from_cbor(&enclave_core::ipc::to_cbor(&RunnerResponse::Text(b"x".to_vec().into())).unwrap()).unwrap();
        assert!(matches!(text, RunnerReply::Text(b) if b.as_ref() == b"x"));
    }
}
