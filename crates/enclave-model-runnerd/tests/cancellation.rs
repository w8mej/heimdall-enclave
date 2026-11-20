//! M7: a wipe during real compute releases nothing, for each real-weight
//! model (SmolLM2, RWKV-7, Qwen3+EAGLE-3, V-JEPA 2, LLaDA-8B).
//!
//! Each test times one uncancelled request on the bound package, starts the
//! same request again, and sends `Zeroize` a third of the way in. The request
//! must still be running when the wipe is signalled, and must then fail with
//! `GENERATION_CANCELLED` or `MODEL_RELEASE_FENCED`: no output is returned.
//! Token-loop models must also stop computing early; a world-model plan is
//! one indivisible step that the release fence withholds.
//!
//! Needs target/<name>-pack and MCPMAC_MLX_WORKER; otherwise it reports a
//! skip unless MCPMAC_REQUIRE_CANCELLATION is set.

mod common;

use std::sync::Arc;
use std::time::{Duration, Instant};

use common::{operator, package_or_skip, ONE_MODEL_AT_A_TIME};
use enclave_core::label::Label;
use enclave_model_runnerd::arena::ZeroizeTrigger;
use enclave_model_runnerd::classes::world::{Action, ResolvedTarget};
use enclave_model_runnerd::dfa::ArgSchema;
use enclave_model_runnerd::service::{RunnerRequest, RunnerResponse, RunnerService};

/// Below this, a third of a generation run is too short to land a wipe reliably.
const MIN_COMPUTE: Duration = Duration::from_millis(600);
/// One V-JEPA 2 plan is a fixed ~0.55 s (two ViT-L frame encodes); a wipe at
/// a third of it still lands during the first encode.
const MIN_PLAN_COMPUTE: Duration = Duration::from_millis(400);
/// Reasons that prove the output was withheld.
const WITHHELD: [&str; 2] = ["GENERATION_CANCELLED", "MODEL_RELEASE_FENCED"];
/// World-model frame side the encoder consumes without resizing.
const FRAME_SIDE: u32 = 256;
/// The V-JEPA 2 package's `world_planner_caps.max_candidates`.
const MAX_CANDIDATES: usize = 16;

fn prompt() -> Vec<u8> {
    "The quick brown fox jumps over the lazy dog while the committee reviews the quarterly plan. "
        .repeat(24)
        .into_bytes()
}

/// Builds one request on `service`, including any per-request setup.
type Prepare = dyn Fn(&RunnerService) -> RunnerRequest;

/// How the wipe is expected to end the request.
#[derive(Clone, Copy, PartialEq)]
enum Stops {
    /// The token loop checks the cancel flag and stops early.
    Early,
    /// One indivisible step (a plan) runs out; the release fence withholds it.
    AtFence,
}

fn cancel_mid_compute(dir: &str, min_compute: Duration, stops: Stops, prepare: &Prepare) {
    cancel_mid_compute_of(package_or_skip, dir, min_compute, stops, prepare)
}

fn cancel_mid_compute_of(load: common::Loader, dir: &str, min_compute: Duration, stops: Stops, prepare: &Prepare) {
    let Some(pack) = load(dir, "MCPMAC_REQUIRE_CANCELLATION", "CANCELLATION_CHECKED") else { return };
    let _serial = ONE_MODEL_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    let service: Arc<RunnerService> = pack.runner();
    assert!(matches!(pack.bind_on(&service, &pack.bytes()), Ok(RunnerResponse::Bound { .. })), "{dir}: bind");

    // Two uncancelled runs; the faster (warm) one sets the wipe point, so a
    // slow cold first run cannot push the wipe past the end of the next.
    let compute = (0..2).map(|_| {
        // Setup (fork, prompt ingest) is not part of the timed request.
        let request = prepare(&service);
        let started = Instant::now();
        let baseline = service.handle(&operator(), request);
        assert!(baseline.is_ok(), "{dir}: uncancelled run must succeed: {baseline:?}");
        started.elapsed()
    }).min().unwrap();
    assert!(compute >= min_compute, "{dir}: run took {compute:?}; raise the workload so a wipe lands mid-compute");

    let request = prepare(&service);
    let worker = service.clone();
    let running = std::thread::spawn(move || {
        let started = Instant::now();
        let result = worker.handle(&operator(), request);
        (result, started.elapsed(), Instant::now())
    });
    std::thread::sleep(compute / 3);
    let wipe_signalled = Instant::now();
    let wiped = service.handle(&operator(), RunnerRequest::Zeroize(ZeroizeTrigger::TaskExit));
    let (result, cancelled_run, finished) = running.join().unwrap();

    let outcome = result.as_ref().map(kind).map_err(|e| e.clone());
    assert!(finished > wipe_signalled, "{dir}: request finished before the wipe ({outcome:?}); not a mid-compute cancel");
    let refusal = match result {
        Ok(response) => panic!("{dir}: output released after a wipe: {}", kind(&response)),
        Err(e) => WITHHELD.into_iter().find(|r| e.is(r)).unwrap_or_else(|| panic!("{dir}: unexpected refusal {e:?}")),
    };
    assert!(matches!(wiped, Ok(RunnerResponse::Wiped(_))), "{dir}: wipe must complete: {wiped:?}");
    if stops == Stops::Early {
        // The wipe lands at a third; stopping must not wait for the full run.
        assert!(cancelled_run < compute * 2 / 3, "{dir}: compute ran {cancelled_run:?} of {compute:?} after the wipe");
    }
    eprintln!("CANCELLATION_CHECKED=true; {dir}; compute {compute:?}, wipe at {:?}, cancelled run {cancelled_run:?}, {refusal}", compute / 3);
}

/// Response kind only; never prints model output.
fn kind(response: &RunnerResponse) -> &'static str {
    match response {
        RunnerResponse::Text(_) => "Text",
        RunnerResponse::Ssm { .. } => "Ssm",
        RunnerResponse::Planned { .. } => "Planned",
        _ => "other",
    }
}

#[test]
fn smollm2_cancel_withholds_output() {
    cancel_mid_compute("smollm2-pack", MIN_COMPUTE, Stops::Early, &|_| RunnerRequest::GenerateStructured {
        schema: ArgSchema::UInt { max_digits: 19 },
        len: 24,
        prompt: Some(prompt().into()),
    });
}

#[test]
fn rwkv7_cancel_withholds_output() {
    cancel_mid_compute("rwkv7-pack", MIN_COMPUTE, Stops::Early, &|service| {
        let scope = enclave_core::rng::bytes32();
        let label = Label::BOTTOM;
        service.handle(&operator(), RunnerRequest::SsmForkOwned { scope, label }).unwrap();
        service.handle(&operator(), RunnerRequest::SsmIngestOwned { scope, label, bytes: prompt().into() }).unwrap();
        RunnerRequest::SsmGenerateOwned { scope, n: 128 }
    });
}

#[test]
fn llada_cancel_withholds_output() {
    // A 32-position block over a short chat prompt (the shared long prompt
    // overruns LLaDA's signed deadline): each denoising step is one full
    // bidirectional pass, and the cancel flag is read between steps.
    let prompt = "<|startoftext|><|start_header_id|>user<|end_header_id|>\n\nHow many days are in a leap year? \
        Reply with the number.<|eot_id|><|start_header_id|>assistant<|end_header_id|>\n\n";
    cancel_mid_compute_of(common::mapped_package_or_skip, "llada-pack", MIN_COMPUTE, Stops::Early, &|_| {
        RunnerRequest::GenerateStructured {
            schema: ArgSchema::UInt { max_digits: 19 },
            len: 32,
            prompt: Some(prompt.as_bytes().to_vec().into()),
        }
    });
}

#[test]
fn eagle3_cancel_withholds_output() {
    cancel_mid_compute("eagle3-pack", MIN_COMPUTE, Stops::Early, &|_| RunnerRequest::Think { prompt: prompt().into(), n: 96, k: 4 });
}

#[test]
fn vjepa2_cancel_withholds_output() {
    cancel_mid_compute("vjepa2-pack", MIN_PLAN_COMPUTE, Stops::AtFence, &|_| {
        let pixels = (FRAME_SIDE * FRAME_SIDE) as usize;
        let origin = "https://owned.invalid";
        RunnerRequest::Plan {
            w: FRAME_SIDE,
            h: FRAME_SIDE,
            px: vec![91; pixels].into(),
            goal_px: vec![64; pixels].into(),
            pii_boxes: vec![],
            scroll_velocity: 0,
            tools_mask: 2,
            origins: vec![origin.into()],
            candidates: (0..MAX_CANDIDATES).map(|i| Action {
                tool_id: 1,
                params_q: vec![i as i8 * 4 - 32],
                target: ResolvedTarget {
                    app_bundle_id: "org.example.browser".into(),
                    ax_role: "AXButton".into(),
                    ax_title: "Continue".into(),
                    url_origin: origin.into(),
                    dom_selector: "#owned".into(),
                },
            }).collect(),
            actuate: false,
        }
    });
}
