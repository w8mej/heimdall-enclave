//! Candidate for enclave-model-runnerd/tests/world_step_lifecycle.rs.
//! Synthetic deterministic reference weights and a counting actuator exercise
//! the real service Bind/Plan/Observe paths. This is no browser/model-quality,
//! production authority, ScreenCaptureKit or physical-memory acceptance.

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use enclave_core::error::EnclaveResult;
use enclave_core::ipc::PeerCredentials;
use enclave_core::profile::Profile;
use enclave_model_runnerd::arena::{WeightBytes, ZeroizeTrigger};
use enclave_model_runnerd::classes::speculative::{FixedThermal, PowerSource, ThermalState};
use enclave_model_runnerd::classes::world::{Action, Actuator, Rect, ResolvedTarget};
use enclave_model_runnerd::manifest::ExecutionClass;
use enclave_model_runnerd::safetensors::build_f32;
use enclave_model_runnerd::service::{
    ResolvedWeights, RunnerConfig, RunnerRequest, RunnerResponse, RunnerService, WeightSource,
};
use enclave_model_runnerd::zoo::{package, Packaged};
use serde_json::{json, Value};
use sha2::Digest;

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        use std::os::unix::fs::DirBuilderExt;
        let path = std::env::temp_dir().join(format!("world-step-{}", enclave_core::rng::u64()));
        std::fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.0); }
}

fn checkpoint() -> Packaged {
    let mut p = package(ExecutionClass::JepaEbmWorldPlanner).unwrap();
    // Width one: the encoder reads one pooled pixel. The predictor always
    // predicts 64/255 for tool1, independently of the input state. Consequently
    // observation64 is nominal and observation128 must exceed tau_surprise0.1.
    let mut encoder = vec![0.0; 64];
    encoder[0] = 1.0;
    let mut predictor = vec![0.0; 9];
    predictor[1] = (64.0_f32 / 255.0).atanh() * 64.0;
    p.weights = build_f32(&[
        ("enclave_adapter.context_encoder.weight", vec![1,64], encoder),
        ("enclave_adapter.predictor.weight", vec![1,9], predictor),
        ("enclave_adapter.ebm_cost_head.weight", vec![1], vec![1.0]),
        ("enclave_adapter.safety_cone.weight", vec![1], vec![1.0]),
        ("enclave_adapter.conformal_energy_lut", vec![1], vec![1.0]),
    ], &[("enclave_adapter.safety_cone.tau", "0.9")]);
    let root = blake3::hash(&p.weights).to_hex().to_string();
    p.set_cas_root(&root);
    p.manifest["artifact"]["sha256"] = json!(hex::encode(sha2::Sha256::digest(&p.weights)));
    p.manifest["model_id"] = json!("owned-world-step-reference-fixture");
    p.manifest["world_planner_caps"]["max_horizon"] = json!(1);
    p.manifest["world_planner_caps"]["max_cem_iters"] = json!(1);
    p.manifest["world_planner_caps"]["tau_surprise"] = json!(0.1);
    p
}

struct FixtureWeights(Packaged);
impl WeightSource for FixtureWeights {
    fn resolve(&self, uri: &str) -> EnclaveResult<ResolvedWeights> {
        assert_eq!(uri, self.0.manifest["artifact"]["cas_uri"].as_str().unwrap());
        Ok(ResolvedWeights { primary: WeightBytes::Owned(self.0.weights.clone()), companions: vec![] })
    }
    fn fetch_manifest(&self, id: &str) -> EnclaveResult<Vec<u8>> {
        assert_eq!(id, self.0.manifest["model_id"].as_str().unwrap());
        // Explicit in-process test trust stand-in, not a TUF verification.
        Ok(self.0.manifest_bytes())
    }
}

#[derive(Debug)]
struct CountingActuator {
    calls: Arc<AtomicUsize>,
    fail_after_effect: bool,
}
impl Actuator for CountingActuator {
    fn prepare_bounded(&mut self, _: &Action, _: std::time::Instant) -> EnclaveResult<()> { Ok(()) }
    fn execute_bounded(&mut self, deadline: std::time::Instant) -> EnclaveResult<()> {
        assert!(std::time::Instant::now() < deadline);
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.fail_after_effect { return Err(enclave_core::err!(EIO, "FIXTURE_EFFECT_REPLY_LOST")); }
        Ok(())
    }
    fn execute(&mut self, _: &Action) -> EnclaveResult<()> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.fail_after_effect {
            return Err(enclave_core::err!(EIO, "FIXTURE_EFFECT_REPLY_LOST"));
        }
        Ok(())
    }
}

fn peer() -> PeerCredentials {
    PeerCredentials::local(enclave_core::ipc::geteuid(), enclave_core::ipc::geteuid())
}

fn start(audit: PathBuf) -> (Arc<RunnerService>, Arc<AtomicUsize>) {
    start_with_failure(audit, false)
}
fn start_with_failure(audit: PathBuf, fail_after_effect: bool) -> (Arc<RunnerService>, Arc<AtomicUsize>) {
    let p = checkpoint();
    let calls = Arc::new(AtomicUsize::new(0));
    let service = RunnerService::start(RunnerConfig {
        dev_same_uid: true, profile: Profile::L2, audit_path: Some(audit),
        calib_corpus_blake3: None, state_dir: None,
        thermal: Box::new(|| Box::new(FixedThermal(ThermalState::Nominal, PowerSource::Ac))),
        actuator: Some(Box::new(CountingActuator { calls: calls.clone(), fail_after_effect })),
    }, Box::new(FixtureWeights(p.clone()))).unwrap();
    let bound = service.handle(&peer(), RunnerRequest::Bind {
        manifest: p.manifest_bytes().into(),
        cas_uri: p.manifest["artifact"]["cas_uri"].as_str().unwrap().into(),
        calibration_corpus: None,
    }).unwrap();
    assert!(matches!(bound, RunnerResponse::Bound { class: ExecutionClass::JepaEbmWorldPlanner, .. }));
    (service, calls)
}

fn plan() -> RunnerRequest {
    RunnerRequest::Plan { actuate:true, w:8, h:8, px:vec![0;64].into(), pii_boxes:vec![],
        scroll_velocity:0, goal_px:vec![64;64].into(), tools_mask:2,
        origins:vec!["https://depot-owned.invalid".into()],
        candidates:vec![Action { tool_id:1, params_q:vec![0,0], target:ResolvedTarget {
            app_bundle_id:"org.depot.owned-development-document".into(), ax_role:"AXButton".into(),
            ax_title:"Owned test action".into(), url_origin:"https://depot-owned.invalid".into(),
            dom_selector:"#increment".into(),
        }}],
    }
}
fn observe(pixel: u8) -> RunnerRequest {
    RunnerRequest::Observe { w:8, h:8, px:vec![pixel;64].into(), pii_boxes:vec![] }
}
fn assert_planned(response: RunnerResponse) {
    assert!(matches!(response, RunnerResponse::Planned { actuated:true, .. }));
}

#[test]
fn world_pending_step_blocks_replanning_and_bad_observation_retains_nominal_check() {
    let fixture = Fixture::new();
    let (service, calls) = start(fixture.0.join("audit.jsonl"));
    assert_planned(service.handle(&peer(), plan()).unwrap());
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let invalid = [
        (RunnerRequest::Observe { w:0, h:8, px:vec![64;64].into(), pii_boxes:vec![] }, "FRAME_SHAPE"),
        (RunnerRequest::Observe { w:8, h:8, px:vec![64;64].into(),
            pii_boxes:vec![Rect { x:8, y:0, w:1, h:1 }] }, "PII_RECT_BOUNDS"),
    ];
    assert!(service.handle(&peer(), plan()).unwrap_err().is("WORLD_OBSERVATION_REQUIRED"));
    for (bad, reason) in invalid {
        assert!(service.handle(&peer(), bad).unwrap_err().is(reason));
        assert!(service.handle(&peer(), plan()).unwrap_err().is("WORLD_OBSERVATION_REQUIRED"));
        assert_eq!(calls.load(Ordering::SeqCst), 1, "no second actuator effect while pending");
    }
    assert!(matches!(service.handle(&peer(), observe(64)).unwrap(), RunnerResponse::Ok));
    assert!(service.handle(&peer(), observe(64)).unwrap_err().is("NO_PENDING_STEP"));
    assert_planned(service.handle(&peer(), plan()).unwrap());
    assert_eq!(calls.load(Ordering::SeqCst), 2, "valid comparison permits the next plan");
    assert!(matches!(service.handle(&peer(), RunnerRequest::Zeroize(ZeroizeTrigger::TaskExit)).unwrap(),
        RunnerResponse::Wiped(1)));
}

#[test]
fn world_bad_observation_retains_old_prediction_until_surprise_wipes_episode() {
    let fixture = Fixture::new();
    let audit = fixture.0.join("audit.jsonl");
    let (service, calls) = start(audit.clone());
    assert_planned(service.handle(&peer(), plan()).unwrap());
    assert!(service.handle(&peer(), RunnerRequest::Observe {
        w:8, h:8, px:vec![128;63].into(), pii_boxes:vec![],
    }).unwrap_err().is("FRAME_SHAPE"));
    assert!(service.handle(&peer(), plan()).unwrap_err().is("WORLD_OBSERVATION_REQUIRED"));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert!(service.handle(&peer(), observe(128)).unwrap_err().is("WORLD_MODEL_SURPRISE_ABORT"));
    assert!(service.handle(&peer(), observe(64)).unwrap_err().is("NO_PENDING_STEP"));
    let rows: Vec<Value> = std::fs::read_to_string(&audit).unwrap().lines()
        .map(|line| serde_json::from_str(line).unwrap()).collect();
    let aborted: Vec<_> = rows.iter().filter(|r| r["payload"]["event"] == "WORLD_SURPRISE_ABORT").collect();
    assert_eq!(aborted.len(), 1);
    let payload = &aborted[0]["payload"];
    assert_eq!(payload["error_reason"], "WORLD_MODEL_SURPRISE_ABORT");
    assert_eq!(payload["wipe_reports"]["backend"], "cpu_guarded_arena");
    let reports = payload["wipe_reports"]["reports"].as_array().unwrap();
    assert_eq!(reports.len(), 1);
    assert!(reports[0]["bytes"].as_u64().unwrap() > 0);
    assert_eq!(reports[0]["residual"], 0);
    enclave_core::audit::verify_journal(&audit, None).unwrap();
    assert!(matches!(service.handle(&peer(), RunnerRequest::Zeroize(ZeroizeTrigger::TaskExit)).unwrap(),
        RunnerResponse::Wiped(0)), "surprise already released the episode arena");
    assert_planned(service.handle(&peer(), plan()).unwrap());
    assert_eq!(calls.load(Ordering::SeqCst), 2, "a new episode may replan after the abort");
    assert!(matches!(service.handle(&peer(), RunnerRequest::Zeroize(ZeroizeTrigger::TaskExit)).unwrap(),
        RunnerResponse::Wiped(1)));
}

#[test]
fn world_all_veto_has_no_observation_obligation_and_explicit_wipe_clears_pending() {
    let fixture = Fixture::new();
    let (service, calls) = start(fixture.0.join("audit.jsonl"));
    let mut denied = plan();
    if let RunnerRequest::Plan { tools_mask, .. } = &mut denied { *tools_mask = 0; }
    assert!(service.handle(&peer(), denied).unwrap_err().is("NO_SAFE_ACTION"));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert!(service.handle(&peer(), observe(64)).unwrap_err().is("NO_PENDING_STEP"));
    assert_planned(service.handle(&peer(), plan()).unwrap());
    assert!(matches!(service.handle(&peer(), RunnerRequest::Zeroize(ZeroizeTrigger::TaskExit)).unwrap(),
        RunnerResponse::Wiped(1)));
    assert!(service.handle(&peer(), observe(64)).unwrap_err().is("NO_PENDING_STEP"));
    assert_planned(service.handle(&peer(), plan()).unwrap());
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert!(matches!(service.handle(&peer(), RunnerRequest::Zeroize(ZeroizeTrigger::TaskExit)).unwrap(),
        RunnerResponse::Wiped(1)));
}

#[test]
fn world_actuator_error_retains_pending_until_observation_or_explicit_wipe() {
    let fixture = Fixture::new();
    let (service, calls) = start_with_failure(fixture.0.join("audit.jsonl"), true);
    // The explicitly bounded fixture has already performed its counted effect before
    // returning an error. An uncertain reply cannot authorize another effect.
    assert!(service.handle(&peer(), plan()).unwrap_err().is("FIXTURE_EFFECT_REPLY_LOST"));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert!(service.handle(&peer(), plan()).unwrap_err().is("WORLD_OBSERVATION_REQUIRED"));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert!(matches!(service.handle(&peer(), observe(64)).unwrap(), RunnerResponse::Ok));
    assert!(service.handle(&peer(), plan()).unwrap_err().is("FIXTURE_EFFECT_REPLY_LOST"));
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert!(service.handle(&peer(), plan()).unwrap_err().is("WORLD_OBSERVATION_REQUIRED"));
    assert!(matches!(service.handle(&peer(), RunnerRequest::Zeroize(ZeroizeTrigger::TaskExit)).unwrap(),
        RunnerResponse::Wiped(1)));
    assert!(service.handle(&peer(), observe(64)).unwrap_err().is("NO_PENDING_STEP"));
    assert!(service.handle(&peer(), plan()).unwrap_err().is("FIXTURE_EFFECT_REPLY_LOST"));
    assert_eq!(calls.load(Ordering::SeqCst), 3);
    assert!(service.handle(&peer(), observe(128)).unwrap_err().is("WORLD_MODEL_SURPRISE_ABORT"));
    assert!(matches!(service.handle(&peer(), RunnerRequest::Zeroize(ZeroizeTrigger::TaskExit)).unwrap(),
        RunnerResponse::Wiped(0)));
}

#[test]
fn world_explicit_rebind_unbind_and_fresh_service_clear_old_observation_scope() {
    let fixture = Fixture::new();
    let (service, calls) = start(fixture.0.join("audit.jsonl"));
    assert_planned(service.handle(&peer(), plan()).unwrap());
    for unbind_first in [false, true] {
        if unbind_first {
            assert!(matches!(service.handle(&peer(), RunnerRequest::Unbind).unwrap(), RunnerResponse::Ok));
            assert!(service.handle(&peer(), observe(64)).unwrap_err().is("MODEL_NOT_BOUND"));
        }
        let p = checkpoint();
        assert!(matches!(service.handle(&peer(), RunnerRequest::Bind {
            manifest:p.manifest_bytes().into(),
            cas_uri:p.manifest["artifact"]["cas_uri"].as_str().unwrap().into(),
            calibration_corpus:None,
        }).unwrap(), RunnerResponse::Bound {..}));
        assert!(service.handle(&peer(), observe(64)).unwrap_err().is("NO_PENDING_STEP"));
        assert_planned(service.handle(&peer(), plan()).unwrap());
    }
    assert_eq!(calls.load(Ordering::SeqCst), 3);
    assert!(matches!(service.handle(&peer(), RunnerRequest::Zeroize(ZeroizeTrigger::TaskExit)).unwrap(),
        RunnerResponse::Wiped(1)));
    drop(service);
    // In-process service reconstruction with fresh test state, not an OS boot
    // or durable model/prediction recovery claim.
    let (fresh, calls) = start(fixture.0.join("fresh-service-audit.jsonl"));
    assert!(fresh.handle(&peer(), observe(64)).unwrap_err().is("NO_PENDING_STEP"));
    assert_planned(fresh.handle(&peer(), plan()).unwrap());
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert!(matches!(fresh.handle(&peer(), RunnerRequest::Zeroize(ZeroizeTrigger::TaskExit)).unwrap(),
        RunnerResponse::Wiped(1)));
}
