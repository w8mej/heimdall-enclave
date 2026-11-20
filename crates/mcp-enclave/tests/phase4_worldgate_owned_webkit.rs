//! Candidate for mcp-enclave/tests/phase4_worldgate_owned_webkit.rs.
//! Real owned WebKit + RunnerService Bind/Plan/Observe + CdpSocketActuator.
//! Test images encode the live DOM counter; they are not captured screenshots.
//! The one-dimensional reference checkpoint is a deterministic test fixture,
//! not V-JEPA/perception quality, production authority or privacy acceptance.
#![cfg(all(target_os = "macos", debug_assertions))]

use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use enclave_core::error::EnclaveResult;
use enclave_core::ipc::PeerCredentials;
use enclave_core::profile::Profile;
use enclave_model_runnerd::arena::{WeightBytes, ZeroizeTrigger};
use enclave_model_runnerd::classes::speculative::{FixedThermal, PowerSource, ThermalState};
use enclave_model_runnerd::classes::world::{Action, CdpSocketActuator, ResolvedTarget};
use enclave_model_runnerd::manifest::ExecutionClass;
use enclave_model_runnerd::owned_browser::OWNED_DOCUMENT_ORIGIN;
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
        // Keep AF_UNIX paths short independently of the user's TMPDIR length.
        let p = PathBuf::from("/tmp").join(format!("world-webkit-{:016x}", enclave_core::rng::u64()));
        std::fs::DirBuilder::new().mode(0o700).create(&p).unwrap();
        Self(p)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.0); }
}
struct OwnedChild(Child);
impl Drop for OwnedChild {
    fn drop(&mut self) { let _ = self.0.kill(); let _ = self.0.wait(); }
}

fn send(stream: &mut UnixStream, value: &Value) {
    let mut bytes = serde_json::to_vec(value).unwrap();
    bytes.push(0);
    stream.write_all(&bytes).unwrap();
}
fn receive(stream: &mut UnixStream) -> Option<Value> {
    let mut bytes = Vec::new();
    loop {
        let mut byte = [0];
        match stream.read(&mut byte) {
            Ok(0) => { assert!(bytes.is_empty(), "truncated browser frame"); return None; },
            Ok(1) => {},
            other => panic!("browser relay read: {other:?}"),
        }
        if byte[0] == 0 { return Some(serde_json::from_slice(&bytes).unwrap()); }
        assert!(bytes.len() < 65_535, "bounded browser frame");
        bytes.push(byte[0]);
    }
}
fn inspect(stream: &mut UnixStream, method: &str, params: Value) -> Value {
    send(stream, &json!({"id":1_000_000,"method":method,"params":params}));
    let response = receive(stream).unwrap();
    assert_eq!(response["id"], 1_000_000);
    assert!(response.get("error").is_none(), "{response}");
    response["result"].clone()
}
fn query(stream: &mut UnixStream, selector: &str) -> u64 {
    inspect(stream, "DOM.querySelector", json!({"nodeId":1,"selector":selector}))
        ["nodeId"].as_u64().filter(|n| *n >= 2).unwrap()
}
fn count(stream: &mut UnixStream, node: u64) -> u64 {
    let result = inspect(stream, "DOM.getOuterHTML", json!({"nodeId":node}));
    let html = result["outerHTML"].as_str().unwrap();
    let content = html.split_once('>').unwrap().1.split_once('<').unwrap().0;
    content.parse().unwrap()
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct BrowserFacts {
    forwarded_methods: Vec<String>,
    releases: usize,
    counter: u64,
    decoys: u64,
    hits: Vec<u64>,
}
fn snapshot(facts: &Arc<Mutex<BrowserFacts>>) -> BrowserFacts { facts.lock().unwrap().clone() }

fn checkpoint() -> Packaged {
    let mut p = package(ExecutionClass::JepaEbmWorldPlanner).unwrap();
    let mut encoder = vec![0.0;64]; encoder[0] = 1.0;
    let mut predictor = vec![0.0;9];
    // tool1/64 is the sole nonzero predictor input. tanh returns64/255.
    // The second real increment to128/255 must therefore surprise-abort.
    predictor[1] = (64.0_f32 / 255.0).atanh() * 64.0;
    p.weights = build_f32(&[
        ("enclave_adapter.context_encoder.weight",vec![1,64],encoder),
        ("enclave_adapter.predictor.weight",vec![1,9],predictor),
        ("enclave_adapter.ebm_cost_head.weight",vec![1],vec![1.0]),
        ("enclave_adapter.safety_cone.weight",vec![1],vec![1.0]),
        ("enclave_adapter.conformal_energy_lut",vec![1],vec![1.0]),
    ], &[("enclave_adapter.safety_cone.tau","0.9")]);
    let root = blake3::hash(&p.weights).to_hex().to_string(); p.set_cas_root(&root);
    p.manifest["artifact"]["sha256"] = json!(hex::encode(sha2::Sha256::digest(&p.weights)));
    p.manifest["model_id"] = json!("owned-webkit-world-service-reference-fixture");
    p.manifest["world_planner_caps"]["max_horizon"] = json!(1);
    p.manifest["world_planner_caps"]["max_cem_iters"] = json!(1);
    p.manifest["world_planner_caps"]["tau_surprise"] = json!(0.1);
    p
}
struct FixtureWeights(Packaged);
impl WeightSource for FixtureWeights {
    fn resolve(&self, uri: &str) -> EnclaveResult<ResolvedWeights> {
        assert_eq!(uri,self.0.manifest["artifact"]["cas_uri"].as_str().unwrap());
        Ok(ResolvedWeights { primary:WeightBytes::Owned(self.0.weights.clone()), companions:vec![] })
    }
    fn fetch_manifest(&self,id:&str) -> EnclaveResult<Vec<u8>> {
        assert_eq!(id,self.0.manifest["model_id"].as_str().unwrap());
        // Deliberate test trust stand-in; no TUF target/signature assertion.
        Ok(self.0.manifest_bytes())
    }
}
fn peer() -> PeerCredentials {
    PeerCredentials::local(enclave_core::ipc::geteuid(), enclave_core::ipc::geteuid())
}
fn action(selector:&str,origin:&str) -> Action {
    Action { tool_id:1,params_q:vec![0,0],target:ResolvedTarget {
        app_bundle_id:"org.mcpmac.owned-development-document".into(),ax_role:"AXButton".into(),
        ax_title:"Owned test action".into(),url_origin:origin.into(),dom_selector:selector.into(),
    }}
}
fn plan(counter:u64,candidates:Vec<Action>,tools_mask:u64,origins:Vec<String>) -> RunnerRequest {
    let pixel = u8::try_from(counter.checked_mul(64).unwrap()).unwrap();
    RunnerRequest::Plan {w:8,h:8,px:vec![pixel;64].into(),pii_boxes:vec![],scroll_velocity:0,
        goal_px:vec![64;64].into(),candidates,tools_mask,origins,actuate:true}
}
fn observe(counter:u64) -> RunnerRequest {
    let pixel = u8::try_from(counter.checked_mul(64).unwrap()).unwrap();
    RunnerRequest::Observe {w:8,h:8,px:vec![pixel;64].into(),pii_boxes:vec![]}
}
fn safe_plan(counter:u64) -> RunnerRequest {
    plan(counter,vec![action("#nested-increment",OWNED_DOCUMENT_ORIGIN)],2,
        vec![OWNED_DOCUMENT_ORIGIN.into()])
}

#[test]
fn phase4_world_service_plans_real_owned_webkit_and_requires_observation_before_next_effect() {
    let fixture = Fixture::new();
    let socket = fixture.0.join("b.sock");
    let mut child = OwnedChild(Command::new(env!("CARGO_BIN_EXE_enclave-cdp-browser"))
        .args(["--owned-webkit","--dev-same-uid"]).arg("--socket").arg(&socket)
        .arg("--throwaway-dir").arg(fixture.0.join("sessions"))
        .stdout(Stdio::null()).stderr(Stdio::piped()).spawn().unwrap());
    let deadline = Instant::now() + Duration::from_secs(20);
    let backend = loop {
        if let Ok(s) = UnixStream::connect(&socket) { break s; }
        if let Some(status) = child.0.try_wait().unwrap() {
            let mut error = String::new();child.0.stderr.take().unwrap().read_to_string(&mut error).unwrap();
            panic!("owned WebKit exited {status}: {error}");
        }
        assert!(Instant::now() < deadline,"owned WebKit startup deadline");
        std::thread::sleep(Duration::from_millis(10));
    };
    assert_eq!(enclave_core::ipc::peer_credentials(&backend).unwrap().uid,peer().uid);
    backend.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    backend.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
    let relay_socket = fixture.0.join("r.sock");
    let listener = UnixListener::bind(&relay_socket).unwrap();
    let facts = Arc::new(Mutex::new(BrowserFacts::default()));
    let relay_facts = facts.clone();
    let (ready,wait_ready) = std::sync::mpsc::channel();
    let relay = std::thread::spawn(move || {
        let mut backend = backend;
        let frame = inspect(&mut backend,"Page.getFrameTree",json!({}));
        assert_eq!(frame["frameTree"]["frame"]["url"],format!("{OWNED_DOCUMENT_ORIGIN}/"));
        let frame_id = frame["frameTree"]["frame"]["id"].as_str().unwrap().to_owned();
        let counter = query(&mut backend,"#count");
        let decoys = query(&mut backend,"#decoy-count");
        let nested_hit = query(&mut backend,"#nested-hit");
        let overlay = query(&mut backend,"#occluder");
        assert_eq!(count(&mut backend,counter),0);
        assert_eq!(count(&mut backend,decoys),0);
        ready.send(()).unwrap();
        let (mut client,_) = listener.accept().unwrap();
        assert_eq!(enclave_core::ipc::peer_credentials(&client).unwrap().uid,peer().uid);
        client.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        client.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
        while let Some(request) = receive(&mut client) {
            // Same live document, transparent JSON-value forwarding. Inspection
            // calls run serially after its actual response, never fabricate it.
            send(&mut backend,&request);
            let response = receive(&mut backend).unwrap();
            assert_eq!(response["id"],request["id"]);
            let mut current = relay_facts.lock().unwrap();
            current.forwarded_methods.push(request["method"].as_str().unwrap().to_owned());
            if request["method"] == "DOM.getNodeForLocation" {
                current.hits.push(response["result"]["backendNodeId"].as_u64().unwrap());
            }
            if request["method"] == "Input.dispatchMouseEvent" && request["params"]["type"] == "mouseReleased" {
                assert!(response.get("error").is_none(),"{response}");
                current.releases += 1;
            }
            current.counter = count(&mut backend,counter);
            current.decoys = count(&mut backend,decoys);
            drop(current);
            send(&mut client,&response);
        }
        let final_facts = snapshot(&relay_facts);
        assert_eq!(final_facts.counter,2);assert_eq!(final_facts.decoys,0);
        assert_eq!(final_facts.releases,2);
        assert_eq!(final_facts.hits,vec![nested_hit,overlay,nested_hit]);
        frame_id
    });
    wait_ready.recv_timeout(Duration::from_secs(15)).unwrap();
    let p = checkpoint();
    let audit = fixture.0.join("audit.jsonl");
    let service = RunnerService::start(RunnerConfig {
        dev_same_uid:true,profile:Profile::L2,audit_path:Some(audit.clone()),
        calib_corpus_blake3:None,state_dir:None,
        thermal:Box::new(|| Box::new(FixedThermal(ThermalState::Nominal,PowerSource::Ac))),
        actuator:Some(Box::new(CdpSocketActuator::new(&relay_socket).with_expected_uid(peer().uid))),
    },Box::new(FixtureWeights(p.clone()))).unwrap();
    let bound = service.handle(&peer(),RunnerRequest::Bind {
        manifest:p.manifest_bytes().into(),
        cas_uri:p.manifest["artifact"]["cas_uri"].as_str().unwrap().into(),calibration_corpus:None,
    }).unwrap();
    assert!(matches!(bound,RunnerResponse::Bound {class:ExecutionClass::JepaEbmWorldPlanner,..}));

    // All-veto planning must neither connect the actuator nor change the page.
    assert!(service.handle(&peer(),plan(0,vec![action("#increment",OWNED_DOCUMENT_ORIGIN)],0,
        vec![OWNED_DOCUMENT_ORIGIN.into()])).unwrap_err().is("NO_SAFE_ACTION"));
    assert_eq!(snapshot(&facts),BrowserFacts::default());
    assert!(service.handle(&peer(),observe(0)).unwrap_err().is("NO_PENDING_STEP"));

    let mut tool_denied = action("#increment",OWNED_DOCUMENT_ORIGIN);tool_denied.tool_id = 2;
    let candidates = vec![tool_denied,action("#delete-repo",OWNED_DOCUMENT_ORIGIN),
        action("#increment","https://other.invalid"),action("#nested-increment",OWNED_DOCUMENT_ORIGIN)];
    match service.handle(&peer(),plan(0,candidates,2,vec![OWNED_DOCUMENT_ORIGIN.into()])).unwrap() {
        RunnerResponse::Planned {action,vetoes,actuated} => {
            assert_eq!(action.target.dom_selector,"#nested-increment");assert!(vetoes>=3);assert!(actuated);
        },other=>panic!("{other:?}"),
    }
    let actual = snapshot(&facts);assert_eq!((actual.counter,actual.decoys,actual.releases),(1,0,1));
    assert!(service.handle(&peer(),safe_plan(1)).unwrap_err().is("WORLD_OBSERVATION_REQUIRED"));
    assert_eq!(snapshot(&facts),actual,"pending refusal must precede browser commands");
    assert!(service.handle(&peer(),RunnerRequest::Observe {w:8,h:8,px:vec![64;63].into(),pii_boxes:vec![]})
        .unwrap_err().is("FRAME_SHAPE"));
    assert!(service.handle(&peer(),safe_plan(1)).unwrap_err().is("WORLD_OBSERVATION_REQUIRED"));
    assert_eq!(snapshot(&facts),actual);
    assert!(matches!(service.handle(&peer(),observe(actual.counter)).unwrap(),RunnerResponse::Ok));
    assert!(service.handle(&peer(),observe(1)).unwrap_err().is("NO_PENDING_STEP"));

    // The planner strings pass its micro-capability policy in these cases;
    // actual browser origin, DOM ancestors and hit-test must independently veto.
    for (selector,origin,reason) in [
        ("#increment","https://other.invalid","ACTUATION_ORIGIN_MISMATCH"),
        ("#delete-repo > button",OWNED_DOCUMENT_ORIGIN,"ACTUATION_NODE_FORBIDDEN_OR_STALE"),
        ("#occluded",OWNED_DOCUMENT_ORIGIN,"ACTUATION_OCCLUDED_OR_STALE"),
    ] {
        let before = snapshot(&facts);
        assert!(service.handle(&peer(),plan(before.counter,vec![action(selector,origin)],2,vec![origin.into()]))
            .unwrap_err().is(reason));
        let after = snapshot(&facts);
        assert_eq!((after.counter,after.decoys,after.releases),(1,0,1));
        assert!(after.forwarded_methods.len()>before.forwarded_methods.len());
        assert!(service.handle(&peer(),safe_plan(1)).unwrap_err().is("WORLD_OBSERVATION_REQUIRED"));
        assert_eq!(snapshot(&facts),after,"uncertain actuator error keeps the fence");
        assert!(matches!(service.handle(&peer(),observe(after.counter)).unwrap(),RunnerResponse::Ok));
    }

    assert!(matches!(service.handle(&peer(),safe_plan(1)).unwrap(),RunnerResponse::Planned {actuated:true,..}));
    let after = snapshot(&facts);assert_eq!((after.counter,after.decoys,after.releases),(2,0,2));
    assert!(service.handle(&peer(),observe(after.counter)).unwrap_err().is("WORLD_MODEL_SURPRISE_ABORT"));
    assert!(service.handle(&peer(),observe(2)).unwrap_err().is("NO_PENDING_STEP"));
    let rows:Vec<Value> = std::fs::read_to_string(&audit).unwrap().lines()
        .map(|line|serde_json::from_str(line).unwrap()).collect();
    let aborted:Vec<_> = rows.iter().filter(|r|r["payload"]["event"]=="WORLD_SURPRISE_ABORT").collect();
    assert_eq!(aborted.len(),1);
    let payload = &aborted[0]["payload"];
    assert_eq!(payload["error_reason"],"WORLD_MODEL_SURPRISE_ABORT");
    assert_eq!(payload["wipe_reports"]["backend"],"cpu_guarded_arena");
    let wipes = payload["wipe_reports"]["reports"].as_array().unwrap();
    assert_eq!(wipes.len(),1);assert!(wipes[0]["bytes"].as_u64().unwrap()>0);assert_eq!(wipes[0]["residual"],0);
    enclave_core::audit::verify_journal(&audit,None).unwrap();
    assert!(matches!(service.handle(&peer(),RunnerRequest::Zeroize(ZeroizeTrigger::TaskExit)).unwrap(),
        RunnerResponse::Wiped(0)),"surprise already wiped the actual episode arena");
    drop(service);
    let old_frame = relay.join().unwrap();

    let mut fresh = UnixStream::connect(&socket).unwrap();
    fresh.set_read_timeout(Some(Duration::from_secs(15))).unwrap();
    fresh.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
    let frame = inspect(&mut fresh,"Page.getFrameTree",json!({}));
    assert_ne!(frame["frameTree"]["frame"]["id"].as_str().unwrap(),old_frame);
    let counter = query(&mut fresh,"#count");let decoys = query(&mut fresh,"#decoy-count");
    assert_eq!(count(&mut fresh,counter),0);assert_eq!(count(&mut fresh,decoys),0);
    eprintln!("OWNED_WEBKIT_WORLD_SERVICE=true actual_bind=true actual_plan=true actual_dom_effects=2 all_veto_no_commands=true pending_fence=true bad_observe_retained=true hostile_refusals=3 actual_observe_surprise=true cpu_episode_wipe=true screenshots=false production_acceptance=false");
}
