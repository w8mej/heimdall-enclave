//! GAP-34 acceptance tests: Class 6 GUI actuation in a sandboxed CDP browser (FS-701 §4.6, ADR-018).
//!
//! Verifies:
//! 1. ADR-018 decoy-label adversarial UI test: a deceptive visual label over `#delete-repo` or
//!    forbidden system bundles (`_enclaveintent`, `Terminal`, `System Settings`) is blocked pre-execution.
//! 2. Post-step surprise gate: state divergence beyond `tau_surprise` halts with `WORLD_MODEL_SURPRISE_ABORT`
//!    and zeroizes the episodic STM arena (`end_episode`).
//! 3. ScreenCaptureKit pre-encoder masking: 0 residual bytes within PII bounding boxes; full-frame blur
//!    during high-velocity scroll.
//! 4. Pipe-passed Unix domain socket communication with the sandboxed CDP browser actuator.

use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use enclave_core::profile::Profile;
use enclave_model_runnerd::adapter::{EnclaveModelAdapter, Engine};
use enclave_model_runnerd::classes::speculative::{FixedThermal, PowerSource, ThermalState};
use enclave_model_runnerd::classes::world::{
    Action, Actuator, CdpPipeDriver, CdpSocketActuator, Frame, MicroCapabilities, Rect,
    ResolvedTarget,
};
use enclave_model_runnerd::manifest::{ExecutionClass, ModelManifestV1};
use enclave_model_runnerd::screencapture::{
    check_screen_recording_permission, ScreenCaptureObserver,
};
use enclave_model_runnerd::topology::OpAttestor;
use enclave_model_runnerd::zoo::package;
use serde_json::json;

fn nominal_thermal() -> Box<FixedThermal> {
    Box::new(FixedThermal(ThermalState::Nominal, PowerSource::Ac))
}

fn target(bundle: &str, origin: &str, title: &str, selector: &str) -> ResolvedTarget {
    ResolvedTarget {
        app_bundle_id: bundle.into(),
        ax_role: "AXButton".into(),
        ax_title: title.into(),
        url_origin: origin.into(),
        dom_selector: selector.into(),
    }
}

#[test]
fn test_adr018_decoy_label_blocked_pre_execution() {
    let p = package(ExecutionClass::JepaEbmWorldPlanner).unwrap();
    let manifest: ModelManifestV1 = serde_json::from_value(p.manifest.clone()).unwrap();
    let mut adapter =
        EnclaveModelAdapter::bind(manifest, &p.weights, Profile::L2, None, nominal_thermal())
            .unwrap();
    let Engine::World(g) = &mut adapter.engine else {
        panic!("expected WorldGate engine");
    };

    let mut attestor = OpAttestor::new(ExecutionClass::JepaEbmWorldPlanner, &[]);

    // Initial and goal states
    let s = g
        .observe(
            Frame {
                w: 16,
                h: 16,
                px: (0..256).map(|i| (i % 256) as u8).collect(),
            },
            &[],
            0.0,
        )
        .unwrap();
    let goal = g
        .observe(
            Frame {
                w: 16,
                h: 16,
                px: vec![128; 256],
            },
            &[],
            0.0,
        )
        .unwrap();

    let policy = MicroCapabilities {
        tools: 0b0010, // Only tool 1 is allowed
        origins: vec!["https://app.corp.internal".into()],
    };

    // Construct candidate actions with adversarial decoy labels
    let cands = vec![
        // Candidate 0: Decoy label ("View User Profile") masquerading over destructive #delete-repo
        Action {
            tool_id: 1,
            target: target(
                "com.google.Chrome",
                "https://app.corp.internal",
                "View User Profile",
                "#delete-repo",
            ),
            params_q: vec![10, 0],
        },
        // Candidate 1: Decoy targeting forbidden Terminal application
        Action {
            tool_id: 1,
            target: target(
                "com.apple.Terminal",
                "https://app.corp.internal",
                "Open Documentation",
                "#open-doc",
            ),
            params_q: vec![0],
        },
        // Candidate 2: Decoy targeting biometric intent prompt helper
        Action {
            tool_id: 1,
            target: target(
                "com.enterprise.enclave.intent",
                "https://app.corp.internal",
                "Authorize Request",
                "#auth-btn",
            ),
            params_q: vec![0],
        },
        // Candidate 3: Decoy on unauthorized origin
        Action {
            tool_id: 1,
            target: target(
                "com.google.Chrome",
                "https://malicious-phishing.example",
                "Click Here For Help",
                "#help-link",
            ),
            params_q: vec![0],
        },
        // Candidate 4: Legitimate authorized action
        Action {
            tool_id: 1,
            target: target(
                "com.google.Chrome",
                "https://app.corp.internal",
                "Save Preferences",
                "#save-prefs",
            ),
            params_q: vec![5, -2],
        },
    ];

    // Planning must veto all deceptive / forbidden candidates
    let plan = g.plan(&s, &goal, &cands, &policy, &mut attestor).unwrap();
    assert_eq!(
        plan.action.target.dom_selector, "#save-prefs",
        "planner selected the only legitimate candidate"
    );
    assert!(
        plan.vetoes >= 3,
        "all adversarial decoy candidates were vetoed pre-execution"
    );

    // If only adversarial candidates are presented, plan() must fail with NO_SAFE_ACTION
    let adversarial_only = &cands[..4];
    let err = g
        .plan(&s, &goal, adversarial_only, &policy, &mut attestor)
        .unwrap_err();
    assert!(
        err.is("NO_SAFE_ACTION"),
        "expected NO_SAFE_ACTION when all candidates are adversarial, got: {err}"
    );

    // Direct actuator execution check: forbidden target fails closed
    let (mut client_w, _server_r) = UnixStream::pair().unwrap();
    let client_r = client_w.try_clone().unwrap();
    let mut driver = CdpPipeDriver::new(&mut client_w, client_r);

    let err = driver.execute(&cands[1]).unwrap_err();
    assert!(
        err.is("ACTUATION_TARGET_FORBIDDEN"),
        "expected ACTUATION_TARGET_FORBIDDEN for Terminal"
    );

    let err = driver.execute(&cands[2]).unwrap_err();
    assert!(
        err.is("ACTUATION_TARGET_FORBIDDEN"),
        "expected ACTUATION_TARGET_FORBIDDEN for _enclaveintent"
    );
}

#[test]
fn test_surprise_gate_divergence_aborts_multi_step() {
    let p = package(ExecutionClass::JepaEbmWorldPlanner).unwrap();
    let manifest: ModelManifestV1 = serde_json::from_value(p.manifest.clone()).unwrap();
    let mut adapter =
        EnclaveModelAdapter::bind(manifest, &p.weights, Profile::L2, None, nominal_thermal())
            .unwrap();
    let Engine::World(g) = &mut adapter.engine else {
        panic!("expected WorldGate engine");
    };

    let mut attestor = OpAttestor::new(ExecutionClass::JepaEbmWorldPlanner, &[]);
    let s = g
        .observe(
            Frame {
                w: 16,
                h: 16,
                px: vec![50; 256],
            },
            &[],
            0.0,
        )
        .unwrap();
    let goal = g
        .observe(
            Frame {
                w: 16,
                h: 16,
                px: vec![60; 256],
            },
            &[],
            0.0,
        )
        .unwrap();
    let policy = MicroCapabilities {
        tools: 0b0010,
        origins: vec!["https://app.corp.internal".into()],
    };
    let cands = vec![Action {
        tool_id: 1,
        target: target(
            "com.google.Chrome",
            "https://app.corp.internal",
            "Submit",
            "#submit",
        ),
        params_q: vec![0],
    }];

    let plan = g.plan(&s, &goal, &cands, &policy, &mut attestor).unwrap();

    // 1. Nominal step: observation matches prediction within tau_surprise
    let nominal_observed = plan.predicted.clone();
    let surprise_val = g.surprise(&plan.predicted, &nominal_observed).unwrap();
    assert!(surprise_val < 0.001);

    // 2. Adversarial / unexpected divergence (e.g., unexpected modal or screen change)
    let diverged_observed: Vec<f32> = plan.predicted.iter().map(|x| x + 2.5).collect();
    let err = g.surprise(&plan.predicted, &diverged_observed).unwrap_err();
    assert!(
        err.is("WORLD_MODEL_SURPRISE_ABORT"),
        "expected WORLD_MODEL_SURPRISE_ABORT on divergence, got: {err}"
    );

    // 3. Wiping episodic STM arena
    let wipe = g.end_episode().expect("STM arena wiped on abort");
    assert_eq!(
        wipe.residual, 0,
        "episodic STM memory verified 0 residual bytes"
    );
}

#[test]
fn test_screencapturekit_pre_encoder_masking() {
    let _ = check_screen_recording_permission();

    let observer = ScreenCaptureObserver::new(Some(12345));
    let mut frame = Frame {
        w: 32,
        h: 32,
        px: vec![220; 1024],
    };

    let pii_boxes = vec![
        Rect {
            x: 4,
            y: 4,
            w: 8,
            h: 8,
        },
        Rect {
            x: 18,
            y: 20,
            w: 10,
            h: 6,
        },
    ];

    assert!(!ScreenCaptureObserver::verify_zero_pii_residual(
        &frame, &pii_boxes
    ));

    // Mask frame under normal velocity
    observer.mask(&mut frame, &pii_boxes, 50.0).unwrap();

    // Verification of zero residual PII
    assert!(ScreenCaptureObserver::verify_zero_pii_residual(
        &frame, &pii_boxes
    ));
    // Non-PII area is intact
    assert_eq!(frame.px[0], 220);

    // High velocity scroll: entire frame is blurred to mean
    let mut fast_frame = Frame {
        w: 4,
        h: 4,
        px: vec![
            10, 20, 30, 40, 50, 60, 70, 80, 90, 100, 110, 120, 130, 140, 150, 160,
        ],
    };
    let expected_mean =
        (fast_frame.px.iter().map(|p| *p as u64).sum::<u64>() / fast_frame.px.len() as u64) as u8;

    observer.mask(&mut fast_frame, &[], 2500.0).unwrap();
    assert!(fast_frame.px.iter().all(|&p| p == expected_mean));
}

#[test]
fn test_cdp_pipe_driver_with_browser_socket() {
    let tmp_dir = std::env::temp_dir().join(format!("depot-cdp-{}", enclave_core::rng::u64()));
    let _ = std::fs::create_dir_all(&tmp_dir);
    let sock_path = tmp_dir.join("browser.sock");

    let listener = UnixListener::bind(&sock_path).unwrap();
    let running = Arc::new(AtomicBool::new(true));
    let r_clone = running.clone();

    let server_handle = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut buf = Vec::new();
        let mut chunk = [0u8; 4096];

        while r_clone.load(Ordering::SeqCst) {
            let n = match stream.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => n,
                Err(_) => break,
            };
            buf.extend_from_slice(&chunk[..n]);

            while let Some(pos) = buf.iter().position(|b| *b == 0) {
                let frame: Vec<u8> = buf.drain(..=pos).collect();
                let msg: serde_json::Value =
                    serde_json::from_slice(&frame[..frame.len() - 1]).unwrap();
                let id = msg["id"].clone();
                let method = msg["method"].as_str().unwrap();

                let result = match method {
                    "Page.getFrameTree" => {
                        json!({"frameTree": {"frame": {"url": "https://app.corp.internal/page"}}})
                    }
                    "DOM.getDocument" => {
                        json!({"root": {"nodeId": 1, "children": [{"nodeId": 42, "backendNodeId": 420, "attributes": ["id", "submit"]}]}})
                    }
                    "DOM.getNodeForLocation" => json!({"backendNodeId": 420}),
                    "DOM.querySelector" => json!({"nodeId": 42}),
                    "DOM.getBoxModel" => json!({
                        "model": {
                            "content": [100.0, 50.0, 200.0, 50.0, 200.0, 90.0, 100.0, 90.0],
                            "width": 100,
                            "height": 40
                        }
                    }),
                    "Input.dispatchMouseEvent" => json!({}),
                    _ => json!({}),
                };

                let mut out = serde_json::to_vec(&json!({"id": id, "result": result})).unwrap();
                out.push(0);
                stream.write_all(&out).unwrap();
                stream.flush().unwrap();
            }
        }
    });

    let mut actuator =
        CdpSocketActuator::new(&sock_path).with_expected_uid(enclave_core::ipc::geteuid());
    let safe_action = Action {
        tool_id: 1,
        target: target(
            "com.google.Chrome",
            "https://app.corp.internal",
            "Submit",
            "#submit-btn",
        ),
        params_q: vec![0],
    };

    actuator.execute(&safe_action).unwrap();
    drop(actuator);

    running.store(false, Ordering::SeqCst);
    let _ = server_handle.join();
    let _ = std::fs::remove_dir_all(&tmp_dir);
}

#[test]
fn f108_overflow_outside_and_bad_shapes_are_rejected_atomically() {
    use enclave_model_runnerd::classes::world::mask_frame;
    for r in [
        Rect {
            x: usize::MAX,
            y: 0,
            w: 1,
            h: 1,
        },
        Rect {
            x: 0,
            y: usize::MAX,
            w: 1,
            h: 1,
        },
        Rect {
            x: 1,
            y: 1,
            w: usize::MAX,
            h: 1,
        },
        Rect {
            x: 3,
            y: 0,
            w: 2,
            h: 1,
        },
        Rect {
            x: 0,
            y: 3,
            w: 1,
            h: 2,
        },
        Rect {
            x: 0,
            y: 0,
            w: 0,
            h: 1,
        },
    ] {
        for velocity in [0.0, 5000.0] {
            let mut f = Frame {
                w: 4,
                h: 4,
                px: vec![7; 16],
            };
            assert!(mask_frame(&mut f, &[r], velocity, 2000.0)
                .unwrap_err()
                .is("PII_RECT_BOUNDS"));
            assert_eq!(f.px, vec![7; 16]);
            assert!(!ScreenCaptureObserver::verify_zero_pii_residual(&f, &[r]));
        }
    }
    let mut f = Frame {
        w: usize::MAX,
        h: 2,
        px: vec![7; 16],
    };
    assert!(mask_frame(&mut f, &[], 0.0, 2000.0)
        .unwrap_err()
        .is("FRAME_SHAPE"));
    let mut f = Frame {
        w: 4,
        h: 4,
        px: vec![7; 16],
    };
    let r = Rect {
        x: 3,
        y: 3,
        w: 1,
        h: 1,
    };
    mask_frame(&mut f, &[r], 0.0, 2000.0).unwrap();
    assert_eq!(f.px[15], 0);
    assert_eq!(f.px[14], 7);
    assert!(ScreenCaptureObserver::verify_zero_pii_residual(&f, &[r]));
}

#[test]
fn f138_browser_facts_override_planner_strings_and_hit_test() {
    fn run(
        origin: &str,
        attrs: serde_json::Value,
        hit: u64,
        next_origin: &str,
    ) -> (bool, Vec<serde_json::Value>) {
        let responses = vec![
            json!({"frameTree":{"frame":{"url":origin}}}),
            json!({"root":{"nodeId":1,"children":[{"nodeId":42,"backendNodeId":420,"attributes":attrs,"children":[{"nodeId":43,"backendNodeId":421}]}]}}),
            json!({"nodeId":42}),
            json!({"model":{"content":[10,20,30,20,30,40,10,40]}}),
            json!({"backendNodeId":hit}),
            json!({"frameTree":{"frame":{"url":next_origin}}}),
            json!({}),
            json!({}),
        ];
        let mut input = Vec::new();
        for (i, result) in responses.into_iter().enumerate() {
            input.extend(serde_json::to_vec(&json!({"id":i+1,"result":result})).unwrap());
            input.push(0);
        }
        let mut output = Vec::new();
        let a = Action {
            tool_id: 1,
            target: target(
                "com.google.Chrome",
                "https://app.corp.internal",
                "safe",
                "[id='delete-repo']",
            ),
            params_q: vec![],
        };
        let ok = CdpPipeDriver::new(&mut output, std::io::Cursor::new(input))
            .execute(&a)
            .is_ok();
        let calls = output
            .split(|b| *b == 0)
            .filter(|b| !b.is_empty())
            .map(|b| serde_json::from_slice(b).unwrap())
            .collect();
        (ok, calls)
    }
    let good = "https://app.corp.internal/path";
    for (url, attrs, hit, next) in [
        ("https://evil.example/", json!([]), 420, good),
        (good, json!(["id", "delete-repo"]), 420, good),
        (good, json!(["id", "safe"]), 999, good),
        (good, json!(["id", "safe"]), 420, "https://evil.example/"),
        (
            "https://app.corp.internal.evil.example/",
            json!([]),
            420,
            good,
        ),
    ] {
        let (ok, calls) = run(url, attrs, hit, next);
        assert!(!ok);
        assert!(!calls
            .iter()
            .any(|c| c["method"] == "Input.dispatchMouseEvent"));
    }
    // A child inside the selected button remains a legitimate hit.
    let (ok, calls) = run(good, json!(["id", "safe"]), 421, good);
    assert!(ok);
    assert_eq!(
        calls
            .iter()
            .filter(|c| c["method"] == "Input.dispatchMouseEvent")
            .count(),
        2
    );
}
