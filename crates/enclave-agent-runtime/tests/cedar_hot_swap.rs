//! GAP-32: TUF-distributed, hot-swappable Cedar bundle.
//! DEFECT-F-64: inline bundles load only when byte-identical to the signed
//! target UID 702 serves (a fake UID 702 here), or unsigned in `simulation`
//! dev builds.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey;
use enclave_agent_runtime::cedar_engine::{
    admit_inline_bundle, CedarBundle, CedarEngine, PolicyProvenance, BASELINE_POLICIES,
    CEDAR_BUNDLE_TARGET, DEFAULT_SCHEMA,
};
use enclave_agent_runtime::pdp::{Decision, Pdp, ToolCallRequest, POLICY_SWAP_GRACE_WINDOW_NS};
use enclave_agent_runtime::registry::ToolRegistry;
use enclave_agent_runtime::service::{
    CustodyPort, Declassifier, IfcConfig, IfcRequest, IfcResponse, IfcService, StepUp,
};
use enclave_core::error::EnclaveResult;
use enclave_core::intent_draft::IntentDraftV1;
use enclave_core::ipc::PeerCredentials;
use enclave_core::label::Conf;
use enclave_core::profile::{ActionClass, Profile};
use enclave_crypto::biscuit_auth::{AuthorizerLimits, Biscuit};
use enclave_crypto::pop_biscuit::{
    make_call, mint_root, spec_limits, AuthorityClaims, Transport, WireClock,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

const EPOCH: &str = "6f1c2c1e-3a54-4b8e-9d7a-0c4f5b6a7e81";

fn test_epoch() -> enclave_core::seq::BootEpoch {
    static SIGNER: std::sync::OnceLock<enclave_crypto::epoch::EpochSigner> =
        std::sync::OnceLock::new();
    SIGNER
        .get_or_init(enclave_crypto::epoch::EpochSigner::random)
        .sign(EPOCH)
}

#[derive(Debug, Default)]
struct FakeVault {
    slots: Mutex<u64>,
}
#[derive(Debug)]
struct VaultPort(Arc<FakeVault>);
impl CustodyPort for VaultPort {
    fn scrub_text(&self, text: &str, _bulk: bool) -> EnclaveResult<String> {
        Ok(text.to_owned())
    }
    fn authorize_intent(&self, _d: &IntentDraftV1) -> EnclaveResult<StepUp> {
        Ok(StepUp {
            d_jcs: "ab".repeat(32),
            factors: vec!["TouchIdCoreauthui".into(), "YubikeyUp".into()],
            // Trusted software fixture only; not native custody evidence.
            lifetime: enclave_agent_runtime::service::IntentLifetimeV1 {
                v: 1, valid_until_unix: None,
                deadline_boot_ns: Some(enclave_core::clock::boot_clock_ns()+10_000_000_000),
            },
        })
    }
    fn allocate_slot(&self) -> EnclaveResult<(String, u64)> {
        let mut n = self.0.slots.lock().unwrap();
        *n += 1;
        Ok((EPOCH.into(), *n))
    }
    fn boot_epoch(&self) -> EnclaveResult<enclave_core::seq::BootEpoch> {
        Ok(test_epoch())
    }
}

fn scratch(sub: &str) -> PathBuf {
    // Short: the fake UID 702 socket lives below this dir (macOS SUN_LEN = 104).
    let tag = &blake3::hash(sub.as_bytes()).to_hex()[..8];
    let p = std::env::temp_dir().join(format!("chs-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&p);
    enclave_core::fsutil::private_dir(&p).unwrap();
    p
}

#[derive(Debug)]
struct Fixed;
impl Declassifier for Fixed {
    fn classify(
        &self,
        _p: &[u8],
        _k: u64,
        _s: &str,
        _slot: &enclave_core::seq::GovernedSlot,
    ) -> enclave_core::error::EnclaveResult<u64> {
        Ok(0)
    }
}

fn lock() -> ToolRegistry {
    let v = json!({
        "v": 1,
        "servers": [{
            "server": "postgres",
            "tools_list_blake3": "00".repeat(32),
            "tools": [
                {
                    "name": "select_bounded",
                    "action_class": "A1",
                    "sink_clearance": "C3",
                    "namespace": "dev-billing",
                    "canonical_verb": "Select",
                    "slots": {"table": "BOUND_LITERAL"},
                    "row_count_arg": "limit",
                    "max_rows": 25,
                    "output_conf": "C2",
                    "entity_key_fields": ["id"],
                },
                {
                    "name": "export_report",
                    "action_class": "A3",
                    "sink_clearance": "C3",
                    "namespace": "dev-billing",
                    "canonical_verb": "Export",
                    "slots": {},
                    "output_conf": "C3",
                }
            ]
        }]
    });
    ToolRegistry::load(&serde_json::to_vec(&v).unwrap()).unwrap()
}

fn admin() -> PeerCredentials {
    let mut p = PeerCredentials::local(enclave_core::ipc::geteuid(), 0);
    p.pid = Some(4242);
    p
}

fn svc_with(
    audit_path: PathBuf,
    cedar: CedarEngine,
    socket_dir: Option<PathBuf>,
    dev_same_uid: bool,
) -> Arc<IfcService> {
    let cfg = IfcConfig {
        profile: Profile::L2,
        audit_path: Some(audit_path),
        policy_key: SigningKey::generate(&mut rand_core::OsRng),
        limits: AuthorizerLimits {
            max_time: Duration::from_millis(50),
            ..spec_limits()
        },
        registry: lock(),
        cedar: Some(cedar),
        state_dir: None,
        socket_dir,
        dev_same_uid,
    };
    IfcService::start(
        cfg,
        Box::new(Fixed),
        Box::new(VaultPort(Arc::new(FakeVault::default()))),
    )
    .unwrap()
}

/// Wire shape of `host_config::fetch_tuf_target` (UID 702 `FetchTarget`).
#[derive(Debug, Deserialize)]
enum FakeCasReq {
    FetchTarget { target: String },
}
#[derive(Debug, Serialize)]
enum FakeCasResp {
    Bytes(serde_bytes::ByteBuf),
}

/// A same-UID stand-in for UID 702 serving `signed` as the TUF-verified
/// policy target. Returns the socket dir to hand to the service.
fn fake_cas(base: &std::path::Path, signed: Vec<u8>) -> PathBuf {
    let sock_dir = base.join("run");
    let dir = enclave_core::daemon::DaemonId::SwarmSync.dir_name();
    let sock = sock_dir.join(dir).join(format!("{dir}.sock"));
    enclave_core::fsutil::private_dir(sock.parent().unwrap()).unwrap();
    let listener =
        enclave_core::ipc::bind(&sock, enclave_core::ipc::SocketAccess::OwnerOnly).unwrap();
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    std::thread::spawn(move || {
        enclave_core::ipc::serve::<FakeCasReq, FakeCasResp, _>(
            listener,
            enclave_core::ipc::PeerPolicy::allow([enclave_core::ipc::geteuid()]),
            Arc::new(move |_p: &PeerCredentials, r: FakeCasReq| {
                let FakeCasReq::FetchTarget { target } = r;
                if target != CEDAR_BUNDLE_TARGET {
                    enclave_core::fail!(EINVAL, "TARGET_UNKNOWN", "{target}");
                }
                Ok(FakeCasResp::Bytes(signed.clone().into()))
            }),
            stop,
        )
    });
    sock_dir
}

fn refresh(s: &IfcService, peer: &PeerCredentials, bytes: Vec<u8>) -> EnclaveResult<IfcResponse> {
    s.handle(
        peer,
        IfcRequest::RefreshPolicy {
            bundle_json: Some(bytes.into()),
        },
    )
}

fn root_peer() -> PeerCredentials {
    let mut p = PeerCredentials::local(0, 0);
    p.pid = Some(4243);
    p
}

fn permit_all_bytes() -> Vec<u8> {
    CedarBundle::new(DEFAULT_SCHEMA, "permit (principal, action, resource);\n")
        .to_json_bytes()
        .unwrap()
}

fn forbid_select_bytes() -> Vec<u8> {
    let p = format!(
        "{BASELINE_POLICIES}\n@id(\"strict-deny\")\nforbid (principal, action, resource == depot::Tool::\"depot://postgres/select_bounded\");\n"
    );
    CedarBundle::new(DEFAULT_SCHEMA, p).to_json_bytes().unwrap()
}

fn journal_events(audit: &std::path::Path) -> Vec<Value> {
    std::fs::read_to_string(audit)
        .unwrap_or_default()
        .lines()
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .collect()
}

fn has_event(events: &[Value], name: &str) -> Option<Value> {
    events
        .iter()
        .find(|v| v.to_string().contains(&format!("\"{name}\"")))
        .cloned()
}

fn mint_turn_token(s: &IfcService, holder: &SigningKey) -> Biscuit {
    let r = s
        .handle(
            &admin(),
            IfcRequest::SubmitTurn {
                turn: enclave_core::user_turn::UserTurnV1 {
                    directive_short: "test turn".into(),
                    attachments: vec![],
                },
                attachments: vec![],
                // DEFECT-F-67: the root token names the tools the turn may use.
                tools: vec![enclave_agent_runtime::turn::ToolSignature {
                    name: "depot://postgres/select_bounded".into(),
                    description: "select_bounded".into(),
                    params: vec![],
                }],
                holder_pk: Some(holder.verifying_key().to_bytes()),
                budget_mb: 500,
            },
        )
        .unwrap();
    let IfcResponse::Plan {
        root_token: Some(t),
        ..
    } = r
    else {
        panic!("expected plan with root token");
    };
    Biscuit::from(t.as_slice(), s.root_public().unwrap()).unwrap()
}

fn call(
    s: &IfcService,
    t: &Biscuit,
    holder: &SigningKey,
    seq: u64,
    tool: &str,
    args: Value,
) -> Decision {
    let args_jcs = enclave_core::jcs::canonicalize(&args).unwrap();
    let clock = WireClock {
        local_boot_id: Some(s.boot_epoch_id().unwrap()),
        mach_continuous_time_ns_expiry: Some(enclave_core::clock::boot_clock_ns() + 60_000_000_000),
        ..Default::default()
    };
    let w = make_call(
        t,
        holder,
        &admin().channel_binding(),
        &args_jcs,
        seq,
        Transport::Uds,
        clock,
    )
    .unwrap();
    let r = s
        .handle(
            &admin(),
            IfcRequest::AuthorizeToolCall {
                server: "postgres".into(),
                tool_name: tool.into(),
                args_jcs: args_jcs.into(),
                arg_handles: vec![],
                wire_cbor: w.to_cbor().unwrap().into(),
                step_up: false,
            },
        )
        .unwrap();
    let IfcResponse::Decision(d) = r else {
        panic!("{r:?}")
    };
    d
}

#[test]
fn hotswap_stricter_policy_denies_immediately() {
    let dir = scratch("hotswap-deny");
    let audit = dir.join("audit.jsonl");

    // 1. Start with baseline bundle; UID 702 publishes a stricter signed bundle.
    let bundle_bytes = forbid_select_bytes();
    let sock_dir = fake_cas(&dir, bundle_bytes.clone());
    let baseline = CedarEngine::baseline_bundle().unwrap();
    let s = svc_with(audit.clone(), baseline, Some(sock_dir), true);

    let holder = SigningKey::generate(&mut rand_core::OsRng);
    let token = mint_turn_token(&s, &holder);
    let args = json!({"table": "users", "columns": "id", "limit": 1});

    // 2. Previously allowed call succeeds
    let d1 = call(&s, &token, &holder, 1, "select_bounded", args.clone());
    assert!(
        d1.allow,
        "baseline bundle must allow select_bounded: {d1:?}"
    );
    assert!(d1.cedar_allow);
    assert!(d1.biscuit_allow);

    // 3. Hot swap to the stricter bundle (inline bytes == signed target).
    let resp = refresh(&s, &admin(), bundle_bytes).unwrap();
    assert!(matches!(resp, IfcResponse::Ok));

    // 4. Exactly the same call is immediately denied by Cedar
    let d2 = call(&s, &token, &holder, 2, "select_bounded", args);
    assert!(
        !d2.allow,
        "stricter bundle must deny select_bounded immediately"
    );
    assert!(!d2.cedar_allow, "cedar must deny");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn malformed_bundle_is_rejected_and_logged() {
    let dir = scratch("hotswap-malformed");
    let audit = dir.join("audit.jsonl");

    // Even a correctly *signed* bundle must pass strict Cedar validation.
    let malformed_bundle = CedarBundle::new(DEFAULT_SCHEMA, "this is not valid cedar syntax !!");
    let bundle_bytes = malformed_bundle.to_json_bytes().unwrap();
    let sock_dir = fake_cas(&dir, bundle_bytes.clone());
    let baseline = CedarEngine::baseline_bundle().unwrap();
    let s = svc_with(audit.clone(), baseline, Some(sock_dir), true);

    let holder = SigningKey::generate(&mut rand_core::OsRng);
    let token = mint_turn_token(&s, &holder);
    let args = json!({"table": "users", "columns": "id", "limit": 1});

    // Call succeeds before
    let d1 = call(&s, &token, &holder, 1, "select_bounded", args.clone());
    assert!(d1.allow);

    // Attempt to refresh with invalid Cedar syntax

    let res = s.handle(
        &admin(),
        IfcRequest::RefreshPolicy {
            bundle_json: Some(bundle_bytes.into()),
        },
    );
    assert!(
        res.is_err(),
        "malformed bundle must be rejected fail-closed"
    );

    // Old policy stays active: call still succeeds
    let d2 = call(&s, &token, &holder, 2, "select_bounded", args);
    assert!(d2.allow, "old bundle must stay active after failed refresh");

    // Check audit journal records POLICY_BUNDLE_INVALID
    let journal_text = std::fs::read_to_string(&audit).unwrap();
    assert!(
        journal_text.contains("POLICY_BUNDLE_INVALID"),
        "journal must record POLICY_BUNDLE_INVALID event: {journal_text}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn token_bundle_hash_mismatch_and_grace_window() {
    // Test Pdp directly to evaluate time-window boundaries
    let engine1 = CedarEngine::baseline_bundle().unwrap();
    let hash1 = engine1.bundle_blake3();

    let epoch = enclave_core::seq::new_boot_epoch_id();
    let limits = enclave_crypto::pop_biscuit::AuthorizerLimits {
        max_time: std::time::Duration::from_millis(50),
        ..spec_limits()
    };
    let mut pdp = Pdp::new(engine1, epoch.clone(), Profile::L2, limits);

    let holder = SigningKey::generate(&mut rand_core::OsRng);
    let claims1 = AuthorityClaims {
        boot_uuid: epoch.clone(),
        effective_profile: 2,
        policy_bundle_blake3: hash1,
        max_c_clearance: 4,
        total_qif_budget_millibits: 10_000,
        allowed_tools: None,
    };
    let peer = admin();
    let cb = peer.channel_binding();
    let root_tok = mint_root(
        pdp.root(),
        &claims1,
        &holder.verifying_key().to_bytes(),
        &cb,
    )
    .unwrap();

    let heap = enclave_agent_runtime::heap::CapabilityHeap::new(epoch.clone());

    let tool_res = enclave_agent_runtime::cedar_engine::ToolResource {
        name: "depot://postgres/select_bounded".into(),
        action_class: ActionClass::A1,
        sink_clearance: Conf::C3,
        namespace: "dev-billing".into(),
        mutates_root: false,
    };

    let args_jcs = b"{\"columns\":\"id\",\"limit\":1,\"table\":\"users\"}".to_vec();
    let clock = WireClock {
        local_boot_id: Some(epoch.clone()),
        mach_continuous_time_ns_expiry: Some(u64::MAX >> 2),
        ..Default::default()
    };
    let w = make_call(&root_tok, &holder, &cb, &args_jcs, 1, Transport::Uds, clock).unwrap();

    let req = ToolCallRequest {
        agent: "orchestrator".into(),
        tool: tool_res.clone(),
        args_jcs: args_jcs.clone(),
        arg_slots: vec![],
        literal_structural: false,
        row_count: 1,
        qif_mb: 10,
        hw_grant: false,
        wire_cbor: w.to_cbor().unwrap(),
    };

    let t0 = 100_000_000_000u64;
    // Call under active bundle succeeds
    let d0 = pdp.authorize(&heap, &peer, &req, t0, 1_000_000).unwrap();
    assert!(d0.allow, "d0 failed: {d0:?}");

    // Swap to engine 2 at t0 + 10s
    let t_swap = t0 + 10_000_000_000;
    let engine2 = CedarEngine::baseline_bundle().unwrap();
    let hash2 = engine2.bundle_blake3();
    assert_eq!(hash1, hash2, "same content yields same hash");

    // Create a truly different policy for engine 2
    let diff_policy = format!(
        "{BASELINE_POLICIES}\n@id(\"extra-rule\")\npermit (principal, action, resource);\n"
    );
    let engine2 = CedarEngine::load(DEFAULT_SCHEMA, &diff_policy).unwrap();
    let hash2 = engine2.bundle_blake3();
    assert_ne!(
        hash1, hash2,
        "different policies must yield different hashes"
    );

    pdp.swap_cedar(engine2, t_swap);

    // 1. Within grace window: t_swap + 10s (grace is 60s)
    let t_within_grace = t_swap + 10_000_000_000;
    let w_grace = make_call(
        &root_tok,
        &holder,
        &cb,
        &args_jcs,
        2,
        Transport::Uds,
        WireClock {
            local_boot_id: Some(epoch.clone()),
            mach_continuous_time_ns_expiry: Some(u64::MAX >> 2),
            ..Default::default()
        },
    )
    .unwrap();
    let req_grace = ToolCallRequest {
        wire_cbor: w_grace.to_cbor().unwrap(),
        ..req.clone()
    };
    let d_grace = pdp
        .authorize(&heap, &peer, &req_grace, t_within_grace, 1_000_000)
        .unwrap();
    assert!(
        d_grace.allow,
        "token within grace window must be admitted: {d_grace:?}"
    );

    // 2. Outside grace window: t_swap + 70s (grace is 60s)
    let t_outside_grace = t_swap + POLICY_SWAP_GRACE_WINDOW_NS + 10_000_000_000;
    let w_outside = make_call(
        &root_tok,
        &holder,
        &cb,
        &args_jcs,
        3,
        Transport::Uds,
        WireClock {
            local_boot_id: Some(epoch),
            mach_continuous_time_ns_expiry: Some(u64::MAX >> 2),
            ..Default::default()
        },
    )
    .unwrap();
    let req_outside = ToolCallRequest {
        wire_cbor: w_outside.to_cbor().unwrap(),
        ..req
    };
    let d_outside = pdp
        .authorize(&heap, &peer, &req_outside, t_outside_grace, 1_000_000)
        .unwrap();
    assert!(
        !d_outside.allow,
        "token outside grace window must be denied"
    );
    assert!(!d_outside.biscuit_allow);
    assert!(
        d_outside
            .biscuit_error
            .as_deref()
            .unwrap_or("")
            .contains("POLICY_BUNDLE_MISMATCH"),
        "error must be POLICY_BUNDLE_MISMATCH: {:?}",
        d_outside.biscuit_error
    );
}

#[test]
fn policy_sync_slo_under_10s() {
    let t0 = Instant::now();
    let bundle = CedarBundle::baseline();
    let bytes = bundle.to_json_bytes().unwrap();
    let parsed = CedarBundle::from_json_bytes(&bytes).unwrap();
    let engine = CedarEngine::from_bundle(&parsed).unwrap();
    assert_ne!(engine.bundle_blake3(), [0u8; 32]);
    let elapsed = t0.elapsed();
    assert!(
        elapsed < Duration::from_secs(10),
        "policy sync must meet freshness SLO p95 < 10 s (elapsed: {elapsed:?})"
    );
}

// ---------------------------------------------------------------------------
// DEFECT-F-64: inline bundles must match the signed target.
// ---------------------------------------------------------------------------

/// A3 call without step-up.
fn call_a3(s: &IfcService, t: &Biscuit, holder: &SigningKey, seq: u64) -> Decision {
    call(s, t, holder, seq, "export_report", json!({}))
}

#[test]
fn f64_root_permit_all_inline_is_refused_and_a3_stays_denied() {
    let dir = scratch("f64-root-permit-all");
    let audit = dir.join("audit.jsonl");
    // UID 702 serves the baseline as the signed target.
    let signed = CedarBundle::baseline().to_json_bytes().unwrap();
    let sock_dir = fake_cas(&dir, signed);
    let s = svc_with(
        audit.clone(),
        CedarEngine::baseline_bundle().unwrap(),
        Some(sock_dir),
        false,
    );
    let holder = SigningKey::generate(&mut rand_core::OsRng);
    let token = mint_turn_token(&s, &holder);
    let before = call_a3(&s, &token, &holder, 1);
    assert!(
        !before.allow,
        "A3 without step-up must be denied: {before:?}"
    );

    let e = refresh(&s, &root_peer(), permit_all_bytes()).unwrap_err();
    assert!(e.is("POLICY_INLINE_UNSIGNED"), "{e}");

    let after = call_a3(&s, &token, &holder, 2);
    assert!(
        !after.allow,
        "A3 must stay denied after refused swap: {after:?}"
    );
    assert_eq!(after.cedar_allow, before.cedar_allow);

    let ev = journal_events(&audit);
    let rej = has_event(&ev, "POLICY_BUNDLE_INLINE_REJECTED").expect("rejection journalled");
    let offered = blake3::hash(&permit_all_bytes()).to_hex().to_string();
    assert!(rej.to_string().contains(&offered), "{rej}");
    assert!(has_event(&ev, "POLICY_BUNDLE_HOTSWAP").is_none(), "{ev:?}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn f64_refused_forbid_bundle_leaves_policy_unchanged() {
    // Non-vacuity: a refused bundle that *would* deny select_bounded has no
    // effect, so the refusal (not the bundle content) is what kept policy.
    let dir = scratch("f64-nonvacuity");
    let audit = dir.join("audit.jsonl");
    let sock_dir = fake_cas(&dir, CedarBundle::baseline().to_json_bytes().unwrap());
    let s = svc_with(
        audit,
        CedarEngine::baseline_bundle().unwrap(),
        Some(sock_dir),
        false,
    );
    let holder = SigningKey::generate(&mut rand_core::OsRng);
    let token = mint_turn_token(&s, &holder);
    let args = json!({"table": "users", "columns": "id", "limit": 1});
    assert!(call(&s, &token, &holder, 1, "select_bounded", args.clone()).allow);
    let e = refresh(&s, &root_peer(), forbid_select_bytes()).unwrap_err();
    assert!(e.is("POLICY_INLINE_UNSIGNED"), "{e}");
    let d = call(&s, &token, &holder, 2, "select_bounded", args);
    assert!(d.allow && d.cedar_allow, "{d:?}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn f64_inline_matching_signed_target_is_accepted_with_provenance() {
    let dir = scratch("f64-match");
    let audit = dir.join("audit.jsonl");
    let signed = forbid_select_bytes();
    let sock_dir = fake_cas(&dir, signed.clone());
    let s = svc_with(
        audit.clone(),
        CedarEngine::baseline_bundle().unwrap(),
        Some(sock_dir),
        true,
    );
    assert!(matches!(
        refresh(&s, &root_peer(), signed.clone()).unwrap(),
        IfcResponse::Ok
    ));
    let ev = journal_events(&audit);
    let swap = has_event(&ev, "POLICY_BUNDLE_HOTSWAP").expect("swap journalled");
    assert!(
        swap.to_string().contains("inline_matches_signed_target"),
        "{swap}"
    );
    let want = CedarEngine::from_bundle(&CedarBundle::from_json_bytes(&signed).unwrap())
        .unwrap()
        .bundle_blake3();
    assert!(swap.to_string().contains(&hex::encode(want)), "{swap}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn f64_signed_none_path_journals_tuf_provenance() {
    let dir = scratch("f64-none");
    let audit = dir.join("audit.jsonl");
    let sock_dir = fake_cas(&dir, forbid_select_bytes());
    let s = svc_with(
        audit.clone(),
        CedarEngine::baseline_bundle().unwrap(),
        Some(sock_dir),
        true,
    );
    s.handle(
        &root_peer(),
        IfcRequest::RefreshPolicy { bundle_json: None },
    )
    .unwrap();
    let swap = has_event(&journal_events(&audit), "POLICY_BUNDLE_HOTSWAP").unwrap();
    assert!(swap.to_string().contains("\"tuf_signed\""), "{swap}");
    let _ = std::fs::remove_dir_all(&dir);
}

// Dev mode reaches the same-UID fake 702; simulation+dev would admit
// unsigned by design, so this runs in non-simulation builds.
#[cfg(not(feature = "simulation"))]
#[test]
fn f64_inline_differing_by_one_byte_is_refused() {
    let dir = scratch("f64-onebyte");
    let audit = dir.join("audit.jsonl");
    let signed = forbid_select_bytes();
    let mut offered = signed.clone();
    // Flip whitespace inside the JSON so the bundle still parses and validates.
    let pos = offered.iter().position(|b| *b == b' ').unwrap();
    offered[pos] = b'\t';
    assert!(CedarBundle::from_json_bytes(&offered).is_ok());
    let sock_dir = fake_cas(&dir, signed);
    let s = svc_with(
        audit,
        CedarEngine::baseline_bundle().unwrap(),
        Some(sock_dir),
        true,
    );
    let e = refresh(&s, &root_peer(), offered.clone()).unwrap_err();
    assert!(e.is("POLICY_INLINE_UNSIGNED"), "{e}");
    assert!(
        e.to_string().contains("differs from the signed target"),
        "{e}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn f64_no_signed_source_is_refused_for_root() {
    // No socket dir: there is no signed target to compare against.
    let dir = scratch("f64-nosource");
    let s = svc_with(
        dir.join("audit.jsonl"),
        CedarEngine::baseline_bundle().unwrap(),
        None,
        false,
    );
    let e = refresh(&s, &root_peer(), permit_all_bytes()).unwrap_err();
    assert!(e.is("POLICY_INLINE_UNSIGNED"), "{e}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(not(feature = "simulation"))]
#[test]
fn f64_dev_same_uid_does_not_admit_unsigned_without_simulation() {
    let dir = scratch("f64-dev-nosim");
    let sock_dir = fake_cas(&dir, CedarBundle::baseline().to_json_bytes().unwrap());
    let s = svc_with(
        dir.join("audit.jsonl"),
        CedarEngine::baseline_bundle().unwrap(),
        Some(sock_dir),
        true,
    );
    let e = refresh(&s, &admin(), permit_all_bytes()).unwrap_err();
    assert!(e.is("POLICY_INLINE_UNSIGNED"), "{e}");
    // And the pure gate agrees with no 702 at all.
    let e = admit_inline_bundle(
        &permit_all_bytes(),
        Err(enclave_core::err!(EIO, "NO_CAS")),
        true,
    )
    .unwrap_err();
    assert!(e.is("POLICY_INLINE_UNSIGNED"), "{e}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(feature = "simulation")]
#[test]
fn f64_simulation_dev_admits_unsigned_with_dev_provenance() {
    let dir = scratch("f64-dev-sim");
    let audit = dir.join("audit.jsonl");
    let s = svc_with(
        audit.clone(),
        CedarEngine::baseline_bundle().unwrap(),
        None,
        true,
    );
    refresh(&s, &admin(), forbid_select_bytes()).unwrap();
    let swap = has_event(&journal_events(&audit), "POLICY_BUNDLE_HOTSWAP").unwrap();
    assert!(
        swap.to_string().contains("inline_unsigned_dev_simulation"),
        "{swap}"
    );
    assert!(
        swap.to_string()
            .contains(enclave_agent_runtime::cedar_engine::UNSIGNED_INLINE_POLICY_MARKER),
        "{swap}"
    );
    // Simulation build, but not dev mode: still refused.
    let e = admit_inline_bundle(
        &permit_all_bytes(),
        Err(enclave_core::err!(EIO, "NO_CAS")),
        false,
    )
    .unwrap_err();
    assert!(e.is("POLICY_INLINE_UNSIGNED"), "{e}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn f64_admit_loads_fetched_bytes_and_reports_provenance() {
    let signed = forbid_select_bytes();
    let (b, p) = admit_inline_bundle(&signed, Ok(signed.clone()), false).unwrap();
    assert_eq!(p, PolicyProvenance::InlineMatchesSignedTarget);
    assert_eq!(b, CedarBundle::from_json_bytes(&signed).unwrap());
    assert_eq!(p.warning(), None);
    let mut one_byte = signed.clone();
    let last = one_byte.len() - 1;
    one_byte[last] ^= 0x01;
    let e = admit_inline_bundle(&one_byte, Ok(signed.clone()), false).unwrap_err();
    assert!(e.is("POLICY_INLINE_UNSIGNED"), "{e}");
    let e = admit_inline_bundle(&permit_all_bytes(), Ok(signed), false).unwrap_err();
    assert!(e.is("POLICY_INLINE_UNSIGNED"), "{e}");
}

#[test]
fn f64_same_uid_impostor_702_is_not_trusted_outside_dev() {
    // Production mode: the fetch must reach the real UID 702 (connect_verified).
    // A same-UID process serving the attacker's bytes as "signed" is refused.
    let dir = scratch("f64-impostor");
    let audit = dir.join("audit.jsonl");
    let sock_dir = fake_cas(&dir, permit_all_bytes());
    let s = svc_with(
        audit,
        CedarEngine::baseline_bundle().unwrap(),
        Some(sock_dir),
        false,
    );
    let e = refresh(&s, &root_peer(), permit_all_bytes()).unwrap_err();
    assert!(e.is("POLICY_INLINE_UNSIGNED"), "{e}");
    assert!(e.to_string().contains("SERVER_UID_MISMATCH"), "{e}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn f64_a3_denial_is_policy_dependent() {
    // Non-vacuity for the A3 check above: when a permit-all bundle *is* the
    // signed target, installing it changes Cedar's A3 decision. So the A3
    // denial after a refused swap is evidence the refusal held.
    let dir = scratch("f64-a3-control");
    let sock_dir = fake_cas(&dir, permit_all_bytes());
    let s = svc_with(
        dir.join("audit.jsonl"),
        CedarEngine::baseline_bundle().unwrap(),
        Some(sock_dir),
        true,
    );
    let holder = SigningKey::generate(&mut rand_core::OsRng);
    let token = mint_turn_token(&s, &holder);
    let before = call_a3(&s, &token, &holder, 1);
    assert!(!before.cedar_allow, "{before:?}");
    refresh(&s, &root_peer(), permit_all_bytes()).unwrap();
    let after = call_a3(&s, &token, &holder, 2);
    assert!(
        after.cedar_allow,
        "signed permit-all must flip Cedar: {after:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
