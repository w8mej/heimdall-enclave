//! GAP-04 – GAP-07 acceptance: the UID 704 IPC boundary decides only on
//! facts the enclave derives itself (signed MCP lock, heap labels, its own
//! clock, its own call to UID 703), mint/grant/label APIs are closed to
//! non-ingress peers, and `C4` never rests in this daemon unscrubbed.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use ed25519_dalek::SigningKey;
use enclave_agent_runtime::cedar_engine::{CedarEngine, BASELINE_POLICIES, DEFAULT_SCHEMA};
use enclave_agent_runtime::registry::{digest_tools_list, ToolRegistry};
use enclave_agent_runtime::service::{
    CustodyPort, Declassifier, IfcConfig, IfcRequest, IfcResponse, IfcService, NoCustody, StepUp,
};
use enclave_core::error::EnclaveResult;
use enclave_core::intent_draft::IntentDraftV1;
use enclave_core::ipc::PeerCredentials;
use enclave_core::label::Conf;
use enclave_core::profile::{ActionClass, Profile};
use enclave_core::user_turn::UserTurnV1;
use enclave_crypto::biscuit_auth::{AuthorizerLimits, Biscuit};
use enclave_crypto::pop_biscuit::{make_call, spec_limits, Transport, WireClock};
use serde_json::{json, Value};

#[derive(Debug)]
struct Fixed;
impl Declassifier for Fixed {
    fn classify(
        &self,
        _p: &[u8],
        _k: u64,
        _s: &str,
        slot: &enclave_core::seq::GovernedSlot,
    ) -> EnclaveResult<u64> {
        // GAP-27: the declassifier receives UID 703's signed epoch and the slot.
        enclave_crypto::epoch::verify(&slot.epoch)?;
        assert_eq!(slot.epoch.boot_epoch_id, EPOCH);
        Ok(0)
    }
}

fn test_epoch() -> enclave_core::seq::BootEpoch {
    static SIGNER: std::sync::OnceLock<enclave_crypto::epoch::EpochSigner> =
        std::sync::OnceLock::new();
    SIGNER
        .get_or_init(enclave_crypto::epoch::EpochSigner::random)
        .sign(EPOCH)
}

/// The sequence authority's epoch in these tests.
const EPOCH: &str = "6f1c2c1e-3a54-4b8e-9d7a-0c4f5b6a7e81";

/// Records every draft and scrub request; approves step-ups (unless `no_hw`)
/// and issues governed slots like UID 703.
#[derive(Debug, Default)]
struct FakeVault {
    drafts: Mutex<Vec<IntentDraftV1>>,
    scrubbed: Mutex<Vec<String>>,
    slots: Mutex<u64>,
    no_hw: bool,
}
#[derive(Debug)]
struct VaultPort(Arc<FakeVault>);
impl CustodyPort for VaultPort {
    fn scrub_text(&self, text: &str, bulk: bool) -> EnclaveResult<String> {
        if self.0.no_hw {
            return NoCustody.scrub_text(text, bulk);
        }
        self.0.scrubbed.lock().unwrap().push(text.to_owned());
        Ok(enclave_core::pii::scan(text)
            .iter()
            .fold(text.to_owned(), |t, f| {
                t.replace(&text[f.start..f.end], "[REDACTED_PAN_C4]")
            }))
    }
    fn authorize_intent(&self, d: &IntentDraftV1) -> EnclaveResult<StepUp> {
        if self.0.no_hw {
            return NoCustody.authorize_intent(d);
        }
        self.0.drafts.lock().unwrap().push(d.clone());
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

/// UID 703 is reachable for slots but has no hardware.
fn no_hw() -> Box<dyn CustodyPort> {
    Box::new(VaultPort(Arc::new(FakeVault {
        no_hw: true,
        ..Default::default()
    })))
}

/// A fresh private directory for one test.
fn scratch(tag: &str) -> std::path::PathBuf {
    let mut r = [0u8; 8];
    enclave_core::rng::fill(&mut r);
    let d = std::env::temp_dir().join(format!("mcpmac-{tag}-{}", hex::encode(r)));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn tools_list() -> Value {
    json!({"tools": [{"name": "select_bounded"}, {"name": "export_csv"}]})
}

fn lock() -> ToolRegistry {
    lock_with_qif(0)
}

fn lock_with_qif(qif_mb: i64) -> ToolRegistry {
    lock_for(qif_mb, Conf::C3)
}

fn lock_for(qif_mb: i64, clearance: Conf) -> ToolRegistry {
    let v = json!({
        "v": 1,
        "servers": [{
            "server": "postgres",
            "tools_list_blake3": digest_tools_list(&tools_list()).unwrap(),
            "tools": [
                {"name": "select_bounded", "action_class": "A1", "sink_clearance": clearance, "namespace": "dev-billing",
                 "canonical_verb": "Select", "slots": {"where_value": "BOUND_LITERAL"}, "row_count_arg": "limit", "max_rows": 25,
                 "qif_mb_per_call": qif_mb,
                 "output_conf": "C2", "entity_key_fields": ["customer_id"]},
                {"name": "export_csv", "action_class": "A3", "sink_clearance": "C3", "namespace": "dev-billing",
                 "canonical_verb": "Export", "slots": {"where_value": "BOUND_LITERAL"}, "output_conf": "C3"}
            ]
        }]
    });
    ToolRegistry::load(&serde_json::to_vec(&v).unwrap()).unwrap()
}

fn svc_with(custody: Box<dyn CustodyPort>, cedar: Option<CedarEngine>) -> Arc<IfcService> {
    let cfg = IfcConfig {
        profile: Profile::L2,
        audit_path: None,
        policy_key: SigningKey::generate(&mut rand_core::OsRng),
        limits: AuthorizerLimits {
            max_time: Duration::from_millis(50),
            ..spec_limits()
        },
        registry: lock(),
        cedar: cedar.or_else(|| CedarEngine::baseline_bundle().ok()),
        state_dir: None,
        socket_dir: None,
        dev_same_uid: true,
    };
    IfcService::start(cfg, Box::new(Fixed), custody).unwrap()
}

/// The single development UID: the operator / ingress stand-in.
fn admin() -> PeerCredentials {
    let mut p = PeerCredentials::local(enclave_core::ipc::geteuid(), 0);
    p.pid = Some(4242);
    p
}

/// Another daemon (the model host).
fn model_host() -> PeerCredentials {
    let mut p = PeerCredentials::local(701, 701);
    p.pid = Some(701);
    p
}

fn root_token(s: &IfcService, holder: &SigningKey) -> Biscuit {
    // DEFECT-F-67: the root token names the tools the turn may use.
    root_token_for(s, holder, &["select_bounded", "export_csv"]).unwrap()
}

fn signature(tool: &str) -> enclave_agent_runtime::turn::ToolSignature {
    enclave_agent_runtime::turn::ToolSignature {
        name: format!("mcp://postgres/{tool}"),
        description: tool.into(),
        params: vec![],
    }
}

fn root_token_for(s: &IfcService, holder: &SigningKey, tools: &[&str]) -> EnclaveResult<Biscuit> {
    root_token_for_budget(s, holder, tools, 12_000)
}

fn root_token_for_budget(
    s: &IfcService,
    holder: &SigningKey,
    tools: &[&str],
    budget_mb: i64,
) -> EnclaveResult<Biscuit> {
    let r = s.handle(
        &admin(),
        IfcRequest::SubmitTurn {
            turn: UserTurnV1 {
                directive_short: "triage invoices".into(),
                attachments: vec![],
            },
            attachments: vec![],
            tools: tools.iter().map(|t| signature(t)).collect(),
            holder_pk: Some(holder.verifying_key().to_bytes()),
            budget_mb,
        },
    )?;
    let IfcResponse::Plan {
        root_token: Some(t),
        ..
    } = r
    else {
        panic!("{r:?}")
    };
    Ok(Biscuit::from(t.as_slice(), s.root_public().unwrap()).unwrap())
}

fn ingest(
    s: &IfcService,
    tool: &str,
    payload: &str,
    hint: Option<Conf>,
) -> EnclaveResult<enclave_core::ifc_envelope::IfcEnvelopeV1> {
    match s.handle(
        &admin(),
        IfcRequest::IngestToolOutput {
            server: "postgres".into(),
            tool_name: tool.into(),
            tools_list: tools_list().to_string(),
            payload: payload.as_bytes().to_vec().into(),
            conf_hint: hint,
            source_uri: "pg://dev-billing".into(),
        },
    )? {
        IfcResponse::Handle(e) => Ok(e),
        r => panic!("{r:?}"),
    }
}

#[allow(clippy::too_many_arguments)]
fn call(
    s: &IfcService,
    t: &Biscuit,
    holder: &SigningKey,
    seq: u64,
    tool: &str,
    args: Value,
    handles: Vec<(String, String)>,
    step_up: bool,
) -> enclave_agent_runtime::pdp::Decision {
    try_call(s, t, holder, seq, tool, args, handles, step_up).unwrap()
}

#[allow(clippy::too_many_arguments)]
fn try_call(
    s: &IfcService,
    t: &Biscuit,
    holder: &SigningKey,
    seq: u64,
    tool: &str,
    args: Value,
    handles: Vec<(String, String)>,
    step_up: bool,
) -> EnclaveResult<enclave_agent_runtime::pdp::Decision> {
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
    let r = s.handle(
        &admin(),
        IfcRequest::AuthorizeToolCall {
            server: "postgres".into(),
            tool_name: tool.into(),
            args_jcs: args_jcs.into(),
            arg_handles: handles,
            wire_cbor: w.to_cbor().unwrap().into(),
            step_up,
        },
    )?;
    let IfcResponse::Decision(d) = r else {
        panic!("{r:?}")
    };
    Ok(d)
}

#[test]
fn service_enforces_tree_call_limit_before_authorization_release() {
    let service = svc_with(no_hw(), None);
    let holder = SigningKey::generate(&mut rand_core::OsRng);
    let token = root_token(&service, &holder);
    for seq in 1..=64 {
        assert!(
            call(
                &service,
                &token,
                &holder,
                seq,
                "select_bounded",
                json!({"limit":1}),
                vec![],
                false
            )
            .allow
        );
    }
    for seq in [65, 66] {
        let error = try_call(
            &service,
            &token,
            &holder,
            seq,
            "select_bounded",
            json!({"limit":1}),
            vec![],
            false,
        )
        .unwrap_err();
        assert!(error.is("TREE_CALL_BUDGET_EXHAUSTED"), "{error}");
    }
}

#[test]
fn tool_charge_persistence_failure_denies_current_call_and_latches_later_calls() {
    let dir = scratch("tool-qif-save-failure");
    let state_dir = dir.join("state");
    let service = IfcService::start(
        IfcConfig {
            profile: Profile::L2,
            audit_path: None,
            policy_key: SigningKey::generate(&mut rand_core::OsRng),
            limits: AuthorizerLimits {
                max_time: Duration::from_millis(50),
                ..spec_limits()
            },
            registry: lock_with_qif(1000),
            cedar: CedarEngine::baseline_bundle().ok(),
            state_dir: Some(state_dir.clone()),
            socket_dir: None,
            dev_same_uid: true,
        },
        Box::new(Fixed),
        no_hw(),
    )
    .unwrap();
    let holder = SigningKey::generate(&mut rand_core::OsRng);
    let token = root_token(&service, &holder);
    assert!(
        call(
            &service,
            &token,
            &holder,
            1,
            "select_bounded",
            json!({"limit":1}),
            vec![],
            false
        )
        .allow
    );
    // A directory at the state-file destination makes atomic replacement fail
    // even when the test runs as root. No timing or permission-mode race.
    let sealed = state_dir.join("qif-ledger.sealed");
    std::fs::remove_file(&sealed).unwrap();
    std::fs::create_dir(&sealed).unwrap();
    let error = try_call(
        &service,
        &token,
        &holder,
        2,
        "select_bounded",
        json!({"limit":1}),
        vec![],
        false,
    )
    .unwrap_err();
    assert!(
        !error.is("QIF_LEDGER_LATCHED"),
        "first call must reach the failed save: {error}"
    );
    // Removing the fault injection does not silently clear the latch.
    std::fs::remove_dir(&sealed).unwrap();
    let error = try_call(
        &service,
        &token,
        &holder,
        3,
        "select_bounded",
        json!({"limit":1}),
        vec![],
        false,
    )
    .unwrap_err();
    assert!(error.is("QIF_LEDGER_LATCHED"), "{error}");
    // The failed post-PDP persistence must retain its completed policy sample;
    // the subsequent pre-PDP latched rejection must not invent another sample.
    let telemetry = policy_sli(&service);
    assert_eq!((telemetry.observed_total, telemetry.observed_errors), (2, 0));
    drop(service);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn phase5_governed_tool_journal_records_the_reserved_charge_and_sealing_zero() {
    // Exercise the actual IFC authorization route, policy evaluation, tree/QIF
    // settlement, egress registry and durable journal writer. A string search
    // for the new field would not establish this value/caller correspondence.
    let dir = scratch("phase5-tool-journal-charge");
    let audit = dir.join("ifc-audit.jsonl");
    let service = IfcService::start(
        IfcConfig {
            profile: Profile::L2,
            audit_path: Some(audit.clone()),
            policy_key: SigningKey::generate(&mut rand_core::OsRng),
            limits: AuthorizerLimits { max_time: Duration::from_millis(50), ..spec_limits() },
            registry: lock_with_qif(37),
            cedar: CedarEngine::baseline_bundle().ok(),
            state_dir: Some(dir.join("state")),
            socket_dir: None,
            dev_same_uid: true,
        },
        Box::new(Fixed),
        no_hw(),
    ).unwrap();
    let holder = SigningKey::generate(&mut rand_core::OsRng);
    let token = root_token(&service, &holder);
    let output = ingest(&service, "select_bounded", r#"[{"customer_id":"synthetic-entity"}]"#, None).unwrap();
    assert!(call(&service, &token, &holder, 1, "select_bounded", json!({"limit":1}), vec![], false).allow);
    // A replay still reaches the governed DENY journal route, but reserves no
    // ledger/tree charge. The signed registry still prices this tool at 37.
    assert!(!call(&service, &token, &holder, 1, "select_bounded", json!({"limit":1}), vec![], false).allow);
    let rows: Vec<Value> = std::fs::read_to_string(&audit).unwrap().lines()
        .map(|line| serde_json::from_str(line).unwrap()).collect();
    let tools: Vec<_> = rows.iter().filter(|row| row["payload"]["event"] == "TOOL_CALL").collect();
    let sealed: Vec<_> = rows.iter().filter(|row| row["payload"]["event"] == "TOOL_OUTPUT_SEALED").collect();
    assert_eq!(tools.len(), 2);
    assert_eq!(sealed.len(), 1);
    assert_eq!(tools[0]["payload"]["qif_mb"], 37);
    assert_eq!(tools[0]["payload"]["decision"], "ALLOW");
    assert_eq!(tools[1]["payload"]["qif_mb"], 0);
    assert_eq!(tools[1]["payload"]["decision"], "DENY");
    assert_eq!(sealed[0]["payload"]["qif_mb"], 0);
    assert_eq!(sealed[0]["payload"]["handle"], output.handle);
    for row in [tools[0], tools[1], sealed[0]] {
        assert_eq!(row["boot_epoch_id"], EPOCH);
        assert_eq!(row["rpc_seq_u64"], row["payload"]["slot"]);
    }
    enclave_core::audit::verify_journal(&audit, None).unwrap();
    drop(service);
    std::fs::remove_dir_all(dir).unwrap();
}

fn metered_service() -> Arc<IfcService> {
    IfcService::start(
        IfcConfig {
            profile: Profile::L2,
            audit_path: None,
            policy_key: SigningKey::generate(&mut rand_core::OsRng),
            limits: AuthorizerLimits {
                max_time: Duration::from_millis(50),
                ..spec_limits()
            },
            registry: lock_with_qif(1000),
            cedar: CedarEngine::baseline_bundle().ok(),
            state_dir: None,
            socket_dir: None,
            dev_same_uid: true,
        },
        Box::new(Fixed),
        no_hw(),
    )
    .unwrap()
}

#[test]
fn tool_settlement_debits_the_resolved_input_entities() {
    let service = metered_service();
    let holder = SigningKey::generate(&mut rand_core::OsRng);
    let token = root_token(&service, &holder);
    let input = ingest(
        &service,
        "select_bounded",
        r#"[{"customer_id":"metered"}]"#,
        None,
    )
    .unwrap();
    for seq in 1..=12 {
        assert!(
            call(
                &service,
                &token,
                &holder,
                seq,
                "select_bounded",
                json!({"limit":1}),
                vec![("where_value".into(), input.handle.clone())],
                false
            )
            .allow
        );
    }
    // A fresh tree has its own call budget but shares the same entity ledger.
    let other = root_token(&service, &holder);
    let error = try_call(
        &service,
        &other,
        &holder,
        13,
        "select_bounded",
        json!({"limit":1}),
        vec![("where_value".into(), input.handle)],
        false,
    )
    .unwrap_err();
    assert!(error.is("QIF_BUDGET_EXCEEDED"), "{error}");
}

#[test]
fn tool_tree_budget_is_cumulative_across_calls() {
    let service = metered_service();
    let holder = SigningKey::generate(&mut rand_core::OsRng);
    let token = root_token_for_budget(&service, &holder, &["select_bounded"], 2000).unwrap();
    for seq in 1..=2 {
        assert!(
            call(
                &service,
                &token,
                &holder,
                seq,
                "select_bounded",
                json!({"limit":1}),
                vec![],
                false
            )
            .allow
        );
    }
    let error = try_call(
        &service,
        &token,
        &holder,
        3,
        "select_bounded",
        json!({"limit":1}),
        vec![],
        false,
    )
    .unwrap_err();
    assert!(error.is("QIF_CONSERVATION_VIOLATION"), "{error}");
}

#[test]
fn tool_facts_come_from_the_lock_not_the_caller() {
    let vault = Arc::new(FakeVault::default());
    let s = svc_with(Box::new(VaultPort(vault.clone())), None);
    let holder = SigningKey::generate(&mut rand_core::OsRng);
    let t = root_token(&s, &holder);
    let v = ingest(
        &s,
        "select_bounded",
        r#"[{"customer_id":"c1","amount":10}]"#,
        None,
    )
    .unwrap();
    assert_eq!(v.label.c, Conf::C2);
    // A1 select within the lock's bounds: allowed by both engines.
    let d = call(
        &s,
        &t,
        &holder,
        1,
        "select_bounded",
        json!({"limit": 10, "where_value": "x"}),
        vec![("where_value".into(), v.handle.clone())],
        false,
    );
    assert!(d.allow, "{d:?}");
    // The caller cannot widen the row bound past the lock.
    let e = s
        .handle(
            &admin(),
            IfcRequest::AuthorizeToolCall {
                server: "postgres".into(),
                tool_name: "select_bounded".into(),
                args_jcs: enclave_core::jcs::canonicalize(&json!({"limit": 1000}))
                    .unwrap()
                    .into(),
                arg_handles: vec![],
                wire_cbor: vec![0u8].into(),
                step_up: false,
            },
        )
        .unwrap_err();
    assert!(e.is("ROW_BOUND_EXCEEDS_LOCK"), "{e}");
    // An argument the lock does not declare is AST_STRUCTURAL: a T3 handle there fails closed.
    let e = s
        .handle(
            &admin(),
            IfcRequest::AuthorizeToolCall {
                server: "postgres".into(),
                tool_name: "select_bounded".into(),
                args_jcs: enclave_core::jcs::canonicalize(&json!({"limit": 1, "table": "t"}))
                    .unwrap()
                    .into(),
                arg_handles: vec![("table".into(), v.handle.clone())],
                wire_cbor: vec![0u8].into(),
                step_up: false,
            },
        )
        .unwrap_err();
    assert!(e.is("T3_BIBA_VIOLATION"), "{e}");
    // Non-canonical argument bytes are refused (the PoP covers exactly the JCS bytes).
    let e = s
        .handle(
            &admin(),
            IfcRequest::AuthorizeToolCall {
                server: "postgres".into(),
                tool_name: "select_bounded".into(),
                args_jcs: br#"{ "limit": 1 }"#.to_vec().into(),
                arg_handles: vec![],
                wire_cbor: vec![0u8].into(),
                step_up: false,
            },
        )
        .unwrap_err();
    assert!(e.is("ARGS_NOT_JCS"));
    // An unannotated tool is default-conservative: every argument is
    // AST_STRUCTURAL, so no tool output (always T3) can reach it at all.
    let e = s
        .handle(
            &admin(),
            IfcRequest::AuthorizeToolCall {
                server: "postgres".into(),
                tool_name: "drop_everything".into(),
                args_jcs: enclave_core::jcs::canonicalize(&json!({"where_value": "x"}))
                    .unwrap()
                    .into(),
                arg_handles: vec![("where_value".into(), v.handle.clone())],
                wire_cbor: vec![0u8].into(),
                step_up: false,
            },
        )
        .unwrap_err();
    assert!(e.is("T3_BIBA_VIOLATION"));
    // ...and its C1 sink refuses even C2 data that is not T3 (Bell-LaPadula).
    let d2 = ingest(&s, "select_bounded", "[]", None).unwrap();
    let IfcResponse::Handle(enumv) = s
        .handle(
            &admin(),
            IfcRequest::DeclassifyEnum {
                agent: "o".into(),
                handle: d2.handle,
                cardinality: 4,
                schema: "ServiceTarget".into(),
            },
        )
        .unwrap()
    else {
        panic!()
    };
    let derived = enumv.handle;
    let d = call(
        &s,
        &t,
        &holder,
        2,
        "drop_everything",
        json!({"where_value": "x"}),
        vec![("where_value".into(), derived)],
        false,
    );
    assert!(!d.allow && !d.cedar_allow, "{d:?}");
}

#[test]
fn hardware_grant_is_the_enclaves_own_step_up() {
    let vault = Arc::new(FakeVault::default());
    let s = svc_with(Box::new(VaultPort(vault.clone())), None);
    let holder = SigningKey::generate(&mut rand_core::OsRng);
    let t = root_token(&s, &holder);
    let v = ingest(&s, "select_bounded", r#"[{"customer_id":"c1"}]"#, None).unwrap();
    let h = vec![("where_value".to_owned(), v.handle.clone())];
    // A3 without a step-up: Cedar forbids; there is no way to claim `hw_grant`.
    let d = call(
        &s,
        &t,
        &holder,
        1,
        "export_csv",
        json!({"where_value": "x"}),
        h.clone(),
        false,
    );
    assert!(!d.allow && !d.cedar_allow, "{d:?}");
    assert!(vault.drafts.lock().unwrap().is_empty());
    // With a step-up, UID 704 builds the draft from the lock and the heap.
    let d = call(
        &s,
        &t,
        &holder,
        2,
        "export_csv",
        json!({"where_value": "x"}),
        h,
        true,
    );
    assert!(d.allow, "{d:?}");
    let drafts = vault.drafts.lock().unwrap();
    assert_eq!(drafts.len(), 1);
    let dr = &drafts[0];
    assert_eq!(
        (
            dr.action_class,
            dr.canonical_verb.as_str(),
            dr.row_count_bound,
            dr.data_class
        ),
        (ActionClass::A3, "Export", 1, Conf::C2)
    );
    assert_eq!(dr.tool_name, "mcp://postgres/export_csv");
    // No custody configured: the step-up fails closed.
    let s2 = svc_with(no_hw(), None);
    let t2 = root_token(&s2, &holder);
    let v2 = ingest(&s2, "select_bounded", "[]", None).unwrap();
    let args = enclave_core::jcs::canonicalize(&json!({"where_value": "x"})).unwrap();
    let clock = WireClock {
        local_boot_id: Some(s2.boot_epoch_id().unwrap()),
        mach_continuous_time_ns_expiry: Some(u64::MAX >> 2),
        ..Default::default()
    };
    let w = make_call(
        &t2,
        &holder,
        &admin().channel_binding(),
        &args,
        1,
        Transport::Uds,
        clock,
    )
    .unwrap();
    let e = s2
        .handle(
            &admin(),
            IfcRequest::AuthorizeToolCall {
                server: "postgres".into(),
                tool_name: "export_csv".into(),
                args_jcs: args.into(),
                arg_handles: vec![("where_value".into(), v2.handle)],
                wire_cbor: w.to_cbor().unwrap().into(),
                step_up: true,
            },
        )
        .unwrap_err();
    assert!(e.is("CUSTODY_UNAVAILABLE"));
}

#[test]
fn mint_and_grant_are_closed_to_other_daemons() {
    let s = svc_with(no_hw(), None);
    let e = s.handle(
        &model_host(),
        IfcRequest::SubmitTurn {
            turn: UserTurnV1 {
                directive_short: "x".into(),
                attachments: vec![],
            },
            attachments: vec![],
            tools: vec![],
            holder_pk: Some([7; 32]),
            budget_mb: 12_000,
        },
    );
    if enclave_core::ipc::geteuid() != 701 {
        assert!(e.unwrap_err().is("SUBMIT_TURN_INGRESS_ONLY"));
        assert!(s
            .handle(
                &model_host(),
                IfcRequest::IssueCustodyGrant {
                    workflow: "fraud-review".into(),
                    ttl_s: 60
                }
            )
            .unwrap_err()
            .is("CUSTODY_GRANT_ADMIN_ONLY"));
    }
    // Even the operator gets no grant for a workflow the signed bundle does not name.
    assert!(s
        .handle(
            &admin(),
            IfcRequest::IssueCustodyGrant {
                workflow: "fraud-review".into(),
                ttl_s: 60
            }
        )
        .unwrap_err()
        .is("CEDAR_DENY_REVERSIBLE_TOKENIZE"));
    let org = format!("{BASELINE_POLICIES}\npermit (principal, action == Custody::Action::\"ReversibleTokenize\", resource == Custody::Workflow::\"fraud-review\") when {{ context.profile >= 2 }};\n");
    let s = svc_with(
        no_hw(),
        Some(CedarEngine::load(DEFAULT_SCHEMA, &org).unwrap()),
    );
    assert!(matches!(
        s.handle(
            &admin(),
            IfcRequest::IssueCustodyGrant {
                workflow: "fraud-review".into(),
                ttl_s: 60
            }
        )
        .unwrap(),
        IfcResponse::Grant { .. }
    ));
    assert!(s
        .handle(
            &admin(),
            IfcRequest::IssueCustodyGrant {
                workflow: "adhoc".into(),
                ttl_s: 60
            }
        )
        .is_err());
}

#[test]
fn labels_only_rise_and_c4_is_scrubbed_by_uid_703() {
    let vault = Arc::new(FakeVault::default());
    let s = svc_with(Box::new(VaultPort(vault.clone())), None);
    // A hint cannot lower the lock's floor (C2), only raise it.
    assert_eq!(
        ingest(&s, "select_bounded", "[]", Some(Conf::C1))
            .unwrap()
            .label
            .c,
        Conf::C2
    );
    assert_eq!(
        ingest(&s, "select_bounded", "[]", Some(Conf::C3))
            .unwrap()
            .label
            .c,
        Conf::C3
    );
    // A tool of a pinned server that the lock does not annotate is (C3, T3).
    assert_eq!(
        ingest(&s, "unlisted_tool", "[]", Some(Conf::C1))
            .unwrap()
            .label
            .c,
        Conf::C3
    );
    // Entity keys come from the lock's fields, not the caller.
    assert_eq!(
        ingest(
            &s,
            "select_bounded",
            r#"[{"customer_id":"c1"},{"customer_id":"c2"}]"#,
            None
        )
        .unwrap()
        .entity_keys
        .len(),
        2
    );
    // A PAN in a tool output never rests here: it goes to UID 703 first.
    let pan = r#"[{"customer_id":"c9","card":"4111 1111 1111 1111"}]"#;
    let env = ingest(&s, "select_bounded", pan, None).unwrap();
    assert_eq!(env.label.c, Conf::C4);
    assert_eq!(vault.scrubbed.lock().unwrap().len(), 1);
    let stored = s.payload_for_test(&env.handle).unwrap();
    assert!(
        !String::from_utf8_lossy(&stored).contains("4111"),
        "raw PAN in the heap"
    );
    // Without UID 703, C4 ingress fails closed.
    let s2 = svc_with(no_hw(), None);
    assert!(ingest(&s2, "select_bounded", pan, None)
        .unwrap_err()
        .is("CUSTODY_UNAVAILABLE"));
    // Unpinned servers and drifted tool lists are refused.
    let e = s
        .handle(
            &admin(),
            IfcRequest::IngestToolOutput {
                server: "postgres".into(),
                tool_name: "select_bounded".into(),
                tools_list: json!({"tools": []}).to_string(),
                payload: b"[]".to_vec().into(),
                conf_hint: None,
                source_uri: "x".into(),
            },
        )
        .unwrap_err();
    assert!(e.is("TOOLS_LIST_DRIFT"));
}

#[test]
fn a_cosigned_tombstone_permanently_blocks_later_release_of_that_slot() {
    let vault = Arc::new(FakeVault::default());
    let s = svc_with(Box::new(VaultPort(vault)), None);
    // UID 704 can attest its own nonrelease even before seeing UID 703's
    // allocated slot. Once signed, this assertion must remain true forever.
    let signature = s
        .handle(
            &admin(),
            IfcRequest::CoSignTombstone {
                slot_rpc_seq: 1,
                boot_epoch_id: EPOCH.into(),
            },
        )
        .unwrap();
    assert!(matches!(signature, IfcResponse::TombstoneSignature { .. }));
    let error = ingest(
        &s,
        "select_bounded",
        r#"[{"customer_id":"closed-slot"}]"#,
        None,
    )
    .unwrap_err();
    assert!(error.is("TOMBSTONE_SLOT_FINALIZED"), "{error}");
}

#[test]
fn governed_calls_need_a_slot_and_released_slots_cannot_be_tombstoned() {
    // Without the sequence authority nothing governed happens (fail closed).
    let s0 = svc_with(Box::new(NoCustody), None);
    assert!(ingest(&s0, "select_bounded", "[]", None)
        .unwrap_err()
        .is("CUSTODY_UNAVAILABLE"));

    let dir = scratch("ifc-slots");
    let audit = dir.join("ifc-audit.jsonl");
    let mk = |vault: Arc<FakeVault>| {
        let cfg = IfcConfig {
            profile: Profile::L2,
            audit_path: Some(audit.clone()),
            policy_key: SigningKey::generate(&mut rand_core::OsRng),
            limits: AuthorizerLimits {
                max_time: Duration::from_millis(50),
                ..spec_limits()
            },
            registry: lock(),
            cedar: CedarEngine::baseline_bundle().ok(),
            state_dir: Some(dir.join("state")),
            socket_dir: None,
            dev_same_uid: true,
        };
        IfcService::start(cfg, Box::new(Fixed), Box::new(VaultPort(vault))).unwrap()
    };
    let vault = Arc::new(FakeVault::default());
    let s = mk(vault.clone());
    let v = ingest(&s, "select_bounded", "[]", None).unwrap(); // slot 1, released
    let r = s
        .handle(
            &admin(),
            IfcRequest::DeclassifyEnum {
                agent: "o".into(),
                handle: v.handle,
                cardinality: 4,
                schema: "S".into(),
            },
        )
        .unwrap(); // slot 2
    assert!(matches!(r, IfcResponse::Handle(_)));
    let cosign = |s: &IfcService, slot: u64| {
        s.handle(
            &admin(),
            IfcRequest::CoSignTombstone {
                slot_rpc_seq: slot,
                boot_epoch_id: EPOCH.into(),
            },
        )
    };
    assert!(cosign(&s, 1).unwrap_err().is("TOMBSTONE_SLOT_RELEASED"));
    assert!(cosign(&s, 2).unwrap_err().is("TOMBSTONE_SLOT_RELEASED"));
    // A slot UID 704 never released may be tombstoned.
    let IfcResponse::TombstoneSignature { public_key, .. } = cosign(&s, 3).unwrap() else {
        panic!()
    };
    // The release record and the tombstone key survive a restart.
    drop(s);
    let s = mk(vault);
    assert!(cosign(&s, 1).unwrap_err().is("TOMBSTONE_SLOT_RELEASED"));
    let IfcResponse::TombstoneSignature {
        public_key: pk2, ..
    } = cosign(&s, 3).unwrap()
    else {
        panic!()
    };
    assert_eq!(public_key, pk2);
    // The model host may not ask for tombstones.
    if enclave_core::ipc::geteuid() != 701 {
        assert!(s
            .handle(
                &model_host(),
                IfcRequest::CoSignTombstone {
                    slot_rpc_seq: 3,
                    boot_epoch_id: EPOCH.into()
                }
            )
            .unwrap_err()
            .is("TOMBSTONE_PEER_REJECTED"));
    }
    // Governed journal lines carry 703's epoch and slot; DeclassifyEnum its QIF cost.
    let lines: Vec<Value> = std::fs::read_to_string(&audit)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    let gov: Vec<&Value> = lines
        .iter()
        .filter(|l| l["payload"]["slot"].is_u64())
        .collect();
    assert_eq!(gov.len(), 2, "{lines:?}");
    assert!(gov
        .iter()
        .all(|l| l["boot_epoch_id"] == EPOCH && l["rpc_seq_u64"] == l["payload"]["slot"]));
    assert_eq!(
        gov[1]["payload"]["qif_mb"],
        enclave_core::qif::millibits_for_outcomes(5)
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn declassifier_error_charge_is_durable_before_the_error_is_returned() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    #[derive(Debug)]
    struct Fails(Arc<AtomicUsize>);
    impl Declassifier for Fails {
        fn classify(
            &self,
            _: &[u8],
            _: u64,
            _: &str,
            _: &enclave_core::seq::GovernedSlot,
        ) -> EnclaveResult<u64> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Err(enclave_core::err!(
                EINVAL,
                "SECRET_BACKEND_ERROR",
                "payload dependent"
            ))
        }
    }
    let dir = scratch("ifc-paid-error");
    let calls = Arc::new(AtomicUsize::new(0));
    let mk = || {
        IfcService::start(
            IfcConfig {
                profile: Profile::L2,
                audit_path: Some(dir.join("audit.jsonl")),
                policy_key: SigningKey::generate(&mut rand_core::OsRng),
                limits: AuthorizerLimits {
                    max_time: Duration::from_millis(50),
                    ..spec_limits()
                },
                registry: lock(),
                cedar: CedarEngine::baseline_bundle().ok(),
                state_dir: Some(dir.join("state")),
                socket_dir: None,
                dev_same_uid: true,
            },
            Box::new(Fails(calls.clone())),
            Box::new(VaultPort(Arc::new(FakeVault::default()))),
        )
        .unwrap()
    };
    let request = |s: &IfcService| {
        let v = ingest(
            s,
            "select_bounded",
            r#"[{"customer_id":"paid-error"}]"#,
            None,
        )
        .unwrap();
        s.handle(
            &admin(),
            IfcRequest::DeclassifyEnum {
                agent: "o".into(),
                handle: v.handle,
                cardinality: 4095,
                schema: "S".into(),
            },
        )
    };
    let s = mk();
    assert!(request(&s).unwrap_err().is("DECLASSIFIER_FAILED"));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let entries: Vec<Value> = std::fs::read_to_string(dir.join("audit.jsonl"))
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    let failure = entries
        .iter()
        .find(|e| e["payload"]["event"] == "DECLASSIFY_ENUM_FAILED")
        .unwrap();
    assert_eq!(failure["payload"]["qif_mb"], 12000);
    let slot = failure["payload"]["slot"].as_u64().unwrap();
    assert!(s
        .handle(
            &admin(),
            IfcRequest::CoSignTombstone {
                slot_rpc_seq: slot,
                boot_epoch_id: EPOCH.into(),
            }
        )
        .unwrap_err()
        .is("TOMBSTONE_SLOT_RELEASED"));
    let encoded = serde_json::to_string(failure).unwrap();
    assert!(!encoded.contains("SECRET_BACKEND_ERROR") && !encoded.contains("payload dependent"));
    drop(s);
    let s = mk();
    assert!(request(&s).unwrap_err().is("QIF_BUDGET_EXCEEDED"));
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "exhausted request must not inspect payload"
    );
    drop(s);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn qif_ledger_survives_restart_and_fails_closed() {
    let dir = scratch("ifc-qif");
    let mk = || {
        let cfg = IfcConfig {
            profile: Profile::L2,
            audit_path: None,
            policy_key: SigningKey::generate(&mut rand_core::OsRng),
            limits: AuthorizerLimits {
                max_time: Duration::from_millis(50),
                ..spec_limits()
            },
            registry: lock(),
            cedar: CedarEngine::baseline_bundle().ok(),
            state_dir: Some(dir.join("state")),
            socket_dir: None,
            dev_same_uid: true,
        };
        IfcService::start(
            cfg,
            Box::new(Fixed),
            Box::new(VaultPort(Arc::new(FakeVault::default()))),
        )
        .unwrap()
    };
    let row = r#"[{"customer_id":"c-42"}]"#;
    // 4095 values plus one failure cost 12,000 mb: the whole window budget.
    let declassify = |s: &IfcService| {
        let v = ingest(s, "select_bounded", row, None).unwrap();
        s.handle(
            &admin(),
            IfcRequest::DeclassifyEnum {
                agent: "o".into(),
                handle: v.handle,
                cardinality: 4095,
                schema: "S".into(),
            },
        )
    };
    let status = |s: &IfcService| match s.handle(&admin(), IfcRequest::Status).unwrap() {
        IfcResponse::Status(st) => st.state,
        r => panic!("{r:?}"),
    };
    let s = mk();
    assert!(status(&s).contains("qif_ledger=sealed"));
    declassify(&s).unwrap();
    assert!(declassify(&s).unwrap_err().is("QIF_BUDGET_EXCEEDED"));
    drop(s);
    // Same entity after a restart: K_vault and the ledger are stable.
    let s = mk();
    assert!(
        declassify(&s).unwrap_err().is("QIF_BUDGET_EXCEEDED"),
        "restart must not reset the 24 h budget"
    );
    drop(s);
    // A deleted ledger is never "clean".
    std::fs::remove_file(dir.join("state/qif-ledger.sealed")).unwrap();
    let s = mk();
    assert!(status(&s).contains("qif_ledger=latched"));
    let e = declassify(&s).unwrap_err();
    assert!(
        e.is("QIF_LEDGER_LATCHED") && e.to_string().contains("STATE_MISSING"),
        "{e}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_quarantine_abort_blocks_subsequent_tool_calls() {
    let vault = Arc::new(FakeVault::default());
    let s = svc_with(Box::new(VaultPort(vault.clone())), None);
    // Force transition to QuarantineAbort
    s.set_flow_state_for_test(enclave_agent_runtime::flow_fsm::FlowState::QuarantineAbort)
        .unwrap();
    // Attempting to authorize a tool call must fail closed with FLOW_GATE_QUARANTINE_ABORT
    let err = s
        .handle(
            &admin(),
            IfcRequest::AuthorizeToolCall {
                server: "sqlite".into(),
                tool_name: "query".into(),
                args_jcs: serde_bytes::ByteBuf::from(b"{}".to_vec()),
                arg_handles: Vec::new(),
                wire_cbor: serde_bytes::ByteBuf::from(Vec::new()),
                step_up: false,
            },
        )
        .unwrap_err();
    assert!(
        err.is("FLOW_GATE_QUARANTINE_ABORT"),
        "Expected FLOW_GATE_QUARANTINE_ABORT, got: {err}"
    );
}

// F66's former ignored failure contract now runs in the ordinary suite.
#[test]
fn f66_literal_copy_must_not_drop_the_recorded_confidentiality() {
    let vault = Arc::new(FakeVault::default());
    let s = svc_with(Box::new(VaultPort(vault)), None);
    let holder = SigningKey::generate(&mut rand_core::OsRng);
    let t = root_token(&s, &holder);
    let marker = "F66-MARKER-confidential";
    let handle = ingest(&s, "select_bounded", marker, Some(Conf::C4)).unwrap();
    let by_handle = call(
        &s,
        &t,
        &holder,
        1,
        "select_bounded",
        json!({"limit": 1, "where_value": marker}),
        vec![("where_value".into(), handle.handle)],
        false,
    );
    assert!(
        !by_handle.allow,
        "control must reject C4 at C3 sink: {by_handle:?}"
    );
    let literal = call(
        &s,
        &t,
        &holder,
        2,
        "select_bounded",
        json!({"limit": 1, "where_value": marker}),
        vec![],
        false,
    );
    assert!(
        !literal.allow,
        "literal copy must retain confidentiality: {literal:?}"
    );
}

fn f66_service(clearance: Conf, state_dir: Option<std::path::PathBuf>) -> Arc<IfcService> {
    IfcService::start(IfcConfig {
        profile: Profile::L2,
        audit_path: None,
        policy_key: SigningKey::generate(&mut rand_core::OsRng),
        limits: AuthorizerLimits { max_time: Duration::from_millis(50), ..spec_limits() },
        registry: lock_for(1000, clearance),
        cedar: Some(CedarEngine::baseline_bundle().unwrap()),
        state_dir,
        socket_dir: None,
        dev_same_uid: true,
    }, Box::new(Fixed), Box::new(VaultPort(Arc::new(FakeVault::default())))).unwrap()
}

#[test]
fn f66_low_literal_and_equal_clearance_calls_remain_usable() {
    let s = f66_service(Conf::C1, None);
    let holder = SigningKey::generate(&mut rand_core::OsRng);
    let token = root_token(&s, &holder);
    let low = call(&s, &token, &holder, 1, "select_bounded", select_args(), vec![], false);
    assert!(low.allow, "low structural arguments must work before exposure: {low:?}");
    assert_eq!(low.input_label, enclave_core::label::Label::DIRECTIVE);
    let s = f66_service(Conf::C4, None);
    let token = root_token(&s, &holder);
    let env = ingest(&s, "select_bounded", "F66-secret", Some(Conf::C4)).unwrap();
    let high = call(&s, &token, &holder, 1, "select_bounded",
        json!({"limit": 1, "where_value": {"nested": ["F66-secret", 123, true]}}), vec![], false);
    assert!(high.allow, "opaque bound literals at adequate clearance remain usable: {high:?}");
    assert_eq!(high.input_label, env.label);
}

#[test]
fn f66_transformed_and_nested_literals_cannot_launder_exposure() {
    let s = svc_with(no_hw(), None);
    let holder = SigningKey::generate(&mut rand_core::OsRng);
    let token = root_token(&s, &holder);
    let env = ingest(&s, "select_bounded", "F66-MARKER-confidential", Some(Conf::C4)).unwrap();
    for (i, value) in [json!("changed-one-byte"), json!({"nested": [false, 7]}), json!(null)].into_iter().enumerate() {
        let decision = call(&s, &token, &holder, i as u64 + 1, "select_bounded",
            json!({"limit": 1, "where_value": value}), vec![], false);
        assert!(!decision.allow, "encoded values must retain exposure: {decision:?}");
        assert_eq!(decision.input_label, env.label);
    }
    s.handle(&admin(), IfcRequest::ReleaseHandles { handles: vec![env.handle] }).unwrap();
    let after_release = call(&s, &token, &holder, 4, "select_bounded", select_args(), vec![], false);
    assert!(!after_release.allow);
    s.handle(&admin(), IfcRequest::Wipe).unwrap();
    let after_wipe = call(&s, &token, &holder, 5, "select_bounded", select_args(), vec![], false);
    assert!(!after_wipe.allow);
    assert_eq!(after_wipe.input_label, env.label);
}

#[test]
fn f66_literals_in_structural_slots_retain_exposure_taint() {
    let s = f66_service(Conf::C4, None);
    let holder = SigningKey::generate(&mut rand_core::OsRng);
    let token = root_token(&s, &holder);
    ingest(&s, "select_bounded", "untrusted-query-template", Some(Conf::C2)).unwrap();
    let structural = call(&s, &token, &holder, 1, "select_bounded",
        json!({"limit": 1, "query": "SELECT 1", "where_value": "safe"}), vec![], false);
    assert!(!structural.allow, "T3 literal may not supply an ungoverned structural field: {structural:?}");
    let bound = call(&s, &token, &holder, 2, "select_bounded", select_args(), vec![], false);
    assert!(bound.allow, "validated row-bound and opaque bound data remain usable: {bound:?}");
}

#[test]
fn f66_attachment_ingress_and_restart_keep_provenance() {
    use enclave_core::user_turn::TurnBuilder;
    let dir = scratch("f66-durable-exposure");
    let holder = SigningKey::generate(&mut rand_core::OsRng);
    let s = f66_service(Conf::C1, Some(dir.clone()));
    let (turn, blobs) = TurnBuilder::new().directive("inspect attachment").unwrap()
        .typed_or_pasted("private\nattachment marker").unwrap().build().unwrap();
    let response = s.handle(&admin(), IfcRequest::SubmitTurn {
        turn,
        attachments: blobs.into_iter().map(|b| (b.reference.handle, b.bytes.into())).collect(),
        tools: vec![signature("select_bounded")],
        holder_pk: Some(holder.verifying_key().to_bytes()), budget_mb: 12_000,
    }).unwrap();
    let IfcResponse::Plan { root_token: Some(bytes), .. } = response else { panic!("{response:?}") };
    let token = Biscuit::from(bytes.as_slice(), s.root_public().unwrap()).unwrap();
    let d = call(&s, &token, &holder, 1, "select_bounded", select_args(), vec![], false);
    assert!(!d.allow);
    assert_eq!(d.input_label, enclave_core::label::Label::ATTACHMENT_DEFAULT);
    drop(s);
    let s = f66_service(Conf::C1, Some(dir.clone()));
    let token = root_token(&s, &holder);
    let d = call(&s, &token, &holder, 1, "select_bounded", select_args(), vec![], false);
    assert!(!d.allow, "restart must not forget plaintext retained by peers: {d:?}");
    assert_eq!(d.input_label, enclave_core::label::Label::ATTACHMENT_DEFAULT);
    drop(s);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn f66_durable_record_tamper_is_not_a_clean_restart() {
    let dir = scratch("f66-exposure-tamper");
    drop(f66_service(Conf::C3, Some(dir.clone())));
    std::fs::write(dir.join("literal-exposure.sealed"), b"tampered").unwrap();
    let error = IfcService::start(IfcConfig {
        profile: Profile::L2, audit_path: None,
        policy_key: SigningKey::generate(&mut rand_core::OsRng), limits: spec_limits(),
        registry: lock(), cedar: None, state_dir: Some(dir.clone()), socket_dir: None,
        dev_same_uid: true,
    }, Box::new(Fixed), no_hw()).unwrap_err();
    assert!(error.is("STATE_TAMPERED"), "{error}");
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn f66_interrupted_ingress_recovers_conservative_crash_floor() {
    #[derive(Debug)]
    struct Interrupted;
    impl Declassifier for Interrupted {
        fn classify(&self, _: &[u8], _: u64, _: &str,
            _: &enclave_core::seq::GovernedSlot) -> EnclaveResult<u64> {
            panic!("simulate termination after write-ahead, before final provenance save")
        }
    }
    let dir = scratch("f66-interrupted-ingress");
    let service = IfcService::start(IfcConfig {
        profile: Profile::L2, audit_path: None,
        policy_key: SigningKey::generate(&mut rand_core::OsRng), limits: spec_limits(),
        registry: lock(), cedar: Some(CedarEngine::baseline_bundle().unwrap()),
        state_dir: Some(dir.clone()), socket_dir: None, dev_same_uid: true,
    }, Box::new(Interrupted), no_hw()).unwrap();
    let env = ingest(&service, "select_bounded", "public-example", Some(Conf::C2)).unwrap();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = service.handle(&admin(), IfcRequest::DeclassifyEnum {
            agent: "test".into(), handle: env.handle, cardinality: 2, schema: "enum".into(),
        });
    }));
    assert!(result.is_err(), "fixture must interrupt the in-flight operation");
    drop(service);
    let service = f66_service(Conf::C3, Some(dir.clone()));
    let holder = SigningKey::generate(&mut rand_core::OsRng);
    let token = root_token(&service, &holder);
    let d = call(&service, &token, &holder, 1, "select_bounded", select_args(), vec![], false);
    assert!(!d.allow);
    assert_eq!(d.input_label, enclave_core::label::Label::TOP,
        "incomplete ingress must not reload the older lower floor");
    drop(service);
    std::fs::remove_dir_all(dir).unwrap();
}

// ---- DEFECT-F-67 ---------------------------------------------------------

fn select_args() -> Value {
    json!({"limit": 1, "where_value": "x"})
}

#[test]
fn f67_empty_tool_list_root_token_authorises_no_tool() {
    let s = svc_with(no_hw(), None);
    let holder = SigningKey::generate(&mut rand_core::OsRng);
    let t = root_token_for(&s, &holder, &[]).unwrap();
    let d = call(
        &s,
        &t,
        &holder,
        1,
        "select_bounded",
        select_args(),
        vec![],
        false,
    );
    assert!(!d.biscuit_allow && !d.allow, "{d:?}");
    // The refusal is the root block's tool caveat (the empty set), not a
    // missing token: the same token shape with the tool named is allowed
    // (`f67_named_tool_is_allowed_non_vacuity`).
    let why = d.biscuit_error.clone().unwrap_or_default();
    assert!(why.contains("check if tool($t)"), "{why}");
}

#[test]
fn f67_named_tool_is_allowed_non_vacuity() {
    let s = svc_with(no_hw(), None);
    let holder = SigningKey::generate(&mut rand_core::OsRng);
    let t = root_token_for(&s, &holder, &["select_bounded"]).unwrap();
    let d = call(
        &s,
        &t,
        &holder,
        1,
        "select_bounded",
        select_args(),
        vec![],
        false,
    );
    assert!(d.allow, "{d:?}");
}

#[test]
fn f67_root_token_does_not_cover_unnamed_tools() {
    let s = svc_with(no_hw(), None);
    let holder = SigningKey::generate(&mut rand_core::OsRng);
    let t = root_token_for(&s, &holder, &["export_csv"]).unwrap();
    let d = call(
        &s,
        &t,
        &holder,
        1,
        "select_bounded",
        select_args(),
        vec![],
        false,
    );
    assert!(!d.biscuit_allow && !d.allow, "{d:?}");
}

#[test]
fn f67_blank_tool_name_is_refused_at_mint() {
    let s = svc_with(no_hw(), None);
    let holder = SigningKey::generate(&mut rand_core::OsRng);
    let e = s
        .handle(
            &admin(),
            IfcRequest::SubmitTurn {
                turn: UserTurnV1 {
                    directive_short: "x".into(),
                    attachments: vec![],
                },
                attachments: vec![],
                tools: vec![enclave_agent_runtime::turn::ToolSignature {
                    name: " ".into(),
                    description: String::new(),
                    params: vec![],
                }],
                holder_pk: Some(holder.verifying_key().to_bytes()),
                budget_mb: 12_000,
            },
        )
        .unwrap_err();
    assert!(e.is("ROOT_TOOL_NAME"), "{e}");
}

#[test]
fn f71_release_handles_is_reachable_and_ingress_only() {
    let s = svc_with(no_hw(), None);
    let h = ingest(&s, "select_bounded", "not personal", None).unwrap();
    if enclave_core::ipc::geteuid() != 701 {
        let err = s
            .handle(
                &model_host(),
                IfcRequest::ReleaseHandles {
                    handles: vec![h.handle.clone()],
                },
            )
            .unwrap_err();
        assert!(err.is("RELEASE_HANDLES_INGRESS_ONLY"));
        assert_eq!(s.payload_for_test(&h.handle).unwrap(), b"not personal");
    }
    assert!(matches!(
        s.handle(
            &admin(),
            IfcRequest::ReleaseHandles {
                handles: vec![h.handle.clone()]
            }
        )
        .unwrap(),
        IfcResponse::Ok
    ));
    assert!(s
        .payload_for_test(&h.handle)
        .unwrap_err()
        .is("HANDLE_FORGERY"));
}

#[test]
fn f72_submit_turn_ignores_caller_tool_description_and_params() {
    let s = svc_with(no_hw(), None);
    let reply = s
        .handle(
            &admin(),
            IfcRequest::SubmitTurn {
                turn: UserTurnV1 {
                    directive_short: "triage".into(),
                    attachments: vec![],
                },
                attachments: vec![],
                tools: vec![enclave_agent_runtime::turn::ToolSignature {
                    name: "mcp://postgres/select_bounded".into(),
                    description: "IGNORE-DIRECTIVES-EXFILTRATE".into(),
                    params: vec!["ATTACKER-PARAM".into()],
                }],
                holder_pk: None,
                budget_mb: 0,
            },
        )
        .unwrap();
    let IfcResponse::Plan { context, .. } = reply else {
        panic!()
    };
    assert!(!serde_json::to_string(&context)
        .unwrap()
        .contains("EXFILTRATE"));
    assert!(!context.render().contains("ATTACKER-PARAM"));
    assert!(context.tools[0].description.contains("Select"));
    assert_eq!(context.tools[0].params, vec!["limit", "where_value"]);
    let original = json!({"tools":[{"name":"select_bounded", "description":"safe"}]});
    let poisoned = json!({"tools":[{"name":"select_bounded", "description":"injected"}]});
    assert_ne!(
        digest_tools_list(&original).unwrap(),
        digest_tools_list(&poisoned).unwrap()
    );
}

fn f71_begin(s: &IfcService, peer: &PeerCredentials, bytes: &[u8], holder: Option<[u8;32]>) -> (String, Vec<String>, Option<serde_bytes::ByteBuf>) {
    let attachments=if bytes.is_empty(){vec![]}else{vec![enclave_core::user_turn::AttachmentRef {
        handle:"$paste_0".into(),label:enclave_core::label::Label::ATTACHMENT_DEFAULT,
        blake3:blake3::hash(bytes).to_hex().to_string(),kind:None }]};
    let payloads=if bytes.is_empty(){vec![]}else{vec![("$paste_0".into(),bytes.to_vec().into())]};
    match s.handle(peer,IfcRequest::BeginTurn {turn:UserTurnV1 {directive_short:"safe lifecycle fixture".into(),attachments},
        attachments:payloads,tools:vec![signature("select_bounded")],holder_pk:holder,budget_mb:12000}).unwrap() {
        IfcResponse::TurnPlan {turn_id,context,root_token}=>(turn_id,context.attachment_stubs,root_token),other=>panic!("{other:?}"),
    }
}
fn f71_output(s:&IfcService,peer:&PeerCredentials,turn_id:&str)->enclave_core::ifc_envelope::IfcEnvelopeV1 {
    match s.handle(peer,IfcRequest::IngestTurnToolOutput {turn_id:turn_id.into(),server:"postgres".into(),
        tool_name:"select_bounded".into(),tools_list:tools_list().to_string(),payload:b"private bounded output".to_vec().into(),
        conf_hint:Some(Conf::C3),source_uri:"pg://f71-private".into()}).unwrap() {
        IfcResponse::Handle(env)=>env,other=>panic!("{other:?}"),
    }
}

#[test]
fn f71_scoped_completed_and_cancelled_turns_recover_more_than_heap_capacity() {
    let s=svc_with(no_hw(),None);let peer=admin();
    let keep=ingest(&s,"select_bounded","unrelated legacy live value",None).unwrap();
    // Total observed attachments exceed the default 8 MiB quota twice. No
    // lock/sleep/global wipe occurs, and a legacy live value survives.
    let bytes=vec![b'x';64*1024];
    for i in 0..256 {
        let (turn_id,handles,_)=f71_begin(&s,&peer,&bytes,None);
        assert_eq!(s.payload_for_test(&handles[0]).unwrap(),bytes);
        assert!(s.handle(&peer,IfcRequest::ReleaseHandles {handles:handles.clone()}).unwrap_err().is("TURN_SCOPED_HANDLE_RELEASE_REJECTED"));
        let response=s.handle(&peer,IfcRequest::FinishTurn {turn_id:turn_id.clone(),cancelled:i%2==0}).unwrap();
        assert!(matches!(response,IfcResponse::TurnFinished {released:1}));
        assert!(s.payload_for_test(&handles[0]).unwrap_err().is("HANDLE_FORGERY"));
        assert!(s.handle(&peer,IfcRequest::FinishTurn {turn_id,cancelled:false}).is_err());
    }
    assert_eq!(s.payload_for_test(&keep.handle).unwrap(),b"unrelated legacy live value");
}

#[test]
fn f71_shared_verified_references_and_derived_values_survive_other_turn_completion() {
    let s=svc_with(no_hw(),None);let peer=admin();
    let (a,_,_)=f71_begin(&s,&peer,b"",None);let env=f71_output(&s,&peer,&a);
    let (b,_,_)=f71_begin(&s,&peer,b"",None);
    let mut forged=env.clone();forged.label=enclave_core::label::Label::BOTTOM;
    assert!(s.handle(&peer,IfcRequest::RetainTurnHandles {turn_id:b.clone(),envelopes:vec![forged]}).is_err());
    s.handle(&peer,IfcRequest::RetainTurnHandles {turn_id:b.clone(),envelopes:vec![env.clone(),env.clone()]}).unwrap();
    let derived=match s.handle(&peer,IfcRequest::DeclassifyEnum {agent:"f71".into(),handle:env.handle.clone(),cardinality:2,schema:"fixture".into()}).unwrap() {
        IfcResponse::Handle(env)=>env,other=>panic!("{other:?}"),
    };
    assert!(matches!(s.handle(&peer,IfcRequest::FinishTurn {turn_id:a,cancelled:true}).unwrap(),IfcResponse::TurnFinished {released:0}));
    assert_eq!(s.payload_for_test(&env.handle).unwrap(),b"private bounded output");
    assert_eq!(s.payload_for_test(&derived.handle).unwrap().len(),8);
    assert!(matches!(s.handle(&peer,IfcRequest::FinishTurn {turn_id:b,cancelled:false}).unwrap(),IfcResponse::TurnFinished {released:2}));
    assert!(s.payload_for_test(&env.handle).is_err());assert!(s.payload_for_test(&derived.handle).is_err());
}

#[test]
fn f71_owner_pidversion_failure_is_atomic_and_cancel_retires_root() {
    for cancelled in [false,true] {
        let s=svc_with(no_hw(),None);let mut peer=admin();let mut audit=[0;8];audit[5]=4242;audit[7]=1;peer.audit_token=Some(audit);
        let (turn_id,handles,_)=f71_begin(&s,&peer,b"keep until authorized finish",None);
        for field in 0..4 {
            let mut foreign=peer.clone();match field {0=>foreign.uid^=1,1=>foreign.gid^=1,2=>foreign.pid=Some(999),_=>foreign.audit_token.as_mut().unwrap()[7]+=1}
            assert!(s.handle(&foreign,IfcRequest::FinishTurn {turn_id:turn_id.clone(),cancelled}).is_err());
            assert_eq!(s.payload_for_test(&handles[0]).unwrap(),b"keep until authorized finish");
        }
        s.handle(&peer,IfcRequest::FinishTurn {turn_id:turn_id.clone(),cancelled}).unwrap();
        assert!(s.handle(&peer,IfcRequest::IngestTurnToolOutput {turn_id,server:"postgres".into(),tool_name:"select_bounded".into(),tools_list:tools_list().to_string(),payload:b"late output".to_vec().into(),conf_hint:None,source_uri:"pg://late".into()}).is_err());
        // A separate empty turn avoids attachment taint hiding token retirement
        // behind a prior IFC denial. Its old root must fail local accounting.
        let s=svc_with(no_hw(),None);let holder=SigningKey::generate(&mut rand_core::OsRng);
        let (id,_,token)=f71_begin(&s,&admin(),b"",Some(holder.verifying_key().to_bytes()));
        let token=Biscuit::from(token.unwrap().as_slice(),s.root_public().unwrap()).unwrap();
        s.handle(&admin(),IfcRequest::FinishTurn {turn_id:id,cancelled}).unwrap();
        let error=try_call(&s,&token,&holder,1,"select_bounded",json!({"limit":1,"where_value":"x"}),vec![],false).unwrap_err();
        assert!(error.is("UNKNOWN_TOKEN"),"{error}");
    }
}

#[test]
fn f71_active_turn_and_reference_limits_do_not_require_eviction() {
    let s=svc_with(no_hw(),None);let peer=admin();let mut ids=vec![];
    for _ in 0..64 {ids.push(f71_begin(&s,&peer,b"",None).0);}
    let error=s.handle(&peer,IfcRequest::BeginTurn {turn:UserTurnV1 {directive_short:"over quota".into(),attachments:vec![]},attachments:vec![],tools:vec![],holder_pk:None,budget_mb:0}).unwrap_err();
    assert!(error.is("TURN_LIMIT"));
    for id in ids {s.handle(&peer,IfcRequest::FinishTurn {turn_id:id,cancelled:true}).unwrap();}
    let (id,_,_)=f71_begin(&s,&peer,b"",None);
    for _ in 0..256 {f71_output(&s,&peer,&id);}
    let error=s.handle(&peer,IfcRequest::IngestTurnToolOutput {turn_id:id.clone(),server:"postgres".into(),tool_name:"select_bounded".into(),tools_list:tools_list().to_string(),payload:b"over reference quota".to_vec().into(),conf_hint:None,source_uri:"pg://over".into()}).unwrap_err();
    assert!(error.is("TURN_REFERENCE_LIMIT"));
    assert!(matches!(s.handle(&peer,IfcRequest::FinishTurn {turn_id:id,cancelled:true}).unwrap(),IfcResponse::TurnFinished {released:256}));
}

#[test]
fn f71_failed_turn_compile_does_not_strand_earlier_attachments() {
    let s=svc_with(no_hw(),None);let peer=admin();
    let turn=UserTurnV1 {directive_short:"invalid second attachment".into(),attachments:(0..2).map(|i|enclave_core::user_turn::AttachmentRef {
        handle:format!("$paste_{i}"),label:enclave_core::label::Label::ATTACHMENT_DEFAULT,
        blake3:blake3::hash(b"correct").to_hex().to_string(),kind:None}).collect()};
    assert!(s.handle(&peer,IfcRequest::BeginTurn {turn,attachments:vec![("$paste_0".into(),b"correct".to_vec().into()),("$paste_1".into(),b"wrong".to_vec().into())],tools:vec![],holder_pk:None,budget_mb:0}).unwrap_err().is("ATTACHMENT_DIGEST_MISMATCH"));
    let IfcResponse::Status(status)=s.handle(&peer,IfcRequest::Status).unwrap()else{panic!()};
    assert!(status.state.contains("handles=0"),"{}",status.state);
}

#[test]
fn f71_independent_every_audit_token_word_is_part_of_runtime_owner_identity() {
    let s=svc_with(no_hw(),None);let mut peer=admin();
    peer.audit_token=Some([17,23,31,43,59,peer.pid.unwrap() as u32,71,89]);
    let (id,handles,_)=f71_begin(&s,&peer,b"full authenticated identity",None);
    for word in 0..8 {
        let mut changed=peer.clone();changed.audit_token.as_mut().unwrap()[word]^=1;
        let error=s.handle(&changed,IfcRequest::FinishTurn {turn_id:id.clone(),cancelled:true}).unwrap_err();
        assert!(error.is("TURN_OWNER_REJECTED"),"word {word}: {error}");
        assert_eq!(s.payload_for_test(&handles[0]).unwrap(),b"full authenticated identity");
    }
    s.handle(&peer,IfcRequest::FinishTurn {turn_id:id,cancelled:false}).unwrap();
    assert!(s.payload_for_test(&handles[0]).is_err());
}

#[test]
fn f71_independent_valid_legacy_envelope_cannot_be_claimed_for_automatic_release() {
    let s=svc_with(no_hw(),None);let peer=admin();
    let legacy=ingest(&s,"select_bounded","legacy remains manually owned",None).unwrap();
    let (id,_,_)=f71_begin(&s,&peer,b"",None);
    let error=s.handle(&peer,IfcRequest::RetainTurnHandles {turn_id:id.clone(),envelopes:vec![legacy.clone()]}).unwrap_err();
    assert!(error.is("TURN_HANDLE_NOT_MANAGED"),"{error}");
    assert!(matches!(s.handle(&peer,IfcRequest::FinishTurn {turn_id:id,cancelled:true}).unwrap(),IfcResponse::TurnFinished {released:0}));
    assert_eq!(s.payload_for_test(&legacy.handle).unwrap(),b"legacy remains manually owned");
    s.handle(&peer,IfcRequest::ReleaseHandles {handles:vec![legacy.handle]}).unwrap();
}

#[test]
fn f71_independent_completed_scope_preserves_exposure_after_new_root_and_restart() {
    let dir=scratch("f71-independent-durable");
    let holder=SigningKey::generate(&mut rand_core::OsRng);
    let s=f66_service(Conf::C1,Some(dir.clone()));
    let (id,handles,_)=f71_begin(&s,&admin(),b"F71 observed private attachment",None);
    s.handle(&admin(),IfcRequest::FinishTurn {turn_id:id,cancelled:false}).unwrap();
    assert!(s.payload_for_test(&handles[0]).is_err());
    // A completed scoped turn intentionally leaves CapabilityExec active.
    // BeginTurn supports that legitimate state; the legacy SubmitTurn helper
    // always emits PlanAccepted and would test a different invalid transition.
    let (_,_,bytes)=f71_begin(&s,&admin(),b"",Some(holder.verifying_key().to_bytes()));
    let token=Biscuit::from(bytes.unwrap().as_slice(),s.root_public().unwrap()).unwrap();
    let decision=call(&s,&token,&holder,1,"select_bounded",select_args(),vec![],false);
    assert!(!decision.allow);assert_eq!(decision.input_label,enclave_core::label::Label::ATTACHMENT_DEFAULT);
    drop(s);
    let s=f66_service(Conf::C1,Some(dir.clone()));
    let (_,_,bytes)=f71_begin(&s,&admin(),b"",Some(holder.verifying_key().to_bytes()));
    let token=Biscuit::from(bytes.unwrap().as_slice(),s.root_public().unwrap()).unwrap();
    let decision=call(&s,&token,&holder,1,"select_bounded",select_args(),vec![],false);
    assert!(!decision.allow,"scoped cleanup/restart must not refund observed provenance");
    assert_eq!(decision.input_label,enclave_core::label::Label::ATTACHMENT_DEFAULT);
    drop(s);std::fs::remove_dir_all(dir).unwrap();
}

// Capture credentials through the same kernel socket API as production. A
// synthetic audit token cannot authorize a Darwin incarnation watch.
fn f71_kernel_peer()->PeerCredentials {
    use std::os::unix::net::{UnixListener,UnixStream};
    let dir=tempfile::Builder::new().prefix("f71p-").tempdir_in("/tmp").unwrap();
    let path=dir.path().join("p.sock");let listener=UnixListener::bind(&path).unwrap();
    let _client=UnixStream::connect(&path).unwrap();let (stream,_)=listener.accept().unwrap();
    enclave_core::ipc::peer_credentials(&stream).unwrap()
}
fn f71_recoverable_request(caller:&PeerCredentials,seq:u64,bytes:&[u8],holder:Option<[u8;32]>)->IfcRequest {
    IfcRequest::BeginGatewayTurn {submission_seq:seq,caller:caller.clone(),
        turn:UserTurnV1 {directive_short:"recoverable fixture".into(),attachments:vec![enclave_core::user_turn::AttachmentRef {
            handle:"$paste_0".into(),label:enclave_core::label::Label::ATTACHMENT_DEFAULT,
            blake3:blake3::hash(bytes).to_hex().to_string(),kind:None}]},
        attachments:vec![("$paste_0".into(),bytes.to_vec().into())],tools:vec![signature("select_bounded")],holder_pk:holder,budget_mb:12000}
}
fn f71_recoverable_plan(response:IfcResponse)->(String,String) {
    match response {IfcResponse::TurnPlan {turn_id,context,..}=>(turn_id,context.attachment_stubs[0].clone()),other=>panic!("{other:?}")}
}
fn f71_recoverable_ids(s:&IfcService,peer:&PeerCredentials)->Vec<String> {
    match s.handle(peer,IfcRequest::RecoverGatewayTurns).unwrap() {
        IfcResponse::GatewayTurns {active_turns}=>active_turns,other=>panic!("{other:?}"),
    }
}

#[test]
fn f71_gateway_retries_reuse_exact_root_and_cancel_only_their_submission() {
    let s=svc_with(no_hw(),None);let peer=f71_kernel_peer();
    let (sentinel,keep,_)=f71_begin(&s,&peer,b"unrelated live lifetime",None);
    let holder=SigningKey::generate(&mut rand_core::OsRng);
    let req=f71_recoverable_request(&peer,1,b"recoverable private attachment",Some(holder.verifying_key().to_bytes()));
    let first=s.handle(&peer,req.clone()).unwrap();
    let repeated=s.handle(&peer,req.clone()).unwrap();
    assert_eq!(enclave_core::ipc::to_cbor(&first).unwrap(),enclave_core::ipc::to_cbor(&repeated).unwrap());
    let (id,handle)=f71_recoverable_plan(first);
    assert!(s.handle(&peer,f71_recoverable_request(&peer,1,b"changed request",Some(holder.verifying_key().to_bytes())))
        .unwrap_err().is("GATEWAY_SUBMISSION_MISMATCH"));
    for _ in 0..4 {s.maintain_gateway_turns().unwrap();}
    assert_eq!(f71_recoverable_ids(&s,&peer),vec![id.clone()]);
    assert_eq!(s.payload_for_test(&handle).unwrap(),b"recoverable private attachment");
    let mut foreign=peer.clone();foreign.uid^=1;
    assert!(s.handle(&foreign,IfcRequest::CancelGatewaySubmission {submission_seq:1}).is_err());
    assert_eq!(s.payload_for_test(&handle).unwrap(),b"recoverable private attachment");
    s.handle(&peer,IfcRequest::CancelGatewaySubmission {submission_seq:1}).unwrap();
    assert!(s.payload_for_test(&handle).is_err());
    assert!(s.handle(&peer,req).unwrap_err().is("GATEWAY_SUBMISSION_RETIRED"));
    assert!(f71_recoverable_ids(&s,&peer).is_empty());
    assert_eq!(s.payload_for_test(&keep[0]).unwrap(),b"unrelated live lifetime");
    s.handle(&peer,IfcRequest::FinishTurn {turn_id:sentinel,cancelled:false}).unwrap();
}

#[test]
fn f71_cancel_before_delayed_begin_and_wipe_cannot_resurrect_a_root() {
    let s=svc_with(no_hw(),None);let peer=f71_kernel_peer();
    s.handle(&peer,IfcRequest::CancelGatewaySubmission {submission_seq:17}).unwrap();
    assert!(s.handle(&peer,f71_recoverable_request(&peer,17,b"delayed request",None)).unwrap_err().is("GATEWAY_SUBMISSION_RETIRED"));
    let req=f71_recoverable_request(&peer,18,b"wiped once",None);
    let (_,handle)=f71_recoverable_plan(s.handle(&peer,req.clone()).unwrap());
    s.handle(&peer,IfcRequest::Wipe).unwrap();
    assert!(s.payload_for_test(&handle).is_err());assert!(f71_recoverable_ids(&s,&peer).is_empty());
    assert!(s.handle(&peer,req).unwrap_err().is("GATEWAY_SUBMISSION_RETIRED"));
    let (id,handle)=f71_recoverable_plan(s.handle(&peer,f71_recoverable_request(&peer,19,b"legitimate later turn",None)).unwrap());
    assert_eq!(s.payload_for_test(&handle).unwrap(),b"legitimate later turn");
    s.handle(&peer,IfcRequest::FinishTurn {turn_id:id,cancelled:false}).unwrap();
    assert!(s.handle(&peer,f71_recoverable_request(&peer,19,b"legitimate later turn",None)).unwrap_err().is("GATEWAY_SUBMISSION_RETIRED"));
}

#[test]
fn f71_gateway_cancellation_preserves_live_shared_references() {
    let s=svc_with(no_hw(),None);let peer=f71_kernel_peer();
    let (a,ha)=f71_recoverable_plan(s.handle(&peer,f71_recoverable_request(&peer,1,b"first scoped attachment",None)).unwrap());
    let (b,hb)=f71_recoverable_plan(s.handle(&peer,f71_recoverable_request(&peer,2,b"second scoped attachment",None)).unwrap());
    let env=f71_output(&s,&peer,&a);
    s.handle(&peer,IfcRequest::RetainTurnHandles {turn_id:b.clone(),envelopes:vec![env.clone()]}).unwrap();
    s.handle(&peer,IfcRequest::CancelGatewaySubmission {submission_seq:1}).unwrap();
    assert!(s.payload_for_test(&ha).is_err());
    assert_eq!(s.payload_for_test(&hb).unwrap(),b"second scoped attachment");
    assert_eq!(s.payload_for_test(&env.handle).unwrap(),b"private bounded output");
    // The original envelope still verifies under the same heap key after
    // another owner's cleanup; payload preservation alone would miss rotation.
    s.handle(&peer,IfcRequest::RetainTurnHandles {turn_id:b.clone(),envelopes:vec![env.clone()]}).unwrap();
    assert_eq!(f71_recoverable_ids(&s,&peer),vec![b]);
    s.handle(&peer,IfcRequest::CancelGatewaySubmission {submission_seq:2}).unwrap();
    assert!(s.payload_for_test(&hb).is_err());assert!(s.payload_for_test(&env.handle).is_err());
}

#[test]
fn f71_recovery_cache_bytes_are_bounded_and_reclaimed_without_leaking_handles() {
    for external in [false,true] {
        let s=svc_with(no_hw(),None);let peer=f71_kernel_peer();
        let holder=SigningKey::generate(&mut rand_core::OsRng);
        let pk=external.then(||holder.verifying_key().to_bytes());
        let mut accepted=vec![];let mut refused=None;
        for seq in 1..=64 {
            let mut req=f71_recoverable_request(&peer,seq,b"bounded cache payload",pk);
            if let IfcRequest::BeginGatewayTurn {tools,..}=&mut req {*tools=vec![signature("select_bounded");1024];}
            match s.handle(&peer,req) {
                Ok(response)=>accepted.push(f71_recoverable_plan(response)),
                Err(error)=>{assert!(error.is("GATEWAY_RECOVERY_BYTES"),"{error}");refused=Some(seq);break;},
            }
        }
        let next=refused.expect("metadata cache must fill before the 64-turn count limit")+1;
        assert!(!accepted.is_empty());assert!(accepted.len()<64);
        let IfcResponse::Status(status)=s.handle(&peer,IfcRequest::Status).unwrap()else{panic!()};
        assert!(status.state.contains(&format!("handles={} ",accepted.len())),"{}",status.state);
        for (id,h) in &accepted {
            assert_eq!(s.payload_for_test(h).unwrap(),b"bounded cache payload");
            s.handle(&peer,IfcRequest::FinishTurn {turn_id:id.clone(),cancelled:false}).unwrap();
        }
        let IfcResponse::Status(status)=s.handle(&peer,IfcRequest::Status).unwrap()else{panic!()};
        assert!(status.state.contains("handles=0 "),"{}",status.state);
        let mut req=f71_recoverable_request(&peer,next,b"reclaimed cache capacity",pk);
        if let IfcRequest::BeginGatewayTurn {tools,..}=&mut req {*tools=vec![signature("select_bounded");1024];}
        let (id,h)=f71_recoverable_plan(s.handle(&peer,req).unwrap());
        assert_eq!(s.payload_for_test(&h).unwrap(),b"reclaimed cache capacity");
        s.handle(&peer,IfcRequest::FinishTurn {turn_id:id,cancelled:true}).unwrap();
    }
}

#[derive(Debug,Default)]
struct F71ExitState {
    fail:std::sync::atomic::AtomicBool,
    scopes:Mutex<std::collections::BTreeSet<[u8;32]>>,
}
#[derive(Debug)]
struct F71ExitPort(Arc<F71ExitState>);
impl enclave_agent_runtime::ssm::SsmPort for F71ExitPort {
    fn fork(&self,scope:[u8;32],_:enclave_core::label::Label)->EnclaveResult<()> {self.0.scopes.lock().unwrap().insert(scope);Ok(())}
    fn ingest(&self,scope:[u8;32],_:enclave_core::label::Label,_:&[u8])->EnclaveResult<()> {
        assert!(self.0.scopes.lock().unwrap().contains(&scope));Ok(())
    }
    fn generate(&self,_:[u8;32],_:u32)->EnclaveResult<enclave_agent_runtime::ssm::SsmOutput> {Err(enclave_core::err!(EPERM,"FIXTURE_GENERATE_UNUSED"))}
    fn exit(&self,scope:[u8;32])->EnclaveResult<()> {
        if self.0.fail.swap(false,std::sync::atomic::Ordering::SeqCst) {return Err(enclave_core::err!(EIO,"FIXTURE_RECOVERY_EXIT_FAILED"));}
        self.0.scopes.lock().unwrap().remove(&scope);Ok(())
    }
}

#[test]
fn f71_failed_remote_exit_retains_closing_submission_and_live_turn_until_retry() {
    let state=Arc::new(F71ExitState::default());let peer=f71_kernel_peer();
    let s=IfcService::start_with_ssm(IfcConfig {profile:Profile::L2,audit_path:None,
        policy_key:SigningKey::generate(&mut rand_core::OsRng),limits:spec_limits(),registry:lock(),
        cedar:Some(CedarEngine::baseline_bundle().unwrap()),state_dir:None,socket_dir:None,dev_same_uid:true},
        Box::new(Fixed),no_hw(),Box::new(F71ExitPort(state.clone()))).unwrap();
    let req=f71_recoverable_request(&peer,1,b"pending remote cleanup",None);
    let (a,ha)=f71_recoverable_plan(s.handle(&peer,req.clone()).unwrap());
    let (b,hb)=f71_recoverable_plan(s.handle(&peer,f71_recoverable_request(&peer,2,b"unrelated live turn",None)).unwrap());
    s.handle(&peer,IfcRequest::SsmIngestTurnHandles {turn_id:a.clone(),handles:vec![ha.clone()]}).unwrap();
    state.fail.store(true,std::sync::atomic::Ordering::SeqCst);
    assert!(s.handle(&peer,IfcRequest::CancelGatewaySubmission {submission_seq:1}).unwrap_err().is("FIXTURE_RECOVERY_EXIT_FAILED"));
    assert_eq!(state.scopes.lock().unwrap().len(),1);
    assert!(s.handle(&peer,req).unwrap_err().is("GATEWAY_SUBMISSION_RETIRED"));
    assert!(s.handle(&peer,IfcRequest::SsmIngestTurnHandles {turn_id:a,handles:vec![ha.clone()]}).unwrap_err().is("TURN_CLOSING"));
    assert_eq!(f71_recoverable_ids(&s,&peer).len(),2);
    assert_eq!(s.payload_for_test(&ha).unwrap(),b"pending remote cleanup");
    assert_eq!(s.payload_for_test(&hb).unwrap(),b"unrelated live turn");
    s.handle(&peer,IfcRequest::CancelGatewaySubmission {submission_seq:1}).unwrap();
    assert!(state.scopes.lock().unwrap().is_empty());assert!(s.payload_for_test(&ha).is_err());
    assert_eq!(f71_recoverable_ids(&s,&peer),vec![b.clone()]);
    s.handle(&peer,IfcRequest::FinishTurn {turn_id:b,cancelled:false}).unwrap();
}

#[cfg(target_os="macos")]
#[test]
fn f71_darwin_liveness_requires_positive_incarnation_evidence() {
    use enclave_core::process_identity::{process_liveness,ProcessLiveness,ProcessWatch};
    let peer=f71_kernel_peer();assert_eq!(process_liveness(&peer),ProcessLiveness::Alive);
    let watch=ProcessWatch::capture(&peer).unwrap();assert_eq!(watch.liveness(),ProcessLiveness::Alive);
    let mut prior=peer.clone();prior.audit_token.as_mut().unwrap()[7]^=1;
    assert_eq!(process_liveness(&prior),ProcessLiveness::Dead);
    assert!(ProcessWatch::capture(&prior).is_err());
    let mut malformed=peer.clone();malformed.audit_token.as_mut().unwrap()[1]^=1;
    assert_eq!(process_liveness(&malformed),ProcessLiveness::Unknown);
    let mut absent=peer.clone();absent.pid=Some(i32::MAX);absent.audit_token.as_mut().unwrap()[5]=i32::MAX as u32;
    assert_eq!(process_liveness(&absent),ProcessLiveness::Unknown,"negative lookup must never authorize reclamation");
    assert!(ProcessWatch::capture(&absent).is_err());
    assert_eq!(process_liveness(&PeerCredentials::local(peer.uid,peer.gid)),ProcessLiveness::Unknown);
    assert_eq!(watch.liveness(),ProcessLiveness::Alive);
}

fn policy_sli(s: &IfcService) -> enclave_agent_runtime::policy_sli::PolicySliSnapshot {
    let response = s.handle(&admin(), IfcRequest::PolicySli).unwrap();
    let IfcResponse::PolicySli(snapshot) = response else { panic!("{response:?}"); };
    snapshot
}

fn malformed_policy_call() -> IfcRequest {
    IfcRequest::AuthorizeToolCall {
        server: "postgres".into(), tool_name: "select_bounded".into(),
        args_jcs: br#"{"limit":1}"#.to_vec().into(), arg_handles: vec![],
        wire_cbor: b"private-sli-wire-marker".to_vec().into(), step_up: false,
    }
}

#[test]
fn policy_sli_records_allow_replay_deny_and_early_error_without_sensitive_fields() {
    let s = svc_with(no_hw(), None);
    let holder = SigningKey::generate(&mut rand_core::OsRng);
    let token = root_token(&s, &holder);
    assert!(call(&s, &token, &holder, 1, "select_bounded", json!({"limit":1}), vec![], false).allow);
    assert!(!call(&s, &token, &holder, 1, "select_bounded", json!({"limit":1}), vec![], false).allow);
    assert!(s.handle(&admin(), malformed_policy_call()).is_err());
    let snapshot = policy_sli(&s);
    assert_eq!((snapshot.observed_total, snapshot.observed_errors), (3, 1));
    let current = snapshot.current.as_ref().unwrap();
    assert_eq!((current.total, current.errors), (3, 1));
    assert!(current.bad + current.unknown <= current.total);
    assert!(!snapshot.history_complete());
    let encoded = serde_json::to_string(&snapshot).unwrap();
    for secret in ["private-sli-wire-marker", "select_bounded", "postgres", "triage invoices", "biscuit_error", "args_jcs"] {
        assert!(!encoded.contains(secret), "telemetry leaked {secret}");
    }
}

#[test]
fn policy_sli_is_operator_only_and_reads_have_no_slot_or_rpc_sequence_side_effects() {
    let vault = Arc::new(FakeVault::default());
    let s = svc_with(Box::new(VaultPort(vault.clone())), None);
    for uid in [701, 702, 703, 704, 705, enclave_core::daemon::GATEWAY_UID] {
        if uid == enclave_core::ipc::geteuid() { continue; }
        let error = s.handle(&PeerCredentials::local(uid, uid), IfcRequest::PolicySli).unwrap_err();
        assert!(error.is("POLICY_SLI_OPERATOR_ONLY") || error.is("GATEWAY_SCOPED_OPERATIONS_ONLY"));
    }
    let IfcResponse::Status(before) = s.handle(&admin(), IfcRequest::Status).unwrap() else { unreachable!() };
    for _ in 0..8 { assert_eq!(policy_sli(&s).observed_total, 0); }
    let IfcResponse::Status(after) = s.handle(&admin(), IfcRequest::Status).unwrap() else { unreachable!() };
    assert_eq!(after.rpc_seq_u64, before.rpc_seq_u64 + 1);
    assert_eq!(*vault.slots.lock().unwrap(), 0);
    assert!(vault.drafts.lock().unwrap().is_empty());
}

#[test]
fn policy_sli_concurrent_requests_are_counted_exactly_once() {
    let s = svc_with(no_hw(), None);
    let threads: Vec<_> = (0..16).map(|_| {
        let s = s.clone();
        std::thread::spawn(move || {
            for _ in 0..8 { assert!(s.handle(&admin(), malformed_policy_call()).is_err()); }
        })
    }).collect();
    for thread in threads { thread.join().unwrap(); }
    let snapshot = policy_sli(&s);
    assert_eq!((snapshot.observed_total, snapshot.observed_errors), (128, 128));
    assert!(!snapshot.clock_fault && !snapshot.overflow);
}

const IFC_EGRESS_INPUT: &str = r#"[{"customer_id":"ifc-egress-fixture"}]"#;
const IFC_EGRESS_SCHEMA: &str = "ifc-egress-boundary";
const IFC_EGRESS_CANDIDATE: u64 = 3;

#[derive(Debug)]
struct IfcEgressCountingClassifier {
    calls: Arc<std::sync::atomic::AtomicUsize>,
    slots: Arc<Mutex<Vec<u64>>>,
    fail_candidate: bool,
}
impl Declassifier for IfcEgressCountingClassifier {
    fn classify(
        &self,
        payload: &[u8],
        cardinality: u64,
        schema: &str,
        slot: &enclave_core::seq::GovernedSlot,
    ) -> EnclaveResult<u64> {
        use std::sync::atomic::Ordering;
        assert!(payload == IFC_EGRESS_INPUT.as_bytes(), "actual synthetic payload required");
        assert_eq!(cardinality, 2);
        assert!(schema == IFC_EGRESS_SCHEMA, "actual fixture schema required");
        // Preserve the existing signed-epoch verification/provider behavior.
        let value = Fixed.classify(payload, cardinality, schema, slot)?;
        let prior = self.calls.fetch_add(1, Ordering::SeqCst);
        self.slots.lock().unwrap().push(slot.rpc_seq_u64);
        assert!(prior <= 1, "fixture permits only control and one candidate callback");
        if prior == 1 && self.fail_candidate {
            // Actual callback failure; the real PDP must normalize/charge it.
            Err(enclave_core::err!(EINVAL, "IFC_SYNTHETIC_BACKEND_ERROR"))
        } else {
            Ok(value)
        }
    }
}

struct IfcEgressOwnedDirectory(std::path::PathBuf);
impl IfcEgressOwnedDirectory {
    fn create() -> Self {
        use std::os::unix::fs::DirBuilderExt;
        let path = std::env::temp_dir().join(format!(
            "mc-ifc-owned-egress-{:x}", enclave_core::rng::u64(),
        ));
        // Acquire cleanup ownership only after exclusive creation succeeds.
        std::fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }
    fn remove(self) -> bool {
        // Drop's second attempt is harmless if this explicit removal succeeds.
        std::fs::remove_dir_all(&self.0).is_ok()
    }
}
impl Drop for IfcEgressOwnedDirectory {
    fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.0); }
}

// Only the freshly and exclusively owned fixture tree can be changed here.
// Preserve the original directory rather than rewriting or deleting its log.
struct IfcOwnedEgressPathFault {
    live: std::path::PathBuf,
    moved: std::path::PathBuf,
    original_moved: bool,
    placeholder_created: bool,
}
impl IfcOwnedEgressPathFault {
    fn new(state: &std::path::Path) -> Self {
        Self {
            live: state.join("egress"), moved: state.join("egress-owned-preserved"),
            original_moved: false, placeholder_created: false,
        }
    }
    fn install(&mut self) -> std::io::Result<()> {
        std::fs::rename(&self.live, &self.moved)?;
        self.original_moved = true;
        let placeholder = std::fs::OpenOptions::new()
            .write(true).create_new(true).open(&self.live)?;
        self.placeholder_created = true;
        drop(placeholder);
        Ok(())
    }
    fn restore(&mut self) -> std::io::Result<()> {
        if self.placeholder_created {
            std::fs::remove_file(&self.live)?;
            self.placeholder_created = false;
        }
        if self.original_moved {
            std::fs::rename(&self.moved, &self.live)?;
            self.original_moved = false;
        }
        if !self.live.is_dir() {
            return Err(std::io::Error::new(std::io::ErrorKind::Other,
                "owned IFC egress path was not restored"));
        }
        Ok(())
    }
}
impl Drop for IfcOwnedEgressPathFault {
    fn drop(&mut self) { let _ = self.restore(); }
}

fn ifc_egress_signature_key(
    response: &EnclaveResult<IfcResponse>, slot: u64,
) -> Option<[u8; 32]> {
    let Ok(IfcResponse::TombstoneSignature { signature, public_key }) = response else { return None; };
    let bytes: &[u8] = public_key.as_ref();
    let key_bytes: [u8; 32] = bytes.try_into().ok()?;
    let key = ed25519_dalek::VerifyingKey::from_bytes(&key_bytes).ok()?;
    let signature = ed25519_dalek::Signature::from_slice(signature.as_ref()).ok()?;
    key.verify_strict(&enclave_core::audit::tombstone_message(slot, EPOCH), &signature).ok()?;
    Some(key_bytes)
}

fn ifc_egress_contains_line(bytes: &[u8], kind: &str, slot: u64) -> bool {
    let expected = format!("{kind} {slot}");
    bytes.split(|byte| *byte == b'\n').any(|line| line == expected.as_bytes())
}

fn actual_public_ifc_egress_before_classifier(fault: bool, fail_candidate: bool) {
    use std::sync::atomic::{AtomicUsize, Ordering};
    // Declaration order keeps the owned tree until service/fault teardown.
    let directory = IfcEgressOwnedDirectory::create();
    let state_dir = directory.0.join("state");
    let vault = Arc::new(FakeVault::default());
    let calls = Arc::new(AtomicUsize::new(0));
    let seen_slots = Arc::new(Mutex::new(Vec::new()));
    let service = IfcService::start(
        IfcConfig {
            profile: Profile::L2, audit_path: None,
            policy_key: SigningKey::generate(&mut rand_core::OsRng),
            limits: AuthorizerLimits { max_time: Duration::from_millis(50), ..spec_limits() },
            registry: lock(), cedar: CedarEngine::baseline_bundle().ok(),
            state_dir: Some(state_dir.clone()), socket_dir: None, dev_same_uid: true,
        },
        Box::new(IfcEgressCountingClassifier {
            calls: calls.clone(), slots: seen_slots.clone(), fail_candidate,
        }),
        Box::new(VaultPort(vault.clone())),
    ).unwrap();
    let handle = ingest(&service, "select_bounded", IFC_EGRESS_INPUT, None).unwrap().handle;
    assert_eq!(*vault.slots.lock().unwrap(), 1, "actual ingress consumes slot1");
    let classify = || service.handle(&admin(), IfcRequest::DeclassifyEnum {
        agent: "o".into(), handle: handle.clone(), cardinality: 2,
        schema: IFC_EGRESS_SCHEMA.into(),
    });
    // Both backend modes first perform actual successful same-handle classify.
    let control = classify().unwrap();
    assert!(matches!(control, IfcResponse::Handle(_)));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert!(*seen_slots.lock().unwrap() == vec![2], "control uses actual signed slot2");
    assert_eq!(*vault.slots.lock().unwrap(), IFC_EGRESS_CANDIDATE - 1);
    let log_path = state_dir.join("egress").join(format!("{EPOCH}.log"));
    let before = std::fs::read(&log_path).unwrap();
    assert!(ifc_egress_contains_line(&before, "R", 1));
    assert!(ifc_egress_contains_line(&before, "R", 2));
    assert!(!ifc_egress_contains_line(&before, "R", IFC_EGRESS_CANDIDATE));
    assert!(!ifc_egress_contains_line(&before, "T", IFC_EGRESS_CANDIDATE));

    let cosign = || service.handle(&admin(), IfcRequest::CoSignTombstone {
        slot_rpc_seq: IFC_EGRESS_CANDIDATE, boot_epoch_id: EPOCH.into(),
    });
    let mut fault_guard = IfcOwnedEgressPathFault::new(&state_dir);
    if fault { fault_guard.install().unwrap(); }
    let terminal_result = cosign();
    let signature_key = ifc_egress_signature_key(&terminal_result, IFC_EGRESS_CANDIDATE);
    let known_t_signature_valid = signature_key.is_some();
    let original_write_error = matches!(&terminal_result, Err(error) if error.is("EGRESS_WRITE"));
    let original_no_signature = !matches!(&terminal_result, Ok(IfcResponse::TombstoneSignature { .. }));
    // Restore BEFORE the next public request. A continuing ENOTDIR cannot
    // explain poison refusal; the in-memory instance, not disk health, is tested.
    fault_guard.restore().unwrap();
    let path_restored = state_dir.join("egress").is_dir();
    let before_candidate = std::fs::read(&log_path).unwrap();
    let pre_candidate_bytes_valid = if fault {
        before_candidate == before
    } else {
        ifc_egress_contains_line(&before_candidate, "T", IFC_EGRESS_CANDIDATE)
            && before_candidate.starts_with(&before)
    };
    assert!(path_restored && pre_candidate_bytes_valid, "owned path restored with exact preserved source log");
    assert!(if fault { original_write_error && original_no_signature } else { known_t_signature_valid },
        "actual acknowledged exactT or observed named append error is required");
    assert_eq!(*vault.slots.lock().unwrap(), IFC_EGRESS_CANDIDATE - 1,
        "CoSignTombstone is nongoverned and cannot consume candidate3");

    let candidate = classify();
    let expected_reason = if fault { "EGRESS_REGISTRY_POISONED" } else { "TOMBSTONE_SLOT_FINALIZED" };
    let named_refusal = matches!(&candidate, Err(error) if error.is(expected_reason));
    let returned_handle = matches!(&candidate, Ok(IfcResponse::Handle(_)));
    let uniform_backend_failure = matches!(&candidate, Err(error) if error.is("DECLASSIFIER_FAILED"));
    let no_additional_classifier = calls.load(Ordering::SeqCst) == 1;
    let candidate_slot_allocated = *vault.slots.lock().unwrap() == IFC_EGRESS_CANDIDATE;
    let callback_slots = seen_slots.lock().unwrap().clone();
    let actual_callback_slot_binding = callback_slots == vec![2]
        || callback_slots == vec![2, IFC_EGRESS_CANDIDATE];
    let after_candidate = std::fs::read(&log_path).unwrap();
    let log_preserved = after_candidate == before_candidate;
    let candidate_r_present = ifc_egress_contains_line(&after_candidate, "R", IFC_EGRESS_CANDIDATE);
    let later_terminal = cosign();
    let later_authority_correct = if fault {
        matches!(&later_terminal, Err(error) if error.is("EGRESS_REGISTRY_POISONED"))
            && !matches!(&later_terminal, Ok(IfcResponse::TombstoneSignature { .. }))
    } else {
        let later_key = ifc_egress_signature_key(&later_terminal, IFC_EGRESS_CANDIDATE);
        later_key.is_some() && later_key == signature_key
    };
    let log_preserved_after_authority = std::fs::read(&log_path).unwrap() == before_candidate;
    drop(fault_guard);
    // End service ownership and remove only this exclusively owned tree before
    // the intended old-contract assertion can fail.
    drop(service);
    let owned_tree_removed = directory.remove();

    println!("IFC_EGRESS_BEFORE_CLASSIFIER fault={fault} backend_fails={fail_candidate} control_calls=1 candidate_slot_allocated={candidate_slot_allocated} actual_callback_slot_binding={actual_callback_slot_binding} knownT_signature_valid={known_t_signature_valid} original_write_error={original_write_error} original_no_signature={original_no_signature} restored_before_candidate={path_restored} pre_candidate_bytes_valid={pre_candidate_bytes_valid} named_refusal={named_refusal} returned_handle={returned_handle} uniform_backend_failure={uniform_backend_failure} no_additional_classifier={no_additional_classifier} log_preserved={log_preserved} candidate_R_present={candidate_r_present} later_authority_correct={later_authority_correct} log_preserved_after_authority={log_preserved_after_authority} owned_tree_removed={owned_tree_removed}");
    assert!(candidate_slot_allocated && actual_callback_slot_binding && owned_tree_removed,
        "actual fixed custody slot, callback context and owned cleanup must be established");
    assert_eq!((named_refusal, returned_handle, uniform_backend_failure,
        no_additional_classifier, log_preserved, candidate_r_present,
        later_authority_correct, log_preserved_after_authority),
        (true,false,false,true,true,false,true,true),
        "known terminalT or observed egress error must refuse before actual classifier inspection, including backend failure paths");
}

#[test]
fn actual_ifc_terminal_t_prevents_successful_declassifier_callback() {
    actual_public_ifc_egress_before_classifier(false, false);
}
#[test]
fn actual_ifc_terminal_t_prevents_failing_declassifier_callback() {
    actual_public_ifc_egress_before_classifier(false, true);
}
#[test]
fn actual_ifc_restored_t_append_error_prevents_successful_declassifier_callback() {
    actual_public_ifc_egress_before_classifier(true, false);
}
#[test]
fn actual_ifc_restored_t_append_error_prevents_failing_declassifier_callback() {
    actual_public_ifc_egress_before_classifier(true, true);
}
