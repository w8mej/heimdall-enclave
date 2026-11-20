//! Tests for EnclaveStarlarkV1 interpreter, frozen dialect, fuel metering,
//! and static Cedar checks (FS-704 §8.2.1, GAP-18).

use enclave_agent_runtime::cedar_engine::CedarEngine;
use enclave_agent_runtime::heap::CapabilityHeap;
use enclave_agent_runtime::plan::interpreter::{EnclaveStarlarkV1, PlanExecutionContext};
use enclave_agent_runtime::plan::ref_value::PlanRef;
use enclave_agent_runtime::registry::ToolRegistry;
use enclave_core::label::Label;
use enclave_core::profile::Profile;

struct TestFixture {
    heap: CapabilityHeap,
    registry: ToolRegistry,
    cedar: CedarEngine,
}

fn make_fixture(cedar: CedarEngine, registry_json: &[u8]) -> TestFixture {
    TestFixture {
        heap: CapabilityHeap::new("6f1c2c1e-3a54-4b8e-9d7a-0c4f5b6a7e81".into()),
        registry: ToolRegistry::load(registry_json).unwrap(),
        cedar,
    }
}

fn ctx_for(fx: &TestFixture, profile: Profile, fuel_budget: u64) -> PlanExecutionContext<'_> {
    PlanExecutionContext {
        profile,
        heap: &fx.heap,
        registry: &fx.registry,
        cedar: &fx.cedar,
        initial_handles: Vec::new(),
        fuel_budget,
    }
}

#[test]
fn frozen_dialect_forbids_load_import_while_getattr() {
    let cedar = CedarEngine::baseline_bundle().unwrap();
    let fx = make_fixture(cedar, br#"{"v":1,"servers":[]}"#);

    let mut ctx = ctx_for(&fx, Profile::L2, 10_000);

    // 1. load() forbidden
    let err = EnclaveStarlarkV1::execute("load('//foo:bar.bzl', 'x')", &mut ctx).unwrap_err();
    assert!(err.is("STARLARK_LOAD_FORBIDDEN"));

    // 2. import forbidden
    let err = EnclaveStarlarkV1::execute("import os\nprint(os)", &mut ctx).unwrap_err();
    assert!(err.is("STARLARK_IMPORT_FORBIDDEN"));

    // 3. while loops forbidden
    let err = EnclaveStarlarkV1::execute("while True:\n    pass", &mut ctx).unwrap_err();
    assert!(err.is("STARLARK_WHILE_FORBIDDEN"));

    // 4. dynamic attribute reflection forbidden
    let err = EnclaveStarlarkV1::execute("x = getattr(None, 'foo')", &mut ctx).unwrap_err();
    assert!(err.is("STARLARK_DYNAMIC_ATTR_FORBIDDEN"));
}

#[test]
fn l3_oblivious_loop_bounds_and_sealed_abort() {
    let cedar = CedarEngine::baseline_bundle().unwrap();
    let fx = make_fixture(cedar, br#"{"v":1,"servers":[]}"#);

    let mut ctx = ctx_for(&fx, Profile::L3, 10_000);

    // In L3, unbounded loop returns ERR_IFC_SEALED_ABORT
    let err = EnclaveStarlarkV1::execute("for x in [1, 2, 3]:\n    pass", &mut ctx).unwrap_err();
    assert!(err.is("ERR_IFC_SEALED_ABORT"));

    // In L3, loop with range > 16 returns ERR_IFC_SEALED_ABORT
    let err = EnclaveStarlarkV1::execute("for x in range(25):\n    pass", &mut ctx).unwrap_err();
    assert!(err.is("ERR_IFC_SEALED_ABORT"));

    // In L3, bounded loop with range <= 16 succeeds
    let res = EnclaveStarlarkV1::execute(
        "res = 0\nfor x in range(5):\n    res = res + x\nres",
        &mut ctx,
    )
    .expect("bounded loop in L3 should succeed");
    assert_eq!(res.return_value, "10");
}

#[test]
fn fuel_exhaustion_halts_execution() {
    let cedar = CedarEngine::baseline_bundle().unwrap();
    let fx = make_fixture(cedar, br#"{"v":1,"servers":[]}"#);

    // Very low fuel limit (5 ticks)
    let mut ctx = ctx_for(&fx, Profile::L2, 5);

    let script = "total = 0\nfor i in range(100):\n    total = total + i\ntotal";
    let err = EnclaveStarlarkV1::execute(script, &mut ctx).unwrap_err();
    assert!(err.is("ERR_IFC_FUEL_EXHAUSTED"));
}

#[test]
fn static_cedar_check_forbids_unauthorized_a3_a4_tools() {
    let cedar = CedarEngine::default_bundle().unwrap(); // deny-all bootstrap bundle

    // Registry with A3 tool
    let lock_json = br#"{
        "v": 1,
        "servers": [
            {
                "server": "git",
                "tools_list_blake3": "0000000000000000000000000000000000000000000000000000000000000000",
                "tools": [
                    {
                        "name": "commit",
                        "action_class": "A3",
                        "sink_clearance": "C1",
                        "namespace": "git",
                        "mutates_root": false,
                        "canonical_verb": "commit",
                        "slots": {},
                        "row_count_arg": null,
                        "max_rows": 1,
                        "qif_mb_per_call": 0,
                        "output_conf": "C1",
                        "entity_key_fields": []
                    }
                ]
            }
        ]
    }"#;
    let fx = make_fixture(cedar, lock_json);

    let mut ctx = ctx_for(&fx, Profile::L2, 10_000);

    // Calling git:commit without Cedar permission must be denied statically
    let script = r#"
tool_call("git", "commit", {"message": "initial commit"})
"#;
    let err = EnclaveStarlarkV1::execute(script, &mut ctx).unwrap_err();
    assert!(err.is("ERR_IFC_STATIC_CEDAR_DENIED"));
}

#[test]
fn plan_executes_with_opaque_refs_and_builtins() {
    let cedar = CedarEngine::baseline_bundle().unwrap();
    let mut fx = make_fixture(cedar, br#"{"v":1,"servers":[]}"#);
    let paste_env = fx
        .heap
        .ingest_attachment(b"error: null pointer at auth.go:42".to_vec(), "paste://001")
        .unwrap();
    let mut ctx = ctx_for(&fx, Profile::L2, 10_000);
    ctx.initial_handles = vec![("paste_0".into(), paste_env.handle.clone())];

    // Plan manipulates opaque ref and builtins
    let script = r#"
ref_str = str(paste_0)
m = min(10, 20)
mx = max(30, 40)
l = len([1, 2, 3])
ref_str
"#;
    let res = EnclaveStarlarkV1::execute(script, &mut ctx).expect("plan should execute cleanly");
    // $paste_0 prints as Ref($paste_0, C3, T3): the label is the heap's.
    assert!(res.return_value.contains("Ref($paste_0, C3, T3)"));
    assert_eq!(res.prechecked_tool_calls, 0);
}

// ---- DEFECT-F-65 ---------------------------------------------------------

const A1_LOCK: &[u8] = br#"{"v":1,"servers":[{"server":"docs","tools_list_blake3":"0000000000000000000000000000000000000000000000000000000000000000","tools":[{"name":"search","action_class":"A1","sink_clearance":"C3","namespace":"docs","mutates_root":false,"canonical_verb":"search","slots":{},"row_count_arg":null,"max_rows":1,"qif_mb_per_call":0,"output_conf":"C1","entity_key_fields":[]}]}]}"#;

#[test]
fn f65_make_ref_is_not_in_the_plan_namespace() {
    let fx = make_fixture(
        CedarEngine::baseline_bundle().unwrap(),
        br#"{"v":1,"servers":[]}"#,
    );
    let mut ctx = ctx_for(&fx, Profile::L2, 10_000);
    let err = EnclaveStarlarkV1::execute(r#"make_ref("$v_0", "C1", "T0")"#, &mut ctx).unwrap_err();
    assert!(err.is("STARLARK_EVAL_ERROR"), "{err}");
    assert!(err.to_string().contains("make_ref"), "{err}");
}

#[test]
fn f65_plan_cannot_construct_a_ref_by_type_name() {
    let fx = make_fixture(
        CedarEngine::baseline_bundle().unwrap(),
        br#"{"v":1,"servers":[]}"#,
    );
    let mut ctx = ctx_for(&fx, Profile::L2, 10_000);
    let err = EnclaveStarlarkV1::execute(r#"Ref("$v_0", "C1", "T0")"#, &mut ctx).unwrap_err();
    assert!(err.is("STARLARK_EVAL_ERROR"), "{err}");
}

#[test]
fn f65_ref_label_is_copied_from_the_verified_envelope() {
    let mut heap = CapabilityHeap::new("6f1c2c1e-3a54-4b8e-9d7a-0c4f5b6a7e81".into());
    let env = heap.ingest_attachment(b"x".to_vec(), "paste://1").unwrap();
    let r = PlanRef::from_heap(&heap, &env.handle).unwrap();
    assert_eq!(r.handle(), env.handle);
    assert_eq!(r.label(), Label::ATTACHMENT_DEFAULT);
    assert_eq!(r.label(), env.label);
}

#[test]
fn f65_unknown_or_wiped_handles_cannot_be_bound() {
    let cedar = CedarEngine::baseline_bundle().unwrap();
    let mut fx = make_fixture(cedar, br#"{"v":1,"servers":[]}"#);
    let env = fx
        .heap
        .ingest_attachment(b"x".to_vec(), "paste://1")
        .unwrap();
    {
        let mut ctx = ctx_for(&fx, Profile::L2, 10_000);
        ctx.initial_handles = vec![("p".into(), "$v_99".into())];
        let err = EnclaveStarlarkV1::execute("p", &mut ctx).unwrap_err();
        assert!(err.is("HANDLE_FORGERY"), "{err}");
    }
    fx.heap.wipe();
    let mut ctx = ctx_for(&fx, Profile::L2, 10_000);
    ctx.initial_handles = vec![("p".into(), env.handle)];
    let err = EnclaveStarlarkV1::execute("p", &mut ctx).unwrap_err();
    assert!(err.is("HANDLE_FORGERY"), "{err}");
}

#[test]
fn f65_binding_names_are_identifiers_and_unique() {
    let cedar = CedarEngine::baseline_bundle().unwrap();
    let mut fx = make_fixture(cedar, br#"{"v":1,"servers":[]}"#);
    let env = fx
        .heap
        .ingest_attachment(b"x".to_vec(), "paste://1")
        .unwrap();
    for bad in [
        vec![("a b".to_owned(), env.handle.clone())],
        vec![("".to_owned(), env.handle.clone())],
        vec![("1a".to_owned(), env.handle.clone())],
        vec![
            ("a".to_owned(), env.handle.clone()),
            ("a".to_owned(), env.handle.clone()),
        ],
    ] {
        let mut ctx = ctx_for(&fx, Profile::L2, 10_000);
        ctx.initial_handles = bad;
        let err = EnclaveStarlarkV1::execute("1", &mut ctx).unwrap_err();
        assert!(err.is("PLAN_BINDING_NAME"), "{err}");
    }
}

#[test]
fn f65_tool_call_fails_closed_after_passing_precheck() {
    let fx = make_fixture(CedarEngine::baseline_bundle().unwrap(), A1_LOCK);
    let mut ctx = ctx_for(&fx, Profile::L2, 10_000);
    let err = EnclaveStarlarkV1::execute(r#"tool_call("docs", "search", {"q": "x"})"#, &mut ctx)
        .unwrap_err();
    assert!(err.is("PLAN_TOOL_DISPATCH_UNWIRED"), "{err}");
}

#[test]
fn f65_tool_call_with_a_ref_argument_is_still_refused() {
    let cedar = CedarEngine::baseline_bundle().unwrap();
    let mut fx = make_fixture(cedar, A1_LOCK);
    let env = fx
        .heap
        .ingest_attachment(b"x".to_vec(), "paste://1")
        .unwrap();
    let mut ctx = ctx_for(&fx, Profile::L2, 10_000);
    ctx.initial_handles = vec![("p".into(), env.handle)];
    let err = EnclaveStarlarkV1::execute(r#"tool_call("docs", "search", {"q": p})"#, &mut ctx)
        .unwrap_err();
    assert!(err.is("PLAN_TOOL_DISPATCH_UNWIRED"), "{err}");
}

#[test]
fn f65_unreached_tool_call_is_prechecked_but_not_dispatched() {
    let fx = make_fixture(CedarEngine::baseline_bundle().unwrap(), A1_LOCK);
    let mut ctx = ctx_for(&fx, Profile::L2, 10_000);
    let script = "x = 1\nif x == 2:\n    tool_call(\"docs\", \"search\", {})\nx";
    let res = EnclaveStarlarkV1::execute(script, &mut ctx).unwrap();
    assert_eq!(res.return_value, "1");
    assert_eq!(res.prechecked_tool_calls, 1);
}

#[test]
fn f65_tool_call_refusal_is_sealed_abort_in_l3() {
    // L3: whether a tool_call was reached is data-dependent, so the refusal
    // takes the constant-size sealed abort like every other L3 failure.
    let fx = make_fixture(CedarEngine::baseline_bundle().unwrap(), A1_LOCK);
    let mut ctx = ctx_for(&fx, Profile::L3, 10_000);
    let err =
        EnclaveStarlarkV1::execute(r#"tool_call("docs", "search", {})"#, &mut ctx).unwrap_err();
    assert!(err.is("ERR_IFC_SEALED_ABORT"), "{err}");
}

// ---- DEFECT-F-68 ---------------------------------------------------------

#[test]
fn f68_error_text_mentioning_limit_or_tick_is_not_fuel_exhaustion() {
    let fx = make_fixture(
        CedarEngine::baseline_bundle().unwrap(),
        br#"{"v":1,"servers":[]}"#,
    );
    for msg in ["rate limit exceeded", "Tick tock", "tick limit"] {
        let mut ctx = ctx_for(&fx, Profile::L2, 10_000);
        let err = EnclaveStarlarkV1::execute(&format!("fail({msg:?})"), &mut ctx).unwrap_err();
        assert!(err.is("STARLARK_EVAL_ERROR"), "{msg}: {err}");
    }
}

#[test]
fn f68_real_fuel_exhaustion_is_still_reported() {
    let fx = make_fixture(
        CedarEngine::baseline_bundle().unwrap(),
        br#"{"v":1,"servers":[]}"#,
    );
    let mut ctx = ctx_for(&fx, Profile::L2, 1_000);
    let script = "t = 0\nfor i in range(100):\n    for j in range(100):\n        t = t + j\nt";
    let err = EnclaveStarlarkV1::execute(script, &mut ctx).unwrap_err();
    assert!(err.is("ERR_IFC_FUEL_EXHAUSTED"), "{err}");
}

// ---- DEFECT-F-69 ---------------------------------------------------------
// The review's validation step: each "Not matched" form of section 18 F-69,
// against `validate_frozen_plan(.., Profile::L3)`, must be rejected (or, for
// tool calls, be seen under the right name so the pre-check applies).

use enclave_agent_runtime::plan::frozen::validate_frozen_plan;

fn l3_rejects(src: &str, code: &str) {
    let err = validate_frozen_plan(src, Profile::L3).expect_err(src);
    assert!(err.is(code), "{src:?}: expected {code}, got {err}");
}

#[test]
fn f69_dynamic_attribute_access_aliased_or_spaced_is_rejected() {
    l3_rejects(
        "g = getattr\nx = g(None, 'foo')",
        "STARLARK_DYNAMIC_ATTR_FORBIDDEN",
    );
    l3_rejects(
        "x = getattr (None, 'foo')",
        "STARLARK_DYNAMIC_ATTR_FORBIDDEN",
    );
    l3_rejects("f = [setattr][0]", "STARLARK_DYNAMIC_ATTR_FORBIDDEN");
    l3_rejects("x = hasattr(1, 'a')", "STARLARK_DYNAMIC_ATTR_FORBIDDEN");
    l3_rejects("x = dir(1)", "STARLARK_DYNAMIC_ATTR_FORBIDDEN");
}

#[test]
fn f69_l3_unbounded_iteration_forms_are_rejected() {
    // Comprehensions (the line does not start with `for `).
    l3_rejects(
        "x = [i for i in range(100000)]",
        "L3_COMPREHENSION_FORBIDDEN",
    );
    l3_rejects("x = {i: i for i in range(3)}", "L3_COMPREHENSION_FORBIDDEN");
    // A tab after `for`: the frozen dialect's parser refuses tabs outright.
    let tab = "for\tx in range(100000):\n    pass";
    let err = validate_frozen_plan(tab, Profile::L3).expect_err(tab);
    assert!(err.is("STARLARK_PARSE_ERROR"), "{err}");
    l3_rejects(
        "for x in  range(100000):\n    pass",
        "L3_LOOP_BOUND_EXCEEDED",
    );
    // An expression that begins with `range(1)` and continues.
    l3_rejects(
        "for x in range(1) + list(range(100000)):\n    pass",
        "L3_UNBOUNDED_LOOP",
    );
    // Dynamic and non-literal bounds.
    l3_rejects(
        "n = 5\nfor x in range(n):\n    pass",
        "L3_DYNAMIC_LOOP_BOUND",
    );
    l3_rejects(
        "for x in range(1, 100000):\n    pass",
        "L3_DYNAMIC_LOOP_BOUND",
    );
    l3_rejects("for x in range(-1):\n    pass", "L3_DYNAMIC_LOOP_BOUND");
    l3_rejects(
        "for x in range(99999999999):\n    pass",
        "L3_LOOP_BOUND_EXCEEDED",
    );
    // Nested loops and loops inside functions are checked too.
    l3_rejects(
        "def f():\n    for x in [1, 2]:\n        pass",
        "L3_UNBOUNDED_LOOP",
    );
    // `range` cannot be rebound to make `range(1)` mean something else.
    l3_rejects(
        "range = list\nfor x in range(1):\n    pass",
        "PLAN_RESERVED_NAME_REBOUND",
    );
    l3_rejects("def f(range):\n    pass", "PLAN_RESERVED_NAME_REBOUND");
    // Non-vacuity: the permitted form passes.
    validate_frozen_plan("for x in range(16):\n    pass", Profile::L3).unwrap();
}

#[test]
fn f69_tool_calls_are_found_by_binding_not_text() {
    // A call through another name.
    l3_rejects(
        "t = tool_call\nt('git', 'commit', {})",
        "PLAN_TOOL_CALL_INDIRECT",
    );
    l3_rejects("x = [tool_call]", "PLAN_TOOL_CALL_INDIRECT");
    l3_rejects("tool_call = print", "PLAN_RESERVED_NAME_REBOUND");
    // Arguments that are variables.
    l3_rejects(
        "s = 'git'\ntool_call(s, 'commit', {})",
        "PLAN_TOOL_CALL_NON_LITERAL",
    );
    l3_rejects(
        "tool_call('git', 'com' + 'mit', {})",
        "PLAN_TOOL_CALL_NON_LITERAL",
    );
    l3_rejects("tool_call(*['git', 'commit', {}])", "PLAN_TOOL_CALL_ARGS");
    // A space before the parenthesis: seen, under the right name.
    let calls = validate_frozen_plan("tool_call ('git', 'commit', {})", Profile::L3).unwrap();
    assert_eq!(calls.len(), 1);
    assert_eq!(
        (calls[0].server.as_str(), calls[0].tool_name.as_str()),
        ("git", "commit")
    );
    // Occurrences inside strings and comments are not calls.
    let src = "x = \"tool_call('git', 'commit')\"  # tool_call('a', 'b')\nx";
    assert!(validate_frozen_plan(src, Profile::L3).unwrap().is_empty());
    // Calls nested in functions and branches are all enumerated.
    let src = "def f():\n    if True:\n        tool_call('a', 'b', {})\ntool_call('c', 'd', {})";
    assert_eq!(validate_frozen_plan(src, Profile::L2).unwrap().len(), 2);
}

#[test]
fn f69_spaced_tool_call_is_statically_denied_end_to_end() {
    let fx = make_fixture(CedarEngine::default_bundle().unwrap(), GIT_A3_LOCK);
    let mut ctx = ctx_for(&fx, Profile::L2, 10_000);
    let err =
        EnclaveStarlarkV1::execute("tool_call (\"git\", \"commit\", {})", &mut ctx).unwrap_err();
    assert!(err.is("ERR_IFC_STATIC_CEDAR_DENIED"), "{err}");
}

#[test]
fn f69_zero_fuel_budget_is_refused_not_unlimited() {
    let fx = make_fixture(
        CedarEngine::baseline_bundle().unwrap(),
        br#"{"v":1,"servers":[]}"#,
    );
    let mut ctx = ctx_for(&fx, Profile::L2, 0);
    let err = EnclaveStarlarkV1::execute("1", &mut ctx).unwrap_err();
    assert!(err.is("ERR_IFC_FUEL_BUDGET"), "{err}");
}

#[test]
fn f69_reserved_names_cannot_be_runtime_bindings() {
    let cedar = CedarEngine::baseline_bundle().unwrap();
    let mut fx = make_fixture(cedar, br#"{"v":1,"servers":[]}"#);
    let env = fx
        .heap
        .ingest_attachment(b"x".to_vec(), "paste://1")
        .unwrap();
    for name in ["range", "tool_call", "getattr"] {
        let mut ctx = ctx_for(&fx, Profile::L2, 10_000);
        ctx.initial_handles = vec![(name.into(), env.handle.clone())];
        let err = EnclaveStarlarkV1::execute("1", &mut ctx).unwrap_err();
        assert!(err.is("PLAN_BINDING_NAME"), "{name}: {err}");
    }
}

const GIT_A3_LOCK: &[u8] = br#"{"v":1,"servers":[{"server":"git","tools_list_blake3":"0000000000000000000000000000000000000000000000000000000000000000","tools":[{"name":"commit","action_class":"A3","sink_clearance":"C1","namespace":"git","mutates_root":false,"canonical_verb":"commit","slots":{},"row_count_arg":null,"max_rows":1,"qif_mb_per_call":0,"output_conf":"C1","entity_key_fields":[]}]}]}"#;
