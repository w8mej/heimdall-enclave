//! Adversarial native-artifact binding and bounded execution (DEFECT-F-100).
use ed25519_dalek::{SigningKey, VerifyingKey};
use enclave_tool_host::TicketReplayFilter;
fn make_host(key: VerifyingKey) -> (tempfile::TempDir, ToolHost) {
    let dir = tempfile::Builder::new()
        .permissions(std::os::unix::fs::PermissionsExt::from_mode(0o700))
        .tempdir()
        .unwrap();
    let replay = TicketReplayFilter::initialize(
        &dir.path().canonicalize().unwrap().join("replay.redb"),
        4096,
    )
    .unwrap();
    (dir, ToolHost::new(key, replay))
}
use enclave_tool_host::{host::ToolHost, ticket::ExecutionTicket};

fn artifact(wat: &str) -> Vec<u8> {
    let mut cfg = wasmtime::Config::new();
    cfg.consume_fuel(true).max_wasm_stack(512 * 1024);
    let engine = wasmtime::Engine::new(&cfg).unwrap();
    wasmtime::Module::new(&engine, wat)
        .unwrap()
        .serialize()
        .unwrap()
}
fn ticket(sk: &SigningKey, bytes: &[u8]) -> ExecutionTicket {
    ExecutionTicket::issue(
        sk,
        "native-ticket".into(),
        "trusted".into(),
        "length".into(),
        blake3::hash(b"{}").to_hex().to_string(),
        1,
        10,
        1000,
    )
    .for_module(sk, *blake3::hash(bytes).as_bytes())
}
const VALID: &str = r#"(module
  (memory (export "memory") 1)
  (func (export "alloc") (param i32) (result i32) i32.const 0)
  (func (export "run") (param i32 i32) (result i32) local.get 1))"#;
#[test]
fn approved_native_module_receives_signed_arguments() {
    let sk = SigningKey::from_bytes(&[3; 32]);
    let (_directory, host) = make_host(sk.verifying_key());
    let bytes = artifact(VALID);
    let t = ticket(&sk, &bytes);
    let out = host
        .execute_cwasm(&t, "trusted", "length", &bytes, b"{}", 11)
        .unwrap();
    assert_eq!(out.bytes, b"[{\"result\":2}]");
}
#[test]
fn valid_ticket_never_authorizes_other_native_bytes() {
    let sk = SigningKey::from_bytes(&[3; 32]);
    let (_directory, host) = make_host(sk.verifying_key());
    let bytes = artifact(VALID);
    let t = ticket(&sk, &bytes);
    assert!(host
        .execute_cwasm(
            &t,
            "trusted",
            "length",
            b"arbitrary executable native payload",
            b"{}",
            11
        )
        .unwrap_err()
        .is("TICKET_MODULE_MISMATCH"));
    assert!(
        host.execute_cwasm(&t, "trusted", "length", &bytes, b"{}", 11)
            .is_ok(),
        "mismatch must not burn valid ticket"
    );
}
#[test]
fn module_digest_cannot_be_changed_without_issuer_signature() {
    let sk = SigningKey::from_bytes(&[3; 32]);
    let (_directory, host) = make_host(sk.verifying_key());
    let bytes = artifact(VALID);
    let mut t = ticket(&sk, &bytes);
    t.module_blake3 = Some([9; 32]);
    assert!(host
        .execute_cwasm(&t, "trusted", "length", &bytes, b"{}", 11)
        .unwrap_err()
        .is("TICKET_SIG_VERIFY_FAILED"));
}
#[test]
fn missing_entrypoint_is_failure_and_infinite_loop_exhausts_fuel() {
    let sk = SigningKey::from_bytes(&[3; 32]);
    let bytes = artifact("(module (memory (export \"memory\") 1))");
    let (_directory, host) = make_host(sk.verifying_key());
    assert!(host
        .execute_cwasm(&ticket(&sk, &bytes), "trusted", "length", &bytes, b"{}", 11)
        .unwrap_err()
        .is("WASM_ALLOC_REQUIRED"));
    let bytes = artifact(
        r#"(module (memory (export "memory") 1)
      (func (export "alloc") (param i32) (result i32) i32.const 0)
      (func (export "run") (param i32 i32) (result i32) (loop br 0) i32.const 0))"#,
    );
    let (_directory, host) = make_host(sk.verifying_key());
    assert!(host
        .execute_cwasm(&ticket(&sk, &bytes), "trusted", "length", &bytes, b"{}", 11)
        .unwrap_err()
        .is("WASM_CALL"));
}
#[test]
fn oversized_memory_is_rejected_by_resource_limiter() {
    let sk = SigningKey::from_bytes(&[3; 32]);
    let (_directory, host) = make_host(sk.verifying_key());
    let bytes = artifact("(module (memory (export \"memory\") 2048))");
    assert!(host
        .execute_cwasm(&ticket(&sk, &bytes), "trusted", "length", &bytes, b"{}", 11)
        .unwrap_err()
        .is("WASM_INSTANCE"));
}

#[test]
fn native_dispatch_target_must_match_ticket() {
    let sk = SigningKey::from_bytes(&[3; 32]);
    let (_directory, host) = make_host(sk.verifying_key());
    let bytes = artifact(VALID);
    let t = ticket(&sk, &bytes);
    assert!(host
        .execute_cwasm(&t, "trusted", "other", &bytes, b"{}", 11)
        .unwrap_err()
        .is("TICKET_TOOL_MISMATCH"));
    assert!(host
        .execute_cwasm(&t, "trusted", "length", &bytes, b"{}", 11)
        .is_ok());
}
