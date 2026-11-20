//! Tool execution host with ticket verification and post-call row truncation (GAP-04, GAP-09, ADR-011).

use ed25519_dalek::VerifyingKey;
use enclave_core::error::EnclaveResult;
use enclave_core::{err, fail};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use crate::ticket::{ExecutionTicket, RowFormat, TicketReplayFilter};
use crate::lifecycle::{DispatchExpiry, trusted_unix_ns};

// No new fence is implied: this rechecks original time limits only. The existing
// cross-process final-handoff/generation contract still needs separate work.
fn dispatch_stage(ticket: &ExecutionTicket, expiry: Option<&DispatchExpiry>, stage: &'static str)
    -> EnclaveResult<()> {
    #[cfg(test)]
    expiry_tests::pause_before_check(stage, expiry, ticket);
    if let Some(expiry) = expiry {
        expiry.check()?;
        if trusted_unix_ns()? >= ticket.expires_at_unix_ns {
            fail!(ESTALE, "TOOL_AUTHORITY_EXPIRED");
        }
    }
    #[cfg(test)]
    expiry_tests::entered(stage);
    #[cfg(not(test))]
    let _ = stage;
    Ok(())
}

/// Tool execution result.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolOutput {
    /// Raw or truncated output bytes.
    pub bytes: Vec<u8>,
    /// Whether row truncation was applied.
    pub truncated: bool,
    /// Original row count if tabular.
    pub original_rows: Option<usize>,
    /// Final row count after truncation.
    pub final_rows: Option<usize>,
}

impl ToolOutput {
    /// Erase the currently owned output allocation. Copies already transferred
    /// to a caller, serializer or external sink require their own owner cleanup.
    pub fn wipe(&mut self) { self.bytes.zeroize(); }
    /// Transfer ownership explicitly; the recipient becomes responsible for
    /// erasing these bytes after use. This object no longer retains a copy.
    pub fn into_bytes(mut self) -> Vec<u8> { std::mem::take(&mut self.bytes) }
}
impl Drop for ToolOutput { fn drop(&mut self) { self.wipe(); } }
impl std::fmt::Debug for ToolOutput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ToolOutput").field("bytes", &format_args!("[REDACTED; {}]", self.bytes.len()))
            .field("truncated", &self.truncated).field("original_rows", &self.original_rows)
            .field("final_rows", &self.final_rows).finish()
    }
}

// serde_json owns additional decoded String buffers independently of the raw
// output. Scrub strings in both retained and discarded rows before freeing them.
// Parser internals, numbers, historical reallocations and library stack copies
// remain outside this bounded ownership claim.
struct SensitiveJson(serde_json::Value);
fn wipe_json_strings(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::String(text) => text.zeroize(),
        serde_json::Value::Array(values) => values.iter_mut().for_each(wipe_json_strings),
        serde_json::Value::Object(values) => {
            for (mut key, mut value) in std::mem::take(values) {
                key.zeroize(); wipe_json_strings(&mut value);
            }
        },
        _ => {},
    }
}
impl Drop for SensitiveJson { fn drop(&mut self) { wipe_json_strings(&mut self.0); } }

/// Enforce the default top-level JSON array row contract; reject unknown shapes.
pub fn truncate_rows(
    output: &[u8],
    row_bound: u64,
) -> EnclaveResult<(Vec<u8>, bool, Option<usize>, Option<usize>)> {
    truncate_rows_as(output, row_bound, RowFormat::JsonArray)
}

/// Enforce an issuer-selected row contract without output-shape guessing.
pub fn truncate_rows_as(
    output: &[u8],
    row_bound: u64,
    format: RowFormat,
) -> EnclaveResult<(Vec<u8>, bool, Option<usize>, Option<usize>)> {
    let bound = usize::try_from(row_bound).unwrap_or(usize::MAX);
    match format {
        RowFormat::JsonArray => {
            let mut parsed = SensitiveJson(serde_json::from_slice(output)
                .map_err(|_| err!(EINVAL, "TOOL_OUTPUT_JSON_REQUIRED"))?);
            let rows = parsed.0.as_array_mut().ok_or_else(|| err!(EINVAL, "TOOL_OUTPUT_ARRAY_REQUIRED"))?;
            let orig = rows.len();
            let retained = bound.min(rows.len());
            for value in &mut rows[retained..] { wipe_json_strings(value); }
            rows.truncate(retained);
            let fin = rows.len();
            let bytes =
                serde_json::to_vec(&rows).map_err(|_| err!(EINVAL, "TOOL_OUTPUT_SERIALIZE"))?;
            Ok((bytes, orig > fin, Some(orig), Some(fin)))
        }
        RowFormat::Utf8Lines => {
            let text = std::str::from_utf8(output)
                .map_err(|_| err!(EINVAL, "TOOL_OUTPUT_UTF8_REQUIRED"))?;
            // CRLF is one separator, and a terminal separator does not add an empty row.
            let normalized = Zeroizing::new(text.replace("\r\n", "\n"));
            let normalized = Zeroizing::new(normalized.replace('\r', "\n"));
            let rows: Vec<&str> = normalized.lines().collect();
            let orig = rows.len();
            let fin = orig.min(bound);
            Ok((
                rows[..fin].join("\n").into_bytes(),
                orig > fin,
                Some(orig),
                Some(fin),
            ))
        }
    }
}

/// Host for executing authorized tools.
pub struct ToolHost {
    grant_key: VerifyingKey,
    replay: TicketReplayFilter,
}

impl std::fmt::Debug for ToolHost {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ToolHost")
            .field("grant_key", &hex::encode(self.grant_key.as_bytes()))
            .finish()
    }
}

impl ToolHost {
    /// Create a new tool host with UID 704's grant verifying key.
    pub fn new(grant_key: VerifyingKey, replay: TicketReplayFilter) -> Self {
        Self { grant_key, replay }
    }

    /// Execute a tool invocation after validating the single-use ticket.
    /// Expected names must come from the dispatcher-selected target, not the ticket.
    pub fn execute<F>(
        &self,
        ticket: &ExecutionTicket,
        expected_server: &str,
        expected_tool: &str,
        args_jcs: &[u8],
        now_unix_ns: u64,
        run_fn: F,
    ) -> EnclaveResult<ToolOutput>
    where
        F: FnOnce(&str, &str, &[u8]) -> EnclaveResult<Vec<u8>>,
    {
        let args_hash = hex::encode(blake3::hash(args_jcs).as_bytes());
        ticket.verify(
            &self.grant_key,
            now_unix_ns,
            expected_server,
            expected_tool,
            &args_hash,
        )?;

        // Consume ticket (prevent replay)
        self.replay
            .consume(&ticket.ticket_id, ticket.expires_at_unix_ns, now_unix_ns)?;

        // Run the tool implementation
        let raw_output = Zeroizing::new(run_fn(expected_server, expected_tool, args_jcs)?);

        // GAP-09: apply row-bound truncation
        let (bytes, truncated, orig, fin) =
            truncate_rows_as(&raw_output, ticket.row_bound, ticket.row_format)?;

        Ok(ToolOutput {
            bytes,
            truncated,
            original_rows: orig,
            final_rows: fin,
        })
    }

    /// Execute a precompiled .cwasm module with Cranelift disabled (Zero-JIT, ADR-011).
    /// Expected names must come from the dispatcher-selected target, not the ticket.
    pub fn execute_cwasm(
        &self,
        ticket: &ExecutionTicket,
        expected_server: &str,
        expected_tool: &str,
        cwasm_bytes: &[u8],
        args_jcs: &[u8],
        now_unix_ns: u64,
    ) -> EnclaveResult<ToolOutput> {
        self.execute_cwasm_inner(ticket, expected_server, expected_tool, cwasm_bytes,
            args_jcs, now_unix_ns, None)
    }

    /// Execute with original custody freshness checks after slow preparation and
    /// before native start/alloc/run/output. This does not add revocation authority.
    #[allow(clippy::too_many_arguments)]
    pub fn execute_cwasm_before(&self, ticket: &ExecutionTicket, expected_server: &str,
        expected_tool: &str, cwasm_bytes: &[u8], args_jcs: &[u8], now_unix_ns: u64,
        expiry: &DispatchExpiry) -> EnclaveResult<ToolOutput> {
        expiry.check()?;
        self.execute_cwasm_inner(ticket, expected_server, expected_tool, cwasm_bytes,
            args_jcs, now_unix_ns, Some(expiry))
    }

    #[allow(clippy::too_many_arguments)]
    fn execute_cwasm_inner(&self, ticket: &ExecutionTicket, expected_server: &str,
        expected_tool: &str, cwasm_bytes: &[u8], args_jcs: &[u8], now_unix_ns: u64,
        expiry: Option<&DispatchExpiry>) -> EnclaveResult<ToolOutput> {
        let args_hash = hex::encode(blake3::hash(args_jcs).as_bytes());
        ticket.verify(
            &self.grant_key,
            now_unix_ns,
            expected_server,
            expected_tool,
            &args_hash,
        )?;
        let approved = ticket
            .module_blake3
            .ok_or_else(|| err!(EACCES, "TICKET_MODULE_UNBOUND"))?;
        if blake3::hash(cwasm_bytes).as_bytes() != &approved {
            fail!(EACCES, "TICKET_MODULE_MISMATCH");
        }
        if cwasm_bytes.len() > 64 * 1024 * 1024 || args_jcs.len() > 1024 * 1024 {
            fail!(E2BIG, "WASM_INPUT_LIMIT");
        }
        self.replay
            .consume(&ticket.ticket_id, ticket.expires_at_unix_ns, now_unix_ns)?;

        // Verify zero JIT by configuring Wasmtime engine without Cranelift
        // In our zero-JIT build, Cranelift feature is disabled.
        let mut config = wasmtime::Config::new();
        config.consume_fuel(true).max_wasm_stack(512 * 1024);
        let engine = wasmtime::Engine::new(&config).map_err(|e| err!(EIO, "WASM_ENGINE", "{e}"))?;

        // SAFETY: the signature-verified ticket binds these exact native bytes to
        // an authenticated offline build artifact. Issuers must never approve a
        // digest supplied by the caller. No raw native code reaches this operation.
        // The artifact must be built with consume_fuel enabled to match this engine.
        // Deserialization of precompiled artifact (zero JIT at runtime)
        let module = unsafe {
            wasmtime::Module::deserialize(&engine, cwasm_bytes)
                .map_err(|e| err!(EINVAL, "WASM_MODULE", "{e}"))?
        };

        let limits = wasmtime::StoreLimitsBuilder::new()
            .memory_size(64 * 1024 * 1024)
            .table_elements(100_000)
            .instances(1)
            .memories(1)
            .tables(1)
            .trap_on_grow_failure(true)
            .build();
        let mut store = wasmtime::Store::new(&engine, limits);
        store.limiter(|limits| limits);
        store
            .set_fuel(1_000_000)
            .map_err(|e| err!(EIO, "WASM_FUEL", "{e}"))?;
        // Instantiation itself may execute an authenticated module's start function.
        dispatch_stage(ticket, expiry, "instance")?;
        let instance = wasmtime::Instance::new(&mut store, &module, &[])
            .map_err(|e| err!(EIO, "WASM_INSTANCE", "{e}"))?;

        // Fixed tool ABI: exported memory, alloc(i32)->i32 and
        // run(args_pointer:i32, args_length:i32)->i32. Arguments are the exact
        // canonical bytes covered by the ticket; missing exports are errors.
        let memory = instance
            .get_memory(&mut store, "memory")
            .ok_or_else(|| err!(EINVAL, "WASM_MEMORY_REQUIRED"))?;
        let result = (|| {
        let alloc = instance
            .get_typed_func::<i32, i32>(&mut store, "alloc")
            .map_err(|e| err!(EINVAL, "WASM_ALLOC_REQUIRED", "{e}"))?;
        let run = instance
            .get_typed_func::<(i32, i32), i32>(&mut store, "run")
            .map_err(|e| err!(EINVAL, "WASM_RUN_REQUIRED", "{e}"))?;
        let length = i32::try_from(args_jcs.len()).map_err(|_| err!(E2BIG, "WASM_ARGUMENTS"))?;
        dispatch_stage(ticket, expiry, "alloc")?;
        let pointer = alloc
            .call(&mut store, length)
            .map_err(|e| err!(EIO, "WASM_ALLOC", "{e}"))?;
        let pointer =
            usize::try_from(pointer).map_err(|_| err!(EINVAL, "WASM_ARGUMENT_POINTER"))?;
        memory
            .write(&mut store, pointer, args_jcs)
            .map_err(|e| err!(EINVAL, "WASM_ARGUMENT_BOUNDS", "{e}"))?;
        dispatch_stage(ticket, expiry, "run")?;
        let result = run
            .call(&mut store, (pointer as i32, length))
            .map_err(|e| err!(EIO, "WASM_CALL", "{e}"))?;
        let raw_output = Zeroizing::new(serde_json::to_vec(&serde_json::json!([{ "result": result }]))
            .map_err(|e| err!(EIO, "WASM_RESULT", "{e}"))?);

        let (bytes, truncated, orig, fin) =
            truncate_rows_as(&raw_output, ticket.row_bound, ticket.row_format)?;
        let output = ToolOutput {
            bytes,
            truncated,
            original_rows: orig,
            final_rows: fin,
        };
        // ToolOutput's Drop wipes even when this last freshness check refuses.
        dispatch_stage(ticket, expiry, "output")?;
        Ok(output)
        })();
        // Arguments can remain in linear memory even when `run` traps or an
        // output/ABI check fails. Scrub the entire live memory before releasing
        // Store ownership; compiled code/framework copies are not covered.
        memory.data_mut(&mut store).zeroize();
        result
    }
}


#[cfg(test)]
mod expiry_tests {
    use super::*;
    use crate::artifacts::{sign_manifest,ApprovedModuleV1,ArtifactDispatcher,ArtifactManifestV1,TrustedArtifactTable};
    use crate::lifecycle::DurableToolHost;
    use ed25519_dalek::SigningKey;
    use std::{cell::RefCell,os::unix::fs::PermissionsExt,time::Duration};
    #[derive(Default)]
    struct Observation {
        pause:Option<&'static str>,
        entered:Vec<&'static str>,
        ticket:Option<ExecutionTicket>,
    }
    thread_local! {static OBSERVATION:RefCell<Option<Observation>>=const {RefCell::new(None)};}
    struct Observe;
    impl Observe {
        fn begin(pause:Option<&'static str>)->Self {
            OBSERVATION.with(|state|*state.borrow_mut()=Some(Observation {pause,..Default::default()}));Self
        }
        fn snapshot(&self)->(Vec<&'static str>,ExecutionTicket) {
            OBSERVATION.with(|state| {let state=state.borrow();let state=state.as_ref().unwrap();
                (state.entered.clone(),state.ticket.clone().unwrap())})
        }
    }
    impl Drop for Observe {fn drop(&mut self) {OBSERVATION.with(|state|*state.borrow_mut()=None);}}
    pub(super) fn pause_before_check(stage:&'static str,expiry:Option<&DispatchExpiry>,ticket:&ExecutionTicket) {
        // Test scheduling pause only: all checks continue to use actual clocks and
        // the originally captured endpoint. No injected clock or product bypass.
        let pause=OBSERVATION.with(|state| {
            let mut state=state.borrow_mut();let Some(state)=state.as_mut() else {return false};
            state.ticket=Some(ticket.clone());state.pause==Some(stage)
        });
        if pause {
            if let Some(expiry)=expiry {
                while enclave_core::clock::boot_clock_ns()<expiry.boot_deadline_ns() {
                    std::thread::sleep(Duration::from_millis(1));
                }
            }
        }
    }
    pub(super) fn entered(stage:&'static str) {
        OBSERVATION.with(|state| {if let Some(state)=state.borrow_mut().as_mut() {state.entered.push(stage);}});
    }
    const WAT:&str=r#"(module
      (memory (export "memory") 1)
      (func (export "alloc") (param i32) (result i32) i32.const 0)
      (func (export "run") (param i32 i32) (result i32)
        local.get 0 i32.const 5 i32.add i32.load8_u))"#;
    struct Fixture {dir:tempfile::TempDir,module:Vec<u8>,build:SigningKey,issuer:SigningKey,signed:Vec<u8>}
    impl Fixture {
        fn new()->Self {Self::with_source(WAT)}
        fn with_source(source:&str)->Self {
            let mut cfg=wasmtime::Config::new();cfg.consume_fuel(true).max_wasm_stack(512*1024);
            let module=wasmtime::Module::new(&wasmtime::Engine::new(&cfg).unwrap(),source).unwrap().serialize().unwrap();
            let dir=tempfile::Builder::new().permissions(std::fs::Permissions::from_mode(0o700)).tempdir().unwrap();
            std::fs::write(dir.path().join("a.cwasm"),&module).unwrap();
            let build=SigningKey::from_bytes(&[81;32]);let issuer=SigningKey::from_bytes(&[82;32]);
            let now=trusted_unix_ns().unwrap();
            let signed=serde_json::to_vec(&sign_manifest(ArtifactManifestV1 {v:1,issued_at_unix_ns:now,
                expires_at_unix_ns:now+60_000_000_000,modules:vec![ApprovedModuleV1 {
                    server:"approved".into(),tool_name:"a".into(),file_name:"a.cwasm".into(),
                    module_blake3:*blake3::hash(&module).as_bytes(),
                    tools_list:serde_json::json!({"tools":[{"name":"a"}]}),row_format:RowFormat::JsonArray,max_rows:1,
                }]},&build).unwrap()).unwrap();
            let fixture=Self {dir,module,build,issuer,signed};
            drop(DurableToolHost::provision(&fixture.replay(),fixture.issuer.verifying_key(),32).unwrap());fixture
        }
        fn replay(&self)->std::path::PathBuf {self.dir.path().canonicalize().unwrap().join("replay")}
        fn dispatcher(&self)->ArtifactDispatcher {
            let mut table=TrustedArtifactTable::load(&self.signed,&self.build.verifying_key(),
                &self.dir.path().canonicalize().unwrap()).unwrap();
            table.verify_tools_lists(|server,list| {
                assert_eq!(server,"approved");assert_eq!(list,&serde_json::json!({"tools":[{"name":"a"}]}));Ok(())
            }).unwrap();ArtifactDispatcher::open(table,&self.replay(),self.issuer.clone()).unwrap()
        }
    }
    #[test]
    fn actual_signed_dispatch_keeps_original_wall_bound_and_replay_consumption() {
        let fixture=Fixture::new();let dispatcher=fixture.dispatcher();
        let wall=(trusted_unix_ns().unwrap()/1_000_000_000) as i64+5;
        let expiry=DispatchExpiry::from_original(Some(wall),enclave_core::clock::boot_clock_ns()+8_000_000_000).unwrap();
        let observation=Observe::begin(None);
        let (output,_)=dispatcher.execute_before("approved","a",br#"{"n":7}"#,1,&[1;32],&expiry).unwrap();
        assert_eq!(output.bytes,br#"[{"result":55}]"#);
        let (stages,ticket)=observation.snapshot();assert_eq!(stages,vec!["instance","alloc","run","output"]);
        assert!(ticket.expires_at_unix_ns<=wall as u64*1_000_000_000);
        assert!(ticket.expires_at_unix_ns-ticket.issued_at_unix_ns<8_000_000_000);
        drop(dispatcher);
        let dispatcher=fixture.dispatcher();
        assert!(dispatcher.execute_before("approved","a",br#"{"n":7}"#,1,&[1;32],&expiry)
            .unwrap_err().is("TICKET_REPLAYED"));
    }
    #[test]
    fn actual_signed_dispatch_refuses_each_delayed_code_or_output_boundary() {
        for (index,stage) in ["instance","alloc","run","output"].into_iter().enumerate() {
            // If the refused Wasm stage ran, it would trap with WASM_INSTANCE,
            // WASM_ALLOC or WASM_CALL instead of the required expiry refusal.
            let source=match stage {
                "instance"=>WAT.replace("(memory", "(func $start unreachable) (start $start) (memory"),
                "alloc"=>WAT.replace("(result i32) i32.const 0)","(result i32) unreachable)"),
                "run"=>WAT.replace("local.get 0 i32.const 5 i32.add i32.load8_u","unreachable"),
                _=>WAT.to_owned(),
            };
            let fixture=Fixture::with_source(&source);let dispatcher=fixture.dispatcher();
            let expiry=DispatchExpiry::from_original(None,enclave_core::clock::boot_clock_ns()+2_000_000_000).unwrap();
            let observation=Observe::begin(Some(stage));
            let error=dispatcher.execute_before("approved","a",br#"{"n":7}"#,1,&[(index+2) as u8;32],&expiry).unwrap_err();
            assert!(error.is("TOOL_AUTHORITY_EXPIRED"),"{stage}: {error}");
            let (entered,ticket)=observation.snapshot();
            assert_eq!(entered,&["instance","alloc","run","output"][..index],"{stage}");
            assert!(ticket.expires_at_unix_ns-ticket.issued_at_unix_ns<=2_000_000_000);
            // Once the shortened ticket expires, its original signed bytes remain
            // unusable across reopen. Replay-store expiry/pruning is unchanged.
            drop(dispatcher);
            let host=DurableToolHost::open(&fixture.replay(),fixture.issuer.verifying_key()).unwrap();
            assert!(host.execute_cwasm(&ticket,"approved","a",&fixture.module,br#"{"n":7}"#)
                .unwrap_err().is("TICKET_EXPIRED"));
        }
    }
    #[test]
    fn late_original_boot_refusal_consumes_still_live_ticket_across_durable_reopen() {
        let fixture=Fixture::new();let now=trusted_unix_ns().unwrap();
        // A deliberately longer low-level test ticket isolates durable consumption
        // from expired-entry pruning. Actual ArtifactDispatcher always shortens it.
        let ticket=ExecutionTicket::issue(&fixture.issuer,"late-native".into(),"approved".into(),"a".into(),
            blake3::hash(br#"{"n":7}"#).to_hex().to_string(),1,now,60_000_000_000)
            .for_module(&fixture.issuer,*blake3::hash(&fixture.module).as_bytes());
        let host=DurableToolHost::open(&fixture.replay(),fixture.issuer.verifying_key()).unwrap();
        let expiry=DispatchExpiry::from_original(None,enclave_core::clock::boot_clock_ns()+2_000_000_000).unwrap();
        let observation=Observe::begin(Some("instance"));
        assert!(host.execute_cwasm_before(&ticket,"approved","a",&fixture.module,br#"{"n":7}"#,&expiry)
            .unwrap_err().is("TOOL_AUTHORITY_EXPIRED"));
        assert!(observation.snapshot().0.is_empty());drop(host);
        let host=DurableToolHost::open(&fixture.replay(),fixture.issuer.verifying_key()).unwrap();
        assert!(host.execute_cwasm(&ticket,"approved","a",&fixture.module,br#"{"n":7}"#)
            .unwrap_err().is("TICKET_REPLAYED"));
    }
}
