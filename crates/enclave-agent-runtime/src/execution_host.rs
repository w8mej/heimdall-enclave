//! Production plan -> signed artifact -> durable native host adapter (F65/F103/F100).
use std::fs::OpenOptions;
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};

use ed25519_dalek::{SigningKey, VerifyingKey};
use enclave_core::error::EnclaveResult;
use enclave_core::runtime::DaemonArgs;
use enclave_core::{err, fail};
use enclave_tool_host::artifacts::{ArtifactDispatcher, TrustedArtifactTable};

use crate::plan::dispatch::{
    AuthorizedToolCall, NoToolDispatch, ToolDispatchOutput, ToolDispatchPort,
};
use crate::registry::ToolRegistry;

fn read_config(path: &Path, max: usize, secret: bool) -> EnclaveResult<Vec<u8>> {
    enclave_tool_host::lifecycle::validate_trusted_ancestry(path)?;
    if !path.is_absolute() {
        fail!(EACCES, "TOOL_CONFIG_ABSOLUTE_PATH");
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
        .map_err(|e| err!(EIO, "TOOL_CONFIG_OPEN", "{e}"))?;
    let meta = file
        .metadata()
        .map_err(|e| err!(EIO, "TOOL_CONFIG_STAT", "{e}"))?;
    // Root/daemon-owned public configuration may be readable; private issuer
    // seeds are daemon-owned and inaccessible to other users.
    let uid = enclave_core::ipc::geteuid();
    if !meta.is_file()
        || meta.nlink() != 1
        || meta.len() > max as u64
        || (meta.uid() != 0 && meta.uid() != uid)
        || meta.mode() & 0o022 != 0
        || (secret && (meta.uid() != uid || meta.mode() & 0o077 != 0))
    {
        fail!(EACCES, "TOOL_CONFIG_UNTRUSTED");
    }
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take((max + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|e| err!(EIO, "TOOL_CONFIG_READ", "{e}"))?;
    if bytes.len() > max {
        fail!(E2BIG, "TOOL_CONFIG_LIMIT");
    }
    Ok(bytes)
}

fn decode_key(bytes: &[u8]) -> EnclaveResult<[u8; 32]> {
    let text = std::str::from_utf8(bytes).map_err(|_| err!(EINVAL, "TOOL_CONFIG_KEY"))?;
    hex::decode(text.trim())
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or_else(|| err!(EINVAL, "TOOL_CONFIG_KEY"))
}

pub(crate) fn load_policy_key(path: &Path) -> EnclaveResult<SigningKey> {
    Ok(SigningKey::from_bytes(&decode_key(&read_config(
        path, 128, true,
    )?)?))
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct InstalledToolConfig {
    v: u8,
    artifact_manifest: String,
    build_key_file: String,
    artifact_dir: String,
    replay_file: String,
}

/// Adapter configured at daemon startup; it accepts no IPC-controlled native code.
#[derive(Debug)]
pub struct NativeToolDispatch {
    dispatcher: ArtifactDispatcher,
}

impl NativeToolDispatch {
    /// Load all configuration together or refuse startup. Normal startup reopens
    /// existing replay state and never provisions it. No flags means the existing
    /// fail-closed unavailable transport, preserving non-tool deployments.
    pub fn from_args(
        args: &DaemonArgs,
        registry: &ToolRegistry,
        issuer: &SigningKey,
    ) -> EnclaveResult<Box<dyn ToolDispatchPort>> {
        let names = [
            "tool-artifact-manifest",
            "tool-build-key-file",
            "tool-artifact-dir",
            "tool-replay-file",
        ];
        let values: Vec<_> = names.iter().map(|key| args.get(key)).collect();
        if values.iter().all(|v| v.is_none()) {
            if let Some(directory) = &args.state_dir {
                let path = directory.join("tool-execution.json");
                match std::fs::symlink_metadata(&path) {
                    Ok(_) => {
                        let config: InstalledToolConfig =
                            serde_json::from_slice(&read_config(&path, 4096, false)?)
                                .map_err(|_| err!(EINVAL, "TOOL_INSTALLED_CONFIG"))?;
                        if config.v != 1 {
                            fail!(EINVAL, "TOOL_INSTALLED_CONFIG_VERSION");
                        }
                        let mut configured = args.clone();
                        for (key, value) in names.into_iter().zip([
                            config.artifact_manifest,
                            config.build_key_file,
                            config.artifact_dir,
                            config.replay_file,
                        ]) {
                            configured.extra.push((key.into(), value));
                        }
                        return Self::from_args(&configured, registry, issuer);
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(e) => return Err(err!(EIO, "TOOL_INSTALLED_CONFIG", "{e}")),
                }
            }
            return Ok(Box::new(NoToolDispatch));
        }
        if values.iter().any(|v| v.is_none()) {
            fail!(EINVAL, "TOOL_CONFIG_INCOMPLETE");
        }
        let seed_path = args
            .get("policy-key-file")
            .ok_or_else(|| err!(EACCES, "TOOL_PERSISTENT_ISSUER_REQUIRED"))?;
        if load_policy_key(Path::new(seed_path))?.verifying_key() != issuer.verifying_key() {
            fail!(EACCES, "TOOL_ISSUER_CHANGED_DURING_STARTUP");
        }
        let build_key = VerifyingKey::from_bytes(&decode_key(&read_config(
            Path::new(values[1].unwrap()),
            128,
            false,
        )?)?)
        .map_err(|_| err!(EINVAL, "TOOL_BUILD_KEY"))?;
        let manifest = read_config(Path::new(values[0].unwrap()), 1024 * 1024, false)?;
        let mut table =
            TrustedArtifactTable::load(&manifest, &build_key, Path::new(values[2].unwrap()))?;
        table.verify_tools_lists(|server, list| {
            registry.verify_tools_list(server, list).map(|_| ())
        })?;
        let dispatcher =
            ArtifactDispatcher::open(table, Path::new(values[3].unwrap()), issuer.clone())?;
        Ok(Box::new(Self { dispatcher }))
    }
}

impl ToolDispatchPort for NativeToolDispatch {
    fn execute(
        &self,
        call: AuthorizedToolCall,
        cancel: &AtomicBool,
    ) -> EnclaveResult<ToolDispatchOutput> {
        if cancel.load(Ordering::SeqCst) {
            fail!(EPERM, "PLAN_TURN_CANCELLED");
        }
        let (output, tools_list) = match call.dispatch_expiry() {
            Some(expiry) => {
                expiry.check()?;
                self.dispatcher.execute_before(call.server(),call.tool_name(),call.args_jcs(),
                    call.row_bound(),call.authorization_id(),expiry)?
            },
            None => self.dispatcher.execute(call.server(),call.tool_name(),call.args_jcs(),
                call.row_bound(),call.authorization_id())?,
        };
        if cancel.load(Ordering::SeqCst) {
            fail!(EPERM, "PLAN_TURN_CANCELLED");
        }
        if let Some(expiry)=call.dispatch_expiry() {expiry.check()?;}
        Ok(ToolDispatchOutput {
            payload: output.into_bytes(),
            tools_list,
        })
    }
}


#[cfg(test)]
mod expiry_tests {
    use super::*;
    use enclave_tool_host::artifacts::{sign_manifest,ApprovedModuleV1,ArtifactManifestV1};
    use enclave_tool_host::lifecycle::{trusted_unix_ns,DispatchExpiry,DurableToolHost};
    use std::{os::unix::fs::PermissionsExt,time::Duration};
    fn call(expiry:DispatchExpiry,id:u8)->AuthorizedToolCall {
        // Internal software fixture; product calls are minted by the live PDP.
        AuthorizedToolCall {server:"approved".into(),tool_name:"a".into(),args_jcs:br#"{"n":7}"#.to_vec(),
            row_bound:1,authorization_id:[id;32],plan_blake3:[99;32],dispatch_expiry:Some(expiry)}
    }
    #[test]
    fn actual_native_adapter_preserves_live_bounds_and_refuses_boot_or_wall_expired_arrival() {
        let mut config=wasmtime::Config::new();config.consume_fuel(true).max_wasm_stack(512*1024);
        let module=wasmtime::Module::new(&wasmtime::Engine::new(&config).unwrap(),r#"(module
          (memory (export "memory") 1)
          (func (export "alloc") (param i32) (result i32) i32.const 0)
          (func (export "run") (param i32 i32) (result i32)
            local.get 0 i32.const 5 i32.add i32.load8_u))"#).unwrap().serialize().unwrap();
        let dir=tempfile::Builder::new().permissions(std::fs::Permissions::from_mode(0o700)).tempdir().unwrap();
        let root=dir.path().canonicalize().unwrap();std::fs::write(root.join("a.cwasm"),&module).unwrap();
        let build=SigningKey::from_bytes(&[83;32]);let issuer=SigningKey::from_bytes(&[84;32]);
        let now=trusted_unix_ns().unwrap();
        let signed=sign_manifest(ArtifactManifestV1 {v:1,issued_at_unix_ns:now,expires_at_unix_ns:now+60_000_000_000,
            modules:vec![ApprovedModuleV1 {server:"approved".into(),tool_name:"a".into(),file_name:"a.cwasm".into(),
                module_blake3:*blake3::hash(&module).as_bytes(),tools_list:serde_json::json!({"tools":[{"name":"a"}]}),
                row_format:enclave_tool_host::ticket::RowFormat::JsonArray,max_rows:1}]},&build).unwrap();
        let mut table=TrustedArtifactTable::load(&serde_json::to_vec(&signed).unwrap(),&build.verifying_key(),&root).unwrap();
        table.verify_tools_lists(|server,list| {
            assert_eq!(server,"approved");assert_eq!(list,&serde_json::json!({"tools":[{"name":"a"}]}));Ok(())
        }).unwrap();
        let replay=root.join("replay");drop(DurableToolHost::provision(&replay,issuer.verifying_key(),32).unwrap());
        let port=NativeToolDispatch {dispatcher:ArtifactDispatcher::open(table,&replay,issuer).unwrap()};
        let cancel=AtomicBool::new(false);
        let fresh=DispatchExpiry::from_original(None,enclave_core::clock::boot_clock_ns()+5_000_000_000).unwrap();
        assert_eq!(port.execute(call(fresh,1),&cancel).unwrap().payload,br#"[{"result":55}]"#);
        for (id,wall) in [(2,None),(3,Some((trusted_unix_ns().unwrap()/1_000_000_000) as i64+2))] {
            let expiry=DispatchExpiry::from_original(wall,enclave_core::clock::boot_clock_ns()+
                if wall.is_some() {8_000_000_000} else {200_000_000}).unwrap();
            loop {
                let boot_late=enclave_core::clock::boot_clock_ns()>=expiry.boot_deadline_ns();
                let wall_late=expiry.wall_deadline_ns().is_some_and(|value|trusted_unix_ns().unwrap()>=value);
                if boot_late || wall_late {break;}
                std::thread::sleep(Duration::from_millis(1));
            }
            assert!(port.execute(call(expiry,id),&cancel).unwrap_err().is("TOOL_AUTHORITY_EXPIRED"));
            // Refusal at adapter entry never consumed/issued this call's ticket.
            // This is an explicit separate internal fixture authorization, not a
            // renewal or retry facility exposed by any production request.
            let fresh=DispatchExpiry::from_original(None,enclave_core::clock::boot_clock_ns()+5_000_000_000).unwrap();
            assert_eq!(port.execute(call(fresh,id),&cancel).unwrap().payload,br#"[{"result":55}]"#);
        }
    }
}
