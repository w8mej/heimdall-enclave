//! Authenticated console ingress caller; never executes native code or prints payloads.
use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use enclave_client_gateway::{ClientGatewayRequest as Request, ClientGatewayResponse as Response};
use enclave_core::{err, fail, error::EnclaveResult, ipc::Client};
use crate::ctl::Env;

fn source(path: &Path) -> EnclaveResult<String> {
    let file=std::fs::OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW|libc::O_NONBLOCK)
        .open(path).map_err(|e|err!(EIO,"GATEWAY_SOURCE_READ","{e}"))?;
    let metadata=file.metadata().map_err(|e|err!(EIO,"GATEWAY_SOURCE_READ","{e}"))?;
    if !metadata.is_file() || metadata.len()>65536 {fail!(E2BIG,"GATEWAY_SOURCE_BOUNDS");}
    let mut bytes=Vec::new();file.take(65537).read_to_end(&mut bytes).map_err(|e|err!(EIO,"GATEWAY_SOURCE_READ","{e}"))?;
    if bytes.len()>65536 {fail!(E2BIG,"GATEWAY_SOURCE_BOUNDS");}
    String::from_utf8(bytes).map_err(|_|err!(EINVAL,"GATEWAY_SOURCE_UTF8"))
}
fn connect(env: &Env) -> EnclaveResult<Client> {
    let path=env.socket_dir.join("gateway/gateway.sock");
    if env.dev {Client::connect(&path,enclave_core::ipc::geteuid())}
    else {
        if !cfg!(target_os="macos") {fail!(EPERM,"GATEWAY_DARWIN_REQUIRED");}
        Client::connect_verified(&path,enclave_core::daemon::GATEWAY_UID,
            Some(&enclave_core::codesign::CodeRequirement::gateway()))
    }
}
/// Execute one explicitly scoped turn and finish on both successful and failed
/// execution. Only authenticated opaque reference metadata is returned; after
/// finish those references have been reclaimed. This is an execution receipt.
pub fn execute(env: &Env, directive: &str, path: &Path, tools: &[String], budget_mb:i64, step_up:bool) -> EnclaveResult<serde_json::Value> {
    enclave_core::user_turn::validate_directive(directive)?;
    if tools.len()>1024 || tools.iter().any(|t|t.len()>1024) || !(0..=12000).contains(&budget_mb) {fail!(EINVAL,"GATEWAY_REQUEST_BOUNDS");}
    let source=source(path)?;
    let turn=enclave_core::user_turn::UserTurnV1 {directive_short:directive.into(),attachments:vec![]};
    let tools=tools.iter().map(|name|enclave_agent_runtime::turn::ToolSignature {name:name.clone(),description:String::new(),params:vec![]}).collect();
    let response:Response=connect(env)?.call(&Request::SubmitExecutableTurn {turn,attachments:vec![],tools,budget_mb})?;
    let Response::Plan {turn_id,root_token:None,..}=response else {fail!(EIO,"GATEWAY_UNEXPECTED_PLAN");};
    let mut result=(|| {
        let response:Response=connect(env)?.call(&Request::ExecuteTurnPlan {turn_id:turn_id.clone(),source,initial_handles:vec![],fuel_budget:10000,step_up})?;
        match response {
            Response::PlanExecuted {return_value,executed_tool_calls,output_refs}=>Ok(serde_json::json!({"status":"executed","return_value":return_value,"executed_tool_calls":executed_tool_calls,"output_refs":output_refs})),
            _=>Err(err!(EIO,"GATEWAY_UNEXPECTED_EXECUTION")),
        }
    })();
    // Reconnect with the same process identity. A reply lost after successful
    // cleanup is idempotently acknowledged while the gateway retains ownership.
    let mut cleanup=None;
    for _ in 0..3 {
        match connect(env).and_then(|mut c|c.call::<_,Response>(&Request::FinishTurn {turn_id:turn_id.clone(),cancelled:result.is_err()})) {
            Ok(Response::Finished {..})=>{cleanup=None;break;}
            Ok(_)=>cleanup=Some(err!(EIO,"GATEWAY_UNEXPECTED_FINISH")),
            Err(error)=>cleanup=Some(error),
        }
    }
    if let Some(error)=cleanup {fail!(EIO,"GATEWAY_CLEANUP_FAILED","turn={turn_id}: {error}");}
    if let Ok(receipt)=result.as_mut() {receipt["references_reclaimed"]=serde_json::json!(true);}
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn source_refuses_symlinks_special_files_and_oversize_without_blocking() {
        use std::os::unix::fs::symlink;
        let directory=std::env::temp_dir().join(format!("f97-source-{:x}",enclave_core::rng::u64()));
        std::fs::create_dir(&directory).unwrap();
        let file=directory.join("plan");std::fs::write(&file,"0").unwrap();
        assert_eq!(source(&file).unwrap(),"0");
        symlink(&file,directory.join("link")).unwrap();assert!(source(&directory.join("link")).is_err());
        assert!(source(&directory).is_err());
        std::fs::write(&file,vec![b'x';65537]).unwrap();assert!(source(&file).unwrap_err().is("GATEWAY_SOURCE_BOUNDS"));
        std::fs::write(&file,[255]).unwrap();assert!(source(&file).unwrap_err().is("GATEWAY_SOURCE_UTF8"));
        let fifo=directory.join("fifo");let c=std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
        assert_eq!(unsafe {libc::mkfifo(c.as_ptr(),0o600)},0);assert!(source(&fifo).is_err());
        std::fs::remove_dir_all(directory).unwrap();
    }
}
