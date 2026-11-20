//! INIT/GetInfo-only native capability probe. Never invokes enrollment or PIN.
use enclave_core::{err, fail};
use enclave_core::error::EnclaveResult;

fn run() -> EnclaveResult<()> {
    let mut expected = None;
    let mut timeout_ms = 5000u64;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--expected-aaguid" => {
                let value = args.next().ok_or_else(||err!(EINVAL,"FIDO_DIAGNOSTIC_ARGUMENT"))?;
                let bytes = hex::decode(value).map_err(|_|err!(EINVAL,"FIDO_DIAGNOSTIC_AAGUID"))?;
                expected = Some(<[u8;16]>::try_from(bytes).map_err(|_|err!(EINVAL,"FIDO_DIAGNOSTIC_AAGUID"))?);
            }
            "--timeout-ms" => {
                timeout_ms = args.next().and_then(|v|v.parse().ok()).filter(|v| (100..=10000).contains(v))
                    .ok_or_else(||err!(EINVAL,"FIDO_DIAGNOSTIC_BUDGET"))?;
            }
            "--help" => {
                println!("enclave-fido-diagnostic [--expected-aaguid MODEL_HEX] [--timeout-ms 100..10000]\nEffects: exclusive HID open, INIT channel allocation and GetInfo only. No credential, assertion or PIN commands. USB-instance/capability observation only; not custody authentication.");
                return Ok(());
            }
            _ => fail!(EINVAL,"FIDO_DIAGNOSTIC_ARGUMENT"),
        }
    }
    if cfg!(feature="simulation") || cfg!(feature="ctap-emulator") {
        fail!(EPERM,"FIDO_DIAGNOSTIC_SIMULATION_BUILD");
    }
    native_probe(expected.as_ref(), timeout_ms)
}

#[cfg(all(target_os="macos",feature="macos-hid"))]
fn native_probe(expected:Option<&[u8;16]>, timeout_ms:u64)->EnclaveResult<()> {
    use enclave_custody_vaultd::ctap::{diagnostic,macos_hid::MacHidDevice};
    let mut devices = MacHidDevice::enumerate()?;
    for device in &mut devices { device.timeout_s=(timeout_ms as f64 / 1000.0).min(1.0); }
    let observation=diagnostic::observe(devices,expected,std::time::Duration::from_millis(timeout_ms))?;
    println!("{}",serde_json::json!({
        "schema":"depot.fido.diagnostic.v1","status":"PASS","mode":"NATIVE_USER",
        "effect":"INIT_GETINFO_ONLY","scope":"USB-instance capability observation; not enrolled-key authentication",
        "model_aaguid":hex::encode(observation.info.aaguid),"firmware":observation.info.firmware_version,
        "versions":observation.info.versions,"extensions":observation.info.extensions,
        "pin_uv_protocols":observation.info.pin_uv_protocols,"built_in_uv":observation.info.built_in_uv,
        "algorithms":observation.info.algorithms,"hub_depth_observation":observation.hub_depth,
        "seize_requested":true,"timeout_ms":timeout_ms,
        "limits":"Underlying IOKit synchronous open/write require outer runner lifetime bound; no physical timing qualification"
    }));
    Ok(())
}

#[cfg(not(all(target_os="macos",feature="macos-hid")))]
fn native_probe(_expected:Option<&[u8;16]>,_timeout_ms:u64)->EnclaveResult<()> {
    fail!(EPERM,"HID_TRANSPORT_NOT_COMPILED","requires macOS --no-default-features --features macos-hid")
}

fn main(){if let Err(error)=run(){eprintln!("{}",serde_json::json!({"schema":"depot.fido.diagnostic.v1","status":"FAIL","error_code":error.reason,"error":error.to_string()}));std::process::exit(1);}}
