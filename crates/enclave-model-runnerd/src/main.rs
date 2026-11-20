//! `enclave-model-runnerd` — UID 701 `_llmagent` LaunchDaemon entry point.

fn main() {
    if let Err(e) =
        enclave_core::runtime::DaemonArgs::from_env().and_then(enclave_model_runnerd::entry::run)
    {
        enclave_core::runtime::exit_with(&e);
    }
}
