//! `enclave-agent-runtime` — UID 704 `_enclaveifc` LaunchDaemon entry point.

fn main() {
    if let Err(e) =
        enclave_core::runtime::DaemonArgs::from_env().and_then(enclave_agent_runtime::entry::run)
    {
        enclave_core::runtime::exit_with(&e);
    }
}
