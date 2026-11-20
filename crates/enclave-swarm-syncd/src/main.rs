//! `enclave-swarm-syncd` — UID 702 `_enclavecas` LaunchDaemon entry point.

fn main() {
    if let Err(e) =
        enclave_core::runtime::DaemonArgs::from_env().and_then(enclave_swarm_syncd::entry::run)
    {
        enclave_core::runtime::exit_with(&e);
    }
}
