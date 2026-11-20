//! `enclave-custody-vaultd` — UID 703 `_piivault` LaunchDaemon entry point.

fn main() {
    if let Err(e) =
        enclave_core::runtime::DaemonArgs::from_env().and_then(enclave_custody_vaultd::entry::run)
    {
        enclave_core::runtime::exit_with(&e);
    }
}
