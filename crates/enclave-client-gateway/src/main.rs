//! Dedicated authenticated client ingress executable (F97).
fn main() {
    if let Err(error) = enclave_core::runtime::DaemonArgs::from_env()
        .and_then(enclave_client_gateway::entry::run) {
        enclave_core::runtime::exit_with(&error);
    }
}
