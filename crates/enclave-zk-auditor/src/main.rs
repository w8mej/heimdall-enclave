//! `enclave-zk-auditor` — UID 705 `_enclavezk` LaunchDaemon entry point.

#[global_allocator]
static HEAP: enclave_zk_auditor::heap::WipingAllocator =
    enclave_zk_auditor::heap::WipingAllocator(std::alloc::System);

fn main() {
    if let Err(e) =
        enclave_core::runtime::DaemonArgs::from_env().and_then(enclave_zk_auditor::entry::run)
    {
        enclave_core::runtime::exit_with(&e);
    }
}
