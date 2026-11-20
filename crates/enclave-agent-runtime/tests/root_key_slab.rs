use ed25519_dalek::SigningKey;
use enclave_agent_runtime::registry::ToolRegistry;
use enclave_agent_runtime::service::{Declassifier, IfcConfig, IfcService, NoCustody};
use enclave_core::error::EnclaveResult;
use enclave_core::Profile;
use enclave_crypto::biscuit_auth::AuthorizerLimits;

#[derive(Debug)]
struct Fixed;
impl Declassifier for Fixed {
    fn classify(
        &self,
        _p: &[u8],
        _k: u64,
        _s: &str,
        _slot: &enclave_core::seq::GovernedSlot,
    ) -> EnclaveResult<u64> {
        Ok(0)
    }
}

#[test]
fn test_agent_runtime_root_keys_slab_guard_page() {
    let cfg = IfcConfig {
        profile: Profile::L2,
        audit_path: None,
        policy_key: SigningKey::generate(&mut rand_core::OsRng),
        limits: AuthorizerLimits::default(),
        registry: ToolRegistry::empty(),
        cedar: None,
        state_dir: None,
        socket_dir: None,
        dev_same_uid: true,
    };
    let svc = IfcService::start(cfg, Box::new(Fixed), Box::new(NoCustody)).unwrap();
    let ranges = svc.root_key_ranges().unwrap();
    assert_eq!(ranges.len(), 2);
    for (key_addr, past_end) in &ranges {
        assert_eq!(*past_end, *key_addr + 32);
    }

    if std::env::var_os("ENCLAVE_GUARD_CHILD_RUNTIME").is_some() {
        let p = ranges[0].1 as *const u8;
        // SAFETY: reading one past end on the guard page traps.
        let v = unsafe { std::ptr::read_volatile(p) };
        println!("UNREACHABLE {v}");
        std::process::exit(0);
    }
    let out = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "test_agent_runtime_root_keys_slab_guard_page",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("ENCLAVE_GUARD_CHILD_RUNTIME", "1")
        .output()
        .unwrap();
    use std::os::unix::process::ExitStatusExt;
    let sig = out.status.signal();
    assert!(
        matches!(sig, Some(libc::SIGSEGV) | Some(libc::SIGBUS)),
        "child status {:?} stdout {}",
        out.status,
        String::from_utf8_lossy(&out.stdout)
    );
}
