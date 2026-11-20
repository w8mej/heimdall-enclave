use enclave_custody_vaultd::service::{VaultConfig, VaultHardware, VaultService};

#[test]
fn test_vault_root_key_slab_guard_page() {
    let hw = VaultHardware::simulated(enclave_core::Profile::L2, 1_700_000_000).unwrap();
    let cfg = VaultConfig::default();
    let svc = VaultService::start(cfg, hw).unwrap();
    let (key_addr, past_end) = svc.tombstone_root_key_range().unwrap();
    assert_eq!(past_end, key_addr + 32);

    if std::env::var_os("ENCLAVE_GUARD_CHILD_VAULT").is_some() {
        let p = past_end as *const u8;
        // SAFETY: reading one past end on the guard page traps.
        let v = unsafe { std::ptr::read_volatile(p) };
        println!("UNREACHABLE {v}");
        std::process::exit(0);
    }
    let out = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "test_vault_root_key_slab_guard_page",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("ENCLAVE_GUARD_CHILD_VAULT", "1")
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
