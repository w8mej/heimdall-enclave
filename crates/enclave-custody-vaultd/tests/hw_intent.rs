//! Native GUI/SEP behavior with a commit-local, separately compiled test helper.
//! Run `python3 scripts/native-macos-check.py intent` from a Mac GUI session.
//! The test transport deliberately excludes production peer-code authentication;
//! signed daemon ingress must be validated separately in the deployment lane.

#[cfg(target_os = "macos")]
#[test]
fn hw_intent_biometric_outcomes_approval_occlusion_and_cancel() {
    use enclave_custody_vaultd::biometric::{
        verify_approval, BiometricOutcome, BiometricPrompt, BiometricProvider, HelperBridge,
    };
    use p256::ecdsa::{SigningKey, VerifyingKey};
    use sha2::{Digest, Sha256};
    use std::os::unix::net::UnixStream;
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command};
    use std::time::Duration;

    if std::env::var("MCPMAC_HW").as_deref() != Ok("1") {
        eprintln!("hw_intent: skipped (set MCPMAC_HW=1 in a macOS Aqua session)");
        return;
    }
    assert_eq!(
        std::env::var("MCPMAC_INTENT_NATIVE_TEST").as_deref(),
        Ok("1"),
        "use scripts/native-macos-check.py intent to build the test-only helper"
    );
    let helper = PathBuf::from(
        std::env::var_os("MCPMAC_INTENT_HELPER")
            .expect("missing explicit helper path; use scripts/native-macos-check.py intent"),
    )
    .canonicalize()
    .expect("helper path is unavailable");
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap();
    let build_root = root.join(".native-macos/intent").canonicalize().unwrap();
    assert!(
        helper.starts_with(build_root),
        "helper must belong to this checkout's native-test build"
    );
    let expected = std::env::var("MCPMAC_INTENT_HELPER_SHA256").expect("missing helper hash");
    assert_eq!(
        format!("{:x}", Sha256::digest(std::fs::read(&helper).unwrap())),
        expected,
        "helper changed after the driver recorded its identity"
    );

    // Do not format BiometricOutcome with Debug: approval includes a wrapped key blob.
    fn outcome_name(outcome: &BiometricOutcome) -> &'static str {
        match outcome {
            BiometricOutcome::Approved { .. } => "Approved",
            BiometricOutcome::Cancelled => "Cancelled",
            BiometricOutcome::TimedOut => "TimedOut",
            BiometricOutcome::Occluded => "Occluded",
            BiometricOutcome::ReportSuspicious => "ReportSuspicious",
        }
    }
    struct HelperGuard {
        child: Child,
        sock: PathBuf,
    }
    impl Drop for HelperGuard {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
            let _ = std::fs::remove_file(&self.sock);
        }
    }
    fn spawn_helper(helper: &Path, occlusion: bool) -> (HelperGuard, HelperBridge<UnixStream>) {
        let sock = std::env::temp_dir().join(format!(
            "enclave-intent-hw-{}.sock",
            enclave_core::rng::u64()
        ));
        let mut command = Command::new(helper);
        command
            .arg("--native-test")
            .arg("--socket")
            .arg(&sock)
            .arg("--idle-exit");
        if occlusion {
            command.arg("--test-occlusion");
        }
        let child = command.spawn().expect("failed to spawn selected helper");
        let guard = HelperGuard { child, sock };
        for _ in 0..100 {
            if guard.sock.exists() {
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        assert!(guard.sock.exists(), "helper socket failed to appear");
        // Test-only same-user socket. Production connect_helper and its root-owned
        // signing pins are intentionally unchanged, and are not claimed as covered.
        let stream =
            UnixStream::connect(&guard.sock).expect("native-test socket connection failed");
        stream
            .set_read_timeout(Some(Duration::from_secs(60)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        (guard, HelperBridge::new(stream))
    }
    fn prompt(reason: &str, byte: u8) -> BiometricPrompt {
        BiometricPrompt {
            localized_reason: reason.into(),
            d_jcs: vec![byte; 32],
            nonce: vec![byte + 1; 32],
            t_start_ns: enclave_core::clock::boot_clock_ns(),
            bio_key_blob: Vec::new(),
        }
    }
    {
        println!("hw_intent: automatic occlusion check; no human action needed");
        let (_guard, mut bridge) = spawn_helper(&helper, true);
        let outcome = bridge.evaluate(&prompt("Automatic Occlusion Check", 0x11));
        assert!(
            matches!(outcome, BiometricOutcome::Occluded),
            "expected Occluded, got {}",
            outcome_name(&outcome)
        );
        println!("hw_intent: occlusion PASSED");
    }
    {
        println!("hw_intent: HUMAN STEP 1 OF 2: CLICK CANCEL. Do not use Touch ID.");
        let (_guard, mut bridge) = spawn_helper(&helper, false);
        let outcome = bridge.evaluate(&prompt(
            "STEP 1 OF 2: CLICK CANCEL (do not use Touch ID)",
            0x33,
        ));
        assert!(
            matches!(outcome, BiometricOutcome::Cancelled),
            "expected Cancelled, got {}",
            outcome_name(&outcome)
        );
        println!("hw_intent: cancellation PASSED");
    }
    {
        println!("hw_intent: HUMAN STEP 2 OF 2: USE TOUCH ID. Do not click Cancel.");
        let (_guard, mut bridge) = spawn_helper(&helper, false);
        let approved_prompt = prompt("STEP 2 OF 2: USE TOUCH ID (do not click Cancel)", 0x55);
        let outcome = bridge.evaluate(&approved_prompt);
        let (public, blob) = match &outcome {
            BiometricOutcome::Approved {
                enrolled_pubkey: Some(public),
                enrolled_blob: Some(blob),
                ..
            } => (public, blob),
            other => panic!("expected enrolled approval, got {}", outcome_name(other)),
        };
        assert!(
            !blob.is_empty(),
            "native enrollment must return a wrapped SEP key"
        );
        let key = VerifyingKey::from_sec1_bytes(public).expect("invalid enrolled P-256 public key");
        let signature = verify_approval(&key, &approved_prompt, &outcome)
            .expect("approval signature or dwell verification failed");
        let mut altered = approved_prompt.clone();
        altered.d_jcs[0] ^= 1;
        assert!(verify_approval(&key, &altered, &outcome)
            .unwrap_err()
            .is("SEP_SIGNATURE_INVALID"));
        altered = approved_prompt.clone();
        altered.nonce[0] ^= 1;
        assert!(verify_approval(&key, &altered, &outcome)
            .unwrap_err()
            .is("SEP_SIGNATURE_INVALID"));
        let wrong = SigningKey::random(&mut rand_core::OsRng);
        assert!(
            verify_approval(wrong.verifying_key(), &approved_prompt, &outcome)
                .unwrap_err()
                .is("SEP_SIGNATURE_INVALID")
        );
        println!("hw_intent: approval PASSED; verified {} signature bytes; altered message, nonce and wrong key rejected", signature.len());
    }
}
