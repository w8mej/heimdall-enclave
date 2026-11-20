//! First-setup disclosure uses real safe CLI paths; no host installation or enrollment.
use std::process::Command;

const NOTICE: &str = depot_enclave::custody_notice::L3_ATTESTATION_NOTICE;

#[test]
fn l3_setup_disclosure_keeps_json_stdout_parseable() {
    for profile in ["L1", "L2", "L3"] {
        let output = Command::new(env!("CARGO_BIN_EXE_depot-enclave"))
            .args(["--profile", profile, "--json", "deploy", "install", "--dry-run"])
            .output()
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(body["profile"], profile);
        let diagnostic = String::from_utf8(output.stderr).unwrap();
        if profile == "L3" {
            assert!(diagnostic.contains(NOTICE), "missing L3 disclosure: {diagnostic}");
            assert_eq!(diagnostic.matches("L3_ATTESTATION_RISK").count(), 1);
        } else {
            assert!(!diagnostic.contains("L3_ATTESTATION_RISK"));
        }
    }
}

#[test]
fn setup_notice_installer_literal_matches_shared_source() {
    // Embedded installers cannot depend on a mutable adjacent notice file.
    let installer = include_str!("../../../packaging/macos/install.sh");
    let start = "  cat >&2 <<'depot_L3_ATTESTATION_NOTICE'\n";
    let literal = installer.split_once(start).unwrap().1
        .split_once("depot_L3_ATTESTATION_NOTICE\n").unwrap().0;
    assert_eq!(literal, NOTICE);
    assert!(installer.find(start).unwrap() < installer.find("[ \"$(uname -s)\" = Darwin ]").unwrap());
}

#[test]
fn disclosure_output_and_failure_are_bounded() {
    let mut out = Vec::new();
    for profile in ["L1", "L2", "invalid"] {
        depot_enclave::custody_notice::write_for_profile(profile, &mut out).unwrap();
    }
    assert!(out.is_empty());
    depot_enclave::custody_notice::write_for_profile("l3", &mut out).unwrap();
    assert_eq!(out, NOTICE.as_bytes());
    struct Broken;
    impl std::io::Write for Broken {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::new(std::io::ErrorKind::BrokenPipe, "closed diagnostic"))
        }
        fn flush(&mut self) -> std::io::Result<()> { Ok(()) }
    }
    assert!(depot_enclave::custody_notice::write_for_profile("L3", &mut Broken).is_err());
}
