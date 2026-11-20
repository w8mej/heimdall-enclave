//! Post-installation verification and socket health probes (FS-706 §1.2, D-R1).

use super::scripts::{run_script, DeployCtx, Script};
use serde_json::json;
use std::path::Path;

/// Execute post-installation verification checks on the real host.
pub fn run_verify(profile: &str) -> (i32, String, serde_json::Value) {
    run_verify_with(profile, &DeployCtx::system())
}

/// [`run_verify`] against an explicit host context.
///
/// DEFECT-F-90: as root, runs the verify-install script embedded in this
/// binary ([`Script::VerifyInstall`]), never `packaging/macos/verify-install.sh`
/// from the current directory.
pub fn run_verify_with(profile: &str, ctx: &DeployCtx<'_>) -> (i32, String, serde_json::Value) {
    let env = crate::ctl::Env::production(
        enclave_core::profile::Profile::parse(profile)
            .unwrap_or(enclave_core::profile::Profile::L3),
    );
    evaluate(
        profile,
        ctx,
        |path| Path::new(path).exists(),
        |d| crate::ctl::status_of(&env, d),
    )
}

fn evaluate(
    profile: &str,
    ctx: &DeployCtx<'_>,
    exists: impl Fn(&str) -> bool,
    status: impl Fn(
        enclave_core::daemon::DaemonId,
    ) -> enclave_core::error::EnclaveResult<enclave_core::ipc::DaemonStatus>,
) -> (i32, String, serde_json::Value) {
    let mut checks = Vec::new();
    let valid_profile = enclave_core::profile::Profile::parse(profile).is_ok();
    checks.push(
        json!({"check":"profile", "required":true, "passed":valid_profile,
        "status":if valid_profile {"pass"} else {"fail"}}),
    );
    let mut paths = vec![
        (
            "binary_depot-enclave".to_owned(),
            "/opt/enterprise/enclave/bin/depot-enclave".to_owned(),
        ),
        (
            "binary_enclave-model-runnerd".into(),
            "/opt/enterprise/enclave/bin/enclave-model-runnerd".into(),
        ),
        (
            "binary_enclave-swarm-syncd".into(),
            "/opt/enterprise/enclave/bin/enclave-swarm-syncd".into(),
        ),
        (
            "custody_app_bundle".into(),
            "/Library/Application Support/EnterpriseEnclave/EnclaveCustody.app".into(),
        ),
    ];
    for name in ["supervisor", "cas"] {
        paths.push((
            format!("socket_{name}"),
            format!("/var/run/enclave/{name}/{name}.sock"),
        ));
    }
    if profile == "L3" {
        for (name, path) in [
            (
                "broker_binary",
                "/opt/enterprise/enclave/bin/enclave-apfs-broker",
            ),
            ("broker_socket", "/var/run/enclave/apfs-broker/broker.sock"),
            (
                "broker_protected_repo",
                "/var/db/enclave/apfs-broker/tuf/repo",
            ),
        ] {
            paths.push((name.into(), path.into()));
        }
    }
    for (name, path) in paths {
        let passed = exists(&path);
        checks.push(
            json!({"check":name,"required":true,"status":if passed {"pass"} else {"fail"},
            "passed":passed,"path":path,"evidence":"layout existence only"}),
        );
    }
    for d in enclave_core::daemon::DaemonId::ALL {
        let observation = status(d);
        let passed = observation.as_ref().is_ok_and(|s| {
            s.daemon_uid == d.uid()
                && s.state
                    .split_whitespace()
                    .any(|token| token == format!("profile={profile}"))
                && (profile != "L3"
                    || d != enclave_core::daemon::DaemonId::SwarmSync
                    || s.state
                        .split_whitespace()
                        .any(|token| token == "apfs_broker_ready=true"))
        });
        checks.push(json!({"check":format!("authenticated_status_{}",d.uid()),"required":true,
            "passed":passed,"status":if passed {"pass"} else {"fail"},
            "evidence":"authenticated pinned daemon Status; identity/profile and L3 CAS broker readiness",
            "error":observation.err().map(|e|e.to_string())}));
    }
    if ctx.is_root {
        match run_script(
            ctx,
            Script::VerifyInstall,
            &[],
            &[("depot_PROFILE", profile)],
        ) {
            Ok(result) => checks.push(json!({"check":"verify_install_script","required":true,
                "status":if result.success() {"pass"} else {"fail"},"passed":result.success(),
                "script":Script::VerifyInstall.argv0(),"exit_code":result.code()})),
            Err(error) => checks.push(json!({"check":"verify_install_script","required":true,
                "status":"blocked","passed":false,"error":error.to_string()})),
        }
    } else {
        checks.push(json!({"check":"verify_install_script","required":true,"status":"skipped",
            "passed":false,"skipped":"not root","reason":"required privileged security exit criteria unavailable"}));
    }
    let failed = checks
        .iter()
        .any(|c| c["required"] == true && c["status"] == "fail");
    let incomplete = checks
        .iter()
        .any(|c| c["required"] == true && (c["status"] == "skipped" || c["status"] == "blocked"));
    let state = if failed {
        "failed"
    } else if incomplete {
        "incomplete"
    } else {
        "ok"
    };
    let code = if state == "ok" {
        0
    } else {
        super::EXIT_VERIFY_FAILED
    };
    let summary = match state {
        "ok" => "All required installation, authenticated readiness and security checks passed",
        "incomplete" => "Required deployment verification checks could not run",
        _ => "One or more required deployment verification checks failed",
    };
    (
        code,
        summary.into(),
        json!({"status":state,"exit_code":code,"complete":!incomplete,"checks":checks}),
    )
}

#[cfg(test)]
mod phase2_tests {
    use super::*;
    use crate::syscmd::Runner;
    use std::{
        io,
        os::unix::process::ExitStatusExt,
        process::{Command, ExitStatus, Output},
    };
    struct Recorder(Option<i32>);
    impl Runner for Recorder {
        fn status(&self, _: Command) -> io::Result<ExitStatus> {
            self.0
                .map(|c| ExitStatus::from_raw(c << 8))
                .ok_or_else(|| io::Error::other("fixture spawn failure"))
        }
        fn output(&self, command: Command) -> io::Result<Output> {
            Ok(Output { status: self.status(command)?, stdout: Vec::new(), stderr: Vec::new() })
        }
    }
    fn run(
        root: bool,
        script: Option<i32>,
        paths: bool,
        bad_uid: bool,
    ) -> (i32, String, serde_json::Value) {
        let recorder = Recorder(script);
        let ctx = DeployCtx {
            is_root: root,
            runner: &recorder,
            anchors_dir: "unused".into(),
            pf_conf: "unused".into(),
        };
        evaluate(
            "L3",
            &ctx,
            |_| paths,
            |d| {
                Ok(enclave_core::ipc::DaemonStatus {
                    daemon_uid: if bad_uid { 0 } else { d.uid() },
                    binary: d.binary().into(),
                    pid: 123,
                    rss_bytes: 1,
                    rss_ceiling_bytes: 1,
                    boot_epoch_id: String::new(),
                    rpc_seq_u64: 0,
                    state: "profile=L3 apfs_broker_ready=true".into(),
                    phys_footprint_bytes: 0,
                    phys_footprint_source: Default::default(),
                })
            },
        )
    }
    #[test]
    fn all_present_nonroot_is_incomplete_and_root_fixture_can_pass() {
        let (code, summary, body) = run(false, Some(0), true, false);
        assert_eq!(code, 30);
        assert_eq!(body["status"], "incomplete");
        assert!(!summary.contains("All required"));
        assert_eq!(
            body["checks"].as_array().unwrap().last().unwrap()["status"],
            "skipped"
        );
        assert_eq!(run(true, Some(0), true, false).0, 0);
    }
    #[test]
    fn required_failure_blocked_script_and_wrong_identity_cannot_pass() {
        for body in [
            run(true, Some(1), true, false),
            run(true, Some(0), false, false),
            run(true, Some(0), true, true),
        ] {
            assert_eq!(body.0, 30);
            assert_eq!(body.2["status"], "failed");
        }
        let body = run(true, None, true, false);
        assert_eq!(body.0, 30);
        assert_eq!(body.2["status"], "incomplete");
    }
}
