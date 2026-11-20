//! Integration and unit tests for mcp-enclave deploy (FS-706, D-R1, Prompt 2).

use mcp_enclave::deploy::{
    classify_hw_tier, evaluate_preflight, execute, DeployArgs, DeployVerb, EXIT_PREFLIGHT_FAILED,
    EXIT_PURGE_REFUSED, EXIT_SUCCESS, EXIT_USAGE_ERROR,
};

#[test]
fn phase2_actual_cli_verify_never_hides_required_skip() {
    // Native acceptance here is non-root only: never execute the installed
    // privileged security script as part of this bounded test selection.
    assert!(!cfg!(target_os = "macos") || unsafe { libc::geteuid() } != 0);
    for profile in ["L1", "L2", "L3"] {
        let out = std::process::Command::new(env!("CARGO_BIN_EXE_mcp-enclave"))
            .args(["deploy", "verify", "--profile", profile, "--json"]).output().unwrap();
        let body: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        assert_eq!(out.status.code(), Some(30), "{body}");
        assert_eq!(body["exit_code"], 30);
        assert_eq!(body["status"], body["details"]["status"]);
        assert!(matches!(body["status"].as_str(), Some("failed" | "incomplete")));
        let checks = body["details"]["checks"].as_array().unwrap();
        assert!(checks.iter().all(|c| c["required"].is_boolean() && c["status"].is_string() && c["passed"].is_boolean()));
        if unsafe { libc::geteuid() } != 0 {
            assert!(checks.iter().any(|c| c["check"] == "verify_install_script" && c["status"] == "skipped" && c["passed"] == false));
        }
    }
}

#[test]
fn phase2_actual_measure_exit_matches_physical_compliance() {
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_mcp-enclave"))
        .args(["measure", "--json"]).output().unwrap();
    let body: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let compliant = body["budget"]["compliant"].as_bool().unwrap();
    assert_eq!(out.status.code(), Some(if compliant {0} else {50}), "{body}");
    assert_eq!(body["physical_memory"]["compliant"], compliant);
    if body["physical_memory"]["unknown_required"] == true {
        assert!(!compliant); assert!(body["daemons"].as_array().unwrap().iter().any(|d|d["footprint_known"]==false));
    }
}

#[test]
fn test_preflight_on_host() {
    std::env::set_var("ENCLAVE_MODEL_FOOTPRINT_BYTES", "104857600");
    let result = evaluate_preflight("L1", None);
    println!("Host preflight: {:?}", result);
    // On this Apple Silicon Mac, preflight must pass and detect valid hardware
    assert!(result.passed, "Preflight failed: {}", result.message);
    assert!(result.preflight.mem_bytes > 0);
    assert!(matches!(
        result.preflight.hw_tier.as_str(),
        "Low" | "Mid" | "High"
    ));
    assert!(result.preflight.disk_free_bytes > 0);
}

#[test]
fn test_hardware_tier_classification() {
    // 8 GiB
    assert_eq!(classify_hw_tier(8 * 1024 * 1024 * 1024), "Low");
    // 15.9 GiB
    assert_eq!(classify_hw_tier(16 * 1024 * 1024 * 1024 - 1), "Low");
    // 16 GiB
    assert_eq!(classify_hw_tier(16 * 1024 * 1024 * 1024), "Mid");
    // 32 GiB
    assert_eq!(classify_hw_tier(32 * 1024 * 1024 * 1024), "Mid");
    // 48 GiB (D-R13 edge case: 48-64 GiB is classified Mid)
    assert_eq!(classify_hw_tier(48 * 1024 * 1024 * 1024), "Mid");
    assert_eq!(classify_hw_tier(60 * 1024 * 1024 * 1024), "Mid");
    // 64 GiB
    assert_eq!(classify_hw_tier(64 * 1024 * 1024 * 1024), "High");
    // 128 GiB
    assert_eq!(classify_hw_tier(128 * 1024 * 1024 * 1024), "High");
}

#[test]
fn test_deploy_exit_codes_and_validation() {
    std::env::set_var("ENCLAVE_MODEL_FOOTPRINT_BYTES", "104857600");
    let args = DeployArgs::default();

    // Unknown profile returns 64 (EXIT_USAGE_ERROR)
    let (res_invalid, code_invalid) = execute(DeployVerb::Preflight, "L99", &args);
    assert_eq!(code_invalid, EXIT_USAGE_ERROR);
    assert_eq!(res_invalid.exit_code, EXIT_USAGE_ERROR);
    assert_eq!(res_invalid.status, "usage_error");

    // Valid preflight returns 0 (EXIT_SUCCESS)
    let (res_ok, code_ok) = execute(DeployVerb::Preflight, "L1", &args);
    assert_eq!(code_ok, EXIT_SUCCESS);
    assert_eq!(res_ok.exit_code, EXIT_SUCCESS);
    assert_eq!(res_ok.status, "ok");
    assert!(res_ok.darwin_preflight.is_some());

    // Purge without --yes returns 60 (EXIT_PURGE_REFUSED)
    let (res_purge, code_purge) = execute(DeployVerb::Purge, "L1", &args);
    assert_eq!(code_purge, EXIT_PURGE_REFUSED);
    assert_eq!(res_purge.exit_code, EXIT_PURGE_REFUSED);
    assert_eq!(res_purge.status, "refused");

    // Dry-run install returns 0
    let dry_args = DeployArgs {
        dry_run: true,
        ..Default::default()
    };
    let (res_install, code_install) = execute(DeployVerb::Install, "L1", &dry_args);
    assert_eq!(code_install, EXIT_SUCCESS);
    assert_eq!(res_install.status, "ok");

    // Simulated failed preflight (impossible disk requirement)
    let pf_fail = evaluate_preflight("L1", Some(u64::MAX / 4));
    assert!(!pf_fail.passed);
    assert_eq!(
        if pf_fail.passed {
            EXIT_SUCCESS
        } else {
            EXIT_PREFLIGHT_FAILED
        },
        EXIT_PREFLIGHT_FAILED
    );
}

#[test]
fn test_deploy_json_schema_compliance() {
    std::env::set_var("ENCLAVE_MODEL_FOOTPRINT_BYTES", "104857600");
    let args = DeployArgs::default();
    let (res, _) = execute(DeployVerb::Preflight, "L1", &args);
    let serialized = serde_json::to_string_pretty(&res).expect("serialization failed");

    // Parse with serde_json
    let val: serde_json::Value = serde_json::from_str(&serialized).expect("deserialization failed");
    assert_eq!(val["verb"], "preflight");
    assert_eq!(val["profile"], "L1");
    assert_eq!(val["exit_code"], 0);
    assert_eq!(val["status"], "ok");
    assert!(val["darwin_preflight"]["mem_bytes"].as_u64().unwrap() > 0);
}

#[test]
fn test_makefile_dry_run_expansion() {
    let repo_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let status = std::process::Command::new("make")
        .arg("-C")
        .arg(&repo_root)
        .args([
            "-n",
            "deploy-L1",
            "deploy-L2",
            "deploy-L3",
            "preflight",
            "verify",
            "clean-deployment",
        ])
        .status();
    match status {
        Ok(s) => assert!(s.success(), "make -n failed: {s}"),
        Err(e) => panic!("make could not be spawned: {e}"),
    }
}

#[test]
fn test_healthcheck_telemetry_outbox_and_pf() {
    let (_, _, details) = mcp_enclave::deploy::health::run_healthcheck("L1");

    // Verify outbox telemetry
    let outbox = details.get("outbox").expect("outbox telemetry missing");
    assert!(outbox["path"].is_null(), "health must not export or scan a guessed queue path");
    assert!(outbox["known"].is_boolean());
    assert_eq!(outbox["cap_mib"], 100.0);
    if outbox["known"].as_bool().unwrap() {
        for field in ["queued_frames", "dead_frames", "disk_bytes"] {
            assert!(outbox[field].is_u64(), "known aggregate field {field}");
        }
        assert!(outbox["budget_exceeded"].is_boolean());
    } else {
        for field in ["queued_frames", "dead_frames", "disk_bytes", "budget_exceeded"] {
            assert!(outbox[field].is_null(), "unknown aggregate must not become zero: {field}");
        }
        assert_ne!(details["overall_status"], "healthy", "unknown queue cannot establish health");
    }

    // Verify quarantine telemetry
    let quarantine = details
        .get("quarantine")
        .expect("quarantine telemetry missing");
    assert!(quarantine.get("latched").is_some());
    assert_eq!(quarantine["source"], "authenticated UID 705 Status");
    assert!(quarantine["known"].is_boolean());
    assert!(quarantine.get("marker_path").is_none(), "mutable marker must not establish health");
    if !quarantine["known"].as_bool().unwrap() {
        assert_ne!(details["overall_status"], "healthy", "unknown quarantine cannot establish health");
    }

    // Verify pf dual-anchor telemetry
    let pf = details.get("pf").expect("pf telemetry missing");
    assert!(pf.get("llm_rules_count").is_some());
    assert!(pf.get("cas_rules_count").is_some());
    assert!(pf.get("total_rules").is_some());
    assert!(pf.get("isolated").is_some());
}

/// Read the actual production CLI without creating a socket, starting/stopping a
/// service, changing PF, or installing anything. Historical never-installed state
/// cannot be inferred from current path absence; record the observed case only.
#[test]
fn f112_observed_cli_rejects_absent_or_stopped_installation() {
    use std::path::Path;
    let names = ["supervisor", "adapter", "cas", "custody", "ifc", "zk"];
    let observed_sockets: Vec<_> = names.iter().map(|name| {
        let path = format!("/var/run/enclave/{name}/{name}.sock");
        let absent = std::fs::symlink_metadata(&path)
            .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound);
        (path, absent)
    }).collect();
    let absent_required = observed_sockets.iter().filter(|(_, absent)| *absent).count();
    let installation_paths_absent = ["/opt/enterprise/enclave", "/var/run/enclave"].iter()
        .all(|path| std::fs::symlink_metadata(path).is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound));
    for profile in ["L1", "L2", "L3"] {
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_mcp-enclave"))
            .args(["--profile", profile, "deploy", "healthcheck", "--json"])
            .output().expect("execute actual read-only CLI");
        let body: serde_json::Value = serde_json::from_slice(&output.stdout)
            .unwrap_or_else(|error| panic!("invalid actual health JSON: {error}; {output:?}"));
        println!("F112_NATIVE_OBSERVATION {}", serde_json::json!({
            "profile": profile, "platform": std::env::consts::OS,
            "observed_case": if installation_paths_absent { "installation-paths-absent" } else { "required-sockets-absent-or-unavailable" },
            "required_sockets_absent_before": absent_required,
            "observed_socket_paths": observed_sockets,
            "actual_cli_exit": output.status.code(),
            "actual_health_result": body,
            "host_mutation": false,
        }));
        if absent_required == 0 {
            println!("SKIPPED: host has no definitely absent required socket; absent/stopped scenario was not established and no service will be changed");
            return;
        }
        assert_eq!(output.status.code(), Some(mcp_enclave::deploy::EXIT_UNHEALTHY), "{output:?}");
        assert_eq!(body["exit_code"], 50);
        assert_eq!(body["status"], "unhealthy");
        assert_eq!(body["profile"], profile);
        let details = &body["details"];
        assert_ne!(details["overall_status"], "healthy");
        let required: Vec<_> = details["daemons"].as_array().unwrap().iter()
            .filter(|daemon| daemon["optional"] == false).collect();
        assert_eq!(required.len(), if profile == "L3" {7} else {6});
        assert!(required.iter().any(|daemon| daemon["socket_present"] == false));
        for daemon in required {
            let path = daemon["socket"].as_str().unwrap();
            assert_eq!(daemon["socket_present"], Path::new(path).exists(), "reported presence must match read-only path observation");
        }
        let quarantine = &details["quarantine"];
        assert_eq!(quarantine["source"], "authenticated UID 705 Status");
        assert!(quarantine["known"].is_boolean());
        assert!(quarantine.get("marker_path").is_none());
        if observed_sockets.iter().any(|(path, absent)| path.ends_with("/zk/zk.sock") && *absent) {
            assert_eq!(quarantine["known"], false, "an absent auditor cannot report known healthy quarantine state");
        }
    }
}
