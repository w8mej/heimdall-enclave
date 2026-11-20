//! Integration tests for Phase 4 fleet adapters (Munki, Ansible, Fleet, Jamf, Lightweight MDM)
//! Validates manifest syntax, plist structures, schema adherence, and script behavior with PATH shims.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

static COUNTER: AtomicUsize = AtomicUsize::new(1);

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

#[test]
fn test_munki_pkginfo_plists() {
    let repo = repo_root();
    let core_pkginfo = repo.join("adapters/munki/enclave-core.pkginfo");
    let model_pkginfo = repo.join("adapters/munki/enclave-model-weights.pkginfo");

    assert!(core_pkginfo.exists(), "core.pkginfo missing");
    assert!(model_pkginfo.exists(), "model-weights.pkginfo missing");

    let core_content = fs::read_to_string(&core_pkginfo).unwrap();
    let model_content = fs::read_to_string(&model_pkginfo).unwrap();

    assert!(core_content.contains("<key>name</key>"));
    assert!(core_content.contains("com.enterprise.enclave.core"));
    assert!(core_content.contains("<key>installer_type</key>\n\t<string>apple_pkg</string>"));
    assert!(!core_content.contains("<key>postinstall_script</key>"), "native package must run its own canonical postinstall");
    assert!(!core_content.contains("/tmp/"), "no user-writable root executable staging");
    let postinstall = fs::read_to_string(repo.join("packaging/pkg/scripts/postinstall")).unwrap();
    assert!(postinstall.contains("deploy install"));
    assert!(postinstall.contains("deploy verify"));
    assert!(core_content.contains("mcp-enclave deploy purge"));

    assert!(model_content.contains("<key>name</key>"));
    assert!(model_content.contains("com.enterprise.enclave.model.llada8b"));
    assert!(model_content.contains("<string>com.enterprise.enclave.core</string>"));
    assert!(model_content.contains("mcp-enclave deploy hydrate"));
}

#[test]
fn test_mobileconfig_plist_structure() {
    let repo = repo_root();
    let mobileconfig = repo.join("adapters/lightweight-mdm/MCPMac-Enclave.mobileconfig");
    assert!(mobileconfig.exists(), "MCPMac-Enclave.mobileconfig missing");

    let content = fs::read_to_string(&mobileconfig).unwrap();
    assert!(content.contains("com.apple.servicemanagement"));
    assert!(content.contains("com.apple.notificationsettings"));
    assert!(content.contains("com.enterprise.enclave."));
    assert!(content.contains("com.enterprise.enclave.intent"));
}

#[test]
fn test_fleet_gitops_and_queries() {
    let repo = repo_root();
    let installer_yaml = repo.join("adapters/fleet/fleet-enclave-installer.yml");
    assert!(installer_yaml.exists(), "fleet installer missing");

    let yaml_content = fs::read_to_string(&installer_yaml).unwrap();
    assert!(yaml_content.contains("kind: software"));
    assert!(yaml_content.contains("mcp-enclave deploy install --profile L2"));

    let queries = [
        "enclave_processes.sql",
        "enclave_launchd.sql",
        "enclave_disk_encryption.sql",
        "enclave_sip.sql",
        "enclave_signatures.sql",
    ];

    for q in queries {
        let sql_path = repo.join("adapters/fleet/queries").join(q);
        assert!(sql_path.exists(), "SQL query missing: {}", q);
        let sql = fs::read_to_string(&sql_path).unwrap();
        assert!(
            sql.starts_with("--"),
            "SQL should have header comments: {}",
            q
        );
        assert!(sql.contains("SELECT "), "SQL should contain SELECT: {}", q);
    }
}

#[test]
fn f121_build_pkg_requires_real_distribution_and_signing_policy() {
    let repo = repo_root();
    let script = repo.join("packaging/pkg/build-pkg.sh");
    let h = MockHarness::new("package-inputs");
    let dist = h.temp_dir.join("dist");
    let run = || Command::new("/bin/sh").arg(&script).args(["--dry-run", "3.0.0"])
        .env("MCPMAC_DIST", &dist).env_remove("MCPMAC_INSTALLER_IDENTITY")
        .output().unwrap();
    let missing = run();
    assert_eq!(missing.status.code(), Some(20));
    assert!(String::from_utf8_lossy(&missing.stderr).contains("missing distribution artifact"));
    assert!(!dist.exists(), "dry-run must not synthesize artifacts");
    // Admission fixtures only: these do not claim a signed macOS distribution.
    for name in ["bin/mcp-enclave", "codesign-pins.json", "SHA256SUMS", "launchd/provision-accounts.sh"] {
        let p = dist.join(name); fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, b"fixture").unwrap();
    }
    let nonexec = run();
    assert_eq!(nonexec.status.code(), Some(20));
    assert!(String::from_utf8_lossy(&nonexec.stderr).contains("CLI is not executable"));
    fs::set_permissions(dist.join("bin/mcp-enclave"), fs::Permissions::from_mode(0o755)).unwrap();
    fs::create_dir(dist.join("EnclaveCustody.app")).unwrap();
    let unsigned = run();
    assert_eq!(unsigned.status.code(), Some(20));
    assert!(String::from_utf8_lossy(&unsigned.stderr).contains("production requires MCPMAC_INSTALLER_IDENTITY"));
}

/// Missing/empty inputs must fail before staging or publishing a package.
#[test]
fn f121_each_missing_artifact_fails_without_staging_or_placeholder() {
    let script = repo_root().join("packaging/pkg/build-pkg.sh");
    for missing in ["bin/mcp-enclave", "codesign-pins.json", "SHA256SUMS", "launchd/provision-accounts.sh"] {
        for empty in [false, true] {
            let h = MockHarness::new("f121-missing");
            let dist = h.temp_dir.join("dist");
            let output = h.temp_dir.join("output");
            for name in ["bin/mcp-enclave", "codesign-pins.json", "SHA256SUMS", "launchd/provision-accounts.sh"] {
                let path = dist.join(name);
                fs::create_dir_all(path.parent().unwrap()).unwrap();
                if name != missing || empty { fs::write(&path, if name == missing { b"".as_slice() } else { b"fixture".as_slice() }).unwrap(); }
            }
            if dist.join("bin/mcp-enclave").exists() {
                fs::set_permissions(dist.join("bin/mcp-enclave"), fs::Permissions::from_mode(0o755)).unwrap();
            }
            fs::create_dir(dist.join("EnclaveCustody.app")).unwrap();
            for dry_run in [false, true] {
                let mut command = Command::new("/bin/sh");
                command.arg(&script).arg("--unsigned-development");
                if dry_run { command.arg("--dry-run"); }
                let result = command.env("MCPMAC_DIST", &dist).env("MCPMAC_PKG_OUTPUT", &output).env_remove("MCPMAC_INSTALLER_IDENTITY").output().unwrap();
                assert_eq!(result.status.code(), Some(20), "missing={missing},empty={empty},dry={dry_run}: {result:?}");
                assert!(String::from_utf8_lossy(&result.stderr).contains(&format!("missing distribution artifact {missing}")));
                assert!(!output.exists(), "admission failure must precede output/staging creation");
                if empty { assert_eq!(fs::metadata(dist.join(missing)).unwrap().len(), 0); }
                else { assert!(!dist.join(missing).exists(), "never synthesize the missing artifact"); }
            }
        }
    }
}

/// Actual macOS shell staging, using only private temporary paths. No package
/// builders, installer scripts, signing identities or installed services run.
#[test]
#[cfg(target_os = "macos")]
fn f121_unsigned_development_dry_run_stages_without_installing_or_publishing() {
    let h = MockHarness::new("f121-stage");
    let dist = h.temp_dir.join("dist with spaces");
    let output = h.temp_dir.join("output with spaces");
    fs::create_dir_all(dist.join("bin")).unwrap();
    // Use the actual built Mach-O CLI, rather than an exit-zero placeholder.
    fs::copy(env!("CARGO_BIN_EXE_mcp-enclave"), dist.join("bin/mcp-enclave")).unwrap();
    fs::set_permissions(dist.join("bin/mcp-enclave"), fs::Permissions::from_mode(0o755)).unwrap();
    fs::create_dir_all(dist.join("launchd")).unwrap();
    fs::copy(repo_root().join("launchd/provision-accounts.sh"), dist.join("launchd/provision-accounts.sh")).unwrap();
    fs::write(dist.join("codesign-pins.json"), b"{\"fixture_only\":true}\n").unwrap();
    fs::write(dist.join("SHA256SUMS"), b"staging fixture only; no production integrity claim\n").unwrap();
    fs::create_dir(dist.join("EnclaveCustody.app")).unwrap();
    fs::write(dist.join("EnclaveCustody.app/fixture-marker"), b"fixture, not a signed application").unwrap();
    // Public-trust staging requires every metadata/target asset even for this
    // unsigned dry-run. These inert documents establish no genuine authority.
    let trust = dist.join("tuf/repo");
    fs::create_dir_all(&trust).unwrap();
    for name in ["root.json", "timestamp.json", "snapshot.json", "targets.json", "enclave-host-config.json", "enclave-policy.cedar.v1.json", "vk_manifest.json", "enclave-distribution-v1.json"] {
        fs::write(trust.join(name), b"{}\n").unwrap();
    }
    let result = Command::new("/bin/sh").arg(repo_root().join("packaging/pkg/build-pkg.sh"))
        .args(["3.0.0", "--dry-run", "--unsigned-development"])
        .env("MCPMAC_DIST", &dist).env("MCPMAC_PKG_OUTPUT", &output)
        .env_remove("MCPMAC_INSTALLER_IDENTITY").output().unwrap();
    assert_eq!(result.status.code(), Some(0), "{result:?}");
    let stdout = String::from_utf8(result.stdout).unwrap();
    assert!(stdout.contains("Dry-run: packaging verification passed."), "{stdout}");
    assert!(output.is_dir());
    assert_eq!(fs::read_dir(&output).unwrap().count(), 0, "dry-run must not publish a package");
    let root = stdout.lines().find_map(|line| line.strip_prefix("Dry-run: pkgbuild --root ")).unwrap().split(" --scripts ").next().unwrap();
    assert!(!std::path::Path::new(root).exists(), "temporary payload is cleaned after staging");
    assert_eq!(fs::read(dist.join("bin/mcp-enclave")).unwrap(), fs::read(env!("CARGO_BIN_EXE_mcp-enclave")).unwrap(), "staging cannot replace actual CLI with placeholder");
    println!("F121_NATIVE_STAGING: actual CLI copied; fixture metadata/app; dry-run only; no pkgbuild/productbuild/install executed");
}

/// Helper to create a temporary test harness with mock binaries
struct MockHarness {
    temp_dir: PathBuf,
    log_file: PathBuf,
    mock_cli: PathBuf,
}

impl MockHarness {
    fn new(prefix: &str) -> Self {
        let id = COUNTER.fetch_add(1, Ordering::SeqCst);
        let temp_dir = std::env::temp_dir().join(format!(
            "mcpmac-adapters-test-{prefix}-{}-{id}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&temp_dir);
        fs::create_dir_all(&temp_dir).unwrap();

        let log_file = temp_dir.join("calls.log");

        // Create mock mcp-enclave
        let mock_cli = temp_dir.join("mcp-enclave");
        let script = format!(
            r#"#!/bin/sh
echo "$@" >> "{}"
case "$1" in
  deploy)
    case "$2" in
      healthcheck)
        echo '{{"status":"ok","details":{{"overall_status":"healthy","daemons":[]}}}}'
        exit 0
        ;;
      *)
        exit 0
        ;;
    esac
    ;;
  *)
    exit 0
    ;;
esac
"#,
            log_file.display()
        );
        fs::write(&mock_cli, script).unwrap();
        fs::set_permissions(&mock_cli, fs::Permissions::from_mode(0o755)).unwrap();

        Self {
            temp_dir,
            log_file,
            mock_cli,
        }
    }

    fn recorded_calls(&self) -> Vec<String> {
        if !self.log_file.exists() {
            return Vec::new();
        }
        let content = fs::read_to_string(&self.log_file).unwrap();
        content.lines().map(|s| s.to_string()).collect()
    }
}

impl Drop for MockHarness {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.temp_dir);
    }
}

#[test]
fn test_jamf_deploy_script_parameter_shift() {
    let repo = repo_root();
    let jamf_script = repo.join("adapters/jamf/jamf_deploy_enclave.sh");
    assert!(jamf_script.exists());

    let harness = MockHarness::new("jamf-shift");

    // 1. Test hydrate action with positional parameter shift:
    // $1 = "/" (mount), $2 = "Mac-001" (host), $3 = "admin" (user)
    // $4 = "custom-llm" (target), $5 = "L2" (profile), $6 = "hydrate" (action)
    let output = Command::new("sh")
        .arg(&jamf_script)
        .args(["/", "Mac-001", "admin", "custom-llm", "L2", "hydrate"])
        .env("ENCLAVE_CLI", &harness.mock_cli)
        .output()
        .expect("Failed to execute jamf script");

    assert!(output.status.success(), "jamf hydrate failed: {:?}", output);
    let calls = harness.recorded_calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(
        calls[0],
        "deploy hydrate --profile L2 --target custom-llm --async"
    );

    // 2. Test bootstrap action
    let output_boot = Command::new("sh")
        .arg(&jamf_script)
        .args(["/", "Mac-001", "admin", "custom-llm", "L3", "bootstrap"])
        .env("ENCLAVE_CLI", &harness.mock_cli)
        .output()
        .expect("Failed to execute jamf script");

    assert!(output_boot.status.success());
    let calls = harness.recorded_calls();
    assert_eq!(calls.len(), 4);
    assert_eq!(calls[1], "deploy preflight --profile L3");
    assert_eq!(calls[2], "deploy install --profile L3");
    assert_eq!(calls[3], "deploy verify --profile L3");

    // 3. Test unknown action (should exit with 64)
    let output_bad = Command::new("sh")
        .arg(&jamf_script)
        .args(["/", "Mac-001", "admin", "target", "L1", "invalid_action"])
        .env("ENCLAVE_CLI", &harness.mock_cli)
        .output()
        .expect("Failed to execute jamf script");

    assert_eq!(output_bad.status.code(), Some(64));
}

#[test]
fn test_jamf_extension_attributes() {
    let repo = repo_root();
    let h = MockHarness::new("jamf-ea");
    let body = h.temp_dir.join("health.json");
    let exit = h.temp_dir.join("exit");
    let parser = h.temp_dir.join("plutil-fixture");
    // Exercise the production scripts with copied fixed paths; production has no
    // environment override. This portable parser implements the used plutil API;
    // native plutil/daemon authentication are separate macOS acceptance checks.
    fs::write(&parser, r#"#!/usr/bin/python3
import json, sys
try:
    value = json.load(sys.stdin)
    for key in sys.argv[2].split("."):
        value = value[key]
    if isinstance(value, bool): value = str(value).lower()
    elif not isinstance(value, str): sys.exit(1)
    print(value)
except (ValueError, KeyError, TypeError): sys.exit(1)
"#).unwrap();
    fs::set_permissions(&parser, fs::Permissions::from_mode(0o755)).unwrap();
    fs::write(&h.mock_cli, format!("#!/bin/sh\n/bin/cat '{}'\nexit \u{24}(/bin/cat '{}')\n", body.display(), exit.display())).unwrap();
    let mut copies = Vec::new();
    for name in ["EA-Enclave-Status.sh", "EA-Enclave-Security.sh"] {
        let source = fs::read_to_string(repo.join("adapters/jamf").join(name)).unwrap();
        assert!(source.contains("CLI=/opt/enterprise/enclave/bin/mcp-enclave"));
        assert!(!source.contains("ENCLAVE_CLI"));
        let copied = source.replace("/opt/enterprise/enclave/bin/mcp-enclave", h.mock_cli.to_str().unwrap())
            .replace("/usr/bin/plutil", parser.to_str().unwrap());
        let path = h.temp_dir.join(name); fs::write(&path, copied).unwrap(); copies.push(path);
    }
    for (json, code, status, security) in [
        ("{\"status\":\"ok\",\"details\":{\"overall_status\":\"healthy\",\"pf_isolated\":true}}", "0", "healthy", "ISOLATED"),
        ("{\n  \"status\": \"ok\",\n  \"details\": {\n    \"overall_status\": \"healthy\",\n    \"pf_isolated\": true\n  }\n}", "0", "healthy", "ISOLATED"),
        ("{\"status\":\"ok\",\"details\":{\"overall_status\":\"healthy\",\"pf_isolated\":true}}", "1", "UNKNOWN", "EXPOSED"),
        ("{\"status\":\"error\",\"details\":{\"overall_status\":\"unhealthy\",\"pf_isolated\":false}}", "1", "unhealthy", "EXPOSED"),
        ("{\"status\":\"error\",\"details\":{\"overall_status\":\"quarantined\"}}", "1", "quarantined", "QUARANTINED"),
        ("{\"status\":\"ok\",\"details\":{\"overall_status\":\"<result>healthy</result>\"}}", "0", "UNKNOWN", "EXPOSED"),
        ("{\"overall_status\":\"healthy\",\"pf_isolated\":true}", "0", "UNKNOWN", "EXPOSED"),
        ("{\"status\":\"ok\",\"details\":null}", "0", "UNKNOWN", "EXPOSED"),
        ("{\"overall_status\":\"healthy\",", "0", "UNKNOWN", "EXPOSED"),
        ("{}", "0", "UNKNOWN", "EXPOSED"),
    ] {
        fs::write(&body, json).unwrap(); fs::write(&exit, code).unwrap();
        for (path, expected) in copies.iter().zip([status, security]) {
            let output = Command::new("/bin/sh").arg(path).output().unwrap();
            assert!(output.status.success());
            assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), format!("<result>{expected}</result>"), "input={json}, code={code}");
        }
    }
    fs::remove_file(&h.mock_cli).unwrap();
    for path in &copies {
        let output = Command::new("/bin/sh").arg(path).output().unwrap();
        assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "<result>NOT_INSTALLED</result>");
    }
}

#[test]
fn test_lightweight_mdm_bootstrap_script() {
    let repo = repo_root();
    let script = repo.join("adapters/lightweight-mdm/lightweight_mdm_bootstrap.sh");
    assert!(script.exists());

    let harness = MockHarness::new("mdm-boot");

    let output = Command::new("sh")
        .arg(&script)
        .args(["L3", "test-weights"])
        .env("ENCLAVE_CLI", &harness.mock_cli)
        .output()
        .expect("Failed to execute lightweight_mdm_bootstrap.sh");

    assert!(output.status.success());
    let calls = harness.recorded_calls();
    assert_eq!(calls.len(), 4);
    assert_eq!(calls[0], "deploy preflight --profile L3");
    assert_eq!(calls[1], "deploy install --profile L3");
    assert_eq!(calls[2], "deploy verify --profile L3");
    assert_eq!(
        calls[3],
        "deploy hydrate --profile L3 --target test-weights --async"
    );
}

#[test]
fn test_fleet_healthcheck_script() {
    let repo = repo_root();
    let script = repo.join("adapters/fleet/scripts/healthcheck.sh");
    assert!(script.exists());

    let harness = MockHarness::new("fleet-hc");

    let output = Command::new("sh")
        .arg(&script)
        .env("ENCLAVE_CLI", &harness.mock_cli)
        .output()
        .expect("Failed to execute fleet healthcheck.sh");

    assert!(output.status.success());
    let calls = harness.recorded_calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0], "deploy healthcheck --profile L2 --json");
}
