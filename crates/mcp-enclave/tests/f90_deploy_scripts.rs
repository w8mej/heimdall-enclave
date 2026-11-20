//! DEFECT-F-90: root deploy verbs must not run scripts from the current
//! directory or tools resolved through `PATH`.
//!
//! Nothing here runs privileged: a recording runner captures the exact
//! commands, and the one test that really executes the embedded scripts runs
//! as the (non-root) test user, where each script stops at its own `id -u`
//! check before touching the system. That test refuses to run as root.

use mcp_enclave::deploy::install::run_install_with;
use mcp_enclave::deploy::purge::run_purge_with;
use mcp_enclave::deploy::scripts::{
    DeployCtx, Script, INSTALL_SH, UNINSTALL_SH, VERIFY_INSTALL_SH,
};
use mcp_enclave::deploy::verify::run_verify_with;
use mcp_enclave::syscmd::{Runner, SystemRunner, SAFE_PATH};
use std::cell::RefCell;
use std::ffi::OsString;
use std::io;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Output};

#[derive(Debug, Clone)]
struct Rec {
    program: String,
    args: Vec<String>,
    cwd: Option<PathBuf>,
    envs: Vec<(String, Option<String>)>,
}

/// Records every command; answers with `exit` (or a spawn error when `None`).
struct Recorder {
    seen: RefCell<Vec<Rec>>,
    exit: Option<i32>,
    fail_pf: bool,
}

impl Recorder {
    fn new(exit: Option<i32>) -> Self {
        Self {
            seen: RefCell::new(Vec::new()),
            exit,
            fail_pf: false,
        }
    }
    fn record(&self, cmd: &Command) -> io::Result<ExitStatus> {
        let s = |o: &std::ffi::OsStr| o.to_string_lossy().into_owned();
        self.seen.borrow_mut().push(Rec {
            program: s(cmd.get_program()),
            args: cmd.get_args().map(s).collect(),
            cwd: cmd.get_current_dir().map(Path::to_path_buf),
            envs: cmd.get_envs().map(|(k, v)| (s(k), v.map(s))).collect(),
        });
        if self.fail_pf && cmd.get_program() == "/sbin/pfctl" {
            return Err(io::Error::new(io::ErrorKind::NotFound, "pfctl spawn refused"));
        }
        match self.exit {
            Some(code) => Ok(ExitStatus::from_raw(code << 8)),
            None => Err(io::Error::new(io::ErrorKind::NotFound, "spawn refused")),
        }
    }
    fn seen(&self) -> Vec<Rec> {
        self.seen.borrow().clone()
    }
}

impl Runner for Recorder {
    fn status(&self, cmd: Command) -> io::Result<ExitStatus> {
        self.record(&cmd)
    }
    fn output(&self, cmd: Command) -> io::Result<Output> {
        let status = self.record(&cmd)?;
        Ok(Output {
            status,
            stdout: Vec::new(),
            stderr: Vec::new(),
        })
    }
}

fn scratch(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("mcpmac-f90-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).expect("scratch dir");
    d.canonicalize().expect("canonical scratch")
}

fn ctx<'a>(root: bool, runner: &'a dyn Runner, dir: &Path) -> DeployCtx<'a> {
    let anchors = dir.join("pf.anchors");
    let conf = dir.join("pf.conf");
    std::fs::write(&conf, "# test pf.conf\n").expect("pf.conf");
    DeployCtx {
        is_root: root,
        runner,
        anchors_dir: anchors,
        pf_conf: conf,
    }
}

fn env_of<'a>(r: &'a Rec, k: &str) -> Option<&'a str> {
    r.envs
        .iter()
        .find(|(n, _)| n == k)
        .and_then(|(_, v)| v.as_deref())
}

fn assert_scrubbed(r: &Rec) {
    assert!(
        r.program.starts_with('/'),
        "bare program name: {}",
        r.program
    );
    assert_eq!(
        env_of(r, "PATH"),
        Some(SAFE_PATH),
        "PATH not pinned for {r:?}"
    );
}

fn assert_embedded(r: &Rec, script: Script) {
    assert_eq!(r.program, "/bin/sh");
    assert_eq!(r.args[0], "-c");
    assert_eq!(
        r.args[1],
        script.body(),
        "script body is not the embedded copy"
    );
    assert_eq!(r.args[2], script.argv0());
    assert_eq!(r.cwd.as_deref(), Some(Path::new("/")));
    assert_scrubbed(r);
}

fn fake_dist(dir: &Path) -> PathBuf {
    let dist = dir.join("dist");
    std::fs::create_dir_all(&dist).expect("dist");
    std::fs::write(dist.join("codesign-pins.json"), "{}").expect("pins");
    dist
}

#[test]
fn install_with_dist_runs_only_the_transaction_owning_embedded_script() {
    let dir = scratch("install-dist");
    let dist = fake_dist(&dir);
    let rec = Recorder::new(Some(0));
    let c = ctx(true, &rec, &dir);
    let (code, msg, details) = run_install_with("L1", false, dist.to_str(), &c);
    assert_eq!(code, 0, "{msg}");
    assert_eq!(details["mode"], "dist");
    let seen = rec.seen();
    assert_embedded(&seen[0], Script::Install);
    assert_eq!(env_of(&seen[0], "MCPMAC_DIST"), dist.to_str());
    assert_eq!(env_of(&seen[0], "MCPMAC_PROFILE"), Some("L1"));
    assert_eq!(seen.len(), 1, "PF activation belongs inside the installer before bootstrap");
}

#[test]
fn install_relative_dist_is_canonicalised_before_use() {
    let dir = scratch("install-rel");
    let dist = fake_dist(&dir);
    let rec = Recorder::new(Some(0));
    let c = ctx(true, &rec, &dir);
    let dotted = format!("{}/../dist", dist.display());
    let (code, _, _) = run_install_with("L1", false, Some(&dotted), &c);
    assert_eq!(code, 0);
    assert_eq!(env_of(&rec.seen()[0], "MCPMAC_DIST"), dist.to_str());
}

#[test]
fn install_without_distribution_cannot_report_standalone_success() {
    let dir = scratch("install-payload");
    let rec = Recorder::new(Some(0));
    let c = ctx(true, &rec, &dir);
    if !Path::new("/opt/enterprise/enclave/dist").exists() {
        let (code, _, details) = run_install_with("L1", false, None, &c);
        assert_eq!(code, 20);
        assert_eq!(details["error"], "INSTALL_DIST_MISSING");
        assert!(rec.seen().is_empty());
    }
}

#[test]
fn install_missing_dist_fails_closed_without_running_anything() {
    let dir = scratch("install-missing");
    let rec = Recorder::new(Some(0));
    let c = ctx(true, &rec, &dir);
    let nowhere = dir.join("nope");
    let (code, msg, details) = run_install_with("L1", false, nowhere.to_str(), &c);
    assert_eq!(code, 20);
    assert_eq!(details["error"], "INSTALL_DIST_MISSING", "{msg}");
    // A directory without a build is refused too.
    let (code2, _, d2) = run_install_with("L1", false, dir.to_str(), &c);
    assert_eq!(
        (code2, d2["error"].as_str()),
        (20, Some("INSTALL_DIST_MISSING"))
    );
    assert!(rec.seen().is_empty());
}

#[test]
fn install_script_failure_stops_before_pf() {
    let dir = scratch("install-fail");
    let dist = fake_dist(&dir);
    let rec = Recorder::new(Some(1));
    let c = ctx(true, &rec, &dir);
    let (code, _, details) = run_install_with("L1", false, dist.to_str(), &c);
    assert_eq!(
        (code, details["error"].as_str()),
        (20, Some("INSTALL_SCRIPT_FAILED"))
    );
    assert_eq!(rec.seen().len(), 1);
}

#[test]
fn pf_validator_that_cannot_run_fails_and_restores_pf_conf() {
    let dir = scratch("pf-spawn");
    let mut rec = Recorder::new(Some(0));
    rec.fail_pf = true; // installation succeeds; the subsequent pf process cannot start
    let c = ctx(true, &rec, &dir);
    std::fs::create_dir_all(&c.anchors_dir).unwrap();
    let old_anchor = c.anchors_dir.join(mcp_enclave::pf::LLM_ISOLATION_ANCHOR);
    std::fs::write(&old_anchor, b"# existing anchor\n").unwrap();
    // This public helper still protects its own disk publications. The full
    // installer no longer calls it after completing the embedded transaction.
    let error = mcp_enclave::deploy::scripts::load_pf_anchors(&c).unwrap_err();
    assert!(error.contains("PF_INSTALL_FAILED") || error.contains("PF_LOAD_FAILED"), "{error}");
    let conf = std::fs::read_to_string(&c.pf_conf).expect("pf.conf");
    assert_eq!(conf, "# test pf.conf\n", "pf.conf not restored");
    assert_eq!(std::fs::read(&old_anchor).unwrap(), b"# existing anchor\n");
    assert!(!c.anchors_dir.join(mcp_enclave::pf::CAS_SWARM_ANCHOR).exists(), "new anchor must be removed on rollback");

}

#[test]
fn non_root_runs_nothing() {
    let dir = scratch("nonroot");
    let dist = fake_dist(&dir);
    let rec = Recorder::new(Some(0));
    let c = ctx(false, &rec, &dir);
    assert_eq!(run_install_with("L1", false, dist.to_str(), &c).0, 20);
    assert_eq!(run_purge_with("L1", true, true, true, &c).0, 20);
    let (_, _, v) = run_verify_with("L1", &c);
    assert!(v["checks"]
        .as_array()
        .expect("checks")
        .iter()
        .any(|c| c["skipped"] == "not root"));
    assert!(rec.seen().is_empty());
}

#[test]
fn purge_runs_embedded_uninstall_with_flags() {
    let dir = scratch("purge");
    let rec = Recorder::new(Some(0));
    let c = ctx(true, &rec, &dir);
    let (code, _, _) = run_purge_with("L1", true, true, false, &c);
    assert_eq!(code, 0);
    let seen = rec.seen();
    assert_eq!(seen.len(), 1);
    assert_embedded(&seen[0], Script::Uninstall);
    assert_eq!(&seen[0].args[3..], ["--purge-state"]);
}

#[test]
fn verify_runs_embedded_verify_install() {
    let dir = scratch("verify");
    let rec = Recorder::new(Some(0));
    let c = ctx(true, &rec, &dir);
    let _ = run_verify_with("L1", &c);
    let seen = rec.seen();
    assert_eq!(seen.len(), 1);
    assert_embedded(&seen[0], Script::VerifyInstall);
}

#[test]
fn embedded_scripts_are_the_repo_scripts_and_have_no_cwd_reads() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../packaging/macos");
    for (name, body) in [
        ("install.sh", INSTALL_SH),
        ("uninstall.sh", UNINSTALL_SH),
        ("verify-install.sh", VERIFY_INSTALL_SH),
    ] {
        let on_disk = std::fs::read_to_string(root.join(name)).expect(name);
        assert_eq!(on_disk, body, "{name} embedded copy is stale");
        assert!(!body.contains("cp packaging/"), "{name} reads from the cwd");
    }
}

/// Static regression guard: no source file launches a program by bare name or
/// names a cwd-relative packaging script.
#[test]
fn no_bare_command_names_or_cwd_scripts_in_sources() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut stack = vec![src];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).expect("read src") {
            let p = e.expect("entry").path();
            if p.is_dir() {
                stack.push(p);
                continue;
            }
            let text = std::fs::read_to_string(&p).expect("read");
            for (i, line) in text.lines().enumerate() {
                let bare = line.contains("Command::new(\"") && !line.contains("Command::new(\"/");
                assert!(
                    !bare,
                    "{}:{}: bare program name: {line}",
                    p.display(),
                    i + 1
                );
                assert!(
                    !line.contains("Path::new(\"packaging/macos/"),
                    "{}:{}: cwd-relative script: {line}",
                    p.display(),
                    i + 1
                );
            }
        }
    }
}

const HOSTILE: &str = "#!/bin/sh\nid -u > \"$MCPMAC_F90_MARKER_DIR/$(basename \"$0\").ran\"\n";

fn plant_hostile_tree(dir: &Path) -> PathBuf {
    let pkg = dir.join("packaging/macos");
    std::fs::create_dir_all(&pkg).expect("pkg");
    for s in ["install.sh", "uninstall.sh", "verify-install.sh"] {
        std::fs::write(pkg.join(s), HOSTILE).expect("plant script");
    }
    let bin = dir.join("hostile-bin");
    std::fs::create_dir_all(&bin).expect("bin");
    for t in [
        "sh",
        "pfctl",
        "launchctl",
        "csrutil",
        "fdesetup",
        "stat",
        "sysctl",
    ] {
        let p = bin.join(t);
        std::fs::write(&p, HOSTILE).expect("plant tool");
        std::fs::set_permissions(&p, std::os::unix::fs::PermissionsExt::from_mode(0o755))
            .expect("chmod");
    }
    bin
}

fn markers(dir: &Path) -> Vec<String> {
    std::fs::read_dir(dir)
        .map(|it| {
            it.filter_map(|e| e.ok())
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default()
}

/// The review's validation step, made safe for an unprivileged run: a hostile
/// `packaging/macos/*.sh` in the cwd and hostile tools first on `PATH`, then
/// the verbs with the root branch forced on and the real process runner.
#[test]
fn review_validation_hostile_cwd_and_path_are_never_executed() {
    // SAFETY: geteuid has no preconditions.
    if unsafe { libc::geteuid() } == 0 {
        eprintln!("refusing to run: this test executes the embedded uninstall script for real");
        return;
    }
    let dir = scratch("hostile");
    let marker_dir = dir.join("markers");
    std::fs::create_dir_all(&marker_dir).expect("markers");
    let bin = plant_hostile_tree(&dir);
    let old_path = std::env::var_os("PATH").unwrap_or_default();
    let mut path = OsString::from(bin.as_os_str());
    path.push(":");
    path.push(&old_path);
    std::env::set_var("PATH", &path);
    std::env::set_var("MCPMAC_F90_MARKER_DIR", &marker_dir);
    std::env::set_current_dir(&dir).expect("chdir hostile");

    // Positive control: the pre-fix pattern does fire in this setup.
    let st = Command::new("sh")
        .arg("packaging/macos/verify-install.sh")
        .status()
        .expect("control");
    assert!(st.success());
    let fired = markers(&marker_dir);
    assert!(
        !fired.is_empty(),
        "control did not fire; the test would be vacuous"
    );
    for m in fired {
        std::fs::remove_file(marker_dir.join(m)).expect("reset marker");
    }

    let pfroot = dir.join("pfroot");
    std::fs::create_dir_all(&pfroot).expect("pfroot");
    let c = ctx(true, &SystemRunner, &pfroot);
    let dist = fake_dist(&dir);
    let _ = run_verify_with("L1", &c);
    let _ = run_purge_with("L1", true, false, false, &c);
    let _ = run_install_with("L1", false, dist.to_str(), &c);
    let _ = run_install_with("L1", false, None, &c);
    let _ = mcp_enclave::deploy::preflight::evaluate_preflight("L1", Some(1));

    std::env::set_var("PATH", &old_path);
    assert!(
        markers(&marker_dir).is_empty(),
        "hostile file ran: {:?}",
        markers(&marker_dir)
    );
}
