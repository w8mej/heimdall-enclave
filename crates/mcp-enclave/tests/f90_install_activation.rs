//! The verified embedded installer owns PF activation before bootstrap.
//! No fallible second PF activation may happen after it reports success.
use depot_enclave::deploy::install::run_install_with;
use depot_enclave::deploy::scripts::DeployCtx;
use depot_enclave::syscmd::Runner;
use std::cell::RefCell;
use std::os::unix::process::ExitStatusExt;
use std::process::{Command, ExitStatus, Output};

struct AfterBootstrapFailure(RefCell<Vec<String>>);
impl Runner for AfterBootstrapFailure {
    fn status(&self, cmd: Command) -> std::io::Result<ExitStatus> {
        let program = cmd.get_program().to_string_lossy().into_owned();
        self.0.borrow_mut().push(program.clone());
        Ok(ExitStatus::from_raw(if program == "/bin/sh" { 0 } else { 1 << 8 }))
    }
    fn output(&self, cmd: Command) -> std::io::Result<Output> {
        Ok(Output { status: self.status(cmd)?, stdout: Vec::new(), stderr: Vec::new() })
    }
}

#[test]
fn f90_installer_success_is_not_followed_by_fallible_pf_reactivation() {
    let root = std::env::temp_dir().join(format!("f90-activation-{}", enclave_core::rng::u64()));
    std::fs::create_dir(&root).unwrap();
    let dist = root.join("dist");
    std::fs::create_dir(&dist).unwrap();
    std::fs::write(dist.join("codesign-pins.json"), b"{}").unwrap();
    let conf = root.join("pf.conf");
    std::fs::write(&conf, b"# prior configured policy\n").unwrap();
    let runner = AfterBootstrapFailure(RefCell::new(Vec::new()));
    let context = DeployCtx { is_root: true, runner: &runner, anchors_dir: root.join("anchors"), pf_conf: conf.clone() };
    let (code, message, details) = run_install_with("L2", false, dist.to_str(), &context);
    assert_eq!(code, 0, "a completed installer must not be followed by a second activation: {message}");
    assert_eq!(details["status"], "ok");
    assert_eq!(runner.0.borrow().as_slice(), ["/bin/sh"]);
    assert_eq!(std::fs::read(&conf).unwrap(), b"# prior configured policy\n");
    assert!(!context.anchors_dir.exists(), "outer CLI must not republish PF files after installer commit");
    std::fs::remove_dir_all(root).unwrap();
}
