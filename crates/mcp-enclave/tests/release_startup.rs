//! FUNC-005 / TEST-005: actual rendered argv enters the shared production
//! validator with explicit trusted fixture observations; no installed mutations.
use enclave_core::daemon::DaemonId;
use enclave_core::runtime::{sandbox, validate_startup, DaemonArgs, StartupContext};
use mcp_enclave::launchd::{self, Layout};
use std::os::unix::fs::{PermissionsExt};
use std::path::PathBuf;

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let base = if enclave_core::ipc::geteuid() == 0 {
            PathBuf::from(std::env::var_os("HOME").expect("root fixture requires a private home"))
        } else { std::env::temp_dir() };
        let p = base.join(format!("release-startup-{}-{:x}", std::process::id(), enclave_core::rng::u64()));
        std::fs::create_dir(&p).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o700)).unwrap();
        Self(p)
    }
    fn layout(&self, profile: &str) -> Layout {
        Layout { sandbox_dir: self.0.display().to_string(), profile: profile.into(), ..Default::default() }
    }
    fn write(&self, name: &str, bytes: &[u8]) -> PathBuf {
        let p = self.0.join(name);
        std::fs::write(&p, bytes).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
        p
    }
}
impl Drop for Fixture { fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.0); } }

fn argv(plist: &str) -> Vec<String> {
    let array = plist.split("<key>ProgramArguments</key>").nth(1).unwrap()
        .split("</array>").next().unwrap();
    array.split("<string>").skip(1).map(|v| v.split("</string>").next().unwrap()
        .replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&")).collect()
}
fn parsed(d: DaemonId, l: &Layout) -> DaemonArgs {
    let a = argv(&launchd::plist(d, l));
    assert_eq!(&a[0..2], &["/usr/bin/sandbox-exec", "-f"]);
    assert_eq!(a[2], format!("{}/{}.sb", l.sandbox_dir, d.plist_suffix()));
    assert_eq!(a[3], launchd::program(d,l));
    DaemonArgs::parse(a.into_iter().skip(3)).unwrap()
}
fn context(d: DaemonId) -> StartupContext {
    StartupContext { effective_uid: d.uid(), require_sandbox: true, profile_owner_uid: enclave_core::ipc::geteuid() }
}

#[test]
fn release_generated_argv_accepts_all_five_daemons_and_profiles() {
    let f = Fixture::new();
    for profile in ["L1", "L2", "L3"] {
        let l = f.layout(profile);
        for d in DaemonId::ALL {
            f.write(&format!("{}.sb",d.plist_suffix()), launchd::sandbox_profile(d,&l).as_bytes());
            let a = parsed(d,&l);
            assert!(!a.dev_same_uid && !a.simulated_hardware);
            assert_eq!(a.profile.to_string(), profile);
            assert_eq!(a.expected_uid(d), d.uid());
            validate_startup(d,&a,context(d)).unwrap();
            // Seatbelt renders the platform's canonical /private aliases; the
            // argv retains the caller's valid spelling for profile loading.
            let seatbelt_layout = l.for_seatbelt();
            for parent in std::path::Path::new(&seatbelt_layout.sandbox_dir).ancestors() {
                assert!(launchd::sandbox_profile(d,&l).contains(&format!(
                    "(allow file-read-data file-read-metadata (literal \"{}\"))", parent.display()
                )), "held-directory profile validation requires a literal directory read grant");
            }
            if d==DaemonId::SwarmSync {
                let sb=launchd::sandbox_profile(d,&l);
                assert_eq!(sb.contains("network-inbound (local udp"),profile=="L2");
                assert_eq!(sb.contains("network-bind network-inbound (local udp \"*:4433\")"),profile=="L2");
                assert_eq!(sb.contains("network-outbound (remote udp \"*:4433\")"),profile=="L2");
                assert!(sb.contains("remote udp"), "FS702 §5.1 preserves outgoing QUIC relay clients");
            }
            // Independently lock in the current ADR-006 identity assignments.
            assert_eq!(d.gid(), 8000+d.uid());
            assert_eq!(d.client_gid(), 8010+d.uid());
        }
    }
}

#[test]
fn release_generated_argv_refuses_missing_unsafe_and_foreign_configuration() {
    let f = Fixture::new();
    for profile in ["L1", "L2", "L3"] {
        let l=f.layout(profile);
        for d in DaemonId::ALL {
            let path=f.write(&format!("{}.sb",d.plist_suffix()),launchd::sandbox_profile(d,&l).as_bytes());
            let a=parsed(d,&l);
            let mut missing=a.clone(); missing.sandbox_profile=None;
            assert!(validate_startup(d,&missing,context(d)).unwrap_err().is("SANDBOX_PROFILE_REQUIRED"));
            let mut wrong=context(d); wrong.effective_uid=9876;
            assert!(validate_startup(d,&a,wrong).unwrap_err().is("WRONG_DAEMON_UID"));
            let mut foreign=context(d); foreign.profile_owner_uid=9876;
            assert!(validate_startup(d,&a,foreign).unwrap_err().is("SANDBOX_PROFILE_DIRECTORY_INSECURE"));
            let mut simulation=a.clone(); simulation.simulated_hardware=true;
            assert!(validate_startup(d,&simulation,context(d)).unwrap_err().is("SIMULATION_REQUIRES_DEV_MODE"));
            std::fs::set_permissions(&path,std::fs::Permissions::from_mode(0o666)).unwrap();
            assert!(validate_startup(d,&a,context(d)).unwrap_err().is("SANDBOX_PROFILE_INSECURE"));
            std::fs::set_permissions(&path,std::fs::Permissions::from_mode(0o600)).unwrap();
            std::fs::set_permissions(&f.0,std::fs::Permissions::from_mode(0o777)).unwrap();
            assert!(validate_startup(d,&a,context(d)).unwrap_err().is("SANDBOX_PROFILE_DIRECTORY_INSECURE"));
            std::fs::set_permissions(&f.0,std::fs::Permissions::from_mode(0o700)).unwrap();
            std::fs::remove_file(&path).unwrap();
            assert!(validate_startup(d,&a,context(d)).unwrap_err().is("SANDBOX_PROFILE_OPEN"));
        }
    }
}

#[test]
fn release_profile_loader_refuses_links_nonfiles_malformed_and_unbounded_input() {
    let f=Fixture::new(); let uid=enclave_core::ipc::geteuid();
    let valid=f.write("valid.sb",b"(version 1)\n(deny default)\n");
    let link=f.0.join("link.sb"); std::os::unix::fs::symlink(&valid,&link).unwrap();
    assert!(sandbox::read_profile(&link,uid).is_err());
    assert!(sandbox::read_profile(&f.0,uid).is_err());
    assert!(sandbox::read_profile(std::path::Path::new("relative.sb"),uid).is_err());
    for bytes in [Vec::new(), vec![0], vec![0xff], vec![b'a';1024*1024+1]] {
        let p=f.write("invalid.sb",&bytes); assert!(sandbox::read_profile(&p,uid).is_err());
    }
    assert_eq!(sandbox::read_profile(&valid,uid).unwrap(),std::fs::read(valid).unwrap());
}

#[test]
fn release_renderer_rejects_path_and_profile_injection_before_writing() {
    let f=Fixture::new();
    for value in ["relative", "/tmp/../etc", "/tmp/x\nhello", "/tmp/x;touch", "/tmp/$(touch)", "/tmp/x\"(allow default)"] {
        let l=Layout {bin_dir:value.into(),..Default::default()};
        assert!(launchd::render_all(&f.0.join("out"),&l).is_err(),"{value}");
        assert!(!f.0.join("out").exists());
    }
    // Equal values do not turn shell directory operands into bundle paths.
    let alias=Layout {socket_dir:"/tmp/two words".into(),custody_app:"/tmp/two words".into(),..Default::default()};
    assert!(launchd::render_all(&f.0.join("out"),&alias).is_err());
    let spaced_binary=Layout {bin_dir:"/Applications/Enterprise Enclave/bin".into(),..Default::default()};
    assert!(spaced_binary.validate().is_ok(), "XML/Seatbelt binary paths preserve spaces");
    let l=Layout {profile:"L0".into(),..Default::default()};
    assert!(launchd::render_all(&f.0.join("out"),&l).is_err());
}

#[cfg(target_os="macos")]
#[test]
fn release_native_profile_reapplication_enforces_file_refusal_in_owned_child() {
    // A dedicated child prevents irreversible sandboxing of the test harness.
    // Both direct and sandbox-exec paths invoke the exact production loader and
    // sandbox_init call. This is private software confinement, not installed UID
    // or serving-socket acceptance evidence.
    if let Some(root)=std::env::var_os("MCPMAC_RELEASE_SANDBOX_CHILD") {
        let root=PathBuf::from(root);
        sandbox::init_sandbox_with_owner(&root.join("fixture.sb"), enclave_core::ipc::geteuid()).unwrap();
        assert_eq!(std::fs::read(root.join("allowed")).unwrap(),b"allowed");
        assert!(std::fs::read(root.join("forbidden")).is_err());
        return;
    }
    let f=Fixture::new();
    let resolved=std::fs::canonicalize(&f.0).unwrap();
    f.write("allowed",b"allowed");f.write("forbidden",b"forbidden");
    let exe=std::env::current_exe().unwrap();
    let mut text=format!("(version 1)\n(deny default)\n(import \"bsd.sb\")\n(allow process-exec (literal \"{}\"))\n(allow file-read* (literal \"{}\"))\n(allow file-read-metadata)\n(allow file-read* (subpath \"/System\") (subpath \"/usr/lib\") (literal \"{}/allowed\") (literal \"{}/fixture.sb\"))\n",exe.display(),exe.display(),resolved.display(),resolved.display());
    // Match the production loader's held-directory traversal without allowing
    // any sibling regular-file reads. The forbidden-file assertion stays below
    // the actual sandbox_init call in both direct and externally wrapped children.
    for directory in resolved.ancestors() {
        use std::fmt::Write;
        writeln!(text,"(allow file-read-data file-read-metadata (literal \"{}\"))",directory.display()).unwrap();
    }
    let p=f.write("fixture.sb",text.as_bytes());
    for wrapped in [false,true] {
        let exe=std::env::current_exe().unwrap();
        let mut c=if wrapped { let mut c=std::process::Command::new("/usr/bin/sandbox-exec");c.args(["-f"]).arg(&p).arg(&exe);c } else {std::process::Command::new(&exe)};
        let o=c.args(["--exact","release_native_profile_reapplication_enforces_file_refusal_in_owned_child","--nocapture"])
            .env("MCPMAC_RELEASE_SANDBOX_CHILD",&f.0).output().unwrap();
        assert!(o.status.success(),"wrapped={wrapped}: {} {}",String::from_utf8_lossy(&o.stdout),String::from_utf8_lossy(&o.stderr));
    }
}
