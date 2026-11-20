//! Inert renderer data shared by actual protected Layout and public export.
//! No checked deployment, provisioning, signer, guard, lease or authority type
//! is stored/constructed here. Existing renderer bodies below are moved intact.
use super::*;
use enclave_core::{
    deployment::{normalized_path, DeploymentRole, DeploymentSigningMode, DeploymentTarget},
    Profile,
};
use std::fmt::Write as _;
use std::{
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
};

#[derive(Clone)]
struct TargetData {
    target: DeploymentTarget,
    descriptor: PathBuf,
}
impl TargetData {
    fn target(&self) -> &DeploymentTarget {
        &self.target
    }
    fn config_path(&self) -> &Path {
        &self.descriptor
    }
}
#[derive(Clone)]
struct CustodyPaths {
    manifest: PathBuf,
    files: Vec<PathBuf>,
}
impl CustodyPaths {
    fn manifest_path(&self) -> &Path {
        &self.manifest
    }
    fn read_paths(&self) -> Vec<&Path> {
        std::iter::once(self.manifest.as_path())
            .chain(self.files.iter().map(PathBuf::as_path))
            .collect()
    }
    fn ancestor_paths(&self) -> BTreeSet<PathBuf> {
        self.read_paths()
            .into_iter()
            .flat_map(|path| path.parent().into_iter().flat_map(Path::ancestors))
            .map(Path::to_owned)
            .collect()
    }
}
#[derive(Clone)]
pub(super) struct Layout {
    bin_dir: String,
    sandbox_dir: String,
    socket_dir: String,
    audit_dir: String,
    state_dir: String,
    profile: String,
    custody_app: String,
    fido_emulator: bool,
    custody_authority: Option<CustodyPaths>,
    deployment: Option<TargetData>,
}
impl Layout {
    pub(super) fn from_protected(layout: &super::Layout) -> Self {
        Self {
            bin_dir: layout.bin_dir.clone(),
            sandbox_dir: layout.sandbox_dir.clone(),
            socket_dir: layout.socket_dir.clone(),
            audit_dir: layout.audit_dir.clone(),
            state_dir: layout.state_dir.clone(),
            profile: layout.profile.clone(),
            custody_app: layout.custody_app.clone(),
            fido_emulator: layout.fido_emulator,
            custody_authority: layout
                .custody_authority
                .as_ref()
                .map(|authority| CustodyPaths {
                    manifest: authority.manifest_path().to_owned(),
                    files: authority
                        .read_paths()
                        .into_iter()
                        .skip(1)
                        .map(Path::to_owned)
                        .collect(),
                }),
            deployment: layout.deployment.as_ref().map(|checked| TargetData {
                target: checked.target().clone(),
                descriptor: checked.config_path().to_owned(),
            }),
        }
    }
    /// Launchd job label; cryptographic signing identifiers stay unchanged.
    pub fn job_label(&self, default: &str) -> String {
        match &self.deployment {
            Some(checked) => format!(
                "{}.{}",
                checked.target().layout.launchd_namespace,
                default
                    .strip_prefix("com.enterprise.enclave.")
                    .unwrap_or(default)
            ),
            None => default.to_owned(),
        }
    }
    fn support_file(&self, name: &str, default: &str) -> String {
        self.deployment
            .as_ref()
            .map(|c| {
                c.target()
                    .layout
                    .support_root
                    .join(name)
                    .display()
                    .to_string()
            })
            .unwrap_or_else(|| default.to_owned())
    }
    fn cas_store(&self) -> String {
        self.deployment
            .as_ref()
            .map(|c| c.target().layout.cas_store_root.display().to_string())
            .unwrap_or_else(|| "/opt/enterprise/enclave/cas".into())
    }
    fn tuf_root(&self) -> String {
        self.deployment
            .as_ref()
            .and_then(|c| c.target().broker.as_ref())
            .map(|b| b.tuf_root_file.display().to_string())
            .unwrap_or_else(|| {
                self.support_file(
                    "tuf/root.json",
                    "/Library/Application Support/EnterpriseEnclave/tuf/root.json",
                )
            })
    }
    fn pin_file(&self) -> String {
        self.deployment
            .as_ref()
            .map(|c| c.target().codesign_pins_file.display().to_string())
            .unwrap_or_else(|| enclave_core::codesign::PIN_FILE.to_owned())
    }
    fn mach_service(&self) -> &str {
        self.deployment
            .as_ref()
            .map(|c| c.target().layout.mach_service.as_str())
            .unwrap_or("com.enterprise.enclave.exception")
    }
    fn append_deployment_args(&self, args: &mut Vec<String>, cli: bool) {
        if let Some(checked) = &self.deployment {
            args.extend([
                if cli {
                    "--deployment-config"
                } else {
                    "--deployment-target"
                }
                .into(),
                checked.config_path().display().to_string(),
            ]);
        }
    }
    fn deployment_read_rules(&self, output: &mut String) {
        if let Some(checked) = &self.deployment {
            let target = checked.target();
            let mut files = vec![
                checked.config_path(),
                target.authority_config.as_path(),
                target.expected_artifacts_manifest.as_path(),
                target.codesign_pins_file.as_path(),
            ];
            if let Some(broker) = &target.broker {
                files.push(&broker.tuf_root_file);
            }
            let mut directories = std::collections::BTreeSet::new();
            for file in files {
                let resolved = seatbelt_path(&file.display().to_string());
                let _ = writeln!(output, "(allow file-read* (literal \"{resolved}\"))");
                for parent in file.ancestors().skip(1) {
                    directories.insert(seatbelt_path(&parent.display().to_string()));
                }
            }
            for directory in directories {
                let _ = writeln!(
                    output,
                    "(allow file-read-data file-read-metadata (literal \"{directory}\"))"
                );
            }
        }
    }
    /// The emulator socket UID 703 connects to.
    pub fn fido_socket(&self) -> String {
        format!(
            "{}/{}/{}",
            self.socket_dir,
            fido::EMULATOR_SOCKET_DIR,
            fido::EMULATOR_SOCKET
        )
    }
    /// `--yubikey-transport` for UID 703.
    pub fn yubikey_transport(&self) -> String {
        if self.fido_emulator {
            format!("emulated:{}", self.fido_socket())
        } else {
            "hid".into()
        }
    }
    /// The intent socket UID 703 connects to (GAP-14).
    pub fn intent_socket(&self) -> String {
        format!(
            "{}/{}/{}",
            self.socket_dir, INTENT_SOCKET_DIR, INTENT_SOCKET
        )
    }
    /// The browser socket UID 701 connects to (GAP-34).
    pub fn browser_socket(&self) -> String {
        format!(
            "{}/{}/{}",
            self.socket_dir, BROWSER_SOCKET_DIR, BROWSER_SOCKET
        )
    }
    /// Dedicated witness socket UID 703 connects to (GAP-10).
    pub fn witness_socket(&self) -> String {
        format!(
            "{}/{}/{}",
            self.socket_dir,
            enclave_core::daemon::WITNESS_SOCKET_DIR,
            enclave_core::daemon::WITNESS_SOCKET
        )
    }
}

impl Layout {
    /// This layout with every directory as Seatbelt resolves it.
    pub fn for_seatbelt(&self) -> Self {
        Self {
            bin_dir: seatbelt_path(&self.bin_dir),
            sandbox_dir: seatbelt_path(&self.sandbox_dir),
            socket_dir: seatbelt_path(&self.socket_dir),
            audit_dir: seatbelt_path(&self.audit_dir),
            state_dir: seatbelt_path(&self.state_dir),
            profile: self.profile.clone(),
            custody_app: seatbelt_path(&self.custody_app),
            fido_emulator: self.fido_emulator,
            custody_authority: self.custody_authority.clone(),
            deployment: self.deployment.clone(),
        }
    }
}

/// The executable launchd starts for `d`.
pub fn program(d: DaemonId, l: &Layout) -> String {
    match d {
        DaemonId::CustodyVault => format!("{}/Contents/MacOS/{}", l.custody_app, d.binary()),
        _ => format!("{}/{}", l.bin_dir, d.binary()),
    }
}

fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// Group whose only member is `_enclavezk`: read access to every journal.
pub const JOURNAL_READ_GROUP: &str = "_enclave_journal_r";
/// Its GID (87xx block, outside the primary `8701..8705` and client
/// `8711..8716` groups).
pub const JOURNAL_READ_GID: u32 = 8720;

/// Daemon-specific arguments.
pub fn daemon_args(d: DaemonId, l: &Layout) -> Vec<String> {
    let mut a = vec![
        "--socket-dir".into(),
        l.socket_dir.clone(),
        "--audit-dir".into(),
        l.audit_dir.clone(),
        "--state-dir".into(),
        format!("{}/{}", l.state_dir, d.dir_name()),
        "--profile".into(),
        l.profile.clone(),
        "--sandbox-profile".into(),
        format!("{}/{}.sb", l.sandbox_dir, d.plist_suffix()),
    ];
    let st = &l.state_dir;
    match d {
        DaemonId::ModelRunner => {}
        DaemonId::SwarmSync => a.extend([
            "--store-dir".into(),
            l.cas_store(),
            "--tuf-root".into(),
            l.tuf_root(),
            "--tuf-repo".into(),
            format!("{st}/cas/tuf/repo"),
        ]),
        DaemonId::CustodyVault => a.extend([
            // GAP-13: `hid` (physical key) unless the emulator is deployed.
            "--yubikey-transport".into(),
            l.yubikey_transport(),
            "--mds-file".into(),
            l.support_file("fido-mds.json", FIDO_MDS_FILE),
            "--oidc-broker-config".into(),
            l.support_file("oidc-broker-identity.json", OIDC_IDENTITY_CONFIG),
        ]),
        DaemonId::AgentRuntime => {
            // GAP-06: the signed depot lock (a TUF target resolved by UID 702 in
            // Phase 2, GAP-20); absent ⇒ every tool is default-conservative.
            a.extend([
                "--policy-key-file".into(),
                format!("{st}/ifc/ifc-policy.key"),
                "--depot-lock-file".into(),
                format!("{st}/ifc/enclave-depot-lock.json"),
            ])
        }
        DaemonId::ZkAuditor => {
            a.extend(["--strike-file".into(), format!("{st}/zk/zk-strikes.json")])
        }
    }
    if d == DaemonId::CustodyVault {
        if let Some(config) = &l.custody_authority {
            a.extend([
                "--custody-authority-config".into(),
                config.manifest_path().display().to_string(),
            ]);
        }
    }
    l.append_deployment_args(&mut a, false);
    a
}

/// Allocator settings for every daemon, in its plist and in the dev fleet.
/// The physical-footprint ceilings (48 MiB for UIDs 701/702) count memory
/// the allocator keeps after `free`. On macOS 26 the default large-block
/// cache keeps freed large blocks resident (8 x 8 MiB freed stays 81 MiB)
/// and `malloc_zone_pressure_relief` does not release them, so a LLaDA bind
/// (6 MB tokenizer JSON, growing parse buffers) settled UID 701 at 48 MiB;
/// with the cache off it holds 12 MiB.
pub const DAEMON_MALLOC_ENV: [(&str, &str); 2] =
    [("MallocNanoZone", "0"), ("MallocLargeCache", "0")];

/// Render the plist for one daemon.
pub fn plist(d: DaemonId, l: &Layout) -> String {
    let label = l.job_label(&d.launchd_label());
    let bin = program(d, l);
    let sb = format!("{}/{}.sb", l.sandbox_dir, d.plist_suffix());
    let mut args = vec!["/usr/bin/sandbox-exec".to_owned(), "-f".into(), sb, bin];
    args.extend(daemon_args(d, l));
    let rss = d.rss_ceiling_bytes();
    let process_type = if d == DaemonId::CustodyVault {
        "Adaptive"
    } else {
        "Background"
    };
    let mut s = String::new();
    s.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\">\n<dict>\n");
    let _ = writeln!(s, "\t<key>Label</key>\n\t<string>{label}</string>");
    s.push_str("\t<key>ProgramArguments</key>\n\t<array>\n");
    for a in &args {
        let _ = writeln!(s, "\t\t<string>{}</string>", esc(a));
    }
    s.push_str("\t</array>\n");
    let _ = writeln!(s, "\t<key>UserName</key>\n\t<string>{0}</string>\n\t<key>GroupName</key>\n\t<string>{0}</string>", d.account());
    // InitGroups must stay true: socket access (client groups, GAP-01) and
    // UID 705's journal access (`_enclave_journal_r`, GAP-10) are
    // supplementary-group memberships, which launchd sets only via initgroups(3).
    s.push_str("\t<key>InitGroups</key>\n\t<true/>\n\t<key>RunAtLoad</key>\n\t<true/>\n");
    s.push_str("\t<key>KeepAlive</key>\n\t<dict>\n\t\t<key>SuccessfulExit</key>\n\t\t<false/>\n\t</dict>\n");
    s.push_str("\t<key>ThrottleInterval</key>\n\t<integer>30</integer>\n");
    let _ = writeln!(
        s,
        "\t<key>ProcessType</key>\n\t<string>{process_type}</string>"
    );
    s.push_str(
        "\t<key>LowPriorityIO</key>\n\t<true/>\n\t<key>Umask</key>\n\t<integer>63</integer>\n",
    );
    for k in ["SoftResourceLimits", "HardResourceLimits"] {
        let _ = writeln!(s, "\t<key>{k}</key>\n\t<dict>\n\t\t<key>Core</key>\n\t\t<integer>0</integer>\n\t\t<key>ResidentSetSize</key>\n\t\t<integer>{rss}</integer>\n\t\t<key>NumberOfFiles</key>\n\t\t<integer>256</integer>\n\t\t<key>NumberOfProcesses</key>\n\t\t<integer>1</integer>\n\t</dict>");
    }
    s.push_str("\t<key>EnvironmentVariables</key>\n\t<dict>\n");
    for (key, value) in DAEMON_MALLOC_ENV {
        let _ = writeln!(s, "\t\t<key>{key}</key>\n\t\t<string>{value}</string>");
    }
    s.push_str("\t</dict>\n");
    let _ = writeln!(s, "\t<key>StandardOutPath</key>\n\t<string>{0}/{1}/{2}.log</string>\n\t<key>StandardErrorPath</key>\n\t<string>{0}/{1}/{2}.log</string>", l.audit_dir, d.dir_name(), d.plist_suffix());
    s.push_str("</dict>\n</plist>\n");
    s
}

/// The root revocation supervisor (GAP-21, FS-702 §7.2): terminates holders
/// of revoked CAS inodes on behalf of UID 702. Root, not sandboxed (it must
/// enumerate other processes' descriptors with `proc_pidinfo`).
pub fn supervisor_plist(l: &Layout) -> String {
    let mut s = String::new();
    s.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\">\n<dict>\n");
    let _ = writeln!(
        s,
        "\t<key>Label</key>\n\t<string>{}</string>",
        l.job_label(enclave_core::supervisor::LAUNCHD_LABEL)
    );
    s.push_str("\t<key>ProgramArguments</key>\n\t<array>\n");
    let mut args = vec![
        format!("{}/depot-enclave", l.bin_dir),
        "--profile".into(),
        l.profile.clone(),
        "supervise".into(),
        "--socket-dir".into(),
        l.socket_dir.clone(),
    ];
    l.append_deployment_args(&mut args, true);
    for a in args {
        let _ = writeln!(s, "\t\t<string>{}</string>", esc(&a));
    }
    s.push_str("\t</array>\n\t<key>UserName</key>\n\t<string>root</string>\n\t<key>RunAtLoad</key>\n\t<true/>\n");
    s.push_str("\t<key>KeepAlive</key>\n\t<true/>\n\t<key>ThrottleInterval</key>\n\t<integer>10</integer>\n\t<key>ProcessType</key>\n\t<string>Interactive</string>\n");
    let _ = write!(
        s,
        "\t<key>MachServices</key>\n\t<dict>\n\t\t<key>{}</key>\n\t\t<true/>\n\t</dict>\n",
        esc(l.mach_service())
    );
    let _ = writeln!(s, "\t<key>StandardOutPath</key>\n\t<string>{0}/supervisor.log</string>\n\t<key>StandardErrorPath</key>\n\t<string>{0}/supervisor.log</string>", l.audit_dir);
    s.push_str("</dict>\n</plist>\n");
    s
}

/// L3 root publisher. Confinement is applied in-process from independently
/// verified exact routing before the selected socket is bound. The optional
/// descriptor selects the complete protected route; arbitrary path argv is refused.
pub fn apfs_broker_plist(l: &Layout) -> String {
    let label = l.job_label("com.enterprise.enclave.apfs-broker");
    let mut extra = String::new();
    if let Some(checked) = &l.deployment {
        extra = format!(
            "<string>--deployment-target</string><string>{}</string>",
            esc(&checked.config_path().display().to_string())
        );
    }
    let audit = if l.deployment.is_some() {
        format!("{}/apfs-broker/broker.log", l.audit_dir)
    } else {
        "/var/log/enclave/apfs-broker/broker.log".into()
    };
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>{label}</string>
<key>ProgramArguments</key><array><string>{}/enclave-apfs-broker</string>{extra}</array>
<key>UserName</key><string>root</string>
<key>GroupName</key><string>wheel</string>
<key>RunAtLoad</key><true/><key>KeepAlive</key><true/>
<key>ThrottleInterval</key><integer>10</integer>
<key>WorkingDirectory</key><string>/</string>
<key>Umask</key><integer>63</integer>
<key>SoftResourceLimits</key><dict><key>Core</key><integer>0</integer><key>NumberOfFiles</key><integer>64</integer></dict>
<key>HardResourceLimits</key><dict><key>Core</key><integer>0</integer><key>NumberOfFiles</key><integer>128</integer></dict>
<key>StandardOutPath</key><string>{audit}</string>
<key>StandardErrorPath</key><string>{audit}</string>
</dict></plist>
"#,
        esc(&l.bin_dir),
        label = esc(&label),
        audit = esc(&audit)
    )
}

/// The `_enclaveintent` biometric helper LaunchAgent (GAP-14, FS-703 §5.1):
/// runs in the console user's Aqua GUI session, serving an authenticated socket.
pub fn intent_plist(l: &Layout) -> String {
    let mut s = String::new();
    s.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\">\n<dict>\n");
    let label = l.job_label(INTENT_LABEL);
    let _ = writeln!(s, "\t<key>Label</key>\n\t<string>{label}</string>");
    s.push_str("\t<key>ProgramArguments</key>\n\t<array>\n");
    let mut args = vec![
        format!("{}/{}", l.bin_dir, INTENT_BINARY),
        "--socket".into(),
        l.intent_socket(),
    ];
    if l.deployment.is_some() {
        args.extend([
            "--supervisor-socket".into(),
            format!("{}/supervisor/supervisor.sock", l.socket_dir),
        ]);
    }
    l.append_deployment_args(&mut args, false);
    for a in args {
        let _ = writeln!(s, "\t\t<string>{}</string>", esc(&a));
    }
    s.push_str("\t</array>\n\t<key>RunAtLoad</key>\n\t<true/>\n");
    s.push_str("\t<key>KeepAlive</key>\n\t<true/>\n\t<key>ThrottleInterval</key>\n\t<integer>1</integer>\n\t<key>ProcessType</key>\n\t<string>Interactive</string>\n");
    let _ = writeln!(
        s,
        "\t<key>StandardOutPath</key>\n\t<string>{0}/intent.log</string>\n\t<key>StandardErrorPath</key>\n\t<string>{0}/intent.log</string>",
        l.audit_dir
    );
    s.push_str("</dict>\n</plist>\n");
    s
}

/// A separate Aqua-session process owns browser state. Missing or stale root
/// configuration refuses once; KeepAlive is disabled to avoid a restart loop.
pub fn oidc_plist() -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>{OIDC_LABEL}</string>
<key>ProgramArguments</key><array>
<string>{OIDC_APP}/Contents/MacOS/enclave-oidc</string>
<string>--identity-config</string><string>{OIDC_IDENTITY_CONFIG}</string>
<string>--oauth-config</string><string>{OIDC_OAUTH_CONFIG}</string>
</array>
<key>LimitLoadToSessionType</key><string>Aqua</string>
<key>RunAtLoad</key><true/>
<key>KeepAlive</key><false/>
<key>ProcessType</key><string>Interactive</string>
<key>SoftResourceLimits</key><dict><key>Core</key><integer>0</integer></dict>
<key>HardResourceLimits</key><dict><key>Core</key><integer>0</integer></dict>
</dict></plist>
"#
    )
}

/// The same separate OIDC actor with explicit target-local public config paths.
/// The protected descriptor binds its config, socket and code-pin routes.
pub fn oidc_plist_for_layout(l: &Layout) -> String {
    let Some(checked) = &l.deployment else { return oidc_plist(); };
    oidc_plist()
        .replace(
            &format!("<string>{OIDC_LABEL}</string>"),
            &format!("<string>{}</string>", esc(&l.job_label(OIDC_LABEL))),
        )
        .replace(OIDC_APP, &esc(&l.support_file("EnclaveOIDC.app", OIDC_APP)))
        .replace(
            OIDC_IDENTITY_CONFIG,
            &esc(&l.support_file("oidc-broker-identity.json", OIDC_IDENTITY_CONFIG)),
        )
        .replace(
            OIDC_OAUTH_CONFIG,
            &esc(&l.support_file("oidc-oauth.json", OIDC_OAUTH_CONFIG)),
        )
        .replace(
            "</array>",
            &format!(
                "<string>--deployment-target</string><string>{}</string>\n</array>",
                esc(&checked.config_path().display().to_string())
            ),
        )
}

/// The detached model hydration worker LaunchDaemon (FS-706 §3.3, D-R8):
/// runs as `_enclavecas` to process async hydration requests in the background.
pub fn hydrate_plist(l: &Layout) -> String {
    let mut s = String::new();
    s.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\">\n<dict>\n");
    let label = l.job_label(HYDRATE_LABEL);
    let _ = writeln!(s, "\t<key>Label</key>\n\t<string>{label}</string>");
    s.push_str("\t<key>ProgramArguments</key>\n\t<array>\n");
    let mut args = vec![
        format!("{}/depot-enclave", l.bin_dir),
        "deploy".into(),
        "hydrate-worker".into(),
    ];
    if l.deployment.is_some() {
        args.extend([
            "--profile".into(),
            l.profile.clone(),
            "--jobs-dir".into(),
            format!("{}/jobs", l.socket_dir),
            "--cas-dir".into(),
            l.cas_store(),
        ]);
    }
    l.append_deployment_args(&mut args, true);
    for a in args {
        let _ = writeln!(s, "\t\t<string>{}</string>", esc(&a));
    }
    s.push_str("\t</array>\n");
    let _ = writeln!(
        s,
        "\t<key>UserName</key>\n\t<string>{}</string>\n\t<key>GroupName</key>\n\t<string>{}</string>",
        DaemonId::SwarmSync.account(),
        DaemonId::SwarmSync.account()
    );
    s.push_str("\t<key>WatchPaths</key>\n\t<array>\n");
    let _ = writeln!(s, "\t\t<string>{}/jobs</string>", esc(&l.socket_dir));
    s.push_str("\t</array>\n\t<key>ThrottleInterval</key>\n\t<integer>2</integer>\n");
    let _ = writeln!(
        s,
        "\t<key>StandardOutPath</key>\n\t<string>{0}/hydrate.log</string>\n\t<key>StandardErrorPath</key>\n\t<string>{0}/hydrate.log</string>",
        l.audit_dir
    );
    s.push_str("</dict>\n</plist>\n");
    s
}

/// Root-owned FIDO MDS allowlist UID 703 checks authenticators against
/// (until UID 702 delivers it as a TUF target, GAP-20).
pub const FIDO_MDS_FILE: &str = "/Library/Application Support/EnterpriseEnclave/fido-mds.json";

/// The CTAPHID emulator (GAP-13): its own account, Seatbelt profile, socket
/// and state, exactly where a physical key would be a separate device.
pub fn fido_plist(l: &Layout) -> String {
    let fido_dir = fido::EMULATOR_SOCKET_DIR;
    let args = [
        "/usr/bin/sandbox-exec".to_owned(),
        "-f".into(),
        format!("{}/{fido_dir}.sb", l.sandbox_dir),
        format!("{}/{FIDO_BINARY}", l.bin_dir),
        "--socket".into(),
        l.fido_socket(),
        "--state".into(),
        format!("{}/{fido_dir}/emulator.state", l.state_dir),
        "--mds-out".into(),
        format!("{}/{fido_dir}/mds-entry.json", l.state_dir),
    ];
    let mut s = String::new();
    s.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\">\n<dict>\n");
    let _ = writeln!(s, "\t<key>Label</key>\n\t<string>{FIDO_LABEL}</string>");
    s.push_str("\t<key>ProgramArguments</key>\n\t<array>\n");
    for a in &args {
        let _ = writeln!(s, "\t\t<string>{}</string>", esc(a));
    }
    s.push_str("\t</array>\n");
    let _ = writeln!(s, "\t<key>UserName</key>\n\t<string>{0}</string>\n\t<key>GroupName</key>\n\t<string>{0}</string>", fido::EMULATOR_ACCOUNT);
    s.push_str("\t<key>InitGroups</key>\n\t<true/>\n\t<key>RunAtLoad</key>\n\t<true/>\n");
    s.push_str("\t<key>KeepAlive</key>\n\t<dict>\n\t\t<key>SuccessfulExit</key>\n\t\t<false/>\n\t</dict>\n");
    s.push_str("\t<key>ThrottleInterval</key>\n\t<integer>10</integer>\n\t<key>ProcessType</key>\n\t<string>Background</string>\n\t<key>Umask</key>\n\t<integer>63</integer>\n");
    for k in ["SoftResourceLimits", "HardResourceLimits"] {
        let _ = writeln!(
            s,
            "\t<key>{k}</key>\n\t<dict>\n\t\t<key>Core</key>\n\t\t<integer>0</integer>\n\t</dict>"
        );
    }
    let _ = writeln!(s, "\t<key>StandardOutPath</key>\n\t<string>{0}/{fido_dir}/{fido_dir}.log</string>\n\t<key>StandardErrorPath</key>\n\t<string>{0}/{fido_dir}/{fido_dir}.log</string>", l.audit_dir);
    s.push_str("</dict>\n</plist>\n");
    s
}

/// Deny-by-default Seatbelt profile of the CTAPHID emulator: its own
/// socket, state and log directories, nothing else (no network, no IOKit).
pub fn fido_sandbox_profile(l: &Layout) -> String {
    let l = &l.for_seatbelt();
    let d = fido::EMULATOR_SOCKET_DIR;
    let exe = format!("{}/{FIDO_BINARY}", l.bin_dir);
    let mut s = format!(";; {FIDO_LABEL} — {FIDO_BINARY} (UID {}). Deny by default.\n(version 1)\n(deny default)\n(import \"bsd.sb\")\n", fido::EMULATOR_UID);
    let _ = writeln!(
        s,
        "(allow process-exec (literal \"{exe}\"))\n(allow file-read* (literal \"{exe}\"))"
    );
    s.push_str("(allow signal (target self))\n(allow sysctl-read)\n");
    let _ = writeln!(
        s,
        "(allow file-read-metadata (literal \"{0}\") (literal \"{1}\") (literal \"{2}\"))",
        l.socket_dir, l.audit_dir, l.state_dir
    );
    let _ = writeln!(s, "(allow file-read* file-write* (subpath \"{0}/{d}\") (subpath \"{1}/{d}\") (subpath \"{2}/{d}\"))", l.socket_dir, l.audit_dir, l.state_dir);
    let _ = writeln!(
        s,
        "(allow network-bind network-inbound (local unix-socket (subpath \"{}/{d}\")))",
        l.socket_dir
    );
    s
}

/// Dedicated console ingress LaunchDaemon, outside DaemonId's five roles.
pub fn gateway_plist(l: &Layout) -> String {
    use enclave_core::daemon::{GATEWAY_ACCOUNT, GATEWAY_BINARY, GATEWAY_IDENTIFIER};
    let mut args = vec![
        format!("{}/{}", l.bin_dir, GATEWAY_BINARY),
        "--socket-dir".into(),
        l.socket_dir.clone(),
        "--sandbox-profile".into(),
        format!("{}/gateway.sb", l.sandbox_dir),
    ];
    if l.deployment.is_some() {
        args.extend([
            "--profile".into(),
            l.profile.clone(),
            "--audit-dir".into(),
            l.audit_dir.clone(),
        ]);
    }
    l.append_deployment_args(&mut args, false);
    let mut s =
        String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<plist version=\"1.0\"><dict>\n");
    let label = l.job_label(GATEWAY_IDENTIFIER);
    let _ = writeln!(
        s,
        "<key>Label</key><string>{label}</string>\n<key>ProgramArguments</key><array>"
    );
    for arg in args {
        let _ = writeln!(s, "<string>{}</string>", esc(&arg));
    }
    let _=writeln!(s,"</array><key>UserName</key><string>{GATEWAY_ACCOUNT}</string><key>GroupName</key><string>{GATEWAY_ACCOUNT}</string>");
    s.push_str("<key>InitGroups</key><true/><key>RunAtLoad</key><true/><key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict><key>ThrottleInterval</key><integer>30</integer><key>ProcessType</key><string>Background</string><key>Umask</key><integer>63</integer>\n");
    for limits in ["SoftResourceLimits", "HardResourceLimits"] {
        let _ = writeln!(
            s,
            "<key>{limits}</key><dict><key>Core</key><integer>0</integer></dict>"
        );
    }
    for log in ["StandardOutPath", "StandardErrorPath"] {
        let _ = writeln!(
            s,
            "<key>{log}</key><string>{}/gateway/gateway.log</string>",
            esc(&l.audit_dir)
        );
    }
    s.push_str("</dict></plist>\n");
    s
}

/// Deny-by-default ingress profile: local clients and runtime only, no IP sockets.
pub fn gateway_sandbox_profile(l: &Layout) -> String {
    let l = l.for_seatbelt();
    let binary = format!("{}/{}", l.bin_dir, enclave_core::daemon::GATEWAY_BINARY);
    let pins = seatbelt_path(&l.pin_file());
    let pin_directory = Path::new(&pins)
        .parent()
        .unwrap_or(Path::new("/"))
        .display()
        .to_string();
    let mut profile = format!(
        r#";; Console ingress: socket is connectable but every peer is UID+code authenticated.
(version 1)
(deny default)
(import "bsd.sb")
(allow process-exec (literal "{binary}"))
(allow file-read* (subpath "{bin}") (subpath "/usr/lib") (subpath "/System/Library"))
(allow file-read* (literal "{pins}") (literal "/dev/urandom") (literal "/dev/random"))
(allow file-read-metadata (literal "/dev/console") (literal "{sock}") (literal "{sock}/ifc") (literal "{sock}/ifc/ifc.sock") (literal "{pin_directory}"))
(allow file-read* file-write* (subpath "{sock}/gateway"))
(allow network-bind network-inbound (local unix-socket (subpath "{sock}/gateway")))
(allow network-outbound (remote unix-socket (literal "{sock}/ifc/ifc.sock")))
(allow mach-lookup (global-name "com.apple.SecurityServer") (global-name "com.apple.securityd.xpc"))
(allow signal (target self))
(allow sysctl-read)
"#,
        bin = l.bin_dir,
        sock = l.socket_dir
    );
    l.deployment_read_rules(&mut profile);
    profile
}

/// The sandboxed CDP browser LaunchDaemon (GAP-34).
pub fn browser_plist(l: &Layout) -> String {
    let d = BROWSER_SOCKET_DIR;
    let mut args = vec![
        "/usr/bin/sandbox-exec".to_owned(),
        "-f".into(),
        format!("{}/{d}.sb", l.sandbox_dir),
        format!("{}/{}", l.bin_dir, BROWSER_BINARY),
        "--socket".into(),
        l.browser_socket(),
        "--throwaway-dir".into(),
        format!("{}/{d}", l.state_dir),
    ];
    if l.deployment.is_some() {
        args.extend(["--profile".into(), l.profile.clone()]);
    }
    l.append_deployment_args(&mut args, false);
    let mut s = String::new();
    s.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\">\n<dict>\n");
    let label = l.job_label(BROWSER_LABEL);
    let _ = writeln!(s, "\t<key>Label</key>\n\t<string>{label}</string>");
    s.push_str("\t<key>ProgramArguments</key>\n\t<array>\n");
    for a in &args {
        let _ = writeln!(s, "\t\t<string>{}</string>", esc(a));
    }
    s.push_str("\t</array>\n");
    let _ = writeln!(
        s,
        "\t<key>UserName</key>\n\t<string>{0}</string>\n\t<key>GroupName</key>\n\t<string>{0}</string>",
        enclave_core::daemon::BROWSER_ACCOUNT
    );
    s.push_str("\t<key>InitGroups</key>\n\t<true/>\n\t<key>RunAtLoad</key>\n\t<true/>\n");
    s.push_str("\t<key>KeepAlive</key>\n\t<dict>\n\t\t<key>SuccessfulExit</key>\n\t\t<false/>\n\t</dict>\n");
    s.push_str("\t<key>ThrottleInterval</key>\n\t<integer>10</integer>\n\t<key>ProcessType</key>\n\t<string>Background</string>\n\t<key>Umask</key>\n\t<integer>63</integer>\n");
    for k in ["SoftResourceLimits", "HardResourceLimits"] {
        let _ = writeln!(
            s,
            "\t<key>{k}</key>\n\t<dict>\n\t\t<key>Core</key>\n\t\t<integer>0</integer>\n\t</dict>"
        );
    }
    let _ = writeln!(
        s,
        "\t<key>StandardOutPath</key>\n\t<string>{0}/{d}/{d}.log</string>\n\t<key>StandardErrorPath</key>\n\t<string>{0}/{d}/{d}.log</string>",
        l.audit_dir
    );
    s.push_str("</dict>\n</plist>\n");
    s
}

/// Deny-by-default Seatbelt profile of the sandboxed CDP browser (GAP-34).
pub fn browser_sandbox_profile(l: &Layout) -> String {
    let l = &l.for_seatbelt();
    let d = BROWSER_SOCKET_DIR;
    let exe = format!("{}/{}", l.bin_dir, BROWSER_BINARY);
    let mut s = format!(
        ";; {BROWSER_LABEL} — {BROWSER_BINARY} (UID {}). Deny by default.\n(version 1)\n(deny default)\n(import \"bsd.sb\")\n",
        enclave_core::daemon::BROWSER_UID
    );
    let _ = writeln!(
        s,
        "(allow process-exec (literal \"{exe}\"))\n(allow file-read* (literal \"{exe}\"))"
    );
    s.push_str("(allow signal (target self))\n(allow sysctl-read)\n");
    let _ = writeln!(
        s,
        "(allow file-read-metadata (literal \"{0}\") (literal \"{1}\") (literal \"{2}\"))",
        l.socket_dir, l.audit_dir, l.state_dir
    );
    let _ = writeln!(
        s,
        "(allow file-read* file-write* (subpath \"{0}/{d}\") (subpath \"{1}/{d}\") (subpath \"{2}/{d}\"))",
        l.socket_dir, l.audit_dir, l.state_dir
    );
    let _ = writeln!(
        s,
        "(allow network-bind network-inbound (local unix-socket (subpath \"{}/{d}\")))",
        l.socket_dir
    );
    if l.deployment.is_some() {
        let support = seatbelt_path(&l.support_file("browser", ""));
        let _ = writeln!(s, "(allow process-exec (literal \"{support}/Google Chrome.app/Contents/MacOS/Google Chrome\") (literal \"{support}/Chromium.app/Contents/MacOS/Chromium\"))");
        let _ = writeln!(s, "(allow file-read* (subpath \"{support}/Google Chrome.app\") (subpath \"{support}/Chromium.app\"))");
        l.deployment_read_rules(&mut s);
    } else {
        s.push_str("(allow file-read* file-write* (subpath \"/private/tmp/enclave-browser\"))\n");
        s.push_str("(allow process-exec (literal \"/Library/Application Support/EnterpriseEnclave/browser/Google Chrome.app/Contents/MacOS/Google Chrome\") (literal \"/Library/Application Support/EnterpriseEnclave/browser/Chromium.app/Contents/MacOS/Chromium\"))\n");
        s.push_str("(allow file-read* (subpath \"/Library/Application Support/EnterpriseEnclave/browser/Google Chrome.app\") (subpath \"/Library/Application Support/EnterpriseEnclave/browser/Chromium.app\"))\n");
    }
    s
}

/// Deny-by-default Seatbelt profile.
pub fn sandbox_profile(d: DaemonId, l: &Layout) -> String {
    let l = &l.for_seatbelt();
    let mut s = format!(
        ";; {} — {} (UID {}). Deny by default.\n(version 1)\n(deny default)\n",
        d.launchd_label(),
        d.binary(),
        d.uid()
    );
    // Apple's BSD baseline (dyld shared cache, libSystem, notifyd, opendirectoryd
    // for initgroups); everything daemon-specific is listed explicitly below.
    s.push_str("(import \"bsd.sb\")\n");
    let exe = program(d, l);
    let _ = writeln!(
        s,
        "(allow process-exec (literal \"{exe}\"))\n(allow file-read* (literal \"{exe}\"))\n;; Peer executable code signature reading (SecCodeCopyGuestWithAttributes)\n(allow file-read* (subpath \"{0}\"))\n(allow file-read* (subpath \"{1}\"))",
        l.bin_dir,
        l.custody_app
    );
    let _ = writeln!(s, ";; Reapply the same root-provisioned confinement in shared runtime (FUNC-005).\n(allow file-read* (literal \"{}/{}.sb\"))\n(allow file-read-metadata (subpath \"{}\"))", l.sandbox_dir, d.plist_suffix(), l.sandbox_dir);
    // The secure loader opens held directory FDs with O_RDONLY|O_DIRECTORY.
    // Seatbelt requires file-read-data even though no directory entries are
    // enumerated. Literal directories grant neither child-file reads nor writes.
    for parent in Path::new(&l.sandbox_dir).ancestors() {
        let _ = writeln!(
            s,
            "(allow file-read-data file-read-metadata (literal \"{}\"))",
            parent.display()
        );
    }
    // Ad-hoc installs authenticate peers by the root-owned cdhash pins.
    let pins = seatbelt_path(&l.pin_file());
    let pin_dir = std::path::Path::new(&pins)
        .parent()
        .map(|p| p.display().to_string())
        .unwrap_or_default();
    let _ = writeln!(s, "(allow file-read* (literal \"{pins}\"))\n(allow file-read-metadata (literal \"{pin_dir}\"))");
    l.deployment_read_rules(&mut s);
    s.push_str("(allow signal (target self))\n(allow sysctl-read)\n(allow mach-lookup (global-name \"com.apple.system.logger\"))\n");
    s.push_str(";; Peer code-identity verification (Security.framework / SecCode)\n(allow mach-lookup (global-name \"com.apple.SecurityServer\") (global-name \"com.apple.securityd.xpc\"))\n");
    s.push_str(";; System power monitoring (GAP-16)\n(allow iokit-open (iokit-user-client-class \"IOPMrootDomain\"))\n(allow mach-lookup (global-name \"com.apple.iokit.powerdxpc\") (global-name \"com.apple.PowerManagement.control\"))\n");
    let _ = writeln!(
        s,
        ";; Supervisor Mach exception port (GAP-12)\n(allow mach-lookup (global-name \"{}\"))",
        l.mach_service()
    );
    s.push_str("(allow file-read* (subpath \"/usr/lib\") (subpath \"/System/Library\") (literal \"/dev/urandom\") (literal \"/dev/random\"))\n");
    if d == DaemonId::SwarmSync && l.profile == "L3" {
        let _=writeln!(s,"(allow file-read-metadata (subpath \"{0}/apfs-broker\"))\n(allow network-outbound (remote unix-socket (literal \"{0}/apfs-broker/broker.sock\")))",l.socket_dir);
    }
    // GAP-01 / GAP-36: write access only to this daemon's own socket and
    // journal directories; the rest of the mesh is read-only (connect needs
    // only path traversal, which POSIX modes then restrict to client groups).
    let _ = writeln!(
        s,
        "(allow file-read-metadata (literal \"{0}\") (literal \"{1}\"))",
        l.socket_dir, l.audit_dir
    );
    let _ = writeln!(
        s,
        "(allow file-read* file-write* (subpath \"{0}/{2}\") (subpath \"{1}/{2}\"))",
        l.socket_dir,
        l.audit_dir,
        d.dir_name()
    );
    let _ = writeln!(
        s,
        "(allow file-read* file-write* (subpath \"{}/{}\"))",
        l.state_dir,
        d.dir_name()
    );
    let _ = writeln!(
        s,
        "(allow network-bind network-inbound (local unix-socket (subpath \"{}/{}\")))",
        l.socket_dir,
        d.dir_name()
    );
    let _ = writeln!(
        s,
        "(allow network-outbound (remote unix-socket (subpath \"{}\")))",
        l.socket_dir
    );
    match d {
        DaemonId::SwarmSync => {
            let _ = writeln!(
                s,
                "(allow file-read* (literal \"{}\"))",
                seatbelt_path(&l.tuf_root())
            );
            let _ = writeln!(
                s,
                "(allow file-read* file-write* (subpath \"{}\"))",
                seatbelt_path(&l.cas_store())
            );
            s.push_str(";; Profile-selected distribution egress: no inbound network in L1 or L3.\n(allow network-outbound (remote tcp \"*:443\") (remote udp \"*:443\"))\n");
            if l.profile.eq_ignore_ascii_case("L2") {
                s.push_str(";; Authenticated L2 QUIC bind and inbound only.\n(allow network-bind network-inbound (local udp \"*:4433\"))\n");
                s.push_str(";; L2 authenticated peer clients use the same declared QUIC port.\n(allow network-outbound (remote udp \"*:4433\"))\n");
            }
            s.push_str(";; Zero-listener enforcement inspects this process's descriptors.\n(allow process-info-pidinfo (target self))\n(allow system-socket)\n");
        }
        DaemonId::AgentRuntime => {
            s.push_str(";; F71: positively bind incarnation watches before recoverable turn allocation.\n(allow process-info-pidinfo)\n");
        }
        DaemonId::ZkAuditor => {
            // GAP-10: the prover reads every journal itself (read-only) and binds the dedicated witness channel.
            let _ = writeln!(s, ";; Epoch witnesses come from the daemon journals, never from callers.\n(allow file-read* (subpath \"{}\"))", l.audit_dir);
            let _ = writeln!(
                s,
                ";; Dedicated witness socket channel (GAP-10).\n(allow file-read* file-write* (subpath \"{0}/{1}\"))\n(allow network-bind network-inbound (local unix-socket (subpath \"{0}/{1}\")))",
                l.socket_dir,
                enclave_core::daemon::WITNESS_SOCKET_DIR
            );
        }
        DaemonId::CustodyVault => {
            if let Some(config) = &l.custody_authority {
                s.push_str(";; Complete root-protected public custody authority; no recursive read or write grants.\n");
                for path in config.read_paths() {
                    let path = seatbelt_path(&path.display().to_string());
                    let _ = writeln!(s, "(allow file-read* (literal \"{path}\"))");
                }
                // The protected reader opens held directory FDs with O_DIRECTORY.
                // Literal directory reads do not permit reading their children.
                for parent in config.ancestor_paths() {
                    let path = seatbelt_path(&parent.display().to_string());
                    let _ = writeln!(
                        s,
                        "(allow file-read-data file-read-metadata (literal \"{path}\"))"
                    );
                }
            }
            // GAP-15: Security.framework + CryptoTokenKit reach the Secure
            // Enclave through securityd and ctkd; the bundle's own signature
            // is read to establish the key's owning identity.
            let _ = writeln!(s, ";; Secure Enclave keys (GAP-15): securityd, CryptoTokenKit, the bundle's own signature.\n(allow file-read* (subpath \"{}\"))", l.custody_app);
            let oidc_identity =
                seatbelt_path(&l.support_file("oidc-broker-identity.json", OIDC_IDENTITY_CONFIG));
            let _ = writeln!(s, ";; Public protected OIDC peer/session binding.\n(allow file-read* (literal \"{oidc_identity}\"))");
            s.push_str("(allow mach-lookup (global-name \"com.apple.SecurityServer\") (global-name \"com.apple.securityd.xpc\") (global-name \"com.apple.ctkd.token-client\") (global-name \"com.apple.CoreAuthentication.daemon\") (global-name \"com.apple.coreauthd\"))\n");
            let mds = seatbelt_path(&l.support_file("fido-mds.json", FIDO_MDS_FILE));
            let _ = writeln!(
                s,
                ";; FIDO MDS allowlist (GAP-13).\n(allow file-read* (literal \"{mds}\"))"
            );
            s.push_str(";; CTAPHID over IOKit HID (YubiKey) incl. USB attach/detach notifications (GAP-13, GAP-16).\n(allow iokit-open (iokit-user-client-class \"IOHIDLibUserClient\"))\n(allow iokit-get-properties)\n");
        }
        DaemonId::ModelRunner => {
            s.push_str(";; Weights arrive only as read-only SCM_RIGHTS FDs from UID 702.\n");
            s.push_str(";; Metal and MLX GPU/ANE execution services (GAP-17).\n");
            s.push_str("(allow iokit-open (iokit-user-client-class \"AGXDeviceUserClient\") (iokit-user-client-class \"IOAccelerator\") (iokit-user-client-class \"IOSurfaceRootUserClient\"))\n");
            s.push_str("(allow mach-lookup (global-name \"com.apple.AGXCompilerService\"))\n");
            s.push_str(";; Thermal pressure (notifyd) and power-source state (IOPS) for the speculative class (GAP-37).\n(allow mach-lookup (global-name \"com.apple.system.notification_center\") (global-name \"com.apple.iokit.powerdxpc\") (global-name \"com.apple.PowerManagement.control\"))\n");
        }
    }
    s
}

/// Hardened-runtime entitlements (zero-JIT, no unsigned executable memory,
/// library validation on, no debugger attach).
pub fn entitlements() -> String {
    let mut s = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\">\n<dict>\n");
    for k in [
        "com.apple.security.cs.allow-jit",
        "com.apple.security.cs.allow-unsigned-executable-memory",
        "com.apple.security.cs.allow-dyld-environment-variables",
        "com.apple.security.cs.disable-library-validation",
        "com.apple.security.cs.disable-executable-page-protection",
        "com.apple.security.cs.debugger",
        "com.apple.security.get-task-allow",
    ] {
        let _ = writeln!(s, "\t<key>{k}</key>\n\t<false/>");
    }
    s.push_str("</dict>\n</plist>\n");
    s
}

/// Account helpers shared by every generated provisioning script.
const PROVISION_HELPERS: &str = r#"say() { echo "provision: $*"; }
die() { echo "provision: $*; refusing to continue" >&2; exit 1; }
dsval() { # Groups|Users name attr -> first value, empty if absent
  dscl . -read "/$1/$2" "$3" 2>/dev/null | awk 'NR == 1 { print $2 }'
}
dsowner() { # Groups|Users attr id -> name of the record holding id
  dscl . -list "/$1" "$2" 2>/dev/null | awk -v id="$3" '$2 == id { print $1; exit }'
}
mkgroup() { # name gid
  if [ "$OS" = Darwin ]; then
    cur=$(dsval Groups "$1" PrimaryGroupID)
    [ -z "$cur" ] || [ "$cur" = "$2" ] || die "group $1 exists with gid $cur, expected $2"
    own=$(dsowner Groups PrimaryGroupID "$2")
    [ -z "$own" ] || [ "$own" = "$1" ] || die "gid $2 already belongs to group $own (wanted $1)"
    if [ -n "$cur" ]; then say "group $1 ($2) present"; else say "create group $1 ($2)"; fi
    dscl . -create "/Groups/$1" PrimaryGroupID "$2"
    dscl . -create "/Groups/$1" RealName "$1"
    dscl . -create "/Groups/$1" Password '*'
  else
    getent group "$1" >/dev/null || groupadd -g "$2" "$1"
  fi
}
mkuser() { # name uid primary-gid
  if [ "$OS" = Darwin ]; then
    cur=$(dsval Users "$1" UniqueID)
    [ -z "$cur" ] || [ "$cur" = "$2" ] || die "user $1 exists with uid $cur, expected $2"
    own=$(dsowner Users UniqueID "$2")
    [ -z "$own" ] || [ "$own" = "$1" ] || die "uid $2 already belongs to user $own (wanted $1)"
    if [ -n "$cur" ]; then say "user $1 ($2) present"; else say "create user $1 ($2)"; fi
    dscl . -create "/Users/$1" UniqueID "$2"
    dscl . -create "/Users/$1" PrimaryGroupID "$3"
    dscl . -create "/Users/$1" RealName "$1"
    dscl . -create "/Users/$1" UserShell /usr/bin/false
    dscl . -create "/Users/$1" NFSHomeDirectory /var/empty
    dscl . -create "/Users/$1" IsHidden 1
    dscl . -create "/Users/$1" Password '*'
  else
    getent passwd "$1" >/dev/null || useradd -r -M -u "$2" -g "$3" -s /usr/sbin/nologin -d /nonexistent "$1"
  fi
}
"#;

/// Root-run provisioning for accounts, client groups and directories
/// (GAP-01, GAP-36). Idempotent. macOS uses `dscl`; the Linux branch exists
/// for the CI VM that runs the multi-UID fleet test.
///
/// * one account per daemon (`UID 701..705`) with its own primary group
///   (`GID 8701..8705`; macOS File Sharing owns 7xx GIDs);
/// * one client group per server (`GID 8711..8715`) whose members are exactly
///   the accounts allowed to call it by `ipc::production_policy`;
/// * `<socket_dir>` and `<audit_dir>` `root:wheel 0755`;
/// * `<socket_dir>/<suffix>` `daemon:<client group> 2750`;
/// * `<audit_dir>/<suffix>` `daemon:_enclave_journal_r 2750` — journals are
///   `0640`, so only `_enclavezk` (the group's sole member) reads them (GAP-10);
/// * `<state_dir>/<suffix>` `daemon:daemon 0700`.
pub fn provision_script(l: &Layout) -> String {
    let mut s = String::from("#!/bin/sh\n# Generated by `depot-enclave launchd render` — do not edit (GAP-01, GAP-36).\n# Provisions daemon accounts, socket client groups and per-daemon directories.\nset -eu\n[ \"$(id -u)\" -eq 0 ] || { echo \"provision: must run as root\" >&2; exit 1; }\nOS=$(uname -s)\n\n");
    // GAP-36: idempotent per attribute (`dscl -create <record> <attr>`
    // creates a missing record and never fails on an existing one), and it
    // refuses, naming the conflict, to adopt a name or ID that already
    // belongs to something else.
    s.push_str(PROVISION_HELPERS);
    s.push_str("addmember() { # group user\n  if [ \"$OS\" = Darwin ]; then dseditgroup -o checkmember -m \"$2\" \"$1\" >/dev/null 2>&1 || { say \"add $2 to $1\"; dseditgroup -o edit -a \"$2\" -t user \"$1\"; }; else usermod -a -G \"$1\" \"$2\"; fi\n}\n");
    s.push_str("mkdirp() { # path owner group mode\n  mkdir -p \"$1\"; chown \"$2:$3\" \"$1\"; chmod \"$4\" \"$1\"\n}\nWHEEL=wheel; [ \"$OS\" = Darwin ] || WHEEL=root\n\n");
    for d in DaemonId::ALL {
        let _ = writeln!(
            s,
            "mkgroup {0} {2}\nmkuser {0} {1} {2}",
            d.account(),
            d.uid(),
            d.gid()
        );
    }
    let _ = writeln!(
        s,
        "mkgroup {account} {gid}\nmkuser {account} {uid} {gid}",
        account = enclave_core::daemon::GATEWAY_ACCOUNT,
        gid = enclave_core::daemon::GATEWAY_GID,
        uid = enclave_core::daemon::GATEWAY_UID
    );
    s.push('\n');
    for server in DaemonId::ALL {
        let _ = writeln!(
            s,
            "mkgroup {} {}",
            server.client_group(),
            server.client_gid()
        );
        for c in enclave_core::ipc::production_policy(server).allowed_uids {
            if let Some(cd) = DaemonId::from_uid(c) {
                let _ = writeln!(s, "addmember {} {}", server.client_group(), cd.account());
            }
        }
    }
    if l.profile == "L3" {
        if let Some(checked) = &l.deployment {
            if let Some(broker) = &checked.target().broker {
                let base = broker.base_dir.display();
                let _ = writeln!(s, "\n# Restricted L3 APFS broker; dedicated APFS volumes are provisioned independently.\nmkdirp {0}/apfs-broker root _enclavecas 2750\nmkdirp {base} root \"$WHEEL\" 0700\nmkdirp {base}/state root \"$WHEEL\" 0700\nmkdirp {base}/tuf root \"$WHEEL\" 0700\nmkdirp {base}/tuf/repo root \"$WHEEL\" 0700\nmkdirp {1}/apfs-broker root \"$WHEEL\" 0700", l.socket_dir, l.audit_dir);
            }
        } else {
            s.push_str("\n# Restricted L3 APFS broker; dedicated APFS volumes are provisioned independently.\nmkdirp /var/run/enclave/apfs-broker root _enclavecas 2750\nmkdirp /var/db/enclave/apfs-broker root \"$WHEEL\" 0700\nmkdirp /var/db/enclave/apfs-broker/state root \"$WHEEL\" 0700\nmkdirp /var/db/enclave/apfs-broker/tuf root \"$WHEEL\" 0700\nmkdirp /var/db/enclave/apfs-broker/tuf/repo root \"$WHEEL\" 0700\nmkdirp /var/log/enclave/apfs-broker root \"$WHEEL\" 0700\n");
        }
    }
    if l.deployment.is_some() {
        let _ = writeln!(
            s,
            "mkdirp {} {} {} 0700",
            l.cas_store(),
            DaemonId::SwarmSync.account(),
            DaemonId::SwarmSync.account()
        );
    }
    let _ = writeln!(
        s,
        "addmember {} {}",
        DaemonId::AgentRuntime.client_group(),
        enclave_core::daemon::GATEWAY_ACCOUNT
    );
    let _ = writeln!(
        s,
        "mkgroup {JOURNAL_READ_GROUP} {JOURNAL_READ_GID}\naddmember {JOURNAL_READ_GROUP} {}",
        DaemonId::ZkAuditor.account()
    );
    // GAP-21: only UID 702 reaches the root revocation supervisor.
    let _ = writeln!(
        s,
        "mkgroup {0} {1}\naddmember {0} {2}",
        enclave_core::supervisor::CLIENT_GROUP,
        enclave_core::supervisor::CLIENT_GID,
        DaemonId::SwarmSync.account()
    );
    let _ = writeln!(s, "\nmkdirp {} root \"$WHEEL\" 0755\nmkdirp {} root \"$WHEEL\" 0755\nmkdirp {} root \"$WHEEL\" 0755", l.socket_dir, l.audit_dir, l.state_dir);
    for d in DaemonId::ALL {
        let _ = writeln!(
            s,
            "mkdirp {sock}/{dir} {acct} {grp} 2750\nmkdirp {audit}/{dir} {acct} {JOURNAL_READ_GROUP} 2750\nmkdirp {state}/{dir} {acct} {acct} 0700",
            sock = l.socket_dir,
            audit = l.audit_dir,
            state = l.state_dir,
            dir = d.dir_name(),
            acct = d.account(),
            grp = d.client_group()
        );
    }
    let _ = writeln!(
        s,
        "mkdirp {}/{} root {} 2750",
        l.socket_dir,
        enclave_core::supervisor::SOCKET_DIR,
        enclave_core::supervisor::CLIENT_GROUP
    );
    let _ = writeln!(
        s,
        "\n# Biometric helper socket directory (GAP-14, DEFECT-F-09: root prepares per-console child at login)\nmkdirp {}/{} root \"$WHEEL\" 0755",
        l.socket_dir,
        INTENT_SOCKET_DIR
    );
    let _ = writeln!(s, "\n# Separate OAuth broker parent; root runtime preparation creates the console child.\nmkdirp {}/oidc root \"$WHEEL\" 0755", l.socket_dir);
    if l.fido_emulator {
        // GAP-13: the emulator's account; only UID 703 reaches its socket.
        let (acct, d) = (fido::EMULATOR_ACCOUNT, fido::EMULATOR_SOCKET_DIR);
        let _ = writeln!(
            s,
            "\n# CTAPHID emulator (GAP-13)\nmkgroup {acct} {gid}\nmkuser {acct} {uid} {gid}\nmkgroup {cg} {cgid}\naddmember {cg} {vault}\nmkdirp {sock}/{d} {acct} {cg} 2750\nmkdirp {audit}/{d} {acct} {acct} 0700\nmkdirp {state}/{d} {acct} {acct} 0700",
            gid = fido::EMULATOR_GID,
            uid = fido::EMULATOR_UID,
            cg = fido::EMULATOR_CLIENT_GROUP,
            cgid = fido::EMULATOR_CLIENT_GID,
            vault = DaemonId::CustodyVault.account(),
            sock = l.socket_dir,
            audit = l.audit_dir,
            state = l.state_dir,
        );
    }
    // GAP-34: sandboxed CDP browser account and socket directory.
    let _ = writeln!(
        s,
        "\n# CDP Browser sandbox (GAP-34)\nmkgroup {acct} {gid}\nmkuser {acct} {uid} {gid}\nmkgroup {cg} {cgid}\naddmember {cg} {adapter}\nmkdirp {sock}/{d} {acct} {cg} 2750\nmkdirp {audit}/{d} {acct} {acct} 0700\nmkdirp {state}/{d} {acct} {acct} 0700",
        acct = enclave_core::daemon::BROWSER_ACCOUNT,
        gid = enclave_core::daemon::BROWSER_GID,
        uid = enclave_core::daemon::BROWSER_UID,
        cg = enclave_core::daemon::BROWSER_CLIENT_GROUP,
        cgid = enclave_core::daemon::BROWSER_CLIENT_GID,
        adapter = DaemonId::ModelRunner.account(),
        sock = l.socket_dir,
        audit = l.audit_dir,
        state = l.state_dir,
        d = BROWSER_SOCKET_DIR,
    );
    let _=writeln!(s,"\n# Dedicated authenticated console ingress (F97)\nmkdirp {sock}/gateway {account} {account} 0755\nmkdirp {audit}/gateway {account} {account} 0700",
        sock=l.socket_dir,audit=l.audit_dir,account=enclave_core::daemon::GATEWAY_ACCOUNT);
    // GAP-10: dedicated witness socket for 703 -> 705 streaming
    let _ = writeln!(
        s,
        "\n# Dedicated witness socket channel (GAP-10)\nmkgroup {cg} {cgid}\naddmember {cg} {vault}\nmkdirp {sock}/{d} {zk} {cg} 2750",
        cg = enclave_core::daemon::WITNESS_CLIENT_GROUP,
        cgid = enclave_core::daemon::WITNESS_CLIENT_GID,
        vault = DaemonId::CustodyVault.account(),
        sock = l.socket_dir,
        d = enclave_core::daemon::WITNESS_SOCKET_DIR,
        zk = DaemonId::ZkAuditor.account(),
    );
    // FS-706 / D-R8: Detached model hydration jobs directory
    let _ = writeln!(
        s,
        "\n# Detached hydration jobs directory (FS-706, D-R8)\nmkdirp {}/jobs {} {} 0700",
        l.socket_dir,
        DaemonId::SwarmSync.account(),
        DaemonId::SwarmSync.account(),
    );
    s
}

fn exact(path: &Path) -> EnclaveResult<()> {
    if normalized_path(path)?!=path||path.components().count()>96
        ||path.components().any(|part|matches!(part,std::path::Component::Normal(name) if name.as_encoded_bytes().len()>255)) {
        return Err(err!(EINVAL,"BIRTH_PUBLIC_RENDER_PATH"));
    }
    Ok(())
}
fn public_layout(raw: &[u8], descriptor: &Path, manifest: &[u8]) -> EnclaveResult<Layout> {
    if raw.is_empty() || raw.len() > 65536 || manifest.is_empty() || manifest.len() > 16384 {
        return Err(err!(E2BIG, "BIRTH_PUBLIC_RENDER_INPUT_BOUND"));
    }
    let target = DeploymentTarget::parse(raw)?;
    exact(descriptor)?;
    let root = descriptor
        .parent()
        .filter(|path| path.file_name().is_some_and(|name| name == "config"))
        .and_then(Path::parent)
        .ok_or_else(|| err!(EINVAL, "BIRTH_PUBLIC_RENDER_ALLOCATED_SCOPE"))?;
    exact(root)?;
    let token = root
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("");
    if target.role != DeploymentRole::DedicatedTest
        || target.profile != Profile::L2
        || target.signing_identity_mode != DeploymentSigningMode::LocalPins
        || target.broker.is_some()
        || !target.shared_read_only_inputs.is_empty()
        || token.len() != 32
        || !token
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || target.target_id != format!("ykft-{token}")
        || descriptor != root.join("config/deployment.json")
        || target.layout.launchd_namespace != format!("com.enterprise.enclave.ykft.n{token}")
        || target.layout.mach_service != format!("com.enterprise.enclave.ykft.n{token}.exception")
    {
        return Err(err!(EACCES, "BIRTH_PUBLIC_RENDER_ALLOCATED_SCOPE"));
    }
    let paths = enclave_custody_vaultd::provisioning::manifest_input_paths(manifest, Profile::L2)?;
    let files = vec![
        paths.asset_policy_file().to_owned(),
        paths.asset_policy_key_file().to_owned(),
        paths.asset_inventory_key_file().to_owned(),
        paths.envelope_policy_key_file().to_owned(),
    ];
    let l = &target.layout;
    for path in [
        &l.binary_dir,
        &l.custody_bundle,
        &l.sandbox_dir,
        &l.socket_root,
        &l.state_root,
        &l.audit_root,
        &l.cas_store_root,
        &l.staging_root,
        &l.support_root,
        &target.authority_config,
        &target.expected_artifacts_manifest,
        &target.codesign_pins_file,
    ]
    .into_iter()
    .chain(files.iter())
    {
        exact(path)?;
        if !path.starts_with(root) || path == root {
            return Err(err!(EACCES, "BIRTH_PUBLIC_RENDER_ALLOCATED_SCOPE"));
        }
    }
    // Syntactic manifest paths do not become provisioning authority. Close
    // aliases here; actual private import later enforces its complete role map.
    let mut seen = Vec::<PathBuf>::new();
    for path in std::iter::once(&target.authority_config).chain(files.iter()) {
        let folded = PathBuf::from(
            path.to_str()
                .ok_or_else(|| err!(EINVAL, "BIRTH_PUBLIC_RENDER_PATH"))?
                .to_ascii_lowercase(),
        );
        if seen
            .iter()
            .any(|old| folded.starts_with(old) || old.starts_with(&folded))
        {
            return Err(err!(EINVAL, "BIRTH_PUBLIC_RENDER_PATH_ALIAS"));
        }
        seen.push(folded);
    }
    Ok(Layout {
        bin_dir: l.binary_dir.display().to_string(),
        sandbox_dir: l.sandbox_dir.display().to_string(),
        socket_dir: l.socket_root.display().to_string(),
        audit_dir: l.audit_root.display().to_string(),
        state_dir: l.state_root.display().to_string(),
        profile: "L2".into(),
        custody_app: l.custody_bundle.display().to_string(),
        fido_emulator: false,
        custody_authority: Some(CustodyPaths {
            manifest: target.authority_config.clone(),
            files,
        }),
        deployment: Some(TargetData {
            target,
            descriptor: descriptor.to_owned(),
        }),
    })
}
fn artifacts(layout: &Layout) -> BTreeMap<String, String> {
    let mut files = BTreeMap::new();
    for daemon in DaemonId::ALL {
        files.insert(
            format!(
                "launchd/{}.plist",
                layout.job_label(&daemon.launchd_label())
            ),
            plist(daemon, layout),
        );
        files.insert(
            format!("launchd/{}.sb", daemon.plist_suffix()),
            sandbox_profile(daemon, layout),
        );
    }
    for (label, bytes) in [
        (
            enclave_core::supervisor::LAUNCHD_LABEL,
            supervisor_plist(layout),
        ),
        (INTENT_LABEL, intent_plist(layout)),
        (OIDC_LABEL, oidc_plist_for_layout(layout)),
        (HYDRATE_LABEL, hydrate_plist(layout)),
        (BROWSER_LABEL, browser_plist(layout)),
        (
            enclave_core::daemon::GATEWAY_IDENTIFIER,
            gateway_plist(layout),
        ),
    ] {
        files.insert(format!("launchd/{}.plist", layout.job_label(label)), bytes);
    }
    files.insert("launchd/browser.sb".into(), browser_sandbox_profile(layout));
    files.insert("launchd/gateway.sb".into(), gateway_sandbox_profile(layout));
    files.insert(
        "launchd/provision-accounts.sh".into(),
        provision_script(layout),
    );
    files.insert("launchd/enclave-daemon.entitlements".into(), entitlements());
    files
}
/// Pure public-data export only. No filesystem I/O, checked/provisioning
/// construction, code execution, signature acceptance or approval occurs.
pub(super) fn public_artifacts(
    raw: &[u8],
    descriptor: &Path,
    manifest: &[u8],
) -> EnclaveResult<BTreeMap<String, String>> {
    let files = artifacts(&public_layout(raw, descriptor, manifest)?);
    if files.len() != 20 || files.values().map(String::len).sum::<usize>() > 1024 * 1024 {
        return Err(err!(E2BIG, "BIRTH_PUBLIC_RENDER_OUTPUT_BOUND"));
    }
    Ok(files)
}

#[cfg(test)]
#[path = "launchd_render_data_tests.rs"]
mod tests;
