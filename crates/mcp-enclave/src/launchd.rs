//! Production `LaunchDaemon` property lists, Seatbelt profiles and
//! hardened-runtime entitlements for UIDs 701–705.
//!
//! Each daemon runs as its dedicated account, under `sandbox-exec` with a
//! deny-by-default profile, `Core = 0` and an `RSS` hard limit equal to its
//! `enclave.lock.toml` ceiling. Only UID 702 may open outbound network
//! sockets (OHTTP relay + TUF/CAS fetch); UIDs 701/703/704/705 hold none.

use std::fmt::Write as _;
use std::path::Path;

use enclave_core::daemon::DaemonId;
use enclave_core::err;
use enclave_core::error::EnclaveResult;

/// Install layout.
#[derive(Debug, Clone)]
pub struct Layout {
    /// Binaries.
    pub bin_dir: String,
    /// Seatbelt profiles.
    pub sandbox_dir: String,
    /// Sockets.
    pub socket_dir: String,
    /// Journals.
    pub audit_dir: String,
    /// Daemon state.
    pub state_dir: String,
    /// Profile.
    pub profile: String,
    /// UID 703's application bundle (FS-703 §4.1, ADR-010, GAP-15).
    pub custody_app: String,
    /// GAP-13: deploy the out-of-process CTAPHID emulator (`_enclavefido`)
    /// and point UID 703 at it instead of the physical key over IOKit HID.
    pub fido_emulator: bool,
    /// Optional complete root-provisioned public native custody authority.
    /// Debug output is hash-only; process arguments contain only its path.
    pub custody_authority: Option<enclave_custody_vaultd::provisioning::CustodyProvisioning>,
    /// Optional checked protected deployment; no caller-provided path overrides.
    pub deployment: Option<enclave_core::deployment::CheckedDeploymentTarget>,
}

impl Default for Layout {
    fn default() -> Self {
        Self {
            bin_dir: "/opt/enterprise/enclave/bin".into(),
            sandbox_dir: "/opt/enterprise/enclave/sandbox".into(),
            socket_dir: "/var/run/enclave".into(),
            audit_dir: "/var/log/enclave".into(),
            state_dir: "/var/db/enclave".into(),
            profile: "L2".into(),
            custody_app: CUSTODY_APP.into(),
            fido_emulator: false,
            custody_authority: None,
            deployment: None,
        }
    }
}

use enclave_custody_vaultd::ctap::transport as fido;

/// Launchd label of the CTAPHID emulator.
pub const FIDO_LABEL: &str = "com.enterprise.enclave.fido";
/// Its binary.
pub const FIDO_BINARY: &str = "enclave-fido-emulator";

/// Launchd label of the _enclaveintent helper LaunchAgent (GAP-14).
pub const INTENT_LABEL: &str = "com.enterprise.enclave.intent";
/// Its binary.
pub const INTENT_BINARY: &str = "enclave-intent";
/// Intent socket directory name under `socket_dir`.
pub const INTENT_SOCKET_DIR: &str = "intent";
/// Intent socket file name.
pub const INTENT_SOCKET: &str = "intent.sock";

/// Separate console-session OAuth broker. Configuration is provisioned by root;
/// packaging never invents an IdP or a current-session authority record.
pub const OIDC_LABEL: &str = "com.enterprise.enclave.oidc-broker";
/// Fixed installed app containing the separately signed browser process.
pub const OIDC_APP: &str = "/Library/Application Support/EnterpriseEnclave/EnclaveOIDC.app";
/// Public root-provisioned current-console peer/session binding.
pub const OIDC_IDENTITY_CONFIG: &str = "/Library/Application Support/EnterpriseEnclave/oidc-broker-identity.json";
/// Public root-provisioned organization OAuth endpoint/client configuration.
pub const OIDC_OAUTH_CONFIG: &str = "/Library/Application Support/EnterpriseEnclave/oidc-oauth.json";

/// Launchd label of the sandboxed CDP browser LaunchDaemon (GAP-34).
pub const BROWSER_LABEL: &str = "com.enterprise.enclave.browser";
/// Its binary.
pub const BROWSER_BINARY: &str = "enclave-cdp-browser";
/// Browser socket directory name under `socket_dir`.
pub const BROWSER_SOCKET_DIR: &str = "browser";
/// Browser socket file name.
pub const BROWSER_SOCKET: &str = "browser.sock";

/// Launchd label of the detached model hydration worker (FS-706 §3.3, D-R8).
pub const HYDRATE_LABEL: &str = "com.enterprise.enclave.hydrate";

impl Layout {
    /// Build a physical production layout from one complete protected descriptor.
    pub fn for_target(checked: enclave_core::deployment::CheckedDeploymentTarget) -> EnclaveResult<Self> {
        let target = checked.target();
        let paths = &target.layout;
        let authority = enclave_custody_vaultd::provisioning::CustodyProvisioning::load(
            &target.authority_config, target.profile, enclave_crypto::time::now_unix(),
        )?;
        let layout = Self { bin_dir: paths.binary_dir.display().to_string(),
            sandbox_dir: paths.sandbox_dir.display().to_string(), socket_dir: paths.socket_root.display().to_string(),
            audit_dir: paths.audit_root.display().to_string(), state_dir: paths.state_root.display().to_string(),
            profile: target.profile.to_string(), custody_app: paths.custody_bundle.display().to_string(),
            fido_emulator: false, custody_authority: Some(authority), deployment: Some(checked) };
        layout.validate()?;
        Ok(layout)
    }
    /// Launchd job label; cryptographic signing identifiers stay unchanged.
    pub fn job_label(&self, default: &str) -> String {
        match &self.deployment {
            Some(checked) => format!("{}.{}", checked.target().layout.launchd_namespace,
                default.strip_prefix("com.enterprise.enclave.").unwrap_or(default)),
            None => default.to_owned(),
        }
    }
    fn support_file(&self, name: &str, default: &str) -> String {
        self.deployment.as_ref().map(|c| c.target().layout.support_root.join(name).display().to_string())
            .unwrap_or_else(|| default.to_owned())
    }
    fn cas_store(&self) -> String {
        self.deployment.as_ref().map(|c| c.target().layout.cas_store_root.display().to_string())
            .unwrap_or_else(|| "/opt/enterprise/enclave/cas".into())
    }
    fn tuf_root(&self) -> String {
        self.deployment.as_ref().and_then(|c| c.target().broker.as_ref())
            .map(|b| b.tuf_root_file.display().to_string())
            .unwrap_or_else(|| self.support_file("tuf/root.json", "/Library/Application Support/EnterpriseEnclave/tuf/root.json"))
    }
    fn pin_file(&self) -> String {
        self.deployment.as_ref().map(|c| c.target().codesign_pins_file.display().to_string())
            .unwrap_or_else(|| enclave_core::codesign::PIN_FILE.to_owned())
    }
    fn mach_service(&self) -> &str {
        self.deployment.as_ref().map(|c| c.target().layout.mach_service.as_str())
            .unwrap_or("com.enterprise.enclave.exception")
    }
    fn append_deployment_args(&self, args: &mut Vec<String>, cli: bool) {
        if let Some(checked) = &self.deployment {
            args.extend([if cli { "--deployment-config" } else { "--deployment-target" }.into(),
                checked.config_path().display().to_string()]);
        }
    }
    fn deployment_read_rules(&self, output: &mut String) {
        if let Some(checked) = &self.deployment {
            let target = checked.target();
            let mut files = vec![checked.config_path(), target.authority_config.as_path(),
                target.expected_artifacts_manifest.as_path(), target.codesign_pins_file.as_path()];
            if let Some(broker) = &target.broker { files.push(&broker.tuf_root_file); }
            let mut directories = std::collections::BTreeSet::new();
            for file in files {
                let resolved = seatbelt_path(&file.display().to_string());
                let _ = writeln!(output, "(allow file-read* (literal \"{resolved}\"))");
                for parent in file.ancestors().skip(1) { directories.insert(seatbelt_path(&parent.display().to_string())); }
            }
            for directory in directories {
                let _ = writeln!(output, "(allow file-read-data file-read-metadata (literal \"{directory}\"))");
            }
        }
    }
    /// Reject layout values that could alter generated shell or Seatbelt syntax.
    /// Socket/audit/state shell operands cannot contain whitespace; binary,
    /// sandbox and custody bundle paths remain whitespace-safe XML/data. No path admits quoting, substitutions, control
    /// bytes or parent traversal. Profile selection is a closed set.
    pub fn validate(&self) -> EnclaveResult<()> {
        let profile = enclave_core::profile::Profile::parse(&self.profile)?;
        if let Some(checked) = &self.deployment {
            let current = enclave_core::deployment::load(checked.config_path())?;
            let target = checked.target();
            let paths = &target.layout;
            if current.target() != target || profile != target.profile || self.fido_emulator
                || [(&self.bin_dir, &paths.binary_dir), (&self.sandbox_dir, &paths.sandbox_dir),
                    (&self.socket_dir, &paths.socket_root), (&self.audit_dir, &paths.audit_root),
                    (&self.state_dir, &paths.state_root), (&self.custody_app, &paths.custody_bundle)]
                    .into_iter().any(|(value, path)| value != &path.display().to_string())
                || self.custody_authority.as_ref().is_none_or(|a|
                    seatbelt_path(&a.manifest_path().display().to_string()) != seatbelt_path(&target.authority_config.display().to_string()))
                || paths.cas_store_root.as_os_str().as_encoded_bytes().iter().any(u8::is_ascii_whitespace)
                || target.broker.as_ref().is_some_and(|b| b.base_dir.as_os_str().as_encoded_bytes().iter().any(u8::is_ascii_whitespace)) {
                return Err(err!(EACCES, "DEPLOYMENT_LAYOUT_MISMATCH"));
            }
        }
        if let Some(config) = &self.custody_authority {
            if self.fido_emulator { return Err(err!(EACCES, "CUSTODY_PROVISIONING_NATIVE_REQUIRED")); }
            config.revalidate(profile, enclave_crypto::time::now_unix())?;
        }
        for (value, allow_space) in [(&self.bin_dir, true), (&self.sandbox_dir, true), (&self.socket_dir, false), (&self.audit_dir, false), (&self.state_dir, false), (&self.custody_app, true)] {
            if (!allow_space && value.chars().any(char::is_whitespace)) || !value.starts_with('/') || value.chars().any(|c| c.is_control() || matches!(c, '\'' | '"' | '`' | '$' | ';' | '&' | '|' | '<' | '>' | '(' | ')' | '\\'))
                || Path::new(value).components().any(|c| matches!(c, std::path::Component::ParentDir)) {
                return Err(err!(EINVAL, "LAUNCHD_LAYOUT_INVALID"));
            }
        }
        Ok(())
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

/// Where UID 703 is installed: an application bundle, because Secure Enclave
/// key APIs bind keys to a signed bundle identity (FS-703 §4.1).
pub const CUSTODY_APP: &str = "/Library/Application Support/EnterpriseEnclave/EnclaveCustody.app";

/// The path Seatbelt sees. Profiles are matched against *resolved* paths,
/// and on macOS `/var`, `/tmp` and `/etc` are symlinks into `/private`: a
/// rule on `/var/db/enclave` never matches (the first bare-metal bring-up
/// denied every daemon its own state directory).
pub fn seatbelt_path(p: &str) -> String {
    for top in ["/var", "/tmp", "/etc"] {
        if p == top || p.strip_prefix(top).is_some_and(|r| r.starts_with('/')) {
            return format!("/private{p}");
        }
    }
    p.to_owned()
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

#[path="launchd_render_data.rs"]
mod render_data;
pub use render_data::{JOURNAL_READ_GROUP,JOURNAL_READ_GID,FIDO_MDS_FILE,DAEMON_MALLOC_ENV};
/// Pure allocated DedicatedL2 public rendering. Returned bytes carry no
/// checked deployment/provisioning/approval or installation authority.
pub fn render_public_birth_artifacts(descriptor_bytes:&[u8],descriptor_path:&Path,custody_manifest_bytes:&[u8])
    ->EnclaveResult<std::collections::BTreeMap<String,String>> {
    render_data::public_artifacts(descriptor_bytes,descriptor_path,custody_manifest_bytes)
}
/// Render using the same inert data engine as the original Layout route.
pub fn program(d:DaemonId,l:&Layout)->String {render_data::program(d,&render_data::Layout::from_protected(l))}
/// Render using the same inert data engine as the original Layout route.
pub fn daemon_args(d:DaemonId,l:&Layout)->Vec<String> {render_data::daemon_args(d,&render_data::Layout::from_protected(l))}
/// Render using the same inert data engine as the original Layout route.
pub fn plist(d:DaemonId,l:&Layout)->String {render_data::plist(d,&render_data::Layout::from_protected(l))}
/// Render using the same inert data engine as the original Layout route.
pub fn sandbox_profile(d:DaemonId,l:&Layout)->String {render_data::sandbox_profile(d,&render_data::Layout::from_protected(l))}
/// Render using the same inert data engine as the original Layout route.
pub fn supervisor_plist(l:&Layout)->String {render_data::supervisor_plist(&render_data::Layout::from_protected(l))}
/// Render using the same inert data engine as the original Layout route.
pub fn apfs_broker_plist(l:&Layout)->String {render_data::apfs_broker_plist(&render_data::Layout::from_protected(l))}
/// Render using the same inert data engine as the original Layout route.
pub fn intent_plist(l:&Layout)->String {render_data::intent_plist(&render_data::Layout::from_protected(l))}
/// Render using the same inert data engine as the original Layout route.
pub fn oidc_plist_for_layout(l:&Layout)->String {render_data::oidc_plist_for_layout(&render_data::Layout::from_protected(l))}
/// Render using the same inert data engine as the original Layout route.
pub fn hydrate_plist(l:&Layout)->String {render_data::hydrate_plist(&render_data::Layout::from_protected(l))}
/// Render using the same inert data engine as the original Layout route.
pub fn fido_plist(l:&Layout)->String {render_data::fido_plist(&render_data::Layout::from_protected(l))}
/// Render using the same inert data engine as the original Layout route.
pub fn fido_sandbox_profile(l:&Layout)->String {render_data::fido_sandbox_profile(&render_data::Layout::from_protected(l))}
/// Render using the same inert data engine as the original Layout route.
pub fn gateway_plist(l:&Layout)->String {render_data::gateway_plist(&render_data::Layout::from_protected(l))}
/// Render using the same inert data engine as the original Layout route.
pub fn gateway_sandbox_profile(l:&Layout)->String {render_data::gateway_sandbox_profile(&render_data::Layout::from_protected(l))}
/// Render using the same inert data engine as the original Layout route.
pub fn browser_plist(l:&Layout)->String {render_data::browser_plist(&render_data::Layout::from_protected(l))}
/// Render using the same inert data engine as the original Layout route.
pub fn browser_sandbox_profile(l:&Layout)->String {render_data::browser_sandbox_profile(&render_data::Layout::from_protected(l))}
/// Render using the same inert data engine as the original Layout route.
pub fn provision_script(l:&Layout)->String {render_data::provision_script(&render_data::Layout::from_protected(l))}
/// Render using the same inert data engine as the original Layout route.
pub fn oidc_plist()->String {render_data::oidc_plist()}
/// Render using the same inert data engine as the original Layout route.
pub fn entitlements()->String {render_data::entitlements()}

/// UID 704's custody-grant signing seed (hex), in `<state_dir>/ifc/`.
pub const GRANT_SEED_FILE: &str = "ifc-policy.key";
/// Its public half (hex), in `<state_dir>/custody/` for UID 703.
pub const GRANT_PUBLIC_FILE: &str = "ifc-grant.pub";

/// Root-run, idempotent: create UID 704's custody-grant signing key on first
/// install (kept on re-install), owned by `_enclaveifc` `0600`, and hand its
/// public half to UID 703 (`_piivault` `0600`). Neither daemon can read the
/// other's state directory, so the installer is the only party that sees
/// both. Returns the public key (hex).
pub fn provision_grant_key(state_dir: &Path) -> EnclaveResult<String> {
    use enclave_core::fsutil::write_private;
    let ifc = DaemonId::AgentRuntime;
    let custody = DaemonId::CustodyVault;
    let seed_p = state_dir.join(ifc.dir_name()).join(GRANT_SEED_FILE);
    let seed: [u8; 32] = match std::fs::read_to_string(&seed_p) {
        Ok(h) => hex::decode(h.trim())
            .ok()
            .and_then(|b| <[u8; 32]>::try_from(b).ok())
            .ok_or_else(|| {
                err!(
                    EINVAL,
                    "GRANT_SEED_INVALID",
                    "{}: expected 64 hex chars",
                    seed_p.display()
                )
            })?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let mut b = [0u8; 32];
            rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut b);
            write_private(&seed_p, hex::encode(b).as_bytes())?;
            b
        }
        Err(e) => return Err(err!(EIO, "GRANT_SEED_READ", "{}: {e}", seed_p.display())),
    };
    let public = hex::encode(
        ed25519_dalek::SigningKey::from_bytes(&seed)
            .verifying_key()
            .to_bytes(),
    );
    let pub_p = state_dir.join(custody.dir_name()).join(GRANT_PUBLIC_FILE);
    write_private(&pub_p, public.as_bytes())?;
    for (p, d) in [(&seed_p, ifc), (&pub_p, custody)] {
        std::os::unix::fs::chown(p, Some(d.uid()), Some(d.gid()))
            .map_err(|e| err!(EPERM, "GRANT_KEY_CHOWN", "{}: {e}", p.display()))?;
    }
    Ok(public)
}

/// Write every plist, profile and the entitlements file into `out`.
pub fn render_all(out: &Path, l: &Layout) -> EnclaveResult<Vec<String>> {
    crate::custody_notice::show_for_profile(&l.profile);
    l.validate()?;
    if let Some(checked) = &l.deployment {
        let expected = checked.target().layout.staging_root.join("launchd");
        if seatbelt_path(&out.display().to_string()) != seatbelt_path(&expected.display().to_string()) {
            return Err(err!(EACCES, "DEPLOYMENT_STAGING_MISMATCH"));
        }
    }
    std::fs::create_dir_all(out).map_err(|e| err!(EIO, "LAUNCHD_RENDER", "{e}"))?;
    let mut written = Vec::new();
    for d in DaemonId::ALL {
        let p = out.join(format!("{}.plist", l.job_label(&d.launchd_label())));
        std::fs::write(&p, plist(d, l)).map_err(|e| err!(EIO, "LAUNCHD_RENDER", "{e}"))?;
        written.push(p.display().to_string());
        let sb = out.join(format!("{}.sb", d.plist_suffix()));
        std::fs::write(&sb, sandbox_profile(d, l))
            .map_err(|e| err!(EIO, "LAUNCHD_RENDER", "{e}"))?;
        written.push(sb.display().to_string());
    }
    if l.fido_emulator {
        let p = out.join(format!("{FIDO_LABEL}.plist"));
        std::fs::write(&p, fido_plist(l)).map_err(|e| err!(EIO, "LAUNCHD_RENDER", "{e}"))?;
        written.push(p.display().to_string());
        let sb = out.join(format!("{}.sb", fido::EMULATOR_SOCKET_DIR));
        std::fs::write(&sb, fido_sandbox_profile(l))
            .map_err(|e| err!(EIO, "LAUNCHD_RENDER", "{e}"))?;
        written.push(sb.display().to_string());
    }
    if l.profile=="L3" {let p=out.join(format!("{}.plist",l.job_label("com.enterprise.enclave.apfs-broker")));std::fs::write(&p,apfs_broker_plist(l)).map_err(|e|err!(EIO,"LAUNCHD_RENDER","{e}"))?;written.push(p.display().to_string());}
    let sup = out.join(format!("{}.plist", l.job_label(enclave_core::supervisor::LAUNCHD_LABEL)));
    std::fs::write(&sup, supervisor_plist(l)).map_err(|e| err!(EIO, "LAUNCHD_RENDER", "{e}"))?;
    written.push(sup.display().to_string());
    let intent_p = out.join(format!("{}.plist", l.job_label(INTENT_LABEL)));
    std::fs::write(&intent_p, intent_plist(l)).map_err(|e| err!(EIO, "LAUNCHD_RENDER", "{e}"))?;
    written.push(intent_p.display().to_string());
    let oidc_p = out.join(format!("{}.plist", l.job_label(OIDC_LABEL)));
    std::fs::write(&oidc_p, oidc_plist_for_layout(l)).map_err(|e| err!(EIO, "LAUNCHD_RENDER", "{e}"))?;
    written.push(oidc_p.display().to_string());
    let hyd_p = out.join(format!("{}.plist", l.job_label(HYDRATE_LABEL)));
    std::fs::write(&hyd_p, hydrate_plist(l)).map_err(|e| err!(EIO, "LAUNCHD_RENDER", "{e}"))?;
    written.push(hyd_p.display().to_string());
    let browser_p = out.join(format!("{}.plist", l.job_label(BROWSER_LABEL)));
    std::fs::write(&browser_p, browser_plist(l)).map_err(|e| err!(EIO, "LAUNCHD_RENDER", "{e}"))?;
    written.push(browser_p.display().to_string());
    let browser_sb = out.join(format!("{BROWSER_SOCKET_DIR}.sb"));
    std::fs::write(&browser_sb, browser_sandbox_profile(l))
        .map_err(|e| err!(EIO, "LAUNCHD_RENDER", "{e}"))?;
    written.push(browser_sb.display().to_string());
    let gateway_p=out.join(format!("{}.plist",l.job_label(enclave_core::daemon::GATEWAY_IDENTIFIER)));
    std::fs::write(&gateway_p,gateway_plist(l)).map_err(|e|err!(EIO,"LAUNCHD_RENDER","{e}"))?;
    written.push(gateway_p.display().to_string());
    let gateway_sb=out.join("gateway.sb");
    std::fs::write(&gateway_sb,gateway_sandbox_profile(l)).map_err(|e|err!(EIO,"LAUNCHD_RENDER","{e}"))?;
    written.push(gateway_sb.display().to_string());
    let pv = out.join("provision-accounts.sh");
    std::fs::write(&pv, provision_script(l)).map_err(|e| err!(EIO, "LAUNCHD_RENDER", "{e}"))?;
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&pv, std::fs::Permissions::from_mode(0o755));
    }
    written.push(pv.display().to_string());
    let e = out.join("enclave-daemon.entitlements");
    std::fs::write(&e, entitlements()).map_err(|e| err!(EIO, "LAUNCHD_RENDER", "{e}"))?;
    written.push(e.display().to_string());
    Ok(written)
}
