//! `mcp-enclave` — operator CLI.

// Also covers the UID 705 entry reached through `mcp-enclave __daemon`.
#[global_allocator]
static HEAP: enclave_zk_auditor::heap::WipingAllocator =
    enclave_zk_auditor::heap::WipingAllocator(std::alloc::System);

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use enclave_core::profile::Profile;
use enclave_model_runnerd::manifest::ExecutionClass;
use mcp_enclave::ctl::{self, AdmitInput, Env};

#[derive(Parser, Debug)]
#[command(
    name = "mcp-enclave",
    version,
    about = "MCPMac enclave operator CLI (UIDs 701–705)"
)]
struct Cli {
    /// Development mode: same-UID daemons with simulated hardware under --state-dir.
    #[arg(long, global = true)]
    dev: bool,
    /// Development state directory.
    #[arg(long, global = true)]
    state_dir: Option<PathBuf>,
    /// Protected production deployment descriptor; no development overrides.
    #[arg(long, global = true)]
    deployment_config: Option<PathBuf>,
    /// Workstation profile.
    #[arg(long, global = true, default_value = "L2")]
    profile: String,
    /// Machine-readable output.
    #[arg(long, global = true)]
    json: bool,
    #[command(subcommand)]
    cmd: Cmd,
}

fn default_state() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            std::env::temp_dir().join(format!("mcpmac-user-{}", unsafe { libc::geteuid() }))
        })
        .join(".mcpmac-dev")
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Create and finish one new native DedicatedL2 birth in this invocation.
    /// Requires existing nonblocking stdin/stdout pipes or sockets; emits JSON.
    DedicatedBirthSession {
        /// Existing protected DedicatedL2/local-pins raw template.
        #[arg(long)]
        template: PathBuf,
        /// Strict ancestor of all raw template paths.
        #[arg(long)]
        template_root: PathBuf,
        /// Existing protected parent for a fresh unpredictable native root.
        #[arg(long)]
        allocator_parent: PathBuf,
    },
    /// Emit public-only birth rendering data from external unadmitted copies.
    /// Requires nonblocking stdout pipe/socket; no deployment selection.
    DedicatedBirthRender {
        /// Final allocated descriptor path reported by the live challenge.
        #[arg(long)]
        descriptor: PathBuf,
        /// External copy of the challenge's exact public descriptor bytes.
        #[arg(long)]
        descriptor_input: PathBuf,
        /// External public custody manifest input, without admission authority.
        #[arg(long)]
        custody_manifest: PathBuf,
    },
    /// Local synchronization-stage diagnostics (no SLO or delivery claim).
    Swarm {
        #[command(subcommand)]
        op:SwarmOp,
    },
    /// Daemon lifecycle.
    Daemon {
        #[command(subcommand)]
        op: DaemonOp,
    },
    /// TUF metadata.
    Tuf {
        #[command(subcommand)]
        op: TufOp,
    },
    /// Model admission.
    Model {
        #[command(subcommand)]
        op: ModelOp,
    },
    /// Custody vault.
    Vault {
        #[command(subcommand)]
        op: VaultOp,
    },
    /// Audit journals.
    Audit {
        #[command(subcommand)]
        op: AuditOp,
    },
    /// Agent runtime IFC controls (GAP-32).
    Ifc {
        #[command(subcommand)]
        op: IfcOp,
    },
    /// Turn operations (GAP-18).
    Turn {
        #[command(subcommand)]
        op: TurnOp,
    },
    /// LaunchDaemon assets.
    Launchd {
        #[command(subcommand)]
        op: LaunchdOp,
    },
    /// Root revocation supervisor (GAP-21): terminates holders of revoked CAS
    /// inodes for UID 702. Runs until killed.
    Supervise {
        /// Mesh socket directory (the socket is `<dir>/supervisor/supervisor.sock`).
        #[arg(long)]
        socket_dir: Option<PathBuf>,
    },
    /// GAP-15 bare-metal spike (FS-703 §8.2.4): which ways of holding a
    /// Secure Enclave key work in this process context; prints JSON.
    SepSpike {
        /// Also sign with the `.biometryCurrentSet` key (Touch ID prompt).
        #[arg(long)]
        touch: bool,
    },
    /// Resource measurement (GAP-38): phys_footprint per daemon vs ceilings.
    Measure {
        /// Optional path to enclave.lock.toml.
        #[arg(long)]
        lock: Option<PathBuf>,
    },
    /// Lint operations.
    Lint {
        #[command(subcommand)]
        op: LintOp,
    },
    /// Enterprise MDM fleet deployment and orchestration (FS-706).
    Deploy {
        #[command(subcommand)]
        verb: mcp_enclave::deploy::DeployVerb,
        /// Model target slug for hydration.
        #[arg(long, global = true)]
        target: Option<String>,
        /// Pre-staged DMG image path for Profile L3.
        #[arg(long, global = true)]
        dmg: Option<String>,
        /// Override jobs directory for hydration worker.
        #[arg(long, global = true)]
        jobs_dir: Option<String>,
        /// Override CAS storage directory for hydration.
        #[arg(long, global = true)]
        cas_dir: Option<String>,
        /// Asynchronous execution mode.
        #[arg(long, global = true)]
        r#async: bool,
        /// Synchronous execution mode.
        #[arg(long, global = true)]
        sync: bool,
        /// Dry-run mode without modifying system state.
        #[arg(long, global = true)]
        dry_run: bool,
        /// Bypass confirmation prompts for destructive operations.
        #[arg(long, global = true)]
        yes: bool,
        /// Remove user and group accounts during purge.
        #[arg(long, global = true)]
        remove_accounts: bool,
        /// Purge all state during purge.
        #[arg(long, global = true)]
        purge_state: bool,
        /// `install` only: build distribution (packaging/macos/build.sh output,
        /// e.g. `.enclave-local/dist`). With it, install runs the install script
        /// embedded in this binary against that dist; without it, install uses
        /// the complete distribution at /opt/enterprise/enclave/dist
        /// (the .pkg flow). Scripts are never read from the current directory.
        #[arg(long, global = true)]
        dist: Option<String>,
    },
    /// Packet Filter anchor operations (FS-706 §4.3, D-R12).
    Pf {
        #[command(subcommand)]
        op: PfOp,
    },
    /// Post-Quantum Cryptographic (PQC) agility, status, and FIPS 203/204 self-test (FS-707, RB-219).
    Crypto {
        #[command(subcommand)]
        op: CryptoOp,
    },
    /// Internal: run a daemon entry point in this process.
    #[command(name = "__daemon", hide = true)]
    Embedded {
        uid: u32,
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        rest: Vec<String>,
    },
}

#[derive(Subcommand, Debug)]
enum CryptoOp {
    /// Display active PQC wire suite, algorithm parameters, and cryptographic-agility state.
    Status,
    /// Execute live NIST FIPS 203 (ML-KEM-768 + X25519) and FIPS 204 (ML-DSA-65 + Ed25519) KAT self-tests.
    SelfTest,
    /// Configure wire cryptographic suite policy (RB-219 emergency agility override).
    Policy {
        #[command(subcommand)]
        op: CryptoPolicyOp,
    },
    /// Flush cached PQC / OHTTP session keys across the enclave state directory (RB-219).
    FlushSessions,
}

#[derive(Subcommand,Debug)]
enum SwarmOp {
    /// Read four fixed local call-result counters from UID 702.
    SyncDiagnostics,
}

#[derive(Subcommand, Debug)]
enum CryptoPolicyOp {
    /// Set the active wire cryptographic suite (`HybridPqc` or `ClassicalOnly`).
    Set {
        /// Target wire suite (`HybridPqc` or `ClassicalOnly`).
        #[arg(long)]
        wire_suite: String,
        /// Required SRE override ticket when downgrading to `ClassicalOnly` (RB-219).
        #[arg(long)]
        temporary_override_ticket: Option<String>,
    },
}

#[derive(Subcommand, Debug)]
enum PfOp {
    /// Render Packet Filter anchor rule files.
    Render {
        /// Destination directory (default: launchd).
        #[arg(long, default_value = "launchd")]
        out: PathBuf,
    },
    /// Install Packet Filter anchors and configure pf.conf.
    Install {
        /// Anchors directory (default: /etc/pf.anchors).
        #[arg(long, default_value = "/etc/pf.anchors")]
        anchors_dir: PathBuf,
        /// Path to pf.conf (default: /etc/pf.conf).
        #[arg(long, default_value = "/etc/pf.conf")]
        pf_conf: PathBuf,
    },
}

#[derive(Subcommand, Debug)]
enum DaemonOp {
    /// Start all five daemons.
    Start,
    /// Bootstrap selected intent for the current console; requires --deployment-config.
    StartIntent,
    /// Register only the selected supervisor; unsupported selected runtime refuses.
    StartSupervisor,
    /// Stop all five daemons.
    Stop,
    /// Stop only selected non-broker auxiliary jobs; requires --deployment-config.
    StopAuxiliary,
    /// Authenticate live selected broker quiescence, then stop its registration.
    StopBroker,
    /// Status, RSS and budget check (non-zero exit if unhealthy).
    Status,
}

#[derive(Subcommand, Debug)]
enum TufOp {
    /// Initialize a TUF repository with 2-of-3 keys per role.
    Init {
        /// Key seeds file (default: .enclave-local/tuf-keys/keys.json).
        #[arg(long)]
        keys: Option<PathBuf>,
        /// Output repository directory.
        #[arg(long)]
        repo: Option<PathBuf>,
    },
    /// Sign and add a target to the repository.
    Sign {
        /// Target name in TUF targets metadata.
        #[arg(long)]
        name: String,
        /// Path to target file on disk.
        #[arg(long)]
        file: PathBuf,
        /// Optional custom JSON string.
        #[arg(long)]
        custom: Option<String>,
        /// Keys file.
        #[arg(long)]
        keys: Option<PathBuf>,
        /// Repository directory.
        #[arg(long)]
        repo: Option<PathBuf>,
    },
    /// Host configuration operations (GAP-20).
    HostConfig {
        #[command(subcommand)]
        op: HostConfigOp,
    },
    /// Manage TUF-distributed Cedar policy bundles (GAP-32).
    Policy {
        #[command(subcommand)]
        op: PolicyOp,
    },
    /// Verifier key manifest operations (GAP-20 / GAP-23 / Prompt 2D).
    Vk {
        #[command(subcommand)]
        op: VkOp,
    },
    /// Re-sign repository metadata with TUF canonical JSON (GAP-31).
    MigrateCanonical {
        /// Key seeds file (default: .enclave-local/tuf-keys/keys.json).
        #[arg(long)]
        keys: Option<PathBuf>,
        /// Repository directory.
        #[arg(long)]
        repo: Option<PathBuf>,
    },
    /// Push repository metadata to UID 702.
    Refresh {
        /// Repository directory (root.json, timestamp.json, snapshot.json, targets.json, N.root.json).
        #[arg(long)]
        repo: Option<PathBuf>,
        /// Trust-on-first-use bootstrap from repo/root.json (admin, once).
        #[arg(long)]
        bootstrap: bool,
    },
}

#[derive(Subcommand, Debug)]
enum PolicyOp {
    /// Bundle and publish a Cedar policy bundle (.cedar + .cedarschema) to TUF.
    Publish {
        /// Path to .cedarschema schema file.
        #[arg(long)]
        schema: Option<PathBuf>,
        /// Path to .cedar policies file.
        #[arg(long)]
        policies: Option<PathBuf>,
        /// Key seeds file.
        #[arg(long)]
        keys: Option<PathBuf>,
        /// Repository directory.
        #[arg(long)]
        repo: Option<PathBuf>,
    },
}

#[derive(Subcommand, Debug)]
enum VkOp {
    /// Publish the verifier key manifest (vk_manifest.json) to TUF (GAP-20 / GAP-23).
    Publish {
        /// Key seeds file.
        #[arg(long)]
        keys: Option<PathBuf>,
        /// Repository directory.
        #[arg(long)]
        repo: Option<PathBuf>,
    },
}

#[derive(Subcommand, Debug)]
enum IfcOp {
    /// Export authenticated per-boot policy timings; never implies SLO acceptance.
    PolicySli {
        /// Emit strict policy-only JSONL to stdout and acquisition metadata to stderr.
        #[arg(long)]
        jsonl: bool,
    },
    /// Hot-swap or refresh the Cedar policy bundle from TUF / UID 702.
    RefreshPolicy {
        /// Optional bundle JSON file. It must be byte-identical to the signed
        /// TUF target `enclave-policy.cedar.v1.json` served by UID 702, or the
        /// daemon refuses it (`POLICY_INLINE_UNSIGNED`) and keeps the current policy.
        /// Unsigned bundles load only in `simulation` dev builds (`--dev`).
        #[arg(long)]
        bundle: Option<PathBuf>,
    },
}

#[derive(Subcommand, Debug)]
enum HostConfigOp {
    /// Generate enclave-host-config.json.
    Generate {
        /// Profile floor (L1, L2, L3).
        #[arg(long, default_value = "L2")]
        profile_floor: String,
        /// UID 704 grant public key.
        #[arg(long)]
        grant_key: Option<String>,
        /// Output file path.
        #[arg(long, short)]
        out: Option<PathBuf>,
    },
    /// Generate, sign and publish enclave-host-config.json into the TUF repository.
    Publish {
        /// Profile floor (L1, L2, L3).
        #[arg(long, default_value = "L2")]
        profile_floor: String,
        /// UID 704 grant public key.
        #[arg(long)]
        grant_key: Option<String>,
        /// Keys file.
        #[arg(long)]
        keys: Option<PathBuf>,
        /// Repository directory.
        #[arg(long)]
        repo: Option<PathBuf>,
    },
}

#[derive(Subcommand, Debug)]
enum ModelOp {
    /// Admit through UID 702 and bind in UID 701.
    Admit {
        /// ExecutionClass (name or 0–6).
        #[arg(long)]
        class: String,
        /// Signed manifest.
        #[arg(long)]
        manifest: Option<PathBuf>,
        /// Weights (.safetensors).
        #[arg(long)]
        weights: Option<PathBuf>,
        /// enclave-calib-eval-v1 corpus.
        #[arg(long)]
        corpus: Option<PathBuf>,
        /// TUF target name.
        #[arg(long)]
        target: Option<String>,
    },
    /// Development fleet only: run one sample request against the bound model.
    Run {
        /// ExecutionClass of the bound model (name or 0–6).
        #[arg(long)]
        class: String,
        /// Prompt for classes that take one.
        #[arg(long, default_value = "hello")]
        prompt: String,
        /// Bytes to generate (block length for structured classes).
        #[arg(long, default_value_t = 32)]
        n: u32,
        /// Track C: take the A2 session lease (Touch ID) at turn start.
        #[arg(long)]
        lease: bool,
        /// Track C: reveal the sealed output on the helper's secure sheet
        /// after an A3 Touch ID. The terminal never receives the plaintext.
        #[arg(long)]
        reveal: bool,
    },
}

#[derive(Subcommand, Debug)]
enum VaultOp {
    /// Enroll the attached FIDO2 authenticator as custodian credential.
    Enroll,
    /// L1 only: register this Mac's Touch ID with custody (one Touch ID).
    EnrollBiometric,
    /// Begin independently authorized enrollment; may create one retained credential.
    EnrollmentBegin {
        /// New absolute private file for public pending evidence; never overwritten.
        #[arg(long)]
        pending_output:PathBuf,
    },
    /// Activate exact pending evidence with an independent signed inventory receipt.
    EnrollmentActivate {
        /// Absolute private JSON receipt file; PINs are entered only in the native helper.
        #[arg(long)]
        receipt:PathBuf,
    },
    /// Renew the unchanged active asset identity; fences old leases and requires fresh factors.
    EnrollmentRenew {
        /// Absolute private JSON receipt with a strictly newer issuer generation.
        #[arg(long)]
        receipt:PathBuf,
    },
    /// Begin backup enrollment on the second authenticator in explicit pair mode.
    EnrollmentBeginBackup {
        /// New absolute private file for public pending evidence; never overwritten.
        #[arg(long)]
        pending_output:PathBuf,
    },
    /// Add the daemon's exact pending backup using its independent signed receipt.
    EnrollmentAddBackup {
        /// Absolute private JSON receipt from the configured inventory issuer.
        #[arg(long)]
        receipt:PathBuf,
    },
    /// Renew both admitted member identities using newer independent receipts.
    EnrollmentRenewMembership {
        /// Absolute private JSON receipt for the original primary member.
        #[arg(long)]
        primary_receipt:PathBuf,
        /// Absolute private JSON receipt for the original backup member.
        #[arg(long)]
        backup_receipt:PathBuf,
    },
    /// Migrate every registered namespace epoch for admitted backup access.
    NamespaceBackupMigrate {
        #[arg(long)]
        namespace:String,
    },
    /// Activate a signed temporary travel session with public actions only.
    TravelRecoveryActivate {
        /// Absolute private file containing the independently signed token.
        #[arg(long)]
        token:PathBuf,
    },
    /// Record a lost member's signed retirement; recovery authority is required.
    MemberLossRecord {
        /// Absolute private file containing the signed inventory statement.
        #[arg(long)]
        statement:PathBuf,
    },
    /// Consume a replacement candidate into inert preparation; grants no access.
    MemberReplacementPrepare {
        /// Absolute private file containing the signed replacement candidate.
        #[arg(long)]
        candidate:PathBuf,
        /// Opaque ID of enrollment evidence already validated by the daemon.
        #[arg(long)]
        enrollment_evidence_id:String,
        /// Absolute private JSON receipt for the new member.
        #[arg(long)]
        replacement_receipt:PathBuf,
        /// Optional fresh independent receipt for the surviving member.
        #[arg(long)]
        survivor_receipt:Option<PathBuf>,
    },
    /// Generate/register a namespace DEK; print only its opaque custody envelope.
    CasWrap { namespace:String, epoch:u64, wrapping_epoch:u64 },
    /// Authenticate/register an existing opaque envelope during migration.
    CasImport { envelope:PathBuf },
    /// Rewrap a registered historical DEK without changing ciphertext.
    CasRotate { envelope:PathBuf, new_wrapping_epoch:u64 },
    /// Retire older KEK epochs after all registered historical keys are rewrapped.
    CasFloor { namespace:String, minimum_wrapping_epoch:u64 },
    /// Run an L2 A3 Detokenize ceremony through the custody vault.
    Detokenize {
        /// Surrogates to detokenize.
        #[arg(long, default_values_t = vec!["SYNTH-A3-CANARY-SURROGATE".to_string()])]
        surrogate: Vec<String>,
        /// Action class.
        #[arg(long, default_value = "A3")]
        class: String,
    },
}

#[derive(Subcommand, Debug)]
enum AuditOp {
    /// Verify dual-hash chains of every journal.
    Verify {
        /// Separately trusted JSON ChainAnchor for one journal (not stored beside mutable input).
        #[arg(long)]
        anchor: Option<PathBuf>,
        /// Journal file or directory (defaults to the audit directory).
        #[arg(long)]
        path: Option<PathBuf>,
    },
}

#[derive(Subcommand, Debug)]
enum TurnOp {
    /// Submit a turn to the enclave IFC runtime.
    Submit {
        /// Short user directive.
        #[arg(long)]
        directive: String,
        /// Attachment files.
        #[arg(long = "attachment")]
        attachments: Vec<PathBuf>,
    },
    /// Execute a bounded plan through authenticated console ingress, then finish.
    Execute {
        /// Short, single-line directive (at most 512 bytes).
        #[arg(long)]
        directive: String,
        /// UTF-8 plan file (at most 65536 bytes; symlinks/special files refused).
        #[arg(long)]
        source: PathBuf,
        /// Requested tool name, for example mcp://server/read (repeatable).
        #[arg(long = "tool")]
        tools: Vec<String>,
        /// Root capability budget in millibits (0 through 12000).
        #[arg(long, default_value_t = 0)]
        budget_mb: i64,
        /// Request actual custody approval where required.
        #[arg(long)]
        step_up: bool,
    },
}

#[derive(Subcommand,Debug)]
enum OidcSessionOp {
    /// Bind a new bounded authority digest to the current root-verified session.
    Renew {
        /// Absolute exclusive expiry, bounded by the protected OAuth authority.
        #[arg(long)]
        expires_unix:i64,
    },
}

#[derive(Subcommand, Debug)]
enum LaunchdOp {
    /// Print an inert selected-target payload and preservation plan as JSON.
    DeploymentInstallPlan,
    /// Check selected staging/profile/signing configuration without output writes.
    DeploymentCheck {
        /// Exact absolute build staging root from the protected descriptor.
        #[arg(long)]
        dist: PathBuf,
        /// Planned packaging signing mode, matching this compiled validator.
        #[arg(long, value_parser = ["local-pins", "team-id"])]
        signing_mode: String,
    },
    /// Renew protected OIDC authority for the actual current console login.
    OidcSession {
        #[command(subcommand)]
        op:OidcSessionOp,
    },
    /// Check protected public custody configuration without hardware or state I/O.
    CustodyConfigCheck {
        /// Absolute root-protected complete public authority manifest.
        #[arg(long)]
        config: PathBuf,
    },
    /// Write plists, Seatbelt profiles and entitlements.
    Render {
        /// Output directory.
        #[arg(long)]
        out: PathBuf,
        /// Binary directory.
        #[arg(long)]
        bin_dir: Option<String>,
        /// GAP-13: also render the CTAPHID emulator (`_enclavefido`) and
        /// point UID 703 at it instead of a physical key.
        #[arg(long)]
        with_fido_emulator: bool,
        /// Complete protected public native authority manifest; no issuer defaults.
        #[arg(long)]
        custody_authority_config: Option<PathBuf>,
    },
    /// Root, at install: create UID 704's custody-grant key and give UID 703
    /// its public half (idempotent).
    GrantKey {
        /// Daemon state root; defaults to the selected descriptor, or /var/db/enclave.
        #[arg(long)]
        state_dir: Option<PathBuf>,
    },
}

#[derive(Subcommand, Debug)]
enum LintOp {
    /// Lint an enclave.lock.toml file against CasUri grammar and FastCDC gear table digest (GAP-45).
    Lockfile {
        /// Path to enclave.lock.toml.
        #[arg(default_value = "schemas/enclave.lock.toml")]
        path: PathBuf,
    },
}

fn lint_lockfile(path: &std::path::Path) -> Result<(), String> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;

    let expected_gear = enclave_swarm_syncd::fastcdc::GEAR_TABLE_SHA256;
    let mut found_gear = None;
    let mut cas_uris = Vec::new();

    for line in content.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("fastcdc_gear_table_sha256 =") {
            let val = rest.trim().trim_matches('"');
            found_gear = Some(val.to_string());
        } else if let Some(rest) = trimmed.strip_prefix("cas_uri =") {
            let val = rest.trim().trim_matches('"');
            cas_uris.push(val.to_string());
        }
    }

    let gear =
        found_gear.ok_or_else(|| "missing fastcdc_gear_table_sha256 in lock file".to_string())?;
    if gear != expected_gear {
        return Err(format!(
            "fastcdc_gear_table_sha256 mismatch: expected {expected_gear}, found {gear}"
        ));
    }

    if cas_uris.is_empty() {
        return Err("no artifacts with cas_uri found in lock file".to_string());
    }

    for uri in &cas_uris {
        enclave_swarm_syncd::cas_uri::CasUri::parse(uri)
            .map_err(|e| format!("invalid cas_uri '{uri}': {e}"))?;
    }

    Ok(())
}

fn print<T: serde::Serialize + std::fmt::Debug>(json: bool, v: &T) {
    if json {
        println!("{}", serde_json::to_string_pretty(v).unwrap_or_default());
    } else {
        println!("{v:#?}");
    }
}

fn validate_deployment_build_destination(
    staging_root: &std::path::Path,
    dist: &std::path::Path,
    target_mode: enclave_core::deployment::DeploymentSigningMode,
    requested_mode: &str,
) -> enclave_core::error::EnclaveResult<()> {
    use enclave_core::{codesign::SigningMode, deployment::{DeploymentSigningMode, normalized_path}};
    let actual = match enclave_core::codesign::signing_mode() {
        SigningMode::LocalPins => DeploymentSigningMode::LocalPins,
        SigningMode::TeamId => DeploymentSigningMode::TeamId,
    };
    let requested = match requested_mode {
        "local-pins" => DeploymentSigningMode::LocalPins,
        "team-id" => DeploymentSigningMode::TeamId,
        _ => return Err(enclave_core::err!(EINVAL, "DEPLOYMENT_SIGNING_MODE")),
    };
    if requested != target_mode || requested != actual {
        return Err(enclave_core::err!(EACCES, "DEPLOYMENT_SIGNING_MODE"));
    }
    if normalized_path(dist)? != normalized_path(staging_root)? {
        return Err(enclave_core::err!(EACCES, "DEPLOYMENT_STAGING_MISMATCH"));
    }
    Ok(())
}

fn validate_dedicated_birth_request(cli:&Cli,profile:Profile)->enclave_core::error::EnclaveResult<()> {
    if cli.dev||cli.state_dir.is_some()||cli.deployment_config.is_some() {
        return Err(enclave_core::err!(EACCES,"BIRTH_SESSION_MIXED_ARGUMENTS"));
    }
    if profile!=Profile::L2 {
        return Err(enclave_core::err!(EACCES,"BIRTH_SESSION_L2_REQUIRED"));
    }
    if enclave_core::deployment::selected().is_some() {
        return Err(enclave_core::err!(EACCES,"BIRTH_SESSION_PRESELECTION_REQUIRED"));
    }
    Ok(())
}

fn validate_selected_supervisor_request(cli:&Cli,profile:Profile)->enclave_core::error::EnclaveResult<()> {
    if cli.deployment_config.is_none() {
        return Err(enclave_core::err!(EACCES,"DEPLOYMENT_CONTEXT_REQUIRED"));
    }
    if cli.dev || cli.state_dir.is_some() {
        return Err(enclave_core::err!(EACCES,"DEPLOYMENT_MIXED_ARGUMENTS"));
    }
    if profile!=Profile::L2 {
        return Err(enclave_core::err!(EACCES,"DEPLOYMENT_SUPERVISOR_SCOPE_UNSUPPORTED"));
    }
    Ok(())
}

fn run(cli: Cli) -> enclave_core::error::EnclaveResult<ExitCode> {
    let profile = Profile::parse(&cli.profile)?;
    if matches!(&cli.cmd,Cmd::Daemon {op:DaemonOp::StartSupervisor}) {
        validate_selected_supervisor_request(&cli,profile)?;
    }
    // These two exact routes must run before any protected descriptor load,
    // selection or default/selected production Env construction. Rendering is
    // data-only; the session creates and retains its actual native owners.
    match &cli.cmd {
        Cmd::DedicatedBirthSession {template,template_root,allocator_parent}=>{
            validate_dedicated_birth_request(&cli,profile)?;
            return mcp_enclave::deploy::run_dedicated_birth_session(mcp_enclave::deploy::DedicatedBirthSessionArgs {
                template:template.clone(),template_root:template_root.clone(),allocator_parent:allocator_parent.clone(),
            }).map(|exit|ExitCode::from(exit.exit_code));
        },
        Cmd::DedicatedBirthRender {descriptor,descriptor_input,custody_manifest}=>{
            validate_dedicated_birth_request(&cli,profile)?;
            return mcp_enclave::deploy::render_dedicated_birth_public_data(mcp_enclave::deploy::DedicatedBirthRenderArgs {
                descriptor:descriptor.clone(),descriptor_input:descriptor_input.clone(),custody_manifest:custody_manifest.clone(),
            }).map(|exit|ExitCode::from(exit.exit_code));
        },
        _=>{},
    }
    if let Some(path) = &cli.deployment_config {
        if cli.dev || cli.state_dir.is_some() || matches!(&cli.cmd, Cmd::Embedded { .. }) {
            return Err(enclave_core::err!(EACCES, "DEPLOYMENT_MIXED_ARGUMENTS"));
        }
        // Restrictive deactivation must remain available after admission-file
        // loss. Only these two exact stop routes use descriptor-only authority;
        // all other operations retain ordinary protected admission/selection.
        if matches!(&cli.cmd, Cmd::Daemon {op:DaemonOp::Stop | DaemonOp::StopAuxiliary}) {
            let teardown=enclave_core::deployment::teardown::load(path)?;
            if teardown.target().profile!=profile {
                return Err(enclave_core::err!(EACCES,"DEPLOYMENT_PROFILE_MISMATCH"));
            }
            let successful=if matches!(&cli.cmd,Cmd::Daemon {op:DaemonOp::StopAuxiliary}) {
                let report=ctl::selected_auxiliary_stop(&teardown)?;
                print(cli.json,&report);report.successful
            } else {
                let env=Env::production_for_teardown(&teardown)?;
                let report=ctl::selected_core_stop(&env,&teardown)?;
                print(cli.json,&report);report.successful
            };
            return Ok(if successful {ExitCode::SUCCESS}else{ExitCode::from(3)});
        }
        let checked = enclave_core::deployment::load(path)?;
        if checked.target().profile != profile {
            return Err(enclave_core::err!(EACCES, "DEPLOYMENT_PROFILE_MISMATCH"));
        }
        enclave_core::deployment::select(checked)?;
    }
    let env = if cli.dev {
        Env::dev(&cli.state_dir.clone().unwrap_or_else(default_state), profile)
    } else if let Some(target) = enclave_core::deployment::selected() {
        Env::production_for_target(target)?
    } else {
        Env::production(profile)
    };
    match cli.cmd {
        Cmd::DedicatedBirthSession {..}|Cmd::DedicatedBirthRender {..}=>
            Err(enclave_core::err!(EACCES,"BIRTH_SESSION_EARLY_DISPATCH_REQUIRED")),
        Cmd::Swarm {op:SwarmOp::SyncDiagnostics}=>{
            let export=ctl::swarm_sync_diagnostics(&env)?;
            // Construct the entire validated representation before stdout.
            let output=if cli.json {serde_json::to_string_pretty(&export)
                .map_err(|_|enclave_core::err!(EIO,"SYNC_DIAGNOSTICS_SERIALIZE"))?}
                else {format!("{export:#?}")};
            println!("{output}");
            Ok(ExitCode::SUCCESS)
        },
        Cmd::Embedded { uid, rest } => ctl::run_embedded(uid, rest).map(|_| ExitCode::SUCCESS),
        Cmd::SepSpike { touch } => {
            let r = enclave_custody_vaultd::darwin_sep::spike(
                &enclave_custody_vaultd::darwin_sep::SpikeOptions { touch },
            );
            println!("{}", serde_json::to_string_pretty(&r).unwrap_or_default());
            Ok(if r["ran"] == true && r["errors_34018"] == 0 {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(5)
            })
        }
        Cmd::Supervise { socket_dir } => {
            if let (Some(target), Some(requested)) = (enclave_core::deployment::selected(), socket_dir.as_ref()) {
                if requested != &target.target().layout.socket_root {
                    return Err(enclave_core::err!(EACCES, "DEPLOYMENT_SOCKET_MISMATCH"));
                }
            }
            let dir = socket_dir.unwrap_or_else(|| env.socket_dir.clone());
            let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            enclave_core::supervisor::serve_with_profile(&dir, cli.dev, profile, stop)?;
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Daemon {
            op: DaemonOp::Start,
        } => {
            if enclave_core::deployment::selected().is_some() {
                let report=ctl::selected_core_start(&env)?;
                print(cli.json,&report);
                return Ok(if report.successful {ExitCode::SUCCESS}else{ExitCode::from(3)});
            }
            let s = ctl::start(&env)?;
            if cli.json {
                print(true, &s);
            } else {
                for d in &s {
                    println!(
                        "started uid={} {} pid={} rss={:.1} MiB",
                        d.daemon_uid,
                        d.binary,
                        d.pid,
                        d.rss_bytes as f64 / 1048576.0
                    );
                }
            }
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Daemon {op:DaemonOp::StartIntent} => {
            let report=ctl::selected_intent_start(&env)?;
            let successful=report.successful;
            print(cli.json,&report);
            Ok(if successful {ExitCode::SUCCESS}else{ExitCode::from(3)})
        }
        Cmd::Daemon {op:DaemonOp::StartSupervisor} => {
            let report=ctl::selected_supervisor_start(&env)?;
            let successful=report.successful;
            print(cli.json,&report);
            Ok(if successful {ExitCode::SUCCESS}else{ExitCode::from(3)})
        }
        Cmd::Daemon { op: DaemonOp::Stop } => {
            println!("stopped {} daemon(s)", ctl::stop(&env)?);
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Daemon {op:DaemonOp::StopAuxiliary} => {
            Err(enclave_core::err!(EACCES,"DEPLOYMENT_CONTEXT_REQUIRED"))
        }
        Cmd::Daemon {op:DaemonOp::StopBroker} => {
            let report=ctl::selected_broker_stop()?;
            let successful=report.successful;
            print(cli.json,&report);
            Ok(if successful {ExitCode::SUCCESS}else{ExitCode::from(3)})
        }
        Cmd::Daemon {
            op: DaemonOp::Status,
        } => {
            let s = ctl::status(&env);
            if cli.json {
                print(true, &s);
            } else {
                println!(
                    "{:<4} {:<24} {:<5} {:>8} {:>12} {:>9}  state",
                    "uid", "binary", "up", "pid", "rss (MiB)", "ceiling"
                );
                for r in &s.rows {
                    println!(
                        "{:<4} {:<24} {:<5} {:>8} {:>12.1} {:>9}  {}",
                        r.uid,
                        r.binary,
                        r.up,
                        r.pid.map(|p| p.to_string()).unwrap_or_default(),
                        r.rss_bytes as f64 / 1048576.0,
                        r.ceiling_bytes / 1048576,
                        r.state
                    );
                }
                println!("UID 702–705 RSS: {:.1} MiB (budget 152)   total: {:.1} MiB (budget 200)   healthy: {}", s.rss_702_705_bytes as f64 / 1048576.0, s.rss_total_bytes as f64 / 1048576.0, s.healthy);
            }
            Ok(if s.healthy {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(3)
            })
        }
        Cmd::Tuf { op } => match op {
            TufOp::Init { keys, repo } => {
                let keys =
                    keys.unwrap_or_else(|| PathBuf::from(".enclave-local/tuf-keys/keys.json"));
                let repo = repo.unwrap_or_else(|| {
                    if env.dev {
                        env.state_dir.join("tuf/repo")
                    } else {
                        PathBuf::from(".enclave-local/dist/tuf/repo")
                    }
                });
                let v = ctl::tuf_init(&keys, &repo)?;
                print(
                    cli.json,
                    &serde_json::json!({"initialized": true, "version": v, "repo": repo}),
                );
                Ok(ExitCode::SUCCESS)
            }
            TufOp::Sign {
                name,
                file,
                custom,
                keys,
                repo,
            } => {
                let keys =
                    keys.unwrap_or_else(|| PathBuf::from(".enclave-local/tuf-keys/keys.json"));
                let repo = repo.unwrap_or_else(|| {
                    if env.dev {
                        env.state_dir.join("tuf/repo")
                    } else {
                        PathBuf::from(".enclave-local/dist/tuf/repo")
                    }
                });
                let bytes = std::fs::read(&file)
                    .map_err(|e| enclave_core::err!(EIO, "TARGET_READ", "{e}"))?;
                let custom_val: Option<serde_json::Value> = match custom {
                    Some(s) => Some(
                        serde_json::from_str(&s)
                            .map_err(|e| enclave_core::err!(EINVAL, "CUSTOM_JSON", "{e}"))?,
                    ),
                    None => None,
                };
                let v = ctl::tuf_sign(&keys, &repo, &name, &bytes, custom_val)?;
                print(cli.json, &serde_json::json!({"signed": name, "version": v}));
                Ok(ExitCode::SUCCESS)
            }
            TufOp::HostConfig { op } => match op {
                HostConfigOp::Generate {
                    profile_floor,
                    grant_key,
                    out,
                } => {
                    let pf = Profile::parse(&profile_floor)?;
                    let cfg = ctl::tuf_generate_host_config(pf, grant_key, &env.state_dir)?;
                    if let Some(out_path) = out {
                        let bytes = cfg.to_json_bytes()?;
                        std::fs::write(&out_path, &bytes)
                            .map_err(|e| enclave_core::err!(EIO, "WRITE_HOST_CONFIG", "{e}"))?;
                        print(
                            cli.json,
                            &serde_json::json!({"written": out_path, "config": cfg}),
                        );
                    } else {
                        print(true, &cfg);
                    }
                    Ok(ExitCode::SUCCESS)
                }
                HostConfigOp::Publish {
                    profile_floor,
                    grant_key,
                    keys,
                    repo,
                } => {
                    let keys =
                        keys.unwrap_or_else(|| PathBuf::from(".enclave-local/tuf-keys/keys.json"));
                    let repo = repo.unwrap_or_else(|| {
                        if env.dev {
                            env.state_dir.join("tuf/repo")
                        } else {
                            PathBuf::from(".enclave-local/dist/tuf/repo")
                        }
                    });
                    let pf = Profile::parse(&profile_floor)?;
                    let (cfg, v) =
                        ctl::tuf_publish_host_config(&keys, &repo, pf, grant_key, &env.state_dir)?;
                    print(
                        cli.json,
                        &serde_json::json!({"published": true, "version": v, "config": cfg}),
                    );
                    Ok(ExitCode::SUCCESS)
                }
            },
            TufOp::Policy { op } => match op {
                PolicyOp::Publish {
                    schema,
                    policies,
                    keys,
                    repo,
                } => {
                    let keys =
                        keys.unwrap_or_else(|| PathBuf::from(".enclave-local/tuf-keys/keys.json"));
                    let repo = repo.unwrap_or_else(|| {
                        if env.dev {
                            env.state_dir.join("tuf/repo")
                        } else {
                            PathBuf::from(".enclave-local/dist/tuf/repo")
                        }
                    });
                    let schema_str = match schema {
                        Some(p) => Some(
                            std::fs::read_to_string(&p)
                                .map_err(|e| enclave_core::err!(EIO, "SCHEMA_READ", "{e}"))?,
                        ),
                        None => None,
                    };
                    let policies_str = match policies {
                        Some(p) => Some(
                            std::fs::read_to_string(&p)
                                .map_err(|e| enclave_core::err!(EIO, "POLICIES_READ", "{e}"))?,
                        ),
                        None => None,
                    };
                    let (_bundle, v) =
                        ctl::tuf_publish_policy(&keys, &repo, schema_str, policies_str)?;
                    print(
                        cli.json,
                        &serde_json::json!({
                            "published": true,
                            "version": v,
                            "target": enclave_agent_runtime::cedar_engine::CEDAR_BUNDLE_TARGET,
                        }),
                    );
                    Ok(ExitCode::SUCCESS)
                }
            },
            TufOp::Vk { op } => match op {
                VkOp::Publish { keys, repo } => {
                    let keys =
                        keys.unwrap_or_else(|| PathBuf::from(".enclave-local/tuf-keys/keys.json"));
                    let repo = repo.unwrap_or_else(|| {
                        if env.dev {
                            env.state_dir.join("tuf/repo")
                        } else {
                            PathBuf::from(".enclave-local/dist/tuf/repo")
                        }
                    });
                    let (manifest, v) = ctl::tuf_publish_vk_manifest(&keys, &repo)?;
                    print(
                        cli.json,
                        &serde_json::json!({
                            "published": true,
                            "version": v,
                            "target": enclave_zk_auditor::zk::manifest::VK_MANIFEST_TARGET,
                            "air_domain": manifest.air_domain,
                            "vk_digest": manifest.vk_digest,
                        }),
                    );
                    Ok(ExitCode::SUCCESS)
                }
            },
            TufOp::MigrateCanonical { keys, repo } => {
                let keys =
                    keys.unwrap_or_else(|| PathBuf::from(".enclave-local/tuf-keys/keys.json"));
                let repo = repo.unwrap_or_else(|| {
                    if env.dev {
                        env.state_dir.join("tuf/repo")
                    } else {
                        PathBuf::from(".enclave-local/dist/tuf/repo")
                    }
                });
                let v = ctl::tuf_migrate_canonical(&keys, &repo)?;
                print(
                    cli.json,
                    &serde_json::json!({"migrated": true, "version": v, "repo": repo, "canonical_json": true}),
                );
                Ok(ExitCode::SUCCESS)
            }
            TufOp::Refresh { repo, bootstrap } => {
                let repo = match repo {
                    Some(r) => r,
                    None if env.dev => env.state_dir.join("tuf/repo"),
                    None => return Err(enclave_core::err!(EINVAL, "TUF_REPO_REQUIRED")),
                };
                let v = ctl::tuf_refresh(&env, &repo, bootstrap)?;
                print(
                    cli.json,
                    &serde_json::json!({"timestamp": v.0, "snapshot": v.1, "targets": v.2}),
                );
                Ok(ExitCode::SUCCESS)
            }
        },
        Cmd::Model {
            op:
                ModelOp::Admit {
                    class,
                    manifest,
                    weights,
                    corpus,
                    target,
                },
        } => {
            let r = ctl::model_admit(
                &env,
                ExecutionClass::parse(&class)?,
                &AdmitInput {
                    manifest,
                    weights,
                    corpus,
                    target,
                },
            )?;
            print(cli.json, &r);
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Model { op: ModelOp::Run { class, prompt, n, lease, reveal } } => {
            let input = mcp_enclave::model_run::RunInput { prompt, n, lease, reveal };
            let r = mcp_enclave::model_run::model_run(&env, ExecutionClass::parse(&class)?, &input)?;
            print(cli.json, &r);
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Vault {
            op: VaultOp::Enroll,
        } => {
            print(cli.json, &ctl::vault_enroll(&env)?);
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Vault { op: VaultOp::EnrollBiometric } => {
            print(cli.json, &ctl::vault_enroll_biometric(&env)?);
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Vault {op:VaultOp::EnrollmentBegin {pending_output}}=>{
            print(cli.json,&ctl::vault_enrollment_begin(&env,&pending_output)?);Ok(ExitCode::SUCCESS)
        }
        Cmd::Vault {op:VaultOp::EnrollmentActivate {receipt}}=>{
            print(cli.json,&ctl::vault_enrollment_activate(&env,&receipt)?);Ok(ExitCode::SUCCESS)
        }
        Cmd::Vault {op:VaultOp::EnrollmentRenew {receipt}}=>{
            print(cli.json,&ctl::vault_enrollment_renew(&env,&receipt)?);Ok(ExitCode::SUCCESS)
        }
        Cmd::Vault {op:VaultOp::EnrollmentBeginBackup {pending_output}}=>{
            print(cli.json,&ctl::vault_enrollment_begin_backup(&env,&pending_output)?);Ok(ExitCode::SUCCESS)
        }
        Cmd::Vault {op:VaultOp::EnrollmentAddBackup {receipt}}=>{
            print(cli.json,&ctl::vault_enrollment_add_backup(&env,&receipt)?);Ok(ExitCode::SUCCESS)
        }
        Cmd::Vault {op:VaultOp::EnrollmentRenewMembership {primary_receipt,backup_receipt}}=>{
            print(cli.json,&ctl::vault_enrollment_renew_membership(&env,&primary_receipt,&backup_receipt)?);Ok(ExitCode::SUCCESS)
        }
        Cmd::Vault {op:VaultOp::NamespaceBackupMigrate {namespace}}=>{
            print(cli.json,&ctl::vault_namespace_backup_migrate(&env,&namespace)?);Ok(ExitCode::SUCCESS)
        }
        Cmd::Vault {op:VaultOp::TravelRecoveryActivate {token}}=>{
            print(cli.json,&ctl::vault_travel_recovery_activate(&env,&token)?);Ok(ExitCode::SUCCESS)
        }
        Cmd::Vault {op:VaultOp::MemberLossRecord {statement}}=>{
            print(cli.json,&ctl::vault_member_loss_record(&env,&statement)?);Ok(ExitCode::SUCCESS)
        }
        Cmd::Vault {op:VaultOp::MemberReplacementPrepare {candidate,enrollment_evidence_id,replacement_receipt,survivor_receipt}}=>{
            print(cli.json,&ctl::vault_member_replacement_prepare(&env,&candidate,&enrollment_evidence_id,
                &replacement_receipt,survivor_receipt.as_deref())?);Ok(ExitCode::SUCCESS)
        }
        Cmd::Vault {op:VaultOp::CasWrap{namespace,epoch,wrapping_epoch}}=>{
            print(cli.json,&ctl::vault_cas_wrap(&env,namespace,epoch,wrapping_epoch)?);Ok(ExitCode::SUCCESS)
        }
        Cmd::Vault {op:VaultOp::CasImport{envelope}}=>{
            print(cli.json,&ctl::vault_cas_import(&env,&envelope)?);Ok(ExitCode::SUCCESS)
        }
        Cmd::Vault {op:VaultOp::CasRotate{envelope,new_wrapping_epoch}}=>{
            print(cli.json,&ctl::vault_cas_rotate(&env,&envelope,new_wrapping_epoch)?);Ok(ExitCode::SUCCESS)
        }
        Cmd::Vault {op:VaultOp::CasFloor{namespace,minimum_wrapping_epoch}}=>{
            print(cli.json,&ctl::vault_cas_floor(&env,namespace,minimum_wrapping_epoch)?);Ok(ExitCode::SUCCESS)
        }
        Cmd::Vault {
            op: VaultOp::Detokenize { surrogate, class },
        } => {
            let action_class = match class.as_str() {
                "A3" => enclave_core::profile::ActionClass::A3,
                "A4" => enclave_core::profile::ActionClass::A4,
                _ => {
                    return Err(enclave_core::err!(
                        EINVAL,
                        "ACTION_CLASS",
                        "expected A3 or A4"
                    ))
                }
            };
            let r = ctl::vault_detokenize(&env, surrogate, profile, action_class)?;
            print(cli.json, &r);
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Audit {
            op: AuditOp::Verify { path, anchor },
        } => {
            let anchor = anchor
                .map(|p| -> enclave_core::error::EnclaveResult<enclave_core::audit::ChainAnchor> {
                    let bytes = std::fs::read(p)
                        .map_err(|e| enclave_core::err!(EIO, "AUDIT_ANCHOR_READ", "{e}"))?;
                    serde_json::from_slice(&bytes)
                        .map_err(|e| enclave_core::err!(EINVAL, "AUDIT_ANCHOR_PARSE", "{e}"))
                })
                .transpose()?;
            let r = ctl::audit_verify_with_anchor(
                &path.unwrap_or_else(|| env.audit_dir.clone()),
                anchor,
            )?;
            let ok = r.iter().all(|j| j.ok && j.truncation_checked);
            print(cli.json, &r);
            Ok(if ok {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(4)
            })
        }
        Cmd::Ifc { op: IfcOp::PolicySli { jsonl } } => {
            let export = ctl::ifc_policy_sli(&env)?;
            if jsonl {
                // Omit buckets with missing outcomes, retaining a coverage hole;
                // metadata stays separate so stdout is exact aggregator JSONL.
                for row in export.snapshot.rows() {
                    println!("{}", serde_json::to_string(&row).map_err(|_| enclave_core::err!(EIO, "POLICY_SLI_SERIALIZE"))?);
                }
                let mut receipt = serde_json::to_value(&export).map_err(|_| enclave_core::err!(EIO, "POLICY_SLI_SERIALIZE"))?;
                receipt["snapshot"].as_object_mut().unwrap().remove("buckets");
                eprintln!("{}", receipt);
            } else { print(cli.json, &export); }
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Ifc {
            op: IfcOp::RefreshPolicy { bundle },
        } => {
            let bundle_bytes = match bundle {
                Some(p) => Some(
                    std::fs::read(&p).map_err(|e| enclave_core::err!(EIO, "BUNDLE_READ", "{e}"))?,
                ),
                None => None,
            };
            ctl::ifc_refresh_policy(&env.socket_dir, bundle_bytes, env.dev)?;
            print(cli.json, &serde_json::json!({ "refreshed": true }));
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Turn {
            op:
                TurnOp::Submit {
                    directive,
                    attachments,
                },
        } => {
            let res = ctl::turn_submit(&env, &directive, &attachments)?;
            print(cli.json, &res);
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Turn {op: TurnOp::Execute {directive,source,tools,budget_mb,step_up}} => {
            let result=mcp_enclave::gateway_client::execute(&env,&directive,&source,&tools,budget_mb,step_up)?;
            print(cli.json,&result);
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Launchd {
            op:
                LaunchdOp::Render {
                    out,
                    bin_dir,
                    with_fido_emulator,
                    custody_authority_config,
                },
        } => {
            let l = if let Some(target) = enclave_core::deployment::selected() {
                if bin_dir.is_some() || custody_authority_config.is_some() || with_fido_emulator {
                    return Err(enclave_core::err!(EACCES, "DEPLOYMENT_MIXED_ARGUMENTS"));
                }
                mcp_enclave::launchd::Layout::for_target(target.clone())?
            } else {
                let custody_authority = custody_authority_config.as_ref().map(|path|
                    enclave_custody_vaultd::provisioning::CustodyProvisioning::load(
                        path, profile, enclave_crypto::time::now_unix(),
                    )).transpose()?;
                mcp_enclave::launchd::Layout {
                    bin_dir: bin_dir.unwrap_or_else(|| "/opt/enterprise/enclave/bin".into()),
                    custody_authority,
                    fido_emulator: with_fido_emulator,
                    profile: profile.to_string(),
                    ..Default::default()
                }
            };
            print(cli.json, &mcp_enclave::launchd::render_all(&out, &l)?);
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Launchd { op: LaunchdOp::DeploymentInstallPlan } => {
            let checked = enclave_core::deployment::selected()
                .ok_or_else(|| enclave_core::err!(EACCES, "DEPLOYMENT_CONTEXT_REQUIRED"))?;
            let plan = mcp_enclave::deploy::target_plan::prepare(checked)?;
            // Fully construct the report before emitting machine JSON stdout.
            let output = serde_json::to_string_pretty(&plan)
                .map_err(|_| enclave_core::err!(EIO, "DEPLOYMENT_PLAN_SERIALIZE"))?;
            println!("{output}");
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Launchd { op: LaunchdOp::DeploymentCheck { dist, signing_mode } } => {
            let checked = enclave_core::deployment::selected()
                .ok_or_else(|| enclave_core::err!(EACCES, "DEPLOYMENT_CONTEXT_REQUIRED"))?;
            validate_deployment_build_destination(&checked.target().layout.staging_root,
                &dist, checked.target().signing_identity_mode, &signing_mode)?;
            print(cli.json, &serde_json::json!({"status":"valid", "profile":profile,
                "signing_mode":signing_mode}));
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Launchd { op: LaunchdOp::CustodyConfigCheck { config } } => {
            if let Some(target) = enclave_core::deployment::selected() {
                if config != target.target().authority_config {
                    return Err(enclave_core::err!(EACCES, "DEPLOYMENT_AUTHORITY_MISMATCH"));
                }
            }
            let checked = enclave_custody_vaultd::provisioning::CustodyProvisioning::load(
                &config, profile, enclave_crypto::time::now_unix(),
            )?;
            print(cli.json, checked.receipt());
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Launchd {op:LaunchdOp::OidcSession {op:OidcSessionOp::Renew {expires_unix}}}=>{
            print(cli.json,&mcp_enclave::oidc_session::renew_current_session(expires_unix)?);Ok(ExitCode::SUCCESS)
        }
        Cmd::Launchd {
            op: LaunchdOp::GrantKey { state_dir },
        } => {
            let public = if enclave_core::deployment::selected().is_some() {
                ctl::provision_target_grant_key(&env, state_dir.as_deref())?
            } else {
                mcp_enclave::launchd::provision_grant_key(
                    state_dir.as_deref().unwrap_or_else(||std::path::Path::new("/var/db/enclave")),
                )?
            };
            print(
                cli.json,
                &serde_json::json!({ "ifc_grant_public_key": public }),
            );
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Measure { lock } => {
            let r = ctl::measure(&env, lock.as_deref())?;
            print(cli.json, &r);
            Ok(ExitCode::from(if r.budget.compliant {0} else {mcp_enclave::deploy::EXIT_UNHEALTHY as u8}))
        }
        Cmd::Lint {
            op: LintOp::Lockfile { path },
        } => match lint_lockfile(&path) {
            Ok(()) => {
                print(
                    cli.json,
                    &serde_json::json!({ "status": "ok", "path": path.display().to_string() }),
                );
                Ok(ExitCode::SUCCESS)
            }
            Err(e) => {
                eprintln!("lockfile lint error: {e}");
                Ok(ExitCode::FAILURE)
            }
        },
        Cmd::Deploy {
            verb,
            target,
            dmg,
            jobs_dir,
            cas_dir,
            r#async,
            sync,
            dry_run,
            yes,
            remove_accounts,
            purge_state,
            dist,
        } => {
            if enclave_core::deployment::selected().is_some() {
                // Default deployment scripts and worker environments contain
                // installed paths; a descriptor cannot authorize those writes.
                return Err(enclave_core::err!(ENOSYS, "DEPLOYMENT_INSTALLER_UNAVAILABLE"));
            }
            let args = mcp_enclave::deploy::DeployArgs {
                target,
                dmg,
                jobs_dir,
                cas_dir,
                r#async,
                sync,
                dry_run,
                yes,
                remove_accounts,
                purge_state,
                dist,
            };
            let (result, code) = mcp_enclave::deploy::execute(verb, &cli.profile, &args);
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&result).unwrap());
            } else {
                println!("[{}] {} (exit {})", result.profile, result.summary, code);
                if let Some(details) = &result.details {
                    println!("{}", serde_json::to_string_pretty(details).unwrap());
                }
            }
            Ok(ExitCode::from(code as u8))
        }
        Cmd::Pf { op } => {
            if enclave_core::deployment::selected().is_some() {
                return Err(enclave_core::err!(ENOSYS, "DEPLOYMENT_PF_UNAVAILABLE"));
            }
            match op {
            PfOp::Render { out } => {
                mcp_enclave::pf::render_anchors(&out)?;
                println!("Rendered pf anchors to {}", out.display());
                Ok(ExitCode::SUCCESS)
            }
            PfOp::Install {
                anchors_dir,
                pf_conf,
            } => {
                mcp_enclave::pf::install_pf(&anchors_dir, &pf_conf)?;
                println!("Installed pf anchors to {}", anchors_dir.display());
                Ok(ExitCode::SUCCESS)
            }
            }
        }
        Cmd::Crypto { op } => match op {
            CryptoOp::Status => {
                print(cli.json, &ctl::crypto_status(&env)?);
                Ok(ExitCode::SUCCESS)
            }
            CryptoOp::SelfTest => {
                print(cli.json, &ctl::crypto_self_test()?);
                Ok(ExitCode::SUCCESS)
            }
            CryptoOp::Policy {
                op:
                    CryptoPolicyOp::Set {
                        wire_suite,
                        temporary_override_ticket,
                    },
            } => {
                print(
                    cli.json,
                    &ctl::crypto_policy_set(
                        &env,
                        &wire_suite,
                        temporary_override_ticket.as_deref(),
                    )?,
                );
                Ok(ExitCode::SUCCESS)
            }
            CryptoOp::FlushSessions => {
                print(cli.json, &ctl::crypto_flush_sessions(&env)?);
                Ok(ExitCode::SUCCESS)
            }
        },
    }
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(1)
        }
    }
}

#[cfg(test)]
mod deployment_build_tests {
    use super::*;
    use enclave_core::deployment::DeploymentSigningMode;

    #[test]
    fn selected_supervisor_route_requires_explicit_l2_protected_target_before_loading() {
        for extra in [None,Some("--dev"),Some("--state-dir=/unopened-state")] {
            let mut arguments=vec!["mcp-enclave"];
            if let Some(extra)=extra {arguments.push(extra);}
            arguments.extend(["daemon","start-supervisor"]);
            let cli=Cli::try_parse_from(arguments).unwrap();
            assert!(validate_selected_supervisor_request(&cli,Profile::L2).unwrap_err().is("DEPLOYMENT_CONTEXT_REQUIRED"));
        }
        for extra in ["--dev","--state-dir=/unopened-state"] {
            let cli=Cli::try_parse_from(["mcp-enclave",extra,"--deployment-config","/unopened-target.json","daemon","start-supervisor"]).unwrap();
            assert!(validate_selected_supervisor_request(&cli,Profile::L2).unwrap_err().is("DEPLOYMENT_MIXED_ARGUMENTS"));
        }
        let cli=Cli::try_parse_from(["mcp-enclave","--deployment-config","/unopened-target.json","daemon","start-supervisor"]).unwrap();
        validate_selected_supervisor_request(&cli,Profile::L2).unwrap();
        for profile in [Profile::L1,Profile::L3] {
            assert!(validate_selected_supervisor_request(&cli,profile).unwrap_err().is("DEPLOYMENT_SUPERVISOR_SCOPE_UNSUPPORTED"));
        }
    }

    #[test]
    fn selected_supervisor_cli_has_no_command_path_domain_or_readiness_override() {
        for extra in ["--uid=0","--domain=system","--plist=/unopened.plist","--command=bootstrap",
            "--runtime-ready","--pf-ready","--skip-pf","--force","--resume"] {
            assert!(Cli::try_parse_from(["mcp-enclave","--deployment-config","/unopened-target.json",
                "daemon","start-supervisor",extra]).is_err());
        }
    }

    #[cfg(not(target_os="macos"))]
    #[test]
    fn only_explicit_selected_stop_routes_use_native_teardown_before_general_admission() {
        // No protected descriptor or reference needs to exist to distinguish
        // the native-only teardown boundary from the ordinary reader path.
        for op in ["stop","stop-auxiliary"] {
            let arguments=["mcp-enclave","--deployment-config","/unopened-target/deployment.json","daemon",op];
            assert!(run(Cli::try_parse_from(arguments).unwrap()).unwrap_err().is("DEPLOYMENT_TEARDOWN_NATIVE_REQUIRED"));
        }
        for op in ["start","status","stop-broker"] {
            let cli=Cli::try_parse_from(["mcp-enclave","--deployment-config","/unopened-target/deployment.json","daemon",op]).unwrap();
            assert!(!run(cli).unwrap_err().is("DEPLOYMENT_TEARDOWN_NATIVE_REQUIRED"));
        }
        for extra in ["--dev","--state-dir=/unopened-state"] {for op in ["stop","stop-auxiliary"] {
            let cli=Cli::try_parse_from(["mcp-enclave",extra,"--deployment-config","/unopened-target/deployment.json","daemon",op]).unwrap();
            assert!(run(cli).unwrap_err().is("DEPLOYMENT_MIXED_ARGUMENTS"));
        }}
        assert!(enclave_core::deployment::selected().is_none());
    }

    #[test]
    fn selected_auxiliary_actions_have_no_default_or_development_target_fallback() {
        for op in ["stop-auxiliary","stop-broker","start-intent"] {for extra in [None,Some("--dev")] {
            let mut arguments=vec!["mcp-enclave"];
            if let Some(extra)=extra {arguments.push(extra);}
            arguments.extend(["daemon",op]);
            assert!(run(Cli::try_parse_from(arguments).unwrap()).unwrap_err().is("DEPLOYMENT_CONTEXT_REQUIRED"));
        }}
    }

    #[test]
    fn grant_key_does_not_parse_an_installed_default_into_selected_arguments() {
        // Choosing the default must occur after the protected target is known.
        let cli=Cli::try_parse_from(["mcp-enclave","launchd","grant-key"]).unwrap();
        assert!(matches!(cli.cmd,Cmd::Launchd {op:LaunchdOp::GrantKey {state_dir:None}}));
        let cli=Cli::try_parse_from(["mcp-enclave","launchd","grant-key","--state-dir","/explicit/state"]).unwrap();
        match cli.cmd {
            Cmd::Launchd {op:LaunchdOp::GrantKey {state_dir:Some(path)}}=>assert_eq!(path,PathBuf::from("/explicit/state")),
            _=>panic!("explicit grant-key state directory was lost"),
        }
    }

    #[test]
    fn dedicated_birth_public_routes_require_exact_closed_arguments() {
        for command in ["dedicated-birth-session","dedicated-birth-render"] {
            assert!(Cli::try_parse_from(["mcp-enclave",command]).is_err());
        }
        let session=["mcp-enclave","dedicated-birth-session","--template","/protected/template.json",
            "--template-root","/template","--allocator-parent","/protected/allocator"];
        let render=["mcp-enclave","dedicated-birth-render","--descriptor","/allocated/config/deployment.json",
            "--descriptor-input","/public/descriptor.json","--custody-manifest","/public/manifest.json"];
        assert!(matches!(Cli::try_parse_from(session).unwrap().cmd,Cmd::DedicatedBirthSession {..}));
        assert!(matches!(Cli::try_parse_from(render).unwrap().cmd,Cmd::DedicatedBirthRender {..}));
        for arguments in [session.as_slice(),render.as_slice()] {for extra in ["--nonce=00","--resume","--pin=never-accepted"] {
            let mut arguments=arguments.to_vec();arguments.push(extra);
            assert!(Cli::try_parse_from(arguments).is_err());
        }}
    }

    #[test]
    fn dedicated_birth_override_refusals_precede_streams_loading_and_environment() {
        for command in ["dedicated-birth-session","dedicated-birth-render"] {
            let fields=if command=="dedicated-birth-session" {
                ["--template","/unopened/template.json","--template-root","/unopened/template","--allocator-parent","/unopened/allocator"]
            }else{
                ["--descriptor","/unopened/config/deployment.json","--descriptor-input","/unopened/public.json","--custody-manifest","/unopened/manifest.json"]
            };
            for (extra,reason) in [("--dev","BIRTH_SESSION_MIXED_ARGUMENTS"),
                ("--state-dir=/unopened/state","BIRTH_SESSION_MIXED_ARGUMENTS"),
                ("--deployment-config=/unopened/deployment.json","BIRTH_SESSION_MIXED_ARGUMENTS"),
                ("--profile=L1","BIRTH_SESSION_L2_REQUIRED"),("--profile=L3","BIRTH_SESSION_L2_REQUIRED")] {
                let mut arguments=vec!["mcp-enclave",extra,command];arguments.extend(fields);
                assert!(run(Cli::try_parse_from(arguments).unwrap()).unwrap_err().is(reason));
            }
        }
        assert!(enclave_core::deployment::selected().is_none());
    }

    fn mode() -> (DeploymentSigningMode, &'static str, &'static str) {
        match enclave_core::codesign::signing_mode() {
            enclave_core::codesign::SigningMode::LocalPins => (DeploymentSigningMode::LocalPins,"local-pins","team-id"),
            enclave_core::codesign::SigningMode::TeamId => (DeploymentSigningMode::TeamId,"team-id","local-pins"),
        }
    }

    #[test]
    fn deployment_check_requires_complete_closed_arguments() {
        for args in [
            vec!["mcp-enclave","launchd","deployment-check"],
            vec!["mcp-enclave","launchd","deployment-check","--dist","/stage"],
            vec!["mcp-enclave","launchd","deployment-check","--signing-mode","local-pins"],
            vec!["mcp-enclave","launchd","deployment-check","--dist","/stage","--signing-mode","unknown"],
        ] { assert!(Cli::try_parse_from(args).is_err()); }
        let (_, name, _) = mode();
        let cli = Cli::try_parse_from(["mcp-enclave","launchd","deployment-check","--dist","/stage","--signing-mode",name]).unwrap();
        assert!(run(cli).unwrap_err().is("DEPLOYMENT_CONTEXT_REQUIRED"));
    }

    #[test]
    fn deployment_build_refuses_wrong_dist_and_signing_before_outputs() {
        let (mode, name, other) = mode();
        let root = std::path::Path::new("/var/tmp/mcpmac-declared-build-stage");
        validate_deployment_build_destination(root,root,mode,name).unwrap();
        validate_deployment_build_destination(root,std::path::Path::new("/private/var/tmp/mcpmac-declared-build-stage"),mode,name).unwrap();
        for wrong in ["/var/tmp", "/var/tmp/mcpmac-declared-build-stage/child", "/var/tmp/other-build-stage"] {
            assert!(validate_deployment_build_destination(root,std::path::Path::new(wrong),mode,name)
                .unwrap_err().is("DEPLOYMENT_STAGING_MISMATCH"));
        }
        for unsafe_path in ["relative-stage", "/", "/var/tmp/../stage", "/var/tmp/stage;write"] {
            assert!(validate_deployment_build_destination(root,std::path::Path::new(unsafe_path),mode,name).is_err());
        }
        for wrong in [other,"unknown"] {
            assert!(validate_deployment_build_destination(root,root,mode,wrong)
                .unwrap_err().is("DEPLOYMENT_SIGNING_MODE"));
        }
        let contrary = match mode {
            DeploymentSigningMode::LocalPins => DeploymentSigningMode::TeamId,
            DeploymentSigningMode::TeamId => DeploymentSigningMode::LocalPins,
        };
        assert!(validate_deployment_build_destination(root,root,contrary,name)
            .unwrap_err().is("DEPLOYMENT_SIGNING_MODE"));
    }
}
