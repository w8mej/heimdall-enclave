//! The five non-colluding `LaunchDaemons` of the v3.0 topology (ADR-006) and
//! their pinned resource envelopes (`schemas/enclave.lock.toml`).

use serde::{Deserialize, Serialize};

/// MiB in bytes.
pub const MIB: u64 = 1024 * 1024;
/// Sum of UID 702–705 RSS ceilings (ADR-006, V21).
pub const UID_702_705_BUDGET_MIB: u64 = 152;
/// Steady-state budget including UID 701.
pub const STEADY_STATE_BUDGET_MIB: u64 = 200;
/// Burst budget while the `_enclaveintent` (uid=501) prompt helper is active.
pub const ACTIVE_PROMPT_BUDGET_MIB: u64 = 232;
/// `_enclaveintent` helper ceiling.
pub const INTENT_HELPER_MIB: u64 = 32;
/// SPIFFE trust domain (F-039).
pub const TRUST_DOMAIN: &str = "corporate.internal";

/// Enclave daemon identities.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum DaemonId {
    /// UID 701 `_llmagent` — `enclave-model-runnerd` (FS-701).
    ModelRunner,
    /// UID 702 `_enclavecas` — `enclave-swarm-syncd` (FS-702).
    SwarmSync,
    /// UID 703 `_piivault` — `enclave-custody-vaultd` (FS-703).
    CustodyVault,
    /// UID 704 `_enclaveifc` — `enclave-agent-runtime` (FS-704).
    AgentRuntime,
    /// UID 705 `_enclavezk` — `enclave-zk-auditor` (FS-705).
    ZkAuditor,
}

/// Offset of every enclave group ID from its spec number (`701` → `8701`).
pub const GID_BLOCK: u32 = 8000;

impl DaemonId {
    /// All daemons in UID order.
    pub const ALL: [DaemonId; 5] = [
        DaemonId::ModelRunner,
        DaemonId::SwarmSync,
        DaemonId::CustodyVault,
        DaemonId::AgentRuntime,
        DaemonId::ZkAuditor,
    ];

    /// Production POSIX UID (the primary group is [`Self::gid`]).
    pub const fn uid(self) -> u32 {
        match self {
            DaemonId::ModelRunner => 701,
            DaemonId::SwarmSync => 702,
            DaemonId::CustodyVault => 703,
            DaemonId::AgentRuntime => 704,
            DaemonId::ZkAuditor => 705,
        }
    }
    /// Look up by UID.
    pub fn from_uid(uid: u32) -> Option<Self> {
        Self::ALL.into_iter().find(|d| d.uid() == uid)
    }
    /// POSIX account name (`enclave.lock.toml`).
    pub const fn account(self) -> &'static str {
        match self {
            DaemonId::ModelRunner => "_llmagent",
            DaemonId::SwarmSync => "_enclavecas",
            DaemonId::CustodyVault => "_piivault",
            DaemonId::AgentRuntime => "_enclaveifc",
            DaemonId::ZkAuditor => "_enclavezk",
        }
    }
    /// Binary name.
    pub const fn binary(self) -> &'static str {
        match self {
            DaemonId::ModelRunner => "enclave-model-runnerd",
            DaemonId::SwarmSync => "enclave-swarm-syncd",
            DaemonId::CustodyVault => "enclave-custody-vaultd",
            DaemonId::AgentRuntime => "enclave-agent-runtime",
            DaemonId::ZkAuditor => "enclave-zk-auditor",
        }
    }
    /// launchd label suffix; plist is `com.enterprise.enclave.<suffix>.plist`.
    pub const fn plist_suffix(self) -> &'static str {
        match self {
            DaemonId::ModelRunner => "adapter",
            DaemonId::SwarmSync => "cas",
            DaemonId::CustodyVault => "custody",
            DaemonId::AgentRuntime => "ifc",
            DaemonId::ZkAuditor => "zk",
        }
    }
    /// launchd label.
    pub fn launchd_label(self) -> String {
        format!("com.enterprise.enclave.{}", self.plist_suffix())
    }
    /// Hard RSS ceiling in MiB (FS-701..705; lock file `memory_limit_mib`).
    pub const fn rss_ceiling_mib(self) -> u64 {
        match self {
            DaemonId::ModelRunner => 48,
            DaemonId::SwarmSync => 48,
            DaemonId::CustodyVault => 24,
            DaemonId::AgentRuntime => 32,
            DaemonId::ZkAuditor => 48,
        }
    }
    /// Hard RSS ceiling in bytes.
    pub const fn rss_ceiling_bytes(self) -> u64 {
        self.rss_ceiling_mib() * MIB
    }
    /// SPIFFE ID `spiffe://corporate.internal/enclave/uid/<uid>`.
    pub fn spiffe_id(self) -> String {
        format!("spiffe://{TRUST_DOMAIN}/enclave/uid/{}", self.uid())
    }
    /// UDS socket path relative to the mesh directory:
    /// `<suffix>/<suffix>.sock`. Each server owns its own sub-directory
    /// (`<mesh>/<suffix>/`, owner = daemon, group = [`Self::client_group`],
    /// mode `2750`) so no daemon can create, replace or chmod another
    /// daemon's socket (GAP-01).
    pub fn socket_name(self) -> String {
        format!("{0}/{0}.sock", self.plist_suffix())
    }
    /// Per-server directory name under the mesh / journal directories.
    pub const fn dir_name(self) -> &'static str {
        self.plist_suffix()
    }
    /// POSIX group whose members may connect to this daemon's socket. Its
    /// members are exactly the daemon accounts of
    /// [`crate::ipc::production_policy`] for this server; the kernel peer
    /// check remains the authorization, the group is defence in depth.
    pub const fn client_group(self) -> &'static str {
        match self {
            DaemonId::ModelRunner => "_enclave_adapter_c",
            DaemonId::SwarmSync => "_enclave_cas_c",
            DaemonId::CustodyVault => "_enclave_custody_c",
            DaemonId::AgentRuntime => "_enclave_ifc_c",
            DaemonId::ZkAuditor => "_enclave_zk_c",
        }
    }
    /// GID of the daemon's primary group (`8701`–`8705`). UIDs keep the
    /// spec numbers 701–705, but group IDs live in the 87xx block: macOS
    /// assigns File Sharing groups (`com.apple.sharepoint.group.N`) upward
    /// from GID 701, so 7xx GIDs collide on ordinary Macs (ADR-006 amendment).
    pub const fn gid(self) -> u32 {
        self.uid() + GID_BLOCK
    }
    /// GID of [`Self::client_group`] (`8711`–`8715`).
    pub const fn client_gid(self) -> u32 {
        self.gid() + 10
    }
    /// Feature specification governing the daemon.
    pub const fn spec(self) -> &'static str {
        match self {
            DaemonId::ModelRunner => "FS-701",
            DaemonId::SwarmSync => "FS-702",
            DaemonId::CustodyVault => "FS-703",
            DaemonId::AgentRuntime => "FS-704",
            DaemonId::ZkAuditor => "FS-705",
        }
    }
}

/// Sandboxed CDP browser daemon account and UID/GID constants (GAP-34).
pub const BROWSER_ACCOUNT: &str = "_cdpbrowser";
/// UID 707.
pub const BROWSER_UID: u32 = 707;
/// Primary GID 8707.
pub const BROWSER_GID: u32 = 8707;
/// Client group GID 8718 (members: `_llmagent`).
pub const BROWSER_CLIENT_GROUP: &str = "_enclave_browser_c";
/// Client group GID 8718.
pub const BROWSER_CLIENT_GID: u32 = 8718;

/// Auxiliary client-ingress service; deliberately outside the five daemon roles.
pub const GATEWAY_ACCOUNT: &str = "_enclaveingress";
/// Dedicated ingress UID; never a console-user fallback.
pub const GATEWAY_UID: u32 = 708;
/// Dedicated ingress primary group.
pub const GATEWAY_GID: u32 = 8708;
/// Ingress socket directory and filename stem.
pub const GATEWAY_SOCKET_DIR: &str = "gateway";
/// Installed ingress executable.
pub const GATEWAY_BINARY: &str = "enclave-client-gateway";
/// Installed ingress signing identifier and launchd label.
pub const GATEWAY_IDENTIFIER: &str = "com.enterprise.enclave.gateway";

/// Dedicated witness socket directory under `socket_dir` (GAP-10).
pub const WITNESS_SOCKET_DIR: &str = "zk-witness";
/// Dedicated witness socket file name (GAP-10).
pub const WITNESS_SOCKET: &str = "witness.sock";
/// Dedicated witness socket name relative to `socket_dir` (GAP-10).
pub const WITNESS_SOCKET_NAME: &str = "zk-witness/witness.sock";
/// Dedicated witness client group name (GAP-10).
pub const WITNESS_CLIENT_GROUP: &str = "_enclave_witness_c";
/// Client group GID 8719 (members: `_piivault` only, GAP-10).
pub const WITNESS_CLIENT_GID: u32 = 8719;

impl std::fmt::Display for DaemonId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} (UID {})", self.binary(), self.uid())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn budget_arithmetic_matches_adr006() {
        let s: u64 = [
            DaemonId::SwarmSync,
            DaemonId::CustodyVault,
            DaemonId::AgentRuntime,
            DaemonId::ZkAuditor,
        ]
        .iter()
        .map(|d| d.rss_ceiling_mib())
        .sum();
        assert_eq!(s, UID_702_705_BUDGET_MIB);
        let total: u64 = DaemonId::ALL.iter().map(|d| d.rss_ceiling_mib()).sum();
        assert!(total <= STEADY_STATE_BUDGET_MIB);
        assert!(total + INTENT_HELPER_MIB <= ACTIVE_PROMPT_BUDGET_MIB);
    }

    #[test]
    fn identities() {
        assert_eq!(DaemonId::from_uid(703), Some(DaemonId::CustodyVault));
        assert_eq!(
            DaemonId::AgentRuntime.spiffe_id(),
            "spiffe://corporate.internal/enclave/uid/704"
        );
        assert_eq!(
            DaemonId::SwarmSync.launchd_label(),
            "com.enterprise.enclave.cas"
        );
    }
}
