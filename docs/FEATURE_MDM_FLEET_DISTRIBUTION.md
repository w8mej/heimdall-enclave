# Feature Design & SRE Production Specification: Enterprise MDM Fleet Distribution, Turnkey Orchestration, and Workstation Governance (`L1` / `L2` / `L3`)

* **Doc ID:** `DESIGN-MDM-DELIVERY-2026-007` (`FS-706`, **Rev 2.6** — Generation `v3.0-Target`; see `§10 Revision History`)
* **Generation:** `v3.0-Target` · **Precedence:** highest tier (with `FS-701..705`, `ADR-006+`) per [`README.md §1.2`](../README.md#12-normative-precedence--architectural-lineage)
* **Implementation Status:** **Partial implementation; signed installed and fleet qualification incomplete.** Delivery/CLI/preflight/rendering/hydration/adapter source and portable or bounded native fixtures provide scoped evidence, not complete production deployment acceptance. Approved amendments and installed D2/helper/identity/resource tests remain open (`YKD-15`). See implementation ledger and current handoff. §11 statements retain historical scope.
* **Author:** Lead Principal Security & SRE Architecture Fellow (Google Distinguished Engineer & Apple Silicon Production Architect Standard)
* **Reviewers:** Endpoint Security Engineering, Enterprise Mac Management (Jamf/Fleet/Munki), Darwin Kernel Systems, SRE Operations
* **Status:** `APPROVED — PRODUCTION SPECIFICATION`
* **Target Hardware Baseline:** Apple Silicon `M1` through `M6+` (`arm64e`, macOS 14.0+ Sonoma/Sequoia)
* **Parent Architecture Tracks:**
  * [Track 1: Model Host & Network Isolation (`FS-701`)](FEATURE_POST_AR_MODEL_ADAPTERS.md)
  * [Track 3: Content-Addressed Swarm Distribution (`FS-702`)](FEATURE_SWARM_SECURITY_PROFILES.md)
  * [Track 4: Hardware Custody & Biometrics (`FS-703`)](FEATURE_HARDWARE_CUSTODY_PROFILES.md)
  * [Track 5: Agent IFC & Policy Delegation (`FS-704`)](FEATURE_AGENT_IFC_AND_DELEGATION.md)
  * [Track 6: Silicon EMTE & ZK Compliance (`FS-705`)](FEATURE_SILICON_EMTE_AND_ZK_COMPLIANCE.md)
* **Authoritative Reconciliation:** [`docs/reviews/MDMME_RECONCILIATION_2026-11-06.md`](reviews/MDMME_RECONCILIATION_2026-11-06.md) (`D-R1` through `D-R18`)

---

## Table of Contents

1. [Executive Architecture, CLI Contract & Fleet Maturity Decision Framework](#1-executive-architecture-cli-contract--fleet-maturity-decision-framework)
   * 1.1 Executive Summary & The Triple Enterprise Challenge
   * 1.2 Canonical CLI Contract (`mcp-enclave deploy`)
   * 1.3 Fleet Maturity Decision Matrix (`L1` vs `L2` vs `L3`)
   * 1.4 Turnkey Orchestration Framework & 4-Stage Pipeline
2. [Fleet Bootstrap & System Hardening Engine (`core/bootstrap_enclave.sh`)](#2-fleet-bootstrap--system-hardening-engine-corebootstrap_enclavesh)
   * 2.1 Hardware Pre-Flight & Platform Gating
   * 2.2 Dedicated POSIX Principals & Privilege Separation
   * 2.3 Sandboxing, Application Bundle & Dual Code Signing
   * 2.4 Core Specification Dependencies & Invariant Deltas
   * 2.5 Script Specification: `core/bootstrap_enclave.sh`
3. [Model Weight Hydration & Content-Addressed Transport (`core/hydrate_model.sh`)](#3-model-weight-hydration--content-addressed-transport-corehydrate_modelsh)
   * 3.1 Content-Addressed Architecture via UID 702
   * 3.2 Tiered Hydration Transports (`L1`, `L2`, `L3`)
   * 3.3 Asynchronous APNs Execution Ceiling Mitigation (< 5s Detached Worker)
   * 3.4 Script Specification: `core/hydrate_model.sh`
4. [Hardened System Daemons & Darwin Subsystem Controls (`launchd/`)](#4-hardened-system-daemons--darwin-subsystem-controls-launchd)
   * 4.1 Deterministic Asset Rendering (`mcp-enclave launchd render`)
   * 4.2 Resource Ceilings & Darwin Kernel Reality (`phys_footprint` vs `RLIMIT_RSS`)
   * 4.3 BSD Packet Filter (`pf`) Anchor Governance & Supervisor Watcher
   * 4.4 Aqua GUI Session Decoupling for Biometrics (`_enclaveintent` Helper D2)
5. [Production-Ready Adapters for Fleet Management Tools](#5-production-ready-adapters-for-fleet-management-tools)
   * 5.1 Adapter 1: Munki (Client Package Management)
   * 5.2 Adapter 2: Ansible (Infrastructure-as-Code)
   * 5.3 Adapter 3: Fleet (osquery GitOps & Continuous Compliance)
   * 5.4 Adapter 4: Jamf Pro (Enterprise Standard Commercial MDM)
   * 5.5 Adapter 5: Lightweight MDM & Configuration Profiles (`.mobileconfig`)
   * 5.6 Enterprise Installer Packaging (`MCPMac-Enclave.pkg`)
6. [Production Readiness Review (PRR) & Operational SRE Runbooks](#6-google-sre-production-readiness-review-prr--operational-runbooks)
   * 6.1 Service Level Indicators (SLIs) & Service Level Objectives (SLOs)
   * 6.2 Failure Modes & Effects Analysis (FMEA Scenarios A–D)
   * 6.3 Lifecycle Operations & Playbooks (Atomic Swaps, FastCDC GC, Emergency Revocation)
7. [Formal Verification & Audit Invariants](#7-formal-verification--audit-invariants)
8. [Hardware Compatibility Matrix](#8-hardware-compatibility-matrix)
9. [Normative References & Citations](#9-normative-references--citations)
10. [Revision History](#10-revision-history)

---

## 1. Executive Architecture, CLI Contract & Fleet Maturity Decision Framework

### 1.1 Executive Summary & The Triple Enterprise Challenge

Deploying local, frontier-class artificial intelligence models on developer workstations is an operational imperative for modern software organizations. It unlocks sub-millisecond autocomplete latencies, zero-cloud egress costs, and offline code intelligence. However, attempting to distribute, isolate, and govern the `MCPMac` zero-trust enclave across hundreds or thousands of heterogeneous Apple Silicon laptops exposes **three fatal enterprise failure modes**:

1. **The Multi-Gigabyte Weight Transfer Hazard:** Frontier weights, quantized models, and calibration heads range from $5\text{ GiB}$ to $40\text{ GiB}$. If an enterprise pushes model updates over unicast HTTPS to 200 developers on a Monday morning, the corporate office WAN saturates immediately. Conversely, naive P2P swarming (BitTorrent) triggers intrusion detection systems (IDS), leaks proprietary IP over public DHTs, and drains laptop batteries.
2. **The Zero-Trust Network Boundary Paradox:** The inference engine (`UID 701`, `enclave-model-runnerd`) must be strictly prevented from exfiltrating customer code or PII. Yet enterprise VPN clients (Cisco AnyConnect, Palo Alto GlobalProtect, Cloudflare WARP, Tailscale) routinely flush macOS BSD Packet Filter (`pf`) tables upon tunnel connection, inadvertently dropping isolation rules and exposing unhardened endpoints.
3. **The Fatal APNs 120–300s Execution Timeout Ceiling:** Enterprise MDM protocols (Apple Push Notification service via `mdmclient`) impose a hard ceiling of 120 to 300 seconds per execution payload [Apple MDM Protocol Reference]. Synchronous scripts attempting to download multi-gigabyte models within an MDM command payload reliably time out, triggering failed deployment states and unbounded retry loops.

`FS-706` solves this triple challenge by defining a **turnkey, setup-ignorant delivery framework** that bridges macOS Darwin kernel primitives, five privilege-separated application LaunchDaemons (`UID 701–705`), the L3-only confined root APFS broker (ADR021), the content-addressed distribution swarm (`FS-702`), and commercial MDM tooling across three fleet maturity profiles.

```
       +-------------------------------------------------------------------------+
       |                           MANAGEMENT PLANE                              |
       |  Munki (L1)  |  Ansible (L1)  |  Fleet/osquery (L2)  |  Jamf Pro (L3)   |
       +-------------------------------------------------------------------------+
                                            |
                         mcp-enclave deploy --profile L<n>
                                            v
       +-------------------------------------------------------------------------+
       |                       DARWIN ORCHESTRATION ENGINE                       |
       |  Pre-Flight Hardware Check -> Artifact Synthesis -> Idempotent Bootstrap|
       +-------------------------------------------------------------------------+
                         |                          |
                         v                          v
       +-------------------------------+   +-------------------------------------+
       |      SYSTEM DAEMONS (UDS)     |   |         KERNEL BOUNDARIES           |
       | UID 701: _llmagent (No Net)   |   | pf: com.enterprise.llm.isolation    |
       | UID 702: _enclavecas (Egress) |<--| pf: com.enterprise.cas.swarm        |
       | UID 703: _piivault (SEP/Bio)  |   | Seatbelt: /opt/enclave/sandbox/*.sb |
       | UID 704: _enclaveifc (Cedar)  |   | Mach: task_info (phys_footprint)    |
       | UID 705: _enclavezk (Auditor) |   | Launchd: Background Task Management |
       +-------------------------------+   +-------------------------------------+
```

### 1.2 Canonical CLI Contract (`mcp-enclave deploy`)

Per reconciliation decision **D-R1**, all deployment, hydration, health telemetry, and lifecycle operations converge on the single operator CLI `mcp-enclave` (code-signing identifier `com.enterprise.enclave.ctl`). The binary name `enclavectl` proposed in preliminary prompts is an alias that redirects to `mcp-enclave deploy`.

#### 1.2.1 Subcommand Grammar

```
mcp-enclave deploy <VERB> --profile <L1|L2|L3> [OPTIONS]

VERBS:
  preflight     Evaluate host hardware tier, memory, disk container space, and macOS security status
  install       Provision POSIX principals, file hierarchy, Seatbelt profiles, and launchd plists
  verify        Execute deterministic socket health probes, code identity attestation, and invariants
  hydrate       Dispatch model weight synchronization via UID 702 content-addressed transport
  healthcheck   Emit real-time fleet health, memory phys_footprint, and pf anchor status
  purge         Tear down daemons, release pf anchors, and optionally remove state and user accounts

OPTIONS:
  --profile <L1|L2|L3>   Target maturity profile (required)
  --json                 Output machine-readable JSON matching schemas/deploy-result.schema.json
  --dry-run              Report planned mutations without modifying filesystem, launchd, or pf
  --yes                  Bypass interactive confirmation (mandatory for non-interactive purge)
  --target <MODEL_NAME>  Specify target artifact slug from schemas/enclave.lock.toml
```

#### 1.2.2 Stable Exit Code Contract

Deploy commands adhere to deterministic POSIX exit codes, enabling robust scripting across all MDM adapters:

| Exit Code | Constant            | Meaning & Remediation                                                                                                                        |
|-----------|---------------------|----------------------------------------------------------------------------------------------------------------------------------------------|
| `0`       | `SUCCESS`           | Operation completed successfully; all exit criteria verified.                                                                                |
| `10`      | `PREFLIGHT_FAILED`  | Hardware tier mismatch, FileVault Off, SIP Disabled, or APFS space `< 2.5x`.                                                                 |
| `20`      | `INSTALL_FAILED`    | Account provisioning, file permissions, or launchd bootstrap rejected by system.                                                             |
| `30`      | `VERIFY_FAILED`     | Required verification failed or could not complete (including a non-root required-check skip). JSON distinguishes `failed` and `incomplete`. |
| `40`      | `HYDRATION_PENDING` | Asynchronous transfer detached to background worker (APNs $<5\text{s}$ exit).                                                                |
| `41`      | `HYDRATION_FAILED`  | Transfer corrupted, Bao tree root mismatch, or network unreachable.                                                                          |
| `50`      | `UNHEALTHY`         | One or more daemons stopped, required physical footprint unknown/breached, or `pf` anchor flushed.                                           |
| `60`      | `PURGE_REFUSED`     | Purge rejected due to active consumers or missing `--yes` flag.                                                                              |
| `64`      | `USAGE_ERROR`       | Unknown verb, invalid flag syntax, or missing mandatory profile selection.                                                                   |

Verification results label each required check `pass`, `fail`, `blocked`, or
`skipped`. Layout existence is diagnostic evidence and does not replace
authenticated daemon readiness or the embedded privileged security checker.
Required skips/blocked checks prevent success. Checker diagnostics use stderr;
`--json` stdout remains one result document. MDM consumers read health fields
under `details`, and must preserve nonzero verification/health exits.

### 1.3 Fleet Maturity Decision Matrix (`L1` vs `L2` vs `L3`)

Enterprise organizations select their target deployment profile based on infrastructure availability, network topology, and compliance requirements:

```
+-------------------------------------------------------------------------------------------------------+
| FEATURE / REQUIREMENT       | PROFILE L1 (STARTUP / OSS)   | PROFILE L2 (LAN SWARM)     | PROFILE L3 (ENTERPRISE MDM)|
+-------------------------------------------------------------------------------------------------------+
| Target Audience             | Solo devs, early startups    | 20-500 dev office clusters | High-compliance/regulated  |
| Infrastructure Cost Floor   | $0 server infrastructure     | $0 extra server (P2P mesh) | Commercial MDM + S3/R2/CDN |
| Management Tooling          | Munki, Ansible, or CLI make  | Fleet (osquery GitOps)     | Jamf Pro, Kandji, Mosyle   |
| Model Weight Transport      | Direct R2/S3 chunked HTTPS   | Iroh QUIC LAN peer swarm   | OHTTP + APFS broker / MDM |
| Office Bandwidth Impact     | High (WAN pull per machine)  | Zero (1 pull, P2P on LAN)  | Relay download or pre-stage|
| Code Signing Mode           | Mode A: Local Pins (cdhash)  | Mode A or Mode B (Team ID) | Mode B: Apple Team ID      |
| Hardware Custody Gate       | Touch ID (SEP) software/dev  | Touch ID + YubiKey PINless | Touch ID + approved attestation/inventory policy (YKD-03) |
| APNs Timeout Mitigation     | N/A (local or pull agent)    | Fleet distributed query    | Detached launchd worker    |
| Emergency Fleet Quarantine  | Manual script / git pull     | osquery fleet policy push  | TUF + MDM wipe within 600s |
+-------------------------------------------------------------------------------------------------------+
```

**Hardware input policy (`YKD-01`, 2026-11-15):** The table's hardware gate
inherits [FS-703 §3.1.1](FEATURE_HARDWARE_CUSTODY_PROFILES.md#311-approved-profile-specific-pinuv-contract-ykd-01-2026-11-15)
and the accepted decision.
`L1` uses built-in SEP/Touch ID without an external key or typed FIDO2 PIN.
`L2` retains zero FIDO2 PIN typing; qualify compatible biometric hardware for
paths requiring on-key UV, including the actual PRF/attestation/algorithm
capabilities. Existing UP-only `L2` factor requirements are preserved. `L3`
allows secure host entry of the existing FIDO2 PIN when required and must verify
signed `UV=1` while preserving separate Touch ID and every other required factor.
PIN UI and its authenticated provider channel remain on the Mac; no PIN/token
may be supplied through MDM jobs, container/runner arguments, environment,
logs or artifacts. A headless deployment without the required interactive UI
refuses/suspends the affected action. Choosing a profile does not reset/change
credentials or qualify the hardware/provider. Other factor exceptions and
installed lifecycle requirements remain open.

**Lifecycle timing policy (`YKD-02`):** Calibrate native endpoint budgets under FS-703 §5.2 immediately before timing-sensitive implementation: broad engineering latitude for L1/L2 and tighter comparable L3 limits. Record host/build/backend/workload, actual physical/notification/fence/CPU/accelerator/scrub origins and uncertainty, finite budgets and residual coverage. No numeric limits or native acceptance are established by this amendment; repeat validation after implementation and retain prior attempts. L1 has no mandatory-key removal event. Wide latency latitude never permits old authority after the release fence or skipped cleanup.

#### Selection Heuristics

1. **Choose Profile `L1` if:**
   * The team operates without a centralized MDM server or dedicated IT staff.
   * Engineers work remotely across home fiber/cable networks where independent cold pulls do not congest a shared office uplink.
   * Deployments execute via developer CLI (`make deploy-L1`), Munki repository, or Ansible playbooks under Mode A (ad-hoc code-signing pins).
2. **Choose Profile `L2` if:**
   * Multiple engineers share a physical co-located office or corporate subnet.
   * Distributing a $30\text{ GiB}$ model update would saturate the corporate internet pipe.
   * Workstations run Fleet (`fleetd`) and participate in `enclave-swarm-syncd`'s peer-to-peer Iroh QUIC LAN mesh using cryptographically attenuated `PoP-Biscuit` capability tokens.
3. **Choose Profile `L3` if:**
   * The fleet is governed by commercial MDM (Jamf Pro, Mosyle, Kandji) requiring strict compliance reporting.
   * Code identity requires Apple Developer ID Application certificates (`anchor apple generic and certificate leaf[subject.OU] = "<TEAM_ID>"`).
   * Deployment must eliminate APNs timeouts through detached LaunchDaemon execution and support sealed APFS volume pre-staging.

**Approved factor and token deployment policy (`YKD-08/09`):** every A3/A4
approval requires actual separate Touch ID through the trusted GUI path. In
clamshell mode use a qualified Apple Touch ID keyboard or open the lid. Apple
Watch, host passcode or on-key biometrics cannot replace Touch ID; missing GUI
or biometric proof refuses/defers. Preserve all other inherited factors and
PIN-free L1/L2 input. Initially do not retain host PIN/UV tokens between
ceremonies or retain the PIN for reacquisition; discard at end/failure and
respect the complete 10 s ceremony bound. Enforce the earliest applicable
session, parent, capability, proof, policy and revocation expiry (FS-703 §11.2.1).
Native API, signing/session and organizational prerequisites remain explicit
qualification blockers; fleet configuration cannot manufacture them.

### 1.4 Turnkey Orchestration Framework & 4-Stage Pipeline

To achieve true zero-touch deployment, `mcp-enclave deploy` executes an idempotent 4-stage pipeline:

```
[1. Pre-Flight Profiler] ---> [2. Artifact Synthesizer] ---> [3. Idempotent Bootstrap] ---> [4. Exit Verifier]
  - sysctl hw.memsize           - mcp-enclave launchd          - provision accounts 8701-8720  - verify-install.sh
  - fdesetup status               render --profile L<n>        - deploy /opt/.../bin           - UDS socket health
  - APFS container space        - mcp-enclave pf render        - install EnclaveCustody.app    - pf anchor audit
  - Console GUI UID check       - generate adapter configs     - bootstrap launchd & gui agent - cdhash / Team ID
```

Top-level Makefile targets wrap this pipeline for immediate local invocation.

> **Script provenance (DEFECT-F-90).** `deploy install`, `deploy purge` and `deploy verify` run the packaging scripts that are *embedded in the `mcp-enclave` binary* (`/bin/sh -c`, working directory `/`, environment cleared to `PATH=/usr/bin:/bin:/usr/sbin:/sbin`). They never execute `packaging/macos/*.sh` from the current directory, and every system tool (`pfctl`, `launchctl`, `fdesetup`, `csrutil`, `stat`, `sysctl`, `hdiutil`, `xattr`) is launched by absolute path. `deploy install --dist DIR` installs from a `build.sh` distribution (verified and staged root-owned by the embedded install.sh); without `--dist` it only installs and loads the pf anchors over a payload already laid down by the `.pkg`. Running from `/` and from a checkout now behaves identically.

```makefile
.PHONY: deploy-L1 deploy-L2 deploy-L3 preflight verify clean-deployment

deploy-L1:
 @echo "==> Deploying MCPMac Enclave (Profile L1: Startup / Direct R2)..."
 sh packaging/macos/build.sh
 sudo mcp-enclave deploy install --profile L1 --dist .enclave-local/dist
 sudo mcp-enclave deploy verify --profile L1

deploy-L2:
 @echo "==> Deploying MCPMac Enclave (Profile L2: Growth / LAN Swarm)..."
 sh packaging/macos/build.sh
 sudo mcp-enclave deploy install --profile L2 --dist .enclave-local/dist
 sudo mcp-enclave deploy verify --profile L2

deploy-L3:
 @echo "==> Deploying MCPMac Enclave (Profile L3: Enterprise MDM)..."
 sh packaging/macos/build.sh
 sudo mcp-enclave deploy install --profile L3 --dist .enclave-local/dist
 sudo mcp-enclave deploy verify --profile L3
```

---

## 2. Fleet Bootstrap & System Hardening Engine (`core/bootstrap_enclave.sh`)

### 2.1 Hardware Pre-Flight & Platform Gating

Workstations vary widely in memory capacity, disk utilization, and security configuration. Per **D-R13**, the pre-flight engine introspects the host environment without assumptions:

1. **Architecture Check:** Verifies `uname -m == arm64`. Intel (`x86_64`) hosts fail immediately with exit code 10 (`PREFLIGHT_FAILED`).
2. **Unified Memory Tier Classification (`sysctl -n hw.memsize`):**
   * **Tier Low (`< 16 GiB`):** Issues advisory warning; restricts admissible model classes in `schemas/enclave.lock.toml` to quantized 3B–8B models (`LLaDA-8B`, `RWKV-7`). Multi-model residency is disallowed.
   * **Tier Mid (`16 GiB – 48 GiB`):** Permitted runner envelopes for 14B–32B models. Hosts between $48\text{ GiB}$ and $64\text{ GiB}$ (e.g. 48GB M2/M3/M4 Max configurations) are classified as Tier Mid to ensure conservative headroom.
   * **Tier High (`\ge 64 GiB`):** Full 70B+ model weights and concurrent model caching permitted.
3. **Container Storage Gating:** Inspects APFS free space on target volume `/opt/enterprise/enclave`:
   $$\text{FreeSpaceBytes} \ge 2.5 \times \text{TargetModelFootprintBytes}$$
   The $2.5\times$ multiplier guarantees sufficient capacity for atomic chunk staging, FastCDC block deduplication, and zero-copy snapshot projection.
4. **macOS Security Baseline:**
   * **FileVault:** `fdesetup status` must return `FileVault is On.` (fails closed if Off).
   * **System Integrity Protection (SIP):** `csrutil status` must be enabled.
   * **OS Version:** `sw_vers -productVersion` must be $\ge 14.0$ (macOS Sonoma / Sequoia).
   * **Console User Detection:** Queries `stat -f %u /dev/console` to identify `CONSOLE_UID` for the interactive GUI agent.

### 2.2 Dedicated POSIX Principals & Privilege Separation

Per `ADR-006` and Phase 2 amendments, the enclave runs under five dedicated system daemons and auxiliary service accounts. Primary GIDs are strictly allocated in the **87xx block** to avoid collisions with macOS File Sharing GIDs (`com.apple.sharepoint.group.*` owning 701+):

```
+--------------------------------------------------------------------------------------------------------+
| UID | USERNAME      | PRIMARY GID | ACCOUNT PURPOSE             | SERVICE BINARY                        |
+--------------------------------------------------------------------------------------------------------+
| 701 | _llmagent     | 8701        | Local Inference Host        | bin/enclave-model-runnerd             |
| 702 | _enclavecas   | 8702        | TUF & Swarm CAS (Egress)    | bin/enclave-swarm-syncd               |
| 703 | _piivault     | 8703        | PII Vault & SEP Custody     | EnclaveCustody.app/Contents/MacOS/... |
| 704 | _enclaveifc   | 8704        | Cedar PDP & Tool Runtime    | bin/enclave-agent-runtime             |
| 705 | _enclavezk    | 8705        | STARK Compliance Auditor    | bin/enclave-zk-auditor                |
| 706 | _enclavefido  | 8706        | Optional CTAPHID Emulator   | bin/enclave-fido-emulator             |
| 707 | _cdpbrowser   | 8707        | Sandboxed CDP Browser Host  | bin/enclave-cdp-browser (GAP-34)      |
|  -  | (console user)| 20 (staff)  | GUI Touch ID Helper         | bin/enclave-intent (LaunchAgent D2)   |
|  -  | _enclavecas   | 8702        | Model Weight Async Hydrator | bin/mcp-enclave (LaunchDaemon D-R8)   |
|  0  | root          | 0 (wheel)   | Revocation Supervisor       | bin/mcp-enclave supervise             |
|  0  | root          | 8702        | L3 APFS Broker (ADR-021)     | bin/enclave-apfs-broker               |
+--------------------------------------------------------------------------------------------------------+
```

Supplementary client groups govern Unix domain socket access:
* `_enclave_adapter_c` (`GID 8711`): Accounts permitted to query UID 701 (UID 704).
* `_enclave_cas_c` (`GID 8712`): Accounts permitted to resolve CAS URIs (UID 701, UID 704).
* `_enclave_custody_c` (`GID 8713`): Accounts permitted to request custody grants (UID 704).
* `_enclave_ifc_c` (`GID 8714`): Client gateway permitted to submit turns (UID 501 client gateway).
* `_enclave_zk_c` (`GID 8715`): Accounts permitted to submit strike proofs (UID 704).
* `_enclave_sup_c` (`GID 8716`): Permitted to request inode revocations (UID 702).
* `_enclave_fido_c` (`GID 8717`): Permitted to communicate with CTAPHID emulator (UID 703).
* `_enclave_browser_c` (`GID 8718`): Accounts permitted to communicate with CDP browser (UID 701, GAP-34).
* `_enclave_journal_r` (`GID 8720`): Permitted to read audit logs across all daemons (UID 705).

All system accounts are provisioned idempotently via `dscl` with `UserShell = /usr/bin/false` and `NFSHomeDirectory = /var/empty`. The Swift biometric helper `helpers/enclaveintent/` executes in the actual console user's Aqua session. The console user's ordinary `staff` membership is descriptive, **not authorization**. Approved `YKD-14` layout follows `runtime_paths.rs`: `/var/run/enclave/intent` is root:wheel `0755`; its `<console_uid>` child is console-UID:custody-GID-8703 `2710`; `intent.sock` inside is `0660`. Root protects the parent and provisions the narrowly traversable per-console directory. Production MUST additionally enforce kernel peer identity, session/boot and reciprocal code-signing requirements; filesystem mode or UID alone is insufficient. Source currently has daemon-side conditional signing verification and helper-side UID checks; complete reciprocal signing/installed qualification remains open. No shared `staff` access or nonexistent helper crate is authorized. See YKD-14.

### 2.3 Sandboxing, Application Bundle, Dual Code Signing & Memory Hardening

Every system daemon executes under Apple Seatbelt via `/usr/bin/sandbox-exec -f /opt/enterprise/enclave/sandbox/<name>.sb`.

#### Code Signing Attestation Modes
* **Mode A (Local Pins / Ad-Hoc):** Used in development and open-source deployments where the operator lacks an Apple Developer Team ID. Binaries are signed ad-hoc (`-`) with Hardened Runtime (`--options runtime`). `packaging/macos/build.sh` computes the cdhash of each executable and populates `/Library/Application Support/EnterpriseEnclave/codesign-pins.json`. IPC peers verify callers via kernel `LOCAL_PEERTOKEN` / `audit_token_t` against these pinned hashes.
* **Mode B (Enterprise Developer ID Team ID):** Mandatory for Profile `L3` production deployments (**D-R6**). Binaries are compiled with `MCPMAC_SIGNING_TEAM_ID` and signed with `Developer ID Application: <Company> (<TEAM_ID>)`. Peer designated requirements resolve to `anchor apple generic and certificate leaf[subject.OU] = "<TEAM_ID>"`. `codesign-pins.json` is not used.
* **Application Bundle Requirement (`UID 703`):** Apple Secure Enclave (`LocalAuthentication` and `kSecAttrAccessControl`) APIs strictly bind hardware keys to a signed bundle identity. Therefore, `enclave-custody-vaultd` is packaged as `/Library/Application Support/EnterpriseEnclave/EnclaveCustody.app`.
* **Memory Hardening (`SecureSlabAllocator`, GAP-40):** Root cryptographic secrets (UID 703 SEP root key, UID 704 Cedar grant signing key) and UID 705 STARK polynomial witness buffers are allocated strictly through `SecureSlabAllocator` (backed by `mlock` and `mprotect`). This guarantees sensitive keys and plaintext unredacted tokens are never paged to Darwin swap (`/var/vm/swapfile*`) or dumped during core generation.

---

### 2.4 Core Specification Dependencies & Invariant Deltas

| Item                                                                    | Disposition in `FS-706`                                                                                                                                                                                                                                                           |
|:------------------------------------------------------------------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Normative Authority Hierarchy**                                       | Resolves strictly per `README.md §1.2`: `FS-701..705 + ADR-006+` > `FS-706` > `GapsDeDuped.me` > `MDMME.md`.                                                                                                                                                                      |
| **UID 701 Network-Less Invariant (`D-R2`)**                             | `UID 701` has **0 network sockets** (UDS only). Developer env vars point at the client gateway socket. `pf` anchor `com.enterprise.llm.isolation` provides defense-in-depth by dropping non-loopback egress for GID 8701.                                                         |
| **CAS Authority for Weight Ingestion (`D-R3`)**                         | Model weights are never pulled via shell `curl` or unverified scripts. All downloads flow through `UID 702` (`enclave-swarm-syncd`), verified via BLAKE3 Bao Merkle trees. `UID 701` receives read-only FDs via `SCM_RIGHTS`. No `SIGHUP` contract.                               |
| **Memory Monitoring & Kernel Reality (`D-R4`)**                         | Darwin kernels ignore `RLIMIT_RSS`. Static plist caps (`HardResourceLimits.ResidentSetSize`) are advisory metadata. Real memory SLIs and alerts enforce `phys_footprint` via Mach `task_info`.                                                                                    |
| **Profile Floor Enforcement (`D-R5`)**                                  | `--profile` selects deployment mode. Daemons read their cryptographic floor strictly from the TUF-signed host config (`enclave-host-config.json`). Mismatches fail with `PROFILE_MISMATCH`.                                                                                       |
| **Mode B Mandate for Profile L3 (`D-R6`)**                              | Profile `L3` strictly requires Mode B (Apple Team ID). Mode A builds fail closed with `L3_REQUIRES_TEAM_ID` unless overridden in dev via `MCPMAC_L3_ADHOC_DEV=1`.                                                                                                                 |
| **Packet Filter Anchor Governance (`D-R12`)**                           | `com.enterprise.llm.isolation` and `com.enterprise.cas.swarm` are generated by Rust from a single source, installed into `/etc/pf.anchors/`, and monitored by the supervisor daemon via `kqueue` and `SCDynamicStore`.                                                            |
| **APNs Detached Execution (`D-R8`)**                                    | Solves 120–300s MDM timeouts by detaching transfers to `com.enterprise.enclave.hydrate` LaunchDaemon, returning exit code 0 to APNs in $< 5\text{ s}$.                                                                                                                            |
| **Bootstrap Entrypoint (`D-R9`)**                                       | `core/bootstrap_enclave.sh` is a thin POSIX `sh` wrapper around `mcp-enclave deploy install`. Never duplicates logic. Consumes pre-built signed `.pkg`.                                                                                                                           |
| **TUF Repository & ZK Key Distribution (`GAP-31`, `GAP-23`, `GAP-20`)** | Standalone flat package stages complete TUF metadata (`root.json`, `targets.json`, `snapshot.json`, `timestamp.json`), `enclave-host-config.json`, `enclave-policy.cedar.v1.json`, and `vk_manifest.json` into `/var/db/enclave/cas/tuf/repo` and `/opt/enterprise/enclave/cas/`. |
| **Synchronous `π_redact` Pre-Egress Gate (`GAP-25`)**                   | Profile L3 tool host egress proxy strictly gates external egress on valid STARK proofs (64 KiB chunk release unit, 5s timeout, verify latency $< 1.5\text{ ms}$).                                                                                                                 |
| **OHTTP Outbox Drainer & Ledger Gateway (`GAP-26`)**                    | Encapsulated compliance rollups are staged in `/var/db/enclave/cas/ohttp-outbox` with a 100 MiB ceiling, background traffic class `SO_TC_BK_SYS`, and AC power gating via Darwin IOPS notifications.                                                                              |
| **Hardware Integrity Quarantine (`ADR-012`, `GAP-10`, `GAP-12`)**       | Mach exception strikes, tampering, or invalid ZK proofs trigger latched quarantine in `quarantine.sealed`. Unquarantine requires TUF `UnquarantineGrant` or multi-sig quorum.                                                                                                     |
| **Cross-Node mTLS & SPIFFE Delegation (`GAP-35`)**                      | Profile L2 supports peer-to-peer delegation over mTLS with SPIFFE X.509-SVIDs and RFC 9266 channel binding (`EXPORTER-Channel-Binding`); compiled out of Profile L3.                                                                                                              |
| **APFS Clonefile Projection (`GAP-19 L1`)**                             | Copy-on-write projection via `clonefile(2)` eliminates duplicate storage for multi-process model evaluation without requiring elevated VFS entitlements.                                                                                                                          |

---

### 2.5 Script Specification: `core/bootstrap_enclave.sh`

`core/bootstrap_enclave.sh` is the standardized, MDM-friendly entrypoint designed to run as `root` via Jamf, Munki, Fleet, or Ansible.

#### Invariants

1. Pure POSIX `sh` with `set -eu`.
2. Must run as root (`[ "$(id -u)" -eq 0 ]`).
3. Invokes `mcp-enclave deploy install --profile <L1|L2|L3>` and verifies via `mcp-enclave deploy verify`.
4. Idempotent: running twice produces identical system state and exit code 0.

```sh
#!/bin/sh
# core/bootstrap_enclave.sh — Canonical MDM Bootstrap Entrypoint (FS-706 / D-R9)
set -eu

PROFILE="${1:-L1}"
case "$PROFILE" in
  L1|L2|L3) ;;
  *) echo "Usage: $0 <L1|L2|L3>"; exit 64 ;;
esac

[ "$(uname -s)" = "Darwin" ] || { echo "bootstrap: macOS required"; exit 10; }
[ "$(id -u)" -eq 0 ] || { echo "bootstrap: must run as root"; exit 1; }

CLI="/opt/enterprise/enclave/bin/mcp-enclave"
if [ ! -x "$CLI" ]; then
  # Fallback to current directory or pre-staged package payload
  if [ -x "./bin/mcp-enclave" ]; then
    CLI="./bin/mcp-enclave"
  else
    echo "bootstrap: mcp-enclave binary not found"; exit 20
  fi
fi

echo "==> [1/3] Executing pre-flight checks ($PROFILE)..."
"$CLI" deploy preflight --profile "$PROFILE"

echo "==> [2/3] Executing idempotent installation ($PROFILE)..."
"$CLI" deploy install --profile "$PROFILE"

echo "==> [3/3] Verifying deployment exit criteria ($PROFILE)..."
"$CLI" deploy verify --profile "$PROFILE"

echo "==> MCPMac Enclave bootstrap complete ($PROFILE)."
exit 0
```

---

## 3. Model Weight Hydration & Content-Addressed Transport (`core/hydrate_model.sh`)

### 3.1 Content-Addressed Architecture via UID 702

Frontier AI model weights are not arbitrary binary blobs. They are structured `.safetensors` files or MLX packages registered in OCI v1.1 manifests, signed by TUF metadata, and chunked via FastCDC (pinned 256-entry gear table) into $16\text{ KiB}$ Bao BLAKE3 Merkle leaves (`cas://blake3-bao-v1/`).

Per **D-R3**, model hydration is strictly delegated to `enclave-swarm-syncd` (`UID 702`). Shell scripts, developer tools, and the inference runner (`UID 701`) are forbidden from initiating external network connections. When hydration completes, `UID 702` passes atomic read-only descriptors (`SCM_RIGHTS`) to `UID 701`.

```
  [MDM Push / CLI] ---> Drop /var/run/enclave/jobs/hydration.json (<5s return)
                                      |
                                      v
  [com.enterprise.enclave.hydrate] LaunchDaemon detects job token
                                      |
                                      v
  [mcp-enclave deploy hydrate] triggers UID 702 via /var/run/enclave/cas/cas.sock
                                      |
       +------------------------------+------------------------------+
       |                              |                              |
       v (Profile L1)                 v (Profile L2)                 v (Profile L3)
  Cloudflare R2 / S3            Iroh QUIC P2P Swarm            RFC9458 OHTTP Relay/Gateway
  Direct Chunked HTTPS          mTLS + PoP-Biscuit             Confined root APFS broker
  Bao Verified in RAM           LAN Peer-to-Peer               Bao Verified in RAM
       |                              |                              |
       +------------------------------+------------------------------+
                                      |
                                      v
  Atomic Verification against logical_plaintext_blake3_root in /opt/enterprise/enclave/cas/
                                      |
                                      v
  Update /var/run/enclave/jobs/hydration-status.json -> Notify Fleet/Jamf EA
```

#### Bao Outboard Trees & Incremental Slice Verification
* Model weights are verified using the BLAKE3 Bao tree outboard format (`enclave_swarm_syncd::bao::bao_root`).
* Slices are grouped into strict **$16\text{ KiB}$ leaf clusters**. Slices are staged into `/opt/enterprise/enclave/cas/staging/<target>/` with `.slice` markers.
* If a WAN drop or MDM timeout interrupts hydration, `run_hydrate` inspects verified slice indexes, skips already-validated chunks, and resumes byte-range fetches immediately at the interruption boundary.
* Corrupted slices in RAM or on disk fail Bao Merkle verification and are discarded without polluting APFS cache or mutating active descriptors.

### 3.2 Tiered Hydration Transports (`L1`, `L2`, `L3`)

1. **Profile `L1` (Direct Cloudflare R2 / S3 Chunked HTTPS & APFS Clonefile):**
   * Transports chunks directly from R2/S3 using byte-range chunk requests.
   * Chunks are verified against the Bao outboard tree in RAM before being written to disk.
   * Materialization uses APFS copy-on-write `clonefile(2)` projection, eliminating duplicate storage across developer sandboxes without requiring elevated VFS entitlements.
   * Zero infrastructure cost; operates without peer-to-peer coordination.
2. **Profile `L2` (LAN Peer Capability Swarm / Iroh QUIC & SPIFFE mTLS):**
   * Dispatches requests over local subnet mesh via QUIC (ALPN `enclave-cas-v2`).
   * Peers authenticate using node public keys pinned in `enclave-host-config.json` and present attenuated `PoP-Biscuit` capability tokens.
   * Cross-node delegation is governed by SPIFFE X.509-SVIDs with RFC 9266 channel binding (`EXPORTER-Channel-Binding`, `l2-a2a`).
   * Dual-socket QoS isolates interactive and background bulk traffic under `SO_TRAFFIC_CLASS = SO_TC_BK_SYS`.
   * SeedGate thermal and battery telemetry gates peer distribution to prevent draining mobile laptops. Chunks are verified in RAM; Byzantine peers delivering invalid slices receive signed `PoisonReceipt` tombstones and immediate quarantine.
   * Packet Filter anchor `com.enterprise.cas.swarm` restricts peer traffic to approved swarm ports.
3. **Profile `L3` (OHTTP Delivery / Sealed APFS & Zero-Listener Guarantee):**
   * Network model delivery uses the production RFC9458 OHTTP relay/gateway adapter in UID702, with signed encrypted targets, custody leases and full eager verification. Detached MDM jobs avoid APNs timeouts but do not authorize a different transport/profile.
   * UID702 sends only an exact signed root and readonly staged FD to the independently pinned, confined root APFS broker. The broker independently verifies root-protected authority and publishes a restricted snapshot on the configured dedicated volume (§3.2.1, FS702 §4.3.1, ADR021).
   * MDM-prestaged DMG ingestion remains a separate offline input workflow. Attaching/detaching a read-only DMG does not prove broker snapshot publication, mount flags, hardware custody or production L3 acceptance.
   * **Zero-Listener Invariant:** At initialization and enforced fetch, UID702 rejects TCP listeners and bound unconnected IPv4/IPv6 UDP receivers. Documented established TCP/connected UDP relay-client controls remain allowed. The root broker has only authenticated local Unix IPC and no Internet sockets.

### 3.2.1 L3 APFS broker deployment and lifecycle (ADR-021)

The auxiliary root helper is `bin/enclave-apfs-broker`, code identity/launch label `com.enterprise.enclave.apfs-broker`. It adds no application account and cannot inherit UID702's network permission. The authenticated socket `/var/run/enclave/apfs-broker/broker.sock` is root-owned with CAS-only group access; the root-only public TUF replica/state is under `/var/db/enclave/apfs-broker/`. The independently retained support bootstrap root and code-pin manifest remain protected from CAS writes. Private signing/custody keys never enter that replica.

The protected metadata replica is updated by the authorized root deployment channel, never by CAS. Its updater stages and verifies complete public roles and signed payloads as one deployment generation; failed refresh leaves the prior authenticated generation available for cleanup, without allowing expired metadata to admit new publications. The organization owns publisher/root and pin rotation; local deployment code may not manufacture that authority.

The packaging/installer must stage the signed binary, distinct code pin, confined launch assets, complete public metadata/payload replica and private state/socket layout together. L3 must fail before serving publication when its helper, trust, confinement or approved snapshot entitlement is unavailable. Do not manufacture entitlement authority by adding an unverified entitlement key or using an ad-hoc signature. Dedicated APFS volume/source/mount roots require explicit prior provisioning; the installer must not create/reformat arbitrary devices from configuration. Safe system `/var` aliases may be normalized only through a fixed trusted-prefix rule; untrusted links remain refused.

Start and establish authenticated helper readiness before L3 CAS publication. Upgrade/removal stops publication callers first, retracts owned publications through their retained original authority, and refuses destructive cleanup while retraction remains incomplete. Preserve bootstrap pins, monotonic TUF state and ownership records across normal upgrade/restart; do not erase them merely to make a retry succeed. Downgrade to L1/L2 must not leave an enabled unnecessary root broker, and may not strand active L3 publications. Ordinary uninstall retains forensic/state material unless explicit authorized purge has completed safe retraction. The fixed root-only `--quiesce-idle` command serializes with the whole accepted broker operation, refuses active work or nonempty/corrupt ownership, and durably marks the helper quiesced before replacement/removal. Subsequent requests refuse effects while marked. `--check-idle` is read-only diagnosis and cannot authorize removal. Recovery may clear only its own barrier after restoring the corresponding validated prior service/trust generation; state uncertainty requires operator diagnosis, never deletion.

Fleet launch/process/signature/file-integrity queries, MDM background-service allowlists, installer recovery, deploy verify/healthcheck/purge and release/reproducibility inventories must include the helper where L3 requires it. Report missing/stopped/unpinned/incomplete-cleanup states distinctly; launchd registration or text equality alone is not readiness. The five application daemon 152 MiB subtotal and 200 MiB total exclude this new root service. Measure/report its footprint and revised aggregate separately; no budget compliance is asserted before execution.

Recovery must preserve explicit uncertain ownership. A snapshot-create error/crash before durable proof does not authorize deletion merely because its name matches a content root; EEXIST preserves the foreign snapshot. Such records block automatic cleanup, upgrade and removal pending trusted diagnosis. Old version1 completed records lacking the new ownership bit refuse safely rather than being silently migrated into deletion authority.

Acceptance traces `SBR-01`–`SBR-14` and TB13/X14–X21 in both directions to code, behavioral tests, raw job evidence and independent review. Actual root/TeamID cross-UID serving, entitlement, dedicated APFS snapshots/mount restrictions, restart/rotation/retraction and measured resource acceptance remain BLOCKED/NOT RUN on the personal development Mac. Private installer/IPC/inert-platform fixtures support software behavior only. The safe handoff is in `macme.md`; no operator should run installed acceptance from this section without a permitted provisioned host.

### 3.3 Asynchronous APNs Execution Ceiling Mitigation (< 5s Detached Worker)

Per **D-R8**, synchronous weight transfers within an MDM execution payload guarantee deployment failure due to Apple's 120–300s APNs timeout.

#### Two-Phase Detached Pattern

1. **Phase 1: Synchronous Submission ($< 5\text{ s}$):**
   * The MDM bootstrap script executes `mcp-enclave deploy hydrate --target <MODEL> --async`.
   * The CLI writes a job descriptor `/var/run/enclave/jobs/hydration.json`:

     ```json
     {
       "job_id": "hyd-20261106-001",
       "target": "llada-8b-instruct",
       "profile": "L1",
       "created_at": 1794019200
     }
     ```

   * Triggers the dedicated LaunchDaemon `com.enterprise.enclave.hydrate` via `launchctl kickstart -k system/com.enterprise.enclave.hydrate`.
   * Returns exit code `40` (`HYDRATION_PENDING`) or `0` immediately to the MDM agent.
2. **Phase 2: Asynchronous Background Transfer:**
   * The background daemon consumes the job token, establishes connection to `UID 702`, and streams chunks with automatic byte-range resume.
   * Progress is atomically written to `/var/run/enclave/jobs/hydration-status.json`.
   * Jamf Extension Attributes or Fleet osquery queries poll this file to report status back to the enterprise console.

### 3.4 Script Specification: `core/hydrate_model.sh`

```sh
#!/bin/sh
# core/hydrate_model.sh — Model Weight Hydration Entrypoint (FS-706 / D-R3 / D-R8)
set -eu

TARGET="${1:-llada-8b-instruct}"
PROFILE="${2:-L1}"
MODE="${3:-async}"

CLI="/opt/enterprise/enclave/bin/mcp-enclave"
[ -x "$CLI" ] || { echo "hydrate: mcp-enclave binary not found"; exit 20; }

case "$MODE" in
  --sync|sync)
    echo "==> Synchronously hydrating $TARGET ($PROFILE)..."
    exec "$CLI" deploy hydrate --profile "$PROFILE" --target "$TARGET"
    ;;
  --async|async|"")
    echo "==> Submitting detached hydration job for $TARGET ($PROFILE)..."
    exec "$CLI" deploy hydrate --profile "$PROFILE" --target "$TARGET" --async
    ;;
  *)
    echo "Usage: $0 <target-slug> <L1|L2|L3> [--sync|--async]"; exit 64
    ;;
esac
```

---

## 4. Hardened System Daemons & Darwin Subsystem Controls (`launchd/`)

### 4.1 Deterministic Asset Rendering (`mcp-enclave launchd render`)

Plists, Seatbelt profiles, and account provisioning scripts are **never hand-edited**. They are rendered deterministically from Rust declarations in `crates/mcp-enclave/src/launchd.rs`:

```sh
cargo run -p mcp-enclave -- launchd render --out launchd
```

Committed assets in `launchd/` must remain byte-for-byte identical to generator output; this invariant is enforced by `tests/fleet.rs::launchd_assets_are_reproducible`.

### 4.2 Resource Ceilings & Darwin Kernel Reality (`phys_footprint` vs `RLIMIT_RSS`)

Per **D-R4**, macOS Darwin kernels **do not enforce `RLIMIT_RSS`** or the LaunchDaemon `HardResourceLimits.ResidentSetSize` plist key (see `setrlimit(2)`). Processes that exceed `ResidentSetSize` are not terminated by the kernel.

Therefore, static plist RSS limits are retained purely as advisory metadata. Real memory governance and enforcement are built around **`phys_footprint`**, queried directly via the Mach kernel `task_info(mach_task_self(), TASK_VM_INFO, ...)` API.

#### Memory Budgets (Adhering to `schemas/enclave.lock.toml` and Check V21)
* **UID 701 (`_llmagent`):** $48\text{ MiB}$ steady-state runner envelope.
* **UID 702 (`_enclavecas`):** $48\text{ MiB}$ CAS streaming envelope.
* **UID 703 (`_piivault`):** $24\text{ MiB}$ SEP custody envelope.
* **UID 704 (`_enclaveifc`):** $32\text{ MiB}$ Cedar PDP envelope.
* **UID 705 (`_enclavezk`):** $48\text{ MiB}$ Plonky3 auditor envelope.
* **Subtotal Daemons (`UID 702–705`):** **$152\text{ MiB}$**.
* **Steady-State Total (including `UID 701`):** **$200\text{ MiB}$**.
* **Active-Prompt Peak (including on-demand `_enclaveintent` GUI agent $\le 32\text{ MiB}$):** **$232\text{ MiB}$**.

The current CLI shares exact-byte decisions between `deploy healthcheck` and
`measure`. Status carries `phys_footprint_bytes` and `phys_footprint_source`;
legacy/missing/zero/failed/unsupported observations are unknown and cannot satisfy
the required five-daemon caps. Linux RSS is separate telemetry, not a Mach
measurement. Checked aggregate totals are null on missing input or overflow.
Per-daemon excess fails even when totals are small. The top-level healthcheck
CLI footprint is explicitly scoped to that CLI, outside the daemon total.
`measure` returns exit 50 on noncompliance or unknown required input. Auxiliary
scope and durable breach-journal acceptance remain explicit separate gates in
Phase 2; source repair is not installed
signed-host acceptance.

#### Auxiliary Envelopes & Storage Quotas
* **UID 707 (`_cdpbrowser`, GAP-34):** $64\text{ MiB}$ isolated browser execution envelope.
* **OHTTP Compliance Outbox Disk Quota (FS-702 §7.4.2, GAP-26):** Staged rollups in `/var/db/enclave/cas/ohttp-outbox` are hard-capped at **$100\text{ MiB}$**. If queue disk consumption exceeds $100\text{ MiB}$ (e.g. during extended offline travel on battery), new audit rollups fail closed and `mcp-enclave deploy healthcheck` flags exit code `50` (`UNHEALTHY`).

Current queue-health implementation: the CAS service inspects its configured
private namespace and the CLI acquires its bounded aggregate through authenticated
IPC. `details.outbox` separates canonical pending and retained dead counts;
`disk_bytes` is their checked logical payload-length sum, with explicit scope,
not allocated filesystem blocks. Exactly 100 MiB is within this conjunct;
above-cap is unhealthy. Missing, busy, unsafe, over-limit, recovery-required or
invalid acquisition is unknown/unhealthy, with null count/byte/budget fields and
no direct-scan fallback. The private configured `path` is null. Production root
reader and development actual-UID policy are additional to existing outer IPC.

This observation is read-only: it grants no drain, cleanup, authenticated receipt
or durable breach-journal authority. Physical allocation, production scheduler,
durable delivery and complete installed acceptance remain separate obligations;
see NEXT-10C
and [RB-212](SRE_RUNBOOKS.md).
Required unknown or excess observations contribute to exit code `50`
(`UNHEALTHY`); other independent health conjuncts remain in force.

### 4.3 BSD Packet Filter (`pf`) Anchor Governance & Supervisor Watcher

Per **D-R12**, network boundaries are enforced by Darwin BSD Packet Filter rules:
* `com.enterprise.llm.isolation`: Blocks all non-loopback IPv4 and IPv6 traffic for GID 8701 (`_llmagent`). Permits loopback access only to Envoy mTLS (8443) and local inference (11434).
* `com.enterprise.cas.swarm`: Isolates FUSE-T NFS loopback port 2049 from interactive console user 501, and permits CAS swarm / mTLS traffic for GID 8702 (`_enclavecas`).

#### VPN Flush Defense

Corporate VPN clients flush `pf` tables when activating tunnels. To prevent window-of-vulnerability exposure:

1. Rules are generated by `mcp-enclave pf render` into `/etc/pf.anchors/` and referenced in `/etc/pf.conf` between `BEGIN/END MCPMAC PF RULES` markers.
2. The root supervisor LaunchDaemon (`com.enterprise.enclave.supervisor`) registers a `kqueue` timer and `SCDynamicStore` network change listener.
3. If `pfctl -a com.enterprise.llm.isolation -s rules` or `pfctl -a com.enterprise.cas.swarm -s rules` returns empty, the supervisor atomically reloads both anchors within **$\le 1000\text{ ms}$** and journals `PF_ANCHOR_RESTORED`.

### 4.4 Aqua GUI Session Decoupling for Biometrics (`_enclaveintent` Helper D2)

LaunchDaemons running in the `system` domain execute without access to Apple WindowServer. If `UID 703` invokes `LocalAuthentication` directly, the call fails immediately with `LAErrorNotInteractive` (-1004).

Per Phase 2 Design **D2**:

1. The biometric prompter binary `enclave-intent` is registered as a **LaunchAgent** (`/Library/LaunchAgents/com.enterprise.enclave.intent.plist`).
2. `install.sh` / `mcp-enclave deploy install` bootstraps this agent into the console user's Aqua GUI domain:

   ```sh
   launchctl bootstrap gui/$CONSOLE_UID /Library/LaunchAgents/com.enterprise.enclave.intent.plist
   ```

3. When `UID 703` requires user biometry, it dispatches an IPC request over `/var/run/enclave/intent/<console_uid>/intent.sock` using the protected layout in §2.2 (`YKD-14`). The D2 helper performs fresh Touch ID-gated proof signing bound to the daemon challenge/intent/session; UID 703 verifies it and retains tier/vault keys, raw ECDH and PRF (`YKD-04`). This supersedes cross-session externalized-LAContext transfer. If no qualified GUI session or authenticated peer exists, refuse the affected operation without minting authority. Installed reciprocal identity and actual key flow remain acceptance requirements.

### 4.5 Background Task Management (BTM) & MDM Policy Governance (macOS 13+)

On macOS 13+ (Ventura, Sonoma, Sequoia), Darwin introduces Background Task Management (BTM), tracked by `sfltool dumpbtm`. This creates two critical enterprise operational considerations:

#### 1. User Notification & User-Disable Risk
* Installing LaunchDaemons or LaunchAgents triggers the macOS system alert: *"Background Items Added: Enterprise Enclave"*.
* Standard and administrative users can view background items in **System Settings → General → Login Items & Extensions**.
* Users can manually toggle off `com.enterprise.enclave.intent` or enclave daemons. If disabled:
  * `launchctl print gui/<uid>/com.enterprise.enclave.intent` reports disabled state.
  * The active per-console biometric intent socket `/var/run/enclave/intent/<console_uid>/intent.sock` is absent or unavailable; a compatibility pathname alone is not health evidence.
  * `mcp-enclave deploy healthcheck` flags exit code `50` (`EXIT_UNHEALTHY`).

#### 2. Enterprise MDM Enforcement (`com.apple.servicemanagement`)

To prevent unauthorized user disabling of enclave security daemons and biometric agents, commercial MDMs deploy a managed configuration profile (`.mobileconfig`) containing the `com.apple.servicemanagement` payload (**D-R7**):
* **RuleType:** `LabelPrefix` (`com.enterprise.enclave.`) or `Label` (`com.enterprise.enclave.intent`).
* **RuleValue:** `com.enterprise.enclave.`
* **TeamIdentifier:** Developer Team ID (in Mode B production deployments).

When managed via MDM, background items appear as *"Managed by your organization"* in System Settings with toggles permanently locked in the enabled state, guaranteeing continuous compliance.

#### 3. Headless & Login Window Deferred Bootstrap

When an MDM installer runs during machine provisioning, pre-stage enrollment, or off-hours maintenance, no interactive user is logged in:
* `/dev/console` is owned by `root` (`UID 0`) or is unassigned.
* The installer detects `CONSOLE_UID == 0` or missing, logs `info: no active console user; intent agent deferred to next login via RunAtLoad`, and completes with exit code 0.
* Because `/Library/LaunchAgents/com.enterprise.enclave.intent.plist` specifies `<key>RunAtLoad</key><true/>`, macOS launchd automatically activates `enclave-intent` in the interactive Aqua GUI session the instant a user logs in.

---

## 5. Production-Ready Adapters for Fleet Management Tools

### 5.1 Adapter 1: Munki (Client Package Management)

Munki manages macOS endpoints via pull-based repository manifests.

#### 5.1.1 `enclave-core.pkginfo`

Declares the base runtime package, requiring macOS 14.0+ on Apple Silicon:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>name</key>
    <string>com.enterprise.enclave.core</string>
    <key>version</key>
    <string>3.0.0</string>
    <key>minimum_os_version</key>
    <string>14.0.0</string>
    <key>supported_architectures</key>
    <array>
        <string>arm64</string>
    </array>
    <key>installer_type</key>
    <string>copy_from_dmg</string>
    <key>items_to_copy</key>
    <array>
        <dict>
            <key>source_item</key>
            <string>MCPMac-Enclave-3.0.0.pkg</string>
            <key>destination_path</key>
            <string>/tmp</string>
        </dict>
    </array>
    <key>postinstall_script</key>
    <string>#!/bin/sh
/usr/sbin/installer -pkg /tmp/MCPMac-Enclave-3.0.0.pkg -target /
/opt/enterprise/enclave/bin/mcp-enclave deploy install --profile L1
rm -f /tmp/MCPMac-Enclave-3.0.0.pkg
exit 0
    </string>
    <key>uninstall_script</key>
    <string>#!/bin/sh
/opt/enterprise/enclave/bin/mcp-enclave deploy purge --profile L1 --yes
exit 0
    </string>
</dict>
</plist>
```

#### 5.1.2 `enclave-model-weights.pkginfo`

Chained to `enclave-core`. Implements an idempotent `installcheck_script` that queries `UID 702` CAS holdings without downloading multi-gigabyte files:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>name</key>
    <string>com.enterprise.enclave.model.llada8b</string>
    <key>version</key>
    <string>1.0.0</string>
    <key>requires</key>
    <array>
        <string>com.enterprise.enclave.core</string>
    </array>
    <key>installcheck_script</key>
    <string>#!/bin/sh
# Check if model CAS chunks and manifest are fully hydrated locally
/opt/enterprise/enclave/bin/mcp-enclave deploy healthcheck --json | grep -q '"target":"llada-8b-instruct","status":"healthy"'
# Exit 0 means installed (skip download); Exit 1 means needs install
if [ $? -eq 0 ]; then exit 1; else exit 0; fi
    </string>
    <key>postinstall_script</key>
    <string>#!/bin/sh
/opt/enterprise/enclave/bin/mcp-enclave deploy hydrate --profile L1 --target llada-8b-instruct --async
exit 0
    </string>
</dict>
</plist>
```

---

### 5.2 Adapter 2: Ansible (Infrastructure-as-Code)

Provides an enterprise Ansible role `roles/mcp_enclave/` for automated Mac workstation management.

#### 5.2.1 `tasks/main.yml`

```yaml
---
- name: Verify Apple Silicon Host Architecture
  ansible.builtin.assert:
    that:
      - ansible_architecture == 'arm64'
      - ansible_os_family == 'Darwin'
    fail_msg: "MCPMac Enclave requires Apple Silicon macOS."

- name: Deploy MCPMac Installer Package
  ansible.builtin.copy:
    src: MCPMac-Enclave-3.0.0.pkg
    dest: /tmp/MCPMac-Enclave-3.0.0.pkg
    mode: '0644'

- name: Install Enclave Base Package
  ansible.builtin.command:
    cmd: /usr/sbin/installer -pkg /tmp/MCPMac-Enclave-3.0.0.pkg -target /
  register: pkg_install
  changed_when: "'installer: The install was successful.' in pkg_install.stdout"

- name: Execute Enclave Bootstrap Orchestration
  ansible.builtin.command:
    cmd: /opt/enterprise/enclave/bin/mcp-enclave deploy install --profile {{ enclave_profile | default('L1') }}
  register: bootstrap_run
  changed_when: "'ok: bootstrapped' in bootstrap_run.stdout"

- name: Configure Developer Environment Variables
  ansible.builtin.include_tasks: developer_env.yml

- name: Verify Post-Install Health
  ansible.builtin.command:
    cmd: /opt/enterprise/enclave/bin/mcp-enclave deploy verify --profile {{ enclave_profile | default('L1') }}
  changed_when: false
```

#### 5.2.2 `tasks/developer_env.yml`

Injects non-bypassable client gateway socket variables into shell profiles per **D-R2**:

```yaml
---
- name: Inject Developer Gateway Environment in /etc/zshrc
  ansible.builtin.blockinfile:
    path: /etc/zshrc
    marker: "# {mark} ANSIBLE MANAGED MCPMAC ENVIRONMENT"
    create: true
    mode: '0644'
    block: |
      export ENCLAVE_SOCKET="/var/run/enclave/ifc/ifc.sock"
      export ENCLAVE_CLIENT_GATEWAY="/var/run/enclave/ifc/ifc.sock"
      export NO_PROXY="127.0.0.1,::1,localhost"
```

---

### 5.3 Adapter 3: Fleet (osquery GitOps & Continuous Compliance)

#### 5.3.1 `fleet-enclave-installer.yml`

Declarative Fleet GitOps software specification:

```yaml
apiVersion: v1
kind: software
spec:
  packages:
    - url: https://dist.enterprise.internal/enclave/MCPMac-Enclave-3.0.0.pkg
      self_service: false
      install_script: |
        #!/bin/sh
        /usr/sbin/installer -pkg MCPMac-Enclave-3.0.0.pkg -target /
        /opt/enterprise/enclave/bin/mcp-enclave deploy install --profile L2
      post_install_query: |
        SELECT 1 FROM launchd WHERE label = 'com.enterprise.enclave.supervisor' AND run_at_load = '1';
      uninstall_script: |
        #!/bin/sh
        /opt/enterprise/enclave/bin/mcp-enclave deploy purge --profile L2 --yes
```

#### 5.3.2 Continuous Compliance Queries (Pinned osquery Schema Tables)

Queries avoid non-existent `pf` tables and execute against valid schema tables (`launchd` joined with `processes`):

```sql
-- 1. Verify Enclave LaunchDaemon Definitions & Running Processes
SELECT l.label, l.name, p.pid, p.uid FROM launchd l
LEFT JOIN processes p ON p.path = l.program OR l.program_arguments LIKE '%' || p.path || '%'
WHERE l.label IN (
  'com.enterprise.enclave.supervisor',
  'com.enterprise.enclave.adapter',
  'com.enterprise.enclave.cas',
  'com.enterprise.enclave.custody',
  'com.enterprise.enclave.ifc',
  'com.enterprise.enclave.zk'
) AND l.run_at_load = '1';

-- 2. Verify FileVault and System Integrity Protection
SELECT (SELECT encrypted FROM disk_encryption WHERE user_uuid = '' OR name = 'Macintosh HD') AS fv,
       (SELECT enabled FROM sip_config) AS sip;

-- 3. Attest Code Signatures (Mode B Production Team ID)
SELECT path, signed, identifier, authority FROM signature
WHERE path = '/opt/enterprise/enclave/bin/mcp-enclave';
```

Compliance auditing of `pf` rules and `phys_footprint` is delegated to Fleet scripts executing `/opt/enterprise/enclave/bin/mcp-enclave deploy healthcheck --json`.

---

### 5.4 Adapter 4: Jamf Pro (Enterprise Standard Commercial MDM)

#### 5.4.1 `jamf_deploy_enclave.sh`

Per **D-R15**, Jamf reserves `$1` (mount point), `$2` (computer name), and `$3` (username). Parameters strictly begin at `$4`:

```sh
#!/bin/sh
# Jamf Pro Deployment Script (FS-706 / D-R15)
# $4: Model Target Slug (e.g. llada-8b-instruct)
# $5: Deployment Profile Tier (L1 | L2 | L3)
# $6: Action (bootstrap | hydrate | healthcheck | purge)

TARGET="${4:-llada-8b-instruct}"
PROFILE="${5:-L3}"
ACTION="${6:-bootstrap}"

CLI="/opt/enterprise/enclave/bin/mcp-enclave"
[ -x "$CLI" ] || { echo "jamf: mcp-enclave binary not found"; exit 20; }

case "$ACTION" in
  bootstrap)
    "$CLI" deploy preflight --profile "$PROFILE"
    "$CLI" deploy install --profile "$PROFILE"
    "$CLI" deploy verify --profile "$PROFILE"
    ;;
  hydrate)
    "$CLI" deploy hydrate --profile "$PROFILE" --target "$TARGET" --async
    ;;
  healthcheck)
    "$CLI" deploy healthcheck --profile "$PROFILE"
    ;;
  purge)
    "$CLI" deploy purge --profile "$PROFILE" --yes
    ;;
  *)
    echo "Unknown action: $ACTION"; exit 64
    ;;
esac
exit 0
```

#### 5.4.2 Jamf Extension Attributes

Outputs wrapped in `<result>...</result>` tags:
* **`EA-Enclave-Status.sh`:**

  ```sh
  #!/bin/sh
  STATUS=$(/opt/enterprise/enclave/bin/mcp-enclave deploy healthcheck --json 2>/dev/null | grep -o '"overall_status":"[^"]*"' | cut -d'"' -f4)
  echo "<result>${STATUS:-NOT_INSTALLED}</result>"
  ```
* **`EA-Enclave-Security.sh`:**

  ```sh
  #!/bin/sh
  PF=$(pfctl -a com.enterprise.llm.isolation -s rules 2>/dev/null | wc -l | tr -d ' ')
  if [ "$PF" -gt 0 ]; then RES="ISOLATED"; else RES="EXPOSED"; fi
  echo "<result>$RES</result>"
  ```

---

### 5.5 Adapter 5: Lightweight MDM & Configuration Profiles (`.mobileconfig`)

#### 5.5.1 `lightweight_mdm_bootstrap.sh`

Executes async hydration and exits within $< 5\text{ s}$ to prevent APNs command timeouts:

```sh
#!/bin/sh
# lightweight_mdm_bootstrap.sh — Async MDM Bootstrap (FS-706 / D-R8)
set -eu
/opt/enterprise/enclave/bin/mcp-enclave deploy install --profile L3
/opt/enterprise/enclave/bin/mcp-enclave deploy hydrate --profile L3 --target llada-8b-instruct --async
exit 0
```

#### 5.5.2 `MCPMac-Enclave.mobileconfig`

Per **D-R7**, profile payloads are restricted to valid Darwin capabilities:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>PayloadIdentifier</key>
    <string>com.enterprise.enclave.profile</string>
    <key>PayloadType</key>
    <string>Configuration</string>
    <key>PayloadUUID</key>
    <string>8A7C6E5D-4B3A-2F1E-0D9C-8B7A6F5E4D3C</string>
    <key>PayloadVersion</key>
    <integer>1</integer>
    <key>PayloadContent</key>
    <array>
        <!-- Background Task Management: Prevent users from disabling daemons -->
        <dict>
            <key>PayloadType</key>
            <string>com.apple.servicemanagement</string>
            <key>PayloadIdentifier</key>
            <string>com.enterprise.enclave.btm</string>
            <key>PayloadUUID</key>
            <string>1A2B3C4D-5E6F-7A8B-9C0D-1E2F3A4B5C6D</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
            <key>Rules</key>
            <array>
                <dict>
                    <key>RuleType</key>
                    <string>LabelPrefix</string>
                    <key>RuleValue</key>
                    <string>com.enterprise.enclave.</string>
                </dict>
            </array>
        </dict>
        <!-- Notification Settings for Intent Agent -->
        <dict>
            <key>PayloadType</key>
            <string>com.apple.notificationsettings</string>
            <key>PayloadIdentifier</key>
            <string>com.enterprise.enclave.notifications</string>
            <key>PayloadUUID</key>
            <string>2B3C4D5E-6F7A-8B9C-0D1E-2F3A4B5C6D7E</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
            <key>NotificationSettings</key>
            <array>
                <dict>
                    <key>BundleIdentifier</key>
                    <string>com.enterprise.enclave.intent</string>
                    <key>NotificationsEnabled</key>
                    <true/>
                    <key>ShowInNotificationCenter</key>
                    <true/>
                </dict>
            </array>
        </dict>
    </array>
</dict>
</plist>
```

---

### 5.6 Enterprise Installer Packaging (`MCPMac-Enclave.pkg`)

Per **D-R10**, `packaging/pkg/build-pkg.sh` generates standalone macOS flat packages using standard Darwin utilities (`pkgbuild` and `productbuild`):
* Packages encapsulate binaries, sandboxes, plists, `EnclaveCustody.app`, codesign pins, and the complete TUF metadata repository (`root.json`, `targets.json`, `snapshot.json`, `timestamp.json`), `enclave-host-config.json`, `enclave-policy.cedar.v1.json`, and `vk_manifest.json` staged into `/var/db/enclave/cas/tuf/repo` and `/opt/enterprise/enclave/cas/`.
* `preinstall` executes account provisioning (`launchd/provision-accounts.sh`).
* `postinstall` sets permissions (`_enclavecas:_enclavecas`) and invokes `core/bootstrap_enclave.sh`.
* Mode A builds are unsigned; Mode B builds are signed when `MCPMAC_INSTALLER_IDENTITY` is configured.

---

## 6. Production Readiness Review (PRR) & Operational SRE Runbooks

### 6.1 Service Level Indicators (SLIs) & Service Level Objectives (SLOs)

Per **D-R16**, formal SLO commitments govern fleet operations. As required by Phase 4 governance, all SLO metrics without bare-metal test bench data are formally marked *"[target; measurement pending]"* until verified by the verification bundle (`E10`):

| Objective                       | Target SLO                                        | SLI Measurement Method                                                   | Production Remediation                  |
|---------------------------------|---------------------------------------------------|--------------------------------------------------------------------------|-----------------------------------------|
| **Fleet Deployment Success**    | $\ge 99.5\%$                                      | Ratio of exit code 0 to total `install` runs over 30d window             | Runbook `RB-207` (Deploy Triage)        |
| **Bootstrap Execution Latency** | $p95 < 45\text{ s}$ [target; measurement pending] | Wall-clock execution time of `bootstrap_enclave.sh` (excl. weights)      | Inspect disk I/O and dscl contention    |
| **Weight Hydration Resumption** | $100\%$                                           | Bao chunk verification resume efficiency after connection reset          | Automatic byte-range retry in UID 702   |
| **Memory Ceiling Compliance**   | $0\text{ breaches}$                               | Continuous sampling of Mach `phys_footprint` $\le 200\text{ MiB}$ budget | Alert on leak; restart leaking daemon   |
| **Emergency Fleet Revocation**  | $\le 600\text{ s}$ [target; measurement pending]  | Time elapsed from TUF revocation publish to global process kill          | Runbook `RB-211` (Emergency Quarantine) |

### 6.2 Failure Modes & Effects Analysis (FMEA Scenarios A–I)

* **Scenario A: Mid-Stream Network Interruption during Hydration:**
  * *Failure Effect:* Download stalls; partial file exists in `/opt/enterprise/enclave/cas/`.
  * *Automated Recovery:* `enclave-swarm-syncd` uses Bao outboard Merkle trees and HTTP byte-range offsets. When connectivity restores, transfer resumes exactly from the last verified $16\text{ KiB}$ slice. Corrupt partial slices in RAM are discarded prior to APFS write.
* **Scenario B: APFS Volume Disk Space Exhaustion:**
  * *Failure Effect:* Free space drops below required staging margins during multi-model staging.
  * *Automated Recovery:* FastCDC ref-counted garbage collection triggers automatically when APFS free space drops below $15\%$. Unreferenced blocks are pruned; active model inodes are pinned.
* **Scenario C: Corporate VPN Drops Packet Filter Anchors:**
  * *Failure Effect:* VPN client re-initializes `/etc/pf.conf`, clearing `com.enterprise.llm.isolation`.
  * *Automated Recovery:* Supervisor daemon's `SCDynamicStore` monitor detects table change and atomically re-applies rules within $\le 1000\text{ ms}$, logging `PF_ANCHOR_RESTORED`.
* **Scenario D: Rogue Process Attempts to Bind or Exfiltrate via UID 701:**
  * *Failure Effect:* Malicious process attempts network access or socket takeover.
  * *Automated Recovery:* Seatbelt profile `adapter.sb` denies all network operations at Darwin kernel level; Packet Filter blocks non-loopback egress for GID 8701; UDS permissions reject unprivileged accounts with `IPC_DIR_INSECURE`.
* **Scenario E: Zero-Console Active User (Loginwindow / Headless MDM Execution):**
  * *Failure Effect:* MDM bootstrap runs when no interactive user is logged into Aqua GUI session (`CONSOLE_UID == 0` or missing).
  * *Automated Recovery:* `install.rs` logs `info: no active console user; intent agent deferred to next login via RunAtLoad`, skips `gui/0` bootstrap, and exits 0. LaunchAgent runs automatically on subsequent GUI login.
* **Scenario F: Local User Disables Daemons via Background Task Management (BTM):**
  * *Failure Effect:* End user modifies *System Settings → General → Login Items & Extensions* to disable enclave background jobs.
  * *Automated Recovery:* MDM pushes configuration profile `MCPMac-Enclave.mobileconfig` carrying payload `com.apple.servicemanagement` (`RuleType = LabelPrefix`, `RuleValue = com.enterprise.enclave.`), locking background task state in the Darwin BTM database.
* **Scenario G: Profile L3 Deployed on Ad-Hoc Mode A Build:**
  * *Failure Effect:* Enterprise policy mandates Team ID attestation, but package is unsigned or ad-hoc cdhash pinned.
  * *Automated Recovery:* `mcp-enclave deploy install --profile L3` fails closed with exit code 20 and error message `L3_REQUIRES_TEAM_ID` (`D-R6`), preventing unverified enterprise operation.
* **Scenario H: Hardware Integrity Quarantine Latch (`quarantine.sealed`):**
  * *Failure Effect:* Kernel Mach exception burst, hardware tampering, or invalid ZK proof triggers graduated strike threshold; `enclave-zk-auditor` latches `quarantine.sealed`. All inference turns and proving jobs refuse execution with `HARDWARE_INTEGRITY_QUARANTINE`.
  * *Automated Recovery:* Healthcheck reports exit code 50 with status `"quarantined"`. Workstation remains safe and fail-closed. Recovery requires deploying an authorized `UnquarantineGrant` target via TUF or an operator multi-sig quorum ceremony (`RB-203` / `RB-210`).
* **Scenario I: OHTTP Compliance Outbox Backlog & Disk Quota Saturation:**
  * *Failure Effect:* Laptop operating disconnected on battery power defers outbox draining passes. Encapsulated rollup frames in `/var/db/enclave/cas/ohttp-outbox` accumulate and reach the $100\text{ MiB}$ limit.
  * *Current observation and required recovery:* Producer admission bounds retained logical payload lengths. Health acquires the configured queue through authenticated CAS diagnostics; known excess or unavailable observation contributes to exit code 50. Unknown counts remain null. Production AC-triggered draining, durable authenticated receipts and retirement/reconciliation remain unimplemented obligations; healthcheck does not trigger a drain. Preserve custody and follow `RB-212`; no archive/delete workaround establishes compliance.
* **Scenario J: Workstation Memory Pressure & Darwin Jetsam Eviction (`GAP-53`):**
  * *Failure Effect:* Workstation experiences severe memory pressure across user processes; Darwin kernel emits `NOTE_MEMORYPRESSURE_WARN` followed by `EXC_RESOURCE` / SIGKILL on resident allocations.
  * *Automated Recovery:* Daemons listen on dispatch memory pressure sources, immediately shedding speculative decoding caches and releasing unreferenced scratch buffers. If killed, `launchd` auto-respawns the daemon; the service runs APFS Write-Ahead Log recovery (`recoverValidWal`), rolls back torn frames, and restores synchronized sequence authority state without triggering hardware quarantine (`RB-213`).

### 6.3 Lifecycle Operations & Playbooks

1. **Atomic Model Swaps (`D-R3`):**  
   Updating active model weights never involves manual copying or service downtime:
   * The operator publishes an updated TUF targets metadata file containing the new model Bao root.
   * `UID 702` downloads and verifies missing FastCDC chunks into CAS storage.
   * When verified, `UID 702` resolves the model to `UID 701` over IPC, passing atomic `SCM_RIGHTS` descriptors (`CasWeights::resolve`).
   * No `SIGHUP` or daemon restart is required; running inferences finish on existing mappings, while new prompts bind to the newly resolved descriptor.
2. **Automated Cache Eviction (`D-R17`):**  
   FastCDC ref-counted chunk pruning runs whenever APFS container free space falls below $15\%$:
   * Chunks with reference count 0 that do not belong to active TUF target roots are unlinked.
   * Models currently pinned in `enclave-host-config.json` are protected from eviction.
   * Operators can manually trigger cleanup via `mcp-enclave deploy purge --profile <tier>`.
3. **Emergency Fleet Quarantine & Revocation ($\le 600\text{ s}$):**  
   In the event of a compromised model checkpoint, grant key, or security incident:
   * Security publishes a TUF target revocation with `"revoked": true`.
   * Fleet MDM triggers immediate check-in: `mcp-enclave deploy healthcheck --profile L3`.
   * `UID 702` detects revocation, unlinks the local model projection, and executes `ftruncate(fd, 0)` (causing active readers to fault with `SIGBUS`).
   * The root supervisor enumerates open descriptors via `proc_pidinfo` and issues `SIGKILL` within $500\text{ ms}$.
   * Complete endpoint wipe path: `mcp-enclave deploy purge --profile L3 --yes --remove-accounts --purge-state`.

---

## 7. Formal Verification & Audit Invariants

Deployments must satisfy non-negotiable formal invariants:
$$\begin{aligned}
\text{NetEgress}(\text{UID } 701) &= \emptyset \quad (\text{UDS only; pf blocks GID } 8701) \\
\text{NetEgress}(\text{UID } 703..705) &= \emptyset \quad (\text{UDS only; 0 listening sockets in L3}) \\
\sum_{d \in \{702..705\}} \text{phys\_footprint}(d) &\le 152\text{ MiB} \\
\sum_{d \in \{701..705\}} \text{phys\_footprint}(d) &\le 200\text{ MiB} \\
\text{DiskOutbox}(\text{UID } 702) &\le 100\text{ MiB} \quad (\text{bounded local queue}) \\
\text{QuarantineLatched}(\text{Host}) &\implies \text{Status} = \text{UNHEALTHY (exit 50)}
\end{aligned}$$

---

## 8. Hardware Compatibility Matrix

| Apple Silicon Generation       | Memory Tiers Tested                | Accelerators Active      | Target Model Envelopes      |
|--------------------------------|------------------------------------|--------------------------|-----------------------------|
| **Apple M1 / M1 Pro / M1 Max** | 8 GB, 16 GB, 32 GB, 64 GB          | NEON BLAKE3, AMX, ANE    | 3B–8B (Low), 14B–32B (Mid)  |
| **Apple M2 / M3 / M4**         | 16 GB, 24 GB, 36 GB, 48 GB, 128 GB | PAC, AMX, ANE, Fast Path | 8B–32B (Mid), 70B+ (High)   |
| **Apple M5+ / Future Silicon** | Up to 192 GB+                      | Apple MIE / Silicon EMTE | Full Residency & Co-Serving |

---

## 9. Normative References & Citations

1. **Apple Developer Documentation:** *Device Management — Mobile Device Management Protocol Reference and Configuration Profile Reference*. URL: `https://developer.apple.com/documentation/devicemanagement` (Accessed 2026-11-06).
2. **Apple Developer Documentation:** *Sending Notification Requests to APNs*. URL: `https://developer.apple.com/documentation/usernotifications/sending-notification-requests-to-apns` (Accessed 2026-11-06).
3. **Jamf Software:** *Jamf Pro Documentation — Parameter Conventions for Scripts ($1-$3 reserved, $4-$11 customizable)*. URL: `https://learn.jamf.com/en-US/bundle/jamf-pro-documentation-current/page/Scripts.html` (Accessed 2026-11-06).
4. **Jamf Software:** *Jamf Pro Documentation — Computer Extension Attributes Scripting and XML Result Structure*. URL: `https://learn.jamf.com/en-US/bundle/jamf-pro-documentation-current/page/Computer_Extension_Attributes.html` (Accessed 2026-11-06).
5. **osquery Foundation:** *osquery Schema Reference v5.12+ (tables: processes, launchd, signature, users, groups, disk_encryption, system_info, os_version, sip_config)*. URL: `https://osquery.io/schema/` (Accessed 2026-11-06).
6. **Munki Project:** *Munki Documentation — Pkginfo Files and installcheck_script Mechanics*. URL: `https://github.com/munki/munki/wiki/Pkginfo-Files` (Accessed 2026-11-06).
7. **Ansible Documentation:** *Ansible Collection ansible.builtin and macOS Darwin Module Execution*. URL: `https://docs.ansible.com/ansible/latest/collections/ansible/builtin/index.html` (Accessed 2026-11-06).
8. **Apple Darwin System Manuals:** *pf.conf(5) and pfctl(8) Manual Pages*. URL: `https://keith.github.io/xcode-man-pages/pf.conf.5.html` (Accessed 2026-11-06).
9. **Apple Darwin System Manuals:** *setrlimit(2) Manual Page (documenting RLIMIT_RSS unenforced status on Darwin)*. URL: `https://keith.github.io/xcode-man-pages/setrlimit.2.html` (Accessed 2026-11-06).

---

## 10. Revision History

* **Rev 2.6 (2026-11-18):** User-approved Track C (L1 alpha). Code-signing Mode A extends to the **development fleet** as a builder-owned trust root. `scripts/pin-local-build.sh` ad-hoc signs (Hardened Runtime) the custody daemon and a development-only Touch ID helper, and installs their cdhashes root-owned in the standard pin file. Fleet packaging refuses a helper built with `MCPMAC_DEV_SAME_UID`. The pin script refuses a Mac with an installed deployment, whose pins it would replace. Installed fleet trust (Mode A from `packaging/macos/build.sh`, Mode B Team ID) is unchanged. See "2026-11-18 development trust root and fleet boundary".

* **Rev 2.5 (2026-11-15):** Approved YKD-03/04/14/15 aligns attestation/disclosure, D2 per-console helper privilege and evidence-bound status. Reciprocal signing, actual admission, installed/physical qualification and measured resources remain open.

* **Rev 1.0 (2026-11-04):** Initial draft specification authored based on exploratory architectural notes (`MDMME.md`).
* **Rev 2.0 (2026-11-06):** Complete normative overhaul incorporating `docs/reviews/MDMME_RECONCILIATION_2026-11-06.md` (`D-R1` through `D-R18`):
  - Formally established `mcp-enclave deploy` as the canonical CLI surface;
  - Enforced network-less isolation for `UID 701` and single-egress CAS Bao streaming for `UID 702`;
  - Documented Darwin kernel `RLIMIT_RSS` unenforced status and established `phys_footprint` Mach task monitoring;
  - Specified two-phase detached asynchronous hydration worker mitigating APNs 120–300s execution ceilings;
  - Added complete production adapters for Munki, Ansible, Fleet, Jamf Pro, and Lightweight MDM.
* **Rev 2.2 (2026-11-15):** User-approved `YKD-01` aligns profile selection with FS-703's PIN-free `L1`/`L2` and secure host existing-PIN `L3` contract. Preserve per-profile factors, headless refusal, actual hardware qualification and host-only secret handling. No fleet/provider implementation or installed acceptance is implied.

* **Rev 2.3 (2026-11-15):** User-approved `YKD-02` calibrates broad L1/L2 and tighter L3 lifecycle budgets from the pre-implementation native baseline. Numeric limits and physical/installed qualification remain pending; preserve release-fence and cleanup semantics.

---

## 11. Implementation Notes

The implementation of FS-706 (Phase 4) is complete in software:

1. **Reconciliation Baseline:** Precedence strictly enforced `FS-701..705` and Darwin platform reality over prompt aspirations per `docs/reviews/MDMME_RECONCILIATION_2026-11-06.md` (`D-R1`..`D-R18`).
2. **Canonical CLI:** Implemented under `mcp-enclave deploy <verb>` with stable exit codes and JSON schema adherence (`schemas/deploy-result.schema.json`).
3. **Packet Filter Anchors:** Implemented in Rust single source (`crates/mcp-enclave/src/pf.rs`), loading `com.enterprise.llm.isolation` (blocking non-loopback egress for GID 8701) and `com.enterprise.cas.swarm`. Monitored and restored by supervisor daemon within $\le 1000\text{ ms}$ upon network state changes.
4. **Hydration Engine:** Implemented detached worker LaunchDaemon `com.enterprise.enclave.hydrate`, supporting streaming Bao chunk verification, L3 DMG pre-stage mounting (`hdiutil attach -readonly -nobrowse -noautoopen`), and $16\text{ KiB}$ slice resume.
5. **GUI Intent Agent & BTM:** Deployed to interactive Aqua user sessions (`gui/$CONSOLE_UID`), deferring cleanly at login window. Mitigated macOS 13+ background task user-disablement via MDM `com.apple.servicemanagement` profile.
6. **Fleet Adapters:** Implemented turnkey configurations for Munki (`enclave-core.pkginfo`, `enclave-model-weights.pkginfo`), Ansible (`roles/mcp_enclave/`), Fleet (GitOps manifest + osquery compliance queries), Jamf Pro (`jamf_deploy_enclave.sh` with `$1`–`$3` preserved, Extension Attributes `EA-Enclave-Status.sh` and `EA-Enclave-Security.sh`), and Lightweight MDM (`lightweight_mdm_bootstrap.sh` and `MCPMac-Enclave.mobileconfig`).
7. **Packaging:** Implemented `packaging/pkg/build-pkg.sh` synthesizing flat packages with preinstall/postinstall scripts.
8. **Operational Runbooks:** Authored `RB-207` through `RB-211` in `docs/SRE_RUNBOOKS.md` covering deployment failure triage, pf flush recovery, hydration stalls, BTM remediation, and emergency fleet revocation drills ($\le 600\text{ s}$).

Rev2.1 amendment (2026-11-12): ADR021/§3.2.1 adds the confined root APFS broker and its packaging, trust, lifecycle, observability and acceptance obligations. The earlier five-daemon budgets and DMG-ingestion descriptions do not establish the helper or L3 publication readiness.

### F38 helper fleet acceptance qualification — 2026-11-12

All L2/L3 daemon and supervisor monitor registration gates, explicit supervisor profile arguments, weak service Wipe-hook lifetimes, bounded GUI screen-lock delivery and five distinct supervisor-assigned target receipts are source obligations now represented in tooling/tests. A running root helper and successful unmount do not prove immutable snapshot-holder revocation: the current actual snapshot inode/mmap observation and authenticated enforcement route remain missing source work, separately from entitlement/mount/physical deadline acceptance. Fleet readiness must retain that limitation until the versioned boundary and allowed holder policy are implemented and verified; no destructive host acceptance ran in this assignment.

The [Lean transport implementation record](formal/transport-lean-implementation.md)
adds bounded broker ownership/quiescence and startup/configuration models with
actual kernel checks. Their observed-platform and identity interfaces remain
assumptions; no theorem replaces installed Fleet, reciprocal pin rotation,
cross-UID confinement, APFS or physical-event acceptance. Deployment readiness
must continue to report those conditions separately.

* **Rev 2.4 (2026-11-15):** User-approved `YKD-08/09` preserves actual A3/A4 Touch ID without Watch/passcode/on-key substitution and specifies earliest-applicable expiry plus no initial host PIN/UV token reuse between ceremonies. Installed qualification and organizational prerequisites remain open.

### 11.3 Rev 2.5 active amendments (YKD-03/04/14/15, 2026-11-15)

At actual first L3 setup disclose the selected attestation mode, Basic plus
independent inventory's weaker per-device assurance, Enterprise rationale,
organization restrictions and remaining risk. Enterprise-required organizations
must refuse unavailable Enterprise rather than silently falling back. The notice
must cover CLI/install/enrollment/fleet entrypoints and preserve JSON output;
interrupted notice source is unverified, and independent asset admission is open.
See YKD-03.
D2 and the per-console helper layout in §2.2/§4.4 supersede shared staff access,
standalone helper-crate descriptions and externalized-context transfer. Complete
reciprocal signing/session verification, protected-directory tests and signed
installed acceptance are still required. Plist RSS limits are advisory; measure
Mach phys_footprint and account helper/broker/auxiliary costs separately. Historical
§11 completion wording is scoped to its source/evidence checkpoint, not all
approved current requirements.

### 2026-11-15 source-bound OIDC auxiliary deployment update

`EnclaveOIDC.app` is separately signed/pinned as
`com.enterprise.enclave.oidc-broker` and runs in the console Aqua session, apart
from UID703 and biometric UI. The LaunchAgent has KeepAlive=false; missing/stale
root-protected public identity/OAuth configuration refuses rather than creating
an IdP or restarting repeatedly. Custody receives only the fixed peer/session
configuration path and never adopts caller-provided IdP identity. Root runtime
maintenance prepares the separate protected `oidc/<actual uid>` child. The
third native build/private-protocol receipt
and deployment source evidence
identify exact inputs, binaries and exclusions; neither performs installation or
genuine login. Source render/core directory tests are portable, and inert
installer/uninstaller tests verify private-filesystem control flow only.

Install/uninstall inventory the native-observed live launchd user domains,
including directory-backed users, and refuse an unknown inventory before
changing payload. Loaded biometric/browser helper jobs must stop before app or
shared-pin replacement/removal; stop failure retains the old payload. This is
a snapshot, without an atomic global login/bootstrap lock; full installed
all-session lifecycle acceptance remains OPEN. Normal rollback must retain
state, counters, revocations and authority/version floors and never restart an
old plist with a newly replaced binary. The existing L3 setup notice is retained.

Protected root per-login identity renewal, initial-lock readiness, real GUI/IdP
authentication/cancellation, signed distinct-UID/code-pin/entitlement/Seatbelt
acceptance and native phys_footprint remain separate OPEN prerequisites. Linux
workspace distinct-UID chown was observed to report success without applying
identity; runtime code now verifies opened-directory owner/group/mode after
mutation and refuses mismatch. The actual Darwin root ownership positive was
NOT RUN without authorized installed/root test environment. OIDC browser/network
state belongs to its separate console broker; the five sensitive daemons gain
no Internet listener or general bridge. Account for auxiliary memory separately;
advisory RSS values and compile/test elapsed time are not footprint/lifecycle
qualification. Full L1/L2/L3 qualification is not established.

## 2026-11-15 selected core lifecycle and supported native verifier

The bounded delivery connects selected core-five start and descriptor-only
restrictive stop with one held cooperative maintenance guard, exact native code
checks, bounded owned-child commands and preserved partial receipts. The exact
Stop route alone bypasses unavailable admission references; start retains full
protected admission. Runtime and full-installation readiness remain unknown.

Actuals are73 focused Linux cases across ordinary, private-root and CLI categories
and61 Mac cases, including generated static signature fixtures and actual nonroot
ownership refusal. Native production compilation/linking and CLI usage loading
pass. These counts overlap prior regressions. Initial ownership and native-loader
failures remain retained; supported selected-digest metadata replaces unavailable
macOS27 signature-slot constants without claiming slot inventory. Installed root
start/stop, real authority/console/BTM/physical factors, upgrade migration and
full L1/L2/L3 qualification remain OPEN. No installed or credential operation ran.

## 2026-11-15 bounded fixed-account and runtime-directory implementation

The source-bound YubiKey delivery implements read-only admission of the existing fixed public user/group identities and required memberships under the system authentication search policy. Independent name/numeric queries and repeated complete observations must agree, including bounded alias sets and exact official names. This is not account creation/adoption, shell/home policy approval, an exhaustive extra-membership audit or an atomic remote-directory transaction.

Dedicated runtime provisioning follows complete public-payload publication and requires that genuine account capability and one real maintenance guard. It creates only absent fixed planner directories, verifies existing exact metadata without touching contents, and retains uncertain prefixes on failure. Existing-upgrade runtime sequencing remains unavailable until a state-preserving producer exists. Focused25Linux/27Mac checks and native compilation/linking pass; UID501 fixtures/public root-wheel reads do not establish installed fixed-UID operation. Concrete installer/release/inactivity/trust/jobs/pins, upgrade migration, full fleet acceptance and L1/L2/L3 qualification remain OPEN.

## 2026-11-15 guarded payload and non-broker auxiliary teardown

The bounded delivery requires real account/maintenance admission for selected public payload publication, preserves conservative failure prefixes and prevents unconditional cleanup after lost exclusion. Explicit selected `daemon stop-auxiliary` uses descriptor-only restrictive authority for non-broker auxiliary registrations and all observed GUI domains; core-five behavior stays unchanged, broker quiescence remains UNKNOWN and no process-inactivity authority is inferred.

Actuals:69unique focused Linux cases across ordinary/private-root/CLI modes and48applicable Mac cases PASS, plus native production checking/linking and CLI usage loading against689exact inputs. Twenty protected-root native cases are ignored, with separate Linux private-root outcomes. Initial missing public-field documentation compile failure and its source correction remain retained. No installed or physical operation ran. Actual installer cooperation, genuine release/inactivity, broker/trust/jobs/pins and forward-only existing-upgrade migration remain work; both routes and all32 item/profile gates remain OPEN.

## 2026-11-16 retained private startup preparation

Actual source and evidence composes original selected root lease/session/monitor/listener/Mach/held/primary owners and revokes before partial teardown or unwind. Normal native checking and36 exact fixtures on each platform pass; this executes no production startup or host configuration. Public selected dispatch and all12PF predicates remain unavailable until authenticated native messages/current custody assignment, effective atomic PF restoration and genuine installed inputs/identities are qualified. No complete deployment, physical factor, lifecycle/erasure or profile gate closes.

## 2026-11-16 selected native resource and identity continuation

Verified bounded continuation adds original message-resource cleanup and local self-task/socket identity continuity. Normal native compilation and69 exact software fixtures on each platform pass. No native assignment/listener/peer authentication, root/PF or installed service was executed. Received-task/kernel-origin/current-custody binding, complete PF readiness and genuine installed inputs/identities remain requirements; all selected readiness/profile gates stay OPEN.

### 2026-11-16 selected native provenance checkpoint

Verified source and limits adds actual kernel-trailer and local task/thread class checks, with24focused fixtures per platform plus normal native checking. The actual own-object calibration confirms public object enum behavior only. All delivered selected messages still refuse the custody actor/current-assignment gap; all12PF terms and public selected startup remain unavailable. No deployment, physical factor, lifecycle/erasure or profile gate closes.

### 2026-11-18 development trust root and fleet boundary

User-approved for the L1 alpha (Track C). This section is written for fleet
administrators and for developers working locally.

**What fleets keep.** Installed deployments use one of the two modes in
§2.3:
- **Mode A:** `packaging/macos/build.sh` computes each shipped binary's
  cdhash into the root-owned `codesign-pins.json`.
- **Mode B:** Team ID designated requirements; mandatory for `L3`.

Custody runs as `_piivault` (UID 703) under launchd. The `_enclaveintent`
helper runs as the per-console LaunchAgent of §4.4 and accepts only a UID
703 custody peer. Nothing here changes that.

**What local development adds.** The development fleet
(`mcp-enclave --dev`) can now run custody on the real Secure Enclave and
Touch ID (`MCP_ENCLAVE_REAL_CUSTODY=1`) instead of simulated hardware. In
that mode:
- **Builder-owned trust root.** `scripts/pin-local-build.sh` builds,
  ad-hoc signs (Hardened Runtime) and pins `enclave-custody-vaultd` and
  `enclave-intent` in the same root-owned pin file, with one `sudo`. Whoever
  builds owns the trust root; no third-party binary or signing identity is
  involved. Other identifiers in the file are kept, and these two are
  replaced.
- **Dev-only helper variant.** The helper is a separate development build
  (`-D MCPMAC_DEV_SAME_UID`). It accepts a custody peer only at the console
  user's own UID, and only from a private 0700 socket directory that user
  owns. The identifier-plus-cdhash check is unchanged.
- **Same pin file, same check.** Custody verifies the helper with exactly
  the code that verifies it in an installed deployment.

**Fleet boundary rules:**
1. **Never ship the development helper.** It carries the marker
   `MCPMac intent helper dev same-UID (development only)`.
   `packaging/macos/build.sh` fails if the packaged `enclave-intent`
   contains it, and the pin script refuses a helper that lacks it. Fleet
   compliance tooling (§5.3 Fleet/osquery) can check installed binaries for
   the same string.
2. **Don't pin development builds on managed Macs.** The pin file is
   shared. Running the pin script on a Mac with an installed deployment
   would replace that deployment's custody and helper pins, so the script
   refuses when `/Library/LaunchDaemons/com.enterprise.enclave.*.plist`
   exists. Use a development Mac without an installed fleet.
3. **A rebuild changes a cdhash.** Development pins name exact builds;
   re-pin after every rebuild. Fleets distribute pins with the package
   (Mode A) or don't use them at all (Mode B).
4. **Same-UID is weaker by design.** With no UID boundary, other processes
   running as the developer can reach the development daemons; the pins
   stop binary substitution only. The installed distinct-UID path remains
   the acceptance gate for every fleet profile.

The runbook is [docs/TRACK_C_LOCAL_CEREMONY.md](TRACK_C_LOCAL_CEREMONY.md).
Custody details are in FS-703, "2026-11-18 L1 integrated ceremony".
