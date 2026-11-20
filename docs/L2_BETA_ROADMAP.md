# Heimdall-Enclave: L2 Beta Architectural Roadmap & Technical Specification

* **Document ID:** `ROADMAP-L2-BETA-2026`
* **Status:** `ACTIVE SPECIFICATION (IN FLIGHT)`
* **Predecessor:** [`docs/L1_ALPHA_ROADMAP.md`](L1_ALPHA_ROADMAP.md) (L1 Alpha Qualified; see Qualification Note)
* **Target Platform:** Apple Silicon (`arm64e`, M1 through M5+) & macOS 14.0+ (Sonoma / Sequoia)
* **Governing Specifications:** [FS-702 (Swarm Distribution)](FEATURE_SWARM_SECURITY_PROFILES.md) · [FS-703 (Hardware Custody)](FEATURE_HARDWARE_CUSTODY_PROFILES.md) · [FS-706 (Fleet Distribution)](FEATURE_MDM_FLEET_DISTRIBUTION.md)

---

## 1. Executive Summary: What L2 Beta Delivers

While **L1 Alpha** established the standalone Apple Silicon agent inference engine across five model paradigms with Apple Secure Enclave (SEP P-256) Touch ID biometrics, **L2 Beta** transitions Heimdall-Enclave from a single-machine developer preview into a **hardened, peer-to-peer enterprise workstation mesh**.

L2 Beta focuses on two transformative enterprise pillars:

1. **Physical FIDO2 Hardware Attestation (YubiKey 5.7/5.8+)**: Anchoring agent authority, model decryption keys, and high-privilege tool execution into genuine external cryptographic hardware authenticators via CTAP 2.1, Yubico Metadata Service (MDS) roots, and HMAC-secret / PRF extensions.
2. **P2P Swarm Intelligence & Content-Addressed Model Distribution**: Eliminating the "Monday morning WAN bottleneck" where hundreds of developers download 10–40 GB model updates simultaneously. L2 enables LAN peer-to-peer distribution using Iroh QUIC, FastCDC content-defined chunking, and BLAKE3 Bao verified streaming trees.

```
                  ┌─────────────────────────────────────────────────────────┐
                  │                 L2 BETA ARCHITECTURE                    │
                  └─────────────────────────────────────────────────────────┘
                                               │
                       ┌───────────────────────┴───────────────────────┐
                       ▼                                               ▼
         ┌───────────────────────────┐                   ┌───────────────────────────┐
         │     HARDWARE CUSTODY      │                   │     P2P SWARM SYNC        │
         │   FIDO2 CTAP 2.1 Attest   │                   │    Iroh QUIC Mesh         │
         │   YubiKey 5.7/5.8+ (USB)  │                   │    FastCDC + BLAKE3 Bao   │
         │   Biometric + PINless     │                   │    Multi-Seed Striping    │
         │   Chained TouchID -> YK   │                   │    0% Office WAN Overload │
         └───────────────────────────┘                   └───────────────────────────┘
```

---

## 2. Milestone Execution Matrix (B0 through B9)

The L2 Beta implementation follows a rigorous, ten-stage delivery ladder:

| Milestone                         | Code | Focus Area               | Deliverable & Acceptance Criteria                                                                             | Current Status  |
|:----------------------------------|:----:|:-------------------------|:--------------------------------------------------------------------------------------------------------------|:---------------:|
| **Baseline & Fleet Inventory**    | `B0` | Environment & Tooling    | Software suite baseline, simulated L2 fleet setup, hardware baseline inventory recorded.                      |  **Complete**   |
| **Physical Hardware Integration** | `B1` | FIDO2 / CTAP 2.1 Driver  | Genuine YubiKey 5C/Bio (`macos-hid`) attestation, ES256/EdDSA algorithm negotiation, PRF extension support.   | **In Progress** |
| **Dev L2 Authority**              | `B2` | Asset Enrollment Policy  | Local L2 enrollment authority, inventory issuer, asset policy keys provisioned for the dev cluster.           | **In Progress** |
| **Hardware Enrollment**           | `B3` | Workstation Enrollment   | Physical enrollment ceremony executed on genuine hardware; signed enrollment receipts generated.              |  **Scheduled**  |
| **Chained A3 Ceremony**           | `B4` | Biometric Chaining       | Chained Secure Enclave Touch ID (`L1`) $\rightarrow$ Physical YubiKey (`L2`) ceremony verifying model output. |  **Scheduled**  |
| **A4 High-Stakes Action**         | `B5` | Multi-Factor Attestation | High-privilege tool execution gate requiring dual-hardware attestation; receipt generation.                   |  **Scheduled**  |
| **Unplugged Fault Tolerance**     | `B6` | Graceful Degradation     | Enclave executes standard actions (`A1/A2`) with YubiKey unplugged; strict refusal on `A3/A4` without crash.  |  **Scheduled**  |
| **5-Model L2 Qualification**      | `B7` | Model Runner Integration | All 5 model classes (AR, Discrete Diffusion, SSM/TTT, Speculative, JEPA) run under Profile L2.                |  **Scheduled**  |
| **Installed Daemons & PF**        | `B8` | System Hardening         | Daemon privilege separation (`UID 701-705`), Darwin Seatbelt sandboxes, and BSD `pf` packet filtering loaded. |  **Scheduled**  |
| **Beta Qualification & Release**  | `B9` | Formal Release Note      | Full regression suite passing, security audit signed, public beta release tagged on GitHub.                   |  **Scheduled**  |

---

## 3. Hardware Custody Specification (`FS-703`)

### 3.1 Supported Hardware Authenticators

* **YubiKey 5 Series** (5 NFC, 5C, 5C NFC, 5 Nano) with firmware **5.4.3**, **5.7.1**, and **5.8+**.
* **YubiKey Bio Series** (FIDO Edition) with on-device fingerprint biometric match.
* **Apple Secure Enclave Processor (SEP)**: On-board hardware root of trust (`P-256`, Secure Enclave Keychain).

### 3.2 FIDO2 CTAP 2.1 Protocol Invariants

1. **Direct USB HID Communication**: Daemons communicate directly with physical authenticators via macOS IOKit HID (`IOHIDDeviceRegisterInputValueCallback`), bypassing web browser prompts.
2. **Yubico MDS Attestation Verification**: Every enrolled authenticator must present an X.509 attestation certificate chaining to official Yubico Root CAs embedded in `packaging/fido-mds/yubico.json`.
3. **Hardware Insertion & Disconnect Watchdog**: Background thread monitors physical USB bus insertion and disconnection events via IOKit notifications, zeroizing cached session leases within 50 ms of device removal.
4. **Topology Gating**: To prevent physical relay and badge-cloning attacks, USB hub depth is strictly gated to `depth <= 1` (direct port or certified Thunderbolt 4 dock).

---

## 4. Content-Addressed Swarm Distribution (`FS-702`)

### 4.1 The Enterprise Problem

A 200-developer office downloading a 14 GB model update simultaneously over unicast HTTPS requires **2.8 Terabytes** of WAN transfer, saturating corporate internet links, causing packet loss, and triggering ISP throttling.

### 4.2 The L2 Solution: LAN Peer-to-Peer Swarming

```mermaid
flowchart TD
    WAN["Corporate WAN / CDN (Cloudflare R2 / S3)"] -->|Single 14 GB Download| Seed1["Workstation 1 (Office Seed / Super-Node)"]
    Seed1 -->|Iroh QUIC LAN Swarm (10 Gbps / Wi-Fi 7)| PeerA["Workstation 2 (Developer)"]
    Seed1 -->|Iroh QUIC LAN Swarm| PeerB["Workstation 3 (Developer)"]
    PeerA -->|FastCDC Chunk Striping| PeerC["Workstation 4 (Developer)"]
    PeerB -->|FastCDC Chunk Striping| PeerC
```

### 4.3 Technical Mechanics

* **FastCDC (Content-Defined Chunking)**: Model checkpoints (`.safetensors`, `.mlx`) are sliced into variable-sized chunks (average 256 KiB, min 64 KiB, max 1024 KiB) using gear-based rolling hashing.
* **BLAKE3 Bao Verified Streaming**: Chunks form a cryptographic Merkle tree. Clients verify individual 16 KiB slices in-flight against the root hash *before* writing to disk. Corrupted chunks are immediately rejected without restarting the download.
* **Iroh QUIC Transport**: Encrypted peer discovery over mDNS on the local subnet; end-to-end TLS 1.3 encryption prevents packet sniffing by rogue network devices.
* **Multi-Seed Striping**: Downloader peers fetch independent chunks in parallel from up to 8 local peers simultaneously, achieving wire-speed saturation (up to 950 MB/s on local 10 GbE networks).

---

## 5. Security & Isolation Invariants

Under Profile `L2`, Heimdall-Enclave enforces four non-negotiable security boundaries:

1. **Inference Process Zero-Egress (`UID 701`)**:
   `UID 701` (`_llmagent`) has **zero network privileges**. BSD Packet Filter (`pf`) rules drop all outbound TCP/UDP traffic from this UID:

   ```pf
   block return out quick proto {tcp, udp} all user _llmagent
   ```

2. **Distribution Daemon Boundary (`UID 702`)**:
   `UID 702` (`_enclavecas`) is the *only* daemon permitted to speak to the local network or internet. It receives model chunks, verifies Bao Merkle trees, and passes read-only file descriptors to `UID 701` via Unix domain socket descriptor passing (`SCM_RIGHTS`).
3. **Darwin Seatbelt Sandboxing**:
   Every daemon runs under a dedicated `/opt/enclave/sandbox/*.sb` profile, blocking execution of unauthorized shells (`/bin/sh`, `/bin/zsh`), unapproved Mach services, and home directory access.
4. **Memory Ceilings**:
   Active daemon processes are continuously audited against a strict `phys_footprint <= 48 MiB` ceiling (measured via Mach `task_info`).

---

## 6. How Remote IT & Security Architects Evaluate L2 Beta

Enterprise engineering teams preparing for the L2 Beta rollout can validate the architecture today using the simulation harnesses and adapter tests:

```bash
# 1. Run the hardware diagnostic harness (simulated or with genuine YubiKey)
python3 scripts/yubikey-profile-tests.py

# 2. Inspect the Bao FastCDC chunking test fixtures
cargo test -p enclave-swarm-syncd

# 3. Validate the BSD pf firewall rules and LaunchDaemon generators
cargo test -p depot-enclave --test launchd_render_tests
```

*For complete implementation details, see [FS-702 (Swarm Security Profiles)](FEATURE_SWARM_SECURITY_PROFILES.md) and [FS-703 (Hardware Custody Profiles)](FEATURE_HARDWARE_CUSTODY_PROFILES.md).*
