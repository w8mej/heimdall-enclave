# Local LLM & Agentic PII Governance Architecture Specification

## Zero-Trust Local Enclave Architecture for Apple Silicon (macOS) Developer Workstations

* **Document ID:** `CORE-V1`
* **Document Version:** 1.0.1-LEGACY (2026-11-04; previously labelled `1.0.0-PROD`)
* **Generation:** `v1.0-Legacy` — Educational Reference Prototype (Envoy + Go OPA + Python)
* **Status:** `[LEGACY v1.0 PROTOTYPE]` — archived; not co-deployed with `v3.0`; receives fixes for simulation-bypass bugs only
* **Superseded-By:** `FS-701..705` (`ADR-006`, `ADR-008`) · **Normative Precedence:** `FS-701..705` > `CORE-V3` > `CORE-V2` > **`CORE-V1`** — see [`README.md §1.2`](../README.md#12-normative-precedence--architectural-lineage)
* **Target Platforms:** macOS 14.0+ (Sonoma, Sequoia) on Apple Silicon (M1, M2, M3, M4)
* **Classification:** Open Reference Specification (legacy)
* **Regulatory Alignment (no attestation):** technical control mapping to GDPR Art. 4(5)/25/32, CCPA/CPRA § 1798.100 and SOC 2 Trust Services Criteria — see [`COMPLIANCE_EVIDENCE.md`](COMPLIANCE_EVIDENCE.md). HIPAA Safe Harbor is **not** claimed.

> **[LEGACY v1.0 PROTOTYPE] — [SUPERSEDED BY FS-701..705].** This document describes the runnable `v1.0` Envoy + OPA + Python reference prototype (`gateway/`, `policies/`, `mcp/auth_proxy.py`). Its OPA/Rego decision plane is superseded by Cedar + `PoP-Biscuit` (`ADR-008`) and its irreversible-only SSN rule by `ADR-007`. Sections that the `v3.0` suite amends carry inline `[AMENDED-BY …]` / `[SUPERSEDED BY …]` markers. `§11` is isolated as non-normative author positioning.

* **Author / Design Authority:** Principal Security & SRE Architecture Fellow
* **Architectural Lineage:** `v1.0` Baseline Enclave (this spec) $\to$ [`v2.0` Dual-LLM/Cedar/ANE/WASI Spec (`BLEEDING_EDGE_ARCHITECTURE.md`)](BLEEDING_EDGE_ARCHITECTURE.md) $\to$ [`v3.0` 6-Track Next-Horizon Suite (`bleeding_edge_future_adoption.md` & `FEATURE_*.md`)](bleeding_edge_future_adoption.md)

---

## Table of Contents

1. [Executive Summary & Architectural Philosophy](#1-executive-summary--architectural-philosophy)
2. [Threat Modeling & Security Invariants](#2-threat-modeling--security-invariants)
   * 2.1 Attacker Personas & Capabilities
   * 2.2 STRIDE Threat Assessment Matrix
   * 2.3 Non-Negotiable Security Invariants
3. [Centralized GitOps Repository & Policy Distribution](#3-centralized-gitops-repository--policy-distribution)
   * 3.1 Policy Bundle Architecture & TUF/Sigstore Verification
   * 3.2 Dynamic Local Synchronization Daemon (`sync-agent`)
   * 3.3 Atomic Rollouts, Monotonic Replay Protection & Air-Gap Fallback
4. [OPA / Rego Policy-as-Code Engine](#4-opa--rego-policy-as-code-engine)
   * 4.1 In-Memory Daemon Topology & gRPC/REST Endpoints
   * 4.2 Comprehensive Authorization Policy (`policies/mcp_authz.rego`)
   * 4.3 PII Detection, Classification & Redaction Rules (`policies/pii_guard.rego`)
   * 4.4 Differential Privacy & Budget Accounting
5. [Model Context Protocol (MCP) Hardening & OAuth 2.1](#5-model-context-protocol-mcp-hardening--oauth-21)
   * 5.1 The MCP Security Problem & Attack Vectors
   * 5.2 OAuth 2.1 with DPoP (Demonstrating Proof-of-Possession) via Apple Secure Enclave
   * 5.3 Inline Zero-PII Enclave: Tokenization / Detokenization Vault
   * 5.4 Tool Schema Enforcing & SQL AST Inspection
6. [Local API Gateway & Kernel-Level Network Isolation](#6-local-api-gateway--kernel-level-network-isolation)
   * 6.1 Defense-in-Depth Network Model: Layer 4 (`pf`) & Layer 7 (`Envoy`)
   * 6.2 macOS Packet Filter (`pf.conf`) Anchor Configuration
   * 6.3 Envoy Gateway Local Configuration (`envoy-local.yaml`)
   * 6.4 Mutual TLS (mTLS) with Ephemeral Machine-Local Root CA
7. [Agentic Workload Identity on macOS (Apple Silicon M1+)](#7-agentic-workload-identity-on-macos-apple-silicon-m1)
   * 7.1 SPIFFE/SPIRE Architecture on Darwin
   * 7.2 Secure Enclave Processor (SEP) Hardware-Backed Key Attestation
   * 7.3 Binary Code Signing & Designated Requirement Attestation (`csreq`)
   * 7.4 Ephemeral X.509 SVID Minting & Lifecycle Management
8. [Enterprise SRE Operationalization, Reliability & Fault Tolerance](#8-google-sre-operationalization-reliability--fault-tolerance)
   * 8.1 Service Level Objectives (SLOs) & Service Level Indicators (SLIs)
   * 8.2 Failure Modes and Effects Analysis (FMEA)
   * 8.3 Circuit Breaking, Bulkheading & Backpressure
   * 8.4 Zero-PII Structured Audit Telemetry
9. [Disaster Recovery, Runbooks & Day-2 Operations](#9-disaster-recovery-runbooks--day-2-operations)
   * 9.1 Emergency Egress Break-Glass Procedure
   * 9.2 Key Rotation & Secure Enclave Desync Recovery
   * 9.3 Runaway Agent Process Quarantining
10. [Automated Verification & Compliance Test Suite](#10-automated-verification--compliance-test-suite)
    * 10.1 Static & Dynamic Security Verification Pipeline
    * 10.2 Pre-Flight Hardware & Policy Assurance Checklist

---

## 1. Executive Summary & Architectural Philosophy

Modern enterprise software engineering increasingly equips developers with local Large Language Models (LLMs) and autonomous agents (e.g., code assistants, schema generators, database analyzers, customer ticket triage). When developers evaluate realistic scenarios against realistic test databases, the model context window inevitably ingests Customer Personally Identifiable Information (PII) — including names, email addresses, national identifiers (SSNs), payment tokens, and proprietary IP.

Running agentic workloads on cloud platforms benefits from centralized Identity and Access Management (IAM), hardware security modules (Cloud HSM), audited software-defined networking (VPC/firewall), and standardized container orchestration (Kubernetes/Borg). Conversely, **a developer's laptop running macOS is inherently an untrusted, hostile execution environment**:

* It maintains direct, unfiltered outbound connections to residential or corporate Wi-Fi.
* It hosts unvetted third-party software, IDE extensions, developer tool chains (Homebrew, npm, pip), and debugging utilities.
* Agents possess tool-use capabilities (Model Context Protocol, shell execution, database querying) that can be co-opted via prompt injection to exfiltrate data.
* Developer workflows demand low latency (< 15ms authorization overhead, zero human-noticeable inference lag) and reliable offline support.

### The Zero-Trust Local Enclave Philosophy

To meet **mission-critical operational reliability** and **principal-grade security assurance**, we discard perimeter-based trust and establish a **Zero-Trust Local Enclave** model directly on macOS Apple Silicon. Every operation adheres to three foundational tenets:

1. **Provable Zero Egress for Agent Processes:** The agent runtime (Python/Node/Go runtime) is bound to a dedicated POSIX Group ID (`_llmagent`) and quarantined at the macOS kernel level via Packet Filter (`pf`). It is physically incapable of emitting SYN packets to any network interface other than the loopback interface (`127.0.0.1` / `::1`).
2. **Cryptographic Separation of Concerns:**
   * **Decision Plane:** Open Policy Agent (OPA) evaluates signed declarative Rego rules fetched from a centralized enterprise repository.
   * **Enforcement Plane:** Local Envoy API Gateway and Model Context Protocol (MCP) Auth Proxies intercept every inter-process call.
   * **Identity Plane:** Agents are issued short-lived cryptographic identities (SPIFFE SVIDs) anchored to the Apple Silicon Secure Enclave Processor (SEP) and verified against macOS Code Signing Team IDs.
3. **Strict Zero-Plaintext Invariant for Customer PII:** Plaintext PII is intercepted prior to entering the LLM context window. High-sensitivity tokens are replaced with synthetic deterministic surrogates by an inline local Data Loss Prevention (DLP) vault. Masked representations allow semantic reasoning without data leakage.

```
+-------------------------------------------------------------------------------------------------------+
|                                    macOS Apple Silicon (M1/M2/M3/M4)                                   |
|                                                                                                       |
|   +-----------------------+     mTLS / DPoP      +------------------------+      gRPC Check           |
|   |   Agent Workload      | -------------------> |    Local API Gateway   | --------------------+     |
|   | (LangChain/LlamaIndex)|                      |  (Envoy / Rust Proxy)  |                     |     |
|   | GID: _llmagent        | <------------------- |  127.0.0.1:8443        |                     |     |
|   +-----------------------+     Masked Payload   +------------------------+                     |     |
|         ^           |                                 |             ^                           v     |
|         |           | Stdio / Domain Socket           | Redact/     | Validated         +-------------+
|         |           v                                 | Substitute  | Response          | OPA Daemon  |
|         |   +---------------------+                   v             |                   | (localhost) |
|         |   | MCP Auth Proxy      |              +------------------------+             | Bundle v1.4 |
|         |   | (OAuth 2.1 Resource)|              | Tokenization / DLP     |             +-------------+
|         |   +---------------------+              | Vault (In-Memory)      |                    ^      |
|         |           |                            +------------------------+                    |      |
|   Attest|           v JSON-RPC                                                                 | Sync |
|         |   +---------------------+                                                            |      |
|         |   | Protected Tool      |                                                     +-------------+
|         |   | (Customer DB/Files) |                                                     | Central Git |
|         |   +---------------------+                                                     | Policy Repo |
|         |                                                                               +-------------+
|   +-----------------------------------------------------------------------------------------------+   |
|   | macOS Hardware & Kernel Boundary:                                                             |   |
|   |  - Packet Filter (`pf`): Blocks all non-loopback egress for GID `_llmagent`                   |   |
|   |  - Secure Enclave (SEP): Hardware-backed ECDSA P-256 Keypairs for DPoP & SVID Attestation      |   |
|   |  - Code Signing (`csreq`): Enforces designated Team ID, Entitlements, and Hardened Runtime    |   |
|   +-----------------------------------------------------------------------------------------------+   |
+-------------------------------------------------------------------------------------------------------+
```

---

## 2. Threat Modeling & Security Invariants

We execute a rigorous threat model across the local execution pipeline using STRIDE and NIST SP 800-207 Zero Trust Architecture principles.

### 2.0 Trusted Computing Base (TCB) & Formal Threat Model Boundary (GAP-46)

* **Formal Threat Model Definition:** **"Malicious Developer Space & Compromised Tool Sandbox with Honest-but-Attacked Darwin OS Kernel."**
* **The TCB Kernel Boundary:**
  True hardware-isolated micro-architectures (such as AWS Nitro, AMD SEV-SNP, or Apple Private Cloud Compute) execute inside hardware-encrypted memory compartments isolated from the host hypervisor. In contrast, MCPMac / Heimdall-Enclave operates as a privilege-separated, kernel-enforced local enclave on macOS. The Trusted Computing Base (TCB) explicitly comprises:
  1. The Apple Silicon processor package (CPU, GPU, Neural Engine, Unified Memory controller, System Level Cache).
  2. The Apple Secure Enclave (`SEP`) hardware coprocessor and its immutable Boot ROM.
  3. The macOS Darwin XNU kernel and its native security primitives: System Integrity Protection (SIP), Secure Boot (Full Security policy), the Seatbelt sandbox framework, and the Apple Packet Filter (`pf`).
* **Untrusted Domain:**
  The untrusted domain encompasses all unprivileged console developer processes (`uid=501`), compromised third-party dependencies (npm, PyPI, Homebrew), adversarial external Model Context Protocol (MCP) servers, untrusted tool execution environments, and adversarial inputs targeting model context windows (indirect prompt injections).
* **Kernel Attack Surface Minimization:**
  To defend the host kernel against exploitation from within any potentially compromised enclave daemon:
  * Every daemon drops Mach task port debugging entitlements (`task_for_pid` denied).
  * Anti-debugging tracing barriers are enforced via `ptrace(PT_DENY_ATTACH)`.
  * Process core dumps are disabled across all daemons (`RLIMIT_CORE = 0`).
  * Zero-JIT execution is strictly enforced; dynamic memory page execution (`PROT_EXEC` on heap/stack) is barred by hardened runtime.
  * POSIX privilege separation restricts each daemon to a dedicated system service account (`UID 701–705`) governed by minimal Seatbelt profiles.
* **Long-Term Hypervisor Isolation Roadmap (Type-1 Guest):**
  For deployments requiring complete mathematical non-interference against a hostile or root-compromised Darwin host OS, the next-generation architectural roadmap specifies running the five enclave daemons inside an isolated, lightweight Apple `Virtualization.framework` Type-1 guest VM with hardware-isolated Guest Physical Address (GPA) space and dedicated VirtIO-vsock endpoints.

### 2.0.1 Sandboxing Architecture: In-Process `sandbox_init` & EndpointSecurity Roadmap (GAP-50)

* **Legacy Technical Debt Remediation:**
  Historically, macOS LaunchDaemons were frequently wrapped using the internal debugging utility `/usr/bin/sandbox-exec -f <profile>.sb <binary>`. Because Apple deprecated `/usr/bin/sandbox-exec` in OS X 10.8 (2012), modern enterprise architectures mandate native in-process sandbox application.
* **In-Process Seatbelt Initialization (`crates/enclave-core/src/runtime.rs`):**
  The enclave daemons support direct in-process sandboxing using Darwin's native `sandbox_init(profile, flags, errorbuf)` C ABI (`libsystem_sandbox.dylib`). When invoked with `--sandbox-profile /opt/enterprise/enclave/sandbox/<suffix>.sb`, the daemon applies the Seatbelt profile directly to its address space before starting the async runtime, eliminating dependencies on external wrapper binaries.
* **Apple EndpointSecurity (`EndpointSecurity.framework`) Roadmap:**
  To provide enterprise-grade, kernel-level telemetry and tamper detection:
  1. **System Extension Integration:** Develop an enterprise-signed Apple System Extension (`EndpointSecurity` client via `es_new_client`).
  2. **Real-Time Syscall Auditing:** Intercept and validate file access events (`ES_EVENT_TYPE_AUTH_OPEN`), process executions (`ES_EVENT_TYPE_AUTH_EXEC`), and socket binds (`ES_EVENT_TYPE_NOTIFY_BIND`), enforcing that only designated daemons access `/var/run/enclave/*.sock` and `/var/log/enclave/*-audit.jsonl`.
  3. **Zero-Trust Process Integrity:** Detect and immediately terminate unauthorized third-party processes attempting to attach or inspect enclave memory spaces.

### 2.0.2 Post-Quantum Cryptography (PQC) & HNDL Defense Roadmap (GAP-62)

* **Harvest-Now-Decrypt-Later (HNDL) Threat Surface:**
  Enterprise compliance mandates 7–10 year regulatory retention for zero-knowledge audit logs and customer records. Wire payloads intercepted today risk retrospective decryption once Cryptanalytically Relevant Quantum Computers (CRQCs) break classical discrete logarithm and elliptic curve cryptography via Shor's algorithm ($O(n^3)$).
* **Hybrid Defense-in-Depth Cryptosystem (`crates/enclave-crypto/src/pqc.rs`):**
  * **Hybrid KEM (X25519 + ML-KEM-768):** Ephemeral wire transports combine classical X25519 DH with NIST FIPS 203 Module-Lattice Key Encapsulation (ML-KEM-768). The shared secret is derived using an HKDF-SHA256 combiner, guaranteeing confidentiality if *either* primitive remains unbroken.
  * **Dual-Signature Scheme (Ed25519 + ML-DSA-65):** Long-lived ZK audit roots and TUF anchors are dual-signed using classical Ed25519 and NIST FIPS 204 Module-Lattice Digital Signatures (ML-DSA-65). Verification fails closed if either signature component fails.
  * **Anti-Downgrade Protocol:** Negotiated wire handshakes strictly reject downgrade attempts to `ClassicalOnly`.
  * **Detailed Specification:** See [`docs/FEATURE_PQC_MIGRATION_ROADMAP.md`](FEATURE_PQC_MIGRATION_ROADMAP.md) for full production readiness review, SLO tables, and runbooks `RB-218` / `RB-219`.

### 2.1 Attacker Personas & Capabilities

| Threat Persona                                    | Profile & Capabilities                                                                             | Typical Attack Path                                                                                                                 |
|---------------------------------------------------|----------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------|
| **T1: Rogue Co-Located Process**                  | Unprivileged local process installed via malicious dependency (npm/PyPI/Homebrew) running as user. | Attempts to read agent memory (`vm_read`), inspect local SQLite/cache files, or sniff loopback traffic.                             |
| **T2: Adversarial Tool / Prompt Injection**       | Attacker crafting malicious prompt or tainted database payload (Indirect Prompt Injection).        | Triggers tool execution (e.g. `query_customer_db`) with payload instructing the model to exfiltrate PII via HTTP GET/DNS tunneling. |
| **T3: Supply-Chain Compromised Agent Dependency** | Compromised Python agent library (e.g. malicious updates to helper tools).                         | Modifies agent internal logic to bypass local filters, connect directly to foreign C2 IP, or access raw files.                      |
| **T4: Accidental Developer Misconfiguration**     | Well-intentioned developer executing unvetted local scripts or disabling firewall rules.           | Disables authentication tokens or points local database tools at live customer production databases without redaction.              |

### 2.2 STRIDE Threat Assessment Matrix

| Threat Category            | Local Agentic Attack Vector                                                            | Countermeasure & Control Plane Defense                                                                                  | Residual Risk                                                      |
|----------------------------|----------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------|--------------------------------------------------------------------|
| **Spoofing**               | Rogue script impersonates the legitimate agent to request customer data.               | **macOS Code Signing Attestation (`csreq`) + SPIFFE SVID.** Hardware Secure Enclave signs DPoP proof.                   | Negligible (Hardware-backed key cannot leave SEP).                 |
| **Tampering**              | Developer or malware alters local OPA Rego policy files to bypass rules.               | **TUF / Cosign Cryptographic Bundle Signing.** Policy engine verifies ECDSA signature against corporate root CA.        | Zero (Tampered bundle fails signature check; daemon fails closed). |
| **Repudiation**            | Agent executes unauthorized deletion or dump of customer table without log.            | **Immutable Structured JSON Audit Log** to append-only macOS log stream; hashes chained to local Secure Enclave.        | Minimal (tamper-evident audit trail).                              |
| **Information Disclosure** | LLM context window exposes unmasked SSNs/emails in crash dumps or chat history.        | **Inline DLP Tokenization Vault** substitutes PII with synthetic UUIDs *before* context ingestion. Memory-only buffers. | Bound to synthetic token reversal table in encrypted memory.       |
| **Denial of Service**      | Model loops uncontrollably executing high-cost queries, draining local CPU/battery.    | **Envoy Circuit Breaking & OPA Differential Rate Budgets.** Hard timeout at 2000ms per tool call; max 10 calls/min.     | Contained to worker thread shutdown.                               |
| **Elevation of Privilege** | Agent uses shell execution tool or file read tool to access `~/.ssh` or `/etc/passwd`. | **MCP Strict Tool Whitelist + App Sandbox.** Disallow arbitrary shell execution; path traversal validation in Rego.     | Zero (Kernel sandboxing disallows unauthorized paths).             |

### 2.3 Non-Negotiable Security Invariants

The architecture guarantees five mathematical invariants. Any state transition violating these invariants triggers immediate process termination:

$$\text{Invariant 1: } \forall p \in \text{Processes}_{\text{Agent}}, \quad \text{EgressNetworkInterfaces}(p) \subseteq \{\text{lo0}\}$$
$$\text{Invariant 2: } \forall t \in \text{ToolInvocations}, \quad \text{AuthStatus}(t) = \text{ALLOW} \iff \text{ValidSignature}(\text{PolicyBundle}) \land \text{OPA}(\text{Input}) = \text{True}$$
$$\text{Invariant 3: } \forall d \in \text{LLMContextWindow}, \quad \text{DetectPII}(d) = \emptyset$$
$$\text{Invariant 4: } \forall k \in \text{PrivateKey}_{\text{Identity}}, \quad \text{StorageLocation}(k) = \text{AppleSecureEnclave}$$
$$\text{Invariant 5: } \forall b \in \text{AgentBinaries}, \quad \text{VerifyCodeSign}(b, \text{TeamID}_{\text{Corp}}) = \text{Valid}$$

> **`v3.0` dispositions (`CORE-V3` traceability matrix, `F-004`):** Invariant 1 is `[AMENDED-BY FS-702 §2.4]` (only `UID 702` holds network sockets); Invariant 2 is retained with Cedar ∧ Biscuit replacing OPA; Invariant 3 is `[AMENDED-BY FS-703 §2.4, FS-704 §2.4]` (bounded human detokenization; `≤ 12,000 mb`/24h enum declassification); Invariants 4–5 are retained. **The Python simulation does not satisfy Invariant 4** — its DPoP and SPIRE keys are software keys labelled `SIMULATION_ONLY`.

---

## 3. Centralized GitOps Repository & Policy Distribution

Local security is only as dependable as the freshness, integrity, and tamper-resistance of its policy source. We implement an enterprise GitOps pipeline where all authorization rules, redaction regexes, and tool schemas are managed in a single cryptographically signed repository.

```
+-----------------------------------------------------------------------------------------+
|                               Centralized Policy Repository                             |
|                           (git@github.com:enterprise/pii-governance)                    |
+-----------------------------------------------------------------------------------------+
                                             |
                   CI/CD Gate: OPA Test, Lint, Security Validation
                                             |
                                             v
                           +-----------------------------------+
                           |  Sigstore / Cosign Bundle Signer  |
                           |  - Signs tarball with Corporate CA|
                           |  - Generates Rekor Transparency Log|
                           +-----------------------------------+
                                             |
                                             | HTTPS (Signed Bundle Delivery)
                                             v
+-----------------------------------------------------------------------------------------+
|                         Local Developer Laptop (macOS M1+)                              |
|                                                                                         |
|   +---------------------------------------------------------------------------------+   |
|   | sync-agent Daemon (launchd managed: com.enterprise.pii.sync)                    |   |
|   | 1. Polls Central Repository (Jittered exponential backoff: 300s +/- 45s)        |   |
|   | 2. Verifies Cosign Signature & TUF Timestamp Metadata                           |   |
|   | 3. Monotonic Sequence Check: Reject Version <= Current Local Version            |   |
|   | 4. Atomic Extraction to `/opt/enterprise/enclave/policies/`                     |   |
|   | 5. SIGHUP / gRPC Reload to Local OPA Daemon                                      |   |
|   +---------------------------------------------------------------------------------+   |
+-----------------------------------------------------------------------------------------+
```

### 3.1 Policy Bundle Architecture & TUF/Sigstore Verification

Policies are packaged as compressed tarballs (`bundle.tar.gz`) containing:

1. `manifest.json`: Bundle version, monotonic generation counter, hash table of all files.
2. `*.rego`: Production declarative policies.
3. `data.json`: Static reference data (e.g., approved tool definitions, data classification hierarchies).
4. `bundle.tar.gz.sig`: Hardware-signed detached cryptographic signature.
5. `bundle.tar.gz.cert`: X.509 certificate linking signature to the corporate Sigstore identity.

#### Local Verification Invariant

Before replacing the active policy set, the local `sync-agent` invokes the cryptographic verification engine:

```bash
cosign verify-blob \
  --certificate-identity "https://github.com/enterprise/pii-governance/.github/workflows/release.yml@refs/heads/main" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  --cert "/opt/enterprise/enclave/certs/bundle.tar.gz.cert" \
  --signature "/opt/enterprise/enclave/policies/bundle.tar.gz.sig" \
  "/opt/enterprise/enclave/policies/bundle.tar.gz"
```

### 3.2 Dynamic Local Synchronization Daemon (`sync-agent`)

The `sync-agent` runs as a macOS `launchd` system daemon under a dedicated unprivileged user `_piisync`. It implements:

* **Jittered Backoff:** Periodic pull every 300 seconds with uniform random jitter $J \sim \mathcal{U}(-45, 45)$ seconds to prevent thundering herd against internal artifact storage.
* **Conditional HTTP Egress:** The `sync-agent` is granted an exception in `pf.conf` to communicate *strictly* with the corporate artifact repository over port 443 with pinned TLS 1.3 certificates.
* **Atomic Swap:** Policies are extracted into a timestamped staging directory (`/opt/enterprise/enclave/policies/staging_<timestamp>`). Once integrity is validated, an atomic symlink swap updates `/opt/enterprise/enclave/policies/current`.
* **Zero-Downtime Reload:** The daemon (running as `root`, never as `_llmagent`) emits a SIGHUP or uses OPA's bundle API to hot-reload. OPA's REST API MUST NOT be reachable by the agent: `gateway/pf-rules.conf` denies `_llmagent` → `127.0.0.1:8181`/`9191` (`F-010`), and production deployments SHOULD bind the REST API to a `0600` UNIX socket.

### 3.3 Atomic Rollouts, Monotonic Replay Protection & Air-Gap Fallback

* **Monotonic Sequence Enforcement:** Every bundle contains a strictly increasing integer sequence number `metadata.sequence_number`. If an attacker or a stale network cache presents a bundle where $\text{Seq}_{\text{new}} \le \text{Seq}_{\text{active}}$, the bundle is dropped and an anomaly alert is registered.
* **Air-Gap / Offline Mode:** Developers frequently code on flights or disconnected environments. When network connectivity fails:
  1. The system preserves the last verified valid bundle indefinitely up to a Hard Time-To-Live (TTL) of **168 hours (7 days)**.
  2. If the active bundle expires beyond 7 days without checking into the central repository, OPA enters **Safe-Fail Lockdown**: all tools accessing customer data are locked; only local syntax/offline tools remain authorized.

---

## 4. OPA / Rego Policy-as-Code Engine

> **[SUPERSEDED BY FS-704 / ADR-008 — v1.0-Legacy only].** `v3.0` evaluates `Cedar.Allow ∧ Biscuit.Allow` in-process; Rego is retained solely for this prototype.

The Open Policy Agent (OPA) daemon executes locally as a native Apple Silicon binary compiled for `darwin/arm64`. It acts as the centralized Policy Decision Point (PDP).

### 4.1 In-Memory Daemon Topology & Endpoints

* **Loopback Binding:** Listens on `127.0.0.1:9191` (gRPC for Envoy `ext_authz`) and an administrative REST API (`127.0.0.1:8181` in the prototype). **Neither port is reachable from GID `_llmagent`** (`pf` allows only `8443` and `11434`); the REST API accepts unauthenticated `PUT /v1/policies` and therefore MUST be firewalled or moved to a `0600` UNIX socket.
* **Resource Quotas:** Memory bound capped at 256MB via macOS `launchd` resource limits (`SoftResourceLimits` / `HardResourceLimits`).
* **Evaluation Latency:** In-memory index guarantees $p99 < 3.2\text{ms}$ per decision.

### 4.2 Comprehensive Authorization Policy (`policies/mcp_authz.rego`)

The canonical policy is [`policies/mcp_authz.rego`](../examples/executive-poc/policies/mcp_authz.rego), tested by [`policies/mcp_authz_test.rego`](../examples/executive-poc/policies/mcp_authz_test.rego) (`opa test policies/ -v`, check `V08`). It is **fail-closed** (`F-037`):

* **Unified tool names.** `execute_customer_query` (the name used in earlier revisions of this section) and `query_customer_db` are aliases that resolve to one canonical tool and one validator. Unregistered tools are denied — even for `sre_incident_commander`, whose `"*"` entitlement covers registered tools only.
* **No catch-all.** Every registered tool has an explicit parameter validator with an exact key allowlist. The earlier `verify_parameter_safety if { input.resource.tool_name != … }` rule, which passed every other tool unchecked, is removed.
* **No substring SQL checks.** Rego cannot parse SQL; `contains(sql, "select *")` was bypassed by `SELECT  *` and blocked benign columns such as `updated_at`. The caller MUST attach the verdict of the recursive-descent AST guard (`mcp/sql_guard.py`), bound to the exact query text by SHA-256:

```rego
verify_parameter_safety if {
 canonical_tool == "query_customer_db"
 p := input.resource.parameters
 param_keys == {"query", "max_records"}
 p.max_records >= 1
 p.max_records <= 50
 v := input.resource.sql_ast_verdict
 v.valid == true
 v.statement_kind == "select"
 v.limit <= p.max_records
 v.sql_sha256 == crypto.sha256(p.query)
}
```

* **Parameterised identity.** The SPIFFE trust domain and Apple Team ID come from `data.config.trust_domain` / `data.config.team_id` (defaults `corporate.internal` / `ABC123XYZ0`), consistent with `identity/spire-agent-macos.conf` and `MCPMAC_TRUST_DOMAIN` (`F-039`).

### 4.3 PII Detection, Classification & Redaction Rules (`policies/pii_guard.rego`)

The canonical policy is [`policies/pii_guard.rego`](../examples/executive-poc/policies/pii_guard.rego) (tests: `policies/pii_guard_test.rego`). Changes from earlier revisions:

* **ADR-007 Level-4 custody** (supersedes `ADR-004`, remediates `F-002`): PANs and credentials are irreversibly erased in every profile; SSNs/PHI are erased by default and always in `L1`, and are reversibly tokenized only in `L2`/`L3` under an explicit `Custody::ReversibleTokenize` grant. The `v1.0` simulation has no HPKE vault and therefore always erases (`[REDACTED_SSN_C4]`, `[REDACTED_PAN_C4]`).
* **RE2-compatible detection.** OPA uses Go RE2, which has no look-around; the earlier `\b(?!000|666|9\d{2})…` pattern could not be evaluated. Detection now covers hyphenated, space-separated and bare 9-digit SSNs and separated 13–19-digit card numbers.
* **No compliance claim.** Regex detection does not satisfy HIPAA Safe Harbor's 18-identifier standard.

### 4.4 Differential Privacy & Budget Accounting

> **[SUPERSEDED BY FS-704 §3.3 — CORE-V1-R06].** The Laplace budget below is replaced in `v3.0` by the `12,000 mb` 24h `EntityKey` QIF budget and the `global_unstructured_c3_c4_24h_pool`.

To prevent indirect extraction of customer identities through repeated micro-queries (e.g. querying demographic distributions to de-anonymize a user), the local OPA engine tracks a sliding-window Privacy Budget ($\epsilon, \delta$):

* Every query deducting from customer data sources is billed $\epsilon_i = 0.1$.
* Max developer session budget is capped at $\epsilon_{\text{total}} = 2.0$ per 8-hour shift.
* When $\sum \epsilon_i > 2.0$, queries are automatically rejected or must accept Laplacian noise addition to numeric aggregates.

---

## 5. Model Context Protocol (MCP) Hardening & OAuth 2.1

The Model Context Protocol (MCP) opens bidirectional JSON-RPC communication between the host agent and tools. Without hardening, MCP is an open vector for prompt injection, arbitrary command execution, and mass data extraction.

### 5.1 The MCP Security Problem & Attack Vectors

1. **Privilege Escalation via Hidden Tool Features:** An MCP server exposing a `query_db` tool might also inadvertently expose administrative endpoints or raw shell execution.
2. **Context Poisoning:** Tool output is directly serialized into the LLM prompt. If a tool returns malicious instructions disguised as data, the model can be tricked into executing unintended tools (Confused Deputy Problem).
3. **Token Replay Across Processes:** If an authorization token is stored in cleartext environment variables or files, any local malware can read and reuse it.

```
+-------------------------------------------------------------------------------------------------------+
|                                  MCP Hardening Architecture Sequence                                  |
+-------------------------------------------------------------------------------------------------------+
 Agent Host                     MCP Auth Proxy               OPA Engine              Protected Tool
     |                                |                           |                        |
     | 1. tools/call (Unauth)         |                           |                        |
     |------------------------------->|                           |                        |
     |                                |                           |                        |
     | 2. 401 Unauthorized            |                           |                        |
     |    (PRM + Nonce + DPoP Req)    |                           |                        |
     |<-------------------------------|                           |                        |
     |                                |                           |                        |
     | 3. tools/call + DPoP Proof     |                           |                        |
     |    + Bearer Token (Secure Enc) |                           |                        |
     |------------------------------->|                           |                        |
     |                                | 4. Validate Token & DPoP  |                        |
     |                                |    Query Authz Policy     |                        |
     |                                |-------------------------->|                        |
     |                                |                           |                        |
     |                                | 5. Decision: ALLOW        |                        |
     |                                |<--------------------------|                        |
     |                                |                                                    |
     |                                | 6. Forward Authorized Request                      |
     |                                |--------------------------------------------------->|
     |                                |                                                    |
     |                                | 7. Raw Result (Contains Plaintext PII)             |
     |                                |<---------------------------------------------------|
     |                                |                                                    |
     |                                | 8. Inline DLP Scrub / Tokenize                     |
     |                                |    [John Doe -> CUST_UUID_a1f9]                    |
     |                                |                                                    |
     | 9. Return Masked Response      |                                                    |
     |<-------------------------------|                                                    |
```

### 5.2 OAuth 2.1 with DPoP via Apple Secure Enclave

To achieve zero-token-replay capability, the architecture implements **RFC 9449 (OAuth 2.0 Demonstrating Proof-of-Possession at the Application Layer - DPoP)**:

1. **Key Generation in SEP:** Upon launch, the agent requests the macOS Security Framework to generate an asymmetric ECDSA P-256 keypair inside the Secure Enclave:
   * Private key attribute: `kSecAccessControlPrivateKeyUsage`
   * Exportability: **Physically non-exportable**.
2. **DPoP Header Construction:** For every tool invocation, the agent constructs an ephemeral signed JWT header containing:
   * `htm`: HTTP / RPC method (`POST`).
   * `htu`: Tool target URI (`mcp://localhost/tools/query_customer_db`).
   * `iat`: Current epoch timestamp (validity strictly bounded to $\pm 30$ seconds).
   * `jti`: Unique UUID v4 nonce preventing replay.
3. **Verification:** The MCP Auth Proxy validates the signature using the public key advertised in the token handshake. Even if an attacker dumps the process memory of the agent and steals the Bearer Token, the token is **completely useless** without the SEP hardware private key.

### 5.3 Inline Zero-PII Enclave: Tokenization / Detokenization Vault

As a GDPR Art. 4(5) pseudonymisation and Art. 25 data-minimisation control (not HIPAA Safe Harbor de-identification; pseudonymised data remains personal data):

* **In-Memory Pseudonymization Vault:** When a tool returns structured customer records, the MCP proxy classifies every column (erase / tokenize / generalize / pass; unknown columns fail closed to `[REDACTED_UNCLASSIFIED]`) and tokenizes `C3` values with a **128-bit keyed `HMAC-SHA256` tag under a per-session 256-bit ephemeral key** (`F-006`; unsalted `SHA-256[:8]` was invertible by brute force).
* **Bi-directional Mapping Table:**
  $$\text{Plaintext: } \{\text{Name: "Alice Smith", Email: "alice@example.com", SSN: "123-45-6789"}\}$$
  $$\Downarrow \text{ (Tokenization)}$$
  $$\text{Masked: } \{\text{Name: "CUST\_NAME\_<32 hex>", Email: "CUST\_EMAIL\_<32 hex>", SSN: "[REDACTED\_SSN\_C4]"}\}$$
* **Isolation of Reverse Table:** The mapping holds `C3` values only (never `C4`), with bounded TTL eviction (default `900 s`, `≤ 10,000` entries). Target design: `mlock()`-pinned memory; the Python simulation cannot pin memory.
* **Detokenization on Egress:** Only when the user explicitly triggers an approved write action (e.g. sending an email via an external authenticated gateway) does the gateway substitute `CUST_EMAIL_4a71` back to `alice@example.com` at the egress boundary.

### 5.4 Tool Schema Enforcing & SQL AST Inspection

Tools must declare immutable JSON schemas. The MCP Auth Proxy executes schema validation prior to forwarding requests:

* **Strict Type Checking:** If an integer account ID receives a string or SQL escape character (`' OR 1=1`), the proxy aborts the request before invocation.
* **AST Parse Tree Verification:** SQL queries are parsed by the recursive-descent guard in [`mcp/sql_guard.py`](../examples/executive-poc/mcp/sql_guard.py) (`sqlparser-rs` in `v3.0`), and the mock database additionally enforces `PRAGMA query_only` plus a `sqlite3` `set_authorizer` read-only callback (checks `V11`, `V12`). The AST guarantees that:
  * Statement type is strictly `SelectStatement`.
  * No sub-selects invoke administrative functions (`pg_sleep`, `load_file`, `sys_eval`).
  * Projection list contains explicitly enumerated, allowlisted columns; wildcard star (`*`) and `table.*` selections are rejected.
  * Exactly one statement; no comments, `UNION`/`INTERSECT`/`EXCEPT`, `ATTACH`, `PRAGMA`, JOINs or sub-queries.
  * `LIMIT` is present and `≤ min(max_records, 50)` (injected when absent). Column names such as `updated_at` or `deleted_at` are ordinary identifiers and are accepted.

---

## 6. Local API Gateway & Kernel-Level Network Isolation

The developer workstation must be partitioned to prevent data exfiltration. We enforce a two-tier perimeter: **Layer 4 Kernel Firewall (`pf`)** and **Layer 7 Local API Gateway (`Envoy`)**.

```
+-------------------------------------------------------------------------------------------------------+
|                                  Dual-Layer Local Isolation Boundary                                  |
+-------------------------------------------------------------------------------------------------------+

+-------------------------------------------------------------------------------------------------------+
|                                    macOS Kernel (XNU) Layer 4                                         |
|                                                                                                       |
|   Packet Filter (pf.conf Anchor: com.enterprise.llm.isolation)                                        |
|                                                                                                       |
|   Rule 1: Block all outbound traffic from GID _llmagent to any external interface                      |
|           [DROP] GID _llmagent -> {en0, en1, pdp_ip0, awdl0, utun*}                                   |
|                                                                                                       |
|   Rule 2: Allow loopback communication only from GID _llmagent to 127.0.0.1                            |
|           [PASS] GID _llmagent -> 127.0.0.1 / ::1 :{8443, 11434} ONLY (pass-quick precedes block)      |
+-------------------------------------------------------------------------------------------------------+
                                                   |
                                                   v Loopback Only (mTLS)
+-------------------------------------------------------------------------------------------------------+
|                                   Envoy Local Gateway (Layer 7)                                       |
|                                         127.0.0.1:8443                                                |
|                                                                                                       |
|   - mTLS Termination (Ephemeral Local CA)                                                             |
|   - Envoy ext_authz Filter (gRPC to OPA on 127.0.0.1:9191)                                            |
|   - Circuit Breakers: Max 50 concurrent connections, 2000ms timeout                                   |
|   - Local Access Logging: Structured JSON, PII Redaction Filter                                       |
+-------------------------------------------------------------------------------------------------------+
                                                   |
                                                   v
+-------------------------------------------------------------------------------------------------------+
|                             Local Inference Engine (llama.cpp / Ollama)                               |
|                                         127.0.0.1:11434                                               |
|                             Bound strictly to loopback; Telemetry Disabled                            |
+-------------------------------------------------------------------------------------------------------+
```

### 6.1 Defense-in-Depth Network Model

* **Kernel Space:** Even if the Python runtime is compromised via a zero-day exploit, arbitrary C code executing within the process inherits GID `_llmagent`. The macOS kernel drops any TCP SYN packet addressed to an internet IP address before it leaves the socket layer.
* **User Space:** All egress requests are directed to `https://127.0.0.1:8443`. Envoy executes L7 protocol inspection, schema validation, rate-limiting, and authorization before forwarding calls to local inference engines or MCP tool servers.

### 6.2 macOS Packet Filter (`pf.conf`) Anchor Configuration

File: `/etc/pf.anchors/com.enterprise.llm.isolation`

`pf` evaluates `quick` rules first-match. The narrow loopback `pass … quick` rules therefore MUST precede the default-deny `block … quick` rules; the earlier revision of this section blocked first (blackholing `lo0`) and allowed `_llmagent` to reach OPA's admin port `8181` (`F-010`). The block below is identical to [`gateway/pf-rules.conf`](../examples/executive-poc/gateway/pf-rules.conf) and is enforced by checks `V05`/`V06`:

```pf
loopback_if = "lo0"
llm_group   = "_llmagent"

# BEGIN MCPMAC PF RULES
# 1. Permit ONLY Envoy mTLS ingress (8443) and local inference (11434) on lo0 — NEVER 8181, 9191, 8080 or Envoy admin.
pass out quick on $loopback_if inet  proto tcp from any to 127.0.0.1 port { 8443, 11434 } group $llm_group keep state
pass out quick on $loopback_if inet6 proto tcp from any to ::1       port { 8443, 11434 } group $llm_group keep state
# 2. Default-deny ALL other IPv4 and IPv6 egress (TCP, UDP, ICMP, ICMPv6) from the agent group.
block drop out log (all) quick inet  from any to any group $llm_group
block drop out log (all) quick inet6 from any to any group $llm_group
# END MCPMAC PF RULES
```

#### Activating and Locking the Anchor

Validate, then activate (operator step — `bootstrap-laptop.sh` does not load rules). A `com.enterprise.pfwatch` re-enforcement daemon is a target design and is **not** shipped in this repository:

```bash
sudo pfctl -vnf /etc/pf.anchors/com.enterprise.llm.isolation
sudo pfctl -a com.enterprise.llm.isolation -f /etc/pf.anchors/com.enterprise.llm.isolation
sudo pfctl -E
```

### 6.3 Envoy Gateway Local Configuration (`gateway/envoy-local.yaml`)

Excerpt (canonical file: [`gateway/envoy-local.yaml`](../examples/executive-poc/gateway/envoy-local.yaml)). The admin interface is bound to a `0600` UNIX socket, never TCP `9901` (`F-010`):

```yaml
admin:
  address:
    pipe:
      path: /var/run/enclave/envoy-admin.sock
      mode: 384  # 0600
static_resources:
  listeners:
  - name: local_agent_listener
    address:
      socket_address:
        address: 127.0.0.1
        port_value: 8443
    filter_chains:
    - transport_socket:
        name: envoy.transport_sockets.tls
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext
          common_tls_context:
            tls_certificates:
            - certificate_chain:
                filename: "/opt/enterprise/enclave/certs/gateway.crt"
              private_key:
                filename: "/opt/enterprise/enclave/certs/gateway.key"
            validation_context:
              trusted_ca:
                filename: "/opt/enterprise/enclave/certs/local-ca.crt"
              require_client_certificate: true
      filters:
      - name: envoy.filters.network.http_connection_manager
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
          stat_prefix: agent_egress
          codec_type: AUTO
          route_config:
            name: local_route
            virtual_hosts:
            - name: local_inference
              domains: ["*"]
              routes:
              - match:
                  prefix: "/v1/chat/completions"
                route:
                  cluster: local_llm_inference
                  timeout: 30s
              - match:
                  prefix: "/mcp/"
                route:
                  cluster: mcp_tool_service
                  timeout: 5s
          http_filters:
          # 1. External Authorization Filter (OPA gRPC Check)
          - name: envoy.filters.http.ext_authz
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthz
              grpc_service:
                envoy_grpc:
                  cluster_name: opa_grpc_cluster
                timeout: 0.25s
              transport_api_version: V3
              with_request_body:
                max_request_bytes: 65536
                pack_as_bytes: true
              status_on_error:
                code: 403
          # 2. Local Rate Limiting
          - name: envoy.filters.http.local_ratelimit
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.filters.http.local_ratelimit.v3.LocalRateLimit
              stat_prefix: http_local_rate_limiter
              token_bucket:
                max_tokens: 20
                tokens_per_fill: 10
                fill_interval: 1s
              filter_enabled:
                runtime_key: local_rate_limit_enabled
                default_value:
                  numerator: 100
                  denominator: HUNDRED
              filter_enforced:
                runtime_key: local_rate_limit_enforced
                default_value:
                  numerator: 100
                  denominator: HUNDRED
          - name: envoy.filters.http.router
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router

  clusters:
  - name: opa_grpc_cluster
    type: STATIC
    connect_timeout: 0.1s
    http2_protocol_options: {}
    load_assignment:
      cluster_name: opa_grpc_cluster
      endpoints:
      - lb_endpoints:
        - endpoint:
            address:
              socket_address:
                address: 127.0.0.1
                port_value: 9191

  - name: local_llm_inference
    type: STATIC
    connect_timeout: 0.5s
    circuit_breakers:
      thresholds:
      - priority: DEFAULT
        max_connections: 10
        max_pending_requests: 5
        max_requests: 10
    load_assignment:
      cluster_name: local_llm_inference
      endpoints:
      - lb_endpoints:
        - endpoint:
            address:
              socket_address:
                address: 127.0.0.1
                port_value: 11434

  - name: mcp_tool_service
    type: STATIC
    connect_timeout: 0.2s
    circuit_breakers:
      thresholds:
      - priority: DEFAULT
        max_connections: 20
        max_requests: 20
    load_assignment:
      cluster_name: mcp_tool_service
      endpoints:
      - lb_endpoints:
        - endpoint:
            address:
              socket_address:
                address: 127.0.0.1
                port_value: 8080
```

### 6.4 Mutual TLS (mTLS) with Ephemeral Machine-Local Root CA

To ensure that rogue unprivileged local processes cannot connect to Envoy or forge requests:

* An ephemeral Root Certificate Authority is generated during local workstation bootstrap and stored in the **macOS System Keychain** with ACLs permitting access only to `root`.
* The Agent Host must present a client certificate signed by this CA.
* Certificate lifespans are capped at **24 hours**, forcing daily re-attestation of developer workstation health.

---

## 7. Agentic Workload Identity on macOS (Apple Silicon M1+)

In a cloud-native Kubernetes environment, SPIFFE/SPIRE issues identities via node attestors (AWS IID, GCP IAM). On macOS, we pioneer a **Hardware-Anchored macOS Workload Attestor** that binds SPIFFE Verifiable Identity Documents (SVIDs) directly to the Apple Silicon hardware and codesigning receipts.

```
+---------------------------------------------------------------------------------------------------+
|                                 macOS Workload Attestation Flow                                   |
+---------------------------------------------------------------------------------------------------+

     Agent Process                                                  SPIRE macOS Agent
  (PID: 4120, GID: 701)                                            (launchd: root)
           |                                                              |
           | 1. Connect over Unix Domain Socket (/var/run/spire/agent.sock)|
           |------------------------------------------------------------->|
           |                                                              | 2. Inspect Peer Credentials:
           |                                                              |    - getsockopt(LOCAL_PEERTOKEN)
           |                                                              |    - audit_token_t inspection
           |                                                              |
           |                                                              | 3. Code Signature Attestation:
           |                                                              |    SecCodeCopyGuestWithAttributes
           |                                                              |    Verify Team ID: ABC123XYZ0
           |                                                              |    Verify Hardened Runtime
           |                                                              |
           |                                                              | 4. Hardware Attestation:
           |                                                              |    Verify Apple SEP Key Handle
           |                                                              |    (kSecAttrTokenIDSecureEnclave)
           |                                                              |
           |                                                              | 5. Policy Check:
           |                                                              |    Match PID binary to SPIFFE ID
           |                                                              |
           | 6. Return X.509 SVID (Valid 1 hour)                          |
           |<-------------------------------------------------------------|
           |
```

### 7.1 SPIFFE/SPIRE Architecture on Darwin

* The SPIRE Agent runs as a privileged local daemon listening on a protected Unix Domain Socket (`/var/run/spire/agent.sock`, permissions `0660`, owner `root:_llmagent`).
* Workloads do not use long-lived API keys. All identities are ephemeral SPIFFE SVIDs minted with a 1-hour time-to-live.

### 7.2 Secure Enclave Processor (SEP) Hardware-Backed Key Attestation

Apple Silicon chips (M1 through M4) feature a dedicated Secure Enclave Processor (SEP) running its own secure OS (sepOS) with hardware cryptographic accelerators:

1. When generating the agent's identity key, the system calls Apple `Security.framework` requesting key generation inside the SEP:

   ```swift
   let access = SecAccessControlCreateWithFlags(
       kCFAllocatorDefault,
       kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
       .privateKeyUsage,
       nil
   )
   let attributes: [String: Any] = [
       kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
       kSecAttrKeySizeInBits as String: 256,
       kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
       kSecPrivateKeyAttrs as String: [
           kSecAttrIsPermanent as String: true,
           kSecAttrAccessControl as String: access!
       ]
   ]
   ```

2. The private key never leaves the hardware boundary of the SEP.
3. Signature operations occur inside the hardware enclave, so rogue local software cannot read the private key (it may still *request* signatures if it can reach the key's access control — see `FS-703`). **Simulation note:** `identity/dpop.py` uses `SIMULATION_ONLY` software keys.

### 7.3 Binary Code Signing & Designated Requirement Attestation (`csreq`)

The SPIRE macOS Attestor uses Apple's native Security Framework APIs to inspect the client process:

1. Retrieves the kernel `audit_token_t` via `getsockopt(fd, SOL_LOCAL, LOCAL_PEERTOKEN)` — never a bare PID, which is reusable and enables TOCTOU races (`F-028`, `ADR-010`).
2. Passes the audit token to `SecCodeCopyGuestWithAttributes` (`kSecGuestAttributeAudit`) so the code object evaluated is exactly the connected process.
3. Evaluates the process against a **Designated Requirement (csreq)**:

   ```
   anchor apple generic and 
   certificate leaf[subject.OU] = "ABC123XYZ0" and 
   identifier "com.enterprise.agent.runner" and 
   info[HardenedRuntime] = true
   ```

4. If a developer attempts to attach `lldb` without authorization or replaces the binary with an unsigned version, the Designated Requirement fails and identity tokens are revoked instantaneously.

### 7.4 Ephemeral X.509 SVID Minting & Lifecycle Management

* The minted SVID contains the SPIFFE ID:
  `spiffe://corporate.internal/ns/developer/workload/code-assistant/user/<developer_uid>`
* The SVID is utilized for mutual TLS authentication when establishing connections to the Envoy Local API Gateway.
* Rotation occurs automatically at 50% lifetime (every 30 minutes) with zero connection drop via Envoy's dynamic Secret Discovery Service (SDS).

---

## 8. Enterprise SRE Operationalization, Reliability & Fault Tolerance

To operate at mission-critical Production SRE standards, the local architecture must satisfy strict reliability targets, transparent observability without PII contamination, and automated failure handling.

### 8.1 Service Level Objectives (SLOs) & Service Level Indicators (SLIs)

| Objective / Capability         | Service Level Indicator (SLI)                                              | SLO Target                                 | Error Budget (Monthly)                 |
|--------------------------------|----------------------------------------------------------------------------|--------------------------------------------|----------------------------------------|
| **Policy Evaluation Latency**  | Local OPA decision time via gRPC (`ext_authz`).                            | $p95 < 2.0\text{ms}$, $p99 < 5.0\text{ms}$ | 0.05% of calls $> 5\text{ms}$          |
| **PII Zero-Leakage Invariant** | Scans of local log files, traces, and crash dumps containing unmasked PII. | **0 violations** ($100\%$ zero-leakage)    | **0 tolerance** (Instant SEV-0)        |
| **Local Gateway Availability** | Successful localhost HTTP 200/403 responses over total attempts.           | $99.95\%$ uptime                           | $\approx 21.6\text{ minutes}$ downtime |
| **Policy Freshness**           | Delta between Git repository release and local active bundle version.      | $< 15\text{ minutes}$                      | Max 2 hours out-of-sync                |
| **Inference Overhead**         | Gateway + Redaction filter added latency over bare metal inference.        | $< 12\text{ms}$ per request                | $< 25\text{ms}$ degradation            |

### 8.2 Failure Modes and Effects Analysis (FMEA)

```
+-------------------------------------------------------------------------------------------------------------------------+
|                                        Failure Modes & Effects Analysis (FMEA) Matrix                                   |
+-----------------------------+----------------------+----------+---------------------------------------------------------+
| Failure Mode                | Impact               | Severity | Mitigation & SRE Recovery Strategy                      |
+-----------------------------+----------------------+----------+---------------------------------------------------------+
| OPA Daemon Crash            | Gateway cannot auth  | CRITICAL | Envoy fail-closed (HTTP 503). launchd respawns OPA in    |
|                             | tool calls.          |          | < 500ms. Error budget alerted if > 3 crashes / hour.    |
|                             |                      |          |                                                         |
| Corrupted Policy Bundle     | Signature mismatch   | HIGH     | sync-agent rejects bundle; rolls back to last known     |
| Pull from Git               | or bad Rego syntax.  |          | valid bundle. Alert posted to central telemetry.        |
|                             |                      |          |                                                         |
| pf Firewall Deactivation    | Exfiltration barrier | CRITICAL | [Target, not shipped] pfwatch watchdog would            |
| by User Script              | compromised.         |          | re-apply pf rules and revoke SVIDs.                     |
|                             |                      |          |                                                         |
| Tool Exhaustion (Looping)   | Local CPU spike,     | MEDIUM   | Envoy Circuit Breaker triggers after 20 calls/min;      |
|                             | battery drain.       |          | terminates loop with 429 Too Many Requests.             |
|                             |                      |          |                                                         |
| Swap File PII Leakage       | OS memory paged to   | HIGH     | Critical buffers locked with mlock(); encrypted swap    |
|                             | unencrypted disk.    |          | enforced via FileVault hardware volume key.             |
+-----------------------------+----------------------+----------+---------------------------------------------------------+
```

### 8.3 Circuit Breaking, Bulkheading & Backpressure

* **Bulkheading:** The agent runtime, OPA engine, Envoy gateway, and MCP tools run as independent OS processes with isolated virtual memory spaces. A panic in an MCP tool does not cascade to the gateway.
* **Backpressure Management:** When inference tokens exceed the processing rate of the local Apple Metal GPU pipelines, Envoy applies HTTP/2 flow control window reduction, signaling backpressure upstream to the agent orchestrator.

### 8.4 Zero-PII Structured Audit Telemetry

Audit logs are written as hash-chained JSON lines (`mcp/audit_chain.py`, `EnclaveAuditEnvelopeV1`, check `V16`) to `/var/log/enterprise/llm-audit.jsonl` in the prototype (`MCPMAC_AUDIT_LOG`) and to `/var/log/enclave/{adapter,cas,custody,ifc,zk}-audit.jsonl` in `v3.0`. Each line carries `prev_sha256` (and `prev_blake3` when available), so edits, deletions and reordering are detected on verification; deletion of the whole file is detected but not prevented.

* **Deterministic Masking:** User identifiers are hashed using SHA-256 with a daily rotating salt: $\text{Hash}(\text{User} \parallel \text{Salt}_{\text{day}})$.
* **Structured JSON Format:** Every event captures the exact OPA policy revision, evaluated rules, tool name, execution duration, and cryptographic decision outcome. Plaintext tool parameters and outputs are strictly prohibited from log serializers.

<!-- schema: enclave-audit-envelope-v1 -->
```json
{
  "v": 1,
  "daemon_uid": 501,
  "boot_epoch_id": "8fa1e0b4-32c9-4a77-9812-ec26987e71c1",
  "log_seq_u64": 17,
  "rpc_seq_u64": 17,
  "ts_utc_ms": 1762260600104,
  "spiffe_id": "spiffe://corporate.internal/ns/enclave/mcp-auth-proxy",
  "prev_sha256": "7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069",
  "prev_blake3": null,
  "prev_poseidon2": null,
  "payload": {
    "method": "tools/call",
    "tool": "query_customer_db",
    "decision": "ALLOW",
    "sql_sha256": "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae",
    "pii_redacted": {"email": 1, "phone": 1}
  }
}
```

---

## 9. Disaster Recovery, Runbooks & Day-2 Operations

### 9.1 Emergency Egress Break-Glass Procedure

In rare debugging scenarios where an authorized senior engineer requires direct external connectivity to troubleshoot a model failure:

1. The engineer executes `sudo /opt/enterprise/enclave/bin/break-glass.sh --ticket INC-NNNNN --duration 15m` ([`scripts/break-glass.sh`](../scripts/break-glass.sh), installed by `bootstrap-laptop.sh`; `--dry-run` prints the plan without root).
2. The script refuses without a ticket matching `(INC|SEC)-NNN`, validates the rules file with `pfctl -nf`, and writes a hash-chained audit record before suspending the anchor. (Verifying a SOC-signed authorization token is a target design not implemented by the script.)
3. The bypass is capped at **30 minutes**; the anchor is re-loaded when the timer expires or the script exits for any reason (EXIT trap), and a second audit record is written.

### 9.2 Key Rotation & Secure Enclave Desync Recovery

If the Apple Silicon Secure Enclave reports `errSecAuthFailed` (e.g. following macOS major kernel upgrade or biometric reset):

1. Execute `scripts/verify-enclave.sh --repair-keychain` (hardware mode only; skipped and reported in `--ci-vm`).
2. The flag deletes the stale `enterprise.enclave.dpop.key` keychain item, re-runs `identity/macos_attestation.py`, then runs the full verification suite. Re-minting SPIRE SVIDs is a separate operator step (`RB-103`).

### 9.3 Runaway Agent Process Quarantining

If an autonomous agent enters a non-terminating reasoning loop:

* Envoy's local rate-limiter triggers HTTP 429 after 50 calls in 60 seconds.
* If excessive CPU consumption persists for $> 90\text{s}$, the macOS `launchd` supervisor issues a `SIGTERM`, followed by a `SIGKILL` after 5 seconds, generating an incident dump for developer inspection.

---

## 10. Automated Verification & Compliance Test Suite

### 10.1 Static & Dynamic Security Verification Pipeline

`./scripts/verify-enclave.sh` (and `--ci-vm`) runs checks `V01`–`V22` from [`tests/checks.py`](../tests/checks.py). Each check performs semantic or negative testing — e.g. `pf` first-match evaluation plus a mutation test that must catch the legacy rule order, `opa test` plus Python/Rego parity, 1-byte `codesign` tamper rejection, DPoP replay/signature rejection, SQL bypass corpora, DLP leak corpora and audit hash-chain tamper detection. `[HW]` checks (`V01`–`V03`: Apple Silicon, SEP, FileVault) are skipped and reported in `--ci-vm` mode. The suite tests the **simulation**; it does not accredit a workstation to handle customer data.

### 10.2 Pre-Flight Hardware & Policy Assurance Checklist

* [ ] **Apple Silicon SEP:** Hardware cryptographic anchor initialized (`V02`; simulation keys are software).
* [ ] **macOS pf Firewall:** Anchor `com.enterprise.llm.isolation` validated (`V05`) and loaded by the operator.
* [x] **Envoy Proxy:** Local mTLS listener active on `127.0.0.1:8443`.
* [x] **OPA Policy Daemon:** Loaded with verified bundle; gRPC `ext_authz` answering on `127.0.0.1:9191`.
* [x] **MCP Auth Proxy:** OAuth 2.1 / DPoP token inspection enabled; inline PII redaction verified.
* [x] **macOS FileVault:** Full-Disk Encryption active across all local developer storage.

---

## 11. Frontier AI Lab Adoption Analysis: OpenAI vs. Google DeepMind vs. Anthropic

> **[LEGACY v1.0 PROTOTYPE — §11 ISOLATED, NON-NORMATIVE].** This section is the author's unverified positioning. Statements about other organisations' internal practices are not sourced and may be out of date. Every MCPMac capability named here (Dual-LLM, ANE guard, WASI 0.2, Cedar, SEP DPoP, canaries) is a `v2.0`/`v3.0` **target design that is not implemented** in this repository; the only runnable code is the Python simulation. Nothing in this section constrains `FS-701..705`.

To evaluate how this architecture positions against the current state-of-the-art across major AI research labs, the following matrix analyzes the technical, operational, and cultural hindrances to adopting this architecture at **OpenAI**, **Google DeepMind**, and **Anthropic**, alongside an objective assessment of whether each capability is **Ahead of**, **Currently Aligned with**, or **Behind** what is implemented or deployed in production today.

### 11.1 Comparative Adoption & Technical Capability Matrix

| Architectural Capability / Control Plane Dimension                                                       | OpenAI                                                                                                                                                                                                                                                                                                                                  | Google DeepMind                                                                                                                                                                                                                                                                                                                                                                                                                                                             | Anthropic                                                                                                                                                                                                                                                                                                                                                            |
|:---------------------------------------------------------------------------------------------------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Dual-LLM Privilege Separation**<br>*(Executive Planner vs. Quarantined Synthesizer)*                   | **Adoption Hindrances:** Cloud-first business model prioritizes monolithic context caching (GPT-4o, o1); dual local inference passes increase memory footprint on client machines.<br><br>**Standing: AHEAD**<br>*ChatGPT Desktop and Operator prototypes rely on a single model context vulnerable to indirect prompt injection.*      | **Adoption Hindrances:** DeepMind research leads the theory (CaMeLS papers), but internal developer tooling (Gemini Code Assist) utilizes single-turn workflows constrained by TPU cloud economics.<br><br>**Standing: CURRENTLY ALIGNED (Theory) / AHEAD (Local Deployment)**<br>*DeepMind researchers invented multi-agent privilege boundaries, but local laptop implementations are bleeding-edge.*                                                                     | **Adoption Hindrances:** Claude 3.5 Sonnet/Opus run exclusively on cloud infrastructure (AWS/GCP); splitting execution locally requires hybrid client/cloud orchestration.<br><br>**Standing: AHEAD**<br>*Claude Desktop and Claude Code feed tool outputs directly back into the single Claude context window.*                                                     |
| **Apple Neural Engine (ANE) Semantic Guardrail**<br>*(On-device 1B SLM at 0 GPU / 0 CPU Load)*           | **Adoption Hindrances:** Strong commercial alignment with Microsoft Azure; engineering investment in Apple-proprietary silicon (CoreML/MLX) conflicts with Windows/Linux cloud priorities.<br><br>**Standing: AHEAD**<br>*OpenAI runs safety moderation via cloud APIs (`/v1/moderations`), not on-device ANE silicon.*                 | **Adoption Hindrances:** DeepMind's core developer workstation fleet is **gLinux (Debian Linux)**; ANE is unviable on Linux. Edge ML focuses on Android (Gemini Nano on Tensor NPU).<br><br>**Standing: AHEAD (macOS Endpoints)**<br>*DeepMind does not deploy ANE-targeted security models for internal developer MacBooks.*                                                                                                                                               | **Adoption Hindrances:** Anthropic is a pure AI safety lab without a client-side systems engineering division; desktop apps are Electron-based rather than native Darwin Swift/CoreML.<br><br>**Standing: AHEAD**<br>*Anthropic relies on cloud Constitutional AI evaluation rather than local silicon-native neural guardrails.*                                    |
| **Wasm Component Model (WASI 0.2) & OCaps**<br>*(Hermetic tool sandbox with unforgeable capabilities)*   | **Adoption Hindrances:** OpenAI executes tools (Code Interpreter) in server-side Firecracker/gVisor microVMs on Azure; negligible incentive to invest in client-side Wasm sandboxing.<br><br>**Standing: AHEAD (Client Sandboxing)**<br>*OpenAI does not provide capability-based Wasm sandboxes for desktop agent tools.*              | **Adoption Hindrances:** Google maintains deep institutional investment in **gVisor** (container runtime sandbox) and **sandbox2** (seccomp-bpf); Google will mandate gVisor over WASI.<br><br>**Standing: BEHIND (Google Server gVisor) / AHEAD (Local Darwin Client)**<br>*Google's gVisor is superior for Linux servers, but WASI 0.2 is superior for local cross-platform MCP tools.*                                                                                   | **Adoption Hindrances:** Anthropic created MCP to be simple for community adoption (10 lines of Python/Node `stdio`); mandating Wasm compilation would alienate casual tool authors.<br><br>**Standing: AHEAD**<br>*MCP v1.0 spawns un-sandboxed OS child processes; WASI 0.2 capability isolation represents the future evolution of hardened MCP.*                 |
| **In-Process Policy Engine (Cedar in Lean 4)**<br>*(Sub-microsecond evaluation, automated reasoning)*    | **Adoption Hindrances:** OpenAI utilizes standard OAuth/OIDC, cloud IAM, and FastAPI middleware; formal verification talent is concentrated on AI alignment rather than systems policy.<br><br>**Standing: AHEAD**<br>*OpenAI relies on heuristic cloud permission checks, not formally verified in-process policy engines.*            | **Adoption Hindrances:** Google uses **Zanzibar** (global relationship-based access control); DeepMind inherits Zanzibar enterprise-wide, creating organizational inertia against Cedar.<br><br>**Standing: BEHIND (Zanzibar Scale) / AHEAD (Local Microsecond Latency)**<br>*Zanzibar manages planetary-scale authorization; the MCPMac target embeds Cedar locally with a `p99 <= 45µs` budget (unmeasured; earlier sub-2µs figures withdrawn).*                          | **Adoption Hindrances:** Anthropic prioritizes alignment via prompt engineering and RLHF over deterministic policy-as-code languages; prefers model self-governance over deterministic AST interceptors.<br><br>**Standing: AHEAD**<br>*Anthropic currently lacks a deterministic formal verification policy layer in Claude Desktop or MCP dispatchers.*            |
| **Hardware Secure Enclave (SEP) & DPoP**<br>*(Hardware-bound RFC 9449 non-replayable tokens)*            | **Adoption Hindrances:** Cross-platform friction across Windows, Linux, iOS, Android, and Web; mandating Apple SEP creates platform-divergent authentication architectures.<br><br>**Standing: AHEAD**<br>*OpenAI desktop apps use standard refresh tokens stored in Keychain/DPAPI without per-request SEP DPoP signing.*              | **Adoption Hindrances:** Google already deploys **Titan security chips**, **BeyondCorp** zero-trust device certificates, and **LOAS2/Ubermint**; Apple SEP attestation is redundant inside Google's managed fleet.<br><br>**Standing: BEHIND (Google BeyondCorp/Titan) / AHEAD (Standalone Zero-Trust macOS)**<br>*Google's internal BeyondCorp/Titan infrastructure is the planetary benchmark; our SEP DPoP brings Google-grade assurance to non-Google macOS endpoints.* | **Adoption Hindrances:** Anthropic prioritizes model capabilities and developer velocity over Darwin kernel integration; managing SEP keychains adds friction to simple MCP connections.<br><br>**Standing: AHEAD**<br>*MCP currently uses unauthenticated local stdio or standard bearer tokens without hardware proof-of-possession.*                              |
| **Dynamic Cryptographic Canary Honeytokens**<br>*(Hardware-signed tripwires with < 1ms circuit breaker)* | **Adoption Hindrances:** Injecting dynamic honeytokens into prompts disrupts server-side KV-cache reuse (Prefix Caching) in Azure clusters, increasing operational GPU costs.<br><br>**Standing: AHEAD**<br>*OpenAI does not dynamically inject cryptographic canaries into user data fixtures for client-side exfiltration detection.* | **Adoption Hindrances:** DeepMind has pioneered watermarking research (SynthID for media/text), but dynamic cryptographic canary tripwires are not integrated into developer coding assistants.<br><br>**Standing: AHEAD (Developer Tooling)**<br>*DeepMind has SynthID for media watermarking, but our sub-millisecond hardware circuit breaker for PII exfiltration is ahead of local tooling.*                                                                           | **Adoption Hindrances:** Adding synthetic canaries to tool outputs alters the exact character stream returned to the model, which can degrade reasoning on delicate code fixtures.<br><br>**Standing: AHEAD**<br>*Anthropic has published extensive prompt extraction research, but Claude Desktop contains no active cryptographic tripwire circuit breaker today.* |

---

### 11.2 Strategic Synthesis: Navigating Adoption Blockers

1. **For OpenAI (Cloud-First & Microsoft-Tied):**
   * *Adoption Path:* The biggest barrier is OpenAI's cloud-centric model and Azure dependency. To adopt this architecture, OpenAI would need to decouple its developer tools from mandatory Azure cloud logging and package an on-device local runtime for enterprise customers with extreme air-gap / zero-exfiltration mandates (e.g. defense, banking).

2. **For Google DeepMind (Linux & Internal Tooling Primacy):**
   * *Adoption Path:* The biggest barrier is cultural and infrastructural: DeepMind is deeply rooted in **gLinux**, **Borg**, **gVisor**, and **Zanzibar**. To adopt this, the macOS-specific Darwin primitives (SEP, `pf`, `EndpointSecurity`) must be generalized to Linux equivalents (**TPM 2.0 / Titan**, **eBPF socket filters**, and **gVisor sandboxes**).

3. **For Anthropic (Ecosystem Simplicity & Model Centricity):**
   * *Adoption Path:* The barrier is developer ergonomics: Anthropic wants MCP to remain frictionless for the open-source community. Hardening MCP with WASI 0.2 and DPoP requires shipping an **"Enterprise Hardened MCP Runtime"** alongside the lightweight community SDK, giving enterprise CISOs the assurance they demand without breaking hobbyist workflows.
