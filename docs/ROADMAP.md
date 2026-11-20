# Heimdall-Enclave Engineering Roadmap

* **Document ID:** `ROADMAP-HEIMDALL-2026`
* **Status:** `ACTIVE`
* **Maintainer:** John Menerick (W8MEJ), AI Systems Security Scientist & Engineer
* **Target Platform:** Apple Silicon (`arm64e`, M1 through M5+) & macOS 14.0+ (Sonoma / Sequoia)

This document tracks forward-looking architectural milestones, advanced cryptographic integrations, and physical hardware verification goals following the initial release of Heimdall-Enclave `v3.0`.

---

## 1. Hardware Security & Silicon Attestation

### 1.1 Physical FIDO2 CTAP 2.1 Hardware Insertion Matrix (`GAP-13`)

* **Current Status:** Software attestation verification (`crates/enclave-custody-vaultd/src/x509.rs`), algorithm negotiation (ES256/EdDSA per `getInfo.algorithms`), official Yubico MDS roots (`packaging/fido-mds/yubico.json`), and CTAPHID software emulation are complete and verified.
* **Roadmap Milestone:**
  * Complete bare-metal testing matrix across genuine YubiKey 5C (firmware 5.4/5.7) and YubiKey Bio (AAGUID matching) devices under physical insertion and USB-C disconnect.
  * Implement dynamic USB hub topology depth gating (`depth <= 1`) across physical USB trees.

### 1.2 Automated Apple Silicon Hardware-in-the-Loop (HIL) CI Runner (`GAP-65`)

* **Current Status:** Automated CI executes on GitHub-hosted `macos-14` runners in `--ci-vm` mode, where physical SEP and Touch ID sensors are virtualized/absent. Bare-metal tests are verified on dedicated Apple Silicon reference hardware.
* **Roadmap Milestone:**
  * Deploy a self-hosted Apple Silicon (`arm64e`) continuous integration runner equipped with a physical loopback testing rig.
  * Automate non-interactive Touch ID biometric authorization via secure hardware test fixtures.

---

## 2. Advanced Cryptography & Formal Verification

### 2.1 Verifiable Q16.16 Fixed-Point Safety Heads (`GAP-41`)

* **Current Status:** Q16.16 fixed-point arithmetic and bounding heads are implemented in `crates/enclave-model-runnerd/src/q16_safety.rs` and enforced during CPU inference gating.
* **Roadmap Milestone:**
  * Mechanize Plonky3 AIR polynomial constraint chips to prove in-circuit that the logits emitted by draft companion models do not violate safety bounds prior to token generation.
  * Integrate polynomial range checks into `EpochAir` batch proofs.

### 2.2 Live Hybrid Post-Quantum Cryptography (PQC) Fleet Rollout (`GAP-62`)

* **Current Status:** Hybrid primitives combining classical X25519/Ed25519 with NIST FIPS 203 `ML-KEM-768` and NIST FIPS 204 `ML-DSA-65` are fully implemented in `crates/enclave-crypto/src/pqc.rs` with formal Lean 4 assurance proofs (`proofs/lean4/Enclave/TierThreeAssurance.lean`).
* **Roadmap Milestone:**
  * Execute phased fleet cutover per `docs/FEATURE_PQC_MIGRATION_ROADMAP.md` (FS-707).
  * Transition external CAS metadata and Identity Provider (IdP) token signing from classical-only to dual-signature hybrid format on live network egress boundaries.

---

## 3. Observability & Distributed Tracing

### 3.1 Distributed W3C Traceparent Context Propagation (`GAP-54`)

* **Current Status:** IPC communication between daemons uses CBOR over Unix Domain Sockets with audit token validation and monotonic sequence counters.
* **Roadmap Milestone:**
  * Embed W3C `traceparent` and `tracestate` headers into the outer CBOR IPC envelope (`EnclaveIpcEnvelope`).
  * Integrate Rust `tracing` with Apple's native Unified Logging (`os_log`) subsystem and an OpenTelemetry OTLP exporter, enabling unified visualization in distributed trace viewers (e.g. Chrome Tracing, Jaeger).
