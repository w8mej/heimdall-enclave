# FEATURE: Post-Quantum Cryptography (PQC) & HNDL Fleet Migration Roadmap (FS-707)

* **Generation:** Generation 3 (Post-Quantum Enclave Security & Defense-in-Depth)
* **Status:** Partial software implementation; hybrid custody, complete wire/state integration and installed fleet qualification remain open. Earlier phase-complete labels are superseded by evidence-bound status (`YKD-15`); see current handoff.
* **Author:** Enterprise Enclave Security & SRE Architecture Team
* **Target Platforms:** Apple Silicon Macs (M1–M6+), macOS 14.0+ (Darwin 23.0+)
* **Lineage & Audit Context:** GAP-62 (AuditME Tier 3 / Long-Term Regulatory Archival)
* **Amendments:** `YKD-09/11`, 2026-11-15; lifetime/scope clarification and authenticated envelope/conditional-classical policy (§10).

---

## 1. Executive Summary & Problem Statement

Autonomous agent workflows on Apple Silicon Macs operate over confidential intellectual property, PII, and sensitive enterprise assets. Compliance frameworks (FINRA, SEC Rule 17a-4, GDPR, HIPAA) mandate **7–10 year regulatory retention** for zero-knowledge audit ledgers, tamper-evident journals, and token custody transactions (`FS-703`, `FS-705`).

Under classical cryptographic assumptions, encrypted records transmitted today over enterprise networks and inter-node swarms are vulnerable to **Harvest-Now-Decrypt-Later (HNDL)** attacks:

1. **The HNDL Vector:** Adversaries passively intercept and store encrypted ciphertext payloads (`C3`/`C4` surrogates, P2P weight chunks, DPoP tokens, ZK audit proofs).
2. **Cryptanalytically Relevant Quantum Computers (CRQCs):** Once Shor's algorithm becomes physical reality on quantum hardware of sufficient scale, discrete logarithm and elliptic curve cryptography (X25519, Ed25519, ECDSA P-256) are completely broken in polynomial time ($O(n^3)$).
3. **The SRE Challenge:** Pure post-quantum algorithms are relatively nascent compared to decades-tested classical primitives. Migrating directly to pure post-quantum algorithms introduces risks of unforeseen mathematical cryptanalytic weaknesses or side-channel vulnerabilities.

To satisfy mission-critical Production SRE standards for mission-critical infrastructure, MCPMac adopts a **defense-in-depth Hybrid Cryptosystem**: combining classical algorithms (X25519, Ed25519) with NIST FIPS-standardized post-quantum lattice primitives (**ML-KEM-768** / FIPS 203 and **ML-DSA-65** / FIPS 204). The intended hybrid security goal is resilience if either component remains secure; the bespoke combiner requires its own cryptographic review and is not certified by a design approval (YKD-11).

---

## 2. Service Level Objectives (SLOs) & Service Level Indicators (SLIs)

Adhering to Production SRE principles, the post-quantum subsystem defines strict latency, availability, and security boundaries.

### 2.1 SLI / SLO Specification Table

| Metric / Objective               | SLI Definition                                                                             | Target SLO                            | Error Budget / Alert Threshold                   |
|:---------------------------------|:-------------------------------------------------------------------------------------------|:--------------------------------------|:-------------------------------------------------|
| **Hybrid KEM Latency Overhead**  | P99 latency delta between classical X25519 DH and Hybrid X25519 + ML-KEM-768 encapsulation | $\le 1.8\text{ ms}$ overhead          | Alert if P99 $> 2.5\text{ ms}$ for 5 min         |
| **Hybrid Decapsulation Latency** | P99 latency of hybrid decapsulation and HKDF combiner execution                            | $\le 2.0\text{ ms}$ overhead          | Alert if P99 $> 3.0\text{ ms}$ for 5 min         |
| **Dual-Signature Verification**  | P99 latency for joint Ed25519 + ML-DSA-65 signature verification                           | $\le 2.5\text{ ms}$ total verify time | Alert if P99 $> 4.0\text{ ms}$ for 5 min         |
| **Anti-Downgrade Enforcement**   | Percentage of classical-only handshake attempts rejected when `HybridPqc` is mandated      | $100.00\%$ fail-closed rejection      | **0.00% tolerance** (SEV-1 on silent fallback)   |
| **Memory Allocation Bound**      | Max heap memory allocated per active hybrid TLS/QUIC session buffer                        | $\le 128\text{ KiB}$ per session      | Alert if daemon RSS leaks $> 10\text{ MiB}$/hour |
| **Wire MTU Overhead**            | Maximum handshake packet amplification factor                                              | $\le 3.5\times$ classical packet size | Alert on packet fragmentation drops              |

---

## 3. Threat Model & Post-Quantum Cryptanalysis

### 3.1 Attack Vectors & Mitigations

```
                HARVEST-NOW-DECRYPT-LATER (HNDL) MITIGATION
                                    
  [Attacker Tap] ──────> Intercepts Wire Ciphertext ─────> Stores in Archive
                                                                 │
                                                                 v
                                                       [Future Quantum Era]
                                                      CRQC Runs Shor's Alg.
                                                                 │
       ┌───────────────────────────────┐                         │
       │    Hybrid Ciphertext Bundle   │                         │
       │ ┌───────────────────────────┐ │                         │
       │ │ Classical X25519 DH       │─┼──> Decrypted by Shor's ─┤ (Compromised)
       │ └───────────────────────────┘ │                         │
       │ ┌───────────────────────────┐ │                         │
       │ │ Post-Quantum ML-KEM-768   │─┼──> Lattice LWE Hardness ┴─> BLOCKED!
       │ └───────────────────────────┘ │    (Quantum Immune)
       │ Combined SS: HKDF(C ‖ PQC)   │
       └───────────────────────────────┘
```

1. **Shor's Algorithm on Elliptic Curves:** Classical X25519 and Ed25519 rely on the Discrete Logarithm Problem on Curve25519. A CRQC solves this in polynomial time. Hybrid encapsulation binds the shared secret using HKDF-SHA256 with the ML-KEM-768 secret. Even if the X25519 factor is solved, the HKDF output remains cryptographically pseudorandom due to the 256-bit entropy from ML-KEM-768.
2. **Grover's Algorithm on Symmetric Ciphers:** Grover's algorithm provides at most a quadratic speedup ($O(2^{n/2})$) against symmetric ciphers. All symmetric keys in MCPMac use 256-bit primitives (ChaCha20Poly1305, BLAKE3, HKDF-SHA256), yielding a post-quantum security margin of at least 128 bits, well exceeding NIST Category 3 requirements.
3. **Lattice Reduction Attacks:** While Module Learning with Errors (M-LWE) is mathematically proven secure against both classical and quantum adversaries under worst-case lattice reduction assumptions, the hybrid combination ensures that if a classical algorithmic breakthrough occurs in lattice reduction, classical elliptic curves preserve security.

---

## 4. Cryptographic System Architecture

### 4.1 Hybrid KEM Combiner (`X25519 + ML-KEM-768`, bespoke MCPMac combiner)
>
> **Not X-Wing (DEFECT-F-76).** The combiner binds the same four values in the same order as `draft-connolly-cfrg-xwing-kem`, but X-Wing uses SHA3-256 with its own label and its own key/ciphertext encodings. This construction uses HKDF-SHA256 and does not interoperate with X-Wing. On the OHTTP wire it is identified by the unregistered local KEM id `0xFF41` (`KEM_ID_HYBRID_MCPMAC`); X-Wing's IANA id `0x647A` is refused (`OHTTP_KEM_XWING_UNSUPPORTED`). The label below is frozen (at-rest envelopes depend on it); its `XWing` substring is historical.

* **Standard:** NIST FIPS 203 (`ML-KEM-768`, polynomial ring $\mathcal{R}_q = \mathbb{Z}_{3329}[X]/(X^{256}+1)$, module rank $k=3$, constant-time Fujisaki-Okamoto $\text{FO}^{\not\perp}$ implicit rejection), RFC 7748 (`X25519`), and NIST SP 800-56C Rev. 2 (two-step KDF). X-Wing-style transcript binding, not X-Wing.
* **Parameters:**
  * X25519 Public Key: 32 bytes
  * ML-KEM-768 Encapsulation Key (`ek`): 1,184 bytes (`HYBRID_KEM_PUBLIC_KEY_SIZE = 1,216 bytes`)
  * ML-KEM-768 Decapsulation Key (`dk`): 2,400 bytes (`HYBRID_KEM_SECRET_KEY_SIZE = 2,432 bytes`)
  * X25519 Ephemeral Public Key: 32 bytes
  * ML-KEM-768 Ciphertext (`c`): 1,088 bytes
  * Total Composite Ciphertext: 1,120 bytes (`HYBRID_KEM_CIPHERTEXT_SIZE`)
* **Combiner Derivation (Transcript-Bound IND-CCA2):**
  $$\text{IKM} = \text{SS}_{\text{ML-KEM-768}} \parallel \text{SS}_{\text{X25519}} \parallel \text{ct}_{\text{X25519}} \parallel \text{pk}_{\text{X25519}} \quad (128\text{ bytes})$$
  $$\text{SharedSecret} = \text{HKDF-SHA256-Expand}(\text{PRK}=\text{HKDF-Extract}(\text{None}, \text{IKM}), \text{info}=\text{"MCPMac-v3-XWing-X25519-ML-KEM-768"}, \text{len}=32)$$

#### 4.1.1 Approved envelope policy and informed classical use (`YKD-11`)

Newly created A3/A4 tier envelopes use independently generated hybrid
X25519 + ML-KEM-768 keypairs by default. Authenticate version/suite, tier,
subject/namespace/profile, key/encapsulation lengths, PRF/wrapping domains,
policy generation and migration state. Reject unknown, mismatched or
downgraded formats; parsing another suite must not trigger a silent retry.
Retain the frozen bespoke §4.1 combiner labels/bytes for compatibility until
separately reviewed/versioned migration. This policy decision does not prove
the construction secure, certify it as X-Wing or change existing ciphertexts.

**Conditional classical use is allowed only explicitly:** authenticated policy
must name the permitted surface/purpose, affected subjects/data/profiles, owner,
finite validity/review and migration/retirement conditions. Explain the missing
post-quantum protection, rationale and residual risk when first enabling that
mode and when its scope changes; make the active suite/exception visible to the
operator and affected relying parties. Do not log secret key material. Preserve
independent tier keys, all custody factors and revocation/cleanup requirements.
A policy requiring hybrid refuses classical use even if a user informally
acknowledges the risk; absence of capability is not fallback authorization.

Legacy envelope opening/migration needs an explicit authenticated format and
compatible reader, verified open/reseal, transactional failure/rollback handling,
old-key retirement and auditable completion. Do not assume a classical reader or
migration path exists merely because the policy allows one. Migration must not
leave a broader or longer-lived decryption path than the approved exception.

SEP P-256, CTAP ES256/Ed25519 and protocol-2 P-256 key agreement remain classical
components subject to their own tracked hardware exceptions. A hybrid tier
envelope does not make recorded USB traffic or end-to-end hardware custody
quantum-safe. Preserve these components conditionally with the same truthful
scope/risk disclosure; do not present a short challenge TTL as confidentiality
protection for archived exchanges. See
YKD-11.

### 4.2 Hybrid Dual-Signature Scheme (`Ed25519 + ML-DSA-65`, IETF LAMPS Composite)

* **Standard:** NIST FIPS 204 (`ML-DSA-65`, polynomial ring $\mathbb{Z}_{8380417}[X]/(X^{256}+1)$, module dimensions $(k,\ell)=(6,5)$), RFC 8032 (`Ed25519`), and `draft-ietf-lamps-pq-composite-sigs`.
* **Parameters:**
  * Ed25519 Verifying Key: 32 bytes
  * ML-DSA-65 Public Key: 1,952 bytes (`HYBRID_VERIFYING_KEY_SIZE = 1,984 bytes`)
  * ML-DSA-65 Signing Key: 4,032 bytes
  * Ed25519 Signature: 64 bytes
  * ML-DSA-65 Signature: 3,309 bytes
  * Total Composite Signature: 3,373 bytes (`HYBRID_SIGNATURE_SIZE`)
* **Composite Message & Verification Invariant:**
  $$M' = \text{"MCPMac-v3-LAMPS-MLDSA65-Ed25519-v1"} \parallel vk_{\text{ed25519}} \parallel \text{BLAKE3}(vk_{\text{mldsa65}}) \parallel \text{len}_{64}(m) \parallel m$$
  $$\text{Verify}_{\text{hybrid}}(m, \sigma_{\text{ed}}, \sigma_{\text{pqc}}, pk_{\text{ed}}, pk_{\text{pqc}}) = \text{Verify}_{\text{ed25519}}(M', \sigma_{\text{ed}}, pk_{\text{ed}}) \land \text{Verify}_{\text{mldsa65}}^{\text{ctx}}(M', \sigma_{\text{pqc}}, pk_{\text{pqc}})$$
  Fails closed with `HYBRID_CLASSICAL_SIG_INVALID` or `HYBRID_PQC_SIG_INVALID` if either component fails.

---

## 5. MTU Budgets, Wire Framing & Fragmentation Strategy

Post-quantum public keys and signatures are substantially larger than classical counterparts:

* Classical Handshake Exchange: $\approx 200\text{ bytes}$
* Hybrid PQC Handshake Exchange: $\approx 2,400\text{ bytes}$ (exceeding standard 1500-byte Ethernet MTU)

### 5.1 Fragmentation Mitigation & QUIC Transport

1. **QUIC Packet Coalescing & Multi-Datagram Reassembly:** For inter-node swarm communication (`_enclavecas`, UID 702), the Iroh QUIC transport enables multi-datagram initial flight reassembly with PMTU discovery.
2. **Local IPC Sockets (Unix Domain):** For local privilege-separated LaunchDaemons (UIDs 701–705), CBOR length-prefixed streaming carries payloads up to 16 MiB without kernel fragmentation issues.
3. **Outbox Batch Framing:** ZK audit root attestations (`_enclavezk`, UID 705) batch audit receipts before dual-signing, amortizing the 3,373-byte signature overhead across up to 1,000 transaction receipts.

---

## 6. Phased Fleet Migration Plan & Live Enforcement Status (Production SRE PRR)

```
Fleet Migration Lifecycle:
Phase 0 (Primitives) ──> Phase 1 (Hybrid KEM) ──> Phase 2 (Hybrid Sig) ──> Phase 3 (Silicon/3P PQC)
   [Evidence required]      [Evidence required]      [Evidence required]    [Tracked Exceptions]
```

### Phase 0: Standardized NIST FIPS 203/204 Primitives & Formal Assurance (Target contract; acceptance evidence required)
* Audited all asymmetric key usages across `enclave-crypto`, `enclave-core`, `enclave-custody-vaultd`, `enclave-swarm-syncd`, and `enclave-zk-auditor`.
* Implemented `crates/enclave-crypto/src/pqc.rs` backed by pure-Rust constant-time `fips203 = "0.4.3"` (`ml_kem_768`) and `fips204 = "0.4.6"` (`ml_dsa_65`).
* Mechanized 8 zero-`sorry` Lean 4 assurance theorems across `proofs/lean4/Enclave/Lattice.lean` and `proofs/lean4/Enclave/TierThreeAssurance.lean`.

### Phase 1: Custody Vault & OHTTP Wire Transport Hybrid KEM Enforcement (Target contract; acceptance evidence required)
* **Custody Vault Dual-Tier Envelopes (`crates/enclave-crypto/src/hpke_envelope.rs`, `_piivault` UID 703):** Upgraded `Envelope_A3` (`C3` per-epoch surrogates, 64-seal cap) and `Envelope_A4` (`C4` / bulk surrogates) to Hybrid `X25519 + ML-KEM-768` (`1,216`-byte composite public key, `1,120`-byte composite ciphertext, `2,432`-byte composite private key wrapped under the two-factor SEP + YubiKey hardware KEK).
* **Oblivious HTTP Relay & L3 Model Fetch (`crates/enclave-crypto/src/ohttp.rs`, `_enclavecas` UID 702 & `services/ledger-gateway`):** Upgraded `gateway_keypair`, `encapsulate`, and `decapsulate` to default to Hybrid `X25519 + ML-KEM-768` (`KEM_ID_HYBRID_MCPMAC = 0xFF41`, local id, DEFECT-F-76).
* **Fail-Closed Anti-Downgrade Guard:** Any attempt to present a classical `KEM_ID = 0x0020` (`DHKEM(X25519, HKDF-SHA256)`) request to a `HybridPqc` gateway fails closed via `enforce_handshake_suite` with `EACCES: PQC_DOWNGRADE_ATTEMPT_REJECTED`. YKD-11 permits a separately authenticated, disclosed conditional classical policy, not a silent downgrade of an enforced HybridPqc surface; full exception/migration enforcement remains to be qualified.

### Phase 2: ZK Compliance Rollup Hybrid Dual-Signature Attestation & Operator CLI (Target contract; acceptance evidence required)
* **ZK Auditor L2 Batch Anchor Dual-Signatures (`crates/enclave-zk-auditor/src/rollup.rs`, `_enclavezk` UID 705):** Implemented `ComplianceRollupProofV1::sign_l2_hybrid_anchor` and `verify_l2_hybrid_anchor`, binding `EpochStatement` public inputs under composite `Ed25519 + NIST FIPS 204 ML-DSA-65` signatures (`"pqc-hybrid-v1:<hex>"`, `3,373` bytes) inside `hardware_batch_anchor_sigs`.
* **Plonky3 STARK Hash-Based Post-Quantum Security:** The core `ComplianceRollupProofV1` zero-knowledge proof (`KoalaBear^5` extension field, Poseidon2 sponge, FRI blowup 4, 84 queries, 16-bit PoW) relies exclusively on collision-resistant symmetric hashing and Reed-Solomon proximity testing—containing zero elliptic-curve or discrete-logarithm assumptions and remaining natively post-quantum secure.
* **Operator Cryptographic Agility CLI (`crates/mcp-enclave/src/ctl.rs`):** Implemented `mcp-enclave crypto status`, `mcp-enclave crypto self-test`, `mcp-enclave crypto policy set --wire-suite <suite> [--temporary-override-ticket <id>]`, and `mcp-enclave crypto flush-sessions`.

### Phase 3: Third-Party Protocol & Hardware Silicon PQC Convergence (Roadmap — Tracked via §6.5)
* Transition hardware-bound SEP and FIDO2 signing slots from `P-256`/`Ed25519` to hardware-accelerated `ML-KEM`/`ML-DSA` once supported by future Apple Silicon Secure Enclave generations and FIDO Alliance CTAP 2.2+ hardware tokens.
* Transition third-party wire and capability libraries (`iroh` QUIC TLS 1.3, `biscuit-auth`, TUF canonical metadata, and OAuth 2.0 DPoP) as upstream IETF / Rust ecosystem crates finalize post-quantum codepoints.

---

## 6.5 Production SRE & Cryptographic Review Board Tracked Architectural Exceptions (`PQC-EXC-01` – `PQC-EXC-06`)

Per Production Readiness Review (PRR) and Cryptographic Review Board standards, any cryptographic surface that cannot yet be migrated to NIST FIPS 203/204 due to **immutable hardware silicon constraints** or **upstream third-party protocol specifications** is formally registered below as a **Tracked Architectural Exception**.

**YKD-11 assurance boundary:** hybrid payload protection is the target for surfaces requiring HybridPqc; actual source/native/installed acceptance is recorded separately. An explicitly permitted classical mode lacks that post-quantum property and must be disclosed to affected parties under §4.1.1. Classical local hardware/authentication exceptions remain classical even with a short challenge TTL. Do not claim universal HNDL protection or end-to-end post-quantum custody from the presence of a hybrid payload wrapper.

| Exception ID     | Subsystem & Crate                                                                                                                  | Current Classical Primitive                                                        | Root Cause (Hardware / Upstream Spec Limitation)                                                                                                                                                                                                  | Threat Vector & HNDL Exposure                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                | Enforced Compensating Controls (Defense-in-Depth)                                                                                                                                                                                                                                                                                                                                                                                               | Retirement Trigger & Roadmap Target                                                                                                                                                     |
|:-----------------|:-----------------------------------------------------------------------------------------------------------------------------------|:-----------------------------------------------------------------------------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **`PQC-EXC-01`** | Apple Secure Enclave Processor (SEP) (`crates/enclave-custody-vaultd/src/sep.rs`)                                                  | `ECDSA / ECDH P-256` (`kSecAttrKeyTypeECSECPrimeRandom`)                           | Apple Silicon M1–M4 SEP hardware key slots only implement fixed-function NIST P-256 in silicon; macOS `Security.framework` / `CryptoKit` does not expose SEP-backed `ML-KEM` or `ML-DSA` private key slots.                                       | **Classical hardware exception, not a post-quantum claim (YKD-11).** Local SEP P-256 confinement reduces exposure paths; it does not prove all recorded hardware/custody exchanges resist future quantum analysis. Disclose the boundary and qualify the actual flow.                                                                                                                                                                                                                                                        | 1. SEP P-256 ECDH output is mixed via `HKDF-SHA256` with the YubiKey 256-bit `hmac-secret` PRF share (`KekShares`) to unwrap a **Hybrid `X25519 + ML-KEM-768`** tier key (`Envelope_A3` / `Envelope_A4`).<br>2. All vaulted PII ciphertexts (`SealedValue`) are encrypted under `X25519 + ML-KEM-768`.                                                                                                                                          | Adopt SEP-backed `ML-KEM` / `ML-DSA` key types when Apple introduces post-quantum SEP key slots in future Apple Silicon / macOS SDK releases.                                           |
| **`PQC-EXC-02`** | Physical YubiKey 5 Series FIDO2 Token (`crates/enclave-custody-vaultd/src/ceremony.rs`)                                            | `CTAP 2.1 ES256 (-7) / EdDSA (-8)` + `hmac-secret` (`HMAC-SHA256`)                 | Commercial YubiKey 5 Series hardware secure elements do not support `ML-DSA-65` (`4,032B` sk / `3,309B` sig exceeds CTAP2 APDU frame limits), and FIDO Alliance COSE PQC algorithms are still in draft.                                           | **Classical authentication/transport exception (YKD-11).** Critical CTAP2 action assertions require live interactive physical presence (`UP=1`) within the complete **10-second monotonic ceremony cap** in FS-703 §3.4 (`YKD-09`), including PIN/UI time. The earlier 60-second description is superseded and cannot extend action authorization. Restricted silent-presence checks under FS-703 §5.3 are not action approval. Short-lived authentication is not a proof that all recorded CTAP exchanges are quantum-safe. | 1. Key-wrapping entropy uses the FIDO2 `hmac-secret` extension (`HMAC-SHA256`), which is a **symmetric 256-bit PRF** with **128-bit post-quantum security** against Grover's algorithm.<br>2. Long-lived `L2` compliance rollups are co-signed in software with `Ed25519 + ML-DSA-65` (`sign_l2_hybrid_anchor`).                                                                                                                                | Migrate to FIDO2 CTAP 2.2+ / COSE `ML-DSA` hardware authenticators once ratified by the FIDO Alliance and shipped in commercial USB-C security keys.                                    |
| **`PQC-EXC-03`** | Biscuit v3 Capability Tokens (`crates/enclave-agent-runtime`, `biscuit-auth = "6.0"`)                                              | `Ed25519` multi-block signature chain                                              | The upstream Biscuit v3 specification (`biscuit-auth`) hardcodes `Ed25519` for attenuated multi-block signature aggregation; `ML-DSA-65` does not support non-interactive block aggregation without $N \times 3,309\text{ B}$ linear size blowup. | **Zero HNDL exposure.** `PoP-Biscuit` tokens carry authorization facts rather than PII payloads. Local UDS capabilities expire within $\le 300\text{ s}$ on a boot-bound continuous clock. The separate cross-node presentation uses FS-704 authenticated UTC, $\le 30,000\text{ ms}$ and its bounded-skew policy; a 900 s A2 delegation or ≤1 h pull grant cannot extend either child lifetime (`YKD-09`).                                                                                                                  | 1. For local capabilities, Unix Domain Socket (`02750`) transport verified by kernel `LOCAL_PEERTOKEN` (`audit_token_t`) and `codesign-pins.json` `cdhash` pinning.<br>2. Boot-bound continuous-clock local TTL ($\le 300\text{ s}$), separate FS-704 cross-node UTC/TTL/holder checks and the earliest applicable parent/revocation bound; retain replay protection.                                                                           | Upgrade to Biscuit v4 / PQ-Biscuit when the upstream `biscuit-auth` specification standardizes lattice-based or hash-based capability chains.                                           |
| **`PQC-EXC-04`** | Iroh P2P QUIC Swarm Transport (`crates/enclave-swarm-syncd`, `iroh = "0.28"`, `rustls = "0.23"`)                                   | `Ed25519` `EndpointId` (`pkarr`) + TLS 1.3 `X25519`                                | Upstream `iroh 0.28` defines peer `EndpointId` as a 32-byte `Ed25519` public key and uses `ring`'s classical `X25519` key exchange in its default QUIC TLS 1.3 config.                                                                            | **Mitigated at payload layer.** Public/L1/L2 model weights transferred over LAN P2P are non-secret public weights; confidential `L3` weights and compliance rollups never rely solely on QUIC TLS for confidentiality.                                                                                                                                                                                                                                                                                                       | 1. **Integrity:** Every 16 KiB slice of model weights is verified against a **256-bit `BLAKE3` Bao Merkle tree** (128-bit quantum collision/preimage resistance via Grover/Brassard-Høyer-Tapp).<br>2. **Confidentiality:** `L3` model fetches (`ohttp_fetch.rs`) and `L2`/`L3` compliance rollups are inner-encapsulated with **Hybrid `X25519 + ML-KEM-768` OHTTP (`0xFF41`)** + 256-bit `ChaCha20Poly1305` DEKs before traversing transport. | Enable `rustls-post-quantum` (`X25519MLKEM768` IETF TLS 1.3 codepoint `0x11EC`) once `iroh` exposes custom `rustls::crypto::CryptoProvider` injection across its QUIC endpoint builder. |
| **`PQC-EXC-05`** | OAuth 2.0 DPoP Client Gateway (`crates/enclave-client-gateway`, `RFC 9449`)                                                        | `ES256` (`ECDSA P-256`) JWS proofs                                                 | IETF RFC 9449 / JOSE has not yet finalized standard `alg` codepoints for `ML-DSA` in commercial OAuth 2.0 / Envoy API gateways.                                                                                                                   | **Zero HNDL exposure.** DPoP proofs are interactive authentication headers bound to a single HTTP request (`htm`, `htu`, `iat`, `jti`) over local loopback (`lo0`) with a 60-second validity window.                                                                                                                                                                                                                                                                                                                         | 1. Mandatory `jti` single-use replay cache (`DPOP_REPLAY_DETECTED`) and 60-second clock-skew ceiling.<br>2. Restricted to local loopback (`127.0.0.1`) and UDS gateway ingress.                                                                                                                                                                                                                                                                 | Adopt JOSE `ML-DSA-65` (`draft-ietf-cose-dilithium` / JOSE PQ `alg`) once ratified by IETF OAuth WG.                                                                                    |
| **`PQC-EXC-06`** | TUF Repository Metadata & Local IPC Grants (`crates/enclave-swarm-syncd/src/tuf.rs`, `crates/enclave-custody-vaultd/src/vault.rs`) | 2-of-3 `Ed25519` TUF role signatures & UID 704 `Ed25519` `ReversibleTokenizeGrant` | Existing TUF v1.0.31 canonical JSON role schemas (`schemas/enclave-host-config.schema.json`) pin 64-hex-char (32-byte) `Ed25519` public key identifiers.                                                                                          | **Zero HNDL exposure.** Signatures protect authenticity of active manifests/grants, not confidentiality against passive archival; TUF timestamp/snapshot metadata rotates continuously.                                                                                                                                                                                                                                                                                                                                      | 1. TUF target artifacts are pinned by **256-bit `BLAKE3` digests and Bao Merkle roots** (quantum-safe).<br>2. Local UID 704 grants traverse only root-provisioned `02750` UDS sockets authenticated by Darwin kernel `audit_token_t` and `cdhash` code-signing pins.                                                                                                                                                                            | Add dual `ed25519 + mldsa65` keytype support in TUF `root.json` v2 schema rotation (`FS-707` Phase 3).                                                                                  |

### Review Board Sign-Off Criteria

1. **Scoped, evidenced protection (YKD-11):** deployments requiring HybridPqc must qualify every sensitive payload/archival surface against its authenticated policy and actual envelope/transport. A zero-knowledge proof is not payload encryption. Explicit classical exceptions must have scoped authority, finite validity/review, informed affected parties and migration/retirement criteria; they cannot claim post-quantum confidentiality or count as HybridPqc-qualified for that surface. The bespoke hybrid combiner still needs cryptographic review.
2. **No Silent Fallback:** Downgrading any enforced `HybridPqc` surface (`ohttp.rs` or `pqc.rs`) without an explicit SRE emergency override ticket (`RB-219`) fails closed with `PQC_DOWNGRADE_ATTEMPT_REJECTED` or `PQC_OVERRIDE_TICKET_REQUIRED`.
3. **Annual Exception Audit:** Exceptions `PQC-EXC-01` through `PQC-EXC-06` are reviewed at each macOS major release and upstream dependency upgrade window.

---

## 7. Operational SRE Runbooks

### RB-218: Post-Quantum Hybrid Handshake Failure & MTU Fragmentation Triage

* **Severity:** SEV-2
* **Trigger:** Alert `EnclavePqcHandshakeFailuresHigh` fires ($> 0.1\%$ failures over 5m) or `enclave_pqc_handshake_total{status="rejected_downgrade"} > 0`.
* **Diagnostic Steps:**
  1. Inspect supervisor logs for downgrade rejection events:

     ```bash
     mcp-enclave audit log --grep "PQC_DOWNGRADE_ATTEMPT_REJECTED"
     ```

  2. Verify peer wire capabilities and inspect MTU path:

     ```bash
     mcp-enclave peer ping --target <peer_id> --pqc
     ```

  3. Check QUIC frame reassembly metrics:

     ```bash
     mcp-enclave metrics get --metric iroh_quic_reassembly_errors_total
     ```

* **Mitigation:**
  * If a legacy un-migrated node attempted connection, update node binary via MDM deployment profile.
  * If network path clamps MTU $< 1200\text{ bytes}$, adjust QUIC max datagram frame size in `enclave.lock.toml`.

### RB-219: Post-Quantum Algorithm Emergency Revocation & Cryptographic Agility Hot-Swap

* **Severity:** SEV-1
* **Context:** An academic or public cryptanalytic finding identifies a theoretical vulnerability in Module-Lattice M-LWE or M-SIS (e.g. unexpected polynomial structure weakness).
* **Execution Drill:**
  1. Trigger cryptographic agility configuration update without daemon binary recompilation:

     ```bash
     mcp-enclave crypto policy set --wire-suite ClassicalOnly --temporary-override-ticket "SRE-PQC-EMERGENCY-2026"
     ```

  2. Invalidate PQC session key cache across all 5 LaunchDaemons:

     ```bash
     mcp-enclave crypto flush-sessions
     ```

  3. Verify daemons fail closed safely into hardened classical mode while preserving all Biba/IFC isolation invariants.

---

## 8. Monitoring, Metrics, and Alerting

The following Prometheus/OpenTelemetry metrics are exposed via the local 0600 monitoring socket:

```promql
# Alert: High PQC Handshake Latency (SLO Breach)
alert: EnclavePqcLatencyHigh
expr: histogram_quantile(0.99, rate(enclave_pqc_kem_duration_seconds_bucket[5m])) > 0.0025
for: 5m
labels:
  severity: warning
annotations:
  summary: "P99 Hybrid PQC KEM duration breached 2.5ms SLO ceiling"

# Alert: Downgrade Attack Detected (Security SEV-1)
alert: EnclavePqcDowngradeAttackDetected
expr: increase(enclave_pqc_downgrade_attempts_total[1m]) > 0
for: 0m
labels:
  severity: critical
annotations:
  summary: "Adversary attempted classical wire downgrade against HybridPqc enforced enclave"
```

---

## 9. References & Standards Citations

1. **NIST FIPS 203:** *Module-Lattice-Based Key-Encapsulation Mechanism Standard (ML-KEM)*, National Institute of Standards and Technology, August 2024. [https://csrc.nist.gov/pubs/fips/203/final](https://csrc.nist.gov/pubs/fips/203/final)
2. **NIST FIPS 204:** *Module-Lattice-Based Digital Signature Standard (ML-DSA)*, National Institute of Standards and Technology, August 2024. [https://csrc.nist.gov/pubs/fips/204/final](https://csrc.nist.gov/pubs/fips/204/final)
3. **NIST FIPS 205:** *Stateless Hash-Based Digital Signature Standard (SLH-DSA)*, National Institute of Standards and Technology, August 2024. [https://csrc.nist.gov/pubs/fips/205/final](https://csrc.nist.gov/pubs/fips/205/final)
4. **RFC 9180:** *Hybrid Public Key Encryption (HPKE)*, R. Barnes, C. Huitema, et al., February 2022.
5. **NIST SP 800-227:** *Recommendations for Post-Quantum Cryptography Migration*, NIST Special Publication, 2024.
6. **BSI TR-02102-1:** *Cryptographic Mechanisms: Recommendations and Key Lengths*, Federal Office for Information Security, Germany, 2024.

## 10. Approved specification amendments

* **2026-11-15 — YKD-09:** supersede PQC-EXC-02's 60 s critical CTAP challenge
  wording with the complete 10 s FS-703 ceremony budget. Distinguish local
  ≤300 s capabilities from ≤30,000 ms cross-node proofs and their different
  clocks/consumers; all remain bounded by applicable parent/revocation limits.
  Host PIN/UV tokens are discarded at ceremony end with no cross-ceremony reuse
  initially. This is a design amendment, not a new cryptographic assurance or
  implementation/hardware PASS. Other PQC exception/combiner decisions remain
  separately governed. See
  YKD-09.

* **2026-11-15 — YKD-11:** hybrid new A3/A4 tier envelopes by default, authenticated
  suite/version/domain policy, explicit scoped and time-bounded classical use
  with informed relying parties, no silent fallback or false PQ claims. Freeze
  existing combiner bytes pending review and require explicit legacy migration.
  Classical SEP/CTAP components remain disclosed hardware exceptions. No runtime
  policy, migration reader, installed notice or cryptographic acceptance is
  established by this specification amendment.

## 11. Evidence status supersession (YKD-15, 2026-11-15)

Earlier phase-complete/enforced labels describe intended targets and historical
software checkpoints; they do not establish full hybrid custody, complete proof
relation, wire privacy, installed hardware or fleet acceptance. Preserve actual
receipts and explicit PQC exceptions. YKD-11 approval does not prove the bespoke
combiner or turn classical CTAP/SEP into post-quantum authentication. Current
acceptance and remaining work are in the implementation handoff.
