# Technical Control Design Alignment — Pre-Audit Target Architecture

## MCPMac Local LLM & Agentic PII Governance (Apple Silicon macOS)

* **Document ID:** `GOV-COMP`
* **Generation:** `v3.0-Production` (technical control implementation in `crates/`) + `v1.0-Legacy` (educational simulation)
* **Status:** `ACTIVE — TECHNICAL CONTROL MAPPING, NOT AN ATTESTATION`
* **Revision:** `2.1.0` (2026-11-08) — updated for Rust `v3.0` production reference workspace (remediates `F-006`, `F-007`, `F-030`, `F-036`)
* **Normative Precedence:** see [`README.md §1.2`](../README.md#12-normative-precedence--architectural-lineage)

> **What this document is.** A mapping from regulatory and framework *criteria* to the *technical control designs* in this repository, with a pointer to the executable check (if any) that exercises the corresponding **simulation**.
>
> **What this document is not.** It is **not** evidence of compliance, certification, or an audit opinion. In particular:
>
> * **HIPAA Safe Harbor (45 CFR § 164.514(b)(2)) is NOT claimed.** The simulation removes a subset of identifiers with regex and column rules; Safe Harbor requires removal of all 18 identifier categories plus the absence of actual knowledge of re-identifiability. Healthcare PHI is not a supported workload (`OQ-05`, resolved: claims excised).
> * **SOC 2 Type II is NOT claimed.** A Type II report evaluates operating effectiveness of an organisation's controls over an observation window (typically 6–12 months). A repository cannot evidence that. The rows below are a *SOC 2 Trust Services Criteria technical control mapping* only.
> * **SLSA levels are NOT claimed.** CI pins actions by SHA and uses a read-only token; no provenance attestation is produced.
> * **Formal Verification (Mechanized vs. Roadmap):** The core Information Flow Control (IFC) and noninterference theorems (`PROOF-I1`, `PROOF-I2`, `PROOF-I4`) and conjunctive authorization monotonicity (`F-021`) are mechanized in **Lean 4** (`v4.14.0`) under `proofs/lean4/` and verified by repository check `V23` (`scripts/check-lean.py`); remaining multi-agent Giry monad / Tamarin wire protocol proofs remain Phase-2 roadmap items (`FS-703..705 §8.3`).

---

## 1. Technical Control Design Mapping (Runnable `v1.0` Simulation)

| Framework / Criterion                                                   | Control Design (what the code does)                                                                                                                                                                                                              | Honest Limitation                                                                                                                                         | Executable Check (`scripts/verify-enclave.sh`)               |
|:------------------------------------------------------------------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------|:-------------------------------------------------------------|
| **GDPR Art. 4(5) — Pseudonymisation**                                   | `mcp/auth_proxy.py` replaces `C3` identifiers (email, phone, customer name) with **128-bit keyed `HMAC-SHA256` surrogates** under a per-session ephemeral key (`CUST_EMAIL_<32 hex>`). The reverse map is held in RAM with bounded TTL eviction. | Pseudonymised data **remains personal data** under GDPR (Art. 4(5), Recital 26). This is a data-minimisation control, not anonymisation.                  | `V13` (surrogate uncorrelated across sessions, TTL eviction) |
| **GDPR Art. 5(1)(c) / Art. 25 — Data minimisation by design**           | Column allowlist + `SELECT`-only recursive-descent SQL validator (rejects `*`, `t.*`, `UNION`, `ATTACH`, `PRAGMA`, multi-statement, `LIMIT > 50`) + SQLite `set_authorizer` read-only lock.                                                      | Validator covers the mock schema's SQL subset only.                                                                                                       | `V11`, `V12`                                                 |
| **GDPR Art. 32 — Security of processing**                               | `pf` egress quarantine for GID `_llmagent` (loopback `8443`/`11434` only; IPv4+IPv6 default-deny); mTLS with ECDSA P-256 local CA and `subjectAltName`; Envoy admin on a `0600` UNIX socket.                                                     | `pf` rules are validated by parser (and `pfctl -nf` on macOS) but **not loaded** by the bootstrap script; loading requires an operator `sudo pfctl` step. | `V05`, `V06`, `V07`                                          |
| **CCPA/CPRA § 1798.100(c) — Purpose-limited collection**                | Same SQL projection and record-count controls as Art. 5(1)(c).                                                                                                                                                                                   | Same.                                                                                                                                                     | `V11`                                                        |
| **SOC 2 TSC CC6.1 — Logical access (technical mapping)**                | Fail-closed Rego authorisation: explicit per-tool parameter validators, parameterised SPIFFE trust domain, unified tool aliases; RFC 9449 DPoP verification (`htm`, `htu`, `iat`, `jti` replay cache, ES256 signature).                          | DPoP keys are **software keys** (`SIMULATION_ONLY`), not SEP keys.                                                                                        | `V08`, `V10`                                                 |
| **SOC 2 TSC CC6.8 — Prevent unauthorised software (technical mapping)** | `codesign --verify --strict --verbose=4` with `returncode == 0` and strict `CodeDirectory flags=…(runtime)` parsing.                                                                                                                             | macOS-only; on Linux the check runs against a stub to prove the fail-closed path.                                                                         | `V09`                                                        |
| **SOC 2 TSC CC7.2 — Monitoring (technical mapping)**                    | Hash-chained JSONL audit journal (`prev_sha256` + `prev_blake3` when available, `log_seq_u64`, `ts_utc_ms`) per `schemas/enclave-audit-envelope-v1.schema.json`.                                                                                 | Single-host tamper *evidence* only; root can still delete the file (detected as a chain gap on next verify, not prevented).                               | `V16`                                                        |
| **PCI-DSS Req. 3.3/3.4 — Do not store PAN (design alignment)**          | PANs are **irreversibly erased** (`[REDACTED_PAN_C4]`) and never enter any vault, in every profile (`ADR-007`).                                                                                                                                  | No PCI scope assessment has been performed.                                                                                                               | `V17`                                                        |

---

## 2. Technical Control Implementation & Verification (Rust Workspace `crates/`)

`[Rust Production Reference Implementation — Implemented & Verified in crates/]`

| Criterion                              | Implemented Control (`crates/`)                                                                                                                                                                                                                                                                                                                                                                                                                         | Honest Technical Limitation                                                                                                                                                                                 | Verification Reference                                              |
|:---------------------------------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|:--------------------------------------------------------------------|
| GDPR Art. 5(1)(c), Art. 25             | `≤ 12,000 mb` / 24h QIF budget per `EntityKey` and a `global_unstructured_c3_c4_24h_pool` persisted in the journal checkpoint (`crates/enclave-agent-runtime/src/qif.rs`).                                                                                                                                                                                                                                                                              | Bounded quantitative tracking; does not eliminate risk of non-conforming inputs.                                                                                                                            | Unit tests in `crates/enclave-agent-runtime`                        |
| GDPR Art. 17 (erasure)                 | `HVZK` compliance rollups carrying zero personal data; raw witnesses destroyed immediately after folding (`crates/enclave-zk-auditor/src/zk/engine.rs`).                                                                                                                                                                                                                                                                                                | Zero-knowledge proof covers audit log validity, not arbitrary external state.                                                                                                                               | Tests in `crates/enclave-zk-auditor`                                |
| SOC 2 TSC CC6.1/CC6.2 (mapping)        | `L1 ⊂ L2 ⊂ L3` custody with chained Touch ID (`CoreAuthUI`) → YubiKey (`FIDO2 CTAP 2.1+`) on `A3`/`A4`; dual-key `Envelope_A3`/`Envelope_A4` (`crates/enclave-custody-vaultd/src/vault.rs`).                                                                                                                                                                                                                                                            | SOC 2 Type II is NOT claimed (attestation requires observation window by accredited auditor).                                                                                                               | Verified in `packaging/phase4/verify-phase4.sh`                     |
| Supply chain (no SLSA level claimed)   | 4-role TUF (`root → timestamp → snapshot → targets`), dual `blake3`/`sha256` target hashes, `allow_p2p_seeding` licence gate (`crates/enclave-swarm-syncd/src/tuf.rs`).                                                                                                                                                                                                                                                                                 | Canonical JSON OLPC standard enforced; local in-toto statement via `scripts/generate-slsa-provenance.py`.                                                                                                   | Tests in `crates/enclave-crypto` interop                            |
| GDPR Chapter V (Art. 44–49)            | `jurisdiction_shard ∈ {EU, US, APAC}` fencing of `L2` swarm peering and relays; relay connection state in RAM `≤ 5 min`, zero disk logs (`crates/enclave-swarm-syncd/src/service.rs`).                                                                                                                                                                                                                                                                  | Transfer Impact Assessment required per enterprise deployment; software enforcement only.                                                                                                                   | Tests in `crates/enclave-swarm-syncd`                               |
| Formal Assurance / Mathematical Proofs | Mechanized Lean 4 proof suite for Biba noninterference (`starlark_biba_noninterference`), QIF channel capacity bounds (`qif_24h_transcript_cardinality_bound` $\le 4096$), conjunctive authorization monotonicity (`conjunctive_monotonicity`), small-step control-flow noninterference (`SmallStepSemantics.lean`), Rust FlowGate bisimulation (`RustModelBridge.lean`), and stateful packet filter connection tracking (`StatefulPacketFilter.lean`). | Machine-checked in Lean 4 (`v4.14.0`) with 0 unproven axioms across 14 modules; models operational semantics of the Starlark capability subset and kernel quarantine. See `docs/FORMAL_METHODS_DEFENSE.md`. | Verified by check `V23` (`scripts/check-lean.py`) & `proofs/lean4/` |

---

## 3. Records of Processing, Retention, Purge & DSAR Schedule (GDPR Art. 30 / 15 / 17)

| Data Store                                            | Personal Data?                                                                 | Retention                                        | Purge Mechanism                                             | DSAR Access (Art. 15)                | DSAR Erasure (Art. 17)                                                                                 |
|:------------------------------------------------------|:-------------------------------------------------------------------------------|:-------------------------------------------------|:------------------------------------------------------------|:-------------------------------------|:-------------------------------------------------------------------------------------------------------|
| `_vault` reverse map (`v1.0` simulation, RAM)         | Yes (pseudonymised `C3`)                                                       | TTL `≤ 900 s` per entry, cleared at process exit | TTL eviction + process exit                                 | Not retained beyond session          | Automatic by TTL                                                                                       |
| `_piivault` (`UID 703`, `v3.0` target) HPKE vault     | Yes (`C3`; `C4` SSN/PHI only under `Custody::ReversibleTokenize` in `L2`/`L3`) | Session close or `< 8 h`, whichever first        | Key shredding (`sk_detok_a3_epoch`, `sk_detok_a4` zeroised) | Via `A4` export under 2-of-2 custody | Key shredding renders ciphertext unrecoverable                                                         |
| PAN / credentials / private keys                      | Never stored                                                                   | —                                                | Erased at ingress (`[REDACTED_PAN_C4]`)                     | N/A                                  | N/A                                                                                                    |
| Hash-chained `.jsonl` audit journals                  | **MUST contain zero raw PII** (counts and surrogate *classes* only)            | 90 days, then rotated and purged                 | Rotation with a sealed final `prev_*` digest                | Pseudonymous actor IDs only          | Not applicable if zero personal data is logged; if a defect logs PII, treat as incident (see `RB-204`) |
| `ComplianceRollupProofV1` (`v3.0` target)             | Designed to contain zero personal data (HVZK)                                  | 7 years                                          | Ledger retention policy                                     | N/A                                  | N/A                                                                                                    |
| `L2` swarm peer metadata / relay logs (`v3.0` target) | Yes (employee IP, SVID)                                                        | RAM only, `≤ 5 min`                              | Ephemeral                                                   | N/A                                  | Automatic                                                                                              |

A Data Protection Impact Assessment (Art. 35) is **required before any production deployment** and is not provided by this repository.

---

## 4. Sample Audit Record (Simulation Output Format)

The simulation writes one hash-chained JSON object per line. Values below are illustrative, generated by `python3 mcp/auth_proxy.py` — they are **not** live audit evidence from a production host.

<!-- schema: enclave-audit-envelope-v1 -->
```json
{
  "v": 1,
  "daemon_uid": 501,
  "boot_epoch_id": "6fe7229d-f77c-47ec-b370-69c20118296e",
  "log_seq_u64": 2,
  "rpc_seq_u64": 2,
  "ts_utc_ms": 1762308012405,
  "spiffe_id": "spiffe://corporate.internal/ns/developer/workload/code-assistant/501",
  "prev_sha256": "3b1f0c9b5d1e0a7f6c2d4e8a9b0c1d2e3f405162738495a6b7c8d9e0f1a2b3c4",
  "prev_blake3": null,
  "prev_poseidon2": null,
  "payload": {
    "method": "tools/call",
    "tool": "query_customer_db",
    "decision": "ALLOW",
    "pii_redacted": {"ssn": 1, "credit_card": 0, "email": 1, "phone": 1, "name": 1}
  }
}
```

`prev_blake3` is populated when the optional `blake3` Python package is installed; `prev_poseidon2` is reserved for the `v3.0` ZK journal fold (`FS-705`) and is `null` in the simulation.
