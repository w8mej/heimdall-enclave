# Security Policy & Vulnerability Disclosure

**Heimdall-Enclave** (formerly codenamed `depot`) is an enterprise-grade Zero-Trust Local Enclave and Information Flow Control (IFC) architecture engineered for Apple Silicon (`arm64e`, M1 through M5+) and macOS 14.0+ (Sonoma / Sequoia). It isolates on-device Large Language Models (LLMs) and Model Context Protocol (depot) agent workloads behind strict hardware, cryptographic, and kernel-level boundaries.

---

## 1. Scope & Architectural Tiers

Security evaluations and vulnerability reports are welcomed across all layers of the repository:

| Layer                             | Path                                               | Technical Foundation                                | Security Boundary & Invariants                                                                                                                                                                                     |
|:----------------------------------|:---------------------------------------------------|:----------------------------------------------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Production Enclave Core**       | `crates/enclave-core/`<br>`crates/enclave-crypto/` | Native Rust (`2021` edition)                        | Monotonic IFC labels ($C_1 \subset C_4, T_0 \subset T_3$), dual-key X25519 HPKE, RFC 9449 DPoP, Ed25519 PoP, Blake3 & Poseidon2 hash chains.                                                                       |
| **Enclave Daemons (UID 701–705)** | `crates/enclave-*d/`<br>`crates/depot-enclave/`      | Non-colluding LaunchDaemons                         | Discrete POSIX UIDs, zero-JIT execution, Unix Domain Sockets with Darwin `LOCAL_PEERTOKEN` / `getpeereid` peer authentication, strictly bounded RSS memory ceilings ($\le 152\text{ MiB}$ total for UIDs 702–705). |
| **Hardware Custody & Vault**      | `crates/enclave-custody-vaultd/`<br>`launchd/`     | Apple SEP, Touch ID (`CoreAuthUI`), FIDO2 CTAP 2.1+ | Chained Touch ID $\to$ YubiKey verification, dual-key isolation (`Envelope_A3` / `Envelope_A4`), atomic in-RAM boot-epoch monotonic counters, instantaneous memory zeroization on USB yank.                        |
| **Agent IFC & Policy Engine**     | `crates/enclave-agent-runtime/`<br>`policies/`     | `cedar-policy`, Biscuit v3 tokens, OPA Rego         | Structured `UserTurnV1` prompt/attachment separation, conjunctive `Cedar.Allow ∧ Biscuit.Allow` authorization ($p99 \le 45\mu\text{s}$ SLO), bounded 24h QIF entropy budgets, strict SQL AST validation.           |
| **Normative Specifications**      | `docs/FEATURE_*.md`<br>`schemas/`                  | Formal RFC 2119 specs                               | Mathematical consistency, lattice flow proofs, cryptographic soundness, and threat model integrity (`docs/THREAT_MODEL_STRIDE.md`).                                                                                |
| **Reference Simulations**         | `examples/executive-poc/`, `scripts/`              | Python / Shell test harnesses                       | Educational simulation verification, negative testing, and test harness integrity.                                                                                                                                 |

---

## 2. Supported Versions

| Branch / Release                 | Status                 | Security Updates                          |
|:---------------------------------|:-----------------------|:------------------------------------------|
| `main` (`v3.0.0-alpha.1`)        | Active Development     | Immediate patches and security advisories |
| Tagged Releases (`v3.0.x`)       | Supported              | Backported critical security fixes        |
| `v1.0-Legacy` (Python Prototype) | Archived / Educational | Simulation-bypass fixes only              |

---

## 3. Reporting a Vulnerability

We treat all security vulnerability disclosures with the highest priority.

### Primary Channel: GitHub Private Vulnerability Reporting

Please submit all vulnerability findings through GitHub's native **Private Vulnerability Reporting**:

1. Navigate to the repository's [**Security** tab](https://github.com).
2. Click **Advisories** $\to$ **Report a vulnerability**.
3. Fill out the report with technical details, steps to reproduce, affected files, and impact assessment.

### Alternative Channel: Encrypted Direct Contact

If GitHub Private Reporting is unavailable, contact the security maintainers via the designated contacts listed in [`.github/CODEOWNERS`](.github/CODEOWNERS) requesting a secure PGP/Signal communication channel.

### Submission Guidelines

To help us triage and resolve findings rapidly, please include:

- **Component**: Crate name, daemon UID (`UID 701–705`), policy, or specification section.
- **Vulnerability Class**: (e.g., Information Flow Control bypass, memory safety violation, cryptographic timing leak, privilege escalation, prompt injection boundary breach).
- **PoC / Steps to Reproduce**: Minimal reproducible code snippet, test payload, or counter-example trace.
- **Proposed Remediation**: Any code or policy diffs that remediate the flaw without regressing invariant tests.
- **Anonymized Data**: Never include real customer credentials, proprietary API keys, or live personal data.

---

## 4. Response & Remediation SLA

As an enterprise-grade security initiative, we adhere to coordinated disclosure guidelines:

| Milestones                    | Target Window      | Action Taken                                                                           |
|:------------------------------|:-------------------|:---------------------------------------------------------------------------------------|
| **Initial Acknowledgement**   | Within 24 hours    | Initial receipt confirmation and assigned lead security reviewer                       |
| **Triage & CVSS Scoring**     | Within 72 hours    | Vulnerability reproduced; CVSS v4.0 severity assigned                                  |
| **Remediation & Testing**     | 7–14 business days | Patch developed in a private fork and validated against regression test suites         |
| **Public Advisory & Release** | 30 days maximum    | Coordinated release of fixed version, credit attribution, and public CVE/GHSA advisory |

---

## 5. Security Research Safe Harbor

We support ethical, good-faith security research against this project:

- **Safe Harbor**: If you conduct vulnerability research in accordance with this policy, we will not pursue civil or criminal legal action against you.
- **Permitted Activities**: Auditing source code, running local fuzzers/linters, developing offline PoCs against `tests/` or local daemon sockets, and verifying cryptographic claims against specs.
- **Prohibited Activities**: Denial of Service (DoS) against developer infrastructure, physical attacks, or exfiltration of real production customer data.
