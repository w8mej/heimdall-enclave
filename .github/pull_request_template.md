## Description & Context
<!-- Provide a concise summary of the architectural changes, defect fixes, or security enhancements. Reference relevant ADRs or issue tickets. -->

Fixes / Closes #(issue)
Relevant Specifications: `FS-70`__/ `ADR-0`__

---

## Type of Change

- [ ] 🔒 **Security Fix** (Vulnerability mitigation, boundary reinforcement, cryptographic patch)
- [ ] 🏛️ **Architectural Feature** (New daemon functionality, policy rule, hardware custody bridge)
- [ ] ⚡ **Performance & SLO** (Latency reduction, RSS ceiling optimization, memory footprint reduction)
- [ ] 🧪 **Testing & Verification** (Adversarial test cases, ZK circuit benchmarks, negative test suites)
- [ ] 📜 **Documentation & Governance** (STRIDE updates, ADR authoring, specification sync)

---

## Security Invariants Checklist (Mandatory)

Every pull request to `Heimdall-Enclave` must certify compliance with the following zero-trust invariants:

- [ ] **Fail-Closed Boundary**: Unhandled errors, parse failures, or network timeouts fail closed immediately.
- [ ] **Zero Plaintext PII**: No raw PAN, SSN, or credentials written to unencrypted logs, crash dumps, or memory.
- [ ] **Zero-JIT Invariant**: No dynamic code execution (`allow-jit` is disabled; all WASI components pre-compiled or interpreted).
- [ ] **Memory & RSS Ceilings**: Daemon RSS remains strictly within its allotted budget (`UID 702–705` $\le 152\text{ MiB}$; total steady state $\le 200\text{ MiB}$).
- [ ] **Darwin Sandbox Integrity**: Seatbelt profiles (`.sb`) and `pf` anchors preserve strict network isolation (`UID 701` on loopback only; `UID 702` CAS egress only).
- [ ] **Cryptographic Invariants**:
  - [ ] Dual-key separation preserved (`Envelope_A3` vs. `Envelope_A4`).
  - [ ] Timestamps / sequence numbers monotonic and anchored to `boot_epoch_id`.
  - [ ] No raw hardware signatures transmitted out-of-circuit on `L3`.
- [ ] **Conjunctive Authorization**: All tool calls gate on `Cedar.Allow == true ∧ Biscuit.Allow == true`.

---

## Verification & Test Results
<!-- Paste terminal snippet demonstrating clean execution of ./scripts/lint-all.sh and relevant cargo tests -->

- [ ] `cargo check --workspace` passes cleanly.
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` passes with 0 warnings.
- [ ] `cargo fmt --all -- --check` passes cleanly.
- [ ] `cargo audit` passes cleanly against `.cargo/audit.toml`.
- [ ] `./scripts/lint-all.sh` completes 100% clean with 0 alerts across all stages.
- [ ] Negative / adversarial test added proving attack payload fails closed.

---

## Dual Security Review Sign-Off

- [ ] Security Reviewer 1 (Cryptography / Systems): `@username`
- [ ] Security Reviewer 2 (AI Security / Architecture): `@username`
