## 🔒 Security Patch & Boundary Hardening Pull Request

### Security Disclosure Context

* **Advisory Reference / Issue:** GHSA-____ / Issue #____
* **Severity Tier:** `sev/critical` | `sev/high` | `sev/medium` | `sev/low`
* **Affected Subsystems:** `crates/enclave-*` / `launchd` / `Seatbelt` / `PacketFilter`

---

### Threat Model & Invariant Certification

Every security patch must certify compliance with core zero-trust invariants:

* [ ] **STRIDE Delta Updated:** Updated [`docs/THREAT_MODEL_STRIDE.md`](../../docs/THREAT_MODEL_STRIDE.md) reflecting modified threat boundaries (`TB-01`..`TB-12`).
* [ ] **Fail-Closed Boundary:** All error branches, unexpected tokens, parse faults, and timeouts fail closed immediately.
* [ ] **Zero-PII Invariant:** No unmasked `C4` data (SSN, PAN, API credentials) written to plain logs, crash dumps, or memory.
* [ ] **Memory & RSS Budgets:** Preserved steady-state memory limits (total daemons $\le 152\text{ MiB}$; single daemon $\le 64\text{ MiB}$).
* [ ] **Darwin Sandbox Integrity:** Seatbelt `.sb` narrowing preserved; Packet Filter `pfctl` loopback rules intact.
* [ ] **Cryptographic Invariants:** Monotonicity preserved; key zeroization on drop; constant-time comparison for secrets.

---

### Adversarial & Negative Test Coverage
<!-- Provide details on the negative tests proving the attack payload is rejected -->
* [ ] Added negative test case in `tests/` or `crates/*/tests/` reproducing the exploit attempt.
* [ ] Ran `./scripts/verify-enclave.sh --ci-vm` with all checks passing.
* [ ] Ran `./scripts/lint-all.sh` with 0 security linter alerts.

---

### Mandatory Dual Security Reviewer Sign-Off

Per [`CONTRIBUTING.md §4`](../../CONTRIBUTING.md#L49), security-critical PRs require two distinct code owners:
* [ ] Security Reviewer 1 (Crypto & Low-Level Systems): `@username`
* [ ] Security Reviewer 2 (Threat Architecture & AI Safety): `@username`
