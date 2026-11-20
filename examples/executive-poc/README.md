# Executive-Sponsored Proof of Concept (PoC) — v1.0 Architectural Prototype

* **Status:** `HISTORICAL_PROTOTYPE` (Superseded by `v3.0` native Rust enclave in `crates/`)
* **Original Scope:** macOS Developer Workstation AI Governance Spike

---

## 1. Executive Context & Lineage

This directory archives the initial **Proof-of-Concept (PoC)** effort, which was sponsored by executive leadership to establish the feasibility of zero-trust containment for local AI agents and Model Context Protocol (MCP) workloads on Apple Silicon workstations.

At the time of this PoC, developer tools (Claude Code, local Ollama, LangChain) were increasingly accessing internal credentials and enterprise databases without operating system or kernel-level boundaries. This prototype validated three critical threat-model hypotheses:

1. **Packet Filter Egress Quarantine:** Proved that BSD Packet Filter (`pf`) loopback rules could strictly confine unprivileged AI processes without breaking developer workflows.
2. **SQL AST Read-Only Validation:** Demonstrated that recursive-descent SQL AST parsing could intercept and reject data-modification attempts (`ATTACH`, `PRAGMA`, multi-statement injections) before reaching backend databases.
3. **Keyed-HMAC PII Tokenization:** Confirmed that developer interactions could be pseudonymized at the workstation boundary using format-preserving tokens (`CUST_*`).

---

## 2. Evolution into the `v3.0` Native Rust Architecture

Following executive review and validation of the PoC's security properties, the initiative was sponsored to expand from this Python/Envoy/Rego simulation into the **production-grade native Rust workspace (`crates/`)** featuring:

* Privilege separation across 5 non-colluding LaunchDaemons (`UID 701–705`).
* Hardware Secure Enclave (SEP) P-256 custody and FIDO2 CTAP 2.1 YubiKey chained biometry.
* Sub-microsecond compiled `cedar-policy` Information Flow Control ($p99 \le 45\mu\text{s}$).
* Plonky3 zero-knowledge compliance rollups (`R_epoch`).
* Native turnkey MDM fleet delivery (`adapters/{jamf,kandji,munki,fleet,ansible}`).

---

## 3. Directory Layout

* **`mcp/`:** Python 3 reference MCP auth proxy (`auth_proxy.py`), inline DLP tokenizer (`dlp.py`), recursive SQL AST guard (`sql_guard.py`), and SHA-256 hash-chained audit logger (`audit_chain.py`).
* **`gateway/`:** Envoy mTLS local reverse proxy configuration (`envoy-local.yaml`) and BSD packet filter rules (`pf-rules.conf`).
* **`identity/`:** Software-key DPoP proof generator (`dpop.py`), Apple Silicon attestation validator (`macos_attestation.py`), and SPIRE agent configuration (`spire-agent-macos.conf`).
* **`policies/`:** Open Policy Agent (OPA) Rego authorization policies (`mcp_authz.rego`, `pii_guard.rego`, `data_masking.rego`).
