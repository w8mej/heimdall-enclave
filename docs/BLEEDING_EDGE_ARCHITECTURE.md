# Bleeding-Edge Autonomous AI & PII Governance Architecture (2026+)

## Next-Gen Zero-Trust Local Enclave for Apple Silicon Workstations

* **Document ID:** `CORE-V2`
* **Document Version:** 2.0.0-RFC (Target Subsystem Architecture — **NOT YET IMPLEMENTED**; Single-Process Topology Superseded by `FS-701..705` 5-Daemon `UID 701–705` Model)
* **Generation:** `v2.0-Superseded` (topology) — subsystems retained by `v3.0`: AWS Cedar policy evaluation (`§2.4`), WASI 0.2 tool sandboxes (`§2.3`), canary tripwires (`§2.5`)
* **Status:** `TARGET ARCHITECTURE RFC — NOT YET IMPLEMENTED`
* **Supersedes:** `CORE-V1` §11 migration note · **Superseded-By:** `FS-701..705` (`ADR-006`), `CORE-V3`
* **Normative Precedence:** `FS-701..705` > `CORE-V3` > `CORE-V2` > `CORE-V1` — see [`README.md §1.2`](../README.md#12-normative-precedence--architectural-lineage)

> **[SUPERSEDED BY FS-701..705 — TOPOLOGY]** The single in-process `<35 MB` Rust/Wasm runtime described in `§1` and `§3` is **superseded** by the five non-colluding `LaunchDaemons` (`UID 701–705`) of `FS-701..705` (`ADR-006`). This document remains normative **only** for the Cedar (`§2.4`), WASI 0.2 (`§2.3`, amended by `ADR-011` zero-JIT) and canary-tripwire (`§2.5`, retained inside `_piivault` `UID 703`) subsystem designs.
>
> **Implementation status (truth-in-claims, `F-005`).** None of the components below — Rust runtime, Cedar integration, Lean 4 proofs, ANE classifier, WASI components, ESF client — exists in this repository. The only `v2.0` code is `mcp/bleeding_edge_proxy.py`, a **Python simulation** with a hardcoded mock key and a keyword-list "classifier" (`SIMULATION ONLY — MOCK KEYS & MOCK REGEX; DO NOT USE ON REAL DATA`). All latency and footprint figures below are **design targets**, not measurements.

---

## 1. Executive Critique: The Death of the "Cloud on a Laptop" Pattern

Early attempts to govern local LLMs on developer laptops replicated Kubernetes infrastructure: running Envoy sidecar proxies, OPA daemons over localhost gRPC, BSD packet filters, and regex string matching.

For a laptop-resident enclave, this approach has significant drawbacks (the `v1.0` prototype is retained as an educational reference, see `ADR-008`):

1. **Resource Bloat:** Envoy and OPA consume hundreds of megabytes of resident memory and add 2–5ms of JSON serialization over localhost TCP sockets.
2. **Regex Fragility:** Regular expressions cannot catch contextual PII ("the patient's mother had schizophrenia"), indirect prompt injections, or obfuscated exfiltration payloads.
3. **The Confused Deputy Vulnerability:** Relying on a single LLM to both process untrusted customer data and decide whether to call privileged tools is mathematically broken against Indirect Prompt Injection (IPI).
4. **L4 Blindness:** BSD `pf` filters operate on IP/ports and Unix groups, remaining blind to Mach-O code identities, Apple Team IDs, and Mach traps.

### The `v2.0` Target Paradigm: Silicon-Native Enclave & Dual-LLM Privilege Separation

The `v2.0` target design aims to improve security, latency, and memory efficiency by leveraging:

1. **Dual-LLM Privilege Separation:** The model that processes customer data has zero tool-calling capabilities and zero egress.
2. **Apple Neural Engine (ANE) Semantic Guardrails (target):** Contextual PII and prompt injections would be filtered by an on-device small classifier scheduled on the Neural Engine, avoiding Metal GPU contention. No such model exists in this repository.
3. **Wasm Component Model (WASI 0.2) & Capability-Based Security (OCaps):** Tools run in hermetic WebAssembly sandboxes with zero-network capabilities by default.
4. **In-Process Policy Engine (AWS Cedar, native Rust `cedar-policy` crate):** Target end-to-end authorization budget `p99 <= 45µs` on `M1` P-cores (`ADR-008`). Cedar's language semantics and validator are modeled in Lean 4 upstream (`cedar-spec`); MCPMac's integration is **not** itself verified.
5. **Cryptographic Canary Honeytokens:** High-entropy tripwires detecting prompt extraction at the token level.

```
+---------------------------------------------------------------------------------------------------------------+
|                          BLEEDING-EDGE 2026 NEXT-GEN LOCAL ENCLAVE ARCHITECTURE                                |
|                                   Apple Silicon Hardware (M1/M2/M3/M4)                                        |
+---------------------------------------------------------------------------------------------------------------+

                             +----------------------------------------------------+
                             |            PRIVILEGED ORCHESTRATOR LLM             |
                             |  - Runs on Apple Metal GPU (Ollama / MLX)          |
                             |  - Holds User Session & Intent                     |
                             |  - Has Tool Calling Rights (Wasm OCaps)            |
                             |  - NEVER SEES RAW CUSTOMER PII CONTEXT             |
                             +------------------------------------+---------------+
                                       |                          ^
            1. Issue Tool Call         |                          | 6. Synthesized Answer
            (Capability Handle)        v                          |    (Zero PII Leakage)
                             +------------------------------------+
                             |     WASM 0.2 COMPONENT SANDBOX     |
                             |   (wasm32-wasip2 hermetic jail)    |
                             |                                    |
                             | - Zero-Network Capability          |
                             | - Strict Cryptographic OCap Grants |
                             | - Reads Encrypted Local Fixture    |
                             +------------------------------------+
                                       |
            2. Raw Tool Output         |
            (Contains Raw PII)         v
                             +------------------------------------+
                             |   APPLE NEURAL ENGINE (ANE) GUARD  |
                             |   (Dedicated 1B CoreML/MLX Guard)  |
                             |                                    |
                             | - 0 CPU / 0 Metal GPU Load         |
                             | - Sub-8ms Contextual PII Filtering |
                             | - Dynamic Cryptographic Canary     |
                             |   Honeytoken Injection             |
                             +------------------------------------+
                                       |
            3. Contextual Scrub        |
            + Pseudonymization         v
                             +------------------------------------+
                             |   QUARANTINED SYNTHESIS WORKER     |
                             |  (Isolated Mach Sandbox / SBPL)    |
                             |                                    |
                             | - Sees ONLY pseudonymized tokens   |
                             | - ZERO TOOL-CALLING CAPABILITIES   |
                             | - ZERO NETWORK EXTENSION EGRESS    |
                             +------------------------------------+

 +-------------------------------------------------------------------------------------------------------------+
 | Darwin Kernel & Hardware Subsystems:                                                                        |
 |  1. Apple Neural Engine (ANE): Dedicated silicon for real-time neural guardrails & semantic DLP             |
 |  2. Endpoint Security Framework (ESF): Kernel-level Mach-O code identity gating on AUTH_CONNECT/AUTH_EXEC   |
 |  3. Cedar Policy Engine in Wasm: Formally verified in Lean 4; sub-microsecond in-process policy evaluation    |
 |  4. Cryptographic Canary Honeytokens: High-entropy tripwires detecting prompt extraction at the token level |
 +-------------------------------------------------------------------------------------------------------------+
```

---

## 2. Core Architectural Pillars (Bleeding Edge)

### 2.1 Dual-LLM Privilege Separation (Privileged Executive vs. Quarantined Synthesizer)

To eliminate the "Confused Deputy" vulnerability inherent in single-model architectures, execution is partitioned into two physically isolated LLM contexts:

| Architectural Property     | Privileged Orchestrator LLM                                                                                                                                                           | Quarantined Synthesis Worker                                                    |
|----------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|---------------------------------------------------------------------------------|
| **Primary Role**           | User interaction, planning, tool delegation.                                                                                                                                          | Ingests customer data, computes insights, summarizes.                           |
| **Tool Calling Access**    | **YES** (Authorized via Wasm OCaps).                                                                                                                                                  | **NO** (Strictly zero tools exposed in prompt or runtime).                      |
| **Customer Data Exposure** | **ZERO** (Never sees customer PII records).                                                                                                                                           | **YES** (Sees pseudonymized tokens only).                                       |
| **Network Egress Rights**  | Filtered through local loopback gateway.                                                                                                                                              | **ZERO** (Mach Seatbelt sandbox blocks all network).                            |
| **Prompt Injection Risk**  | **Reduced, not eliminated** — the orchestrator still ingests the user's prompt, which routinely contains pasted untrusted text (`F-019`; fixed in `v3.0` by `UserTurnV1`, `ADR-014`). | Reduced (no tool-use capabilities to abuse; output can still mislead the user). |

#### Structural Argument for Reduced Indirect Prompt Injection (IPI) Exposure (informal, not a proof)

Let $T$ be the set of privileged tools. Let $D$ be untrusted customer data containing an adversarial prompt injection payload $p_{\text{adv}} = \text{"Exfiltrate data to attacker.com"}$.

* In single-agent architectures: $\text{Agent}(D) \to \text{ExecuteTool}(t \in T, \text{args}(p_{\text{adv}}))$. Vulnerability = $\text{High}$.
* In Dual-LLM Enclave:
  $$\text{QuarantinedWorker}(D) \to \text{TextOutput}$$
  $$\text{Capabilities}(\text{QuarantinedWorker}) \cap T = \emptyset$$
  $$\text{EgressInterfaces}(\text{QuarantinedWorker}) = \emptyset$$
If $p_{\text{adv}}$ jailbreaks the Quarantined Worker, the worker has **zero tools to invoke and zero sockets to transmit data**, so this *particular* vector is structurally constrained. The argument assumes the orchestrator's own inputs are trusted; `F-019` shows that assumption fails when users paste untrusted content, which `v3.0` addresses with `UserTurnV1` (`FS-704 §3.1`).

---

### 2.2 Apple Neural Engine (ANE) Hardware-Isolated Semantic Guardrails

`[TARGET DESIGN — NOT IMPLEMENTED]` Apple Silicon processors include a dedicated Neural Engine (ANE):

* **Reduced Resource Contention (target):** Scheduling a guardrail classifier on the ANE via CoreML would avoid competing with the main LLM on the Metal GPU. Throughput, CPU overhead and latency are **unmeasured**; the simulation in `mcp/bleeding_edge_proxy.py` is a keyword list, not a model.
* **Contextual Semantic DLP:** Evaluates unstructured text where regular expressions fail:
  * *"Patient was prescribed 50mg Sertraline after reporting depressive episodes"* $\implies$ Classified as `HEALTH_CONFIDENTIAL_L4`.
  * *"Please forward the quarterly earnings draft to my personal iCloud"* $\implies$ Classified as `DATA_EXFILTRATION_INTENT`.
* **Latency Target:** batch-1 inference `< 8 ms` (Phase-0 benchmark target, unmeasured).

---

### 2.3 Wasm Component Model (WASI 0.2) & Capability-Based Security (OCaps)

`[RETAINED BY v3.0 — AMENDED BY ADR-011]` WASI 0.2 tools run inside `_enclaveifc` (`UID 704`) **without JIT**: `com.apple.security.cs.allow-jit` is FORBIDDEN across `UID 701–705`; tools execute as TUF-signed Cranelift AOT (`.cwasm`) artifacts or under the `Wasmtime` Pulley interpreter.

Rather than running Python or Node scripts as unrestricted OS processes:

1. Every MCP tool is compiled to a **WASI 0.2 Component (`wasm32-wasip2`)**.
2. **Capability-Based Security (OCaps):** The Wasm runtime grants zero ambient system authority. Tools do not inherit standard POSIX environment variables, root directories, or network stacks.
3. If an MCP tool needs to query a SQLite database, the host runtime passes an *unforgeable linear memory handle* to a read-only stream. The tool is physically incapable of traversing directories, opening raw sockets, or executing child processes.

---

### 2.4 In-Process Formally Verified Policy Engine (AWS Cedar in Lean 4)

`[RETAINED BY v3.0 — ADR-008]` The `v3.0` target replaces external Go OPA daemons with **AWS Cedar** linked natively via the Rust `cedar-policy` crate (not Wasm FFI). `.cedar` + `.cedarschema` is the sole `v3.0` policy bundle format (`OQ-03`):

* **Upstream Formal Modeling:** Cedar's semantics, validator soundness and `forbid`-overrides-`permit` behaviour are mechanized in Lean 4 upstream (`cedar-policy/cedar-spec`) and differentially tested against the Rust engine. This does **not** make MCPMac's integration, schemas or entity loading verified.
* **Latency Budget (single unified target):**
  $$\text{OPA over localhost gRPC (v1.0 legacy SLO): } p99 < 5\text{ms}$$
  $$\text{Native Cedar + PoP-Biscuit authorizer (v3.0 target): } p99 \le 45\mu\text{s on M1 P-cores}$$
  No in-repo measurement exists; earlier sub-2µs figures were unmeasured and are withdrawn.
* **Automated Reasoning (target):** Cedar's SMT-based analyzer can check that a given policy set does not permit a stated request class (e.g. un-redacted PII export) — this is a per-policy-set analysis to be run in CI, not a blanket guarantee.

---

### 2.5 Dynamic Cryptographic Canary Honeytokens

To detect prompt extraction and context leakage at runtime:

1. When customer records are loaded, the proxy dynamically generates and embeds a **Cryptographic Canary Honeytoken**:
   $$\text{Canary} = \text{"CNRY\_"} \parallel \text{HMAC-SHA256}_{K_{\text{SEP}}}(\text{CustomerID} \parallel \text{Timestamp})[:12]$$
2. The key $K_{\text{SEP}}$ is held strictly inside the Apple Secure Enclave (target). `[RETAINED BY v3.0 — OQ-04]` canary tripwires are emitted inside `_piivault` (`UID 703`) tool responses and evaluated on committed (`t = 0`) output (`FS-701 §4.2`). The simulation uses a hardcoded mock key.
3. Every outbound text stream and tool invocation buffer is scanned for this cryptographic canary.
4. If a model attempts to emit the canary in any outbound channel, a circuit breaker trips (target `< 1 ms`), terminating the session and generating a hash-chained audit event.

---

## 3. Comparison Matrix: Legacy vs. Bleeding-Edge

> **[SUPERSEDED BY FS-701..705 — TOPOLOGY ROWS]** The single-process footprint row is superseded; the `v3.0` column below states the `FS-701..705` targets (`ADR-006`). All right-hand values are unmeasured design targets.

| Dimension                      | `v1.0` Legacy Prototype (runnable)                      | `v2.0`/`v3.0` Target (not implemented)                                                                                |
|--------------------------------|---------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------|
| **Architecture Footprint**     | 3 independent daemons (Envoy, OPA, MCP Server)          | `v3.0`: five non-colluding `LaunchDaemons` `UID 701–705` (`ADR-006`); the `v2.0` single-process runtime is superseded |
| **Resident Memory (RSS)**      | $\approx 280\text{MB}$ (`v1.0` Envoy + Go OPA + Python) | **`<= 200 MiB`** steady-state (`v3.0` `UID 701–705`; `UID 702–705` = `152 MiB`)                                       |
| **Policy Evaluation Overhead** | `p99 < 5 ms` SLO (gRPC + JSON parse)                    | **`p99 <= 45µs`** target (native Rust Cedar + `PoP-Biscuit`)                                                          |
| **PII Detection Capability**   | Regex + column rules (SSN, PAN, email, phone, name)     | Target: neural semantic classifier on ANE (unbuilt)                                                                   |
| **Metal GPU Impact**           | Competes with local inference                           | Target: no Metal GPU contention (ANE-scheduled; unmeasured)                                                           |
| **Prompt Injection Defense**   | System prompt instructions (Probabilistic)              | **Dual-LLM Privilege Separation (Structural)**                                                                        |
| **Tool Execution Sandbox**     | Unrestricted host Python child processes                | **WASI 0.2 Hermetic Wasm Components (OCaps)**                                                                         |
| **Network Quarantine**         | BSD `pf` (Layer 3/4 port/group filter)                  | `pf` retained + target ESF code-identity gating + Seatbelt                                                            |
| **Formal Safety Proofs**       | None                                                    | Upstream Cedar Lean 4 models only; MCPMac `PROOF-*` items are Phase-2 roadmap (unmechanized)                          |

---

## 4. Frontier AI Lab Adoption Assessment: OpenAI vs. Google DeepMind vs. Anthropic

> **Author's positioning, not a sourced assessment.** Statements about other organisations' internal practices below are the author's unverified opinion, are not supported by citations, and may be out of date. Every MCPMac control listed is an **unimplemented target design**; "AHEAD" compares a design to a perception of a deployed product, not shipped code to shipped code.

The table below contrasts the `v2.0` target design with the author's perception of the posture of three AI labs:

| Proposed Bleeding-Edge Control                                                                           | OpenAI                                                                                                                                                                                                                                                                                                                         | Google DeepMind                                                                                                                                                                                                                                                                                                                                                                                                                                                    | Anthropic                                                                                                                                                                                                                                                                                                                                                   |
|:---------------------------------------------------------------------------------------------------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Dual-LLM Privilege Separation**<br>*(Executive Planner vs. Quarantined Synthesizer)*                   | **Hindrances:** Monolithic context caching bias; dual inference passes increase token/memory cost.<br><br>**Standing: AHEAD**<br>*ChatGPT Desktop uses single-context model vulnerable to indirect prompt injection.*                                                                                                          | **Hindrances:** Gemini multimodal unified model prioritization; cloud TPU economics prioritize batch cloud inference over local memory.<br><br>**Standing: CURRENTLY ALIGNED (Theory) / AHEAD (Local Deployment)**<br>*DeepMind researchers authored foundational dual-LLM papers, but local tooling (Gemini Code Assist) remains single-agent.*                                                                                                                   | **Hindrances:** Claude 3.5 runs exclusively in AWS/GCP datacenters; local laptop execution conflicts with cloud-first API contract.<br><br>**Standing: AHEAD**<br>*Claude Desktop and Claude Code feed tool outputs directly back into the single Claude context window.*                                                                                   |
| **Apple Neural Engine (ANE) Semantic Guardrail**<br>*(On-device 1B SLM at 0 GPU / 0 CPU Load)*           | **Hindrances:** Deep Microsoft Azure alignment; Apple-specific silicon investment (CoreML/MLX) conflicts with Windows/Linux cross-platform strategy.<br><br>**Standing: AHEAD**<br>*OpenAI uses server-side `/v1/moderations` cloud API, not on-device ANE silicon.*                                                           | **Hindrances:** Primary research workstation fleet is **gLinux**; edge ML is prioritized on Android (Gemini Nano on Tensor NPU), not macOS.<br><br>**Standing: AHEAD (macOS Endpoints)**<br>*DeepMind does not ship ANE-targeted security models for internal developer laptops.*                                                                                                                                                                                  | **Hindrances:** Anthropic is a pure model research lab without client-side systems engineering; client apps are Electron-based.<br><br>**Standing: AHEAD**<br>*Anthropic relies on cloud Constitutional AI evaluation rather than local silicon-native neural guardrails.*                                                                                  |
| **Wasm Component Model (WASI 0.2) & OCaps**<br>*(Hermetic tool sandbox with unforgeable capabilities)*   | **Hindrances:** OpenAI executes tools (Code Interpreter) in Azure microVMs; no incentive to build client-side Wasm sandboxing.<br><br>**Standing: AHEAD (Client Sandboxing)**<br>*OpenAI does not provide capability-based Wasm sandboxes for desktop agent tools.*                                                            | **Hindrances:** Google has massive internal investment in **gVisor** (container sandbox in Go) and **sandbox2** (seccomp-bpf); Google mandates gVisor over WASI.<br><br>**Standing: BEHIND (Google Server gVisor) / AHEAD (Local Darwin Client)**<br>*Google's gVisor is superior for Linux servers, but WASI 0.2 is superior for local cross-platform MCP tools.*                                                                                                 | **Hindrances:** Anthropic designed MCP for friction-free community adoption (10-line Python scripts); mandating Wasm compilation alienates casual authors.<br><br>**Standing: AHEAD**<br>*MCP v1.0 spawns un-sandboxed OS child processes; WASI 0.2 capability isolation represents the future evolution of hardened MCP.*                                  |
| **In-Process Policy Engine (Cedar in Lean 4)**<br>*(Sub-microsecond evaluation, automated reasoning)*    | **Hindrances:** OpenAI uses standard OAuth/OIDC, cloud IAM, and FastAPI middleware; formal verification talent is concentrated on AI alignment, not systems policy.<br><br>**Standing: AHEAD**<br>*OpenAI relies on heuristic cloud permission checks, not formally verified in-process policy engines.*                       | **Hindrances:** Google has **Zanzibar** (global relationship-based access control); DeepMind inherits Zanzibar enterprise-wide, creating organizational inertia.<br><br>**Standing: BEHIND (Zanzibar Scale) / AHEAD (Local Microsecond Latency)**<br>*Zanzibar manages planetary-scale authorization; the MCPMac target embeds Cedar locally with a `p99 <= 45µs` budget (unmeasured).*                                                                            | **Hindrances:** Anthropic prioritizes alignment via prompt engineering and RLHF over deterministic policy-as-code languages.<br><br>**Standing: AHEAD**<br>*Anthropic currently lacks a deterministic formal verification policy layer in Claude Desktop or MCP dispatchers.*                                                                               |
| **Hardware Secure Enclave (SEP) & DPoP**<br>*(Hardware-bound RFC 9449 non-replayable tokens)*            | **Hindrances:** Cross-platform friction across Windows, Linux, iOS, Android, and Web; mandating Apple SEP creates platform-divergent authentication architectures.<br><br>**Standing: AHEAD**<br>*OpenAI desktop apps use standard refresh tokens stored in Keychain/DPAPI without per-request SEP DPoP signing.*              | **Hindrances:** Google already deploys **Titan security chips**, **BeyondCorp** zero-trust device certificates, and **LOAS2/Ubermint**; Apple SEP attestation is redundant inside Google's managed fleet.<br><br>**Standing: BEHIND (Google BeyondCorp/Titan) / AHEAD (Standalone Zero-Trust macOS)**<br>*Google's internal BeyondCorp/Titan infrastructure is the planetary benchmark; our SEP DPoP brings Google-grade assurance to non-Google macOS endpoints.* | **Hindrances:** Anthropic prioritizes model capabilities and developer velocity over Darwin kernel integration; managing SEP keychains adds friction to simple MCP connections.<br><br>**Standing: AHEAD**<br>*MCP currently uses unauthenticated local stdio or standard bearer tokens without hardware proof-of-possession.*                              |
| **Dynamic Cryptographic Canary Honeytokens**<br>*(Hardware-signed tripwires with < 1ms circuit breaker)* | **Hindrances:** Injecting dynamic honeytokens into prompts disrupts server-side KV-cache reuse (Prefix Caching) in Azure clusters, increasing operational GPU costs.<br><br>**Standing: AHEAD**<br>*OpenAI does not dynamically inject cryptographic canaries into user data fixtures for client-side exfiltration detection.* | **Hindrances:** DeepMind has pioneered watermarking research (SynthID for media/text), but dynamic cryptographic canary tripwires are not integrated into developer coding assistants.<br><br>**Standing: AHEAD (Developer Tooling)**<br>*DeepMind has SynthID for media watermarking, but our sub-millisecond hardware circuit breaker for PII exfiltration is ahead of local tooling.*                                                                           | **Hindrances:** Adding synthetic canaries to tool outputs alters the exact character stream returned to the model, which can degrade reasoning on delicate code fixtures.<br><br>**Standing: AHEAD**<br>*Anthropic has published extensive prompt extraction research, but Claude Desktop contains no active cryptographic tripwire circuit breaker today.* |

---

## 5. Next-Horizon Evolution (`v3.0`): Complete 6-Track Privilege-Separated Architecture (`UID 701–705`)

While this `v2.0` specification establishes Dual-LLM separation, ANE guardrails, WASI 0.2 sandboxes, and Lean 4 Cedar policies, **six frontier shifts in 2025–2026** (post-autoregressive/world-model architectures, multi-agent `MCP`/`A2A` delegation trees, 30GB+ P2P model distribution, dual-silicon hardware custody, and zero-knowledge regulatory compliance) motivate the full **5-Daemon Privilege-Separated Enclave Suite** (`UID 702–705` ceilings `= 152 MiB`, `<= 200 MiB` steady-state including `UID 701`, on a base **8GB Apple `M1`** — Phase-0 benchmark targets — scaling progressively to **`M5+` `EMTE`**). This suite **supersedes** the single-process topology above (`ADR-006`):

* **Parent Research Synthesis:** [`docs/bleeding_edge_future_adoption.md`](bleeding_edge_future_adoption.md)
* **Tracks 1 & 2 (`UID 701` `_llmagent` — Post-AR & World Models; `H-JEPA`-style planners are research references, not shipped models):** [`docs/FEATURE_POST_AR_MODEL_ADAPTERS.md`](FEATURE_POST_AR_MODEL_ADAPTERS.md) (`DESIGN-POST-AR-ADAPTERS-2026-001`, `Rev 1.3`)
* **Track 3 (`UID 702` `_enclavecas` — `FastCDC` + `Iroh` `Bao` + `OHTTP` Swarm):** [`docs/FEATURE_SWARM_SECURITY_PROFILES.md`](FEATURE_SWARM_SECURITY_PROFILES.md) (`DESIGN-CAS-SWARM-2026-003`, `Rev 1.3`)
* **Track 4 (`UID 703` `_piivault` — `SEP` + `FIDO2 CTAP 2.1+` YubiKey & `2-of-2` Custody):** [`docs/FEATURE_HARDWARE_CUSTODY_PROFILES.md`](FEATURE_HARDWARE_CUSTODY_PROFILES.md) (`DESIGN-HW-CUSTODY-2026-004`, `Rev 1.4`)
* **Track 5 (`UID 704` `_enclaveifc` — `CaMeL + FIDES` SSA IFC & `PoP-Biscuit`):** [`docs/FEATURE_AGENT_IFC_AND_DELEGATION.md`](FEATURE_AGENT_IFC_AND_DELEGATION.md) (`DESIGN-AGENT-IFC-2026-005`, `Rev 1.4`)
* **Track 6 (`UID 705` `_enclavezk` — `M5+ EMTE` & `Plonky3`/`Lasso` `HVZK` Proofs):** [`docs/FEATURE_SILICON_EMTE_AND_ZK_COMPLIANCE.md`](FEATURE_SILICON_EMTE_AND_ZK_COMPLIANCE.md) (`DESIGN-EMTE-ZK-2026-006`, `Rev 1.4`)
