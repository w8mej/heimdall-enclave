# Forward-Looking Research & Architectural Horizon (2026–2028)

## Preparing the Zero-Trust macOS AI Enclave for Post-Autoregressive Models, Swarm Distribution, and Hardware-Bound Cryptography

* **Document ID:** `CORE-V3`
* **Document Status:** Living Research Report & Collaborative Design RFC (`DRAFT v0.10` — remediation of `ADVERSARIAL_SPEC_REVIEW_2026-11-04`)
* **Generation:** `v3.0-Target` (cross-track synthesis) · **Supersedes:** `CORE-V2` single-process topology · **Superseded-By:** none
* **Normative Precedence:** `FS-701..705` (and `ADR-006+`) > **`CORE-V3` (this document)** > `CORE-V2` (Cedar & WASI 0.2 subsystems only) > `CORE-V1` (`v1.0-Legacy` prototype) — see [`README.md §1.2`](../README.md#12-normative-precedence--architectural-lineage). Where this synthesis and a feature specification disagree, the feature specification wins.
* **Implementation Status:** Nothing described here is implemented. Citations tagged `[Unverified]` could not be resolved to a public DOI, arXiv ID, RFC, or repository at the time of revision and MUST NOT be treated as available dependencies (`F-009`).
* **Target Baseline:** Universal Apple Silicon Compatibility (`M1` baseline through `M4`/`M5` progressive enhancement)
* **Research Horizon:** Applied Academic Literature & Frontier Systems Engineering (Late 2026 $\to$ Q4 2027)
* **Engineering Standard:** Google Distinguished Engineer / Principal Research Scientist Rigor

---

## Executive Thesis: Why 2026 Agent Enclaves Risk Obsolescence by 2028

Most local AI security architectures designed today embed three silent, brittle assumptions:

1. **The Autoregressive Text Assumption:** That models consume and emit discrete natural-language tokens (`str -> str`), making token-stream DLP, text-based Chain-of-Thought (CoT) monitors, and Dual-LLM text summaries sufficient.
2. **The Unicast Client-Server Assumption:** That policy bundles, Sparse Autoencoder (SAE) guardrail weights, and 30GB–140GB local model checkpoints can be pulled over standard HTTPS from centralized corporate registries without saturating VPNs or cloud egress budgets.
3. **The Ambient Session Identity Assumption:** That proving *machine* identity once at boot via the Apple Silicon Secure Enclave Processor (SEP) is equivalent to proving *per-action human intent* when an autonomous agent attempts a destructive or PII-exposing operation.

Across late-2025 and 2026 academic literature (IEEE S&P, USENIX Security, NDSS, ICML, NeurIPS) and frontier industry releases, **all three assumptions are actively breaking**:

* **Post-Autoregressive & Non-Transformer Paradigms:** Discriminative "System-1" evaluators (**TypeSafe AI's `jev`**, Sept 2026 `[Unverified]`), parallel **Diffusion & Flow-Matching LLMs (`LLaDA 2.0`, `Dream-7B`, `Mercury 2`, `FS-DFM`)**, constant-memory **State-Space & Test-Time Memory Models (`Mamba-3`, `RWKV-7`, Google `Titans` / `TTT`)**, tokenizer-free **Byte/Concept Models (`BLT`, `LCM`)**, Objective-Driven & Continuous Latent World Models (**Yann LeCun's `AMI Labs` `H-JEPA`/`EBM`** `[Research Horizon — no public weights]`, **Meta `V-JEPA 2`**, **DeepMind `Genie 3`** `[Non-Goal on 8GB M1 — ADR-018]`), and continuous latent reasoning (**`COCONUT`**, **`Huginn`**) shatter the left-to-right subword token stream assumption.
* **Content-Addressed P2P Swarms:** Enterprise model and policy synchronization is migrating toward Merkle-verified peer-to-peer protocols (**BitTorrent v2 BEP 52**, **Iroh QUIC/BLAKE3**, **CNCF Dragonfly + Nydus**).
* **Physical Per-Action Intent & Attenuated Capabilities:** Hardware keys (**FIDO2 `CTAP 2.1+` security keys, e.g. YubiKey 5 Series firmware `>= 5.7` for `Ed25519` or `>= 5.4` for `ES256`**), deterministic Information-Flow Control (**DeepMind `CaMeL`**, **Microsoft Research `FIDES`**), **Biscuit Datalog tokens**, and **Zero-Knowledge Proof-of-Redaction** (`NanoZK` `[Unverified]`, `FlashProve` `[Unverified]`) are candidate replacements for static bearer tokens and trust-based audit logs.

This research report synthesizes the foundational whitepapers, maps their concrete security implications for customer PII on macOS developer laptops, and defines the **modular extension seams** intended to let the enclave adopt each candidate technology without architectural rewrites. Readiness differs sharply by track (see the staged TRL table below); several tracks are research-engineering targets gated on Phase-0 benchmarks.

---

## Architecture Horizon Map (2026 Baseline $\to$ 2027/2028 Frontier)

```
+-------------------------------------------------------------------------------------------------------------------+
|                        NEXT-12-MONTH RESEARCH HORIZON: SEAMS & FUTURE-PROOFING TOPOLOGY                           |
+-------------------------------------------------------------------------------------------------------------------+

  [1. SWARM ARTIFACT PLANE]                      [2. DUAL-CUSTODY HARDWARE TRUST]
  BitTorrent v2 (BEP 52) / Iroh (BLAKE3 QUIC)    Apple Silicon SEP (M1-M5)  <---2-of-2--->  Local YubiKey 5.7+
  - 16KiB Bao Merkle chunk verification          (Machine Identity + M5 EMTE)  k-of-n/PRF  (CTAP 2.1+ Physical Touch
  - ORAS OCI Model/Policy/SAE Shards                                                         Per-Action Payload Sig)
                  |                                                                |
                  v                                                                v
+-------------------------------------------------------------------------------------------------------------------+
|                                 DETERMINISTIC IFC & CAPABILITY RUNTIME (CaMeL / FIDES)                            |
|  - Monotonic Dual Lattice SSA Handles:  Ref<v_i, Confidentiality C1..C4, TaintRisk T0..T3, EntityKeys>            |
|  - Multi-hop depot / A2A delegation via sender-constrained `PoP-Biscuit` Tokens (Datalog + Ed25519 PoP)             |
+-------------------------------------------------------------------------------------------------------------------+
         |                                                 |                                         |
         | Modality A: Post-AR Text/Decision             | Modality B: Visual/Latent World         | Modality C: Verifiable Audit
         v                                               v                                         v
+-----------------------------------+    +-----------------------------------------+      +-------------------------+
| POST-AUTOREGRESSIVE MODEL ADAPTER |    | WORLD MODEL & LATENT REASONING ENCLAVE  |      | ZK-COMPLIANCE PROVER    |
| (`jev`, `LLaDA`, `Mamba-3`, `BLT`)|    | (`AMI H-JEPA`/`EBM`, `V-JEPA 2`, `Genie`)|     | (`NanoZK` / `FlashProve`)|
|                                   |    |                                         |      |                         |
| - `jev` RLCD QIF Bit-Budget Diode |    | - `ScreenCaptureKit` Frame-Sync Masking |      | - Commit-and-Prove      |
| - `DINGO` DFA Diffusion Infilling |    | - Enclave `C_intrinsic = +Inf` MPC Gate |      |   Proof of Redaction    |
| - SSM/`Titans` CoW State Zeroize  |    | - `Smooth-LCM` LEACE/SAE & Latent Cone  |      | - Zero raw PII leaves   |
| - `BLT` Byte-DFA & `Huginn` Caps  |    |   Breakers on Apple Neural Engine (ANE) |      |   developer MacBook     |
+-----------------------------------+    +-----------------------------------------+      +-------------------------+
```

---

## Core Invariant Traceability Matrix & Shared Cross-Track Contracts (`F-004`, `F-039`)

### Retained / Amended / Superseded Mapping of `CORE-V1` and `CORE-V2` Requirements

| Core Requirement                                             | Source         | `v3.0` Disposition                                                                                                                                                            | Owning Spec        |
|:-------------------------------------------------------------|:---------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|:-------------------|
| `CORE-V1-R01` Invariant 1 — agent egress `⊆ {lo0}`           | `CORE-V1 §2.3` | **Amended-By** `FS-702 §2.4`: only `UID 702` (`_enclavecas`) may hold LAN/WAN/OHTTP sockets; `UID 701/703/704` remain loopback/UDS-only; `UID 705` holds `0` sockets          | `FS-702`           |
| `CORE-V1-R02` Invariant 2 — tool auth requires signed bundle | `CORE-V1 §2.3` | **Retained**; engine changes from OPA to `Cedar.Allow ∧ Biscuit.Allow` (`ADR-008`)                                                                                            | `FS-704`           |
| `CORE-V1-R03` Invariant 3 — `DetectPII(LLMContext) = ∅`      | `CORE-V1 §2.3` | **Amended-By** `FS-703 §2.4` (bounded `A3`/`A4` detokenization to a human, never into model context) and `FS-704 §2.4` (`≤ 12,000 mb`/24h QIF declassification of enums only) | `FS-703`, `FS-704` |
| `CORE-V1-R04` Invariant 4 — private keys in SEP              | `CORE-V1 §2.3` | **Retained** for `v3.0`; the Python simulations are explicitly non-compliant (`SIMULATION_ONLY`)                                                                              | `FS-703`           |
| `CORE-V1-R05` Invariant 5 — code-signed binaries             | `CORE-V1 §2.3` | **Retained**; mechanism becomes `LOCAL_PEERTOKEN` + `SecCodeCopyGuestWithAttributes` (`ADR-010`)                                                                              | `FS-702`, `FS-703` |
| `CORE-V1-R06` Laplace DP `ε = 0.1`/query, `ε_max = 2.0`/8h   | `CORE-V1 §4.4` | **Superseded-By** `12,000 mb` 24h `EntityKey` QIF + `global_unstructured_c3_c4_24h_pool` (`FS-704 §3.3`) and `Smooth-LCM` `d_χ`-privacy (`FS-701 §4.4`)                       | `FS-704`, `FS-701` |
| `CORE-V1-R07` SQL `SELECT`-only, no `*`, `max_records ≤ 50`  | `CORE-V1 §5.4` | **Retained** as AST validation (never substring matching, `F-037`) inside the `UID 704` WASI SQL wrapper                                                                      | `FS-704`           |
| `CORE-V2-R01` Dual-LLM privilege separation                  | `CORE-V2 §2.1` | **Amended-By** `CaMeL + FIDES` SSA handles with `UserTurnV1` prompt split (`ADR-014`)                                                                                         | `FS-704`           |
| `CORE-V2-R02` ANE semantic guard                             | `CORE-V2 §2.2` | **Retained** as a `UID 701` companion classifier (`Class 1`), not a separate runtime                                                                                          | `FS-701`           |
| `CORE-V2-R03` WASI 0.2 OCaps                                 | `CORE-V2 §2.3` | **Retained, Amended-By** `ADR-011` (zero-JIT: AOT `.cwasm` or Pulley)                                                                                                         | `FS-704`, `FS-705` |
| `CORE-V2-R04` In-process Cedar                               | `CORE-V2 §2.4` | **Retained**; native Rust crate, `p99 ≤ 45µs` (`ADR-008`)                                                                                                                     | `FS-704`           |
| `CORE-V2-R05` `CNRY_SEP_*` canary tripwires                  | `CORE-V2 §2.5` | **Retained** inside `_piivault` (`UID 703`) responses (`OQ-04`); evaluated on committed `t = 0` output plus `SONAR` cosine canaries (`FS-701 §4.2`)                           | `FS-703`, `FS-701` |
| `CORE-V2-R06` Single-process `<35MB` topology                | `CORE-V2 §3`   | **Superseded-By** 5-daemon `UID 701–705` (`ADR-006`)                                                                                                                          | all                |

### Shared `EnclaveAuditEnvelopeV1` Header (`MUST`, all five daemons)

Every line of `/var/log/enclave/{adapter,cas,custody,ifc,zk}-audit.jsonl` MUST be a JSON object validating against [`schemas/enclave-audit-envelope-v1.schema.json`](../schemas/enclave-audit-envelope-v1.schema.json):

```json
{ "v": 1, "daemon_uid": 704, "boot_epoch_id": "<uuid>", "log_seq_u64": 1042, "rpc_seq_u64": 8810,
  "ts_utc_ms": 1762308012405, "spiffe_id": "spiffe://<trust_domain>/enclave/uid/704",
  "prev_blake3": "<hex64>", "prev_poseidon2": "<8 x KoalaBear u32, hex>", "payload": { } }
```

* `rpc_seq_u64` is the cross-daemon join key consumed by `FS-705 §3.5` (`R_epoch` constraint 4). It is an in-RAM atomic `u64` anchored to a per-boot SEP-signed `boot_epoch_id` (`ADR-010`), **not** a per-RPC SEP NVRAM counter.
* `ts_utc_ms` (integer Unix epoch milliseconds) replaces the inconsistent `ts_unix_ms` / ISO-8601 `ts` fields of earlier revisions.
* `<trust_domain>` is a deployment parameter (default `corporate.internal`); `spiffe://local.dev/...` appears only in `L1` developer examples.

### Staged Technology Readiness (replaces the earlier blanket "TRL 7–9" claim, `F-009`)

| Track                          | Spec     | Readiness | Rationale                                                                                                  |
|:-------------------------------|:---------|:---------:|:-----------------------------------------------------------------------------------------------------------|
| 3 — CAS / TUF / OHTTP          | `FS-702` | `TRL 7–8` | Mature primitives (`FastCDC`, BLAKE3/`Bao`, TUF, RFC 9458)                                                 |
| 4 — SEP + `CTAP 2.1+` custody  | `FS-703` |  `TRL 7`  | Standard CTAP 2.1 commands; Darwin packaging (`ADR-010`) unvalidated                                       |
| 5 — `CaMeL`/`FIDES` + Biscuit  | `FS-704` | `TRL 4–5` | Published research prototypes; `PoPBiscuitWireV1` new                                                      |
| 1 & 2 — Post-AR / world models | `FS-701` | `TRL 3–5` | Phase-1 targets `LLaDA-8B`, `RWKV-7`, `EAGLE-3`, `V-JEPA 2`; `jev`/`AMI Labs` classes are research horizon |
| 6 — `M5 EMTE` + `Plonky3` IVC  | `FS-705` | `TRL 3–4` | Gated on Phase-0 `M1` prover benchmark and Apple entitlement verification                                  |

---

## Track 1: Day-1 Post-Autoregressive & Non-Transformer Model Governance (`jev`/RLCD, Diffusion `LLaDA`/`Dream`, `Mamba-3`/`RWKV-7`/`Titans`, `BLT`/`LCM`, `Huginn`/`EAGLE-3`)

If our open-source enclave ships on Day 1 assuming every local model is a causal, left-to-right, BPE-tokenized Autoregressive (AR) Transformer (`Llama`/`Qwen`), early adopters running 2025–2026 non-autoregressive or state-space weights on Apple Silicon (`MLX` / `CoreML` / `ANE`) will silently break structured tool constraints, KV-cache PII redaction, and streaming DLP. To guarantee **Day-1 model-agnostic support on M1–M5 Macs**, Track 1 expands beyond `jev` alone to govern all **five post-autoregressive local model families**.

### 1.1 Literature & Industry Signal: The 5 Beyond-Autoregressive Families on Apple Silicon

1. **Discriminative "System-1" Decision Models (`jev` & RLCD — TypeSafe AI, Almeida, Gafni, Sheng, Sept 2026 `[Unverified]`; Conformal Risk Control, Angelopoulos & Bates):** Replaces sequential chat generation with a non-autoregressive multi-head architecture trained via **Reinforcement Learning for Calibrated Decisions (RLCD)** using proper scoring rules (Brier / logarithmic loss) rather than sycophancy-prone RLHF. Accepts raw state (tickets, logs, DOM, SQL results) and emits strictly typed primitives (`Choice`/`Enum`, `bool`, ordinal `Score`, calibrated probabilities in $[0,1]$) in a single forward pass ($10\text{–}30\text{ms}$ on Apple ANE/MLX).
2. **Discrete Diffusion & Flow-Matching Language Models (`LLaDA` & `LLaDA 2.0`, Nie et al. 2025–2026; `Dream-7B`; Inception `Mercury 2`; Google `Gemini Diffusion`; Few-Step Discrete Flow Matching `FS-DFM`, 2025–2026):** Generates text via parallel, bidirectional iterative denoising ($x_T \to x_{T-1} \to \dots \to x_0$) or 8-step discrete flow matching across entire blocks simultaneously—shattering the memory-bandwidth wall at $>500\text{–}1,000+\text{ tok/s}$ without left-to-right ordering.
3. **State-Space Models (SSMs), Linear RNNs & Test-Time Neural Memory (`Mamba-2`/`Mamba-3`, Dao & Gu; `RWKV-7 "Goose"`; `Jamba` Hybrids; Google `Titans` & `TTT` Test-Time Training, 2025–2026):** Achieves $O(N)$ linear compute and $O(1)$ constant memory inference—making SSMs and `Titans` (which update neural long-term memory weights dynamically at test time across $2\text{M}+$ context tokens) prime candidates for 8GB–16GB developer MacBooks where Transformer KV-caches OOM.
4. **Tokenizer-Free Byte-Patch & Sentence-Concept Models (Meta `Byte Latent Transformer / BLT`, Pagnoni et al.; Meta `Large Concept Models / LCM` over `SONAR`, 2025–2026):** `BLT` eliminates BPE subword vocabularies entirely, grouping raw bytes into dynamic entropy-bounded patches; `LCM` performs diffusion/generation natively in 1024-dimensional multilingual `SONAR` sentence-concept space before surface decoding.
5. **Recurrent-Depth & Speculative Draft-Tree Models (`Huginn`, Geiping et al. 2025; `EAGLE-3` on `mlx-lm`, 2025–2026):** `Huginn` unrolls a shared core block recurrently for variable test-time compute depth ($r \in [1, 64]$) per token, while `EAGLE-3` verifies multi-branch draft token trees in parallel inside Apple Silicon unified memory.

### 1.2 Why Autoregressive Security Controls Shatter Across Non-AR Models

| Model Family                                                             | Broken Autoregressive Security Assumption                                                                                              | Concrete Day-1 Attack / PII Failure Mode on macOS                                                                                                                                                                                                                                                                                                                                                                                     |
|:-------------------------------------------------------------------------|:---------------------------------------------------------------------------------------------------------------------------------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **`1A. Discriminative System-1` (`jev`, RLCD Heads)**                    | Assumes Quarantined Worker is `str -> str` prose; ignores multi-query adaptive composition.                                            | Single calls prevent prose steganography, **but** a compromised orchestrator can play **"20-Questions" Adaptive Binary Search**—exfiltrating a 9-digit SSN ($\approx 30\text{ bits}$) across 30 sequential `bool` invocations!                                                                                                                                                                                                        |
| **`1B. Discrete Diffusion / Flow` (`LLaDA 2.0`, `Dream`, `FS-DFM`)**     | Assumes left-to-right token generation ($t_1 \to t_2 \to \dots$) for CFG/JSON logit masking (`Outlines`/`XGrammar`) and SSE token DLP. | 1. **Left-to-Right Grammar Crash:** Unmasking arbitrary middle-out positions simultaneously breaks prefix FSMs.<br>2. **Intermediate Denoising Priming & Leaks:** Adversarial suffixes prime early denoising steps ($t > 0$) past final-layer alignment, and intermediate steps transiently unmask raw memorized PII before $t=0$ convergence.                                                                                        |
| **`1C. SSMs & Test-Time Memory` (`Mamba-3`, `RWKV-7`, `Titans`, `TTT`)** | Assumes discrete per-token KV-cache slots that can be surgically sliced or evicted after tool calls.                                   | 1. **Continuous State PII Entanglement:** Customer PII from turn $k$ is mathematically superimposed into dense state $h_t \in \mathbb{R}^{d \times n}$ or `TTT` fast-weight deltas $\Delta W_t$—causing cross-session PII bleed and breaking GDPR erasure!<br>2. **Hidden State Poisoning (`HiSPA`):** Short crafted token bursts saturate SSM selective forget gates ($\Delta_t, B_t$), erasing system-prompt safety rules in $h_0$. |
| **`1D. Tokenizer-Free Byte / Concept` (`BLT`, `LCM`)**                   | Assumes fixed BPE subword token IDs for PII surrogate tags (`<PII_SSN_1>`) and vocabulary-level logit bans.                            | **`BLT` Byte-Boundary Split:** Dynamic entropy patching splits or mutates raw UTF-8/Base64 byte sequences seamlessly past BPE filters; **`LCM` Concept Bypass:** PII semantics are manipulated across 200 languages inside `SONAR` embeddings invisibly to text filters.                                                                                                                                                              |
| **`1E. Recurrent-Depth & Draft Trees` (`Huginn`, `EAGLE-3`)**            | Assumes fixed FLOPs per token and single-path causal emission without rejected GPU branches.                                           | 1. **Adaptive-Depth "Sponge" DoS:** Adversarial inputs prevent `Huginn` latent convergence, forcing $64\times$ recurrent loop burn and thermal throttling on fanless M1 Airs.<br>2. **Draft-Tree Side Channels:** `EAGLE-3` acceptance burst timing leaks token entropy and leaves rejected PII draft branches in unzeroed Metal memory.                                                                                              |

### 1.3 Day-1 Enclave Solution: The Universal `EnclaveModelAdapter` Contract

Rather than coupling the enclave to an OpenAI-style `chat/completions` text stream, every local model artifact registered via `enclave-cas` declares an immutable signed **`execution_class`** in its manifest, activating five mathematical & kernel-enforced adapters on Day 1:

```
+----------------------------------------------------------------------------------------------------------+
|                  UNIVERSAL ENCLAVE INFERENCE ABI (`EnclaveModelAdapter` — DAY-1 SUPPORT)                 |
+----------------------------------------------------------------------------------------------------------+
|  1. `DISCRIMINATIVE_RLCD` (`jev`, ANE Classifiers)                                                       |
|     -> Information-Theoretic Diode: I(Secret; Y) <= log2(|Y|) bits/call                                  |
|     -> Session QIF Privacy Budget Ledger in Cedar (`sum(log2|Y_i|) <= B_max` blocks 20-Questions leaks!) |
|     -> RLCD Proper-Scoring Calibration Gate (Neyman-Pearson alpha <= 10^-4 on Apple ANE)                 |
|                                                                                                          |
|  2. `DISCRETE_DIFFUSION` (`LLaDA 2.0`, `Dream-7B`, `FS-DFM`)                                             |
|     -> Automata-Infilling Constrained Diffusion (`DINGO` DP Trellis over DFAs/JSON Schema, <5% overhead) |
|     -> Buffered Denoising Barrier (zero t > 0 drafts cross IPC; `mlock` scratch zeroized at t = 0)       |
|     -> Refusal-Aware Early Commitment (`RAEC`) + ANE Step-Watchers at t in {0.75T, 0.5T, 0.25T, 0}       |
|                                                                                                          |
|  3. `RECURRENT_SSM_TTT` (`Mamba-3`, `RWKV-7`, `Jamba`, `Titans`, `TTT`)                                  |
|     -> Copy-on-Write `StateSnapshotDAG`: Freeze clean `h_sys`; fork disposable `h_task` + `Delta_W`      |
|     -> Mandatory `explicit_bzero()` (`memset_s`) of recurrent state & TTT fast weights on taint exit     |
|     -> Periodic System-Invariant Anchor Re-Injection (neutralizes `HiSPA` forget-gate saturation)        |
|                                                                                                          |
|  4. `BYTE_OR_CONCEPT` (`BLT`, `LCM` / `SONAR`)                                                           |
|     -> Byte-Level Deterministic Finite Automata (`Byte-DFA`) + UTF-8 NFC Canonicalization (`BLT`)        |
|     -> Pre-Decoder `SONAR` Concept-Space LEACE / Linear Safety Probes (`LCM`)                            |
|                                                                                                          |
|  5. `SPECULATIVE_OR_RECURRENT_DEPTH` (`Huginn`, `EAGLE-3`)                                               |
|     -> Hard Metal Watchdog Iteration Cap (`r <= r_max`, dynamically lowered when Thermal >= .fair)       |
|     -> Immediate Rejected-Draft-Tree Zeroization + 20ms Constant-Cadence IPC Pacing                      |
+----------------------------------------------------------------------------------------------------------+
```

#### Mathematical Anchor for `1A` (`jev` / RLCD Quarantine Diode + Anti-Binary-Search Ledger)

For a `jev`-class discriminative call over output schema $\mathcal{Y} = \mathcal{Y}_1 \times \dots \times \mathcal{Y}_m$, single-call Shannon leakage is strictly bounded:

$$I(\text{Secret}_{\text{PII}}; \text{Output}_{\text{jev}}) \le H(\mathcal{Y}) \le \sum_{j=1}^{m} \log_2 |\mathcal{Y}_j| \text{ bits}$$

To defeat **adaptive multi-query exfiltration, handle laundering, and pooled cohort group testing** across $K$ calls touching provenance taint set $\mathcal{E}(\text{input})$, our in-process Cedar/IFC state quantizes confidences to 4-bit deciles and tracks cumulative channel capacity per canonical subject key `EntityKey(e) = BLAKE3_keyed(K_vault, canonical_entity_id(e))`: $\forall e \in \mathcal{E}(\text{input}), \; C_{\text{cum}}(\text{EntityKey}(e)) + \log_2 |\mathcal{Y}^{(k)}| \le B_{\text{max}}$ (default $B_{\text{max}} = 12.0\text{ bits}$ over 24h—provably insufficient to reconstruct a 30-bit SSN, 53-bit PAN, or 80-bit email address before tripping a **Class `A3` hardware human-intent gate**!).

* **Full Feature & SRE Design Spec:** See [**`docs/FEATURE_POST_AR_MODEL_ADAPTERS.md`**](FEATURE_POST_AR_MODEL_ADAPTERS.md) (`DESIGN-POST-AR-ADAPTERS-2026-001`, `Rev 1.3`; `DESIGN-WORLD-MODELS-2026-002` was merged into it and retired) for the specification covering **all six execution classes** (unifying Tracks 1 & 2; Phase-1 adapter bring-up targets `LLaDA-8B`, `RWKV-7`, `EAGLE-3`, `V-JEPA 2` packaged via depot-owned `enclave-pack` tensor namespaces; `AMI Labs`-style `JEPA_EBM_WORLD_PLANNER` remains research horizon), two-layer static + runtime compute-graph attestation, dynamic 6-subsystem auto-adaptation across `L1`/`L2`/`L3`, the DeepMind/Anthropic/OpenAI/`AMI Labs` crosswalk, pre-publication How-To documentation scope, and Phase-2 formal proof obligations.

---

## Track 2: Objective-Driven World Models (`AMI Labs` `H-JEPA`/`EBM`, `V-JEPA 2`, `Genie 3`) & Latent Thought (`COCONUT`)

### 2.1 Literature & Industry Signal

* **`AMI Labs` — Objective-Driven `H-JEPA` & Energy-Based World Models (Yann LeCun, Alexandre LeBrun, Saining Xie, Pascale Fung, Michael Rabbat; reported March 2026 `[Unverified — no public weights or model format]`):** Operationalizes LeCun's *Autonomous Machine Intelligence (AMI)* blueprint as a non-generative, open-research alternative to LLMs targeting clinical healthcare (e.g., Nabla), industrial, and enterprise workflows. Rather than predicting tokens or pixels, `AMI` combines six coupled modules: **(1) Perception Encoder**, **(2) Hierarchical JEPA (`H-JEPA`) Multi-Timescale World Predictor**, **(3) Energy-Based Model (`EBM`) Cost Module** ($C_{\text{intrinsic}} + C_{\text{trainable}}$ outputting unnormalized scalar energy $F(x, y) \in \mathbb{R}$), **(4) Inference-Time `MPC` / `CEM` Action Trajectory Optimizer** ($\arg\min_{a_{0..T-1}} \sum_t C(\tilde{s}_t)$), **(5) Episodic Short-Term Memory (`STM`)**, and **(6) Top-Level `Configurator`**.
* **Joint-Embedding Predictive Architectures (`V-JEPA 2` & `V-JEPA 2-AC`, Assran, Bardes, LeCun et al., Meta FAIR 2025–2026):** Action-conditioned world models trained on $1\text{M}+$ hours of video and interaction streams predicting future state trajectories directly in abstract continuous representation space: $\hat{z}_{t+\Delta} = \text{Predictor}_\theta(z_t, a_t)$.
* **Generative Interactive World Models (`Genie 3`, Google DeepMind 2025–2026):** Action-conditioned spatio-temporal world simulators capable of modeling interactive environments and UI/physical state transitions. **Explicit Non-Goal (`ADR-018`):** generative pixel-world simulation is out of scope on 8GB `M1`; `FS-701 Class 6` confines GUI actuation to a sandboxed browser (`CDP`) with DOM/`AX` target resolution and a post-step prediction-surprise abort.
* **Continuous Latent Reasoning (`COCONUT`: *Chain of Continuous Thought*, Hao et al., Meta AI):** Models that feed continuous hidden states $h_t \in \mathbb{R}^d$ directly back as embeddings without projecting to discrete vocabulary tokens.
* **Representation Engineering & Circuit Breakers (*Representation Engineering*, Zou et al.; *Circuit Breakers*, Zou et al. / Gray Swan AI; Anthropic *Sparse Autoencoders* 2025–2026):** Intercepting and steering internal residual-stream manifolds rather than filtering input/output text.

### 2.2 New Threat Vectors on macOS Developer Laptops (Including `AMI Labs` `H-JEPA` / `EBM` Risks)

Over the next 12 months, developer and clinical/enterprise agents on macOS will incorporate **Objective-Driven World Models** (`AMI Labs` `H-JEPA`, `V-JEPA 2-AC`) and **Latent Reasoning Planners** (`COCONUT`):

1. **Total Blindness of Text/Token DLP:** When a `JEPA` encoder ingests a developer's macOS window containing a customer database table, clinical EHR chart, or Stripe dashboard, there is no UTF-8 string to run regex or NER tokenizers against—only dense `float16`/`bfloat16` embeddings in Apple Silicon Unified Memory.
2. **`EBM` Spurious Energy Valleys & `Configurator` Cost Hijacking (`AMI` Specific):** Because Energy-Based Models output unnormalized scalar energies $E \in (-\infty, +\infty)$ optimized at inference time via gradient descent ($\nabla_a E$) or Cross-Entropy Method (`CEM` / `MPC`), an out-of-distribution adversarial screen/DOM state can create a **spurious low-energy hallucination** where a destructive or PII-exfiltrating action ($a_{\text{exfil}}$) appears to minimize $C_{\text{trainable}}(\tilde{s}_{t+1})$.
3. **Hierarchical (`H-JEPA`) Confused-Deputy Escalation & Continuous Action Steganography:** In `H-JEPA`, a benign macro-goal approved at the slow timescale ($g_{\text{macro}}$) can decompose at the fast controller timescale into unauthorized micro-actions ($a_1, \dots, a_k$), or encode raw PII from **Short-Term Memory (`STM`)** into continuous action floats (cursor `(x, y)` sub-pixel coordinates or timing delays).
4. **Embedding Inversion on Episodic `STM` (*Vec2Text* / *Vec2Pix*, Morris et al.) & "Dark Reasoning" (`COCONUT`):** Persistent `JEPA` `STM` buffers retain recoverable biometric/textual PII across episodes unless scrubbed, while `COCONUT` continuous thought plans multi-step trajectories with zero English CoT tokens.

### 2.3 Next-Gen Defenses: Geometric & Energy-Barrier Security in Unified Memory

1. **Pre-Encoder Visual/DOM Masking at `ScreenCaptureKit` Boundary:** Before frames hit a `JEPA` perception encoder on Apple Metal, leverage macOS native Accessibility (`AXUIElement`) bounding-box metadata + ultra-fast ANE region classifiers to redact sensitive DOM/window regions at the `IOSurface` GPU buffer level.
2. **Hardwired Enclave $C_{\text{intrinsic}}$ Energy Barrier inside the `MPC` Loop (`AMI` Adapter):** Rather than trusting neural $C_{\text{trainable}}$ weights alone, our Day-1 `JEPA_EBM_WORLD_PLANNER` adapter ([`FEATURE_POST_AR_MODEL_ADAPTERS.md` Class 6](FEATURE_POST_AR_MODEL_ADAPTERS.md)) injects a deterministic **Enclave Intrinsic Cost Barrier** directly into every `MPC`/`CEM` rollout step:
   $$E_{\text{total}}(\tilde{s}_{t+1}, a_t) = C_{\text{model}}(\tilde{s}_{t+1}, a_t) + \underbrace{\mathbb{I}_{\text{Cedar/IFC\_Violation}}(a_t) \cdot (+\infty)}_{\text{Deterministic Policy Barrier}} + \underbrace{\mathbb{I}_{\text{SafetyCone}}(\tilde{s}_{t+1}) \cdot (+\infty)}_{\text{ANE Latent Circuit Breaker}}$$
   Any rollout trajectory touching unauthorized PII sinks or prohibited geometric latent cones receives $+\infty$ energy *before* action selection, combined with **Conformal Energy Quantile Calibration** over unnormalized EBM scores. Because $\tilde{s}_{t+1}$ is the model's own *prediction*, the barrier alone is insufficient (`F-026`): Cedar MUST evaluate the **DOM/`AX`-resolved target** of $a_t$, and a **post-step surprise gate** ($\lVert \text{Encoder}(x_{t+1}) - \tilde{s}_{t+1} \rVert_2 > \tau_{\text{surprise}} \Rightarrow$ abort) MUST halt multi-step actuation (`FS-701 §4.6`).
3. **Hierarchical `H-JEPA` `Biscuit` Attenuation, Action Quantization & `STM` Zeroization:** Macro-goals $g_{\text{macro}}$ mint attenuated `Biscuit` tokens bounding the low-level `H-JEPA` action space; continuous GUI/tool parameters pass through an **Action Quantization Diode** (snapping sub-pixel floats to discrete semantic `AXUIElement` IDs); and episodic `STM` buffers run inside `mlock()` Copy-on-Write arenas wiped via `LEACE` + `explicit_bzero()` on episode exit.

---

## Track 3: Content-Addressed P2P & Swarm Distribution (`FastCDC`, `Iroh` BLAKE3/Bao, `R2`, `Dragonfly`)

### 3.1 Literature & Industry Signal

* **BitTorrent v2 Specification (`BEP 52`):** Replaces legacy SHA-1 flat piece lists with **SHA-256 Merkle hash trees** at 16KiB leaf-block granularity, enabling immediate sub-piece cryptographic verification.
* **`Iroh` & `Bao` Verified Streaming (n0 computer — Rust QUIC + BLAKE3 Merkle Trees, used in Nous Research *Psyche* 2025–2026):** Peer-to-peer QUIC transport with NAT hole-punching and **ARM64 NEON SIMD-accelerated BLAKE3 (`Bao`)** verified byte-range streaming ($>6\text{ GB/s}$ verification throughput on Apple M1).
* **Content-Defined Chunking (`FastCDC`, Xia et al. USENIX ATC; HuggingFace `Xet` / `hf_xet` 2025–2026):** Splits `.safetensors` model weights and bundles using a fast Gear-based rolling hash (~64KB variable blocks) so fine-tunes, quantized updates, and policy edits share 80%–98% identical content-addressed chunks.
* **CNCF `Dragonfly` + `Nydus` RAFS & `Cloudflare R2` Zero-Egress CAS:** Enterprise Kubernetes P2P scheduling (`Dragonfly`) vs. serverless S3-compatible object storage with \$0.00 egress fees (`R2`) acting as an immortal cold WebSeed.

### 3.2 Candidate Architecture Showdown: Startup TCO vs. Security vs. Developer Friction

P2P distribution on developer laptops is historically a flashpoint between **Platform/DevEx teams** (who hate slow 30GB downloads *and* hate background agents ruining Zoom calls or battery life), **CorpIT/SecOps** (who block BitTorrent ports and fear poisoned peers), and **Startup Leadership** (who refuse to pay \$2,000/month in Kubernetes DevOps overhead).

Evaluating the three candidate stacks reveals a clear architectural winner:

| Evaluation Criterion                     | Option A: Raw BitTorrent v2 (`BEP 52`)                                                                                         | Option B: `CNCF Dragonfly` + `Harbor` OCI                                                                               | Option C (Recommended): **`FastCDC` + `Iroh` (`Bao`/QUIC) + `Cloudflare R2` Zero-Egress Seed**                                                                                                                              |
|:-----------------------------------------|:-------------------------------------------------------------------------------------------------------------------------------|:------------------------------------------------------------------------------------------------------------------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Startup Infra Cost (100GB Artifacts)** | Low (requires custom private TLS tracker VM: ~\$15–\$40/mo)                                                                    | **High / Prohibitive for Startups** (K8s Scheduler, Seed-Peer StatefulSets, Redis/DB: **\$800–\$2,500+/mo** + SRE toil) | **Near-Zero (~\$1.50/mo total)** — Cloudflare R2 charges \$0.015/GB-mo storage and **\$0.00 egress**; zero control-plane servers required for LAN/R2 mode.                                                                  |
| **CorpIT / Firewall Compatibility**      | **Poor** — Triggers enterprise IDS/IPS BitTorrent signatures; blocked by Wi-Fi client isolation or strict UDP filters.         | **Medium** — Works inside K8s VPCs, awkward to expose safely to roaming WFH developer MacBooks.                         | **Excellent** — Pure HTTP/3 & QUIC (`UDP/443`) with automatic HTTPS/TLS 1.3 fallback to R2; indistinguishable from standard web traffic.                                                                                    |
| **Delta Update Efficiency**              | **Poor** — Fixed-size pieces mean inserting metadata at offset 0 of a 32GB `.safetensors` file invalidates *every* chunk hash. | **Medium** — Layer-based OCI diffs still re-pull multi-GB layers on single weight changes.                              | **Bleeding-Edge (`FastCDC` / `Xet`)** — Gear rolling-hash chunking deduplicates unchanged transformer layers; updating an adapter or policy pulls **only the 2% changed chunks**.                                           |
| **Developer Cold-Start Friction**        | **High** — Must allocate files and complete piece assembly before `mmap` load.                                                 | **Low** (with `Nydus` FUSE daemon, though FUSE kexts require macOS Recovery Mode approval!).                            | **Ultra-Low (Zero Kext!)** — Fetches `.safetensors` JSON header first ($<80\text{ms}$) and streams active layers via user-space HTTP-Range / macOS `FileProvider` or `FUSE-T` (NFSv4 loopback, **zero kernel extension!**). |
| **Cryptographic Poisoning Defense**      | SHA-256 16KiB Merkle tree (`BEP 52`).                                                                                          | SHA-256 per-blob/chunk manifest check.                                                                                  | **BLAKE3 `Bao` Verified Streaming** — Verifies every 1KiB–16KiB slice in RAM at $>6\text{ GB/s}$ on M1 NEON *before* touching APFS or `mmap`.                                                                               |

### 3.3 Solving the DevEx Contention Point: Kernel-Enforced Zero Battery & Zero Uplink DoS

To win unanimous support from developer-supporting teams, the local swarm client must **provably never degrade laptop battery, thermal headroom, or interactive video/coding latency**. Instead of brittle user-space rate limiters, we bind directly to four native Darwin / XNU kernel primitives (supported across M1 through M5):

1. **XNU Kernel Scavenger Congestion Control (`SO_TRAFFIC_CLASS = SO_TC_BK_SYS`):**
   * Every outbound swarm socket sets the Darwin socket option `setsockopt(fd, SOL_SOCKET, SO_TRAFFIC_CLASS, &SO_TC_BK_SYS, ...)`—the exact kernel primitive Apple uses for background macOS Software Updates.
   * **Hardware/Kernel Effect:** XNU switches congestion control to **LEDBAT++ (Low Extra Delay Background Transport)** and tags Wi-Fi frames with **WMM `AC_BK` (Background Access Category)**. The instant a developer speaks on Zoom, runs `git push`, or queries an API, any router/AP queuing delay $>5\text{ms}$ causes the XNU kernel to collapse the P2P upload window to near-zero within **1 RTT**—mathematically eliminating residential asymmetric uplink DoS!
2. **Power, Hotspot & Metered Link Hardware Gates (`IOKit` + `Network.framework`):**
   * Subscribes to `IOPSNotificationCreateRunLoopSource` (AC vs. Battery), `NSProcessInfoPowerStateDidChange` (macOS Low Power Mode), and `NWParameters`:
     * `prohibitExpensivePaths = true` (instantly blocks iPhone Personal Hotspot / cellular `pdp_ip0` tethering).
     * `prohibitConstrainedPaths = true` (instantly respects macOS Low Data Mode).
   * **Hard Invariant:** Peer *seeding* is physically disabled the millisecond AC power is unplugged; battery-powered laptops act strictly as *leeches/pullers* for required deltas only.
3. **Apple Silicon Thermal Throttle Yield (`ProcessInfo.thermalState`):**
   * Subscribes to `ProcessInfo.thermalStateDidChangeNotification`. If local compilation or Metal LLM inference pushes an M1 MacBook Air (fanless!) from `.nominal` to `.fair`, `.serious`, or `.critical`, background chunk verification and seeding pause immediately.

### 3.4 Progressive Security Tiers: Startup Day-1 Simplicity to Defense-Grade Isolation

Rather than forcing a one-size-fits-all deployment, the `cas://blake3-bao-v1/<root_hash>` resolver (hash-agile `cas://<alg>/<digest>` syntax, `F-028`) supports **three policy-selectable security profiles**—all retaining full `SO_TC_BK_SYS` / `IOKit` Battery & Uplink DoS protection:

```
+-------------------------------------------------------------------------------------------------------------+
|                        TIERED SWARM SECURITY PROFILES (SINGLE ARCHITECTURE, 3 MODES)                        |
+-----------------------------------+-----------------------------------+-------------------------------------+
| Profile L1: `startup-zero-ops`    | Profile L2: `enterprise-mesh`     | Profile L3: `classified-enclave`    |
| (~$1.50/mo | Zero Servers)        | (Private Capability Swarm)        | (Zero-Seed / OHTTP / Sealed APFS)   |
+-----------------------------------+-----------------------------------+-------------------------------------+
| - Discovery: Office LAN Bonjour   | - Discovery: Private mTLS         | - Discovery: P2P Seeding HARD OFF   |
|   (`_enclave-cas._udp.local`)     |   `iroh-relay` / WireGuard mesh   |   (Pull-only from attested origins) |
| - Fallback: Cloudflare R2 HTTPS   | - Anti-Enumeration: QUIC ALPN     | - IP Privacy: Oblivious HTTP        |
|   ($0 egress presigned chunks)    |   requires valid `Biscuit` token  |   (RFC 9458) hides laptop IP        |
| - Integrity: 4-role TUF + Rekor    |   *before* revealing held hashes  | - Crypto: Convergent ChaCha20-AEAD  |
|   root sig + BLAKE3 `Bao` stream  | - Poisoning: Bad chunk auto-revokes|   + m-of-n YubiKey TUF root sigs    |
| - QoS: LEDBAT++ & AC-power-only   |   offending peer's SPIFFE SVID    | - Storage: Read-only APFS snapshot  |
+-----------------------------------+-----------------------------------+-------------------------------------+
```

#### Threat Matrix Covered Across Tiers

| Swarm Attack Vector                                   | Technical Mechanism                                                                                       | Zero-Trust Architectural Countermeasure                                                                                                                            |   Active In    |
|-------------------------------------------------------|-----------------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------|:--------------:|
| **Developer Battery / Uplink DoS**                    | Seeding drains battery on flights, burns cellular hotspot quota, or chokes home Zoom upload.              | **XNU `SO_TC_BK_SYS` (LEDBAT++ + WMM `AC_BK`)** + `IOKit` AC-power check + `prohibitExpensivePaths` + thermal yield.                                               | **L1, L2, L3** |
| **Tensor Shard Poisoning**                            | Compromised peer serves Trojan bit-flipped `.safetensors` weights or tampered Cedar rules.                | Out-of-band **TUF + Sigstore Rekor** root hash + **16KiB `Bao` BLAKE3 Merkle** RAM verification before disk write.                                                 | **L1, L2, L3** |
| **Deserialization RCE**                               | Malicious pickle bytecode inside `.pt`/`.pkl` checkpoints executes on load.                               | **Strict `safetensors` / MLX / `.cedar` format invariant** (zero executable bytecode loaders) + `uchg` immutable flags.                                            | **L1, L2, L3** |
| **Swarm Peer Enumeration & Clearance Fingerprinting** | Rogue insider joins swarm to observe *which* laptops hold `policy-m&a-secret` or restricted fraud models. | **Zero Public DHTs + Capability-Gated QUIC Handshake:** Peers must prove a valid `Biscuit` / SPIFFE capability for the artifact namespace before hash negotiation. |   **L2, L3**   |
| **Traffic Analysis of Remote Executives/Engineers**   | Untrusted ISP or storage CDN correlates developer IP addresses with model/policy fetch timings.           | **Oblivious HTTP (RFC 9458)** relay decouples client IP from R2/origin chunk fetches + pull-only zero-seeding mode.                                                |     **L3**     |

### 3.5 Architectural Readiness Seam & Full Feature Spec

* **Full Feature & SRE Design Spec:** See [**`docs/FEATURE_SWARM_SECURITY_PROFILES.md`**](FEATURE_SWARM_SECURITY_PROFILES.md) (`DESIGN-CAS-SWARM-2026-003`, `Rev 1.3`) for the specification covering `L1`/`L2`/`L3`, 4-role TUF (`root → timestamp → snapshot → targets`), `allow_p2p_seeding` licence gating, `jurisdiction_shard` GDPR fencing, `ORAS`/OCI v1.1 layout, namespace-keyed convergent AEAD, the five Darwin kernel/tunnel/lazy-`mmap`/firewall paradox resolutions, the DeepMind/Anthropic/OpenAI standards crosswalk, and the Phase-2 formal verification proof obligations.
* **Design Preparation:** Replace file-path/HTTPS-coupled bundle loaders in our `sync-agent` with a **Content-Addressed Artifact URI Resolver** (`cas://blake3-bao-v1/<logical_plaintext_hex64>?target=<slug>&ns=<namespace>&min_profile=L1|L2|L3&rekor=<log_index>`). Startups boot in `L1` with a \$1.50/month Cloudflare R2 bucket and instant office LAN mDNS swarming, and graduate to `L2`/`L3` solely via TUF-enforced policy configuration without changing a single URI.

---

## Track 4: Cumulative Hardware Custody Tiers (`L1 ⊂ L2 ⊂ L3`) & Monotonic Action Intent Signing (`Apple SEP`, `Touch ID`, `FIDO2 CTAP 2.1+` YubiKey & `2-of-2` Split Custody)

### 4.1 Literature & Industry Signal

* **FIDO2 `CTAP 2.1+` & YubiKey 5.7+:** Hardware `authenticatorGetAssertion (0x02)` over RFC 8785 JCS intent digests passed as the opaque 32-byte `clientDataHash`, `hmac-secret` PRF key wrapping, and `pinUvAuthProtocol=2` bus encryption. **No CTAP 2.2/2.3 extension is used** (`F-008`): `Ed25519` (COSE `-8`) on YubiKey firmware `>= 5.7`, or `ES256` (COSE `-7`) on `>= 5.4`. Screenless keys provide physical presence (`UP=1`), not a trusted display — the trusted display is SIP-protected `CoreAuthUI` (`ADR-009`).
* **Hardware-Gated depot (`depotkey` & Out-of-Band Agent Approval Patterns, 2025–2026):** Halting high-consequence depot JSON-RPC calls to bind physical human touch on an external EAL6+ Secure Element (`NXP` / `Infineon`) directly to the canonical RFC 8785 (JCS) SHA-256 digest of the tool payload.
* **Split-Key Hardware Custody & Discrete Quorums (`2-of-2` Dual-Chip HKDF + `k`-of-`n` `Ed25519`):** Splitting cryptographic authority across disjoint silicon roots of trust (`Apple Silicon SEP` + external `YubiKey`) so no single compromised OS kernel, Electron RCE, or microcontroller can sign or unwrap secrets unilaterally. Multi-party approvals use **discrete `k`-of-`n` `Ed25519` multi-signatures** — `k` independent standard CTAP 2.1 assertions from distinct enrolled keys — because stock YubiKey firmware cannot run interactive threshold Schnorr protocols (RFC 9591 is therefore not used, `ADR-013`).
* **Apple `LocalAuthentication` (`LAContext` + `.biometryCurrentSet`) & Darwin `IOKit` HID Observers:** Native Apple Silicon `SEP` biometric key gating paired with sub-millisecond kernel USB removal interrupts (`kIOTerminatedNotification`).

### 4.2 Why Apple Silicon SEP Alone Is Insufficient at Higher Tiers ("The Post-Unlock Open Door")

Our baseline anchors machine identity in the Apple Silicon Secure Enclave Processor (`SEP`). While `SEP` prevents raw private-key *extraction*, consider what happens when an enterprise developer's MacBook is **unlocked** and hit by a malicious npm/PyPI post-install script, rogue VS Code extension, or Electron RCE:

1. **Confused-Deputy Abuse of Non-Interactive Keys:** Routine SEP keys (configured without `.biometryCurrentSet` so background depot calls do not spam Touch ID popups every 30 seconds) can be invoked via `Security.framework` IPC by compromised user-space processes running under the developer's UID.
2. **Blind Biometric Prompts ("What You See != What SEP Signs"):** Standard macOS Touch ID system dialogs authenticate *who* touched the fingerprint sensor, not *which exact SQL AST or depot arguments* are being signed—unless bound to a hardened intent surface (`L1`) or signed inside an air-gapped USB-C hardware token over a canonical JCS payload digest (`L2`/`L3`).

### 4.3 Unified Architecture: Cumulative Custody Tiers (`L1 ⊂ L2 ⊂ L3`) $\times$ Monotonic Action Classes (`A1 < A2 < A3 < A4`)

Rather than implementing `SEP`, `Touch ID`, per-action `CTAP 2.1+` signing, `2-of-2` split-key vault custody, and USB yank-to-zeroize as disconnected mix-and-match toggles (which creates $2^N$ untested state permutations), the enclave implements **one unified `HardwareCustodyEngine` trait** organized along two **strictly monotonic scales** (where **a larger number ALWAYS means higher risk and stronger hardware assurance**, matching Track 3's `L1`–`L3` 1-to-1):

1. **Cumulative Hardware Custody Profiles (`L1 ⊂ L2 ⊂ L3`):** Higher profiles strictly subsume and compose all controls from lower profiles:

   ```
   +---------------------------------------------------------------------------------------------------------------+
   |                  UNIFIED HARDWARE CUSTODY ENGINE — STRICTLY NESTED TIERS (`L1 ⊂ L2 ⊂ L3`)                     |
   +-------------------------------------+------------------------------------+------------------------------------+
   | Profile L1: `sep-biometric`         | Profile L2: `step-up-yubikey`      | Profile L3: `dual-custody-deadman` |
   | ($0 Extra HW | Startup Day-1)       | (L1 + Per-Action CTAP 2.1+ Intent) | (L2 + 2-of-2 Vault + Yank-Zeroize) |
   +-------------------------------------+------------------------------------+------------------------------------+
   | - Hardware: Built-in Apple SEP      | - Hardware: Apple SEP + Touch ID + | - Hardware: Continuously Present   |
   |   + MacBook Touch ID ONLY ($0 key)  |   YubiKey ONLY on A3/A4 actions    |   Apple SEP + YubiKey 5.7+ (2-of-2)|
   | - Vault: 1-of-1 SEP-wrapped key     | - Airplane-Safe Routine: `Tokenize | - Vault: Dual-Chip HKDF (`SEP ||   |
   |   (wiped on lid-close sleep)        |   -Only` mode works with NO key!   |   YubiKey PRF`) at morning unlock  |
   | - Critical A3 Gate: Touch ID bound  | - Critical A3 Gate: Touch ID       | - Dead-Man's Switch: CPU <0.5ms +  |
   |   to Hardened JCS Digest Sheet      |   (CoreAuthUI) -> YubiKey tap, JCS |   GPU/ANE fence <=4.5ms on USB yank|
   +-------------------------------------+------------------------------------+------------------------------------+
   ```

2. **Monotonic Action Sensitivity Classes (`A1 < A2 < A3 < A4`):** Every enclave operation across Tracks 1–6 maps deterministically to one of four increasing risk classes:

| Action Class *(Larger = Higher Risk)* | Concrete Enclave Triggers (Across Tracks 1–6)                                                                                                                          | **`L1` (`startup-zero-ops`)**<br>*Apple SEP + Touch ID Only (\$0)*                                           | **`L2` (`enterprise-mesh`)**<br>*`L1` + Per-Action YubiKey Step-Up*                                                                       | **`L3` (`classified-enclave`)**<br>*`L2` + 2-of-2 Vault + Yank-Wipe*                                                |
|:--------------------------------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------|:-------------------------------------------------------------------------------------------------------------|:------------------------------------------------------------------------------------------------------------------------------------------|:--------------------------------------------------------------------------------------------------------------------|
| **`A1: Routine Tokenized`**           | Scrubbed SQL reads (`SYNTH-SSN-...`), `jev` call $\le 12\text{b}$ QIF cap, local `LLaDA`/`Mamba-3` code gen                                                            | **0 Prompts:** Non-interactive Apple SEP workload key + DPoP                                                 | **0 Prompts (100% Airplane-Safe!):** SEP workload key; **no YubiKey plugged in needed**                                                   | **0 Extra Touch Prompts:** Requires YubiKey inserted (`2-of-2` unlocked vault) + SEP DPoP                           |
| **`A2: Elevated Session`**            | Cross-tool joins, reading `INTERNAL` schemas, refreshing `L2` `Biscuit` swarm lease                                                                                    | **15-min Touch ID Lease** (`LAContext` biometric cache)                                                      | **15-min Touch ID Lease** + `Biscuit` Datalog attenuation check                                                                           | **15-min Bound Lease:** Touch ID + continuous `IOKit` YubiKey USB presence                                          |
| **`A3: Critical Intent`**             | **Single-record `C3` detokenization** (or `C4` only under `Custody::ReversibleTokenize` in `L2`/`L3`, `ADR-007`), `jev` $>12\text{b}$ QIF step-up, schema DDL mutation | **Per-Action Touch ID** bound to SIP-protected `CoreAuthUI` JCS payload-digest sheet (`.biometryCurrentSet`) | **Chained `Touch ID` (`CoreAuthUI`) $\to$ `YubiKey` Tap** (`CTAP 2.1` `UP=1` over exact RFC 8785 JCS hash) — restores `L1 ⊂ L2` (`F-013`) | **Chained `Touch ID` $\to$ `YubiKey` Co-Signature** (`PIN/UV=1`, `10s` window) + synchronous ZK egress gate         |
| **`A4: Extreme / Break-Glass`**       | **Bulk (`> 1`-row) or `C4` export** (never in `L1`, which erases `C4`), world-model OOD safety override, firewall bypass, local/org TUF root mutation                  | **Per-Action Touch ID + Out-of-Band OIDC Re-Auth**                                                           | **Chained `Touch ID` $\to$ `YubiKey` Co-Signature** *(+ `k`-of-`n` `Ed25519` lead quorum for org TUF)*                                    | **Chained `Touch ID` $\to$ `YubiKey` Co-Signature** *(+ offline `k`-of-`n` `Ed25519` YubiKey quorum for org roots)* |

### 4.4 Core Cryptographic, Ergonomic & Darwin Kernel Mechanics

1. **Canonical RFC 8785 (JCS) Signing & Chained `Touch ID` $\to$ `YubiKey` Co-Signature (`A3` / `A4`):**
   * Before executing any `A3`/`A4` action, the depot Proxy canonicalizes `(spiffe_id, model_blake3, tool_name, canonical_arguments, qif_bits_delta, monotonic_ts, policy_hash)` under RFC 8785 (JCS) and computes $d_{\text{JCS}} = \text{SHA-256}(\text{payload})$.
   * **Removed (`F-013`):** The earlier single-touch YubiKey-only `L2` `A3` gate dropped Touch ID and `CoreAuthUI`, violating `L1 ⊂ L2`. Every `A3` and `A4` action in `L2` and `L3` now uses the chained co-signature below.
   * **Chained Dual-Silicon Biometric Co-Signature (`L2` & `L3` Classes `A3`+`A4`):** Rather than relying on a flush-mounted YubiKey 5C Nano's non-biometric touch sensor alone (vulnerable to shoulder-reach taps) or requiring a typed keyboard FIDO2 PIN (vulnerable to user-space keyloggers), the enclave cryptographically chains **Apple `SEP` live fingerprint verification** directly into the **YubiKey `CTAP 2.1` `authenticatorGetAssertion` challenge** inside a strict `10-second` monotonic window:
     $$\sigma_{\text{SEP}} = \text{Sign}_{\text{AppleSEP\_BiometryCurrentSet}}\big(d_{\text{JCS}} \parallel \text{nonce}_{\text{enclave}}\big), \qquad \sigma_{\text{YubiKey}} = \text{Sign}_{\text{YubiKey\_CTAP2.1}}\Big(\text{SHA-256}\big(d_{\text{JCS}} \parallel \sigma_{\text{SEP}}\big)\Big)$$
     The developer rests their finger on MacBook Touch ID and slides 3 inches to tap the flashing YubiKey (**~1.5s total gesture, zero keystrokes, two independent hardware Secure Elements**).
2. **`L2` "Airplane-Safe" Asymmetric Vault Mode vs. `L3` Dual-Hardware `2-of-2` Split Custody:**
   * **Why `L2` Passes the "Airplane Test":** In `L2`, routine `A1`/`A2` PII scrubbing runs inside a privilege-separated `UID 703` `_piivault` `LaunchDaemon` (verifying callers via kernel `audit_token_t` `cdhash` pinning) in **asymmetric HPKE `Tokenize-Only` mode** with **two cryptographically independent X25519 keypairs** (`ADR-009`, `F-012`): `C3` surrogates are sealed under `pk_detok_a3_epoch` (`Envelope_A3`, at most `64` per epoch before re-key), while all `C4` surrogates and every bulk set are sealed **exclusively** under `pk_detok_a4` (`Envelope_A4`). No decryption key exists in RAM while the YubiKey is unplugged; unwrapping `Envelope_A3` reveals zero bits of `sk_detok_a4`. Both envelopes require chained Touch ID + YubiKey `PRF` (`pinUvAuthProtocol=2`).
   * **How `L3` Enforces Dual-Silicon Custody:** For regulated workloads (HIPAA / PCI-DSS Level 1 / M&A data rooms), the symmetric key $K_{\text{vault}}$ wrapping the `mlock()`-pinned PII vault is derived at morning unlock via **Dual-Hardware HKDF**:
     $$K_{\text{vault}} = \text{HKDF-SHA256}\Big(\text{IKM} = \text{ECDH}_{\text{SEP}}\big(\text{sk}_{\text{SEP}}, Q_{\text{eph}}(s_t)\big) \;\parallel\; \text{FIDO2-PRF}_{\text{YubiKey}}(s_t), \;\text{salt}=s_t, \;\text{info}=\text{"enclave-l3-vault-v2"}\Big)$$
3. **Physical Dead-Man's Switch (`IOKit` Yank-to-Zeroize), Screen-Lock Wipe & Zero-Brick Recovery (`L3`):**
   * **Yank-to-Zeroize (`< 5ms`) & Screen-Lock Zeroize (`Cmd+Ctrl+Q`):** Per-daemon kernel `IOKit` `IOServiceAddMatchingNotification(kIOTerminatedNotification)` ports (paired with `<35/day` event-driven `CTAP2 up=false` anti-spoof attestation) watch the YubiKey USB HID node, while `com.apple.screenIsLocked` catches docked walk-aways. Pulling the YubiKey out of USB-C triggers `<0.5ms` `VM_PROT_NONE` freeze + fence-synchronized GPU+ANE+CPU zeroization (`MTLBlitCommandEncoder::fillBuffer(0)`, ANE `IOSurface` scrub, `Class 5` `20ms` IPC ring drop, and `explicit_bzero()`) over $K_{\text{vault}}$, $K_{\text{cas\_session}}$, and tainted Track 1/2 arenas—sterilizing the laptop even while macOS stays unlocked!
   * **Zero-Brick Guarantee:** Because laptop vaults hold *ephemeral in-memory session translation tables* (never persistent production databases on disk), losing a YubiKey on travel **never bricks enterprise data**—the ephemeral session simply self-zeroizes until a backup FIDO2 key is enrolled.
4. **Closed-Clamshell External Monitor Ergonomics (`M1`–`M5` Docked Desks):**
   * When a MacBook is docked in **closed-clamshell mode** (`AppleClamshellState == true`), external Apple Magic Keyboards with Touch ID satisfy `.biometryCurrentSet` natively over Apple's encrypted Secure Enclave channel; if docked with a third-party non-biometric keyboard, `A2` routes to YubiKey `FIDO2 UV` (`PIN + touch`), while extreme `A4` / `L3` co-signatures require opening the lid, Magic Keyboard Touch ID, or an enrolled biometric **YubiKey Bio** + SEP co-signature (never downgrading dual-silicon biometric assurance).

### 4.5 Architectural Readiness Seam & Full Feature Spec

* **Full Feature & SRE Design Spec:** See [**`docs/FEATURE_HARDWARE_CUSTODY_PROFILES.md`**](FEATURE_HARDWARE_CUSTODY_PROFILES.md) (`DESIGN-HW-CUSTODY-2026-004`, `Rev 1.4`) for the specification covering `L1 ⊂ L2 ⊂ L3` $\times$ `A1..A4`, dual-key vault tier separation, `.app`-bundled `UID 703` SEP packaging, the chained `Touch ID -> YubiKey` co-signature protocol, WindowServer anti-occlusion defenses, USB dock-glitch debounce without security windows, the DeepMind/Anthropic/OpenAI crosswalk, and Phase-2 formal proofs.
* **Design Preparation:** Isolate all hardware signing, session leases, vault key derivation, and dead-man's zeroize callbacks behind a single Rust/Swift trait (`HardwareCustodyEngine` implementing `attest_a1()`, `lease_a2()`, `authorize_intent_a3(jcs_digest)`, `authorize_extreme_a4(jcs_digest)`, and `on_hardware_yank()`), automatically bound to the workstation's effective `L1` / `L2` / `L3` posture.

---

## Track 5: Deterministic Information-Flow Control (`CaMeL`, `FIDES`) & `PoP-Biscuit` Multi-Hop Delegation

### 5.1 Literature & Industry Signal

* **`CaMeL` (*"Defeating Prompt Injections by Design"*, Debenedetti, Shumailov, Fan, Carlini, Papernot et al. — Google, Google DeepMind, ETH Zurich; arXiv:2503.18813, March 2025):** Extracts an explicit Python-subset dataflow graph from the trusted user prompt *before* touching untrusted data. Every value carries capabilities and provenance metadata enforced by a deterministic interpreter—solving 77% of `AgentDojo` tasks with **provable zero-exfiltration guarantees** (while failing ~23% of tasks requiring dynamic data-dependent branching).
* **`FIDES` (*"Securing AI Agents with Information-Flow Control"*, Costa, Köpf, Paverd, Russinovich, Zanella-Béguelin et al. — Microsoft Research; arXiv:2505.23643, May 2025):** Formalizes Denning-style security lattices tracking Confidentiality and Untrusted Taint across agent loops, using constrained *Selective-Hide Variable Declassifiers* (`jev`-compatible!) to support dynamic branching safely.
* **Multi-Tool Attack Surfaces (*Cross-Tool Harvesting and Polluting / XTHP*, NDSS 2025/2026; *StruQ*, USENIX Security 2025):** Demonstrates how attackers chain benign-looking read tools into benign-looking write tools (e.g., GitHub Issue comment $\to$ local SQLite lookup $\to$ Jira ticket update) when taint isn't tracked across hops.
* **`Biscuit` Tokens & `AIP` (*Agent Identity Protocol for Verifiable Delegation Across depot and A2A*, arXiv 2026; IETF AAT Drafts):** Replaces ambient OAuth 2.1 tokens and nested-JWT UCANs (quadratic size bloat) with **Biscuit tokens**—cryptographic tokens carrying **embedded Datalog policy blocks** upgraded with sender **Proof-of-Possession (`PoP`)** across multi-hop depot and Agent-to-Agent (`A2A`) sub-agent trees.

### 5.2 Unified `EnclaveFlowEngine` (`UID 704`): Monotonic Dual Lattice, `CaMeL+FIDES` SSA Handles & `PoP-Biscuit` Delegation

When developers run **multi-agent teams** (`Planner` $\to$ `Issue Triage` $\to$ `DB Researcher` $\to$ `Refactorer` $\to$ `Git PR Writer`), `EnclaveFlowEngine` replaces static two-box Dual-LLM separation across **`L1 ⊂ L2 ⊂ L3`**:

1. **Universal Monotonic Dual Lattice ($\mathcal{L} = \mathcal{C} \times \mathcal{T}$, Join $\sqcup = \max$):** Every SSA value handle (`$v_i`), file descriptor, and sink carries `(Confidentiality C1..C4, TaintRisk T0..T3)` where **a larger number always signifies higher sensitivity/danger** (`C1: Public < C2: Internal < C3: Confidential < C4: Restricted L4 PII` and `T0: Signed System Root < T1: Short User Directive (UserTurnV1.directive_short ≤ 512B) < T2: Enclave-Verified < T3: Untrusted External` — pasted text, files and stacktraces are `T3` attachments, never `T1`, `ADR-014`), aligning 1-to-1 with `L1..L3` and `A1..A4`!
2. **Opaque SSA Capability Handles (`Ref<v_i>`) + `FIDES`/`jev` Bounded-Entropy Branch Gates (Solving `CaMeL`'s 23% Gap):** Raw `C3`/`C4` and `T3` strings stay sealed inside `_enclaveifc`'s `mlock()`/`EMTE` Capability Heap (`UID 704`, pre-tokenized under HPKE in `L2` Airplane Mode), preventing context-wide "taint explosion." When a Starlark plan must branch on runtime data (`declassify_enum($v_log, Enum[ServiceTarget])`), an ephemeral `Class 1` (`jev`) / `Class 2` (`DINGO` DFA) worker extracts *only* a closed finite enum (`T3 -> T2`, dropping `C` only for Cedar-allowlisted routing metadata), deducts integer millibits ($\lceil 1000 \log_2 |\mathcal{Y}| \rceil$) from `_enclaveifc`'s `SEP`-sealed 24h `EntityKey` QIF journal, and rolls back its `StateSnapshotDAG` leaf in `<0.2ms`!
3. **Sender-Constrained `PoP-Biscuit` Attenuation, FD-Relative `openat(O_RDONLY | O_NOFOLLOW | O_CLOEXEC)` Allowlists & Additive QIF Conservation:** Sub-agents receive in-memory attenuated `PoPBiscuitWireV1` tokens (CBOR wrapping a standard sealed Biscuit v3 token, `ADR-015`) (`<45µs` verify, `i64` millibit arithmetic, `authorizer`-scoped facts) bound to an ephemeral `Ed25519` PoP key + dual-transport channel binding (`audit_token_t` `cdhash` locally; RFC 9266 `tls-exporter` + SPIFFE on `L2` A2A) + 64-bit sliding replay bitmap, `openat(O_NOFOLLOW)` APFS case-folded `AST-Slot Projection`, and **conserved QIF slices ($\sum_i B_i \le B_{\text{parent}}$)** defeating fork-bomb privacy amplification.
4. **8GB Base `M1` Multiplexing & `L1 ⊂ L2 ⊂ L3` Scaling:** Up to 8 concurrent sub-agents share Track 3's single `MAP_PRIVATE` / `clonefile(2)` weight mapping inside `<512 KiB` Starlark/Wasm capability micro-frames (`<= 32 MiB` total RSS), scaling from value capabilities (`L1`) to hard Biba `AST-Slot` + QIF gating (`L2`) and constant-control-flow (`20ms` quantized) oblivious execution + `<5ms` USB yank / `Cmd+Ctrl+Q` Capability Heap zeroization (`L3`).

### 5.3 Architectural Readiness Seam & Full Feature Spec

* **Full Feature & SRE Design Spec:** See [**`docs/FEATURE_AGENT_IFC_AND_DELEGATION.md`**](FEATURE_AGENT_IFC_AND_DELEGATION.md) (`DESIGN-AGENT-IFC-2026-005`, `Rev 1.4`) for the specification covering `C1..C4` $\times$ `T0..T3`, `UserTurnV1`, `PoPBiscuitWireV1`, `Cedar.Allow ∧ Biscuit.Allow`, `tools/list` digest pinning, `CaMeL` + `FIDES`/`jev` SSA execution, `PoP-Biscuit` Datalog contracts, mixed-provenance Git/IDE `AST-Slot Projection`, 8GB `M1` multiplexing, the DeepMind/Anthropic/OpenAI/MSR crosswalk, and Phase-2 `Lean 4` / `Tamarin` formal proofs.

---

## Track 6: Silicon Memory Tagging (`Apple M5 EMTE`) & Zero-Knowledge Compliance Proofs (`Plonky3` + `Lasso`)

### 6.1 Hardware Horizon: Progressive Enhancement from `M1`–`M4` Guarded `PAC` to `M5+` Hardware `EMTE`

Our non-negotiable baseline requirement is **100% operational parity on an 8GB Apple `M1` Mac**. Across mixed-generation enterprise fleets (`M1` through `M5+`), all five enclave daemons (`UID 701–705`) allocate secret slabs via a single unified **`SecureSlabAllocator`** trait:

* **Apple `Memory Integrity Enforcement (MIE)` & `EMTE` (`FEAT_MTE4` on `M5+` with `SPTM` Secure Page Table Monitor, 2025–2026):** Assigns hardware-checked 4-bit cryptographic tags to 16-byte memory granules in **strict synchronous fault mode**, terminating on the exact load/store clock cycle of a spatial overflow or temporal use-after-free (`UAF`).
* **Progressive Hardware Strategy (Zero `M1` Regression + Single-Fault Quarantine):**
  * **On `M1` / `M2` / `M3` / `M4` (`arm64e`, pre-`EMTE`):** Enforces `#![forbid(unsafe_code)]` Rust slabs pinned via `mlock()`, `arm64e` Pointer Authentication (`PAC`), and **`16KiB` `VM_PROT_NONE` redzone guard pages** bracketing every secret arena.
  * **On `M5+` (runtime detection; exact `sysctl` selector and entitlement keys to be verified against Apple documentation before lock, `F-016`):** Enables synchronous hardware `EMTE` tagging across `UID 701–705` with **neighbor-excluded `STZG` tag rotation on `explicit_bzero()`** and the graduated **`HardwareIntegrityQuarantine`** strike policy (`ADR-012`): page-zero null dereferences (`addr < 0x10000`) never latch; heap-tag/`PAC`/redzone faults latch NVRAM on Strike `2` within `24h` in `L1`/`L2` (Strike `1` in `L3`), recoverable via a TUF-signed fleet `UnquarantineGrant`.
  * **Pre-`M5` scoping (`F-018`):** dedicated 1-object `16KiB` guard pages apply only to `<= 32` root keys; high-cardinality handles live in type-segregated randomized-cookie slabs (no hardware spatial isolation is claimed for pooled objects on `M1`–`M4`).
  * **Zero-JIT (`ADR-011`):** `allow-jit` is FORBIDDEN across `UID 701–705`.

### 6.2 Streaming `Plonky3` + `Lasso` Proof-of-Redaction & 4-Journal `IVC` Compliance Rollups (`_enclavezk` `UID 705`)

* **Literature & Realistic 8GB `M1` Scope:** Rather than running multi-gigabyte full-backbone LLM `ZKML` on laptop batteries, `_enclavezk` (`UID/GID 705`, **RSS $\le 48\text{ MiB}$**, `0` network sockets) proves **deterministic enclave boundary invariants** using **`Plonky3`** (`KoalaBear` 31-bit `NEON` SIMD field) + **`Lasso` DFA lookup tables** + **`Poseidon2` commitments**, while treating verifiable neural inference (`NanoZK` `[Unverified]`, `FlashProve` `[Unverified]`) as research horizon only:
  1. **256-Bit Blinded Commitments & Contiguous Ingress Binding (GDPR Art. 17 & Anti-Omission Safe):** `_piivault` (`UID 703`) anchors $C_{\text{raw}} = \text{Poseidon2}(D_{\text{raw}} \parallel r_{\text{raw}})$ ($r_{\text{raw}} \xleftarrow{\$} \{0,1\}^{256}$, wiped after folding) to the boot-anchored `rpc_seq_u64` sequence (in-RAM atomic `u64` under a SEP-signed `boot_epoch_id`, `ADR-010`), defeating rainbow-table SSN searches, dummy-input substitution, and cherry-picked receipt/epoch omission.
  2. **`64KiB` + `128B`-Carry Streaming `IVC` Across Surrogates & Dual-Hash Journals:** Folds arbitrary-length tool redactions (`<85ms` per `64KiB` chunk on `M1` — **Phase-0 benchmark target, unmeasured**, `F-025`) with a `128B` boundary holdback carry (defeating split-SSN boundary bugs), `Lasso` + `Poseidon2_PRF` format-preserving surrogate verification, and dual `(BLAKE3, Poseidon2)` chains across `adapter`, `cas`, `custody`, and `ifc` journals (`qif_cap_invariant_satisfied == true`) inside a fixed `32 MiB` ring buffer.
  3. **Cumulative `L1 ⊂ L2 ⊂ L3` Scaling:** `0%` background ZK CPU load on **`L1`** (lazy commitments, `0` disk plaintext); E-core hourly `ComplianceRollupProofV1` uploads via `_enclavecas` (`UID 702`) TLS 1.3 (`<1.2W`) on **`L2`**; synchronous pre-egress $\pi_{\text{redact}}$ verification + binary-CBOR `128 KiB`-padded RFC 9458 `OHTTP` anonymous attestation with in-circuit fleet Merkle membership (zero hardware signatures on the wire, `ADR-016`) + `<5ms` `IOKit` YubiKey-yank / `Cmd+Ctrl+Q` witness & key zeroization on **`L3`**.

### 6.3 Architectural Readiness Seam & Full Feature Spec

* **Full Feature & SRE Design Spec:** See [**`docs/FEATURE_SILICON_EMTE_AND_ZK_COMPLIANCE.md`**](FEATURE_SILICON_EMTE_AND_ZK_COMPLIANCE.md) (`DESIGN-EMTE-ZK-2026-006`, `Rev 1.4`) for the specification covering the exact `R_epoch` relation over $\mathbb{F}_{p^5}$ `KoalaBear` with `DuplexChallenger` Fiat-Shamir schedule (`ADR-017`), `SecureSlabAllocator` + C/C++ FFI `checked-allocations` (`M1`–`M4` $\to$ `M5+` `EMTE`), `_enclavezk` (`UID 705`) `Plonky3` (`HVZK`, injective `Pack_24`, `80b` `Q16.16`) + `Lasso` `64KiB`+`128B` streaming `IVC`, dual `UID 703 + UID 704` co-signed `AbortedPreEgressTombstone` contiguity, `L3` Merkle-nullifier unlinkability, `k`-of-`n` `Ed25519` `UnquarantineGrant`, the complete `UID 701–705` daemon topology, standards crosswalk, and Phase-2 `Arklib`/`Lean 4`/`Islaris` formal proofs.

---

## Consolidated 12-Month Adoption & Future-Proofing Matrix

| Research Domain                            | Primary Papers / Tech (2025–2026)                                                                                                         |                   TRL Today                   |                                Target Horizon                                |                               M1 Mac Compatible?                                | Seam to Architect Today (Zero-Code-Churn Prep)                                                                                                                                                                   |
|:-------------------------------------------|:------------------------------------------------------------------------------------------------------------------------------------------|:---------------------------------------------:|:----------------------------------------------------------------------------:|:-------------------------------------------------------------------------------:|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Post-AR & Non-Transformer Runtime**      | TypeSafe `jev` (RLCD) `[Unverified]`, `LLaDA 2.0`/`Dream`/`DINGO`, `Mamba-3`/`RWKV-7`/`Titans`, `BLT`/`LCM`, `Huginn`/`COCONUT`/`EAGLE-3` |                  **TRL 3–5**                  |                 **Phase 1: `LLaDA-8B`, `RWKV-7`, `EAGLE-3`**                 |                        **Yes** (`MLX` / ANE / Metal CoW)                        | Ship universal `EnclaveModelAdapter` (`execution_class` + runtime IR attestation): entity-set QIF ledger, `DINGO` DFA diffusion infilling, fence-synced SSM `StateSnapshotDAG` wipe, and `BLT` Byte-DFAs.        |
| **P2P Swarm Model/Policy Sync**            | `Iroh` (QUIC + `Bao` BLAKE3), BitTorrent v2 (`BEP 52`), `Dragonfly`/`ORAS`                                                                |                  **TRL 7–8**                  |                                **3–6 Months**                                |                    **Yes** (Rust QUIC + `IOKit` power check)                    | Address all policies, models, and companion safety layers via tier-invariant `cas://blake3-bao-v1/<logical_plaintext_hex64>` URIs (`L1` / `L2` / `L3`).                                                          |
| **Physical Hardware Key Intent**           | `Apple SEP`, YubiKey 5 (`>= 5.7`), `FIDO2 CTAP 2.1+`, PRF, `depotkey`, `k`-of-`n` `Ed25519`                                                 |                   **TRL 7**                   |                                **3–6 Months**                                |                  **Yes** (`SEP` + USB-C / NFC `IOHIDManager`)                   | Ship unified `HardwareCustodyEngine` (`L1 ⊂ L2 ⊂ L3` $\times$ monotonic `A1..A4` classes): JCS `CTAP 2.1+` intent signing, dual-key `2-of-2` PRF vault, & USB yank wipe (CPU `<0.5ms`, GPU/ANE fence `<=4.5ms`). |
| **Deterministic Agent IFC & Delegation**   | DeepMind `CaMeL` (2503.18813), MSR `FIDES` (2505.23643), `PoP-Biscuit` Datalog                                                            |                  **TRL 4–5**                  |                                **3–6 Months**                                |                  **Yes** (Rust/Starlark, $\le 32\text{ MiB}$)                   | Ship `EnclaveFlowEngine` (`UID 704`): monotonic `(C1..C4, T0..T3)` SSA handles, `jev` enum branch gates, & `PoP-Biscuit` delegation.                                                                             |
| **World Models & Latent Circuit Breakers** | `AMI Labs` (`H-JEPA`/`EBM`) `[Unverified]`, Meta `V-JEPA 2`, DeepMind `Genie 3` (Non-Goal), `COCONUT`, `Smooth-LCM` LEACE/SAE             |                  **TRL 3–4**                  | **Phase 1: `V-JEPA 2` encoder only; `Class 6` actuation gated on `ADR-018`** |                     **Yes** (Metal / MLX / ANE Unified RAM)                     | Enforce `JEPA_EBM_WORLD_PLANNER` (`C_intrinsic = +Inf` Metal `MPC` barrier, conformal $E_\alpha$, frame-sync `IOSurface` masking & `STM` zeroization).                                                           |
| **Silicon EMTE & ZK Proof-of-Redaction**   | Apple `MIE`/`EMTE` (`M5+`), `Plonky3`+`Lasso`, `NanoZK` / `FlashProve` `[Unverified]`                                                     | **TRL 3–4** (gated on Phase-0 `M1` benchmark) |                               **6–12 Months**                                | **Yes** (`M1`–`M4` Guarded `PAC`; `M5+` `EMTE`; $\le 48\text{ MiB}$ E-core IVC) | Ship `SecureSlabAllocator` + `_enclavezk` (`UID 705`): `64KiB` streaming `Poseidon2`/`Lasso` DFA proofs & zero-PII rollups (realistic FRI proof size `~35–150 KB`, `<= 96 KiB` target, `F-025`).                 |

---

## Collaborative Workshop Agenda: Open Architectural Decisions for Review

Since we are collaborating on shaping this research roadmap before locking any implementation plans, here are the **five high-leverage architectural trade-offs**. Each is **specified in draft**; **implementation remains gated on the `§8.2` prerequisites** listed in the owning feature specification (`F-034`), and the locked owner decisions are recorded in `ADR-006`–`ADR-018`:

1. **Day-1 Post-Autoregressive & World-Model Adapter Priority — All 6 Classes Specified as Fail-Closed Gates `[SPECIFIED IN DRAFT — IMPLEMENTATION GATED ON §8.2 PREREQUISITES]`:**
   * Specified in [**`docs/FEATURE_POST_AR_MODEL_ADAPTERS.md`**](FEATURE_POST_AR_MODEL_ADAPTERS.md) (`Rev 1.3`): **all six** beyond-autoregressive execution classes (`DISCRIMINATIVE_RLCD`, `DISCRETE_DIFFUSION`, `RECURRENT_SSM_TTT`, `BYTE_OR_CONCEPT`, `SPECULATIVE_OR_RECURRENT_DEPTH` including `COCONUT`, and `JEPA_EBM_WORLD_PLANNER` for Yann LeCun's `AMI Labs` `H-JEPA`/`EBM` + `V-JEPA 2-AC`) ship as **Tier-1 Mandatory Fail-Closed Gates** with static+runtime topological attestation and automatic 6-subsystem adaptation across `L1`/`L2`/`L3` (user-facing How-To guides tracked for pre-publication).
2. **P2P Swarm Topology — Validating the 3-Tier (`L1` / `L2` / `L3`) Swarm Model `[SPECIFIED IN DRAFT — IMPLEMENTATION GATED ON §8.2 PREREQUISITES]`:**
   * Specified in [**`docs/FEATURE_SWARM_SECURITY_PROFILES.md`**](FEATURE_SWARM_SECURITY_PROFILES.md) (`Rev 1.3`): **`FastCDC` (`Xet`) + `Iroh` (`Bao` BLAKE3 over QUIC with `TCP/443` `tcp_ledbat` fallback) + `Cloudflare R2` (\$0 egress WebSeed)** with tier-invariant `logical_plaintext_blake3_root` URIs, `FUSE-T` lazy hydration restricted to `L1` public weights (`> 1 GiB`, `pf`-blocked for `uid=501`), eager verified hydration in `L2`, and `clonefile(2)` + Chunked OHTTP + Sealed APFS Snapshots in `L3`.
3. **Cumulative Hardware Custody Tiers (`L1 ⊂ L2 ⊂ L3`) & Monotonic Action Classes (`A1..A4`) `[SPECIFIED IN DRAFT — IMPLEMENTATION GATED ON §8.2 PREREQUISITES]`:**
   * Specified in [**`docs/FEATURE_HARDWARE_CUSTODY_PROFILES.md`**](FEATURE_HARDWARE_CUSTODY_PROFILES.md) (`DESIGN-HW-CUSTODY-2026-004`, `Rev 1.4`): unified `HardwareCustodyEngine` combining **`L1` (`sep-biometric`, \$0 hardware)** $\subset$ **`L2` (`step-up-yubikey`, airplane-safe dual-key `Tokenize-Only` routine + chained Touch ID → YubiKey on `A3`/`A4`)** $\subset$ **`L3` (`dual-custody-deadman`, `2-of-2` `SEP || YubiKey PRF` morning unlock + USB yank-to-zeroize)**, using a **~1.5s Zero-Keystroke Chained `Touch ID (SEP, CoreAuthUI)` $\to$ `YubiKey CTAP 2.1+` Co-Signature** on every `A3`/`A4` prompt in `L2` and `L3`.
4. **Deterministic Agent IFC (`CaMeL` + `FIDES`) & Multi-Hop `PoP-Biscuit` Delegation `[SPECIFIED IN DRAFT — IMPLEMENTATION GATED ON §8.2 PREREQUISITES]`:**
   * Specified in [**`docs/FEATURE_AGENT_IFC_AND_DELEGATION.md`**](FEATURE_AGENT_IFC_AND_DELEGATION.md) (`DESIGN-AGENT-IFC-2026-005`, `Rev 1.4`): unified `EnclaveFlowEngine` (`UID 704`) enforcing monotonic **`(C1..C4, T0..T3)`** SSA value handles with the `UserTurnV1` prompt/attachment split (`join = max`), **`FIDES` + `jev` bounded-entropy branch gates** (closing pure `CaMeL`'s 23% dynamic-task gap while conserving Track 1's `12.0-bit` QIF cap), **`AST-Slot Projection`** for taint-explosion-free Git/IDE coding, sender-constrained **`PoP-Biscuit`** sub-agent delegation, and **8GB `M1` single-weight multiplexing ($\le 32\text{ MiB}$ RSS)** across `L1 ⊂ L2 ⊂ L3`.
5. **Progressive Silicon `EMTE` (`M1`–`M4` $\to$ `M5+`) & Streaming `ZK Proof-of-Redaction` Rollups `[SPECIFIED IN DRAFT — IMPLEMENTATION GATED ON §8.2 PREREQUISITES]`:**
   * Specified in [**`docs/FEATURE_SILICON_EMTE_AND_ZK_COMPLIANCE.md`**](FEATURE_SILICON_EMTE_AND_ZK_COMPLIANCE.md) (`DESIGN-EMTE-ZK-2026-006`, `Rev 1.4`): `SecureSlabAllocator` (`M1`–`M4` root-key-only `16KiB` guard pages + randomized-cookie slabs $\to$ `M5+` synchronous `EMTE` `STZG` + graduated `HardwareIntegrityQuarantine`) paired with `_enclavezk` (`UID 705`, `Plonky3` + `Lasso` `64KiB` streaming `IVC` targeting $\le 48\text{ MiB}$ RSS with a `<= 12 MiB` thermal queue), folding all four cross-track JSONL journals (joined on `rpc_seq_u64`) into GDPR Art. 17-safe rollups (`0%` ZK overhead on `L1`, E-core hourly rollups on `L2`, synchronous pre-egress gates on `L3`). All latency, RAM and proof-size figures are Phase-0 benchmark targets.

---

## Selected Academic & Technical References (2025–2026)

Tags: `[Verified-ID]` resolves to a public arXiv/RFC/DOI given inline; `[Unverified]` could not be resolved and MUST NOT be treated as an available dependency; `[Internal depot Mechanism]` is defined by this project.

1. **Debenedetti, E., Shumailov, I., Fan, T., Carlini, N., Papernot, N., et al. (Google, Google DeepMind, ETH Zurich, Mar 2025).** *"Defeating Prompt Injections by Design (CaMeL)."* `arXiv:2503.18813` `[Verified-ID]`.
2. **Costa, M., Köpf, B., Paverd, A., Russinovich, M., Zanella-Béguelin, S., et al. (Microsoft Research, May 2025).** *"Securing AI Agents with Information-Flow Control (FIDES)."* `arXiv:2505.23643` `[Verified-ID]`.
3. **Almeida, D., Gafni, E., & Sheng, S. (TypeSafe AI, Sept 2026).** *"Jev: Non-Autoregressive Discriminative System-1 Models via Reinforcement Learning for Calibrated Decisions (RLCD)."* Technical Release & Architecture Specification. `[Unverified]`
4. **Assran, M., Bardes, A., LeCun, Y., et al. (Meta FAIR, 2025–2026).** *"V-JEPA 2: Self-Supervised Video World Models for Visual Understanding and Action-Conditioned Planning."*
5. **Google DeepMind Genie Team (2025–2026).** *"Genie 3: Interactive Action-Conditioned World Models at Real-Time Horizon."* (Referenced only to record it as a Non-Goal, `ADR-018`.)
6. **Hao, S., Sukhbaatar, S., et al. (Meta AI, 2024–2025).** *"Training Large Language Models to Reason in a Continuous Latent Space (COCONUT)."*
7. **Zou, A., Phan, L., Wang, H., et al. (2024–2025).** *"Improving Alignment and Robustness with Circuit Breakers"* & *"Representation Engineering: A Top-Down Approach to AI Transparency."*
8. **Wang, Z. (2026).** *"NanoZK: Privacy-Preserving Verifiable Inference for Large Language Models via Layerwise Zero-Knowledge Proofs."* `arXiv` (2026) `[Unverified]`; alongside *"FlashProve: Provable LLM Inference via zkSNARKs"* `[Unverified — no public paper or repository located; attribution withdrawn]`.
9. **Apple Platform Security Engineering (2025–2026).** *"Memory Integrity Enforcement (MIE), Enhanced Memory Tagging Extension (EMTE / ARM MTE4), and Secure Page Table Monitor (SPTM) on Apple Silicon."*
10. **FIDO Alliance.** *"Client to Authenticator Protocol (CTAP) 2.1"* (Proposed Standard, 2021-06-15) — `authenticatorGetAssertion`, `hmac-secret`, `pinUvAuthProtocol` 2 `[Verified-ID]`; **Yubico** YubiKey 5 Series firmware 5.7 release notes (`Ed25519`, CTAP 2.1). depot uses **no** CTAP 2.2/2.3 extension (`F-008`).
11. **BitTorrent Enhancement Proposal `BEP 52` (BitTorrent v2 SHA-256 Merkle Trees)** & **n0 Computer (`Iroh` / `Bao` BLAKE3 Verified Streaming over QUIC, 2025–2026).**
12. **Biscuit Authorization Specification & Agent Identity Protocol (`AIP`, 2026).** *"Invocation-Bound Capability Tokens and Datalog Attenuation for Multi-Hop depot and A2A Delegation."* (Biscuit v3 specification `[Verified-ID]` at `biscuitsec.org`; `AIP` `[Unverified]`.)
13. **Xia, W., et al. (USENIX ATC)** *"FastCDC: A Fast and Efficient Content-Defined Chunking Approach for Data Deduplication"* (adopted in HuggingFace `Xet` / `hf_xet` CAS, 2025–2026); paired with **IETF RFC 9458** (*Oblivious HTTP*) & **Apple XNU `SO_TC_BK_SYS` LEDBAT++ Scavenger Transport**.
14. **Nie, S., Zhu, F., et al. (2025–2026).** *"Large Language Diffusion Models (`LLaDA` & `LLaDA 2.0`)"*; alongside **`Dream-7B`**, **Inception Labs (`Mercury 2`)**, **Automata-Based Constrained Diffusion (`DINGO`)**, and **Refusal-Aware Early Commitment (`RAEC`)** for intermediate denoising trajectory safety.
15. **Dao, T., & Gu, A. (`Mamba-2` / `Mamba-3`, 2024–2026)**; **Peng, B., et al. (`RWKV-7 "Goose"`, 2025)**; **Behrouz, A., Zhong, P., & Mirrokni, V. (Google Research, 2025)**, *"Titans: Learning to Memorize at Test Time"*; paired with **Hidden State Poisoning Attacks (`HiSPA`, 2025–2026)** on recurrent state-space memory.
16. **Pagnoni, A., Pasunuru, R., Rodriguez, P., et al. (Meta FAIR, 2024–2025).** *"Byte Latent Transformer (`BLT`): Patches Scale Better Than Tokens"*; and **Meta FAIR `SONAR` / `LCM` Team (2024–2025)**, *"Large Concept Models: Language Modeling in a Sentence Representation Space."*
17. **Geiping, J., McLeish, S., Jain, N., et al. (2025).** *"Scaling up Test-Time Compute with Latent Reasoning: A Recurrent Depth Approach (`Huginn`)"*; and **Li, Y., et al. (2025)**, *"`EAGLE-3`: Scaling up Inference Acceleration of Large Language Models via Training-Time Test"* (`mlx-lm` Apple Silicon port).
18. **LeCun, Y. (2022–2026)**, *"A Path Towards Autonomous Machine Intelligence"* (`H-JEPA`, Energy-Based Models, Intrinsic Cost & Configurator); operationalized by **`AMI Labs` (LeCun, LeBrun, Xie, Fung, Rabbat — March 2026 Launch)** for objective-driven world-model planning. `[Unverified — announcement only; no public weights]`
