# Feature Design, SRE Production Spec & Operator How-To: Day-1 Post-Autoregressive Model Governance (`EnclaveModelAdapter`)

Current implementation checkpoint (2026-11-13): the installed CDP helper refuses
startup with `BROWSER_BACKEND_UNAVAILABLE` before socket/profile effects. Canned
responses require both `--response-fixture --dev-same-uid` in a debug build and
cannot be combined with a real-browser path/hash. This mitigates false browser
success; real model execution and confined browser actuation remain incomplete.
The normative requirements below remain in force. See the
Phase 3–6 checkpoint.

* **Doc ID:** `DESIGN-POST-AR-ADAPTERS-2026-001` (`FS-701`, **Rev 1.6** — remediation of `ADVERSARIAL_SPEC_REVIEW_2026-11-04`; see `§10 Revision History`)
* **Generation:** `v3.0-Target` · **Precedence:** highest tier (with `FS-702..705`, `ADR-006+`) per [`README.md §1.2`](../README.md#12-normative-precedence--architectural-lineage)
* **Implementation Status:** **Partial implementation; full specification and hardware acceptance remain open.** Revision-specific software/native fixtures and bounded Lean models verify their named subsets; they do not establish every adapter, physical custody or installed deployment requirement. What is built, what is open and what diverges are tracked in `docs/IMPLEMENTATION_LEDGER.md` and `GapsDeDuped.me`; §11 records implementation decisions made while closing gaps.
* **Retired Design ID:** `DESIGN-WORLD-MODELS-2026-002` (standalone Track 2) was merged into this document at `Rev 1.0` and permanently retired (`ADR-018`); the ID is not reused.
* **Author:** Principal Security & SRE Architecture Fellow (Google Distinguished Engineer Standard)
* **Reviewers:** ML Systems & Compilers (`MLX`/`ANE`), Applied Cryptography & QIF, Darwin Kernel Systems, Developer Experience (DevEx) SRE
* **Status:** `DRAFT — DESIGN COLLABORATION` (fail-closed gate specification; implementation gated on `§8.2`-equivalent prerequisites: Phase-1 checkpoints and `enclave-pack`)
* **Target Hardware Baseline:** Apple Silicon `M1` (8GB Unified Memory safe, `arm64e`, macOS 14.0+) with progressive hardware acceleration on `M2` / `M3` / `M4` (`PAC` + `AMX`) and `M5+` (`Apple MIE` / `EMTE` Memory Tagging)
* **Companion Specifications:**
  * Parent Research Horizon: [Track 1 & Track 2 in `bleeding_edge_future_adoption.md`](bleeding_edge_future_adoption.md#track-1-day-1-post-autoregressive--non-transformer-model-governance-jevrlcd-diffusion-lladadream-mamba-3rwkv-7titans-bltlcm-huginneagle-3)
  * Swarm Distribution Plane (`L1` / `L2` / `L3`): [`FEATURE_SWARM_SECURITY_PROFILES.md`](FEATURE_SWARM_SECURITY_PROFILES.md) (`DESIGN-CAS-SWARM-2026-003`)
  * Hardware Custody & Intent Signing (`L1 ⊂ L2 ⊂ L3` $\times$ `A1..A4`): [`FEATURE_HARDWARE_CUSTODY_PROFILES.md`](FEATURE_HARDWARE_CUSTODY_PROFILES.md) (`DESIGN-HW-CUSTODY-2026-004`)
  * Deterministic Agent IFC & `PoP-Biscuit` Delegation (`C1..C4` $\times$ `T0..T3`): [`FEATURE_AGENT_IFC_AND_DELEGATION.md`](FEATURE_AGENT_IFC_AND_DELEGATION.md) (`DESIGN-AGENT-IFC-2026-005`)
  * Silicon `EMTE` (`M1`–`M5+`) & ZK Compliance Proofs (`L1 ⊂ L2 ⊂ L3`): [`FEATURE_SILICON_EMTE_AND_ZK_COMPLIANCE.md`](FEATURE_SILICON_EMTE_AND_ZK_COMPLIANCE.md) (`DESIGN-EMTE-ZK-2026-006`)

**Lifecycle timing amendment (`YKD-02`, 2026-11-15):** The accepted measurement-first policy and FS-703 §5.2 govern removal/lock/sleep freeze, release-fence and owned-state cleanup latency. Give L1/L2 broad measured latitude and derive tighter comparable L3 budgets from native baseline tests immediately before timing-sensitive implementation. Numeric lifecycle budgets remain pending; previous fixed sub-millisecond/sub-5 ms wipe labels are historical references. Preserve per-class/factor/proof gates, finite waiting, cancellation and complete claimed-owner cleanup. Unrelated inference, proof-fold, network, ceremony and token-lifetime targets are unchanged.

---

## Table of Contents

1. [Context, Motivation & The Death of the Autoregressive Assumption](#1-context-motivation--the-death-of-the-autoregressive-assumption)
2. [Goals, Explicit Non-Goals & Alternatives Rejected](#2-goals-explicit-non-goals--alternatives-rejected)
3. [Universal `EnclaveModelAdapter` Architecture & Anti-Misclassification Attestation](#3-universal-enclavemodeladapter-architecture--anti-misclassification-attestation)
   * 3.1 Closed Tier-1 `ExecutionClass` Taxonomy & Tensor-Graph Fingerprint Verifier
   * 3.2 Signed `enclave-model.manifest.json` Schema (OCI v1.1 + TUF Binding)
   * 3.3 Dynamic Control-Plane Auto-Adaptation Matrix (6 Enclave Subsystems)
4. [Tier-1 Mandatory Gate Specifications Across All 6 Post-Autoregressive Classes](#4-tier-1-mandatory-gate-specifications-across-all-6-post-autoregressive-classes)
   * 4.1 Class 1 (`DISCRIMINATIVE_RLCD`): `jev` & ANE Heads — QIF Diode + Anti-Binary-Search Privacy Ledger
   * 4.2 Class 2 (`DISCRETE_DIFFUSION`): `LLaDA 2.0`, `Dream`, `FS-DFM` — `DINGO` DFA Trellis & `RAEC` Step-Watchers
   * 4.3 Class 3 (`RECURRENT_SSM_TTT`): `Mamba-3`, `RWKV-7`, `Titans`, `TTT` — CoW `StateSnapshotDAG` & `HiSPA` Defense
   * 4.4 Class 4 (`BYTE_OR_CONCEPT`): `BLT` & `LCM`/`SONAR` — SIMD `Byte-DFA` & `Smooth-LCM` `LEACE` Clamping
   * 4.5 Class 5 (`SPECULATIVE_OR_RECURRENT_DEPTH`): `Huginn`, `COCONUT` & `EAGLE-3` — Sponge Watchdog, Latent Circuit Breakers & Draft-Tree Zeroization
   * 4.6 Class 6 (`JEPA_EBM_WORLD_PLANNER`): Yann LeCun's `AMI Labs` (`H-JEPA` + `EBM` + `MPC`), `V-JEPA 2-AC` — Hardwired $C_{\text{intrinsic}}$ Energy Barrier & Hierarchical `Biscuit` Attenuation
5. [Conceptual Model Lifecycle & Pre-Publication How-To Documentation Scope (`L1`, `L2`, `L3`)](#5-conceptual-model-lifecycle--pre-publication-how-to-documentation-scope-l1-l2-l3)
   * 5.1 Conceptual 3-Stage Model Lifecycle (Import/Attest $\to$ Declare/Include $\to$ Hydrate/Auto-Adapt)
   * 5.2 Architectural Interaction Matrix: `L1` / `L2` / `L3` Swarm Profiles $\times$ All 6 Model Classes
   * 5.3 Pre-Publication Documentation Deliverables Tracker (To Author Near Public Release)
6. [Frontier AI Lab Standards Crosswalk: Google DeepMind, Anthropic, OpenAI & `AMI Labs`](#6-frontier-ai-lab-standards-crosswalk-google-deepmind-anthropic-openai--ami-labs)
7. [Production Readiness Review (PRR) & Operational SRE Runbooks: SLIs, SLOs, FMEA & Audit Receipts](#7-google-sre-production-readiness-review-prr-slis-slos-fmea--audit-receipts)
   * 7.1 Service Level Indicators (SLIs) & Service Level Objectives (SLOs) on Apple M1 Baseline
   * 7.2 Failure Modes & Effects Analysis (FMEA)
   * 7.3 Zero-PII Adapter Execution Receipt (Track-3 & Track-6 ZK Compliance Seam)
8. [Future Section: Formal Verification & Mathematical Security Proofs Roadmap (All 6 Classes)](#8-future-section-formal-verification--mathematical-security-proofs-roadmap-all-6-classes)

---

## 1. Context, Motivation & The Death of the Autoregressive Assumption

Virtually every open-source agent framework and enterprise LLM gateway available in 2026 hardcodes three brittle assumptions into its security perimeter:

1. **Left-to-Right Causal Decoding (`t_1 -> t_2 -> ...`):** Structured JSON/SQL tool-call validators (`Outlines`, `XGrammar`, `llguidance`) and streaming DLP filters assume tokens are emitted strictly sequentially from left to right.
2. **Discrete Per-Token KV-Caches:** Session isolation and context unlearning assume attention keys/values are indexed by discrete token positions `[0..N]` that can be selectively truncated when tool outputs carry customer PII.
3. **Fixed Subword Tokenizers (BPE) & Constant Per-Token Compute:** Guardrails assume PII surrogates (`<PII_SSN_01>`) map to atomic vocabulary IDs and that generating $K$ tokens consumes $O(K)$ predictable FLOPs.

On Apple Silicon developer laptops (`MLX`, `CoreML`, `Apple Neural Engine`), **developers are already moving past standard causal Transformers**—adopting `jev`-style RLCD classifiers for $15\text{ms}$ deterministic triage, `LLaDA 2.0` / `Dream` diffusion LLMs for $1,000\text{ tok/s}$ parallel code synthesis, `Mamba-3` / `RWKV-7` / `Titans` state-space models to fit $1\text{M}+$ token repositories into 16GB of unified RAM without KV-cache OOMs, `BLT` / `LCM` tokenizer-free architectures, `Huginn` / `EAGLE-3` recurrent-depth / speculative engines, and objective-driven world models in the style of LeCun's `H-JEPA` + `EBM` + `MPC` blueprint (`V-JEPA 2` exists publicly; `AMI Labs`-style planners are `[Research Horizon — no public weights]`, `F-009`).

**Phase-1 concrete adapter targets (`OQ-08`, `ADR-018`):** `LLaDA-8B` (`Class 2`), `RWKV-7` (`Class 3`), `EAGLE-3` (`Class 5` wrapper) and `V-JEPA 2` (`Class 6` encoder/predictor only). Every upstream checkpoint is re-packaged by depot's offline packager **`enclave-pack`** into depot-owned `enclave_adapter.*` `.safetensors` tensor namespaces; the enclave never assumes upstream checkpoints ship depot key names.

If a local enclave treats these six post-autoregressive families as second-class plugins—or forces them through legacy `chat/completions` wrappers—**PII containment fails silently on Day 1**. This specification defines **all six post-autoregressive execution classes as fail-closed gates** (classes without Phase-1 checkpoints stay specification-only until public weights exist) integrated directly with our [Tiered Swarm Distribution Plane (`L1` / `L2` / `L3`)](FEATURE_SWARM_SECURITY_PROFILES.md).

---

## 2. Goals, Explicit Non-Goals & Alternatives Rejected

### 2.1 Goals

* **G1 (100% Tier-1 Day-1 Coverage):** Ship mandatory, kernel- and memory-enforced runtime gates for **all six post-autoregressive families** (`DISCRIMINATIVE_RLCD`, `DISCRETE_DIFFUSION`, `RECURRENT_SSM_TTT`, `BYTE_OR_CONCEPT`, `SPECULATIVE_OR_RECURRENT_DEPTH`, and `JEPA_EBM_WORLD_PLANNER`) alongside baseline `AR_CAUSAL`.
* **G2 (Zero-Touch Control Auto-Adaptation):** When a developer pins any model URI from `enclave-cas` (`L1`, `L2`, or `L3`), the local enclave **automatically reconfigures** its IPC contract, grammar constraint engine, unified-memory zeroizer, PII surrogate encoding, Cedar QIF bit-leakage ledger, and thermal watchdog—requiring **zero security knob tuning** by application developers.
* **G3 (Unspoofable Topological Binding):** Prevent accidental or malicious model misclassification via deterministic **Tensor-Graph Fingerprint Verification** at both publish time (`onboard`) and local admission time (`admit`).
* **G4 (Universal Apple M1 Baseline Parity):** Guarantee full safety invariants and $<48\text{MiB}$ adapter overhead on an entry-level **8GB Apple M1 MacBook Air** (`16KiB` Guarded `PAC` slabs on `M1`–`M4`), while progressively activating synchronous hardware `EMTE` (`FEAT_MTE4`) memory tagging on `M5+` silicon.

### 2.2 Explicit Non-Goals

* **NG1:** Training or fine-tuning base weights on developer laptops containing live production PII (test-time fast weights $\Delta W_t$ in `Titans`/`TTT` are strictly ephemeral, `mlock()`-isolated, and zeroized upon session exit—never persisted to disk or swarm storage).
* **NG2:** Unverified "custom Python `forward()` hooks" supplied by untrusted repositories (`execution_class` adapters are compiled into the signed Rust/Swift/Metal enclave binary).
* **NG3 (`ADR-018`):** Generative interactive world simulation (`Genie 3`-class pixel-world models) is explicitly **out of scope** on 8GB `M1`: memory, thermal and safety-verification costs are unbounded relative to the enclave budget.
* **NG4:** Global macOS TCC `Accessibility` actuation (`CGEventPost`, `AXUIElementPerformAction` against arbitrary apps). `Class 6` GUI actuation is confined to a sandboxed browser driven over `CDP` (`§4.6`).

### 2.3 Alternatives Considered & Rejected

| Candidate Approach                                               | Why It Appears Attractive                               | Reason for Distinguished-Engineer Rejection                                                                                                                                                        |
|:-----------------------------------------------------------------|:--------------------------------------------------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Tier-2 Optional Plugins for `BLT`/`LCM` & `Huginn`/`EAGLE-3`** | Reduces initial v1.0 surface area.                      | Leaves a Day-1 fail-open gap for tokenizer-free byte-splitting bypasses and fanless M1 battery/thermal sponge attacks; violates zero-trust uniformity.                                             |
| **Black-Box Post-Hoc Regex Proxy Around Non-AR Engines**         | Zero awareness of internal model architecture required. | Fails catastrophically against `Mamba-3`/`Titans` cross-turn continuous state PII entanglement, `jev` 30-call binary-search exfiltration, and broken JSON tool calls in parallel diffusion models. |
| **Developer-Declared `model_type` in Local `.env` / YAML**       | Simple developer configuration.                         | Trivial downgrade vector: renaming a `Mamba-3` checkpoint to `AR_CAUSAL` in YAML would bypass `StateSnapshotDAG` and `explicit_bzero()` state wiping.                                              |

### 2.4 Core Specification Dependencies & Invariant Deltas

| Item                      | Disposition in `FS-701`                                                                                                                                                                                                                                                                   |
|:--------------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Requires (`CORE-V2`)**  | Cedar PDP via `UID 704` (`ADR-008`); ANE classifier as `Class 1` companion; `CNRY_SEP_*` canary tripwires (`CORE-V2 §2.5`, retained inside `_piivault`, `OQ-04`) evaluated on committed `t = 0` output (`§4.2`) and via `SONAR` cosine canaries (`§4.4`).                                 |
| **Requires (`v3.0`)**     | `FS-702` CAS + 4-role TUF for atomic model/companion hydration; `FS-704` QIF journal (`global_unstructured_c3_c4_24h_pool`) and `PoP-Biscuit`; `FS-705` `SecureSlabAllocator` and zero-JIT rule.                                                                                          |
| **Supersedes**            | `CORE-V1 §4.4` Laplace DP (`ε = 0.1`, `ε_max = 2.0`) — replaced by the `12,000 mb` 24h `EntityKey` QIF ledger and `Smooth-LCM` $d_\chi$-privacy. `CORE-V2` token-stream stop-sequence DLP — replaced by per-class output caps (`max_output_bytes <= 65536`, `max_diffusion_steps <= 64`). |
| **Amends `CORE-V1 §2.3`** | Invariant 3 (`DetectPII(context) = ∅`) is amended: `Class 1` may declassify bounded enums (`≤ 12.0` bits/24h/entity) — never raw values. Invariant 1 unchanged for `UID 701` (no network sockets).                                                                                        |
| **Shared contracts**      | Journal lines use `EnclaveAuditEnvelopeV1` (`schemas/enclave-audit-envelope-v1.schema.json`); manifests validate against `schemas/enclave-model.manifest.schema.json`.                                                                                                                    |

---

## 3. Universal `EnclaveModelAdapter` Architecture & Anti-Misclassification Attestation

### 3.1 Closed Tier-1 `ExecutionClass` Taxonomy & Tensor-Graph Fingerprint Verifier

Every model admitted via `enclave-cas` must map to exactly one primary variant of the closed `ExecutionClass` enum, optionally composed with orthogonal `auxiliary_wrappers` (such as `SPECULATIVE_OR_RECURRENT_DEPTH` when `EAGLE-3` draft heads or `COCONUT` continuous-latent-thought loops wrap an `AR_CAUSAL`, `DISCRETE_DIFFUSION`, or `RECURRENT_SSM_TTT` backbone). **Strict Lattice Join (`⊔`) Composition Law:** Whenever `auxiliary_wrappers` are present, `EnclaveModelAdapter::bind()` enforces the **least upper bound (most restrictive union)** of controls across all 6 enclave subsystems—an auxiliary wrapper can only *tighten* pacing, loop caps, latent probes, or zeroization, never relax a primary class's invariants.

**Tensor Namespace Convention (`MUST`, `F-009`):** every tensor key glob in this section (e.g. `enclave_adapter.rlcd_head.*`, `enclave_adapter.ebm_cost_head`, `enclave_adapter.latent_thought_proj.*`) names an **depot-owned `enclave-adapter-v1` namespace** produced by `enclave-pack`. Upstream architecture signatures (`mixer.A_log`, `rwkv.time_mix_*`, bidirectional masks) are detected structurally, not by depot key names.

**Cross-RPC Statelessness (`MUST`, `F-027`):** for `AR_CAUSAL` and every other class, no raw float, KV-cache or recurrent-state tensor may be returned across an RPC boundary or accepted back as an input; only UTF-8 token IDs, typed primitives and opaque handles cross. A manifest-declared `AR_CAUSAL` model attempting host-loop recurrence (returning an activation at step $t$ and re-ingesting it at $t+1$) fails with `EACCES`.

**Cross-Silicon Margin (`MUST`):** in `L1`/`L2` (no `Q16.16` fixed-point), any calibrated decision within `threshold_margin_fail_closed` (default `1e-3`) of a `jev`, `RAEC` or `LEACE` threshold resolves to the more restrictive outcome, so `FP16`/`BF16` non-determinism across `M1`–`M5` cannot flip a decision toward permissive.

To defeat **Misclassification & Tensor-Renaming Downgrade Attacks**, topological attestation operates at **two coupled layers**:

1. **Static Shape & Companion-Layer Verification (`onboard` + `enclave-cas` Pre-Admission):** Inspects `.safetensors` tensor rank/shape invariants, `.mlpackage` `MIL` operators, and mandatory companion safety layers (`ece_calibration_lut`, `leace_nullspace`, `conformal_energy_lut`) bundled atomically inside the same OCI v1.1 manifest (`FDSet`).
2. **Runtime Compute-Graph Operator Attestation (Defeating Key-Name Obfuscation):** Because `.safetensors` stores raw arrays whose string keys could be maliciously renamed (e.g., renaming `mixer.A_log` $\to$ `self_attn.q_proj` to masquerade an SSM as `AR_CAUSAL`), the enclave's signed `MLX` / `CoreML` runtime builder intercepts operator graph construction in RAM. Instantiating a stateful recurrent carry-over primitive (`mlx::core::scan` / persistent state tensor), a bidirectional non-causal mask (`is_causal == false`), a multi-step recurrent depth / continuous-thought loop (`r > 1` or hidden-to-embedding feedback), or an `MPC` rollout optimizer **immediately faults (`EACCES` / `SIGABRT`) unless the manifest's signed `ExecutionClass` (or `auxiliary_wrappers`) authorizes that exact operator family!**

| Tier-1 `ExecutionClass`                                                                                | Mandatory Topological Signatures Inspected in `.safetensors` / `.mlpackage`                                                                                                                                                                     | Fail-Closed Admission Rule                                                                                                                                                                                                                     |
|:-------------------------------------------------------------------------------------------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **`DISCRIMINATIVE_RLCD`**<br>*(`jev`-class, ANE Guard Heads)*                                          | Presence of typed classification/calibration heads (`enclave_adapter.rlcd_head.*`, `enclave_adapter.choice_proj.*`, `ece_calibration_lut`), **absence** of generative vocabulary `lm_head` `[vocab_size, d_model]`.                             | Rejects (`EACCES`) if generative `lm_head` exists or calibration fails **$\text{ECE} \le 0.015$** (15 equal-mass bins over the TUF-pinned `enclave-calib-eval-v1` corpus — the single bound used throughout this spec).                        |
| **`DISCRETE_DIFFUSION`**<br>*(`LLaDA 2.0`, `Dream`, `FS-DFM`)*                                         | Bidirectional attention masks (`is_causal == false`), mask/absorbing token embedding slot, or flow-matching timestep conditioning (`*.t_embed.*`).                                                                                              | Rejects if declared `AR_CAUSAL`; forces `DINGO` DFA trellis + $t > 0$ IPC buffer barrier.                                                                                                                                                      |
| **`RECURRENT_SSM_TTT`**<br>*(`Mamba-3`, `RWKV-7`, `Jamba`, `Titans`, `TTT`)*                           | State-space / linear-RNN / fast-weight tensors (`*.mixer.A_log`, `*.dt_proj`, `rwkv.time_mix_*`, `*.neural_memory.fast_w*`), including hybrid attention+SSM (`Jamba`).                                                                          | **Any** single recurrent/TTT layer in a hybrid graph upgrades the *entire* model to `RECURRENT_SSM_TTT`!                                                                                                                                       |
| **`BYTE_OR_CONCEPT`**<br>*(`BLT`, `LCM` / `SONAR`)*                                                    | `BLT` byte-entropy patcher (`*.entropy_patcher.*`, `vocab_size == 256..260`) or `LCM` concept diffusion (`*.sonar_encoder.*`, `*.concept_denoiser.*`).                                                                                          | Disables BPE token-ID assumptions; enforces `Byte-DFA` + UTF-8 NFC and/or `SONAR` `LEACE` projection.                                                                                                                                          |
| **`SPECULATIVE_OR_RECURRENT_DEPTH`**<br>*(`Huginn`, `COCONUT`, `EAGLE-3`, `Medusa`)*                   | Shared-weight recurrent prelude/core/coda (`num_recurrent_steps > 1`), continuous latent thought feedback (`enclave_adapter.latent_thought_proj.*`), or speculative draft head (`enclave_adapter.eagle_fc.*`, `enclave_adapter.medusa_head.*`). | Enforces Metal loop watchdog (`r <= r_max`) + ANE mid-loop latent circuit breakers (`COCONUT`) + rejected draft-tree zeroization + $20\text{ms}$ pacing.                                                                                       |
| **`JEPA_EBM_WORLD_PLANNER`**<br>*(`V-JEPA 2-AC`; `H-JEPA`/`EBM` research horizon; `Genie 3` Non-Goal)* | Joint-embedding `enclave_adapter.context_encoder` + `enclave_adapter.predictor` + scalar `enclave_adapter.ebm_cost_head` / `configurator` (`zero` vocabulary `lm_head`).                                                                        | Enforces pre-encoder masking, hardwired $C_{\text{intrinsic}} = +\infty$ `MPC` barrier over **DOM/`AX`-resolved targets**, mandatory `world_planner_caps`, post-step surprise abort, `CDP`-sandboxed actuation, and `STM` `memset_s` (`§4.6`). |
| **`AR_CAUSAL`** *(Baseline)*                                                                           | Pure causal mask (`is_causal == true`), fixed BPE tokenizer, standard discrete KV-cache, `r == 1`.                                                                                                                                              | Enforces standard `XGrammar` left-to-right CFG mask, discrete KV-cache slot eviction, and Dual-LLM boundary.                                                                                                                                   |

### 3.2 Signed `enclave-model.manifest.json` Schema (OCI v1.1 + TUF Binding)

Bundled inside the OCI v1.1 artifact manifest on Cloudflare R2 (`application/vnd.enclave.model.config.v1+json`) and signed under the organization's TUF root (`L1` OIDC Sigstore, `L2` Corporate TUF, `L3` $m$-of-$n$ YubiKey Quorum):

The manifest MUST validate against [`schemas/enclave-model.manifest.schema.json`](../schemas/enclave-model.manifest.schema.json) (check `V18`). Required additions in `Rev 1.3`: `tensor_namespace` (`enclave_adapter.*`), `stateless_across_rpc`, `output_caps`, `calibration` (`ece_max <= 0.015`, 15 equal-mass bins, `enclave-calib-eval-v1`), `license_policy` (`allow_p2p_seeding`, default `false`), and — for `JEPA_EBM_WORLD_PLANNER` — `world_planner_caps`.

<!-- schema: enclave-model.manifest -->
```json
{
  "v": 1,
  "model_id": "rwkv7-world-code-audit-mlx-q4",
  "execution_class": "RECURRENT_SSM_TTT",
  "upstream_checkpoint": "RWKV/rwkv-7-world",
  "auxiliary_wrappers": ["SPECULATIVE_OR_RECURRENT_DEPTH"],
  "artifact": {
    "cas_uri": "cas://blake3-bao-v1/9a4f8c2e1b0d7743a51908c4e6b2d1f0883a7c5e9d1b4f2a6c8e0d2f4a6b8c0e",
    "blake3": "9a4f8c2e1b0d7743a51908c4e6b2d1f0883a7c5e9d1b4f2a6c8e0d2f4a6b8c0e",
    "sha256": "4e1a7c5d2b3f8a9e0c6d7b1a2f3e4d5c6b7a8f9e0d1c2b3a4f5e6d7c8b9a0f1e",
    "format": "safetensors"
  },
  "tensor_namespace": "enclave_adapter.rwkv7.v1",
  "topology_fingerprint_blake3": "3c1d9e0000000000000000000000000000000000000000000000000000000000",
  "stateless_across_rpc": true,
  "companion_safety_layers": [
    {
      "role": "eagle_draft_head",
      "cas_uri": "cas://blake3-bao-v1/51d0e80000000000000000000000000000000000000000000000000000000000",
      "eager_hydrate_required": true,
      "max_size_mib": 48
    }
  ],
  "apple_silicon_dispatch": {
    "min_chip": "M1",
    "min_unified_ram_gb": 16,
    "preferred_backend": "MLX_METAL",
    "ane_mil_subgraphs": []
  },
  "output_caps": {"max_output_bytes": 65536, "max_steps": 32},
  "calibration": {"ece_max": 0.015, "bins": 15, "binning": "equal_mass", "dataset": "enclave-calib-eval-v1"},
  "max_provenance_fanin": 64,
  "security_controls": {
    "min_swarm_profile": "L2",
    "qif_max_millibits_per_record": 12000,
    "ssm_anchor_reinject_tokens": 2048,
    "ssm_zeroize_on_taint_exit": true,
    "max_recurrent_depth_nominal": 32,
    "max_recurrent_depth_fair_thermal": 8,
    "anchor_mix_alpha": 1.0,
    "threshold_margin_fail_closed": 0.001
  },
  "license_policy": {"spdx_id": "Apache-2.0", "allow_p2p_seeding": false}
}
```

### 3.2.1 Main and companion bindings at admission

The manifest's `artifact` identifies the requested main model. Every mandatory
`companion_safety_layers[]` entry retains its own `role`, `cas_uri` and
`eager_hydrate_required` binding. CAS must resolve these against one authenticated
metadata snapshot and enforce [FS-702 `ADM-01`–`ADM-06`](FEATURE_SWARM_SECURITY_PROFILES.md#321-exact-requested-metadata-and-eager-bundle-admission)
before the adapter accepts the resulting bundle. A matching root cannot replace
the requested main with another signed record or satisfy a required role using
an unrelated artifact. Shared payload storage must preserve those distinct bindings.

Exact content length comes from the authenticated target metadata; a companion's
`max_size_mib` is a size ceiling, not its authenticated exact length. Retain the
existing manifest schema and signed digest fields. This clarification introduces
no new JSON field and does not make schema validation alone prove the relation
between a manifest, TUF targets, verified bytes and returned descriptors.

The fully eager bundle must contain the actual main and every mandatory direct
eager companion with verified bytes and unambiguous role-to-artifact associations.
Refuse absent, revoked, mismatched or stale required members before binding the
model. Companion-of-companion traversal is additional policy; it is not implied
by the direct-eager baseline. Descriptor ordering must follow the declared IPC
contract; the Lean model's internal root-list order does not establish a wire ABI.

The bounded LAT-05 contract models only
`Target {root,length,eager,revoked}` and logical admission. It does not model
execution-class detection, calibration quality, the JSON schema, full TUF role
semantics or physical `SCM_RIGHTS` delivery. Those requirements retain their
existing independent acceptance obligations.

### 3.3 Dynamic Control-Plane Auto-Adaptation Matrix (6 Enclave Subsystems)

At process bootstrap—before accepting any model descriptor—the Inference Host locks down crash/diagnostic persistence via `setrlimit(RLIMIT_CORE, {0, 0})`, `ptrace(PT_DENY_ATTACH, 0, 0, 0)`, Hardened Runtime, and Mach `EXC_CORPSE_NOTIFY` exception-port masking (guaranteeing unexpected crashes never write tainted `MTLHeap` memory to `/cores/core.<pid>` or `ReportCrash`). Then, the moment `enclave-cas` resolves a `cas://` URI and hands the atomic read-only `SCM_RIGHTS` `FDSet` + verified manifest to the Inference Host, **`EnclaveModelAdapter::bind()` automatically reconfigures six local controls**:

```
  [enclave.lock.toml (`cas://blake3-bao-v1/9a4f...?target=mamba3-audit&ns=secops&min_profile=L2`)]
                                        |
                                        v
            [`enclave-cas` Daemon (Hydrates via L1 / L2 / L3 + Verifies TUF & Topology)]
                                        |
          Passes Atomic Read-Only `FDSet` (`SCM_RIGHTS`) + Verified `ExecutionClass`
                                        |
                                        v
  +---------------------------------------------------------------------------------------------------+
  |                    `EnclaveModelAdapter::bind()` — ZERO-CONFIG AUTO-ADAPTATION                    |
  +---------------------------------------------------------------------------------------------------+
         |                 |                 |                 |                 |                 |
         v                 v                 v                 v                 v                 v
  [1. IPC Wire]    [2. Grammar]      [3. RAM/State]    [4. PII Vault]    [5. Cedar QIF]    [6. Silicon QoS]
```

| Enclave Subsystem                | `DISCRIMINATIVE_RLCD` (`jev`)                | `DISCRETE_DIFFUSION` (`LLaDA`/`Dream`)          | `RECURRENT_SSM_TTT` (`Mamba-3`/`Titans`)                                 | `BYTE_OR_CONCEPT` (`BLT`/`LCM`)             | `SPECULATIVE_RECURRENT` (`Huginn`/`EAGLE-3`) | `JEPA_EBM_WORLD_PLANNER` (`AMI` `H-JEPA`/`EBM`)          |
|:---------------------------------|:---------------------------------------------|:------------------------------------------------|:-------------------------------------------------------------------------|:--------------------------------------------|:---------------------------------------------|:---------------------------------------------------------|
| **1. IPC Wire Contract**         | `EvaluateTypedSchema` RPC ONLY               | **Block-Buffered RPC** ($t > 0$ blocked)        | Session-scoped stream bound to taint label                               | Canonical UTF-8 NFC byte-verified frame     | **20ms Constant-Cadence** batches            | **Quantized Discrete Action RPC** (zero raw floats)      |
| **2. Schema / Grammar Engine**   | Finite-set simplex ($\sum p_i = 1$)          | **`DINGO` DP DFA Trellis** over `[MASK]`        | Hybrid left-to-right `XGrammar` FSM                                      | **SIMD `Byte-DFA`** over raw bytes          | Tree-parallel FSM state cloning              | **Enclave $C_{\text{intrinsic}} = +\infty$ Action Mask** |
| **3. Unified Memory & State**    | Stateless single-pass ANE buffer             | `mlock()` scratch + `memset_s` at $t = 0$       | **CoW `StateSnapshotDAG`** ($h_{\text{sys}}$ RO; wipe $h_{\text{task}}$) | `mlock()` arena zeroized post-call          | **Immediate Zeroization** of rejected drafts | **CoW Episodic `STM`** + `LEACE` + `memset_s`            |
| **4. PII Surrogate Format**      | Opaque handle ref (`ref://pii/8f2a`)         | Fixed-byte BPE-aligned surrogate                | Format-preserving surrogate + zero carry-over                            | **ASCII `SYNTH-SSN-...`** + `SONAR` `LEACE` | Surrogate IDs locked against speculation     | **`ScreenCaptureKit` `IOSurface` Pre-Encoder Blur**      |
| **5. Cedar Policy & QIF**        | **Cumulative Bit-Budget** ($\le 12\text{b}$) | `RAEC` early-refusal + output taint tag         | **Strict Taint Monotonicity**                                            | Cross-lingual concept taint invariance      | Compute-budget quota per tool call           | **Hierarchical `H-JEPA` `Biscuit` Attenuation**          |
| **6. Darwin / Silicon Watchdog** | Local `.mlpackage` $\to$ ANE compile         | ANE step-watcher at $t \in \{.75T, .5T, .25T\}$ | Periodic anchor re-injection ($W=2048$)                                  | ANE linear concept probe pre-decode         | **Thermal Loop Clamp** ($r: 32 \to 8$)       | **Metal `MPC`/`CEM` Rollout Cap** + Conformal $E_\alpha$ |

---

## 4. Tier-1 Mandatory Gate Specifications Across All 6 Post-Autoregressive Classes

### 4.1 Class 1 (`DISCRIMINATIVE_RLCD`): `jev` & ANE Heads — QIF Diode + Anti-Binary-Search Privacy Ledger

* **Threat Eliminated:** Prose steganography, `float32` mantissa covert channels, handle-reset laundering, multi-query "20-Questions" binary-search exfiltration, *and* pooled cohort-differencing / combinatorial group testing.
* **Mandatory Runtime Enforcement:**
  1. **Typed Primitive & Quantized-Confidence Output Simplex (Zero `float32` Mantissa Leaks):** Free-form string types (`str`, `bytes`) and raw IEEE-754 `float32` confidence outputs (which leak 23 mantissa bits in a single call!) are prohibited across the quarantine boundary. Confidence thresholds (`p >= 0.90`) either evaluate *inside* the adapter (returning 1 boolean bit) or emit **4-bit quantized deciles (`0.0, 0.1, ..., 1.0`)**, charging exact $\log_2(11) \approx 3.46\text{ bits}$ to the QIF ledger.
  2. **Provenance-Set Entity-Keyed QIF Ledger in `_enclaveifc` (Defeating Handle Laundering, Empty-Entity Bypass, Lock-Cycle Resets & Pooled Group Testing):** Budgets are settled atomically in `_enclaveifc`'s (`UID 704`, per [`FEATURE_AGENT_IFC_AND_DELEGATION.md`](FEATURE_AGENT_IFC_AND_DELEGATION.md)) Apple `SEP`-sealed 24-hour rolling journal (`i64` millibits, `12,000 mb = 12.0 bits`) strictly by individual canonical subject identity **`EntityKey(e) = BLAKE3_keyed(K_vault, canonical_entity_id(e))`** (with a mandatory non-empty fallback SimHash/URI `EntityKey` on unstructured `C3`/`C4` inputs so $\mathcal{E}(\text{input}) \neq \emptyset$). For any input carrying [`CaMeL`/`FIDES` SSA provenance taint set](FEATURE_AGENT_IFC_AND_DELEGATION.md) $\mathcal{E}(\text{input}) = \{e_1, \dots, e_m\}$ ($1 \le m \le 64$), call $k$ **conservatively charges every constituent entity simultaneously**:
     $$\forall e \in \mathcal{E}(\text{input}): \quad L\big(\text{EntityKey}(e)\big) + \log_2 |\mathcal{Y}^{(k)}| \le B_{\text{max}} \quad (\text{default } B_{\text{max}} = 12.0\text{ bits})$$
     Exceeding $12.0\text{ bits}$ on *any* entity $e \in \mathcal{E}(\text{input})$ halts execution and requires a **Class `A3` hardware human-intent declassification grant** (per [`FEATURE_HARDWARE_CUSTODY_PROFILES.md`](FEATURE_HARDWARE_CUSTODY_PROFILES.md)). Unstructured `C3`/`C4` inputs without a structured `EntityKey` are charged against the **24-hour SEP-checkpointed `global_unstructured_c3_c4_24h_pool`** (`≤ 12,000 mb` across all sessions and URIs, `FS-704 §3.3`), never a session-scoped pool.
     **Fan-In Overflow (`MUST`, `F-022`):** if $|\mathcal{E}(\text{input})| > 64$, `_llmagent` MUST abort fail-closed with `E2BIG: PROVENANCE_FANIN_EXCEEDED` before running `Class 1` or `declassify_enum`; the set is never truncated.
  3. **Eagerly Verified RLCD Calibration LUT:** Companion `ece_calibration_lut` layers are 100% eagerly hydrated ($<5\text{MiB}$) by `enclave-cas` and verified for **Expected Calibration Error ($\text{ECE} \le 0.015$)** computed over **15 equal-mass bins** on the TUF-pinned `enclave-calib-eval-v1` corpus before returning the `SCM_RIGHTS` `FDSet`.

### 4.2 Class 2 (`DISCRETE_DIFFUSION`): `LLaDA 2.0`, `Dream`, `FS-DFM` — `DINGO` DFA Trellis & `RAEC` Step-Watchers

* **Threat Eliminated:** Parallel unmasking grammar crashes, recursive-CFG state blowup, bidirectional prompt contamination, intermediate denoising priming, and $t > 0$ PII draft leakage.
* **Mandatory Runtime Enforcement:**
  1. **Bounded-Depth `DINGO` DFA Trellis & Prefix-Locked Block Diffusion:** depot tool JSON Schemas are restricted to **bounded nesting depth ($d \le 4$)** and compiled ahead-of-time at `admit` into minimal DFAs ($\le 4,096$ states, preventing exponential CFG-to-DFA memory blowup on 8GB M1 Macs). Prompt tokens execute under **Prefix-Locked Block Diffusion** (frozen input KV-cache; bidirectional attention restricted to active response `[MASK]` blocks), maintaining forward-backward reachability masks $R_{\text{fwd}}[i, q], R_{\text{bwd}}[i, q]$ in $O(L \cdot |Q|)$ Metal scan time ($<4\%$ overhead).
  2. **Zero-Draft IPC Barrier & Fence-Synchronized GPU/CPU Scrubbing:** Intermediate denoising states $x_T, \dots, x_1$ reside inside an isolated per-request `MTLHeap` (bypassing `MLX`'s shared caching allocator). Zero bytes cross IPC until $t = 0$ passes `DINGO` and `RAEC` checks, after which the adapter executes **Fence-Synchronized Dual Zeroization**: `MTLCommandBuffer::waitUntilCompleted()` $\to$ `MTLBlitCommandEncoder::fillBuffer(0)` $\to$ CPU `explicit_bzero()` + `seq_cst` fence (eliminating async GPU-after-CPU writeback races).
  3. **Output Caps & Canary Placement (`MUST`, `F-027`):** the manifest MUST declare `max_diffusion_steps <= 64` and `max_output_bytes <= 65536`. `CNRY_SEP_*` literal canary tripwires are evaluated **only on the committed $t = 0$ output** (intermediate $t > 0$ drafts never leave the `MTLHeap` and are never scanned, so random unmasking cannot cause false trips); a $t = 0$ match trips in `< 1 ms`.
  4. **Refusal-Aware Early Commitment (`RAEC`) + ANE Step-Watchers:** At milestone steps $t \in \{\lceil 0.75T \rceil, \lceil 0.5T \rceil, \lceil 0.25T \rceil\}$, lightweight ANE probes check $p_\theta(x_0 \mid x_t)$ for refusal-suppression priming or raw memorized PII—aborting in $<1.5\text{ms}$ if contaminated.

### 4.3 Class 3 (`RECURRENT_SSM_TTT`): `Mamba-3`, `RWKV-7`, `Titans`, `TTT` — CoW `StateSnapshotDAG` & `HiSPA` Defense

* **Threat Eliminated:** Cross-turn continuous recurrent-state PII entanglement (GDPR violation), sub-window **Hidden State Poisoning Attacks (`HiSPA`)**, Metal allocator bleed, crash core-dump persistence, and MacBook lid-close hibernation (`/var/vm/sleepimage`) persistence.
* **Mandatory Runtime Enforcement:**
  1. **Metal Copy-on-Write `StateSnapshotDAG` + Sleep/Crash/Yank Hardware Zeroizer:**
     * Clean system state $h_{\text{sys}}$ (and `Titans` base memory $M_{\text{sys}}$) is locked hardware read-only (`mach_vm_protect(..., VM_PROT_READ)`).
     * Ingesting data with confidentiality $C > \text{PUBLIC}$ forks an isolated `MTLHeap` Copy-on-Write arena $(h_{\text{task}}, \Delta W_{\text{TTT}})$ tagged with taint label $C$ (and hardware `EMTE` tags on M5), protected against crash serialization by process-wide `RLIMIT_CORE = 0`, `PT_DENY_ATTACH`, and `EXC_CORPSE_NOTIFY` masking.
     * **Fence-Synchronized Exit, Screen-Lock & Hibernation Zeroization:** On sub-task exit—**AND synchronously upon `IORegisterForSystemPower` (`kIOMessageSystemWillSleep`) lid-close interrupts, `com.apple.screenIsLocked` (`Cmd+Ctrl+Q`), or direct `L3` `IOKit` YubiKey USB removal**—the enclave completes in-flight GPU work, runs `MTLBlitCommandEncoder::fillBuffer(0)` + CPU `explicit_bzero()` over $(h_{\text{task}}, \Delta W_{\text{TTT}})$ in $<0.8\text{ms}$ *before* acknowledging kernel sleep (guaranteeing tainted SSM states never touch `/var/vm/sleepimage`!).
  2. **Dual-Trigger System-Anchor Re-Injection (Closing the Sub-Window `HiSPA` Gap):** The injection operator is defined explicitly (`F-027`) as convex mixing toward the clean system state, $\mathcal{T}(h_{\text{curr}}) = (1 - \alpha)\, h_{\text{curr}} + \alpha\, h_{\text{sys}}$ with `anchor_mix_alpha` $\alpha \in [0.25, 1.0]$ from the signed manifest; $\alpha = 1.0$ (default) is a full reset to $h_{\text{sys}}$ followed by re-prefill of the system prefix. $\mathcal{T}$ fires **both** every $W = 2,048$ ingested tokens **AND unconditionally at the exact `Ingest -> Generate` phase transition** (after the final untrusted input token and *before* output token #1 is sampled)—preventing short $<2,048$-token payloads from saturating SSM forget gates $(\Delta_t, B_t)$ right before tool decoding.

### 4.4 Class 4 (`BYTE_OR_CONCEPT`): `BLT` & `LCM`/`SONAR` — SIMD `Byte-DFA` & `Smooth-LCM` `LEACE` Clamping

* **Threat Eliminated:** BPE boundary-splitting bypasses in `BLT`, confused-deputy surrogate forgery, and both linear *and* non-linear PII recovery inside `LCM` `SONAR` embeddings.
* **Mandatory Runtime Enforcement:**
  1. **Canonical UTF-8 NFC + MAC-Authenticated Format-Preserving Synthetics (`BLT`):** Raw L4 PII is vaulted prior to `BLT` ingestion (so `BLT` never receives raw SSNs to Base64/Hex-encode). Inputs undergo UTF-8 `NFC` normalization + zero-width stripping, and surrogates carry a per-session `BLAKE3_keyed` MAC tag (`SYNTH-SSN-904-00-1182-a91f4c` — a reversible `C4` surrogate that exists **only** in `L2`/`L3` under a Cedar `Custody::ReversibleTokenize` grant; otherwise SSNs are erased to `[REDACTED_SSN_C4]`, `ADR-007`; the tag defeats confused-deputy detokenization of attacker-forged tags), validated on output by an ARM64 NEON **`Byte-DFA`** invariant to `BLT` patch splits.
  2. **Pre-Decoder `LEACE` + $d_\chi$-Privacy `Smooth-LCM` Clamping:** The noise scale is bounded below by the manifest's `smooth_lcm_sigma_min` ($\sigma \ge \sigma_{\min}$, verified at `admit`). Because `LCM` can paraphrase canaries into concept space, `Class 4` additionally checks **`SONAR` cosine canaries**: an output concept $c_{\text{out}}$ with $\cos(c_{\text{out}}, c_{\text{canary}}) \ge 0.88$ (`sonar_canary_cos_threshold`) trips the canary breaker (`F-027`). Because `LEACE` orthogonal projection $P_{\perp \text{PII}} c_k$ alone removes only *linear* PII subspaces (leaving non-linear MLP manifolds potentially invertible), the ANE pre-decoder hook pairs `LEACE` with **SAE non-linear feature clamping + bounded-norm calibrated Gaussian smoothing ($P_{\perp \text{PII}} c_k + \mathcal{N}(0, \sigma^2 I)$, local metric $d_\chi$-privacy)** before `SONAR` surface text decoding.

### 4.5 Class 5 (`SPECULATIVE_OR_RECURRENT_DEPTH`): `Huginn`, `COCONUT` & `EAGLE-3` — Sponge Watchdog, Latent Circuit Breakers & Draft-Tree Zeroization

* **Threat Eliminated:** Fanless M1 thermal/battery "sponge" DoS via unbounded recurrent loops, unmonitored "dark reasoning" in continuous latent thought (`COCONUT`), and speculative draft-tree timing/memory side-channels.
* **Mandatory Runtime Enforcement:**
  1. **Thermal-Coupled Metal Iteration Watchdog (`Huginn` & `COCONUT`):** Subscribes to `ProcessInfo.thermalState` and `IOPSCopyPowerSourcesInfo`:
     * On AC Power + `.nominal` thermal state: `r_max = manifest.max_recurrent_depth_nominal` (e.g., $32$ steps) + KL-divergence early-exit halting ($\text{KL}(p_r \parallel p_{r-1}) < 10^{-3}$).
     * On Battery OR `.fair` thermal state: clamps `r_max = 8` automatically; on `.serious`/`.critical`: clamps `r_max = 4` on E-cores/throttled Metal command queues—guaranteeing zero laptop thermal shutdowns.
  2. **ANE Mid-Loop Latent Circuit Breakers (`COCONUT` Continuous Thought):** When hidden vectors $h_1 \to h_2 \to \dots \to h_r \in \mathbb{R}^d$ feed directly back as continuous embeddings without discrete vocabulary projection, an in-loop ANE linear/SAE safety-cone probe inspects $h_r$ at every recurrent step ($<0.3\text{ms}$)—aborting and zeroizing the `MTLHeap` immediately if continuous reasoning enters an exfiltration or policy-evasion manifold.
  3. **Speculative Draft Scrubbing & Constant-Cadence Pacing (`EAGLE-3`):** Rejected draft token subtrees in unified memory are overwritten with zeros inside the same Metal command buffer before step commit, and accepted tokens are released across IPC on fixed **$20\text{ms}$ quantized ticks** (immediately dropped and zeroized if an `L3` YubiKey yank or Screen Lock fires mid-tick) so burst-acceptance counts never leak secret prefix predictability.

### 4.6 Class 6 (`JEPA_EBM_WORLD_PLANNER`): `V-JEPA 2-AC` (Phase 1) and `H-JEPA` + `EBM` + `MPC` Planners (Research Horizon) — Target-Resolved Energy Barrier, Surprise Abort & Sandboxed Actuation

* **Threat Eliminated:** WindowServer-vs-Accessibility TOCTOU frame leaks, spurious low-energy hallucinations in unnormalized Energy-Based Models (`EBMs`), `Configurator` objective hijacking, `H-JEPA` macro-to-micro confused-deputy escalation, continuous-action `(x, y, Δt)` steganography, and episodic Short-Term Memory (`STM`) PII embedding inversion.
* **Mandatory Runtime Enforcement:**
  1. **Frame-Synchronous `IOSurface` Masking (Defeating `ScreenCaptureKit` / `AXUIElement` TOCTOU Races):** Because `SCStream` delivers $60\text{Hz}$ GPU frames asynchronously while Mach `AXUIElement` tree queries lag by $2\text{–}15\text{ms}$ during scrolling or `Cmd+Tab` switches, the enclave combines **(a)** compositor-level `SCContentFilter` window exclusion (blocking unauthorized apps inside WindowServer before capture), **(b)** an **in-frame ANE Visual PII/Text Bounding-Box Fast-Detector ($<2.5\text{ms}$)** executed directly on the captured `IOSurface` snapshot (union-merged with `AXUIElement` bounds), and **(c)** automatic full-frame Gaussian blur during high-velocity scroll/window-transition deltas until spatial layout stabilizes.
  2. **Hardwired Enclave $C_{\text{intrinsic}} = +\infty$ Energy Barrier & Conformal Energy Calibration:** Because `AMI`-style EBMs output unnormalized scalar energies $E \in (-\infty, +\infty)$ minimized via inference-time `MPC` / Cross-Entropy Method (`CEM`) or $\nabla_a E$ gradient search, neural $C_{\text{trainable}}$ weights alone can be fooled by out-of-distribution states. The adapter clamps `C_EBM` to finite bounds $[-E_{\max}, +E_{\max}]$ (preventing IEEE-754 `-Inf + +Inf = NaN` barrier cancellation) and wraps the `MPC` objective directly inside Metal:
     $$E_{\text{enclave\_total}}(\tilde{s}_{t+1}, a_t) = \text{clamp}\big(C_{\text{EBM}}(\tilde{s}_{t+1}, a_t), -E_{\max}, E_{\max}\big) + \mathbb{I}_{\neg \text{CedarAllow}(\text{ResolveDOMOrAXTarget}(a_t), \mathcal{B}_{\text{micro}})} \cdot (+\infty) + \mathbb{I}_{\text{SafetyCone}(\tilde{s}_{t+1}) > \tau} \cdot (+\infty)$$
     **Predicted ≠ observed (`MUST`, `F-026`):** $\tilde{s}_{t+1}$ is the model's own prediction and cannot by itself authorize an action. Cedar evaluates the **resolved target** `(app_bundle_id, ax_role, ax_title, url_origin, dom_selector)` obtained from the browser DOM / `AX` tree — never raw pixel coordinates `(grid_x, grid_y)` — and MUST deny targets inside `_enclaveintent`, `CoreAuthUI`, `System Settings`, `Keychain Access` or `Terminal`.
     Additionally, unnormalized energy thresholds are calibrated via **split-conformal energy quantiles ($E_{\alpha}$)** verified at model onboarding so high-uncertainty OOD rollouts ($E > E_{0.99}$) halt automatically.
  3. **Hierarchical `H-JEPA` `PoP-Biscuit` Attenuation & Action Quantization Diode:** When the high-level `H-JEPA` planner commits to macro-subgoal $g_{\text{macro}}$, the enclave attenuates its sender-constrained [`PoP-Biscuit` token](FEATURE_AGENT_IFC_AND_DELEGATION.md) ($\mathcal{B}_{\text{micro}} \subset \mathcal{B}_{\text{macro}}$) to restrict low-level `MPC` candidate actions strictly to authorized semantic `AXUIElement` / depot tool IDs—quantizing continuous float parameters to eliminate sub-pixel/timing steganography.
  4. **Post-Step Prediction-Surprise Gate (`MUST`):** after executing $a_t$, if $\lVert \text{Encoder}(x_{t+1}) - \tilde{s}_{t+1} \rVert_2 > \tau_{\text{surprise}}$ (manifest `world_planner_caps.tau_surprise`), `_llmagent` MUST abort multi-step actuation immediately (`EAGAIN: WORLD_MODEL_SURPRISE_ABORT`) and replan from observed state.
  5. **Bounded Planning (`MUST`):** `world_planner_caps` is mandatory for this class: `max_horizon <= 5`, `max_candidates <= 64`, `max_cem_iters <= 4`, `e_max <= 1000.0`, `step_wallclock_ms <= 150` (schema-enforced, `V18`).
  6. **Sandboxed Actuation Only (`MUST`, `OQ-21`):** GUI actions are executed inside an isolated, Seatbelt-confined browser profile over the Chrome DevTools Protocol (`CDP`, `actuation_sandbox = "cdp_browser"`). `_llmagent` MUST NOT hold macOS TCC `Accessibility` or call `CGEventPost` against the desktop.
  7. **Episodic `STM` CoW & Hibernation/Yank-Safe Isolation:** `AMI` Short-Term Memory (`STM`) embeddings pass through `LEACE` + SAE clamping, reside in isolated `MTLHeap` Copy-on-Write arenas (`RLIMIT_CORE = 0`), and execute **fence-synchronized GPU + ANE `IOSurface` + CPU zeroization** upon episode exit, `kIOMessageSystemWillSleep` lid-close interrupts, `com.apple.screenIsLocked`, or direct `L3` YubiKey USB removal.

---

## 5. Conceptual Model Lifecycle & Pre-Publication How-To Documentation Scope (`L1`, `L2`, `L3`)

> **[STATUS: CONCEPTUAL UX CONTRACT — EXACT USER HOW-TO GUIDES DEFERRED TO PRE-PUBLICATION PHASE]**  
> *Note: Exact CLI command syntax, lockfile key names, and step-by-step developer tutorials will be authored once all architectural tracks (Tracks 1–6) are locked down prior to public GitHub release. This section establishes the **conceptual 3-stage lifecycle** and **cross-tier auto-adaptation contract** so that future documentation has a clean, deterministic mental model to target.*

### 5.1 Conceptual 3-Stage Model Lifecycle (Import/Attest $\to$ Declare/Include $\to$ Hydrate/Auto-Adapt)

Rather than requiring application developers to manually wire up `DINGO` diffusion grammars, SSM memory-wiping hooks, or `Byte-DFA` scanners when switching models, the user experience separates **model supply-chain onboarding** from **zero-touch local control adaptation**:

1. **Stage 1 — Upstream Onboarding & Topological Attestation (*"Import"*):**
   * An ML/Platform publisher points the packaging pipeline at raw model artifacts (`.safetensors` or portable CoreML `.mlpackage` `MIL`).
   * The pipeline automatically introspects tensor graph signatures (Section 3.1) to bind the unspoofable `ExecutionClass`, chunks via `FastCDC` + `Bao`, applies tier-appropriate encryption/signing (`L1` keyless OIDC, `L2` namespace-keyed convergent AEAD + corporate TUF, `L3` $m$-of-$n$ YubiKey quorum), and publishes to the `ORAS` R2 origin—emitting a single tier-invariant `cas://blake3-bao-v1/<logical_plaintext_hex64>` URI.
2. **Stage 2 — Declarative Project Inclusion (*"Include"*):**
   * Teams reference only the canonical `cas://` URI inside their repository's enclave manifest alongside their minimum required swarm profile (`L1`, `L2`, or `L3`). No model-architecture security flags are trusted or required in local application configs.
3. **Stage 3 — Local Swarm Hydration & Control Auto-Adaptation (*"Install & Adapt"*):**
   * On any developer's M1–M5 MacBook, `enclave-cas` hydrates chunks according to the active Swarm Profile (`L1` Bonjour LAN + R2, `L2` `Biscuit`-gated mesh, or `L3` Zero-Seed Chunked OHTTP + Sealed APFS Snapshot), runs local pre-admission sanitization + chip-specific ANE compilation if needed, and hands the read-only `SCM_RIGHTS` descriptor + verified `ExecutionClass` to `EnclaveModelAdapter::bind()`.
   * **All 6 local enclave controls** (IPC wire contract, constrained decoder, RAM/state zeroizer, PII surrogate format, Cedar QIF bit-budget ledger, and Darwin thermal/Metal loop watchdogs) reconfigure themselves **automatically and fail-closed**.

### 5.2 Architectural Interaction Matrix: `L1` / `L2` / `L3` Swarm Profiles $\times$ All 6 Model Classes

| Tier-1 Model Class                                                                | `L1: startup-zero-ops` Hydration & Adaptation                                                                                              | `L2: enterprise-mesh` Hydration & Adaptation                                                                                  | `L3: classified-enclave` Hydration & Adaptation                                                                                               |
|:----------------------------------------------------------------------------------|:-------------------------------------------------------------------------------------------------------------------------------------------|:------------------------------------------------------------------------------------------------------------------------------|:----------------------------------------------------------------------------------------------------------------------------------------------|
| **`1. DISCRIMINATIVE_RLCD`**<br>*(`jev`, $0.5\text{B}$–$2\text{B}$ `.mlpackage`)* | Eager Bonjour/R2 pull $\to$ local host ANE compile (`H13G`–`H17G`) $\to$ `uchg` + **12-bit Cedar QIF ledger**.                             | `Biscuit`-gated pull $\to$ SEP decrypt $\to$ local ANE compile $\to$ `uchg` + QIF ledger.                                     | OHTTP pull $\to$ staging ANE compile $\to$ **sealed `MNT_RDONLY` APFS snapshot** + YubiKey step-up on QIF budget exhaustion.                  |
| **`2. DISCRETE_DIFFUSION`**<br>*(`LLaDA 2.0`, `Dream`, `FS-DFM`)*                 | Fault-safe lazy Range/`FUSE-T` $\to$ auto-loads **`DINGO` DFA trellis** + `RAEC` step-watcher + $t>0$ IPC block.                           | Same fault-safe lazy hydration over mTLS mesh $\to$ atomic `uchg` promotion + `DINGO`/`RAEC`.                                 | **100% Pre-Hydrated via `clonefile(2)`** + Sealed APFS Snapshot prior to first denoising trajectory.                                          |
| **`3. RECURRENT_SSM_TTT`**<br>*(`Mamba-3`, `RWKV-7`, `Titans`, `TTT`)*            | Fast header/init pull ($<400\text{ms}$) $\to$ sequential lookahead $\to$ **CoW `StateSnapshotDAG` + `memset_s` wipe**.                     | Keyed Convergent AEAD stream $\to$ immediate `VM_PROT_READ` lock on $h_{\text{sys}}$ + `HiSPA` anchor re-injection.           | Sealed APFS weights + **`mlock()` non-swappable RAM arena** for $(h_{\text{task}}, \Delta W_{\text{TTT}})$ + USB YubiKey yank-to-zeroize.     |
| **`4. BYTE_OR_CONCEPT`**<br>*(`BLT`, `LCM` / `SONAR`)*                            | Atomic co-hydration: `LCM` weights cannot resolve without companion `LEACE` nullspace matrix + **`Byte-DFA`**.                             | Co-hydrated under identical namespace capability token + verified via joint TUF target set.                                   | Model weights + `LEACE` nullspace sealed into the **same atomic APFS snapshot** (zero version skew).                                          |
| **`5. SPECULATIVE_RECURRENT`**<br>*(`Huginn`, `EAGLE-3` draft)*                   | Shared recurrent core eagerly hydrated on LAN $\to$ arms **Darwin thermal loop clamp** + $20\text{ms}$ IPC pacing.                         | Co-pinned TUF target ensures `EAGLE-3` draft head matches exact base hidden-state epoch + draft zeroization.                  | Sealed APFS Snapshot + permanent hardware thermal/iteration watchdog armed prior to FD return.                                                |
| **`6. JEPA_EBM_WORLD_PLANNER`**<br>*(`AMI Labs` `H-JEPA`/`EBM`, `V-JEPA 2-AC`)*   | Atomic co-hydration of `H-JEPA` weights + conformal energy table $E_\alpha$ $\to$ arms **$C_{\text{intrinsic}} = +\infty$ `MPC` barrier**. | Co-hydrated under clinical/enterprise `ns` capability + `ScreenCaptureKit` `IOSurface` blur + `H-JEPA` `Biscuit` attenuation. | Sealed APFS Snapshot + `mlock()` episodic `STM` + **Class `A4` Chained `Touch ID -> YubiKey` co-signature required for OOD energy override**. |

### 5.3 Pre-Publication Documentation Deliverables Tracker (To Author Near Public Release)

Once CLI names, configuration schemas, and YubiKey/IFC ceremonies across Tracks 1–6 stabilize, the following public-facing guides will be authored for GitHub adopters and security auditors:

* [ ] **`docs/guides/IMPORTING_MODELS_L1_L2_L3.md`:** Step-by-step publisher runbooks for packaging HuggingFace / `mlx-community` / custom weights across `L1` (GitHub Actions OIDC + R2), `L2` (Enterprise KMS/TUF), and `L3` (Air-gapped YubiKey quorum).
* [ ] **`docs/guides/POST_AR_DEVELOPER_QUICKSTART.md`:** Copy-paste developer examples demonstrating how pinning a `jev` classifier (`Class 1`), `LLaDA` diffusion coder (`Class 2`), `Mamba-3`/`Titans` long-context auditor (`Class 3`), `BLT`/`LCM` model (`Class 4`), `Huginn`/`COCONUT` reasoner (`Class 5`), or `AMI Labs` `H-JEPA`/`EBM` world planner (`Class 6`) automatically switches local enclave protections with zero application code churn.
* [ ] **`docs/guides/CALIBRATION_AND_LEACE_PREP.md`:** Reference workflow for generating RLCD Brier calibration tables (`Class 1`), `SONAR` `Smooth-LCM` `LEACE` + SAE projection matrices (`Class 4`), and split-conformal energy quantile tables $E_\alpha$ (`Class 6`) during model onboarding.

---

## 6. Frontier AI Lab Standards Crosswalk: Google DeepMind, Anthropic, OpenAI & `AMI Labs`

> **Non-normative author positioning.** The "Ahead"/"Vastly Ahead" labels compare an **unimplemented** depot design with the author's unverified perception of other organisations' products. They are not sourced findings and impose no requirement.

| Enclave Capability                                                                                 | Google DeepMind Standing & Internal Equivalent                                                                                                                                                                                                                                                                                                                                                 | Anthropic Standing & Internal Equivalent                                                                                                                                                                                                               | OpenAI Standing & Internal Equivalent                                                                                                                                                                       |
|:---------------------------------------------------------------------------------------------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **`Class 1: DISCRIMINATIVE_RLCD`**<br>*(`jev` Diode + Cumulative QIF Budget)*                      | **Ahead of Public / Aligned with `CaMeL` Research:** DeepMind's `CaMeL` (`arXiv:2503.18813`) advocates strict control/data separation, but internal developer agents still rely heavily on generative Gemini calls; our **12-bit Cedar QIF ledger** closes the multi-query binary-search gap formally.                                                                                         | **Ahead of Current Tooling:** Anthropic deploys internal **Constitutional Classifiers** for jailbreak filtering, but lacks a local information-theoretic `jev` RLCD quarantine diode with per-record Shannon leakage accounting on developer MacBooks. | **Vastly Ahead:** OpenAI's safety stack leans heavily on autoregressive moderation endpoints and verbalized CoT monitoring—neither of which bounds steganographic or 20-Questions bit leakage on local PII. |
| **`Class 2: DISCRETE_DIFFUSION`**<br>*(`DINGO` DFA + `RAEC` Step-Watchers)*                        | **At Frontier Parity (Local Edge Equivalent of `Gemini Diffusion`):** DeepMind pioneered commercial parallel diffusion (`Gemini Diffusion`) in cloud TPUs; our spec is the **first open architecture** bringing `DINGO` DFA schema infilling + `RAEC` step-watching to local Apple Silicon (`LLaDA 2.0`/`Dream`).                                                                              | **Ahead (Greenfield):** Anthropic's Claude lineage is currently purely autoregressive; Claude Desktop / depot lacks non-left-to-right diffusion grammar or intermediate denoising trajectory guards.                                                     | **Ahead (Greenfield):** OpenAI's `GPT` / `o`-series developer APIs and Codex CLI assume causal left-to-right token streams and break if pointed at masked diffusion engines without shim wrappers.          |
| **`Class 3: RECURRENT_SSM_TTT`**<br>*(`StateSnapshotDAG` + `HiSPA` Defense)*                       | **Ahead on Security Governance for Google's Own `Titans`:** Google Research invented `Titans` (test-time neural memory), yet published zero endpoint security specs solving **GDPR PII entanglement in test-time fast weights ($\Delta W_t$)** or `HiSPA` gate poisoning—our CoW `StateSnapshotDAG` + `memset_s` solves both!                                                                  | **Ahead:** Anthropic does not currently ship local SSM/TTT state-forking or continuous hidden-state cryptographic zeroizers in its depot ecosystem.                                                                                                      | **Ahead:** OpenAI relies on cloud stateless/KV-cached Transformer sessions; lacks local recurrent/fast-weight Copy-on-Write taint sandboxing.                                                               |
| **`Class 4 & 5: BYTE_OR_CONCEPT` & `RECURRENT_DEPTH`**<br>*(`Byte-DFA`, `LEACE`, Sponge Watchdog)* | **Ahead on Endpoint Silicon Integration:** Combines Meta FAIR's `BLT`/`LCM` paradigms with ANE `LEACE` subspace erasure and Darwin XNU thermal-loop clamping (`Huginn`) on developer laptops.                                                                                                                                                                                                  | **Aligned with SAE Interpretability Research, Ahead on Edge Enforcement:** Operationalizes Anthropic-style activation/subspace clamping directly inside real-time Apple ANE pre-decoder hooks on M1–M5 laptops.                                        | **Ahead:** Protects fanless developer laptops against adaptive-compute sponge attacks and speculative `EAGLE-3` draft-tree timing side-channels.                                                            |
| **`Class 6: JEPA_EBM_WORLD_PLANNER`**<br>*(`AMI Labs` `H-JEPA`/`EBM` + `Genie 3`)*                 | **Ahead on Action-Planning Governance:** DeepMind leads on generative `Genie 3` world simulation, while **Yann LeCun's `AMI Labs`** (March 2026) leads non-generative `H-JEPA`/`EBM` planning—our enclave is the **first specification anywhere** binding LeCun's theoretical $C_{\text{intrinsic}}$ guardrail directly to deterministic Cedar/`Biscuit` policies inside Metal `MPC` rollouts! | **Vastly Ahead:** Anthropic's Computer-Use Claude takes raw desktop screenshots into an autoregressive VLM without `ScreenCaptureKit` pre-encoder GPU masking or `H-JEPA` `MPC` energy barriers.                                                       | **Vastly Ahead:** OpenAI's `Operator` / CUA pipelines rely on cloud VLM token loops rather than local non-generative `H-JEPA` world models with cryptographic episodic `STM` erasure.                       |

---

## 7. Production Readiness Review (PRR) & Operational SRE Runbooks: SLIs, SLOs, FMEA & Audit Receipts

### 7.1 Service Level Indicators (SLIs) & Service Level Objectives (SLOs) on Apple M1 Baseline

| SLI Metric                                         | Measurement Mechanism                                                                                                       | Target SLO (`M1` Baseline $\to$ `M5`)                                   | Automated Error-Budget Action                                                                          |
|:---------------------------------------------------|:----------------------------------------------------------------------------------------------------------------------------|:------------------------------------------------------------------------|:-------------------------------------------------------------------------------------------------------|
| **`DISCRIMINATIVE_RLCD` Gate Latency**             | p99 wall-clock for `jev`-class ANE decision call                                                                            | **$p99 \le 18.0\text{ms}$ on M1 ANE**                                   | Fallback to Metal GPU queue if ANE busy; alert if ECE drifts $>0.015$ (`enclave-calib-eval-v1`).       |
| **`DINGO` Constrained Diffusion Overhead**         | Wall-clock delta vs. unconstrained `LLaDA`/`Dream` step                                                                     | **$\le 5.0\%$ latency overhead; $100\%$ valid JSON**                    | Pre-compile bounded ($d \le 4$) depot JSON Schemas to minimal DFAs ($\le 4,096$ states) at `admit` time. |
| **SSM / `Titans` / `STM` Fence-Synced Erasure**    | Residual non-zero bytes in isolated `MTLHeap` $(h_{\text{task}}, \Delta W_{\text{TTT}}, \text{STM})$ post-turn or pre-sleep | **$0\text{ bytes}$ residual ($100\%$ invariant) in $\le 1.0\text{ms}$** | Verified via GPU+CPU fence + canary page scan; non-zero byte triggers `SIGABRT` + `SEV-1`.             |
| **Fanless M1 Air Thermal Stability (`Huginn`)**    | Seconds spent in `ProcessInfo.thermalState == .critical` attributable to enclave                                            | **$0\text{ seconds}$**                                                  | Hard clamp `r_max -> 4` at `.serious` and yield GPU command buffer for $250\text{ms}$.                 |
| **`H-JEPA` / `EBM` `MPC` Energy Barrier Overhead** | Wall-clock delta of injecting deterministic $C_{\text{intrinsic}}$ + ANE cone check across 128 `CEM` rollouts               | **$p99 \le 2.0\text{ms}$ per planning step**                            | Vectorize candidate action capability checks via bitmask lookup before GPU rollout.                    |
| **Misclassified / Obfuscated Model Admission**     | Models admitted whose tensor shapes or runtime `MLX`/`MIL` ops contradict `execution_class`                                 | **$0$ admissions ($100\%$ hard invariant)**                             | `enclave-cas` refuses `SCM_RIGHTS` `FDSet` return and logs signed security event.                      |

### 7.2 Failure Modes & Effects Analysis (FMEA)

| Failure Scenario                                                                                    | Impact if Unmitigated                                                                                                                | Automated Deterministic Mitigation                                                                                                                                                                |
|:----------------------------------------------------------------------------------------------------|:-------------------------------------------------------------------------------------------------------------------------------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Publisher Renames `Mamba-3` Tensors to `self_attn.q_proj` (`AR_CAUSAL`)**                         | Static key-name check passes; SSM layers retain PII across turns.                                                                    | **Runtime Compute-Graph Operator Attestation** intercepts `mlx::core::scan` / persistent state allocation in RAM and aborts (`EACCES`) prior to first forward pass.                               |
| **Compromised Orchestrator Uses `float32` Mantissas, Handle Resets, or Cohort Subset Differencing** | Steals 23 bits/call via `float32`, resets QIF cap via new handles, or differences $S$ vs. $S \cup \{e^*\}$ via pooled group testing. | **4-bit decile quantization** + **Provenance-Set Entity-Keyed QIF Ledger** (`BLAKE3_keyed(K_vault, canonical_entity_id)`) charges $\forall e \in \mathcal{E}(\text{input})$ ($m \le 64$) for 24h. |
| **50-Token `HiSPA` Payload Inside Short 400-Token Ticket (`< 2048` Window)**                        | Saturates SSM forget gates before periodic $W=2048$ anchor fires.                                                                    | **Unconditional `Ingest -> Generate` Phase-Boundary Anchor Re-Injection** restores system safety invariants right before output token #1 is sampled.                                              |
| **Developer Closes MacBook Lid (`sleepimage`) OR Inference Host Crashes (`ReportCrash`)**           | Kernel writes `mlock()` unified RAM containing tainted SSM/`STM` states to `/var/vm/sleepimage` or `/cores/core.<pid>`.              | `IORegisterForSystemPower` (`kIOMessageSystemWillSleep`) forces $<1\text{ms}$ GPU+CPU wipe before sleep; `RLIMIT_CORE = 0` + `PT_DENY_ATTACH` + `EXC_CORPSE_NOTIFY` masking block crash dumps.    |
| **User Scrolls / `Cmd+Tab`s During `H-JEPA` Capture (`ScreenCaptureKit` vs. `AXUIElement` Lag)**    | Stale `AXUIElement` bounds leave 1–2 frames of unredacted PII visible to `JEPA` encoder.                                             | `SCContentFilter` compositor window exclusion + **in-frame ANE Visual PII Fast-Detector ($<2.5\text{ms}$)** on the exact `IOSurface` + full-frame blur on high-velocity scroll deltas.            |
| **8GB Base M1 MacBook Hits Wired Memory Ceiling During Concurrent Tasks**                           | Memory pressure or allocator reuse leaks state.                                                                                      | Per-taint isolated `MTLHeap` wired cap ($1.5\text{GiB}$ ceiling on 8GB M1) rejects excess concurrency cleanly (`429 EnclaveMemoryPressure`); FileVault AES-XTS verified active at boot.           |

### 7.3 Zero-PII Adapter Execution Receipt (Track-3 & Track-6 ZK Compliance Seam)

Every governed inference session appends a SEP-signed, dual-hash (`BLAKE3` + `KoalaBear` `Poseidon2`), zero-PII JSONL receipt to `/var/log/enclave/adapter-audit.jsonl`—cryptographically joining [Track 3's `cas-audit.jsonl`](FEATURE_SWARM_SECURITY_PROFILES.md) (`logical_plaintext_blake3`) directly into [Track 6's `_enclavezk` (`UID 705`) Streaming `IVC` Compliance Prover (`FEATURE_SILICON_EMTE_AND_ZK_COMPLIANCE.md`)](FEATURE_SILICON_EMTE_AND_ZK_COMPLIANCE.md):

Receipt lines use the shared `EnclaveAuditEnvelopeV1` header (`CORE-V3`; replaces the earlier `ts_monotonic_ns` / `prev_receipt_blake3` fields, `F-039`), joined to the other journals by `rpc_seq_u64`:

<!-- schema: enclave-audit-envelope-v1 -->
```json
{
  "v": 1,
  "daemon_uid": 701,
  "boot_epoch_id": "2b9f6c1e-7d34-4a0b-9e21-5c8d3f6a1b07",
  "log_seq_u64": 5531,
  "rpc_seq_u64": 8810,
  "ts_utc_ms": 1762308012405,
  "spiffe_id": "spiffe://corporate.internal/enclave/uid/701",
  "prev_blake3": "5d2a90e1c4b8771000000000000000000000000000000000000000000000000a",
  "prev_poseidon2": "19e4a7c02b83f11400000000000000000000000000000000000000000000000b",
  "payload": {
    "logical_plaintext_blake3": "9a4f8c2e1b0d7743a51908c4e6b2d1f0883a7c5e9d1b4f2a6c8e0d2f4a6b8c0e",
    "execution_class_enforced": "RECURRENT_SSM_TTT",
    "runtime_graph_ir_blake3": "c02e71b400000000000000000000000000000000000000000000000000000000",
    "qif_millibits_charged": 3460,
    "hispa_boundary_anchor_applied": true,
    "ebm_intrinsic_barrier_vetoes": 0,
    "world_model_surprise_aborts": 0,
    "mtlheap_dual_zeroize_verified": true
  }
}
```

---

## 8. Future Section: Formal Verification & Mathematical Security Proofs Roadmap (All 6 Classes)

> **[STATUS: PLANNED — PHASE 2 POST-ARCHITECTURE LOCKDOWN]**  
> *Part of our 26-theorem formal verification suite across [`FEATURE_SWARM_SECURITY_PROFILES.md`](FEATURE_SWARM_SECURITY_PROFILES.md#8-future-section-formal-verification--mathematical-security-proofs-roadmap-l2--l3), [`FEATURE_HARDWARE_CUSTODY_PROFILES.md`](FEATURE_HARDWARE_CUSTODY_PROFILES.md#8-future-section-formal-verification--mathematical-security-proofs-roadmap-l2--l3), [`FEATURE_AGENT_IFC_AND_DELEGATION.md`](FEATURE_AGENT_IFC_AND_DELEGATION.md#8-future-section-formal-verification--mathematical-security-proofs-roadmap-l1l3), and [`FEATURE_SILICON_EMTE_AND_ZK_COMPLIANCE.md`](FEATURE_SILICON_EMTE_AND_ZK_COMPLIANCE.md#8-future-section-formal-verification--mathematical-security-proofs-roadmap-l1l3). Once `enclave-model.manifest.json` schemas and adapter traits are frozen, machine-checkable proofs will be developed across all six Tier-1 gates.*

| Proof ID | Target Class | Formal Property to Prove | Verification Toolchain | Mathematical Guarantee Statement |
| :--- | :---: | :--- | :---: | :--- |
| **`PROOF-M1-QIF`** | **`Class 1`**<br>*(RLCD / `jev`)* | **Adaptive Multi-Query & Cohort Group-Testing Mutual Information Bound** | **`Lean 4`** *(Information Theory + Cedar Semantics)* | Prove under adaptive chosen-query *and* overlapping-cohort composition ($Y_k = f_k(S_{\mathcal{E}_k}, Y_{1..k-1})$ over quantized outputs $\mathcal{Y}_k$) that provenance-set charging $\forall e \in \mathcal{E}*k: \sum*{k: e \in \mathcal{E}_k} \log_2 | \mathcal{Y}_k | \le B_{\text{max}}$ bounds per-entity leakage $I(S_e; Y_1, \dots, Y_K \mid S_{-e}) \le B_{\text{max}}$ bits—defeating differential cohort differencing and Dorfman group testing. |
| **`PROOF-M2-DINGO`** | **`Class 2`**<br>*(dLLMs)* | **Soundness & Bounded-State Termination of Prefix-Locked `DINGO` DFA Infilling** | **`Coq` / `Rocq`** | Prove for any depth-bounded ($d \le 4$, $ | Q | \le 4096$) minimal DFA $\mathcal{A}$ under Prefix-Locked Block Diffusion that every terminal sequence $x_0$ satisfies $x_0 \in \mathcal{L}(\mathcal{A})$ with probability $1$, and zero $t > 0$ tokens cross IPC prior to fence-synced `MTLHeap` zeroization. |
| **`PROOF-M3-SSM-WIPE`** | **`Class 3`**<br>*(SSM / `Titans`)* | **Non-Interference, GPU-Fence Ordering & Pre-Hibernation Zero State Remnance** | **`TLA+` (`Apalache`)** + **`LLVM-SAW`** | 1. Model-check `StateSnapshotDAG` + `kIOMessageSystemWillSleep` protocol to prove zero tainted bytes reach lower-confidentiality turns or `/var/vm/sleepimage`.<br>2. Verify via `SAW` + litmus memory-model semantics that `waitUntilCompleted -> fillBuffer(0) -> explicit_bzero` clears $100\%$ of $(h_{\text{task}}, \Delta W_{\text{TTT}})$ without GPU writeback races or dead-store elimination. |
| **`PROOF-M4-BYTEDFA`** | **`Class 4`**<br>*(`BLT` / `LCM`)* | **Patch-Invariance, Surrogate MAC Unforgeability & `Smooth-LCM` $d_\chi$-Privacy** | **`Lean 4`** | 1. Prove `Byte-DFA` + `BLAKE3_keyed` surrogate validation is invariant under arbitrary `BLT` byte-patch splits and EUF-CMA unforgeable against confused-deputy prompt synthesis.<br>2. Prove `LEACE` + SAE clamping + $\mathcal{N}(0, \sigma^2 I)$ satisfies metric $d_\chi$-privacy against both linear and Lipschitz non-linear `SONAR` inversion decoders. |
| **`PROOF-M5-HALT`** | **`Class 5`**<br>*(`Huginn` / `COCONUT` / `EAGLE-3`)* | **Bounded-Time Halting, Latent Cone Safety & Speculative Timing Non-Interference** | **`TLA+`** + **Jasmin/Constant-Time Check** | Prove worst-case Metal execution halts within $r_{\max}(\text{ThermalState}) \cdot \Delta t_{\text{step}}$ (or earlier upon ANE `COCONUT` safety-cone violation), and prove quantized $20\text{ms}$ IPC release leaks zero timing mutual information from rejected `EAGLE-3` branches. |
| **`PROOF-M6-EBM-MPC`** | **`Class 6`**<br>*(`AMI` `H-JEPA` / `EBM`)* | **Safety Invariance of Hardwired $C_{\text{intrinsic}} = +\infty$ Barrier Under `MPC`/`CEM` Optimization** | **`Lean 4`** + **`dReal`** *(SMT over Reals)* | Prove over IEEE-754 floating-point / extended-real optimization (`clamp` to $[-E_{\max}, E_{\max}]$ before adding `+Inf`, preventing `NaN` cancellation) that for arbitrary adversarial `C_EBM` weights and `Configurator` states, $\arg\min_{a_{0..T-1}} E_{\text{enclave\_total}}$ never selects an action $a_t \notin \text{Authorized}(\mathcal{B}_{\text{micro}})$. |

---

## 9. References & Citation Status (`F-009`)

| Reference                                                                | Status                                                                                                         |
|:-------------------------------------------------------------------------|:---------------------------------------------------------------------------------------------------------------|
| `LLaDA` / `LLaDA-8B` (Nie et al., 2025)                                  | `[Verified-ID]` arXiv:2502.09992 — Phase-1 target                                                              |
| `RWKV-7 "Goose"` (Peng et al., 2025)                                     | `[Verified-ID]` arXiv:2503.14456 — Phase-1 target                                                              |
| `EAGLE-3` (Li et al., 2025)                                              | `[Verified-ID]` arXiv:2503.01840 — Phase-1 target                                                              |
| `V-JEPA 2` (Assran et al., Meta FAIR, 2025)                              | `[Verified-ID]` arXiv:2506.09985 — Phase-1 target (encoder/predictor)                                          |
| `Mamba-3`, `Titans`, `BLT`, `LCM`/`SONAR`, `Huginn`, `COCONUT`           | Published research; adapters specification-only until a Phase-2 checkpoint is chosen                           |
| TypeSafe AI `jev` / RLCD (Sept 2026)                                     | `[Unverified]` — no public paper or repository located; `Class 1` targets generic ANE classifier heads instead |
| `AMI Labs` `H-JEPA` + `EBM` planner (2026)                               | `[Unverified — announcement only; no public weights]` — `Class 6` planner research horizon                     |
| `Genie 3` (Google DeepMind)                                              | Referenced only as an explicit Non-Goal (`NG3`)                                                                |
| `enclave-pack`, `enclave-adapter-v1` namespaces, `enclave-calib-eval-v1` | `[Internal depot Mechanism]` — to be built                                                                    |

---

## 10. Revision History

| Rev     | Date           | Author                                             | Normative Changes                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
|:--------|:---------------|:---------------------------------------------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| 1.0     | 2026-10        | Spec owner                                         | Initial Tracks 1 & 2 merged specification; `DESIGN-WORLD-MODELS-2026-002` retired into this document.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| 1.1     | 2026-10        | Spec owner                                         | Added runtime compute-graph attestation and `L1`/`L2`/`L3` interaction matrix.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| 1.2     | 2026-11        | Spec owner                                         | Second-pass internal review: QIF fan-in charging, `HiSPA` boundary anchor, `Class 6` energy clamp.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| **1.3** | **2026-11-04** | Remediation (`ADVERSARIAL_SPEC_REVIEW_2026-11-04`) | `F-009`: `enclave-pack` `enclave_adapter.*` namespaces, Phase-1 targets (`LLaDA-8B`, `RWKV-7`, `EAGLE-3`, `V-JEPA 2`), citation status table. `F-026`: DOM/`AX` target resolution, post-step surprise abort, mandatory `world_planner_caps`, `CDP`-sandboxed actuation, `Genie 3` Non-Goal. `F-027`: cross-RPC statelessness, unified `ECE <= 0.015` (15 equal-mass bins, `enclave-calib-eval-v1`), diffusion/output caps, `t = 0` and `SONAR` cosine canaries, explicit `Class 3`/`Class 4` operators, cross-silicon fail-closed margin. `F-022`: ` | E | > 64` → `E2BIG`; global 24h unstructured pool.`F-004`:`§2.4`.`F-032`: retirement note + this history.`F-039`:`EnclaveAuditEnvelopeV1` receipts. |
| 1.x-p1  | 2026-11-05     | Phase 1 gap remediation (`GapsDeDuped.me` §4)      | No normative requirement changed. Implementation status line updated; §11 Implementation Notes added.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| **1.4** | **2026-11-09** | Security hardening (`GAP-47`, `GAP-58`)            | Mechanized Lean 4 proofs and implemented runtime gates: (a) LeftoverLocals (CVE-2023-4969) zeroization barrier (`arena_metal.m`, `proofs/lean4/Enclave/LeftoverLocalsDefense.lean`); (b) Multi-tenant PagedAttention KV-cache memory isolation (`paged_attention.rs`, `proofs/lean4/Enclave/PagedAttentionIsolation.lean`).                                                                                                                                                                                                                                                                                                                                                                                |

| **1.5** | **2026-11-12** | Bounded admission contract | §3.2.1 binds actual main/direct companion roles to FS-702 `ADM-01`–`ADM-06`, distinguishes signed exact length from size ceilings, and preserves schema/FD/model acceptance boundaries. |
| **1.6** | **2026-11-15** | User-approved `YKD-02` | Measurement-first lifecycle timing: broad L1/L2 latitude, tighter measured L3 budgets. Numeric limits remain pending native baseline before timing-sensitive implementation; preserve release fencing, factor requirements and actual CPU/accelerator/owned-state cleanup. Prior fixed lifecycle latency labels are historical references, not current release thresholds. |

---

## 11. Implementation Notes (`crates/`, gap remediation)

### 11.0 Mesh, identity and simulation (all daemons)

* **Socket and journal layout (`GAP-01`, `ADR-006`).** Each daemon serves on `<socket_dir>/<suffix>/<suffix>.sock` (`/var/run/enclave/cas/cas.sock`, …) and writes only `<audit_dir>/<suffix>/` and `<state_dir>/<suffix>/`. The per-server socket directory is provisioned by root as `daemon:<client group> 2750`; its socket is `0660`. The client group (`_enclave_<suffix>_c`, GID `711`–`715`) contains exactly the accounts of `ipc::production_policy`. Daemons verify this layout at bind time and refuse to start on an unsafe directory (`IPC_DIR_INSECURE`); they never create or chmod shared directories. `launchd/provision-accounts.sh` (generated by `depot-enclave launchd render`) creates accounts, groups and directories; Seatbelt profiles grant writes only to the daemon's own sub-directories. Verified with five distinct UIDs by `crates/enclave-core/tests/multiuid.rs` (Linux CI, root).
* **Peer code identity (`GAP-02`, `ADR-005`, `ADR-010`).** On macOS every accepted connection's `audit_token_t` is resolved with `SecCodeCopyGuestWithAttributes` and checked with `SecCodeCheckValidity` against `anchor apple generic and certificate leaf[subject.OU] = "<Team ID>" and identifier "<daemon label>"`; the `cdhash` is read with `SecCodeCopySigningInformation` and bound into the PoP channel binding. `uid 0` is admitted only as the signed CLI `com.enterprise.enclave.ctl`. Clients verify the server the same way before sending. The Team ID comes from `depot_SIGNING_TEAM_ID` at build time; `cdhash` allowlists are supported and will be distributed by TUF (`GAP-20`). Linux CI has no code signing and falls back to the UID matrix. Code: `crates/enclave-core/src/codesign.rs`, `ipc.rs`. Compiled on macOS arm64; not yet exercised against signed binaries.
* **Simulated hardware (`GAP-03`).** Software SEP, scripted/auto-approving CoreAuthUI, the virtual CTAP authenticator and the always-approving `L3` egress gate are compiled only with the `simulation` Cargo feature (never in release builds). `--simulated-hardware` additionally requires `--dev-same-uid`, a non-daemon UID and a non-production socket directory; every simulated custody receipt carries `simulated_hw: true`.
* **One sequence authority for governed slots (`GAP-27`, `ADR-010`, `ADR-016`).** `UID 703` issues every governed `(boot_epoch_id, rpc_seq_u64)` slot: its own `Tokenize`, `ScrubText`, `Detokenize` and `AuthorizeIntent`, and — through `AllocateSlot`, callable only by `UID 704` — each `UID 704` tool call, tool-output ingestion and `declassify_enum` (journaled by 703 as `SLOT_ISSUED` at the slot). Governed journal lines carry `UID 703`'s epoch, `rpc_seq_u64 = slot` and `payload.slot`; non-governed lines keep the daemon's own epoch. `UID 701`, `UID 704` and `UID 705` verify `UID 703`'s SEP-signed `BootEpoch` (P-256 ECDSA over `depot-BootEpoch-v1`) before using a slot of it and pin the signer key in sealed state (`epoch-signer`, trust on first verified epoch over the authenticated 703 channel; any other key is `EPOCH_SIGNER_CHANGED`). `UID 704` hands the signed epoch and slot to `UID 701` with `Declassify`, so one `declassify_enum` is journaled by 701, 703 and 704 under the same `(boot_epoch_id, rpc_seq_u64)`. `UID 702` has no governed RPCs and keeps its own epoch. Code: `crates/enclave-crypto/src/epoch.rs`.
* **Egress registries (`GAP-11`).** `UID 703` and `UID 704` each keep a persisted, fsync'd per-epoch record of the slots they issued and released (`crates/enclave-core/src/egress.rs`, `<state_dir>/<suffix>/egress/`), plus a long-lived tombstone signing key (`<state_dir>/<suffix>/tombstone.key`; a root-owned file in this build, SEP-wrapped in Phase 2). Each refuses to co-sign a tombstone for a slot it released (`TOMBSTONE_SLOT_RELEASED`); `UID 703` also refuses slots it never issued (`TOMBSTONE_SLOT_UNKNOWN`). Both accept `CoSignTombstone` only from `UID 705`.
* **Journal access.** Audit sub-directories are provisioned `daemon:_enclave_journal_r 2750` and journals are `0640`; `_enclave_journal_r` (GID `720`) has `_enclavezk` as its only member, and only `zk.sb` grants reads of the audit root. Plists set `InitGroups = true`, which supplementary-group access (client groups and the journal group) requires. Every daemon now receives `--state-dir <state_dir>/<suffix>`.
* **Sealed persistent state (`GAP-08`, `GAP-12`, `GAP-28`, `GAP-30`).** Security state that must survive a restart is kept in `enclave_core::sealed::SealedStore`: `<state_dir>/<suffix>/<name>.sealed` holds `{v, domain, generation, body, mac}` with `mac = BLAKE3-keyed(K, domain ‖ generation ‖ body)`, replaced atomically, plus a MAC'd generation checkpoint `<name>.gen` that only grows. Loading fails closed: checkpoint without state is `STATE_MISSING`, a bad MAC or a swapped store is `STATE_TAMPERED`, an older generation (or state without its checkpoint) is `STATE_ROLLBACK`. Stores: `UID 702` `tuf`, `UID 703` `signcount`, `UID 704` `qif-ledger`, `UID 705` `quarantine`. The key derives per store from a `0600` seed `sealing.key` in the daemon's own state directory. **Scope of this build:** the key and the checkpoint are files, so the guarantees hold against peers and against restoring or editing individual files, not against root replacing the directory; deleting a store *and* its checkpoint reads as a first boot everywhere except `UID 705` (which treats an existing `sealing.key` as "initialised"). On hardware (Phase 2) the key is SEP-unwrapped and the checkpoint is the `ADR-010` SEP monotonic checkpoint / NVRAM variable.
* **Peer resource limits (`GAP-39`, `ADR-006`).** `ipc::serve_with` enforces per-daemon `ServeLimits`: the request length is checked before any allocation; bodies are buffered in 64 KiB steps charged to a global in-flight budget (`IPC_BUSY` when exhausted); at most 8 concurrent connections per peer UID (`IPC_PEER_QUOTA`; the 16-connection cap in the single-UID dev mesh); a whole frame, including the wait for its first byte, must arrive within 30 s (`IPC_FRAME_DEADLINE`) — a peer trickling bytes no longer holds a slot forever. `UID 703`: frames `<= 256 KiB`, 1 MiB budget; all others: 1 MiB / 4 MiB. Wipe and zeroize RPCs (`Tamper` 703, `Wipe` 704/705, `Zeroize` 701) are accepted only from `uid 0` (operator / supervisor) or the dev UID (`WIPE_PEER_REJECTED`). Test: `crates/enclave-core/src/ipc.rs` (16 concurrent 1 MiB frames to 703's limits allocate nothing, partial frames never exceed the budget, the server keeps answering).
* **Root revocation supervisor (`GAP-21`).** `depot-enclave supervise` (`com.enterprise.enclave.supervisor.plist`, root) serves `<socket_dir>/supervisor/supervisor.sock` (`root:_enclave_sup_c 2750`; `_enclavecas` is the group's only member) to `UID 702` only, finds the holders of a revoked inode itself and signals only daemon accounts (UIDs 701–705). Code: `crates/enclave-core/src/supervisor.rs`; see `FS-702 §11.3`.

### 11.1 Governed declassification (`GAP-27`, `GAP-39`)

* `RunnerRequest::Declassify` carries the governed slot (`GovernedSlot`: `UID 703`'s signed `BootEpoch` and `rpc_seq_u64`). `UID 701` verifies the epoch signature and the pinned signer key (`<state_dir>/adapter/epoch-signer.sealed`), refuses a declassification without a slot (`DECLASSIFY_SLOT_REQUIRED`), and journals it as `DECLASSIFY` under that `(boot_epoch_id, rpc_seq_u64)` with `payload.slot`. Other receipts keep `UID 701`'s own epoch.
* `Zeroize` is accepted only from `uid 0` / the dev UID (`WIPE_PEER_REJECTED`); the daemon's own sleep / lock observers wipe in-process.
* Tests: `crates/enclave-model-runnerd/tests/service.rs`, `crates/depot-enclave/tests/fleet.rs`.

### 11.2 LeftoverLocals (CVE-2023-4969) GPU Unified Memory Defense (`GAP-47`)

* **Threat Analysis:** On Apple Silicon Unified Memory Architecture (UMA), GPU compute buffers share physical LPDDR5/LPDDR5X channels with CPU cores. In unhardened engines, deallocating an `MTLBuffer` leaves dirty activations or intermediate weights resident in physical memory blocks, enabling subsequent processes or model turns to read residual data across security boundaries.
* **Remediation Protocol:** `arena_metal.m` and `enclave-model-runnerd` enforce a multi-stage zeroization sequence prior to releasing or reallocating any GPU buffer:
  1. `[blit fillBuffer:buffer range:NSMakeRange(0, len) value:0]` submitted to the Metal command queue.
  2. `MTLSharedEvent` encoded and committed to guarantee GPU-side barrier completion (`waitUntilCompleted`).
  3. CPU-side `memset_s(contents, len, 0, len)` ensuring all cache lines are zeroed.
  4. Memory fence (`__sync_synchronize()`) and readback canary verification. If any non-zero byte persists, the daemon immediately aborts (`SIGABRT`).
* **Formal Verification:** Mechanized in `proofs/lean4/Enclave/LeftoverLocalsDefense.lean` (`leftover_locals_vram_cleared`, `vram_cross_session_isolation`).

### 11.3 Multi-Tenant PagedAttention KV-Cache Memory Isolation (`GAP-58`)

* **Tenant Block Table Disjointness:** `crates/enclave-model-runnerd/src/paged_attention.rs` manages physical KV-cache allocations via `PagedAttentionBlockManager`. Each tenant maintains a private block table mapping logical positions to physical memory blocks.
* **Non-Interference Guarantee:** Physical blocks allocated to tenant $A$ and tenant $B$ satisfy $S_A \cap S_B = \emptyset$. Deallocated blocks are immediately zeroized using volatile writes and memory barriers before returning to the free pool.
* **Formal Verification:** Mechanized in `proofs/lean4/Enclave/PagedAttentionIsolation.lean` (`paged_attention_cross_tenant_isolation`, `recycled_block_zeroed_before_alloc`).

## 2026-11-15 bounded model browser dispatch

OPEN. The concrete model/browser handoff now shares the accepted wipe release
serial, prepares a capped immutable action outside it, and keeps one shortening
absolute deadline across all reads/writes, notifications and mouse events.
Uncertain failure retains the observation obligation and closes the connection.
Source-bound delivery evidence
records portable47 PASS, native15 distinct release cases across the retained
13PASS/2SUN_LEN failure and unchanged-binary2PASS correction, and98 native
synthetic CDP observations. Internal Agent1 reviews found no scoped blocker.

Continuing notifications now refuse at2.000425s versus prior success at2.986286s;
nominal p50 rose0.243833ms to12.945709ms (p95 15.235542ms, max40.728083ms). These
are bounded same-workload observations, not approved YKD-02 profile budgets or
physical cleanup evidence. The complete10s ceremony cap is unchanged. Installed
browser/confinement, distinct UID, global drain, remaining owner/backend and
physical timing qualification remain open. Completed pre-fence effects stand.
Rollback preserves pending/fence obligations and disables unsupported actuation.

## 2026-11-15 depth-model current-allocation cleanup

OPEN. Actual ReferenceDepth matrix output, returned coda logits and current/
previous softmax distributions now retain FloatScratch owners through success,
KL replacement, cancellation, breaker and error exits. Logits are adopted before
the cancellation checkpoint. Source-bound evidence
records22 focused software PASS and Agent1 scoped internal review. Five new
owner tests inspect live initialized storage after scrub and before deallocation;
existing outputs, arena reports, generation cancellation and thermal behavior
remain covered. No new timer, factor or numerical policy is introduced.

Backend-private/accelerator/allocator-history owners and speculative byte output
remain separate; these checks do not establish physical erasure, installed or
full-profile qualification. Rollback must preserve existing release/cancellation
fences and must not restore unguarded transient float owners.

## 2026-11-15 speculative-decode byte-owner cleanup

OPEN. Speculative decoding now reserves the complete admitted context/output
bounds before copying private bytes, scrubs its current private allocations on
every error and cancellation path, and transfers only the final accepted output
allocation. Context cleanup precedes the original final cancellation/deadline
check; the existing two-second computation bound and guarded draft arena remain.
Source-bound evidence
records 26 focused portable software tests PASS, including six actual-decode
live-allocation checks and unchanged generation, pacing, thermal and depth cases.
Same-team source review found no scoped blocker. This supplies no physical
erasure, accelerator/allocator-history or complete L1/L2/L3 qualification. Shared
output-guard lossy-text copies and backend-private owners remain separate work.
Rollback preserves the current owners and accepted release/cancellation fences.

## 2026-11-15 model output-guard temporary cleanup

OPEN. The shared output guard now retains and scrubs the exact owned lossy-UTF8
conversion on allowed and denied output; valid UTF8 remains borrowed without a
new allocation. Size/canary refusal order, PII matching, offsets and errors are
preserved. Source-bound evidence
records 18 focused portable software tests PASS, including four actual guard
owner tests and six integration consumers. Temporary scanner digit vectors and
standard-library construction/allocator history remain separate owner gaps.
No physical erasure, backend completion or full-profile qualification is claimed.
Rollback preserves cleanup owners and release/cancellation fences.

## 2026-11-15 borrowed PII digit validation

OPEN. The shared scanner validates PAN/SSN matches directly from borrowed text,
eliminating two temporary copied digit vectors. Existing regexes, public slice
helpers, precedence, ASCII filtering of Unicode matches and byte spans retain
their meanings. Source-bound evidence
records 21 focused software checks PASS, including 1,600 PAN and 16,000 SSN
equivalence cases inside four new tests. The remaining checks cover actual
scanning, shared output guards, speculation and five integration consumers.
Internal source review found no scoped blocker. Standard-library lossy-text
construction history, class-private output/probe owners, backend cleanup and
full L1/L2/L3 qualification remain distinct work.

## 2026-11-15 guarded lossy-text construction

OPEN. Invalid UTF8 now uses two standard Utf8Chunks passes: count the exact
replacement representation, then reserve once under the scrub owner before any
private copy. Valid UTF8 remains borrowed. This closes the previously recorded
construction-reallocation gap without changing replacement grouping, cap/PII/
canary behavior or byte offsets. Source-bound evidence records 18 focused
software tests PASS and Agent2 scoped review, including all 65,536 two-byte
inputs and multibyte boundaries inside an equivalence test.

Actual source-bound evidence.
Class-private/backend owners and physical/installed/full-profile qualification
remain OPEN. No timing budget or protocol policy changes. Rollback preserves
cleanup ownership and accepted release/cancellation fences.

## 2026-11-15 diffusion probe and output owners

OPEN. Diffusion now reserves fixed private byte owners before probe/output
copies, scrubs them on every entered exit and reuses guarded lossy text. Borrowed
ASCII-insensitive matching preserves the previous ASCII-only comparison while
eliminating the lowercase String copy. Scratch cleanup precedes the original
final cancellation/two-second check and only accepted final output transfers.
Actual source-bound evidence records 19 focused portable software tests
PASS and same-team source review. Confidence-order score tuples, AR and backend
owners remain separate work; no physical/installed/full-profile qualification or
numeric lifecycle budgets are established. Rollback preserves the scrub owners
and accepted release/cancellation fences.

## 2026-11-15 AR partial and terminal byte owners

OPEN. AR decode reserves its admitted partial-output bound before the first
private byte and keeps the unpadded terminal copy guarded through output checks.
Every entered error/unwind scrubs initialized bytes; success scrubs the partial
allocation before moving the accepted final allocation. DFA/greedy tie-break,
attestation and output-guard behavior remain unchanged.
Actual source-bound evidence records 12 focused portable software tests
PASS, including five new actual decode cases, and same-team source review. Stack
logits, backend/model storage, caller output and physical/native/installed/full
profile qualification remain separate contracts. No new timer or budget policy
is introduced. Rollback preserves current owners and release/cancel fences.

## 2026-11-15 diffusion confidence-order owner

OPEN. Diffusion ranking reserves its fixed score/index allocation before private
scores are copied, retains ownership through borrowed index iteration and wipes
initialized fields on every entered exit. The unchanged total comparator uses
unique indices, permitting an in-place unstable sort with identical ordering and
no heap sort scratch. Source-bound evidence records 11 focused portable
software tests PASS and same-team review, including 144 edge-case datasets and
actual multistep/probe-failure/cancellation behavior. Stack/register/backend and
framework owners, physical erasure and full-profile qualification remain OPEN;
original generation and ceremony caps remain. Rollback preserves scrub owners
and accepted release/cancel fences.

## 2026-11-15 CoreML Rust prediction owners

OPEN. The actual macOS CoreML Rust prediction path now keeps fixed feature and
output float buffers under scrub ownership across synchronous native calls,
partial failure, nonfinite output, poisoned locks and unwind. Features are
scrubbed before the exact accepted output allocation transfers.
Source-bound evidence records 10 portable checks, the native macOS build
and four native synthetic-callback tests PASS with scoped same-team review.
These checks exercise Rust ownership; actual model prediction, native/framework
working copies and physical/installed/full-profile qualification remain separate.
Development-only and closed-graph admission are unchanged. Current tool hashes
are recorded separately as a dated post-build observation. Rollback preserves
cleanup ownership and accepted release/cancel fences.

## 2026-11-15 CoreML native directory ownership

OPEN. The native classifier now acquires cleanup authority only after exclusive
0700 directory creation succeeds. Failed creation cannot adopt or delete an
existing file, directory or symlink. Actual source-bound evidence
records seven native cases PASS against the included production implementation,
covering collisions, sentinel preservation and successful-owner cleanup, with
scoped same-team review. No model prediction or framework-buffer erasure is
claimed. Physical/installed/full-profile acceptance remains OPEN. Rollback
preserves exclusive ownership and never restores cleanup of unowned paths.

### 2026-11-15 bounded native classifier current-array evidence

OPEN. The experimental CoreML classifier now uses checked public Float32
callbacks with retained input/result owners. It scrubs the current exposed
writable spans after synchronous returns and caught exceptions, attempts both
owners independently and refuses success if cleanup fails. This avoids
application-created per-value secret NSNumber copies. Source-bound delivery
records15 native real-array/fault fixture cases PASS and a separate actual
closed-graph prediction test PASS against three independent dense-reference
vectors. The initial fixture compile failure is preserved; its correction
changed only fixture pointer capture and callback annotations. Production
prediction evidence is reused for unchanged source, with scoped same-team
review. SDK mutable access may replace backing storage: inaccessible prior
framework copies/caches and physical erasure remain excluded. Development-only
admission, original10s/2s limits, installed/lifecycle and full-profile gates are
unchanged. Rollback preserves current-span cleanup and failure refusal.

### 2026-11-15 guarded tensor-decoder refusal

OPEN. The shared F32/F16/BF16 decoder now guards one fixed initialized numeric
allocation before writing decoded values. A late nonfinite tensor refusal
volatile-scrubs that live buffer; success transfers the same Vec explicitly.
Shape/range/dtype/error ordering and exact finite bits remain unchanged.
Source-bound actual evidence
records3 focused actual-decoder tests,10 CoreML/BERT tests and44 model-class
regressions PASS, with scoped same-team review. These are portable software
checks; this increment has no native/installed/physical erasure claim. Borrowed
checkpoint mappings, successfully transferred caller Vecs, allocator/compiler
history, stack/register and native/framework copies remain separate owners.
Abort/kill does not run Drop. Lifecycle budgets/fullprofiles remain OPEN;
original10s/2s and resource limits are unchanged. Rollback preserves refusal
cleanup, authority/counter/fence state and existing model admission gates.

### 2026-11-15 classifier load and export buffers

OPEN. Classifier loading now scrubs decoded weight/bias copies before the
synchronous native callback, and retains a wiping owner over canonical model
bytes until that callback returns or unwinds. Fixed initialized byte owners
also cover the float/parameter/layer/network export intermediates without
growth after private writes. The public graph Vec and exact protobuf bytes,
SHA256, shape/error order and admission gates are preserved.
Exact source and results
record five new exporter tests, four prediction-owner tests, three decoder
tests and four integration tests PASS on each platform. Linux correctly
refuses actual CoreML execution; macOS executes the real classifier and adapter,
including predictions against three independent reference vectors. Tests
compare complete old/new canonical exports across twelve boundary datasets
and observe live owned buffers after wipe on success/error/unwind.

These checks establish current allocation cleanup and numerical compatibility.
They establish no physical erasure, resource acceptance or full-profile
qualification. Public caller Vecs, borrowed checkpoint mappings, native model
data/file/framework copies, allocator/compiler history and lifecycle timing
remain separate owners or open checks. Earlier BERT resource-cap failure
remains FAILED. Preserve cleanup, exact model/admission gates and all original
timers, factors and release fences on rollback.
