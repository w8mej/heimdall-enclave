> Current assurance boundary (2026-11-11): these are Lean specifications and proofs with the implementation comparisons and extracted AIR results documented in [COVERAGE.md](COVERAGE.md) and [ASSURANCE.md](ASSURANCE.md). Historical descriptions below do not establish product, cryptographic, OS or hardware verification. Run the pinned compiler/axiom/type gate from the repository root: `python3 scripts/check-lean.py`.

# Current twenty-area extension

The current objectives, completed sub-results and remaining gaps are tracked in
[COVERAGE.md](COVERAGE.md). Full twenty-area completion has not been signed off.
The actual AIR slot-coverage and Merkle position-binding proofs, native boundary
repairs, tests and limits are documented in
[the refinement record](../../docs/formal/slot-and-membership-refinement.md).
Historical theorem descriptions below must be read with [ASSURANCE.md](ASSURANCE.md);
compilation of an abstract model alone does not certify production or hardware.

Future gap-closing assignments are detailed in the
crux-task backlog, including
per-slice proof domains, proposed declarations, production symbols, regressions,
native obligations and a structured closure record. Its
two-pass documentation audit
checks those specifications, not completion of the proofs or production fixes.

# Heimdall-Enclave Lean 4 Formal Verification Package (`proofs/lean4`)

This directory houses the machine-checked formal verification package for the Heimdall-Enclave zero-trust enclave architecture (formerly codenamed `MCPMac`), mechanized in **Lean 4** (`v4.14.0`). It formally proves the core mathematical and language-theoretic safety invariants specified across `FS-701` (Model Host), `FS-702` (TUF & Swarm Sync), `FS-703` (PII Vault & Custody), `FS-704` (Agent IFC & Delegation), `FS-705` (ZK Auditor), and `ADVERSARIAL_SPEC_REVIEW_2026-11-04 §10.3`.

## Assurance Boundaries: What Lean 4 Proves vs. What It Does NOT Assure

In high-assurance engineering, formal verification provides mathematical certainty *strictly within the boundaries of the mechanized model*. To ensure absolute transparency with security architects, cryptographers, and auditors:

### 1. What the Lean 4 Proofs Assure

* **Algebraic Soundness of Security Lattices (`Lattice.lean`):** Machine-checked proof that the dual Confidentiality ($C_1..C_4$) and Taint ($T_0..T_3$) lattices satisfy reflexivity, transitivity, antisymmetry, and the Bell-LaPadula / Biba noninterference rules.
* **Small-Step Noninterference (`SmallStepSemantics.lean`):** Machine-checked proof that untrusted inputs ($T_3$) cannot influence conditional branch execution in agent scripts (`branch_condition_taint_safe`).
* **Information Channel Bounds (`QifBound.lean`, `ProbabilisticQif.lean`):** Measure-theoretic proof that the quantitative information flow (QIF) ceiling bounds posterior Bayes vulnerability $V(X \mid Y) \le |\mathcal{Y}| \cdot V(X)$ without circular assumptions.
* **FSM Bisimulation & Safe Abort (`RustModelBridge.lean`):** Proof that abstract state transitions commute with `FlowGate` operations and all out-of-order/hostile transitions terminate in `QuarantineAbort`.
* **Zero Unproven Axioms:** All **94** `Enclave/*.lean` modules and **25** `Test/*.lean` modules (**1,036** kernel-checked theorem types pinned in `theorem-types.json`) compile with **zero `sorry` or `admit` axioms** under the pinned Lean 4.14.0 toolchain (`python3 scripts/check-lean.py`).

### 2. What the Lean 4 Proofs Do NOT Assure (Formal Non-Assurances)

* **Physical Microarchitectural Immunity:** Lean 4 proofs verify mathematical algorithms and constant-time cost models (`ConstantTimeSemantics.lean`). They do *not* guarantee physical silicon resistance to unmodeled hardware side-channels (e.g. Spectre-v2, LeftoverLocals GPU VRAM remanence, or cache line contention) without hardware mitigations (Apple Silicon MTE, PAC, Metal barriers).
* **Darwin Kernel & OS Runtime Races:** Lean models Darwin Seatbelt `.sb` profiles and Packet Filter rules as ideal state machines; it does *not* verify Mach kernel scheduler preemption, Mach IPC race conditions, or APFS corruption beneath the `F_FULLFSYNC` barrier.
* **Compiler & ABI Lowering (LLVM Optimization Passes):** Lean operates on inductive abstract data types (ADTs), not `arm64e` assembly. Miscompilations, register allocation anomalies, or undefined behavior in external C/FFI libraries are outside the Lean model (mitigated via `#![forbid(unsafe_code)]`, PAC, EMTE, and planned L2 Beta Aeneas/Charon MIR translation validation).
* **Serialization & Parser Divergence:** Mechanized proofs consume clean typed symbols. Real-world adversaries target malformed CBOR, non-canonical JSON, FastCDC Bao chunk boundaries, and raw UDS framing before they reach the typed state machine.
* **Dynamic Semantic Drift:** A static mathematical proof remains static, while production Rust code evolves. Refactoring, performance tuning, and bug fixes can cause the production runtime to silently diverge from the Lean specification over time.

### 3. Bridging the Gap: 5-Layer Anti-Drift Gate & 9-Target Continuous Differential Fuzzing

To continuously verify that production Rust does not drift from its Lean 4 specification, Heimdall-Enclave executes a single-command 5-layer anti-drift pipeline:

* **Unified Verification Gate:** [`scripts/verify-formal-bridge.sh`](../../scripts/verify-formal-bridge.sh) (verifies zero-sorry hygiene, **9/9** Rust-to-Lean source guards + **29** adversarial mutation tests, **62/62** live KoalaBear STARK AIR polynomials, **10,544** offline pinned Lean oracle vectors / **34,599** total with `lake`, and **9-target** continuous fuzzing).
* **Fuzzing Harness & Runner:** [`crates/enclave-agent-runtime/tests/formal_conformance_fuzz.rs`](../../crates/enclave-agent-runtime/tests/formal_conformance_fuzz.rs) & [`scripts/run-fuzz.sh`](../../scripts/run-fuzz.sh)
* **9 Differential & Adversarial Boundary Checks (63,000+ iterations, 0 defects):** FlowGate FSM bisimulation (Thm 11), lattice algebra, exact integer QIF non-undercharge (Thm 2), Context DAG provenance (Thm 23), RFC 8785 JCS idempotence, Rolling 24h QIF ledger clock-rollback & atomicity, Delegation slice conservation & overflow guard (Thm 35), Capability heap exposure monotonicity & wipe soundness, and adversarial wire-format/parser crash-freedom.
* **Continuous Conformance Report:** [`reports/fuzz-report.md`](../../reports/fuzz-report.md) records per-target iteration totals and shrinks any discovered counterexample to a minimal reproduction test case.

## Historical package catalogue

The catalogue and theorem descriptions below are retained as historical context.
Use the actual export file, current coverage register and per-module assurance
for the present inventory and proof scope; the historical security descriptions
are not current implementation guarantees.

```text
proofs/lean4/
├── lean-toolchain                     # Pinned to leanprover/lean4:v4.14.0
├── lakefile.lean                      # Lake package definition (EnclaveProofs)
├── Enclave.lean                       # Top-level library export; see current source
├── Main.lean                          # Verification CLI executable
├── Enclave/
│   ├── Lattice.lean                   # Monotonic C1..C4 × T0..T3 IFC lattices & preorders
│   ├── BibaNoninterference.lean       # Theorem 1: Starlark Biba integrity noninterference
│   ├── QifBound.lean                  # Theorem 2: 24h rolling QIF channel capacity bound (≤ 4096)
│   ├── ConjunctiveAuth.lean           # Theorem 3: Cedar ∧ PoP-Biscuit conjunctive monotonicity
│   ├── HardwareCustody.lean           # Theorem 4: 2-of-2 hardware custody, airplane mode & quorum
│   ├── AuditChain.lean                # Theorem 5: Contiguous hash chaining & pre-egress tombstone
│   ├── TufAntiRollback.lean           # Theorem 6: TUF 4-role monotonic versioning & anti-rollback
│   ├── PacketFilter.lean              # Theorem 7: Darwin Packet Filter kernel quarantine soundness
│   ├── MetalFence.lean                # Theorem 8: Metal shared event fence surprise abort semantics
│   ├── MultiAgentQifTree.lean         # Theorem 9: Multi-agent fork-join tree QIF conservation
│   ├── SmallStepSemantics.lean        # Theorem 10: Small-step Starlark semantics, loops & NMD
│   ├── RustModelBridge.lean           # Theorem 11: Rust FlowGate FSM bisimulation translation validation
│   ├── ProbabilisticQif.lean          # Theorem 12: Measure-theoretic Bayes vulnerability channel capacity
│   ├── StatefulPacketFilter.lean      # Theorem 13: Darwin pf stateful connection tracking ('keep state')
│   ├── SqlAstGuard.lean               # Theorem 14: SQL AST read-only guard & database immutability
│   ├── DpopBinding.lean               # Theorem 15: RFC 9449 DPoP proof-of-possession token binding
│   ├── CedarSemantics.lean            # Theorem 16: Cedar default-deny & forbid-overrides-permit
│   ├── BaoStreamVerification.lean     # Theorem 17: Iroh FastCDC & BLAKE3 Bao verified hash trees
│   ├── StarkAirSoundness.lean         # Theorem 18: Plonky3 STARK AIR constraints & Lasso lookups
│   ├── LeftoverLocalsDefense.lean     # Theorem 19: LeftoverLocals VRAM clearing & GPU isolation (GAP-47)
│   ├── EphemeralDelegation.lean       # Theorem 20: Scoped ephemeral delegation grant attenuation (GAP-51)
│   ├── SepAntiRollback.lean           # Theorem 21: SEP monotonic hardware counter anti-rollback (GAP-57)
│   ├── PagedAttentionIsolation.lean   # Theorem 22: Multi-tenant PagedAttention KV-cache isolation (GAP-58)
│   ├── ContextDagProvenance.lean      # Theorem 23: Multi-turn conversation DAG taint tracking (GAP-61)
│   ├── CrashConsistencyWal.lean       # Theorem 24: APFS F_FULLFSYNC write-ahead log recovery (GAP-64)
│   ├── ExtractionGapDefense.lean      # Theorem 25: Aeneas/Charon extraction refinement & safety fence (GAP-48)
│   ├── TierTwoAssurance.lean          # Theorem 26: QUIC rate limiting, staging quota & peripheral defense (GAP-59/60)
│   ├── TierThreeAssurance.lean        # Theorem 27: Post-quantum hybrid KEM and dual-signature soundness (GAP-62)
│   ├── ConstantTimeSemantics.lean     # Theorem 28: Microarchitectural timing noninterference & straight-line dispatch
│   ├── SeatbeltCapabilityMonotonicity.lean # Theorem 29: Darwin Seatbelt .sb profile capability narrowing
│   ├── PeerTokenPidReuseImmunity.lean # Theorem 30: Darwin audit_token_t 64-bit generation vs. PID wrap-around
│   ├── RssMemoryCeilingAccounting.lean # Theorem 31: Mach task_info phys_footprint 152 MiB collective ceiling
│   ├── SpeculativeVerificationGate.lean # Theorem 32: Speculative draft verification & ECE ≤ 0.015 calibration
│   ├── FixedPointQ16ArithSafety.lean  # Theorem 33: Q16.16 fixed-point logit overflow bounds & monotonic temperature
│   ├── WasiCapabilitySandbox.lean     # Theorem 34: WASI 0.2 linear memory bounds & pre-opened FD confinement
│   ├── DelegationTreeConservation.lean # Theorem 35: Multi-agent delegation tree fuel conservation & depth termination
│   ├── CompositionalNoninterference.lean # Theorem 36: Parallel automata composition & generalized noninterference (M1 ⊗ M2)
│   ├── HybridKdfCombiner.lean         # Theorem 37: NIST SP 800-227 dual-PRF HKDF reduction (ML-KEM-768 + X25519)
│   ├── ZkWitnessUniqueness.lean       # Theorem 38: STARK AIR constraint uniqueness & quotient degree bounds
│   ├── FriProximitySoundness.lean     # Theorem 39: Plonky3 FRI round folding degree halving & terminal soundness
│   ├── HpkeAuthEncapSoundness.lean    # Theorem 40: RFC 9180 AuthEncap ciphertext integrity & authentication
│   ├── CrashConsistentRecovery.lean   # Theorem 41: Two-phase SEP NVRAM / APFS WAL crash-consistent recovery
│   └── UsbYankZeroization.lean        # Theorem 42: Physical USB YubiKey yank synchronous memory zeroization
└── Test/
    ├── LatticeTest.lean               # Evaluator tests for join, meet, and flow decidability
    ├── NoninterferenceTest.lean       # AST SQL-injection immunity verification under T3 inputs
    ├── CustodyTest.lean               # Evaluator tests for custody, audit, and TUF progression
    ├── FrontierTest.lean              # Evaluator tests for Packet Filter, Metal and QIF trees
    ├── AcademicAuditTest.lean         # Evaluator tests for small-step, Rust bridge, QIF & stateful PF
    ├── ExtendedAssuranceTest.lean     # Evaluator tests for SQL guard, DPoP, Cedar, Bao & STARK AIR
    ├── TierZeroAssuranceTest.lean     # Evaluator tests for LeftoverLocals, SEP counter, PagedAttention & WAL
    ├── TierOneAssuranceTest.lean      # Evaluator tests for translation validation extraction gap
    ├── TierTwoAssuranceTest.lean      # Evaluator tests for token bucket rate limit, quota & peripheral wipe
    ├── TierThreeAssuranceTest.lean    # Evaluator tests for post-quantum hybrid KEM & anti-downgrade (GAP-62)
    ├── MicroarchitectureAssuranceTest.lean # Evaluator tests for constant-time, Seatbelt, audit token & RSS bounds
    ├── AgenticGovernanceAssuranceTest.lean # Evaluator tests for draft ECE, Q16 logits, WASI memory & agent tree fuel
    ├── AdvancedCryptoAssuranceTest.lean # Evaluator tests for automata composition, hybrid KDF, AIR determinism, FRI & HPKE
    └── HardwareResilienceAssuranceTest.lean # Evaluator tests for two-phase crash recovery & USB yank zeroization
```

## Historical theorem descriptions

| Theorem Identifier                            | Source File                                   | Formal Statement                                                                      | Security Guarantee                                                                                                                                   |
|:----------------------------------------------|:----------------------------------------------|:--------------------------------------------------------------------------------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------|
| **`starlark_biba_noninterference`**           | `Enclave/BibaNoninterference.lean`            | `∀ env₁ env₂, agree_on_T2 → structuralToolTrace env₁ = structuralToolTrace env₂`      | Proves untrusted `T3` prompt-injection payloads cannot modify structural tool call traces (`FS-704 §8.1`).                                           |
| **`structural_injection_impossible`**         | `Enclave/BibaNoninterference.lean`            | `∀ idx, trace(env₁)[idx] = trace(env₂)[idx]`                                          | Proves parameterized tool calls are AST-isomorphic modulo literal leaf slots (`PROOF-I4-BIBA-AST`).                                                  |
| **`qif_24h_transcript_cardinality_bound`**    | `Enclave/QifBound.lean`                       | `distinctTranscripts e runs ≤ 4096`                                                   | Proves the rolling 24h $12,000\text{ millibit}$ ceiling ($12.0\text{ bits}$) strictly bounds declassified transcripts to $\le 4096$ (`FS-705 §3.2`). |
| **`min_entropy_leakage_bounded`**             | `Enclave/QifBound.lean`                       | `Card(Transcripts) ≤ 4096`                                                            | Worst-case min-entropy leakage $\Delta H_\infty$ to an observer is strictly bounded by $12.0\text{ bits}$.                                           |
| **`conjunctive_monotonicity`**                | `Enclave/ConjunctiveAuth.lean`                | `Attenuates(b', b) ∧ Auth(c, b', req) → Auth(c, b, req)`                              | Proves conjoining Cedar policy with attenuated PoP-Biscuit tokens preserves monotonic authorization (`F-021`, `ADR-008`).                            |
| **`conjunctive_dual_monotonicity`**           | `Enclave/ConjunctiveAuth.lean`                | `Refines(c', c) ∧ Attenuates(b', b) ∧ Auth(c', b', req) → Auth(c, b, req)`            | Dynamic policy revocation in Cedar combined with token attenuation maintains fail-closed safety.                                                     |
| **`conf_join_least` / `conf_join_assoc`**     | `Enclave/Lattice.lean`                        | Lattice axioms for $C1 < C2 < C3 < C4$                                                | Proves Confidentiality labels form a verified bounded lattice with join $\sqcup$ and meet $\sqcap$.                                                  |
| **`integ_join_assoc` / `integ_join_comm`**    | `Enclave/Lattice.lean`                        | Lattice axioms for $T0 < T1 < T2 < T3$                                                | Proves Integrity/Taint labels form a verified monotonic lattice.                                                                                     |
| **`a4_requires_dual_hardware`**               | `Enclave/HardwareCustody.lean`                | `Auth(A4, st) → TouchID ∧ YubiKey ∧ SEP ∧ UserPresence`                               | Proves irreversible actions ($A4$) strictly require dual-silicon verification (Touch ID + YubiKey touch) (`FS-703 §4`).                              |
| **`airplane_mode_blocks_a4`**                 | `Enclave/HardwareCustody.lean`                | `airplane_mode = true → Auth(A4, st) = false`                                         | Proves Airplane Mode or detached authenticators strictly block destructive $A4$ operations fail-closed.                                              |
| **`quorum_insufficient_rejected`**            | `Enclave/HardwareCustody.lean`                | `m < k → IsQuorumValid = false`                                                       | Proves $m < k$ insider collusion cannot authorize root rotations or policy overrides (`PROOF-H5-QUORUM`, `ADR-013`).                                 |
| **`journal_step_strictly_monotonic`**         | `Enclave/AuditChain.lean`                     | `Contiguous(chain) → seq_{i} < seq_{i+1}`                                             | Proves audit log sequence numbers are strictly monotonic and gap-free (`PROOF-Z3-INGRESS-BIND`, `FS-705 §3.2`).                                      |
| **`entry_hash_tamper_detected`**              | `Enclave/AuditChain.lean`                     | `p1 ≠ p2 → hashStep(..., p1) ≠ hashStep(..., p2)`                                     | Proves in-place mutation or tampering of journal records alters downstream hash-chain digests.                                                       |
| **`tombstone_distinguishable`**               | `Enclave/AuditChain.lean`                     | `hashStep(..., tomb=true) ≠ hashStep(..., tomb=false)`                                | Proves aborted pre-egress tombstones are cryptographically distinct from released payloads (`Fixes F-025`).                                          |
| **`anti_rollback_rejected`**                  | `Enclave/TufAntiRollback.lean`                | `v_{candidate} ≤ v_{current} → Admissible = false`                                    | Proves TUF metadata rollbacks and freeze attacks are deterministically rejected (`FS-702 §3.3`, `ADR-011`).                                          |
| **`monotonic_version_transitivity`**          | `Enclave/TufAntiRollback.lean`                | `Admissible(m1, m2) ∧ Admissible(m2, m3) → v1 < v3`                                   | Proves successive valid TUF repository updates enforce strictly increasing version numbers.                                                          |
| **`pf_quarantine_soundness`**                 | `Enclave/PacketFilter.lean`                   | `src=8701 ∧ (iface≠lo0 ∨ port∉{8443,11434} ∨ ¬TCP) → Drop`                            | Proves Darwin Packet Filter kernel quarantine deterministically blocks all unauthorized network egress from GID `_llmagent`.                         |
| **`non_loopback_strictly_dropped`**           | `Enclave/PacketFilter.lean`                   | `src=8701 ∧ iface≠"lo0" → Drop`                                                       | Proves physical interfaces (Wi-Fi, Ethernet, VPN split tunnels) are physically unreachable by the agent.                                             |
| **`surprise_abort_zero_emitted_bytes`**       | `Enclave/MetalFence.lean`                     | `surprise > 8500 → emitted_bytes = 0 ∧ Aborted`                                       | Proves Metal compute command buffer halts on semantic surprise divergence, emitting 0 bytes across IPC (`FS-701 §3.3`).                              |
| **`tensor_leakage_impossibility`**            | `Enclave/MetalFence.lean`                     | `status = Aborted → emitted_bytes = 0`                                                | Proves intermediate neural activations cannot cross the IPC ring buffer if an abort fires.                                                           |
| **`multi_agent_tree_entropy_bound`**          | `Enclave/MultiAgentQifTree.lean`              | `isTreeWithinBudget(t) → 2^(mb/1000) ≤ 4096`                                          | Proves declassification entropy across arbitrary fork-join sub-agent trees ($d \le 4, w \le 8$) is bounded by $\le 4096$ states (`FS-704 §8.3`).     |
| **`branch_condition_taint_safe`**             | `Enclave/SmallStepSemantics.lean`             | `typeCheckExpr (IfThenElse c t e) = some lvl → c_lvl ≤ T2`                            | Proves small-step branch conditions are strictly verified to have integrity $\le T2$, preventing control-flow hijacking.                             |
| **`t3_branch_statically_rejected`**           | `Enclave/SmallStepSemantics.lean`             | `typeCheckExpr c = some T3 → typeCheckExpr (IfThenElse c t e) = none`                 | Proves conditional statements evaluating $T3$ untrusted variables are deterministically rejected at parse/type time.                                 |
| **`small_step_trace_noninterference`**        | `Enclave/SmallStepSemantics.lean`             | `agree_on_low(st₁, st₂) → step(c, st₁, tr) = step(c, st₂, tr)`                        | Proves small-step reduction takes bitwise identical paths on environments agreeing on trusted inputs.                                                |
| **`unbounded_loop_statically_rejected`**      | `Enclave/SmallStepSemantics.lean`             | `bound > 16 → typeCheckExpr (ForRange x bound body) = none`                           | Proves Starlark loops exceeding bound 16 are statically rejected, immunizing against algorithmic DoS (`FS-704`).                                     |
| **`bounded_loop_fuel_termination`**           | `Enclave/SmallStepSemantics.lean`             | `bound ≤ 16 → fuelRequired ≤ 16 * cost + 1`                                           | Proves strong normalization and bounded step termination, showing untrusted inputs cannot induce divergence.                                         |
| **`noninterference_modulo_declassification`** | `Enclave/SmallStepSemantics.lean`             | `agree_modulo_declass(st₁, st₂) → evalPure st₁ c = evalPure st₂ c`                    | Proves Sabelfeld-Myers Delimited Release: noninterference holds strictly modulo explicit Cedar-authorized declassifications.                         |
| **`rust_lean_bisimulation_preservation`**     | `Enclave/RustModelBridge.lean`                | `stateAbstraction(rustStep s e) = specStep(stateAbstraction s, eventAbstraction e)`   | Translation validation contract proving Rust `crates/enclave-agent-runtime/src/flow_fsm.rs` bisimulates Lean security model.                         |
| **`rust_quarantine_fail_closed`**             | `Enclave/RustModelBridge.lean`                | `rustStep s e = QuarantineAbort → stateAbstraction = SafeAbort`                       | Proves unexpected, out-of-order, or invalid transitions in the Rust runtime fail closed into quarantine.                                             |
| **`bayes_vulnerability_cardinality_bound`**   | `Enclave/ProbabilisticQif.lean`               | `V(X \| Y) ≤ \|Y\| · V(X)`                                                            | Proves from first principles that posterior Bayes vulnerability cannot exceed output cardinality times prior vulnerability.                          |
| **`bayes_vulnerability_ratio_bound`**         | `Enclave/ProbabilisticQif.lean`               | `V(X \| Y) ≤ 4096 · V(X)`                                                             | Proves the $2^{12} = 4096$ transcript ceiling and min-entropy loss bound $\Delta H_\infty \le 12.0\text{ bits}$ from channel matrix theory.          |
| **`stateful_quarantine_soundness`**           | `Enclave/StatefulPacketFilter.lean`           | `src=8701 ∧ iface≠lo0 → (evalStateful tbl pkt).verdict = Drop ∧ table' = tbl`         | Proves Darwin Packet Filter stateful connection tracking (`keep state`) preserves default-deny kernel quarantine across arbitrary traffic.           |
| **`state_table_quarantine_invariant`**        | `Enclave/StatefulPacketFilter.lean`           | `TableQuarantineInvariant tbl → TableQuarantineInvariant (evalStateful tbl pkt).1`    | Proves dynamic entries created in the kernel state table for GID 8701 strictly maintain loopback addressing.                                         |
| **`out_of_window_packet_strictly_dropped`**   | `Enclave/StatefulPacketFilter.lean`           | `seq ∉ [rcv_nxt, rcv_nxt + rcv_wnd) → evalSeqCheck = Drop`                            | Proves out-of-window TCP packets are deterministically dropped, preventing blind sequence number desynchronization.                                  |
| **`sql_guard_rejects_mutations`**             | `Enclave/SqlAstGuard.lean`                    | `stmt ∈ {Insert, Update, Delete, Attach, Pragma, MultiStmt} → isReadOnlySql = false`  | Proves all state-modifying SQL operations, filesystem attachments, and multi-statement injection vectors are strictly rejected.                      |
| **`db_state_immutability`**                   | `Enclave/SqlAstGuard.lean`                    | `isReadOnlySql(q) = true ∧ evalSql(db, q) = some(db', rows) → db' = db`               | Proves database state is strictly invariant under any query accepted by the SQL AST guard.                                                           |
| **`filesystem_containment`**                  | `Enclave/SqlAstGuard.lean`                    | `isReadOnlySql (Attach path alias) = false`                                           | Proves ATTACH DATABASE is deterministically rejected, preventing directory escape or external file creation.                                         |
| **`dpop_method_substitution_rejected`**       | `Enclave/DpopBinding.lean`                    | `p.htm ≠ expected_method → verifyDpopProof = false`                                   | Proves RFC 9449 DPoP proofs cannot be replayed across different HTTP methods (e.g. read proof replayed against write endpoint).                      |
| **`dpop_uri_substitution_rejected`**          | `Enclave/DpopBinding.lean`                    | `p.htu ≠ expected_uri → verifyDpopProof = false`                                      | Proves DPoP proofs are strictly bound to target tool endpoints, preventing cross-endpoint token relay.                                               |
| **`dpop_token_swap_rejected`**                | `Enclave/DpopBinding.lean`                    | `p.ath ≠ sha256(token) → verifyDpopProof = false`                                     | Proves presenting a stolen access token with a DPoP proof minted for another token fails cryptographic binding verification.                         |
| **`dpop_replay_window_expired`**              | `Enclave/DpopBinding.lean`                    | `now - p.iat > 60 → verifyDpopProof = false`                                          | Proves DPoP proofs older than 60 seconds are deterministically rejected, bounding adversary replay windows.                                          |
| **`cedar_default_deny`**                      | `Enclave/CedarSemantics.lean`                 | `evalCedarPolicySet [] req = Deny`                                                    | Proves Cedar policy evaluation is fail-closed: access is denied in the absence of an explicit matching Permit policy.                                |
| **`forbid_overrides_permit`**                 | `Enclave/CedarSemantics.lean`                 | `∃ p ∈ policies, p.effect = Forbid ∧ p.matches(req) → evalCedarPolicySet = Deny`      | Proves Cedar's fundamental security axiom: any matching Forbid rule unconditionally overrides all matching Permit rules.                             |
| **`permit_monotonicity_under_forbid`**        | `Enclave/CedarSemantics.lean`                 | `eval(forbid :: policies) = Allow → eval(policies) = Allow`                           | Proves adding Forbid policies monotonically narrows or preserves permissions; policy expansion cannot widen access.                                  |
| **`bao_out_of_order_rejected`**               | `Enclave/BaoStreamVerification.lean`          | `isSequentialStream chunks = false → verifyBaoStream = false`                         | Proves P2P swarm model weight chunks arriving out-of-order or with gaps are deterministically rejected.                                              |
| **`bao_truncation_detected`**                 | `Enclave/BaoStreamVerification.lean`          | `chunks.length ≠ expected_count → verifyBaoStream = false`                            | Proves stream truncation by an adversarial peer fails verification, preventing incomplete weight ingestion.                                          |
| **`bao_root_tamper_detected`**                | `Enclave/BaoStreamVerification.lean`          | `computeBaoRoot chunks ≠ expected_root → verifyBaoStream = false`                     | Proves bit-flips or byte modifications in any chunk invalidate the computed BLAKE3 Bao hash tree root.                                               |
| **`air_sequence_strictly_monotonic`**         | `Enclave/StarkAirSoundness.lean`              | `airTransitionValid r1 r2 → r1.seq_num < r2.seq_num`                                  | Proves Plonky3 STARK AIR transition constraints strictly enforce monotonic sequence progression.                                                     |
| **`air_gap_free_chaining`**                   | `Enclave/StarkAirSoundness.lean`              | `airTransitionValid r1 r2 → r2.seq_num = r1.seq_num + 1`                              | Proves STARK compliance rollups guarantee zero skipped, omitted, or missing audit log records.                                                       |
| **`air_hash_chain_contiguous`**               | `Enclave/StarkAirSoundness.lean`              | `airTransitionValid r1 r2 → r2.prev_digest = r1.curr_digest`                          | Proves STARK proof satisfaction enforces contiguous cryptographic hash chaining between adjacent steps.                                              |
| **`multiset_lookup_soundness`**               | `Enclave/StarkAirSoundness.lean`              | `(∀ e ∈ A, e ∈ T) ∧ unauth ∉ T → unauth ∉ A`                                          | Proves Lasso multiset lookup argument guarantees that proof witnesses contain only pre-authorized event types.                                       |
| **`timing_observation_invariance`**           | `Enclave/ConstantTimeSemantics.lean`          | `c1.label = c2.label → evalConstantTime c1 = evalConstantTime c2`                     | Proves microarchitectural execution traces are identical across secret payloads, immunizing against timing side channels.                            |
| **`seatbelt_capability_monotonicity`**        | `Enclave/SeatbeltCapabilityMonotonicity.lean` | `isSubCapability (restrictChildProfile p ...) p`                                      | Proves Darwin Seatbelt `.sb` sandbox profile derivation strictly narrows or preserves parent rights.                                                 |
| **`pid_reuse_spoofing_impossible`**           | `Enclave/PeerTokenPidReuseImmunity.lean`      | `token.generation_id < slot.current_generation → authenticatePeerToken = false`       | Proves Darwin `LOCAL_PEERTOKEN` 64-bit generation tags prevent PID recycling race exploits.                                                          |
| **`cumulative_rss_ceiling_invariant`**        | `Enclave/RssMemoryCeilingAccounting.lean`     | `Σ limits ≤ 152 MiB ∧ d_i ≤ limit_i → cumulativeRss ≤ 152 MiB`                        | Proves Mach `phys_footprint` accounting strictly confines UIDs 702–705 to 152 MiB cumulative memory.                                                 |
| **`speculative_draft_rejection_soundness`**   | `Enclave/SpeculativeVerificationGate.lean`    | `ece > 15 → verifyDraftToken = false`                                                 | Proves draft tokens with empirical calibration error $> 0.015$ are deterministically rejected.                                                       |
| **`q16_no_overflow_under_bounded_logits`**    | `Enclave/FixedPointQ16ArithSafety.lean`       | `safeAddLogit a b = some res → res.raw ≤ MAX_Q16`                                     | Proves Q16.16 fixed-point logit transforms avoid IEEE-754 NaN/overflow vulnerabilities.                                                              |
| **`linear_memory_bound_soundness`**           | `Enclave/WasiCapabilitySandbox.lean`          | `offset + size > maxOffset → isMemoryAccessValid = false`                             | Proves WASI 0.2 Zero-JIT tools trap on memory access outside their pre-allocated linear buffer.                                                      |
| **`delegation_tree_fuel_conservation`**       | `Enclave/DelegationTreeConservation.lean`     | `spawnChild parent = some (parent', child) → parent'.fuel + child.fuel = parent.fuel` | Proves recursive multi-agent delegation strictly conserves fuel without synthesizing compute ex nihilo.                                              |
| **`composition_preserves_noninterference`**   | `Enclave/CompositionalNoninterference.lean`   | `transmitM1toM2 sys msg = some sys' → confLe msg.label sys'.m2.conf_level`            | Proves parallel composition $\mathcal{M}_1 \otimes \mathcal{M}_2$ preserves end-to-end noninterference across mTLS.                                  |
| **`hybrid_kdf_dual_security`**                | `Enclave/HybridKdfCombiner.lean`              | `deriveHybridMasterKey.is_secure = true ↔ (¬classical_broken ∨ ¬pqc_broken)`          | Proves NIST SP 800-227 dual-PRF reduction: master key is secure if either primitive is unbroken.                                                     |
| **`air_witness_uniqueness`**                  | `Enclave/ZkWitnessUniqueness.lean`            | `airTransitionValid r1 r2_a ∧ airTransitionValid r1 r2_b → r2_a = r2_b`               | Proves STARK AIR transition constraints admit a unique witness, preventing under-constraint forging.                                                 |
| **`fri_folding_degree_halving`**              | `Enclave/FriProximitySoundness.lean`          | `(foldFriRound st).max_poly_degree = st.max_poly_degree / 2`                          | Proves Plonky3 FRI round folding strictly halves the polynomial degree bound.                                                                        |
| **`auth_encap_ciphertext_integrity`**         | `Enclave/HpkeAuthEncapSoundness.lean`         | `ct.auth_tag ≠ valid_tag → authDecap = none`                                          | Proves RFC 9180 AuthEncap decapsulation strictly verifies sender authentication and ciphertext integrity.                                            |
| **`two_phase_epoch_atomicity`**               | `Enclave/CrashConsistentRecovery.lean`        | `recoverEpochState snap = snap.prev ∨ recoverEpochState snap = snap.proposed`         | Proves sudden power-loss recovery deterministically resolves to previous valid or proposed committed epoch.                                          |
| **`usb_disconnect_instant_zeroize`**          | `Enclave/UsbYankZeroization.lean`             | `handleUsbBusEvent Disconnected slot = ZeroizedClean`                                 | Proves physical YubiKey disconnect immediately zeroizes volatile vault memory slots.                                                                 |

## Academic Rigor, Defense Strategy & Peer-Review Critiques

For a thorough breakdown of how this formal verification suite answers peer-review challenges regarding translation validation gaps, Dolev-Yao symbolic assumptions, multi-core interleaving, and delimited release, see:

👉 **[Formal Methods & Assurance Defense (`docs/FORMAL_METHODS_DEFENSE.md`)](../../docs/FORMAL_METHODS_DEFENSE.md)**

The mechanized Lean 4 package addresses nine foundational requirements for academic-grade formal verification:

1. **Small-Step Operational Semantics (`Enclave/SmallStepSemantics.lean`):**
   Replaces high-level relational abstractions with an inductive small-step transition system $\langle e, \sigma, \tau \rangle \to \langle e', \sigma', \tau' \rangle$. The type system enforces that conditional branches cannot depend on $T3$ untrusted variables (`branch_condition_taint_safe`), proving rigorous control-flow noninterference.
2. **Translation Validation Contract to Rust Implementation (`Enclave/RustModelBridge.lean`):**
   Connects the abstract security automaton directly to the production Rust runtime (`crates/enclave-agent-runtime/src/flow_fsm.rs`). Using a formal simulation bisimulation relation, it proves that the Rust runtime's `FlowGate::on` function faithfully implements the Lean specification, with all undefined transitions deterministically failing into `QuarantineAbort`.
3. **Measure-Theoretic Bayes Vulnerability & Channel Capacity (`Enclave/ProbabilisticQif.lean`):**
   Derives the $4096$ declassification ceiling from first principles of discrete probability spaces and Markov channel matrices $C_{x,y} = P(Y=y \mid X=x)$. It constructively proves that posterior Bayes vulnerability $V(X \mid Y) \le |\mathcal{Y}| \cdot V(X)$, establishing that the $12,000\text{ millibit}$ budget enforces $\Delta H_\infty \le 12.0\text{ bits}$ without circular assumptions.
4. **Stateful Kernel Packet Filter Connection Tracking (`Enclave/StatefulPacketFilter.lean`):**
   Formalizes Darwin pf's dynamic state table (`keep state`), TCP connection lifecycle (`SynSent`, `Established`, `FinWait`, `Closed`), and TCP sliding sequence window validation. It inductively proves that state table insertion and lookup preserve the kernel quarantine invariant across arbitrary packet interleavings.
5. **SQL AST Read-Only Semantic Guard & Immutability (`Enclave/SqlAstGuard.lean`):**
   Formalizes read-only SQL grammar restrictions, proving that queries accepted by the AST guard preserve database state bitwise identically and deterministically reject `ATTACH DATABASE` filesystem escapes.
6. **RFC 9449 DPoP Application-Layer Token Binding (`Enclave/DpopBinding.lean`):**
   Formalizes proof-of-possession verification across method substitution, URI substitution, token swapping, timestamp expiration, and JTI cache replay prevention.
7. **Cedar Engine Default-Deny & Forbid Precedence (`Enclave/CedarSemantics.lean`):**
   Formalizes Cedar policy evaluation semantics, proving default-deny fail-closed safety and the foundational axiom that any matching `Forbid` rule strictly overrides all `Permit` rules.
8. **Iroh FastCDC & BLAKE3 Bao Hash-Tree Streaming Verification (`Enclave/BaoStreamVerification.lean`):**
   Formalizes P2P swarm model weight chunk verification, proving that out-of-order chunk arrival, slice-and-splice attacks, and stream truncation are deterministically detected.
9. **Plonky3 STARK AIR Constraints & Lasso Multiset Lookups (`Enclave/StarkAirSoundness.lean`):**
   Formalizes algebraic intermediate representations and multiset lookups for the ZK Auditor, proving that STARK proof satisfaction enforces contiguous, gap-free audit log rollups with zero forged events.

## Verification & Execution

### Mandatory compiler gate (`V23`)

The repository test runner (`tests/checks.py`, check `V23`) invokes
`scripts/check-lean.py`. The gate requires the pinned Lean toolchain; a missing
compiler fails the check. It builds `Enclave`, `Test` and `enclave_verifier`,
audits kernel theorem declarations and transitive axiom dependencies, checks
reviewed theorem types, and records source hashes in `reports/lean-build.json`.
Only the disclosed standard logical principles are permitted. Definitions,
admitted proofs and source-text assertions cannot replace required theorems.

Run the automated check:

```bash
python3 scripts/check-lean.py
python3 -m unittest discover -s scripts/tests -p test_lean_gate.py
```

### Standalone Lake Build (with Lean 4 Installed)

```bash
cd proofs/lean4
lake exe cache get
lake build Enclave Test enclave_verifier
lake exe enclave_verifier
```

## Resumed extension checkpoint

`Enclave.AdaptiveBudget` supports observation-dependent alphabets and branch
depths. Its probability-mass and Bayes-vulnerability theorems derive their
conclusions from normalized kernels and an exact charge check on every path.
`Enclave.RollingQif` separately proves rolling-ledger invariants; it is not yet a
refinement of Rust's lazy bucket pruning. The tests include unequal branches,
boundary expiry/rollback, atomic multi-entity denial, and authenticated artifact
companions with independent digest/length failures and successful publication.
See [COVERAGE.md](COVERAGE.md) for the remaining composition and implementation
work. No area is closed by this checkpoint.
