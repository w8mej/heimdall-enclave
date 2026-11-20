# L1/L2/L3 Lean implementation and assurance record

This records executable **model subsets**, not full completion of LAT-01–06 or
F38. Full objectives and source anchors remain in
[the feature addendum](../FEATURE_LEAN4_ADDITIONS.md). The pinned compiler is
Lean4.14.0; no toolchain installation or production Mac mutation was needed.
Final gate results, reviewed hashes and mainline integration are recorded below.
Do not infer source, cryptographic, OS or hardware verification.

## Implemented models

| Slice  | Source and tests under `proofs/lean4/`                                | Checked mathematical scope                                                                                                                                                                                                                                | Remaining refinement                                                                                                                                                                                                                                            |
|--------|-----------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| LAT-01 | `Enclave/TransportAdmission.lean`, `Test/TransportAdmissionTest.lean` | Checked counters, both pre-State and locked Wipe advances, pending guards, sticky failure/overlap, fresh-boot premise, positive recovery; current journal/queued-FD/non-atomic-observation counterexamples                                                | Actual atomic/source simulation, journal optionality, precise admission/delivery boundary, metadata/custody and physical erasure                                                                                                                                |
| LAT-02 | `Enclave/SnapshotBrokerProtocol.lean`, corresponding Test file        | Intent distinct from platform ownership, arbitrary-history owned/foreign invariants, original-authority revoke, current reopen, poison/crash/lost reply, bounded refusal and durable quiescence                                                           | Single-target observed-primitive abstraction; actual bytes/FD/parser/pins/storage/APFS/source relation and immutable-holder route                                                                                                                               |
| LAT-03 | `Enclave/NamespaceKeyringProtocol.lean`, corresponding Test file      | History/floor invariants, retired wrapping denial, checkpoint-relative restart and partial-restoration counterexample, migration marker, consumed counter and poison/disabled/boot lease denial                                                           | Separate slices are not a composed Rust protocol; authenticated codecs, atomic-write assumptions, genuine rewrap/hardware and engineer membership                                                                                                               |
| LAT-04 | `Enclave/SwarmAuthorization.lean`, corresponding Test file            | Computed supported positive-check pre-seal attenuation over histories; sealed admission, unsupported ambient/rule refusal, exact channel/PoP tuple, replay and serial current revocation/renewal                                                          | General Biscuit v3 Datalog/parser, signed bytes/chain identity, cryptographic/exporter/source correspondence, bounded bitmap/TTL and native delivery                                                                                                            |
| LAT-05 | `Enclave/TransportClosure.lean`, corresponding Test file              | Exact main and coherent selected-root metadata, direct eager set, verified complete certificates, logical visibility, root ownership/rollback, retained-stage quotas, no L3 fallback and empty encrypted refusal                                          | Authenticated catalog/hash/chunk/cleanup primitives; staged bytes are not total detached/canonical allocation or RSS; physical effects, crypto and source simulation                                                                                            |
| LAT-06 | `Enclave/TransportStartup.lean`, corresponding Test file              | Signed canonical selection/no corrupt-present fallback, current byte/length primitives, release/monitor/floor checks; arbitrary histories preserve the original checked startup permit, and each fetch checks its supplied listener snapshot; close/retry | No revalidation of changing configuration/floors or continuing monitor health on each fetch; identity/configuration/observation primitives, real JSON/bytes/OS behavior, future listeners, GUI/worker lifetime, installed/native/hardware and source refinement |

All models retain admitted positive executions. L1 is not given a namespace
unwrap witness that real custody rejects. L2/L3 channel/privacy and platform
differences are explicit. The LAT-01 desired atomic checked-effect events are a
stronger proposed interface; they do not repair Rust's current release windows.
The LAT-03 disabled Wipe event can return a state-changing refusal at exhaustion;
`some state` is a model transition, not proof of RPC success.

## Selected main-source guard increment (2026-11-13)

Main `0832c2f2` governs the [nine bounded guard obligations](transport-guard-source-contract.md).
New `RustGuardSemantics`, `TransportGuardSource`, `TransportGuardRefinement` and
an imported test module preserve the six older models. A strict trusted shallow
translator checks current prefixes and selected complete helper bodies. Exact
query correspondence preserves the positive-length premise and the actual
zero/zero difference. Monitor result preservation does not imply continuing
health; bounded append requires an initially valid buffer. Cryptography, full
Rust frontend/caller refinement, allocation, I/O and native acceptance remain
open. Two audits and raw checks
record the precise closure evidence.

## Audit findings and corrections

The documentation two-pass review preceded code.
The implementation pass uses the real pinned compiler, root/test imports,
transitive axiom audit, reviewed theorem types, meaningful positive and hostile
traces. Independent semantic review is by a different agent from each implementer:

| Finding                                                                  | Implementer / independent reviewer | Correction                                                                                                                     |
|--------------------------------------------------------------------------|------------------------------------|--------------------------------------------------------------------------------------------------------------------------------|
| LAT-01 omitted second locked checked generation advance                  | listener / transport               | `69dd5ecc`: explicit locked advance/exhaustion; positives use actual two/four increments; retained first-fence counterexamples |
| LAT-03 max-generation Wipe could leave modeled leases valid              | transport / release                | `22a32f63`: disabled latch precedes checked advancement, sticky denial and boundary witnesses                                  |
| LAT-05 roots-only selection could substitute signed alias for exact main | listener / transport               | `18fc116f`: exact main membership/coherent same-root metadata, exact-main certificate theorem and alias refusal                |
| LAT-06 normal release positive had inconsistent UID/socket observations  | release / listener                 | `82505144`: coherent production positive and explicitly isolated development positive; separate negative factors               |
| Gate inventory-shrink test initially called only a helper                | coordinator / release              | Both new mutations now run the actual copied gate; inventory deletion also verifies stale PASS-report removal                  |

Coordinator also renamed the bounds-only LAT-01 theorem to
`arbitrary_history_preserves_counter_bounds` (`64899df1`); its exact conclusion
was preserved. Independent reviews retain assumptions and counterexamples rather
than treating a compiled model as an extracted implementation. Exact final
review commits/source equality and elapsed intervals are kept with the delivery
evidence; resumed review excludes the apparent container/host downtime.

## Gates and reproduction

From the MCPMac repository root, with the existing pinned Lean/Lake on PATH:

```sh
python3 scripts/check-lean.py
python3 -m unittest discover -s scripts/tests -p test_lean_gate.py
```

`check-lean.py` compiles all root/test imports and the executable, audits actual
kernel declarations and transitive axioms, checks required theorem kinds/types,
and verifies `transport-contracts.json` against a fixed fourteen-file inventory:
six model/test pairs plus `Enclave.lean` and `Test.lean`. This also protects the
imports that execute anonymous kernel-checked examples. Standard `propext`,
`Quot.sound` and `Classical.choice` are allowed; custom axioms, `sorry`, `admit`,
`native_decide` and unsafe proof dependencies are rejected.

The new gate regressions mutate a model definition with unchanged reviewed
artifacts and remove a contract inventory member. Existing actual compiler/gate
attacks cover missing compiler, custom axioms, invalid proofs, fake replacement
definitions, weakened types and removed/invalid imports. A hash is an integrity
contract, not a semantic proof. The gate source and manifests themselves must be
trusted/reviewed; a hostile Harbor verifier must own immutable copies outside
solver-controlled state, rebuild submitted source, and ignore submitted logs,
binaries, rewards and `.olean` files.

After intentional semantic/type changes, independently review the definitions
and expanded types, then run `scripts/update-lean-theorem-types.py` explicitly.
It builds and audits before regenerating the type and definition artifacts; CI
never regenerates them. Review their diff and run the mandatory gate afterward.
No existing theorem type may silently disappear or change during this addition.

## Execution and disposition

The combined pinned gate **PASS** at
`171548f2be5bf339d01e942c31e6862ae037a003`: all six modules, imported tests and
the executable compiled; 2,899 kernel declarations passed the transitive axiom
audit. This is a declaration count, not 2,899 completed objectives. All 777
historical theorem type entries remain unchanged; 212 named entries were added
(989 total). The fourteen-file definition/import contract is enforced.

The adversarial gate suite **PASS: 12 tests in 65.272s**, after
`1989ea19981452f66fc6cd74a63fcedfad154f45`. The retained first attempt was
11 pass/1 fail: the new definition guard correctly rejected the bad-import
fixture before Lean reached its intentionally invalid proof. The correction
updates only the private fixture's import hash so that specific test reaches
the compiler; product manifests and checks remain unchanged. An independent
review found no bypass. Separate definition/inventory mutations still run the
actual gate. Raw logs, the failed attempt, exact source hashes and compiler
provenance are under
`evidence/`.

Independent final reviews are retained in the dated
adversarial audit index.
The source-preservation verifier compares every provenance source against the
final Git tree, each model/test against its reviewed revision, and native build
inputs against the tested checkpoint. Subsequent documentation changes do not
require extrapolating a test pass to different proof or production code.

An executable LAT-05 before/after regression
also checks exact Git sources independently: starting `8a0756ab` accepts a
same-root alias instead of the exact main metadata; `18fc116f` refuses it while
both admit the valid exact-main control. The identical rejection theorem fails
on the old definition and compiles on the solution. Ten commands took 3.995s
(4.013s wall), with isolated fresh module roots. This is a bounded model repair,
not evidence of a Rust vulnerability or collision.

Native product verification completed separately: aggregate
`2807a16f376847e0aaa8fa22169d7798` PASS at `7892ba0d` (30 positive test commands),
normal release broker/CLI and private Swift checks PASS. Subsequent Lean/docs/
gate changes do not alter those native build inputs; final Git equality is
checked separately. Those fixture results do not prove the models' source relation.

F38 and full LAT objectives remain nonterminal. Actual cancellation-to-delivery
linearization, state-ahead checkpoint recovery beyond the committed floor,
private-registry client authorization, hardware network identity, engineer
namespace membership, fleet poison adjudication/dissemination, actual snapshot
inode/mmap-holder enforcement and installed/hardware/resource acceptance remain
explicitly open. No safe Mac fixture or conditional Lean theorem closes them.
No Harbor task was scaffolded or trialed by this work.

Individual LAT-03/LAT-04 exploratory stdout/stderr was not retained by its original executor. No historical log was reconstructed or inferred from compiled objects. Their final source is covered by the complete combined gate/kernel log,129-file source provenance and separate semantic reviews. Exact exploratory timing is unavailable.
