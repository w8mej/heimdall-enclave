# Settlement, failure observations and terminal tombstones

This continuation strengthens areas 2, 13 and 14 of the twenty-area Lean
extension. It does not close the other implementation obligations or constitute
final two-pass sign-off. Mathematical proofs, bounded Rust comparisons, native
regressions and platform evidence are distinct assurance surfaces.

## Key normalization and rolling accounting

`Enclave/RollingKeyNormalization.lean` implements the first-occurrence,
append-if-absent key loop. It proves membership preservation, derives uniqueness
from arbitrary raw lists, excludes the actual reserved pool name using the
necessary `ek_` prefix, and proves that a push-back for-loop equals one debit
per selected identity. A counterexample establishes that the correspondence is
false for an unnormalized duplicate list. The string-prefix theorem uses the
character-list semantic view; it does not verify Rust's string parser.

`RollingQifRefinement` proves chronological prefix pruning equals live filtering;
preflight's early rejection changes no live observations; and arbitrary native
algorithm histories refine eager settlement while obeying all caps. Natural
arithmetic and validated timestamps model the mathematical view of the signed
machine implementation. Restore validation establishes chronological,
nonfuture, nonnegative, bounded snapshots for native callers. The checked
addition lemma explains why accepted bounded charges fit i64.

1,620 production/compiled-Lean steps compare both decisions and exact retained
bucket storage, including duplicate entities, unstructured global pools, zero
and lowered caps, C4/L3's 4,000 mb cap, expiry boundaries, clock rollback and
u64::MAX. Native serde restoration is exercised after each step. This is bounded
translation validation, not a universal Rust or compiler proof. Evidence:
`evidence/finalization-rolling-correspondence.log`.

## Adaptive delegated and rolling composition

`DelegatedAdaptiveComposition` executes actual accounting transitions before
exposing an observation kernel. Accepted calls consume remaining per-root
balances; successful delegation preserves those balances; rejected calls cannot
expose their kernel. Variable alphabets, adaptive continuations and intervening
delegations are supported. It derives pricing and the 4,096 Bayes-vulnerability
bound from checked balances, rather than requiring a pricing/security conclusion
as a hypothesis. The initial grant is at most 12,000 mb; minting new grants is
outside a single grant's bound. Normalized kernels and nonnegative priors are
explicit probability assumptions, not assumed vulnerability conclusions.

`RollingAdaptiveComposition` independently derives the bound from rolling
settlement during an interval shorter than 24 hours. Neither theorem claims a
lifetime bound across expired/refunded windows. The monitors are formal
operational definitions; production call-site linkage and external crypto/OS
assumptions remain obligations.

## Fallible classifiers have K+1 observations

A classifier that can return K valid values or fail has K+1 public observations.
Previously `Pdp::declassify_enum` charged only K, propagated arbitrary backend
error reasons/details, and the service returned classifier errors before
persisting their charge. A restart could refund those observed errors.

The production path now charges `ceil(1000 * log2(K+1))`, coalesces backend
errors, out-of-range values and declassified-storage failures into the same
`EIO: DECLASSIFIER_FAILED` with no detail, and persists the reservation before
returning success or that error. A paid error also finalizes the egress slot as
released and journals its QIF charge, so it cannot become a zero-cost tombstone.
Public input/authorization/budget failures before payload classification remain
separate. Reservations are conservative and are not refunded on subsequent
errors. Timing, backend external channels and OS failure behavior are outside
the value-channel theorem.

This intentionally changes budget-visible behavior. Three K=15 calls, each with
one reserved failure outcome, consume 12,000 mb. A protected K=4095 call consumes
the entire window. K=4096 plus failure cannot fit a protected 12,000 mb budget;
the classifier is not invoked when the ledger rejects its charge. Raw
`millibits_for_outcomes(K)` remains correct for a genuinely K-valued channel.

`FallibleQif` proves all private errors and invalid values collapse to one symbol,
valid values remain distinct, charging K alone is unsafe even for K=2, and the
full window permits at most 4,095 values plus failure. Tests include an actual
failing-before backend-error regression, native budget-boundary tests, charged
failure persistence across restart, journal content and tombstone refusal.

Evidence: `finalization-declassifier-alphabet-before.log` (expected failure),
`finalization-declassifier-alphabet-after.log` (pass),
`finalization-runtime-paid-failure-outcome.log` (115 passed, two ignored), and
`finalization-paid-error-journal-after.log` (pass). The 115-test suite predates
the terminal-tombstone source change below. The ignored F66 literal-provenance
test is still an unresolved defect, not evidence of completion.

## Tombstone signatures must freeze future release

Checking only that a slot has not been released permits this invalid sequence:
sign a nonrelease tombstone, then release the same slot. The existing formal
`EgressProtocol` proves only release-before-sign refusal and cannot establish
the stronger objective. A real service regression demonstrated the opposite
order was accepted (`finalization-tombstone-before-release-before.log`).

The registry now persists a terminal `T <seq>` reservation before signing.
`reserve_tombstone` is UID 703's strict issued-slot operation;
`reserve_nonrelease` is UID 704's operation, which can attest its own behavior
without having seen UID 703's issuance. Release rejects any tombstoned slot.
Repeated reservations are idempotent. Replay restores R records as issued as
well as released, understands T records, and rejects contradictory R/T logs.
Synchronized operations sync both file bytes and the directory entry. Existing
I/R logs remain readable. No new tombstone message domain or key rotation is
introduced; old signatures issued without reservations have no retroactive
terminal-state guarantee. Deployment compatibility and native macOS fsync
behavior require separate validation.

`EgressFinalization` proves arbitrary histories keep released and tombstoned
slots disjoint, a signed slot cannot later release, and a released slot cannot
later sign. It distinguishes the two attestors' issuance rules, denies failed
sync publication, rejects conflicting restored logs and tests both operation
orders plus epoch separation. Stable-log sync and signature authenticity are
explicit external primitives. It does not prove that a storage device cannot
lose acknowledged writes.

Two focused core egress tests passed (`finalization-egress-terminal-after.log`),
including restart, unknown/non-owner reservations, duplicate reservation,
release/sign conflicts and valid-format corrupt logs. The complete agent and
custody suites were interrupted during compilation by ext4 emergency read-only
mode; the new end-to-end terminal-signature regression has NOT passed yet.
`finalization-terminal-egress-services-after.log` records the infrastructure
failure. Planned exhaustive four-operation egress comparisons were not written
before the filesystem failure and are not claimed as evidence.

## Reproduction after host repair

1. Check every saved source against `RECOVERY-MANIFEST.json`; this is an
   incomplete recovery copy, not a replacement checkout. Restore missing files
   from the repaired original checkout and reconcile documentation addenda.
2. Run the focused service regression
   `cargo test --locked -p enclave-agent-runtime --test service_boundary a_cosigned_tombstone_permanently_blocks_later_release_of_that_slot`.
3. Run `cargo test --locked -p enclave-agent-runtime -p enclave-custody-vaultd`
   and `cargo test --locked -p enclave-model-runnerd`. The model runner's earlier
   validated-restore checkpoint passed 55 tests with no ignored tests.
4. Build Lean's `Enclave`, `Test` and `enclave_verifier`; review compiled theorem
   type changes before intentionally refreshing `theorem-types.json`.
5. Run the adversarial gate tests, final mandatory gate, production/protocol
   comparisons and AIR extraction. Record new exact source hashes. Do not reuse
   the older provenance as evidence for these later changes.
6. Continue the full twenty-area implementation and semantic audit; zero full
   objectives have received final two-pass sign-off so far.

## Resumed verification

After host recovery the full Lean library/test/executable build passed and the
combined native runtime/custody suite completed with no failures. Evidence is
`evidence/resumed-lean-stable-types.log` and
`evidence/resumed-terminal-services-no-incremental.log`. The previously pending
sign-before-release service regression passed. Planned egress comparisons are
now implemented and pass all 5,184 transitions; see
`evidence/resumed-protocol-correspondence.log`. Historical interruption notes
above remain for provenance; these fresh runs supersede their pending statuses
for the named checks only. Full twenty-area sign-off is still outstanding.

## Independent two-attestor composition

`EgressAttestorComposition.lean` models the custody and IFC registries as two
independent states. Owner issuance/release/sign events and IFC release/sign
events can interleave arbitrarily. Each operation delegates to its own local
terminal-reservation transition; neither daemon shares the other's state.

The invariant for both registries is derived by induction. A matching joint
reservation survives arbitrary later interleavings and excludes release by
either local daemon. A negative kernel test and an actual two-registry native
regression demonstrate why one attestor's reservation is insufficient: the
other daemon may still release the slot, after which a joint reservation cannot
be formed. Reservations for different epochs do not combine. A successful joint
reservation test checks denial on both subsequent release paths.

These are statements about correctly executing local protocols and terminal
records. Signature authenticity, the link from a returned signature to its
prior durable reservation, and faithful log restoration remain explicit external
obligations. A theorem about correct registries does not imply that an arbitrary
compromised daemon cannot bypass them. That system claim needs every governed
release to traverse a correct attestor. Native service and restart regressions
remain supporting evidence, not universal implementation proofs.
