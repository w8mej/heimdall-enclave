# Actual slot coverage and cohort position binding

This iteration strengthens areas 18 and 19 in the [completion register](../../proofs/lean4/COVERAGE.md).
The results below do not close all twenty objectives. Kernel proofs, production
constraint extraction, native regressions and cryptographic soundness are
different evidence surfaces.

## Slot coverage from the actual AIR

`Enclave/EpochAirSlotCoverage.lean` consumes `ValidTrace`: every actual extracted
polynomial vanishes on every row, with first/last/transition selectors computed
from row positions. Selectors are not caller-selected Boolean hypotheses.
The proof derives a nonempty active prefix, sequence equal to row position,
the final active sequence equal to the public span, and exactly one active row
for each public offset. It does not assume prefix shape or slot completeness.

Every active row has exactly one of the fold/tombstone flags. Tombstones and
padding have zero charge. Padding preserves the last active running total.
`actual_epoch_accounts_exactly_the_public_slots` therefore strengthens the
previous padded-trace accounting theorem: the integer sum runs over exactly
`span + 1` slots, and the public output stays within the cap.

Natural-number sequence uniqueness requires the last row index below the field
prime. `supported_degree_prevents_sequence_wrap` discharges that condition for
degree bits at most 24. In pinned Plonky3 0.8.0, `verify_with_preprocessed` calls
`validate_degree_bits` before constructing the row domain; both FRI PCS variants
report KoalaBear's two-adicity, 24, as the maximum. The hiding configuration
subtracts its extra bit for the base row domain. Thus the conservative bound
`height <= 2^24 < 2130706433` suffices. This library correspondence is source
review and regression evidence, not a Lean verification of Plonky3 or FRI.
Malformed degree 25 and `usize::MAX` are rejected by both actual verifier paths.

`native_bounded_trace_covers_absolute_interval` combines the derived coverage
with native statement encoding and the checked span below `2^20`: each absolute
sequence in `[s_start, s_end]` has exactly one active row. Encoding and native
degree checks remain explicit premises; a probabilistic STARK soundness theorem
turning proof acceptance into `ValidTrace` remains open.

## Absolute span repairs and verifier-key version

The old production polynomial checked only the low u32 limb difference.
An honest interval starting at `u32::MAX` and ending one slot later failed it.
The repaired polynomial uses both limbs:

```
(end_low - start_low) + 2^32 * (end_high - start_high) = span
```

In KoalaBear, the extracted multiplier is `33554430`. A kernel theorem proves
two-limb reconstruction for every natural sequence; another proves that native
endpoint/span encoding satisfies this exact extracted polynomial, including
limb crossings. This is consistency of the encoding, not injectivity of a
single field element over all u64 values. The transcript separately absorbs
the absolute endpoints.

Both provers previously added one to an unbounded u64 difference before checking
its length, panicking for `[0, u64::MAX]`. They now reject spans at least `2^20`
before that addition. The verifier paths already had this subtraction bound.

The changed AIR relation uses **`EpochAir-v5-full-span`** in its verifier-key
digest. The manifest now takes the same domain constant instead of advertising
stale v3 metadata. All 62 polynomials were re-extracted and reviewed; only
polynomial 52 changed in this iteration. Existing v3/v4 proofs and approved keys
must not be relabeled as v5. Distributing or approving a new key is separate
deployment work; this continuation changes source and tests only.

Native regressions in `tests/air_range.rs` cover the two failing-before bugs,
nonzero fold charges with a tombstone and padding, duplicate/gapped/missing
slots, changed spans, both real prover/verifier configurations at u32 and u64
boundaries, endpoint reattachment rejection, malformed degree and manifest
roundtrip. Kernel tests include a concrete satisfying trace for all 62
constraints and universally quantified rejection/coverage consumers.

## Merkle position and identity

`Enclave/MerkleIndexBinding.lean` derives the address consumed by the native
bottom-up verifier as `index mod 2^depth`. With the native range/depth checks,
an accepted opening binds the value at the exact claimed position or yields an
explicit node-compression collision. This is stronger than membership somewhere
in the tree. The balanced constructor preserves the ordered leaf list; padding
cannot replace a real member at an in-range index.

`size_committed_opening_binds_exact_index_or_collision` composes the raw-tree
proof with the separate size-commitment domain. Acceptance gives the actual
size and exact position, or a collision in one of those two domains. No finite
hash function is assumed globally injective.

The exact key-pair framing (u32 big-endian SEP length, SEP bytes, authenticator
bytes) has a roundtrip and injectivity proof when the SEP length fits u32.
Different pairs sharing a digest yield an explicit leaf-hash collision.
Duplicate-free leaf digests exclude a repeated identical key pair regardless
of the hash's security. This does not exclude one key appearing in different
pairs, prove physical-host uniqueness or authenticate enrollment.

The native regression attempts other enrolled leaves at each claimed position,
checks key-boundary framing, and retains duplicate-leaf, padding and depth
rejections. Production Poseidon2, loop/constructor correspondence, SEP length
admissibility at all callers, and verifier-side inclusion in the epoch circuit
remain open. The epoch engine still does not instantiate the auxiliary Merkle
AIR; host-side membership checks must not be advertised as a ZK membership proof.

## Two-pass review of this increment

Pass 1 compiles root, tests and verifier; checks declaration kinds and transitive
axioms; reviews theorem-type additions while retaining existing statements;
and exercises the adversarial gate. Logs are recorded in the assurance ticket
after these checks finish.

Pass 2 checked the premises against the extracted polynomial definitions and
native call sites. It found the low-limb and span-overflow defects above. The
successful witness and actual native proof roundtrips exclude an impossible
premise or an always-rejecting implementation for these paths. The explicit
collision alternatives avoid assumed hash injectivity. FRI soundness, auxiliary
relations and universal Rust/compiler refinement remain open; this is an
incremental audit, not full twenty-area sign-off.

The type review also found that `accepted_machine_addition_is_exact` had an
insufficient cast-identity clause. It now evaluates actual `BitVec 64` addition
and proves its signed result equals the integer sum for accepted nonnegative
charges under 12,000 mb. A counterexample proves that the same operation really
wraps at `i64::MAX + 1`, outside those bounds. The bit-vector result is required
by the gate; universal correspondence to Rust's checked-add instruction remains
separate. This strengthened statement is intentionally included in the reviewed
type delta, rather than retaining the weaker helper as assurance.
