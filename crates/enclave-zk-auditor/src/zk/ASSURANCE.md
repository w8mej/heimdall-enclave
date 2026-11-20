# Scope of the epoch accounting proof

The epoch engine instantiates `EpochAir` only. Transcript absorption binds the
finished proof to the supplied statement; it does not establish the truth of
unconstrained journal roots, nullifier, fleet membership or QIF-tree roots.
Native checks on the proving host are not independently verified compliance.
Neither this proof nor the presence of unused auxiliary AIRs establishes an
anonymous enrolled host, a real journal, absence of PII or a hardware assertion.

| Auxiliary AIR | Actual constraints                                    | Missing relation                                                                |
|---------------|-------------------------------------------------------|---------------------------------------------------------------------------------|
| Poseidon2Air  | Boolean activity, squared/quad auxiliaries, row links | Full permutation, absorption, round constants and linear layers                 |
| MerkleAir     | Boolean activity/direction, row links                 | Parent hash and authenticated root                                              |
| SigAir        | Boolean activity; tautological key expression         | Message/tag/key registration and signature or MAC verification                  |
| ImtAir        | Boolean activity, 16-bit field differences            | Authenticated leaves, pointers, roots and updates                               |
| LassoDfaAir   | Boolean flags, zero reject flag, limited links        | Byte classifiers, transition table, reject-state relation and stream continuity |

These skeletons are retained for development and are **not part of any epoch
proof**. No cryptographic result follows from their current constraints.

Reproduce five concrete equal-input/different-output traces from actual
`Air::eval` polynomials with:

```sh
python3 tools/zk-audit/audit_chips.py --output /tmp/air-audit.json
# Expected exit 1: actual counterexamples were found.
python3 -m unittest discover -s tools/zk-audit/tests -v
# Expected exit 0: harness controls and vulnerability-detection regressions pass.
```

The bounded counterexamples disprove determinism. A future run with no fixture
counterexample would not prove soundness. The complete relation requires a
reviewed circuit design, authenticated journal and enrollment inputs, full
cryptographic constraints, and a multi-phase extension-field lookup protocol.
F78/F87/F115 remain pending that work; F134 separately records lookup limits.
The legacy `ComplianceRollupProofV1` name is retained for wire compatibility and
must not be interpreted as proof of full compliance.

## USED range repair (EpochAir v4)

The old slack-only equation admitted `USED = p - 1`, `CAP = 12000`,
`SLACK = 12001` in KoalaBear. EpochAir now constrains USED with fourteen Boolean
bits and their reconstruction, alongside the existing slack bits. The trace has
52 columns, including four blinding columns. Witness generation and both public
verifier entry points enforce the corresponding fourteen-bit accounting domain.
The verifier-key shape is `EpochAir-v4-used-range`; old approved keys must not be
silently relabeled or reused.

`proofs/lean4/Enclave/EpochAirCorrespondence.lean` proves that every assignment
satisfying all 62 exported production polynomials has canonical `USED ≤ CAP`.
`scripts/extract-epoch-air.py` checks every polynomial against actual Rust
`Air::eval` output without regenerating the reviewed Lean source. Field primality,
Booleanity, range bounds and the no-wrap lifting are kernel checked. The theorem
is an actual-constraint accounting result; the auxiliary gaps above remain open.
Regressions in `tests/air_range.rs` evaluate the actual symbolic constraints
against forged USED and non-Boolean bits; `tests/hvzk.rs` retains independent
blinding checks for the updated layout. Proof-size tests use the existing
FS-705 Rev 1.4 ceiling of 320 KiB exported by `MAX_PROOF_BYTES`.

## Slot coverage and absolute spans (EpochAir v5)

The current relation domain is `EpochAir-v5-full-span`. Polynomial 52 now uses
both u32 endpoint limbs, fixing rejection of honest spans crossing `2^32`.
The manifest and verifier digest share `AIR_DOMAIN`. V3/v4 keys and proofs are
not interchangeable with v5; approved-key distribution remains separate work.
Both provers check the span below `2^20` before adding one, preventing a panic
on a full-u64 span.

`EpochAirSlotCoverage.lean` derives the active prefix, exact sequence positions,
exclusive fold/tombstone kinds and zero padding/tombstone charges from all actual
constraints. It proves one row per public slot and integer accounting summed
over precisely those slots. The trace-height bound prevents field wraparound;
the pinned Plonky3 verifier already bounds degree bits by KoalaBear's 24-bit
two-adicity. A separate theorem checks full-limb endpoint encoding against the
actual span polynomial. See [the detailed refinement and audit record](../../../../docs/formal/slot-and-membership-refinement.md)
for premises, native regressions and the remaining FRI/implementation boundary.
These results do not establish any missing auxiliary relation listed above.
