# Selected main-source transport guard contract

Behavioral authority: main `0832c2f23cdff635c21220db2b85399cc56b831e`.
This is a bounded extension of LAT-03/05/06 and areas 00/10/12/17, separate
from all 57 planned full-source slices. It changes no Rust behavior, historical
theorem statement, deployment privilege or whole-area disposition.

`scripts/check-transport-guards.py` recognizes selected signatures and translates
their first executable guards into `Enclave/TransportGuardSource.lean`. Query,
monitor, disk-reserve and bounded-write helper bodies must have the complete
supported shape, including returns. Crypto/KDF tails are outside the fragment.
The mandatory Lean gate checks source agreement without regenerating it, imports
the new proofs/tests, checks their reviewed definition inventory and named types,
and audits transitive axioms. Regeneration is an explicit reviewed action.

| ID    | Exact bounded obligation              | Mathematical acceptance / result                                                                                                                                                                                                                                                                                                                        |
|-------|---------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| SG-01 | Namespace encrypt prefix              | Plaintext byte length 1–16,368; a nonfinal leaf has exactly 16,368 bytes. Refusal projects `EINVAL/NAMESPACE_CHUNK_LENGTH`.                                                                                                                                                                                                                             |
| SG-02 | Namespace decrypt prefix and geometry | Record length 72; ciphertext length 17–16,384; a nonfinal leaf has exactly 16,384 bytes. Adding/subtracting a 16-byte tag bridges the two accepted length domains without machine overflow; 24/72-byte record slicing is in bounds. Refusal projects `EACCES/NAMESPACE_CHUNK_LENGTH`.                                                                   |
| SG-03 | Dual-share shape                      | Each share is independently exactly 32 bytes. This does not establish independent hardware custody or KDF security.                                                                                                                                                                                                                                     |
| SG-04 | Signed descriptor enumeration         | Positive signed count, strictly below capacity, nonzero item size, exact multiple of item size; returned value is that positive count. The supported source order refuses before a negative cast or remainder by zero.                                                                                                                                  |
| SG-05 | Exact descriptor query                | Status zero and returned length equal to expected length, including zero/zero. The previous startup model additionally requires positive expected length; its bridge has that explicit premise.                                                                                                                                                         |
| SG-06 | Namespace envelope byte shape         | Namespace has 1–128 UTF-8 bytes, all ASCII alphanumeric or `.`, `_`, `-`; both epochs are nonzero; envelope has exactly 144 lowercase ASCII hexadecimal bytes. No Unicode-character-length substitution or uppercase acceptance.                                                                                                                        |
| SG-07 | Profile-dependent monitor result      | Successful monitor payload retained for every profile; L1 discards a returned error; L2/L3 retain the same error. The recognized source invokes `start()` once for every profile. The pure state-threading lemma models that observation interface.                                                                                                     |
| SG-08 | Checked disk reserve                  | Success iff `4 GiB + outstanding + extra ≤ u64::MAX`, returning exactly the sum. Both checked-add overflow paths project `E2BIG/ADMISSION_DISK_RESERVE`. This is the real streaming ledger helper, not production quota wiring.                                                                                                                         |
| SG-09 | Incremental bounded target append     | Given current length ≤ signed expected length, success appends exactly incoming bytes, reports their length and stays within expected length. Error has `InvalidData/signed target length exceeded`; the supported Rust refusal precedes the append. Empty input on an already overfull buffer remains a source counterexample to dropping the premise. |

The independent mathematical relations and universally quantified theorems are
in `Enclave/TransportGuardRefinement.lean`; positive/hostile controls are imported
from `Test/TransportGuardRefinementTest.lean`. All names are included in the
reviewed theorem-type manifest. Existing LAT models and tests remain unchanged.
These are guard-fragment proofs under the stated translation boundary, not a
general Rust semantics or a claim that every function succeeds after its guard.

## Domains and trusted boundaries

Lengths represent Rust `usize` on the documented 64-bit platforms; bytes use
`u8` and key epochs use `u64` ranges. Signed observations are 32-bit `libc::c_int`;
the cast lemma requires positivity and the signed upper bound. `usize64` models
modulo 2^64. Logical results outside native input ranges add no runtime claim.
ASCII predicates consume byte values, not Unicode scalar values. Native UTF-8
string-to-byte conversion, iterator traversal and library primitives remain
trusted. The model does not implement or verify hexadecimal decoding.

The Python lexer/parser is trusted and deliberately narrow. It rejects nested
block comments, raw strings, unknown expressions, ambiguous function names,
changed signatures, pre-guard statements and unsupported helper tails. It rejects
dynamic arithmetic, except the exact enumeration remainder expression whose
short-circuit order is checked. Constant arithmetic is checked at every node for
64-bit overflow/underflow. It does not resolve Rust names, macros, modules,
enclosing impls or active cfgs; the correspondence is conditional on the reviewed
symbol/binding/configuration context. Context/caller source hashes are evidence
of inspected bytes, not a verified frontend or proof of invocation.

`fail!` and errors are projected to errno/reason. Query diagnostic formatting,
allocation failure, panics, divergence, LLVM/compiler correctness and machine
execution are outside that projection. `checked_add`, `saturating_sub`, length,
ASCII and list/slice operations use their documented primitive semantics.
Bounded writes assume successful `Vec` allocation when they model an append.
The Rust refusal precedes the append; physical allocation failure is separate.

Cryptography, randomness, authentic signed metadata, Bao-before-decrypt caller
ordering, custody authority, lease revocation, callbacks that panic/diverge,
monitor registration health/lifetime, filesystem durability and OS/FFI outcomes
remain open. No root service, installed identity, production key, account,
firewall, reboot or fault injection is exercised here.

## Review and regression requirements

Every source mutation fixture must first pass the real source checker. Tests
that claim unsupported syntax rejection must call the translator itself and
check its error, rather than merely observing changed generated bytes. Nested
comment spoofing uses a fake guard identical to the original plus a different
executable guard. Runtime subtraction, unguarded remainder and constant underflow
must be rejected even when a mathematical interpretation could hide them.

Five source mutations are explicitly regenerated and compiled against unchanged
independent relations and positive controls: changed tag geometry, unconditional
refusal, inverted query status, wrong optional monitor profile and changed envelope
length. Each mutation has a fresh successful compiler baseline. All must fail
actual Lean compilation. Reviewed type/definition manifests are never refreshed
by the gate; existing compiler/axiom/import/stale-result attacks remain required.

Actual command outcomes, both audits, preservation checks, timing and the
requirement/code/test matrix are in the
implementation record.
Unrun native suites and unresolved acceptance remain in leangaps.md.
