# Lean 4 additions for L1, L2 and L3 transport assurance

Status: **PARTIAL MODEL IMPLEMENTATION — full source/correspondence objectives open**.
Requested 2026-11-12. Implementation baseline:
`23c7cd83d67a9ddb86d09dcfce71530335d8dc2e`. Rebase source mappings and refresh
evidence before further refinement. The delivery matrix
and source review equivalence
identify the reviewed implementation; fixture success does not prove its model.

The 2026-11-13 bundle reconciliation uses main `c4a0f303` as behavioral authority.
Its current mapping binds these
objectives to current Rust, tests and the existing reviewed models. See
leangaps.md for unresolved source/specification differences
and the integration record
for actual fresh-build outcomes. Historical hashes/results do not supersede
current implementation or acceptance rules.

The main `0832c2f2` follow-up adds nine bounded source-guard obligations in the
[selected guard contract](formal/transport-guard-source-contract.md): namespace
chunk/record geometry, share and envelope shape (LAT-03/05), signed query guards
and monitor result policy (LAT-06), checked disk reserve and incremental bounded
append (LAT-05). A trusted shallow translator binds these fragments to current
Rust; independent mathematical relations and actual compiler mutations check the
results. This does not close whole-function, caller, native or any full LAT proof.
Exact query/model equivalence requires positive expected length; main's helper
accepts zero/zero. Allocation, binding/cfg resolution and callback health remain
explicit boundaries. See the closure evidence.

Six executable Lean model subsets and their tests now exist. See the
[implementation and audit record](formal/transport-lean-implementation.md) for
their exact limits, corrective reviews and actual combined gate results. The
full objectives below remain future obligations where not discharged there;
the proposed stronger release contract is not implemented Rust behavior.

This adds transport-specific work to the existing formal backlog,
especially areas 00, 06, 08, 09, 10, 11, 12, 17 and 20. It does not replace the
[twenty-area register](../proofs/lean4/COVERAGE.md) or close those areas.
The initial implementation priorities were LAT-01 cancellation, LAT-02 broker
ownership and LAT-03 keyring persistence. LAT-04 is also an existing normative
obligation, `PROOF-L2-02`, rather than a newly completed result.

## Authority, existing proofs and assumptions

Read FS-702 [Swarm Security Profiles](FEATURE_SWARM_SECURITY_PROFILES.md), FS-706
[Fleet Distribution](FEATURE_MDM_FLEET_DISTRIBUTION.md),
[ADR-021](ARCHITECTURE_DECISION_RECORDS.md#adr-021-confined-root-broker-for-l3-apfs-snapshot-publication),
[hardware custody](FEATURE_HARDWARE_CUSTODY_PROFILES.md), and
[STRIDE TB13/X14–X21](THREAT_MODEL_STRIDE.md).
Use the stable requirement IDs/quotations in
current-coverage.json, including
REQ-702-0191–0209, SBR-01–14, FUNC-005/FUNC-024 and TEST-005. Do not infer that
every suffix in that numeric span exists. Existing signed-profile floors and
authority precedence remain mandatory.

Existing `AuthorizationProtocol.lean` proves list-intersection attenuation;
`ConjunctiveAuth.lean` has predicate-level monotonicity. Neither establishes
Biscuit v3 parser/Datalog/source correspondence. `CustodyProtocol.lean` and
`CustodyLifecycle.lean` cover modeled intent/factors/lease lifecycle;
`ArtifactProtocol.lean` and `LifecycleProtocol.lean` cover abstract admission
and generations. `CrashConsistencyWal.lean` uses records/Booleans, and
`BaoStreamVerification.lean` uses arithmetic codes, not real authenticated Bao.
Reuse useful definitions after reviewing their expanded types; do not rename
these results as transport, APFS, AEAD or hardware proofs. See
[ASSURANCE.md](../proofs/lean4/ASSURANCE.md).

Keep Lean `leanprover/lean4:v4.14.0`, the locked Lake manifest and mathlib
`4bbdccd9c5f862bf90ff12f0a9e2c8be032b9a84`. Model cryptographic verification,
kernel peer identity, descriptor lifetime, filesystem durability, clock and
hardware events as explicitly scoped interfaces with failure outcomes. Derive
each local transition guard; never assume an `admitted`, `safe`, `authorized`,
`durable` or `equivalent` Boolean that is the conclusion being sought.

## Profile coverage and shared model

| Obligation                            | L1                                                             | L2                                         | L3                                                                            |
|---------------------------------------|----------------------------------------------------------------|--------------------------------------------|-------------------------------------------------------------------------------|
| LAT-01 cancellation/admission/receipt | registry, cache and manual admission                           | QUIC, seed and cache                       | OHTTP, broker, cache; no plain-CAS fallback                                   |
| LAT-02 ownership/quiescence           | no broker; prove dispatch exclusion                            | no broker; prove dispatch exclusion        | broker Publish/Reopen/Revoke and lifecycle                                    |
| LAT-03 custody/history/floors         | actual L1 factor policy; namespace unwrap rejects L1 by design | current dual-custody/namespace lease       | current dual-custody/namespace lease                                          |
| LAT-04 capabilities                   | relevant registry/local authorization, separately specified    | Biscuit/issuer/mTLS/exporter/shard/license | local custody and configured relay/gateway authority; no assumed QUIC channel |
| LAT-05 closure/stream/resource        | TLS/registry verified plaintext                                | encrypted QUIC/Bao/AEAD                    | encrypted OHTTP/Bao/AEAD and sealed handoff                                   |
| LAT-06 configuration/startup          | normal release and signed floors                               | required monitor before serving            | required monitor, zero listeners, confined helper                             |

Use a shared `Profile`, exact fixed-width counter operations, root/namespace and
authority identities, current metadata snapshot, lease generation, per-root
plan ownership, staged-byte accounting, visible artifact set, publication owner
and receipt state. Separate logical root names from `(device,inode)` identities
and distinguish ordinary CAS, immutable snapshot and transferred descriptor.
Specify the observation boundary: staged private bytes are not client-visible;
an emitted IPC descriptor or successful durable receipt is observable.

Model small-step events, not only completed RPCs: authorization, atomic load/
update, State-lock acquire, chunk verification, disk write, lease check,
publication effect, save, journal append, descriptor transfer, reply loss,
cleanup, crash and restart. A mutex or SeqCst label alone is not a proof of the
composition. Define permitted interleavings and each operation's linearization
point from actual code. Safety holds for finite prefixes; liveness requires
separately stated fair scheduling, responsive primitives and available storage.

## LAT-01: Cancellation, overlapping Wipes and successful admission

Suggested module `Enclave/TransportAdmission.lean`; tests
`Test/TransportAdmissionTest.lean`. Extend area 10/11; depend on area 00 source
bridge, area 09 durability and explicit authority/lease interfaces.

Source: `crates/enclave-swarm-syncd/src/service.rs` (`DownloadCancellation`,
`PendingWipe`, `DownloadPlan`, `handle`, access epoch and download-authority
checks). Trace every Hydrate/OpenTarget/Resolve/Fetch/FetchTarget/SeedDecision,
manual Admit/AdmitBegin/AdmitChunk/AdmitCommit, seed and receipt branch. Status,
abort and authenticated management remain available for recovery.

State includes u64 generation, checked usize pending count, sticky blocked
latch, State-lock owner, original plan epoch, active-root reservations, owned
publications and pending/committed journal results. Model the individual ordered
atomics in `observe`, `begin`, `advance`, `finish` and Drop; do not replace the
multi-load `observe` with an assumed atomic snapshot. Authorized public Wipe
fences before waiting for State; serialized Wipe reasserts blocked before its
first fallible operation. Only fully successful cleanup **and journal append**
may clear it; pending guards still deny until all outstanding Wipes leave.
Journaling is conditional in the current `CasConfig`: if no audit path/journal
is configured, the append is skipped before latch clear. State the configured-
journal premise or add a separately reviewed production requirement; do not
invent universal durable receipts. Cancellation generation is process-local and
restarts at zero. Include boot/process identity and destruction of old plans in
cross-restart claims, separately from custody leases' existing boot binding.

Prove arbitrary-history statements (proposed names):

- `unauthorized_wipe_preserves_authority`: rejection causes no cancellation or
  owned-resource mutation, including while State is held.
- `cancelled_epoch_cannot_admit`: after the defined fence, an old epoch cannot
  newly publish, hand off bytes or append a successful governed receipt. Locate
  every final check/effect race; if Rust cannot discharge this stronger claim,
  repair Rust or retain the counterexample, never assume atomic check-and-use.
- `failed_cleanup_keeps_blocked`: dropping a failed pending guard is not recovery.
- `last_serialized_wipe_controls_latch`: success of an earlier overlapping Wipe
  cannot clear a later failed Wipe's refusal; a healthy authorized retry recovers.
- `checked_counters_never_reauthorize`: overflow/exhaustion refuses without wrap
  or pending-count leak; include error paths and Drop.
- `success_has_current_authority`: coherent metadata, effective floor, current
  lease/generation, complete verified eager closure and owned publication precede
  successful acknowledgment; a reply failure is not proof of no side effect.

Required traces: unauthorized Wipe during held State; Wipe during blocked
network/copy/publication; success-Wipe then failure-Wipe overlap; failure then
healthy retry; stale queued cached/manual request; revoked lease/metadata between
verification and commit; journal failure after cleanup; generation/pending limits;
valid fresh retry and legitimate L1/L2/L3 cache hit. Use actual `f38_` service
regressions plus `l2l3_transport` and `quic_download` as executable starting points.
Already transferred descriptors/mappings require LAT-02 holder work; this
theorem cannot claim to retract plaintext a client already observed.

**Concrete unresolved release schedules at the baseline:**
`handle_locked_access` validates the epoch, then appends to the journal and
returns. Wipe can execute its pre-State fence between validation and append.
`ipc::serve_connection` calls the handler, then writes the reply and sends queued
OUTBOX_FDS; Wipe can occur after handler return but before transfer. Platform
publication effects can also occur between checks before later rollback. These
are source/refinement obligations, not proved prevention or "already transferred"
cases. SBR-09/10 require cancellation/current-authority refusal but do not define
the pre-State fence as a universal external-release linearization point. Specify
whether an already admitted operation may acknowledge later, and preserve both
the actual trace and the stronger desired contract. A cancellation-aware response/
FD permit needs an atomic release boundary; another unchecked check-to-send gap
or a gate held across unbounded socket/fsync operations is not a sufficient fix.
Do not silently weaken the desired theorem or describe current Rust as satisfying it.

## LAT-02: Broker ownership, crash cuts and deployment quiescence

Suggested module `Enclave/SnapshotBrokerProtocol.lean`; tests
`Test/SnapshotBrokerProtocolTest.lean`. Extend areas 09/10/17. L3 only; L1/L2
must not invoke this privilege boundary.

Source: `snapshot_broker.rs`, `snapshot_publication.rs`, `transport` broker caller
through `service.rs`, `enclave-core/src/{ipc,codesign,sealed}.rs`, and actual
`mcp-enclave`/packaging lifecycle tooling. Use the SBR-01–14 production/assertion
map in broker trace.

Represent absent, intent-only/ownership-uncertain, owned-incomplete and
owned-complete states using **separate durable record and actual platform state**.
Include poisoned persistence, independent TUF high-water state, original target/
volume authority, private verified copy, code pins, operation lock and durable
deployment.quiesced marker. Publish carries exactly one RO regular APFS FD;
Reopen/Revoke carry none. Canonical roots, exact bounded framing and fresh
reciprocal identity are preconditions derived from the authenticated parser,
not caller-provided claims. The helper has no generic path, shell or PID command.

Prove `intent_does_not_grant_delete`, `foreign_eexist_never_owned`,
`uncertain_creation_refuses_automatic_cleanup`, `revoke_uses_original_authority`,
`reopen_requires_current_authority`, `quiesced_no_later_effect` and
`state_overflow_precedes_effect_or_overwrite`. Intent persisted before creation
does not prove creation success; every crash/save cut must preserve uncertainty.
Revoke may use stored original authority after current metadata revocation or
volume rotation; do not impose fresh publish authorization that prevents cleanup.
An absent revoke is idempotent. Owned-incomplete recovery is distinct from
uncertain ownership and may clean only resources it actually owns.

The operation lock spans whole accepted operations and the durable quiescence
decision. Diagnostic `--check-idle` alone cannot justify removal. Refuse lifecycle
removal with owned/uncertain/corrupt/incomplete state. Model serialized-state
encoding bounds (currently 32MiB), record and TUF-chain bounds before mutation.

Counterexamples: foreign snapshot EEXIST; success then lost reply; crash after
create before ownership save; save failure after irreversible effect; changed
config during copy and after publication; retry against original publisher;
quiesce racing accepted Publish; truncated/extra FD/framing; stale peer pins;
record/serialized-cap limits. Positive witnesses must publish/reopen/revoke an
owned fixture and quiesce a genuinely idle fixture.

**Holder sub-obligation remains missing source work:** current enforcement sees
the ordinary CAS inode, not the actual snapshot inode; FD-only Darwin scanning
misses closed-FD mmap holders and can treat query errors as absence. Specify a
separately versioned authenticated broker-to-supervisor held-FD contract, fresh
exact broker pin, bounded mapped-vnode observation with explicit incomplete/error
states and existing daemon UID701–705 signaling limits before claiming holder
revocation. No arbitrary CAS-provided PID/inode authority or expansion of the
three-operation broker grammar is authorized by this backlog. Prove safety only
for the implemented boundary; APFS mount flags, entitlements, physical erasure
and already-mapped plaintext remain separate native/hardware obligations.

## LAT-03: Namespace history, migration and durable anti-rollback

Suggested module `Enclave/NamespaceKeyringProtocol.lean`; tests
`Test/NamespaceKeyringProtocolTest.lean`. Extend areas 08/09/12; depend on
actual custody factor/intent/lease semantics and authenticated byte codecs.

Source: `crates/enclave-custody-vaultd/src/{cas_keyring,service,ceremony,lease}.rs`,
`crates/enclave-crypto/src/namespace.rs`, `enclave-core/src/sealed.rs`,
`enclave-swarm-syncd/src/transport/custody.rs` and `mcp-enclave vault cas-*` callers.
State: namespace DEK epoch, KEK wrapping epoch, authenticated envelope identity
and full historical set, monotonic wrapping-retirement floors, sealed generation/checkpoint,
legacy migration marker, lease generation, persisted authenticator signcounts
and sticky save-failure poison. Distinguish DEK rotation from KEK rewrap.

Prove history/floor rollback refusal relative to the last durably committed
checkpoint; rewrap keeps historical ciphertext/DEKs usable under current allowed
custody; retired wrapping epochs cannot re-enter through old envelopes. Engineer
principal offboarding is a separate future theorem requiring the missing
membership/authorization contract. `namespace_peer` rejects L1 by design; L1
factor-policy proofs belong to `CustodyLifecycle`, not a fabricated successful
L1 namespace-unwrap witness. Migration preserves the
complete authenticated history once and stale legacy input cannot override a new
store. A partially consumed hardware counter must persist even when the second
PRF or later registration fails. Poisoned persistence revokes service leases;
commit rechecks revocation and cannot revive a removed lease.

Specify exact legacy/new/checkpoint write order and every crash cut, concurrent
registration/removal, failed second factor, exhausted epoch/counter, corrupt or
oversized state, missing checkpoint, stale envelope, repeated migration and healthy
restart/rewrap witnesses. Existing `f38_` custody and keyring tests supply fixtures.
If both legacy state and checkpoint were deleted before the first upgrade, this
is indistinguishable from never initialized; no local theorem can establish an
external anchor that does not exist. Whole-authority rollback needs an independent
trusted anchor. Per-engineer SPIFFE+Biscuit unwrap policy is missing source/policy;
local UID admission and software factors must not be assumed to implement it.
`SealedStore::save` writes state before checkpoint and accepts state-ahead
recovery. Explicit counterexample: crash with state generation g+1 and checkpoint
g; restart may accept g+1, yet restoring authenticated old state g also satisfies
checkpoint g. This partial-state rollback is distinct from whole-directory
replacement. Stronger monotonicity relative to every ever-observed state needs
additional recovery code/anchor; retain it as open rather than assuming it proved.

## LAT-04: Non-amplifying capabilities and actual channel binding

Suggested module `Enclave/SwarmAuthorization.lean`; tests
`Test/SwarmAuthorizationTest.lean`. Refine area 06/07 and `PROOF-L2-02` over
the admitted **Biscuit v3 Datalog** semantics, including block trust scopes, facts,
rules, checks and authorizer ambient facts. Establish for a valid token and any
admitted appended blocks `AuthorizedHashes(T ++ blocks) ⊆ AuthorizedHashes(T)`;
equality is allowed. Strict shrinkage is not required for every attenuation.
Do not prove only predicate intersection or assume the subset as a premise.
Current `parse_and_verify_token`/`make_call_sealed` require sealed wire tokens;
appendable tokens and delegated ambient facts/rules are rejected. Define the
attenuation construction over pre-seal chains, then relate each sealed admitted
chain to it. Require a successful parent-to-child narrowing witness at fixed
request/ambient context; quantifying over impossible appended wire tokens would
make the proof vacuous. Publish the admitted block grammar and reject unsupported
facts/rules explicitly instead of silently treating them as accepted constructs.

Map `transport/{quic,quic_seed,quic_poison}.rs`, crypto
`{pop_biscuit,pop_biscuit_facts}.rs`, current namespace/shard/license policy and
actual service seed/hydration callers. Derive peer from authenticated TLS,
certificate identity and exporter from the actual connection; bind issuer,
namespace/root/right/shard/license, PoP, expiry/replay and revocation to it.
Renewals and reused connections recheck current authority before storage and
before response bytes. A request-supplied peer or nonempty token is insufficient.

Use independently signed valid/forged/unknown-issuer tokens, appended permissive
facts/rules and narrowing checks, wrong peer/exporter/root/scope, expired/replayed
capabilities, slow source followed by revocation, live-connection revocation and
valid renewal. Include rejection without inventory/payload/success receipt.
Cryptographic unforgeability, exporter security and network identity hardware
remain conditional primitives. Current software Ed25519 identity versus SEP P256
requires a versioned signer/holder/issuer design; do not silently model it solved.
Local detector-signed poison/quarantine is not fleet adjudication/dissemination.

## LAT-05: Whole closure, encrypted streams and bounded resources

The selected bounded task is specified independently in the
exact-main admission contract, with
authoring/source history in L4G-10C.
It refines FS-702 `ADM-01`–`ADM-06` and FS-701 §3.2.1 using the existing four-field
`Target`, exact main membership, selected same-root consistency and admitted
positive bundles. It freezes interfaces and existing theorem statements while
allowing the admission predicate and affected proof bodies to be repaired.
Trusted verification must check the complete acceptance relation as well as
rejection examples, and derive a certificate-level exact-main result. The
contract describes future task packaging; no Harbor verifier or trial result is
implied. Completing this slice leaves the broader LAT-05 objectives below open.

Suggested module `Enclave/TransportClosure.lean`; tests
`Test/TransportClosureTest.lean`. Refine area 10, alongside LAT-01/03/04 and TUF
byte/authority contracts. Map `service.rs`, `streaming.rs`, `cas.rs`,
`transport/{registry,quic,quic_seed,oblivious,ohttp_fetch,quota}.rs`,
`enclave-crypto/src/namespace.rs`, and actual broker publication caller.

Define authenticated main/direct-eager-companion set and coherent metadata snapshot,
required profile floor, verification progress, exact lengths/EOF, aggregate
session quota, independent per-artifact staging bound and per-root reservation.
Prove no partial eager closure becomes admitted, one plan cannot retract another
plan's committed root, reservations/quota return on every owned failure, cached
corruption is refused, and valid multi-artifact closure is reachable. Preserve
unchanged existing artifacts and original cleanup authority across reply loss.
Current `prepare_download` enumerates direct eager companions, not transitive
graph closure. Include main→A→B as a distinguishing trace; recursive closure is
additional source/spec work if required, not an established baseline guarantee.

Model ciphertext Bao authentication before AEAD plaintext release, root/index/
finality context, ordered chunks and key-index records, including empty-input
refusal (encrypted artifacts/chunks are nonempty), valid short/full final leaves
and actual 16368/16384/72-byte geometry. `context_body_separation` must use
a precise KDF/AEAD assumption: differing tags alone do not show stream separation,
and universal collision-free KDF output is false. Tests compare ciphertext bodies
excluding tags, same-context determinism, alternate-context roundtrips, wrong
context and tamper refusal; a conditional Lean model does not prove IND-CDA.

L1: authenticated registry TLS, exact verified bytes and effective-profile cache
gates. L2: actual QUIC identity and encrypted verified adapter. L3: RFC9458 OHTTP/
BHTTP HPKE request/response context binding, pinned relay/gateway, padding/framing,
range/deadline limits and no downgrade/direct-origin fallback. Separate model
download from compliance-proof upload: the latter needs its own source map and
acceptance. Metadata snapshot changes, truncation/oversize, malicious framing,
five-artifact quota, interruption/Wipe and atomic rollback require counterexamples
and positive witnesses through actual adapters.

The actual production L3 model adapter is `transport/oblivious.rs`, with
`frame`, `RelayReader`, `fetch`, `EncryptedTarget` and `verify_encrypted_streams`,
plus `enclave-crypto/src/ohttp.rs`, pinned `ohttp_rfc` and
`tests/l2l3_transport.rs`. `ohttp_fetch.rs` also contains the guard and an older
helper; a proof only of that helper cannot establish production model delivery.
L1 anchors include `tests/download_dispatch.rs` (actual IPC/TLS, framing,
deadlines, configuration and companion-policy rotation), effective-profile/cache
and manual-admission service assertions, and the two named `l1_gc_ttl.rs`
tests `test_cas_ref_counted_gc_pruning` and
`test_168h_offline_ttl_safe_fail_lockdown`. Model reference counts, collection,
168h offline expiry and valid recovery. Do not run the entire `l1_gc_ttl` target
as a safe surrogate: its snapshot-entitlement probe is a distinct restricted
native operation. Registry server-TLS/content authentication is not client
authorization: baseline `RegistryConfig` uses `with_no_client_auth()` and has no
private-registry credential contract. Retain that provisioning gap explicitly.

FS-702 assigns inventory privacy to Tamarin/CryptoVerif, Bao/keyed-MLE crypto
properties to EasyCrypt/Coq, and concurrent platform temporal properties to
TLA+/Apalache. Lean can prove orchestration under explicit primitives; it must
not claim those distinct analyses, universal timing privacy, relay noncollusion,
large-artifact RSS/throughput or installed APFS behavior.

## LAT-06: Signed configuration, startup, monitoring and zero listeners

Suggested module `Enclave/TransportStartup.lean`; tests
`Test/TransportStartupTest.lean`. Refine area 08/17/20. Map `entry.rs`,
`enclave-core/src/{runtime,power,supervisor}.rs`,
`mcp-enclave/src/launchd.rs`, `transport/ohttp_fetch.rs`, native socket-observation
shim, broker lifecycle and `helpers/enclaveintent` relay. Enumerate actual paths
before translating; these modules do not imply a complete OS semantics.

Prove signed canonical payload precedence over stale loose copies, exact bytes/
length, nofollow/nonregular/path/argument refusal and bounded growth before
allocation. Bind root-chain rotation, expiry/revocation and profile-floor decisions
to authenticated current configuration. Normal release argv must reach production
confinement validation; simulation is not a successful release witness.

State required monitor registration and thread ownership, partial cleanup,
serving/seed enablement, weak Wipe hooks, bounded GUI frame/reply deadlines and
five distinct supervisor-assigned daemon UID receipts. L2/L3 cannot serve before
required power/USB registration; L1 follows its actual policy. Root GUI relay UID
authentication alone is not an established exact supervisor code pin. Remaining
non-CAS pre-confinement construction and ZK detached-worker lifetime after bind
failure must remain explicit source gaps.

For L3, define descriptor observation `Known(description) | Incomplete | Error`:
reject unavailable required observations, TCP listeners and bound unconnected
IPv4/IPv6 receiving UDP, preserve documented client/Unix controls, and recover
after close. A static descriptor snapshot does not prove that a later listener
cannot appear: caller repetition and native confinement are separate premises.
Include short/unsupported/query-failure results, fragmented replies, duplicate/
missing daemon receipts, failed registration, failed bind and normal release
positive controls. Use actual `listener_guard`, `config_provisioning`,
`release_startup`, power-hook and private Swift relay regressions.

## Implementation deliverables and two-pass closure

For each LAT slice, freeze exact source/hash and public theorem statements,
transition/observation definitions, numeric bounds, valid domain, external
assumptions and dependencies. Provide a production-to-Lean relation and derive
its simulation for the supported subset using the
source-bridge contract.
Executable trace comparisons are regression evidence; no extraction pipeline or
universal refinement may be inferred from copied Lean definitions and vectors.

Export modules in `proofs/lean4/Enclave.lean`, tests in `Test.lean`; add mandatory
theorems and exact dependency/type review to `scripts/check-lean.py` and
`theorem-types.json`. No `sorry`, `admit`, custom proof axiom or hidden conclusion
premise. Record standard logical principles. Guard referenced **definitions** as
well as type hashes. Retain valid witnesses so always-refuse implementations fail.

Run the pinned gate and affected correspondence/Rust suites, with exact commands,
revisions, exits, counts and raw hashes. Commands already defined in the backlog:

```sh
python3 scripts/check-lean.py
python3 -m unittest discover -s scripts/tests -p test_lean_gate.py
python3 scripts/check-formal-correspondence.py
python3 scripts/check-protocol-correspondence.py
```

Future LAT-specific correspondence/mutation checks must be implemented; the
commands above do not already enforce this document. Challenge removed epoch/
lease checks, cleared failure latch, foreign ownership adoption, stale config,
unchecked counters, widened capability facts and ignored observation errors.
Rebuild from trusted source, reject forged logs/prebuilt `.olean`/changed
contracts and report sampled traces as sampled. Keep positive and negative cases.

Proof implementation pass 1 must compile exact final statements/tests and audit
transitive axioms/types/source provenance. Pass 2 independently reviews source
callers, all profiles, assumptions, check/effect races, crash/error cuts,
counterexamples and non-vacuity. Fix findings and rerun affected evidence. These
future proof audits are distinct from the **documentation** two-pass audit in
the review record.

Portable Lean/model work may run in a pinned offline image. Native Darwin checks
use only reviewed bounded private fixtures on the configured Mac runner, exact
committed source, doctor READY/live/current and its serial queue. No installation,
accounts/firewall/security/production-key changes, root APFS mutation, reboot,
fault injection or exhaustion on this personal host. Installed identity, mount
flags/entitlements, physical SEP/FIDO/lock/yank/deadlines and SLOs remain BLOCKED/
NOT RUN. A future authorized environment and authentic authority material are
prerequisites, not substitutes for the missing source contracts.

Update this feature addendum, FS-702/FS-706/STRIDE, formal COVERAGE/ASSURANCE,
the delivery matrix, both implementation/independent audit records and handoffs
with theorem names, proved hypotheses, correspondence scope, actual outcomes and
remaining blockers. A bounded proof slice may complete while F38, full-profile
conformance and the broader twenty-area objective remain nonterminal. No Harbor
scaffolding or trial follows automatically from this documentation assignment.
