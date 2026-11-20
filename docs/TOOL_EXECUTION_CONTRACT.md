# Tool execution and egress contract

The configured live `IfcRequest::ExecuteTurnPlan` path authorizes each actual
`tool_call` and dispatches through `NativeToolDispatch` and `ArtifactDispatcher`
to ToolHost. See [configured native execution](tool-execution.md) for the
independent offline build key, signed immutable artifacts and durable replay
provisioning requirements. Missing configuration leaves transport unavailable;
partial configuration refuses startup. Standalone `EnclaveStarlarkV1::execute`
still refuses tool dispatch. `declassify_enum` is not registered in either plan
dialect; its separate RPC does not establish in-plan wiring. These contracts do
not establish installed macOS acceptance.

Following the user's RD-07 decision, live execution checks every tool site in
every AST branch before evaluating any statement. One active policy snapshot,
the verified chain principal and immutable curated tool scope determine
eligibility with fixed C1/T1, one-row, zero-charge facts. A3/A4 eligibility may
assume hardware only when step-up was explicitly requested; it never runs a
ceremony or grants authority. Unsupported plan-local declassification is refused
by the AST guard. Unknown, out-of-scope or denied dead branches reject the plan
before dispatch, debit, replay consumption or governed-slot allocation.

Each reached call still uses current policy and actual arguments through the
conjunctive live PDP. A later denial, transport error or cancellation can follow
earlier effects. L1/L2 errors then include a sanitized `dispatched_tool_calls`
count and tell callers not to retry automatically. This counts attempts, not
confirmed remote commits or rollback. L3 retains its sealed error. See the
implementation and bounded acceptance record
and original finding.

The trusted dispatcher selects the server/tool independently of the ticket. The
issuer signs canonical argument bytes, the approved row count and interpretation,
and, for native modules, a digest from an authenticated offline build registry.
Never approve a native digest taken solely from an invocation request. Recompile
native artifacts for the pinned Wasmtime version with fuel enabled; execute only
that approved digest. Guest exports are `memory`, `alloc(i32)->i32` and
`run(i32,i32)->i32`; run receives the signed argument pointer and byte length.

An approved JSON row is one element of a top-level array. Text output is allowed
only when trusted metadata/approval explicitly selects UTF-8 lines as the row
unit; CR, LF and CRLF delimit lines. Unknown output formats fail. A bound of zero
returns no rows. A single approved row may contain nested values; callers must
not present line or array-element counts as a bound on nested semantic records.

Provision replay storage once in an absolute, canonical daemon-owned mode0700
directory with `TicketReplayFilter::initialize(path, capacity)`. Reopen with
`open(path)` after restart; never reset state to recover a transient error. Files
must remain mode0600. Consumption is durable before side effects, and failure
still spends a ticket. Supply trusted UNIX epoch nanoseconds to both issuer and
host. Clock rollback blocks calls. Capacity refuses additional live tickets until
expiry; it does not evict them. To deliberately reset storage, revoke the old
issuer key/tickets first and provision state with the new issuer key.

External output requires a locally pinned auditor verification key. Each gated
window includes128 bytes of context/lookahead, and the proxy holds the suffix
until the next bytes have been scanned. This covers the current finite
SSN/digit-hyphen recognizer, not all possible PII or arbitrary future recognizers.
The gate result is a signed DFA attestation; it is not a succinct zero-knowledge
proof. macOS additionally checks the auditor's designated code requirement.
Linux tests cannot establish that macOS check.

Transmission is incremental. On a later rejection or sink error, an earlier
verified clean prefix may already have reached the destination. Treat an error
as partial transmission: report failure, record the delivered offset if the sink
provides it, and use the destination's transaction/idempotency mechanism before
retrying. Never report success or blindly resend the entire payload after an
error. No byte of a boundary-spanning identifier is intentionally released before
the complete matching window has passed.
