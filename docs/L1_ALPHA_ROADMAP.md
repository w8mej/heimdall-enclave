# L1 alpha roadmap: five real models under `L1`

Status: **PROPOSED, 2026-11-16.** Written after the first passing standalone
Touch ID and YubiKey diagnostics. It is a plan, not evidence: nothing here
closes a feature gate, and it does not edit any hash-pinned specification.

## 1. Goal and scope

**Alpha goal:** on one Apple Silicon Mac, five real published checkpoints each
produce model-derived output through the authenticated runner chain under
profile `L1`, with receipts that name the backend that actually ran.

| # | Model type              | Execution class                    | Phase-one target                                                                        |
|---|-------------------------|------------------------------------|-----------------------------------------------------------------------------------------|
| 1 | Autoregressive          | `AR_CAUSAL`                        | SmolLM2-135M-Instruct (already selected and pinned in `scripts/fetch-trained-model.py`) |
| 2 | Discrete diffusion      | `DISCRETE_DIFFUSION` (class 2)     | LLaDA-8B                                                                                |
| 3 | Recurrent / state-space | `RECURRENT_SSM_TTT` (class 3)      | RWKV-7                                                                                  |
| 4 | Speculative             | `SPECULATIVE_RECURRENT` (class 5)  | EAGLE-3 draft head on Qwen3-0.6B                                                        |
| 5 | World model             | `JEPA_EBM_WORLD_PLANNER` (class 6) | V-JEPA 2, encoder and predictor only                                                    |

**In the alpha**

- Real inference for all five through signed manifest, authenticated weight
  resolution, bind, class gate, output guards and receipt.
- The development fleet (`mcp-enclave --dev`: the five real daemons under one
  user, in a private state directory) on the development Mac (M1 Pro, 32 GB).
  `scripts/bootstrap-laptop.sh` is the legacy Python simulation and is not
  used.
- The integrated `L1` Touch ID and Secure Enclave ceremony for the actions
  that require it. `L1` needs no YubiKey.
- A refusal matrix per model: mutated weights, wrong class, missing companion
  and unsupported format must refuse before any output.

**Deferred to beta**

- Installed services under distinct users, firewall readiness, signed
  packaging, updates and fleet distribution.
- `L2` and `L3`, every YubiKey factor, and the chained Touch ID to YubiKey
  ceremony.
- GPU and Neural Engine execution, measured memory erasure, performance
  targets and formal correspondence.
- Classes 1 (classifier) and 4 (byte/concept), which have no phase-one
  checkpoint.

**Two scope decisions this plan relies on.** The residual specifications say
neither has been approved before, so they are recorded here as decisions by the
project owner on 2026-11-16:

1. Alpha means "runs for real in the local deployment", not the stricter
   installed acceptance that
   WL-01 step 4
   describes. That stricter gate stays open and becomes the beta bar.
2. The alpha covers five of the seven engines.
   WL-16 keeps all
   six post-autoregressive classes in release scope; classes 1 and 4 are
   deferred, not cut.

## 2. Where the code stands

From a read of `crates/enclave-model-runnerd`, the open finding
APR-006
and the workload specifications. The storage, gateway and startup code was not
surveyed in depth; milestone M0 closes that gap by running the stack.

- **Every class binds a tiny reference engine.** `adapter.rs` selects
  `BigramLm`, `BigramDenoiser`, `DiagonalSsm`, `ReferenceDepth` and
  `ReferenceJepa`. Receipts say `cpu_reference`.
- **The class gates are real and tested.** Grammar constraint, diffusion
  release at the final step, recurrent state snapshots, thermal pacing, the
  planner barrier, output guards and scrub-on-error all exist around the
  reference engines. The alpha keeps them and swaps what sits behind them.
- **The backend interfaces are byte-level.** Each backend trait returns 256
  logits over bytes. Real checkpoints are token-level (SmolLM2 has a
  49,152-entry vocabulary). This is the main design gap.
- **There is one real framework path, and it is narrow.** `mlx_bigram_v1`
  runs a fixed 256×256 product in a Python worker, in debug builds only, with
  weights piped over stdin. `coreml_linear_v1` is a single dense layer.
- **A real checkpoint has already run outside the runner.**
  `scripts/phase4-trained-mlx.py` runs SmolLM2-135M on MLX with a closed,
  repository-owned Llama implementation and no upstream model code.
  `phase4-trained-smolvlm.py` does the same for a small vision model.
- **Weights are handed over as one in-memory byte slice.** That works for
  megabytes, not for an 8B-parameter model on a 32 GB machine.
- **The runner's unit tests are almost green.** On 2026-11-16 with Rust
  1.99.1, 140 of 141 library tests passed. The one failure,
  `bounded_prepare_stall_never_holds_fence_and_captured_epoch_cannot_dispatch`,
  passed three out of three times when run alone, so it looks
  order- or timing-dependent; the cause is not yet diagnosed. Cargo stopped
  there, so the crate's integration tests have not been run.
- **MLX is not installed on the development Mac.** The earlier probes used
  hash-pinned wheels that were under the deleted `target/`.
- **`L1` custody:** the production Touch ID sheet and Secure Enclave signing
  passed standalone on 2026-11-16. The integrated ceremony through the helper
  and custody service
  (AP-02)
  has not run.

## 3. Strategy

1. **Walking skeleton first.** Take the smallest real model (SmolLM2) through
   the whole chain before starting any other class. Shared gaps in manifest,
   weight handoff, tokenizer, receipt and deployment surface once, on the
   cheapest model.
2. **Keep the gates, replace the engines.** Each class keeps its existing gate
   and tests. New work goes behind the backend traits.
3. **One closed graph per architecture.** Follow the existing rule: the
   repository owns the graph code, and no publisher code, pickle or arbitrary
   graph is loaded. Each architecture is a reviewed implementation selected by
   a signed architecture identifier.
4. **Token-aware seam, byte-level guards.** Backends work in tokens. The
   runner owns a closed tokenizer loaded from an authenticated companion.
   Grammar, PII and canary guards keep operating on decoded bytes.
5. **Smallest published checkpoint per class.** The alpha proves the path,
   not model quality. Use quantized weights wherever the published size would
   not fit in memory.
6. **An explicit alpha backend gate.** Replace "debug builds only" with a
   named build feature and a signed manifest field, so a release build can
   never select the alpha backend by accident and receipts state it.
7. **Reference engines stay.** They remain the fast test fixtures and the
   differential oracle for gate behaviour.
8. **Evidence discipline.** Check hash pins before editing any tracked
   document, keep receipts out of the ignored `target/`, and never promote a
   fixture run to real-model evidence.

## 4. Milestones

Estimates assume one engineer working with an agent. They are low-confidence
until M2 lands; APR-006 itself estimates 6–12 engineer-weeks for the first
real backend and model.

| Milestone                  | Outcome                                                                                                            | Estimate  |
|----------------------------|--------------------------------------------------------------------------------------------------------------------|-----------|
| M0 Foundations             | Decisions recorded, stack running locally with reference models, MLX pinned                                        | 1 week    |
| M1 Runtime seam            | Native MLX worker spike, token interface, tokenizer companion, weight handoff, worker protocol v2, honest receipts | 3–4 weeks |
| M2 Autoregressive          | SmolLM2 end to end under `L1`                                                                                      | 1–2 weeks |
| M3 Recurrent               | RWKV-7 end to end                                                                                                  | 2 weeks   |
| M4 Diffusion               | LLaDA-8B end to end                                                                                                | 2–3 weeks |
| M5 Speculative             | EAGLE-3 with its base model end to end                                                                             | 2–3 weeks |
| M6 World model             | V-JEPA 2 encoder and predictor end to end                                                                          | 3 weeks   |
| C Custody track (parallel) | Integrated `L1` Touch ID ceremony in the local deployment                                                          | 3–4 weeks |
| M7 Alpha qualification     | All five in one run, refusal matrix, receipts, tag                                                                 | 1–2 weeks |

Serial total is roughly 15–21 weeks. M3 to M6 are independent after M2 and
can overlap; track C is independent of all model work.

### M0 Foundations

- Record the two scope decisions and the checkpoint table in the scope
  documents (new files or unpinned ones only).
- Confirm licence and redistribution terms for each checkpoint, and pin each
  by revision, size and SHA-256 as `fetch-trained-model.py` already does.
- Bring up the development fleet and run each of the five classes with its
  reference fixture under `L1`, through the gateway. This proves the chain as
  it stands and exposes storage, gateway and startup gaps before model work.
- Re-pin an MLX runtime by hash for the golden-output reference runs.
- Diagnose the one intermittent release-fence test, run the integration
  tests, and keep a fully green runner suite as the regression baseline.
- Exit: one command runs all five reference classes locally and saves receipts.

### M1 Runtime seam

- One-week spike: a native worker process linking MLX through its C API,
  running the existing bigram graph. Decide native or Python fallback.
- Token-level backend traits with a declared vocabulary size, replacing the
  fixed 256-way arrays.
- Closed tokenizer in Rust, loaded from an authenticated companion, with
  byte-exact decode for the guards.
- Weight handoff by file descriptor or mapping instead of piping floats.
- Worker protocol v2: architecture identifier, tensor layout check, bounded
  requests, cancellation and deadline, kill on fault.
- Receipt fields for backend, architecture identifier, runtime version and
  checkpoint digest; `cpu_reference` only when that is true.
- Exit: the existing bigram fixture runs through the new seam with all current
  gate tests passing.

### M2 to M6 per-model work

Each model follows the same steps: closed graph implementation, manifest and
companions, bind through the class gate, golden-output check against an
independent run of the same checkpoint, refusal matrix, saved receipt.

- **M2 SmolLM2.** Promote the existing closed Llama probe into the worker.
  This is the acceptance test for the M1 seam.
- **M3 RWKV-7.** New closed graph. Recurrent state lives in the existing
  snapshot structure, with system-state locking and wipe on session end.
- **M4 LLaDA-8B.** A bidirectional transformer mask predictor, so it should
  share blocks with the M2 graph. Needs quantized weights to fit in 32 GB.
  Output is released only at the final denoising step, as the gate enforces.
- **M5 EAGLE-3.** A draft head tied to a specific base model; see section 7
  for the chosen pair. The 8B base should share blocks with the M2 graph. The base hidden-state binding and thermal pacing already exist.
- **M6 V-JEPA 2.** Vision encoder and predictor over frames. Needs a
  calibrated energy table companion for the planner barrier. Actuation stays
  out of scope, as phase one specifies.

Architecture details for RWKV-7, LLaDA, EAGLE-3 and V-JEPA 2 above are from
general knowledge and must be confirmed against the published checkpoints
during each milestone's first day.

### Track C: `L1` custody

- Run the real helper and custody service together in the local deployment.
- One positive Touch ID ceremony bound to a real intent, then cancel, timeout,
  occlusion and lock cases.
- Bind the ceremony to a model action that requires it, so M7 exercises it.
- Distinct-user installed identity stays a beta gate.

### M7 Alpha qualification

- One run that takes all five models from fetch to receipt under `L1`.
- The refusal matrix for every model.
- Cancellation during real compute withholds output.
- Receipts and a short release note kept in `docs/releases/`, with every
  deferred gate listed as open.

## 5. Acceptance per model

A model counts toward the alpha only when all of these hold:

- [ ] Checkpoint pinned by revision, size and SHA-256; licence recorded.
- [ ] Output comes from the real checkpoint and matches an independent run of
      the same weights within a stated tolerance.
- [ ] The request went through gateway, runner and class gate under `L1`.
- [ ] Receipt names the real backend, architecture and checkpoint digest.
- [ ] Mutated weights, mutated manifest, wrong class, missing companion and
      unsupported format each refuse before output.
- [ ] Cancellation mid-compute releases nothing.
- [ ] Existing reference-engine tests for that class still pass.

## 6. Risks

| Risk                                           | Effect                        | Response                                                                 |
|------------------------------------------------|-------------------------------|--------------------------------------------------------------------------|
| Token seam is larger than estimated            | M1 slips, everything waits    | Do M1 and M2 together; SmolLM2 defines "enough"                          |
| 8B models do not fit or are too slow on CPU    | M4 and M5 stall               | Quantize; allow a smaller published variant; GPU is a beta item          |
| No suitable published EAGLE-3 pair             | M5 blocked                    | Decide the pair in M0; fall back to a smaller base with a documented gap |
| Checkpoint licences restrict use               | A model drops out             | Check in M0 before any engineering                                       |
| Python worker is not acceptable long-term      | Rework after alpha            | Alpha gate makes it explicit; native MLX binding is a beta item          |
| Local deployment hides installed-only faults   | False confidence              | Receipts and the release note state the deployment mode                  |
| Closed graph diverges from the published model | Wrong output that looks right | Golden-output check is mandatory per model                               |

## 7. Decisions taken on 2026-11-16

Agreed by the project owner. Licences and file formats are still to be
confirmed in M0 before anything is pinned.

| Topic             | Alpha                                                                                                                                      | Beta                                                                               | Production                                                                 |
|-------------------|--------------------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------|----------------------------------------------------------------------------|
| EAGLE-3 pair      | Qwen3-0.6B with a published EAGLE-3 draft head (see checkpoint table). Fallback: Qwen3-8B with Red Hat's head                              | Same                                                                               | Same or larger, from an organisation publisher                             |
| RWKV-7            | 0.1B (12 layers, width 768)                                                                                                                | 1.5B                                                                               | 2.9B or as quality requires                                                |
| V-JEPA 2          | ViT-L/16, 300M, 256 resolution, encoder and predictor                                                                                      | ViT-g/16 with the action-conditioned predictor                                     | Same, with an energy table calibrated on real data                         |
| Weight provenance | Pinned by hash; one-time manual conversion to safetensors where the publisher ships pickle                                                 | Reproducible conversion in an isolated converter, signed into the model repository | Reviewed converter and signed provenance chain; no third-party conversions |
| MLX backend       | Native MLX in a separate worker process, after a one-week spike at the start of M1. Fallback: the Python worker, with native moved to beta | Native worker                                                                      | Native worker                                                              |
| Touch ID in M7    | One `A2` session lease at the start, plus one `A3` single-record reveal on SmolLM2 output through the intent sheet                         | Adds the `A4` world-model override                                                 | Full action matrix                                                         |

Notes:

- Ordinary inference is `A1` at `L1` and never prompts, so the five models run
  without Touch ID; the `A3` reveal is what exercises the ceremony.
- The official RWKV-7 files are `.pth` (pickle), which this repository does
  not load. Convert offline and pin the result.
- The worker stays a separate process even when native, so a faulted worker
  can still be killed and its memory released with it.
- The `A4` override is deferred because at `L1` it also needs an identity
  provider sign-in and the alpha world model has no planner.

### Alpha checkpoints (checked 2026-11-17)

Revisions are the Hugging Face repository commit at the time of checking.
File SHA-256 values are pinned when each checkpoint is first fetched.

| Model              | Repository @ revision                                                                      | Licence    | Weight format                                        | Notes                                                                                                                                   |
|--------------------|--------------------------------------------------------------------------------------------|------------|------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------|
| SmolLM2-135M       | `HuggingFaceTB/SmolLM2-135M-Instruct` @ `12fd25f7`                                         | Apache-2.0 | safetensors                                          | Already pinned by file hash in `scripts/fetch-trained-model.py`                                                                         |
| LLaDA-8B           | `GSAI-ML/LLaDA-8B-Instruct` @ `08b83a6f`                                                   | MIT        | safetensors, 6 shards (bf16, about 16 GB)            | Quantize for the 32 GB Mac; the repository's `modeling_llada.py` is not used                                                            |
| RWKV-7 0.1B        | `BlinkDL/rwkv-7-world` @ `2c0ebae3`, file `RWKV-x070-World-0.1B-v2.8-20241210-ctx4096.pth` | Apache-2.0 | `.pth` only (pickle)                                 | Convert offline with a restricted reader that loads tensors without running pickled code                                                |
| EAGLE-3 base       | `Qwen/Qwen3-0.6B` @ `c1899de2`                                                             | Apache-2.0 | safetensors                                          |                                                                                                                                         |
| EAGLE-3 draft head | `GavinLucky/SGLang-EAGLE3-Qwen3-0.6B-SpecForge` @ `5fe9c43a`                               | MIT        | safetensors                                          | One decoder layer, 32,000-token draft vocabulary; trained with SpecForge for `Qwen/Qwen3-0.6B`. Individual publisher: weaker provenance |
| EAGLE-3 fallback   | `RedHatAI/Qwen3-8B-speculator.eagle3` @ `08610ffa` with `Qwen/Qwen3-8B` @ `b968826d`       | Apache-2.0 | safetensors                                          | Organisation publisher; 8B base needs 4-bit                                                                                             |
| V-JEPA 2 ViT-L     | `facebook/vjepa2-vitl-fpc64-256` @ `b3c1679b`                                              | MIT        | safetensors (a `.pth` original also present, unused) |                                                                                                                                         |

Rejected: `Tengyunw/qwen3_8b_eagle3` and `AngelSlim/Qwen3-1.7B_eagle3`
(no declared licence, pickle weights) and
`nm-testing/Llama3_2_1B_speculator.eagle3` (no declared licence).

## 8. M0 progress, 2026-11-16

Done so far, all with reference models. Evidence is under the ignored
`target/` (`baseline-20261116/`, `m0-dev-l1/`, `m0-dev-l2/`, `m0-probe-l1/`).

**What works**

- The command-line tool builds with the development feature, and the five
  daemons start and report healthy under `L1`.
- `enclave-pack` packages a reference model for every class and already
  accepts the phase-one target names with real weights.
- With the two workarounds below, all five reference models were admitted
  through the storage daemon and bound in the runner under `L1`.

**What broke**

| #  | Finding                                                                                                                                                                                    | Effect                                                                                      | Status                                                                                                                                                                                                                                                                                                                                                                |
|----|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| 1  | `daemon start` needs `assets/calibration.corpus` in the working directory, and the repository has none                                                                                     | Development fleet will not start from a clean checkout                                      | Handled by `scripts/l1-alpha-smoke.sh`, which builds the inputs privately                                                                                                                                                                                                                                                                                             |
| 2  | `model admit` hardcodes the target classification `internal_l2` (`ctl.rs`, `model_admit`)                                                                                                  | No model can be admitted at `L1`: "artifact required floor L2 exceeds host profile L1"      | Fixed 2026-11-17: development classification now follows the manifest's minimum profile                                                                                                                                                                                                                                                                               |
| 3  | At `L2`, local admission of a classified model is refused (`AUTHENTICATED_DOWNLOAD_REQUIRED`)                                                                                              | The same command cannot be used for an `L2` comparison                                      | By design as far as read; not an `L1` blocker                                                                                                                                                                                                                                                                                                                         |
| 4  | Bind fetches the calibration corpus through `FetchTarget`, which refuses any target carrying `min_profile`, and the corpus is published with `min_profile`                                 | Bind fails with `MODEL_DESCRIPTOR_REQUIRED` unless the corpus is passed on the command line | Fixed 2026-11-17: the corpus target no longer carries profile keys; its digest stays pinned by the signed host config                                                                                                                                                                                                                                                 |
| 5  | No command drives generation. `turn submit` only compiles a plan                                                                                                                           | Nothing end to end produces model output outside the test suite                             | Fixed 2026-11-17: `mcp-enclave --dev model run`                                                                                                                                                                                                                                                                                                                       |
| 6  | Runner tests: one release-fence unit test fails intermittently, and two `world_bounded_transport` tests fail every time on macOS when the peer closes before the test sets socket timeouts | Suite is not green                                                                          | Fixed 2026-11-17: all three were test-harness races or macOS socket behaviour; runner suite green                                                                                                                                                                                                                                                                     |
| 7  | The development fleet runs custody with simulated hardware                                                                                                                                 | A Touch ID ceremony in this mode is simulated, not the real sheet                           | Track C must add a real-hardware path for the `A3` reveal                                                                                                                                                                                                                                                                                                             |
| 8  | The policy bundle had the same profile keys as finding 4, so the agent runtime silently fell back to its deny-all bootstrap policy at every profile                                        | Every governed declassification was denied (`CEDAR_DENY_DECLASSIFY`)                        | Fixed 2026-11-17; the denial error now names the denying policy ids                                                                                                                                                                                                                                                                                                   |
| 9  | The five-daemon fleet test could never pass on macOS: it put state under `/tmp`, a symlink the daemons rightly refuse                                                                      | The main end-to-end test had been red unnoticed                                             | Fixed 2026-11-17, and the test now runs at `L1`, asserting the `L1` refusals (YubiKey enrollment, compliance rollup)                                                                                                                                                                                                                                                  |
| 10 | `model run` called the runner (UID 701) directly and printed model plaintext; the agent runtime (UID 704) could drive only the SSM class                                                   | Generation skipped the turn lifecycle and the custody boundary                              | Fixed 2026-11-17: 701 accepts `GenerateStructured`, `Think` and `Plan` only from 704 (or the same-UID dev fleet); 704's turn-scoped `ModelGenerateTurn` reads prompts from turn-owned handles and seals output into a managed handle; `model run` runs BeginTurn, generate, FinishTurn and prints a handle receipt. Seeing the text waits for the Track C `A3` reveal |
| 11 | Every tokenizer parse failure reported the reason `{code}`                                                                                                                                 | Tokenizer refusals could not be told apart                                                  | Fixed 2026-11-17                                                                                                                                                                                                                                                                                                                                                      |

**Constraint that needs a decision.** The files that must change
(`ctl.rs`, `service.rs`, `adapter.rs`, the test files) are each hash-pinned in
several hundred traceability and audit records. Real-model work cannot proceed
without changing them.

**Unrelated host finding.** An older installed deployment from 2026-11-06 is
still registered with launchd on the development Mac and is restarting in a
loop (each service has exited with code 1 over two thousand times). It does
not share paths with the development fleet, but it should be unloaded or
uninstalled.

**M0 exit reached on 2026-11-17.** `scripts/l1-alpha-smoke.sh` starts a
fresh `L1` development fleet, admits all five alpha classes, runs one sample
request against each through the real daemons and saves the results and
journals. All five pass with the reference models. Still open from M0: the
licence and format checks for the real checkpoints, re-pinning MLX, and the
unrelated crash-looping older installation on the development Mac.

**M1 spike done on 2026-11-17: native MLX chosen.** `enclave-mlx-worker`
(feature `mlx-native`, system MLX 0.32.4 / mlx-c 0.8.0 from Homebrew) runs the
existing fixed graph with exact results, 0.11 ms per request on the CPU
stream, and passes the existing MLX runtime test through the adapter. The
Python worker remains only as a fallback path; alpha work targets the native
worker.

**M2 reached on 2026-11-17: real SmolLM2 under L1.** The native worker's
closed `llama-v1` graph matches the independent transformers reference
(identical top-10 tokens, logits within 4e-5, identical greedy text). A closed
BPE tokenizer matches the reference tokenizer on every recorded case.
`enclave-pack --hf-llama` builds one `mlx_llama_v1` artifact (tensors, explicit
`lm_head`, config and tokenizer in metadata). In the development fleet the
model is admitted, bound and serves grammar-constrained classification in
about 0.5 s per request. Reproduce with:

```sh
python3 -I scripts/fetch-trained-model.py smollm2   # plus config.json and tokenizer.json at the pinned revision
cargo build -p enclave-model-runnerd --features mlx-native --bin enclave-mlx-worker
cargo build -p mcp-enclave --features simulation
target/debug/enclave-pack --class AR_CAUSAL --hf-llama target/phase4-trained-mlx --model-id smollm2-135m --out-dir target/smollm2-pack
MCPMAC_MLX_WORKER=$PWD/target/debug/enclave-mlx-worker AR_PACKAGE_DIR=target/smollm2-pack scripts/l1-alpha-smoke.sh
```

Changes made on the way: memory ceilings now measure physical footprint, not
RSS, because RSS counts the reclaimable pages of the read-only mapped weights
(333 MB RSS against a 17 MB footprint). Open points from M2: the runner's
footprint after binding is 43 MiB of its 48 MiB ceiling, mostly the tokenizer
tables; generation recomputes the whole context each token (no KV cache) and
runs on the CPU stream; and an automated end-to-end test that needs the
checkpoint is still to be added.

**M3 reached on 2026-11-17: real RWKV-7 0.1B under L1.** The official `.pth`
is converted by `scripts/convert-rwkv7.py` with a restricted unpickler that
maps exactly three globals to inert stubs, so no pickled code runs; torch's
own `weights_only` loader yields bit-identical tensors. The native worker's
closed `rwkv7-v1` graph keeps no state between requests: the runner owns the
recurrent state (2.4 MB per session) in the existing `StateSnapshotDag`
arenas and sends it with each request. Against the independent `rwkv` 0.8.32
reference (`RWKV_x070`, CPU fp32) every tokenizer case, the state layout and
both 24-token greedy outputs are identical, and top-10 logits agree within
1.3e-5. In the development fleet RWKV-7 classifies the outage ticket as
`Critical`, with the boundary anchor applied, at a runner footprint of
33 MiB. Reproduce with:

```sh
python3 -I scripts/fetch-trained-model.py rwkv7
# rwkv_vocab_v20230424.txt from rwkv-0.8.32-py3-none-any.whl (sha256 d3f05948...67c1)
python3 -I scripts/convert-rwkv7.py target/rwkv7-0.1b/RWKV-x070-World-0.1B-v2.8-20241210-ctx4096.pth VOCAB target/rwkv7-0.1b/rwkv7-0.1b.safetensors
target/debug/enclave-pack --class RECURRENT_SSM_TTT --weights target/rwkv7-0.1b/rwkv7-0.1b.safetensors --model-id rwkv7-0_1b --anchor-mix-alpha 0.25 --out-dir target/rwkv7-pack
MCPMAC_REQUIRE_RWKV7=1 MCPMAC_MLX_WORKER=$PWD/target/debug/enclave-mlx-worker cargo test -p enclave-model-runnerd --test rwkv7_golden
MCPMAC_MLX_WORKER=$PWD/target/debug/enclave-mlx-worker AR_PACKAGE_DIR=target/smollm2-pack SSM_PACKAGE_DIR=target/rwkv7-pack scripts/l1-alpha-smoke.sh
```

Decisions and findings in M3:

- Token-level recurrent models keep the newest token pending, so the state
  is always the state before that token. The `Ingest -> Generate` anchor
  therefore acts on the state that produces output token #1, as the HiSPA
  design intends. Ingestion is chunked to end exactly at anchor points.
- The anchor strength is a security/utility trade-off. At the zoo default
  `anchor_mix_alpha = 1.0` the boundary anchor resets the session to the
  system state and the model loses the whole prompt (measured on the
  reference: the capital prompt continues with unrelated text). At 0.25,
  with the zoo's 64-token window, answers survive. RWKV-7 is packaged with
  0.25. `h_sys` is the zero state until a system prefix is declared.
- The runner tokenizer was compacted (flat token bytes, id-pair merges):
  SmolLM2's binding footprint fell from 43 MiB to 36.5 MiB.
- Admission refuses below its disk reserve. The volume had 3.8 GiB free;
  rebuildable build caches were removed to continue (18 GiB free after).

**M5 reached on 2026-11-17: real Qwen3-0.6B + EAGLE-3 under L1.** The
worker's closed `eagle3-v1` mode runs the Llama graph generalised to Qwen3
(per-head QK RMSNorm) as target and SpecForge's one-layer EAGLE-3 draft
head, statelessly: VERIFY returns the target's greedy ids for the last
positions plus its captured features, DRAFT returns k chained draft ids.
The runner's speculative gate drafts into an isolated arena, verifies with
one target pass, commits the matching prefix plus the target's own token
and zeroes rejected drafts before release, with the thermal watchdog
bounding the draft width. Output is therefore identical to greedy target
decoding. Against the references (transformers 4.51.3 for the target, the
SpecForge draft forward for the head) the target argmax, greedy text and
draft chain are identical and features agree within 4.6e-5. In the
development fleet the pair classifies the outage ticket as `urgent`, at a
runner footprint of 38.5 MiB. Reproduce with:

```sh
python3 -I scripts/fetch-trained-model.py qwen3 && python3 -I scripts/fetch-trained-model.py eagle3
target/debug/enclave-pack --class SPECULATIVE_OR_RECURRENT_DEPTH --hf-eagle3-target target/qwen3-0.6b --eagle3-head target/eagle3-qwen3-0.6b --model-id qwen3-0_6b-eagle3 --out-dir target/eagle3-pack
MCPMAC_REQUIRE_EAGLE3=1 MCPMAC_MLX_WORKER=$PWD/target/debug/enclave-mlx-worker cargo test -p enclave-model-runnerd --test eagle3_golden
MCPMAC_MLX_WORKER=$PWD/target/debug/enclave-mlx-worker AR_PACKAGE_DIR=target/smollm2-pack SSM_PACKAGE_DIR=target/rwkv7-pack SPEC_PACKAGE_DIR=target/eagle3-pack scripts/l1-alpha-smoke.sh
```

Decisions and findings in M5:

- Capture features: the outputs of target layers 1, 13 and 24 (SpecForge's
  default, SGLang's inputs to layers 2, 14, 25). A control recorded in the
  goldens confirms them on chat text: 1.13 of 3 drafts accepted per round,
  against 0.96 one layer earlier, 0.39 for distant layers, 0 when zeroed.
- The latent-cone probe guards the recurrent-depth loop's continuous
  thought; a token-level pair has no such loop, so it binds without a probe
  and `think()` refuses. A trained probe for EAGLE-3 is a beta item.
- The Qwen3 tokenizer (NFC, Qwen2 split, 151k merges) is admitted as a
  second exact shape and parsed by streaming visitors (peak 85 MB to 36 MB).
- Header metadata must stay small: an 11 MB tokenizer string in the
  safetensors header pushed UID 702 to 64.6 MB in the admission sanitizer.
  It now travels as the U8 tensor `enclave_adapter.tokenizer_json`.
- The RSS watchdog now names the breach in the daemon log; it used to exit
  silently with code 70.
- GB-sized artifacts need explicit bounds: admission commit (600 s), CAS
  resolution and bind (300 s). Admitting the 1.6 GB pair takes about
  2.5 minutes, mostly chunked upload and re-verification.

**M6 reached on 2026-11-17: real V-JEPA 2 ViT-L encoder under L1.** The
worker's closed `vjepa2-v1` mode runs transformers' `VJEPA2Model.encoder`
(Conv3d tubelet patches, 24 pre-LN blocks with the 3-axis rotary attention,
exact-erf GELU, final LayerNorm) and returns the mean-pooled 1024-wide
latent; the predictor is never read. Against transformers 4.53.3 the pooled
latents agree within 5.8e-4 and norms within 0.1% on four synthetic frames.
In the development fleet the world-planner gate masks each frame, resamples
it to 256x256, encodes it with V-JEPA 2 and plans over the real latents
(runner footprint 26.6 MiB). Reproduce with:

```sh
python3 -I scripts/fetch-trained-model.py vjepa2
target/debug/enclave-pack --class JEPA_EBM_WORLD_PLANNER --hf-vjepa2 target/vjepa2-vitl --model-id vjepa2-vitl --out-dir target/vjepa2-pack
MCPMAC_REQUIRE_VJEPA2=1 MCPMAC_MLX_WORKER=$PWD/target/debug/enclave-mlx-worker cargo test -p enclave-model-runnerd --test vjepa2_golden
MCPMAC_MLX_WORKER=... AR_PACKAGE_DIR=target/smollm2-pack SSM_PACKAGE_DIR=target/rwkv7-pack SPEC_PACKAGE_DIR=target/eagle3-pack WORLD_PACKAGE_DIR=target/vjepa2-pack caffeinate -i scripts/l1-alpha-smoke.sh
```

Decisions and findings in M6:

- The pinned checkpoint is the self-supervised video model and has no
  action-conditioned dynamics (that is V-JEPA 2-AC, trained on robot
  end-effector actions). The planner's prediction, EBM cost and safety
  cone are therefore deterministic adapter heads over the real latent
  (`[I | A]` predictor, mean-squared goal distance, fixed cone direction),
  documented as uncalibrated. A trained UI-action head and a calibrated
  conformal energy table are beta work.
- The rotary attention rotates pairs interleaved while repeating its
  frequency table, which MLX's built-in RoPE cannot express; the worker
  uses host cos/sin tables and a fixed pair-swap matrix.
- Lid sleep during a run triggers the designed zeroize: every daemon wipes
  and UID 702 cancels in-flight admissions (`DOWNLOAD_WIPED`). Long smoke
  runs use `caffeinate -i`; a closed lid still sleeps the machine.

Known test debt outside the alpha path, failing identically on the commit
before these changes: 35 `mcp-enclave` unit tests in deployment upgrade and
OIDC session protection, two `f118` audit tests (symlinked `/tmp`), one
broker-deployment test and two owned-WebKit tests.

### M7 progress, 2026-11-17

- Receipts name the real backend, architecture and bound artifact SHA-256
  at every journal site (`stamp_backend`); diffusion still reports
  `cpu_reference` because it is.
- Generation goes only through the agent runtime (finding 10): every run in
  the smoke script now reports route `uid704-turn` and a sealed handle.
- Refusal matrix for the four real-weight models, through the runner's own
  `Bind` request, each followed by a probe that finds no bound model:

| Mutation                                       | SmolLM2                               | RWKV-7              | Qwen3+EAGLE-3       | V-JEPA 2                       |
|------------------------------------------------|---------------------------------------|---------------------|---------------------|--------------------------------|
| One flipped weight byte                        | `ARTIFACT_SHA256_MISMATCH`            | same                | same                | same                           |
| Inline manifest differs from the signed target | `MODEL_MANIFEST_UNSIGNED`             | same                | same                | same                           |
| Wrong class, honestly signed                   | `FRAMEWORK_BACKEND_CLASS_UNSUPPORTED` | same                | same                | same                           |
| Declared eager companion not supplied          | `COMPANIONS_MISSING`                  | same                | same                | same                           |
| Embedded companion removed, re-digested        | `TOKENIZER_MISSING`                   | `TOKENIZER_MISSING` | `TOKENIZER_MISSING` | `TENSOR_MISSING` (safety cone) |
| `gguf` format, honestly signed                 | `ARTIFACT_FORMAT_UNSUPPORTED`         | same                | same                | same                           |

```sh
MCPMAC_REQUIRE_REFUSAL_MATRIX=1 MCPMAC_MLX_WORKER=$PWD/$CARGO_TARGET_DIR/debug/enclave-mlx-worker \
  cargo test -p enclave-model-runnerd --test refusal_matrix
```

  Takes about 90 s; it reads the packages under `target/*-pack`. LLaDA joins
  the matrix with M4.

- Cancellation during real compute withholds output for all four. Each test
  times an uncancelled request, starts it again and sends `Zeroize` a third
  of the way in; the request must still be running at the wipe and must
  fail. AR and SSM token loops now check the cancel flag before every
  forward pass, as speculative decoding already did, so a wipe no longer
  waits for the whole generation (SmolLM2 previously ran its full 4.3 s, now
  stops within one token); their partial output is wiped. A V-JEPA 2 plan is
  one indivisible ~0.55 s step that the release fence withholds.

| Model         | Request                    | Wipe at | Request ends | Refusal                |
|---------------|----------------------------|---------|--------------|------------------------|
| SmolLM2       | structured, 2 KB prompt    | 1.43 s  | 1.46 s       | `GENERATION_CANCELLED` |
| RWKV-7        | 128-byte SSM generation    | 1.00 s  | 1.01 s       | `GENERATION_CANCELLED` |
| Qwen3+EAGLE-3 | 96-byte speculative decode | 1.23 s  | 1.31 s       | `GENERATION_CANCELLED` |
| V-JEPA 2      | one 16-candidate plan      | 0.18 s  | 0.55 s       | `MODEL_RELEASE_FENCED` |

```sh
MCPMAC_REQUIRE_CANCELLATION=1 MCPMAC_MLX_WORKER=$PWD/$CARGO_TARGET_DIR/debug/enclave-mlx-worker \
  cargo test -p enclave-model-runnerd --test cancellation -- --test-threads=1
```

  Still open: a turn-scoped cancel in UID 704 waits on the runtime's session
  gate, so cancelling through the agent runtime is not yet prompt; and a
  plan cannot be interrupted between its two frame encodes.

### M4 day one, 2026-11-18

- Pinned `GSAI-ML/LLaDA-8B-Instruct` @ `08b83a6feb34df1a6011b80c3c00c7563e963b07`
  (MIT): six bf16 shards, 16,037,450,386 bytes, each by size and SHA-256
  from the hub's LFS records, plus `config.json`, `tokenizer.json`,
  `tokenizer_config.json`, `special_tokens_map.json`,
  `generation_config.json` and the shard index, each checked against its
  git blob id before pinning. `fetch-trained-model.py` now fetches shards
  and scales its download deadline with file size (2 MiB/s floor).
  `modeling_llada.py` and `configuration_llada.py` are not fetched.
- The config confirms the planned shape: Llama-style blocks (RMSNorm,
  SwiGLU `ff_proj`/`up_proj`/`ff_out`, RoPE θ = 500,000), d_model 4096,
  32 layers, 32 heads with no grouped KV, 126,464-token vocabulary, mask
  token 126336, no causal mask and no KV cache (`use_cache: false`).
- Two things the current diffusion gate cannot do yet:
  1. It is byte-level: `DiffusionBackend::logits` returns `[f32; 256]` per
     position, and the DINGO trellis that keeps every parallel commit
     satisfiable is over byte positions. LLaDA commits whole tokens of
     varying byte length, so the trellis needs a token-level form: a
     (position, DFA state) lattice where each token advances the DFA by its
     byte string, with the allowed set per position computed over the
     vocabulary. The AR path's `walk` already does the per-token step.
  2. `denoise` fails any generation that runs past 2 s
     (`GENERATION_DEADLINE`, from DEFECT-F-139, sized for the byte-level
     reference). One forward pass of an 8B model on this Mac is a large
     share of that, and diffusion needs several. **Decision needed:** keep a
     hard bound but derive it per model (for example a signed manifest field
     with a profile ceiling), or keep 2 s and accept that LLaDA cannot run.
- Planned conversion: 4-bit MLX affine quantization (group 64) of the
  linear weights, embedding and output head kept 8-bit or bf16 by measured
  error, packaged with the tokenizer as `mlx_llada_v1`. The golden check
  needs an independent reference, and the checkpoint's own
  `modeling_llada.py` is excluded, so the reference is a short NumPy/PyTorch
  forward written from the config, compared on bf16 weights.

### M4 outcome, 2026-11-18

Both gaps from day one are closed, and LLaDA-8B runs on real weights.

- **Deadline, decided:** per model, signed, capped by profile.
  `output_caps.diffusion_deadline_ms` (1 to 20,000, diffusion only;
  default 2,000) is refused at bind above the profile ceiling: L1 20 s,
  L2 10 s, L3 5 s. It is refused, never clamped. The 20 s maximum stays
  under the 30 s IPC timeout of the runtime waiting on the runner, so no
  caller abandons a generation that still holds the runner (F-139).
- **Token-level gate:** the DINGO trellis runs over a token lattice
  (DFA states x vocabulary, built by walking a byte trie of the vocabulary
  along DFA transitions; 44 ms per model, under 0.1 ms per request at
  LLaDA's 126k tokens). Token denoising keeps every byte-path safeguard:
  arena wiped on every exit, RAEC watchers, final DFA and output guard,
  and a refusal before compute when the block cannot hold any document.
- **Package:** `enclave-pack --hf-llada` streams the six shards into a
  5.52 GB `mlx_llada_v1` artifact in 55 s (peak 19 GB RAM). The block
  linears are 4-bit and the head 8-bit, in MLX affine layout (group 64,
  BF16 scales and biases). The embedding and norms stay BF16. OLMo tensor
  names are mapped to Llama names, and the artifact carries
  `is_causal=false`, so the topology says diffusion.
- **Worker:** a closed `llada-v1` mode runs on the Metal GPU stream with
  `quantized_matmul` and unmasked attention, and returns logits only for
  the block. Load takes 6 s; a warm forward pass over 33 tokens takes about
  460 ms on this M1 Pro (32 GiB).
- **Golden check:** this is a semantic probe rather than a NumPy forward. A
  full f32 reference of an 8B model does not fit this machine. The packaged
  model must unmask "Paris" for the capital of France. Swapping the gate
  and up projections turns the answer into noise, so the probe checks the
  converter's tensor roles without any publisher code.
- **End to end in the runner:** an outage ticket fills the priority schema
  with `{"priority":"critical"}` in 8.0 s (16 steps, 16 token positions).
  The refusal matrix holds all six refusals for LLaDA. A wipe at 2.7 s of
  an 8.1 s generation stops it at 3.1 s with `GENERATION_CANCELLED`. With
  streamed rows the same ticket takes 5.9 s, and the wipe stops it at
  2.2 s. The
  shared 500-token cancellation prompt overruns the signed 20 s deadline
  and is refused with `GENERATION_DEADLINE`, as designed.
- **Fleet:** the first fleet runs shut UID 701 down with
  `RSS_CEILING_BREACHED` (48 MiB physical footprint), something in-process
  tests never enforce. There were two causes, both fixed:
  - Full-block logits (32 positions x 126k x 4 B, received and decoded)
    are now streamed row by row, each row reduced to at most 4,096
    permitted candidates (05b41708). The vocabulary trie is laid out flat,
    about 3 MB instead of 28 MB (2cecf75d).
  - Bind no longer stacks on the previous model's heap (a2395e13). The
    header is parsed once, metadata strings are moved rather than copied,
    the tokenizer JSON is freed once parsed, and freed allocator pages are
    returned on bind and unbind.

  `tests/llada_footprint.rs`, running SmolLM2 and then LLaDA in its own
  process, measures 18.7 MiB bound, a 42.0 MiB bind peak and 20.7 MiB
  during generation. In a fleet run with SmolLM2 then LLaDA, both pass:
  701 peaks at 45.0 MB and settles at 27 MB, so the bind peak is the
  margin to watch. The fleet run also needs about 6 GB of free disk for
  the CAS copy (702 keeps a 4 GiB reserve plus staging), and the Mac must
  stay awake (`caffeinate`), because system sleep wipes in-flight
  downloads by design.
- **Limits:**
  - With reference weights, the SSM and speculative classes now fail in
    the smoke run (`SSM_OUTPUT_NOT_TEXT`, `MODEL_OUTPUT_NOT_TEXT`): 704
    seals only UTF-8 model output, and those reference models emit raw
    bytes. Real-weight runs pass.
  - LLaDA cannot meet the L3 ceiling (5 s) at this block size on this Mac.
    At L2 (10 s) it has little headroom.
  - Every step recomputes the full sequence (no cache); prompt length
    drives cost.
  - Bind of the debug runner takes about 20 s, mostly hashing 5.5 GB.

### Track C progress, 2026-11-18

The source work is done and tested in software. The physical run waits for
the user at the console. Decisions (user, 2026-11-18):

- **Trust path:** dev-only same-UID trust, with **builder-generated,
  root-owned cdhash pins** (one `sudo`). No Apple Developer account; the
  person who builds owns the trust root.
- **Reveal:** the plaintext appears **only in the helper's secure sheet**.
- **Signing:** ad-hoc with Hardened Runtime (FS-706 Mode A). Developer
  ID / Team ID remains the beta gate.

Gaps found and closed:

1. **No `L1` biometric enrollment existed**, so a real `L1` ceremony
   checked Touch ID against the SEP epoch key and could never pass. Now
   `vault enroll-biometric`: one Touch ID, the helper creates the key,
   custody verifies and seals it.
2. **`A2` intents were refused at the custody service**, so the FS-703
   15-minute lease was unreachable. They are accepted now; each approval
   keeps a <= 10 s dispatch window, and lease hits don't count against the
   prompt rate limit.
3. **There was no reveal.** Now custody `RevealRecord` and 704
   `RevealTurnHandle`: own handles only, `C4` refused, the plaintext only on
   the trusted display.

Shipped:

- **Commits:** `d0924705` (custody, 704, CLI) and `2e869c4e` (helper dev
  trust path, `scripts/pin-local-build.sh`, `scripts/track-c-ceremony.sh`,
  packaging guard).
- **Tests (all pass):** custody 26, 704 7. The pre-existing failures are
  unchanged: 35 in the `mcp-enclave` lib (OIDC and target upgrade) and 6 in
  the custody lib, all failing on the base commit too.
- **Docs:** FS-703 Rev 2.2, FS-704 Rev 1.8, FS-706 Rev 2.6, ADR-022,
  threat model 3.4.0 (T-C1–T-C7), AP-02, the runbook
  [TRACK_C_LOCAL_CEREMONY.md](TRACK_C_LOCAL_CEREMONY.md), the quickstart
  addendum and CONTRIBUTING.

Still open in Track C:

- **The physical run** (three Touch IDs: enroll, lease, reveal). Its
  receipts go into AP-02 and the release note.
- **Routing `A2` tool calls through the lease.** The alpha lock has no
  `A2` tool.
- **The full AP-02 negative/interleaving matrix**, and installed
  distinct-UID acceptance (beta).

## 9. Next step

The alpha is qualified. The supervised Track C ceremony passed on real
Touch ID and SEP custody on 2026-11-18
(receipts). M7 passed
on 2026-11-19 from a clean worktree of `55b1009d`: all five models from
pinned checkpoint to receipt, 269 runner tests and 18 Track C tests, and a
5/5 smoke (receipts,
release note). Next are the beta gates listed in
the release note. Still open from the alpha: batched syncs in CAS admission
(LLaDA admits in about 12 minutes), a KV cache for
the AR path, the tokenizer-as-tensor layout for `mlx_llama_v1`, trained
heads for the speculative probe and the world planner, and a prompt cache
for diffusion steps.
