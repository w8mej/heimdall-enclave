# Track C: the L1 Touch ID ceremony on your own Mac

Status: **development deployment, 2026-11-18.** This runbook takes the `L1`
custody ceremony from source to a real Touch ID on one Apple Silicon Mac. It
is the local-development path. Fleet and installed deployment keep their own
trust root; see "Fleet deployments" below and
[FS-706](FEATURE_MDM_FLEET_DISTRIBUTION.md).

## What you will see

Three Touch ID sheets, each saying what it is for:

| # | Sheet text                                                 | Action                            | What it proves                                                                                      |
|---|------------------------------------------------------------|-----------------------------------|-----------------------------------------------------------------------------------------------------|
| 1 | `[Enrollment] Register this Mac's Touch ID for L1 custody` | one-time `vault enroll-biometric` | Custody now holds a `.biometryCurrentSet` Secure Enclave key that only your enrolled finger can use |
| 2 | `[A2] enclave://session/lease on session (1 rows) …`       | `A2` session lease                | One Touch ID covers `A2` approvals for this session for 15 minutes; screen lock or sleep ends it    |
| 3 | `[A3] enclave://reveal/model-output on turn (1 rows) …`    | `A3` reveal                       | SmolLM2's sealed output is shown in the helper's secure sheet, and only there                       |

Each sheet ends with SAS words, so you can match the sheet to the intent it
approves. The terminal never prints the model output. The receipts carry
only intent digests (`d_jcs`) and the factors proven.

## Who you trust

Nobody's binaries but your own build. There is no Apple Developer account,
no signing identity and no prebuilt artifact:

1. `scripts/pin-local-build.sh` builds the CLI, the custody daemon
   (`enclave-custody-vaultd`) and the **development** Touch ID helper
   (`enclave-intent`, compiled with `-D depot_DEV_SAME_UID`). It copies them
   to `target/track-c/bin` and ad-hoc signs them with fixed identifiers:
   `com.enterprise.enclave.custody` and `com.enterprise.enclave.intent`.
2. It reads each binary's code-directory hash (cdhash) and installs both,
   **root-owned**, in the pin file the production code already trusts:
   `/Library/Application Support/EnterpriseEnclave/codesign-pins.json`.
   That takes one `sudo`. Entries for other identifiers are kept; these two
   are replaced, so an older build stops being trusted.
3. At run time each side checks the other before reading a byte. The
   helper requires custody's identifier and pinned cdhash. Custody requires
   the helper's identifier and pinned cdhash.

Root ownership matters: a process running as you can replace a file in
`target/`, but cannot re-pin it, so a swapped binary is refused.

**Any rebuild changes a cdhash.** Run the pin script again before the next
ceremony.

## Prerequisites

- An Apple Silicon Mac with Touch ID enrolled in System Settings, unlocked,
  with you at the console.
- The SmolLM2 package: `scripts/fetch-trained-model.py smollm2`, then
  `enclave-pack --hf-llama …`, giving `target/smollm2-pack/`.
- The native MLX worker:
  `cargo build -p enclave-model-runnerd --features mlx-native --bin enclave-mlx-worker`.
- About 1 GB of free disk.

## Run it

```sh
scripts/pin-local-build.sh          # builds, signs, pins (asks for sudo once)
scripts/track-c-ceremony.sh         # three Touch ID sheets; receipts in target/track-c-<time>
```

The ceremony script starts an `L1` development fleet with
`depot_ENCLAVE_REAL_CUSTODY=1`. In that fleet:

- custody runs on the real Secure Enclave;
- the helper is started in the fleet's private `run/intent/` directory;
- every other daemon keeps its simulated hardware.

The script then enrolls, admits SmolLM2, and runs
`model run --lease --reveal`. It stops the fleet and copies the journals
on exit.

To try the refusal paths, cancel a sheet, or let it time out. The step
reports `[REFUSED]` with the reason (`TOUCH_ID_CANCELLED`,
`TOUCH_ID_TIMEOUT`, `UI_OCCLUSION_ABORT`), and nothing is shown or leased.

## Tamper checks

Each of these must refuse before any sheet appears:

| Change                                                | Expected                                                         |
|-------------------------------------------------------|------------------------------------------------------------------|
| Rebuild either binary without re-pinning              | The helper or custody refuses the connection (cdhash not pinned) |
| Edit a byte of `target/track-c/bin/enclave-intent`    | Signature invalid; custody refuses the helper                    |
| Re-sign a binary with another identifier              | Identifier mismatch; refused                                     |
| Ship the dev helper in a package                      | `packaging/macos/build.sh` fails: the dev marker is present      |
| Ask to reveal another turn's handle, or a `C4` record | `704` refuses (`REVEAL_C4_REFUSED` for `C4`)                     |

The software side of these checks runs in CI-style tests:

- `crates/enclave-custody-vaultd/tests/{reveal_record,a2_lease,l1_biometric_enrollment}.rs`
- `crates/enclave-agent-runtime/tests/track_c_turn.rs`

## What this is not

- **Not the installed deployment.** Here custody runs as you, not as
  `_piivault` (UID 703) under launchd. The pins stop binary substitution,
  but there is no UID boundary between your other processes and the dev
  fleet. The distinct-UID installed path, Developer ID / Team ID signing and
  TUF-distributed cdhash allowlists are the beta gate.
- **Not a release build.** The development helper exists only with
  `-D depot_DEV_SAME_UID`. Fleet packaging builds the helper without it,
  and refuses one that carries the marker.
- **`A2` tool calls are not yet routed through the lease.** The alpha's
  signed tool lock has no `A2` tool. The lease is taken and recorded, and a
  repeat within 15 minutes needs no prompt.

## Troubleshooting

| Symptom                                                                      | Cause                                                                               |
|------------------------------------------------------------------------------|-------------------------------------------------------------------------------------|
| `REAL_CUSTODY_BINARY_MISSING`                                                | Run from `target/track-c/bin/depot-enclave` (the pin script's copy)                   |
| `INTENT_HELPER_REQUIRED`                                                     | `depot_ENCLAVE_INTENT_HELPER` is unset; the ceremony script sets it                   |
| `CODESIGN_PINS_MISSING` / `CODESIGN_PINS_INSECURE`                           | Pins not installed, or the file is not root-owned; rerun the pin script             |
| `protected current-console socket directory required` in `intent-helper.log` | Not at the unlocked console, or the socket directory is not private (0700, yours)   |
| `BIOMETRIC_ENROLLMENT_INCOMPLETE`                                            | The helper returned no new key; check Touch ID is enrolled in System Settings       |
| `PROMPT_RATE_LIMIT`                                                          | More than three prompts in 60 s; wait a minute                                      |
| `ALREADY_ENROLLED`                                                           | This state directory is enrolled; use a fresh one (the ceremony script always does) |
