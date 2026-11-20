# Standalone Touch ID diagnostic

This app links the actual production `enclaveintent` sheet with a small diagnostic entry point. `--signature-self-test` verifies public P-256 signature fixtures without showing UI or creating a private key. The separately invoked `--touch` path requests fresh biometric authentication and a signature from a new nonpermanent Secure Enclave key, then verifies the fresh prompt locally. It has no passcode or software-signing fallback.

The reviewed native build has compiled, received a local ad-hoc hardened-runtime signature, passed strict signature verification, and passed the positive and negative public signature fixtures. Physical Touch ID observation is still pending.

## Physical observation on the configured Mac

While present at the unlocked Mac console, run the already prepared one-shot controller:

```sh
/usr/bin/python3 /Users/solidus/Repository/Heimdall-Enclave/target/touchid-diagnostic-rebuild-20261116-attempt1/run-touchid-once.py
```

This launcher was regenerated on 2026-11-16 after the repository moved and the original `target/` outputs were removed. The rebuilt signed executable is byte-identical to the reviewed build (SHA256 `9d0ca6349080f4373bbfd2fefd2aefcc2cac1fe2c4f6cff60a9c04d51c63d788`, CDHash `ee4536b1c7527930d95a8bbb14cb416462a8ff4f`). The launcher itself is new (SHA256 `6302a29f72c4f46f7f8593f6ead412903199979a0bc4ed5a1797d472dfa753fc`): it no longer binds the former MCPMacRunner worker and configuration, and instead takes a repository-local exclusive lock shared with the YubiKey selection launcher.

Read the security intent sheet and touch the sensor when macOS requests it. The original complete ceremony cap is ten seconds. The controller checks the exact signed artifact, the host and the local controller lock, reserves one attempt, and waits at most fifteen seconds before requesting bounded cleanup. It never retries. Framework stderr is discarded; only a bounded, whitelisted result reaches the terminal and output-local receipt. The app independently checks the current console.

Success reports `FRESH_BIOMETRIC_AND_SEP_SIGNATURE_VERIFIED`. Cancellation, occlusion, timeout or controller interruption may leave whether biometric evaluation began unknown. Preserve the receipt and review the outcome before preparing another attempt. Avoid invoking the app's raw `--touch` mode: the controller supplies the outer process timeout and one-attempt reservation.

## Build and public fixtures

Run from the repository root on an Apple Silicon Mac with Xcode. Choose a new absent output directory; the first `mkdir` must succeed before continuing. These commands prepare a local app and run public fixtures only:

```sh
(
set -eu
diagnostic_out="$PWD/target/enclaveintent-diagnostic-local"
mkdir "$diagnostic_out"
mkdir -p "$diagnostic_out/MCPMacTouchIDDiagnostic.app/Contents/MacOS" "$diagnostic_out/module-cache"
cp helpers/enclaveintent-diagnostic/Info.plist "$diagnostic_out/MCPMacTouchIDDiagnostic.app/Contents/Info.plist"
/usr/bin/xcrun --sdk macosx swiftc -O -Xlinker -no_adhoc_codesign \
  -sdk "$(/usr/bin/xcrun --sdk macosx --show-sdk-path)" \
  -target arm64-apple-macos13.0 -module-cache-path "$diagnostic_out/module-cache" \
  helpers/enclaveintent/Sources/enclaveintent/CBOR.swift \
  helpers/enclaveintent/Sources/enclaveintent/IntentSheet.swift \
  helpers/enclaveintent/Sources/enclaveintent/OcclusionDetector.swift \
  helpers/enclaveintent/Sources/enclaveintent/PeerIdentity.swift \
  helpers/enclaveintent/Sources/enclaveintent/DeploymentTarget.swift \
  helpers/enclaveintent/Sources/enclaveintent/DeploymentUpgrade.swift \
  helpers/enclaveintent-diagnostic/main.swift \
  -o "$diagnostic_out/MCPMacTouchIDDiagnostic.app/Contents/MacOS/mcpmac-touchid-diagnostic"
/usr/bin/codesign --sign - --options runtime --timestamp=none \
  --identifier com.enterprise.enclave.touchid-diagnostic "$diagnostic_out/MCPMacTouchIDDiagnostic.app"
/usr/bin/codesign --verify --strict --verbose=1 "$diagnostic_out/MCPMacTouchIDDiagnostic.app"
/usr/bin/codesign -dvvv "$diagnostic_out/MCPMacTouchIDDiagnostic.app"
"$diagnostic_out/MCPMacTouchIDDiagnostic.app/Contents/MacOS/mcpmac-touchid-diagnostic" --signature-self-test
)
```

Expected fixture status: `SOFTWARE_PUBLIC_SIGNATURE_FIXTURES_PASS`. No testing defines or privileged entitlements are used. The reviewed native preparation additionally pins the configured worker, host, tool identities, SDK headers and source hashes, and retains bounded command logs. A rebuild needs a new controller bound to its resulting signed artifact before physical observation.

## Acceptance limits

This diagnostic can establish a standalone production-sheet biometric and SEP-signature observation. Integrated D2, UID703 reciprocal IPC, YubiKey touch/assertion, enrollment, installation, lifecycle bounds and memory erasure remain separate acceptance work. Public keys, signatures, wrapped blobs and biometric contexts are not emitted by the diagnostic. Transient Swift memory erasure and exhaustive descendant cleanup are not established.
