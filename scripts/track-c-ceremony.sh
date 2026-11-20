#!/usr/bin/env bash
# Track C: the L1 Touch ID ceremony on real hardware, in the development fleet.
#
# Run at the unlocked Mac console, after scripts/pin-local-build.sh. You will
# be asked for Touch ID three times; each sheet says what it is for:
#   1. "[Enrollment] Register this Mac's Touch ID for L1 custody"  (once per state dir)
#   2. "[A2] enclave://session/lease ..."     the 15-minute session lease
#   3. "[A3] enclave://reveal/model-output ..." the reveal of SmolLM2's sealed output
# After (3) the model output appears in the helper's secure sheet, not in this
# terminal. Cancel any sheet to see the refusal path instead.
#
# Usage: scripts/track-c-ceremony.sh [OUTPUT_DIR]
#   AR_PACKAGE_DIR  real SmolLM2 package (default: target/smollm2-pack)
#   depot_MLX_WORKER  native worker (default: target/debug/enclave-mlx-worker)
#
# Receipts and journals land in OUTPUT_DIR (default target/track-c-<UTC time>).
# No plaintext model output is written there.

set -euo pipefail
umask 077

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"
TARGET_DIR="${CARGO_TARGET_DIR:-$REPO_ROOT/target}"
BIN="$TARGET_DIR/track-c/bin"
PIN_FILE="/Library/Application Support/EnterpriseEnclave/codesign-pins.json"
AR_PACKAGE_DIR="${AR_PACKAGE_DIR:-$TARGET_DIR/smollm2-pack}"
export depot_MLX_WORKER="${depot_MLX_WORKER:-$TARGET_DIR/debug/enclave-mlx-worker}"
readonly PROMPT='<|im_start|>system
Classify the support ticket priority as routine, important, urgent or critical. Reply in JSON.<|im_end|>
<|im_start|>user
Production database is down and customers cannot log in.<|im_end|>
<|im_start|>assistant
'

for f in "$BIN/depot-enclave" "$BIN/enclave-custody-vaultd" "$BIN/enclave-intent" "$BIN/enclave-pack" "$depot_MLX_WORKER"; do
	[ -x "$f" ] || {
		echo "[FAIL] missing $f; run scripts/pin-local-build.sh (and build the MLX worker)" >&2
		exit 2
	}
done
[ -f "$PIN_FILE" ] || {
	echo "[FAIL] no root-owned pins at $PIN_FILE; run scripts/pin-local-build.sh" >&2
	exit 2
}
ls "$AR_PACKAGE_DIR"/*.manifest.json "$AR_PACKAGE_DIR"/*.safetensors >/dev/null ||
	{
		echo "[FAIL] no SmolLM2 package in $AR_PACKAGE_DIR" >&2
		exit 2
	}

OUT="${1:-$TARGET_DIR/track-c-$(date -u +%Y%m%dT%H%M%SZ)}"
[ -e "$OUT" ] && {
	echo "[FAIL] output directory already exists: $OUT" >&2
	exit 2
}
mkdir -p "$OUT/receipts" "$OUT/inputs/assets" "$OUT/inputs/schemas" "$OUT/inputs/packaging/fido-mds"
OUT="$(cd "$OUT" && pwd -P)"
# Short private state path: UNIX socket paths are limited to 104 bytes.
STATE="$(mktemp -d "$(cd /tmp && pwd -P)/tc.XXXXXX")"

cp "$("$BIN/enclave-pack" --class DISCRIMINATIVE_RLCD --out-dir "$OUT/inputs" >/dev/null && ls "$OUT"/inputs/*.calib.jsonl)" \
	"$OUT/inputs/assets/calibration.corpus"
cp schemas/enclave.lock.toml "$OUT/inputs/schemas/"
cp packaging/fido-mds/yubico.json "$OUT/inputs/packaging/fido-mds/"

cli() {
	(cd "$OUT/inputs" && depot_ENCLAVE_REAL_CUSTODY=1 depot_ENCLAVE_INTENT_HELPER="$BIN/enclave-intent" \
		"$BIN/depot-enclave" --dev --state-dir "$STATE" --profile L1 --json "$@")
}
stop_fleet() {
	cli daemon stop >"$OUT/receipts/stop.json" 2>&1 || true
	[ -d "$STATE/log" ] && cp -R "$STATE/log" "$OUT/journals"
	rm -rf "$STATE"
}
trap stop_fleet EXIT

step() { printf '\n== %s\n' "$1"; }
run() { # run <name> <args...>: save the JSON receipt, show its status
	local name="$1"
	shift
	if cli "$@" >"$OUT/receipts/$name.json" 2>&1; then
		echo "[OK] $name"
	else
		echo "[REFUSED] $name: $(tail -1 "$OUT/receipts/$name.json")"
		return 1
	fi
}

step "Start the L1 fleet with real custody (SEP + Touch ID helper)"
run start daemon start
step "Touch ID 1 of 3: register this Mac's Touch ID with custody"
run enroll vault enroll-biometric
step "Admit SmolLM2 (no prompt: ordinary inference is A1)"
run admit model admit --class AR_CAUSAL \
	--manifest "$(ls "$AR_PACKAGE_DIR"/*.manifest.json)" --weights "$(ls "$AR_PACKAGE_DIR"/*.safetensors)"
step "Touch ID 2 and 3: A2 session lease, then A3 reveal of the sealed output"
echo "The output appears in the secure sheet, not here."
run lease-and-reveal model run --class AR_CAUSAL --prompt "$PROMPT" --n 32 --lease --reveal
# The sheet lives only while custody holds its connection (at most 30 s):
# keep the fleet up until the operator has read it.
if [ -t 0 ]; then
	printf 'Read the "Enclave protected values" sheet, then press Return to stop the fleet. '
	read -r _ || true
fi
step "Receipts (no plaintext)"
cat "$OUT/receipts/lease-and-reveal.json"
echo
echo "results: $OUT"
