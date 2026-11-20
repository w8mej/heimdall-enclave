#!/usr/bin/env bash
# L1 alpha smoke run (docs/L1_ALPHA_ROADMAP.md, milestone M0 exit).
#
# Starts a fresh development fleet under L1, admits each of the five alpha
# execution classes, runs one sample request against each through the real
# daemons, saves every result plus the daemon audit journals, and stops the
# fleet. Development mode only: same-UID daemons with simulated custody
# hardware. Reference models are used unless a later milestone supplies
# real packaged weights in PACKAGES_DIR.
#
# Usage: scripts/l1-alpha-smoke.sh [OUTPUT_DIR]
#   CARGO_TARGET_DIR  build directory (default: target)
#   depot_ENCLAVE       prebuilt CLI with the `simulation` feature (default: build it)
#   PACKAGES_DIR      directory of <CLASS>/model.{safetensors,manifest.json}
#                     (default: freshly packaged reference models)
#   AR_PACKAGE_DIR    real AR_CAUSAL package (one *.safetensors and one
#                     *.manifest.json from `enclave-pack --hf-llama`); needs
#                     depot_MLX_WORKER naming the native enclave-mlx-worker
#   SSM_PACKAGE_DIR   real RECURRENT_SSM_TTT package (RWKV-7 from
#                     scripts/convert-rwkv7.py, then `enclave-pack --class
#                     RECURRENT_SSM_TTT --anchor-mix-alpha 0.25`); same worker
#   SPEC_PACKAGE_DIR  real SPECULATIVE_OR_RECURRENT_DEPTH package (Qwen3-0.6B
#                     + EAGLE-3 from `enclave-pack --hf-eagle3-target ...
#                     --eagle3-head ...`); same worker
#   DIFF_PACKAGE_DIR  real DISCRETE_DIFFUSION package (LLaDA-8B-Instruct from
#                     `enclave-pack --hf-llada ... --diffusion-deadline-ms
#                     20000`); same worker, Metal GPU required
#   WORLD_PACKAGE_DIR real JEPA_EBM_WORLD_PLANNER package (V-JEPA 2 ViT-L from
#                     `enclave-pack --hf-vjepa2 ...`); same worker

set -euo pipefail
umask 077

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

readonly CLASSES=(AR_CAUSAL DISCRETE_DIFFUSION RECURRENT_SSM_TTT SPECULATIVE_OR_RECURRENT_DEPTH JEPA_EBM_WORLD_PLANNER)
readonly PROMPT="hello"
# Chat-formatted classification request for a real AR checkpoint.
readonly AR_PROMPT='<|im_start|>system
Classify the support ticket priority as routine, important, urgent or critical. Reply in JSON.<|im_end|>
<|im_start|>user
Production database is down and customers cannot log in.<|im_end|>
<|im_start|>assistant
'
# RWKV World chat format for a real recurrent checkpoint.
readonly SSM_PROMPT='User: Classify the support ticket priority as routine, important, urgent or critical. Reply with one word. Ticket: Production database is down and customers cannot log in.

Assistant:'
# Qwen3 chat format, thinking disabled, for the real speculative pair.
readonly SPEC_PROMPT='<|im_start|>user
Classify the support ticket priority as routine, important, urgent or critical. Reply with one word. Ticket: Production database is down and customers cannot log in.<|im_end|>
<|im_start|>assistant
<think>

</think>

'
# LLaDA chat format for a real diffusion checkpoint (no system turn).
readonly DIFF_PROMPT='<|startoftext|><|start_header_id|>user<|end_header_id|>

Classify the support ticket priority as routine, important, urgent or critical. Reply in JSON. Ticket: Production database is down and customers cannot log in.<|eot_id|><|start_header_id|>assistant<|end_header_id|>

'
readonly GENERATE_BYTES=32

OUT="${1:-$REPO_ROOT/target/l1-alpha-smoke-$(date -u +%Y%m%dT%H%M%SZ)}"
if [ -e "$OUT" ]; then
	echo "[FAIL] output directory already exists: $OUT" >&2
	exit 2
fi
mkdir -p "$OUT/results" "$OUT/inputs/assets" "$OUT/inputs/schemas" "$OUT/inputs/packaging/fido-mds"
OUT="$(cd "$OUT" && pwd -P)"
# Daemon state lives in a short private directory: UNIX socket paths are
# limited to 104 bytes on macOS, and daemons refuse symlinked state paths.
STATE="$(mktemp -d "$(cd /tmp && pwd -P)/l1a.XXXXXX")"

TARGET_DIR="${CARGO_TARGET_DIR:-$REPO_ROOT/target}"
if [ -z "${depot_ENCLAVE:-}" ]; then
	cargo build --offline --locked -p depot-enclave --features simulation >"$OUT/build.log" 2>&1
	depot_ENCLAVE="$TARGET_DIR/debug/depot-enclave"
fi
# Absolute paths: the CLI runs from the private inputs directory.
depot_ENCLAVE="$(cd "$(dirname "$depot_ENCLAVE")" && pwd -P)/$(basename "$depot_ENCLAVE")"
PACK="$(dirname "$depot_ENCLAVE")/enclave-pack"
for tool in "$depot_ENCLAVE" "$PACK"; do
	[ -x "$tool" ] || {
		echo "[FAIL] missing executable: $tool" >&2
		exit 2
	}
done

# Reference packages (and the calibration corpus host input) unless supplied.
PACKAGES="${PACKAGES_DIR:-$OUT/packages}"
if [ -z "${PACKAGES_DIR:-}" ]; then
	for class in "${CLASSES[@]}" DISCRIMINATIVE_RLCD; do
		mkdir -p "$PACKAGES/$class"
		"$PACK" --class "$class" --out-dir "$PACKAGES/$class" >"$PACKAGES/$class/pack.log"
	done
fi
cp "$("$PACK" --class DISCRIMINATIVE_RLCD --out-dir "$OUT/inputs" >/dev/null && ls "$OUT"/inputs/*.calib.jsonl)" \
	"$OUT/inputs/assets/calibration.corpus"
cp schemas/enclave.lock.toml "$OUT/inputs/schemas/"
cp packaging/fido-mds/yubico.json "$OUT/inputs/packaging/fido-mds/"

cli() {
	(cd "$OUT/inputs" && depot_ENCLAVE_EMBEDDED_DAEMONS=1 \
		"$depot_ENCLAVE" --dev --state-dir "$STATE" --profile L1 --json "$@")
}
stop_fleet() {
	cli daemon stop >"$OUT/stop.json" 2>&1 || true
	[ -d "$STATE/log" ] && cp -R "$STATE/log" "$OUT/journals"
	rm -rf "$STATE"
}
trap stop_fleet EXIT

cli daemon start >"$OUT/start.json"
failures=0
for class in "${CLASSES[@]}"; do
	status="PASS"
	manifest="$PACKAGES/$class/model.manifest.json"
	weights="$PACKAGES/$class/model.safetensors"
	prompt="$PROMPT"
	if [ "$class" = AR_CAUSAL ]; then
		# Byte-level reference engines take no prompt; a real checkpoint does.
		prompt=""
		if [ -n "${AR_PACKAGE_DIR:-}" ]; then
			AR_PACKAGE_DIR="$(cd "$AR_PACKAGE_DIR" && pwd -P)"
			manifest="$(ls "$AR_PACKAGE_DIR"/*.manifest.json)"
			weights="$(ls "$AR_PACKAGE_DIR"/*.safetensors)"
			prompt="$AR_PROMPT"
		fi
	fi
	if [ "$class" = DISCRETE_DIFFUSION ]; then
		# Same split as AR: the byte-level reference refuses a prompt.
		prompt=""
		if [ -n "${DIFF_PACKAGE_DIR:-}" ]; then
			DIFF_PACKAGE_DIR="$(cd "$DIFF_PACKAGE_DIR" && pwd -P)"
			manifest="$(ls "$DIFF_PACKAGE_DIR"/*.manifest.json)"
			weights="$(ls "$DIFF_PACKAGE_DIR"/*.safetensors)"
			prompt="$DIFF_PROMPT"
			echo "[INFO] DISCRETE_DIFFUSION (LLaDA-8B, 5.52 GB): UID 702 synchronously fsync-commits each chunk (~12 min on M1 Pro)." >&2
			echo "[INFO] This is expected crash-consistent behavior, not a hang. Omit DIFF_PACKAGE_DIR for the <30s 4-model fast path." >&2
		fi
	fi
	if [ "$class" = RECURRENT_SSM_TTT ] && [ -n "${SSM_PACKAGE_DIR:-}" ]; then
		SSM_PACKAGE_DIR="$(cd "$SSM_PACKAGE_DIR" && pwd -P)"
		manifest="$(ls "$SSM_PACKAGE_DIR"/*.manifest.json)"
		weights="$(ls "$SSM_PACKAGE_DIR"/*.safetensors)"
		prompt="$SSM_PROMPT"
	fi
	if [ "$class" = SPECULATIVE_OR_RECURRENT_DEPTH ] && [ -n "${SPEC_PACKAGE_DIR:-}" ]; then
		SPEC_PACKAGE_DIR="$(cd "$SPEC_PACKAGE_DIR" && pwd -P)"
		manifest="$(ls "$SPEC_PACKAGE_DIR"/*.manifest.json)"
		weights="$(ls "$SPEC_PACKAGE_DIR"/*.safetensors)"
		prompt="$SPEC_PROMPT"
	fi
	if [ "$class" = JEPA_EBM_WORLD_PLANNER ] && [ "${WORLD_PACKAGE_DIR:-}" != "" ]; then
		WORLD_PACKAGE_DIR="$(cd "$WORLD_PACKAGE_DIR" && pwd -P)"
		manifest="$(ls "$WORLD_PACKAGE_DIR"/*.manifest.json)"
		weights="$(ls "$WORLD_PACKAGE_DIR"/*.safetensors)"
	fi
	if ! cli model admit --class "$class" --manifest "$manifest" --weights "$weights" \
		>"$OUT/results/$class.admit.json" 2>&1; then
		status="ADMIT_FAILED"
	elif ! cli model run --class "$class" --prompt "$prompt" --n "$GENERATE_BYTES" \
		>"$OUT/results/$class.run.json" 2>&1; then
		status="RUN_FAILED"
	fi
	# Owned memory while this model is bound (runner budget evidence).
	cli daemon status >"$OUT/results/$class.status.json" 2>&1 || true
	[ "$status" = "PASS" ] || failures=$((failures + 1))
	printf '%-32s %s\n' "$class" "$status" | tee -a "$OUT/summary.txt"
done
cli daemon status >"$OUT/status.json" || true
stop_fleet
trap - EXIT

echo "results: $OUT"
[ "$failures" -eq 0 ] || {
	echo "[FAIL] $failures class(es) failed" >&2
	exit 1
}
echo "[PASS] all ${#CLASSES[@]} classes admitted and ran under L1"
