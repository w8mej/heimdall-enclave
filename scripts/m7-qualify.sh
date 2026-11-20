#!/usr/bin/env bash
# M7 alpha qualification (docs/L1_ALPHA_ROADMAP.md): one run, fetch ->
# package -> suites -> five-model smoke, from a clean worktree of HEAD.
# Checkpoints are verified offline against their pins (fetch them first with
# scripts/fetch-trained-model.py); everything else is rebuilt and repackaged
# from source into target/m7-<UTC time>. Every model artifact is required:
# a missing one fails instead of skipping.
#
# Usage: RWKV_VOCAB=path/to/rwkv_vocab_v20230424.txt scripts/m7-qualify.sh
#   RWKV_VOCAB  the RWKV World vocabulary from rwkv-0.8.32-py3-none-any.whl
#               (convert-rwkv7.py pins its SHA-256)
# Takes about 40 minutes on an M1 Pro; LLaDA's admission is 12 of them.
set -uo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VOCAB="${RWKV_VOCAB:?set RWKV_VOCAB to rwkv_vocab_v20230424.txt}"
HEAD=$(git -C "$REPO" rev-parse HEAD)
M="$REPO/target/m7-$(date -u +%Y%m%dT%H%M%SZ)"
SRC="$M/src"
T="$M/t"
CT="$M/cargo"
L="$M/logs"
mkdir -p "$T" "$L"
STATUS="$M/status.txt"
note() { printf '%s %s\n' "$(date -u +%H:%M:%S)" "$*" | tee -a "$STATUS"; }
step() { # step <name> <cmd...>: log output, record PASS/FAIL, keep going
	local name="$1"
	shift
	local t0=$SECONDS
	if "$@" >"$L/$name.log" 2>&1; then note "PASS $name ($((SECONDS - t0)) s)"; else note "FAIL $name ($((SECONDS - t0)) s) see logs/$name.log"; fi
}
note "M7 qualification at $HEAD in $M"

git -C "$REPO" worktree add --detach "$SRC" "$HEAD" >"$L/worktree.log" 2>&1 || {
	note "FAIL worktree"
	exit 1
}
if [ -z "$(git -C "$SRC" status --porcelain)" ]; then
	note "PASS clean worktree"
else
	note "FAIL worktree not clean"
fi
ln -s "$T" "$SRC/target"
for d in phase4-trained-mlx qwen3-0.6b eagle3-qwen3-0.6b vjepa2-vitl llada-8b-instruct; do ln -s "$REPO/target/$d" "$T/$d"; done
mkdir -p "$T/rwkv7-0.1b" "$T/reports"
ln -s "$REPO/target/rwkv7-0.1b/RWKV-x070-World-0.1B-v2.8-20241210-ctx4096.pth" "$T/rwkv7-0.1b/"

# 1. Fetch: every checkpoint (and companion file) against its pinned size and SHA-256.
for m in smollm2 rwkv7 qwen3 eagle3 vjepa2 llada; do
	step "fetch-$m" python3 -I "$REPO/scripts/fetch-trained-model.py" "$m" --offline
done

# 2. Build from the clean worktree.
cd "$SRC" || exit 1
export CARGO_TARGET_DIR="$CT"
step build-cli cargo build --locked -p depot-enclave --features simulation --bins
step build-worker cargo build --locked -p enclave-model-runnerd --features mlx-native --bin enclave-mlx-worker
PACK="$CT/debug/enclave-pack"
export depot_MLX_WORKER="$CT/debug/enclave-mlx-worker"

# 3. Convert and package all five with this build.
step convert-rwkv7 python3 -I scripts/convert-rwkv7.py "$T/rwkv7-0.1b/RWKV-x070-World-0.1B-v2.8-20241210-ctx4096.pth" "$VOCAB" "$T/rwkv7-0.1b/rwkv7-0.1b.safetensors"
step pack-smollm2 "$PACK" --class AR_CAUSAL --hf-llama "$T/phase4-trained-mlx" --model-id smollm2-135m --out-dir "$T/smollm2-pack"
step pack-rwkv7 "$PACK" --class RECURRENT_SSM_TTT --weights "$T/rwkv7-0.1b/rwkv7-0.1b.safetensors" --model-id rwkv7-0_1b --anchor-mix-alpha 0.25 --out-dir "$T/rwkv7-pack"
step pack-eagle3 "$PACK" --class SPECULATIVE_OR_RECURRENT_DEPTH --hf-eagle3-target "$T/qwen3-0.6b" --eagle3-head "$T/eagle3-qwen3-0.6b" --model-id qwen3-0_6b-eagle3 --out-dir "$T/eagle3-pack"
step pack-vjepa2 "$PACK" --class JEPA_EBM_WORLD_PLANNER --hf-vjepa2 "$T/vjepa2-vitl" --model-id vjepa2-vitl --out-dir "$T/vjepa2-pack"
step pack-llada "$PACK" --target-model llada-8b --model-id llada-8b-instruct --hf-llada "$T/llada-8b-instruct" --diffusion-deadline-ms 20000 --out-dir "$T/llada-pack"
for p in smollm2 rwkv7 eagle3 vjepa2 llada; do
	for f in "$T/$p-pack"/*.safetensors "$REPO/target/$p-pack"/*.safetensors; do printf '%s  %s\n' "$(shasum -a 256 "$f" | cut -c1-64)" "$f"; done
done >"$M/package-digests.txt" 2>&1

# 4. Suites. Every artifact is required: a missing one fails instead of skipping.
export depot_REQUIRE_SMOLLM2=1 depot_REQUIRE_RWKV7=1 depot_REQUIRE_QWEN3=1 depot_REQUIRE_EAGLE3=1 \
	depot_REQUIRE_VJEPA2=1 depot_REQUIRE_LLADA=1 depot_REQUIRE_MLX=1 \
	depot_REQUIRE_REFUSAL_MATRIX=1 depot_REQUIRE_CANCELLATION=1
step suite-runner cargo test --locked -p enclave-model-runnerd
step suite-custody-track-c cargo test --locked -p enclave-custody-vaultd --features simulation --test reveal_record --test a2_lease --test l1_biometric_enrollment
step suite-custody-display-frame cargo test --locked -p enclave-custody-vaultd --features simulation --lib display_frame
step suite-runtime-track-c cargo test --locked -p enclave-agent-runtime --test track_c_turn
step suite-dev-envelope cargo test --locked -p depot-enclave --features simulation --lib dev_envelope

# 5. One five-model smoke run under L1 on the fresh packages.
step smoke env depot_ENCLAVE="$CT/debug/depot-enclave" \
	AR_PACKAGE_DIR="$T/smollm2-pack" SSM_PACKAGE_DIR="$T/rwkv7-pack" SPEC_PACKAGE_DIR="$T/eagle3-pack" \
	DIFF_PACKAGE_DIR="$T/llada-pack" WORLD_PACKAGE_DIR="$T/vjepa2-pack" \
	scripts/l1-alpha-smoke.sh "$M/smoke"
note "DONE"
