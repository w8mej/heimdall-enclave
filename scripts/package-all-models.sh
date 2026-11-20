#!/usr/bin/env bash
# Automated packaging helper for Heimdall-Enclave L1 Alpha models.
# Detects downloaded checkpoints in target/ and runs enclave-pack with verified flags.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

PACK="${REPO_ROOT}/target/debug/enclave-pack"
[ -x "$PACK" ] || PACK="${REPO_ROOT}/target/release/enclave-pack"

if [ ! -x "$PACK" ]; then
	echo "[INFO] Compiling enclave-pack..."
	cargo build --locked -p depot-enclave --features simulation --bin enclave-pack
	PACK="${REPO_ROOT}/target/debug/enclave-pack"
fi

echo "================================================================================"
echo "HEIMDALL-ENCLAVE: AUTOMATED MODEL PACKAGING (L1 Alpha)"
echo "Packager binary: $PACK"
echo "================================================================================"

# 1. SmolLM2 (AR_CAUSAL)
if [ -d "target/phase4-trained-mlx" ]; then
	echo "[1/5] Packaging SmolLM2-135M (AR_CAUSAL)..."
	"$PACK" --class AR_CAUSAL --hf-llama target/phase4-trained-mlx --model-id smollm2-135m --out-dir target/smollm2-pack
else
	echo "[SKIP] target/phase4-trained-mlx not found (fetch with: python3 scripts/fetch-trained-model.py smollm2)"
fi

# 2. RWKV-7 (RECURRENT_SSM_TTT)
if [ -f "target/rwkv7-0.1b/RWKV-x070-World-0.1B-v2.8-20241210-ctx4096.pth" ]; then
	VOCAB_PATH="${RWKV_VOCAB:-target/rwkv7-0.1b/rwkv_vocab_v20230424.txt}"
	if [ ! -f "$VOCAB_PATH" ]; then
		echo "[2/5] Fetching pinned RWKV-7 World vocabulary via scripts/get-rwkv-vocab.sh..."
		./scripts/get-rwkv-vocab.sh "$VOCAB_PATH"
	fi
	if [ -f "$VOCAB_PATH" ]; then
		echo "[2/5] Converting and packaging RWKV-7 (RECURRENT_SSM_TTT)..."
		python3 scripts/convert-rwkv7.py target/rwkv7-0.1b/RWKV-x070-World-0.1B-v2.8-20241210-ctx4096.pth "$VOCAB_PATH" target/rwkv7-0.1b/rwkv7-0.1b.safetensors
		"$PACK" --class RECURRENT_SSM_TTT --weights target/rwkv7-0.1b/rwkv7-0.1b.safetensors --model-id rwkv7-0_1b --anchor-mix-alpha 0.25 --out-dir target/rwkv7-pack
	else
		echo "[SKIP] RWKV-7 weights present, but vocabulary missing. Run: ./scripts/get-rwkv-vocab.sh"
	fi
else
	echo "[SKIP] target/rwkv7-0.1b weights not found (fetch with: python3 scripts/fetch-trained-model.py rwkv7 && ./scripts/get-rwkv-vocab.sh)"
fi

# 3. Qwen3 + EAGLE-3 (SPECULATIVE_OR_RECURRENT_DEPTH)
if [ -d "target/qwen3-0.6b" ] && [ -d "target/eagle3-qwen3-0.6b" ]; then
	echo "[3/5] Packaging Qwen3 + EAGLE-3 (SPECULATIVE_OR_RECURRENT_DEPTH)..."
	"$PACK" --class SPECULATIVE_OR_RECURRENT_DEPTH --hf-eagle3-target target/qwen3-0.6b --eagle3-head target/eagle3-qwen3-0.6b --model-id qwen3-0_6b-eagle3 --out-dir target/eagle3-pack
else
	echo "[SKIP] Qwen3/EAGLE-3 targets not found (fetch with: python3 scripts/fetch-trained-model.py qwen3 && python3 scripts/fetch-trained-model.py eagle3)"
fi

# 4. V-JEPA 2 (JEPA_EBM_WORLD_PLANNER)
if [ -d "target/vjepa2-vitl" ]; then
	echo "[4/5] Packaging V-JEPA 2 ViT-L (JEPA_EBM_WORLD_PLANNER)..."
	"$PACK" --class JEPA_EBM_WORLD_PLANNER --hf-vjepa2 target/vjepa2-vitl --model-id vjepa2-vitl --out-dir target/vjepa2-pack
else
	echo "[SKIP] target/vjepa2-vitl not found (fetch with: python3 scripts/fetch-trained-model.py vjepa2)"
fi

# 5. LLaDA-8B (DISCRETE_DIFFUSION on Metal GPU)
if [ -d "target/llada-8b-instruct" ]; then
	echo "[5/5] Packaging LLaDA-8B (DISCRETE_DIFFUSION, 4-bit blocks / 8-bit head)..."
	echo "      Note: Subsequent UID 702 synchronous per-chunk admission of this 5.52 GB package"
	echo "      takes ~12 minutes on M1 Pro (expected crash-consistent behavior; batching is L2 Beta B7)."
	"$PACK" --target-model llada-8b --model-id llada-8b-instruct --hf-llada target/llada-8b-instruct --diffusion-deadline-ms 20000 --out-dir target/llada-pack
else
	echo "[SKIP] target/llada-8b-instruct not found (optional heavy Metal GPU checkpoint; lightweight 4-model suite admits in <30s)"
fi

echo "================================================================================"
echo "Packaging evaluation complete."
echo "================================================================================"
