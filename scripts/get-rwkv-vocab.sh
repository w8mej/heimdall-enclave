#!/usr/bin/env bash
# ==============================================================================
# scripts/get-rwkv-vocab.sh — Hash-Pinned RWKV-7 World Vocabulary Fetcher
# ==============================================================================
# Fetches and verifies `rwkv_vocab_v20230424.txt` directly from the immutable
# PyPI `rwkv==0.8.32` wheel without `pip install` or executing any upstream code.
#
# Double-pinned integrity:
#   Wheel SHA-256: d3f0594810a4a7e91569f177003ec22294c3eabc91c5f8d0ff3511702d4b67c1
#   Vocab SHA-256: 8324476023347dec2964625ccb2075c864d250a9c6d9a74f36daba628de8c008
#   Vocab Length:  1,159,262 bytes
#
# Usage:
#   ./scripts/get-rwkv-vocab.sh [--offline] [OUTPUT_PATH]
#
# Default OUTPUT_PATH: target/rwkv7-0.1b/rwkv_vocab_v20230424.txt
# ==============================================================================

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OFFLINE=0
OUT_PATH=""

for arg in "$@"; do
	case "$arg" in
	--offline)
		OFFLINE=1
		;;
	-h | --help)
		sed -n '2,18p' "${BASH_SOURCE[0]}"
		exit 0
		;;
	*)
		if [ -n "$OUT_PATH" ]; then
			echo "[FAIL] unexpected extra argument: $arg" >&2
			exit 2
		fi
		OUT_PATH="$arg"
		;;
	esac
done

OUT_PATH="${OUT_PATH:-${REPO_ROOT}/target/rwkv7-0.1b/rwkv_vocab_v20230424.txt}"

python3 - "$OUT_PATH" "$OFFLINE" <<'PY'
import hashlib
import io
import os
import sys
import urllib.request
import zipfile
from pathlib import Path

WHEEL_URL = (
    "https://files.pythonhosted.org/packages/5b/61/"
    "d7c764f01da87145342a8cdc3a86690e03cda4dfc2cf20377bdf5dc86b05/"
    "rwkv-0.8.32-py3-none-any.whl"
)
WHEEL_SHA256 = "d3f0594810a4a7e91569f177003ec22294c3eabc91c5f8d0ff3511702d4b67c1"
WHEEL_MAX_BYTES = 5 * 1024 * 1024
VOCAB_MEMBER = "rwkv/rwkv_vocab_v20230424.txt"
VOCAB_LEN = 1159262
VOCAB_SHA256 = "8324476023347dec2964625ccb2075c864d250a9c6d9a74f36daba628de8c008"


def verify_file(path: Path) -> None:
    if path.is_symlink() or not path.is_file():
        raise SystemExit(f"[FAIL] refused non-regular or symlink path: {path}")
    data = path.read_bytes()
    if len(data) != VOCAB_LEN:
        raise SystemExit(f"[FAIL] vocab length mismatch: got {len(data)}, expected {VOCAB_LEN}")
    got = hashlib.sha256(data).hexdigest()
    if got != VOCAB_SHA256:
        raise SystemExit(f"[FAIL] vocab SHA-256 mismatch: got {got}, expected {VOCAB_SHA256}")


out = Path(sys.argv[1])
offline = sys.argv[2] == "1"

if out.exists() or out.is_symlink():
    verify_file(out)
    print(f"[PASS] Verified existing RWKV-7 vocab: {out} (sha256={VOCAB_SHA256})")
    sys.exit(0)

if offline:
    raise SystemExit(f"[FAIL] --offline requested and vocab missing at {out}")

print(f"[INFO] Downloading pinned rwkv==0.8.32 wheel (data-only extraction, zero code execution)...")
with urllib.request.urlopen(WHEEL_URL, timeout=45) as resp:
    wheel_bytes = resp.read(WHEEL_MAX_BYTES + 1)

if len(wheel_bytes) > WHEEL_MAX_BYTES:
    raise SystemExit("[FAIL] downloaded wheel exceeds 5 MiB bound")

got_wheel = hashlib.sha256(wheel_bytes).hexdigest()
if got_wheel != WHEEL_SHA256:
    raise SystemExit(f"[FAIL] wheel SHA-256 mismatch: got {got_wheel}, expected {WHEEL_SHA256}")

with zipfile.ZipFile(io.BytesIO(wheel_bytes)) as zf:
    vocab_bytes = zf.read(VOCAB_MEMBER)

if len(vocab_bytes) != VOCAB_LEN:
    raise SystemExit(f"[FAIL] extracted vocab length mismatch: got {len(vocab_bytes)}, expected {VOCAB_LEN}")

got_vocab = hashlib.sha256(vocab_bytes).hexdigest()
if got_vocab != VOCAB_SHA256:
    raise SystemExit(f"[FAIL] extracted vocab SHA-256 mismatch: got {got_vocab}, expected {VOCAB_SHA256}")

out.parent.mkdir(parents=True, exist_ok=True)
tmp = out.with_suffix(".txt.tmp")
if tmp.exists() or tmp.is_symlink():
    tmp.unlink()
tmp.write_bytes(vocab_bytes)
os.replace(tmp, out)
verify_file(out)
print(f"[PASS] Extracted & verified RWKV-7 vocab: {out} ({VOCAB_LEN} bytes, sha256={VOCAB_SHA256})")
PY
