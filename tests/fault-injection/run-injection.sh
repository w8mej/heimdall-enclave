#!/bin/sh
# FS-705 §5.3.5 / GAP-12 fault-injection matrix test script.
# Run on macOS as root with depot_HW=1.
set -eu

cd "$(dirname "$0")/../.."
[ "$(uname -s)" = Darwin ] || {
	echo "run-injection.sh: run on macOS"
	exit 1
}

CRASHER_BIN=".enclave-local/crasher/crasher"
mkdir -p ".enclave-local/crasher"

echo "== 1. Building test crasher binary"
clang -Wall -Wextra -O2 packaging/crasher/crasher.c -o "$CRASHER_BIN"
codesign --force --sign - --options runtime --identifier com.enterprise.enclave.crasher "$CRASHER_BIN"

echo "== 2. Running null-dereference test (classified as Segv under 0x10000)"
"$CRASHER_BIN" null || true

echo "== 3. Running illegal-instruction test (classified as Redzone)"
"$CRASHER_BIN" illegal || true

echo "== 4. Running PAC corruption test (classified as Pac)"
"$CRASHER_BIN" pac || true

echo "== 5. Checking NVRAM enclave-hiq status"
if [ "$(id -u)" -eq 0 ]; then
	nvram -p | grep "enclave-hiq" || echo "enclave-hiq not yet set in NVRAM"
else
	echo "note: read NVRAM with sudo: sudo nvram -p | grep enclave-hiq"
fi

echo "== 6. Completed fault injection test run"
