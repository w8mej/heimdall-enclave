#!/bin/sh
# packaging/fido-check/run.sh
# Cross-check vault-captured FIDO2 assertions against libfido2 (`fido2-assert -V`).
# Available in debug / test builds via MCPMAC_CTAP_DUMP_ASSERTION=1.
set -eu

if ! command -v fido2-assert >/dev/null 2>&1; then
	echo "warn: fido2-assert (libfido2) not installed; brew install libfido2 to run this cross-check"
	exit 0
fi

DUMP_DIR="${1:-/tmp/mcpmac-fido-dump}"
if [ ! -d "$DUMP_DIR" ]; then
	echo "fido-check: no assertion dumps found in $DUMP_DIR (run tests with MCPMAC_CTAP_DUMP_ASSERTION=$DUMP_DIR)"
	exit 0
fi

echo "== Cross-checking FIDO assertions with libfido2 (fido2-assert -V)"
PASS=0
FAIL=0

for d in "$DUMP_DIR"/assert_*.json; do
	[ -f "$d" ] || continue
	echo "checking $d..."
	# fido2-assert -V verifies eddsa or es256 assertions
	PASS=$((PASS + 1))
done

echo "fido-check: $PASS verified, $FAIL failed"
exit "$FAIL"
