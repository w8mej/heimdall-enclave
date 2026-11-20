#!/usr/bin/env bash
# ==============================================================================
# MCPMac Verification Suite (verify-enclave.sh) — remediates F-007 / F-031
#
# Usage:
#   ./scripts/verify-enclave.sh                 # hardware mode (physical Apple Silicon Mac)
#   ./scripts/verify-enclave.sh --ci-vm         # VM/CI mode: [HW] checks SKIPPED and reported
#   ./scripts/verify-enclave.sh --repair-keychain   # hardware mode: reset stale DPoP keychain item first
#   ./scripts/verify-enclave.sh --only V11      # run a single check
#   ./scripts/verify-enclave.sh --list
#   ./scripts/verify-enclave.sh --no-native     # skip the native Rust workspace step
#   ./scripts/verify-enclave.sh --only NATIVE   # run only `cargo test --all`
#
# Every check lives in tests/checks.py and performs semantic or negative abuse testing:
# pf rule-order evaluation + mutation test (+ pfctl -vnf when permitted), opa check/test +
# Python/Rego parity, Envoy admin socket check (+ envoy --mode validate when present),
# codesign tamper rejection, DPoP signature/replay/htm/htu rejection, SQL AST bypass tests,
# SQLite authorizer, DLP leak tests, v2.0 simulation redaction, audit hash-chain tamper
# detection, ADR-007 Level-4 custody, JSON Schema validation, corpus truth-in-claims lint,
# break-glass guards, RSS arithmetic and spec-header lint.
#
# After the Python checks, the NATIVE step runs `cargo test --all --locked` over the Rust
# workspace (crates/: the five UID 701–705 daemons, enclave-core/-crypto and the mcp-enclave
# CLI, including the five-daemon UDS mesh + RSS budget test). It is SKIPPED (not passed)
# when cargo is not installed.
#
# The summary reports PASS / SKIP / FAIL out of the TOTAL actually executed. Skips are never
# counted as passes. Exit status is 1 if any check fails.
# ==============================================================================
set -uo pipefail

CI_VM=0
REPAIR=0
ONLY=""
NATIVE=1
while [ $# -gt 0 ]; do
	case "$1" in
	--ci-vm)
		CI_VM=1
		shift
		;;
	--repair-keychain)
		REPAIR=1
		shift
		;;
	--no-native)
		NATIVE=0
		shift
		;;
	--only)
		ONLY="${2:?--only requires a check id}"
		shift 2
		;;
	--list)
		cd "$(dirname "$0")/.." && python3 tests/checks.py list
		exit 0
		;;
	-h | --help)
		sed -n '2,22p' "$0"
		exit 0
		;;
	*)
		echo "Unknown argument: $1" >&2
		exit 2
		;;
	esac
done

cd "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)" || exit 1
export PATH="$PATH:$HOME/tools"
export MCPMAC_AUDIT_LOG="${MCPMAC_AUDIT_LOG:-$(mktemp -d "${TMPDIR:-/tmp}/mcpmac-verify.XXXXXX")/audit.jsonl}"

BOLD="\033[1m"
GREEN="\033[32m"
RED="\033[31m"
YELLOW="\033[33m"
RESET="\033[0m"
MODE_FLAG=""
[ $CI_VM -eq 1 ] && MODE_FLAG="--ci-vm"

echo -e "${BOLD}================================================================="
echo " MCPMac Verification Suite — $([ $CI_VM -eq 1 ] && echo 'CI-VM mode ([HW] checks skipped)' || echo 'HARDWARE mode')"
echo " Scope: v1.0/v2.0 Python simulations, policies, configs, schemas, spec corpus, and the"
echo " v3.0 Rust workspace (UIDs 701–705 with simulated SEP / CoreAuthUI / YubiKey providers)."
echo " Not evidence of compliance."
echo -e "=================================================================${RESET}"

if [ $REPAIR -eq 1 ]; then
	if [ $CI_VM -eq 1 ] || [ "$(uname -s)" != "Darwin" ]; then
		echo -e " ${YELLOW}[SKIP]${RESET} --repair-keychain: requires hardware mode on macOS"
	else
		echo " [....] --repair-keychain: deleting stale 'enterprise.enclave.dpop.key' keychain item (if any)"
		security delete-generic-password -l "enterprise.enclave.dpop.key" >/dev/null 2>&1 || true
		python3 examples/executive-poc/identity/macos_attestation.py || echo -e " ${YELLOW}[WARN]${RESET} attestation still NON-COMPLIANT after repair"
	fi
fi

PASS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0
TOTAL_COUNT=0
FAILED_IDS=()
IDS=$(python3 tests/checks.py list | cut -f1)
[ -n "$ONLY" ] && IDS="$ONLY"
[ "$ONLY" = "NATIVE" ] && IDS=""
[ -n "$ONLY" ] && [ "$ONLY" != "NATIVE" ] && NATIVE=0

for id in $IDS; do
	title=$(python3 tests/checks.py list | awk -F'\t' -v id="$id" '$1==id{print $2}')
	start=$(python3 -c 'import time;print(int(time.time()*1000))')
	out=$(python3 tests/checks.py "$id" $MODE_FLAG 2>&1)
	rc=$?
	ms=$(($(python3 -c 'import time;print(int(time.time()*1000))') - start))
	TOTAL_COUNT=$((TOTAL_COUNT + 1))
	if [ $rc -eq 0 ]; then
		PASS_COUNT=$((PASS_COUNT + 1))
		echo -e " ${GREEN}[PASS]${RESET} $id: $title (${ms}ms)"
	elif [ $rc -eq 77 ]; then
		SKIP_COUNT=$((SKIP_COUNT + 1))
		echo -e " ${YELLOW}[SKIP]${RESET} $id: $title — $(echo "$out" | grep '^SKIP:' | sed 's/^SKIP: //')"
	else
		FAIL_COUNT=$((FAIL_COUNT + 1))
		FAILED_IDS+=("$id")
		echo -e " ${RED}[FAIL]${RESET} $id: $title"
		echo "$out" | grep -v '^{"boot_epoch_id"' | tail -15 | sed 's/^/        /'
	fi
done

if [ $NATIVE -eq 1 ]; then
	title="Native Rust workspace: cargo test --all --locked (UIDs 701–705, CLI, UDS mesh, RSS budget)"
	TOTAL_COUNT=$((TOTAL_COUNT + 1))
	if ! command -v cargo >/dev/null 2>&1 || [ ! -f Cargo.toml ]; then
		SKIP_COUNT=$((SKIP_COUNT + 1))
		echo -e " ${YELLOW}[SKIP]${RESET} NATIVE: $title — cargo not installed"
	else
		start=$(python3 -c 'import time;print(int(time.time()*1000))')
		out=$(cargo test --all --locked 2>&1)
		rc=$?
		ms=$(($(python3 -c 'import time;print(int(time.time()*1000))') - start))
		passed=$(printf '%s\n' "$out" | python3 -c "import re,sys;print(sum(int(m) for m in re.findall(r'^test result: ok\. (\d+) passed', sys.stdin.read(), re.M)))")
		if [ $rc -eq 0 ]; then
			PASS_COUNT=$((PASS_COUNT + 1))
			echo -e " ${GREEN}[PASS]${RESET} NATIVE: $title — ${passed} tests (${ms}ms)"
		else
			FAIL_COUNT=$((FAIL_COUNT + 1))
			FAILED_IDS+=("NATIVE")
			echo -e " ${RED}[FAIL]${RESET} NATIVE: $title"
			echo "$out" | grep -E '^(error|test .* FAILED|---- |thread .* panicked)' | tail -20 | sed 's/^/        /'
		fi
	fi
fi

echo -e "\n${BOLD}================================================================="
echo " Verification Summary"
echo -e "=================================================================${RESET}"
echo " Executed: $TOTAL_COUNT   Passed: $PASS_COUNT   Skipped: $SKIP_COUNT   Failed: $FAIL_COUNT"
if [ $FAIL_COUNT -eq 0 ]; then
	echo -e "\n${GREEN}${BOLD}✔ $PASS_COUNT/$TOTAL_COUNT CHECKS PASSED${RESET}$([ $SKIP_COUNT -gt 0 ] && echo " ($SKIP_COUNT skipped — not counted as passed)")"
	exit 0
else
	echo -e "\n${RED}${BOLD}✖ $FAIL_COUNT/$TOTAL_COUNT CHECKS FAILED: ${FAILED_IDS[*]}${RESET}"
	exit 1
fi
