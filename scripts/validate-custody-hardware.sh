#!/usr/bin/env bash
set -euo pipefail
if [[ $(uname -s) != Darwin ]]; then
	echo 'BLOCKED: actual macOS hardware required; no hardware verification performed' >&2
	exit 77
fi
if [[ ${MCPMAC_HW:-} != 1 ]]; then
	echo 'BLOCKED: set MCPMAC_HW=1 on an authorized disposable hardware test host' >&2
	exit 77
fi
cd "$(dirname "$0")/.."
git rev-parse HEAD
sw_vers
uname -m
rustc --version
# Native build admission: preserve the 4 GiB reserve + 1.5 GiB allowance.
free_bytes=$(df -Pk . | awk 'NR == 2 { printf "%.0f", $4 * 1024 }')
if [[ ! $free_bytes =~ ^[0-9]+$ || $free_bytes -lt 5905580032 ]]; then
	echo "BLOCKED: native build admission requires 5905580032 free bytes; observed ${free_bytes:-unknown}" >&2
	exit 77
fi
case ${1:---diagnostic} in
--diagnostic)
	# This path is structurally separate from tests that create credentials.
	cargo run --locked -p enclave-custody-vaultd --no-default-features --features macos-hid --bin enclave-fido-diagnostic -- --timeout-ms 5000
	exit $?
	;;
--enrollment-begin)
	if [[ ${MCPMAC_HW_OPERATION:-} != enrollment-begin || -z ${MCPMAC_PENDING_OUTPUT:-} ]]; then
		echo 'BLOCKED: MCPMAC_HW_OPERATION=enrollment-begin and absolute MCPMAC_PENDING_OUTPUT required; may create one retained credential after actual Touch ID/UV' >&2
		exit 77
	fi
	cargo run --locked -p mcp-enclave --no-default-features -- --profile "${MCPMAC_PROFILE:-L3}" vault enrollment-begin --pending-output "$MCPMAC_PENDING_OUTPUT"
	exit $?
	;;
--enrollment-activate)
	if [[ ${MCPMAC_HW_OPERATION:-} != enrollment-activate || -z ${MCPMAC_ASSET_RECEIPT:-} ]]; then
		echo 'BLOCKED: MCPMAC_HW_OPERATION=enrollment-activate and absolute private MCPMAC_ASSET_RECEIPT required; actual Touch ID and correct existing-PIN/on-key UV required' >&2
		exit 77
	fi
	cargo run --locked -p mcp-enclave --no-default-features -- --profile "${MCPMAC_PROFILE:-L3}" vault enrollment-activate --receipt "$MCPMAC_ASSET_RECEIPT"
	exit $?
	;;
--enrollment-renew)
	if [[ ${MCPMAC_HW_OPERATION:-} != enrollment-renew || -z ${MCPMAC_ASSET_RECEIPT:-} ]]; then
		echo 'BLOCKED: MCPMAC_HW_OPERATION=enrollment-renew and absolute private MCPMAC_ASSET_RECEIPT required; advances admission generation and requires fresh Touch ID/UV, preserves ciphertexts' >&2
		exit 77
	fi
	cargo run --locked -p mcp-enclave --no-default-features -- --profile "${MCPMAC_PROFILE:-L3}" vault enrollment-renew --receipt "$MCPMAC_ASSET_RECEIPT"
	exit $?
	;;
--enroll-and-assert)
	if [[ ${MCPMAC_HW_OPERATION:-} != enroll-and-assert ]]; then
		echo "BLOCKED: MCPMAC_HW_OPERATION=enroll-and-assert required; creates retained credentials and may advance counters/authentication state" >&2
		exit 77
	fi
	;;
*)
	echo "usage: $0 --diagnostic | --enrollment-begin | --enrollment-activate | --enrollment-renew | --enroll-and-assert" >&2
	exit 64
	;;
esac
echo "EFFECTS: new MCPMac nonresident credential plus UV assertions; preserves existing PINs/credentials/interfaces. No physical negative PIN/reset/delete cases." >&2
cargo test --locked -p enclave-custody-vaultd --features macos-hid --test hw_yubikey -- --ignored --nocapture

if [[ -n ${MCPMAC_EXPECTED_AAGUID:-} ]]; then
	cargo test --locked -p enclave-custody-vaultd --features macos-hid --lib ctap::transport::tests::physical_foreign_before_enrolled_selection -- --ignored --nocapture
fi
