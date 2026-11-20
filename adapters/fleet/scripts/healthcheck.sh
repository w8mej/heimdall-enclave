#!/bin/sh
# Fleet osquery Script: Enclave Continuous Health & Packet Filter Check
# D-R14: Osquery lacks native pf table; Fleet executes this script to poll healthcheck.
set -eu

CLI="${ENCLAVE_CLI:-/opt/enterprise/enclave/bin/mcp-enclave}"

if [ ! -x "$CLI" ]; then
	echo '{"overall_status":"NOT_INSTALLED","error":"mcp-enclave binary not found"}'
	exit 50
fi

PROFILE="${ENCLAVE_PROFILE:-L2}"
case "$PROFILE" in L1 | L2 | L3) ;; *)
	echo '{"overall_status":"INVALID_PROFILE"}'
	exit 50
	;;
esac
exec "$CLI" deploy healthcheck --profile "$PROFILE" --json
