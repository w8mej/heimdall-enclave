#!/bin/sh
# lightweight_mdm_bootstrap.sh — Async Lightweight MDM Bootstrap (FS-706 / D-R8)
# Designed for execution via Kandji Run Script, SimpleMDM, or generic MDM commands.
# Runs preflight, install and verification, then dispatches async hydration.
# Installation/verification are synchronous; only hydration is detached.
set -eu

CLI="${ENCLAVE_CLI:-/opt/enterprise/enclave/bin/mcp-enclave}"
PROFILE="${1:-L3}"
TARGET="${2:-llada-8b-instruct}"
case "$PROFILE" in L1 | L2 | L3) ;; *)
	echo "lightweight-mdm: invalid profile"
	exit 2
	;;
esac

if [ ! -x "$CLI" ]; then
	echo "lightweight-mdm: mcp-enclave binary not found at $CLI"
	exit 20
fi

# Execute idempotent install
"$CLI" deploy preflight --profile "$PROFILE"
"$CLI" deploy install --profile "$PROFILE"

"$CLI" deploy verify --profile "$PROFILE"

# Detach hydration to LaunchDaemon worker
"$CLI" deploy hydrate --profile "$PROFILE" --target "$TARGET" --async

echo "lightweight-mdm: bootstrap complete; hydration dispatched asynchronously"
exit 0
