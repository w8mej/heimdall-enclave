#!/bin/sh
# Jamf Pro Deployment Script (FS-706 / D-R15)
# $1: Mount point (passed by Jamf Pro; ignored)
# $2: Computer name (passed by Jamf Pro; ignored)
# $3: Username (passed by Jamf Pro; ignored)
# $4: Model Target Slug (e.g. llada-8b-instruct)
# $5: Deployment Profile Tier (L1 | L2 | L3)
# $6: Action (bootstrap | hydrate | healthcheck | purge)
set -eu

TARGET="${4:-llada-8b-instruct}"
PROFILE="${5:-L3}"
ACTION="${6:-bootstrap}"

CLI="${ENCLAVE_CLI:-/opt/enterprise/enclave/bin/depot-enclave}"

if [ ! -x "$CLI" ]; then
	echo "jamf: depot-enclave binary not found at $CLI"
	exit 20
fi

case "$ACTION" in
bootstrap)
	"$CLI" deploy preflight --profile "$PROFILE"
	"$CLI" deploy install --profile "$PROFILE"
	"$CLI" deploy verify --profile "$PROFILE"
	;;
hydrate)
	"$CLI" deploy hydrate --profile "$PROFILE" --target "$TARGET" --async
	;;
healthcheck)
	"$CLI" deploy healthcheck --profile "$PROFILE"
	;;
purge)
	"$CLI" deploy purge --profile "$PROFILE" --yes
	;;
*)
	echo "Unknown action: $ACTION"
	exit 64
	;;
esac

exit 0
