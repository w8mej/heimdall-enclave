#!/bin/sh
# Jamf Pro attribute. Parse real JSON and restrict output to known status values.
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH
PROFILE=${ENCLAVE_PROFILE-L2}
case "$PROFILE" in
L1 | L2 | L3) ;;
*)
	echo 'Invalid ENCLAVE_PROFILE; expected L1, L2 or L3' >&2
	echo '<result>UNKNOWN</result>'
	exit 0
	;;
esac
CLI=/opt/enterprise/enclave/bin/mcp-enclave
if [ ! -x "$CLI" ]; then
	echo '<result>NOT_INSTALLED</result>'
	exit 0
fi
CODE=0
JSON=$("$CLI" deploy healthcheck --profile "$PROFILE" --json 2>/dev/null) || CODE=$?
STATUS=$(printf '%s' "$JSON" | /usr/bin/plutil -extract details.overall_status raw -o - - 2>/dev/null) || STATUS=UNKNOWN
case "$STATUS" in
healthy) [ "$CODE" -eq 0 ] || STATUS=UNKNOWN ;;
unhealthy | quarantined) ;;
*) STATUS=UNKNOWN ;;
esac
printf '<result>%s</result>\n' "$STATUS"
