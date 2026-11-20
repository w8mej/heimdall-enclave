#!/bin/sh
# Use the authenticated daemon/quarantine and canonical pf health observations.
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH
PROFILE=${ENCLAVE_PROFILE-L2}
case "$PROFILE" in
L1 | L2 | L3) ;;
*)
	echo 'Invalid ENCLAVE_PROFILE; expected L1, L2 or L3' >&2
	echo '<result>EXPOSED</result>'
	exit 0
	;;
esac
CLI=/opt/enterprise/enclave/bin/depot-enclave
[ -x "$CLI" ] || {
	echo '<result>NOT_INSTALLED</result>'
	exit 0
}
CODE=0
JSON=$("$CLI" deploy healthcheck --profile "$PROFILE" --json 2>/dev/null) || CODE=$?
STATUS=$(printf '%s' "$JSON" | /usr/bin/plutil -extract details.overall_status raw -o - - 2>/dev/null) || STATUS=unknown
ISOLATED=$(printf '%s' "$JSON" | /usr/bin/plutil -extract details.pf_isolated raw -o - - 2>/dev/null) || ISOLATED=false
case "$STATUS:$ISOLATED:$CODE" in
quarantined:*) RESULT=QUARANTINED ;;
healthy:true:0) RESULT=ISOLATED ;;
*) RESULT=EXPOSED ;;
esac
printf '<result>%s</result>\n' "$RESULT"
