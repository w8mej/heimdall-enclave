#!/bin/bash
# Root-operated, time-bounded suspension of the product isolation anchor.
# Ticket is an incident reference, not an authenticated remote authorization.
# Usage: sudo break-glass.sh --ticket INC-123 --duration 30s [--reason text]
set -euo pipefail
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH
unset BASH_ENV ENV CDPATH
cd /
umask 077
ANCHOR=com.enterprise.llm.isolation
STATE=/var/run/enclave-break-glass
JOB=/Library/LaunchDaemons/com.enterprise.enclave.break-glass-watchdog.plist
LABEL=com.enterprise.enclave.break-glass-watchdog
TICKET=''
DURATION=''
REASON=unspecified
DRY_RUN=0
while [ "$#" -gt 0 ]; do
	case "$1" in
	--ticket | --duration | --reason)
		[ "$#" -ge 2 ] || {
			echo 'missing option value' >&2
			exit 2
		}
		case "$1" in --ticket) TICKET=$2 ;; --duration) DURATION=$2 ;; --reason) REASON=$2 ;; esac
		shift 2
		;;
	--dry-run)
		DRY_RUN=1
		shift
		;;
	-h | --help)
		echo 'Usage: break-glass.sh --ticket INC-NNN --duration Ns|Nm [--reason text] [--dry-run]'
		exit 0
		;;
	*)
		echo 'unknown argument' >&2
		exit 2
		;;
	esac
done
[[ "$TICKET" =~ ^(INC|SEC)-[0-9]{3,10}$ ]] || {
	echo 'invalid ticket' >&2
	exit 2
}
[[ "$DURATION" =~ ^([0-9]{1,4})([sm])$ ]] || {
	echo 'invalid duration' >&2
	exit 2
}
SECS=$((10#${BASH_REMATCH[1]}))
[ "${BASH_REMATCH[2]}" = s ] || SECS=$((SECS * 60))
[ "$SECS" -ge 1 ] && [ "$SECS" -le 1800 ] || {
	echo 'duration outside 1..1800s' >&2
	exit 2
}
REASON=${REASON:0:256}
if [ "$DRY_RUN" -eq 1 ]; then
	echo "PLAN: snapshot live $ANCHOR; validate; arm independent launchd watchdog for ${SECS}s; system audit; suspend; restore exact snapshot"
	exit 0
fi
[ "$(/usr/bin/uname -s)" = Darwin ] || {
	echo 'NOT RUN: requires macOS pf/launchd' >&2
	exit 69
}
[ "$(/usr/bin/id -u)" -eq 0 ] || {
	echo 'requires root' >&2
	exit 1
}
# Atomic mkdir serializes operators and rejects pre-existing objects/symlinks.
/bin/mkdir -m 0700 "$STATE" || {
	echo 'break-glass state already exists; inspect previous watchdog before retry' >&2
	exit 1
}
ARMED=0 JOB_CREATED=0
retain_recovery() {
	/usr/bin/logger -p auth.alert -t depot-break-glass "$1; recovery files retained" || true
	echo "$1; inspect $JOB and $STATE before retry" >&2
	exit 1
}
cleanup() {
	status=$?
	trap - EXIT INT TERM HUP
	if [ "$ARMED" -eq 1 ]; then
		if ! /sbin/pfctl -a "$ANCHOR" -f "$STATE/rules"; then
			retain_recovery 'RESTORE FAILED; watchdog retained'
		fi
		# Audit failure must not prevent stopping the watchdog after a successful
		# restore. Still report failure to the operator instead of silently passing.
		/usr/bin/logger -p auth.notice -t depot-break-glass "RELOCK ticket=$TICKET" || status=1
		# A failed bootstrap can still have registered a job. Treat bootout failure
		# as uncertain and retain its sole snapshot, even before any successful open.
		/bin/launchctl bootout "system/$LABEL" || retain_recovery 'WATCHDOG STOP FAILED'
		wait_count=0
		while /bin/launchctl print "system/$LABEL" >/dev/null 2>&1; do
			[ "$wait_count" -lt 10 ] || retain_recovery 'WATCHDOG STILL LOADED'
			/bin/sleep 1 || retain_recovery 'WATCHDOG STOP WAIT FAILED'
			wait_count=$((wait_count + 1))
		done
	fi
	[ "$JOB_CREATED" -eq 0 ] || /bin/rm -f "$JOB"
	/bin/rm -rf "$STATE"
	exit "$status"
}
# Do not remove or replace an unrelated existing job.
if [ -e "$JOB" ] || [ -L "$JOB" ]; then
	/bin/rmdir "$STATE"
	echo 'watchdog job already exists' >&2
	exit 1
fi
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM HUP
/sbin/pfctl -a "$ANCHOR" -sr >"$STATE/rules"
[ -s "$STATE/rules" ] || {
	echo 'refusing to suspend an empty/unobserved anchor' >&2
	exit 1
}
/sbin/pfctl -nf "$STATE/rules"
# launchd owns this child; terminal loss or SIGKILL of the operator shell does
# not kill it. It restores the snapshot even if the parent is gone.
cat >"$STATE/watchdog" <<'WATCHDOG'
#!/bin/sh
set -eu
# Mark the first launch atomically before waiting. A crash/restart must relock
# immediately, rather than granting another full suspension interval.
if /bin/mkdir /var/run/enclave-break-glass/started 2>/dev/null; then
  /bin/sleep "$1"
fi
# Retain the snapshot and keep restoring until the operator confirms cleanup.
# This also covers an unusually delayed flush in the parent after the deadline.
while :; do
  if /sbin/pfctl -a com.enterprise.llm.isolation -f /var/run/enclave-break-glass/rules; then
    /usr/bin/logger -p auth.alert -t depot-break-glass 'WATCHDOG RELOCK complete' || true
  else
    /usr/bin/logger -p auth.alert -t depot-break-glass 'WATCHDOG RESTORE FAILED; retrying' || true
  fi
  /bin/sleep 1
done
WATCHDOG
/bin/chmod 0700 "$STATE/watchdog"
# All interpolated values are fixed paths or validated decimal duration.
(
	set -C
	cat >"$JOB" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>$LABEL</string>
<key>ProgramArguments</key><array><string>/bin/sh</string><string>$STATE/watchdog</string><string>$SECS</string></array>
<key>RunAtLoad</key><true/><key>UserName</key><string>root</string>
<key>KeepAlive</key><true/><key>ThrottleInterval</key><integer>1</integer>
<key>StandardErrorPath</key><string>/var/log/enclave-break-glass-watchdog.log</string>
</dict></plist>
PLIST
)
JOB_CREATED=1
/bin/chmod 0600 "$JOB"
ARMED=1
/bin/launchctl bootstrap system "$JOB"
/bin/launchctl print "system/$LABEL" >/dev/null
/usr/bin/logger -p auth.notice -t depot-break-glass "OPEN ticket=$TICKET duration=$SECS reason=$REASON"
/sbin/pfctl -a "$ANCHOR" -F rules
/bin/sleep "$SECS"
