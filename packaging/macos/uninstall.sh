#!/bin/sh
# Undo packaging/macos/install.sh.
#
#   sudo sh packaging/macos/uninstall.sh                     # stop + remove programs
#   sudo sh packaging/macos/uninstall.sh --purge-state       # … and sockets, journals, state
#   sudo sh packaging/macos/uninstall.sh --purge-state --remove-accounts
#
# Default: boot out the supervisor and the five daemons, remove the plists,
# binaries, Seatbelt profiles, EnclaveCustody.app and the cdhash pins. State
# (/var/db/enclave — including UID 703's SEP-wrapped epoch key blob, which no
# other Mac can open), journals (/var/log/enclave) and the CAS store are kept
# unless --purge-state is given. --remove-accounts deletes the accounts and
# groups listed in the installed provision-accounts.sh.
set -eu
# Direct operator entry points must not inherit executable search paths or
# interpreter startup hooks. Embedded CLI calls already start with env_clear.
PATH=/usr/bin:/bin:/usr/sbin:/sbin
LC_ALL=C
export PATH LC_ALL
unset BASH_ENV ENV CDPATH PERL5OPT PERL5LIB PERLLIB PYTHONPATH PYTHONHOME \
	RUBYOPT RUBYLIB DYLD_INSERT_LIBRARIES DYLD_LIBRARY_PATH DYLD_FRAMEWORK_PATH \
	LD_PRELOAD LD_LIBRARY_PATH
PURGE=0
ACCOUNTS=0
for a in "$@"; do
	case "$a" in
	--purge-state) PURGE=1 ;;
	--remove-accounts) ACCOUNTS=1 ;;
	-h | --help)
		sed -n '2,13p' "$0"
		exit 0
		;;
	*)
		echo "uninstall.sh: unknown argument $a"
		exit 2
		;;
	esac
done
[ "$(uname -s)" = Darwin ] || {
	echo "uninstall.sh: run this on macOS"
	exit 1
}
[ "$(id -u)" -eq 0 ] || {
	echo "uninstall.sh: run with sudo"
	exit 1
}

PREFIX=/opt/enterprise/enclave
SUPPORT="/Library/Application Support/EnterpriseEnclave"
LD=/Library/LaunchDaemons
LABELS="com.enterprise.enclave.ifc com.enterprise.enclave.adapter com.enterprise.enclave.cas com.enterprise.enclave.apfs-broker com.enterprise.enclave.custody com.enterprise.enclave.fido com.enterprise.enclave.zk com.enterprise.enclave.supervisor com.enterprise.enclave.browser com.enterprise.enclave.hydrate com.enterprise.enclave.gateway"
BINS="mcp-enclave enclave-model-runnerd enclave-swarm-syncd enclave-apfs-broker enclave-agent-runtime enclave-zk-auditor enclave-fido-emulator enclave-intent enclave-cdp-browser enclave-client-gateway"

# Stop the only broker callers, then refuse before removing any recovery
# program/pin/state if a publication remains or durable state is uncertain.
if [ -d /var/db/enclave/apfs-broker ]; then
	for l in com.enterprise.enclave.hydrate com.enterprise.enclave.cas; do
		if launchctl print "system/$l" >/dev/null 2>&1; then
			launchctl bootout "system/$l" || exit 1
			i=0
			while launchctl print "system/$l" >/dev/null 2>&1 && [ "$i" -lt 60 ]; do
				sleep 0.1
				i=$((i + 1))
			done
			if launchctl print "system/$l" >/dev/null 2>&1; then
				echo 'FAIL: CAS still running; broker retained'
				exit 1
			fi
		fi
	done
	"$PREFIX/bin/enclave-apfs-broker" --quiesce-idle || {
		echo 'FAIL: broker publications/state require explicit safe retraction; broker retained'
		exit 1
	}
fi

CONSOLE_UID=$(stat -f %u /dev/console 2>/dev/null || true)
case "$CONSOLE_UID" in '' | *[!0-9]*)
	echo 'FAIL: cannot identify console domain; payload retained'
	exit 1
	;;
esac
# Enumerate live launchd domains, including directory-backed users that are
# absent from dscl's local node. Unknown output refuses before payload mutation.
DOMAIN_INVENTORY=$(launchctl print system) || {
	echo 'FAIL: cannot enumerate live launchd domains; payload retained' >&2
	exit 1
}
GUI_DOMAIN_UIDS=$(printf '%s\n' "$DOMAIN_INVENTORY" | awk '
  /^[[:space:]]*subdomains = \{[[:space:]]*$/ { if (seen++) bad=1; inside=1; next }
  inside && /^[[:space:]]*\}[[:space:]]*$/ { inside=0; closed=1; next }
  inside {
    line=$0; sub(/^[[:space:]]*/, "", line); sub(/[[:space:]]*$/, "", line)
    if (line == "") next
    # Per-process XPC domains (macOS 26 lists them here) hold no console helper.
    if (line ~ /^pid\/[0-9]+$/) next
    if (line !~ /^(user|gui)\/[0-9]+([[:space:]]+\[[0-9]+\])?$/) {bad=1; next}
    sub(/^(user|gui)\//, "", line); sub(/[[:space:]].*$/, "", line)
    if (line+0 >= 500 && line+0 < 4294967295) print line
  }
  END {if (!seen || !closed || inside || bad) exit 1}
') || {
	echo 'FAIL: unsupported live launchd domain inventory; payload retained' >&2
	exit 1
}
unset DOMAIN_INVENTORY
GUI_UIDS=$({
	printf '%s\n' "$GUI_DOMAIN_UIDS"
	echo "$CONSOLE_UID"
} | sort -nu)
for uid in $GUI_UIDS; do
	[ "$uid" -ge 500 ] || continue
	for agent in com.enterprise.enclave.intent com.enterprise.enclave.oidc-broker; do
		job="gui/$uid/$agent"
		if launchctl print "$job" >/dev/null 2>&1; then
			launchctl bootout "$job" || {
				echo 'FAIL: cannot stop console helper; payload and pins retained'
				exit 1
			}
			i=0
			while launchctl print "$job" >/dev/null 2>&1 && [ "$i" -lt 60 ]; do
				sleep 0.1
				i=$((i + 1))
			done
			if launchctl print "$job" >/dev/null 2>&1; then
				echo 'FAIL: console helper still running; payload and pins retained'
				exit 1
			fi
		fi
	done
done
for agent in com.enterprise.enclave.intent com.enterprise.enclave.oidc-broker; do
	rm -f "/Library/LaunchAgents/$agent.plist"
done

for l in $LABELS; do
	if launchctl print "system/$l" >/dev/null 2>&1; then
		launchctl bootout "system/$l" || {
			echo "FAIL: cannot stop $l; programs and recovery state retained"
			exit 1
		}
		i=0
		while launchctl print "system/$l" >/dev/null 2>&1 && [ "$i" -lt 60 ]; do
			sleep 0.1
			i=$((i + 1))
		done
		if launchctl print "system/$l" >/dev/null 2>&1; then
			echo "FAIL: $l still running; programs and recovery state retained"
			exit 1
		fi
		echo "stopped $l"
	fi
	rm -f "$LD/$l.plist"
done
for b in $BINS; do rm -f "$PREFIX/bin/$b"; done
for s in adapter cas custody ifc zk fido browser gateway; do rm -f "$PREFIX/sandbox/$s.sb"; done
rmdir "$PREFIX/sandbox" 2>/dev/null || true
rm -rf "$SUPPORT/EnclaveCustody.app" "$SUPPORT/EnclaveOIDC.app"
rm -f "$SUPPORT/codesign-pins.json" "$SUPPORT/fido-mds.json"
rmdir "$SUPPORT" 2>/dev/null || true
# Flush pf anchors and remove pf.conf markers if present
pfctl -a com.enterprise.llm.isolation -F rules 2>/dev/null || true
pfctl -a com.enterprise.cas.swarm -F rules 2>/dev/null || true
rm -f /etc/pf.anchors/com.enterprise.llm.isolation /etc/pf.anchors/com.enterprise.cas.swarm
if [ -f /etc/pf.conf ] && grep -q "BEGIN MCPMAC PF RULES" /etc/pf.conf; then
	sed -i '' '/# BEGIN MCPMAC PF RULES/,/# END MCPMAC PF RULES/d' /etc/pf.conf 2>/dev/null || true
fi

echo "removed programs, profiles, plists, EnclaveCustody.app and pins"

if [ "$PURGE" -eq 1 ]; then
	rm -rf /var/run/enclave /var/log/enclave /var/db/enclave "$PREFIX/cas"
	echo "purged /var/run/enclave /var/log/enclave /var/db/enclave $PREFIX/cas"
else
	echo "kept /var/db/enclave (SEP key blob), /var/log/enclave, $PREFIX/cas (use --purge-state to remove)"
fi

PV="$PREFIX/provision-accounts.sh"
if [ "$ACCOUNTS" -eq 1 ]; then
	[ -f "$PV" ] || {
		echo "uninstall.sh: $PV missing; cannot tell which accounts were created"
		exit 1
	}
	sed -n 's/^mkuser \([^ ]*\) .*/\1/p' "$PV" | while IFS= read -r u; do
		if dscl . -delete "/Users/$u" 2>/dev/null; then echo "deleted user $u"; fi
	done
	sed -n 's/^mkgroup \([^ ]*\) .*/\1/p' "$PV" | while IFS= read -r g; do
		if dscl . -delete "/Groups/$g" 2>/dev/null; then echo "deleted group $g"; fi
	done
	rm -f "$PV"
fi
rmdir "$PREFIX/bin" "$PREFIX" /opt/enterprise 2>/dev/null || true
echo "uninstall complete"
